"""
Activity log entries from `TrackerEvent` rows: one entry per suggestion and batch
(one reconciliation run, or one verdict request), carrying the changes as data for
the client to phrase.
"""

from collections.abc import Collection
from datetime import datetime
from typing import Any, Literal, TypedDict
from uuid import UUID

from shared.models.matching import TrackerEvent

Kind = TrackerEvent.Kind

TrackerAction = Literal[
    "tracker.matches",
    "tracker.exposures",
    "tracker.verdicts",
    "tracker.fixes",
    "tracker.mixed",
]

# Remediation: pull requests linked as fixes, fix commits found, fixes reaching channels.
FIX_KINDS = {
    Kind.FIX_LANDED,
    Kind.FIX_LINK_ADDED,
    Kind.FIX_LINK_RETRACTED,
    Kind.EXPOSURE_FIX_COMMIT_SET,
}

# Deleted accounts must not be resolvable from the log, as in `fetchers._annotate_username`.
REDACTED = "REDACTED"


class TrackerChange(TypedDict):
    kind: str
    attrpath: str
    branch: str | None
    matcher: str | None
    evaluation_commit: str | None
    old_version: str | None
    new_version: str | None
    old_status: str | None
    new_status: str | None
    old_reason: str | None
    new_reason: str | None
    detail: str | None
    inferred: bool
    regression: bool
    fix_candidate: bool
    score: float | None
    old_score: float | None
    evidence: dict[str, Any] | None
    matcher_truncated: int | None
    verdict: str | None
    old_verdict: str | None
    fix_commit: str | None
    comment: str | None
    # The `not_same` mapping a retraction is due to.
    vetoed_by: dict[str, Any] | None
    # How it came about: for a verdict the action it came with ("accept", "publish",
    # "reject"); for a landing what was tracked ("fix_commit", "fixed_evaluation").
    via: str | None
    # fix_link_*: the pull request; exposure_fix_commit_set: the one that gave the commit.
    pull_request: int | None
    repository: str | None
    base_ref: str | None
    title: str | None
    # How the pull request was linked (closing reference, ...).
    source: str | None
    # exposure_fix_commit_set: how the pull request was confirmed as the fix.
    method: str | None
    # fix_landed: the channel, the fix's commit, the channel commit it arrived with, when.
    channel: str | None
    commit: str | None
    channel_commit: str | None
    landed_at: str | None


class TrackerEntry(TypedDict):
    suggestion_id: int
    batch: UUID
    action: TrackerAction
    timestamp: datetime
    username: str | None
    cause: str
    changes: list[TrackerChange]


def _action(kinds: set[str]) -> TrackerAction:
    if kinds <= FIX_KINDS:
        return "tracker.fixes"
    prefixes = {k.split("_", 1)[0] for k in kinds}
    if prefixes == {"match"}:
        return "tracker.matches"
    if prefixes == {"exposure"}:
        return "tracker.exposures"
    if prefixes == {"verdict"}:
        return "tracker.verdicts"
    return "tracker.mixed"


def _change(e: TrackerEvent) -> TrackerChange:
    d = e.data
    new = d.get("new") or {}
    old = d.get("old") or {}
    return {
        "kind": e.kind,
        "attrpath": e.attrpath,
        "branch": e.branch_id,
        "matcher": e.matcher,
        "evaluation_commit": e.evaluation.commit_sha1 if e.evaluation else None,
        "old_version": d.get("old_version"),
        "new_version": d.get("new_version"),
        "old_status": d.get("old_status"),
        "new_status": d.get("new_status"),
        "old_reason": d.get("old_reason"),
        "new_reason": d.get("new_reason"),
        "detail": d.get("detail"),
        "inferred": bool(d.get("inferred")),
        "regression": bool(d.get("regression")),
        "fix_candidate": bool(d.get("fix_candidate")),
        "score": d.get("score"),
        "old_score": d.get("old_score"),
        "evidence": d.get("evidence"),
        "matcher_truncated": d.get("matcher_truncated"),
        "verdict": new.get("verdict"),
        "old_verdict": old.get("verdict"),
        # A verdict records it in `new`; a fix commit found or patched, at the top.
        "fix_commit": new.get("fix_commit") or d.get("fix_commit"),
        "comment": new.get("comment"),
        "vetoed_by": d.get("vetoed_by"),
        "via": d.get("via"),
        "pull_request": d.get("pull_request"),
        "repository": d.get("repository"),
        "base_ref": d.get("base_ref"),
        "title": d.get("title"),
        "source": d.get("source"),
        "method": d.get("method"),
        "channel": d.get("channel"),
        "commit": d.get("commit"),
        "channel_commit": d.get("channel_commit"),
        "landed_at": d.get("landed_at"),
    }


def _username(e: TrackerEvent) -> str | None:
    if e.actor is not None:
        return e.actor.username
    # A user action whose author is gone; tracker actions have no user.
    return REDACTED if e.cause == TrackerEvent.Cause.USER else None


def fetch_tracker_entries(
    suggestion_ids: Collection[int],
) -> dict[int, list[TrackerEntry]]:
    """Tracker events of several suggestions, grouped by batch, oldest first, in one query."""
    result: dict[int, list[TrackerEntry]] = {sid: [] for sid in suggestion_ids}
    if not suggestion_ids:
        return result
    open_entries: dict[tuple[int, UUID], TrackerEntry] = {}
    kinds: dict[tuple[int, UUID], set[str]] = {}
    for e in (
        TrackerEvent.objects.filter(suggestion_id__in=suggestion_ids)
        .select_related("actor", "evaluation")
        .order_by("created_at", "pk")
    ):
        key = (e.suggestion_id, e.batch)
        entry = open_entries.get(key)
        if entry is None:
            entry = open_entries[key] = {
                "suggestion_id": e.suggestion_id,
                "batch": e.batch,
                "action": "tracker.mixed",
                "timestamp": e.created_at,
                "username": _username(e),
                "cause": e.cause,
                "changes": [],
            }
            kinds[key] = set()
            result[e.suggestion_id].append(entry)
        entry["timestamp"] = e.created_at
        entry["changes"].append(_change(e))
        kinds[key].add(e.kind)
    for key, entry in open_entries.items():
        entry["action"] = _action(kinds[key])
    return result
