"""
Backfill of the unified model from what the legacy write path left: `legacy-v2` matches and
as-matched exposures from the derivation links of suggestions matched by the legacy algorithm
(version below 3), then exposures reconciled against the current snapshot; `irrelevant`
verdicts from ignore overlays; `affected` verdicts for what accepted and published suggestions
show. Idempotent.

`backfill_suggestions` is what `manage.py backfill_unified_model` runs batch by batch, and
what the write path runs on a legacy suggestion before anything else touches it
(`ensure_backfilled`), so correctness does not depend on the backfill having reached it.
"""

import uuid
from collections import defaultdict
from typing import Any

from django.contrib.auth.models import User
from django.db import transaction
from django.utils import timezone

from shared.exposure import (
    Cause,
    _load_context,
    _Run,
    _write,
    is_dismissed,
    lock_suggestions,
    observe,
    reconcile_exposures,
    tracked_branches,
)
from shared.matching.selection import LEGACY_MATCHER, LEGACY_MATCHER_VERSION
from shared.models import (  # type: ignore[attr-defined]
    CVEDerivationClusterProposalStatusEvent,
    PackageOverlayEvent,
)
from shared.models.linkage import (
    CVEDerivationClusterProposal,
    DerivationClusterProposalLink,
    PackageOverlay,
    ProvenanceFlags,
)
from shared.models.matching import Exposure, Match, TrackerEvent, Verdict
from shared.models.nix_evaluation import NixEvaluation, parse_drv_name
from shared.models.snapshot import BranchPackage

Kind = TrackerEvent.Kind
Status = CVEDerivationClusterProposal.Status


def legacy_evidence(flags: int) -> dict[str, Any]:
    """Evidence of a `legacy-v2` match: the provenance bits and the CVE field they name."""
    fields = [
        name
        for flag, name in (
            (ProvenanceFlags.PACKAGE_NAME_MATCH, "package_name"),
            (ProvenanceFlags.PRODUCT_MATCH, "product"),
            (ProvenanceFlags.CPE_MATCH, "cpe"),
        )
        if flags & flag
    ]
    evidence: dict[str, Any] = {"provenance_flags": flags, "source": "legacy links"}
    if fields:
        evidence["cve_field"] = fields[0]
        evidence["cve_fields"] = fields
    return evidence


def ensure_backfilled(suggestion: CVEDerivationClusterProposal) -> dict[str, int]:
    """
    Backfill one suggestion if the legacy write path made it, before the new one touches it:
    otherwise a re-match drops what humans accepted, since their acceptance is still only in
    the links. A no-op (one query) for suggestions of the new write path.
    """
    if (
        suggestion.algorithm_version
        >= CVEDerivationClusterProposal.CURRENT_ALGORITHM_VERSION
    ):
        return {}
    return backfill_suggestions([suggestion.pk])


def backfill_suggestions(
    ids: list[int], reconcile: bool = True, branches: dict[str, Any] | None = None
) -> dict[str, int]:
    """
    Backfill these suggestions in the caller's transaction. Takes their exposure locks first
    and reads their status and algorithm version under them, so a suggestion re-matched
    concurrently (now version 3) gets no fresh `legacy-v2` matches nothing would retire.
    """
    from shared.derived_state import flush_derived_states

    branches = (
        branches if branches is not None else {b.name: b for b in tracked_branches()}
    )
    counts: dict[str, int] = defaultdict(int)
    with transaction.atomic():
        lock_suggestions(ids)
        batch = list(
            CVEDerivationClusterProposal.objects.filter(pk__in=ids)
            .order_by("pk")
            .values_list("pk", "status", "rejection_reason", "algorithm_version")
        )
        legacy = {
            pk
            for pk, _, _, version in batch
            if version < CVEDerivationClusterProposal.CURRENT_ALGORITHM_VERSION
        }
        open_legacy = [
            pk
            for pk, status, reason, _ in batch
            if pk in legacy and not is_dismissed(status, reason)
        ]
        counts["verdicts"] = _verdicts([pk for pk, *_ in batch])
        counts["acceptances"] = _acceptances(
            [
                pk
                for pk, status, _, _ in batch
                if status in (Status.ACCEPTED, Status.PUBLISHED)
            ]
        )
        if legacy:
            run = _Run(cause=Cause.BACKFILL, batch=uuid.uuid4())
            links = list(
                DerivationClusterProposalLink.objects.filter(
                    proposal_id__in=legacy
                ).values_list(
                    "proposal_id",
                    "provenance_flags",
                    "derivation__attribute",
                    "derivation__name",
                    "derivation__parent_evaluation_id",
                    "derivation__metadata__known_vulnerabilities",
                )
            )
            counts["matches"] = _matches(links, run)
            counts["exposures"] = _exposures(
                [link for link in links if link[0] in set(open_legacy)], branches, run
            )
            TrackerEvent.objects.bulk_create(run.events)
            if reconcile:
                for suggestion in CVEDerivationClusterProposal.objects.filter(
                    pk__in=open_legacy
                ):
                    result = reconcile_exposures(suggestion, Cause.BACKFILL)
                    counts["reconciled_events"] += sum(result.events.values())
        counts["derived_states"] = flush_derived_states([pk for pk, *_ in batch])
    return counts


def _matches(links: list[tuple[Any, ...]], run: _Run) -> int:
    flags: dict[tuple[int, str], int] = defaultdict(int)
    for sid, f, attr, *_ in links:
        flags[(sid, attr)] |= f
    existing = set(
        Match.objects.filter(
            suggestion_id__in={s for s, _ in flags}, matcher=LEGACY_MATCHER
        ).values_list("suggestion_id", "attrpath")
    )
    now = timezone.now()
    new = [
        Match(
            suggestion_id=sid,
            attrpath=attr,
            matcher=LEGACY_MATCHER,
            matcher_version=LEGACY_MATCHER_VERSION,
            score=1.0,
            evidence=legacy_evidence(f),
            last_seen_at=now,
        )
        for (sid, attr), f in sorted(flags.items())
        if (sid, attr) not in existing
    ]
    Match.objects.bulk_create(new, ignore_conflicts=True)
    run.events += [
        TrackerEvent(
            suggestion_id=m.suggestion_id,
            kind=Kind.MATCH_ADDED,
            attrpath=m.attrpath,
            matcher=LEGACY_MATCHER,
            cause=Cause.BACKFILL,
            data={"score": 1.0, "evidence": m.evidence},
            batch=run.batch,
        )
        for m in new
    ]
    return len(new)


def _exposures(
    links: list[tuple[Any, ...]],
    branches: dict[str, Any],
    run: _Run,
) -> int:
    """
    One row per (suggestion, attribute, tracked branch) as matched: the newest linked
    derivation of the attribute on that branch, classified against the CVE. Only where the
    branch has a snapshot row for the attribute, as `shared.exposure` requires.
    """
    if not links:
        return 0
    evaluations = NixEvaluation.objects.in_bulk({link[4] for link in links})
    on_branches: dict[int, set[str]] = defaultdict(set)
    for evaluation, branch in NixEvaluation.on_branches.through.objects.filter(
        nixevaluation_id__in=evaluations, nixpkgsbranch_id__in=branches
    ).values_list("nixevaluation_id", "nixpkgsbranch_id"):
        on_branches[evaluation].add(branch)

    newest: dict[tuple[int, str, str], tuple[Any, ...]] = {}
    for link in links:
        sid, _, attr, _, evaluation_id, _ = link
        evaluation = evaluations[evaluation_id]
        for branch in on_branches[evaluation_id]:
            key = (sid, attr, branch)
            current = newest.get(key)
            if current is None or (evaluation.created_at, evaluation.pk) > (
                evaluations[current[4]].created_at,
                current[4],
            ):
                newest[key] = link
    attrs = {a for _, a, _ in newest}
    snapshotted = set(
        BranchPackage.objects.filter(
            attrpath__in=attrs, branch_id__in=branches
        ).values_list("branch_id", "attrpath")
    )
    existing = set(
        Exposure.objects.filter(
            suggestion_id__in={s for s, _, _ in newest}
        ).values_list("suggestion_id", "attrpath", "branch_id")
    )
    ctx = _load_context({s for s, _, _ in newest}, attrs)
    written = 0
    for (sid, attr, branch), link in sorted(newest.items()):
        if (branch, attr) not in snapshotted or (sid, attr, branch) in existing:
            continue
        _, _, _, name, evaluation_id, known = link
        evaluation = evaluations[evaluation_id]
        as_matched = BranchPackage(
            attrpath=attr,
            branch_id=branch,
            present=True,
            version=parse_drv_name(name)[1],
            known_vulnerabilities=known or [],
            evaluation_id=evaluation_id,
        )
        obs = observe(as_matched, ctx.cve_id[sid], ctx.products_for(sid, attr))
        _write(
            run,
            None,
            obs,
            suggestion_id=sid,
            attrpath=attr,
            branch=branches[branch],
            evaluation=evaluation,
            previous_evaluation=None,
        )
        written += 1
    return written


def _acceptances(ids: list[int]) -> int:
    """
    `affected` verdicts for what accepted and published suggestions show and do not ignore,
    by the user who accepted (or published) if the status history records one.
    """
    if not ids:
        return 0
    linked: dict[int, set[str]] = defaultdict(set)
    for sid, attr in (
        DerivationClusterProposalLink.objects.filter(proposal_id__in=ids)
        .values_list("proposal_id", "derivation__attribute")
        .distinct()
    ):
        linked[sid].add(attr)
    decided = set(
        Verdict.objects.filter(suggestion_id__in=ids, branch__isnull=True).values_list(
            "suggestion_id", "attrpath"
        )
    )
    authors: dict[int, int | None] = {}
    for sid, metadata in (
        CVEDerivationClusterProposalStatusEvent.objects.filter(
            pgh_obj_id__in=ids,
            status__in=[Status.ACCEPTED, Status.PUBLISHED],
        )
        .exclude(pgh_label="rematch")
        .order_by("pgh_created_at")
        .values_list("pgh_obj_id", "pgh_context__metadata")
    ):
        user = (metadata or {}).get("user")
        if user is not None:
            authors[sid] = int(user)
    users = set(
        User.objects.filter(
            pk__in={u for u in authors.values() if u is not None}
        ).values_list("pk", flat=True)
    )
    new = [
        Verdict(
            suggestion_id=sid,
            attrpath=attr,
            branch=None,
            verdict=Verdict.Kind.AFFECTED,
            author_id=a if (a := authors.get(sid)) in users else None,
            comment="",
        )
        for sid in ids
        for attr in sorted(linked[sid])
        if (sid, attr) not in decided
    ]
    Verdict.objects.bulk_create(new, ignore_conflicts=True)
    batch = uuid.uuid4()
    TrackerEvent.objects.bulk_create(
        TrackerEvent(
            suggestion_id=v.suggestion_id,
            kind=Kind.VERDICT_SET,
            attrpath=v.attrpath,
            cause=Cause.BACKFILL,
            actor_id=v.author_id,
            data={"new": {"verdict": v.verdict}, "via": "accept", "from": "status"},
            batch=batch,
        )
        for v in new
    )
    return len(new)


def _verdicts(ids: list[int]) -> int:
    """`irrelevant` verdicts for ignore overlays, by the user who ignored if recorded."""
    overlays = list(
        PackageOverlay.objects.filter(
            suggestion_id__in=ids, type=PackageOverlay.Type.IGNORED
        ).values_list("suggestion_id", "package_attribute")
    )
    if not overlays:
        return 0
    existing = set(
        Verdict.objects.filter(suggestion_id__in=ids, branch__isnull=True).values_list(
            "suggestion_id", "attrpath"
        )
    )
    authors: dict[tuple[int, str], int | None] = {}
    for sid, attr, metadata in (
        PackageOverlayEvent.objects.filter(
            suggestion_id__in=ids, pgh_label="package.ignore"
        )
        .order_by("pgh_created_at")
        .values_list("suggestion_id", "package_attribute", "pgh_context__metadata")
    ):
        user = (metadata or {}).get("user")
        authors[(sid, attr)] = int(user) if user is not None else None
    users = set(
        User.objects.filter(
            pk__in={u for u in authors.values() if u is not None}
        ).values_list("pk", flat=True)
    )
    new = [
        Verdict(
            suggestion_id=sid,
            attrpath=attr,
            branch=None,
            verdict=Verdict.Kind.IRRELEVANT,
            author_id=a if (a := authors.get((sid, attr))) in users else None,
            comment="",
        )
        for sid, attr in overlays
        if (sid, attr) not in existing
    ]
    Verdict.objects.bulk_create(new, ignore_conflicts=True)
    batch = uuid.uuid4()
    TrackerEvent.objects.bulk_create(
        TrackerEvent(
            suggestion_id=v.suggestion_id,
            kind=Kind.VERDICT_SET,
            attrpath=v.attrpath,
            cause=Cause.BACKFILL,
            actor_id=v.author_id,
            data={"new": {"verdict": v.verdict}, "from": "package overlay"},
            batch=batch,
        )
        for v in new
    )
    return len(new)
