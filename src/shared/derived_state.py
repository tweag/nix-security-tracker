"""
Decisions and derived state over the unified model (section 3.2 of the matching design).

- `set_verdict` / `remove_verdict`: the only writers of `Verdict`, each with a `TrackerEvent`.
- `effective_status`: verdict (branch-specific over all-branches) if present, else observation.
- `derive_state` / `derive_states`: the derived suggestion state of the report's table.
- `possibly_fixed_queue`: exposures observed fixed that no verdict confirms yet.
- `flush_derived_states`: store the derived state of suggestions whose inputs changed
  (`SuggestionDerivedState`); every writer calls it before committing.

Every human decision is a real `Verdict`: ignoring a package writes `irrelevant`, accepting or
publishing a suggestion writes `affected` for the attributes shown and not ignored
(`record_acceptance`), rejecting an accepted one withdraws those (`withdraw_acceptance`);
`backfill_unified_model` writes both for suggestions decided before. Nothing is implied.
"""

import re
import uuid
from collections import defaultdict
from collections.abc import Collection, Iterable
from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum

from django.contrib.auth.models import User
from django.db import transaction
from django.db.models import Max
from django.utils import timezone

from shared.exposure import dismissed_q, is_dismissed, lock_suggestions
from shared.models.linkage import CVEDerivationClusterProposal
from shared.models.matching import (
    Exposure,
    Match,
    SuggestionDerivedState,
    TrackerEvent,
    Verdict,
)
from shared.models.nix_evaluation import NixEvaluation, NixpkgsBranch

Observed = Exposure.Observed
VerdictKind = Verdict.Kind
Status = CVEDerivationClusterProposal.Status

_SHA1 = re.compile(r"^[0-9a-f]{40}$")

# Verdicts that settle a (package, branch): it needs no further action.
SETTLING = (
    VerdictKind.IRRELEVANT,
    VerdictKind.NOT_AFFECTED,
    VerdictKind.FIXED,
    VerdictKind.WONTFIX,
)
# Verdicts that confirm an observed fix, taking it out of the possibly-fixed queue.
CONFIRMING_FIX = (VerdictKind.FIXED, VerdictKind.NOT_AFFECTED, VerdictKind.IRRELEVANT)


class DerivedState(StrEnum):
    NO_CANDIDATES = "no_candidates"
    NEEDS_TRIAGE = "needs_triage"
    POSSIBLY_FIXED = "possibly_fixed"
    TRACKING = "tracking"
    RESOLVED = "resolved"
    DISMISSED = "dismissed"


# --- Verdicts -------------------------------------------------------------------------------


def _verdict_data(v: Verdict) -> dict[str, str | None]:
    return {"verdict": v.verdict, "comment": v.comment, "fix_commit": v.fix_commit}


def set_verdict(
    suggestion: CVEDerivationClusterProposal,
    attrpath: str,
    verdict: str,
    author: User | None,
    branch: NixpkgsBranch | None = None,
    comment: str = "",
    fix_commit: str | None = None,
    batch: uuid.UUID | None = None,
    via: str | None = None,
) -> Verdict:
    """
    `via` names the action the decision came with ("accept", "ignore"), for the event.

    Record a decision for an attribute on one branch (or all, `branch=None`), with a
    `verdict_set` or `verdict_changed` event. Setting the same decision again writes nothing.
    """
    if fix_commit is not None and not _SHA1.match(fix_commit):
        raise ValueError(
            f"fix_commit must be a 40-character lowercase sha: {fix_commit!r}"
        )
    with transaction.atomic():
        lock_suggestions([suggestion.pk])
        existing = Verdict.objects.filter(
            suggestion=suggestion, attrpath=attrpath, branch=branch
        ).first()
        if existing is None:
            row = Verdict.objects.create(
                suggestion=suggestion,
                attrpath=attrpath,
                branch=branch,
                verdict=verdict,
                comment=comment,
                fix_commit=fix_commit,
                author=author,
            )
            _verdict_event(row, TrackerEvent.Kind.VERDICT_SET, author, batch, None, via)
            return row
        old = _verdict_data(existing)
        if old == {"verdict": verdict, "comment": comment, "fix_commit": fix_commit}:
            return existing
        existing.verdict = verdict
        existing.comment = comment
        existing.fix_commit = fix_commit
        existing.author = author
        existing.save()
        _verdict_event(
            existing, TrackerEvent.Kind.VERDICT_CHANGED, author, batch, old, via
        )
        return existing


def remove_verdict(
    suggestion: CVEDerivationClusterProposal,
    attrpath: str,
    author: User | None,
    branch: NixpkgsBranch | None = None,
    batch: uuid.UUID | None = None,
    via: str | None = None,
) -> bool:
    """Remove a decision, with a `verdict_removed` event. False if there was none."""
    with transaction.atomic():
        lock_suggestions([suggestion.pk])
        existing = Verdict.objects.filter(
            suggestion=suggestion, attrpath=attrpath, branch=branch
        ).first()
        if existing is None:
            return False
        old = _verdict_data(existing)
        existing.delete()
        _verdict_event(
            existing, TrackerEvent.Kind.VERDICT_REMOVED, author, batch, old, via
        )
        return True


def shown_unignored_attributes(suggestion: CVEDerivationClusterProposal) -> set[str]:
    """Attributes the suggestion shows (its links) that a human did not ignore."""
    linked = set(suggestion.derivations.values_list("attribute", flat=True).distinct())
    ignored = set(
        Verdict.objects.filter(
            suggestion=suggestion, branch=None, verdict=VerdictKind.IRRELEVANT
        ).values_list("attrpath", flat=True)
    )
    return linked - ignored


def record_acceptance(
    suggestion: CVEDerivationClusterProposal, author: User | None, via: str = "accept"
) -> int:
    """
    A human accepted (or published) the suggestion: an all-branches `affected` verdict by
    them for every attribute shown and not ignored that has no all-branches verdict yet.
    Returns how many were written.
    """
    decided = set(
        Verdict.objects.filter(suggestion=suggestion, branch=None).values_list(
            "attrpath", flat=True
        )
    )
    batch = uuid.uuid4()
    attrs = sorted(shown_unignored_attributes(suggestion) - decided)
    for attr in attrs:
        set_verdict(
            suggestion, attr, VerdictKind.AFFECTED, author, batch=batch, via=via
        )
    return len(attrs)


def withdraw_acceptance(
    suggestion: CVEDerivationClusterProposal, author: User | None
) -> int:
    """
    A human rejected a suggestion they had accepted: its all-branches `affected` verdicts
    contradict that and go; ignores and branch-specific decisions stay.
    """
    batch = uuid.uuid4()
    attrs = list(
        Verdict.objects.filter(
            suggestion=suggestion, branch=None, verdict=VerdictKind.AFFECTED
        ).values_list("attrpath", flat=True)
    )
    for attr in attrs:
        remove_verdict(suggestion, attr, author, batch=batch, via="reject")
    return len(attrs)


def _verdict_event(
    v: Verdict,
    kind: str,
    author: User | None,
    batch: uuid.UUID | None,
    old: dict[str, str | None] | None,
    via: str | None = None,
) -> None:
    data: dict[str, object] = {}
    if via is not None:
        data["via"] = via
    if kind != TrackerEvent.Kind.VERDICT_REMOVED:
        data["new"] = _verdict_data(v)
    if old is not None:
        data["old"] = old
    TrackerEvent.objects.create(
        suggestion_id=v.suggestion_id,
        kind=kind,
        attrpath=v.attrpath,
        branch_id=v.branch_id,
        cause=TrackerEvent.Cause.USER,
        actor=author,
        data=data,
        batch=batch or uuid.uuid4(),
    )
    flush_derived_states([v.suggestion_id])


# --- Effective status -----------------------------------------------------------------------


@dataclass(frozen=True)
class VerdictFact:
    attrpath: str
    branch_id: str | None
    verdict: str
    updated_at: datetime | None = None


@dataclass(frozen=True)
class Effective:
    """Effective status of one (attribute, branch)."""

    status: str
    source: str  # "verdict", "observed", "none"
    verdict: VerdictFact | None = None
    exposure: Exposure | None = None
    regression: bool = False


def pick_verdict(
    verdicts: Iterable[VerdictFact], attrpath: str, branch_id: str | None
) -> VerdictFact | None:
    """The most specific verdict: branch-specific over all-branches."""
    general = None
    for v in verdicts:
        if v.attrpath != attrpath:
            continue
        if v.branch_id is not None and v.branch_id == branch_id:
            return v
        if v.branch_id is None:
            general = v
    return general


def effective_status(
    exposure: Exposure | None,
    verdict: VerdictFact | None,
    last_became_affected: datetime | None = None,
) -> Effective:
    """
    The verdict if there is one, else the observation. A `fixed` verdict followed by a later
    became-affected event keeps the verdict but raises `regression`.
    """
    if verdict is not None:
        regression = (
            verdict.verdict == VerdictKind.FIXED
            and last_became_affected is not None
            and (
                verdict.updated_at is None or last_became_affected > verdict.updated_at
            )
        )
        return Effective(
            status=verdict.verdict,
            source="verdict",
            verdict=verdict,
            exposure=exposure,
            regression=regression,
        )
    if exposure is not None:
        return Effective(status=exposure.observed, source="observed", exposure=exposure)
    return Effective(status=Observed.UNKNOWN, source="none")


# --- Derived suggestion state ---------------------------------------------------------------


@dataclass
class SuggestionFacts:
    """Everything `derive_state` reads, prefetched for one suggestion."""

    suggestion_id: int
    status: str
    rejection_reason: str | None
    matched: set[str] = field(default_factory=set)
    verdicts: list[VerdictFact] = field(default_factory=list)
    exposures: list[Exposure] = field(default_factory=list)
    became_affected: dict[tuple[str, str], datetime] = field(default_factory=dict)


@dataclass
class Derived:
    state: DerivedState
    candidates: list[str] = field(default_factory=list)
    needs_triage: list[tuple[str, str | None]] = field(default_factory=list)
    possibly_fixed: list[tuple[str, str]] = field(default_factory=list)
    regressions: list[tuple[str, str | None]] = field(default_factory=list)
    affected: list[tuple[str, str | None]] = field(default_factory=list)


def derive_state(facts: SuggestionFacts) -> Derived:
    """
    Derived state of a suggestion, in this order:
    - `dismissed`: rejected for a CVE-level reason (exclusively hosted service, not in nixpkgs,
      hardware only) or by a human without a reason. Matcher rejections (no matches, too many
      matches, known vulnerability) are not dismissals; the facts decide for those.
    - `no_candidates`: no attribute with an active match or a verdict.
    - `needs_triage`: a candidate (attribute, branch) without a verdict that is observed
      affected or unknown, or not present on any tracked branch; or a regression (a `fixed`
      verdict followed by a became-affected event). Acknowledged exposures (the CVE is in
      `meta.knownVulnerabilities`) count as affected without triage (#1376).
    - `tracking`: some (attribute, branch) is effectively affected.
    - `possibly_fixed`: nothing effectively affected, and some exposure that was affected is
      now observed unaffected (with `fixed_evaluation`) or absent, without a confirming verdict.
    - `resolved`: everything else, i.e. every (attribute, branch) is settled by a verdict or
      was never observed affected. The report's table lists only the first; candidates that
      the classifier never saw affected (every branch outside the ranges) also land here.
    Exposures of attributes that are no longer candidates are ignored.
    """
    if is_dismissed(facts.status, facts.rejection_reason):
        return Derived(DerivedState.DISMISSED)
    candidates = candidates_of(facts)
    if not candidates:
        return Derived(DerivedState.NO_CANDIDATES)
    verdicts = facts.verdicts

    by_attr: dict[str, list[Exposure]] = defaultdict(list)
    for e in facts.exposures:
        if e.attrpath in candidates:
            by_attr[e.attrpath].append(e)

    result = Derived(DerivedState.RESOLVED, candidates=sorted(candidates))
    for attr in sorted(candidates):
        keys: list[tuple[str | None, Exposure | None]] = [
            (e.branch_id, e) for e in sorted(by_attr[attr], key=lambda e: e.branch_id)
        ] or [(None, None)]
        for branch_id, exposure in keys:
            eff = effective_status(
                exposure,
                pick_verdict(verdicts, attr, branch_id),
                facts.became_affected.get((attr, branch_id)) if branch_id else None,
            )
            key = (attr, branch_id)
            if eff.regression:
                result.regressions.append(key)
                result.needs_triage.append(key)
            elif eff.source in ("observed", "none"):
                if eff.status == Observed.UNKNOWN or (
                    eff.status == Observed.AFFECTED
                    and exposure is not None
                    and exposure.reason != Exposure.Reason.ACKNOWLEDGED
                ):
                    result.needs_triage.append(key)
            if eff.status == VerdictKind.AFFECTED:  # same value as Observed.AFFECTED
                result.affected.append(key)
            if (
                exposure is not None
                and branch_id is not None
                and _was_fixed_or_gone(exposure)
                and not (eff.verdict and eff.verdict.verdict in CONFIRMING_FIX)
            ):
                result.possibly_fixed.append((attr, branch_id))

    if result.needs_triage:
        result.state = DerivedState.NEEDS_TRIAGE
    elif result.affected:
        result.state = DerivedState.TRACKING
    elif result.possibly_fixed:
        result.state = DerivedState.POSSIBLY_FIXED
    return result


def candidates_of(facts: SuggestionFacts) -> set[str]:
    """Attributes with an active match or an explicit verdict."""
    return set(facts.matched) | {v.attrpath for v in facts.verdicts}


def _was_fixed_or_gone(e: Exposure) -> bool:
    if e.observed == Observed.UNAFFECTED:
        return e.fixed_evaluation_id is not None
    return e.observed == Observed.ABSENT and e.first_affected_evaluation_id is not None


def load_facts(suggestion_ids: Collection[int]) -> dict[int, SuggestionFacts]:
    """Prefetch the facts of many suggestions in a fixed number of queries."""
    facts = {
        pk: SuggestionFacts(pk, status, reason)
        for pk, status, reason in CVEDerivationClusterProposal.objects.filter(
            pk__in=suggestion_ids
        ).values_list("pk", "status", "rejection_reason")
    }
    ids = list(facts)
    for sid, attr in (
        Match.objects.active()
        .filter(suggestion_id__in=ids)
        .values_list("suggestion_id", "attrpath")
        .distinct()
    ):
        facts[sid].matched.add(attr)
    for sid, attr, branch_id, verdict, updated_at in Verdict.objects.filter(
        suggestion_id__in=ids
    ).values_list("suggestion_id", "attrpath", "branch_id", "verdict", "updated_at"):
        facts[sid].verdicts.append(VerdictFact(attr, branch_id, verdict, updated_at))
    for e in Exposure.objects.filter(suggestion_id__in=ids):
        facts[e.suggestion_id].exposures.append(e)
    for sid, attr, branch_id, at in (
        TrackerEvent.objects.filter(
            suggestion_id__in=ids,
            kind=TrackerEvent.Kind.EXPOSURE_BECAME_AFFECTED,
            branch__isnull=False,
        )
        .values_list("suggestion_id", "attrpath", "branch_id")
        .annotate(at=Max("created_at"))
    ):
        facts[sid].became_affected[(attr, branch_id)] = at
    return facts


def flush_derived_states(
    suggestion_ids: Iterable[int] | None = None, limit: int | None = None
) -> int:
    """
    Recompute the stored derived state of suggestions marked stale (by the triggers on tracker
    events and on status changes), within the caller's transaction, so a writer that calls
    this with the suggestions it wrote, before committing, leaves them consistent. Without
    ids, every stale row (`recompute_derived_state --stale-only`). Rows another transaction
    holds are skipped; that transaction flushes them itself. Returns how many were recomputed.
    """
    with transaction.atomic():
        rows = SuggestionDerivedState.objects.filter(stale=True)
        if suggestion_ids is not None:
            rows = rows.filter(suggestion_id__in=list(suggestion_ids))
        stale = (
            rows.select_for_update(skip_locked=True)
            .order_by("pk")
            .values_list("suggestion_id", flat=True)
        )
        ids = list(stale[:limit] if limit is not None else stale)
        if not ids:
            return 0
        now = timezone.now()
        SuggestionDerivedState.objects.bulk_update(
            [
                SuggestionDerivedState(
                    suggestion_id=pk, state=d.state, stale=False, updated_at=now
                )
                for pk, d in derive_states(ids).items()
            ],
            ["state", "stale", "updated_at"],
        )
        return len(ids)


def derive_states(suggestion_ids: Collection[int]) -> dict[int, Derived]:
    """`derive_state` for many suggestions without per-suggestion queries."""
    return {sid: derive_state(f) for sid, f in load_facts(suggestion_ids).items()}


# --- Possibly fixed queue -------------------------------------------------------------------


@dataclass(frozen=True)
class PossiblyFixed:
    suggestion_id: int
    cve_id: str
    attrpath: str
    branch_id: str
    old_version: str | None
    new_version: str | None
    # The fix lies between these two evaluations; their commits give a compare link.
    last_affected_evaluation: NixEvaluation | None
    fixed_evaluation: NixEvaluation
    exposure_id: int

    @property
    def compare_url(self) -> str | None:
        if self.last_affected_evaluation is None:
            return None
        return (
            "https://github.com/NixOS/nixpkgs/compare/"
            f"{self.last_affected_evaluation.commit_sha1}...{self.fixed_evaluation.commit_sha1}"
        )


def possibly_fixed_queue(
    suggestion_ids: Collection[int] | None = None,
) -> list[PossiblyFixed]:
    """
    Exposures that were affected and are now observed unaffected (`fixed_evaluation` set),
    on attributes that are still candidates, without a verdict confirming the fix. Removal
    is not listed here: a package that disappeared is not a fix. Oldest fixes first.
    """
    rows = (
        Exposure.objects.filter(
            fixed_evaluation__isnull=False, observed=Observed.UNAFFECTED
        )
        .exclude(dismissed_q("suggestion__"))
        .select_related(
            "fixed_evaluation", "last_affected_evaluation", "suggestion__cve"
        )
        .order_by("fixed_evaluation__created_at", "pk")
    )
    if suggestion_ids is not None:
        rows = rows.filter(suggestion_id__in=suggestion_ids)
    exposures = list(rows)
    facts = load_facts({e.suggestion_id for e in exposures})
    queue = []
    for e in exposures:
        f = facts[e.suggestion_id]
        if e.attrpath not in candidates_of(f):
            continue
        v = pick_verdict(f.verdicts, e.attrpath, e.branch_id)
        if v is not None and v.verdict in CONFIRMING_FIX:
            continue
        assert e.fixed_evaluation is not None
        queue.append(
            PossiblyFixed(
                suggestion_id=e.suggestion_id,
                cve_id=e.suggestion.cve.cve_id,
                attrpath=e.attrpath,
                branch_id=e.branch_id,
                old_version=e.detail.get("last_affected_version"),
                new_version=e.version,
                last_affected_evaluation=e.last_affected_evaluation,
                fixed_evaluation=e.fixed_evaluation,
                exposure_id=e.pk,
            )
        )
    return queue
