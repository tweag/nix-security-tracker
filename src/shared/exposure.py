"""
Exposure layer: the affected status of attribute A on branch B for the CVE of a suggestion,
kept current from `BranchPackage` and the version classifier, with a `TrackerEvent` for every
change (section 3.2 of the matching design, keyed by attribute path).

Two entry points write `Exposure` rows:
- `reconcile_exposures`: everything one suggestion cares about, on every tracked branch.
  For match changes, CVE updates and backfill.
- `apply_branch_changes`: the differential path for one evaluation step of one branch, driven
  by its `BranchPackageChange` rows, touching only attributes some suggestion cares about.

Rules shared by both:
- An attribute takes part while it has an active `Match` or any `Verdict`. When it has
  neither, its rows are kept as they are (never deleted) and no longer updated; the derived
  state ignores them. A later match or verdict makes the next reconciliation catch them up.
- Suggestions dismissed by a CVE-level rejection (`is_dismissed`) are not updated. Suggestions
  rejected by the matcher itself (no matches, too many, known vulnerability) are, so that the
  old one-way ratchet to REJECTED (1.8, problem 2) has no counterpart here; published ones are
  too, since "fixed on master, still affected on the release branch" is the backport signal.
- Rows exist only where the branch has a `BranchPackage` row for the attribute.
- All writers serialise per suggestion with transaction-scoped advisory locks taken in
  ascending suggestion order, so concurrent runs neither race on creation nor deadlock.
"""

import logging
import uuid
from collections import Counter, defaultdict
from collections.abc import Collection, Iterable, Iterator, Sequence
from dataclasses import dataclass, field
from typing import Any

from django.db import connection, transaction
from django.db.models import F, Q
from django.utils import timezone

from shared.candidates import candidates
from shared.models.cve import AffectedProduct
from shared.models.linkage import CVEDerivationClusterProposal
from shared.models.matching import Exposure, Match, TrackerEvent, Verdict
from shared.models.nix_evaluation import NixChannel, NixEvaluation, NixpkgsBranch
from shared.models.remediation import FixLanding
from shared.models.snapshot import BranchPackage, BranchPackageChange
from shared.versions import (
    Classification,
    ProductVersions,
    classify,
    products_from_rows,
)

logger = logging.getLogger(__name__)

Observed = Exposure.Observed
Reason = Exposure.Reason
EventKind = TrackerEvent.Kind
Cause = TrackerEvent.Cause
Rejection = CVEDerivationClusterProposal.RejectionReason

# An attribute missing from a branch is `removed` (rather than merely `absent`) once this many
# completed evaluations of the branch, newer than the last one it was seen in, lack it.
# One missing evaluation is usually an evaluation failure of that attribute (1.8, problem 2).
REMOVAL_AFTER_EVALUATIONS = 3

# Rejections that say "nothing in nixpkgs is affected by this CVE". The others
# (`no_matches`, `max_matches_exceeded`, `known_vulnerability`) are matcher outcomes.
DISMISSING_REJECTIONS = (
    Rejection.EXCLUSIVELY_HOSTED_SERVICE,
    Rejection.NOT_IN_NIXPKGS,
    Rejection.HARDWARE_ONLY_CPE,
)

# Keys of `Exposure.detail` that are bookkeeping, not part of the observation.
LAST_AFFECTED_VERSION = "last_affected_version"
BOOKKEEPING_KEYS = (LAST_AFFECTED_VERSION,)

_ADVISORY_NAMESPACE = 0x45585030  # "EXP0"
_CHUNK = 200


def dismissed_q(prefix: str = "") -> Q:
    """Suggestions rejected for a CVE-level reason, or by a human without a reason."""
    return Q(**{f"{prefix}status": CVEDerivationClusterProposal.Status.REJECTED}) & (
        Q(**{f"{prefix}rejection_reason__isnull": True})
        | Q(**{f"{prefix}rejection_reason__in": DISMISSING_REJECTIONS})
    )


def is_dismissed(status: str, rejection_reason: str | None) -> bool:
    return status == CVEDerivationClusterProposal.Status.REJECTED and (
        rejection_reason is None or rejection_reason in DISMISSING_REJECTIONS
    )


def tracked_branches() -> list[NixpkgsBranch]:
    """Branches with a channel in a tracked state."""
    return list(
        NixpkgsBranch.objects.filter(channels__state__in=NixChannel.TRACKED_STATES)
        .select_related("current_evaluation")
        .distinct()
        .order_by("name")
    )


# --- Observation ----------------------------------------------------------------------------


@dataclass(frozen=True)
class Observation:
    """What an `Exposure` row should say about a `BranchPackage` row right now."""

    present: bool
    version: str | None
    observed: str
    reason: str
    detail: dict[str, Any]


def classification_detail(c: Classification) -> dict[str, Any]:
    detail: dict[str, Any] = {"detail": c.detail}
    if c.inferred:
        detail["inferred"] = True
    if c.product is not None and c.product.id is not None:
        detail["affected_product"] = c.product.id
    if c.entry is not None and c.entry.id is not None:
        detail["version_entry"] = c.entry.id
    if c.range is not None:
        detail["range"] = str(c.range)
        detail["range_source"] = c.range.source
    return detail


def observe(
    package: BranchPackage,
    cve_id: str,
    products: Sequence[ProductVersions],
    removed: bool = False,
    previous: Exposure | None = None,
    strict: bool = False,
) -> Observation:
    """
    The observation for one attribute on one branch.
    Listing the CVE in `meta.knownVulnerabilities` makes it affected whatever the version (#1376).
    """
    if not package.present:
        reason = (
            Reason.REMOVED
            if removed
            else previous.reason
            if previous is not None and previous.reason != Reason.REMOVED
            else Reason.NO_RANGE
        )
        return Observation(
            present=False,
            version=package.version or (previous.version if previous else None),
            observed=Observed.ABSENT,
            reason=reason,
            detail={"last_seen_evaluation": package.evaluation_id},
        )
    if cve_id in package.known_vulnerabilities:
        return Observation(
            present=True,
            version=package.version,
            observed=Observed.AFFECTED,
            reason=Reason.ACKNOWLEDGED,
            detail={"detail": f"{cve_id} in meta.knownVulnerabilities"},
        )
    c = classify(package.version, products, strict)
    return Observation(
        present=True,
        version=package.version,
        observed=str(c.status),
        reason=str(c.reason),
        detail=classification_detail(c),
    )


# --- Writing --------------------------------------------------------------------------------


def _newer(a: NixEvaluation, b: NixEvaluation) -> bool:
    return (a.created_at, a.pk) > (b.created_at, b.pk)


def _observation_detail(detail: dict[str, Any]) -> dict[str, Any]:
    return {k: v for k, v in detail.items() if k not in BOOKKEEPING_KEYS}


def _decision(obs: Observation) -> tuple[Any, ...]:
    """What decided the status: a change here is a status change even at the same status."""
    d = obs.detail
    return (
        obs.observed,
        obs.reason,
        d.get("inferred", False),
        d.get("affected_product"),
        d.get("version_entry"),
        d.get("range"),
    )


@dataclass
class _Run:
    cause: str
    batch: uuid.UUID
    events: list[TrackerEvent] = field(default_factory=list)

    def counts(self) -> Counter[str]:
        return Counter(e.kind for e in self.events)


def _write(
    run: _Run,
    row: Exposure | None,
    obs: Observation,
    *,
    suggestion_id: int,
    attrpath: str,
    branch: NixpkgsBranch,
    evaluation: NixEvaluation | None,
    previous_evaluation: NixEvaluation | None,
) -> Exposure:
    """
    Bring one row to `obs`, keep the transition bookkeeping, and queue at most one event.

    Bookkeeping:
    - `first_affected_evaluation`: first evaluation observed affected.
    - `evaluation`: the evaluation at which the row's current state was established. Rows are
      written only when something visible changes, so a no-op run writes nothing.
    - `last_affected_evaluation`: last evaluation known affected. Set on every affected write;
      when the row leaves affected, it is the evaluation before the change (the old side of
      the evaluation step on the differential path, the row's previous `evaluation` on a full
      reconciliation, which is coarser), and brackets the fix with `fixed_evaluation`.
    - `fixed_evaluation`: set when the row is observed unaffected while it has been affected
      and not fixed since. This includes affected -> unknown or absent -> unaffected: the fix
      lies between `last_affected_evaluation` and `fixed_evaluation` either way. Unknown ->
      unaffected without a known affected state is not a fix (nothing was known affected).
    - Affected again after `fixed_evaluation`: a regression. `fixed_evaluation` is cleared,
      the event carries `regression: true` and the previous fix evaluation.
    """
    data_extra: dict[str, Any] = {}
    if row is None:
        row = Exposure(
            suggestion_id=suggestion_id,
            attrpath=attrpath,
            branch=branch,
            present=obs.present,
            version=obs.version,
            observed=obs.observed,
            reason=obs.reason,
            detail=dict(obs.detail),
            evaluation=evaluation,
        )
        if obs.observed == Observed.AFFECTED:
            row.first_affected_evaluation = evaluation
            row.last_affected_evaluation = evaluation
            row.detail[LAST_AFFECTED_VERSION] = obs.version
        row.save()
        _event(run, row, EventKind.EXPOSURE_APPEARED, evaluation, None, obs)
        return row

    if (
        row.evaluation is not None
        and evaluation is not None
        and _newer(row.evaluation, evaluation)
    ):
        # A late run for an older evaluation step must not overwrite newer state.
        return row

    old = Observation(
        present=row.present,
        version=row.version,
        observed=row.observed,
        reason=row.reason,
        detail=_observation_detail(row.detail),
    )
    open_affected = (
        row.first_affected_evaluation_id is not None and row.fixed_evaluation_id is None
    )
    fix_candidate = obs.observed == Observed.UNAFFECTED and open_affected
    regression = (
        obs.observed == Observed.AFFECTED and row.fixed_evaluation_id is not None
    )
    reappearing = not old.present and obs.present

    kind: str
    if old.present and not obs.present:
        kind = EventKind.EXPOSURE_DISAPPEARED
    elif fix_candidate:
        kind = EventKind.EXPOSURE_BECAME_UNAFFECTED
    elif regression:
        kind = EventKind.EXPOSURE_BECAME_AFFECTED
    elif reappearing:
        kind = EventKind.EXPOSURE_REAPPEARED
    elif obs.observed == Observed.AFFECTED and old.observed != Observed.AFFECTED:
        kind = EventKind.EXPOSURE_BECAME_AFFECTED
    elif _decision(old) != _decision(obs):
        kind = EventKind.EXPOSURE_STATUS_CHANGED
    elif old.version != obs.version:
        kind = EventKind.EXPOSURE_VERSION_CHANGED
    else:
        # Nothing a user could see changed: no write, no event.
        return row

    detail = dict(obs.detail)
    if LAST_AFFECTED_VERSION in row.detail:
        detail[LAST_AFFECTED_VERSION] = row.detail[LAST_AFFECTED_VERSION]
    if reappearing:
        data_extra["reappeared"] = True
    if obs.observed == Observed.AFFECTED:
        if row.first_affected_evaluation_id is None:
            row.first_affected_evaluation = evaluation
        if regression:
            data_extra["regression"] = True
            data_extra["previous_fixed_evaluation"] = row.fixed_evaluation_id
            row.fixed_evaluation = None
            data_extra |= _retract_fix(row)
        row.last_affected_evaluation = evaluation
        detail[LAST_AFFECTED_VERSION] = obs.version
    elif old.observed == Observed.AFFECTED and previous_evaluation is not None:
        row.last_affected_evaluation = previous_evaluation
    if fix_candidate:
        row.fixed_evaluation = evaluation
        data_extra["fix_candidate"] = True
        if old.observed != Observed.AFFECTED:
            data_extra["via"] = old.observed

    row.present = obs.present
    row.version = obs.version
    row.observed = obs.observed
    row.reason = obs.reason
    row.detail = detail
    if evaluation is not None:
        row.evaluation = evaluation
    row.save()
    _event(run, row, kind, evaluation, old, obs, data_extra)
    return row


def _retract_fix(row: Exposure) -> dict[str, Any]:
    """
    A regression voids the fix: its channel landings are retracted (kept, with a time) and the
    fix commit is cleared, so the next fix is recorded and lands anew. Reported in the event.
    """
    data: dict[str, Any] = {}
    landings = FixLanding.objects.live().filter(exposure=row)
    channels = sorted(landings.values_list("channel_id", flat=True))
    if channels:
        landings.update(retracted_at=timezone.now())
        data["retracted_landings"] = channels
    if row.fix_commit is not None:
        data["previous_fix_commit"] = row.fix_commit
        row.fix_commit = None
    return data


def _event(
    run: _Run,
    row: Exposure,
    kind: str,
    evaluation: NixEvaluation | None,
    old: Observation | None,
    new: Observation,
    extra: dict[str, Any] | None = None,
) -> None:
    data: dict[str, Any] = {
        "old_version": old.version if old else None,
        "new_version": new.version,
        "old_status": old.observed if old else None,
        "new_status": new.observed,
        "old_reason": old.reason if old else None,
        "new_reason": new.reason,
    }
    if "detail" in new.detail:
        data["detail"] = new.detail["detail"]
    if new.detail.get("inferred"):
        data["inferred"] = True
    data |= extra or {}
    run.events.append(
        TrackerEvent(
            suggestion_id=row.suggestion_id,
            kind=kind,
            attrpath=row.attrpath,
            branch_id=row.branch_id,
            cause=run.cause,
            evaluation=evaluation,
            data=data,
            batch=run.batch,
        )
    )


def fixed_by_reclassification(exposures: Iterable[Exposure]) -> set[int]:
    """
    Exposures whose current fix is a reclassification, not a package change: the
    `exposure_became_unaffected` event that set `fixed_evaluation` came from a CVE update,
    a matcher or a mapping (not an evaluation) and kept the version. Their fix point is not a
    commit that fixed anything, so it has no channel landing. An exact `fix_commit` (from a
    pull request or a patch) always counts as a change.
    """
    rows = [
        e for e in exposures if e.fixed_evaluation_id is not None and not e.fix_commit
    ]
    if not rows:
        return set()
    wanted = {
        (e.suggestion_id, e.attrpath, e.branch_id, e.fixed_evaluation_id): e.pk
        for e in rows
    }
    latest: dict[tuple[int, str, str, int], tuple[str, Any]] = {}
    for sid, attr, branch, evaluation, cause, data in (
        TrackerEvent.objects.filter(
            kind=EventKind.EXPOSURE_BECAME_UNAFFECTED,
            suggestion_id__in={e.suggestion_id for e in rows},
            evaluation_id__in={e.fixed_evaluation_id for e in rows},
        )
        .order_by("pk")
        .values_list(
            "suggestion_id", "attrpath", "branch_id", "evaluation_id", "cause", "data"
        )
    ):
        latest[(sid, attr, branch, evaluation)] = (cause, data)
    result = set()
    for key, pk in wanted.items():
        cause, data = latest.get(key, (Cause.EVALUATION, {}))
        if cause != Cause.EVALUATION and data.get("old_version") == data.get(
            "new_version"
        ):
            result.add(pk)
    return result


def lock_suggestions(suggestion_ids: Iterable[int]) -> None:
    """Serialise exposure writers per suggestion until the end of the transaction."""
    ids = sorted(set(suggestion_ids))
    if not ids:
        return
    with connection.cursor() as cursor:
        cursor.execute(
            "SELECT pg_advisory_xact_lock(%s, id) FROM unnest(%s::int[]) AS id ORDER BY id",
            [_ADVISORY_NAMESPACE, ids],
        )


def _removal_due(package: BranchPackage, evaluation: NixEvaluation | None) -> bool:
    """Whether a missing attribute has stayed missing long enough to call it removed."""
    if package.present or evaluation is None:
        return False
    last_seen = package.evaluation
    missed = NixEvaluation.objects.filter(
        on_branches=package.branch_id,
        state=NixEvaluation.EvaluationState.COMPLETED,
        created_at__gt=last_seen.created_at,
        created_at__lte=evaluation.created_at,
    ).count()
    return missed >= REMOVAL_AFTER_EVALUATIONS


# --- Context: which attributes matter and against which products ---------------------------


@dataclass
class _Context:
    """Prefetched facts for a set of suggestions."""

    cve_id: dict[int, str]
    relevant: set[tuple[int, str]]
    products: dict[int, list[ProductVersions]]
    scope: dict[tuple[int, str], set[int]]

    def products_for(self, suggestion_id: int, attrpath: str) -> list[ProductVersions]:
        """
        The affected products the attribute's matches came from, together with the CVE's
        other products of the same identity (vendor, product, package name): those describe
        the same thing, like the kernel CNA's git and semver products, and evidence stored
        before `affected_products` existed names only one of them. All of the CVE's products
        when no match names one (or the named ones are no longer part of the record).
        """
        everything = self.products.get(suggestion_id, [])
        wanted = self.scope.get((suggestion_id, attrpath))
        if wanted:
            keys = {p.key for p in everything if p.id in wanted}
            scoped = [p for p in everything if p.id in wanted or p.key in keys]
            if scoped:
                return scoped
        return everything


def evidence_products(evidence: object) -> set[int]:
    """
    The affected product pks a match names: `affected_products` (every source of a merged
    view product), and `affected_product` (the first, the only one stored before).
    """
    if not isinstance(evidence, dict):
        return set()
    named = evidence.get("affected_products")
    pks = (
        {pk for pk in named if isinstance(pk, int)}
        if isinstance(named, list)
        else set()
    )
    first = evidence.get("affected_product")
    if isinstance(first, int):
        pks.add(first)
    return pks


def _load_context(
    suggestion_ids: Collection[int], attrpaths: Collection[str] | None = None
) -> _Context:
    suggestions = CVEDerivationClusterProposal.objects.filter(
        pk__in=suggestion_ids
    ).values_list("pk", "cve_id", "cve__cve_id")
    cve_id = {pk: cve for pk, _, cve in suggestions}
    cve_pk = {pk: cve for pk, cve, _ in suggestions}

    match_filter = Q(suggestion_id__in=suggestion_ids)
    if attrpaths is not None:
        match_filter &= Q(attrpath__in=attrpaths)
    active_scope: dict[tuple[int, str], set[int]] = defaultdict(set)
    retracted_scope: dict[tuple[int, str], set[int]] = defaultdict(set)
    relevant: set[tuple[int, str]] = set()
    for sid, attr, evidence, retracted_at in Match.objects.filter(
        match_filter
    ).values_list("suggestion_id", "attrpath", "evidence", "retracted_at"):
        key = (sid, attr)
        named = evidence_products(evidence)
        if retracted_at is None:
            relevant.add(key)
            active_scope[key] |= named
        else:
            retracted_scope[key] |= named
    relevant |= set(
        Verdict.objects.filter(match_filter).values_list("suggestion_id", "attrpath")
    )
    scope = {
        key: active_scope.get(key) or retracted_scope.get(key, set())
        for key in relevant
    }

    rows = (
        AffectedProduct.objects.filter(container__cve_id__in=set(cve_pk.values()))
        .filter(Q(package_name__isnull=False) | Q(product__isnull=False))
        .annotate(cve_pk=F("container__cve_id"))
        .prefetch_related("versions")
        .order_by("pk")
    )
    by_cve: dict[int, list[AffectedProduct]] = defaultdict(list)
    seen: set[tuple[int, int]] = set()
    for ap in rows:
        key = (ap.cve_pk, ap.pk)  # pyright: ignore [reportAttributeAccessIssue]
        if key not in seen:
            seen.add(key)
            by_cve[key[0]].append(ap)
    products = {
        sid: products_from_rows(by_cve.get(cve, [])) for sid, cve in cve_pk.items()
    }
    return _Context(cve_id=cve_id, relevant=relevant, products=products, scope=scope)


# --- Entry points ---------------------------------------------------------------------------


@dataclass
class ExposureResult:
    batch: uuid.UUID
    events: Counter[str] = field(default_factory=Counter)
    # `added` attributes no suggestion references: input for reverse matching.
    unreferenced_added: list[str] = field(default_factory=list)
    # Affected exposures whose derivation was rebuilt with the same version (#1434 seam).
    rebuilt_affected: list[int] = field(default_factory=list)
    skipped_dismissed: list[int] = field(default_factory=list)
    # Suggestions with at least one exposure event in this run.
    touched: set[int] = field(default_factory=set)


def reconcile_exposures(
    suggestion: CVEDerivationClusterProposal,
    cause: str,
    batch: uuid.UUID | None = None,
    strict: bool = False,
) -> ExposureResult:
    """
    Make every `Exposure` of the suggestion say what `BranchPackage` and the classifier say
    now, for every attribute that has an active match or a verdict, on every tracked branch.
    Rows are labelled with the branch's current evaluation.
    """
    result = ExposureResult(batch=batch or uuid.uuid4())
    run = _Run(cause=cause, batch=result.batch)
    branches = tracked_branches()
    with transaction.atomic():
        lock_suggestions([suggestion.pk])
        status, rejection = CVEDerivationClusterProposal.objects.values_list(
            "status", "rejection_reason"
        ).get(pk=suggestion.pk)
        if is_dismissed(status, rejection):
            result.skipped_dismissed.append(suggestion.pk)
            return result
        ctx = _load_context([suggestion.pk])
        attrs = {a for s, a in ctx.relevant if s == suggestion.pk} & (
            candidates([suggestion.pk])[suggestion.pk].attributes
        )
        packages = {
            (p.branch_id, p.attrpath): p
            for p in BranchPackage.objects.filter(
                branch__in=branches, attrpath__in=attrs
            ).select_related("evaluation")
        }
        rows = {
            (r.branch_id, r.attrpath): r
            for r in Exposure.objects.filter(
                suggestion=suggestion, attrpath__in=attrs
            ).select_related("evaluation")
        }
        for branch in branches:
            for attr in sorted(attrs):
                package = packages.get((branch.name, attr))
                if package is None:
                    continue
                evaluation = branch.current_evaluation or package.evaluation
                row = rows.get((branch.name, attr))
                obs = observe(
                    package,
                    ctx.cve_id[suggestion.pk],
                    ctx.products_for(suggestion.pk, attr),
                    removed=_removal_due(package, evaluation),
                    previous=row,
                    strict=strict,
                )
                _write(
                    run,
                    row,
                    obs,
                    suggestion_id=suggestion.pk,
                    attrpath=attr,
                    branch=branch,
                    evaluation=evaluation,
                    previous_evaluation=row.evaluation if row else None,
                )
        TrackerEvent.objects.bulk_create(run.events)
    result.events = run.counts()
    result.touched = {e.suggestion_id for e in run.events}
    return result


def detect_patch_fix(exposure: Exposure, change: BranchPackageChange) -> None:
    """
    Seam for patch detection (#1434): called for an affected exposure whose derivation was
    rebuilt with an unchanged version. Intentionally does nothing yet; the design is to look
    for commits touching the package file between the two evaluations that mention the CVE,
    and record a fix candidate with reason `patch`.
    """


def apply_branch_changes(
    evaluation: NixEvaluation,
    branch: NixpkgsBranch,
    batch: uuid.UUID | None = None,
    strict: bool = False,
) -> ExposureResult:
    """
    Update exposures for one evaluation step of one branch from its `BranchPackageChange`
    rows. Work is proportional to the changed attributes that some suggestion references,
    plus the rows of this branch still waiting to be called `removed`.

    Per change kind: `version_changed` and `meta_changed` re-run the classifier (and the
    knownVulnerabilities check); `removed` marks the row absent, and `removed` as reason only
    after `REMOVAL_AFTER_EVALUATIONS`; `added` creates or revives rows for referenced
    attributes and reports unreferenced ones; `rebuilt` calls `detect_patch_fix` for affected
    rows and changes nothing.
    """
    result = ExposureResult(batch=batch or uuid.uuid4())
    run = _Run(cause=Cause.EVALUATION, batch=result.batch)
    changes = BranchPackageChange.objects.filter(
        new_evaluation=evaluation, branch=branch
    )
    changed_attrs = changes.values("attrpath")
    referenced = set(
        Match.objects.active()
        .filter(attrpath__in=changed_attrs)
        .values_list("suggestion_id", "attrpath")
    ) | set(
        Verdict.objects.filter(attrpath__in=changed_attrs).values_list(
            "suggestion_id", "attrpath"
        )
    )
    pending_removal = set(
        Exposure.objects.filter(branch=branch, present=False)
        .exclude(reason=Reason.REMOVED)
        .values_list("suggestion_id", "attrpath")
    )
    referenced_attrs = {a for _, a in referenced}
    result.unreferenced_added = sorted(
        changes.filter(kind=BranchPackageChange.Kind.ADDED)
        .exclude(attrpath__in=referenced_attrs)
        .values_list("attrpath", flat=True)
    )

    work: dict[int, set[str]] = defaultdict(set)
    for sid, attr in referenced | pending_removal:
        work[sid].add(attr)
    dismissed = set(
        CVEDerivationClusterProposal.objects.filter(pk__in=work.keys())
        .filter(dismissed_q())
        .values_list("pk", flat=True)
    )
    result.skipped_dismissed = sorted(dismissed)
    # Only candidates (`shared.candidates`): a hidden match keeps no exposure current.
    shown = candidates(set(work) - dismissed)
    for sid in list(work):
        work[sid] &= shown[sid].attributes if sid in shown else set()
    suggestion_ids = sorted(sid for sid in set(work) - dismissed if work[sid])
    if not suggestion_ids:
        return result

    for chunk in _chunks(suggestion_ids, _CHUNK):
        attrs = set().union(*(work[s] for s in chunk))
        change_by_attr = {
            c.attrpath: c
            for c in changes.filter(attrpath__in=attrs).select_related("old_evaluation")
        }
        with transaction.atomic():
            lock_suggestions(chunk)
            ctx = _load_context(chunk, attrs)
            packages = {
                p.attrpath: p
                for p in BranchPackage.objects.filter(
                    branch=branch, attrpath__in=attrs
                ).select_related("evaluation")
            }
            rows = {
                (r.suggestion_id, r.attrpath): r
                for r in Exposure.objects.filter(
                    suggestion_id__in=chunk, branch=branch, attrpath__in=attrs
                ).select_related("evaluation")
            }
            for sid in chunk:
                for attr in sorted(work[sid]):
                    if (sid, attr) not in ctx.relevant:
                        continue
                    package = packages.get(attr)
                    if package is None:
                        continue
                    row = rows.get((sid, attr))
                    change = change_by_attr.get(attr)
                    if change is not None and change.kind == (
                        BranchPackageChange.Kind.REBUILT
                    ):
                        if row is not None and row.observed == Observed.AFFECTED:
                            detect_patch_fix(row, change)
                            result.rebuilt_affected.append(row.pk)
                        if row is not None:
                            continue
                    obs = observe(
                        package,
                        ctx.cve_id[sid],
                        ctx.products_for(sid, attr),
                        removed=_removal_due(package, evaluation),
                        previous=row,
                        strict=strict,
                    )
                    _write(
                        run,
                        row,
                        obs,
                        suggestion_id=sid,
                        attrpath=attr,
                        branch=branch,
                        evaluation=evaluation,
                        previous_evaluation=(
                            change.old_evaluation
                            if change is not None
                            else row.evaluation
                            if row is not None
                            else None
                        ),
                    )
            TrackerEvent.objects.bulk_create(run.events)
            result.events += run.counts()
            result.touched |= {e.suggestion_id for e in run.events}
            run.events = []
    return result


def _chunks(items: Sequence[int], size: int) -> Iterator[Sequence[int]]:
    for i in range(0, len(items), size):
        yield items[i : i + size]
