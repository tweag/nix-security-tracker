"""
The live write path over the unified model: what happens when a CVE arrives or changes, when a
branch's snapshot advances, and when matchers change. Each path reconciles `Match`, then
`Exposure`, then the compatibility projection (`shared.projection`), then the cache.

Entry points:
- `build_new_links(container)`: a container was ingested (one suggestion per CVE, F1).
- `on_cve_record_changed(cve_pk)`: a known CVE record changed (reconciles or creates).
- `apply_evaluation(evaluation, branch)`: a branch's snapshot advanced to `evaluation`.
- `refresh_suggestion(suggestion)`: re-run stale matchers (deploy-time re-match), then
  projection and cache; also what the evaluation path fans out for suggestions it did not touch.
- `reverse_match_attributes(attrpaths, ...)`: open suggestions new or changed attributes may belong to.

Status rules (F3, F4): the stored status is decided once, at creation: pending if there is
something to show, rejected `no_matches` if not, rejected `known_vulnerability` if nixpkgs
already lists the CVE. Re-matching never rejects; it only reopens `no_matches` and
`max_matches_exceeded` rejections (to pending) when it finds something to show.
"""

import logging
import uuid
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from typing import Any

import pghistory
import pgpubsub
from django.contrib.auth.models import User
from django.db import connection, transaction
from django.db.models import Exists, OuterRef, Q
from django.utils import timezone

from shared.cache_suggestions import cache_new_suggestions
from shared.channels import (
    PatchDetectionChannel,
    SuggestionRefreshChannel,
    SuggestionRematchChannel,
)
from shared.derived_state import flush_derived_states
from shared.exposure import (
    ExposureResult,
    apply_branch_changes,
    dismissed_q,
    reconcile_exposures,
)
from shared.legacy_backfill import ensure_backfilled
from shared.locking import lock_for_write
from shared.matching.base import MatcherResult, Universe
from shared.matching.matchers import collect_candidates
from shared.matching.reconcile import ReconcileResult, reconcile_matches
from shared.matching.selection import (
    KNOWN_VULNERABILITY_MATCHER,
    LEGACY_MATCHER,
    current_matcher_versions,
    enabled_matchers,
    select_attributes,
)
from shared.matching.view import CveView, build_cve_view
from shared.models.cve import Container, CveRecord
from shared.models.linkage import (
    MACHINE_REOPENABLE_REJECTIONS,
    CVEDerivationClusterProposal,
    DerivationClusterProposalLink,
)
from shared.models.matching import Match, TrackerEvent
from shared.models.nix_evaluation import NixEvaluation, NixpkgsBranch
from shared.models.snapshot import BranchPackage, BranchPackageChange
from shared.projection import ProjectionResult, is_frozen_for_projection, project_links

logger = logging.getLogger(__name__)

Status = CVEDerivationClusterProposal.Status
Rejection = CVEDerivationClusterProposal.RejectionReason
Cause = TrackerEvent.Cause
Change = BranchPackageChange.Kind

_CVE_LOCK_NAMESPACE = 0x43564530  # "CVE0"


def lock_cve(cve_id: str) -> None:
    """Serialise suggestion creation and re-matching per CVE id until the end of the transaction."""
    with connection.cursor() as cursor:
        cursor.execute(
            "SELECT pg_advisory_xact_lock(%s, hashtext(%s))",
            [_CVE_LOCK_NAMESPACE, cve_id],
        )


def find_suggestion(cve_id: str) -> CVEDerivationClusterProposal | None:
    """
    The suggestion of a CVE id. Production has duplicates (one per algorithm version, and
    duplicate `CveRecord` rows of one id); prefer the newest algorithm version, then the newest.
    """
    return (
        CVEDerivationClusterProposal.objects.filter(cve__cve_id=cve_id)
        .order_by("-algorithm_version", "-pk")
        .first()
    )


def open_for_projection_q(prefix: str = "") -> Q:
    """Suggestions whose links the projection maintains."""
    return ~Q(**{f"{prefix}status": Status.PUBLISHED}) & ~dismissed_q(prefix)


# --- Creation -------------------------------------------------------------------------------


def _create(
    cve: CveRecord,
    status: str,
    rejection_reason: str | None,
    matcher_versions: dict[str, int],
) -> CVEDerivationClusterProposal:
    return CVEDerivationClusterProposal.objects.create(
        cve=cve,
        status=status,
        rejection_reason=rejection_reason,
        algorithm_version=CVEDerivationClusterProposal.CURRENT_ALGORITHM_VERSION,
        matcher_versions=matcher_versions,
    )


def build_new_links(container: Container) -> bool:
    """A container was ingested. Returns whether a suggestion was created (`ensure_suggestion`)."""
    return ensure_suggestion(container.cve)


def on_cve_record_changed(cve_pk: int) -> bool:
    """
    The CVE record `cve_pk` changed (affected products, versions, CPEs, hosted-service tag):
    reconcile its suggestion, or create it if the CVE has none yet (an update never inserts a
    container, so the container path did not run). Returns whether a suggestion was created.
    The channel that calls this is defined with CVE update ingestion.
    """
    return ensure_suggestion(CveRecord.objects.get(pk=cve_pk))


def ensure_suggestion(cve: CveRecord) -> bool:
    """
    Make sure the CVE has its one suggestion, current with all its containers. Returns
    whether one was created.

    Under a lock on the CVE id: if the CVE already has a suggestion, this is a CVE update and
    every enabled matcher is reconciled on the new view (cause `cve_update`), then exposures,
    links and cache; otherwise the matchers run over the view of all containers and the
    suggestion is created with its matches, exposures and links in one transaction, so the
    insert notification (cache, subscribers) sees them.
    """
    cve_id = cve.cve_id
    if cve.triaged:
        logger.info("'%s' is already triaged, skipping.", cve_id)
        return False

    with transaction.atomic():
        lock_cve(cve_id)
        existing = find_suggestion(cve_id)
        if existing is not None:
            logger.info(
                "Suggestion %d exists for '%s', reconciling with the CVE's current data",
                existing.pk,
                cve_id,
            )
            refresh_suggestion(existing, Cause.CVE_UPDATE, matchers=enabled_matchers())
            return False

        view = build_cve_view(cve_id)
        if view.exclusively_hosted_service:
            logger.info("'%s' is an exclusively hosted service, rejecting.", cve_id)
            _create(cve, Status.REJECTED, Rejection.EXCLUSIVELY_HOSTED_SERVICE, {})
            return True
        if view.hardware_only:
            logger.info("'%s' has only hardware CPEs, rejecting.", cve_id)
            _create(cve, Status.REJECTED, Rejection.HARDWARE_ONLY_CPE, {})
            return True

        matchers = enabled_matchers()
        results = collect_candidates(view, matchers)
        selection = select_attributes(
            (c.attrpath, slug, c.score)
            for slug, result in results.items()
            for c in result.candidates
        )
        known = results.get(KNOWN_VULNERABILITY_MATCHER, MatcherResult()).candidates
        if known:
            status, reason = Status.REJECTED, Rejection.KNOWN_VULNERABILITY
        elif not selection.shown:
            status, reason = Status.REJECTED, Rejection.NO_MATCHES
        else:
            status, reason = Status.PENDING, None
        suggestion = _create(cve, status, reason, current_matcher_versions(matchers))
        reconcile_matches(
            suggestion, Cause.CVE_UPDATE, matchers, view=view, results=results
        )
        batch = uuid.uuid4()
        reconcile_exposures(suggestion, Cause.CVE_UPDATE, batch=batch)
        projection = project_links(suggestion)
        flush_derived_states([suggestion.pk])
        logger.info(
            "Created suggestion %d for '%s' (%s %s): %d attributes shown, %d below threshold, %d beyond cap",
            suggestion.pk,
            cve_id,
            status,
            reason or "",
            len(projection.attributes),
            selection.below_threshold,
            selection.beyond_cap,
        )
    return True


# --- Re-matching ----------------------------------------------------------------------------


@dataclass
class RematchResult:
    frozen: bool = False
    matches: ReconcileResult | None = None
    legacy_retracted: int = 0
    exposures: ExposureResult | None = None
    projection: ProjectionResult = field(default_factory=ProjectionResult)
    reopened: bool = False

    @property
    def needs_cache(self) -> bool:
        """Links or matches may have moved, or an exposure (the shown status) changed."""
        return not self.frozen or bool(self.exposures and self.exposures.touched)

    @property
    def changed(self) -> bool:
        return bool(
            (self.matches and self.matches.events)
            or self.legacy_retracted
            or (self.exposures and self.exposures.touched)
            or self.projection.changed
            or self.reopened
        )


def retire_legacy_matches(
    suggestion: CVEDerivationClusterProposal, batch: uuid.UUID
) -> int:
    """Retract the backfilled `legacy-v2` matches, once the real matchers have run."""
    rows = list(
        Match.objects.active().filter(suggestion=suggestion, matcher=LEGACY_MATCHER)
    )
    if not rows:
        return 0
    Match.objects.filter(pk__in=[m.pk for m in rows]).update(
        retracted_at=timezone.now()
    )
    TrackerEvent.objects.bulk_create(
        TrackerEvent(
            suggestion=suggestion,
            kind=TrackerEvent.Kind.MATCH_RETRACTED,
            attrpath=m.attrpath,
            matcher=LEGACY_MATCHER,
            cause=Cause.MATCHER,
            data={"score": m.score, "superseded": True},
            batch=batch,
        )
        for m in rows
    )
    return len(rows)


def _reopen_if_matched(
    suggestion: CVEDerivationClusterProposal, projection: ProjectionResult
) -> bool:
    if not (
        suggestion.status == Status.REJECTED
        and suggestion.rejection_reason in MACHINE_REOPENABLE_REJECTIONS
        and projection.attributes - projection.unmatched
    ):
        return False
    suggestion.status = Status.PENDING
    suggestion.rejection_reason = None
    suggestion.rejection_match_count = None
    suggestion.rejection_max_matches_limit = None
    with pghistory.context(system=True):
        suggestion.save(
            update_fields=[
                "status",
                "rejection_reason",
                "rejection_match_count",
                "rejection_max_matches_limit",
                "in_issue_draft",
                "updated_at",
            ]
        )
    logger.info("Reopened suggestion %d: the re-match found matches", suggestion.pk)
    return True


def rematch(
    suggestion: CVEDerivationClusterProposal,
    cause: TrackerEvent.Cause,
    matchers: Sequence[str] | None = None,
    *,
    evaluation: NixEvaluation | None = None,
    exposures: bool = True,
    view: CveView | None = None,
    universe: Universe | None = None,
    actor: User | None = None,
) -> RematchResult:
    """
    Reconcile the given matchers (default: all enabled), then exposures, then the projection.
    Retires the backfilled legacy matches once every enabled matcher has run. Never rejects.
    Published and dismissed suggestions keep their matches and links; published ones still
    get their exposures reconciled (the backport signal).
    """
    matchers = enabled_matchers() if matchers is None else list(matchers)
    result = RematchResult()
    batch = uuid.uuid4()
    with transaction.atomic():
        lock_for_write([suggestion.pk])
        suggestion.refresh_from_db(
            fields=["status", "rejection_reason", "comment", "algorithm_version"]
        )
        # A suggestion of the legacy write path: record what it shows and what humans decided
        # (acceptance, ignores) before anything re-matches it, whether or not
        # `backfill_unified_model` has reached it yet.
        ensure_backfilled(suggestion)
        result.frozen = is_frozen_for_projection(
            suggestion.status, suggestion.rejection_reason
        )
        if not result.frozen and matchers:
            result.matches = reconcile_matches(
                suggestion,
                cause,
                matchers,
                evaluation=evaluation,
                view=view,
                universe=universe,
                actor=actor,
            )
            update: dict[str, Any] = {
                "matcher_versions": {
                    **CVEDerivationClusterProposal.objects.values_list(
                        "matcher_versions", flat=True
                    ).get(pk=suggestion.pk),
                    **current_matcher_versions(matchers),
                }
            }
            if set(enabled_matchers()) <= set(matchers):
                result.legacy_retracted = retire_legacy_matches(suggestion, batch)
                update["algorithm_version"] = (
                    CVEDerivationClusterProposal.CURRENT_ALGORITHM_VERSION
                )
            CVEDerivationClusterProposal.objects.filter(pk=suggestion.pk).update(
                **update
            )
        if exposures:
            result.exposures = reconcile_exposures(suggestion, cause, batch=batch)
        result.projection = project_links(suggestion)
        result.reopened = _reopen_if_matched(suggestion, result.projection)
        # What a user could notice: matches, shown attributes, or their provenance changed.
        # Moving links to a newer evaluation alone is not logged.
        if (
            (result.matches is not None and result.matches.events)
            or result.legacy_retracted
            or result.projection.attributes_changed
            or result.projection.updated
        ):
            with pghistory.context(system=True):
                pghistory.create_event(suggestion, label="rematch")
        flush_derived_states([suggestion.pk])
        if result.needs_cache:
            cache_new_suggestions(suggestion)
    return result


def stale_matchers(suggestion: CVEDerivationClusterProposal) -> list[str]:
    """Enabled matchers whose current version has not run on this suggestion."""
    if (
        suggestion.algorithm_version
        < CVEDerivationClusterProposal.CURRENT_ALGORITHM_VERSION
    ):
        return enabled_matchers()
    ran = suggestion.matcher_versions or {}
    return [
        slug
        for slug, version in current_matcher_versions().items()
        if ran.get(slug) != version
    ]


def stale_q() -> Q:
    """Suggestions matched by the legacy algorithm, or missing a current matcher version."""
    return Q(
        algorithm_version__lt=CVEDerivationClusterProposal.CURRENT_ALGORITHM_VERSION
    ) | ~Q(matcher_versions__contains=current_matcher_versions())


def refresh_suggestion(
    suggestion: CVEDerivationClusterProposal,
    cause: TrackerEvent.Cause = Cause.MATCHER,
    matchers: Sequence[str] | None = None,
    *,
    evaluation: NixEvaluation | None = None,
) -> RematchResult:
    """
    Re-run the given matchers (default: the stale ones), reconcile exposures if any ran,
    project and cache. With nothing stale this only moves links to the current evaluations.
    """
    if matchers is None:
        matchers = stale_matchers(suggestion)
    result = rematch(
        suggestion,
        cause,
        matchers,
        evaluation=evaluation,
        exposures=bool(matchers),
    )
    return result


# --- Evaluation -----------------------------------------------------------------------------


def reverse_match_attributes(
    attrpaths: Sequence[str],
    evaluation: NixEvaluation,
    branch: NixpkgsBranch,
) -> dict[int, set[str]]:
    """
    Reverse matching: the open suggestions whose CVE these new or changed attributes might be
    the product of (`identity.reverse.select_suggestions`: by name, CPE, repository, mapping
    and knownVulnerabilities through the CVE-side product key index). The caller re-matches
    them together with the suggestions found forward, so none is reconciled twice.
    """
    from shared.identity.reverse import select_suggestions

    return select_suggestions(branch, attrpaths)


@dataclass
class EvaluationOutcome:
    exposures: ExposureResult
    # Dispatched to `SuggestionRematchChannel`.
    rematched: list[int] = field(default_factory=list)
    # Exposures changed (dispatched to `SuggestionRefreshChannel` unless re-matched).
    projected: list[int] = field(default_factory=list)
    # Dispatched to `SuggestionRefreshChannel`.
    dispatched: list[int] = field(default_factory=list)
    reverse_candidates: list[str] = field(default_factory=list)
    # Suggestions selected by reverse matching, with the attributes that pointed at them.
    reverse_selected: dict[int, set[str]] = field(default_factory=dict)
    gone: list[str] = field(default_factory=list)


def _gone_attributes(branch: NixpkgsBranch) -> set[str]:
    """
    Attributes with active matches that the matchers no longer see on any tracked branch:
    missing from this branch for at least `REMOVAL_AFTER_EVALUATIONS` completed evaluations
    and not in the matchers' universe (`Universe.packages`: present, or absent for fewer
    evaluations) on any other tracked branch. A single evaluation missing an attribute does
    not make it gone.

    Decided from `BranchPackage` and the evaluation count alone, the same rule the matcher
    universe applies, not from `Exposure` rows: exposures of suggestions that are no longer
    kept current (dismissed, or the attribute no longer a candidate) stay `absent` without
    reason `removed` forever, and one of them must not block the retraction for every other
    suggestion. Self-healing: an attribute missed at its step is picked up at the next one,
    as long as some active match still refers to it.
    """
    universe = Universe.tracked()
    window = dict(universe.absent_since).get(branch.name, ())
    long_absent = BranchPackage.objects.filter(branch=branch, present=False).exclude(
        evaluation_id__in=window
    )
    candidates = set(
        Match.objects.active()
        .filter(attrpath__in=long_absent.values("attrpath"))
        .values_list("attrpath", flat=True)
        .distinct()
    )
    if not candidates:
        return set()
    seen = set(
        universe.packages()
        .filter(attrpath__in=candidates)
        .values_list("attrpath", flat=True)
    )
    return candidates - seen


# Snapshot fields a matcher reads (`shared.snapshot.META_FIELDS` without `position`); the
# generated match keys derive from `pname` and `homepage`.
MATCHING_FIELDS = (
    "pname",
    "cpe_vendor",
    "cpe_product",
    "known_vulnerabilities",
    "homepage",
)


@dataclass
class RematchSelection:
    # Attributes whose matching data changed on the branch: added, or a `MATCHING_FIELDS` change.
    changed: list[str]
    # Suggestions reverse matching selects, with the attributes that point at each; without
    # those pointed at only by new attributes they already match.
    reverse_selected: dict[int, set[str]]
    # Open suggestions with an active match on a changed attribute (not a new one).
    referencing: set[int]


def _redundant_additions(branch: NixpkgsBranch, added: set[str]) -> set[str]:
    """
    Attributes new on `branch` that another tracked branch already has with the same matching
    fields: the matchers' universe gains nothing but a branch name in evidence.
    """
    if not added:
        return set()
    here = {
        row[0]: row[1:]
        for row in BranchPackage.objects.filter(
            branch=branch, attrpath__in=added
        ).values_list("attrpath", *MATCHING_FIELDS)
    }
    elsewhere = (
        Universe.tracked()
        .packages()
        .exclude(branch=branch)
        .filter(attrpath__in=added)
        .values_list("attrpath", *MATCHING_FIELDS)
    )
    return {row[0] for row in elsewhere if here.get(row[0]) == row[1:]}


def _matching_modifications(
    branch: NixpkgsBranch, changes: Iterable[tuple[str, list[str]]]
) -> set[str]:
    """
    Changed attributes whose change a matcher can see. A CPE product without a vendor, before
    and after, matches nothing (`nixpkgs-cpe` needs both parts; nixpkgs defaults the product to
    the pname), so a change of only that is none.
    """
    modified: set[str] = set()
    cpe_only: set[str] = set()
    for attrpath, fields in changes:
        relevant = set(fields) & set(MATCHING_FIELDS)
        (cpe_only if relevant == {"cpe_product"} else modified).add(attrpath)
    if cpe_only:
        modified |= set(
            BranchPackage.objects.filter(branch=branch, attrpath__in=cpe_only)
            .exclude(Q(cpe_vendor__isnull=True) | Q(cpe_vendor=""))
            .values_list("attrpath", flat=True)
        )
    return modified


def rematch_selection(
    evaluation: NixEvaluation, branch: NixpkgsBranch
) -> RematchSelection:
    """
    Which open suggestions an evaluation step can change the candidates of (read only):
    - an attribute whose matching data changed: suggestions actively matching it (they may
      lose or change it) and those reverse matching selects for it (they may gain it);
    - a new attribute: only the suggestions reverse matching selects that do not match it yet.
    A version change, a rebuild, or a moved file change nothing a matcher reads.
    """
    changes = BranchPackageChange.objects.filter(
        new_evaluation=evaluation, branch=branch
    )
    added = set(changes.filter(kind=Change.ADDED).values_list("attrpath", flat=True))
    added -= _redundant_additions(branch, added)
    modified = _matching_modifications(
        branch,
        changes.filter(
            kind__in=[Change.META_CHANGED, Change.VERSION_CHANGED],
            changed_fields__overlap=list(MATCHING_FIELDS),
        ).values_list("attrpath", "changed_fields"),
    )
    changed = sorted(added | modified)
    selected = reverse_match_attributes(changed, evaluation, branch) if changed else {}
    already = set(
        Match.objects.active()
        .filter(attrpath__in=added, suggestion__in=list(selected))
        .values_list("suggestion_id", "attrpath")
    )
    reverse_selected = {
        pk: remaining
        for pk, attrs in selected.items()
        if (remaining := {a for a in attrs if (pk, a) not in already})
    }
    referencing = set(
        Match.objects.active()
        .filter(attrpath__in=modified)
        .filter(open_for_projection_q("suggestion__"))
        .values_list("suggestion_id", flat=True)
        .distinct()
    )
    return RematchSelection(changed, reverse_selected, referencing)


def apply_evaluation(
    evaluation: NixEvaluation, branch: NixpkgsBranch
) -> EvaluationOutcome:
    """
    One evaluation step of one branch, in the listener's transaction, holding as little as
    possible for as short as possible (see `shared.locking`):
    1. read the change set (`rematch_selection`): attributes whose matching data changed, the
       suggestions actively matching them, those reverse matching selects, and those whose
       links point at an older evaluation of this branch (no locks);
    2. exposures of referenced attributes (`apply_branch_changes`: exposure locks, ascending),
       attributes now gone from every tracked branch, and the stored derived state of the
       suggestions whose exposures changed;
    3. dispatch, in the same transaction: `SuggestionRematchChannel` for every suggestion to
       re-match (matches, exposures, links, cache), `SuggestionRefreshChannel` for the others
       whose exposures changed or whose links are behind (links, cache), `PatchDetectionChannel`
       if affected exposures were rebuilt (git, so outside this transaction). Each is
       idempotent and runs in its own transaction with its own locks.
    """
    selection = rematch_selection(evaluation, branch)
    reverse_candidates = selection.changed
    reverse_selected = selection.reverse_selected
    behind = set(
        CVEDerivationClusterProposal.objects.filter(open_for_projection_q())
        .filter(
            Exists(
                DerivationClusterProposalLink.objects.filter(
                    proposal=OuterRef("pk"),
                    derivation__parent_evaluation__on_branches=branch,
                ).exclude(derivation__parent_evaluation=evaluation)
            )
        )
        .values_list("pk", flat=True)
    )

    exposure_result = apply_branch_changes(evaluation, branch)
    outcome = EvaluationOutcome(
        exposures=exposure_result,
        reverse_candidates=reverse_candidates,
        reverse_selected=reverse_selected,
    )
    gone = _gone_attributes(branch)
    outcome.gone = sorted(gone)
    referencing = selection.referencing | {
        sid
        for sid in Match.objects.active()
        .filter(attrpath__in=gone)
        .filter(open_for_projection_q("suggestion__"))
        .values_list("suggestion_id", flat=True)
        .distinct()
    }
    # Not frozen: pending, accepted, and machine rejections (reverse selection returns
    # those within the reopen window).
    selected = set(
        CVEDerivationClusterProposal.objects.filter(pk__in=set(reverse_selected))
        .filter(open_for_projection_q())
        .values_list("pk", flat=True)
    )
    rematch_ids = sorted(referencing | selected)
    touched = set(exposure_result.touched)
    flush_derived_states(touched)

    # In the transaction: delivered on commit, gone on rollback, never lost in between.
    for pk in rematch_ids:
        pgpubsub.notify(SuggestionRematchChannel, pk=pk, evaluation_pk=evaluation.pk)
    outcome.rematched = rematch_ids
    outcome.projected = sorted(touched - set(rematch_ids))
    outcome.dispatched = sorted((behind | touched) - set(rematch_ids))
    for pk in outcome.dispatched:
        pgpubsub.notify(SuggestionRefreshChannel, pk=pk)
    if exposure_result.rebuilt_affected:
        pgpubsub.notify(
            PatchDetectionChannel, evaluation_pk=evaluation.pk, branch=branch.name
        )
    logger.info(
        "Applied evaluation %s to %s: %d rematched, %d projected, %d dispatched, %d reverse candidates",
        evaluation.pk,
        branch.name,
        len(outcome.rematched),
        len(outcome.projected),
        len(outcome.dispatched),
        len(outcome.reverse_candidates),
    )
    return outcome
