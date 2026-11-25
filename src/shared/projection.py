"""
Compatibility projection: keep a suggestion's `DerivationClusterProposalLink` rows in line with
the attributes it shows, so that the readers of `suggestion.derivations` (cache, API,
notifications, GitHub issues, garbage collection, training data) keep working unchanged while
`Match`, `Exposure` and `Verdict` are the source of truth (section 3.1 "Migration", step 3).

What a suggestion shows (`shown_attributes`):
- the best-scored matched attributes (`shared.matching.selection`); for a suggestion rejected
  because nixpkgs already lists the CVE, only the attributes `known-vuln` found;
- every attribute with a `Verdict`: an ignore stays visible as such and can be undone, and
  what a human accepted or published (`affected` verdicts, `record_acceptance`) stays, so a
  re-match never takes an attribute away from a human;
- every attribute already linked if the re-match found nothing at all: a re-match never
  empties a suggestion.
Attributes kept without an active match carry `ProvenanceFlags.NO_LONGER_MATCHED`.

Links point at the derivations of the attribute in the tracked branches' current evaluations.
Where a shown attribute has none on a branch (missing from that evaluation), its existing
links for that branch stay, and an attribute with no current derivation at all keeps all of
its links: the last known record is not dropped.

Frozen suggestions (published, or dismissed: rejected by a human or for a CVE-level reason)
are never touched. `PackageClusterProposalLink` is not maintained: it has no reader.
"""

import logging
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any

from django.db import transaction

from shared.exposure import is_dismissed
from shared.matching.selection import (
    KNOWN_VULNERABILITY_MATCHER,
    LEGACY_MATCHER,
    counted_matchers,
    select_attributes,
)
from shared.models.linkage import (
    CVEDerivationClusterProposal,
    DerivationClusterProposalLink,
    PackageOverlay,
    ProvenanceFlags,
)
from shared.models.matching import Match, Verdict
from shared.models.nix_evaluation import NixChannel, NixDerivation, NixEvaluation

logger = logging.getLogger(__name__)

Status = CVEDerivationClusterProposal.Status
Rejection = CVEDerivationClusterProposal.RejectionReason


def is_frozen_for_projection(status: str, rejection_reason: str | None) -> bool:
    """Published, or dismissed (human rejection, CVE-level rejection)."""
    return status == Status.PUBLISHED or is_dismissed(status, rejection_reason)


def provenance_of(matcher: str, evidence: dict[str, Any]) -> int:
    """Legacy provenance bits for one match."""
    if matcher == LEGACY_MATCHER:
        return int(evidence.get("provenance_flags", 0))
    if matcher == "nixpkgs-cpe" or evidence.get("cve_field") == "cpe":
        return ProvenanceFlags.CPE_MATCH
    match evidence.get("cve_field"):
        case "package_name":
            return ProvenanceFlags.PACKAGE_NAME_MATCH
        case "product":
            return ProvenanceFlags.PRODUCT_MATCH
    return 0


@dataclass
class Shown:
    # Shown attributes and the provenance flags their links should carry.
    flags: dict[str, int] = field(default_factory=dict)
    # Shown attributes that no active counted match produces.
    unmatched: set[str] = field(default_factory=set)
    # Attributes shown because of a match (not only kept).
    matched: set[str] = field(default_factory=set)
    below_threshold: int = 0
    beyond_cap: int = 0


def shown_attributes(
    suggestion: CVEDerivationClusterProposal,
    linked_flags: dict[str, int] | None = None,
) -> Shown:
    """
    The attributes the suggestion shows and their flags (see the module docstring).
    `linked_flags`: flags of the attributes currently linked, OR-ed per attribute.
    """
    linked_flags = (
        linked_flags if linked_flags is not None else _linked_flags(suggestion)
    )
    matches = list(
        Match.objects.active()
        .filter(suggestion=suggestion, matcher__in=counted_matchers())
        .values_list("attrpath", "matcher", "score", "evidence")
    )
    decided = set(
        Verdict.objects.filter(suggestion=suggestion).values_list("attrpath", flat=True)
    ) | set(
        PackageOverlay.objects.filter(
            suggestion=suggestion, type=PackageOverlay.Type.IGNORED
        ).values_list("package_attribute", flat=True)
    )

    result = Shown()
    if (
        suggestion.status == Status.REJECTED
        and suggestion.rejection_reason == Rejection.KNOWN_VULNERABILITY
    ):
        result.matched = {
            a for a, m, _, _ in matches if m == KNOWN_VULNERABILITY_MATCHER
        }
    else:
        selection = select_attributes(
            ((a, m, s) for a, m, s, _ in matches), exclude=decided
        )
        result.matched = selection.attributes
        result.below_threshold = selection.below_threshold
        result.beyond_cap = selection.beyond_cap

    shown = result.matched | decided
    if not result.matched:
        shown |= set(linked_flags)

    matched_flags: dict[str, int] = defaultdict(int)
    for attr, matcher, _, evidence in matches:
        matched_flags[attr] |= provenance_of(matcher, evidence)
    for attr in shown:
        if attr in matched_flags:
            result.flags[attr] = matched_flags[attr]
        else:
            result.unmatched.add(attr)
            result.flags[attr] = (
                linked_flags.get(attr, 0) | ProvenanceFlags.NO_LONGER_MATCHED
            )
    return result


def _linked_flags(suggestion: CVEDerivationClusterProposal) -> dict[str, int]:
    flags: dict[str, int] = defaultdict(int)
    for attr, f in DerivationClusterProposalLink.objects.filter(
        proposal=suggestion
    ).values_list("derivation__attribute", "provenance_flags"):
        flags[attr] |= f
    return dict(flags)


@dataclass
class ProjectionResult:
    frozen: bool = False
    attributes: set[str] = field(default_factory=set)
    added_attributes: set[str] = field(default_factory=set)
    removed_attributes: set[str] = field(default_factory=set)
    unmatched: set[str] = field(default_factory=set)
    created: int = 0
    deleted: int = 0
    updated: int = 0

    @property
    def changed(self) -> bool:
        return bool(self.created or self.deleted or self.updated)

    @property
    def attributes_changed(self) -> bool:
        return bool(self.added_attributes or self.removed_attributes)


def _tracked_current_evaluations() -> dict[int, set[str]]:
    """Current evaluation of every tracked branch, with the tracked branches it is current for."""
    current = list(NixEvaluation.objects.current().values_list("pk", flat=True))
    branches: dict[int, set[str]] = defaultdict(set)
    for pk, branch in NixEvaluation.on_branches.through.objects.filter(
        nixevaluation_id__in=current,
        nixpkgsbranch__channels__state__in=NixChannel.TRACKED_STATES,
    ).values_list("nixevaluation_id", "nixpkgsbranch_id"):
        branches[pk].add(branch)
    return dict(branches)


def project_links(suggestion: CVEDerivationClusterProposal) -> ProjectionResult:
    """
    Bring the suggestion's derivation links in line with what it shows, by diffing:
    create the missing links, delete the superfluous ones, fix flags. A no-op writes nothing.
    """
    with transaction.atomic():
        status, reason = (
            CVEDerivationClusterProposal.objects.select_for_update()
            .values_list("status", "rejection_reason")
            .get(pk=suggestion.pk)
        )
        suggestion.status, suggestion.rejection_reason = status, reason
        if is_frozen_for_projection(status, reason):
            return ProjectionResult(frozen=True)

        links = list(
            DerivationClusterProposalLink.objects.filter(
                proposal=suggestion
            ).values_list(
                "pk",
                "derivation_id",
                "provenance_flags",
                "derivation__attribute",
                "derivation__parent_evaluation_id",
            )
        )
        linked_flags: dict[str, int] = defaultdict(int)
        for _, _, flags, attr, _ in links:
            linked_flags[attr] |= flags
        shown = shown_attributes(suggestion, dict(linked_flags))

        current = _tracked_current_evaluations()
        current_drvs: dict[str, dict[int, set[str]]] = {a: {} for a in shown.flags}
        for pk, attr, evaluation in (
            NixDerivation.objects.filter(
                attribute__in=shown.flags,
                parent_evaluation__in=current,
                metadata__isnull=False,
            )
            .exclude(attribute__startswith="tests.")
            .values_list("pk", "attribute", "parent_evaluation_id")
        ):
            current_drvs[attr][pk] = current[evaluation]

        link_branches: dict[int, set[str]] = defaultdict(set)
        for evaluation, branch in NixEvaluation.on_branches.through.objects.filter(
            nixevaluation_id__in={e for *_, e in links}
        ).values_list("nixevaluation_id", "nixpkgsbranch_id"):
            link_branches[evaluation].add(branch)
        tracked = set().union(*current.values()) if current else set()

        desired: dict[int, int] = {}
        attribute_of: dict[int, str] = {}
        for attr, flags in shown.flags.items():
            covered = set().union(*current_drvs[attr].values())
            for pk in current_drvs[attr]:
                desired[pk] = flags
                attribute_of[pk] = attr
            for _, drv, _, link_attr, evaluation in links:
                if link_attr != attr or drv in desired:
                    continue
                if not covered or (link_branches[evaluation] & tracked) - covered:
                    desired[drv] = flags
                    attribute_of[drv] = attr

        to_delete: list[int] = []
        to_update: list[DerivationClusterProposalLink] = []
        seen: set[int] = set()
        for pk, drv, flags, _, _ in links:
            if drv not in desired or drv in seen:
                to_delete.append(pk)
                continue
            seen.add(drv)
            if flags != desired[drv]:
                to_update.append(
                    DerivationClusterProposalLink(pk=pk, provenance_flags=desired[drv])
                )
        to_create = [
            DerivationClusterProposalLink(
                proposal=suggestion, derivation_id=drv, provenance_flags=flags
            )
            for drv, flags in desired.items()
            if drv not in seen
        ]
        if to_delete:
            DerivationClusterProposalLink.objects.filter(pk__in=to_delete).delete()
        if to_update:
            DerivationClusterProposalLink.objects.bulk_update(
                to_update, ["provenance_flags"]
            )
        if to_create:
            DerivationClusterProposalLink.objects.bulk_create(to_create)

        before = set(linked_flags)
        after = set(attribute_of.values())
    result = ProjectionResult(
        attributes=after,
        added_attributes=after - before,
        removed_attributes=before - after,
        unmatched=shown.unmatched & after,
        created=len(to_create),
        deleted=len(to_delete),
        updated=len(to_update),
    )
    if result.changed:
        logger.info(
            "Projected links of suggestion %d: +%d -%d ~%d links, +%s -%s",
            suggestion.pk,
            result.created,
            result.deleted,
            result.updated,
            sorted(result.added_attributes),
            sorted(result.removed_attributes),
        )
    return result
