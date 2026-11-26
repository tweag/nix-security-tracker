"""
Which attributes of a suggestion are its candidates: the one definition the projection (what
is linked and shown), the exposure layer (what is kept current) and the derived state (what
needs triage, what is possibly fixed) share.

Candidates = the matched attributes the suggestion shows (`shared.matching.selection`: above
the score threshold, within the cap; for a `known_vulnerability` rejection only what
`known-vuln` found) + every attribute a human decided on (a `Verdict`, or an ignore overlay
not converted yet). An active match below the threshold or beyond the cap is a fact the
tracker keeps, not a candidate: nobody is shown it, so nothing may ask anybody to triage it.
"""

from collections import defaultdict
from collections.abc import Collection
from dataclasses import dataclass, field

from shared.matching.selection import (
    KNOWN_VULNERABILITY_MATCHER,
    counted_matchers,
    select_attributes,
)
from shared.models.linkage import CVEDerivationClusterProposal, PackageOverlay
from shared.models.matching import Match, Verdict

Status = CVEDerivationClusterProposal.Status
Rejection = CVEDerivationClusterProposal.RejectionReason


@dataclass
class Candidates:
    # Matched attributes shown.
    matched: set[str] = field(default_factory=set)
    # Attributes with a verdict or an ignore overlay.
    decided: set[str] = field(default_factory=set)
    below_threshold: int = 0
    beyond_cap: int = 0

    @property
    def attributes(self) -> set[str]:
        return self.matched | self.decided


def candidates(suggestion_ids: Collection[int]) -> dict[int, Candidates]:
    """Candidates of many suggestions, in four queries."""
    ids = list(suggestion_ids)
    status = {
        pk: (s, r)
        for pk, s, r in CVEDerivationClusterProposal.objects.filter(
            pk__in=ids
        ).values_list("pk", "status", "rejection_reason")
    }
    contributions: dict[int, list[tuple[str, str, float]]] = defaultdict(list)
    for sid, attr, matcher, score in (
        Match.objects.active()
        .filter(suggestion_id__in=ids, matcher__in=counted_matchers())
        .values_list("suggestion_id", "attrpath", "matcher", "score")
    ):
        contributions[sid].append((attr, matcher, score))
    decided: dict[int, set[str]] = defaultdict(set)
    for sid, attr in Verdict.objects.filter(suggestion_id__in=ids).values_list(
        "suggestion_id", "attrpath"
    ):
        decided[sid].add(attr)
    for sid, attr in PackageOverlay.objects.filter(
        suggestion_id__in=ids, type=PackageOverlay.Type.IGNORED
    ).values_list("suggestion_id", "package_attribute"):
        decided[sid].add(attr)

    result: dict[int, Candidates] = {}
    for pk, (s, reason) in status.items():
        c = Candidates(decided=decided[pk])
        if s == Status.REJECTED and reason == Rejection.KNOWN_VULNERABILITY:
            c.matched = {
                a for a, m, _ in contributions[pk] if m == KNOWN_VULNERABILITY_MATCHER
            } - c.decided
        else:
            selection = select_attributes(contributions[pk], exclude=c.decided)
            c.matched = selection.attributes
            c.below_threshold = selection.below_threshold
            c.beyond_cap = selection.beyond_cap
        result[pk] = c
    return result
