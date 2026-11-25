"""
Per-attribute score of a suggestion: noisy-OR over its active matches,
`1 - prod(1 - weight_m * score_m)`.
"""

import logging
import math
from collections.abc import Iterable
from dataclasses import dataclass

from shared.models.linkage import CVEDerivationClusterProposal
from shared.models.matching import Match

logger = logging.getLogger(__name__)

# Base weight per matcher slug: how much a perfect hit of that matcher alone is worth.
# Starting constants from the design report (section 3.1), to be fitted on triage labels.
BASE_WEIGHTS: dict[str, float] = {
    "nixpkgs-cpe": 1.0,
    "known-vuln": 1.0,
    "repo-url": 0.9,
    "name-exact": 0.8,
    "name-trigram": 0.7,
    # Not in the report's table; between trigram and substring.
    "name-prefix": 0.5,
    "name-substring": 0.2,
}
# Matchers without a weight here (e.g. a future `manual` or `curated`) count fully,
# so that adding one does not silently hide its matches.
DEFAULT_WEIGHT = 1.0


def weight_of(matcher: str) -> float:
    return BASE_WEIGHTS.get(matcher, DEFAULT_WEIGHT)


def noisy_or(contributions: Iterable[tuple[str, float]]) -> float:
    """Combine (matcher, matcher-local score) pairs as independent evidence."""
    miss = math.prod(1 - min(1.0, max(0.0, weight_of(m) * s)) for m, s in contributions)
    return 1 - miss


@dataclass(frozen=True)
class RankedAttribute:
    attrpath: str
    score: float
    # Contributing active matches, strongest first.
    matches: tuple[Match, ...]


def rank_matches(matches: Iterable[Match]) -> list[RankedAttribute]:
    """Group matches by attribute and rank attributes by noisy-OR score, then name."""
    by_attr: dict[str, list[Match]] = {}
    for match in matches:
        by_attr.setdefault(match.attrpath, []).append(match)
    ranked = [
        RankedAttribute(
            attrpath=attrpath,
            score=noisy_or((m.matcher, m.score) for m in attr_matches),
            matches=tuple(
                sorted(
                    attr_matches,
                    key=lambda m: (-weight_of(m.matcher) * m.score, m.matcher),
                )
            ),
        )
        for attrpath, attr_matches in by_attr.items()
    ]
    ranked.sort(key=lambda r: (-r.score, r.attrpath))
    return ranked


def rank_attributes(suggestion: CVEDerivationClusterProposal) -> list[RankedAttribute]:
    """Ranked attributes of a suggestion with their contributing active matches, in one query."""
    return rank_matches(Match.objects.active().filter(suggestion=suggestion))
