"""
Per-attribute score of a suggestion: noisy-OR over its active matches,
`1 - prod(1 - weight_m * score_m)`.
"""

import logging
import math
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Any

from shared.identity.keys import stored_or_derived_keys
from shared.identity.mappings import Mappings, load_mappings
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
    # Mappings (`MappingRule.describe()`) that vetoed the other active matches of this
    # attribute; an attribute all of whose matches are vetoed has score 0 and no `matches`.
    vetoed_by: tuple[dict[str, Any], ...] = ()


# Product keys of an affected product pk, as `shared.identity.mappings.Key` tuples.
ProductKeysOf = Mapping[int, frozenset[tuple[str, str, str]]]


def rank_matches(
    matches: Iterable[Match],
    mappings: Mappings | None = None,
    keys_of: ProductKeysOf | None = None,
) -> list[RankedAttribute]:
    """
    Group matches by attribute and rank attributes by noisy-OR score, then name. With
    `mappings`, a match whose evidence comes from an affected product that a mapping vetoes
    for that attribute does not contribute (the same rule `Matcher.run` applies).
    """
    by_attr: dict[str, list[Match]] = {}
    vetoes: dict[str, list[dict[str, Any]]] = {}
    for match in matches:
        rule = None
        product = match.evidence.get("affected_product")
        if mappings and keys_of and product in keys_of:
            rule = mappings.veto(keys_of[product], match.attrpath)
        by_attr.setdefault(match.attrpath, [])
        if rule is None:
            by_attr[match.attrpath].append(match)
        elif (described := rule.describe()) not in vetoes.setdefault(
            match.attrpath, []
        ):
            vetoes[match.attrpath].append(described)
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
            vetoed_by=tuple(vetoes.get(attrpath, ())),
        )
        for attrpath, attr_matches in by_attr.items()
    ]
    ranked.sort(key=lambda r: (-r.score, r.attrpath))
    return ranked


def rank_attributes(suggestion: CVEDerivationClusterProposal) -> list[RankedAttribute]:
    """
    Ranked attributes of a suggestion with their contributing active matches. Vetoes apply
    here too, so a mapping takes effect in the ranking before reconciliation has retracted
    the matches it vetoes (four queries; one when there are no matches).
    """
    matches = list(Match.objects.active().filter(suggestion=suggestion))
    products = {
        pk for m in matches if isinstance(pk := m.evidence.get("affected_product"), int)
    }
    keys_of = stored_or_derived_keys(products) if products else {}
    mappings = load_mappings(k for keys in keys_of.values() for k in keys)
    return rank_matches(matches, mappings, keys_of)
