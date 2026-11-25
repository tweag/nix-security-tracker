"""
`ProductMapping` rows as the matchers see them, and the rule that decides which mapping
applies when several bear on one (product, attribute) pair:

1. the most authoritative source wins (curated > rule file > triage > nixpkgs metadata);
2. among those, the most specific target wins (an exact attribute path, then the glob with
   the most literal characters, then no target);
3. among those, a veto (`not_same`, `irrelevant`) wins over `same`.

So "product `Linux` is only the kernel" is a rule file `not_same` with glob `*` plus `same`
rules with the kernel globs, and a curator's `same` overrides a `not_same` learned from triage.
"""

import re
from collections.abc import Iterable
from dataclasses import dataclass, field
from functools import cached_property
from typing import Any

from shared.models.matching import ProductMapping

Relation = ProductMapping.Relation
Source = ProductMapping.Source

# (kind, vendor, product) as stored; `shared.matching.view.KeySpec` is such a tuple.
Key = tuple[str, str, str]

SOURCE_RANK: dict[str, int] = {
    Source.CURATED: 3,
    Source.RULE_FILE: 2,
    Source.TRIAGE: 1,
    Source.NIXPKGS_META: 0,
}

GLOB_RE = re.compile(r"^[A-Za-z0-9_.+*'-]+$")


def validate_glob(glob: str) -> None:
    """Attribute globs only know `*` (any sequence, dots included) and attribute path characters."""
    if not GLOB_RE.match(glob):
        raise ValueError(f"invalid attribute glob {glob!r}")


def glob_regex(glob: str) -> str:
    """The glob as an anchored POSIX/Python regular expression (same meaning in both)."""
    validate_glob(glob)
    return "^" + ".*".join(re.escape(part) for part in glob.split("*")) + "$"


@dataclass(frozen=True)
class MappingRule:
    """One `ProductMapping`, detached from the database."""

    id: int
    key: Key
    relation: str
    source: str
    attrpath: str | None = None
    attr_glob: str | None = None

    @classmethod
    def of(cls, mapping: ProductMapping) -> "MappingRule":
        key = mapping.product_key
        return cls(
            id=mapping.pk,
            key=(key.kind, key.vendor, key.product),
            relation=mapping.relation,
            source=mapping.source,
            attrpath=mapping.attrpath,
            attr_glob=mapping.attr_glob,
        )

    @property
    def is_veto(self) -> bool:
        return self.relation != Relation.SAME

    @cached_property
    def _regex(self) -> re.Pattern[str] | None:
        return re.compile(glob_regex(self.attr_glob)) if self.attr_glob else None

    def applies_to(self, attrpath: str) -> bool:
        if self.attrpath is not None:
            return self.attrpath == attrpath
        if self._regex is not None:
            return self._regex.match(attrpath) is not None
        return self.relation == Relation.IRRELEVANT

    @property
    def specificity(self) -> int:
        if self.attrpath is not None:
            return 1 << 16
        if self.attr_glob is not None:
            return len(self.attr_glob.replace("*", ""))
        return -1

    def precedence(self) -> tuple[int, int, bool]:
        return (SOURCE_RANK.get(self.source, 0), self.specificity, self.is_veto)

    @property
    def target(self) -> str | None:
        return self.attrpath or self.attr_glob

    def describe(self) -> dict[str, Any]:
        """What events and evidence record of the mapping, so they stay readable after it is deleted."""
        kind, vendor, product = self.key
        return {
            "id": self.id,
            "product_key": f"{kind}:{vendor}/{product}",
            "relation": self.relation,
            "source": self.source,
            "target": self.target,
        }


@dataclass(frozen=True)
class Mappings:
    """The mappings bearing on a set of product keys."""

    by_key: dict[Key, tuple[MappingRule, ...]] = field(default_factory=dict)

    def __bool__(self) -> bool:
        return bool(self.by_key)

    def for_keys(self, keys: Iterable[Key]) -> list[MappingRule]:
        return sorted(
            (rule for key in keys for rule in self.by_key.get(key, ())),
            key=lambda r: r.id,
        )

    def decide(self, keys: Iterable[Key], attrpath: str) -> MappingRule | None:
        """The mapping that decides whether a product with these keys is `attrpath`, if any."""
        applicable = [rule for rule in self.for_keys(keys) if rule.applies_to(attrpath)]
        if not applicable:
            return None
        return max(applicable, key=lambda r: (r.precedence(), -r.id))

    def veto(self, keys: Iterable[Key], attrpath: str) -> MappingRule | None:
        """The veto that removes `attrpath` as a candidate for a product with these keys, if any."""
        rule = self.decide(keys, attrpath)
        return rule if rule is not None and rule.is_veto else None

    def same(self, keys: Iterable[Key], *, globs: bool) -> list[MappingRule]:
        """`same` mappings with an attribute path (or, with `globs`, an attribute glob) target."""
        return [
            rule
            for rule in self.for_keys(keys)
            if rule.relation == Relation.SAME
            and (rule.attr_glob if globs else rule.attrpath) is not None
        ]


NO_MAPPINGS = Mappings()


def load_mappings(keys: Iterable[Key]) -> Mappings:
    """Mappings on any of the given keys, in one query (the mapping table is small)."""
    wanted = set(keys)
    if not wanted:
        return NO_MAPPINGS
    found: dict[Key, list[MappingRule]] = {}
    for mapping in ProductMapping.objects.filter(
        product_key__product__in={product for _, _, product in wanted}
    ).select_related("product_key"):
        rule = MappingRule.of(mapping)
        if rule.key in wanted:
            found.setdefault(rule.key, []).append(rule)
    return Mappings({key: tuple(rules) for key, rules in found.items()})
