"""
Matchers driven by `ProductMapping(relation=same)`: `curated` for mappings to one attribute
path, `rules` for mappings to an attribute glob. Vetoes act in `Matcher.run` for every matcher.
"""

from collections.abc import Iterable

from django.db.models import Q

from shared.identity.mappings import MappingRule, glob_regex
from shared.matching.base import Hit, Matcher, Universe, register
from shared.matching.view import CveView, ViewProduct


def _hit(attrpath: str, branch: str, product: ViewProduct, rule: MappingRule) -> Hit:
    description = rule.describe()
    return Hit(
        attrpath,
        branch,
        1.0,
        product,
        "product_key",
        description["product_key"],
        "attr_glob" if rule.attr_glob else "attrpath",
        rule.target or "",
        extra={"mapping": description},
    )


@register
class Curated(Matcher):
    """A `same` mapping from one of the CVE's product keys to an attribute path."""

    slug = "curated"
    version = 1
    limit = 200

    def hits(self, view: CveView, universe: Universe) -> Iterable[Hit]:
        targets: dict[str, list[tuple[ViewProduct, MappingRule]]] = {}
        for product in view.matchable:
            for rule in view.mappings.same(product.keys, globs=False):
                assert rule.attrpath is not None
                targets.setdefault(rule.attrpath, []).append((product, rule))
        if not targets:
            return
        rows = self._fetch(
            universe.packages().filter(attrpath__in=list(targets)),
            "attrpath",
            "branch_id",
        )
        for attrpath, branch in rows:
            for product, rule in targets[attrpath]:
                yield _hit(attrpath, branch, product, rule)


@register
class Rules(Matcher):
    """
    A `same` mapping from one of the CVE's product keys to an attribute glob, expanded against
    the present attributes (`linuxPackages*.nvidia_x11*` for Nvidia driver CVEs, #1461).
    """

    slug = "rules"
    version = 1
    # Kernel globs legitimately name a few hundred attributes over two branches.
    limit = 500

    def hits(self, view: CveView, universe: Universe) -> Iterable[Hit]:
        rules: list[tuple[ViewProduct, MappingRule]] = [
            (product, rule)
            for product in view.matchable
            for rule in view.mappings.same(product.keys, globs=True)
        ]
        if not rules:
            return
        condition = Q()
        for glob in sorted({rule.attr_glob for _, rule in rules if rule.attr_glob}):
            # Served by the trigram index on `attrpath`.
            condition |= Q(attrpath__regex=glob_regex(glob))
        rows = self._fetch(
            universe.packages().filter(condition), "attrpath", "branch_id"
        )
        for attrpath, branch in rows:
            for product, rule in rules:
                if rule.applies_to(attrpath):
                    yield _hit(attrpath, branch, product, rule)
