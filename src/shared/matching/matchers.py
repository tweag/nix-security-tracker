"""
The matchers. Each one is index-served or bounded; see the migration
`0117_branch_package_match_keys` for the indexes on `BranchPackage` they rely on.
"""

import re
from collections.abc import Iterable
from typing import cast

from django.contrib.postgres.lookups import TrigramSimilar
from django.contrib.postgres.search import TrigramSimilarity
from django.db import connection, transaction
from django.db.models import Expression, F, Func, Q, TextField, Value
from django.db.models.functions import Lower

from shared.matching.base import (
    REGISTRY,
    Hit,
    ILike,
    Matcher,
    MatcherResult,
    Universe,
    register,
)
from shared.matching.names import (
    ecosystem_for,
    ecosystem_package_name,
    normalise_name,
    registry_pages,
)
from shared.matching.view import CveView, NameTerm, ViewProduct


def _column(name: str) -> Expression:
    """A column reference usable as the left-hand side of a lookup expression."""
    return cast(Expression, F(name))


def _any(conditions: Iterable[Q]) -> Q | None:
    combined: Q | None = None
    for condition in conditions:
        combined = condition if combined is None else combined | condition
    return combined


@register
class NixpkgsCpe(Matcher):
    """A CVE CPE (vendor, product) equals the CPE parts nixpkgs declares, case-insensitively."""

    slug = "nixpkgs-cpe"
    version = 1
    # Declared CPEs are precise; `linux:linux_kernel` alone is a few dozen kernel attributes.
    limit = 500

    def hits(self, view: CveView, universe: Universe) -> Iterable[Hit]:
        pairs: dict[tuple[str, str], list[tuple[ViewProduct, str]]] = {}
        for product in view.matchable:
            for vendor, name in sorted(product.cpe_pairs):
                pairs.setdefault((vendor.lower(), name.lower()), []).append(
                    (product, f"{vendor}:{name}")
                )
        condition = _any(Q(cpe_v=v, cpe_p=p) for v, p in pairs)
        if condition is None:
            return
        rows = self._fetch(
            universe.packages()
            .annotate(cpe_v=Lower("cpe_vendor"), cpe_p=Lower("cpe_product"))
            .filter(condition),
            "attrpath",
            "branch_id",
            "cpe_vendor",
            "cpe_product",
        )
        for attrpath, branch, vendor, name in rows:
            for product, cve_value in pairs[(vendor.lower(), name.lower())]:
                yield Hit(
                    attrpath,
                    branch,
                    1.0,
                    product,
                    "cpe",
                    cve_value,
                    "cpe",
                    f"{vendor}:{name}",
                )


@register
class KnownVulnerability(Matcher):
    """The CVE id appears in the package's `meta.knownVulnerabilities`, independent of names."""

    slug = "known-vuln"
    version = 1
    limit = 500

    def hits(self, view: CveView, universe: Universe) -> Iterable[Hit]:
        # Entries are either the bare id or free text such as "CVE-2026-1234: SQL injection in ...".
        pattern = rf"(^|[^0-9a-z]){re.escape(view.cve_id)}([^0-9]|$)"
        rows = self._fetch(
            universe.packages()
            # Matches the partial index `branchpackage_known_vulns`.
            .exclude(known_vulnerabilities=[])
            .annotate(
                known_text=Func(
                    F("known_vulnerabilities"),
                    Value("\n"),
                    function="array_to_string",
                    output_field=TextField(),
                )
            )
            .filter(known_text__iregex=pattern),
            "attrpath",
            "branch_id",
            "known_vulnerabilities",
        )
        needle = re.compile(pattern, re.IGNORECASE)
        for attrpath, branch, entries in rows:
            entry = next((e for e in entries if needle.search(e)), view.cve_id)
            yield Hit(
                attrpath,
                branch,
                1.0,
                None,
                "cve_id",
                view.cve_id,
                "known_vulnerabilities",
                entry,
            )


def _terms(
    view: CveView, min_length: int = 1
) -> dict[str, list[tuple[ViewProduct, NameTerm]]]:
    """
    Name terms and every product naming them: a veto on one product must not remove the
    hits another product with the same name produces.
    """
    terms: dict[str, list[tuple[ViewProduct, NameTerm]]] = {}
    for product in view.matchable:
        for name in product.names:
            if len(name.term) >= min_length:
                terms.setdefault(name.term, []).append((product, name))
    return terms


def _is_derived(name: NameTerm) -> bool:
    return name.term != normalise_name(name.cve_value)


def _name_evidence(name: NameTerm) -> tuple[str, str]:
    """`cve_field` and `cve_value`; a derived term names the original value and the term."""
    if _is_derived(name):
        return name.cve_field, f"{name.cve_value} -> {name.term}"
    return name.cve_field, name.cve_value


@register
class NameExact(Matcher):
    """
    A normalised product or packageName equals the normalised `pname` (language prefix
    stripped) or the last attribute path component.
    """

    slug = "name-exact"
    version = 1
    # "linux" or "firefox" are legitimately dozens of attributes; beyond 100 a name is generic.
    limit = 100
    # Score of a term derived from a field (vendor word stripped, qualified name cut) rather than the field itself.
    DERIVED_SCORE = 0.9

    def hits(self, view: CveView, universe: Universe) -> Iterable[Hit]:
        terms = _terms(view)
        if not terms:
            return
        rows = self._fetch(
            universe.packages().filter(
                Q(match_pname__in=list(terms)) | Q(match_attr__in=list(terms))
            ),
            "attrpath",
            "branch_id",
            "pname",
            "match_pname",
            "match_attr",
        )
        for attrpath, branch, pname, match_pname, match_attr in rows:
            # The `pname` is the better evidence when both agree.
            for key, pkg_field, pkg_value in (
                (match_pname, "pname", pname),
                (match_attr, "attrpath", attrpath),
            ):
                if key in terms:
                    for product, name in terms[key]:
                        cve_field, cve_value = _name_evidence(name)
                        yield Hit(
                            attrpath,
                            branch,
                            self.DERIVED_SCORE if _is_derived(name) else 1.0,
                            product,
                            cve_field,
                            cve_value,
                            pkg_field,
                            pkg_value,
                        )
                    break


@register
class NameTrigram(Matcher):
    """
    `pg_trgm` similarity between a normalised product or packageName and the normalised
    `pname` (language prefix stripped) at or above `THRESHOLD`; score is the similarity.
    """

    slug = "name-trigram"
    version = 1
    limit = 50
    # Measured on 1028 triaged CVEs against a 2026-09 nixos-unstable/26.05 snapshot: 0.5 doubles
    # the candidates of 0.6 (8.8 vs 4.2 per CVE) for 1.5x the kept attributes exact matching misses.
    THRESHOLD = 0.6
    # Below this, a term has too few trigrams for similarity to mean anything ("qt", "vim").
    MIN_TERM_LENGTH = 4

    def hits(self, view: CveView, universe: Universe) -> Iterable[Hit]:
        terms = _terms(view, self.MIN_TERM_LENGTH)
        if not terms:
            return
        with transaction.atomic(), connection.cursor() as cursor:
            # The `%` operator, which the GIN index serves, compares against this setting.
            cursor.execute(
                "SELECT set_config('pg_trgm.similarity_threshold', %s, true)",
                [str(self.THRESHOLD)],
            )
            for term, named in terms.items():
                rows = self._fetch(
                    universe.packages()
                    .filter(TrigramSimilar(_column("match_pname"), Value(term)))
                    .annotate(similarity=TrigramSimilarity("match_pname", term))
                    .order_by("-similarity", "attrpath", "branch_id"),
                    "attrpath",
                    "branch_id",
                    "pname",
                    "similarity",
                )
                for attrpath, branch, pname, similarity in rows:
                    for product, name in named:
                        cve_field, cve_value = _name_evidence(name)
                        yield Hit(
                            attrpath,
                            branch,
                            min(1.0, similarity),
                            product,
                            cve_field,
                            cve_value,
                            "pname",
                            pname,
                            similarity,
                        )


@register
class NamePrefix(Matcher):
    """
    A normalised product or packageName is the leading word(s) of the normalised `pname`:
    "Zabbix" -> `zabbix-server`, "gocd" -> `gocd-server`. What substring matching finds that
    exact and trigram matching miss, without matching inside words ("Tesla" -> `teslajsonpy`).
    The score is the share of the `pname` the term covers.
    """

    slug = "name-prefix"
    version = 1
    limit = 50
    MIN_TERM_LENGTH = 3

    def hits(self, view: CveView, universe: Universe) -> Iterable[Hit]:
        terms = _terms(view, self.MIN_TERM_LENGTH)
        if not terms:
            return
        condition = _any(Q(match_pname__startswith=f"{term}-") for term in terms)
        assert condition is not None
        rows = self._fetch(
            universe.packages().filter(condition),
            "attrpath",
            "branch_id",
            "pname",
            "match_pname",
        )
        for attrpath, branch, pname, match_pname in rows:
            for term, named in terms.items():
                if not match_pname.startswith(f"{term}-"):
                    continue
                for product, name in named:
                    cve_field, cve_value = _name_evidence(name)
                    yield Hit(
                        attrpath,
                        branch,
                        len(term) / len(match_pname),
                        product,
                        cve_field,
                        cve_value,
                        "pname",
                        pname,
                    )


@register
class NameSubstring(Matcher):
    """
    Today's matcher: product or packageName is a case-insensitive substring of the package
    name. Kept at a low weight to compare and migrate; the score is the share of the `pname`
    the term covers.

    Unlike today it searches `pname`, not the derivation name: the trigram index on `pname`
    serves it, and the hits only the version part produced were noise on real data
    ("linux" in `cmake-3.10.2-linux-x86_64.zip`).
    """

    slug = "name-substring"
    version = 1
    # Today's `MAX_MATCHES` of 1000 derivations is about 125 to 250 attributes.
    limit = 200
    # Shorter terms have no trigram; they need a sequential scan, run as a separate query.
    MIN_INDEXED_LENGTH = 3

    def hits(self, view: CveView, universe: Universe) -> Iterable[Hit]:
        terms: dict[str, list[tuple[ViewProduct, str, str]]] = {}
        for product in view.matchable:
            for cve_field, value in (
                ("package_name", product.fields.package_name),
                ("product", product.fields.product),
            ):
                if value:
                    terms.setdefault(value.lower(), []).append(
                        (product, cve_field, value)
                    )
        indexed = [t for t in terms if len(t) >= self.MIN_INDEXED_LENGTH]
        short = [t for t in terms if len(t) < self.MIN_INDEXED_LENGTH]
        for group in (indexed, short):
            condition = _any(
                Q(ILike(_column("pname"), Value(f"%{_escape_like(term)}%")))
                for term in group
            )
            if condition is None:
                continue
            rows = self._fetch(
                universe.packages().filter(condition), "attrpath", "branch_id", "pname"
            )
            for attrpath, branch, pname in rows:
                lowered = pname.lower()
                for term in group:
                    if term not in lowered:
                        continue
                    for product, cve_field, value in terms[term]:
                        yield Hit(
                            attrpath,
                            branch,
                            min(1.0, len(term) / max(1, len(pname))),
                            product,
                            cve_field,
                            value,
                            "pname",
                            pname,
                        )


def _escape_like(value: str) -> str:
    return value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


@register
class RepoUrl(Matcher):
    """
    The upstream repository or registry package of an affected product is the package's
    homepage, or names an attribute of the nixpkgs package set mirroring that registry
    (`collectionURL: https://pypi.org` + `packageName: requests` -> `python3*Packages.requests`).
    """

    slug = "repo-url"
    version = 1
    limit = 50

    def hits(self, view: CveView, universe: Universe) -> Iterable[Hit]:
        homepages: dict[str, list[tuple[ViewProduct, str, str]]] = {}
        attr_sets: dict[tuple[str, str], list[tuple[ViewProduct, str]]] = {}
        for product in view.matchable:
            fields = product.fields
            for repo in product.repos:
                homepages.setdefault(repo, []).append(
                    (product, "repo", fields.repo or repo)
                )
            ecosystem = ecosystem_for(fields.collection_url)
            if ecosystem is None or not fields.package_name:
                continue
            for page in registry_pages(ecosystem, fields.package_name):
                homepages.setdefault(page, []).append(
                    (product, "package_name", fields.package_name)
                )
            if ecosystem.attr_set_re:
                name = ecosystem_package_name(ecosystem, fields.package_name)
                attr_sets.setdefault((name, ecosystem.attr_set_re), []).append(
                    (product, fields.package_name)
                )

        if homepages:
            rows = self._fetch(
                universe.packages().filter(match_homepage__in=list(homepages)),
                "attrpath",
                "branch_id",
                "homepage",
                "match_homepage",
            )
            for attrpath, branch, homepage, key in rows:
                for product, cve_field, cve_value in homepages[key]:
                    yield Hit(
                        attrpath,
                        branch,
                        1.0,
                        product,
                        cve_field,
                        cve_value,
                        "homepage",
                        homepage,
                    )

        condition = _any(
            Q(match_attr=name, attrpath__regex=attr_set) for name, attr_set in attr_sets
        )
        if condition is not None:
            rows = self._fetch(
                universe.packages().filter(condition),
                "attrpath",
                "branch_id",
                "match_attr",
            )
            for attrpath, branch, key in rows:
                for (name, attr_set), named in attr_sets.items():
                    if name != key or not re.match(attr_set, attrpath):
                        continue
                    for product, package_name in named:
                        yield Hit(
                            attrpath,
                            branch,
                            1.0,
                            product,
                            "package_name",
                            package_name,
                            "attrpath",
                            attrpath,
                        )


# Registers `curated` and `rules`; they live apart because they read mappings, not names.
from shared.matching import mapped  # noqa: E402, F401


def matchers_for(slugs: Iterable[str] | None = None) -> list[Matcher]:
    """Instances of the given registered matchers, or of all of them, in registry order."""
    if slugs is None:
        return [cls() for cls in REGISTRY.values()]
    wanted = set(slugs)
    unknown = wanted - REGISTRY.keys()
    if unknown:
        raise ValueError(f"unknown matchers: {', '.join(sorted(unknown))}")
    return [cls() for slug, cls in REGISTRY.items() if slug in wanted]


def collect_candidates(
    view: CveView,
    matchers: Iterable[str] | None = None,
    universe: Universe | None = None,
) -> dict[str, MatcherResult]:
    """Scored candidates per matcher slug, without touching the database beyond reading."""
    universe = universe or Universe.tracked()
    return {
        matcher.slug: matcher.run(view, universe) for matcher in matchers_for(matchers)
    }
