"""
Matcher protocol, registry, the package universe matchers search, and the
aggregation of per-branch hits into one candidate per attribute.
"""

from abc import ABC, abstractmethod
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any, ClassVar, NamedTuple

from django.db.models import Lookup, Q, QuerySet

from shared.matching.scoring import weight_of
from shared.matching.view import CveView, ViewProduct
from shared.models.nix_evaluation import NixChannel, NixEvaluation, NixpkgsBranch
from shared.models.snapshot import BranchPackage

# Rows a single matcher query may return before the matcher reports truncation
# without knowing the exact remainder. Rows are (attribute x branch).
ROW_CEILING = 5000


@dataclass(frozen=True)
class Candidate:
    """Matcher M proposes attribute `attrpath` with matcher-local confidence `score`."""

    attrpath: str
    score: float
    # See `Match.evidence`.
    evidence: dict[str, Any]


@dataclass
class MatcherResult:
    candidates: list[Candidate] = field(default_factory=list)
    # Attributes found beyond the matcher's limit, dropped from `candidates`.
    truncated: int = 0
    # Whether `truncated` is exact; False when a query hit `ROW_CEILING`.
    truncated_exact: bool = True
    # Attributes every hit of which a `ProductMapping` vetoed, with the deciding mapping
    # (`MappingRule.describe()`). Vetoed hits count against no limit.
    vetoed: dict[str, dict[str, Any]] = field(default_factory=dict)


@dataclass(frozen=True)
class Universe:
    """
    What matchers search: `BranchPackage` rows on tracked branches, without `tests.*`; present
    ones, and absent ones not yet called removed (missing from fewer than
    `REMOVAL_AFTER_EVALUATIONS` completed evaluations), so that a re-match while an attribute
    fails to evaluate once does not retract its match.
    """

    branches: tuple[str, ...]
    # Per branch: absent rows last seen in one of these evaluations (the most recent completed
    # ones up to the current one) still count.
    absent_since: tuple[tuple[str, tuple[int, ...]], ...] = ()

    @classmethod
    def tracked(cls) -> "Universe":
        """Branches with a channel in a tracked state, as `latest_completed_per_branch` defines them."""
        from shared.exposure import REMOVAL_AFTER_EVALUATIONS

        branches = list(
            NixpkgsBranch.objects.filter(channels__state__in=NixChannel.TRACKED_STATES)
            .select_related("current_evaluation")
            .distinct()
            .order_by("name")
        )
        absent_since = []
        for branch in branches:
            current = branch.current_evaluation
            if current is None:
                continue
            recent = list(
                NixEvaluation.objects.filter(
                    on_branches=branch,
                    state=NixEvaluation.EvaluationState.COMPLETED,
                    created_at__lte=current.created_at,
                )
                .order_by("-created_at", "-pk")
                .values_list("pk", flat=True)[:REMOVAL_AFTER_EVALUATIONS]
            )
            if recent:
                absent_since.append((branch.name, tuple(recent)))
        return cls(tuple(b.name for b in branches), tuple(absent_since))

    def packages(self) -> QuerySet[BranchPackage]:
        condition = Q(present=True)
        for branch, evaluations in self.absent_since:
            condition |= Q(
                branch_id=branch, present=False, evaluation_id__in=evaluations
            )
        return (
            BranchPackage.objects.filter(condition)
            .filter(branch_id__in=self.branches)
            .exclude(
                # Test derivations are a Nixpkgs implementation detail and never represent software to be distributed.
                attrpath__startswith="tests.",
            )
        )


class Hit(NamedTuple):
    """One reason why one attribute on one branch matched."""

    attrpath: str
    branch: str
    score: float
    product: ViewProduct | None
    cve_field: str
    cve_value: str
    pkg_field: str
    pkg_value: str
    similarity: float | None = None
    # Further evidence, e.g. the `ProductMapping` behind a `curated` hit.
    extra: dict[str, Any] | None = None

    def evidence(self) -> dict[str, Any]:
        evidence: dict[str, Any] = (
            self.product.evidence()
            if self.product is not None
            else {"affected_product": None, "affected_products": [], "container": None}
        )
        evidence |= {
            "cve_field": self.cve_field,
            "cve_value": self.cve_value[:255],
            "pkg_field": self.pkg_field,
            "pkg_value": self.pkg_value[:255],
        }
        if self.similarity is not None:
            evidence["similarity"] = round(self.similarity, 3)
        if self.extra:
            evidence |= self.extra
        return evidence

    def reason(self) -> tuple[Any, ...]:
        return (
            self.product.affected_product if self.product else None,
            self.cve_field,
            self.cve_value,
            self.pkg_field,
        )


def _product_order(hit: Hit) -> tuple[bool, int]:
    """Claimed affected products first, by pk; then hits with no affected product pk."""
    pk = hit.product.affected_product if hit.product else None
    return (pk is None, pk or 0)


def aggregate(
    hits: Iterable[Hit], limit: int, ceiling_hit: bool = False
) -> MatcherResult:
    """
    One candidate per attribute: the best hit's evidence, the branches it was found on,
    and how many other reasons hit the same attribute. Keeps the `limit` best attributes.
    """
    by_attr: dict[str, list[Hit]] = {}
    for hit in hits:
        by_attr.setdefault(hit.attrpath, []).append(hit)

    candidates = []
    for attrpath, attr_hits in by_attr.items():
        attr_hits.sort(
            key=lambda h: (
                -h.score,
                *_product_order(h),
                h.cve_field,
                h.cve_value,
                h.pkg_field,
                h.pkg_value,
                h.branch,
            )
        )
        best = attr_hits[0]
        evidence = best.evidence()
        evidence["branches"] = sorted({h.branch for h in attr_hits})
        others = {h.reason() for h in attr_hits} - {best.reason()}
        if others:
            evidence["other_hits"] = len(others)
        candidates.append(Candidate(attrpath, best.score, evidence))

    candidates.sort(key=lambda c: (-c.score, c.attrpath))
    return MatcherResult(
        candidates=candidates[:limit],
        truncated=max(0, len(candidates) - limit),
        truncated_exact=not ceiling_hit,
    )


class Matcher(ABC):
    """
    Proposes attributes for a CVE. Subclasses set `slug` and `version` (bump it when
    behaviour changes) and implement `hits`; `register` adds them to `REGISTRY`.
    Base weights live in `shared.matching.scoring.BASE_WEIGHTS`.
    """

    slug: ClassVar[str]
    version: ClassVar[int]
    # Maximum number of attributes kept per CVE; the rest is reported as truncated.
    limit: ClassVar[int] = 200

    @property
    def weight(self) -> float:
        return weight_of(self.slug)

    @abstractmethod
    def hits(self, view: CveView, universe: Universe) -> Iterable[Hit]:
        """Every (attribute, branch, reason) this matcher finds, at most `ROW_CEILING` rows per query."""

    def __init__(self) -> None:
        self._ceiling_hit = False

    def run(self, view: CveView, universe: Universe) -> MatcherResult:
        """Hits minus those a `ProductMapping` vetoes, one candidate per attribute."""
        self._ceiling_hit = False
        hits: list[Hit] = []
        vetoed: dict[str, dict[str, Any]] = {}
        for hit in self.hits(view, universe):
            rule = view.veto(hit.product, hit.attrpath)
            if rule is None:
                hits.append(hit)
            else:
                vetoed.setdefault(hit.attrpath, rule.describe())
        result = aggregate(hits, self.limit, ceiling_hit=self._ceiling_hit)
        found = {hit.attrpath for hit in hits}
        result.vetoed = {
            attrpath: rule
            for attrpath, rule in sorted(vetoed.items())
            if attrpath not in found
        }
        return result

    def candidates(self, view: CveView, universe: Universe) -> list[Candidate]:
        return self.run(view, universe).candidates

    def _fetch(self, queryset: QuerySet, *fields: str) -> list[tuple[Any, ...]]:
        """Rows of `queryset`, at most `ROW_CEILING`; records whether the ceiling was hit."""
        rows = list(queryset.values_list(*fields)[: ROW_CEILING + 1])
        if len(rows) > ROW_CEILING:
            self._ceiling_hit = True
            rows = rows[:ROW_CEILING]
        return rows


REGISTRY: dict[str, type[Matcher]] = {}


def register[M: type[Matcher]](matcher: M) -> M:
    """Class decorator that makes a matcher part of every reconciliation."""
    assert matcher.slug not in REGISTRY, f"duplicate matcher slug {matcher.slug}"
    REGISTRY[matcher.slug] = matcher
    return matcher


class ILike(Lookup):
    """`ILIKE`, which trigram GIN indexes serve, unlike Django's `UPPER(x) LIKE UPPER(y)`."""

    lookup_name = "ilike"

    def as_sql(self, compiler: Any, connection: Any) -> tuple[str, list[Any]]:
        lhs, lhs_params = self.process_lhs(compiler, connection)
        rhs, rhs_params = self.process_rhs(compiler, connection)
        return f"{lhs} ILIKE {rhs}", [*lhs_params, *rhs_params]
