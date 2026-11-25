"""
Propose `ProductMapping(source=triage)` rows from human decisions, only where they are unambiguous.

Labels per suggestion (`TriageCase`):
- positive outcome: published (or rejected as `known_vulnerability`, where nixpkgs itself names
  the CVE); `kept` are the proposed attributes minus the ignored ones;
- negative outcome: rejected as `not_in_nixpkgs`; every proposed attribute is a negative.

Rules (`propose`):
- Only *identity keys* count: when an affected product names a product and a different package
  in it (Red Hat: product "Red Hat Enterprise Linux 9", packageName "sudo"), the product and its
  CPEs name a platform and only the package keys name the software.
- A key is *unambiguous* for a case when the CVE has exactly one matchable product with keys,
  or when it is the only key of its kind on the CVE. Only unambiguous keys learn `same`.
- Negatives of a case: for a negative outcome all proposed attributes; for a positive outcome the
  ignored attributes that are not a *variant* of a kept one (same `pname`, or the same name once a
  version suffix is cut: keeping `openssl_3` and ignoring `openssl_1_1` is a version choice, not
  an identity decision). Negatives hold for every key of the CVE: the human ruled them out for the
  CVE as a whole.
- `same(K, a)`: `a` kept in at least `min_same` cases where K is unambiguous, and never a negative
  of a case with K.
- `not_same(K, a)`: `a` a negative of at least `min_not_same` distinct CVEs with K, and never kept
  in a case with K.
- `irrelevant(K)` (optional, `min_irrelevant`): K is the only product of at least that many
  `not_in_nixpkgs` rejections and of no positive case.
Anything else (a key both kept and ruled out for an attribute) is a conflict for a human.
"""

import re
from collections import defaultdict
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field, replace

from django.db import transaction
from django.db.models import Q

from shared.identity.keys import get_or_create_keys
from shared.identity.mappings import Key
from shared.matching.names import normalise_name
from shared.matching.view import KeySpec, ViewProduct, build_cve_views, product_keys
from shared.models.linkage import (
    CVEDerivationClusterProposal,
    DerivationClusterProposalLink,
    PackageOverlay,
)
from shared.models.matching import Match, ProductMapping, Verdict
from shared.models.snapshot import BranchPackage

Status = CVEDerivationClusterProposal.Status
Reason = CVEDerivationClusterProposal.RejectionReason
Relation = ProductMapping.Relation

MIN_SAME = 1
MIN_NOT_SAME = 2


@dataclass(frozen=True)
class TriageCase:
    suggestion: int
    cve_id: str
    positive: bool
    # Keys of each matchable product of the CVE that has keys.
    products: tuple[frozenset[Key], ...]
    proposed: frozenset[str]
    kept: frozenset[str] = frozenset()
    ignored: frozenset[str] = frozenset()

    @property
    def keys(self) -> frozenset[Key]:
        return frozenset(k for keys in self.products for k in keys)

    def unambiguous_keys(self) -> frozenset[Key]:
        if len(self.products) == 1:
            return self.products[0]
        by_kind: dict[str, set[Key]] = defaultdict(set)
        for key in self.keys:
            by_kind[key[0]].add(key)
        return frozenset(k for keys in by_kind.values() if len(keys) == 1 for k in keys)


def identity_keys(product: ViewProduct) -> frozenset[Key]:
    """The product's keys minus those naming a platform the package is shipped in."""
    fields = product.fields
    if not (
        fields.package_name
        and fields.product
        and normalise_name(fields.package_name) != normalise_name(fields.product)
    ):
        return frozenset(product.keys)
    platform = product_keys(
        replace(fields, package_name=None, collection_url=None, repo=None)
    )
    return frozenset(product.keys - platform)


_VERSION_SUFFIX = re.compile(r"([_-]?v?\d[\w.]*|[_-](latest|stable|beta|lts))$")


def variant_key(attrpath: str, pname_of: Mapping[str, str]) -> str:
    """What variants of one package share: the `pname`, else the last component without a version suffix."""
    if pname := pname_of.get(attrpath):
        return pname.lower()
    tail = attrpath.rsplit(".", 1)[-1].lower()
    return _VERSION_SUFFIX.sub("", tail) or tail


def negatives(case: TriageCase, pname_of: Mapping[str, str]) -> frozenset[str]:
    if not case.positive:
        return case.proposed
    kept = {variant_key(a, pname_of) for a in case.kept}
    return frozenset(a for a in case.ignored if variant_key(a, pname_of) not in kept)


@dataclass(frozen=True)
class Proposal:
    key: Key
    relation: str
    attrpath: str | None
    # CVE ids of the supporting cases.
    support: tuple[str, ...]

    def comment(self) -> str:
        shown = ", ".join(self.support[:10])
        more = f" and {len(self.support) - 10} more" if len(self.support) > 10 else ""
        return f"Learned from triage of {shown}{more}."


@dataclass
class Learned:
    proposals: list[Proposal] = field(default_factory=list)
    # (key, attrpath) both kept and ruled out: for a human, not for a rule.
    conflicts: list[tuple[Key, str]] = field(default_factory=list)


def propose(
    cases: Iterable[TriageCase],
    pname_of: Mapping[str, str] | None = None,
    *,
    min_same: int = MIN_SAME,
    min_not_same: int = MIN_NOT_SAME,
    min_irrelevant: int | None = None,
) -> Learned:
    pname_of = pname_of or {}
    kept_unambiguous: dict[tuple[Key, str], set[str]] = defaultdict(set)
    kept_any: set[tuple[Key, str]] = set()
    ruled_out: dict[tuple[Key, str], set[str]] = defaultdict(set)
    rejected_alone: dict[Key, set[str]] = defaultdict(set)
    positive_keys: set[Key] = set()
    for case in cases:
        unambiguous = case.unambiguous_keys()
        for key in case.keys:
            for attrpath in case.kept:
                kept_any.add((key, attrpath))
                if key in unambiguous:
                    kept_unambiguous[(key, attrpath)].add(case.cve_id)
            for attrpath in negatives(case, pname_of):
                ruled_out[(key, attrpath)].add(case.cve_id)
        if case.positive:
            positive_keys |= case.keys
        elif len(case.products) == 1:
            for key in case.products[0]:
                rejected_alone[key].add(case.cve_id)

    learned = Learned()
    for (key, attrpath), support in kept_unambiguous.items():
        if (key, attrpath) in ruled_out:
            learned.conflicts.append((key, attrpath))
        elif len(support) >= min_same:
            learned.proposals.append(
                Proposal(key, Relation.SAME, attrpath, tuple(sorted(support)))
            )
    for (key, attrpath), support in ruled_out.items():
        if (key, attrpath) in kept_any:
            if (key, attrpath) not in kept_unambiguous:
                learned.conflicts.append((key, attrpath))
        elif len(support) >= min_not_same:
            learned.proposals.append(
                Proposal(key, Relation.NOT_SAME, attrpath, tuple(sorted(support)))
            )
    if min_irrelevant is not None:
        for key, support in rejected_alone.items():
            if key not in positive_keys and len(support) >= min_irrelevant:
                learned.proposals.append(
                    Proposal(key, Relation.IRRELEVANT, None, tuple(sorted(support)))
                )
    learned.proposals.sort(key=lambda p: (p.key, p.relation, p.attrpath or ""))
    learned.conflicts.sort()
    return learned


def labelled_suggestions() -> Q:
    """Suggestions whose outcome is a human (or nixpkgs) identity decision."""
    return Q(status=Status.PUBLISHED) | Q(
        status=Status.REJECTED,
        rejection_reason__in=[Reason.NOT_IN_NIXPKGS, Reason.KNOWN_VULNERABILITY],
    )


def triage_cases(
    suggestions: Iterable[CVEDerivationClusterProposal],
) -> list[TriageCase]:
    """
    Cases from the database. Proposed attributes are the active `Match` rows and the legacy
    derivation links; ignored ones are `ignored` overlays and attribute-wide `irrelevant`
    verdicts; any other verdict counts as kept.
    """
    suggestions = list(suggestions)
    ids = [s.pk for s in suggestions]
    proposed: dict[int, set[str]] = defaultdict(set)
    for pk, attrpath in (
        Match.objects.active()
        .filter(suggestion__in=ids)
        .values_list("suggestion_id", "attrpath")
    ):
        proposed[pk].add(attrpath)
    for pk, attrpath in DerivationClusterProposalLink.objects.filter(
        proposal__in=ids
    ).values_list("proposal_id", "derivation__attribute"):
        proposed[pk].add(attrpath)
    ignored: dict[int, set[str]] = defaultdict(set)
    for pk, attrpath in PackageOverlay.objects.filter(
        suggestion__in=ids, type=PackageOverlay.Type.IGNORED
    ).values_list("suggestion_id", "package_attribute"):
        ignored[pk].add(attrpath)
    affirmed: dict[int, set[str]] = defaultdict(set)
    for pk, attrpath, verdict in Verdict.objects.filter(
        suggestion__in=ids, branch__isnull=True
    ).values_list("suggestion_id", "attrpath", "verdict"):
        (ignored if verdict == Verdict.Kind.IRRELEVANT else affirmed)[pk].add(attrpath)

    views = build_cve_views({s.cve.cve_id for s in suggestions})
    cases = []
    for s in suggestions:
        view = views.get(s.cve.cve_id)
        products = tuple(
            keys for p in (view.matchable if view else ()) if (keys := identity_keys(p))
        )
        positive = s.status == Status.PUBLISHED or (
            s.rejection_reason == Reason.KNOWN_VULNERABILITY
        )
        attrs = frozenset(proposed[s.pk])
        cases.append(
            TriageCase(
                suggestion=s.pk,
                cve_id=s.cve.cve_id,
                positive=positive,
                products=products,
                proposed=attrs,
                kept=frozenset((attrs - ignored[s.pk]) | affirmed[s.pk])
                if positive
                else frozenset(),
                ignored=frozenset(ignored[s.pk]),
            )
        )
    return cases


def pnames(attrpaths: Iterable[str]) -> dict[str, str]:
    return dict(
        BranchPackage.objects.filter(attrpath__in=set(attrpaths))
        .order_by("attrpath", "branch_id")
        .distinct("attrpath")
        .values_list("attrpath", "pname")
    )


@dataclass
class TriageSync:
    learned: Learned
    created: list[ProductMapping] = field(default_factory=list)
    deleted: list[ProductMapping] = field(default_factory=list)
    # Proposals not written because a curated mapping on the same target exists.
    overridden: int = 0

    @property
    def changed(self) -> list[ProductMapping]:
        return self.created + self.deleted


@transaction.atomic
def sync_triage_mappings(learned: Learned) -> TriageSync:
    """Make the `triage` mappings equal to the proposals (relearned from scratch each time)."""
    result = TriageSync(learned)
    curated = {
        (m.product_key_id, m.attrpath)
        for m in ProductMapping.objects.filter(source=ProductMapping.Source.CURATED)
    }
    existing = {
        (m.product_key_id, m.attrpath, m.relation): m
        for m in ProductMapping.objects.filter(source=ProductMapping.Source.TRIAGE)
    }
    ids = get_or_create_keys(KeySpec(*p.key) for p in learned.proposals)
    wanted = set()
    for proposal in learned.proposals:
        key_id = ids[KeySpec(*proposal.key)]
        if (key_id, proposal.attrpath) in curated:
            result.overridden += 1
            continue
        wanted.add((key_id, proposal.attrpath, proposal.relation))
        if (key_id, proposal.attrpath, proposal.relation) in existing:
            continue
        # A relation that flipped: the unique constraint allows one row per target and source.
        stale = [
            m
            for (k, a, _), m in existing.items()
            if (k, a) == (key_id, proposal.attrpath)
        ]
        for mapping in stale:
            mapping.delete()
            result.deleted.append(mapping)
            del existing[(mapping.product_key_id, mapping.attrpath, mapping.relation)]
        result.created.append(
            ProductMapping.objects.create(
                product_key_id=key_id,
                attrpath=proposal.attrpath,
                relation=proposal.relation,
                source=ProductMapping.Source.TRIAGE,
                comment=proposal.comment(),
            )
        )
    for target, mapping in existing.items():
        if target not in wanted:
            mapping.delete()
            result.deleted.append(mapping)
    return result


def learn_triage_mappings(
    *,
    write: bool = True,
    min_same: int = MIN_SAME,
    min_not_same: int = MIN_NOT_SAME,
    min_irrelevant: int | None = None,
) -> TriageSync:
    """Relearn `triage` mappings from every labelled suggestion; with `write`, sync them."""
    suggestions = CVEDerivationClusterProposal.objects.filter(
        labelled_suggestions()
    ).select_related("cve")
    cases = triage_cases(suggestions)
    learned = propose(
        cases,
        pnames(a for c in cases for a in c.proposed),
        min_same=min_same,
        min_not_same=min_not_same,
        min_irrelevant=min_irrelevant,
    )
    if not write:
        return TriageSync(learned)
    return sync_triage_mappings(learned)
