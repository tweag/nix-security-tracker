"""
Reverse matching: given attributes that are new on a branch or changed their name or CPE
metadata, find the open suggestions they might belong to through the CVE-side product key
index, and reconcile just those (step 3 of the differential re-matching in the design report).

Selection is a superset of what the forward matchers can find for these attributes
(`test_identity_reverse_coverage`), except the matchers in `NOT_COVERED`: `name-substring`
(the product named anywhere inside the `pname`) has no index-served reverse, and at weight 0.2
it never reaches the display threshold on its own.
"""

import re
import time
from collections import defaultdict
from collections.abc import Iterable
from dataclasses import dataclass, field

from django.db import connection, transaction
from django.db.models import Q

from shared.identity.mappings import glob_regex
from shared.identity.reconcile import OPEN_STATUSES, reconcile_suggestions
from shared.matching.matchers import NameTrigram
from shared.matching.names import normalise_repo, registry_package_names
from shared.matching.reconcile import ReconcileResult
from shared.matching.selection import reopen_cutoff, reopenable_q
from shared.models.cve import CpeApplicability
from shared.models.linkage import (
    MACHINE_REOPENABLE_REJECTIONS,
    CVEDerivationClusterProposal,
)
from shared.models.matching import ProductKey, ProductMapping, ProductName, TrackerEvent
from shared.models.nix_evaluation import NixpkgsBranch
from shared.models.snapshot import BranchPackage

# Matchers whose forward hits reverse selection does not promise to find.
NOT_COVERED = ("name-substring",)

CVE_ID = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.IGNORECASE)


@dataclass
class ReverseResult:
    # Suggestion pk -> attributes that pointed at it.
    selected: dict[int, set[str]] = field(default_factory=dict)
    reconciled: dict[int, ReconcileResult] = field(default_factory=dict)
    select_seconds: float = 0.0
    reconcile_seconds: float = 0.0

    @property
    def events(self) -> int:
        return sum(r.events for r in self.reconciled.values())


def name_terms(row: BranchPackage) -> set[str]:
    """
    Terms a CVE product's `ProductName` must equal for the name matchers to find this attribute:
    `name-exact` compares against `match_pname` and `match_attr`, `name-prefix` matches when the
    term is the leading words of `match_pname` ("zabbix" for zabbix-server), and `repo-url`
    finds registry packages by name (the ecosystem attribute sets and registry homepages).
    """
    terms = {row.match_pname, row.match_attr}
    parts = row.match_pname.split("-")
    terms |= {"-".join(parts[:i]) for i in range(1, len(parts))}
    terms |= registry_package_names(row.homepage)
    return {t for t in terms if t}


def _exact_keys(rows: list[BranchPackage]) -> dict[tuple[str, str, str], set[str]]:
    exact: dict[tuple[str, str, str], set[str]] = defaultdict(set)
    for row in rows:
        if row.cpe_vendor and row.cpe_product:
            key = ("cpe", row.cpe_vendor.lower(), row.cpe_product.lower())
            exact[key].add(row.attrpath)
        repo = normalise_repo(row.homepage)
        if repo and "/" in repo:
            owner, _, name = repo.rpartition("/")
            exact[("repo", owner, name)].add(row.attrpath)
    return exact


def _names(
    exact: dict[str, set[str]], similar: dict[str, set[str]]
) -> dict[int, set[str]]:
    """
    `ProductName`s equal to an exact term, or trigram-similar to a `match_pname` as
    `name-trigram` requires, served by the unique index and `productname_term_trgm`.
    """
    found: dict[int, set[str]] = defaultdict(set)
    for pk, term in ProductName.objects.filter(term__in=list(exact)).values_list(
        "pk", "term"
    ):
        found[pk] |= exact[term]
    if not similar:
        return found
    with transaction.atomic(), connection.cursor() as cursor:
        cursor.execute(
            "SELECT set_config('pg_trgm.similarity_threshold', %s, true)",
            [str(NameTrigram.THRESHOLD)],
        )
        cursor.execute(
            f"""
            SELECT n.id, t.term
            FROM unnest(%s::text[]) AS t(term)
            JOIN {ProductName._meta.db_table} n ON n.term %% t.term
            """,
            [sorted(similar)],
        )
        for pk, term in cursor.fetchall():
            found[pk] |= similar[term]
    return found


def _keys(rows: list[BranchPackage]) -> dict[int, set[str]]:
    """Product keys of the CPE and repository an attribute declares, and of `same` mappings to it."""
    found: dict[int, set[str]] = defaultdict(set)
    exact = _exact_keys(rows)
    if exact:
        condition = Q()
        for kind, vendor, product in exact:
            condition |= Q(kind=kind, vendor=vendor, product=product)
        for key_id, kind, vendor, product in ProductKey.objects.filter(
            condition
        ).values_list("id", "kind", "vendor", "product"):
            found[key_id] |= exact[(kind, vendor, product)]
    for key_id, attrs in _keys_by_mapping({r.attrpath for r in rows}).items():
        found[key_id] |= attrs
    return found


def _applicability(rows: list[BranchPackage]) -> dict[int, set[str]]:
    """
    Containers whose `cpeApplicability` names the CPE an attribute declares. Read directly:
    pairs no affected product claims have no product key, yet `nixpkgs-cpe` matches them.
    """
    pairs: dict[tuple[str, str], set[str]] = defaultdict(set)
    for row in rows:
        if row.cpe_vendor and row.cpe_product:
            pairs[(row.cpe_vendor.lower(), row.cpe_product.lower())].add(row.attrpath)
    found: dict[int, set[str]] = defaultdict(set)
    if not pairs:
        return found
    condition = Q()
    for vendor, product in pairs:
        condition |= Q(vendor=vendor, product=product)
    for container, vendor, product in CpeApplicability.objects.filter(
        condition
    ).values_list("container_id", "vendor", "product"):
        found[container] |= pairs.get((vendor.lower(), product.lower()), set())
    return found


def _keys_by_mapping(attrpaths: set[str]) -> dict[int, set[str]]:
    found: dict[int, set[str]] = defaultdict(set)
    for key_id, attrpath, glob in ProductMapping.objects.filter(
        relation=ProductMapping.Relation.SAME
    ).values_list("product_key_id", "attrpath", "attr_glob"):
        if attrpath in attrpaths:
            found[key_id].add(attrpath)
        elif glob:
            regex = re.compile(glob_regex(glob))
            found[key_id] |= {a for a in attrpaths if regex.match(a)}
    return found


def _open_suggestions(
    names: dict[int, set[str]],
    keys: dict[int, set[str]],
    containers: dict[int, set[str]],
) -> dict[int, set[str]]:
    """Open suggestion pk -> attributes, from names, keys and containers, in one query."""
    if not (names or keys or containers):
        return {}
    cutoff = reopen_cutoff()
    with connection.cursor() as cursor:
        cursor.execute(
            """
            WITH hits(affected, via, id) AS (
                SELECT affectedproduct_id, 'n', productname_id
                FROM shared_affectedproduct_product_names WHERE productname_id = ANY(%s)
                UNION ALL
                SELECT affectedproduct_id, 'k', productkey_id
                FROM shared_affectedproduct_product_keys WHERE productkey_id = ANY(%s)
            ), found(container, via, id) AS (
                SELECT ca.container_id, h.via, h.id
                FROM hits h JOIN shared_container_affected ca ON ca.affectedproduct_id = h.affected
                UNION ALL
                SELECT c, 'c', c FROM unnest(%s::int[]) AS c
            )
            SELECT DISTINCT s.id, f.via, f.id
            FROM found f
            JOIN shared_container c ON c.id = f.container
            JOIN shared_cvederivationclusterproposal s ON s.cve_id = c.cve_id
            JOIN shared_cverecord r ON r.id = s.cve_id
            WHERE s.status = ANY(%s) OR (
                %s::timestamptz IS NOT NULL AND s.status = 'rejected'
                AND s.rejection_reason = ANY(%s) AND r.date_published >= %s::timestamptz
            )
            """,
            [
                sorted(names),
                sorted(keys),
                sorted(containers),
                list(OPEN_STATUSES),
                cutoff,
                MACHINE_REOPENABLE_REJECTIONS,
                cutoff,
            ],
        )
        sources = {"n": names, "k": keys, "c": containers}
        found: dict[int, set[str]] = defaultdict(set)
        for suggestion, via, pk in cursor.fetchall():
            found[suggestion] |= sources[via][pk]
        return found


def select_suggestions(
    branch: NixpkgsBranch | str, attrpaths: Iterable[str]
) -> dict[int, set[str]]:
    """Open suggestions the attributes might belong to, with the attributes that point at each."""
    rows = list(
        BranchPackage.objects.present().filter(
            branch=branch, attrpath__in=set(attrpaths)
        )
    )
    exact: dict[str, set[str]] = defaultdict(set)
    similar: dict[str, set[str]] = defaultdict(set)
    for row in rows:
        for term in name_terms(row):
            exact[term].add(row.attrpath)
        similar[row.match_pname].add(row.attrpath)
    selected: dict[int, set[str]] = defaultdict(
        set,
        _open_suggestions(_names(exact, similar), _keys(rows), _applicability(rows)),
    )

    # `known-vuln`: the attribute names the CVE itself.
    named: dict[str, set[str]] = defaultdict(set)
    for row in rows:
        for entry in row.known_vulnerabilities:
            for cve_id in CVE_ID.findall(entry):
                named[cve_id.upper()].add(row.attrpath)
    if named:
        for pk, cve_id in CVEDerivationClusterProposal.objects.filter(
            Q(status__in=OPEN_STATUSES) | reopenable_q(),
            cve__cve_id__in=list(named),
        ).values_list("pk", "cve__cve_id"):
            selected[pk] |= named[cve_id]
    return dict(selected)


def reverse_match(
    branch: NixpkgsBranch | str,
    attrpaths: Iterable[str],
    *,
    cause: TrackerEvent.Cause = TrackerEvent.Cause.EVALUATION,
) -> ReverseResult:
    """
    Reconcile the open suggestions that attributes new or changed on `branch` might belong to.
    Entry point for the evaluation pipeline, called with the `ADDED` and `META_CHANGED`
    attributes of a `BranchPackageChange` batch.
    """
    result = ReverseResult()
    start = time.monotonic()
    result.selected = select_suggestions(branch, attrpaths)
    result.select_seconds = time.monotonic() - start
    start = time.monotonic()
    result.reconciled = reconcile_suggestions(sorted(result.selected), cause=cause)
    result.reconcile_seconds = time.monotonic() - start
    return result
