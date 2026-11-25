"""
Reverse matching: given attributes that are new on a branch or changed their name or CPE
metadata, find the open suggestions they might belong to through the CVE-side product key
index, and reconcile just those (step 3 of the differential re-matching in the design report).

Selection is a superset of what the forward matchers can find for these attributes, except
`name-substring` (product named somewhere inside the `pname`), which has no index-served
reverse and is kept only for comparison; and registry homepages of `repo-url`.
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
from shared.matching.names import normalise_repo
from shared.matching.reconcile import ReconcileResult
from shared.matching.selection import reopen_cutoff, reopenable_q
from shared.models.linkage import (
    MACHINE_REOPENABLE_REJECTIONS,
    CVEDerivationClusterProposal,
)
from shared.models.matching import ProductKey, ProductMapping, TrackerEvent
from shared.models.nix_evaluation import NixpkgsBranch
from shared.models.snapshot import BranchPackage

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
    """What a CVE product key could be called for this attribute to match by name."""
    terms = {row.match_pname, row.match_attr}
    # `name-prefix`: the product is the leading words of the pname ("zabbix" for zabbix-server).
    parts = row.match_pname.split("-")
    terms |= {"-".join(parts[:i]) for i in range(1, len(parts))}
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


def _keys_by_name(terms: dict[str, set[str]]) -> dict[int, set[str]]:
    """Product keys whose product is trigram-similar to a term, served by `productkey_product_trgm`."""
    found: dict[int, set[str]] = defaultdict(set)
    if not terms:
        return found
    with transaction.atomic(), connection.cursor() as cursor:
        cursor.execute(
            "SELECT set_config('pg_trgm.similarity_threshold', %s, true)",
            [str(NameTrigram.THRESHOLD)],
        )
        cursor.execute(
            f"""
            SELECT k.id, t.term
            FROM unnest(%s::text[]) AS t(term)
            JOIN {ProductKey._meta.db_table} k ON k.product %% t.term
            """,
            [sorted(terms)],
        )
        for key_id, term in cursor.fetchall():
            found[key_id] |= terms[term]
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


def _open_suggestions_by_key(key_ids: Iterable[int]) -> dict[int, set[int]]:
    """Open suggestion pk -> key ids, in one query over the key index."""
    ids = sorted(set(key_ids))
    if not ids:
        return {}
    cutoff = reopen_cutoff()
    with connection.cursor() as cursor:
        cursor.execute(
            """
            SELECT DISTINCT s.id, apk.productkey_id
            FROM shared_affectedproduct_product_keys apk
            JOIN shared_container_affected ca ON ca.affectedproduct_id = apk.affectedproduct_id
            JOIN shared_container c ON c.id = ca.container_id
            JOIN shared_cvederivationclusterproposal s ON s.cve_id = c.cve_id
            JOIN shared_cverecord r ON r.id = s.cve_id
            WHERE apk.productkey_id = ANY(%s) AND (
                s.status = ANY(%s)
                OR (%s::timestamptz IS NOT NULL AND s.status = 'rejected'
                    AND s.rejection_reason = ANY(%s) AND r.date_published >= %s::timestamptz)
            )
            """,
            [
                ids,
                list(OPEN_STATUSES),
                cutoff,
                MACHINE_REOPENABLE_REJECTIONS,
                cutoff,
            ],
        )
        found: dict[int, set[int]] = defaultdict(set)
        for suggestion, key_id in cursor.fetchall():
            found[suggestion].add(key_id)
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
    attrs_of_key: dict[int, set[str]] = defaultdict(set)
    terms: dict[str, set[str]] = defaultdict(set)
    for row in rows:
        for term in name_terms(row):
            terms[term].add(row.attrpath)
    for key_id, attrs in _keys_by_name(terms).items():
        attrs_of_key[key_id] |= attrs
    exact = _exact_keys(rows)
    if exact:
        condition = Q()
        for kind, vendor, product in exact:
            condition |= Q(kind=kind, vendor=vendor, product=product)
        for key_id, kind, vendor, product in ProductKey.objects.filter(
            condition
        ).values_list("id", "kind", "vendor", "product"):
            attrs_of_key[key_id] |= exact[(kind, vendor, product)]
    for key_id, attrs in _keys_by_mapping({r.attrpath for r in rows}).items():
        attrs_of_key[key_id] |= attrs

    selected: dict[int, set[str]] = defaultdict(set)
    for suggestion, key_ids in _open_suggestions_by_key(attrs_of_key).items():
        for key_id in key_ids:
            selected[suggestion] |= attrs_of_key[key_id]

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
