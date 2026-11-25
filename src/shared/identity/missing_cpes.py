"""
"Missing CPEs" as a query over the identity tables: CPE product keys that a `same` mapping from
triage or a curator ties to an attribute, minus what nixpkgs declares for that attribute on a
tracked branch. Same response shape as `shared.missing_cpes.missing_cpes`, without its cross
product (every CPE of a CVE assigned to every kept attribute).
"""

import re
import urllib.parse
from collections import defaultdict

from shared.matching.base import Universe
from shared.missing_cpes import MissingCPEs
from shared.models.matching import ProductKey, ProductMapping
from shared.models.package import PackageAttrpath

_POSITION = re.compile(r"^(.+):(\d+)$")


def position_url(commit_sha1: str, position: str | None) -> str | None:
    """GitHub URL of a repo-relative `file:line` position (`BranchPackage.position`)."""
    if not position or not (match := _POSITION.match(position)):
        return None
    path, line = match.groups()
    return (
        f"https://github.com/NixOS/nixpkgs/blob/{urllib.parse.quote(commit_sha1)}/"
        f"{urllib.parse.quote(path)}#L{line}"
    )


def missing_cpes_from_mappings() -> list[MissingCPEs]:
    mapped: dict[str, set[MissingCPEs.CPE]] = defaultdict(set)
    for attrpath, vendor, product in ProductMapping.objects.filter(
        product_key__kind=ProductKey.Kind.CPE,
        relation=ProductMapping.Relation.SAME,
        source__in=[ProductMapping.Source.TRIAGE, ProductMapping.Source.CURATED],
        attrpath__isnull=False,
    ).values_list("attrpath", "product_key__vendor", "product_key__product"):
        mapped[attrpath].add(MissingCPEs.CPE(vendor=vendor, product=product))

    declared: dict[str, set[MissingCPEs.CPE]] = {}
    positions: dict[str, set[str]] = defaultdict(set)
    for attrpath, commit, position, vendor, product in (
        Universe.tracked()
        .packages()
        .filter(attrpath__in=list(mapped))
        .values_list(
            "attrpath",
            "evaluation__commit_sha1",
            "position",
            "cpe_vendor",
            "cpe_product",
        )
    ):
        cpes = declared.setdefault(attrpath, set())
        if vendor and product:
            cpes.add(
                MissingCPEs.CPE(
                    vendor=ProductKey.normalise(vendor),
                    product=ProductKey.normalise(product),
                )
            )
        if url := position_url(commit, position):
            positions[attrpath].add(url)

    missing = {
        attrpath: mapped[attrpath] - cpes
        for attrpath, cpes in declared.items()
        if mapped[attrpath] - cpes
    }
    grouped: dict[tuple[str, int], set[str]] = defaultdict(set)
    for attrpath, package, name in PackageAttrpath.objects.filter(
        attrpath__in=list(missing)
    ).values_list("attrpath", "package_id", "package__name"):
        grouped[(name, package)].add(attrpath)
    return [
        MissingCPEs(
            package=name,
            attributes=sorted(attributes),
            positions=sorted(set[str]().union(*(positions[a] for a in attributes))),
            cpes=sorted(
                set[MissingCPEs.CPE]().union(*(missing[a] for a in attributes)),
                key=lambda cpe: (cpe.vendor, cpe.product),
            ),
        )
        for (name, _), attributes in sorted(grouped.items())
    ]
