"""
Reverse selection covers forward matching: for every matcher reverse matching claims to cover,
an attribute a forward matcher finds for an open suggestion is selected for that suggestion when
the attribute is new or changed.
"""

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

import pytest

from shared.identity.keys import persist_product_keys
from shared.identity.reverse import NOT_COVERED, select_suggestions
from shared.matching.base import REGISTRY
from shared.matching.matchers import collect_candidates
from shared.matching.view import build_cve_view
from shared.models.cve import AffectedProduct, Container, Cpe, CpeApplicability
from shared.models.linkage import CVEDerivationClusterProposal
from shared.models.matching import ProductKey, ProductMapping
from shared.models.nix_evaluation import NixpkgsBranch
from shared.models.snapshot import BranchPackage


@dataclass
class Scenario:
    """A CVE (one affected product, optionally applicability pairs and a mapping) and an attribute."""

    name: str
    # The matcher expected to find `attrpath` forward, to keep the fixture honest.
    matcher: str
    product: dict[str, Any]
    package: dict[str, Any]
    applicability: list[tuple[str, str]] = field(default_factory=list)
    mapping: dict[str, Any] | None = None


SCENARIOS = [
    Scenario("plain name", "name-exact", {"product": "Widget"}, {"attrpath": "widget"}),
    Scenario(
        "vendor word stripped",
        "name-exact",
        {"vendor": "Apache Software Foundation", "product": "Apache Tomcat"},
        {"attrpath": "tomcat"},
    ),
    Scenario(
        "vendor word stripped (firefox)",
        "name-exact",
        {"vendor": "Mozilla", "product": "Mozilla Firefox"},
        {"attrpath": "firefox"},
    ),
    Scenario(
        "tail of a qualified package name",
        "name-exact",
        {"product": "sshd", "package_name": "org.apache.sshd:sshd-core"},
        {"attrpath": "sshd-core"},
    ),
    Scenario(
        "last attribute component",
        "name-exact",
        {"product": "Requests Toolbelt"},
        {"attrpath": "python313Packages.requests-toolbelt", "pname": "python3.13-rtb"},
    ),
    Scenario(
        "trigram",
        "name-trigram",
        {"product": "ImageMagick7"},
        {"attrpath": "imagemagick", "pname": "imagemagick"},
    ),
    Scenario(
        "trigram on a derived term",
        "name-trigram",
        {"vendor": "acme", "product": "acme widgetry"},
        {"attrpath": "widgetry2", "pname": "widgetry2"},
    ),
    Scenario(
        "prefix",
        "name-prefix",
        {"product": "Zabbix"},
        {"attrpath": "zabbix-server", "pname": "zabbix-server"},
    ),
    Scenario(
        "prefix of a derived term",
        "name-prefix",
        {"vendor": "acme", "product": "acme gizmo"},
        {"attrpath": "gizmo-daemon-full", "pname": "gizmo-daemon-full"},
    ),
    Scenario(
        "cpe in affected",
        "nixpkgs-cpe",
        {"product": "something", "cpes": ["cpe:2.3:a:haxx:curl:*:*:*:*:*:*:*:*"]},
        {
            "attrpath": "curl-full",
            "pname": "curl-full",
            "cpe_vendor": "haxx",
            "cpe_product": "curl",
        },
    ),
    Scenario(
        "cpe only in cpeApplicability, unclaimed",
        "nixpkgs-cpe",
        {"product": "Other Thing", "cpes": ["cpe:2.3:h:acme:board:*:*:*:*:*:*:*:*"]},
        {
            "attrpath": "libfrob",
            "pname": "libfrob",
            "cpe_vendor": "frob",
            "cpe_product": "libfrob",
        },
        applicability=[("frob", "libfrob")],
    ),
    Scenario(
        "cpe only in cpeApplicability, claimed",
        "nixpkgs-cpe",
        {"vendor": "frob", "product": "Frob Suite"},
        {
            "attrpath": "frobd",
            "pname": "frobd",
            "cpe_vendor": "frob",
            "cpe_product": "frob_daemon",
        },
        applicability=[("frob", "frob_daemon")],
    ),
    Scenario(
        "repository homepage",
        "repo-url",
        {"product": "thing", "repo": "https://github.com/acme/thing"},
        {
            "attrpath": "unrelated",
            "pname": "unrelated",
            "homepage": "https://github.com/acme/thing",
        },
    ),
    Scenario(
        "registry page homepage",
        "repo-url",
        {
            "product": "n/a",
            "package_name": "Requests_OAuth",
            "collection_url": "https://pypi.org",
        },
        {
            "attrpath": "roauth",
            "pname": "roauth",
            "homepage": "https://pypi.org/project/requests-oauth/",
        },
    ),
    Scenario(
        "ecosystem attribute set",
        "repo-url",
        {
            "product": "n/a",
            "package_name": "Foo_Bar",
            "collection_url": "https://pypi.org",
        },
        {"attrpath": "python313Packages.foo-bar", "pname": "python3.13-fb"},
    ),
    Scenario(
        "known vulnerability",
        "known-vuln",
        {"product": "nothing alike"},
        {"attrpath": "zz", "pname": "zz", "known_vulnerabilities": ["{cve}: details"]},
    ),
    Scenario(
        "curated mapping",
        "curated",
        {"vendor": "nvidia", "product": "GPU Display Driver"},
        {"attrpath": "nvidia-settings", "pname": "nvidia-settings"},
        mapping={"attrpath": "nvidia-settings"},
    ),
    Scenario(
        "rule glob",
        "rules",
        {"vendor": "nvidia", "product": "GeForce"},
        {"attrpath": "linuxPackages_6_6.nvidia_x11", "pname": "nvidia-x11"},
        mapping={"attr_glob": "linuxPackages*.nvidia_x11*"},
    ),
]


def covered() -> set[str]:
    return set(REGISTRY) - set(NOT_COVERED)


@pytest.mark.parametrize("scenario", SCENARIOS, ids=lambda s: s.name)
def test_reverse_selects_every_forward_candidate(
    scenario: Scenario,
    make_container: Callable[..., Container],
    make_suggestion: Callable[..., CVEDerivationClusterProposal],
    make_branch_package: Callable[..., BranchPackage],
    branch: NixpkgsBranch,
) -> None:
    cve_id = "CVE-2025-4242"
    fields = dict(scenario.product)
    cpes = fields.pop("cpes", [])
    container = make_container(cve_id=cve_id, package_name=None, product=None)
    affected = container.affected.get()
    AffectedProduct.objects.filter(pk=affected.pk).update(**fields)
    for name in cpes:
        affected.cpes.add(Cpe.objects.get_or_create(name=name)[0])
    for vendor, product in scenario.applicability:
        CpeApplicability.objects.create(
            container=container,
            criteria=f"cpe:2.3:a:{vendor}:{product}:*:*:*:*:*:*:*:*",
            part="a",
            vendor=vendor,
            product=product,
            version="*",
            vulnerable=True,
        )
    suggestion = make_suggestion(container=container, drvs={})
    persist_product_keys(list(AffectedProduct.objects.all()))
    if scenario.mapping is not None:
        key = ProductKey.objects.get(
            kind="cna",
            vendor=ProductKey.normalise(fields.get("vendor")),
            product=ProductKey.normalise(fields["product"]),
        )
        ProductMapping.objects.create(
            product_key=key, relation="same", source="curated", **scenario.mapping
        )
    package = dict(scenario.package)
    package.setdefault("pname", package["attrpath"])
    package["known_vulnerabilities"] = [
        v.format(cve=cve_id) for v in package.get("known_vulnerabilities", [])
    ]
    make_branch_package(**package)

    forward = collect_candidates(build_cve_view(container.cve))
    found = {
        (slug, c.attrpath)
        for slug, result in forward.items()
        for c in result.candidates
        if slug in covered()
    }
    assert (scenario.matcher, package["attrpath"]) in found

    selected = select_suggestions(branch, {attrpath for _, attrpath in found})
    missing = {
        (slug, attrpath)
        for slug, attrpath in found
        if attrpath not in selected.get(suggestion.pk, set())
    }
    assert missing == set()
