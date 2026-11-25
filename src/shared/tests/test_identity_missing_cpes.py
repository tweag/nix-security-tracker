from collections.abc import Callable

import pytest
from rest_framework.reverse import reverse
from rest_framework.test import APIClient

from shared.identity.keys import persist_product_keys
from shared.identity.missing_cpes import missing_cpes_from_mappings, position_url
from shared.identity.triage import learn_triage_mappings
from shared.missing_cpes import missing_cpes
from shared.models.cve import AffectedProduct, Container, Cpe
from shared.models.linkage import CVEDerivationClusterProposal, ProvenanceFlags
from shared.models.matching import ProductKey, ProductMapping
from shared.models.nix_evaluation import NixDerivation
from shared.models.package import Package
from shared.models.snapshot import BranchPackage

Published = CVEDerivationClusterProposal.Status.PUBLISHED


def test_position_url() -> None:
    assert (
        position_url("abc", "pkgs/by-name/fo/foo/package.nix:10")
        == "https://github.com/NixOS/nixpkgs/blob/abc/pkgs/by-name/fo/foo/package.nix#L10"
    )
    assert position_url("abc", None) is None


@pytest.fixture
def two_product_cve(
    make_container: Callable[..., Container],
    make_suggestion: Callable[..., CVEDerivationClusterProposal],
    make_drv: Callable[..., NixDerivation],
    make_package: Callable[..., Package],
    make_branch_package: Callable[..., BranchPackage],
) -> None:
    """
    A published CVE naming two products, `foo` (cpe acme:foo) and `bar` (cpe acme:bar),
    with `foo` and `bar` kept; neither attribute declares a CPE. Plus a published CVE naming
    only `foo`.
    """
    drvs = {}
    for name in ("foo", "bar"):
        drv = make_drv(pname=name, attribute=name, cpe_vendor=None, cpe_product=None)
        drvs[drv] = make_package(drv, name=name)
        make_branch_package(
            attrpath=name, pname=name, position=f"pkgs/by-name/{name}/package.nix:1"
        )
    container = make_container(
        package_name=None, product="foo", cpes=["cpe:2.3:a:acme:foo:*:*:*:*:*:*:*:*"]
    )
    bar = AffectedProduct.objects.create(product="bar")
    bar.cpes.add(Cpe.objects.create(name="cpe:2.3:a:acme:bar:*:*:*:*:*:*:*:*"))
    container.affected.add(bar)
    make_suggestion(
        container=container,
        drvs=dict.fromkeys(drvs, ProvenanceFlags.PACKAGE_NAME_MATCH),
        packages=drvs,
        status=Published,
    )
    foo_only = make_container(
        cve_id="CVE-2025-0002",
        package_name=None,
        product="foo",
        cpes=["cpe:2.3:a:acme:foo:*:*:*:*:*:*:*:*"],
    )
    foo_drv = next(d for d in drvs if d.attribute == "foo")
    make_suggestion(
        container=foo_only,
        drvs={foo_drv: ProvenanceFlags.PACKAGE_NAME_MATCH},
        status=Published,
    )
    persist_product_keys(list(AffectedProduct.objects.all()))


def cpes_by_package(results: list) -> dict[str, list[str]]:
    return {r.package: [f"{c.vendor}:{c.product}" for c in r.cpes] for r in results}


def test_mappings_remove_the_cross_product(two_product_cve: None) -> None:
    # Today: both CPEs of the two-product CVE are attributed to both attributes.
    assert cpes_by_package(missing_cpes()) == {
        "bar": ["acme:bar", "acme:foo"],
        "foo": ["acme:bar", "acme:foo"],
    }
    # From learned mappings: only the unambiguous CVE teaches anything.
    learn_triage_mappings()
    assert cpes_by_package(missing_cpes_from_mappings()) == {"foo": ["acme:foo"]}
    [foo] = missing_cpes_from_mappings()
    assert foo.positions == [
        position_url(
            BranchPackage.objects.get(attrpath="foo").evaluation.commit_sha1,
            "pkgs/by-name/foo/package.nix:1",
        )
    ]


def test_declared_and_rule_mappings_are_not_missing(
    two_product_cve: None,
) -> None:
    key, _ = ProductKey.objects.get_or_create(kind="cpe", vendor="acme", product="bar")
    ProductMapping.objects.create(
        product_key=key, attrpath="bar", relation="same", source="curated"
    )
    ProductMapping.objects.create(
        product_key=key, attr_glob="bar*", relation="same", source="rule_file"
    )
    assert cpes_by_package(missing_cpes_from_mappings()) == {"bar": ["acme:bar"]}
    BranchPackage.objects.filter(attrpath="bar").update(
        cpe_vendor="ACME", cpe_product="bar"
    )
    assert missing_cpes_from_mappings() == []


def test_endpoint_source_parameter(two_product_cve: None) -> None:
    learn_triage_mappings()
    client = APIClient()
    response = client.get(reverse("missing-cpes"), {"source": "mappings"})
    assert response.status_code == 200
    assert [r["package"] for r in response.data["results"]] == ["foo"]
    assert set(response.data["results"][0]) == {
        "package",
        "attributes",
        "positions",
        "cpes",
    }
    assert len(client.get(reverse("missing-cpes")).data["results"]) == 2
    assert client.get(reverse("missing-cpes"), {"source": "x"}).status_code == 400
