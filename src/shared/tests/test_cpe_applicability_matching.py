from collections.abc import Callable
from typing import Any

from shared.matching.matchers import collect_candidates
from shared.matching.view import build_cve_view
from shared.models.cve import AffectedProduct, Container, CpeApplicability
from shared.models.nix_evaluation import NixDerivation, NixEvaluation
from shared.snapshot import update_branch_snapshot


def applicability(
    container: Container,
    vendor: str,
    product: str,
    part: str = "a",
    vulnerable: bool = True,
    **fields: Any,
) -> CpeApplicability:
    return CpeApplicability.objects.create(
        container=container,
        criteria=f"cpe:2.3:{part}:{vendor}:{product}:*:*:*:*:*:*:*:*",
        part=part,
        vendor=vendor,
        product=product,
        version="*",
        vulnerable=vulnerable,
        **fields,
    )


def cpe_hits(container: Container) -> dict[str, dict[str, Any]]:
    view = build_cve_view(container.cve)
    result = collect_candidates(view, ["nixpkgs-cpe"])["nixpkgs-cpe"]
    return {c.attrpath: c.evidence for c in result.candidates}


def test_pair_joins_the_only_affected_product(
    make_container: Callable[..., Container],
    make_drv: Callable[..., NixDerivation],
    evaluation: NixEvaluation,
) -> None:
    make_drv(pname="bar", cpe_vendor="acme", cpe_product="bar")
    update_branch_snapshot(evaluation)
    container = make_container(package_name="unrelated", product=None)
    applicability(container, "acme", "bar")

    hits = cpe_hits(container)
    assert hits["bar"]["affected_product"] == AffectedProduct.objects.get().pk
    assert hits["bar"]["cve_field"] == "cpe"


def test_pair_joins_the_product_it_names(
    make_container: Callable[..., Container],
    make_drv: Callable[..., NixDerivation],
    evaluation: NixEvaluation,
) -> None:
    make_drv(pname="bar", cpe_vendor="acme", cpe_product="bar")
    update_branch_snapshot(evaluation)
    container = make_container(
        package_name="foo", product=None, extra_affected=[("bar", [])]
    )
    applicability(container, "acme", "bar")

    hits = cpe_hits(container)
    named = AffectedProduct.objects.get(package_name="bar").pk
    assert hits["bar"]["affected_product"] == named


def test_unclaimed_pair_is_container_level(
    make_container: Callable[..., Container],
    make_drv: Callable[..., NixDerivation],
    evaluation: NixEvaluation,
) -> None:
    """Several products, none named like the CPE: no affected product to scope to."""
    make_drv(pname="libbaz", cpe_vendor="acme", cpe_product="baz_library")
    update_branch_snapshot(evaluation)
    container = make_container(
        package_name="foo", product=None, extra_affected=[("bar", [])]
    )
    applicability(container, "acme", "baz_library")

    hits = cpe_hits(container)
    assert hits["libbaz"]["affected_product"] is None


def test_windows_cve_matches_nothing(
    make_container: Callable[..., Container],
    make_drv: Callable[..., NixDerivation],
    evaluation: NixEvaluation,
) -> None:
    make_drv(pname="wine-thing", cpe_vendor="microsoft", cpe_product="windows_10")
    update_branch_snapshot(evaluation)
    container = make_container(package_name="Windows", product=None)
    applicability(container, "microsoft", "windows_10", part="o")

    assert cpe_hits(container) == {}
    view = build_cve_view(container.cve)
    assert all(not p.cpe_pairs for p in view.products)


def test_application_on_platform_uses_the_application(
    make_container: Callable[..., Container],
    make_drv: Callable[..., NixDerivation],
    evaluation: NixEvaluation,
) -> None:
    make_drv(pname="bar", cpe_vendor="acme", cpe_product="bar")
    make_drv(pname="win", cpe_vendor="microsoft", cpe_product="windows")
    update_branch_snapshot(evaluation)
    container = make_container(package_name="bar", product=None)
    applicability(container, "acme", "bar", conjunctive=True)
    applicability(
        container, "microsoft", "windows", part="o", vulnerable=False, conjunctive=True
    )

    assert set(cpe_hits(container)) == {"bar"}


def test_linux_kernel_os_cpe_is_kept(
    make_container: Callable[..., Container],
    make_drv: Callable[..., NixDerivation],
    evaluation: NixEvaluation,
) -> None:
    make_drv(
        pname="linux",
        attribute="linuxKernel.kernels.linux_6_6",
        cpe_vendor="linux",
        cpe_product="linux_kernel",
    )
    update_branch_snapshot(evaluation)
    container = make_container(package_name="Linux", product=None)
    applicability(container, "linux", "linux_kernel", part="o")

    assert set(cpe_hits(container)) == {"linuxKernel.kernels.linux_6_6"}


def test_negated_and_placeholder_criteria_are_ignored(
    make_container: Callable[..., Container],
    make_drv: Callable[..., NixDerivation],
    evaluation: NixEvaluation,
) -> None:
    make_drv(pname="bar", cpe_vendor="acme", cpe_product="bar")
    update_branch_snapshot(evaluation)
    container = make_container(package_name="unrelated", product=None)
    applicability(container, "acme", "bar", negated=True)
    applicability(container, "*", "bar")
    assert cpe_hits(container) == {}


def test_applicability_keys_are_indexed_for_reverse_matching(
    make_container: Callable[..., Container],
) -> None:
    from shared.identity.keys import attach_applicability_keys

    container = make_container(package_name="unrelated", product=None)
    applicability(container, "acme", "bar")
    applicability(container, "microsoft", "windows", part="o")
    attach_applicability_keys([container])
    keys = set(
        AffectedProduct.objects.get().product_keys.values_list(
            "kind", "vendor", "product"
        )
    )
    assert ("cpe", "acme", "bar") in keys
    assert not any(v == "microsoft" for _, v, _ in keys)
