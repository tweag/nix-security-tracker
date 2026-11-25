"""
The port of today's matcher to `BranchPackage` loses nothing.

`name-substring` searches `pname` where today's matcher searches the derivation name, so
the two agree as long as no term occurs only in a version; the data set below is of that kind.
"""

from collections.abc import Callable

from shared.listeners.automatic_linkage import resolve_linkage_candidates
from shared.matching.matchers import collect_candidates
from shared.matching.view import build_cve_view
from shared.models.cve import AffectedProduct, Container, Cpe
from shared.models.nix_evaluation import NixDerivation, parse_drv_name
from shared.models.snapshot import BranchPackage

PACKAGES = [
    # (attribute, pname, version, cpe_vendor, cpe_product)
    ("foo", "foo", "1.0", None, None),
    ("libfoo", "libfoo", "2.3", None, None),
    ("python313Packages.foo-bar", "python3.13-foo-bar", "0.1", None, None),
    ("FooTool", "FooTool", "4", None, None),
    ("bar", "bar", "1.0", None, None),
    ("barcode", "barcode", "0.99", None, None),
    ("openssl", "openssl", "3.0.1", "openssl", "openssl"),
    ("openssl_1_1", "openssl", "1.1.1w", "OpenSSL", "OpenSSL"),
    ("libressl", "libressl", "4.0", "openbsd", "libressl"),
    ("unrelated", "unrelated", "1.0", None, None),
    ("tests.foo", "foo-test", "1.0", None, None),
    ("teslajsonpy", "python3.13-teslajsonpy", "3.0", None, None),
    ("frobnicator", "frobnicator", "1.0", "acme", "frob"),
]


def test_name_substring_and_cpe_equal_todays_matcher(
    make_container: Callable[..., Container],
    make_drv: Callable[..., NixDerivation],
    make_branch_package: Callable[..., BranchPackage],
) -> None:
    for attribute, pname, version, vendor, product in PACKAGES:
        for system in ("x86_64-linux", "aarch64-darwin"):
            drv = make_drv(
                pname=pname,
                version=version,
                attribute=attribute,
                system=system,
                cpe_vendor=vendor,
                cpe_product=product,
            )
        assert parse_drv_name(drv.name) == (pname, version)
        make_branch_package(
            attrpath=attribute,
            pname=pname,
            version=version,
            cpe_vendor=vendor,
            cpe_product=product,
        )

    container = make_container(
        package_name="Foo",
        product="tesla",
        cpes=["cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:*"],
        extra_affected=[("CODE", [])],
    )
    # A hardware-only product is screened out by both.
    hardware = AffectedProduct.objects.create(product="frobnicator")
    hardware.cpes.add(Cpe.objects.create(name="cpe:2.3:h:acme:frob:-:*:*:*:*:*:*:*"))
    container.affected.add(hardware)
    # A software CPE on a product that does not name-match.
    other = AffectedProduct.objects.create(product="zzz")
    other.cpes.add(
        Cpe.objects.create(name="cpe:2.3:a:openbsd:libressl:*:*:*:*:*:*:*:*")
    )
    container.affected.add(other)

    outcome = resolve_linkage_candidates(container)
    assert outcome.rejection is None and outcome.derivations is not None
    today = {drv.attribute for drv in outcome.derivations}

    results = collect_candidates(
        build_cve_view(container.cve), ["name-substring", "nixpkgs-cpe"]
    )
    ported = {c.attrpath for r in results.values() for c in r.candidates}

    assert today == {
        "foo",
        "libfoo",
        "python313Packages.foo-bar",
        "FooTool",
        "barcode",
        "openssl",
        "openssl_1_1",
        "libressl",
        "teslajsonpy",
    }
    assert ported == today
