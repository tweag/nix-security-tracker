from collections.abc import Callable

import pytest

from shared.matching.base import REGISTRY, Universe
from shared.matching.matchers import NameExact, NameTrigram, collect_candidates
from shared.matching.view import build_cve_view
from shared.models.cve import Container
from shared.models.nix_evaluation import NixChannel, NixpkgsBranch
from shared.models.snapshot import BranchPackage
from shared.tests.test_matching_view import AddContainer, add_container  # noqa: F401

MakeContainer = Callable[..., Container]
MakePackage = Callable[..., BranchPackage]


def found(container: Container, matcher: str) -> dict[str, float]:
    """Attributes the matcher proposes for the container's CVE, with scores."""
    result = collect_candidates(build_cve_view(container.cve), [matcher])[matcher]
    return {c.attrpath: c.score for c in result.candidates}


def test_registry_has_initial_matchers() -> None:
    assert set(REGISTRY) == {
        "nixpkgs-cpe",
        "known-vuln",
        "name-exact",
        "name-trigram",
        "name-prefix",
        "name-substring",
        "repo-url",
    }


def test_nixpkgs_cpe(
    make_container: MakeContainer, make_branch_package: MakePackage
) -> None:
    make_branch_package(
        attrpath="openssl", pname="openssl", cpe_vendor="OpenSSL", cpe_product="openssl"
    )
    make_branch_package(
        attrpath="libressl",
        pname="libressl",
        cpe_vendor="openbsd",
        cpe_product="openssl",
    )
    container = make_container(
        package_name=None,
        product="something else",
        cpes=["cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:*"],
    )
    assert found(container, "nixpkgs-cpe") == {"openssl": 1.0}


def test_nixpkgs_cpe_finds_cpes_only_in_adp_container(
    make_container: MakeContainer,
    add_container: AddContainer,  # noqa: F811
    make_branch_package: MakePackage,
) -> None:
    make_branch_package(
        attrpath="nvidia_x11",
        pname="nvidia-x11",
        cpe_vendor="nvidia",
        cpe_product="gpu_display_driver",
    )
    container = make_container(package_name=None, product="GPU Display Driver")
    assert found(container, "nixpkgs-cpe") == {}

    add_container(
        container,
        [
            {
                "vendor": "nvidia",
                "product": "gpu_display_driver",
                "cpes": ["cpe:2.3:a:nvidia:gpu_display_driver:*:*:*:*:*:*:*:*"],
            }
        ],
    )
    result = collect_candidates(build_cve_view(container.cve), ["nixpkgs-cpe"])
    [candidate] = result["nixpkgs-cpe"].candidates
    assert candidate.attrpath == "nvidia_x11"
    assert candidate.evidence["container"] == "adp"
    assert candidate.evidence["cve_field"] == "cpe"
    assert candidate.evidence["cve_value"] == "nvidia:gpu_display_driver"


def test_nixpkgs_cpe_ignores_hardware_cpes(
    make_container: MakeContainer, make_branch_package: MakePackage
) -> None:
    make_branch_package(
        attrpath="router", pname="router", cpe_vendor="acme", cpe_product="router"
    )
    container = make_container(
        package_name=None,
        product="router",
        cpes=["cpe:2.3:h:acme:router:-:*:*:*:*:*:*:*"],
    )
    assert found(container, "nixpkgs-cpe") == {}


def test_known_vuln_is_independent_of_names(
    make_container: MakeContainer, make_branch_package: MakePackage
) -> None:
    make_branch_package(
        attrpath="a", pname="a", known_vulnerabilities=["CVE-2025-0001"]
    )
    make_branch_package(
        attrpath="b",
        pname="b",
        known_vulnerabilities=[
            "Old",
            "CVE-2025-0001: SQL injection in the query parser",
        ],
    )
    make_branch_package(
        attrpath="c", pname="c", known_vulnerabilities=["CVE-2025-00010"]
    )
    make_branch_package(attrpath="d", pname="d")
    container = make_container(package_name="unrelated", product="unrelated")

    result = collect_candidates(build_cve_view(container.cve), ["known-vuln"])
    candidates = {c.attrpath: c for c in result["known-vuln"].candidates}
    assert set(candidates) == {"a", "b"}
    assert candidates["b"].evidence["pkg_value"].startswith("CVE-2025-0001:")


def test_name_exact(
    make_container: MakeContainer, make_branch_package: MakePackage
) -> None:
    make_branch_package(
        attrpath="python313Packages.requests", pname="python3.13-requests"
    )
    make_branch_package(attrpath="requests-tool", pname="requests-tool")
    make_branch_package(attrpath="apache-tomcat", pname="apache-tomcat")
    make_branch_package(attrpath="tomcat10", pname="tomcat")
    container = make_container(package_name="requests", product="Requests")
    assert found(container, "name-exact") == {"python313Packages.requests": 1.0}

    tomcat = make_container(
        cve_id="CVE-2025-0002", package_name=None, product="Apache Tomcat"
    )
    tomcat.affected.update(vendor="Apache Software Foundation")
    assert found(tomcat, "name-exact") == {
        "apache-tomcat": 1.0,
        "tomcat10": NameExact.DERIVED_SCORE,
    }


def test_name_exact_matches_last_attribute_component(
    make_container: MakeContainer, make_branch_package: MakePackage
) -> None:
    make_branch_package(attrpath="linuxPackages.nvidia_x11", pname="nvidia-x11-570")
    container = make_container(package_name=None, product="nvidia_x11")
    result = collect_candidates(build_cve_view(container.cve), ["name-exact"])
    [candidate] = result["name-exact"].candidates
    assert candidate.evidence["pkg_field"] == "attrpath"


def test_tesla_matches_only_by_substring(
    make_container: MakeContainer, make_branch_package: MakePackage
) -> None:
    """#1461: the Nvidia product "Tesla" is not `teslajsonpy`."""
    make_branch_package(
        attrpath="python313Packages.teslajsonpy", pname="python3.13-teslajsonpy"
    )
    container = make_container(package_name=None, product="Tesla")

    assert found(container, "name-exact") == {}
    assert found(container, "name-trigram") == {}
    substring = found(container, "name-substring")
    assert set(substring) == {"python313Packages.teslajsonpy"}
    assert substring["python313Packages.teslajsonpy"] < 0.5


def test_name_trigram(
    make_container: MakeContainer, make_branch_package: MakePackage
) -> None:
    make_branch_package(attrpath="libxml2", pname="libxml2")
    make_branch_package(attrpath="libxslt", pname="libxslt")
    container = make_container(package_name=None, product="libxml")
    result = collect_candidates(build_cve_view(container.cve), ["name-trigram"])
    [candidate] = result["name-trigram"].candidates
    assert candidate.attrpath == "libxml2"
    assert NameTrigram.THRESHOLD <= candidate.score < 1
    assert candidate.evidence["similarity"] == round(candidate.score, 3)


def test_name_trigram_skips_short_terms(
    make_container: MakeContainer, make_branch_package: MakePackage
) -> None:
    make_branch_package(attrpath="qt5", pname="qt")
    container = make_container(package_name=None, product="Qt")
    assert found(container, "name-trigram") == {}
    assert found(container, "name-exact") == {"qt5": 1.0}


def test_name_prefix(
    make_container: MakeContainer, make_branch_package: MakePackage
) -> None:
    make_branch_package(attrpath="zabbix.server", pname="zabbix-server")
    make_branch_package(attrpath="zabbix-cli", pname="python3.13-zabbix-cli")
    make_branch_package(attrpath="zabbixctl", pname="zabbixctl")
    make_branch_package(attrpath="zabbix", pname="zabbix")
    container = make_container(package_name=None, product="Zabbix")
    assert found(container, "name-prefix") == {
        "zabbix-cli": pytest.approx(6 / 10),
        "zabbix.server": pytest.approx(6 / 13),
    }


def test_name_substring_is_todays_matcher(
    make_container: MakeContainer, make_branch_package: MakePackage
) -> None:
    make_branch_package(attrpath="foo", pname="foo")
    make_branch_package(attrpath="libfoo_bar", pname="libfoo_bar")
    make_branch_package(attrpath="bar", pname="bar")
    container = make_container(package_name="foo", product="o_b")
    assert set(found(container, "name-substring")) == {"foo", "libfoo_bar"}


def test_repo_url_homepage(
    make_container: MakeContainer, make_branch_package: MakePackage
) -> None:
    make_branch_package(
        attrpath="bar", pname="bar", homepage="https://www.github.com/Foo/Bar/"
    )
    make_branch_package(
        attrpath="baz", pname="baz", homepage="https://github.com/foo/baz"
    )
    container = make_container(package_name=None, product="x")
    container.affected.update(repo="git@github.com:foo/bar.git")
    result = collect_candidates(build_cve_view(container.cve), ["repo-url"])
    [candidate] = result["repo-url"].candidates
    assert candidate.attrpath == "bar"
    assert candidate.evidence["pkg_field"] == "homepage"


def test_repo_url_ecosystem(
    make_container: MakeContainer, make_branch_package: MakePackage
) -> None:
    make_branch_package(
        attrpath="python313Packages.flask-cors", pname="python3.13-flask-cors"
    )
    make_branch_package(
        attrpath="python314Packages.flask-cors", pname="python3.14-flask-cors"
    )
    make_branch_package(attrpath="flask-cors", pname="flask-cors")
    make_branch_package(
        attrpath="pyfoo", pname="pyfoo", homepage="https://pypi.org/project/pyfoo/"
    )
    container = make_container(package_name="Flask_Cors", product="x")
    container.affected.update(collection_url="https://pypi.org/")
    assert found(container, "repo-url") == {
        "python313Packages.flask-cors": 1.0,
        "python314Packages.flask-cors": 1.0,
    }
    other = make_container(cve_id="CVE-2025-0002", package_name="pyfoo", product="x")
    other.affected.update(collection_url="https://pypi.python.org")
    assert found(other, "repo-url") == {"pyfoo": 1.0}


def test_universe(
    make_container: MakeContainer,
    make_branch_package: MakePackage,
    make_branch: Callable[..., NixpkgsBranch],
    make_channel: Callable[..., NixChannel],
) -> None:
    stable = make_branch("release-26.05")
    make_channel(
        channel_branch="nixos-26.05",
        release_branch=stable,
        state=NixChannel.ChannelState.STABLE,
    )
    eol = make_branch("release-20.03")
    make_channel(
        channel_branch="nixos-20.03",
        release_branch=eol,
        state=NixChannel.ChannelState.END_OF_LIFE,
    )
    make_branch_package(attrpath="foo", pname="foo")
    make_branch_package(attrpath="foo", pname="foo", branch=stable)
    make_branch_package(attrpath="foo2", pname="foo", branch=eol)
    make_branch_package(attrpath="foo3", pname="foo", present=False)
    make_branch_package(attrpath="tests.foo", pname="foo")
    container = make_container(package_name="foo", product=None)

    assert Universe.tracked().branches == ("master", "release-26.05")
    result = collect_candidates(build_cve_view(container.cve), ["name-exact"])
    [candidate] = result["name-exact"].candidates
    assert candidate.attrpath == "foo"
    assert candidate.evidence["branches"] == ["master", "release-26.05"]


def test_several_reasons_keep_the_best(
    make_container: MakeContainer, make_branch_package: MakePackage
) -> None:
    make_branch_package(attrpath="foo", pname="foo")
    container = make_container(package_name="foo", product="foo-cli")
    result = collect_candidates(build_cve_view(container.cve), ["name-substring"])
    [candidate] = result["name-substring"].candidates
    assert candidate.evidence["cve_field"] == "package_name"
    assert "other_hits" not in candidate.evidence

    make_branch_package(attrpath="foo-cli", pname="foo-cli")
    result = collect_candidates(build_cve_view(container.cve), ["name-substring"])
    by_attr = {c.attrpath: c for c in result["name-substring"].candidates}
    assert by_attr["foo-cli"].evidence["other_hits"] == 1


def test_limit_reports_truncation(
    make_container: MakeContainer,
    make_branch_package: MakePackage,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(NameExact, "limit", 2)
    for attr in ("a", "b", "c", "d"):
        make_branch_package(attrpath=f"{attr}.foo", pname="foo")
    container = make_container(package_name="foo", product=None)
    result = collect_candidates(build_cve_view(container.cve), ["name-exact"])
    assert [c.attrpath for c in result["name-exact"].candidates] == ["a.foo", "b.foo"]
    assert result["name-exact"].truncated == 2
    assert result["name-exact"].truncated_exact


def test_collect_rejects_unknown_matchers(make_container: MakeContainer) -> None:
    with pytest.raises(ValueError, match="nope"):
        collect_candidates(build_cve_view(make_container().cve), ["nope"])
