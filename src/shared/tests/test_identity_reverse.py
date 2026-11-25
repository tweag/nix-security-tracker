from collections.abc import Callable

from shared.identity.keys import persist_product_keys
from shared.identity.reverse import reverse_match, select_suggestions
from shared.models.cve import AffectedProduct, Container
from shared.models.linkage import CVEDerivationClusterProposal
from shared.models.matching import Match, ProductKey, ProductMapping, TrackerEvent
from shared.models.nix_evaluation import NixpkgsBranch
from shared.models.snapshot import BranchPackage

MakeContainer = Callable[..., Container]
MakeSuggestion = Callable[..., CVEDerivationClusterProposal]
MakePackage = Callable[..., BranchPackage]


def open_suggestion(
    make_container: MakeContainer,
    make_suggestion: MakeSuggestion,
    cve_id: str,
    status: str = CVEDerivationClusterProposal.Status.PENDING,
    **fields: object,
) -> CVEDerivationClusterProposal:
    suggestion = make_suggestion(
        container=make_container(cve_id=cve_id, **fields), drvs={}, status=status
    )
    persist_product_keys(list(AffectedProduct.objects.all()))
    return suggestion


def test_reverse_match_finds_a_suggestion_for_a_new_attribute(
    make_container: MakeContainer,
    make_suggestion: MakeSuggestion,
    make_branch_package: MakePackage,
    branch: NixpkgsBranch,
) -> None:
    widget = open_suggestion(
        make_container,
        make_suggestion,
        "CVE-2025-1001",
        package_name=None,
        product="Widget",
    )
    other = open_suggestion(
        make_container,
        make_suggestion,
        "CVE-2025-1002",
        package_name=None,
        product="Gadget",
    )
    open_suggestion(
        make_container,
        make_suggestion,
        "CVE-2025-1003",
        status=CVEDerivationClusterProposal.Status.PUBLISHED,
        package_name=None,
        product="Widget",
    )

    make_branch_package(attrpath="python313Packages.widget", pname="python3.13-widget")
    result = reverse_match(branch, ["python313Packages.widget"])

    assert result.selected == {widget.pk: {"python313Packages.widget"}}
    assert other.pk not in result.reconciled
    assert ("name-exact", "python313Packages.widget") in result.reconciled[
        widget.pk
    ].added
    assert Match.objects.filter(suggestion=widget, matcher="name-exact").exists()
    assert TrackerEvent.objects.filter(
        suggestion=widget, cause=TrackerEvent.Cause.EVALUATION
    ).exists()


def test_reverse_selection_by_prefix_cpe_known_vulnerability_and_rule(
    make_container: MakeContainer,
    make_suggestion: MakeSuggestion,
    make_branch_package: MakePackage,
    branch: NixpkgsBranch,
) -> None:
    by_prefix = open_suggestion(
        make_container,
        make_suggestion,
        "CVE-2025-1001",
        package_name=None,
        product="Zabbix",
    )
    by_cpe = open_suggestion(
        make_container,
        make_suggestion,
        "CVE-2025-1002",
        package_name=None,
        product="Something Else",
        cpes=["cpe:2.3:a:haxx:curl:*:*:*:*:*:*:*:*"],
    )
    by_kv = open_suggestion(
        make_container,
        make_suggestion,
        "CVE-2025-1003",
        package_name=None,
        product="x y",
    )
    by_rule = open_suggestion(
        make_container,
        make_suggestion,
        "CVE-2025-1004",
        package_name=None,
        product="GeForce",
    )
    ProductMapping.objects.create(
        product_key=ProductKey.objects.get(kind="cna", product="geforce"),
        attr_glob="linuxPackages*.nvidia_x11*",
        relation="same",
        source="rule_file",
    )
    make_branch_package(attrpath="zabbix-server", pname="zabbix-server")
    make_branch_package(
        attrpath="curl-full", pname="curl-full", cpe_vendor="haxx", cpe_product="curl"
    )
    make_branch_package(
        attrpath="unrelated",
        pname="unrelated",
        known_vulnerabilities=["CVE-2025-1003: something"],
    )
    make_branch_package(attrpath="linuxPackages_6_6.nvidia_x11", pname="nvidia-x11")

    selected = select_suggestions(
        branch,
        ["zabbix-server", "curl-full", "unrelated", "linuxPackages_6_6.nvidia_x11"],
    )
    assert selected == {
        by_prefix.pk: {"zabbix-server"},
        by_cpe.pk: {"curl-full"},
        by_kv.pk: {"unrelated"},
        by_rule.pk: {"linuxPackages_6_6.nvidia_x11"},
    }


def test_reverse_ignores_absent_and_other_branch_attributes(
    make_container: MakeContainer,
    make_suggestion: MakeSuggestion,
    make_branch_package: MakePackage,
    make_branch: Callable[..., NixpkgsBranch],
    branch: NixpkgsBranch,
) -> None:
    open_suggestion(make_container, make_suggestion, "CVE-2025-1001", product="widget")
    make_branch_package(attrpath="widget", pname="widget", present=False)
    make_branch_package(attrpath="widget", pname="widget", branch=make_branch("other"))
    assert select_suggestions(branch, ["widget"]) == {}
