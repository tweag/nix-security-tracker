from collections.abc import Callable
from typing import Any

import pytest

from shared.identity.keys import persist_product_keys
from shared.identity.mappings import MappingRule, Mappings, glob_regex
from shared.identity.reconcile import reconcile_mapping_change
from shared.matching.matchers import collect_candidates
from shared.matching.reconcile import reconcile_matches
from shared.matching.scoring import rank_attributes
from shared.matching.view import build_cve_view
from shared.models.cve import AffectedProduct, Container
from shared.models.linkage import CVEDerivationClusterProposal
from shared.models.matching import Match, ProductKey, ProductMapping, TrackerEvent
from shared.models.snapshot import BranchPackage

MakeContainer = Callable[..., Container]
MakePackage = Callable[..., BranchPackage]
MakeKey = Callable[..., ProductKey]
Relation = ProductMapping.Relation
Source = ProductMapping.Source
Kind = TrackerEvent.Kind


@pytest.fixture
def make_mapping(make_product_key: MakeKey) -> Callable[..., ProductMapping]:
    def wrapped(
        product: str,
        relation: str = Relation.SAME,
        attrpath: str | None = None,
        attr_glob: str | None = None,
        source: str = Source.CURATED,
        vendor: str = "",
        kind: str = ProductKey.Kind.CNA,
    ) -> ProductMapping:
        return ProductMapping.objects.create(
            product_key=make_product_key(product, vendor, kind),
            relation=relation,
            attrpath=attrpath,
            attr_glob=attr_glob,
            source=source,
        )

    return wrapped


MakeMapping = Callable[..., ProductMapping]


def persist_keys() -> None:
    """Fixtures create affected products directly; ingestion or the backfill would add keys."""
    persist_product_keys(list(AffectedProduct.objects.all()))


def found(container: Container, *matchers: str) -> dict[str, dict[str, Any]]:
    """Attributes the matchers propose for the container's CVE, with the evidence of the first."""
    results = collect_candidates(build_cve_view(container.cve), list(matchers))
    out: dict[str, dict[str, Any]] = {}
    for result in results.values():
        for c in result.candidates:
            out.setdefault(c.attrpath, c.evidence)
    return out


def test_glob_regex() -> None:
    regex = glob_regex("linuxPackages*.nvidia_x11*")
    assert regex == r"^linuxPackages.*\.nvidia_x11.*$"
    with pytest.raises(ValueError):
        glob_regex("linux[0-9]")


def test_precedence() -> None:
    key = ("cna", "", "linux")

    def rule(i: int, relation: str, source: str, **target: str) -> MappingRule:
        return MappingRule(i, key, relation, source, **target)

    only_kernel = Mappings(
        {
            key: (
                rule(1, Relation.NOT_SAME, Source.RULE_FILE, attr_glob="*"),
                rule(2, Relation.SAME, Source.RULE_FILE, attr_glob="linux_*"),
                rule(3, Relation.NOT_SAME, Source.TRIAGE, attrpath="linux_6_6"),
                rule(4, Relation.SAME, Source.TRIAGE, attrpath="linux-pam"),
                rule(5, Relation.NOT_SAME, Source.CURATED, attrpath="linux_rpi"),
            )
        }
    )
    veto = only_kernel.veto
    # The kernel glob is more specific than `*`.
    assert veto([key], "linux_6_12") is None
    # A rule file outranks triage, in both directions.
    assert veto([key], "linux_6_6") is None
    assert veto([key], "linux-pam") == only_kernel.by_key[key][0]
    # A curator outranks the rule file.
    assert veto([key], "linux_rpi") == only_kernel.by_key[key][4]
    # Other keys are unaffected.
    assert veto([("cna", "", "other")], "linux-pam") is None


def test_curated(
    make_container: MakeContainer,
    make_branch_package: MakePackage,
    make_mapping: MakeMapping,
) -> None:
    container = make_container(package_name=None, product="GPU Display Driver")
    make_branch_package(attrpath="nvidia-settings", pname="nvidia-settings")
    make_branch_package(attrpath="absent-attr", pname="absent", present=False)
    mapping = make_mapping("gpu display driver", attrpath="nvidia-settings")
    make_mapping("gpu display driver", attrpath="absent-attr")

    assert found(container, "curated") == {
        "nvidia-settings": {
            "affected_product": container.affected.get().pk,
            "container": "cna",
            "cve_field": "product_key",
            "cve_value": "cna:/gpu display driver",
            "pkg_field": "attrpath",
            "pkg_value": "nvidia-settings",
            "branches": ["master"],
            "mapping": {
                "id": mapping.pk,
                "product_key": "cna:/gpu display driver",
                "relation": "same",
                "source": "curated",
                "target": "nvidia-settings",
            },
        }
    }


def test_rules_expand_globs(
    make_container: MakeContainer,
    make_branch_package: MakePackage,
    make_mapping: MakeMapping,
) -> None:
    container = make_container(
        package_name=None,
        product="GPU Display Driver",
        cpes=["cpe:2.3:a:nvidia:gpu_display_driver:*:*:*:*:*:*:*:*"],
    )
    for attrpath in (
        "linuxPackages.nvidia_x11",
        "linuxPackages_6_12.nvidia_x11_beta",
        "linuxPackages_latest.nvidia_x11_production",
        "linuxPackages.nvidia_x11.settings",
        "nvidia_x11",
        "linuxPackagesXnvidia_x11",
    ):
        make_branch_package(attrpath=attrpath, pname="nvidia-x11")
    make_mapping(
        "gpu_display_driver",
        vendor="nvidia",
        kind=ProductKey.Kind.CPE,
        attr_glob="linuxPackages*.nvidia_x11*",
        source=Source.RULE_FILE,
    )

    candidates = found(container, "rules")
    assert sorted(candidates) == [
        "linuxPackages.nvidia_x11",
        "linuxPackages.nvidia_x11.settings",
        "linuxPackages_6_12.nvidia_x11_beta",
        "linuxPackages_latest.nvidia_x11_production",
    ]
    evidence = candidates["linuxPackages.nvidia_x11"]
    assert evidence["pkg_field"] == "attr_glob"
    assert evidence["mapping"]["target"] == "linuxPackages*.nvidia_x11*"


def test_not_same_vetoes_every_matcher(
    make_container: MakeContainer,
    make_branch_package: MakePackage,
    make_mapping: MakeMapping,
) -> None:
    container = make_container(package_name=None, product="Tesla")
    make_branch_package(attrpath="teslajsonpy", pname="teslajsonpy")
    make_branch_package(attrpath="tesla", pname="tesla")
    assert set(found(container, "name-substring", "name-exact")) == {
        "teslajsonpy",
        "tesla",
    }

    make_mapping("tesla", Relation.NOT_SAME, attrpath="teslajsonpy")
    view = build_cve_view(container.cve)
    results = collect_candidates(view, ["name-substring"])
    assert [c.attrpath for c in results["name-substring"].candidates] == ["tesla"]
    assert results["name-substring"].vetoed["teslajsonpy"]["relation"] == "not_same"


def test_irrelevant_removes_every_candidate_of_the_product(
    make_container: MakeContainer,
    make_branch_package: MakePackage,
    make_mapping: MakeMapping,
) -> None:
    container = make_container(package_name=None, product="Tesla")
    make_branch_package(attrpath="teslajsonpy", pname="teslajsonpy")
    make_branch_package(attrpath="tesla", pname="tesla")
    make_mapping("tesla", Relation.IRRELEVANT)
    assert found(container, "name-substring", "name-exact") == {}


def test_veto_is_scoped_to_the_vetoed_product(
    make_container: MakeContainer,
    make_branch_package: MakePackage,
    make_mapping: MakeMapping,
) -> None:
    # Two products both name `foo`; one of them (by its product key `bar`) is vetoed.
    container = make_container(package_name="foo", product="bar")
    make_branch_package()
    make_mapping("bar", Relation.IRRELEVANT)
    assert found(container, "name-exact") == {}

    other = make_container(
        cve_id="CVE-2025-0002",
        package_name="foo",
        product="bar",
        extra_affected=[("foo", [])],
    )
    candidates = found(other, "name-exact")
    assert list(candidates) == ["foo"]
    # The surviving evidence is the other product's.
    assert candidates["foo"]["affected_product"] != other.affected.order_by("pk")[0].pk


def test_known_vulnerability_is_never_vetoed(
    make_container: MakeContainer,
    make_branch_package: MakePackage,
    make_mapping: MakeMapping,
) -> None:
    container = make_container(package_name="foo", product=None)
    make_branch_package(known_vulnerabilities=["CVE-2025-0001"])
    make_mapping("foo", Relation.IRRELEVANT)
    assert list(found(container, "known-vuln")) == ["foo"]
    assert found(container, "name-exact") == {}


def test_veto_retracts_and_deletion_restores(
    suggestion: CVEDerivationClusterProposal,
    make_branch_package: MakePackage,
    make_mapping: MakeMapping,
) -> None:
    make_branch_package()
    persist_keys()
    reconcile_matches(suggestion, TrackerEvent.Cause.MATCHER, ["name-exact"])
    assert Match.objects.active().filter(suggestion=suggestion).count() == 1

    mapping = make_mapping("foo", Relation.NOT_SAME, attrpath="foo")
    # Ranking applies the veto before reconciliation has run.
    [ranked] = rank_attributes(suggestion)
    assert (ranked.score, ranked.matches) == (0, ())
    assert ranked.vetoed_by[0]["id"] == mapping.pk

    outcome = reconcile_mapping_change(mapping)
    assert outcome.suggestions == 1 and not outcome.deferred
    assert not Match.objects.active().filter(suggestion=suggestion).exists()
    event = TrackerEvent.objects.get(kind=Kind.MATCH_RETRACTED)
    assert event.cause == TrackerEvent.Cause.MAPPING
    assert event.data["vetoed_by"] == {
        "id": mapping.pk,
        "product_key": "cna:/foo",
        "relation": "not_same",
        "source": "curated",
        "target": "foo",
    }

    mapping.delete()
    outcome = reconcile_mapping_change(mapping)
    # A veto change runs every matcher; the vetoed one is restored, others are added.
    assert outcome.reconciled[suggestion.pk].restored == [("name-exact", "foo")]
    restored = TrackerEvent.objects.get(kind=Kind.MATCH_RESTORED)
    assert restored.cause == TrackerEvent.Cause.MAPPING
    [ranked] = rank_attributes(suggestion)
    assert ranked.score > 0.8 and ranked.vetoed_by == ()


def test_same_mapping_change_runs_only_mapped_matchers(
    suggestion: CVEDerivationClusterProposal,
    make_branch_package: MakePackage,
    make_mapping: MakeMapping,
) -> None:
    make_branch_package(attrpath="libfoo", pname="libfoo")
    persist_keys()
    mapping = make_mapping("foo", attrpath="libfoo")
    outcome = reconcile_mapping_change(mapping)
    assert outcome.reconciled[suggestion.pk].added == [("curated", "libfoo")]
    assert set(
        Match.objects.filter(suggestion=suggestion).values_list("matcher", flat=True)
    ) == {"curated"}


def test_mapping_change_on_many_suggestions_is_deferred(
    make_suggestion: Callable[..., CVEDerivationClusterProposal],
    make_container: MakeContainer,
    make_mapping: MakeMapping,
    make_branch_package: MakePackage,
) -> None:
    make_branch_package()
    suggestions = [
        make_suggestion(container=make_container(cve_id=f"CVE-2025-100{i}"))
        for i in range(3)
    ]
    persist_keys()
    mapping = make_mapping("foo", Relation.IRRELEVANT)
    outcome = reconcile_mapping_change(mapping, sync_limit=2)
    assert outcome.reconciled == {}
    assert outcome.deferred == sorted(s.pk for s in suggestions)

    # Closed suggestions are not reconciled.
    CVEDerivationClusterProposal.objects.filter(pk=suggestions[0].pk).update(
        status=CVEDerivationClusterProposal.Status.REJECTED
    )
    outcome = reconcile_mapping_change(mapping, sync_limit=2)
    assert sorted(outcome.reconciled) == sorted(s.pk for s in suggestions[1:])
