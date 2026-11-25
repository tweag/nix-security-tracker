"""
Which affected products an exposure is classified against, for every kind of match evidence.
Regression tests for the 2026-11-26 review (finding 5): the Linux kernel CNA publishes one
product with git ranges and one with semver ranges under the same identity.
"""

from collections.abc import Callable
from typing import Any

import pytest

from shared.matching.matchers import collect_candidates
from shared.matching.view import build_cve_view
from shared.models.cve import AffectedProduct, Container, Version
from shared.models.matching import Exposure
from shared.models.snapshot import BranchPackage
from shared.tests.test_exposure import World, add_product, record, world  # noqa: F401
from shared.versions import Status, classify_affected_products

REPO = "https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git"
Observed = Exposure.Observed


def kernel_products(container: Container) -> tuple[AffectedProduct, AffectedProduct]:
    """The shape of CVE-2026-89970: a git product, then a semver product, same identity."""
    container.affected.clear()
    git = AffectedProduct.objects.create(
        vendor="Linux",
        product="Linux",
        repo=REPO,
        default_status="unaffected",
        default_status_recorded=True,
    )
    git.versions.add(
        Version.objects.create(
            status="affected",
            version="1a70200f404ae210b4f0334e3936e84f8edb6bc8",
            less_than="2b70200f404ae210b4f0334e3936e84f8edb6bc8",
            version_type="git",
        )
    )
    semver = AffectedProduct.objects.create(
        vendor="Linux",
        product="Linux",
        repo=REPO,
        default_status="affected",
        default_status_recorded=True,
    )
    for v, lt, le in [
        ("6.0", None, None),
        ("0", "6.0", None),
        ("6.1.188", None, "6.1.*"),
    ]:
        semver.versions.add(
            Version.objects.create(
                status="affected" if v == "6.0" else "unaffected",
                version=v,
                less_than=lt,
                less_equal=le,
                version_type="semver",
            )
        )
    container.affected.add(git, semver)
    return git, semver


def test_kernel_evidence_names_every_merged_product(
    make_container: Callable[..., Container],
    make_branch_package: Callable[..., BranchPackage],
) -> None:
    container = make_container(cve_id="CVE-2026-89970", package_name=None, product="x")
    git, semver = kernel_products(container)
    make_branch_package(attrpath="linux_6_1", pname="linux", version="6.1.100")

    result = collect_candidates(build_cve_view(container.cve), ["name-exact"])
    (candidate,) = result["name-exact"].candidates
    # Unchanged for existing readers: the first source.
    assert candidate.evidence["affected_product"] == git.pk
    assert candidate.evidence["affected_products"] == [git.pk, semver.pk]
    scoped = AffectedProduct.objects.filter(
        pk__in=candidate.evidence["affected_products"]
    )
    assert classify_affected_products("6.1.100", scoped).status == Status.AFFECTED
    assert classify_affected_products("6.1.190", scoped).status == Status.UNAFFECTED


@pytest.mark.parametrize(
    "evidence_of, version, observed",
    [
        # Stored before `affected_products` existed: names only the git row. Products of the
        # same identity are classified together, so the semver ranges still decide.
        (
            lambda git, semver: {"affected_product": git.pk},
            "6.1.100",
            Observed.AFFECTED,
        ),
        (
            lambda git, semver: {"affected_product": git.pk},
            "6.1.190",
            Observed.UNAFFECTED,
        ),
        (
            lambda git, semver: {
                "affected_product": git.pk,
                "affected_products": [git.pk, semver.pk],
            },
            "6.1.190",
            Observed.UNAFFECTED,
        ),
        (
            lambda git, semver: {"affected_product": semver.pk},
            "5.15.1",
            Observed.UNAFFECTED,
        ),
    ],
)
def test_kernel_exposure_is_decided(
    world: World,  # noqa: F811
    record: Container,  # noqa: F811
    evidence_of: Callable[[AffectedProduct, AffectedProduct], dict[str, Any]],
    version: str,
    observed: str,
) -> None:
    git, semver = kernel_products(record)
    world.match("foo", **evidence_of(git, semver))
    world.package(version)
    world.reconcile()
    assert world.row().observed == observed


@pytest.mark.parametrize(
    "evidence",
    [
        # Unattributed `cpeApplicability` pairs and `known-vuln` name no product.
        {"affected_product": None, "container": None, "cve_field": "cpe"},
        # Backfilled `legacy-v2` rows carry provenance flags only.
        {"provenance_flags": 2, "source": "legacy links", "cve_field": "product"},
        # Malformed.
        {"affected_product": "12", "affected_products": "x"},
    ],
)
def test_evidence_without_a_product_uses_all_products(
    world: World,  # noqa: F811
    record: Container,  # noqa: F811
    evidence: dict[str, Any],
) -> None:
    """The pooled reading: foo-server's range makes 3.0.1 affected."""
    record.affected.clear()
    add_product(record, "foo", [("affected", "2.0", "2.0.5")])
    add_product(record, "foo-server", [("affected", "3.0", "3.0.2")])
    world.match("foo", **evidence)
    world.package("3.0.1")
    world.reconcile()
    assert world.row().observed == Observed.AFFECTED


@pytest.mark.parametrize("matcher", ["curated", "rules", "nixpkgs-cpe", "name-exact"])
def test_evidence_naming_a_product_scopes_to_it(
    world: World,  # noqa: F811
    record: Container,  # noqa: F811
    matcher: str,
) -> None:
    """Mapping matches and attributed `cpeApplicability` pairs name their product."""
    record.affected.clear()
    foo = add_product(record, "foo", [("affected", "2.0", "2.0.5")])
    add_product(record, "foo-server", [("affected", "3.0", "3.0.2")])
    evidence: dict[str, Any] = {
        "affected_product": foo.pk,
        "affected_products": [foo.pk],
    }
    if matcher in ("curated", "rules"):
        evidence["mapping"] = {"id": 1, "relation": "same", "source": matcher}
    world.match("foo", **evidence)
    world.suggestion.matches.filter(attrpath="foo").update(matcher=matcher)
    world.package("3.0.1")
    world.reconcile()
    assert world.row().observed == Observed.UNAFFECTED


def test_matches_naming_different_products_are_combined(
    world: World,  # noqa: F811
    record: Container,  # noqa: F811
) -> None:
    record.affected.clear()
    foo = add_product(record, "foo", [("affected", "2.0", "2.0.5")])
    server = add_product(record, "foo-server", [("affected", "3.0", "3.0.2")])
    world.match("foo", affected_product=foo.pk)
    world.suggestion.matches.create(
        attrpath="foo",
        matcher="other",
        matcher_version=1,
        score=0.5,
        evidence={"affected_product": server.pk},
    )
    world.package("3.0.1")
    world.reconcile()
    assert world.row().observed == Observed.AFFECTED


def test_rematch_adds_the_product_list_silently(
    make_container: Callable[..., Container],
    make_suggestion: Callable[..., Any],
    make_branch_package: Callable[..., BranchPackage],
) -> None:
    """Stored evidence gains `affected_products` on the next re-match, without an event."""
    from shared.matching.reconcile import reconcile_matches
    from shared.models.matching import Match, TrackerEvent

    container = make_container(cve_id="CVE-2026-89970", package_name=None, product="x")
    git, semver = kernel_products(container)
    make_branch_package(attrpath="linux_6_1", pname="linux", version="6.1.100")
    suggestion = make_suggestion(container=container)
    reconcile_matches(suggestion, TrackerEvent.Cause.MATCHER, ["name-exact"])
    match = Match.objects.get(suggestion=suggestion, attrpath="linux_6_1")
    old = dict(match.evidence)
    del old["affected_products"]
    Match.objects.filter(pk=match.pk).update(evidence=old)
    events = TrackerEvent.objects.count()

    result = reconcile_matches(suggestion, TrackerEvent.Cause.MATCHER, ["name-exact"])
    assert result.events == 0
    assert TrackerEvent.objects.count() == events
    match.refresh_from_db()
    assert match.evidence["affected_products"] == [git.pk, semver.pk]
