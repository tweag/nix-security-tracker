"""
The package list hides exactly the attributes with an all-branches `irrelevant` verdict,
whether it was set by ignoring the package or from the matching panel (review finding 7).
"""

import pytest
from rest_framework.reverse import reverse
from rest_framework.test import APIClient

from api.tests.test_suggestion_packages import (  # noqa: F401
    PACKAGE_ATTRIBUTE_1,
    PACKAGE_ATTRIBUTE_2,
    suggestion_with_packages,
)
from shared.models.linkage import CVEDerivationClusterProposal, PackageOverlay
from shared.models.matching import Match, Verdict
from shared.models.nix_evaluation import NixChannel

ATTR = PACKAGE_ATTRIBUTE_1


def packages_url(pk: int) -> str:
    return reverse("cvederivationclusterproposal-packages", kwargs={"pk": pk})


def verdicts_url(pk: int) -> str:
    return reverse("cvederivationclusterproposal-verdicts", kwargs={"pk": pk})


@pytest.fixture
def matched(
    suggestion_with_packages: CVEDerivationClusterProposal,  # noqa: F811
    channel: NixChannel,
) -> CVEDerivationClusterProposal:
    for attr in (PACKAGE_ATTRIBUTE_1, PACKAGE_ATTRIBUTE_2):
        Match.objects.create(
            suggestion=suggestion_with_packages,
            attrpath=attr,
            matcher="test",
            matcher_version=1,
            score=1.0,
        )
    return suggestion_with_packages


def ignored(s: CVEDerivationClusterProposal, attr: str = ATTR) -> bool:
    """Whether the overlay, the cached package list and the verdict all say "ignored"."""
    s.cached.refresh_from_db()
    overlay = PackageOverlay.objects.filter(
        suggestion=s, package_attribute=attr, type=PackageOverlay.Type.IGNORED
    ).exists()
    hidden = attr not in s.cached.payload["packages"]
    verdict = Verdict.objects.filter(
        suggestion=s, attrpath=attr, branch=None, verdict=Verdict.Kind.IRRELEVANT
    ).exists()
    assert overlay == hidden == verdict, (overlay, hidden, verdict)
    return overlay


def set_verdict(
    c: APIClient, s: CVEDerivationClusterProposal, verdict: str | None, **fields: object
) -> None:
    response = c.patch(
        verdicts_url(s.pk),
        {"package_attributes": [ATTR], "branch": None, "verdict": verdict} | fields,
        format="json",
    )
    assert response.status_code == 204, response.data


def test_panel_verdicts_keep_the_package_list_in_step(
    matched: CVEDerivationClusterProposal, committer_client: APIClient
) -> None:
    response = committer_client.patch(
        packages_url(matched.pk),
        {"package_attributes": [ATTR], "ignored": True},
        format="json",
    )
    assert response.status_code == 204
    assert ignored(matched)
    # "Affected" from the panel un-ignores it.
    set_verdict(committer_client, matched, "affected")
    assert not ignored(matched)
    # "Irrelevant" from the panel ignores it.
    set_verdict(committer_client, matched, "irrelevant")
    assert ignored(matched)
    # Clearing the verdict shows it again.
    set_verdict(committer_client, matched, None)
    assert not ignored(matched)
    # And restore works on a package the panel ignored.
    set_verdict(committer_client, matched, "irrelevant")
    response = committer_client.patch(
        packages_url(matched.pk),
        {"package_attributes": [ATTR], "ignored": False},
        format="json",
    )
    assert response.status_code == 204
    assert not ignored(matched)


def test_branch_irrelevant_keeps_the_package_listed(
    matched: CVEDerivationClusterProposal, committer_client: APIClient
) -> None:
    """Irrelevant on one branch says nothing about the others: the package stays listed."""
    set_verdict(committer_client, matched, "irrelevant", branch="master")
    assert not ignored(matched)


def test_bulk_verdicts_keep_the_package_list_in_step(
    matched: CVEDerivationClusterProposal, committer_client: APIClient
) -> None:
    bulk = reverse("cvederivationclusterproposal-bulk-verdicts")
    response = committer_client.patch(
        bulk + f"?package={ATTR}",
        {"package_attributes": [ATTR], "branch": None, "verdict": "irrelevant"},
        format="json",
    )
    assert response.status_code == 200, response.data
    assert ignored(matched)
    assert not ignored(matched, PACKAGE_ATTRIBUTE_2)
