from collections.abc import Callable

import pytest
from django.contrib.auth.models import User
from rest_framework.reverse import reverse
from rest_framework.test import APIClient

from shared.models.cve import Container
from shared.models.issue import (
    NixpkgsIssue,
)
from shared.models.linkage import (
    CVEDerivationClusterProposal,
)


def test_published_issue(
    make_container: Callable[..., Container],
    make_cached_suggestion: Callable[..., CVEDerivationClusterProposal],
) -> None:
    container1 = make_container(cve_id="CVE-2025-1111")
    container2 = make_container(cve_id="CVE-2025-2222")
    suggestion1 = make_cached_suggestion(
        container=container1,
        status=CVEDerivationClusterProposal.Status.PUBLISHED,
    )
    suggestion2 = make_cached_suggestion(
        container=container2,
        status=CVEDerivationClusterProposal.Status.PUBLISHED,
    )

    issue1 = NixpkgsIssue.create_nixpkgs_issue(suggestion1)
    _ = NixpkgsIssue.create_nixpkgs_issue(suggestion2)
    client = APIClient()
    url = reverse("nixpkgsissue-list")

    # All CVEs
    response = client.get(url)
    assert response.status_code == 200
    assert len(response.data) == 2

    # A specific CVE
    response = client.get(url, {"cve": container1.cve.cve_id})
    assert response.status_code == 200
    assert len(response.data) == 1
    assert response.data[0]["code"] == issue1.code
    assert response.data[0]["cve"] == container1.cve.cve_id

    # Multiple CVEs
    response = client.get(
        url, {"cve": f"{container1.cve.cve_id},{container2.cve.cve_id}"}
    )
    assert response.status_code == 200
    assert len(response.data) == 2

    # Non-existent CVE
    response = client.get(url, {"cve": "CVE-9999-0000"})
    assert response.status_code == 200
    assert len(response.data) == 0


@pytest.mark.parametrize(
    # This is a smoke test to check the wiring, deliberately not exhaustive.
    # We rely on `pgtrigger` declarations and `model.clean()` to enforce constraints simple enough to be inspected manually.
    ("from_status", "to_status", "post_data", "code", "error"),
    [
        (
            CVEDerivationClusterProposal.Status.PENDING,
            CVEDerivationClusterProposal.Status.PENDING,
            {},
            400,
            "Already in status",
        ),
        (
            CVEDerivationClusterProposal.Status.PENDING,
            CVEDerivationClusterProposal.Status.ACCEPTED,
            {},
            200,
            None,
        ),
        (
            CVEDerivationClusterProposal.Status.PENDING,
            CVEDerivationClusterProposal.Status.ACCEPTED,
            {
                "rejection_reason": CVEDerivationClusterProposal.RejectionReason.NOT_IN_NIXPKGS
            },
            400,
            "Cannot set rejection reason",
        ),
        (
            CVEDerivationClusterProposal.Status.ACCEPTED,
            CVEDerivationClusterProposal.Status.REJECTED,
            {},
            400,
            "requires a reason",
        ),
        (
            CVEDerivationClusterProposal.Status.ACCEPTED,
            CVEDerivationClusterProposal.Status.REJECTED,
            {"comment": "foo", "rejection_reason": None},
            200,
            None,
        ),
        (
            CVEDerivationClusterProposal.Status.PENDING,
            CVEDerivationClusterProposal.Status.REJECTED,
            {
                "rejection_reason": CVEDerivationClusterProposal.RejectionReason.NOT_IN_NIXPKGS
            },
            200,
            None,
        ),
    ],
)
def test_suggestion_change_state(
    make_cached_suggestion: Callable[..., CVEDerivationClusterProposal],
    staff: User,
    from_status: CVEDerivationClusterProposal.Status,
    to_status: CVEDerivationClusterProposal.Status,
    post_data: dict,
    code: int,
    error: str | None,
) -> None:
    client = APIClient()
    client.force_login(staff)
    cached_suggestion = make_cached_suggestion(status=from_status)
    response = client.post(
        f"/api/v1/suggestions/{cached_suggestion.pk}/change_status",
        {
            "status": to_status,
        }
        | post_data,
        format="json",
    )
    assert response.status_code == code
    if error is not None:
        assert error in response.text
    else:
        assert response.data == {"status": to_status} | post_data
