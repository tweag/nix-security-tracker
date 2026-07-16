from collections.abc import Callable

import pytest
from django.contrib.auth.models import User
from rest_framework.reverse import reverse
from rest_framework.test import APIClient

from shared.models.linkage import CVEDerivationClusterProposal, ProvenanceFlags
from shared.models.nix_evaluation import NixDerivation, NixMaintainer

PACKAGE_ATTRIBUTE_1 = "package1"
PACKAGE_ATTRIBUTE_2 = "package2"
PACKAGE_ATTRIBUTE_NON_EXISTING = "foo"


def url(id: int) -> str:
    return reverse("cvederivationclusterproposal-packages", kwargs={"pk": id})


@pytest.fixture
def suggestion_with_packages(
    make_drv: Callable[..., NixDerivation],
    make_cached_suggestion: Callable[..., CVEDerivationClusterProposal],
) -> CVEDerivationClusterProposal:
    drv1 = make_drv(pname=PACKAGE_ATTRIBUTE_1)
    drv2 = make_drv(pname=PACKAGE_ATTRIBUTE_2)
    return make_cached_suggestion(
        drvs={
            drv1: ProvenanceFlags.PACKAGE_NAME_MATCH,
            drv2: ProvenanceFlags.PACKAGE_NAME_MATCH,
        },
    )


def test_get_packages_anonymous(
    suggestion_with_packages: CVEDerivationClusterProposal,
) -> None:
    client = APIClient()
    response = client.get(url(suggestion_with_packages.pk))
    assert response.status_code == 200
    data = response.data
    assert "original" in data
    assert "active" in data
    assert "ignored" in data
    assert PACKAGE_ATTRIBUTE_1 in data["original"]
    assert PACKAGE_ATTRIBUTE_1 in data["active"]
    assert data["ignored"] == {}


def test_get_packages_not_found(
    suggestion_with_packages: CVEDerivationClusterProposal,
) -> None:
    client = APIClient()
    response = client.get(url(suggestion_with_packages.pk + 1))
    assert response.status_code == 404


def test_patch_ignore_unauthenticated(
    suggestion_with_packages: CVEDerivationClusterProposal,
) -> None:
    client = APIClient()
    response = client.patch(
        url(suggestion_with_packages.pk),
        {"package_attribute": PACKAGE_ATTRIBUTE_1, "ignored": True},
        format="json",
    )
    assert response.status_code == 401


def test_patch_ignore_non_committer(
    suggestion_with_packages: CVEDerivationClusterProposal,
    user: User,
) -> None:
    client = APIClient()
    client.force_login(user)
    response = client.patch(
        url(suggestion_with_packages.pk),
        {"package_attribute": PACKAGE_ATTRIBUTE_1, "ignored": True},
        format="json",
    )
    assert response.status_code == 403


def test_patch_ignore_package_not_found(
    suggestion_with_packages: CVEDerivationClusterProposal,
    committer: User,
) -> None:
    client = APIClient()
    client.force_login(committer)
    response = client.patch(
        url(suggestion_with_packages.pk),
        {"package_attribute": PACKAGE_ATTRIBUTE_NON_EXISTING, "ignored": True},
        format="json",
    )
    assert response.status_code == 400


def test_patch_ignore_package_success(
    suggestion_with_packages: CVEDerivationClusterProposal,
    committer: User,
) -> None:
    client = APIClient()
    client.force_login(committer)
    response = client.patch(
        url(suggestion_with_packages.pk),
        {"package_attribute": PACKAGE_ATTRIBUTE_1, "ignored": True},
        format="json",
    )
    assert response.status_code == 204

    # Verify the package moved to ignored
    get_response = client.get(url(suggestion_with_packages.pk))
    assert get_response.status_code == 200
    data = get_response.data
    assert PACKAGE_ATTRIBUTE_1 not in data["active"]
    assert PACKAGE_ATTRIBUTE_1 in data["ignored"]


def test_patch_ignore_package_already_ignored(
    suggestion_with_packages: CVEDerivationClusterProposal,
    committer: User,
) -> None:
    client = APIClient()
    client.force_login(committer)
    # First ignore
    client.patch(
        url(suggestion_with_packages.pk),
        {"package_attribute": PACKAGE_ATTRIBUTE_1, "ignored": True},
        format="json",
    )
    # Second ignore should fail
    response = client.patch(
        url(suggestion_with_packages.pk),
        {"package_attribute": PACKAGE_ATTRIBUTE_1, "ignored": True},
        format="json",
    )
    assert response.status_code == 400


def test_patch_restore_unauthenticated(
    suggestion_with_packages: CVEDerivationClusterProposal,
) -> None:
    client = APIClient()
    response = client.patch(
        url(suggestion_with_packages.pk),
        {"package_attribute": PACKAGE_ATTRIBUTE_1, "ignored": False},
        format="json",
    )
    assert response.status_code == 401


def test_patch_restore_non_committer(
    suggestion_with_packages: CVEDerivationClusterProposal,
    user: User,
) -> None:
    client = APIClient()
    client.force_login(user)
    response = client.patch(
        url(suggestion_with_packages.pk),
        {"package_attribute": PACKAGE_ATTRIBUTE_1, "ignored": False},
        format="json",
    )
    assert response.status_code == 403


def test_patch_restore_package_not_ignored(
    suggestion_with_packages: CVEDerivationClusterProposal,
    committer: User,
) -> None:
    client = APIClient()
    client.force_login(committer)
    # Not yet ignored, so restoring should fail
    response = client.patch(
        url(suggestion_with_packages.pk),
        {"package_attribute": PACKAGE_ATTRIBUTE_1, "ignored": False},
        format="json",
    )
    assert response.status_code == 400


def test_patch_restore_package_success(
    suggestion_with_packages: CVEDerivationClusterProposal,
    committer: User,
) -> None:
    client = APIClient()
    client.force_login(committer)
    # First ignore
    client.patch(
        url(suggestion_with_packages.pk),
        {"package_attribute": PACKAGE_ATTRIBUTE_1, "ignored": True},
        format="json",
    )
    # Then restore
    response = client.patch(
        url(suggestion_with_packages.pk),
        {"package_attribute": PACKAGE_ATTRIBUTE_1, "ignored": False},
        format="json",
    )
    assert response.status_code == 204

    # Verify the package is back in active
    get_response = client.get(url(suggestion_with_packages.pk))
    assert get_response.status_code == 200
    data = get_response.data
    assert PACKAGE_ATTRIBUTE_1 in data["active"]
    assert PACKAGE_ATTRIBUTE_1 not in data["ignored"]


def test_patch_ignore_package_updates_maintainers(
    committer: User,
    make_maintainer: Callable[..., NixMaintainer],
    make_drv: Callable[..., NixDerivation],
    make_cached_suggestion: Callable[..., CVEDerivationClusterProposal],
) -> None:
    """Ignoring the only package a maintainer is associated with ignores it in the suggestion."""
    only_maintainer_of_package1 = make_maintainer(github_id=999, github="solo")
    drv1 = make_drv(pname=PACKAGE_ATTRIBUTE_1, maintainer=only_maintainer_of_package1)
    drv2 = make_drv(pname=PACKAGE_ATTRIBUTE_2)
    suggestion = make_cached_suggestion(
        drvs={
            drv1: ProvenanceFlags.PACKAGE_NAME_MATCH,
            drv2: ProvenanceFlags.PACKAGE_NAME_MATCH,
        },
    )

    client = APIClient()
    client.force_login(committer)

    suggestion_url = reverse(
        "cvederivationclusterproposal-detail", kwargs={"pk": suggestion.pk}
    )
    before = client.get(suggestion_url)
    maintainer_github_ids_before = {
        m["github_id"] for m in before.data["categorized_maintainers"]["active"]
    }
    assert only_maintainer_of_package1.github_id in maintainer_github_ids_before

    response = client.patch(
        url(suggestion.pk),
        {"package_attribute": PACKAGE_ATTRIBUTE_1, "ignored": True},
        format="json",
    )
    assert response.status_code == 204

    after = client.get(suggestion_url)
    maintainer_github_ids_after = {
        m["github_id"] for m in after.data["categorized_maintainers"]["active"]
    }
    assert only_maintainer_of_package1.github_id not in maintainer_github_ids_after
