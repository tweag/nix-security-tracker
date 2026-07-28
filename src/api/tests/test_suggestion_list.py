from collections.abc import Callable
from datetime import timedelta

from django.utils import timezone
from rest_framework.reverse import reverse
from rest_framework.test import APIClient

from shared.models.linkage import CVEDerivationClusterProposal


def url() -> str:
    return reverse("cvederivationclusterproposal-list")


def test_suggestion_list_anonymous(
    make_cached_suggestion: Callable[..., CVEDerivationClusterProposal],
) -> None:
    """Anonymous users can list suggestions."""
    client = APIClient()
    make_cached_suggestion()
    response = client.get(url())
    assert response.status_code == 200


def test_suggestion_list_paginated_shape(
    make_cached_suggestion: Callable[..., CVEDerivationClusterProposal],
) -> None:
    """The response is paginated with count/next/previous/results."""
    client = APIClient()
    make_cached_suggestion()
    response = client.get(url())
    assert response.status_code == 200
    assert set(response.data.keys()) == {"count", "next", "previous", "results"}
    assert response.data["count"] == 1
    assert len(response.data["results"]) == 1
    assert (
        response.data["results"][0]["id"]
        == CVEDerivationClusterProposal.objects.get().pk
    )


def test_suggestion_list_orders_by_most_recently_modified_first(
    make_cached_suggestion: Callable[..., CVEDerivationClusterProposal],
) -> None:
    """Suggestions are sorted by most recently updated (then created) first."""
    client = APIClient()
    older = make_cached_suggestion()
    newer = make_cached_suggestion()

    now = timezone.now()
    CVEDerivationClusterProposal.objects.filter(pk=older.pk).update(
        created_at=now - timedelta(days=2), updated_at=now - timedelta(days=2)
    )
    CVEDerivationClusterProposal.objects.filter(pk=newer.pk).update(
        created_at=now - timedelta(days=1), updated_at=now - timedelta(days=1)
    )

    response = client.get(url())
    assert response.status_code == 200
    ids = [item["id"] for item in response.data["results"]]
    assert ids == [newer.pk, older.pk]


def test_suggestion_list_reflects_updated_at_over_created_at(
    make_cached_suggestion: Callable[..., CVEDerivationClusterProposal],
) -> None:
    """A suggestion created earlier but modified more recently sorts first."""
    client = APIClient()
    created_first = make_cached_suggestion()
    created_second = make_cached_suggestion()

    now = timezone.now()
    # `created_first` was created before `created_second`, but was modified after it.
    CVEDerivationClusterProposal.objects.filter(pk=created_first.pk).update(
        created_at=now - timedelta(days=2), updated_at=now
    )
    CVEDerivationClusterProposal.objects.filter(pk=created_second.pk).update(
        created_at=now - timedelta(days=1), updated_at=now - timedelta(days=1)
    )

    response = client.get(url())
    assert response.status_code == 200
    ids = [item["id"] for item in response.data["results"]]
    assert ids == [created_first.pk, created_second.pk]


def test_suggestion_list_excludes_suggestions_without_fresh_cache(
    make_suggestion: Callable[..., CVEDerivationClusterProposal],
) -> None:
    """Suggestions without a fresh (or any) cache are not listed."""
    client = APIClient()
    uncached = make_suggestion()

    response = client.get(url())
    assert response.status_code == 200
    ids = [item["id"] for item in response.data["results"]]
    assert uncached.pk not in ids


def test_suggestion_list_excludes_outdated_algorithm_version_pending_suggestions(
    make_cached_suggestion: Callable[..., CVEDerivationClusterProposal],
) -> None:
    """Pending suggestions from an outdated matching algorithm version are excluded."""
    client = APIClient()
    outdated = make_cached_suggestion(
        status=CVEDerivationClusterProposal.Status.PENDING,
        algorithm_version=CVEDerivationClusterProposal.CURRENT_ALGORITHM_VERSION - 1,  # type: ignore[operator]
    )
    current = make_cached_suggestion(status=CVEDerivationClusterProposal.Status.PENDING)

    response = client.get(url())
    assert response.status_code == 200
    ids = [item["id"] for item in response.data["results"]]
    assert outdated.pk not in ids
    assert current.pk in ids


def test_suggestion_list_second_page(
    make_cached_suggestion: Callable[..., CVEDerivationClusterProposal],
) -> None:
    """Requesting a second page returns the next batch of results."""
    client = APIClient()
    for _ in range(15):
        make_cached_suggestion()

    first_page = client.get(url())
    assert first_page.status_code == 200
    assert first_page.data["count"] == 15
    assert len(first_page.data["results"]) == 10
    assert first_page.data["next"] is not None

    second_page = client.get(url(), {"page": 2})
    assert second_page.status_code == 200
    assert len(second_page.data["results"]) == 5
    assert second_page.data["next"] is None

    first_page_ids = {item["id"] for item in first_page.data["results"]}
    second_page_ids = {item["id"] for item in second_page.data["results"]}
    assert first_page_ids.isdisjoint(second_page_ids)
