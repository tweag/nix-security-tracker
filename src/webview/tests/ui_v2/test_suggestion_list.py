from collections.abc import Callable
from datetime import timedelta

from django.utils import timezone
from playwright.sync_api import Page, expect
from pytest_django.live_server_helper import LiveServer

from shared.models.cve import Container
from shared.models.linkage import CVEDerivationClusterProposal

from .routes import SUGGESTION_LIST


def make_suggestions(
    count: int,
    make_container: Callable[..., Container],
    make_cached_suggestion: Callable[..., CVEDerivationClusterProposal],
) -> list[CVEDerivationClusterProposal]:
    """Create `count` distinct, cached suggestions, oldest (index 0) to newest (index count - 1)."""
    now = timezone.now()
    suggestions = []
    for i in range(count):
        container = make_container(
            cve_id=f"CVE-2026-{1000 + i}", title=f"Suggestion {i}"
        )
        suggestion = make_cached_suggestion(container=container)
        # Deterministic ordering, independent of wall-clock timing between creations.
        CVEDerivationClusterProposal.objects.filter(pk=suggestion.pk).update(
            created_at=now - timedelta(days=count - i),
            updated_at=now - timedelta(days=count - i),
        )
        suggestion.refresh_from_db()
        suggestions.append(suggestion)
    return suggestions


def test_suggestion_list_loads(
    live_server: LiveServer,
    page: Page,
    cached_suggestion: CVEDerivationClusterProposal,
) -> None:
    """The suggestion list page loads and shows a suggestion."""
    page.goto(live_server.url + SUGGESTION_LIST)
    expect(page.get_by_test_id(f"suggestion-{cached_suggestion.pk}")).to_be_visible()


def test_suggestion_list_no_pagination_controls_for_single_page(
    live_server: LiveServer,
    page: Page,
    cached_suggestion: CVEDerivationClusterProposal,
) -> None:
    """Pagination controls are hidden when there's only one page of results."""
    page.goto(live_server.url + SUGGESTION_LIST)
    expect(page.get_by_test_id(f"suggestion-{cached_suggestion.pk}")).to_be_visible()
    expect(page.get_by_role("button", name="Next page")).not_to_be_visible()


def test_suggestion_list_pagination_controls_appear_with_multiple_pages(
    live_server: LiveServer,
    page: Page,
    make_container: Callable[..., Container],
    make_cached_suggestion: Callable[..., CVEDerivationClusterProposal],
) -> None:
    """Pagination controls appear once there's more than one page of results."""
    make_suggestions(15, make_container, make_cached_suggestion)
    page.goto(live_server.url + SUGGESTION_LIST)
    expect(page.get_by_role("button", name="Next page")).to_be_visible()


def test_suggestion_list_page_navigation_shows_different_suggestions(
    live_server: LiveServer,
    page: Page,
    make_container: Callable[..., Container],
    make_cached_suggestion: Callable[..., CVEDerivationClusterProposal],
) -> None:
    """Navigating to the next page shows different suggestions, most recent first."""
    suggestions = make_suggestions(15, make_container, make_cached_suggestion)
    newest = suggestions[-1]
    oldest = suggestions[0]

    page.goto(live_server.url + SUGGESTION_LIST)
    expect(page.get_by_test_id(f"suggestion-{newest.pk}")).to_be_visible()
    expect(page.get_by_test_id(f"suggestion-{oldest.pk}")).not_to_be_visible()

    page.get_by_role("button", name="Next page").click()
    expect(page.get_by_test_id(f"suggestion-{oldest.pk}")).to_be_visible()
    expect(page.get_by_test_id(f"suggestion-{newest.pk}")).not_to_be_visible()
