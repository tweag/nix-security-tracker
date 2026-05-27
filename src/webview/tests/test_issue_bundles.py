"""Tests for the 'multi suggestions per issue' (issue bundle / draft) feature.

This feature is not yet implemented. These tests are written in a test-first
approach and are expected to fail until the feature is built.

User stories covered:
- Staff users see a link to the issue draft page in the nav.
- The issue draft page lists suggestions in the draft.
- The issue draft page has a text area to import suggestions by CVE ID.
- The issue draft page has a 'Publish' button.
- Accepted suggestions can be added to / removed from the draft via a button.
- Publishing the draft empties it, redirects to the published issue, and
  creates a GitHub issue that mentions all bundled suggestions.
- A published bundle issue shows the GitHub issue link and all attached
  suggestions.
- Importing by CVE ID accepts the matching suggestions and adds them to the
  draft.
- The draft is shared across all users (global state).
"""

from collections.abc import Callable
from contextlib import AbstractContextManager

import pytest
from django.contrib.auth.models import User
from django.urls import reverse
from playwright.sync_api import Page, expect
from pytest_django.live_server_helper import LiveServer
from pytest_mock import MockerFixture

from shared.models.linkage import CVEDerivationClusterProposal, ProvenanceFlags


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# Navigation
# ---------------------------------------------------------------------------


def test_staff_sees_issue_draft_link_in_nav(
    as_staff: Page,
    live_server: LiveServer,
) -> None:
    """A logged-in staff user sees a link to the issue draft page in the header/menu."""
    as_staff.goto(live_server.url + reverse("webview:suggestion:untriaged_suggestions"))
    link = as_staff.get_by_role("link", name="Issue draft")
    expect(link).to_be_visible()
    expect(link).to_have_attribute("href", reverse("webview:suggestion:issue_draft"))
    as_staff.goto(live_server.url + reverse("webview:home"))
    link = as_staff.get_by_role("link", name="Issue draft")
    expect(link).to_be_visible()
    expect(link).to_have_attribute("href", reverse("webview:suggestion:issue_draft"))


# ---------------------------------------------------------------------------
# Draft page — basic layout
# ---------------------------------------------------------------------------


def test_draft_page_lists_suggestions_in_draft(
    make_cached_suggestion: Callable[..., CVEDerivationClusterProposal],
    as_staff: Page,
    live_server: LiveServer,
    no_js: bool,
) -> None:
    """When there is at least one suggestion in the draft, it appears in the draft page list."""
    suggestion = make_cached_suggestion(
        status=CVEDerivationClusterProposal.Status.ACCEPTED,
        in_issue_draft=True
    )
    as_staff.goto(live_server.url + reverse("webview:suggestion:issue_draft"))

    entry = as_staff.locator(f"#suggestion-{suggestion.pk}")
    expect(entry).to_be_visible()


@pytest.mark.xfail(reason="Not implemented")
def test_draft_page_shows_import_textarea(
    make_cached_suggestion: Callable[..., CVEDerivationClusterProposal],
    as_staff: Page,
    live_server: LiveServer,
    no_js: bool,
) -> None:
    """The draft page has a CVE-ID import text area and an Import button."""
    suggestion = make_cached_suggestion(
        status=CVEDerivationClusterProposal.Status.ACCEPTED
    )
    suggestion.add_to_issue_draft()

    as_staff.goto(_draft_url(live_server))

    expect(as_staff.get_by_role("textbox", name="Import by CVE ID")).to_be_visible()
    expect(as_staff.get_by_role("button", name="Import")).to_be_visible()


@pytest.mark.xfail(reason="Not implemented")
def test_draft_page_shows_publish_button(
    make_cached_suggestion: Callable[..., CVEDerivationClusterProposal],
    as_staff: Page,
    live_server: LiveServer,
    no_js: bool,
) -> None:
    """When there is at least one suggestion in the draft, a Publish button is shown."""
    suggestion = make_cached_suggestion(
        status=CVEDerivationClusterProposal.Status.ACCEPTED
    )
    suggestion.add_to_issue_draft()

    as_staff.goto(_draft_url(live_server))

    expect(as_staff.get_by_role("button", name="Publish")).to_be_visible()


# ---------------------------------------------------------------------------
# Add / remove individual suggestions from the draft
# ---------------------------------------------------------------------------


@pytest.mark.xfail(reason="Not implemented")
def test_add_to_draft_button_on_accepted_suggestion(
    make_cached_suggestion: Callable[..., CVEDerivationClusterProposal],
    as_staff: Page,
    live_server: LiveServer,
    no_js: bool,
) -> None:
    """Clicking 'Add to issue draft' on an accepted suggestion adds it to the draft
    and replaces the button with 'Remove from issue draft'."""
    suggestion = make_cached_suggestion(
        status=CVEDerivationClusterProposal.Status.ACCEPTED
    )

    as_staff.goto(live_server.url + reverse("webview:suggestion:accepted_suggestions"))
    card = as_staff.locator(f"#suggestion-{suggestion.cached.pk}")

    add_button = card.get_by_role("button", name="Add to issue draft")
    expect(add_button).to_be_visible()
    add_button.click()

    # After clicking, the button should flip.
    expect(card.get_by_role("button", name="Remove from issue draft")).to_be_visible()
    expect(card.get_by_role("button", name="Add to issue draft")).to_have_count(0)

    # And the suggestion must appear on the draft page.
    as_staff.goto(_draft_url(live_server))
    expect(as_staff.locator(f"#draft-suggestion-{suggestion.pk}")).to_be_visible()


@pytest.mark.xfail(reason="Not implemented")
def test_remove_from_draft_button(
    make_cached_suggestion: Callable[..., CVEDerivationClusterProposal],
    as_staff: Page,
    live_server: LiveServer,
    no_js: bool,
) -> None:
    """Clicking 'Remove from issue draft' removes the suggestion from the draft
    and replaces the button with 'Add to issue draft'."""
    suggestion = make_cached_suggestion(
        status=CVEDerivationClusterProposal.Status.ACCEPTED
    )
    suggestion.add_to_issue_draft()

    as_staff.goto(live_server.url + reverse("webview:suggestion:accepted_suggestions"))
    card = as_staff.locator(f"#suggestion-{suggestion.cached.pk}")

    remove_button = card.get_by_role("button", name="Remove from issue draft")
    expect(remove_button).to_be_visible()
    remove_button.click()

    # Button flips back.
    expect(card.get_by_role("button", name="Add to issue draft")).to_be_visible()
    expect(card.get_by_role("button", name="Remove from issue draft")).to_have_count(0)

    # Suggestion disappears from the draft page.
    as_staff.goto(_draft_url(live_server))
    expect(as_staff.locator(f"#draft-suggestion-{suggestion.pk}")).to_have_count(0)

# ---------------------------------------------------------------------------
# Reset draft
# ---------------------------------------------------------------------------


def test_reset_draft_removes_all_suggestions(
    make_cached_suggestion: Callable[..., CVEDerivationClusterProposal],
    as_staff: Page,
    live_server: LiveServer,
    no_js: bool,
) -> None:
    """Clicking 'Reset draft' removes all suggestions from the draft and
    reloads the draft page, which then shows no suggestions."""
    suggestion1 = make_cached_suggestion(
        status=CVEDerivationClusterProposal.Status.ACCEPTED,
        in_issue_draft=True,
    )
    suggestion2 = make_cached_suggestion(
        status=CVEDerivationClusterProposal.Status.ACCEPTED,
        in_issue_draft=True,
    )

    as_staff.goto(live_server.url + reverse("webview:suggestion:issue_draft"))

    # Both suggestions are visible before the reset.
    expect(as_staff.locator(f"#suggestion-{suggestion1.pk}")).to_be_visible()
    expect(as_staff.locator(f"#suggestion-{suggestion2.pk}")).to_be_visible()

    as_staff.get_by_role("button", name="Reset draft").click()

    # After the reset the draft page is shown and lists no suggestions.
    expect(as_staff).to_have_url(
        live_server.url + reverse("webview:suggestion:issue_draft")
    )
    expect(as_staff.locator(f"#suggestion-{suggestion1.pk}")).to_have_count(0)
    expect(as_staff.locator(f"#suggestion-{suggestion2.pk}")).to_have_count(0)

    # The model-level flag must be cleared for both suggestions.
    suggestion1.refresh_from_db()
    suggestion2.refresh_from_db()
    assert not suggestion1.in_issue_draft
    assert not suggestion2.in_issue_draft


def test_reset_draft_unauthenticated_is_forbidden(
    make_cached_suggestion: Callable[..., CVEDerivationClusterProposal],
    page: Page,
    live_server: LiveServer,
    no_js: bool,
) -> None:
    """An unauthenticated user POSTing to the reset endpoint is redirected to
    login rather than being able to mutate the draft."""
    make_cached_suggestion(
        status=CVEDerivationClusterProposal.Status.ACCEPTED,
        in_issue_draft=True,
    )

    reset_url = live_server.url + reverse("webview:suggestion:reset_issue_draft")
    page.goto(reset_url)

    # Should be redirected away (to login), not reach the reset endpoint.
    expect(page).not_to_have_url(reset_url)


# ---------------------------------------------------------------------------
# Draft membership invariants
# ---------------------------------------------------------------------------

@pytest.mark.xfail(reason="Not implemented")
def test_status_change_removes_suggestion_from_draft(
    make_cached_suggestion: Callable[..., CVEDerivationClusterProposal],
    as_staff: Page,
    live_server: LiveServer,
    no_js: bool,
) -> None:
    """When a suggestion in the draft has its status changed away from ACCEPTED,
    it is automatically removed from the draft."""
    suggestion = make_cached_suggestion(
        status=CVEDerivationClusterProposal.Status.ACCEPTED
    )
    suggestion.add_to_issue_draft()

    # Sanity-check: the suggestion is visible on the draft page before the change.
    as_staff.goto(_draft_url(live_server))
    expect(as_staff.locator(f"#draft-suggestion-{suggestion.pk}")).to_be_visible()

    # Change the status away from ACCEPTED (e.g. back to PENDING).
    suggestion.change_status(CVEDerivationClusterProposal.Status.PENDING)

    # The suggestion must no longer appear in the draft.
    as_staff.goto(_draft_url(live_server))
    expect(as_staff.locator(f"#draft-suggestion-{suggestion.pk}")).to_have_count(0)

    # And the model-level flag must be cleared.
    suggestion.refresh_from_db()
    assert not suggestion.in_issue_draft


# ---------------------------------------------------------------------------
# Publishing the draft
# ---------------------------------------------------------------------------


@pytest.mark.xfail(reason="Not implemented")
def test_publish_draft_creates_github_issue_and_redirects(
    make_cached_suggestion: Callable[..., CVEDerivationClusterProposal],
    make_container: Callable,
    make_drv: Callable,
    mocker: MockerFixture,
    as_staff: Page,
    live_server: LiveServer,
    no_js: bool,
) -> None:
    """Clicking 'Publish' on the draft page:
    - creates a GitHub issue mentioning all bundled suggestions;
    - empties the draft;
    - redirects to the published issue page on the tracker.
    """
    container2 = make_container(cve_id="CVE-2025-0002")
    drv2 = make_drv(pname="bar")
    suggestion1 = make_cached_suggestion(
        status=CVEDerivationClusterProposal.Status.ACCEPTED
    )
    suggestion2 = make_cached_suggestion(
        container=container2,
        drvs={drv2: ProvenanceFlags.PACKAGE_NAME_MATCH},
        status=CVEDerivationClusterProposal.Status.ACCEPTED,
    )
    suggestion1.add_to_issue_draft()
    suggestion2.add_to_issue_draft()

    mock_repo = mocker.Mock()
    mock_issue = mocker.Mock()
    mock_issue.html_url = "https://github.com/NixOS/nixpkgs/issues/999"
    mock_repo.create_issue.return_value = mock_issue
    mock_github = mocker.Mock()
    mock_github.get_repo.return_value = mock_repo

    mocker.patch(
        "shared.github.create_gh_issue",
        side_effect=lambda *a, **kw: mock_issue,
    )

    as_staff.goto(_draft_url(live_server))
    as_staff.get_by_role("button", name="Publish").click()

    # Redirected to the published bundle issue page.
    expect(as_staff).to_have_url(lambda url: "/issues/" in url)

    # Draft is now empty — navigating back shows no suggestions.
    as_staff.goto(_draft_url(live_server))
    expect(as_staff.locator(f"#draft-suggestion-{suggestion1.pk}")).to_have_count(0)
    expect(as_staff.locator(f"#draft-suggestion-{suggestion2.pk}")).to_have_count(0)

    # GitHub issue creation was called once and the body mentions both CVEs.
    mock_repo.create_issue.assert_called_once()
    issue_body: str = mock_repo.create_issue.call_args[1]["body"]
    cve_id1 = suggestion1.cve.cve_id
    cve_id2 = suggestion2.cve.cve_id
    assert cve_id1 in issue_body, f"{cve_id1} not found in issue body"
    assert cve_id2 in issue_body, f"{cve_id2} not found in issue body"


# ---------------------------------------------------------------------------
# Published bundle issue page
# ---------------------------------------------------------------------------


@pytest.mark.xfail(reason="Not implemented")
def test_published_bundle_shows_github_link_and_all_suggestions(
    make_cached_suggestion: Callable[..., CVEDerivationClusterProposal],
    mocker: MockerFixture,
    as_staff: Page,
    live_server: LiveServer,
    no_js: bool,
) -> None:
    """A published bundle issue page shows the GitHub issue link and all
    suggestions that were part of the bundle."""
    suggestion1 = make_cached_suggestion(
        status=CVEDerivationClusterProposal.Status.ACCEPTED
    )
    suggestion2 = make_cached_suggestion(
        status=CVEDerivationClusterProposal.Status.ACCEPTED
    )

    # Create a published bundle (model helper does not exist yet).
    from shared.models.issue import NixpkgsIssueBundle  # noqa: F401 — will not exist yet

    bundle = NixpkgsIssueBundle.create_bundle(
        suggestions=[suggestion1, suggestion2],
        github_issue_url="https://github.com/NixOS/nixpkgs/issues/42",
    )

    as_staff.goto(
        live_server.url + reverse("webview:issue_bundle_detail", args=[bundle.pk])
    )

    # GitHub issue link is visible.
    github_link = as_staff.get_by_role("link", name="GitHub issue")
    expect(github_link).to_be_visible()
    expect(github_link).to_have_attribute(
        "href", "https://github.com/NixOS/nixpkgs/issues/42"
    )

    # Both suggestions are listed.
    expect(
        as_staff.locator(f"#bundle-suggestion-{suggestion1.pk}")
    ).to_be_visible()
    expect(
        as_staff.locator(f"#bundle-suggestion-{suggestion2.pk}")
    ).to_be_visible()


# ---------------------------------------------------------------------------
# Import by CVE ID
# ---------------------------------------------------------------------------


@pytest.mark.xfail(reason="Not implemented")
def test_import_by_cve_id_accepts_and_adds_to_draft(
    make_cached_suggestion: Callable[..., CVEDerivationClusterProposal],
    as_staff: Page,
    live_server: LiveServer,
    no_js: bool,
) -> None:
    """Pasting text containing CVE IDs and clicking 'Import':
    - switches matching suggestions to Accepted status;
    - adds them to the issue draft and makes them visible on the draft page.
    """
    suggestion = make_cached_suggestion(
        status=CVEDerivationClusterProposal.Status.PENDING
    )
    cve_id = suggestion.cve.cve_id

    as_staff.goto(_draft_url(live_server))

    textarea = as_staff.get_by_role("textbox", name="Import by CVE ID")
    textarea.fill(
        f"Some surrounding text {cve_id} and more text\nWith another line"
    )
    as_staff.get_by_role("button", name="Import").click()

    # The suggestion now appears in the draft.
    expect(as_staff.locator(f"#draft-suggestion-{suggestion.pk}")).to_be_visible()

    # Its status has been updated to ACCEPTED in the database.
    suggestion.refresh_from_db()
    assert suggestion.status == CVEDerivationClusterProposal.Status.ACCEPTED


# ---------------------------------------------------------------------------
# Shared draft (global state)
# ---------------------------------------------------------------------------


@pytest.mark.xfail(reason="Not implemented")
def test_draft_is_shared_across_users(
    make_cached_suggestion: Callable[..., CVEDerivationClusterProposal],
    staff: User,
    make_user: Callable[..., User],
    logged_in_as: Callable[..., AbstractContextManager[Page]],
    live_server: LiveServer,
    no_js: bool,
) -> None:
    """The issue draft is global: a second user logging in sees the same content."""
    suggestion = make_cached_suggestion(
        status=CVEDerivationClusterProposal.Status.ACCEPTED
    )
    suggestion.add_to_issue_draft()

    second_staff = make_user(
        username="second_staff",
        is_staff=True,
        uid="1000",
    )

    with logged_in_as(second_staff) as page:
        page.goto(_draft_url(live_server))
        expect(
            page.locator(f"#draft-suggestion-{suggestion.pk}")
        ).to_be_visible()

