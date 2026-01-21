from collections.abc import Callable
from unittest.mock import patch

from django.contrib.messages import get_messages
from django.test import Client
from django.urls import reverse
from playwright.sync_api import Page, expect
from pytest_django.live_server_helper import LiveServer

from shared.github import create_gh_issue
from shared.listeners.cache_suggestions import cache_new_suggestions
from shared.models.cve import (
    Container,
)
from shared.models.issue import (
    EventType,
    NixpkgsEvent,
    NixpkgsIssue,
)
from shared.models.linkage import (
    CVEDerivationClusterProposal,
)
from shared.models.nix_evaluation import (
    NixDerivation,
)
from shared.tests.test_github_sync import MockGithub


def test_publish_gh_issue_empty_title(
    make_container: Callable[..., Container],
    make_suggestion: Callable[..., CVEDerivationClusterProposal],
    drv: NixDerivation,
    live_server: LiveServer,
    as_staff: Page,
    no_js: bool,
) -> None:
    """Test that creating a GitHub issue will succeed and update the suggestion status, despite empty CVE title"""
    # [tag:test-github-create_issue-title]

    # 3/4 of all CVEs in the source data have empty title
    container = make_container(title="", description="Test description")
    suggestion = make_suggestion(
        container=container, status=CVEDerivationClusterProposal.Status.ACCEPTED
    )
    cache_new_suggestions(suggestion)

    as_staff.goto(live_server.url + reverse("webview:drafts_view"))
    suggestion = as_staff.locator(f"#suggestion-{suggestion.cached.pk}")
    publish = suggestion.get_by_role("button", name="Publish issue")

    # FIXME(@fricklerhandwerk): Mock Github's `create_issue()` here, not our own procedure! [ref:todo-github-connection]
    # Then we can test in-context that the right arguments have been passed, using `mock.assert_called_with()`.
    with patch("webview.views.create_gh_issue") as mock:
        mock.side_effect = lambda *args, **kwargs: create_gh_issue(
            *args,
            github=MockGithub(expected_issue_title="Test description"),  # type: ignore
            **kwargs,
        )
        publish.click()
        # XXX(@fricklerhandwerk): Checking the mock call too early would run into a deadlock exception.
        # And only `networkidle` seems to do the trick here.
        as_staff.wait_for_load_state("networkidle")
        mock.assert_called()

    if no_js:
        error = as_staff.locator("#messages")
    else:
        error = suggestion.locator(".error-block")

    expect(error).to_have_count(0)

    if no_js:
        as_staff.goto(live_server.url + reverse("webview:issue_list"))
    else:
        link = as_staff.get_by_role("link", name="View")
        link.click()

    expect(suggestion).to_be_visible()


def test_publish_gh_issue_empty_description(
    db: None,
    make_container: Callable[..., Container],
    make_suggestion: Callable[..., CVEDerivationClusterProposal],
    drv: NixDerivation,
    authenticated_client: Client,
) -> None:
    """Test that creating a GitHub issue will succeed and update suggestion status, despite no CVE description"""
    # [tag:test-github-create_issue-description]

    url = reverse("webview:drafts_view")
    container = make_container(title="Dummy Title", description=None)
    suggestion = make_suggestion(
        container=container, status=CVEDerivationClusterProposal.Status.ACCEPTED
    )
    cache_new_suggestions(suggestion)

    # FIXME(@fricklerhandwerk): Mock Github's `create_issue()` here, not our own procedure! [ref:todo-github-connection]
    with patch("webview.views.create_gh_issue") as mock:
        mock.side_effect = lambda *args, **kwargs: create_gh_issue(
            *args,
            github=MockGithub(expected_issue_title="Dummy Title"),  # type: ignore
            **kwargs,
        )
        response = authenticated_client.post(
            url,
            {
                "suggestion_id": suggestion.pk,
                "new_status": CVEDerivationClusterProposal.Status.PUBLISHED,
                "comment": "",
                "attribute": suggestion.cached.payload["packages"].keys(),
            },
        )
        mock.assert_called()

    messages = list(get_messages(response.wsgi_request))
    assert not any(m.level_tag == "error" for m in messages), (
        "Errors on issue submission"
    )
    suggestion.refresh_from_db()
    assert suggestion.status == CVEDerivationClusterProposal.Status.PUBLISHED


def test_store_issue_link(
    make_suggestion: Callable[..., CVEDerivationClusterProposal],
    authenticated_client: Client,
) -> None:
    url = reverse("webview:drafts_view")
    suggestion = make_suggestion(status=CVEDerivationClusterProposal.Status.ACCEPTED)
    cache_new_suggestions(suggestion)
    # FIXME(@fricklerhandwerk): Mock Github's `create_issue()` here, not our own procedure! [ref:todo-github-connection]
    with patch("webview.views.create_gh_issue") as mock:
        container = suggestion.cve.container.first()
        assert container
        mock.side_effect = lambda *args, **kwargs: create_gh_issue(
            *args,
            github=MockGithub(expected_issue_title=container.title),  # type: ignore
            **kwargs,
        )
        response = authenticated_client.post(
            url,
            {
                "suggestion_id": suggestion.pk,
                "new_status": CVEDerivationClusterProposal.Status.PUBLISHED,
                "comment": "",
                "attribute": suggestion.cached.payload["packages"].keys(),
            },
        )
        mock.assert_called()
    messages = list(get_messages(response.wsgi_request))
    assert not any(m.level_tag == "error" for m in messages), (
        f"""Errors on issue submission: {"; ".join(str(m) for m in messages if m.level_tag == "error")}"""
    )
    issue = NixpkgsIssue.objects.first()
    assert issue
    assert issue.suggestion == suggestion
    result = NixpkgsEvent.objects.filter(issue=issue)
    assert result.count() == 1
    event = result.first()
    assert event
    assert event.event_type == EventType.OPENED | EventType.ISSUE
    assert event.url is not None
