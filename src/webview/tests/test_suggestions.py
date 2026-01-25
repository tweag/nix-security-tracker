from collections.abc import Callable, Generator
from contextlib import AbstractContextManager
from datetime import timedelta
from unittest.mock import patch

import freezegun
import pytest
from allauth.socialaccount.models import SocialAccount
from django.conf import settings
from django.contrib.auth.models import User
from django.test import Client, TestCase
from django.urls import reverse
from django.utils import timezone
from freezegun.api import FakeDatetime
from playwright.sync_api import Page, expect
from pytest_django.live_server_helper import LiveServer

from shared.listeners.cache_suggestions import cache_new_suggestions
from shared.models.cve import (
    AffectedProduct,
    CveRecord,
    Description,
    Metric,
    Organization,
    Version,
)
from shared.models.linkage import (
    CVEDerivationClusterProposal,
    DerivationClusterProposalLink,
    ProvenanceFlags,
)
from shared.models.nix_evaluation import (
    NixChannel,
    NixDerivation,
    NixDerivationMeta,
    NixEvaluation,
    NixMaintainer,
)


@pytest.mark.parametrize(
    "status, editable, endpoint",
    [
        (CVEDerivationClusterProposal.Status.PENDING, True, "suggestions"),
        (CVEDerivationClusterProposal.Status.REJECTED, False, "dismissed"),
        (CVEDerivationClusterProposal.Status.ACCEPTED, True, "drafts"),
    ],
)
def test_package_removal(
    live_server: LiveServer,
    as_staff: Page,
    make_cached_suggestion: Callable[..., CVEDerivationClusterProposal],
    make_drv: Callable[..., NixDerivation],
    editable: bool,
    status: CVEDerivationClusterProposal.Status,
    endpoint: str,
    no_js: bool,
) -> None:
    """Test removing a package permanently"""
    drv1 = make_drv(pname="package1")
    drv2 = make_drv(pname="package2")
    suggestion = make_cached_suggestion(
        status=status,
        drvs={
            drv1: ProvenanceFlags.PACKAGE_NAME_MATCH,
            drv2: ProvenanceFlags.PACKAGE_NAME_MATCH,
        },
    )

    as_staff.goto(live_server.url + reverse(f"webview:{endpoint}_view"))
    matches = as_staff.locator(f"#nixpkgs-matches-{suggestion.pk}")
    expect(matches.get_by_text("package1")).to_be_visible()
    expect(matches.get_by_text("package2")).to_be_visible()

    checkbox = as_staff.locator('input[value="package1"]')
    if not editable:
        expect(checkbox).not_to_be_visible()
        return
    else:
        if no_js:
            checkbox.uncheck()
            purge = as_staff.get_by_role("button", name="Purge deleted packages")
            purge.click()
        else:
            # FIXME(@fricklerhandwerk): There's currently no visible indication whether the action is done.
            with as_staff.expect_response(
                live_server.url + reverse(f"webview:{endpoint}_view")
            ):
                checkbox.uncheck()
            as_staff.reload()

    expect(matches.get_by_text("package1")).not_to_be_visible()
    expect(matches.get_by_text("package2")).to_be_visible()


@pytest.mark.parametrize(
    "status, editable, endpoint",
    [
        (CVEDerivationClusterProposal.Status.PENDING, True, "suggestions"),
        (CVEDerivationClusterProposal.Status.REJECTED, False, "dismissed"),
        (CVEDerivationClusterProposal.Status.ACCEPTED, True, "drafts"),
    ],
)
def test_restore_package(
    live_server: LiveServer,
    as_staff: Page,
    make_cached_suggestion: Callable[..., CVEDerivationClusterProposal],
    make_drv: Callable[..., NixDerivation],
    editable: bool,
    status: CVEDerivationClusterProposal.Status,
    endpoint: str,
    no_js: bool,
) -> None:
    """Test removing a package from a suggestion in pending status (editable)"""
    drv1 = make_drv(pname="package1")
    drv2 = make_drv(pname="package2")
    suggestion = make_cached_suggestion(
        status=status,
        drvs={
            drv1: ProvenanceFlags.PACKAGE_NAME_MATCH,
            drv2: ProvenanceFlags.PACKAGE_NAME_MATCH,
        },
    )

    as_staff.goto(live_server.url + reverse(f"webview:{endpoint}_view"))
    matches = as_staff.locator(f"#nixpkgs-matches-{suggestion.pk}")
    expect(matches.get_by_text("package1")).to_be_visible()
    expect(matches.get_by_text("package2")).to_be_visible()

    checkbox = as_staff.locator('input[value="package1"]')

    if not editable:
        expect(checkbox).not_to_be_visible()
        return
    else:
        if no_js:
            checkbox.uncheck()
            checkbox.check()
            purge = as_staff.get_by_role("button", name="Purge deleted packages")
            purge.click()
        else:
            # FIXME(@fricklerhandwerk): There's currently no visible indication whether the action is done.
            with as_staff.expect_response(
                live_server.url + reverse(f"webview:{endpoint}_view")
            ):
                checkbox.uncheck()
            with as_staff.expect_response(
                live_server.url + reverse(f"webview:{endpoint}_view")
            ):
                checkbox.check()
            as_staff.reload()

    expect(matches.get_by_text("package1")).to_be_visible()
    expect(matches.get_by_text("package2")).to_be_visible()


class PackageEditActivityLogTests(TestCase):
    def setUp(self) -> None:
        # Create user and log in
        self.user = User.objects.create_user(username="admin", password="pw")
        self.user.is_staff = True
        self.user.save()

        # Create a GitHub social account for the user
        SocialAccount.objects.get_or_create(
            user=self.user,
            provider="github",
            uid="123456",
            extra_data={"login": "admin"},
        )

        self.client = Client()
        self.client.login(username="admin", password="pw")

        # Create CVE and related objects
        self.assigner = Organization.objects.create(uuid=1, short_name="foo")
        self.cve_record = CveRecord.objects.create(
            cve_id="CVE-2025-0001",
            assigner=self.assigner,
        )
        self.description = Description.objects.create(value="Test description")
        self.metric = Metric.objects.create(format="cvssV3_1", raw_cvss_json={})
        self.affected_product = AffectedProduct.objects.create(
            package_name="dummy-package"
        )
        self.affected_product.versions.add(
            Version.objects.create(status=Version.Status.AFFECTED, version="1.0")
        )
        self.cve_container = self.cve_record.container.create(
            provider=self.assigner,
            title="Dummy Title",
        )
        self.cve_container.affected.add(self.affected_product)
        self.cve_container.descriptions.add(self.description)
        self.cve_container.metrics.add(self.metric)

        # Create maintainer and metadata
        self.maintainer = NixMaintainer.objects.create(
            github_id=123,
            github="testuser",
            name="Test User",
            email="test@example.com",
        )
        self.meta1 = NixDerivationMeta.objects.create(
            description="First dummy derivation",
            insecure=False,
            available=True,
            broken=False,
            unfree=False,
            unsupported=False,
        )
        self.meta1.maintainers.add(self.maintainer)

        self.meta2 = NixDerivationMeta.objects.create(
            description="Second dummy derivation",
            insecure=False,
            available=True,
            broken=False,
            unfree=False,
            unsupported=False,
        )
        self.meta2.maintainers.add(self.maintainer)

        # Create evaluation and derivations
        self.evaluation = NixEvaluation.objects.create(
            channel=NixChannel.objects.create(
                staging_branch="release-24.05",
                channel_branch="nixos-24.05",
                head_sha1_commit="deadbeef",
                state=NixChannel.ChannelState.STABLE,
                release_version="24.05",
                repository="https://github.com/NixOS/nixpkgs",
            ),
            commit_sha1="deadbeef",
            state=NixEvaluation.EvaluationState.COMPLETED,
        )

        # Create two derivations for the same suggestion
        self.derivation1 = NixDerivation.objects.create(
            attribute="package1",
            derivation_path="/nix/store/package1.drv",
            name="package1-1.0",
            metadata=self.meta1,
            system="x86_64-linux",
            parent_evaluation=self.evaluation,
        )

        self.derivation2 = NixDerivation.objects.create(
            attribute="package2",
            derivation_path="/nix/store/package2.drv",
            name="package2-1.0",
            metadata=self.meta2,
            system="x86_64-linux",
            parent_evaluation=self.evaluation,
        )

        # Create suggestion and link both derivations
        self.suggestion = CVEDerivationClusterProposal.objects.create(
            status=CVEDerivationClusterProposal.Status.PENDING,
            cve_id=self.cve_record.pk,
        )
        DerivationClusterProposalLink.objects.create(
            proposal=self.suggestion,
            derivation=self.derivation1,
            provenance_flags=ProvenanceFlags.PACKAGE_NAME_MATCH,
        )
        DerivationClusterProposalLink.objects.create(
            proposal=self.suggestion,
            derivation=self.derivation2,
            provenance_flags=ProvenanceFlags.PACKAGE_NAME_MATCH,
        )

        # Cache the suggestion to populate the packages payload
        cache_new_suggestions(self.suggestion)
        self.suggestion.refresh_from_db()

    def test_package_removal_creates_activity_log_entry(self) -> None:
        """Test that removing a package creates an activity log entry"""
        # Remove package2 by only selecting package1
        url = reverse("webview:suggestions_view")
        self.client.post(
            url,
            {
                "suggestion_id": self.suggestion.pk,
                "attribute": ["package1"],
            },
        )

        # Check that activity log data is properly sent to the template context
        # by making a GET request to the suggestions view
        response = self.client.get(reverse("webview:suggestions_view"))
        self.assertEqual(response.status_code, 200)

        # Find our suggestion in the context
        suggestions = response.context["object_list"]
        our_suggestion = next(
            (s for s in suggestions if s.proposal_id == self.suggestion.pk), None
        )
        self.assertIsNotNone(our_suggestion)
        assert our_suggestion is not None  # Needed for type checking

        # Verify activity log is attached to the suggestion object
        self.assertTrue(hasattr(our_suggestion, "activity_log"))
        self.assertEqual(len(our_suggestion.activity_log), 1)

        # Verify the activity log entry matches what we expect
        log_entry = our_suggestion.activity_log[0]
        self.assertEqual(log_entry.action, "package.remove")
        self.assertEqual(log_entry.package_names[0], "package2")
        self.assertEqual(log_entry.username, "admin")

    def test_package_restoration_within_time_window_cancels_events(self) -> None:
        """Test that restoring a removed package within time window cancels both events"""

        url = reverse("webview:suggestions_view")
        self.client.post(
            url,
            {
                "suggestion_id": self.suggestion.pk,
                "attribute": ["package1"],
            },
        )

        with patch(
            "django.utils.timezone.now",
            return_value=timezone.now() + timedelta(seconds=5),
        ):
            self.client.post(
                url,
                {
                    "suggestion_id": self.suggestion.pk,
                    "attribute": ["package1", "package2"],
                },
            )

        # Check that activity log data is properly sent to the template context
        response = self.client.get(reverse("webview:suggestions_view"))
        self.assertEqual(response.status_code, 200)

        suggestions = response.context["object_list"]
        our_suggestion = next(
            (s for s in suggestions if s.proposal_id == self.suggestion.pk), None
        )
        self.assertIsNotNone(our_suggestion)
        assert our_suggestion is not None  # Needed for type checking

        # Verify activity log is attached and contains no events
        self.assertTrue(hasattr(our_suggestion, "activity_log"))
        self.assertEqual(len(our_suggestion.activity_log), 0)

    def test_package_restoration_outside_time_window_preserves_events(self) -> None:
        """Test that restoring a removed package outside time window preserves both events"""
        url = reverse("webview:suggestions_view")
        self.client.post(
            url,
            {
                "suggestion_id": self.suggestion.pk,
                "attribute": ["package1"],
            },
        )

        with patch(
            "django.utils.timezone.now",
            return_value=timezone.now() + timedelta(seconds=40),
        ):
            self.client.post(
                url,
                {
                    "suggestion_id": self.suggestion.pk,
                    "attribute": ["package1", "package2"],
                },
            )

        # Check that activity log data is properly sent to the template context
        response = self.client.get(reverse("webview:suggestions_view"))
        self.assertEqual(response.status_code, 200)

        suggestions = response.context["object_list"]
        our_suggestion = next(
            (s for s in suggestions if s.proposal_id == self.suggestion.pk), None
        )
        self.assertIsNotNone(our_suggestion)
        assert our_suggestion is not None  # Needed for type checking

        # Verify activity log is attached and contains both events
        self.assertTrue(hasattr(our_suggestion, "activity_log"))
        self.assertEqual(len(our_suggestion.activity_log), 2)

        # Verify the activity log entries match what we expect
        log_removal = our_suggestion.activity_log[0]
        log_restoration = our_suggestion.activity_log[1]

        self.assertEqual(log_removal.action, "package.remove")
        self.assertEqual(log_removal.package_names[0], "package2")

        self.assertEqual(log_restoration.action, "package.add")
        self.assertEqual(log_restoration.package_names[0], "package2")

    def test_multiple_package_edits_are_batched_in_activity_log(self) -> None:
        """Test that multiple package edits by the same user are batched together"""
        # Create a third derivation
        meta3 = NixDerivationMeta.objects.create(
            description="Third dummy derivation",
            insecure=False,
            available=True,
            broken=False,
            unfree=False,
            unsupported=False,
        )
        meta3.maintainers.add(self.maintainer)

        derivation3 = NixDerivation.objects.create(
            attribute="package3",
            derivation_path="/nix/store/package3.drv",
            name="package3-1.0",
            metadata=meta3,
            system="x86_64-linux",
            parent_evaluation=self.evaluation,
        )

        DerivationClusterProposalLink.objects.create(
            proposal=self.suggestion,
            derivation=derivation3,
            provenance_flags=ProvenanceFlags.PACKAGE_NAME_MATCH,
        )

        # Re-cache the suggestion to include the new package
        cache_new_suggestions(self.suggestion)
        self.suggestion.refresh_from_db()

        # Remove multiple packages by only selecting package1
        url = reverse("webview:suggestions_view")
        self.client.post(
            url,
            {
                "suggestion_id": self.suggestion.pk,
                "attribute": ["package1"],
            },
        )

        # Check that activity log data is properly sent to the template context
        response = self.client.get(reverse("webview:suggestions_view"))
        self.assertEqual(response.status_code, 200)

        # Find our suggestion in the context
        suggestions = response.context["object_list"]
        our_suggestion = next(
            (s for s in suggestions if s.proposal_id == self.suggestion.pk), None
        )
        self.assertIsNotNone(our_suggestion)
        assert our_suggestion is not None  # Needed for type checking

        # Verify activity log is attached and contains the batched event
        self.assertTrue(hasattr(our_suggestion, "activity_log"))
        self.assertEqual(len(our_suggestion.activity_log), 1)

        # Verify the batched activity log entry matches what we expect
        log_entry = our_suggestion.activity_log[0]
        self.assertEqual(log_entry.action, "package.remove")
        self.assertEqual(len(log_entry.package_names), 2)
        self.assertIn("package2", log_entry.package_names)
        self.assertIn("package3", log_entry.package_names)

    def test_package_edits_by_different_users_not_batched(self) -> None:
        """Test that package edits by different users are not batched together"""
        # Create another user
        other_user = User.objects.create_user(username="other", password="pw")
        other_user.is_staff = True
        other_user.save()

        SocialAccount.objects.get_or_create(
            user=other_user,
            provider="github",
            uid="789012",
            extra_data={"login": "other"},
        )

        # First user removes package2
        url = reverse("webview:suggestions_view")
        self.client.post(
            url,
            {
                "suggestion_id": self.suggestion.pk,
                "attribute": ["package1"],
            },
        )

        # Switch to other user and restore package2, then remove package1
        other_client = Client()
        other_client.login(username="other", password="pw")

        other_client.post(
            url,
            {
                "suggestion_id": self.suggestion.pk,
                "attribute": ["package2"],
            },
        )

        # Check that activity log data is properly sent to the template context
        response = self.client.get(reverse("webview:suggestions_view"))
        self.assertEqual(response.status_code, 200)

        # Find our suggestion in the context
        suggestions = response.context["object_list"]
        our_suggestion = next(
            (s for s in suggestions if s.proposal_id == self.suggestion.pk), None
        )
        self.assertIsNotNone(our_suggestion)
        assert our_suggestion is not None  # Needed for type checking

        # Verify activity log is attached and contains separate events for different users
        self.assertTrue(hasattr(our_suggestion, "activity_log"))
        self.assertGreaterEqual(len(our_suggestion.activity_log), 2)

        # Verify that the activity log entries have different usernames
        context_package_events = [
            e
            for e in our_suggestion.activity_log
            if hasattr(e, "action") and e.action.startswith("package.")
        ]
        context_usernames = {event.username for event in context_package_events}
        self.assertIn("admin", context_usernames)
        self.assertIn("other", context_usernames)


def test_maintainer_addition_creates_activity_log_entry(
    live_server: LiveServer,
    as_staff: Page,
    staff: User,
    committer: User,
    make_maintainer_from_user: Callable[..., NixMaintainer],
    cached_suggestion: CVEDerivationClusterProposal,
    no_js: bool,
) -> None:
    """Test that adding a maintainer creates an activity log entry"""
    if no_js:
        pytest.xfail("Not implemented")
    maintainer = make_maintainer_from_user(committer)
    as_staff.goto(live_server.url + reverse("webview:suggestions_view"))
    suggestion = as_staff.locator(f"#suggestion-{cached_suggestion.pk}")
    maintainers_list = suggestion.locator(f"#maintainers-list-{cached_suggestion.pk}")
    maintainers_list.locator("input").fill(maintainer.github)
    add = maintainers_list.get_by_role("button", name="Add")
    add.click()
    maintainers_list = suggestion.locator(f"#maintainers-list-{cached_suggestion.pk}")
    new_maintainer = maintainers_list.get_by_text(maintainer.github)
    expect(new_maintainer).to_be_visible()
    if not no_js:
        # FIXME(@fricklerhandwerk): Activity log should be updated automatically
        as_staff.reload()
    activity_log = suggestion.locator(
        f"#suggestion-activity-log-{cached_suggestion.pk}"
    )
    activity_log.click()
    activity_log.get_by_text(staff.username)
    entry = (
        activity_log.filter(has_text=staff.username)
        .filter(has_text="added maintainer")
        .filter(has_text=maintainer.github)
    )
    expect(entry).to_be_visible()


def test_maintainer_removal_creates_activity_log_entry(
    live_server: LiveServer,
    as_staff: Page,
    staff: User,
    committer: User,
    cached_suggestion: CVEDerivationClusterProposal,
    no_js: bool,
) -> None:
    """Test that removing a maintainer creates an activity log entry"""
    if no_js:
        pytest.xfail("Not implemented")
    as_staff.goto(live_server.url + reverse("webview:suggestions_view"))
    suggestion = as_staff.locator(f"#suggestion-{cached_suggestion.pk}")
    maintainers_list = suggestion.locator(f"#maintainers-list-{cached_suggestion.pk}")
    maintainer_name, *_ = cached_suggestion.derivations.all().values_list(
        "metadata__maintainers__github", flat=True
    )
    remove = maintainers_list.get_by_role("button", name="Remove")
    remove.click()
    restore = maintainers_list.get_by_role("button", name="Restore")
    expect(restore).to_be_visible()
    # FIXME(@fricklerhandwerk): Activity log should be updated automatically
    as_staff.reload()

    activity_log = suggestion.locator(
        f"#suggestion-activity-log-{cached_suggestion.pk}"
    )
    activity_log.click()
    entry = (
        activity_log.filter(has_text=staff.username)
        .filter(has_text="removed maintainer")
        .filter(has_text=maintainer_name)
    )
    expect(entry).to_be_visible()


@pytest.fixture()
def frozen_time() -> Generator:
    with freezegun.freeze_time("2026-01-13") as ft:
        yield ft


@pytest.mark.parametrize(
    "within_interval",
    [True, False],
)
def test_maintainer_restoration_activity_log_cancels(
    live_server: LiveServer,
    as_staff: Page,
    staff: User,
    committer: User,
    cached_suggestion: CVEDerivationClusterProposal,
    frozen_time: FakeDatetime,
    no_js: bool,
    within_interval: bool,
) -> None:
    """Test that restoring a removed maintainer within time window cancels both events"""
    if no_js:
        pytest.xfail("Not implemented")
    as_staff.goto(live_server.url + reverse("webview:suggestions_view"))
    suggestion = as_staff.locator(f"#suggestion-{cached_suggestion.pk}")
    maintainers_list = suggestion.locator(f"#maintainers-list-{cached_suggestion.pk}")
    maintainer_name, *_ = cached_suggestion.derivations.all().values_list(
        "metadata__maintainers__github", flat=True
    )

    remove = maintainers_list.get_by_role("button", name="Remove")
    remove.click()
    expect(remove).not_to_be_visible()

    if within_interval:
        seconds = settings.DEBOUNCE_ACTIVITY_LOG_SECONDS / 2
    else:
        seconds = settings.DEBOUNCE_ACTIVITY_LOG_SECONDS * 2

    frozen_time.tick(delta=timedelta(seconds=seconds))
    restore = maintainers_list.get_by_role("button", name="Restore")
    expect(restore).to_be_visible()
    restore.click()
    expect(restore).not_to_be_visible()

    # FIXME(@fricklerhandwerk): Activity log should be updated automatically
    as_staff.reload()

    activity_log = suggestion.locator(
        f"#suggestion-activity-log-{cached_suggestion.pk}"
    )
    if not within_interval:
        expect(activity_log).to_be_visible()
        activity_log.click()
        removed_maintainer = (
            activity_log.filter(has_text=staff.username)
            .filter(has_text="removed maintainer")
            .filter(has_text=maintainer_name)
        )
        added_maintainer = (
            activity_log.filter(has_text=staff.username)
            .filter(has_text="added maintainer")
            .filter(has_text=maintainer_name)
        )
        expect(removed_maintainer).to_be_visible()
        expect(added_maintainer).to_be_visible()
    else:
        expect(activity_log).to_have_count(0)


def test_multiple_maintainer_edits_are_batched_in_activity_log(
    live_server: LiveServer,
    as_staff: Page,
    staff: User,
    committer: User,
    cached_suggestion: CVEDerivationClusterProposal,
    make_maintainer_from_user: Callable[..., NixMaintainer],
    no_js: bool,
) -> None:
    """Test that multiple maintainer edits by the same user are batched together"""
    if no_js:
        pytest.xfail("Not implemented")
    as_staff.goto(live_server.url + reverse("webview:suggestions_view"))
    suggestion = as_staff.locator(f"#suggestion-{cached_suggestion.pk}")
    maintainers_list = suggestion.locator(f"#maintainers-list-{cached_suggestion.pk}")
    maintainer1 = make_maintainer_from_user(staff)
    maintainer2 = make_maintainer_from_user(committer)
    name = maintainers_list.locator("input")
    name.fill(maintainer1.github)
    add = maintainers_list.get_by_role("button", name="Add")
    add.click()
    remove = maintainers_list.get_by_role("button", name="Remove")
    # There's already one maintainer in the `cached_suggestion`'s derivaiton 'by default
    expect(remove).to_have_count(2)
    name.fill(maintainer2.github)
    add.click()
    expect(remove).to_have_count(3)

    # FIXME(@fricklerhandwerk): Activity log should be updated automatically
    as_staff.reload()

    activity_log = suggestion.locator(
        f"#suggestion-activity-log-{cached_suggestion.pk}"
    )
    expect(activity_log).to_be_visible()
    activity_log.click()
    # FIXME(@fricklerhandwerk): We may want to not collapse events that are further apart than some threshold.
    added_maintainers = (
        activity_log.filter(has_text=staff.username)
        .filter(has_text="added")
        .filter(has_text="2 maintainers")
    )
    expect(added_maintainers).to_be_visible()


def test_maintainer_edits_by_different_users_not_batched(
    live_server: LiveServer,
    logged_in_as: Callable[..., AbstractContextManager[Page]],
    make_user: Callable[..., User],
    committer: User,
    cached_suggestion: CVEDerivationClusterProposal,
    make_maintainer_from_user: Callable[..., NixMaintainer],
    no_js: bool,
) -> None:
    """Test that maintainer edits by different users are not batched together"""
    if no_js:
        pytest.xfail("Not implemented")

    user1 = make_user(username="user1", is_staff=True, uid="666")
    user2 = make_user(username="user2", is_staff=True, uid="999")

    maintainer1 = make_maintainer_from_user(user1)
    maintainer2 = make_maintainer_from_user(user2)

    with logged_in_as(user1) as as_user1:
        as_user1.goto(live_server.url + reverse("webview:suggestions_view"))
        suggestion = as_user1.locator(f"#suggestion-{cached_suggestion.pk}")
        maintainers_list = suggestion.locator(
            f"#maintainers-list-{cached_suggestion.pk}"
        )
        name = maintainers_list.locator("input")
        name.fill(maintainer1.github)
        add = maintainers_list.get_by_role("button", name="Add")
        add.click()

    with logged_in_as(user2) as as_user2:
        as_user2.goto(live_server.url + reverse("webview:suggestions_view"))
        suggestion = as_user2.locator(f"#suggestion-{cached_suggestion.pk}")
        maintainers_list = suggestion.locator(
            f"#maintainers-list-{cached_suggestion.pk}"
        )
        name = maintainers_list.locator("input")
        name.fill(maintainer2.github)
        add = maintainers_list.get_by_role("button", name="Add")
        add.click()
        remove = maintainers_list.get_by_role("button", name="Remove")
        # There's already one maintainer in the `cached_suggestion`'s derivaiton 'by default
        expect(remove).to_have_count(3)

        as_user2.reload()

        activity_log = suggestion.locator(
            f"#suggestion-activity-log-{cached_suggestion.pk}"
        )
        expect(activity_log).to_be_visible()
        activity_log.click()
        added_maintainer1 = (
            activity_log.filter(has_text=user1.username)
            .filter(has_text="added maintainer")
            .filter(has_text=maintainer1.github)
        )
        expect(added_maintainer1).to_be_visible()
        added_maintainer2 = (
            activity_log.filter(has_text=user2.username)
            .filter(has_text="added maintainer")
            .filter(has_text=maintainer2.github)
        )
        expect(added_maintainer2).to_be_visible()
