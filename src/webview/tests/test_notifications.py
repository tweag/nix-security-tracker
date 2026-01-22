from collections.abc import Callable

from allauth.socialaccount.models import SocialAccount
from django.contrib.auth.models import User
from django.test import Client, TestCase
from django.urls import reverse
from playwright.sync_api import Page, expect
from pytest_django.live_server_helper import LiveServer

from shared.listeners.notify_users import create_package_subscription_notifications
from shared.models.linkage import CVEDerivationClusterProposal, ProvenanceFlags
from shared.models.nix_evaluation import (
    NixDerivation,
    NixMaintainer,
)
from webview.models import Notification

from ..notifications.views import NotificationCenterView


def test_mark_notification_read_unread(
    live_server: LiveServer,
    staff: User,
    as_staff: Page,
    make_suggestion: Callable[..., CVEDerivationClusterProposal],
    make_maintainer_from_user: Callable[..., NixMaintainer],
    make_drv: Callable[..., NixDerivation],
) -> None:
    """
    Check that marking a notification read and unread has the desired effect
    """
    maintainer = make_maintainer_from_user(staff)
    drv = make_drv(maintainer=maintainer)
    suggestion = make_suggestion(drvs={drv: ProvenanceFlags.PACKAGE_NAME_MATCH})
    create_package_subscription_notifications(suggestion)

    as_staff.goto(live_server.url + reverse("webview:suggestions_view"))
    badge = as_staff.locator("#notifications-badge")
    expect(badge).to_have_text("1")

    badge.click()

    db_notification = Notification.objects.first()
    assert db_notification
    notification = as_staff.locator(f"#notification-{db_notification.pk}")
    expect(notification).to_be_visible()

    mark_read = notification.get_by_role("button", name="Mark read")
    mark_read.click()
    expect(badge).to_have_text("0")
    notification = as_staff.locator(f"#notification-{db_notification.pk}")
    expect(notification).to_be_visible()
    mark_unread = notification.get_by_role("button", name="Mark unread")
    mark_unread.click()
    expect(badge).to_have_text("1")


def test_notifications_bulk_operations(
    live_server: LiveServer,
    staff: User,
    as_staff: Page,
    make_suggestion: Callable[..., CVEDerivationClusterProposal],
    make_maintainer_from_user: Callable[..., NixMaintainer],
    make_drv: Callable[..., NixDerivation],
) -> None:
    """
    Check that bulk operations on notifications work as expected
    """
    num_notifications = 3
    maintainer = make_maintainer_from_user(staff)
    drv = make_drv(maintainer=maintainer)
    suggestion = make_suggestion(drvs={drv: ProvenanceFlags.PACKAGE_NAME_MATCH})
    for i in range(num_notifications):
        create_package_subscription_notifications(suggestion)

    as_staff.goto(live_server.url + reverse("webview:suggestions_view"))
    badge = as_staff.locator("#notifications-badge")
    expect(badge).to_have_text(str(num_notifications))
    badge.click()

    db_notifications = Notification.objects.all()
    for db_notification in db_notifications:
        notification = as_staff.locator(f"#notification-{db_notification.pk}")
        expect(notification).to_be_visible()
        mark_read = notification.get_by_role("button", name="Mark read")
        expect(mark_read).to_be_visible()

    all_read = as_staff.get_by_role("button", name="Mark all as read")
    all_read.click()

    expect(badge).to_have_text("0")

    for db_notification in db_notifications:
        notification = as_staff.locator(f"#notification-{db_notification.pk}")
        expect(notification).to_be_visible()
        mark_unread = notification.get_by_role("button", name="Mark unread")
        expect(mark_unread).to_be_visible()

    remove_read = as_staff.get_by_role("button", name="Remove read notification")
    remove_read.click()

    expect(
        as_staff.get_by_text("You don't have any notifications yet.")
    ).to_be_visible()

    assert Notification.objects.count() == 0


def test_paginated_notifications(
    live_server: LiveServer,
    staff: User,
    as_staff: Page,
    make_suggestion: Callable[..., CVEDerivationClusterProposal],
    make_maintainer_from_user: Callable[..., NixMaintainer],
    make_drv: Callable[..., NixDerivation],
) -> None:
    """
    Check that browsing multiple pages of notifications works as expected
    """
    page_size = NotificationCenterView.paginate_by
    num_notifications = page_size + 1
    maintainer = make_maintainer_from_user(staff)
    drv = make_drv(maintainer=maintainer)
    suggestion = make_suggestion(drvs={drv: ProvenanceFlags.PACKAGE_NAME_MATCH})
    for i in range(num_notifications):
        create_package_subscription_notifications(suggestion)

    as_staff.goto(live_server.url + reverse("webview:suggestions_view"))
    badge = as_staff.locator("#notifications-badge")
    expect(badge).to_have_text(str(num_notifications))
    badge.click()

    db_notifications = Notification.objects.all()
    for i, db_notification in enumerate(reversed(db_notifications), start=1):
        notification = as_staff.locator(f"#notification-{db_notification.pk}")
        if i > page_size:
            expect(notification).to_have_count(0)
        else:
            expect(notification).to_be_visible()
            mark_read = notification.get_by_role("button", name="Mark read")
            expect(mark_read).to_be_visible()

    pagination = as_staff.locator("#pagination")
    page_2 = pagination.get_by_role("link", name="2")
    page_2.click()

    for i, db_notification in enumerate(reversed(db_notifications), start=1):
        notification = as_staff.locator(f"#notification-{db_notification.pk}")
        if i <= page_size:
            expect(notification).to_have_count(0)
        else:
            expect(notification).to_be_visible()
            mark_read = notification.get_by_role("button", name="Mark read")
            expect(mark_read).to_be_visible()

    mark_read = as_staff.get_by_text("Mark read")
    mark_read.click()

    page_1 = pagination.get_by_role("link", name="1")
    page_1.click()

    expect(mark_read).to_have_count(num_notifications - 1)
    expect(badge).to_have_text(str(num_notifications - 1))


class NotificationUserStoriesTests(TestCase):
    def setUp(self) -> None:
        # Create test user with social account
        self.user = User.objects.create_user(username="testuser", password="testpass")
        self.user.is_staff = True
        self.user.save()

        SocialAccount.objects.get_or_create(
            user=self.user,
            provider="github",
            uid="123456",
            extra_data={"login": "testuser"},
        )

        self.client = Client()
        self.client.login(username="testuser", password="testpass")

        # Create another user to test security boundaries
        self.other_user = User.objects.create_user(
            username="otheruser", password="testpass"
        )

    def test_user_works_without_javascript(self) -> None:
        """
        User story: User with JavaScript disabled can still manage notifications

        1. User (no JS) receives notifications
        2. User navigates to notification center
        3. User marks notification as read - gets redirected to same page
        4. User uses bulk operations - gets redirected appropriately
        5. User stays on current page throughout operations
        """
        # Step 1: User receives notifications
        notification1 = Notification.objects.create_for_user(
            user=self.user, title="First Notification", message="First message"
        )
        notification2 = Notification.objects.create_for_user(
            user=self.user, title="Second Notification", message="Second message"
        )

        # Step 2: User navigates to notification center
        response = self.client.get(reverse("webview:notifications:center"))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "First Notification")
        self.assertContains(response, "Second Notification")

        # Step 3: User marks notification as read without HTMX - gets redirected
        response = self.client.post(
            reverse("webview:notifications:toggle_read", args=[notification1.id]),
            data={"page": "1"},  # Simulate page preservation
        )
        self.assertEqual(response.status_code, 302)
        self.assertIn("notifications", response.url)
        self.assertIn("page=1", response.url)

        # Follow the redirect and verify state
        response = self.client.get(response.url)
        self.assertEqual(response.status_code, 200)

        # Verify notification was marked as read
        notification1.refresh_from_db()
        self.assertTrue(notification1.is_read)

        # Step 4: User uses "mark all as read" - gets redirected appropriately
        response = self.client.post(
            reverse("webview:notifications:mark_all_read"), data={"page": "1"}
        )
        self.assertEqual(response.status_code, 302)
        self.assertIn("notifications", response.url)

        # Follow redirect and verify all are read
        response = self.client.get(response.url)
        self.assertEqual(response.status_code, 200)

        notification2.refresh_from_db()
        self.assertTrue(notification2.is_read)

        # Step 5: User removes all read notifications
        response = self.client.post(reverse("webview:notifications:remove_all_read"))
        self.assertEqual(response.status_code, 302)
        self.assertIn("notifications", response.url)

        # Follow redirect - should show empty state
        response = self.client.get(response.url)
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "You don't have any notifications yet.")

    def test_user_security_boundaries_enforced(self) -> None:
        """
        User story: System properly enforces security boundaries

        1. User A receives notifications
        2. User B cannot access User A's notifications
        3. User B cannot modify User A's notifications
        4. Anonymous users are redirected to login
        """
        # Step 1: User A receives notifications
        notification = Notification.objects.create_for_user(
            user=self.user,
            title="Private Notification",
            message="This should only be visible to the owner",
        )

        # Step 2: User B cannot access User A's notifications
        other_client = Client()
        other_client.login(username="otheruser", password="testpass")

        # Other user's notification center should not show User A's notifications
        response = other_client.get(reverse("webview:notifications:center"))
        self.assertEqual(response.status_code, 200)
        self.assertNotContains(response, "Private Notification")
        self.assertContains(response, "You don't have any notifications yet.")

        # Step 3: User B cannot modify User A's notifications
        response = other_client.post(
            reverse("webview:notifications:toggle_read", args=[notification.id])
        )
        self.assertEqual(response.status_code, 404)  # Should not find the notification

        # Step 4: Anonymous users are redirected to login
        anonymous_client = Client()

        response = anonymous_client.get(reverse("webview:notifications:center"))
        self.assertEqual(response.status_code, 302)  # Redirect to login
        self.assertIn("login", response.url)

        response = anonymous_client.post(
            reverse("webview:notifications:toggle_read", args=[notification.id])
        )
        self.assertEqual(response.status_code, 302)  # Redirect to login
        self.assertIn("login", response.url)

    def test_user_sees_helpful_empty_state(self) -> None:
        """
        User story: User sees appropriate messages for various empty states
        """
        # Step 1: New user has no notifications
        response = self.client.get(reverse("webview:notifications:center"))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "You don't have any notifications yet.")

        # Should not show bulk operation buttons when empty
        self.assertNotContains(response, "Mark all as read")
        self.assertNotContains(response, "Remove read notifications")

        # Step 2: User gets notifications, then removes them all
        notification = Notification.objects.create_for_user(
            user=self.user,
            title="Temporary Notification",
            message="This will be removed",
        )

        # Mark as read and remove
        self.client.post(
            reverse("webview:notifications:toggle_read", args=[notification.id])
        )
        self.client.post(reverse("webview:notifications:remove_all_read"))

        # Step 3: Should see empty state again
        response = self.client.get(reverse("webview:notifications:center"))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "You don't have any notifications yet.")

        # Verify notification was actually deleted
        self.assertFalse(Notification.objects.filter(user=self.user).exists())

        # Badge should show no unread notifications
        response = self.client.get(reverse("webview:suggestions_view"))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.context["user"].profile.unread_notifications_count, 0)
