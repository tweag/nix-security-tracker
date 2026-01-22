import re
from collections.abc import Callable
from contextlib import AbstractContextManager

import pytest
from django.contrib.auth.models import User
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

    for db_notification in db_notifications:
        notification = as_staff.locator(f"#notification-{db_notification.pk}")
        expect(notification).to_have_count(0)

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


@pytest.mark.parametrize(
    "user_fixture,has_access",
    [
        ("committer", False),
        ("staff", True),
    ],
)
def test_notification_access_control(
    has_access: bool,
    request: pytest.FixtureRequest,
    make_maintainer_from_user: Callable[..., NixMaintainer],
    make_drv: Callable[..., NixDerivation],
    make_suggestion: Callable[..., CVEDerivationClusterProposal],
    staff: User,
    user_fixture: str,
) -> None:
    """
    Low-level test of access control on notifications

    This only tests methods in use at the time of writing.
    """
    maintainer = make_maintainer_from_user(staff)
    drv = make_drv(maintainer=maintainer)
    suggestion = make_suggestion(drvs={drv: ProvenanceFlags.PACKAGE_NAME_MATCH})
    create_package_subscription_notifications(suggestion)
    notification = Notification.objects.first()
    assert notification

    # https://docs.pytest.org/en/latest/reference/reference.html?highlight=getfixturevalue#pytest.FixtureRequest.getfixturevalue
    user = request.getfixturevalue(user_fixture)

    if has_access:
        assert Notification.objects.toggle_read_for_user(user, notification.id) == 0
        assert Notification.objects.toggle_read_for_user(user, notification.id) == 1
        assert Notification.objects.mark_all_read_for_user(user) == 1
        assert Notification.objects.clear_all_for_user(user) == 1
    else:
        assert Notification.objects.toggle_read_for_user(user, notification.id) is None
        assert Notification.objects.mark_all_read_for_user(user) == 0
        assert Notification.objects.clear_all_for_user(user) == 0


def test_notifications_per_user(
    live_server: LiveServer,
    page: Page,
    make_suggestion: Callable[..., CVEDerivationClusterProposal],
    make_maintainer_from_user: Callable[..., NixMaintainer],
    make_drv: Callable[..., NixDerivation],
    logged_in_as: Callable[..., AbstractContextManager[Page]],
    staff: User,
    committer: User,
) -> None:
    """
    Check that users only get their own notifications
    """

    staff_maintainer = make_maintainer_from_user(staff)
    staff_drv = make_drv(maintainer=staff_maintainer)
    staff_suggestion = make_suggestion(
        drvs={staff_drv: ProvenanceFlags.PACKAGE_NAME_MATCH}
    )
    create_package_subscription_notifications(staff_suggestion)

    # Anonymous users are redirected to login
    page.goto(live_server.url + reverse("webview:notifications:center"))
    expect(page).to_have_url(re.compile(re.escape(reverse("account_login"))))

    with logged_in_as(staff) as as_staff:
        as_staff.goto(live_server.url + reverse("webview:notifications:center"))
        badge = as_staff.locator("#notifications-badge")
        expect(badge).to_have_text("1")

    with logged_in_as(committer) as as_committer:
        as_committer.goto(live_server.url + reverse("webview:notifications:center"))
        badge = as_committer.locator("#notifications-badge")
        expect(badge).to_have_text("0")


def test_notifications_empty_state(
    live_server: LiveServer,
    staff: User,
    as_staff: Page,
    make_suggestion: Callable[..., CVEDerivationClusterProposal],
    make_maintainer_from_user: Callable[..., NixMaintainer],
    make_drv: Callable[..., NixDerivation],
) -> None:
    """
    Check that appropriate message is displayed for the empty state
    """
    as_staff.goto(live_server.url + reverse("webview:notifications:center"))
    empty_message = "You don't have any notifications yet."
    expect(as_staff.get_by_text(empty_message)).to_be_visible()

    badge = as_staff.locator("#notifications-badge")
    expect(badge).to_have_text("0")

    mark_all_read = as_staff.get_by_text("Mark all as read")
    expect(mark_all_read).to_have_count(0)
    remove_read = as_staff.get_by_text("Remove read notifications")
    expect(remove_read).to_have_count(0)

    maintainer = make_maintainer_from_user(staff)
    drv = make_drv(maintainer=maintainer)
    suggestion = make_suggestion(drvs={drv: ProvenanceFlags.PACKAGE_NAME_MATCH})
    create_package_subscription_notifications(suggestion)

    as_staff.goto(live_server.url + reverse("webview:notifications:center"))
    mark_all_read.click()
    remove_read.click()

    expect(mark_all_read).to_have_count(0)
    expect(remove_read).to_have_count(0)

    expect(as_staff.get_by_text(empty_message)).to_be_visible()

    badge = as_staff.locator("#notifications-badge")
    expect(badge).to_have_text("0")

    assert Notification.objects.count() == 0
