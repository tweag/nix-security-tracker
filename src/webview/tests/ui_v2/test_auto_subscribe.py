from django.contrib.auth.models import User
from playwright.sync_api import Page, expect
from pytest_django.live_server_helper import LiveServer

from .routes import USER_SETTINGS

AUTO_SUBSCRIBE_LABEL = "Auto-subscribe to maintained packages"


def test_auto_subscribe_toggle_persists(
    live_server: LiveServer,
    as_staff: Page,
    staff: User,
) -> None:
    """Toggling auto-subscribe in the new UI persists across reloads."""
    as_staff.goto(live_server.url + USER_SETTINGS)

    checkbox = as_staff.get_by_label(AUTO_SUBSCRIBE_LABEL)
    expect(checkbox).to_be_checked()

    # The checkbox is a controlled component: clicking fires the PUT mutation, and the
    # rendered state only flips once the cache-invalidation refetch resolves. So click
    # and let the retrying assertion wait for the round-trip to settle (this also proves
    # the mutation, including CSRF, succeeded).
    checkbox.click()
    expect(checkbox).not_to_be_checked()

    # Reload to prove the new state was persisted server-side (refetched from the API).
    as_staff.reload()
    checkbox = as_staff.get_by_label(AUTO_SUBSCRIBE_LABEL)
    expect(checkbox).not_to_be_checked()

    # Re-enable and confirm that persists too.
    checkbox.click()
    expect(checkbox).to_be_checked()
    as_staff.reload()
    checkbox = as_staff.get_by_label(AUTO_SUBSCRIBE_LABEL)
    expect(checkbox).to_be_checked()
