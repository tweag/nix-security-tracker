from django.urls import reverse
from playwright.sync_api import Page, expect
from pytest_django.live_server_helper import LiveServer


def test_redirect_after_login(
    live_server: LiveServer,
    mock_oauth_login: None,
    page: Page,
) -> None:
    entry_point = reverse("webview:suggestions_view")
    page.goto(f"{live_server.url}{entry_point}")
    login_link = page.get_by_role("link", name="Login with GitHub")
    expect(login_link).to_be_visible()
    login_link.click()
    # We skip the confirmation form in the mock, so the response will be the final redirect
    expect(page).to_have_url(f"{live_server.url}{entry_point}")
