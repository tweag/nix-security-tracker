from datetime import timedelta

import pytest
from django.contrib.auth.models import User
from django.urls import reverse
from knox.models import AuthToken
from rest_framework.test import APIClient

pytest_plugins = ["shared.tests.conftest"]

TOKEN_LIFETIME_DAYS = 30


def _create_token(user: User) -> tuple[AuthToken, str]:
    return AuthToken.objects.create(  # type: ignore[return-value]
        user=user, expiry=timedelta(days=TOKEN_LIFETIME_DAYS)
    )


@pytest.mark.django_db
def test_token_page_redirects_anonymous(client: APIClient) -> None:
    response = client.get(reverse("webview:tokens:manage"))
    assert response.status_code == 302
    # LoginRequiredMixin redirects to the allauth login URL
    login_url = reverse("account_login")
    assert response.headers["Location"].startswith(login_url)


@pytest.mark.django_db
def test_token_page_no_token(user: User, client: APIClient) -> None:
    client.force_login(user)
    response = client.get(reverse("webview:tokens:manage"))
    assert response.status_code == 200
    assert b"Generate API token" in response.content


@pytest.mark.django_db
def test_generate_shows_token_value_once(user: User, client: APIClient) -> None:
    client.force_login(user)
    response = client.post(reverse("webview:tokens:manage"), {"action": "generate"})
    assert response.status_code == 200
    content = response.content.decode()
    assert "Copy this value now" in content
    assert AuthToken.objects.filter(user=user).exists()


@pytest.mark.django_db
def test_second_get_hides_token_value(user: User, client: APIClient) -> None:
    client.force_login(user)
    client.post(reverse("webview:tokens:manage"), {"action": "generate"})
    # Follow-up GET must not expose the raw value
    response = client.get(reverse("webview:tokens:manage"))
    assert response.status_code == 200
    assert b"Active token" in response.content


@pytest.mark.django_db
def test_revoke_deletes_token(user: User, client: APIClient) -> None:
    _create_token(user)
    client.force_login(user)
    response = client.post(
        reverse("webview:tokens:manage"), {"action": "revoke"}, follow=True
    )
    assert response.status_code == 200
    assert not AuthToken.objects.filter(user=user).exists()
    assert b"Generate API token" in response.content


@pytest.mark.django_db
def test_extend_pushes_expiry(user: User, client: APIClient) -> None:
    token_obj, _ = _create_token(user)
    old_expiry = token_obj.expiry
    client.force_login(user)
    client.post(reverse("webview:tokens:manage"), {"action": "extend"}, follow=True)
    token_obj.refresh_from_db()
    assert old_expiry is not None
    assert token_obj.expiry is not None
    assert token_obj.expiry > old_expiry


@pytest.mark.django_db
def test_generate_replaces_existing_token(user: User, client: APIClient) -> None:
    old_obj, _ = _create_token(user)
    client.force_login(user)
    client.post(reverse("webview:tokens:manage"), {"action": "generate"})
    assert AuthToken.objects.filter(user=user).count() == 1
    new_obj = AuthToken.objects.get(user=user)
    assert new_obj.pk != old_obj.pk
