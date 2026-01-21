import os
from collections.abc import Generator
from typing import Any
from unittest.mock import patch

import pytest
from allauth.account.utils import get_login_redirect_url
from allauth.socialaccount.providers.oauth2.views import OAuth2LoginView
from django.contrib.auth import login
from django.contrib.auth.models import User
from django.http import HttpRequest, HttpResponse
from django.shortcuts import redirect
from django.test import Client

pytest_plugins = ["shared.tests.conftest"]

# XXX(@fricklerhandwerk): Allows mixing async `live_server` with sync `db` fixtures.
# There seems to be no better way to make that work.
os.environ["DJANGO_ALLOW_ASYNC_UNSAFE"] = "true"


@pytest.fixture
def mock_oauth_login(
    db: None,
    user: User,
) -> Generator[None]:
    def mock_dispatch(
        self: OAuth2LoginView, request: HttpRequest, *args: Any, **kwargs: Any
    ) -> HttpResponse:
        login(
            request,
            user,
            backend="allauth.account.auth_backends.AuthenticationBackend",
        )
        return redirect(get_login_redirect_url(request))

    with patch.object(OAuth2LoginView, "dispatch", mock_dispatch):
        yield


@pytest.fixture
def authenticated_client(
    client: Client,
    user: User,
) -> Client:
    # https://docs.djangoproject.com/en/6.0/topics/testing/tools/#django.test.Client.force_login
    client.force_login(
        user,
        backend="allauth.account.auth_backends.AuthenticationBackend",
    )
    return client
