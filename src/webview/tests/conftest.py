import os
from collections.abc import Callable, Generator
from typing import Any
from unittest.mock import _patch, patch

import pytest
from allauth.account.utils import get_login_redirect_url
from allauth.socialaccount.providers.github.provider import GitHubProvider
from allauth.socialaccount.providers.oauth2.views import OAuth2LoginView
from django.contrib.auth import login
from django.contrib.auth.models import User
from django.http import HttpRequest, HttpResponse
from django.shortcuts import redirect
from django.test import Client
from django.urls import reverse
from playwright.sync_api import Page
from pytest_django.live_server_helper import LiveServer

pytest_plugins = ["shared.tests.conftest"]

# XXX(@fricklerhandwerk): Allows mixing async `live_server` with sync `db` fixtures.
# There seems to be no better way to make that work.
os.environ["DJANGO_ALLOW_ASYNC_UNSAFE"] = "true"


@pytest.fixture
def mock_oauth_login(
    db: None,
) -> Callable[[User], _patch]:
    def wrapped(user: User) -> _patch:
        def mock_dispatch(
            self: OAuth2LoginView, request: HttpRequest, *args: Any, **kwargs: Any
        ) -> HttpResponse:
            login(
                request,
                user,
                backend="allauth.account.auth_backends.AuthenticationBackend",
            )
            return redirect(get_login_redirect_url(request))

        return patch.object(OAuth2LoginView, "dispatch", mock_dispatch)

    return wrapped


@pytest.fixture
def as_staff(
    live_server: LiveServer,
    mock_oauth_login: Callable[[User], _patch],
    page: Page,
    staff: User,
) -> Generator[Page]:
    with mock_oauth_login(staff):
        # XXX(@fricklerhandwerk): Login URLs are "{provider.id}_login":
        # https://github.com/pennersr/django-allauth/blob/main/allauth/socialaccount/providers/oauth/urls.py#L11
        page.goto(live_server.url + reverse(f"{GitHubProvider.id}_login"))
        yield page


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
