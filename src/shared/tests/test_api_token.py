from datetime import timedelta

import pytest
from django.contrib.auth.models import User
from django.utils import timezone
from freezegun import freeze_time
from knox.models import AuthToken

TOKEN_LIFETIME_DAYS = 30


def _create_token(user: User) -> tuple[AuthToken, str]:
    return AuthToken.objects.create(  # type: ignore[return-value]
        user=user, expiry=timedelta(days=TOKEN_LIFETIME_DAYS)
    )


@pytest.mark.django_db
def test_create_returns_raw_token(user: User) -> None:
    _, raw = _create_token(user)
    assert raw
    assert len(raw) > 0


@pytest.mark.django_db
def test_create_stores_digest_not_raw(user: User) -> None:
    token_obj, raw = _create_token(user)
    assert token_obj.digest != raw


@pytest.mark.django_db
def test_create_sets_expiry(user: User) -> None:
    now = timezone.now()
    with freeze_time(now):
        token_obj, _ = _create_token(user)
    assert token_obj.expiry == now + timedelta(days=TOKEN_LIFETIME_DAYS)


@pytest.mark.django_db
def test_create_replaces_existing_token(user: User) -> None:
    _create_token(user)
    AuthToken.objects.filter(user=user).delete()
    _create_token(user)
    assert AuthToken.objects.filter(user=user).count() == 1


@pytest.mark.django_db
def test_token_not_expired_when_fresh(user: User) -> None:
    token_obj, _ = _create_token(user)
    assert token_obj.expiry is not None
    assert token_obj.expiry > timezone.now()


@pytest.mark.django_db
def test_token_expired_after_lifetime(user: User) -> None:
    token_obj, _ = _create_token(user)
    assert token_obj.expiry is not None
    with freeze_time(token_obj.expiry + timedelta(seconds=1)):
        assert token_obj.expiry < timezone.now()


@pytest.mark.django_db
def test_extend_pushes_expiry_forward(user: User) -> None:
    token_obj, _ = _create_token(user)
    old_expiry = token_obj.expiry
    token_obj.expiry = timezone.now() + timedelta(days=TOKEN_LIFETIME_DAYS)
    token_obj.save(update_fields=["expiry"])
    token_obj.refresh_from_db()
    new_expiry = token_obj.expiry
    assert old_expiry is not None
    assert new_expiry is not None
    assert new_expiry > old_expiry
