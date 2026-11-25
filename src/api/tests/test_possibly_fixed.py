from collections.abc import Callable

import pytest
from django.contrib.auth.models import User
from django.test.utils import CaptureQueriesContext
from rest_framework.reverse import reverse
from rest_framework.test import APIClient

from shared.derived_state import possibly_fixed_queue
from shared.models.matching import Exposure, Verdict
from shared.models.nix_evaluation import NixpkgsBranch
from shared.tests.test_exposure import World, record, world  # noqa: F401

V = Verdict.Kind
SHA = "0123456789abcdef0123456789abcdef01234567"


def list_url() -> str:
    return reverse("possibly-fixed-list")


def action_url(pk: int, action: str) -> str:
    return reverse(f"possibly-fixed-{action.replace('_', '-')}", kwargs={"pk": pk})


@pytest.fixture
def fixed(world: World) -> World:  # noqa: F811
    world.match()
    world.package("1.5")
    world.reconcile()
    world.apply(world.package("2.0"))
    return world


def row_id(world: World) -> int:  # noqa: F811
    return Exposure.objects.get(suggestion=world.suggestion, attrpath="foo").pk


def test_list_shape(anonymous_client: APIClient, fixed: World) -> None:
    response = anonymous_client.get(list_url())
    assert response.status_code == 200
    assert response.data["count"] == 1
    (row,) = response.json()["results"]
    first, second = fixed.evaluations
    assert row == {
        "id": row_id(fixed),
        "suggestion_id": fixed.suggestion.pk,
        "cve_id": "CVE-2025-0001",
        "attrpath": "foo",
        "branch": "master",
        "old_version": "1.5",
        "new_version": "2.0",
        "last_affected_commit": first.commit_sha1,
        "last_affected_at": row["last_affected_at"],
        "fixed_commit": second.commit_sha1,
        "fixed_at": row["fixed_at"],
        "compare_url": f"https://github.com/NixOS/nixpkgs/compare/{first.commit_sha1}...{second.commit_sha1}",
    }


def test_branch_filter(
    anonymous_client: APIClient,
    fixed: World,
    make_branch: Callable[..., NixpkgsBranch],
) -> None:
    make_branch("release-26.05")
    assert (
        anonymous_client.get(list_url(), {"branch": "release-26.05"}).data["count"] == 0
    )
    response = anonymous_client.get(list_url(), {"branch": ["release-26.05", "master"]})
    assert response.data["count"] == 1


def test_pagination(
    anonymous_client: APIClient,
    world: World,  # noqa: F811
    django_assert_max_num_queries: Callable[..., CaptureQueriesContext],
) -> None:
    for i in range(12):
        world.match(f"foo{i}")
    for i in range(12):
        world.package("1.5", attrpath=f"foo{i}")
    world.reconcile()
    for i in range(12):
        world.apply(world.package("2.0", attrpath=f"foo{i}"))
    assert len(possibly_fixed_queue()) == 12
    # The queue query, then the facts of its suggestions: constant in the row count.
    with django_assert_max_num_queries(12):
        first = anonymous_client.get(list_url()).json()
    assert (first["count"], len(first["results"])) == (12, 10)
    second = anonymous_client.get(list_url(), {"page": 2}).json()
    assert len(second["results"]) == 2
    assert not {r["id"] for r in first["results"]} & {
        r["id"] for r in second["results"]
    }


@pytest.mark.parametrize("action", ["confirm_fixed", "still_affected"])
def test_action_permissions(
    action: str,
    anonymous_client: APIClient,
    client: APIClient,
    fixed: World,
) -> None:
    assert anonymous_client.post(action_url(row_id(fixed), action)).status_code == 401
    assert client.post(action_url(row_id(fixed), action)).status_code == 403
    assert not Verdict.objects.exists()


def test_confirm_fixed(
    committer_client: APIClient, committer: User, fixed: World
) -> None:
    response = committer_client.post(
        action_url(row_id(fixed), "confirm_fixed"), {"fix_commit": SHA}, format="json"
    )
    assert response.status_code == 204
    v = Verdict.objects.get()
    assert (v.attrpath, v.branch_id, v.verdict, v.fix_commit, v.author) == (
        "foo",
        "master",
        V.FIXED,
        SHA,
        committer,
    )
    assert committer_client.get(list_url()).data["count"] == 0


def test_still_affected_then_fixed_again(staff_client: APIClient, fixed: World) -> None:
    response = staff_client.post(
        action_url(row_id(fixed), "still_affected"), {}, format="json"
    )
    assert response.status_code == 204
    assert Verdict.objects.get().verdict == V.AFFECTED
    assert staff_client.get(list_url()).data["count"] == 0
    # Affected again, then unaffected again: the row comes back.
    fixed.apply(fixed.package("1.9"))
    assert staff_client.get(list_url()).data["count"] == 0
    fixed.apply(fixed.package("2.1"))
    (row,) = staff_client.get(list_url()).json()["results"]
    assert (row["old_version"], row["new_version"]) == ("1.9", "2.1")


def test_action_validation(committer_client: APIClient, fixed: World) -> None:
    response = committer_client.post(
        action_url(row_id(fixed), "confirm_fixed"), {"fix_commit": "abc"}, format="json"
    )
    assert response.status_code == 400
    assert "fix_commit" in response.data
    response = committer_client.post(action_url(row_id(fixed) + 1, "confirm_fixed"))
    assert response.status_code == 404
    assert not Verdict.objects.exists()


def test_branches(
    anonymous_client: APIClient,
    fixed: World,
    make_branch: Callable[..., NixpkgsBranch],
) -> None:
    make_branch("staging")
    response = anonymous_client.get(reverse("possibly-fixed-branches"))
    assert response.status_code == 200
    assert response.json() == [{"name": "master", "count": 1}]


@pytest.mark.parametrize("action", ["confirm_fixed", "still_affected"])
def test_action_refuses_a_row_not_in_the_queue(
    action: str,
    committer_client: APIClient,
    world: World,  # noqa: F811
) -> None:
    """An exposure that is affected now is no queue row: the answer is a conflict."""
    world.match()
    world.package("1.5")
    world.reconcile()
    response = committer_client.post(
        action_url(row_id(world), action), {}, format="json"
    )
    assert response.status_code == 409
    assert not Verdict.objects.exists()


def test_action_refuses_an_untracked_branch(
    committer_client: APIClient,
    fixed: World,
    make_branch: Callable[..., NixpkgsBranch],
) -> None:
    staging = make_branch("staging")
    Exposure.objects.filter(pk=row_id(fixed)).update(branch=staging)
    response = committer_client.post(
        action_url(row_id(fixed), "still_affected"), {}, format="json"
    )
    assert response.status_code == 400
    assert "branch" in response.data
    assert not Verdict.objects.exists()
    # Nor is it listed.
    assert committer_client.get(list_url()).data["count"] == 0


def test_second_answer_to_a_row_is_a_conflict(
    committer_client: APIClient, staff_client: APIClient, fixed: World
) -> None:
    first = staff_client.post(
        action_url(row_id(fixed), "still_affected"), {}, format="json"
    )
    assert first.status_code == 204
    second = committer_client.post(
        action_url(row_id(fixed), "confirm_fixed"), {}, format="json"
    )
    assert second.status_code == 409
    assert "detail" in second.data
    assert Verdict.objects.get().verdict == V.AFFECTED
