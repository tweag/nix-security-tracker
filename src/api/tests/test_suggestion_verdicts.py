from collections.abc import Callable
from typing import Any

import pytest
from django.contrib.auth.models import User
from rest_framework.reverse import reverse
from rest_framework.test import APIClient

from shared.cache_suggestions import cache_new_suggestions
from shared.derived_state import flush_derived_states
from shared.models.linkage import CVEDerivationClusterProposal
from shared.models.matching import (
    Exposure,
    Match,
    SuggestionDerivedState,
    TrackerEvent,
    Verdict,
)
from shared.models.nix_evaluation import NixpkgsBranch

V = Verdict.Kind
SHA = "0123456789abcdef0123456789abcdef01234567"


def url(pk: int) -> str:
    return reverse("cvederivationclusterproposal-verdicts", kwargs={"pk": pk})


@pytest.fixture
def candidates(
    suggestion: CVEDerivationClusterProposal,
    branch: NixpkgsBranch,
    make_match: Callable[..., Match],
    make_exposure: Callable[..., Exposure],
) -> CVEDerivationClusterProposal:
    """`foo` matched, `bar` only exposed, on the tracked branch `master`."""
    make_match("foo")
    make_exposure("bar")
    return suggestion


def body(**fields: Any) -> dict[str, Any]:
    return {
        "package_attributes": ["foo", "bar"],
        "branch": None,
        "verdict": "irrelevant",
    } | fields


def test_anonymous(
    anonymous_client: APIClient, candidates: CVEDerivationClusterProposal
) -> None:
    assert (
        anonymous_client.patch(url(candidates.pk), body(), format="json").status_code
        == 401
    )


def test_plain_user(
    client: APIClient, candidates: CVEDerivationClusterProposal
) -> None:
    assert client.patch(url(candidates.pk), body(), format="json").status_code == 403
    assert not Verdict.objects.exists()


@pytest.mark.parametrize("who", ["committer", "staff"])
def test_set_and_remove(
    who: str,
    request: pytest.FixtureRequest,
    make_client: Callable[..., APIClient],
    candidates: CVEDerivationClusterProposal,
) -> None:
    user: User = request.getfixturevalue(who)
    c = make_client(user)
    response = c.patch(url(candidates.pk), body(), format="json")
    assert response.status_code == 204
    assert set(
        Verdict.objects.values_list("attrpath", "branch", "verdict", "author")
    ) == {
        ("foo", None, V.IRRELEVANT, user.pk),
        ("bar", None, V.IRRELEVANT, user.pk),
    }
    events = TrackerEvent.objects.filter(kind=TrackerEvent.Kind.VERDICT_SET)
    assert {e.actor_id for e in events} == {user.pk}
    # One request, one batch.
    assert len({e.batch for e in events}) == 1

    response = c.patch(
        url(candidates.pk),
        body(
            package_attributes=["foo"], branch="master", verdict="fixed", fix_commit=SHA
        ),
        format="json",
    )
    assert response.status_code == 204
    assert Verdict.objects.get(branch="master").fix_commit == SHA

    response = c.patch(url(candidates.pk), body(verdict=None), format="json")
    assert response.status_code == 204
    assert list(Verdict.objects.values_list("attrpath", "branch")) == [
        ("foo", "master")
    ]


def test_unknown_attribute_changes_nothing(
    committer_client: APIClient, candidates: CVEDerivationClusterProposal
) -> None:
    response = committer_client.patch(
        url(candidates.pk), body(package_attributes=["foo", "nope"]), format="json"
    )
    assert response.status_code == 400
    assert "nope" in str(response.data["package_attributes"])
    assert not Verdict.objects.exists()


def test_untracked_branch(
    committer_client: APIClient,
    candidates: CVEDerivationClusterProposal,
    make_branch: Callable[..., NixpkgsBranch],
) -> None:
    make_branch("staging")
    response = committer_client.patch(
        url(candidates.pk), body(branch="staging"), format="json"
    )
    assert response.status_code == 400
    assert "branch" in response.data


@pytest.mark.parametrize(
    "fields,error",
    [
        ({"verdict": "fixed", "fix_commit": "ABC"}, "fix_commit"),
        ({"verdict": "fixed", "fix_commit": SHA.upper()}, "fix_commit"),
        ({"verdict": "affected", "fix_commit": SHA}, "fix_commit"),
        ({"verdict": "maybe"}, "verdict"),
        ({"package_attributes": []}, "package_attributes"),
        ({"verdict": None, "comment": "why"}, "comment"),
    ],
)
def test_validation(
    committer_client: APIClient,
    candidates: CVEDerivationClusterProposal,
    fields: dict[str, Any],
    error: str,
) -> None:
    response = committer_client.patch(url(candidates.pk), body(**fields), format="json")
    assert response.status_code == 400
    assert error in response.data


def test_remove_missing(
    committer_client: APIClient, candidates: CVEDerivationClusterProposal
) -> None:
    response = committer_client.patch(
        url(candidates.pk), body(verdict=None), format="json"
    )
    assert response.status_code == 400
    assert "package_attributes" in response.data


def test_not_found(
    committer_client: APIClient, candidates: CVEDerivationClusterProposal
) -> None:
    response = committer_client.patch(url(candidates.pk + 1), body(), format="json")
    assert response.status_code == 404


def test_bulk(
    committer_client: APIClient,
    client: APIClient,
    make_suggestion: Callable[..., CVEDerivationClusterProposal],
    make_container: Callable[..., Any],
    make_match: Callable[..., Match],
) -> None:
    suggestions = []
    for i in range(3):
        s = make_suggestion(container=make_container(cve_id=f"CVE-2025-300{i}"))
        cache_new_suggestions(s)
        suggestions.append(s)
    for s in suggestions[:2]:
        make_match("foo", suggestion=s)
    bulk = reverse("cvederivationclusterproposal-bulk-verdicts")
    data = body(package_attributes=["foo"])

    assert (
        client.patch(bulk + "?status=pending", data, format="json").status_code == 403
    )
    # Unfiltered selections are refused.
    assert committer_client.patch(bulk, data, format="json").status_code == 400
    # The third suggestion has no `foo`: nothing is written.
    response = committer_client.patch(bulk + "?status=pending", data, format="json")
    assert response.status_code == 400
    assert set(response.json()["reasons"]) == {str(suggestions[2].pk)}
    assert not Verdict.objects.exists()

    SuggestionDerivedState.objects.update(stale=True)
    flush_derived_states()
    # Selecting by derived state leaves out the suggestion without candidates.
    response = committer_client.patch(
        bulk + "?derived_state=needs_triage", data, format="json"
    )
    assert response.status_code == 200
    assert response.data["affected"] == 2
    assert set(Verdict.objects.values_list("suggestion", flat=True)) == {
        s.pk for s in suggestions[:2]
    }
