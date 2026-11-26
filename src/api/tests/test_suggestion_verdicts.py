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


def test_query_count_does_not_grow_with_attributes(
    committer_client: APIClient,
    suggestion: CVEDerivationClusterProposal,
    make_match: Callable[..., Match],
    django_assert_num_queries: Callable[..., Any],
) -> None:
    from django.db import connection
    from django.test.utils import CaptureQueriesContext

    def patch(attrs: list[str], verdict: str | None) -> int:
        with CaptureQueriesContext(connection) as ctx:
            response = committer_client.patch(
                url(suggestion.pk),
                {"package_attributes": attrs, "branch": None, "verdict": verdict},
                format="json",
            )
        assert response.status_code == 204, response.data
        return len(ctx.captured_queries)

    one = [f"one{i}" for i in range(1)]
    many = [f"many{i}" for i in range(20)]
    for attr in one + many:
        make_match(attr)
    # The first request also builds the suggestion's cache.
    make_match("warm")
    patch(["warm"], "affected")
    for verdict in ("affected", "fixed", None):
        assert patch(one, verdict) == patch(many, verdict), verdict
    events = TrackerEvent.objects.filter(attrpath__in=many)
    assert events.count() == 60 and len({e.batch for e in events}) == 3
    # The same event data as `set_verdict` / `remove_verdict` write.
    changed = events.get(attrpath="many0", kind=TrackerEvent.Kind.VERDICT_CHANGED)
    assert changed.data == {
        "old": {"verdict": "affected", "comment": "", "fix_commit": None},
        "new": {"verdict": "fixed", "comment": "", "fix_commit": None},
    }
    removed = events.get(attrpath="many0", kind=TrackerEvent.Kind.VERDICT_REMOVED)
    assert removed.data == {
        "old": {"verdict": "fixed", "comment": "", "fix_commit": None}
    }


def test_attribute_list_is_capped(
    committer_client: APIClient, candidates: CVEDerivationClusterProposal
) -> None:
    response = committer_client.patch(
        url(candidates.pk),
        body(package_attributes=[f"a{i}" for i in range(201)]),
        format="json",
    )
    assert response.status_code == 400
    assert "no more than 200" in str(response.data["package_attributes"])


def test_changing_a_verdict_keeps_its_comment(
    committer_client: APIClient, candidates: CVEDerivationClusterProposal
) -> None:
    """The menu sends only the verdict: what it does not change stays."""

    def patch(**fields: Any) -> Verdict:
        response = committer_client.patch(
            url(candidates.pk), body(package_attributes=["foo"]) | fields, format="json"
        )
        assert response.status_code == 204, response.data
        return Verdict.objects.get(attrpath="foo")

    v = patch(verdict="fixed", fix_commit=SHA, comment="fixed by the 2.0 bump")
    assert (v.comment, v.fix_commit) == ("fixed by the 2.0 bump", SHA)
    v = patch(verdict="fixed")
    assert (v.comment, v.fix_commit) == ("fixed by the 2.0 bump", SHA)
    # A fix commit belongs to a `fixed` verdict only.
    v = patch(verdict="wontfix")
    assert (v.verdict, v.comment, v.fix_commit) == (
        "wontfix",
        "fixed by the 2.0 bump",
        None,
    )
    v = patch(verdict="wontfix", comment="")
    assert v.comment == ""


def test_verdict_on_a_legacy_suggestion_backfills_it_first(
    committer_client: APIClient,
    make_legacy_suggestion: Callable[..., CVEDerivationClusterProposal],
    committer: User,
) -> None:
    """
    A suggestion the legacy matcher made has no new-model rows yet: the verdict must not be
    the first, or acceptance (still only in the links) would be lost to the next re-match.
    """
    s = make_legacy_suggestion(status=CVEDerivationClusterProposal.Status.ACCEPTED)
    response = committer_client.patch(
        url(s.pk),
        body(package_attributes=["foo"], verdict="wontfix"),
        format="json",
    )
    assert response.status_code == 204, response.data
    assert Match.objects.filter(suggestion=s, matcher="legacy-v2").exists()
    assert set(Verdict.objects.values_list("attrpath", "verdict")) == {
        ("foo", V.WONTFIX),
        ("foobar", V.AFFECTED),
    }


def test_lock_comes_before_reading(
    committer_client: APIClient,
    make_suggestion: Callable[..., CVEDerivationClusterProposal],
    make_container: Callable[..., Any],
    make_match: Callable[..., Match],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """`shared.locking`: the advisory locks of every suggestion written, ascending, first."""
    import api.unified.verdicts as verdicts

    suggestions = []
    for i in range(3):
        s = make_suggestion(container=make_container(cve_id=f"CVE-2025-800{i}"))
        cache_new_suggestions(s)
        make_match("foo", suggestion=s)
        suggestions.append(s)
    calls: list[tuple[str, object]] = []
    lock, check = verdicts.lock_for_write, verdicts.check_verdicts

    def recording_lock(ids: Any) -> None:
        calls.append(("lock", sorted(ids)))
        lock(ids)

    def recording_check(s: CVEDerivationClusterProposal, *args: Any) -> None:
        calls.append(("check", s.pk))
        check(s, *args)

    monkeypatch.setattr(verdicts, "lock_for_write", recording_lock)
    monkeypatch.setattr(verdicts, "check_verdicts", recording_check)
    response = committer_client.patch(
        url(suggestions[0].pk), body(package_attributes=["foo"]), format="json"
    )
    assert response.status_code == 204
    assert calls[0] == ("lock", [suggestions[0].pk])

    calls.clear()
    response = committer_client.patch(
        reverse("cvederivationclusterproposal-bulk-verdicts") + "?status=pending",
        body(package_attributes=["foo"], verdict="affected"),
        format="json",
    )
    assert response.status_code == 200, response.data
    assert calls[0] == ("lock", sorted(s.pk for s in suggestions))
