from collections.abc import Callable
from typing import Any

import pytest
from django.db import connection
from django.test.utils import CaptureQueriesContext
from rest_framework.reverse import reverse
from rest_framework.test import APIClient

from shared.cache_suggestions import cache_new_suggestions
from shared.derived_state import flush_derived_states
from shared.models.linkage import CVEDerivationClusterProposal
from shared.models.matching import Exposure, Match, SuggestionDerivedState, Verdict
from shared.models.nix_evaluation import NixEvaluation

Observed = Exposure.Observed
Status = CVEDerivationClusterProposal.Status


def url() -> str:
    return reverse("cvederivationclusterproposal-list")


@pytest.fixture
def states(
    make_suggestion: Callable[..., CVEDerivationClusterProposal],
    make_container: Callable[..., Any],
    make_match: Callable[..., Match],
    make_exposure: Callable[..., Exposure],
    make_verdict: Callable[..., Verdict],
    evaluation: NixEvaluation,
) -> dict[str, CVEDerivationClusterProposal]:
    """One cached suggestion per derived state."""
    n = iter(range(100))

    def new(**kwargs: Any) -> CVEDerivationClusterProposal:
        s = make_suggestion(
            container=make_container(cve_id=f"CVE-2025-40{next(n):02}"), **kwargs
        )
        cache_new_suggestions(s)
        return s

    out = {
        "no_candidates": new(),
        "needs_triage": new(),
        "possibly_fixed": new(),
        "tracking": new(),
        "resolved": new(),
        "dismissed": new(
            status=Status.REJECTED,
            rejection_reason=CVEDerivationClusterProposal.RejectionReason.NOT_IN_NIXPKGS,
        ),
    }
    make_match(suggestion=out["needs_triage"])
    make_exposure(suggestion=out["needs_triage"])
    make_match(suggestion=out["possibly_fixed"])
    make_exposure(
        suggestion=out["possibly_fixed"],
        observed=Observed.UNAFFECTED,
        first_affected_evaluation=evaluation,
        fixed_evaluation=evaluation,
    )
    make_match(suggestion=out["tracking"])
    make_exposure(suggestion=out["tracking"])
    make_verdict(suggestion=out["tracking"], verdict=Verdict.Kind.AFFECTED)
    make_match(suggestion=out["resolved"])
    make_exposure(suggestion=out["resolved"])
    make_verdict(suggestion=out["resolved"], verdict=Verdict.Kind.IRRELEVANT)
    make_match(suggestion=out["dismissed"])
    # The factories write rows directly, without the events whose triggers mark states stale.
    refresh_stored_states()
    return out


def refresh_stored_states() -> None:
    SuggestionDerivedState.objects.update(stale=True)
    flush_derived_states()


@pytest.mark.parametrize(
    "state",
    [
        "no_candidates",
        "needs_triage",
        "possibly_fixed",
        "tracking",
        "resolved",
        "dismissed",
    ],
)
def test_filter(
    anonymous_client: APIClient,
    states: dict[str, CVEDerivationClusterProposal],
    state: str,
) -> None:
    response = anonymous_client.get(url(), {"derived_state": state})
    assert response.status_code == 200
    assert [r["id"] for r in response.data["results"]] == [states[state].pk]


def test_filter_or_and_combined(
    anonymous_client: APIClient, states: dict[str, CVEDerivationClusterProposal]
) -> None:
    response = anonymous_client.get(
        url(), {"derived_state": ["tracking", "dismissed", "no_candidates"]}
    )
    assert {r["id"] for r in response.data["results"]} == {
        states[s].pk for s in ("tracking", "dismissed", "no_candidates")
    }
    response = anonymous_client.get(
        url(), {"derived_state": ["tracking", "dismissed"], "status": "pending"}
    )
    assert [r["id"] for r in response.data["results"]] == [states["tracking"].pk]


def test_filter_invalid(anonymous_client: APIClient) -> None:
    response = anonymous_client.get(url(), {"derived_state": "nope"})
    assert response.status_code == 400


def test_field_on_lists_and_detail(
    anonymous_client: APIClient, states: dict[str, CVEDerivationClusterProposal]
) -> None:
    response = anonymous_client.get(url())
    assert {r["id"]: r["derived_state"] for r in response.data["results"]} == {
        s.pk: name for name, s in states.items()
    }
    detail = reverse(
        "cvederivationclusterproposal-detail", kwargs={"pk": states["tracking"].pk}
    )
    assert anonymous_client.get(detail).data["derived_state"] == "tracking"


def test_stale_rows_are_computed_live(
    anonymous_client: APIClient,
    states: dict[str, CVEDerivationClusterProposal],
    make_verdict: Callable[..., Verdict],
) -> None:
    """A row whose writer has not flushed yet is neither shown nor filtered by its old value."""
    s = states["needs_triage"]
    make_verdict(suggestion=s, verdict=Verdict.Kind.AFFECTED)
    SuggestionDerivedState.objects.filter(suggestion=s).update(stale=True)
    ids = [
        r["id"]
        for r in anonymous_client.get(url(), {"derived_state": "tracking"}).data[
            "results"
        ]
    ]
    assert s.pk in ids
    assert s.pk not in [
        r["id"]
        for r in anonymous_client.get(url(), {"derived_state": "needs_triage"}).data[
            "results"
        ]
    ]
    response = anonymous_client.get(url())
    assert {r["id"]: r["derived_state"] for r in response.data["results"]}[
        s.pk
    ] == "tracking"
    # Nothing is written by reading.
    assert SuggestionDerivedState.objects.get(suggestion=s).stale


def test_list_field_query_count(
    anonymous_client: APIClient,
    states: dict[str, CVEDerivationClusterProposal],
    make_suggestion: Callable[..., CVEDerivationClusterProposal],
    make_container: Callable[..., Any],
    make_match: Callable[..., Match],
    django_assert_num_queries: Callable[..., CaptureQueriesContext],
) -> None:
    """The stored state comes with the page's join: no query per suggestion."""
    with CaptureQueriesContext(connection) as before:
        anonymous_client.get(url())
    for i in range(4):
        s = make_suggestion(container=make_container(cve_id=f"CVE-2025-41{i:02}"))
        make_match(suggestion=s)
        cache_new_suggestions(s)
    refresh_stored_states()
    with django_assert_num_queries(len(before)):
        response = anonymous_client.get(url())
    assert len(response.data["results"]) == 10
    assert all(r["derived_state"] for r in response.data["results"])
    filtered = {"derived_state": "needs_triage"}
    with CaptureQueriesContext(connection) as one_page:
        anonymous_client.get(url(), filtered)
    # The filter adds one query, for the stale rows of the selection.
    assert len(one_page) == len(before) + 1

