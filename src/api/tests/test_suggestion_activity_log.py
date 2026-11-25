import uuid
from collections.abc import Callable
from typing import Any

from django.contrib.auth.models import User
from django.db import connection
from django.test.utils import CaptureQueriesContext
from rest_framework.reverse import reverse
from rest_framework.test import APIClient

from shared.derived_state import set_verdict
from shared.identity.reconcile import reconcile_mapping_change
from shared.matching.reconcile import reconcile_matches
from shared.models.issue import NixpkgsIssue
from shared.models.linkage import CVEDerivationClusterProposal
from shared.models.matching import Match, ProductMapping, TrackerEvent, Verdict
from shared.models.nix_evaluation import NixChannel, NixEvaluation
from shared.pipeline import refresh_suggestion
from shared.snapshot import update_branch_snapshot
from shared.tests.test_exposure import World, record, world  # noqa: F401
from shared.tests.test_identity_mappings import make_mapping, persist_keys  # noqa: F401


def test_detail_activity_log_null_by_default(
    cached_suggestion: CVEDerivationClusterProposal,
    client: APIClient,
) -> None:
    response = client.get(
        reverse(
            "cvederivationclusterproposal-detail", kwargs={"pk": cached_suggestion.pk}
        )
    )
    assert response.status_code == 200
    assert response.data["activity_log"] is None


def test_detail_activity_log_inlined_when_requested(
    cached_suggestion: CVEDerivationClusterProposal,
    client: APIClient,
) -> None:
    response = client.get(
        reverse(
            "cvederivationclusterproposal-detail", kwargs={"pk": cached_suggestion.pk}
        ),
        {"activity_log": "true"},
    )
    assert response.status_code == 200
    activity_log = response.data["activity_log"]
    assert isinstance(activity_log, list)
    assert len(activity_log) >= 1
    entry = activity_log[0]
    assert set(entry.keys()) >= {"action", "timestamp"}
    assert any(e["action"] == "create" for e in activity_log)


def test_list_activity_log_null_by_default(
    cached_suggestion: CVEDerivationClusterProposal,
    client: APIClient,
) -> None:
    response = client.get(reverse("cvederivationclusterproposal-list"))
    assert response.status_code == 200
    assert response.data["results"][0]["activity_log"] is None


def test_list_activity_log_inlined_when_requested(
    make_cached_suggestion: Callable[..., CVEDerivationClusterProposal],
    client: APIClient,
) -> None:
    make_cached_suggestion()
    make_cached_suggestion()
    response = client.get(
        reverse("cvederivationclusterproposal-list"), {"activity_log": "true"}
    )
    assert response.status_code == 200
    for result in response.data["results"]:
        assert isinstance(result["activity_log"], list)
        assert len(result["activity_log"]) >= 1


def test_issue_expanded_suggestions_inline_activity_log(
    issue: NixpkgsIssue,
    client: APIClient,
) -> None:
    # Without the param, expanded suggestions carry a null activity log.
    response = client.get(
        reverse("nixpkgsissue-detail", kwargs={"code": issue.code}),
        {"expand": "suggestions"},
    )
    assert response.status_code == 200
    assert response.data["suggestions"][0]["activity_log"] is None

    # With the param, they carry the folded activity log.
    response = client.get(
        reverse("nixpkgsissue-detail", kwargs={"code": issue.code}),
        {"expand": "suggestions", "activity_log": "true"},
    )
    assert response.status_code == 200
    activity_log = response.data["suggestions"][0]["activity_log"]
    assert isinstance(activity_log, list)
    assert len(activity_log) >= 1


def test_issue_list_expanded_suggestions_inline_activity_log(
    issue: NixpkgsIssue,
    client: APIClient,
) -> None:
    response = client.get(
        reverse("nixpkgsissue-list"),
        {"expand": "suggestions", "activity_log": "true"},
    )
    assert response.status_code == 200
    suggestions = response.data["results"][0]["suggestions"]
    assert isinstance(suggestions[0]["activity_log"], list)
    assert len(suggestions[0]["activity_log"]) >= 1


def test_rematch_appears_in_activity_log(
    cached_suggestion: CVEDerivationClusterProposal,
    client: APIClient,
) -> None:
    """
    A rematch call must be visible in the activity log so API consumers
    can track algorithm reruns without reading server logs.
    Here the re-match finds nothing, so the packages stay, flagged as no longer matched.
    """
    refresh_suggestion(cached_suggestion)
    response = client.get(
        reverse(
            "cvederivationclusterproposal-detail",
            kwargs={"pk": cached_suggestion.pk},
        ),
        {"activity_log": "true"},
    )
    assert response.status_code == 200
    rematch = next(e for e in response.data["activity_log"] if e["action"] == "rematch")
    assert rematch["username"] is None


def test_rematch_reopening_is_not_attributed_to_anyone(
    cached_suggestion: CVEDerivationClusterProposal,
    evaluation: NixEvaluation,
    client: APIClient,
) -> None:
    """Re-matching no longer rejects (F4); it reopens a `no_matches` rejection, as the tracker."""
    update_branch_snapshot(evaluation)
    CVEDerivationClusterProposal.objects.filter(pk=cached_suggestion.pk).update(
        status=CVEDerivationClusterProposal.Status.REJECTED,
        rejection_reason=CVEDerivationClusterProposal.RejectionReason.NO_MATCHES,
    )
    cached_suggestion.refresh_from_db()
    refresh_suggestion(cached_suggestion)
    response = client.get(
        reverse(
            "cvederivationclusterproposal-detail",
            kwargs={"pk": cached_suggestion.pk},
        ),
        {"activity_log": "true"},
    )
    assert response.status_code == 200
    reopening = next(
        e
        for e in response.data["activity_log"]
        if e["action"] == "update"
        and e["status_value"] == CVEDerivationClusterProposal.Status.PENDING
    )
    assert reopening["username"] is None


def _log(c: APIClient, pk: int) -> list[dict]:
    response = c.get(
        reverse("cvederivationclusterproposal-activity-log", kwargs={"pk": pk})
    )
    assert response.status_code == 200
    return response.json()


def test_tracker_batches_in_activity_log(
    world: World,  # noqa: F811
    committer_client: APIClient,
    anonymous_client: APIClient,
) -> None:
    world.match("foo", affected_product=None, cve_field="product", cve_value="foo")
    batch = uuid.uuid4()
    for attr in ("foo", "bar"):
        TrackerEvent.objects.create(
            suggestion=world.suggestion,
            kind=TrackerEvent.Kind.MATCH_ADDED,
            attrpath=attr,
            matcher="name-trigram",
            cause=TrackerEvent.Cause.MATCHER,
            data={
                "score": 0.8,
                "evidence": {"cve_field": "product", "similarity": 0.8},
            },
            batch=batch,
        )
    world.package("1.5")
    world.reconcile()
    world.apply(world.package("2.0"))
    response = committer_client.patch(
        reverse(
            "cvederivationclusterproposal-verdicts", kwargs={"pk": world.suggestion.pk}
        ),
        {"package_attributes": ["foo"], "branch": "master", "verdict": "fixed"},
        format="json",
    )
    assert response.status_code == 204

    entries = [
        e
        for e in _log(anonymous_client, world.suggestion.pk)
        if e["action"].startswith("tracker.")
    ]
    assert [e["action"] for e in entries] == [
        "tracker.matches",
        "tracker.exposures",
        "tracker.exposures",
        "tracker.verdicts",
    ]
    matches, appeared, fixed, verdict = entries
    assert (matches["username"], matches["cause"]) == (None, "matcher")
    assert [(c["kind"], c["attrpath"], c["matcher"]) for c in matches["changes"]] == [
        ("match_added", "foo", "name-trigram"),
        ("match_added", "bar", "name-trigram"),
    ]
    evidence = matches["changes"][0]["evidence"]
    assert evidence["similarity"] == 0.8 and evidence["pkg_field"] is None
    (change,) = fixed["changes"]
    assert change["kind"] == "exposure_became_unaffected"
    assert (change["branch"], change["old_version"], change["new_version"]) == (
        "master",
        "1.5",
        "2.0",
    )
    assert (change["old_status"], change["new_status"]) == ("affected", "unaffected")
    assert change["fix_candidate"] is True
    assert change["evaluation_commit"] == world.evaluations[-1].commit_sha1
    assert appeared["changes"][0]["kind"] == "exposure_appeared"
    assert (verdict["username"], verdict["cause"]) == ("committer", "user")
    assert verdict["changes"][0]["verdict"] == "fixed"
    # Old entries keep their shape, with the new fields empty.
    create = next(
        e
        for e in _log(anonymous_client, world.suggestion.pk)
        if e["action"] == "create"
    )
    assert (create["cause"], create["changes"]) == (None, [])


def test_tracker_entry_of_deleted_user_is_redacted(
    world: World,  # noqa: F811
    committer: User,
    anonymous_client: APIClient,
) -> None:
    world.match()
    set_verdict(world.suggestion, "foo", Verdict.Kind.IRRELEVANT, committer)
    committer.delete()
    (entry,) = [
        e
        for e in _log(anonymous_client, world.suggestion.pk)
        if e["action"] == "tracker.verdicts"
    ]
    assert entry["username"] == "REDACTED"


def test_tracker_entries_batched_on_list(
    make_cached_suggestion: Callable[..., CVEDerivationClusterProposal],
    make_container: Callable[..., Any],
    make_match: Callable[..., Match],
    anonymous_client: APIClient,
    django_assert_num_queries: Callable[..., CaptureQueriesContext],
) -> None:
    def add(i: int) -> None:
        s = make_cached_suggestion(
            container=make_container(cve_id=f"CVE-2025-50{i:02}")
        )
        TrackerEvent.objects.create(
            suggestion=s,
            kind=TrackerEvent.Kind.MATCH_ADDED,
            attrpath="foo",
            matcher="name-exact",
            cause=TrackerEvent.Cause.MATCHER,
            batch=uuid.uuid4(),
        )

    add(0)
    with CaptureQueriesContext(connection) as one:
        anonymous_client.get(
            reverse("cvederivationclusterproposal-list"), {"activity_log": "true"}
        )
    for i in range(1, 5):
        add(i)
    with django_assert_num_queries(len(one)):
        response = anonymous_client.get(
            reverse("cvederivationclusterproposal-list"), {"activity_log": "true"}
        )
    for result in response.data["results"]:
        assert [e["action"] for e in result["activity_log"]][-1] == "tracker.matches"


def test_vetoed_retraction_names_the_mapping(
    anonymous_client: APIClient,
    suggestion: CVEDerivationClusterProposal,
    channel: NixChannel,
    make_branch_package: Callable[..., object],
    make_mapping: Callable[..., ProductMapping],  # noqa: F811
) -> None:
    make_branch_package()
    persist_keys()
    reconcile_matches(suggestion, TrackerEvent.Cause.MATCHER, ["name-exact"])
    veto = make_mapping("foo", ProductMapping.Relation.NOT_SAME, attrpath="foo")
    reconcile_mapping_change(veto)
    (entry,) = [
        e
        for e in _log(anonymous_client, suggestion.pk)
        if any(c["kind"] == "match_retracted" for c in e["changes"])
    ]
    assert entry["cause"] == "mapping"
    (change,) = entry["changes"]
    assert change["vetoed_by"] == {
        "id": veto.pk,
        "product_key": "cna:/foo",
        "relation": "not_same",
        "source": "curated",
        "target": "foo",
    }
