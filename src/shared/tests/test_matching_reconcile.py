import threading
from collections.abc import Callable
from datetime import timedelta
from io import StringIO

import pytest
from django.core.management import call_command
from django.db import connection, connections
from django.test.utils import CaptureQueriesContext
from django.utils import timezone

from shared.matching.matchers import NameExact
from shared.matching.reconcile import LAST_SEEN_RESOLUTION, reconcile_matches
from shared.models.linkage import CVEDerivationClusterProposal
from shared.models.matching import Match, TrackerEvent, Verdict
from shared.models.snapshot import BranchPackage

Cause = TrackerEvent.Cause
Kind = TrackerEvent.Kind
MakePackage = Callable[..., BranchPackage]


def reconcile(
    suggestion: CVEDerivationClusterProposal, matchers: list[str] | None = None
) -> list[tuple[str, str, str]]:
    """Reconcile and return the events written, as (kind, matcher, attrpath)."""
    result = reconcile_matches(suggestion, Cause.MATCHER, matchers)
    events = TrackerEvent.objects.filter(batch=result.batch).order_by("pk")
    return [(e.kind, e.matcher or "", e.attrpath) for e in events]


def rows(suggestion: CVEDerivationClusterProposal) -> list[tuple]:
    return list(
        Match.objects.filter(suggestion=suggestion)
        .order_by("matcher", "attrpath")
        .values_list(
            "matcher",
            "attrpath",
            "score",
            "evidence",
            "matcher_version",
            "last_seen_at",
            "retracted_at",
        )
    )


def test_add(
    suggestion: CVEDerivationClusterProposal, make_branch_package: MakePackage
) -> None:
    make_branch_package()  # `foo`, the CVE's package name
    result = reconcile_matches(
        suggestion, Cause.EVALUATION, ["name-exact", "name-substring"]
    )

    assert sorted(result.added) == [("name-exact", "foo"), ("name-substring", "foo")]
    matches = Match.objects.filter(suggestion=suggestion)
    assert {(m.matcher, m.matcher_version, m.score) for m in matches} == {
        ("name-exact", 1, 1.0),
        ("name-substring", 3, 1.0),
    }
    exact = matches.get(matcher="name-exact")
    assert exact.evidence["cve_field"] == "package_name"
    assert exact.evidence["branches"] == ["master"]
    events = TrackerEvent.objects.filter(suggestion=suggestion)
    assert {e.kind for e in events} == {Kind.MATCH_ADDED}
    assert {e.batch for e in events} == {result.batch}
    assert {e.cause for e in events} == {Cause.EVALUATION}
    assert all(e.actor is None and e.data["score"] == 1.0 for e in events)


def test_second_run_writes_nothing(
    suggestion: CVEDerivationClusterProposal, make_branch_package: MakePackage
) -> None:
    make_branch_package()
    make_branch_package(attrpath="libfoo", pname="libfoo")
    reconcile(suggestion)
    before = rows(suggestion)
    assert before

    with CaptureQueriesContext(connection) as queries:
        result = reconcile_matches(suggestion, Cause.MATCHER)

    assert result.events == 0
    assert result.refreshed == 0
    assert rows(suggestion) == before
    writes = [
        q["sql"]
        for q in queries
        if q["sql"].split()[0] in {"INSERT", "UPDATE", "DELETE"}
    ]
    assert writes == []


def test_retract_and_restore(
    suggestion: CVEDerivationClusterProposal, make_branch_package: MakePackage
) -> None:
    package = make_branch_package()
    assert reconcile(suggestion, ["name-exact"]) == [
        (Kind.MATCH_ADDED, "name-exact", "foo")
    ]

    BranchPackage.objects.filter(pk=package.pk).update(present=False)
    assert reconcile(suggestion, ["name-exact"]) == [
        (Kind.MATCH_RETRACTED, "name-exact", "foo")
    ]
    match = Match.objects.get(suggestion=suggestion)
    assert match.retracted_at is not None
    assert not Match.objects.active().filter(suggestion=suggestion).exists()
    # Still retracted, nothing new to say.
    assert reconcile(suggestion, ["name-exact"]) == []

    BranchPackage.objects.filter(pk=package.pk).update(present=True)
    assert reconcile(suggestion, ["name-exact"]) == [
        (Kind.MATCH_RESTORED, "name-exact", "foo")
    ]
    restored = Match.objects.get(suggestion=suggestion)
    assert restored.pk == match.pk
    assert restored.retracted_at is None
    assert restored.first_seen_at == match.first_seen_at


def test_material_change(
    suggestion: CVEDerivationClusterProposal, make_branch_package: MakePackage
) -> None:
    make_branch_package()
    reconcile(suggestion, ["name-exact"])
    Match.objects.filter(suggestion=suggestion).update(score=0.5)

    assert reconcile(suggestion, ["name-exact"]) == [
        (Kind.MATCH_CHANGED, "name-exact", "foo")
    ]
    event = TrackerEvent.objects.get(kind=Kind.MATCH_CHANGED)
    assert (event.data["old_score"], event.data["score"]) == (0.5, 1.0)
    assert Match.objects.get(suggestion=suggestion).score == 1.0


def test_immaterial_change_updates_without_event(
    suggestion: CVEDerivationClusterProposal,
    make_branch_package: MakePackage,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    make_branch_package()
    reconcile(suggestion, ["name-exact"])
    match = Match.objects.get(suggestion=suggestion)
    match.evidence["branches"] = ["master", "release-26.05"]
    match.save()

    result = reconcile_matches(suggestion, Cause.MATCHER, ["name-exact"])
    assert result.events == 0
    assert result.refreshed == 1
    assert Match.objects.get(pk=match.pk).evidence["branches"] == ["master"]

    monkeypatch.setattr(NameExact, "version", 2)
    result = reconcile_matches(suggestion, Cause.MATCHER, ["name-exact"])
    assert result.events == 0
    assert Match.objects.get(pk=match.pk).matcher_version == 2


def test_last_seen_is_refreshed_coarsely(
    suggestion: CVEDerivationClusterProposal, make_branch_package: MakePackage
) -> None:
    make_branch_package()
    reconcile(suggestion, ["name-exact"])
    stale = timezone.now() - LAST_SEEN_RESOLUTION - timedelta(minutes=1)
    Match.objects.filter(suggestion=suggestion).update(last_seen_at=stale)

    result = reconcile_matches(suggestion, Cause.MATCHER, ["name-exact"])

    assert result.events == 0
    assert result.refreshed == 1
    assert Match.objects.get(suggestion=suggestion).last_seen_at > stale


def test_subset_leaves_other_matchers_alone(
    suggestion: CVEDerivationClusterProposal,
    make_branch_package: MakePackage,
    make_match: Callable[..., Match],
    make_verdict: Callable[..., Verdict],
) -> None:
    make_branch_package()
    manual = make_match("bar", "manual", 1.0)
    reconcile(suggestion, ["name-exact"])
    old_substring = make_match("gone", "name-substring", 0.3)
    verdict = make_verdict("foo", Verdict.Kind.IRRELEVANT)

    assert reconcile(suggestion, ["name-exact"]) == []
    assert reconcile(suggestion, ["name-substring"]) == [
        (Kind.MATCH_ADDED, "name-substring", "foo"),
        (Kind.MATCH_RETRACTED, "name-substring", "gone"),
    ]
    manual.refresh_from_db()
    assert manual.retracted_at is None
    old_substring.refresh_from_db()
    assert old_substring.retracted_at is not None
    after = Verdict.objects.get(pk=verdict.pk)
    assert (after.verdict, after.updated_at) == (verdict.verdict, verdict.updated_at)


def test_truncation_is_recorded(
    suggestion: CVEDerivationClusterProposal,
    make_branch_package: MakePackage,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(NameExact, "limit", 1)
    make_branch_package(attrpath="a.foo")
    make_branch_package(attrpath="b.foo")
    result = reconcile_matches(suggestion, Cause.MATCHER, ["name-exact"])
    assert result.added == [("name-exact", "a.foo")]
    assert result.truncated == {"name-exact": 1}
    assert TrackerEvent.objects.get().data["matcher_truncated"] == 1


@pytest.mark.django_db(transaction=True)
def test_concurrent_runs_serialise(
    suggestion: CVEDerivationClusterProposal, make_branch_package: MakePackage
) -> None:
    make_branch_package()
    barrier = threading.Barrier(2)
    errors: list[BaseException] = []

    def run() -> None:
        try:
            barrier.wait()
            reconcile_matches(suggestion, Cause.MATCHER, ["name-exact"])
        except BaseException as e:  # noqa: BLE001
            errors.append(e)
        finally:
            connections.close_all()

    threads = [threading.Thread(target=run) for _ in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert errors == []
    assert Match.objects.filter(suggestion=suggestion).count() == 1
    assert TrackerEvent.objects.filter(kind=Kind.MATCH_ADDED).count() == 1


def test_command(
    suggestion: CVEDerivationClusterProposal, make_branch_package: MakePackage
) -> None:
    make_branch_package()
    out = StringIO()
    call_command(
        "reconcile_matches",
        suggestion.cve.cve_id,
        "--matcher",
        "name-exact",
        stdout=out,
    )
    assert "+1 -0" in out.getvalue()
    assert Match.objects.get(suggestion=suggestion).matcher == "name-exact"
    assert TrackerEvent.objects.get().cause == Cause.BACKFILL

    call_command("reconcile_matches", "--all-open", stdout=out)
    assert Match.objects.filter(suggestion=suggestion).count() > 1
