from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from django.contrib.auth.models import User
from django.test.utils import CaptureQueriesContext

from shared.derived_state import (
    DerivedState,
    SuggestionFacts,
    VerdictFact,
    derive_state,
    derive_states,
    effective_status,
    pick_verdict,
    possibly_fixed_keys,
    possibly_fixed_queue,
    possibly_fixed_rows,
    remove_verdict,
    set_verdict,
)
from shared.models.linkage import CVEDerivationClusterProposal, Overlay, PackageOverlay
from shared.models.matching import Exposure, Match, TrackerEvent, Verdict
from shared.models.nix_evaluation import NixpkgsBranch
from shared.models.package import Package
from shared.tests.test_exposure import World, record, world  # noqa: F401

Observed = Exposure.Observed
Reason = Exposure.Reason
V = Verdict.Kind
Status = CVEDerivationClusterProposal.Status
Kind = TrackerEvent.Kind
T0 = datetime(2026, 11, 1, tzinfo=UTC)


def exposure(
    attrpath: str = "foo",
    branch: str = "master",
    observed: str = Observed.AFFECTED,
    reason: str = Reason.VERSION_RANGE,
    fixed: bool = False,
    was_affected: bool | None = None,
) -> Exposure:
    """An unsaved row, enough for the pure functions."""
    if was_affected is None:
        was_affected = observed == Observed.AFFECTED or fixed
    return Exposure(
        attrpath=attrpath,
        branch_id=branch,
        observed=observed,
        reason=reason,
        first_affected_evaluation_id=1 if was_affected else None,
        fixed_evaluation_id=2 if fixed else None,
    )


def facts(
    *exposures: Exposure,
    matched: tuple[str, ...] = ("foo",),
    verdicts: tuple[VerdictFact, ...] = (),
    status: str = Status.PENDING,
    reason: str | None = None,
    **fields: Any,
) -> SuggestionFacts:
    return SuggestionFacts(
        suggestion_id=1,
        status=status,
        rejection_reason=reason,
        matched=set(matched),
        verdicts=list(verdicts),
        exposures=list(exposures),
        **fields,
    )


STATES: list[tuple[str, SuggestionFacts, DerivedState]] = [
    (
        "dismissed by a CVE-level rejection",
        facts(exposure(), status=Status.REJECTED, reason="not_in_nixpkgs"),
        DerivedState.DISMISSED,
    ),
    (
        "rejected by a human without reason",
        facts(exposure(), status=Status.REJECTED),
        DerivedState.DISMISSED,
    ),
    (
        "matcher rejection is not a dismissal",
        facts(exposure(), status=Status.REJECTED, reason="no_matches"),
        DerivedState.NEEDS_TRIAGE,
    ),
    ("no candidates", facts(matched=()), DerivedState.NO_CANDIDATES),
    (
        "exposures of retracted matches are ignored",
        facts(exposure(), matched=()),
        DerivedState.NO_CANDIDATES,
    ),
    ("observed affected", facts(exposure()), DerivedState.NEEDS_TRIAGE),
    (
        "observed unknown",
        facts(exposure(observed=Observed.UNKNOWN)),
        DerivedState.NEEDS_TRIAGE,
    ),
    (
        "candidate on no tracked branch",
        facts(),
        DerivedState.NEEDS_TRIAGE,
    ),
    (
        "affected verdict",
        facts(exposure(), verdicts=(VerdictFact("foo", None, V.AFFECTED),)),
        DerivedState.TRACKING,
    ),
    (
        "acknowledged in knownVulnerabilities",
        facts(exposure(reason=Reason.ACKNOWLEDGED)),
        DerivedState.TRACKING,
    ),
    (
        "fixed without confirmation",
        facts(exposure(observed=Observed.UNAFFECTED, fixed=True)),
        DerivedState.POSSIBLY_FIXED,
    ),
    (
        "removed after being affected",
        facts(exposure(observed=Observed.ABSENT, was_affected=True)),
        DerivedState.POSSIBLY_FIXED,
    ),
    (
        "fixed and confirmed",
        facts(
            exposure(observed=Observed.UNAFFECTED, fixed=True),
            verdicts=(VerdictFact("foo", None, V.FIXED),),
        ),
        DerivedState.RESOLVED,
    ),
    (
        "never affected",
        facts(exposure(observed=Observed.UNAFFECTED)),
        DerivedState.RESOLVED,
    ),
    (
        "wontfix",
        facts(exposure(), verdicts=(VerdictFact("foo", None, V.WONTFIX),)),
        DerivedState.RESOLVED,
    ),
    (
        "backport: fixed on master, affected on the release branch",
        facts(
            exposure(observed=Observed.UNAFFECTED, fixed=True),
            exposure(branch="release-26.05"),
            verdicts=(VerdictFact("foo", None, V.AFFECTED),),
        ),
        DerivedState.TRACKING,
    ),
    (
        "branch-specific verdict over all-branches verdict",
        facts(
            exposure(),
            verdicts=(
                VerdictFact("foo", None, V.FIXED),
                VerdictFact("foo", "master", V.AFFECTED),
            ),
        ),
        DerivedState.TRACKING,
    ),
    (
        "needs triage wins over tracking",
        facts(
            exposure(),
            exposure("bar"),
            matched=("foo", "bar"),
            verdicts=(VerdictFact("foo", None, V.AFFECTED),),
        ),
        DerivedState.NEEDS_TRIAGE,
    ),
    (
        "regression after a fixed verdict",
        facts(
            exposure(),
            verdicts=(VerdictFact("foo", None, V.FIXED, updated_at=T0),),
            became_affected={("foo", "master"): T0 + timedelta(days=1)},
        ),
        DerivedState.NEEDS_TRIAGE,
    ),
    (
        "became affected before the fixed verdict",
        facts(
            exposure(),
            verdicts=(VerdictFact("foo", None, V.FIXED, updated_at=T0),),
            became_affected={("foo", "master"): T0 - timedelta(days=1)},
        ),
        DerivedState.RESOLVED,
    ),
    (
        "published: the publisher's affected verdict tracks",
        facts(
            exposure(),
            status=Status.PUBLISHED,
            verdicts=(VerdictFact("foo", None, V.AFFECTED),),
        ),
        DerivedState.TRACKING,
    ),
    (
        "published and fixed everywhere stays tracking until confirmed",
        facts(
            exposure(observed=Observed.UNAFFECTED, fixed=True),
            status=Status.PUBLISHED,
            verdicts=(VerdictFact("foo", None, V.AFFECTED),),
        ),
        DerivedState.TRACKING,
    ),
    (
        "ignored (irrelevant verdict) resolves",
        facts(exposure(), verdicts=(VerdictFact("foo", None, V.IRRELEVANT),)),
        DerivedState.RESOLVED,
    ),
]


@pytest.mark.parametrize(
    "f, expected", [s[1:] for s in STATES], ids=[s[0] for s in STATES]
)
def test_derive_state(f: SuggestionFacts, expected: DerivedState) -> None:
    assert derive_state(f).state == expected


def test_derived_details() -> None:
    d = derive_state(
        facts(
            exposure(observed=Observed.UNAFFECTED, fixed=True),
            exposure(branch="release-26.05"),
            verdicts=(VerdictFact("foo", None, V.FIXED, updated_at=T0),),
            became_affected={("foo", "release-26.05"): T0 + timedelta(hours=1)},
        )
    )
    assert d.regressions == [("foo", "release-26.05")]
    assert d.possibly_fixed == []


def test_pick_verdict() -> None:
    general = VerdictFact("foo", None, V.FIXED)
    specific = VerdictFact("foo", "master", V.AFFECTED)
    other = VerdictFact("bar", "master", V.IRRELEVANT)
    verdicts = [general, specific, other]
    assert pick_verdict(verdicts, "foo", "master") == specific
    assert pick_verdict(verdicts, "foo", "release-26.05") == general
    assert pick_verdict(verdicts, "baz", "master") is None


def test_effective_status_sources() -> None:
    e = exposure(observed=Observed.UNKNOWN)
    assert effective_status(e, None).status == Observed.UNKNOWN
    assert effective_status(e, None).source == "observed"
    assert effective_status(None, None).source == "none"
    eff = effective_status(e, VerdictFact("foo", None, V.NOT_AFFECTED))
    assert (eff.status, eff.source) == (V.NOT_AFFECTED, "verdict")


# --- Verdict helpers ------------------------------------------------------------------------


@pytest.fixture
def author(db: None) -> User:
    return User.objects.create(username="triager")


def test_set_change_remove_verdict(
    suggestion: CVEDerivationClusterProposal, author: User, branch: NixpkgsBranch
) -> None:
    def events() -> list[TrackerEvent]:
        return list(TrackerEvent.objects.order_by("pk"))

    set_verdict(suggestion, "foo", V.AFFECTED, author)
    (event,) = events()
    assert (event.kind, event.cause, event.actor, event.branch) == (
        Kind.VERDICT_SET,
        TrackerEvent.Cause.USER,
        author,
        None,
    )
    assert event.data["new"]["verdict"] == V.AFFECTED

    set_verdict(suggestion, "foo", V.AFFECTED, author)
    assert len(events()) == 1

    sha = "a" * 40
    set_verdict(suggestion, "foo", V.FIXED, author, fix_commit=sha)
    changed = events()[-1]
    assert changed.kind == Kind.VERDICT_CHANGED
    assert changed.data["old"]["verdict"] == V.AFFECTED
    assert changed.data["new"] == {"verdict": V.FIXED, "comment": "", "fix_commit": sha}
    assert Verdict.objects.get().verdict == V.FIXED

    # A branch-specific verdict is a separate row.
    set_verdict(suggestion, "foo", V.AFFECTED, author, branch=branch)
    assert Verdict.objects.count() == 2
    assert events()[-1].branch == branch

    assert remove_verdict(suggestion, "foo", author)
    assert events()[-1].kind == Kind.VERDICT_REMOVED
    assert events()[-1].data["old"]["verdict"] == V.FIXED
    assert not remove_verdict(suggestion, "foo", author)
    assert list(Verdict.objects.values_list("branch", flat=True)) == [branch.name]


def test_set_verdict_rejects_bad_fix_commit(
    suggestion: CVEDerivationClusterProposal, author: User
) -> None:
    with pytest.raises(ValueError):
        set_verdict(suggestion, "foo", V.FIXED, author, fix_commit="ABC")
    assert not Verdict.objects.exists()


# --- With the exposure layer ----------------------------------------------------------------


def fixed_world(world: World) -> World:  # noqa: F811
    world.match()
    world.package("1.5")
    world.reconcile()
    world.apply(world.package("2.0"))
    return world


def test_queue_row(world: World) -> None:  # noqa: F811
    fixed_world(world)
    (row,) = possibly_fixed_queue()
    first, fixed = world.evaluations[0], world.evaluations[1]
    assert (row.attrpath, row.branch_id, row.cve_id) == (
        "foo",
        "master",
        "CVE-2025-0001",
    )
    assert (row.old_version, row.new_version) == ("1.5", "2.0")
    assert (row.last_affected_evaluation, row.fixed_evaluation) == (first, fixed)
    assert row.compare_url == (
        f"https://github.com/NixOS/nixpkgs/compare/{first.commit_sha1}...{fixed.commit_sha1}"
    )
    assert derive_states([world.suggestion.pk])[world.suggestion.pk].state == (
        DerivedState.POSSIBLY_FIXED
    )


def test_queue_excludes_confirmed(world: World, author: User) -> None:  # noqa: F811
    fixed_world(world)
    set_verdict(world.suggestion, "foo", V.FIXED, author)
    assert possibly_fixed_queue() == []
    assert derive_states([world.suggestion.pk])[world.suggestion.pk].state == (
        DerivedState.RESOLVED
    )


def test_queue_still_affected_answers_until_next_fix(
    world: World,  # noqa: F811
    author: User,
) -> None:
    fixed_world(world)
    set_verdict(world.suggestion, "foo", V.AFFECTED, author, branch=world.branch)
    assert possibly_fixed_queue() == []
    d = derive_states([world.suggestion.pk])[world.suggestion.pk]
    assert (d.state, d.possibly_fixed) == (DerivedState.TRACKING, [])
    # Affected again, then fixed again: the new fix is a new question.
    world.apply(world.package("1.9"))
    assert possibly_fixed_queue() == []
    world.apply(world.package("2.1"))
    (row,) = possibly_fixed_queue()
    assert (row.old_version, row.new_version) == ("1.9", "2.1")


def test_queue_keeps_fix_after_later_all_branches_affected(
    world: World,  # noqa: F811
    author: User,
) -> None:
    """Accepting a suggestion records `affected` on all branches; that is not "still affected"."""
    fixed_world(world)
    set_verdict(world.suggestion, "foo", V.AFFECTED, author)
    assert len(possibly_fixed_queue()) == 1


def test_queue_keeps_fix_after_earlier_affected_verdict(
    world: World,  # noqa: F811
    author: User,
) -> None:
    world.match()
    world.package("1.5")
    world.reconcile()
    set_verdict(world.suggestion, "foo", V.AFFECTED, author)
    world.apply(world.package("2.0"))
    assert len(possibly_fixed_queue()) == 1


def test_queue_keys_by_branch(world: World) -> None:  # noqa: F811
    fixed_world(world)
    (row,) = possibly_fixed_queue()
    assert possibly_fixed_keys() == [(row.exposure_id, "master")]
    assert possibly_fixed_keys(branch_ids=["release-26.05"]) == []
    assert possibly_fixed_rows([row.exposure_id]) == [row]


def test_queue_keeps_published(world: World) -> None:  # noqa: F811
    fixed_world(world)
    for status in (Status.ACCEPTED, Status.PUBLISHED):
        CVEDerivationClusterProposal.objects.filter(pk=world.suggestion.pk).update(
            status=status
        )
    assert len(possibly_fixed_queue()) == 1


def test_queue_excludes_dismissed_and_retracted(world: World) -> None:  # noqa: F811
    fixed_world(world)
    Match.objects.update(retracted_at=T0)
    assert possibly_fixed_queue() == []
    Match.objects.update(retracted_at=None)
    CVEDerivationClusterProposal.objects.filter(pk=world.suggestion.pk).update(
        status=Status.REJECTED, rejection_reason="not_in_nixpkgs"
    )
    assert possibly_fixed_queue() == []


def test_queue_excludes_ignored(world: World, author: User) -> None:  # noqa: F811
    fixed_world(world)
    set_verdict(world.suggestion, "foo", V.IRRELEVANT, author)
    assert possibly_fixed_queue() == []


def test_ignore_overlay_alone_is_no_verdict(world: World) -> None:  # noqa: F811
    """Ignores write a verdict (and are backfilled), so an overlay alone implies nothing."""
    fixed_world(world)
    PackageOverlay.objects.create(
        suggestion=world.suggestion,
        package_attribute="foo",
        package=Package.objects.create(name="foo", homepage="https://foo"),
        type=Overlay.Type.IGNORED,
    )
    assert [q.attrpath for q in possibly_fixed_queue()] == ["foo"]


def test_regression_flag_end_to_end(world: World, author: User) -> None:  # noqa: F811
    fixed_world(world)
    set_verdict(world.suggestion, "foo", V.FIXED, author)
    world.apply(world.package("1.9"))
    d = derive_states([world.suggestion.pk])[world.suggestion.pk]
    assert d.state == DerivedState.NEEDS_TRIAGE
    assert d.regressions == [("foo", "master")]
    # The verdict itself was not touched.
    assert Verdict.objects.get().verdict == V.FIXED


def test_derive_states_query_count(
    make_suggestion: Callable[..., CVEDerivationClusterProposal],
    make_container: Callable[..., Any],
    make_exposure: Callable[..., Exposure],
    make_match: Callable[..., Match],
    django_assert_max_num_queries: Callable[..., CaptureQueriesContext],
) -> None:
    ids = []
    for i in range(5):
        s = make_suggestion(container=make_container(cve_id=f"CVE-2025-100{i}"))
        make_match(suggestion=s)
        make_exposure(suggestion=s)
        ids.append(s.pk)
    with django_assert_max_num_queries(10):
        states = derive_states(ids)
    assert {d.state for d in states.values()} == {DerivedState.NEEDS_TRIAGE}
