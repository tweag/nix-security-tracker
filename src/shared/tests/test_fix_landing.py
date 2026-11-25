from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from shared.channel_history import compute_landings, first_containing
from shared.history import CachedAncestry, HistoryClone
from shared.models.linkage import CVEDerivationClusterProposal
from shared.models.matching import Exposure, TrackerEvent
from shared.models.nix_evaluation import NixChannel, NixEvaluation, NixpkgsBranch
from shared.models.remediation import ChannelAdvance, FixLanding
from shared.tests import test_exposure
from shared.tests.local_repo import LocalRepo
from shared.tests.test_exposure import World

# The exposure test world: a suggestion on `foo`, affected in [1.0, 2.0), on a tracked branch.
record = test_exposure.record
world = test_exposure.world

T0 = datetime(2026, 11, 1, tzinfo=UTC)
Kind = TrackerEvent.Kind


class FakeAncestry:
    """`heads[h]` is the set of commits head `h` contains."""

    def __init__(self) -> None:
        self.heads: dict[str, set[str]] = {}
        self.queries = 0

    def contains(self, head: str, commit: str) -> bool | None:
        self.queries += 1
        if head not in self.heads:
            return None
        known = set().union(*self.heads.values())
        if commit not in known:
            return None
        return commit in self.heads[head]

    def advance(
        self, channel: NixChannel, head: str, commits: set[str], hours: int
    ) -> ChannelAdvance:
        previous = max(
            (self.heads[a.commit] for a in channel.advances.all()),
            key=len,
            default=set(),
        )
        self.heads[head] = previous | commits | {head}
        return ChannelAdvance.objects.create(
            channel=channel, commit=head, observed_at=T0 + timedelta(hours=hours)
        )


def fixed(world: World) -> tuple[Exposure, NixEvaluation]:
    world.match()
    world.package("1.5")
    world.reconcile()
    fixed_at = world.package("2.0")
    world.apply(fixed_at)
    row = world.row()
    assert row.fixed_evaluation == fixed_at
    return row, fixed_at


def test_lands_at_first_containing_advance(world: World) -> None:
    row, fixed_at = fixed(world)
    ancestry = FakeAncestry()
    ancestry.advance(world.channel, "a" * 40, set(), 0)
    second = ancestry.advance(world.channel, "b" * 40, {fixed_at.commit_sha1}, 5)
    ancestry.advance(world.channel, "c" * 40, set(), 9)

    result = compute_landings(ancestry)

    assert result.landed == 1
    landing = FixLanding.objects.get()
    assert (landing.exposure, landing.channel, landing.advance) == (
        row,
        world.channel,
        second,
    )
    assert landing.landed_at == second.observed_at
    assert landing.commit == fixed_at.commit_sha1
    event = world.events()[-1]
    assert (event.kind, event.cause, event.branch_id) == (
        Kind.FIX_LANDED,
        TrackerEvent.Cause.CHANNEL,
        world.branch.name,
    )
    assert event.data["via"] == "fixed_evaluation"
    assert event.data["channel"] == world.channel.channel_branch

    # Never recomputed: nothing is pending any more, no ancestry query at all.
    ancestry.queries = 0
    assert compute_landings(ancestry).landed == 0
    assert ancestry.queries == 0


def test_not_yet_contained_stays_pending(world: World) -> None:
    _, fixed_at = fixed(world)
    ancestry = FakeAncestry()
    ancestry.advance(world.channel, "a" * 40, {"d" * 40}, 0)
    ancestry.heads["x" * 40] = {
        fixed_at.commit_sha1
    }  # known commit, not in the channel

    result = compute_landings(ancestry)
    assert (result.landed, result.pending, result.unknown) == (0, 1, 0)

    ancestry.advance(world.channel, "b" * 40, {fixed_at.commit_sha1}, 1)
    assert compute_landings(ancestry).landed == 1


def test_unknown_fix_point_is_counted(world: World) -> None:
    fixed(world)
    ancestry = FakeAncestry()
    ancestry.advance(world.channel, "a" * 40, set(), 0)
    result = compute_landings(ancestry)
    assert (result.landed, result.unknown) == (0, 1)


def test_fix_commit_is_preferred(world: World) -> None:
    row, fixed_at = fixed(world)
    exact = "e" * 40
    Exposure.objects.filter(pk=row.pk).update(fix_commit=exact)
    ancestry = FakeAncestry()
    first = ancestry.advance(world.channel, "a" * 40, {exact}, 0)
    ancestry.advance(world.channel, "b" * 40, {fixed_at.commit_sha1}, 1)

    compute_landings(ancestry)

    landing = FixLanding.objects.get()
    assert (landing.commit, landing.advance) == (exact, first)
    assert world.events()[-1].data["via"] == "fix_commit"


def test_each_channel_of_the_branch(
    world: World,
    make_channel: Callable[..., NixChannel],
    make_branch: Callable[..., NixpkgsBranch],
) -> None:
    _, fixed_at = fixed(world)
    big = make_channel("nixos-unstable", release_branch=world.branch)
    other = make_channel("nixos-26.05", release_branch=make_branch("release-26.05"))
    ancestry = FakeAncestry()
    ancestry.advance(world.channel, "a" * 40, {fixed_at.commit_sha1}, 0)
    ancestry.advance(big, "b" * 40, set(), 0)
    ancestry.advance(other, "c" * 40, {fixed_at.commit_sha1}, 0)

    compute_landings(ancestry)
    assert set(FixLanding.objects.values_list("channel_id", flat=True)) == {
        world.channel.pk
    }

    ancestry.advance(big, "d" * 40, {fixed_at.commit_sha1}, 3)
    compute_landings(ancestry)
    assert set(FixLanding.objects.values_list("channel_id", flat=True)) == {
        world.channel.pk,
        big.pk,
    }


def test_dismissed_suggestions_are_skipped(world: World) -> None:
    _, fixed_at = fixed(world)
    CVEDerivationClusterProposal.objects.filter(pk=world.suggestion.pk).update(
        status=CVEDerivationClusterProposal.Status.REJECTED,
        rejection_reason=CVEDerivationClusterProposal.RejectionReason.NOT_IN_NIXPKGS,
    )
    ancestry = FakeAncestry()
    ancestry.advance(world.channel, "a" * 40, {fixed_at.commit_sha1}, 0)
    assert compute_landings(ancestry).landed == 0


def test_regression_retracts_landings_and_lands_again(world: World) -> None:
    row, fixed_at = fixed(world)
    Exposure.objects.filter(pk=row.pk).update(fix_commit="e" * 40)
    ancestry = FakeAncestry()
    ancestry.advance(world.channel, "a" * 40, {"e" * 40, fixed_at.commit_sha1}, 0)
    compute_landings(ancestry)

    world.apply(world.package("1.9"))

    row.refresh_from_db()
    assert row.fix_commit is None
    landing = FixLanding.objects.get()
    assert landing.retracted_at is not None
    data = world.events()[-1].data
    assert data["regression"] is True
    assert data["retracted_landings"] == [world.channel.pk]
    assert data["previous_fix_commit"] == "e" * 40

    refixed_at = world.package("2.1")
    world.apply(refixed_at)
    ancestry.advance(world.channel, "b" * 40, {refixed_at.commit_sha1}, 2)
    compute_landings(ancestry)
    live = FixLanding.objects.live().get()
    assert live.commit == refixed_at.commit_sha1
    assert FixLanding.objects.count() == 2


@pytest.mark.parametrize("n", [1, 2, 7, 16])
def test_first_containing_is_a_binary_search(n: int, channel: NixChannel) -> None:
    ancestry = FakeAncestry()
    advances = [
        ancestry.advance(channel, f"{i:040x}", {"f" * 40} if i == n - 1 else set(), i)
        for i in range(n + 3)
    ]
    counted = CachedAncestry(ancestry)
    assert first_containing(advances, "f" * 40, counted) == advances[n - 1]
    assert counted.queries <= max(1, (n + 3).bit_length())


def test_with_a_real_history_clone(world: World, tmp_path: Path) -> None:
    repo = LocalRepo(tmp_path / "nixpkgs")
    before = repo.commit("master", "foo: 1.5")
    repo.commit("nixos-small", "channel bump", base=before)
    fix = repo.commit("master", "foo: 1.5 -> 2.0")
    world.match()
    world.package("1.5")
    world.reconcile()
    fixed_at = world.package("2.0")
    NixEvaluation.objects.filter(pk=fixed_at.pk).update(commit_sha1=fix)
    world.apply(fixed_at)
    clone = HistoryClone(tmp_path / "history.git", repo.url, "tree:0")

    clone.fetch(["master", world.channel.channel_branch, "nixos-small"])
    ChannelAdvance.objects.create(
        channel=world.channel,
        commit=repo.git("rev-parse", "nixos-small"),
        observed_at=T0,
    )
    assert compute_landings(clone).pending == 1

    repo.set_branch("nixos-small", fix)
    clone.fetch(["nixos-small"])
    ChannelAdvance.objects.create(
        channel=world.channel, commit=fix, observed_at=T0 + timedelta(hours=1)
    )
    assert compute_landings(clone).landed == 1
    assert FixLanding.objects.get().landed_at == T0 + timedelta(hours=1)


def test_reclassification_has_no_landing(world: World, record: object) -> None:
    """A CVE update that moves the range past the version fixes nothing in git."""
    from shared.models.cve import Version

    world.match()
    world.package("1.5")
    world.reconcile()
    evaluation = world.branch.current_evaluation
    Version.objects.filter(affectedproduct__container=record).update(
        version="1.6", less_than="2.0"
    )
    world.reconcile(TrackerEvent.Cause.CVE_UPDATE)
    row = world.row()
    assert (row.observed, row.fixed_evaluation) == ("unaffected", evaluation)
    ancestry = FakeAncestry()
    ancestry.advance(world.channel, "a" * 40, {evaluation.commit_sha1}, 0)

    result = compute_landings(ancestry)

    assert (result.landed, result.pending) == (0, 0)
    # An exact fix commit is a change whatever the cause of the observation.
    Exposure.objects.filter(pk=row.pk).update(fix_commit=evaluation.commit_sha1)
    assert compute_landings(ancestry).landed == 1


def test_hidden_matches_get_no_landing(world: World, settings: object) -> None:
    row, fixed_at = fixed(world)
    settings.MATCHING_SCORE_THRESHOLD = 1.0  # type: ignore[attr-defined]
    ancestry = FakeAncestry()
    ancestry.advance(world.channel, "a" * 40, {fixed_at.commit_sha1}, 0)
    assert compute_landings(ancestry).landed == 0
