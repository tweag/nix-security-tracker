from collections.abc import Callable
from datetime import UTC, datetime, timedelta

import pytest
from django.db import connection
from django.test.utils import CaptureQueriesContext

from shared.derived_state import set_verdict
from shared.models.issue import (
    ISSUE_COMPLETED,
    ISSUE_OPENED,
    PULL_REQUEST_OPENED,
    GitHubItem,
    NixpkgsIssue,
)
from shared.models.linkage import CVEDerivationClusterProposal
from shared.models.matching import Exposure, Match, TrackerEvent, Verdict
from shared.models.nix_evaluation import NixChannel, NixEvaluation, NixpkgsBranch
from shared.models.remediation import ChannelAdvance, FixLanding, FixLink
from shared.timeline import CveTimeline, Stage, build_timeline, build_timelines

Observed = Exposure.Observed
T0 = datetime(2026, 10, 1, tzinfo=UTC)


class Life:
    """A suggestion on `foo`, tracked on master (one channel) and release-26.05 (one channel)."""

    def __init__(
        self,
        suggestion: CVEDerivationClusterProposal,
        make_branch: Callable[..., NixpkgsBranch],
        make_channel: Callable[..., NixChannel],
        make_evaluation: Callable[..., NixEvaluation],
        make_exposure: Callable[..., Exposure],
        make_match: Callable[..., Match],
    ) -> None:
        self.suggestion = suggestion
        self.master = make_branch("master")
        self.release = make_branch("release-26.05")
        self.master_channel = make_channel("nixos-unstable", release_branch=self.master)
        self.release_channel = make_channel(
            "nixos-26.05",
            release_branch=self.release,
            state=NixChannel.ChannelState.STABLE,
        )
        self.before = make_evaluation(age=timedelta(days=5))
        self.fixed_at = make_evaluation(age=timedelta(days=2))
        # Only the two channels above: drop the default one `make_evaluation` came with.
        NixChannel.objects.exclude(
            channel_branch__in=["nixos-unstable", "nixos-26.05"]
        ).delete()
        make_match("foo", suggestion=suggestion)
        self.exposures = {
            branch.name: make_exposure(
                suggestion=suggestion,
                branch=branch,
                evaluation=self.before,
                first_affected_evaluation=self.before,
                last_affected_evaluation=self.before,
            )
            for branch in (self.master, self.release)
        }

    def timeline(self) -> CveTimeline:
        return build_timeline(self.suggestion)

    def fix(self, branch: str) -> Exposure:
        e = self.exposures[branch]
        Exposure.objects.filter(pk=e.pk).update(
            observed=Observed.UNAFFECTED, version="2.0", fixed_evaluation=self.fixed_at
        )
        e.refresh_from_db()
        return e

    def land(self, branch: str, channel: NixChannel, at: datetime) -> None:
        advance = ChannelAdvance.objects.create(
            channel=channel, commit=self.fixed_at.commit_sha1, observed_at=at
        )
        FixLanding.objects.create(
            exposure=self.exposures[branch],
            channel=channel,
            advance=advance,
            commit=self.fixed_at.commit_sha1,
            landed_at=at,
        )


@pytest.fixture
def life(
    suggestion: CVEDerivationClusterProposal,
    make_branch: Callable[..., NixpkgsBranch],
    make_channel: Callable[..., NixChannel],
    make_evaluation: Callable[..., NixEvaluation],
    make_exposure: Callable[..., Exposure],
    make_match: Callable[..., Match],
) -> Life:
    return Life(
        suggestion,
        make_branch,
        make_channel,
        make_evaluation,
        make_exposure,
        make_match,
    )


def publish(life: Life) -> GitHubItem:
    issue = NixpkgsIssue.create_nixpkgs_issue([life.suggestion], "foo")
    item = GitHubItem.objects.create(
        owner="NixOS", repository="nixpkgs", number=1, kind=GitHubItem.Kind.ISSUE
    )
    item.nixpkgs_issues.add(issue)
    item.events.create(event_type=ISSUE_OPENED, occurred_at=T0)
    return item


def test_lifecycle_through_every_stage(life: Life) -> None:
    t = life.timeline()
    assert t.stage == Stage.MATCHED
    assert t.matched_at is not None and t.cve_id == life.suggestion.cve.cve_id

    set_verdict(life.suggestion, "foo", Verdict.Kind.AFFECTED, None)
    t = life.timeline()
    assert t.stage == Stage.TRIAGED and t.triaged_at is not None

    publish(life)
    t = life.timeline()
    assert (t.stage, t.reported_at) == (Stage.REPORTED, T0)

    pr = GitHubItem.objects.create(
        owner="NixOS",
        repository="nixpkgs",
        number=2,
        kind=GitHubItem.Kind.PULL_REQUEST,
        base_ref="master",
    )
    pr.events.create(event_type=PULL_REQUEST_OPENED, occurred_at=T0 + timedelta(days=1))
    FixLink.objects.create(
        suggestion=life.suggestion,
        item=pr,
        source=FixLink.Source.CLOSING_REFERENCE,
        branch=life.master,
    )
    t = life.timeline()
    assert (t.stage, t.first_fix_pr_at) == (Stage.FIX_PROPOSED, T0 + timedelta(days=1))

    # The affected verdict is for all branches; the fix on master needs a branch verdict
    # to override it, as a human (or the tracker) confirming the fix would write.
    set_verdict(life.suggestion, "foo", Verdict.Kind.FIXED, None, branch=life.master)
    life.fix("master")
    t = life.timeline()
    assert t.stage == Stage.FIXED_TRACKING_BRANCH
    assert t.backport_required == [("foo", "release-26.05")]
    assert t.fixed_tracking_at is not None

    set_verdict(life.suggestion, "foo", Verdict.Kind.FIXED, None, branch=life.release)
    t = life.timeline()
    assert t.stage == Stage.FIX_BACKPORTED
    assert t.backport_required == [] and t.fixed_all_branches_at is not None


def observed_only(life: Life) -> None:
    """Fixed by observation on both branches, without verdicts; published."""
    publish(life)
    life.fix("master")
    life.fix("release-26.05")


def test_backport_requirement_and_channels(life: Life) -> None:
    publish(life)
    life.fix("master")
    t = life.timeline()
    assert t.stage == Stage.FIXED_TRACKING_BRANCH
    assert t.backport_required == [("foo", "release-26.05")]
    assert t.missing_landings == [("foo", "master", "nixos-unstable")]

    life.fix("release-26.05")
    t = life.timeline()
    assert t.stage == Stage.FIX_BACKPORTED
    assert set(t.missing_landings) == {
        ("foo", "master", "nixos-unstable"),
        ("foo", "release-26.05", "nixos-26.05"),
    }

    life.land("master", life.master_channel, T0 + timedelta(days=3))
    life.land("release-26.05", life.release_channel, T0 + timedelta(days=6))
    t = life.timeline()
    assert (t.stage, t.in_all_channels_at) == (
        Stage.IN_ALL_CHANNELS,
        T0 + timedelta(days=6),
    )

    item = GitHubItem.objects.get(number=1)
    item.events.create(event_type=ISSUE_COMPLETED, occurred_at=T0 + timedelta(days=7))
    t = life.timeline()
    assert (t.stage, t.closed_at) == (Stage.CLOSED, T0 + timedelta(days=7))


def test_unpublished_observed_fix_needs_confirmation(life: Life) -> None:
    life.fix("master")
    life.fix("release-26.05")
    assert life.timeline().stage == Stage.MATCHED
    set_verdict(life.suggestion, "foo", Verdict.Kind.FIXED, None, branch=life.master)
    assert life.timeline().stage == Stage.FIX_BACKPORTED


def test_regression_goes_back(life: Life) -> None:
    observed_only(life)
    assert life.timeline().stage == Stage.FIX_BACKPORTED
    e = life.exposures["master"]
    Exposure.objects.filter(pk=e.pk).update(
        observed=Observed.AFFECTED, fixed_evaluation=None
    )
    TrackerEvent.objects.create(
        suggestion=life.suggestion,
        kind=TrackerEvent.Kind.EXPOSURE_BECAME_AFFECTED,
        attrpath="foo",
        branch=life.master,
        cause=TrackerEvent.Cause.EVALUATION,
        data={"regression": True},
        batch="00000000-0000-0000-0000-000000000000",
    )
    t = life.timeline()
    assert t.stage == Stage.REPORTED
    assert t.regressed


def test_dismissed_and_no_candidates(
    life: Life, make_suggestion: Callable[..., CVEDerivationClusterProposal]
) -> None:
    CVEDerivationClusterProposal.objects.filter(pk=life.suggestion.pk).update(
        status=CVEDerivationClusterProposal.Status.REJECTED,
        rejection_reason=CVEDerivationClusterProposal.RejectionReason.NOT_IN_NIXPKGS,
    )
    assert life.timeline().stage == Stage.DISMISSED
    assert build_timeline(make_suggestion()).stage == Stage.NO_CANDIDATES


def test_batch_costs_a_fixed_number_of_queries(
    life: Life, make_suggestion: Callable[..., CVEDerivationClusterProposal]
) -> None:
    observed_only(life)
    ids = [life.suggestion.pk]
    with CaptureQueriesContext(connection) as one:
        build_timelines(ids)
    ids += [make_suggestion().pk for _ in range(5)]
    with CaptureQueriesContext(connection) as many:
        timelines = build_timelines(ids)
    assert len(timelines) == 6
    assert len(many) <= len(one) + 2


def test_reclassification_needs_no_landing(life: Life) -> None:
    publish(life)
    for branch in ("master", "release-26.05"):
        e = life.fix(branch)
        TrackerEvent.objects.create(
            suggestion=life.suggestion,
            kind=TrackerEvent.Kind.EXPOSURE_BECAME_UNAFFECTED,
            attrpath="foo",
            branch_id=branch,
            cause=TrackerEvent.Cause.CVE_UPDATE
            if branch == "release-26.05"
            else TrackerEvent.Cause.EVALUATION,
            evaluation=e.fixed_evaluation,
            data={
                "old_version": "2.0" if branch == "release-26.05" else "1.0",
                "new_version": "2.0",
            },
            batch="00000000-0000-0000-0000-000000000000",
        )
    t = life.timeline()
    assert t.missing_landings == [("foo", "master", "nixos-unstable")]
