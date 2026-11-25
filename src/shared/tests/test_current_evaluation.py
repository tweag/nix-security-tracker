from collections.abc import Callable
from datetime import timedelta
from io import StringIO

from django.core.management import call_command

from shared.pipeline import build_new_links
from shared.models.cve import Container
from shared.models.linkage import CVEDerivationClusterProposal
from shared.models.nix_evaluation import (
    NixChannel,
    NixDerivation,
    NixEvaluation,
    NixpkgsBranch,
)
from shared.snapshot import update_branch_snapshot


def finish_late(evaluation: NixEvaluation) -> None:
    """Complete an evaluation now, giving it the most recent `updated_at`."""
    evaluation.state = NixEvaluation.EvaluationState.COMPLETED
    evaluation.save()


def test_current_falls_back_to_latest_completed_without_pointer(
    make_evaluation: Callable[..., NixEvaluation],
) -> None:
    make_evaluation(age=timedelta(days=1))
    latest = make_evaluation()

    assert list(NixEvaluation.objects.current()) == [latest]


def test_current_follows_pointer_not_completion_time(
    make_evaluation: Callable[..., NixEvaluation],
    make_drv: Callable[..., NixDerivation],
) -> None:
    older = make_evaluation(
        state=NixEvaluation.EvaluationState.IN_PROGRESS, age=timedelta(days=1)
    )
    make_drv(evaluation=older)
    newer = make_evaluation()
    make_drv(evaluation=newer)
    update_branch_snapshot(newer)
    finish_late(older)
    update_branch_snapshot(older)

    assert list(NixEvaluation.objects.latest_completed_per_branch()) == [older]
    assert list(NixEvaluation.objects.current()) == [newer]


def test_current_excludes_untracked_branches(
    make_branch: Callable[..., NixpkgsBranch],
    make_channel: Callable[..., NixChannel],
    make_evaluation: Callable[..., NixEvaluation],
) -> None:
    eol = make_channel(
        channel_branch="nixos-20.03",
        release_branch=make_branch("release-20.03"),
        state=NixChannel.ChannelState.END_OF_LIFE,
    )
    tracked = make_evaluation()
    untracked = make_evaluation(channel=eol)
    update_branch_snapshot(untracked)

    assert list(NixEvaluation.objects.current()) == [tracked]


def test_matcher_uses_current_evaluation(
    make_container: Callable[..., Container],
    make_evaluation: Callable[..., NixEvaluation],
    make_drv: Callable[..., NixDerivation],
) -> None:
    older = make_evaluation(
        state=NixEvaluation.EvaluationState.IN_PROGRESS, age=timedelta(days=1)
    )
    make_drv(evaluation=older, pname="foobar", version="1.0")
    newer = make_evaluation()
    make_drv(evaluation=newer, pname="foobar", version="2.0")
    update_branch_snapshot(newer)
    finish_late(older)

    assert build_new_links(make_container(package_name="foobar"))

    suggestion = CVEDerivationClusterProposal.objects.get()
    assert list(suggestion.derivations.values_list("name", flat=True)) == ["foobar-2.0"]


def test_garbage_collect_keeps_current_and_newer_evaluations(
    make_evaluation: Callable[..., NixEvaluation],
    make_drv: Callable[..., NixDerivation],
) -> None:
    stale = make_evaluation(age=timedelta(days=3))
    make_drv(evaluation=stale)
    current = make_evaluation(age=timedelta(days=2))
    make_drv(evaluation=current)
    update_branch_snapshot(current)
    # Completed, but its snapshot has not run yet.
    pending = make_evaluation(age=timedelta(days=1))
    make_drv(evaluation=pending)
    # An older evaluation that finished last, as consumers saw before the pointer existed.
    late = make_evaluation(
        state=NixEvaluation.EvaluationState.IN_PROGRESS, age=timedelta(days=4)
    )
    make_drv(evaluation=late)
    finish_late(late)

    call_command("garbage_collect", stdout=StringIO())

    remaining = set(NixDerivation.objects.values_list("parent_evaluation", flat=True))
    assert remaining == {current.pk, pending.pk, late.pk}
