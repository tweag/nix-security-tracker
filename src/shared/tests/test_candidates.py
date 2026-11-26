"""
One candidate definition (`shared.candidates`) for the projection, exposures and the derived
state; exposures of untracked branches say nothing (review finding 6).
"""

from collections.abc import Callable

from shared.derived_state import derive_states, possibly_fixed_keys
from shared.models.cve import Container
from shared.models.linkage import CVEDerivationClusterProposal
from shared.models.matching import Exposure, Match, SuggestionDerivedState
from shared.models.nix_evaluation import NixChannel, NixDerivation, NixEvaluation
from shared.pipeline import build_new_links
from shared.snapshot import update_branch_snapshot
from shared.tests.conftest import run_snapshot_step

Status = CVEDerivationClusterProposal.Status


def test_hidden_match_is_no_candidate(
    make_container: Callable[..., Container],
    make_evaluation: Callable[..., NixEvaluation],
    make_drv: Callable[..., NixDerivation],
) -> None:
    """Substring only: recorded as a match, not shown, not kept current, not triaged."""
    evaluation = make_evaluation()
    make_drv(attribute="teslajsonpy", pname="teslajsonpy", evaluation=evaluation)
    update_branch_snapshot(evaluation)
    assert build_new_links(make_container(package_name="tesla", product=None))
    suggestion = CVEDerivationClusterProposal.objects.get()
    assert suggestion.status == Status.REJECTED
    assert Match.objects.active().filter(attrpath="teslajsonpy").exists()
    assert not Exposure.objects.exists()
    assert derive_states([suggestion.pk])[suggestion.pk].state == "no_candidates"
    assert SuggestionDerivedState.objects.get(suggestion=suggestion).state == (
        "no_candidates"
    )


def test_hidden_match_never_enters_the_possibly_fixed_queue(
    make_container: Callable[..., Container],
    make_evaluation: Callable[..., NixEvaluation],
    make_drv: Callable[..., NixDerivation],
) -> None:
    first = make_evaluation()
    make_drv(attribute="teslajsonpy", pname="teslajsonpy", evaluation=first)
    update_branch_snapshot(first)
    assert build_new_links(
        make_container(package_name="tesla", product=None, affected_version="1.0")
    )
    second = make_evaluation()
    make_drv(
        attribute="teslajsonpy", pname="teslajsonpy", version="2.0", evaluation=second
    )
    update_branch_snapshot(second)
    run_snapshot_step(second)
    assert not possibly_fixed_keys()


def test_end_of_life_branch_stops_counting(
    make_container: Callable[..., Container],
    make_evaluation: Callable[..., NixEvaluation],
    make_drv: Callable[..., NixDerivation],
    channel: NixChannel,
) -> None:
    evaluation = make_evaluation()
    make_drv(attribute="foo", pname="foo", evaluation=evaluation)
    update_branch_snapshot(evaluation)
    assert build_new_links(make_container(package_name="foo", product=None))
    suggestion = CVEDerivationClusterProposal.objects.get()
    assert Exposure.objects.filter(observed="affected").exists()
    assert SuggestionDerivedState.objects.get(suggestion=suggestion).state == (
        "needs_triage"
    )

    # The channel goes end of life (as `fetch_all_channels` writes it).
    NixChannel.objects.filter(pk=channel.pk).update(
        state=NixChannel.ChannelState.END_OF_LIFE
    )
    assert derive_states([suggestion.pk])[suggestion.pk].state != "needs_triage"
    stored = SuggestionDerivedState.objects.get(suggestion=suggestion)
    assert stored.stale  # the channel trigger marked it; `fetch_all_channels` flushes

    from shared.derived_state import flush_derived_states

    flush_derived_states()
    stored.refresh_from_db()
    assert stored.state == derive_states([suggestion.pk])[suggestion.pk].state
