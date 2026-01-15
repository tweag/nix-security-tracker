from collections.abc import Callable
from datetime import timedelta

from shared.listeners.automatic_linkage import build_new_links
from shared.models.cve import Container
from shared.models.linkage import (
    CVEDerivationClusterProposal,
)
from shared.models.nix_evaluation import (
    MAJOR_CHANNELS,
    NixChannel,
    NixDerivation,
    NixEvaluation,
)


def test_link_only_latest_eval(
    make_container: Callable[..., Container],
    make_channel: Callable[..., NixChannel],
    make_evaluation: Callable[..., NixEvaluation],
    make_drv: Callable[..., NixDerivation],
) -> None:
    """
    Check that only derivations from the latest complete evaluation of each channel are matched.
    """

    # FIXME(@fricklerhandwerk): This will fall apart when we obtain the channel structure dynamically [ref:channel-structure]
    release = MAJOR_CHANNELS[1]
    channels = [
        make_channel(
            release=release,
            branch=branch,
            state=NixChannel.ChannelState.UNSTABLE,
        )
        for branch in [
            f"nixos-${release}",
            f"nixos-${release}-small",
            f"nixpkgs-${release}-darwin",
        ]
    ]

    evaluations = []
    # We don't really need to test for `WAITING` since we don't expect derivations to exist for such an evaluation that hasn't started yet.
    # But for simplicity we simply iterate over all states.
    for state in NixEvaluation.EvaluationState.values:
        for channel in channels:
            for day in range(3):
                ev = make_evaluation(channel=channel, state=state)
                target_time = ev.created_at - timedelta(days=day)
                # Overwrite the timestamp without triggering the `save()` hook that would write the current time again
                NixEvaluation.objects.filter(pk=ev.pk).update(
                    created_at=target_time,
                    updated_at=target_time,
                )
                evaluations.append(ev)

    for i, ev in enumerate(evaluations):
        make_drv(
            evaluation=ev,
            pname="foobar",
            version=f"1.{i}",
        )

    container = make_container(package_name="foo", affected_version="<3.2")
    match = build_new_links(container)
    assert match
    suggestion = CVEDerivationClusterProposal.objects.first()
    assert suggestion
    states = suggestion.derivations.values_list("parent_evaluation__state", flat=True)
    assert set(states) == {NixEvaluation.EvaluationState.COMPLETED}
    assert suggestion.derivations.count() == len(channels)
    assert suggestion.derivations.count() < len(evaluations)
