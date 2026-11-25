"""
After an evaluation, the branch snapshot drives re-matching: `apply_snapshot_changes` updates
exposures and matches, projects and caches what it touched, and fans out the remaining open
suggestions whose links point at an older evaluation (`SuggestionRefreshChannel`).
"""

from collections.abc import Callable
from unittest import mock

import pytest
from django.db import transaction

from shared.cache_suggestions import cache_new_suggestions
from shared.listeners.package_clustering import (
    cluster_after_evaluation,
    refresh_and_cache_suggestion,
)
from shared.listeners.snapshot import apply_snapshot_changes
from shared.models.cached import CachedSuggestions
from shared.models.cve import Container
from shared.models.linkage import (
    CVEDerivationClusterProposal,
    DerivationClusterProposalLink,
    ProvenanceFlags,
)
from shared.models.nix_evaluation import NixDerivation, NixEvaluation
from shared.snapshot import update_branch_snapshot


@pytest.fixture
def mock_snapshot_trigger() -> Callable[..., list[int]]:
    """Snapshot the evaluation, run the snapshot listener, capture the fanned-out refreshes."""

    def run(evaluation: NixEvaluation) -> list[int]:
        update_branch_snapshot(evaluation)
        with mock.patch("shared.pipeline.pgpubsub.notify") as mock_notify:
            with transaction.atomic():
                for branch in evaluation.on_branches.all():
                    apply_snapshot_changes(
                        evaluation_pk=evaluation.pk, branch=branch.name
                    )
        return [call.kwargs["pk"] for call in mock_notify.call_args_list]

    return run


@pytest.fixture
def snapshot_and_process_refreshes(
    mock_snapshot_trigger: Callable[..., list[int]],
) -> Callable[..., None]:
    """Recreates how the notifications following a snapshot are processed."""

    def run(evaluation: NixEvaluation) -> None:
        for pk in mock_snapshot_trigger(evaluation):
            with transaction.atomic():
                refresh_and_cache_suggestion(pk=pk)

    return run


def _two_evaluations(
    make_evaluation: Callable[..., NixEvaluation],
    make_drv: Callable[..., NixDerivation],
    pname: str = "foo",
) -> tuple[NixDerivation, NixDerivation, NixEvaluation]:
    old_eval = make_evaluation()
    old_drv = make_drv(pname=pname, evaluation=old_eval)
    update_branch_snapshot(old_eval)
    new_eval = make_evaluation()
    new_drv = make_drv(pname=pname, evaluation=new_eval, attribute=old_drv.attribute)
    return old_drv, new_drv, new_eval


@pytest.mark.django_db(transaction=True)
def test_cache_rebuilt_after_snapshot(
    cve: Container,
    make_evaluation: Callable[..., NixEvaluation],
    make_drv: Callable[..., NixDerivation],
    make_suggestion: Callable[..., CVEDerivationClusterProposal],
    snapshot_and_process_refreshes: Callable[..., None],
) -> None:
    old_drv, new_drv, new_eval = _two_evaluations(make_evaluation, make_drv)
    suggestion = make_suggestion(
        container=cve, drvs={old_drv: ProvenanceFlags.PACKAGE_NAME_MATCH}
    )
    cache_new_suggestions(suggestion)
    cached_before = CachedSuggestions.objects.get(proposal=suggestion)

    snapshot_and_process_refreshes(new_eval)

    cached_after = CachedSuggestions.objects.get(proposal=suggestion)
    assert cached_after.updated_at > cached_before.updated_at
    assert suggestion.derivations.get() == new_drv


@pytest.mark.django_db(transaction=True)
@pytest.mark.parametrize(
    "status",
    [
        CVEDerivationClusterProposal.Status.REJECTED,
        CVEDerivationClusterProposal.Status.PUBLISHED,
    ],
)
def test_frozen_suggestions_keep_their_links(
    status: CVEDerivationClusterProposal.Status,
    cve: Container,
    make_evaluation: Callable[..., NixEvaluation],
    make_drv: Callable[..., NixDerivation],
    make_suggestion: Callable[..., CVEDerivationClusterProposal],
    snapshot_and_process_refreshes: Callable[..., None],
) -> None:
    """Human-rejected and published suggestions are not refreshed."""
    old_drv, _, new_eval = _two_evaluations(make_evaluation, make_drv)
    suggestion = make_suggestion(
        container=cve,
        drvs={old_drv: ProvenanceFlags.PACKAGE_NAME_MATCH},
        status=status,
        comment="human decision",
    )

    snapshot_and_process_refreshes(new_eval)

    link = DerivationClusterProposalLink.objects.get(proposal=suggestion)
    assert link.derivation == old_drv


@pytest.mark.django_db(transaction=True)
def test_multiple_suggestions_all_refreshed(
    make_container: Callable[..., Container],
    make_evaluation: Callable[..., NixEvaluation],
    make_drv: Callable[..., NixDerivation],
    make_suggestion: Callable[..., CVEDerivationClusterProposal],
    snapshot_and_process_refreshes: Callable[..., None],
) -> None:
    old_eval = make_evaluation()
    new_eval = make_evaluation()
    test_data = []
    old_drvs = []
    for i in range(3):
        old_drvs.append(make_drv(pname=f"foo{i}", evaluation=old_eval))
    update_branch_snapshot(old_eval)
    for i, old_drv in enumerate(old_drvs):
        container = make_container(cve_id=f"CVE-2025-100{i}", package_name=f"foo{i}")
        new_drv = make_drv(
            pname=f"foo{i}", evaluation=new_eval, attribute=old_drv.attribute
        )
        suggestion = make_suggestion(
            container=container, drvs={old_drv: ProvenanceFlags.PACKAGE_NAME_MATCH}
        )
        cache_new_suggestions(suggestion)
        test_data.append((CachedSuggestions.objects.get(proposal=suggestion), new_drv))

    snapshot_and_process_refreshes(new_eval)

    for cached_before, new_drv in test_data:
        cached_after = CachedSuggestions.objects.get(proposal=cached_before.proposal)
        assert cached_after.updated_at > cached_before.updated_at
        assert cached_after.proposal.derivations.get() == new_drv


@pytest.mark.django_db(transaction=True)
def test_suggestion_refresh_failure_does_not_block_others(
    make_container: Callable[..., Container],
    make_evaluation: Callable[..., NixEvaluation],
    make_drv: Callable[..., NixDerivation],
    make_suggestion: Callable[..., CVEDerivationClusterProposal],
    mock_snapshot_trigger: Callable[..., list[int]],
) -> None:
    """Each fanned-out suggestion is processed independently."""
    old_eval = make_evaluation()
    new_eval = make_evaluation()
    old_drvs = {}
    new_drvs = {}
    suggestions = []
    for i in range(3):
        old_drv = make_drv(pname=f"foo{i}", evaluation=old_eval)
        new_drv = make_drv(
            pname=f"foo{i}", evaluation=new_eval, attribute=old_drv.attribute
        )
        container = make_container(cve_id=f"CVE-2025-300{i}", package_name=f"foo{i}")
        suggestion = make_suggestion(
            container=container, drvs={old_drv: ProvenanceFlags.PACKAGE_NAME_MATCH}
        )
        cache_new_suggestions(suggestion)
        suggestions.append(suggestion)
        old_drvs[suggestion.pk] = old_drv
        new_drvs[suggestion.pk] = new_drv
    update_branch_snapshot(old_eval)
    failing_pk = suggestions[0].pk

    from shared.pipeline import refresh_suggestion

    def maybe_fail(suggestion: CVEDerivationClusterProposal) -> None:
        if suggestion.pk == failing_pk:
            raise RuntimeError("simulated failure")
        refresh_suggestion(suggestion)

    pks = mock_snapshot_trigger(new_eval)
    assert set(pks) == {s.pk for s in suggestions}

    with mock.patch(
        "shared.listeners.package_clustering.refresh_suggestion", new=maybe_fail
    ):
        for pk in pks:
            with transaction.atomic():
                if pk == failing_pk:
                    with pytest.raises(RuntimeError, match="simulated failure"):
                        refresh_and_cache_suggestion(pk=pk)
                else:
                    refresh_and_cache_suggestion(pk=pk)

    for suggestion in suggestions:
        expected = new_drvs if suggestion.pk != failing_pk else old_drvs
        assert suggestion.derivations.get() == expected[suggestion.pk]


@pytest.mark.django_db(transaction=True)
def test_refresh_skips_suggestion_published_meanwhile(
    make_evaluation: Callable[..., NixEvaluation],
    make_drv: Callable[..., NixDerivation],
    make_suggestion: Callable[..., CVEDerivationClusterProposal],
    mock_snapshot_trigger: Callable[..., list[int]],
) -> None:
    """A suggestion published between dispatch and processing keeps its links and status."""
    old_drv, _, new_eval = _two_evaluations(make_evaluation, make_drv)
    suggestion = make_suggestion(drvs={old_drv: ProvenanceFlags.PACKAGE_NAME_MATCH})

    pks = mock_snapshot_trigger(new_eval)
    assert pks == [suggestion.pk]

    suggestion.status = CVEDerivationClusterProposal.Status.ACCEPTED
    suggestion.save(update_fields=["status"])
    suggestion.status = CVEDerivationClusterProposal.Status.PUBLISHED
    suggestion.save(update_fields=["status"])

    for pk in pks:
        with transaction.atomic():
            refresh_and_cache_suggestion(pk=pk)

    suggestion.refresh_from_db()
    assert suggestion.status == CVEDerivationClusterProposal.Status.PUBLISHED
    assert DerivationClusterProposalLink.objects.get(
        proposal=suggestion
    ).derivation == (old_drv)


@pytest.mark.django_db(transaction=True)
def test_refresh_never_rejects(
    make_evaluation: Callable[..., NixEvaluation],
    make_drv: Callable[..., NixDerivation],
    make_suggestion: Callable[..., CVEDerivationClusterProposal],
    snapshot_and_process_refreshes: Callable[..., None],
) -> None:
    """The matched package is gone from the new evaluation: still pending, links kept (F4)."""
    old_eval = make_evaluation()
    old_drv = make_drv(evaluation=old_eval)
    make_drv(pname="other", evaluation=old_eval)
    update_branch_snapshot(old_eval)
    new_eval = make_evaluation()
    make_drv(pname="other", evaluation=new_eval)
    suggestion = make_suggestion(drvs={old_drv: ProvenanceFlags.PACKAGE_NAME_MATCH})

    snapshot_and_process_refreshes(new_eval)

    suggestion.refresh_from_db()
    assert suggestion.status == CVEDerivationClusterProposal.Status.PENDING
    assert suggestion.derivations.get() == old_drv


@pytest.mark.django_db(transaction=True)
def test_refresh_not_dispatched_when_transaction_rolls_back(
    cve: Container,
    make_evaluation: Callable[..., NixEvaluation],
    make_drv: Callable[..., NixDerivation],
    make_suggestion: Callable[..., CVEDerivationClusterProposal],
) -> None:
    old_drv, _, new_eval = _two_evaluations(make_evaluation, make_drv)
    make_suggestion(container=cve, drvs={old_drv: ProvenanceFlags.PACKAGE_NAME_MATCH})
    update_branch_snapshot(new_eval)

    from pgpubsub.models import Notification

    from shared.channels import SuggestionRefreshChannel

    def refreshes() -> int:
        return Notification.objects.filter(
            channel=SuggestionRefreshChannel.listen_safe_name()
        ).count()

    with pytest.raises(RuntimeError), transaction.atomic():
        apply_snapshot_changes(evaluation_pk=new_eval.pk, branch="master")
        assert refreshes() == 1  # written in the transaction, not after commit
        raise RuntimeError("simulate a later failure in the same pgpubsub transaction")

    assert refreshes() == 0


@pytest.mark.django_db(transaction=True)
def test_clustering_no_longer_schedules_refreshes(
    make_evaluation: Callable[..., NixEvaluation],
    make_drv: Callable[..., NixDerivation],
    make_suggestion: Callable[..., CVEDerivationClusterProposal],
) -> None:
    """Package clustering is display grouping only; re-matching does not depend on it."""
    old_drv, _, new_eval = _two_evaluations(make_evaluation, make_drv)
    make_suggestion(drvs={old_drv: ProvenanceFlags.PACKAGE_NAME_MATCH})

    with mock.patch("pgpubsub.notify") as mock_notify, transaction.atomic():
        cluster_after_evaluation(
            old=NixEvaluation(state=NixEvaluation.EvaluationState.IN_PROGRESS),
            new=new_eval,
        )
    mock_notify.assert_not_called()
