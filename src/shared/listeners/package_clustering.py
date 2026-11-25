import logging

import pgpubsub

from shared.cache_suggestions import cache_new_suggestions
from shared.channels import (
    NixEvaluationUpdateChannel,
    SuggestionRefreshChannel,
    SuggestionRematchChannel,
)
from shared.exposure import dismissed_q
from shared.locking import lock_for_write
from shared.models import NixDerivation, NixEvaluation
from shared.models.linkage import CVEDerivationClusterProposal
from shared.models.matching import TrackerEvent
from shared.package_clustering import cluster_packages
from shared.pipeline import refresh_suggestion, rematch
from shared.snapshot import fill_package_groups

logger = logging.getLogger(__name__)


@pgpubsub.post_update_listener(NixEvaluationUpdateChannel)
def cluster_after_evaluation(old: NixEvaluation, new: NixEvaluation) -> None:
    """
    Group the evaluation's attributes into packages, for display only. Re-matching after an
    evaluation is driven by the branch snapshot (`shared.listeners.snapshot`), not by this.
    """
    if old.state == new.state:
        return
    if new.state != NixEvaluation.EvaluationState.COMPLETED:
        return
    logger.info("Clustering derivations from evaluation %s", new)
    result = cluster_packages(
        NixDerivation.objects.filter(parent_evaluation_id=new.pk),
        update_packages=new.is_on_tracking_branch,
    )
    logger.info(
        f"Done. Clustered {result.derivations_processed} derivations: "
        f"updated {result.packages_updated}, created {result.packages_created} packages, "
        f"updated {result.attrpaths_updated}, created {result.attrpaths_created} attrpaths."
    )
    # The snapshot may have run first, before the new attributes had a package.
    fill_package_groups(list(new.on_branches.all()))


@pgpubsub.listener(SuggestionRefreshChannel)
def refresh_and_cache_suggestion(pk: int) -> None:
    """
    Re-run the suggestion's stale matchers (if any), bring its links to the current
    evaluations, and rebuild its cache. Dispatched at deploy for stale matchers and after
    each evaluation for suggestions whose exposures changed or whose links point at an older
    one. Published suggestions only get their cache rebuilt (their links are frozen, their
    exposure status is shown); dismissed ones nothing.
    """
    lock_for_write([pk])
    suggestion = (
        CVEDerivationClusterProposal.objects.select_for_update()
        .exclude(dismissed_q())
        .filter(pk=pk)
        .first()
    )
    if suggestion is None:
        # We don't want to try again! If we crash here, the work is put back on the queue.
        logger.info("Suggestion %d is dismissed or gone, skipping refresh", pk)
        return
    if suggestion.status == CVEDerivationClusterProposal.Status.PUBLISHED:
        cache_new_suggestions(suggestion)
        return
    refresh_suggestion(suggestion)


@pgpubsub.listener(SuggestionRematchChannel)
def rematch_after_evaluation(pk: int, evaluation_pk: int) -> None:
    """Re-match with every enabled matcher after an evaluation changed what it may match."""
    lock_for_write([pk])
    suggestion = CVEDerivationClusterProposal.objects.filter(pk=pk).first()
    evaluation = NixEvaluation.objects.filter(pk=evaluation_pk).first()
    if suggestion is None:
        return
    rematch(suggestion, TrackerEvent.Cause.EVALUATION, evaluation=evaluation)
