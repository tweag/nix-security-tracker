import logging

import pgpubsub

from shared.channels import (
    BranchSnapshotChannel,
    NixEvaluationSnapshotChannel,
    PatchDetectionChannel,
    SuggestionRefreshChannel,
)
from shared.exposure import detect_patches
from shared.models import NixEvaluation
from shared.models.nix_evaluation import NixpkgsBranch
from shared.pipeline import apply_evaluation
from shared.snapshot import update_branch_snapshot

logger = logging.getLogger(__name__)


@pgpubsub.post_update_listener(NixEvaluationSnapshotChannel)
def snapshot_after_evaluation(old: NixEvaluation, new: NixEvaluation) -> None:
    if old.state == new.state:
        return
    if new.state != NixEvaluation.EvaluationState.COMPLETED:
        return
    logger.info("Updating branch snapshots from evaluation %s", new)
    update_branch_snapshot(new)


@pgpubsub.listener(BranchSnapshotChannel)
def apply_snapshot_changes(evaluation_pk: int, branch: str) -> None:
    """Exposures, matches, links and caches after a branch's snapshot advanced."""
    evaluation = NixEvaluation.objects.get(pk=evaluation_pk)
    apply_evaluation(evaluation, NixpkgsBranch.objects.get(name=branch))


@pgpubsub.listener(PatchDetectionChannel)
def detect_patches_after_snapshot(evaluation_pk: int, branch: str) -> None:
    """Patch fix candidates of an evaluation step; refresh links and caches of those it wrote."""
    evaluation = NixEvaluation.objects.get(pk=evaluation_pk)
    result = detect_patches(evaluation, NixpkgsBranch.objects.get(name=branch))
    for pk in sorted(result.touched):
        pgpubsub.notify(SuggestionRefreshChannel, pk=pk)
