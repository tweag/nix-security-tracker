import logging

import pgpubsub

from shared.channels import NixEvaluationSnapshotChannel
from shared.models import NixEvaluation
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
