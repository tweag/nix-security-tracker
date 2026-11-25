import logging

import pgpubsub

from shared.cache_suggestions import cache_new_suggestions
from shared.channels import CvePresentationChannel, CveUpdateChannel
from shared.locking import lock_for_write
from shared.models.cve import CveRecord
from shared.models.linkage import CVEDerivationClusterProposal
from shared.pipeline import on_cve_record_changed

logger = logging.getLogger(__name__)


@pgpubsub.listener(CveUpdateChannel)
def rematch_after_cve_update(pk: int) -> None:
    """Re-match the CVE's suggestion on the updated record, or create it if there is none."""
    if not CveRecord.objects.filter(pk=pk).exists():
        logger.info("CVE record %d is gone, skipping", pk)
        return
    on_cve_record_changed(pk)


@pgpubsub.listener(CvePresentationChannel)
def recache_after_cve_update(pk: int) -> None:
    """Rebuild the cached payloads of the CVE's suggestions: only displayed fields changed."""
    cve_id = CveRecord.objects.filter(pk=pk).values_list("cve_id", flat=True).first()
    if cve_id is None:
        return
    suggestions = list(
        CVEDerivationClusterProposal.objects.filter(cve__cve_id=cve_id).order_by("pk")
    )
    lock_for_write([s.pk for s in suggestions])
    for suggestion in suggestions:
        cache_new_suggestions(suggestion)
