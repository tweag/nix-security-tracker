"""
Bring open suggestions in line after `ProductMapping` rows were created, changed or deleted:
product key -> affected products -> CVEs -> open suggestions -> `reconcile_matches(cause=mapping)`.
"""

import logging
import uuid
from collections.abc import Iterable
from dataclasses import dataclass, field

from django.contrib.auth.models import User
from django.db.models import QuerySet

from shared.matching.base import Universe
from shared.matching.reconcile import ReconcileResult
from shared.matching.view import build_cve_views
from shared.models.linkage import CVEDerivationClusterProposal
from shared.models.matching import ProductMapping, TrackerEvent

logger = logging.getLogger(__name__)

Status = CVEDerivationClusterProposal.Status
OPEN_STATUSES = (Status.PENDING, Status.ACCEPTED)
# Above this many suggestions a mapping change is not reconciled in the request; the caller
# gets the suggestion ids back and hands them to `reconcile_product_keys` (management command).
SYNC_LIMIT = 200
# Matchers a `same` mapping can change: vetoes act on every matcher, `same` only feeds these.
MAPPED_MATCHERS = ("curated", "rules")
VIEW_BATCH = 200


@dataclass
class MappingReconcileResult:
    suggestions: int = 0
    reconciled: dict[int, ReconcileResult] = field(default_factory=dict)
    # Suggestions not reconciled because there were more than the synchronous limit.
    deferred: list[int] = field(default_factory=list)

    @property
    def events(self) -> int:
        return sum(r.events for r in self.reconciled.values())


def open_suggestions_for_keys(
    key_ids: Iterable[int],
) -> QuerySet[CVEDerivationClusterProposal]:
    """Pending and accepted suggestions whose CVE has an affected product with one of these keys."""
    return CVEDerivationClusterProposal.objects.filter(
        status__in=OPEN_STATUSES,
        cve__container__affected__product_keys__in=list(key_ids),
    ).distinct()


def matchers_for_relations(relations: Iterable[str]) -> list[str] | None:
    """The matchers a change of mappings with these relations can affect; None for all."""
    if all(r == ProductMapping.Relation.SAME for r in relations):
        return list(MAPPED_MATCHERS)
    return None


def reconcile_suggestions(
    suggestion_ids: list[int],
    matchers: list[str] | None = None,
    *,
    actor: User | None = None,
    cause: TrackerEvent.Cause = TrackerEvent.Cause.MAPPING,
) -> dict[int, ReconcileResult]:
    """
    Reconcile these suggestions with one universe and views built in batches, through the
    pipeline (`shared.pipeline.rematch`), so exposures, links, status and cache follow.
    """
    from shared.cache_suggestions import cache_new_suggestions
    from shared.pipeline import rematch

    universe = Universe.tracked()
    results: dict[int, ReconcileResult] = {}
    for start in range(0, len(suggestion_ids), VIEW_BATCH):
        suggestions = list(
            CVEDerivationClusterProposal.objects.filter(
                pk__in=suggestion_ids[start : start + VIEW_BATCH]
            )
            .select_related("cve")
            .order_by("pk")
        )
        views = build_cve_views({s.cve.cve_id for s in suggestions})
        for suggestion in suggestions:
            outcome = rematch(
                suggestion,
                cause,
                matchers,
                view=views.get(suggestion.cve.cve_id),
                universe=universe,
                actor=actor,
            )
            if not outcome.frozen:
                cache_new_suggestions(suggestion)
            results[suggestion.pk] = outcome.matches or ReconcileResult(
                batch=uuid.uuid4()
            )
    return results


def reconcile_for_product_keys(
    key_ids: Iterable[int],
    relations: Iterable[str] = (ProductMapping.Relation.NOT_SAME,),
    *,
    actor: User | None = None,
    sync_limit: int | None = SYNC_LIMIT,
) -> MappingReconcileResult:
    """
    Reconcile the open suggestions that mappings on these product keys bear on. `relations`
    are those of the mappings before and after the change and decide which matchers run.
    With more than `sync_limit` suggestions nothing is reconciled and their ids are returned
    in `deferred`; `sync_limit=None` reconciles any number.
    """
    ids = list(
        open_suggestions_for_keys(key_ids).order_by("pk").values_list("pk", flat=True)
    )
    outcome = MappingReconcileResult(suggestions=len(ids))
    if sync_limit is not None and len(ids) > sync_limit:
        outcome.deferred = ids
        logger.info("Mapping change bears on %d open suggestions, deferred", len(ids))
        return outcome
    outcome.reconciled = reconcile_suggestions(
        ids, matchers_for_relations(relations), actor=actor
    )
    return outcome


def reconcile_mapping_change(
    *mappings: ProductMapping,
    actor: User | None = None,
    sync_limit: int | None = SYNC_LIMIT,
) -> MappingReconcileResult:
    """
    Call after writing mappings: pass the rows created, the rows as they were before and as
    they are after a change, and deleted instances (which keep their field values).
    """
    return reconcile_for_product_keys(
        {m.product_key_id for m in mappings},
        {m.relation for m in mappings},
        actor=actor,
        sync_limit=sync_limit,
    )
