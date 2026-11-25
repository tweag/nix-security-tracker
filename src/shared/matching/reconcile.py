"""
Run matchers on a CVE and keep a suggestion's `Match` rows current by diffing:
insert, update, retract, restore; never delete, never touch `Verdict`.
"""

import logging
import uuid
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any

from django.contrib.auth.models import User
from django.db import transaction
from django.utils import timezone

from shared.matching.base import Candidate, Universe
from shared.matching.matchers import collect_candidates, matchers_for
from shared.matching.view import CveView, build_cve_view
from shared.models.linkage import CVEDerivationClusterProposal
from shared.models.matching import Match, TrackerEvent
from shared.models.nix_evaluation import NixEvaluation

logger = logging.getLogger(__name__)

__all__ = ["collect_candidates", "reconcile_matches"]

# Active rows were by definition seen by the latest run; `last_seen_at` of an otherwise
# unchanged row is only refreshed when it is older than this, to avoid a row write per
# match per suggestion per run.
LAST_SEEN_RESOLUTION = timedelta(days=7)
# A score change smaller than this is not worth an event (the row is still updated).
SCORE_EPSILON = 0.01
# Evidence keys whose change alone is not worth an event: where else the attribute was
# found, and the primary key of the affected product row (re-ingestion renumbers it).
IMMATERIAL_EVIDENCE_KEYS = frozenset({"branches", "other_hits", "affected_product"})


@dataclass
class ReconcileResult:
    batch: uuid.UUID
    added: list[tuple[str, str]] = field(default_factory=list)
    retracted: list[tuple[str, str]] = field(default_factory=list)
    restored: list[tuple[str, str]] = field(default_factory=list)
    # Material changes, with an event.
    changed: list[tuple[str, str]] = field(default_factory=list)
    # Rows written without an event: immaterial changes and `last_seen_at` refreshes.
    refreshed: int = 0
    # Attributes per matcher dropped by its limit.
    truncated: dict[str, int] = field(default_factory=dict)

    @property
    def events(self) -> int:
        return (
            len(self.added)
            + len(self.retracted)
            + len(self.restored)
            + len(self.changed)
        )


def _material_evidence(evidence: dict[str, Any]) -> dict[str, Any]:
    return {k: v for k, v in evidence.items() if k not in IMMATERIAL_EVIDENCE_KEYS}


def _is_material(match: Match, candidate: Candidate) -> bool:
    return abs(match.score - candidate.score) >= SCORE_EPSILON or _material_evidence(
        match.evidence
    ) != _material_evidence(candidate.evidence)


def _differs(match: Match, candidate: Candidate, version: int) -> bool:
    return (
        match.score != candidate.score
        or match.evidence != candidate.evidence
        or match.matcher_version != version
    )


def reconcile_matches(
    suggestion: CVEDerivationClusterProposal,
    cause: TrackerEvent.Cause,
    matchers: Iterable[str] | None = None,
    *,
    view: CveView | None = None,
    universe: Universe | None = None,
    evaluation: NixEvaluation | None = None,
    actor: User | None = None,
    now: datetime | None = None,
) -> ReconcileResult:
    """
    Run the given matchers (all registered ones by default) on the suggestion's CVE and
    bring its `Match` rows of those matchers in line, writing one `TrackerEvent` per
    transition, all sharing one batch id. Matches of other matchers are left alone.

    Matching runs before the transaction; the diff runs under a row lock on the
    suggestion, so concurrent runs for one suggestion serialise and the later one
    sees the earlier one's rows.
    """
    selected = matchers_for(matchers)
    view = view or build_cve_view(suggestion.cve)
    universe = universe or Universe.tracked()
    results = {matcher.slug: matcher.run(view, universe) for matcher in selected}
    versions = {matcher.slug: matcher.version for matcher in selected}
    now = now or timezone.now()
    outcome = ReconcileResult(
        batch=uuid.uuid4(),
        truncated={slug: r.truncated for slug, r in results.items() if r.truncated},
    )

    events: list[TrackerEvent] = []

    def event(kind: TrackerEvent.Kind, slug: str, attrpath: str, **data: Any) -> None:
        if results[slug].truncated:
            data["matcher_truncated"] = results[slug].truncated
        events.append(
            TrackerEvent(
                suggestion=suggestion,
                kind=kind,
                attrpath=attrpath,
                matcher=slug,
                cause=cause,
                evaluation=evaluation,
                actor=actor,
                data=data,
                batch=outcome.batch,
            )
        )

    with transaction.atomic():
        CVEDerivationClusterProposal.objects.select_for_update().filter(
            pk=suggestion.pk
        ).values_list("pk", flat=True).get()
        existing = {
            (m.matcher, m.attrpath): m
            for m in Match.objects.filter(suggestion=suggestion, matcher__in=results)
        }

        to_create: list[Match] = []
        to_update: list[Match] = []
        to_touch: list[int] = []
        to_retract: list[int] = []

        for slug, result in results.items():
            version = versions[slug]
            produced = {c.attrpath: c for c in result.candidates}
            for attrpath, candidate in produced.items():
                match = existing.get((slug, attrpath))
                if match is None:
                    to_create.append(
                        Match(
                            suggestion=suggestion,
                            attrpath=attrpath,
                            matcher=slug,
                            matcher_version=version,
                            score=candidate.score,
                            evidence=candidate.evidence,
                            last_seen_at=now,
                        )
                    )
                    outcome.added.append((slug, attrpath))
                    event(
                        TrackerEvent.Kind.MATCH_ADDED,
                        slug,
                        attrpath,
                        score=candidate.score,
                        evidence=candidate.evidence,
                    )
                elif match.retracted_at is not None:
                    material = _is_material(match, candidate)
                    old_score = match.score
                    match.retracted_at = None
                    match.score = candidate.score
                    match.evidence = candidate.evidence
                    match.matcher_version = version
                    match.last_seen_at = now
                    to_update.append(match)
                    outcome.restored.append((slug, attrpath))
                    data: dict[str, Any] = {"score": candidate.score}
                    if material:
                        data |= {"old_score": old_score, "evidence": candidate.evidence}
                    event(TrackerEvent.Kind.MATCH_RESTORED, slug, attrpath, **data)
                elif _differs(match, candidate, version):
                    if _is_material(match, candidate):
                        outcome.changed.append((slug, attrpath))
                        event(
                            TrackerEvent.Kind.MATCH_CHANGED,
                            slug,
                            attrpath,
                            old_score=match.score,
                            score=candidate.score,
                            old_evidence=match.evidence,
                            evidence=candidate.evidence,
                        )
                    else:
                        outcome.refreshed += 1
                    match.score = candidate.score
                    match.evidence = candidate.evidence
                    match.matcher_version = version
                    match.last_seen_at = now
                    to_update.append(match)
                elif now - match.last_seen_at >= LAST_SEEN_RESOLUTION:
                    to_touch.append(match.pk)
                    outcome.refreshed += 1

            for (match_slug, attrpath), match in existing.items():
                if (
                    match_slug == slug
                    and attrpath not in produced
                    and match.retracted_at is None
                ):
                    to_retract.append(match.pk)
                    outcome.retracted.append((slug, attrpath))
                    event(
                        TrackerEvent.Kind.MATCH_RETRACTED,
                        slug,
                        attrpath,
                        score=match.score,
                    )

        Match.objects.bulk_create(to_create)
        Match.objects.bulk_update(
            to_update,
            ["retracted_at", "score", "evidence", "matcher_version", "last_seen_at"],
        )
        if to_touch:
            Match.objects.filter(pk__in=to_touch).update(last_seen_at=now)
        if to_retract:
            Match.objects.filter(pk__in=to_retract).update(retracted_at=now)
        TrackerEvent.objects.bulk_create(events)

    if outcome.events:
        logger.info(
            "Reconciled matches of suggestion %d (%s): +%d -%d restored %d changed %d",
            suggestion.pk,
            view.cve_id,
            len(outcome.added),
            len(outcome.retracted),
            len(outcome.restored),
            len(outcome.changed),
        )
    return outcome
