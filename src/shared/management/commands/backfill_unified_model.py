import argparse
import uuid
from collections import defaultdict
from typing import Any

from django.contrib.auth.models import User
from django.core.management.base import BaseCommand
from django.db import transaction
from django.utils import timezone

from shared.derived_state import flush_derived_states
from shared.exposure import (
    Cause,
    _load_context,
    _Run,
    _write,
    is_dismissed,
    lock_suggestions,
    observe,
    reconcile_exposures,
    tracked_branches,
)
from shared.matching.selection import LEGACY_MATCHER, LEGACY_MATCHER_VERSION
from shared.models import (  # type: ignore[attr-defined]
    CVEDerivationClusterProposalStatusEvent,
    PackageOverlayEvent,
)
from shared.models.linkage import (
    CVEDerivationClusterProposal,
    DerivationClusterProposalLink,
    PackageOverlay,
    ProvenanceFlags,
)
from shared.models.matching import Exposure, Match, TrackerEvent, Verdict
from shared.models.nix_evaluation import NixEvaluation, parse_drv_name
from shared.models.snapshot import BranchPackage

Kind = TrackerEvent.Kind
Status = CVEDerivationClusterProposal.Status


def legacy_evidence(flags: int) -> dict[str, Any]:
    """Evidence of a `legacy-v2` match: the provenance bits and the CVE field they name."""
    fields = [
        name
        for flag, name in (
            (ProvenanceFlags.PACKAGE_NAME_MATCH, "package_name"),
            (ProvenanceFlags.PRODUCT_MATCH, "product"),
            (ProvenanceFlags.CPE_MATCH, "cpe"),
        )
        if flags & flag
    ]
    evidence: dict[str, Any] = {"provenance_flags": flags, "source": "legacy links"}
    if fields:
        evidence["cve_field"] = fields[0]
        evidence["cve_fields"] = fields
    return evidence


class Command(BaseCommand):
    help = (
        "Backfill the unified model from the legacy data, in batches of suggestions by "
        "primary key. Idempotent and restartable (--start-after): `legacy-v2` matches and "
        "as-matched exposures from derivation links of suggestions matched by the legacy "
        "algorithm, then exposures reconciled against the current snapshot; `irrelevant` "
        "verdicts from ignore overlays of every suggestion, `affected` verdicts for what "
        "accepted and published suggestions show. Run after `backfill_branch_packages`."
    )

    def add_arguments(self, parser: argparse.ArgumentParser) -> None:
        parser.add_argument("--batch-size", type=int, default=500)
        parser.add_argument("--start-after", type=int, default=0)
        parser.add_argument(
            "--no-reconcile",
            action="store_true",
            help="Skip reconciling exposures against the current snapshot.",
        )

    def handle(self, *args: Any, **options: Any) -> None:
        cursor = options["start_after"]
        size = options["batch_size"]
        totals: dict[str, int] = defaultdict(int)
        branches = {b.name: b for b in tracked_branches()}
        while True:
            batch = list(
                CVEDerivationClusterProposal.objects.filter(pk__gt=cursor)
                .order_by("pk")
                .values_list("pk", "status", "rejection_reason", "algorithm_version")[
                    :size
                ]
            )
            if not batch:
                break
            with transaction.atomic():
                counts = self.backfill(batch, branches, not options["no_reconcile"])
                counts["derived_states"] = flush_derived_states(
                    [pk for pk, *_ in batch]
                )
            for key, value in counts.items():
                totals[key] += value
            cursor = batch[-1][0]
            self.stdout.write(
                f"up to suggestion {cursor}: "
                + ", ".join(f"{k} {v}" for k, v in sorted(counts.items()))
            )
        self.stdout.write(
            self.style.SUCCESS(
                "Done: " + ", ".join(f"{k} {v}" for k, v in sorted(totals.items()))
            )
        )

    def backfill(
        self,
        batch: list[tuple[int, str, str | None, int]],
        branches: dict[str, Any],
        reconcile: bool,
    ) -> dict[str, int]:
        counts: dict[str, int] = defaultdict(int)
        ids = [pk for pk, *_ in batch]
        lock_suggestions(ids)
        legacy = [
            pk
            for pk, _, _, version in batch
            if version < CVEDerivationClusterProposal.CURRENT_ALGORITHM_VERSION
        ]
        open_legacy = [
            pk
            for pk, status, reason, version in batch
            if pk in set(legacy) and not is_dismissed(status, reason)
        ]
        counts["verdicts"] = self.verdicts(ids)
        counts["acceptances"] = self.acceptances(
            [
                pk
                for pk, status, _, _ in batch
                if status in (Status.ACCEPTED, Status.PUBLISHED)
            ]
        )
        if not legacy:
            return counts
        run = _Run(cause=Cause.BACKFILL, batch=uuid.uuid4())
        links = list(
            DerivationClusterProposalLink.objects.filter(
                proposal_id__in=legacy
            ).values_list(
                "proposal_id",
                "provenance_flags",
                "derivation__attribute",
                "derivation__name",
                "derivation__parent_evaluation_id",
                "derivation__metadata__known_vulnerabilities",
            )
        )
        counts["matches"] = self.matches(links, run)
        counts["exposures"] = self.exposures(
            [link for link in links if link[0] in set(open_legacy)], branches, run
        )
        TrackerEvent.objects.bulk_create(run.events)
        if reconcile:
            for suggestion in CVEDerivationClusterProposal.objects.filter(
                pk__in=open_legacy
            ):
                result = reconcile_exposures(suggestion, Cause.BACKFILL)
                counts["reconciled_events"] += sum(result.events.values())
        return counts

    def matches(self, links: list[tuple[Any, ...]], run: _Run) -> int:
        flags: dict[tuple[int, str], int] = defaultdict(int)
        for sid, f, attr, *_ in links:
            flags[(sid, attr)] |= f
        existing = set(
            Match.objects.filter(
                suggestion_id__in={s for s, _ in flags}, matcher=LEGACY_MATCHER
            ).values_list("suggestion_id", "attrpath")
        )
        now = timezone.now()
        new = [
            Match(
                suggestion_id=sid,
                attrpath=attr,
                matcher=LEGACY_MATCHER,
                matcher_version=LEGACY_MATCHER_VERSION,
                score=1.0,
                evidence=legacy_evidence(f),
                last_seen_at=now,
            )
            for (sid, attr), f in sorted(flags.items())
            if (sid, attr) not in existing
        ]
        Match.objects.bulk_create(new, ignore_conflicts=True)
        run.events += [
            TrackerEvent(
                suggestion_id=m.suggestion_id,
                kind=Kind.MATCH_ADDED,
                attrpath=m.attrpath,
                matcher=LEGACY_MATCHER,
                cause=Cause.BACKFILL,
                data={"score": 1.0, "evidence": m.evidence},
                batch=run.batch,
            )
            for m in new
        ]
        return len(new)

    def exposures(
        self,
        links: list[tuple[Any, ...]],
        branches: dict[str, Any],
        run: _Run,
    ) -> int:
        """
        One row per (suggestion, attribute, tracked branch) as matched: the newest linked
        derivation of the attribute on that branch, classified against the CVE. Only where the
        branch has a snapshot row for the attribute, as `shared.exposure` requires.
        """
        if not links:
            return 0
        evaluations = NixEvaluation.objects.in_bulk({link[4] for link in links})
        on_branches: dict[int, set[str]] = defaultdict(set)
        for evaluation, branch in NixEvaluation.on_branches.through.objects.filter(
            nixevaluation_id__in=evaluations, nixpkgsbranch_id__in=branches
        ).values_list("nixevaluation_id", "nixpkgsbranch_id"):
            on_branches[evaluation].add(branch)

        newest: dict[tuple[int, str, str], tuple[Any, ...]] = {}
        for link in links:
            sid, _, attr, _, evaluation_id, _ = link
            evaluation = evaluations[evaluation_id]
            for branch in on_branches[evaluation_id]:
                key = (sid, attr, branch)
                current = newest.get(key)
                if current is None or (evaluation.created_at, evaluation.pk) > (
                    evaluations[current[4]].created_at,
                    current[4],
                ):
                    newest[key] = link
        attrs = {a for _, a, _ in newest}
        snapshotted = set(
            BranchPackage.objects.filter(
                attrpath__in=attrs, branch_id__in=branches
            ).values_list("branch_id", "attrpath")
        )
        existing = set(
            Exposure.objects.filter(
                suggestion_id__in={s for s, _, _ in newest}
            ).values_list("suggestion_id", "attrpath", "branch_id")
        )
        ctx = _load_context({s for s, _, _ in newest}, attrs)
        written = 0
        for (sid, attr, branch), link in sorted(newest.items()):
            if (branch, attr) not in snapshotted or (sid, attr, branch) in existing:
                continue
            _, _, _, name, evaluation_id, known = link
            evaluation = evaluations[evaluation_id]
            as_matched = BranchPackage(
                attrpath=attr,
                branch_id=branch,
                present=True,
                version=parse_drv_name(name)[1],
                known_vulnerabilities=known or [],
                evaluation_id=evaluation_id,
            )
            obs = observe(as_matched, ctx.cve_id[sid], ctx.products_for(sid, attr))
            _write(
                run,
                None,
                obs,
                suggestion_id=sid,
                attrpath=attr,
                branch=branches[branch],
                evaluation=evaluation,
                previous_evaluation=None,
            )
            written += 1
        return written

    def acceptances(self, ids: list[int]) -> int:
        """
        `affected` verdicts for what accepted and published suggestions show and do not ignore,
        by the user who accepted (or published) if the status history records one.
        """
        if not ids:
            return 0
        linked: dict[int, set[str]] = defaultdict(set)
        for sid, attr in (
            DerivationClusterProposalLink.objects.filter(proposal_id__in=ids)
            .values_list("proposal_id", "derivation__attribute")
            .distinct()
        ):
            linked[sid].add(attr)
        decided = set(
            Verdict.objects.filter(
                suggestion_id__in=ids, branch__isnull=True
            ).values_list("suggestion_id", "attrpath")
        )
        authors: dict[int, int | None] = {}
        for sid, metadata in (
            CVEDerivationClusterProposalStatusEvent.objects.filter(
                pgh_obj_id__in=ids,
                status__in=[Status.ACCEPTED, Status.PUBLISHED],
            )
            .exclude(pgh_label="rematch")
            .order_by("pgh_created_at")
            .values_list("pgh_obj_id", "pgh_context__metadata")
        ):
            user = (metadata or {}).get("user")
            if user is not None:
                authors[sid] = int(user)
        users = set(
            User.objects.filter(
                pk__in={u for u in authors.values() if u is not None}
            ).values_list("pk", flat=True)
        )
        new = [
            Verdict(
                suggestion_id=sid,
                attrpath=attr,
                branch=None,
                verdict=Verdict.Kind.AFFECTED,
                author_id=a if (a := authors.get(sid)) in users else None,
                comment="",
            )
            for sid in ids
            for attr in sorted(linked[sid])
            if (sid, attr) not in decided
        ]
        Verdict.objects.bulk_create(new, ignore_conflicts=True)
        batch = uuid.uuid4()
        TrackerEvent.objects.bulk_create(
            TrackerEvent(
                suggestion_id=v.suggestion_id,
                kind=Kind.VERDICT_SET,
                attrpath=v.attrpath,
                cause=Cause.BACKFILL,
                actor_id=v.author_id,
                data={"new": {"verdict": v.verdict}, "via": "accept", "from": "status"},
                batch=batch,
            )
            for v in new
        )
        return len(new)

    def verdicts(self, ids: list[int]) -> int:
        """`irrelevant` verdicts for ignore overlays, by the user who ignored if recorded."""
        overlays = list(
            PackageOverlay.objects.filter(
                suggestion_id__in=ids, type=PackageOverlay.Type.IGNORED
            ).values_list("suggestion_id", "package_attribute")
        )
        if not overlays:
            return 0
        existing = set(
            Verdict.objects.filter(
                suggestion_id__in=ids, branch__isnull=True
            ).values_list("suggestion_id", "attrpath")
        )
        authors: dict[tuple[int, str], int | None] = {}
        for sid, attr, metadata in (
            PackageOverlayEvent.objects.filter(
                suggestion_id__in=ids, pgh_label="package.ignore"
            )
            .order_by("pgh_created_at")
            .values_list("suggestion_id", "package_attribute", "pgh_context__metadata")
        ):
            user = (metadata or {}).get("user")
            authors[(sid, attr)] = int(user) if user is not None else None
        users = set(
            User.objects.filter(
                pk__in={u for u in authors.values() if u is not None}
            ).values_list("pk", flat=True)
        )
        new = [
            Verdict(
                suggestion_id=sid,
                attrpath=attr,
                branch=None,
                verdict=Verdict.Kind.IRRELEVANT,
                author_id=a if (a := authors.get((sid, attr))) in users else None,
                comment="",
            )
            for sid, attr in overlays
            if (sid, attr) not in existing
        ]
        Verdict.objects.bulk_create(new, ignore_conflicts=True)
        batch = uuid.uuid4()
        TrackerEvent.objects.bulk_create(
            TrackerEvent(
                suggestion_id=v.suggestion_id,
                kind=Kind.VERDICT_SET,
                attrpath=v.attrpath,
                cause=Cause.BACKFILL,
                actor_id=v.author_id,
                data={"new": {"verdict": v.verdict}, "from": "package overlay"},
                batch=batch,
            )
            for v in new
        )
        return len(new)
