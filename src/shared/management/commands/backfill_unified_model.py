import argparse
from collections import defaultdict
from typing import Any

from django.core.management.base import BaseCommand

from shared.exposure import tracked_branches
from shared.legacy_backfill import backfill_suggestions
from shared.models.linkage import CVEDerivationClusterProposal


class Command(BaseCommand):
    help = (
        "Backfill the unified model from the legacy data, in batches of suggestions by "
        "primary key (`shared.legacy_backfill`). Idempotent and restartable (--start-after): "
        "`legacy-v2` matches and as-matched exposures from derivation links of suggestions "
        "matched by the legacy algorithm, then exposures reconciled against the current "
        "snapshot; `irrelevant` verdicts from ignore overlays of every suggestion, `affected` "
        "verdicts for what accepted and published suggestions show. Run after "
        "`backfill_branch_packages`."
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
        totals: dict[str, int] = defaultdict(int)
        branches = {b.name: b for b in tracked_branches()}
        while True:
            ids = list(
                CVEDerivationClusterProposal.objects.filter(pk__gt=cursor)
                .order_by("pk")
                .values_list("pk", flat=True)[: options["batch_size"]]
            )
            if not ids:
                break
            counts = backfill_suggestions(
                ids, reconcile=not options["no_reconcile"], branches=branches
            )
            for key, value in counts.items():
                totals[key] += value
            cursor = ids[-1]
            self.stdout.write(
                f"up to suggestion {cursor}: "
                + ", ".join(f"{k} {v}" for k, v in sorted(counts.items()))
            )
        self.stdout.write(
            self.style.SUCCESS(
                "Done: " + ", ".join(f"{k} {v}" for k, v in sorted(totals.items()))
            )
        )
