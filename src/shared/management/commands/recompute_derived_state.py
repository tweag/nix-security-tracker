import argparse
from collections import Counter
from typing import Any

from django.core.management.base import BaseCommand
from django.db import transaction
from django.utils import timezone

from shared.derived_state import derive_states, flush_derived_states
from shared.models.linkage import CVEDerivationClusterProposal
from shared.models.matching import SuggestionDerivedState


class Command(BaseCommand):
    help = (
        "Recompute the stored derived state of every suggestion in batches and report drift: "
        "rows that were missing, stale, or held a value other than the computed one. "
        "With --check nothing is written and the exit status is 1 on drift."
    )

    def add_arguments(self, parser: argparse.ArgumentParser) -> None:
        parser.add_argument("--batch-size", type=int, default=2000)
        parser.add_argument("--check", action="store_true")
        parser.add_argument(
            "--stale-only",
            action="store_true",
            help="Only recompute rows marked stale (cheap; for a periodic catch-up).",
        )

    def handle(self, *args: Any, **options: Any) -> None:
        if options["stale_only"]:
            total = 0
            while n := flush_derived_states(limit=options["batch_size"]):
                total += n
            self.stdout.write(self.style.SUCCESS(f"Recomputed {total} stale row(s)."))
            return

        drift: Counter[str] = Counter()
        examples: list[str] = []
        last = 0
        checked = 0
        while True:
            ids = list(
                CVEDerivationClusterProposal.objects.filter(pk__gt=last)
                .order_by("pk")
                .values_list("pk", flat=True)[: options["batch_size"]]
            )
            if not ids:
                break
            last = ids[-1]
            checked += len(ids)
            with transaction.atomic():
                stored = {
                    row.suggestion_id: row
                    for row in SuggestionDerivedState.objects.filter(
                        suggestion_id__in=ids
                    ).select_for_update()
                }
                now = timezone.now()
                fix: list[SuggestionDerivedState] = []
                for pk, derived in derive_states(ids).items():
                    row = stored.get(pk)
                    kind = (
                        "missing"
                        if row is None
                        else "stale"
                        if row.stale
                        else "wrong"
                        if row.state != derived.state
                        else None
                    )
                    if kind is None:
                        continue
                    drift[kind] += 1
                    if kind == "wrong" and len(examples) < 10:
                        examples.append(
                            f"{pk}: stored {row.state}, computed {derived.state}"
                        )  # type: ignore[union-attr]
                    fix.append(
                        SuggestionDerivedState(
                            suggestion_id=pk,
                            state=derived.state,
                            stale=False,
                            updated_at=now,
                        )
                    )
                if fix and not options["check"]:
                    SuggestionDerivedState.objects.bulk_create(
                        fix,
                        update_conflicts=True,
                        unique_fields=["suggestion"],
                        update_fields=["state", "stale", "updated_at"],
                    )
        summary = ", ".join(f"{k} {v}" for k, v in sorted(drift.items())) or "none"
        self.stdout.write(f"Checked {checked} suggestion(s); drift: {summary}")
        for line in examples:
            self.stdout.write(f"  {line}")
        if options["check"] and drift:
            raise SystemExit(1)
