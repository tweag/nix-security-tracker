from pathlib import Path
from typing import Any

from django.core.management.base import BaseCommand, CommandError, CommandParser

from shared.identity.reconcile import reconcile_mapping_change
from shared.identity.rules import RULE_FILE, sync_rule_file


class Command(BaseCommand):
    help = (
        "Sync the checked-in product rule file into `ProductMapping(source=rule_file)` rows "
        "and reconcile the open suggestions the changed rules bear on."
    )

    def add_arguments(self, parser: CommandParser) -> None:
        parser.add_argument("--file", type=Path, default=RULE_FILE)
        parser.add_argument(
            "--no-reconcile",
            action="store_true",
            help="Only write the mappings; run `reconcile_product_keys` later",
        )

    def handle(self, *args: Any, **options: Any) -> None:
        try:
            result = sync_rule_file(options["file"].read_text())
        except (OSError, ValueError) as e:
            raise CommandError(str(e)) from e
        self.stdout.write(
            f"Rules: {len(result.created)} created, {len(result.updated)} updated, "
            f"{len(result.deleted)} deleted, {result.unchanged} unchanged."
        )
        if not result.changed or options["no_reconcile"]:
            return
        outcome = reconcile_mapping_change(*result.changed, sync_limit=None)
        self.stdout.write(
            self.style.SUCCESS(
                f"Reconciled {len(outcome.reconciled)} open suggestion(s), "
                f"{outcome.events} event(s)."
            )
        )
