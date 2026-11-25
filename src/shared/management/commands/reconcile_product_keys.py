import time
from typing import Any

from django.core.management.base import BaseCommand, CommandError, CommandParser

from shared.identity.reconcile import (
    open_suggestions_for_keys,
    reconcile_suggestions,
)
from shared.models.matching import ProductMapping


class Command(BaseCommand):
    help = (
        "Reconcile the open suggestions whose CVEs have these product keys, with cause "
        "`mapping`: the deferred half of a mapping change that bears on too many suggestions "
        "to reconcile in the request."
    )

    def add_arguments(self, parser: CommandParser) -> None:
        parser.add_argument("key_ids", nargs="*", type=int, help="ProductKey ids")
        parser.add_argument(
            "--all-mapped",
            action="store_true",
            help="Every product key that has a mapping",
        )
        parser.add_argument(
            "--matcher",
            action="append",
            dest="matchers",
            help="Only run this matcher (repeatable); default: all registered",
        )

    def handle(self, *args: Any, **options: Any) -> None:
        if bool(options["key_ids"]) == options["all_mapped"]:
            raise CommandError("Give key ids or --all-mapped, not both or neither.")
        keys = options["key_ids"] or list(
            ProductMapping.objects.values_list("product_key_id", flat=True).distinct()
        )
        ids = list(
            open_suggestions_for_keys(keys).order_by("pk").values_list("pk", flat=True)
        )
        start = time.monotonic()
        results = reconcile_suggestions(ids, options["matchers"])
        events = sum(r.events for r in results.values())
        self.stdout.write(
            self.style.SUCCESS(
                f"Reconciled {len(results)} suggestion(s), {events} event(s) "
                f"in {time.monotonic() - start:.1f} s."
            )
        )
