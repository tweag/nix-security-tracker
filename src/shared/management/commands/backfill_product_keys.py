import time
from typing import Any

from django.core.management.base import BaseCommand, CommandParser
from django.db import transaction

from shared.identity.keys import persist_product_keys
from shared.models.cve import AffectedProduct


class Command(BaseCommand):
    help = "Attach derived `ProductKey` rows to existing affected products, in batches."

    def add_arguments(self, parser: CommandParser) -> None:
        parser.add_argument("--batch-size", type=int, default=2000)
        parser.add_argument(
            "--all",
            action="store_true",
            help="Resync every row, also dropping links derivation no longer produces "
            "(after a change to key derivation)",
        )

    def handle(self, *args: Any, **options: Any) -> None:
        rows = AffectedProduct.objects.order_by("pk").only(
            "pk", "vendor", "product", "package_name", "collection_url", "repo"
        )
        if not options["all"]:
            rows = rows.filter(product_keys__isnull=True)
        total = links = 0
        last = 0
        start = time.monotonic()
        while True:
            batch = list(
                rows.filter(pk__gt=last).prefetch_related("cpes")[
                    : options["batch_size"]
                ]
            )
            if not batch:
                break
            with transaction.atomic():
                links += persist_product_keys(batch, replace=options["all"])
            total += len(batch)
            last = batch[-1].pk
            if options["verbosity"] > 1:
                rate = total / max(time.monotonic() - start, 1e-9)
                self.stdout.write(f"{total} rows, {rate:.0f} rows/s")
        elapsed = time.monotonic() - start
        self.stdout.write(
            self.style.SUCCESS(
                f"Processed {total} affected product(s), {links} key link(s) "
                f"in {elapsed:.1f} s ({total / max(elapsed, 1e-9):.0f} rows/s)."
            )
        )
