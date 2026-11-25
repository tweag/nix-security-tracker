import argparse
from typing import Any

from django.core.management.base import BaseCommand

from shared.channel_history import (
    compute_landings,
    history_branches,
    poll_channel_heads,
)
from shared.history import CachedAncestry, HistoryClone


class Command(BaseCommand):
    help = (
        "Record channel head advances (one git ls-remote), fetch the history clone, and record "
        "which fixes landed in which channel. Cheap; meant to run hourly."
    )

    def add_arguments(self, parser: argparse.ArgumentParser) -> None:
        parser.add_argument(
            "--no-poll", action="store_true", help="Do not read channel heads."
        )
        parser.add_argument(
            "--no-fetch",
            action="store_true",
            help="Use the history clone as it is, without fetching.",
        )

    def handle(self, *args: Any, **options: Any) -> None:
        if not options["no_poll"]:
            advances = poll_channel_heads()
            self.stdout.write(f"{len(advances)} channel(s) advanced")
        clone = HistoryClone.from_settings()
        if clone is None:
            self.stdout.write(
                "NIXPKGS_HISTORY_CHECKOUT is not set; no landings computed"
            )
            return
        if not options["no_fetch"]:
            seconds = clone.fetch(history_branches())
            self.stdout.write(f"Fetched history in {seconds:.1f}s")
        ancestry = CachedAncestry(clone)
        result = compute_landings(ancestry)
        self.stdout.write(
            self.style.SUCCESS(
                f"{result.landed} landing(s) recorded, {result.pending} pending "
                f"({result.unknown} with an unknown fix point), {ancestry.queries} ancestry queries"
            )
        )
