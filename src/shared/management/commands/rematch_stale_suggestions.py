import argparse
from datetime import timedelta
from typing import Any

import pgpubsub
from django.core.management.base import BaseCommand
from django.db.models import Q
from django.utils import timezone

from shared.channels import SuggestionRefreshChannel
from shared.matching.selection import reopenable_q
from shared.models.linkage import (
    MACHINE_REOPENABLE_REJECTIONS,
    CVEDerivationClusterProposal,
)
from shared.pipeline import stale_q

Status = CVEDerivationClusterProposal.Status


class Command(BaseCommand):
    help = (
        "Dispatch a re-match of open suggestions that were matched by the legacy algorithm, "
        "or that a matcher's current version has not run on."
    )

    def add_arguments(self, parser: argparse.ArgumentParser) -> None:
        parser.add_argument(
            "--reopen-window-days",
            type=int,
            default=None,
            help=(
                "Also re-match suggestions the matcher rejected (no matches, too many matches) "
                "whose CVE was published within this many days; those that now find something "
                "are reopened as pending. Default: MATCHING_REOPEN_WINDOW_DAYS. 0: none."
            ),
        )
        parser.add_argument(
            "--include-machine-rejected",
            action="store_true",
            help="Re-match every machine-rejected suggestion, whatever its age.",
        )

    def handle(self, *args: Any, **options: Any) -> None:
        selected = Q(status__in=[Status.PENDING, Status.ACCEPTED])
        if options["include_machine_rejected"]:
            selected |= Q(
                status=Status.REJECTED,
                rejection_reason__in=MACHINE_REOPENABLE_REJECTIONS,
            )
        else:
            days = options["reopen_window_days"]
            if days is None:
                selected |= reopenable_q()
            elif days > 0:
                selected |= reopenable_q(cutoff=timezone.now() - timedelta(days=days))
        stale_pks = CVEDerivationClusterProposal.objects.filter(
            selected & stale_q()
        ).values_list("pk", flat=True)

        if not stale_pks:
            self.stdout.write("No stale suggestions; nothing to do.")
            return

        for pk in stale_pks.iterator():
            pgpubsub.notify(SuggestionRefreshChannel, pk=pk)

        self.stdout.write(
            self.style.SUCCESS(
                f"Dispatched {stale_pks.count()} stale suggestion(s) for rematch."
            )
        )
