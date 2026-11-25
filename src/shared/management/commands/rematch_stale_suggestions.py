import argparse
from typing import Any

import pgpubsub
from django.core.management.base import BaseCommand

from shared.channels import SuggestionRefreshChannel
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
            "--include-machine-rejected",
            action="store_true",
            help=(
                "Also re-match suggestions the matcher rejected (no matches, too many matches); "
                "those that now find something are reopened as pending."
            ),
        )

    def handle(self, *args: Any, **options: Any) -> None:
        open_statuses = CVEDerivationClusterProposal.objects.filter(
            status__in=[Status.PENDING, Status.ACCEPTED]
        )
        if options["include_machine_rejected"]:
            open_statuses = open_statuses | CVEDerivationClusterProposal.objects.filter(
                status=Status.REJECTED,
                rejection_reason__in=MACHINE_REOPENABLE_REJECTIONS,
            )
        stale_pks = open_statuses.filter(stale_q()).values_list("pk", flat=True)

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
