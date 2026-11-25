from typing import Any

from django.core.management.base import BaseCommand, CommandError, CommandParser

from shared.matching.base import Universe
from shared.matching.matchers import matchers_for
from shared.matching.reconcile import reconcile_matches
from shared.matching.view import build_cve_view
from shared.models.linkage import CVEDerivationClusterProposal
from shared.models.matching import TrackerEvent


class Command(BaseCommand):
    help = "Run the matchers on suggestions and reconcile their `Match` rows."

    def add_arguments(self, parser: CommandParser) -> None:
        parser.add_argument(
            "cve_ids", nargs="*", help="CVE ids whose suggestions to reconcile"
        )
        parser.add_argument(
            "--all-open",
            action="store_true",
            help="Reconcile every pending or accepted suggestion",
        )
        parser.add_argument(
            "--matcher",
            action="append",
            dest="matchers",
            help="Only run this matcher (repeatable); default: all registered",
        )
        parser.add_argument(
            "--cause",
            choices=TrackerEvent.Cause.values,
            default=TrackerEvent.Cause.BACKFILL,
        )

    def handle(self, *args: Any, **options: Any) -> None:
        if bool(options["cve_ids"]) == options["all_open"]:
            raise CommandError("Give CVE ids or --all-open, not both or neither.")
        try:
            matchers_for(options["matchers"])
        except ValueError as e:
            raise CommandError(str(e)) from e

        suggestions = CVEDerivationClusterProposal.objects.select_related("cve")
        if options["all_open"]:
            suggestions = suggestions.filter(
                status__in=[
                    CVEDerivationClusterProposal.Status.PENDING,
                    CVEDerivationClusterProposal.Status.ACCEPTED,
                ]
            )
        else:
            suggestions = suggestions.filter(cve__cve_id__in=options["cve_ids"])

        universe = Universe.tracked()
        total = events = 0
        for suggestion in suggestions.order_by("pk").iterator():
            result = reconcile_matches(
                suggestion,
                options["cause"],
                options["matchers"],
                view=build_cve_view(suggestion.cve),
                universe=universe,
            )
            total += 1
            events += result.events
            if result.events or options["verbosity"] > 1:
                self.stdout.write(
                    f"{suggestion.cve.cve_id} (#{suggestion.pk}): "
                    f"+{len(result.added)} -{len(result.retracted)} "
                    f"restored {len(result.restored)} changed {len(result.changed)}"
                    + (f" truncated {result.truncated}" if result.truncated else "")
                )
        self.stdout.write(
            self.style.SUCCESS(f"Reconciled {total} suggestion(s), {events} event(s).")
        )
