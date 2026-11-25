from typing import Any

from django.core.management.base import BaseCommand, CommandParser

from shared.identity.reconcile import reconcile_mapping_change
from shared.identity.triage import MIN_NOT_SAME, MIN_SAME, learn_triage_mappings


class Command(BaseCommand):
    help = (
        "Relearn `ProductMapping(source=triage)` rows from published and rejected suggestions, "
        "in unambiguous cases only, and reconcile the open suggestions they bear on."
    )

    def add_arguments(self, parser: CommandParser) -> None:
        parser.add_argument("--dry-run", action="store_true")
        parser.add_argument("--min-same", type=int, default=MIN_SAME)
        parser.add_argument("--min-not-same", type=int, default=MIN_NOT_SAME)
        parser.add_argument(
            "--min-irrelevant",
            type=int,
            default=None,
            help="Also learn `irrelevant` from this many sole-product not_in_nixpkgs rejections",
        )
        parser.add_argument("--no-reconcile", action="store_true")

    def handle(self, *args: Any, **options: Any) -> None:
        result = learn_triage_mappings(
            write=not options["dry_run"],
            min_same=options["min_same"],
            min_not_same=options["min_not_same"],
            min_irrelevant=options["min_irrelevant"],
        )
        by_relation: dict[str, int] = {}
        for proposal in result.learned.proposals:
            by_relation[proposal.relation] = by_relation.get(proposal.relation, 0) + 1
            if options["verbosity"] > 1:
                kind, vendor, product = proposal.key
                self.stdout.write(
                    f"{proposal.relation} {kind}:{vendor}/{product} -> "
                    f"{proposal.attrpath or '*'} ({len(proposal.support)})"
                )
        self.stdout.write(
            f"Proposed {by_relation or 'nothing'}; {len(result.learned.conflicts)} conflict(s); "
            f"{len(result.created)} created, {len(result.deleted)} deleted, "
            f"{result.overridden} overridden by curated mappings."
        )
        if options["dry_run"] or options["no_reconcile"] or not result.changed:
            return
        outcome = reconcile_mapping_change(*result.changed, sync_limit=None)
        self.stdout.write(
            self.style.SUCCESS(
                f"Reconciled {len(outcome.reconciled)} open suggestion(s), "
                f"{outcome.events} event(s)."
            )
        )
