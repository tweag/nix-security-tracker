from typing import Any

from django.core.management.base import BaseCommand

from shared.models.nix_evaluation import NixChannel, NixEvaluation, NixpkgsBranch
from shared.snapshot import update_branch_snapshot


class Command(BaseCommand):
    help = (
        "Initialise the package snapshot of every tracked branch from its latest completed evaluation. "
        "Idempotent: branches whose snapshot is current or newer are left alone."
    )

    def handle(self, *args: Any, **options: Any) -> None:
        branches = NixpkgsBranch.objects.filter(
            channels__state__in=NixChannel.TRACKED_STATES
        ).distinct()
        for branch in branches.order_by("name"):
            # The evaluation `NixEvaluation.objects.latest_completed_per_branch()` picks for this branch.
            evaluation = (
                NixEvaluation.objects.filter(
                    on_branches=branch, state=NixEvaluation.EvaluationState.COMPLETED
                )
                .order_by("-updated_at")
                .first()
            )
            if evaluation is None:
                self.stdout.write(f"{branch}: no completed evaluation")
                continue
            (result,) = update_branch_snapshot(evaluation, branches=[branch]).branches
            self.stdout.write(
                f"{branch}: {result.outcome} from evaluation {evaluation} "
                f"({result.attributes} attributes)"
            )
