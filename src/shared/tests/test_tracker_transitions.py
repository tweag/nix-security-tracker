from collections.abc import Callable

import pytest
from django.core.exceptions import ValidationError
from django.db import ProgrammingError, transaction

from shared.models.linkage import CVEDerivationClusterProposal

Status = CVEDerivationClusterProposal.Status
Reason = CVEDerivationClusterProposal.RejectionReason


@pytest.mark.parametrize("reason", [Reason.NO_MATCHES, Reason.MAX_MATCHES_EXCEEDED])
def test_tracker_reopens_machine_rejection(
    make_suggestion: Callable[..., CVEDerivationClusterProposal], reason: Reason
) -> None:
    suggestion = make_suggestion(status=Status.REJECTED, rejection_reason=reason)
    suggestion.status = Status.PENDING
    suggestion.rejection_reason = None
    suggestion.save()
    suggestion.refresh_from_db()
    assert suggestion.status == Status.PENDING


@pytest.mark.parametrize(
    "reason",
    [None, Reason.NOT_IN_NIXPKGS, Reason.KNOWN_VULNERABILITY, Reason.HARDWARE_ONLY_CPE],
)
def test_database_refuses_reopening_other_rejections(
    make_suggestion: Callable[..., CVEDerivationClusterProposal],
    reason: Reason | None,
) -> None:
    suggestion = make_suggestion(
        status=Status.REJECTED, rejection_reason=reason, comment="no"
    )
    suggestion.status = Status.PENDING
    suggestion.rejection_reason = None
    with pytest.raises(ProgrammingError), transaction.atomic():
        suggestion.save()


def test_users_cannot_reopen_a_machine_rejection(
    make_suggestion: Callable[..., CVEDerivationClusterProposal],
) -> None:
    suggestion = make_suggestion(
        status=Status.REJECTED, rejection_reason=Reason.NO_MATCHES
    )
    with pytest.raises(ValidationError):
        suggestion.check_change_status(Status.PENDING)
