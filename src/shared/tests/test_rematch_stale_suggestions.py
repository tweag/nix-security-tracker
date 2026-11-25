from collections.abc import Callable, Iterator
from io import StringIO
from unittest import mock

import pytest
from django.core.management import call_command

from shared.channels import SuggestionRefreshChannel
from shared.matching.selection import current_matcher_versions
from shared.models.cve import Container
from shared.models.linkage import CVEDerivationClusterProposal
from shared.pipeline import stale_matchers


@pytest.fixture
def mock_notify() -> Iterator[mock.MagicMock]:
    with mock.patch(
        "shared.management.commands.rematch_stale_suggestions.pgpubsub.notify"
    ) as mocked:
        yield mocked


def test_no_stale_suggestions(db: None, mock_notify: mock.MagicMock) -> None:
    """Nothing to do when there are no PENDING/ACCEPTED suggestions on an outdated algorithm_version."""
    out = StringIO()
    call_command("rematch_stale_suggestions", stdout=out)

    assert "no stale suggestions; nothing to do.\n" == out.getvalue().lower()
    mock_notify.assert_not_called()


def _current(suggestion: CVEDerivationClusterProposal) -> CVEDerivationClusterProposal:
    CVEDerivationClusterProposal.objects.filter(pk=suggestion.pk).update(
        matcher_versions=current_matcher_versions()
    )
    return suggestion


def test_dispatches_stale_suggestion(
    cve: Container,
    make_suggestion: Callable[..., CVEDerivationClusterProposal],
    mock_notify: mock.MagicMock,
) -> None:
    """Open suggestions on an outdated algorithm_version are dispatched for rematch."""
    pending_suggestion = make_suggestion(container=cve, algorithm_version=0)
    accepted_suggestion = make_suggestion(
        container=cve,
        algorithm_version=0,
        status=CVEDerivationClusterProposal.Status.ACCEPTED,
    )
    make_suggestion(
        container=cve,
        algorithm_version=0,
        status=CVEDerivationClusterProposal.Status.REJECTED,
        rejection_reason=CVEDerivationClusterProposal.RejectionReason.NO_MATCHES,
    )
    make_suggestion(
        container=cve,
        algorithm_version=0,
        status=CVEDerivationClusterProposal.Status.PUBLISHED,
    )
    _current(make_suggestion(container=cve))

    out = StringIO()
    call_command("rematch_stale_suggestions", stdout=out)

    expected_calls = [
        mock.call(SuggestionRefreshChannel, pk=pending_suggestion.pk),
        mock.call(SuggestionRefreshChannel, pk=accepted_suggestion.pk),
    ]
    mock_notify.assert_has_calls(expected_calls, any_order=True)
    assert mock_notify.call_count == 2


def test_dispatches_suggestion_with_outdated_matcher_version(
    cve: Container,
    make_suggestion: Callable[..., CVEDerivationClusterProposal],
    mock_notify: mock.MagicMock,
) -> None:
    """A matcher version bump makes only the suggestions that did not run it stale."""
    stale = make_suggestion(container=cve)
    CVEDerivationClusterProposal.objects.filter(pk=stale.pk).update(
        matcher_versions={**current_matcher_versions(), "name-exact": 0}
    )
    _current(make_suggestion(container=cve))

    call_command("rematch_stale_suggestions", stdout=StringIO())

    mock_notify.assert_called_once_with(SuggestionRefreshChannel, pk=stale.pk)
    stale.refresh_from_db()
    assert stale_matchers(stale) == ["name-exact"]


def test_machine_rejections_only_on_request(
    cve: Container,
    make_suggestion: Callable[..., CVEDerivationClusterProposal],
    mock_notify: mock.MagicMock,
) -> None:
    rejected = make_suggestion(
        container=cve,
        algorithm_version=0,
        status=CVEDerivationClusterProposal.Status.REJECTED,
        rejection_reason=CVEDerivationClusterProposal.RejectionReason.NO_MATCHES,
    )
    call_command("rematch_stale_suggestions", stdout=StringIO())
    mock_notify.assert_not_called()

    call_command(
        "rematch_stale_suggestions", "--include-machine-rejected", stdout=StringIO()
    )
    mock_notify.assert_called_once_with(SuggestionRefreshChannel, pk=rejected.pk)
