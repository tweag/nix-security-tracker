from collections.abc import Callable
from io import StringIO
from unittest import mock

import pghistory
from django.contrib.auth.models import User
from django.core.management import call_command

from shared.models.linkage import CVEDerivationClusterProposal, ProvenanceFlags
from shared.models.matching import Match, Verdict
from shared.models.nix_evaluation import NixDerivation
from shared.projection import project_links

Status = CVEDerivationClusterProposal.Status
V = Verdict.Kind


def verdicts(
    suggestion: CVEDerivationClusterProposal,
) -> set[tuple[str, str, int | None]]:
    return set(
        Verdict.objects.filter(suggestion=suggestion).values_list(
            "attrpath", "verdict", "author_id"
        )
    )


def two_packages(
    make_drv: Callable[..., NixDerivation],
    make_cached_suggestion: Callable[..., CVEDerivationClusterProposal],
) -> CVEDerivationClusterProposal:
    return make_cached_suggestion(
        drvs={
            make_drv(pname="foo"): ProvenanceFlags.PACKAGE_NAME_MATCH,
            make_drv(pname="bar"): ProvenanceFlags.PACKAGE_NAME_MATCH,
        }
    )


def test_accepting_records_affected_for_shown_unignored(
    make_drv: Callable[..., NixDerivation],
    make_cached_suggestion: Callable[..., CVEDerivationClusterProposal],
    committer: User,
) -> None:
    suggestion = two_packages(make_drv, make_cached_suggestion)
    suggestion.ignore_packages(["bar"], committer)
    suggestion.change_status(Status.ACCEPTED, author=committer)
    assert verdicts(suggestion) == {
        ("foo", V.AFFECTED, committer.pk),
        ("bar", V.IRRELEVANT, committer.pk),
    }


def test_rejecting_an_accepted_suggestion_withdraws_acceptance(
    make_drv: Callable[..., NixDerivation],
    make_cached_suggestion: Callable[..., CVEDerivationClusterProposal],
    committer: User,
) -> None:
    suggestion = two_packages(make_drv, make_cached_suggestion)
    suggestion.ignore_packages(["bar"], committer)
    suggestion.change_status(Status.ACCEPTED, author=committer)
    suggestion.change_status(
        Status.REJECTED,
        rejection_reason=CVEDerivationClusterProposal.RejectionReason.NOT_IN_NIXPKGS,
        author=committer,
    )
    assert verdicts(suggestion) == {("bar", V.IRRELEVANT, committer.pk)}

    suggestion.change_status(Status.ACCEPTED, author=committer)
    assert ("foo", V.AFFECTED, committer.pk) in verdicts(suggestion)


def test_publishing_records_affected(
    make_drv: Callable[..., NixDerivation],
    make_cached_suggestion: Callable[..., CVEDerivationClusterProposal],
    committer: User,
) -> None:
    from shared.models.issue import NixpkgsIssue

    suggestion = two_packages(make_drv, make_cached_suggestion)
    CVEDerivationClusterProposal.objects.filter(pk=suggestion.pk).update(
        status=Status.ACCEPTED
    )
    issue = mock.MagicMock()
    with mock.patch.object(NixpkgsIssue, "create_nixpkgs_issue", return_value=issue):
        NixpkgsIssue.publish_suggestions([suggestion], "title", committer)
    issue.publish.assert_called_once()
    assert verdicts(suggestion) == {
        ("foo", V.AFFECTED, committer.pk),
        ("bar", V.AFFECTED, committer.pk),
    }


def test_accepted_attribute_stays_through_its_verdict(
    make_drv: Callable[..., NixDerivation],
    make_cached_suggestion: Callable[..., CVEDerivationClusterProposal],
    make_match: Callable[..., Match],
    committer: User,
) -> None:
    """Stickiness is the verdict now: an accepted attribute nothing matches stays linked."""
    suggestion = two_packages(make_drv, make_cached_suggestion)
    make_match(attrpath="foo", matcher="name-exact", suggestion=suggestion)
    suggestion.change_status(Status.ACCEPTED, author=committer)
    result = project_links(suggestion)
    assert result.removed_attributes == set()
    assert result.unmatched == {"bar"}


def test_backfill_records_acceptance_by_who_accepted(
    make_drv: Callable[..., NixDerivation],
    make_cached_suggestion: Callable[..., CVEDerivationClusterProposal],
    committer: User,
) -> None:
    suggestion = two_packages(make_drv, make_cached_suggestion)
    with pghistory.context(user=committer.pk):
        CVEDerivationClusterProposal.objects.filter(pk=suggestion.pk).update(
            status=Status.ACCEPTED
        )
    call_command("backfill_unified_model", stdout=StringIO())
    assert verdicts(suggestion) == {
        ("foo", V.AFFECTED, committer.pk),
        ("bar", V.AFFECTED, committer.pk),
    }
    call_command("backfill_unified_model", stdout=StringIO())
    assert Verdict.objects.count() == 2
