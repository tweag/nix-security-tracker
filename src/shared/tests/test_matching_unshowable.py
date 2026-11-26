from collections.abc import Callable

from django.test import override_settings

from shared.matching.reconcile import reconcile_matches
from shared.models.linkage import CVEDerivationClusterProposal
from shared.models.matching import Match, TrackerEvent
from shared.models.snapshot import BranchPackage

MakePackage = Callable[..., BranchPackage]


def stored(suggestion: CVEDerivationClusterProposal) -> set[tuple[str, str]]:
    return set(
        Match.objects.active()
        .filter(suggestion=suggestion)
        .values_list("matcher", "attrpath")
    )


def test_unshowable_matches_are_stored_by_default(
    suggestion: CVEDerivationClusterProposal, make_branch_package: MakePackage
) -> None:
    make_branch_package(attrpath="libfoo_bar", pname="libfoo_bar")
    reconcile_matches(suggestion, TrackerEvent.Cause.MATCHER)
    assert ("name-substring", "libfoo_bar") in stored(suggestion)


@override_settings(MATCHING_STORE_UNSHOWABLE=False)
def test_matches_of_attributes_that_cannot_be_shown_are_not_stored(
    suggestion: CVEDerivationClusterProposal, make_branch_package: MakePackage
) -> None:
    make_branch_package()  # `foo`: exact and substring
    make_branch_package(attrpath="libfoo_bar", pname="libfoo_bar")  # substring only
    result = reconcile_matches(suggestion, TrackerEvent.Cause.MATCHER)
    assert stored(suggestion) == {("name-exact", "foo"), ("name-substring", "foo")}
    assert ("name-substring", "libfoo_bar") not in result.added

    # A partial run counts the stored matches of the other matchers.
    reconcile_matches(suggestion, TrackerEvent.Cause.MATCHER, ["name-substring"])
    assert ("name-substring", "foo") in stored(suggestion)


@override_settings(MATCHING_STORE_UNSHOWABLE=False)
def test_turning_storage_off_retracts_stored_unshowable_matches(
    suggestion: CVEDerivationClusterProposal, make_branch_package: MakePackage
) -> None:
    make_branch_package(attrpath="libfoo_bar", pname="libfoo_bar")
    with override_settings(MATCHING_STORE_UNSHOWABLE=True):
        reconcile_matches(suggestion, TrackerEvent.Cause.MATCHER)
    assert stored(suggestion) == {("name-substring", "libfoo_bar")}
    result = reconcile_matches(suggestion, TrackerEvent.Cause.MATCHER)
    assert result.retracted == [("name-substring", "libfoo_bar")]
    assert reconcile_matches(suggestion, TrackerEvent.Cause.MATCHER).events == 0
