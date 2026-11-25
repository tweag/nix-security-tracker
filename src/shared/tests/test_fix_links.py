from collections.abc import Callable, Iterator
from datetime import UTC, datetime, timedelta

import pytest
import responses
from django.utils import timezone
from github import Github

from shared.fix_links import (
    FoundLink,
    attrpath_from_title,
    backport_branches,
    confirm_fix_links,
    polled_issue_items,
    resolve_branch,
    update_fix_links,
)
from shared.ingest_github_events import sync_github_events
from shared.models.issue import (
    ISSUE_COMPLETED,
    PULL_REQUEST_MERGED,
    GitHubItem,
    NixpkgsIssue,
)
from shared.models.linkage import CVEDerivationClusterProposal
from shared.models.matching import Exposure, TrackerEvent
from shared.models.nix_evaluation import NixEvaluation, NixpkgsBranch
from shared.models.remediation import FixLink
from shared.tests.fake_github import (
    GRAPHQL_URL,
    ClosedEvent,
    ConnectedEvent,
    CrossReferencedEvent,
    DisconnectedEvent,
    FakeGitHub,
    Issue,
    MergedEvent,
    PullRequest,
    ReopenedEvent,
)

Source = FixLink.Source
Kind = TrackerEvent.Kind
D = datetime(2026, 10, 1, tzinfo=UTC)
KNOWN = {"master", "release-26.05", "release-25.11"}


@pytest.fixture
def fake_github() -> Iterator[FakeGitHub]:
    fake = FakeGitHub()
    with responses.RequestsMock(assert_all_requests_are_fired=False) as mock:
        mock.add_callback(responses.POST, GRAPHQL_URL, callback=fake.handle)
        yield fake


@pytest.fixture
def branches(make_branch: Callable[..., NixpkgsBranch]) -> dict[str, NixpkgsBranch]:
    return {name: make_branch(name) for name in sorted(KNOWN)}


@pytest.fixture
def published(
    issue: NixpkgsIssue, make_match: Callable[..., object]
) -> tuple[GitHubItem, CVEDerivationClusterProposal]:
    """A published issue whose suggestion has `foo` as a candidate."""
    item = GitHubItem.objects.create(
        owner="NixOS", repository="nixpkgs", number=1, kind=GitHubItem.Kind.ISSUE
    )
    item.nixpkgs_issues.add(issue)
    suggestion = issue.suggestions.get()
    make_match("foo", matcher="name-exact", suggestion=suggestion)
    return item, suggestion


@pytest.mark.parametrize(
    ("base", "branch"),
    [
        ("master", "master"),
        ("staging", "master"),
        ("staging-next", "master"),
        ("staging-nixos", "master"),
        ("release-26.05", "release-26.05"),
        ("staging-26.05", "release-26.05"),
        ("staging-next-26.05", "release-26.05"),
        ("staging-nixos-26.05", "release-26.05"),
        ("staging-24.05", None),
        ("haskell-updates", None),
        (None, None),
    ],
)
def test_resolve_branch(base: str | None, branch: str | None) -> None:
    assert resolve_branch(base, KNOWN) == branch


def test_backport_branches_and_titles() -> None:
    assert backport_branches(
        ["backport release-26.05", "8.has: port to stable", "backport staging-25.11"]
    ) == ["release-26.05", "staging-25.11"]
    candidates = {"foo", "python3Packages.bar"}
    assert attrpath_from_title("foo: 1.0 -> 1.1", candidates) == "foo"
    assert (
        attrpath_from_title(
            "[Backport release-26.05] python3Packages.bar: 2 -> 3", candidates
        )
        == "python3Packages.bar"
    )
    assert attrpath_from_title("[release-25.11] foo: patch CVE", candidates) == "foo"
    assert attrpath_from_title("baz: 1 -> 2", candidates) is None
    assert attrpath_from_title("foo 1.0 -> 1.1", candidates) is None


def links(suggestion: CVEDerivationClusterProposal) -> set[tuple[int, str, str | None]]:
    return set(
        FixLink.objects.live()
        .filter(suggestion=suggestion)
        .values_list("item__number", "source", "branch_id")
    )


def test_sync_discovers_links_and_backports(
    published: tuple[GitHubItem, CVEDerivationClusterProposal],
    branches: dict[str, NixpkgsBranch],
    fake_github: FakeGitHub,
) -> None:
    _, suggestion = published
    bot_backport = PullRequest(
        "NixOS/nixpkgs",
        5,
        created_at=D + timedelta(days=2),
        title="[Backport release-26.05] foo: 1.0 -> 1.1",
        base_ref_name="release-26.05",
    )
    unrelated = PullRequest(
        "NixOS/nixpkgs",
        6,
        created_at=D + timedelta(days=2),
        title="treewide: something",
        base_ref_name="master",
    )
    original = PullRequest(
        "NixOS/nixpkgs",
        2,
        created_at=D,
        title="foo: 1.0 -> 1.1",
        base_ref_name="staging",
        merge_commit_oid="a" * 40,
        label_names=["backport release-26.05"],
        timeline=[
            MergedEvent(created_at=D + timedelta(days=1)),
            CrossReferencedEvent(created_at=D + timedelta(days=2), source=bot_backport),
            CrossReferencedEvent(created_at=D + timedelta(days=2), source=unrelated),
        ],
    )
    manual_backport = PullRequest(
        "NixOS/nixpkgs",
        3,
        created_at=D,
        title="[release-25.11] foo: patch",
        base_ref_name="staging-25.11",
    )
    mention = PullRequest("NixOS/nixpkgs", 4, created_at=D, base_ref_name="master")
    fake_github.items = [
        Issue(
            "NixOS/nixpkgs",
            1,
            created_at=D,
            closed_by=[original],
            timeline=[
                ConnectedEvent(created_at=D, subject=original),
                ConnectedEvent(created_at=D, subject=manual_backport),
                CrossReferencedEvent(created_at=D, source=mention),
            ],
        ),
        original,
        manual_backport,
        mention,
        bot_backport,
        unrelated,
    ]

    result = sync_github_events(Github())

    assert links(suggestion) == {
        (2, Source.CLOSING_REFERENCE, "master"),
        (2, Source.CONNECTED, "master"),
        (3, Source.CONNECTED, "release-25.11"),
        (4, Source.CROSS_REFERENCE, "master"),
        (5, Source.BACKPORT, "release-26.05"),
        (2, Source.BACKPORT_LABEL, "release-26.05"),
    }
    assert result.added == 6
    backport = GitHubItem.objects.get(number=5)
    assert (backport.backport_of, backport.base_ref) == (2, "release-26.05")
    assert not GitHubItem.objects.filter(number=6).exists()
    # The candidate attribute `foo` is named by the backport's title.
    assert set(
        FixLink.objects.filter(item__number=5).values_list("attrpath", flat=True)
    ) == {"foo"}
    events = TrackerEvent.objects.filter(
        suggestion=suggestion, kind=Kind.FIX_LINK_ADDED
    )
    assert events.count() == 6
    assert {e.cause for e in events} == {TrackerEvent.Cause.GITHUB}

    # Idempotent.
    assert sync_github_events(Github()).added == 0

    # A link that disappears is retracted, with an event.
    fake_github.items[0].timeline = [  # type: ignore[union-attr]
        ConnectedEvent(created_at=D, subject=original),
        ConnectedEvent(created_at=D, subject=manual_backport),
        DisconnectedEvent(created_at=D + timedelta(hours=1), subject=manual_backport),
    ]
    result = sync_github_events(Github())
    assert result.retracted == 2
    assert (3, Source.CONNECTED, "release-25.11") not in links(suggestion)
    assert (4, Source.CROSS_REFERENCE, "master") not in links(suggestion)
    assert (
        TrackerEvent.objects.filter(
            suggestion=suggestion, kind=Kind.FIX_LINK_RETRACTED
        ).count()
        == 2
    )


def test_title_names_the_attribute(
    published: tuple[GitHubItem, CVEDerivationClusterProposal],
    branches: dict[str, NixpkgsBranch],
) -> None:
    item, suggestion = published
    pr = GitHubItem.objects.create(
        owner="NixOS",
        repository="nixpkgs",
        number=2,
        kind=GitHubItem.Kind.PULL_REQUEST,
        title="foo: 1.0 -> 1.1",
        base_ref="master",
    )
    update_fix_links(item, [FoundLink(pr, Source.CLOSING_REFERENCE)])
    link = FixLink.objects.get()
    assert (link.attrpath, link.branch_id) == ("foo", "master")


def test_poll_is_restricted_to_open_or_unresolved(
    published: tuple[GitHubItem, CVEDerivationClusterProposal],
    branches: dict[str, NixpkgsBranch],
    make_exposure: Callable[..., Exposure],
    make_channel: Callable[..., object],
    evaluation: NixEvaluation,
) -> None:
    item, suggestion = published
    make_channel("nixos-26.05", release_branch=branches["release-26.05"])
    assert set(polled_issue_items()) == {item}  # never synced: open
    item.events.create(event_type=ISSUE_COMPLETED, occurred_at=D)
    assert set(polled_issue_items()) == set()
    exposure = make_exposure(suggestion=suggestion, branch=branches["release-26.05"])
    assert set(polled_issue_items()) == {item}  # still affected on a branch
    Exposure.objects.filter(pk=exposure.pk).update(
        observed=Exposure.Observed.UNAFFECTED, fixed_evaluation=evaluation
    )
    assert set(polled_issue_items()) == {item}  # fixed recently, fix commit unknown
    Exposure.objects.filter(pk=exposure.pk).update(fix_commit="c" * 40)
    assert set(polled_issue_items()) == set()
    # Only candidates on tracked branches keep an issue polled.
    hidden = make_exposure(
        attrpath="hidden", suggestion=suggestion, branch=branches["release-26.05"]
    )
    assert set(polled_issue_items()) == set()
    Exposure.objects.filter(pk=hidden.pk).update(
        attrpath="foo", branch=branches["release-25.11"]
    )
    assert set(polled_issue_items()) == set()


class Setup:
    def __init__(
        self,
        suggestion: CVEDerivationClusterProposal,
        make_evaluation: Callable[..., NixEvaluation],
        make_exposure: Callable[..., Exposure],
        branch: NixpkgsBranch,
    ) -> None:
        self.before = make_evaluation(age=timedelta(days=3))
        self.after = make_evaluation(age=timedelta(days=1))
        self.exposure = make_exposure(
            suggestion=suggestion,
            branch=branch,
            observed=Exposure.Observed.UNAFFECTED,
            version="1.1",
            first_affected_evaluation=self.before,
            last_affected_evaluation=self.before,
            fixed_evaluation=self.after,
            evaluation=self.after,
        )
        self.suggestion = suggestion
        self.branch = branch

    def pull_request(
        self, number: int, merged_ago: timedelta | None, merge: str
    ) -> FixLink:
        pr = GitHubItem.objects.create(
            owner="NixOS",
            repository="nixpkgs",
            number=number,
            kind=GitHubItem.Kind.PULL_REQUEST,
            base_ref=self.branch.name,
            merge_commit=merge if merged_ago is not None else None,
        )
        if merged_ago is not None:
            pr.events.create(
                event_type=PULL_REQUEST_MERGED, occurred_at=timezone.now() - merged_ago
            )
        return FixLink.objects.create(
            suggestion=self.suggestion,
            item=pr,
            source=Source.CLOSING_REFERENCE,
            branch=self.branch,
        )


@pytest.fixture
def setup(
    published: tuple[GitHubItem, CVEDerivationClusterProposal],
    make_evaluation: Callable[..., NixEvaluation],
    make_exposure: Callable[..., Exposure],
    branch: NixpkgsBranch,
) -> Setup:
    return Setup(published[1], make_evaluation, make_exposure, branch)


def test_merged_link_sets_fix_commit_by_time(setup: Setup) -> None:
    link = setup.pull_request(2, timedelta(days=2), "a" * 40)
    setup.pull_request(
        3, timedelta(hours=1), "b" * 40
    )  # merged after the fix evaluation
    setup.pull_request(4, None, "c" * 40)  # not merged

    result = confirm_fix_links()

    assert result.confirmed == 1
    setup.exposure.refresh_from_db()
    assert setup.exposure.fix_commit == "a" * 40
    link.refresh_from_db()
    assert link.confirmed
    event = TrackerEvent.objects.get(kind=Kind.EXPOSURE_FIX_COMMIT_SET)
    assert event.data | {} == {
        "fix_commit": "a" * 40,
        "pull_request": 2,
        "source": Source.CLOSING_REFERENCE,
        "method": "time",
    }
    assert confirm_fix_links().confirmed == 0


def test_ancestry_decides_over_time(setup: Setup) -> None:
    setup.pull_request(2, timedelta(days=2), "a" * 40)
    setup.pull_request(3, timedelta(days=2), "b" * 40)

    class Ancestry:
        def contains(self, head: str, commit: str) -> bool | None:
            return head == setup.after.commit_sha1 and commit == "b" * 40

    assert confirm_fix_links(Ancestry()).confirmed == 1
    setup.exposure.refresh_from_db()
    assert setup.exposure.fix_commit == "b" * 40
    assert (
        TrackerEvent.objects.get(kind=Kind.EXPOSURE_FIX_COMMIT_SET).data["method"]
        == "ancestry"
    )


def test_ambiguous_links_stay_claims(setup: Setup) -> None:
    setup.pull_request(2, timedelta(days=2), "a" * 40)
    setup.pull_request(3, timedelta(days=2), "b" * 40)
    result = confirm_fix_links()
    assert (result.confirmed, result.ambiguous) == (0, 1)
    setup.exposure.refresh_from_db()
    assert setup.exposure.fix_commit is None


def test_link_on_another_branch_does_not_confirm(
    setup: Setup, make_branch: Callable[..., NixpkgsBranch]
) -> None:
    link = setup.pull_request(2, timedelta(days=2), "a" * 40)
    FixLink.objects.filter(pk=link.pk).update(branch=make_branch("release-26.05"))
    assert confirm_fix_links().confirmed == 0


def backported_original(cross_referenced: bool) -> list[Issue | PullRequest]:
    timeline: list[ClosedEvent | ReopenedEvent | MergedEvent | CrossReferencedEvent] = [
        MergedEvent(created_at=D)
    ]
    bot = PullRequest(
        "NixOS/nixpkgs",
        5,
        created_at=D,
        title="[Backport release-26.05] foo: 1.0 -> 1.1",
        base_ref_name="release-26.05",
    )
    if cross_referenced:
        timeline.append(CrossReferencedEvent(created_at=D, source=bot))
    original = PullRequest(
        "NixOS/nixpkgs",
        2,
        created_at=D,
        title="foo: 1.0 -> 1.1",
        merge_commit_oid="a" * 40,
        label_names=["backport release-26.05"],
        timeline=timeline,
    )
    return [
        Issue("NixOS/nixpkgs", 1, created_at=D, closed_by=[original]),
        original,
        bot,
    ]


@pytest.mark.parametrize("visible", [True, False])
def test_sync_reports_whether_cross_references_are_visible(
    published: tuple[GitHubItem, CVEDerivationClusterProposal],
    branches: dict[str, NixpkgsBranch],
    fake_github: FakeGitHub,
    caplog: pytest.LogCaptureFixture,
    visible: bool,
) -> None:
    """Without visible cross-references, discovery is reduced but works, and says so."""
    _, suggestion = published
    fake_github.items = backported_original(cross_referenced=visible)

    result = sync_github_events(Github())

    assert (result.issues, result.issues_without_cross_references) == (1, 1)
    assert (
        result.labelled_originals,
        result.labelled_originals_without_cross_references,
    ) == (
        1,
        0 if visible else 1,
    )
    assert result.cross_references_visible is visible
    found = links(suggestion)
    assert (2, Source.CLOSING_REFERENCE, "master") in found
    assert (2, Source.BACKPORT_LABEL, "release-26.05") in found
    assert ((5, Source.BACKPORT, "release-26.05") in found) is visible
    warned = any("does not see cross-references" in r.message for r in caplog.records)
    assert warned is not visible


def test_sync_command_prints_visibility(
    published: tuple[GitHubItem, CVEDerivationClusterProposal],
    branches: dict[str, NixpkgsBranch],
    fake_github: FakeGitHub,
) -> None:
    from io import StringIO
    from unittest import mock

    from django.core.management import call_command

    fake_github.items = backported_original(cross_referenced=False)
    out = StringIO()
    with mock.patch(
        "shared.management.commands.sync_github_events.get_gh", return_value=Github()
    ):
        call_command("sync_github_events", stdout=out)
    assert "none on 1 of 1 with a backport label; visible to this token: NO" in (
        out.getvalue()
    )
