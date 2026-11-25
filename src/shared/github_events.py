"""
Typed views on the parts of GitHub's GraphQL API we query.

Each class pairs the fragment that requests a piece of data with the code that interprets the response, so the query and its consumer cannot drift apart.
Fragments for single items are static and built once.
The repository fragment is built per batch, since GraphQL offers no lookup of several issues by number in one field, and each requested issue therefore gets its own aliased field.

Connections are fetched with a first page inside the batch query. When a `Pager` is given, the remaining pages are fetched with one follow-up query per page and connection; without one, a connection longer than its first page raises `TruncatedError`.
"""

from collections.abc import Callable, Iterable, Iterator
from dataclasses import dataclass
from functools import cache
from typing import Any

import github_graphql as schema
from django.utils.functional import classproperty
from github import Github
from sgqlc.operation import Fragment, Operation

from shared.models.issue import EventType, GitHubEvent


class TruncatedError(Exception):
    def __init__(self, number: int, what: str) -> None:
        super().__init__(f"{what} of #{number}")
        self.number = number
        self.what = what


Select = Callable[[Any], None]


class Pager:
    """Fetch the pages after the first of a connection of one issue or pull request."""

    PAGE_SIZE = 100

    def __init__(self, github: Github, owner: str, name: str) -> None:
        self.github = github
        self.owner = owner
        self.name = name
        self.requests = 0

    def page(
        self,
        kind: str,
        number: int,
        field: str,
        select: Select,
        after: str,
        **args: Any,
    ) -> Any:
        operation = Operation(schema.github.query_type)
        item = getattr(operation.repository(owner=self.owner, name=self.name), kind)(
            number=number
        )
        connection = getattr(item, field)(
            first=self.PAGE_SIZE, after=after, __alias__="page", **args
        )
        connection.page_info.has_next_page()
        connection.page_info.end_cursor()
        select(connection.nodes)
        _, response = self.github.requester.graphql_query(str(operation), {})
        self.requests += 1
        data = operation + response
        return getattr(data.repository, kind).page


def select_page_info(connection: Any) -> None:
    connection.page_info.has_next_page()
    connection.page_info.end_cursor()


def collect(
    page: Any,
    more: Callable[[str], Any] | None,
    number: int,
    what: str,
) -> list[Any]:
    """All nodes of a connection, following pages with `more` (or raising without it)."""
    result = list(page.nodes or [])
    while page.page_info.has_next_page:
        if more is None:
            raise TruncatedError(number, what)
        page = more(page.page_info.end_cursor)
        result.extend(page.nodes or [])
    return result


class PullRequest:
    TIMELINE_TYPES = ["CLOSED_EVENT", "REOPENED_EVENT", "MERGED_EVENT"]

    @classproperty
    @cache
    def closed(cls) -> Fragment:
        fragment = Fragment(schema.ClosedEvent, "PullRequestClosed")
        fragment.created_at()
        return fragment

    @classproperty
    @cache
    def reopened(cls) -> Fragment:
        fragment = Fragment(schema.ReopenedEvent, "PullRequestReopened")
        fragment.created_at()
        return fragment

    @classproperty
    @cache
    def merged(cls) -> Fragment:
        fragment = Fragment(schema.MergedEvent, "PullRequestMerged")
        fragment.created_at()
        return fragment

    @classproperty
    @cache
    def label(cls) -> Fragment:
        fragment = Fragment(schema.Label, "LabelName")
        fragment.name()
        return fragment

    @staticmethod
    def select_timeline(nodes: Any) -> None:
        nodes.__fragment__(PullRequest.closed)
        nodes.__fragment__(PullRequest.reopened)
        nodes.__fragment__(PullRequest.merged)

    @staticmethod
    def select_labels(nodes: Any) -> None:
        nodes.__fragment__(PullRequest.label)

    @classproperty
    @cache
    def fragment(cls) -> Fragment:
        fragment = Fragment(schema.PullRequest, "PullRequestHistory")
        fragment.number()
        fragment.created_at()
        fragment.title()
        fragment.base_ref_name()
        fragment.merge_commit.oid()
        fragment.base_repository.name_with_owner()
        labels = fragment.labels(first=20)
        select_page_info(labels)
        cls.select_labels(labels.nodes)
        timeline = fragment.timeline_items(first=20, item_types=cls.TIMELINE_TYPES)
        select_page_info(timeline)
        cls.select_timeline(timeline.nodes)
        return fragment

    @classproperty
    @cache
    def cross_referenced(cls) -> Fragment:
        fragment = Fragment(schema.CrossReferencedEvent, "PullRequestCrossReferenced")
        fragment.created_at()
        fragment.source.__fragment__(cls.fragment)
        return fragment

    @staticmethod
    def select_references(nodes: Any) -> None:
        nodes.__fragment__(PullRequest.cross_referenced)

    @classproperty
    @cache
    def with_references(cls) -> Fragment:
        """A pull request and the pull requests that mention it (bot backports do)."""
        fragment = Fragment(schema.PullRequest, "PullRequestReferences")
        fragment.__fragment__(cls.fragment)
        references = fragment.timeline_items(
            first=20, item_types=["CROSS_REFERENCED_EVENT"], __alias__="references"
        )
        select_page_info(references)
        cls.select_references(references.nodes)
        return fragment

    def __init__(self, data: schema.PullRequest, pager: Pager | None = None) -> None:
        self.data = data
        self.pager = pager
        self._labels: list[str] | None = None

    def _more(
        self, field: str, select: Select, **args: Any
    ) -> Callable[[str], Any] | None:
        pager = self.pager
        if pager is None:
            return None
        return lambda after: pager.page(
            "pull_request", self.number, field, select, after, **args
        )

    @property
    def number(self) -> int:
        return self.data.number

    @property
    def repository(self) -> str | None:
        if repository := self.data.base_repository:
            return repository.name_with_owner
        return None

    @property
    def title(self) -> str:
        return self.data.title or ""

    @property
    def base_ref(self) -> str | None:
        return self.data.base_ref_name or None

    @property
    def merge_commit(self) -> str | None:
        if commit := self.data.merge_commit:
            return commit.oid
        return None

    def labels(self) -> list[str]:
        if self._labels is None:
            self._labels = [
                node.name
                for node in collect(
                    self.data.labels,
                    self._more("labels", self.select_labels),
                    self.number,
                    "labels",
                )
            ]
        return self._labels

    def references(self) -> list["PullRequest"]:
        """Pull requests mentioning this one, from `with_references`."""
        return [
            PullRequest(node.source, self.pager)
            for node in collect(
                self.data.references,
                self._more(
                    "timeline_items",
                    self.select_references,
                    item_types=["CROSS_REFERENCED_EVENT"],
                ),
                self.number,
                "references",
            )
            if isinstance(node, schema.CrossReferencedEvent)
            and isinstance(node.source, schema.PullRequest)
        ]

    def events(self) -> Iterator[GitHubEvent]:
        yield GitHubEvent(
            event_type=EventType.PULL_REQUEST_OPENED,
            occurred_at=self.data.created_at,
        )
        timeline = collect(
            self.data.timeline_items,
            self._more(
                "timeline_items", self.select_timeline, item_types=self.TIMELINE_TYPES
            ),
            self.number,
            "timeline",
        )
        # GitHub records a PR being merged as both a merge and a close event, the close event at the same moment or shortly after.
        # Recording both would leave two latest events in unknown order, and a merged pull request may end up showing as merely closed.
        # We therefore filter those cases.
        # A merged pull request can't be reopened, so the merge's close is its last one.
        merge_close = (
            next(
                (
                    node
                    for node in reversed(timeline)
                    if isinstance(node, schema.ClosedEvent)
                ),
                None,
            )
            if any(isinstance(node, schema.MergedEvent) for node in timeline)
            else None
        )
        for node in timeline:
            match node:
                case schema.MergedEvent():
                    yield GitHubEvent(
                        event_type=EventType.PULL_REQUEST_MERGED,
                        occurred_at=node.created_at,
                    )
                case schema.ClosedEvent() if node is merge_close:
                    continue
                case schema.ClosedEvent():
                    yield GitHubEvent(
                        event_type=EventType.PULL_REQUEST_CLOSED,
                        occurred_at=node.created_at,
                    )
                case schema.ReopenedEvent():
                    yield GitHubEvent(
                        event_type=EventType.PULL_REQUEST_OPENED,
                        occurred_at=node.created_at,
                    )
                case _:
                    raise ValueError(f"Unexpected timeline item: {type(node).__name__}")


@dataclass(frozen=True)
class Reference:
    """A pull request linked to an issue other than by a closing keyword on the default branch."""

    pull_request: PullRequest
    # "connected" (linked in the development sidebar or by a closing keyword) or "cross_reference".
    kind: str


class Issue:
    TIMELINE_TYPES = ["CLOSED_EVENT", "REOPENED_EVENT"]
    REFERENCE_TYPES = [
        "CONNECTED_EVENT",
        "DISCONNECTED_EVENT",
        "CROSS_REFERENCED_EVENT",
    ]

    @classproperty
    @cache
    def closed(cls) -> Fragment:
        fragment = Fragment(schema.ClosedEvent, "IssueClosed")
        fragment.created_at()
        fragment.state_reason()
        return fragment

    @classproperty
    @cache
    def reopened(cls) -> Fragment:
        fragment = Fragment(schema.ReopenedEvent, "IssueReopened")
        fragment.created_at()
        return fragment

    @classproperty
    @cache
    def connected(cls) -> Fragment:
        fragment = Fragment(schema.ConnectedEvent, "IssueConnected")
        fragment.created_at()
        fragment.subject.__fragment__(PullRequest.fragment)
        return fragment

    @classproperty
    @cache
    def pull_request_number(cls) -> Fragment:
        fragment = Fragment(schema.PullRequest, "PullRequestNumber")
        fragment.number()
        return fragment

    @classproperty
    @cache
    def disconnected(cls) -> Fragment:
        fragment = Fragment(schema.DisconnectedEvent, "IssueDisconnected")
        fragment.created_at()
        fragment.subject.__fragment__(cls.pull_request_number)
        return fragment

    @classproperty
    @cache
    def cross_referenced(cls) -> Fragment:
        fragment = Fragment(schema.CrossReferencedEvent, "IssueCrossReferenced")
        fragment.created_at()
        fragment.source.__fragment__(PullRequest.fragment)
        return fragment

    @staticmethod
    def select_timeline(nodes: Any) -> None:
        nodes.__fragment__(Issue.closed)
        nodes.__fragment__(Issue.reopened)

    @staticmethod
    def select_references(nodes: Any) -> None:
        nodes.__fragment__(Issue.connected)
        nodes.__fragment__(Issue.disconnected)
        nodes.__fragment__(Issue.cross_referenced)

    @staticmethod
    def select_closing(nodes: Any) -> None:
        nodes.__fragment__(PullRequest.fragment)

    @classproperty
    @cache
    def fragment(cls) -> Fragment:
        fragment = Fragment(schema.Issue, "IssueHistory")
        fragment.number()
        fragment.created_at()
        timeline = fragment.timeline_items(first=20, item_types=cls.TIMELINE_TYPES)
        select_page_info(timeline)
        cls.select_timeline(timeline.nodes)
        references = fragment.timeline_items(
            first=20, item_types=cls.REFERENCE_TYPES, __alias__="references"
        )
        select_page_info(references)
        cls.select_references(references.nodes)
        closing = fragment.closed_by_pull_requests_references(
            first=10, include_closed_prs=True
        )
        select_page_info(closing)
        cls.select_closing(closing.nodes)
        return fragment

    def __init__(self, data: schema.Issue, pager: Pager | None = None) -> None:
        self.data = data
        self.pager = pager

    def _more(
        self, field: str, select: Select, **args: Any
    ) -> Callable[[str], Any] | None:
        pager = self.pager
        if pager is None:
            return None
        return lambda after: pager.page(
            "issue", self.number, field, select, after, **args
        )

    @property
    def number(self) -> int:
        return self.data.number

    def events(self) -> Iterator[GitHubEvent]:
        yield GitHubEvent(
            event_type=EventType.ISSUE_OPENED,
            occurred_at=self.data.created_at,
        )
        timeline = collect(
            self.data.timeline_items,
            self._more(
                "timeline_items", self.select_timeline, item_types=self.TIMELINE_TYPES
            ),
            self.number,
            "timeline",
        )
        for node in timeline:
            match node:
                case schema.ClosedEvent():
                    match node.state_reason:
                        case "COMPLETED":
                            event_type = EventType.ISSUE_COMPLETED
                        case "NOT_PLANNED":
                            event_type = EventType.ISSUE_NOT_PLANNED
                        case "DUPLICATE":
                            event_type = EventType.ISSUE_DUPLICATE
                        case _:
                            raise ValueError(
                                f"Unexpected close reason: {node.state_reason}"
                            )
                    yield GitHubEvent(
                        event_type=event_type,
                        occurred_at=node.created_at,
                    )
                case schema.ReopenedEvent():
                    yield GitHubEvent(
                        event_type=EventType.ISSUE_OPENED,
                        occurred_at=node.created_at,
                    )
                case _:
                    raise ValueError(f"Unexpected timeline item: {type(node).__name__}")

    def closing_pull_requests(self) -> Iterator[PullRequest]:
        for node in collect(
            self.data.closed_by_pull_requests_references,
            self._more(
                "closed_by_pull_requests_references",
                self.select_closing,
                include_closed_prs=True,
            ),
            self.number,
            "closing pull requests",
        ):
            yield PullRequest(node, self.pager)

    def references(self) -> list[Reference]:
        """
        Pull requests connected to the issue (and not disconnected later) and pull requests
        that mention it. Connected pull requests are those GitHub lists as closing
        references, and the ones linked by hand.
        """
        nodes = collect(
            self.data.references,
            self._more(
                "timeline_items",
                self.select_references,
                item_types=self.REFERENCE_TYPES,
            ),
            self.number,
            "references",
        )
        connected: dict[int, PullRequest] = {}
        mentioned: dict[int, PullRequest] = {}
        for node in nodes:
            match node:
                case schema.ConnectedEvent() if isinstance(
                    node.subject, schema.PullRequest
                ):
                    connected[node.subject.number] = PullRequest(
                        node.subject, self.pager
                    )
                case schema.DisconnectedEvent() if isinstance(
                    node.subject, schema.PullRequest
                ):
                    connected.pop(node.subject.number, None)
                case schema.CrossReferencedEvent() if isinstance(
                    node.source, schema.PullRequest
                ):
                    mentioned[node.source.number] = PullRequest(node.source, self.pager)
        return [Reference(pr, "connected") for pr in connected.values()] + [
            Reference(pr, "cross_reference")
            for number, pr in mentioned.items()
            if number not in connected
        ]


class Repository:
    @staticmethod
    def alias(number: int) -> str:
        return f"issue{number}"

    @classmethod
    def fragment(cls, numbers: Iterable[int]) -> Fragment:
        fragment = Fragment(schema.Repository, "RepositoryIssues")
        for number in numbers:
            fragment.issue(number=number, __alias__=cls.alias(number)).__fragment__(
                Issue.fragment
            )
        return fragment

    @staticmethod
    def pull_request_alias(number: int) -> str:
        return f"pr{number}"

    @classmethod
    def pull_requests_fragment(cls, numbers: Iterable[int]) -> Fragment:
        fragment = Fragment(schema.Repository, "RepositoryPullRequests")
        for number in numbers:
            fragment.pull_request(
                number=number, __alias__=cls.pull_request_alias(number)
            ).__fragment__(PullRequest.with_references)
        return fragment

    def __init__(self, data: schema.Repository, pager: Pager | None = None) -> None:
        self.data = data
        self.pager = pager

    def issues(self, numbers: Iterable[int]) -> Iterator[Issue]:
        for number in numbers:
            if data := getattr(self.data, self.alias(number)):
                yield Issue(data, self.pager)

    def pull_requests(self, numbers: Iterable[int]) -> Iterator[PullRequest]:
        for number in numbers:
            if data := getattr(self.data, self.pull_request_alias(number), None):
                yield PullRequest(data, self.pager)
