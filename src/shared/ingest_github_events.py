"""
Record what happened on GitHub to the issues we published, and which pull requests fix them.

Per polled issue (`polled_issue_items`): its open/close history, its closing references (kept
as `GitHubClosingReference`), the pull requests connected to or mentioning it, and, for the
merged ones into the tracking branch, the release-branch pull requests mentioning those (bot
backports reference the original, not the issue) and their `backport <branch>` labels. All
of it becomes `FixLink` rows of the issue's suggestions; merged links whose branch was then
observed fixed set `Exposure.fix_commit` (`confirm_fix_links`).
"""

import logging
import time
import uuid
from itertools import batched, groupby

import github_graphql as schema
from django.conf import settings
from github import Github, GithubException
from sgqlc.operation import Operation

from shared.fix_links import (
    FoundLink,
    LinkResult,
    backport_branches,
    confirm_fix_links,
    polled_issue_items,
    resolve_branch,
    update_fix_links,
)
from shared.github_events import Pager, PullRequest, Repository, TruncatedError
from shared.history import CachedAncestry, HistoryClone
from shared.models.issue import (
    EventType,
    GitHubClosingReference,
    GitHubItem,
    GitHubSyncError,
)
from shared.models.nix_evaluation import NixpkgsBranch
from shared.models.remediation import FixLink

logger = logging.getLogger(__name__)

# Large enough to save requests, small enough to stay clear of GitHub's query timeouts.
BATCH_SIZE = 200


def record_pull_request(
    owner: str,
    name: str,
    data: PullRequest,
    events: list | None = None,
    backport_of: int | None = None,
) -> GitHubItem:
    """Create or update the item of a pull request with its fields and events."""
    fields = {
        "title": data.title,
        "base_ref": data.base_ref,
        "merge_commit": data.merge_commit,
        "labels": sorted(data.labels()),
    }
    if backport_of is not None:
        fields["backport_of"] = backport_of
    item, created = GitHubItem.objects.get_or_create(
        owner=owner,
        repository=name,
        number=data.number,
        defaults={"kind": GitHubItem.Kind.PULL_REQUEST, **fields},
    )
    if not created and any(getattr(item, k) != v for k, v in fields.items()):
        for k, v in fields.items():
            setattr(item, k, v)
        item.save(update_fields=list(fields))
    item.add_events(events if events is not None else data.events())
    return item


def discover_backports(
    pager: Pager,
    owner: str,
    name: str,
    originals: dict[int, GitHubItem],
    known: set[str],
    counts: LinkResult,
) -> dict[int, list[FoundLink]]:
    """
    Per original pull request number: the release-branch pull requests mentioning it, and its
    `backport <branch>` labels as intent. One query per `BATCH_SIZE` originals.
    """
    found: dict[int, list[FoundLink]] = {}
    for number, item in originals.items():
        found[number] = [
            FoundLink(item, FixLink.Source.BACKPORT_LABEL, branch_ref=branch)
            for branch in backport_branches(item.labels)
        ]
    for batch in batched(sorted(originals), BATCH_SIZE):
        operation = Operation(schema.github.query_type)
        operation.repository(owner=owner, name=name).__fragment__(
            Repository.pull_requests_fragment(batch)
        )
        try:
            _, response = pager.github.requester.graphql_query(str(operation), {})
            data = operation + response
            for original in Repository(data.repository, pager).pull_requests(batch):
                references = original.references()
                labelled = bool(backport_branches(originals[original.number].labels))
                counts.originals += 1
                counts.labelled_originals += labelled
                if not original.cross_reference_count:
                    counts.originals_without_cross_references += 1
                    counts.labelled_originals_without_cross_references += labelled
                for pr in references:
                    if pr.repository != f"{owner}/{name}":
                        continue
                    branch = resolve_branch(pr.base_ref, known)
                    if branch is None or branch == settings.TRACKING_BRANCH:
                        continue
                    backport = record_pull_request(
                        owner, name, pr, backport_of=original.number
                    )
                    found[original.number].append(
                        FoundLink(backport, FixLink.Source.BACKPORT)
                    )
        except GithubException as e:
            logger.error(f"{owner}/{name}: backport discovery failed for {batch}: {e}")
    return found


def sync_github_events(github: Github) -> LinkResult:
    """
    Fetch the history of the published issues worth polling from GitHub, record events not
    seen before, and update the fix links of their suggestions.
    """
    items = (
        polled_issue_items()
        .distinct()
        .order_by("owner", "repository", "number")
        .prefetch_related("nixpkgs_issues")
    )
    known = set(NixpkgsBranch.objects.values_list("name", flat=True))
    links = LinkResult(batch=uuid.uuid4())
    repositories = items.order_by().values("owner", "repository").distinct().count()
    logger.info(
        f"Syncing {items.count()} published GitHub issues in {repositories} repositories..."
    )
    synced = 0
    failed = 0
    start = time.monotonic()

    # NOTE(@fricklerhandwerk): While we currently don't support multiple source repositories,
    # item numbering is scoped per repository and thus it makes sense to arrange the query accordingly.
    for (owner, name), group in groupby(
        items, key=lambda item: (item.owner, item.repository)
    ):
        by_number = {item.number: item for item in group}
        pager = Pager(github, owner, name)
        logger.info(
            f"{owner}/{name}: Syncing GitHub events for {len(by_number)} issues..."
        )
        for batch in batched(by_number, BATCH_SIZE):
            operation = Operation(schema.github.query_type)
            operation.repository(owner=owner, name=name).__fragment__(
                Repository.fragment(batch)
            )
            batch_start = time.monotonic()
            try:
                _, response = github.requester.graphql_query(str(operation), {})
            except GithubException as e:
                response = e.data
                by_alias = {Repository.alias(number): number for number in batch}
                for error in response.get("errors", []):
                    match error:
                        case {"type": "NOT_FOUND", "path": ["repository", alias]} if (
                            alias in by_alias
                        ):
                            logger.warning(
                                f"Skipping {owner}/{name}#{by_alias[alias]}: {error['message']}"
                            )
                            GitHubSyncError.objects.update_or_create(
                                item=by_number[by_alias[alias]],
                                error_type=error["type"],
                                defaults={"message": error["message"]},
                            )
                        case _:
                            raise
            fetched = time.monotonic()
            data = operation + response
            found = []
            found_links: dict[int, list[FoundLink]] = {}
            events = 0
            for issue in Repository(data.repository, pager).issues(batch):
                item = by_number[issue.number]
                try:
                    issue_events = list(issue.events())
                    closing_pull_requests = [
                        (closing_pr, list(closing_pr.events()), closing_pr.labels())
                        for closing_pr in issue.closing_pull_requests()
                        if closing_pr.repository == f"{owner}/{name}"
                    ]
                    references = [
                        (
                            ref,
                            list(ref.pull_request.events()),
                            ref.pull_request.labels(),
                        )
                        for ref in issue.references()
                        if ref.pull_request.repository == f"{owner}/{name}"
                    ]
                    links.issues += 1
                    if not issue.cross_reference_count:
                        links.issues_without_cross_references += 1
                except GithubException as e:
                    message = f"Fetching further pages failed: {e}"
                    logger.error(f"Skipping {owner}/{name}#{issue.number}: {message}")
                    GitHubSyncError.objects.update_or_create(
                        item=item,
                        error_type="PAGINATION",
                        defaults={"message": message},
                    )
                    continue
                except TruncatedError as e:
                    message = f"Query result has more items than could be fetched in one page: {e.what} of {owner}/{name}#{e.number}"
                    logger.error(f"Skipping {owner}/{name}#{issue.number}: {message}")
                    GitHubSyncError.objects.update_or_create(
                        item=item,
                        error_type="TRUNCATED",
                        defaults={"message": message},
                    )
                    continue
                logger.debug(
                    f"{owner}/{name}#{issue.number}: "
                    + (
                        ", ".join(
                            f"{EventType(event.event_type).name} at {event.occurred_at.isoformat()}"
                            for event in issue_events
                        )
                        or "no events"
                    )
                )
                item.add_events(issue_events)
                events += len(issue_events)
                pull_requests = []
                for closing_pr, pr_events, _ in closing_pull_requests:
                    pull_requests.append(
                        record_pull_request(owner, name, closing_pr, pr_events)
                    )
                GitHubClosingReference.objects.filter(issue=item).exclude(
                    pull_request__in=pull_requests
                ).delete()
                GitHubClosingReference.objects.bulk_create(
                    [
                        GitHubClosingReference(pull_request=pull_request, issue=item)
                        for pull_request in pull_requests
                    ],
                    ignore_conflicts=True,
                )
                issue_links = [
                    FoundLink(pr, FixLink.Source.CLOSING_REFERENCE)
                    for pr in pull_requests
                ]
                for ref, pr_events, _ in references:
                    pr = record_pull_request(owner, name, ref.pull_request, pr_events)
                    issue_links.append(
                        FoundLink(
                            pr,
                            FixLink.Source.CONNECTED
                            if ref.kind == "connected"
                            else FixLink.Source.CROSS_REFERENCE,
                        )
                    )
                found_links[item.pk] = issue_links
                found.append(item)
            originals = {
                link.item.number: link.item
                for issue_links in found_links.values()
                for link in issue_links
                if link.item.merge_commit
                and resolve_branch(link.item.base_ref, known)
                == settings.TRACKING_BRANCH
            }
            backports = discover_backports(pager, owner, name, originals, known, links)
            for item in found:
                issue_links = found_links[item.pk]
                for link in list(issue_links):
                    issue_links += backports.get(link.item.number, [])
                update_fix_links(item, issue_links, links)
            found_links.clear()
            GitHubSyncError.objects.filter(item__in=found).delete()
            logger.info(
                f"{owner}/{name}: {len(found)} of {len(batch)} issues synced, {len(batch) - len(found)} failed, {events} events fetched"
                f" (fetch {fetched - batch_start:.1f}s, record {time.monotonic() - fetched:.1f}s)"
            )
            synced += len(found)
            failed += len(batch) - len(found)
    if links.cross_references_visible is False:
        logger.warning(
            "No cross-reference visible on any merged pull request with a backport label:"
            " this token likely does not see cross-references. %s",
            links.visibility(),
        )
    else:
        logger.info(links.visibility())
    clone = HistoryClone.from_settings()
    confirmed = confirm_fix_links(CachedAncestry(clone) if clone else None)
    logger.info(
        f"Synced {synced} issues, {failed} failed, in {time.monotonic() - start:.1f}s;"
        f" fix links: {links.added} added, {links.retracted} retracted;"
        f" {confirmed.confirmed} fix commits confirmed, {confirmed.ambiguous} ambiguous"
    )
    return links
