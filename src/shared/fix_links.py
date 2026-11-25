"""
Pull requests that fix a CVE, per suggestion and branch (`FixLink`, section 3.4 of the matching
design, PR tracking), and the confirmation that turns a merged one into `Exposure.fix_commit`.

- `resolve_branch`: the tracked branch a base ref feeds (`staging*` to its release branch).
- `update_fix_links`: make the live links of the suggestions of one published issue equal to
  what the GitHub sync found, with `fix_link_added` / `fix_link_retracted` events.
- `confirm_fix_links`: for exposures observed fixed without a fix commit, the merge commit of
  the one linked pull request into that branch that the fix evaluation contains and the last
  affected evaluation does not (by ancestry in the history clone when available, else by
  time). Sets `fix_commit`, marks the link confirmed, writes `exposure_fix_commit_set`.
- `polled_issue_items`: the published issues the daily sync still needs to look at.
"""

import logging
import re
import uuid
from collections import defaultdict
from collections.abc import Collection, Iterable
from dataclasses import dataclass, field
from datetime import timedelta

from django.conf import settings
from django.db import transaction
from django.db.models import Exists, OuterRef, Q, QuerySet
from django.utils import timezone

from shared.candidates import candidates
from shared.derived_state import flush_derived_states
from shared.exposure import dismissed_q, tracked_branches
from shared.history import Ancestry
from shared.locking import lock_for_write
from shared.models.issue import EventType, GitHubEvent, GitHubItem
from shared.models.linkage import CVEDerivationClusterProposal
from shared.models.matching import Exposure, TrackerEvent
from shared.models.nix_evaluation import NixpkgsBranch
from shared.models.remediation import FixLink

logger = logging.getLogger(__name__)

Source = FixLink.Source

# After a fix is observed, keep polling the issue this long for the pull request that made it.
FIX_LINK_GRACE = timedelta(days=14)

_STAGING = re.compile(r"^staging(?:-next)?(?:-nixos)?(?:-(?P<release>\d\d\.\d\d))?$")
_BACKPORT_LABEL = re.compile(r"^backport (?P<branch>\S+)$")
_TITLE_PREFIX = re.compile(r"^(?:\s*\[[^\]]*\]\s*)+")


def resolve_branch(base_ref: str | None, known: Collection[str]) -> str | None:
    """The tracked branch a pull request into `base_ref` ends up on, if any."""
    if not base_ref:
        return None
    if base_ref in known:
        return base_ref
    if m := _STAGING.match(base_ref):
        name = f"release-{m['release']}" if m["release"] else settings.TRACKING_BRANCH
        return name if name in known else None
    return None


def backport_branches(labels: Iterable[str]) -> list[str]:
    """Branches named by `backport <branch>` labels."""
    return sorted(
        {m["branch"] for label in labels if (m := _BACKPORT_LABEL.match(label))}
    )


def attrpath_from_title(title: str, candidates: Collection[str]) -> str | None:
    """`foo: 1.0 -> 1.1` (also behind `[Backport release-26.05]`) names `foo` if it is a candidate."""
    head, sep, _ = _TITLE_PREFIX.sub("", title).partition(":")
    head = head.strip()
    return head if sep and head in candidates else None


@dataclass(frozen=True)
class FoundLink:
    item: GitHubItem
    source: str
    # For backport labels: the branch named by the label, not the item's base.
    branch_ref: str | None = None


@dataclass
class LinkResult:
    batch: uuid.UUID
    added: int = 0
    retracted: int = 0
    touched: set[int] = field(default_factory=set)
    # Whether the token sees cross-references at all (GitHub hides them from some tokens):
    # issues and merged original pull requests synced, and how many showed none.
    issues: int = 0
    issues_without_cross_references: int = 0
    originals: int = 0
    originals_without_cross_references: int = 0
    # Originals with a `backport <branch>` label: the backport bot's pull request mentions
    # them, so none visible on all of them means the token does not see cross-references.
    labelled_originals: int = 0
    labelled_originals_without_cross_references: int = 0

    @property
    def cross_references_visible(self) -> bool | None:
        """False if labelled originals were checked and none showed a cross-reference."""
        if not self.labelled_originals:
            return None
        return (
            self.labelled_originals_without_cross_references < self.labelled_originals
        )

    def visibility(self) -> str:
        verdict = {
            None: "unknown (no labelled original checked)",
            True: "yes",
            False: "NO: backports are found from closing references, linked pull requests and backport labels only",
        }[self.cross_references_visible]
        return (
            f"cross-references: none on {self.issues_without_cross_references} of {self.issues} issues,"
            f" none on {self.originals_without_cross_references} of {self.originals} merged originals,"
            f" none on {self.labelled_originals_without_cross_references} of {self.labelled_originals}"
            f" with a backport label; visible to this token: {verdict}"
        )


def _candidates(suggestion_ids: Collection[int]) -> dict[int, set[str]]:
    return {sid: c.attributes for sid, c in candidates(suggestion_ids).items()}


def update_fix_links(
    issue_item: GitHubItem,
    found: Iterable[FoundLink],
    result: LinkResult | None = None,
) -> LinkResult:
    """
    Bring the live GitHub-sourced links of the suggestions published in `issue_item` to `found`.
    Manual links are left alone. Every link applies to every suggestion of the issue (GitHub
    cannot say which CVE of a bundled issue a pull request fixes); the attribute is set when
    the title names one of the suggestion's candidates.
    """
    result = result or LinkResult(batch=uuid.uuid4())
    suggestions = list(
        CVEDerivationClusterProposal.objects.filter(
            nixpkgs_issue__github_items=issue_item
        ).values_list("pk", flat=True)
    )
    if not suggestions:
        return result
    known = set(NixpkgsBranch.objects.values_list("name", flat=True))
    candidate_attrs = _candidates(suggestions)
    found = list({(f.item.pk, f.source, f.branch_ref): f for f in found}.values())
    events: list[TrackerEvent] = []
    now = timezone.now()
    with transaction.atomic():
        lock_for_write(suggestions)
        existing = {
            (link.suggestion_id, link.item_id, link.source, link.branch_id): link
            for link in FixLink.objects.filter(suggestion_id__in=suggestions).exclude(
                source=Source.MANUAL
            )
        }
        wanted = set()
        for sid in suggestions:
            for f in found:
                branch = resolve_branch(f.branch_ref or f.item.base_ref, known)
                key = (sid, f.item.pk, f.source, branch)
                if key in wanted:
                    continue
                wanted.add(key)
                link = existing.get(key)
                if link is not None and link.retracted_at is None:
                    continue
                attrpath = attrpath_from_title(
                    f.item.title, candidate_attrs.get(sid, set())
                )
                if link is None:
                    link = FixLink.objects.create(
                        suggestion_id=sid,
                        item=f.item,
                        source=f.source,
                        branch_id=branch,
                        attrpath=attrpath,
                    )
                else:
                    link.retracted_at = None
                    link.attrpath = attrpath
                    link.save(update_fields=["retracted_at", "attrpath"])
                events.append(_event(link, TrackerEvent.Kind.FIX_LINK_ADDED, result))
                result.added += 1
        for key, link in existing.items():
            if key not in wanted and link.retracted_at is None:
                link.retracted_at = now
                link.save(update_fields=["retracted_at"])
                events.append(
                    _event(link, TrackerEvent.Kind.FIX_LINK_RETRACTED, result)
                )
                result.retracted += 1
        TrackerEvent.objects.bulk_create(events)
        touched = {e.suggestion_id for e in events}
        flush_derived_states(touched)
    result.touched |= touched
    return result


def _event(link: FixLink, kind: str, result: LinkResult) -> TrackerEvent:
    item = link.item
    return TrackerEvent(
        suggestion_id=link.suggestion_id,
        kind=kind,
        attrpath=link.attrpath or "",
        branch_id=link.branch_id,
        cause=TrackerEvent.Cause.GITHUB,
        data={
            "pull_request": item.number,
            "repository": f"{item.owner}/{item.repository}",
            "source": link.source,
            "base_ref": item.base_ref,
            "title": item.title,
        },
        batch=result.batch,
    )


# --- Confirmation ---------------------------------------------------------------------------


def _merged_at(items: Collection[int]) -> dict[int, object]:
    return dict(
        GitHubEvent.objects.filter(
            item_id__in=items, event_type=EventType.PULL_REQUEST_MERGED
        )
        .order_by("item_id", "occurred_at")
        .distinct("item_id")
        .values_list("item_id", "occurred_at")
    )


@dataclass
class ConfirmResult:
    batch: uuid.UUID
    confirmed: int = 0
    ambiguous: int = 0
    touched: set[int] = field(default_factory=set)


def confirm_fix_links(
    ancestry: Ancestry | None = None,
    suggestion_ids: Collection[int] | None = None,
) -> ConfirmResult:
    """Set `fix_commit` of fixed exposures from the one merged linked pull request that fits."""
    result = ConfirmResult(batch=uuid.uuid4())
    exposures = (
        Exposure.objects.filter(fixed_evaluation__isnull=False, fix_commit__isnull=True)
        .exclude(dismissed_q("suggestion__"))
        .filter(
            Exists(
                FixLink.objects.live().filter(
                    suggestion=OuterRef("suggestion"),
                    branch=OuterRef("branch"),
                    item__merge_commit__isnull=False,
                )
            )
        )
        .select_related("fixed_evaluation", "last_affected_evaluation")
    )
    if suggestion_ids is not None:
        exposures = exposures.filter(suggestion_id__in=suggestion_ids)
    shown = candidates({e.suggestion_id for e in exposures})
    rows = [
        e
        for e in exposures.filter(branch__in=tracked_branches())
        if e.suggestion_id in shown and e.attrpath in shown[e.suggestion_id].attributes
    ]
    if not rows:
        return result
    links: dict[tuple[int, str], list[FixLink]] = defaultdict(list)
    for link in (
        FixLink.objects.live()
        .filter(
            suggestion_id__in={e.suggestion_id for e in rows},
            item__merge_commit__isnull=False,
            branch__isnull=False,
        )
        .exclude(source=Source.BACKPORT_LABEL)
        .select_related("item")
    ):
        links[(link.suggestion_id, link.branch_id)].append(link)
    merged_at = _merged_at({link.item_id for ls in links.values() for link in ls})

    decisions: list[tuple[Exposure, FixLink, str]] = []
    for e in rows:
        assert e.fixed_evaluation is not None
        fits: dict[str, list[tuple[FixLink, str]]] = defaultdict(list)
        for link in links.get((e.suggestion_id, e.branch_id), []):
            if link.attrpath not in (None, e.attrpath):
                continue
            merge = link.item.merge_commit
            assert merge is not None
            if method := _fits(e, merge, merged_at.get(link.item_id), ancestry):
                fits[merge].append((link, method))
        if not fits:
            continue
        specific = {
            m: ls
            for m, ls in fits.items()
            if any(lk.attrpath == e.attrpath for lk, _ in ls)
        }
        chosen = specific or fits
        if len(chosen) != 1:
            result.ambiguous += 1
            continue
        [(_, [(link, method), *_])] = chosen.items()
        decisions.append((e, link, method))

    if decisions:
        _confirm(decisions, result)
    return result


def _fits(
    e: Exposure, merge: str, merged_at: object, ancestry: Ancestry | None
) -> str | None:
    """How the merge commit is shown to lie between the last affected and the fix evaluation."""
    fixed = e.fixed_evaluation
    before = e.last_affected_evaluation
    assert fixed is not None
    if ancestry is not None:
        inside = ancestry.contains(fixed.commit_sha1, merge)
        outside = (
            ancestry.contains(before.commit_sha1, merge)
            if before is not None
            else False
        )
        if inside is not None and outside is not None:
            return "ancestry" if inside and not outside else None
    if merged_at is None:
        return None
    if merged_at <= fixed.created_at and (  # type: ignore[operator]
        before is None or merged_at > before.created_at  # type: ignore[operator]
    ):
        return "time"
    return None


def _confirm(
    decisions: list[tuple[Exposure, FixLink, str]], result: ConfirmResult
) -> None:
    with transaction.atomic():
        # The ancestry was answered before: no git under the locks (`shared.locking`).
        lock_for_write(e.suggestion_id for e, _, _ in decisions)
        events = []
        for e, link, method in decisions:
            merge = link.item.merge_commit
            updated = Exposure.objects.filter(
                pk=e.pk, fix_commit__isnull=True, fixed_evaluation=e.fixed_evaluation
            ).update(fix_commit=merge, updated_at=timezone.now())
            if not updated:
                continue
            FixLink.objects.filter(pk=link.pk).update(confirmed=True)
            events.append(
                TrackerEvent(
                    suggestion_id=e.suggestion_id,
                    kind=TrackerEvent.Kind.EXPOSURE_FIX_COMMIT_SET,
                    attrpath=e.attrpath,
                    branch_id=e.branch_id,
                    cause=TrackerEvent.Cause.GITHUB,
                    evaluation=e.fixed_evaluation,
                    data={
                        "fix_commit": merge,
                        "pull_request": link.item.number,
                        "source": link.source,
                        "method": method,
                    },
                    batch=result.batch,
                )
            )
        TrackerEvent.objects.bulk_create(events)
        result.confirmed += len(events)
        result.touched |= {ev.suggestion_id for ev in events}
        flush_derived_states(result.touched)


# --- Polling --------------------------------------------------------------------------------


def polled_issue_items() -> QuerySet[GitHubItem]:
    """
    Published GitHub issues still worth syncing: open ones (or never synced), and closed ones
    whose suggestions have a candidate attribute (`shared.candidates`) on a tracked branch
    still affected, or fixed recently without a known fix commit.
    """
    published = GitHubItem.objects.filter(
        kind=GitHubItem.Kind.ISSUE, nixpkgs_issues__isnull=False
    )
    open_items = set(published.open().values_list("pk", flat=True))
    issue_of = defaultdict(set)
    for sid, item in CVEDerivationClusterProposal.objects.filter(
        nixpkgs_issue__github_items__in=published.exclude(pk__in=open_items)
    ).values_list("pk", "nixpkgs_issue__github_items"):
        issue_of[sid].add(item)
    shown = candidates(issue_of)
    unresolved = set()
    for sid, attr in (
        Exposure.objects.filter(
            suggestion_id__in=list(issue_of), branch__in=tracked_branches()
        )
        .filter(
            Q(observed=Exposure.Observed.AFFECTED)
            | Q(
                fixed_evaluation__isnull=False,
                fix_commit__isnull=True,
                fixed_evaluation__created_at__gte=timezone.now() - FIX_LINK_GRACE,
            )
        )
        .values_list("suggestion_id", "attrpath")
    ):
        if attr in shown[sid].attributes:
            unresolved |= issue_of[sid]
    return GitHubItem.objects.filter(pk__in=open_items | unresolved)
