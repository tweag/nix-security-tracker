"""
CVE lifecycle read model (section 3.4 of the matching design, "CVE lifecycle"): the stage of
the report's state diagram and the time each stage was reached, per suggestion, assembled from
the events that exist: `TrackerEvent` (matches, exposures, verdicts, landings, links), the
suggestion's status history, GitHub events, `FixLink` and `FixLanding`.

Computed on demand rather than stored. A stored table would have to be marked stale from six
sources (tracker events already do that for `SuggestionDerivedState`, but GitHub events, fix
links and landings would need triggers of their own, and the time-based parts move without any
write), and nothing filters lists by stage yet. `build_timelines` costs a fixed number of
queries for any number of suggestions. If a stage filter is needed, store `stage` the way
`SuggestionDerivedState` stores its state.

Stages, in diagram order: `published` (the CVE exists), `matched`, `triaged` (an `affected`
verdict, or accepted/published), `reported` (a GitHub issue, or the CVE acknowledged in
`meta.knownVulnerabilities`), `fix_proposed` (a fix link), `fixed_tracking_branch`,
`fix_backported` (every tracked branch settled: fixed, not affected, irrelevant or wontfix),
`in_all_channels` (every fixed exposure, observed or by a `fixed` verdict, landed in every
tracked channel of its branch; a `fixed` verdict without a fix point never shows as landed),
`closed` (GitHub issue closed, or none exists). Candidates are `triage_candidates` (shown
or decided attributes), branches the tracked ones; an exposure fixed by a reclassification
of the CVE needs no landing (`fixed_by_reclassification`); `dismissed` and `no_candidates` aside. From
`matched`, reaching `fixed_tracking_branch` needs a confirming verdict (the possibly-fixed
queue), as in the diagram. A regression puts the suggestion back where its facts are and
sets `regressed`. `backport_required` is the backport requirement of #1297: once the tracking
branch is fixed, the (attribute, release branch) pairs still not settled.
"""

from collections import defaultdict
from collections.abc import Collection
from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum

from django.conf import settings
from django.db.models import Min

from shared.derived_state import (
    CONFIRMING_FIX,
    SETTLING,
    DerivedState,
    SuggestionFacts,
    derive_state,
    effective_status,
    load_facts,
    pick_verdict,
    triage_candidates,
)
from shared.exposure import fixed_by_reclassification, tracked_branches
from shared.models.issue import EventType, GitHubEvent, GitHubItem
from shared.models.linkage import CVEDerivationClusterProposal
from shared.models.matching import Exposure, TrackerEvent, Verdict
from shared.models.nix_evaluation import NixChannel, NixEvaluation
from shared.models.remediation import FixLanding, FixLink

Observed = Exposure.Observed
Status = CVEDerivationClusterProposal.Status


class Stage(StrEnum):
    PUBLISHED = "published"
    MATCHED = "matched"
    TRIAGED = "triaged"
    REPORTED = "reported"
    FIX_PROPOSED = "fix_proposed"
    FIXED_TRACKING_BRANCH = "fixed_tracking_branch"
    FIX_BACKPORTED = "fix_backported"
    IN_ALL_CHANNELS = "in_all_channels"
    CLOSED = "closed"
    DISMISSED = "dismissed"
    NO_CANDIDATES = "no_candidates"


@dataclass
class CveTimeline:
    suggestion_id: int
    cve_id: str
    stage: Stage
    published_at: datetime | None = None
    ingested_at: datetime | None = None
    matched_at: datetime | None = None
    triaged_at: datetime | None = None
    reported_at: datetime | None = None
    first_fix_pr_at: datetime | None = None
    fixed_tracking_at: datetime | None = None
    fixed_all_branches_at: datetime | None = None
    in_all_channels_at: datetime | None = None
    closed_at: datetime | None = None
    regressed: bool = False
    # (attribute, branch) still to be settled once the tracking branch is fixed (#1297).
    backport_required: list[tuple[str, str]] = field(default_factory=list)
    # (attribute, branch, channel) fixed on the branch but not yet in the channel.
    missing_landings: list[tuple[str, str, str]] = field(default_factory=list)


@dataclass
class _Extra:
    """What the timeline reads beyond the derived state's facts."""

    cve: dict[int, tuple[str, datetime | None, datetime]] = field(default_factory=dict)
    created: dict[int, datetime] = field(default_factory=dict)
    status: dict[int, str] = field(default_factory=dict)
    first_match: dict[int, datetime] = field(default_factory=dict)
    first_affected_verdict: dict[int, datetime] = field(default_factory=dict)
    first_accepted: dict[int, datetime] = field(default_factory=dict)
    regressions: dict[int, set[tuple[str, str]]] = field(
        default_factory=lambda: defaultdict(set)
    )
    issue: dict[int, GitHubItem] = field(default_factory=dict)
    issue_events: dict[int, list[tuple[datetime, int]]] = field(
        default_factory=lambda: defaultdict(list)
    )
    first_fix_pr: dict[int, datetime] = field(default_factory=dict)
    landings: dict[int, dict[str, datetime]] = field(
        default_factory=lambda: defaultdict(dict)
    )
    evaluation_time: dict[int, datetime] = field(default_factory=dict)
    channels: dict[str, list[str]] = field(default_factory=lambda: defaultdict(list))
    # Exposures fixed by a reclassification of the CVE, not a package change: no landing.
    reclassified: set[int] = field(default_factory=set)


def _load_extra(ids: Collection[int], facts: dict[int, SuggestionFacts]) -> _Extra:
    from shared.models import CVEDerivationClusterProposalStatusEvent  # type: ignore

    x = _Extra()
    for (
        pk,
        created,
        status,
        cve_id,
        published,
        ingested,
    ) in CVEDerivationClusterProposal.objects.filter(pk__in=ids).values_list(
        "pk",
        "created_at",
        "status",
        "cve__cve_id",
        "cve__date_published",
        "cve__local_timestamp",
    ):
        x.cve[pk] = (cve_id, published, ingested)
        x.created[pk] = created
        x.status[pk] = status
    events = TrackerEvent.objects.filter(suggestion_id__in=ids)
    x.first_match = dict(
        events.filter(kind=TrackerEvent.Kind.MATCH_ADDED)
        .values("suggestion_id")
        .annotate(at=Min("created_at"))
        .values_list("suggestion_id", "at")
    )
    x.first_affected_verdict = dict(
        events.filter(
            kind__in=[TrackerEvent.Kind.VERDICT_SET, TrackerEvent.Kind.VERDICT_CHANGED],
            data__new__verdict=Verdict.Kind.AFFECTED,
        )
        .values("suggestion_id")
        .annotate(at=Min("created_at"))
        .values_list("suggestion_id", "at")
    )
    x.first_accepted = dict(
        CVEDerivationClusterProposalStatusEvent.objects.filter(
            pgh_obj_id__in=ids, status__in=[Status.ACCEPTED, Status.PUBLISHED]
        )
        .values("pgh_obj_id")
        .annotate(at=Min("pgh_created_at"))
        .values_list("pgh_obj_id", "at")
    )
    for sid, attr, branch in events.filter(
        kind=TrackerEvent.Kind.EXPOSURE_BECAME_AFFECTED,
        data__regression=True,
        branch__isnull=False,
    ).values_list("suggestion_id", "attrpath", "branch_id"):
        x.regressions[sid].add((attr, branch))

    for sid, item in (
        (s.pk, item)
        for s in CVEDerivationClusterProposal.objects.filter(
            pk__in=ids, nixpkgs_issue__isnull=False
        ).prefetch_related("nixpkgs_issue__github_items")
        for item in s.nixpkgs_issue.github_items.all()  # type: ignore[union-attr]
        if item.kind == GitHubItem.Kind.ISSUE
    ):
        x.issue[sid] = item
    by_item = defaultdict(list)
    for item_id, at, kind in GitHubEvent.objects.filter(
        item__in=list(x.issue.values())
    ).values_list("item_id", "occurred_at", "event_type"):
        by_item[item_id].append((at, kind))
    for sid, item in x.issue.items():
        x.issue_events[sid] = sorted(by_item[item.pk])

    link_rows = list(
        FixLink.objects.live()
        .filter(suggestion_id__in=ids)
        .exclude(source=FixLink.Source.BACKPORT_LABEL)
        .values_list("suggestion_id", "item_id", "created_at")
    )
    opened = dict(
        GitHubEvent.objects.filter(
            item_id__in={i for _, i, _ in link_rows},
            event_type=EventType.PULL_REQUEST_OPENED,
        )
        .values("item_id")
        .annotate(at=Min("occurred_at"))
        .values_list("item_id", "at")
    )
    for sid, item_id, created in link_rows:
        at = opened.get(item_id, created)
        if sid not in x.first_fix_pr or at < x.first_fix_pr[sid]:
            x.first_fix_pr[sid] = at

    x.reclassified = fixed_by_reclassification(
        e for f in facts.values() for e in f.exposures
    )
    exposure_ids = [e.pk for f in facts.values() for e in f.exposures]
    for exposure_id, channel, landed in (
        FixLanding.objects.live()
        .filter(exposure_id__in=exposure_ids)
        .values_list("exposure_id", "channel_id", "landed_at")
    ):
        x.landings[exposure_id][channel] = landed
    evaluation_ids = {
        e.fixed_evaluation_id
        for f in facts.values()
        for e in f.exposures
        if e.fixed_evaluation_id
    }
    x.evaluation_time = dict(
        NixEvaluation.objects.filter(pk__in=evaluation_ids).values_list(
            "pk", "created_at"
        )
    )
    for name, branch in NixChannel.objects.filter(
        state__in=NixChannel.TRACKED_STATES
    ).values_list("channel_branch", "release_branch_id"):
        x.channels[branch].append(name)
    return x


def build_timelines(suggestion_ids: Collection[int]) -> dict[int, CveTimeline]:
    facts = load_facts(suggestion_ids)
    extra = _load_extra(list(facts), facts)
    branches = [b.name for b in tracked_branches()]
    return {
        sid: _timeline(f, extra, branches, settings.TRACKING_BRANCH)
        for sid, f in facts.items()
    }


def build_timeline(suggestion: CVEDerivationClusterProposal) -> CveTimeline:
    return build_timelines([suggestion.pk])[suggestion.pk]


def _max(times: list[datetime | None]) -> datetime | None:
    present = [t for t in times if t is not None]
    return max(present) if present else None


def _timeline(
    f: SuggestionFacts, x: _Extra, branches: list[str], tracking: str
) -> CveTimeline:
    sid = f.suggestion_id
    cve_id, published, ingested = x.cve[sid]
    t = CveTimeline(
        suggestion_id=sid,
        cve_id=cve_id,
        stage=Stage.PUBLISHED,
        published_at=published,
        ingested_at=ingested,
    )
    candidates = triage_candidates(f)
    if candidates:
        t.matched_at = x.first_match.get(sid, x.created[sid])
    accepted = x.first_accepted.get(sid)
    affected_verdict = x.first_affected_verdict.get(sid)
    triaged = any(v.verdict == Verdict.Kind.AFFECTED for v in f.verdicts) or (
        x.status[sid] in (Status.ACCEPTED, Status.PUBLISHED)
    )
    if triaged:
        t.triaged_at = min(
            (d for d in (accepted, affected_verdict) if d is not None), default=None
        )
    issue = x.issue.get(sid)
    acknowledged = [
        e.created_at
        for e in f.exposures
        if e.attrpath in candidates and e.reason == Exposure.Reason.ACKNOWLEDGED
    ]
    issue_events = x.issue_events.get(sid, [])
    if issue is not None:
        t.reported_at = issue_events[0][0] if issue_events else None
    elif acknowledged:
        t.reported_at = min(acknowledged)
    t.first_fix_pr_at = x.first_fix_pr.get(sid)
    if issue_events and EventType(issue_events[-1][1]) & EventType.CLOSED:
        t.closed_at = issue_events[-1][0]

    # Per (attribute, branch) on tracked branches: settled, and since when.
    unsettled: list[tuple[str, str]] = []
    settled_at: dict[str, list[datetime | None]] = defaultdict(list)
    ever_affected = False
    confirmed_on_tracking = False
    fixed_exposures: list[Exposure] = []
    for e in sorted(f.exposures, key=lambda e: (e.attrpath, e.branch_id)):
        if e.attrpath not in candidates or e.branch_id not in branches:
            continue
        verdict = pick_verdict(f.verdicts, e.attrpath, e.branch_id)
        eff = effective_status(
            e, verdict, f.became_affected.get((e.attrpath, e.branch_id))
        )
        was_affected = e.first_affected_evaluation_id is not None or (
            eff.status == Verdict.Kind.AFFECTED
        )
        ever_affected |= was_affected
        if eff.regression:
            unsettled.append((e.attrpath, e.branch_id))
        elif eff.source == "verdict" and eff.status in SETTLING:
            settled_at[e.branch_id].append(verdict.updated_at if verdict else None)
            if e.branch_id == tracking and eff.status in CONFIRMING_FIX:
                confirmed_on_tracking = True
            if eff.status == Verdict.Kind.FIXED:
                # Fixed must reach the channels too; without a fix point it never shows
                # as landed, which is the honest answer.
                fixed_exposures.append(e)
        elif eff.status == Observed.UNAFFECTED or (
            eff.status == Observed.ABSENT and e.reason == Exposure.Reason.REMOVED
        ):
            if e.fixed_evaluation_id is not None:
                settled_at[e.branch_id].append(
                    x.evaluation_time.get(e.fixed_evaluation_id)
                )
                fixed_exposures.append(e)
        else:
            unsettled.append((e.attrpath, e.branch_id))
    t.regressed = any(
        key in unsettled for key in x.regressions.get(sid, set())
    ) or bool(derive_state(f).regressions)

    tracking_fixed = ever_affected and not any(b == tracking for _, b in unsettled)
    if tracking_fixed:
        t.fixed_tracking_at = _max(settled_at.get(tracking, []))
        t.backport_required = [(a, b) for a, b in unsettled if b != tracking]
    all_fixed = ever_affected and not unsettled
    if all_fixed:
        t.fixed_all_branches_at = _max([d for ds in settled_at.values() for d in ds])
    for e in fixed_exposures:
        if e.pk in x.reclassified:
            continue
        for channel in sorted(x.channels.get(e.branch_id, [])):
            if channel not in x.landings.get(e.pk, {}):
                t.missing_landings.append((e.attrpath, e.branch_id, channel))
    in_all_channels = all_fixed and not t.missing_landings
    if in_all_channels:
        t.in_all_channels_at = _max(
            [d for e in fixed_exposures for d in x.landings.get(e.pk, {}).values()]
        )

    derived = derive_state(f).state
    if derived == DerivedState.DISMISSED:
        t.stage = Stage.DISMISSED
        return t
    if derived == DerivedState.NO_CANDIDATES:
        t.stage = Stage.NO_CANDIDATES
        return t
    t.stage = Stage.MATCHED
    if triaged:
        t.stage = Stage.TRIAGED
    if issue is not None or acknowledged:
        t.stage = Stage.REPORTED
    if t.first_fix_pr_at is not None:
        t.stage = Stage.FIX_PROPOSED
    if tracking_fixed and (t.stage != Stage.MATCHED or confirmed_on_tracking):
        t.stage = Stage.FIXED_TRACKING_BRANCH
        if all_fixed:
            t.stage = Stage.FIX_BACKPORTED
            if in_all_channels:
                t.stage = Stage.IN_ALL_CHANNELS
                if issue is None or t.closed_at is not None:
                    t.stage = Stage.CLOSED
    return t
