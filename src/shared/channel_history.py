"""
Channel history and fix landings (section 3.4 of the matching design, "Channel monitoring").

- `poll_channel_heads`: read the heads of all tracked channels with one `git ls-remote` and append a
  `ChannelAdvance` for each channel whose head moved. Cheap enough to run hourly, independently of
  the daily evaluation run; the channel list and states stay with `fetch_all_channels`.
- `compute_landings`: for every exposure with a fix point (`fix_commit`, else the commit of
  `fixed_evaluation`) not yet landed on a tracked channel of its branch, record the first
  advance of that channel whose head contains it (`FixLanding`) and a `fix_landed` event.

Per channel and run, each pending exposure costs one ancestry test against the current head
(shared by all exposures with the same fix point, which is usually one evaluation's commit),
and a landed one a binary search over the channel's advances. Landed exposures are excluded by
the query, so the work is proportional to the exposures not yet landed. The binary search
assumes a channel's head only moves forward, which is how channels are updated.
"""

import logging
import uuid
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime

from django.conf import settings
from django.db import transaction
from django.db.models import Exists, OuterRef, Q
from django.utils import timezone
from pydantic import AnyUrl

from shared.candidates import candidates
from shared.derived_state import flush_derived_states
from shared.exposure import dismissed_q, fixed_by_reclassification
from shared.git import get_head_sha1s
from shared.history import Ancestry
from shared.locking import lock_for_write
from shared.models.matching import Exposure, TrackerEvent
from shared.models.nix_evaluation import NixChannel
from shared.models.remediation import ChannelAdvance, FixLanding

logger = logging.getLogger(__name__)


def tracked_channels() -> list[NixChannel]:
    return list(
        NixChannel.objects.filter(state__in=NixChannel.TRACKED_STATES)
        .select_related("release_branch")
        .order_by("channel_branch")
    )


def history_branches() -> list[str]:
    """Refs the history clone needs: tracked channels and the branches they follow."""
    names = set()
    for channel in tracked_channels():
        names |= {channel.channel_branch, channel.release_branch_id}
    return sorted(names)


def record_advance(
    channel: NixChannel, commit: str, observed_at: datetime
) -> ChannelAdvance | None:
    """
    Append an advance if `commit` differs from the channel's last observed head. Observations
    older than the last one are ignored, so the history stays ordered by observation time.
    """
    last = channel.advances.order_by("-observed_at", "-pk").first()
    if last is not None and (last.commit == commit or last.observed_at >= observed_at):
        return None
    return ChannelAdvance.objects.create(
        channel=channel, commit=commit, observed_at=observed_at
    )


def poll_channel_heads(
    url: AnyUrl | str | None = None, now: datetime | None = None
) -> list[ChannelAdvance]:
    """Record the current head of every tracked channel; returns the advances written."""
    channels = tracked_channels()
    heads = get_head_sha1s(
        url or settings.GIT_CLONE_URL, [c.channel_branch for c in channels]
    )
    now = now or timezone.now()
    advances = []
    with transaction.atomic():
        for channel in channels:
            head = heads.get(channel.channel_branch)
            if head is None:
                logger.warning("Channel branch %s not found", channel.channel_branch)
                continue
            if advance := record_advance(channel, head, now):
                advances.append(advance)
            if channel.head_sha1_commit != head:
                channel.head_sha1_commit = head
                channel.save(update_fields=["head_sha1_commit", "updated_at"])
    logger.info(
        "Polled %d channels, %d advanced: %s",
        len(channels),
        len(advances),
        ", ".join(f"{a.channel_id} {a.commit[:12]}" for a in advances) or "-",
    )
    return advances


def fix_point(exposure: Exposure) -> str | None:
    """The commit a fix is known to be in: the exact fix commit, else the fixing evaluation's."""
    if exposure.fix_commit:
        return exposure.fix_commit
    if exposure.fixed_evaluation is not None:
        return exposure.fixed_evaluation.commit_sha1
    return None


def first_containing(
    advances: list[ChannelAdvance], commit: str, ancestry: Ancestry
) -> ChannelAdvance:
    """The earliest advance containing `commit`, given that the last one does."""
    lo, hi = 0, len(advances) - 1
    while lo < hi:
        mid = (lo + hi) // 2
        if ancestry.contains(advances[mid].commit, commit):
            hi = mid
        else:
            lo = mid + 1
    return advances[lo]


def pending_exposures(channel: NixChannel) -> "list[Exposure]":
    """
    Exposures of the channel's branch with a fix point and no live landing on the channel, of
    candidate attributes (`shared.candidates`) of suggestions not dismissed, whose fix is a
    package change rather than a reclassification (`fixed_by_reclassification`).
    """
    rows = list(
        Exposure.objects.filter(branch_id=channel.release_branch_id)
        .filter(Q(fix_commit__isnull=False) | Q(fixed_evaluation__isnull=False))
        .exclude(dismissed_q("suggestion__"))
        .exclude(
            Exists(
                FixLanding.objects.live().filter(
                    exposure=OuterRef("pk"), channel=channel
                )
            )
        )
        .select_related("fixed_evaluation")
        .order_by("pk")
    )
    shown = candidates({e.suggestion_id for e in rows})
    rows = [
        e
        for e in rows
        if e.suggestion_id in shown and e.attrpath in shown[e.suggestion_id].attributes
    ]
    reclassified = fixed_by_reclassification(rows)
    return [e for e in rows if e.pk not in reclassified]


@dataclass
class LandingResult:
    batch: uuid.UUID
    landed: int = 0
    pending: int = 0
    # Fix points the history does not know (not fetched yet, or not on the branch).
    unknown: int = 0
    touched: set[int] = field(default_factory=set)


def compute_landings(
    ancestry: Ancestry,
    channels: list[NixChannel] | None = None,
    batch: uuid.UUID | None = None,
) -> LandingResult:
    result = LandingResult(batch=batch or uuid.uuid4())
    for channel in channels if channels is not None else tracked_channels():
        advances = list(channel.advances.order_by("observed_at", "pk"))
        if not advances:
            continue
        head = advances[-1]
        by_point: dict[str, list[Exposure]] = defaultdict(list)
        for exposure in pending_exposures(channel):
            if point := fix_point(exposure):
                by_point[point].append(exposure)
        landings: list[tuple[Exposure, ChannelAdvance, str]] = []
        for point, exposures in by_point.items():
            match ancestry.contains(head.commit, point):
                case True:
                    first = first_containing(advances, point, ancestry)
                    landings += [(e, first, point) for e in exposures]
                case None:
                    result.unknown += len(exposures)
                    result.pending += len(exposures)
                case False:
                    result.pending += len(exposures)
        if landings:
            _record(channel, landings, result)
    logger.info(
        "Landings: %d recorded, %d pending, %d with an unknown fix point",
        result.landed,
        result.pending,
        result.unknown,
    )
    return result


def _record(
    channel: NixChannel,
    landings: list[tuple[Exposure, ChannelAdvance, str]],
    result: LandingResult,
) -> None:
    # Ancestry was answered before: no git under the locks (`shared.locking`).
    with transaction.atomic():
        lock_for_write(e.suggestion_id for e, _, _ in landings)
        # Under the lock: skip rows that regressed or landed concurrently since they were read.
        ids = [e.pk for e, _, _ in landings]
        landed = set(
            FixLanding.objects.live()
            .filter(exposure_id__in=ids, channel=channel)
            .values_list("exposure_id", flat=True)
        )
        still = {
            e.pk: e
            for e in Exposure.objects.filter(pk__in=ids).select_related(
                "fixed_evaluation"
            )
            if e.pk not in landed
        }
        rows, events = [], []
        for exposure, advance, point in landings:
            current = still.get(exposure.pk)
            if current is None or fix_point(current) != point:
                continue
            rows.append(
                FixLanding(
                    exposure=current,
                    channel=channel,
                    advance=advance,
                    commit=point,
                    landed_at=advance.observed_at,
                )
            )
            events.append(
                TrackerEvent(
                    suggestion_id=current.suggestion_id,
                    kind=TrackerEvent.Kind.FIX_LANDED,
                    attrpath=current.attrpath,
                    branch_id=current.branch_id,
                    cause=TrackerEvent.Cause.CHANNEL,
                    evaluation=current.fixed_evaluation,
                    data={
                        "channel": channel.channel_branch,
                        "commit": point,
                        "via": "fix_commit"
                        if current.fix_commit
                        else "fixed_evaluation",
                        "channel_commit": advance.commit,
                        "landed_at": advance.observed_at.isoformat(),
                    },
                    batch=result.batch,
                )
            )
        FixLanding.objects.bulk_create(rows)
        TrackerEvent.objects.bulk_create(events)
        result.landed += len(rows)
        touched = {e.suggestion_id for e in events}
        flush_derived_states(touched)
        result.touched |= touched
