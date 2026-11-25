"""
Channel history and fix landings (section 3.4 of the matching design, "Channel monitoring").

- `poll_channel_heads`: read the heads of all tracked channels with one `git ls-remote` and append a
  `ChannelAdvance` for each channel whose head moved. Cheap enough to run hourly, independently of
  the daily evaluation run; the channel list and states stay with `fetch_all_channels`.
"""

import logging
from datetime import datetime

from django.conf import settings
from django.db import transaction
from django.utils import timezone
from pydantic import AnyUrl

from shared.git import get_head_sha1s
from shared.models.nix_evaluation import NixChannel
from shared.models.remediation import ChannelAdvance

logger = logging.getLogger(__name__)


def tracked_channels() -> list[NixChannel]:
    return list(
        NixChannel.objects.filter(state__in=NixChannel.TRACKED_STATES)
        .select_related("release_branch")
        .order_by("channel_branch")
    )


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
