"""
Remediation layer of the unified model (section 3.4 of the matching design): when channel heads
moved, and when a fix reached a channel.
"""

from django.db import models
from django.db.models import Q

from shared.models.nix_evaluation import SHA1_COMMIT_REGEX, NixChannel


class ChannelAdvance(models.Model):
    """A channel head observed at a commit different from the previous observation. Append-only."""

    channel = models.ForeignKey(
        NixChannel,
        on_delete=models.CASCADE,
        related_name="advances",
        db_index=False,
    )
    commit = models.CharField(max_length=40)
    observed_at = models.DateTimeField()

    class Meta:  # type: ignore[override]
        constraints = [
            models.UniqueConstraint(
                fields=["channel", "observed_at"], name="channeladvance_unique"
            ),
            models.CheckConstraint(
                condition=Q(commit__regex=SHA1_COMMIT_REGEX),
                name="channeladvance_commit_valid",
            ),
        ]

    def __str__(self) -> str:
        return f"{self.channel_id} -> {self.commit[:12]} at {self.observed_at:%Y-%m-%d %H:%M}"
