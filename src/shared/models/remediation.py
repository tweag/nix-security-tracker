"""
Remediation layer of the unified model (section 3.4 of the matching design): when channel heads
moved, and when a fix reached a channel.
"""

from django.db import models
from django.db.models import Q

from shared.models.matching import Exposure
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


class FixLandingQuerySet(models.QuerySet):
    def live(self) -> "FixLandingQuerySet":
        return self.filter(retracted_at__isnull=True)


class FixLanding(models.Model):
    """
    The first advance of a channel whose head contains the fix of an exposure. The fix point is
    `Exposure.fix_commit`, else the commit of `Exposure.fixed_evaluation` (an upper bound: the fix
    is in that commit's history). Containment is monotonic, so a live row is never recomputed;
    a regression of the exposure retracts its rows (kept for history) and a later fix lands anew.
    """

    objects = FixLandingQuerySet.as_manager()

    exposure = models.ForeignKey(
        Exposure, on_delete=models.CASCADE, related_name="landings", db_index=False
    )
    channel = models.ForeignKey(NixChannel, on_delete=models.CASCADE, related_name="+")
    advance = models.ForeignKey(
        ChannelAdvance, on_delete=models.PROTECT, related_name="+"
    )
    # The fix point that was tested.
    commit = models.CharField(max_length=40)
    # `advance.observed_at`, denormalised for ordering and display.
    landed_at = models.DateTimeField()
    retracted_at = models.DateTimeField(null=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:  # type: ignore[override]
        constraints = [
            models.UniqueConstraint(
                fields=["exposure", "channel"],
                condition=Q(retracted_at__isnull=True),
                name="fixlanding_unique_live",
            ),
            models.CheckConstraint(
                condition=Q(commit__regex=SHA1_COMMIT_REGEX),
                name="fixlanding_commit_valid",
            ),
        ]
        indexes = [
            models.Index(fields=["exposure", "channel"], name="fixlanding_exposure"),
        ]

    def __str__(self) -> str:
        retracted = " (retracted)" if self.retracted_at else ""
        return f"{self.exposure_id} in {self.channel_id} at {self.landed_at:%Y-%m-%d %H:%M}{retracted}"
