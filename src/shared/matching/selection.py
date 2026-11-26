"""
Which matched attributes a suggestion shows, and the settings that decide it:
`MATCHING_MATCHERS` (enabled matchers), `MATCHING_SCORE_THRESHOLD` (on the noisy-OR score)
and `MATCHING_MAX_ATTRIBUTES` (cap, best scored first).
"""

from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import datetime, timedelta

from django.conf import settings
from django.db.models import Q
from django.utils import timezone

from shared.matching.base import REGISTRY
from shared.matching.scoring import noisy_or

# Matches backfilled from the links of the legacy matcher (algorithm version 2). Not a registered
# matcher: nothing runs it. It counts fully until a re-match with the real matchers retracts it.
LEGACY_MATCHER = "legacy-v2"
LEGACY_MATCHER_VERSION = 2

KNOWN_VULNERABILITY_MATCHER = "known-vuln"


def enabled_matchers() -> list[str]:
    """Slugs of the matchers that run, in registry order."""
    configured = settings.MATCHING_MATCHERS
    if configured is None:
        return list(REGISTRY)
    unknown = set(configured) - REGISTRY.keys()
    if unknown:
        raise ValueError(f"MATCHING_MATCHERS: unknown matchers {sorted(unknown)}")
    return [slug for slug in REGISTRY if slug in configured]


def counted_matchers() -> list[str]:
    """Matchers whose active matches count towards what a suggestion shows."""
    return [*enabled_matchers(), LEGACY_MATCHER]


def current_matcher_versions(slugs: Iterable[str] | None = None) -> dict[str, int]:
    """Current version of the given (default: enabled) matchers, by slug."""
    return {
        slug: REGISTRY[slug].version
        for slug in (enabled_matchers() if slugs is None else slugs)
    }


@dataclass(frozen=True)
class Selection:
    # Shown attributes with their score, best first.
    shown: list[tuple[str, float]] = field(default_factory=list)
    # Matched attributes at or below the threshold.
    below_threshold: int = 0
    # Attributes above the threshold dropped by the cap.
    beyond_cap: int = 0

    @property
    def attributes(self) -> set[str]:
        return {attr for attr, _ in self.shown}


def select_attributes(
    contributions: Iterable[tuple[str, str, float]],
    exclude: Iterable[str] = (),
    threshold: float | None = None,
    cap: int | None = None,
) -> Selection:
    """
    The matched attributes a suggestion shows, from (attrpath, matcher, score) of its active
    matches: noisy-OR per attribute over the counted matchers, strictly above the threshold,
    at most `cap`, best score then name first. `exclude` (attributes shown anyway because a
    human decided on them) do not take a place under the cap.
    """
    floor: float = settings.MATCHING_SCORE_THRESHOLD if threshold is None else threshold
    limit: int = settings.MATCHING_MAX_ATTRIBUTES if cap is None else cap
    counted = set(counted_matchers())
    excluded = set(exclude)
    by_attr: dict[str, list[tuple[str, float]]] = {}
    for attr, matcher, score in contributions:
        if matcher in counted and attr not in excluded:
            by_attr.setdefault(attr, []).append((matcher, score))
    scored = sorted(
        ((attr, noisy_or(c)) for attr, c in by_attr.items()),
        key=lambda a: (-a[1], a[0]),
    )
    above = [a for a in scored if a[1] > floor]
    return Selection(
        shown=above[:limit],
        below_threshold=len(scored) - len(above),
        beyond_cap=max(0, len(above) - limit),
    )


def reopen_cutoff() -> datetime | None:
    """Machine-rejected suggestions of CVEs published since then are re-matched and reopenable."""
    days = settings.MATCHING_REOPEN_WINDOW_DAYS
    return timezone.now() - timedelta(days=days) if days > 0 else None


def reopenable_q(prefix: str = "", cutoff: datetime | None = None) -> Q:
    """Machine-rejected suggestions within the reopen window (`MATCHING_REOPEN_WINDOW_DAYS`)."""
    from shared.models.linkage import MACHINE_REOPENABLE_REJECTIONS

    cutoff = cutoff or reopen_cutoff()
    if cutoff is None:
        return Q(pk__in=[])
    return Q(
        **{
            f"{prefix}status": "rejected",
            f"{prefix}rejection_reason__in": MACHINE_REOPENABLE_REJECTIONS,
            f"{prefix}cve__date_published__gte": cutoff,
        }
    )


def showable_attributes(
    contributions: Iterable[tuple[str, str, float]], threshold: float | None = None
) -> set[str]:
    """
    Attributes whose noisy-OR over these (attribute, matcher, score) contributions of the
    counted matchers is above the display threshold: those a suggestion could show.
    """
    floor: float = settings.MATCHING_SCORE_THRESHOLD if threshold is None else threshold
    counted = set(counted_matchers())
    by_attr: dict[str, list[tuple[str, float]]] = {}
    for attr, matcher, score in contributions:
        if matcher in counted:
            by_attr.setdefault(attr, []).append((matcher, score))
    return {attr for attr, c in by_attr.items() if noisy_or(c) > floor}
