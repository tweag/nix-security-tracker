"""Setting and removing verdicts from the API, validated and grouped into one event batch."""

import uuid
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any

from django.contrib.auth.models import User
from django.core.exceptions import ValidationError
from django.db import transaction
from django.db.models import QuerySet

from shared.derived_state import remove_verdict, set_verdict
from shared.exposure import tracked_branches
from shared.models.linkage import (
    BulkValidationError,
    CVEDerivationClusterProposal,
    PackageOverlay,
)
from shared.models.matching import Exposure, Match, Verdict
from shared.models.nix_evaluation import NixpkgsBranch
from shared.models.package import PackageAttrpath


@dataclass(frozen=True)
class VerdictChange:
    """One request: a verdict (or its removal, `verdict=None`) on several attributes."""

    attrpaths: list[str]
    branch: str | None
    verdict: str | None
    fix_commit: str | None = None
    comment: str = ""


def check_verdicts(
    suggestion: CVEDerivationClusterProposal,
    change: VerdictChange,
    tracked: Iterable[str] | None = None,
) -> None:
    """
    Raise unless the change applies to this suggestion: every attribute has a match
    (active or retracted) or an exposure on it, the branch is tracked, and a removal
    has a verdict to remove.
    """
    errors: dict[str, Any] = {}
    known = set(
        Match.objects.filter(
            suggestion=suggestion, attrpath__in=change.attrpaths
        ).values_list("attrpath", flat=True)
    ) | set(
        Exposure.objects.filter(
            suggestion=suggestion, attrpath__in=change.attrpaths
        ).values_list("attrpath", flat=True)
    )
    existing = set(
        Verdict.objects.filter(
            suggestion=suggestion,
            attrpath__in=change.attrpaths,
            branch_id=change.branch,
        ).values_list("attrpath", flat=True)
    )
    if change.verdict is None:
        missing = [a for a in change.attrpaths if a not in existing]
        if missing:
            errors["package_attributes"] = [
                "No verdict to remove on "
                + (change.branch or "all branches")
                + " for: "
                + ", ".join(missing)
            ]
    else:
        unknown = [a for a in change.attrpaths if a not in known]
        if unknown:
            errors["package_attributes"] = [
                "Packages not found in the suggestion: " + ", ".join(unknown)
            ]
        if change.branch is not None:
            names = (
                set(tracked)
                if tracked is not None
                else {b.name for b in tracked_branches()}
            )
            if change.branch not in names:
                errors["branch"] = [f"Not a tracked branch: {change.branch}"]
    if errors:
        raise ValidationError(errors)


def apply_verdicts(
    suggestion: CVEDerivationClusterProposal,
    change: VerdictChange,
    author: User | None,
    batch: uuid.UUID | None = None,
    check: bool = True,
) -> None:
    """Check and apply the change in one transaction, with one event batch."""
    batch = batch or uuid.uuid4()
    with transaction.atomic():
        if check:
            check_verdicts(suggestion, change)
        branch = (
            NixpkgsBranch.objects.get(pk=change.branch)
            if change.branch is not None
            else None
        )
        for attrpath in change.attrpaths:
            if change.verdict is None:
                remove_verdict(suggestion, attrpath, author, branch=branch, batch=batch)
            else:
                set_verdict(
                    suggestion,
                    attrpath,
                    change.verdict,
                    author,
                    branch=branch,
                    comment=change.comment,
                    fix_commit=change.fix_commit,
                    batch=batch,
                )
        if change.branch is None:
            sync_ignore_overlays(suggestion, change.attrpaths)


def sync_ignore_overlays(
    suggestion: CVEDerivationClusterProposal, attrpaths: Iterable[str]
) -> None:
    """
    Make the package list agree with the verdicts: an attribute is ignored (overlay, hidden
    from the cached package list and so from a published issue) exactly when it has an
    all-branches `irrelevant` verdict, as `ignore_packages` / `restore_packages` leave it.
    A branch-specific `irrelevant` leaves the package listed: it is still relevant elsewhere.
    Attributes the package list does not show (no link) have nothing to hide.
    """
    attrpaths = list(attrpaths)
    irrelevant = set(
        Verdict.objects.filter(
            suggestion=suggestion,
            attrpath__in=attrpaths,
            branch=None,
            verdict=Verdict.Kind.IRRELEVANT,
        ).values_list("attrpath", flat=True)
    )
    overlays = set(
        suggestion.package_overlays.filter(
            package_attribute__in=attrpaths, type=PackageOverlay.Type.IGNORED
        ).values_list("package_attribute", flat=True)
    )
    suggestion.ensure_fresh_cache()
    listed = suggestion.cached.payload["original_packages"]
    to_ignore = [a for a in sorted(irrelevant - overlays) if a in listed]
    to_restore = overlays - irrelevant
    if not to_ignore and not to_restore:
        return
    package_ids = dict(
        PackageAttrpath.objects.filter(attrpath__in=to_ignore).values_list(
            "attrpath", "package_id"
        )
    )
    for attr in to_ignore:
        if attr in package_ids:
            suggestion.package_overlays.get_or_create(
                package_attribute=attr,
                defaults={
                    "type": PackageOverlay.Type.IGNORED,
                    "package_id": package_ids[attr],
                },
            )
    suggestion.package_overlays.filter(
        package_attribute__in=to_restore, type=PackageOverlay.Type.IGNORED
    ).delete()
    suggestion._recompute_package_cache()  # pyright: ignore[reportPrivateUsage]


def bulk_apply_verdicts(
    queryset: QuerySet[CVEDerivationClusterProposal],
    change: VerdictChange,
    author: User | None,
) -> int:
    """Apply the change to every selected suggestion, or to none if any refuses it."""
    with transaction.atomic():
        suggestions = list(queryset)
        tracked = [b.name for b in tracked_branches()]
        errors = {}
        for suggestion in suggestions:
            try:
                check_verdicts(suggestion, change, tracked)
            except ValidationError as error:
                errors[suggestion.pk] = error.message_dict
        if errors:
            raise BulkValidationError(errors)
        for suggestion in suggestions:
            apply_verdicts(suggestion, change, author, check=False)
    return len(suggestions)
