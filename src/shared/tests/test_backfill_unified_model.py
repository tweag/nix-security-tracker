from collections.abc import Callable
from io import StringIO

import pghistory
from django.contrib.auth.models import User
from django.core.management import call_command

from shared.legacy_matching import legacy_build_new_links
from shared.models.cve import AffectedProduct, Container, Version
from shared.models.linkage import CVEDerivationClusterProposal, PackageOverlay
from shared.models.matching import Exposure, Match, TrackerEvent, Verdict
from shared.models.nix_evaluation import NixDerivation, NixEvaluation
from shared.models.package import Package
from shared.pipeline import refresh_suggestion
from shared.snapshot import update_branch_snapshot

Observed = Exposure.Observed


def backfill(*args: str) -> str:
    out = StringIO()
    call_command("backfill_unified_model", *args, stdout=out)
    return out.getvalue()


def test_backfill_suggestion_created_by_the_legacy_matcher(
    make_container: Callable[..., Container],
    make_evaluation: Callable[..., NixEvaluation],
    make_drv: Callable[..., NixDerivation],
    user: User,
) -> None:
    matched_at = make_evaluation()
    for attr in ("foo", "foobar"):
        make_drv(attribute=attr, pname=attr, version="1.0", evaluation=matched_at)
    container = make_container(package_name="foo", product=None)
    Version.objects.update(version="1.0", less_than="2.0")
    AffectedProduct.objects.update(default_status="unaffected")
    assert legacy_build_new_links(container)
    suggestion = CVEDerivationClusterProposal.objects.get()
    CVEDerivationClusterProposal.objects.filter(pk=suggestion.pk).update(
        algorithm_version=2
    )
    with pghistory.context(user=user.pk):
        PackageOverlay.objects.create(
            suggestion=suggestion,
            package_attribute="foobar",
            package=Package.objects.create(name="foobar", homepage="https://x"),
            type=PackageOverlay.Type.IGNORED,
        )
    update_branch_snapshot(matched_at)
    now = make_evaluation()
    for attr in ("foo", "foobar"):
        make_drv(attribute=attr, pname=attr, version="2.0", evaluation=now)
    update_branch_snapshot(now)

    backfill()

    assert {
        (m.attrpath, m.matcher, m.evidence["provenance_flags"])
        for m in Match.objects.active()
    } == {("foo", "legacy-v2", 1), ("foobar", "legacy-v2", 1)}
    foo = Exposure.objects.get(attrpath="foo")
    # As matched (1.0 affected at `matched_at`), then reconciled against today (2.0).
    assert (foo.version, foo.observed) == ("2.0", Observed.UNAFFECTED)
    assert foo.first_affected_evaluation == matched_at
    assert foo.last_affected_evaluation == matched_at
    assert foo.fixed_evaluation == now
    verdict = Verdict.objects.get()
    assert (verdict.attrpath, verdict.verdict, verdict.author) == (
        "foobar",
        Verdict.Kind.IRRELEVANT,
        user,
    )
    assert TrackerEvent.objects.filter(cause=TrackerEvent.Cause.BACKFILL).exists()

    # Idempotent.
    events = TrackerEvent.objects.count()
    backfill("--start-after", "0")
    assert TrackerEvent.objects.count() == events
    assert Match.objects.count() == 2

    # Deploy-time re-match: real matchers take over, the human's ignore stays.
    refresh_suggestion(suggestion)
    suggestion.refresh_from_db()
    assert not Match.objects.active().filter(matcher="legacy-v2").exists()
    assert set(suggestion.derivations.values_list("name", flat=True)) == {
        "foo-2.0",
        "foobar-2.0",
    }
    assert "foobar" not in suggestion.cached.payload["packages"]
    assert "foobar" in suggestion.cached.payload["original_packages"]


def test_backfill_skips_suggestions_of_the_unified_path(
    make_container: Callable[..., Container],
    make_suggestion: Callable[..., CVEDerivationClusterProposal],
) -> None:
    make_suggestion(container=make_container())
    backfill()
    assert not Match.objects.exists()
