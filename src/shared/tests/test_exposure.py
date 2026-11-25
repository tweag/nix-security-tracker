import threading
from collections.abc import Callable
from datetime import timedelta
from typing import Any

import pytest
from django.db import connection

from shared import exposure as exposure_module
from shared.exposure import (
    REMOVAL_AFTER_EVALUATIONS,
    apply_branch_changes,
    reconcile_exposures,
)
from shared.models.cve import AffectedProduct, Container, Version
from shared.models.linkage import CVEDerivationClusterProposal
from shared.models.matching import Exposure, Match, TrackerEvent, Verdict
from shared.models.nix_evaluation import NixChannel, NixEvaluation, NixpkgsBranch
from shared.models.snapshot import BranchPackage, BranchPackageChange

Observed = Exposure.Observed
Reason = Exposure.Reason
Kind = TrackerEvent.Kind
Cause = TrackerEvent.Cause
ChangeKind = BranchPackageChange.Kind
Status = CVEDerivationClusterProposal.Status

CVE_ID = "CVE-2025-0001"


def add_product(
    container: Container,
    product: str,
    ranges: list[tuple[str, str, str]],
    default: str | None = "unaffected",
) -> AffectedProduct:
    """`ranges` are (status, version, lessThan) triples."""
    ap = AffectedProduct.objects.create(
        product=product,
        default_status=default or "unknown",
        default_status_recorded=default is not None,
    )
    for status, version, less_than in ranges:
        ap.versions.add(
            Version.objects.create(status=status, version=version, less_than=less_than)
        )
    container.affected.add(ap)
    return ap


@pytest.fixture
def record(cve: Container) -> Container:
    """The CVE of the default suggestion, with `foo` affected in [1.0, 2.0)."""
    cve.affected.clear()
    add_product(cve, "foo", [("affected", "1.0", "2.0")])
    return cve


@pytest.fixture
def world(
    record: Container,
    make_suggestion: Callable[..., CVEDerivationClusterProposal],
    channel: NixChannel,
    branch: NixpkgsBranch,
    make_evaluation: Callable[..., NixEvaluation],
) -> "World":
    return World(make_suggestion(container=record), branch, channel, make_evaluation)


class World:
    """A suggestion, a tracked branch, and helpers to move the branch through evaluations."""

    def __init__(
        self,
        suggestion: CVEDerivationClusterProposal,
        branch: NixpkgsBranch,
        channel: NixChannel,
        make_evaluation: Callable[..., NixEvaluation],
    ) -> None:
        self.suggestion = suggestion
        self.branch = branch
        self.channel = channel
        self._make_evaluation = make_evaluation
        self.evaluations: list[NixEvaluation] = []
        self._age = 1000

    def evaluation(self) -> NixEvaluation:
        """A new completed evaluation of the branch, newer than all previous ones."""
        self._age -= 1
        evaluation = self._make_evaluation(
            channel=self.channel, age=timedelta(hours=self._age)
        )
        self.evaluations.append(evaluation)
        return evaluation

    def match(self, attrpath: str = "foo", **evidence: Any) -> Match:
        return Match.objects.create(
            suggestion=self.suggestion,
            attrpath=attrpath,
            matcher="test",
            matcher_version=1,
            score=1.0,
            evidence=evidence,
        )

    def package(
        self,
        version: str,
        attrpath: str = "foo",
        present: bool = True,
        known_vulnerabilities: list[str] | None = None,
        kind: str | None = None,
    ) -> NixEvaluation:
        """Advance the branch one evaluation, setting the attribute's state and change row."""
        old = self.branch.current_evaluation
        new = self.evaluation()
        existing = BranchPackage.objects.filter(
            branch=self.branch, attrpath=attrpath
        ).first()
        fields: dict[str, Any] = dict(
            present=present,
            name=f"foo-{version}",
            pname="foo",
            version=version,
            known_vulnerabilities=known_vulnerabilities or [],
            systems=["x86_64-linux"],
            drv_digest=f"{version}{present}{known_vulnerabilities}",
        )
        if present:
            fields["evaluation"] = new
        if existing is None:
            fields.setdefault("evaluation", new)
            BranchPackage.objects.create(
                branch=self.branch, attrpath=attrpath, **fields
            )
            kind = kind or ChangeKind.ADDED
        else:
            if kind is None:
                if not present:
                    kind = ChangeKind.REMOVED
                elif not existing.present:
                    kind = ChangeKind.ADDED
                elif existing.version != version:
                    kind = ChangeKind.VERSION_CHANGED
                else:
                    kind = ChangeKind.META_CHANGED
            BranchPackage.objects.filter(pk=existing.pk).update(**fields)
        if old is not None:
            BranchPackageChange.objects.create(
                branch=self.branch,
                attrpath=attrpath,
                kind=kind,
                old_version=existing.version if existing else None,
                new_version=version,
                old_evaluation=old,
                new_evaluation=new,
            )
        self.advance(new)
        return new

    def advance(self, evaluation: NixEvaluation) -> None:
        self.branch.current_evaluation = evaluation
        self.branch.save()

    def idle(self) -> NixEvaluation:
        """An evaluation step in which nothing changed for any attribute."""
        new = self.evaluation()
        self.advance(new)
        return new

    def apply(self, evaluation: NixEvaluation) -> exposure_module.ExposureResult:
        return apply_branch_changes(evaluation, self.branch)

    def reconcile(self, cause: str = Cause.MATCHER) -> exposure_module.ExposureResult:
        return reconcile_exposures(self.suggestion, cause)

    def row(self, attrpath: str = "foo") -> Exposure:
        return Exposure.objects.get(
            suggestion=self.suggestion, attrpath=attrpath, branch=self.branch
        )

    def events(self) -> list[TrackerEvent]:
        return list(
            TrackerEvent.objects.filter(suggestion=self.suggestion).order_by("pk")
        )


def kinds(result: exposure_module.ExposureResult) -> dict[str, int]:
    return dict(result.events)


def test_appears_on_reconcile(world: World) -> None:
    world.match()
    first = world.package("1.5")
    result = world.reconcile()
    assert kinds(result) == {Kind.EXPOSURE_APPEARED: 1}
    row = world.row()
    assert (row.observed, row.reason, row.version) == (
        Observed.AFFECTED,
        Reason.VERSION_RANGE,
        "1.5",
    )
    assert row.first_affected_evaluation == first
    assert row.last_affected_evaluation == first
    assert row.detail["range"] == "[1.0, 2.0)"
    (event,) = world.events()
    assert (event.cause, event.evaluation, event.batch) == (
        Cause.MATCHER,
        first,
        result.batch,
    )
    assert event.data["new_status"] == Observed.AFFECTED


def test_fix_is_observed(world: World) -> None:
    world.match()
    affected_at = world.package("1.5")
    world.reconcile()
    fixed_at = world.package("2.0")
    result = world.apply(fixed_at)
    assert kinds(result) == {Kind.EXPOSURE_BECAME_UNAFFECTED: 1}
    row = world.row()
    assert row.observed == Observed.UNAFFECTED
    assert row.fixed_evaluation == fixed_at
    assert row.last_affected_evaluation == affected_at
    assert row.detail["last_affected_version"] == "1.5"
    event = world.events()[-1]
    assert event.cause == Cause.EVALUATION
    assert event.data | {"detail": None} == {
        "old_version": "1.5",
        "new_version": "2.0",
        "old_status": "affected",
        "new_status": "unaffected",
        "old_reason": "version_range",
        "new_reason": "default_status",
        "detail": None,
        "fix_candidate": True,
    }


def test_version_change_within_range(world: World) -> None:
    world.match()
    world.package("1.5")
    world.reconcile()
    second = world.package("1.6")
    assert kinds(world.apply(second)) == {Kind.EXPOSURE_VERSION_CHANGED: 1}
    assert world.row().last_affected_evaluation == second


def test_fix_through_unknown(world: World) -> None:
    world.match()
    affected_at = world.package("1.5")
    world.reconcile()
    unknown_at = world.package("1.5-unstable-2026-01-02")
    assert kinds(world.apply(unknown_at)) == {Kind.EXPOSURE_STATUS_CHANGED: 1}
    row = world.row()
    assert (row.observed, row.fixed_evaluation) == (Observed.UNKNOWN, None)
    assert row.last_affected_evaluation == affected_at
    fixed_at = world.package("2.1")
    assert kinds(world.apply(fixed_at)) == {Kind.EXPOSURE_BECAME_UNAFFECTED: 1}
    row = world.row()
    assert row.fixed_evaluation == fixed_at
    assert row.last_affected_evaluation == affected_at
    assert world.events()[-1].data["via"] == Observed.UNKNOWN


def test_unknown_to_unaffected_without_affected_is_not_a_fix(world: World) -> None:
    world.match()
    world.package("1.5-unstable-2026-01-02")
    world.reconcile()
    assert world.row().observed == Observed.UNKNOWN
    later = world.package("2.1")
    assert kinds(world.apply(later)) == {Kind.EXPOSURE_STATUS_CHANGED: 1}
    row = world.row()
    assert (row.observed, row.fixed_evaluation) == (Observed.UNAFFECTED, None)


def test_regression_after_fix(world: World) -> None:
    world.match()
    world.package("1.5")
    world.reconcile()
    fixed_at = world.package("2.0")
    world.apply(fixed_at)
    regressed_at = world.package("1.9")
    assert kinds(world.apply(regressed_at)) == {Kind.EXPOSURE_BECAME_AFFECTED: 1}
    row = world.row()
    assert (row.observed, row.fixed_evaluation) == (Observed.AFFECTED, None)
    assert row.last_affected_evaluation == regressed_at
    data = world.events()[-1].data
    assert data["regression"] is True
    assert data["previous_fixed_evaluation"] == fixed_at.pk


def test_acknowledged_in_known_vulnerabilities(world: World) -> None:
    world.match()
    world.package("2.5")
    world.reconcile()
    assert world.row().observed == Observed.UNAFFECTED
    flagged = world.package("2.5", known_vulnerabilities=[CVE_ID])
    assert kinds(world.apply(flagged)) == {Kind.EXPOSURE_BECAME_AFFECTED: 1}
    row = world.row()
    assert (row.observed, row.reason) == (Observed.AFFECTED, Reason.ACKNOWLEDGED)


def test_missing_for_one_evaluation_loses_nothing(world: World) -> None:
    """1.8 problem 2: one failed attribute evaluation must not reject or drop anything."""
    world.match()
    world.package("1.5")
    world.reconcile()
    gone = world.package("1.5", present=False)
    assert kinds(world.apply(gone)) == {Kind.EXPOSURE_DISAPPEARED: 1}
    row = world.row()
    assert (row.present, row.observed, row.reason) == (
        False,
        Observed.ABSENT,
        Reason.VERSION_RANGE,
    )
    back = world.package("1.5")
    assert kinds(world.apply(back)) == {Kind.EXPOSURE_REAPPEARED: 1}
    row = world.row()
    assert (row.present, row.observed) == (True, Observed.AFFECTED)
    assert row.fixed_evaluation is None
    world.suggestion.refresh_from_db()
    assert world.suggestion.status == Status.PENDING
    assert Match.objects.active().filter(suggestion=world.suggestion).count() == 1


def test_removed_after_staying_gone(world: World) -> None:
    world.match()
    world.package("1.5")
    world.reconcile()
    # The evaluation it disappears in is the first one missing it.
    world.apply(world.package("1.5", present=False))
    for _ in range(REMOVAL_AFTER_EVALUATIONS - 2):
        assert kinds(world.apply(world.idle())) == {}
        assert world.row().reason == Reason.VERSION_RANGE
    result = world.apply(world.idle())
    assert kinds(result) == {Kind.EXPOSURE_STATUS_CHANGED: 1}
    row = world.row()
    assert (row.observed, row.reason) == (Observed.ABSENT, Reason.REMOVED)
    assert kinds(world.apply(world.idle())) == {}
    # Coming back after removal is a reappearance like any other.
    assert kinds(world.apply(world.package("1.5"))) == {Kind.EXPOSURE_REAPPEARED: 1}
    assert world.row().observed == Observed.AFFECTED


def test_reappearing_fixed_is_a_fix(world: World) -> None:
    world.match()
    world.package("1.5")
    world.reconcile()
    world.apply(world.package("1.5", present=False))
    back = world.package("2.0")
    assert kinds(world.apply(back)) == {Kind.EXPOSURE_BECAME_UNAFFECTED: 1}
    assert world.events()[-1].data["reappeared"] is True
    assert world.row().fixed_evaluation == back


def test_scoping_by_match_evidence(
    world: World,
    record: Container,
    make_evaluation: Callable[..., NixEvaluation],
) -> None:
    """The report's pooled-products case: [2.0, 2.0.5) of foo, [3.0, 3.0.2) of foo-server."""
    record.affected.clear()
    foo = add_product(record, "foo", [("affected", "2.0", "2.0.5")])
    add_product(record, "foo-server", [("affected", "3.0", "3.0.2")])
    world.match(affected_product=foo.pk)
    world.package("3.0.1")
    world.reconcile()
    row = world.row()
    assert (row.observed, row.detail["affected_product"]) == (
        Observed.UNAFFECTED,
        foo.pk,
    )
    world.package("2.1.0")
    world.reconcile()
    assert world.row().observed == Observed.UNAFFECTED


def test_without_evidence_all_products_count(world: World, record: Container) -> None:
    record.affected.clear()
    add_product(record, "foo", [("affected", "2.0", "2.0.5")])
    add_product(record, "foo-server", [("affected", "3.0", "3.0.2")])
    world.match()
    world.package("3.0.1")
    world.reconcile()
    assert world.row().observed == Observed.AFFECTED


def test_stale_evidence_falls_back_to_all_products(world: World) -> None:
    world.match(affected_product=987654)
    world.package("1.5")
    world.reconcile()
    assert world.row().observed == Observed.AFFECTED


def test_inferred_unaffected_is_marked(world: World, record: Container) -> None:
    record.affected.clear()
    add_product(record, "foo", [("affected", "0", "2.0")], default=None)
    world.match()
    world.package("2.1")
    world.reconcile()
    row = world.row()
    assert (row.observed, row.detail["inferred"]) == (Observed.UNAFFECTED, True)
    assert world.events()[-1].data["inferred"] is True


def test_idempotence(world: World) -> None:
    world.match()
    world.match("bar")
    first = world.package("1.5")
    world.package("1.0", attrpath="bar")
    world.reconcile()
    assert kinds(world.reconcile()) == {}
    step = world.package("2.0")
    assert kinds(world.apply(step)) == {Kind.EXPOSURE_BECAME_UNAFFECTED: 1}
    count = len(world.events())
    before = list(Exposure.objects.order_by("pk").values())
    assert kinds(world.apply(step)) == {}
    assert kinds(world.reconcile()) == {}
    assert kinds(world.apply(step)) == {}
    assert len(world.events()) == count
    assert list(Exposure.objects.order_by("pk").values()) == before
    # A late run for an older step does not roll anything back.
    assert kinds(world.apply(first)) == {}
    assert list(Exposure.objects.order_by("pk").values()) == before


def test_rebuilt_calls_patch_seam(
    world: World, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[tuple[Exposure, BranchPackageChange]] = []
    monkeypatch.setattr(
        exposure_module, "detect_patch_fix", lambda e, c: calls.append((e, c))
    )
    world.match()
    world.package("1.5")
    world.reconcile()
    rebuilt = world.package("1.5", kind=ChangeKind.REBUILT)
    result = world.apply(rebuilt)
    assert kinds(result) == {}
    assert result.rebuilt_affected == [world.row().pk]
    assert len(calls) == 1


def test_added_attributes(world: World) -> None:
    world.idle()
    world.match()
    added = world.package("1.5")
    world.package("1.0", attrpath="unrelated")
    # Both added in their own steps; the matched one gets an exposure.
    result = world.apply(added)
    assert kinds(result) == {Kind.EXPOSURE_APPEARED: 1}
    assert result.unreferenced_added == []
    result = world.apply(world.branch.current_evaluation)  # type: ignore[arg-type]
    assert result.unreferenced_added == ["unrelated"]


def test_retracted_matches_freeze_rows(world: World) -> None:
    match = world.match()
    world.package("1.5")
    world.reconcile()
    match.retracted_at = match.last_seen_at
    match.save()
    step = world.package("2.0")
    assert kinds(world.apply(step)) == {}
    assert world.row().observed == Observed.AFFECTED
    # A verdict keeps the attribute current without any match.
    Verdict.objects.create(
        suggestion=world.suggestion, attrpath="foo", verdict=Verdict.Kind.AFFECTED
    )
    assert kinds(world.apply(step)) == {Kind.EXPOSURE_BECAME_UNAFFECTED: 1}


@pytest.mark.parametrize(
    "status, reason, updated",
    [
        (Status.PUBLISHED, None, True),
        (Status.ACCEPTED, None, True),
        (Status.REJECTED, "no_matches", True),
        (Status.REJECTED, "known_vulnerability", True),
        (Status.REJECTED, "not_in_nixpkgs", False),
        (Status.REJECTED, "exclusively_hosted_service", False),
        (Status.REJECTED, None, False),
    ],
)
def test_which_suggestions_take_part(
    world: World, status: str, reason: str | None, updated: bool
) -> None:
    world.match()
    world.package("1.5")
    world.reconcile()
    paths: dict[str, list[str]] = {
        Status.PUBLISHED: [Status.ACCEPTED, Status.PUBLISHED],
        Status.ACCEPTED: [Status.ACCEPTED],
        Status.REJECTED: [Status.REJECTED],
    }
    path = paths[status]
    for step in path:
        CVEDerivationClusterProposal.objects.filter(pk=world.suggestion.pk).update(
            status=step, rejection_reason=reason if step == Status.REJECTED else None
        )
    result = world.apply(world.package("2.0"))
    assert bool(result.events) == updated
    assert (world.suggestion.pk in result.skipped_dismissed) != updated
    assert (world.row().observed == Observed.UNAFFECTED) == updated


def test_untracked_branch_is_ignored(
    world: World, make_branch: Callable[..., NixpkgsBranch]
) -> None:
    world.match()
    world.package("1.5")
    other = make_branch("release-20.03")
    BranchPackage.objects.create(
        branch=other,
        attrpath="foo",
        evaluation=world.evaluations[-1],
        name="foo-1.5",
        pname="foo",
        version="1.5",
        drv_digest="x",
    )
    world.reconcile()
    assert Exposure.objects.filter(branch=other).count() == 0


def test_concurrent_reconciliations(
    transactional_db: None,
    make_container: Callable[..., Container],
    make_suggestion: Callable[..., CVEDerivationClusterProposal],
    channel: NixChannel,
    branch: NixpkgsBranch,
    make_evaluation: Callable[..., NixEvaluation],
) -> None:
    container = make_container()
    container.affected.clear()
    add_product(container, "foo", [("affected", "1.0", "2.0")])
    world = World(
        make_suggestion(container=container), branch, channel, make_evaluation
    )
    for attr in ("foo", "bar", "baz"):
        world.match(attr)
        world.package("1.5", attrpath=attr)
    errors: list[BaseException] = []
    start = threading.Barrier(4)

    def run() -> None:
        try:
            start.wait()
            reconcile_exposures(world.suggestion, Cause.BACKFILL)
            step = world.branch.current_evaluation
            assert step is not None
            apply_branch_changes(step, world.branch)
        except BaseException as e:  # noqa: BLE001
            errors.append(e)
        finally:
            connection.close()

    threads = [threading.Thread(target=run) for _ in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert errors == []
    assert Exposure.objects.count() == 3
    assert TrackerEvent.objects.filter(kind=Kind.EXPOSURE_APPEARED).count() == 3, list(
        TrackerEvent.objects.values_list("kind", "attrpath")
    )
    assert TrackerEvent.objects.count() == 3


def test_record_without_cve_products(world: World) -> None:
    world.suggestion.cve.container.first().affected.clear()  # type: ignore[union-attr]
    world.match()
    world.package("1.5")
    world.reconcile()
    assert (world.row().observed, world.row().reason) == (
        Observed.UNKNOWN,
        Reason.NO_RANGE,
    )
