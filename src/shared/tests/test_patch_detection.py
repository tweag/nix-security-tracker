from pathlib import Path
from typing import Any

import pytest

from shared.exposure import ExposureResult, detect_patches, package_paths
from shared.history import HistoryClone
from shared.models.matching import Exposure, TrackerEvent
from shared.models.nix_evaluation import NixEvaluation
from shared.models.snapshot import BranchPackage, BranchPackageChange
from shared.tests import test_exposure
from shared.tests.local_repo import LocalRepo
from shared.tests.test_exposure import CVE_ID, World

record = test_exposure.record
world = test_exposure.world

Observed = Exposure.Observed
Reason = Exposure.Reason
REBUILT = BranchPackageChange.Kind.REBUILT
FILE = "pkgs/by-name/fo/foo/package.nix"


@pytest.mark.parametrize(
    ("position", "paths"),
    [
        (f"{FILE}:12", ["pkgs/by-name/fo/foo"]),
        ("pkgs/tools/foo/default.nix:3", ["pkgs/tools/foo"]),
        ("pkgs/top-level/all-packages.nix:100", ["pkgs/top-level/all-packages.nix"]),
        ("/nix/store/abc-source/foo.nix:1", []),
        (None, []),
    ],
)
def test_package_paths(position: str | None, paths: list[str]) -> None:
    assert package_paths(position) == paths


class Nixpkgs:
    """A local nixpkgs whose commits the world's evaluations point at, and its history clone."""

    def __init__(self, tmp_path: Path, settings: Any, filter: str) -> None:
        self.repo = LocalRepo(tmp_path / "nixpkgs")
        settings.GIT_CLONE_URL = self.repo.url
        settings.NIXPKGS_HISTORY_CHECKOUT = tmp_path / "history.git"
        settings.NIXPKGS_HISTORY_FILTER = filter
        self.settings = settings

    def at(
        self, evaluation: NixEvaluation, message: str, files: dict[str, str]
    ) -> None:
        commit = self.repo.commit("master", message, files)
        NixEvaluation.objects.filter(pk=evaluation.pk).update(commit_sha1=commit)

    def fetch(self) -> None:
        clone = HistoryClone.from_settings()
        assert clone is not None
        clone.fetch(["master"])


def step(world: World, evaluation: NixEvaluation) -> ExposureResult:
    """The evaluation step, then the patch detection it dispatches."""
    world.apply(evaluation)
    return detect_patches(evaluation, world.branch)


def affected(world: World, nixpkgs: Nixpkgs) -> NixEvaluation:
    world.match()
    first = world.package("1.5")
    BranchPackage.objects.filter(attrpath="foo").update(position=f"{FILE}:10")
    nixpkgs.at(first, "foo: init at 1.5", {FILE: "1.5"})
    world.reconcile()
    assert world.row().observed == Observed.AFFECTED
    return first


@pytest.mark.parametrize("filter", ["blob:none", "tree:0"])
def test_patch_commit_makes_a_fix_candidate(
    world: World, tmp_path: Path, settings: Any, filter: str
) -> None:
    nixpkgs = Nixpkgs(tmp_path, settings, filter)
    affected(world, nixpkgs)
    rebuilt = world.package("1.5", kind=REBUILT)
    nixpkgs.repo.commit("master", "bar: unrelated", {"pkgs/bar.nix": "x"})
    nixpkgs.at(
        rebuilt,
        f"foo: add patch for {CVE_ID}",
        {FILE: "1.5 + patch", "pkgs/by-name/fo/foo/fix.patch": "+"},
    )
    nixpkgs.fetch()

    result = step(world, rebuilt)

    row = world.row()
    rebuilt.refresh_from_db()
    assert (row.observed, row.reason, row.version) == (
        Observed.UNAFFECTED,
        Reason.PATCH,
        "1.5",
    )
    assert row.fixed_evaluation == rebuilt
    assert row.fix_commit == rebuilt.commit_sha1
    assert result.patched == [row.pk]
    event = world.events()[-1]
    assert event.kind == TrackerEvent.Kind.EXPOSURE_BECAME_UNAFFECTED
    assert event.data["fix_candidate"] is True
    assert event.data["fix_commit"] == rebuilt.commit_sha1

    # The patch holds through later metadata changes of the same version ...
    meta = world.package("1.5")
    world.apply(meta)
    assert world.row().reason == Reason.PATCH
    # ... until the version changes.
    world.apply(world.package("1.6"))
    row = world.row()
    assert (row.observed, row.reason) == (Observed.AFFECTED, Reason.VERSION_RANGE)


def test_commit_elsewhere_is_ignored_with_trees(
    world: World, tmp_path: Path, settings: Any
) -> None:
    nixpkgs = Nixpkgs(tmp_path, settings, "blob:none")
    affected(world, nixpkgs)
    rebuilt = world.package("1.5", kind=REBUILT)
    nixpkgs.at(rebuilt, f"bar: patch {CVE_ID}", {"pkgs/bar/default.nix": "p"})
    nixpkgs.fetch()

    result = step(world, rebuilt)

    assert result.patched == []
    assert world.row().observed == Observed.AFFECTED


def test_no_mention_no_candidate(world: World, tmp_path: Path, settings: Any) -> None:
    nixpkgs = Nixpkgs(tmp_path, settings, "blob:none")
    affected(world, nixpkgs)
    rebuilt = world.package("1.5", kind=REBUILT)
    nixpkgs.at(rebuilt, "foo: fix build", {FILE: "1.5 + build fix"})
    nixpkgs.fetch()
    assert step(world, rebuilt).patched == []


def test_unknown_commits_or_no_clone_do_nothing(
    world: World, tmp_path: Path, settings: Any
) -> None:
    nixpkgs = Nixpkgs(tmp_path, settings, "blob:none")
    affected(world, nixpkgs)
    rebuilt = world.package("1.5", kind=REBUILT)
    nixpkgs.at(rebuilt, f"foo: patch {CVE_ID}", {FILE: "p"})
    # Not fetched: the commits are unknown to the clone, nothing is downloaded.
    assert step(world, rebuilt).patched == []

    settings.NIXPKGS_HISTORY_CHECKOUT = None
    again = world.package("1.5", kind=REBUILT)
    assert step(world, again).patched == []


def test_a_later_evaluation_wins(world: World, tmp_path: Path, settings: Any) -> None:
    """Detection for an old step does not overwrite what a newer evaluation established."""
    nixpkgs = Nixpkgs(tmp_path, settings, "blob:none")
    affected(world, nixpkgs)
    rebuilt = world.package("1.5", kind=REBUILT)
    nixpkgs.at(rebuilt, f"foo: patch {CVE_ID}", {FILE: "p"})
    nixpkgs.fetch()
    world.apply(rebuilt)
    world.apply(world.package("1.6"))  # still affected, newer evaluation
    assert detect_patches(rebuilt, world.branch).patched == []
    assert world.row().reason == Reason.VERSION_RANGE


def test_evaluation_step_dispatches_patch_detection(
    world: World, tmp_path: Path, settings: Any
) -> None:
    from unittest import mock

    from shared.channels import PatchDetectionChannel
    from shared.pipeline import apply_evaluation

    nixpkgs = Nixpkgs(tmp_path, settings, "blob:none")
    affected(world, nixpkgs)
    rebuilt = world.package("1.5", kind=REBUILT)
    with mock.patch("shared.pipeline.pgpubsub.notify") as notify:
        apply_evaluation(rebuilt, world.branch)
    assert (
        mock.call(
            PatchDetectionChannel, evaluation_pk=rebuilt.pk, branch=world.branch.name
        )
        in notify.call_args_list
    )


def test_patch_level_bump_that_stays_in_range(
    world: World, tmp_path: Path, settings: Any
) -> None:
    """`glibc 2.42-100 -> 2.42-103; fixes CVE-...`: a version change still in range."""
    nixpkgs = Nixpkgs(tmp_path, settings, "blob:none")
    affected(world, nixpkgs)
    bumped = world.package("1.5.1")
    nixpkgs.at(bumped, f"foo: 1.5 -> 1.5.1, fixes {CVE_ID}", {FILE: "1.5.1"})
    nixpkgs.fetch()

    applied = world.apply(bumped)
    assert applied.rebuilt_affected == [world.row().pk]
    result = detect_patches(bumped, world.branch)

    row = world.row()
    assert result.patched == [row.pk]
    assert (row.observed, row.reason, row.version) == (
        Observed.UNAFFECTED,
        Reason.PATCH,
        "1.5.1",
    )
