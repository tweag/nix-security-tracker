from collections.abc import Callable
from datetime import timedelta
from typing import Any
from unittest import mock

import pytest

from shared.models.matching import Match
from shared.models.nix_evaluation import (
    NixChannel,
    NixDerivation,
    NixEvaluation,
    NixpkgsBranch,
    parse_drv_name,
)
from shared.models.package import Package, PackageAttrpath
from shared.models.snapshot import BranchPackage, BranchPackageChange
from shared.snapshot import (
    Outcome,
    SnapshotResult,
    fill_package_groups,
    update_branch_snapshot,
)

Kind = BranchPackageChange.Kind


@pytest.fixture
def make_attr(
    make_drv: Callable[..., NixDerivation],
) -> Callable[..., NixDerivation]:
    """A derivation of `attribute` in `evaluation`; `rebuild` changes its derivation path only."""

    def wrapped(
        evaluation: NixEvaluation,
        attribute: str,
        version: str = "1.0",
        pname: str | None = None,
        rebuild: str = "",
        **kwargs: Any,
    ) -> NixDerivation:
        drv = make_drv(
            pname=pname or attribute,
            version=version,
            attribute=attribute,
            evaluation=evaluation,
            **kwargs,
        )
        if rebuild:
            drv.derivation_path = drv.derivation_path.replace(
                "<hash>", f"<hash{rebuild}>"
            )
            drv.save()
        return drv

    return wrapped


def outcomes(result: SnapshotResult) -> dict[str, Outcome]:
    return {b.branch: b.outcome for b in result.branches}


def changes(evaluation: NixEvaluation) -> dict[str, tuple[str, list[str]]]:
    return {
        c.attrpath: (c.kind, c.changed_fields)
        for c in BranchPackageChange.objects.filter(new_evaluation=evaluation)
    }


def test_first_snapshot_writes_rows_but_no_changes(
    branch: NixpkgsBranch,
    evaluation: NixEvaluation,
    make_attr: Callable[..., NixDerivation],
) -> None:
    make_attr(evaluation, "foo", version="1.2.3", homepage="https://foo.org")
    make_attr(evaluation, "python3Packages.bar", pname="python3.12-bar")

    result = update_branch_snapshot(evaluation)

    assert outcomes(result) == {"master": Outcome.INITIALISED}
    assert not BranchPackageChange.objects.exists()
    foo = BranchPackage.objects.get(attrpath="foo")
    assert (foo.name, foo.pname, foo.version) == ("foo-1.2.3", "foo", "1.2.3")
    assert foo.homepage == "https://foo.org"
    assert foo.evaluation == evaluation
    assert foo.present
    assert len(foo.drv_digest) == 64
    bar = BranchPackage.objects.get(attrpath="python3Packages.bar")
    assert (bar.pname, bar.version) == ("python3.12-bar", "1.0")
    branch.refresh_from_db()
    assert branch.current_evaluation == evaluation


def test_change_kinds(
    make_evaluation: Callable[..., NixEvaluation],
    make_attr: Callable[..., NixDerivation],
) -> None:
    old = make_evaluation()
    make_attr(old, "version", cpe_vendor="v")
    make_attr(old, "meta", homepage="https://old.org")
    make_attr(old, "rebuilt")
    make_attr(old, "same", position="/tmp/tmpold/pkgs/same.nix:1")
    make_attr(old, "removed")
    update_branch_snapshot(old)

    new = make_evaluation()
    make_attr(new, "version", version="2.0", cpe_vendor="w", rebuild="x")
    make_attr(new, "meta", homepage="https://new.org", rebuild="x")
    make_attr(new, "rebuilt", rebuild="x")
    # A different line in a different temporary worktree is no change.
    make_attr(new, "same", position="/tmp/tmpnew/pkgs/same.nix:2")
    make_attr(new, "added")
    result = update_branch_snapshot(new, rebuilt="all")

    assert outcomes(result) == {"master": Outcome.ADVANCED}
    assert changes(new) == {
        "version": (Kind.VERSION_CHANGED, ["cpe_vendor"]),
        "meta": (Kind.META_CHANGED, ["homepage"]),
        "rebuilt": (Kind.REBUILT, []),
        "removed": (Kind.REMOVED, []),
        "added": (Kind.ADDED, []),
    }
    version = BranchPackageChange.objects.get(attrpath="version")
    assert (version.old_version, version.new_version) == ("1.0", "2.0")
    assert (version.old_evaluation, version.new_evaluation) == (old, new)
    removed = BranchPackageChange.objects.get(attrpath="removed")
    assert (removed.old_version, removed.new_version) == ("1.0", None)
    assert result.branches[0].changes == {
        Kind.VERSION_CHANGED: 1,
        Kind.META_CHANGED: 1,
        Kind.REBUILT: 1,
        Kind.REMOVED: 1,
        Kind.ADDED: 1,
    }
    assert BranchPackage.objects.get(attrpath="same").position == "pkgs/same.nix:2"


def test_position_file_change_is_meta_change(
    make_evaluation: Callable[..., NixEvaluation],
    make_attr: Callable[..., NixDerivation],
) -> None:
    old = make_evaluation()
    make_attr(old, "foo", position="/tmp/tmpa/pkgs/foo/default.nix:3")
    make_attr(old, "bar")
    update_branch_snapshot(old)
    new = make_evaluation()
    make_attr(new, "foo", position="/tmp/tmpb/pkgs/by-name/fo/foo/package.nix:3")
    make_attr(new, "bar")
    update_branch_snapshot(new)

    assert changes(new) == {"foo": (Kind.META_CHANGED, ["position"])}


@pytest.mark.parametrize(
    "policy,recorded",
    [("all", True), ("none", False), ("matched", True)],
)
def test_rebuilt_policy(
    make_evaluation: Callable[..., NixEvaluation],
    make_attr: Callable[..., NixDerivation],
    make_match: Callable[..., Match],
    policy: str,
    recorded: bool,
) -> None:
    old = make_evaluation()
    make_attr(old, "matched")
    make_attr(old, "unmatched")
    update_branch_snapshot(old)
    make_match(attrpath="matched")
    make_match(attrpath="unmatched", retracted_at=old.created_at)
    new = make_evaluation()
    make_attr(new, "matched", rebuild="x")
    make_attr(new, "unmatched", rebuild="x")

    update_branch_snapshot(new, rebuilt=policy)  # type: ignore[arg-type]

    expected = {"matched": (Kind.REBUILT, [])} if recorded else {}
    if policy == "all":
        expected["unmatched"] = (Kind.REBUILT, [])
    assert changes(new) == expected


def test_multi_system_collapse(
    make_evaluation: Callable[..., NixEvaluation],
    make_attr: Callable[..., NixDerivation],
) -> None:
    def evaluate(systems: list[str]) -> NixEvaluation:
        evaluation = make_evaluation()
        for system in systems:
            # Systems disagree on the version; x86_64-linux wins.
            version = "1.0" if system == "x86_64-linux" else f"1.0-{system}"
            make_attr(evaluation, "foo", version=version, system=system)
        make_attr(evaluation, "bar")
        return evaluation

    first = evaluate(["aarch64-darwin", "x86_64-linux", "aarch64-linux"])
    update_branch_snapshot(first)
    foo = BranchPackage.objects.get(attrpath="foo")
    assert foo.systems == ["aarch64-darwin", "aarch64-linux", "x86_64-linux"]
    assert foo.version == "1.0"

    # Same derivations, inserted in a different order: nothing changes.
    second = evaluate(["x86_64-linux", "aarch64-linux", "aarch64-darwin"])
    update_branch_snapshot(second, rebuilt="all")
    assert changes(second) == {}
    assert BranchPackage.objects.get(attrpath="foo").drv_digest == foo.drv_digest

    # Without x86_64-linux, the next preferred system describes the attribute.
    third = evaluate(["aarch64-darwin", "aarch64-linux"])
    update_branch_snapshot(third, rebuilt="all")
    assert changes(third) == {"foo": (Kind.VERSION_CHANGED, [])}
    assert BranchPackage.objects.get(attrpath="foo").version == "1.0-aarch64-linux"


def test_derivation_without_metadata_is_not_representative(
    evaluation: NixEvaluation,
    make_attr: Callable[..., NixDerivation],
) -> None:
    make_attr(evaluation, "foo", system="aarch64-darwin", cpe_vendor="foo")
    bare = make_attr(evaluation, "foo", system="x86_64-linux")
    bare.metadata = None
    bare.save()

    update_branch_snapshot(evaluation)

    assert BranchPackage.objects.get(attrpath="foo").cpe_vendor == "foo"


@pytest.mark.parametrize(
    "position,normalised",
    [
        (
            "/tmp/tmpfh7ff2xs/pkgs/development/python-modules/qemu/default.nix:67",
            "pkgs/development/python-modules/qemu/default.nix:67",
        ),
        (
            "/nix/store/0123abcd-source/pkgs/by-name/he/hello/package.nix:4",
            "pkgs/by-name/he/hello/package.nix:4",
        ),
        ("pkgs/top-level/all-packages.nix:10", "pkgs/top-level/all-packages.nix:10"),
        (None, None),
    ],
)
def test_position_normalisation(
    evaluation: NixEvaluation,
    make_attr: Callable[..., NixDerivation],
    position: str | None,
    normalised: str | None,
) -> None:
    make_attr(evaluation, "foo", position=position)

    update_branch_snapshot(evaluation)

    assert BranchPackage.objects.get(attrpath="foo").position == normalised


@pytest.mark.parametrize(
    "name",
    [
        "hello-2.12",
        "python3.12-requests-2.32.3",
        "nix-2.24.0pre20240101_abcdef",
        "linux-6.6.1-rt",
        "foo",
        "foo-bar",
        "foo-bar-1",
        "foo--1",
        "-1.0",
        "gcc-wrapper-13.2.0",
        "openssl-3.0.13-dev",
    ],
)
def test_name_parsing_matches_parse_drv_name(
    evaluation: NixEvaluation,
    make_attr: Callable[..., NixDerivation],
    name: str,
) -> None:
    drv = make_attr(evaluation, "foo")
    drv.name = name
    drv.save()

    update_branch_snapshot(evaluation)

    row = BranchPackage.objects.get(attrpath="foo")
    assert (row.pname, row.version) == parse_drv_name(name)


def test_vanished_attribute_is_kept_and_reappears(
    make_evaluation: Callable[..., NixEvaluation],
    make_attr: Callable[..., NixDerivation],
) -> None:
    first = make_evaluation()
    for attribute in ["foo", "bar", "baz"]:
        make_attr(first, attribute)
    update_branch_snapshot(first)

    second = make_evaluation()
    for attribute in ["foo", "bar"]:
        make_attr(second, attribute)
    result = update_branch_snapshot(second)
    assert result.branches[0].marked_absent == 1
    assert changes(second) == {"baz": (Kind.REMOVED, [])}
    baz = BranchPackage.objects.get(attrpath="baz")
    assert not baz.present
    assert baz.evaluation == first
    assert list(
        BranchPackage.objects.present()
        .order_by("attrpath")
        .values_list("attrpath", flat=True)
    ) == ["bar", "foo"]

    # Still missing: no further change.
    third = make_evaluation()
    for attribute in ["foo", "bar"]:
        make_attr(third, attribute)
    update_branch_snapshot(third)
    assert changes(third) == {}

    fourth = make_evaluation()
    for attribute in ["foo", "bar"]:
        make_attr(fourth, attribute)
    make_attr(fourth, "baz", version="2.0")
    update_branch_snapshot(fourth)
    assert changes(fourth) == {"baz": (Kind.ADDED, [])}
    added = BranchPackageChange.objects.get(new_evaluation=fourth)
    assert (added.old_version, added.new_version) == ("1.0", "2.0")
    baz.refresh_from_db()
    assert baz.present
    assert baz.evaluation == fourth


def test_older_evaluation_completing_late_is_skipped(
    branch: NixpkgsBranch,
    make_evaluation: Callable[..., NixEvaluation],
    make_attr: Callable[..., NixDerivation],
) -> None:
    older = make_evaluation(
        state=NixEvaluation.EvaluationState.IN_PROGRESS, age=timedelta(hours=1)
    )
    make_attr(older, "foo", version="1.0")
    newer = make_evaluation()
    make_attr(newer, "foo", version="2.0")
    update_branch_snapshot(newer)

    # The older one finishes last, so it has the most recent `updated_at`.
    older.state = NixEvaluation.EvaluationState.COMPLETED
    older.save()
    result = update_branch_snapshot(older)

    assert outcomes(result) == {"master": Outcome.SKIPPED_OLDER}
    branch.refresh_from_db()
    assert branch.current_evaluation == newer
    assert BranchPackage.objects.get(attrpath="foo").version == "2.0"


def test_unfinished_evaluation_is_skipped(
    branch: NixpkgsBranch,
    make_evaluation: Callable[..., NixEvaluation],
    make_attr: Callable[..., NixDerivation],
) -> None:
    evaluation = make_evaluation(state=NixEvaluation.EvaluationState.IN_PROGRESS)
    make_attr(evaluation, "foo")

    result = update_branch_snapshot(evaluation)

    assert outcomes(result) == {"master": Outcome.SKIPPED_NOT_COMPLETED}
    assert not BranchPackage.objects.exists()


def test_rerun_is_a_no_op(
    make_evaluation: Callable[..., NixEvaluation],
    make_attr: Callable[..., NixDerivation],
) -> None:
    old = make_evaluation()
    make_attr(old, "foo")
    update_branch_snapshot(old)
    new = make_evaluation()
    make_attr(new, "foo", version="2.0")
    update_branch_snapshot(new)
    rows = list(BranchPackage.objects.values())

    result = update_branch_snapshot(new)

    assert outcomes(result) == {"master": Outcome.ALREADY_CURRENT}
    assert BranchPackageChange.objects.count() == 1
    assert list(BranchPackage.objects.values()) == rows


def test_pointer_without_rows_initialises(
    branch: NixpkgsBranch,
    evaluation: NixEvaluation,
    make_attr: Callable[..., NixDerivation],
) -> None:
    """The data migration sets pointers before any snapshot exists."""
    make_attr(evaluation, "foo")
    branch.current_evaluation = evaluation
    branch.save()

    result = update_branch_snapshot(evaluation)

    assert outcomes(result) == {"master": Outcome.INITIALISED}
    assert BranchPackage.objects.count() == 1


def test_evaluation_on_two_branches(
    branch: NixpkgsBranch,
    make_branch: Callable[..., NixpkgsBranch],
    make_channel: Callable[..., NixChannel],
    make_evaluation: Callable[..., NixEvaluation],
    make_attr: Callable[..., NixDerivation],
) -> None:
    release = make_branch("release-26.05")
    release_channel = make_channel(
        channel_branch="nixos-26.05",
        release_branch=release,
        state=NixChannel.ChannelState.STABLE,
        variant=NixChannel.Variant.PRIMARY,
    )
    on_release = make_evaluation(channel=release_channel)
    make_attr(on_release, "foo")
    update_branch_snapshot(on_release)

    shared = make_evaluation()
    shared.on_branches.add(release)
    make_attr(shared, "foo", version="2.0")
    result = update_branch_snapshot(shared)

    assert outcomes(result) == {
        "master": Outcome.INITIALISED,
        "release-26.05": Outcome.ADVANCED,
    }
    assert BranchPackage.objects.filter(attrpath="foo").count() == 2
    assert list(
        BranchPackageChange.objects.values_list("branch", "attrpath", "kind")
    ) == [("release-26.05", "foo", Kind.VERSION_CHANGED)]
    for b in (branch, release):
        b.refresh_from_db()
        assert b.current_evaluation == shared


def test_shrinking_evaluation_is_refused(
    branch: NixpkgsBranch,
    make_evaluation: Callable[..., NixEvaluation],
    make_attr: Callable[..., NixDerivation],
) -> None:
    old = make_evaluation()
    for attribute in ["a", "b", "c"]:
        make_attr(old, attribute)
    update_branch_snapshot(old)
    broken = make_evaluation()
    make_attr(broken, "a")

    result = update_branch_snapshot(broken)

    assert outcomes(result) == {"master": Outcome.SKIPPED_SHRUNK}
    assert BranchPackage.objects.present().count() == 3
    assert not BranchPackageChange.objects.exists()
    branch.refresh_from_db()
    assert branch.current_evaluation == old


def test_package_group(
    branch: NixpkgsBranch,
    evaluation: NixEvaluation,
    make_attr: Callable[..., NixDerivation],
    make_package: Callable[..., Package],
) -> None:
    make_attr(evaluation, "foo")
    make_attr(evaluation, "bar")
    foo = Package.objects.create(name="foo")
    PackageAttrpath.objects.create(package=foo, attrpath="foo")

    update_branch_snapshot(evaluation)
    assert BranchPackage.objects.get(attrpath="foo").package == foo
    assert BranchPackage.objects.get(attrpath="bar").package is None

    # Clustering ran after the snapshot.
    bar = Package.objects.create(name="bar")
    PackageAttrpath.objects.create(package=bar, attrpath="bar")
    assert fill_package_groups([branch]) == 1
    assert BranchPackage.objects.get(attrpath="bar").package == bar


def test_notifies_after_commit(
    evaluation: NixEvaluation,
    make_attr: Callable[..., NixDerivation],
    django_capture_on_commit_callbacks: Any,
) -> None:
    make_attr(evaluation, "foo")

    with (
        mock.patch("shared.snapshot.pgpubsub.notify") as notify,
        django_capture_on_commit_callbacks(execute=True),
    ):
        update_branch_snapshot(evaluation)
        assert not notify.called
        update_branch_snapshot(evaluation)

    assert notify.call_count == 1
    assert notify.call_args.kwargs == {
        "evaluation_pk": evaluation.pk,
        "branch": "master",
    }
