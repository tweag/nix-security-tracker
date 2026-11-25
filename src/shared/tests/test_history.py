import subprocess
from pathlib import Path

import pytest

from shared.history import CachedAncestry, HistoryClone
from shared.tests.local_repo import LocalRepo


@pytest.fixture
def repo(tmp_path: Path) -> LocalRepo:
    return LocalRepo(tmp_path / "nixpkgs")


@pytest.mark.parametrize("filter", ["tree:0", "blob:none"])
def test_ancestry_in_partial_clone(
    repo: LocalRepo, tmp_path: Path, filter: str
) -> None:
    fix = repo.commit("master", "foo: 1.0 -> 1.1", {"pkgs/foo.nix": "1.1"})
    repo.commit("nixos-unstable", "channel", base=fix)
    later = repo.commit("master", "bar: init")
    clone = HistoryClone(tmp_path / "history.git", repo.url, filter)

    clone.fetch(["master", "nixos-unstable"])

    assert clone.contains("nixos-unstable", fix) is True
    assert clone.contains("nixos-unstable", later) is False
    assert clone.contains("master", later) is True
    assert clone.contains("nixos-unstable", "f" * 40) is None
    assert clone.resolve(fix[:12]) == fix
    assert (
        subprocess.run(
            [
                "git",
                "-C",
                str(clone.path),
                "config",
                "remote.origin.partialclonefilter",
            ],
            capture_output=True,
            text=True,
        ).stdout.strip()
        == filter
    )


def test_incremental_fetch_sees_new_commits(repo: LocalRepo, tmp_path: Path) -> None:
    clone = HistoryClone(tmp_path / "history.git", repo.url, "tree:0")
    clone.fetch(["master"])
    new = repo.commit("master", "next")
    assert clone.contains("master", new) is None
    clone.fetch(["master"])
    assert clone.contains("master", new) is True


def test_commits_mentioning(repo: LocalRepo, tmp_path: Path) -> None:
    old = repo.git("rev-parse", "HEAD")
    repo.commit("master", "bar: patch cve-2026-1234", {"pkgs/bar.nix": "x"})
    fix = repo.commit(
        "master", "foo: add patch for CVE-2026-1234", {"pkgs/foo.nix": "p"}
    )
    repo.commit("master", "foo: unrelated", {"pkgs/foo.nix": "q"})
    new = repo.git("rev-parse", "HEAD")

    with_trees = HistoryClone(tmp_path / "trees.git", repo.url, "blob:none")
    with_trees.fetch(["master"])
    assert with_trees.commits_mentioning(
        old, new, "CVE-2026-1234", ["pkgs/foo.nix"]
    ) == (
        [fix],
        True,
    )

    treeless = HistoryClone(tmp_path / "treeless.git", repo.url, "tree:0")
    treeless.fetch(["master"])
    commits, by_path = treeless.commits_mentioning(
        old, new, "CVE-2026-1234", ["pkgs/foo.nix"]
    ) or ([], True)
    # Offline, a commit-only clone cannot restrict by path: both mentions are found.
    assert not by_path
    assert len(commits) == 2 and commits[-1] == fix
    assert treeless.commits_mentioning(old, "f" * 40, "CVE-2026-1234") is None


def test_cached_ancestry_asks_once() -> None:
    calls = []

    class Inner:
        def contains(self, head: str, commit: str) -> bool | None:
            calls.append((head, commit))
            return True

    cached = CachedAncestry(Inner())
    assert cached.contains("h", "c") and cached.contains("h", "c")
    assert calls == [("h", "c")]
