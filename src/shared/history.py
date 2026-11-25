"""
A history-only clone of nixpkgs for ancestry questions (option A of section 3.4 of the matching
design): "does channel head C contain commit X" and "which commits between two evaluations
mention a CVE". The evaluation checkout is depth 1 and cannot answer either.

The clone is bare and partial: `--filter=tree:0` keeps only commits (about 640 MB for master,
two release branches and their channels, measured 2026-11-25), `--filter=blob:none` also keeps
trees (about 1.9 GB for master and one release branch), which path-limited log needs. Only
`fetch` talks to the network; every other command runs with lazy fetching disabled, so a
missing object is an answer ("unknown"), never a download.
"""

import logging
import os
import subprocess
import time
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from django.conf import settings

logger = logging.getLogger(__name__)

OFFLINE = {"GIT_NO_LAZY_FETCH": "1", "GIT_TERMINAL_PROMPT": "0"}


class Ancestry(Protocol):
    """Containment of commits in heads. `None` means the answer is not known (commit unknown)."""

    def contains(self, head: str, commit: str) -> bool | None: ...


@dataclass
class HistoryClone:
    path: Path
    url: str
    filter: str = "blob:none"

    @classmethod
    def from_settings(cls) -> "HistoryClone | None":
        path = settings.NIXPKGS_HISTORY_CHECKOUT
        if path is None:
            return None
        return cls(
            Path(path), str(settings.GIT_CLONE_URL), settings.NIXPKGS_HISTORY_FILTER
        )

    def _git(
        self, *args: str, check: bool = True, offline: bool = True
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["git", "-C", str(self.path), *args],
            capture_output=True,
            text=True,
            check=check,
            env={**os.environ, **(OFFLINE if offline else {})},
        )

    def ensure(self) -> None:
        """Create the bare partial clone's configuration if it does not exist yet."""
        if (self.path / "HEAD").exists():
            return
        self.path.mkdir(parents=True, exist_ok=True)
        self._git("init", "-q", "--bare")
        for key, value in [
            ("remote.origin.url", self.url),
            ("remote.origin.promisor", "true"),
            ("remote.origin.partialclonefilter", self.filter),
            ("fetch.writeCommitGraph", "true"),
            ("gc.auto", "0"),
        ]:
            self._git("config", key, value)

    def fetch(self, branches: Iterable[str]) -> float:
        """Fetch the history of `branches` into refs of the same name. Returns seconds taken."""
        self.ensure()
        refspecs = [f"+refs/heads/{b}:refs/heads/{b}" for b in sorted(set(branches))]
        if not refspecs:
            return 0.0
        start = time.monotonic()
        self._git(
            "fetch",
            "--quiet",
            "--no-tags",
            f"--filter={self.filter}",
            "origin",
            *refspecs,
            offline=False,
        )
        elapsed = time.monotonic() - start
        logger.info(
            "Fetched %d refs into %s in %.1fs", len(refspecs), self.path, elapsed
        )
        return elapsed

    def has_commit(self, sha: str) -> bool:
        return (
            self._git("cat-file", "-e", f"{sha}^{{commit}}", check=False).returncode
            == 0
        )

    def resolve(self, rev: str) -> str | None:
        """Full hash of a commit given by (abbreviated) hash or ref, if the clone has it."""
        result = self._git(
            "rev-parse", "--verify", "-q", f"{rev}^{{commit}}", check=False
        )
        return result.stdout.strip() or None

    def contains(self, head: str, commit: str) -> bool | None:
        if not (self.has_commit(head) and self.has_commit(commit)):
            return None
        rc = self._git("merge-base", "--is-ancestor", commit, head, check=False)
        match rc.returncode:
            case 0:
                return True
            case 1:
                return False
            case _:
                logger.warning("merge-base %s %s: %s", commit, head, rc.stderr.strip())
                return None

    def commits_mentioning(
        self, old: str, new: str, needle: str, paths: Iterable[str] = ()
    ) -> tuple[list[str], bool] | None:
        """
        Commits in `old..new` whose message contains `needle` (case-insensitive), restricted to
        commits touching `paths` when the clone has trees. Returns the commits, oldest first,
        and whether the path restriction was applied; `None` if either end is unknown.
        """
        if not (self.has_commit(old) and self.has_commit(new)):
            return None
        args = [
            "log",
            "--format=%H",
            "--reverse",
            "-i",
            "--fixed-strings",
            f"--grep={needle}",
            f"{old}..{new}",
        ]
        paths = list(paths)
        if paths:
            result = self._git(*args, "--", *paths, check=False)
            if result.returncode == 0:
                return result.stdout.split(), True
            # A treeless clone cannot filter by path offline; fall back to the message.
            logger.debug("path-limited log failed: %s", result.stderr.strip())
        result = self._git(*args, check=False)
        if result.returncode != 0:
            logger.warning("git log %s..%s: %s", old, new, result.stderr.strip())
            return None
        return result.stdout.split(), False


class CachedAncestry:
    """Memoise answers within one run; containment does not change for fixed commits."""

    def __init__(self, inner: Ancestry) -> None:
        self.inner = inner
        self.answers: dict[tuple[str, str], bool | None] = {}
        self.queries = 0

    def contains(self, head: str, commit: str) -> bool | None:
        key = (head, commit)
        if key not in self.answers:
            self.queries += 1
            self.answers[key] = self.inner.contains(head, commit)
        return self.answers[key]
