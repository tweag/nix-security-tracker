"""A small git repository in a temporary directory, standing in for nixpkgs without the network."""

import os
import subprocess
from pathlib import Path

ENV = {
    "GIT_AUTHOR_NAME": "test",
    "GIT_AUTHOR_EMAIL": "test@example.org",
    "GIT_COMMITTER_NAME": "test",
    "GIT_COMMITTER_EMAIL": "test@example.org",
    "GIT_CONFIG_GLOBAL": os.devnull,
    "GIT_CONFIG_NOSYSTEM": "1",
}


class LocalRepo:
    def __init__(self, path: Path) -> None:
        self.path = path
        path.mkdir(parents=True, exist_ok=True)
        self.git("init", "-q", "--initial-branch=master")
        (path / "README").write_text("nixpkgs\n")
        self.git("add", "-A")
        self.git("commit", "-q", "-m", "init")

    @property
    def url(self) -> str:
        return f"file://{self.path}"

    def git(self, *args: str) -> str:
        return subprocess.run(
            ["git", "-C", str(self.path), *args],
            capture_output=True,
            text=True,
            check=True,
            env={**os.environ, **ENV},
        ).stdout.strip()

    def commit(
        self,
        branch: str,
        message: str,
        files: dict[str, str] | None = None,
        base: str | None = None,
    ) -> str:
        """Commit `files` on `branch` (created at `base`, or the current commit, if missing)."""
        exists = (
            branch
            in self.git("branch", "--list", "--format=%(refname:short)").splitlines()
        )
        if exists:
            self.git("checkout", "-q", branch)
        else:
            self.git("checkout", "-q", "-b", branch, *([base] if base else []))
        for name, content in (files or {}).items():
            target = self.path / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(content)
        self.git("add", "-A")
        self.git("commit", "-q", "--allow-empty", "-m", message)
        return self.git("rev-parse", "HEAD")

    def merge(self, branch: str, other: str, message: str = "merge") -> str:
        self.git("checkout", "-q", branch)
        self.git("merge", "-q", "--no-ff", "-m", message, other)
        return self.git("rev-parse", "HEAD")

    def set_branch(self, branch: str, commit: str) -> None:
        current = self.git("rev-parse", "--abbrev-ref", "HEAD")
        if current == branch:
            self.git("reset", "-q", "--hard", commit)
        else:
            self.git("branch", "-f", branch, commit)
