from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from io import StringIO
from pathlib import Path
from typing import Any

import pytest
from django.core.management import call_command

from shared.channel_history import (
    history_branches,
    poll_channel_heads,
    record_advance,
)
from shared.git import get_head_sha1s
from shared.models.nix_evaluation import NixChannel, NixpkgsBranch
from shared.models.remediation import ChannelAdvance
from shared.tests.local_repo import LocalRepo

T0 = datetime(2026, 11, 1, tzinfo=UTC)


@pytest.fixture
def repo(tmp_path: Path) -> LocalRepo:
    return LocalRepo(tmp_path / "nixpkgs")


def test_get_head_sha1s_reads_several_branches(repo: LocalRepo) -> None:
    head = repo.git("rev-parse", "HEAD")
    other = repo.commit("nixos-unstable", "channel")
    assert get_head_sha1s(repo.url, ["master", "nixos-unstable", "missing"]) == {
        "master": head,
        "nixos-unstable": other,
    }
    assert get_head_sha1s(repo.url, []) == {}


def test_record_advance_only_when_head_moves(channel: NixChannel) -> None:
    a, b = "a" * 40, "b" * 40
    assert record_advance(channel, a, T0) is not None
    assert record_advance(channel, a, T0 + timedelta(hours=1)) is None
    assert record_advance(channel, b, T0 + timedelta(hours=2)) is not None
    # An observation older than the last one does not rewrite history.
    assert record_advance(channel, a, T0 + timedelta(hours=1)) is None
    assert list(
        ChannelAdvance.objects.order_by("observed_at").values_list("commit", flat=True)
    ) == [a, b]


def test_poll_records_moved_heads_of_tracked_channels(
    repo: LocalRepo,
    make_channel: Callable[..., NixChannel],
    make_branch: Callable[..., NixpkgsBranch],
) -> None:
    master = make_branch("master")
    unstable = make_channel("nixos-unstable", release_branch=master)
    eol = make_channel(
        "nixos-25.05",
        release_branch=make_branch("release-25.05"),
        state=NixChannel.ChannelState.END_OF_LIFE,
    )
    first = repo.commit("nixos-unstable", "one")
    repo.commit("nixos-25.05", "old")

    assert [a.commit for a in poll_channel_heads(repo.url, now=T0)] == [first]
    unstable.refresh_from_db()
    assert unstable.head_sha1_commit == first
    assert not eol.advances.exists()

    assert poll_channel_heads(repo.url, now=T0 + timedelta(hours=1)) == []

    second = repo.commit("nixos-unstable", "two")
    [advance] = poll_channel_heads(repo.url, now=T0 + timedelta(hours=2))
    assert (advance.channel_id, advance.commit, advance.observed_at) == (
        "nixos-unstable",
        second,
        T0 + timedelta(hours=2),
    )


def test_poll_skips_missing_channel_branch(
    repo: LocalRepo, make_channel: Callable[..., NixChannel]
) -> None:
    make_channel("nixos-unstable")
    assert poll_channel_heads(repo.url, now=T0) == []


def test_track_channels_command(
    repo: LocalRepo,
    tmp_path: Path,
    settings: Any,
    make_channel: Callable[..., NixChannel],
    make_branch: Callable[..., NixpkgsBranch],
) -> None:
    make_channel("nixos-unstable", release_branch=make_branch("master"))
    head = repo.commit("nixos-unstable", "channel")
    settings.GIT_CLONE_URL = repo.url
    settings.NIXPKGS_HISTORY_CHECKOUT = tmp_path / "history.git"
    settings.NIXPKGS_HISTORY_FILTER = "tree:0"
    out = StringIO()

    call_command("track_channels", stdout=out)

    assert ChannelAdvance.objects.get().commit == head
    assert "0 landing(s) recorded" in out.getvalue()
    assert (tmp_path / "history.git" / "refs" / "heads" / "nixos-unstable").exists()
    assert history_branches() == ["master", "nixos-unstable"]


def test_track_channels_without_history_clone(
    repo: LocalRepo, settings: Any, make_channel: Callable[..., NixChannel]
) -> None:
    make_channel("nixos-unstable")
    repo.commit("nixos-unstable", "channel")
    settings.GIT_CLONE_URL = repo.url
    settings.NIXPKGS_HISTORY_CHECKOUT = None
    out = StringIO()
    call_command("track_channels", stdout=out)
    assert ChannelAdvance.objects.count() == 1
    assert "no landings computed" in out.getvalue()
