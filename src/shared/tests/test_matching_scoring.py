from collections.abc import Callable

import pytest
from django.utils import timezone

from shared.matching.scoring import BASE_WEIGHTS, noisy_or, rank_attributes, weight_of
from shared.models.matching import Match


def test_noisy_or() -> None:
    assert noisy_or([]) == 0
    assert noisy_or([("nixpkgs-cpe", 1.0)]) == 1.0
    assert noisy_or([("name-substring", 1.0)]) == pytest.approx(0.2)
    # 1 - (1 - 0.8) * (1 - 0.7 * 0.5)
    assert noisy_or([("name-exact", 1.0), ("name-trigram", 0.5)]) == pytest.approx(0.87)


def test_weights() -> None:
    assert weight_of("repo-url") == BASE_WEIGHTS["repo-url"] == 0.9
    assert weight_of("manual") == 1.0


def test_rank_attributes(make_match: Callable[..., Match]) -> None:
    make_match("weak", "name-substring", 1.0)
    make_match("strong", "name-exact", 1.0)
    strong_trigram = make_match("strong", "name-trigram", 0.9)
    make_match("cpe", "nixpkgs-cpe", 1.0)
    make_match("gone", "nixpkgs-cpe", 1.0, retracted_at=timezone.now())

    ranked = rank_attributes(strong_trigram.suggestion)

    assert [r.attrpath for r in ranked] == ["cpe", "strong", "weak"]
    assert ranked[1].score == pytest.approx(1 - 0.2 * (1 - 0.7 * 0.9))
    assert [m.matcher for m in ranked[1].matches] == ["name-exact", "name-trigram"]
