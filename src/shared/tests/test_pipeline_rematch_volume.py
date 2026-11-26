"""
Work after an evaluation is proportional to what changed for matching: `apply_evaluation`
re-matches only the suggestions a forward run could change.
"""

from collections.abc import Callable
from typing import Any
from unittest import mock

import pytest

from shared.identity.keys import persist_product_keys
from shared.identity.rules import sync_rule_file
from shared.models.cve import AffectedProduct, Container
from shared.models.linkage import CVEDerivationClusterProposal
from shared.models.matching import Match
from shared.models.nix_evaluation import NixDerivation, NixEvaluation, NixpkgsBranch
from shared.pipeline import EvaluationOutcome, apply_evaluation, build_new_links
from shared.snapshot import update_branch_snapshot

Packages = dict[str, tuple[str, str] | tuple[str, str, dict[str, Any]]]

KERNEL_RULES = """
[[rule]]
keys = [{ kind = "cna", vendor = "linux", product = "linux" }]
same_glob = ["linuxKernel.kernels.*"]
only = true
"""


@pytest.fixture
def evaluate(
    make_evaluation: Callable[..., NixEvaluation],
    make_drv: Callable[..., NixDerivation],
    branch: NixpkgsBranch,
) -> Callable[[Packages], EvaluationOutcome]:
    """Snapshot an evaluation of these packages and apply it, without running what it dispatches."""

    def wrapped(packages: Packages) -> EvaluationOutcome:
        evaluation = make_evaluation()
        for attribute, (pname, version, *rest) in packages.items():
            make_drv(
                attribute=attribute,
                pname=pname,
                version=version,
                evaluation=evaluation,
                **(rest[0] if rest else {}),
            )
        update_branch_snapshot(evaluation)
        with mock.patch("pgpubsub.notify"):
            return apply_evaluation(evaluation, branch)

    return wrapped


@pytest.fixture
def suggest(
    make_container: Callable[..., Container],
) -> Callable[..., CVEDerivationClusterProposal]:
    """A suggestion created by the live path, with persisted product keys."""

    def wrapped(cve_id: str, **fields: Any) -> CVEDerivationClusterProposal:
        container = make_container(cve_id=cve_id, package_name=None, product=None)
        AffectedProduct.objects.filter(pk=container.affected.get().pk).update(**fields)
        persist_product_keys(list(AffectedProduct.objects.all()))
        build_new_links(container)
        return CVEDerivationClusterProposal.objects.get(cve=container.cve)

    return wrapped


def test_unrelated_change_does_not_select_suggestions_of_a_rule(
    evaluate: Callable[[Packages], EvaluationOutcome],
    suggest: Callable[..., CVEDerivationClusterProposal],
) -> None:
    sync_rule_file(KERNEL_RULES)
    evaluate({"linuxKernel.kernels.linux_6_6": ("linux", "6.6.1")})
    kernel = suggest("CVE-2025-1001", vendor="Linux", product="Linux")
    assert Match.objects.active().filter(suggestion=kernel, matcher="rules").exists()

    outcome = evaluate(
        {
            "linuxKernel.kernels.linux_6_6": ("linux", "6.6.2"),
            "unrelated": ("unrelated", "1"),
        }
    )
    assert outcome.reverse_candidates == ["unrelated"]
    assert outcome.rematched == []

    # A new kernel does concern every kernel CVE.
    outcome = evaluate(
        {
            "linuxKernel.kernels.linux_6_6": ("linux", "6.6.2"),
            "linuxKernel.kernels.linux_6_12": ("linux", "6.12.1"),
            "unrelated": ("unrelated", "1"),
        }
    )
    assert outcome.rematched == [kernel.pk]
