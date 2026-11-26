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


def test_version_only_change_rematches_nothing(
    evaluate: Callable[[Packages], EvaluationOutcome],
    suggest: Callable[..., CVEDerivationClusterProposal],
) -> None:
    old = {"position": "/tmp/x/pkgs/by-name/fo/foo/package.nix:1"}
    evaluate({"foo": ("foo", "1.0", old), "foo-cli": ("foo", "1.0")})
    suggestion = suggest("CVE-2025-1001", package_name="foo")
    assert Match.objects.active().filter(suggestion=suggestion).exists()

    # The version, and the file the package is defined in, change: nothing a matcher reads.
    new = {"position": "/tmp/x/pkgs/by-name/fo/foo/v2.nix:1"}
    outcome = evaluate({"foo": ("foo", "1.1", new), "foo-cli": ("foo", "1.1")})
    assert outcome.rematched == []
    assert outcome.reverse_candidates == []


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


def test_new_attribute_rematches_only_suggestions_not_already_matching_it(
    evaluate: Callable[[Packages], EvaluationOutcome],
    suggest: Callable[..., CVEDerivationClusterProposal],
) -> None:
    evaluate({"foo": ("foo", "1.0")})
    first = suggest("CVE-2025-1001", package_name="foo")
    second = suggest("CVE-2025-1002", package_name="foo")
    # `second` already has `foo-utils`, e.g. found on another branch.
    Match.objects.create(
        suggestion=second,
        attrpath="foo-utils",
        matcher="name-prefix",
        matcher_version=1,
        score=0.5,
    )

    outcome = evaluate({"foo": ("foo", "1.0"), "foo-utils": ("foo-utils", "1.0")})
    assert outcome.rematched == [first.pk]


def test_generic_terms_select_only_what_forward_matching_would_add(
    evaluate: Callable[[Packages], EvaluationOutcome],
    suggest: Callable[..., CVEDerivationClusterProposal],
) -> None:
    sync_rule_file(KERNEL_RULES)
    evaluate({"linuxKernel.kernels.linux_6_6": ("linux", "6.6.1")})
    suggest("CVE-2025-1001", vendor="Linux", product="Linux")
    # A one-letter product: no prefix or trigram matcher looks it up.
    suggest("CVE-2025-1002", product="R")

    outcome = evaluate(
        {
            "linuxKernel.kernels.linux_6_6": ("linux", "6.6.1"),
            # By name `Linux` is the prefix of these; the kernel rule vetoes them.
            "linux-firmware": ("linux-firmware", "1"),
            "linux-pam": ("linux-pam", "1"),
            "r-ggplot": ("r-ggplot", "1"),
        }
    )
    assert sorted(outcome.reverse_candidates) == [
        "linux-firmware",
        "linux-pam",
        "r-ggplot",
    ]
    assert outcome.rematched == []


def test_cpe_product_without_vendor_is_no_matching_change(
    evaluate: Callable[[Packages], EvaluationOutcome],
    suggest: Callable[..., CVEDerivationClusterProposal],
) -> None:
    evaluate({"foo": ("foo", "1.0", {"cpe_product": "foo"})})
    suggest("CVE-2025-1001", package_name="foo")
    # `nixpkgs-cpe` needs both parts: a product default without a vendor matches nothing.
    outcome = evaluate({"foo": ("foo", "1.0", {"cpe_product": "foo2"})})
    assert outcome.rematched == []
    outcome = evaluate(
        {"foo": ("foo", "1.0", {"cpe_vendor": "acme", "cpe_product": "foo2"})}
    )
    assert outcome.reverse_candidates == ["foo"]
