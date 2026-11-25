import uuid
from collections.abc import Callable
from datetime import timedelta
from io import StringIO

import pytest
from django.core.management import call_command
from django.db import IntegrityError, transaction
from django.utils import timezone

from shared.models.linkage import CVEDerivationClusterProposal
from shared.models.matching import (
    Exposure,
    Match,
    ProductKey,
    ProductMapping,
    TrackerEvent,
    Verdict,
)
from shared.models.nix_evaluation import NixDerivation, NixEvaluation, NixpkgsBranch
from shared.models.snapshot import BranchPackage, BranchPackageChange


def assert_integrity_error(create: Callable[[], object]) -> None:
    with pytest.raises(IntegrityError), transaction.atomic():
        create()


def test_current_evaluation_is_cleared_when_evaluation_is_deleted(
    branch: NixpkgsBranch,
    make_evaluation: Callable[..., NixEvaluation],
) -> None:
    evaluation = make_evaluation()
    branch.current_evaluation = evaluation
    branch.save()

    evaluation.delete()

    branch.refresh_from_db()
    assert branch.current_evaluation is None


def test_branch_package_unique_per_branch(
    make_branch: Callable[..., NixpkgsBranch],
    make_branch_package: Callable[..., BranchPackage],
) -> None:
    make_branch_package()
    make_branch_package(branch=make_branch("release-26.05"))

    assert_integrity_error(lambda: make_branch_package())


def test_branch_package_present(
    make_branch_package: Callable[..., BranchPackage],
) -> None:
    present = make_branch_package(attrpath="foo")
    make_branch_package(attrpath="bar", present=False)

    assert list(BranchPackage.objects.present()) == [present]


def test_branch_package_change_minimal(
    branch: NixpkgsBranch,
    evaluation: NixEvaluation,
) -> None:
    change = BranchPackageChange.objects.create(
        branch=branch,
        attrpath="foo",
        kind=BranchPackageChange.Kind.ADDED,
        new_version="1.0",
        new_evaluation=evaluation,
    )
    assert str(change) == "master:foo added"


def test_product_key_unique_and_normalised(
    make_product_key: Callable[..., ProductKey],
) -> None:
    key = make_product_key(product=" OpenSSL ", vendor="OpenSSL")
    assert (key.vendor, key.product) == ("openssl", "openssl")
    assert make_product_key(product="openssl", vendor="openssl") == key

    assert_integrity_error(
        lambda: ProductKey.objects.create(
            kind=ProductKey.Kind.CPE, vendor="openssl", product="openssl"
        )
    )


def test_product_key_needs_product(db: None) -> None:
    assert_integrity_error(
        lambda: ProductKey.objects.create(kind=ProductKey.Kind.CNA, product="")
    )


def test_product_mapping_target(
    make_product_key: Callable[..., ProductKey],
) -> None:
    key = make_product_key()

    def mapping(
        relation: ProductMapping.Relation,
        attrpath: str | None = None,
        attr_glob: str | None = None,
    ) -> ProductMapping:
        return ProductMapping.objects.create(
            product_key=key,
            attrpath=attrpath,
            attr_glob=attr_glob,
            relation=relation,
            source=ProductMapping.Source.CURATED,
        )

    mapping(ProductMapping.Relation.SAME, attrpath="foo")
    mapping(ProductMapping.Relation.NOT_SAME, attr_glob="linuxPackages*.foo")
    mapping(ProductMapping.Relation.IRRELEVANT)

    # Both targets.
    assert_integrity_error(
        lambda: mapping(ProductMapping.Relation.SAME, attrpath="bar", attr_glob="bar*")
    )
    # No target, but claims to be the same as something.
    assert_integrity_error(lambda: mapping(ProductMapping.Relation.SAME))


def test_product_mapping_unique_with_nulls(
    make_product_key: Callable[..., ProductKey],
) -> None:
    key = make_product_key()

    def irrelevant(source: ProductMapping.Source) -> ProductMapping:
        return ProductMapping.objects.create(
            product_key=key,
            relation=ProductMapping.Relation.IRRELEVANT,
            source=source,
        )

    irrelevant(ProductMapping.Source.CURATED)
    irrelevant(ProductMapping.Source.TRIAGE)

    assert_integrity_error(lambda: irrelevant(ProductMapping.Source.CURATED))


def test_match_unique(make_match: Callable[..., Match]) -> None:
    make_match()
    make_match(matcher="other")
    make_match(attrpath="bar")

    assert_integrity_error(lambda: make_match())


@pytest.mark.parametrize("score", [-0.1, 1.1, float("nan")])
def test_match_score_range(make_match: Callable[..., Match], score: float) -> None:
    assert_integrity_error(lambda: make_match(score=score))


def test_match_active(make_match: Callable[..., Match]) -> None:
    active = make_match()
    make_match(attrpath="bar", retracted_at=timezone.now())

    assert list(Match.objects.active()) == [active]


def test_exposure_unique(
    make_branch: Callable[..., NixpkgsBranch],
    make_exposure: Callable[..., Exposure],
) -> None:
    make_exposure()
    make_exposure(branch=make_branch("release-26.05"))

    assert_integrity_error(lambda: make_exposure())


@pytest.mark.parametrize(
    "fix_commit,valid",
    [
        (None, True),
        ("a" * 40, True),
        ("abc123", False),
        ("A" * 40, False),
    ],
)
def test_fix_commit_is_a_full_sha1(
    make_exposure: Callable[..., Exposure],
    make_verdict: Callable[..., Verdict],
    fix_commit: str | None,
    valid: bool,
) -> None:
    for make in (make_exposure, make_verdict):
        if valid:
            make(fix_commit=fix_commit)
        else:
            assert_integrity_error(lambda: make(fix_commit=fix_commit))


def test_verdict_unique_with_all_branches(
    branch: NixpkgsBranch,
    make_verdict: Callable[..., Verdict],
) -> None:
    make_verdict(branch=None)
    make_verdict(branch=branch)

    assert_integrity_error(lambda: make_verdict(branch=None))
    assert_integrity_error(lambda: make_verdict(branch=branch))


def test_tracker_event_minimal(suggestion: CVEDerivationClusterProposal) -> None:
    event = TrackerEvent.objects.create(
        suggestion=suggestion,
        kind=TrackerEvent.Kind.MATCH_ADDED,
        attrpath="foo",
        cause=TrackerEvent.Cause.MATCHER,
        batch=uuid.uuid4(),
    )
    assert event.actor is None
    assert str(event) == "match_added foo (matcher)"


def test_garbage_collect_keeps_stale_suggestion_with_verdict(
    make_suggestion: Callable[..., CVEDerivationClusterProposal],
    make_verdict: Callable[..., Verdict],
) -> None:
    suggestion = make_suggestion(age=timedelta(days=400))
    make_verdict(suggestion=suggestion)

    call_command("garbage_collect", stdout=StringIO())

    assert CVEDerivationClusterProposal.objects.filter(pk=suggestion.pk).exists()


def test_garbage_collect_with_new_tables_referencing_evaluations(
    make_evaluation: Callable[..., NixEvaluation],
    make_drv: Callable[..., NixDerivation],
    make_suggestion: Callable[..., CVEDerivationClusterProposal],
    make_branch_package: Callable[..., BranchPackage],
    make_match: Callable[..., Match],
    make_exposure: Callable[..., Exposure],
) -> None:
    """
    The `PROTECT` foreign keys to evaluations do not get in the way: garbage
    collection deletes derivations of superseded evaluations, not the
    evaluations, and stale suggestions cascade to their facts.
    """
    old = make_evaluation(age=timedelta(days=2))
    make_drv(evaluation=old)
    new = make_evaluation()
    make_drv(evaluation=new)
    make_branch_package(evaluation=old)
    stale = make_suggestion(age=timedelta(days=400), drvs={})
    make_match(suggestion=stale)
    make_exposure(suggestion=stale, evaluation=old, first_affected_evaluation=old)

    call_command("garbage_collect", stdout=StringIO())

    assert NixEvaluation.objects.filter(pk=old.pk).exists()
    assert not NixDerivation.objects.filter(parent_evaluation=old).exists()
    assert BranchPackage.objects.count() == 1
    assert not CVEDerivationClusterProposal.objects.filter(pk=stale.pk).exists()
    assert not Match.objects.exists()
    assert not Exposure.objects.exists()
