"""
The new write path meeting suggestions as the legacy one left them (`make_legacy_suggestion`),
before `backfill_unified_model` reached them: every entry point, every status.
"""

from collections.abc import Callable
from io import StringIO
from typing import Any

import pytest
from django.contrib.auth.models import User
from django.core.management import call_command
from django.db import transaction

from shared.derived_state import derive_states
from shared.listeners.package_clustering import refresh_and_cache_suggestion
from shared.models.linkage import CVEDerivationClusterProposal
from shared.models.matching import SuggestionDerivedState, Verdict
from shared.models.nix_evaluation import NixDerivation, NixEvaluation
from shared.pipeline import on_cve_record_changed
from shared.snapshot import update_branch_snapshot
from shared.tests.conftest import run_snapshot_step

Status = CVEDerivationClusterProposal.Status
Reason = CVEDerivationClusterProposal.RejectionReason


def linked(suggestion: CVEDerivationClusterProposal) -> set[str]:
    return set(suggestion.derivations.values_list("attribute", flat=True))


def test_cve_update_before_backfill_keeps_accepted_attributes(
    make_legacy_suggestion: Callable[..., CVEDerivationClusterProposal],
    committer: User,
) -> None:
    """Review finding 1: the re-match ran before the backfill and dropped `foobar`."""
    suggestion = make_legacy_suggestion(status=Status.ACCEPTED)
    on_cve_record_changed(suggestion.cve.pk)
    assert linked(suggestion) == {"foo", "foobar"}
    call_command("backfill_unified_model", stdout=StringIO())
    assert linked(suggestion) == {"foo", "foobar"}
    assert set(Verdict.objects.values_list("attrpath", "verdict", "author")) == {
        ("foo", Verdict.Kind.AFFECTED, committer.pk),
        ("foobar", Verdict.Kind.AFFECTED, committer.pk),
    }


def _cve_update(s: CVEDerivationClusterProposal, **_: Any) -> None:
    on_cve_record_changed(s.cve.pk)


def _deploy_refresh(s: CVEDerivationClusterProposal, **_: Any) -> None:
    with transaction.atomic():
        refresh_and_cache_suggestion(pk=s.pk)


def _evaluation(
    s: CVEDerivationClusterProposal,
    make_evaluation: Callable[..., NixEvaluation],
    make_drv: Callable[..., NixDerivation],
) -> None:
    """A new evaluation (foo bumped, foobar rebuilt), the listener and its fan-out."""
    evaluation = make_evaluation()
    make_drv(attribute="foo", pname="foo", version="1.1", evaluation=evaluation)
    make_drv(attribute="foobar", pname="foobar", version="1.0", evaluation=evaluation)
    update_branch_snapshot(evaluation)
    run_snapshot_step(evaluation)


def _mapping(s: CVEDerivationClusterProposal, **_: Any) -> None:
    from shared.identity.keys import persist_product_keys
    from shared.identity.reconcile import reconcile_mapping_change
    from shared.models.cve import AffectedProduct
    from shared.models.matching import ProductKey, ProductMapping

    persist_product_keys(list(AffectedProduct.objects.all()))
    mapping = ProductMapping.objects.create(
        product_key=ProductKey.objects.get(kind="cna", vendor="", product="foo"),
        relation=ProductMapping.Relation.SAME,
        attrpath="foo",
        source=ProductMapping.Source.CURATED,
    )
    reconcile_mapping_change(mapping)


ENTRY_POINTS = {
    "cve_update": _cve_update,
    "deploy_refresh": _deploy_refresh,
    "evaluation": _evaluation,
    "mapping": _mapping,
}

SHAPES: dict[str, dict[str, Any]] = {
    "pending": {},
    "pending_ignored": {"ignored": ("foobar",)},
    "pending_commented": {"comment": "looked at it"},
    "accepted": {"status": Status.ACCEPTED},
    "accepted_ignored": {"status": Status.ACCEPTED, "ignored": ("foobar",)},
    "published": {"status": Status.PUBLISHED},
    "rejected_human": {"status": Status.REJECTED, "comment": "not ours"},
    "rejected_not_in_nixpkgs": {
        "status": Status.REJECTED,
        "rejection_reason": Reason.NOT_IN_NIXPKGS,
    },
    "rejected_known_vulnerability": {
        "status": Status.REJECTED,
        "rejection_reason": Reason.KNOWN_VULNERABILITY,
    },
    # The legacy matcher rejected it without links; the new one finds `foo`.
    "rejected_max_matches": {
        "status": Status.REJECTED,
        "rejection_reason": Reason.MAX_MATCHES_EXCEEDED,
        "linked": False,
    },
}


@pytest.mark.parametrize("entry", ENTRY_POINTS)
@pytest.mark.parametrize("shape", SHAPES)
def test_write_path_on_legacy_suggestion(
    shape: str,
    entry: str,
    make_legacy_suggestion: Callable[..., CVEDerivationClusterProposal],
    make_evaluation: Callable[..., NixEvaluation],
    make_drv: Callable[..., NixDerivation],
) -> None:
    fields = dict(SHAPES[shape])
    has_links = fields.pop("linked", True)
    suggestion = make_legacy_suggestion(**fields)
    if not has_links:
        suggestion.derivations.clear()
    status = suggestion.status
    ENTRY_POINTS[entry](suggestion, make_evaluation=make_evaluation, make_drv=make_drv)
    suggestion.refresh_from_db()

    # Never rejects (F4), never reopens a human decision. A machine rejection outside the
    # reopen window (no publication date here) is reopened when a CVE update or a dispatched
    # refresh re-matches it; evaluations and mappings select it only within the window.
    if shape == "rejected_max_matches" and entry in ("cve_update", "deploy_refresh"):
        assert suggestion.status == Status.PENDING
        assert "foo" in linked(suggestion)
        return
    assert suggestion.status == status
    attrs = linked(suggestion)
    if not has_links:
        assert attrs == set()
    elif status in (Status.ACCEPTED, Status.PUBLISHED, Status.REJECTED):
        # What a human decided on stays exactly.
        assert attrs == {"foo", "foobar"}
    else:
        # Nobody acted on `foobar` (substring only): it may go. `foo` and ignores stay.
        assert "foo" in attrs
        assert set(fields.get("ignored", ())) <= attrs
    ignored = set(fields.get("ignored", ()))
    packages = suggestion.cached.payload["packages"]
    assert not ignored & set(packages)
    assert ignored <= set(suggestion.cached.payload["original_packages"])
    # Acceptance is recorded once something processed the suggestion (published ones are
    # left alone by the refresh fan-out and mapping reconciliation: their links are frozen).
    touched = status == Status.ACCEPTED or entry == "cve_update"
    if status in (Status.ACCEPTED, Status.PUBLISHED) and touched:
        assert (
            set(
                Verdict.objects.filter(
                    suggestion=suggestion, verdict=Verdict.Kind.AFFECTED
                ).values_list("attrpath", flat=True)
            )
            == {"foo", "foobar"} - ignored
        )
    # Stored derived state consistent, or still stale (as every legacy row is after
    # migration 0124) where the entry point left a frozen suggestion alone.
    stored = SuggestionDerivedState.objects.get(suggestion=suggestion)
    assert stored.stale or (
        stored.state == derive_states([suggestion.pk])[suggestion.pk].state
    )
