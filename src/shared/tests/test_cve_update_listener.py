from collections.abc import Callable

from pgpubsub.models import Notification

from shared.cache_suggestions import cache_new_suggestions
from shared.channels import CvePresentationChannel
from shared.fetchers import make_cve, reconcile_cve
from shared.listeners.cve_updates import (
    recache_after_cve_update,
    rematch_after_cve_update,
)
from shared.models.linkage import CVEDerivationClusterProposal
from shared.models.nix_evaluation import NixDerivation, NixEvaluation
from shared.pipeline import build_new_links
from shared.snapshot import update_branch_snapshot
from shared.tests.test_cve_updates import cisa_adp, product, record

Status = CVEDerivationClusterProposal.Status


def test_update_of_cve_without_suggestion_creates_one(
    evaluation: NixEvaluation, make_drv: Callable[..., NixDerivation]
) -> None:
    make_drv(pname="foo")
    update_branch_snapshot(evaluation)
    cve = make_cve(record())  # the insert listener does not run in tests

    rematch_after_cve_update(pk=cve.pk)

    suggestion = CVEDerivationClusterProposal.objects.get()
    assert suggestion.status == Status.PENDING
    assert list(suggestion.derivations.values_list("attribute", flat=True)) == ["foo"]


def test_update_rematches_with_the_new_data(
    evaluation: NixEvaluation, make_drv: Callable[..., NixDerivation]
) -> None:
    make_drv(pname="bar", attribute="bar", cpe_vendor="acme", cpe_product="bar")
    update_branch_snapshot(evaluation)
    cve = make_cve(record(affected=[product(product="nothing-here")]))
    build_new_links(cve.container.get())
    suggestion = CVEDerivationClusterProposal.objects.get()
    assert suggestion.rejection_reason == "no_matches"

    cpe = "cpe:2.3:a:acme:bar:*:*:*:*:*:*:*:*"
    reconcile_cve(cve, record(adp=[cisa_adp(affected=[product(cpes=[cpe])])]))
    rematch_after_cve_update(pk=cve.pk)

    suggestion.refresh_from_db()
    assert suggestion.status == Status.PENDING
    assert list(suggestion.derivations.values_list("attribute", flat=True)) == ["bar"]


def test_presentation_update_recaches(
    evaluation: NixEvaluation, make_drv: Callable[..., NixDerivation]
) -> None:
    make_drv(pname="foo")
    update_branch_snapshot(evaluation)
    cve = make_cve(record())
    build_new_links(cve.container.get())
    suggestion = CVEDerivationClusterProposal.objects.get()
    cache_new_suggestions(suggestion)

    reconcile_cve(cve, record(title="Heap overflow in foo"))
    assert Notification.objects.filter(
        channel=CvePresentationChannel.listen_safe_name()
    ).exists()
    recache_after_cve_update(pk=cve.pk)

    suggestion.refresh_from_db()
    assert suggestion.cached.payload["title"] == "Heap overflow in foo"
