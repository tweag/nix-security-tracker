"""
Concurrent writers keep one lock order (`shared.locking`); review finding 3 was a deadlock of
the evaluation listener against a CVE update and against a human accepting.
"""

import threading
import time
from collections.abc import Callable
from typing import Any
from unittest import mock

import pytest
from django.db import connection, transaction

from shared.listeners.snapshot import apply_snapshot_changes
from shared.models.cve import Container
from shared.models.linkage import CVEDerivationClusterProposal
from shared.models.nix_evaluation import NixDerivation, NixEvaluation
from shared.pipeline import build_new_links, on_cve_record_changed
from shared.snapshot import update_branch_snapshot


@pytest.mark.django_db(transaction=True)
def test_evaluation_step_against_cve_update_and_acceptance(
    make_container: Callable[..., Container],
    make_evaluation: Callable[..., NixEvaluation],
    make_drv: Callable[..., NixDerivation],
) -> None:
    first = make_evaluation()
    make_drv(attribute="foo", pname="foo", version="1.0", evaluation=first)
    update_branch_snapshot(first)
    container = make_container(package_name="foo", product=None)
    assert build_new_links(container)
    suggestion = CVEDerivationClusterProposal.objects.get()

    # foo bumped and its homepage changed: an exposure change and a re-match candidate.
    second = make_evaluation()
    make_drv(
        attribute="foo",
        pname="foo",
        version="1.1",
        evaluation=second,
        homepage="https://other.example",
    )
    update_branch_snapshot(second)

    import shared.pipeline

    real = shared.pipeline.apply_branch_changes
    exposures_locked = threading.Event()

    def pausing(*args: Any, **kwargs: Any) -> Any:
        result = real(*args, **kwargs)
        # The exposure locks are held now; the other writers start meanwhile.
        exposures_locked.set()
        time.sleep(1.5)
        return result

    errors: list[BaseException] = []

    def run(target: Callable[[], None], wait: bool) -> Callable[[], None]:
        def wrapped() -> None:
            try:
                if wait:
                    assert exposures_locked.wait(timeout=30)
                with transaction.atomic():  # as pgpubsub runs every listener
                    target()
            except BaseException as e:  # noqa: BLE001
                errors.append(e)
            finally:
                connection.close()

        return wrapped

    def evaluation_step() -> None:
        with (
            mock.patch("shared.pipeline.apply_branch_changes", new=pausing),
            mock.patch("pgpubsub.notify"),
        ):
            apply_snapshot_changes(evaluation_pk=second.pk, branch="master")

    def cve_update() -> None:
        on_cve_record_changed(container.cve.pk)

    def accept() -> None:
        CVEDerivationClusterProposal.objects.get(pk=suggestion.pk).change_status(
            CVEDerivationClusterProposal.Status.ACCEPTED
        )

    threads = [
        threading.Thread(target=run(evaluation_step, wait=False)),
        threading.Thread(target=run(cve_update, wait=True)),
        threading.Thread(target=run(accept, wait=True)),
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=60)
    assert not errors, [repr(e) for e in errors]
    suggestion.refresh_from_db()
    assert suggestion.status == CVEDerivationClusterProposal.Status.ACCEPTED
