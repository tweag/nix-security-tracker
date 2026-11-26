"""The live write path over the unified model (`shared.pipeline`, `shared.projection`)."""

import threading
import time
from collections.abc import Callable, Iterator
from typing import Any
from unittest import mock

import pytest
from django.db import connection, transaction
from django.test import override_settings

from shared.cache_suggestions import cache_new_suggestions
from shared.derived_state import DerivedState, derive_states
from shared.exposure import reconcile_exposures
from shared.identity.keys import persist_product_keys
from shared.listeners.snapshot import snapshot_after_evaluation
from shared.matching import matchers as matchers_module
from shared.models.cached import CachedSuggestions
from shared.models.cve import AffectedProduct, Container, Cpe, Tag, Version
from shared.models.linkage import (
    CVEDerivationClusterProposal,
    DerivationClusterProposalLink,
    ProvenanceFlags,
)
from shared.models.matching import Exposure, Match, TrackerEvent
from shared.models.nix_evaluation import NixDerivation, NixEvaluation
from shared.pipeline import (
    build_new_links,
    on_cve_record_changed,
    refresh_suggestion,
)
from shared.projection import project_links
from shared.snapshot import update_branch_snapshot
from shared.tests.conftest import run_snapshot_step

Status = CVEDerivationClusterProposal.Status
Reason = CVEDerivationClusterProposal.RejectionReason


@pytest.fixture
def snapshot(
    make_evaluation: Callable[..., NixEvaluation],
    make_drv: Callable[..., NixDerivation],
) -> Callable[..., NixEvaluation]:
    """A completed evaluation with derivations `{attribute: (pname, version, extra)}`, snapshotted."""

    def wrapped(
        packages: dict[str, tuple[str, str] | tuple[str, str, dict[str, Any]]],
        apply: bool = True,
    ) -> NixEvaluation:
        evaluation = make_evaluation()
        for attribute, spec in packages.items():
            pname, version, *rest = spec
            make_drv(
                attribute=attribute,
                pname=pname,
                version=version,
                evaluation=evaluation,
                **(rest[0] if rest else {}),
            )
        update_branch_snapshot(evaluation)
        if apply:
            run_snapshot_step(evaluation)
        return evaluation

    return wrapped


def linked(suggestion: CVEDerivationClusterProposal) -> dict[str, list[str]]:
    """Linked derivation names by attribute."""
    result: dict[str, list[str]] = {}
    for attr, name in suggestion.derivations.values_list("attribute", "name"):
        result.setdefault(attr, []).append(name)
    return {k: sorted(v) for k, v in sorted(result.items())}


def link_flags(suggestion: CVEDerivationClusterProposal, attr: str) -> int:
    return DerivationClusterProposalLink.objects.filter(
        proposal=suggestion, derivation__attribute=attr
    ).values_list("provenance_flags", flat=True)[0]


def add_container(
    container: Container,
    kind: str = Container.Type.ADP,
    package_name: str | None = None,
    product: str | None = None,
    cpes: list[str] = [],
) -> Container:
    """Another container of the same CVE record."""
    extra = container.cve.container.create(provider=container.provider, _type=kind)
    affected = AffectedProduct.objects.create(
        package_name=package_name, product=product
    )
    for name in cpes:
        cpe, _ = Cpe.objects.get_or_create(name=name)
        affected.cpes.add(cpe)
    extra.affected.add(affected)
    return extra


# --- New CVE --------------------------------------------------------------------------------


def test_new_cve_pending_with_matches_exposures_and_links(
    make_container: Callable[..., Container],
    snapshot: Callable[..., NixEvaluation],
) -> None:
    evaluation = snapshot({"foo": ("foo", "1.0"), "bar": ("other", "1.0")})
    assert build_new_links(make_container(package_name="foo", product=None))

    suggestion = CVEDerivationClusterProposal.objects.get()
    assert suggestion.status == Status.PENDING
    assert (
        suggestion.algorithm_version
        == CVEDerivationClusterProposal.CURRENT_ALGORITHM_VERSION
    )
    assert "name-exact" in suggestion.matcher_versions
    assert linked(suggestion) == {"foo": ["foo-1.0"]}
    assert link_flags(suggestion, "foo") == ProvenanceFlags.PACKAGE_NAME_MATCH
    assert set(Match.objects.active().values_list("attrpath", flat=True)) == {"foo"}
    exposure = Exposure.objects.get(suggestion=suggestion)
    assert (exposure.attrpath, exposure.observed, exposure.evaluation) == (
        "foo",
        Exposure.Observed.AFFECTED,
        evaluation,
    )


def test_substring_only_is_not_shown(
    make_container: Callable[..., Container],
    snapshot: Callable[..., NixEvaluation],
) -> None:
    """Below the default threshold: recorded as a match, rejected `no_matches`."""
    snapshot({"teslajsonpy": ("teslajsonpy", "1.0")})
    assert build_new_links(make_container(package_name="tesla", product=None))

    suggestion = CVEDerivationClusterProposal.objects.get()
    assert suggestion.status == Status.REJECTED
    assert suggestion.rejection_reason == Reason.NO_MATCHES
    assert Match.objects.active().get().matcher == "name-substring"
    assert not suggestion.derivations.exists()


def test_settings_tune_what_is_shown(
    make_container: Callable[..., Container],
    snapshot: Callable[..., NixEvaluation],
    settings: Any,
) -> None:
    snapshot({"teslajsonpy": ("teslajsonpy", "1.0")})
    settings.MATCHING_SCORE_THRESHOLD = 0.0
    assert build_new_links(make_container(package_name="tesla", product=None))
    assert linked(CVEDerivationClusterProposal.objects.get()) == {
        "teslajsonpy": ["teslajsonpy-1.0"]
    }


def test_cap_shows_best_attributes_instead_of_rejecting(
    make_container: Callable[..., Container],
    snapshot: Callable[..., NixEvaluation],
    settings: Any,
) -> None:
    """No `max_matches_exceeded` any more: the best-scored attributes are shown (#1436)."""
    snapshot({"foo": ("foo", "1.0"), "foo-utils": ("foo-utils", "1.0")})
    settings.MATCHING_MAX_ATTRIBUTES = 1
    assert build_new_links(make_container(package_name="foo", product=None))

    suggestion = CVEDerivationClusterProposal.objects.get()
    assert suggestion.status == Status.PENDING
    assert list(linked(suggestion)) == ["foo"]
    assert Match.objects.active().filter(attrpath="foo-utils").exists()


def test_disabled_matcher_does_not_count(
    make_container: Callable[..., Container],
    snapshot: Callable[..., NixEvaluation],
    settings: Any,
) -> None:
    snapshot({"foo": ("foo", "1.0")})
    settings.MATCHING_MATCHERS = ["name-substring"]
    settings.MATCHING_SCORE_THRESHOLD = 0.0
    assert build_new_links(make_container(package_name="foo", product=None))
    assert set(Match.objects.values_list("matcher", flat=True)) == {"name-substring"}


def test_exclusively_hosted_service_screen(
    make_container: Callable[..., Container],
    snapshot: Callable[..., NixEvaluation],
) -> None:
    snapshot({"foo": ("foo", "1.0")})
    container = make_container()
    tag, _ = Tag.objects.get_or_create(value="exclusively-hosted-service")
    container.tags.add(tag)

    assert build_new_links(container)
    suggestion = CVEDerivationClusterProposal.objects.get()
    assert (suggestion.status, suggestion.rejection_reason) == (
        Status.REJECTED,
        Reason.EXCLUSIVELY_HOSTED_SERVICE,
    )
    assert not suggestion.derivations.exists()
    assert not Match.objects.exists()


def test_hardware_only_screen(
    make_container: Callable[..., Container],
    snapshot: Callable[..., NixEvaluation],
) -> None:
    snapshot({"some_router": ("some_router", "1.0")})
    container = make_container(
        package_name="some_router",
        product="some_router",
        cpes=["cpe:2.3:h:cisco:some_router:1.0:*:*:*:*:*:*:*"],
    )
    assert build_new_links(container)
    suggestion = CVEDerivationClusterProposal.objects.get()
    assert suggestion.rejection_reason == Reason.HARDWARE_ONLY_CPE
    assert not suggestion.derivations.exists()


def test_known_vulnerability_keeps_only_acknowledging_attributes(
    make_container: Callable[..., Container],
    snapshot: Callable[..., NixEvaluation],
) -> None:
    """As before: rejected `known_vulnerability`, linked to the attributes listing the CVE."""
    snapshot(
        {
            "foo": ("foo", "1.0"),
            "foo-cli": (
                "foo-cli",
                "1.0",
                {"known_vulnerabilities": ["CVE-2025-0001"]},
            ),
        }
    )
    assert build_new_links(make_container(package_name="foo", product=None))
    suggestion = CVEDerivationClusterProposal.objects.get()
    assert (suggestion.status, suggestion.rejection_reason) == (
        Status.REJECTED,
        Reason.KNOWN_VULNERABILITY,
    )
    assert list(linked(suggestion)) == ["foo-cli"]


def test_tests_attributes_are_not_linked(
    make_container: Callable[..., Container],
    snapshot: Callable[..., NixEvaluation],
) -> None:
    snapshot({"foo": ("foo", "1.0"), "tests.foo": ("foo", "1.0")})
    assert build_new_links(make_container(package_name="foo", product=None))
    assert list(linked(CVEDerivationClusterProposal.objects.get())) == ["foo"]


def test_cpe_only_in_adp_container_is_matched(
    make_container: Callable[..., Container],
    snapshot: Callable[..., NixEvaluation],
) -> None:
    """The second container re-matches over all containers and reopens `no_matches` (F1)."""
    snapshot(
        {"hello": ("hello-nix", "2.12", {"cpe_vendor": "gnu", "cpe_product": "hello"})}
    )
    cna = make_container(package_name="unrelated", product="unrelated")
    assert build_new_links(cna)
    suggestion = CVEDerivationClusterProposal.objects.get()
    assert suggestion.rejection_reason == Reason.NO_MATCHES

    adp = add_container(cna, cpes=["cpe:2.3:a:gnu:hello:2.12:*:*:*:*:*:*:*"])
    assert not build_new_links(adp)

    suggestion.refresh_from_db()
    assert CVEDerivationClusterProposal.objects.count() == 1
    assert suggestion.status == Status.PENDING
    assert suggestion.rejection_reason is None
    assert list(linked(suggestion)) == ["hello"]
    assert link_flags(suggestion, "hello") == ProvenanceFlags.CPE_MATCH
    match = Match.objects.active().get(matcher="nixpkgs-cpe")
    assert match.evidence["container"] == "adp"
    assert TrackerEvent.objects.filter(
        kind=TrackerEvent.Kind.MATCH_ADDED, cause=TrackerEvent.Cause.CVE_UPDATE
    ).exists()
    # Reopening is attributed to the tracker in the activity log.
    assert suggestion.cached.payload["packages"].keys() == {"hello"}


def test_cve_record_changed_without_suggestion_creates_one(
    make_container: Callable[..., Container],
    snapshot: Callable[..., NixEvaluation],
) -> None:
    snapshot({"foo": ("foo", "1.0")})
    container = make_container(package_name="foo", product=None)
    assert on_cve_record_changed(container.cve.pk)
    assert not on_cve_record_changed(container.cve.pk)
    assert CVEDerivationClusterProposal.objects.get().status == Status.PENDING


@pytest.mark.django_db(transaction=True)
def test_concurrent_containers_create_one_suggestion(
    make_container: Callable[..., Container],
    snapshot: Callable[..., NixEvaluation],
) -> None:
    snapshot({"foo": ("foo", "1.0")})
    cna = make_container(package_name="foo", product=None)
    adp = add_container(cna, package_name="foo")
    real = matchers_module.collect_candidates
    barrier = threading.Barrier(2)

    def slow(*args: Any, **kwargs: Any) -> Any:
        time.sleep(0.5)
        return real(*args, **kwargs)

    created: list[bool] = []
    errors: list[BaseException] = []

    def run(container: Container) -> None:
        try:
            barrier.wait()
            created.append(build_new_links(container))
        except BaseException as e:  # noqa: BLE001
            errors.append(e)
        finally:
            connection.close()

    with mock.patch("shared.pipeline.collect_candidates", new=slow):
        threads = [threading.Thread(target=run, args=(c,)) for c in (cna, adp)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

    assert not errors
    assert sorted(created) == [False, True]
    assert CVEDerivationClusterProposal.objects.count() == 1


# --- Re-matching ----------------------------------------------------------------------------


@pytest.fixture
def pending(
    make_container: Callable[..., Container],
    snapshot: Callable[..., NixEvaluation],
) -> CVEDerivationClusterProposal:
    """A pending suggestion for `foo`, with `foo` and `foo-cli` exactly matched."""
    snapshot({"foo": ("foo", "1.0"), "foo-cli": ("foo", "1.0"), "x": ("x", "1")})
    assert build_new_links(make_container(package_name="foo", product=None))
    suggestion = CVEDerivationClusterProposal.objects.get()
    cache_new_suggestions(suggestion)
    assert list(linked(suggestion)) == ["foo", "foo-cli"]
    return suggestion


def test_projection_is_a_noop_when_nothing_changed(
    pending: CVEDerivationClusterProposal,
) -> None:
    before = list(DerivationClusterProposalLink.objects.values_list("pk", flat=True))
    result = project_links(pending)
    assert not result.changed
    assert (
        list(DerivationClusterProposalLink.objects.values_list("pk", flat=True))
        == before
    )


def test_rematch_finding_nothing_keeps_pending_and_flags(
    pending: CVEDerivationClusterProposal,
    settings: Any,
) -> None:
    """F4: a re-match that finds nothing neither rejects nor empties the suggestion."""
    settings.MATCHING_MATCHERS = ["nixpkgs-cpe"]
    Match.objects.update(retracted_at="2026-01-01T00:00:00Z")
    refresh_suggestion(pending, matchers=["nixpkgs-cpe"])

    pending.refresh_from_db()
    assert pending.status == Status.PENDING
    assert list(linked(pending)) == ["foo", "foo-cli"]
    assert link_flags(pending, "foo") & ProvenanceFlags.NO_LONGER_MATCHED


def test_rematch_drops_unmatched_attribute_of_untouched_pending(
    pending: CVEDerivationClusterProposal,
) -> None:
    Match.objects.filter(attrpath="foo-cli").update(retracted_at="2026-01-01T00:00:00Z")
    result = project_links(pending)
    assert result.removed_attributes == {"foo-cli"}
    assert list(linked(pending)) == ["foo"]


def test_accepted_keeps_attribute_no_matcher_finds(
    pending: CVEDerivationClusterProposal,
) -> None:
    pending.change_status(Status.ACCEPTED)
    Match.objects.filter(attrpath="foo-cli").update(retracted_at="2026-01-01T00:00:00Z")
    result = project_links(pending)
    assert result.removed_attributes == set()
    assert list(linked(pending)) == ["foo", "foo-cli"]
    assert link_flags(pending, "foo-cli") & ProvenanceFlags.NO_LONGER_MATCHED
    assert not link_flags(pending, "foo") & ProvenanceFlags.NO_LONGER_MATCHED


def test_ignored_attribute_survives_rematch_and_is_restorable(
    pending: CVEDerivationClusterProposal,
) -> None:
    pending.ignore_packages(["foo-cli"])
    Match.objects.filter(attrpath="foo-cli").update(retracted_at="2026-01-01T00:00:00Z")
    refresh_suggestion(pending, matchers=[])
    pending.refresh_from_db()
    assert list(linked(pending)) == ["foo", "foo-cli"]
    assert "foo-cli" in pending.cached.payload["original_packages"]
    assert "foo-cli" not in pending.cached.payload["packages"]

    pending.restore_packages(["foo-cli"])
    pending.refresh_from_db()
    assert "foo-cli" in pending.cached.payload["packages"]


def test_attribute_missing_from_one_evaluation(
    pending: CVEDerivationClusterProposal,
    snapshot: Callable[..., NixEvaluation],
) -> None:
    """An attribute that fails to evaluate once stays shown with its last derivation."""
    snapshot({"foo": ("foo", "1.1"), "x": ("x", "1")})
    assert linked(pending) == {"foo": ["foo-1.1"], "foo-cli": ["foo-1.0"]}
    assert Match.objects.active().filter(attrpath="foo-cli").exists()
    absent = Exposure.objects.get(suggestion=pending, attrpath="foo-cli")
    assert absent.observed == Exposure.Observed.ABSENT

    snapshot({"foo": ("foo", "1.1"), "foo-cli": ("foo", "1.1"), "x": ("x", "1")})
    assert linked(pending) == {"foo": ["foo-1.1"], "foo-cli": ["foo-1.1"]}


def test_rematch_while_attribute_is_missing_keeps_its_match(
    pending: CVEDerivationClusterProposal,
    snapshot: Callable[..., NixEvaluation],
) -> None:
    """A CVE update re-matches while `foo-cli` failed to evaluate once: its match stays."""
    snapshot({"foo": ("foo", "1.1"), "x": ("x", "1")})
    refresh_suggestion(pending, TrackerEvent.Cause.CVE_UPDATE, matchers=None)
    on_cve_record_changed(pending.cve.pk)
    assert Match.objects.active().filter(attrpath="foo-cli").exists()
    assert list(linked(pending)) == ["foo", "foo-cli"]


def test_attribute_gone_from_every_branch_is_retracted(
    pending: CVEDerivationClusterProposal,
    snapshot: Callable[..., NixEvaluation],
) -> None:
    for _ in range(3):
        snapshot({"foo": ("foo", "1.0"), "x": ("x", "1")})
    assert not Match.objects.active().filter(attrpath="foo-cli").exists()
    assert list(linked(pending)) == ["foo"]
    pending.refresh_from_db()
    assert pending.status == Status.PENDING


def test_stale_exposure_of_a_frozen_suggestion_does_not_block_retraction(
    pending: CVEDerivationClusterProposal,
    make_container: Callable[..., Container],
    snapshot: Callable[..., NixEvaluation],
) -> None:
    """
    `foo-cli` disappears. Another suggestion's exposure of it stays `absent` without reason
    `removed` forever, because that suggestion was dismissed and is no longer kept current;
    the pending suggestion's match on `foo-cli` must still be retracted.
    """
    assert build_new_links(make_container(cve_id="CVE-2025-0002", package_name="foo"))
    dismissed = CVEDerivationClusterProposal.objects.get(cve__cve_id="CVE-2025-0002")
    snapshot({"foo": ("foo", "1.0"), "x": ("x", "1")})
    stale = Exposure.objects.get(suggestion=dismissed, attrpath="foo-cli")
    assert stale.observed == Exposure.Observed.ABSENT
    dismissed.change_status(Status.REJECTED, rejection_reason=Reason.NOT_IN_NIXPKGS)
    for _ in range(3):
        snapshot({"foo": ("foo", "1.0"), "x": ("x", "1")})

    stale.refresh_from_db()
    assert stale.reason != Exposure.Reason.REMOVED  # frozen: never updated again
    assert (
        not Match.objects.active()
        .filter(suggestion=pending, attrpath="foo-cli")
        .exists()
    )
    assert list(linked(pending)) == ["foo"]


def test_new_attribute_is_reverse_matched(
    pending: CVEDerivationClusterProposal,
    snapshot: Callable[..., NixEvaluation],
) -> None:
    """An attribute added by an evaluation joins the open suggestion whose CVE names it."""
    persist_product_keys(list(AffectedProduct.objects.all()))
    snapshot(
        {
            "foo": ("foo", "1.0"),
            "foo-cli": ("foo", "1.0"),
            "x": ("x", "1"),
            "python3Packages.foo": ("python3.13-foo", "1.0"),
            "unrelated": ("unrelated", "1"),
        }
    )
    assert list(linked(pending)) == ["foo", "foo-cli", "python3Packages.foo"]
    causes = set(
        TrackerEvent.objects.filter(
            kind=TrackerEvent.Kind.MATCH_ADDED, attrpath="python3Packages.foo"
        ).values_list("cause", flat=True)
    )
    assert causes == {TrackerEvent.Cause.EVALUATION}


def test_reverse_selection_gets_every_added_or_changed_attribute(
    pending: CVEDerivationClusterProposal,
    snapshot: Callable[..., NixEvaluation],
) -> None:
    with mock.patch(
        "shared.pipeline.reverse_match_attributes", return_value={}
    ) as reverse:
        snapshot(
            {
                "foo": ("foo", "1.0", {"cpe_vendor": "foo", "cpe_product": "foo"}),
                "foo-cli": ("foo", "1.0"),
                "x": ("x", "2"),
                "new": ("new", "1"),
            }
        )
    (attrpaths, *_), _ = reverse.call_args
    # `foo` changed CPE metadata (already matched), `new` was added; a version bump is not a change.
    assert attrpaths == ["foo", "new"]


@override_settings(MATCHING_MAX_ATTRIBUTES=50)
def test_legacy_suggestion_moves_to_real_matchers(
    make_container: Callable[..., Container],
    snapshot: Callable[..., NixEvaluation],
    make_suggestion: Callable[..., CVEDerivationClusterProposal],
    make_match: Callable[..., Match],
) -> None:
    """Backfilled `legacy-v2` matches are retracted once every enabled matcher ran."""
    evaluation = snapshot({"foo": ("foo", "1.0"), "foobar": ("foobar", "1.0")})
    drvs = {
        d.attribute: d
        for d in NixDerivation.objects.filter(parent_evaluation=evaluation)
    }
    container = make_container(package_name="foo", product=None)
    suggestion = make_suggestion(
        container=container,
        drvs={d: ProvenanceFlags.PACKAGE_NAME_MATCH for d in drvs.values()},
        algorithm_version=2,
    )
    for attr in drvs:
        make_match(
            attrpath=attr,
            matcher="legacy-v2",
            suggestion=suggestion,
            evidence={"provenance_flags": 1},
        )

    refresh_suggestion(suggestion)

    suggestion.refresh_from_db()
    assert (
        suggestion.algorithm_version
        == CVEDerivationClusterProposal.CURRENT_ALGORITHM_VERSION
    )
    assert not Match.objects.active().filter(matcher="legacy-v2").exists()
    # `foobar` was a substring-only legacy find.
    assert list(linked(suggestion)) == ["foo"]


# --- End to end -----------------------------------------------------------------------------


@pytest.fixture
def no_notify() -> Iterator[None]:
    with mock.patch("shared.pipeline.pgpubsub.notify"):
        yield


def test_evaluation_to_cached_payload(
    pending: CVEDerivationClusterProposal,
    make_evaluation: Callable[..., NixEvaluation],
    make_drv: Callable[..., NixDerivation],
    no_notify: None,
) -> None:
    """Evaluation completed -> snapshot -> exposure change -> projection -> cache."""
    # Affected from 1.0 up to (excluding) 2.0, unaffected otherwise.
    Version.objects.filter(affectedproduct__container__cve=pending.cve).update(
        version="1.0", less_than="2.0"
    )
    AffectedProduct.objects.filter(container__cve=pending.cve).update(
        default_status="unaffected", default_status_recorded=True
    )
    refresh_suggestion(pending, matchers=[])
    reconcile_exposures(pending, TrackerEvent.Cause.CVE_UPDATE)
    pending.refresh_from_db()
    assert (
        pending.cached.payload["packages"]["foo"]["branches"]["master"]["status"]
        == "affected"
    )
    evaluation = make_evaluation(state=NixEvaluation.EvaluationState.IN_PROGRESS)
    for attr in ("foo", "foo-cli"):
        make_drv(attribute=attr, pname="foo", version="2.0", evaluation=evaluation)
    make_drv(attribute="x", pname="x", version="1", evaluation=evaluation)
    previous = NixEvaluation.objects.get(pk=evaluation.pk)
    evaluation.state = NixEvaluation.EvaluationState.COMPLETED
    evaluation.save()

    with transaction.atomic():
        snapshot_after_evaluation(old=previous, new=evaluation)
    run_snapshot_step(evaluation)

    exposure = Exposure.objects.get(suggestion=pending, attrpath="foo")
    assert (exposure.version, exposure.observed) == (
        "2.0",
        Exposure.Observed.UNAFFECTED,
    )
    assert exposure.fixed_evaluation == evaluation
    payload = CachedSuggestions.objects.get(proposal=pending).payload
    branch = payload["packages"]["foo"]["branches"]["master"]
    # The chip comes from the exposure: the pooled classifier said "unknown" here.
    assert (branch["version"], branch["status"]) == ("2.0", "unaffected")
    assert derive_states([pending.pk])[pending.pk].state == DerivedState.POSSIBLY_FIXED
    pending.refresh_from_db()
    assert pending.status == Status.PENDING


def test_new_cve_is_atomic(
    make_container: Callable[..., Container],
    snapshot: Callable[..., NixEvaluation],
) -> None:
    """A failure after creating the suggestion leaves nothing behind; a retry succeeds."""
    snapshot({"foo": ("foo", "1.0")})
    container = make_container(package_name="foo", product=None)
    with (
        mock.patch(
            "shared.pipeline.project_links", side_effect=RuntimeError("simulated")
        ),
        pytest.raises(RuntimeError),
    ):
        build_new_links(container)
    assert not CVEDerivationClusterProposal.objects.exists()
    assert not Match.objects.exists()

    assert build_new_links(container)
    assert list(linked(CVEDerivationClusterProposal.objects.get())) == ["foo"]


def test_untracked_branch_is_not_matched(
    make_container: Callable[..., Container],
    make_branch: Callable[..., Any],
    make_channel: Callable[..., Any],
    make_evaluation: Callable[..., NixEvaluation],
    make_drv: Callable[..., NixDerivation],
) -> None:
    from shared.models.nix_evaluation import NixChannel

    eol = make_channel(
        channel_branch="nixos-24.05",
        release_branch=make_branch("release-24.05"),
        state=NixChannel.ChannelState.END_OF_LIFE,
    )
    evaluation = make_evaluation(channel=eol)
    make_drv(pname="foo", evaluation=evaluation)
    update_branch_snapshot(evaluation)
    assert build_new_links(make_container(package_name="foo", product=None))
    suggestion = CVEDerivationClusterProposal.objects.get()
    assert suggestion.rejection_reason == Reason.NO_MATCHES
    assert not suggestion.derivations.exists()


def test_mapping_change_reaches_links_and_cache(
    pending: CVEDerivationClusterProposal,
    make_product_key: Callable[..., Any],
) -> None:
    """Mapping-driven reconciliation goes through the pipeline: links and cache follow."""
    from shared.identity.reconcile import reconcile_mapping_change
    from shared.models.matching import ProductMapping

    persist_product_keys(list(AffectedProduct.objects.all()))
    mapping = ProductMapping.objects.create(
        product_key=make_product_key("foo", "", "cna"),
        relation=ProductMapping.Relation.SAME,
        attrpath="x",
        source=ProductMapping.Source.CURATED,
    )
    reconcile_mapping_change(mapping)
    pending.refresh_from_db()
    assert "x" in linked(pending)
    assert "x" in pending.cached.payload["packages"]


def _range_1_to_2(suggestion: CVEDerivationClusterProposal) -> None:
    """Affected in [1.0, 2.0), unaffected otherwise."""
    Version.objects.filter(affectedproduct__container__cve=suggestion.cve).update(
        version="1.0", less_than="2.0"
    )
    AffectedProduct.objects.filter(container__cve=suggestion.cve).update(
        default_status="unaffected", default_status_recorded=True
    )
    reconcile_exposures(suggestion, TrackerEvent.Cause.CVE_UPDATE)


def test_cached_status_honours_lower_bound_through_exposure(
    pending: CVEDerivationClusterProposal,
    snapshot: Callable[..., NixEvaluation],
) -> None:
    """0.5 is below the range: the pooled classifier said affected, the exposure says not."""
    _range_1_to_2(pending)
    snapshot({"foo": ("foo", "0.5"), "foo-cli": ("foo", "1.0"), "x": ("x", "1")})
    packages = CachedSuggestions.objects.get(proposal=pending).payload["packages"]
    assert packages["foo"]["branches"]["master"]["status"] == "unaffected"
    assert packages["foo-cli"]["branches"]["master"]["status"] == "affected"


def test_published_suggestion_keeps_status_of_its_frozen_version(
    pending: CVEDerivationClusterProposal,
    snapshot: Callable[..., NixEvaluation],
) -> None:
    """Links stay at the version of publication; the exposure follows the branch."""
    _range_1_to_2(pending)
    pending.change_status(Status.ACCEPTED)
    CVEDerivationClusterProposal.objects.filter(pk=pending.pk).update(
        status=Status.PUBLISHED
    )
    snapshot({"foo": ("foo", "2.0"), "foo-cli": ("foo", "1.0"), "x": ("x", "1")})

    foo = CachedSuggestions.objects.get(proposal=pending).payload["packages"]["foo"]
    assert (
        foo["branches"]["master"]["version"],
        foo["branches"]["master"]["status"],
    ) == (
        "1.0",
        "affected",
    )
    assert Exposure.objects.get(suggestion=pending, attrpath="foo").observed == (
        Exposure.Observed.UNAFFECTED
    )


# --- Stored derived state ---------------------------------------------------------------------


def stored_state(suggestion: CVEDerivationClusterProposal) -> str:
    from shared.models.matching import SuggestionDerivedState

    return SuggestionDerivedState.objects.get(suggestion=suggestion).state


def assert_derived_states_consistent() -> None:
    from shared.models.matching import SuggestionDerivedState

    assert not SuggestionDerivedState.objects.filter(stale=True).exists()
    ids = list(CVEDerivationClusterProposal.objects.values_list("pk", flat=True))
    stored = dict(SuggestionDerivedState.objects.values_list("suggestion_id", "state"))
    assert stored == {pk: str(d.state) for pk, d in derive_states(ids).items()}


def test_every_writer_keeps_the_stored_derived_state(
    make_container: Callable[..., Container],
    snapshot: Callable[..., NixEvaluation],
    make_product_key: Callable[..., Any],
    committer: Any,
) -> None:
    from shared.derived_state import remove_verdict, set_verdict
    from shared.identity.reconcile import reconcile_mapping_change
    from shared.models.matching import ProductMapping, Verdict

    snapshot({"foo": ("foo", "1.0"), "foo-cli": ("foo", "1.0"), "x": ("x", "1")})
    # Creation.
    assert build_new_links(make_container(package_name="foo", product=None))
    assert build_new_links(make_container(cve_id="CVE-2025-0002", package_name="nope"))
    assert_derived_states_consistent()
    suggestion = CVEDerivationClusterProposal.objects.get(cve__cve_id="CVE-2025-0001")
    rejected = CVEDerivationClusterProposal.objects.get(cve__cve_id="CVE-2025-0002")
    assert stored_state(suggestion) == DerivedState.NEEDS_TRIAGE
    assert stored_state(rejected) == DerivedState.NO_CANDIDATES
    # Verdicts, ignore and restore.
    set_verdict(suggestion, "foo", Verdict.Kind.NOT_AFFECTED, committer)
    assert_derived_states_consistent()
    remove_verdict(suggestion, "foo", committer)
    cache_new_suggestions(suggestion)
    suggestion.ignore_packages(["foo-cli"], committer)
    assert_derived_states_consistent()
    # Status changes.
    suggestion.change_status(Status.ACCEPTED, author=committer)
    assert_derived_states_consistent()
    assert stored_state(suggestion) == DerivedState.TRACKING
    # Evaluation (exposures, re-match, projection).
    snapshot({"foo": ("foo", "1.1"), "foo-cli": ("foo", "1.0"), "x": ("x", "2")})
    assert_derived_states_consistent()
    # Re-match and mapping-driven reconciliation, reopening the rejection.
    persist_product_keys(list(AffectedProduct.objects.all()))
    mapping = ProductMapping.objects.create(
        product_key=make_product_key("nope", "", "cna"),
        relation=ProductMapping.Relation.SAME,
        attrpath="x",
        source=ProductMapping.Source.CURATED,
    )
    refresh_suggestion(rejected, matchers=["curated"])
    rejected.refresh_from_db()
    assert rejected.status == Status.PENDING
    assert_derived_states_consistent()
    reconcile_mapping_change(mapping)
    assert_derived_states_consistent()
    # Backfill.
    from io import StringIO

    from django.core.management import call_command

    call_command("backfill_unified_model", stdout=StringIO())
    assert_derived_states_consistent()


def test_recompute_command_reports_and_fixes_drift(
    pending: CVEDerivationClusterProposal,
) -> None:
    from io import StringIO

    from django.core.management import call_command

    from shared.models.matching import SuggestionDerivedState

    SuggestionDerivedState.objects.filter(suggestion=pending).update(state="resolved")
    out = StringIO()
    with pytest.raises(SystemExit):
        call_command("recompute_derived_state", "--check", stdout=out)
    assert "wrong 1" in out.getvalue()
    call_command("recompute_derived_state", stdout=StringIO())
    assert_derived_states_consistent()


def test_mapping_reopens_recent_too_many_matches_rejection(
    make_container: Callable[..., Container],
    make_suggestion: Callable[..., CVEDerivationClusterProposal],
    make_product_key: Callable[..., Any],
    snapshot: Callable[..., NixEvaluation],
    settings: Any,
) -> None:
    """A rule turns a legacy `max_matches_exceeded` rejection into a sensible candidate set."""
    from datetime import timedelta

    from django.utils import timezone

    from shared.identity.reconcile import reconcile_mapping_change
    from shared.models.cve import CveRecord
    from shared.models.matching import ProductMapping

    settings.MATCHING_REOPEN_WINDOW_DAYS = 30
    snapshot({"linuxKernel.kernels.linux_6_6": ("linux", "6.6.1"), "x": ("x", "1")})
    container = make_container(package_name="Linux", product=None)
    CveRecord.objects.filter(pk=container.cve.pk).update(
        date_published=timezone.now() - timedelta(days=3)
    )
    suggestion = make_suggestion(
        container=container,
        drvs={},
        status=Status.REJECTED,
        rejection_reason=Reason.MAX_MATCHES_EXCEEDED,
    )
    persist_product_keys(list(AffectedProduct.objects.all()))
    mapping = ProductMapping.objects.create(
        product_key=make_product_key("linux", "", "cna"),
        relation=ProductMapping.Relation.SAME,
        attr_glob="linuxKernel.kernels.*",
        source=ProductMapping.Source.RULE_FILE,
    )
    reconcile_mapping_change(mapping)

    suggestion.refresh_from_db()
    assert suggestion.status == Status.PENDING
    assert list(linked(suggestion)) == ["linuxKernel.kernels.linux_6_6"]
