import json
from collections.abc import Callable
from datetime import UTC, datetime

import pytest
from django.contrib.auth.models import User
from django.db import connection
from django.test.utils import CaptureQueriesContext
from rest_framework.reverse import reverse
from rest_framework.test import APIClient

from shared.identity.reconcile import reconcile_mapping_change
from shared.matching.reconcile import reconcile_matches
from shared.models.cve import AffectedProduct
from shared.models.linkage import CVEDerivationClusterProposal
from shared.models.matching import (
    Exposure,
    Match,
    ProductMapping,
    TrackerEvent,
    Verdict,
)
from shared.models.nix_evaluation import NixChannel, NixEvaluation, NixpkgsBranch
from shared.tests.test_identity_mappings import make_mapping, persist_keys  # noqa: F401

Observed = Exposure.Observed
V = Verdict.Kind


def url(pk: int) -> str:
    return reverse("cvederivationclusterproposal-matching", kwargs={"pk": pk})


@pytest.fixture
def release(
    make_branch: Callable[..., NixpkgsBranch],
    make_channel: Callable[..., NixChannel],
) -> NixpkgsBranch:
    """A second tracked branch."""
    branch = make_branch("release-26.05")
    make_channel(
        channel_branch="nixos-26.05",
        release_branch=branch,
        state=NixChannel.ChannelState.STABLE,
    )
    return branch


def evidence(product: AffectedProduct | None = None, **extra: object) -> dict:
    return {
        "affected_product": product.pk if product else None,
        "container": "cna",
        "cve_field": "product",
        "cve_value": "foo",
        "pkg_field": "pname",
        "pkg_value": "foo",
        "branches": ["master"],
    } | extra


def populate(
    suggestion: CVEDerivationClusterProposal,
    n: int,
    branches: list[NixpkgsBranch],
    evaluation: NixEvaluation,
) -> None:
    """`n` attributes, two matches each, an exposure per branch."""
    product = AffectedProduct.objects.create(vendor="acme", product="foo")
    for i in range(n):
        attr = f"attr{i:02}"
        Match.objects.create(
            suggestion=suggestion,
            attrpath=attr,
            matcher="name-exact",
            matcher_version=1,
            score=1.0,
            evidence=evidence(product),
        )
        Match.objects.create(
            suggestion=suggestion,
            attrpath=attr,
            matcher="name-trigram",
            matcher_version=1,
            score=0.6 + i / (n * 3),
            evidence=evidence(product, similarity=0.7),
        )
        for b in branches:
            Exposure.objects.create(
                suggestion=suggestion,
                attrpath=attr,
                branch=b,
                version="1.2.3",
                observed=Observed.AFFECTED,
                reason=Exposure.Reason.VERSION_RANGE,
                evaluation=evaluation,
                first_affected_evaluation=evaluation,
                last_affected_evaluation=evaluation,
                detail={
                    "detail": "1.2.3 in [1.0, 2.0)",
                    "range": "[1.0, 2.0)",
                    "range_source": "cna",
                    "affected_product": product.pk,
                    "last_affected_version": "1.2.3",
                },
            )


def test_shape(
    anonymous_client: APIClient,
    suggestion: CVEDerivationClusterProposal,
    branch: NixpkgsBranch,
    release: NixpkgsBranch,
    evaluation: NixEvaluation,
    make_match: Callable[..., Match],
    make_exposure: Callable[..., Exposure],
    make_verdict: Callable[..., Verdict],
    committer: User,
) -> None:
    product = AffectedProduct.objects.create(vendor="acme", product="foo")
    make_match("foo", "name-exact", 1.0, evidence=evidence(product, other_hits=2))
    make_match("foo", "name-trigram", 0.8, evidence=evidence(similarity=0.8))
    make_match("bar", "name-substring", 0.5, evidence=evidence())
    make_exposure(
        "foo",
        detail={"detail": "1.0 in [1.0, 2.0)", "inferred": False, "secret": 1},
        first_affected_evaluation=evaluation,
    )
    make_exposure(
        "foo",
        observed=Observed.UNAFFECTED,
        reason=Exposure.Reason.VERSION_RANGE,
        version="2.1",
        branch=release,
        detail={"detail": "outside every affected range", "inferred": True},
    )
    # Retracted, but carries a verdict.
    make_match("gone", "name-exact", 1.0, retracted_at=datetime(2026, 1, 1, tzinfo=UTC))
    make_verdict("gone", V.IRRELEVANT, author=committer)
    make_verdict("foo", V.WONTFIX, branch=release)
    # Retracted without verdict: not a candidate.
    make_match("old", "name-exact", 1.0, retracted_at=datetime(2026, 1, 1, tzinfo=UTC))

    response = anonymous_client.get(url(suggestion.pk))
    assert response.status_code == 200
    data = response.json()
    assert data["cve_id"] == suggestion.cve.cve_id
    assert [b["name"] for b in data["branches"]] == ["master", "release-26.05"]
    assert [a["attrpath"] for a in data["attributes"]] == ["foo", "bar", "gone"]
    foo, bar, gone = data["attributes"]

    assert (foo["rank"], bar["rank"], gone["rank"]) == (1, 2, None)
    assert foo["score"] == pytest.approx(1 - (1 - 0.8) * (1 - 0.7 * 0.8))
    assert foo["has_active_match"] and not foo["retracted"]
    assert (gone["has_active_match"], gone["retracted"], gone["score"]) == (
        False,
        True,
        None,
    )
    assert [m["matcher"] for m in foo["matches"]] == ["name-exact", "name-trigram"]
    exact = foo["matches"][0]
    assert exact["evidence"] == {
        "affected_product": product.pk,
        "container": "cna",
        "cve_field": "product",
        "cve_value": "foo",
        "pkg_field": "pname",
        "pkg_value": "foo",
        "similarity": None,
        "branches": ["master"],
        "other_hits": 2,
        "mapping": None,
        "provenance_flags": None,
        "cve_fields": [],
    }
    assert exact["vetoed"] is False and foo["vetoed_by"] == []
    assert exact["weight"] == 0.8 and exact["contribution"] == 0.8
    assert foo["matches"][1]["evidence"]["similarity"] == 0.8
    assert data["affected_products"] == {
        str(product.pk): {
            "vendor": "acme",
            "product": "foo",
            "package_name": None,
            "repo": None,
        }
    }

    master, rel = foo["branches"]
    assert master["exposure"]["observed"] == "affected"
    assert master["exposure"]["detail"]["detail"] == "1.0 in [1.0, 2.0)"
    assert "secret" not in master["exposure"]["detail"]
    assert master["exposure"]["first_affected_evaluation"] == evaluation.pk
    assert data["evaluations"][str(evaluation.pk)]["commit_sha1"] == (
        evaluation.commit_sha1
    )
    assert master["effective"] == {
        "status": "affected",
        "source": "observed",
        "regression": False,
        "verdict_branch": None,
    }
    assert rel["exposure"]["detail"]["inferred"] is True
    assert rel["effective"]["status"] == "wontfix"
    assert rel["effective"]["verdict_branch"] == "release-26.05"
    assert foo["verdicts"][0]["branch"] == "release-26.05"

    # bar has no exposure anywhere and no verdict.
    assert [b["effective"] for b in bar["branches"]] == [None, None]
    assert gone["verdicts"][0]["author"] == "committer"
    assert [b["effective"]["status"] for b in gone["branches"]] == [
        "irrelevant",
        "irrelevant",
    ]

    assert data["derived"]["state"] == "needs_triage"
    assert {"attrpath": "foo", "branch": "master"} in data["derived"]["needs_triage"]
    assert {"attrpath": "bar", "branch": None} in data["derived"]["needs_triage"]


def test_acceptance_is_a_verdict(
    anonymous_client: APIClient,
    committer_client: APIClient,
    cached_suggestion: CVEDerivationClusterProposal,
    make_match: Callable[..., Match],
    make_exposure: Callable[..., Exposure],
) -> None:
    make_match(suggestion=cached_suggestion)
    make_exposure(suggestion=cached_suggestion)
    response = committer_client.post(
        reverse(
            "cvederivationclusterproposal-status", kwargs={"pk": cached_suggestion.pk}
        ),
        {"status": "accepted"},
        format="json",
    )
    assert response.status_code == 200
    data = anonymous_client.get(url(cached_suggestion.pk)).json()
    (foo,) = data["attributes"]
    assert foo["verdicts"][0]["author"] == "committer"
    assert foo["branches"][0]["effective"] == {
        "status": "affected",
        "source": "verdict",
        "regression": False,
        "verdict_branch": None,
    }
    assert data["derived"]["state"] == "tracking"


def test_rules_evidence_and_veto(
    anonymous_client: APIClient,
    suggestion: CVEDerivationClusterProposal,
    channel: NixChannel,
    make_branch_package: Callable[..., object],
    make_mapping: Callable[..., ProductMapping],  # noqa: F811
) -> None:
    """A `rules` match names its mapping; a `not_same` mapping vetoes, then retracts."""
    make_branch_package()
    rule = make_mapping("foo", ProductMapping.Relation.SAME, attr_glob="fo*")
    persist_keys()
    result = reconcile_matches(
        suggestion, TrackerEvent.Cause.MATCHER, ["rules", "name-exact"]
    )
    assert result.added, result
    (foo,) = anonymous_client.get(url(suggestion.pk)).json()["attributes"]
    rules = next(m for m in foo["matches"] if m["matcher"] == "rules")
    assert rules["evidence"]["mapping"] == {
        "id": rule.pk,
        "product_key": "cna:/foo",
        "relation": "same",
        "source": "curated",
        "target": "fo*",
    }
    assert rules["evidence"]["pkg_field"] == "attr_glob"

    veto = make_mapping("foo", ProductMapping.Relation.NOT_SAME, attrpath="foo")
    (foo,) = anonymous_client.get(url(suggestion.pk)).json()["attributes"]
    assert [m["vetoed"] for m in foo["matches"]] == [True, True]
    assert foo["score"] == 0
    assert foo["vetoed_by"][0]["id"] == veto.pk

    reconcile_mapping_change(veto)
    # Retracted without a verdict: no longer a candidate.
    assert anonymous_client.get(url(suggestion.pk)).json()["attributes"] == []


def test_empty_and_missing(
    anonymous_client: APIClient, suggestion: CVEDerivationClusterProposal
) -> None:
    data = anonymous_client.get(url(suggestion.pk)).json()
    assert data["attributes"] == []
    assert data["derived"]["state"] == "no_candidates"
    assert anonymous_client.get(url(suggestion.pk + 1)).status_code == 404


def test_query_count_and_size(
    anonymous_client: APIClient,
    make_suggestion: Callable[..., CVEDerivationClusterProposal],
    make_container: Callable[..., object],
    branch: NixpkgsBranch,
    release: NixpkgsBranch,
    make_branch: Callable[..., NixpkgsBranch],
    make_channel: Callable[..., NixChannel],
    evaluation: NixEvaluation,
    django_assert_num_queries: Callable[..., CaptureQueriesContext],
) -> None:
    small = make_suggestion(container=make_container(cve_id="CVE-2025-2000"))
    large = make_suggestion(container=make_container(cve_id="CVE-2025-2001"))
    third = make_branch("release-25.11")
    make_channel(
        channel_branch="nixos-25.11",
        release_branch=third,
        state=NixChannel.ChannelState.DEPRECATED,
    )
    branches = [branch, release, third]
    populate(small, 1, branches, evaluation)
    populate(large, 50, branches, evaluation)

    with CaptureQueriesContext(connection) as ctx:
        anonymous_client.get(url(small.pk))
    with django_assert_num_queries(len(ctx.captured_queries)):
        response = anonymous_client.get(url(large.pk))
    assert len(ctx.captured_queries) <= 16
    data = response.json()
    assert len(data["attributes"]) == 50
    assert all(len(a["branches"]) == 3 for a in data["attributes"])
    # 50 attributes x 2 matches x 3 branches stays well under 200 kB.
    size = len(json.dumps(data))
    print(f"matching view: {len(ctx.captured_queries)} queries, {size} bytes")
    assert size < 200_000, size


def test_offset_limit(
    anonymous_client: APIClient,
    suggestion: CVEDerivationClusterProposal,
    branch: NixpkgsBranch,
    evaluation: NixEvaluation,
) -> None:
    populate(suggestion, 5, [branch], evaluation)
    full = anonymous_client.get(url(suggestion.pk)).json()
    ranked = [a["attrpath"] for a in full["attributes"]]
    page = anonymous_client.get(url(suggestion.pk), {"offset": 1, "limit": 2}).json()
    assert page["attribute_count"] == 5
    assert [a["attrpath"] for a in page["attributes"]] == ranked[1:3]
    assert [a["rank"] for a in page["attributes"]] == [2, 3]
    assert page["derived"] == full["derived"]
    response = anonymous_client.get(url(suggestion.pk), {"limit": 0})
    assert response.status_code == 400
