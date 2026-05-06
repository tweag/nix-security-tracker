from collections.abc import Callable

from django.test import Client
from django.urls import reverse

from shared.models.cve import Container
from shared.models.linkage import (
    CVEDerivationClusterProposal,
    PackageOverlay,
    ProvenanceFlags,
)
from shared.models.nix_evaluation import NixDerivation


def test_feed_unknown_package_fails(client: Client, db: None) -> None:
    response = client.get(
        reverse("feeds:package_feed", kwargs={"package_name": "nonexistent"})
    )
    assert response.status_code == 404


def test_feed_known_package_succeeds(
    client: Client,
    make_cached_suggestion: Callable[..., CVEDerivationClusterProposal],
    drv: NixDerivation,
) -> None:
    make_cached_suggestion()
    response = client.get(
        reverse("feeds:package_feed", kwargs={"package_name": drv.attribute})
    )
    assert response.status_code == 200
    assert "application/atom+xml" in response["Content-Type"]


def test_feed_contains_creation_event(
    client: Client,
    make_cached_suggestion: Callable[..., CVEDerivationClusterProposal],
    drv: NixDerivation,
) -> None:
    make_cached_suggestion()
    response = client.get(
        reverse("feeds:package_feed", kwargs={"package_name": drv.attribute})
    )
    assert response.status_code == 200
    content = response.content.decode()
    assert "created" in content
    assert "CVE-2025-0001" in content


def test_feed_contains_status_change_event(
    client: Client,
    make_cached_suggestion: Callable[..., CVEDerivationClusterProposal],
    drv: NixDerivation,
) -> None:
    suggestion = make_cached_suggestion()
    # Change status to accepted to produce a status-change event
    suggestion.status = CVEDerivationClusterProposal.Status.ACCEPTED
    suggestion.save()

    response = client.get(
        reverse("feeds:package_feed", kwargs={"package_name": drv.attribute})
    )
    content = response.content.decode()
    assert "accepted" in content


def test_feed_item_links_to_suggestion_detail(
    client: Client,
    make_cached_suggestion: Callable[..., CVEDerivationClusterProposal],
    drv: NixDerivation,
) -> None:
    suggestion = make_cached_suggestion()
    response = client.get(
        reverse("feeds:package_feed", kwargs={"package_name": drv.attribute})
    )
    content = response.content.decode()
    suggestion_url = reverse(
        "webview:suggestion:detail", kwargs={"suggestion_id": suggestion.pk}
    )
    assert suggestion_url in content


def test_feed_contains_cve_link(
    client: Client,
    make_cached_suggestion: Callable[..., CVEDerivationClusterProposal],
    drv: NixDerivation,
) -> None:
    make_cached_suggestion()
    response = client.get(
        reverse("feeds:package_feed", kwargs={"package_name": drv.attribute})
    )
    content = response.content.decode()
    assert "nvd.nist.gov/vuln/detail/CVE-2025-0001" in content


def test_feed_excludes_suggestion_with_ignored_package(
    client: Client,
    make_cached_suggestion: Callable[..., CVEDerivationClusterProposal],
    drv: NixDerivation,
) -> None:
    suggestion = make_cached_suggestion()
    # Ignore the package in the suggestion
    PackageOverlay.objects.create(
        suggestion=suggestion,
        package_attribute=drv.attribute,
        overlay_type=PackageOverlay.Type.IGNORED,
    )

    response = client.get(
        reverse("feeds:package_feed", kwargs={"package_name": drv.attribute})
    )
    assert response.status_code == 200
    content = response.content.decode()
    # No entries should appear for this suggestion
    suggestion_url = reverse(
        "webview:suggestion:detail", kwargs={"suggestion_id": suggestion.pk}
    )
    assert suggestion_url not in content


def test_feed_includes_non_ignored_suggestion_but_excludes_ignored_one(
    client: Client,
    make_container: Callable[..., Container],
    make_drv: Callable[..., NixDerivation],
    make_cached_suggestion: Callable[..., CVEDerivationClusterProposal],
) -> None:
    drv = make_drv(pname="shared-pkg")
    container_a = make_container(cve_id="CVE-2025-0001")
    container_b = make_container(cve_id="CVE-2025-0002")

    suggestion_active = make_cached_suggestion(
        container=container_a,
        drvs={drv: ProvenanceFlags.PACKAGE_NAME_MATCH},
    )
    suggestion_ignored = make_cached_suggestion(
        container=container_b,
        drvs={drv: ProvenanceFlags.PACKAGE_NAME_MATCH},
    )
    PackageOverlay.objects.create(
        suggestion=suggestion_ignored,
        package_attribute=drv.attribute,
        overlay_type=PackageOverlay.Type.IGNORED,
    )

    response = client.get(
        reverse("feeds:package_feed", kwargs={"package_name": drv.attribute})
    )
    content = response.content.decode()

    active_url = reverse(
        "webview:suggestion:detail", kwargs={"suggestion_id": suggestion_active.pk}
    )
    ignored_url = reverse(
        "webview:suggestion:detail", kwargs={"suggestion_id": suggestion_ignored.pk}
    )
    assert active_url in content
    assert ignored_url not in content


def test_feed_creation_event_with_rejection_reason(
    client: Client,
    make_cached_suggestion: Callable[..., CVEDerivationClusterProposal],
    drv: NixDerivation,
) -> None:
    make_cached_suggestion(
        rejection_reason=CVEDerivationClusterProposal.RejectionReason.EXCLUSIVELY_HOSTED_SERVICE
    )
    response = client.get(
        reverse("feeds:package_feed", kwargs={"package_name": drv.attribute})
    )
    content = response.content.decode()
    assert "auto-dismissed" in content
    assert "exclusively hosted service" in content
