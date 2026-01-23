from collections.abc import Callable

from allauth.socialaccount.models import SocialAccount
from django.contrib.auth.models import User
from django.test import Client, TestCase
from django.urls import reverse
from playwright.sync_api import Page, expect
from pytest_django.live_server_helper import LiveServer

from shared.listeners.automatic_linkage import build_new_links
from shared.listeners.notify_users import create_package_subscription_notifications
from shared.models.cve import (
    AffectedProduct,
    CveRecord,
    Description,
    Metric,
    Organization,
    Version,
)
from shared.models.linkage import CVEDerivationClusterProposal, ProvenanceFlags
from shared.models.nix_evaluation import (
    NixChannel,
    NixDerivation,
    NixDerivationMeta,
    NixEvaluation,
    NixMaintainer,
)
from webview.models import Notification


def test_user_subscribes_to_valid_package_success(
    live_server: LiveServer,
    as_staff: Page,
    staff: User,
    drv: NixDerivation,
    no_js: bool,
) -> None:
    """Test subscribing to an existing package and unsubscribing again"""
    as_staff.goto(live_server.url + reverse("webview:subscriptions:center"))
    subscriptions = as_staff.locator("#package-subscriptions")
    subscriptions.get_by_placeholder("Package name").fill(drv.attribute)
    empty_state = subscriptions.get_by_text(
        "You haven't subscribed to any packages yet."
    )
    expect(empty_state).to_be_visible()
    subscribe = subscriptions.get_by_role("button", name="Subscribe")
    subscribe.click()
    unsubscribe = subscriptions.filter(has_text=drv.attribute).get_by_role(
        "button", name="Unsubscribe"
    )
    if not no_js:
        # FIXME(@fricklerhandwerk): Shouldn't we always have a confirmation dialog?
        as_staff.on("dialog", lambda dialog: dialog.accept())
    unsubscribe.click()
    expect(empty_state).to_be_visible()
    expect(unsubscribe).to_have_count(0)


def test_user_subscribes_to_invalid_package_fails(
    live_server: LiveServer,
    as_staff: Page,
    no_js: bool,
) -> None:
    """Test subscription fails for non-existent package"""
    as_staff.goto(live_server.url + reverse("webview:subscriptions:center"))
    subscriptions = as_staff.locator("#package-subscriptions")
    subscriptions.get_by_placeholder("Package name").fill("nonexistent")
    subscribe = subscriptions.get_by_role("button", name="Subscribe")
    subscribe.click()

    if no_js:
        error = as_staff.locator(
            "#messages",
            has_text="does not exist",
        )
    else:
        error = subscriptions.locator(
            ".error-block",
            has_text="does not exist",
        )

    expect(error).to_be_visible()


def test_user_cannot_subscribe_to_same_package_twice(
    live_server: LiveServer,
    as_staff: Page,
    staff: User,
    no_js: bool,
    drv: NixDerivation,
) -> None:
    """Test that one can't subscribe to a package twice"""
    as_staff.goto(live_server.url + reverse("webview:subscriptions:center"))
    subscriptions = as_staff.locator("#package-subscriptions")
    subscriptions.get_by_placeholder("Package name").fill(drv.attribute)
    subscribe = subscriptions.get_by_role("button", name="Subscribe", exact=True)
    subscribe.click()

    unsubscribe = subscriptions.filter(has_text=drv.attribute).get_by_role(
        "button", name="Unsubscribe"
    )
    expect(unsubscribe).to_be_visible()

    subscriptions.get_by_placeholder("Package name").fill(drv.attribute)
    subscribe.click()

    if no_js:
        error = as_staff.locator(
            "#messages",
            has_text="already subscribed",
        )
    else:
        error = subscriptions.locator(
            ".error-block",
            has_text="already subscribed",
        )
    expect(error).to_be_visible()
    expect(unsubscribe).to_be_visible()


def test_subscription_center_shows_user_subscriptions(
    make_drv: Callable[..., NixDerivation],
    live_server: LiveServer,
    as_staff: Page,
    no_js: bool,
) -> None:
    """Test that the center displays user's current subscriptions"""
    make_drv(pname="firefox")
    make_drv(pname="chromium")

    as_staff.goto(live_server.url + reverse("webview:subscriptions:center"))
    subscriptions = as_staff.locator("#package-subscriptions")
    input_field = subscriptions.get_by_placeholder("Package name")
    input_field.fill("firefox")
    subscribe = subscriptions.get_by_role("button", name="Subscribe", exact=True)
    subscribe.click()
    unsubscribe = subscriptions.get_by_role("button", name="Unsubscribe")
    expect(unsubscribe).to_have_count(1)
    input_field.fill("chromium")
    subscribe.click()
    expect(unsubscribe).to_have_count(2)


class SubscriptionTests(TestCase):
    def setUp(self) -> None:
        # Create test user with social account
        self.user = User.objects.create_user(username="testuser", password="testpass")
        self.user.is_staff = True
        self.user.save()

        SocialAccount.objects.get_or_create(
            user=self.user,
            provider="github",
            uid="123456",
            extra_data={"login": "testuser"},
        )

        self.client = Client()
        self.client.login(username="testuser", password="testpass")

        # Create test NixDerivation data for package validation
        self.maintainer = NixMaintainer.objects.create(
            github_id=123,
            github="testmaintainer",
            name="Test Maintainer",
            email="test@example.com",
        )
        self.meta = NixDerivationMeta.objects.create(
            description="Test package",
            insecure=False,
            available=True,
            broken=False,
            unfree=False,
            unsupported=False,
        )
        self.meta.maintainers.add(self.maintainer)

        self.evaluation = NixEvaluation.objects.create(
            channel=NixChannel.objects.create(
                staging_branch="release-24.05",
                channel_branch="nixos-24.05",
                head_sha1_commit="deadbeef",
                state=NixChannel.ChannelState.STABLE,
                release_version="24.05",
                repository="https://github.com/NixOS/nixpkgs",
            ),
            commit_sha1="deadbeef",
            state=NixEvaluation.EvaluationState.COMPLETED,
        )

        # Create valid packages that can be subscribed to
        self.valid_package1 = NixDerivation.objects.create(
            attribute="firefox",
            derivation_path="/nix/store/firefox.drv",
            name="firefox-120.0",
            metadata=self.meta,
            system="x86_64-linux",
            parent_evaluation=self.evaluation,
        )

        # Create separate metadata for chromium
        self.meta2 = NixDerivationMeta.objects.create(
            description="Test chromium package",
            insecure=False,
            available=True,
            broken=False,
            unfree=False,
            unsupported=False,
        )
        self.meta2.maintainers.add(self.maintainer)

        self.valid_package2 = NixDerivation.objects.create(
            attribute="chromium",
            derivation_path="/nix/store/chromium.drv",
            name="chromium-119.0",
            metadata=self.meta2,
            system="x86_64-linux",
            parent_evaluation=self.evaluation,
        )

        # Create a maintainer for the test user
        self.user_maintainer = NixMaintainer.objects.create(
            github_id=123456,  # Same as the user's social account uid
            github="testuser",  # Same as the user's username
            name="Test User",
            email="testuser@example.com",
        )

        # Create metadata for a package where test user is maintainer
        self.meta3 = NixDerivationMeta.objects.create(
            description="Test package maintained by test user",
            insecure=False,
            available=True,
            broken=False,
            unfree=False,
            unsupported=False,
        )
        self.meta3.maintainers.add(self.user_maintainer)

        # Create a package where the test user is a maintainer
        self.user_maintained_package = NixDerivation.objects.create(
            attribute="neovim",
            derivation_path="/nix/store/neovim.drv",
            name="neovim-0.9.5",
            metadata=self.meta3,
            system="x86_64-linux",
            parent_evaluation=self.evaluation,
        )

    def test_subscription_center_requires_login(self) -> None:
        """Test that subscription center redirects when not logged in"""
        # Logout the user
        self.client.logout()

        response = self.client.get(reverse("webview:subscriptions:center"))
        self.assertEqual(response.status_code, 302)
        self.assertIn("login", response.url)

        # Test add endpoint also requires login
        response = self.client.post(
            reverse("webview:subscriptions:add"), {"package_name": "firefox"}
        )
        self.assertEqual(response.status_code, 302)
        self.assertIn("login", response.url)

        # Test remove endpoint also requires login
        response = self.client.post(
            reverse("webview:subscriptions:remove"), {"package_name": "firefox"}
        )
        self.assertEqual(response.status_code, 302)
        self.assertIn("login", response.url)

        # Test HTMX requests also require login
        response = self.client.post(
            reverse("webview:subscriptions:add"),
            {"package_name": "firefox"},
            HTTP_HX_REQUEST="true",
        )
        self.assertEqual(response.status_code, 302)
        self.assertIn("login", response.url)

        response = self.client.post(
            reverse("webview:subscriptions:remove"),
            {"package_name": "firefox"},
            HTTP_HX_REQUEST="true",
        )
        self.assertEqual(response.status_code, 302)
        self.assertIn("login", response.url)

    def test_user_receives_notification_for_subscribed_package_suggestion(self) -> None:
        """Test that users receive notifications when suggestions affect their subscribed packages"""
        # User subscribes to firefox package
        add_url = reverse("webview:subscriptions:add")
        self.client.post(add_url, {"package_name": "firefox"}, HTTP_HX_REQUEST="true")

        # Create CVE and container
        assigner = Organization.objects.create(uuid=1, short_name="test_org")
        cve_record = CveRecord.objects.create(
            cve_id="CVE-2025-0001",
            assigner=assigner,
        )

        description = Description.objects.create(value="Test firefox vulnerability")
        metric = Metric.objects.create(format="cvssV3_1", raw_cvss_json={})
        affected_product = AffectedProduct.objects.create(package_name="firefox")
        affected_product.versions.add(
            Version.objects.create(status=Version.Status.AFFECTED, version="120.0")
        )

        container = cve_record.container.create(
            provider=assigner,
            title="Firefox Security Issue",
        )

        container.affected.set([affected_product])
        container.descriptions.set([description])
        container.metrics.set([metric])

        # Trigger the linkage and notification system manually since pgpubsub triggers won't work in tests
        linkage_created = build_new_links(container)

        if linkage_created:
            # Get the created proposal and trigger notifications
            suggestion = CVEDerivationClusterProposal.objects.get(cve=cve_record)
            create_package_subscription_notifications(suggestion)

        # Verify notification appears in notification center context
        response = self.client.get(reverse("webview:notifications:center"))
        self.assertEqual(response.status_code, 200)

        # Check that notification appears in context
        notifications = response.context["notifications"]
        self.assertEqual(len(notifications), 1)

        notification = notifications[0]
        self.assertEqual(notification.user, self.user)
        self.assertIn("firefox", notification.message)
        self.assertIn("CVE-2025-0001", notification.title)
        self.assertFalse(notification.is_read)  # Should be unread initially

    def test_user_receives_notification_for_maintained_package_suggestion(self) -> None:
        """Test that users receive notifications when suggestions affect packages they maintain (automatic subscription)"""

        # Create CVE and container
        assigner = Organization.objects.create(uuid=2, short_name="test_org2")
        cve_record = CveRecord.objects.create(
            cve_id="CVE-2025-0002",
            assigner=assigner,
        )

        description = Description.objects.create(value="Test neovim vulnerability")
        metric = Metric.objects.create(format="cvssV3_1", raw_cvss_json={})
        affected_product = AffectedProduct.objects.create(package_name="neovim")
        affected_product.versions.add(
            Version.objects.create(status=Version.Status.AFFECTED, version="0.9.5")
        )

        container = cve_record.container.create(
            provider=assigner,
            title="Neovim Security Issue",
        )

        container.affected.set([affected_product])
        container.descriptions.set([description])
        container.metrics.set([metric])

        # Trigger the linkage and notification system manually since pgpubsub triggers won't work in tests
        linkage_created = build_new_links(container)

        if linkage_created:
            # Get the created proposal and trigger notifications
            suggestion = CVEDerivationClusterProposal.objects.get(cve=cve_record)
            create_package_subscription_notifications(suggestion)

        # Verify notification appears in notification center context
        response = self.client.get(reverse("webview:notifications:center"))
        self.assertEqual(response.status_code, 200)

        # Check that notification appears in context
        notifications = response.context["notifications"]
        self.assertEqual(len(notifications), 1)

        notification = notifications[0]
        self.assertEqual(notification.user, self.user)
        self.assertIn("neovim", notification.message)
        self.assertIn("CVE-2025-0002", notification.title)
        self.assertFalse(notification.is_read)  # Should be unread initially

    def test_user_does_not_receive_notification_when_auto_subscribe_disabled(
        self,
    ) -> None:
        """Test that users do NOT receive notifications for maintained packages when auto-subscription is disabled"""
        # Disable auto-subscription using the view
        toggle_url = reverse("webview:subscriptions:toggle_auto_subscribe")
        response = self.client.post(
            toggle_url, {"action": "disable"}, HTTP_HX_REQUEST="true"
        )

        # Should return 200 with component template for HTMX request
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(
            response, "subscriptions/components/auto_subscribe.html"
        )

        # Verify auto-subscription is disabled in response context
        self.assertIn("auto_subscribe_enabled", response.context)
        self.assertFalse(response.context["auto_subscribe_enabled"])

        # Create CVE and container
        assigner = Organization.objects.create(uuid=3, short_name="test_org3")
        cve_record = CveRecord.objects.create(
            cve_id="CVE-2025-0003",
            assigner=assigner,
        )

        description = Description.objects.create(
            value="Test neovim vulnerability with auto-subscribe disabled"
        )
        metric = Metric.objects.create(format="cvssV3_1", raw_cvss_json={})
        affected_product = AffectedProduct.objects.create(package_name="neovim")
        affected_product.versions.add(
            Version.objects.create(status=Version.Status.AFFECTED, version="0.9.5")
        )

        container = cve_record.container.create(
            provider=assigner,
            title="Neovim Security Issue",
        )

        container.affected.set([affected_product])
        container.descriptions.set([description])
        container.metrics.set([metric])

        # Trigger the linkage and notification system manually since pgpubsub triggers won't work in tests
        linkage_created = build_new_links(container)

        if linkage_created:
            # Get the created proposal and trigger notifications
            suggestion = CVEDerivationClusterProposal.objects.get(cve=cve_record)
            create_package_subscription_notifications(suggestion)

        # Verify NO notification appears in notification center context
        response = self.client.get(reverse("webview:notifications:center"))
        self.assertEqual(response.status_code, 200)

        # Check that NO notifications appear in context
        notifications = response.context["notifications"]
        self.assertEqual(len(notifications), 0)

    def test_package_subscription_page_shows_valid_package(self) -> None:
        """Test that the package subscription page displays correctly for valid packages"""
        url = reverse(
            "webview:subscriptions:package", kwargs={"package_name": "firefox"}
        )
        response = self.client.get(url)

        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "subscriptions/package_subscription.html")

        # Check context
        self.assertEqual(response.context["package_name"], "firefox")
        self.assertTrue(response.context["package_exists"])
        self.assertFalse(response.context["is_subscribed"])
        self.assertIsNone(response.context["error_message"])

    def test_package_subscription_page_shows_invalid_package(self) -> None:
        """Test that the package subscription page shows error for invalid packages"""
        url = reverse(
            "webview:subscriptions:package", kwargs={"package_name": "nonexistent"}
        )
        response = self.client.get(url)

        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "subscriptions/package_subscription.html")

        # Check context
        self.assertEqual(response.context["package_name"], "nonexistent")
        self.assertFalse(response.context["package_exists"])
        self.assertFalse(response.context["is_subscribed"])
        self.assertIsNotNone(response.context["error_message"])
        self.assertIn("does not exist", response.context["error_message"])

    def test_package_subscription_page_subscribe_action(self) -> None:
        """Test subscribing to a package via the package subscription page"""
        url = reverse(
            "webview:subscriptions:package", kwargs={"package_name": "firefox"}
        )
        response = self.client.post(url, {"action": "subscribe"})

        # Should redirect back to the same page
        self.assertEqual(response.status_code, 302)
        self.assertIn("firefox", response.url)

        # Follow redirect and check subscription status
        response = self.client.get(response.url)
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.context["is_subscribed"])

    def test_package_subscription_page_unsubscribe_action(self) -> None:
        """Test unsubscribing from a package via the package subscription page"""
        # First subscribe to the package
        self.user.profile.package_subscriptions.append("firefox")
        self.user.profile.save(update_fields=["package_subscriptions"])

        url = reverse(
            "webview:subscriptions:package", kwargs={"package_name": "firefox"}
        )

        # Verify initially subscribed
        response = self.client.get(url)
        self.assertTrue(response.context["is_subscribed"])

        # Unsubscribe
        response = self.client.post(url, {"action": "unsubscribe"})

        # Should redirect back to the same page
        self.assertEqual(response.status_code, 302)
        self.assertIn("firefox", response.url)

        # Follow redirect and check subscription status
        response = self.client.get(response.url)
        self.assertEqual(response.status_code, 200)
        self.assertFalse(response.context["is_subscribed"])


def test_maintainer_notification_many_packages_in_suggestion(
    make_suggestion: Callable[..., CVEDerivationClusterProposal],
    make_drv: Callable[..., NixDerivation],
    maintainer: NixMaintainer,
    make_user: Callable[..., User],
) -> None:
    """
    Check that many packages by one maintainer in a suggestion can be processed.
    """

    user = make_user(username=maintainer.github, uid=str(maintainer.github_id))
    drvs = {
        make_drv(
            attribute=f"package{i}", maintainer=maintainer
        ): ProvenanceFlags.PACKAGE_NAME_MATCH
        for i in range(100)
    }
    suggestion = make_suggestion(drvs=drvs)

    create_package_subscription_notifications(suggestion)

    notification = Notification.objects.first()
    assert notification
    assert notification.user == user
