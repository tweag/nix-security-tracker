import re
import uuid
from collections.abc import Callable

import pytest
from django.contrib.auth.models import User
from playwright.sync_api import Page, expect
from pytest_django.live_server_helper import LiveServer

from shared.derived_state import flush_derived_states, set_verdict
from shared.models.cve import AffectedProduct
from shared.models.linkage import CVEDerivationClusterProposal
from shared.models.matching import (
    Exposure,
    Match,
    SuggestionDerivedState,
    TrackerEvent,
    Verdict,
)
from shared.models.nix_evaluation import NixChannel, NixEvaluation

from .routes import SUGGESTION_DETAIL, SUGGESTION_LIST

POSSIBLY_FIXED = "/possibly-fixed"
Observed = Exposure.Observed


@pytest.fixture
def matched(
    cached_suggestion: CVEDerivationClusterProposal,
    channel: NixChannel,
    evaluation: NixEvaluation,
    make_match: Callable[..., Match],
    make_exposure: Callable[..., Exposure],
) -> CVEDerivationClusterProposal:
    """`foo` matched by name and observed affected on master; `bar` a low-confidence candidate."""
    product = AffectedProduct.objects.create(vendor="acme", product="foo")
    make_match(
        "foo",
        "name-exact",
        1.0,
        evidence={
            "affected_product": product.pk,
            "container": "cna",
            "cve_field": "product",
            "cve_value": "foo",
            "pkg_field": "pname",
            "pkg_value": "foo",
            "branches": ["master"],
        },
    )
    make_match("bar", "name-substring", 0.5)
    make_exposure(
        "foo",
        version="1.2.3",
        detail={"detail": "1.2.3 in [1.0, 2.0)"},
        first_affected_evaluation=evaluation,
    )
    refresh_stored_states()
    return cached_suggestion


def refresh_stored_states() -> None:
    """The factories write rows directly, without the events that mark states stale."""
    SuggestionDerivedState.objects.update(stale=True)
    flush_derived_states()


def open_panel(page: Page, url: str, suggestion: CVEDerivationClusterProposal) -> None:
    page.goto(url + SUGGESTION_DETAIL + f"/{suggestion.pk}")
    page.get_by_test_id(f"suggestion-{suggestion.pk}-matching-toggle").click()
    expect(page.get_by_test_id(f"suggestion-{suggestion.pk}-matching")).to_be_visible()


@pytest.mark.django_db
def test_matching_panel_shows_candidates_and_evidence(
    live_server: LiveServer,
    page: Page,
    matched: CVEDerivationClusterProposal,
) -> None:
    open_panel(page, live_server.url, matched)
    row = page.get_by_test_id("matching-attribute-foo")
    expect(row).to_be_visible()
    expect(page.get_by_test_id("status-foo-master")).to_have_text(
        re.compile("affected")
    )
    # The low-confidence candidate is folded away.
    expect(page.get_by_test_id("matching-attribute-bar")).to_be_hidden()
    page.get_by_test_id(f"suggestion-{matched.pk}-matching-low-toggle").click()
    expect(page.get_by_test_id("matching-attribute-bar")).to_be_visible()
    # Evidence expands from the provenance chip.
    page.get_by_test_id("provenance-foo-name-exact").click()
    evidence = page.get_by_test_id("evidence-foo")
    expect(evidence).to_contain_text("CVE product foo")
    expect(evidence).to_contain_text("acme/foo")
    # Anonymous visitors get no verdict menus.
    expect(page.get_by_test_id("verdict-menu-foo-master")).to_be_hidden()


@pytest.mark.django_db
def test_committer_sets_and_clears_a_verdict(
    live_server: LiveServer,
    as_committer: Page,
    matched: CVEDerivationClusterProposal,
) -> None:
    open_panel(as_committer, live_server.url, matched)
    as_committer.get_by_test_id("verdict-menu-foo-master").click()
    as_committer.get_by_role("menuitem", name="not affected").click()
    status = as_committer.get_by_test_id("status-foo-master")
    expect(status).to_have_text(re.compile("not affected"))
    expect(status).to_have_attribute("aria-label", re.compile(r"\(verdict\)"))
    expect(as_committer.get_by_test_id("matching-attribute-foo")).to_contain_text(
        "observed affected"
    )
    verdict = Verdict.objects.get()
    assert (verdict.attrpath, verdict.branch_id, verdict.verdict) == (
        "foo",
        "master",
        "not_affected",
    )

    as_committer.get_by_test_id("verdict-menu-foo-master").click()
    as_committer.get_by_role("menuitem", name="Clear verdict on master").click()
    expect(status).to_have_attribute("aria-label", re.compile(r"\(observed\)"))
    as_committer.wait_for_load_state("networkidle")
    assert not Verdict.objects.exists()


@pytest.mark.django_db
def test_derived_state_badge_and_filter(
    live_server: LiveServer,
    page: Page,
    matched: CVEDerivationClusterProposal,
    make_cached_suggestion: Callable[..., CVEDerivationClusterProposal],
    make_container: Callable[..., object],
) -> None:
    other = make_cached_suggestion(container=make_container(cve_id="CVE-2026-9999"))
    refresh_stored_states()
    page.goto(live_server.url + SUGGESTION_LIST)
    expect(page.get_by_test_id(f"suggestion-{matched.pk}-derived-state")).to_have_text(
        "Needs triage"
    )
    expect(page.get_by_test_id(f"suggestion-{other.pk}-derived-state")).to_have_text(
        "No candidates"
    )
    page.get_by_test_id("derived-state-filter").get_by_text("Needs triage").click()
    expect(page).to_have_url(re.compile("derived_state=needs_triage"))
    expect(page.get_by_test_id(f"suggestion-{other.pk}")).to_be_hidden()
    expect(page.get_by_test_id(f"suggestion-{matched.pk}")).to_be_visible()


@pytest.fixture
def possibly_fixed(
    matched: CVEDerivationClusterProposal,
    make_evaluation: Callable[..., NixEvaluation],
    evaluation: NixEvaluation,
) -> Exposure:
    fixed = make_evaluation()
    exposure = Exposure.objects.get(attrpath="foo")
    exposure.observed = Observed.UNAFFECTED
    exposure.version = "2.0.1"
    exposure.last_affected_evaluation = evaluation
    exposure.fixed_evaluation = fixed
    exposure.detail = {"last_affected_version": "1.2.3"}
    exposure.save()
    refresh_stored_states()
    return exposure


@pytest.mark.django_db
def test_possibly_fixed_queue(
    live_server: LiveServer,
    page: Page,
    possibly_fixed: Exposure,
) -> None:
    page.goto(live_server.url + POSSIBLY_FIXED)
    row = page.get_by_test_id(f"possibly-fixed-{possibly_fixed.pk}")
    expect(row).to_contain_text("foo")
    expect(row).to_contain_text("1.2.3")
    expect(row).to_contain_text("2.0.1")
    expect(row.get_by_role("link", name=re.compile(r"\.\.\.|…"))).to_have_attribute(
        "href", re.compile("compare")
    )
    expect(page.get_by_role("button", name="Confirm fixed")).to_be_hidden()
    page.get_by_test_id("possibly-fixed-branch-filter").get_by_text(
        "master (1)"
    ).click()
    expect(page).to_have_url(re.compile("branch=master"))
    expect(row).to_be_visible()


@pytest.mark.django_db
@pytest.mark.parametrize("action", ["still_affected", "confirm_fixed"])
def test_possibly_fixed_actions_remove_the_row(
    live_server: LiveServer,
    as_committer: Page,
    possibly_fixed: Exposure,
    action: str,
) -> None:
    as_committer.goto(live_server.url + POSSIBLY_FIXED)
    row = as_committer.get_by_test_id(f"possibly-fixed-{possibly_fixed.pk}")
    expect(row).to_be_visible()
    if action == "still_affected":
        row.get_by_role("button", name="Still affected").click()
    else:
        row.get_by_role("button", name="Confirm fixed").click()
        as_committer.get_by_label("Fix commit (optional)").fill("a" * 40)
        as_committer.get_by_role("button", name="Confirm", exact=True).click()
    expect(row).to_be_hidden()
    expect(as_committer.get_by_text("Nothing to confirm.")).to_be_visible()
    verdict = Verdict.objects.get()
    assert verdict.verdict == ("affected" if action == "still_affected" else "fixed")
    if action == "confirm_fixed":
        assert verdict.fix_commit == "a" * 40


@pytest.mark.django_db
def test_tracker_entry_in_activity_log(
    live_server: LiveServer,
    page: Page,
    matched: CVEDerivationClusterProposal,
) -> None:
    batch = uuid.uuid4()
    for attr in ("foo", "baz"):
        TrackerEvent.objects.create(
            suggestion=matched,
            kind=TrackerEvent.Kind.MATCH_ADDED,
            attrpath=attr,
            matcher="name-trigram",
            cause=TrackerEvent.Cause.MATCHER,
            data={"score": 0.8, "evidence": {"similarity": 0.8}},
            batch=batch,
        )
    TrackerEvent.objects.create(
        suggestion=matched,
        kind=TrackerEvent.Kind.EXPOSURE_BECAME_UNAFFECTED,
        attrpath="foo",
        branch_id="master",
        cause=TrackerEvent.Cause.EVALUATION,
        data={
            "old_version": "1.2.3",
            "new_version": "1.2.5",
            "old_status": "affected",
            "new_status": "unaffected",
            "new_reason": "version_range",
        },
        batch=uuid.uuid4(),
    )
    page.goto(live_server.url + SUGGESTION_DETAIL + f"/{matched.pk}")
    page.get_by_test_id(f"suggestion-{matched.pk}-activity-log-toggle").click()
    log = page.get_by_test_id(f"suggestion-{matched.pk}-activity-log")
    expect(log).to_contain_text("+2 packages via name ≈")
    expect(log).to_contain_text(
        "foo on master: 1.2.3 → 1.2.5, now outside the affected range"
    )
    log.get_by_role("button", name=re.compile(r"\+2 packages")).click()
    expect(log).to_contain_text("+ baz via name ≈ 0.80")


@pytest.mark.django_db
def test_possibly_fixed_answer_to_a_stale_row(
    live_server: LiveServer,
    as_committer: Page,
    possibly_fixed: Exposure,
    staff: User,
) -> None:
    """Someone else answered the row meanwhile: a warning, and the row stays gone."""
    as_committer.goto(live_server.url + POSSIBLY_FIXED)
    row = as_committer.get_by_test_id(f"possibly-fixed-{possibly_fixed.pk}")
    expect(row).to_be_visible()
    set_verdict(
        possibly_fixed.suggestion,
        "foo",
        Verdict.Kind.FIXED,
        staff,
        branch=possibly_fixed.branch,
    )
    row.get_by_role("button", name="Still affected").click()
    expect(as_committer.get_by_text("Already answered")).to_be_visible()
    expect(row).to_be_hidden()
    assert Verdict.objects.get().author == staff


@pytest.mark.django_db
def test_matching_panel_follows_accept_and_ignore(
    live_server: LiveServer,
    as_committer: Page,
    matched: CVEDerivationClusterProposal,
) -> None:
    """Accepting records verdicts and ignoring writes one: the open panel shows both."""
    open_panel(as_committer, live_server.url, matched)
    status = as_committer.get_by_test_id("status-foo-master")
    expect(status).to_have_attribute("aria-label", re.compile(r"\(observed\)"))
    as_committer.get_by_role("button", name="Accept").click()
    expect(status).to_have_attribute("aria-label", re.compile(r"affected \(verdict\)"))
    packages = as_committer.get_by_test_id(f"suggestion-{matched.pk}-packages")
    packages.get_by_role("button", name="Ignore", exact=True).click()
    expect(status).to_have_attribute(
        "aria-label", re.compile(r"irrelevant \(verdict\)")
    )
