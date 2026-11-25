from collections.abc import Callable
from io import StringIO

from django.core.management import call_command

from shared.identity.keys import persist_product_keys
from shared.identity.triage import (
    Learned,
    TriageCase,
    learn_triage_mappings,
    propose,
    sync_triage_mappings,
    variant_key,
)
from shared.models.cve import AffectedProduct, Container
from shared.models.linkage import CVEDerivationClusterProposal
from shared.models.matching import Match, ProductMapping, Verdict

OPENSSL = ("cna", "openssl", "openssl")
OPENSSL_CPE = ("cpe", "openssl", "openssl")
RHEL = ("cna", "red hat", "red hat enterprise linux 9")
TESLA = ("cna", "nvidia", "tesla")

Status = CVEDerivationClusterProposal.Status
Reason = CVEDerivationClusterProposal.RejectionReason


def published(
    cve: str,
    *products: frozenset[tuple[str, str, str]],
    kept: set[str],
    ignored: set[str] = set(),
) -> TriageCase:
    return TriageCase(
        suggestion=0,
        cve_id=cve,
        positive=True,
        products=tuple(products),
        proposed=frozenset(kept | ignored),
        kept=frozenset(kept),
        ignored=frozenset(ignored),
    )


def rejected(
    cve: str, *products: frozenset[tuple[str, str, str]], proposed: set[str]
) -> TriageCase:
    return TriageCase(
        suggestion=0,
        cve_id=cve,
        positive=False,
        products=tuple(products),
        proposed=frozenset(proposed),
    )


def learned(result: Learned) -> set[tuple[tuple[str, str, str], str, str | None]]:
    return {(p.key, p.relation, p.attrpath) for p in result.proposals}


def test_one_product_learns_same_for_all_its_keys() -> None:
    case = published("CVE-1", frozenset({OPENSSL, OPENSSL_CPE}), kept={"openssl"})
    assert learned(propose([case])) == {
        (OPENSSL, "same", "openssl"),
        (OPENSSL_CPE, "same", "openssl"),
    }


def test_variants_are_all_mapped_and_ignored_variants_are_no_negative() -> None:
    pnames = {"openssl": "openssl", "openssl_3": "openssl", "openssl_1_1": "openssl"}
    case = published(
        "CVE-1",
        frozenset({OPENSSL}),
        kept={"openssl", "openssl_3"},
        ignored={"openssl_1_1", "libressl"},
    )
    other = published(
        "CVE-2", frozenset({OPENSSL}), kept={"openssl"}, ignored={"libressl"}
    )
    result = propose([case, other], pnames)
    assert learned(result) == {
        (OPENSSL, "same", "openssl"),
        (OPENSSL, "same", "openssl_3"),
        (OPENSSL, "not_same", "libressl"),
    }
    # The ignored variant is a version choice, not evidence against `openssl_1_1`.
    assert result.conflicts == []


def test_variant_key_without_pname() -> None:
    assert variant_key("openssl_1_1", {}) == "openssl"
    assert variant_key("python313Packages.requests", {}) == "requests"
    assert variant_key("libsoup_3", {}) == "libsoup"


def test_ambiguous_cases_learn_nothing() -> None:
    # Two products, each with one key of the same kind: neither is unambiguous.
    two_products = published(
        "CVE-1",
        frozenset({OPENSSL}),
        frozenset({("cna", "openssl", "libcrypto")}),
        kept={"openssl"},
    )
    # A key kept in one case and ruled out in another: a conflict, not a rule.
    kept_once = published("CVE-2", frozenset({TESLA}), kept={"teslajsonpy"})
    ruled_out = rejected("CVE-3", frozenset({TESLA}), proposed={"teslajsonpy"})
    result = propose([two_products, kept_once, ruled_out])
    assert result.proposals == []
    assert result.conflicts == [(TESLA, "teslajsonpy")]


def test_only_key_of_its_kind_is_unambiguous() -> None:
    case = published(
        "CVE-1",
        frozenset({("cna", "x", "a"), OPENSSL_CPE}),
        frozenset({("cna", "x", "b")}),
        kept={"openssl"},
    )
    assert learned(propose([case])) == {(OPENSSL_CPE, "same", "openssl")}


def test_not_same_needs_repetition_and_no_kept_evidence() -> None:
    once = rejected("CVE-1", frozenset({TESLA}), proposed={"teslajsonpy"})
    assert propose([once]).proposals == []

    twice = rejected(
        "CVE-2", frozenset({TESLA}), frozenset({RHEL}), proposed={"teslajsonpy"}
    )
    result = propose([once, twice])
    assert learned(result) == {(TESLA, "not_same", "teslajsonpy")}
    assert result.proposals[0].support == ("CVE-1", "CVE-2")
    # Kept anywhere with that key, even ambiguously: no veto.
    kept = published(
        "CVE-3", frozenset({TESLA}), frozenset({RHEL}), kept={"teslajsonpy"}
    )
    result = propose([once, twice, kept])
    assert result.proposals == []
    assert result.conflicts == [(TESLA, "teslajsonpy"), (RHEL, "teslajsonpy")]


def test_irrelevant_is_opt_in() -> None:
    cases = [
        rejected(f"CVE-{i}", frozenset({TESLA}), proposed={f"a{i}"}) for i in range(2)
    ]
    assert propose(cases).proposals == []
    assert learned(propose(cases, min_irrelevant=2)) == {(TESLA, "irrelevant", None)}


def test_learn_from_database(
    make_container: Callable[..., Container],
    make_suggestion: Callable[..., CVEDerivationClusterProposal],
) -> None:
    def suggestion(cve_id: str, **fields: object) -> CVEDerivationClusterProposal:
        container = make_container(cve_id=cve_id, package_name=None, product="Widget")
        AffectedProduct.objects.filter(pk=container.affected.get().pk).update(
            vendor="acme"
        )
        return make_suggestion(container=container, drvs={}, **fields)

    pub = suggestion("CVE-2025-1001", status=Status.PUBLISHED)
    for attrpath in ("widget", "widget-gtk"):
        Match.objects.create(
            suggestion=pub,
            attrpath=attrpath,
            matcher="legacy",
            matcher_version=2,
            score=1,
        )
    Verdict.objects.create(suggestion=pub, attrpath="widget-gtk", verdict="irrelevant")
    for i in (2, 3):
        rej = suggestion(
            f"CVE-2025-100{i}",
            status=Status.REJECTED,
            rejection_reason=Reason.NOT_IN_NIXPKGS,
        )
        Match.objects.create(
            suggestion=rej,
            attrpath="widget-gtk",
            matcher="legacy",
            matcher_version=2,
            score=1,
        )
    # Pending suggestions are no label.
    suggestion("CVE-2025-1004")
    persist_product_keys(list(AffectedProduct.objects.all()))

    result = learn_triage_mappings()
    assert set(
        ProductMapping.objects.values_list(
            "product_key__product", "relation", "attrpath", "source"
        )
    ) == {
        ("widget", "same", "widget", "triage"),
        ("widget", "not_same", "widget-gtk", "triage"),
    }
    assert (
        "CVE-2025-1002, CVE-2025-1003"
        in ProductMapping.objects.get(relation="not_same").comment
    )

    # Relearning is idempotent; a curated mapping on the same target wins.
    again = sync_triage_mappings(result.learned)
    assert again.changed == [] and again.overridden == 0
    same = ProductMapping.objects.get(relation="same")
    ProductMapping.objects.create(
        product_key=same.product_key,
        attrpath="widget",
        relation="not_same",
        source="curated",
    )
    out = StringIO()
    call_command("learn_triage_mappings", stdout=out)
    assert "1 deleted, 1 overridden" in out.getvalue()
    assert not ProductMapping.objects.filter(source="triage", relation="same").exists()
