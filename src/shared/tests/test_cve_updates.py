import copy
from typing import Any

import pytest
from django.db import connection
from django.test.utils import CaptureQueriesContext
from pgpubsub.models import Notification

from shared.channels import CveUpdateChannel
from shared.fetchers import find_cve_record, make_cve, reconcile_cve
from shared.listeners.automatic_linkage import build_new_links
from shared.models.cve import (
    AffectedProduct,
    Container,
    CpeApplicability,
    CveRecord,
    Description,
    Reference,
    Version,
)
from shared.models.linkage import CVEDerivationClusterProposal

CNA_ORG = "11111111-1111-1111-1111-111111111111"
CISA_ORG = "134c704f-9b21-4f2e-91b3-4a467353bcc0"
CVE_ID = "CVE-2026-1234"


def product(
    product: str = "foo",
    vendor: str = "acme",
    less_than: str = "1.2",
    cpes: list[str] | None = None,
) -> dict[str, Any]:
    entry: dict[str, Any] = {
        "vendor": vendor,
        "product": product,
        "defaultStatus": "unaffected",
        "versions": [
            {
                "version": "0",
                "lessThan": less_than,
                "status": "affected",
                "versionType": "semver",
            }
        ],
    }
    if cpes is not None:
        entry["cpes"] = cpes
    return entry


def cisa_adp(
    affected: list[dict[str, Any]] | None = None, timestamp: str = "2026-09-02"
) -> dict[str, Any]:
    adp: dict[str, Any] = {
        "title": "CISA ADP Vulnrichment",
        "providerMetadata": {
            "orgId": CISA_ORG,
            "shortName": "CISA-ADP",
            "dateUpdated": f"{timestamp}T10:00:00.000Z",
        },
        "metrics": [
            {
                "other": {
                    "type": "ssvc",
                    "content": {
                        "timestamp": f"{timestamp}T09:59:59.123456Z",
                        "id": CVE_ID,
                        "options": [{"Exploitation": "none"}],
                        "role": "CISA Coordinator",
                        "version": "2.0.3",
                    },
                }
            }
        ],
    }
    if affected is not None:
        adp["affected"] = affected
    return adp


def record(
    affected: list[dict[str, Any]] | None = None,
    adp: list[dict[str, Any]] | None = None,
    title: str = "Overflow in foo",
    updated: str = "2026-09-01T00:00:00.000Z",
) -> dict[str, Any]:
    data: dict[str, Any] = {
        "dataType": "CVE_RECORD",
        "dataVersion": "5.1",
        "cveMetadata": {
            "cveId": CVE_ID,
            "assignerOrgId": CNA_ORG,
            "assignerShortName": "acme",
            "state": "PUBLISHED",
            "dateReserved": "2026-08-01T00:00:00.000Z",
            "datePublished": "2026-09-01T00:00:00.000Z",
            "dateUpdated": updated,
        },
        "containers": {
            "cna": {
                "title": title,
                "providerMetadata": {
                    "orgId": CNA_ORG,
                    "shortName": "acme",
                    "dateUpdated": updated,
                },
                "descriptions": [{"lang": "en", "value": "A buffer overflow."}],
                "affected": [product()] if affected is None else affected,
                "references": [{"url": "https://example.org/advisory"}],
                "metrics": [
                    {
                        "cvssV3_1": {
                            "version": "3.1",
                            "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                        }
                    }
                ],
            }
        },
    }
    if adp is not None:
        data["containers"]["adp"] = adp
    return data


def updates_notified() -> int:
    return Notification.objects.filter(
        channel=CveUpdateChannel.listen_safe_name()
    ).count()


def products(cve: CveRecord) -> list[AffectedProduct]:
    return list(
        AffectedProduct.objects.filter(container__cve=cve).order_by("pk").distinct()
    )


def writes(ctx: CaptureQueriesContext) -> list[str]:
    return [
        q["sql"]
        for q in ctx.captured_queries
        if q["sql"].split()[0].upper() in ("INSERT", "UPDATE", "DELETE")
    ]


def test_noop_update_writes_nothing(db: None) -> None:
    data = record(adp=[cisa_adp()])
    cve = make_cve(data)
    notifications = Notification.objects.count()

    with CaptureQueriesContext(connection) as ctx:
        assert make_cve(copy.deepcopy(data)) == cve

    assert len(ctx.captured_queries) == 1
    assert writes(ctx) == []
    assert Notification.objects.count() == notifications


def test_timestamp_churn_is_noop(db: None) -> None:
    cve = make_cve(record(adp=[cisa_adp()]))
    notifications = Notification.objects.count()
    churned = record(
        adp=[cisa_adp(timestamp="2026-11-24")], updated="2026-11-24T08:00:00.654321Z"
    )

    with CaptureQueriesContext(connection) as ctx:
        result = reconcile_cve(cve, churned)

    assert not result.changed
    assert writes(ctx) == []
    assert Notification.objects.count() == notifications


def test_late_adp_with_cpes_is_added_and_notifies(db: None) -> None:
    cve = make_cve(record())
    cna_product = products(cve)[0]
    cpe = "cpe:2.3:a:acme:foo:*:*:*:*:*:*:*:*"

    result = reconcile_cve(cve, record(adp=[cisa_adp(affected=[product(cpes=[cpe])])]))

    assert result.containers_added == 1
    assert result.matching_changed
    adp = cve.container.get(_type=Container.Type.ADP)
    assert list(adp.affected.values_list("cpes__name", flat=True)) == [cpe]
    assert products(cve)[0].pk == cna_product.pk
    assert updates_notified() == 1


def test_late_adp_with_only_metrics_does_not_notify(db: None) -> None:
    cve = make_cve(record())

    result = reconcile_cve(cve, record(adp=[cisa_adp()]))

    assert result.containers_added == 1
    assert not result.matching_changed
    assert updates_notified() == 0


def test_changed_version_range_updates_in_place(db: None) -> None:
    cve = make_cve(record(affected=[product("foo"), product("bar")]))
    foo, bar = products(cve)
    old_version = foo.versions.get()

    result = reconcile_cve(
        cve, record(affected=[product("foo", less_than="1.3"), product("bar")])
    )

    assert (result.products_updated, result.products_unchanged) == (1, 1)
    assert [p.pk for p in products(cve)] == [foo.pk, bar.pk]
    assert foo.versions.get().less_than == "1.3"
    assert not Version.objects.filter(pk=old_version.pk).exists()
    assert updates_notified() == 1


def test_identity_ignores_case_and_whitespace(db: None) -> None:
    cve = make_cve(record(affected=[product("foo")]))
    foo = products(cve)[0]

    reconcile_cve(cve, record(affected=[product(" Foo")]))

    foo.refresh_from_db()
    assert [p.pk for p in products(cve)] == [foo.pk]
    assert foo.product == " Foo"


def test_products_with_one_identity_keep_their_rows(db: None) -> None:
    cve = make_cve(
        record(affected=[product(less_than="1.0"), product(less_than="2.0")])
    )
    first, second = products(cve)

    # The first entry was dropped: the second one keeps its row, the first row goes.
    reconcile_cve(cve, record(affected=[product(less_than="2.0")]))

    assert [p.pk for p in products(cve)] == [second.pk]


def test_product_removed(db: None) -> None:
    cve = make_cve(record(affected=[product("foo"), product("bar")]))
    foo, bar = products(cve)
    bar_version = bar.versions.get().pk

    result = reconcile_cve(cve, record(affected=[product("foo")]))

    assert result.products_removed == 1
    assert [p.pk for p in products(cve)] == [foo.pk]
    assert not AffectedProduct.objects.filter(pk=bar.pk).exists()
    assert not Version.objects.filter(pk=bar_version).exists()
    assert updates_notified() == 1


def test_container_removed(db: None) -> None:
    cpe = "cpe:2.3:a:acme:foo:*:*:*:*:*:*:*:*"
    cve = make_cve(record(adp=[cisa_adp(affected=[product(cpes=[cpe])])]))
    adp = cve.container.get(_type=Container.Type.ADP)
    adp_product = adp.affected.get()

    result = reconcile_cve(cve, record())

    assert result.containers_removed == 1
    assert not Container.objects.filter(pk=adp.pk).exists()
    assert not AffectedProduct.objects.filter(pk=adp_product.pk).exists()
    assert updates_notified() == 1


def test_presentation_change_does_not_notify(db: None) -> None:
    cve = make_cve(record())
    cna = cve.container.get()
    foo = products(cve)[0]
    old_reference = cna.references.get().pk
    data = record(title="Heap overflow in foo")
    data["containers"]["cna"]["references"] = [{"url": "https://example.org/fix"}]

    result = reconcile_cve(cve, data)

    assert result.containers_updated == 1
    assert not result.matching_changed
    cna.refresh_from_db()
    assert cna.title == "Heap overflow in foo"
    assert list(cna.references.values_list("url", flat=True)) == [
        "https://example.org/fix"
    ]
    assert not Reference.objects.filter(pk=old_reference).exists()
    assert Description.objects.count() == 1
    assert [p.pk for p in products(cve)] == [foo.pk]
    assert updates_notified() == 0


def test_hosted_service_tag_notifies(db: None) -> None:
    cve = make_cve(record())
    data = record()
    data["containers"]["cna"]["tags"] = ["exclusively-hosted-service"]

    assert reconcile_cve(cve, data).matching_changed
    assert updates_notified() == 1


def test_rejected_cve(db: None) -> None:
    cve = make_cve(record(adp=[cisa_adp()]))
    rejected = {
        "dataType": "CVE_RECORD",
        "dataVersion": "5.1",
        "cveMetadata": {
            "cveId": CVE_ID,
            "assignerOrgId": CNA_ORG,
            "state": "REJECTED",
            "dateReserved": "2026-08-01T00:00:00.000Z",
            "dateRejected": "2026-10-01T00:00:00.000Z",
            "dateUpdated": "2026-10-01T00:00:00.000Z",
        },
        "containers": {
            "cna": {
                "providerMetadata": {
                    "orgId": CNA_ORG,
                    "dateUpdated": "2026-10-01T00:00:00.000Z",
                },
                "rejectedReasons": [
                    {"lang": "en", "value": "This CVE ID is a duplicate."}
                ],
            }
        },
    }

    result = reconcile_cve(cve, rejected)

    assert cve.state == CveRecord.RecordState.REJECTED
    assert (result.containers_updated, result.containers_removed) == (1, 1)
    assert result.products_removed == 1
    assert products(cve) == []
    assert cve.container.get().descriptions.count() == 0
    assert updates_notified() == 1


def test_update_creates_no_suggestion(db: None) -> None:
    cve = make_cve(record())
    assert build_new_links(cve.container.get())
    suggestion = CVEDerivationClusterProposal.objects.get(cve=cve)
    # A suggestion from before an algorithm bump does not count for `build_new_links`.
    CVEDerivationClusterProposal.objects.filter(pk=suggestion.pk).update(
        algorithm_version=0
    )
    container_notifications = Notification.objects.exclude(
        channel=CveUpdateChannel.listen_safe_name()
    ).count()

    reconcile_cve(cve, record(adp=[cisa_adp(affected=[product("bar")])]))

    # The insert trigger did not ask for a suggestion for the new container.
    assert (
        Notification.objects.exclude(
            channel=CveUpdateChannel.listen_safe_name()
        ).count()
        == container_notifications
    )
    assert CVEDerivationClusterProposal.objects.filter(cve=cve).count() == 1
    assert updates_notified() == 1


def test_new_cve_still_asks_for_a_suggestion(db: None) -> None:
    before = Notification.objects.count()
    make_cve(record(adp=[cisa_adp()]))
    assert Notification.objects.count() == before + 2


def test_rows_without_hash_are_reconciled_once(db: None) -> None:
    data = record(affected=[product("foo"), product("bar")])
    cve = make_cve(data)
    pks = [p.pk for p in products(cve)]
    CveRecord.objects.update(content_hash=None)
    Container.objects.update(content_hash=None)
    AffectedProduct.objects.update(content_hash=None)
    cve.refresh_from_db()

    result = reconcile_cve(cve, data)

    assert result.changed and result.products_updated == 2
    assert not result.matching_changed
    assert [p.pk for p in products(cve)] == pks
    assert updates_notified() == 0
    assert not reconcile_cve(cve, data).changed


@pytest.mark.parametrize("suggested", [None, 0, 1])
def test_duplicate_records(db: None, suggested: int | None) -> None:
    first = make_cve(record())
    # Past bulk ingestions created a second record for the same id.
    second = CveRecord.objects.get(pk=first.pk)
    second.pk = None
    second.content_hash = None
    second.save()
    make_cve(record(), record=second)
    records = [first, second]
    if suggested is not None:
        CVEDerivationClusterProposal.objects.create(cve=records[suggested])
    expected = records[suggested or 0]
    assert find_cve_record(CVE_ID) == expected

    make_cve(record(affected=[product(less_than="9")]))

    for r in records:
        bound = Version.objects.filter(affectedproduct__container__cve=r).get()
        assert bound.less_than == ("9" if r == expected else "1.2")


def applicability(*nodes: list[dict[str, Any]], operator: str | None = None) -> dict:
    config: dict[str, Any] = {
        "nodes": [
            {"operator": "OR", "negate": False, "cpeMatch": matches}
            for matches in nodes
        ]
    }
    if operator is not None:
        config["operator"] = operator
    return config


def with_applicability(*configs: dict[str, Any]) -> dict[str, Any]:
    data = record()
    data["containers"]["cna"]["cpeApplicability"] = list(configs)
    return data


FOO_CPE = "cpe:2.3:a:acme:foo:*:*:*:*:*:*:*:*"
BAR_CPE = "cpe:2.3:a:acme:bar:*:*:*:*:*:*:*:*"


def foo_range(end: str = "1.2") -> dict[str, Any]:
    return {
        "vulnerable": True,
        "criteria": FOO_CPE,
        "versionStartIncluding": "0",
        "versionEndExcluding": end,
    }


def test_cpe_applicability_is_parsed(db: None) -> None:
    data = with_applicability(
        applicability(
            [foo_range(), foo_range(), {"vulnerable": True, "criteria": "x"}]
        ),
        applicability(
            [{"vulnerable": True, "criteria": BAR_CPE}],
            [
                {
                    "vulnerable": False,
                    "criteria": "cpe:2.3:o:linux:linux_kernel:-:*:*:*:*:*:*:*",
                }
            ],
            operator="AND",
        ),
    )

    cve = make_cve(data)

    rows = CpeApplicability.objects.filter(container__cve=cve).order_by("pk")
    assert [
        (r.part, r.vendor, r.product, r.version, r.vulnerable, r.conjunctive)
        for r in rows
    ] == [
        ("a", "acme", "foo", "*", True, False),
        ("a", "acme", "bar", "*", True, True),
        ("o", "linux", "linux_kernel", "-", False, True),
    ]
    assert (rows[0].version_start_including, rows[0].version_end_excluding) == (
        "0",
        "1.2",
    )


def test_cpe_applicability_change_is_reconciled(db: None) -> None:
    cve = make_cve(
        with_applicability(
            applicability([foo_range(), {"vulnerable": True, "criteria": BAR_CPE}])
        )
    )
    bar = CpeApplicability.objects.get(product="bar")

    result = reconcile_cve(
        cve,
        with_applicability(
            applicability([foo_range("1.3"), {"vulnerable": True, "criteria": BAR_CPE}])
        ),
    )

    assert result.matching_changed
    assert CpeApplicability.objects.get(product="bar").pk == bar.pk
    assert CpeApplicability.objects.get(product="foo").version_end_excluding == "1.3"
    assert updates_notified() == 1


def test_cpe_applicability_arrives_on_legacy_rows(db: None) -> None:
    data = with_applicability(applicability([foo_range()]))
    cve = make_cve(data)
    CpeApplicability.objects.all().delete()
    CveRecord.objects.update(content_hash=None)
    Container.objects.update(content_hash=None)
    cve.refresh_from_db()

    result = reconcile_cve(cve, data)

    assert result.matching_changed
    assert CpeApplicability.objects.filter(container__cve=cve).count() == 1
    assert updates_notified() == 1
