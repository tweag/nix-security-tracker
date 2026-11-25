from collections.abc import Callable
from typing import Any

import pytest
from django.db import connection
from django.test.utils import CaptureQueriesContext

from shared.matching.view import (
    KeySpec,
    ProductFields,
    build_cve_view,
    build_cve_views,
    name_terms,
    parse_cpe,
    product_keys,
)
from shared.models.cve import AffectedProduct, Container, Cpe, Organization, Tag

AddContainer = Callable[..., Container]


@pytest.fixture
def add_container(db: None) -> AddContainer:
    """Add a container with the given affected products (dicts of `AffectedProduct` fields plus `cpes`) to a CVE."""

    def wrapped(
        container: Container,
        affected: list[dict[str, Any]],
        kind: str = Container.Type.ADP,
        tags: list[str] = [],
    ) -> Container:
        org, _ = Organization.objects.get_or_create(uuid=2, short_name="CISA-ADP")
        new = container.cve.container.create(provider=org, _type=kind)
        for fields in affected:
            fields = dict(fields)
            cpes = fields.pop("cpes", [])
            product = AffectedProduct.objects.create(**fields)
            for name in cpes:
                product.cpes.add(Cpe.objects.get_or_create(name=name)[0])
            new.affected.add(product)
        for tag in tags:
            new.tags.add(Tag.objects.get_or_create(value=tag)[0])
        return new

    return wrapped


def test_view_unions_containers(
    make_container: Callable[..., Container], add_container: AddContainer
) -> None:
    cna = make_container(package_name=None, product="widget")
    add_container(
        cna,
        [
            # Same product as the CNA's: merged, CPEs added.
            {"product": "Widget", "cpes": ["cpe:2.3:a:acme:widget:*:*:*:*:*:*:*:*"]},
            {"vendor": "acme", "product": "gadget"},
        ],
    )

    view = build_cve_view(cna.cve)

    assert len(view.products) == 2
    widget = next(p for p in view.products if p.fields.product == "widget")
    assert widget.containers == ("adp", "cna")
    assert widget.container == "cna"
    assert len(widget.sources) == 2
    assert widget.cpe_pairs == {("acme", "widget")}
    assert KeySpec("cpe", "acme", "widget") in widget.keys
    gadget = next(p for p in view.products if p.fields.product == "gadget")
    assert gadget.containers == ("adp",)


def test_view_screens(
    make_container: Callable[..., Container], add_container: AddContainer
) -> None:
    cna = make_container(
        package_name=None,
        product="router",
        cpes=["cpe:2.3:h:acme:router:-:*:*:*:*:*:*:*"],
    )
    view = build_cve_view(cna.cve)
    assert view.hardware_only
    assert view.matchable == ()
    assert not view.exclusively_hosted_service

    add_container(
        cna,
        [{"product": "router firmware", "cpes": ["cpe:2.3:o:acme:fw:*:*:*:*:*:*:*:*"]}],
        tags=["exclusively-hosted-service"],
    )
    view = build_cve_view(cna.cve)
    assert not view.hardware_only
    assert [p.fields.product for p in view.matchable] == ["router firmware"]
    assert view.exclusively_hosted_service


def test_view_queries_are_bounded(
    make_container: Callable[..., Container], add_container: AddContainer
) -> None:
    containers = [
        make_container(
            cve_id=f"CVE-2025-000{i}", cpes=[f"cpe:2.3:a:v:p{i}:*:*:*:*:*:*:*:*"]
        )
        for i in range(1, 4)
    ]
    for container in containers:
        add_container(container, [{"product": "x"}, {"product": "y"}])

    with CaptureQueriesContext(connection) as one:
        build_cve_view("CVE-2025-0001")
    with CaptureQueriesContext(connection) as many:
        views = build_cve_views([c.cve.cve_id for c in containers])

    assert len(views) == 3
    assert len(one) == len(many) == 8


def test_parse_cpe_is_cached() -> None:
    parse_cpe.cache_clear()
    for _ in range(3):
        parse_cpe("cpe:2.3:a:acme:widget:*:*:*:*:*:*:*:*")
    info = parse_cpe.cache_info()
    assert (info.misses, info.hits) == (1, 2)


def test_product_keys() -> None:
    keys = product_keys(
        ProductFields(
            vendor="Python Software Foundation",
            product="Requests",
            package_name="requests",
            collection_url="https://pypi.org",
            repo="https://github.com/psf/requests.git",
            cpes=(
                "cpe:2.3:a:python:requests:*:*:*:*:*:*:*:*",
                "cpe:2.3:h:acme:board:-:*:*:*:*:*:*:*",
            ),
        )
    )
    assert keys == {
        KeySpec("cpe", "python", "requests"),
        KeySpec("cna", "python software foundation", "requests"),
        KeySpec("purl", "pypi", "requests"),
        KeySpec("repo", "github.com/psf", "requests"),
    }
    assert product_keys(ProductFields(vendor="n/a", product="n/a")) == frozenset()
    assert product_keys(ProductFields(product="tool", package_name="tool-cli")) == {
        KeySpec("cna", "", "tool"),
        KeySpec("cna", "", "tool-cli"),
    }


def test_name_terms() -> None:
    terms = name_terms(
        ProductFields(
            vendor="Apache Software Foundation",
            product="Apache Tomcat",
            package_name="org.apache.tomcat:tomcat-catalina",
        )
    )
    assert [t.term for t in terms] == [
        "apache-tomcat",
        "tomcat",
        "org-apache-tomcat:tomcat-catalina",
        "tomcat-catalina",
    ]
    assert name_terms(ProductFields(product="n/a")) == ()
