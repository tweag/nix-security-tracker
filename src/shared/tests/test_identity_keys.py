from collections.abc import Callable
from io import StringIO

from django.core.management import call_command

from shared.fetchers import make_affected_product
from shared.identity.keys import persist_product_keys
from shared.matching.view import KEY_PRODUCT_BYTES, KeySpec, build_cve_view
from shared.models.cve import AffectedProduct, Container
from shared.models.matching import ProductKey


def keys(product: AffectedProduct) -> set[tuple[str, str, str]]:
    return set(product.product_keys.values_list("kind", "vendor", "product"))


def test_ingestion_attaches_keys(db: None) -> None:
    product = make_affected_product(
        {
            "vendor": "NVIDIA",
            "product": "GPU Display Driver",
            "cpes": ["cpe:2.3:a:nvidia:gpu_display_driver:*:*:*:*:*:*:*:*"],
            "repo": "https://github.com/NVIDIA/open-gpu-kernel-modules",
        }
    )
    assert keys(product) == {
        ("cpe", "nvidia", "gpu_display_driver"),
        ("cna", "nvidia", "gpu display driver"),
        ("repo", "github.com/nvidia", "open-gpu-kernel-modules"),
    }


def test_keys_are_shared_between_products(db: None) -> None:
    first = make_affected_product({"vendor": "acme", "product": "Widget"})
    second = make_affected_product({"vendor": "ACME ", "product": "widget"})
    assert keys(first) == keys(second) == {("cna", "acme", "widget")}
    assert ProductKey.objects.count() == 1


def test_absurdly_long_values_are_capped(db: None) -> None:
    long = "x" * 2000
    product = make_affected_product({"vendor": "acme", "product": long})
    [(kind, vendor, stored)] = keys(product)
    assert len(stored.encode()) == KEY_PRODUCT_BYTES
    # The view derives the same capped key, so lookups agree with storage.
    assert KeySpec(kind, vendor, stored) == KeySpec("cna", "acme", long).capped()


def test_multibyte_values_are_capped_on_a_character_boundary() -> None:
    capped = KeySpec("cna", "", "é" * 1000).capped()
    assert capped.product == "é" * (KEY_PRODUCT_BYTES // 2)


def test_persist_is_idempotent(db: None) -> None:
    product = AffectedProduct.objects.create(vendor="acme", product="widget")
    persist_product_keys([product])
    persist_product_keys([product])
    assert product.product_keys.count() == 1


def test_backfill(make_container: Callable[..., Container]) -> None:
    # The fixture creates rows directly, without ingestion.
    container = make_container(
        package_name="foo", product="bar", cpes=["cpe:2.3:a:v:p:*:*:*:*:*:*:*:*"]
    )
    product = container.affected.get()
    assert not product.product_keys.exists()

    out = StringIO()
    call_command("backfill_product_keys", "--batch-size", "1", stdout=out)
    assert "Processed 1 affected product(s)" in out.getvalue()
    assert keys(product) == {("cpe", "v", "p"), ("cna", "", "bar"), ("cna", "", "foo")}

    out = StringIO()
    call_command("backfill_product_keys", stdout=out)
    assert "Processed 0 affected product(s)" in out.getvalue()


def test_view_reads_persisted_keys(make_container: Callable[..., Container]) -> None:
    container = make_container(package_name="foo", product=None)
    product = container.affected.get()
    view = build_cve_view(container.cve)
    assert view.products[0].keys == {KeySpec("cna", "", "foo")}

    # Persisted keys win over derivation, e.g. when derivation has changed since ingestion.
    stored, _ = ProductKey.objects.get_or_create(kind="cna", vendor="", product="old")
    product.product_keys.add(stored)
    view = build_cve_view(container.cve)
    assert view.products[0].keys == {KeySpec("cna", "", "old")}
