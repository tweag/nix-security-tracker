"""
Persist the `ProductKey` rows `product_keys()` derives from affected products, so that
mappings, reverse matching and curation can find CVEs by product identity in SQL.
"""

from collections.abc import Iterable, Sequence

from django.db.models import Q

from shared.matching.view import KeySpec, ProductFields, product_keys
from shared.models.cve import AffectedProduct
from shared.models.matching import ProductKey

Through = AffectedProduct.product_keys.through


def get_or_create_keys(specs: Iterable[KeySpec]) -> dict[KeySpec, int]:
    """Primary keys of the given product keys, creating missing ones, in two or three queries."""
    wanted = {spec.capped() for spec in specs}
    if not wanted:
        return {}
    found = _lookup(wanted)
    missing = wanted - found.keys()
    if missing:
        ProductKey.objects.bulk_create(
            [
                ProductKey(kind=k.kind, vendor=k.vendor, product=k.product)
                for k in missing
            ],
            ignore_conflicts=True,
        )
        found |= _lookup(missing)
    return found


def _lookup(specs: set[KeySpec]) -> dict[KeySpec, int]:
    condition = Q()
    for spec in specs:
        condition |= Q(kind=spec.kind, vendor=spec.vendor, product=spec.product)
    return {
        KeySpec(kind, vendor, product): pk
        for pk, kind, vendor, product in ProductKey.objects.filter(
            condition
        ).values_list("pk", "kind", "vendor", "product")
    }


def keys_of(affected: Sequence[AffectedProduct]) -> dict[int, frozenset[KeySpec]]:
    """Derived keys per affected product pk; reads `cpes` through the prefetch cache when there is one."""
    return {row.pk: product_keys(ProductFields.of(row)) for row in affected}


def persist_product_keys(affected: Sequence[AffectedProduct]) -> int:
    """
    Attach the derived keys to each affected product, additively and idempotently.
    Returns the number of (affected product, key) links offered.
    """
    derived = keys_of(affected)
    ids = get_or_create_keys(spec for specs in derived.values() for spec in specs)
    links = [
        Through(affectedproduct_id=row, productkey_id=ids[spec])
        for row, specs in derived.items()
        for spec in specs
    ]
    created = Through.objects.bulk_create(links, ignore_conflicts=True)
    return len(created)


def stored_or_derived_keys(affected: Iterable[int]) -> dict[int, frozenset[KeySpec]]:
    """Keys per affected product pk: the persisted ones, or derived for rows without any (three queries)."""
    rows = AffectedProduct.objects.filter(pk__in=list(affected)).prefetch_related(
        "cpes", "product_keys"
    )
    result: dict[int, frozenset[KeySpec]] = {}
    for row in rows:
        stored = frozenset(
            KeySpec(k.kind, k.vendor, k.product) for k in row.product_keys.all()
        )
        result[row.pk] = stored or product_keys(ProductFields.of(row))
    return result
