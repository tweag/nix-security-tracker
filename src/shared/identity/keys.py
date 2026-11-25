"""
Persist the `ProductKey` rows `product_keys()` derives from affected products, so that
mappings, reverse matching and curation can find CVEs by product identity in SQL.
"""

from collections.abc import Iterable, Mapping, Sequence

from django.db.models import Q

from shared.matching.view import (
    KeySpec,
    ProductFields,
    applicability_pairs,
    attribute_applicability,
    cpe_pair_keys,
    product_keys,
)
from shared.models.cve import AffectedProduct, Container
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


def persist_product_keys(
    affected: Sequence[AffectedProduct], *, replace: bool = False
) -> int:
    """
    Attach the derived keys to each affected product, idempotently. With `replace`, also drop
    links derivation no longer produces (after a change to `product_keys`); keys from another
    source attached through `attach_product_keys` would have to be re-attached afterwards.
    Returns the number of (affected product, key) links offered.
    """
    derived = keys_of(affected)
    offered = attach_product_keys(derived)
    if replace:
        ids = get_or_create_keys(spec for specs in derived.values() for spec in specs)
        stale = Q()
        for row, specs in derived.items():
            stale |= Q(affectedproduct_id=row) & ~Q(
                productkey_id__in=[ids[spec.capped()] for spec in specs]
            )
        Through.objects.filter(stale).delete()
    return offered


def attach_product_keys(links: Mapping[int, Iterable[KeySpec]]) -> int:
    """
    Link affected products (by pk) to these keys, creating missing keys; additive and
    idempotent. A second source of keys (e.g. container-level `cpeApplicability` pairs via
    `cpe_pair_keys`) attaches through here.
    """
    wanted = {row: {spec.capped() for spec in specs} for row, specs in links.items()}
    ids = get_or_create_keys(spec for specs in wanted.values() for spec in specs)
    rows = [
        Through(affectedproduct_id=row, productkey_id=ids[spec])
        for row, specs in wanted.items()
        for spec in specs
    ]
    return len(Through.objects.bulk_create(rows, ignore_conflicts=True))


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


def attach_applicability_keys(containers: Iterable[Container]) -> int:
    """
    Attach the `cpe` keys of each container's `cpeApplicability` pairs to the affected
    products `attribute_applicability` assigns them to, so reverse matching and mappings find
    the CVE by them. Pairs no affected product claims stay unindexed: they reach the matchers
    through `CveView` only. Additive; a criterion removed later leaves its key link behind.
    """
    links: dict[int, set[KeySpec]] = {}
    for container in containers:
        own = [(a.pk, ProductFields.of(a)) for a in container.affected.all()]
        pairs = applicability_pairs(container.cpe_applicability.all())
        for pk, assigned in attribute_applicability(own, pairs).items():
            if pk is not None:
                links.setdefault(pk, set()).update(cpe_pair_keys(assigned))
    return attach_product_keys(links) if links else 0
