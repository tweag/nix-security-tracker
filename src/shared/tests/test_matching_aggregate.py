from shared.matching.base import Hit, aggregate
from shared.matching.view import ProductFields, ViewProduct


def product(pk: int | None) -> ViewProduct:
    return ViewProduct(
        fields=ProductFields(),
        sources=((pk, "cna"),),
        cpe_pairs=frozenset({("foo", "foo")}),
        hardware_only=False,
        keys=frozenset(),
        names=(),
        repos=(),
    )


def hit(pk: int | None, has_product: bool = True) -> Hit:
    return Hit(
        "foo",
        "master",
        1.0,
        product(pk) if has_product else None,
        "cpe",
        "foo:foo",
        "cpe",
        "foo:foo",
    )


def test_tie_prefers_a_claimed_affected_product_in_any_order() -> None:
    # A container-level `cpeApplicability` product has no affected product pk.
    for hits in ([hit(7), hit(None)], [hit(None), hit(7)]):
        [candidate] = aggregate(hits, 10).candidates
        assert candidate.evidence["affected_product"] == 7
        assert candidate.evidence["other_hits"] == 1


def test_tie_between_unclaimed_and_productless_hits() -> None:
    [candidate] = aggregate([hit(None), hit(None, has_product=False)], 10).candidates
    assert candidate.evidence["affected_product"] is None
