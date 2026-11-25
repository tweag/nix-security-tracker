"""
The identity layer: normalised upstream product keys of affected products, and reusable
mappings from product keys to nixpkgs attributes (or vetoes against them).

Entry points: `shared.identity.keys.persist_product_keys`, `shared.identity.mappings.load_mappings`,
`shared.identity.reconcile.reconcile_for_product_keys`, `shared.identity.triage.learn_triage_mappings`,
`shared.identity.reverse.reverse_match`, `shared.identity.missing_cpes.missing_cpes_from_mappings`.
"""
