"""
Matchers that propose nixpkgs attributes for a CVE, with scores and evidence,
and the reconciliation that keeps `Match` rows current.

Entry points: `shared.matching.view.build_cve_view`, `shared.matching.matchers.collect_candidates`,
`shared.matching.reconcile.reconcile_matches`, `shared.matching.scoring.rank_attributes`.
"""
