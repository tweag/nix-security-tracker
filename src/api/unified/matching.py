"""
Per-suggestion view of the unified matching model: ranked attributes with their
matches, per-branch exposures, verdicts and effective statuses, in a fixed number of
queries whatever the number of attributes.

Evaluations and affected products are referenced by id and listed once at the top level,
so that a suggestion with many attributes on several branches does not repeat them.
"""

from collections import defaultdict
from typing import Any

from shared.derived_state import (
    Derived,
    Effective,
    candidates_of,
    derive_state,
    effective_status,
    load_facts,
    pick_verdict,
)
from shared.exposure import tracked_branches
from shared.identity.keys import stored_or_derived_keys
from shared.identity.mappings import load_mappings
from shared.matching.scoring import rank_matches, weight_of
from shared.models.cve import AffectedProduct
from shared.models.linkage import CVEDerivationClusterProposal, PackageOverlay
from shared.models.matching import Exposure, Match, Verdict
from shared.models.nix_evaluation import NixEvaluation

# Keys of `Exposure.detail` the API documents; others are internal.
EXPOSURE_DETAIL_KEYS = (
    "detail",
    "inferred",
    "range",
    "range_source",
    "affected_product",
    "last_affected_version",
    "last_seen_evaluation",
    "patch_commit",
)


def evidence_of(raw: dict[str, Any]) -> dict[str, Any]:
    """`Match.evidence` in the documented shape: absent keys are null, unknown keys dropped."""
    return {
        "affected_product": raw.get("affected_product"),
        "container": raw.get("container"),
        "cve_field": raw.get("cve_field"),
        "cve_value": raw.get("cve_value"),
        "pkg_field": raw.get("pkg_field"),
        "pkg_value": raw.get("pkg_value"),
        "similarity": raw.get("similarity"),
        "branches": list(raw.get("branches", [])),
        "other_hits": raw.get("other_hits", 0),
        "mapping": mapping_of(raw.get("mapping")),
        "provenance_flags": raw.get("provenance_flags"),
        "cve_fields": list(raw.get("cve_fields", [])),
        "affected_products": [
            pk for pk in raw.get("affected_products", []) if isinstance(pk, int)
        ],
    }


def mapping_of(raw: Any) -> dict[str, Any] | None:
    """A `MappingRule.describe()` record in the documented shape."""
    if not isinstance(raw, dict):
        return None
    return {
        k: raw.get(k) for k in ("id", "product_key", "relation", "source", "target")
    }


def _match(m: Match, vetoed: bool = False) -> dict[str, Any]:
    weight = weight_of(m.matcher)
    return {
        "vetoed": vetoed,
        "matcher": m.matcher,
        "matcher_version": m.matcher_version,
        "score": m.score,
        "weight": weight,
        "contribution": min(1.0, weight * m.score),
        "retracted": m.retracted_at is not None,
        "retracted_at": m.retracted_at,
        "first_seen_at": m.first_seen_at,
        "last_seen_at": m.last_seen_at,
        "evidence": evidence_of(m.evidence),
    }


def _exposure(e: Exposure) -> dict[str, Any]:
    detail = {k: e.detail.get(k) for k in EXPOSURE_DETAIL_KEYS}
    detail["inferred"] = bool(detail["inferred"])
    return {
        "present": e.present,
        "version": e.version,
        "observed": e.observed,
        "reason": e.reason,
        "detail": detail,
        "evaluation": e.evaluation_id,
        "first_affected_evaluation": e.first_affected_evaluation_id,
        "last_affected_evaluation": e.last_affected_evaluation_id,
        "fixed_evaluation": e.fixed_evaluation_id,
        "fix_commit": e.fix_commit,
        "updated_at": e.updated_at,
    }


def _verdict(v: Verdict) -> dict[str, Any]:
    return {
        "branch": v.branch_id,
        "verdict": v.verdict,
        "fix_commit": v.fix_commit,
        "comment": v.comment,
        "author": v.author.username if v.author is not None else None,
        "created_at": v.created_at,
        "updated_at": v.updated_at,
    }


def _effective(eff: Effective) -> dict[str, Any]:
    return {
        "status": eff.status,
        "source": eff.source,
        "regression": eff.regression,
        # Which verdict applied: the branch-specific one, or the all-branches one (null).
        "verdict_branch": eff.verdict.branch_id if eff.verdict else None,
    }


def keys(pairs: list[tuple[str, str | None]]) -> list[dict[str, str | None]]:
    return [{"attrpath": a, "branch": b} for a, b in pairs]


def derived_data(d: Derived) -> dict[str, Any]:
    return {
        "state": d.state.value,
        "needs_triage": keys(d.needs_triage),
        "possibly_fixed": keys(list(d.possibly_fixed)),
        "regressions": keys(d.regressions),
        "affected": keys(d.affected),
    }


def build_matching_view(
    suggestion: CVEDerivationClusterProposal,
    offset: int = 0,
    limit: int | None = None,
) -> dict[str, Any]:
    """
    The per-suggestion view, in a constant number of queries. `offset` and `limit`
    select a slice of the ranked attributes; the derived state is always over all.
    """
    sid = suggestion.pk
    facts = load_facts([sid])[sid]
    derived = derive_state(facts)
    verdict_facts = facts.verdicts

    matches_by_attr: dict[str, list[Match]] = defaultdict(list)
    for m in Match.objects.filter(suggestion_id=sid).order_by("matcher"):
        matches_by_attr[m.attrpath].append(m)
    verdicts_by_attr: dict[str, list[Verdict]] = defaultdict(list)
    for v in (
        Verdict.objects.filter(suggestion_id=sid)
        .select_related("author")
        .order_by("branch_id")
    ):
        verdicts_by_attr[v.attrpath].append(v)
    exposures_by_attr: dict[str, dict[str, Exposure]] = defaultdict(dict)
    for e in facts.exposures:
        exposures_by_attr[e.attrpath][e.branch_id] = e

    # Ignored as the package list has it: the overlay, kept in step with an all-branches
    # `irrelevant` verdict by both the packages and the verdicts endpoints.
    ignored = set(
        PackageOverlay.objects.filter(
            suggestion_id=sid, type=PackageOverlay.Type.IGNORED
        ).values_list("package_attribute", flat=True)
    ) | {
        v.attrpath
        for v in facts.verdicts
        if v.branch_id is None and v.verdict == Verdict.Kind.IRRELEVANT
    }
    branches = tracked_branches()
    tracked = [b.name for b in branches]
    active_matches = [
        m for ms in matches_by_attr.values() for m in ms if m.retracted_at is None
    ]
    # Vetoes by `not_same` mappings apply as in `rank_attributes`.
    products = {
        pk
        for m in active_matches
        if isinstance(pk := m.evidence.get("affected_product"), int)
    }
    keys_of = stored_or_derived_keys(products) if products else {}
    mappings = load_mappings(k for keys in keys_of.values() for k in keys)
    ranked = rank_matches(active_matches, mappings, keys_of)
    contributing = {id(m) for r in ranked for m in r.matches}
    vetoed_by = {r.attrpath: r.vetoed_by for r in ranked}
    candidates = candidates_of(facts)
    order = [r.attrpath for r in ranked if r.attrpath in candidates]
    order += sorted(candidates - set(order))
    scores = {r.attrpath: r.score for r in ranked}

    evaluation_ids: set[int] = {
        b.current_evaluation_id for b in branches if b.current_evaluation_id
    }
    product_ids: set[int] = set()
    attributes = []
    end = None if limit is None else offset + limit
    for rank, attr in list(enumerate(order, start=1))[offset:end]:
        matches = matches_by_attr.get(attr, [])
        active = [m for m in matches if m.retracted_at is None]
        exposures = exposures_by_attr.get(attr, {})
        verdicts = verdicts_by_attr.get(attr, [])
        branch_names = tracked + sorted(
            ({*exposures} | {v.branch_id for v in verdicts if v.branch_id})
            - set(tracked)
        )
        per_branch = []
        for name in branch_names:
            exposure = exposures.get(name)
            verdict = pick_verdict(verdict_facts, attr, name)
            eff = (
                effective_status(
                    exposure, verdict, facts.became_affected.get((attr, name))
                )
                if exposure is not None or verdict is not None
                else None
            )
            if exposure is not None:
                evaluation_ids.update(
                    i
                    for i in (
                        exposure.evaluation_id,
                        exposure.first_affected_evaluation_id,
                        exposure.last_affected_evaluation_id,
                        exposure.fixed_evaluation_id,
                    )
                    if i is not None
                )
                if isinstance(exposure.detail.get("affected_product"), int):
                    product_ids.add(exposure.detail["affected_product"])
            per_branch.append(
                {
                    "branch": name,
                    "exposure": _exposure(exposure) if exposure else None,
                    "effective": _effective(eff) if eff else None,
                }
            )
        for m in matches:
            if isinstance(m.evidence.get("affected_product"), int):
                product_ids.add(m.evidence["affected_product"])
            product_ids.update(evidence_of(m.evidence)["affected_products"])
        attributes.append(
            {
                "attrpath": attr,
                "shown": attr in facts.shown,
                "ignored": attr in ignored,
                "score": scores.get(attr, 0.0) if active else None,
                "rank": rank if active else None,
                "has_active_match": bool(active),
                # Matched once, retracted since; kept because a verdict refers to it.
                "retracted": bool(matches) and not active,
                "matches": [
                    _match(m, m.retracted_at is None and id(m) not in contributing)
                    for m in sorted(matches, key=_match_order)
                ],
                "vetoed_by": [mapping_of(v) for v in vetoed_by.get(attr, ())],
                "verdicts": [_verdict(v) for v in verdicts],
                "branches": per_branch,
            }
        )

    evaluations = {
        str(pk): {"commit_sha1": sha, "created_at": created_at}
        for pk, sha, created_at in NixEvaluation.objects.filter(
            pk__in=evaluation_ids
        ).values_list("pk", "commit_sha1", "created_at")
    }
    products = {
        str(row["pk"]): {k: v for k, v in row.items() if k != "pk"}
        for row in AffectedProduct.objects.filter(pk__in=product_ids).values(
            "pk", "vendor", "product", "package_name", "repo"
        )
    }
    return {
        "suggestion_id": sid,
        "cve_id": suggestion.cve.cve_id,
        "status": suggestion.status,
        "derived": derived_data(derived),
        "branches": [
            {"name": b.name, "current_evaluation": b.current_evaluation_id}
            for b in branches
        ],
        "attribute_count": len(order),
        "attributes": attributes,
        "evaluations": evaluations,
        "affected_products": products,
    }


def _match_order(m: Match) -> tuple[bool, float, str]:
    """Active first, strongest contribution first."""
    return (m.retracted_at is not None, -weight_of(m.matcher) * m.score, m.matcher)
