"""
Suggestion relevance for sorting lists: the best noisy-OR score among the attributes
of a suggestion, computed in SQL with the same weights as `shared.matching.scoring`.
"""

from django.db.models import FloatField, QuerySet
from django.db.models.expressions import RawSQL

from shared.matching.scoring import BASE_WEIGHTS, DEFAULT_WEIGHT
from shared.models.linkage import CVEDerivationClusterProposal
from shared.models.matching import Match


def relevance_sql() -> RawSQL:
    """
    max over attributes of `1 - prod(1 - min(1, weight * score))`, as
    `1 - exp(sum(ln(1 - ...)))`, with the factor floored to keep the logarithm defined.
    """
    cases = " ".join("WHEN %s THEN %s" for _ in BASE_WEIGHTS)
    params: list[object] = [v for item in BASE_WEIGHTS.items() for v in item]
    table = Match._meta.db_table
    suggestion = CVEDerivationClusterProposal._meta.db_table
    sql = f"""
        SELECT COALESCE(MAX(a.score), 0) FROM (
            SELECT 1 - exp(sum(ln(GREATEST(f.miss, 1e-12)))) AS score
            FROM (
                SELECT m.attrpath,
                       1 - LEAST(1.0, (CASE m.matcher {cases} ELSE %s END) * m.score) AS miss
                FROM {table} m
                WHERE m.suggestion_id = {suggestion}.id AND m.retracted_at IS NULL
            ) f
            GROUP BY f.attrpath
        ) a
    """
    return RawSQL(sql, [*params, DEFAULT_WEIGHT], output_field=FloatField())


def order_by_relevance(
    queryset: QuerySet[CVEDerivationClusterProposal],
) -> QuerySet[CVEDerivationClusterProposal]:
    """Most relevant first; ties keep the usual most-recent-first order."""
    return queryset.annotate(relevance=relevance_sql()).order_by(
        "-relevance", "-updated_at", "-created_at"
    )
