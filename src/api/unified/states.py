"""
Derived suggestion state on lists, read from the stored `SuggestionDerivedState`.

Writers flush the rows they touch before committing, so a stale row is one whose writer has
not committed yet, or a row nobody flushed (a bug or a backlog `recompute_derived_state
--stale-only` clears). Those few are computed live here, so lists stay correct either way.
"""

from collections.abc import Collection, Iterable

from django.db.models import Q, QuerySet

from shared.derived_state import derive_states
from shared.models.linkage import CVEDerivationClusterProposal
from shared.models.matching import SuggestionDerivedState


def _stale_q(prefix: str = "") -> Q:
    return Q(**{f"{prefix}derived__stale": True}) | Q(
        **{f"{prefix}derived__isnull": True}
    )


def live_states(suggestion_ids: Collection[int]) -> dict[int, str]:
    """Derived state computed from the facts, for rows the stored state cannot be trusted for."""
    if not suggestion_ids:
        return {}
    return {sid: d.state.value for sid, d in derive_states(suggestion_ids).items()}


def stored_state(suggestion: CVEDerivationClusterProposal) -> str | None:
    """The stored state of a suggestion, or None if it is stale or missing."""
    try:
        row = suggestion.derived  # pyright: ignore[reportAttributeAccessIssue]
    except SuggestionDerivedState.DoesNotExist:
        return None
    return None if row.stale else row.state


def derived_state_map(
    suggestions: Iterable[CVEDerivationClusterProposal],
) -> dict[int, str]:
    """
    Derived state per suggestion: stored where fresh, computed live for the stale rest.
    With `derived` already loaded (`select_related`), no query unless some row is stale.
    """
    states: dict[int, str] = {}
    stale: list[int] = []
    for suggestion in suggestions:
        state = stored_state(suggestion)
        if state is None:
            stale.append(suggestion.pk)
        else:
            states[suggestion.pk] = state
    return states | live_states(stale)


def filter_by_derived_state(
    queryset: QuerySet[CVEDerivationClusterProposal], states: Collection[str]
) -> QuerySet[CVEDerivationClusterProposal]:
    """
    Narrow a selection to suggestions in any of these derived states: an indexed condition on
    the stored state, plus the stale rows of the selection computed live (one query when
    there are none).
    """
    wanted = list(states)
    stale = list(
        queryset.filter(_stale_q()).order_by().values_list("pk", flat=True).distinct()
    )
    live = [sid for sid, state in live_states(stale).items() if state in wanted]
    return queryset.filter(
        Q(derived__state__in=wanted, derived__stale=False) | Q(pk__in=live)
    )
