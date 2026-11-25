"""
The lock order of every writer of the unified model, in one place.

Rule: before a transaction reads-to-write or writes anything that belongs to a suggestion
(its row, matches, exposures, verdicts, links, cached payload, stored derived state, tracker
events), it takes that suggestion's advisory lock with `lock_for_write`; a transaction that
works on several suggestions takes all their advisory locks before it needs them, in ascending
pk order (`lock_for_write` sorts), and never takes the advisory lock of a lower pk after
holding one of a higher pk. Only then come the row locks:

1. `pipeline.lock_cve` (advisory, per CVE id) when creating or re-matching a CVE's suggestion;
2. suggestion advisory locks (`lock_for_write`), ascending;
3. the suggestion row (`select_for_update`, or the `UPDATE` of `save()`), and the
   `FOR KEY SHARE` that inserting a row referencing it takes;
4. the `SuggestionDerivedState` row, which the tracker event and status triggers upsert, and
   `flush_derived_states` locks with `SKIP LOCKED`.

Why: an advisory lock taken after a row lock inverts the order of a writer that went the other
way round. The evaluation listener holds the advisory locks of every suggestion whose
exposures it changes until it commits (`apply_branch_changes`) and writes their events
(derived-state rows); a CVE update that inserted match events (derived-state row) before
taking the advisory lock, or a status change whose `UPDATE` fired the derived-state trigger
before `record_acceptance` took it, deadlocked against it (review finding 3).

Hold times: the evaluation listener takes only advisory locks and derived-state rows, for the
duration of `apply_branch_changes` plus flushing those suggestions' derived state; every
re-match runs later in its own transaction (`SuggestionRematchChannel`) holding the locks of
one suggestion.
"""

from collections.abc import Iterable

from shared.exposure import lock_suggestions


def lock_for_write(suggestion_ids: Iterable[int]) -> None:
    """Take the advisory locks of these suggestions, ascending, until the end of the transaction."""
    lock_suggestions(suggestion_ids)
