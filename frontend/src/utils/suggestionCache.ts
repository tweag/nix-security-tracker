/**
 * The same suggestion can be cached in:
 * - the detail query
 * - embedded in one or more paginated list pages (`getListSuggestionsQueryKey`)
 * These helpers aim to maintain coherent caches.
 */
import type { QueryClient } from "@tanstack/react-query";
import { getGetSuggestionQueryKey, getListSuggestionsQueryKey } from "@/api/generated/endpoints";
import type { PaginatedSuggestionList, Suggestion } from "@/api/generated/models";

const listQueryKeyPrefix = getListSuggestionsQueryKey();

// Common query key prefix regardless of query params (e.g. activity log)
function detailQueryKeyPrefix(id: number) {
  return getGetSuggestionQueryKey(id);
}

export function getCachedSuggestion(queryClient: QueryClient, id: number): Suggestion | undefined {
  const detailQueries = queryClient.getQueriesData<Suggestion>({
    queryKey: detailQueryKeyPrefix(id),
  });
  for (const [, data] of detailQueries) {
    if (data) return data;
  }

  const listQueries = queryClient.getQueriesData<PaginatedSuggestionList>({
    queryKey: listQueryKeyPrefix,
  });
  for (const [, data] of listQueries) {
    const found = data?.results.find((s) => s.id === id);
    if (found) return found;
  }

  return undefined;
}

export async function cancelCachedSuggestionQueries(
  queryClient: QueryClient,
  id: number,
): Promise<void> {
  await Promise.all([
    queryClient.cancelQueries({ queryKey: detailQueryKeyPrefix(id) }),
    queryClient.cancelQueries({ queryKey: listQueryKeyPrefix }),
  ]);
}

export function setCachedSuggestion(
  queryClient: QueryClient,
  id: number,
  updater: (prev: Suggestion) => Suggestion,
): void {
  queryClient.setQueriesData<Suggestion>({ queryKey: detailQueryKeyPrefix(id) }, (prev) =>
    prev ? updater(prev) : prev,
  );

  queryClient.setQueriesData<PaginatedSuggestionList>({ queryKey: listQueryKeyPrefix }, (prev) => {
    if (!prev) return prev;
    let changed = false;
    const results = prev.results.map((s) => {
      if (s.id !== id) return s;
      changed = true;
      return updater(s);
    });
    return changed ? { ...prev, results } : prev;
  });
}

export function invalidateCachedSuggestion(queryClient: QueryClient, id: number): void {
  queryClient.invalidateQueries({ queryKey: detailQueryKeyPrefix(id) });
  queryClient.invalidateQueries({ queryKey: listQueryKeyPrefix });
}
