/**
 * The same suggestion can be cached in:
 * - the detail query
 * - embedded in one or more paginated list pages (`getListSuggestionsQueryKey`)
 * These helpers aim to maintain coherent caches.
 */
import type { QueryClient, QueryKey } from "@tanstack/react-query";
import {
  getGetSuggestionActivityLogQueryKey,
  getGetSuggestionQueryKey,
  getListIssuesQueryKey,
  getListSuggestionsQueryKey,
} from "@/api/generated/endpoints";
import type {
  Issue,
  ListSuggestionsParams,
  PaginatedIssueList,
  PaginatedSuggestionList,
  Suggestion,
} from "@/api/generated/models";

const listQueryKeyPrefix = getListSuggestionsQueryKey();
const listIssuesUrl = getListIssuesQueryKey()[0];

// Matches only the suggestion detail endpoint
// Not sub-resources under it such as `/api/v1/suggestions/42/activity_log`.
const detailUrlPattern = new RegExp(`^${listQueryKeyPrefix[0]}/\\d+$`);

// Matches only the issue detail endpoint (`/api/v1/issues/<code>`)
// Not sub-resources under it.
const issueDetailUrlPattern = new RegExp(`^${listIssuesUrl}/[^/]+$`);

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

/**
 * Mark queries under stale refresh when component is mounted again in the future without refetching fresh data right now.
 * Used when a mutation may move a suggestion in/out of a filtered list to keep showing the old suggestion in faded form.
 */
export function staleQuietly(queryClient: QueryClient, queryKeyPrefix: QueryKey): void {
  queryClient.invalidateQueries({ queryKey: queryKeyPrefix, refetchType: "none" });
}

/** Empty every cached suggestion list page filtered to the issue draft (`in_issue_draft: true`). */
export function clearCachedIssueDraftLists(queryClient: QueryClient): void {
  const draftListQueries = queryClient.getQueryCache().findAll({
    queryKey: listQueryKeyPrefix,
    predicate: (query) =>
      (query.queryKey[1] as ListSuggestionsParams | undefined)?.in_issue_draft === true,
  });
  for (const query of draftListQueries) {
    queryClient.setQueryData<PaginatedSuggestionList>(query.queryKey, (prev) =>
      prev ? { ...prev, results: [], count: 0, next: null, previous: null } : prev,
    );
  }
}

/**
 * Patches every cached suggestion (in any list page, or in a detail query) matching `predicate`.
 */
export function patchCachedSuggestionsMatching(
  queryClient: QueryClient,
  predicate: (suggestion: Suggestion) => boolean,
  updater: (suggestion: Suggestion) => Suggestion,
): void {
  queryClient.setQueriesData<Suggestion>(
    {
      predicate: (query) =>
        typeof query.queryKey[0] === "string" && detailUrlPattern.test(query.queryKey[0]),
    },
    (prev) => (prev && predicate(prev) ? updater(prev) : prev),
  );

  queryClient.setQueriesData<PaginatedSuggestionList>({ queryKey: listQueryKeyPrefix }, (prev) => {
    if (!prev) return prev;
    let changed = false;
    const results = prev.results.map((s) => {
      if (!predicate(s)) return s;
      changed = true;
      return updater(s);
    });
    return changed ? { ...prev, results } : prev;
  });
}

/**
 * Extract suggestions embedded in a query response (suggestion list/detail, or issue list/detail).
 */
function extractEmbeddedSuggestions(queryKey: QueryKey, data: unknown): Suggestion[] {
  const url = typeof queryKey[0] === "string" ? queryKey[0] : undefined;
  if (!url || !data) return [];

  if (url === listQueryKeyPrefix[0]) {
    return (data as PaginatedSuggestionList).results ?? [];
  }
  if (detailUrlPattern.test(url)) {
    return [data as Suggestion];
  }
  if (url === listIssuesUrl) {
    const issues = (data as PaginatedIssueList).results ?? [];
    return issues.flatMap((issue) => issue.suggestions.filter(isEmbeddedSuggestion));
  }
  if (issueDetailUrlPattern.test(url)) {
    return (data as Issue).suggestions.filter(isEmbeddedSuggestion);
  }

  return [];
}

function isEmbeddedSuggestion(item: number | Suggestion): item is Suggestion {
  return typeof item === "object";
}

/**
 * Seeds the activity-log query cache for suggestion embedded in a successful query response, as soon as that response is cached.
 *
 * Avoids firing a redundant activity log refetches on component mount.
 */
export function syncEmbeddedActivityLogs(
  queryClient: QueryClient,
  queryKey: QueryKey,
  data: unknown,
): void {
  for (const suggestion of extractEmbeddedSuggestions(queryKey, data)) {
    if (!suggestion.activity_log) continue;
    queryClient.setQueryData(getGetSuggestionActivityLogQueryKey(suggestion.id), [
      ...suggestion.activity_log,
    ]);
  }
}
