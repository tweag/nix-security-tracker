import { type QueryClient, useQueryClient } from "@tanstack/react-query";
import {
  getListPossiblyFixedQueryKey,
  useConfirmPossiblyFixed,
  useStillAffectedPossiblyFixed,
} from "@/api/generated/endpoints";
import type { PaginatedPossiblyFixedList, PossiblyFixed } from "@/api/generated/models";
import { invalidateAfterVerdict } from "@/hooks/useVerdict";
import { getApiErrorMessage } from "@/utils/apiError";
import { toaster } from "@/utils/toaster";

type MutationContext = { previous: [readonly unknown[], PaginatedPossiblyFixedList | undefined][] };

/** Optimistic removal of a row from every cached page of the queue, with rollback and a toast on error. */
function rowRemovalHandlers(queryClient: QueryClient, row: PossiblyFixed, errorTitle: string) {
  const listKey = getListPossiblyFixedQueryKey();
  return {
    onMutate: async (): Promise<MutationContext> => {
      await queryClient.cancelQueries({ queryKey: listKey });
      const previous = queryClient.getQueriesData<PaginatedPossiblyFixedList>({
        queryKey: listKey,
      });
      queryClient.setQueriesData<PaginatedPossiblyFixedList>({ queryKey: listKey }, (prev) => {
        if (!prev?.results.some((r) => r.id === row.id)) return prev;
        return {
          ...prev,
          count: prev.count - 1,
          results: prev.results.filter((r) => r.id !== row.id),
        };
      });
      return { previous };
    },
    onError: (err: unknown, _vars: unknown, context?: MutationContext) => {
      for (const [key, data] of context?.previous ?? []) {
        queryClient.setQueryData(key, data);
      }
      toaster.error({ title: errorTitle, description: getApiErrorMessage(err) });
    },
    onSettled: () => invalidateAfterVerdict(queryClient, row.suggestion_id),
  };
}

/** "Confirm fixed" and "still affected" on a row of the possibly-fixed queue. */
export function usePossiblyFixedActions(row: PossiblyFixed) {
  const queryClient = useQueryClient();
  const where = `${row.attrpath} on ${row.branch}`;
  const confirm = useConfirmPossiblyFixed({
    mutation: rowRemovalHandlers(queryClient, row, `Failed to confirm the fix of ${where}`),
  });
  const stillAffected = useStillAffectedPossiblyFixed({
    mutation: rowRemovalHandlers(queryClient, row, `Failed to mark ${where} still affected`),
  });
  return { confirm, stillAffected, isPending: confirm.isPending || stillAffected.isPending };
}
