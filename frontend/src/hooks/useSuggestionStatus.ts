import { useQueryClient } from "@tanstack/react-query";
import {
  getGetSuggestionActivityLogQueryKey,
  getGetSuggestionQueryKey,
  useChangeSuggestionStatus,
} from "@/api/generated/endpoints";
import type { Suggestion, SuggestionStatus as SuggestionStatusData } from "@/api/generated/models";
import { getApiErrorMessage } from "@/utils/apiError";
import { toaster } from "@/utils/toaster";

type MutationVars = { id: number; data: SuggestionStatusData };
type MutationContext = { previous?: Suggestion };

export function useSuggestionStatusMutation(suggestionId: number) {
  const queryClient = useQueryClient();
  const queryKey = getGetSuggestionQueryKey(suggestionId);

  return useChangeSuggestionStatus({
    mutation: {
      onMutate: async ({ data }: MutationVars): Promise<MutationContext> => {
        await queryClient.cancelQueries({ queryKey });
        const previous = queryClient.getQueryData<Suggestion>(queryKey);

        queryClient.setQueryData<Suggestion>(queryKey, (prev) => {
          if (!prev) return prev;
          return {
            ...prev,
            status: data.status,
            rejection_reason: data.status === "rejected" ? data.rejection_reason : undefined,
          };
        });

        return { previous };
      },
      onError: (err: unknown, _vars: MutationVars, context?: MutationContext) => {
        const description = getApiErrorMessage(err);
        if (context?.previous) {
          queryClient.setQueryData(queryKey, context.previous);
        }
        toaster.error({ title: "Failed to change status", description });
      },
      onSuccess: () => {
        queryClient.invalidateQueries({
          queryKey: getGetSuggestionActivityLogQueryKey(suggestionId),
        });
      },
    },
  });
}
