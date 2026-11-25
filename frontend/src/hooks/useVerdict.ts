import { type QueryClient, useQueryClient } from "@tanstack/react-query";
import {
  getGetSuggestionMatchingQueryKey,
  getListPossiblyFixedBranchesQueryKey,
  getListPossiblyFixedQueryKey,
  useUpdateSuggestionVerdicts,
} from "@/api/generated/endpoints";
import type {
  AttributeBranch,
  MatchedAttribute,
  PatchedVerdictUpdate,
  SuggestionMatching,
  Verdict,
  VerdictKindEnum,
} from "@/api/generated/models";
import { verdictLabel } from "@/components/matching/labels";
import { getApiErrorMessage } from "@/utils/apiError";
import { invalidateActivityLog, invalidateCachedSuggestion } from "@/utils/suggestionCache";
import { toaster } from "@/utils/toaster";

type MutationVars = { id: number; data: PatchedVerdictUpdate };
type MutationContext = { previous: [readonly unknown[], SuggestionMatching | undefined][] };

/** What changes when a verdict is set or cleared, for the optimistic update. */
type Change = { attrpaths: string[]; branch: string | null; verdict: VerdictKindEnum | null };

function effectiveFor(cell: AttributeBranch, verdicts: Verdict[]): AttributeBranch["effective"] {
  const specific = verdicts.find((v) => v.branch === cell.branch);
  const general = verdicts.find((v) => v.branch === null);
  const applied = specific ?? general;
  if (applied) {
    return {
      status: applied.verdict,
      source: "verdict",
      regression: false,
      verdict_branch: applied.branch,
    };
  }
  if (cell.exposure) {
    return {
      status: cell.exposure.observed,
      source: "observed",
      regression: false,
      verdict_branch: null,
    };
  }
  return null;
}

function patchAttribute(attribute: MatchedAttribute, change: Change): MatchedAttribute {
  if (!change.attrpaths.includes(attribute.attrpath)) return attribute;
  const now = new Date().toISOString();
  const others = attribute.verdicts.filter((v) => v.branch !== change.branch);
  const verdicts: Verdict[] =
    change.verdict === null
      ? others
      : [
          ...others,
          {
            branch: change.branch,
            verdict: change.verdict,
            fix_commit: null,
            comment: "",
            author: null,
            created_at: now,
            updated_at: now,
          },
        ];
  const branches = attribute.branches.map((cell) => {
    if (change.branch !== null && cell.branch !== change.branch) return cell;
    return { ...cell, effective: effectiveFor(cell, verdicts) };
  });
  return { ...attribute, verdicts, branches };
}

function patchMatching(data: SuggestionMatching, change: Change): SuggestionMatching {
  return { ...data, attributes: data.attributes.map((a) => patchAttribute(a, change)) };
}

/** Everything a verdict can change: the matching view, the derived state, the log and the queue. */
export function invalidateAfterVerdict(queryClient: QueryClient, suggestionId: number): void {
  queryClient.invalidateQueries({ queryKey: getGetSuggestionMatchingQueryKey(suggestionId) });
  invalidateCachedSuggestion(queryClient, suggestionId);
  invalidateActivityLog(queryClient, suggestionId);
  queryClient.invalidateQueries({ queryKey: getListPossiblyFixedQueryKey() });
  queryClient.invalidateQueries({ queryKey: getListPossiblyFixedBranchesQueryKey() });
}

function describe({ data }: MutationVars): string {
  const what = data.package_attributes?.join(", ") ?? "";
  const where = data.branch ? `on ${data.branch}` : "on all branches";
  return data.verdict
    ? `Failed to mark ${what} ${verdictLabel(data.verdict)} ${where}`
    : `Failed to clear the verdict of ${what} ${where}`;
}

/** Sets or clears verdicts on a suggestion's attributes, updating the matching view at once. */
export function useVerdictMutation(suggestionId: number) {
  const queryClient = useQueryClient();
  const matchingKey = getGetSuggestionMatchingQueryKey(suggestionId);

  return useUpdateSuggestionVerdicts({
    mutation: {
      onMutate: async ({ data }: MutationVars): Promise<MutationContext> => {
        await queryClient.cancelQueries({ queryKey: matchingKey });
        const previous = queryClient.getQueriesData<SuggestionMatching>({ queryKey: matchingKey });
        const change: Change = {
          attrpaths: data.package_attributes ?? [],
          branch: data.branch ?? null,
          verdict: data.verdict ?? null,
        };
        queryClient.setQueriesData<SuggestionMatching>({ queryKey: matchingKey }, (prev) =>
          prev ? patchMatching(prev, change) : prev,
        );
        return { previous };
      },
      onError: (err: unknown, vars: MutationVars, context?: MutationContext) => {
        for (const [key, data] of context?.previous ?? []) {
          queryClient.setQueryData(key, data);
        }
        toaster.error({ title: describe(vars), description: getApiErrorMessage(err) });
      },
      onSettled: () => invalidateAfterVerdict(queryClient, suggestionId),
    },
  });
}
