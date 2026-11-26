import type { RefObject } from "preact";
import { useGetSuggestionMatching } from "@/api/generated/endpoints";
import type {
  MatchedAttribute,
  SuggestionMatching,
  Suggestion as SuggestionType,
} from "@/api/generated/models";
import { useNearViewport } from "@/hooks/useNearViewport";

/** One package of a suggestion, as the "Matching in Nixpkgs" section lists it. */
export type PackageRow = {
  attrpath: string;
  description: string | null;
  /** The matching model's facts; absent while loading, or for a package it has no rows for. */
  attribute?: MatchedAttribute;
  /** In the suggestion's package list, so the ignore and restore buttons apply. */
  listed: boolean;
  ignored: boolean;
  /** Shown to triagers; otherwise behind the low-confidence-or-retracted toggle. */
  shown: boolean;
};

/**
 * The packages of a suggestion, from the matching model, in rank order. Whether a listed
 * package is ignored comes from the suggestion's own package list, which ignoring and
 * restoring update at once; the server keeps it in step with the verdicts.
 * Before the matching model has loaded, the listed packages, without any facts.
 */
export function packageRows(
  suggestion: SuggestionType,
  data: SuggestionMatching | undefined,
): PackageRow[] {
  const listed = suggestion.original_packages;
  const ignored = suggestion.ignored_packages;
  const rows: PackageRow[] = (data?.attributes ?? []).map((attribute) => {
    const isListed = attribute.attrpath in listed;
    return {
      attrpath: attribute.attrpath,
      description: listed[attribute.attrpath]?.description ?? null,
      attribute,
      listed: isListed,
      ignored: isListed ? attribute.attrpath in ignored : attribute.ignored,
      shown: attribute.shown && !attribute.retracted,
    };
  });
  const known = new Set(rows.map((row) => row.attrpath));
  for (const [attrpath, pkg] of Object.entries(listed)) {
    if (known.has(attrpath)) continue;
    rows.push({
      attrpath,
      description: pkg.description,
      listed: true,
      ignored: attrpath in ignored,
      shown: true,
    });
  }
  return rows;
}

/**
 * The matching model of a suggestion, fetched once the element is in or near the viewport,
 * so a list page does not fetch it for every card at once. Its derived state is newer than
 * the card's (a verdict refetches it): show `data.derived.state` first. It is not written
 * back into the cached suggestion, since patching a list page marks it fresh and would hide
 * changes a mutation marked it stale for.
 */
export function useSuggestionMatching(suggestionId: number, ref: RefObject<Element>) {
  const near = useNearViewport(ref);
  return useGetSuggestionMatching(suggestionId, undefined, {
    query: { enabled: near, staleTime: Infinity },
  });
}

/** "3 packages, 2 to triage, 1 possibly fixed". */
export function matchingSummary(rows: PackageRow[], data: SuggestionMatching): string {
  const shown = rows.filter((row) => row.shown && !row.ignored).length;
  const toTriage = new Set(data.derived.needs_triage.map((k) => k.attrpath)).size;
  const possiblyFixed = new Set(data.derived.possibly_fixed.map((k) => k.attrpath)).size;
  return [
    `${shown} package${shown === 1 ? "" : "s"}`,
    toTriage > 0 && `${toTriage} to triage`,
    possiblyFixed > 0 && `${possiblyFixed} possibly fixed`,
  ]
    .filter(Boolean)
    .join(", ");
}
