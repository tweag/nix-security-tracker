import type { LucideIcon } from "lucide-preact";
import type { ComponentChildren } from "preact";
import type { SuggestionStatusEnum, Suggestion as SuggestionType } from "@/api/generated/models";
import { AffectedProductsTree } from "./AffectedProductsTree";
import { CategorizedMaintainersList } from "./CategorizedMaintainersList";
import { CategorizedReferencesList } from "./CategorizedReferencesList";
import { MatchingInNixpkgs } from "./MatchingInNixpkgs";
import { SUGGESTION_SECTION_HEADINGS, type SuggestionSectionId } from "./SuggestionSectionHeadings";

export type SuggestionSection = {
  value: SuggestionSectionId;
  label: string;
  icon: LucideIcon;
  content: ComponentChildren;
};

/**
 * Whether a suggestion in this status still accepts changes to its references, packages and maintainers.
 */
export function isSuggestionEditable(status: SuggestionStatusEnum): boolean {
  return status === "pending" || status === "accepted";
}

function section(value: SuggestionSectionId, content: ComponentChildren): SuggestionSection {
  return { value, ...SUGGESTION_SECTION_HEADINGS[value], content };
}

/**
 * The non-empty sections of a suggestion, in display order.
 */
export function suggestionSections(
  suggestion: SuggestionType,
  userCanEdit: boolean,
): SuggestionSection[] {
  const { id, status, affected_products, categorized_maintainers, categorized_url_references } =
    suggestion;

  const editable = userCanEdit && isSuggestionEditable(status);

  const sections: (SuggestionSection | false)[] = [
    categorized_url_references.original.length > 0 &&
      section(
        "references",
        <CategorizedReferencesList
          categorizedReferences={categorized_url_references}
          suggestionId={id}
          editable={editable}
        />,
      ),
    affected_products.length > 0 &&
      section("affected-products", <AffectedProductsTree affectedProducts={affected_products} />),
    // Always: the matching model may list packages the cached payload does not.
    section(
      "packages",
      <MatchingInNixpkgs suggestion={suggestion} editable={editable} userCanEdit={userCanEdit} />,
    ),
    categorized_maintainers.original.length > 0 &&
      section(
        "maintainers",
        <CategorizedMaintainersList
          suggestionId={id}
          categorizedMaintainers={categorized_maintainers}
          editable={editable}
        />,
      ),
  ];

  return sections.filter((s): s is SuggestionSection => Boolean(s));
}
