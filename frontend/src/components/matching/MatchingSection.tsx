import { ChevronDownIcon, ChevronRightIcon, ScaleIcon } from "lucide-preact";
import { useState } from "preact/hooks";
import type { DerivedStateEnum } from "@/api/generated/models";
import { Collapsible } from "@/components/ui/Collapsible";
import { InlineIcon } from "@/components/ui/InlineIcon";
import { DerivedStateBadge } from "./DerivedStateBadge";
import { MatchingPanel } from "./MatchingPanel";

type Props = {
  suggestionId: number;
  /** Absent where the embedding response does not carry it. */
  derivedState?: DerivedStateEnum;
  userCanEdit: boolean;
};

/**
 * Collapsed-by-default entry to the matching model of a suggestion.
 * The panel is only fetched once opened.
 */
export function MatchingSection({ suggestionId, derivedState, userCanEdit }: Props) {
  const [open, setOpen] = useState(false);
  return (
    <div className="column gap-small">
      <div className="row gap-small baseline wrap">
        <button
          type="button"
          className="btn-plain text-black"
          aria-expanded={open}
          onClick={() => setOpen((v) => !v)}
          data-testid={`suggestion-${suggestionId}-matching-toggle`}
        >
          <InlineIcon icon={open ? ChevronDownIcon : ChevronRightIcon} />
          <InlineIcon icon={ScaleIcon} />
          Matching model
        </button>
        {derivedState && (
          <DerivedStateBadge
            state={derivedState}
            testId={`suggestion-${suggestionId}-derived-state`}
          />
        )}
      </div>
      <Collapsible open={open}>
        <MatchingPanel
          suggestionId={suggestionId}
          userCanEdit={userCanEdit}
          showState={!derivedState}
        />
      </Collapsible>
    </div>
  );
}
