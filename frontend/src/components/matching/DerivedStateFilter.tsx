import type { ListSuggestionsDerivedStateItem } from "@/api/generated/models";
import { nextToggleSelection } from "@/components/suggestions/SuggestionFilters";
import { InlineIcon } from "@/components/ui/InlineIcon";
import { PillToggleGroup, type ToggleGroupOption } from "@/components/ui/PillToggleGroup";
import { DERIVED_STATES, derivedStateInfo } from "./labels";

const OPTIONS: ToggleGroupOption[] = DERIVED_STATES.map((state) => {
  const { label, icon } = derivedStateInfo(state);
  return {
    value: state,
    label: (
      <>
        <InlineIcon icon={icon} />
        {label}
      </>
    ),
  };
});

type Props = {
  value: ListSuggestionsDerivedStateItem[];
  onChange: (states: ListSuggestionsDerivedStateItem[]) => void;
};

/** Filter by the state derived by the matching model; same click behaviour as the status filter. */
export function DerivedStateFilter({ value, onChange }: Props) {
  return (
    <div className="row gap-small wrap align-center" data-testid="derived-state-filter">
      <span className="text-gray">Matching model:</span>
      <PillToggleGroup
        value={value}
        options={OPTIONS}
        onItemClick={(clicked, event) =>
          onChange(nextToggleSelection(value, clicked, event) as ListSuggestionsDerivedStateItem[])
        }
      />
    </div>
  );
}
