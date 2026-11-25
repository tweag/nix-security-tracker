import type { DerivedStateEnum } from "@/api/generated/models";
import { InlineIcon } from "@/components/ui/InlineIcon";
import { cx } from "@/utils/className";
import { derivedStateInfo } from "./labels";

type Props = {
  state: DerivedStateEnum;
  testId?: string;
};

/** The state the matching model derives for a suggestion from its matches, exposures and verdicts. */
export function DerivedStateBadge({ state, testId }: Props) {
  const { label, icon, className } = derivedStateInfo(state);
  return (
    <span
      className={cx("tag border no-line-breaks", className)}
      title="Derived from matches, exposures and verdicts"
      data-testid={testId}
    >
      <InlineIcon icon={icon} />
      {label}
    </span>
  );
}
