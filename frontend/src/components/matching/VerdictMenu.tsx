import { EllipsisVerticalIcon, GavelIcon, UndoIcon } from "lucide-preact";
import type { MatchedAttribute } from "@/api/generated/models";
import { InlineIcon } from "@/components/ui/InlineIcon";
import { Menu, type MenuEntry } from "@/components/ui/Menu";
import { useVerdictMutation } from "@/hooks/useVerdict";
import { VERDICT_KINDS, verdictLabel } from "./labels";

type Props = {
  suggestionId: number;
  attribute: MatchedAttribute;
  /** Null for the all-branches verdict. */
  branch: string | null;
};

/** Set or clear the verdict of an attribute on one branch, or on all branches. */
export function VerdictMenu({ suggestionId, attribute, branch }: Props) {
  const mutation = useVerdictMutation(suggestionId);
  const where = branch ?? "all branches";
  const current = attribute.verdicts.find((v) => v.branch === branch);

  function set(verdict: (typeof VERDICT_KINDS)[number] | null) {
    mutation.mutate({
      id: suggestionId,
      data: { package_attributes: [attribute.attrpath], branch, verdict },
    });
  }

  const items: MenuEntry[] = VERDICT_KINDS.map((kind) => ({
    value: kind,
    label: `${verdictLabel(kind)}${current?.verdict === kind ? " (current)" : ""}`,
    icon: <GavelIcon />,
    onSelect: () => set(kind),
    disabled: current?.verdict === kind,
  }));
  if (current) {
    items.push(
      { type: "separator" },
      {
        value: "clear",
        label: `Clear verdict on ${where}`,
        icon: <UndoIcon />,
        onSelect: () => set(null),
      },
    );
  }

  return (
    <Menu
      trigger={
        <span
          className="btn-plain"
          title={`Verdict for ${attribute.attrpath} on ${where}`}
          data-testid={`verdict-menu-${attribute.attrpath}-${branch ?? "all"}`}
        >
          <InlineIcon
            icon={branch ? EllipsisVerticalIcon : GavelIcon}
            pending={mutation.isPending}
          />
          {branch === null && "All branches"}
        </span>
      }
      items={items}
    />
  );
}
