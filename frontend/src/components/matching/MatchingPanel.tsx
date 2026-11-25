import { ChevronsDownIcon, ChevronsUpIcon, TriangleAlertIcon } from "lucide-preact";
import { useState } from "preact/hooks";
import { useGetSuggestionMatching } from "@/api/generated/endpoints";
import type { MatchedAttribute, SuggestionMatching } from "@/api/generated/models";
import { InlineIcon } from "@/components/ui/InlineIcon";
import { Skeleton } from "@/components/ui/Skeleton";
import { getApiErrorMessage } from "@/utils/apiError";
import { cx } from "@/utils/className";
import { DerivedStateBadge } from "./DerivedStateBadge";
import { LOW_CONFIDENCE_SCORE, mappingLabel } from "./labels";
import styles from "./MatchingPanel.module.css";
import { Provenance } from "./Provenance";
import { StatusChip } from "./StatusChip";
import { VerdictMenu } from "./VerdictMenu";

/** Attribute rows rendered at once, before "Show more". */
const SHOWN_ROWS = 10;

type Props = {
  suggestionId: number;
  userCanEdit: boolean;
  /** Show the derived state badge, unless the surrounding card already does. */
  showState?: boolean;
};

function isLowConfidence(attribute: MatchedAttribute): boolean {
  return attribute.has_active_match && (attribute.score ?? 0) < LOW_CONFIDENCE_SCORE;
}

function AttributeRow({
  suggestionId,
  attribute,
  data,
  userCanEdit,
}: {
  suggestionId: number;
  attribute: MatchedAttribute;
  data: SuggestionMatching;
  userCanEdit: boolean;
}) {
  const byBranch = new Map(attribute.branches.map((cell) => [cell.branch, cell]));
  return (
    <tr data-testid={`matching-attribute-${attribute.attrpath}`}>
      <td className={styles.rank}>
        {attribute.rank ?? "–"}
        <div className="text-gray">{attribute.score?.toFixed(2)}</div>
      </td>
      <td>
        <div className="column gap-small">
          <div className="row gap-small wrap baseline">
            <strong className={styles.attrpath}>{attribute.attrpath}</strong>
            {attribute.retracted && (
              <span className="tag tag-gray" title="All matches retracted; kept for its verdict">
                retracted
              </span>
            )}
            {attribute.vetoed_by.length > 0 && (
              <span
                className="tag tag-gray"
                title={attribute.vetoed_by.map(mappingLabel).join("; ")}
                data-testid={`vetoed-${attribute.attrpath}`}
              >
                vetoed: {attribute.vetoed_by.map(mappingLabel).join("; ")}
              </span>
            )}
            {!attribute.has_active_match && !attribute.retracted && (
              <span className="tag tag-gray" title="Never matched; kept for its verdict">
                manual
              </span>
            )}
            {userCanEdit && (
              <VerdictMenu suggestionId={suggestionId} attribute={attribute} branch={null} />
            )}
          </div>
          <Provenance
            attrpath={attribute.attrpath}
            matches={attribute.matches}
            affectedProducts={data.affected_products}
          />
        </div>
      </td>
      {data.branches.map(({ name }) => {
        const cell = byBranch.get(name);
        return (
          <td key={name}>
            {cell && (
              <div className="row gap-small align-start">
                <StatusChip attribute={attribute} cell={cell} evaluations={data.evaluations} />
                {userCanEdit && (
                  <VerdictMenu suggestionId={suggestionId} attribute={attribute} branch={name} />
                )}
              </div>
            )}
          </td>
        );
      })}
    </tr>
  );
}

function AttributeTable({
  suggestionId,
  attributes,
  data,
  userCanEdit,
  testId,
}: {
  suggestionId: number;
  attributes: MatchedAttribute[];
  data: SuggestionMatching;
  userCanEdit: boolean;
  testId: string;
}) {
  const [expanded, setExpanded] = useState(false);
  const shown = expanded ? attributes : attributes.slice(0, SHOWN_ROWS);
  const hidden = attributes.length - SHOWN_ROWS;
  return (
    <div className="column gap-small">
      <div className={styles.scroll}>
        <table className={styles.table} data-testid={testId}>
          <thead>
            <tr>
              <th className={styles.rank} title="Rank and noisy-OR score">
                #
              </th>
              <th>Attribute and provenance</th>
              {data.branches.map(({ name }) => (
                <th key={name} className={styles.branch}>
                  {name}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {shown.map((attribute) => (
              <AttributeRow
                key={attribute.attrpath}
                suggestionId={suggestionId}
                attribute={attribute}
                data={data}
                userCanEdit={userCanEdit}
              />
            ))}
          </tbody>
        </table>
      </div>
      {hidden > 0 && (
        <div>
          <button
            type="button"
            className="btn-plain"
            aria-expanded={expanded}
            onClick={() => setExpanded((v) => !v)}
          >
            <InlineIcon icon={expanded ? ChevronsUpIcon : ChevronsDownIcon} />
            {expanded ? "Show less" : `Show more (${hidden})`}
          </button>
        </div>
      )}
    </div>
  );
}

/** The matching model's view of a suggestion: ranked candidates, their provenance and per-branch status. */
export function MatchingPanel({ suggestionId, userCanEdit, showState = true }: Props) {
  const [showLow, setShowLow] = useState(false);
  const { data, isLoading, isError, error } = useGetSuggestionMatching(suggestionId, undefined, {
    query: { staleTime: Infinity },
  });

  if (isLoading) return <Skeleton width="100%" height="8em" />;
  if (isError || !data) {
    return (
      <p className="rounded box bg-red-light">
        Failed to load the matching model: {getApiErrorMessage(error)}
      </p>
    );
  }

  const confident = data.attributes.filter((a) => !isLowConfidence(a));
  const low = data.attributes.filter(isLowConfidence);
  const { derived } = data;
  const toTriage = new Set(derived.needs_triage.map((k) => k.attrpath)).size;
  const possiblyFixed = new Set(derived.possibly_fixed.map((k) => k.attrpath)).size;

  return (
    <div className="column gap" data-testid={`suggestion-${suggestionId}-matching`}>
      <div className="row gap wrap baseline">
        {showState && (
          <DerivedStateBadge
            state={derived.state}
            testId={`suggestion-${suggestionId}-matching-state`}
          />
        )}
        <span data-testid={`suggestion-${suggestionId}-matching-summary`}>
          {data.attribute_count} candidate{data.attribute_count === 1 ? "" : "s"}
          {toTriage > 0 && `, ${toTriage} to triage`}
          {possiblyFixed > 0 && `, ${possiblyFixed} possibly fixed`}
        </span>
        {derived.regressions.length > 0 && (
          <span className="tag bg-red text-white">
            <InlineIcon icon={TriangleAlertIcon} />
            {derived.regressions.length} regression{derived.regressions.length === 1 ? "" : "s"}:{" "}
            {derived.regressions.map((r) => `${r.attrpath} on ${r.branch}`).join(", ")}
          </span>
        )}
      </div>

      {data.status === "published" && (
        <p className="text-gray" data-testid={`suggestion-${suggestionId}-matching-published-note`}>
          Live state of each package on each branch. The package list of a published suggestion
          shows the versions it was published with, which may since have changed.
        </p>
      )}

      {confident.length > 0 ? (
        <AttributeTable
          suggestionId={suggestionId}
          attributes={confident}
          data={data}
          userCanEdit={userCanEdit}
          testId={`suggestion-${suggestionId}-matching-attributes`}
        />
      ) : (
        <p className="text-gray">No confident candidates.</p>
      )}

      {low.length > 0 && (
        <div className="column gap-small align-start">
          <button
            type="button"
            className={cx("btn-plain", !showLow && "text-black")}
            aria-expanded={showLow}
            onClick={() => setShowLow((v) => !v)}
            data-testid={`suggestion-${suggestionId}-matching-low-toggle`}
          >
            <InlineIcon icon={showLow ? ChevronsUpIcon : ChevronsDownIcon} />
            {showLow
              ? "Hide low-confidence candidates"
              : `${low.length} more low-confidence candidate${low.length === 1 ? "" : "s"} (score below ${LOW_CONFIDENCE_SCORE})`}
          </button>
          {showLow && (
            <AttributeTable
              suggestionId={suggestionId}
              attributes={low}
              data={data}
              userCanEdit={userCanEdit}
              testId={`suggestion-${suggestionId}-matching-low`}
            />
          )}
        </div>
      )}
    </div>
  );
}
