import { ToggleRoot } from "@ark-ui/react";
import {
  ChevronsDownIcon,
  ChevronsUpIcon,
  EyeIcon,
  EyeOffIcon,
  PackageMinusIcon,
  PackagePlusIcon,
  TriangleAlertIcon,
} from "lucide-preact";
import { useRef, useState } from "preact/hooks";
import type { SuggestionMatching, Suggestion as SuggestionType } from "@/api/generated/models";
import { DerivedStateBadge } from "@/components/matching/DerivedStateBadge";
import { mappingLabel } from "@/components/matching/labels";
import styles from "@/components/matching/Matching.module.css";
import { Provenance } from "@/components/matching/Provenance";
import { StatusChip } from "@/components/matching/StatusChip";
import { VerdictMenu } from "@/components/matching/VerdictMenu";
import { CollectionCard } from "@/components/ui/CollectionCard";
import { InlineIcon } from "@/components/ui/InlineIcon";
import { Skeleton } from "@/components/ui/Skeleton";
import { usePackageMutation } from "@/hooks/usePackage";
import { useSuggestionListFilterHref, withPackageFilter } from "@/hooks/useSuggestionListFilters";
import { getApiErrorMessage } from "@/utils/apiError";
import { cx } from "@/utils/className";
import { FilterShortcut } from "./FilterShortcut";
import { IgnoreRestoreButton } from "./IgnoreRestoreButton";
import {
  matchingSummary,
  type PackageRow,
  packageRows,
  useSuggestionMatching,
} from "./matchingRows";
import itemStyles from "./SuggestionItemCollection.module.css";
import { SuggestionSectionHeading } from "./SuggestionSectionHeadings";

type Props = {
  suggestion: SuggestionType;
  /** The suggestion accepts ignoring and restoring packages, by this user. */
  editable: boolean;
  /** The user may set verdicts. */
  userCanEdit: boolean;
};

type RowProps = {
  suggestionId: number;
  row: PackageRow;
  data: SuggestionMatching | undefined;
  editable: boolean;
  userCanEdit: boolean;
};

function IgnoreButton({ suggestionId, row }: { suggestionId: number; row: PackageRow }) {
  const mutation = usePackageMutation(suggestionId);
  return (
    <IgnoreRestoreButton
      action={row.ignored ? "restore" : "ignore"}
      icon={row.ignored ? PackagePlusIcon : PackageMinusIcon}
      disabled={mutation.isPending}
      onClick={() =>
        mutation.mutate({
          id: suggestionId,
          data: { package_attributes: [row.attrpath], ignored: !row.ignored },
        })
      }
    />
  );
}

function Row({ suggestionId, row, data, editable, userCanEdit }: RowProps) {
  const filterHref = useSuggestionListFilterHref();
  const { attribute } = row;
  const byBranch = new Map(attribute?.branches.map((cell) => [cell.branch, cell]) ?? []);
  return (
    <tr data-testid={`package-row-${row.attrpath}`}>
      {editable && (
        <td className={styles.action}>
          {row.listed && <IgnoreButton suggestionId={suggestionId} row={row} />}
        </td>
      )}
      <td className={cx(styles.rank, row.ignored && itemStyles.faded)}>
        {attribute?.rank ?? "–"}
        <div className="text-gray">{attribute?.score?.toFixed(2)}</div>
      </td>
      <td className={cx(row.ignored && itemStyles.faded)}>
        <div className="column gap-small">
          <div className="row gap-small wrap baseline">
            <h3 className={cx("bold", styles.attrpath)}>{row.attrpath}</h3>
            <FilterShortcut
              href={filterHref(withPackageFilter(row.attrpath))}
              label={`Filter suggestions by package '${row.attrpath}'`}
            />
            {attribute?.retracted && (
              <span className="tag tag-gray" title="All matches retracted; kept for its verdict">
                retracted
              </span>
            )}
            {attribute && attribute.vetoed_by.length > 0 && (
              <span
                className="tag tag-gray"
                title={attribute.vetoed_by.map(mappingLabel).join("; ")}
                data-testid={`vetoed-${row.attrpath}`}
              >
                vetoed: {attribute.vetoed_by.map(mappingLabel).join("; ")}
              </span>
            )}
            {attribute && !attribute.has_active_match && !attribute.retracted && (
              <span className="tag tag-gray" title="Never matched; kept for its verdict">
                manual
              </span>
            )}
            {data && !attribute && (
              <span className="tag tag-gray" title="The matching model has nothing on it yet">
                no facts yet
              </span>
            )}
            {userCanEdit && attribute && (
              <VerdictMenu suggestionId={suggestionId} attribute={attribute} branch={null} />
            )}
          </div>
          {row.description && <span>{row.description}</span>}
          {attribute && (
            <Provenance
              attrpath={row.attrpath}
              matches={attribute.matches}
              affectedProducts={data?.affected_products ?? {}}
            />
          )}
        </div>
      </td>
      {data?.branches.map(({ name }) => {
        const cell = byBranch.get(name);
        return (
          <td key={name} className={cx(row.ignored && itemStyles.faded)}>
            {cell && attribute && (
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

function RowTable({
  rows,
  testId,
  ...rowProps
}: Omit<RowProps, "row"> & { rows: readonly PackageRow[]; testId?: string }) {
  return (
    <div className={styles.scroll}>
      <table className={styles.table} data-testid={testId}>
        <thead>
          <tr>
            {rowProps.editable && <th className={styles.action} />}
            <th className={styles.rank} title="Rank and noisy-OR score">
              #
            </th>
            <th>Package and provenance</th>
            {rowProps.data?.branches.map(({ name }) => (
              <th key={name} className={styles.branch}>
                {name}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {rows.map((row) => (
            <Row key={row.attrpath} row={row} {...rowProps} />
          ))}
        </tbody>
      </table>
    </div>
  );
}

/**
 * The packages of a suggestion, from the matching model: per package its provenance, and per
 * branch the version and status the tracker observes now, with the verdicts on them.
 */
export function MatchingInNixpkgs({ suggestion, editable, userCanEdit }: Props) {
  const { id } = suggestion;
  const testId = `suggestion-${id}-packages`;
  const ref = useRef<HTMLDivElement>(null);
  const { data, isError, error } = useSuggestionMatching(id, ref);
  const [showIgnored, setShowIgnored] = useState(false);
  const [showMore, setShowMore] = useState(false);

  const rows = packageRows(suggestion, data);
  const visible = rows.filter((row) => (row.ignored ? showIgnored : row.shown));
  const more = rows.filter((row) => !row.shown && !row.ignored);
  const ignoredCount = rows.filter((row) => row.ignored).length;
  const state = data?.derived.state ?? suggestion.derived_state;
  const rowProps = { suggestionId: id, data, editable, userCanEdit };

  return (
    <div ref={ref}>
      <CollectionCard
        items={visible}
        label={<SuggestionSectionHeading section="packages" />}
        labelExtra={
          state && <DerivedStateBadge state={state} testId={`suggestion-${id}-derived-state`} />
        }
        viewToggle={
          <ToggleRoot
            pressed={showIgnored}
            onPressedChange={setShowIgnored}
            className={`row centered cursor-pointer ${itemStyles.ignoredToggle}`}
            data-testid={`${testId}-ignored-toggle`}
          >
            <InlineIcon icon={showIgnored ? EyeIcon : EyeOffIcon} />
            Ignored ({ignoredCount})
          </ToggleRoot>
        }
        testId={testId}
        footer={
          more.length > 0 && (
            <div className="column gap-small align-start">
              <button
                type="button"
                className={cx("btn-plain", !showMore && "text-black")}
                aria-expanded={showMore}
                onClick={() => setShowMore((v) => !v)}
                data-testid={`${testId}-more-toggle`}
              >
                <InlineIcon icon={showMore ? ChevronsUpIcon : ChevronsDownIcon} />
                {showMore
                  ? "Hide low-confidence and retracted candidates"
                  : `${more.length} more low-confidence or retracted candidate${more.length === 1 ? "" : "s"}`}
              </button>
              {showMore && <RowTable rows={more} testId={`${testId}-more`} {...rowProps} />}
            </div>
          )
        }
      >
        {(shownRows) => (
          <div className="column gap">
            {data ? (
              <div className="row gap wrap baseline">
                <span data-testid={`${testId}-summary`}>{matchingSummary(rows, data)}</span>
                {data.derived.regressions.length > 0 && (
                  <span className="tag bg-red text-white">
                    <InlineIcon icon={TriangleAlertIcon} />
                    {data.derived.regressions.length} regression
                    {data.derived.regressions.length === 1 ? "" : "s"}:{" "}
                    {data.derived.regressions.map((r) => `${r.attrpath} on ${r.branch}`).join(", ")}
                  </span>
                )}
              </div>
            ) : isError ? (
              <p className="rounded box bg-red-light">
                Failed to load versions and statuses: {getApiErrorMessage(error)}
              </p>
            ) : (
              <Skeleton width="12em" height="1.2em" />
            )}
            {data?.status === "published" && (
              <p className="text-gray" data-testid={`${testId}-published-note`}>
                Versions and statuses as the tracker sees them now; the published issue lists the
                packages as they were at publication.
              </p>
            )}
            {shownRows.length > 0 ? (
              <RowTable rows={shownRows} {...rowProps} />
            ) : (
              data && <p className="text-gray">No package shown.</p>
            )}
          </div>
        )}
      </CollectionCard>
    </div>
  );
}

/** Compact view: one line with the state, the summary and the names of the packages shown. */
export function MatchingInNixpkgsLine({ suggestion }: { suggestion: SuggestionType }) {
  const { id } = suggestion;
  const ref = useRef<HTMLDivElement>(null);
  const { data } = useSuggestionMatching(id, ref);
  const rows = packageRows(suggestion, data).filter((row) => row.shown && !row.ignored);
  const state = data?.derived.state ?? suggestion.derived_state;
  const names = rows.slice(0, 5).map((row) => row.attrpath);
  return (
    <div
      ref={ref}
      className="row gap-small wrap baseline"
      data-testid={`suggestion-${id}-packages-line`}
    >
      <span className="bold">
        <SuggestionSectionHeading section="packages" />:
      </span>
      {state && <DerivedStateBadge state={state} testId={`suggestion-${id}-derived-state`} />}
      {data && <span className="text-gray">{matchingSummary(rows, data)}</span>}
      <span className={styles.attrpath}>
        {names.join(", ")}
        {rows.length > names.length && ` +${rows.length - names.length}`}
      </span>
    </div>
  );
}
