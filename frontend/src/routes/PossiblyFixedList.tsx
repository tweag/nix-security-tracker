import { GitBranchIcon } from "lucide-preact";
import { useListPossiblyFixed, useListPossiblyFixedBranches } from "@/api/generated/endpoints";
import { PossiblyFixedRow } from "@/components/possibly-fixed/PossiblyFixedRow";
import { nextToggleSelection } from "@/components/suggestions/SuggestionFilters";
import { InlineIcon } from "@/components/ui/InlineIcon";
import { Pagination } from "@/components/ui/Pagination";
import { PillToggleGroup, type ToggleGroupOption } from "@/components/ui/PillToggleGroup";
import { Skeleton } from "@/components/ui/Skeleton";
import { useAuth } from "@/hooks/useAuth";
import { useFilterParams } from "@/hooks/useFilterParams";
import { usePageParam } from "@/hooks/usePageParam";
import { getApiErrorMessage } from "@/utils/apiError";
import type { ParamsUpdate } from "@/utils/searchParams";
import styles from "./PossiblyFixedList.module.css";

// The page size of the API, as for the suggestion list.
const PAGE_SIZE = 10;

const withBranches =
  (branches: string[]): ParamsUpdate =>
  (params) => {
    const next = new URLSearchParams(params);
    next.delete("branch");
    for (const branch of branches) next.append("branch", branch);
    return next;
  };

/**
 * Exposures that were affected and are now observed unaffected, waiting for a human to
 * confirm the fix or say the attribute is still affected.
 */
export function PossiblyFixedList() {
  const [filterParams, updateFilterParams] = useFilterParams();
  const [page, handlePageChange] = usePageParam();
  const branches = filterParams.getAll("branch");
  const { user } = useAuth();
  const userCanEdit = Boolean(user?.is_committer || user?.is_admin);

  const { data: branchCounts } = useListPossiblyFixedBranches();
  const { data, isLoading, isError, error } = useListPossiblyFixed({
    page,
    branch: branches.length > 0 ? branches : undefined,
  });

  const options: ToggleGroupOption[] = (branchCounts ?? []).map(({ name, count }) => ({
    value: name,
    label: (
      <>
        <InlineIcon icon={GitBranchIcon} />
        {name} ({count})
      </>
    ),
  }));

  return (
    <div className="column gap-big centered" data-testid="possibly-fixed">
      <div className="column gap full-width">
        <h1 className="text-l bold">Possibly fixed</h1>
        <p>
          Packages that were in an affected version range and are now outside of it. Confirm the
          fix, or say the package is still affected (for instance when the range is wrong).
        </p>
        <div data-testid="possibly-fixed-branch-filter">
          <PillToggleGroup
            value={branches}
            options={options}
            onItemClick={(clicked, event) =>
              updateFilterParams(withBranches(nextToggleSelection(branches, clicked, event)))
            }
          />
        </div>
      </div>

      {isLoading && <Skeleton width="100%" height="20em" />}

      {isError && (
        <p className="rounded box bg-red-light">
          Failed to load the queue: {getApiErrorMessage(error)}
        </p>
      )}

      {data &&
        (data.results.length === 0 ? (
          <p>Nothing to confirm.</p>
        ) : (
          <>
            <div className="full-width box">
              <table className={styles.table}>
                <thead>
                  <tr>
                    <th>CVE</th>
                    <th>Package</th>
                    <th>Branch</th>
                    <th>Version</th>
                    <th>Changes</th>
                    <th>Seen</th>
                    {userCanEdit && <th>Decision</th>}
                  </tr>
                </thead>
                <tbody>
                  {data.results.map((row) => (
                    <PossiblyFixedRow key={row.id} row={row} userCanEdit={userCanEdit} />
                  ))}
                </tbody>
              </table>
            </div>
            <Pagination
              page={page}
              count={data.count}
              pageSize={PAGE_SIZE}
              onPageChange={handlePageChange}
            />
          </>
        ))}
    </div>
  );
}
