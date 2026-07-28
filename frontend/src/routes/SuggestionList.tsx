import { useSearchParams } from "wouter-preact";
import { useListSuggestions } from "@/api/generated/endpoints";
import { Suggestion } from "@/components/suggestions/Suggestion";
import { Pagination } from "@/components/ui/Pagination";
import { Skeleton } from "@/components/ui/Skeleton";
import { getApiErrorMessage } from "@/utils/apiError";

// FIXME(@florentc): Hardcoded in the API for now, we should ultimately make it a query param
const PAGE_SIZE = 10;

function parsePage(searchParams: URLSearchParams): number {
  const raw = Number(searchParams.get("page"));
  return Number.isInteger(raw) && raw > 0 ? raw : 1;
}

export function SuggestionList() {
  const [searchParams, setSearchParams] = useSearchParams();
  const page = parsePage(searchParams);

  const { data, isLoading, isError, error } = useListSuggestions({ page });

  const handlePageChange = (newPage: number) => {
    setSearchParams((prev) => {
      const next = new URLSearchParams(prev);
      if (newPage <= 1) {
        next.delete("page");
      } else {
        next.set("page", String(newPage));
      }
      return next;
    });
    window.scrollTo({ top: 0 });
  };

  if (isLoading) {
    return (
      <div className="column gap-big">
        <div className="column gap">
          {Array.from({ length: PAGE_SIZE }).map((_, i) => (
            <Skeleton key={i} width="100%" height="20em" />
          ))}
        </div>
      </div>
    );
  }

  if (isError) {
    return (
      <p className="rounded box bg-red-light">
        Failed to load suggestions: {getApiErrorMessage(error)}
      </p>
    );
  }

  if (!data) {
    return null;
  }

  return (
    <div className="column gap-big centered">
      {data.results.length === 0 ? (
        <p>No suggestions found.</p>
      ) : (
        <div className="column gap-big">
          {data.results.map((suggestion) => (
            <Suggestion key={suggestion.id} suggestion={suggestion} />
          ))}
        </div>
      )}
      <Pagination
        page={page}
        count={data.count}
        pageSize={PAGE_SIZE}
        onPageChange={handlePageChange}
      />
    </div>
  );
}
