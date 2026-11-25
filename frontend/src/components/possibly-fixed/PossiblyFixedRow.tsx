import { FormatRelativeTime } from "@ark-ui/react";
import { ArrowRightIcon, CheckIcon, TriangleAlertIcon, XIcon } from "lucide-preact";
import { useState } from "preact/hooks";
import { Link } from "wouter-preact";
import type { PossiblyFixed } from "@/api/generated/models";
import { shortSha } from "@/components/matching/labels";
import { ExternalLink } from "@/components/ui/ExternalLink";
import { InlineIcon } from "@/components/ui/InlineIcon";
import { usePossiblyFixedActions } from "@/hooks/usePossiblyFixedActions";
import { suggestionPath } from "@/routes/paths";
import { formatTime } from "@/utils/date";
import styles from "./PossiblyFixedRow.module.css";

const SHA1 = /^[0-9a-f]{40}$/;

type Props = {
  row: PossiblyFixed;
  userCanEdit: boolean;
};

export function PossiblyFixedRow({ row, userCanEdit }: Props) {
  const { confirm, stillAffected, isPending } = usePossiblyFixedActions(row);
  const [confirming, setConfirming] = useState(false);
  const [fixCommit, setFixCommit] = useState("");
  const commit = fixCommit.trim().toLowerCase();
  const commitValid = commit === "" || SHA1.test(commit);

  function submitConfirm(event: Event) {
    event.preventDefault();
    if (!commitValid) return;
    confirm.mutate({ id: row.id, data: { fix_commit: commit || null } });
  }

  return (
    <>
      <tr data-testid={`possibly-fixed-${row.id}`}>
        <td>
          <Link href={suggestionPath(row.suggestion_id)}>{row.cve_id}</Link>
        </td>
        <td className={styles.attrpath}>
          <strong>{row.attrpath}</strong>
        </td>
        <td className="no-line-breaks">{row.branch}</td>
        <td className="monospace no-line-breaks">
          {row.old_version ?? "?"} <InlineIcon icon={ArrowRightIcon} label="to" />{" "}
          {row.new_version ?? "?"}
        </td>
        <td>
          {row.compare_url ? (
            <ExternalLink
              href={row.compare_url}
              title={`${row.last_affected_commit} → ${row.fixed_commit}`}
            >
              <span className="monospace">
                {row.last_affected_commit && shortSha(row.last_affected_commit)}…
                {shortSha(row.fixed_commit)}
              </span>
            </ExternalLink>
          ) : (
            <span className="monospace">{shortSha(row.fixed_commit)}</span>
          )}
        </td>
        <td>
          <time datetime={row.fixed_at} title={formatTime(row.fixed_at)}>
            <FormatRelativeTime value={new Date(row.fixed_at)} style="short" />
          </time>
        </td>
        {userCanEdit && (
          <td className="no-line-breaks">
            <div className="row gap-small">
              <button
                type="button"
                className="btn btn-green"
                disabled={isPending}
                aria-expanded={confirming}
                onClick={() => setConfirming((v) => !v)}
              >
                <InlineIcon icon={CheckIcon} pending={confirm.isPending} />
                Confirm fixed
              </button>
              <button
                type="button"
                className="btn btn-red"
                disabled={isPending}
                onClick={() => stillAffected.mutate({ id: row.id, data: {} })}
              >
                <InlineIcon icon={TriangleAlertIcon} pending={stillAffected.isPending} />
                Still affected
              </button>
            </div>
          </td>
        )}
      </tr>
      {userCanEdit && confirming && (
        <tr className={styles.formRow}>
          <td colSpan={7}>
            <form className="row gap-small wrap baseline" onSubmit={submitConfirm}>
              <label htmlFor={`fix-commit-${row.id}`}>Fix commit (optional)</label>
              <input
                id={`fix-commit-${row.id}`}
                type="text"
                className={`monospace ${styles.commitInput}`}
                placeholder="40-character commit sha"
                value={fixCommit}
                onInput={(e) => setFixCommit(e.currentTarget.value)}
                aria-invalid={!commitValid}
              />
              <button type="submit" className="btn btn-green" disabled={!commitValid || isPending}>
                <InlineIcon icon={CheckIcon} />
                Confirm
              </button>
              <button type="button" className="btn btn-gray" onClick={() => setConfirming(false)}>
                <InlineIcon icon={XIcon} />
                Cancel
              </button>
              {!commitValid && (
                <span className="text-gray">A full lowercase 40-character sha, or nothing.</span>
              )}
            </form>
          </td>
        </tr>
      )}
    </>
  );
}
