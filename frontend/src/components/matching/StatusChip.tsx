import { GavelIcon, TriangleAlertIcon } from "lucide-preact";
import type {
  AttributeBranch,
  EvaluationRef,
  MatchedAttribute,
  SuggestionMatchingEvaluations,
} from "@/api/generated/models";
import { InlineIcon } from "@/components/ui/InlineIcon";
import { Tooltip } from "@/components/ui/Tooltip";
import { cx } from "@/utils/className";
import { formatTime } from "@/utils/date";
import { reasonLabel, shortSha, statusInfo, verdictLabel } from "./labels";
import styles from "./Matching.module.css";

type Props = {
  attribute: MatchedAttribute;
  cell: AttributeBranch;
  evaluations: SuggestionMatchingEvaluations;
};

function EvaluationLine({ label, evaluation }: { label: string; evaluation?: EvaluationRef }) {
  if (!evaluation) return null;
  return (
    <li>
      {label}: <span className="monospace">{shortSha(evaluation.commit_sha1)}</span> (
      {formatTime(evaluation.created_at)})
    </li>
  );
}

/** Why the cell says what it says: the observation, the classifier's reasoning and the verdict. */
function StatusDetails({ attribute, cell, evaluations }: Props) {
  const { exposure, effective } = cell;
  const evaluation = (id: number | null) => (id === null ? undefined : evaluations[String(id)]);
  const verdict = attribute.verdicts.find(
    (v) => effective?.source === "verdict" && v.branch === effective.verdict_branch,
  );
  return (
    <div className={cx("column gap-small", styles.details)}>
      {effective?.source === "verdict" && verdict && (
        <div>
          <strong>Verdict</strong> {verdictLabel(verdict.verdict)}{" "}
          {verdict.branch ? `on ${verdict.branch}` : "on all branches"}
          {verdict.author && <> by @{verdict.author}</>}
          {verdict.fix_commit && (
            <>
              , fix <span className="monospace">{shortSha(verdict.fix_commit)}</span>
            </>
          )}
          {verdict.comment && <div>“{verdict.comment}”</div>}
        </div>
      )}
      {exposure ? (
        <div>
          <strong>Observed</strong> {statusInfo(exposure.observed).label}
          {exposure.version && (
            <>
              {" "}
              at <span className="monospace">{exposure.version}</span>
            </>
          )}{" "}
          ({reasonLabel(exposure.reason)}
          {exposure.detail.inferred && ", inferred: no default status, outside every range"})
          {exposure.detail.detail && <div className="monospace">{exposure.detail.detail}</div>}
          {exposure.detail.patch_commit && (
            <div>
              patched by <span className="monospace">{shortSha(exposure.detail.patch_commit)}</span>
            </div>
          )}
          <ul className={styles.plainList}>
            {exposure.detail.last_affected_version &&
              exposure.observed !== "affected" &&
              exposure.detail.last_affected_version !== exposure.version && (
                <li>
                  last affected version:{" "}
                  <span className="monospace">{exposure.detail.last_affected_version}</span>
                </li>
              )}
            <EvaluationLine
              label="first seen affected"
              evaluation={evaluation(exposure.first_affected_evaluation)}
            />
            <EvaluationLine
              label="first seen fixed"
              evaluation={evaluation(exposure.fixed_evaluation)}
            />
            <EvaluationLine label="state since" evaluation={evaluation(exposure.evaluation)} />
          </ul>
        </div>
      ) : (
        <div>Never seen on {cell.branch}.</div>
      )}
      {effective?.regression && (
        <div>
          <strong>Regression:</strong> marked fixed, but observed affected again since.
        </div>
      )}
    </div>
  );
}

/**
 * Effective status of an attribute on a branch.
 * A human verdict has a solid border and a gavel; an observation has a dashed border.
 * Icon and word carry the status, so it reads without colour (#1508).
 */
export function StatusChip({ attribute, cell, evaluations }: Props) {
  const { exposure, effective } = cell;
  if (!effective) {
    return (
      <span className="text-gray" title={`Not seen on ${cell.branch}`}>
        —
      </span>
    );
  }
  const { label, icon, className } = statusInfo(effective.status);
  const decided = effective.source === "verdict";
  const observedDiffers = decided && exposure && exposure.observed !== effective.status;

  return (
    <div className="column gap-small">
      <Tooltip
        content={<StatusDetails attribute={attribute} cell={cell} evaluations={evaluations} />}
      >
        <button
          type="button"
          className={cx(
            "tag border no-line-breaks",
            className,
            decided ? styles.decided : "border-dashed",
          )}
          data-testid={`status-${attribute.attrpath}-${cell.branch}`}
          aria-label={`${attribute.attrpath} on ${cell.branch}: ${label}${
            decided ? " (verdict)" : " (observed)"
          }`}
        >
          {effective.source === "verdict" && <InlineIcon icon={GavelIcon} label="verdict" />}
          <InlineIcon icon={icon} />
          {label}
          {effective.source === "observed" && exposure?.detail.inferred && " (inferred)"}
          {effective.source === "observed" && exposure?.reason === "patch" && " (patched)"}
        </button>
      </Tooltip>
      {effective.regression && (
        <span className="tag bg-red text-white no-line-breaks">
          <InlineIcon icon={TriangleAlertIcon} />
          regression
        </span>
      )}
      <span className={cx("monospace", styles.version)}>
        {exposure?.version ?? ""}
        {exposure && !exposure.present && " (gone)"}
      </span>
      {observedDiffers && (
        <span className="text-gray">observed {statusInfo(exposure.observed).label}</span>
      )}
    </div>
  );
}
