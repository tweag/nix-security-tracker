import type { ComponentChildren } from "preact";
import type { TrackerChange, TrackerEventCauseEnum } from "@/api/generated/models";
import {
  mappingLabel,
  matcherLabel,
  reasonLabel,
  shortSha,
  statusInfo,
  verdictLabel,
} from "./labels";

// The action a verdict came with, as the events record it.
const VIA_LABELS: Record<string, string> = {
  accept: "by accepting the suggestion",
  publish: "by publishing the suggestion",
  reject: "by dismissing the suggestion",
};

function Attr({ name }: { name: string }) {
  return <code>{name}</code>;
}

function versions(c: TrackerChange): ComponentChildren {
  if (c.old_version && c.new_version && c.old_version !== c.new_version) {
    return (
      <>
        {c.old_version} → {c.new_version}
      </>
    );
  }
  return c.new_version ?? c.old_version ?? "";
}

function where(c: TrackerChange): ComponentChildren {
  return c.branch ? (
    <>
      {" "}
      on <strong>{c.branch}</strong>
    </>
  ) : (
    " on all branches"
  );
}

/** Why the status is what it is now, in words. */
function outcome(c: TrackerChange): string {
  const inferred = c.inferred ? " (inferred)" : "";
  if (c.new_status === "unaffected") {
    return c.new_reason === "version_range"
      ? `now outside the affected range${inferred}`
      : `now unaffected (${reasonLabel(c.new_reason ?? "")})${inferred}`;
  }
  if (c.new_status === "affected") {
    return c.new_reason === "acknowledged"
      ? "now listed in meta.knownVulnerabilities"
      : "now inside the affected range";
  }
  if (c.new_status === "unknown") return `status unknown (${reasonLabel(c.new_reason ?? "")})`;
  return c.new_status ? statusInfo(c.new_status).label : "";
}

/** One change, phrased like the design's examples: "`foo` on `release-26.05`: 1.2.3 → 1.2.5, now outside the affected range". */
export function phraseChange(c: TrackerChange): ComponentChildren {
  const attr = <Attr name={c.attrpath} />;
  const via = c.matcher ? matcherLabel(c.matcher, c.evidence) : "";
  switch (c.kind) {
    case "match_added":
      return (
        <>
          + {attr} via {via}
        </>
      );
    case "match_retracted":
      return c.vetoed_by ? (
        <>
          − {attr} ({via}) removed by mapping <code>{mappingLabel(c.vetoed_by)}</code>
        </>
      ) : (
        <>
          − {attr} no longer matched by {via}
        </>
      );
    case "match_restored":
      return (
        <>
          {attr} matched again by {via}
        </>
      );
    case "match_changed":
      return (
        <>
          {attr}: {via} score {c.old_score?.toFixed(2)} → {c.score?.toFixed(2)}
        </>
      );
    case "exposure_appeared":
      return (
        <>
          {attr}
          {where(c)}: {c.new_version}, {outcome(c)}
        </>
      );
    case "exposure_version_changed":
      return (
        <>
          {attr}
          {where(c)}: {versions(c)}
        </>
      );
    case "exposure_became_unaffected":
    case "exposure_became_affected":
    case "exposure_status_changed":
      return (
        <>
          {attr}
          {where(c)}: {versions(c)}, {outcome(c)}
          {c.new_reason === "patch" && c.fix_commit && (
            <>
              {" "}
              by <code>{shortSha(c.fix_commit)}</code>
            </>
          )}
          {c.regression && ", a regression after a fix"}
        </>
      );
    case "exposure_disappeared":
      return (
        <>
          {attr} no longer present{where(c)}
        </>
      );
    case "exposure_reappeared":
      return (
        <>
          {attr} back{where(c)} at {c.new_version}, {outcome(c)}
        </>
      );
    case "verdict_set":
      return (
        <>
          {attr}
          {where(c)}: {c.verdict && verdictLabel(c.verdict)}
          {c.via && VIA_LABELS[c.via] && <>, {VIA_LABELS[c.via]}</>}
          {c.comment && <> — “{c.comment}”</>}
        </>
      );
    case "verdict_changed":
      return (
        <>
          {attr}
          {where(c)}: {c.old_verdict && verdictLabel(c.old_verdict)} →{" "}
          {c.verdict && verdictLabel(c.verdict)}
        </>
      );
    case "verdict_removed":
      return (
        <>
          {attr}
          {where(c)}: verdict {c.old_verdict && verdictLabel(c.old_verdict)} cleared
          {c.via && VIA_LABELS[c.via] && <>, {VIA_LABELS[c.via]}</>}
        </>
      );
    case "fix_link_added":
      return (
        <>
          linked {pullRequest(c)} as a fix for {attr}
          {where(c)}
        </>
      );
    case "fix_link_retracted":
      return (
        <>
          unlinked {pullRequest(c)} as a fix for {attr}
          {where(c)}
        </>
      );
    case "exposure_fix_commit_set":
      return (
        <>
          {attr}
          {where(c)}: fix commit set to <code>{c.fix_commit && shortSha(c.fix_commit)}</code>
          {c.pull_request !== null && <>, from {pullRequest(c)}</>}
        </>
      );
    case "fix_landed":
      return (
        <>
          fix for {attr}
          {where(c)} landed in <strong>{c.channel}</strong>
        </>
      );
    default: {
      // Exhaustive over the generated enum, so a new kind fails the type check; an unknown
      // kind from a newer server still renders.
      const unknown: never = c.kind;
      return (
        <>
          {attr}: {String(unknown)}
        </>
      );
    }
  }
}

/** "#4242", linked to the pull request when the repository is known. */
function pullRequest(c: TrackerChange): ComponentChildren {
  if (c.pull_request === null) return "a pull request";
  const label = `#${c.pull_request}`;
  return c.repository ? (
    <a
      href={`https://github.com/${c.repository}/pull/${c.pull_request}`}
      title={c.title ?? undefined}
      target="_blank"
      rel="noreferrer"
    >
      {label}
    </a>
  ) : (
    label
  );
}

const MATCH_KINDS = new Set(["match_added", "match_retracted", "match_restored", "match_changed"]);

/**
 * A one-line summary of a batch: "+2 packages via name ≈, −1 via name contains"
 * for matches, the phrased change when there is only one, else counts by kind.
 */
export function summariseChanges(changes: TrackerChange[]): ComponentChildren {
  if (changes.length === 1) return phraseChange(changes[0]);
  if (changes.every((c) => MATCH_KINDS.has(c.kind))) {
    const groups = new Map<string, number>();
    for (const c of changes) {
      const sign = c.kind === "match_retracted" ? "−" : c.kind === "match_added" ? "+" : "~";
      const label = c.vetoed_by
        ? `mapping ${mappingLabel(c.vetoed_by)}`
        : c.matcher
          ? matcherLabel(c.matcher)
          : "?";
      const key = `${sign}\u0000${label}`;
      groups.set(key, (groups.get(key) ?? 0) + 1);
    }
    return [...groups.entries()]
      .map(([key, n]) => {
        const [sign, label] = key.split("\u0000");
        const how = label.startsWith("mapping ") ? "removed by" : "via";
        return `${sign}${n} package${n === 1 ? "" : "s"} ${how} ${label}`;
      })
      .join(", ");
  }
  const attrs = new Set(changes.map((c) => c.attrpath));
  const branches = new Set(changes.map((c) => c.branch).filter(Boolean));
  return `${changes.length} changes to ${attrs.size} package${attrs.size === 1 ? "" : "s"}${
    branches.size > 0 ? ` on ${[...branches].join(", ")}` : ""
  }`;
}

const CAUSE_LABELS: Record<TrackerEventCauseEnum, string> = {
  evaluation: "new evaluation",
  cve_update: "CVE update",
  matcher: "matcher run",
  mapping: "product mapping",
  user: "user",
  backfill: "backfill",
  channel: "channel advance",
  github: "GitHub",
};

export function causeLabel(cause: TrackerEventCauseEnum): string {
  return CAUSE_LABELS[cause] ?? cause;
}
