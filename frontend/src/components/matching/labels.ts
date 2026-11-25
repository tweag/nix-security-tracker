import {
  BanIcon,
  CircleCheckIcon,
  CircleDashedIcon,
  CircleHelpIcon,
  CircleMinusIcon,
  HistoryIcon,
  type LucideIcon,
  SearchIcon,
  ShieldAlertIcon,
  ShieldCheckIcon,
  TriangleAlertIcon,
} from "lucide-preact";
import type {
  DerivedStateEnum,
  EffectiveStatusStatusEnum,
  ExposureReasonEnum,
  MappingRef,
  MatchEvidence,
  VerdictKindEnum,
} from "@/api/generated/models";

/** Below this noisy-OR score, a candidate is folded away as low-confidence. */
export const LOW_CONFIDENCE_SCORE = 0.5;

const MATCHER_LABELS: Record<string, string> = {
  "nixpkgs-cpe": "CPE",
  "known-vuln": "known vulnerability",
  "repo-url": "repo URL",
  "name-exact": "name",
  "name-trigram": "name ≈",
  "name-prefix": "name prefix",
  "name-substring": "name contains",
  curated: "curated",
  rules: "rule",
  "legacy-v2": "legacy",
  manual: "manual",
};

/**
 * Short label of a matcher for a provenance chip, e.g. "name ≈ 0.82".
 * Unknown slugs (legacy or future matchers) are shown as they are.
 */
export function matcherLabel(matcher: string, evidence?: MatchEvidence | null): string {
  const label = MATCHER_LABELS[matcher] ?? matcher;
  if (matcher === "name-trigram" && evidence?.similarity != null) {
    return `${label} ${evidence.similarity.toFixed(2)}`;
  }
  return label;
}

const CVE_FIELD_LABELS: Record<string, string> = {
  cpe: "CPE",
  product: "product",
  package_name: "package name",
  repo: "repository",
  collection_url: "collection URL",
  vendor: "vendor",
  product_key: "product key",
};

const PKG_FIELD_LABELS: Record<string, string> = {
  pname: "pname",
  attrpath: "attribute path",
  cpe: "meta CPE",
  homepage: "homepage",
  known_vulnerabilities: "meta.knownVulnerabilities",
  name: "derivation name",
  attr_glob: "attribute glob",
};

const MAPPING_SOURCE_LABELS: Record<string, string> = {
  nixpkgs_meta: "nixpkgs metadata",
  triage: "triage",
  curated: "curated",
  rule_file: "rule file",
};

/** "cna:/foo → fo* (rule file)", "cna:/foo ≠ foo (triage)": what a mapping says, in a line. */
export function mappingLabel(mapping: MappingRef): string {
  const sign =
    mapping.relation === "not_same" ? "≠" : mapping.relation === "irrelevant" ? "∉ nixpkgs" : "→";
  const target = mapping.relation === "irrelevant" ? "" : ` ${mapping.target ?? "*"}`;
  const source = mapping.source
    ? ` (${MAPPING_SOURCE_LABELS[mapping.source] ?? mapping.source})`
    : "";
  return `${mapping.product_key ?? "?"} ${sign}${target}${source}`;
}

export function cveFieldLabel(field: string): string {
  return CVE_FIELD_LABELS[field] ?? field;
}

export function pkgFieldLabel(field: string): string {
  return PKG_FIELD_LABELS[field] ?? field;
}

type StatusInfo = { label: string; icon: LucideIcon; className: string };

// Each status has its own icon and word, so it reads without colour (#1508).
const STATUS_INFO: Record<EffectiveStatusStatusEnum, StatusInfo> = {
  affected: { label: "affected", icon: TriangleAlertIcon, className: "bg-red-light" },
  unaffected: { label: "unaffected", icon: CircleCheckIcon, className: "bg-green-light" },
  unknown: { label: "unknown", icon: CircleHelpIcon, className: "bg-yellow-light" },
  absent: { label: "absent", icon: CircleMinusIcon, className: "bg-gray-light" },
  fixed: { label: "fixed", icon: ShieldCheckIcon, className: "bg-green-light" },
  not_affected: { label: "not affected", icon: CircleCheckIcon, className: "bg-green-light" },
  irrelevant: { label: "irrelevant", icon: BanIcon, className: "bg-gray-light" },
  wontfix: { label: "won't fix", icon: CircleDashedIcon, className: "bg-yellow-light" },
};

export function statusInfo(status: EffectiveStatusStatusEnum): StatusInfo {
  return STATUS_INFO[status] ?? { label: status, icon: CircleHelpIcon, className: "" };
}

export const VERDICT_KINDS: VerdictKindEnum[] = [
  "affected",
  "not_affected",
  "fixed",
  "wontfix",
  "irrelevant",
];

export function verdictLabel(verdict: VerdictKindEnum): string {
  return statusInfo(verdict).label;
}

const REASON_LABELS: Record<ExposureReasonEnum, string> = {
  version_range: "version range",
  no_range: "no version range",
  unparseable: "unparseable range",
  acknowledged: "listed in meta.knownVulnerabilities",
  patch: "patched",
  removed: "removed",
  default_status: "default status",
};

export function reasonLabel(reason: ExposureReasonEnum | string): string {
  return REASON_LABELS[reason as ExposureReasonEnum] ?? reason;
}

type DerivedStateInfo = { label: string; icon: LucideIcon; className: string };

const DERIVED_STATE_INFO: Record<DerivedStateEnum, DerivedStateInfo> = {
  no_candidates: { label: "No candidates", icon: CircleMinusIcon, className: "bg-gray-light" },
  needs_triage: { label: "Needs triage", icon: SearchIcon, className: "bg-yellow-light" },
  possibly_fixed: { label: "Possibly fixed", icon: HistoryIcon, className: "bg-green-light" },
  tracking: { label: "Tracking", icon: ShieldAlertIcon, className: "bg-red-light" },
  resolved: { label: "Resolved", icon: ShieldCheckIcon, className: "bg-green-light" },
  dismissed: { label: "Dismissed", icon: BanIcon, className: "bg-gray-light" },
};

export const DERIVED_STATES = Object.keys(DERIVED_STATE_INFO) as DerivedStateEnum[];

export function derivedStateInfo(state: DerivedStateEnum): DerivedStateInfo {
  return DERIVED_STATE_INFO[state];
}

/** Short form of a commit sha. */
export function shortSha(sha: string): string {
  return sha.slice(0, 10);
}
