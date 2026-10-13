import { z } from "zod";

import type { Tier } from "../tier.js";

// Advisories, tiering and findings (SPEC "Tiers", "Severity source", "Inventory, advisories, and
// tiering"). The tier tuple itself lives in `tier.ts`.

/** Tiers that produce fix workflows ("Digest … no automatic fix PR"). */
export const FIX_TIERS = ["P0", "P1"] as const satisfies readonly Tier[];
export const fixTierSchema = z.enum(FIX_TIERS);
export type FixTier = z.infer<typeof fixTierSchema>;

/** SPEC severity labels, as `tier()` compares them (`'HIGH'`, `'CRITICAL'`), plus `UNKNOWN`. */
export const SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"] as const;
export const severitySchema = z.enum(SEVERITIES);
export type Severity = z.infer<typeof severitySchema>;

/**
 * Where a severity came from: "Prefer the GHSA `database_specific.severity` label when present;
 * otherwise derive severity from the highest supported CVSS v4/v3 vector". `none` pairs with
 * `UNKNOWN`.
 */
export const SEVERITY_SOURCES = ["ghsa_label", "cvss_v4", "cvss_v3", "none"] as const;
export const severitySourceSchema = z.enum(SEVERITY_SOURCES);
export type SeveritySource = z.infer<typeof severitySourceSchema>;

/**
 * The recorded parsing reason ("Record the source and parsing reason"):
 * - `ghsa_label`: the label was used as-is; `ghsa_label_moderate`: GHSA's `MODERATE` became `MEDIUM`.
 * - `cvss_highest`: no usable label; the highest supported vector's score decided.
 * - `invalid_label`, `invalid_vector`, `unsupported_vector` (e.g. CVSS v2 only), `missing`: why the
 *   result is `UNKNOWN`.
 */
export const SEVERITY_REASONS = [
  "ghsa_label",
  "ghsa_label_moderate",
  "cvss_highest",
  "invalid_label",
  "invalid_vector",
  "unsupported_vector",
  "missing",
] as const;
export const severityReasonSchema = z.enum(SEVERITY_REASONS);
export type SeverityReason = z.infer<typeof severityReasonSchema>;

/**
 * Why `tier()` produced its result, one per branch of SPEC's `tier()` function, in its order.
 */
export const TIER_REASONS = [
  "malicious",
  "dev_dependency",
  "kev",
  "not_high_or_critical",
  "curated_package_and_cwe",
  "high_or_critical",
] as const;
export const tierReasonSchema = z.enum(TIER_REASONS);
export type TierReason = z.infer<typeof tierReasonSchema>;

/** The tier each `tier()` branch returns. */
export const TIER_REASON_TIER = {
  malicious: "P0",
  dev_dependency: "digest",
  kev: "P0",
  not_high_or_critical: "digest",
  curated_package_and_cwe: "P0",
  high_or_critical: "P1",
} as const satisfies Record<TierReason, Tier>;

/** "Malicious-package and production KEV matches are independent P0 triggers" (plus the heuristic). */
export const P0_TRIGGERS = [
  "malicious",
  "kev",
  "curated_package_and_cwe",
] as const satisfies readonly TierReason[];
export const p0TriggerSchema = z.enum(P0_TRIGGERS);
export type P0Trigger = z.infer<typeof p0TriggerSchema>;

/**
 * How an advisory was recognized as malicious: an OpenSSF `MAL-` ID, a GHSA aliasing a `MAL-` ID,
 * or a GHSA carrying CWE-506 (docs/libraries/sandbox-ai-feeds.md §5.2).
 */
export const MALICIOUS_REASONS = ["mal_id", "mal_alias", "cwe_506"] as const;
export const maliciousReasonSchema = z.enum(MALICIOUS_REASONS);
export type MaliciousReason = z.infer<typeof maliciousReasonSchema>;

/** `advisories.ecosystem`: the MVP covers the public npm registry only. */
export const ADVISORY_ECOSYSTEMS = ["npm"] as const;
export const advisoryEcosystemSchema = z.enum(ADVISORY_ECOSYSTEMS);
export type AdvisoryEcosystem = z.infer<typeof advisoryEcosystemSchema>;

/** `advisory_ranges.range_type` (OSV range types). */
export const ADVISORY_RANGE_TYPES = ["SEMVER", "ECOSYSTEM", "GIT"] as const;
export const advisoryRangeTypeSchema = z.enum(ADVISORY_RANGE_TYPES);
export type AdvisoryRangeType = z.infer<typeof advisoryRangeTypeSchema>;

/** OSV range event kinds. */
export const ADVISORY_RANGE_EVENT_KINDS = [
  "introduced",
  "fixed",
  "last_affected",
  "limit",
] as const;
export const advisoryRangeEventKindSchema = z.enum(ADVISORY_RANGE_EVENT_KINDS);
export type AdvisoryRangeEventKind = z.infer<typeof advisoryRangeEventKindSchema>;

/** Advisory feeds (`pollOsv`, `pollKev`). */
export const ADVISORY_FEEDS = ["osv", "kev"] as const;
export const advisoryFeedSchema = z.enum(ADVISORY_FEEDS);
export type AdvisoryFeed = z.infer<typeof advisoryFeedSchema>;

/** `findings.status` ("open|resolved|dismissed|withdrawn"). */
export const FINDING_STATUSES = ["open", "resolved", "dismissed", "withdrawn"] as const;
export const findingStatusSchema = z.enum(FINDING_STATUSES);
export type FindingStatus = z.infer<typeof findingStatusSchema>;

/**
 * `findings.dismiss_reason` ("reason required; affected-version scope"). `other` requires the
 * free-text note the dismiss route accepts.
 */
export const DISMISS_REASONS = [
  "false_positive",
  "not_exploitable",
  "risk_accepted",
  "mitigated_elsewhere",
  "other",
] as const;
export const dismissReasonSchema = z.enum(DISMISS_REASONS);
export type DismissReason = z.infer<typeof dismissReasonSchema>;
