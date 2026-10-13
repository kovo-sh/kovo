import type { Severity, SeverityReason, SeveritySource } from "@kovo/contracts";

import { scoreCvssEntry, type CvssScoring, type CvssVersion } from "./cvss/index.js";

// SPEC "Severity source": "Prefer the GHSA `database_specific.severity` label when present;
// otherwise derive severity from the highest supported CVSS v4/v3 vector: ≥ 9.0 Critical, ≥ 7.0
// High, ≥ 4.0 Medium, else Low. Missing/invalid severity remains `UNKNOWN` … Record the source and
// parsing reason."

/** GHSA labels (GitHub writes `MODERATE` where SPEC and CVSS say `MEDIUM`). */
const GHSA_LABELS: Readonly<Record<string, { severity: Severity; reason: SeverityReason }>> = {
  CRITICAL: { severity: "CRITICAL", reason: "ghsa_label" },
  HIGH: { severity: "HIGH", reason: "ghsa_label" },
  MODERATE: { severity: "MEDIUM", reason: "ghsa_label_moderate" },
  MEDIUM: { severity: "MEDIUM", reason: "ghsa_label" },
  LOW: { severity: "LOW", reason: "ghsa_label" },
};

/** SPEC's thresholds; a 0.0 score is Low ("else Low"), unlike CVSS's own `None`. */
export function severityFromScore(score: number): Exclude<Severity, "UNKNOWN"> {
  if (score >= 9) return "CRITICAL";
  if (score >= 7) return "HIGH";
  if (score >= 4) return "MEDIUM";
  return "LOW";
}

export interface SeverityEntry {
  readonly type: string;
  readonly score: string;
}

export interface SeverityInput {
  /** Whether the record is a GitHub advisory (`GHSA-…`): only GHSA labels are honoured. */
  readonly isGhsa: boolean;
  /** `database_specific.severity` as published (any JSON value), or undefined when absent. */
  readonly label: unknown;
  /** Every `severity[]` entry of the record and of its npm `affected[]` entries. */
  readonly entries: readonly SeverityEntry[];
}

/** How one severity entry was assessed (sanitized: type, outcome and score only). */
export type VectorAssessment =
  | {
      readonly type: string;
      readonly outcome: "scored";
      readonly version: CvssVersion;
      readonly score: number;
    }
  | { readonly type: string; readonly outcome: "invalid" | "unsupported" };

export interface SeverityAssessment {
  readonly severity: Severity;
  readonly source: SeveritySource;
  readonly reason: SeverityReason;
  /**
   * The highest-scoring valid supported vector and its score, whatever decided the severity (the
   * advisory keeps its CVSS score next to a GHSA label); absent when no vector scored.
   */
  readonly score?: number;
  readonly vector?: string;
  /** What happened to `database_specific.severity`: used, invalid, absent, or ignored (not GHSA). */
  readonly label: "used" | "invalid" | "absent" | "not_ghsa";
  readonly assessments: readonly VectorAssessment[];
}

function assess(entry: SeverityEntry): { scoring: CvssScoring; assessment: VectorAssessment } {
  const scoring = scoreCvssEntry(entry.type, entry.score);
  if (scoring.outcome === "scored") {
    return {
      scoring,
      assessment: {
        type: entry.type,
        outcome: "scored",
        version: scoring.version,
        score: scoring.score,
      },
    };
  }
  return { scoring, assessment: { type: entry.type, outcome: scoring.outcome } };
}

/**
 * Derives an advisory's severity. Order: a valid GHSA label; else the highest score among valid
 * CVSS v4.0/v3.x vectors (a v4 vector wins a tie with a v3 one); else UNKNOWN with the most
 * specific reason (`invalid_label` > `invalid_vector` > `unsupported_vector` > `missing`).
 */
export function deriveSeverity(input: SeverityInput): SeverityAssessment {
  const assessed = input.entries.map(assess);
  let best: Extract<CvssScoring, { outcome: "scored" }> | null = null;
  for (const { scoring } of assessed) {
    if (scoring.outcome !== "scored") continue;
    const better =
      best === null ||
      scoring.score > best.score ||
      (scoring.score === best.score && scoring.version === "4.0" && best.version !== "4.0");
    if (better) best = scoring;
  }
  const assessments = assessed.map(({ assessment }) => assessment);
  const cvss = best === null ? {} : { score: best.score, vector: best.vector };

  const published = input.label !== undefined && input.label !== null;
  const labelPresent = input.isGhsa && published;
  const label =
    labelPresent && typeof input.label === "string" && Object.hasOwn(GHSA_LABELS, input.label)
      ? GHSA_LABELS[input.label]
      : undefined;
  if (label !== undefined) {
    return {
      severity: label.severity,
      source: "ghsa_label",
      reason: label.reason,
      ...cvss,
      label: "used",
      assessments,
    };
  }
  const labelOutcome = labelPresent ? "invalid" : published ? "not_ghsa" : "absent";
  if (best !== null) {
    return {
      severity: severityFromScore(best.score),
      source: best.version === "4.0" ? "cvss_v4" : "cvss_v3",
      reason: "cvss_highest",
      ...cvss,
      label: labelOutcome,
      assessments,
    };
  }
  const reason: SeverityReason = labelPresent
    ? "invalid_label"
    : assessments.some((a) => a.outcome === "invalid")
      ? "invalid_vector"
      : assessments.some((a) => a.outcome === "unsupported")
        ? "unsupported_vector"
        : "missing";
  return { severity: "UNKNOWN", source: "none", reason, label: labelOutcome, assessments };
}
