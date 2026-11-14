import type { ReportFormat, Sha256Hex, TestCounts } from "@kovo/contracts";

// Reporter files come out of an untrusted sandbox (SPEC "Sandbox B": "Reporter files originate in
// an untrusted sandbox: reading JSON from the control plane does not make it trustworthy"). Parsers
// therefore return only counts, flags and the file's SHA-256 — never test names, messages, paths
// or any other text from the report — and every limit below is enforced before work proportional
// to hostile input is done.

export const REPORT_LIMITS = {
  /** The sandbox port's bounded read (`SANDBOX_READ_MAX_BYTES`, 16 MiB). */
  maxBytes: 16 * 1024 * 1024,
  /** JSON nesting accepted before parsing (real reports nest about six levels). */
  maxJsonDepth: 64,
  /** Individual test results per report. */
  maxTests: 200_000,
  /** Test files per report. */
  maxFiles: 50_000,
  /** TAP lines per report. */
  maxTapLines: 2_000_000,
  /** TAP subtest nesting depth. */
  maxTapDepth: 32,
} as const;

/**
 * Test counts from a report. `total = passed + failed + skipped + todo`; `executed` tests are the
 * ones that ran to a verdict (`passed + failed`).
 */
export interface ReportCounts {
  readonly total: number;
  readonly passed: number;
  readonly failed: number;
  readonly skipped: number;
  readonly todo: number;
}

/** Why a report could not be used. */
export type ReportParseError =
  | "empty"
  | "too_large"
  | "invalid_utf8"
  | "invalid_json"
  | "too_deep"
  | "schema_mismatch"
  | "too_many_tests"
  /** The report contradicts itself (summary totals versus individual results). */
  | "inconsistent_counts"
  | "tap_missing_plan"
  | "tap_plan_mismatch"
  | "tap_bad_numbering"
  | "tap_bad_indentation"
  | "tap_unterminated_yaml"
  | "tap_truncated_subtest";

export type ParsedReport =
  | {
      readonly ok: true;
      readonly format: ReportFormat;
      readonly counts: ReportCounts;
      /** Test files or suites that failed outside any individual test (e.g. an import error). */
      readonly failedSuites: number;
      /** The run was interrupted (`Bail out!`, an interrupted Jest run, unfinished tests). */
      readonly aborted: boolean;
      /**
       * The report itself says the run failed (Vitest/Jest `success: false` for a non-empty run,
       * or failed suites in the summary), whatever its individual results show.
       */
      readonly reportedFailure: boolean;
      readonly sha256: Sha256Hex;
    }
  | {
      readonly ok: false;
      readonly format: ReportFormat;
      readonly error: ReportParseError;
      /** Null only when the report exceeded the size bound before it was hashed. */
      readonly sha256: Sha256Hex | null;
    };

/** Tests that ran to a verdict. */
export function executedTests(counts: ReportCounts): number {
  return counts.passed + counts.failed;
}

/**
 * The contracts' `TestCounts` for a sanitized step result. Contracts count `todo` tests as
 * skipped (`passed + failed + skipped = total`).
 */
export function toTestCounts(counts: ReportCounts): TestCounts {
  return {
    total: counts.total,
    passed: counts.passed,
    failed: counts.failed,
    skipped: counts.skipped + counts.todo,
  };
}
