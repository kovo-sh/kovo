import {
  DEPENDENCY_VERDICTS,
  type DependencyVerdictChangeWire,
  type DependencyVerdictKind,
  type DependencyVerdictWire,
} from "@kovo/contracts";

import { CliError } from "../errors.js";
import { EXIT, type ExitCode } from "../exit.js";
import type { UnsupportedLockfile } from "./change-list.js";

// What `kovo deps check` prints. Only identifiers: package names and versions, verdicts, reason
// codes, wait-end times, counts, commits and the lockfile's path. `--format json` is a stable,
// versioned shape (`version: 1`); fields are only ever added.

export const JSON_FORMAT = "kovo-deps-check";
export const JSON_FORMAT_VERSION = 1;
/** Text output lists at most this many packages, then "and N more". */
export const TEXT_LIST_LIMIT = 100;

export type CheckMode = "online" | "offline";

export interface CheckContext {
  readonly mode: CheckMode;
  /** The lockfile's path relative to the repository root. */
  readonly lockfile: string | null;
  readonly base: string | null;
  /** How the base was chosen: `--base`, or the merge base with the named default branch. */
  readonly baseFrom: string | null;
  /** The head commit; null for the working tree. */
  readonly head: string | null;
}

export interface CheckReport extends CheckContext {
  readonly changes: readonly DependencyVerdictChangeWire[];
  /** Aligned with `changes`. */
  readonly verdicts: readonly DependencyVerdictWire[];
  readonly unavailableSignals: readonly string[];
  /** Offline: the OSV snapshot judged against; null online or when nothing changed. */
  readonly osvSnapshot: {
    readonly generation: string;
    readonly sha256: string;
    readonly cached: boolean;
  } | null;
}

/** Printed on every offline run, first after the context line. */
export const OFFLINE_NOTICE = "offline: Kovo holds not consulted";

const SEVERITY: ReadonlyMap<DependencyVerdictKind, number> = new Map(
  DEPENDENCY_VERDICTS.map((verdict, index) => [verdict, index]),
);

/** 1 when any version is `block` or `wait`, otherwise 0. */
export function verdictExitCode(
  verdicts: readonly Pick<DependencyVerdictWire, "verdict">[],
): ExitCode {
  return verdicts.some((v) => v.verdict === "block" || v.verdict === "wait")
    ? EXIT.fail
    : EXIT.pass;
}

function counts(verdicts: readonly DependencyVerdictWire[]): Record<DependencyVerdictKind, number> {
  const out: Record<DependencyVerdictKind, number> = { allow: 0, warn: 0, wait: 0, block: 0 };
  for (const verdict of verdicts) out[verdict.verdict] += 1;
  return out;
}

function headLabel(head: string | null): string {
  return head === null ? "working tree" : head.slice(0, 12);
}

function contextLine(context: CheckContext): string {
  const base =
    context.base === null
      ? "unknown base"
      : `base ${context.base.slice(0, 12)}${context.baseFrom === null ? "" : ` (${context.baseFrom})`}`;
  const offline = context.mode === "offline" ? " offline" : "";
  return `kovo deps check${offline}: ${context.lockfile ?? "no lockfile"}, ${base}, head ${headLabel(context.head)}`;
}

function verdictLine(verdict: DependencyVerdictWire): string {
  const reasons = verdict.reasons.length === 0 ? "" : `  ${verdict.reasons.join(", ")}`;
  const until = verdict.wait_until === null ? "" : `  until ${verdict.wait_until.toISOString()}`;
  return `  ${verdict.verdict.padEnd(5)}  ${verdict.name}@${verdict.version}${reasons}${until}`;
}

/**
 * The text report: one line per changed package, most severe first, then the outcome. `heading`
 * replaces the context line (the package-manager wrappers name their own sides).
 */
export function renderText(report: CheckReport, heading?: string): string {
  const lines = [heading ?? contextLine(report)];
  if (report.mode === "offline") lines.push(OFFLINE_NOTICE);
  if (report.osvSnapshot !== null)
    lines.push(
      `OSV snapshot: generation ${report.osvSnapshot.generation}, SHA-256 ${report.osvSnapshot.sha256}` +
        (report.osvSnapshot.cached ? " (cached)" : ""),
    );
  if (report.verdicts.length === 0) {
    lines.push("No changed or new dependency versions.", "Passed (exit 0).");
    return `${lines.join("\n")}\n`;
  }
  const tally = counts(report.verdicts);
  lines.push(
    `${report.verdicts.length} changed or new version${report.verdicts.length === 1 ? "" : "s"}: ` +
      `${tally.block} block, ${tally.wait} wait, ${tally.warn} warn, ${tally.allow} allow`,
  );
  const ordered = report.verdicts
    .map((verdict, index) => ({ verdict, index }))
    .toSorted(
      (a, b) =>
        SEVERITY.get(b.verdict.verdict)! - SEVERITY.get(a.verdict.verdict)! || a.index - b.index,
    );
  for (const { verdict } of ordered.slice(0, TEXT_LIST_LIMIT)) lines.push(verdictLine(verdict));
  if (ordered.length > TEXT_LIST_LIMIT)
    lines.push(`  and ${ordered.length - TEXT_LIST_LIMIT} more (--format json lists every one)`);
  const notEvaluated = [...new Set(report.verdicts.flatMap((v) => v.not_evaluated))].toSorted();
  if (notEvaluated.length > 0) lines.push(`Not evaluated: ${notEvaluated.join(", ")}`);
  if (report.unavailableSignals.length > 0)
    lines.push(`Unavailable for this check: ${report.unavailableSignals.join(", ")}`);
  const failing = tally.block + tally.wait;
  lines.push(
    failing > 0
      ? `Failed (exit 1): ${failing} version${failing === 1 ? " is" : "s are"} blocked or waiting.`
      : tally.warn > 0
        ? `Passed with ${tally.warn} warning${tally.warn === 1 ? "" : "s"} (exit 0).`
        : "Passed (exit 0).",
  );
  return `${lines.join("\n")}\n`;
}

function jsonContext(context: CheckContext, exitCode: ExitCode) {
  return {
    format: JSON_FORMAT,
    version: JSON_FORMAT_VERSION,
    mode: context.mode,
    exit_code: exitCode,
    lockfile: context.lockfile,
    base: context.base,
    base_from: context.baseFrom,
    head: context.head,
  };
}

/** The JSON report (`version: 1`). */
export function renderJson(report: CheckReport): string {
  const exitCode = verdictExitCode(report.verdicts);
  const document = {
    ...jsonContext(report, exitCode),
    counts: { changes: report.verdicts.length, ...counts(report.verdicts) },
    changes: report.changes.map((change, index) => {
      const verdict = report.verdicts[index]!;
      return {
        ecosystem: change.ecosystem,
        name: change.name,
        version: change.version,
        kind: change.kind,
        direct: change.direct,
        previous_version: change.previous_version,
        source: change.source,
        verdict: verdict.verdict,
        reasons: verdict.reasons,
        wait_until: verdict.wait_until === null ? null : verdict.wait_until.toISOString(),
        not_evaluated: verdict.not_evaluated,
      };
    }),
    unavailable_signals: report.unavailableSignals,
    osv_snapshot: report.osvSnapshot,
    error: null,
  };
  return `${JSON.stringify(document, null, 2)}\n`;
}

/** An unsupported lockfile as an error the CLI reports (exit 2). */
export function unsupportedLockfileError(side: string, refusal: UnsupportedLockfile): CliError {
  const named = refusal.packages.length === 0 ? "" : `; packages: ${refusal.packages.join(", ")}`;
  return new CliError(
    EXIT.usage,
    "unsupported_lockfile",
    `The lockfile at ${side} is not supported: ${refusal.unsupported} (${refusal.reasons.join(", ")}${named}).`,
  );
}

/** The text and JSON forms of an error that ended the check. */
export function renderError(
  context: CheckContext,
  error: CliError,
  extra: { readonly unsupported?: UnsupportedLockfile } = {},
): { readonly text: string; readonly json: string } {
  const json = {
    ...jsonContext(context, error.exit),
    counts: null,
    changes: [],
    unavailable_signals: [],
    osv_snapshot: null,
    error: {
      code: error.code,
      message: error.message,
      ...(error.details.status === undefined ? {} : { status: error.details.status }),
      ...(error.details.reason === undefined ? {} : { reason: error.details.reason }),
      ...(extra.unsupported === undefined
        ? {}
        : {
            unsupported: extra.unsupported.unsupported,
            reasons: extra.unsupported.reasons,
            packages: extra.unsupported.packages,
          }),
    },
  };
  const prefix = context.mode === "offline" ? "kovo deps check offline" : "kovo deps check";
  return {
    text: `${context.mode === "offline" ? `${OFFLINE_NOTICE}\n` : ""}${prefix}: ${error.message} [${error.code}] (exit ${error.exit})\n`,
    json: `${JSON.stringify(json, null, 2)}\n`,
  };
}
