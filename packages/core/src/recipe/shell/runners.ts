import type { ReportFormat } from "@kovo/contracts";

import type { Invocation } from "./argv.js";

// Test runners discovery recognizes, the reporter Kovo's harness can configure for each, and the
// flags that would weaken a run. SPEC: `expect: { reportFormat?: 'vitest-json' | 'jest-json' |
// 'tap'; forbidFlags?: string[] }`; "reportFormat when a supported reporter can be configured".

export type TestRunner =
  | "vitest"
  | "jest"
  | "node-test"
  | "mocha"
  | "ava"
  | "tap"
  | "jasmine"
  | "playwright"
  | "cypress";

/** Runners whose reporter the harness can configure, and the format it produces. */
export const RUNNER_REPORT_FORMAT: Partial<Record<TestRunner, ReportFormat>> = {
  vitest: "vitest-json",
  jest: "jest-json",
  "node-test": "tap",
};

/**
 * Flags that make a test run vacuous, partial or unable to fail: pass with no tests, update
 * snapshots instead of checking them, run only focused/changed/related/sharded/name-filtered
 * tests, list instead of run, ignore unhandled errors (Vitest) or exit 0 on failures (Jest's
 * `--testFailureExitCode`). `--bail` is not forbidden: stopping early cannot turn a failing run
 * into a passing one. At most 32 flags per step in total (the contracts' `forbidFlags` bound).
 */
export const RUNNER_FORBID_FLAGS: Partial<Record<TestRunner, readonly string[]>> = {
  vitest: [
    "--passWithNoTests",
    "-u",
    "--update",
    "--allowOnly",
    "--changed",
    "--related",
    "--shard",
    "-t",
    "--testNamePattern",
    "--dangerouslyIgnoreUnhandledErrors",
  ],
  jest: [
    "--passWithNoTests",
    "-u",
    "--updateSnapshot",
    "-o",
    "--onlyChanged",
    "--changedSince",
    "--findRelatedTests",
    "--listTests",
    "--shard",
    "-t",
    "--testNamePattern",
    "--testFailureExitCode",
  ],
  "node-test": [
    "--test-only",
    "--test-name-pattern",
    "--test-skip-pattern",
    "--test-shard",
    "--test-update-snapshots",
  ],
};

const WATCH_FLAGS = new Set(["--watch", "-w", "--watchAll", "--ui"]);

/** The test runner an invocation starts, or null (a watch-mode invocation never counts). */
export function detectTestRunner(invocation: Invocation): TestRunner | null {
  const { program, args } = invocation;
  if (args.some((arg) => WATCH_FLAGS.has(arg))) return null;
  switch (program) {
    case "vitest": {
      const sub = args.find((arg) => !arg.startsWith("-"));
      if (sub === "watch" || sub === "dev" || sub === "bench" || sub === "init" || sub === "list") {
        return null;
      }
      return "vitest";
    }
    case "jest":
      return "jest";
    case "node":
      return args.includes("--test") ? "node-test" : null;
    case "mocha":
    case "_mocha":
      return "mocha";
    case "ava":
      return "ava";
    case "tap":
      return "tap";
    case "jasmine":
      return "jasmine";
    case "playwright":
      return args[0] === "test" ? "playwright" : null;
    case "cypress":
      return args[0] === "run" ? "cypress" : null;
    default:
      return null;
  }
}

/** Whether a package script name is a test script (`test`, `test:unit`, `test-ci`, `tests`). */
export function isTestScriptName(name: string): boolean {
  return /^tests?(?:$|[:_-])/.test(name);
}
