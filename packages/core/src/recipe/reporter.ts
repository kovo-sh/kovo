import type { ReportFormat } from "@kovo/contracts";

import { unwrapInvocation, type Invocation } from "./shell/argv.js";
import { parseScript, type SimpleCommand } from "./shell/parse.js";
import { detectTestRunner } from "./shell/runners.js";
import { pnpmBinInvocation, scriptInvocation } from "./shell/scripts.js";

// How the Sandbox B harness makes a report step write its report where Kovo reads it (SPEC "Sandbox
// B": "Execute a fixed baseline-derived harness with protected recipe/reporting configuration";
// docs/decisions/recipe.md "Reporter expectations": "How the harness appends reporter options is
// the verifier's"). The reporter and its output path come from trusted code, never from the
// repository: the step's approved command runs unchanged, with only these options added.
//
// Verified against the pinned runtimes (docs/decisions/verification.md "Reporter injection"):
// - `node --test` (TAP): `NODE_OPTIONS=--test-reporter=tap --test-reporter-destination=<path>`.
//   Node reads test-runner options from NODE_OPTIONS whatever script chain starts it, while an
//   option appended after a positional file argument is passed to the test file instead.
// - Vitest (`--reporter=json --outputFile=<path>`) and Jest (`--json --outputFile=<path>`): the
//   options are appended to the step's single command. For `npm test`/`npm run x` they follow a
//   `--` (npm hands what follows it to the script); pnpm passes a script's extra arguments on as
//   they are. A script that reaches the runner through another script (`"test": "npm run unit"`)
//   is resolved to its inner invocation when doing so preserves its hooks and arguments.

/** A report path the harness chose: an absolute path of safe characters only. */
const SAFE_PATH = /^\/[A-Za-z0-9._/-]{1,512}$/;

export interface HarnessInjection {
  /** The step's command with the harness's options added (the command itself is unchanged). */
  readonly command: string;
  /** Environment the harness adds for this step. */
  readonly env: Readonly<Record<string, string>>;
}

export type HarnessInjectionResult =
  | { readonly ok: true; readonly injection: HarnessInjection }
  /**
   * - `unsafe_path`: the harness passed a path it must never interpolate.
   * - `not_single_command`: the step runs several commands, or shell constructs the parser does not
   *   model, so there is no one runner invocation to extend.
   * - `unsupported_runner`: the single command is neither a script invocation nor a runner the
   *   format belongs to.
   */
  | {
      readonly ok: false;
      readonly reason: "unsafe_path" | "not_single_command" | "unsupported_runner";
    };

/** The single runner command of `run` (ignoring `cd` lines), with its position in the script. */
function singleCommand(run: string): {
  readonly text: string;
  readonly command: SimpleCommand;
  readonly invocation: Invocation;
} | null {
  const text = run.replaceAll("\r\n", "\n");
  const parsed = parseScript(text);
  if (parsed.complex || parsed.truncated) return null;
  const commands = parsed.commands.filter((command) => command.argv[0] !== "cd");
  const [only] = commands;
  if (commands.length !== 1 || only === undefined) return null;
  // Options go at the end of the command, which must be the script's last one (a `cd dir &&`
  // prefix is fine; anything after the runner would take them instead).
  if (parsed.commands.at(-1) !== only || only.terminator === "&") return null;
  const invocation = unwrapInvocation(only.argv);
  return invocation === null ? null : { text, command: only, invocation };
}

/**
 * Where the command's last word ends: before a trailing comment and blanks, which the parser counts
 * as part of the command's range (a quote-aware scan of that range only).
 */
function wordsEnd(text: string, command: SimpleCommand): number {
  let end = command.end;
  let quote: "'" | '"' | null = null;
  for (let index = command.start; index < command.end; index += 1) {
    const ch = text.charAt(index);
    if (quote === "'") {
      if (ch === "'") quote = null;
    } else if (quote === '"') {
      if (ch === "\\") index += 1;
      else if (ch === '"') quote = null;
    } else if (ch === "\\") {
      index += 1;
    } else if (ch === "'" || ch === '"') {
      quote = ch;
    } else if (ch === "#" && (index === command.start || /[ \t]/.test(text.charAt(index - 1)))) {
      end = index;
      break;
    }
  }
  while (end > command.start && /[ \t\n]/.test(text.charAt(end - 1))) end -= 1;
  return end;
}

function insertAt(text: string, at: number, words: readonly string[]): string {
  return `${text.slice(0, at)} ${words.join(" ")}${text.slice(at)}`;
}

/** Resolve forwarding-only script chains without dropping hooks, assignments or arguments.
 * The last script invocation stays intact so its own pre/post hooks still run.
 */
export function reporterCommand(
  run: string,
  scripts: ReadonlyMap<string, string>,
  depth = 0,
): string | null {
  if (depth > 32) return null;
  const single = singleCommand(run);
  if (single === null) return null;
  const script = scriptInvocation(single.invocation);
  if (script === null || !scripts.has(script.script)) return run;
  const body = scripts.get(script.script) ?? "";
  const inner = singleCommand(body);
  if (inner === null) return null;
  if (
    scriptInvocation(inner.invocation) === null ||
    pnpmBinInvocation(inner.invocation, scripts) !== null
  )
    return run;
  if (
    scripts.has(`pre${script.script}`) ||
    scripts.has(`post${script.script}`) ||
    script.extraArgs.length > 0 ||
    single.command.assignments.length > 0 ||
    single.command.argv.some((word) => word.startsWith("-")) ||
    inner.command.assignments.length > 0 ||
    inner.text.slice(0, inner.command.start).trim() !== ""
  )
    return null;
  const resolved = reporterCommand(body, scripts, depth + 1);
  return resolved === null
    ? null
    : `${single.text.slice(0, single.command.start)}${resolved}${single.text.slice(wordsEnd(single.text, single.command))}`;
}

/** Appends `options` to the step's command so they reach the runner (see the file comment). */
function appendToRunner(
  run: string,
  runners: readonly string[],
  options: readonly string[],
): HarnessInjectionResult {
  const single = singleCommand(run);
  if (single === null) return { ok: false, reason: "not_single_command" };
  const { text, command, invocation } = single;
  const script = scriptInvocation(invocation);
  if (script !== null) {
    const words =
      script.packageManager === "npm" && !command.argv.includes("--")
        ? ["--", ...options]
        : options;
    return {
      ok: true,
      injection: { command: insertAt(text, wordsEnd(text, command), words), env: {} },
    };
  }
  const runner =
    detectTestRunner(invocation) ??
    detectBinRunner(invocation) ??
    (["eslint", "tsc"].includes(invocation.program) ? invocation.program : null);
  if (runner === null || !runners.includes(runner))
    return { ok: false, reason: "unsupported_runner" };
  return {
    ok: true,
    injection: { command: insertAt(text, wordsEnd(text, command), options), env: {} },
  };
}

function detectBinRunner(invocation: Invocation): string | null {
  const bin = pnpmBinInvocation(invocation, new Map());
  return bin === null ? null : detectTestRunner(bin);
}

/**
 * The step's command and environment that make its runner write a `format` report to
 * `reportPath` (a path the harness chose, of safe characters only).
 */
export function reporterInjection(
  run: string,
  format: ReportFormat,
  reportPath: string,
  scripts?: ReadonlyMap<string, string>,
): HarnessInjectionResult {
  if (!SAFE_PATH.test(reportPath)) return { ok: false, reason: "unsafe_path" };
  if (format === "tap") {
    return {
      ok: true,
      injection: {
        command: run,
        env: { NODE_OPTIONS: `--test-reporter=tap --test-reporter-destination=${reportPath}` },
      },
    };
  }
  if (scripts !== undefined) {
    const resolved = reporterCommand(run, scripts);
    if (resolved === null) return { ok: false, reason: "unsupported_runner" };
    run = resolved;
  }
  if (format === "vitest-json") {
    return appendToRunner(run, ["vitest"], ["--reporter=json", `--outputFile=${reportPath}`]);
  }
  return appendToRunner(run, ["jest"], ["--json", `--outputFile=${reportPath}`]);
}

/**
 * The command that receives the words appended to `run`: its last command, followed into the body
 * of the package script it invokes (a package manager appends a script's extra arguments to the end
 * of the script's text, so `"build": "tsc && tsup"` hands them to `tsup`). Null when that is not
 * certain: a construct the parser does not model, a background job, or a script the manifest does
 * not hold.
 */
function appendedOptionsReceiver(
  run: string,
  scripts: ReadonlyMap<string, string>,
  depth = 0,
): Invocation | null {
  if (depth > 32) return null;
  const parsed = parseScript(run.replaceAll("\r\n", "\n"));
  if (parsed.complex || parsed.truncated) return null;
  const last = parsed.commands.at(-1);
  if (last === undefined || last.terminator === "&") return null;
  const invocation = unwrapInvocation(last.argv);
  if (invocation === null) return null;
  const script = scriptInvocation(invocation);
  if (script === null) return invocation;
  // The scripts are the root manifest's. After a `cd`, or with a package-manager option before the
  // script name (`pnpm -r build`, `--filter`, `--workspaces`, `-C dir`), the script that runs may be
  // another package's, so the receiver is not certain (rv7752 N1, N2).
  if (
    parsed.commands
      .slice(0, -1)
      .some((command) => ["cd", "pushd", "popd"].includes(command.argv[0] ?? "")) ||
    invocation.args
      .slice(
        0,
        invocation.args.includes(script.script)
          ? invocation.args.indexOf(script.script)
          : invocation.args.findIndex((arg) => !arg.startsWith("-")),
      )
      .some((arg) => arg.startsWith("-"))
  )
    return null;
  const body = scripts.get(script.script);
  return body === undefined ? null : appendedOptionsReceiver(body, scripts, depth + 1);
}

/**
 * The step's command with options that make its ESLint or tsc write machine-readable diagnostics.
 * The options are added only when they reach that tool: a `"build": "tsc && tsup"` script
 * would hand tsc's `--pretty false` to tsup, which then fails on the unknown option, so such a
 * step runs unchanged (`unsupported_runner`).
 */
export function diagnosticReporterInjection(
  run: string,
  tool: "eslint" | "tsc",
  reportPath: string,
  scripts: ReadonlyMap<string, string>,
): HarnessInjectionResult {
  if (!SAFE_PATH.test(reportPath)) return { ok: false, reason: "unsafe_path" };
  if (appendedOptionsReceiver(run, scripts)?.program !== tool)
    return { ok: false, reason: "unsupported_runner" };
  return appendToRunner(
    run,
    [tool],
    tool === "eslint" ? ["--format", "json", "--output-file", reportPath] : ["--pretty", "false"],
  );
}
