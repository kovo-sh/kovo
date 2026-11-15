import type { PackageManager, RecipeStep } from "@kovo/contracts";

import { findForbiddenFlags, unwrapInvocation, type Invocation } from "./shell/argv.js";
import { reporterCommand } from "./reporter.js";
import { parseScript, withoutKeywords } from "./shell/parse.js";
import {
  RUNNER_FORBID_FLAGS,
  RUNNER_REPORT_FORMAT,
  detectTestRunner,
  type TestRunner,
} from "./shell/runners.js";
import { pnpmBinInvocation, scriptInvocation, scriptsRunBy } from "./shell/scripts.js";

// Recipe commands in terms of the package scripts they run: the effective command (scripts
// expanded, for forbidden-flag checks), the test runner a step starts, its expectations, and the
// install command per sandbox phase.

const MAX_DEPTH = 4;

/** At most this much effective-command text (the shell parser's own bound). */
export const MAX_EFFECTIVE_COMMAND_LENGTH = 64 * 1024;
/** Script chains deeper than this are not followed; the expansion is then incomplete. */
const MAX_EXPANSION_DEPTH = 32;

/** A step's command with the package scripts it runs expanded. */
export interface EffectiveCommand {
  readonly text: string;
  /**
   * False when the expansion was cut short (over {@link MAX_EFFECTIVE_COMMAND_LENGTH}, a chain
   * deeper than 32 scripts, or a script too long to parse): flags may be hidden in the rest, so
   * verification fails closed.
   */
  readonly complete: boolean;
}

/**
 * `run` with every package script it invokes appended (npm's and pnpm's pre/post scripts included:
 * `scriptsRunBy`), so flags inside a script are visible. Verification computes it from the scripts
 * of the tree under test.
 * Each script (with the same pass-through arguments) is expanded once, so scripts that call each
 * other many times cannot multiply the output; the text is bounded and marked incomplete when cut.
 */
export function effectiveCommand(
  run: string,
  scripts: ReadonlyMap<string, string>,
  options: { readonly envOptions?: true } = {},
): EffectiveCommand {
  const parts: string[] = [];
  const expanded = new Set<string>();
  let length = 0;
  let complete = true;

  const append = (text: string, depth: number): void => {
    if (!complete) return;
    if (length + text.length + 1 > MAX_EFFECTIVE_COMMAND_LENGTH) {
      complete = false;
      return;
    }
    parts.push(text);
    length += text.length + 1;
    const parsed = parseScript(text);
    if (parsed.truncated) {
      complete = false; // not parsed to the end: the scripts it runs are unknown
      return;
    }
    for (const command of parsed.commands) {
      const invocation = unwrapInvocation(
        options.envOptions === true ? withoutKeywords(command.argv) : command.argv,
        options,
      );
      if (options.envOptions === true && invocation === null && command.argv.length > 0) {
        complete = false;
        return;
      }
      const script = invocation === null ? null : scriptInvocation(invocation);
      if (script === null) continue;
      for (const name of scriptsRunBy(script)) {
        const body = scripts.get(name);
        if (body === undefined) continue;
        const args =
          name === script.script && script.extraArgs.length > 0
            ? ` ${script.extraArgs.join(" ")}`
            : "";
        const key = `${name}\u0000${args}`;
        if (expanded.has(key)) continue;
        expanded.add(key);
        if (depth >= MAX_EXPANSION_DEPTH) {
          complete = false;
          return;
        }
        append(`${body}${args}`, depth + 1);
      }
    }
  };
  append(run, 0);
  return { text: parts.join("\n"), complete };
}

/** Commands of `run` that are not `cd` lines (a working directory prefix). */
function checkCommands(run: string) {
  const parsed = parseScript(run);
  return {
    complex: parsed.complex,
    commands: parsed.commands.filter((command) => command.argv[0] !== "cd"),
  };
}

/**
 * The test runner `run` starts when it is a single command (directly or through one package
 * script chain), so a reporter can be configured for it; null otherwise.
 */
export function singleTestRunner(
  run: string,
  scripts: ReadonlyMap<string, string>,
  depth = 0,
): TestRunner | null {
  const { complex, commands } = checkCommands(run);
  const [only] = commands;
  if (complex || commands.length !== 1 || only === undefined || depth > MAX_DEPTH) return null;
  const invocation = unwrapInvocation(only.argv);
  if (invocation === null) return null;
  const runner = runnerOf(invocation, scripts);
  if (runner !== null) return runner;
  const script = scriptInvocation(invocation);
  const body = script === null ? undefined : scripts.get(script.script);
  return body === undefined ? null : singleTestRunner(body, scripts, depth + 1);
}

/** The runner an invocation starts directly or as a pnpm binary (`pnpm vitest run`). */
export function runnerOf(
  invocation: Invocation,
  scripts: ReadonlyMap<string, string>,
): TestRunner | null {
  const bin = pnpmBinInvocation(invocation, scripts);
  return detectTestRunner(invocation) ?? (bin === null ? null : detectTestRunner(bin));
}

/** Every test runner the effective command starts. */
function runnersIn(effective: string, scripts: ReadonlyMap<string, string>): TestRunner[] {
  const runners = new Set<TestRunner>();
  for (const command of parseScript(effective).commands) {
    const invocation = unwrapInvocation(command.argv);
    const runner = invocation === null ? null : runnerOf(invocation, scripts);
    if (runner !== null) runners.add(runner);
  }
  return [...runners];
}

/**
 * SPEC `expect`: `reportFormat` "when a supported reporter can be configured" (a single Vitest,
 * Jest or `node --test` invocation) and `forbidFlags` for every runner the step starts, except
 * flags the discovered command already uses (a sharded CI run keeps `--shard`). When the scripts
 * cannot be expanded completely, every runner's flags are forbidden (fail closed).
 */
export function expectationsFor(
  run: string,
  scripts: ReadonlyMap<string, string>,
): RecipeStep["expect"] {
  const effective = effectiveCommand(run, scripts);
  const runner = singleTestRunner(run, scripts);
  const reportFormat =
    runner === null || (runner !== "node-test" && reporterCommand(run, scripts) === null)
      ? undefined
      : RUNNER_REPORT_FORMAT[runner];
  const flagLists = effective.complete
    ? runnersIn(effective.text, scripts).map((name) => RUNNER_FORBID_FLAGS[name] ?? [])
    : Object.values(RUNNER_FORBID_FLAGS);
  const candidates = [...new Set(flagLists.flatMap((flags) => flags ?? []))];
  const present = new Set(findForbiddenFlags(effective.text, candidates));
  const forbidFlags = candidates.filter((flag) => !present.has(flag));
  return {
    ...(reportFormat === undefined ? {} : { reportFormat }),
    ...(forbidFlags.length === 0 ? {} : { forbidFlags }),
  };
}

/** A readable step name for a command without one: its script, runner or first line. */
export function commandName(run: string): string {
  const { commands } = checkCommands(run);
  const [only] = commands;
  if (commands.length === 1 && only !== undefined) {
    const invocation = unwrapInvocation(only.argv);
    const script = invocation === null ? null : scriptInvocation(invocation);
    if (script !== null) return script.script;
  }
  const firstLine =
    run.split("\n").find((line) => line.trim() !== "" && !line.startsWith("cd ")) ?? run;
  const text = firstLine.trim();
  return text.length > 60 ? `${text.slice(0, 57)}...` : text;
}

/** CI install flags the recipe keeps (they change how the lockfile resolves peers or hoists). */
const KEPT_INSTALL_FLAGS: Readonly<Record<PackageManager, readonly string[]>> = {
  yarn: [],
  npm: ["--legacy-peer-deps", "--strict-peer-deps"],
  pnpm: ["--shamefully-hoist", "--strict-peer-dependencies", "--no-strict-peer-dependencies"],
};

/**
 * The frozen-lockfile install. Sandbox B installs with lifecycle scripts (SPEC phase table:
 * "Sandbox B install | … lifecycle scripts allowed"); Sandbox A never runs them ("Sandbox A installs
 * with lifecycle scripts disabled"). npm skips its audit and funding requests, which the proxy
 * would refuse anyway.
 */
export function installCommand(
  packageManager: PackageManager,
  options: { readonly lifecycleScripts: boolean; readonly ciFlags?: readonly string[] },
): string {
  const kept = (options.ciFlags ?? []).filter((flag) =>
    KEPT_INSTALL_FLAGS[packageManager].includes(flag),
  );
  const words =
    packageManager === "npm"
      ? ["npm", "ci", "--no-audit", "--no-fund"]
      : packageManager === "yarn"
        ? [
            "yarn",
            "--no-default-rc",
            "install",
            "--frozen-lockfile",
            "--non-interactive",
            "--no-progress",
          ]
        : ["pnpm", "install", "--frozen-lockfile"];
  return [
    ...words,
    ...new Set(kept),
    ...(options.lifecycleScripts ? [] : ["--ignore-scripts"]),
  ].join(" ");
}

/** The command that runs package script `name` with `packageManager`. */
export function scriptCommand(packageManager: PackageManager, name: string): string {
  if (name === "test") return `${packageManager} test`;
  const quoted = /^[A-Za-z0-9:._-]+$/.test(name) ? name : `'${name.replaceAll("'", "'\\''")}'`;
  return `${packageManager} run ${quoted}`;
}
