import type { Invocation } from "./argv.js";

// Which package.json script an npm or pnpm invocation runs (`npm test`, `npm run build`,
// `pnpm lint`, `pnpm run test:unit -- --coverage`).

export interface ScriptInvocation {
  readonly packageManager: "npm" | "pnpm" | "yarn";
  readonly script: string;
  /** Arguments passed through to the script. */
  readonly extraArgs: readonly string[];
}

/** pnpm's own commands; any other first word runs the package script of that name. */
const PNPM_COMMANDS = new Set([
  "add",
  "approve-builds",
  "audit",
  "bin",
  "cache",
  "cat-file",
  "cat-index",
  "config",
  "create",
  "dedupe",
  "deploy",
  "dlx",
  "doctor",
  "env",
  "exec",
  "fetch",
  "find-hash",
  "i",
  "ignored-builds",
  "import",
  "init",
  "install",
  "install-test",
  "it",
  "licenses",
  "link",
  "list",
  "ln",
  "ls",
  "outdated",
  "pack",
  "patch",
  "patch-commit",
  "patch-remove",
  "prune",
  "publish",
  "rb",
  "rebuild",
  "remove",
  "rm",
  "root",
  "self-update",
  "server",
  "setup",
  "store",
  "un",
  "uninstall",
  "unlink",
  "up",
  "update",
  "upgrade",
  "why",
]);

/** Yarn 1.22.22 src/cli/commands/index.js plus src/cli/aliases.js: builtins outrank scripts.
 * https://github.com/yarnpkg/yarn/blob/v1.22.22/src/cli/commands/index.js
 */
const YARN_CLASSIC_COMMANDS = new Set([
  "access",
  "add",
  "audit",
  "autoclean",
  "bin",
  "cache",
  "check",
  "config",
  "create",
  "dedupe",
  "exec",
  "generateLockEntry",
  "global",
  "help",
  "import",
  "info",
  "init",
  "install",
  "licenses",
  "link",
  "lockfile",
  "login",
  "logout",
  "list",
  "node",
  "outdated",
  "owner",
  "pack",
  "policies",
  "prune",
  "publish",
  "remove",
  "run",
  "tag",
  "team",
  // src/cli/index.js rewrites `yarn set version` to `policies set-version`.
  "set",
  "unplug",
  "unlink",
  "upgrade",
  "version",
  "versions",
  "why",
  "workspaces",
  "workspace",
  "upgradeInteractive",
  "generate-lock-entry",
  "upgrade-interactive",
]);

/** Keyed by repository text, so a Map: `npm constructor` must not find `Object.prototype` members. */
const NPM_LIFECYCLE_ALIASES: ReadonlyMap<string, string> = new Map([
  ["test", "test"],
  ["t", "test"],
  ["tst", "test"],
  ["start", "start"],
  ["stop", "stop"],
  ["restart", "restart"],
]);

const NPM_RUN = new Set(["run", "run-script", "rum", "urn"]);
const PNPM_TEST = new Set(["test", "t", "tst"]);

function afterDashDash(args: readonly string[]): readonly string[] {
  const separator = args.indexOf("--");
  return separator === -1 ? args : args.slice(separator + 1);
}

/** The script a package-manager invocation runs, or null. */
export function scriptInvocation(invocation: Invocation): ScriptInvocation | null {
  const { program, args } = invocation;
  if (program !== "npm" && program !== "pnpm" && program !== "yarn") return null;
  const firstIndex = args.findIndex((arg) => !arg.startsWith("-"));
  if (firstIndex === -1) return null;
  const command = args[firstIndex] ?? "";
  const rest = args.slice(firstIndex + 1);

  if (program === "yarn") {
    if (command !== "run") {
      // Retain the existing conservative exclusions (such as rebuild) as well as Yarn builtins.
      if (PNPM_COMMANDS.has(command) || YARN_CLASSIC_COMMANDS.has(command)) return null;
      return { packageManager: "yarn", script: command, extraArgs: afterDashDash(rest) };
    }
  } else if (program === "npm") {
    const lifecycle = NPM_LIFECYCLE_ALIASES.get(command);
    if (lifecycle !== undefined) {
      return { packageManager: "npm", script: lifecycle, extraArgs: afterDashDash(rest) };
    }
    if (!NPM_RUN.has(command)) return null;
  } else {
    if (PNPM_TEST.has(command)) {
      return { packageManager: "pnpm", script: "test", extraArgs: afterDashDash(rest) };
    }
    if (command !== "run" && !PNPM_COMMANDS.has(command)) {
      return { packageManager: "pnpm", script: command, extraArgs: afterDashDash(rest) };
    }
    if (command !== "run") return null;
  }
  const scriptIndex = rest.findIndex((arg) => !arg.startsWith("-"));
  if (scriptIndex === -1) return null;
  return {
    packageManager: program,
    script: rest[scriptIndex] ?? "",
    extraArgs: afterDashDash(rest.slice(scriptIndex + 1)),
  };
}

/**
 * The package scripts a script invocation runs, in order: `pre<name>`, the script, `post<name>`.
 * npm always runs the pre and post scripts; so do pnpm 9 and 10, whose `enable-pre-post-scripts`
 * defaults to true (checked against the pinned pnpm 10.34.5: `pnpm run build` and `pnpm build` run
 * `prebuild` and `postbuild`). A repository `.npmrc` turning them off only makes this an
 * over-approximation, which every caller treats as more work to check, never less.
 */
export function scriptsRunBy(script: ScriptInvocation): readonly string[] {
  return [`pre${script.script}`, script.script, `post${script.script}`];
}

/**
 * pnpm runs a binary when its first word is neither one of its commands nor a package script
 * (`pnpm vitest run` runs `vitest run`). Returns that binary invocation, or null.
 */
export function pnpmBinInvocation(
  invocation: Invocation,
  scripts: ReadonlyMap<string, string>,
): Invocation | null {
  if (invocation.program !== "pnpm") return null;
  const index = invocation.args.findIndex((arg) => !arg.startsWith("-"));
  const first = invocation.args[index];
  if (first === undefined || first === "run" || PNPM_COMMANDS.has(first) || PNPM_TEST.has(first)) {
    return null;
  }
  return scripts.has(first) ? null : { program: first, args: invocation.args.slice(index + 1) };
}
