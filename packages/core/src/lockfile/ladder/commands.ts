import type { PackageManager } from "@kovo/contracts";

import type { DependencySection } from "../../manifest/package-json.js";
import type { PmCommand } from "./types.js";

// Package-manager invocations for each ladder action, verified against npm 10.9/11.19 and pnpm
// 9.15/10.34 (test-fixtures/lockfiles/generate.sh runs exactly these argument lists and commits
// the lockfiles they produce). Every command edits the lockfile only (no node_modules) and disables
// lifecycle scripts (SPEC: "Sandbox A installs with lifecycle scripts disabled"); npm also skips
// its audit and funding requests. Findings from docs/libraries/sandbox-ai-feeds.md §3 and the
// fixture runs:
// - `npm update <name>` moves a transitive dependency to the newest version its dependents' ranges
//   admit; npm refuses a version argument (EUPDATEARGS). `pnpm update <name>` does the same at every
//   depth (and ignores a version argument).
// - `npm install <alias>@<version>` / `pnpm add <alias>@<version>` pin exactly that version in the
//   lockfile, keep the dependency's section when told which one, and write the declared spec with
//   `--save-exact` or `--save-prefix=<^|~>`.
// - `pnpm remove` rejects `--ignore-scripts`; removals and overrides are package.json edits
//   followed by a lockfile-only re-lock instead.

/** How the rewritten spec is saved: exact, caret or tilde. */
export type SaveStyle = "exact" | "^" | "~";

const NPM_SUFFIX = ["--package-lock-only", "--ignore-scripts", "--no-audit", "--no-fund"] as const;
const PNPM_SUFFIX = ["--lockfile-only", "--ignore-scripts"] as const;

const SECTION_FLAG = {
  dependencies: "--save-prod",
  devDependencies: "--save-dev",
  optionalDependencies: "--save-optional",
  peerDependencies: "--save-peer",
} as const satisfies Record<DependencySection, string>;

function saveFlag(style: SaveStyle): string {
  return style === "exact" ? "--save-exact" : `--save-prefix=${style}`;
}

/**
 * A positional argument that a CLI could mistake for an option or a path. Package names come from
 * hostile lockfiles; the ladder refuses to plan with such a name rather than escape it.
 */
export function isUnsafePositional(value: string): boolean {
  return !/^[A-Za-z0-9@]/.test(value) || /[\s\\]/.test(value) || value.includes("..");
}

/** Lockfile-only update of a (transitive) package within its dependents' ranges (rung 1). */
export function updateCommand(pm: PackageManager, name: string): PmCommand {
  if (pm === "yarn") return relockCommand(pm);
  return pm === "npm"
    ? { executable: "npm", args: ["update", name, ...NPM_SUFFIX] }
    : { executable: "pnpm", args: ["update", name, ...PNPM_SUFFIX] };
}

/** Pins a direct dependency to an exact version and rewrites its declared spec (rungs 2–4, M). */
export function installCommand(
  pm: PackageManager,
  alias: string,
  installSpec: string,
  section: DependencySection,
  style: SaveStyle,
): PmCommand {
  const positional = `${alias}@${installSpec}`;
  if (pm === "yarn") return relockCommand(pm);
  return pm === "npm"
    ? {
        executable: "npm",
        args: ["install", positional, SECTION_FLAG[section], saveFlag(style), ...NPM_SUFFIX],
      }
    : {
        executable: "pnpm",
        args: ["add", positional, SECTION_FLAG[section], saveFlag(style), ...PNPM_SUFFIX],
      };
}

/** Re-locks after trusted code edited package.json (overrides, removals). */
export function relockCommand(pm: PackageManager): PmCommand {
  if (pm === "yarn")
    return {
      executable: "yarn",
      args: [
        "--no-default-rc",
        "install",
        "--ignore-scripts",
        "--non-interactive",
        "--no-progress",
      ],
    };
  return pm === "npm"
    ? { executable: "npm", args: ["install", ...NPM_SUFFIX] }
    : { executable: "pnpm", args: ["install", ...PNPM_SUFFIX, "--no-frozen-lockfile"] };
}

/**
 * Installs node_modules from the patched lockfile with scripts disabled, for Sandbox A's quick
 * checks (not part of a plan: the lockfile edit comes first).
 */
export function frozenInstallCommand(pm: PackageManager): PmCommand {
  if (pm === "yarn")
    return {
      executable: "yarn",
      args: [
        "--no-default-rc",
        "install",
        "--frozen-lockfile",
        "--ignore-scripts",
        "--non-interactive",
        "--no-progress",
      ],
    };
  return pm === "npm"
    ? { executable: "npm", args: ["ci", "--ignore-scripts", "--no-audit", "--no-fund"] }
    : { executable: "pnpm", args: ["install", "--frozen-lockfile", "--ignore-scripts"] };
}
