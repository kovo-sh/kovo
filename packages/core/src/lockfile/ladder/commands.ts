import type { PackageManager, StoredPackageManager } from "@kovo/contracts";

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
// Yarn 4 and Bun (verified on Yarn 4.18.1 and Bun 1.4.4 in a worker, 2026-11-08): Yarn's
// `--mode=update-lockfile` resolves and fetches into a throwaway cache but never links or runs a
// script; Bun's `--lockfile-only` resolves from packuments alone. `yarn up -R <name>` moves a
// transitive package to the newest version its dependents' ranges admit, as `npm update` does, and
// `bun update <name>` does the same; `yarn up <alias>@<version>` and `bun add <alias>@<spec>` pin a
// direct dependency and rewrite its declared spec in its own section.
const BERRY_SUFFIX = ["--mode=update-lockfile"] as const;
const BUN_SUFFIX = ["--lockfile-only", "--ignore-scripts"] as const;
const BERRY_STYLE = { exact: "--exact", "^": "--caret", "~": "--tilde" } as const;
const BUN_SECTION = {
  dependencies: [],
  devDependencies: ["--dev"],
  optionalDependencies: ["--optional"],
  peerDependencies: ["--peer"],
} as const satisfies Record<DependencySection, readonly string[]>;

/** A root without a lockfile runs no package manager: every edit is trusted code's. */
function noCommand(pm: "manifest-only"): never {
  throw new RangeError(`${pm} plans carry no package-manager command`);
}

function unknownManager(pm: never): never {
  throw new RangeError(`unknown package manager ${String(pm)}`);
}

/** `1.2.3` → `^1.2.3`; an `npm:` alias keeps its name (`npm:foo@^1.2.3`). */
function bunRangeSpec(installSpec: string, style: "^" | "~"): string {
  if (!installSpec.startsWith("npm:")) return `${style}${installSpec}`;
  const at = installSpec.lastIndexOf("@");
  return `${installSpec.slice(0, at + 1)}${style}${installSpec.slice(at + 1)}`;
}

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
export function updateCommand(pm: StoredPackageManager, name: string): PmCommand {
  switch (pm) {
    case "yarn":
      return relockCommand(pm);
    case "npm":
      return { executable: "npm", args: ["update", name, ...NPM_SUFFIX] };
    case "pnpm":
      return { executable: "pnpm", args: ["update", name, ...PNPM_SUFFIX] };
    case "yarn-berry":
      return { executable: "yarn-berry", args: ["up", "-R", name, ...BERRY_SUFFIX] };
    case "bun":
      return { executable: "bun", args: ["update", name, ...BUN_SUFFIX] };
    case "manifest-only":
      return noCommand(pm);
    default:
      return unknownManager(pm);
  }
}

/** Pins a direct dependency to an exact version and rewrites its declared spec (rungs 2–4, M). */
export function installCommand(
  pm: StoredPackageManager,
  alias: string,
  installSpec: string,
  section: DependencySection,
  style: SaveStyle,
): PmCommand {
  const positional = `${alias}@${installSpec}`;
  switch (pm) {
    case "yarn":
      return relockCommand(pm);
    case "npm":
      return {
        executable: "npm",
        args: ["install", positional, SECTION_FLAG[section], saveFlag(style), ...NPM_SUFFIX],
      };
    case "pnpm":
      return {
        executable: "pnpm",
        args: ["add", positional, SECTION_FLAG[section], saveFlag(style), ...PNPM_SUFFIX],
      };
    case "yarn-berry":
      // `yarn up` keeps the dependency in its own section.
      return {
        executable: "yarn-berry",
        args: ["up", positional, BERRY_STYLE[style], ...BERRY_SUFFIX],
      };
    case "bun":
      // Bun saves a range spec as given (`^1.2.3`, `~1.2.3`) and an exact one with `--exact`.
      return {
        executable: "bun",
        args: [
          "add",
          style === "exact" ? positional : `${alias}@${bunRangeSpec(installSpec, style)}`,
          ...BUN_SECTION[section],
          ...(style === "exact" ? ["--exact"] : []),
          ...BUN_SUFFIX,
        ],
      };
    case "manifest-only":
      return noCommand(pm);
    default:
      return unknownManager(pm);
  }
}

/** Re-locks after trusted code edited package.json (overrides, removals). */
export function relockCommand(pm: StoredPackageManager): PmCommand {
  if (pm === "yarn-berry") return { executable: "yarn-berry", args: ["install", ...BERRY_SUFFIX] };
  if (pm === "bun") return { executable: "bun", args: ["install", ...BUN_SUFFIX] };
  if (pm === "manifest-only") return noCommand(pm);
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
