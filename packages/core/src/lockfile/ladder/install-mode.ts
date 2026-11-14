import type { PackageManager } from "@kovo/contracts";

import { frozenInstallCommand } from "./commands.js";
import type { PmCommand } from "./types.js";

// Owner D-615 item 3 (source: https://github.com/kovo-sh/kovo-cloud/issues/626#issuecomment-6673702551;
// specs/npm-proxy-and-network-egress.md): sandbox installs are lockfile-only. With a present,
// current lockfile the package manager installs exactly what the lockfile names and never resolves
// a version: `npm ci` (package-lock's resolved URL and integrity; npm's default replace-registry-host
// rewrites the URL to the proxy), `pnpm install --frozen-lockfile`, and for the admitted yarn
// (classic; discovery refuses Berry with `yarn_berry_unsupported`) `yarn install --frozen-lockfile`,
// classic's spelling of Berry's `--immutable`. Bun is not an admitted package manager, so it never
// installs in a sandbox. A missing or stale lockfile, or a fix that changes dependencies, takes a
// normal (resolving) install instead, and the reason is a stable code the caller records.

/** Why a sandbox install resolves versions instead of installing the lockfile as it is. */
export const INSTALL_FALLBACK_REASONS = [
  "install_fallback_lockfile_missing",
  "install_fallback_lockfile_stale",
  "install_fallback_dependencies_changed",
] as const;
export type InstallFallbackReason = (typeof INSTALL_FALLBACK_REASONS)[number];

export interface SandboxInstallInput {
  readonly packageManager: PackageManager;
  /** Whether the install root has its package manager's lockfile. */
  readonly lockfile: "present" | "absent";
  /** False when trusted code knows the lockfile does not match its manifest. */
  readonly lockfileCurrent: boolean;
  /** True when the fix itself changes the dependency graph (the ladder's edits and re-locks). */
  readonly dependenciesChanged: boolean;
}

export type SandboxInstallMode =
  /** The lockfile-only install: no version is resolved. */
  | { readonly mode: "frozen"; readonly command: PmCommand }
  /** A resolving install; the caller runs its own resolving commands and records `reason`. */
  | { readonly mode: "normal"; readonly reason: InstallFallbackReason };

/**
 * How a sandbox installs `input.packageManager`'s dependencies: lockfile-only when it can, else a
 * normal install with the reason. The first true condition names the reason: a missing lockfile,
 * then a stale one, then a fix that changes dependencies.
 */
export function sandboxInstallMode(input: SandboxInstallInput): SandboxInstallMode {
  if (input.lockfile === "absent")
    return { mode: "normal", reason: "install_fallback_lockfile_missing" };
  if (!input.lockfileCurrent) return { mode: "normal", reason: "install_fallback_lockfile_stale" };
  if (input.dependenciesChanged)
    return { mode: "normal", reason: "install_fallback_dependencies_changed" };
  return { mode: "frozen", command: frozenInstallCommand(input.packageManager) };
}
