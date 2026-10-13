import { lstat, readFile, realpath, rm, writeFile } from "node:fs/promises";
import { basename, dirname, join } from "node:path";

import {
  LOCKFILE_MAX_BYTES,
  LOCKFILE_NAMES,
  WORKSPACE_LIMITS,
  type LockfileName,
} from "@kovo/core/lockfile";
import { PACKAGE_JSON_LIMITS } from "@kovo/core/manifest";

import { usageError } from "../errors.js";
import { WorkingTreeReader } from "../deps/git.js";
import type { HeldFiles } from "../deps/memory.js";
import type { PackageManager } from "./classify.js";

// The project files a resolve may change, held in memory before and after it and restored byte for
// byte when the check does not pass. They are read into memory and written back only to their own
// paths: never copied elsewhere, printed or sent.

/** The project directory the wrapper protects, and the files it holds. */
export interface Project {
  readonly pm: PackageManager;
  readonly dir: string;
  readonly fileName: LockfileName;
  /** Project-relative paths the resolve may write: the manifest, the lockfile, pnpm's settings. */
  readonly held: readonly string[];
}

const WORKSPACE_FILE = "pnpm-workspace.yaml";

function missing(error: unknown): boolean {
  if (!(error instanceof Error) || !("code" in error)) return false;
  return error.code === "ENOENT" || error.code === "ENOTDIR";
}

async function exists(path: string): Promise<boolean> {
  try {
    await lstat(path);
    return true;
  } catch (error) {
    if (missing(error)) return false;
    throw usageError("unreadable_file", "The project directory could not be read.");
  }
}

/** Whether a package.json's text declares npm workspaces (unparseable text: npm would fail too). */
function declaresWorkspaces(bytes: Uint8Array | null): boolean {
  if (bytes === null) return false;
  try {
    const manifest: unknown = JSON.parse(new TextDecoder().decode(bytes));
    return typeof manifest === "object" && manifest !== null && "workspaces" in manifest;
  } catch {
    return false;
  }
}

async function boundedManifest(path: string): Promise<Uint8Array | null> {
  try {
    const stats = await lstat(path);
    if (!stats.isFile() || stats.size > PACKAGE_JSON_LIMITS.maxLength) return null;
    return new Uint8Array(await readFile(path));
  } catch {
    return null;
  }
}

/**
 * The project in `cwd`. Errors (exit 2): no package.json there, npm's shrinkwrap (which npm reads
 * instead of package-lock.json), or a directory inside a workspace whose lockfile lives above it.
 */
export async function openProject(pm: PackageManager, cwd: string): Promise<Project> {
  let dir: string;
  try {
    dir = await realpath(cwd);
  } catch {
    throw usageError("unreadable_file", "The project directory could not be read.");
  }
  if (!(await exists(join(dir, "package.json"))))
    throw usageError(
      "missing_manifest",
      `kovo ${pm} needs the project's package.json in the current directory: run it from the project's root.`,
    );
  if (pm === "npm" && (await exists(join(dir, "npm-shrinkwrap.json"))))
    throw usageError(
      "unsupported_lockfile_name",
      "npm reads npm-shrinkwrap.json instead of package-lock.json, and kovo checks package-lock.json only.",
    );
  for (
    let child = dir, parent = dirname(dir);
    parent !== child;
    child = parent, parent = dirname(parent)
  ) {
    const above =
      pm === "pnpm"
        ? await exists(join(parent, WORKSPACE_FILE))
        : declaresWorkspaces(await boundedManifest(join(parent, "package.json")));
    if (above)
      throw usageError(
        "workspace_member",
        `This directory is inside a workspace whose lockfile is in ${parent}: run kovo ${pm} there.`,
      );
  }
  const fileName = pm === "pnpm" ? LOCKFILE_NAMES.pnpm : LOCKFILE_NAMES.npm;
  return {
    pm,
    dir,
    fileName,
    held: pm === "pnpm" ? ["package.json", fileName, WORKSPACE_FILE] : ["package.json", fileName],
  };
}

function boundOf(project: Project, path: string): number {
  return path === project.fileName
    ? LOCKFILE_MAX_BYTES[project.fileName]
    : PACKAGE_JSON_LIMITS.maxLength;
}

/**
 * The held files' bytes, now. Errors (exit 2): a held path that is not a regular file (a symlink
 * included) or exceeds the CLI's bounds.
 */
export async function readHeld(project: Project, env: NodeJS.ProcessEnv): Promise<HeldFiles> {
  const reader = new WorkingTreeReader(project.dir, env);
  const held = new Map<string, Uint8Array | null>();
  for (const path of project.held)
    held.set(path, await reader.readFile(path, boundOf(project, path)));
  return held;
}

/** Whether the project is a workspace: pnpm's settings file, or npm's `workspaces` field. */
export function isWorkspace(project: Project, held: HeldFiles): boolean {
  return project.pm === "pnpm"
    ? (held.get(WORKSPACE_FILE) ?? null) !== null
    : declaresWorkspaces(held.get("package.json") ?? null);
}

/**
 * Lockfiles of the package manager's kind below the project root (a workspace with one lockfile per
 * project): the check reads only the root one, so any other is refused.
 */
export async function nestedLockfiles(
  project: Project,
  live: WorkingTreeReader,
): Promise<readonly string[]> {
  const entries = await live.listTree(WORKSPACE_LIMITS.maxTreeEntries);
  return entries
    .filter(
      (entry) =>
        entry.path !== project.fileName &&
        basename(entry.path) === project.fileName &&
        !/(?:^|\/)node_modules\//u.test(entry.path),
    )
    .map((entry) => entry.path);
}

function equal(a: Uint8Array | null, b: Uint8Array | null): boolean {
  if (a === null || b === null) return a === b;
  return Buffer.from(a).equals(Buffer.from(b));
}

/** Whether two holds of the same project have the same bytes for every file. */
export function sameHeld(a: HeldFiles, b: HeldFiles): boolean {
  for (const [path, bytes] of a) if (!equal(bytes, b.get(path) ?? null)) return false;
  return a.size === b.size;
}

async function currentBytes(path: string): Promise<Uint8Array | null | "other"> {
  try {
    const stats = await lstat(path);
    if (!stats.isFile()) return "other";
    return new Uint8Array(await readFile(path));
  } catch (error) {
    if (missing(error)) return null;
    return "other";
  }
}

export interface Restored {
  /** Paths written back or removed. */
  readonly restored: readonly string[];
  /** Paths that could not be restored: they may hold the unchecked resolve. */
  readonly failed: readonly string[];
}

/**
 * Puts every held file back to `before`, byte for byte (a file the resolve created is removed), and
 * removes `created` (nested lockfiles the resolve wrote). Each path is read back to confirm.
 */
export async function restore(
  project: Project,
  before: HeldFiles,
  created: readonly string[] = [],
): Promise<Restored> {
  const restored: string[] = [];
  const failed: string[] = [];
  const wanted: [string, Uint8Array | null][] = [
    ...before,
    ...created.map((path): [string, null] => [path, null]),
  ];
  for (const [path, bytes] of wanted) {
    const absolute = join(project.dir, path);
    const now = await currentBytes(absolute);
    if (now !== "other" && equal(now, bytes)) continue;
    try {
      // A path that is not a regular file (a symlink, say) is removed, never written through; a
      // regular file is overwritten in place, keeping its mode.
      if (now === "other" || (now !== null && bytes === null)) await rm(absolute, { force: true });
      if (bytes !== null) await writeFile(absolute, bytes);
    } catch {
      // Confirmed below.
    }
    const after = await currentBytes(absolute);
    if (after !== "other" && equal(after, bytes)) restored.push(path);
    else failed.push(path);
  }
  return { restored, failed };
}
