import {
  detectPackageManager,
  FOREIGN_LOCKFILES,
  YARN_BERRY_MARKERS,
  type DetectionRejectionReason,
} from "../detect.js";
import { LOCKFILE_NAMES } from "../parse.js";
import { dependencyWorkspaceMember } from "../dependency-ignore.js";

// Which lockfiles a pull request's evaluation reads (agent decision 2026-10-13, pending owner review
// #1120; #2005): every npm, pnpm and Yarn lockfile in the head tree, not only the root's. Pure: it
// sees the paths and blob IDs of both sides' trees (or, when GitHub truncated a tree, the compared
// file list) and never a file's text.
//
// - A lockfile directory is one holding a lockfile, supported or not. A dependency file
//   (`package.json`, `pnpm-workspace.yaml`, a lockfile or a Yarn Berry marker) belongs to the
//   nearest lockfile directory at or above it: its own project's, or the workspace root's.
// - A lockfile directory is evaluated when the pull request adds, changes or removes a dependency
//   file belonging to it. Its layout must be one Kovo reads (exactly one supported lockfile next to
//   a package.json, as inventory detects it), at most {@link MAX_LOCKFILE_DEPTH} directories deep,
//   and the repository may hold at most {@link MAX_LOCKFILE_DIRECTORIES} lockfile directories;
//   otherwise a pull request that changes such a file is an unsupported layout, which fails the
//   check (`unsupported_dependency_layout`), never a pass.
// - A changed package.json that no lockfile directory owns is an unsupported layout too; a removed
//   one, or a removed project, introduces nothing.
// - Only a head with no JavaScript manifest or lockfile anywhere has no dependencies.
// - Paths under `node_modules` or `.git` are vendored and never read.

/** The deepest a lockfile directory may be: `a/b/c/d/e/f/g/h/package-lock.json` is depth 8. */
export const MAX_LOCKFILE_DEPTH = 8;
/** The most lockfile directories a repository may hold for its pull requests to be evaluated. */
export const MAX_LOCKFILE_DIRECTORIES = 20;

/** Why a pull request's dependency layout cannot be evaluated (a fixed code in the check's text). */
export const DEPENDENCY_LAYOUT_REASONS = [
  "manifest_without_lockfile",
  "lockfile_without_manifest",
  "multiple_lockfiles",
  "unsupported_package_manager",
  "npm_shrinkwrap",
  "too_deep",
  "too_many_lockfiles",
  "tree_too_large",
  "dependency_ignore_config_invalid",
  "dependency_ignore_workspace_invalid",
  "dependency_ignore_list_too_large",
  // The hosted gate's reads of one evaluation passed their GitHub request cap (#4717).
  "dependency_read_limit",
] as const;
export type DependencyLayoutReason = (typeof DEPENDENCY_LAYOUT_REASONS)[number];

const DETECTION_LAYOUT: Readonly<Record<DetectionRejectionReason, DependencyLayoutReason>> = {
  missing_package_json: "lockfile_without_manifest",
  missing_lockfile: "manifest_without_lockfile",
  multiple_lockfiles: "multiple_lockfiles",
  foreign_lockfile: "unsupported_package_manager",
  npm_shrinkwrap: "npm_shrinkwrap",
};

const LOCKFILES: ReadonlySet<string> = new Set([
  ...Object.values(LOCKFILE_NAMES),
  ...Object.keys(FOREIGN_LOCKFILES),
]);
export function isDependencyLockfile(path: string): boolean {
  return LOCKFILES.has(split(path).name) && !vendored(path);
}
/** Files that make a directory a JavaScript project. */
const JAVASCRIPT: ReadonlySet<string> = new Set([
  ...LOCKFILES,
  "package.json",
  "pnpm-workspace.yaml",
]);
/** Every file whose change can change what a lockfile directory resolves or how it is detected. */
const DEPENDENCY_FILES: ReadonlySet<string> = new Set([...JAVASCRIPT, ...YARN_BERRY_MARKERS]);

/** One entry of a git tree listing (paths relative to the repository root). */
export interface ListedEntry {
  readonly path: string;
  readonly type: "blob" | "tree" | "commit";
  readonly sha: string;
}

function hasListedBlob(entries: readonly ListedEntry[], path: string): boolean {
  return entries.some((entry) => entry.type === "blob" && entry.path === path);
}

/** D-227 root/member exemptions, shared by the hosted and CLI directory gates. */
export function protectedGateLockfile(
  path: string,
  declarations: readonly { readonly dir: string; readonly patterns: readonly string[] }[],
  base: readonly ListedEntry[],
  head: readonly ListedEntry[],
  work: { remaining: number },
): boolean {
  const dir = path.slice(0, path.lastIndexOf("/"));
  return (
    !path.includes("/") ||
    declarations.some((declaration) => {
      if (!path.startsWith(declaration.dir)) return false;
      const parts = dir.slice(declaration.dir.length).split("/");
      return parts.some((_, index) => {
        const member = parts.slice(0, index + 1).join("/");
        if (!dependencyWorkspaceMember(declaration.patterns, member, work)) return false;
        if (index === parts.length - 1) return true;
        return [base, head].some(
          (entries) =>
            hasListedBlob(entries, path) && !hasListedBlob(entries, `${dir}/package.json`),
        );
      });
    })
  );
}

export type Discovery =
  /** No JavaScript manifest or lockfile anywhere in the head. */
  | { readonly kind: "no_dependencies" }
  | { readonly kind: "unsupported"; readonly reason: DependencyLayoutReason }
  /** The lockfile directories to evaluate ("" is the root), sorted; empty when none changed. */
  | { readonly kind: "directories"; readonly directories: readonly string[] };

function vendored(path: string): boolean {
  return path
    .split("/")
    .some((part) => part.toLowerCase() === "node_modules" || part.toLowerCase() === ".git");
}

function split(path: string): { readonly dir: string; readonly name: string } {
  const slash = path.lastIndexOf("/");
  return slash === -1
    ? { dir: "", name: path }
    : { dir: path.slice(0, slash), name: path.slice(slash + 1) };
}

/** The directory's depth: "" is 0, "app" is 1. */
export function directoryDepth(dir: string): number {
  return dir === "" ? 0 : dir.split("/").length;
}

function parent(dir: string): string | null {
  if (dir === "") return null;
  return split(dir).dir;
}

/** The dependency files of a listing (path to blob ID), vendored paths left out. */
function dependencyFiles(entries: readonly ListedEntry[]): Map<string, string> {
  const files = new Map<string, string>();
  for (const entry of entries)
    if (
      entry.type === "blob" &&
      DEPENDENCY_FILES.has(split(entry.path).name) &&
      !vendored(entry.path)
    )
      files.set(entry.path, entry.sha);
  return files;
}

/** Whether a head listing holds a JavaScript manifest or lockfile anywhere (vendored excluded). */
export function hasJavaScript(entries: readonly ListedEntry[]): boolean {
  return [...dependencyFiles(entries).keys()].some((path) => JAVASCRIPT.has(split(path).name));
}

/** The dependency file names in each directory. */
function byDirectory(files: ReadonlyMap<string, string>): Map<string, Set<string>> {
  const dirs = new Map<string, Set<string>>();
  for (const path of files.keys()) {
    const { dir, name } = split(path);
    const names = dirs.get(dir) ?? new Set<string>();
    names.add(name);
    dirs.set(dir, names);
  }
  return dirs;
}

function holdsLockfile(names: ReadonlySet<string> | undefined): boolean {
  return names !== undefined && [...names].some((name) => LOCKFILES.has(name));
}

type Owner =
  | { readonly kind: "directory"; readonly dir: string }
  | { readonly kind: "unsupported"; readonly reason: DependencyLayoutReason }
  | { readonly kind: "nothing" };

/** The lockfile directory a changed dependency file at `dir` belongs to in the head. */
function owner(dir: string, head: ReadonlyMap<string, ReadonlySet<string>>): Owner {
  for (let at: string | null = dir; at !== null; at = parent(at)) {
    const names = head.get(at);
    if (names === undefined || !holdsLockfile(names)) continue;
    if (directoryDepth(at) > MAX_LOCKFILE_DEPTH) return { kind: "unsupported", reason: "too_deep" };
    const detection = detectPackageManager([...names]);
    if (!detection.ok) return { kind: "unsupported", reason: DETECTION_LAYOUT[detection.reason] };
    return { kind: "directory", dir: at };
  }
  // No lockfile owns it: a package.json left at the head is a manifest Kovo cannot evaluate; a
  // removed project (or a removed manifest) introduces nothing.
  return head.get(dir)?.has("package.json") === true
    ? { kind: "unsupported", reason: "manifest_without_lockfile" }
    : { kind: "nothing" };
}

/**
 * The lockfile directories a pull request's evaluation reads, from both sides' complete tree
 * listings (see the module comment).
 */
export function discoverDirectories(
  head: readonly ListedEntry[],
  base: readonly ListedEntry[],
  ignoredPaths: ReadonlySet<string> = new Set(),
  maxDirectories: number = MAX_LOCKFILE_DIRECTORIES,
): Discovery {
  if (!hasJavaScript(head)) return { kind: "no_dependencies" };
  const filtered = (entries: readonly ListedEntry[]) => {
    const files = dependencyFiles(entries);
    for (const path of ignoredPaths) files.delete(path);
    const originalDirs = byDirectory(dependencyFiles(entries));
    const dirs = byDirectory(files);
    return new Map(
      [...files].filter(([path]) => {
        for (let at: string | null = split(path).dir; at !== null; at = parent(at)) {
          const names = dirs.get(at);
          if (!holdsLockfile(originalDirs.get(at))) continue;
          const prefix = at === "" ? "" : `${at}/`;
          return (
            holdsLockfile(names) ||
            ![...(originalDirs.get(at) ?? [])].some(
              (name) => LOCKFILES.has(name) && ignoredPaths.has(`${prefix}${name}`),
            )
          );
        }
        return true;
      }),
    );
  };
  const headFiles = filtered(head);
  const baseFiles = filtered(base);
  const changed = [...new Set([...headFiles.keys(), ...baseFiles.keys()])]
    .filter((path) => headFiles.get(path) !== baseFiles.get(path))
    .toSorted();
  if (changed.length === 0) return { kind: "directories", directories: [] };
  const dirs = byDirectory(headFiles);
  const lockfileDirectories = [...dirs].filter(
    ([dir, names]) => holdsLockfile(names) && directoryDepth(dir) <= MAX_LOCKFILE_DEPTH,
  ).length;
  if (lockfileDirectories > maxDirectories)
    return { kind: "unsupported", reason: "too_many_lockfiles" };
  const directories = new Set<string>();
  for (const path of changed) {
    const found = owner(split(path).dir, dirs);
    if (found.kind === "unsupported") return found;
    if (found.kind === "directory") directories.add(found.dir);
  }
  return { kind: "directories", directories: [...directories].toSorted() };
}

/** Whether a compared path (or a rename's previous path) is a dependency file Kovo reads. */
function touchesDependencies(path: string | null): boolean {
  return path !== null && !vendored(path) && DEPENDENCY_FILES.has(split(path).name);
}

/**
 * When GitHub truncated a side's tree, Kovo cannot see every lockfile: a pull request whose compared
 * files (complete, else anything may have changed) touch no dependency file changes no dependency;
 * any other is over the bound (`tree_too_large`).
 */
export function discoverFromComparison(
  files: readonly { readonly path: string; readonly previousPath: string | null }[],
  complete: boolean,
): Discovery {
  if (!complete) return { kind: "unsupported", reason: "tree_too_large" };
  return files.some(
    (file) => touchesDependencies(file.path) || touchesDependencies(file.previousPath),
  )
    ? { kind: "unsupported", reason: "tree_too_large" }
    : { kind: "directories", directories: [] };
}
