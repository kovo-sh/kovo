import { packageNameSchema } from "@kovo/contracts/npm";
import type { ChangedFile, FileRole } from "@kovo/contracts";

import { parsePointer } from "./json-pointer.js";

// File roles for changed-file evidence (contracts `FILE_ROLES`) and the files whose change on the
// default branch requires a new inventory (SPEC "Inventory triggers: … default-branch pushes
// touching manifests or lockfiles"). Nested manifests/configuration may change declared workspace
// membership or support, including a member that the previous inventory did not yet know about.

/** Root lockfiles of every package manager (supported or not: a new one changes detection). */
export const ROOT_LOCKFILES = [
  "package-lock.json",
  "pnpm-lock.yaml",
  "npm-shrinkwrap.json",
  "yarn.lock",
  "bun.lock",
  "bun.lockb",
] as const;

/**
 * Root files inventory reads: the manifest, lockfiles, the pnpm workspace marker, the registry
 * settings (`.npmrc`, `checkNpmrc`) and the runtime declarations the compatibility matrix resolves.
 */
export const INVENTORY_INPUT_FILES = [
  "package.json",
  ...ROOT_LOCKFILES,
  "pnpm-workspace.yaml",
  ".npmrc",
  ".nvmrc",
  ".node-version",
  ".tool-versions",
  "nx.json",
  "turbo.json",
  "lerna.json",
] as const;

const SOURCE_EXTENSIONS =
  /\.(?:[cm]?[jt]sx?|vue|svelte|astro|json|css|scss|sass|less|html|md|mdx|graphql|gql)$/i;

/** The role of a changed file. */
export function classifyFileRole(path: string): FileRole {
  // Evidence currently interprets manifest pointers at the root; P4 adds member-qualified edits.
  if (path === "package.json") return "manifest";
  if ((ROOT_LOCKFILES as readonly string[]).includes(path)) return "lockfile";
  if (SOURCE_EXTENSIONS.test(path)) return "source";
  return "other";
}

/**
 * File names that declare or pin dependencies wherever they sit: every workspace member and every
 * install root has its own manifest, and a nested install root has its own lockfile and workspace
 * manifest. Base freshness treats these at any depth as dependency files, a superset of the
 * repository-root roles above, so a base change under any workspace or install root re-verifies.
 */
export const DEPENDENCY_FILE_NAMES = [
  "package.json",
  ...ROOT_LOCKFILES,
  "pnpm-workspace.yaml",
] as const;

/**
 * Whether a base change to `path` may change the dependencies of some workspace or install root.
 * It matches the file name at any depth (including vendored `node_modules`, conservatively), so it
 * holds for every path `classifyFileRole` marks `manifest` or `lockfile` and never narrows.
 */
export function isDependencyFilePath(path: string): boolean {
  return (DEPENDENCY_FILE_NAMES as readonly string[]).includes(path.split("/").at(-1) ?? "");
}

/** Persisted catalog entry pointers come only from the trusted root YAML proof, never by name
 * alone. This checks the shape of trusted evidence; the allowed-files check still certifies
 * the actual before/after bytes. */
export function isDependencyFile(file: ChangedFile): boolean {
  if (file.path !== "pnpm-workspace.yaml")
    return file.role === "manifest" || file.role === "lockfile";
  const pointers = file.manifest_pointers ?? [];
  return (
    file.role === "manifest" &&
    file.change === "modified" &&
    pointers.length > 0 &&
    pointers.every((pointer) => {
      const tokens = parsePointer(pointer);
      return (
        tokens !== null &&
        ((tokens.length === 2 && tokens[0] === "catalog") ||
          (tokens.length === 3 &&
            tokens[0] === "catalogs" &&
            /^[A-Za-z0-9_-]{1,256}$/u.test(tokens[1]!))) &&
        packageNameSchema.safeParse(tokens.at(-1)).success
      );
    })
  );
}

/** Whether a change to `path` on the default branch requires a new inventory. */
export function isInventoryInput(path: string): boolean {
  if (/(?:^|\/)(?:node_modules|\.git)\//.test(path)) return false;
  return (INVENTORY_INPUT_FILES as readonly string[]).includes(path.split("/").at(-1) ?? "");
}
