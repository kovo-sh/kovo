import type { FileRole } from "@kovo/contracts";

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

/** Whether a change to `path` on the default branch requires a new inventory. */
export function isInventoryInput(path: string): boolean {
  if (/(?:^|\/)(?:node_modules|\.git)\//.test(path)) return false;
  return (INVENTORY_INPUT_FILES as readonly string[]).includes(path.split("/").at(-1) ?? "");
}
