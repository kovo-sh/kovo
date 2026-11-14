import type { PackageManager } from "@kovo/contracts";

import { compileWorkspaceGlob, PreparedPath } from "../../manifest/glob.js";
import { workspaceMemberOf } from "../../recipe/workspace.js";
import type { LockfileName } from "../parse.js";
import type { WorkspaceLayout, WorkspaceTreeEntry } from "../workspace/types.js";
import type { InstallRoot } from "./types.js";

/** v1: root configuration members may read, but fixes may never edit. */
export const SHARED_CONFIGURATION_VERSION = 1;
export const SHARED_CONFIGURATION = {
  npm: ["tsconfig.json", "tsconfig.*.json", "turbo.json", "nx.json", ".npmrc"],
  pnpm: ["tsconfig.json", "tsconfig.*.json", "turbo.json", "nx.json", ".npmrc"],
  yarn: ["tsconfig.json", "tsconfig.*.json", "turbo.json", "nx.json", ".npmrc", ".yarnrc"],
} as const satisfies Record<PackageManager, readonly string[]>;

/** Component-aware containment also supports the directory itself. */
export function withinTree(path: string, directory: string): boolean {
  return directory === "." || path === directory || path.startsWith(`${directory}/`);
}
export function relativeToRoot(path: string, root: string): string {
  return root === "." ? path : path.slice(root.length + 1);
}

export function rootFileOwnership(
  root: string,
  layout: WorkspaceLayout,
  lockfile: LockfileName,
  entries: readonly WorkspaceTreeEntry[],
  excluded: readonly string[],
  work: { remaining: number },
): InstallRoot["files"] {
  const members = layout.members.map((member) => member.path);
  const editable = new Set([lockfile, "package.json", "pnpm-workspace.yaml"]);
  const shared = SHARED_CONFIGURATION[layout.packageManager].map(compileWorkspaceGlob);
  const files: InstallRoot["files"][number][] = [];
  for (const entry of entries) {
    if (entry.mode !== "file" || !withinTree(entry.path, root)) continue;
    if (excluded.some((path) => withinTree(entry.path, path))) continue;
    const path = relativeToRoot(entry.path, root);
    const member = workspaceMemberOf(path, members);
    if (member === null) continue;
    // Each file is checked against several shared globs; prepare its characters only once.
    let preparedPath: PreparedPath | undefined;
    const access = editable.has(path)
      ? "shared_editable"
      : !path.includes("/") &&
          shared.some((matcher) => matcher.test((preparedPath ??= new PreparedPath(path)), work))
        ? "shared_readonly"
        : "owned";
    files.push({ path: entry.path, member, access });
  }
  return files;
}
