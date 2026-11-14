/**
 * Whether a declared workspace package set has members beyond the install root (D-228).
 *
 * The root is always a project. A `pnpm-workspace.yaml` `packages` list or a package.json
 * `workspaces` list whose patterns can select only the root (`.` or `./`, which Dyad generates
 * for single-package pnpm apps) declares no members, so the root is one single-package project.
 * Agent decision (2026-10-27), pending owner review #5501: SPEC "Monorepo projects (D-228)".
 *
 * Every reader that decides `hasWorkspaces` or the `workspaces` refusal uses these helpers so the
 * readers cannot disagree. Anything unrecognised counts as declaring members: when unsure, refuse.
 */

/** A positive pattern naming only the install root: `.`, `./`, `./.` and similar. */
export function isRootOnlyWorkspacePattern(pattern: string): boolean {
  const trimmed = pattern.endsWith("/") ? pattern.slice(0, -1) : pattern;
  return trimmed.length > 0 && trimmed.split("/").every((segment) => segment === ".");
}

/**
 * Whether a pattern list can select a member other than the root. Exclusions (`!glob`) never add
 * members, but an exclusion naming the root, a non-string entry or any other positive pattern
 * (including `*` and `**`, which match directories) counts as members.
 */
export function workspacePatternsDeclareMembers(patterns: readonly unknown[]): boolean {
  return patterns.some((pattern) => {
    if (typeof pattern !== "string") return true;
    if (pattern.startsWith("!")) return isRootOnlyWorkspacePattern(pattern.slice(1));
    return !isRootOnlyWorkspacePattern(pattern);
  });
}

/**
 * Whether a root package.json `workspaces` value declares members beyond the root: an array of
 * patterns, or yarn's `{ packages: [...] }` with no other keys. Any other present value counts.
 */
export function workspaceDeclarationHasMembers(declaration: unknown): boolean {
  if (declaration === undefined || declaration === null) return false;
  if (Array.isArray(declaration)) return workspacePatternsDeclareMembers(declaration);
  if (typeof declaration === "object") {
    const keys = Object.keys(declaration);
    const packages: unknown = Reflect.get(declaration, "packages");
    if (keys.length === 1 && keys[0] === "packages" && Array.isArray(packages))
      return workspacePatternsDeclareMembers(packages);
  }
  return true;
}
