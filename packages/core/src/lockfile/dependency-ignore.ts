import { z } from "zod";
import { hasControlCharacter } from "@kovo/contracts/primitives";
import { parseBoundedJson } from "../manifest/bounded-json.js";
import { PACKAGE_JSON_LIMITS } from "../manifest/package-json.js";
import { isRootOnlyWorkspacePattern } from "../manifest/workspace-members.js";

import { compileWorkspaceGlob, PreparedPath } from "../manifest/glob.js";
import { workspaceYaml } from "./workspace/yaml.js";

export const DEPENDENCY_IGNORE_CONFIG_PATH = ".kovo/config.yml";
export const DEPENDENCY_IGNORE_CONFIG_MAX_BYTES = 16_384;

const patternSchema = z
  .string()
  .min(1)
  .max(200)
  .refine(
    (pattern) =>
      !pattern.startsWith("/") &&
      !pattern.startsWith("!") &&
      !pattern.includes("..") &&
      !/[\\:()]/u.test(pattern) &&
      !hasControlCharacter(pattern) &&
      pattern.split("/").every((part) => part !== "" && part !== "."),
  );
const configSchema = z.strictObject({
  dependencies: z.strictObject({ ignore: z.array(patternSchema).max(50) }),
});

/** Alias-free bounded YAML and Zod; malformed configuration never enables an ignore. */
export function parseDependencyIgnoreConfig(text: string): readonly string[] | null {
  if (text.length > DEPENDENCY_IGNORE_CONFIG_MAX_BYTES) return null;
  try {
    const parsed = configSchema.safeParse(workspaceYaml(text));
    return parsed.success ? parsed.data.dependencies.ignore : null;
  } catch {
    return null;
  }
}

/** The same anchored, case-sensitive POSIX matcher used for workspace membership. */
export function dependencyIgnoreMatches(
  pattern: string,
  path: string,
  work = { remaining: 1_000_000 },
): boolean {
  return compileWorkspaceGlob(pattern).test(new PreparedPath(path), work);
}

/** Only declaration parsing: unrelated package-manager settings remain the evaluator's concern. */
export function dependencyWorkspacePatterns(
  text: string,
  kind: "package.json" | "pnpm-workspace.yaml",
): readonly string[] | null {
  try {
    const parsedJson = kind === "package.json" ? parseBoundedJson(text, PACKAGE_JSON_LIMITS) : null;
    if (parsedJson !== null && !parsedJson.ok) return null;
    const value: unknown = parsedJson?.ok ? parsedJson.value : workspaceYaml(text);
    if (typeof value !== "object" || value === null || Array.isArray(value)) return null;
    const key = kind === "package.json" ? "workspaces" : "packages";
    let declaration: unknown = Object.hasOwn(value, key) ? Reflect.get(value, key) : undefined;
    if (declaration === undefined) return [];
    if (
      kind === "package.json" &&
      typeof declaration === "object" &&
      declaration !== null &&
      !Array.isArray(declaration)
    )
      declaration = Object.hasOwn(declaration, "packages")
        ? Reflect.get(declaration, "packages")
        : null;
    const parsed = z.array(z.string().min(1).max(200)).max(100).safeParse(declaration);
    if (!parsed.success) return null;
    // The root is always a member, so root-only positive patterns (`.`, `./`) name no further
    // member; an exclusion of the root (`!.`) still fails the pattern check below.
    const patterns = parsed.data.filter((pattern) => !isRootOnlyWorkspacePattern(pattern));
    if (
      patterns.some(
        (pattern) =>
          !patternSchema.safeParse(pattern.startsWith("!") ? pattern.slice(1) : pattern).success,
      )
    )
      return null;
    return patterns;
  } catch {
    return null;
  }
}

/** pnpm/npm exclude patterns remove members regardless of declaration order. */
export function dependencyWorkspaceMember(
  patterns: readonly string[],
  path: string,
  work = { remaining: 1_000_000 },
): boolean {
  return (
    patterns.some(
      (pattern) => !pattern.startsWith("!") && dependencyIgnoreMatches(pattern, path, work),
    ) &&
    !patterns.some(
      (pattern) => pattern.startsWith("!") && dependencyIgnoreMatches(pattern.slice(1), path, work),
    )
  );
}
