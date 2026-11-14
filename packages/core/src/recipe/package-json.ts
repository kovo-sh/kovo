import type { Sha256Hex } from "@kovo/contracts";

import {
  workspaceDeclarationHasMembers,
  workspacePatternsDeclareMembers,
} from "../manifest/workspace-members.js";
import { sha256Hex } from "./digest/sha256.js";
import { RECIPE_INPUT_LIMITS } from "./inputs.js";
import { jsonDepthWithin } from "./reports/bounded.js";

// The package.json facts recipe discovery and the fingerprint read: scripts, engines,
// `packageManager`, dependency names and whether workspaces are declared. Only own, string-valued
// members are read, into Maps, so `__proto__` or odd member types cannot confuse anything. (The
// inventory's full manifest validation, workspaces rejection included, is `@kovo/core/manifest`'s.)

const MAX_SCRIPTS = 1_000;
const DEPENDENCY_FIELDS = [
  "dependencies",
  "devDependencies",
  "optionalDependencies",
  "peerDependencies",
] as const;

export interface PackageFacts {
  readonly scripts: ReadonlyMap<string, string>;
  /** `engines` members with string values (`node`, `npm`, `pnpm`, …). */
  readonly engines: ReadonlyMap<string, string>;
  /** The raw `packageManager` field, when it is a string. */
  readonly packageManager: string | null;
  /** Volta pins (`volta.node`, `volta.npm`, `volta.pnpm`), a runtime declaration. */
  readonly volta: ReadonlyMap<string, string>;
  /** Names declared in any dependency field. */
  readonly dependencyNames: ReadonlySet<string>;
  readonly hasWorkspaces: boolean;
  /** Whether the manifest declares an `eslintConfig` member (ESLint's package.json configuration). */
  readonly eslintConfigDeclared: boolean;
  /** SHA-256 of the file text. */
  readonly sha256: Sha256Hex;
}

export type PackageFactsResult =
  | { readonly ok: true; readonly facts: PackageFacts }
  | {
      readonly ok: false;
      readonly reason: "invalid_package_json" | "too_large";
      readonly sha256: Sha256Hex;
    };

function isRecord(value: unknown): value is object {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function stringEntries(value: unknown, limit: number): Map<string, string> {
  const out = new Map<string, string>();
  if (!isRecord(value)) return out;
  for (const key of Object.keys(value)) {
    if (out.size >= limit) break;
    const member: unknown = Reflect.get(value, key);
    if (typeof member === "string") out.set(key, member);
  }
  return out;
}

/** Reads the recipe-relevant facts of a package.json text. */
export function readPackageFacts(content: string): PackageFactsResult {
  const sha256 = sha256Hex(content);
  if (content.length > RECIPE_INPUT_LIMITS.maxFileLength) {
    return { ok: false, reason: "too_large", sha256 };
  }
  if (!jsonDepthWithin(content, 64)) return { ok: false, reason: "invalid_package_json", sha256 };
  let parsed: unknown;
  try {
    parsed = JSON.parse(content);
  } catch {
    return { ok: false, reason: "invalid_package_json", sha256 };
  }
  if (!isRecord(parsed)) return { ok: false, reason: "invalid_package_json", sha256 };

  const packageManager: unknown = Reflect.get(parsed, "packageManager");
  const dependencyNames = new Set<string>();
  for (const field of DEPENDENCY_FIELDS) {
    const deps: unknown = Reflect.get(parsed, field);
    if (isRecord(deps)) for (const name of Object.keys(deps)) dependencyNames.add(name);
  }
  const workspaces: unknown = Reflect.get(parsed, "workspaces");
  return {
    ok: true,
    facts: {
      scripts: stringEntries(Reflect.get(parsed, "scripts"), MAX_SCRIPTS),
      engines: stringEntries(Reflect.get(parsed, "engines"), 50),
      packageManager: typeof packageManager === "string" ? packageManager : null,
      volta: stringEntries(Reflect.get(parsed, "volta"), 10),
      dependencyNames,
      // A root-only declaration (`["."]`) is one project (D-228); other shapes keep refusing.
      hasWorkspaces:
        (Array.isArray(workspaces) && workspacePatternsDeclareMembers(workspaces)) ||
        (isRecord(workspaces) &&
          Object.keys(workspaces).length > 0 &&
          workspaceDeclarationHasMembers(workspaces)),
      eslintConfigDeclared: Object.hasOwn(parsed, "eslintConfig"),
      sha256,
    },
  };
}
