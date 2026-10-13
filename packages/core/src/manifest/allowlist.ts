import type { JsonValue } from "./bounded-json.js";
import { diffPointers, parsePointer, pointerWithin } from "./json-pointer.js";
import { reportablePointer } from "./safe-pointer.js";

// The package.json JSON-pointer allowlist (SPEC Sandbox B: "Enforce protected paths and
// package-manifest JSON-pointer allowlists in trusted code so an allowed `package.json` change
// cannot smuggle script/config edits"; decideMerge gate 4: "Exact allowed paths and allowed
// manifest fields"). Every leaf that differs between the base and the patched package.json must lie
// under a pointer the fix plan allows; everything else (scripts, engines, config, packageManager,
// other dependencies, …) is a violation.

/**
 * The only places an allowlist entry may point into: one dependency entry, or one override rule.
 * An entry granting a whole section (`/dependencies`), the document root or any other field is
 * refused, so a plan can never authorize a script or engines change by accident.
 */
export const ALLOWLISTABLE_PREFIXES = [
  ["dependencies"],
  ["devDependencies"],
  ["optionalDependencies"],
  ["peerDependencies"],
  ["overrides"],
  ["pnpm", "overrides"],
  ["resolutions"],
] as const;

export const MANIFEST_VIOLATION_REASONS = [
  "manifest_field_not_allowed", // a changed leaf outside every allowed pointer
  "invalid_allowlist_entry", // the plan's allowlist itself is too broad or malformed
] as const;
export type ManifestViolationReason = (typeof MANIFEST_VIOLATION_REASONS)[number];

export interface ManifestViolation {
  readonly pointer: string;
  readonly reason: ManifestViolationReason;
}

export interface ManifestCheck {
  /**
   * Every changed leaf, sorted, as it may be reported: a key that is neither a package name nor
   * an override selector (a new script name, say) appears as its position (`/scripts/#4`).
   */
  readonly changed: readonly string[];
  readonly violations: readonly ManifestViolation[];
}

/** Whether an allowlist entry points at one dependency entry or one override rule. */
export function isAllowlistablePointer(pointer: string): boolean {
  const tokens = parsePointer(pointer);
  if (tokens === null) return false;
  return ALLOWLISTABLE_PREFIXES.some(
    (prefix) =>
      tokens.length > prefix.length &&
      prefix.every((token, index) => tokens[index] === token) &&
      tokens.slice(prefix.length).every((token) => token !== ""),
  );
}

/**
 * Compares the base and patched package.json documents against the pointers a plan allows. A
 * change is allowed only at or below an allowed pointer; invalid or over-broad allowlist entries
 * are reported and grant nothing. Matching uses the exact pointers; what is reported shows hostile
 * keys only by position (`safe-pointer.ts`), since the result is persisted as evidence.
 */
export function checkManifestAllowlist(
  before: JsonValue,
  after: JsonValue,
  allowed: readonly string[],
): ManifestCheck {
  const violations: ManifestViolation[] = [];
  const grants: string[] = [];
  for (const pointer of allowed) {
    if (isAllowlistablePointer(pointer)) grants.push(pointer);
    else violations.push({ pointer, reason: "invalid_allowlist_entry" });
  }
  const changed = diffPointers(before, after);
  const reported = (pointer: string): string => reportablePointer(pointer, after, before);
  for (const pointer of changed) {
    if (!grants.some((grant) => pointerWithin(pointer, grant))) {
      violations.push({ pointer: reported(pointer), reason: "manifest_field_not_allowed" });
    }
  }
  return { changed: changed.map(reported), violations };
}
