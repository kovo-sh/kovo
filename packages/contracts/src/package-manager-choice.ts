import { z } from "zod";

import { exactVersionSchema } from "./npm.js";
import { tolerantReader } from "./tolerant-reader.js";
import { utcDateTimeSchema } from "./time.js";

// A repository admin's recorded package-manager choice for a repository whose root commits both
// `package-lock.json` and `pnpm-lock.yaml` (owner choice A, 2026-10-27; SPEC "Web
// application and onboarding UI" → "Two root lockfiles"). Detection still refuses such a root
// (`multiple_lockfiles`); once a choice is recorded, admission protects the repository with the
// chosen manager and its lockfile and ignores the other. The choice holds names, an exact version
// and where that version came from: never repository content.

/** The managers a two-lockfile root can choose between ("npm and pnpm"). */
export const PACKAGE_MANAGER_CHOICE_OPTIONS = ["npm", "pnpm"] as const;
export const packageManagerChoiceOptionSchema = z.enum(PACKAGE_MANAGER_CHOICE_OPTIONS);
export type PackageManagerChoiceOption = z.infer<typeof packageManagerChoiceOptionSchema>;

/** The root lockfile each option keeps; the other option's lockfile is ignored. */
export const PACKAGE_MANAGER_CHOICE_LOCKFILES = {
  npm: "package-lock.json",
  pnpm: "pnpm-lock.yaml",
} as const satisfies Record<PackageManagerChoiceOption, string>;

/**
 * Where the recorded exact version came from: the runtime resolver's package-manager sources
 * (`@kovo/core/lockfile` `PM_SOURCES`, in its precedence order), or `admin_entered` when the admin
 * typed a version instead of keeping the suggested one.
 */
export const PACKAGE_MANAGER_VERSION_SOURCES = [
  "package_manager_field",
  "volta",
  "engines",
  "ci",
  "bundled_with_node",
  "default",
  "admin_entered",
] as const;
export const packageManagerVersionSourceSchema = z.enum(PACKAGE_MANAGER_VERSION_SOURCES);
export type PackageManagerVersionSource = z.infer<typeof packageManagerVersionSourceSchema>;

/**
 * Why a manager is preselected in the picker, in precedence order: the root `packageManager`
 * field names it, CI installs with it (and not the other), or its lockfile changed most recently
 * (commit metadata only). `none` preselects nothing.
 */
export const PACKAGE_MANAGER_PRESELECTION_BASES = [
  "package_manager_field",
  "ci_install",
  "lockfile_recency",
  "none",
] as const;
export const packageManagerPreselectionBasisSchema = z.enum(PACKAGE_MANAGER_PRESELECTION_BASES);
export type PackageManagerPreselectionBasis = z.infer<typeof packageManagerPreselectionBasisSchema>;

/**
 * The stored choice (`repos.package_manager_choice`, a new nullable column no earlier release
 * reads). Writers use this strict schema; readers use {@link packageManagerChoiceReaderSchema},
 * which ignores members a later release may add.
 */
export const packageManagerChoiceSchema = z.strictObject({
  package_manager: packageManagerChoiceOptionSchema,
  /** The exact version the admin confirmed (validated against the compatibility matrix). */
  version: exactVersionSchema,
  version_source: packageManagerVersionSourceSchema,
  /** When the admin recorded it (stored as an RFC 3339 UTC string). */
  chosen_at: utcDateTimeSchema,
});
export type PackageManagerChoice = z.infer<typeof packageManagerChoiceSchema>;

/** The tolerant reader of a stored choice. */
export const packageManagerChoiceReaderSchema = tolerantReader(packageManagerChoiceSchema);

export type StoredPackageManagerChoice =
  | { readonly kind: "absent" }
  | { readonly kind: "recorded"; readonly choice: PackageManagerChoice }
  /** A stored value no known shape reads; callers refuse with `package_manager_choice_unreadable`. */
  | { readonly kind: "unreadable" };

/** Reads a stored choice without throwing; the stored value itself is never echoed. */
export function readPackageManagerChoice(value: unknown): StoredPackageManagerChoice {
  if (value === null || value === undefined) return { kind: "absent" };
  const parsed = packageManagerChoiceReaderSchema.safeParse(value);
  return parsed.success ? { kind: "recorded", choice: parsed.data } : { kind: "unreadable" };
}
