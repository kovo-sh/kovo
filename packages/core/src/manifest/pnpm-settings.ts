import { exactVersionSchema, packageNameSchema } from "@kovo/contracts";
import { z } from "zod";

import { workspaceYaml } from "../lockfile/workspace/yaml.js";
import { isJsonObject, type JsonObject } from "./bounded-json.js";
import { classifyDependencySpec } from "./dependency-spec.js";
import { parsePnpmSelector } from "./selectors.js";
import { parsePnpmCatalogs } from "./pnpm-catalogs.js";

// Settings-only YAML is single-package configuration, never inferred workspace membership.
// Resolution-changing features need graph support. Admitted text is preserved byte-for-byte.
const BOOLEAN_SETTINGS = new Set([
  "strictDepBuilds",
  "saveExact",
  "engineStrict",
  "packageManagerStrict",
  "packageManagerStrictVersion",
  "ignoreScripts",
  "strictPeerDependencies",
  "autoInstallPeers",
  "dedupePeerDependents",
  "resolvePeersFromWorkspaceRoot",
  "preferFrozenLockfile",
  "lockfileIncludeTarballUrl",
  "audit",
  "fund",
  "updateNotifier",
]);
const LIST_SETTINGS = new Set([
  "onlyBuiltDependencies",
  "ignoredBuiltDependencies",
  "neverBuiltDependencies",
  "minimumReleaseAgeExclude",
]);
const boolean = (value: unknown) => value === "true" || value === "false";
const MAX_LIST_ENTRY_LENGTH = 1024;
const listOfBoundedStrings = (value: unknown): value is string[] =>
  Array.isArray(value) &&
  value.every((item) => typeof item === "string" && item.length <= MAX_LIST_ENTRY_LENGTH);

/**
 * One `trustPolicyExclude` selector: an exact package name, or `name@version` where the version
 * is one exact SemVer version or a `||` union of them (the forms pnpm documents for this key).
 * Name patterns are refused: pnpm reads `*` and `?` as globs and a leading `!` as a negation, so
 * a name containing `*` (which legacy npm names may) is refused too. Ranges, tags and pnpm's
 * looser `v`/`=` version prefixes are refused; refusal keeps the workspace unsupported, as before.
 */
function trustPolicyExcludeEntry(entry: string): boolean {
  const at = entry.indexOf("@", entry.startsWith("@") ? 1 : 0);
  const name = at === -1 ? entry : entry.slice(0, at);
  if (name.includes("*") || !packageNameSchema.safeParse(name).success) return false;
  if (at === -1) return true;
  return entry
    .slice(at + 1)
    .split("||")
    .every((part) => {
      const version = part.replace(/^ +| +$/g, "");
      return exactVersionSchema.safeParse(version).success;
    });
}

// Decimal minutes; the failsafe YAML schema yields every scalar as a string.
const decimalMinutes = (value: unknown) => typeof value === "string" && /^\d{1,10}$/.test(value);

/**
 * Every admitted setting with a scalar or string-list value, and what it accepts. Shared by
 * `pnpm-workspace.yaml` and, for pnpm 9 and 10, root `.npmrc` (`pnpmNpmrcSetting`), so both files
 * admit exactly the same settings and values. Map-valued settings (`overrides`, `allowBuilds`,
 * catalogs) and `packages` exist only in the YAML file.
 */
const SETTING_VALUES: ReadonlyMap<string, (value: unknown) => boolean> = new Map<
  string,
  (value: unknown) => boolean
>([
  ...[...BOOLEAN_SETTINGS].map((key) => [key, boolean] as const),
  ...[...LIST_SETTINGS].map((key) => [key, listOfBoundedStrings] as const),
  ["minimumReleaseAge", decimalMinutes],
  ["trustPolicyIgnoreAfter", decimalMinutes],
  ["trustPolicy", (value) => value === "no-downgrade" || value === "off"],
  [
    "trustPolicyExclude",
    (value) => listOfBoundedStrings(value) && value.every(trustPolicyExcludeEntry),
  ],
  ["managePackageManagerVersions", (value) => value === "false"],
  ["pmOnFail", (value) => value === "ignore"],
  ["savePrefix", (value) => value === "" || value === "^" || value === "~"],
]);
const LIST_VALUED = new Set([...LIST_SETTINGS, "trustPolicyExclude"]);

/** The `.npmrc` spelling pnpm documents for a setting: `saveExact` is `save-exact`. */
const kebab = (name: string) => name.replaceAll(/[A-Z]/g, (letter) => `-${letter.toLowerCase()}`);
const NPMRC_SETTINGS: ReadonlyMap<string, string> = new Map(
  [...SETTING_VALUES.keys()].map((name) => [kebab(name), name]),
);

/**
 * The admitted `pnpm-workspace.yaml` setting a root `.npmrc` key sets for pnpm 9 and 10 (#1836),
 * or null. Only the documented kebab-case spelling counts: pnpm also folds other spellings
 * (`saveExact`, `SAVE_EXACT`), which the `.npmrc` check refuses rather than models. `list` says
 * whether the value is a list (written `key[]=…`).
 */
export function pnpmNpmrcSetting(
  key: string,
): { readonly name: string; readonly list: boolean } | null {
  const name = NPMRC_SETTINGS.get(key);
  return name === undefined ? null : { name, list: LIST_VALUED.has(name) };
}

/** Whether an admitted setting accepts this failsafe value (a string or a list of strings). */
export function pnpmSettingValueAccepted(name: string, value: string | readonly string[]): boolean {
  return SETTING_VALUES.get(name)?.(value) ?? false;
}

/** Settings whose value is a count of minutes (a JSON number in package.json). */
const MINUTES_SETTINGS = new Set(["minimumReleaseAge", "trustPolicyIgnoreAfter"]);
/** Settings pnpm reads as booleans (a JSON boolean in package.json, never a truthy string). */
const JSON_BOOLEAN_SETTINGS = new Set([...BOOLEAN_SETTINGS, "managePackageManagerVersions"]);

/**
 * Whether an admitted setting accepts this typed JSON value, as the root package.json `pnpm` field
 * holds it (pnpm 9 and 10 read settings there, #1879). The same allowlist and values as
 * `pnpm-workspace.yaml`, in JSON's own types: a boolean setting takes a JSON boolean, a minutes
 * setting a non-negative integer, a list setting an array of strings and every other setting a
 * string. A value of another type (the string `"false"`, which JavaScript reads as true, or the
 * number `1440.5`) is refused rather than modelled through pnpm's coercions.
 */
export function pnpmSettingJsonValueAccepted(name: string, value: unknown): boolean {
  const accepts = SETTING_VALUES.get(name);
  if (accepts === undefined) return false;
  if (JSON_BOOLEAN_SETTINGS.has(name)) return typeof value === "boolean" && accepts(`${value}`);
  // The decimal-minutes check refuses fractions, signs and exponents (`1e+21`).
  if (MINUTES_SETTINGS.has(name)) return typeof value === "number" && accepts(`${value}`);
  if (LIST_VALUED.has(name)) return Array.isArray(value) && accepts(value);
  return typeof value === "string" && accepts(value);
}

const settingsSchema = z.record(z.string(), z.json());

/** Returns validated settings, or null for unreadable/unsupported configuration. */
export function singlePackagePnpmSettings(text: string): JsonObject | null {
  const settings = pnpmWorkspaceSettings(text);
  return settings !== null && !Object.hasOwn(settings, "packages") ? settings : null;
}

/** Shared validation for root workspace and settings-only files; never admits nested roots. */
export function pnpmWorkspaceSettings(text: string): JsonObject | null {
  try {
    const parsed = settingsSchema.safeParse(workspaceYaml(text));
    if (!parsed.success) return null;
    const settings = parsed.data;
    if (!isJsonObject(settings) || parsePnpmCatalogs(settings) === null) return null;
    for (const [key, value] of Object.entries(settings)) {
      if (key === "catalog" || key === "catalogs" || key === "catalogMode") {
        // Validated together above, including every registry source.
      } else if (key === "packages") {
        if (!Array.isArray(value) || !value.every((item) => typeof item === "string")) return null;
      } else if (SETTING_VALUES.has(key)) {
        if (!SETTING_VALUES.get(key)!(value)) return null;
      } else if (key === "allowBuilds") {
        if (!isJsonObject(value) || !Object.values(value).every(boolean)) return null;
      } else if (key === "overrides") {
        if (!isJsonObject(value)) return null;
        for (const [selector, spec] of Object.entries(value)) {
          if (parsePnpmSelector(selector) === null || typeof spec !== "string") return null;
          const source = classifyDependencySpec(spec);
          if (source.kind === "invalid" || source.kind === "rejected") return null;
        }
      } else return null;
    }
    return settings;
  } catch {
    return null;
  }
}

export function isSettingsOnlyPnpmYaml(text: string): boolean {
  return singlePackagePnpmSettings(text) !== null;
}

/** Stable reasons why Kovo refuses to generate or verify fixes under admitted pnpm settings. */
export const PNPM_FIX_REFUSAL_REASONS = ["trust_policy_unenforced", "npmrc_unverifiable"] as const;
export type PnpmFixRefusalReason = (typeof PNPM_FIX_REFUSAL_REASONS)[number];

/**
 * Why fixes are refused for admitted root `pnpm-workspace.yaml` text, or null. Dependency checks
 * still accept these settings; only fix generation and verification refuse them.
 *
 * `trustPolicy: no-downgrade` compares a version's trust evidence with every earlier-published
 * version of the package. Kovo's verification install reads a packument filtered to the locked
 * versions, so the check passes there vacuously while the customer's own CI, reading the full
 * registry history, can refuse the same lockfile with `ERR_PNPM_TRUST_DOWNGRADE`. Fixes are
 * refused until Kovo can enforce the policy. Text the allowlist refuses yields null: callers
 * refuse it already.
 */
export function pnpmFixRefusal(text: string): PnpmFixRefusalReason | null {
  return pnpmWorkspaceSettings(text)?.["trustPolicy"] === "no-downgrade"
    ? "trust_policy_unenforced"
    : null;
}

export function pnpmSettingsOverrides(
  text: string | undefined,
): Record<string, string> | undefined {
  if (text === undefined) return undefined;
  const value = singlePackagePnpmSettings(text)?.["overrides"];
  if (!isJsonObject(value)) return undefined;
  return Object.fromEntries(
    Object.entries(value).filter(
      (entry): entry is [string, string] => typeof entry[1] === "string",
    ),
  );
}
