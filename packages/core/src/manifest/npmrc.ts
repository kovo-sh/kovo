import { NPM_PUBLIC_REGISTRY_ORIGIN, type UnsupportedRepoReason } from "@kovo/contracts";

import { npmrcKeyName, type NpmrcEntry, type NpmrcValue, tokenizeNpmrc } from "./npmrc-tokens.js";
import {
  type PnpmFixRefusalReason,
  pnpmNpmrcSetting,
  pnpmSettingValueAccepted,
} from "./pnpm-settings.js";
import { primaryUnsupportedReason } from "./reasons.js";

// The repository's root `.npmrc`, which npm and pnpm both read (SPEC: "npm and pnpm, public npm
// registry only"; "Reject private registries … outside the supported public-registry model").
// pnpm lockfile v9 records only `integrity` for a tarball at the configured registry's standard
// path, so a private registry configured here is invisible in pnpm-lock.yaml; npm lockfiles may
// omit `resolved` too. Inventory therefore checks the registry settings here.
//
// Every check reads the file through the one strict tokenizer (`tokenizeNpmrc`): a file it cannot
// read exactly as npm 10/11 and pnpm 9-12 do is refused as `npmrc_unverifiable` (#1841, #1842).
//
// The file is hostile and often holds credentials (`//host/:_authToken=…`): nothing from it is
// returned. A rejection names only its reason and line number.

/** Longest `.npmrc` read (real files are a few lines). */
export const NPMRC_MAX_LENGTH = 64 * 1024;

export const NPMRC_REJECTION_REASONS = [
  "npmrc_too_large",
  "npmrc_unverifiable", // a construct Kovo cannot read exactly as npm and pnpm do (#1841)
  "registry_override", // `registry=` names anything but the public registry
  "package_manager_override", // executable package-manager configuration
  "scoped_registry", // `@scope:registry=` names anything but the public registry
  "unsupported_workspace_setting", // pnpm 9/10: a setting the pnpm-workspace.yaml allowlist refuses
] as const;
export type NpmrcRejectionReason = (typeof NPMRC_REJECTION_REASONS)[number];

export const NPMRC_REJECTION_UNSUPPORTED = {
  npmrc_too_large: "too_large",
  // Kovo cannot tell which registry the package managers would use.
  npmrc_unverifiable: "private_registry",
  package_manager_override: "unsupported_package_manager",
  registry_override: "private_registry",
  scoped_registry: "private_registry",
  // The coarse reason pnpm-workspace.yaml settings outside the allowlist get.
  unsupported_workspace_setting: "workspaces",
} as const satisfies Record<NpmrcRejectionReason, UnsupportedRepoReason>;

export interface NpmrcRejection {
  readonly reason: NpmrcRejectionReason;
  readonly unsupported: UnsupportedRepoReason;
  /** 1-based line of the setting; null for the whole file. */
  readonly line: number | null;
}

export type NpmrcResult =
  | { readonly ok: true }
  | {
      readonly ok: false;
      readonly unsupported: UnsupportedRepoReason;
      readonly rejections: readonly NpmrcRejection[];
    };

/** At most this many rejections are reported; one is enough to reject. */
const MAX_REJECTIONS = 50;

function unquote(value: string): string {
  const quoted = /^(["'])(.*)\1$/.exec(value);
  return quoted === null ? value : (quoted[2] ?? "");
}

/**
 * Whether a registry setting names the public registry exactly (`https://registry.npmjs.org`,
 * with or without the trailing slash), read the same way by every supported package manager.
 * Anything else, including plain HTTP, another path, an inline comment (pnpm 12 keeps it in the
 * value) or an environment reference (`${REGISTRY}`, unknowable here), is not the supported
 * registry.
 */
function isPublicRegistry(value: NpmrcValue | null): boolean {
  return (
    value?.kind === "plain" &&
    (value.text === NPM_PUBLIC_REGISTRY_ORIGIN || value.text === `${NPM_PUBLIC_REGISTRY_ORIGIN}/`)
  );
}

/** Package-manager self-management settings, by `npmrcKeyName`. */
const PACKAGE_MANAGER_KEYS = new Set([
  "managepackagemanagerversions",
  "pmonfail",
  "packagemanagerstrict",
  "packagemanagerstrictversion",
]);

class Rejections {
  readonly list: NpmrcRejection[] = [];

  add(reason: NpmrcRejectionReason, line: number | null): void {
    if (this.list.length < MAX_REJECTIONS) {
      this.list.push({ reason, unsupported: NPMRC_REJECTION_UNSUPPORTED[reason], line });
    }
  }

  result(): NpmrcResult {
    if (this.list.length === 0) return { ok: true };
    return {
      ok: false,
      unsupported: primaryUnsupportedReason(this.list.map((rejection) => rejection.unsupported)),
      rejections: this.list,
    };
  }
}

/** The tokenized file, or null after recording why it is refused. */
function entriesOf(text: string, rejections: Rejections): readonly NpmrcEntry[] | null {
  if (text.length > NPMRC_MAX_LENGTH) {
    rejections.add("npmrc_too_large", null);
    return null;
  }
  const tokens = tokenizeNpmrc(text);
  if (!tokens.ok) {
    rejections.add(tokens.reason, tokens.line);
    return null;
  }
  return tokens.entries;
}

/**
 * Checks the registry and package-manager controls of root `.npmrc` (null when absent): the
 * default registry and every scope registry must be public; manager overrides are refused; a file
 * the strict tokenizer cannot read is refused as `npmrc_unverifiable`.
 */
export function checkNpmrc(text: string | null): NpmrcResult {
  if (text === null) return { ok: true };
  const rejections = new Rejections();
  if (text.length <= NPMRC_MAX_LENGTH) {
    // Manager overrides are found in any spelling first, on lines split as broadly as any reader
    // splits them and before the strict read, so a hidden or quoted one keeps its own reason.
    // This scan only ever adds refusals.
    for (const [index, raw] of text.split(/\r\n|[\n\r\u0085\u2028\u2029\f\v]/u).entries()) {
      const line = raw.trim();
      if (line === "" || line.startsWith("#") || line.startsWith(";")) continue;
      const equals = line.indexOf("=");
      const rawKey = equals === -1 ? line : line.slice(0, equals);
      if (PACKAGE_MANAGER_KEYS.has(npmrcKeyName(unquote(rawKey.replace(/[#;].*$/, "").trim())))) {
        rejections.add("package_manager_override", index + 1);
      }
    }
  }
  const managerLines = new Set(rejections.list.map((rejection) => rejection.line));
  if (text.length > NPMRC_MAX_LENGTH) {
    rejections.add("npmrc_too_large", null);
    return rejections.result();
  }
  const tokens = tokenizeNpmrc(text);
  if (!tokens.ok) {
    // A manager override on the line the tokenizer stopped at keeps its own reason alone.
    if (!managerLines.has(tokens.line)) rejections.add(tokens.reason, tokens.line);
    return rejections.result();
  }
  for (const entry of tokens.entries) {
    const key = entry.key.toLowerCase();
    if (key === "registry" && (entry.array || !isPublicRegistry(entry.value))) {
      rejections.add("registry_override", entry.line);
    } else if (/^@[^:]+:registry$/.test(key) && (entry.array || !isPublicRegistry(entry.value))) {
      rejections.add("scoped_registry", entry.line);
    }
  }
  return rejections.result();
}

/** pnpm majors that read every non-auth setting from `.npmrc` (#1836). pnpm 11 and 12 do not. */
const PNPM_MAJORS_READING_NPMRC_SETTINGS = new Set([9, 10]);

/**
 * Per-registry settings (`//host/path/:<field>`) a pnpm 9/10 `.npmrc` may hold: credentials and
 * the client certificate for that registry. Others, `tokenHelper` (a command pnpm 9/10 run from a
 * project `.npmrc`) included, are refused.
 */
const PER_REGISTRY_FIELDS = new Set([
  "_auth",
  "_authToken",
  "_password",
  "username",
  "email",
  "certfile",
  "keyfile",
  "always-auth",
]);

/**
 * The settings of a pnpm repository's root `.npmrc` (null when absent) for the pnpm release that
 * runs it (`pmVersion`, the exact resolved release). pnpm 9 and 10 read every non-auth setting from
 * `.npmrc`, so there the file may set only what `pnpm-workspace.yaml` may (the same allowlist, in
 * pnpm's documented kebab-case spelling and with the same values), plus the registry settings
 * `checkNpmrc` checks and per-registry credentials. Anything else is refused as
 * `unsupported_workspace_setting`, the coarse reason (`workspaces`) the YAML file gets (#1836).
 * pnpm 11 and 12 read only registry, credential and TLS settings from `.npmrc`. An unparseable
 * version is treated as pnpm 9/10.
 */
export function checkPnpmNpmrcSettings(text: string | null, pmVersion: string): NpmrcResult {
  if (text === null) return { ok: true };
  const major = /^(\d+)\./.exec(pmVersion);
  if (major !== null && !PNPM_MAJORS_READING_NPMRC_SETTINGS.has(Number(major[1]))) {
    return { ok: true };
  }
  const rejections = new Rejections();
  for (const entry of entriesOf(text, rejections) ?? []) {
    const refuse = () => rejections.add("unsupported_workspace_setting", entry.line);
    if (entry.key.startsWith("//")) {
      const field = entry.key.slice(entry.key.lastIndexOf("/:") + 2);
      if (!entry.key.includes("/:") || !PER_REGISTRY_FIELDS.has(field) || entry.array) refuse();
      continue;
    }
    // `checkNpmrc` judges the registry settings.
    if (entry.key === "registry" || /^@[^:]+:registry$/.test(entry.key)) continue;
    const setting = pnpmNpmrcSetting(entry.key);
    const value = entry.value;
    if (
      setting === null ||
      setting.list !== entry.array ||
      value === null ||
      value.kind === "opaque"
    ) {
      refuse();
      continue;
    }
    // Every list setting validates its entries one by one, so each `key[]=` line is checked alone.
    if (!pnpmSettingValueAccepted(setting.name, setting.list ? [value.text] : value.text)) refuse();
  }
  return rejections.result();
}

/**
 * Why fixes are refused for a pnpm repository's root `.npmrc` (null when absent), or null.
 * Dependency checks still accept the file; only fix generation and verification refuse it.
 *
 * pnpm 10 reads `trust-policy` from `.npmrc` (pnpm 11.28 and 12.9 ignore it), and Kovo's
 * verification install cannot enforce `no-downgrade` (see `pnpmFixRefusal`). A file the strict
 * tokenizer cannot read (a bare carriage return; a key that is quoted, escaped, cut by `#` or `;`,
 * or expanded from `${…}`; a section; a duplicate key) refuses as `npmrc_unverifiable`. In the
 * rest, every key that normalizes to `trustpolicy` (case, `-`/`_`, trailing `[]`) with a value
 * other than exactly `off`, read the same by every reader, refuses as `trust_policy_unenforced`.
 */
export function npmrcFixRefusal(text: string | null): PnpmFixRefusalReason | null {
  if (text === null) return null;
  const tokens = tokenizeNpmrc(text);
  if (!tokens.ok) return tokens.reason;
  let refusal: PnpmFixRefusalReason | null = null;
  for (const entry of tokens.entries) {
    if (npmrcKeyName(entry.key) !== "trustpolicy") continue;
    if (entry.array || entry.value?.kind !== "plain" || entry.value.text !== "off") {
      refusal = "trust_policy_unenforced";
    }
  }
  return refusal;
}
