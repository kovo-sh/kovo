import { z } from "zod";

/** Public, unauthenticated routing fingerprint, pinned against the real npm proxy route. */
export const NPM_EDGE_PROBE_METHOD = "GET";
export const NPM_EDGE_PROBE_PATH = "/npm/sec003-public-probe";
export const NPM_EDGE_PROBE_STATUS = 401;

/** npm's maximum package name length. */
export const NPM_PACKAGE_NAME_MAX_LENGTH = 214;

// A name segment: URL-safe characters, never starting with `.` or `_` (npm has always rejected
// both). Upper case and `!'()*` are allowed because legacy registry packages (e.g. `JSONStream`)
// still appear in lockfiles; new-package rules are the registry's concern, not Kovo's.
const SEGMENT = "[A-Za-z0-9~-][A-Za-z0-9._~!'()*-]*";
// npm checks the leading-underscore rule on the whole name, which starts with `@` when scoped, so a
// scope or scoped name may begin with `_` (validate-npm-package-name). Real packages do, including
// malicious ones (OpenSSF MAL-2026-2420 `@_wnpm/wnpm-cli`); docs/decisions/advisory.md.
const SCOPED_SEGMENT = "[A-Za-z0-9~_-][A-Za-z0-9._~!'()*-]*";
const PACKAGE_NAME = new RegExp(`^(?:${SEGMENT}|@${SCOPED_SEGMENT}/${SCOPED_SEGMENT})$`);

/**
 * A public npm registry package name, optionally scoped (`express`, `@auth/core`). Names contain
 * `@` and `/` but never `:`, whitespace or path traversal.
 */
export const packageNameSchema = z
  .string()
  .min(1)
  .max(NPM_PACKAGE_NAME_MAX_LENGTH)
  .regex(PACKAGE_NAME, { error: "must be an npm package name" })
  .brand<"PackageName">();
export type PackageName = z.infer<typeof packageNameSchema>;

/** SemVer 2.0.0 (semver.org) exact version, no leading `v`, no range operators. */
const SEMVER =
  /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-((?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*)(?:\.(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*))*))?(?:\+([0-9a-zA-Z-]+(?:\.[0-9a-zA-Z-]+)*))?$/;

/** node-semver's maximum version string length. */
export const SEMVER_MAX_LENGTH = 256;

/**
 * Whether `major.minor.patch` are each at most `Number.MAX_SAFE_INTEGER`. SemVer 2.0.0 sets no bound,
 * but node-semver (what npm, pnpm and Kovo's range evaluation use) refuses larger components, so a
 * version beyond it can be neither installed nor compared. Numeric prerelease identifiers are not
 * bounded: node-semver accepts them (real versions carry long timestamps there).
 */
function hasSafeCoreComponents(version: string): boolean {
  const match = SEMVER.exec(version);
  if (match === null) return true; // reported by the regex check
  return [match[1], match[2], match[3]].every(
    (component) => Number(component) <= Number.MAX_SAFE_INTEGER,
  );
}

/**
 * An exact SemVer 2.0.0 version string (`4.12.12`, `0.40.0-preview.2`) that node-semver accepts:
 * at most 256 characters and no core component above `Number.MAX_SAFE_INTEGER`.
 */
export const exactVersionSchema = z
  .string()
  .max(SEMVER_MAX_LENGTH)
  .regex(SEMVER, { error: "must be an exact SemVer 2.0.0 version" })
  .refine(hasSafeCoreComponents, {
    error: "major, minor and patch must be at most 9007199254740991",
  });

/** An exact resolved package version, branded so it cannot be confused with a range. */
export const packageVersionSchema = exactVersionSchema.brand<"PackageVersion">();
export type PackageVersion = z.infer<typeof packageVersionSchema>;

/** The major component of an exact SemVer version (`"22.22.0"` → `22`). */
export function semverMajor(version: string): number {
  const match = SEMVER.exec(version);
  if (match === null) {
    throw new RangeError(`not an exact SemVer version: ${JSON.stringify(version)}`);
  }
  return Number(match[1]);
}

/**
 * The only registry origin Kovo supports (SPEC: "public npm registry only"; "committed lockfiles
 * retain valid canonical public URLs and integrity").
 */
export const NPM_PUBLIC_REGISTRY_ORIGIN = "https://registry.npmjs.org";

/**
 * The canonical public tarball URL the registry serves for `name@version`
 * (`https://registry.npmjs.org/@auth/core/-/core-0.40.0.tgz`). Callers pass a validated package
 * name and exact version.
 */
export function npmTarballUrl(name: string, version: string): string {
  const basename = name.startsWith("@") ? name.slice(name.indexOf("/") + 1) : name;
  return `${NPM_PUBLIC_REGISTRY_ORIGIN}/${name}/-/${basename}-${version}.tgz`;
}
