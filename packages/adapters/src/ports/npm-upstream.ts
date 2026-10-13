import {
  NPM_PUBLIC_REGISTRY_ORIGIN,
  exactVersionSchema,
  hasControlCharacter,
  packageNameSchema,
  packageVersionSchema,
  sriSha512Schema,
  whenValid,
  type PackageName,
  type PackageVersion,
  type SriSha512,
} from "@kovo/contracts";
import { z } from "zod";

import {
  byteLimitSchema,
  bytesSchema,
  httpsUrlSchema,
  jsonObjectSchema,
  type ByteStream,
  type CallOptions,
  type JsonObject,
} from "./common.js";

// NpmUpstreamPort: the public npm registry, read by the npm proxy and by target resolution. SPEC:
// "It pulls public npm metadata/tarballs, verifies integrity and stores content-addressed tarballs
// … Record served artifact integrity, publication metadata, scripts and provenance evidence";
// provenance table (young versions, added lifecycle scripts, changed maintainer identity, missing
// provenance). Notes: docs/libraries/sandbox-ai-feeds.md §3 and §7.
//
// Implementations (BUILD_PLAN item 11; status in docs/status/adapters.md): real HTTP client over
// `https://registry.npmjs.org` (conditional GETs by ETag, byte-bounded bodies, tarballs only from
// the registry origin); fake registry serving real tarballs with real integrity values.
//
// Everything is a side-effect-free read: UnavailableError and RateLimitedError are retryable.
// Registry content is hostile. The typed `packument` view is what trusted code decides on; the raw
// `document` is kept only so the proxy can re-serve it to package managers after its own filtering
// (packuments carry fields npm/pnpm need that Kovo never interprets). Integrity is never taken on
// trust: the proxy hashes every tarball it serves, including cache hits.

/**
 * The registry origin tarball URLs must use (also the only origin the adapter contacts): the one
 * contracts defines for every package (`NPM_PUBLIC_REGISTRY_ORIGIN`).
 */
export const NPM_REGISTRY_ORIGIN = NPM_PUBLIC_REGISTRY_ORIGIN;

/** A canonical registry tarball URL (`https://registry.npmjs.org/<name>/-/<file>.tgz`). */
export const npmTarballUrlSchema = httpsUrlSchema.refine(
  (value) => {
    const url = new URL(value);
    return (
      url.origin === NPM_REGISTRY_ORIGIN &&
      url.search === "" &&
      url.hash === "" &&
      /^\/(?:@[^/]+\/)?[^/]+\/-\/[^/]+\.tgz$/.test(url.pathname)
    );
  },
  { ...whenValid, error: "must be a registry.npmjs.org tarball URL" },
);

/** A dist-tag name (`latest`, `next`, `v4-lts`). */
export const distTagSchema = z
  .string()
  .regex(/^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/, { error: "must be a dist-tag name" });

/** A dependency range string from a manifest (`^1.2.3`, `npm:other@1`, `workspace:*`, …). */
export const dependencyRangeSchema = z
  .string()
  .max(1024)
  .refine((value) => !hasControlCharacter(value), {
    ...whenValid,
    error: "must not contain control characters",
  });

const dependencyMapSchema = z.record(packageNameSchema, dependencyRangeSchema);

/** An npm registry signature over `${name}@${version}:${integrity}` (ECDSA P-256). */
export const registrySignatureSchema = z.strictObject({
  keyid: z.string().min(1).max(256),
  sig: z.string().regex(/^[A-Za-z0-9+/]+={0,2}$/, { error: "must be base64" }),
});

export const npmDistSchema = z.strictObject({
  tarball: npmTarballUrlSchema,
  /**
   * SRI sha512 ({@link registryIntegrity}); null for old versions published before sha512
   * integrity (none, or only a legacy `sha1-` value, which `shasum` carries anyway).
   */
  integrity: sriSha512Schema.nullable(),
  /** Legacy SHA-1 hex digest of the tarball. */
  shasum: z
    .string()
    .regex(/^[0-9a-f]{40}$/)
    .nullable(),
  signatures: z.array(registrySignatureSchema).max(16),
  /** Whether the registry advertises attestations (`dist.attestations`) for this version. */
  hasAttestations: z.boolean(),
  unpackedSize: z.int().nonnegative().nullable(),
});
export type NpmDist = z.infer<typeof npmDistSchema>;

/** The lifecycle scripts that run on install (SPEC: "Added lifecycle scripts … Review-only"). */
export const INSTALL_LIFECYCLE_SCRIPTS = ["preinstall", "install", "postinstall"] as const;

/**
 * The publishing identity of a version (`_npmUser`). Names only: publisher emails are personal data
 * and are never read. `trustedPublisher` is set for OIDC trusted publishing, so a switch between
 * human and trusted publishing shows up as an identity change.
 */
export const npmPublisherSchema = z.strictObject({
  name: z.string().min(1).max(214),
  trustedPublisher: z.string().min(1).max(64).nullable(),
});
export type NpmPublisher = z.infer<typeof npmPublisherSchema>;

export const npmVersionSchema = z.strictObject({
  version: packageVersionSchema,
  dist: npmDistSchema,
  dependencies: dependencyMapSchema,
  optionalDependencies: dependencyMapSchema,
  peerDependencies: dependencyMapSchema,
  os: z.array(z.string().min(1).max(64)).max(64).exactOptional(),
  cpu: z.array(z.string().min(1).max(64)).max(64).exactOptional(),
  libc: z
    .union([z.string().min(1).max(64), z.array(z.string().min(1).max(64)).max(64)])
    .transform((value) => (typeof value === "string" ? [value] : value))
    .exactOptional(),
  /**
   * Whether installing runs lifecycle scripts: the abbreviated `hasInstallScript`, or in a full
   * packument the presence of any {@link INSTALL_LIFECYCLE_SCRIPTS} (or a `binding.gyp` default
   * rebuild, which npm treats as an implicit install script).
   */
  hasInstallScript: z.boolean(),
  /** Full packuments only: which install lifecycle scripts are declared (names, never commands). */
  installScripts: z.array(z.enum(INSTALL_LIFECYCLE_SCRIPTS)).nullable(),
  deprecated: z.boolean(),
  /** Full packuments only; null when absent (SPEC: "do not fabricate historical maintainer data"). */
  publisher: npmPublisherSchema.nullable(),
  /** Full packuments only: maintainer names at publication; null when absent. */
  maintainers: z.array(z.string().min(1).max(214)).max(1000).nullable(),
  /** Public declared source repository; ephemeral metadata only. */
  repository: z.string().max(2048).nullable().exactOptional(),
});
export type NpmVersion = z.infer<typeof npmVersionSchema>;

export const PACKUMENT_KINDS = ["full", "abbreviated"] as const;
export type PackumentKind = (typeof PACKUMENT_KINDS)[number];

/**
 * The typed view of a packument, built version by version so one malformed legacy version never
 * fails the whole document (popular packages carry old junk versions):
 * - A version is omitted, and counted in `omittedVersions`, when its key is not an exact SemVer
 *   version, its `version` differs from its key, or its entry fails {@link npmVersionSchema}
 *   (non-object dependency maps, dependency names outside `packageNameSchema`, a tarball URL off
 *   the registry origin, an integrity that is neither sha512 nor legacy sha1, …). Omitted versions
 *   can never be targeted; nothing about them is guessed. Use {@link partitionPackumentVersions}.
 * - A legacy `sha1-` integrity is not malformed: it becomes `integrity: null`
 *   ({@link registryIntegrity}).
 * - Dist-tags with a malformed name or version are dropped; a kept dist-tag may still name an
 *   omitted version, so look it up in `versions` before using it.
 */
export const packumentSchema = z.strictObject({
  name: packageNameSchema,
  kind: z.enum(PACKUMENT_KINDS),
  distTags: z.record(distTagSchema, packageVersionSchema),
  versions: z.record(exactVersionSchema, npmVersionSchema),
  /** How many registry versions were left out of `versions` as malformed (see above). */
  omittedVersions: z.int().nonnegative(),
  /** Full parser's exact version keys omitted as malformed; no manifest contents. */
  omittedVersionNames: z.array(exactVersionSchema).max(100_000).exactOptional(),
  /**
   * Publication time per version (full packuments only: the abbreviated form has no `time`). The
   * P1 cooldown and publication evidence need it, so target resolution reads the full packument.
   */
  publishedAt: z.record(exactVersionSchema, z.date()).nullable(),
  /** The packument's own modification time, when present. */
  modifiedAt: z.date().nullable(),
});
export type Packument = z.infer<typeof packumentSchema>;

export type PackumentResult =
  | {
      readonly outcome: "found";
      readonly packument: Packument;
      /** The document as served, for the proxy to filter and re-serve. Never logged or persisted. */
      readonly document: JsonObject;
      /** The response ETag for a later conditional request. */
      readonly etag: string | null;
    }
  | { readonly outcome: "not_modified" }
  /** The registry has no such package (404), e.g. unpublished or a typo-squat that was removed. */
  | { readonly outcome: "not_found" };

/** All typed version metadata, without the document used only for re-serving. */
export type PackumentMetadataResult =
  | { readonly outcome: "found"; readonly packument: Packument; readonly etag: string | null }
  | { readonly outcome: "not_modified" | "not_found" };

export const packumentRequestSchema = z.strictObject({
  name: packageNameSchema,
  kind: z.enum(PACKUMENT_KINDS),
  /** Send `If-None-Match` with this ETag; `not_modified` when it still matches. */
  ifNoneMatch: z.string().min(1).max(512).nullable(),
  maxBytes: byteLimitSchema,
});
export type PackumentRequest = z.infer<typeof packumentRequestSchema>;

export const tarballRequestSchema = z.strictObject({
  name: packageNameSchema,
  version: packageVersionSchema,
  /** `dist.tarball` from the packument; the adapter refuses any other origin. */
  tarballUrl: npmTarballUrlSchema,
  maxBytes: byteLimitSchema,
});
export type TarballRequest = z.infer<typeof tarballRequestSchema>;

export interface TarballResponse {
  /** The tarball bytes; errors with LimitExceededError past `maxBytes`. Unverified until hashed. */
  readonly body: ByteStream;
  /** The declared length, when the registry sent one (a hint only). */
  readonly contentLength: number | null;
}

/** One SLSA/npm attestation statement (claims; see {@link NpmUpstreamPort.getAttestations}). */
export const npmAttestationSchema = z.strictObject({
  /** e.g. `https://slsa.dev/provenance/v1`, `https://github.com/npm/attestation/tree/main/specs/publish/v0.1`. */
  predicateType: z.string().min(1).max(512),
  /** In-toto statement subjects (`pkg:npm/<name>@<version>` with its sha512 digest). */
  subjects: z
    .array(
      z.strictObject({
        name: z.string().min(1).max(512),
        sha512Hex: z
          .string()
          .regex(/^[0-9a-f]{128}$/)
          .nullable(),
      }),
    )
    .max(16),
  /** SLSA provenance: the source repository URL, when the predicate records one. */
  sourceRepository: z.string().max(2048).nullable(),
  /** SLSA provenance: the build workflow path and ref (e.g. `.github/workflows/release.yml`). */
  workflowPath: z.string().max(1024).nullable(),
  workflowRef: z.string().max(1024).nullable(),
  /** The Sigstore bundle as served, for signature verification by the caller. */
  bundle: jsonObjectSchema,
});
export type NpmAttestation = z.infer<typeof npmAttestationSchema>;

export const registryKeySchema = z.strictObject({
  keyid: z.string().min(1).max(256),
  /** DER-encoded SubjectPublicKeyInfo (ECDSA P-256). */
  publicKeySpki: bytesSchema,
  expires: z.date().nullable(),
});
export type RegistryKey = z.infer<typeof registryKeySchema>;

/** Options of a packument read. */
export interface PackumentReadOptions extends CallOptions {
  /** getPackument only (metadata-only reads ignore this option): consume complete version
   * records incrementally. The returned document/view have empty
   * versions; root metadata (including trailing publication times) is still returned. Nothing
   * may be published before the complete body validates. reset handles retries and duplicate
   * root versions fields; visit includes malformed records so a duplicate can remove a candidate.
   * Consumers must not retain parsed records or their typed views. */
  readonly consumeVersions?: {
    reset(): void;
    visit(key: string, document: JsonObject | null, version: NpmVersion | null): void;
  };
  /**
   * Called with the size of each part of the response body before it is kept, so the caller can
   * count a document (tens of MB for popular packages) against its memory budget before holding
   * it. Whatever it throws stops the read: nothing more is read, buffered or parsed, and the
   * exception reaches the caller unchanged (it is never retried). The sizes sum to the body's
   * length; a retried attempt reports its body again.
   */
  readonly reserveBytes?: (bytes: number) => void;
  /** Additional structural allocation credits, independent of wire size; held with the body lease. */
  readonly reserveParseBytes?: (bytes: number) => void;
}

export interface NpmUpstreamPort {
  /**
   * Fetches a packument. `full` includes `time`, scripts and publisher data; `abbreviated`
   * (`application/vnd.npm.install-v1+json`) is much smaller and is what package managers request.
   * LimitExceededError past `maxBytes`.
   * Structural parsing limits fail as UnavailableError with code `packument_too_large`:
   * registry decisions must wait/retry, never treat it as absent evidence or a clean version.
   */
  getPackument(request: PackumentRequest, options?: PackumentReadOptions): Promise<PackumentResult>;

  /**
   * Same complete body, UTF-8, JSON and per-version validation as getPackument, but does not
   * retain uninterpreted manifest fields. All versions and publication metadata are returned.
   */
  getPackumentMetadata(
    request: PackumentRequest,
    options?: PackumentReadOptions,
  ): Promise<PackumentMetadataResult>;

  /** Streams a tarball from the registry origin. NotFoundError if the registry no longer has it. */
  fetchTarball(request: TarballRequest, options?: CallOptions): Promise<TarballResponse>;

  /**
   * Attestations for a version (`/-/npm/v1/attestations/<name>@<version>`); an empty list when the
   * version has none (404). These are unverified claims: the port decodes the DSSE statements but
   * does not verify Sigstore signatures or certificate chains, so callers may record them as
   * evidence and match subject digests but must not treat them as proof.
   */
  getAttestations(name: PackageName, version: PackageVersion): Promise<readonly NpmAttestation[]>;

  /** The registry's signing keys (`/-/npm/v1/keys`) for verifying `dist.signatures`. */
  getRegistryKeys(): Promise<readonly RegistryKey[]>;
}

const SHA1_SRI = /^sha1-[A-Za-z0-9+/]{27}=$/;

/**
 * The typed `dist.integrity` of a registry version: the sha512 SRI value; null when the version
 * predates sha512 integrity (absent, or only legacy `sha1-` values); undefined when the value is
 * malformed or names two different sha512 digests (the version is then omitted). SRI strings may
 * list several space-separated hashes.
 */
export function registryIntegrity(value: unknown): SriSha512 | null | undefined {
  if (value === undefined || value === null) return null;
  if (typeof value !== "string") return undefined;
  const tokens = value.split(/\s+/).filter((token) => token.length > 0);
  if (tokens.length === 0) return null;
  const sha512 = new Set<SriSha512>();
  for (const token of tokens) {
    const parsed = sriSha512Schema.safeParse(token);
    if (parsed.success) sha512.add(parsed.data);
    else if (!SHA1_SRI.test(token)) return undefined;
  }
  if (sha512.size > 1) return undefined;
  const [only] = sha512;
  return only ?? null;
}

/**
 * Splits mapped registry version entries (keyed by the registry's version string) into the typed
 * versions and a count of omitted ones, following {@link packumentSchema}'s per-version rule. The
 * real adapter and the fake both build `versions`/`omittedVersions` with it.
 */
export function partitionPackumentVersions(candidates: Readonly<Record<string, unknown>>): {
  readonly versions: Record<string, NpmVersion>;
  readonly omittedVersions: number;
} {
  const versions: Record<string, NpmVersion> = {};
  let omittedVersions = 0;
  for (const [key, candidate] of Object.entries(candidates)) {
    const parsed = npmVersionSchema.safeParse(candidate);
    if (
      exactVersionSchema.safeParse(key).success &&
      parsed.success &&
      parsed.data.version === key
    ) {
      versions[key] = parsed.data;
    } else {
      omittedVersions += 1;
    }
  }
  return { versions, omittedVersions };
}

/** The message npm registry signatures cover: `${name}@${version}:${integrity}`. */
export function registrySignaturePayload(
  name: PackageName,
  version: PackageVersion,
  integrity: z.infer<typeof sriSha512Schema>,
): string {
  return `${name}@${version}:${integrity}`;
}
