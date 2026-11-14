import { imageDigestSchema, repoFilePathSchema } from "@kovo/contracts/primitives";
import { lockfileFormatSchema } from "@kovo/contracts";
import { z } from "zod";

import { runtimeCatalogSchema } from "../lockfile/compat.js";

// Inputs of discovery and fingerprinting. Core does no I/O: trusted code reads the files at the
// immutable commit (GitHub contents API or the source archive) and passes them in. Everything
// here is repository content, i.e. hostile input, so every size is bounded.

export const RECIPE_INPUT_LIMITS = {
  /** Bytes (UTF-16 code units) per file. */
  maxFileLength: 1024 * 1024,
  /** Files per discovery. */
  maxFiles: 500,
  /** Paths in the repository tree listing. */
  maxTreePaths: 50_000,
} as const;

/** One repository file at the commit being discovered. */
export const repoFileSchema = z.strictObject({
  path: repoFilePathSchema,
  content: z.string().max(RECIPE_INPUT_LIMITS.maxFileLength),
});
export type RepoFile = z.infer<typeof repoFileSchema>;

export const repoFilesSchema = z
  .array(repoFileSchema)
  .max(RECIPE_INPUT_LIMITS.maxFiles)
  .refine((files) => new Set(files.map((file) => file.path)).size === files.length, {
    error: "file paths must be unique",
  });

/**
 * The sandbox image's identity and the exact runtime/package-manager releases baked into it
 * (SPEC: "an Ubuntu LTS sandbox image pinned by digest, with supported Node 22/24 runtimes, npm
 * 10/11 and pnpm 9/10 … Resolve an exact compatible runtime/PM version into each recipe"): the
 * digest, the image's runtime catalog, the one `@kovo/core/lockfile` resolves every runtime
 * against (`catalogNodeVersions` and `catalogPmVersions` list what it bakes), and the digest of
 * its runtime toolchain manifest (`runtime-manifest.ts`, D-496).
 *
 * The fingerprint's `sandbox_image` component covers the runtimes and the manifest digest, not
 * `digest` (D-496): an image rebuilt with the same runtime content keeps every fingerprint. The
 * digest stays the image a sandbox runs and the provenance recipes and evidence record.
 *
 * A `SandboxImage` is built from the deployment's configuration and never crosses a DBOS step or
 * workflow boundary, so in-flight workflows never read one without `toolchainManifestDigest`.
 */
export const sandboxImageSchema = z.strictObject({
  digest: imageDigestSchema,
  runtimes: runtimeCatalogSchema,
  /** SHA-256 (64 lower-case hex) of the image's runtime toolchain manifest. */
  toolchainManifestDigest: z.string().regex(/^[0-9a-f]{64}$/, {
    error: "must be 64 lower-case hex digits",
  }),
});
export type SandboxImage = z.infer<typeof sandboxImageSchema>;

/** The lockfile inventory already parsed and accepted (`@kovo/core/lockfile`, `lockfile_snapshots`). */
export const lockfileInfoSchema = z.strictObject({
  path: z.enum(["package-lock.json", "pnpm-lock.yaml", "yarn.lock"]),
  format: lockfileFormatSchema,
});
export type LockfileInfo = z.infer<typeof lockfileInfoSchema>;

/** Looks up a file by exact path. */
export function fileAt(files: readonly RepoFile[], path: string): RepoFile | undefined {
  return files.find((file) => file.path === path);
}
