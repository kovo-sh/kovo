import type { PackageName } from "@kovo/contracts";
import type { DependencyRegistryFacts } from "@kovo/core/dependency-verdicts";
import { packumentFromDocument } from "@kovo/adapters/npm/packument";

/** The npm adapter's typed packument view. */
export type Packument = ReturnType<typeof packumentFromDocument>;

// The public npm registry's facts for `kovo deps check --offline`: one full packument read per
// changed package, from the registry the lockfile resolves against (the public registry, or a
// mirror of it), parsed by the npm adapter's own packument parser. Bounded: a few reads in flight,
// a byte cap per packument and a deadline per read. A packument that cannot be read is
// `unavailable`, which the engine turns into a wait, never a pass. Attestations are not verified
// offline and publisher identities are not compared, so those facts are left unknown.

export const NPM_REGISTRY_URL = "https://registry.npmjs.org/";
/**
 * The CLI's own bound on one packument, no larger than the control plane's `PACKUMENT_MAX_BYTES`
 * (64 MiB, apps/control-plane/src/services/target-resolution/target-resolver.ts).
 */
export const PACKUMENT_MAX_BYTES = 64 * 1024 * 1024;
/** Packument reads in flight at once. */
export const REGISTRY_CONCURRENCY = 8;
const REQUEST_TIMEOUT_MS = 60_000;

export type PackumentRead =
  | { readonly status: "read"; readonly packument: Packument }
  /** The registry does not list the package (404). */
  | { readonly status: "not_found" }
  /** Unreachable, an error status, too large or not a packument. */
  | { readonly status: "unavailable" };

export interface RegistryOptions {
  readonly registryUrl: URL;
  readonly fetch: typeof fetch;
}

/** The packument URL of `name` (`@scope/name` → `@scope%2fname`). */
export function packumentUrl(registryUrl: URL, name: string): URL {
  return new URL(name.replace("/", "%2f"), registryUrl);
}

async function boundedJson(response: Response): Promise<unknown> {
  if (response.body === null) return undefined;
  const chunks: Uint8Array[] = [];
  let size = 0;
  for await (const chunk of response.body) {
    size += chunk.byteLength;
    if (size > PACKUMENT_MAX_BYTES) {
      await response.body.cancel().catch(() => undefined);
      return undefined;
    }
    chunks.push(chunk);
  }
  try {
    return JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(Buffer.concat(chunks)));
  } catch {
    return undefined;
  }
}

async function readPackument(name: PackageName, options: RegistryOptions): Promise<PackumentRead> {
  let response: Response;
  try {
    response = await options.fetch(packumentUrl(options.registryUrl, name), {
      headers: { accept: "application/json" },
      redirect: "error",
      signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
    });
  } catch {
    return { status: "unavailable" };
  }
  if (response.status === 404) {
    await response.body?.cancel().catch(() => undefined);
    return { status: "not_found" };
  }
  if (response.status !== 200) {
    await response.body?.cancel().catch(() => undefined);
    return { status: "unavailable" };
  }
  let document: unknown;
  try {
    document = await boundedJson(response);
  } catch {
    return { status: "unavailable" };
  }
  if (document === undefined) return { status: "unavailable" };
  try {
    return { status: "read", packument: packumentFromDocument(document, "full", name) };
  } catch {
    return { status: "unavailable" };
  }
}

/** One read per name, at most {@link REGISTRY_CONCURRENCY} in flight. */
export async function readPackuments(
  names: readonly PackageName[],
  options: RegistryOptions,
): Promise<ReadonlyMap<string, PackumentRead>> {
  const results = new Map<string, PackumentRead>();
  let next = 0;
  const worker = async () => {
    for (let index = next++; index < names.length; index = next++) {
      const name = names[index]!;
      results.set(name, await readPackument(name, options));
    }
  };
  await Promise.all(
    Array.from({ length: Math.min(REGISTRY_CONCURRENCY, names.length) }, () => worker()),
  );
  return results;
}

/** One version's facts as the engine reads them; null when the packument does not list it. */
export function versionFacts(
  packument: Packument,
  version: string,
): DependencyRegistryFacts | null {
  if (!Object.hasOwn(packument.versions, version)) return null;
  const entry = packument.versions[version]!;
  return {
    integrity: entry.dist.integrity,
    publishedAt: packument.publishedAt?.[version] ?? null,
    hasInstallScripts: entry.hasInstallScript,
    // Not verified offline: no trust-downgrade signal is raised from an unverified fact.
    attested: null,
    publisherHash: null,
  };
}
