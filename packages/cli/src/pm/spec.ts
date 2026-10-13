import {
  dependencyVerdictChangeSchema,
  exactVersionSchema,
  packageNameSchema,
  type DependencyVerdictChangeWire,
  type PackageName,
} from "@kovo/contracts";

import { unavailableError, usageError } from "../errors.js";
import { readPackuments, versionFacts } from "../deps/offline/registry.js";

// The one registry package `dlx`, `exec` and `create` fetch: its spec, parsed without a range
// engine (an exact version or a dist-tag only), resolved to one version from the registry's
// metadata without installing anything, and pinned so the package manager runs exactly the version
// that was checked. Its own dependencies are resolved by the package manager into a temporary
// directory, never into a lockfile, so they are not checked.

/** What a spec asks for: an exact version, or the version a dist-tag points at. */
export type Selector =
  | { readonly kind: "version"; readonly version: string }
  | { readonly kind: "tag"; readonly tag: string };

export interface RegistrySpec {
  readonly name: PackageName;
  readonly selector: Selector;
}

/** A dist-tag as npm accepts one: not a version or a range (those start with a digit or operator). */
const DIST_TAG = /^[A-Za-z][A-Za-z0-9._-]{0,127}$/u;
/** Tags node-semver reads as "any version", which npm treats as a range, not a tag. */
const RANGE_WORDS = new Set(["x", "X"]);

/** Splits `name@selector` (the name may be scoped: `@scope/name@selector`). */
function splitSpec(spec: string): { readonly name: string; readonly selector: string | null } {
  const at = spec.indexOf("@", spec.startsWith("@") ? 1 : 0);
  return at === -1
    ? { name: spec, selector: null }
    : { name: spec.slice(0, at), selector: spec.slice(at + 1) };
}

function selectorOf(raw: string | null, spec: string): Selector {
  if (raw === null) return { kind: "tag", tag: "latest" };
  if (exactVersionSchema.safeParse(raw).success) return { kind: "version", version: raw };
  if (DIST_TAG.test(raw) && !RANGE_WORDS.has(raw)) return { kind: "tag", tag: raw };
  throw usageError(
    "unsupported_spec",
    `${spec} is not a registry package with an exact version or a dist-tag: kovo checks one exact version, so give one (for example name@1.2.3 or name@latest).`,
  );
}

/** A registry spec: `name`, `name@1.2.3` or `name@tag`. Error (exit 2): anything else. */
export function parseRegistrySpec(spec: string): RegistrySpec {
  const { name, selector } = splitSpec(spec);
  const parsed = packageNameSchema.safeParse(name);
  if (!parsed.success)
    throw usageError(
      "unsupported_spec",
      "The package to fetch is not a registry package name: kovo checks registry packages only.",
    );
  return { name: parsed.data, selector: selectorOf(selector, name) };
}

const CREATE_PREFIX = "create-";

/**
 * The package `create <initializer>` runs. Both map `foo` → `create-foo`, `@usr/foo` →
 * `@usr/create-foo` and `@usr` → `@usr/create`, keeping any `@version`. They differ on a starter
 * already named `create-…`:
 * - npm 10 always adds the prefix (`lib/commands/init.js` `execCreate`:
 *   `req.name.replace(/^(@[^/]+\/)?/, '$1create-')`), so `npm init create-vite` runs
 *   `create-create-vite`;
 * - pnpm 11 keeps it (`exec/commands/src/create.ts` `ensureCreatePrefixed`).
 * Returns the initializer without its selector, to pin as `<initializer>@<v>`.
 */
export function parseCreateSpec(
  pm: "pnpm" | "npm",
  initializer: string,
): {
  readonly spec: RegistrySpec;
  readonly initializer: string;
} {
  const { name: base, selector } = splitSpec(initializer);
  const prefixed = (name: string): string =>
    pm === "pnpm" && name.startsWith(CREATE_PREFIX) ? name : `${CREATE_PREFIX}${name}`;
  let name: string;
  if (base.startsWith("@")) {
    const [scope = "", rest = ""] = base.split("/", 2);
    name = rest === "" ? `${scope}/create` : `${scope}/${prefixed(rest)}`;
  } else name = prefixed(base);
  const parsed = packageNameSchema.safeParse(name);
  if (!parsed.success || base === "" || base.includes(":"))
    throw usageError(
      "unsupported_spec",
      "The starter to create from is not a registry package name: kovo checks registry packages only.",
    );
  return { spec: { name: parsed.data, selector: selectorOf(selector, base) }, initializer: base };
}

/** A spec's registry version and its integrity, read from the packument; nothing is installed. */
export interface ResolvedSpec {
  readonly name: PackageName;
  readonly version: string;
  readonly integrity: string | null;
}

/**
 * Resolves `spec` from `registryUrl`'s packument. Errors: exit 2 when the registry does not list the
 * package, the version or the tag; exit 3 when the registry cannot be read.
 */
export async function resolveSpec(
  spec: RegistrySpec,
  options: { readonly registryUrl: URL; readonly fetch: typeof fetch },
): Promise<ResolvedSpec> {
  const read = (await readPackuments([spec.name], options)).get(spec.name);
  if (read === undefined || read.status === "unavailable")
    throw unavailableError(
      "registry_unreachable",
      `The registry's metadata for ${spec.name} could not be read.`,
    );
  if (read.status === "not_found")
    throw usageError("unknown_package", `The registry does not list ${spec.name}.`);
  let version: string;
  if (spec.selector.kind === "version") version = spec.selector.version;
  else {
    const tagged = read.packument.distTags[spec.selector.tag];
    if (tagged === undefined)
      throw usageError(
        "unknown_version",
        `The registry has no dist-tag ${spec.selector.tag} for ${spec.name}.`,
      );
    version = tagged;
  }
  const facts = versionFacts(read.packument, version);
  if (facts === null)
    throw usageError("unknown_version", `The registry does not list ${spec.name}@${version}.`);
  return { name: spec.name, version, integrity: facts.integrity };
}

/** The fetched package as the check judges it: a new, direct registry dependency. */
export function fetchedChange(resolved: ResolvedSpec): DependencyVerdictChangeWire {
  return dependencyVerdictChangeSchema.parse({
    ecosystem: "npm",
    name: resolved.name,
    version: resolved.version,
    integrity: resolved.integrity,
    kind: "new",
    direct: true,
    previous_version: null,
    source: "registry",
  });
}
