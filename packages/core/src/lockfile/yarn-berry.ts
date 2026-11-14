import semver from "semver";

import { hasControlCharacter } from "@kovo/contracts/primitives";
import { npmTarballUrl, packageNameSchema, packageVersionSchema } from "@kovo/contracts/npm";

import { classifyDependencySpec } from "../manifest/dependency-spec.js";
import type { PackageManifest } from "../manifest/package-json.js";
import type { Instance, InstanceEdge, InstanceSet, RootDependency } from "./instances.js";
import { RejectionCollector } from "./reasons.js";
import { GRAPH_LIMITS, SECTION_KIND, type LockfileLimits } from "./types.js";

// Yarn 4's `yarn.lock` (#8256 R2): a YAML document Yarn writes in one fixed layout, read here by a
// bounded line scanner, never by a YAML engine (no anchors, aliases, tags, flow collections or
// multi-line scalars are accepted). Kovo fixes a Yarn 4 repository with its own pinned Yarn
// (`FIX_ONLY_TOOLS["yarn-berry"]`) and never runs it in Sandbox B, so the graph serves inventory,
// planning and the candidate's diff only.
//
// Only lockfile version 10 is read: the version the pinned Yarn writes. Yarn 4 releases that wrote
// version 8, and Yarn 2 and 3 (versions 4 and 6), would have the whole file rewritten by a
// lockfile-only update (every checksum gains a cache-key prefix), so they refuse as
// `pm_version_unsupported` (verified on Yarn 4.0.2, 3.6.4 and 4.18.1 in a worker, 2026-11-08).
//
// The model: every entry resolves `<name>@npm:<version>` from the public registry, or is the root
// workspace `<name>@workspace:.`, or is one of Yarn's own built-in compatibility patches of an npm
// entry (`patch:typescript@npm%3A…#optional!builtin<compat/typescript>`), recorded as a patched
// instance of that version. Any other protocol (git, file, link, portal, exec, URL, a repository
// patch file) and a second workspace refuse with the existing source reasons. Yarn's `checksum` is
// the hash of its own cache archive, not the npm tarball's integrity, so instances carry none.

/** Bounds of the line scanner (the parser's other bounds are `GRAPH_LIMITS`). */
export const YARN_BERRY_LOCKFILE_LIMITS = {
  // `yarn.lock` is fetched with one byte bound for both Yarn lines (`LOCKFILE_MAX_BYTES`).
  maxLength: 8 * 1024 * 1024,
  maxLineLength: 64 * 1024,
} as const;

/** The only `__metadata.version` read: the one the pinned Yarn 4 writes. */
export const YARN_BERRY_LOCKFILE_VERSION = "10";

/** Whether a `yarn.lock` is a Yarn 2+ (Berry) lockfile: it has a `__metadata` entry. */
export function isYarnBerryLockfile(text: string): boolean {
  return /^"?__metadata"?\s*:/mu.test(text);
}

interface Entry {
  readonly descriptors: readonly string[];
  readonly fields: Map<string, string>;
  readonly maps: Map<string, Map<string, string>>;
}

/** A field of an entry that holds a map of scalars (`dependencies:`) or of maps (`…Meta:`). */
const MAP_FIELDS = new Set(["dependencies", "peerDependencies", "bin"]);
const NESTED_MAP_FIELDS = new Set(["dependenciesMeta", "peerDependenciesMeta"]);
const SCALAR_FIELDS = new Set([
  "version",
  "resolution",
  "checksum",
  "languageName",
  "linkType",
  "conditions",
]);

/** One key or value token: a JSON double-quoted string or a plain run without YAML syntax. */
function scalar(text: string): string | null {
  if (text.startsWith('"')) {
    try {
      const value: unknown = JSON.parse(text);
      return typeof value === "string" && !hasControlCharacter(value) ? value : null;
    } catch {
      return null;
    }
  }
  if (text === "" || /^[&*!|>'{[%@`-]/u.test(text) || /\s#|: |^\s|\s$/u.test(text)) return null;
  return hasControlCharacter(text) ? null : text;
}

/** `key: value` or `key:` at one level; the key may be quoted. Null for anything else. */
function pair(body: string): { key: string; value: string | null } | null {
  let keyEnd: number;
  if (body.startsWith('"')) {
    let index = 1;
    let escaped = false;
    for (; index < body.length; index += 1) {
      const char = body[index];
      if (!escaped && char === '"') break;
      escaped = !escaped && char === "\\";
    }
    if (index >= body.length) return null;
    keyEnd = index + 1;
    if (body[keyEnd] !== ":") return null;
  } else {
    keyEnd = body.indexOf(":");
    if (keyEnd < 1) return null;
  }
  const key = scalar(body.slice(0, keyEnd));
  if (key === null) return null;
  const rest = body.slice(keyEnd + 1);
  if (rest === "") return { key, value: null };
  if (!rest.startsWith(" ")) return null;
  const value = scalar(rest.slice(1));
  return value === null ? null : { key, value };
}

/** `<name>@<range>` after an optional `npm:` and alias: what a dependency value names. */
function npmTarget(value: string): { name: string; range: string } | null {
  if (!value.startsWith("npm:")) return null;
  const rest = value.slice("npm:".length);
  const at = rest.indexOf("@", rest.startsWith("@") ? 1 : 0);
  if (at > 0 && packageNameSchema.safeParse(rest.slice(0, at)).success)
    return { name: rest.slice(0, at), range: rest.slice(at + 1) };
  return { name: "", range: rest };
}

/** Yarn's built-in compatibility patch of an npm descriptor or resolution, else null. */
function builtinPatch(value: string): string | null {
  const match = /^patch:(.+?)#(?:optional!)?builtin<compat\/[a-z0-9-]+>(?:::.*)?$/u.exec(value);
  if (match === null) return null;
  const inner = decodeURIComponent(match[1] ?? "");
  const at = inner.indexOf("@", inner.startsWith("@") ? 1 : 0);
  return at > 0 && inner.slice(at + 1).startsWith("npm:") ? inner : null;
}

/** Splits `name@protocol:…` at the name's `@`. */
function splitDescriptor(descriptor: string): { name: string; reference: string } | null {
  const at = descriptor.indexOf("@", descriptor.startsWith("@") ? 1 : 0);
  if (at < 1) return null;
  return { name: descriptor.slice(0, at), reference: descriptor.slice(at + 1) };
}

/** The source reason for a reference Kovo does not model (git, file, URL, other protocols). */
function rejectedSource(reference: string) {
  const classified = classifyDependencySpec(reference);
  return classified.kind === "rejected" ? classified.reason : "unsupported_protocol";
}

export type YarnBerryParseResult =
  | { readonly ok: true; readonly instances: InstanceSet }
  | {
      readonly ok: false;
      readonly rejections: RejectionCollector;
      /** True when the lockfile is a Berry lockfile of a version Kovo's Yarn would rewrite. */
      readonly versionUnsupported?: true;
    };

/**
 * Parses a Yarn 4 (lockfile version 10) `yarn.lock` with its root manifest, which decides each
 * direct dependency's section (the root workspace entry merges them).
 */
export function parseYarnBerryLockfile(
  text: string,
  manifest: PackageManifest,
  limits: LockfileLimits = GRAPH_LIMITS,
): YarnBerryParseResult {
  const rejections = new RejectionCollector();
  const fail = (): YarnBerryParseResult => ({ ok: false, rejections });
  if (text.length > YARN_BERRY_LOCKFILE_LIMITS.maxLength) {
    rejections.add("lockfile_too_large");
    return fail();
  }
  const entries: Entry[] = [];
  let metadata: Map<string, string> | null = null;
  let current: Entry | undefined;
  let open: Map<string, string> | undefined;
  let nested: Map<string, string> | undefined;
  let openField: string | undefined;
  let edgeCount = 0;
  for (const raw of text.split("\n")) {
    const line = raw.endsWith("\r") ? raw.slice(0, -1) : raw;
    if (line.length > YARN_BERRY_LOCKFILE_LIMITS.maxLineLength) {
      rejections.add("lockfile_too_large");
      return fail();
    }
    if (line === "" || line.startsWith("#")) continue;
    if (line.includes("\t")) {
      rejections.add("lockfile_syntax");
      return fail();
    }
    const indent = line.length - line.trimStart().length;
    const parsed = pair(line.slice(indent));
    if (parsed === null) {
      rejections.add("lockfile_syntax");
      return fail();
    }
    if (indent === 0) {
      if (parsed.value !== null) {
        rejections.add("lockfile_syntax");
        return fail();
      }
      open = undefined;
      nested = undefined;
      openField = undefined;
      if (parsed.key === "__metadata") {
        if (metadata !== null) {
          rejections.add("lockfile_duplicate_key");
          return fail();
        }
        metadata = new Map();
        current = undefined;
        continue;
      }
      if (entries.length >= limits.maxPackages) {
        rejections.add("too_many_packages");
        return fail();
      }
      const descriptors = parsed.key.split(", ");
      if (descriptors.some((descriptor) => descriptor === "")) {
        rejections.add("lockfile_syntax");
        return fail();
      }
      current = { descriptors, fields: new Map(), maps: new Map() };
      entries.push(current);
    } else if (indent === 2) {
      nested = undefined;
      if (current === undefined) {
        if (metadata === null || parsed.value === null || metadata.has(parsed.key)) {
          rejections.add("lockfile_invalid");
          return fail();
        }
        metadata.set(parsed.key, parsed.value);
        continue;
      }
      if (current.fields.has(parsed.key) || current.maps.has(parsed.key)) {
        rejections.add("lockfile_duplicate_key");
        return fail();
      }
      if (parsed.value === null) {
        if (!MAP_FIELDS.has(parsed.key) && !NESTED_MAP_FIELDS.has(parsed.key)) {
          rejections.add("lockfile_invalid");
          return fail();
        }
        open = new Map();
        openField = parsed.key;
        current.maps.set(parsed.key, open);
      } else {
        if (!SCALAR_FIELDS.has(parsed.key)) {
          rejections.add("lockfile_invalid");
          return fail();
        }
        open = undefined;
        openField = undefined;
        current.fields.set(parsed.key, parsed.value);
      }
    } else if (indent === 4 && open !== undefined && openField !== undefined) {
      if (open.has(parsed.key)) {
        rejections.add("lockfile_duplicate_key");
        return fail();
      }
      if (NESTED_MAP_FIELDS.has(openField)) {
        // Meta maps (`optional: true`, `built: false`) are read for shape only.
        if (parsed.value !== null) {
          rejections.add("lockfile_invalid");
          return fail();
        }
        open.set(parsed.key, "");
        nested = new Map();
        continue;
      }
      if (parsed.value === null) {
        rejections.add("lockfile_invalid");
        return fail();
      }
      if (++edgeCount > limits.maxDependencyEdges) {
        rejections.add("too_many_dependencies");
        return fail();
      }
      open.set(parsed.key, parsed.value);
    } else if (indent === 6 && nested !== undefined) {
      if (parsed.value === null || nested.has(parsed.key)) {
        rejections.add("lockfile_invalid");
        return fail();
      }
      nested.set(parsed.key, parsed.value);
    } else {
      rejections.add("lockfile_syntax");
      return fail();
    }
  }
  if (metadata === null) {
    rejections.add("unsupported_lockfile_version");
    return fail();
  }
  if (metadata.get("version") !== YARN_BERRY_LOCKFILE_VERSION) {
    rejections.add("pm_version_unsupported");
    return { ok: false, rejections, versionUnsupported: true };
  }

  const instances = new Map<string, Instance>();
  /** Lockfile descriptor (`color-convert@npm:^1.9.0`) → instance ID. */
  const byDescriptor = new Map<string, string>();
  let rootEntry: Entry | undefined;
  for (const entry of entries) {
    const resolution = entry.fields.get("resolution");
    const split = resolution === undefined ? null : splitDescriptor(resolution);
    if (resolution === undefined || split === null) {
      rejections.add("lockfile_invalid");
      continue;
    }
    if (split.reference.startsWith("workspace:")) {
      if (split.reference !== "workspace:." || rootEntry !== undefined) {
        rejections.add("workspace_packages");
        continue;
      }
      rootEntry = entry;
      continue;
    }
    const patched = builtinPatch(split.reference);
    const npm = splitDescriptor(patched ?? resolution);
    const reference = npm?.reference ?? "";
    if (npm === null || !reference.startsWith("npm:")) {
      const source = rejectedSource(split.reference);
      const name = packageNameSchema.safeParse(split.name);
      rejections.add(source, name.success ? name.data : null);
      continue;
    }
    const name = packageNameSchema.safeParse(npm.name);
    if (!name.success) {
      rejections.add("invalid_package_name");
      continue;
    }
    const version = packageVersionSchema.safeParse(reference.slice("npm:".length));
    if (!version.success || entry.fields.get("version") !== version.data) {
      rejections.add("invalid_package_version", name.data);
      continue;
    }
    if (entry.fields.get("linkType") !== "hard") {
      rejections.add("lockfile_invalid", name.data);
      continue;
    }
    const id = `yarn-berry:${resolution}`;
    if (instances.has(id)) {
      rejections.add("lockfile_duplicate_key", name.data);
      continue;
    }
    instances.set(id, {
      id,
      name: name.data,
      version: version.data,
      integrity: null,
      integrityAlgorithm: null,
      resolved: npmTarballUrl(name.data, version.data),
      bundled: false,
      bundles: [],
      hasInstallScript: null,
      patched: patched !== null,
      edges: [],
    });
    for (const descriptor of entry.descriptors) {
      if (byDescriptor.has(descriptor)) rejections.add("lockfile_duplicate_key", name.data);
      byDescriptor.set(descriptor, id);
    }
  }
  if (rootEntry === undefined) rejections.add("missing_root");
  if (!rejections.empty || rootEntry === undefined) return fail();

  /** One edge from a dependencies map entry (`alias: "npm:^1.0.0"`). */
  const edge = (
    alias: string,
    value: string,
    kind: InstanceEdge["kind"],
    optional: boolean,
  ): InstanceEdge | null => {
    const parsedAlias = packageNameSchema.safeParse(alias);
    if (!parsedAlias.success) {
      rejections.add("invalid_package_name");
      return null;
    }
    const target = byDescriptor.get(`${alias}@${value}`) ?? null;
    const patchedInner = builtinPatch(value);
    const npm = npmTarget(
      patchedInner === null ? value : (splitDescriptor(patchedInner)?.reference ?? ""),
    );
    if (npm === null) {
      if (kind === "peer") return { alias: parsedAlias.data, range: value, kind, optional, target };
      rejections.add(rejectedSource(value), parsedAlias.data);
      return null;
    }
    const range = classifyDependencySpec(npm.range);
    if (range.kind === "rejected") {
      rejections.add(range.reason, parsedAlias.data);
      return null;
    }
    if (range.kind === "invalid") {
      rejections.add("lockfile_invalid", parsedAlias.data);
      return null;
    }
    if (target === null && !optional && kind !== "peer") {
      rejections.add("dangling_reference", parsedAlias.data);
      return null;
    }
    if (target !== null && range.kind === "range") {
      const resolved = instances.get(target);
      if (resolved !== undefined && !semver.satisfies(resolved.version, range.range)) {
        rejections.add("lockfile_invalid", resolved.name);
        return null;
      }
    }
    return { alias: parsedAlias.data, range: npm.range, kind, optional, target };
  };
  for (const entry of entries) {
    if (entry === rootEntry) continue;
    const resolution = entry.fields.get("resolution") ?? "";
    const id = `yarn-berry:${resolution}`;
    const instance = instances.get(id);
    if (instance === undefined) continue;
    const optional = new Set(entry.maps.get("dependenciesMeta")?.keys() ?? []);
    const edges: InstanceEdge[] = [];
    for (const [alias, value] of entry.maps.get("dependencies") ?? []) {
      const made = edge(
        alias,
        value,
        optional.has(alias) ? "optional" : "prod",
        optional.has(alias),
      );
      if (made !== null) edges.push(made);
    }
    instances.set(id, { ...instance, edges });
  }

  // The root workspace entry merges every section; the manifest names each dependency's section.
  const declared = rootEntry.maps.get("dependencies") ?? new Map<string, string>();
  const root: RootDependency[] = [];
  for (const dep of manifest.dependencies) {
    if (dep.section === "peerDependencies") continue;
    if (++edgeCount > limits.maxDependencyEdges) {
      rejections.add("too_many_dependencies");
      return fail();
    }
    const value = declared.get(dep.alias);
    if (value === undefined) {
      if (dep.section !== "optionalDependencies") rejections.add("dangling_reference");
      continue;
    }
    const made = edge(
      dep.alias,
      value,
      SECTION_KIND[dep.section],
      dep.section === "optionalDependencies",
    );
    if (made !== null)
      root.push({ alias: dep.alias, section: dep.section, spec: dep.spec, edge: made });
  }
  // A root dependency the manifest does not declare: a stale or foreign lockfile.
  const known = new Set<string>(manifest.dependencies.map((dep) => dep.alias));
  if ([...declared.keys()].some((alias) => !known.has(alias))) rejections.add("lockfile_invalid");
  if (!rejections.empty) return fail();
  return {
    ok: true,
    instances: {
      packageManager: "yarn-berry",
      format: "yarn-berry-v10",
      root,
      instances,
      lockfileOverrides: [],
    },
  };
}
