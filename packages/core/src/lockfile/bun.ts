import semver from "semver";

import { packageNameSchema, packageVersionSchema, npmTarballUrl } from "@kovo/contracts/npm";

import { isJsonObject, parseBoundedJson, type JsonValue } from "../manifest/bounded-json.js";
import { classifyDependencySpec } from "../manifest/dependency-spec.js";
import { DEPENDENCY_SECTIONS, type DependencySection } from "../manifest/package-json.js";
import type { Instance, InstanceEdge, InstanceSet, RootDependency } from "./instances.js";
import { RejectionCollector } from "./reasons.js";
import { checkIntegrity } from "./registry-source.js";
import { GRAPH_LIMITS, SECTION_KIND, type LockfileLimits } from "./types.js";

// Bun's text lockfile `bun.lock`: JSON with trailing commas, read by the strict bounded
// JSON parser after a string-aware pass drops only the commas before a closing `}` or `]`. Kovo
// fixes a Bun repository with its own pinned Bun (`FIX_ONLY_TOOLS.bun`) and never runs it in
// Sandbox B. Versions 1 and 2 are read; the pinned Bun 1.4.4 keeps a version 1 file at version 1
// (adding one `configVersion` line) and writes version 2 for a new file (verified in a worker,
// 2026-11-08). The binary `bun.lockb` is never parsed: trusted code cannot read or check it, so it
// refuses before any sandbox (`detect.ts`).
//
// `packages` maps an install path (`chalk`, `mkdirp/minimist`, `@scope/a/@scope/b`) to
// `[ident, registry, meta, integrity]`. A public registry package has the empty registry ("the
// default"); anything else (a private registry, a tarball URL, git, a workspace or a file) refuses
// with the existing source reasons. A dependency resolves as Node does: the dependent's own nested
// path first, then each ancestor's, then the hoisted top level.

export const BUN_LOCKFILE_LIMITS = {
  maxLength: 16 * 1024 * 1024,
  maxDepth: 16,
  maxNodes: 2_000_000,
  maxStringLength: 64 * 1024,
} as const;

/** The `lockfileVersion` values read, with their formats. */
const BUN_FORMATS = { 1: "bun-v1", 2: "bun-v2" } as const;

/** Drops every comma that only precedes a closing bracket, outside strings; null when unbalanced. */
export function withoutTrailingCommas(text: string): string | null {
  let out = "";
  let inString = false;
  let escaped = false;
  let pendingComma = -1;
  for (let index = 0; index < text.length; index += 1) {
    const char = text[index]!;
    if (inString) {
      out += char;
      if (escaped) escaped = false;
      else if (char === "\\") escaped = true;
      else if (char === '"') inString = false;
      continue;
    }
    if (char === '"') {
      pendingComma = -1;
      inString = true;
      out += char;
    } else if (char === ",") {
      pendingComma = out.length;
      out += char;
    } else if (char === "}" || char === "]") {
      if (pendingComma >= 0) out = out.slice(0, pendingComma) + out.slice(pendingComma + 1);
      pendingComma = -1;
      out += char;
    } else {
      if (!/[ \t\r\n]/u.test(char)) pendingComma = -1;
      out += char;
    }
  }
  return inString ? null : out;
}

/** `name@version` (scoped names keep their first `@`). */
function splitIdent(ident: string): { name: string; reference: string } | null {
  const at = ident.indexOf("@", ident.startsWith("@") ? 1 : 0);
  return at < 1 ? null : { name: ident.slice(0, at), reference: ident.slice(at + 1) };
}

/** The path segments of an install path, a scope and its name kept together. */
function segments(path: string): string[] | null {
  const parts = path.split("/");
  const out: string[] = [];
  for (let index = 0; index < parts.length; index += 1) {
    const part = parts[index]!;
    if (part === "") return null;
    if (part.startsWith("@")) {
      const next = parts[index + 1];
      if (next === undefined || next === "") return null;
      out.push(`${part}/${next}`);
      index += 1;
    } else out.push(part);
  }
  return out;
}

export type BunParseResult =
  | { readonly ok: true; readonly instances: InstanceSet }
  | { readonly ok: false; readonly rejections: RejectionCollector };

/** Parses a `bun.lock` of a single-package root (a second workspace refuses as workspaces). */
export function parseBunLockfile(
  text: string,
  limits: LockfileLimits = GRAPH_LIMITS,
): BunParseResult {
  const rejections = new RejectionCollector();
  const fail = (): BunParseResult => ({ ok: false, rejections });
  if (text.length > BUN_LOCKFILE_LIMITS.maxLength) {
    rejections.add("lockfile_too_large");
    return fail();
  }
  const stripped = withoutTrailingCommas(text);
  const parsed = stripped === null ? null : parseBoundedJson(stripped, BUN_LOCKFILE_LIMITS);
  if (parsed === null || !parsed.ok) {
    rejections.add(
      parsed !== null && !parsed.ok && parsed.error === "duplicate_key"
        ? "lockfile_duplicate_key"
        : parsed !== null && !parsed.ok && parsed.error !== "syntax"
          ? "lockfile_too_large"
          : "lockfile_syntax",
    );
    return fail();
  }
  const document = parsed.value;
  if (!isJsonObject(document)) {
    rejections.add("lockfile_invalid");
    return fail();
  }
  const version = document["lockfileVersion"];
  const format = version === 1 || version === 2 ? BUN_FORMATS[version] : null;
  if (format === null) {
    rejections.add("pm_version_unsupported");
    return fail();
  }
  const workspaces = document["workspaces"];
  const packages = document["packages"];
  if (!isJsonObject(workspaces) || !isJsonObject(packages)) {
    rejections.add("lockfile_invalid");
    return fail();
  }
  const keys = Object.keys(workspaces);
  if (keys.length !== 1 || keys[0] !== "") {
    rejections.add(keys.includes("") ? "workspace_packages" : "missing_root");
    return fail();
  }
  const rootWorkspace = workspaces[""];
  if (!isJsonObject(rootWorkspace)) {
    rejections.add("missing_root");
    return fail();
  }
  const patched = new Set(
    isJsonObject(document["patchedDependencies"])
      ? Object.keys(document["patchedDependencies"])
      : [],
  );
  if (Object.keys(packages).length > limits.maxPackages) {
    rejections.add("too_many_packages");
    return fail();
  }

  const instances = new Map<string, Instance>();
  const declared = new Map<
    string,
    readonly (readonly [string, string, InstanceEdge["kind"], boolean])[]
  >();
  let edgeCount = 0;
  for (const [path, value] of Object.entries(packages)) {
    const pathSegments = segments(path);
    if (pathSegments === null || !Array.isArray(value)) {
      rejections.add("lockfile_invalid");
      continue;
    }
    const [ident, registry, meta, integrityText] = value as readonly (JsonValue | undefined)[];
    const split = typeof ident === "string" ? splitIdent(ident) : null;
    const name = packageNameSchema.safeParse(split?.name);
    if (split === null || !name.success) {
      rejections.add("invalid_package_name");
      continue;
    }
    const versionResult = packageVersionSchema.safeParse(split.reference);
    if (!versionResult.success) {
      // A workspace, git, file or URL reference rather than a registry version.
      const classified = classifyDependencySpec(split.reference);
      rejections.add(
        classified.kind === "rejected" ? classified.reason : "unsupported_protocol",
        name.data,
      );
      continue;
    }
    if (
      value.length !== 4 ||
      typeof registry !== "string" ||
      meta === undefined ||
      !isJsonObject(meta)
    ) {
      rejections.add("lockfile_invalid", name.data);
      continue;
    }
    if (registry !== "") {
      rejections.add(
        /^https?:\/\//iu.test(registry) ? "private_registry_dependency" : "unsupported_protocol",
        name.data,
      );
      continue;
    }
    const integrity = checkIntegrity(typeof integrityText === "string" ? integrityText : undefined);
    if (!integrity.ok) {
      rejections.add(integrity.reason, name.data);
      continue;
    }
    const metadata = meta;
    const optionalPeers = new Set(
      Array.isArray(metadata["optionalPeers"])
        ? metadata["optionalPeers"].filter((item): item is string => typeof item === "string")
        : [],
    );
    const edges: (readonly [string, string, InstanceEdge["kind"], boolean])[] = [];
    for (const [field, kind] of [
      ["dependencies", "prod"],
      ["optionalDependencies", "optional"],
      ["peerDependencies", "peer"],
    ] as const) {
      const map = metadata[field];
      if (map === undefined) continue;
      if (!isJsonObject(map)) {
        rejections.add("lockfile_invalid", name.data);
        break;
      }
      for (const [alias, range] of Object.entries(map)) {
        if (typeof range !== "string") {
          rejections.add("lockfile_invalid", name.data);
          continue;
        }
        if (++edgeCount > limits.maxDependencyEdges) {
          rejections.add("too_many_dependencies");
          return fail();
        }
        edges.push([alias, range, kind, kind === "optional" || optionalPeers.has(alias)]);
      }
    }
    declared.set(path, edges);
    instances.set(path, {
      id: path,
      name: name.data,
      version: versionResult.data,
      integrity: integrity.integrity,
      integrityAlgorithm: integrity.algorithm,
      ...(integrity.algorithm === "sha1" ? { legacySha1: integrity.sha1 } : {}),
      resolved: npmTarballUrl(name.data, versionResult.data),
      bundled: false,
      bundles: [],
      hasInstallScript: null,
      patched: patched.has(`${name.data}@${versionResult.data}`),
      edges: [],
    });
  }
  if (!rejections.empty) return fail();

  /** The installed path a dependency of `from` (an install path, or the root) resolves to. */
  const resolve = (from: string | null, alias: string): string | null => {
    const base = from === null ? [] : (segments(from) ?? []);
    for (let depth = base.length; depth >= 0; depth -= 1) {
      const candidate = [...base.slice(0, depth), alias].join("/");
      if (instances.has(candidate)) return candidate;
    }
    return null;
  };
  const edge = (
    from: string | null,
    alias: string,
    range: string,
    kind: InstanceEdge["kind"],
    optional: boolean,
  ): InstanceEdge | null => {
    const parsedAlias = packageNameSchema.safeParse(alias);
    if (!parsedAlias.success) {
      rejections.add("invalid_package_name");
      return null;
    }
    const classified = classifyDependencySpec(range);
    if (classified.kind === "rejected") {
      rejections.add(classified.reason, parsedAlias.data);
      return null;
    }
    if (classified.kind === "invalid") {
      rejections.add("lockfile_invalid", parsedAlias.data);
      return null;
    }
    const target = resolve(from, alias);
    if (target === null && !optional && kind !== "peer") {
      rejections.add("dangling_reference", parsedAlias.data);
      return null;
    }
    const spec = classified.kind === "alias" ? classified.target : classified;
    const resolved = target === null ? undefined : instances.get(target);
    if (
      resolved !== undefined &&
      spec.kind === "range" &&
      !semver.satisfies(resolved.version, spec.range)
    ) {
      // A peer the package manager left at another version is reported, not trusted.
      if (kind !== "peer") {
        rejections.add("lockfile_invalid", resolved.name);
        return null;
      }
    }
    return { alias: parsedAlias.data, range, kind, optional, target };
  };
  for (const [path, edges] of declared) {
    const instance = instances.get(path)!;
    const made: InstanceEdge[] = [];
    for (const [alias, range, kind, optional] of edges) {
      const resolvedEdge = edge(path, alias, range, kind, optional);
      if (resolvedEdge !== null) made.push(resolvedEdge);
    }
    instances.set(path, { ...instance, edges: made });
  }
  const root: RootDependency[] = [];
  for (const section of DEPENDENCY_SECTIONS) {
    const map = rootWorkspace[section];
    if (map === undefined) continue;
    if (!isJsonObject(map)) {
      rejections.add("lockfile_invalid");
      return fail();
    }
    for (const [alias, spec] of Object.entries(map)) {
      if (typeof spec !== "string") {
        rejections.add("lockfile_invalid");
        return fail();
      }
      if (++edgeCount > limits.maxDependencyEdges) {
        rejections.add("too_many_dependencies");
        return fail();
      }
      const typedSection: DependencySection = section;
      if (typedSection === "peerDependencies") continue;
      const made = edge(
        null,
        alias,
        spec,
        SECTION_KIND[typedSection],
        typedSection === "optionalDependencies",
      );
      if (made !== null) root.push({ alias: made.alias, section: typedSection, spec, edge: made });
    }
  }
  if (!rejections.empty) return fail();
  return {
    ok: true,
    instances: { packageManager: "bun", format, root, instances, lockfileOverrides: [] },
  };
}
