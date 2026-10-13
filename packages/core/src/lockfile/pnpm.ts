import {
  SUPPORTED_PM_MAJORS,
  packageNameSchema,
  packageVersionSchema,
  type PackageName,
} from "@kovo/contracts";
import { parseDocument } from "yaml";
import { z } from "zod";
import semver from "semver";

import { classifyDependencySpec } from "../manifest/dependency-spec.js";
import { catalogEntry } from "../manifest/pnpm-catalogs.js";
import type { DependencySection } from "../manifest/package-json.js";
import { parsePnpmSelector } from "../manifest/selectors.js";
import {
  findMappingKeyProblem,
  scanYamlShape,
  type YamlShapeError,
  type YamlShapeLimits,
} from "../yaml/bounded-yaml.js";
import type { Instance, InstanceEdge, InstanceSet, RootDependency } from "./instances.js";
import { RejectionCollector, type LockfileRejectionReason } from "./reasons.js";
import { checkIntegrity, checkTarballSource } from "./registry-source.js";
import { GRAPH_LIMITS, SECTION_KIND, type LockfileLimits } from "./types.js";
import { required } from "./util.js";
import { resolveMemberLink } from "./workspace/discover.js";
import {
  localInstance,
  memberDeclarationsMatch,
  type WorkspaceParserContext,
} from "./workspace/parser-context.js";

// pnpm lockfile v9 (`pnpm-lock.yaml`, lockfileVersion '9.0', written by pnpm 9, 10, 11 and 12) → instances.
// `packages` holds one entry per package/version (resolution, peers, engines); `snapshots` holds one
// entry per package/version *and peer context* (`debug@4.3.4(supports-color@7.2.0)`) with its
// resolved dependencies; `importers["."]` is the project. Peers appear in a snapshot's dependencies
// once resolved; pnpm v9 records no ranges for ordinary dependencies.
//
// The YAML is parsed with the failsafe schema (every scalar a string, so `1.10` never becomes
// `1.1`), unique keys (checked in one linear walk), no aliases, at most the verified toolchain/project pair, and bounded size,
// node count and nesting checked before the parser runs (docs/decisions/lockfile.md "Hostile files
// are parsed with bounded, strict parsers": the yaml library holds up to about 1 KiB per node while
// parsing, so the structural-character bound is what keeps a parse within a worker's memory).

export const PNPM_LOCKFILE_LIMITS = {
  /** 8 MiB: a real lockfile needs about 350 bytes per package (over 20 000 packages). */
  maxLength: 8 * 1024 * 1024,
  /**
   * Structural characters (`scanYamlShape`): a real lockfile has about 23–29 per package, so this
   * admits more than 10 000 packages, and a hostile document at the bound parses within about
   * 400 MB of heap and 2.5 s (measured, `pnpm.perf.test.ts` › hostile shapes).
   */
  maxStructure: 300_000,
  /** Flow-collection nesting (`{…[…]…}`); pnpm writes at most 2. */
  maxFlowDepth: 32,
  /** Leading spaces on a line; pnpm indents at most 8. */
  maxIndent: 256,
  /** Each individual document is marker-free; the verified stream wrapper is handled separately. */
  allowDocumentMarkers: false,
} as const satisfies YamlShapeLimits;

export const SUPPORTED_PNPM_LOCKFILE_VERSION = "9.0";

const stringMap = z.record(z.string().max(4096), z.string().max(4096));

/**
 * An optional map YAML may leave empty: `key:` with no value parses as "" under the failsafe
 * schema (and pnpm omits empty sections, which is the same thing).
 */
function optionalMap<T extends z.ZodType>(schema: T) {
  return z.preprocess(
    (value) => (value === "" || value === null ? undefined : value),
    schema.optional(),
  );
}

const importerDependencySchema = z.looseObject({
  specifier: z.string().max(4096),
  version: z.string().max(4096),
});
const importerSchema = z.looseObject({
  dependencies: optionalMap(z.record(z.string().max(256), importerDependencySchema)),
  devDependencies: optionalMap(z.record(z.string().max(256), importerDependencySchema)),
  optionalDependencies: optionalMap(z.record(z.string().max(256), importerDependencySchema)),
});

const packageEntrySchema = z.looseObject({
  resolution: z.looseObject({
    integrity: z.string().max(4096).optional(),
    tarball: z.string().max(4096).optional(),
    type: z.string().max(64).optional(),
    gitHosted: z.string().max(16).optional(),
  }),
  version: z.string().max(256).optional(),
  peerDependencies: stringMap.optional(),
  peerDependenciesMeta: z
    .record(z.string().max(256), z.looseObject({ optional: z.string().max(16).optional() }))
    .optional(),
  bundledDependencies: z.union([z.array(z.string().max(256)), z.string().max(16)]).optional(),
});
type PackageEntry = z.infer<typeof packageEntrySchema>;

const snapshotSchema = z.looseObject({
  dependencies: optionalMap(stringMap),
  optionalDependencies: optionalMap(stringMap),
});
type Snapshot = z.infer<typeof snapshotSchema>;

const pnpmLockfileSchema = z.looseObject({
  lockfileVersion: z.string(),
  overrides: optionalMap(stringMap),
  catalogs: z.unknown().optional(),
  importers: z.record(z.string().max(4096), importerSchema),
  packages: optionalMap(z.record(z.string().max(8192), packageEntrySchema)),
  snapshots: optionalMap(z.record(z.string().max(8192), snapshotSchema)),
});

export type PnpmParseResult =
  | { readonly ok: true; readonly instances: InstanceSet }
  | { readonly ok: false; readonly rejections: RejectionCollector };

/** How a failed shape scan is reported: an oversized or over-complex document is too large. */
const SHAPE_REASON = {
  too_large: "lockfile_too_large",
  too_complex: "lockfile_too_large",
  too_deep: "lockfile_too_deep",
  document_marker: "lockfile_syntax",
} as const satisfies Record<YamlShapeError, LockfileRejectionReason>;

interface KeyParts {
  readonly name: string;
  readonly version: string;
  /** The peer/patch context, e.g. `(supports-color@7.2.0)`. */
  readonly suffix: string;
}

/** Splits `name@version(peer@x)(patch_hash=…)`; the name may be scoped. */
function splitKey(key: string): KeyParts | null {
  const at = key.indexOf("@", key.startsWith("@") ? 1 : 0);
  if (at <= 0) return null;
  const rest = key.slice(at + 1);
  const paren = rest.indexOf("(");
  return {
    name: key.slice(0, at),
    version: paren === -1 ? rest : rest.slice(0, paren),
    suffix: paren === -1 ? "" : rest.slice(paren),
  };
}

type RefTarget =
  | { readonly kind: "snapshot"; readonly key: string }
  | { readonly kind: "rejected"; readonly reason: LockfileRejectionReason };

/**
 * Resolves a dependency reference (`2.1.2`, `4.3.4(supports-color@7.2.0)`, `debug@2.6.9`,
 * `link:../x`, `file:x`, a URL) to the snapshot key it names.
 */
function refTarget(alias: string, ref: string): RefTarget {
  const lower = ref.toLowerCase();
  if (lower.startsWith("link:") || lower.startsWith("file:")) {
    return { kind: "rejected", reason: "local_path_dependency" };
  }
  if (/^\d/.test(ref) || lower.startsWith("http://") || lower.startsWith("https://")) {
    return { kind: "snapshot", key: `${alias}@${ref}` };
  }
  return { kind: "snapshot", key: ref };
}

function jsonShapeError(error: unknown): LockfileRejectionReason {
  return error instanceof RangeError ? "lockfile_too_deep" : "lockfile_syntax";
}

function loadYaml(
  text: string,
): { ok: true; value: unknown } | { ok: false; reason: LockfileRejectionReason } {
  const shape = scanYamlShape(text, PNPM_LOCKFILE_LIMITS);
  if (!shape.ok) return { ok: false, reason: SHAPE_REASON[shape.error] };
  try {
    // One marker-free document, after the verified stream envelope (if any) is handled.
    // The shape scan refuses markers; `logLevel: "error"` reports any second document anyway.
    // Duplicate keys are found below in one walk: the parser's own check is quadratic.
    const document = parseDocument(text, {
      schema: "failsafe",
      uniqueKeys: false,
      strict: true,
      prettyErrors: false,
      logLevel: "error",
      merge: false,
      version: "1.2",
    });
    if (document.errors.length > 0) return { ok: false, reason: "lockfile_syntax" };
    const keyProblem = findMappingKeyProblem(document.contents);
    if (keyProblem !== null) {
      return {
        ok: false,
        reason: keyProblem === "duplicate_key" ? "lockfile_duplicate_key" : "lockfile_syntax",
      };
    }
    return { ok: true, value: document.toJS({ maxAliasCount: 0 }) };
  } catch (error) {
    return { ok: false, reason: jsonShapeError(error) };
  }
}

const IMPORTER_SECTIONS = ["dependencies", "devDependencies", "optionalDependencies"] as const;

/** Parses a pnpm v9 lockfile into instances, rejecting anything outside the supported model. */
export function parsePnpmLockfile(
  text: string,
  limits: LockfileLimits = GRAPH_LIMITS,
  workspace?: WorkspaceParserContext,
): PnpmParseResult {
  if (text.length > PNPM_LOCKFILE_LIMITS.maxLength) return rejectedDocument("lockfile_too_large");
  const normalized = text.replace(/^\uFEFF/u, "").replace(/\r\n/gu, "\n");
  if (!normalized.startsWith("---\n")) {
    const loaded = loadYaml(text);
    if (!loaded.ok) return rejectedDocument(loaded.reason);
    return parsePnpmDocument(loaded.value, limits, workspace);
  }
  // Check the entire stream before splitting: two documents share the original memory/shape bound.
  const shape = scanYamlShape(normalized, { ...PNPM_LOCKFILE_LIMITS, allowDocumentMarkers: true });
  if (!shape.ok) return rejectedDocument(SHAPE_REASON[shape.error]);
  const separator = normalized.indexOf("\n---\n", 4);
  if (separator === -1 || normalized.indexOf("\n---\n", separator + 5) !== -1)
    return rejectedDocument("lockfile_syntax");
  const header = normalized.slice(4, separator);
  if (header.length > 256 * 1024) return rejectedDocument("lockfile_too_large");
  const first = loadYaml(header);
  if (!first.ok) return rejectedDocument(first.reason);
  const bootstrap = pnpmToolchainSchema.safeParse(first.value);
  if (!bootstrap.success) return rejectedDocument("lockfile_invalid");
  const env = bootstrap.data;
  const pmDependencies = env.importers["."].packageManagerDependencies ?? {};
  if (
    Object.keys(env.importers["."].configDependencies).length !== 0 ||
    Object.keys(pmDependencies).some((name) => name !== "pnpm") ||
    Object.keys(env.packages).length > 128 ||
    Object.keys(env.snapshots).length > 128
  )
    return rejectedDocument("lockfile_invalid");
  for (const entry of Object.values(pmDependencies)) {
    if (
      !packageVersionSchema.safeParse(entry.version).success ||
      entry.specifier !== entry.version ||
      !(SUPPORTED_PM_MAJORS.pnpm as readonly number[]).includes(Number(entry.version.split(".")[0]))
    )
      return rejectedDocument("lockfile_invalid");
  }
  // Bootstrap packages are not project inventory, but cannot conceal private/local sources,
  // malformed integrity or dangling edges. Reuse the same registry graph reader for validation.
  const validated = parsePnpmDocument(
    {
      ...env,
      importers: { ".": { dependencies: pmDependencies } },
    },
    limits,
  );
  if (!validated.ok) return validated;
  const main = loadYaml(normalized.slice(separator + 5));
  if (!main.ok) return rejectedDocument(main.reason);
  return parsePnpmDocument(main.value, limits, workspace);
}

const pnpmToolchainSchema = z.strictObject({
  lockfileVersion: z.literal(SUPPORTED_PNPM_LOCKFILE_VERSION),
  importers: z.strictObject({
    ".": z.strictObject({
      configDependencies: z.record(z.string(), z.unknown()),
      packageManagerDependencies: z
        .record(
          z.string(),
          z.strictObject({
            specifier: z.string().max(4096),
            version: z.string().max(4096),
          }),
        )
        .optional(),
    }),
  }),
  packages: z.record(z.string(), z.unknown()),
  snapshots: z.record(z.string(), z.unknown()),
});

function rejectedDocument(reason: LockfileRejectionReason): PnpmParseResult {
  const rejections = new RejectionCollector();
  rejections.add(reason);
  return { ok: false, rejections };
}

function parsePnpmDocument(
  raw: unknown,
  limits: LockfileLimits,
  workspace?: WorkspaceParserContext,
): PnpmParseResult {
  const rejections = new RejectionCollector();
  const fail = (): PnpmParseResult => ({ ok: false, rejections });
  const rawVersion = z.looseObject({ lockfileVersion: z.unknown() }).safeParse(raw)
    .data?.lockfileVersion;
  if (typeof rawVersion !== "string") {
    rejections.add("lockfile_invalid");
    return fail();
  }
  if (rawVersion !== SUPPORTED_PNPM_LOCKFILE_VERSION) {
    rejections.add("unsupported_lockfile_version");
    return fail();
  }
  const parsed = pnpmLockfileSchema.safeParse(raw);
  if (!parsed.success) {
    rejections.add("lockfile_invalid");
    return fail();
  }
  const lockfile = parsed.data;
  const packages = lockfile.packages ?? {};
  const snapshots = lockfile.snapshots ?? {};
  if (
    Object.keys(snapshots).length > limits.maxPackages ||
    Object.keys(packages).length > limits.maxPackages
  ) {
    rejections.add("too_many_packages");
    return fail();
  }
  let declarations = 0;
  for (const snapshot of Object.values(snapshots)) {
    declarations += Object.keys(snapshot.dependencies ?? {}).length;
    declarations += Object.keys(snapshot.optionalDependencies ?? {}).length;
  }
  if (declarations > limits.maxDependencyEdges) {
    rejections.add("too_many_dependencies");
    return fail();
  }
  const project = lockfile.importers["."];
  if (project === undefined) {
    rejections.add("missing_root");
    return fail();
  }
  if (workspace !== undefined && !workspace.matchesMembers(Object.keys(lockfile.importers))) {
    rejections.add("workspace_packages");
  }
  if (workspace === undefined && Object.keys(lockfile.importers).some((key) => key !== ".")) {
    rejections.add("workspace_packages");
  }
  const lockedCatalogs = z
    .record(z.string(), z.record(z.string(), importerDependencySchema))
    .safeParse(lockfile.catalogs ?? {});
  if (lockfile.catalogs !== undefined && lockfile.catalogs !== null && workspace === undefined)
    rejections.add("catalog_protocol");
  if (!lockedCatalogs.success) rejections.add("lockfile_invalid");
  else if (workspace !== undefined) {
    for (const [name, entries] of Object.entries(lockedCatalogs.data)) {
      for (const [alias, entry] of Object.entries(entries)) {
        const catalogs = workspace.layout.catalogs;
        const source = classifyDependencySpec(entry.specifier);
        const registryName = source.kind === "alias" ? source.name : alias;
        const target = refTarget(registryName, entry.version);
        const parts = target.kind === "snapshot" ? splitKey(target.key) : null;
        if (
          catalogs === undefined ||
          catalogEntry(catalogs, name, alias) !== entry.specifier ||
          parts === null ||
          parts.name !== registryName ||
          !packageVersionSchema.safeParse(parts.version).success
        )
          rejections.add("lockfile_invalid");
      }
    }
  }
  // Override selectors are kept on the graph, so only ones that parse are accepted (pnpm refuses
  // any other selector too); a key is never copied out unvalidated.
  const lockfileOverrides: string[] = [];
  for (const [selector, value] of Object.entries(lockfile.overrides ?? {})) {
    if (parsePnpmSelector(selector) === null) {
      rejections.add("lockfile_invalid");
      continue;
    }
    lockfileOverrides.push(selector);
    if (value === "-" || /^\$\S+$/.test(value)) continue;
    const classified = classifyDependencySpec(value);
    if (classified.kind === "rejected") rejections.add(classified.reason);
    else if (classified.kind === "invalid") rejections.add("lockfile_invalid");
  }

  // Validate every package entry: name, exact version and a public-registry source.
  const validPackages = new Map<
    string,
    { name: PackageName; entry: PackageEntry; version: string }
  >();
  for (const [key, entry] of Object.entries(packages)) {
    const parts = splitKey(key);
    const name = parts === null ? null : packageNameSchema.safeParse(parts.name);
    if (parts === null || name === null || !name.success) {
      rejections.add("invalid_package_name");
      continue;
    }
    const resolution = entry.resolution;
    if (resolution.type !== undefined) {
      rejections.add(
        resolution.type === "git"
          ? "git_dependency"
          : resolution.type === "directory"
            ? "local_path_dependency"
            : "unsupported_protocol",
        name.data,
      );
      continue;
    }
    if (resolution.gitHosted === "true") {
      rejections.add("git_dependency", name.data);
      continue;
    }
    const version = packageVersionSchema.safeParse(parts.version);
    if (resolution.tarball !== undefined) {
      const source = checkTarballSource(
        resolution.tarball,
        name.data,
        version.success ? version.data : (entry.version ?? parts.version),
      );
      if (source !== null) {
        rejections.add(source, name.data);
        continue;
      }
    }
    if (!version.success) {
      rejections.add("invalid_package_version", name.data);
      continue;
    }
    const integrity = checkIntegrity(resolution.integrity);
    if (!integrity.ok) {
      rejections.add(integrity.reason, name.data);
      continue;
    }
    validPackages.set(key, { name: name.data, entry, version: version.data });
  }

  // Importer specifiers are package.json specs; reject non-registry ones explicitly.
  const rootRefs: {
    importer: string;
    alias: PackageName;
    section: DependencySection;
    spec: string;
    ref: string;
  }[] = [];
  for (const [importer, importerProject] of Object.entries(
    workspace === undefined ? { ".": project } : lockfile.importers,
  )) {
    if (
      workspace !== undefined &&
      !memberDeclarationsMatch(workspace, importer, importerProject, false)
    )
      rejections.add("lockfile_invalid");
    for (const section of IMPORTER_SECTIONS) {
      for (const [alias, dependency] of Object.entries(importerProject[section] ?? {})) {
        const name = packageNameSchema.safeParse(alias);
        if (!name.success) {
          rejections.add("invalid_package_name");
          continue;
        }
        const sourceSection = workspace?.sourceSection(importer, section, alias) ?? section;
        const spec =
          workspace?.resolvedSpec(importer, sourceSection, alias, dependency.specifier) ??
          dependency.specifier;
        const classified = classifyDependencySpec(spec);
        const catalog = workspace?.catalogDeclaration(importer, sourceSection, alias);
        const override = workspace?.overrideSpec(alias);
        if (override !== undefined) {
          const locked =
            catalog !== undefined && lockedCatalogs.success
              ? lockedCatalogs.data[catalog.catalog]?.[alias]
              : undefined;
          const importerRef = refTarget(alias, dependency.version);
          const importerKey = importerRef.kind === "snapshot" ? splitKey(importerRef.key) : null;
          const range = classified.kind === "alias" ? classified.target : classified;
          // pnpm replaces even catalog references with the root override, and omits their
          // catalog-lock entries. Bind the effective pin to both immutable root YAML and lock.
          if (
            lockfile.overrides?.[alias] !== override ||
            dependency.specifier !== override ||
            locked !== undefined ||
            importerKey === null ||
            importerKey.name !== (classified.kind === "alias" ? classified.name : alias) ||
            range.kind !== "range" ||
            !semver.satisfies(importerKey.version, range.range)
          )
            rejections.add("lockfile_invalid");
        } else if (catalog !== undefined) {
          const locked = lockedCatalogs.success
            ? lockedCatalogs.data[catalog.catalog]?.[alias]
            : undefined;
          const catalogPackage = classified.kind === "alias" ? classified.name : alias;
          const lockedRef = locked === undefined ? null : refTarget(catalogPackage, locked.version);
          const importerRef = refTarget(alias, dependency.version);
          const lockedKey = lockedRef?.kind === "snapshot" ? splitKey(lockedRef.key) : null;
          const importerKey = importerRef.kind === "snapshot" ? splitKey(importerRef.key) : null;
          if (
            locked?.specifier !== spec ||
            lockedKey === null ||
            importerKey === null ||
            lockedKey.name !== catalogPackage ||
            lockedKey.name !== importerKey.name ||
            lockedKey.version !== importerKey.version
          )
            rejections.add("lockfile_invalid");
        }
        const local = workspace?.localTarget(importer, sourceSection, alias, dependency.specifier);
        if (local !== undefined) {
          if (
            !dependency.version.startsWith("link:") ||
            resolveMemberLink(importer, dependency.version.slice(5)) !== local
          )
            rejections.add("dangling_reference", name.data);
          else
            rootRefs.push({
              importer,
              alias: name.data,
              section: sourceSection,
              spec: dependency.specifier,
              ref: `workspace:${local}`,
            });
          continue;
        }
        if (classified.kind === "rejected") {
          rejections.add(classified.reason, name.data);
          continue;
        }
        if (classified.kind === "invalid") {
          rejections.add("lockfile_invalid", name.data);
          continue;
        }
        rootRefs.push({
          importer,
          alias: name.data,
          section: sourceSection,
          spec,
          ref: dependency.version,
        });
      }
    }
  }
  if (workspace !== undefined && rootRefs.length + declarations > limits.maxDependencyEdges)
    rejections.add("too_many_dependencies");
  if (!rejections.empty) return fail();

  const instances = new Map<string, Instance>();
  for (const member of workspace?.layout.members ?? [])
    if (member.path !== ".") instances.set(`workspace:${member.path}`, localInstance(member));
  const snapshotEntries = new Map<
    string,
    { readonly snapshot: Snapshot; readonly base: { readonly entry: PackageEntry } }
  >();
  for (const [key, snapshot] of Object.entries(snapshots)) {
    const parts = splitKey(key);
    const base = parts === null ? undefined : validPackages.get(`${parts.name}@${parts.version}`);
    if (parts === null || base === undefined) {
      rejections.add("dangling_reference");
      continue;
    }
    const integrity = checkIntegrity(base.entry.resolution.integrity);
    const bundles = base.entry.bundledDependencies;
    snapshotEntries.set(key, { snapshot, base });
    instances.set(key, {
      id: key,
      name: base.name,
      version: packageVersionSchema.parse(base.version),
      integrity: integrity.ok ? integrity.integrity : null,
      integrityAlgorithm: integrity.ok ? integrity.algorithm : null,
      resolved: base.entry.resolution.tarball ?? null,
      bundled: false,
      bundles: Array.isArray(bundles) ? bundles.toSorted() : [],
      hasInstallScript: null,
      patched: parts.suffix.includes("(patch_hash="),
      edges: [],
    });
  }
  if (!rejections.empty) return fail();

  const edgeTo = (
    alias: string,
    ref: string,
    kind: InstanceEdge["kind"],
    optional: boolean,
    range: string | null,
    allowLocal = false,
  ): InstanceEdge | null => {
    const name = packageNameSchema.safeParse(alias);
    if (!name.success) {
      rejections.add("invalid_package_name");
      return null;
    }
    if (allowLocal && ref.startsWith("workspace:") && instances.has(ref))
      return { alias: name.data, kind, range, optional, target: ref };
    const target = refTarget(alias, ref);
    if (target.kind === "rejected") {
      rejections.add(target.reason, name.data);
      return null;
    }
    if (!instances.has(target.key)) {
      rejections.add("dangling_reference", name.data);
      return null;
    }
    return { alias: name.data, kind, range, optional, target: target.key };
  };

  for (const [key, { snapshot, base }] of snapshotEntries) {
    const instance = required(instances, key);
    const entry = base.entry;
    const peers = entry.peerDependencies ?? {};
    const optionalPeer = (alias: string): boolean =>
      entry.peerDependenciesMeta?.[alias]?.optional === "true";
    const edges: InstanceEdge[] = [];
    for (const [alias, ref] of Object.entries(snapshot.dependencies ?? {})) {
      const isPeer = Object.hasOwn(peers, alias) || optionalPeer(alias);
      const edge = edgeTo(
        alias,
        ref,
        isPeer ? "peer" : "prod",
        isPeer && optionalPeer(alias),
        isPeer ? (peers[alias] ?? "*") : null,
      );
      if (edge !== null) edges.push(edge);
    }
    for (const [alias, ref] of Object.entries(snapshot.optionalDependencies ?? {})) {
      const isPeer = Object.hasOwn(peers, alias) || optionalPeer(alias);
      const edge = edgeTo(
        alias,
        ref,
        isPeer ? "peer" : "optional",
        true,
        isPeer ? (peers[alias] ?? "*") : null,
      );
      if (edge !== null) edges.push(edge);
    }
    instances.set(key, { ...instance, edges });
  }

  const root: RootDependency[] = [];
  for (const { importer, alias, section, spec, ref } of rootRefs) {
    const kind = SECTION_KIND[section];
    const edge = edgeTo(alias, ref, kind, kind === "optional", spec, true);
    if (edge !== null)
      root.push({ ...(workspace === undefined ? {} : { importer }), alias, section, spec, edge });
  }
  if (workspace !== undefined) {
    for (const member of workspace.layout.members) {
      if (member.path === ".") continue;
      const id = `workspace:${member.path}`;
      const instance = required(instances, id);
      instances.set(id, {
        ...instance,
        edges: root
          .filter((dep) => dep.importer === member.path && dep.section !== "devDependencies")
          .map((dep) => dep.edge),
      });
    }
  }
  if (!rejections.empty) return fail();

  return {
    ok: true,
    instances: {
      packageManager: "pnpm",
      format: "pnpm-v9",
      root,
      instances,
      lockfileOverrides,
    },
  };
}
