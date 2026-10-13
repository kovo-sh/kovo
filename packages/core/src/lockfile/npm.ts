import { packageNameSchema, packageVersionSchema } from "@kovo/contracts";
import { z } from "zod";

import { isJsonObject, parseBoundedJson, type JsonLimits } from "../manifest/bounded-json.js";
import { classifyDependencySpec } from "../manifest/dependency-spec.js";
import { DEPENDENCY_SECTIONS, type DependencySection } from "../manifest/package-json.js";
import type { Instance, InstanceEdge, InstanceSet, RootDependency } from "./instances.js";
import { RejectionCollector, type LockfileRejectionReason } from "./reasons.js";
import { checkIntegrity, checkTarballSource } from "./registry-source.js";
import { GRAPH_LIMITS, SECTION_KIND, type DependencyKind, type LockfileLimits } from "./types.js";
import { required } from "./util.js";
import {
  localInstance,
  memberDeclarationsMatch,
  type WorkspaceParserContext,
} from "./workspace/parser-context.js";
import { canonicalWorkspacePath } from "./workspace/discover.js";

// npm lockfile v2/v3 (`package-lock.json`, lockfileVersion 2 or 3) → instances. Only the `packages`
// section is read (v2 also carries the legacy v1 `dependencies` tree for old npm; npm 7+ ignores it
// when `packages` exists). Keys are install locations (`node_modules/a/node_modules/b`); a
// dependency resolves the way Node does, from the dependent's own `node_modules` up to the root.

/**
 * The bounded parser's limits for package-lock.json (docs/decisions/lockfile.md "Hostile files are
 * parsed with bounded, strict parsers"). Real entries hold 10–20 JSON values, so the node bound
 * follows the package bound (`GRAPH_LIMITS.maxPackages` × 20); 16 MiB holds more than 20 000 real
 * entries. At either bound a hostile document parses within about 400 MB of heap and a few seconds
 * (measured, `npm.test.ts` › hostile shapes), where the former 64 MiB / 5 000 000 nodes needed
 * 860 MB for 45 MB: more than a 2 GiB worker can give each of several inventories.
 */
export const NPM_LOCKFILE_LIMITS: JsonLimits = {
  maxLength: 16 * 1024 * 1024,
  maxDepth: 256,
  maxNodes: GRAPH_LIMITS.maxPackages * 20,
  maxStringLength: 64 * 1024,
};

const specMap = z.record(z.string().max(256), z.string().max(4096));

const npmEntrySchema = z.looseObject({
  name: z.string().max(256).optional(),
  version: z.string().max(256).optional(),
  resolved: z.string().max(4096).optional(),
  integrity: z.string().max(4096).optional(),
  link: z.boolean().optional(),
  inBundle: z.boolean().optional(),
  hasInstallScript: z.boolean().optional(),
  dependencies: specMap.optional(),
  optionalDependencies: specMap.optional(),
  peerDependencies: specMap.optional(),
  devDependencies: specMap.optional(),
  peerDependenciesMeta: z
    .record(z.string().max(256), z.looseObject({ optional: z.boolean().optional() }))
    .optional(),
  bundleDependencies: z.union([z.array(z.string().max(256)), z.boolean()]).optional(),
  workspaces: z.unknown().optional(),
});
type NpmEntry = z.infer<typeof npmEntrySchema>;

const npmLockfileSchema = z.looseObject({
  lockfileVersion: z.union([z.literal(2), z.literal(3)]),
  packages: z.record(z.string().max(8192), npmEntrySchema),
});

export type NpmParseResult =
  | { readonly ok: true; readonly instances: InstanceSet }
  | { readonly ok: false; readonly rejections: RejectionCollector };

const NODE_MODULES = "node_modules/";
const NESTED = "/node_modules/";

interface Declared {
  readonly alias: string;
  readonly kind: DependencyKind;
  readonly range: string;
  readonly optional: boolean;
  readonly section: DependencySection;
}

/** Splits `node_modules/a/node_modules/@s/b` into its folder names, or null if malformed. */
function locationSegments(location: string): string[] | null {
  if (!location.startsWith(NODE_MODULES)) return null;
  const segments = location.slice(NODE_MODULES.length).split(NESTED);
  return segments.every((segment) => packageNameSchema.safeParse(segment).success)
    ? segments
    : null;
}

/**
 * A package folder in the install tree: the project root, or a `node_modules/<name>` folder, with
 * the packages installed in its own `node_modules`. `entry` is the lockfile location when the
 * lockfile has an entry there (intermediate folders may have none).
 */
interface Folder {
  readonly parent: Folder | null;
  readonly children: Map<string, Folder>;
  entry: string | null;
  /** The entry declares `bundleDependencies`: everything below it ships in its tarball. */
  bundler: boolean;
}

function folder(parent: Folder | null): Folder {
  return { parent, children: new Map(), entry: null, bundler: false };
}

/** The install tree of every lockfile location, so each lookup walks parents, never strings. */
class InstallTree {
  readonly root: Folder = folder(null);

  add(location: string, segments: readonly string[]): Folder {
    let current = this.root;
    for (const segment of segments) {
      let child = current.children.get(segment);
      if (child === undefined) {
        child = folder(current);
        current.children.set(segment, child);
      }
      current = child;
    }
    current.entry = location;
    return current;
  }

  /**
   * The location a dependency named `alias` of the package in `from` resolves to, the way Node
   * resolves `require`: the dependent's own `node_modules`, then each enclosing one up to the root.
   */
  resolve(from: Folder, alias: string): string | null {
    for (let current: Folder | null = from; current !== null; current = current.parent) {
      const entry = current.children.get(alias)?.entry;
      if (entry !== undefined && entry !== null) return entry;
    }
    return null;
  }

  /** Whether a folder above `at` bundles its dependencies (npm `bundleDependencies`). */
  insideBundle(at: Folder): boolean {
    for (let current = at.parent; current !== null; current = current.parent) {
      if (current.bundler) return true;
    }
    return false;
  }
}

function declaresBundle(entry: NpmEntry): boolean {
  const bundle = entry.bundleDependencies;
  return bundle === true || (Array.isArray(bundle) && bundle.length > 0);
}

/** How many dependency declarations the entries hold (bounded before any is resolved). */
function declarationCount(entries: Iterable<NpmEntry>): number {
  let count = 0;
  for (const entry of entries) {
    for (const map of [
      entry.dependencies,
      entry.optionalDependencies,
      entry.peerDependencies,
      entry.devDependencies,
      entry.peerDependenciesMeta,
    ]) {
      if (map !== undefined) count += Object.keys(map).length;
    }
  }
  return count;
}

/**
 * An entry's declared dependencies; optional peers may come from peerDependenciesMeta alone. The
 * root keeps one declaration per section (package.json may list a name in two sections, and the
 * production one must count); a dependency keeps one per name.
 */
function declaredDependencies(entry: NpmEntry, isRoot: boolean): Declared[] {
  const declared = new Map<string, Declared>();
  const sections: readonly DependencySection[] = isRoot
    ? DEPENDENCY_SECTIONS
    : ["dependencies", "optionalDependencies", "peerDependencies"];
  for (const section of sections) {
    for (const [alias, range] of Object.entries(entry[section] ?? {})) {
      const kind = SECTION_KIND[section];
      const optional =
        kind === "optional" ||
        (kind === "peer" && entry.peerDependenciesMeta?.[alias]?.optional === true);
      // A later section wins: npm lists an optional dependency only under optionalDependencies.
      declared.set(isRoot ? `${section}\u0000${alias}` : alias, {
        alias,
        kind,
        range,
        optional,
        section,
      });
    }
  }
  if (!isRoot) {
    // `peerDependenciesMeta` without a `peerDependencies` entry is an optional peer on any version
    // (npm and pnpm treat it as `*`; debug@4 declares supports-color this way).
    for (const [alias, meta] of Object.entries(entry.peerDependenciesMeta ?? {})) {
      if (!declared.has(alias) && meta.optional === true) {
        declared.set(alias, {
          alias,
          kind: "peer",
          range: "*",
          optional: true,
          section: "peerDependencies",
        });
      }
    }
  }
  return [...declared.values()];
}

function jsonErrorReason(error: string): LockfileRejectionReason {
  if (error === "duplicate_key") return "lockfile_duplicate_key";
  if (error === "syntax") return "lockfile_syntax";
  if (error === "too_deep") return "lockfile_too_deep";
  return "lockfile_too_large";
}

/** Parses an npm v2/v3 lockfile into instances, rejecting anything outside the supported model. */
export function parseNpmLockfile(
  text: string,
  limits: LockfileLimits = GRAPH_LIMITS,
  workspace?: WorkspaceParserContext,
): NpmParseResult {
  const rejections = new RejectionCollector();
  const fail = (): NpmParseResult => ({ ok: false, rejections });

  const json = parseBoundedJson(text, NPM_LOCKFILE_LIMITS);
  if (!json.ok) {
    rejections.add(jsonErrorReason(json.error));
    return fail();
  }
  const document = json.value;
  if (!isJsonObject(document)) {
    rejections.add("lockfile_invalid");
    return fail();
  }
  const lockfileVersion = document["lockfileVersion"];
  if (lockfileVersion !== 2 && lockfileVersion !== 3) {
    rejections.add(
      typeof lockfileVersion === "number" ? "unsupported_lockfile_version" : "lockfile_invalid",
    );
    return fail();
  }
  // Counted before validation, so the schema never copies an oversized `packages` map.
  const rawPackages = document["packages"];
  if (isJsonObject(rawPackages) && Object.keys(rawPackages).length > limits.maxPackages) {
    rejections.add("too_many_packages");
    return fail();
  }
  const parsed = npmLockfileSchema.safeParse(document);
  if (!parsed.success) {
    rejections.add("lockfile_invalid");
    return fail();
  }
  const packages = parsed.data.packages;
  const root = packages[""];
  if (root === undefined) {
    rejections.add("missing_root");
    return fail();
  }
  if (declarationCount(Object.values(packages)) > limits.maxDependencyEdges) {
    rejections.add("too_many_dependencies");
    return fail();
  }
  const workspaces = root.workspaces !== undefined;
  const linkReason: LockfileRejectionReason = workspaces
    ? "workspace_packages"
    : "local_path_dependency";
  if (workspaces && workspace === undefined) rejections.add("workspace_packages");
  const memberEntries = new Map<string, NpmEntry>();
  if (
    workspace !== undefined &&
    JSON.stringify(root.workspaces ?? []) !==
      JSON.stringify(
        workspace.layout.members.find((member) => member.path === ".")?.manifest.document[
          "workspaces"
        ] ?? [],
      )
  )
    rejections.add("workspace_packages");
  if (workspace !== undefined) {
    for (const member of workspace.layout.members) {
      const entry = packages[member.path === "." ? "" : member.path];
      if (
        entry === undefined ||
        !memberDeclarationsMatch(workspace, member.path, entry, true) ||
        (member.path !== "." &&
          ((entry.name !== undefined && entry.name !== member.manifest.name) ||
            entry.version !== (member.manifest.version ?? undefined)))
      ) {
        rejections.add("lockfile_invalid");
      } else memberEntries.set(member.path, entry);
    }
  }

  // Root dependencies are validated as package.json specs: a URL or git spec is rejected even
  // when npm recorded a canonical-looking `resolved` for it.
  const rootDeclared = declaredDependencies(root, true);
  for (const declared of rootDeclared) {
    const name = packageNameSchema.safeParse(declared.alias);
    if (!name.success) {
      rejections.add("invalid_package_name");
      continue;
    }
    if (workspace?.localTarget(".", declared.section, declared.alias, declared.range) !== undefined)
      continue;
    const classified = classifyDependencySpec(declared.range);
    if (classified.kind === "rejected") rejections.add(classified.reason, name.data);
    else if (classified.kind === "invalid") rejections.add("lockfile_invalid", name.data);
  }

  // The install tree first: whether an entry sits inside a bundle depends on its ancestors.
  const tree = new InstallTree();
  const memberTrees = new Map<string, InstallTree>();
  for (const path of memberEntries.keys())
    if (path !== ".") memberTrees.set(path, new InstallTree());
  const locationTree = (location: string): { tree: InstallTree; relative: string } | null => {
    if (location.startsWith(NODE_MODULES)) return { tree, relative: location };
    const member = [...memberTrees.keys()].find((path) =>
      location.startsWith(`${path}/node_modules/`),
    );
    const memberTree = member === undefined ? undefined : memberTrees.get(member);
    return member === undefined || memberTree === undefined
      ? null
      : { tree: memberTree, relative: location.slice(member.length + 1) };
  };
  const located: {
    readonly location: string;
    readonly entry: NpmEntry;
    readonly place: { readonly segments: string[]; readonly at: Folder } | null;
  }[] = [];
  for (const [location, entry] of Object.entries(packages)) {
    if (location === "") continue;
    if (workspace !== undefined && memberEntries.has(location)) continue;
    const placed = locationTree(location);
    const segments = placed === null ? null : locationSegments(placed.relative);
    if (segments !== null && segments.length > limits.maxNestingDepth) {
      rejections.add("lockfile_too_deep");
      return fail();
    }
    const at = segments === null || placed === null ? null : placed.tree.add(location, segments);
    if (at !== null) at.bundler = declaresBundle(entry);
    located.push({
      location,
      entry,
      place: segments === null || at === null ? null : { segments, at },
    });
  }

  const instances = new Map<string, Instance>();
  for (const member of workspace?.layout.members ?? [])
    if (member.path !== ".") instances.set(`workspace:${member.path}`, localInstance(member));
  const links = new Map<string, string>();
  const entries = new Map<string, { readonly entry: NpmEntry; readonly at: Folder }>();
  for (const { location, entry, place } of located) {
    if (place === null) {
      // A package folder outside node_modules: the target of a workspace or file: link.
      rejections.add(linkReason);
      continue;
    }
    const { segments, at } = place;
    const name = packageNameSchema.safeParse(entry.name ?? segments.at(-1));
    if (!name.success) {
      rejections.add("invalid_package_name");
      continue;
    }
    if (entry.link === true) {
      const member = workspace?.layout.members.find(
        (item) =>
          item.path === entry.resolved && item.path !== "." && item.manifest.name === name.data,
      );
      if (member === undefined || !canonicalWorkspacePath(member.path))
        rejections.add(linkReason, name.data);
      else links.set(location, `workspace:${member.path}`);
      continue;
    }
    const version = packageVersionSchema.safeParse(entry.version);
    if (!version.success) {
      rejections.add("invalid_package_version", name.data);
      continue;
    }
    if (entry.resolved !== undefined) {
      const source = checkTarballSource(entry.resolved, name.data, version.data);
      if (source !== null) {
        rejections.add(source, name.data);
        continue;
      }
    }
    // Bundled packages ship inside their bundler's tarball, whose integrity covers them. The
    // `inBundle` flag is the lockfile's claim; it only exempts an entry that really sits below a
    // package declaring `bundleDependencies` (npm derives bundling from the bundler, too).
    const bundled = entry.inBundle === true && tree.insideBundle(at);
    const integrity =
      bundled && entry.integrity === undefined ? null : checkIntegrity(entry.integrity);
    if (integrity !== null && !integrity.ok) {
      rejections.add(integrity.reason, name.data);
      continue;
    }
    entries.set(location, { entry, at });
    instances.set(location, {
      id: location,
      name: name.data,
      version: version.data,
      integrity: integrity === null ? null : integrity.integrity,
      integrityAlgorithm: integrity === null ? null : integrity.algorithm,
      resolved: entry.resolved ?? null,
      bundled,
      bundles: Array.isArray(entry.bundleDependencies) ? entry.bundleDependencies.toSorted() : [],
      hasInstallScript: entry.hasInstallScript === true,
      patched: false,
      edges: [],
    });
  }
  if (!rejections.empty) return fail();

  const resolveWorkspace = (from: string, alias: string): string | null => {
    let dir = from;
    while (true) {
      const location = dir === "" ? `node_modules/${alias}` : `${dir}/node_modules/${alias}`;
      const linked = links.get(location);
      if (linked !== undefined) return linked;
      if (instances.has(location)) return location;
      if (dir === "") return null;
      const slash = dir.lastIndexOf("/");
      dir = slash === -1 ? "" : dir.slice(0, slash);
    }
  };
  const edgeFor = (from: Folder, declared: Declared, location = ""): InstanceEdge | null => {
    const alias = packageNameSchema.safeParse(declared.alias);
    if (!alias.success) {
      rejections.add("invalid_package_name");
      return null;
    }
    const target =
      workspace === undefined
        ? tree.resolve(from, declared.alias)
        : resolveWorkspace(location, declared.alias);
    return {
      alias: alias.data,
      kind: declared.kind,
      range: declared.range,
      optional: declared.optional,
      target: target !== null && instances.has(target) ? target : null,
    };
  };

  for (const [location, { entry, at }] of entries) {
    const instance = required(instances, location);
    const edges = declaredDependencies(entry, false).flatMap((declared) => {
      const edge = edgeFor(at, declared, location);
      if (workspace !== undefined && edge?.target?.startsWith("workspace:") === true)
        rejections.add("local_path_dependency", edge.alias);
      return edge === null ? [] : [edge];
    });
    instances.set(location, { ...instance, edges });
  }
  const rootDependencies: RootDependency[] = [];
  for (const [importer, entry] of workspace === undefined
    ? [[".", root] as const]
    : memberEntries) {
    for (const declared of declaredDependencies(entry, true)) {
      const expectedLocal = workspace?.localTarget(
        importer,
        declared.section,
        declared.alias,
        declared.range,
      );
      const classified = classifyDependencySpec(declared.range);
      if (expectedLocal === undefined && classified.kind === "rejected")
        rejections.add(classified.reason);
      if (classified.kind === "invalid") rejections.add("lockfile_invalid");
      const edge = edgeFor(tree.root, declared, importer === "." ? "" : importer);
      if (
        workspace !== undefined &&
        edge !== null &&
        (expectedLocal === undefined
          ? edge.target?.startsWith("workspace:") === true
          : edge.target !== `workspace:${expectedLocal}`)
      )
        rejections.add("dangling_reference");
      if (edge !== null) {
        rootDependencies.push({
          ...(workspace === undefined ? {} : { importer }),
          alias: edge.alias,
          section: declared.section,
          spec: declared.range,
          edge,
        });
      }
    }
  }
  if (workspace !== undefined) {
    for (const member of workspace.layout.members) {
      if (member.path === ".") continue;
      const id = `workspace:${member.path}`;
      const instance = required(instances, id);
      instances.set(id, {
        ...instance,
        edges: rootDependencies
          .filter((dep) => dep.importer === member.path && dep.section !== "devDependencies")
          .map((dep) => dep.edge),
      });
    }
  }
  if (!rejections.empty) return fail();

  return {
    ok: true,
    instances: {
      packageManager: "npm",
      format: lockfileVersion === 2 ? "npm-v2" : "npm-v3",
      root: rootDependencies,
      instances,
      lockfileOverrides: [],
    },
  };
}
