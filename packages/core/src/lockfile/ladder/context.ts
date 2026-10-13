import type { PackageName, PackageVersion } from "@kovo/contracts";
import semver from "semver";

import { pointerOf } from "../../manifest/json-pointer.js";
import type { ManifestDependency, PackageManifest } from "../../manifest/package-json.js";
import type { LockfileName } from "../parse.js";
import { LOCKFILE_NAMES } from "../parse.js";
import {
  indexPackages,
  type DependencyEdge,
  type DependencyGraph,
  type DirectDependency,
  type PackageKey,
  type ResolvedPackageNode,
} from "../types.js";
import { required } from "../util.js";
import { isUnsafePositional, type SaveStyle } from "./commands.js";
import { RegistryIndex } from "./registry.js";
import type {
  LadderInput,
  LadderPlanKind,
  LadderSkipReason,
  LadderStep,
  ManifestEdit,
  PlanRung,
  PmCommand,
} from "./types.js";

// Shared lookups for the rung planners.

export interface ParentLink {
  readonly parent: ResolvedPackageNode;
  readonly edge: DependencyEdge;
}

/** A direct dependency the plan moves to an exact package/version. */
export interface Pin {
  readonly alias: PackageName;
  readonly name: PackageName;
  readonly version: PackageVersion;
}

/** One way to clear one affected instance at one rung. */
export interface Technique {
  readonly rung: PlanRung;
  readonly kind: LadderPlanKind;
  readonly from: PackageVersion;
  readonly to: PackageVersion | null;
  readonly via: LadderStep["via"];
  /** package.json edits trusted code applies before any command (overrides, removals). */
  readonly applyEdits: readonly ManifestEdit[];
  /** package.json edits the package manager writes itself (`install`/`add` with a save style). */
  readonly writtenEdits: readonly ManifestEdit[];
  /** Commands that must run before the others (moving a shared instance's dependents). */
  readonly preCommands: readonly PmCommand[];
  readonly commands: readonly PmCommand[];
  readonly pins: readonly Pin[];
  readonly anchors: readonly PackageName[];
}

export type TechniqueResult =
  | { readonly ok: true; readonly technique: Technique }
  | { readonly ok: false; readonly reason: LadderSkipReason };

export function skip(reason: LadderSkipReason): TechniqueResult {
  return { ok: false, reason };
}

export class LadderContext {
  readonly input: LadderInput;
  readonly graph: DependencyGraph;
  readonly registry: RegistryIndex;
  readonly lockfileName: LockfileName;
  readonly nodes: ReadonlyMap<PackageKey, ResolvedPackageNode>;
  /** Safe versions, ascending. */
  readonly safe: readonly PackageVersion[];
  readonly affected: ReadonlySet<string>;
  private readonly safeSet: ReadonlySet<string>;
  private readonly parentsByKey: ReadonlyMap<PackageKey, readonly ParentLink[]>;

  constructor(input: LadderInput) {
    this.input = input;
    this.graph = input.graph;
    this.registry = new RegistryIndex(input.registry);
    this.lockfileName = LOCKFILE_NAMES[input.graph.packageManager];
    this.nodes = indexPackages(input.graph);
    this.safe = [...new Set(input.target.safeVersions)]
      .filter((version) => !input.target.affectedVersions.includes(version))
      .toSorted(semver.compare);
    this.safeSet = new Set(this.safe);
    this.affected = new Set(input.target.affectedVersions);
    const parents = new Map<PackageKey, ParentLink[]>();
    for (const parent of input.graph.packages) {
      for (const edge of parent.dependencies) {
        const list = parents.get(edge.target);
        if (list === undefined) parents.set(edge.target, [{ parent, edge }]);
        else list.push({ parent, edge });
      }
    }
    this.parentsByKey = parents;
  }

  get pm(): DependencyGraph["packageManager"] {
    return this.graph.packageManager;
  }

  get manifest(): PackageManifest {
    return this.input.manifest;
  }

  /** Packages depending on `key` (root declarations excluded). */
  parents(key: PackageKey): readonly ParentLink[] {
    return this.parentsByKey.get(key) ?? [];
  }

  /** Root declarations resolving to `key`. */
  directDeclarations(key: PackageKey): readonly DirectDependency[] {
    return this.graph.direct.filter((dependency) => dependency.target === key);
  }

  /** Whether any root declaration's key or resolved package has this name. */
  nameIsDirect(name: string): boolean {
    return this.graph.direct.some(
      (dependency) =>
        dependency.alias === name ||
        (dependency.target !== null && this.nodes.get(dependency.target)?.name === name),
    );
  }

  /** The package.json declaration for a root dependency (by alias and section). */
  declaration(direct: DirectDependency): ManifestDependency | undefined {
    return this.manifest.dependencies.find(
      (dependency) => dependency.alias === direct.alias && dependency.section === direct.section,
    );
  }

  /** The range a dependent declares for `edge`, from the lockfile or the registry metadata. */
  rangeOf(link: ParentLink): string | undefined {
    return (
      link.edge.range ??
      this.registry.rangeFor(link.parent.name, link.parent.version, link.edge.alias)
    );
  }

  /** Whether `version` is one of the safe versions. */
  isSafe(version: string): boolean {
    return this.safeSet.has(version);
  }

  /** The safe version equal to `version`, typed as a package version. */
  safeVersion(version: string | null): PackageVersion | null {
    return version === null ? null : (this.safe.find((candidate) => candidate === version) ?? null);
  }

  /** The node for a key the graph is known to contain. */
  node(key: PackageKey): ResolvedPackageNode {
    return required(this.nodes, key);
  }

  /**
   * Every dependent's declared range for its edge, or null when one is unknown (neither in the
   * lockfile nor in the registry metadata) or not a valid range.
   */
  knownRanges(links: readonly ParentLink[]): string[] | null {
    const ranges: string[] = [];
    for (const link of links) {
      const range = this.rangeOf(link);
      if (range === undefined || semver.validRange(range) === null) return null;
      ranges.push(range);
    }
    return ranges;
  }

  /** Every resolved version of `name` in the graph. */
  versionsOf(name: string): PackageVersion[] {
    return this.graph.packages.filter((node) => node.name === name).map((node) => node.version);
  }

  /** Whether `from` reaches an affected instance of the target through dependency edges. */
  reachesAffected(from: PackageKey): boolean {
    const seen = new Set<PackageKey>();
    const queue: PackageKey[] = [from];
    for (let key = queue.pop(); key !== undefined; key = queue.pop()) {
      if (seen.has(key)) continue;
      seen.add(key);
      const node = this.nodes.get(key);
      if (node === undefined) continue;
      if (node.name === this.input.target.name && this.affected.has(node.version)) return true;
      for (const edge of node.dependencies) queue.push(edge.target);
    }
    return false;
  }

  /** An override (either manager's) already targeting `name`. */
  overridesTarget(name: string): boolean {
    return this.manifest.overrides.some((rule) => rule.target === name);
  }
}

/** The save style of a declared spec: `^x.y.z`, `~x.y.z`, an exact version, or anything else. */
export function saveStyleOf(declaration: ManifestDependency): SaveStyle {
  const spec = declaration.registrySpec;
  if (spec.kind === "tag") return "exact";
  const range = spec.range.trim();
  if (/^\^\s*v?\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.+-]*)?$/.test(range)) return "^";
  if (/^~\s*v?\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.+-]*)?$/.test(range)) return "~";
  // Exact versions stay exact; anything else (unions, comparators, x-ranges) is narrowed to the
  // exact version, the narrowest edit that pins the fix.
  return "exact";
}

/** The spec written for `version` in `style`, re-wrapped in `npm:` for aliases. */
export function specFor(
  declaration: ManifestDependency,
  version: string,
  style: SaveStyle,
): string {
  const range = style === "exact" ? version : `${style}${version}`;
  return declaration.aliased ? `npm:${declaration.name}@${range}` : range;
}

/** The install argument after `alias@`: the version, or `npm:<name>@<version>` for aliases. */
export function installSpecFor(declaration: ManifestDependency, version: string): string {
  return declaration.aliased ? `npm:${declaration.name}@${version}` : version;
}

export function dependencyPointer(declaration: ManifestDependency): string {
  return pointerOf([declaration.section, declaration.alias]);
}

/** Names that would be passed to a package manager must not look like options or paths. */
export function unsafeNames(...names: readonly string[]): boolean {
  return names.some(isUnsafePositional);
}
