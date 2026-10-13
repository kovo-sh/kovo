import type { AdvisoryId, PackageName, PackageVersion, TierConfigSets } from "@kovo/contracts";

import type { AdvisoryFacts } from "./model.js";
import { compileAdvisory, compiledAdvisoryAffects, type CompiledAdvisory } from "./ranges.js";
import { tierDecision, type TierDecision } from "./tier.js";
import { compareVersionText, parseNpmVersion } from "./version.js";

// SPEC inventoryWorkflow step 4: "Match advisory ranges and explicit affected versions." Matching is
// per resolved package instance, i.e. per (name, version): "retain all paths needed to resolve
// multiple affected instances; is_dev is false if any prod path exists". SPEC: "Advisory matching
// uses an index on resolved package names and versions".

/** One resolved package instance of a snapshot (`resolved_packages`). */
export interface ResolvedInstance {
  readonly name: PackageName;
  readonly version: PackageVersion;
  /** False if any production path reaches the instance. */
  readonly isDev: boolean;
  /** Package-name chains from a direct dependency down to the instance. */
  readonly depPaths: readonly (readonly PackageName[])[];
}

/** One advisory affecting one instance: a finding candidate `(advisory, package, version)`. */
export interface AdvisoryMatch {
  readonly advisoryId: AdvisoryId;
  readonly package: PackageName;
  readonly version: PackageVersion;
  readonly isDev: boolean;
  readonly depPaths: readonly (readonly PackageName[])[];
  /** The advisory is withdrawn: its findings are withdrawn, never opened. */
  readonly withdrawn: boolean;
  readonly tier: TierDecision;
}

/** Advisories compiled and indexed by package name, reusable across repositories. */
export interface AdvisoryIndex<A extends AdvisoryFacts = AdvisoryFacts> {
  readonly byPackage: ReadonlyMap<PackageName, readonly CompiledAdvisory<A>[]>;
}

export function indexAdvisories<A extends AdvisoryFacts>(
  advisories: readonly A[],
): AdvisoryIndex<A> {
  const byPackage = new Map<PackageName, CompiledAdvisory<A>[]>();
  const seen = new Set<AdvisoryId>();
  for (const advisory of advisories) {
    if (seen.has(advisory.id)) throw new RangeError(`duplicate advisory ${advisory.id}`);
    seen.add(advisory.id);
    const compiled = compileAdvisory(advisory);
    for (const name of compiled.byPackage.keys()) {
      const list = byPackage.get(name) ?? [];
      list.push(compiled);
      byPackage.set(name, list);
    }
  }
  return { byPackage };
}

/**
 * Merges duplicate `(name, version)` rows into one instance: production if any row is, with the
 * union of their paths.
 */
function mergeInstances(packages: readonly ResolvedInstance[]): ResolvedInstance[] {
  interface Merged {
    isDev: boolean;
    readonly first: Pick<ResolvedInstance, "name" | "version">;
    readonly paths: (readonly PackageName[])[];
    readonly pathKeys: Set<string>;
  }
  const merged = new Map<string, Merged>();
  for (const instance of packages) {
    const key = `${instance.name}@${instance.version}`;
    let entry = merged.get(key);
    if (entry === undefined) {
      entry = { isDev: instance.isDev, first: instance, paths: [], pathKeys: new Set() };
      merged.set(key, entry);
    }
    entry.isDev &&= instance.isDev;
    for (const path of instance.depPaths) {
      // Package names never contain NUL, so the joined key identifies the path.
      const pathKey = path.join("\u0000");
      if (entry.pathKeys.has(pathKey)) continue;
      entry.pathKeys.add(pathKey);
      entry.paths.push(path);
    }
  }
  return [...merged.values()].map(({ first, isDev, paths }) => ({
    name: first.name,
    version: first.version,
    isDev,
    depPaths: paths,
  }));
}

function compareMatches(a: AdvisoryMatch, b: AdvisoryMatch): number {
  if (a.package !== b.package) return a.package < b.package ? -1 : 1;
  if (a.version !== b.version) return compareVersionText(a.version, b.version);
  return a.advisoryId < b.advisoryId ? -1 : a.advisoryId > b.advisoryId ? 1 : 0;
}

export interface MatchInput {
  readonly packages: readonly ResolvedInstance[];
  readonly index: AdvisoryIndex;
  /** CVE IDs currently in CISA KEV. */
  readonly kev: ReadonlySet<string>;
  readonly tierConfig: TierConfigSets;
}

/**
 * Every (advisory, package, version) the advisories affect, tiered with SPEC's `tier()` for the
 * instance's own dev/production status. Withdrawn advisories still match (flagged), so the finding
 * lifecycle can tell a withdrawal from an absent version. Sorted by package, version, advisory.
 * Every contracts `PackageVersion` parses (the schema refuses what node-semver cannot compare), so a
 * RangeError for an unparseable instance version is an invariant violation (unvalidated input).
 */
export function matchAdvisories(input: MatchInput): AdvisoryMatch[] {
  const matches: AdvisoryMatch[] = [];
  for (const instance of mergeInstances(input.packages)) {
    const candidates = input.index.byPackage.get(instance.name);
    if (candidates === undefined) continue;
    const version = parseNpmVersion(instance.version);
    if (version === null)
      throw new RangeError(`not an exact version: ${instance.name}@${instance.version}`);
    for (const compiled of candidates) {
      if (!compiledAdvisoryAffects(compiled, instance.name, version)) continue;
      const advisory = compiled.advisory;
      matches.push({
        advisoryId: advisory.id,
        package: instance.name,
        version: instance.version,
        isDev: instance.isDev,
        depPaths: instance.depPaths,
        withdrawn: advisory.withdrawnAt !== null,
        tier: tierDecision(
          { package: instance.name, isDev: instance.isDev },
          advisory,
          input.kev,
          input.tierConfig,
        ),
      });
    }
  }
  return matches.toSorted(compareMatches);
}
