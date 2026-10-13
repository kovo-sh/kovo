import { exactVersionSchema, packageNameSchema, packageVersionSchema } from "@kovo/contracts";
import semver from "semver";
import { z } from "zod";

// The registry metadata the ladder reads to predict resolutions: for each package, its versions'
// declared dependency ranges and deprecation, and the `latest` dist-tag. The control plane builds it
// from the npm upstream port's typed packument view (`@kovo/adapters/ports` NpmUpstreamPort); this
// is the minimal, validated subset core needs.

const rangeMapSchema = z.record(packageNameSchema, z.string().max(1024));

export const registryVersionSchema = z.strictObject({
  dependencies: rangeMapSchema,
  optionalDependencies: rangeMapSchema,
  peerDependencies: rangeMapSchema,
  deprecated: z.boolean(),
});
export type RegistryVersion = z.infer<typeof registryVersionSchema>;

export const registryPackageSchema = z.strictObject({
  name: packageNameSchema,
  /** The `latest` dist-tag, when it names a known version. */
  latest: packageVersionSchema.nullable(),
  versions: z.record(exactVersionSchema, registryVersionSchema),
});
export type RegistryPackage = z.infer<typeof registryPackageSchema>;

export class RegistryIndex {
  private readonly byName: ReadonlyMap<string, RegistryPackage>;

  constructor(packages: readonly RegistryPackage[]) {
    this.byName = new Map(packages.map((pkg) => [pkg.name, pkg]));
  }

  package(name: string): RegistryPackage | undefined {
    return this.byName.get(name);
  }

  version(name: string, version: string): RegistryVersion | undefined {
    const pkg = this.byName.get(name);
    return pkg !== undefined && Object.hasOwn(pkg.versions, version)
      ? pkg.versions[version]
      : undefined;
  }

  /**
   * The range `name@version` declares for the dependency `alias` (dependencies, then optional,
   * then peer), or undefined when the version does not depend on it. Throws nothing; callers
   * distinguish "no metadata" with {@link version}.
   */
  rangeFor(name: string, version: string, alias: string): string | undefined {
    const manifest = this.version(name, version);
    if (manifest === undefined) return undefined;
    const maps: readonly Readonly<Record<string, string>>[] = [
      manifest.dependencies,
      manifest.optionalDependencies,
      manifest.peerDependencies,
    ];
    for (const map of maps) {
      if (Object.hasOwn(map, alias)) return map[alias];
    }
    return undefined;
  }

  /**
   * The version a package manager resolves a fresh `range` to: the `latest` tag when it satisfies
   * the range and is not deprecated, otherwise the highest non-deprecated satisfying version,
   * otherwise the highest satisfying one (npm-pick-manifest's order; pnpm's default `highest`
   * resolution agrees on these inputs).
   */
  pick(name: string, range: string): string | null {
    return this.pickWithin(name, [range]);
  }

  /** {@link pick} for a version every range admits (one instance serving several dependents). */
  pickWithin(name: string, ranges: readonly string[]): string | null {
    const pkg = this.byName.get(name);
    if (pkg === undefined || ranges.some((range) => semver.validRange(range) === null)) return null;
    const admitted = Object.keys(pkg.versions)
      .filter((version) => ranges.every((range) => semver.satisfies(version, range)))
      .toSorted(semver.rcompare);
    const deprecated = (version: string): boolean => pkg.versions[version]?.deprecated === true;
    if (pkg.latest !== null && admitted.includes(pkg.latest) && !deprecated(pkg.latest)) {
      return pkg.latest;
    }
    return admitted.find((version) => !deprecated(version)) ?? admitted[0] ?? null;
  }
}
