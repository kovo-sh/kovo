import { packageNameSchema, packageVersionSchema } from "@kovo/contracts";

import { DEPENDENCY_SECTIONS, type DependencySection } from "../../manifest/package-json.js";
import type { Instance } from "../instances.js";
import type { WorkspaceLayout, WorkspaceMember } from "./types.js";

/** Internal adapter context; constructed only after immutable-tree discovery. */
export class WorkspaceParserContext {
  readonly layout: WorkspaceLayout;
  readonly #catalogDeclarations = new Map<
    string,
    NonNullable<WorkspaceMember["catalogDeclarations"]>[number]
  >();
  readonly #catalogSpecs = new Map<string, string>();
  readonly #dependencyAliases = new Set<string>();
  readonly #peerAliases = new Set<string>();
  constructor(layout: WorkspaceLayout) {
    this.layout = layout;
    for (const member of layout.members) {
      for (const dep of member.catalogDeclarations ?? [])
        this.#catalogDeclarations.set(`${member.path}\0${dep.section}\0${dep.alias}`, dep);
      for (const dep of [...member.manifest.dependencies, ...member.local]) {
        const key = `${member.path}\0${dep.section}\0${dep.alias}`;
        if (this.#catalogDeclarations.has(key)) this.#catalogSpecs.set(key, dep.spec);
        if (dep.section === "dependencies")
          this.#dependencyAliases.add(`${member.path}\0${dep.alias}`);
        if (dep.section === "peerDependencies")
          this.#peerAliases.add(`${member.path}\0${dep.alias}`);
      }
    }
  }
  matchesMembers(paths: readonly string[]): boolean {
    const expected = new Set(this.layout.members.map((member) => member.path));
    return paths.length === expected.size && paths.every((path) => expected.has(path));
  }
  catalogDeclaration(importer: string, section: DependencySection, alias: string) {
    return this.#catalogDeclarations.get(`${importer}\0${section}\0${alias}`);
  }
  overrideSpec(alias: string): string | undefined {
    const overrides = this.layout.pnpmWorkspaceOverrides;
    return overrides !== undefined && Object.hasOwn(overrides, alias)
      ? overrides[alias]
      : undefined;
  }
  importerSpecifier(
    importer: string,
    section: DependencySection,
    alias: string,
    spec: string,
  ): string {
    return (
      this.overrideSpec(alias) ?? this.catalogDeclaration(importer, section, alias)?.spec ?? spec
    );
  }
  resolvedSpec(importer: string, section: DependencySection, alias: string, spec: string): string {
    const declared = this.catalogDeclaration(importer, section, alias);
    if (declared === undefined || declared.spec !== spec) return spec;
    return this.#catalogSpecs.get(`${importer}\0${section}\0${alias}`) ?? spec;
  }
  sourceSection(importer: string, section: DependencySection, alias: string): DependencySection {
    if (section !== "dependencies") return section;
    const key = `${importer}\0${alias}`;
    return !this.#dependencyAliases.has(key) && this.#peerAliases.has(key)
      ? "peerDependencies"
      : section;
  }
  localTarget(
    importer: string,
    section: DependencySection,
    alias: string,
    spec: string,
  ): string | undefined {
    return this.layout.members
      .find((member) => member.path === importer)
      ?.local.find((edge) => edge.section === section && edge.alias === alias && edge.spec === spec)
      ?.target;
  }
}
export function localInstance(member: WorkspaceMember): Instance {
  return {
    id: `workspace:${member.path}`,
    localMember: member.path,
    name: packageNameSchema.parse(member.manifest.name ?? "workspace-root"),
    version: packageVersionSchema.parse(member.manifest.version ?? "0.0.0"),
    integrity: null,
    integrityAlgorithm: null,
    resolved: null,
    bundled: false,
    bundles: [],
    hasInstallScript: null,
    patched: false,
    edges: [],
  };
}
/** Detect stale/missing importer declarations, including dropped sections and alias changes. */
export function memberDeclarationsMatch(
  context: WorkspaceParserContext,
  path: string,
  entry: Partial<
    Record<DependencySection, Readonly<Record<string, string | { specifier: string }>> | undefined>
  >,
  peers: boolean,
): boolean {
  const member = context.layout.members.find((item) => item.path === path);
  if (member === undefined) return false;
  for (const section of DEPENDENCY_SECTIONS) {
    if (!peers && section === "peerDependencies") continue;
    const locked = entry[section] ?? {};
    const declared = [...member.manifest.dependencies, ...member.local].filter(
      (dep) =>
        dep.section === section ||
        (!peers &&
          section === "dependencies" &&
          dep.section === "peerDependencies" &&
          Object.hasOwn(locked, dep.alias) &&
          context.sourceSection(path, section, dep.alias) === "peerDependencies"),
    );
    if (declared.length !== Object.keys(locked).length) return false;
    if (
      declared.some((dep) => {
        const value = locked[dep.alias];
        const spec = typeof value === "string" ? value : value?.specifier;
        return spec !== context.importerSpecifier(path, dep.section, dep.alias, dep.spec);
      })
    )
      return false;
  }
  return true;
}
