import { pointerOf } from "../../manifest/json-pointer.js";
import { classifyDependencySpec, isRegistrySpec } from "../../manifest/dependency-spec.js";
import { importerInstances } from "./parse.js";
import type { WorkspaceGraph } from "./types.js";

export interface WorkspaceAnchor {
  readonly importer: string;
  readonly name: string;
}

/** Existing shared sources and their direct consumers, using effective override precedence. */
function sources(workspace: WorkspaceGraph) {
  if (workspace.layout.catalogs === undefined) return [];
  const catalogAliases = new Set(
    workspace.layout.members.flatMap((member) =>
      (member.catalogDeclarations ?? []).map((entry) => entry.alias),
    ),
  );
  return workspace.importers.flatMap((importer) => {
    const declarations = new Map(
      (importer.member.catalogDeclarations ?? []).map((entry) => [
        `${entry.section}\0${entry.alias}`,
        entry,
      ]),
    );
    const directByDeclaration = new Map(
      importer.direct.map((entry) => [`${entry.section}\0${entry.alias}`, entry]),
    );
    return importer.member.manifest.dependencies.flatMap((dependency) => {
      const key = `${dependency.section}\0${dependency.alias}`;
      const declaration = declarations.get(key);
      const override =
        catalogAliases.has(dependency.alias) &&
        Object.hasOwn(workspace.layout.pnpmWorkspaceOverrides ?? {}, dependency.alias);
      if (!override && declaration === undefined) return [];
      const pointer = override
        ? pointerOf(["overrides", dependency.alias])
        : declaration!.catalog === "default" &&
            Object.hasOwn(workspace.layout.pnpmWorkspaceConfig ?? {}, "catalog")
          ? pointerOf(["catalog", dependency.alias])
          : pointerOf(["catalogs", declaration!.catalog, dependency.alias]);
      const direct = directByDeclaration.get(key);
      const effective = override
        ? classifyDependencySpec(workspace.layout.pnpmWorkspaceOverrides![dependency.alias]!)
        : dependency.registrySpec;
      if (!isRegistrySpec(effective)) return [];
      const sourceName = override
        ? effective.kind === "alias"
          ? effective.name
          : dependency.alias
        : dependency.name;
      const name =
        direct?.edge.target == null
          ? sourceName
          : (workspace.instances.get(direct.edge.target)?.name ?? sourceName);
      return [{ pointer, importer: importer.member.path, name: String(name) }];
    });
  });
}

/** Only sources already belonging to a targeted importer closure can authorize a YAML edit. */
export function workspaceCatalogSourcePointers(
  workspace: WorkspaceGraph,
  anchors: readonly WorkspaceAnchor[],
): readonly string[] {
  const owners = new Set(anchors.map((anchor) => `${anchor.importer}\0${anchor.name}`));
  return [
    ...new Set(
      sources(workspace)
        .filter((source) => owners.has(`${source.importer}\0${source.name}`))
        .map((source) => source.pointer),
    ),
  ].toSorted();
}

/** Every reference shares the source, even when its locked instance was already safe/absent. */
export function workspaceCatalogSourceAnchors(
  workspace: WorkspaceGraph,
  pointers: readonly string[],
): readonly WorkspaceAnchor[] {
  if (pointers.length === 0) return [];
  const selected = new Set(pointers);
  const localIdsByMember = new Map<string, Set<string>>();
  for (const instance of workspace.instances.values()) {
    if (instance.localMember === undefined) continue;
    const ids = localIdsByMember.get(instance.localMember) ?? new Set<string>();
    ids.add(instance.id);
    localIdsByMember.set(instance.localMember, ids);
  }
  const reachableByMember = new Map<string, ReadonlySet<string>>();
  const reaches = (importer: string, localIds: ReadonlySet<string>) => {
    if (localIds.size === 0) return false;
    let reachable = reachableByMember.get(importer);
    if (reachable === undefined) {
      reachable = importerInstances(workspace, importer);
      reachableByMember.set(importer, reachable);
    }
    return [...localIds].some((id) => reachable.has(id));
  };
  const anchors = sources(workspace)
    .filter((source) => selected.has(source.pointer))
    .flatMap((source) => {
      const localIds = localIdsByMember.get(source.importer) ?? new Set<string>();
      return workspace.importers
        .filter(
          (importer) =>
            importer.member.path === source.importer || reaches(importer.member.path, localIds),
        )
        .map((importer) => ({ importer: importer.member.path, name: source.name }));
    });
  return [...new Map(anchors.map((anchor) => [JSON.stringify(anchor), anchor])).values()];
}
