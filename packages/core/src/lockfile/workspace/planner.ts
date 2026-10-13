import type { MergeBlockReason, Plan } from "@kovo/contracts";

import { checkManifestAllowlist } from "../../manifest/allowlist.js";
import {
  diffPointers,
  getAtPointer,
  parsePointer,
  pointerOf,
} from "../../manifest/json-pointer.js";
import { classifyDependencySpec, isRegistrySpec } from "../../manifest/dependency-spec.js";
import type { PnpmWorkspaceEdit } from "../../manifest/pnpm-workspace-edits.js";
import { parsePnpmSelector } from "../../manifest/selectors.js";
import { buildGraph } from "../build-graph.js";
import { relockCommand, updateCommand } from "../ladder/commands.js";
import { planLadder, planMajorUpgrade } from "../ladder/planner.js";
import type { RegistryPackage } from "../ladder/registry.js";
import {
  ladderOrder,
  type LadderPlan,
  type LadderTarget,
  type LockfileExpectation,
  type ManifestEdit,
  type PlanRung,
  type PmCommand,
} from "../ladder/types.js";
import {
  GRAPH_LIMITS,
  packageKey,
  type DependencyGraph,
  type PackageKey,
  type ResolvedPackageNode,
} from "../types.js";
import { compareStrings } from "../util.js";
import { importerInstances } from "./parse.js";
import { workspaceCatalogSourceAnchors } from "./catalog-scope.js";
import type { WorkspaceGraph } from "./types.js";

/** Transient trusted plan; member documents never enter durable workflow inputs or evidence. */
export interface WorkspaceManifestPlan {
  readonly importer: string;
  readonly path: string;
  readonly manifestEdits: readonly ManifestEdit[];
  readonly expectedManifest: readonly ManifestEdit[];
  readonly allowedManifestPointers: readonly string[];
}
export interface WorkspaceLadderPlan extends LadderPlan {
  readonly rung: PlanRung;
  readonly kind: LadderPlan["kind"];
  readonly packageManager: LadderPlan["packageManager"];
  readonly target: LadderPlan["target"];
  readonly memberPlans: readonly { readonly importer: string; readonly plan: LadderPlan }[];
  readonly manifests: readonly WorkspaceManifestPlan[];
  readonly workspaceYamlEdits?: readonly PnpmWorkspaceEdit[];
  readonly commands: readonly PmCommand[];
  readonly allowedFiles: readonly string[];
  readonly importerExpectations: readonly {
    readonly importer: string;
    readonly expectation: LockfileExpectation;
  }[];
  readonly workspaceAnchors: readonly { readonly importer: string; readonly name: string }[];
  readonly targetInstances: readonly string[];
  readonly affectedMembers: readonly string[];
  readonly autoMergeEligible: boolean;
  readonly reviewReasons: readonly MergeBlockReason[];
  readonly evidence: LadderPlan["evidence"];
}
export interface WorkspaceLadderInput {
  readonly pmVersion?: string;
  readonly plan: Plan;
  readonly workspace: WorkspaceGraph;
  readonly target: LadderTarget;
  readonly registry: readonly RegistryPackage[];
}
export interface WorkspaceLadderResult {
  readonly plans: readonly WorkspaceLadderPlan[];
  readonly skipped: readonly {
    readonly rung: PlanRung | null;
    readonly reason: string;
    readonly importer: string | null;
  }[];
}

/** Exact path filters, never package-name selectors, globs, shell fragments or recursive filters. */
export function workspaceCommand(command: PmCommand, importer: string): PmCommand {
  if (importer !== "." && !/^[A-Za-z0-9_@-]+(?:\/[A-Za-z0-9_.@-]+)*$/u.test(importer))
    throw new RangeError("invalid workspace command path");
  if (importer !== "." && importer.split("/").some((part) => part === "." || part === ".."))
    throw new RangeError("invalid workspace command path");
  if (command.executable === "yarn") {
    // Yarn manifests are edited by trusted code; relock runs once from the workspace root.
    return command;
  }
  return command.executable === "pnpm"
    ? {
        ...command,
        args: [...(importer === "." ? ["-w"] : ["--filter", `./${importer}`]), ...command.args],
      }
    : {
        ...command,
        args: [...command.args, ...(importer === "." ? [] : [`--workspace=${importer}`])],
      };
}
function editsCombined(edits: readonly ManifestEdit[]): ManifestEdit[] | null {
  const result = new Map<string, ManifestEdit>();
  for (const edit of edits) {
    const prior = result.get(edit.pointer);
    if (prior !== undefined && JSON.stringify(prior) !== JSON.stringify(edit)) return null;
    result.set(edit.pointer, edit);
  }
  return [...result.values()].toSorted((a, b) => compareStrings(a.pointer, b.pointer));
}
const overridePointer = (pointer: string) =>
  pointer.startsWith("/overrides/") ||
  pointer.startsWith("/pnpm/overrides/") ||
  pointer.startsWith("/resolutions/");

/** Combine owning declarations atomically: a local member is never an upgradable registry parent. */
export function planWorkspaceLadder(input: WorkspaceLadderInput): WorkspaceLadderResult {
  const workspace = input.workspace;
  const catalogs = workspace.layout.catalogs !== undefined;
  const catalogAliases = new Set<string>(
    workspace.layout.members.flatMap((member) =>
      (member.catalogDeclarations ?? []).map((entry) => entry.alias),
    ),
  );
  const root = workspace.importers.find((item) => item.member.path === ".");
  if (
    Object.keys(workspace.layout.pnpmWorkspaceOverrides ?? {}).some((selector) => {
      const parsed = parsePnpmSelector(selector);
      return parsed !== null && catalogAliases.has(parsed.target) && selector !== parsed.target;
    })
  )
    return {
      plans: [],
      skipped: [{ rung: null, reason: "catalog_edit_unsupported", importer: null }],
    };
  if (
    root === undefined ||
    !workspace.layout.hasWorkspaces ||
    workspace.importers.some(
      ({ graph }) =>
        graph.unresolved.length > 0 || graph.packages.some((node) => node.pathsTruncated),
    )
  )
    return { plans: [], skipped: [{ rung: null, reason: "incomplete_graph", importer: null }] };
  try {
    for (const item of workspace.importers)
      workspaceCommand({ executable: workspace.layout.packageManager, args: [] }, item.member.path);
  } catch {
    return {
      plans: [],
      skipped: [{ rung: null, reason: "unsupported_command_path", importer: null }],
    };
  }
  const targetInstances = [...workspace.instances.values()]
    .filter(
      (node) =>
        node.localMember === undefined &&
        node.name === input.target.name &&
        input.target.affectedVersions.includes(node.version),
    )
    .map((node) => node.id)
    .toSorted();
  if (targetInstances.length === 0)
    return { plans: [], skipped: [{ rung: null, reason: "target_not_in_graph", importer: null }] };
  const affectedMembers = workspace.importers
    .filter((item) =>
      targetInstances.some((id) => importerInstances(workspace, item.member.path).has(id)),
    )
    .map((item) => item.member.path);
  const registryInstances = new Map(
    [...workspace.instances].filter(([, node]) => node.localMember === undefined),
  );
  const owners = workspace.importers
    .map((item) => {
      const graph = buildGraph(
        {
          packageManager: workspace.layout.packageManager,
          format: item.graph.format,
          instances: registryInstances,
          lockfileOverrides: item.graph.lockfileOverrides,
          root: item.direct.filter(
            (dep) => dep.edge.target === null || registryInstances.has(dep.edge.target),
          ),
        },
        {
          ...GRAPH_LIMITS,
          maxPathWork: Math.floor(GRAPH_LIMITS.maxPathWork / workspace.layout.members.length),
          maxTotalPaths: Math.floor(GRAPH_LIMITS.maxTotalPaths / workspace.layout.members.length),
        },
      );
      // Resolution rules are root-owned; declarations and pins still belong to the actual member.
      const manifest = {
        ...item.member.manifest,
        dependencies: item.member.manifest.dependencies.map((declaration) => {
          const effective =
            catalogs && catalogAliases.has(declaration.alias)
              ? workspace.layout.pnpmWorkspaceOverrides?.[declaration.alias]
              : undefined;
          const source = effective === undefined ? undefined : classifyDependencySpec(effective);
          return source === undefined || !isRegistrySpec(source)
            ? declaration
            : {
                ...declaration,
                spec: effective!,
                name: source.kind === "alias" ? source.name : declaration.alias,
                aliased: source.kind === "alias",
                registrySpec: source.kind === "alias" ? source.target : source,
              };
        }),
        overrides: root.member.manifest.overrides,
        document: {
          ...item.member.manifest.document,
          overrides: root.member.manifest.document["overrides"] ?? {},
          pnpm: root.member.manifest.document["pnpm"] ?? {},
          ...(workspace.layout.packageManager === "yarn"
            ? { resolutions: root.member.manifest.document["resolutions"] ?? {} }
            : {}),
        },
      };
      const ladderInput = {
        ...(input.pmVersion === undefined ? {} : { pmVersion: input.pmVersion }),
        plan: input.plan,
        graph,
        manifest,
        target: input.target,
        registry: input.registry,
      };
      return {
        importer: item.member.path,
        graph,
        result: {
          plans: [...planLadder(ladderInput).plans, ...planMajorUpgrade(ladderInput).plans],
        },
      };
    })
    .filter((item) =>
      item.graph.packages.some((node) => targetInstances.some((id) => node.instances.includes(id))),
    );
  if (
    owners.some(
      (owner) =>
        owner.graph.unresolved.length > 0 ||
        owner.graph.packages.some((node) => node.pathsTruncated),
    )
  )
    return { plans: [], skipped: [{ rung: null, reason: "incomplete_graph", importer: null }] };
  if (
    targetInstances.some(
      (id) =>
        !owners.some((owner) => owner.graph.packages.some((node) => node.instances.includes(id))),
    )
  )
    return {
      plans: [],
      skipped: [{ rung: null, reason: "unowned_target_instance", importer: null }],
    };
  const plans: WorkspaceLadderPlan[] = [];
  const skipped: WorkspaceLadderResult["skipped"][number][] = [];
  const rungs = [
    ...new Set(owners.flatMap((owner) => owner.result.plans.map((plan) => plan.rung))),
  ].toSorted((a, b) => ladderOrder(a) - ladderOrder(b));
  let prior = "";
  for (const rung of rungs) {
    const members: { importer: string; plan: LadderPlan }[] = [];
    for (const owner of owners) {
      const plan = owner.result.plans.findLast(
        (candidate) => ladderOrder(candidate.rung) <= ladderOrder(rung),
      );
      if (plan === undefined) {
        skipped.push({ rung, reason: "member_has_no_safe_plan", importer: owner.importer });
        break;
      }
      members.push({ importer: owner.importer, plan });
    }
    if (members.length !== owners.length) continue;
    const memberEvidence = members.flatMap(({ plan }) =>
      plan.evidence === null ? [] : [plan.evidence],
    );
    if (new Set(memberEvidence.map((item) => item.kind)).size > 1) {
      skipped.push({ rung, reason: "conflicting_rollback_evidence", importer: null });
      continue;
    }
    const firstEvidence = memberEvidence[0];
    const evidence: LadderPlan["evidence"] =
      firstEvidence === undefined
        ? null
        : firstEvidence.kind === "removal"
          ? {
              ...firstEvidence,
              advisoryIds: [
                ...new Set(memberEvidence.flatMap((item) => item.advisoryIds)),
              ].toSorted(),
            }
          : {
              kind: "rollback",
              versions: [
                ...new Map(
                  memberEvidence
                    .flatMap((item) => (item.kind === "rollback" ? item.versions : []))
                    .map((version) => [JSON.stringify(version), version]),
                ).values(),
              ],
              advisoryIds: [
                ...new Set(memberEvidence.flatMap((item) => item.advisoryIds)),
              ].toSorted(),
            };
    // npm's $ reference resolves root dependencies, never child declarations.
    if (
      members.some(
        ({ importer, plan }) =>
          importer !== "." &&
          plan.manifestEdits.some((edit) => edit.op === "set" && edit.value.startsWith("$")),
      )
    ) {
      skipped.push({ rung, reason: "root_override_reference_unavailable", importer: null });
      continue;
    }
    const overrides = editsCombined(
      members.flatMap(({ plan }) =>
        plan.manifestEdits.filter((edit) => overridePointer(edit.pointer)),
      ),
    );
    if (overrides === null) {
      skipped.push({ rung, reason: "conflicting_edits", importer: null });
      continue;
    }
    const manifests: WorkspaceManifestPlan[] = [];
    const yamlEdits: PnpmWorkspaceEdit[] = [];
    let unsupportedYamlEdit = false;
    for (const item of workspace.importers) {
      const member = members.find((entry) => entry.importer === item.member.path);
      const memberEdits: ManifestEdit[] = [];
      const expectedEdits: ManifestEdit[] = [];
      for (const edit of member?.plan.expectedManifest.filter(
        (candidate) => !overridePointer(candidate.pointer),
      ) ?? []) {
        const tokens = parsePointer(edit.pointer);
        const alias = tokens?.length === 2 ? tokens[1] : undefined;
        const declaration = item.member.catalogDeclarations?.find(
          (entry) => entry.alias === alias && entry.section === tokens?.[0],
        );
        const effectiveOverride =
          alias !== undefined &&
          catalogAliases.has(alias) &&
          Object.hasOwn(workspace.layout.pnpmWorkspaceOverrides ?? {}, alias);
        if (declaration !== undefined || effectiveOverride) {
          if (edit.op !== "set" || alias === undefined) {
            unsupportedYamlEdit = true;
            break;
          }
          const pointer = effectiveOverride
            ? pointerOf(["overrides", alias])
            : declaration!.catalog === "default" &&
                Object.hasOwn(workspace.layout.pnpmWorkspaceConfig ?? {}, "catalog")
              ? pointerOf(["catalog", alias])
              : pointerOf(["catalogs", declaration!.catalog, alias]);
          if (getAtPointer(workspace.layout.pnpmWorkspaceConfig ?? {}, pointer) !== edit.value)
            yamlEdits.push({ pointer, value: edit.value });
          // The shared source changes; the member's catalog or ordinary declaration stays intact.
        } else {
          expectedEdits.push(edit);
          if (catalogs) memberEdits.push(edit);
        }
      }
      const manifestEdits = [
        ...(catalogs
          ? memberEdits
          : (member?.plan.manifestEdits.filter((edit) => !overridePointer(edit.pointer)) ?? [])),
        ...(item.member.path === "." ? overrides : []),
      ];
      const expectedManifest = editsCombined([...expectedEdits, ...manifestEdits]);
      if (expectedManifest === null) break;
      manifests.push({
        importer: item.member.path,
        path: item.member.path === "." ? "package.json" : `${item.member.path}/package.json`,
        manifestEdits,
        expectedManifest,
        allowedManifestPointers: expectedManifest.map((edit) => edit.pointer),
      });
    }
    const combinedYaml = editsCombined(
      yamlEdits.map((edit) => ({ op: "set", pointer: edit.pointer, value: edit.value })),
    );
    if (unsupportedYamlEdit || combinedYaml === null) {
      skipped.push({ rung, reason: "catalog_edit_unsupported", importer: null });
      continue;
    }
    const workspaceYamlEdits = combinedYaml.flatMap((edit) =>
      edit.op === "set" ? [{ pointer: edit.pointer, value: edit.value }] : [],
    );
    if (manifests.length !== workspace.importers.length) {
      skipped.push({ rung, reason: "conflicting_edits", importer: null });
      continue;
    }
    const commands = [
      ...(workspaceYamlEdits.length > 0 || manifests.some((item) => item.manifestEdits.length > 0)
        ? [workspaceCommand(relockCommand(workspace.layout.packageManager), ".")]
        : []),
      // npm's workspace lockfile can retain an old transitive resolution after a new root
      // override. A targeted update applies that rule; trusted owner/churn checks still confine it.
      ...(workspace.layout.packageManager === "npm" && overrides.length > 0
        ? [updateCommand("npm", input.target.name)]
        : []),
      ...members.flatMap(({ importer, plan }) =>
        plan.commands
          .filter(
            (command) =>
              workspace.layout.packageManager !== "yarn" &&
              (!catalogs || command.args[0] === "update") &&
              !(command.args[0] === "install" && command.args[1]?.startsWith("--")),
          )
          .map((command) => workspaceCommand(command, importer)),
      ),
    ];
    const signature = JSON.stringify({ manifests, workspaceYamlEdits, commands });
    if (signature === prior) continue;
    prior = signature;
    const top = members.find((member) => member.plan.rung === rung)?.plan ?? members[0]?.plan;
    if (top === undefined) continue;
    const expectations = workspace.importers.flatMap((item) => [
      ...input.target.affectedVersions.map((version) => ({
        importer: item.member.path,
        expectation: { kind: "version_absent" as const, name: input.target.name, version },
      })),
      ...(
        members.find((entry) => entry.importer === item.member.path)?.plan.expectations ?? []
      ).map((expectation) => ({ importer: item.member.path, expectation })),
    ]);
    const workspaceAnchors: { importer: string; name: string }[] = members.flatMap(
      ({ importer, plan }) => {
        const owner = owners.find((entry) => entry.importer === importer);
        return plan.anchors.flatMap((name) => {
          const instances = new Set(
            owner?.graph.packages
              .filter((node) => node.name === name)
              .flatMap((node) => node.instances) ?? [],
          );
          return workspace.importers
            .filter((item) =>
              [...importerInstances(workspace, item.member.path)].some((id) => instances.has(id)),
            )
            .map((item) => ({ importer: item.member.path, name }));
        });
      },
    );
    workspaceAnchors.push(
      ...workspaceCatalogSourceAnchors(
        workspace,
        workspaceYamlEdits.map((edit) => edit.pointer),
      ),
    );
    if (overrides.length > 0 || workspaceYamlEdits.length > 0)
      workspaceAnchors.push({ importer: ".", name: input.target.name });
    plans.push({
      rung,
      kind: top.kind,
      packageManager: workspace.layout.packageManager,
      target: input.target.name,
      memberPlans: members,
      manifests,
      ...(workspaceYamlEdits.length === 0 ? {} : { workspaceYamlEdits }),
      commands,
      allowedFiles: [
        workspace.layout.packageManager === "npm"
          ? "package-lock.json"
          : workspace.layout.packageManager === "yarn"
            ? "yarn.lock"
            : "pnpm-lock.yaml",
        ...manifests
          .filter((item) => item.allowedManifestPointers.length > 0)
          .map((item) => item.path),
        ...(workspaceYamlEdits.length > 0 ? ["pnpm-workspace.yaml"] : []),
      ],
      steps: members.flatMap(({ plan }) => plan.steps),
      manifestEdits: [],
      expectedManifest: [],
      allowedManifestPointers: [],
      expectations: input.target.affectedVersions.map((version) => ({
        kind: "version_absent" as const,
        name: input.target.name,
        version,
      })),
      anchors: [...new Set(members.flatMap(({ plan }) => plan.anchors))],
      importerExpectations: expectations,
      workspaceAnchors: [
        ...new Map(workspaceAnchors.map((anchor) => [JSON.stringify(anchor), anchor])).values(),
      ],
      targetInstances,
      affectedMembers: [
        ...new Set([...affectedMembers, ...workspaceAnchors.map((anchor) => anchor.importer)]),
      ].toSorted(),
      autoMergeEligible: members.every(({ plan }) => plan.autoMergeEligible),
      reviewReasons: [...new Set(members.flatMap(({ plan }) => plan.reviewReasons))],
      evidence,
    });
  }
  return { plans, skipped };
}

/** All member documents are checked, including unchanged siblings and protected root fields. */
export function checkWorkspacePlannedManifests(
  plan: WorkspaceLadderPlan,
  before: WorkspaceGraph,
  after: WorkspaceGraph,
): boolean {
  if (
    before.importers.length !== after.importers.length ||
    (plan.workspaceYamlEdits === undefined &&
      before.layout.workspaceConfigOid !== after.layout.workspaceConfigOid)
  )
    return false;
  if (plan.workspaceYamlEdits !== undefined) {
    const base = before.layout.pnpmWorkspaceConfig;
    const head = after.layout.pnpmWorkspaceConfig;
    if (
      base === undefined ||
      head === undefined ||
      diffPointers(base, head).some(
        (pointer) => !plan.workspaceYamlEdits!.some((edit) => edit.pointer === pointer),
      ) ||
      !plan.workspaceYamlEdits.every((edit) => getAtPointer(head, edit.pointer) === edit.value)
    )
      return false;
  }
  return before.importers.every((base) => {
    const head = after.importers.find((item) => item.member.path === base.member.path);
    const expected = plan.manifests.find((item) => item.importer === base.member.path);
    if (head === undefined || expected === undefined) return false;
    if (
      checkManifestAllowlist(
        base.member.manifest.document,
        head.member.manifest.document,
        expected.allowedManifestPointers,
      ).violations.length > 0
    )
      return false;
    return expected.expectedManifest.every(
      (edit) =>
        getAtPointer(head.member.manifest.document, edit.pointer) ===
        (edit.op === "set" ? edit.value : undefined),
    );
  });
}
export function workspaceExpectationsSatisfied(
  plan: WorkspaceLadderPlan,
  after: WorkspaceGraph,
): boolean {
  return plan.importerExpectations.every(({ importer, expectation }) => {
    const graph = after.importers.find((item) => item.member.path === importer)?.graph;
    if (
      graph === undefined ||
      graph.unresolved.length > 0 ||
      graph.packages.some((node) => node.pathsTruncated)
    )
      return false;
    const versions = graph.packages
      .filter((node) => node.name === expectation.name)
      .map((node) => node.version);
    switch (expectation.kind) {
      case "package_absent":
        return versions.length === 0;
      case "version_absent":
        return !versions.includes(expectation.version);
      case "versions_within":
        return versions.every((version) => expectation.allowed.includes(version));
      case "direct_resolves_to": {
        const direct = graph.direct.filter((dep) => dep.alias === expectation.alias);
        return (
          direct.length > 0 &&
          direct.every((dep) => dep.target === packageKey(expectation.name, expectation.version))
        );
      }
      default:
        return false;
    }
  });
}

/** Registry aggregate for advisory/capability/provenance only; never an ownership/churn proof. */
export function aggregateWorkspaceGraph(workspace: WorkspaceGraph): DependencyGraph {
  const root = workspace.importers.find((item) => item.member.path === ".")?.graph;
  if (root === undefined) throw new RangeError("workspace root missing");
  const nodes = new Map<PackageKey, ResolvedPackageNode>();
  for (const { graph } of workspace.importers)
    for (const node of graph.packages) {
      const prior = nodes.get(node.key);
      if (prior === undefined) {
        nodes.set(node.key, node);
        continue;
      }
      if (
        (prior.integrity !== null &&
          node.integrity !== null &&
          prior.integrity !== node.integrity) ||
        (prior.resolved !== null && node.resolved !== null && prior.resolved !== node.resolved)
      )
        throw new RangeError("workspace artifact metadata conflict");
      const paths = [
        ...new Map(
          [...prior.paths, ...node.paths].map((path) => [JSON.stringify(path), path]),
        ).values(),
      ];
      const dependencies = [
        ...new Map(
          [...prior.dependencies, ...node.dependencies].map((edge) => [JSON.stringify(edge), edge]),
        ).values(),
      ];
      nodes.set(node.key, {
        ...prior,
        integrity: prior.integrity ?? node.integrity,
        integrityAlgorithm:
          prior.integrity !== null
            ? prior.integrityAlgorithm
            : node.integrity !== null
              ? node.integrityAlgorithm
              : (prior.integrityAlgorithm ?? node.integrityAlgorithm),
        resolved: prior.resolved ?? node.resolved,
        bundled: prior.bundled && node.bundled,
        patched: prior.patched || node.patched,
        hasInstallScript:
          prior.hasInstallScript === true || node.hasInstallScript === true
            ? true
            : prior.hasInstallScript === null || node.hasInstallScript === null
              ? null
              : false,
        bundles: [...new Set([...prior.bundles, ...node.bundles])].toSorted(),
        isDirect: prior.isDirect || node.isDirect,
        isDev: prior.isDev && node.isDev,
        isOptional: prior.isOptional && node.isOptional,
        pathsTruncated: prior.pathsTruncated || node.pathsTruncated,
        instances: [...new Set([...prior.instances, ...node.instances])].toSorted(),
        paths,
        dependencies,
      });
    }
  return {
    ...root,
    packages: [...nodes.values()].toSorted((a, b) => compareStrings(a.key, b.key)),
    direct: workspace.importers.flatMap((item) => item.graph.direct),
    unresolved: workspace.importers.flatMap((item) => item.graph.unresolved),
  };
}
