import { z } from "zod";
import {
  UNSUPPORTED_REPO_REASONS,
  type LockfileFormat,
  type UnsupportedRepoReason,
} from "@kovo/contracts";

import { GlobWorkExceeded } from "../../manifest/glob.js";
import {
  checkNpmrc,
  checkNpmrcFixOnly,
  checkPnpmNpmrcSettings,
  type NpmrcFixOnlyResult,
} from "../../manifest/npmrc.js";
import { npmrcKeyName, tokenizeNpmrc } from "../../manifest/npmrc-tokens.js";
import { parsePackageJson } from "../../manifest/package-json.js";
import { resolveRuntime, runtimeCatalogSchema, runtimeDeclarationsOf } from "../compat.js";
import {
  dependencyIgnoreMatches,
  dependencyWorkspaceMember,
  dependencyWorkspacePatterns,
  parseDependencyIgnoreConfig,
} from "../dependency-ignore.js";
import { detectPackageManager, FOREIGN_LOCKFILES, YARN_BERRY_MARKERS } from "../detect.js";
import { admitPackageManagerChoice, withChosenPackageManager } from "../package-manager-choice.js";
import { LOCKFILE_NAMES, parseLockfile } from "../parse.js";
import { privateRegistryAdmission } from "../private-registry.js";
import { GRAPH_LIMITS, isVerifiableGraph } from "../types.js";
import { canonicalWorkspacePath, discoverWorkspaces } from "../workspace/discover.js";
import { parseWorkspaceGraph, workspaceRuntimeCompatible } from "../workspace/parse.js";
import { WORKSPACE_LIMITS, type WorkspaceTreeEntry } from "../workspace/types.js";
import { relativeToRoot, rootFileOwnership, withinTree } from "./ownership.js";
import {
  DISCOVERY_LIMITS,
  type DiscoveryLimits,
  type InstallRoot,
  type InstallRootDiscoveryInput,
  type InstallRootDiscoveryResult,
  type RefusedCandidate,
  type RootRegistryIntegrityNeed,
} from "./types.js";

const entrySchema = z.strictObject({
  path: z.string().min(1).max(1024),
  mode: z.enum(["file", "directory", "symlink", "submodule"]),
  oid: z.string().regex(/^(?:[a-f0-9]{40}|[a-f0-9]{64})$/u),
  text: z.string().exactOptional(),
});
const MARKERS = new Set<string>([
  "package.json",
  ...Object.values(LOCKFILE_NAMES),
  ...Object.keys(FOREIGN_LOCKFILES),
  "pnpm-workspace.yaml",
  ...YARN_BERRY_MARKERS,
  ".yarnrc",
  "bunfig.toml",
]);
const PARSED_FILES = new Set([...MARKERS, ".npmrc", ".nvmrc", ".node-version", ".tool-versions"]);
function holdsLockfile(names: readonly string[]): boolean {
  return names.some(
    (name) =>
      Object.values(LOCKFILE_NAMES).some((lock) => lock === name) ||
      Object.hasOwn(FOREIGN_LOCKFILES, name),
  );
}
function collisionKey(path: string): string {
  return path.normalize("NFKC").toUpperCase().toLowerCase();
}

function directoryOf(path: string): string {
  const separator = path.lastIndexOf("/");
  return separator < 0 ? "." : path.slice(0, separator);
}
function basename(path: string): string {
  return path.slice(path.lastIndexOf("/") + 1);
}
function workspaceNpmrc(text: string): boolean {
  const tokens = tokenizeNpmrc(text);
  return !tokens.ok || tokens.entries.some(({ key }) => /workspace/u.test(npmrcKeyName(key)));
}
function ancestorPaths(path: string): string[] {
  const parts = path.split("/");
  return parts.map((_, index) => parts.slice(0, index + 1).join("/"));
}
function depth(path: string): number {
  return path === "." ? 0 : path.split("/").length;
}
function fail(
  reason: Extract<InstallRootDiscoveryResult, { ok: false }>["reason"],
  refusals: readonly RefusedCandidate[] = [],
): InstallRootDiscoveryResult {
  return { ok: false, reason, refusals };
}

/**
 * Pure M2 discovery. No I/O or clock reads; deterministic input/work budgets bound aggregate
 * parsing cost. Results, including manifests/layouts, are transient and never persistence proof.
 * M3 counts classified apps (and library bundles); M2 enforces the necessary 100-root floor.
 */
export function discoverInstallRoots(
  input: InstallRootDiscoveryInput,
  limits: DiscoveryLimits = DISCOVERY_LIMITS,
): InstallRootDiscoveryResult {
  if (!z.literal(true).safeParse(input.treeComplete).success) return fail("incomplete_tree");
  if (input.entries.length > limits.maxTreeEntries) return fail("too_large");
  if (
    input.baseIgnore === null ||
    parseDependencyIgnoreConfig(JSON.stringify({ dependencies: { ignore: input.baseIgnore } })) ===
      null
  )
    return fail("invalid_ignore_config");
  if (!runtimeCatalogSchema.safeParse(input.catalog).success) return fail("runtime_mismatch");
  const work = { remaining: limits.maxWork };
  // A recorded two-lockfile choice (#5500) applies to the repository root only, and only when it
  // really commits both npm and pnpm lockfiles: the other root lockfile is then not an input.
  const choice = admitPackageManagerChoice(
    input.entries.flatMap((entry) =>
      entry.mode === "file" && !entry.path.includes("/") ? [entry.path] : [],
    ),
    input.packageManagerChoice ?? { kind: "absent" },
  );
  const inputEntries = choice.honoured
    ? input.entries.filter((entry) => entry.path !== choice.ignoredLockfile)
    : input.entries;
  try {
    const entries: WorkspaceTreeEntry[] = [];
    const seen = new Map<string, WorkspaceTreeEntry>();
    let pathBytes = 0;
    for (const raw of inputEntries) {
      const parsed = entrySchema.safeParse(raw);
      if (!parsed.success) return fail("invalid_path");
      const entry = parsed.data;
      const segments = entry.path.split("/");
      if (
        entry.path.startsWith("/") ||
        segments.some((part) => !part || part === "." || part === "..")
      )
        return fail("invalid_path");
      pathBytes += entry.path.length * 3;
      // Ancestor construction and normalization below cost quadratically with path depth.
      work.remaining -= segments.length * entry.path.length;
      if (pathBytes > limits.maxTreePathBytes || work.remaining < 0) return fail("too_large");
      if (seen.has(entry.path)) return fail("identity_collision");
      seen.set(entry.path, entry);
    }
    // Links and gitlinks are never followed, including hostile supplied descendants.
    const ignored = new Set<string>();
    const identities = new Map<string, string>();
    const collisions = new Set<string>();
    for (const entry of seen.values()) {
      if (
        entry.path.split("/").some((part) => ["node_modules", ".git"].includes(part.toLowerCase()))
      )
        continue;
      const ancestors = ancestorPaths(entry.path);
      if (
        ancestors.some((path) => {
          const mode = seen.get(path)?.mode;
          return mode === "symlink" || mode === "submodule";
        })
      )
        continue;
      for (const ancestor of ancestors.slice(0, -1)) {
        const parent = seen.get(ancestor);
        if (parent !== undefined && parent.mode !== "directory") return fail("unsafe_tree_entry");
      }
      const ignoredAncestor = ancestors.find((path) => {
        if (ignored.has(path)) return true;
        if (input.baseIgnore?.some((pattern) => dependencyIgnoreMatches(pattern, path, work))) {
          ignored.add(path);
          return true;
        }
        return false;
      });
      if (ignoredAncestor !== undefined) continue;
      for (const ancestor of ancestors) {
        const key = collisionKey(ancestor);
        const prior = identities.get(key);
        if (prior !== undefined && prior !== ancestor) collisions.add(key);
        identities.set(key, ancestor);
      }
      entries.push(entry);
    }
    entries.sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0));
    const candidates = new Map<string, string[]>();
    let manifestBytes = 0;
    let parseBytes = 0;
    for (const entry of entries) {
      if (entry.mode !== "file") continue;
      const name = basename(entry.path);
      if (PARSED_FILES.has(name)) {
        // Foreign binary markers need names only; supported parsers need immutable full reads.
        if (
          entry.text === undefined &&
          (name === "package.json" ||
            name === "pnpm-workspace.yaml" ||
            Object.values(LOCKFILE_NAMES).some((lock) => lock === name) ||
            [".npmrc", ".nvmrc", ".node-version", ".tool-versions"].includes(name))
        )
          return fail("incomplete_tree");
        parseBytes += (entry.text?.length ?? 0) * 3;
        if (name === "package.json") manifestBytes += (entry.text?.length ?? 0) * 3;
        if (manifestBytes > limits.maxManifestBytes || parseBytes > limits.maxParseBytes)
          return fail("too_large");
      }
      if (!MARKERS.has(name) && !(name === ".npmrc" && workspaceNpmrc(entry.text ?? ""))) continue;
      const path = directoryOf(entry.path);
      if (!canonicalWorkspacePath(path, true)) return fail("invalid_path");
      // Only dependency identities and their ancestors must be collision-free. Ordinary
      // source/fixture names retain workspace discovery's case-sensitive Git semantics.
      if (ancestorPaths(entry.path).some((ancestor) => collisions.has(collisionKey(ancestor))))
        return fail("identity_collision");
      if (holdsLockfile([name]) && depth(path) > limits.maxCandidateDepth) return fail("too_large");
      const files = candidates.get(path) ?? [];
      files.push(name);
      candidates.set(path, files);
    }
    const paths = [...candidates.keys()].toSorted((a, b) => {
      return depth(a) - depth(b) || (a < b ? -1 : a > b ? 1 : 0);
    });
    const roots: InstallRoot[] = [];
    const refusals: RefusedCandidate[] = [];
    const needs: RootRegistryIntegrityNeed[] = [];
    const withNeeds = () => (needs.length === 0 ? {} : { registryIntegrityNeeds: needs });
    const consumed = new Set<string>();
    let edges = 0;
    const lockCharacters = entries.reduce(
      (total, entry) =>
        total +
        (Object.values(LOCKFILE_NAMES).some((name) => basename(entry.path) === name)
          ? (entry.text?.length ?? 0)
          : 0),
      0,
    );
    for (const path of paths) {
      if (consumed.has(path)) continue;
      const names = candidates.get(path) ?? [];
      // A lockfile-less manifest/settings directory belongs to its containing install root,
      // including undeclared manifests inside workspace members. Outside roots it is refused.
      if (!holdsLockfile(names) && roots.some((root) => withinTree(path, root.path))) continue;
      const detection = detectPackageManager(names);
      if (!detection.ok) {
        refusals.push({ path, reason: detection.unsupported });
        continue;
      }
      work.remaining -= entries.length * 2 + paths.length;
      if (work.remaining < 0) return fail("too_large", refusals);
      const subtree = entries
        .filter((entry) => entry.path !== path && withinTree(entry.path, path))
        .map((entry) => Object.assign({}, entry, { path: relativeToRoot(entry.path, path) }));
      const byPath = new Map(subtree.map((entry) => [entry.path, entry]));
      const manifest = byPath.get("package.json")?.text;
      const lock = byPath.get(detection.lockfileName)?.text;
      if (manifest === undefined || lock === undefined) return fail("incomplete_tree", refusals);
      const yaml = byPath.get("pnpm-workspace.yaml")?.text;
      const declared = dependencyWorkspacePatterns(
        detection.packageManager === "pnpm" ? (yaml ?? "{}") : manifest,
        detection.packageManager === "pnpm" ? "pnpm-workspace.yaml" : "package.json",
      );
      // A single-package manifest keeps its existing coarse reasons; workspace discovery
      // intentionally has a separate detailed vocabulary for member/layout failures.
      if (declared !== null && !declared.some((pattern) => !pattern.startsWith("!"))) {
        const parsedManifest = parsePackageJson({
          text: manifest,
          packageManager: detection.packageManager,
          pnpmWorkspaceYamlPresent: yaml !== undefined,
          ...(yaml === undefined ? {} : { pnpmWorkspaceYaml: yaml }),
        });
        if (!parsedManifest.ok) {
          refusals.push({ path, reason: parsedManifest.unsupported });
          continue;
        }
      }
      // D-726 fix-only: the repository's own single-package npm root may name private registries
      // for some scopes; every other root keeps the public-registry-only rule.
      const fixOnlyRoot = path === "." && declared === null && detection.packageManager === "npm";
      const npmrcOf = (text: string | null): NpmrcFixOnlyResult => {
        if (fixOnlyRoot) return checkNpmrcFixOnly(text);
        const strict = checkNpmrc(text);
        return strict.ok ? { ok: true, privateScopes: [] } : strict;
      };
      const rootNpmrc = npmrcOf(byPath.get(".npmrc")?.text ?? null);
      if (!rootNpmrc.ok) {
        refusals.push({ path, reason: rootNpmrc.unsupported });
        continue;
      }
      const childPaths = paths.filter((child) => child !== path && withinTree(child, path));
      const nested =
        declared === null
          ? []
          : childPaths.filter(
              (child) =>
                holdsLockfile(candidates.get(child) ?? []) &&
                !dependencyWorkspaceMember(declared, relativeToRoot(child, path), work),
            );
      work.remaining -= subtree.length * (nested.length + 1);
      if (work.remaining < 0) return fail("too_large", refusals);
      // Subtract undeclared lockfile roots before discovery: they must never poison or belong to
      // the outer root. Declared members keep their lockfiles, so the existing conflict gate fires.
      const rootEntries = subtree.filter(
        (entry) => !nested.some((child) => withinTree(entry.path, relativeToRoot(child, path))),
      );
      const workspaceInput = {
        packageManager: detection.packageManager,
        treeComplete: true,
        entries: rootEntries,
      };
      // Partition graph and workspace parse work across all immutable inputs rather than
      // allowing every root to spend a new full repository budget. Nested/refused inputs
      // retain their share, which is conservative and deterministic.
      const graphLimits = {
        ...GRAPH_LIMITS,
        maxPathWork: Math.min(
          GRAPH_LIMITS.maxPathWork,
          Math.floor((limits.maxGraphWork * lock.length) / Math.max(1, lockCharacters)),
        ),
      };
      const workspaceLimits = {
        ...WORKSPACE_LIMITS,
        maxGlobWork: Math.min(
          WORKSPACE_LIMITS.maxGlobWork,
          Math.floor((limits.maxWork * rootEntries.length) / Math.max(1, entries.length) / 2),
        ),
        maxProjectionWork: graphLimits.maxPathWork,
      };
      const discovered = discoverWorkspaces(workspaceInput, workspaceLimits);
      if (!discovered.ok) {
        refusals.push({
          path,
          reason:
            discovered.reason === "invalid_manifest" && declared === null
              ? "invalid_package_json"
              : discovered.reason,
        });
        if (discovered.reason === "conflicting_lockfile") {
          for (const child of childPaths) {
            if (nested.includes(child)) continue;
            const childNames = candidates.get(child) ?? [];
            if (
              childNames.some(
                (name) =>
                  Object.values(LOCKFILE_NAMES).some((lockName) => lockName === name) ||
                  Object.hasOwn(FOREIGN_LOCKFILES, name),
              )
            ) {
              refusals.push({ path: child, reason: "conflicting_lockfile" });
              consumed.add(child);
            }
          }
        }
        continue;
      }
      const layout = discovered.value;
      let format: LockfileFormat | undefined;
      let graphEdges = layout.members.reduce((count, member) => count + member.local.length, 0);
      if (layout.hasWorkspaces) {
        const graph = parseWorkspaceGraph(
          workspaceInput,
          { fileName: detection.lockfileName, text: lock },
          workspaceLimits,
          graphLimits,
          // Only this root's own registry-sourced integrity (#7338), never another root's.
          input.registryIntegrity?.get(path),
        );
        if (!graph.ok) {
          refusals.push({ path, reason: graph.reason });
          // A refusal registry-sourced integrity could lift, when this root had no values yet.
          if (
            graph.registryIntegrityCandidates !== undefined &&
            input.registryIntegrity?.has(path) !== true
          )
            needs.push({
              path,
              candidates: graph.registryIntegrityCandidates,
              // The root `.npmrc` passed `checkNpmrc` above; every nested one must pass it too,
              // and one that was not read counts as unknown, which is not public.
              publicRegistry: rootEntries.every(
                (entry) =>
                  !entry.path.endsWith("/.npmrc") ||
                  (entry.mode === "file" && entry.text !== undefined && checkNpmrc(entry.text).ok),
              ),
            });
          continue;
        }
        const importerGraph = graph.value.importers[0]?.graph;
        format =
          importerGraph !== undefined && isVerifiableGraph(importerGraph)
            ? importerGraph.format
            : undefined;
        graphEdges += [...graph.value.instances.values()].reduce(
          (count, instance) => count + instance.edges.length,
          0,
        );
      } else {
        const parsedManifest = parsePackageJson({
          text: manifest,
          packageManager: detection.packageManager,
          pnpmWorkspaceYamlPresent: yaml !== undefined,
          ...(yaml === undefined ? {} : { pnpmWorkspaceYaml: yaml }),
        });
        if (!parsedManifest.ok) {
          refusals.push({ path, reason: parsedManifest.unsupported });
          continue;
        }
        const parsedLock = parseLockfile(
          {
            fileName: detection.lockfileName,
            text: lock,
            manifest: parsedManifest.manifest,
          },
          graphLimits,
        );
        if (!parsedLock.ok) {
          refusals.push({ path, reason: parsedLock.unsupported });
          continue;
        }
        // Discovery never parses the fix-only formats (no `fixOnly`): install roots stay verifiable.
        if (!isVerifiableGraph(parsedLock.graph)) {
          refusals.push({ path, reason: "unsupported_package_manager" });
          continue;
        }
        // D-726: a package locked at a private registry needs its scope declared private in this
        // root's `.npmrc` (and fix-only covers npm and pnpm only).
        if (
          privateRegistryAdmission(
            parsedLock.graph,
            rootNpmrc.privateScopes,
            detection.packageManager,
          ) !== null
        ) {
          refusals.push({ path, reason: "private_registry" });
          continue;
        }
        format = parsedLock.graph.format;
        graphEdges +=
          parsedLock.graph.direct.length +
          // Legacy graphs collapse equal registry identities. Count the union for every
          // install instance as a conservative upper bound, never just once per name/version.
          parsedLock.graph.packages.reduce(
            (count, node) => count + node.dependencies.length * node.instances.length,
            0,
          );
      }
      edges += graphEdges;
      if (edges > limits.maxGraphEdges) return fail("too_large", refusals);
      const rootManifest = layout.members.find((member) => member.path === ".")?.manifest;
      if (rootManifest === undefined || format === undefined)
        return fail("incomplete_graph", refusals);
      // A complete graph establishes ownership even when runtime/settings admission refuses
      // its root. Its members must not become spurious lockfile-less install roots.
      for (const member of layout.members) {
        if (member.path !== ".")
          consumed.add(path === "." ? member.path : `${path}/${member.path}`);
      }
      const rootFile = (name: string) => byPath.get(name)?.text ?? null;
      const runtime = resolveRuntime({
        declarations: withChosenPackageManager(
          runtimeDeclarationsOf(rootManifest, {
            nvmrc: rootFile(".nvmrc"),
            nodeVersionFile: rootFile(".node-version"),
            toolVersions: rootFile(".tool-versions"),
          }),
          path === "." && choice.honoured ? choice.declaration : undefined,
        ),
        packageManager: detection.packageManager,
        lockfileFormat: format,
        catalog: input.catalog,
        pnpmSettingsOnly: yaml !== undefined && !layout.hasWorkspaces,
      });
      if (!runtime.ok) {
        refusals.push({ path, reason: runtime.unsupported });
        continue;
      }
      if (!workspaceRuntimeCompatible(layout, runtime.runtime)) {
        refusals.push({ path, reason: "runtime_mismatch" });
        continue;
      }
      const npmrc = npmrcOf(rootFile(".npmrc"));
      const settings =
        detection.packageManager === "pnpm"
          ? checkPnpmNpmrcSettings(rootFile(".npmrc"), runtime.runtime.pmVersion)
          : ({ ok: true } as const);
      if (!npmrc.ok || !settings.ok) {
        refusals.push({
          path,
          reason: !npmrc.ok
            ? npmrc.unsupported
            : !settings.ok
              ? settings.unsupported
              : "private_registry",
        });
        continue;
      }
      roots.push({
        path,
        lockfileName: detection.lockfileName,
        layout,
        excludedTrees: nested,
        files: rootFileOwnership(path, layout, detection.lockfileName, entries, nested, work),
      });
      if (roots.length > limits.maxRoots) return fail("too_many_projects", refusals);
      for (const child of nested) {
        refusals.push({ path: child, reason: "nested_project" });
        consumed.add(child);
      }
    }
    if (roots.length === 0) {
      const rootNames = candidates.get(".") ?? [];
      const detection = detectPackageManager(rootNames);
      const reason = detection.ok
        ? (refusals[0]?.reason ?? "missing_package_json")
        : detection.unsupported;
      // Preserve the existing root-level detection priority when no supported roots remain.
      if (!detection.ok && rootNames.includes("pnpm-workspace.yaml"))
        return {
          ok: false,
          reason: "workspaces",
          refusals,
          refusalsComplete: true,
          ...withNeeds(),
        };
      const repositoryReason = UNSUPPORTED_REPO_REASONS.find((known) => known === reason);
      const coarse: UnsupportedRepoReason =
        repositoryReason ?? (reason === "resource_limit" ? "too_large" : "workspaces");
      return { ok: false, reason: coarse, refusals, refusalsComplete: true, ...withNeeds() };
    }
    return { ok: true, roots, refusals, ...withNeeds() };
  } catch (error) {
    if (error instanceof GlobWorkExceeded) return fail("too_large");
    throw error;
  }
}
