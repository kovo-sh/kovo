import {
  DEPENDENCY_IGNORE_CONFIG_MAX_BYTES,
  LOCKFILE_MAX_BYTES,
  dependencyIgnoreMatches,
  dependencyWorkspacePatterns,
  discoverDirectories,
  discoverGateScope,
  detectPackageManager,
  gateScopeGraphs,
  isDependencyLockfile,
  parseDependencyIgnoreConfig,
  protectedGateLockfile,
  type ListedEntry,
  type GateRootScope,
  type WorkspaceTreeEntry,
} from "@kovo/core/lockfile";
import { PACKAGE_JSON_LIMITS } from "@kovo/core/manifest";

import { usageError } from "../errors.js";
import type { CliIo } from "../io.js";
import type { ExitCode } from "../exit.js";
import type { DepsCheckOptions, Judge } from "./check.js";
import { changeListOf, snapshotGraph } from "./change-list.js";
import {
  blobOid,
  CommitReader,
  defaultBase,
  resolveCommit,
  WorkingTreeReader,
  type ProjectReader,
} from "./git.js";
import { renderJson, renderText, verdictExitCode, type CheckReport } from "./report.js";

const AUTHORITY =
  /(?:^|\/)(?:package\.json|pnpm-workspace\.yaml|\.npmrc|\.nvmrc|\.node-version|\.tool-versions)$/u;
const VENDORED = /(?:^|\/)(?:node_modules|\.git)(?:\/|$)/iu;
const decoder = new TextDecoder("utf-8", { fatal: true });

/** Read only authority files, under one aggregate budget; source files are names/OIDs only. */
async function tree(
  reader: ProjectReader,
  patterns: readonly string[],
  work: { remaining: number },
): Promise<readonly WorkspaceTreeEntry[]> {
  const listed = (await reader.listTree(100_000)).filter(({ path }) => !VENDORED.test(path));
  const needed = listed.filter(
    ({ path, mode }) =>
      mode === "file" &&
      (AUTHORITY.test(path) ||
        (isDependencyLockfile(path) &&
          !(
            path.includes("/") &&
            patterns.some((pattern) => dependencyIgnoreMatches(pattern, path, work))
          ))),
  );
  const contents = await reader.readEntries(
    needed,
    (path) => {
      const name = path.slice(path.lastIndexOf("/") + 1);
      return (
        Object.entries(LOCKFILE_MAX_BYTES).find(([key]) => key === name)?.[1] ??
        PACKAGE_JSON_LIMITS.maxLength
      );
    },
    64 * 1024 * 1024,
  );
  const texts = new Map(
    needed.map((entry, index) => {
      const bytes = contents[index]!;
      let text;
      try {
        text = decoder.decode(bytes);
      } catch {
        throw usageError("unreadable_file", "A dependency file is not valid UTF-8.");
      }
      return [entry.path, { text, oid: blobOid(bytes, entry.oid) }];
    }),
  );
  return listed.map((entry) => Object.assign({}, entry, texts.get(entry.path)));
}

function metadata(entries: readonly WorkspaceTreeEntry[]): ListedEntry[] {
  return entries.map((entry) => ({
    path: entry.path,
    sha: entry.oid,
    type: entry.mode === "directory" ? "tree" : entry.mode === "file" ? "blob" : "commit",
  }));
}

function cliProjects(scope: GateRootScope): GateRootScope["projects"] {
  // Workspace tooling is installed alongside every app. Give it its own section instead of
  // losing it when M3 classifies only app members as independently protectable projects.
  return scope.graph !== null && !scope.projects.some(({ path }) => path === ".")
    ? [{ path: ".", name: null, members: ["."] }, ...scope.projects]
    : scope.projects;
}

/** Ignore patterns cannot suppress the root/member exceptions from D-227. */
async function readRetainedLocks(
  reader: ProjectReader,
  entries: readonly WorkspaceTreeEntry[],
  ignored: ReadonlySet<string>,
): Promise<readonly WorkspaceTreeEntry[]> {
  const needed = entries.filter(
    ({ path, mode, text }) =>
      mode === "file" && text === undefined && isDependencyLockfile(path) && !ignored.has(path),
  );
  const alreadyRead = entries.reduce(
    (total, entry) => total + (entry.text === undefined ? 0 : Buffer.byteLength(entry.text)),
    0,
  );
  const contents = await reader.readEntries(
    needed,
    (path) =>
      Object.entries(LOCKFILE_MAX_BYTES).find(
        ([name]) => name === path.slice(path.lastIndexOf("/") + 1),
      )?.[1] ?? PACKAGE_JSON_LIMITS.maxLength,
    64 * 1024 * 1024 - alreadyRead,
  );
  const restored = new Map(
    needed.map((entry, index) => {
      const bytes = contents[index]!;
      try {
        return [entry.path, { text: decoder.decode(bytes), oid: blobOid(bytes, entry.oid) }];
      } catch {
        throw usageError("unreadable_file", "A dependency file is not valid UTF-8.");
      }
    }),
  );
  return entries.map((entry) => Object.assign({}, entry, restored.get(entry.path)));
}

/** All-projects mode is opt-in CLI presentation, with the same pure gate discovery and M3 scopes. */
export async function checkAllProjects(
  options: DepsCheckOptions,
  io: CliIo,
  root: string,
  headCommit: string | null,
  env: NodeJS.ProcessEnv,
  judge: Judge,
): Promise<ExitCode> {
  const base =
    options.base === undefined
      ? await defaultBase(root, headCommit, env).then(({ commit, branch }) => ({
          commit,
          from: `merge base with ${branch}`,
        }))
      : { commit: await resolveCommit(root, options.base, "--base", env), from: "--base" };
  const baseReader = new CommitReader(root, base.commit, "", env);
  const headReader =
    headCommit === null
      ? new WorkingTreeReader(root, env)
      : new CommitReader(root, headCommit, "", env);
  const config = await baseReader.readFile(".kovo/config.yml", DEPENDENCY_IGNORE_CONFIG_MAX_BYTES);
  const patterns = config === null ? [] : parseDependencyIgnoreConfig(decoder.decode(config));
  if (patterns === null)
    throw usageError(
      "dependency_ignore_config_invalid",
      "The base dependency ignore list is invalid.",
    );
  const work = { remaining: 64 * 1024 * 1024 };
  let baseTree = await tree(baseReader, patterns, work);
  let headTree = await tree(headReader, patterns, work);
  const matched = [
    ...new Set(
      [...baseTree, ...headTree]
        .filter(
          ({ path }) =>
            isDependencyLockfile(path) &&
            patterns.some((pattern) => dependencyIgnoreMatches(pattern, path, work)),
        )
        .map(({ path }) => path),
    ),
  ];
  const declarations: { dir: string; patterns: readonly string[] }[] = [];
  for (const entry of [...baseTree, ...headTree]) {
    const kind =
      entry.path === "package.json" || entry.path.endsWith("/package.json")
        ? "package.json"
        : entry.path === "pnpm-workspace.yaml" || entry.path.endsWith("/pnpm-workspace.yaml")
          ? "pnpm-workspace.yaml"
          : null;
    if (kind === null) continue;
    const dir = entry.path.slice(0, -kind.length);
    if (!matched.some((path) => path.startsWith(dir) && path.slice(dir.length).includes("/")))
      continue;
    const memberPatterns =
      entry.text === undefined ? null : dependencyWorkspacePatterns(entry.text, kind);
    if (memberPatterns === null || declarations.length >= 300)
      throw usageError(
        "dependency_ignore_workspace_invalid",
        "Workspace ignore authority cannot be read.",
      );
    declarations.push({ dir, patterns: memberPatterns });
  }
  const ignored = new Set<string>();
  const baseMetadata = metadata(baseTree);
  const headMetadata = metadata(headTree);
  for (const path of matched)
    if (!protectedGateLockfile(path, declarations, baseMetadata, headMetadata, work))
      ignored.add(path);
  baseTree = await readRetainedLocks(baseReader, baseTree, ignored);
  headTree = await readRetainedLocks(headReader, headTree, ignored);
  const roots = (entries: readonly WorkspaceTreeEntry[]) => {
    const found = discoverDirectories(metadata(entries), [], ignored, 100);
    if (found.kind === "unsupported")
      throw usageError(found.reason, "The dependency layout cannot be evaluated.");
    return found.kind === "directories" ? found.directories : [];
  };
  const directories = [...new Set([...roots(baseTree), ...roots(headTree)])].toSorted();
  if (directories.length > 100)
    throw usageError("too_many_lockfiles", "The gate reads at most 100 install roots.");
  const reports: { path: string; name: string | null; report: CheckReport }[] = [];
  for (const dir of directories) {
    const prefix = dir === "" ? "" : `${dir}/`;
    const side = (entries: readonly WorkspaceTreeEntry[]) => {
      const relative = entries
        .filter((entry) => entry.path.startsWith(prefix))
        .map((entry) => Object.assign({}, entry, { path: entry.path.slice(prefix.length) }));
      const detected = detectPackageManager(
        relative
          .filter((entry) => !entry.path.includes("/") && entry.mode === "file")
          .map(({ path }) => path),
      );
      if (!detected.ok)
        throw usageError(
          "unsupported_dependency_layout",
          "An install root has no supported lockfile and manifest.",
        );
      const lockfile = relative.find(({ path }) => path === detected.lockfileName)?.text;
      const manifest = relative.find(({ path }) => path === "package.json")?.text;
      if (lockfile === undefined || manifest === undefined)
        throw usageError("missing_lockfile", "An install root cannot be read.");
      const input = {
        packageManager: detected.packageManager,
        treeComplete: true,
        entries: relative,
      };
      const scope = discoverGateScope(input, detected.lockfileName, lockfile);
      const parsed = snapshotGraph(detected.lockfileName, { lockfile, manifest, workspace: input });
      if (scope === null || !parsed.ok)
        throw usageError("project_scope_ambiguous", "Project ownership cannot be established.");
      return { scope, graph: parsed.graph, lockfile: `${prefix}${detected.lockfileName}` };
    };
    const before = baseTree.some(({ path }) => path === `${prefix}package.json`)
      ? side(baseTree)
      : null;
    const after = side(headTree);
    const baseProjects = before === null ? [] : cliProjects(before.scope);
    const headProjects = cliProjects(after.scope);
    const selected = [
      ...baseProjects,
      ...headProjects.filter(({ path }) => !baseProjects.some((project) => project.path === path)),
    ];
    if (reports.length + selected.length > 100)
      throw usageError("too_many_projects", "The gate reads at most 100 projects.");
    for (const project of selected) {
      const previous = baseProjects.find(({ path }) => path === project.path);
      const current = headProjects.find(({ path }) => path === project.path);
      if (current === undefined)
        throw usageError(
          "project_scope_ambiguous",
          "A base project disappeared from the candidate.",
        );
      const graphs = gateScopeGraphs(
        before === null || previous === undefined
          ? null
          : { ...before.scope, projects: [previous] },
        { ...after.scope, projects: [current] },
      );
      const changes = changeListOf(
        graphs.base ?? (previous === undefined ? null : (before?.graph ?? null)),
        graphs.head ?? after.graph,
      );
      const answer =
        changes.length === 0
          ? { verdicts: [], unavailableSignals: [], osvSnapshot: null }
          : await judge(changes);
      reports.push({
        path: dir === "" ? project.path : project.path === "." ? dir : `${dir}/${project.path}`,
        name: project.name,
        report: {
          mode: options.mode.kind,
          lockfile: after.lockfile,
          base: base.commit,
          baseFrom: base.from,
          head: headCommit,
          changes,
          ...answer,
        },
      });
    }
  }
  if (options.format === "json") {
    io.stdout(
      JSON.stringify({
        format: "kovo-deps-check-projects",
        version: 1,
        projects: reports.map(({ path, name, report }) => ({
          path,
          name,
          report: JSON.parse(renderJson(report)) as unknown,
        })),
      }) + "\n",
    );
  } else {
    io.stdout(
      reports.length === 0
        ? "No projects discovered.\n"
        : reports
            .map(({ path, name, report }) =>
              renderText(report, `Project ${path}${name === null ? "" : ` (${name})`}`),
            )
            .join("\n"),
    );
  }
  return reports.some(({ report }) => verdictExitCode(report.verdicts) === 1) ? 1 : 0;
}
