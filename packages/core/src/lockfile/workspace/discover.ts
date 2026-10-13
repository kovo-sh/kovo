import { packageNameSchema, packageVersionSchema } from "@kovo/contracts";
import semver from "semver";
import { z } from "zod";

import { isJsonObject, parseBoundedJson, type JsonObject } from "../../manifest/bounded-json.js";
import { compileWorkspaceGlob, GlobWorkExceeded, PreparedPath } from "../../manifest/glob.js";
import { checkNpmrc } from "../../manifest/npmrc.js";
import { npmrcKeyName, tokenizeNpmrc } from "../../manifest/npmrc-tokens.js";
import { pnpmWorkspaceSettings } from "../../manifest/pnpm-settings.js";
import {
  catalogEntry,
  catalogName,
  parsePnpmCatalogs,
  type PnpmCatalogs,
} from "../../manifest/pnpm-catalogs.js";
import {
  DEPENDENCY_SECTIONS,
  PACKAGE_JSON_LIMITS,
  parsePackageJson,
} from "../../manifest/package-json.js";
import {
  WORKSPACE_LIMITS,
  workspaceFailure,
  type WorkspaceInput,
  type WorkspaceLayout,
  type WorkspaceLimits,
  type WorkspaceMember,
  type WorkspaceResult,
  type WorkspaceTreeEntry,
  type LocalDeclaration,
} from "./types.js";
import { UnsupportedWorkspaceYamlError, workspaceYaml } from "./yaml.js";

const entriesSchema = z.array(
  z.strictObject({
    path: z.string().max(1024),
    mode: z.enum(["file", "directory", "symlink", "submodule"]),
    oid: z.string().regex(/^(?:[a-f0-9]{40}|[a-f0-9]{64})$/),
    text: z.string().exactOptional(),
  }),
);
const patternsSchema = z.array(z.string());

function unsafePathCharacters(value: string): boolean {
  return (
    /[\\:%]/u.test(value) ||
    Array.from(value).some((char) => char.charCodeAt(0) < 32 || char.charCodeAt(0) === 127)
  );
}

export function canonicalWorkspacePath(path: string, root = false): boolean {
  return (
    (root && path === ".") ||
    (path.length > 0 &&
      path.length <= 1024 &&
      !unsafePathCharacters(path) &&
      !path.startsWith("/") &&
      path
        .split("/")
        .every(
          (part) =>
            part !== "" &&
            part !== "." &&
            part !== ".." &&
            part.toLowerCase() !== "node_modules" &&
            part.toLowerCase() !== ".git",
        ))
  );
}
function collisionKey(value: string): string {
  return value.normalize("NFKC").toUpperCase().toLowerCase();
}
/** Confined member-relative link resolution; dot segments never escape the repository. */
export function resolveMemberLink(from: string, ref: string): string | null {
  if (!ref || unsafePathCharacters(ref) || ref.startsWith("/")) return null;
  const parts = from === "." ? [] : from.split("/");
  for (const segment of ref.split("/")) {
    if (segment === "..") {
      if (parts.pop() === undefined) return null;
    } else if (segment !== "." && segment !== "") parts.push(segment);
  }
  const path = parts.length === 0 ? "." : parts.join("/");
  return canonicalWorkspacePath(path, true) ? path : null;
}

/** Discover only from a complete immutable Git tree. Missing reads never become zero members. */
export function discoverWorkspaces(
  input: WorkspaceInput,
  limits: WorkspaceLimits = WORKSPACE_LIMITS,
): WorkspaceResult<WorkspaceLayout> {
  if (
    input.packageManager !== "npm" &&
    input.packageManager !== "pnpm" &&
    input.packageManager !== "yarn"
  )
    return workspaceFailure("manager_mismatch");
  if (!input.treeComplete) return workspaceFailure("incomplete_tree");
  if (input.entries.length > limits.maxTreeEntries) return workspaceFailure("resource_limit");
  const validated = entriesSchema.safeParse(input.entries);
  if (!validated.success) return workspaceFailure("invalid_path");
  const entries = new Map<string, WorkspaceTreeEntry>();
  const dirs = new Set<string>();
  const identities = new Map<string, string>();
  const collisions = new Set<string>();
  let pathBytes = 0;
  for (const entry of validated.data) {
    // Ordinary source/fixture filenames are not workspace identities. Only reject structural
    // traversal here; member identities and their manifests receive stricter checks below.
    if (
      !entry.path ||
      entry.path.startsWith("/") ||
      entry.path.split("/").some((part) => part === "" || part === "." || part === "..") ||
      entry.path.split("/").length > limits.maxDepth
    ) {
      return workspaceFailure("invalid_path");
    }
    pathBytes += entry.path.length * 3;
    if (pathBytes > limits.maxTreePathBytes) return workspaceFailure("resource_limit");
    if (entries.has(entry.path)) return workspaceFailure("identity_collision");
    entries.set(entry.path, entry);
    const segments = entry.path.split("/");
    for (let i = 1; i <= segments.length; i += 1) {
      const path = segments.slice(0, i).join("/");
      const key = collisionKey(path);
      const old = identities.get(key);
      if (old !== undefined && old !== path) collisions.add(key);
      identities.set(key, path);
      if (i < segments.length || entry.mode === "directory") dirs.add(path);
    }
  }
  // A file/symlink/gitlink cannot also be a directory containing fetched descendants.
  for (const dir of dirs) {
    const entry = entries.get(dir);
    if (entry !== undefined && entry.mode !== "directory")
      return workspaceFailure("unsafe_tree_entry");
  }
  const rootEntry = entries.get("package.json");
  if (rootEntry?.mode !== "file" || rootEntry.text === undefined)
    return workspaceFailure("missing_manifest");
  const root = parseBoundedJson(rootEntry.text, PACKAGE_JSON_LIMITS);
  if (!root.ok || !isJsonObject(root.value)) return workspaceFailure("invalid_manifest");
  const yamlEntry = entries.get("pnpm-workspace.yaml");
  let patterns: string[] = [];
  let catalogs: PnpmCatalogs | undefined;
  let pnpmWorkspaceOverrides: Readonly<Record<string, string>> | undefined;
  let pnpmWorkspaceConfig: JsonObject | undefined;
  if (input.packageManager === "pnpm" && yamlEntry !== undefined) {
    if (yamlEntry.mode !== "file" || yamlEntry.text === undefined)
      return workspaceFailure("invalid_workspace_yaml");
    let raw: unknown;
    try {
      raw = workspaceYaml(yamlEntry.text);
    } catch (error) {
      return workspaceFailure(
        error instanceof UnsupportedWorkspaceYamlError
          ? "unsupported_workspace_setting"
          : "invalid_workspace_yaml",
      );
    }
    const parsedCatalogs = parsePnpmCatalogs(raw);
    if (parsedCatalogs === null)
      return workspaceFailure(
        raw !== null &&
          typeof raw === "object" &&
          ["catalog", "catalogs", "catalogMode"].some((key) => Object.hasOwn(raw, key))
          ? "invalid_catalog"
          : "unsupported_workspace_setting",
      );
    const settings = pnpmWorkspaceSettings(yamlEntry.text);
    if (settings === null) return workspaceFailure("unsupported_workspace_setting");
    pnpmWorkspaceConfig = settings;
    if (isJsonObject(settings["overrides"]))
      pnpmWorkspaceOverrides = Object.fromEntries(
        Object.entries(settings["overrides"]).filter(
          (entry): entry is [string, string] => typeof entry[1] === "string",
        ),
      );
    const declaredPatterns = patternsSchema.safeParse(settings["packages"] ?? []);
    if (!declaredPatterns.success) return workspaceFailure("unsupported_workspace_setting");
    patterns = declaredPatterns.data;
    if (
      Object.hasOwn(settings, "catalog") ||
      Object.hasOwn(settings, "catalogs") ||
      Object.hasOwn(settings, "catalogMode")
    )
      catalogs = parsedCatalogs;
  }
  const workspaces = root.value["workspaces"];
  const npmPatterns = patternsSchema.safeParse(
    input.packageManager === "yarn" && isJsonObject(workspaces)
      ? workspaces["packages"]
      : (workspaces ?? []),
  );
  if (
    input.packageManager === "yarn" &&
    isJsonObject(workspaces) &&
    Object.keys(workspaces).some((key) => key !== "packages")
  )
    return workspaceFailure("unsupported_workspace_setting");
  if (!npmPatterns.success) return workspaceFailure("unsupported_layout");
  if (input.packageManager === "npm" || input.packageManager === "yarn") {
    if (yamlEntry !== undefined) return workspaceFailure("manager_mismatch");
    patterns = npmPatterns.data;
  } else if (npmPatterns.data.length > 0) return workspaceFailure("manager_mismatch");
  if (input.packageManager === "yarn" && patterns.length > 0 && root.value["private"] !== true)
    return workspaceFailure("unsupported_layout");
  if (patterns.length > limits.maxPatterns) return workspaceFailure("resource_limit");
  const matchers = [];
  for (const pattern of patterns) {
    const exclude = pattern.startsWith("!");
    const glob = exclude ? pattern.slice(1) : pattern;
    if (glob.length > limits.maxPatternLength) return workspaceFailure("resource_limit");
    if (!canonicalWorkspacePath(glob) || glob.startsWith("!") || /[()]/u.test(glob))
      return workspaceFailure("invalid_pattern");
    matchers.push({ exclude, glob, matcher: compileWorkspaceGlob(glob) });
  }
  const candidates = new Set(dirs);
  for (const entry of entries.values())
    if (entry.mode === "symlink" || entry.mode === "submodule") candidates.add(entry.path);
  const selected = new Set<string>();
  const work = { remaining: limits.maxGlobWork };
  try {
    for (const path of candidates) {
      const prepared = new PreparedPath(path);
      let included = false;
      let excluded = false;
      for (const { exclude, matcher } of matchers) {
        if (matcher.test(prepared, work)) {
          if (exclude) excluded = true;
          else included = true;
        }
      }
      if (!included || excluded) continue;
      const at = entries.get(path);
      if (at?.mode === "symlink" || at?.mode === "submodule")
        return workspaceFailure("unsafe_tree_entry");
      const manifest = entries.get(`${path}/package.json`);
      if (manifest === undefined) {
        // Recursive globs also match ordinary code directories; exact/immediate declarations must exist.
        if (
          matchers.some(
            ({ exclude, glob, matcher }) =>
              !exclude && !glob.includes("**") && matcher.test(prepared, work),
          )
        ) {
          return workspaceFailure("missing_manifest");
        }
      } else selected.add(path);
    }
    for (const { exclude, glob } of matchers) {
      if (!exclude && !/[*?[\]{}]/u.test(glob) && !dirs.has(glob))
        return workspaceFailure("missing_manifest");
    }
  } catch (error) {
    if (error instanceof GlobWorkExceeded) return workspaceFailure("resource_limit");
    throw error;
  }
  for (const entry of entries.values()) {
    if (
      (entry.mode === "symlink" || entry.mode === "submodule") &&
      [...selected].some((path) => entry.path.startsWith(`${path}/`))
    )
      return workspaceFailure("unsafe_tree_entry");
  }
  if (selected.size > limits.maxMembers) return workspaceFailure("resource_limit");
  const paths = [".", ...selected].toSorted();
  // Compare all tree entries against each identity, including its ancestors. Unrelated fixture
  // trees may contain node_modules, platform-specific filenames or case/Unicode collisions.
  for (const path of paths) {
    const manifest = path === "." ? "package.json" : `${path}/package.json`;
    if (!canonicalWorkspacePath(manifest)) return workspaceFailure("invalid_path");
    const segments = manifest.split("/");
    for (let i = 1; i <= segments.length; i += 1)
      if (collisions.has(collisionKey(segments.slice(0, i).join("/"))))
        return workspaceFailure("identity_collision");
  }
  const documents = new Map<string, { entry: WorkspaceTreeEntry; document: typeof root.value }>();
  const names = new Map<string, string>();
  let manifestBytes = 0;
  for (const path of paths) {
    const file = path === "." ? "package.json" : `${path}/package.json`;
    const entry = entries.get(file);
    if (entry?.mode !== "file" || entry.text === undefined)
      return workspaceFailure("missing_manifest");
    manifestBytes += entry.text.length * 3;
    if (manifestBytes > limits.maxManifestBytes) return workspaceFailure("resource_limit");
    const parsed = parseBoundedJson(entry.text, PACKAGE_JSON_LIMITS);
    if (!parsed.ok || !isJsonObject(parsed.value)) return workspaceFailure("invalid_manifest");
    const document = parsed.value;
    if (
      path !== "." &&
      (document["workspaces"] !== undefined || entries.has(`${path}/pnpm-workspace.yaml`))
    )
      return workspaceFailure("unsupported_layout");
    if (
      path !== "." &&
      (!packageNameSchema.safeParse(document["name"]).success ||
        (document["version"] !== undefined &&
          !packageVersionSchema.safeParse(document["version"]).success))
    )
      return workspaceFailure("invalid_member_identity");
    if (typeof document["name"] === "string") {
      const key = collisionKey(document["name"]);
      if (names.has(key)) return workspaceFailure("identity_collision");
      names.set(key, path);
    }
    for (const lock of [
      "package-lock.json",
      "npm-shrinkwrap.json",
      "pnpm-lock.yaml",
      "yarn.lock",
      "bun.lock",
      "bun.lockb",
    ]) {
      if (
        entries.has(path === "." ? lock : `${path}/${lock}`) &&
        (path !== "." ||
          lock !==
            (input.packageManager === "npm"
              ? "package-lock.json"
              : input.packageManager === "yarn"
                ? "yarn.lock"
                : "pnpm-lock.yaml"))
      )
        return workspaceFailure("conflicting_lockfile");
    }
    const npmrc = entries.get(path === "." ? ".npmrc" : `${path}/.npmrc`);
    if (
      npmrc !== undefined &&
      (npmrc.mode !== "file" || npmrc.text === undefined || !checkNpmrc(npmrc.text).ok)
    )
      return workspaceFailure("invalid_manifest");
    if (npmrc?.text !== undefined) {
      // `checkNpmrc` above admitted the file, so the strict tokenizer reads it.
      const tokens = tokenizeNpmrc(npmrc.text);
      for (const setting of tokens.ok ? tokens.entries : []) {
        const name = npmrcKeyName(setting.key);
        if (
          name === "injectworkspacepackages" ||
          (name === "sharedworkspacelockfile" &&
            setting.value !== null && // a bare key reads as `true`
            (setting.value.kind !== "plain" || setting.value.text.toLowerCase() !== "true"))
        )
          return workspaceFailure("unsupported_workspace_setting");
      }
      if (!tokens.ok) return workspaceFailure("invalid_manifest");
    }
    documents.set(path, { entry, document });
  }
  const members: WorkspaceMember[] = [];
  let localEdges = 0;
  for (const [path, { entry, document }] of documents) {
    const copy = { ...document };
    delete copy["workspaces"];
    const local: LocalDeclaration[] = [];
    const catalogDeclarations: NonNullable<WorkspaceMember["catalogDeclarations"]>[number][] = [];
    for (const section of DEPENDENCY_SECTIONS) {
      const map = document[section];
      if (!isJsonObject(map)) continue;
      const registry = { ...map };
      for (const [alias, spec] of Object.entries(map)) {
        if (typeof spec !== "string") continue;
        if (spec.startsWith("catalog:")) {
          if (input.packageManager !== "pnpm") return workspaceFailure("catalogs_unsupported");
          const name = catalogName(spec);
          if (name === null) return workspaceFailure("invalid_catalog");
          const resolved = catalogs === undefined ? undefined : catalogEntry(catalogs, name, alias);
          if (resolved === undefined) return workspaceFailure("catalog_entry_missing");
          const parsedAlias = packageNameSchema.safeParse(alias);
          if (!parsedAlias.success) return workspaceFailure("invalid_manifest");
          registry[alias] = resolved;
          catalogDeclarations.push({ alias: parsedAlias.data, section, spec, catalog: name });
          continue;
        }
        const byName = names.get(collisionKey(alias));
        let target: string | undefined;
        if (spec.startsWith("workspace:")) {
          if (
            input.packageManager !== "pnpm" ||
            !["workspace:*", "workspace:^", "workspace:~"].includes(spec)
          )
            return workspaceFailure("invalid_local_edge");
          target = byName;
        } else if (spec.startsWith("file:") || spec.startsWith("link:")) {
          target = resolveMemberLink(path, spec.slice(spec.indexOf(":") + 1)) ?? undefined;
        } else if (byName !== undefined && byName !== ".") {
          const version = documents.get(byName)?.document["version"];
          if (
            typeof version === "string" &&
            semver.validRange(spec) !== null &&
            semver.satisfies(version, spec)
          )
            target = byName;
        }
        if (target !== undefined || /^(workspace|file|link):/u.test(spec)) {
          const member = target === undefined ? undefined : documents.get(target)?.document;
          const name = packageNameSchema.safeParse(alias);
          if (target === undefined || target === "." || member?.["name"] !== alias || !name.success)
            return workspaceFailure("invalid_local_edge");
          if (++localEdges > limits.maxLocalEdges) return workspaceFailure("resource_limit");
          local.push({ alias: name.data, section, spec, target });
          delete registry[alias];
        }
      }
      copy[section] = registry;
    }
    const parsed = parsePackageJson({
      text: JSON.stringify(copy),
      pnpmWorkspaceYamlPresent: false,
      // pnpm 9/10 read settings from the `pnpm` field, so pnpm members get the settings allowlist (#1879).
      ...(input.packageManager === "npm" ? {} : { packageManager: input.packageManager }),
    });
    if (!parsed.ok) return workspaceFailure("invalid_manifest");
    const manifest = { ...parsed.manifest, document };
    if (
      manifest.packageManager !== null &&
      !manifest.packageManager.startsWith(`${input.packageManager}@`)
    )
      return workspaceFailure("manager_mismatch");
    members.push({
      path,
      manifestOid: entry.oid,
      manifest,
      local,
      ...(catalogDeclarations.length === 0 ? {} : { catalogDeclarations }),
    });
  }
  return {
    ok: true,
    value: {
      packageManager: input.packageManager,
      members,
      hasWorkspaces: patterns.some((pattern) => !pattern.startsWith("!")),
      workspaceConfigOid: yamlEntry?.oid ?? null,
      ...(catalogs === undefined ? {} : { catalogs }),
      ...(catalogs === undefined || pnpmWorkspaceConfig === undefined
        ? {}
        : { pnpmWorkspaceConfig }),
      ...(catalogs === undefined || pnpmWorkspaceOverrides === undefined
        ? {}
        : { pnpmWorkspaceOverrides }),
    },
  };
}
