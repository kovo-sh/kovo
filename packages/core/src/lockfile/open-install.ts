import { packageNameSchema, packageVersionSchema } from "@kovo/contracts/npm";
import semver from "semver";
import { stringify } from "yaml";

import {
  isJsonObject,
  parseBoundedJson,
  type JsonObject,
  type JsonValue,
} from "../manifest/bounded-json.js";
import { classifyDependencySpec } from "../manifest/dependency-spec.js";
import type { DependencySection, PackageManifest } from "../manifest/package-json.js";
import type { Instance } from "./instances.js";
import { NPM_LOCKFILE_LIMITS } from "./npm.js";
import { loadPnpmLockfileYaml, SUPPORTED_PNPM_LOCKFILE_VERSION } from "./pnpm.js";
import { checkIntegrity } from "./registry-source.js";
import { GRAPH_LIMITS } from "./types.js";
import { WorkspaceParserContext } from "./workspace/parser-context.js";
import type { WorkspaceLayout } from "./workspace/types.js";
import { parseYarnLockfile, yarnResolvedFragments } from "./yarn.js";

// "Open install, sealed code" (specs/npm-proxy-and-network-egress.md): the manifest
// set a Sandbox B open install runs from, synthesized by trusted code from the customer's lockfile
// (npm, pnpm, and Yarn classic, whose v1 lockfile is rewritten with resolved URLs at the job-scoped
// proxy by name@version).
// It holds only what installing needs: exact name@version with integrity, the dependency edges the
// registry's own manifests declare, and platform and bin metadata. Workspace members are renamed
// (`kovo-ws-m<N>`, at `kovo-ws/m<N>` paths of the same depth), the root and member manifests carry
// no scripts or other fields, and resolved URLs are dropped (the package manager fetches each
// name@version through the job-scoped proxy). The lockfile file itself is never shipped. Anything
// outside that model (git, file, link or tarball-only sources, sha1-only or missing integrity,
// pnpm patches, multi-document pnpm lockfiles) refuses, and the caller takes today's restricted
// install path. Pure: no I/O.

export const OPEN_INSTALL_REFUSALS = [
  "lockfile_unreadable",
  "lockfile_unsupported",
  "too_many_packages",
  "non_registry_dependency",
  "integrity_missing",
  "workspace_member_invalid",
  "member_name_dependency",
  "unresolved_dependency",
  "patched_dependency",
  "invalid_entry",
  "yarn_resolutions",
] as const;
export type OpenInstallRefusal = (typeof OPEN_INSTALL_REFUSALS)[number];

/** One synthesized file, its path relative to the open install root. */
export interface OpenInstallFile {
  readonly path: string;
  readonly content: string;
}

/** A renamed workspace member: its directory in the open install root and in the real tree. */
export interface OpenInstallMember {
  readonly synthesized: string;
  readonly real: string;
}

export interface OpenInstallManifests {
  readonly files: readonly OpenInstallFile[];
  /** Every workspace member, sorted by real path (the root is not listed). */
  readonly members: readonly OpenInstallMember[];
}

export type OpenInstallSynthesis =
  | { readonly ok: true; readonly value: OpenInstallManifests }
  | { readonly ok: false; readonly reason: OpenInstallRefusal };

/**
 * pnpm's dependency build policy, mirrored into the open install's `pnpm-workspace.yaml` so it
 * builds what today's install would build. Lists of package selectors only.
 */
export interface PnpmBuildPolicy {
  readonly onlyBuiltDependencies?: readonly string[];
  readonly ignoredBuiltDependencies?: readonly string[];
  readonly neverBuiltDependencies?: readonly string[];
}

/**
 * A mirrored root `.npmrc` setting: one of a closed set of keys with a literal boolean
 * or enum value, validated by the caller. Written into the open install root as `key=value`.
 */
export type OpenInstallNpmrcSetting = readonly [key: string, value: string];

/** Yarn classic's inputs besides the lockfile: v1 records no importer declarations. */
export interface YarnOpenInstallInput {
  /** The job-scoped proxy's Yarn registry URL (`<proxy>/yarn/`); resolved URLs point under it. */
  readonly registryUrl: string;
  /** The root manifest of a single-package tree. */
  readonly manifest?: PackageManifest;
  /** The workspace layout (root and members) of a workspace tree. */
  readonly layout?: WorkspaceLayout;
}

export interface OpenInstallInput {
  readonly packageManager: "npm" | "pnpm" | "yarn";
  /** The customer lockfile's text (package-lock.json, pnpm-lock.yaml or yarn.lock). Never shipped. */
  readonly lockfile: string;
  readonly pnpmBuildPolicy?: PnpmBuildPolicy;
  readonly yarn?: YarnOpenInstallInput;
  /** Mirrored root `.npmrc` settings, written as the open root's `.npmrc` (none: no file). */
  readonly npmrc?: readonly OpenInstallNpmrcSetting[];
}

const ROOT_NAME = "kovo-open-install";
const SYNTHETIC_VERSION = "0.0.0";
const NPM_SECTIONS = [
  "dependencies",
  "devDependencies",
  "optionalDependencies",
  "peerDependencies",
] as const;
/** npm package entry fields an install needs: registry metadata, never project content. */
const NPM_STRING_FIELDS = ["version", "integrity", "license"] as const;
const NPM_BOOLEAN_FIELDS = [
  "dev",
  "optional",
  "devOptional",
  "peer",
  "inBundle",
  "hasInstallScript",
] as const;
const NPM_LIST_FIELDS = ["os", "cpu", "libc"] as const;
const NPM_MAP_FIELDS = [
  "dependencies",
  "optionalDependencies",
  "peerDependencies",
  "engines",
] as const;

class Refused extends Error {
  readonly reason: OpenInstallRefusal;
  constructor(reason: OpenInstallRefusal) {
    super(reason);
    this.reason = reason;
  }
}

function refuse(reason: OpenInstallRefusal): never {
  throw new Refused(reason);
}

/** Synthesizes the open install manifest set; refuses anything outside the supported model. */
export function synthesizeOpenInstall(input: OpenInstallInput): OpenInstallSynthesis {
  try {
    const value =
      input.packageManager === "npm"
        ? synthesizeNpm(input.lockfile)
        : input.packageManager === "pnpm"
          ? synthesizePnpm(input.lockfile, input.pnpmBuildPolicy ?? {})
          : synthesizeYarn(input.lockfile, input.yarn ?? refuse("lockfile_unsupported"));
    return { ok: true, value: withNpmrc(value, input.npmrc ?? []) };
  } catch (error) {
    if (error instanceof Refused) return { ok: false, reason: error.reason };
    throw error;
  }
}

/** One mirrored `.npmrc` line: a lowercase key and a lowercase enum word, nothing else. */
const NPMRC_LINE = /^[a-z-]{1,64}=[a-z]{1,16}$/;

/** The open root's `.npmrc` from mirrored settings (validated by the caller; re-checked here). */
function withNpmrc(
  manifests: OpenInstallManifests,
  settings: readonly OpenInstallNpmrcSetting[],
): OpenInstallManifests {
  if (settings.length === 0) return manifests;
  const lines = settings.map(([key, value]) => `${key}=${value}`);
  if (lines.some((line) => !NPMRC_LINE.test(line))) refuse("invalid_entry");
  return {
    ...manifests,
    files: [...manifests.files, { path: ".npmrc", content: `${lines.join("\n")}\n` }],
  };
}

/** A normalized relative directory: no empty, `.` or `..` segment, no leading slash. */
function relativeDir(path: string): readonly string[] {
  const segments = path.split("/");
  if (
    path === "" ||
    path.length > 1024 ||
    segments.some((segment) => segment === "" || segment === "." || segment === "..") ||
    segments.includes("node_modules") ||
    path.includes("\\") ||
    Array.from({ length: path.length }, (_, index) => path.charCodeAt(index)).some(
      (code) => code < 0x20,
    )
  )
    refuse("workspace_member_invalid");
  return segments;
}

/**
 * Renamed member directories of the same depth as the real ones, so relative links inside a
 * member's `node_modules` stay valid when it moves to the real path.
 */
function renameMembers(paths: readonly string[]): Map<string, { path: string; name: string }> {
  const renamed = new Map<string, { path: string; name: string }>();
  [...new Set(paths)].toSorted().forEach((real, index) => {
    const depth = relativeDir(real).length;
    const id = `m${index + 1}`;
    const path =
      depth === 1
        ? `kovo-ws-${id}`
        : ["kovo-ws", id, ...Array<string>(depth - 2).fill("x")].join("/");
    renamed.set(real, { path, name: `kovo-ws-${id}` });
  });
  return renamed;
}

/** `to` relative to `from` (both normalized relative directories, `.` for the root). */
function relativePath(from: string, to: string): string {
  const a = from === "." ? [] : from.split("/");
  const b = to === "." ? [] : to.split("/");
  let common = 0;
  while (common < a.length && common < b.length && a[common] === b[common]) common++;
  const up = a.slice(common).map(() => "..");
  const parts = [...up, ...b.slice(common)];
  return parts.length === 0 ? "." : parts.join("/");
}

function joinPath(base: string, rest: string): string {
  const parts: string[] = base === "." ? [] : base.split("/");
  for (const segment of rest.split("/")) {
    if (segment === "" || segment === ".") continue;
    if (segment === "..") {
      if (parts.length === 0) refuse("non_registry_dependency");
      parts.pop();
    } else parts.push(segment);
  }
  return parts.length === 0 ? "." : parts.join("/");
}

function json(value: unknown): string {
  return `${JSON.stringify(value, null, 2)}\n`;
}

function memberManifest(name: string, sections: Readonly<Record<string, Record<string, string>>>) {
  return json({ name, version: SYNTHETIC_VERSION, private: true, ...sections });
}

// ---- npm (package-lock.json v2/v3 → v3) ----

function stringRecord(value: JsonValue | undefined): Record<string, string> | null {
  if (value === undefined) return null;
  if (!isJsonObject(value)) refuse("invalid_entry");
  const out: Record<string, string> = {};
  for (const [key, item] of Object.entries(value)) {
    if (typeof item !== "string") refuse("invalid_entry");
    out[key] = item;
  }
  return out;
}

/** The package name at an npm install location (`a/node_modules/@s/b` → `@s/b`). */
function locationName(location: string): string {
  const index = location.lastIndexOf("node_modules/");
  return location.slice(index + "node_modules/".length);
}

function synthesizeNpm(text: string): OpenInstallManifests {
  const parsed = parseBoundedJson(text, NPM_LOCKFILE_LIMITS);
  if (!parsed.ok || !isJsonObject(parsed.value)) refuse("lockfile_unreadable");
  const lockfile = parsed.value;
  if (lockfile["lockfileVersion"] !== 2 && lockfile["lockfileVersion"] !== 3)
    refuse("lockfile_unsupported");
  const packages = lockfile["packages"];
  if (!isJsonObject(packages)) refuse("lockfile_unsupported");
  const entries = Object.entries(packages);
  if (entries.length > GRAPH_LIMITS.maxPackages) refuse("too_many_packages");
  const root = packages[""];
  if (!isJsonObject(root)) refuse("lockfile_unsupported");

  // Workspace members: folder entries outside node_modules, each the target of a link entry.
  const linkTargets = new Map<string, string>();
  for (const [location, entry] of entries) {
    if (!isJsonObject(entry) || entry["link"] !== true) continue;
    const resolved = entry["resolved"];
    if (typeof resolved !== "string") refuse("non_registry_dependency");
    linkTargets.set(location, resolved);
  }
  const folders = entries
    .map(([location]) => location)
    .filter((location) => location !== "" && !location.split("/").includes("node_modules"));
  if (folders.some((folder) => ![...linkTargets.values()].includes(folder)))
    refuse("non_registry_dependency");
  if ([...linkTargets.values()].some((target) => !folders.includes(target)))
    refuse("non_registry_dependency");
  const renamed = renameMembers(folders);
  const memberNames = new Map<string, string>();
  for (const folder of folders) {
    const entry = packages[folder];
    if (!isJsonObject(entry)) refuse("workspace_member_invalid");
    // npm leaves `name` out of a member's folder entry when it equals the folder's basename
    // (`apps/api` holding package `api`), and links that member as `node_modules/<basename>`; a
    // member without a name gets the basename too. An invalid name still refuses.
    const name = entry["name"] ?? folder.slice(folder.lastIndexOf("/") + 1);
    if (typeof name !== "string" || !packageNameSchema.safeParse(name).success)
      refuse("workspace_member_invalid");
    memberNames.set(name, folder);
  }

  /** A location under a member directory, moved under its renamed directory. */
  const moved = (location: string): string => {
    for (const [real, synthesized] of renamed)
      if (location.startsWith(`${real}/node_modules/`))
        return `${synthesized.path}${location.slice(real.length)}`;
    return location;
  };

  const out: Record<string, JsonObject> = {};
  for (const [location, entry] of entries) {
    if (location === "" || folders.includes(location)) continue;
    if (!isJsonObject(entry)) refuse("invalid_entry");
    if (!location.startsWith("node_modules/") && !location.includes("/node_modules/"))
      refuse("invalid_entry");
    const target = linkTargets.get(location);
    if (target !== undefined) {
      const member = renamed.get(target);
      if (member === undefined) refuse("non_registry_dependency");
      const at = moved(location);
      out[`${at.slice(0, at.length - locationName(at).length)}${member.name}`] = {
        resolved: member.path,
        link: true,
      };
      continue;
    }
    const resolved = entry["resolved"];
    if (resolved !== undefined && (typeof resolved !== "string" || !/^https?:\/\//u.test(resolved)))
      refuse("non_registry_dependency");
    const version = entry["version"];
    if (typeof version !== "string" || !packageVersionSchema.safeParse(version).success)
      refuse("invalid_entry");
    const bundled = entry["inBundle"] === true;
    if (!bundled) {
      const integrity = checkIntegrity(
        typeof entry["integrity"] === "string" ? entry["integrity"] : undefined,
      );
      if (!integrity.ok || integrity.algorithm !== "sha512") refuse("integrity_missing");
    }
    const kept: JsonObject = {};
    const name = entry["name"];
    if (name !== undefined) {
      if (typeof name !== "string" || !packageNameSchema.safeParse(name).success)
        refuse("invalid_entry");
      if (name !== locationName(location)) kept["name"] = name;
    }
    for (const field of NPM_STRING_FIELDS) {
      const value = entry[field];
      if (value === undefined) continue;
      if (typeof value !== "string") refuse("invalid_entry");
      kept[field] = value;
    }
    for (const field of NPM_BOOLEAN_FIELDS) {
      const value = entry[field];
      if (value === undefined) continue;
      if (typeof value !== "boolean") refuse("invalid_entry");
      kept[field] = value;
    }
    for (const field of NPM_LIST_FIELDS) {
      const value = entry[field];
      if (value === undefined) continue;
      if (!Array.isArray(value) || value.some((item) => typeof item !== "string"))
        refuse("invalid_entry");
      kept[field] = value;
    }
    for (const field of NPM_MAP_FIELDS) {
      const value = stringRecord(entry[field]);
      if (value === null) continue;
      if (field !== "engines" && Object.keys(value).some((dep) => memberNames.has(dep)))
        refuse("member_name_dependency");
      kept[field] = value;
    }
    const bin = entry["bin"];
    if (bin !== undefined) {
      const bins = stringRecord(bin);
      if (bins !== null) kept["bin"] = bins;
    }
    const peerMeta = entry["peerDependenciesMeta"];
    if (peerMeta !== undefined) {
      if (!isJsonObject(peerMeta)) refuse("invalid_entry");
      const meta: JsonObject = {};
      for (const [dep, value] of Object.entries(peerMeta)) {
        if (!isJsonObject(value)) refuse("invalid_entry");
        meta[dep] = value["optional"] === true ? { optional: true } : {};
      }
      kept["peerDependenciesMeta"] = meta;
    }
    const bundle = entry["bundleDependencies"];
    if (bundle !== undefined) {
      if (
        !(typeof bundle === "boolean") &&
        !(Array.isArray(bundle) && bundle.every((item) => typeof item === "string"))
      )
        refuse("invalid_entry");
      kept["bundleDependencies"] = bundle;
    }
    out[moved(location)] = kept;
  }

  /** An importer's declared dependencies, rewritten to exact versions or renamed members. */
  const importer = (dir: string, entry: JsonObject): Record<string, Record<string, string>> => {
    const sections: Record<string, Record<string, string>> = {};
    for (const section of NPM_SECTIONS) {
      const declared = stringRecord(entry[section]);
      if (declared === null) continue;
      const rewritten: Record<string, string> = {};
      for (const alias of Object.keys(declared)) {
        const member = memberNames.get(alias);
        if (member !== undefined) {
          const synthesized = renamed.get(member);
          if (synthesized === undefined) refuse("workspace_member_invalid");
          rewritten[synthesized.name] = "*";
          continue;
        }
        const candidates =
          dir === "."
            ? [`node_modules/${alias}`]
            : [`${dir}/node_modules/${alias}`, `node_modules/${alias}`];
        const found = candidates
          .map((location) => packages[location])
          .find((value): value is JsonObject => isJsonObject(value));
        const version = found?.["version"];
        if (found === undefined || typeof version !== "string" || found["link"] === true) {
          if (section === "optionalDependencies" || section === "peerDependencies") continue;
          refuse("unresolved_dependency");
        }
        const name = found["name"];
        rewritten[alias] =
          typeof name === "string" && name !== alias ? `npm:${name}@${version}` : version;
      }
      if (Object.keys(rewritten).length > 0) sections[section] = rewritten;
    }
    return sections;
  };

  const files: OpenInstallFile[] = [];
  const members: OpenInstallMember[] = [];
  const workspaces = [...renamed.values()].map((member) => member.path).toSorted();
  const rootSections = importer(".", root);
  const rootManifest = {
    name: ROOT_NAME,
    version: SYNTHETIC_VERSION,
    private: true,
    ...(workspaces.length === 0 ? {} : { workspaces }),
    ...rootSections,
  };
  const lockPackages: Record<string, JsonObject> = {
    "": {
      name: ROOT_NAME,
      version: SYNTHETIC_VERSION,
      ...(workspaces.length === 0 ? {} : { workspaces }),
      ...rootSections,
    },
  };
  for (const [real, synthesized] of [...renamed].toSorted(([a], [b]) => (a < b ? -1 : 1))) {
    const entry = packages[real];
    if (!isJsonObject(entry)) refuse("workspace_member_invalid");
    const sections = importer(real, entry);
    lockPackages[synthesized.path] = {
      name: synthesized.name,
      version: SYNTHETIC_VERSION,
      ...sections,
    };
    files.push({
      path: `${synthesized.path}/package.json`,
      content: memberManifest(synthesized.name, sections),
    });
    members.push({ synthesized: synthesized.path, real });
  }
  for (const [location, entry] of Object.entries(out).toSorted(([a], [b]) => (a < b ? -1 : 1)))
    lockPackages[location] = entry;
  files.unshift(
    { path: "package.json", content: json(rootManifest) },
    {
      path: "package-lock.json",
      content: json({
        name: ROOT_NAME,
        version: SYNTHETIC_VERSION,
        lockfileVersion: 3,
        requires: true,
        packages: lockPackages,
      }),
    },
  );
  return { files, members };
}

// ---- pnpm (pnpm-lock.yaml v9) ----

const PNPM_IMPORTER_SECTIONS = ["dependencies", "devDependencies", "optionalDependencies"] as const;
const PNPM_PACKAGE_LISTS = ["cpu", "os", "libc"] as const;
const PNPM_SNAPSHOT_MAPS = ["dependencies", "optionalDependencies"] as const;

function record(value: unknown): Record<string, unknown> | null {
  if (value === undefined || value === null || value === "") return null;
  if (typeof value !== "object" || Array.isArray(value)) refuse("invalid_entry");
  return Object.fromEntries(Object.entries(value));
}

function strings(value: unknown): Record<string, string> | null {
  const map = record(value);
  if (map === null) return null;
  const out: Record<string, string> = {};
  for (const [key, item] of Object.entries(map)) {
    if (typeof item !== "string") refuse("invalid_entry");
    out[key] = item;
  }
  return out;
}

/** The version part of a pnpm dependency reference (`1.2.3(react@18.2.0)` → `1.2.3`). */
function bareVersion(ref: string): string {
  const paren = ref.indexOf("(");
  return paren === -1 ? ref : ref.slice(0, paren);
}

function synthesizePnpm(text: string, policy: PnpmBuildPolicy): OpenInstallManifests {
  const normalized = text.replace(/^﻿/u, "").replace(/\r\n/gu, "\n");
  if (normalized.startsWith("---\n")) refuse("lockfile_unsupported");
  const loaded = loadPnpmLockfileYaml(text);
  if (!loaded.ok) refuse("lockfile_unreadable");
  const lockfile = record(loaded.value);
  if (lockfile === null || lockfile["lockfileVersion"] !== SUPPORTED_PNPM_LOCKFILE_VERSION)
    refuse("lockfile_unsupported");
  if (record(lockfile["patchedDependencies"]) !== null) refuse("patched_dependency");
  const importers = record(lockfile["importers"]);
  if (importers === null || record(importers["."]) === null) refuse("lockfile_unsupported");
  const packages = record(lockfile["packages"]) ?? {};
  const snapshots = record(lockfile["snapshots"]) ?? {};
  if (
    Object.keys(packages).length > GRAPH_LIMITS.maxPackages ||
    Object.keys(snapshots).length > GRAPH_LIMITS.maxPackages
  )
    refuse("too_many_packages");
  const memberPaths = Object.keys(importers).filter((path) => path !== ".");
  const renamed = renameMembers(memberPaths);
  const newPath = (path: string): string =>
    path === "." ? "." : (renamed.get(path)?.path ?? refuse("workspace_member_invalid"));

  const outPackages: Record<string, Record<string, unknown>> = {};
  for (const [key, value] of Object.entries(packages)) {
    if (key.includes("(patch_hash=")) refuse("patched_dependency");
    const entry = record(value);
    if (entry === null) refuse("invalid_entry");
    const resolution = record(entry["resolution"]);
    if (resolution === null || resolution["type"] !== undefined) refuse("non_registry_dependency");
    // A registry tarball (`…/-/name-1.0.0.tgz`) may be dropped; any other tarball source refuses.
    const tarball = resolution["tarball"];
    if (
      tarball !== undefined &&
      (typeof tarball !== "string" || !/^https:\/\/[^\s]+\/-\/[^/\s]+\.tgz$/u.test(tarball))
    )
      refuse("non_registry_dependency");
    const integrity = checkIntegrity(
      typeof resolution["integrity"] === "string" ? resolution["integrity"] : undefined,
    );
    if (!integrity.ok || integrity.algorithm !== "sha512") refuse("integrity_missing");
    const kept: Record<string, unknown> = { resolution: { integrity: resolution["integrity"] } };
    if (typeof entry["version"] === "string") kept["version"] = entry["version"];
    if (entry["hasBin"] === "true" || entry["hasBin"] === true) kept["hasBin"] = true;
    if (entry["requiresBuild"] === "true" || entry["requiresBuild"] === true)
      kept["requiresBuild"] = true;
    for (const field of PNPM_PACKAGE_LISTS) {
      const list = entry[field];
      if (list === undefined) continue;
      if (!Array.isArray(list) || list.some((item) => typeof item !== "string"))
        refuse("invalid_entry");
      kept[field] = list;
    }
    const engines = strings(entry["engines"]);
    if (engines !== null) kept["engines"] = engines;
    const peers = strings(entry["peerDependencies"]);
    if (peers !== null) kept["peerDependencies"] = peers;
    const peerMeta = record(entry["peerDependenciesMeta"]);
    if (peerMeta !== null) {
      const meta: Record<string, unknown> = {};
      for (const [dep, item] of Object.entries(peerMeta)) {
        const fields = record(item) ?? {};
        meta[dep] =
          fields["optional"] === "true" || fields["optional"] === true ? { optional: true } : {};
      }
      kept["peerDependenciesMeta"] = meta;
    }
    const bundled = entry["bundledDependencies"];
    if (bundled !== undefined) {
      if (!Array.isArray(bundled) || bundled.some((item) => typeof item !== "string"))
        refuse("invalid_entry");
      kept["bundledDependencies"] = bundled;
    }
    outPackages[key] = kept;
  }

  const outSnapshots: Record<string, Record<string, unknown>> = {};
  for (const [key, value] of Object.entries(snapshots)) {
    if (key.includes("(patch_hash=")) refuse("patched_dependency");
    const entry = record(value) ?? {};
    const kept: Record<string, unknown> = {};
    for (const field of PNPM_SNAPSHOT_MAPS) {
      const map = strings(entry[field]);
      if (map === null) continue;
      if (Object.values(map).some((ref) => /^(?:link|file|workspace):/iu.test(ref)))
        refuse("non_registry_dependency");
      kept[field] = map;
    }
    const transitive = entry["transitivePeerDependencies"];
    if (transitive !== undefined) {
      if (!Array.isArray(transitive) || transitive.some((item) => typeof item !== "string"))
        refuse("invalid_entry");
      kept["transitivePeerDependencies"] = transitive;
    }
    if (entry["optional"] === "true" || entry["optional"] === true) kept["optional"] = true;
    outSnapshots[key] = kept;
  }

  const files: OpenInstallFile[] = [];
  const members: OpenInstallMember[] = [];
  const outImporters: Record<string, Record<string, unknown>> = {};
  const manifests = new Map<string, Record<string, Record<string, string>>>();
  for (const path of [".", ...memberPaths.toSorted()]) {
    const importer = record(importers[path]) ?? {};
    const synthesized = newPath(path);
    const lockSections: Record<string, Record<string, { specifier: string; version: string }>> = {};
    const manifestSections: Record<string, Record<string, string>> = {};
    for (const section of PNPM_IMPORTER_SECTIONS) {
      const declared = record(importer[section]);
      if (declared === null) continue;
      const lockSection: Record<string, { specifier: string; version: string }> = {};
      const manifestSection: Record<string, string> = {};
      for (const [alias, value] of Object.entries(declared)) {
        const dependency = record(value);
        const ref = dependency?.["version"];
        if (typeof ref !== "string") refuse("invalid_entry");
        if (/^link:/iu.test(ref)) {
          const target = joinPath(path, ref.slice("link:".length));
          if (target !== "." && !renamed.has(target)) refuse("non_registry_dependency");
          const name = target === "." ? ROOT_NAME : (renamed.get(target)?.name ?? "");
          const version = `link:${relativePath(synthesized, newPath(target))}`;
          lockSection[name] = { specifier: "workspace:*", version };
          manifestSection[name] = "workspace:*";
          continue;
        }
        if (/^(?:file|workspace):/iu.test(ref) || /^https?:/iu.test(ref) || ref.includes("://"))
          refuse("non_registry_dependency");
        const bare = bareVersion(ref);
        const aliased = packageVersionSchema.safeParse(bare).success ? null : bare;
        const specifier = aliased === null ? bare : `npm:${aliased}`;
        if (aliased !== null) {
          const at = aliased.indexOf("@", aliased.startsWith("@") ? 1 : 0);
          if (
            at <= 0 ||
            !packageNameSchema.safeParse(aliased.slice(0, at)).success ||
            !packageVersionSchema.safeParse(aliased.slice(at + 1)).success
          )
            refuse("non_registry_dependency");
        }
        lockSection[alias] = { specifier, version: ref };
        manifestSection[alias] = specifier;
      }
      if (Object.keys(lockSection).length > 0) {
        lockSections[section] = lockSection;
        manifestSections[section] = manifestSection;
      }
    }
    outImporters[synthesized] = lockSections;
    manifests.set(path, manifestSections);
  }
  const settings = record(lockfile["settings"]);
  const autoInstallPeers = settings?.["autoInstallPeers"] !== "false";
  const excludeLinksFromLockfile = settings?.["excludeLinksFromLockfile"] === "true";
  const lock = {
    lockfileVersion: SUPPORTED_PNPM_LOCKFILE_VERSION,
    settings: { autoInstallPeers, excludeLinksFromLockfile },
    importers: outImporters,
    ...(Object.keys(outPackages).length === 0 ? {} : { packages: outPackages }),
    ...(Object.keys(outSnapshots).length === 0 ? {} : { snapshots: outSnapshots }),
  };
  files.push(
    {
      path: "package.json",
      content: memberManifest(ROOT_NAME, manifests.get(".") ?? {}),
    },
    { path: "pnpm-lock.yaml", content: stringify(lock, { lineWidth: 0 }) },
  );
  const workspace: Record<string, unknown> = {};
  if (renamed.size > 0) workspace["packages"] = [...renamed.values()].map((m) => m.path).toSorted();
  // The frozen install compares the lockfile's settings with the configuration: keep them equal.
  if (!autoInstallPeers) workspace["autoInstallPeers"] = false;
  if (excludeLinksFromLockfile) workspace["excludeLinksFromLockfile"] = true;
  for (const key of [
    "onlyBuiltDependencies",
    "ignoredBuiltDependencies",
    "neverBuiltDependencies",
  ] as const) {
    const list = policy[key];
    if (list === undefined) continue;
    if (list.some((item) => typeof item !== "string" || item.length > 1024))
      refuse("invalid_entry");
    workspace[key] = [...list];
  }
  if (Object.keys(workspace).length > 0)
    files.push({ path: "pnpm-workspace.yaml", content: stringify(workspace, { lineWidth: 0 }) });
  for (const path of memberPaths.toSorted()) {
    const synthesized = renamed.get(path);
    if (synthesized === undefined) refuse("workspace_member_invalid");
    files.push({
      path: `${synthesized.path}/package.json`,
      content: memberManifest(synthesized.name, manifests.get(path) ?? {}),
    });
    members.push({ synthesized: synthesized.path, real: path });
  }
  return { files, members };
}

// ---- Yarn classic (yarn.lock v1) ----

/** The sections a synthesized Yarn manifest declares (Yarn v1 never installs peers). */
const YARN_MANIFEST_SECTIONS: readonly DependencySection[] = [
  "dependencies",
  "devDependencies",
  "optionalDependencies",
];

/** A Yarn v1 lockfile word, always quoted (Yarn's lexer and Kovo's parser read either form). */
function yarnWord(value: string): string {
  return JSON.stringify(value);
}

/** The exact spec an importer declares for a registry instance under `alias`. */
function exactSpec(alias: string, instance: Instance): string {
  return alias === instance.name ? instance.version : `npm:${instance.name}@${instance.version}`;
}

/** Whether a declared spec admits the instance it resolves to (a tag admits any version). */
function satisfies(spec: string, instance: Instance): boolean {
  const classified = classifyDependencySpec(spec);
  if (classified.kind === "alias")
    return (
      classified.name === instance.name &&
      (classified.target.kind === "tag" ||
        semver.satisfies(instance.version, classified.target.range))
    );
  if (classified.kind === "tag") return true;
  if (classified.kind === "range") return semver.satisfies(instance.version, classified.range);
  return false;
}

/**
 * A Yarn v1 lockfile and manifest set for the open install. Each stanza is keyed by the ranges the
 * registry's own manifests declare (other entries' dependency edges) and by the exact specs the
 * synthesized importers declare; it keeps the version, the integrity, the dependency edges and the
 * customer lockfile's sha1 fragment (Yarn names its cache directories by it, so the sealed relink
 * finds the open install's cache offline), and its resolved URL is the job-scoped proxy's by
 * name@version. Workspace members are renamed; a member depends on another as
 * `kovo-ws-m<N>@0.0.0`. Entries nothing reaches are left out (the frozen install stays in sync).
 */
function synthesizeYarn(text: string, input: YarnOpenInstallInput): OpenInstallManifests {
  const registry = input.registryUrl;
  if (!/^https?:\/\/[^\s?#]+\/$/u.test(registry)) refuse("invalid_entry");
  let parsed: ReturnType<typeof parseYarnLockfile>;
  if (input.layout !== undefined)
    parsed = parseYarnLockfile(
      text,
      GRAPH_LIMITS,
      undefined,
      new WorkspaceParserContext(input.layout),
    );
  else if (input.manifest !== undefined)
    parsed = parseYarnLockfile(text, GRAPH_LIMITS, input.manifest);
  else refuse("lockfile_unsupported");
  if (!parsed.ok)
    refuse(yarnRefusal(parsed.rejections.rejections.map((rejection) => rejection.reason)));
  const { instances, root } = parsed.instances;
  // Opaque nodes stay on the restricted install path: the open install is
  // registry-only, as for npm and pnpm, whose synthesis refuses their non-registry entries.
  if ([...instances.values()].some((instance) => instance.opaque !== undefined))
    refuse("non_registry_dependency");
  const registryInstances = [...instances.values()].filter(
    (item) => item.localMember === undefined,
  );
  const fragments = yarnResolvedFragments(text);
  const memberPaths = (input.layout?.members ?? [])
    .map((member) => member.path)
    .filter((path) => path !== ".");
  const renamed = renameMembers(memberPaths);
  const memberNames = new Set(
    (input.layout?.members ?? []).flatMap((member) =>
      member.path === "." || member.manifest.name === null ? [] : [member.manifest.name],
    ),
  );

  // Every registry entry: sha512 integrity the lockfile itself records (Yarn's cache entry name
  // depends on it), and dependency edges whose targets satisfy them (resolutions are not mirrored).
  const keys = new Map<string, Set<string>>();
  const keyOf = (id: string): Set<string> => {
    let set = keys.get(id);
    if (set === undefined) {
      set = new Set();
      keys.set(id, set);
    }
    return set;
  };
  for (const instance of registryInstances) {
    if (
      instance.integrity === null ||
      instance.integrityAlgorithm !== "sha512" ||
      instance.integritySource === "registry"
    )
      refuse("integrity_missing");
    for (const edge of instance.edges) {
      if (memberNames.has(edge.alias)) refuse("member_name_dependency");
      if (edge.target === null || edge.range === null) continue;
      const target = instances.get(edge.target);
      if (target === undefined || target.localMember !== undefined)
        refuse("non_registry_dependency");
      if (!satisfies(edge.range, target)) refuse("yarn_resolutions");
      keyOf(target.id).add(`${edge.alias}@${edge.range}`);
    }
  }

  // Importer declarations, rewritten to exact versions or renamed members.
  const manifests = new Map<string, Record<string, Record<string, string>>>();
  for (const direct of root) {
    if (direct.section === "peerDependencies") continue;
    const importer = direct.importer ?? ".";
    const sections = manifests.get(importer) ?? {};
    manifests.set(importer, sections);
    const section = (sections[direct.section] ??= {});
    const target = direct.edge.target;
    if (target === null) refuse("unresolved_dependency");
    if (target.startsWith("workspace:")) {
      const member = renamed.get(target.slice("workspace:".length));
      if (member === undefined) refuse("non_registry_dependency");
      section[member.name] = SYNTHETIC_VERSION;
      continue;
    }
    const instance = instances.get(target);
    if (instance === undefined || instance.localMember !== undefined)
      refuse("non_registry_dependency");
    if (!satisfies(direct.spec, instance)) refuse("yarn_resolutions");
    const spec = exactSpec(direct.alias, instance);
    section[direct.alias] = spec;
    keyOf(instance.id).add(`${direct.alias}@${spec}`);
  }

  const stanzas: string[] = [];
  const sorted = registryInstances.toSorted((a, b) =>
    a.name === b.name ? semver.compare(a.version, b.version) : a.name < b.name ? -1 : 1,
  );
  for (const instance of sorted) {
    const selectors = [...(keys.get(instance.id) ?? [])].toSorted();
    if (selectors.length === 0) continue;
    const base = instance.name.slice(instance.name.lastIndexOf("/") + 1);
    const fragment = fragments.get(instance.id);
    const resolved = `${registry}${instance.name}/-/${base}-${instance.version}.tgz${
      fragment === undefined ? "" : `#${fragment}`
    }`;
    const lines = [
      `${selectors.map(yarnWord).join(", ")}:`,
      `  version ${JSON.stringify(instance.version)}`,
      `  resolved ${JSON.stringify(resolved)}`,
      `  integrity ${instance.integrity ?? ""}`,
    ];
    for (const [heading, optional] of [
      ["dependencies", false],
      ["optionalDependencies", true],
    ] as const) {
      const edges = instance.edges
        .filter((edge) => edge.optional === optional && edge.range !== null)
        .toSorted((a, b) => (a.alias < b.alias ? -1 : 1));
      if (edges.length === 0) continue;
      lines.push(`  ${heading}:`);
      for (const edge of edges)
        lines.push(`    ${yarnWord(edge.alias)} ${JSON.stringify(edge.range ?? "")}`);
    }
    stanzas.push(lines.join("\n"));
  }
  const lockfile = [
    "# THIS IS AN AUTOGENERATED FILE. DO NOT EDIT THIS FILE DIRECTLY.",
    "# yarn lockfile v1",
    "",
    "",
    stanzas.join("\n\n"),
    "",
  ].join("\n");

  const files: OpenInstallFile[] = [];
  const members: OpenInstallMember[] = [];
  const workspaces = [...renamed.values()].map((member) => member.path).toSorted();
  files.push(
    {
      path: "package.json",
      content: json({
        name: ROOT_NAME,
        version: SYNTHETIC_VERSION,
        private: true,
        ...(workspaces.length === 0 ? {} : { workspaces }),
        ...yarnSections(manifests.get(".") ?? {}),
      }),
    },
    { path: "yarn.lock", content: lockfile },
  );
  for (const path of memberPaths.toSorted()) {
    const synthesized = renamed.get(path);
    if (synthesized === undefined) refuse("workspace_member_invalid");
    files.push({
      path: `${synthesized.path}/package.json`,
      content: memberManifest(synthesized.name, yarnSections(manifests.get(path) ?? {})),
    });
    members.push({ synthesized: synthesized.path, real: path });
  }
  return { files, members };
}

/** Manifest sections in Yarn's order, each sorted by alias. */
function yarnSections(
  sections: Readonly<Record<string, Record<string, string>>>,
): Record<string, Record<string, string>> {
  const out: Record<string, Record<string, string>> = {};
  for (const section of YARN_MANIFEST_SECTIONS) {
    const entries = sections[section];
    if (entries === undefined || Object.keys(entries).length === 0) continue;
    out[section] = Object.fromEntries(
      Object.entries(entries).toSorted(([a], [b]) => (a < b ? -1 : 1)),
    );
  }
  return out;
}

/** The synthesis refusal of a Yarn lockfile the parser refused (a closed code, never content). */
function yarnRefusal(reasons: readonly string[]): OpenInstallRefusal {
  if (reasons.includes("too_many_packages") || reasons.includes("too_many_dependencies"))
    return "too_many_packages";
  if (reasons.includes("unsupported_lockfile_version")) return "lockfile_unsupported";
  if (reasons.some((reason) => reason.includes("integrity"))) return "integrity_missing";
  if (reasons.includes("dangling_reference")) return "unresolved_dependency";
  if (
    reasons.some(
      (reason) =>
        reason.includes("git") ||
        reason.includes("path") ||
        reason.includes("protocol") ||
        reason.includes("tarball") ||
        reason.includes("source"),
    )
  )
    return "non_registry_dependency";
  return "lockfile_unreadable";
}
