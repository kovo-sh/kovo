import semver from "semver";

import {
  FIX_ONLY_TOOLS,
  type FixOnlyPackageManager,
  type UnsupportedRepoReason,
} from "@kovo/contracts";

import { npmrcKeyName, tokenizeNpmrc } from "../manifest/npmrc-tokens.js";
import type { RuntimeCatalog } from "./compat.js";
import { detectPackageManager, YARN_BERRY_MARKERS } from "./detect.js";
import { STORED_LOCKFILE_NAMES, type StoredLockfileName } from "./parse.js";

// CI-first admission (#8256 R2, plans/js-coverage-phase1.md §2.2): a root Kovo can fix but not run.
// Kovo produces the change with its own pinned Yarn 4 or Bun in Sandbox A (or, without a lockfile,
// a range edit in package.json), Sandbox B never installs it (`can_verify` is false), and the
// repository's CI decides under owner D-674. This module holds the pure parts: which root layouts
// are fix-only, the keys-only readers of `.yarnrc.yml` and `bunfig.toml` (never a value), the runtime
// a fix-only root records, and the canonical form of a Bun lockfile Kovo's proxy resolved.
//
// Only the repository root is admitted this way: install-root discovery (`discovery/`) and the
// dependency gate keep refusing these layouts, so no repository gains a project (D-228).

/** The closed refusal details of fix-only roots (D-267), each with its coarse stored reason. */
export const FIX_ONLY_REFUSALS = {
  // A Yarn configuration that would run the repository's own code (committed plugins), or one Kovo
  // cannot read well enough to rule plugins out (owner D-726 keeps only this Yarn refusal).
  "pm_config_unsupported:yarn_plugin": "unsupported_package_manager",
  // `.yarn/cache` is committed (zero-installs): a lockfile-only update cannot add the archives.
  "pm_config_unsupported:yarn_zero_install": "unsupported_package_manager",
  // A `bunfig.toml` Kovo cannot read well enough to route its registries through the proxy.
  "pm_config_unsupported:bunfig_unreadable": "unsupported_package_manager",
  // The binary `bun.lockb`: trusted code cannot read or check it.
  "pm_lockfile_unsupported:bun_lockb": "unsupported_lockfile_format",
  // Both `bun.lock` and `bun.lockb`.
  "pm_lockfile_unsupported:bun_ambiguous": "ambiguous_package_manager",
} as const satisfies Record<string, UnsupportedRepoReason>;
export type FixOnlyRefusal = keyof typeof FIX_ONLY_REFUSALS;

export type FixOnlyDetection =
  | {
      readonly ok: true;
      readonly packageManager: FixOnlyPackageManager;
      readonly lockfileName: StoredLockfileName;
    }
  | { readonly ok: false; readonly refusal: FixOnlyRefusal }
  /** Not a fix-only layout: the caller keeps the ordinary detection's answer. */
  | null;

/**
 * The fix-only layout of a root from its file names, when the ordinary detection refuses it: Yarn
 * 4 (`yarn.lock` with `.yarnrc.yml` or a PnP file), Bun's text `bun.lock`, or no lockfile at all.
 * A root the ordinary detection admits, or refuses for another reason (two lockfiles, a shrinkwrap,
 * no package.json), is null. A Berry `yarn.lock` without a marker file is found by its content
 * (`isYarnBerryLockfile`) when the caller parses it.
 */
export function detectFixOnlyRoot(rootFiles: readonly string[]): FixOnlyDetection {
  const ordinary = detectPackageManager(rootFiles);
  if (ordinary.ok) return null;
  const present = new Set(rootFiles);
  if (ordinary.reason === "missing_lockfile")
    return {
      ok: true,
      packageManager: "manifest-only",
      lockfileName: STORED_LOCKFILE_NAMES["manifest-only"],
    };
  if (ordinary.reason !== "foreign_lockfile") return null;
  const others = ["package-lock.json", "pnpm-lock.yaml", "npm-shrinkwrap.json"];
  if (others.some((name) => present.has(name))) return null;
  const yarn = present.has("yarn.lock");
  const bunText = present.has("bun.lock");
  const bunBinary = present.has("bun.lockb");
  if (yarn && !bunText && !bunBinary && YARN_BERRY_MARKERS.some((name) => present.has(name)))
    return { ok: true, packageManager: "yarn-berry", lockfileName: "yarn.lock" };
  if (yarn) return null;
  if (bunText && bunBinary) return { ok: false, refusal: "pm_lockfile_unsupported:bun_ambiguous" };
  if (bunBinary) return { ok: false, refusal: "pm_lockfile_unsupported:bun_lockb" };
  if (bunText) return { ok: true, packageManager: "bun", lockfileName: "bun.lock" };
  return null;
}

/** The most bytes read of `.yarnrc.yml` or `bunfig.toml`. */
export const FIX_ONLY_CONFIG_MAX_BYTES = 64 * 1024;

/**
 * `.yarnrc.yml` keys whose value routes registry requests (scopes, registries, credentials). Owner
 * D-726: they are not refused; Sandbox A's copy of the file drops them (`yarnrcForProxy`), so the
 * environment-forced registry, the job-scoped proxy, serves every request.
 */
const YARN_REGISTRY_KEYS = new Set([
  "npmScopes",
  "npmRegistries",
  "npmRegistryServer",
  "npmAuthToken",
  "npmAuthIdent",
  "npmAlwaysAuth",
  "npmPublishRegistry",
]);
/** `.yarnrc.yml` keys that change how Yarn reaches the network (proxies, TLS files, per host). */
const YARN_NETWORK_KEYS = new Set([
  "networkSettings",
  "httpProxy",
  "httpsProxy",
  "httpsCaFilePath",
  "httpsCertFilePath",
  "httpsKeyFilePath",
  "caFilePath",
  "unsafeHttpWhitelist",
  "enableStrictSsl",
]);

/** One top-level block of a config file: its key and its lines `[start, end)`. */
interface Block {
  readonly key: string;
  readonly start: number;
  readonly end: number;
}

/**
 * The top-level blocks of a `.yarnrc.yml`, or null when Kovo cannot read it. Keys only: a block is
 * a top-level key line and the indented, blank or comment lines below it; values are never read.
 * Anything outside Yarn's plain block style (a tab, a flow or quoted key, an anchor, a merge key, a
 * document marker, a duplicate key) is unreadable rather than guessed at. So are the two shapes a
 * YAML reader splits differently from this scanner (review round 2, N1): a lone carriage return,
 * which YAML reads as a line break, and an indented line before the first top-level key, which a
 * YAML reader may read as the document's first key (a hidden `plugins` or `npmScopes`).
 */
function yarnrcBlocks(text: string): Block[] | null {
  const lines = text.split("\n");
  const blocks: { key: string; start: number }[] = [];
  const keys = new Set<string>();
  for (const [index, raw] of lines.entries()) {
    const line = raw.endsWith("\r") ? raw.slice(0, -1) : raw;
    if (line.includes("\t") || line.includes("\r")) return null;
    if (blocks.length === 0 && /^\s+[^\s#]/u.test(line)) return null;
    if (line === "" || line.startsWith("#") || /^\s/u.test(line)) continue;
    const match = /^([A-Za-z][A-Za-z0-9]*):(?:\s|$)/u.exec(line);
    if (match === null || keys.has(match[1]!)) return null;
    keys.add(match[1]!);
    blocks.push({ key: match[1]!, start: index });
  }
  return blocks.map((block, index) => ({
    key: block.key,
    start: block.start,
    end: blocks[index + 1]?.start ?? lines.length,
  }));
}

/**
 * Why a Yarn 4 root's `.yarnrc.yml` refuses the fix, or null. Owner D-726 keeps exactly one
 * refusal: `plugins` (Yarn would run the repository's own plugin code in Sandbox A), and a file
 * Kovo cannot read well enough to rule plugins out. Registry, scope and network keys are routed
 * through the proxy instead (`yarnrcForProxy`); `yarnPath` never runs (`YARN_IGNORE_PATH`).
 */
export function yarnrcRefusal(text: string | null): FixOnlyRefusal | null {
  if (text === null) return null;
  const blocks = yarnrcBlocks(text);
  return blocks === null || blocks.some((block) => block.key === "plugins")
    ? "pm_config_unsupported:yarn_plugin"
    : null;
}

/**
 * Sandbox A's copy of a Yarn 4 root's `.yarnrc.yml` (owner D-726), or null when it names no
 * registry, scope or network setting (the file stays as committed). Each such top-level block is
 * dropped whole, by key, never reading a value; every other line stays byte for byte. With the
 * registry forced to the job-scoped proxy by `YARN_NPM_REGISTRY_SERVER`, every package, scoped ones
 * included, is then fetched through the proxy's malware and advisory screening. A package that
 * exists only on a private registry is then not found, and the fix fails without leaving the
 * sandbox. The copy is written into the sandbox checkout before each command and never staged.
 */
export function yarnrcForProxy(text: string | null): string | null {
  if (text === null) return null;
  const blocks = yarnrcBlocks(text);
  if (blocks === null) return null;
  const dropped = blocks.filter(
    (block) => YARN_REGISTRY_KEYS.has(block.key) || YARN_NETWORK_KEYS.has(block.key),
  );
  if (dropped.length === 0) return null;
  return withoutBlocks(text, dropped);
}

/** `text` without the lines of `dropped`, keeping the file's final newline. */
function withoutBlocks(text: string, dropped: readonly Block[]): string {
  const kept = text
    .split("\n")
    .filter((_, index) => !dropped.some((block) => index >= block.start && index < block.end))
    .join("\n");
  return text.endsWith("\n") && !kept.endsWith("\n") && kept !== "" ? `${kept}\n` : kept;
}

/**
 * The tables and assignments of a `bunfig.toml`, with their lines, or null when Kovo cannot read
 * it. Keys only: table headers and bare (dotted) keys are read, never a value; a value spanning
 * lines (an array, an inline table, a multi-line string) is followed by its brackets and quotes. A
 * quoted key, an unterminated value or any line that is not a header or a `key = value` is
 * unreadable. A table's block runs to the next header; an assignment's to its value's last line.
 */
function bunfigBlocks(text: string): { tables: Block[]; entries: Block[] } | null {
  const lines = text.split("\n");
  const tables: { key: string; start: number }[] = [];
  const entries: Block[] = [];
  let table = "";
  const seen = new Set<string>();
  let depth = 0;
  let multiline: '"""' | "'''" | null = null;
  const consume = (value: string): boolean => {
    let index = 0;
    while (index < value.length) {
      if (multiline !== null) {
        const end = value.indexOf(multiline, index);
        if (end < 0) return true;
        index = end + 3;
        multiline = null;
        continue;
      }
      const char = value[index]!;
      if (value.startsWith('"""', index) || value.startsWith("'''", index)) {
        multiline = value.startsWith('"""', index) ? '"""' : "'''";
        index += 3;
      } else if (char === '"' || char === "'") {
        let end = index + 1;
        while (end < value.length && value[end] !== char)
          end += char === '"' && value[end] === "\\" ? 2 : 1;
        if (end >= value.length) return false;
        index = end + 1;
      } else if (char === "#") return true;
      else {
        if (char === "[" || char === "{") depth += 1;
        if (char === "]" || char === "}") depth -= 1;
        if (depth < 0) return false;
        index += 1;
      }
    }
    return true;
  };
  let open: { key: string; start: number } | null = null;
  for (const [index, raw] of lines.entries()) {
    const line = raw.endsWith("\r") ? raw.slice(0, -1) : raw;
    if (multiline !== null || depth > 0) {
      if (!consume(line)) return null;
      if (multiline === null && depth === 0 && open !== null) {
        entries.push({ ...open, end: index + 1 });
        open = null;
      }
      continue;
    }
    const trimmed = line.trim();
    if (trimmed === "" || trimmed.startsWith("#")) continue;
    const header = /^\[\[?\s*([A-Za-z0-9_-]+(?:\s*\.\s*[A-Za-z0-9_-]+)*)\s*\]\]?\s*(?:#.*)?$/u.exec(
      trimmed,
    );
    if (header !== null) {
      table = header[1]!.replace(/\s+/gu, "");
      tables.push({ key: table, start: index });
      continue;
    }
    const assignment = /^([A-Za-z0-9_-]+(?:\s*\.\s*[A-Za-z0-9_-]+)*)\s*=(.*)$/u.exec(trimmed);
    if (assignment === null) return null;
    const key = assignment[1]!.replace(/\s+/gu, "");
    const full = table === "" ? key : `${table}.${key}`;
    if (seen.has(full)) return null;
    seen.add(full);
    if (!consume(assignment[2] ?? "")) return null;
    if (multiline !== null || depth > 0) open = { key: full, start: index };
    else entries.push({ key: full, start: index, end: index + 1 });
  }
  if (multiline !== null || depth !== 0) return null;
  return {
    tables: tables.map((block, index) => ({
      key: block.key,
      start: block.start,
      end: tables[index + 1]?.start ?? lines.length,
    })),
    entries,
  };
}

/** A `bunfig.toml` key or table that names a registry or a scope's registry. */
function bunfigRegistryKey(key: string): boolean {
  return /^install\.(?:registry|scopes)(?:\.|$)/u.test(key);
}

/**
 * Why a Bun root's `bunfig.toml` refuses the fix, or null: only a file Kovo cannot read well
 * enough to route its registries through the proxy (owner D-726). Registry and scope settings are
 * routed instead (`bunfigForProxy`; `--registry` already beats `[install] registry`).
 */
export function bunfigRefusal(text: string | null): FixOnlyRefusal | null {
  if (text === null) return null;
  return bunfigBlocks(text) === null ? "pm_config_unsupported:bunfig_unreadable" : null;
}

/**
 * Sandbox A's copy of a Bun root's `bunfig.toml` (owner D-726), or null when it names no registry
 * or scope (the file stays as committed). Every `install.registry*` and `install.scopes*` table and
 * assignment is dropped whole, by key, never reading a value; every other line stays byte for
 * byte. Bun then resolves every package, scoped ones included, at `--registry`, the job-scoped
 * proxy. The copy is written into the sandbox checkout before each command and never staged.
 */
export function bunfigForProxy(text: string | null): string | null {
  if (text === null) return null;
  const blocks = bunfigBlocks(text);
  if (blocks === null) return null;
  // A whole `install = { … }` inline table may hold `scopes` or `registry` too (review round 2,
  // N2): it is dropped whole, as values are never read.
  const dropped = [
    ...blocks.tables.filter((block) => bunfigRegistryKey(block.key)),
    ...blocks.entries.filter((block) => bunfigRegistryKey(block.key) || block.key === "install"),
  ];
  if (dropped.length === 0) return null;
  return withoutBlocks(text, dropped);
}

/**
 * A Bun root's project `.npmrc` with every registry routed through the job-scoped proxy (#8256 R2,
 * review N1), or null when it names no registry (nothing to rewrite). Bun reads a project
 * `.npmrc`, and a scope line (`@acme:registry=…`) is not covered by `--registry`: left alone, Bun
 * would resolve that scope at the named registry itself, past the proxy's malware and advisory
 * screening. Admission has already judged the file (`checkNpmrc`: only the public registry may be
 * named, so a private registry stays refused as `scoped_registry`/`registry_override`). Here the
 * keys alone decide: each `registry` or `<scope>:registry` line is replaced whole by the same key
 * naming `registryUrl` (its value is never read), every other line stays byte for byte, and one
 * credential line for the proxy expands the per-command capability variable, so the token never
 * appears in the file. Trusted code writes the result into the sandbox checkout only, before each
 * command; it is never read back or staged (a candidate changes only package.json and the lockfile).
 * Null too for a file the strict tokenizer cannot read: `checkNpmrc` refuses those first.
 */
export function bunNpmrcForProxy(text: string | null, registryUrl: string): string | null {
  if (text === null) return null;
  const tokens = tokenizeNpmrc(text);
  if (!tokens.ok) return null;
  const lines = text.split("\n");
  let rewritten = false;
  for (const entry of tokens.entries) {
    const key = npmrcKeyName(entry.key);
    if (key !== "registry" && !key.endsWith(":registry")) continue;
    lines[entry.line - 1] = `${entry.key}=${registryUrl}`;
    rewritten = true;
  }
  if (!rewritten) return null;
  const nerfDart = registryUrl.replace(/^https?:/u, "");
  return `${lines.join("\n").replace(/\n?$/u, "\n")}${nerfDart}:_authToken=\${KOVO_REGISTRY_TOKEN}\n`;
}

/**
 * The runtime a fix-only root records: the newest baked Node of the catalog's default major and the
 * pinned tool's version (for a lockfile-less root, that Node's bundled npm, which runs nothing).
 * Kovo's own tool runs these roots, so the repository's declarations do not choose a release.
 */
export function fixOnlyRuntime(
  catalog: RuntimeCatalog,
  packageManager: FixOnlyPackageManager,
): { readonly node: string; readonly pmVersion: string } {
  const node = catalog.node
    .filter((entry) => semver.major(entry.version) === catalog.defaultNodeMajor)
    .toSorted((a, b) => semver.rcompare(a.version, b.version))[0];
  if (node === undefined) throw new RangeError("the catalog bakes its default Node major");
  return {
    node: node.version,
    pmVersion:
      packageManager === "manifest-only" ? node.npm : FIX_ONLY_TOOLS[packageManager].version,
  };
}

/**
 * A candidate `bun.lock` with the proxy's tarball URLs put back to the default registry (`""`).
 * Bun records the tarball URL of every package it resolved from a registry other than its default,
 * so a lockfile-only update through Kovo's proxy would name the proxy in every entry (Bun 1.4.4,
 * verified in a worker). Only the exact JSON string `"<registryUrl><name>/-/<file>.tgz"` (the
 * proxy's standard tarball path, which the pnpm route's packuments name) is replaced; the proxy
 * serves the public registry's own tarballs, so the default registry is the canonical source. Any
 * other mention of the proxy stays and fails the candidate's `proxy_reference` check.
 */
export function canonicalBunLockfile(text: string, registryUrl: string): string {
  if (!registryUrl.endsWith("/")) throw new RangeError("the registry URL ends with a slash");
  const escaped = registryUrl.replace(/[.*+?^${}()|[\]\\/]/gu, "\\$&");
  const pattern = new RegExp(
    `"${escaped}(?:@[a-z0-9][a-z0-9._~-]*/)?[a-z0-9][a-z0-9._~-]*/-/[A-Za-z0-9._~-]+\\.tgz"`,
    "gu",
  );
  return text.replace(pattern, '""');
}
