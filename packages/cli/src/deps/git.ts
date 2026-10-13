import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { lstat, readdir, readFile } from "node:fs/promises";
import { join } from "node:path";

import { usageError } from "../errors.js";

// Reads a project's files at a commit (through `git`) or in the working tree, into memory only.
// Nothing is written to disk: a lockfile is a child process's stdout or one file read, held in a
// buffer for the parse and dropped (plans/dependency-firewall.md Part 2: "send only the change
// list, never the lockfile").

export type TreeMode = "file" | "directory" | "symlink" | "submodule";

/** One entry of a project's tree, relative to the project directory (POSIX separators). */
export interface TreeEntry {
  readonly path: string;
  readonly mode: TreeMode;
  /** The git object ID; all zeros for an untracked working-tree file that was not read. */
  readonly oid: string;
}

/** One side of the diff: a commit's tree or the working tree, below the project directory. */
export interface ProjectReader {
  /** An abbreviated commit, or "working tree". */
  readonly label: string;
  /** The commit, or null for the working tree. */
  readonly commit: string | null;
  /** Names at the project root; null when the project directory does not exist there. */
  rootFiles(): Promise<readonly string[] | null>;
  /**
   * A regular file's bytes; null when it does not exist. Errors (exit 2): a symlink or other
   * non-file, or more than `maxBytes`.
   */
  readFile(path: string, maxBytes: number): Promise<Uint8Array | null>;
  /** Every entry below the project directory, directories included where the source lists them. */
  listTree(maxEntries: number): Promise<readonly TreeEntry[]>;
  /** The listed regular files' bytes, in order; at most `maxTotalBytes` together. */
  readEntries(
    entries: readonly TreeEntry[],
    maxBytes: (path: string) => number,
    maxTotalBytes: number,
  ): Promise<readonly Uint8Array[]>;
}

const UNREAD_OID = "0".repeat(40);
const MAX_LISTING_BYTES = 64 * 1024 * 1024;
const MAX_SMALL_OUTPUT = 1024 * 1024;

export interface GitResult {
  readonly status: number | null;
  readonly stdout: Buffer;
  /** stdout exceeded the bound: the process was stopped and `stdout` is incomplete. */
  readonly overflow: boolean;
}

/** The environment a child git gets: the caller's, without the Kovo API key. */
export function childEnvironment(
  env: Readonly<Record<string, string | undefined>>,
): NodeJS.ProcessEnv {
  const out: NodeJS.ProcessEnv = {};
  for (const [name, value] of Object.entries(env))
    if (value !== undefined && name !== "KOVO_API_KEY") out[name] = value;
  // Never prompt, and never take optional locks in a checkout another process may be using.
  out["GIT_TERMINAL_PROMPT"] = "0";
  out["GIT_OPTIONAL_LOCKS"] = "0";
  // Paths are literal paths, never pathspec magic.
  out["GIT_LITERAL_PATHSPECS"] = "1";
  return out;
}

/**
 * Runs `git` with a bound on stdout, kept in memory. stderr is discarded: it can echo paths or
 * contents and is never printed. `core.fsmonitor` is off, so listing a working tree never starts a
 * repository-configured hook program.
 */
export function runGit(
  cwd: string,
  args: readonly string[],
  env: NodeJS.ProcessEnv,
  maxBytes: number,
  input?: string,
): Promise<GitResult> {
  return new Promise((resolve, reject) => {
    const child = spawn(
      "git",
      ["-c", "core.fsmonitor=false", "-c", "core.quotePath=false", ...args],
      { cwd, env, stdio: [input === undefined ? "ignore" : "pipe", "pipe", "ignore"] },
    );
    const chunks: Buffer[] = [];
    let size = 0;
    let overflow = false;
    child.stdout?.on("data", (chunk: Buffer) => {
      if (overflow) return;
      size += chunk.byteLength;
      if (size > maxBytes) {
        overflow = true;
        child.kill("SIGKILL");
        return;
      }
      chunks.push(chunk);
    });
    child.on("error", (error: NodeJS.ErrnoException) => {
      reject(
        error.code === "ENOENT"
          ? usageError("git_missing", "git is not installed or not on PATH.")
          : usageError("git_failed", "git could not be started."),
      );
    });
    child.on("close", (status) => resolve({ status, stdout: Buffer.concat(chunks), overflow }));
    if (input !== undefined && child.stdin !== null) {
      // The process may exit before reading every line (a bound was hit); `close` reports it.
      child.stdin.on("error", () => {});
      child.stdin.end(input);
    }
  });
}

async function gitOk(
  cwd: string,
  args: readonly string[],
  env: NodeJS.ProcessEnv,
  maxBytes = MAX_SMALL_OUTPUT,
  input?: string,
): Promise<Buffer | null> {
  const result = await runGit(cwd, args, env, maxBytes, input);
  if (result.overflow)
    throw usageError("too_large", "The repository listing exceeds the CLI's bounds.");
  return result.status === 0 ? result.stdout : null;
}

function records(output: Buffer): string[] {
  const text = output.toString("utf8");
  return text.split("\0").filter((record) => record !== "");
}

function modeOf(raw: string): TreeMode {
  switch (raw) {
    case "100644":
    case "100755":
      return "file";
    case "040000":
      return "directory";
    case "120000":
      return "symlink";
    case "160000":
      return "submodule";
    default:
      throw usageError("unsupported_tree", "The repository tree has an entry of an unknown kind.");
  }
}

function checkEntryCount(count: number, maxEntries: number): void {
  if (count > maxEntries)
    throw usageError("too_large", "The project has more files than the CLI reads.");
}

/** The git blob ID of `bytes`, in the hash `like` uses (SHA-1, or SHA-256 for 64-digit IDs). */
export function blobOid(bytes: Uint8Array, like: string): string {
  return createHash(like.length === 64 ? "sha256" : "sha1")
    .update(`blob ${bytes.byteLength}\0`)
    .update(bytes)
    .digest("hex");
}

/** Validates a user-supplied ref before git sees it: never an option, never a pathspec. */
export function checkRef(ref: string, flag: string): string {
  let unsafe = false;
  for (const char of ref) {
    const code = char.codePointAt(0) ?? 0;
    if (code <= 0x20 || code === 0x7f || char === ":") unsafe = true;
  }
  if (ref === "" || ref.startsWith("-") || unsafe)
    throw usageError("invalid_ref", `${flag} must name a commit (a branch, tag or SHA).`);
  return ref;
}

/** The repository's top-level directory for `cwd`. Error (exit 2): not inside a git work tree. */
export async function repositoryRoot(cwd: string, env: NodeJS.ProcessEnv): Promise<string> {
  const out = await gitOk(cwd, ["rev-parse", "--show-toplevel"], env);
  const root = out?.toString("utf8").replace(/\n$/u, "");
  if (root === undefined || root === "")
    throw usageError("not_a_repository", "Run kovo deps check inside a git repository.");
  return root;
}

/** The full commit ID `ref` names. Error (exit 2): it names no commit here. */
export async function resolveCommit(
  root: string,
  ref: string,
  flag: string,
  env: NodeJS.ProcessEnv,
): Promise<string> {
  const out = await gitOk(
    root,
    ["rev-parse", "--verify", "--quiet", `${checkRef(ref, flag)}^{commit}`],
    env,
  );
  const sha = out?.toString("utf8").trim();
  if (sha === undefined || !/^(?:[0-9a-f]{40}|[0-9a-f]{64})$/u.test(sha))
    throw usageError("unknown_ref", `${flag} ${ref} names no commit in this repository.`);
  return sha;
}

/** Remote-tracking default branches tried, in order, after `origin/HEAD`. */
const DEFAULT_BRANCHES = ["refs/remotes/origin/main", "refs/remotes/origin/master"];

/**
 * The default base: the merge base of the default branch and `head` (a commit, or HEAD for the
 * working tree). The default branch is what `origin/HEAD` points at, else `origin/main`, else
 * `origin/master`. Errors (exit 2): no default branch is known, or no merge base exists (a shallow
 * clone or unrelated history).
 */
export async function defaultBase(
  root: string,
  head: string | null,
  env: NodeJS.ProcessEnv,
): Promise<{ readonly commit: string; readonly branch: string }> {
  const symbolic = await gitOk(root, ["symbolic-ref", "--quiet", "refs/remotes/origin/HEAD"], env);
  const candidates = [
    ...(symbolic === null ? [] : [symbolic.toString("utf8").trim()]),
    ...DEFAULT_BRANCHES,
  ].filter((ref) => ref.startsWith("refs/remotes/"));
  for (const ref of candidates) {
    const exists = await gitOk(root, ["rev-parse", "--verify", "--quiet", `${ref}^{commit}`], env);
    if (exists === null) continue;
    const base = await gitOk(root, ["merge-base", ref, head ?? "HEAD"], env);
    const commit = base?.toString("utf8").trim();
    const branch = ref.slice("refs/remotes/".length);
    if (commit === undefined || !/^(?:[0-9a-f]{40}|[0-9a-f]{64})$/u.test(commit))
      throw usageError(
        "no_merge_base",
        `No merge base with ${branch}: fetch the full history (for example fetch-depth: 0) or pass --base.`,
      );
    return { commit, branch };
  }
  throw usageError(
    "no_default_branch",
    "No default branch found (origin/HEAD, origin/main or origin/master): pass --base.",
  );
}

function joinPrefix(prefix: string, path: string): string {
  return prefix === "" ? path : `${prefix}/${path}`;
}

/** Reads blobs by object ID in one `git cat-file` pair: sizes first, then the bounded contents. */
async function readBlobs(
  root: string,
  env: NodeJS.ProcessEnv,
  blobs: readonly { readonly oid: string; readonly path: string; readonly maxBytes: number }[],
  maxTotalBytes: number,
): Promise<Uint8Array[]> {
  if (blobs.length === 0) return [];
  const input = `${blobs.map((blob) => blob.oid).join("\n")}\n`;
  const check = await gitOk(root, ["cat-file", "--batch-check"], env, MAX_SMALL_OUTPUT * 8, input);
  const lines =
    check
      ?.toString("utf8")
      .split("\n")
      .filter((line) => line !== "") ?? [];
  if (lines.length !== blobs.length)
    throw usageError("unreadable_file", "A file could not be read from the repository.");
  let total = 0;
  for (const [index, line] of lines.entries()) {
    const blob = blobs[index]!;
    const match = /^([0-9a-f]+) blob (\d+)$/u.exec(line);
    if (match === null || match[1] !== blob.oid)
      throw usageError("unreadable_file", `${blob.path} could not be read from the repository.`);
    const size = Number(match[2]);
    if (size > blob.maxBytes)
      throw usageError("too_large", `${blob.path} exceeds the CLI's bounds.`);
    total += size;
  }
  if (total > maxTotalBytes)
    throw usageError("too_large", "The project's files exceed the CLI's bounds.");
  const out = await gitOk(root, ["cat-file", "--batch"], env, total + blobs.length * 200, input);
  if (out === null)
    throw usageError("unreadable_file", "A file could not be read from the repository.");
  const contents: Uint8Array[] = [];
  let offset = 0;
  for (const blob of blobs) {
    const newline = out.indexOf(0x0a, offset);
    const header = newline === -1 ? "" : out.subarray(offset, newline).toString("utf8");
    const match = /^([0-9a-f]+) blob (\d+)$/u.exec(header);
    if (match === null || match[1] !== blob.oid)
      throw usageError("unreadable_file", `${blob.path} could not be read from the repository.`);
    const size = Number(match[2]);
    const start = newline + 1;
    contents.push(new Uint8Array(out.subarray(start, start + size)));
    offset = start + size + 1;
  }
  return contents;
}

/** A project directory in a commit's tree. */
export class CommitReader implements ProjectReader {
  readonly label: string;
  readonly commit: string;
  readonly #root: string;
  readonly #prefix: string;
  readonly #env: NodeJS.ProcessEnv;

  constructor(root: string, commit: string, prefix: string, env: NodeJS.ProcessEnv) {
    this.#root = root;
    this.commit = commit;
    this.label = commit.slice(0, 12);
    this.#prefix = prefix;
    this.#env = env;
  }

  async rootFiles(): Promise<readonly string[] | null> {
    const out = await gitOk(
      this.#root,
      ["ls-tree", "-z", "--name-only", `${this.commit}:${this.#prefix}`],
      this.#env,
      MAX_LISTING_BYTES,
    );
    return out === null ? null : records(out);
  }

  async readFile(path: string, maxBytes: number): Promise<Uint8Array | null> {
    const full = joinPrefix(this.#prefix, path);
    const out = await gitOk(
      this.#root,
      ["ls-tree", "-z", "--full-tree", this.commit, "--", full],
      this.#env,
    );
    const entry = out === null ? undefined : records(out)[0];
    if (entry === undefined) return null;
    const match = /^(\d{6}) (\w+) ([0-9a-f]+)\t(.*)$/su.exec(entry);
    if (match === null || match[4] !== full) return null;
    if (modeOf(match[1]!) !== "file")
      throw usageError("not_a_file", `${full} is not a regular file at ${this.label}.`);
    const [bytes] = await readBlobs(
      this.#root,
      this.#env,
      [{ oid: match[3]!, path: full, maxBytes }],
      maxBytes,
    );
    return bytes ?? null;
  }

  async listTree(maxEntries: number): Promise<readonly TreeEntry[]> {
    const out = await gitOk(
      this.#root,
      ["ls-tree", "-r", "-t", "-z", `${this.commit}:${this.#prefix}`],
      this.#env,
      MAX_LISTING_BYTES,
    );
    if (out === null)
      throw usageError("unreadable_tree", `The project tree at ${this.label} could not be listed.`);
    const lines = records(out);
    checkEntryCount(lines.length, maxEntries);
    return lines.map((line) => {
      const match = /^(\d{6}) (\w+) ([0-9a-f]+)\t(.*)$/su.exec(line);
      if (match === null)
        throw usageError(
          "unreadable_tree",
          `The project tree at ${this.label} could not be listed.`,
        );
      return { path: match[4]!, mode: modeOf(match[1]!), oid: match[3]! };
    });
  }

  readEntries(
    entries: readonly TreeEntry[],
    maxBytes: (path: string) => number,
    maxTotalBytes: number,
  ): Promise<readonly Uint8Array[]> {
    return readBlobs(
      this.#root,
      this.#env,
      entries.map((entry) => ({
        oid: entry.oid,
        path: joinPrefix(this.#prefix, entry.path),
        maxBytes: maxBytes(entry.path),
      })),
      maxTotalBytes,
    );
  }
}

function missing(error: unknown): boolean {
  if (!(error instanceof Error) || !("code" in error)) return false;
  return error.code === "ENOENT" || error.code === "ENOTDIR";
}

/** A project directory in the working tree (tracked and untracked, ignoring ignored files). */
export class WorkingTreeReader implements ProjectReader {
  readonly label = "working tree";
  readonly commit = null;
  readonly #dir: string;
  readonly #env: NodeJS.ProcessEnv;

  /** `dir` is the project directory's absolute path. */
  constructor(dir: string, env: NodeJS.ProcessEnv) {
    this.#dir = dir;
    this.#env = env;
  }

  async rootFiles(): Promise<readonly string[] | null> {
    try {
      return await readdir(this.#dir);
    } catch (error) {
      if (missing(error)) return null;
      throw usageError("unreadable_file", "The project directory could not be read.");
    }
  }

  async readFile(path: string, maxBytes: number): Promise<Uint8Array | null> {
    const absolute = join(this.#dir, path);
    let stats;
    try {
      stats = await lstat(absolute);
    } catch (error) {
      if (missing(error)) return null;
      throw usageError("unreadable_file", `${path} could not be read.`);
    }
    if (!stats.isFile()) throw usageError("not_a_file", `${path} is not a regular file.`);
    if (stats.size > maxBytes) throw usageError("too_large", `${path} exceeds the CLI's bounds.`);
    let bytes: Buffer;
    try {
      bytes = await readFile(absolute);
    } catch {
      throw usageError("unreadable_file", `${path} could not be read.`);
    }
    if (bytes.byteLength > maxBytes)
      throw usageError("too_large", `${path} exceeds the CLI's bounds.`);
    return new Uint8Array(bytes);
  }

  async listTree(maxEntries: number): Promise<readonly TreeEntry[]> {
    const list = async (args: readonly string[]): Promise<string[]> => {
      const out = await gitOk(this.#dir, ["ls-files", "-z", ...args], this.#env, MAX_LISTING_BYTES);
      if (out === null)
        throw usageError("unreadable_tree", "The working tree could not be listed.");
      return records(out);
    };
    const deleted = new Set(await list(["--deleted"]));
    const entries: TreeEntry[] = [];
    for (const line of await list(["--stage", "--cached"])) {
      const match = /^(\d{6}) ([0-9a-f]+) (\d)\t(.*)$/su.exec(line);
      if (match === null)
        throw usageError("unreadable_tree", "The working tree could not be listed.");
      if (match[3] !== "0")
        throw usageError(
          "unmerged_paths",
          "The working tree has unmerged paths: resolve them first.",
        );
      if (deleted.has(match[4]!)) continue;
      entries.push({ path: match[4]!, mode: modeOf(match[1]!), oid: match[2]! });
      checkEntryCount(entries.length, maxEntries);
    }
    for (const listed of await list(["--others", "--exclude-standard"])) {
      // A nested repository is listed as a directory with a trailing slash.
      const path = listed.replace(/\/+$/u, "");
      let stats;
      try {
        stats = await lstat(join(this.#dir, path));
      } catch {
        continue;
      }
      const mode: TreeMode = stats.isSymbolicLink()
        ? "symlink"
        : stats.isDirectory()
          ? "submodule"
          : "file";
      entries.push({ path, mode, oid: UNREAD_OID });
      checkEntryCount(entries.length, maxEntries);
    }
    return entries;
  }

  async readEntries(
    entries: readonly TreeEntry[],
    maxBytes: (path: string) => number,
    maxTotalBytes: number,
  ): Promise<readonly Uint8Array[]> {
    const contents: Uint8Array[] = [];
    let total = 0;
    for (const entry of entries) {
      const bytes = await this.readFile(entry.path, maxBytes(entry.path));
      if (bytes === null)
        throw usageError("unreadable_file", `${entry.path} changed while it was being read.`);
      total += bytes.byteLength;
      if (total > maxTotalBytes)
        throw usageError("too_large", "The project's files exceed the CLI's bounds.");
      contents.push(bytes);
    }
    return contents;
  }
}
