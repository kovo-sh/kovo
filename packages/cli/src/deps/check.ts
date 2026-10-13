import { realpath } from "node:fs/promises";
import { basename, dirname, isAbsolute, join, relative, resolve, sep } from "node:path";

import type { DependencyVerdictChangeWire, DependencyVerdictWire } from "@kovo/contracts";
import { LOCKFILE_NAMES, detectPackageManager, type LockfileName } from "@kovo/core/lockfile";

import { CliError, unavailableError, usageError } from "../errors.js";
import type { ExitCode } from "../exit.js";
import type { CliIo } from "../io.js";
import { DEFAULT_API_URL, hostedVerdicts, parseApiUrl } from "./api.js";
import type { UnsupportedLockfile } from "./change-list.js";
import {
  childEnvironment,
  CommitReader,
  defaultBase,
  repositoryRoot,
  resolveCommit,
  WorkingTreeReader,
  type ProjectReader,
} from "./git.js";
import { offlineVerdicts } from "./offline/evaluate.js";
import { OSV_STORAGE_ORIGIN } from "./offline/osv-snapshot.js";
import { NPM_REGISTRY_URL } from "./offline/registry.js";
import {
  renderError,
  renderJson,
  renderText,
  unsupportedLockfileError,
  verdictExitCode,
  type CheckContext,
  type CheckReport,
} from "./report.js";
import { readChangeList, UnsupportedLockfileError } from "./snapshot.js";

// `kovo deps check` (plans/dependency-firewall.md Part 2 "Distribution for any CI", Part 3b and
// Part 4 items 3-4): diff the lockfile between a base commit and the head (the working tree by
// default), judge only the changed and new versions (online: the hosted check gets the change list;
// offline: the same engine over OSV's public export and the public registry), print the verdicts
// and exit 0, 1, 2 or 3.

/** The environment variable the API key is read from; never a flag. */
export const API_KEY_ENV = "KOVO_API_KEY";

export interface OnlineMode {
  readonly kind: "online";
  readonly apiUrl: string | undefined;
}

export interface OfflineMode {
  readonly kind: "offline";
  readonly osvCache: string | undefined;
  readonly osvGeneration: string | undefined;
  readonly osvUrl: string | undefined;
  readonly registryUrl: string | undefined;
}

export interface DepsCheckOptions {
  readonly base: string | undefined;
  readonly head: string | undefined;
  readonly lockfile: string | undefined;
  readonly format: "text" | "json";
  readonly mode: OnlineMode | OfflineMode;
}

/** The verdicts for a change list, from the hosted check or the offline engine. */
export interface Answer {
  readonly verdicts: readonly DependencyVerdictWire[];
  readonly unavailableSignals: readonly string[];
  readonly osvSnapshot: CheckReport["osvSnapshot"];
}

export type Judge = (changes: readonly DependencyVerdictChangeWire[]) => Promise<Answer>;

/** The default OSV cache: `$XDG_CACHE_HOME/kovo/osv`, else `~/.cache/kovo/osv`. */
export function defaultOsvCache(env: CliIo["env"]): string {
  const xdg = env["XDG_CACHE_HOME"];
  if (xdg !== undefined && isAbsolute(xdg)) return join(xdg, "kovo", "osv");
  const home = env["HOME"];
  if (home !== undefined && isAbsolute(home)) return join(home, ".cache", "kovo", "osv");
  throw usageError("osv_cache_unknown", "No cache directory is known: pass --osv-cache.");
}

/** How the change list is judged, checked before any git or network work. */
export function judgeFor(mode: OnlineMode | OfflineMode, io: CliIo): Judge {
  if (mode.kind === "online") {
    const key = apiKeyFrom(io.env);
    const apiUrl = parseApiUrl(mode.apiUrl ?? DEFAULT_API_URL);
    return async (changes) => {
      const answer = await hostedVerdicts(
        changes,
        { apiUrl, key, fetch: io.fetch, sleep: io.sleep },
        io.now,
      );
      return {
        verdicts: answer.verdicts,
        unavailableSignals: answer.unavailable_signals,
        osvSnapshot: null,
      };
    };
  }
  if (mode.osvGeneration !== undefined && !/^\d{1,20}$/u.test(mode.osvGeneration))
    throw usageError("invalid_osv_generation", "--osv-generation must be an object generation.");
  const osv = {
    origin: parseApiUrl(mode.osvUrl ?? OSV_STORAGE_ORIGIN, "--osv-url"),
    cacheDir: resolve(io.cwd, mode.osvCache ?? defaultOsvCache(io.env)),
    generation: mode.osvGeneration ?? null,
  };
  const registry = {
    registryUrl: parseApiUrl(mode.registryUrl ?? NPM_REGISTRY_URL, "--registry-url"),
  };
  return async (changes) => {
    const answer = await offlineVerdicts(changes, {
      osv,
      registry,
      fetch: io.fetch,
      now: io.now(),
    });
    return {
      verdicts: answer.verdicts,
      unavailableSignals: answer.unavailableSignals,
      osvSnapshot: {
        generation: answer.snapshot.generation,
        sha256: answer.snapshot.sha256,
        cached: answer.snapshot.cached,
      },
    };
  };
}

/** The API key from the environment. Error (exit 2): unset, empty or not a header-safe token. */
export function apiKeyFrom(env: CliIo["env"]): string {
  const key = env["KOVO_API_KEY"];
  if (key === undefined || key === "")
    throw usageError(
      "missing_api_key",
      `Set ${API_KEY_ENV} to a Kovo API key; the key is read only from the environment.`,
    );
  let printable = true;
  for (const char of key) {
    const code = char.codePointAt(0) ?? 0;
    if (code <= 0x20 || code >= 0x7f) printable = false;
  }
  if (!printable) throw usageError("invalid_api_key", `${API_KEY_ENV} is not a valid API key.`);
  return key;
}

interface Located {
  readonly root: string;
  /** The project directory relative to the repository root, POSIX separators ("" at the root). */
  readonly prefix: string;
  /** The project directory's absolute path in the working tree. */
  readonly dir: string;
  readonly fileName: LockfileName | null;
}

async function realOrSelf(path: string): Promise<string> {
  try {
    return await realpath(path);
  } catch {
    return path;
  }
}

function lockfileNameOf(name: string): LockfileName | null {
  for (const candidate of Object.values(LOCKFILE_NAMES)) if (candidate === name) return candidate;
  return null;
}

async function locate(root: string, cwd: string, lockfile: string | undefined): Promise<Located> {
  const target = lockfile === undefined ? null : resolve(cwd, lockfile);
  const dir = await realOrSelf(target === null ? cwd : dirname(target));
  const fileName = target === null ? null : lockfileNameOf(basename(target));
  if (target !== null && fileName === null)
    throw usageError(
      "unsupported_lockfile_name",
      `--lockfile must name one of ${Object.values(LOCKFILE_NAMES).join(", ")}.`,
    );
  const fromRoot = relative(await realOrSelf(root), dir);
  if (fromRoot === ".." || fromRoot.startsWith(`..${sep}`) || isAbsolute(fromRoot))
    throw usageError("outside_repository", "The lockfile must be inside the repository.");
  return {
    root,
    prefix: fromRoot.split(sep).join("/"),
    dir,
    fileName,
  };
}

async function detectLockfile(head: ProjectReader): Promise<LockfileName> {
  const files = await head.rootFiles();
  if (files === null)
    throw usageError("missing_project", `The project directory does not exist at ${head.label}.`);
  const detected = detectPackageManager(files);
  if (!detected.ok)
    throw new UnsupportedLockfileError(head.label, {
      unsupported: detected.unsupported,
      reasons: [detected.reason],
      packages: [],
    });
  return detected.lockfileName;
}

/** The change list between two sides of one project, and its verdicts (none asked when empty). */
export async function judgeSides(
  base: ProjectReader,
  head: ProjectReader,
  fileName: LockfileName,
  judge: Judge,
): Promise<{ readonly changes: readonly DependencyVerdictChangeWire[]; readonly answer: Answer }> {
  const changes = await readChangeList(base, head, fileName);
  const answer: Answer =
    changes.length === 0
      ? { verdicts: [], unavailableSignals: [], osvSnapshot: null }
      : await judge(changes);
  return { changes, answer };
}

/**
 * The CLI error a failed check reports: an unsupported lockfile (exit 2), a `CliError` as thrown,
 * or, for anything else, `internal_error` (exit 3), whose message never carries the input.
 */
export function failureOf(error: unknown): {
  readonly error: CliError;
  readonly unsupported?: UnsupportedLockfile;
} {
  if (error instanceof UnsupportedLockfileError)
    return {
      error: unsupportedLockfileError(error.side, error.refusal),
      unsupported: error.refusal,
    };
  if (error instanceof CliError) return { error };
  // An unexpected failure is never a pass. Its message is not printed: it could carry input.
  return {
    error: unavailableError(
      "internal_error",
      `The check failed unexpectedly (${error instanceof Error ? error.name : "unknown"}).`,
    ),
  };
}

/** Runs `kovo deps check` and writes its report. Returns the exit code. */
export async function depsCheck(options: DepsCheckOptions, io: CliIo): Promise<ExitCode> {
  let context: CheckContext = {
    mode: options.mode.kind,
    lockfile: null,
    base: null,
    baseFrom: null,
    head: null,
  };
  const fail = (error: CliError, unsupported?: UnsupportedLockfile): ExitCode => {
    const rendered = renderError(context, error, unsupported === undefined ? {} : { unsupported });
    if (options.format === "json") io.stdout(rendered.json);
    else io.stderr(rendered.text);
    return error.exit;
  };
  try {
    const judge = judgeFor(options.mode, io);
    const env = childEnvironment(io.env);
    const root = await repositoryRoot(io.cwd, env);
    const headCommit =
      options.head === undefined ? null : await resolveCommit(root, options.head, "--head", env);
    const located = await locate(root, io.cwd, options.lockfile);
    const head: ProjectReader =
      headCommit === null
        ? new WorkingTreeReader(located.dir, env)
        : new CommitReader(root, headCommit, located.prefix, env);
    const fileName = located.fileName ?? (await detectLockfile(head));
    const lockfilePath = located.prefix === "" ? fileName : `${located.prefix}/${fileName}`;
    context = { ...context, lockfile: lockfilePath, head: headCommit };
    const base =
      options.base === undefined
        ? await defaultBase(root, headCommit, env).then(({ commit, branch }) => ({
            commit,
            from: `merge base with ${branch}`,
          }))
        : { commit: await resolveCommit(root, options.base, "--base", env), from: "--base" };
    context = { ...context, base: base.commit, baseFrom: base.from };
    const { changes, answer } = await judgeSides(
      new CommitReader(root, base.commit, located.prefix, env),
      head,
      fileName,
      judge,
    );
    const report: CheckReport = {
      ...context,
      changes,
      verdicts: answer.verdicts,
      unavailableSignals: answer.unavailableSignals,
      osvSnapshot: answer.osvSnapshot,
    };
    io.stdout(options.format === "json" ? renderJson(report) : renderText(report));
    return verdictExitCode(report.verdicts);
  } catch (error) {
    const failure = failureOf(error);
    return fail(failure.error, failure.unsupported);
  }
}
