import type { ChildProcess } from "node:child_process";

import type { DependencyVerdictChangeWire } from "@kovo/contracts";
import type { LockfileName } from "@kovo/core/lockfile";

import { CliError, usageError } from "../errors.js";
import { EXIT } from "../exit.js";
import type { CliIo } from "../io.js";
import { parseApiUrl } from "../deps/api.js";
import {
  depsCheck,
  failureOf,
  judgeFor,
  judgeSides,
  type Answer,
  type OfflineMode,
  type OnlineMode,
} from "../deps/check.js";
import { childEnvironment, WorkingTreeReader } from "../deps/git.js";
import { MemoryReader, type HeldFiles } from "../deps/memory.js";
import { NPM_REGISTRY_URL } from "../deps/offline/registry.js";
import { OFFLINE_NOTICE, renderText, verdictExitCode, type CheckReport } from "../deps/report.js";
import { readGraph } from "../deps/snapshot.js";
import {
  classify,
  pinnedArgs,
  type FetchCommand,
  type FrozenCommand,
  type PackageManager,
  type ResolveCommand,
} from "./classify.js";
import {
  isWorkspace,
  nestedLockfiles,
  openProject,
  readHeld,
  restore,
  sameHeld,
  type Project,
} from "./files.js";
import { exitOf, packageManagerEnvironment, runChild } from "./process.js";
import { fetchedChange, resolveSpec } from "./spec.js";

// `kovo pnpm …` and `kovo npm …` (plans/dependency-firewall.md Part 3b): check before anything
// installs. A resolving command runs lockfile-only (no dependency is fetched into node_modules and
// no lifecycle script runs), the lockfile diff is judged exactly as `kovo deps check` judges it, and
// only a passing check reaches the frozen install. Anything else (a block or wait, an unreadable
// lockfile, a check that cannot be answered, an interrupt) puts package.json and the lockfile back
// byte for byte and installs nothing. The wrapper's own output goes to stderr, so the wrapped
// command's stdout stays the package manager's.

/** Options for the check, given before the package-manager command. */
interface CheckOptions {
  readonly offline: boolean;
  readonly apiUrl: string | undefined;
  readonly osvCache: string | undefined;
  readonly osvGeneration: string | undefined;
  readonly osvUrl: string | undefined;
  readonly registryUrl: string | undefined;
}

const VALUE_OPTIONS = {
  "--api-url": "apiUrl",
  "--osv-cache": "osvCache",
  "--osv-generation": "osvGeneration",
  "--osv-url": "osvUrl",
  "--registry-url": "registryUrl",
} as const satisfies Record<string, keyof CheckOptions>;

function isValueOption(name: string): name is keyof typeof VALUE_OPTIONS {
  return Object.hasOwn(VALUE_OPTIONS, name);
}

/** The check options before the command; the rest is the package-manager command line. */
function splitArgs(
  argv: readonly string[],
): { readonly help: true } | { readonly options: CheckOptions; readonly rest: readonly string[] } {
  const values: Record<string, string | undefined> = {};
  let offline = false;
  let index = 0;
  for (; index < argv.length; index += 1) {
    const token = argv[index]!;
    if (!token.startsWith("-")) break;
    refuseKeyFlags([token]);
    if (token === "--help" || token === "-h") return { help: true };
    if (token === "--offline") {
      offline = true;
      continue;
    }
    const eq = token.indexOf("=");
    const name = eq === -1 ? token : token.slice(0, eq);
    if (!isValueOption(name))
      throw usageError(
        "unknown_option",
        "Unknown option before the command: the check's options go before the package-manager command, the package manager's after it.",
      );
    const value = eq === -1 ? argv[(index += 1)] : token.slice(eq + 1);
    if (value === undefined || values[VALUE_OPTIONS[name]] !== undefined)
      throw usageError("unknown_option", `${name} needs one value.`);
    values[VALUE_OPTIONS[name]] = value;
  }
  return {
    options: {
      offline,
      apiUrl: values["apiUrl"],
      osvCache: values["osvCache"],
      osvGeneration: values["osvGeneration"],
      osvUrl: values["osvUrl"],
      registryUrl: values["registryUrl"],
    },
    rest: argv.slice(index),
  };
}

/** The check's mode. Error (exit 2): an online option offline, or an OSV option online. */
function modeOf(options: CheckOptions, registryUrl: string | undefined): OnlineMode | OfflineMode {
  if (options.offline) {
    if (options.apiUrl !== undefined)
      throw usageError("invalid_options", "--api-url and --offline cannot be combined.");
    return {
      kind: "offline",
      osvCache: options.osvCache,
      osvGeneration: options.osvGeneration,
      osvUrl: options.osvUrl,
      registryUrl,
    };
  }
  for (const [name, value] of [
    ["--osv-cache", options.osvCache],
    ["--osv-generation", options.osvGeneration],
    ["--osv-url", options.osvUrl],
  ] as const)
    if (value !== undefined) throw usageError("invalid_options", `${name} needs --offline.`);
  return { kind: "online", apiUrl: options.apiUrl };
}

/** Flags a key might be passed with (as `kovo deps check` refuses them). */
const KEY_FLAG = /^--?(?:api-?key|key|token)(?:=|$)/iu;

/** Error (exit 2): a key flag; the flag (and its value) is never echoed. */
function refuseKeyFlags(args: readonly string[]): void {
  if (args.some((arg) => KEY_FLAG.test(arg)))
    throw usageError("key_flag", "The API key is read only from KOVO_API_KEY, never from a flag.");
}

/** Commands whose arguments after the package are the fetched tool's own. */
const FETCH_COMMANDS = new Set(["dlx", "create", "exec", "x", "init", "innit"]);

const BEFORE = "the project before resolving";
const AFTER = "the project after resolving";

class Wrapper {
  readonly #pm: PackageManager;
  readonly #io: CliIo;
  #offline = false;

  constructor(pm: PackageManager, io: CliIo) {
    this.#pm = pm;
    this.#io = io;
  }

  say(text: string): void {
    this.#io.stderr(`kovo ${this.#pm}: ${text}\n`);
  }

  /** Reports a failure (with the offline notice when offline) and returns its exit code. */
  fail(error: unknown): number {
    const { error: failure } = failureOf(error);
    if (this.#offline) this.#io.stderr(`${OFFLINE_NOTICE}\n`);
    this.say(`${failure.message} [${failure.code}] (exit ${failure.exit})`);
    return failure.exit;
  }

  async run(argv: readonly string[], help: () => void): Promise<number> {
    try {
      const split = splitArgs(argv);
      if ("help" in split) {
        help();
        return EXIT.pass;
      }
      this.#offline = split.options.offline;
      // A fetched tool's own arguments are its own; everything else is refused as `deps check`
      // does, before classification so the refusal names the key rule.
      if (!FETCH_COMMANDS.has(split.rest[0] ?? "")) refuseKeyFlags(split.rest);
      const command = classify(this.#pm, split.rest);
      if (command.kind === "passthrough") return await this.#inherit(command.args);
      if (command.kind === "frozen") return await this.#frozen(command, split.options);
      if (command.kind === "fetch") return await this.#fetch(command, split.options);
      return await this.#resolve(command, split.options);
    } catch (error) {
      return this.fail(error);
    }
  }

  async #inherit(args: readonly string[]): Promise<number> {
    const exit = await runChild(this.#pm, args, {
      cwd: this.#io.cwd,
      env: packageManagerEnvironment(this.#io.env),
      stdio: "inherit",
    });
    return exitOf(exit);
  }

  /** `pnpm install --frozen-lockfile`, `npm ci`: `kovo deps check` first, then the command as is. */
  async #frozen(command: FrozenCommand, options: CheckOptions): Promise<number> {
    const mode = modeOf(options, options.registryUrl);
    const project = await openProject(this.#pm, this.#io.cwd);
    const code = await depsCheck(
      { base: undefined, head: undefined, lockfile: project.fileName, format: "text", mode },
      { ...this.#io, cwd: project.dir, stdout: this.#io.stderr },
    );
    if (code !== EXIT.pass) {
      this.say("the check did not pass; nothing was installed.");
      return code;
    }
    return this.#inherit(command.args);
  }

  /** `dlx`, `create`, `exec`, `init <starter>`: check the one package, then run it pinned. */
  async #fetch(command: FetchCommand, options: CheckOptions): Promise<number> {
    // The package manager's --registry is refused; the project's configured registry is not read
    // (docs/libraries/package-manager-wrappers.md "Limits").
    const registry = options.registryUrl ?? NPM_REGISTRY_URL;
    const mode = modeOf(options, registry);
    const judge = judgeFor(mode, this.#io);
    const resolved = await resolveSpec(command.spec, {
      registryUrl: parseApiUrl(registry, "--registry-url"),
      fetch: this.#io.fetch,
    });
    const change = fetchedChange(resolved);
    const answer = await judge([change]);
    const heading = `kovo ${this.#pm} ${command.command}: ${resolved.name}@${resolved.version} (fetched by ${this.#pm} ${command.command}; not in a lockfile, so its own dependencies are not checked)`;
    const code = this.#report(mode, null, [change], answer, heading);
    if (code !== EXIT.pass) {
      this.say("the check did not pass; nothing was run.");
      return code;
    }
    return this.#inherit(pinnedArgs(command, resolved.version));
  }

  #report(
    mode: OnlineMode | OfflineMode,
    lockfile: LockfileName | null,
    changes: readonly DependencyVerdictChangeWire[],
    answer: Answer,
    heading: string,
  ): number {
    const report: CheckReport = {
      mode: mode.kind,
      lockfile,
      base: null,
      baseFrom: null,
      head: null,
      changes,
      verdicts: answer.verdicts,
      unavailableSignals: answer.unavailableSignals,
      osvSnapshot: answer.osvSnapshot,
    };
    this.#io.stderr(renderText(report, heading));
    return verdictExitCode(report.verdicts);
  }

  /** Puts the held files back, says what happened, and returns `code`. */
  async #undo(
    project: Project,
    before: HeldFiles,
    code: number,
    created: readonly string[] = [],
  ): Promise<number> {
    const { restored, failed } = await restore(project, before, created);
    if (restored.length > 0) this.say(`restored ${restored.join(", ")}; nothing was installed.`);
    else this.say("nothing was installed.");
    if (failed.length > 0) {
      this.say(
        `could not restore ${failed.join(", ")}: they may hold versions that were not checked. Restore them (for example from version control) before installing.`,
      );
      return code === EXIT.pass ? EXIT.unavailable : code;
    }
    return code;
  }

  /** `add`, `install`, `update`, `remove`, `dedupe`: resolve lockfile-only, check, then install. */
  async #resolve(command: ResolveCommand, options: CheckOptions): Promise<number> {
    const mode = modeOf(options, options.registryUrl);
    const judge = judgeFor(mode, this.#io);
    const gitEnv = childEnvironment(this.#io.env);
    const project = await openProject(this.#pm, this.#io.cwd);
    const before = await readHeld(project, gitEnv);
    let live: WorkingTreeReader | null = null;
    if (isWorkspace(project, before)) {
      live = new WorkingTreeReader(project.dir, gitEnv);
      if ((await nestedLockfiles(project, live)).length > 0)
        throw usageError(
          "nested_lockfile",
          `This workspace has a ${project.fileName} per project, and kovo checks only the root one.`,
        );
    }
    // A lockfile the check cannot read is refused before anything runs.
    await readGraph(new MemoryReader(BEFORE, before, live), project.fileName);

    const state: { interrupted: boolean; child: ChildProcess | null } = {
      interrupted: false,
      child: null,
    };
    const unsubscribe =
      this.#io.onInterrupt?.(() => {
        state.interrupted = true;
        state.child?.kill("SIGTERM");
      }) ?? (() => {});
    let created: readonly string[] = [];
    try {
      const resolved = await runChild(this.#pm, command.resolveArgs, {
        cwd: project.dir,
        env: packageManagerEnvironment(this.#io.env),
        stdio: "quiet",
        onStart: (started) => {
          state.child = started;
          // An interrupt that arrived while it was starting.
          if (state.interrupted) started.kill("SIGTERM");
        },
      });
      if (state.interrupted) {
        this.say("interrupted.");
        return await this.#undo(project, before, 130);
      }
      if (resolved.status !== 0) {
        this.say(
          `${this.#pm} ${command.command} (lockfile only) ${resolved.status === null ? "was stopped by a signal" : `failed with exit ${resolved.status}`}; run it with ${this.#pm} and --${this.#pm === "pnpm" ? "lockfile-only" : "package-lock-only"} to see why.`,
        );
        return await this.#undo(project, before, exitOf(resolved));
      }
      const after = await readHeld(project, gitEnv);
      if (live !== null) {
        created = await nestedLockfiles(project, live);
        if (created.length > 0)
          throw usageError(
            "nested_lockfile",
            `${this.#pm} wrote a ${project.fileName} below the root, and kovo checks only the root one.`,
          );
      }
      const { changes, answer } = await judgeSides(
        new MemoryReader(BEFORE, before, live),
        new MemoryReader(AFTER, after, live),
        project.fileName,
        judge,
      );
      if (state.interrupted) {
        this.say("interrupted.");
        return await this.#undo(project, before, 130);
      }
      const heading = `kovo ${this.#pm} ${command.command}: ${project.fileName}, before and after resolving (lockfile only)`;
      const code = this.#report(mode, project.fileName, changes, answer, heading);
      if (code !== EXIT.pass) return await this.#undo(project, before, code);
      if (!sameHeld(after, await readHeld(project, gitEnv)))
        throw new CliError(
          EXIT.unavailable,
          "changed_during_check",
          "package.json or the lockfile changed while it was being checked.",
        );
    } catch (error) {
      return await this.#undo(project, before, this.fail(error), created);
    } finally {
      unsubscribe();
    }
    // Only the fixed command is named: the user's arguments are never printed.
    const install = this.#pm === "pnpm" ? "pnpm install --frozen-lockfile" : "npm ci";
    this.say(`the check passed; running ${install}.`);
    return this.#inherit(command.installArgs);
  }
}

/** Runs `kovo pnpm …` or `kovo npm …` (`argv` without the `pnpm`/`npm` word). Never throws. */
export function runWrapper(
  pm: PackageManager,
  argv: readonly string[],
  io: CliIo,
  help: () => void,
): Promise<number> {
  return new Wrapper(pm, io).run(argv, help);
}
