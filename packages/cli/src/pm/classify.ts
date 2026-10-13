import { usageError } from "../errors.js";
import {
  isOptionToken,
  isTerminator,
  lastBoolean,
  lastValue,
  normalize,
  readOption,
  refuseRegistryOption,
  type Allowlist,
  type LongSpec,
  type Normalized,
} from "./args.js";
import { parseCreateSpec, parseRegistrySpec, type RegistrySpec } from "./spec.js";

// What `kovo pnpm …` and `kovo npm …` do with a package-manager command line, decided before
// anything runs (plans/dependency-firewall.md Part 3b). Pure: the arguments are only classified,
// never printed.
//
// - resolve: `add`, `install`, `update`, `remove`, `dedupe` (and their aliases). The command runs
//   once with the lockfile-only flags, the lockfile diff is checked, and only then does the frozen
//   install run (the step where lifecycle scripts can run).
// - frozen: `pnpm install --frozen-lockfile` and `npm ci`. `kovo deps check` runs first, then the
//   command runs.
// - fetch: `pnpm dlx`/`create`, `npm exec`/`init <initializer>`. The one package fetched is checked
//   and pinned to the checked version.
// - passthrough: read-only commands that neither resolve nor install (`ls`, `why`, `outdated`, …).
// - anything else is refused with a usage error naming the reason.
//
// Every wrapped command's options go through `normalize` (./args.ts): only the options on that
// command's allowlist, written in full, are accepted, each is re-emitted as one canonical token, and
// the safety flags are appended last so they win (both package managers read the last occurrence).
// docs/libraries/package-manager-wrappers.md cites each flag.

export type PackageManager = "pnpm" | "npm";

export interface ResolveCommand {
  readonly kind: "resolve";
  /** The canonical command: `add`, `install`, `update`, `remove` or `dedupe`. */
  readonly command: string;
  /** The resolve step: the command, the normalised arguments, then the lockfile-only flags. */
  readonly resolveArgs: readonly string[];
  /** The install step after a passing check. */
  readonly installArgs: readonly string[];
}

export interface FrozenCommand {
  readonly kind: "frozen";
  /** The command and its normalised arguments. */
  readonly args: readonly string[];
}

/** Where the checked package goes in a fetch command line: `${prefix}${spec}@<version>`. */
export interface Pin {
  readonly prefix: string;
  readonly spec: string;
}

export interface FetchCommand {
  readonly kind: "fetch";
  /** The canonical command: `dlx`, `create`, `exec` or `init`. */
  readonly command: string;
  readonly spec: RegistrySpec;
  /**
   * The command line to run: the command, its normalised leading options, `--` before the package
   * for npm, the pin where the checked package goes, then the tool's own arguments.
   */
  readonly template: readonly (string | Pin)[];
}

export interface PassthroughCommand {
  readonly kind: "passthrough";
  readonly args: readonly string[];
}

export type Classified = ResolveCommand | FrozenCommand | FetchCommand | PassthroughCommand;

function refuse(code: string, message: string): never {
  throw usageError(code, message);
}

const BOOL: LongSpec = { type: "boolean" };
const CARRY_BOOL: LongSpec = { type: "boolean", carry: true };
const CARRY_STRING: LongSpec = { type: "string", carry: true };
/** Scripts stay off for the resolve: the wrapper also pins it last. */
const SCRIPTS_OFF: LongSpec = { type: "boolean", carry: true, must: true };

// pnpm 11.27.1 (`installing/commands/src/*.ts` option types; shorthands in `pnpm/src/shorthands.ts`
// and the commands' own: `-D`/`-P`/`-E`/`-O` save fields on add/remove, dev/prod filters on install
// and update, `-w` the workspace root, `-L` `--latest`).
const PNPM_SAVE: Allowlist["long"] = {
  "save-dev": BOOL,
  "save-prod": BOOL,
  "save-optional": BOOL,
  "save-exact": BOOL,
  "save-peer": BOOL,
};
const PNPM_FILTERS: Allowlist["long"] = {
  production: CARRY_BOOL,
  prod: CARRY_BOOL,
  dev: CARRY_BOOL,
  optional: CARRY_BOOL,
  offline: CARRY_BOOL,
  "prefer-offline": CARRY_BOOL,
};

const PNPM: Readonly<Record<string, Allowlist>> = {
  add: {
    long: {
      ...PNPM_SAVE,
      "ignore-workspace-root-check": BOOL,
      "workspace-root": BOOL,
      offline: BOOL,
      "prefer-offline": BOOL,
      "ignore-scripts": SCRIPTS_OFF,
    },
    short: { D: {}, P: {}, O: {}, E: {}, w: {} },
  },
  install: {
    long: {
      ...PNPM_FILTERS,
      "fix-lockfile": BOOL,
      // A plain install is resolved and checked: a frozen lockfile is the frozen class.
      "frozen-lockfile": { type: "boolean", must: false },
      "ignore-scripts": SCRIPTS_OFF,
    },
    short: { D: { carry: true }, P: { carry: true } },
  },
  frozen: {
    long: {
      ...PNPM_FILTERS,
      "frozen-lockfile": BOOL,
      "ignore-scripts": BOOL,
    },
    short: { D: {}, P: {} },
  },
  update: {
    long: {
      latest: BOOL,
      production: BOOL,
      prod: BOOL,
      dev: BOOL,
      optional: BOOL,
      save: BOOL,
      depth: { type: "string" },
      offline: BOOL,
      "prefer-offline": BOOL,
      "ignore-scripts": SCRIPTS_OFF,
    },
    short: { L: {}, D: {}, P: {} },
  },
  // pnpm 11's `remove` takes no --ignore-scripts.
  remove: {
    long: { "save-dev": BOOL, "save-prod": BOOL, "save-optional": BOOL },
    short: { D: {}, P: {}, O: {} },
  },
  dedupe: {
    long: { offline: BOOL, "prefer-offline": BOOL, "ignore-scripts": SCRIPTS_OFF },
    short: {},
  },
  // `dedupe --check` changes nothing: it is read-only.
  "dedupe-check": { long: { check: BOOL }, short: {} },
  dlx: { long: { package: { type: "string", once: true } }, short: {} },
  create: { long: {}, short: {} },
};

// npm 10 (`workspaces/config/lib/definitions/definitions.js`; shorthands `-D` save-dev, `-P`
// save-prod, `-O` save-optional, `-E` save-exact, `-y` yes).
const NPM_COMMON: Allowlist["long"] = {
  include: CARRY_STRING,
  omit: CARRY_STRING,
  "legacy-peer-deps": CARRY_BOOL,
  "prefer-offline": CARRY_BOOL,
  offline: CARRY_BOOL,
  audit: BOOL,
  fund: BOOL,
  "ignore-scripts": SCRIPTS_OFF,
};
const NPM_SAVE: Allowlist["long"] = {
  // `--no-save` also stops npm writing package-lock.json.
  save: { type: "boolean", must: true },
  "save-dev": BOOL,
  "save-prod": BOOL,
  "save-optional": BOOL,
  "save-exact": BOOL,
  "save-peer": BOOL,
};

const NPM: Readonly<Record<string, Allowlist>> = {
  install: {
    long: {
      ...NPM_COMMON,
      ...NPM_SAVE,
      "strict-peer-deps": BOOL,
      force: BOOL,
      "install-links": BOOL,
    },
    short: { D: {}, P: {}, O: {}, E: {} },
  },
  update: { long: NPM_COMMON, short: {} },
  remove: { long: { ...NPM_SAVE }, short: { D: {}, P: {}, O: {} } },
  dedupe: { long: NPM_COMMON, short: {} },
  frozen: {
    long: { ...NPM_COMMON, "ignore-scripts": BOOL },
    short: {},
  },
  exec: { long: { package: { type: "string", once: true }, yes: BOOL }, short: { y: {} } },
  init: { long: { yes: BOOL }, short: { y: {} } },
};

const ALLOWLISTS: Record<PackageManager, Readonly<Record<string, Allowlist>>> = {
  pnpm: PNPM,
  npm: NPM,
};

function allowlistOf(pm: PackageManager, key: string): Allowlist {
  const found = ALLOWLISTS[pm][key];
  if (found === undefined) throw new Error(`no allowlist for ${pm} ${key}`);
  return found;
}

/**
 * A registry package spec: a name, optionally scoped, and an optional version, range or tag. No
 * part may start with `.`: npm-package-arg and pnpm read `..`, `foo@..` or `.evil.tgz` as a
 * directory or a tarball.
 */
const REGISTRY_SPEC =
  /^(?:@(?!\.)[^@/\s:]+\/)?(?!\.)[^@/\s:]+(?:@(?!\.)[A-Za-z0-9.^~<>=|*+\- ]+)?$/u;

/** Positionals of a resolving command: each must be a registry package spec (or name). */
function refuseNonRegistrySpecs(positionals: readonly string[]): void {
  for (const token of positionals)
    if (!REGISTRY_SPEC.test(token))
      refuse(
        "unsupported_spec",
        "kovo checks registry packages only: a git, URL, tarball, path or alias spec is not supported.",
      );
}

const PNPM_RESOLVE: Readonly<Record<string, string>> = {
  add: "add",
  install: "install",
  i: "install",
  update: "update",
  up: "update",
  upgrade: "update",
  remove: "remove",
  uninstall: "remove",
  rm: "remove",
  un: "remove",
  uni: "remove",
  dedupe: "dedupe",
};

const NPM_RESOLVE: Readonly<Record<string, string>> = {
  install: "install",
  add: "install",
  i: "install",
  in: "install",
  ins: "install",
  inst: "install",
  insta: "install",
  instal: "install",
  isnt: "install",
  isnta: "install",
  isntal: "install",
  isntall: "install",
  update: "update",
  up: "update",
  upgrade: "update",
  udpate: "update",
  uninstall: "remove",
  unlink: "remove",
  remove: "remove",
  rm: "remove",
  r: "remove",
  un: "remove",
  dedupe: "dedupe",
  ddp: "dedupe",
};

const NPM_CI = new Set(["ci", "clean-install", "ic", "install-clean", "isntall-clean"]);

const PASSTHROUGH: Record<PackageManager, ReadonlySet<string>> = {
  pnpm: new Set([
    "ls",
    "list",
    "ll",
    "la",
    "why",
    "outdated",
    "licenses",
    "root",
    "bin",
    "help",
    "audit",
  ]),
  npm: new Set([
    "ls",
    "list",
    "ll",
    "la",
    "explain",
    "why",
    "outdated",
    "view",
    "info",
    "show",
    "v",
    "help",
    "root",
    "prefix",
    "fund",
    "query",
    "audit",
  ]),
};

function tokensOf(normalized: Normalized): string[] {
  return normalized.options.map((option) => option.token);
}

function resolveCommand(
  pm: PackageManager,
  command: string,
  canonical: string,
  normalized: Normalized,
): ResolveCommand {
  refuseNonRegistrySpecs(normalized.positionals);
  // Pinned last, so they win over anything before them (both package managers read the last
  // occurrence). pnpm 11's `remove` does not accept --ignore-scripts; --lockfile-only alone skips
  // linking and every dependency build there (the deps-installer's `!opts.lockfileOnly` guards).
  const pinned =
    pm === "pnpm"
      ? ["--lockfile-only", ...(canonical === "remove" ? [] : ["--ignore-scripts"])]
      : ["--package-lock-only", "--ignore-scripts"];
  const install = pm === "pnpm" ? ["install"] : ["ci"];
  const carried = normalized.options.filter((option) => option.carry).map((o) => o.token);
  return {
    kind: "resolve",
    command: canonical,
    resolveArgs: [command, ...tokensOf(normalized), ...normalized.positionals, ...pinned],
    installArgs: [...install, ...carried, ...(pm === "pnpm" ? ["--frozen-lockfile"] : [])],
  };
}

function frozenCommand(pm: PackageManager, command: string, normalized: Normalized): FrozenCommand {
  if (normalized.positionals.length > 0)
    refuse(
      "unsupported_option",
      `kovo ${pm} ${command} installs the lockfile as it is: it takes no package names (pnpm reads them as an add).`,
    );
  return {
    kind: "frozen",
    args: [command, ...tokensOf(normalized), ...(pm === "pnpm" ? ["--frozen-lockfile"] : [])],
  };
}

/**
 * The leading options of a fetch command (up to the first positional or a run of dashes), and
 * where the package or starter is. Error (exit 2): an option the command's allowlist lacks.
 */
function leading(
  pm: PackageManager,
  args: readonly string[],
  allowlist: Allowlist,
): { readonly normalized: Normalized; readonly index: number; readonly ended: boolean } {
  let end = 1;
  while (end < args.length && isOptionToken(args[end]!)) {
    // A value option written with a separate value takes the next token.
    const read = readOption(args[end]!);
    const spec = read.short ? undefined : allowlist.long[read.name];
    end += spec?.type === "string" && read.inline === null ? 2 : 1;
  }
  const context = `kovo ${pm} ${args[0]}`;
  const normalized = normalize(args.slice(1, end), allowlist, context);
  const ended = end < args.length && isTerminator(args[end]!);
  // pnpm hands everything after its escape word to the tool, but a run of dashes before it would
  // let the next token through unread (an unchecked --package or registry): refused.
  if (ended && pm === "pnpm")
    refuse("unsupported_option", `${context} does not take ${args[end]} before the package.`);
  const index = ended ? end + 1 : end;
  const positional = args[index];
  if (positional?.startsWith("-") === true)
    refuse(
      "unsupported_option",
      `${context}: the package or tool name cannot start with -: write the options before it.`,
    );
  return { normalized, index, ended };
}

/**
 * The tool's own arguments. npm ends its options at the first run of dashes; the wrapper puts its
 * own `--` before the package, so the user's first one (when none came before the package) is
 * dropped, and the tool receives exactly what npm would have handed it (`npm create vite app --
 * --template react` gives the starter `--template react`). pnpm passes everything after the
 * package to the tool as written.
 */
function toolArgs(pm: PackageManager, rest: readonly string[], ended: boolean): string[] {
  if (pm !== "npm" || ended) return [...rest];
  const first = rest.findIndex((token) => isTerminator(token));
  return first === -1 ? [...rest] : [...rest.slice(0, first), ...rest.slice(first + 1)];
}

/** pnpm parses these after a dlx package too; refused there, so only the checked one counts. */
function refuseTrailingFetchOptions(pm: PackageManager, rest: readonly string[]): void {
  if (pm !== "pnpm") return;
  for (const token of rest) {
    if (isTerminator(token)) continue;
    if (!isOptionToken(token)) continue;
    const name = readOption(token).name.toLowerCase();
    refuseRegistryOption(name);
    if (
      name.includes(".") ||
      name.includes(":") ||
      (name.length > 0 && ["package", "registry"].some((guarded) => guarded.startsWith(name)))
    )
      refuse(
        "unsupported_option",
        `kovo pnpm dlx refuses ${token.split("=")[0]} after the package: it could fetch a package or use a registry that was not checked.`,
      );
  }
}

function fetchCommand(
  pm: PackageManager,
  canonical: string,
  args: readonly string[],
): FetchCommand | PassthroughCommand {
  const command = args[0]!;
  // npm parses options anywhere on the line (an `npm exec foo --package=bar` installs bar too), so
  // its fetched command gets `--` before the package: everything after it is the tool's.
  const separator = pm === "npm" ? ["--"] : [];
  const { normalized, index, ended } = leading(pm, args, allowlistOf(pm, canonical));
  const positional = args[index];
  const rest = toolArgs(pm, args.slice(index + 1), ended);
  if (canonical === "create" || canonical === "init") {
    if (positional === undefined) {
      // `npm init` without a starter writes package.json from prompts: it fetches nothing.
      if (pm === "npm") return { kind: "passthrough", args: [command, ...tokensOf(normalized)] };
      refuse("missing_starter", "kovo pnpm create needs the starter's name.");
    }
    const { spec, initializer } = parseCreateSpec(pm, positional);
    return {
      kind: "fetch",
      command: canonical,
      spec,
      template: [
        command,
        ...tokensOf(normalized),
        ...separator,
        { prefix: "", spec: initializer },
        ...rest,
      ],
    };
  }
  const selected = lastValue(normalized, "package");
  const packageSpec = typeof selected === "string" ? selected : undefined;
  refuseTrailingFetchOptions(pm, rest);
  const spec = packageSpec ?? positional;
  if (spec === undefined) refuse("missing_package", `kovo ${pm} ${command} needs the package.`);
  const parsed = parseRegistrySpec(spec);
  const options = normalized.options.map((option): string | Pin =>
    option.name === "package" ? { prefix: "--package=", spec: parsed.name } : option.token,
  );
  const tail: (string | Pin)[] =
    positional === undefined
      ? []
      : [...separator, packageSpec === undefined ? { prefix: "", spec: parsed.name } : positional];
  return {
    kind: "fetch",
    command: canonical,
    spec: parsed,
    template: [command, ...options, ...tail, ...rest],
  };
}

/** The fetch command's arguments with the package pinned to `version`. */
export function pinnedArgs(fetched: FetchCommand, version: string): string[] {
  return fetched.template.map((part) =>
    typeof part === "string" ? part : `${part.prefix}${part.spec}@${version}`,
  );
}

/**
 * Classifies `args` (the package-manager command and its arguments). Error (exit 2): a command or
 * option the wrapper refuses, with the reason.
 */
export function classify(pm: PackageManager, args: readonly string[]): Classified {
  const [command, ...rest] = args;
  if (command === undefined || command.startsWith("-"))
    refuse(
      "missing_command",
      `kovo ${pm} needs the ${pm} command first (for example kovo ${pm} install).`,
    );
  const context = `kovo ${pm} ${command}`;
  if (pm === "pnpm") {
    const canonical = PNPM_RESOLVE[command];
    // The last --frozen-lockfile decides, as in pnpm; a resolve refuses any that is on.
    if (canonical === "install" && lastBoolean(rest, "frozen-lockfile") === true)
      return frozenCommand(pm, command, normalize(rest, allowlistOf(pm, "frozen"), context));
    if (canonical === "dedupe" && lastBoolean(rest, "check") === true) {
      const check = normalize(rest, allowlistOf(pm, "dedupe-check"), context);
      return { kind: "passthrough", args: [command, ...tokensOf(check)] };
    }
    if (canonical !== undefined)
      return resolveCommand(
        pm,
        command,
        canonical,
        normalize(rest, allowlistOf(pm, canonical), context),
      );
    if (command === "dlx") return fetchCommand(pm, "dlx", args);
    if (command === "create") return fetchCommand(pm, "create", args);
  } else {
    if (NPM_CI.has(command))
      return frozenCommand(pm, command, normalize(rest, allowlistOf(pm, "frozen"), context));
    const canonical = NPM_RESOLVE[command];
    if (canonical !== undefined)
      return resolveCommand(
        pm,
        command,
        canonical,
        normalize(rest, allowlistOf(pm, canonical), context),
      );
    if (command === "exec" || command === "x") return fetchCommand(pm, "exec", args);
    if (command === "init" || command === "create" || command === "innit")
      return fetchCommand(pm, "init", args);
  }
  if (PASSTHROUGH[pm].has(command)) {
    const fixes = rest.some((token) => {
      if (token === "fix") return true;
      if (!isOptionToken(token)) return false;
      const { name } = readOption(token);
      return name !== "" && "fix".startsWith(name);
    });
    if (command === "audit" && fixes)
      refuse(
        "not_wrapped",
        `${pm} audit fix changes dependencies without a check: use kovo ${pm} update instead.`,
      );
    return { kind: "passthrough", args };
  }
  return refuse(
    "not_wrapped",
    `kovo ${pm} wraps the commands that resolve, install or fetch dependencies (add, install, update, remove, dedupe, ${pm === "pnpm" ? "dlx, create" : "ci, exec, init"}) and read-only ones (ls, why, outdated and similar). This command can install or run project code without a check: run it with ${pm} directly after kovo ${pm} install.`,
  );
}
