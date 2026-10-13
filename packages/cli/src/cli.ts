import { parseArgs } from "node:util";

import { API_KEY_ENV, depsCheck, type DepsCheckOptions } from "./deps/check.js";
import { DEFAULT_API_URL } from "./deps/api.js";
import { OSV_STORAGE_ORIGIN } from "./deps/offline/osv-snapshot.js";
import { NPM_REGISTRY_URL } from "./deps/offline/registry.js";
import { CLI_VERSION, EXIT, type ExitCode } from "./exit.js";
import type { CliIo } from "./io.js";
import { runWrapper } from "./pm/run.js";

export const HELP = `kovo ${CLI_VERSION}

Usage:
  kovo deps check [--base <ref>] [--head <ref>] [--lockfile <path>] [--format text|json]
                  [--api-url <url>]
  kovo deps check --offline [--base <ref>] [--head <ref>] [--lockfile <path>]
                  [--format text|json] [--osv-cache <dir>] [--osv-generation <n>]
                  [--osv-url <url>] [--registry-url <url>]
  kovo pnpm [<check options>] <pnpm command> [<pnpm arguments>]
  kovo npm [<check options>] <npm command> [<npm arguments>]
  kovo --version
  kovo --help

kovo deps check diffs the lockfile between a base commit and the head and judges only the changed
and new versions. Online, it sends the change list (names, versions, integrity, new or changed,
direct or transitive, source) to Kovo's hosted dependency check; the lockfile itself never leaves
the machine. Offline, the same engine judges them from OSV's public npm database and the public npm
registry; Kovo's own holds are not consulted. Supported lockfiles: package-lock.json (v2, v3),
pnpm-lock.yaml (v9) and yarn.lock (v1), including workspaces.

Options:
  --base <ref>           Base commit (default: the merge base with origin/HEAD, origin/main or
                         origin/master).
  --head <ref>           Head commit (default: the working tree).
  --lockfile <path>      The lockfile (default: the one in the current directory).
  --format <f>           text (default) or json.
  --api-url <url>        The Kovo API (default: ${DEFAULT_API_URL}).
  --offline              Judge without the Kovo API.
  --osv-cache <dir>      Where OSV's database is cached (default: ~/.cache/kovo/osv).
  --osv-generation <n>   Pin OSV's export to one object generation (default: the current one).
  --osv-url <url>        OSV's bucket API, or a mirror of it (default: ${OSV_STORAGE_ORIGIN}).
  --registry-url <url>   The npm registry, or a mirror of it (default: ${NPM_REGISTRY_URL}).

Environment:
  ${API_KEY_ENV}           The Kovo API key (online only). Read only from the environment, never
                         printed.

Exit codes:
  0  Every changed or new version is allowed or only warned about (warnings are printed).
  1  At least one version is blocked or waiting (the wait-end time is printed).
  2  Usage error, or a missing, unreadable or unsupported lockfile.
  3  The check could not be answered: the hosted check (online), or OSV's database or the
     registry (offline), could not be reached or read.

kovo pnpm and kovo npm check before anything installs. The check options (--offline, --api-url,
--osv-cache, --osv-generation, --osv-url, --registry-url) go before the package-manager command;
everything after it is the package manager's. Their own output goes to stderr.
  add, install, update, remove, dedupe (and their aliases)
      Resolve once with --lockfile-only --ignore-scripts (pnpm; its remove takes --lockfile-only
      alone) or --package-lock-only --ignore-scripts (npm), so nothing is downloaded into
      node_modules and no dependency lifecycle script runs; check the lockfile diff against the
      state before; then install with pnpm install --frozen-lockfile or npm ci. On a block or
      wait, an unreadable lockfile or a check that cannot be answered, package.json and the
      lockfile are restored byte for byte, nothing is installed, and the exit code is 1, 2 or 3
      as above. --ignore-scripts and the install filters (pnpm install's --prod, --dev,
      --no-optional; npm's --omit, --include) carry over to the install.
  pnpm install --frozen-lockfile, npm ci
      Run kovo deps check (merge base against the working tree) first; then the command. It takes
      no package names.
  pnpm dlx, pnpm create, npm exec, npm init <starter>
      Resolve the one package (an exact version or a dist-tag) from registry metadata, check it as
      a new direct dependency, then run it pinned to that version. Its own dependencies are not in
      any lockfile and are not checked. The metadata comes from --registry-url, else
      ${NPM_REGISTRY_URL}. npm gets -- before the package, so later options are the tool's;
      pnpm dlx refuses --package or --registry after it.
  ls, why, outdated and other read-only commands
      Run unchanged. Every other command is refused with the reason.
  Run them from the project's root (a workspace's root). Each command accepts only a short list
  of options, written in full (for example --save-dev or -D, --save-exact or -E, --omit=dev,
  --prod); any other option, spelling or abbreviation is refused with its name, and the options
  that keep the check safe are added last so they win. --registry (and --config.registry,
  --<scope>:registry) is refused: the check cannot evaluate packages from an unchecked registry,
  so configure the registry in the project .npmrc, or run the plain package manager without kovo.
  The project's own configuration (.npmrc, pnpm-workspace.yaml) is trusted and applies. The package
  manager never receives ${API_KEY_ENV}. Otherwise the exit code is the package manager's.
`;

/** Flags a key might be passed with; refused with a pointer to the environment variable. */
const KEY_FLAG = /^--?(?:api-?key|key|token)(?:=|$)/iu;

function usage(io: CliIo, message: string): ExitCode {
  io.stderr(`kovo: ${message}\nRun kovo --help for usage.\n`);
  return EXIT.usage;
}

/**
 * Runs the CLI with `argv` (without the node and script paths). Returns the exit code; never throws
 * for bad input.
 */
export async function runCli(argv: readonly string[], io: CliIo): Promise<number> {
  const [first, second, ...rest] = argv;
  if (first === "--version" || first === "-v") {
    io.stdout(`${CLI_VERSION}\n`);
    return EXIT.pass;
  }
  if (first === "--help" || first === "-h") {
    io.stdout(HELP);
    return EXIT.pass;
  }
  if (first === "pnpm" || first === "npm")
    return runWrapper(first, argv.slice(1), io, () => io.stdout(HELP));
  if (first !== "deps" || second !== "check")
    return usage(io, first === undefined ? "no command given." : "unknown command.");
  if (rest.some((arg) => KEY_FLAG.test(arg)))
    return usage(io, `the API key is read only from ${API_KEY_ENV}, never from a flag.`);
  let values;
  try {
    ({ values } = parseArgs({
      args: rest,
      options: {
        base: { type: "string" },
        head: { type: "string" },
        lockfile: { type: "string" },
        "api-url": { type: "string" },
        format: { type: "string" },
        offline: { type: "boolean" },
        "osv-cache": { type: "string" },
        "osv-generation": { type: "string" },
        "osv-url": { type: "string" },
        "registry-url": { type: "string" },
        help: { type: "boolean", short: "h" },
      },
      strict: true,
      allowPositionals: false,
    }));
  } catch {
    // The parser's own message can echo an argument; only a fixed message is printed.
    return usage(io, "unknown option, missing option value or unexpected argument.");
  }
  if (values.help === true) {
    io.stdout(HELP);
    return EXIT.pass;
  }
  const format = values.format ?? "text";
  if (format !== "text" && format !== "json") return usage(io, "--format must be text or json.");
  const offlineOnly = ["osv-cache", "osv-generation", "osv-url", "registry-url"] as const;
  let mode: DepsCheckOptions["mode"];
  if (values.offline === true) {
    if (values["api-url"] !== undefined)
      return usage(io, "--api-url and --offline cannot be combined.");
    mode = {
      kind: "offline",
      osvCache: values["osv-cache"],
      osvGeneration: values["osv-generation"],
      osvUrl: values["osv-url"],
      registryUrl: values["registry-url"],
    };
  } else {
    const stray = offlineOnly.find((name) => values[name] !== undefined);
    if (stray !== undefined) return usage(io, `--${stray} needs --offline.`);
    mode = { kind: "online", apiUrl: values["api-url"] };
  }
  return depsCheck(
    { base: values.base, head: values.head, lockfile: values.lockfile, format, mode },
    io,
  );
}
