// The `kovo` CLI's identity and its documented exit codes (SPEC "Recipes and verification" →
// "`kovo deps check`"). The exit codes are a public contract: CI jobs branch on them, in particular
// on 3 to fall back to `--offline` in the same job (plans/dependency-firewall.md Part 4 item 3).

/** The package version (packages/cli/package.json; a test keeps them equal). */
export const CLI_VERSION = "0.1.0";

export const EXIT = {
  /** Every changed or new version is `allow` or `warn` (warnings are printed). */
  pass: 0,
  /** At least one changed or new version is `block` or `wait`. */
  fail: 1,
  /** A usage error, or a lockfile that is missing, unreadable or unsupported. */
  usage: 2,
  /** The check could not be answered: the hosted check (or, offline, its evidence) is unreachable. */
  unavailable: 3,
} as const;
export type ExitCode = (typeof EXIT)[keyof typeof EXIT];
