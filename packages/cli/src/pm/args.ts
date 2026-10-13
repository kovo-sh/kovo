import { usageError } from "../errors.js";

// Command-line normalisation for `kovo pnpm` / `kovo npm`, faithful to how both package managers
// read their arguments (npm's nopt and pnpm's fork of it), then held to an allowlist.
//
// nopt, for a token that starts with `-` (and is not a run of dashes), in npm's nopt 10.0.1
// `lib/nopt-lib.js` `parse` and pnpm's fork alike:
// - splits an inline `=value` off first, as the next argument;
// - resolves an exact option name as itself, else an exact or abbreviated shorthand, else single
//   characters that are all shorthands (`resolveShort`), for any number of leading dashes;
// - strips every leading dash, then every leading `no-` in any case (each one inverts a boolean),
//   then expands an unambiguous abbreviation;
// - a boolean (or any `no-` option) consumes a following `true`/`false` token; a string option
//   consumes the next token unless it looks like an option (then its value is empty);
// - treats any run of two or more dashes (`--`, `---`) as the end of options.
//
// Instead of expanding abbreviations and shorthands against each package manager's full option
// list, the wrapper accepts only exact, full option names and exact single-dash shorthands from a
// per-command allowlist, and refuses every other spelling. Accepted options are re-emitted as one
// canonical token each (`--name`, `--no-name`, `--name=value`, or the shorthand as written), so the
// package manager reads exactly what the wrapper checked.

/** An allowed long option: its type, whether the install step repeats it, a required value. */
export interface LongSpec {
  readonly type: "boolean" | "string";
  /** Repeated on the install step after a passing check. */
  readonly carry?: boolean;
  /** A boolean that must have this value; any spelling of the other value is refused. */
  readonly must?: boolean;
  /** A string option given at most once. */
  readonly once?: boolean;
}

/** An allowed single-dash shorthand, accepted only exactly as written (`-D`). */
export interface ShortSpec {
  readonly carry?: boolean;
}

export interface Allowlist {
  readonly long: Readonly<Record<string, LongSpec>>;
  readonly short: Readonly<Record<string, ShortSpec>>;
}

/** One accepted option, re-emitted as `token`. */
export interface NormalizedOption {
  readonly name: string;
  readonly value: boolean | string;
  readonly token: string;
  readonly carry: boolean;
}

export interface Normalized {
  readonly options: readonly NormalizedOption[];
  readonly positionals: readonly string[];
}

/** A run of two or more dashes: nopt's end of options. */
export function isTerminator(token: string): boolean {
  return /^-{2,}$/u.test(token);
}

/** A token nopt reads as an option (or shorthand), rather than a positional or a terminator. */
export function isOptionToken(token: string): boolean {
  return token.length > 1 && token.startsWith("-") && !isTerminator(token);
}

/** One token as nopt reads its name: the name after dashes and `no-` prefixes, and the value. */
export interface ReadOption {
  /** True when written with a single dash: nopt tries it as a shorthand first. */
  readonly short: boolean;
  readonly name: string;
  /** An odd number of `no-` prefixes (any case). */
  readonly negated: boolean;
  /** An inline `=value`, or null. */
  readonly inline: string | null;
}

/** How nopt reads an option token's name (see the module comment). */
export function readOption(token: string): ReadOption {
  const eq = token.indexOf("=");
  const head = eq === -1 ? token : token.slice(0, eq);
  const inline = eq === -1 ? null : token.slice(eq + 1);
  const short = !head.startsWith("--");
  let name = head.replace(/^-+/u, "");
  let negated = false;
  while (name.toLowerCase().startsWith("no-")) {
    negated = !negated;
    name = name.slice(3);
  }
  return { short, name, negated, inline };
}

function refuse(code: string, message: string): never {
  throw usageError(code, message);
}

/**
 * The fixed refusal for a registry option (agent decision, owner review #1475): `--registry`,
 * pnpm's dotted `--config.registry` and the scoped `--@scope:registry` / `--//host/:registry` forms.
 */
export const REGISTRY_REFUSAL =
  "--registry is not supported by the Kovo wrapper because the check cannot evaluate packages from an unchecked registry; configure the registry in the project .npmrc, or run the plain package manager without kovo.";

/** Whether an option name (as `readOption` reads it) sets a registry. */
export function isRegistryOption(name: string): boolean {
  const lower = name.toLowerCase();
  return lower === "registry" || lower.endsWith(".registry") || lower.endsWith(":registry");
}

/** Error (exit 2) with {@link REGISTRY_REFUSAL} when `name` sets a registry. */
export function refuseRegistryOption(name: string): void {
  if (isRegistryOption(name)) refuse("unsupported_option", REGISTRY_REFUSAL);
}

/**
 * Normalises `args` (one command's arguments, after the command word) against `allowlist`. Error
 * (exit 2): a run of dashes, any option or spelling the allowlist does not hold, a boolean with a
 * value other than true or false, a value option without its value, a required value spelled the
 * other way, or a repeated once-only option. `context` names the command in messages.
 */
export function normalize(
  args: readonly string[],
  allowlist: Allowlist,
  context: string,
): Normalized {
  const options: NormalizedOption[] = [];
  const positionals: string[] = [];
  for (let index = 0; index < args.length; index += 1) {
    const token = args[index]!;
    if (isTerminator(token))
      refuse("unsupported_option", `${context} does not pass arguments after ${token}.`);
    if (!isOptionToken(token)) {
      positionals.push(token);
      continue;
    }
    const read = readOption(token);
    refuseRegistryOption(read.name);
    const next = args[index + 1];
    if (read.short && !token.startsWith("--") && Object.hasOwn(allowlist.short, read.name)) {
      if (read.inline !== null || read.negated || token !== `-${read.name}`)
        refuse("unsupported_option", `${context} accepts ${token.split("=")[0]} only as written.`);
      if (next === "true" || next === "false")
        refuse(
          "unsupported_option",
          `${context}: write the option's value with = (for example --save-dev=false), not as a separate ${next}.`,
        );
      options.push({
        name: read.name,
        value: true,
        token,
        carry: allowlist.short[read.name]!.carry === true,
      });
      continue;
    }
    // A single-dash token that is not an allowed shorthand is a shorthand group or an abbreviation
    // nopt would expand: refused, like any long name the allowlist does not hold exactly.
    const spec =
      !read.short && Object.hasOwn(allowlist.long, read.name)
        ? allowlist.long[read.name]
        : undefined;
    if (spec === undefined)
      refuse(
        "unsupported_option",
        `${context} does not accept ${token.split("=")[0]}: only the options it checks, written in full, are passed to the package manager.`,
      );
    const name = read.name;
    if (spec.type === "boolean") {
      let value: boolean;
      if (read.inline !== null) {
        if (read.inline !== "true" && read.inline !== "false")
          refuse("unsupported_option", `${context}: --${name} takes true or false.`);
        value = read.inline === "true";
      } else if (next === "true" || next === "false") {
        value = next === "true";
        index += 1;
      } else value = true;
      if (read.negated) value = !value;
      if (spec.must !== undefined && value !== spec.must)
        refuse(
          "unsupported_option",
          `${context} needs --${spec.must ? "" : "no-"}${name}: it ${spec.must ? "keeps" : "turns off"} it for the check.`,
        );
      options.push({
        name,
        value,
        token: value ? `--${name}` : `--no-${name}`,
        carry: spec.carry === true,
      });
      continue;
    }
    if (read.negated) refuse("unsupported_option", `${context}: --${name} cannot be negated.`);
    let value = read.inline;
    if (value === null) {
      // nopt gives a string option an empty value when the next token looks like an option, and
      // stops at a run of dashes: both are refused rather than modelled.
      if (next === undefined || next.startsWith("-"))
        refuse("unsupported_option", `${context}: --${name} needs a value (--${name}=<value>).`);
      value = next;
      index += 1;
    }
    if (spec.once === true && options.some((option) => option.name === name))
      refuse("unsupported_option", `${context} accepts --${name} once.`);
    options.push({ name, value, token: `--${name}=${value}`, carry: spec.carry === true });
  }
  return { options, positionals };
}

/** The last value of an option, or undefined when it is absent. */
export function lastValue(normalized: Normalized, name: string): boolean | string | undefined {
  let value: boolean | string | undefined;
  for (const option of normalized.options) if (option.name === name) value = option.value;
  return value;
}

/**
 * The last value nopt gives a boolean option written in full in `args` (up to a run of dashes),
 * before any allowlist: it decides which allowlist a line is held to. Undefined when absent.
 */
export function lastBoolean(args: readonly string[], name: string): boolean | undefined {
  let value: boolean | undefined;
  for (const [index, token] of args.entries()) {
    if (isTerminator(token)) break;
    if (!isOptionToken(token)) continue;
    const read = readOption(token);
    if (read.short || read.name !== name) continue;
    const next = args[index + 1];
    let on: boolean | undefined;
    if (read.inline !== null)
      on = read.inline === "true" ? true : read.inline === "false" ? false : undefined;
    else on = next !== "false";
    value = on === undefined ? undefined : read.negated ? !on : on;
  }
  return value;
}
