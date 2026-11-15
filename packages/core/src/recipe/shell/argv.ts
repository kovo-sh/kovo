import { parseScript } from "./parse.js";

// Helpers over parsed command words: which program a command really runs once launcher wrappers
// (`npx`, `pnpm exec`, `cross-env`, …) are removed, and forbidden-flag detection.

export interface Invocation {
  /** The program's base name (`vitest` for `./node_modules/.bin/vitest`). */
  readonly program: string;
  /** The arguments after the program. */
  readonly args: readonly string[];
}

const MAX_UNWRAP = 8;

/** A command word's program name: its last path segment (`vitest` for `./node_modules/.bin/vitest`). */
export function programName(word: string): string {
  const slash = word.lastIndexOf("/");
  return slash === -1 ? word : word.slice(slash + 1);
}

/** Skips leading `NAME=value` words (after `env`/`cross-env`). */
function skipAssignments(words: readonly string[], from: number): number {
  let index = from;
  while (index < words.length && /^[A-Za-z_][A-Za-z0-9_]*=/.test(words[index] ?? "")) index += 1;
  return index;
}

/**
 * The program a command runs after removing launchers: `npx [-y|--yes|--no-install|-p <pkg>]`,
 * `npm exec [--]`, `pnpm exec`, `pnpm dlx`, `env`, `cross-env`, `time`, `nohup`, `dotenv --`.
 * Returns null for an empty command.
 */
export function unwrapInvocation(
  argv: readonly string[],
  options: { readonly envOptions?: true } = {},
): Invocation | null {
  let words = [...argv];
  for (let depth = 0; depth < MAX_UNWRAP && words.length > 0; depth += 1) {
    const program = programName(words[0] ?? "");
    let rest = 1;
    switch (program) {
      case "env":
        if (options.envOptions === true) {
          while (words[rest]?.startsWith("-")) {
            const option = words[rest]!;
            if (option === "--") {
              rest += 1;
              break;
            }
            if (option === "-u" || option === "--unset") {
              if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(words[rest + 1] ?? "")) return null;
              rest += 2;
            } else if (
              option === "-i" ||
              option === "--ignore-environment" ||
              /^--unset=[A-Za-z_][A-Za-z0-9_]*$/.test(option)
            )
              rest += 1;
            else return null;
          }
        }
        rest = skipAssignments(words, rest);
        break;
      case "cross-env":
        rest = skipAssignments(words, 1);
        break;
      case "time":
      case "nohup":
        break;
      case "npx":
        while (rest < words.length && (words[rest] ?? "").startsWith("-")) {
          const flag = words[rest] ?? "";
          rest += flag === "-p" || flag === "--package" ? 2 : 1;
        }
        break;
      case "npm":
      case "pnpm":
        if (words[1] === "exec" || (program === "pnpm" && words[1] === "dlx")) {
          rest = 2;
          while (rest < words.length && (words[rest] ?? "").startsWith("-")) {
            if (words[rest] === "--") {
              rest += 1;
              break;
            }
            rest += 1;
          }
          break;
        }
        return { program, args: words.slice(1) };
      case "dotenv": {
        const separator = words.indexOf("--");
        if (separator === -1) return { program, args: words.slice(1) };
        rest = separator + 1;
        break;
      }
      default:
        return { program, args: words.slice(1) };
    }
    words = words.slice(rest);
  }
  if (words.length === 0 || options.envOptions === true) return null;
  return { program: programName(words[0] ?? ""), args: words.slice(1) };
}

/** The normalized identity of a long flag: no dashes, underscores or case (`--pass-with-no-tests`). */
function longFlagKey(flag: string): string {
  return flag.replace(/^--/, "").replaceAll("-", "").replaceAll("_", "").toLowerCase();
}

function matchesFlag(word: string, forbidden: string): boolean {
  if (!word.startsWith("-")) return false;
  const [wordName = "", wordValue] = word.split(/=(.*)/s, 2);
  const [forbiddenName = "", forbiddenValue] = forbidden.split(/=(.*)/s, 2);
  if (forbiddenName.startsWith("--")) {
    if (!wordName.startsWith("--") || longFlagKey(wordName) !== longFlagKey(forbiddenName)) {
      return false;
    }
  } else if (wordName !== forbiddenName) {
    return false;
  }
  if (forbiddenValue !== undefined) return wordValue === forbiddenValue;
  // `--flag=false` / `--flag=0` turns a boolean flag off.
  return wordValue === undefined || !["false", "0"].includes(wordValue.toLowerCase());
}

/**
 * The forbidden flags that appear in `command` (for example `--passWithNoTests`, `-u`), in the order
 * of `forbidden`. Long flags match regardless of dash/camel spelling (`--pass-with-no-tests`),
 * because the CLI parsers of Vitest (cac) and Jest (yargs) accept both. The command is scanned as
 * parsed words and, as a fallback for scripts the parser marks complex, as raw whitespace-separated
 * tokens, so quoting or odd constructs cannot hide a flag.
 */
export function findForbiddenFlags(command: string, forbidden: readonly string[]): string[] {
  const parsed = parseScript(command);
  const words = parsed.commands.flatMap((cmd) => cmd.argv);
  const raw = command.split(/[\s;&|()<>`]+/).map((token) => token.replaceAll(/["']/g, ""));
  const candidates = [...words, ...raw];
  return forbidden.filter((flag) => candidates.some((word) => matchesFlag(word, flag)));
}
