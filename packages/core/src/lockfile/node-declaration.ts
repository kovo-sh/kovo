import semver from "semver";

// Reads a Node version declaration the way version managers interpret it: `.nvmrc` (nvm),
// `.node-version` (fnm, nodenv, n), the `nodejs`/`node` line of `.tool-versions` (asdf, mise), a
// Volta `node` pin, or a CI `setup-node` version. Repository content is hostile input: the text is
// bounded, codenames are looked up in a Map (never on an object, where `lts/constructor` would find a
// prototype member), and anything else is refused explicitly. One parser for inventory, recipe
// discovery and CI runtime preferences (docs/decisions/lockfile.md "Runtime resolution").

/** Node LTS codenames and their majors (immutable once assigned). */
export const NODE_LTS_CODENAMES: ReadonlyMap<string, number> = new Map([
  ["argon", 4],
  ["boron", 6],
  ["carbon", 8],
  ["dubnium", 10],
  ["erbium", 12],
  ["fermium", 14],
  ["gallium", 16],
  ["hydrogen", 18],
  ["iron", 20],
  ["jod", 22],
  ["krypton", 24],
]);

const MOVING_ALIASES: ReadonlySet<string> = new Set([
  "node",
  "latest",
  "stable",
  "current",
  "system",
  "iojs",
  "unstable",
]);

export type NodeDeclaration =
  /**
   * A version or version prefix (`22`, `22.11`, `22.11.0`, `22.x`, `v22`) or an LTS name: it fixes
   * the major. SPEC scopes support by major ("supported Node 22/24 runtimes"; "Unsupported
   * majors/formats produce an explicit unsupported reason"), and the exact version run is the
   * image's baked release of that major.
   */
  | { readonly kind: "major"; readonly major: number; readonly text: string }
  /** A semver range (`>=22.12 <25`): the baked release must satisfy it. */
  | { readonly kind: "range"; readonly range: string; readonly text: string }
  /** A moving alias (`node`, `latest`, `lts/*` without a known LTS major) that names no version. */
  | { readonly kind: "alias"; readonly text: string }
  /** Not a version declaration any version manager accepts. */
  | { readonly kind: "unrecognized"; readonly text: string }
  /** The file holds no declaration (empty or comments only). */
  | { readonly kind: "empty" };

/** At most this many characters of a version file are read. */
export const MAX_VERSION_FILE_LENGTH = 1024;

/**
 * Parses a Node declaration: the first line that is not blank or a `#` comment, `v` prefix
 * optional. `lts/*` resolves to `ltsMajor` (the pinned image's active LTS major), and is a moving
 * alias without one.
 */
export function parseNodeDeclaration(content: string, ltsMajor: number | null): NodeDeclaration {
  if (content.length > MAX_VERSION_FILE_LENGTH) return { kind: "unrecognized", text: "" };
  const text = content
    .split(/\r?\n/)
    .map((raw) => (raw.split("#")[0] ?? "").trim())
    .find((candidate) => candidate !== "");
  if (text === undefined) return { kind: "empty" };
  const value = text.toLowerCase().replace(/^v(?=\d)/, "");
  if (MOVING_ALIASES.has(value)) return { kind: "alias", text };
  if (value === "lts/*" || value === "lts") {
    return ltsMajor === null ? { kind: "alias", text } : { kind: "major", major: ltsMajor, text };
  }
  const lts = /^lts\/([a-z]+)$/.exec(value);
  if (lts !== null) {
    const major = NODE_LTS_CODENAMES.get(lts[1] ?? "");
    return major === undefined ? { kind: "unrecognized", text } : { kind: "major", major, text };
  }
  // `22`, `22.11`, `22.11.0`, `22.x`, `22.x.x`: a version or prefix, which fixes the major.
  const version = /^(\d+)(?:\.(?:\d+|x))?(?:\.(?:\d+|x))?$/.exec(value);
  if (version !== null) return { kind: "major", major: Number(version[1]), text };
  const range = semver.validRange(value);
  return range === null ? { kind: "unrecognized", text } : { kind: "range", range, text };
}

/** At most this many characters of `.tool-versions` (one line per tool) are read. */
export const MAX_TOOL_VERSIONS_LENGTH = 16 * 1024;

/**
 * The Node version `.tool-versions` names (`nodejs` or `node` line): `none` when it names none,
 * `unreadable` when the file is over its bound (a declaration Kovo cannot read is refused, never
 * skipped).
 */
export function toolVersionsNode(
  content: string,
):
  | { readonly kind: "version"; readonly text: string }
  | { readonly kind: "none" }
  | { readonly kind: "unreadable" } {
  if (content.length > MAX_TOOL_VERSIONS_LENGTH) return { kind: "unreadable" };
  for (const line of content.split(/\r?\n/)) {
    const match = /^\s*(?:nodejs|node)\s+(\S+)/.exec(line);
    const text = match?.[1];
    if (text !== undefined) return { kind: "version", text };
  }
  return { kind: "none" };
}

/** Whether `range` is a valid semver range (an `engines` value Kovo can evaluate). */
export function isValidRange(range: string): boolean {
  return semver.validRange(range) !== null;
}
