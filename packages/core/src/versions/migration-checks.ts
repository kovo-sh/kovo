import semver from "semver";

import { CHANGELOG_SCAN_LIMITS, releaseSectionsInRange } from "./changelog-check.js";

// Trusted checks of a major upgrade's migration. Kovo
// verified wrong fixes because nothing it ran looked at the code the upgrade breaks:
// - a silent return-shape change breaks no repository check, so the ladder's bump with no
//   migration passed verification;
// - where the type check is the only check that sees a type break, an option the notes call
//   unsafe turns it green (suppressions and casts are `findCheckBypasses`' in `@kovo/core/patch`).
// The checks here are pure and can only refuse a candidate. They read the release notes the
// installed package ships and the repository files that import it, as untrusted data matched by
// fixed patterns (no model reads them, so text in them cannot steer anything: the upstream screen is
// structural). Nothing but outcomes, reason codes and counts leaves this module.

export type MigrationCallSiteOutcome = "clear" | "unavailable" | "blocked";

export const MIGRATION_CALL_SITE_REASONS = [
  // Nothing the notes name is left unmigrated by a bump alone, and no unsafe option is added.
  "migration_call_sites_clear",
  // No release notes could be read for any moved major, or the files were over the bounds (the
  // check does not block then).
  "migration_notes_unavailable",
  // A bump with no source change, while a source file calls an API the major's notes name.
  "migration_call_sites_unchanged",
  // The candidate adds an option the major's notes call unsafe (an opt-out of the fix).
  "migration_unsafe_option_added",
] as const;
export type MigrationCallSiteReason = (typeof MIGRATION_CALL_SITE_REASONS)[number];

export interface MigrationCallSiteResult {
  readonly outcome: MigrationCallSiteOutcome;
  readonly reason: MigrationCallSiteReason;
  /** The findings behind a block (unchanged calls, added casts or added unsafe options). */
  readonly count: number;
}

/** Bounds on the untrusted text the check reads. */
export const MIGRATION_CHECK_LIMITS = {
  maxPackages: 8,
  maxFiles: 200,
  maxFileChars: 512 * 1024,
} as const;

/** One direct dependency the candidate moved across a major, with the notes it ships. */
export interface MovedMajor {
  readonly name: string;
  readonly from: string;
  readonly to: string;
  /** Release notes as read (untrusted, ephemeral): CHANGELOG, migration or upgrading guides. */
  readonly documents: readonly string[];
}

/** A source file that may change: its base text, and its text in the candidate (null: deleted). */
export interface MigrationFile {
  readonly path: string;
  readonly base: string;
  readonly head: string | null;
}

export interface MigrationCallSiteInput {
  readonly packages: readonly MovedMajor[];
  readonly files: readonly MigrationFile[];
}

const IDENTIFIER = /[A-Za-z_$][\w$]*/gu;
// Inline code spans: the notes name APIs in code (`sanitizeUrl`), and prose words never count.
const CODE_SPAN = /`+([^`\n]+?)`+/gu;
// An option key inside a code span (`{ allowOutside: true }`).
const OPTION_KEY = /([A-Za-z_$][\w$]*)\s*:/gu;
// A note that calls something unsafe.
const UNSAFE = /\b(?:unsafe|insecure|dangerous|not safe|vulnerable)\b/iu;
// A list item opening a note; the lines after it, up to a blank line, a heading or the next item,
// continue it.
const ITEM = /^\s*(?:[-*+]|\d+[.)])\s/u;

/** What a major's notes say: the APIs they name in code, and the option keys they call unsafe. */
export interface MajorNotes {
  readonly apis: Set<string>;
  readonly unsafeOptions: Set<string>;
}

/**
 * Bounds on what the notes may yield (the notes are untrusted upstream text). Only
 * identifiers ever leave the parse, each at most `maxIdentifierChars` long and at most
 * `maxNames` of them; nothing else of the text is kept, returned, logged or given to a model.
 */
export const NOTES_LIMITS = {
  maxIdentifierChars: 128,
  maxNames: 2000,
  maxItemChars: 8 * 1024,
} as const;

const FENCE = /^\s*(?:```|~~~)/u;

/**
 * The notes' items (a list item with its continuation lines, or a paragraph line), each cut at
 * `NOTES_LIMITS.maxItemChars`. Fenced code blocks are skipped: an example names no API change.
 */
function noteItems(lines: readonly string[]): string[] {
  const items: string[] = [];
  let open = false;
  let fenced = false;
  for (const line of lines) {
    if (FENCE.test(line)) {
      fenced = !fenced;
      open = false;
      continue;
    }
    if (fenced) continue;
    const trimmed = line.trim();
    if (trimmed === "" || trimmed.startsWith("#")) {
      open = false;
      continue;
    }
    if (ITEM.test(line) || !open) {
      items.push(trimmed);
      open = true;
    } else {
      items[items.length - 1] = `${items.at(-1) ?? ""} ${trimmed}`.slice(
        0,
        NOTES_LIMITS.maxItemChars,
      );
    }
  }
  return items.map((item) => item.slice(0, NOTES_LIMITS.maxItemChars));
}

/** Adds an identifier to a bounded name set. */
function addName(names: Set<string>, name: string): void {
  if (name.length <= NOTES_LIMITS.maxIdentifierChars && names.size < NOTES_LIMITS.maxNames) {
    names.add(name);
  }
}

/**
 * The notes of a major, read from the sections of the releases the caret range from `from` does
 * not admit (the major itself and later releases up to `to`). Every line of such a section counts:
 * a major's notes describe breaks without a "breaking" marker. A document with no version
 * headings Kovo can read (a setext or dated history file, a heading-less guide) is skipped: read
 * as one section it would name every API of every release. Null when no versioned notes remain.
 */
export function readMajorNotes(moved: MovedMajor): MajorNotes | null {
  const from = semver.parse(moved.from);
  const to = semver.parse(moved.to);
  if (from === null || to === null) return null;
  const documents = moved.documents
    .slice(0, CHANGELOG_SCAN_LIMITS.maxDocuments)
    .filter((document) => document.trim().length > 0);
  if (documents.length === 0) return null;
  const apis = new Set<string>();
  const unsafeOptions = new Set<string>();
  let versioned = false;
  for (const document of documents) {
    for (const section of releaseSectionsInRange(document, from, to)) {
      if (section.version === null) continue;
      versioned = true;
      if (semver.satisfies(section.version, `^${moved.from}`)) continue;
      for (const item of noteItems(section.lines)) {
        const unsafe = UNSAFE.test(item);
        for (const span of item.matchAll(CODE_SPAN)) {
          const code = span[1] ?? "";
          for (const token of code.match(IDENTIFIER) ?? []) addName(apis, token);
          if (!unsafe) continue;
          for (const option of code.matchAll(OPTION_KEY)) {
            if (option[1] !== undefined) addName(unsafeOptions, option[1]);
          }
        }
      }
    }
  }
  return versioned ? { apis, unsafeOptions } : null;
}

function escapeRegExp(text: string): string {
  return text.replace(/[.*+?^${}()|[\]\\/]/gu, "\\$&");
}

/** How a file binds a package: named imports (local → exported) and namespace/default bindings. */
export interface Bindings {
  readonly named: Map<string, string>;
  readonly namespaces: Set<string>;
}

/** `a`, `a: b`, `a as b`, `a = x` entries of a destructuring or an import clause. */
function addNamed(named: Map<string, string>, list: string, separator: ":" | "as"): void {
  for (const raw of list.split(",")) {
    const entry = raw
      .replace(/=.*$/su, "")
      .replace(/^\s*type\s+/u, "")
      .trim();
    if (entry === "" || entry.startsWith("...")) continue;
    const parts =
      separator === ":" ? entry.split(":") : entry.split(/\s+as\s+/u).filter((p) => p !== "");
    const exported = parts[0]?.trim();
    const local = (parts[1] ?? parts[0])?.trim();
    if (exported === undefined || local === undefined) continue;
    if (!/^[A-Za-z_$][\w$]*$/u.test(exported) || !/^[A-Za-z_$][\w$]*$/u.test(local)) continue;
    named.set(local, exported);
  }
}

/** The bindings `text` makes for package `name` (or a subpath of it); structural, never run. */
export function packageBindings(text: string, name: string): Bindings {
  // A named group: the patterns below put the specifier after a group of their own.
  const spec = `(?<quote>['"])${escapeRegExp(name)}(?:/[^'"\\n]*)?\\k<quote>`;
  const named = new Map<string, string>();
  const namespaces = new Set<string>();
  const requireLike = `(?:require|(?:await\\s+)?import)\\s*\\(\\s*${spec}\\s*\\)`;
  for (const match of text.matchAll(
    new RegExp(`(?:const|let|var)\\s*\\{([^}]*)\\}\\s*=\\s*${requireLike}`, "gu"),
  )) {
    addNamed(named, match[1] ?? "", ":");
  }
  for (const match of text.matchAll(
    new RegExp(`(?:const|let|var)\\s+([A-Za-z_$][\\w$]*)\\s*=\\s*${requireLike}`, "gu"),
  )) {
    if (match[1] !== undefined) namespaces.add(match[1]);
  }
  for (const match of text.matchAll(new RegExp(`import\\s+([^;'"]*?)\\s+from\\s*${spec}`, "gu"))) {
    let clause = (match[1] ?? "").replace(/^type\s+/u, "");
    const braces = /\{([^}]*)\}/u.exec(clause);
    if (braces !== null) {
      addNamed(named, braces[1] ?? "", "as");
      clause = clause.replace(braces[0], "");
    }
    const star = /\*\s*as\s+([A-Za-z_$][\w$]*)/u.exec(clause);
    if (star?.[1] !== undefined) namespaces.add(star[1]);
    const defaultName = /^\s*([A-Za-z_$][\w$]*)/u.exec(clause.replace(/\*\s*as\s+[\w$]+/u, ""));
    if (defaultName?.[1] !== undefined) namespaces.add(defaultName[1]);
  }
  return { named, namespaces };
}

/** A pattern matching a call of one of `apis` (all of the package's when null) through `bindings`. */
function callPatterns(bindings: Bindings, apis: ReadonlySet<string> | null): RegExp[] {
  const patterns: RegExp[] = [];
  for (const [local, exported] of bindings.named) {
    if (apis === null || apis.has(exported)) {
      patterns.push(new RegExp(`(?<![\\w$.])${escapeRegExp(local)}\\s*\\(`, "u"));
    }
  }
  const members = apis === null ? "[A-Za-z_$][\\w$]*" : [...apis].map(escapeRegExp).join("|");
  if (members === "") return patterns;
  for (const namespace of bindings.namespaces) {
    patterns.push(
      new RegExp(`(?<![\\w$.])${escapeRegExp(namespace)}\\s*\\.\\s*(?:${members})\\s*\\(`, "u"),
    );
  }
  return patterns;
}

/** Line indexes (0-based) of `text` that call one of `apis` through `bindings`. */
export function callLines(
  text: string,
  bindings: Bindings,
  apis: ReadonlySet<string> | null,
): number[] {
  const patterns = callPatterns(bindings, apis);
  if (patterns.length === 0) return [];
  const calls: number[] = [];
  for (const [index, line] of text.split(/\r?\n/u).entries()) {
    if (patterns.some((pattern) => pattern.test(line))) calls.push(index);
  }
  return calls;
}

function occurrences(text: string, word: string): number {
  return text.match(new RegExp(`(?<![\\w$])${escapeRegExp(word)}(?![\\w$])`, "gu"))?.length ?? 0;
}

const result = (
  outcome: MigrationCallSiteOutcome,
  reason: MigrationCallSiteReason,
  count = 0,
): MigrationCallSiteResult => ({ outcome, reason, count });

/**
 * Whether a candidate that moves direct dependencies across a major migrated the code that uses
 * them. It refuses (`blocked`) when, in a file the candidate may change and that imports a moved
 * package:
 * - the candidate adds an option key the major's notes call unsafe;
 * - it changes no source file at all (a bump alone) while the file calls an API the major's notes
 *   name in code.
 * Suppressions and `any` casts an agent adds are `findCheckBypasses`' (`@kovo/core/patch`), run on
 * every agent candidate before this. Blocks only on evidence: without notes, or over the bounds,
 * it is `unavailable`. A candidate that edits source is not judged call by call: the eval
 * corpus showed correct migrations (an ESM `import()`, an aliased import, a changed constructor
 * call) that leave named calls as they were, so a partial migration stays the repository's
 * checks' and the reviewer's to catch.
 */
export function checkMigrationCallSites(input: MigrationCallSiteInput): MigrationCallSiteResult {
  if (
    input.packages.length > MIGRATION_CHECK_LIMITS.maxPackages ||
    input.files.length > MIGRATION_CHECK_LIMITS.maxFiles ||
    input.files.some(
      (file) =>
        file.base.length > MIGRATION_CHECK_LIMITS.maxFileChars ||
        (file.head?.length ?? 0) > MIGRATION_CHECK_LIMITS.maxFileChars,
    )
  ) {
    return result("unavailable", "migration_notes_unavailable");
  }
  let read = false;
  let unsafe = 0;
  let unchanged = 0;
  const bumpOnly = input.files.every((file) => file.head === file.base);
  for (const moved of input.packages) {
    const notes = readMajorNotes(moved);
    if (notes !== null) read = true;
    for (const file of input.files) {
      const bindings = packageBindings(file.base, moved.name);
      const headBindings = file.head === null ? null : packageBindings(file.head, moved.name);
      const imports =
        bindings.named.size + bindings.namespaces.size > 0 ||
        (headBindings !== null && headBindings.named.size + headBindings.namespaces.size > 0);
      if (!imports || file.head === null) continue;
      for (const option of notes?.unsafeOptions ?? []) {
        unsafe += Math.max(0, occurrences(file.head, option) - occurrences(file.base, option));
      }
      if (bumpOnly && notes !== null && notes.apis.size > 0) {
        unchanged += callLines(file.base, bindings, notes.apis).length;
      }
    }
  }
  if (unsafe > 0) return result("blocked", "migration_unsafe_option_added", unsafe);
  if (!read) return result("unavailable", "migration_notes_unavailable");
  if (unchanged > 0) return result("blocked", "migration_call_sites_unchanged", unchanged);
  return result("clear", "migration_call_sites_clear");
}

// ---- Untested call sites ----

/** Bounds on the repository read to judge test reach. */
export const TEST_REACH_LIMITS = { maxFiles: 400, maxFileChars: 512 * 1024 } as const;

// A relative module specifier in `require()`, `import(...)`, `import … from` or `export … from`.
const RELATIVE_SPECIFIER =
  /(?:require\s*\(\s*|import\s*\(\s*|\bfrom\s*)(['"])(\.{1,2}\/[^'"\n]*)\1/gu;
const RESOLVE_EXTENSIONS = ["", ".js", ".cjs", ".mjs", ".jsx", ".ts", ".cts", ".mts", ".tsx"];

/** Normalises `dir/specifier` to a repository path; null when it leaves the repository. */
function joinPath(dir: string, specifier: string): string | null {
  const parts = dir === "" ? [] : dir.split("/");
  for (const part of specifier.split("/")) {
    if (part === "" || part === ".") continue;
    if (part === "..") {
      if (parts.length === 0) return null;
      parts.pop();
    } else parts.push(part);
  }
  return parts.join("/");
}

/** The repository files `path` imports by relative specifier, resolved against `known`. */
function relativeImports(path: string, text: string, known: ReadonlySet<string>): string[] {
  const dir = path.includes("/") ? path.slice(0, path.lastIndexOf("/")) : "";
  const found: string[] = [];
  for (const match of text.matchAll(RELATIVE_SPECIFIER)) {
    const joined = joinPath(dir, match[2] ?? "");
    if (joined === null) continue;
    // TypeScript ESM imports name the emitted `.js`; the source is `.ts`.
    const stem = joined.replace(/\.(?:[cm]?js|jsx)$/u, "");
    const candidates = [
      ...RESOLVE_EXTENSIONS.map((extension) => `${joined}${extension}`),
      ...RESOLVE_EXTENSIONS.map((extension) => `${stem}${extension}`),
      ...RESOLVE_EXTENSIONS.slice(1).map((extension) => `${joined}/index${extension}`),
    ];
    const hit = candidates.find((candidate) => known.has(candidate));
    if (hit !== undefined) found.push(hit);
  }
  return found;
}

export interface TestReachInput {
  /** The moved direct majors' package names. */
  readonly packages: readonly string[];
  /** Every JavaScript and TypeScript file of the candidate's checkout (`node_modules` excluded). */
  readonly files: readonly { readonly path: string; readonly text: string }[];
  /** Whether a path is a test file (Kovo's protected test paths). */
  readonly isTest: (path: string) => boolean;
  /**
   * The repository's own check commands (its package.json `scripts` values), untrusted text. A
   * repository file a command names (`node scripts/build.js`) is an entry point like a test: a
   * check runs it, and what it imports.
   */
  readonly checkCommands?: readonly string[];
}

/** Repository files that `commands` name as plain path tokens (`scripts/build.js`, `./x.mjs`). */
function commandEntryPoints(commands: readonly string[], known: ReadonlySet<string>): string[] {
  const found = new Set<string>();
  for (const command of commands.slice(0, 200)) {
    for (const token of command.slice(0, 4096).split(/[\s'"=;&|()]+/u)) {
      const path = joinPath("", token);
      if (path !== null && known.has(path)) found.add(path);
    }
  }
  return [...found];
}

/**
 * How many non-test files call a moved package and are reached by no check: neither a test nor a
 * file a check command names imports them, directly or through other files (relative imports).
 * Null when the repository is over the bounds (nothing is claimed either way). Structural only;
 * nothing is run.
 */
export function untestedCallSiteFiles(input: TestReachInput): number | null {
  if (
    input.files.length > TEST_REACH_LIMITS.maxFiles ||
    input.files.some((file) => file.text.length > TEST_REACH_LIMITS.maxFileChars)
  ) {
    return null;
  }
  const known = new Set(input.files.map((file) => file.path));
  const imports = new Map(
    input.files.map((file) => [file.path, relativeImports(file.path, file.text, known)]),
  );
  const entries = commandEntryPoints(input.checkCommands ?? [], known);
  const reached = new Set<string>(entries);
  const queue = [
    ...input.files.filter((file) => input.isTest(file.path)).map((file) => file.path),
    ...entries,
  ];
  for (let path = queue.shift(); path !== undefined; path = queue.shift()) {
    for (const next of imports.get(path) ?? []) {
      if (reached.has(next)) continue;
      reached.add(next);
      queue.push(next);
    }
  }
  return input.files.filter(
    (file) =>
      !input.isTest(file.path) &&
      !reached.has(file.path) &&
      input.packages.some(
        (name) => callLines(file.text, packageBindings(file.text, name), null).length > 0,
      ),
  ).length;
}
