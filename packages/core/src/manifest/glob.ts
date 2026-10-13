// A small, dependency-free glob matcher for repository paths (protected paths and policy
// `protected_paths`). Semantics, chosen to fail closed (docs/decisions/lockfile.md "Manifest
// allowlist and protected paths"):
// - Patterns are anchored at the repository root; `**` spans any number of path segments
//   (including none), `*` and `?` stay inside one segment, `[…]` is a character class (`[!…]` or
//   `[^…]` negated), `{a,b}` is an alternation.
// - `*` also matches names starting with a dot (a protection must not miss `.env`).
// - A pattern matching a directory protects everything below it (`tests` protects `tests/a.ts`).
// - Matching is case-insensitive: a protection must not be bypassed by `.GitHub/` on a
//   case-insensitive checkout.
// - A path equal to the pattern taken literally (or below it) matches too: there is no escape
//   character (backslashes are refused), so a policy protecting a Next.js route such as
//   `app/[slug]/page.tsx` would otherwise compile `[slug]` into a character class and protect
//   nothing.
//
// Policy globs are hostile input (a repository admin or a write key sets them). The first version
// compiled them to backtracking regular expressions: `*a*a*a*a*a*a*a*a*b` took 23.6 s against a
// 60-character path. A glob now compiles to a Thompson NFA that is simulated over the path, one
// set of states per character, so a match costs at most (path length × pattern states) steps and
// never backtracks. The simulation reports its steps to an optional {@link GlobWork} budget, so a
// caller matching many paths against many globs bounds the total (`protected-paths.ts`).

/** Longest pattern accepted (policy globs are at most 256 characters). */
export const MAX_GLOB_LENGTH = 1024;

/** A step budget shared by many matches; {@link GlobWorkExceeded} is thrown when it runs out. */
export interface GlobWork {
  remaining: number;
}

/** Thrown by a match that would take more steps than its {@link GlobWork} has left. */
export class GlobWorkExceeded extends Error {
  override readonly name = "GlobWorkExceeded";

  constructor() {
    super("glob matching exceeded its step budget");
  }
}

// ---- Pattern pieces: exactly the constructs the first version compiled to a RegExp. ----

type ClassItem = readonly [low: number, high: number];

type Piece =
  | { readonly kind: "char"; readonly char: string }
  | { readonly kind: "not_slash" } // `?`, and each character of a `[^/]+`
  | { readonly kind: "not_slash_star" } // `*`
  | { readonly kind: "any_star" } // `**` as the whole pattern's last segment at the root
  | { readonly kind: "class"; readonly negated: boolean; readonly items: readonly ClassItem[] }
  | { readonly kind: "alternation"; readonly alternatives: readonly (readonly Piece[])[] }
  | { readonly kind: "segments_star" } // `**/`: any number of `name/` segments
  | { readonly kind: "optional_descendant" }; // `(/…)?`: the path itself or anything below it

/** The items of a class body: single characters and `a-z` ranges (a reversed range is literal). */
function classItems(body: string): ClassItem[] {
  const items: ClassItem[] = [];
  for (let index = 0; index < body.length; index += 1) {
    const low = body.charCodeAt(index);
    if (body.charAt(index + 1) === "-" && index + 2 < body.length) {
      const high = body.charCodeAt(index + 2);
      if (low <= high) items.push([low, high]);
      // A reversed range is a syntax error in a RegExp; read literally, it protects more.
      else items.push([low, low], [0x2d, 0x2d], [high, high]);
      index += 2;
    } else {
      items.push([low, low]);
    }
  }
  return items;
}

/** The pieces of the part of a pattern inside one path segment. */
function segmentPieces(segment: string): Piece[] {
  const pieces: Piece[] = [];
  for (let index = 0; index < segment.length; index += 1) {
    const char = segment.charAt(index);
    if (char === "*") {
      pieces.push({ kind: "not_slash_star" });
    } else if (char === "?") {
      pieces.push({ kind: "not_slash" });
    } else if (char === "[") {
      const close = segment.indexOf("]", index + 2);
      if (close === -1) {
        pieces.push({ kind: "char", char });
        continue;
      }
      let body = segment.slice(index + 1, close);
      const negated = body.startsWith("!") || body.startsWith("^");
      if (negated) body = body.slice(1);
      pieces.push({ kind: "class", negated, items: classItems(body) });
      index = close;
    } else if (char === "{") {
      const close = segment.indexOf("}", index + 1);
      if (close === -1) {
        pieces.push({ kind: "char", char });
        continue;
      }
      const alternatives = segment
        .slice(index + 1, close)
        .split(",")
        .map(segmentPieces);
      pieces.push({ kind: "alternation", alternatives });
      index = close;
    } else {
      pieces.push({ kind: "char", char });
    }
  }
  return pieces;
}

/** The pieces of a whole pattern: segments, `**` segments and the descendant suffix. */
function patternPieces(pattern: string, descendants = true): Piece[] {
  const segments = pattern.split("/");
  const pieces: Piece[] = [];
  segments.forEach((segment, index) => {
    const last = index === segments.length - 1;
    const previousWasGlobstar = index > 0 && segments[index - 1] === "**";
    if (segment === "**") {
      if (last) pieces.push(index === 0 ? { kind: "any_star" } : { kind: "optional_descendant" });
      else {
        if (index > 0) pieces.push({ kind: "char", char: "/" });
        pieces.push({ kind: "segments_star" });
      }
      return;
    }
    if (index > 0 && !previousWasGlobstar) pieces.push({ kind: "char", char: "/" });
    pieces.push(...segmentPieces(segment));
  });
  if (descendants) pieces.push({ kind: "optional_descendant" });
  return pieces;
}

// ---- The NFA ----

type State =
  | { readonly kind: "accept" }
  | { readonly kind: "split"; next: number; readonly alt: number }
  | { readonly kind: "char"; readonly key: string; readonly next: number }
  | { readonly kind: "not_slash"; readonly next: number }
  | { readonly kind: "any"; readonly next: number }
  | {
      readonly kind: "class";
      readonly negated: boolean;
      readonly items: readonly ClassItem[];
      readonly next: number;
    };

const ACCEPT = 0;

/** A one-code-unit case mapping, or the code unit itself when the mapping is longer. */
function single(mapped: string, char: string): string {
  return mapped.length === 1 ? mapped : char;
}

/**
 * The case-insensitive comparison key of one code unit: lower case of upper case, so `ς`, `σ` and
 * `Σ` share one key. Keys are equal whenever a case-insensitive RegExp would call the characters
 * equal, and for a few more (`ſ` and `s`), which only protects more.
 */
function caseKey(char: string): string {
  const upper = single(char.toUpperCase(), char);
  return single(upper.toLowerCase(), upper);
}

/** A path character as every state tests it. */
interface PathChar {
  readonly char: string;
  readonly key: string;
  /** The character, its key and its one-code-unit case mappings, as class tests need them. */
  readonly codes: readonly number[];
}

function pathChar(char: string): PathChar {
  const key = caseKey(char);
  const variants = [key, single(char.toUpperCase(), char), single(char.toLowerCase(), char)];
  const codes = [char.charCodeAt(0)];
  for (const variant of variants) {
    const code = variant.charCodeAt(0);
    if (!codes.includes(code)) codes.push(code);
  }
  return { char, key, codes };
}

/**
 * A path analysed once for matching against many globs (its characters' case keys and its lower
 * case for the literal comparison). `compilePathMatcher` matchers accept one in place of a string.
 */
export class PreparedPath {
  readonly text: string;
  readonly lower: string;
  readonly chars: readonly PathChar[];

  constructor(text: string) {
    this.text = text;
    this.lower = text.toLowerCase();
    this.chars = Array.from({ length: text.length }, (_, index) => pathChar(text.charAt(index)));
  }
}

function prepared(path: string | PreparedPath): PreparedPath {
  return typeof path === "string" ? new PreparedPath(path) : path;
}

function inClass(items: readonly ClassItem[], codes: readonly number[]): boolean {
  return codes.some((code) => items.some(([low, high]) => code >= low && code <= high));
}

class NfaBuilder {
  readonly states: State[] = [{ kind: "accept" }];

  readonly caseSensitive: boolean;
  constructor(caseSensitive = false) {
    this.caseSensitive = caseSensitive;
  }

  add(state: State): number {
    this.states.push(state);
    return this.states.length - 1;
  }

  /** `atom*` before `next`: a split looping through the atom. */
  star(atom: (next: number) => number, next: number): number {
    const loop = this.add({ kind: "split", next: -1, alt: next });
    const body = atom(loop);
    const state = this.states[loop];
    if (state?.kind === "split") state.next = body;
    return loop;
  }

  sequence(pieces: readonly Piece[], next: number): number {
    let start = next;
    for (let index = pieces.length - 1; index >= 0; index -= 1) {
      const piece = pieces[index];
      if (piece !== undefined) start = this.piece(piece, start);
    }
    return start;
  }

  piece(piece: Piece, next: number): number {
    switch (piece.kind) {
      case "char":
        return this.add({
          kind: "char",
          key: this.caseSensitive ? piece.char : caseKey(piece.char),
          next,
        });
      case "not_slash":
        return this.add({ kind: "not_slash", next });
      case "not_slash_star":
        return this.star((loop) => this.add({ kind: "not_slash", next: loop }), next);
      case "any_star":
        return this.star((loop) => this.add({ kind: "any", next: loop }), next);
      case "class":
        return this.add({ kind: "class", negated: piece.negated, items: piece.items, next });
      case "alternation": {
        const starts = piece.alternatives.map((alternative) => this.sequence(alternative, next));
        let start = starts.at(-1) ?? next;
        for (let index = starts.length - 2; index >= 0; index -= 1) {
          start = this.add({ kind: "split", next: starts[index] ?? next, alt: start });
        }
        return start;
      }
      case "segments_star":
        // `(?:[^/]+/)*`: a name of at least one character, then `/`, any number of times.
        return this.star((loop) => {
          const slash = this.add({ kind: "char", key: "/", next: loop });
          const rest = this.star((inner) => this.add({ kind: "not_slash", next: inner }), slash);
          return this.add({ kind: "not_slash", next: rest });
        }, next);
      case "optional_descendant": {
        // `(?:/.*)?`: nothing, or `/` and anything.
        const rest = this.star((loop) => this.add({ kind: "any", next: loop }), next);
        const slash = this.add({ kind: "char", key: "/", next: rest });
        return this.add({ kind: "split", next: slash, alt: next });
      }
      default: {
        const unreachable: never = piece;
        throw new RangeError(`unknown glob piece ${JSON.stringify(unreachable)}`);
      }
    }
  }
}

function consumes(state: State, char: PathChar, caseSensitive = false): number | null {
  switch (state.kind) {
    case "char":
      return state.key === (caseSensitive ? char.char : char.key) ? state.next : null;
    case "not_slash":
      return char.char === "/" ? null : state.next;
    case "any":
      return state.next;
    case "class":
      if (char.char === "/") return null;
      return inClass(state.items, caseSensitive ? [char.char.charCodeAt(0)] : char.codes) !==
        state.negated
        ? state.next
        : null;
    case "accept":
    case "split":
      return null;
    default: {
      const unreachable: never = state;
      throw new RangeError(`unknown glob state ${JSON.stringify(unreachable)}`);
    }
  }
}

/** A compiled glob. */
export interface CompiledGlob {
  /** Whether `path` matches; each state visited costs one step of `work` when given. */
  test(path: string | PreparedPath, work?: GlobWork): boolean;
}

class GlobNfa implements CompiledGlob {
  readonly #states: readonly State[];
  readonly #start: number;
  /** Per-state generation marks, so a state enters each set once. */
  readonly #marks: Uint32Array;
  readonly #pending: number[] = [];
  #generation = 0;

  readonly caseSensitive: boolean;
  constructor(states: readonly State[], start: number, caseSensitive = false) {
    this.caseSensitive = caseSensitive;
    this.#states = states;
    this.#start = start;
    this.#marks = new Uint32Array(states.length);
  }

  /** Adds `state` and everything reachable from it without consuming a character. */
  #close(state: number, into: number[], work: GlobWork | undefined): void {
    const pending = this.#pending;
    pending.push(state);
    for (let next = pending.pop(); next !== undefined; next = pending.pop()) {
      if (this.#marks[next] === this.#generation) continue;
      this.#marks[next] = this.#generation;
      if (work !== undefined && --work.remaining < 0) {
        pending.length = 0;
        throw new GlobWorkExceeded();
      }
      const node = this.#states[next];
      if (node?.kind === "split") pending.push(node.alt, node.next);
      else into.push(next);
    }
  }

  #nextGeneration(): void {
    if (this.#generation === 0xffff_ffff) {
      this.#marks.fill(0);
      this.#generation = 0;
    }
    this.#generation += 1;
  }

  test(path: string | PreparedPath, work?: GlobWork): boolean {
    const { chars } = prepared(path);
    this.#nextGeneration();
    let current: number[] = [];
    this.#close(this.#start, current, work);
    for (let index = 0; index < chars.length && current.length > 0; index += 1) {
      const char = chars[index];
      if (char === undefined) break;
      this.#nextGeneration();
      const next: number[] = [];
      for (const state of current) {
        const node = this.#states[state];
        const target = node === undefined ? null : consumes(node, char, this.caseSensitive);
        if (target !== null) this.#close(target, next, work);
      }
      current = next;
    }
    return current.includes(ACCEPT);
  }
}

/** Compiles a glob into a case-insensitive matcher that also matches descendants. */
export function compileGlob(pattern: string): CompiledGlob {
  if (pattern.length === 0 || pattern.length > MAX_GLOB_LENGTH) {
    throw new RangeError("glob pattern is empty or too long");
  }
  const builder = new NfaBuilder();
  const start = builder.sequence(patternPieces(pattern), ACCEPT);
  return new GlobNfa(builder.states, start);
}

/** Whether `path` equals `literal` or lies below it, compared case-insensitively. */
function literalMatch(literal: string, path: PreparedPath): boolean {
  return path.lower === literal || path.lower.startsWith(`${literal}/`);
}

/** A path matcher: `work`, when given, bounds (and is charged for) the glob's steps. */
export type PathMatcher = (path: string | PreparedPath, work?: GlobWork) => boolean;

/** A compiled pattern: the glob, or the pattern read literally (both case-insensitive). */
export function compilePathMatcher(pattern: string): PathMatcher {
  const glob = compileGlob(pattern);
  const literal = pattern.toLowerCase();
  return (path, work) => {
    const target = prepared(path);
    return literalMatch(literal, target) || glob.test(target, work);
  };
}

/** Whether `path` (repository-relative, `/`-separated) matches `pattern` (see above). */
export function globMatches(pattern: string, path: string): boolean {
  return compilePathMatcher(pattern)(path);
}

/** Workspace membership uses exact, case-sensitive directory matching. */
export function compileWorkspaceGlob(pattern: string): CompiledGlob {
  if (pattern.length === 0 || pattern.length > MAX_GLOB_LENGTH) {
    throw new RangeError("glob pattern is empty or too long");
  }
  const builder = new NfaBuilder(true);
  const start = builder.sequence(patternPieces(pattern, false), ACCEPT);
  return new GlobNfa(builder.states, start, true);
}
