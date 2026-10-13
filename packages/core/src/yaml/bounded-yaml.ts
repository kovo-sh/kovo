import { isMap, isPair, isScalar, isSeq } from "yaml";

// Bounds for hostile YAML (pnpm-lock.yaml, GitHub Actions workflows and actions). SPEC: "Treat
// repositories, packages and model output as hostile"; ARCHITECTURE §6: "parsed with bounded
// parsers". Measured on yaml 2.9.1 (docs/decisions/lockfile.md "Hostile files are parsed with
// bounded, strict parsers"):
//
// - Its `uniqueKeys` check compares every new key with every earlier key of the same map, so a map
//   of n keys costs n² comparisons (41 000 keys: 8.7 s instead of 0.28 s). Callers parse with
//   `uniqueKeys: false` and run {@link findMappingKeyProblem}, which does the same check in one
//   linear walk.
// - Memory and time grow with the number of nodes, not with the number of characters: a flow
//   sequence `[a,a,a,…]` holds about 1 KiB per item while it is parsed (4 MB of it took 2 GB and
//   4.8 s). {@link scanYamlShape} bounds the node count before parsing by counting the characters
//   every node needs at least one of (a line break, a flow separator or bracket, an indicator), so
//   the parser never sees a document whose node count could exceed what a worker can hold.

/** Limits applied by {@link scanYamlShape}. */
export interface YamlShapeLimits {
  /** Maximum length in UTF-16 code units. */
  readonly maxLength: number;
  /** Maximum count of structural characters (see {@link isStructural}). */
  readonly maxStructure: number;
  /** Maximum flow-collection nesting (`[` and `{`, counted outside and inside quotes alike). */
  readonly maxFlowDepth: number;
  /** Maximum leading spaces on a line (bounds block nesting). */
  readonly maxIndent: number;
  /**
   * Whether `---` / `...` document markers may appear. Refused, the text is a single implicit
   * document, so the parser never composes a stream of many documents.
   */
  readonly allowDocumentMarkers: boolean;
}

export const YAML_SHAPE_ERRORS = [
  "too_large",
  "too_complex",
  "too_deep",
  "document_marker",
] as const;
export type YamlShapeError = (typeof YAML_SHAPE_ERRORS)[number];

export type YamlShape =
  | { readonly ok: true; readonly structure: number }
  | { readonly ok: false; readonly error: YamlShapeError };

const LF = 0x0a;
const CR = 0x0d;
const SPACE = 0x20;
const TAB = 0x09;

/**
 * Characters at least one of which every YAML node other than the root needs next to it: line
 * breaks (block entries), `,` `[` `{` (flow entries and collections), `:` `-` `?` (indicators) and
 * `!` `&` `*` (tags, anchors, aliases, each of which adds a node or node property). Counting them in
 * quoted and plain scalars too only over-counts.
 */
function isStructural(code: number): boolean {
  switch (code) {
    case LF:
    case CR:
    case 0x2c: // ,
    case 0x5b: // [
    case 0x7b: // {
    case 0x3a: // :
    case 0x2d: // -
    case 0x3f: // ?
    case 0x21: // !
    case 0x26: // &
    case 0x2a: // *
      return true;
    default:
      return false;
  }
}

/** Whether a document marker (`---` or `...` then a blank or the end) starts at `index`. */
function markerAt(text: string, index: number): boolean {
  const first = text.charCodeAt(index);
  if (first !== 0x2d && first !== 0x2e) return false;
  if (text.charCodeAt(index + 1) !== first || text.charCodeAt(index + 2) !== first) return false;
  const next = text.charCodeAt(index + 3);
  return Number.isNaN(next) || next === SPACE || next === TAB || next === LF || next === CR;
}

/**
 * One linear pass over `text` before any YAML parser sees it: length, structural characters (a
 * bound on the node count), flow nesting, indentation and document markers.
 */
export function scanYamlShape(text: string, limits: YamlShapeLimits): YamlShape {
  if (text.length > limits.maxLength) return { ok: false, error: "too_large" };
  let structure = 0;
  let flow = 0;
  let indent = 0;
  let atLineStart = true;
  for (let index = 0; index < text.length; index += 1) {
    const code = text.charCodeAt(index);
    if (isStructural(code)) {
      structure += 1;
      if (structure > limits.maxStructure) return { ok: false, error: "too_complex" };
    }
    if (code === LF || code === CR) {
      atLineStart = true;
      indent = 0;
      continue;
    }
    if (atLineStart) {
      if (code === SPACE) {
        indent += 1;
        if (indent > limits.maxIndent) return { ok: false, error: "too_deep" };
        continue;
      }
      atLineStart = false;
      if (indent === 0 && !limits.allowDocumentMarkers && markerAt(text, index)) {
        return { ok: false, error: "document_marker" };
      }
    }
    if (code === 0x5b || code === 0x7b) {
      flow += 1;
      if (flow > limits.maxFlowDepth) return { ok: false, error: "too_deep" };
    } else if ((code === 0x5d || code === 0x7d) && flow > 0) {
      flow -= 1;
    }
  }
  return { ok: true, structure };
}

export type MappingKeyProblem = "duplicate_key" | "complex_key";

/**
 * The first repeated or non-scalar mapping key anywhere in a parsed document's `contents`, found
 * in one walk with a set per mapping. Scalar keys are equal when their resolved values are (the
 * comparison the yaml library's `uniqueKeys` makes; a merge key `<<` resolves to a fresh symbol and
 * is never a duplicate, as there). Collection and alias keys are reported as `complex_key`: a plain
 * object keeps only their stringified form, so two of them could silently collapse into one member.
 * Aliases are not followed: the node they name is walked where it is defined. Iterative, so nesting
 * depth cannot overflow the stack.
 */
export function findMappingKeyProblem(contents: unknown): MappingKeyProblem | null {
  const stack: unknown[] = [contents];
  while (stack.length > 0) {
    const node = stack.pop();
    if (isMap(node)) {
      const seen = new Set<unknown>();
      for (const pair of node.items) {
        const key: unknown = pair.key;
        if (isScalar(key)) {
          const value: unknown = key.value;
          if (typeof value !== "symbol") {
            if (seen.has(value)) return "duplicate_key";
            seen.add(value);
          }
        } else if (key !== null && key !== undefined) {
          return "complex_key";
        }
        stack.push(pair.value);
      }
    } else if (isSeq(node)) {
      for (const item of node.items) stack.push(item);
    } else if (isPair(node)) {
      // yaml 2 wraps `[a: b]` in a one-pair map; a bare pair is checked the same way regardless.
      if (node.key !== null && node.key !== undefined && !isScalar(node.key)) return "complex_key";
      stack.push(node.value);
    }
  }
  return null;
}
