import { packageNameSchema } from "@kovo/contracts";

import { isJsonObject, type JsonValue } from "./bounded-json.js";
import { parsePointer, pointerOf } from "./json-pointer.js";
import { parsePnpmSelector, parseSelectorStep } from "./selectors.js";

// Pointers into hostile package.json documents that Kovo reports (rejections, allowlist
// violations, changed manifest fields) are persisted and logged, while package.json content never
// is (SPEC: "Never persist or log source, diffs, manifests …"). Keys are hostile: a dependency key
// can be a URL with credentials, carry terminal escape sequences or be 64 KB long. So a reported
// pointer shows a key only when it validates, and otherwise names its position.

/** Longest reported pointer (contracts `jsonPointerSchema`). */
export const MAX_REPORTED_POINTER_LENGTH = 512;

/**
 * Whether an object key may appear in a reported pointer: a valid package name (which every
 * package.json field Kovo reads is) or a parsable override selector (`.` included).
 */
export function isShowableKey(key: string): boolean {
  if (key === ".") return true;
  if (packageNameSchema.safeParse(key).success) return true;
  return parseSelectorStep(key) !== null || parsePnpmSelector(key) !== null;
}

function isIndex(segment: string): boolean {
  return /^(?:0|[1-9]\d{0,8})$/.test(segment);
}

/**
 * The pointer to report for `segments` in `document`: each key that is not showable is replaced
 * by its position among its object's keys (`/dependencies/#3`; `#` when the key is not there).
 * A pointer that would still be too long keeps only the top-level field and uses positions below.
 */
export function reportedPointer(document: JsonValue | null, segments: readonly string[]): string {
  const tokens = (showNames: boolean): string[] => {
    let current: JsonValue | undefined = document ?? undefined;
    return segments.map((segment, index) => {
      const parent = current;
      if (isJsonObject(parent)) {
        current = Object.hasOwn(parent, segment) ? parent[segment] : undefined;
      } else if (Array.isArray(parent) && isIndex(segment)) {
        current = parent[Number(segment)];
        return segment;
      } else {
        current = undefined;
      }
      if ((showNames || index === 0) && isShowableKey(segment)) return segment;
      const position = isJsonObject(parent) ? Object.keys(parent).indexOf(segment) : -1;
      return position === -1 ? "#" : `#${position}`;
    });
  };
  const pointer = pointerOf(tokens(true));
  return pointer.length <= MAX_REPORTED_POINTER_LENGTH ? pointer : pointerOf(tokens(false));
}

/**
 * `pointer` (into `document`) as it may be reported. `fallback` locates keys the pointer names but
 * `document` lacks (a member only the other side of a diff has).
 */
export function reportablePointer(
  pointer: string,
  document: JsonValue,
  fallback: JsonValue | null = null,
): string {
  const tokens = parsePointer(pointer);
  if (tokens === null) return "";
  let inDocument: JsonValue | undefined = document;
  for (const token of tokens) {
    inDocument = isJsonObject(inDocument)
      ? Object.hasOwn(inDocument, token)
        ? inDocument[token]
        : undefined
      : Array.isArray(inDocument) && isIndex(token)
        ? inDocument[Number(token)]
        : undefined;
    if (inDocument === undefined) break;
  }
  return reportedPointer(
    inDocument === undefined && fallback !== null ? fallback : document,
    tokens,
  );
}
