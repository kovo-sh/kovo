import { isJsonObject, type JsonObject, type JsonValue } from "./bounded-json.js";

// RFC 6901 JSON Pointers over parsed JSON documents: building, reading, immutable edits and a
// leaf-level structural diff. Used for package.json edit plans and the manifest allowlist.

/** Escapes one reference token (`~` → `~0`, `/` → `~1`). */
export function escapePointerToken(token: string): string {
  return token.replaceAll("~", "~0").replaceAll("/", "~1");
}

/** Builds a pointer from unescaped reference tokens (`["dependencies", "@a/b"]` → `/dependencies/@a~1b`). */
export function pointerOf(tokens: readonly string[]): string {
  return tokens.map((token) => `/${escapePointerToken(token)}`).join("");
}

const POINTER = /^(?:\/(?:[^~/]|~[01])*)*$/;

/** Splits a pointer into unescaped tokens, or null when it is not an RFC 6901 pointer. */
export function parsePointer(pointer: string): string[] | null {
  if (!POINTER.test(pointer)) return null;
  if (pointer === "") return [];
  return pointer
    .slice(1)
    .split("/")
    .map((token) => token.replaceAll("~1", "/").replaceAll("~0", "~"));
}

/** Whether `pointer` is `ancestor` itself or lies inside it. */
export function pointerWithin(pointer: string, ancestor: string): boolean {
  return pointer === ancestor || pointer.startsWith(`${ancestor}/`);
}

/** An object's own member, or undefined (never an inherited property such as `__proto__`). */
function member(object: JsonObject, key: string): JsonValue | undefined {
  return Object.hasOwn(object, key) ? object[key] : undefined;
}

function childOf(value: JsonValue, token: string): JsonValue | undefined {
  if (Array.isArray(value)) {
    return /^(?:0|[1-9]\d*)$/.test(token) ? value[Number(token)] : undefined;
  }
  return isJsonObject(value) ? member(value, token) : undefined;
}

/** The value at `pointer`, or undefined when absent (or the pointer is invalid). */
export function getAtPointer(document: JsonValue, pointer: string): JsonValue | undefined {
  const tokens = parsePointer(pointer);
  if (tokens === null) return undefined;
  let current: JsonValue | undefined = document;
  for (const token of tokens) {
    if (current === undefined) return undefined;
    current = childOf(current, token);
  }
  return current;
}

/** A copy of `source` with `key` set to `value` (in place when present) or removed (undefined). */
function withMember(source: JsonObject, key: string, value: JsonValue | undefined): JsonObject {
  const copy: JsonObject = {};
  const define = (name: string, item: JsonValue): void => {
    Object.defineProperty(copy, name, {
      value: item,
      enumerable: true,
      writable: true,
      configurable: true,
    });
  };
  let replaced = false;
  for (const [existingKey, existingValue] of Object.entries(source)) {
    if (existingKey !== key) {
      define(existingKey, existingValue);
    } else if (value !== undefined) {
      define(key, value);
      replaced = true;
    }
  }
  if (!replaced && value !== undefined) define(key, value);
  return copy;
}

function editTokens(pointer: string): string[] {
  const tokens = parsePointer(pointer);
  if (tokens === null || tokens.length === 0) throw new RangeError("invalid edit pointer");
  return tokens;
}

/**
 * Returns a copy of `document` with `value` at `pointer` (objects only; missing intermediate
 * objects are created, a replaced member keeps its position). Throws RangeError for an invalid
 * pointer or a path through a non-object.
 */
export function setAtPointer(document: JsonValue, pointer: string, value: JsonValue): JsonValue {
  const tokens = editTokens(pointer);
  const apply = (node: JsonValue | undefined, depth: number): JsonValue => {
    const base = node ?? {};
    if (!isJsonObject(base)) throw new RangeError("edit pointer crosses a non-object");
    const token = tokens[depth] ?? "";
    const next = depth === tokens.length - 1 ? value : apply(member(base, token), depth + 1);
    return withMember(base, token, next);
  };
  return apply(document, 0);
}

/**
 * Returns a copy of `document` without the member at `pointer`; removing an absent member is a
 * no-op and parent objects left empty are kept. Throws RangeError for an invalid pointer.
 */
export function removeAtPointer(document: JsonValue, pointer: string): JsonValue {
  const tokens = editTokens(pointer);
  const apply = (node: JsonValue, depth: number): JsonValue => {
    if (!isJsonObject(node)) return node;
    const token = tokens[depth] ?? "";
    const child = member(node, token);
    if (child === undefined) return node;
    return withMember(
      node,
      token,
      depth === tokens.length - 1 ? undefined : apply(child, depth + 1),
    );
  };
  return apply(document, 0);
}

/** The pointers of every leaf of `value` (an empty object or array is its own leaf). */
function collectLeaves(value: JsonValue, pointer: string, into: string[]): void {
  const entries: [string, JsonValue][] = Array.isArray(value)
    ? value.map((item, index) => [String(index), item])
    : isJsonObject(value)
      ? Object.entries(value)
      : [];
  if (entries.length === 0) {
    into.push(pointer);
    return;
  }
  for (const [key, child] of entries) {
    collectLeaves(child, `${pointer}/${escapePointerToken(key)}`, into);
  }
}

function sameScalar(left: JsonValue, right: JsonValue): boolean {
  const leftContainer = typeof left === "object" && left !== null;
  const rightContainer = typeof right === "object" && right !== null;
  return !leftContainer && !rightContainer && left === right;
}

/**
 * Leaf-level structural differences between two documents, as sorted pointers. A member present on
 * one side only is expanded to the leaves of its subtree (an empty object or array is its own
 * leaf), so adding `{"overrides": {"a": {"b": "1"}}}` reports `/overrides/a/b`. A type change is
 * reported at the node; object key order is not a difference.
 */
export function diffPointers(before: JsonValue, after: JsonValue): string[] {
  const changed: string[] = [];
  const walk = (left: JsonValue, right: JsonValue, pointer: string): void => {
    if (isJsonObject(left) && isJsonObject(right)) {
      for (const key of new Set([...Object.keys(left), ...Object.keys(right)])) {
        const child = `${pointer}/${escapePointerToken(key)}`;
        const leftValue = member(left, key);
        const rightValue = member(right, key);
        if (leftValue !== undefined && rightValue !== undefined) walk(leftValue, rightValue, child);
        else collectLeaves(leftValue ?? rightValue ?? null, child, changed);
      }
      return;
    }
    if (Array.isArray(left) && Array.isArray(right)) {
      const length = Math.max(left.length, right.length);
      for (let index = 0; index < length; index += 1) {
        const child = `${pointer}/${index}`;
        const leftValue = left[index];
        const rightValue = right[index];
        if (leftValue !== undefined && rightValue !== undefined) walk(leftValue, rightValue, child);
        else collectLeaves(leftValue ?? rightValue ?? null, child, changed);
      }
      return;
    }
    if (!sameScalar(left, right)) changed.push(pointer);
  };
  walk(before, after, "");
  return changed.toSorted();
}
