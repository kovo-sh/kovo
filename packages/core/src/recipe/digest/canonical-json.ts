import type { Sha256Hex } from "@kovo/contracts";

import { sha256Hex } from "./sha256.js";

// Canonical JSON for hashing: object keys sorted by UTF-16 code units at every level, no
// whitespace, `JSON.stringify` escaping for strings and numbers. Two structurally equal values
// always serialize identically, whatever the key insertion order. Only JSON values are accepted:
// `undefined` object members are omitted (as JSON.stringify does, matching exact-optional fields),
// and anything else that JSON cannot represent throws instead of being silently dropped.

function write(value: unknown, path: string, out: string[]): void {
  if (value === null) {
    out.push("null");
    return;
  }
  switch (typeof value) {
    case "string":
    case "boolean":
      out.push(JSON.stringify(value));
      return;
    case "number":
      if (!Number.isFinite(value)) throw new TypeError(`${path}: non-finite number`);
      out.push(JSON.stringify(value));
      return;
    case "object":
      break;
    case "bigint":
    case "function":
    case "symbol":
    case "undefined":
      throw new TypeError(`${path}: ${typeof value} is not a JSON value`);
  }
  if (Array.isArray(value)) {
    out.push("[");
    value.forEach((item: unknown, index) => {
      if (index > 0) out.push(",");
      if (item === undefined) throw new TypeError(`${path}[${index}]: undefined array element`);
      write(item, `${path}[${index}]`, out);
    });
    out.push("]");
    return;
  }
  const prototype: unknown = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) {
    throw new TypeError(`${path}: only plain objects are JSON values`);
  }
  const keys = Object.keys(value).toSorted((a, b) => (a < b ? -1 : a > b ? 1 : 0));
  out.push("{");
  let first = true;
  for (const key of keys) {
    const member: unknown = Reflect.get(value, key);
    if (member === undefined) continue;
    if (!first) out.push(",");
    first = false;
    out.push(JSON.stringify(key), ":");
    write(member, `${path}.${key}`, out);
  }
  out.push("}");
}

/** The canonical JSON text of `value`. */
export function canonicalJson(value: unknown): string {
  const out: string[] = [];
  write(value, "$", out);
  return out.join("");
}

/** SHA-256 of the canonical JSON text of `value`. */
export function canonicalHash(value: unknown): Sha256Hex {
  return sha256Hex(canonicalJson(value));
}
