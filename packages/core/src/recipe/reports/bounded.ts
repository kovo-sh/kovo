import { REPORT_LIMITS, type ReportParseError } from "./types.js";

// Bounded decoding of untrusted report bytes: size first, then strict UTF-8, then a nesting scan
// before JSON.parse, so hostile input cannot exhaust memory or the stack.

export type Decoded =
  | { readonly ok: true; readonly text: string }
  | { readonly ok: false; readonly error: ReportParseError };

const decoder = new TextDecoder("utf-8", { fatal: true });

/** Decodes report bytes as strict UTF-8 (a leading BOM is dropped). */
export function decodeReport(bytes: Uint8Array): Decoded {
  if (bytes.byteLength > REPORT_LIMITS.maxBytes) return { ok: false, error: "too_large" };
  let text: string;
  try {
    text = decoder.decode(bytes);
  } catch {
    return { ok: false, error: "invalid_utf8" };
  }
  if (text.trim().length === 0) return { ok: false, error: "empty" };
  return { ok: true, text };
}

/** Whether JSON `text` nests arrays/objects at most `maxDepth` deep (strings are skipped). */
export function jsonDepthWithin(text: string, maxDepth: number): boolean {
  let depth = 0;
  let inString = false;
  for (let i = 0; i < text.length; i += 1) {
    const code = text.charCodeAt(i);
    if (inString) {
      if (code === 0x5c) i += 1; // backslash: skip the escaped character
      else if (code === 0x22) inString = false;
      continue;
    }
    if (code === 0x22) inString = true;
    else if (code === 0x7b || code === 0x5b) {
      depth += 1;
      if (depth > maxDepth) return false;
    } else if (code === 0x7d || code === 0x5d) depth -= 1;
  }
  return true;
}

export type ParsedJson =
  | { readonly ok: true; readonly value: unknown }
  | { readonly ok: false; readonly error: ReportParseError };

/** Parses bounded, depth-checked JSON. */
export function parseBoundedJson(text: string): ParsedJson {
  if (!jsonDepthWithin(text, REPORT_LIMITS.maxJsonDepth)) return { ok: false, error: "too_deep" };
  try {
    const value: unknown = JSON.parse(text);
    return { ok: true, value };
  } catch {
    return { ok: false, error: "invalid_json" };
  }
}
