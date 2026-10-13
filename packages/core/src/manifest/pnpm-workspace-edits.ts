import { packageNameSchema } from "@kovo/contracts";
import { isScalar, parseDocument } from "yaml";

import { classifyDependencySpec, isRegistrySpec } from "./dependency-spec.js";
import { diffPointers, getAtPointer, parsePointer } from "./json-pointer.js";
import { pnpmWorkspaceSettings } from "./pnpm-settings.js";

export interface PnpmWorkspaceEdit {
  readonly pointer: string;
  readonly value: string;
}

const certified = new WeakSet<object>();
/** Transient proof minted only after comparing bounded before/after root YAML bytes. */
export interface PnpmWorkspaceEntryChange {
  readonly pointers: readonly string[];
}
export function isPnpmWorkspaceEntryChange(value: PnpmWorkspaceEntryChange | undefined): boolean {
  return value !== undefined && certified.has(value);
}

function entryPointer(pointer: string, catalogAliases: readonly string[]): boolean {
  const tokens = parsePointer(pointer);
  return (
    tokens !== null &&
    ((tokens.length === 2 && tokens[0] === "catalog") ||
      (tokens.length === 2 && tokens[0] === "overrides" && catalogAliases.includes(tokens[1]!)) ||
      (tokens.length === 3 &&
        tokens[0] === "catalogs" &&
        /^[A-Za-z0-9_-]{1,256}$/u.test(tokens[1]!))) &&
    packageNameSchema.safeParse(tokens[tokens.length - 1]).success
  );
}
function sameRegistrySource(before: string, after: string): boolean {
  const a = classifyDependencySpec(before);
  const b = classifyDependencySpec(after);
  return (
    isRegistrySpec(a) &&
    isRegistrySpec(b) &&
    after.trim().length > 0 &&
    !after.trim().startsWith(".") &&
    (b.kind !== "alias" || b.target.kind !== "tag" || !b.target.tag.startsWith(".")) &&
    (a.kind === "alias" ? b.kind === "alias" && a.name === b.name : b.kind !== "alias")
  );
}

/** Replace existing scalar entry values only; preserve every other byte, including comments. */
export function editedPnpmWorkspaceYaml(
  text: string,
  edits: readonly PnpmWorkspaceEdit[],
  catalogAliases: readonly string[] = [],
): string | null {
  const settings = pnpmWorkspaceSettings(text);
  if (
    settings === null ||
    !Array.isArray(settings["packages"]) ||
    edits.length === 0 ||
    edits.length > 500
  )
    return null;
  const document = parseDocument(text, {
    schema: "failsafe",
    strict: true,
    prettyErrors: false,
    logLevel: "error",
  });
  if (document.errors.length > 0 || document.warnings.length > 0) return null;
  const spans: { start: number; end: number; value: string }[] = [];
  const pointers = new Set<string>();
  for (const edit of edits) {
    const before = getAtPointer(settings, edit.pointer);
    if (
      !entryPointer(edit.pointer, catalogAliases) ||
      pointers.has(edit.pointer) ||
      typeof before !== "string" ||
      before === edit.value ||
      !sameRegistrySource(before, edit.value)
    )
      return null;
    pointers.add(edit.pointer);
    const node = document.getIn(parsePointer(edit.pointer), true);
    if (!isScalar(node) || node.range == null || typeof node.value !== "string") return null;
    spans.push({ start: node.range[0], end: node.range[1], value: JSON.stringify(edit.value) });
  }
  let output = text;
  let boundary = text.length;
  for (const span of spans.toSorted((a, b) => b.start - a.start)) {
    if (span.end > boundary || span.start >= span.end) return null;
    output = output.slice(0, span.start) + span.value + output.slice(span.end);
    boundary = span.start;
  }
  return pnpmWorkspaceSettings(output) === null ? null : output;
}

/** Independent read-back check: no new/deleted entries, formatting changes or other settings. */
export function checkPnpmWorkspaceEntryChanges(
  before: string,
  after: string,
  catalogAliases: readonly string[] = [],
): PnpmWorkspaceEntryChange | null {
  const base = pnpmWorkspaceSettings(before);
  const head = pnpmWorkspaceSettings(after);
  if (base === null || head === null) return null;
  const pointers = diffPointers(base, head);
  const edits: PnpmWorkspaceEdit[] = [];
  for (const pointer of pointers) {
    const value = getAtPointer(head, pointer);
    if (typeof value !== "string") return null;
    edits.push({ pointer, value });
  }
  if (editedPnpmWorkspaceYaml(before, edits, catalogAliases) !== after) return null;
  const proof = Object.freeze({ pointers: Object.freeze(pointers) });
  certified.add(proof);
  return proof;
}
