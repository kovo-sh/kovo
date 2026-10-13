import { isMap, isScalar, isSeq, parseDocument } from "yaml";

import { findMappingKeyProblem, scanYamlShape } from "../../yaml/bounded-yaml.js";

/**
 * Keys that name JavaScript object machinery rather than settings. pnpm 10 merges
 * `pnpm-workspace.yaml` into its config so that settings nested under a top-level `__proto__` are
 * applied (probed with 10.34.5), while Kovo's own readers drop or hide such keys. A file holding
 * one at any level is refused.
 */
export const RESERVED_WORKSPACE_YAML_KEYS: ReadonlySet<string> = new Set([
  "__proto__",
  "constructor",
  "prototype",
]);

/**
 * A carriage return not followed by a line feed. pnpm's YAML readers (10.34.5, 11.28.x, 12.9.1)
 * treat it as a line break, while the `yaml` library keeps it inside a comment, so a line hidden
 * behind it would be applied by pnpm and never seen by Kovo's allowlist.
 */
const BARE_CARRIAGE_RETURN = /\r(?!\n)/;

/**
 * Workspace YAML Kovo cannot read exactly as pnpm does: a reserved key or a bare carriage return.
 * An unsupported setting, not malformed YAML.
 */
export class UnsupportedWorkspaceYamlError extends RangeError {
  readonly reason: "reserved_key" | "bare_carriage_return";

  constructor(reason: "reserved_key" | "bare_carriage_return") {
    super(`unsupported workspace YAML: ${reason}`);
    this.name = "UnsupportedWorkspaceYamlError";
    this.reason = reason;
  }
}

// yaml 2 wraps a flow pair (`[a: b]`) in a one-pair map, so maps and sequences are every container.
function hasReservedKey(contents: unknown): boolean {
  const stack: unknown[] = [contents];
  while (stack.length > 0) {
    const node = stack.pop();
    if (isMap(node)) {
      for (const pair of node.items) {
        if (isScalar(pair.key) && RESERVED_WORKSPACE_YAML_KEYS.has(String(pair.key.value)))
          return true;
        stack.push(pair.value);
      }
    } else if (isSeq(node)) {
      for (const item of node.items) stack.push(item);
    }
  }
  return false;
}

/** The same alias-free, strict, linear-key-check parser as lockfile ingestion. */
export function workspaceYaml(text: string): unknown {
  if (BARE_CARRIAGE_RETURN.test(text))
    throw new UnsupportedWorkspaceYamlError("bare_carriage_return");
  if (
    !scanYamlShape(text, {
      maxLength: 1024 * 1024,
      maxStructure: 30_000,
      maxFlowDepth: 32,
      maxIndent: 64,
      allowDocumentMarkers: false,
    }).ok
  )
    throw new RangeError("workspace YAML bound");
  const document = parseDocument(text, {
    schema: "failsafe",
    uniqueKeys: false,
    strict: true,
    prettyErrors: false,
    logLevel: "error",
    merge: false,
    version: "1.2",
  });
  if (document.errors.length > 0 || findMappingKeyProblem(document.contents) !== null) {
    throw new RangeError("invalid workspace YAML");
  }
  if (hasReservedKey(document.contents)) throw new UnsupportedWorkspaceYamlError("reserved_key");
  return document.toJS({ maxAliasCount: 0 });
}
