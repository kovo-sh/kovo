import type { DependencyVerdictChangeWire } from "@kovo/contracts";
import {
  LOCKFILE_MAX_BYTES,
  WORKSPACE_LIMITS,
  type DependencyGraph,
  type LockfileName,
  type WorkspaceInput,
  type WorkspaceTreeEntry,
} from "@kovo/core/lockfile";
import { PACKAGE_JSON_LIMITS } from "@kovo/core/manifest";

import { usageError } from "../errors.js";
import {
  changeListOf,
  snapshotGraph,
  type ProjectSnapshot,
  type UnsupportedLockfile,
} from "./change-list.js";
import { blobOid, type ProjectReader } from "./git.js";

// Reads one side's lockfile (and, for a workspace, the project's workspace authority files) into
// memory and parses its graph. The bytes never leave this module: they are decoded, parsed and
// dropped; only the graph's identifiers continue.

const decoder = new TextDecoder("utf-8", { fatal: true });

/** The workspace authority files `discoverWorkspaces` reads (as Kovo's verification reads them). */
const AUTHORITY_INPUT =
  /(?:^|\/)(?:package\.json|\.npmrc|\.nvmrc|\.node-version|\.tool-versions)$|^pnpm-workspace\.yaml$/u;
const NEVER_READ = /(?:^|\/)(?:node_modules|\.git)(?:\/|$)/u;

function decode(bytes: Uint8Array, path: string): string {
  try {
    return decoder.decode(bytes);
  } catch {
    throw usageError("unreadable_file", `${path} is not valid UTF-8.`);
  }
}

export class UnsupportedLockfileError extends Error {
  readonly side: string;
  readonly refusal: UnsupportedLockfile;

  constructor(side: string, refusal: UnsupportedLockfile) {
    super(`The lockfile at ${side} is not supported (${refusal.unsupported}).`);
    this.name = "UnsupportedLockfileError";
    this.side = side;
    this.refusal = refusal;
  }
}

async function workspaceInput(
  reader: ProjectReader,
  fileName: LockfileName,
  lockfile: string,
): Promise<WorkspaceInput> {
  const listed = await reader.listTree(WORKSPACE_LIMITS.maxTreeEntries);
  const needed = listed.filter(
    (entry) =>
      entry.mode === "file" &&
      entry.path !== fileName &&
      !NEVER_READ.test(entry.path) &&
      AUTHORITY_INPUT.test(entry.path),
  );
  if (needed.length > WORKSPACE_LIMITS.maxMembers * 5 + 1)
    throw new UnsupportedLockfileError(reader.label, {
      unsupported: "too_large",
      reasons: ["resource_limit"],
      packages: [],
    });
  const contents = await reader.readEntries(
    needed,
    () => PACKAGE_JSON_LIMITS.maxLength,
    WORKSPACE_LIMITS.maxManifestBytes,
  );
  const texts = new Map(
    needed.map((entry, index) => [entry.path, { bytes: contents[index]!, oid: entry.oid }]),
  );
  const lockEntry = listed.find((entry) => entry.path === fileName);
  const entries: WorkspaceTreeEntry[] = listed.map((entry) => {
    if (entry.path === fileName && entry.mode === "file") {
      const bytes = new TextEncoder().encode(lockfile);
      return { path: entry.path, mode: entry.mode, oid: blobOid(bytes, entry.oid), text: lockfile };
    }
    const read = texts.get(entry.path);
    if (read === undefined) return { path: entry.path, mode: entry.mode, oid: entry.oid };
    return {
      path: entry.path,
      mode: entry.mode,
      oid: blobOid(read.bytes, entry.oid),
      text: decode(read.bytes, entry.path),
    };
  });
  // The workspace parse checks the lockfile against the tree's entry, so it must be listed.
  if (lockEntry === undefined)
    throw new UnsupportedLockfileError(reader.label, {
      unsupported: "workspaces",
      reasons: ["invalid_lockfile"],
      packages: [],
    });
  const packageManager =
    fileName === "pnpm-lock.yaml" ? "pnpm" : fileName === "yarn.lock" ? "yarn" : "npm";
  return { packageManager, treeComplete: true, entries };
}

/**
 * One side's dependency graph; null when the lockfile does not exist there. Errors: exit 2 for an
 * unreadable file, `UnsupportedLockfileError` for a lockfile Kovo's parser does not support.
 */
export async function readGraph(
  reader: ProjectReader,
  fileName: LockfileName,
): Promise<DependencyGraph | null> {
  const lockBytes = await reader.readFile(fileName, LOCKFILE_MAX_BYTES[fileName]);
  if (lockBytes === null) return null;
  const manifestBytes = await reader.readFile("package.json", PACKAGE_JSON_LIMITS.maxLength);
  let snapshot: ProjectSnapshot = {
    lockfile: decode(lockBytes, fileName),
    manifest: manifestBytes === null ? null : decode(manifestBytes, "package.json"),
  };
  let parsed = snapshotGraph(fileName, snapshot);
  if (!parsed.ok && parsed.needsWorkspace) {
    snapshot = {
      ...snapshot,
      workspace: await workspaceInput(reader, fileName, snapshot.lockfile),
    };
    parsed = snapshotGraph(fileName, snapshot);
  }
  if (parsed.ok) return parsed.graph;
  throw new UnsupportedLockfileError(
    reader.label,
    parsed.needsWorkspace
      ? { unsupported: "workspaces", reasons: ["incomplete_tree"], packages: [] }
      : parsed.refusal,
  );
}

/**
 * The change list between the base and head sides. The head lockfile must exist; a base without
 * one makes every head version new. Errors as `readGraph`, plus exit 2 when the head has none.
 */
export async function readChangeList(
  base: ProjectReader,
  head: ProjectReader,
  fileName: LockfileName,
): Promise<readonly DependencyVerdictChangeWire[]> {
  const headGraph = await readGraph(head, fileName);
  if (headGraph === null)
    throw usageError("missing_lockfile", `${fileName} does not exist at ${head.label}.`);
  const baseGraph = await readGraph(base, fileName);
  try {
    return changeListOf(baseGraph, headGraph);
  } catch (error) {
    if (error instanceof RangeError)
      throw new UnsupportedLockfileError(head.label, {
        unsupported: "unsupported_lockfile_format",
        reasons: ["diff"],
        packages: [],
      });
    throw error;
  }
}
