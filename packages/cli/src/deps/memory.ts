import { usageError } from "../errors.js";
import { blobOid, type ProjectReader, type TreeEntry } from "./git.js";

// One side of a check whose files are held in memory: the bytes a caller read before or after a
// change (the package-manager wrappers' pre- and post-resolve snapshots), laid over the live
// working tree for every other file a workspace parse reads. Nothing here writes or prints a file.

/** A project-relative path (POSIX separators) and its bytes, or null when it does not exist. */
export type HeldFiles = ReadonlyMap<string, Uint8Array | null>;

const SHA1_LIKE = "0".repeat(40);

function rootName(path: string): string | null {
  return path.includes("/") ? null : path;
}

/**
 * A project directory whose `held` files are read from memory. Every other file, and the tree
 * listing a workspace parse needs, comes from `live` (the working tree), or, without one, is
 * refused (exit 2): an in-memory side never reads a file it does not hold as if it were absent.
 */
export class MemoryReader implements ProjectReader {
  readonly label: string;
  readonly commit = null;
  readonly #held: HeldFiles;
  readonly #live: ProjectReader | null;

  constructor(label: string, held: HeldFiles, live: ProjectReader | null) {
    this.label = label;
    this.#held = held;
    this.#live = live;
  }

  async rootFiles(): Promise<readonly string[] | null> {
    const names = new Set((this.#live === null ? [] : await this.#live.rootFiles()) ?? []);
    for (const [path, bytes] of this.#held) {
      const name = rootName(path);
      if (name === null) continue;
      if (bytes === null) names.delete(name);
      else names.add(name);
    }
    return [...names];
  }

  async readFile(path: string, maxBytes: number): Promise<Uint8Array | null> {
    if (this.#held.has(path)) {
      const bytes = this.#held.get(path) ?? null;
      if (bytes !== null && bytes.byteLength > maxBytes)
        throw usageError("too_large", `${path} exceeds the CLI's bounds.`);
      return bytes;
    }
    if (this.#live === null)
      throw usageError("unreadable_file", `${path} was not read before the change.`);
    return this.#live.readFile(path, maxBytes);
  }

  async listTree(maxEntries: number): Promise<readonly TreeEntry[]> {
    if (this.#live === null)
      throw usageError("unreadable_tree", "The working tree could not be listed.");
    const listed = (await this.#live.listTree(maxEntries)).filter(
      (entry) => !this.#held.has(entry.path),
    );
    const entries: TreeEntry[] = [...listed];
    for (const [path, bytes] of this.#held)
      if (bytes !== null) entries.push({ path, mode: "file", oid: blobOid(bytes, SHA1_LIKE) });
    if (entries.length > maxEntries)
      throw usageError("too_large", "The project has more files than the CLI reads.");
    return entries;
  }

  async readEntries(
    entries: readonly TreeEntry[],
    maxBytes: (path: string) => number,
    maxTotalBytes: number,
  ): Promise<readonly Uint8Array[]> {
    const contents: Uint8Array[] = [];
    let total = 0;
    for (const entry of entries) {
      const bytes = await this.readFile(entry.path, maxBytes(entry.path));
      if (bytes === null)
        throw usageError("unreadable_file", `${entry.path} changed while it was being read.`);
      total += bytes.byteLength;
      if (total > maxTotalBytes)
        throw usageError("too_large", "The project's files exceed the CLI's bounds.");
      contents.push(bytes);
    }
    return contents;
  }
}
