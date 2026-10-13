import { advisoryIdSchema, packageNameSchema, type PackageName } from "@kovo/contracts";
import { isAffected, normalizeOsvRecord, type NormalizedAdvisory } from "@kovo/core/advisory";
import type { DependencyHoldTier } from "@kovo/core/dependency-verdicts";
import { osvRecordFromDocument, readZipEntries } from "@kovo/adapters/osv";

import { unavailableError } from "../../errors.js";
import { snapshotStream, type OsvSnapshot } from "./osv-snapshot.js";

// OSV's advisories for the changed packages, read from the pinned snapshot with the OSV adapter's
// own archive reader and record envelope (`@kovo/adapters/osv`), normalized by
// `@kovo/core/advisory`, and judged with its range evaluation. Only records that name a changed
// package are parsed in full: the export holds hundreds of thousands of records.

/** As the OSV adapter bounds one record (OSV_RECORD_MAX_BYTES); larger entries are skipped unread. */
const OSV_ENTRY_MAX_BYTES = 2 * 1024 * 1024;
const NAME_FIELD = /"name"\s*:\s*"([^"\\]{1,214})"/gu;

export interface ChangeQuery {
  readonly name: string;
  readonly version: string;
  readonly previousVersion: string | null;
}

/** What OSV says about one change, in the engine's evidence vocabulary. */
export interface OsvChangeEvidence {
  /**
   * Hold tiers: an active malware record (`MAL-`) affecting the version reads as confirmed, as the
   * control plane reads a malware advisory without a hold row; a record naming the package that
   * cannot be read reads as unknown (a wait, never a pass).
   */
  readonly holds: readonly DependencyHoldTier[];
  /** Non-withdrawn, non-malicious advisories that affect the version and not the previous one. */
  readonly introducedAdvisories: readonly string[];
}

export interface OsvAdvisories {
  readonly advisories: readonly NormalizedAdvisory[];
  /** Changed packages named by a record that could not be read or normalized. */
  readonly unreadableFor: ReadonlySet<string>;
}

/** The changed packages a record's text names; every one of them when a name may be escaped. */
function namedIn(text: string, names: ReadonlySet<string>): string[] {
  const named = new Set<string>();
  for (const match of text.matchAll(NAME_FIELD)) if (names.has(match[1]!)) named.add(match[1]!);
  // An escaped name cannot be matched cheaply: such a record is read in full.
  if (named.size === 0 && text.includes("\\u")) return [...names];
  return [...named];
}

function normalized(entryName: string, text: string): NormalizedAdvisory | null {
  const id = advisoryIdSchema.safeParse(entryName.slice(0, -".json".length));
  if (!id.success) return null;
  try {
    const record = osvRecordFromDocument(JSON.parse(text), id.data, { operation: "exportAll" });
    const result = normalizeOsvRecord(record.raw, { expectedId: record.id });
    return result.ok ? result.advisory : null;
  } catch {
    return null;
  }
}

/**
 * The advisories in `snapshot` that name a changed package, normalized. Error (exit 3): the archive
 * cannot be read (corrupt, truncated, or not the OSV export's layout).
 */
export async function advisoriesFor(
  snapshot: OsvSnapshot,
  names: ReadonlySet<string>,
): Promise<OsvAdvisories> {
  const decoder = new TextDecoder("utf-8", { fatal: true });
  const advisories: NormalizedAdvisory[] = [];
  const unreadableFor = new Set<string>();
  let records = 0;
  try {
    for await (const entry of readZipEntries(
      snapshotStream(snapshot),
      { maxCompressedBytes: OSV_ENTRY_MAX_BYTES + 64 * 1024, maxEntryBytes: OSV_ENTRY_MAX_BYTES },
      { service: "osv", operation: "exportAll" },
    )) {
      if (!entry.name.endsWith(".json")) continue;
      records += 1;
      // Oversized entries are skipped, as Kovo's own OSV ingestion skips them.
      if (entry.data === null) continue;
      let text: string;
      try {
        text = decoder.decode(entry.data);
      } catch {
        continue;
      }
      const named = namedIn(text, names);
      if (named.length === 0) continue;
      const advisory = normalized(entry.name, text);
      if (advisory === null) for (const name of named) unreadableFor.add(name);
      else advisories.push(advisory);
    }
  } catch {
    throw unavailableError(
      "osv_snapshot_unreadable",
      "OSV snapshot: the archive cannot be read as OSV's npm export.",
    );
  }
  if (records === 0)
    throw unavailableError(
      "osv_snapshot_unreadable",
      "OSV snapshot: the archive holds no records.",
    );
  return { advisories, unreadableFor };
}

function affects(advisory: NormalizedAdvisory, name: PackageName, version: string): boolean {
  try {
    return isAffected(advisory, name, version);
  } catch {
    // A version core cannot order is never silently clean: treat it as affected.
    return true;
  }
}

/** OSV's evidence for each change, aligned with `changes`. */
export function osvEvidence(
  changes: readonly ChangeQuery[],
  found: OsvAdvisories,
): OsvChangeEvidence[] {
  const active = found.advisories.filter((advisory) => advisory.withdrawnAt === null);
  return changes.map((change) => {
    const name = packageNameSchema.parse(change.name);
    const touching = active.filter((advisory) => affects(advisory, name, change.version));
    const holds: DependencyHoldTier[] = [];
    if (touching.some((advisory) => advisory.isMalicious)) holds.push("confirmed");
    if (found.unreadableFor.has(change.name)) holds.push("unknown");
    return {
      holds,
      introducedAdvisories: touching
        .filter(
          (advisory) =>
            !advisory.isMalicious &&
            (change.previousVersion === null || !affects(advisory, name, change.previousVersion)),
        )
        .map((advisory) => advisory.id)
        .toSorted(),
    };
  });
}
