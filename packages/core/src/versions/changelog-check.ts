import semver from "semver";

// Owner D-722 check 3 (source: https://github.com/kovo-sh/kovo-cloud/issues/626#issuecomment-6728249336):
// the release notes between the two versions, screened first under D-363, have no breaking or
// deprecation note for an API the repository uses. This check can only block.
//
// The screen is structural: no model reads the notes. This pure scanner treats them as untrusted
// data, matching fixed markers and identifier tokens, so text in them cannot steer anything. The
// notes are never stored or logged; only the outcome and its reason code leave this module.

/** The changelog check's outcome (the core policy `ChangelogCheckOutcome` without `pending`). */
export type ChangelogScanOutcome = "clear" | "unavailable" | "blocked";

export const CHANGELOG_SCAN_REASONS = [
  // No note in the range marks an API the repository uses as breaking or deprecated.
  "changelog_clear",
  // No release notes could be read for the range (the check does not block).
  "changelog_unavailable",
  // A breaking or deprecation note in the range names an API the repository uses.
  "changelog_breaking_used_api",
  // A breaking or deprecation note is in the range, and which APIs the repository uses is unknown.
  "changelog_breaking_usage_unknown",
] as const;
export type ChangelogScanReason = (typeof CHANGELOG_SCAN_REASONS)[number];

export interface ChangelogScanResult {
  readonly outcome: ChangelogScanOutcome;
  readonly reason: ChangelogScanReason;
}

/** Bounds on the untrusted text the scanner reads. */
export const CHANGELOG_SCAN_LIMITS = {
  maxDocuments: 8,
  maxDocumentChars: 512 * 1024,
  maxUsedApis: 2000,
} as const;

export interface ChangelogScanInput {
  /**
   * Release notes for the update (a release body, a CHANGELOG file), as fetched. Untrusted and
   * ephemeral: read here and never kept.
   */
  readonly documents: readonly string[];
  readonly from: string;
  readonly to: string;
  /**
   * The names the repository imports from the package; null when unknown, in which case any
   * breaking or deprecation note in the range blocks.
   */
  readonly usedApis: readonly string[] | null;
}

// A breaking or deprecation marker, as release notes write them.
const MARKER =
  /\b(?:breaking|deprecat(?:e|es|ed|ion|ions)|no longer (?:supported|exported|available))\b/iu;
// A version heading: a Markdown heading or bracketed version opening a line.
const HEADING_VERSION = /^(?:#{1,6}\s*\[?v?|\[v?|v)(\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?)\b/u;
const IDENTIFIER = /[A-Za-z_$][\w$]*/gu;
// Any other heading: a Markdown heading, or a line that is only bold text ("**Breaking changes**").
const HEADING = /^(?:#{1,6}\s|\*\*[^*]+\*\*:?$)/u;

/** One version section of release notes: its heading's version (null: a heading-less body). */
export interface ReleaseSection {
  readonly version: string | null;
  readonly lines: readonly string[];
}

/**
 * The version sections of a document inside `(from, to]`; a document with no version headings (a
 * release body for one tag) is one section about the update, with a null version.
 */
export function releaseSectionsInRange(
  document: string,
  from: semver.SemVer,
  to: semver.SemVer,
): ReleaseSection[] {
  const lines = document.slice(0, CHANGELOG_SCAN_LIMITS.maxDocumentChars).split(/\r?\n/u);
  const sections: { version: string | null; lines: string[] }[] = [{ version: null, lines: [] }];
  for (const line of lines) {
    const heading = HEADING_VERSION.exec(line.trim());
    if (heading?.[1] !== undefined) sections.push({ version: heading[1], lines: [] });
    else sections.at(-1)?.lines.push(line);
  }
  const versioned = sections.filter((section) => section.version !== null);
  // A release body for one tag has no version headings: all of it is about that version.
  if (versioned.length === 0) return [{ version: null, lines }];
  return versioned.filter((section) => {
    const version = semver.parse(section.version);
    return version !== null && semver.gt(version, from) && semver.lte(version, to);
  });
}

/** The version sections of a document inside `(from, to]`: one section when it has none. */
function inRange(document: string, from: semver.SemVer, to: semver.SemVer): (readonly string[])[] {
  return releaseSectionsInRange(document, from, to).map((section) => section.lines);
}

/** Markdown `#` count; a bold-line heading counts as deeper than any `#` heading. */
function headingLevel(heading: string): number {
  return /^#{1,6}\s/u.test(heading) ? (/^#+/u.exec(heading)?.[0].length ?? 6) : 7;
}

/**
 * The lines of a section that carry a breaking or deprecation note: a line with a marker, and
 * every line under a heading with one ("BREAKING CHANGES", "Deprecations") until the next heading.
 */
function markedLines(section: readonly string[]): string[] {
  const marked: string[] = [];
  // The level of the marked heading whose reach is open; null when none is.
  let reach: number | null = null;
  for (const line of section) {
    const trimmed = line.trim();
    if (HEADING.test(trimmed)) {
      const level = headingLevel(trimmed);
      if (reach === null || level <= reach) reach = MARKER.test(trimmed) ? level : null;
    }
    if (reach !== null || MARKER.test(trimmed)) marked.push(trimmed);
  }
  return marked;
}

/**
 * Scans the release notes between `from` and `to` for a breaking or deprecation note that names
 * an API the repository uses. Pure; the notes are data, never instructions.
 */
export function scanChangelog(input: ChangelogScanInput): ChangelogScanResult {
  const from = semver.parse(input.from);
  const to = semver.parse(input.to);
  const documents = input.documents
    .slice(0, CHANGELOG_SCAN_LIMITS.maxDocuments)
    .filter((document) => document.trim().length > 0);
  if (from === null || to === null || documents.length === 0)
    return { outcome: "unavailable", reason: "changelog_unavailable" };
  const used =
    input.usedApis === null
      ? null
      : new Set(input.usedApis.slice(0, CHANGELOG_SCAN_LIMITS.maxUsedApis));
  for (const document of documents) {
    for (const line of inRange(document, from, to).flatMap(markedLines)) {
      // A marked heading alone names no API; with the use unknown, any marked line blocks.
      if (used === null) return { outcome: "blocked", reason: "changelog_breaking_usage_unknown" };
      for (const token of line.match(IDENTIFIER) ?? []) {
        if (used.has(token)) return { outcome: "blocked", reason: "changelog_breaking_used_api" };
      }
    }
  }
  return { outcome: "clear", reason: "changelog_clear" };
}

/**
 * Owner D-726 (DX-PRINCIPLE a, source:
 * https://github.com/kovo-sh/kovo-cloud/issues/626#issuecomment-6733241173): one package move
 * whose changelog check came back `clear` (never `unavailable`). A 0.x patch move on this list is
 * judged as a patch step (`versionStepWithChangelog`); every other move is judged as before.
 * Names and versions only (metadata).
 */
export interface ChangelogClearance {
  readonly name: string;
  readonly from: string;
  readonly to: string;
}

/** Whether `name` moving `from → to` is on the cleared list (exact versions; absent: no). */
export function changelogCleared(
  cleared: readonly ChangelogClearance[] | undefined,
  name: string,
  from: string,
  to: string,
): boolean {
  return (cleared ?? []).some(
    (entry) => entry.name === name && entry.from === from && entry.to === to,
  );
}
