import type { AdvisoryRangeEventKind, PackageName } from "@kovo/contracts";

import {
  INTRODUCED_ZERO,
  LIMIT_INFINITY,
  type AdvisoryFacts,
  type AdvisoryRange,
  type AdvisoryRangeEvent,
} from "./model.js";
import { parseNpmVersion, type NpmVersion } from "./version.js";

// OSV range evaluation for npm (OSV schema "Evaluation", `IsVulnerable`): a version is affected if
// it equals a listed version or lies in any range. Per range, if it is below some `limit` (none
// means an implicit `*`), walk the events sorted by version: `introduced` sets affected when
// v ≥ it (`"0"` sorts before everything), `fixed` clears it when v ≥ it, `last_affected` clears it
// when v > it. SEMVER and ECOSYSTEM ranges both use SemVer 2.0.0 precedence; GIT ranges are
// ignored (their listed versions still count).

interface CompiledEvent {
  readonly kind: AdvisoryRangeEventKind;
  /** null for `introduced: "0"` (−∞) and `limit: "*"` (+∞). */
  readonly version: NpmVersion | null;
  readonly text: string;
}

/** A range with its versions parsed once, for repeated evaluation. */
export interface CompiledRange {
  readonly package: PackageName;
  /** Sorted events without limits; null for a versions-only or GIT row. */
  readonly events: readonly CompiledEvent[] | null;
  /** Upper bound from `limit` events: null when unbounded (none, or a `*` limit). */
  readonly limit: { readonly version: NpmVersion; readonly text: string } | null;
  /** Listed versions by precedence identity (build metadata dropped), for O(1) lookups. */
  readonly explicit: ReadonlySet<string>;
}

function parseOrThrow(text: string): NpmVersion {
  const parsed = parseNpmVersion(text);
  if (parsed === null) throw new RangeError(`not an exact version: ${JSON.stringify(text)}`);
  return parsed;
}

function compileEvent(event: AdvisoryRangeEvent): CompiledEvent {
  const unbounded =
    (event.kind === "introduced" && event.version === INTRODUCED_ZERO) ||
    (event.kind === "limit" && event.version === LIMIT_INFINITY);
  return {
    kind: event.kind,
    version: unbounded ? null : parseOrThrow(event.version),
    text: event.version,
  };
}

/**
 * Sorts events by version, `introduced: "0"` first. The sort is stable, so events at the same
 * version keep the record's order (`[introduced 1.0.0, fixed 1.0.0]` is empty, while
 * `[…, fixed 2.0.0, introduced 2.0.0]` re-affects 2.0.0), which is the author's evident intent.
 */
function sortEvents(events: readonly CompiledEvent[]): CompiledEvent[] {
  return events.toSorted((a, b) => {
    if (a.version === null) return b.version === null ? 0 : -1;
    if (b.version === null) return 1;
    return a.version.compare(b.version);
  });
}

/**
 * A version's identity under SemVer precedence: node-semver's `version` (no build metadata; numeric
 * identifiers have no leading zeros in strict SemVer, so equal precedence means equal text).
 */
function precedenceKey(version: NpmVersion): string {
  return version.version;
}

/** Compiles a stored or normalized range. Throws RangeError on versions that are not exact. */
export function compileRange(range: AdvisoryRange): CompiledRange {
  const explicit = new Set(range.explicitVersions.map((text) => precedenceKey(parseOrThrow(text))));
  if (range.rangeType === null || range.rangeType === "GIT") {
    return { package: range.package, events: null, limit: null, explicit };
  }
  const compiled = range.events.map(compileEvent);
  // "BeforeLimits": below any limit, so the bound is the highest one; a `*` limit removes it.
  const limits = compiled.filter((event) => event.kind === "limit");
  let limit: { readonly version: NpmVersion; readonly text: string } | null = null;
  if (limits.every((event) => event.version !== null)) {
    for (const event of limits) {
      if (event.version !== null && (limit === null || event.version.compare(limit.version) > 0)) {
        limit = { version: event.version, text: event.text };
      }
    }
  }
  return {
    package: range.package,
    events: sortEvents(compiled.filter((event) => event.kind !== "limit")),
    limit,
    explicit,
  };
}

function inEvents(events: readonly CompiledEvent[], version: NpmVersion): boolean {
  let affected = false;
  for (const event of events) {
    if (event.kind === "introduced") {
      if (event.version === null || version.compare(event.version) >= 0) affected = true;
    } else if (event.kind === "fixed") {
      if (event.version !== null && version.compare(event.version) >= 0) affected = false;
    } else if (event.kind === "last_affected") {
      if (event.version !== null && version.compare(event.version) > 0) affected = false;
    }
  }
  return affected;
}

/**
 * Whether a compiled range affects `version`. Listed versions match by SemVer equality, so build
 * metadata is ignored (OSV: versions "may be normalized, or have build metadata stripped").
 */
export function compiledRangeAffects(range: CompiledRange, version: NpmVersion): boolean {
  if (range.explicit.has(precedenceKey(version))) return true;
  if (range.events === null) return false;
  if (range.limit !== null && version.compare(range.limit.version) >= 0) return false;
  return inEvents(range.events, version);
}

/** Whether one range row affects `version` (an exact version string). */
export function rangeAffects(range: AdvisoryRange, version: string): boolean {
  return compiledRangeAffects(compileRange(range), parseOrThrow(version));
}

/** An advisory compiled for one or more packages. */
export interface CompiledAdvisory<A extends AdvisoryFacts = AdvisoryFacts> {
  readonly advisory: A;
  readonly byPackage: ReadonlyMap<PackageName, readonly CompiledRange[]>;
}

export function compileAdvisory<A extends AdvisoryFacts>(advisory: A): CompiledAdvisory<A> {
  const byPackage = new Map<PackageName, CompiledRange[]>();
  for (const range of advisory.ranges) {
    const list = byPackage.get(range.package) ?? [];
    list.push(compileRange(range));
    byPackage.set(range.package, list);
  }
  return { advisory, byPackage };
}

/** Whether a compiled advisory affects `packageName@version` (any of its rows). */
export function compiledAdvisoryAffects(
  compiled: CompiledAdvisory,
  packageName: PackageName,
  version: NpmVersion,
): boolean {
  return (compiled.byPackage.get(packageName) ?? []).some((range) =>
    compiledRangeAffects(range, version),
  );
}

/** `isAffected`: whether the advisory's ranges or listed versions include `packageName@version`. */
export function isAffected(
  advisory: AdvisoryFacts,
  packageName: PackageName,
  version: string,
): boolean {
  return compiledAdvisoryAffects(compileAdvisory(advisory), packageName, parseOrThrow(version));
}

// ---- Affected set description ----

/** One end of an interval; null means unbounded. */
export interface VersionBound {
  readonly version: string;
  readonly inclusive: boolean;
}

/** A contiguous affected interval in SemVer order. */
export interface VersionInterval {
  readonly from: VersionBound | null;
  readonly to: VersionBound | null;
}

/** The whole affected set of one package: intervals from the ranges plus listed versions. */
export interface AffectedSet {
  readonly intervals: readonly VersionInterval[];
  readonly versions: readonly string[];
}

interface BoundedEvent {
  readonly kind: AdvisoryRangeEventKind;
  readonly version: NpmVersion;
  readonly text: string;
}

type Segment =
  | { readonly kind: "below"; readonly affected: boolean }
  | { readonly kind: "point" | "after"; readonly at: string; readonly affected: boolean };

/** Groups sorted events with a version into runs of equal versions, keeping record order. */
function groupByVersion(events: readonly CompiledEvent[]): BoundedEvent[][] {
  const groups: BoundedEvent[][] = [];
  for (const event of events) {
    if (event.version === null) continue;
    const bounded: BoundedEvent = { kind: event.kind, version: event.version, text: event.text };
    const last = groups.at(-1);
    if (last?.[0] !== undefined && last[0].version.compare(bounded.version) === 0)
      last.push(bounded);
    else groups.push([bounded]);
  }
  return groups;
}

/** The affected state on each region between and at the distinct event versions of one range. */
function segments(events: readonly CompiledEvent[]): Segment[] {
  const openAtStart = events.some((event) => event.version === null && event.kind === "introduced");
  const result: Segment[] = [{ kind: "below", affected: openAtStart }];
  let lastApplicable: AdvisoryRangeEventKind | null = openAtStart ? "introduced" : null;
  for (const group of groupByVersion(events)) {
    const at = group[0]?.text ?? "";
    // At the point itself: `introduced`/`fixed` at this version apply, `last_affected` does not.
    const atPoint =
      group.findLast((event) => event.kind !== "last_affected")?.kind ?? lastApplicable;
    result.push({ kind: "point", at, affected: atPoint === "introduced" });
    // Just after it every event of the group applies; the last one in record order decides.
    lastApplicable = group.at(-1)?.kind ?? lastApplicable;
    result.push({ kind: "after", at, affected: lastApplicable === "introduced" });
  }
  return result;
}

function capAt(
  intervals: VersionInterval[],
  limit: { readonly version: NpmVersion; readonly text: string } | null,
): VersionInterval[] {
  if (limit === null) return intervals;
  const capped: VersionInterval[] = [];
  for (const interval of intervals) {
    const from = interval.from === null ? null : parseOrThrow(interval.from.version);
    if (from !== null && from.compare(limit.version) >= 0) continue;
    const to = interval.to === null ? null : parseOrThrow(interval.to.version);
    const exceeds =
      to === null ||
      to.compare(limit.version) > 0 ||
      (to.compare(limit.version) === 0 && interval.to?.inclusive === true);
    capped.push(
      exceeds ? { from: interval.from, to: { version: limit.text, inclusive: false } } : interval,
    );
  }
  return capped;
}

/** The affected intervals of one compiled range (listed versions excluded). */
export function rangeIntervals(range: CompiledRange): VersionInterval[] {
  if (range.events === null) return [];
  const intervals: VersionInterval[] = [];
  let open: VersionBound | null | undefined;
  for (const segment of segments(range.events)) {
    if (segment.kind === "below") {
      if (segment.affected) open = null;
      continue;
    }
    if (segment.affected && open === undefined) {
      open = { version: segment.at, inclusive: segment.kind === "point" };
    } else if (!segment.affected && open !== undefined) {
      intervals.push({
        from: open,
        to: { version: segment.at, inclusive: segment.kind === "after" },
      });
      open = undefined;
    }
  }
  if (open !== undefined) intervals.push({ from: open, to: null });
  return capAt(intervals, range.limit);
}

/** The full affected set of `packageName` under an advisory (every row, in record order). */
export function affectedSet(advisory: AdvisoryFacts, packageName: PackageName): AffectedSet {
  const intervals: VersionInterval[] = [];
  const versions = new Set<string>();
  for (const range of advisory.ranges) {
    if (range.package !== packageName) continue;
    const compiled = compileRange(range);
    intervals.push(...rangeIntervals(compiled));
    for (const version of range.explicitVersions) versions.add(version);
  }
  return { intervals, versions: [...versions] };
}

/** Whether `version` lies in an interval (used to cross-check descriptions against evaluation). */
export function intervalContains(interval: VersionInterval, version: NpmVersion): boolean {
  if (interval.from !== null) {
    const order = version.compare(parseOrThrow(interval.from.version));
    if (order < 0 || (order === 0 && !interval.from.inclusive)) return false;
  }
  if (interval.to !== null) {
    const order = version.compare(parseOrThrow(interval.to.version));
    if (order > 0 || (order === 0 && !interval.to.inclusive)) return false;
  }
  return true;
}
