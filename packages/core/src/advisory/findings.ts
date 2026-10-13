import {
  P0_TRIGGERS,
  p0TriggerSchema,
  type AdvisoryId,
  type FindingStatus,
  type P0Trigger,
  type PackageName,
  type PackageVersion,
  type Tier,
  type TierReason,
} from "@kovo/contracts";

import type { AdvisoryMatch } from "./match.js";
import type { TierDecision } from "./tier.js";
import { compareVersionText } from "./version.js";

// SPEC inventoryWorkflow step 4: "Upsert findings, resolve absent findings, and reopen recurring
// affected versions without losing history. Dismissal is scoped to the affected version; advisory
// withdrawal and later reinstatement are distinct events." Step 5: "Immediately enqueue
// `finding.p0_detected` on a newly detected/reopened P0". "A withdrawn advisory withdraws its
// findings". `reclassify`: "Re-tier affected findings". A pure reducer over one repository's
// findings; the inventory and advisory services persist its output. Transitions
// (docs/decisions/advisory.md "Finding lifecycle"; "matched" means the current snapshot has the
// version and the advisory's current revision affects it):
//
// | before \ now | matched, advisory active     | matched, withdrawn | unmatched, active | unmatched, withdrawn |
// | ------------ | ---------------------------- | ------------------ | ----------------- | -------------------- |
// | none         | opened (open)                | —                  | —                 | —                    |
// | open         | seen (re-tiered in place)    | withdrawn          | resolved          | withdrawn            |
// | dismissed    | seen (stays dismissed), or   | withdrawn          | resolved          | withdrawn            |
// |              | escalated (open) on a new P0 |                    |                   |                      |
// | withdrawn    | reinstated (open, or         | seen (tier kept)   | resolved          | — (stays withdrawn)  |
// |              | dismissed if dismissed this  |                    |                   |                      |
// |              | occurrence and not a new P0) |                    |                   |                      |
// | resolved     | reopened (open)              | — (stays resolved) | —                 | —                    |
//
// A withdrawn finding keeps the tier it last had while its advisory was active, so a reinstatement
// judges escalation against the risk the finding (and any dismissal) was assessed at.

/** A finding's lifecycle facts (`findings` columns the reducer reads and writes). */
export interface FindingState {
  readonly advisoryId: AdvisoryId;
  readonly package: PackageName;
  readonly version: PackageVersion;
  readonly status: FindingStatus;
  readonly isDev: boolean;
  readonly tier: Tier;
  readonly tierReason: TierReason;
  readonly tierConfigVersion: string;
  /** When Kovo first recorded the finding; never changes. */
  readonly firstSeenAt: Date;
  readonly lastSeenAt: Date;
  /** Start of the current occurrence (created, reopened, reinstated or escalated): latency clock. */
  readonly detectedAt: Date;
  /** History: kept when the finding reopens. */
  readonly resolvedAt: Date | null;
  /** History: kept when the advisory is reinstated. */
  readonly withdrawnAt: Date | null;
  /** History: a dismissal belongs to the current occurrence iff `dismissedAt ≥ detectedAt`. */
  readonly dismissedAt: Date | null;
}

/** The current state of an advisory, as the reducer needs it. */
export interface AdvisoryState {
  readonly withdrawn: boolean;
  /** When the current revision of the advisory was ingested. */
  readonly ingestedAt: Date;
}

export interface ReconcileInput {
  /** Every finding the repository has for the advisories in scope (any status). */
  readonly existing: readonly FindingState[];
  /** `matchAdvisories` over the current snapshot (withdrawn advisories included). */
  readonly matches: readonly AdvisoryMatch[];
  /**
   * The state of every matched advisory and of every advisory with an unresolved finding in scope
   * (so a withdrawn revision that no longer lists a version withdraws its findings rather than
   * resolving them).
   */
  readonly advisories: ReadonlyMap<AdvisoryId, AdvisoryState>;
  /**
   * `all` after a new inventory (every finding is in scope, so absent ones resolve); the changed
   * advisories after `reclassify`, whose other findings are left alone.
   */
  readonly scope: "all" | ReadonlySet<AdvisoryId>;
  /** When the inventory being reconciled was parsed. */
  readonly observedAt: Date;
  readonly now: Date;
}

export type FindingChangeKind =
  | "opened"
  | "reopened"
  | "reinstated"
  | "escalated"
  | "withdrawn"
  | "resolved"
  | "seen";

export interface FindingChange {
  readonly kind: FindingChangeKind;
  readonly before: FindingState | null;
  readonly after: FindingState;
  /** The tier changed (reclassification, a dev/production change or new tier config). */
  readonly retiered: boolean;
}

/** A `finding.p0_detected` alert: sent before any fix attempt. */
export interface P0Detection {
  readonly advisoryId: AdvisoryId;
  readonly package: PackageName;
  readonly version: PackageVersion;
  readonly isDev: boolean;
  readonly trigger: P0Trigger;
  /** How the finding became an open P0. */
  readonly cause: "opened" | "reopened" | "reinstated" | "escalated";
  readonly detectedAt: Date;
}

export interface ReconcileCounts {
  readonly opened: number;
  readonly reopened: number;
  readonly reinstated: number;
  /** Dismissed findings reopened because they became a P0 (or a stronger P0 trigger). */
  readonly escalated: number;
  readonly withdrawn: number;
  readonly resolved: number;
  /** Findings re-tiered in place (`seen` with a different tier). */
  readonly retiered: number;
}

export interface ReconcileResult {
  /** One entry per finding that is created or changes, sorted by package, version, advisory. */
  readonly changes: readonly FindingChange[];
  readonly p0Detected: readonly P0Detection[];
  readonly counts: ReconcileCounts;
}

function keyOf(f: { advisoryId: string; package: string; version: string }): string {
  return `${f.package}\u0000${f.version}\u0000${f.advisoryId}`;
}

function laterOf(a: Date, b: Date): Date {
  return a.getTime() >= b.getTime() ? a : b;
}

function earlierOf(a: Date, b: Date): Date {
  return a.getTime() <= b.getTime() ? a : b;
}

/** Whether the finding's dismissal was made during its current occurrence. */
export function dismissalIsCurrent(finding: FindingState): boolean {
  return (
    finding.dismissedAt !== null && finding.dismissedAt.getTime() >= finding.detectedAt.getTime()
  );
}

function isP0Trigger(reason: TierReason): reason is P0Trigger {
  return p0TriggerSchema.safeParse(reason).success;
}

/**
 * How strong a tier reason is as a P0 trigger: 0 for anything that is not P0, otherwise by SPEC
 * `tier()`'s precedence (contracts `P0_TRIGGERS`: malicious, then KEV, then the package-and-CWE
 * heuristic).
 */
function p0Strength(reason: TierReason): number {
  return isP0Trigger(reason) ? P0_TRIGGERS.length - P0_TRIGGERS.indexOf(reason) : 0;
}

/**
 * Whether a dismissed finding's new tiering is a new P0: it was not P0, or it now rests on a
 * stronger trigger (a heuristic P0 that enters KEV, anything that turns out to be malware). A
 * dismissal judged the risk as it was then; SPEC alerts on and fixes P0s, so a stale dismissal must
 * not silence a known-exploited or malicious finding.
 */
export function escalatesDismissal(
  before: Pick<FindingState, "tierReason">,
  current: Pick<TierDecision, "reason">,
): boolean {
  return p0Strength(current.reason) > p0Strength(before.tierReason);
}

function tiered(state: FindingState, match: AdvisoryMatch, now: Date): FindingState {
  return {
    ...state,
    isDev: match.isDev,
    tier: match.tier.tier,
    tierReason: match.tier.reason,
    tierConfigVersion: match.tier.configVersion,
    lastSeenAt: laterOf(state.lastSeenAt, now),
  };
}

function inScope(scope: ReconcileInput["scope"], advisoryId: AdvisoryId): boolean {
  return scope === "all" || scope.has(advisoryId);
}

/**
 * Reconciles a repository's findings with the current matches. Pure: the result says what to
 * insert and update; nothing is deleted, and dismissal, resolution and withdrawal facts stay as
 * history on the row. Throws RangeError on inconsistent input (duplicate findings or matches, an
 * advisory in play without state).
 */
export function reconcileFindings(input: ReconcileInput): ReconcileResult {
  const { now } = input;
  const existing = new Map<string, FindingState>();
  for (const finding of input.existing) {
    if (!inScope(input.scope, finding.advisoryId)) continue;
    const key = keyOf(finding);
    if (existing.has(key)) throw new RangeError(`duplicate finding ${key}`);
    existing.set(key, finding);
  }
  const matched = new Map<string, AdvisoryMatch>();
  for (const match of input.matches) {
    if (!inScope(input.scope, match.advisoryId)) continue;
    const key = keyOf({
      advisoryId: match.advisoryId,
      package: match.package,
      version: match.version,
    });
    if (matched.has(key)) throw new RangeError(`duplicate match ${key}`);
    matched.set(key, match);
  }
  const stateOf = (advisoryId: AdvisoryId): AdvisoryState => {
    const state = input.advisories.get(advisoryId);
    if (state === undefined) throw new RangeError(`no state for advisory ${advisoryId}`);
    return state;
  };

  // A new occurrence starts at `start` (never later than now) and always after an earlier
  // dismissal, so that dismissal stays history.
  const occurrenceStart = (start: Date, before: FindingState | null) => {
    const capped = earlierOf(start, now);
    const dismissed = before?.dismissedAt;
    return dismissed != null && dismissed.getTime() >= capped.getTime()
      ? new Date(dismissed.getTime() + 1)
      : capped;
  };
  // Opened, reopened, reinstated: the later of the advisory revision's ingestion and the
  // inventory's parse. Escalated: now, when the run observed the new P0 (a KEV or tier-config
  // change has no advisory revision to date it by).
  const detectedAtFor = (advisory: AdvisoryState, before: FindingState | null) =>
    occurrenceStart(laterOf(advisory.ingestedAt, input.observedAt), before);

  const changes: FindingChange[] = [];
  const push = (kind: FindingChangeKind, before: FindingState | null, after: FindingState) =>
    changes.push({ kind, before, after, retiered: before !== null && before.tier !== after.tier });
  // Withdrawal keeps the tier the finding had while its advisory was active.
  const withdraw = (before: FindingState, seen: boolean) =>
    push("withdrawn", before, {
      ...before,
      status: "withdrawn",
      withdrawnAt: now,
      lastSeenAt: seen ? laterOf(before.lastSeenAt, now) : before.lastSeenAt,
    });

  for (const [key, match] of matched) {
    const advisory = stateOf(match.advisoryId);
    const before = existing.get(key) ?? null;
    if (before === null) {
      if (advisory.withdrawn) continue;
      push("opened", null, {
        advisoryId: match.advisoryId,
        package: match.package,
        version: match.version,
        status: "open",
        isDev: match.isDev,
        tier: match.tier.tier,
        tierReason: match.tier.reason,
        tierConfigVersion: match.tier.configVersion,
        firstSeenAt: now,
        lastSeenAt: now,
        detectedAt: detectedAtFor(advisory, null),
        resolvedAt: null,
        withdrawnAt: null,
        dismissedAt: null,
      });
      continue;
    }
    if (advisory.withdrawn) {
      if (before.status === "open" || before.status === "dismissed") withdraw(before, true);
      else if (before.status === "withdrawn") {
        push("seen", before, { ...before, lastSeenAt: laterOf(before.lastSeenAt, now) });
      }
      // A resolved finding stays resolved while its advisory is withdrawn.
      continue;
    }
    const updated = tiered(before, match, now);
    switch (before.status) {
      case "open":
        push("seen", before, updated);
        break;
      case "dismissed":
        if (escalatesDismissal(before, match.tier)) {
          push("escalated", before, {
            ...updated,
            status: "open",
            detectedAt: occurrenceStart(now, before),
          });
        } else {
          push("seen", before, updated);
        }
        break;
      case "resolved":
        push("reopened", before, {
          ...updated,
          status: "open",
          detectedAt: detectedAtFor(advisory, before),
        });
        break;
      case "withdrawn":
        push(
          "reinstated",
          before,
          dismissalIsCurrent(before) && !escalatesDismissal(before, match.tier)
            ? { ...updated, status: "dismissed" }
            : { ...updated, status: "open", detectedAt: detectedAtFor(advisory, before) },
        );
        break;
    }
  }
  for (const [key, before] of existing) {
    if (matched.has(key) || before.status === "resolved") continue;
    // Unmatched: the version left the snapshot, or the advisory's current revision no longer lists
    // it. "A withdrawn advisory withdraws its findings" either way; otherwise they resolve.
    if (stateOf(before.advisoryId).withdrawn) {
      if (before.status !== "withdrawn") withdraw(before, false);
      continue;
    }
    push("resolved", before, { ...before, status: "resolved", resolvedAt: now });
  }

  changes.sort((a, b) => {
    if (a.after.package !== b.after.package) return a.after.package < b.after.package ? -1 : 1;
    if (a.after.version !== b.after.version)
      return compareVersionText(a.after.version, b.after.version);
    return a.after.advisoryId < b.after.advisoryId
      ? -1
      : a.after.advisoryId > b.after.advisoryId
        ? 1
        : 0;
  });

  const p0Detected: P0Detection[] = [];
  for (const change of changes) {
    const { after, before } = change;
    if (after.status !== "open" || after.tier !== "P0" || !isP0Trigger(after.tierReason)) continue;
    let cause: P0Detection["cause"] | null = null;
    let detectedAt = after.detectedAt;
    if (
      change.kind === "opened" ||
      change.kind === "reopened" ||
      change.kind === "reinstated" ||
      change.kind === "escalated"
    ) {
      cause = change.kind;
    } else if (change.kind === "seen" && before?.status === "open" && before.tier !== "P0") {
      // An open finding escalated to P0: a first detection as P0 within the same occurrence.
      cause = "escalated";
      detectedAt = now;
    }
    if (cause === null) continue;
    p0Detected.push({
      advisoryId: after.advisoryId,
      package: after.package,
      version: after.version,
      isDev: after.isDev,
      trigger: after.tierReason,
      cause,
      detectedAt,
    });
  }

  const count = (kind: FindingChangeKind) => changes.filter((c) => c.kind === kind).length;
  return {
    changes,
    p0Detected,
    counts: {
      opened: count("opened"),
      reopened: count("reopened"),
      reinstated: count("reinstated"),
      escalated: count("escalated"),
      withdrawn: count("withdrawn"),
      resolved: count("resolved"),
      retiered: changes.filter((c) => c.kind === "seen" && c.retiered).length,
    },
  };
}

export type DismissOutcome =
  | { readonly outcome: "dismissed"; readonly after: FindingState }
  | { readonly outcome: "unchanged"; readonly after: FindingState }
  | { readonly outcome: "conflict"; readonly status: FindingStatus };

/**
 * Dismisses one finding: its own `(advisory, package, version)` only ("Dismissal is scoped to the
 * affected version"). Another version of the package, or the same version under another advisory,
 * is a different finding. Dismissing a dismissed finding changes nothing; a resolved or withdrawn
 * finding cannot be dismissed (`conflict`, SPEC `POST …/dismiss` answers 409). A dismissal holds
 * until the finding becomes a new P0 (`escalatesDismissal`).
 */
export function dismissFinding(finding: FindingState, now: Date): DismissOutcome {
  if (finding.status === "dismissed") return { outcome: "unchanged", after: finding };
  if (finding.status !== "open") return { outcome: "conflict", status: finding.status };
  return { outcome: "dismissed", after: { ...finding, status: "dismissed", dismissedAt: now } };
}
