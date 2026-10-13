import { DURATIONS, type FixTier } from "@kovo/contracts";

// Publication age applies to every introduced version: P0 24 hours, P1 24 hours.
// Sandbox admission is a separate decision.

export interface CooldownInput {
  readonly tier: FixTier;
  readonly version: string;
  /** Registry publication time (packument `time[version]`); null when the registry has none. */
  readonly publishedAt: Date | null;
  /** Versions of the package already in the repository's lockfile. */
  readonly lockedVersions: ReadonlySet<string>;
  readonly now: Date;
}

export type CooldownOutcome =
  /** Already locked in the repository: exempt. */
  | { readonly status: "exempt_locked" }
  /** Published at least its tier’s minimum age ago. */
  | { readonly status: "cleared"; readonly publishedAt: Date }
  /** Wait until the tier’s publication minimum clears. */
  | { readonly status: "blocked"; readonly publishedAt: Date; readonly until: Date }
  /** The registry has no publication time, so the cooldown can never be shown to have passed. */
  | { readonly status: "publish_time_unknown" };

/** Whether an outcome lets the version be used now. */
export function cooldownAllows(outcome: CooldownOutcome): boolean {
  return outcome.status === "exempt_locked" || outcome.status === "cleared";
}

export function evaluateCooldown(input: CooldownInput): CooldownOutcome {
  if (input.lockedVersions.has(input.version)) return { status: "exempt_locked" };
  const { publishedAt } = input;
  const clearsAt =
    publishedAt === null
      ? null
      : new Date(publishedAt.getTime() + minimumPublicationAge(input.tier));
  if (publishedAt !== null && clearsAt !== null && clearsAt.getTime() <= input.now.getTime()) {
    return { status: "cleared", publishedAt };
  }
  if (
    publishedAt === null ||
    !Number.isFinite(publishedAt.getTime()) ||
    clearsAt === null ||
    !Number.isFinite(clearsAt.getTime())
  )
    return { status: "publish_time_unknown" };
  return { status: "blocked", publishedAt, until: clearsAt };
}

export function minimumPublicationAge(tier: FixTier): number {
  return tier === "P0" ? DURATIONS.p0MinimumAge : DURATIONS.p1PublicationCooldown;
}
