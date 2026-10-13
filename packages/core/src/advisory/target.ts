import type {
  AdvisoryId,
  DependencyChangeKind,
  FixTier,
  PackageName,
  PackageVersion,
  SemverBump,
  TierConfigSets,
} from "@kovo/contracts";

import { bumpBetween, caretLine } from "../versions/step.js";
import { evaluateCooldown, type CooldownOutcome } from "./cooldown.js";
import { isIntroducedSevere, isSevere, severeBaseline, type TieredMatch } from "./introduced.js";
import type { AdvisoryFacts } from "./model.js";
import { compileAdvisory, compiledAdvisoryAffects, type CompiledAdvisory } from "./ranges.js";
import { tierDecision } from "./tier.js";
import { parseNpmVersion, parseVersionText, releaseTuple, type NpmVersion } from "./version.js";

// SPEC "Fix identity and enqueueing": "A candidate must clear the union of all affected
// ranges/explicit versions for every targeted package instance and avoid new P0/P1 or malicious
// findings. Taking the maximum of individual minimal fixed versions is insufficient when affected
// ranges are disjoint or vulnerabilities recur." Fix ladder: "Stop at the smallest candidate that
// clears all targeted affected instances without introducing P0/P1 or malicious findings." Rung M:
// "Evidenced rollback/removal for malicious package"; "A rollback requires evidence that the
// chosen version is outside all known malicious/affected ranges; older does not automatically mean
// safe. If no safe version is known, alert immediately … Never guess a replacement package."
//
// Every candidate is checked against every range directly (not by combining per-advisory fixed
// versions), so disjoint and recurring ranges are handled by construction. "New" findings follow
// `introduced.ts`: an advisory that already affected a replaced instance at P0/P1 (such as a
// dismissed finding) is carried and disclosed, not a reason to reject the candidate; malware never
// is.
//
// Only the targeted instances (those with open P0/P1 findings the fix targets) are replaced, and
// candidates are ordered relative to them alone. A copy of the package without targeted findings is
// left as it is: it neither raises the search floor (a copy already on the fixed version, or on a
// newer one, must not push the target past the smallest candidate) nor is it rolled back. Its
// version stays a candidate like any other, and when it is locked it is exempt from the cooldown,
// so a dedupe onto it is found first when it is the smallest candidate.

/** One locked instance of the package: the target replaces it when the fix targets it. */
export interface TargetInstance {
  readonly version: PackageVersion;
  readonly isDev: boolean;
  /** Package-name chains from a direct dependency down to the instance (`resolved_packages`). */
  readonly depPaths: readonly (readonly PackageName[])[];
  /**
   * Advisories of the open P0/P1 findings on this instance that the fix targets. None (or only
   * withdrawn ones): the instance is not targeted and the target leaves it as it is.
   */
  readonly advisoryIds: readonly AdvisoryId[];
}

/** A published version from the registry, with its packument `time[version]`. */
export interface RegistryVersion {
  readonly version: string;
  readonly publishedAt: Date | null;
}

export interface TargetRequest {
  readonly package: PackageName;
  readonly fixTier: FixTier;
  /** Every locked instance of the package, with or without targeted findings. */
  readonly instances: readonly TargetInstance[];
  /** Every version of the package currently in the lockfile (cooldown exemption). */
  readonly lockedVersions: readonly PackageVersion[];
  /** Every known advisory with ranges for the package (targeted ones included, withdrawn allowed). */
  readonly advisories: readonly AdvisoryFacts[];
  readonly kev: ReadonlySet<string>;
  readonly tierConfig: TierConfigSets;
  readonly registry: readonly RegistryVersion[];
  readonly now: Date;
}

/** How the target changes one instance (contracts `DependencyChangeKind` and `SemverBump`). */
export interface InstanceChange {
  readonly from: PackageVersion;
  readonly to: PackageVersion;
  /**
   * The instance's dependency paths, so the ladder planner (`core/lockfile`) can tell which parent
   * ranges must accept `to` (a lower copy may need its parent updated, or be out of reach).
   */
  readonly depPaths: readonly (readonly PackageName[])[];
  readonly change: Extract<DependencyChangeKind, "upgraded" | "downgraded">;
  readonly bump: SemverBump;
  /** npm caret compatibility (`^from` includes `to`): an upgrade within the same breaking line. */
  readonly caretCompatible: boolean;
}

/** A locked copy without targeted findings: the target leaves it as it is. */
export interface UnchangedInstance {
  readonly version: PackageVersion;
  readonly isDev: boolean;
  readonly depPaths: readonly (readonly PackageName[])[];
}

/** Why candidates were rejected, for "no eligible target" explanations. */
export interface CandidateCounts {
  /** Candidates in the searched direction(s) that passed the prerelease rule. */
  readonly considered: number;
  /** Still inside a targeted advisory's ranges or listed versions. */
  readonly affectedByTargeted: number;
  /**
   * Would introduce a new P0/P1 or malicious finding (`introduced.ts`), or is a version a malicious
   * advisory lists (a fix never lands on malware, even a copy that is already locked).
   */
  readonly introducesSevere: number;
  /** P1 only: the registry has no publication time. */
  readonly publishTimeUnknown: number;
}

export type TargetResolution =
  | {
      readonly status: "target";
      readonly version: PackageVersion;
      readonly direction: "upgrade" | "rollback";
      readonly publishedAt: Date | null;
      /** How the target changes each targeted instance (the ones it replaces). */
      readonly instances: readonly InstanceChange[];
      /** The locked copies without targeted findings, which the target leaves as they are. */
      readonly unchanged: readonly UnchangedInstance[];
      readonly cooldown: Extract<
        CooldownOutcome,
        { status: "exempt_locked" | "cleared" | "blocked" }
      >;
      /** The targeted advisories the target clears (every active one). */
      readonly clearedAdvisoryIds: readonly AdvisoryId[];
      /**
       * Other advisories that still affect the target, disclosed rather than blocking: digest-tier
       * ones, and the carried ones below. Never a malicious one.
       */
      readonly remainingAdvisoryIds: readonly AdvisoryId[];
      /**
       * The P0/P1 subset of `remainingAdvisoryIds`: each already affected a replaced instance at
       * P0/P1 (for example a dismissed finding with no fix), so the target carries it, not adds it.
       */
      readonly carriedSevereAdvisoryIds: readonly AdvisoryId[];
      /**
       * Every candidate the target could have been, ascending: each passes the same checks as
       * `version` (outside every targeted range, no new P0/P1 or malicious finding, the cooldown
       * cleared or exempt for P1; P0 may verify a dated young candidate in the sandbox). Upgrades only, plus rollbacks when a targeted
       * advisory is malicious. Package managers resolve to the newest version a range admits, so
       * the ladder (`core/lockfile` `LadderTarget.safeVersions`) accepts any of these, never a
       * version outside them: for P1 a newer candidate still inside its 24-hour cooldown is not
       * here.
       */
      readonly eligibleVersions: readonly PackageVersion[];
      readonly tierConfigVersion: string;
    }
  | {
      /** P1: the smallest eligible candidate is younger than 24 hours; recompute at `until`. */
      readonly status: "wait";
      readonly reason: "cooldown";
      readonly candidate: PackageVersion;
      readonly until: Date;
      readonly tierConfigVersion: string;
    }
  | {
      readonly status: "no_eligible_target";
      /** The fix's wait reason: malicious packages need a safe version or a reviewed removal. */
      readonly reason: "no_fixed_version" | "no_safe_version";
      readonly candidates: CandidateCounts;
      readonly tierConfigVersion: string;
    }
  /** Every targeted advisory is withdrawn (or none was given): nothing to fix. */
  | { readonly status: "no_actionable_advisories" };

/**
 * npm `^from` semantics for an upgrade: `to` is newer and on the same caret line (prereleases
 * compared by precedence, not excluded).
 */
function caretCompatible(from: NpmVersion, to: NpmVersion): boolean {
  return to.compare(from) > 0 && caretLine(from) === caretLine(to);
}

function describeChange(
  from: {
    readonly text: PackageVersion;
    readonly version: NpmVersion;
    readonly depPaths: readonly (readonly PackageName[])[];
  },
  to: { readonly text: PackageVersion; readonly version: NpmVersion },
): InstanceChange {
  const upgrade = to.version.compare(from.version) > 0;
  return {
    from: from.text,
    to: to.text,
    depPaths: from.depPaths,
    change: upgrade ? "upgraded" : "downgraded",
    bump: bumpBetween(from.version, to.version),
    caretCompatible: upgrade && caretCompatible(from.version, to.version),
  };
}

interface Candidate {
  readonly text: PackageVersion;
  readonly version: NpmVersion;
  readonly publishedAt: Date | null;
}

/**
 * Chooses the fix target for one package: the smallest published version above every targeted
 * instance that is outside the union of the targeted advisories' ranges and listed versions and
 * that introduces no new P0/P1 or malicious finding (`isIntroducedSevere` against the package's
 * findings before the change; never a version a malicious advisory lists). For a malicious package
 * with no such upgrade, the newest such version below every targeted instance (an evidenced
 * rollback). Copies without targeted findings are not replaced and do not bound the search.
 * P1 applies the 24-hour cooldown to the chosen version and waits for it rather than jumping to a
 * larger one (a locked version is exempt); P0 prefers an aged candidate within the same bump class and verifies young candidates before publication waits. Prerelease versions
 * are candidates only when every targeted instance is on a prerelease of the same
 * `major.minor.patch`.
 */
export function resolveTarget(request: TargetRequest): TargetResolution {
  const cfg = request.tierConfig;
  if (request.instances.length === 0) return { status: "no_actionable_advisories" };
  const byId = new Map<AdvisoryId, AdvisoryFacts>();
  for (const advisory of request.advisories) byId.set(advisory.id, advisory);

  const targetedIds = [...new Set(request.instances.flatMap((instance) => instance.advisoryIds))];
  const targeted: CompiledAdvisory[] = [];
  for (const id of targetedIds) {
    const advisory = byId.get(id);
    if (advisory === undefined) throw new RangeError(`targeted advisory ${id} was not provided`);
    if (advisory.withdrawnAt === null) targeted.push(compileAdvisory(advisory));
  }
  if (targeted.length === 0) return { status: "no_actionable_advisories" };
  const targetedSet = new Set(targeted.map((compiled) => compiled.advisory.id));
  const others = request.advisories
    .filter((advisory) => advisory.withdrawnAt === null && !targetedSet.has(advisory.id))
    .map((advisory) => compileAdvisory(advisory));
  const malicious = targeted.some((compiled) => compiled.advisory.isMalicious);

  const current = request.instances.map((instance) => {
    const version = parseNpmVersion(instance.version);
    if (version === null) throw new RangeError(`not an exact version: ${instance.version}`);
    return {
      text: instance.version,
      version,
      depPaths: instance.depPaths,
      isDev: instance.isDev,
      // SPEC: "for every targeted package instance". An instance is targeted when the fix targets
      // an active advisory on it; the others are left as they are.
      targeted: instance.advisoryIds.some((id) => targetedSet.has(id)),
    };
  });
  const replaced = current.filter((instance) => instance.targeted);
  const unchanged: UnchangedInstance[] = current
    .filter((instance) => !instance.targeted)
    .map((instance) => ({
      version: instance.text,
      isDev: instance.isDev,
      depPaths: instance.depPaths,
    }));
  const instances = replaced.map((instance) => instance.version);
  const highest = instances.reduce((a, b) => (b.compare(a) > 0 ? b : a));
  const lowest = instances.reduce((a, b) => (b.compare(a) < 0 ? b : a));
  // The target replaces the targeted instances, so it is production unless every one of them is
  // dev-only, and unless it is the version of a production copy left in place (the package
  // manager then resolves both to one production instance).
  const replacedDevOnly = replaced.every((instance) => instance.isDev);
  const productionVersions = new Set(
    current.filter((instance) => !instance.isDev).map((instance) => instance.version.version),
  );
  const isDevTarget = (candidate: Candidate) =>
    replacedDevOnly && !productionVersions.has(candidate.version.version);
  const prereleaseTuple =
    instances.every((v) => v.prerelease.length > 0) &&
    new Set(instances.map(releaseTuple)).size === 1
      ? releaseTuple(highest)
      : null;

  const seen = new Set<string>();
  const candidates: Candidate[] = [];
  for (const entry of request.registry) {
    const parsed = parseVersionText(entry.version);
    if (parsed === null || seen.has(parsed.version.version)) continue;
    seen.add(parsed.version.version);
    const { version } = parsed;
    if (version.prerelease.length > 0 && releaseTuple(version) !== prereleaseTuple) continue;
    candidates.push({ text: parsed.text, version, publishedAt: entry.publishedAt });
  }
  candidates.sort((a, b) => a.version.compare(b.version));

  const counts = {
    considered: 0,
    affectedByTargeted: 0,
    introducesSevere: 0,
    publishTimeUnknown: 0,
  };
  const locked = new Set<string>(request.lockedVersions);
  const affects = (compiled: CompiledAdvisory, version: NpmVersion) =>
    compiledAdvisoryAffects(compiled, request.package, version);
  const tiered = (
    compiled: CompiledAdvisory,
    version: PackageVersion,
    dev: boolean,
  ): TieredMatch => ({
    advisoryId: compiled.advisory.id,
    package: request.package,
    version,
    tier: tierDecision(
      { package: request.package, isDev: dev },
      compiled.advisory,
      request.kev,
      cfg,
    ),
  });
  // The package's findings before the change (every locked copy), under every active advisory.
  const baseline = severeBaseline(
    current.flatMap((instance) =>
      [...targeted, ...others]
        .filter((compiled) => affects(compiled, instance.version))
        .map((compiled) => tiered(compiled, instance.text, instance.isDev)),
    ),
  );

  type Assessment =
    | { readonly kind: "affected" | "introduces_severe" | "publish_time_unknown" }
    | { readonly kind: "blocked"; readonly until: Date }
    | {
        readonly kind: "eligible";
        readonly remaining: readonly TieredMatch[];
        readonly cooldown: Extract<
          CooldownOutcome,
          { status: "exempt_locked" | "cleared" | "blocked" }
        >;
      };

  const assess = (candidate: Candidate): Assessment => {
    if (targeted.some((compiled) => affects(compiled, candidate.version))) {
      return { kind: "affected" };
    }
    const remaining = others
      .filter((compiled) => affects(compiled, candidate.version))
      .map((compiled) => tiered(compiled, candidate.text, isDevTarget(candidate)));
    // A locked copy's malware finding is in the baseline (possibly dismissed), but moving the
    // targeted instances onto that version would still land them on malware.
    if (
      remaining.some(
        (match) => match.tier.reason === "malicious" || isIntroducedSevere(match, baseline),
      )
    ) {
      return { kind: "introduces_severe" };
    }
    const cooldown = evaluateCooldown({
      tier: request.fixTier,
      version: candidate.text,
      publishedAt: candidate.publishedAt,
      lockedVersions: locked,
      now: request.now,
    });
    if (cooldown.status === "publish_time_unknown") return { kind: "publish_time_unknown" };
    if (cooldown.status === "blocked" && request.fixTier !== "P0")
      return { kind: "blocked", until: cooldown.until };
    return { kind: "eligible", remaining, cooldown };
  };

  // Candidates in the searched directions: above every targeted instance, and below every targeted
  // instance when a targeted advisory is malicious.
  const searched = candidates.filter(
    (candidate) =>
      candidate.version.compare(highest) > 0 ||
      (malicious && candidate.version.compare(lowest) < 0),
  );

  const tryCandidate = (
    candidate: Candidate,
    direction: "upgrade" | "rollback",
  ): TargetResolution | null => {
    counts.considered += 1;
    const assessment = assess(candidate);
    switch (assessment.kind) {
      case "affected":
        counts.affectedByTargeted += 1;
        return null;
      case "introduces_severe":
        counts.introducesSevere += 1;
        return null;
      case "publish_time_unknown":
        counts.publishTimeUnknown += 1;
        return null;
      case "blocked":
        return {
          status: "wait",
          reason: "cooldown",
          candidate: candidate.text,
          until: assessment.until,
          tierConfigVersion: cfg.version,
        };
      case "eligible":
        return {
          status: "target",
          version: candidate.text,
          direction,
          publishedAt: candidate.publishedAt,
          instances: replaced.map((from) => describeChange(from, candidate)),
          unchanged,
          cooldown: assessment.cooldown,
          clearedAdvisoryIds: targeted.map((compiled) => compiled.advisory.id),
          remainingAdvisoryIds: assessment.remaining.map((match) => match.advisoryId),
          carriedSevereAdvisoryIds: assessment.remaining
            .filter(isSevere)
            .map((match) => match.advisoryId),
          eligibleVersions: searched
            .filter((other) => other === candidate || assess(other).kind === "eligible")
            .map((other) => other.text),
          tierConfigVersion: cfg.version,
        };
      default: {
        const unreachable: never = assessment;
        throw new RangeError(`unknown assessment ${JSON.stringify(unreachable)}`);
      }
    }
  };

  // Prefer the smallest already-aged P0 candidate without increasing any instance's bump class
  // or adding a direct major. Otherwise verify the smallest now and wait only at publication.
  const upgrades = candidates.filter((candidate) => candidate.version.compare(highest) > 0);
  const viable = upgrades.filter((candidate) => assess(candidate).kind === "eligible");
  const smallest = viable[0];
  if (request.fixTier === "P0" && smallest !== undefined) {
    const rank = { prerelease: 0, patch: 1, minor: 2, major: 3 };
    const aged = viable.find((candidate) => {
      const assessment = assess(candidate);
      return (
        assessment.kind === "eligible" &&
        assessment.cooldown.status !== "blocked" &&
        replaced.every((from) => {
          const chosen = describeChange(from, candidate);
          const minimal = describeChange(from, smallest);
          return (
            rank[chosen.bump] <= rank[minimal.bump] &&
            !(
              chosen.bump === "major" &&
              minimal.bump !== "major" &&
              from.depPaths.some((path) => path.length <= 1)
            )
          );
        })
      );
    });
    if (aged !== undefined) return tryCandidate(aged, "upgrade")!;
  }
  for (const candidate of candidates) {
    if (candidate.version.compare(highest) <= 0) continue;
    const result = tryCandidate(candidate, "upgrade");
    if (result !== null) return result;
  }
  if (malicious) {
    for (const candidate of candidates.toReversed()) {
      if (candidate.version.compare(lowest) >= 0) continue;
      const result = tryCandidate(candidate, "rollback");
      if (result !== null) return result;
    }
  }
  return {
    status: "no_eligible_target",
    reason: malicious ? "no_safe_version" : "no_fixed_version",
    candidates: counts,
    tierConfigVersion: cfg.version,
  };
}
