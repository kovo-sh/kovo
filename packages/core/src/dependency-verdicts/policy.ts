import {
  DEPENDENCY_VERDICT_REASONS,
  DEPENDENCY_VERDICTS,
  DURATIONS,
  dependencyChangeSchema,
  type DependencyChange,
  type DependencyEcosystem,
  type DependencySource,
  type DependencyVerdictChangeKind,
  type DependencyVerdictKind,
  type DependencyVerdictReason,
  type SriSha512,
} from "@kovo/contracts";

import { classifyVersionChange } from "../lockfile/semver-change.js";
import { detectPublishingPath, type PublishingPathIdentity } from "../policy/publishing-path.js";
import { typosquatTarget, type PopularPackageIndex } from "./typosquat.js";

// The dependency verdict engine (plans/dependency-firewall.md Part 1; SPEC "Recipes and
// verification" → "Dependency verdict engine"). Pure: the control plane gathers the evidence of each
// change through its ports and passes the time in; this module only decides. Platform defaults:
// block confirmed malware, integrity mismatches and exotic transitive sources; wait while under the
// minimum age (24 hours) and on suspicion or unknown evidence; warn on introduced vulnerabilities,
// added install scripts, trust downgrades, maintainer changes, private-registry sources, exotic
// direct sources and typosquat candidates. Unknown is never a pass.

/** One changed or new version, derived from a lockfile diff by the caller. */
export interface DependencyVerdictInput {
  readonly ecosystem: DependencyEcosystem;
  readonly name: string;
  readonly version: string;
  /** The lockfile's sha512 integrity; null when it records none. */
  readonly integrity: SriSha512 | null;
  readonly kind: DependencyVerdictChangeKind;
  readonly direct: boolean;
  /** The version it replaces; null exactly for a new package. */
  readonly previousVersion: string | null;
  readonly source: DependencySource;
}

/** The tier of an active global Kovo hold. Its source (advisory, scanner, research) is not kept. */
export type DependencyHoldTier = "unknown" | "suspected" | "confirmed";

/** The public registry's record of one version (never persisted). */
export interface DependencyRegistryFacts {
  readonly integrity: SriSha512 | null;
  readonly publishedAt: Date | null;
  readonly hasInstallScripts: boolean | null;
  /** A verified registry provenance attestation names the version's integrity. */
  readonly attested: boolean | null;
  /** Hash of the publishing identity; null when the registry records none. */
  readonly publisherHash: string | null;
  /** Verified publishing identities of the version and its predecessors in the same major. */
  readonly publishingPath?: {
    readonly current: PublishingPathIdentity;
    readonly history: readonly PublishingPathIdentity[];
  };
}

/** What the control plane found about one change. */
export interface DependencyEvidence {
  /** Tiers of the active global holds naming this exact version, malware advisories included. */
  readonly holds: readonly DependencyHoldTier[];
  /** Non-withdrawn, non-malicious advisories that affect the version but not the previous one. */
  readonly introducedAdvisories: readonly string[];
  readonly registry:
    /** The registry could not be read: the version's age and provenance are unknown. */
    | { readonly status: "unavailable" }
    | {
        readonly status: "read";
        /** Null when the registry does not list the version (or the package). */
        readonly current: DependencyRegistryFacts | null;
        /** Null for a new package, or when the registry does not list the previous version. */
        readonly previous: DependencyRegistryFacts | null;
      };
}

/** Per-repository configuration may raise these, never lower them (later slice). */
export interface DependencyVerdictPolicy {
  readonly minimumAgeMs: number;
}

export const PLATFORM_DEPENDENCY_POLICY: DependencyVerdictPolicy = {
  minimumAgeMs: DURATIONS.p1PublicationCooldown,
};

export interface DependencyVerdict {
  readonly ecosystem: DependencyEcosystem;
  readonly name: string;
  readonly version: string;
  readonly verdict: DependencyVerdictKind;
  /** In {@link DEPENDENCY_VERDICT_REASONS} order; empty exactly for `allow`. */
  readonly reasons: readonly DependencyVerdictReason[];
  /** When a wait ends by itself (every waiting reason is `min_age`); null otherwise. */
  readonly waitUntil: Date | null;
}

export const DEPENDENCY_VERDICT_SIGNALS = ["possible_typosquat"] as const;
export type DependencyVerdictSignal = (typeof DEPENDENCY_VERDICT_SIGNALS)[number];

export interface DependencyVerdictRequest {
  readonly changes: readonly DependencyVerdictInput[];
  /** Aligned with `changes`. */
  readonly evidence: readonly DependencyEvidence[];
  /** Null when no popularity list is mirrored: the typosquat signal is then unavailable. */
  readonly popular: PopularPackageIndex | null;
  readonly now: Date;
  /** Defaults to {@link PLATFORM_DEPENDENCY_POLICY}. */
  readonly policy?: DependencyVerdictPolicy;
}

export interface DependencyVerdictResult {
  /** Aligned with the request's changes. */
  readonly verdicts: readonly DependencyVerdict[];
  /** Signals that could not run for this request; disclosed, never a verdict by themselves. */
  readonly unavailableSignals: readonly DependencyVerdictSignal[];
}

const SEVERITY = new Map(DEPENDENCY_VERDICTS.map((verdict, index) => [verdict, index]));
const REASON_ORDER = new Map(DEPENDENCY_VERDICT_REASONS.map((reason, index) => [reason, index]));

/** The verdict a reason calls for on its own. */
export function reasonVerdict(
  reason: DependencyVerdictReason,
  change: Pick<DependencyVerdictInput, "direct">,
): DependencyVerdictKind {
  switch (reason) {
    case "malware_confirmed":
    case "integrity_mismatch":
      return "block";
    case "non_registry_source":
      return change.direct ? "warn" : "block";
    case "malware_suspected":
    case "evidence_unknown":
    case "min_age":
      return "wait";
    case "private_registry_source":
    case "vulnerability_introduced":
    case "install_script_added":
    case "trust_downgrade":
    case "maintainer_changed":
    case "possible_typosquat":
      return "warn";
    default:
      throw new RangeError("unknown dependency verdict reason");
  }
}

function checkInput(change: DependencyVerdictInput): void {
  if ((change.kind === "new") !== (change.previousVersion === null))
    throw new RangeError("exactly a changed version names the version it replaces");
  if (change.previousVersion === change.version)
    throw new RangeError("a changed version differs from the version it replaces");
}

function checkPolicy(policy: DependencyVerdictPolicy): void {
  if (
    !Number.isSafeInteger(policy.minimumAgeMs) ||
    policy.minimumAgeMs < PLATFORM_DEPENDENCY_POLICY.minimumAgeMs
  )
    throw new RangeError("the minimum age cannot be lowered below the platform floor");
}

interface Judged {
  readonly reasons: Set<DependencyVerdictReason>;
  ageClearsAt: Date | null;
}

function judgeRegistry(
  change: DependencyVerdictInput,
  registry: DependencyEvidence["registry"],
  judged: Judged,
  now: Date,
  policy: DependencyVerdictPolicy,
): void {
  if (registry.status === "unavailable" || registry.current === null) {
    judged.reasons.add("evidence_unknown");
    return;
  }
  const { current, previous } = registry;
  if (
    change.integrity !== null &&
    current.integrity !== null &&
    current.integrity !== change.integrity
  )
    judged.reasons.add("integrity_mismatch");
  const published = current.publishedAt?.getTime();
  if (published === undefined || !Number.isFinite(published)) {
    judged.reasons.add("evidence_unknown");
  } else {
    // A future publication time is young until its minimum age after that time.
    const clears = published + policy.minimumAgeMs;
    if (now.getTime() < clears) {
      judged.reasons.add("min_age");
      judged.ageClearsAt = new Date(clears);
    }
  }
  // Warn-only signals rest on the new version's verified facts: a missing fact of it never raises
  // one, and a previous version not shown to run install scripts counts as not running them.
  if (current.hasInstallScripts === true && previous?.hasInstallScripts !== true)
    judged.reasons.add("install_script_added");
  if (change.kind === "changed" && previous?.attested === true && current.attested !== true)
    judged.reasons.add("trust_downgrade");
  if (
    current.publishingPath !== undefined &&
    detectPublishingPath(current.publishingPath.current, current.publishingPath.history).length > 0
  )
    judged.reasons.add("trust_downgrade");
  if (
    change.kind === "changed" &&
    previous !== null &&
    current.publisherHash !== null &&
    previous.publisherHash !== null &&
    current.publisherHash !== previous.publisherHash
  )
    judged.reasons.add("maintainer_changed");
}

function judge(
  change: DependencyVerdictInput,
  evidence: DependencyEvidence,
  popular: PopularPackageIndex | null,
  now: Date,
  policy: DependencyVerdictPolicy,
): DependencyVerdict {
  checkInput(change);
  const judged: Judged = { reasons: new Set(), ageClearsAt: null };
  for (const tier of evidence.holds) {
    if (tier === "confirmed") judged.reasons.add("malware_confirmed");
    else if (tier === "suspected") judged.reasons.add("malware_suspected");
    else judged.reasons.add("evidence_unknown");
  }
  if (evidence.introducedAdvisories.length > 0) judged.reasons.add("vulnerability_introduced");
  // Public-registry evidence describes only versions the public registry serves.
  if (change.source === "exotic") judged.reasons.add("non_registry_source");
  else if (change.source === "private_registry") judged.reasons.add("private_registry_source");
  else judgeRegistry(change, evidence.registry, judged, now, policy);
  if (
    popular !== null &&
    change.kind === "new" &&
    change.direct &&
    typosquatTarget(change.name, popular) !== null
  )
    judged.reasons.add("possible_typosquat");
  const reasons = [...judged.reasons].toSorted(
    (a, b) => REASON_ORDER.get(a)! - REASON_ORDER.get(b)!,
  );
  let verdict: DependencyVerdictKind = "allow";
  for (const reason of reasons) {
    const kind = reasonVerdict(reason, change);
    if (SEVERITY.get(kind)! > SEVERITY.get(verdict)!) verdict = kind;
  }
  const waitsOnAgeOnly =
    verdict === "wait" &&
    reasons.every((reason) => reasonVerdict(reason, change) !== "wait" || reason === "min_age");
  return {
    ecosystem: change.ecosystem,
    name: change.name,
    version: change.version,
    verdict,
    reasons,
    waitUntil: waitsOnAgeOnly ? judged.ageClearsAt : null,
  };
}

/**
 * Judges every change against its evidence. Errors: RangeError when the evidence is not aligned
 * with the changes, a change is malformed, or the policy is below the platform floor.
 */
export function evaluateDependencyChanges(
  request: DependencyVerdictRequest,
): DependencyVerdictResult {
  const policy = request.policy ?? PLATFORM_DEPENDENCY_POLICY;
  checkPolicy(policy);
  if (request.evidence.length !== request.changes.length)
    throw new RangeError("evidence must be aligned with the changes");
  if (!Number.isFinite(request.now.getTime())) throw new RangeError("invalid evaluation time");
  const verdicts = request.changes.map((change, index) =>
    judge(change, request.evidence[index]!, request.popular, request.now, policy),
  );
  const typosquatApplies = request.changes.some((change) => change.kind === "new" && change.direct);
  return {
    verdicts,
    unavailableSignals: request.popular === null && typosquatApplies ? ["possible_typosquat"] : [],
  };
}

/**
 * The change in the contracts evidence shape that registry fact readers take: a new package is an
 * addition, a changed one an upgrade or downgrade. Null when the two versions differ only in build
 * metadata, which SemVer orders equal.
 */
export function toRegistryChange(change: DependencyVerdictInput): DependencyChange | null {
  checkInput(change);
  const paths = [[change.name]];
  if (change.previousVersion === null)
    return dependencyChangeSchema.parse({
      name: change.name,
      from: null,
      to: change.version,
      change: "added",
      bump: null,
      is_direct: change.direct,
      is_dev: false,
      paths,
      base_versions: [],
    });
  const classified = classifyVersionChange(change.previousVersion, change.version);
  if (classified === null) return null;
  return dependencyChangeSchema.parse({
    name: change.name,
    from: change.previousVersion,
    to: change.version,
    change: classified.direction,
    bump: classified.bump,
    is_direct: change.direct,
    is_dev: false,
    paths,
  });
}
