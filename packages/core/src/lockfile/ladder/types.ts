import type {
  AdvisoryId,
  LadderRung,
  MergeBlockReason,
  PackageManager,
  PackageName,
  PackageVersion,
  Plan,
} from "@kovo/contracts";

import type { PackageManifest } from "../../manifest/package-json.js";
import type { LockfileName } from "../parse.js";
import type { DependencyGraph } from "../types.js";
import type { RegistryPackage } from "./registry.js";

// Ladder plans are data (BUILD_PLAN item 7): what to edit in package.json (JSON pointers), which
// package-manager commands to run (always with lifecycle scripts disabled), what the resulting
// lockfile must look like, and whether the result is expected to be auto-merge eligible. Sandbox A
// executes them (BUILD_PLAN item 23); trusted code checks the outcome with `checkLadderOutcome`.

/** The rungs this planner produces: SPEC rungs 1–5 and M (6 and 7 are major upgrades). */
export const PLANNED_RUNGS = [
  "1",
  "2",
  "3",
  "4",
  "5",
  "M",
] as const satisfies readonly LadderRung[];
export type PlannedRung = (typeof PLANNED_RUNGS)[number];

/**
 * SPEC rung 6, "Major upgrade, optionally agent-assisted on Plus": `planMajorUpgrade` plans its
 * deterministic part (a direct dependency moved to a safe version on a newer major line); agent
 * assistance and rung 7 are the control plane's (BUILD_PLAN items 23 and 26).
 */
export const MAJOR_RUNG = "6" as const satisfies LadderRung;

/** Every rung a plan, step or skip of this module can carry: the planned rungs and rung 6. */
export type PlanRung = PlannedRung | typeof MAJOR_RUNG;

/**
 * The order candidates are tried in, every rung once: the planned rungs (M after 5, so an evidenced
 * rollback on either plan comes before a Plus-only major upgrade), rung 6, then the agent's rung 7.
 * The planner sorts its plans by it; the control plane's generation runs candidates in it and
 * escalates past a rung that failed verification by it.
 */
export const LADDER_ORDER = [
  ...PLANNED_RUNGS,
  MAJOR_RUNG,
  "7",
] as const satisfies readonly LadderRung[];

/** A rung's position in {@link LADDER_ORDER} (smaller runs first). */
export function ladderOrder(rung: LadderRung): number {
  return (LADDER_ORDER as readonly LadderRung[]).indexOf(rung);
}

export const LADDER_PLAN_KINDS = [
  "lockfile_update", // rung 1
  "direct_update", // rungs 2–3
  "parent_update", // rung 4
  "override", // rung 5
  "rollback", // rung M with an evidenced safe older version
  "removal", // rung M without one
] as const;
export type LadderPlanKind = (typeof LADDER_PLAN_KINDS)[number];

/** An upgrade target, or a malicious package to roll back or remove. */
export type LadderTarget =
  | {
      readonly kind: "upgrade";
      readonly name: PackageName;
      /** The affected resolved versions this fix targets (its targeted instances). */
      readonly affectedVersions: readonly PackageVersion[];
      /**
       * Every known version that clears all affected ranges, introduces no P0/P1/malicious
       * finding and, for a P1 fix, is at least 24 hours old (or already locked): core/advisory
       * `resolveTarget`'s `eligibleVersions` (`ladderTargetFor`), not only the minimal target.
       * Package managers resolve to the newest version a range admits, and the result must stay
       * inside this set; a newer version still in its cooldown is outside it.
       */
      readonly safeVersions: readonly PackageVersion[];
    }
  | {
      readonly kind: "malicious";
      readonly name: PackageName;
      readonly affectedVersions: readonly PackageVersion[];
      /**
       * Versions evidenced outside every known malicious/affected range, above or below the
       * malicious ones (`resolveTarget`'s `eligibleVersions`; may be empty: "If no safe version
       * is known … prepare a reviewed removal only when feasible").
       */
      readonly safeVersions: readonly PackageVersion[];
      /** The advisories whose ranges the safe versions were checked against. */
      readonly advisoryIds: readonly AdvisoryId[];
    };

export interface LadderInput {
  /** Exact selected manager release. Legacy callers omit it for the pnpm 9/10 model. */
  readonly pmVersion?: string;
  readonly plan: Plan;
  readonly graph: DependencyGraph;
  readonly manifest: PackageManifest;
  readonly target: LadderTarget;
  /** Registry metadata for the target, its parents and candidate ancestor versions. */
  readonly registry: readonly RegistryPackage[];
}

/** A package.json edit at an RFC 6901 pointer. */
export type ManifestEdit =
  | { readonly op: "set"; readonly pointer: string; readonly value: string }
  | { readonly op: "remove"; readonly pointer: string };

/** A package-manager invocation; `args` never contain a shell and always disable scripts. */
export interface PmCommand {
  readonly executable: PackageManager;
  readonly args: readonly string[];
}

/** What the patched lockfile must satisfy. */
export type LockfileExpectation =
  /** The affected version no longer resolves anywhere in the graph. */
  | {
      readonly kind: "version_absent";
      readonly name: PackageName;
      readonly version: PackageVersion;
    }
  /** Every remaining version of the package is one of these. */
  | {
      readonly kind: "versions_within";
      readonly name: PackageName;
      readonly allowed: readonly PackageVersion[];
    }
  /** The direct dependency declared as `alias` resolves to exactly this package/version. */
  | {
      readonly kind: "direct_resolves_to";
      readonly alias: PackageName;
      readonly name: PackageName;
      readonly version: PackageVersion;
    }
  /** No version of the package remains (a removal). */
  | { readonly kind: "package_absent"; readonly name: PackageName };

/** How one targeted instance is cleared by a plan. */
export interface LadderStep {
  readonly rung: PlanRung;
  readonly kind: LadderPlanKind;
  /** The affected version this step clears. */
  readonly from: PackageVersion;
  /** The version the step aims for (the smallest acceptable one); null for a removal. */
  readonly to: PackageVersion | null;
  /** For parent updates: the direct ancestors moved and their new versions. */
  readonly via: readonly {
    readonly name: PackageName;
    readonly from: PackageVersion;
    readonly to: PackageVersion;
  }[];
}

export type RollbackEvidence =
  | {
      readonly kind: "rollback";
      /** Each affected version and the evidenced version it rolls back to. */
      readonly versions: readonly { readonly from: PackageVersion; readonly to: PackageVersion }[];
      readonly advisoryIds: readonly AdvisoryId[];
    }
  | {
      readonly kind: "removal";
      /** No version outside every known malicious/affected range is known. */
      readonly reason: "no_known_safe_version";
      readonly advisoryIds: readonly AdvisoryId[];
    };

export interface LadderPlan {
  readonly rung: PlanRung;
  readonly kind: LadderPlanKind;
  readonly packageManager: PackageManager;
  readonly target: PackageName;
  readonly steps: readonly LadderStep[];
  /** package.json edits trusted code applies before running `commands` (overrides, removals). */
  readonly manifestEdits: readonly ManifestEdit[];
  /**
   * Every package.json change the fix must end with: `manifestEdits` plus the specs the package
   * manager rewrites while pinning direct dependencies.
   */
  readonly expectedManifest: readonly ManifestEdit[];
  /** package.json pointers the fix may change (the manifest allowlist for this plan). */
  readonly allowedManifestPointers: readonly string[];
  /** Repository files the fix may change. */
  readonly allowedFiles: readonly string[];
  readonly commands: readonly PmCommand[];
  readonly expectations: readonly LockfileExpectation[];
  /** Packages the plan means to change: the closure churn is measured against. */
  readonly anchors: readonly PackageName[];
  /** SPEC ladder table: rungs 1–4 eligible after all gates; 5 and M need human review. */
  readonly autoMergeEligible: boolean;
  /** Why the plan needs review regardless of verification (empty when eligible). */
  readonly reviewReasons: readonly MergeBlockReason[];
  readonly evidence: RollbackEvidence | null;
}

export const LADDER_SKIP_REASONS = [
  "plan_excludes_rung", // the account's plan does not permit the rung
  "target_not_in_graph", // no affected version of the target is resolved in the lockfile
  "no_safe_version", // no candidate version was supplied
  "not_transitive", // rungs 1/4/5 only apply to transitive instances
  "not_direct", // rungs 2/3 only apply to direct dependencies
  "name_shared_with_direct", // a direct dependency has the target's name (lockfile-only update would move it)
  "bundled_instance", // shipped inside another package's tarball
  "patched_instance", // modified by a pnpm patch
  "range_unknown", // a dependent's range is neither in the lockfile nor in the registry metadata
  "no_compatible_version", // no safe version is a patch (rung 2) / minor (rungs 1, 3, 4) step within the ranges
  "predicted_version_unsafe", // the version the package manager would pick (newest in range) is not safe
  "ambiguous_declaration", // the dependency is declared in more than one section
  "peer_declaration", // a root peerDependency (pnpm add --save-peer also writes devDependencies)
  "metadata_missing", // registry metadata needed to predict the resolution is missing
  "no_parent_version", // no patch/minor version of the direct ancestor pulls a safe version
  "shared_ancestor", // the ancestor is also required by other packages the update would not move
  "paths_truncated", // not every dependency path is known, so ancestors cannot be enumerated
  "aliased_edge", // a dependent depends on the target through an npm: alias
  "override_storage_unsupported", // pnpm 11+ requires the separately gated protected-YAML writer
  "override_conflict", // package.json already overrides the target or the selector
  "unsafe_package_name", // a name that could be read as a command-line flag
  "no_rollback_version", // no evidenced safe version below the malicious one
  "removal_infeasible", // other packages depend on the malicious package
  "conflicting_edits", // two instances need different values at one pointer
  "no_major_version", // rung 6: no safe version on a newer major line
] as const;
export type LadderSkipReason = (typeof LADDER_SKIP_REASONS)[number];

export interface LadderSkip {
  readonly rung: PlanRung;
  readonly reason: LadderSkipReason;
  /** The affected version that could not be handled, when the reason is per instance. */
  readonly version: PackageVersion | null;
}

export interface LadderResult {
  /** Candidate plans in ladder order; the executor stops at the first that verifies. */
  readonly plans: readonly LadderPlan[];
  /** Why each rung without a plan has none. */
  readonly skipped: readonly LadderSkip[];
}

export type { LockfileName };
