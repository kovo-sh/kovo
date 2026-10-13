import type { MergeBlockReason } from "@kovo/contracts";

import { checkManifestAllowlist, type ManifestViolation } from "../../manifest/allowlist.js";
import { isJsonObject, type JsonValue } from "../../manifest/bounded-json.js";
import { getAtPointer, removeAtPointer, setAtPointer } from "../../manifest/json-pointer.js";
import {
  assessChurn,
  assessDiff,
  diffGraphs,
  DEFAULT_MAX_CHANGED_PACKAGES,
  type ChurnAssessment,
  type DiffAssessment,
  type GraphDiff,
} from "../diff.js";
import { packageKey, type DependencyGraph } from "../types.js";
import type { LadderPlan, LockfileExpectation, ManifestEdit } from "./types.js";

// Trusted checks of what running a plan actually produced (BUILD_PLAN items 23–24: "rejecting
// churn"; "trusted checks (allowed files, manifest pointer allowlist, …)"). Everything is computed
// from the base and patched graphs and manifests the control plane parses itself.

export interface ExpectationViolation {
  readonly expectation: LockfileExpectation;
  /** The versions (or resolved package) found instead, never other content. */
  readonly found: readonly string[];
}

export interface LadderOutcome {
  /** Every expectation holds, no locked integrity changed and the change is free of churn. */
  readonly satisfied: boolean;
  readonly violations: readonly ExpectationViolation[];
  /**
   * Package/versions both lockfiles resolve whose integrity or tarball URL the patch changed
   * (SPEC provenance: "Integrity mismatch → Reject artifact/fix").
   */
  readonly integrityChanges: GraphDiff["integrityChanges"];
  readonly diff: GraphDiff;
  readonly assessment: DiffAssessment;
  readonly churn: ChurnAssessment;
  /** The plan's expected eligibility, confirmed by the actual graph: patch/minor only, no churn. */
  readonly autoMergeEligible: boolean;
  /** decideMerge gate 3 reasons: the plan's review reasons plus what the diff shows. */
  readonly mergeBlockReasons: readonly MergeBlockReason[];
}

function checkExpectation(
  expectation: LockfileExpectation,
  after: DependencyGraph,
): ExpectationViolation | null {
  const versions = (name: string): string[] =>
    after.packages.filter((node) => node.name === name).map((node) => node.version);
  switch (expectation.kind) {
    case "version_absent": {
      const present = versions(expectation.name).filter(
        (version) => version === expectation.version,
      );
      return present.length > 0 ? { expectation, found: present } : null;
    }
    case "versions_within": {
      const allowed = new Set<string>(expectation.allowed);
      const outside = versions(expectation.name).filter((version) => !allowed.has(version));
      return outside.length > 0 ? { expectation, found: outside } : null;
    }
    case "direct_resolves_to": {
      const wanted = packageKey(expectation.name, expectation.version);
      const targets = after.direct
        .filter((dependency) => dependency.alias === expectation.alias)
        .map((dependency) => dependency.target ?? "unresolved");
      return targets.length > 0 && targets.every((target) => target === wanted)
        ? null
        : { expectation, found: targets };
    }
    case "package_absent": {
      const present = versions(expectation.name);
      return present.length > 0 ? { expectation, found: present } : null;
    }
    default: {
      const unreachable: never = expectation;
      throw new RangeError(`unknown expectation ${JSON.stringify(unreachable)}`);
    }
  }
}

/** What an outcome check reads of a plan (a planned rung, rung 6, or an agent candidate's checks). */
export type OutcomePlan = Pick<
  LadderPlan,
  "expectations" | "anchors" | "autoMergeEligible" | "reviewReasons"
>;

/** What the manifest check reads of a plan. */
export type ManifestPlan = Pick<LadderPlan, "allowedManifestPointers" | "expectedManifest">;

/**
 * Checks a patched lockfile against a plan: the plan's expectations, unchanged integrity for every
 * package/version both lockfiles lock, the whole-graph SemVer classification and the churn bound.
 * `autoMergeEligible` is true only when the plan expected eligibility and the actual diff is
 * dependency-only patch/minor without churn.
 */
export function checkLadderOutcome(
  plan: OutcomePlan,
  before: DependencyGraph,
  after: DependencyGraph,
  maxChangedPackages: number = DEFAULT_MAX_CHANGED_PACKAGES,
): LadderOutcome {
  const violations = plan.expectations
    .map((expectation) => checkExpectation(expectation, after))
    .filter((violation): violation is ExpectationViolation => violation !== null);
  const diff = diffGraphs(before, after);
  const assessment = assessDiff(diff);
  const churn = assessChurn(before, after, diff, { anchors: plan.anchors, maxChangedPackages });
  const integrityChanges = diff.integrityChanges;
  const satisfied = violations.length === 0 && integrityChanges.length === 0 && !churn.rejected;
  const autoMergeEligible = satisfied && plan.autoMergeEligible && assessment.patchMinorOnly;
  const mergeBlockReasons: MergeBlockReason[] = [
    ...new Set([
      ...plan.reviewReasons,
      ...assessment.mergeBlockReasons,
      ...(integrityChanges.length > 0 ? (["integrity_mismatch"] as const) : []),
    ]),
  ];
  return {
    satisfied,
    violations,
    integrityChanges,
    diff,
    assessment,
    churn,
    autoMergeEligible,
    mergeBlockReasons,
  };
}

export interface PlannedManifestCheck {
  /** Allowlist violations (fields the plan does not allow). */
  readonly violations: readonly ManifestViolation[];
  /** Planned edits the patched package.json does not carry exactly. */
  readonly missing: readonly ManifestEdit[];
}

/**
 * Checks the patched package.json against a plan: only the plan's pointers changed, and each one
 * holds exactly the planned value (or is gone, for removals).
 */
export function checkPlannedManifest(
  plan: ManifestPlan,
  before: JsonValue,
  after: JsonValue,
): PlannedManifestCheck {
  const { violations } = checkManifestAllowlist(before, after, plan.allowedManifestPointers);
  const missing = plan.expectedManifest.filter((edit) => {
    const value = getAtPointer(after, edit.pointer);
    return edit.op === "remove" ? value !== undefined : value !== edit.value;
  });
  return { violations, missing };
}

/** Applies a plan's trusted edits to a parsed package.json (for the runner, before commands). */
export function applyManifestEdits(document: JsonValue, edits: readonly ManifestEdit[]): JsonValue {
  if (!isJsonObject(document)) throw new RangeError("package.json is not an object");
  let current: JsonValue = document;
  for (const edit of edits) {
    current =
      edit.op === "set"
        ? setAtPointer(current, edit.pointer, edit.value)
        : removeAtPointer(current, edit.pointer);
  }
  return current;
}
