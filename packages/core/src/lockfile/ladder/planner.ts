import {
  LADDER,
  ladderRungsForPlan,
  type AdvisoryId,
  type MergeBlockReason,
  type PackageName,
  type PackageVersion,
} from "@kovo/contracts";
import semver from "semver";

import type { ResolvedPackageNode } from "../types.js";
import { compareStrings } from "../util.js";
import { relockCommand } from "./commands.js";
import { LadderContext, type Technique, type TechniqueResult } from "./context.js";
import { removal, rollback } from "./rung-malicious.js";
import { majorUpgrade } from "./rung-major.js";
import { narrowOverride } from "./rung-override.js";
import { parentUpdate } from "./rung-parent.js";
import { directUpdate, lockfileUpdate } from "./rung-updates.js";
import {
  MAJOR_RUNG,
  PLANNED_RUNGS,
  ladderOrder,
  type LadderInput,
  type LadderPlan,
  type LadderResult,
  type LadderSkip,
  type LockfileExpectation,
  type ManifestEdit,
  type PlannedRung,
  type PlanRung,
  type PmCommand,
  type RollbackEvidence,
} from "./types.js";

// The ladder planner (SPEC "Fix ladder and agent"): for a targeted package and its affected
// instances, ordered package-manager-specific edit plans for rungs 1–5 and M. A plan at rung r
// clears every targeted instance using techniques of rung ≤ r ("Stop at the smallest candidate
// that clears all targeted affected instances"); a rung whose plan would equal a lower rung's is
// not repeated. "Free supports rungs 1–5 and deterministic M": the plan filter is contracts'
// `ladderRungsForPlan`.

type UpgradeRung = "1" | "2" | "3" | "4" | "5";
const UPGRADE_RUNGS: readonly UpgradeRung[] = ["1", "2", "3", "4", "5"];

function techniqueFor(
  ctx: LadderContext,
  node: ResolvedPackageNode,
  rung: UpgradeRung,
): TechniqueResult {
  switch (rung) {
    case "1":
      return lockfileUpdate(ctx, node);
    case "2":
    case "3":
      return directUpdate(ctx, node, rung);
    case "4":
      return parentUpdate(ctx, node);
    case "5":
      return narrowOverride(ctx, node);
    default: {
      const unreachable: never = rung;
      throw new RangeError(`unknown rung ${String(unreachable)}`);
    }
  }
}

function commandId(command: PmCommand): string {
  return `${command.executable}\u0000${command.args.join("\u0000")}`;
}

function uniqueCommands(commands: readonly PmCommand[]): PmCommand[] {
  const seen = new Set<string>();
  return commands.filter((command) => {
    const id = commandId(command);
    if (seen.has(id)) return false;
    seen.add(id);
    return true;
  });
}

/** Merges edits; two different values at one pointer cannot be combined. */
function mergeEdits(edits: readonly ManifestEdit[]): ManifestEdit[] | null {
  const byPointer = new Map<string, ManifestEdit>();
  for (const edit of edits) {
    const existing = byPointer.get(edit.pointer);
    if (existing === undefined) {
      byPointer.set(edit.pointer, edit);
      continue;
    }
    const same =
      existing.op === edit.op &&
      (existing.op === "remove" || (edit.op === "set" && existing.value === edit.value));
    if (!same) return null;
  }
  return [...byPointer.values()].toSorted((a, b) => compareStrings(a.pointer, b.pointer));
}

function isLockfileUpdate(technique: Technique): boolean {
  return technique.kind === "lockfile_update";
}

function reviewReasonsFor(rung: PlanRung, usesOverride: boolean): MergeBlockReason[] {
  const reasons: MergeBlockReason[] = [];
  if (!LADDER[rung].autoMergeEligible) reasons.push("ladder_rung_review_only");
  if (usesOverride) reasons.push("override_used");
  if (rung === "M") reasons.push("removal_or_rollback");
  if (rung === MAJOR_RUNG) reasons.push("major_update");
  return reasons;
}

/** Builds one plan from per-instance techniques (all at or below `rung`). */
function combine(
  ctx: LadderContext,
  rung: PlanRung,
  techniques: readonly Technique[],
  evidence: RollbackEvidence | null,
): LadderPlan | "conflicting_edits" {
  const applyEdits = mergeEdits(
    techniques.flatMap((technique) => [
      ...technique.applyEdits,
      ...(ctx.pm === "yarn" ? technique.writtenEdits : []),
    ]),
  );
  const writtenEdits = mergeEdits(
    ctx.pm === "yarn" ? [] : techniques.flatMap((technique) => technique.writtenEdits),
  );
  if (applyEdits === null || writtenEdits === null) return "conflicting_edits";
  const expectedManifest = mergeEdits([...applyEdits, ...writtenEdits]);
  if (expectedManifest === null) return "conflicting_edits";

  // Trusted code applies the edits, the re-lock picks them up, then dependents of shared
  // instances move, then direct pins, then lockfile-only updates.
  const commands = uniqueCommands([
    ...(applyEdits.length > 0 ? [relockCommand(ctx.pm)] : []),
    ...techniques.flatMap((technique) => technique.preCommands),
    ...techniques.filter((t) => !isLockfileUpdate(t)).flatMap((technique) => technique.commands),
    ...techniques.filter(isLockfileUpdate).flatMap((technique) => technique.commands),
  ]);

  const target = ctx.input.target;
  const pins = new Map(
    techniques.flatMap((technique) => technique.pins).map((pin) => [pin.alias, pin] as const),
  );
  const unaffected = ctx.versionsOf(target.name).filter((version) => !ctx.affected.has(version));
  const expectations: LockfileExpectation[] = [];
  const removalPlan = techniques.some((technique) => technique.kind === "removal");
  if (removalPlan) {
    expectations.push({ kind: "package_absent", name: target.name });
  } else {
    for (const version of [...new Set(target.affectedVersions)].toSorted(semver.compare)) {
      expectations.push({ kind: "version_absent", name: target.name, version });
    }
    expectations.push({
      kind: "versions_within",
      name: target.name,
      allowed: [...new Set([...ctx.safe, ...unaffected])].toSorted(semver.compare),
    });
  }
  for (const pin of [...pins.values()].toSorted((a, b) => compareStrings(a.alias, b.alias))) {
    expectations.push({
      kind: "direct_resolves_to",
      alias: pin.alias,
      name: pin.name,
      version: pin.version,
    });
  }

  const usesOverride = techniques.some(
    (technique) =>
      technique.kind === "override" || technique.applyEdits.some((edit) => edit.op === "set"),
  );
  const top = techniques.find((technique) => technique.rung === rung) ?? techniques[0];
  const anchors = [
    ...new Set<PackageName>(techniques.flatMap((technique) => technique.anchors)),
  ].toSorted();
  const allowedManifestPointers = expectedManifest.map((edit) => edit.pointer);
  return {
    rung,
    kind: top?.kind ?? "lockfile_update",
    packageManager: ctx.pm,
    target: target.name,
    steps: techniques.map((technique) => ({
      rung: technique.rung,
      kind: technique.kind,
      from: technique.from,
      to: technique.to,
      via: technique.via,
    })),
    manifestEdits: applyEdits,
    expectedManifest,
    allowedManifestPointers,
    allowedFiles:
      allowedManifestPointers.length > 0 ? ["package.json", ctx.lockfileName] : [ctx.lockfileName],
    commands,
    expectations,
    anchors,
    // Planning cannot prove the final graph. Publication/merge assess qualifying overrides
    // from actual verified manifests and whole-graph evidence (owner decision 2026-10-04).
    autoMergeEligible: LADDER[rung].autoMergeEligible && !usesOverride,
    reviewReasons: reviewReasonsFor(rung, usesOverride),
    evidence,
  };
}

/**
 * The ladder's order (`LADDER_ORDER`): for a malicious package the evidenced rollback (M, both
 * plans) comes before a Plus-only major upgrade.
 */
function rungOrder(rung: PlanRung): number {
  return ladderOrder(rung);
}

/**
 * Plans the ladder for one target. Returns every distinct candidate plan in ladder order, and for
 * each rung without a plan the reason (with the affected version that blocked it).
 */
export function planLadder(input: LadderInput): LadderResult {
  const ctx = new LadderContext(input);
  const permitted = new Set<string>(ladderRungsForPlan(input.plan));
  const instances = input.graph.packages.filter(
    (node) => node.name === input.target.name && ctx.affected.has(node.version),
  );
  const plans: LadderPlan[] = [];
  const skipped: LadderSkip[] = [];
  const rungs: PlannedRung[] =
    input.target.kind === "malicious" ? [...PLANNED_RUNGS] : [...UPGRADE_RUNGS];

  if (instances.length === 0) {
    return {
      plans,
      skipped: rungs.map((rung) => ({
        rung,
        reason: "target_not_in_graph" as const,
        version: null,
      })),
    };
  }

  const cache = new Map<string, TechniqueResult>();
  const technique = (node: ResolvedPackageNode, rung: UpgradeRung): TechniqueResult => {
    const id = `${node.key}\u0000${rung}`;
    const cached = cache.get(id);
    if (cached !== undefined) return cached;
    const result = techniqueFor(ctx, node, rung);
    cache.set(id, result);
    return result;
  };

  for (const rung of UPGRADE_RUNGS) {
    if (!permitted.has(rung)) {
      skipped.push({ rung, reason: "plan_excludes_rung", version: null });
      continue;
    }
    // Each instance uses this rung's technique when it applies, otherwise the smallest lower one
    // that works, so every rung is a distinct escalation of the previous plan.
    const chosen: Technique[] = [];
    let blocked: LadderSkip | null = null;
    let firstFailure: LadderSkip | null = null;
    for (const node of instances) {
      const own = technique(node, rung);
      if (own.ok) {
        chosen.push(own.technique);
        continue;
      }
      firstFailure ??= { rung, reason: own.reason, version: node.version };
      const lower = UPGRADE_RUNGS.slice(0, UPGRADE_RUNGS.indexOf(rung))
        .map((candidate) => technique(node, candidate))
        .find((result) => result.ok);
      if (lower === undefined || !lower.ok) {
        blocked = { rung, reason: own.reason, version: node.version };
        break;
      }
      chosen.push(lower.technique);
    }
    if (blocked !== null) {
      skipped.push(blocked);
      continue;
    }
    // No instance uses this rung: the plan would repeat a lower one.
    if (!chosen.some((found) => found.rung === rung)) {
      if (firstFailure !== null) skipped.push(firstFailure);
      continue;
    }
    const plan = combine(ctx, rung, chosen, null);
    if (plan === "conflicting_edits") skipped.push({ rung, reason: plan, version: null });
    else plans.push(plan);
  }

  if (input.target.kind === "malicious") {
    if (permitted.has("M")) {
      const outcome = planMalicious(ctx, instances, input.target.advisoryIds);
      if (outcome.kind === "plan") plans.push(outcome.plan);
      else skipped.push(outcome.skip);
    } else {
      skipped.push({ rung: "M", reason: "plan_excludes_rung", version: null });
    }
  }

  return { plans: plans.toSorted((a, b) => rungOrder(a.rung) - rungOrder(b.rung)), skipped };
}

/**
 * Plans rung 6's deterministic major upgrade (Plus only, `ladderRungsForPlan`): every direct
 * affected instance moves to the smallest safe version of a newer major line, and every other
 * instance uses the smallest lower technique that works (as each rung of `planLadder` escalates the
 * previous one). No plan when no instance can take a major step or one instance cannot be cleared
 * at all; the transitive-only case is the agent's.
 */
export function planMajorUpgrade(input: LadderInput): LadderResult {
  const ctx = new LadderContext(input);
  if (!ladderRungsForPlan(input.plan).includes(MAJOR_RUNG)) {
    return {
      plans: [],
      skipped: [{ rung: MAJOR_RUNG, reason: "plan_excludes_rung", version: null }],
    };
  }
  const instances = input.graph.packages.filter(
    (node) => node.name === input.target.name && ctx.affected.has(node.version),
  );
  if (instances.length === 0) {
    return {
      plans: [],
      skipped: [{ rung: MAJOR_RUNG, reason: "target_not_in_graph", version: null }],
    };
  }
  const chosen: Technique[] = [];
  let firstFailure: LadderSkip | null = null;
  for (const node of instances) {
    const own = majorUpgrade(ctx, node);
    if (own.ok) {
      chosen.push(own.technique);
      continue;
    }
    firstFailure ??= { rung: MAJOR_RUNG, reason: own.reason, version: node.version };
    const lower = UPGRADE_RUNGS.map((rung) => techniqueFor(ctx, node, rung)).find(
      (result) => result.ok,
    );
    if (lower === undefined || !lower.ok) {
      return {
        plans: [],
        skipped: [{ rung: MAJOR_RUNG, reason: own.reason, version: node.version }],
      };
    }
    chosen.push(lower.technique);
  }
  if (!chosen.some((technique) => technique.rung === MAJOR_RUNG)) {
    return { plans: [], skipped: firstFailure === null ? [] : [firstFailure] };
  }
  const plan = combine(ctx, MAJOR_RUNG, chosen, null);
  return plan === "conflicting_edits"
    ? { plans: [], skipped: [{ rung: MAJOR_RUNG, reason: plan, version: null }] }
    : { plans: [plan], skipped: [] };
}

type MaliciousOutcome =
  | { readonly kind: "plan"; readonly plan: LadderPlan }
  | { readonly kind: "skip"; readonly skip: LadderSkip };

function combined(
  ctx: LadderContext,
  techniques: readonly Technique[],
  evidence: RollbackEvidence,
): MaliciousOutcome {
  const plan = combine(ctx, "M", techniques, evidence);
  return plan === "conflicting_edits"
    ? { kind: "skip", skip: { rung: "M", reason: plan, version: null } }
    : { kind: "plan", plan };
}

/**
 * Rung M: roll every malicious instance back to an evidenced safe version; when no safe version
 * is known at all, remove the package if that is feasible; otherwise nothing (a human decides).
 */
function planMalicious(
  ctx: LadderContext,
  instances: readonly ResolvedPackageNode[],
  advisoryIds: readonly AdvisoryId[],
): MaliciousOutcome {
  const techniques: Technique[] = [];
  const versions: { from: PackageVersion; to: PackageVersion }[] = [];
  let failed: LadderSkip | null = null;
  for (const node of instances) {
    const result = rollback(ctx, node);
    if (result.ok && result.technique.to !== null) {
      techniques.push(result.technique);
      versions.push({ from: result.technique.from, to: result.technique.to });
    } else {
      failed ??= {
        rung: "M",
        reason: result.ok ? "no_rollback_version" : result.reason,
        version: node.version,
      };
    }
  }
  if (failed === null)
    return combined(ctx, techniques, { kind: "rollback", versions, advisoryIds });
  // A safe version is known but not every instance can roll back to one: the upgrade rungs cover
  // newer safe versions, and removal is only for "no safe version is known".
  if (ctx.safe.length > 0) return { kind: "skip", skip: failed };

  const removed = removal(ctx, instances);
  if (!removed.ok)
    return { kind: "skip", skip: { rung: "M", reason: removed.reason, version: null } };
  const removals: Technique[] = [];
  for (const node of instances) removals.push({ ...removed.technique, from: node.version });
  return combined(ctx, removals, { kind: "removal", reason: "no_known_safe_version", advisoryIds });
}
