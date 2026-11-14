import { z } from "zod";

import { packageNameSchema } from "./npm.js";
import { gitShaSchema, sha256HexSchema } from "./primitives.js";
import { recipeStepSchema } from "./recipe.js";

// Owner D-674 (#626 comment 6703993855, #7846): just-in-time probes. At onboarding the model
// proposes boot and build probes; when a fix for package P arrives and no accepted probe covers P,
// it proposes 2-5 probes for P against the base commit. Deterministic code accepts a probe only if
// it passes 3/3 on the base and goes red when P is replaced by a throwing stub, within its time
// bound, with no secret and loopback-only network. Accepted probes are cached per repository and
// package, and stored like recipe steps (SPEC never-persist note). The model only proposes; code
// judges. This module is the typed boundary the CI-evidence merge gate (D-674 PR A) consumes:
// `covered(P)` plus pass/fail, as `FixProbeEvidence`.

/** What a probe exercises: the app boots, the app builds, or one dependency package's behaviour. */
export const PROBE_KINDS = ["boot", "build", "package"] as const;
export const probeKindSchema = z.enum(PROBE_KINDS);
export type ProbeKind = z.infer<typeof probeKindSchema>;

/** D-674 bounds, enforced by deterministic code, never by the model. */
export const PROBE_LIMITS = {
  /** Proposals for one package: at least 2, at most 5. */
  minPerPackage: 2,
  maxPerPackage: 5,
  /** Onboarding boot and build probes. */
  maxOnboarding: 4,
  /** Base runs a probe must pass, all of them. */
  baseRuns: 3,
  /** A probe's own time bound (seconds); a slower probe is never accepted. */
  maxTimeoutSec: 300,
  /** Accepted probes cached for one repository (all packages together). */
  maxCachedPerRepo: 200,
} as const;

/**
 * One probe: a recipe step (`source: "agent"`) run after the recipe's install and setup. Its name
 * is Kovo's own (`probe:<kind>:<n>` or `probe:package:<n>`), never model text. `package` names P
 * for a package probe and is null for boot and build probes.
 */
export const probeSchema = z
  .strictObject({
    kind: probeKindSchema,
    package: packageNameSchema.nullable(),
    step: recipeStepSchema.refine((step) => step.source === "agent", {
      error: "a probe is a model proposal",
    }),
  })
  .refine((probe) => (probe.kind === "package") === (probe.package !== null), {
    error: "only a package probe names a package",
  })
  .refine((probe) => probe.step.timeoutSec <= PROBE_LIMITS.maxTimeoutSec, {
    error: "a probe's timeout is above the probe time bound",
  });
export type Probe = z.infer<typeof probeSchema>;

/** A probe deterministic acceptance kept, with the base commit it was accepted against. */
export const acceptedProbeSchema = z.strictObject({
  probe: probeSchema,
  acceptedSha: gitShaSchema,
  acceptedAt: z.coerce.date(),
});
export type AcceptedProbe = z.infer<typeof acceptedProbeSchema>;

/** Why a candidate probe was not accepted (stable reason codes; no output or source). */
export const PROBE_REJECTION_REASONS = [
  /** Not a valid recipe step, a duplicate, or over the per-package count. */
  "invalid",
  "contains_credential",
  /** An install, toolchain change, or a command Sandbox B cannot run. */
  "install_command",
  "unavailable_command",
  /** A non-loopback URL or host in the command: probes get loopback network only. */
  "network_not_allowlisted",
  /** The wrong kind for the request (a package probe at onboarding, or for another package). */
  "wrong_kind",
  "timeout_above_bound",
  /** Not 3/3 green on the base commit (or slower than its bound there). */
  "base_not_green",
  /** Still green with P replaced by a throwing stub: it does not exercise P. */
  "stub_not_red",
  /** The throwing stub could not be applied (P not installed under node_modules). */
  "stub_not_applied",
  /** The base itself did not install or set up, so the probe could not be judged. */
  "base_unavailable",
] as const;
export const probeRejectionReasonSchema = z.enum(PROBE_REJECTION_REASONS);
export type ProbeRejectionReason = z.infer<typeof probeRejectionReasonSchema>;

/** Why a fix carries no probe coverage for P (stable reason codes). */
export const PROBE_UNCOVERED_REASONS = [
  /** No accepted probe for P and none could be proposed (no AI entitlement, model unavailable). */
  "no_proposal",
  /** Proposals came back, but deterministic acceptance kept none. */
  "none_accepted",
  /** Accepted probes for P all failed on the fresh base control, so none counts. */
  "red_on_base",
  /** The repository has no recipe to install and run probes with. */
  "no_recipe",
  /** The probe runs could not start or complete (sandbox, reservation). */
  "runs_unavailable",
] as const;
export const probeUncoveredReasonSchema = z.enum(PROBE_UNCOVERED_REASONS);
export type ProbeUncoveredReason = z.infer<typeof probeUncoveredReasonSchema>;

/**
 * Owner D-748 (6), R1: the verification subject a fix's probes ran on. The base commit, plus the
 * staged patch's SHA-256 (a fix not yet published) or the published head (a re-verified head):
 * exactly one of the two.
 */
export const probeSubjectSchema = z
  .strictObject({
    baseSha: gitShaSchema,
    patchSha256: sha256HexSchema.nullable(),
    headSha: gitShaSchema.nullable(),
  })
  .refine((subject) => (subject.patchSha256 === null) !== (subject.headSha === null), {
    error: "a probe subject is a staged patch or a published head",
  });
export type ProbeSubject = z.infer<typeof probeSubjectSchema>;

const probeTallySchema = z.strictObject({
  /** Probes that were green on the fresh base control, so they count. */
  counted: z.int().nonnegative(),
  /** Counted probes that were not green on the fix. */
  failed: z.int().nonnegative(),
});

/**
 * One fix's probe evidence, baseline-relative: only probes green on the fresh base control count;
 * a probe red on base is ignored (and regenerated next time). Metadata only: counts and codes.
 *
 * - `covered` is D-674's covered(P): at least one accepted probe for P counted.
 * - `result` is `fail` when any counted probe (base boot/build or P's) was not green on the fix,
 *   `pass` when P is covered and every counted probe was green, and `not_probed` otherwise.
 */
export const fixProbeEvidenceSchema = z
  .strictObject({
    version: z.literal(1),
    package: packageNameSchema,
    covered: z.boolean(),
    result: z.enum(["pass", "fail", "not_probed"]),
    baseProbes: probeTallySchema,
    packageProbes: probeTallySchema,
    /** Accepted probes red on the base control: ignored for this fix. */
    ignored: z.int().nonnegative(),
    /** Why P is not covered; null when it is. */
    uncovered: probeUncoveredReasonSchema.nullable(),
    /**
     * The subject the probes ran on (R1): the merge gate counts them only for the evidence it
     * judges. Absent on evidence recorded before R1, which the gate reads as not probed.
     */
    judgedOn: probeSubjectSchema.exactOptional(),
  })
  .refine((evidence) => evidence.covered === evidence.packageProbes.counted > 0, {
    error: "covered means at least one counted probe for the package",
  })
  .refine((evidence) => evidence.covered === (evidence.uncovered === null), {
    error: "an uncovered reason belongs to uncovered evidence only",
  })
  .refine((evidence) => evidence.result === probeResult(evidence), {
    error: "the result must follow from the counts",
  });
export type FixProbeEvidence = z.infer<typeof fixProbeEvidenceSchema>;

/** The result the counts decide (the schema refuses any other). */
export function probeResult(evidence: {
  readonly covered: boolean;
  readonly baseProbes: { readonly failed: number };
  readonly packageProbes: { readonly failed: number };
}): "pass" | "fail" | "not_probed" {
  if (evidence.baseProbes.failed > 0 || evidence.packageProbes.failed > 0) return "fail";
  return evidence.covered ? "pass" : "not_probed";
}

/** D-674 covered(P). */
export function probeCovered(evidence: FixProbeEvidence | null): boolean {
  return evidence !== null && evidence.covered;
}

/** Evidence for a fix that could not be probed at all (no counted probe of any kind). */
export function notProbed(
  pkg: FixProbeEvidence["package"],
  uncovered: ProbeUncoveredReason,
): FixProbeEvidence {
  return {
    version: 1,
    package: pkg,
    covered: false,
    result: "not_probed",
    baseProbes: { counted: 0, failed: 0 },
    packageProbes: { counted: 0, failed: 0 },
    ignored: 0,
    uncovered,
  };
}
