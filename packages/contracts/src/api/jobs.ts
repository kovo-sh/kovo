import { z } from "zod";

import { ladderRungSchema, verificationResultSchema } from "../enums/fixes.js";
import {
  TERMINAL_JOB_STATUSES,
  jobStatusSchema,
  sandboxPhaseSchema,
  type JobKind,
  type JobStatus,
  JOB_KINDS,
} from "../enums/operations.js";
import { calibrationStatusSchema } from "../enums/recipes.js";
import { unsupportedRepoReasonSchema } from "../enums/repos.js";
import { FAILURE_EXCERPT_MAX_BYTES, failureExcerptRunKindSchema } from "../failure-excerpt.js";
import {
  evidenceIdSchema,
  failureExcerptIdSchema,
  fixIdSchema,
  jobIdSchema,
  recipeVersionIdSchema,
  repoIdSchema,
  runRecordIdSchema,
  snapshotIdSchema,
} from "../ids.js";
import { countSchema, gitShaSchema, sha256HexSchema, whenValid } from "../primitives.js";
import { durableFailureReasonCodeSchema } from "../problem.js";
import { stepNameSchema } from "../step-result.js";
import { utcDateTimeSchema } from "../time.js";
import { pullRequestRefSchema } from "../webhooks.js";
import { runRecordListResponseSchema } from "../run-record.js";
import { defineEndpoint } from "./endpoint.js";

// `GET /v1/jobs/{id}`: asynchronous work (SPEC Public API row "Scoped read, including tenant
// ownership of job"): inventory, recipe discovery, rediscovery and calibration, fix generation
// (Sandbox A) and verification (Sandbox B), and reverts. The web client polls it with a bound until
// the status is terminal. Results carry identifiers, counts and codes only: never output, diffs or
// patch blob references.

const jobBase = {
  id: jobIdSchema,
  repo_id: repoIdSchema,
  status: jobStatusSchema,
  created_at: utcDateTimeSchema,
  started_at: utcDateTimeSchema.nullable(),
  finished_at: utcDateTimeSchema.nullable(),
  /** Why a failed job failed, as a stable reason code (never provider output). */
  failure: z.strictObject({ reason: durableFailureReasonCodeSchema }).nullable(),
};

/** The recipe version a discovery produced. */
const discoveredVersionSchema = z.strictObject({
  id: recipeVersionIdSchema,
  version: z.int().positive(),
  calibration_status: calibrationStatusSchema,
});

/**
 * Each job kind's sanitized result: identifiers, counts and codes only, never output, diffs or patch
 * blob references. Stored as `jobs.result` (set exactly when the job succeeded) and returned by
 * `GET /v1/jobs/{id}`.
 */
export const JOB_RESULT_SCHEMAS = {
  inventory: z.strictObject({ snapshot_id: snapshotIdSchema, open_findings: countSchema }),
  /** The first discovery of an enabled repository always produces version 1 or fails. */
  recipe_discovery: z.strictObject({ recipe_version: discoveredVersionSchema }),
  /** `recipe_version` is null when the fingerprint was unchanged. */
  recipe_rediscovery: z.strictObject({ recipe_version: discoveredVersionSchema.nullable() }),
  recipe_calibration: z.strictObject({ calibration_status: z.enum(["calibrated", "weak"]) }),
  /**
   * Sandbox A: the rung that produced the staged candidate and whether the agent helped, for this
   * job (a fix's later attempts may differ). The staged patch itself never leaves the control plane.
   */
  fix_generation: z.strictObject({ ladder_rung: ladderRungSchema, used_agent: z.boolean() }),
  /**
   * Sandbox B: the verification outcome and the sanitized evidence record it wrote. A job that ran
   * to completion succeeds even when the verification itself failed.
   */
  fix_verification: z.strictObject({
    verification: verificationResultSchema,
    evidence_id: evidenceIdSchema,
  }),
  revert: z.strictObject({ revert_pull_request: pullRequestRefSchema }),
} as const satisfies Record<JobKind, z.ZodType>;

/** A job's result in its stored (wire) form, by kind. */
export type JobResultJson = { [K in JobKind]: z.input<(typeof JOB_RESULT_SCHEMAS)[K]> }[JobKind];

/** One job kind: its own fields plus `result`, set exactly when the job succeeded. */
function jobVariant<const Kind extends JobKind, Shape extends z.ZodRawShape>(
  kind: Kind,
  shape: Shape,
) {
  return z.strictObject({
    ...jobBase,
    kind: z.literal(kind),
    ...shape,
    result: JOB_RESULT_SCHEMAS[kind].nullable(),
  });
}

/**
 * Every job kind with its sanitized result. Keyed by `JobKind`, so adding a kind without its
 * variant is a compile error rather than a job `GET /v1/jobs/{id}` cannot encode.
 */
const JOB_VARIANTS = {
  inventory: jobVariant("inventory", {}),
  recipe_discovery: jobVariant("recipe_discovery", {}),
  recipe_rediscovery: jobVariant("recipe_rediscovery", {}),
  recipe_calibration: jobVariant("recipe_calibration", {
    recipe_version_id: recipeVersionIdSchema,
  }),
  fix_generation: jobVariant("fix_generation", { fix_id: fixIdSchema }),
  fix_verification: jobVariant("fix_verification", { fix_id: fixIdSchema }),
  revert: jobVariant("revert", { fix_id: fixIdSchema }),
} as const satisfies Record<JobKind, z.ZodType>;

const [FIRST_JOB_KIND, ...OTHER_JOB_KINDS] = JOB_KINDS;
const JOB_VARIANT_LIST = [
  JOB_VARIANTS[FIRST_JOB_KIND],
  ...OTHER_JOB_KINDS.map((kind) => JOB_VARIANTS[kind]),
] as const;

const TERMINAL: ReadonlySet<JobStatus> = new Set(TERMINAL_JOB_STATUSES);

/** A job, discriminated by `kind`, in `JOB_KINDS` order. */
export const jobSchema = z.discriminatedUnion("kind", JOB_VARIANT_LIST).superRefine((job, ctx) => {
  if ((job.status === "succeeded") !== (job.result !== null)) {
    ctx.addIssue({
      code: "custom",
      path: ["result"],
      message: "exactly succeeded jobs have a result",
    });
  }
  if ((job.status === "failed") !== (job.failure !== null)) {
    ctx.addIssue({
      code: "custom",
      path: ["failure"],
      message: "exactly failed jobs record a failure",
    });
  }
  if (TERMINAL.has(job.status) !== (job.finished_at !== null)) {
    ctx.addIssue({
      code: "custom",
      path: ["finished_at"],
      message: "exactly terminal jobs have finished_at",
    });
  }
  if (job.status === "queued" && job.started_at !== null) {
    ctx.addIssue({
      code: "custom",
      path: ["started_at"],
      message: "a queued job has not started",
    });
  }
  if ((job.status === "running" || job.status === "succeeded") && job.started_at === null) {
    ctx.addIssue({
      code: "custom",
      path: ["started_at"],
      message: "a job that ran has started_at",
    });
  }
  const times = [job.created_at, job.started_at, job.finished_at].filter(
    (time): time is Date => time !== null,
  );
  if (
    times.some((time, index) => index > 0 && time.getTime() < (times[index - 1]?.getTime() ?? 0))
  ) {
    ctx.addIssue({
      code: "custom",
      path: ["finished_at"],
      message: "created, started and finished in order",
    });
  }
}, whenValid);
export type Job = z.output<typeof jobSchema>;

export const jobResponseSchema = z.strictObject({ job: jobSchema });

// ---- A repository's scan ----

/**
 * Where a repository's inventory stands (SPEC First-run flow: "Run inventory and deterministic
 * recipe discovery for each enabled repo"). Inventory runs are not jobs, so this is derived from the
 * repository's own state (docs/decisions/contracts.md "A repository's scan"):
 * - `inactive`: protection is not enabled (disabled, waiting for capacity, archived) and no
 *   inventory is current;
 * - `pending`: protection is enabled and the first inventory has not been published yet;
 * - `done`: an inventory is current; `finished_at` is when it was published;
 * - `unsupported`: the last inventory recorded an unsupported reason.
 */
export const INVENTORY_SCAN_STATES = ["inactive", "pending", "done", "unsupported"] as const;
export const inventoryScanStateSchema = z.enum(INVENTORY_SCAN_STATES);
export type InventoryScanState = z.infer<typeof inventoryScanStateSchema>;

export const inventoryPublicationSchema = z.strictObject({
  snapshot_id: snapshotIdSchema,
  commit_sha: gitShaSchema,
  lockfile_hash: sha256HexSchema,
  publication_generation: z.int().nonnegative(),
});

export type InventoryPublication = z.output<typeof inventoryPublicationSchema>;

export const inventoryScanSchema = z
  .strictObject({
    state: inventoryScanStateSchema,
    provenance: inventoryPublicationSchema.nullable().optional(),
    finished_at: utcDateTimeSchema.nullable(),
    unsupported_reason: unsupportedRepoReasonSchema.nullable(),
  })
  .superRefine((inventory, ctx) => {
    if (inventory.provenance != null && inventory.state !== "done") {
      ctx.addIssue({
        code: "custom",
        path: ["provenance"],
        message: "only done inventory has publication provenance",
      });
    }
    if ((inventory.state === "done") !== (inventory.finished_at !== null)) {
      ctx.addIssue({
        code: "custom",
        path: ["finished_at"],
        message: "exactly a done inventory has finished_at",
      });
    }
    if ((inventory.state === "unsupported") !== (inventory.unsupported_reason !== null)) {
      ctx.addIssue({
        code: "custom",
        path: ["unsupported_reason"],
        message: "exactly an unsupported inventory has its reason",
      });
    }
  }, whenValid);
export type InventoryScan = z.output<typeof inventoryScanSchema>;

const DISCOVERY_JOB_KINDS: ReadonlySet<JobKind> = new Set([
  "recipe_discovery",
  "recipe_rediscovery",
]);

/**
 * `GET /v1/repos/{repo}/scan`: the repository's inventory and its newest recipe discovery and
 * calibration jobs (poll either with `GET /v1/jobs/{id}`). Calibration run counts are not reported:
 * the number of runs a calibration needs is decided inside its workflow and never stored.
 */
export const repoScanSchema = z
  .strictObject({
    repo_id: repoIdSchema,
    inventory: inventoryScanSchema,
    /** The newest `recipe_discovery` or `recipe_rediscovery` job, if any. */
    discovery: jobSchema.nullable(),
    /** The newest `recipe_calibration` job, if any. */
    calibration: jobSchema.nullable(),
  })
  .superRefine((scan, ctx) => {
    if (scan.discovery !== null && !DISCOVERY_JOB_KINDS.has(scan.discovery.kind)) {
      ctx.addIssue({ code: "custom", path: ["discovery", "kind"], message: "a discovery job" });
    }
    if (scan.calibration !== null && scan.calibration.kind !== "recipe_calibration") {
      ctx.addIssue({ code: "custom", path: ["calibration", "kind"], message: "a calibration job" });
    }
    for (const key of ["discovery", "calibration"] as const) {
      const job = scan[key];
      if (job !== null && job.repo_id !== scan.repo_id) {
        ctx.addIssue({ code: "custom", path: [key, "repo_id"], message: "the scanned repository" });
      }
    }
  }, whenValid);
export type RepoScan = z.output<typeof repoScanSchema>;

export const repoScanResponseSchema = z.strictObject({ scan: repoScanSchema });

/**
 * A failed step's output excerpt (docs/decisions/verification.md "Failed-step output excerpts",
 * owner-directed): the redacted tail of the combined output of one failed or timed-out recipe step
 * in a Sandbox B run of the job, and which run and step it came from. `redaction_count` says how
 * many secrets were replaced, never what they were.
 */
export const failureExcerptSchema = z.strictObject({
  id: failureExcerptIdSchema,
  repo_id: repoIdSchema,
  job_id: jobIdSchema,
  run_kind: failureExcerptRunKindSchema,
  phase: sandboxPhaseSchema,
  step_name: stepNameSchema,
  /** The redacted output, UTF-8; at most the last 300 lines and 16 KiB of what the step printed. */
  output: z.string().max(FAILURE_EXCERPT_MAX_BYTES),
  /** Whether the step printed more than the excerpt keeps (only its tail is here). */
  truncated: z.boolean(),
  redaction_count: countSchema,
  created_at: utcDateTimeSchema,
  expires_at: utcDateTimeSchema,
});
export type FailureExcerpt = z.output<typeof failureExcerptSchema>;

export const failureExcerptResponseSchema = z.strictObject({ excerpt: failureExcerptSchema });

/** Sanitized explanations are informational and readable by every repository reader. */
export const failureDiagnosisViewSchema = z.strictObject({
  job_id: jobIdSchema,
  excerpt_id: failureExcerptIdSchema.nullable(),
  mutation_sha256: sha256HexSchema.nullable(),
  run_kind: failureExcerptRunKindSchema,
  phase: sandboxPhaseSchema,
  step_name: stepNameSchema,
  category: z.string().min(1).max(100),
  confidence: z.number().min(0).max(1),
  summary: z.string().max(300),
  remediation: z.string().max(300),
  created_at: utcDateTimeSchema,
  expires_at: utcDateTimeSchema,
});
export type FailureDiagnosis = z.output<typeof failureDiagnosisViewSchema>;
export const failureDiagnosesQuerySchema = z
  .strictObject({
    job: jobIdSchema.exactOptional(),
    excerpt: failureExcerptIdSchema.exactOptional(),
    recipe_version: recipeVersionIdSchema.exactOptional(),
    evidence: evidenceIdSchema.exactOptional(),
    phase: sandboxPhaseSchema.exactOptional(),
    step: stepNameSchema.exactOptional(),
    run_kind: failureExcerptRunKindSchema.exactOptional(),
  })
  .refine(
    (query) =>
      [query.job, query.excerpt, query.recipe_version, query.evidence].filter(
        (value) => value !== undefined,
      ).length === 1,
    {
      error: "Name exactly one job, excerpt, recipe version or evidence record.",
    },
  );

export const JOB_ENDPOINTS = {
  listJobRunRecords: defineEndpoint({
    operationId: "listJobRunRecords",
    area: "jobs",
    method: "GET",
    path: "/v1/repos/{repo}/jobs/{job}/records",
    summary: "List a job's run-record metadata for a human repository reader.",
    source: {
      kind: "owner_directed",
      decision: "run-records.md",
      heading: "Customer reads (owner-directed, R5)",
    },
    params: z.strictObject({ repo: repoIdSchema, job: jobIdSchema }),
    query: null,
    body: null,
    responses: { 200: runRecordListResponseSchema },
    authorization: {
      spec: "Human members who can read the repo's fixes may read records through a repo-authorized session; API keys are excluded in v1.",
      actors: ["human_session"],
      tenant: "path_resource",
      repoAuthority: { level: "read", over: "path_repo" },
    },
  }),
  getRunRecord: defineEndpoint({
    operationId: "getRunRecord",
    area: "jobs",
    method: "GET",
    path: "/v1/repos/{repo}/records/{record}",
    summary: "Stream authenticated, decrypted run-record NDJSON without caching it.",
    source: {
      kind: "owner_directed",
      decision: "run-records.md",
      heading: "Customer reads (owner-directed, R5)",
    },
    params: z.strictObject({ repo: repoIdSchema, record: runRecordIdSchema }),
    query: null,
    body: null,
    responses: { 200: z.instanceof(ReadableStream<Uint8Array>) },
    authorization: {
      spec: "Human members who can read the repo's fixes may read records through a repo-authorized session; API keys are excluded in v1.",
      actors: ["human_session"],
      tenant: "path_resource",
      repoAuthority: { level: "read", over: "path_repo" },
    },
    problems: ["record_expired", "record_unavailable"],
  }),
  getFailureDiagnoses: defineEndpoint({
    operationId: "getFailureDiagnoses",
    area: "jobs",
    method: "GET",
    path: "/v1/repos/{repo}/failure-diagnoses",
    summary:
      "Read up to 100 recent sanitized failure explanations for a repository's run, without raw output.",
    source: {
      kind: "owner_directed",
      decision: "verification.md",
      heading: "Failure diagnoses (owner-directed exception, 2026-10-02)",
    },
    params: z.strictObject({ repo: repoIdSchema }),
    query: failureDiagnosesQuerySchema,
    body: null,
    responses: { 200: z.strictObject({ diagnoses: z.array(failureDiagnosisViewSchema).max(100) }) },
    authorization: {
      managementPermission: "getJob",
      spec: "Repository visibility always requires current GitHub read access.",
      actors: ["human_session", "api_key_read", "api_key_write"],
      tenant: "path_resource",
      repoAuthority: { level: "read", over: "path_repo" },
    },
  }),
  getJob: defineEndpoint({
    operationId: "getJob",
    area: "jobs",
    method: "GET",
    path: "/v1/jobs/{id}",
    summary: "Poll an asynchronous job of a repository the caller can read.",
    source: { kind: "spec_row", path: "/v1/jobs/{id}" },
    params: z.strictObject({ id: jobIdSchema }),
    query: null,
    body: null,
    responses: { 200: jobResponseSchema },
    authorization: {
      spec: "Scoped read, including tenant ownership of job",
      actors: ["human_session", "api_key_read", "api_key_write"],
      tenant: "path_resource",
      repoAuthority: { level: "read", over: "resource_repos" },
    },
  }),
  getRepoScan: defineEndpoint({
    operationId: "getRepoScan",
    area: "jobs",
    method: "GET",
    path: "/v1/repos/{repo}/scan",
    summary:
      "Read where a repository's scan stands: its inventory and newest recipe discovery and calibration jobs.",
    source: { kind: "spec_implied", section: "First-run flow" },
    params: z.strictObject({ repo: repoIdSchema }),
    query: null,
    body: null,
    responses: { 200: repoScanResponseSchema },
    authorization: {
      spec: "Surface missing verification setup while scanning and alerts continue.",
      actors: ["human_session", "api_key_read", "api_key_write"],
      tenant: "path_resource",
      repoAuthority: { level: "read", over: "path_repo" },
    },
  }),
  getFailureExcerpt: defineEndpoint({
    operationId: "getFailureExcerpt",
    area: "jobs",
    method: "GET",
    path: "/v1/repos/{repo}/failure-excerpts/{id}",
    summary:
      "Read the redacted output excerpt of a failed recipe step while it has not expired (every read is audited).",
    source: {
      kind: "owner_directed",
      decision: "verification.md",
      heading: "Failed-step output excerpts (owner-directed exception, 2026-10-02)",
    },
    params: z.strictObject({ repo: repoIdSchema, id: failureExcerptIdSchema }),
    query: null,
    body: null,
    responses: { 200: failureExcerptResponseSchema },
    authorization: {
      // The excerpt is decrypted like a patch blob; who may read it follows the audit row's rule.
      spec: "Encrypt patch blobs with per-blob data keys wrapped by KMS and audit decrypt access.",
      actors: ["human_session"],
      tenant: "path_resource",
      accountRoles: ["owner", "admin"],
      repoAuthority: { level: "read", over: "path_repo" },
    },
    revealedOutputFields: ["/excerpt/output"],
    problems: ["failure_excerpt_expired"],
  }),
} as const;
