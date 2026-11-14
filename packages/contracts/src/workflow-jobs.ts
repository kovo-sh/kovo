import { z } from "zod";

import { checkTierSchema } from "./convergence.js";
import { repoFilePathSchema } from "./primitives.js";
import { stepNameSchema } from "./step-result.js";

// Phase 2 R3 (#8256, plans/js-coverage-phase2.md §2.7; owner D-674, D-708, D-713, D-714): Kovo runs
// the repository's own `pull_request` workflow jobs with a pinned act-style executor inside the
// isolation tier's Sandbox B, instead of translating them (the importer, now frozen). Each job is a
// candidate check that R5 keeps only when it passes on the unchanged base. These are the job's
// stored metadata: the workflow path and job ID, the one matrix cell, the action references pinned
// to commit SHAs by trusted code, and closed drop reasons. Never workflow text, step commands,
// output or secrets.

/**
 * The workflow executor baked into the sandbox image: nektos/act, host mode (`-self-hosted`
 * platform), no Docker. Plan §0.8 and §2.7: it enters at this reviewed version, and every later
 * version change needs owner approval on #626 before merge. The image's tool manifest
 * (`infra/sandbox-image/tool-cache.json`, `act`) pins the release tarballs' sha256 from the tag's
 * published checksums (D-761, screened under D-363), and the image build verifies the download
 * against it. On an image built before that, R3 jobs fail on the base and R5 drops them, so the
 * imported checks they would replace keep running.
 */
export const WORKFLOW_EXECUTOR = {
  name: "act",
  version: "0.2.92",
  /** Where the image installs it (read-only to the workload on the tier). */
  path: "/opt/kovo/bin/act",
} as const;

/** Why a `pull_request` workflow job is not run as an R3 check (disclosed by code, never text). */
export const WORKFLOW_JOB_DROP_REASONS = [
  /** The workflow does not run on `pull_request`. */
  "workflow_job_not_pull_request",
  /** The job names a deployment environment (`environment:`). */
  "workflow_job_environment",
  /** The job's name or ID marks it as a deploy or publish job (the D-674 name rules). */
  "workflow_job_deploy_or_publish",
  /** Service containers (`services:`): containers are owner D-708, phase 3. */
  "workflow_job_services",
  /** A job container (`container:`): D-708, phase 3. */
  "workflow_job_container",
  /** A Docker action (`docker://` or `runs.using: docker`): D-708, phase 3. */
  "workflow_job_docker_action",
  /** A reusable workflow call (`jobs.<id>.uses`). */
  "workflow_job_reusable_workflow",
  /** `runs-on` is not one GitHub-hosted Ubuntu label. */
  "workflow_job_unsupported_runner",
  /** The matrix is an expression, or a dimension is not a list of scalars. */
  "workflow_job_matrix_unresolved",
  /** A Node dimension has no value matching the image's Node major. */
  "workflow_job_matrix_no_node_cell",
  /** An action reference could not be resolved to a commit SHA from public metadata. */
  "workflow_job_action_unresolved",
  /** The workflow file or the job could not be parsed. */
  "workflow_job_unparseable",
  /** The job has no steps. */
  "workflow_job_no_steps",
  /** Past the per-recipe job limit. */
  "workflow_job_limit",
] as const;
export const workflowJobDropReasonSchema = z.enum(WORKFLOW_JOB_DROP_REASONS);
export type WorkflowJobDropReason = z.infer<typeof workflowJobDropReasonSchema>;

export const WORKFLOW_JOB_LIMITS = {
  /** R3 jobs per recipe. */
  maxJobs: 8,
  /** Distinct pinned action references per job. */
  maxActions: 24,
  /** Matrix dimensions of the one selected cell. */
  maxMatrix: 8,
  /** Dropped jobs disclosed per recipe. */
  maxDropped: 64,
  /** The per-job time budget, in seconds (the job's `timeout-minutes` is capped here). */
  maxJobTimeoutSec: 1200,
} as const;

/** The GitHub-hosted Ubuntu labels the executor maps to its host platform. */
export const WORKFLOW_RUNNER_LABELS = [
  "ubuntu-latest",
  "ubuntu-24.04",
  "ubuntu-22.04",
  "ubuntu-20.04",
] as const;
export const workflowRunnerLabelSchema = z.enum(WORKFLOW_RUNNER_LABELS);

/** A workflow file path (`.github/workflows/<name>.yml|yaml`). */
export const workflowPathSchema = repoFilePathSchema.refine(
  (path) => /^\.github\/workflows\/[A-Za-z0-9._-]+\.ya?ml$/.test(path),
  { error: "must be a workflow file path" },
);

/** A GitHub Actions job ID: a letter or `_`, then letters, digits, `-` and `_`. */
export const workflowJobIdSchema = z
  .string()
  .regex(/^[A-Za-z_][A-Za-z0-9_-]{0,99}$/, { error: "must be a workflow job ID" });

/** A matrix dimension name of the selected cell. */
const matrixKeySchema = z.string().regex(/^[A-Za-z_][A-Za-z0-9_-]{0,63}$/);
/** A scalar matrix value as the executor's `--matrix key:value` takes it. */
const matrixValueSchema = z.string().regex(/^[A-Za-z0-9._@+/-]{1,64}$/);

/**
 * A public action reference as written in a workflow (`owner/repo[/path]@ref`): GitHub owner and
 * repository name rules, an optional subdirectory, and a tag, branch or SHA without spaces or shell
 * metacharacters. It is public package-like metadata (D-242), resolved by trusted code.
 */
export const actionUsesSchema = z
  .string()
  .max(256)
  .regex(
    /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})\/[A-Za-z0-9._-]{1,100}(?:\/[A-Za-z0-9._-]{1,100}){0,8}@[A-Za-z0-9._/+-]{1,128}$/,
    { error: "must be an action reference" },
  )
  .refine(
    (uses) =>
      !uses
        .split("@")[0]!
        .split("/")
        .some((part) => part === "." || part === ".."),
    {
      error: "must not hold a dot segment",
    },
  );

/** One pinned action: the reference as written and the commit SHA trusted code resolved it to. */
export const pinnedActionSchema = z.strictObject({
  uses: actionUsesSchema,
  /** The full commit SHA (an upstream action's commit, not a repository commit of the customer). */
  sha: z.string().regex(/^[0-9a-f]{40}$/, { error: "must be a full commit SHA" }),
});
export type PinnedAction = z.infer<typeof pinnedActionSchema>;

/** One R3 candidate check: a `pull_request` workflow job run by the executor. */
export const recipeWorkflowJobSchema = z.strictObject({
  /** The recipe check's name (`StepResult.name`). */
  name: stepNameSchema,
  path: workflowPathSchema,
  job: workflowJobIdSchema,
  runsOn: workflowRunnerLabelSchema,
  /** The one matrix cell run (empty without a matrix). */
  matrix: z.record(matrixKeySchema, matrixValueSchema),
  actions: z.array(pinnedActionSchema).max(WORKFLOW_JOB_LIMITS.maxActions),
  timeoutSec: z.int().positive().max(WORKFLOW_JOB_LIMITS.maxJobTimeoutSec),
  /** The imported recipe checks this job replaces once it is kept on the base. */
  replaces: z.array(stepNameSchema).max(50),
  /** The check tiers of the imported checks it replaces (`other` when none). */
  tiers: z.array(checkTierSchema).min(1).max(7),
});
export type WorkflowJob = z.infer<typeof recipeWorkflowJobSchema>;

export const workflowJobDropSchema = z.strictObject({
  path: workflowPathSchema,
  job: workflowJobIdSchema.nullable(),
  reason: workflowJobDropReasonSchema,
});
export type WorkflowJobDrop = z.infer<typeof workflowJobDropSchema>;

/** A recipe's R3 metadata (`Recipe.workflow`): the executor version, the jobs and the drops. */
export const recipeWorkflowSchema = z
  .strictObject({
    /** The executor the jobs were selected for (`act@<version>`). */
    executor: z.string().regex(/^act@\d+\.\d+\.\d+$/),
    jobs: z.array(recipeWorkflowJobSchema).max(WORKFLOW_JOB_LIMITS.maxJobs),
    dropped: z.array(workflowJobDropSchema).max(WORKFLOW_JOB_LIMITS.maxDropped),
  })
  .refine(
    (workflow) => new Set(workflow.jobs.map((job) => job.name)).size === workflow.jobs.length,
    { error: "workflow job names are unique", path: ["jobs"] },
  );
export type RecipeWorkflow = z.infer<typeof recipeWorkflowSchema>;
