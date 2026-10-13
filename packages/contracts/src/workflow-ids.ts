import { z } from "zod";

import { repoIdSchema, type FixId, type RepoId } from "./ids.js";
import { packageNameSchema, type PackageName } from "./npm.js";

// SPEC "Workflows": "Each fix is a DBOS workflow with stable ID `fix:{repoId}:{package}:{attempt}`."
// The ID is stored in `fixes.workflow_id UNIQUE` and used for duplicate-harmless dispatch, so the
// builder and parser must agree on exactly one canonical string per (repo, package, attempt).

export const FIX_WORKFLOW_ID_PREFIX = "fix:";

export interface FixWorkflowIdParts {
  readonly repoId: RepoId;
  readonly package: PackageName;
  /** 1 for the first attempt; an explicit retry creates `attempt + 1`. */
  readonly attempt: number;
}

/** A fix attempt number: a positive safe integer. */
export const fixAttemptSchema = z.int().positive();

const UUID_LENGTH = 36;
const CANONICAL_ATTEMPT = /^[1-9]\d*$/;

function build(parts: FixWorkflowIdParts): string {
  return `${FIX_WORKFLOW_ID_PREFIX}${parts.repoId}:${parts.package}:${parts.attempt}`;
}

/**
 * Parses a fix workflow ID. Returns `null` unless `value` is the canonical ID of valid parts, so
 * `fixWorkflowId(parseFixWorkflowId(s)) === s` for every accepted `s`. Package names may contain `@`
 * and `/`; the attempt is taken after the last `:` and the repo ID is the fixed-width UUID.
 */
export function parseFixWorkflowId(value: string): FixWorkflowIdParts | null {
  if (!value.startsWith(FIX_WORKFLOW_ID_PREFIX)) return null;
  const repoStart = FIX_WORKFLOW_ID_PREFIX.length;
  const repoEnd = repoStart + UUID_LENGTH;
  if (value.charAt(repoEnd) !== ":") return null;
  const rest = value.slice(repoEnd + 1);
  const attemptSeparator = rest.lastIndexOf(":");
  if (attemptSeparator < 0) return null;
  const attemptText = rest.slice(attemptSeparator + 1);
  if (!CANONICAL_ATTEMPT.test(attemptText)) return null;

  const repoId = repoIdSchema.safeParse(value.slice(repoStart, repoEnd));
  const pkg = packageNameSchema.safeParse(rest.slice(0, attemptSeparator));
  const attempt = fixAttemptSchema.safeParse(Number(attemptText));
  if (!repoId.success || !pkg.success || !attempt.success) return null;

  const parts: FixWorkflowIdParts = {
    repoId: repoId.data,
    package: pkg.data,
    attempt: attempt.data,
  };
  // Rejects non-canonical spellings (an upper-case UUID, a huge attempt that loses precision).
  return build(parts) === value ? parts : null;
}

/** A canonical fix workflow ID string. */
export const fixWorkflowIdSchema = z
  .string()
  .refine((value) => parseFixWorkflowId(value) !== null, {
    error: "must be a canonical fix workflow ID fix:{repoId}:{package}:{attempt}",
  })
  .brand<"FixWorkflowId">();
export type FixWorkflowId = z.infer<typeof fixWorkflowIdSchema>;

/** Builds the stable fix workflow ID; throws if any part is invalid. */
export function fixWorkflowId(parts: FixWorkflowIdParts): FixWorkflowId {
  return fixWorkflowIdSchema.parse(
    build({
      repoId: repoIdSchema.parse(parts.repoId),
      package: packageNameSchema.parse(parts.package),
      attempt: fixAttemptSchema.parse(parts.attempt),
    }),
  );
}

/** SPEC "Reverts": "Create an idempotent `kovo/revert-{fixId}` branch". */
export function revertBranchName(fixId: FixId): string {
  return `kovo/revert-${fixId}`;
}
