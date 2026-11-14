import { z } from "zod";

import {
  installRootIdSchema,
  repoIdSchema,
  type FixId,
  type InstallRootId,
  type RepoId,
} from "./ids.js";
import { packageNameSchema, type PackageName } from "./npm.js";

// SPEC "Workflows": "Each fix is a DBOS workflow with stable ID `fix:{repoId}:{package}:{attempt}`."
// The ID is stored in `fixes.workflow_id UNIQUE` and used for duplicate-harmless dispatch, so the
// builder and parser must agree on one canonical string per legacy or root-scoped identity.
// M1 accepts the root-scoped form; production builders keep omitting installRootId until M8.

export const FIX_WORKFLOW_ID_PREFIX = "fix:";

export interface FixWorkflowIdParts {
  readonly repoId: RepoId;
  readonly installRootId?: InstallRootId | null;
  readonly package: PackageName;
  /** 1 for the first attempt; an explicit retry creates `attempt + 1`. */
  readonly attempt: number;
}

/** A fix attempt number: a positive safe integer. */
export const fixAttemptSchema = z.int().positive();

const UUID_LENGTH = 36;
const CANONICAL_ATTEMPT = /^[1-9]\d*$/;

function build(parts: FixWorkflowIdParts): string {
  const root = parts.installRootId == null ? "" : `${parts.installRootId}:`;
  return `${FIX_WORKFLOW_ID_PREFIX}${parts.repoId}:${root}${parts.package}:${parts.attempt}`;
}

/**
 * Parses a fix workflow ID. Returns `null` unless `value` is the canonical ID of valid parts, so
 * `fixWorkflowId(parseFixWorkflowId(s)) === s` for every accepted `s`. Package names may contain `@`
 * and `/`; the attempt is taken after the last `:` and the repo ID is the fixed-width UUID.
 */
export function parseFixWorkflowId(
  value: string,
): (FixWorkflowIdParts & { readonly installRootId: InstallRootId | null }) | null {
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
  const packageAndRoot = rest.slice(0, attemptSeparator);
  const hasRoot = packageAndRoot.includes(":");
  const root = hasRoot ? installRootIdSchema.safeParse(packageAndRoot.slice(0, UUID_LENGTH)) : null;
  if (hasRoot && (packageAndRoot.charAt(UUID_LENGTH) !== ":" || !root?.success)) return null;
  const pkg = packageNameSchema.safeParse(
    hasRoot ? packageAndRoot.slice(UUID_LENGTH + 1) : packageAndRoot,
  );
  const attempt = fixAttemptSchema.safeParse(Number(attemptText));
  if (!repoId.success || !pkg.success || !attempt.success) return null;

  const parts: FixWorkflowIdParts & { readonly installRootId: InstallRootId | null } = {
    repoId: repoId.data,
    installRootId: root?.success ? root.data : null,
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

/** Stable attempt ID of either form, including when followed by run/phase child suffixes. */
export function fixWorkflowIdBase(value: string): FixWorkflowId | null {
  const segments = value.split(":");
  for (const count of [5, 4]) {
    const base = segments.slice(0, count).join(":");
    if (parseFixWorkflowId(base) !== null) return fixWorkflowIdSchema.parse(base);
  }
  return null;
}

/** Builds the stable fix workflow ID; throws if any part is invalid. */
export function fixWorkflowId(parts: FixWorkflowIdParts): FixWorkflowId {
  return fixWorkflowIdSchema.parse(
    build({
      repoId: repoIdSchema.parse(parts.repoId),
      installRootId:
        parts.installRootId == null ? null : installRootIdSchema.parse(parts.installRootId),
      package: packageNameSchema.parse(parts.package),
      attempt: fixAttemptSchema.parse(parts.attempt),
    }),
  );
}

/** SPEC "Reverts": "Create an idempotent `kovo/revert-{fixId}` branch". */
export function revertBranchName(fixId: FixId): string {
  return `kovo/revert-${fixId}`;
}
