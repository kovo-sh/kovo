import { z } from "zod";

import { repoIdSchema } from "../ids.js";
import { exactVersionSchema } from "../npm.js";
import {
  PACKAGE_MANAGER_CHOICE_LOCKFILES,
  packageManagerChoiceOptionSchema,
  packageManagerPreselectionBasisSchema,
  packageManagerVersionSourceSchema,
} from "../package-manager-choice.js";
import { gitShaSchema } from "../primitives.js";
import { utcDateTimeSchema } from "../time.js";
import { defineEndpoint } from "./endpoint.js";

// `/v1/repos/{repo}/package-manager-choice`: read and record which package manager a repository
// with two root lockfiles uses (owner choice A, 2026-10-27, #5500; SPEC Public API row). A new
// route with its own response, so no strict repository reader that earlier releases parse changes.

const lockfileNameSchema = z.enum([
  PACKAGE_MANAGER_CHOICE_LOCKFILES.npm,
  PACKAGE_MANAGER_CHOICE_LOCKFILES.pnpm,
]);

/** The recorded choice as the API shows it, with the lockfile it keeps and the one it ignores. */
export const packageManagerChoiceWireSchema = z.strictObject({
  package_manager: packageManagerChoiceOptionSchema,
  version: exactVersionSchema,
  version_source: packageManagerVersionSourceSchema,
  chosen_at: utcDateTimeSchema,
  /** Root-relative path of the lockfile Kovo keeps (`pnpm-lock.yaml`). */
  kept_lockfile_path: lockfileNameSchema,
  /** Root-relative path of the lockfile Kovo ignores. */
  ignored_lockfile_path: lockfileNameSchema,
});
export type PackageManagerChoiceWire = z.infer<typeof packageManagerChoiceWireSchema>;

export const packageManagerChoiceResponseSchema = z.strictObject({
  /** Null until a repository admin records a choice. */
  choice: packageManagerChoiceWireSchema.nullable(),
});
export type PackageManagerChoiceResponse = z.infer<typeof packageManagerChoiceResponseSchema>;

/**
 * Recording a choice: the manager, the exact version (the picker prefills the suggested one) and
 * where that version came from (`admin_entered` when the admin typed it). The version must be
 * inside the compatibility matrix; refusals carry the resolver's rejection reason.
 */
export const recordPackageManagerChoiceBodySchema = z.strictObject({
  package_manager: packageManagerChoiceOptionSchema,
  version: exactVersionSchema,
  version_source: packageManagerVersionSourceSchema,
});
export type RecordPackageManagerChoiceBody = z.infer<typeof recordPackageManagerChoiceBodySchema>;

/** One picker option: the exact version Kovo suggests for it and where it came from, or why none. */
export const packageManagerSuggestionOptionSchema = z.strictObject({
  package_manager: packageManagerChoiceOptionSchema,
  /** The image's baked release of the resolved major; null when the resolver refuses this option. */
  version: exactVersionSchema.nullable(),
  /** Where the major came from; `default` means no declaration or CI chose it. */
  version_source: packageManagerVersionSourceSchema.exclude(["admin_entered"]).nullable(),
  /** The resolver's stable rejection reason when `version` is null (`package_manager_mismatch`, …). */
  unavailable_reason: z
    .string()
    .regex(/^[a-z][a-z0-9_]{0,63}$/)
    .nullable(),
});
export type PackageManagerSuggestionOption = z.infer<typeof packageManagerSuggestionOptionSchema>;

/**
 * What the picker shows, read from the default branch's root (names, the `packageManager`,
 * `engines` and `volta` fields, version files and CI install steps; nothing is stored).
 */
export const packageManagerSuggestionResponseSchema = z.strictObject({
  /** Whether the root commits exactly `package-lock.json` and `pnpm-lock.yaml`. */
  needs_choice: z.boolean(),
  /** The default-branch commit the suggestion was read at. */
  commit_sha: gitShaSchema,
  preselected: packageManagerChoiceOptionSchema.nullable(),
  preselection_basis: packageManagerPreselectionBasisSchema,
  /** npm then pnpm; empty when the root needs no choice. */
  options: z.array(packageManagerSuggestionOptionSchema).max(2),
});
export type PackageManagerSuggestionResponse = z.infer<
  typeof packageManagerSuggestionResponseSchema
>;

/** The SPEC row's authorization text, quoted by both methods. */
export const PACKAGE_MANAGER_CHOICE_ROW =
  "Human repo admin; two root lockfiles: chosen npm or pnpm, exact version and its source; version validated against the compatibility matrix; audited";

/** The suggestion row's authorization text. */
export const PACKAGE_MANAGER_SUGGESTION_ROW =
  "Human repo admin; two root lockfiles: preselected manager, and for npm and pnpm the exact version and its source, read from the default branch; nothing stored";

const params = z.strictObject({ repo: repoIdSchema });
const authorization = {
  spec: PACKAGE_MANAGER_CHOICE_ROW,
  actors: ["human_session"] as const,
  tenant: "path_resource" as const,
  repoAuthority: { level: "admin" as const, over: "path_repo" as const },
};

export const PACKAGE_MANAGER_CHOICE_ENDPOINTS = {
  getPackageManagerChoice: defineEndpoint({
    operationId: "getPackageManagerChoice",
    area: "repos",
    method: "GET",
    path: "/v1/repos/{repo}/package-manager-choice",
    summary: "Read the package manager recorded for a repository with two root lockfiles.",
    source: { kind: "spec_row", path: "/v1/repos/{repo}/package-manager-choice" },
    params,
    query: null,
    body: null,
    responses: { 200: packageManagerChoiceResponseSchema },
    authorization,
  }),
  recordPackageManagerChoice: defineEndpoint({
    operationId: "recordPackageManagerChoice",
    area: "repos",
    method: "PUT",
    path: "/v1/repos/{repo}/package-manager-choice",
    summary:
      "Record npm or pnpm, with an exact version inside the compatibility matrix, for a repository with two root lockfiles.",
    source: { kind: "spec_row", path: "/v1/repos/{repo}/package-manager-choice" },
    auditActions: ["repo.package_manager_chosen"],
    params,
    query: null,
    body: recordPackageManagerChoiceBodySchema,
    responses: { 200: packageManagerChoiceResponseSchema },
    authorization,
    problems: ["validation_failed"],
  }),
  getPackageManagerSuggestion: defineEndpoint({
    operationId: "getPackageManagerSuggestion",
    area: "repos",
    method: "GET",
    path: "/v1/repos/{repo}/package-manager-choice/suggestion",
    summary:
      "Read the picker's suggestion for a repository with two root lockfiles: the preselected manager and, for npm and pnpm, the exact version and its source.",
    source: { kind: "spec_row", path: "/v1/repos/{repo}/package-manager-choice/suggestion" },
    params,
    query: null,
    body: null,
    responses: { 200: packageManagerSuggestionResponseSchema },
    authorization: {
      spec: PACKAGE_MANAGER_SUGGESTION_ROW,
      actors: ["human_session"] as const,
      tenant: "path_resource" as const,
      repoAuthority: { level: "admin" as const, over: "path_repo" as const },
    },
    problems: ["installation_suspended", "upstream_error"],
  }),
} as const;
