import { z } from "zod";
import { writerPinned } from "./compatibility.js";

import { apiKeyIdSchema, installationIdSchema, repoIdSchema } from "./ids.js";
import { utcDateTimeSchema } from "./time.js";

/** Owner-directed account automation; legacy keys remain Runtime keys. */
export const API_KEY_KINDS = ["runtime", "management", "registry"] as const;
/** Registry issuance follows the production promotion of the tolerant reader. */
export const apiKeyKindWriteSchema = z.enum(API_KEY_KINDS);
export const apiKeyKindSchema = writerPinned(z.enum(API_KEY_KINDS), apiKeyKindWriteSchema);
export type ApiKeyKind = z.infer<typeof apiKeyKindSchema>;

/**
 * Exact account permissions, never wildcard authority or automatic future-route grants.
 * Agent decision (2026-10-04), pending owner review: reevaluateFix maps to retryFix.
 * As a strict-subset exception to the future-route rule, existing Management
 * keys holding retryFix (including delegated keys) can call POST /v1/fixes/{id}/reevaluate,
 * subject to fresh repository admin authority, key lineage and current reevaluation gates.
 */
export const MANAGEMENT_KEY_PERMISSIONS = [
  "deleteAccount",
  "listInvitations",
  "createInvitation",
  "revokeInvitation",
  "listMembers",
  "getMember",
  "updateMember",
  "removeMember",
  "getAttention",
  "listActivity",
  "listApiKeys",
  "listAuditEvents",
  "getBilling",
  "startCheckout",
  "openPortal",
  "previewCapacity",
  "confirmCapacity",
  "getCapacityQuote",
  "cancelSubscription",
  "setRetainedRepo",
  "getOverages",
  "putOverages",
  "listFindings",
  "listAccountFindings",
  "dismissFinding",
  "listFindingAlerts",
  "listFixes",
  "listAccountFixes",
  "getFix",
  "retryFix",
  "revertFix",
  "getJob",
  "getRepoScan",
  "getNotifications",
  "putNotifications",
  "getRepoNotifications",
  "putRepoNotifications",
  "pauseRepo",
  "resumeRepo",
  "pauseAccount",
  "resumeAccount",
  "pauseInstallation",
  "resumeInstallation",
  "getPolicy",
  "putPolicy",
  "getRecipe",
  "listRecipeVersions",
  "getRecipeVersion",
  "getRecipeDiff",
  "updateRecipeOverrides",
  "rediscoverRecipe",
  "approveRecipeVersion",
  "rollbackRecipeVersion",
  "listRepos",
  "getRepo",
  "enableProtection",
  "disableProtection",
  "setRepoMode",
  "getUsage",
  "listWebhooks",
  "createWebhook",
  "revokeWebhook",
  "rotateWebhookSecret",
  "listWebhookDeliveries",
  "testWebhook",
  "createRuntimeKey",
  "createManagementKey",
  "revokeRuntimeKey",
  "revokeManagementKey",
  "recipe.egress.refresh_catalog",
  "evaluateDependencyChanges",
  "createMalwareReport",
  "createSyntheticAdvisory",
  "retractMalwareReport",
  "retractSyntheticAdvisory",
  "acceptDependencyOverrideDrill",
  "setThirdPartyScannersDrill",
  "armFixVerificationDrillFault",
  "retryDependencyGateDrill",
  "overrideUnevaluatedDependencyGateDrill",
  "armDependencyGateDrillFault",
] as const;

/**
 * Permissions accepted by a tolerant reader before their issuance release.
 * Empty after promotion of the reader-only grants to explicit Custom issuance.
 */
export const READER_ONLY_MANAGEMENT_KEY_PERMISSIONS = [] as const;

/** Issuance stays limited to the promoted catalog. */
export const managementKeyPermissionWriteSchema = z.enum(MANAGEMENT_KEY_PERMISSIONS);
export const managementKeyPermissionSchema = writerPinned(
  z.enum([...MANAGEMENT_KEY_PERMISSIONS, ...READER_ONLY_MANAGEMENT_KEY_PERMISSIONS]),
  managementKeyPermissionWriteSchema,
);
export type ManagementKeyPermission = z.infer<typeof managementKeyPermissionSchema>;

/** Materialized at issuance. Dependency evaluation must be explicitly selected. */
export const FULL_MANAGEMENT_KEY_PERMISSIONS = MANAGEMENT_KEY_PERMISSIONS.filter(
  (permission) =>
    permission !== "evaluateDependencyChanges" &&
    permission !== "createMalwareReport" &&
    permission !== "createSyntheticAdvisory" &&
    permission !== "retractMalwareReport" &&
    permission !== "retractSyntheticAdvisory" &&
    permission !== "acceptDependencyOverrideDrill" &&
    permission !== "setThirdPartyScannersDrill" &&
    permission !== "armFixVerificationDrillFault" &&
    permission !== "retryDependencyGateDrill" &&
    permission !== "overrideUnevaluatedDependencyGateDrill" &&
    permission !== "armDependencyGateDrillFault",
);
export const MAX_API_KEY_LINEAGE_DEPTH = 8;
export const managementKeyPermissionsSchema = writerPinned(
  z
    .array(managementKeyPermissionSchema)
    .max(MANAGEMENT_KEY_PERMISSIONS.length + READER_ONLY_MANAGEMENT_KEY_PERMISSIONS.length)
    .refine((permissions) => new Set(permissions).size === permissions.length, {
      error: "permissions must be unique",
    }),
  z
    .array(managementKeyPermissionWriteSchema)
    .max(MANAGEMENT_KEY_PERMISSIONS.length)
    .refine((permissions) => new Set(permissions).size === permissions.length, {
      error: "permissions must be unique",
    }),
);

const uniqueIds = <T extends z.ZodType<string>>(schema: T, min = 0) =>
  z
    .array(schema)
    .min(min)
    .max(100)
    .refine((ids) => new Set(ids).size === ids.length, { error: "IDs must be unique" });

/** Installation grants explicitly include future reconciled repositories of those installations. */
export const apiKeyRepositoryAuthoritySchema = z.discriminatedUnion("kind", [
  z.strictObject({ kind: z.literal("explicit"), repo_ids: uniqueIds(repoIdSchema) }),
  z.strictObject({
    kind: z.literal("installation"),
    installation_ids: uniqueIds(installationIdSchema, 1),
  }),
]);
export type ApiKeyRepositoryAuthority = z.infer<typeof apiKeyRepositoryAuthoritySchema>;

export const apiKeyAuthoritySchema = z
  .strictObject({
    kind: apiKeyKindSchema,
    permissions: managementKeyPermissionsSchema,
    repo_authority: apiKeyRepositoryAuthoritySchema,
    parent_key_id: apiKeyIdSchema.nullable(),
    expires_at: utcDateTimeSchema.nullable(),
  })
  .refine((authority) => authority.kind === "management" || authority.permissions.length === 0, {
    error: "Only Management keys hold Management permissions",
    path: ["permissions"],
  })
  .refine(
    (authority) =>
      authority.kind === "management" ||
      (authority.repo_authority.kind === "explicit" &&
        (authority.kind === "registry"
          ? authority.repo_authority.repo_ids.length === 0
          : authority.repo_authority.repo_ids.length > 0)),
    {
      error: "Runtime keys name explicit repositories; Registry keys have none",
      path: ["repo_authority"],
    },
  );
export type ApiKeyAuthority = z.output<typeof apiKeyAuthoritySchema>;
