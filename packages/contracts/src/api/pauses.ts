import { z } from "zod";

import { ACCOUNT_ADMIN_ROLES } from "../enums/accounts.js";
import { accountIdSchema, installationIdSchema, repoIdSchema } from "../ids.js";
import { whenValid } from "../primitives.js";
import { accountResponseSchema, installationSummarySchema } from "./accounts.js";
import { pauseReasonCodeSchema } from "../enums/repos.js";
import { defineEndpoint, type Escalation } from "./endpoint.js";
import { repoResponseSchema } from "./repos.js";

// Merge pauses at repo, account and installation scope (SPEC "Repo, account, installation, and
// global pauses independently block merges"; "merge pauses leave scanning/alerts and funded PR
// preparation active"; Public API rows 18, 23, 24). The global pause is an operator route.

const ROW_REPO = "Repo authority; keys may pause, never resume into autopilot";
const ROW_ACCOUNT =
  "Human owner/admin for account pause; clearing does not override repository gates";
const ROW_INSTALLATION = "Verified authority over affected repos; resume rechecks activation gates";

const PAUSERS = ["human_session", "api_key_write"] as const;
const NO_KEY_RESUME_INTO_AUTOPILOT: readonly Escalation[] = [
  { when: "resumes_into_autopilot", requires: { humanSession: true }, unmet: "deny" },
];

const repoParams = z.strictObject({ repo: repoIdSchema });
const accountParams = z.strictObject({ account: accountIdSchema });
const installationParams = z.strictObject({ installation: installationIdSchema });

export const installationResponseSchema = z.strictObject({
  installation: installationSummarySchema,
});

/**
 * Every pause names why, as a closed code (`PAUSE_REASON_CODES`): "log actor/reason and alert until
 * cleared", without free text in audit or alert paths.
 */
export const pauseBodySchema = z.strictObject({ reason: pauseReasonCodeSchema });

export const PAUSE_ENDPOINTS = {
  pauseRepo: defineEndpoint({
    operationId: "pauseRepo",
    area: "pauses",
    method: "POST",
    path: "/v1/repos/{repo}/pause",
    summary: "Pause merges for a repository.",
    source: { kind: "spec_row", path: "/v1/repos/{repo}/pause" },
    auditActions: ["repo.paused"],
    params: repoParams,
    query: null,
    body: pauseBodySchema,
    responses: {
      200: repoResponseSchema.refine((body) => body.repo.pauses.some((p) => p.scope === "repo"), {
        ...whenValid,
        error: "the repository is paused",
      }),
    },
    authorization: {
      spec: ROW_REPO,
      actors: PAUSERS,
      tenant: "path_resource",
      repoAuthority: { level: "admin", over: "path_repo" },
    },
  }),
  resumeRepo: defineEndpoint({
    operationId: "resumeRepo",
    area: "pauses",
    method: "DELETE",
    path: "/v1/repos/{repo}/pause",
    summary: "Clear a repository pause; the effective mode is recomputed from every other gate.",
    source: { kind: "spec_row", path: "/v1/repos/{repo}/pause" },
    auditActions: ["repo.resumed"],
    params: repoParams,
    query: null,
    body: null,
    responses: {
      200: repoResponseSchema.refine((body) => !body.repo.pauses.some((p) => p.scope === "repo"), {
        ...whenValid,
        error: "the repository pause is cleared",
      }),
    },
    authorization: {
      spec: ROW_REPO,
      actors: PAUSERS,
      tenant: "path_resource",
      repoAuthority: { level: "admin", over: "path_repo" },
      escalations: NO_KEY_RESUME_INTO_AUTOPILOT,
    },
  }),
  pauseAccount: defineEndpoint({
    operationId: "pauseAccount",
    area: "pauses",
    method: "POST",
    path: "/v1/accounts/{account}/pause",
    summary: "Pause merges for every repository of the account.",
    source: { kind: "spec_row", path: "/v1/accounts/{account}/pause" },
    auditActions: ["account.paused"],
    params: accountParams,
    query: null,
    body: pauseBodySchema,
    responses: {
      200: accountResponseSchema.refine((body) => body.account.pause !== null, {
        ...whenValid,
        error: "the account is paused",
      }),
    },
    authorization: {
      spec: ROW_ACCOUNT,
      actors: ["human_session"],
      tenant: "path_account",
      accountRoles: ACCOUNT_ADMIN_ROLES,
    },
  }),
  resumeAccount: defineEndpoint({
    operationId: "resumeAccount",
    area: "pauses",
    method: "DELETE",
    path: "/v1/accounts/{account}/pause",
    summary: "Clear the account pause; repository gates still apply.",
    source: { kind: "spec_row", path: "/v1/accounts/{account}/pause" },
    auditActions: ["account.resumed"],
    params: accountParams,
    query: null,
    body: null,
    responses: {
      200: accountResponseSchema.refine((body) => body.account.pause === null, {
        ...whenValid,
        error: "the account pause is cleared",
      }),
    },
    authorization: {
      spec: ROW_ACCOUNT,
      actors: ["human_session"],
      tenant: "path_account",
      accountRoles: ACCOUNT_ADMIN_ROLES,
    },
  }),
  pauseInstallation: defineEndpoint({
    operationId: "pauseInstallation",
    area: "pauses",
    method: "POST",
    path: "/v1/installations/{installation}/pause",
    summary: "Pause merges for every repository of a GitHub App installation.",
    source: { kind: "spec_row", path: "/v1/installations/{installation}/pause" },
    auditActions: ["installation.paused"],
    params: installationParams,
    query: null,
    body: pauseBodySchema,
    responses: {
      200: installationResponseSchema.refine((body) => body.installation.paused_at !== null, {
        ...whenValid,
        error: "the installation is paused",
      }),
    },
    authorization: {
      spec: ROW_INSTALLATION,
      actors: PAUSERS,
      tenant: "path_resource",
      repoAuthority: { level: "admin", over: "installation_repos" },
    },
  }),
  resumeInstallation: defineEndpoint({
    operationId: "resumeInstallation",
    area: "pauses",
    method: "DELETE",
    path: "/v1/installations/{installation}/pause",
    summary: "Clear an installation pause after rechecking activation gates.",
    source: { kind: "spec_row", path: "/v1/installations/{installation}/pause" },
    auditActions: ["installation.resumed"],
    params: installationParams,
    query: null,
    body: null,
    responses: {
      200: installationResponseSchema.refine((body) => body.installation.paused_at === null, {
        ...whenValid,
        error: "the installation pause is cleared",
      }),
    },
    authorization: {
      spec: ROW_INSTALLATION,
      actors: PAUSERS,
      tenant: "path_resource",
      repoAuthority: { level: "admin", over: "installation_repos" },
      escalations: NO_KEY_RESUME_INTO_AUTOPILOT,
    },
  }),
} as const;
