import { z } from "zod";

import {
  accountTypeSchema,
  onboardingStateSchema,
  type OnboardingState,
} from "../enums/accounts.js";
import {
  githubAccountIdSchema,
  githubInstallationIdSchema,
  onboardingRequestIdSchema,
} from "../ids.js";
import { githubAccountLoginMatchesType, githubLoginSchema } from "../github.js";
import { whenValid } from "../primitives.js";
import { utcDateTimeSchema } from "../time.js";
import { emptyBodySchema, userRefSchema } from "./common.js";
import { defineEndpoint, type AuthorizationInit } from "./endpoint.js";

// Onboarding requests and the GitHub administrator's decision on ambiguous ownership (SPEC
// "First-run flow" step 2; "Accounts and permissions": "A GitHub-approved installation must be
// bound to the initiating user's onboarding request. An unprivileged installation requester waits
// for approval, and ambiguous ownership requires confirmation from an authorized GitHub
// administrator."). Starting a request and binding the installation are account routes
// (accounts.ts); the administrator, who need not belong to the Kovo account, decides here.

const onboardingRequestShape = {
  id: onboardingRequestIdSchema,
  state: onboardingStateSchema,
  initiated_by: userRefSchema,
  created_at: utcDateTimeSchema,
  expires_at: utcDateTimeSchema,
};

function expiresAfterCreation(request: { created_at: Date; expires_at: Date }): boolean {
  return request.expires_at.getTime() > request.created_at.getTime();
}

const EXPIRY_ORDER = {
  ...whenValid,
  error: "an onboarding request expires after it is created",
  path: ["expires_at"],
};

/**
 * An onboarding request: "A GitHub-approved installation must be bound to the initiating user's
 * onboarding request. An unprivileged installation requester waits for approval, and ambiguous
 * ownership requires confirmation from an authorized GitHub administrator."
 */
export const onboardingRequestSchema = z
  .strictObject(onboardingRequestShape)
  .refine(expiresAfterCreation, EXPIRY_ORDER);
export type OnboardingRequest = z.output<typeof onboardingRequestSchema>;

/** The GitHub account an onboarding request would link (keyed by its immutable ID). */
export const githubAccountRefSchema = z
  .strictObject({
    id: githubAccountIdSchema,
    login: githubLoginSchema,
    type: accountTypeSchema,
  })
  .refine((account) => githubAccountLoginMatchesType(account.login, account.type), {
    ...whenValid,
    error: "an organization login has no underscore",
    path: ["login"],
  });

/**
 * States of a request that is bound to an installation, so that a GitHub administrator of its
 * account can review it: waiting for the decision, or decided (linked, rejected) or lapsed.
 */
export const REVIEWABLE_ONBOARDING_STATES = [
  "awaiting_admin_confirmation",
  "linked",
  "rejected",
  "expired",
] as const satisfies readonly OnboardingState[];
const REVIEWABLE: ReadonlySet<OnboardingState> = new Set(REVIEWABLE_ONBOARDING_STATES);

/**
 * A request as the confirming GitHub administrator reviews it: who asked, and which GitHub account
 * and installation the Kovo account would be linked to. The administrator is not necessarily a
 * member of the Kovo account, so nothing else about the account is shown.
 */
export const onboardingReviewSchema = z
  .strictObject({
    ...onboardingRequestShape,
    github_account: githubAccountRefSchema,
    github_installation_id: githubInstallationIdSchema,
  })
  .refine(expiresAfterCreation, EXPIRY_ORDER)
  .refine((review) => REVIEWABLE.has(review.state), {
    ...whenValid,
    error: "only a request bound to an installation is reviewed",
    path: ["state"],
  });
export type OnboardingReview = z.output<typeof onboardingReviewSchema>;

const onboardingReviewResponseSchema = z.strictObject({ onboarding: onboardingReviewSchema });

function decidedAs(state: OnboardingState) {
  return onboardingReviewResponseSchema.refine((body) => body.onboarding.state === state, {
    ...whenValid,
    error: `the request is ${state}`,
    path: ["onboarding", "state"],
  });
}

// ---- Endpoints ----

const ROW_AMBIGUOUS_OWNERSHIP =
  "An unprivileged installation requester waits for approval, and ambiguous ownership requires confirmation from an authorized GitHub administrator.";

/**
 * A human GitHub administrator of the request's GitHub account, verified fresh ("revalidate
 * sensitive actions, joining/linking, and role changes at execution time"); Kovo membership is
 * neither needed nor sufficient. A request not yet bound to an installation has no GitHub account
 * to administer and is `not_found` for everyone.
 */
const GITHUB_ADMIN: AuthorizationInit = {
  spec: ROW_AMBIGUOUS_OWNERSHIP,
  actors: ["human_session"],
  tenant: "path_resource",
  accountMember: false,
  githubAccountAdmin: true,
};

const onboardingParams = z.strictObject({ id: onboardingRequestIdSchema });

export const ONBOARDING_ENDPOINTS = {
  getOnboardingRequest: defineEndpoint({
    operationId: "getOnboardingRequest",
    area: "accounts",
    method: "GET",
    path: "/v1/onboarding/{id}",
    summary:
      "Review an onboarding request as an administrator of the GitHub account it would link.",
    source: { kind: "spec_implied", section: "Accounts and permissions" },
    params: onboardingParams,
    query: null,
    body: null,
    responses: { 200: onboardingReviewResponseSchema },
    authorization: GITHUB_ADMIN,
    // The installation is re-read first: its current login names the organization to verify.
    problems: ["upstream_error"],
  }),
  confirmOnboarding: defineEndpoint({
    operationId: "confirmOnboarding",
    area: "accounts",
    method: "POST",
    path: "/v1/onboarding/{id}/confirm",
    summary:
      "Confirm an ambiguous-ownership request: the Kovo account is linked to the GitHub account and its installation.",
    source: { kind: "spec_implied", section: "Accounts and permissions" },
    auditActions: ["onboarding.confirmed", "account.linked", "installation.linked"],
    params: onboardingParams,
    query: null,
    body: emptyBodySchema,
    responses: { 200: decidedAs("linked") },
    authorization: GITHUB_ADMIN,
    problems: ["account_link_conflict", "onboarding_mismatch", "conflict", "upstream_error"],
  }),
  rejectOnboarding: defineEndpoint({
    operationId: "rejectOnboarding",
    area: "accounts",
    method: "POST",
    path: "/v1/onboarding/{id}/reject",
    summary: "Reject an ambiguous-ownership request; the Kovo account stays pending and unlinked.",
    source: { kind: "spec_implied", section: "Accounts and permissions" },
    auditActions: ["onboarding.rejected"],
    params: onboardingParams,
    query: null,
    body: emptyBodySchema,
    responses: { 200: decidedAs("rejected") },
    authorization: GITHUB_ADMIN,
    // An installation that is gone or now belongs to another GitHub account has nothing to reject.
    problems: ["onboarding_mismatch", "conflict", "upstream_error"],
  }),
} as const;
