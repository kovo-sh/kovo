import { z } from "zod";

import { customerAskActionResultSchema, customerAsksResponseSchema } from "../customer-asks.js";
import { customerAskIdSchema, repoIdSchema } from "../ids.js";
import { emptyBodySchema } from "./common.js";
import { defineEndpoint } from "./endpoint.js";

// "Kovo needs X" asks (#8256 V6; SPEC notifications.md "Customer asks"). Reading is like any
// repository read; each button is human-only with no Management grant, so API, Runtime and
// Management keys are all refused.

const source = { kind: "spec_implied", section: "Customer asks" } as const;
const askParams = z.strictObject({ repo: repoIdSchema, ask: customerAskIdSchema });
const humanAdmin = {
  spec: "Only a signed-in repository admin can answer a Kovo ask; API keys cannot",
  actors: ["human_session"],
  tenant: "path_resource",
  repoAuthority: { level: "admin", over: "path_repo" },
} as const;

export const CUSTOMER_ASK_ENDPOINTS = {
  listRepoCustomerAsks: defineEndpoint({
    operationId: "listRepoCustomerAsks",
    area: "recipes",
    method: "GET",
    path: "/v1/repos/{repo}/asks",
    summary: 'List the repository\'s "Kovo needs X" asks and the state of its ask issue.',
    source,
    params: z.strictObject({ repo: repoIdSchema }),
    query: null,
    body: null,
    responses: { 200: customerAsksResponseSchema },
    authorization: {
      managementPermission: "getRecipeVersion",
      spec: "Anyone who can read the repository can see its Kovo asks",
      actors: ["human_session", "api_key_read", "api_key_write"],
      tenant: "path_resource",
      repoAuthority: { level: "read", over: "path_repo" },
    },
  }),
  answerRepoCustomerAsk: defineEndpoint({
    operationId: "answerRepoCustomerAsk",
    area: "recipes",
    method: "POST",
    path: "/v1/repos/{repo}/asks/{ask}/answer",
    summary: "Answer an ask with its one button: open its PR, or allow its build host.",
    source,
    params: askParams,
    query: null,
    body: emptyBodySchema,
    responses: { 200: customerAskActionResultSchema },
    authorization: humanAdmin,
    auditActions: ["recipe.customer_ask_answered"],
    problems: ["conflict", "human_approval_required", "repo_not_enabled"],
  }),
  dismissRepoCustomerAsk: defineEndpoint({
    operationId: "dismissRepoCustomerAsk",
    area: "recipes",
    method: "POST",
    path: "/v1/repos/{repo}/asks/{ask}/dismiss",
    summary: "Dismiss an ask; later runs never raise it again.",
    source,
    params: askParams,
    query: null,
    body: emptyBodySchema,
    responses: { 200: customerAskActionResultSchema },
    authorization: humanAdmin,
    auditActions: ["recipe.customer_ask_answered"],
    problems: ["human_approval_required"],
  }),
};
