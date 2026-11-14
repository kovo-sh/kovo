import { WORKSPACE_ENDPOINTS } from "./workspaces.js";
import { SYNTHETIC_DRILL_ENDPOINTS } from "./synthetic-drill.js";
import type { z } from "zod";

import {
  STAFF_RECORD_ENDPOINTS,
  RECORD_AUTHORIZATION_ENDPOINTS,
  AGENT_RECORD_ENDPOINTS,
} from "./run-records-staff.js";
import { DIAGNOSTIC_ENDPOINTS } from "./diagnostics.js";
import { DEPENDENCY_VERDICT_ENDPOINTS } from "./dependency-verdicts.js";
import { DEPENDENCY_OVERRIDE_ENDPOINTS } from "./dependency-overrides.js";
import { ACCOUNT_ENDPOINTS } from "./accounts.js";
import { ACTIVITY_ENDPOINTS } from "./activity.js";
import { ANALYTICS_CONSENT_ENDPOINTS } from "./analytics-consent.js";
import { API_KEY_ENDPOINTS } from "./api-keys.js";
import { AUDIT_ENDPOINTS } from "./audit.js";
import { EMAIL_PREFERENCE_ENDPOINTS } from "./email-preferences.js";
import { BILLING_ENDPOINTS } from "./billing.js";
import type { AnyEndpoint, ApiArea, HttpMethod } from "./endpoint.js";
import { FINDING_ENDPOINTS } from "./findings.js";
import { FIX_ENDPOINTS } from "./fixes.js";
import { HEALTH_ENDPOINTS } from "./health.js";
import { JOB_ENDPOINTS } from "./jobs.js";
import { ME_ENDPOINTS } from "./me.js";
import { NOTIFICATION_ENDPOINTS } from "./notifications.js";
import { ONBOARDING_ENDPOINTS } from "./onboarding.js";
import { ADMIN_ENDPOINTS } from "./admin.js";
import { WAITLIST_ENDPOINTS } from "./waitlist.js";
import { PROD_VERIFICATION_ENDPOINTS } from "./prod-verification.js";
import { OUTREACH_ADMIN_ENDPOINTS } from "./outreach-admin.js";
import { SUPPORT_ADMIN_ENDPOINTS } from "./support-admin.js";
import { OPERATOR_ENDPOINTS } from "./operator.js";
import { PAUSE_ENDPOINTS } from "./pauses.js";
import { POLICY_ENDPOINTS } from "./policy.js";
import { RECIPE_LIMITED_ENDPOINTS } from "./recipe-limited.js";
import { RECIPE_LABEL_ENDPOINTS } from "./recipe-labels.js";
import { CUSTOMER_ASK_ENDPOINTS } from "./customer-asks.js";
import { EGRESS_ENDPOINTS } from "./egress.js";
import { RECIPE_ENDPOINTS } from "./recipes.js";
import { EXPLAIN_ENDPOINTS } from "./explain.js";
import { REPO_ENDPOINTS } from "./repos.js";
import { PACKAGE_MANAGER_CHOICE_ENDPOINTS } from "./package-manager-choice.js";
import { USAGE_ENDPOINTS } from "./usage.js";
import { WEBHOOK_ENDPOINTS } from "./webhooks.js";

// The typed `/v1` endpoint registry: every SPEC Public API row, the routes SPEC behaviour implies,
// the operator routes and the health probes, keyed by operationId. The control plane registers its
// Hono routes from it and the web client derives request/response types from it.

// Explicit types (each the intersection of the spread objects' own types, so every endpoint keeps
// its exact type): the inferred object types exceed the size the compiler will serialize in the
// declaration output (TS7056).
type AccountsArea = typeof ACCOUNT_ENDPOINTS &
  typeof RECORD_AUTHORIZATION_ENDPOINTS &
  typeof ONBOARDING_ENDPOINTS &
  typeof ANALYTICS_CONSENT_ENDPOINTS &
  typeof ACTIVITY_ENDPOINTS &
  typeof ME_ENDPOINTS;
type ReposArea = typeof REPO_ENDPOINTS &
  typeof EXPLAIN_ENDPOINTS &
  typeof WORKSPACE_ENDPOINTS &
  typeof PACKAGE_MANAGER_CHOICE_ENDPOINTS;
type RecipesArea = typeof RECIPE_ENDPOINTS &
  typeof RECIPE_LABEL_ENDPOINTS &
  typeof RECIPE_LIMITED_ENDPOINTS &
  typeof EGRESS_ENDPOINTS &
  typeof CUSTOMER_ASK_ENDPOINTS;
type NotificationsArea = typeof NOTIFICATION_ENDPOINTS & typeof EMAIL_PREFERENCE_ENDPOINTS;
type OperatorArea = typeof OPERATOR_ENDPOINTS &
  typeof ADMIN_ENDPOINTS &
  typeof WAITLIST_ENDPOINTS &
  typeof PROD_VERIFICATION_ENDPOINTS &
  typeof OUTREACH_ADMIN_ENDPOINTS &
  typeof SUPPORT_ADMIN_ENDPOINTS &
  typeof DIAGNOSTIC_ENDPOINTS &
  typeof STAFF_RECORD_ENDPOINTS &
  typeof AGENT_RECORD_ENDPOINTS;
type DependencyVerdictsArea = typeof DEPENDENCY_VERDICT_ENDPOINTS &
  typeof DEPENDENCY_OVERRIDE_ENDPOINTS &
  typeof SYNTHETIC_DRILL_ENDPOINTS;

// A type alias, not an interface: an object type literal keeps the implicit index signature the
// inferred type had, so `Object.entries`/`Object.values` still see each endpoint's type.
type ApiEndpointsByArea = {
  readonly accounts: AccountsArea;
  readonly repos: ReposArea;
  readonly findings: typeof FINDING_ENDPOINTS;
  readonly recipes: RecipesArea;
  readonly policy: typeof POLICY_ENDPOINTS;
  readonly fixes: typeof FIX_ENDPOINTS;
  readonly jobs: typeof JOB_ENDPOINTS;
  readonly pauses: typeof PAUSE_ENDPOINTS;
  readonly notifications: NotificationsArea;
  readonly "api-keys": typeof API_KEY_ENDPOINTS;
  readonly audit: typeof AUDIT_ENDPOINTS;
  readonly webhooks: typeof WEBHOOK_ENDPOINTS;
  readonly billing: typeof BILLING_ENDPOINTS;
  readonly usage: typeof USAGE_ENDPOINTS;
  readonly operator: OperatorArea;
  readonly health: typeof HEALTH_ENDPOINTS;
  readonly "dependency-verdicts": DependencyVerdictsArea;
};

type AllEndpoints = AccountsArea &
  ReposArea &
  typeof FINDING_ENDPOINTS &
  RecipesArea &
  typeof POLICY_ENDPOINTS &
  typeof FIX_ENDPOINTS &
  typeof JOB_ENDPOINTS &
  typeof PAUSE_ENDPOINTS &
  NotificationsArea &
  typeof API_KEY_ENDPOINTS &
  typeof AUDIT_ENDPOINTS &
  typeof WEBHOOK_ENDPOINTS &
  typeof BILLING_ENDPOINTS &
  typeof USAGE_ENDPOINTS &
  OperatorArea &
  typeof HEALTH_ENDPOINTS &
  DependencyVerdictsArea;

/** Endpoints grouped by area file. */
export const API_ENDPOINTS_BY_AREA: ApiEndpointsByArea = {
  accounts: {
    ...ACCOUNT_ENDPOINTS,
    ...RECORD_AUTHORIZATION_ENDPOINTS,
    ...ONBOARDING_ENDPOINTS,
    ...ANALYTICS_CONSENT_ENDPOINTS,
    ...ACTIVITY_ENDPOINTS,
    ...ME_ENDPOINTS,
  },
  repos: {
    ...REPO_ENDPOINTS,
    ...EXPLAIN_ENDPOINTS,
    ...WORKSPACE_ENDPOINTS,
    ...PACKAGE_MANAGER_CHOICE_ENDPOINTS,
  },
  findings: FINDING_ENDPOINTS,
  recipes: {
    ...RECIPE_ENDPOINTS,
    ...RECIPE_LABEL_ENDPOINTS,
    ...RECIPE_LIMITED_ENDPOINTS,
    ...EGRESS_ENDPOINTS,
    ...CUSTOMER_ASK_ENDPOINTS,
  },
  policy: POLICY_ENDPOINTS,
  fixes: FIX_ENDPOINTS,
  jobs: JOB_ENDPOINTS,
  pauses: PAUSE_ENDPOINTS,
  notifications: { ...NOTIFICATION_ENDPOINTS, ...EMAIL_PREFERENCE_ENDPOINTS },
  "api-keys": API_KEY_ENDPOINTS,
  audit: AUDIT_ENDPOINTS,
  webhooks: WEBHOOK_ENDPOINTS,
  billing: BILLING_ENDPOINTS,
  usage: USAGE_ENDPOINTS,
  operator: {
    ...OPERATOR_ENDPOINTS,
    ...ADMIN_ENDPOINTS,
    ...WAITLIST_ENDPOINTS,
    ...PROD_VERIFICATION_ENDPOINTS,
    ...OUTREACH_ADMIN_ENDPOINTS,
    ...SUPPORT_ADMIN_ENDPOINTS,
    ...DIAGNOSTIC_ENDPOINTS,
    ...STAFF_RECORD_ENDPOINTS,
    ...AGENT_RECORD_ENDPOINTS,
  },
  health: HEALTH_ENDPOINTS,
  "dependency-verdicts": {
    ...DEPENDENCY_VERDICT_ENDPOINTS,
    ...DEPENDENCY_OVERRIDE_ENDPOINTS,
    ...SYNTHETIC_DRILL_ENDPOINTS,
  },
} as const satisfies Record<ApiArea, Readonly<Record<string, AnyEndpoint>>>;

/** Every endpoint by operationId. */
export const API_ENDPOINTS: AllEndpoints = {
  ...DEPENDENCY_OVERRIDE_ENDPOINTS,
  ...WORKSPACE_ENDPOINTS,
  ...ACCOUNT_ENDPOINTS,
  ...RECORD_AUTHORIZATION_ENDPOINTS,
  ...ONBOARDING_ENDPOINTS,
  ...ANALYTICS_CONSENT_ENDPOINTS,
  ...ACTIVITY_ENDPOINTS,
  ...ME_ENDPOINTS,
  ...REPO_ENDPOINTS,
  ...EXPLAIN_ENDPOINTS,
  ...PACKAGE_MANAGER_CHOICE_ENDPOINTS,
  ...FINDING_ENDPOINTS,
  ...RECIPE_ENDPOINTS,
  ...RECIPE_LABEL_ENDPOINTS,
  ...RECIPE_LIMITED_ENDPOINTS,
  ...EGRESS_ENDPOINTS,
  ...CUSTOMER_ASK_ENDPOINTS,
  ...POLICY_ENDPOINTS,
  ...FIX_ENDPOINTS,
  ...JOB_ENDPOINTS,
  ...PAUSE_ENDPOINTS,
  ...NOTIFICATION_ENDPOINTS,
  ...EMAIL_PREFERENCE_ENDPOINTS,
  ...API_KEY_ENDPOINTS,
  ...AUDIT_ENDPOINTS,
  ...WEBHOOK_ENDPOINTS,
  ...BILLING_ENDPOINTS,
  ...USAGE_ENDPOINTS,
  ...OPERATOR_ENDPOINTS,
  ...ADMIN_ENDPOINTS,
  ...WAITLIST_ENDPOINTS,
  ...PROD_VERIFICATION_ENDPOINTS,
  ...OUTREACH_ADMIN_ENDPOINTS,
  ...SUPPORT_ADMIN_ENDPOINTS,
  ...DIAGNOSTIC_ENDPOINTS,
  ...STAFF_RECORD_ENDPOINTS,
  ...AGENT_RECORD_ENDPOINTS,
  ...HEALTH_ENDPOINTS,
  ...DEPENDENCY_VERDICT_ENDPOINTS,
  ...SYNTHETIC_DRILL_ENDPOINTS,
} as const;

export type ApiEndpoints = typeof API_ENDPOINTS;
export type OperationId = keyof ApiEndpoints;

/** Every endpoint, in registry order. */
export const API_ENDPOINT_LIST: readonly AnyEndpoint[] = Object.values(API_ENDPOINTS);

/** The endpoint registered for a method and path template, if any. */
export function findEndpoint(method: HttpMethod, pathTemplate: string): AnyEndpoint | undefined {
  return API_ENDPOINT_LIST.find(
    (endpoint) => endpoint.method === method && endpoint.path === pathTemplate,
  );
}

// ---- Types for clients and route handlers ----

type InputOf<Schema> = Schema extends z.ZodType ? z.input<Schema> : undefined;
type OutputOf<Schema> = Schema extends z.ZodType ? z.output<Schema> : undefined;

/** Path parameters as sent (strings). */
export type EndpointParams<Op extends OperationId> = InputOf<ApiEndpoints[Op]["params"]>;
/** Query parameters as sent. */
export type EndpointQuery<Op extends OperationId> = InputOf<ApiEndpoints[Op]["query"]>;
/** The JSON request body as sent (money as strings, timestamps as ISO strings). */
export type EndpointBody<Op extends OperationId> = InputOf<ApiEndpoints[Op]["body"]>;
/** The parsed request body a handler receives. */
export type EndpointParsedBody<Op extends OperationId> = OutputOf<ApiEndpoints[Op]["body"]>;
/** The success statuses an endpoint declares. */
export type EndpointStatus<Op extends OperationId> = keyof ApiEndpoints[Op]["responses"] & number;
/** A decoded success response (money as `bigint`, timestamps as `Date`). */
export type EndpointResponse<
  Op extends OperationId,
  Status extends EndpointStatus<Op> = EndpointStatus<Op>,
> = OutputOf<ApiEndpoints[Op]["responses"][Status]>;
/** A success response in its JSON wire form. */
export type EndpointResponseJson<
  Op extends OperationId,
  Status extends EndpointStatus<Op> = EndpointStatus<Op>,
> = InputOf<ApiEndpoints[Op]["responses"][Status]>;
