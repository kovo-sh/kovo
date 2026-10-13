import { z } from "zod";

import {
  ACCOUNT_ADMIN_ROLES,
  accountLinkStateSchema,
  accountRoleSchema,
  accountTypeSchema,
  installationStateSchema,
  invitationStateSchema,
  membershipStateSchema,
  planSchema,
  type AccountRole,
} from "../enums/accounts.js";
import { notificationStatusSchema } from "../enums/notifications.js";
import { pauseReasonCodeSchema } from "../enums/repos.js";
import {
  accountIdSchema,
  githubAccountIdSchema,
  githubInstallationIdSchema,
  githubUserIdSchema,
  installationIdSchema,
  invitationIdSchema,
  onboardingRequestIdSchema,
  userIdSchema,
} from "../ids.js";
import { pageSchema, paginationQueryShape } from "../pagination.js";
import { countSchema, whenValid } from "../primitives.js";
import { KOVO_SECRET_TOKEN_PREFIXES } from "../secret-tokens.js";
import { DURATIONS, utcDateTimeSchema } from "../time.js";
import { githubAccountLoginMatchesType, githubLoginSchema } from "../github.js";
import { emptyBodySchema, httpsUrlSchema, oneTimeSecretSchema, userRefSchema } from "./common.js";
import { defineEndpoint } from "./endpoint.js";
import { onboardingRequestSchema } from "./onboarding.js";

// `/v1/accounts`: joined accounts, pending-account creation, GitHub linking, invitations and
// members (SPEC "First-run flow", "Accounts and permissions", Public API rows 1–4).

// ---- Shapes ----

/** The account's GitHub App installation (a GitHub account installs an app at most once). */
export const installationSummarySchema = z
  .strictObject({
    id: installationIdSchema,
    github_installation_id: githubInstallationIdSchema,
    state: installationStateSchema,
    paused_at: utcDateTimeSchema.nullable(),
    /** Why the installation's merges are paused; set exactly with `paused_at`. */
    pause_reason: pauseReasonCodeSchema.nullable(),
    /** "If no deliverable address exists, show `no_recipient` prominently". */
    notification_status: notificationStatusSchema,
  })
  .superRefine((installation, ctx) => {
    if ((installation.paused_at === null) !== (installation.pause_reason === null)) {
      ctx.addIssue({
        code: "custom",
        path: ["pause_reason"],
        message: "a pause records its time and reason together",
      });
    }
    // The state takes deleted, then suspended, then paused precedence (enums/accounts.ts).
    if (installation.state === "paused" && installation.paused_at === null) {
      ctx.addIssue({
        code: "custom",
        path: ["paused_at"],
        message: "a paused installation has paused_at",
      });
    }
    if (installation.state === "active" && installation.paused_at !== null) {
      ctx.addIssue({
        code: "custom",
        path: ["state"],
        message: "an installation with paused_at is not active",
      });
    }
  }, whenValid);
export type InstallationSummary = z.output<typeof installationSummarySchema>;

/** An account-level merge pause ("Human owner/admin for account pause"). */
export const accountPauseSchema = z.strictObject({
  paused_at: utcDateTimeSchema,
  reason: pauseReasonCodeSchema,
});

/**
 * An account as one of its members sees it. A pending account has no GitHub identity ("Creating a
 * pending account does not reserve a GitHub organization"); a linked account carries the immutable
 * GitHub account ID it is keyed by.
 */
export const accountSchema = z
  .strictObject({
    id: accountIdSchema,
    link_state: accountLinkStateSchema,
    github_account_id: githubAccountIdSchema.nullable(),
    login: githubLoginSchema.nullable(),
    account_type: accountTypeSchema.nullable(),
    /** The caller's own role in this account. */
    role: accountRoleSchema,
    plan: planSchema,
    pause: accountPauseSchema.nullable(),
    installation: installationSummarySchema.nullable(),
    /** The latest onboarding request, for "onboarding/install approval status". */
    onboarding: onboardingRequestSchema.nullable(),
    created_at: utcDateTimeSchema,
    /**
     * How many of the account's repositories are protected (taking a protected slot), whoever can
     * read them: a count, never which ones ("Billing-only views expose counts and charges, not
     * private repository names"). The setup checklist's "next required action" follows it, also
     * for a member who cannot read any of the repositories.
     */
    protected_repos: countSchema,
    /**
     * How many repository admins' protection selections wait for a billing-authorized capacity
     * grant ("a repository admin authorizes protection, and a billing-authorized actor approves
     * additional capacity"), as a count.
     */
    pending_protection_requests: countSchema,
  })
  .superRefine((account, ctx) => {
    if (
      account.link_state !== "linked" &&
      (account.protected_repos > 0 || account.pending_protection_requests > 0)
    ) {
      ctx.addIssue({
        code: "custom",
        path: ["protected_repos"],
        message: "a pending account has no repositories to protect",
      });
    }
    const identity = [account.github_account_id, account.login, account.account_type];
    const linked = account.link_state === "linked";
    if (linked ? identity.includes(null) : identity.some((value) => value !== null)) {
      ctx.addIssue({
        code: "custom",
        path: ["link_state"],
        message: "a linked account has its GitHub identity and a pending one has none",
      });
    }
    if (
      account.login !== null &&
      account.account_type !== null &&
      !githubAccountLoginMatchesType(account.login, account.account_type)
    ) {
      ctx.addIssue({
        code: "custom",
        path: ["login"],
        message: "an organization login has no underscore",
      });
    }
    if (!linked && account.installation !== null) {
      ctx.addIssue({
        code: "custom",
        path: ["installation"],
        message: "a pending account has no installation",
      });
    }
  }, whenValid);
export type Account = z.output<typeof accountSchema>;

/** `{ account }` responses. */
export const accountResponseSchema = z.strictObject({ account: accountSchema });

/**
 * A deleted account's retention schedule. SPEC: "Kovo account deletion requires billing
 * settlement/cancellation handling and the retention schedule above"; "On account deletion, remove
 * non-financial operational metadata within 30 days; audit/financial exceptions remain
 * access-restricted under their explicit schedule."
 */
export const accountDeletionSchema = z
  .strictObject({
    account_id: accountIdSchema,
    deleted_at: utcDateTimeSchema,
    /** When the operational purge is complete at the latest (30 days after deletion). */
    purge_due_at: utcDateTimeSchema,
  })
  .refine(
    (deletion) =>
      deletion.purge_due_at.getTime() - deletion.deleted_at.getTime() ===
      DURATIONS.accountDeletionPurge,
    { ...whenValid, error: "the purge completes 30 days after deletion", path: ["purge_due_at"] },
  );
export type AccountDeletion = z.output<typeof accountDeletionSchema>;

/**
 * Roles an invitation can grant: "Account owners may delegate account administration and billing
 * roles through expiring, single-use invitations"; "joining never grants account ownership".
 */
export const INVITABLE_ROLES = [
  "admin",
  "billing_manager",
  "member",
] as const satisfies readonly AccountRole[];
export const invitableRoleSchema = z.enum(INVITABLE_ROLES);

/** Invitation lifetime in hours: default three days, at most seven. */
export const INVITATION_TTL_HOURS = { default: 72, min: 1, max: 168 } as const;

/** The single-use invitation secret, shown once to the inviter (`kinv_…`). */
export const invitationTokenSchema = oneTimeSecretSchema(
  KOVO_SECRET_TOKEN_PREFIXES.invitationToken,
  "InvitationToken",
);
export type InvitationToken = z.infer<typeof invitationTokenSchema>;

/**
 * An invitation. `invitee_github_user_id`, when set, binds it to one verified GitHub user: a leaked
 * link then grants nothing to anyone else ("accepted by a verified user").
 */
export const invitationSchema = z
  .strictObject({
    id: invitationIdSchema,
    role: invitableRoleSchema,
    state: invitationStateSchema,
    invited_by: userRefSchema,
    invitee_github_user_id: githubUserIdSchema.nullable(),
    expires_at: utcDateTimeSchema,
    accepted_by: userRefSchema.nullable(),
  })
  .superRefine((invitation, ctx) => {
    const accepted = invitation.accepted_by;
    if ((invitation.state === "accepted") !== (accepted !== null)) {
      ctx.addIssue({
        code: "custom",
        path: ["accepted_by"],
        message: "exactly accepted invitations name who accepted them",
      });
    }
    const invitee = invitation.invitee_github_user_id;
    if (accepted !== null && invitee !== null && accepted.github_user_id !== invitee) {
      ctx.addIssue({
        code: "custom",
        path: ["accepted_by"],
        message: "a bound invitation is accepted only by its invitee",
      });
    }
  }, whenValid);
export type Invitation = z.output<typeof invitationSchema>;

export const createInvitationBodySchema = z.strictObject({
  role: invitableRoleSchema,
  expires_in_hours: z
    .int()
    .min(INVITATION_TTL_HOURS.min)
    .max(INVITATION_TTL_HOURS.max)
    .default(INVITATION_TTL_HOURS.default),
  /** Optional binding to the one GitHub user (immutable ID, not login) who may accept it. */
  invitee_github_user_id: githubUserIdSchema.exactOptional(),
});

/** Joining or accepting never grants ownership ("never grants account ownership … automatically"). */
function joinedAs(roles: readonly AccountRole[], error: string) {
  const allowed: ReadonlySet<AccountRole> = new Set(roles);
  return accountResponseSchema.refine((body) => allowed.has(body.account.role), {
    ...whenValid,
    error,
    path: ["account", "role"],
  });
}

/** A membership; its state follows `accepted_at` and `revoked_at`. */
export const memberSchema = z
  .strictObject({
    user: userRefSchema,
    role: accountRoleSchema,
    state: membershipStateSchema,
    invited_by: userRefSchema.nullable(),
    accepted_at: utcDateTimeSchema.nullable(),
    revoked_at: utcDateTimeSchema.nullable(),
  })
  .refine(
    (member) => {
      if (member.revoked_at !== null) return member.state === "revoked";
      return member.state === (member.accepted_at === null ? "pending" : "active");
    },
    { ...whenValid, error: "state must follow accepted_at and revoked_at", path: ["state"] },
  );
export type Member = z.output<typeof memberSchema>;

export const memberResponseSchema = z.strictObject({ member: memberSchema });

/**
 * The GitHub App setup callback bound to the caller's onboarding request. GitHub reports
 * `setup_action=request` without an installation when an unprivileged user asked for approval.
 */
export const linkAccountBodySchema = z.discriminatedUnion("setup_action", [
  z.strictObject({
    onboarding_request_id: onboardingRequestIdSchema,
    setup_action: z.literal("install"),
    github_installation_id: githubInstallationIdSchema,
  }),
  z.strictObject({
    onboarding_request_id: onboardingRequestIdSchema,
    setup_action: z.literal("update"),
    github_installation_id: githubInstallationIdSchema,
  }),
  z.strictObject({
    onboarding_request_id: onboardingRequestIdSchema,
    setup_action: z.literal("request"),
  }),
]);

/**
 * The account's "no third-party scanners" setting (SPEC "Third-party scanner opt-out"): while
 * `opted_out`, Kovo never looks up or queues the account's artifacts with a third-party scanner.
 * The same shape is the `PUT` body and both responses.
 */
export const thirdPartyScannersSchema = z.strictObject({ opted_out: z.boolean() });
export type ThirdPartyScanners = z.output<typeof thirdPartyScannersSchema>;

/** The GitHub App installation page, carrying the onboarding request ID as `state`. */
export const githubInstallUrlSchema = httpsUrlSchema(/^github\.com$/);

// ---- Endpoints ----

const HUMAN = ["human_session"] as const;
const ROW_ACCOUNTS = "Human session; list joined accounts/create pending account";
const ROW_LINK = "Verified installation/onboarding binding; cannot claim an existing account";
const ROW_INVITATIONS = "Human owner/admin; expiring scoped invitations";
const ACCOUNT_DELETION_SPEC =
  "Kovo account deletion requires billing settlement/cancellation handling and the retention schedule above.";
const ROW_MEMBERS =
  "Owner/admin for changes; no GitHub privilege elevation; preserve an account owner";
/**
 * SPEC Public API row; agent decision (2026-10-09), pending owner review #1120: members read it,
 * owners and admins change it, and no API key (Runtime or Management) does either.
 */
const ROW_THIRD_PARTY_SCANNERS =
  "Human member reads; human owner/admin changes; audited; API keys refused";
const OWNER_CHANGES = [
  {
    when: "changes_owner_membership",
    requires: { accountRoles: ["owner"] },
    unmet: "deny",
  },
] as const;

const accountParams = z.strictObject({ account: accountIdSchema });
const memberParams = z.strictObject({ account: accountIdSchema, user: userIdSchema });

export const ACCOUNT_ENDPOINTS = {
  listAccounts: defineEndpoint({
    operationId: "listAccounts",
    area: "accounts",
    method: "GET",
    path: "/v1/accounts",
    summary: "List the accounts the signed-in user has joined.",
    source: { kind: "spec_row", path: "/v1/accounts" },
    params: null,
    query: z.strictObject(paginationQueryShape),
    body: null,
    responses: { 200: pageSchema(accountSchema) },
    authorization: { spec: ROW_ACCOUNTS, actors: HUMAN, tenant: "user" },
    paginated: true,
  }),
  createAccount: defineEndpoint({
    operationId: "createAccount",
    area: "accounts",
    method: "POST",
    path: "/v1/accounts",
    summary: "Create a pending account owned by the caller; it reserves no GitHub organization.",
    source: { kind: "spec_row", path: "/v1/accounts" },
    auditActions: ["account.created"],
    params: null,
    query: null,
    body: emptyBodySchema,
    responses: { 201: accountResponseSchema },
    authorization: { spec: ROW_ACCOUNTS, actors: HUMAN, tenant: "user" },
    idempotency: "accepted",
  }),
  deleteAccount: defineEndpoint({
    operationId: "deleteAccount",
    area: "accounts",
    method: "DELETE",
    path: "/v1/accounts/{account}",
    summary:
      "Delete the account once billing is settled; access ends now and operational data is purged within 30 days.",
    source: { kind: "spec_implied", section: "Retention" },
    auditActions: ["account.deleted"],
    params: accountParams,
    query: null,
    body: null,
    responses: { 202: z.strictObject({ deletion: accountDeletionSchema }) },
    authorization: {
      spec: ACCOUNT_DELETION_SPEC,
      actors: HUMAN,
      tenant: "path_account",
      accountRoles: ["owner"],
    },
    // A paid subscription that has not ended, or overage and reservations not yet settled.
    problems: ["conflict"],
  }),
  startOnboarding: defineEndpoint({
    operationId: "startOnboarding",
    area: "accounts",
    method: "POST",
    path: "/v1/accounts/{account}/onboarding",
    summary: "Start an onboarding request and return the GitHub App install URL bound to it.",
    source: { kind: "spec_implied", section: "First-run flow" },
    auditActions: ["onboarding.started"],
    params: accountParams,
    query: null,
    body: emptyBodySchema,
    responses: {
      201: z.strictObject({
        onboarding: onboardingRequestSchema,
        install_url: githubInstallUrlSchema,
      }),
    },
    authorization: {
      spec: "Install the GitHub App or request GitHub approval. Link the stable GitHub account ID only after verifying installation authorization and the initiating user.",
      actors: HUMAN,
      tenant: "path_account",
      accountRoles: ACCOUNT_ADMIN_ROLES,
    },
  }),
  linkAccount: defineEndpoint({
    operationId: "linkAccount",
    area: "accounts",
    method: "POST",
    path: "/v1/accounts/{account}/link",
    summary:
      "Bind a verified GitHub App installation to the caller's onboarding request; ambiguous ownership waits for a GitHub administrator (`/v1/onboarding/{id}/confirm`).",
    source: { kind: "spec_row", path: "/v1/accounts/{account}/link" },
    auditActions: ["account.linked", "installation.linked"],
    params: accountParams,
    query: null,
    body: linkAccountBodySchema,
    responses: { 200: accountResponseSchema },
    authorization: {
      spec: ROW_LINK,
      actors: HUMAN,
      tenant: "path_account",
      accountRoles: ACCOUNT_ADMIN_ROLES,
    },
    problems: [
      "account_link_conflict",
      "installation_not_authorized",
      "onboarding_mismatch",
      "conflict",
      "upstream_error",
    ],
  }),
  joinAccount: defineEndpoint({
    operationId: "joinAccount",
    area: "accounts",
    method: "POST",
    path: "/v1/accounts/join",
    summary: "Join the account linked to a GitHub account through verified repository access.",
    source: { kind: "spec_implied", section: "Accounts and permissions" },
    auditActions: ["member.joined"],
    params: null,
    query: null,
    body: z.strictObject({ github_account_id: githubAccountIdSchema }),
    responses: {
      // Nor billing authority: joining through repository access makes a plain member.
      200: joinedAs(["member"], "joining through repository access makes a member"),
    },
    authorization: {
      spec: "Existing accounts can be joined through verified repo access or invitation, but joining never grants account ownership or billing authority automatically.",
      actors: HUMAN,
      tenant: "user",
      // Explicit collaborator access, never public visibility: otherwise any GitHub user could join
      // the account that protects a public repository (docs/decisions/ports.md).
      repoAuthority: { level: "explicit_read", over: "any_account_repo" },
    },
    problems: ["not_found", "conflict", "upstream_error"],
  }),
  acceptInvitation: defineEndpoint({
    operationId: "acceptInvitation",
    area: "accounts",
    method: "POST",
    path: "/v1/invitations/accept",
    summary:
      "Accept a single-use invitation as the signed-in, verified user; a bound invitation only as its invitee.",
    source: { kind: "spec_implied", section: "Accounts and permissions" },
    auditActions: ["invitation.accepted", "member.joined"],
    params: null,
    query: null,
    body: z.strictObject({ token: invitationTokenSchema }),
    responses: { 200: joinedAs(INVITABLE_ROLES, "an invitation never grants ownership") },
    authorization: {
      spec: "Account owners may delegate account administration and billing roles through expiring, single-use invitations accepted by a verified user.",
      actors: HUMAN,
      tenant: "user",
    },
    problems: ["invitation_invalid", "conflict"],
  }),
  listInvitations: defineEndpoint({
    operationId: "listInvitations",
    area: "accounts",
    method: "GET",
    path: "/v1/accounts/{account}/invitations",
    summary: "List the account's invitations.",
    source: { kind: "spec_row", path: "/v1/accounts/{account}/invitations" },
    params: accountParams,
    query: z.strictObject({
      ...paginationQueryShape,
      state: invitationStateSchema.exactOptional(),
    }),
    body: null,
    responses: { 200: pageSchema(invitationSchema) },
    authorization: {
      spec: ROW_INVITATIONS,
      actors: HUMAN,
      tenant: "path_account",
      accountRoles: ACCOUNT_ADMIN_ROLES,
    },
    paginated: true,
  }),
  createInvitation: defineEndpoint({
    operationId: "createInvitation",
    area: "accounts",
    method: "POST",
    path: "/v1/accounts/{account}/invitations",
    summary: "Create an expiring single-use invitation; the token is shown once.",
    source: { kind: "spec_row", path: "/v1/accounts/{account}/invitations" },
    auditActions: ["invitation.created"],
    params: accountParams,
    query: null,
    body: createInvitationBodySchema,
    responses: {
      201: z.strictObject({ invitation: invitationSchema, token: invitationTokenSchema }),
    },
    authorization: {
      spec: ROW_INVITATIONS,
      actors: HUMAN,
      tenant: "path_account",
      accountRoles: ACCOUNT_ADMIN_ROLES,
    },
    oneTimeFields: ["/token"],
    // The account already holds `LIMITS.accounts.maxPendingInvitations` pending invitations.
    problems: ["conflict"],
  }),
  revokeInvitation: defineEndpoint({
    operationId: "revokeInvitation",
    area: "accounts",
    method: "DELETE",
    path: "/v1/accounts/{account}/invitations/{id}",
    summary: "Revoke a pending invitation.",
    source: { kind: "spec_row", path: "/v1/accounts/{account}/invitations" },
    auditActions: ["invitation.revoked"],
    params: z.strictObject({ account: accountIdSchema, id: invitationIdSchema }),
    query: null,
    body: null,
    responses: { 200: z.strictObject({ invitation: invitationSchema }) },
    authorization: {
      spec: ROW_INVITATIONS,
      actors: HUMAN,
      tenant: "path_account",
      accountRoles: ACCOUNT_ADMIN_ROLES,
    },
    problems: ["conflict"],
  }),
  listMembers: defineEndpoint({
    operationId: "listMembers",
    area: "accounts",
    method: "GET",
    path: "/v1/accounts/{account}/members",
    summary: "List the account's members and roles.",
    source: { kind: "spec_implied", section: "Web application and onboarding UI" },
    params: accountParams,
    query: z.strictObject({ ...paginationQueryShape, role: accountRoleSchema.exactOptional() }),
    body: null,
    responses: { 200: pageSchema(memberSchema) },
    // Membership is account administration, not repository scope: keys never list members.
    authorization: { spec: ROW_MEMBERS, actors: HUMAN, tenant: "path_account" },
    paginated: true,
  }),
  getMember: defineEndpoint({
    operationId: "getMember",
    area: "accounts",
    method: "GET",
    path: "/v1/accounts/{account}/members/{user}",
    summary: "Read one membership.",
    source: { kind: "spec_row", path: "/v1/accounts/{account}/members/{user}" },
    params: memberParams,
    query: null,
    body: null,
    responses: { 200: memberResponseSchema },
    // Membership is account administration, not repository scope: keys never list members.
    authorization: { spec: ROW_MEMBERS, actors: HUMAN, tenant: "path_account" },
  }),
  updateMember: defineEndpoint({
    operationId: "updateMember",
    area: "accounts",
    method: "PATCH",
    path: "/v1/accounts/{account}/members/{user}",
    summary: "Change a member's Kovo role; it never changes GitHub authority.",
    source: { kind: "spec_row", path: "/v1/accounts/{account}/members/{user}" },
    auditActions: ["member.role_changed"],
    params: memberParams,
    query: null,
    body: z.strictObject({ role: accountRoleSchema }),
    responses: { 200: memberResponseSchema },
    authorization: {
      spec: ROW_MEMBERS,
      actors: HUMAN,
      tenant: "path_account",
      accountRoles: ACCOUNT_ADMIN_ROLES,
      escalations: OWNER_CHANGES,
    },
    problems: ["owner_required", "conflict"],
  }),
  removeMember: defineEndpoint({
    operationId: "removeMember",
    area: "accounts",
    method: "DELETE",
    path: "/v1/accounts/{account}/members/{user}",
    summary: "Remove a member, never the last owner.",
    source: { kind: "spec_row", path: "/v1/accounts/{account}/members/{user}" },
    auditActions: ["member.removed"],
    params: memberParams,
    query: null,
    body: null,
    responses: { 200: memberResponseSchema },
    authorization: {
      spec: ROW_MEMBERS,
      actors: HUMAN,
      tenant: "path_account",
      accountRoles: ACCOUNT_ADMIN_ROLES,
      escalations: OWNER_CHANGES,
    },
    problems: ["owner_required"],
  }),
  getThirdPartyScanners: defineEndpoint({
    operationId: "getThirdPartyScanners",
    area: "accounts",
    method: "GET",
    path: "/v1/accounts/{account}/third-party-scanners",
    summary: "Whether the account opted out of third-party scanner lookups.",
    source: { kind: "spec_row", path: "/v1/accounts/{account}/third-party-scanners" },
    params: accountParams,
    query: null,
    body: null,
    responses: { 200: thirdPartyScannersSchema },
    authorization: { spec: ROW_THIRD_PARTY_SCANNERS, actors: HUMAN, tenant: "path_account" },
  }),
  setThirdPartyScanners: defineEndpoint({
    operationId: "setThirdPartyScanners",
    area: "accounts",
    method: "PUT",
    path: "/v1/accounts/{account}/third-party-scanners",
    summary:
      "Turn the account's third-party scanner opt-out on or off; setting the current value changes nothing.",
    source: { kind: "spec_row", path: "/v1/accounts/{account}/third-party-scanners" },
    auditActions: ["account.third_party_scanners_changed"],
    params: accountParams,
    query: null,
    body: thirdPartyScannersSchema,
    responses: { 200: thirdPartyScannersSchema },
    authorization: {
      spec: ROW_THIRD_PARTY_SCANNERS,
      actors: HUMAN,
      tenant: "path_account",
      accountRoles: ACCOUNT_ADMIN_ROLES,
    },
  }),
} as const;
