import { z } from "zod";

// Accounts, identity and access (SPEC "Accounts and permissions", "Public API", data model).

/** `subscriptions.plan`. */
export const PLANS = ["free", "plus"] as const;
export const planSchema = z.enum(PLANS);
export type Plan = z.infer<typeof planSchema>;

/** `account_memberships.role` (SPEC: "owner|admin|billing_manager|member"). */
export const ACCOUNT_ROLES = ["owner", "admin", "billing_manager", "member"] as const;
export const accountRoleSchema = z.enum(ACCOUNT_ROLES);
export type AccountRole = z.infer<typeof accountRoleSchema>;

/** "Owner/admin manage account settings and delegation". */
export const ACCOUNT_ADMIN_ROLES = ["owner", "admin"] as const satisfies readonly AccountRole[];
/** "owner/admin/billing manager manage subscription, capacity and overage spending". */
export const BILLING_ROLES = [
  "owner",
  "admin",
  "billing_manager",
] as const satisfies readonly AccountRole[];

/**
 * `accounts.account_type`: the kind of GitHub account the Kovo account links to (GitHub reports
 * `Organization` or `User`). Null until the authorized link exists.
 */
export const ACCOUNT_TYPES = ["organization", "user"] as const;
export const accountTypeSchema = z.enum(ACCOUNT_TYPES);
export type AccountType = z.infer<typeof accountTypeSchema>;

/**
 * An account's link state: "Create a pending Kovo account … A pending account gains an organization
 * link only through verified GitHub authorization".
 */
export const ACCOUNT_LINK_STATES = ["pending", "linked"] as const;
export const accountLinkStateSchema = z.enum(ACCOUNT_LINK_STATES);
export type AccountLinkState = z.infer<typeof accountLinkStateSchema>;

/** Derived from `account_memberships.accepted_at` / `revoked_at`. */
export const MEMBERSHIP_STATES = ["pending", "active", "revoked"] as const;
export const membershipStateSchema = z.enum(MEMBERSHIP_STATES);
export type MembershipState = z.infer<typeof membershipStateSchema>;

/** "expiring, single-use invitations accepted by a verified user". */
export const INVITATION_STATES = ["pending", "accepted", "expired", "revoked"] as const;
export const invitationStateSchema = z.enum(INVITATION_STATES);
export type InvitationState = z.infer<typeof invitationStateSchema>;

/**
 * Derived from `installations.deleted_at` / `suspended_at` / `paused_at`, in that precedence.
 * "suspension pauses new work and merges"; "Uninstall cancels installation work".
 */
export const INSTALLATION_STATES = ["active", "paused", "suspended", "deleted"] as const;
export const installationStateSchema = z.enum(INSTALLATION_STATES);
export type InstallationState = z.infer<typeof installationStateSchema>;

/**
 * Onboarding request lifecycle ("Install the GitHub App or request GitHub approval. Link … only
 * after verifying installation authorization and the initiating user"; "An unprivileged
 * installation requester waits for approval, and ambiguous ownership requires confirmation from an
 * authorized GitHub administrator").
 */
export const ONBOARDING_STATES = [
  "started",
  "awaiting_github_approval",
  "awaiting_admin_confirmation",
  "linked",
  "rejected",
  "expired",
] as const;
export const onboardingStateSchema = z.enum(ONBOARDING_STATES);
export type OnboardingState = z.infer<typeof onboardingStateSchema>;

/** "API keys … have `read`/`write` plus explicit repo scope" (`api_keys.scope`). */
export const API_KEY_SCOPES = ["read", "write"] as const;
export const apiKeyScopeSchema = z.enum(API_KEY_SCOPES);
export type ApiKeyScope = z.infer<typeof apiKeyScopeSchema>;

/**
 * Who performs a request or mutation (ARCHITECTURE §3; `audit_log.actor_type`): a human Better Auth
 * session, an account API key, an operator (service identity + operator authorization) or an
 * internal component.
 */
export const ACTOR_TYPES = ["user", "api_key", "operator", "system"] as const;
export const actorTypeSchema = z.enum(ACTOR_TYPES);
export type ActorType = z.infer<typeof actorTypeSchema>;
