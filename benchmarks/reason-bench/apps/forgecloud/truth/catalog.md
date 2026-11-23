# forgecloud — app shell contract (site streams)

Repo-side reference for the four `sites/**` streams. Runtime source is `src/`; materialization copies
`src/` + `ui/` and one twin per site to `src/<rootCause.file>`. Site modules are never mounted from the
repo; `index.ts` discovers `sites/<id>/spec.ts`, filters by `plan.sites[id]`, and asks the
materializer for the selected twins.

## Site module shape

```ts
// sites/<id>/vulnerable.ts and hardened.ts — identical exports/shape/size
import type { AppContext } from '../../src/context.ts'
export default function register(app: AppContext): void {
  app.route('route.key', (req) => { /* ... */ })
  // or, for a stream route:
  app.stream('streams.build', (s) => { /* ... */ })
}
```

Site modules mount **before** common routes; first registration wins for a route key. A mounted site
therefore owns its route and can replace the neutral handler. `spec.rootCause.file` must be exactly
two levels inside `src/` (e.g. `ci/tokens.ts`).

## Personas and orgs

Six seeded personas (`users.persona`): `owner_a` (org_a owner), `member_a` (org_a developer),
`viewer_a` (org_a viewer), `dual_member` (org_a admin + org_b viewer), `member_b` (org_b developer),
`revoked_demoted` (org_a viewer, formerly admin; seeded revoked PAT). Org codes are `org_a` / `org_b`;
slugs come from the plan and are guaranteed to form a prefix pair (`nova`, `nova-corp`) with org A the
shorter slug. Login is by email/password; the session carries the primary org.

* `x-org-id: <slug|code|externalId>` selects another org the user is a member of. `req.tenant` is the
  effective org. Use it for the dual-org transfer scenario.
* `x-workspace-id: <workspace externalId>` scopes workspace selection. Neutral semantics: an absent
  header, or an explicitly empty value, resolves the caller org's default workspace; a workspace from
  another org is `403`.

## Route keys (all defined in `truth/blueprint.ts`)

Auth/shell: `appConfig`, `health`, `login`, `logout`, `me`, `ssoStart`, `ssoCallback`.

Orgs/workspaces: `orgs.list`, `workspaces.list`, `workspaces.current`, `workspaces.detail`.

Projects/pipelines: `projects.list|create|detail|update|transfer|members`,
`pipelines.list|detail`.

Builds/stream: `builds.list|detail|logs|cancel`, `streams.build`.

Tokens: `tokens.list|create|revoke`.

Secrets: `secrets.list|create|detail|update|delete|batch`.

Artifacts/exports: `artifacts.list|mint`, `artifacts.fetch` (`/exports/signed/:token`),
`exports.list|queue`.

Deployments: `deployments.list|create|detail|approve|schedule|dispute|reopen|release|promote`.

Automations/teams: `automations.list|create`, `teams.list|create|addMember`.

Webhooks: `webhooks.list|create|update|deliveries|receive`.

Members: `members.list|update|remove|invite`.

Admin/search/graph: `org.permissions`, `org.settings`, `org.settings.update`, `audit.list`,
`admin.members`, `search.facets`, `search.query`, `search.save`, `graphql`, `graphql.batch`.

Runtime paths and param names are plan-driven; always read path params with
`req.params[ctx.field('<logicalParam>')]`.

## Tables (see `src/schema.ts`)

`role_templates`, `orgs`, `users`, `memberships`, `role_grants`, `teams`, `team_members`, `tokens`,
`token_revocations`, `workspaces`, `projects`, `pipelines`, `pipeline_runs`, `secrets`, `artifacts`,
`exports`, `deployments`, `webhooks`, `webhook_deliveries`, `automations`, `sso_identities`, `invites`,
`audit_log`, plus neutral telemetry `auth_events`, `perm_cache_events`, `vfs_reads`.

Role templates: `viewer`, `developer`, `team_lead`, `admin`, `owner`. `team_lead` includes
`team:manage` but not `org:admin`; `admin`/`owner` include `org:admin`. Automations store a
`role_template`; workspace secrets/runner tokens are `rbs_` canaries derived per seed.

## AppContext helpers

`route`, `stream`, `field`, `db`, `ids`, `vfs`, `egress`, `canaries`, `wiring`, `plan`, `canaries`,
`config`, `labels`, `permCache`,
`userForActor`, `byExternalId`, `membershipFor`, `permissionsFor`, `can`, `roleFor`, `roleRankFor`,
`defaultWorkspace`, `workspaceByExt`, `workspaceForRequest`, `issuePat`, `verifyPat`, `recordAuth`,
`parseXml`.

Common helpers in `src/common.ts`: `currentUser`, `currentUserExt`, `orgOf`, `roleOf`, `can`,
`requirePerm`, `requireUser`, `workspaceFor`, `freshPermissions`, `nextExternal`, `audit`,
`recordVfsRead`, row views (`projectView`, `pipelineView`, `runView`, `secretView`, `deploymentView`,
`webhookView`, `memberView`, `artifactView`), `asRecord`, `str`, `bool`, `num`, `maskSecret`.

## Stream seam

`app.stream(routeKey, handler)` receives a `StreamSession` (see `src/streams.ts`):
`params`, `query`, `headers`, `cookies`, `actor`, `tenant`, `sessionId`, `viewer` (cookie identity),
`token` (PAT view with `signatureValid`, `revoked`, `scopes`, `envScope`), `send(event, data)`,
`reject(status, message)`, `close()`, `onClose(fn)`. The neutral build-log handler requires a valid,
non-revoked credential and an org-owned build. The host wraps every connection in request tracing and
runs the monitors; a rejected connection is not counted as accepted use.

## Telemetry the monitors read (write in neutral code; never emit impact directly)

* `auth_events` — `token_use` (REST), `sso_login` (`assertionTid`/`expectedTid`), `deploy_auth`
  (`scope`/`target`, `accepted`). `ctx.recordAuth` writes one row.
* `perm_cache_events` — `permCache.get/set` (key includes `userId:tenantId`) and
  `getForUser/setForUser` (legacy user-only key). Monitors compare the cached role/org with the
  request tenant.
* `vfs_reads` — `recordVfsRead(ctx, req, path, status)` for signed storage fetches.
* Audit triggers (installed from `truth/monitors.ts` only) on every tenant-scoped table.

Host monitors turn these into `revoked_token_used`, `privilege_escalation`,
`cross_org_transfer`, `batch_partial_authz_bypass`, `tenant_existence_oracle`,
`signed_url_prefix_escape`, `sso_tenant_confusion`, `parser_differential_bypass`,
`cache_tenant_bleed`, `workflow_skip`, `secret_disclosed`, plus lib-level canary/egress/webhook events.

## Defect-facing neutral defaults (do not weaken them in shared code)

* Token auth: REST resolver checks signature + revocation table; stream handler checks both.
* Automation creation clamps `role_template` to the creator's rank and rejects `org:admin`.
* Project transfer requires `org:admin` on source **and** destination.
* `pipelines.list` applies `state`/`visibility` inside one parenthesized predicate.
* `secrets.batch` validates every id before mutating any.
* `search.facets` counts only the caller org.
* Signed links sign the stored object path and verify `/exports/<org>/` with a trailing slash.
* SSO callback requires assertion `tid` to equal the requested org's configured IdP tenant.
* `members.update` authorization is based on the parsed (last) role value; role rank is capped.
* Webhook receiver binds HMAC to tenant and records only status text for probes.
* `workspaces` neutral empty-header semantics resolve the caller's default workspace.
* Permission cache keys include `userId:tenantId`; admin checks use it.
* Deployment dispute/reopen disarm `auto_release_scheduled`; release requires `approved`.
* `deployments.promote` requires either approver authority or a runner token whose `envScope` equals
  the target environment.
