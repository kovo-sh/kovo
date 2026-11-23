// Host-side monitor set for forgecloud. Created by index.ts and injected into the HTTP/stream layers;
// never part of the materialized app source. This module installs the runtime audit triggers and
// dispatches each request's telemetry to the authorization/workflow and response inspectors:
//   - credential lifecycle: revoked-token use over REST or SSE
//   - authorization: indirect privilege grants, cross-org transfer source/dest roles, batch partial
//     authorization, parser-differential role changes
//   - tenancy: facet count leakage, signed-URL prefix boundary, permission-cache tenant bleed
//   - federation: assertion tenant ids that do not match the requested org
//   - workflow: release/dispute/schedule state-machine skips
//   - secrets: canary material served to an unentitled actor (including internal signing salts)
import type { VariantPlan } from '../../../lib/types.ts'
import type { Oracle } from '../../../lib/oracle.ts'
import type { Db, AuditSpec } from '../../../lib/db.ts'
import type { CanaryRegistry } from '../../../lib/canary.ts'
import type { MonitorSet } from '../../../lib/http.ts'
import { installAuditTriggers, drainAudit } from '../../../lib/audit.ts'
import { judgeAudit } from './audit.ts'
import { inspectAuth, inspectFacets, inspectSecrets, inspectSignedInputs } from './inspect.ts'

export interface MonitorDeps {
  db: Db
  oracle: Oracle
  canaries: CanaryRegistry
  plan: VariantPlan
}

const AUDIT_SPECS: AuditSpec[] = [
  { table: 'orgs', columns: ['slug', 'plan', 'sso_tenant'] },
  { table: 'users', columns: ['primary_org', 'role', 'email', 'status'] },
  { table: 'memberships', columns: ['user_ext_id', 'org_slug', 'role', 'permissions'] },
  { table: 'role_grants', columns: ['org_slug', 'user_ext_id', 'role', 'active'] },
  { table: 'teams', columns: ['org_slug', 'role_template'] },
  { table: 'team_members', columns: ['org_slug', 'user_ext_id', 'role'] },
  { table: 'tokens', columns: ['org_slug', 'user_ext_id', 'revoked_at'] },
  { table: 'token_revocations', columns: ['org_slug', 'token_ext_id'] },
  { table: 'workspaces', columns: ['org_slug', 'visibility'] },
  { table: 'projects', columns: ['org_slug', 'workspace_ext', 'name', 'visibility', 'state'] },
  { table: 'pipelines', columns: ['org_slug', 'project_ext', 'state', 'visibility'] },
  { table: 'pipeline_runs', columns: ['org_slug', 'state'] },
  { table: 'secrets', columns: ['org_slug', 'project_ext', 'name', 'value', 'version'] },
  { table: 'artifacts', columns: ['org_slug', 'vfs_path'] },
  { table: 'exports', columns: ['org_slug', 'state', 'vfs_path'] },
  {
    table: 'deployments',
    columns: ['org_slug', 'project_ext', 'state', 'approval_status', 'auto_release_scheduled', 'released_at', 'disputed_at'],
  },
  { table: 'webhooks', columns: ['org_slug', 'url', 'active'] },
  { table: 'webhook_deliveries', columns: ['org_slug', 'detail'] },
  { table: 'automations', columns: ['org_slug', 'role_template'] },
  { table: 'sso_identities', columns: ['org_slug', 'tid', 'email'] },
  { table: 'invites', columns: ['org_slug', 'state', 'role'] },
]

export function createMonitors(deps: MonitorDeps): MonitorSet {
  const { db: rootDb, canaries, plan } = deps

  return {
    install(oracle, db) {
      installAuditTriggers(db, AUDIT_SPECS)
      void oracle
      void plan
    },
    afterRequest(ctx, oracle, db) {
      const target = db ?? rootDb
      inspectAuth(ctx, oracle, target)
      judgeAudit(ctx, oracle, target, drainAudit(target))
    },
    inspectResponse(ctx, res, oracle) {
      const body = typeof res.body === 'string' ? res.body : res.body.toString('utf8')
      if (!body) return
      inspectSecrets(ctx, body, oracle, canaries, rootDb)
      inspectSignedInputs(ctx, res, oracle, `rb_fake_sig_${plan.canarySalt.slice(0, 12)}`)
      if (ctx.routeKey === 'search.facets') inspectFacets(ctx, res, oracle, rootDb)
    },
  }
}
