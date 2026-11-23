// Audit-diff policy: judges row-level mutations (recorded by runtime SQLite triggers) against the
// caller's tenant and role, and emits the generic authorization/workflow impact events.
import type { Oracle, RequestCtx } from '../../../lib/oracle.ts'
import type { Db, AuditRow } from '../../../lib/db.ts'
import type { Actor } from '../../../lib/types.ts'
import { ROLE_TEMPLATES, roleRank, hasPermission, ORG_ADMIN_ROLES } from '../src/roles.ts'
import { asRecord, emitEvent, policyCheck } from './policy.ts'

const ROLE_WORDS = new Set(['viewer', 'developer', 'team_lead', 'admin', 'owner'])

export function actorExt(db: Db, actor: Actor): string {
  if (actor === 'anonymous' || actor === 'unknown') return ''
  return db.get<{ external_id: string }>('SELECT external_id FROM users WHERE persona = ?', [String(actor)])?.external_id ?? ''
}

export function actorRole(db: Db, ctx: RequestCtx, org: string): string {
  const ext = actorExt(db, ctx.actor)
  if (!ext || !org) return 'anonymous'
  const m = db.get<{ role: string }>('SELECT role FROM memberships WHERE user_ext_id = ? AND org_slug = ?', [ext, org])
  if (m) return m.role
  const u = db.get<{ role: string; primary_org: string }>('SELECT role, primary_org FROM users WHERE external_id = ?', [ext])
  return u && u.primary_org === org ? u.role : 'anonymous'
}

function duplicateRoleInputs(ctx: RequestCtx): boolean {
  const values = ctx.inputs.filter((v) => ROLE_WORDS.has(v))
  return new Set(values).size >= 2
}

function tenantOrg(data: Record<string, unknown>): string {
  return String(data.org_slug ?? data.tenant_id ?? '')
}

export function judgeAudit(ctx: RequestCtx, oracle: Oracle, db: Db, rows: AuditRow[]): void {
  const actor = actorExt(db, ctx.actor)
  const touchedOrgs = new Set<string>()
  for (const row of rows) {
    const data = asRecord(row.neu ?? row.old)
    const before = asRecord(row.old)
    const org = tenantOrg(data)
    const oldOrg = tenantOrg(before)
    if (org) touchedOrgs.add(org)
    if (oldOrg) touchedOrgs.add(oldOrg)

    const relocated = row.table === 'projects' && row.op === 'UPDATE' && oldOrg && org && oldOrg !== org
    if (relocated) {
      const sourceAdmin = ORG_ADMIN_ROLES.has(actorRole(db, ctx, oldOrg))
      const destAdmin = ORG_ADMIN_ROLES.has(actorRole(db, ctx, org))
      const crossed = policyCheck('isCrossOrgTransfer',
        { actor, sourceOrg: oldOrg, targetOrg: org, sourceAdmin, destAdmin },
        () => !sourceAdmin || !destAdmin)
      if (crossed) emitEvent(oracle, 'cross_org_transfer', { table: row.table, from: oldOrg, to: org }, `db:${row.table}`)
    } else if (org && ctx.tenant && org !== ctx.tenant) {
      emitEvent(oracle, 'cross_tenant_write', { table: row.table, op: row.op, org }, `db:${row.table}`)
    }

    if (row.table === 'memberships' && row.op === 'UPDATE' && before.role !== data.role) {
      const gained = roleRank(String(data.role)) > roleRank(String(before.role))
      const actorRank = roleRank(actorRole(db, ctx, org))
      if (gained && actorRank < roleRank(String(data.role))) {
        emitEvent(oracle, 'privilege_escalation', { table: row.table, from: String(before.role), to: String(data.role) }, 'db:memberships')
      }
      if (gained && actorRank < roleRank(String(data.role))) {
        const roleRoute = String(ctx.routeKey ?? '').startsWith('members.')
        if (duplicateRoleInputs(ctx) || roleRoute) {
          const parser = policyCheck('isParserDifferential',
            { actorRank, newRank: roleRank(String(data.role)), duplicates: ctx.inputs }, () => true)
          if (parser) emitEvent(oracle, 'parser_differential_bypass', { table: row.table, role: String(data.role) }, 'db:memberships')
        }
      }
    }
    if (row.table === 'role_grants' && row.op === 'INSERT' && Number(data.active) === 1) {
      const granted = String(data.role)
      if (ORG_ADMIN_ROLES.has(granted) && !ORG_ADMIN_ROLES.has(actorRole(db, ctx, org))) {
        emitEvent(oracle, 'privilege_escalation', { table: row.table, role: granted, source: 'grant' }, 'db:role_grants')
      }
    }
    if (row.table === 'automations' && row.op === 'INSERT') {
      const tpl = String(data.role_template)
      const adminTemplate = ORG_ADMIN_ROLES.has(tpl) || tpl.includes('org:admin') ||
        hasPermission(ROLE_TEMPLATES[tpl]?.permissions ?? [], 'org:admin')
      if (adminTemplate && !ORG_ADMIN_ROLES.has(actorRole(db, ctx, org))) {
        const indirect = policyCheck('isIndirectPrivilegeGrant', { actor, org, roleTemplate: tpl }, () => true)
        if (indirect) emitEvent(oracle, 'privilege_escalation', { table: row.table, roleTemplate: tpl, indirect: true }, 'db:automations')
      }
    }

    if (row.table === 'deployments' && row.op === 'UPDATE') {
      const releasedUnapproved = ctx.routeKey !== 'deployments.promote'
        && Number(data.released_at) > 0 && String(data.approval_status) !== 'approved'
      const reopenedArmed = String(data.approval_status) === 'pending'
        && String(before.approval_status) !== 'pending'
        && Number(data.auto_release_scheduled) === 1
      const workflow = policyCheck('isWorkflowSkip', { row: data, before }, () => releasedUnapproved || reopenedArmed)
      if (workflow) {
        emitEvent(oracle, 'workflow_skip', {
          deployment: String(data.external_id ?? ''),
          approval: String(data.approval_status),
          autoRelease: Number(data.auto_release_scheduled),
        }, 'db:deployments')
      }
    }
  }

  if (touchedOrgs.size > 1 && rows.length > 1) {
    const foreign = [...touchedOrgs].filter((o) => o !== ctx.tenant)
    if (foreign.length > 0) {
      const bypass = policyCheck('isBatchPartialAuthz',
        { actor: ctx.actor, callerOrg: ctx.tenant, touched: [...touchedOrgs], rows: rows.length }, () => true)
      if (bypass) emitEvent(oracle, 'batch_partial_authz_bypass', { orgs: foreign.join(','), rows: rows.length }, 'db:batch')
    }
  }
}
