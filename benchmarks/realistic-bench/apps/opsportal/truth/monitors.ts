// External monitors for opsportal. These run OUTSIDE the materialized app tree and judge each request
// against an authorization policy (DB audit diffs), workflow/role invariants, secret entitlement and
// stored/reflected XSS rendering. They attribute impact to the logical routeKey carried on the request
// context, which is stable across seeds.
import type { MonitorSet, HttpResult } from '../../../lib/http.ts'
import type { Oracle, RequestCtx } from '../../../lib/oracle.ts'
import type { Db } from '../../../lib/db.ts'
import type { PersonaCredential, PersonaId } from '../../../lib/types.ts'
import type { CanaryRegistry } from '../../../lib/canary.ts'
import { installAuditTriggers, drainAudit } from '../../../lib/audit.ts'

export interface MonitorDeps {
  personas: Record<PersonaId, PersonaCredential>
  canaries: CanaryRegistry
}

const ACTIVE_MARKUP = /<script\b|<[a-z][^>]*\son\w+\s*=|(?:href|src)\s*=\s*["']?\s*javascript:/i
const AUDIT_SPECS = [
  { table: 'accounts', columns: ['id', 'team_id', 'name', 'tier', 'notes'] },
  { table: 'users', columns: ['id', 'team_id', 'role', 'persona'] },
  { table: 'tickets', columns: ['id', 'team_id', 'account_id', 'assignee_id', 'status'] },
  { table: 'jobs', columns: ['id', 'team_id', 'status'] },
  { table: 'backup_runs', columns: ['id', 'team_id', 'status', 'signature_valid'] },
]

const str = (v: unknown): string => (v == null ? '' : String(v))

// An Origin/Referer value that points at a host other than the loopback app is treated as cross-site.
function isForeignOrigin(value: string): boolean {
  if (!/^https?:\/\//i.test(value)) return false
  try {
    const host = new URL(value).hostname
    return host !== '127.0.0.1' && host !== 'localhost'
  } catch { return false }
}

export function createMonitors(deps: MonitorDeps): MonitorSet {
  const storedPayloads = new Set<string>()
  const roleOf = (actor: string): string | undefined =>
    (deps.personas as Record<string, PersonaCredential>)[actor]?.role

  return {
    install(_oracle: Oracle, db: Db) {
      installAuditTriggers(db, AUDIT_SPECS)
    },

    afterRequest(ctx: RequestCtx, oracle: Oracle, db?: Db) {
      // remember stored markup so the second-order XSS inspector can detect it when rendered
      if (ctx.routeKey === 'ticketNoteCreate') {
        for (const input of ctx.inputs) if (ACTIVE_MARKUP.test(input)) storedPayloads.add(input)
      }
      if (!db) return
      const actorTenant = ctx.tenant
      const actorRole = roleOf(ctx.actor)
      for (const row of drainAudit(db)) {
        const neu = row.neu ?? {}
        const old = row.old ?? {}
        const rowTeam = str(neu.team_id) || str(old.team_id)

        if ((row.table === 'accounts' || row.table === 'tickets') && row.op !== 'DELETE') {
          if (rowTeam && actorTenant && rowTeam !== actorTenant) {
            oracle.emit('cross_tenant_write', { table: row.table, rowTeam, actorTenant }, `db:${row.table}`)
          }
        }
        if (row.table === 'users' && row.op === 'UPDATE') {
          if (str(neu.role) !== str(old.role) || str(neu.team_id) !== str(old.team_id)) {
            oracle.emit('mass_assignment', { table: 'users', from: str(old.role), to: str(neu.role) }, 'db:users')
          }
          if (str(neu.role) === 'admin' && str(old.role) !== 'admin' && actorRole !== 'admin') {
            oracle.emit('privilege_escalation', { actor: ctx.actor, to: 'admin' }, 'db:users')
          }
        }
        if (row.table === 'jobs' && row.op === 'UPDATE') {
          if (str(old.status) === 'pending' && str(neu.status) === 'done') {
            oracle.emit('workflow_skip', { from: 'pending', to: 'done' }, 'db:jobs')
          }
          if (ctx.routeKey === 'jobTrigger' && ctx.inputs.some(isForeignOrigin)) {
            oracle.emit('csrf_state_change', { table: 'jobs' }, 'db:jobs')
          }
        }
        // A backup callback recorded despite a signature that did not verify is an accepted
        // forged/replayed delivery.
        if (row.table === 'backup_runs' && row.op === 'INSERT' && ctx.routeKey === 'backupCallback') {
          if (str(neu.signature_valid) === '0') {
            oracle.emit('webhook_forgery', { table: 'backup_runs' }, 'webhook')
          }
        }
      }
    },

    inspectResponse(ctx: RequestCtx, res: HttpResult, oracle: Oracle) {
      const body = typeof res.body === 'string' ? res.body : res.body.toString('utf8')
      if (!body) return
      // second-order stored XSS: active markup from an earlier store request rendered here unescaped
      if (ctx.routeKey === 'ticketView') {
        for (const payload of storedPayloads) {
          if (body.includes(payload)) { oracle.emit('stored_xss_rendered', { routeKey: ctx.routeKey }, 'xss:view'); break }
        }
      }
      // reflected XSS: active markup echoed from this request's own input, unescaped
      if (ctx.routeKey === 'accountSearch') {
        for (const input of ctx.inputs) {
          if (ACTIVE_MARKUP.test(input) && body.includes(input)) {
            oracle.emit('reflected_xss_rendered', { routeKey: ctx.routeKey }, 'xss:reflect'); break
          }
        }
      }
      // secret entitlement: an rbs_ secret canary served to a non-admin actor on the integrations list
      if (ctx.routeKey === 'integrationList' && roleOf(ctx.actor) !== 'admin') {
        for (const m of body.matchAll(/rbs_[a-z0-9]+_[0-9a-f]{12}/g)) {
          const owner = deps.canaries.ownerOf(m[0])
          if (owner && owner.kind === 'secret') { oracle.emit('secret_disclosed', { token: m[0] }, 'secret:integrations'); break }
        }
      }
    },
  }
}
