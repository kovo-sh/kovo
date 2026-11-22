// Host-side monitors for acme-saas. These are created by index.ts and injected into the HTTP layer;
// they are never part of the materialized app source. They turn generic runtime signals into the
// per-site impact events the grader attributes:
//   - authorization: cross-tenant writes, privilege escalation and mass assignment from audit diffs
//   - invariants: seat limits, non-negative credits, plan price consistency, invite workflow state
//   - secret entitlement: secret canaries disclosed to an unentitled actor
//   - XSS: active markup rendered on configured trigger routes
import type { VariantPlan, Actor } from '../../../lib/types.ts'
import type { Oracle, RequestCtx } from '../../../lib/oracle.ts'
import type { Db, AuditSpec, AuditRow } from '../../../lib/db.ts'
import type { CanaryRegistry } from '../../../lib/canary.ts'
import type { MonitorSet, HttpResult } from '../../../lib/http.ts'
import { installAuditTriggers, drainAudit } from '../../../lib/audit.ts'

export interface MonitorDeps {
  db: Db
  oracle: Oracle
  canaries: CanaryRegistry
  plan: VariantPlan
}

const AUDIT_SPECS: AuditSpec[] = [
  { table: 'projects', columns: ['tenant_id', 'name', 'owner_id', 'visibility'] },
  { table: 'invoices', columns: ['tenant_id', 'amount_cents', 'status'] },
  { table: 'files', columns: ['tenant_id', 'name'] },
  { table: 'users', columns: ['tenant_id', 'role', 'email'] },
  { table: 'invites', columns: ['tenant_id', 'state'] },
  { table: 'api_keys', columns: ['tenant_id', 'secret'] },
  { table: 'webhooks', columns: ['tenant_id', 'url'] },
  { table: 'reports', columns: ['tenant_id', 'name'] },
  { table: 'notifications', columns: ['tenant_id', 'seen'] },
  { table: 'tenants', columns: ['slug', 'plan_id', 'seats_used', 'credits'] },
  { table: 'plans', columns: ['code', 'price_cents', 'seat_limit'] },
]

const ROLE_RANK: Record<string, number> = { viewer: 0, member: 1, admin: 2, owner: 3 }
// Trigger route keys whose HTML responses are inspected for active markup.
const XSS_STORED_ROUTES = ['renderProjectCard']
const XSS_REFLECTED_ROUTES = ['reflectedSearch']
// Legacy auth route keys where issuing a session is treated as a credential-free hand-off.
const LEGACY_AUTH_ROUTES = ['legacyLogin']
// State-changing route keys whose cookie-authenticated mutations require a same-origin, tokened request.
const CSRF_STATE_ROUTES = ['updateSettings']
// Import route keys whose responses are inspected for resolved external-entity (server-local) content.
const XXE_IMPORT_ROUTES = ['importProjects']
// Signatures of server-local files that only appear in a response when a declared entity was resolved.
const RESOLVED_FILE_MARKER = /root:x:0:0:|SESSION_SECRET=|DB_PASSWORD=|API_KEY=rbs_/
// Active markup only: a real tag carrying an event handler, or an executable scheme inside an
// attribute. Escaped entities (`&lt;img … onerror=…`) are inert text and must not trip this.
const ACTIVE_MARKUP = /<script\b|<[a-z][^>]*\son\w+\s*=|(?:href|src)\s*=\s*["']?\s*javascript:/i

export function createMonitors(deps: MonitorDeps): MonitorSet {
  const { canaries, plan } = deps

  const actorRole = (db: Db, actor: Actor): number => {
    if (actor === 'anonymous' || actor === 'unknown') return -1
    const u = db.get<{ role: string }>('SELECT role FROM users WHERE persona = ?', [String(actor)])
    return u ? ROLE_RANK[u.role] ?? 0 : -1
  }

  const judgeWrite = (ctx: RequestCtx, oracle: Oracle, db: Db, row: AuditRow): void => {
    const data = (row.neu ?? row.old ?? {}) as Record<string, unknown>
    const rowTenant = data.tenant_id !== undefined ? String(data.tenant_id) : null
    // Cross-tenant write: a mutation lands on a row outside the caller tenant.
    if (rowTenant !== null && ctx.tenant && rowTenant !== ctx.tenant) {
      oracle.emit('cross_tenant_write', { table: row.table, op: row.op, rowTenant }, `db:${row.table}`)
    }
    // Tenant reassignment of a row == mass assignment of a protected field.
    if (row.op === 'UPDATE' && row.old && row.neu && String(row.old.tenant_id) !== String(row.neu.tenant_id)) {
      oracle.emit('mass_assignment', { table: row.table, field: 'tenant_id' }, `db:${row.table}`)
    }
    // Create-time mass assignment: a protected tenant field is persisted outside the caller tenant.
    if (row.op === 'INSERT' && row.table === 'projects' && rowTenant !== null && ctx.tenant && rowTenant !== ctx.tenant) {
      oracle.emit('mass_assignment', { table: row.table, field: 'tenant_id' }, `db:${row.table}`)
    }
    if (row.table === 'users' && row.op === 'UPDATE' && row.old && row.neu) {
      const before = ROLE_RANK[String(row.old.role)] ?? 0
      const after = ROLE_RANK[String(row.neu.role)] ?? 0
      if (after > before && actorRole(db, ctx.actor) < ROLE_RANK.admin) {
        oracle.emit('privilege_escalation', { from: String(row.old.role), to: String(row.neu.role) }, 'db:users')
      }
    }
    // A destructive administrative user action executed by a non-administrative caller.
    if (row.table === 'users' && row.op === 'DELETE' && actorRole(db, ctx.actor) < ROLE_RANK.admin) {
      oracle.emit('privilege_escalation', { op: 'delete', role: String(row.old?.role ?? '') }, 'db:users')
    }
    if (row.table === 'invites' && row.op === 'UPDATE' && row.old && row.neu
      && String(row.neu.state) === 'accepted' && String(row.old.state) !== 'pending') {
      oracle.emit('workflow_skip', { from: String(row.old.state), to: 'accepted' }, 'db:invites')
    }
    if (row.table === 'tenants' && row.neu) {
      const seats = Number(row.neu.seats_used)
      const credits = Number(row.neu.credits)
      const planCode = String(row.neu.plan_id)
      const limit = db.get<{ seat_limit: number }>('SELECT seat_limit FROM plans WHERE code = ?', [planCode])?.seat_limit
      if (limit !== undefined && seats > limit) oracle.emit('invariant_violation', { kind: 'seats', seats, limit }, 'db:tenants')
      if (Number.isFinite(credits) && credits < 0) oracle.emit('race_double_spend', { credits }, 'db:tenants')
    }
    if (row.table === 'plans' && row.op === 'UPDATE' && row.old && row.neu
      && Number(row.old.price_cents) !== Number(row.neu.price_cents)) {
      oracle.emit('invariant_violation', { kind: 'plan_price', code: String(row.neu.code) }, 'db:plans')
    }
  }

  const inspectSecrets = (ctx: RequestCtx, body: string, oracle: Oracle): void => {
    const seen = new Set<string>()
    for (const m of body.matchAll(/rbs_[a-z0-9]+_[0-9a-f]{12}/g)) {
      const token = m[0]
      if (seen.has(token)) continue
      seen.add(token)
      const owner = canaries.ownerOf(token)
      if (!owner || owner.kind !== 'secret') continue
      const entitled = owner.owner === ctx.tenant && actorIsPrivileged(ctx)
      if (!entitled) oracle.emit('secret_disclosed', { token, owner: owner.owner }, `secret:${owner.owner}`)
    }
  }

  const actorIsPrivileged = (ctx: RequestCtx): boolean => {
    const u = deps.db.get<{ role: string }>('SELECT role FROM users WHERE persona = ?', [String(ctx.actor)])
    return !!u && (u.role === 'owner' || u.role === 'admin')
  }

  return {
    install(oracle, db) {
      installAuditTriggers(db, AUDIT_SPECS)
      void oracle; void plan
    },
    afterRequest(ctx, oracle, db) {
      if (!db) return
      const rows = drainAudit(db)
      for (const row of rows) judgeWrite(ctx, oracle, db, row)
      // A cookie-authenticated state change that landed from a foreign origin == a CSRF-accepted write.
      if (ctx.routeKey && CSRF_STATE_ROUTES.includes(ctx.routeKey) && ctx.sessionId && rows.length) {
        const foreignOrigin = ctx.inputs.some(
          (v) => /^https?:\/\//i.test(v) && !/^https?:\/\/(127\.0\.0\.1|localhost|\[?::1\]?)(:|\/|$)/i.test(v),
        )
        if (foreignOrigin) oracle.emit('csrf_state_change', { route: ctx.routeKey }, 'csrf')
      }
    },
    inspectResponse(ctx, res: HttpResult, oracle) {
      const body = typeof res.body === 'string' ? res.body : res.body.toString('utf8')
      if (!body) return
      inspectSecrets(ctx, body, oracle)
      // Import response carrying server-local file content == a resolved external XML entity.
      if (ctx.routeKey && XXE_IMPORT_ROUTES.includes(ctx.routeKey) && RESOLVED_FILE_MARKER.test(body)) {
        oracle.emit('xxe_entity_resolved', {}, 'xml:file')
      }
      // Legacy login that establishes a session == authentication without verified credentials.
      if (ctx.routeKey && LEGACY_AUTH_ROUTES.includes(ctx.routeKey) && res.status >= 200 && res.status < 300) {
        const setCookie = res.headers['set-cookie']
        const sessionIssued = Array.isArray(setCookie) ? setCookie.length > 0 : !!setCookie
        if (sessionIssued) oracle.emit('auth_bypass', {}, 'session')
      }
      const ct = String(res.headers['content-type'] ?? '')
      if (!ct.includes('html')) return
      if (!ACTIVE_MARKUP.test(body)) return
      const fromInput = ctx.inputs.some((v) => v.length >= 4 && ACTIVE_MARKUP.test(v) && body.includes(v))
      if (ctx.routeKey && XSS_REFLECTED_ROUTES.includes(ctx.routeKey) && fromInput) {
        oracle.emit('reflected_xss_rendered', {}, 'html')
      } else if (ctx.routeKey && XSS_STORED_ROUTES.includes(ctx.routeKey)) {
        oracle.emit('stored_xss_rendered', {}, 'html')
      }
    },
  }
}
