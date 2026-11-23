// AppContext — the dependency surface every route module receives. The host server wires concrete
// collaborators (database, virtual filesystem, contained egress, id codec, token helpers, template
// renderer, simulated shell, XML parser) and injects them here so route code stays declarative.
//
// SITE MODULE CONTRACT: every mounted site file default-exports
//   export default function register(app: AppContext): void
// registering exactly its own route(s) via app.route(...). The host mounts site modules before the
// shared area modules so a mounted site owns its route key.
import type { VariantPlan, Actor, PersonaId } from '../../../lib/types.ts'
import type { Db } from '../../../lib/db.ts'
import type { Vfs } from '../../../lib/vfs.ts'
import type { Egress, InternalServiceRef } from '../../../lib/egress.ts'
import type { IdCodec } from '../../../lib/ids.ts'
import type { CanaryRegistry } from '../../../lib/canary.ts'
import type { Handler, RouteOpts, HttpApp } from '../../../lib/http.ts'
import type { XmlNode } from '../../../lib/xml.ts'
import type { LedgerLabels } from './plan.ts'

export interface AppConfig {
  metadataOrigin: string
  jwtSecret: string
  webhookSecretFor(tenant: string): string
  labels: LedgerLabels
}

export interface Wiring {
  makeVfs(files: Record<string, string>): Vfs
  makeEgress(services: InternalServiceRef[], oob?: number[]): Egress
  render(source: string, data: Record<string, unknown>, inputDerived?: boolean): string
  signToken(payload: Record<string, unknown>): string
  verifyToken(token: string, acceptNone: boolean): { valid: boolean; payload?: unknown }
  signWebhook(secret: string, body: string, ts: string): string
  verifyWebhook(secret: string, body: string, ts: string, sig: string): boolean
  verifyScopedWebhook(secret: string, scope: string, body: string, ts: string, sig: string): boolean
  simulate(template: string, args: string[]): { output: string; commands: string[] }
  parseXml(source: string, external: boolean, vfs: Vfs, egress: Egress): XmlNode
}

export interface UserRow {
  id: number
  external_id: string
  tenant_id: string
  email: string
  password_hash: string
  role: string
  persona: string | null
  name: string
  status: string
  email_verified: number
  pending_email: string
  created_at: number
}

export interface TenantRow { id: string; slug: string; name: string; plan_code: string; base_currency: string; sso_domain: string; data_ref: string }
export interface OrderRow {
  id: number; external_id: string; tenant_id: string; user_ext_id: string; cart_id: string; status: string
  subtotal_cents: number; discount_cents: number; total_cents: number; paid_cents: number
  currency: string; coupon_code: string; note: string; created_at: number; paid_at: number | null
}
export interface CartRow { id: number; external_id: string; tenant_id: string; user_ext_id: string; status: string; coupon_code: string; currency: string; updated_at: number }
export interface PayoutRow {
  id: number; external_id: string; tenant_id: string; creator_id: string; approved_by: string
  status: string; amount_cents: number; currency: string; memo: string; destination: string
  created_at: number; approved_at: number | null
}
export interface WalletRow { id: number; external_id: string; tenant_id: string; user_ext_id: string; currency: string; balance_micros: number; rate_to_base_micros: number }
export interface InviteRow { id: number; external_id: string; tenant_id: string; email: string; role: string; state: string; token: string; created_by: string; created_at: number }
export interface ExportRow { id: number; external_id: string; tenant_id: string; creator_id: string; creator_role: string; kind: string; status: string; vfs_path: string; created_at: number; completed_at: number | null }
export interface FileRow { id: number; external_id: string; tenant_id: string; name: string; vfs_path: string; note: string; created_at: number }

export interface Table<T> {
  all(tenant?: string): T[]
  byExternalId(externalId: string): T | undefined
}

export interface AppContext {
  plan: VariantPlan
  db: Db
  ids: IdCodec
  vfs: Vfs
  egress: Egress
  canary: CanaryRegistry
  canaries: CanaryRegistry
  config: AppConfig
  wiring: Wiring
  labels: LedgerLabels
  personas: Record<string, UserRow>
  tables: {
    users: Table<UserRow>
    tenants: Table<TenantRow>
    orders: Table<OrderRow>
    carts: Table<CartRow>
    payouts: Table<PayoutRow>
    wallets: Table<WalletRow>
    invites: Table<InviteRow>
    exports: Table<ExportRow>
    files: Table<FileRow>
  }
  /** Register by logical route key, or by runtime method+path (resolved back to its route key). */
  route(routeKey: string, handler: Handler, opts?: RouteOpts): void
  route(method: string, path: string, opts: RouteOpts, handler: Handler): void
  /** Unique per-process external id for a newly created row. */
  newId(kind: string): string
  /** Runtime field/param name for a logical param key (e.g. 'orderId' -> 'ord'). */
  field(key: string): string
  userForActor(actor: Actor | PersonaId | string): UserRow | undefined
  byExternalId<T = Record<string, unknown>>(table: string, externalId: string): T | undefined
  /** The actor's current role in a tenant, consulting the membership matrix. */
  roleInTenant(userExtId: string, tenant: string): string | undefined
  recordActivity(tenant: string, actor: string, action: string, subject?: string, detail?: string): void
  parseXml(source: string, external: boolean): XmlNode
  /** Template renderer (input-derived output is tracked by the host sink). */
  template(source: string, data: Record<string, unknown>, inputDerived?: boolean): string
  /** Signed token helpers (HS256). */
  token: { sign(payload: Record<string, unknown>): string; verify(token: string, acceptNone?: boolean): { valid: boolean; payload?: unknown } }
  /** Delivery signature helpers: unscoped legacy verify plus tenant/event-scoped verify. */
  webhook: { sign(secret: string, body: string, ts: string): string; verify(secret: string, body: string, ts: string, sig: string): boolean; verifyScoped(secret: string, scope: string, body: string, ts: string, sig: string): boolean }
  /** Simulated command runner; never touches the real host. */
  simshell(template: string, args: string[]): { output: string; commands: string[] }
}

export interface BuildContextDeps {
  app: HttpApp
  plan: VariantPlan
  db: Db
  ids: IdCodec
  canaries: CanaryRegistry
  config: AppConfig
  wiring: Wiring
  vfs: Vfs
  egress: Egress
}

function shape(path: string): string {
  return path.split('/').map((seg) => (seg.startsWith(':') ? ':' : seg)).join('/')
}

function tableFor<T>(db: Db, name: string): Table<T> {
  return {
    all(tenant) {
      return tenant
        ? db.all<T>(`SELECT * FROM ${name} WHERE tenant_id = ? ORDER BY id`, [tenant])
        : db.all<T>(`SELECT * FROM ${name} ORDER BY id`)
    },
    byExternalId(externalId) {
      return db.get<T>(`SELECT * FROM ${name} WHERE external_id = ?`, [externalId])
    },
  }
}

export function buildContext(deps: BuildContextDeps): AppContext {
  const { app, plan, db, ids, canaries, config, wiring, vfs, egress } = deps

  const route = (a: string, b: Handler | string, c?: RouteOpts | Handler, d?: Handler): void => {
    if (typeof b === 'function') {
      if (!plan.routes[a]) return
      app.route(a, b, c as RouteOpts | undefined)
      return
    }
    const method = a.toUpperCase()
    const wanted = shape(b)
    const key = Object.keys(plan.routes).find((k) => {
      const spec = plan.routes[k]!
      return spec.method.toUpperCase() === method && shape(spec.path) === wanted
    })
    if (!key) return
    app.route(key, d as Handler, (c as RouteOpts | undefined) ?? {})
  }

  const personas: Record<string, UserRow> = {}
  for (const row of db.all<UserRow>('SELECT * FROM users WHERE persona IS NOT NULL')) personas[row.persona!] = row
  let idSeq = 0
  const newId = (kind: string): string => ids.encode(kind, Date.now() * 1000 + (idSeq++ % 1000))

  const ctx: AppContext = {
    plan, db, ids, vfs, egress, canary: canaries, canaries, config, wiring, labels: config.labels,
    personas,
    tables: {
      users: tableFor<UserRow>(db, 'users'),
      tenants: tableFor<TenantRow>(db, 'tenants'),
      orders: tableFor<OrderRow>(db, 'orders'),
      carts: tableFor<CartRow>(db, 'carts'),
      payouts: tableFor<PayoutRow>(db, 'payouts'),
      wallets: tableFor<WalletRow>(db, 'wallets'),
      invites: tableFor<InviteRow>(db, 'invites'),
      exports: tableFor<ExportRow>(db, 'exports'),
      files: tableFor<FileRow>(db, 'files'),
    },
    route: route as AppContext['route'],
    newId,
    field(key) {
      return plan.params[key] ?? key
    },
    userForActor(actor) {
      if (!actor || actor === 'anonymous' || actor === 'unknown') return undefined
      return db.get<UserRow>('SELECT * FROM users WHERE persona = ?', [String(actor)])
    },
    byExternalId<T = Record<string, unknown>>(table: string, externalId: string): T | undefined {
      return db.get<T>(`SELECT * FROM ${table} WHERE external_id = ?`, [externalId])
    },
    roleInTenant(userExtId, tenant) {
      if (!userExtId) return undefined
      const m = db.get<{ role: string }>('SELECT role FROM memberships WHERE user_ext_id = ? AND tenant_id = ?', [userExtId, tenant])
      if (m) return m.role
      const u = db.get<{ tenant_id: string; role: string }>('SELECT tenant_id, role FROM users WHERE external_id = ?', [userExtId])
      return u && u.tenant_id === tenant ? u.role : undefined
    },
    recordActivity(tenant, actor, action, subject = '', detail = '') {
      db.run(
        'INSERT INTO activity (external_id,tenant_id,actor,action,subject,detail,created_at) VALUES (?,?,?,?,?,?,?)',
        [newId('activity'), tenant, actor, action, subject, detail, Date.now()],
      )
    },
    parseXml(source, external) {
      return wiring.parseXml(source, external, vfs, egress)
    },
    template(source, data, inputDerived = false) {
      return wiring.render(source, data, inputDerived)
    },
    token: {
      sign: (payload) => wiring.signToken(payload),
      verify: (token, acceptNone = false) => wiring.verifyToken(token, acceptNone),
    },
    webhook: {
      sign: (secret, body, ts) => wiring.signWebhook(secret, body, ts),
      verify: (secret, body, ts, sig) => wiring.verifyWebhook(secret, body, ts, sig),
      verifyScoped: (secret, scope, body, ts, sig) => wiring.verifyScopedWebhook(secret, scope, body, ts, sig),
    },
    simshell(template, args) {
      return wiring.simulate(template, args)
    },
  }
  return ctx
}
