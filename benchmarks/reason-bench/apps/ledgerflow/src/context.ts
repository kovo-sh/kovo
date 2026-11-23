// AppContext — the dependency surface every route module receives. The host server wires concrete
// collaborators (database, virtual filesystem, contained egress, id codec, token helpers, template
// renderer, simulated shell, XML parser) and injects them here so route code stays declarative.
//
// SITE MODULE CONTRACT: every mounted site file default-exports
//   export default function register(app: AppContext): void
// registering exactly its own route(s) via app.route(...). The host mounts site modules before the
// shared area modules so a mounted site owns its route key.
import type { VariantPlan, Actor, PersonaId, PersonaCredential, PersonaRole } from '../../../lib/types.ts'
import type { Db } from '../../../lib/db.ts'
import type { Vfs } from '../../../lib/vfs.ts'
import type { Egress, InternalServiceRef } from '../../../lib/egress.ts'
import type { IdCodec } from '../../../lib/ids.ts'
import type { CanaryRegistry } from '../../../lib/canary.ts'
import type { Handler, RouteOpts, HttpApp } from '../../../lib/http.ts'
import type { SessionStore } from '../../../lib/http-session.ts'
import type { RenderOpts } from '../../../lib/template.ts'
import type { SignOpts, VerifyOpts, VerifyResult } from '../../../lib/jwt.ts'
import type { VerifyWebhookOpts } from '../../../lib/webhook.ts'
import type { SimResult } from '../../../lib/simshell.ts'
import type { ParseXmlOpts } from '../../../lib/xml.ts'
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
  signTokenWith(payload: Record<string, unknown>, secret: string, opts?: SignOpts): string
  verifyTokenWith(token: string, opts: VerifyOpts): VerifyResult
  verifyWebhook(secret: string, body: string, ts: string, sig: string, opts?: VerifyWebhookOpts): boolean
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
  sessions: SessionStore
  /** Register by logical route key, or by runtime method+path (resolved back to its route key). */
  route(routeKey: string, handler: Handler, opts?: RouteOpts): AppContext
  route(method: string, path: string, opts: RouteOpts, handler: Handler): AppContext
  serve(dir: string): void
  listen(): Promise<number>
  close(): Promise<void>
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
  template: { render(source: string, data: Record<string, unknown>, opts?: RenderOpts): string }
  /** Signed token helpers (per-call secret, contract shape). */
  tokens: { sign(payload: Record<string, unknown>, secret: string, opts?: SignOpts): string; verify(token: string, opts: VerifyOpts): VerifyResult }
  /** Session-bound aliases used by the shared area modules. */
  token: { sign(payload: Record<string, unknown>): string; verify(token: string, acceptNone?: boolean): { valid: boolean; payload?: unknown } }
  /** Delivery signature helpers: unscoped legacy verify plus tenant/event-scoped verify. */
  webhook: { sign(secret: string, body: string, ts: string): string; verify(secret: string, body: string, ts: string, sig: string, opts?: VerifyWebhookOpts): boolean; verifyScoped(secret: string, scope: string, body: string, ts: string, sig: string): boolean }
  /** Simulated command runner; never touches the real host. */
  simshell: { run(template: string, args: string[]): SimResult }
  /** XML parser with explicit external-entity policy. */
  xml: { parse(source: string, opts?: ParseXmlOpts): XmlNode }
  /** Contract convenience seams. */
  paramName(logical: string): string
  personaFor(id: PersonaId): PersonaCredential | undefined
  findPersona(email: string, password: string): PersonaCredential | null
  tenantOf(personaOrId: PersonaId): string
  memberRole(personaOrId: PersonaId, tenant: string): PersonaRole | null
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

  let ctx: AppContext
  const route = (a: string, b: Handler | string, c?: RouteOpts | Handler, d?: Handler): AppContext => {
    if (typeof b === 'function') {
      if (plan.routes[a]) app.route(a, b, c as RouteOpts | undefined)
      return ctx
    }
    const method = a.toUpperCase()
    const wanted = shape(b)
    const key = Object.keys(plan.routes).find((k) => {
      const spec = plan.routes[k]!
      return spec.method.toUpperCase() === method && shape(spec.path) === wanted
    })
    if (key) app.route(key, d as Handler, (c as RouteOpts | undefined) ?? {})
    return ctx
  }

  const personas: Record<string, UserRow> = {}
  for (const row of db.all<UserRow>('SELECT * FROM users WHERE persona IS NOT NULL')) personas[row.persona!] = row
  let idSeq = 0
  const newId = (kind: string): string => ids.encode(kind, Date.now() * 1000 + (idSeq++ % 1000))

  ctx = {
    plan, db, ids, vfs, egress, canary: canaries, canaries, config, wiring, labels: config.labels,
    sessions: app.sessions,
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
    serve(dir) { app.static(dir) },
    listen() { return app.listen() },
    close() { return app.close() },
    newId,
    field(key) {
      return plan.params[key] ?? key
    },
    paramName(key) {
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
    xml: {
      parse(source, opts) {
        return wiring.parseXml(source, opts?.resolveExternalEntities === true, (opts?.vfs as Vfs | undefined) ?? vfs, (opts?.egress as Egress | undefined) ?? egress)
      },
    },
    template: {
      render(source, data, opts) {
        return wiring.render(source, data, opts?.inputDerived === true)
      },
    },
    tokens: {
      sign: (payload, secret, opts) => wiring.signTokenWith(payload, secret, opts),
      verify: (token, opts) => wiring.verifyTokenWith(token, opts),
    },
    token: {
      sign: (payload) => wiring.signToken(payload),
      verify: (token, acceptNone = false) => wiring.verifyToken(token, acceptNone),
    },
    webhook: {
      sign: (secret, body, ts) => wiring.signWebhook(secret, body, ts),
      verify: (secret, body, ts, sig, opts) => wiring.verifyWebhook(secret, body, ts, sig, opts),
      verifyScoped: (secret, scope, body, ts, sig) => wiring.verifyScopedWebhook(secret, scope, body, ts, sig),
    },
    simshell: {
      run: (template, args) => {
        const result = wiring.simulate(template, args)
        return { output: result.output, commands: result.commands }
      },
    },
    personaFor(id) {
      return (plan.personas as unknown as Record<string, PersonaCredential | undefined>)[String(id)]
    },
    findPersona(email, password) {
      const all = plan.personas as unknown as Record<string, PersonaCredential | undefined>
      for (const cred of Object.values(all)) if (cred && cred.email === email && cred.password === password) return cred
      return null
    },
    tenantOf(personaOrId) {
      const cred = (plan.personas as unknown as Record<string, PersonaCredential | undefined>)[String(personaOrId)]
      return cred?.tenant ?? String(personaOrId)
    },
    memberRole(personaOrId, tenant) {
      const cred = (plan.personas as unknown as Record<string, PersonaCredential | undefined>)[String(personaOrId)]
      const user = db.get<{ external_id: string }>('SELECT external_id FROM users WHERE persona = ?', [String(personaOrId)])
        ?? (cred ? db.get<{ external_id: string }>('SELECT external_id FROM users WHERE email = ?', [cred.email]) : undefined)
      if (!user) return null
      return (ctx.roleInTenant(user.external_id, tenant) as PersonaRole | undefined) ?? null
    },
  }
  return ctx
}
