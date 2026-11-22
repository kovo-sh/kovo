// AppContext — the dependency surface every route module (common area modules and planted site
// modules alike) receives. The host wires the concrete collaborators (database, virtual filesystem,
// contained egress, id codec, template renderer, token helpers) and injects them here so route code
// stays declarative. Impact-recording collaborators are injected pre-bound by the host via `Wiring`
// factories; route code never constructs them.
//
// SITE MODULE CONTRACT: every planted site file (both twins) default-exports
//   export default function register(app: AppContext): void
// registering exactly its own route(s) via app.route(...). Both twins export the same `register`
// symbol with similar shape and size. The host mounts site modules before the shared area modules so
// a mounted site owns its route key.
import type { VariantPlan, Actor, PersonaId } from '../../../lib/types.ts'
import type { Db } from '../../../lib/db.ts'
import type { Vfs } from '../../../lib/vfs.ts'
import type { Egress, InternalServiceRef } from '../../../lib/egress.ts'
import type { IdCodec } from '../../../lib/ids.ts'
import type { CanaryRegistry } from '../../../lib/canary.ts'
import type { Handler, RouteOpts, HttpApp } from '../../../lib/http.ts'
import type { XmlNode } from '../../../lib/xml.ts'

export interface AppConfig {
  metadataOrigin: string // base origin of the internal metadata/service-discovery mock
  jwtSecret: string
  webhookSecret: string
}

// Host-provided, pre-bound collaborators. The factories close over the request-impact recorder so
// route code cannot reach it directly.
export interface Wiring {
  makeVfs(files: Record<string, string>): Vfs
  makeEgress(services: InternalServiceRef[], oob?: number[]): Egress
  render(source: string, data: Record<string, unknown>, inputDerived?: boolean): string
  signToken(payload: Record<string, unknown>): string
  verifyToken(token: string, acceptNone: boolean): { valid: boolean; payload?: unknown }
  verifyWebhook(secret: string, body: string, ts: string, sig: string): boolean
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
  avatar_url: string
  name: string
  twofa_enabled: number
  twofa_state: string
}

export interface AppContext {
  plan: VariantPlan
  db: Db
  ids: IdCodec
  vfs: Vfs
  egress: Egress
  canaries: CanaryRegistry
  config: AppConfig
  wiring: Wiring
  /** Register a handler for a logical route key; a no-op if the plan omits the key. */
  route(routeKey: string, handler: Handler, opts?: RouteOpts): void
  /** Runtime field/param name for a logical param key (e.g. 'invoiceId' -> 'invId'). */
  field(key: string): string
  /** The seeded user row bound to a persona/actor, if any. */
  userForActor(actor: Actor | PersonaId | string): UserRow | undefined
  /** Fetch a tenant-scoped row by its external id from a table (undefined if absent). */
  byExternalId<T = Record<string, unknown>>(table: string, externalId: string): T | undefined
  /** Parse an XML document; external entities resolve through the virtual filesystem/egress. */
  parseXml(source: string, external: boolean): XmlNode
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

export function buildContext(deps: BuildContextDeps): AppContext {
  const { app, plan, db, ids, canaries, config, wiring, vfs, egress } = deps
  return {
    plan, db, ids, vfs, egress, canaries, config, wiring,
    route(routeKey, handler, opts) {
      if (!plan.routes[routeKey]) return
      app.route(routeKey, handler, opts)
    },
    field(key) {
      return plan.params[key] ?? key
    },
    userForActor(actor) {
      if (!actor || actor === 'anonymous' || actor === 'unknown') return undefined
      return db.get<UserRow>('SELECT * FROM users WHERE persona = ?', [String(actor)])
    },
    byExternalId(table, externalId) {
      return db.get(`SELECT * FROM ${table} WHERE external_id = ?`, [externalId]) as never
    },
    parseXml(source, external) {
      return wiring.parseXml(source, external, vfs, egress)
    },
  }
}
