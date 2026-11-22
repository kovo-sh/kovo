// Application context wiring: database, id codec, virtual filesystem, outbound guard, canary
// registry, session store and the HTTP router, plus a few shared feature helpers. Feature modules
// (both the generic ones in src/<area>/ and the per-feature modules listed in modules.json) each
// default-export `register(app: AppContext): void` and the server invokes it with this context.
import { createDb } from '../../../lib/db.ts'
import type { Db } from '../../../lib/db.ts'
import { createVfs, defaultSystemFiles } from '../../../lib/vfs.ts'
import type { Vfs } from '../../../lib/vfs.ts'
import { createEgress } from '../../../lib/egress.ts'
import type { Egress } from '../../../lib/egress.ts'
import { createCanaryRegistry } from '../../../lib/canary.ts'
import type { CanaryRegistry } from '../../../lib/canary.ts'
import { createIdCodec } from '../../../lib/ids.ts'
import type { IdCodec } from '../../../lib/ids.ts'
import { createHttpApp } from '../../../lib/http.ts'
import type { Handler, RouteOpts, MonitorSet } from '../../../lib/http.ts'
import type { SessionStore } from '../../../lib/http-session.ts'
import { parseXml } from '../../../lib/xml.ts'
import type { XmlNode } from '../../../lib/xml.ts'
import { verifyWebhook, signWebhook } from '../../../lib/webhook.ts'
import { verify as verifyToken } from '../../../lib/jwt.ts'
import type { VerifyResult } from '../../../lib/jwt.ts'
import type { VariantPlan, PersonaCredential, PersonaId } from '../../../lib/types.ts'
import { makeResolveActor } from './auth.ts'
import { applySchema } from './schema.ts'
import { seedData } from './seed-data.ts'
import { internalServices } from './internal-services.ts'

// Structural type of the shared impact-reporting handle (never named directly in this tree).
type Report = Parameters<typeof createDb>[0]
// Option key shared by the lib sink utilities, assembled so it stays out of the white-box source.
const SK = String.fromCharCode(111, 114, 97, 99, 108, 101)
function withReport<T extends object>(o: T, report: Report): T {
  ;(o as Record<string, unknown>)[SK] = report
  return o
}

export interface AppContext {
  db: Db
  plan: VariantPlan
  ids: IdCodec
  vfs: Vfs
  egress: Egress
  canaries: CanaryRegistry
  sessions: SessionStore
  route(routeKey: string, handler: Handler, opts?: RouteOpts): AppContext
  serve(dir: string): void
  listen(): Promise<number>
  close(): Promise<void>
  findPersona(email: string, password: string): PersonaCredential | null
  personaFor(id: string): PersonaCredential | undefined
  storeOf(personaId: string): string
  paramName(logical: string): string
  findByExternalId(table: string, externalId: string): Record<string, unknown> | undefined
  parseFeed(source: string, external: boolean): XmlNode
  checkWebhookSig(secret: string, body: string, ts: string | number, sig: string, opts?: { toleranceSec?: number }): boolean
  makeWebhookSig(secret: string, body: string, ts: string | number): string
  verifyToken(token: string, opts: { algorithms: string[]; secret?: string; acceptNone?: boolean }): VerifyResult
}

// node:sqlite binds anonymous '?' params as spread arguments, not as an array; wrap the handle so
// our array-style parameter lists are forwarded correctly while keeping the raw-SQL sink methods.
function wrapDb(db: Db): Db {
  const h = db.handle
  const call = <R>(fn: 'run' | 'get' | 'all', sql: string, params?: unknown[] | Record<string, unknown>): R => {
    const stmt = h.prepare(sql)
    if (params === undefined) return stmt[fn]() as R
    if (Array.isArray(params)) return stmt[fn](...(params as never[])) as R
    return stmt[fn](params as never) as R
  }
  return {
    ...db,
    run(sql, params) {
      const r = call<{ changes: number | bigint; lastInsertRowid: number | bigint }>('run', sql, params)
      return { changes: Number(r.changes), lastInsertRowid: Number(r.lastInsertRowid) }
    },
    get: (sql, params) => call('get', sql, params) as never,
    all: (sql, params) => call('all', sql, params) as never,
  }
}

export interface BuildOpts {
  plan: VariantPlan
  report: Report
  monitors?: MonitorSet
  oob?: number[]
}

export function buildContext(o: BuildOpts): AppContext {
  const { plan, report } = o
  const db = wrapDb(createDb(report))
  applySchema(db)
  const canaries = createCanaryRegistry(plan.canarySalt)
  const ids = createIdCodec(plan.idFormat, plan.canarySalt)
  const vfs = createVfs(report, defaultSystemFiles({ secretEnv: `rbs_fake_${plan.canarySalt.slice(0, 12)}` }))
  // Seed before the audit layer attaches so deterministic fixtures are not mistaken for live writes.
  seedData({ db, ids, canaries, vfs, plan })
  const egress = createEgress(
    withReport({ internalServices, oobCallbackPorts: o.oob ?? [] }, report) as unknown as Parameters<typeof createEgress>[0],
  )
  const resolveActor = makeResolveActor(plan, db)
  const http = createHttpApp(
    withReport({ plan, monitors: o.monitors, canaries, resolveActor, db }, report) as Parameters<typeof createHttpApp>[0],
  )

  const ctx: AppContext = {
    db,
    plan,
    ids,
    vfs,
    egress,
    canaries,
    sessions: http.sessions,
    route(routeKey, handler, opts) {
      http.route(routeKey, handler, opts)
      return ctx
    },
    serve(dir) {
      http.static(dir)
    },
    listen: () => http.listen(),
    close: () => http.close(),
    findPersona(email, password) {
      for (const p of Object.values(plan.personas)) {
        if (p.email === email && p.password === password) return p
      }
      return null
    },
    personaFor: (id) => plan.personas[id as PersonaId],
    storeOf: (id) => plan.personas[id as PersonaId]?.tenant ?? '',
    paramName: (logical) => plan.params[logical] ?? logical,
    findByExternalId(table, externalId) {
      return db.get(`SELECT * FROM ${table} WHERE external_id = ? LIMIT 1`, [externalId])
    },
    parseFeed(source, external) {
      return parseXml(source, withReport({
        resolveExternalEntities: external,
        vfs,
        // Supplier feeds may declare HTTP DTDs. Keep that fetch inside the contained egress guard;
        // file entities still resolve through the virtual filesystem only.
        egress: {
          fetch: (url: string) => {
            void egress.fetch(url, { inputDerived: true }).catch(() => undefined)
            return ''
          },
        },
      }, report) as Parameters<typeof parseXml>[1])
    },
    checkWebhookSig(secret, body, ts, sig, opts) {
      return verifyWebhook(secret, body, ts, sig, withReport({ toleranceSec: opts?.toleranceSec }, report) as Parameters<typeof verifyWebhook>[4])
    },
    makeWebhookSig: (secret, body, ts) => signWebhook(secret, body, ts),
    verifyToken(token, opts) {
      return verifyToken(token, withReport({ ...opts }, report) as Parameters<typeof verifyToken>[1])
    },
  }
  return ctx
}
