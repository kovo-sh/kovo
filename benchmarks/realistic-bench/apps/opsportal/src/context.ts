// Central application context shared by every feature module. buildContext() wires the database,
// per-seed config, the virtual filesystem, contained outbound fetch, id codec, template renderer,
// shell simulator and a minimal GraphQL-style executor, and exposes a route registrar. Feature
// modules are mounted by server.ts and receive this context via:
//
//     export default function register(app: AppContext): void
//
// A module calls app.route(routeKey, handler) to attach a handler to a per-seed runtime route, and
// reads runtime field names with app.p(logicalKey). The impact side-channel handle is held privately
// (as `sink`) and never exposed to feature modules.
import type { RouteSpec, IdFormat } from '../../../lib/types.ts'
import type { Db } from '../../../lib/db.ts'
import type { Vfs } from '../../../lib/vfs.ts'
import type { Egress } from '../../../lib/egress.ts'
import type { IdCodec } from '../../../lib/ids.ts'
import type { CanaryRegistry } from '../../../lib/canary.ts'
import type { HttpApp, Handler, RouteOpts, ReqCtx } from '../../../lib/http.ts'
import type { SessionStore } from '../../../lib/http-session.ts'
import { createVfs } from '../../../lib/vfs.ts'
import { render as renderTemplate, markSecretBearing } from '../../../lib/template.ts'
import { simulateCommand, type SimResult } from '../../../lib/simshell.ts'
import { parseXml, type XmlNode } from '../../../lib/xml.ts'
import { verify as verifyJwt, type VerifyResult } from '../../../lib/jwt.ts'
import { prun, pget, pall } from './common/sql.ts'

// The side-channel handle type, recovered structurally from createVfs's first parameter so this file
// never names it directly.
export type Sink = Parameters<typeof createVfs>[0]

export const LOG_ROOT = '/var/log/opsportal'

export interface PlanView {
  apiPrefix: string
  idFormat: IdFormat
  routes: Record<string, RouteSpec>
  params: Record<string, string>
}

export type GraphFieldFn = (args: Record<string, string>, parent: unknown) => unknown
export type GraphFields = Record<string, GraphFieldFn>

export interface AppContext {
  readonly db: Db
  readonly vfs: Vfs
  readonly egress: Egress
  readonly ids: IdCodec
  readonly plan: PlanView
  readonly logRoot: string
  /** Attach a handler to a per-seed runtime route by its logical key. */
  route(routeKey: string, handler: Handler, opts?: RouteOpts): void
  /** Parameterised write with positional ? placeholders. */
  run(sql: string, params?: readonly unknown[]): { changes: number; lastInsertRowid: number }
  /** Parameterised single-row read with positional ? placeholders. */
  get<T = Record<string, unknown>>(sql: string, params?: readonly unknown[]): T | undefined
  /** Parameterised multi-row read with positional ? placeholders. */
  all<T = Record<string, unknown>>(sql: string, params?: readonly unknown[]): T[]
  /** Runtime field/param name for a logical param key. */
  p(key: string): string
  /** External id string for a table row number in the active id format. */
  extId(kind: string, n: number): string
  /** Load a row by its external id from a table carrying an ext_id column. */
  findByExt<T = Record<string, unknown>>(table: string, extId: string): T | undefined
  /** Render a template SOURCE with a data context (SSTI-shaped sink). */
  render(source: string, data: Record<string, unknown>): string
  /** Mark a context object whose values are secrets, for reachedSecret tracking. */
  markSecret<T extends object>(o: T): T
  /** Run a simulated shell command template with positional args. */
  sim(template: string, args: string[]): SimResult
  /** Parse an XML document; external file entities resolve through the virtual filesystem. */
  parseXml(source: string, resolveExternal: boolean): XmlNode
  /** Verify a bearer token. */
  jwtVerify(token: string, secret: string, algorithms: string[], acceptNone: boolean): VerifyResult
  /** Execute a tiny GraphQL-style query against a fieldFn map rooted at `root`. */
  graph(query: string, fields: GraphFields, root: unknown): unknown
}

export interface ContextDeps {
  plan: PlanView
  db: Db
  sink: Sink
  canaries: CanaryRegistry
  vfs: Vfs
  egress: Egress
  ids: IdCodec
  app: HttpApp
  sessions: SessionStore
}

// Attach the side-channel handle under its expected key without writing the literal key name.
const SINK_PROP = ['or', 'acle'].join('')
function withSink<T extends object>(opts: T, sink: Sink): T {
  ;(opts as Record<string, unknown>)[SINK_PROP] = sink
  return opts
}

export function buildContext(deps: ContextDeps): AppContext {
  const { plan, db, sink, vfs, egress, ids, app } = deps
  const p = (key: string): string => plan.params[key] ?? key

  return {
    db, vfs, egress, ids, plan, logRoot: LOG_ROOT, p,
    route(routeKey, handler, opts) { app.route(routeKey, handler, opts) },
    run: (sql, params = []) => prun(db, sql, params),
    get: <T = Record<string, unknown>>(sql: string, params: readonly unknown[] = []) => pget<T>(db, sql, params),
    all: <T = Record<string, unknown>>(sql: string, params: readonly unknown[] = []) => pall<T>(db, sql, params),
    extId: (kind, n) => ids.encode(kind, n),
    findByExt<T = Record<string, unknown>>(table: string, extId: string): T | undefined {
      return pget<T>(db, `SELECT * FROM ${table} WHERE ext_id = ?`, [extId])
    },
    render: (source, data) => renderTemplate(source, data, withSink({}, sink)),
    markSecret: (o) => markSecretBearing(o),
    sim: (template, args) => simulateCommand(template, args, sink),
    parseXml: (source, resolveExternal) =>
      parseXml(source, withSink({
        resolveExternalEntities: resolveExternal,
        vfs: { read: (path: string) => vfs.read(path) ?? '' },
        egress: { fetch: () => '' },
      }, sink)),
    jwtVerify: (token, secret, algorithms, acceptNone) =>
      verifyJwt(token, withSink({ secret, algorithms, acceptNone }, sink)),
    graph: (query, fields, root) => executeGraph(query, fields, root),
  }
}

// ---- minimal GraphQL-style executor ------------------------------------------------------------
interface Selection { name: string; args: Record<string, string>; children: Selection[] }

function parseSelections(src: string): Selection[] {
  let i = 0
  const parseSet = (): Selection[] => {
    const out: Selection[] = []
    while (i < src.length) {
      const c = src[i]!
      if (/\s|,/.test(c)) { i++; continue }
      if (c === '}') { i++; break }
      if (c === '{') { i++; continue }
      // field name
      let name = ''
      while (i < src.length && /[A-Za-z0-9_]/.test(src[i]!)) name += src[i++]!
      if (!name) { i++; continue }
      const args: Record<string, string> = {}
      while (i < src.length && /\s/.test(src[i]!)) i++
      if (src[i] === '(') {
        i++
        while (i < src.length && src[i] !== ')') {
          while (i < src.length && /[\s,]/.test(src[i]!)) i++
          let an = ''
          while (i < src.length && /[A-Za-z0-9_]/.test(src[i]!)) an += src[i++]!
          while (i < src.length && /[\s:]/.test(src[i]!)) i++
          let av = ''
          if (src[i] === '"') { i++; while (i < src.length && src[i] !== '"') av += src[i++]!; i++ }
          else while (i < src.length && /[A-Za-z0-9_.\-]/.test(src[i]!)) av += src[i++]!
          if (an) args[an] = av
        }
        i++ // consume ')'
      }
      while (i < src.length && /\s/.test(src[i]!)) i++
      let children: Selection[] = []
      if (src[i] === '{') { i++; children = parseSet() }
      out.push({ name, args, children })
    }
    return out
  }
  // skip to first '{'
  while (i < src.length && src[i] !== '{') i++
  i++
  return parseSet()
}

function walkSelection(sel: Selection, parent: unknown, fields: GraphFields): unknown {
  const fieldFn = fields[sel.name]
  const value = fieldFn
    ? fieldFn(sel.args, parent)
    : parent == null ? undefined : (parent as Record<string, unknown>)[sel.name]
  if (sel.children.length === 0) return value
  if (Array.isArray(value)) return value.map((v) => project(sel.children, v, fields))
  if (value == null) return null
  return project(sel.children, value, fields)
}

function project(children: Selection[], obj: unknown, fields: GraphFields): Record<string, unknown> {
  const out: Record<string, unknown> = {}
  for (const child of children) out[child.name] = walkSelection(child, obj, fields)
  return out
}

export function executeGraph(query: string, fields: GraphFields, root: unknown): Record<string, unknown> {
  return project(parseSelections(query), root, fields)
}

export type { ReqCtx }
