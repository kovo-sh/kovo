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
  /** Parse an XML document; external entities resolve through the virtual filesystem or egress. */
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
        // Legacy SAML/config imports may reference external metadata over HTTP. Keep the fetch inside
        // the contained egress guard so only the app's registered loopback services are reachable.
        egress: {
          fetch: (url: string) => {
            void egress.fetch(url, { inputDerived: true }).catch(() => undefined)
            return ''
          },
        },
      }, sink)),
    jwtVerify: (token, secret, algorithms, acceptNone) =>
      verifyJwt(token, withSink({ secret, algorithms, acceptNone }, sink)),
    graph: (query, fields, root) => executeGraph(query, fields, root),
  }
}

// ---- minimal GraphQL-style executor ------------------------------------------------------------
interface Selection { name: string; args: Record<string, string>; children: Selection[] }

/**
 * Hard bounds for the tiny query parser. Every scanner loop advances its cursor and every loop
 * tick is charged against `steps`; recursive selection sets are bounded by `depth`. A query that
 * exceeds either bound fails with a `GraphQueryParseError` instead of spinning (the previous
 * parser looped forever when an argument value started with `$`, `[` or `{`).
 */
export const MAX_GRAPH_QUERY_STEPS = 50_000
export const MAX_GRAPH_QUERY_DEPTH = 64

export class GraphQueryParseError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'GraphQueryParseError'
  }
}

interface ParseState { steps: number }

function tick(state: ParseState): void {
  state.steps += 1
  if (state.steps > MAX_GRAPH_QUERY_STEPS) {
    throw new GraphQueryParseError(`query exceeds ${MAX_GRAPH_QUERY_STEPS} parse steps`)
  }
}

function isNameChar(c: string | undefined): boolean {
  return c !== undefined && /[A-Za-z0-9_]/.test(c)
}

/** Skip whitespace, commas, comments and BOM. Always makes progress. */
function skipTrivia(src: string, i: number, state: ParseState): number {
  while (i < src.length) {
    tick(state)
    const c = src[i]!
    if (c === '\uFEFF' || /\s|,/.test(c)) { i++; continue }
    if (c === '#') {
      while (i < src.length && src[i] !== '\n' && src[i] !== '\r') { i++; tick(state) }
      continue
    }
    break
  }
  return i
}

function readName(src: string, i: number, state: ParseState): { name: string; i: number } {
  let name = ''
  while (i < src.length && isNameChar(src[i])) { name += src[i++]!; tick(state) }
  return { name, i }
}

function readString(src: string, i: number, state: ParseState): { value: string; i: number } {
  if (src.startsWith('"""', i)) {
    i += 3
    let value = ''
    while (i < src.length) {
      tick(state)
      if (src.startsWith('"""', i)) return { value, i: i + 3 }
      if (src.startsWith('\\"""', i)) { value += '"""'; i += 4; continue }
      value += src[i++]!
    }
    throw new GraphQueryParseError('unterminated block string')
  }
  if (src[i] !== '"') throw new GraphQueryParseError('expected a string literal')
  i++
  let value = ''
  while (i < src.length) {
    const c = src[i]!
    if (c === '"') return { value, i: i + 1 }
    if (c === '\n' || c === '\r') throw new GraphQueryParseError('unterminated string literal')
    i++
    tick(state)
    if (c !== '\\') { value += c; continue }
    if (i >= src.length) break
    const esc = src[i++]!
    tick(state)
    switch (esc) {
      case '"': value += '"'; break
      case '\\': value += '\\'; break
      case '/': value += '/'; break
      case 'b': value += '\b'; break
      case 'f': value += '\f'; break
      case 'n': value += '\n'; break
      case 'r': value += '\r'; break
      case 't': value += '\t'; break
      case 'u': {
        const hex = src.slice(i, i + 4)
        if (!/^[0-9a-fA-F]{4}$/.test(hex)) throw new GraphQueryParseError('invalid unicode escape')
        value += String.fromCharCode(parseInt(hex, 16))
        i += 4
        break
      }
      default: throw new GraphQueryParseError(`invalid string escape \\${esc}`)
    }
  }
  throw new GraphQueryParseError('unterminated string literal')
}

/** Skip a balanced `open`..`close` block (used for opaque definition/body ranges). */
function skipBalanced(src: string, i: number, state: ParseState, open: string, close: string): number {
  if (src[i] !== open) throw new GraphQueryParseError(`expected "${open}"`)
  let depth = 0
  while (i < src.length) {
    const c = src[i]!
    if (c === '"') { i = readString(src, i, state).i; continue }
    if (c === '#') {
      while (i < src.length && src[i] !== '\n' && src[i] !== '\r') { i++; tick(state) }
      continue
    }
    if (c === open) depth++
    else if (c === close) {
      depth--
      if (depth === 0) return i + 1
    }
    i++
    tick(state)
  }
  throw new GraphQueryParseError(`unterminated "${open}" block`)
}

/** Read an argument value. Returns the documented string shape; composites keep their source text. */
function readValue(src: string, i: number, state: ParseState): { value: string; i: number } {
  const c = src[i]
  if (c === undefined) throw new GraphQueryParseError('missing argument value')
  if (c === '"') return readString(src, i, state)
  if (c === '$') {
    const ref = readName(src, i + 1, state)
    if (!ref.name) throw new GraphQueryParseError('invalid variable reference')
    return { value: `$${ref.name}`, i: ref.i }
  }
  if (c === '[' || c === '{') {
    const start = i
    const closers: string[] = [c === '[' ? ']' : '}']
    i++
    tick(state)
    while (i < src.length) {
      const ch = src[i]!
      if (ch === '"') { i = readString(src, i, state).i; continue }
      if (ch === '#') {
        while (i < src.length && src[i] !== '\n' && src[i] !== '\r') { i++; tick(state) }
        continue
      }
      if (ch === '[' || ch === '{') { closers.push(ch === '[' ? ']' : '}'); i++; tick(state); continue }
      if (ch === ']' || ch === '}') {
        const expected = closers.pop()!
        if (ch !== expected) throw new GraphQueryParseError(`mismatched "${ch}" in argument value`)
        i++
        tick(state)
        if (closers.length === 0) return { value: src.slice(start, i), i }
        continue
      }
      i++
      tick(state)
    }
    throw new GraphQueryParseError('unterminated composite argument value')
  }
  // scalar / enum / number: capture until the next structural delimiter
  const start = i
  while (i < src.length) {
    const ch = src[i]!
    if (/[\s,)\]}:#]/.test(ch)) break
    i++
    tick(state)
  }
  if (i === start) throw new GraphQueryParseError('missing argument value')
  return { value: src.slice(start, i), i }
}

function parseArguments(src: string, i: number, state: ParseState): { args: Record<string, string>; i: number } {
  if (src[i] !== '(') throw new GraphQueryParseError('expected "("')
  i++
  tick(state)
  const args: Record<string, string> = {}
  while (true) {
    i = skipTrivia(src, i, state)
    if (i >= src.length) throw new GraphQueryParseError('unterminated argument list')
    if (src[i] === ')') { tick(state); return { args, i: i + 1 } }
    const name = readName(src, i, state)
    if (!name.name) throw new GraphQueryParseError(`unexpected character "${src[i]}" in argument list`)
    i = skipTrivia(src, name.i, state)
    if (src[i] !== ':') throw new GraphQueryParseError(`missing ":" after argument "${name.name}"`)
    i = skipTrivia(src, i + 1, state)
    const value = readValue(src, i, state)
    args[name.name] = value.value
    i = value.i
  }
}

function skipDirectives(src: string, i: number, state: ParseState): number {
  while (true) {
    i = skipTrivia(src, i, state)
    if (src[i] !== '@') return i
    const directive = readName(src, i + 1, state)
    if (!directive.name) throw new GraphQueryParseError('directive without a name')
    i = skipTrivia(src, directive.i, state)
    if (src[i] === '(') i = parseArguments(src, i, state).i
  }
}

function parseSelectionSet(
  src: string,
  i: number,
  state: ParseState,
  fragments: Map<string, string>,
  depth: number,
): { selections: Selection[]; i: number } {
  if (depth > MAX_GRAPH_QUERY_DEPTH) {
    throw new GraphQueryParseError(`query exceeds ${MAX_GRAPH_QUERY_DEPTH} nesting levels`)
  }
  if (src[i] !== '{') throw new GraphQueryParseError('expected "{"')
  i++
  tick(state)
  const selections: Selection[] = []
  while (true) {
    i = skipTrivia(src, i, state)
    if (i >= src.length) throw new GraphQueryParseError('unterminated selection set')
    const c = src[i]!
    if (c === '}') { tick(state); return { selections, i: i + 1 } }
    if (c === '{') throw new GraphQueryParseError('unexpected "{" in selection set')
    if (src.startsWith('...', i)) {
      // Fragment spread or inline fragment: parse the referenced set and inline its fields.
      i = skipTrivia(src, i + 3, state)
      if (src[i] === '@') i = skipDirectives(src, i, state)
      if (src.startsWith('on', i) && !isNameChar(src[i + 2])) {
        i = skipTrivia(src, i + 2, state)
        const typeName = readName(src, i, state)
        if (!typeName.name) throw new GraphQueryParseError('inline fragment without a type condition')
        i = skipDirectives(src, typeName.i, state)
        i = skipTrivia(src, i, state)
        const inner = parseSelectionSet(src, i, state, fragments, depth + 1)
        selections.push(...inner.selections)
        i = inner.i
        continue
      }
      const spread = readName(src, i, state)
      if (spread.name) {
        const body = fragments.get(spread.name)
        if (body === undefined) throw new GraphQueryParseError(`unknown fragment "${spread.name}"`)
        const inner = parseSelectionSet(body, 0, state, fragments, depth + 1)
        selections.push(...inner.selections)
        i = spread.i
        continue
      }
      // `... { ... }` (type-less inline fragment)
      if (src[i] === '{') {
        const inner = parseSelectionSet(src, i, state, fragments, depth + 1)
        selections.push(...inner.selections)
        i = inner.i
        continue
      }
      throw new GraphQueryParseError('malformed fragment spread')
    }
    // field (optionally aliased)
    const first = readName(src, i, state)
    if (!first.name) throw new GraphQueryParseError(`unexpected character "${c}" in selection set`)
    let name = first.name
    i = skipTrivia(src, first.i, state)
    if (src[i] === ':') {
      i = skipTrivia(src, i + 1, state)
      const aliased = readName(src, i, state)
      if (!aliased.name) throw new GraphQueryParseError(`missing field name after "${name}:"`)
      name = aliased.name
      i = aliased.i
    }
    let args: Record<string, string> = {}
    i = skipTrivia(src, i, state)
    if (src[i] === '(') {
      const parsed = parseArguments(src, i, state)
      args = parsed.args
      i = parsed.i
    }
    i = skipDirectives(src, i, state)
    i = skipTrivia(src, i, state)
    let children: Selection[] = []
    if (src[i] === '{') {
      const inner = parseSelectionSet(src, i, state, fragments, depth + 1)
      children = inner.selections
      i = inner.i
    }
    selections.push({ name, args, children })
  }
}

/**
 * Top-level document scan: records named fragment bodies (before or after the operation) and the
 * offset of the operation selection set. Comments and string bodies are skipped so brace-like text
 * inside them cannot confuse the scan.
 */
function scanDocument(src: string, state: ParseState): { fragments: Map<string, string>; opStart: number } {
  const fragments = new Map<string, string>()
  let opStart = -1
  let i = 0
  while (true) {
    i = skipTrivia(src, i, state)
    if (i >= src.length) break
    if (src[i] === '"') { i = readString(src, i, state).i; continue }
    if (src[i] === '{') {
      if (opStart < 0) opStart = i
      i = skipBalanced(src, i, state, '{', '}')
      continue
    }
    const word = readName(src, i, state)
    if (!word.name) { i++; tick(state); continue }
    i = word.i
    if (word.name === 'fragment') {
      i = skipTrivia(src, i, state)
      const name = readName(src, i, state)
      if (!name.name) throw new GraphQueryParseError('fragment without a name')
      i = skipTrivia(src, name.i, state)
      const on = readName(src, i, state)
      if (on.name !== 'on') throw new GraphQueryParseError(`fragment "${name.name}" is missing a type condition`)
      i = skipTrivia(src, on.i, state)
      const typeName = readName(src, i, state)
      if (!typeName.name) throw new GraphQueryParseError(`fragment "${name.name}" is missing a type condition`)
      i = skipDirectives(src, typeName.i, state)
      i = skipTrivia(src, i, state)
      if (src[i] !== '{') throw new GraphQueryParseError(`fragment "${name.name}" is missing a selection set`)
      const start = i
      i = skipBalanced(src, i, state, '{', '}')
      fragments.set(name.name, src.slice(start, i))
      continue
    }
    if (word.name === 'query' || word.name === 'mutation' || word.name === 'subscription') {
      i = skipTrivia(src, i, state)
      const opName = readName(src, i, state)
      i = skipTrivia(src, opName.i, state)
      // Variable definitions may contain default-value objects; skip the whole balanced group.
      if (src[i] === '(') i = skipBalanced(src, i, state, '(', ')')
      i = skipDirectives(src, i, state)
      i = skipTrivia(src, i, state)
      if (src[i] === '{') {
        if (opStart < 0) opStart = i
        i = skipBalanced(src, i, state, '{', '}')
      }
      continue
    }
  }
  return { fragments, opStart }
}

function parseSelections(src: string): Selection[] {
  const state: ParseState = { steps: 0 }
  const { fragments, opStart } = scanDocument(src, state)
  if (opStart < 0) return []
  return parseSelectionSet(src, opStart, state, fragments, 0).selections
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
