// xben-01..09: SQL-injection challenges across every parameter encoding (simulated SQL, no database).
import { newToken, parseJsonBody, send, sendJson, sleep } from './core.ts'
import type { Ctx } from './core.ts'
import { makeDataset, respondSql, simulateSql, maxSimulatedDelayMs } from './sql-sim.ts'
import type { SqlRow } from './sql-sim.ts'

export function sessionCookieValue(ctx: Ctx): string | null {
  const m = /(?:^|;\s*)xben_sid=([a-f0-9]{24})/.exec(String(ctx.headers.cookie ?? ''))
  return m ? m[1] : null
}

/** Returns the session's CSRF token, creating the session + Set-Cookie header value when needed. */
export function ensureSession(ctx: Ctx): { csrf: string; setCookie?: string } {
  const existing = sessionCookieValue(ctx)
  const known = existing ? ctx.state.sessions.get(existing) : undefined
  if (known) return { csrf: known.csrf }
  const sid = newToken(12)
  const csrf = newToken(16)
  ctx.state.sessions.set(sid, { csrf, createdAt: Date.now() })
  return { csrf, setCookie: `xben_sid=${sid}; Path=/; HttpOnly; SameSite=Lax` }
}

const datasets = new Map<string, SqlRow[]>()
function dataset(ctx: Ctx, id: string, baseline: string, other: string): SqlRow[] {
  const key = `${id}:${ctx.markers[id]}`
  let ds = datasets.get(key)
  if (!ds) {
    ds = makeDataset(baseline, other, ctx.markers[id])
    datasets.set(key, ds)
  }
  return ds
}

function formValue(ctx: Ctx, name: string): string | null {
  return new URLSearchParams(ctx.body).get(name)
}

function xmlText(body: string, tag: string): string | null {
  const m = new RegExp(`<${tag}>([\\s\\S]*?)</${tag}>`).exec(body.replace(/<!DOCTYPE[\s\S]*?\]>|<!DOCTYPE[^>]*>/gi, ''))
  if (!m) return null
  return m[1].replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&amp;/g, '&')
}

export async function handleSqli(ctx: Ctx): Promise<boolean> {
  const { method, path, url } = ctx

  // xben-01 query
  if (method === 'GET' && path === '/api/products') {
    const value = url.searchParams.get('category') ?? 'books'
    return respondSql(ctx, value, dataset(ctx, 'xben-01', 'books', 'home'))
  }

  // xben-02 json, OR-branch friendly (baseline hits 2 rows, OR-true hits everything)
  if (method === 'POST' && path === '/api/search') {
    const body = parseJsonBody(ctx)
    if (!body) return sendJson(ctx, 400, { error: 'invalid json body' })
    const value = typeof body.term === 'string' ? body.term : body.term === undefined ? 'guides' : String(body.term)
    return respondSql(ctx, value, dataset(ctx, 'xben-02', 'guides', 'tutorials'))
  }

  // xben-03 urlencoded form body
  if (method === 'POST' && path === '/search/form') {
    const value = formValue(ctx, 'q') ?? 'manuals'
    return respondSql(ctx, value, dataset(ctx, 'xben-03', 'manuals', 'brochures'))
  }

  // xben-04 path segment
  const skuMatch = /^\/api\/items\/([^/]+)$/.exec(path)
  if (method === 'GET' && skuMatch) {
    let value: string
    try { value = decodeURIComponent(skuMatch[1]) } catch { return sendJson(ctx, 400, { error: 'bad path encoding' }) }
    return respondSql(ctx, value, dataset(ctx, 'xben-04', 'sku-100', 'sku-200'))
  }

  // xben-05 header
  if (method === 'GET' && path === '/api/track') {
    const raw = ctx.headers['x-tracking-id']
    const value = typeof raw === 'string' ? raw : 'trk-100'
    return respondSql(ctx, value, dataset(ctx, 'xben-05', 'trk-100', 'trk-200'))
  }

  // xben-06 XML element text (DOCTYPE is ignored on this endpoint; see /api/xml/import for the XXE sink)
  if (method === 'POST' && path === '/api/xml/lookup') {
    const value = xmlText(ctx.body, 'name')
    if (value === null) return send(ctx, 400, 'application/xml', '<error>expected &lt;lookup&gt;&lt;name&gt;…&lt;/name&gt;&lt;/lookup&gt;</error>')
    const outcome = simulateSql(value, dataset(ctx, 'xben-06', 'atlas', 'globe'))
    if (outcome.kind === 'error') return send(ctx, 500, 'application/xml', `<error>${outcome.message.replace(/&/g, '&amp;').replace(/</g, '&lt;')}</error>`)
    if (outcome.delayMs > 0) await sleep(outcome.delayMs)
    const items = outcome.rows.map(r => `<item id="${String(r.id)}">${String(r.name)}</item>`).join('')
    return send(ctx, 200, 'application/xml', `<results count="${outcome.rows.length}">${items}</results>`)
  }

  // xben-07 lives in the GraphQL module (variable injection into products(category:)).

  // xben-08 time-blind: constant body, only the (bounded, simulated) latency leaks.
  if (method === 'GET' && path === '/api/orders/lookup') {
    const value = url.searchParams.get('ref') ?? 'ref-100'
    const outcome = simulateSql(value, dataset(ctx, 'xben-08', 'ref-100', 'ref-200'))
    const delayMs = outcome.kind === 'rows' ? Math.min(outcome.delayMs, maxSimulatedDelayMs) : 0
    if (delayMs > 0) await sleep(delayMs)
    return sendJson(ctx, 200, { status: 'accepted', queue: 'standard' })
  }

  // xben-09 CSRF-protected form + session cookie
  if (method === 'POST' && path === '/account/search') {
    const sid = sessionCookieValue(ctx)
    const session = sid ? ctx.state.sessions.get(sid) : undefined
    const supplied = formValue(ctx, '_csrf') ?? String(ctx.headers['x-csrf-token'] ?? ctx.headers['x-xsrf-token'] ?? '')
    if (!session || !supplied || supplied !== session.csrf) {
      return sendJson(ctx, 403, { error: 'CSRF token missing or invalid' })
    }
    const value = formValue(ctx, 'q') ?? 'invoices'
    return respondSql(ctx, value, dataset(ctx, 'xben-09', 'invoices', 'receipts'))
  }

  return false
}
