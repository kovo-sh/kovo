/**
 * Kovo Hunter v3 — Suite B deterministic Full-Stack Lab fixture server (SPEC-v3 §8 Suite B).
 *
 * A single in-process Node HTTP + WebSocket server emulating a modern Next.js + Express +
 * GraphQL-ish + WebSocket SaaS app with 12 planted High/Critical vulnerability classes and
 * 3 safe decoys. Everything is in-memory, deterministic, loopback-only and resettable.
 *
 *  #  | Planted class                                   | Endpoint
 * ----+-------------------------------------------------+------------------------------------------
 *  1  | Server Action missing ownership check (BOLA)     | POST /_actions/getInvoice
 *  2  | DELETE org member missing tenant check (BFLA)    | DELETE /api/orgs/:orgId/members/:memberId
 *  3  | Webhook signature fails open (secret unset)      | POST /api/webhooks/billing
 *  4  | Boolean-blind SQLi in filter                     | GET  /api/products?category=
 *  5  | Non-destructive SSTI (arithmetic evaluation)     | GET  /api/preview-template?template=
 *  6  | Blind SSRF via webhook preview (DNS + HTTP)      | GET  /api/webhooks/preview?url=
 *  7  | Cross-Site WebSocket Hijacking                   | WS   /ws/notifications
 *  8  | postMessage -> innerHTML DOM XSS                 | GET  /preview-frame
 *  9  | Single-use coupon race                           | POST /api/coupons/redeem
 * 10  | Stored SVG XSS via multipart upload              | POST /api/uploads -> GET /uploads/:id
 * 11  | Credentialed reflected-Origin CORS               | GET  /api/me
 * 12  | CVE-2025-29927 x-middleware-subrequest bypass    | GET  /api/admin/stats
 *  D1 | Edge-blocked CVE-2025-29927 (safe)               | GET  /edge/api/admin/stats
 *  D2 | SPA 200 index.html catch-all (safe)              | GET  /actuator/env (and any non-/api path)
 *  D3 | Reflected non-executing template (safe)          | GET  /api/echo-template?template=
 */
import { createHash, randomUUID } from 'node:crypto'
import { Resolver } from 'node:dns/promises'
import { once } from 'node:events'
import { createServer } from 'node:http'
import type { IncomingMessage, ServerResponse } from 'node:http'
import type { Duplex } from 'node:stream'
import { setTimeout as delay } from 'node:timers/promises'

export const LAB_PERSONA_A_TOKEN = 'lab-persona-a-opaque-token-48151623'
export const LAB_PERSONA_B_TOKEN = 'lab-persona-b-opaque-token-42108736'
export const LAB_WEBHOOK_SECRET_PAYMENTS = 'whsec_lab_payments_configured_5521'

export const SUITE_B_CLASSES = [
  'server_action_bola',
  'delete_member_bfla',
  'webhook_fail_open',
  'sqli_boolean',
  'ssti_math',
  'blind_ssrf_dns_http',
  'cswsh',
  'postmessage_dom_xss',
  'coupon_race',
  'svg_upload_xss',
  'credentialed_cors',
  'cve_2025_29927',
] as const
export type SuiteBClass = typeof SUITE_B_CLASSES[number]

export const SUITE_B_DECOYS = ['edge_blocked_cve', 'spa_catchall', 'reflected_template'] as const
export type SuiteBDecoy = typeof SUITE_B_DECOYS[number]

interface LabUser { id: string; orgId: string; email: string; token: string }
interface Invoice { id: string; ownerId: string; orgId: string; totalCents: number; memo: string }
interface Member { orgId: string; memberId: string; role: string }
interface Upload { id: string; filename: string; contentType: string; content: string; ownerId: string | null }

export interface LabRequestRecord {
  method: string
  path: string
  headers: Record<string, string | string[] | undefined>
  at: number
}

export interface SuiteBLabOptions {
  /** Optional authoritative DNS canary listener (host:port) used by the SSRF sink for name resolution. */
  dnsResolver?: { host: string; port: number }
  /** Artificial async gap in coupon redemption to make the race deterministic. */
  raceGapMs?: number
}

const PRODUCTS = [
  { id: 1, title: 'Starter Plan', category: 'plans' },
  { id: 2, title: 'Growth Plan', category: 'plans' },
  { id: 3, title: 'Audit Add-on', category: 'addons' },
  { id: 4, title: 'SSO Add-on', category: 'addons' },
  { id: 5, title: 'Internal Partner Discount', category: 'internal' },
]

const INDEX_HTML = '<!doctype html><html><head><meta charset="utf-8"><title>Northstar Lab</title></head>'
  + '<body><div id="root">Northstar Lab SPA</div><script src="/app.js"></script></body></html>'

const PREVIEW_FRAME_HTML = `<!doctype html><html><head><meta charset="utf-8"><title>Preview Frame</title></head>
<body><h1>Template Preview</h1><div id="out">waiting</div>
<script>
  window.addEventListener('message', function (event) {
    // PLANTED BUG (#8): no event.origin validation + unsanitized innerHTML sink.
    if (event.data && typeof event.data.html === 'string') {
      document.getElementById('out').innerHTML = event.data.html;
    }
  });
</script></body></html>`

function users(): LabUser[] {
  return [
    { id: 'user_a', orgId: 'org-a', email: 'alice@org-a.test', token: LAB_PERSONA_A_TOKEN },
    { id: 'user_b', orgId: 'org-b', email: 'bob@org-b.test', token: LAB_PERSONA_B_TOKEN },
  ]
}

function freshState() {
  return {
    invoices: new Map<string, Invoice>([
      ['inv_a_1001', { id: 'inv_a_1001', ownerId: 'user_a', orgId: 'org-a', totalCents: 129_900, memo: 'org-a confidential renewal' }],
      ['inv_b_2001', { id: 'inv_b_2001', ownerId: 'user_b', orgId: 'org-b', totalCents: 4_900, memo: 'org-b starter' }],
    ]),
    members: new Map<string, Member>([
      ['org-a:mem_a_1', { orgId: 'org-a', memberId: 'mem_a_1', role: 'owner' }],
      ['org-a:mem_a_2', { orgId: 'org-a', memberId: 'mem_a_2', role: 'test-member' }],
      ['org-b:mem_b_1', { orgId: 'org-b', memberId: 'mem_b_1', role: 'owner' }],
    ]),
    redeemedCoupons: new Set<string>(),
    redemptions: [] as Array<{ code: string; userId: string; receipt: string }>,
    uploads: new Map<string, Upload>(),
    webhookEvents: [] as Array<{ endpoint: string; signed: boolean; body: string }>,
    ssrfFetches: [] as Array<{ url: string; dnsAnswered: boolean; httpStatus: number | null }>,
  }
}

// ---------------------------------------------------------------------------
// Minimal deterministic SQL WHERE-clause evaluator for the planted boolean SQLi.
// Emulates: SELECT id,title FROM products WHERE category = '<filter>'
// ---------------------------------------------------------------------------
type SqlEval = { kind: 'rows'; rows: typeof PRODUCTS } | { kind: 'error'; message: string }

function evalSqlTerm(term: string): boolean | null {
  const t = term.trim()
  const eq = /^(-?\d+)\s*(=|<>|!=|>|<)\s*(-?\d+)$/.exec(t)
  if (eq) {
    const a = Number(eq[1]); const b = Number(eq[3])
    switch (eq[2]) {
      case '=': return a === b
      case '<>': case '!=': return a !== b
      case '>': return a > b
      case '<': return a < b
    }
  }
  const strEq = /^'([^']*)'\s*=\s*'([^']*)'$/.exec(t)
  if (strEq) return strEq[1] === strEq[2]
  if (/^(?:true|1)$/i.test(t)) return true
  if (/^(?:false|0)$/i.test(t)) return false
  return null
}

export function evaluateProductFilter(filter: string): SqlEval {
  const where = `category = '${filter}'`
  // Strip trailing SQL comment once the quoted literal has been closed.
  let clause = where
  const commentIdx = (() => {
    let inStr = false
    for (let i = 0; i < clause.length; i++) {
      const ch = clause[i]
      if (ch === "'") {
        if (inStr && clause[i + 1] === "'") { i++; continue }
        inStr = !inStr
      } else if (!inStr && (clause.startsWith('--', i) || ch === '#')) {
        return i
      }
    }
    return inStr ? -2 : -1
  })()
  if (commentIdx === -2) return { kind: 'error', message: 'SQLITE_ERROR: unrecognized token: "\'"' }
  if (commentIdx >= 0) clause = clause.slice(0, commentIdx)
  // Balanced quotes required after comment stripping.
  const quoteCount = (clause.match(/'/g) ?? []).length - 2 * (clause.match(/''/g) ?? []).length
  if (quoteCount % 2 !== 0) return { kind: 'error', message: 'SQLITE_ERROR: unrecognized token: "\'"' }

  const m = /^category = '((?:[^']|'')*)'(.*)$/s.exec(clause.trim())
  if (!m) return { kind: 'error', message: 'SQLITE_ERROR: syntax error' }
  const category = m[1].replace(/''/g, "'")
  const tail = m[2].trim()
  const base = PRODUCTS.filter(p => p.category === category)
  if (!tail) return { kind: 'rows', rows: base }
  const logic = /^(AND|OR)\s+(.+)$/is.exec(tail)
  if (!logic) return { kind: 'error', message: `SQLITE_ERROR: near "${tail.slice(0, 16)}": syntax error` }
  const term = evalSqlTerm(logic[2].trim().replace(/^\((.*)\)$/s, '$1'))
  if (term === null) return { kind: 'error', message: 'SQLITE_ERROR: syntax error' }
  if (logic[1].toUpperCase() === 'AND') return { kind: 'rows', rows: term ? base : [] }
  return { kind: 'rows', rows: term ? PRODUCTS : base }
}

// ---------------------------------------------------------------------------
// Minimal RFC 6455 WebSocket server helpers (text frames only, deterministic).
// ---------------------------------------------------------------------------
function wsAccept(key: string): string {
  return createHash('sha1').update(key + '258EAFA5-E914-47DA-95CA-C5AB0DC85B11').digest('base64')
}

function wsEncodeText(text: string): Buffer {
  const payload = Buffer.from(text, 'utf8')
  const len = payload.length
  let header: Buffer
  if (len < 126) {
    header = Buffer.from([0x81, len])
  } else if (len < 65_536) {
    header = Buffer.alloc(4); header[0] = 0x81; header[1] = 126; header.writeUInt16BE(len, 2)
  } else {
    header = Buffer.alloc(10); header[0] = 0x81; header[1] = 127; header.writeBigUInt64BE(BigInt(len), 2)
  }
  return Buffer.concat([header, payload])
}

function wsClose(code = 1000): Buffer {
  const b = Buffer.alloc(4); b[0] = 0x88; b[1] = 2; b.writeUInt16BE(code, 2); return b
}

function wsDecodeFrames(buf: Buffer): { frames: Array<{ opcode: number; payload: Buffer }>; rest: Buffer } {
  const frames: Array<{ opcode: number; payload: Buffer }> = []
  let off = 0
  while (buf.length - off >= 2) {
    const b0 = buf[off]; const b1 = buf[off + 1]
    const opcode = b0 & 0x0f
    const masked = (b1 & 0x80) !== 0
    let len = b1 & 0x7f
    let hdr = 2
    if (len === 126) { if (buf.length - off < 4) break; len = buf.readUInt16BE(off + 2); hdr = 4 }
    else if (len === 127) { if (buf.length - off < 10) break; len = Number(buf.readBigUInt64BE(off + 2)); hdr = 10 }
    const maskLen = masked ? 4 : 0
    if (buf.length - off < hdr + maskLen + len) break
    const mask = masked ? buf.subarray(off + hdr, off + hdr + 4) : null
    const payload = Buffer.from(buf.subarray(off + hdr + maskLen, off + hdr + maskLen + len))
    if (mask) for (let i = 0; i < payload.length; i++) payload[i] ^= mask[i % 4]
    frames.push({ opcode, payload })
    off += hdr + maskLen + len
  }
  return { frames, rest: buf.subarray(off) }
}

// ---------------------------------------------------------------------------
// Multipart parser (bounded, text-only — sufficient for benign upload probes).
// ---------------------------------------------------------------------------
function parseMultipart(body: Buffer, contentType: string): Array<{ name: string; filename?: string; contentType?: string; content: string }> {
  const bm = /boundary=(?:"([^"]+)"|([^;]+))/i.exec(contentType)
  if (!bm) return []
  const boundary = '--' + (bm[1] ?? bm[2]).trim()
  const text = body.toString('latin1')
  const parts: Array<{ name: string; filename?: string; contentType?: string; content: string }> = []
  for (const raw of text.split(boundary).slice(1)) {
    if (raw.startsWith('--')) break
    const section = raw.replace(/^\r\n/, '')
    const sep = section.indexOf('\r\n\r\n')
    if (sep === -1) continue
    const headerBlock = section.slice(0, sep)
    let content = section.slice(sep + 4)
    if (content.endsWith('\r\n')) content = content.slice(0, -2)
    const disp = /content-disposition:\s*form-data;([^\r\n]*)/i.exec(headerBlock)?.[1] ?? ''
    const name = /\bname="([^"]*)"/i.exec(disp)?.[1] ?? ''
    const filename = /\bfilename="([^"]*)"/i.exec(disp)?.[1]
    const ct = /content-type:\s*([^\r\n]+)/i.exec(headerBlock)?.[1]?.trim()
    parts.push({ name, filename, contentType: ct, content: Buffer.from(content, 'latin1').toString('utf8') })
  }
  return parts
}

function readBody(req: IncomingMessage, limit = 512 * 1024): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = []
    let size = 0
    req.on('data', (c: Buffer) => {
      size += c.length
      if (size > limit) { reject(new Error('body too large')); req.destroy(); return }
      chunks.push(c)
    })
    req.on('end', () => resolve(Buffer.concat(chunks)))
    req.on('error', reject)
  })
}

function json(res: ServerResponse, status: number, body: unknown, headers: Record<string, string> = {}) {
  res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8', ...headers }).end(JSON.stringify(body))
}

function escapeHtml(s: string): string {
  return s.replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]!))
}

export async function createSuiteBLab(options: SuiteBLabOptions = {}) {
  let state = freshState()
  const knownUsers = users()
  const requests: LabRequestRecord[] = []
  const raceGapMs = options.raceGapMs ?? 40
  const wsSockets = new Set<Duplex>()

  function authUser(req: IncomingMessage): LabUser | null {
    const authz = req.headers.authorization
    if (typeof authz === 'string') {
      const token = /^Bearer\s+(.+)$/i.exec(authz)?.[1]?.trim()
      const user = knownUsers.find(u => u.token === token)
      if (user) return user
    }
    const cookie = req.headers.cookie
    if (typeof cookie === 'string') {
      const sid = /(?:^|;\s*)sid=([^;]+)/.exec(cookie)?.[1]
      const user = knownUsers.find(u => u.token === sid)
      if (user) return user
    }
    return null
  }

  async function ssrfSink(target: string): Promise<{ dnsAnswered: boolean; httpStatus: number | null }> {
    let url: URL
    try { url = new URL(target) } catch { return { dnsAnswered: false, httpStatus: null } }
    let dnsAnswered = false
    let httpStatus: number | null = null
    const host = url.hostname
    if (!/^[\d.]+$/.test(host) && options.dnsResolver) {
      const resolver = new Resolver({ timeout: 1500, tries: 1 })
      resolver.setServers([`${options.dnsResolver.host}:${options.dnsResolver.port}`])
      try {
        const answers = await resolver.resolve4(host)
        dnsAnswered = answers.length > 0
      } catch { /* blind */ }
    }
    // Only ever fetch loopback (the local HTTP canary listener) — the lab never egresses.
    if (host === '127.0.0.1' && (url.protocol === 'http:' || url.protocol === 'https:')) {
      try {
        const r = await fetch(url, { signal: AbortSignal.timeout(2000), redirect: 'manual' })
        httpStatus = r.status
        await r.body?.cancel().catch(() => undefined)
      } catch { /* blind */ }
    }
    return { dnsAnswered, httpStatus }
  }

  async function handle(req: IncomingMessage, res: ServerResponse) {
    const url = new URL(req.url ?? '/', 'http://lab.local')
    const path = url.pathname
    const method = req.method ?? 'GET'
    requests.push({ method, path: path + url.search, headers: { ...req.headers }, at: Date.now() })
    const user = authUser(req)

    // ---- infra ----
    if (path === '/health') return json(res, 200, { ok: true })
    if (path === '/app.js') {
      res.writeHead(200, { 'Content-Type': 'application/javascript; charset=utf-8' })
        .end('fetch("/api/me",{credentials:"include"});fetch("/api/products?category=plans");\n')
      return
    }

    // ---- #1 Server Action BOLA ----
    if (path === '/_actions/getInvoice' && method === 'POST') {
      if (!user) return json(res, 401, { ok: false, error: 'unauthenticated' })
      const body = JSON.parse((await readBody(req)).toString('utf8') || '{}') as { invoiceId?: string }
      const invoice = state.invoices.get(String(body.invoiceId ?? ''))
      if (!invoice) return json(res, 404, { ok: false, error: 'not_found' })
      // PLANTED BUG: missing invoice.ownerId === user.id check.
      return json(res, 200, { ok: true, invoice })
    }

    // ---- #2 DELETE member BFLA ----
    const memberMatch = /^\/api\/orgs\/([a-z0-9-]+)\/members\/([a-z0-9_]+)$/.exec(path)
    if (memberMatch) {
      const [, orgId, memberId] = memberMatch
      const key = `${orgId}:${memberId}`
      if (!user) return json(res, 401, { error: 'unauthenticated' })
      if (method === 'GET') {
        const m = state.members.get(key)
        if (!m) return json(res, 404, { error: 'not_found' })
        if (user.orgId !== orgId) return json(res, 403, { error: 'forbidden' })
        return json(res, 200, { member: m })
      }
      if (method === 'DELETE') {
        if (!state.members.has(key)) return json(res, 404, { error: 'not_found' })
        // PLANTED BUG: no user.orgId === orgId tenant check before delete.
        state.members.delete(key)
        return json(res, 200, { deleted: true, orgId, memberId, deletedBy: user.id })
      }
    }

    // ---- #3 Webhook fail-open ----
    if ((path === '/api/webhooks/billing' || path === '/api/webhooks/payments') && method === 'POST') {
      const raw = (await readBody(req)).toString('utf8')
      const sig = req.headers['x-signature']
      const secret = path.endsWith('/payments') ? LAB_WEBHOOK_SECRET_PAYMENTS : undefined
      let accepted: boolean
      if (!secret) {
        accepted = true // PLANTED BUG: signing secret unset => fail open.
      } else {
        const expected = createHash('sha256').update(secret + raw).digest('hex')
        accepted = typeof sig === 'string' && sig === expected
      }
      state.webhookEvents.push({ endpoint: path, signed: typeof sig === 'string', body: raw.slice(0, 512) })
      if (!accepted) return json(res, 401, { accepted: false, error: 'invalid_signature' })
      return json(res, 200, { accepted: true, endpoint: path, processed: 'invoice.paid' })
    }

    // ---- #4 Boolean-blind SQLi ----
    if (path === '/api/products' && method === 'GET') {
      const category = url.searchParams.get('category') ?? 'plans'
      const result = evaluateProductFilter(category)
      if (result.kind === 'error') return json(res, 500, { error: 'database_error', detail: result.message })
      return json(res, 200, { count: result.rows.length, products: result.rows })
    }

    // ---- #5 SSTI (arithmetic evaluation) ----
    if (path === '/api/preview-template' && method === 'GET') {
      const template = url.searchParams.get('template') ?? 'Hello'
      // PLANTED BUG: evaluates {{a*b}} / ${a*b} / <%= a*b %> / #{a*b} expressions from user input.
      const rendered = template.replace(/(?:\{\{|\$\{|<%=|#\{)\s*(\d{1,9})\s*\*\s*(\d{1,9})\s*(?:\}\}|\}|%>)/g,
        (_m, a: string, b: string) => String(BigInt(a) * BigInt(b)))
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' }).end(`<div class="preview">${rendered}</div>`)
      return
    }

    // ---- D3 decoy: reflected, non-executing template ----
    if (path === '/api/echo-template' && method === 'GET') {
      const template = url.searchParams.get('template') ?? ''
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' })
        .end(`<div class="echo">You entered: ${escapeHtml(template)}</div>`)
      return
    }

    // ---- #6 Blind SSRF ----
    if (path === '/api/webhooks/preview' && method === 'GET') {
      const target = url.searchParams.get('url') ?? ''
      const outcome = await ssrfSink(target)
      state.ssrfFetches.push({ url: target, ...outcome })
      return json(res, 202, { queued: true })
    }

    // ---- #8 postMessage DOM XSS page ----
    if (path === '/preview-frame') {
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' }).end(PREVIEW_FRAME_HTML)
      return
    }

    // ---- #9 Coupon race ----
    if (path === '/api/coupons/redeem' && method === 'POST') {
      if (!user) return json(res, 401, { error: 'unauthenticated' })
      const body = JSON.parse((await readBody(req)).toString('utf8') || '{}') as { code?: string }
      const code = String(body.code ?? '')
      if (code !== 'WELCOME50') return json(res, 404, { error: 'unknown_coupon' })
      const key = `${user.id}:${code}`
      if (state.redeemedCoupons.has(key)) return json(res, 409, { error: 'already_redeemed' })
      await delay(raceGapMs) // PLANTED BUG: async gap between check and set.
      state.redeemedCoupons.add(key)
      const receipt = 'rcpt_' + randomUUID().slice(0, 8)
      state.redemptions.push({ code, userId: user.id, receipt })
      return json(res, 200, { redeemed: true, receipt })
    }
    if (path === '/api/coupons/redemptions' && method === 'GET') {
      if (!user) return json(res, 401, { error: 'unauthenticated' })
      const count = state.redemptions.filter(r => r.userId === user.id).length
      return json(res, 200, { userId: user.id, redemptionCount: count })
    }

    // ---- #10 Stored SVG upload ----
    if (path === '/api/uploads' && method === 'POST') {
      const ct = String(req.headers['content-type'] ?? '')
      if (!ct.toLowerCase().startsWith('multipart/form-data')) return json(res, 415, { error: 'multipart_required' })
      const parts = parseMultipart(await readBody(req), ct)
      const file = parts.find(p => p.filename)
      if (!file) return json(res, 400, { error: 'file_required' })
      const id = 'up_' + randomUUID().slice(0, 12)
      state.uploads.set(id, {
        id,
        filename: file.filename!,
        contentType: file.contentType ?? 'application/octet-stream',
        content: file.content,
        ownerId: user?.id ?? null,
      })
      return json(res, 201, { id, url: `/uploads/${id}` })
    }
    const uploadMatch = /^\/uploads\/(up_[a-f0-9-]{1,40})$/.exec(path)
    if (uploadMatch) {
      const upload = state.uploads.get(uploadMatch[1])
      if (!upload) return json(res, 404, { error: 'not_found' })
      if (method === 'DELETE') {
        state.uploads.delete(upload.id)
        return json(res, 200, { deleted: true })
      }
      // PLANTED BUG: served inline with the attacker-supplied content type, no Content-Disposition.
      res.writeHead(200, { 'Content-Type': upload.contentType }).end(upload.content)
      return
    }

    // ---- #11 Credentialed reflected CORS ----
    if (path === '/api/me') {
      const origin = req.headers.origin
      const cors: Record<string, string> = typeof origin === 'string'
        ? { 'Access-Control-Allow-Origin': origin, 'Access-Control-Allow-Credentials': 'true', Vary: 'Origin' }
        : {}
      if (method === 'OPTIONS') {
        res.writeHead(204, { ...cors, 'Access-Control-Allow-Methods': 'GET', 'Access-Control-Allow-Headers': 'content-type' }).end()
        return
      }
      if (!user) return json(res, 401, { error: 'unauthenticated' }, cors)
      return json(res, 200, { id: user.id, email: user.email, orgId: user.orgId, billingRole: 'admin' }, cors)
    }

    // ---- #12 CVE-2025-29927 / D1 edge-blocked decoy ----
    if (path === '/api/admin/stats' || path === '/edge/api/admin/stats') {
      const edgeProtected = path.startsWith('/edge/')
      const sub = edgeProtected ? undefined : req.headers['x-middleware-subrequest']
      if (sub && String(sub).includes('middleware')) {
        return json(res, 200, { admin: true, marker: 'admin_bypass_confirmed', tenants: 42 })
      }
      return json(res, 401, { error: 'unauthorized' })
    }

    // ---- unknown API → real 404 ----
    if (path.startsWith('/api/')) return json(res, 404, { error: 'not_found' })

    // ---- D2: SPA catch-all for everything else (/, /actuator/env, /.kovo-cal-*, ...) ----
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' }).end(INDEX_HTML)
  }

  function handleUpgrade(req: IncomingMessage, socket: Duplex) {
    const url = new URL(req.url ?? '/', 'http://lab.local')
    requests.push({ method: 'WS', path: url.pathname + url.search, headers: { ...req.headers }, at: Date.now() })
    const key = req.headers['sec-websocket-key']
    if (url.pathname !== '/ws/notifications' || typeof key !== 'string') {
      socket.end('HTTP/1.1 404 Not Found\r\nConnection: close\r\n\r\n')
      return
    }
    const user = authUser(req)
    // PLANTED BUG (#7): Origin header is never validated on a cookie/bearer-authenticated socket.
    socket.write([
      'HTTP/1.1 101 Switching Protocols',
      'Upgrade: websocket',
      'Connection: Upgrade',
      `Sec-WebSocket-Accept: ${wsAccept(key)}`,
      '', '',
    ].join('\r\n'))
    wsSockets.add(socket)
    socket.on('close', () => wsSockets.delete(socket))
    socket.on('error', () => wsSockets.delete(socket))
    if (!user) {
      socket.write(wsEncodeText(JSON.stringify({ type: 'error', error: 'unauthenticated' })))
      socket.end(wsClose(1008))
      return
    }
    socket.write(wsEncodeText(JSON.stringify({
      type: 'account',
      userId: user.id,
      email: user.email,
      orgId: user.orgId,
      unreadInvoices: [...state.invoices.values()].filter(i => i.ownerId === user.id).map(i => i.id),
      origin: req.headers.origin ?? null,
    })))
    let buffered: Buffer = Buffer.alloc(0)
    socket.on('data', (chunk: Buffer) => {
      buffered = Buffer.concat([buffered, chunk])
      const { frames, rest } = wsDecodeFrames(buffered)
      buffered = rest
      for (const f of frames) {
        if (f.opcode === 0x8) { socket.end(wsClose(1000)); return }
        if (f.opcode === 0x9) continue
        if (f.opcode === 0x1) {
          const text = f.payload.toString('utf8')
          socket.write(wsEncodeText(JSON.stringify({ type: 'echo', userId: user.id, received: text.slice(0, 512) })))
        }
      }
    })
  }

  const server = createServer((req, res) => {
    handle(req, res).catch(err => {
      if (!res.headersSent) json(res, 500, { error: 'lab_internal', detail: String(err?.message ?? err) })
      else res.end()
    })
  })
  server.on('upgrade', handleUpgrade)
  server.listen(0, '127.0.0.1')
  await once(server, 'listening')
  const address = server.address()
  if (!address || typeof address === 'string') throw new Error('Suite B lab has no address.')
  const origin = `http://127.0.0.1:${address.port}`

  return {
    origin,
    port: address.port,
    users: knownUsers,
    requests,
    get state() { return state },
    reset() {
      state = freshState()
      requests.length = 0
    },
    async close() {
      for (const s of wsSockets) s.destroy()
      server.closeAllConnections()
      await new Promise<void>(resolve => server.close(() => resolve()))
    },
  }
}

export type SuiteBLab = Awaited<ReturnType<typeof createSuiteBLab>>
