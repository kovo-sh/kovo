// Shared helpers for the XBEN-25 dev benchmark server.
// Safety: this server is a fully simulated, loopback-only target. It never spawns processes,
// never reads host files, and only ever fetches loopback http URLs (see safeLoopbackFetch).
import { createHmac, randomBytes, timingSafeEqual } from 'node:crypto'
import type { IncomingHttpHeaders, IncomingMessage, ServerResponse } from 'node:http'

export interface PersonaInfo {
  headerName: string
  token: string
  cookie?: string
  jwt?: string
  role: string
  userId: string
}

export interface Profile {
  id: string
  name: string
  email: string
  role: string
  plan: string
  isAdmin: boolean
  [extra: string]: unknown
}

export interface CacheEntry {
  status: number
  contentType: string
  body: string
  storedAt: number
}

export interface ServerState {
  profiles: Map<string, Profile>
  roles: Map<string, string>
  comments: Array<{ id: number; author: string; body: string }>
  cache: Map<string, CacheEntry>
  sessions: Map<string, { csrf: string; createdAt: number }>
}

export interface Authn {
  persona: string | null
  userId: string | null
  role: string | null
  via: 'bearer' | 'cookie' | null
}

export interface Ctx {
  req: IncomingMessage
  res: ServerResponse
  url: URL
  method: string
  path: string
  body: string
  headers: IncomingHttpHeaders
  markers: Record<string, string>
  state: ServerState
  auth: Authn
  jwtSecret: string
  /** Assigned after the listener binds so handlers can emit absolute URLs. */
  origin: string
}

export const USERS: Record<string, { persona: string; role: string; email: string; name: string }> = {
  'u-1000': { persona: 'admin', role: 'admin', email: 'admin@xben.test', name: 'Ada Admin' },
  'u-1001': { persona: 'persona_a', role: 'user', email: 'alice@xben.test', name: 'Alice Archer' },
  'u-1002': { persona: 'persona_b', role: 'user', email: 'bob@xben.test', name: 'Bob Baker' },
  'u-1003': { persona: 'viewer', role: 'viewer', email: 'vera@xben.test', name: 'Vera Viewer' },
  'u-2001': { persona: 'guest', role: 'guest', email: 'guest@xben.test', name: 'Guest Target' },
}

export function freshState(): ServerState {
  const profiles = new Map<string, Profile>()
  const roles = new Map<string, string>()
  for (const [id, u] of Object.entries(USERS)) {
    profiles.set(id, { id, name: u.name, email: u.email, role: u.role, plan: 'free', isAdmin: false })
    roles.set(id, u.role)
  }
  return { profiles, roles, comments: [], cache: new Map(), sessions: new Map() }
}

export const loopbackHosts = new Set(['127.0.0.1', 'localhost', '[::1]', '::1'])

export function isLoopbackHost(host: string): boolean {
  return loopbackHosts.has(host.toLowerCase())
}

// ---------- JWT (HS256) ----------

export function b64u(input: Buffer | string): string {
  return Buffer.from(input).toString('base64url')
}

export function signJwt(payload: Record<string, unknown>, secret: string, header: Record<string, unknown> = { alg: 'HS256', typ: 'JWT' }): string {
  const signingInput = `${b64u(JSON.stringify(header))}.${b64u(JSON.stringify(payload))}`
  const sig = createHmac('sha256', secret).update(signingInput).digest('base64url')
  return `${signingInput}.${sig}`
}

export interface ParsedJwt {
  header: Record<string, unknown>
  payload: Record<string, unknown>
  signingInput: string
  sig: string
}

export function parseJwt(token: string): ParsedJwt | null {
  const parts = token.split('.')
  if (parts.length !== 3) return null
  try {
    const header = JSON.parse(Buffer.from(parts[0], 'base64url').toString('utf8')) as Record<string, unknown>
    const payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8')) as Record<string, unknown>
    if (!header || typeof header !== 'object' || !payload || typeof payload !== 'object') return null
    return { header, payload, signingInput: `${parts[0]}.${parts[1]}`, sig: parts[2] }
  } catch {
    return null
  }
}

export function hmacMatches(parsed: ParsedJwt, secret: string): boolean {
  const expected = createHmac('sha256', secret).update(parsed.signingInput).digest()
  let given: Buffer
  try { given = Buffer.from(parsed.sig, 'base64url') } catch { return false }
  return given.length === expected.length && timingSafeEqual(given, expected)
}

/** Strict verifier used by every normal endpoint: HS256 only, signature + expiry enforced. */
export function verifyJwtStrict(token: string, secret: string): Record<string, unknown> | null {
  const parsed = parseJwt(token)
  if (!parsed || parsed.header.alg !== 'HS256' || !hmacMatches(parsed, secret)) return null
  const exp = parsed.payload.exp
  if (typeof exp === 'number' && exp * 1000 < Date.now()) return null
  return parsed.payload
}

export function readJwtFromRequest(headers: IncomingHttpHeaders): { token: string; via: 'bearer' | 'cookie' } | null {
  const auth = headers.authorization
  if (typeof auth === 'string' && /^bearer\s+/i.test(auth)) return { token: auth.replace(/^bearer\s+/i, '').trim(), via: 'bearer' }
  const cookie = headers.cookie
  if (typeof cookie === 'string') {
    const m = /(?:^|;\s*)xben_session=([^;\s]+)/.exec(cookie)
    if (m) return { token: m[1], via: 'cookie' }
  }
  return null
}

export function authenticate(headers: IncomingHttpHeaders, secret: string): Authn {
  const found = readJwtFromRequest(headers)
  if (!found) return { persona: null, userId: null, role: null, via: null }
  const payload = verifyJwtStrict(found.token, secret)
  const sub = typeof payload?.sub === 'string' ? payload.sub : null
  const user = sub ? USERS[sub] : undefined
  if (!payload || !sub || !user) return { persona: null, userId: null, role: null, via: null }
  return { persona: user.persona, userId: sub, role: typeof payload.role === 'string' ? payload.role : user.role, via: found.via }
}

export function createPersonas(secret: string): Record<string, PersonaInfo> {
  const out: Record<string, PersonaInfo> = {}
  const iat = Math.floor(Date.now() / 1000)
  for (const [userId, u] of Object.entries(USERS)) {
    if (u.persona === 'guest') continue
    const jwt = signJwt({ sub: userId, role: u.role, email: u.email, iat, exp: iat + 86_400 }, secret)
    out[u.persona] = { headerName: 'Authorization', token: `Bearer ${jwt}`, cookie: `xben_session=${jwt}`, jwt, role: u.role, userId }
  }
  return out
}

// ---------- HTTP helpers ----------

export async function readBody(req: IncomingMessage, cap = 256 * 1024): Promise<string> {
  const chunks: Buffer[] = []
  let size = 0
  for await (const chunk of req) {
    const buf = chunk as Buffer
    size += buf.length
    if (size > cap) break
    chunks.push(buf)
  }
  return Buffer.concat(chunks).toString('utf8')
}

export function send(ctx: Ctx, status: number, contentType: string, body: string, headers: Record<string, string | string[]> = {}): true {
  ctx.res.writeHead(status, { 'Content-Type': contentType, 'Cache-Control': 'no-store', ...headers })
  ctx.res.end(body)
  return true
}

export function sendJson(ctx: Ctx, status: number, data: unknown, headers: Record<string, string | string[]> = {}): true {
  return send(ctx, status, 'application/json; charset=utf-8', JSON.stringify(data), headers)
}

export function sendHtml(ctx: Ctx, status: number, html: string, headers: Record<string, string | string[]> = {}): true {
  return send(ctx, status, 'text/html; charset=utf-8', html, headers)
}

export function requireAuth(ctx: Ctx): boolean {
  if (ctx.auth.userId) return true
  sendJson(ctx, 401, { error: 'authentication required' }, { 'WWW-Authenticate': 'Bearer' })
  return false
}

export function parseJsonBody(ctx: Ctx): Record<string, unknown> | null {
  try {
    const parsed = JSON.parse(ctx.body) as unknown
    return parsed && typeof parsed === 'object' && !Array.isArray(parsed) ? parsed as Record<string, unknown> : null
  } catch {
    return null
  }
}

export function sleep(ms: number): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, ms))
}

export function escapeHtml(s: string): string {
  return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#39;')
}

export function newToken(bytes = 12): string {
  return randomBytes(bytes).toString('hex')
}

/**
 * The ONLY outbound network primitive in this server. Loopback http(s) targets only; redirects are
 * never followed; response bodies are truncated. Anything else is refused without a request.
 */
export async function safeLoopbackFetch(rawUrl: string, timeoutMs = 2000): Promise<{ ok: boolean; status: number; body: string; refused?: string }> {
  let target: URL
  try { target = new URL(rawUrl) } catch { return { ok: false, status: 0, body: '', refused: 'malformed_url' } }
  if (target.protocol !== 'http:' && target.protocol !== 'https:') return { ok: false, status: 0, body: '', refused: 'scheme_not_allowed' }
  if (!isLoopbackHost(target.hostname) || target.username || target.password) return { ok: false, status: 0, body: '', refused: 'host_not_loopback' }
  try {
    const resp = await fetch(target, { redirect: 'manual', signal: AbortSignal.timeout(timeoutMs), headers: { 'User-Agent': 'xben25-sim/1' } })
    const text = (await resp.text()).slice(0, 512)
    return { ok: true, status: resp.status, body: text }
  } catch {
    return { ok: false, status: 0, body: '', refused: 'fetch_failed' }
  }
}
