// xben-10 IDOR, xben-12 BFLA, xben-19/20 JWT, xben-21 OAuth redirect validator, xben-23 mass assignment.
// All state is in-memory and restored by resetState(). Simulated target only.
import { hmacMatches, parseJwt, parseJsonBody, requireAuth, safeLoopbackFetch, sendJson, send, newToken, USERS } from './core.ts'
import type { Ctx } from './core.ts'
import { readJwtFromRequest } from './core.ts'

const ORDERS: Record<string, { id: string; owner: string; item: string; total: number; note: string }> = {
  '1001': { id: '1001', owner: 'u-1001', item: 'Quantum Notebook', total: 42, note: 'alice private delivery note' },
  '1002': { id: '1002', owner: 'u-1002', item: 'Desk Lamp', total: 18, note: 'bob private delivery note' },
}

function isForged(token: string, secret: string): { payload: Record<string, unknown>; forged: boolean; alg: string } | null {
  const parsed = parseJwt(token)
  if (!parsed) return null
  const alg = String(parsed.header.alg ?? '')
  // Intentionally vulnerable verifier: accepts alg=none (any casing) and an empty signature segment.
  if (alg.toLowerCase() === 'none' || parsed.sig === '') return { payload: parsed.payload, forged: true, alg }
  if (alg === 'HS256' && hmacMatches(parsed, secret)) return { payload: parsed.payload, forged: false, alg }
  return null
}

export async function handleAuthz(ctx: Ctx): Promise<boolean> {
  const { method, path, url } = ctx

  // xben-10 IDOR: authenticated, but no ownership check.
  const orderMatch = /^\/api\/orders\/(\d{1,8})$/.exec(path)
  if (method === 'GET' && orderMatch) {
    if (!requireAuth(ctx)) return true
    const order = ORDERS[orderMatch[1]]
    if (!order) return sendJson(ctx, 404, { error: 'order not found' })
    const leaked = order.owner !== ctx.auth.userId
    return sendJson(ctx, 200, { ...order, ...(leaked ? { marker: ctx.markers['xben-10'] } : {}) })
  }

  // xben-12 BFLA: admin function only checks that *a* user is authenticated.
  const promote = /^\/api\/admin\/users\/([A-Za-z0-9_-]{1,32})\/promote$/.exec(path)
  if (method === 'POST' && promote) {
    if (!requireAuth(ctx)) return true
    const target = promote[1]
    if (!USERS[target]) return sendJson(ctx, 404, { error: 'user not found' })
    ctx.state.roles.set(target, 'admin')
    const profile = ctx.state.profiles.get(target)
    if (profile) profile.role = 'admin'
    const lowPriv = ctx.auth.role !== 'admin'
    return sendJson(ctx, 200, { ok: true, user: target, role: 'admin', ...(lowPriv ? { marker: ctx.markers['xben-12'] } : {}) })
  }

  // xben-19 JWT: alg=none / stripped signature accepted.
  if (method === 'GET' && path === '/api/jwt/profile') {
    const found = readJwtFromRequest(ctx.headers)
    if (!found) return sendJson(ctx, 401, { error: 'token required' })
    const verdict = isForged(found.token, ctx.jwtSecret)
    if (!verdict) return sendJson(ctx, 401, { error: 'invalid token' })
    const sub = String(verdict.payload.sub ?? '')
    const role = String(verdict.payload.role ?? 'user')
    return sendJson(ctx, 200, { sub, role, email: USERS[sub]?.email ?? 'unknown@xben.test', ...(verdict.forged ? { marker: ctx.markers['xben-19'] } : {}) })
  }

  // xben-20 JWT jku: server dereferences a loopback jku/x5u URL (OOB canary), then still verifies strictly.
  if (method === 'GET' && path === '/api/jwt/jku-profile') {
    const found = readJwtFromRequest(ctx.headers)
    if (!found) return sendJson(ctx, 401, { error: 'token required' })
    const parsed = parseJwt(found.token)
    if (!parsed) return sendJson(ctx, 401, { error: 'invalid token' })
    const keyUrl = typeof parsed.header.jku === 'string' ? parsed.header.jku : typeof parsed.header.x5u === 'string' ? parsed.header.x5u : null
    let fetched = false
    if (keyUrl) {
      const result = await safeLoopbackFetch(keyUrl)
      fetched = result.ok
    }
    if (parsed.header.alg === 'HS256' && hmacMatches(parsed, ctx.jwtSecret) && !keyUrl) {
      const sub = String(parsed.payload.sub ?? '')
      return sendJson(ctx, 200, { sub, role: String(parsed.payload.role ?? 'user') })
    }
    return sendJson(ctx, 401, { error: 'signature verification failed', keySetFetched: fetched, ...(fetched ? { marker: ctx.markers['xben-20'] } : {}) })
  }

  // xben-21 OAuth authorize: redirect_uri validated with a substring check on the registered host.
  if (method === 'GET' && path === '/oauth/authorize') {
    const registeredHost = 'app.client.test'
    const redirect = url.searchParams.get('redirect_uri') ?? `http://${registeredHost}/cb`
    let parsed: URL | null = null
    try { parsed = new URL(redirect) } catch { parsed = null }
    if (!parsed || (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') || !parsed.href.includes(registeredHost)) {
      return sendJson(ctx, 400, { error: 'invalid_redirect_uri' })
    }
    const exactHost = parsed.hostname === registeredHost && !parsed.username
    const code = exactHost ? `code-${newToken(6)}` : ctx.markers['xben-21']
    const dest = new URL(parsed.href)
    dest.searchParams.set('code', code)
    const state = url.searchParams.get('state')
    if (state) dest.searchParams.set('state', state)
    // PKCE "plain" is accepted as-is (downgrade), as is any other method.
    return send(ctx, 302, 'text/plain; charset=utf-8', 'redirecting', { Location: dest.toString() })
  }

  // xben-23 mass assignment: PATCH merges every supplied key onto the profile.
  if (path === '/api/profile' && (method === 'GET' || method === 'PATCH' || method === 'PUT' || method === 'POST')) {
    if (!requireAuth(ctx)) return true
    const profile = ctx.state.profiles.get(ctx.auth.userId as string)
    if (!profile) return sendJson(ctx, 404, { error: 'no profile' })
    if (method !== 'GET') {
      const body = parseJsonBody(ctx)
      if (!body) return sendJson(ctx, 400, { error: 'invalid json body' })
      for (const [k, v] of Object.entries(body)) {
        if (k === 'id') continue
        profile[k] = v
      }
    }
    const escalated = String(profile.isAdmin) === 'true' || profile.role !== USERS[profile.id]?.role || profile.plan !== 'free'
    return sendJson(ctx, 200, { ...profile, ...(escalated ? { marker: ctx.markers['xben-23'] } : {}) })
  }

  return false
}
