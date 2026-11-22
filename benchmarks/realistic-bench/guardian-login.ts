// Persona login for a materialized realistic-bench app.
//
// Guardian's EngineEnv expects ready-to-use credentials per persona ({cookie} or {token}),
// while the benchmark briefing only hands out email/password (plus origin + optional API ref).
// This module bridges the two by deriving the login route from the materialized surface
// (variant.json routes), never from truth/ or a manifest.
import { LOOPBACK } from './lib/safety.ts'

export interface LoginPersona {
  id: string
  email: string
  password: string
  role?: string
  /** Multi-tenant apps may require the workspace slug at login; tried as a fallback only. */
  tenant?: string
}

export interface PersonaAuth {
  /** Cookie header value, e.g. `sid=abc; theme=dark`. */
  cookie?: string
  /** Bearer token when the app returns one instead of a cookie. */
  token?: string
  role?: string
}

export interface LoginOutcome {
  personas: Record<string, PersonaAuth>
  notes: string[]
}

const LOGIN_TIMEOUT_MS = 5_000
const TOKEN_FIELDS = ['access_token', 'accessToken', 'token', 'jwt', 'id_token']

function cookieHeader(setCookies: string[]): string | undefined {
  const pairs: string[] = []
  for (const raw of setCookies) {
    const pair = raw.split(';', 1)[0]?.trim() ?? ''
    if (!pair.includes('=')) continue
    // Drop explicit deletions (logout/expired) but keep every name: labs use prefixed
    // cookies such as `acme_sid` / `shopflow_sid`, not just `sid`/`session`.
    if (/(?:^|;\s*)max-age=0(?:;|$)/i.test(raw)) continue
    if (/;\s*expires=thu,\s*01\s*jan\s*1970/i.test(raw)) continue
    pairs.push(pair)
  }
  return pairs.length ? pairs.join('; ') : undefined
}

function tokenFromBody(text: string): string | undefined {
  let parsed: unknown
  try { parsed = JSON.parse(text) } catch { return undefined }
  if (!parsed || typeof parsed !== 'object') return undefined
  const rec = parsed as Record<string, unknown>
  for (const key of TOKEN_FIELDS) {
    const v = rec[key]
    if (typeof v === 'string' && v.length >= 8) return v
  }
  const data = rec.data
  if (data && typeof data === 'object') {
    const nested = data as Record<string, unknown>
    for (const key of TOKEN_FIELDS) {
      const v = nested[key]
      if (typeof v === 'string' && v.length >= 8) return v
    }
  }
  return undefined
}

function setCookies(res: Response): string[] {
  const headers = res.headers as unknown as { getSetCookie?: () => string[] }
  if (typeof headers.getSetCookie === 'function') return headers.getSetCookie()
  const single = res.headers.get('set-cookie')
  return single ? [single] : []
}

/** Choose the login route from the materialized surface. Prefers POST, avoids legacy surfaces. */
export function pickLoginPath(
  routes: Array<{ routeKey?: string; method: string; path: string }>,
): string | null {
  const named = routes.filter(r => /login|signin|sign-in|session/i.test(`${r.routeKey ?? ''} ${r.path}`))
  const posts = named.filter(r => r.method.toUpperCase() === 'POST')
  const ranked = (posts.length ? posts : named).slice().sort((a, b) => {
    const legacy = (r: { routeKey?: string }) => (/legacy|v1\//i.test(r.routeKey ?? '') ? 1 : 0)
    const exact = (r: { routeKey?: string }) => (/^(login|signin|session)$/i.test(r.routeKey ?? '') ? 0 : 1)
    return exact(a) - exact(b) || legacy(a) - legacy(b)
  })
  return ranked[0]?.path ?? null
}

function loopbackOrigin(origin: string): boolean {
  try {
    const u = new URL(origin)
    return u.hostname === LOOPBACK || u.hostname === 'localhost' || u.hostname === '::1'
  } catch { return false }
}

/**
 * Log every briefing persona in and return cookie/bearer credentials keyed by persona id.
 * Failures are recorded as notes instead of throwing: a partial persona set still lets the
 * engine probe the unauthenticated surface.
 */
export async function loginPersonas(
  origin: string,
  loginPath: string | null,
  personas: LoginPersona[],
  fetchImpl: typeof fetch = fetch,
): Promise<LoginOutcome> {
  const notes: string[] = []
  const out: Record<string, PersonaAuth> = {}
  if (!loginPath) {
    notes.push('no login route found in the materialized surface; personas are unauthenticated')
    return { personas: out, notes }
  }
  if (!loopbackOrigin(origin)) {
    notes.push(`refusing persona login against non-loopback origin ${origin}`)
    return { personas: out, notes }
  }
  for (const p of personas) {
    const url = new URL(loginPath, origin).toString()
    const bodies: Array<{ label: string; body: string; headers: Record<string, string> }> = [
      { label: 'json', body: JSON.stringify({ email: p.email, password: p.password }), headers: { 'content-type': 'application/json' } },
      { label: 'form', body: new URLSearchParams({ email: p.email, password: p.password }).toString(), headers: { 'content-type': 'application/x-www-form-urlencoded' } },
    ]
    if (p.tenant) {
      bodies.push({
        label: 'json+tenant',
        body: JSON.stringify({ email: p.email, password: p.password, tenant: p.tenant }),
        headers: { 'content-type': 'application/json' },
      })
    }
    let lastStatus = 0
    for (const attempt of bodies) {
      let res: Response
      try {
        res = await fetchImpl(url, {
          method: 'POST', headers: attempt.headers, body: attempt.body, redirect: 'manual',
          signal: AbortSignal.timeout(LOGIN_TIMEOUT_MS),
        })
      } catch (err) {
        notes.push(`login ${p.id} (${attempt.label}) failed: ${(err as Error).message.slice(0, 120)}`)
        continue
      }
      lastStatus = res.status
      const text = await res.text().catch(() => '')
      if (res.status < 200 || res.status >= 400) continue
      const cookie = cookieHeader(setCookies(res))
      const token = tokenFromBody(text)
      if (cookie || token) {
        out[p.id] = { ...(cookie ? { cookie } : {}), ...(token ? { token } : {}), ...(p.role ? { role: p.role } : {}) }
        break
      }
    }
    if (!out[p.id]) notes.push(`login ${p.id}: no session credential (last status ${lastStatus || 'n/a'})`)
  }
  return { personas: out, notes }
}
