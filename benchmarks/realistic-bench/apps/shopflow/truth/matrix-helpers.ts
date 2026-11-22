// Reusable helpers for the site self-test matrix and the per-site solvers: runtime path building and
// a cookie-aware HTTP client bound to one running lab origin.
import type { PersonaId, VariantPlan } from '../../../lib/types.ts'

export interface SolverCtx {
  origin: string
  plan: VariantPlan
  login(persona: PersonaId): Promise<void>
  fetch(path: string, init?: RequestInit): Promise<Response>
  csrf?: string
}

/** Build a runtime request path for a routeKey, substituting path params (keyed by logical name). */
export function buildPath(plan: VariantPlan, routeKey: string, subs: Record<string, string> = {}): string {
  const route = plan.routes[routeKey]
  if (!route) throw new Error(`unknown routeKey ${routeKey}`)
  let path = route.path
  for (const [logical, value] of Object.entries(subs)) {
    const runtime = plan.params[logical] ?? logical
    path = path.replace(`:${runtime}`, encodeURIComponent(value))
  }
  return path
}

export function makeSolverCtx(origin: string, plan: VariantPlan): SolverCtx {
  const jar = new Map<string, string>()
  const cookieHeader = (): string => [...jar].map(([k, v]) => `${k}=${v}`).join('; ')
  const store = (res: Response): void => {
    const setCookies = typeof res.headers.getSetCookie === 'function' ? res.headers.getSetCookie() : []
    for (const c of setCookies) {
      const pair = c.split(';')[0] ?? ''
      const i = pair.indexOf('=')
      if (i > 0) jar.set(pair.slice(0, i), pair.slice(i + 1))
    }
  }

  const doFetch = async (path: string, init: RequestInit = {}): Promise<Response> => {
    const headers = new Headers(init.headers as HeadersInit | undefined)
    if (jar.size) headers.set('cookie', cookieHeader())
    headers.set('origin', origin)
    if (ctx.csrf) headers.set('x-csrf-token', ctx.csrf)
    const res = await fetch(origin + path, { ...init, headers, redirect: 'manual' })
    store(res)
    return res
  }

  const ctx: SolverCtx = {
    origin,
    plan,
    csrf: undefined,
    async login(persona) {
      const p = plan.personas[persona]
      const res = await doFetch(buildPath(plan, 'login'), {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ email: p.email, password: p.password }),
      })
      const data = (await res.json().catch(() => ({}))) as { csrf?: string }
      if (data && typeof data.csrf === 'string') ctx.csrf = data.csrf
    },
    fetch: doFetch,
  }
  return ctx
}
