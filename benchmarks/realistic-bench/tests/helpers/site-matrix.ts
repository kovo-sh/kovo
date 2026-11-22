// Reusable self-test harness shared by app selftests: an HTTP solver context (login + fetch +
// route-path builder), oracle-event attribution, and a forced-mode boot that drives every planted
// site to a single mode (bypassing the per-seed decoy-count constraint, for the matrix only).
import { request } from 'node:http'
import type {
  AppModule, OracleEvent, PersonaId, SiteSpec, SiteMode, StartedApp, VariantPlan,
} from '../../lib/types.ts'
import { buildGroundTruth } from '../../generator/groundtruth.ts'

export interface SolverSession {
  persona: PersonaId
  headers: Record<string, string>
  csrfToken?: string
  user?: Record<string, unknown>
}

export interface FetchInit {
  method?: string
  headers?: Record<string, string>
  body?: string | Record<string, unknown>
  session?: SolverSession
}

export interface FetchResult {
  status: number
  headers: Record<string, string | string[]>
  text: string
  json: Record<string, unknown> | null
}

export interface SolverCtx {
  origin: string
  plan: VariantPlan
  login(persona: PersonaId): Promise<SolverSession>
  fetch(path: string, init?: FetchInit): Promise<FetchResult>
  path(routeKey: string, pathParams?: Record<string, unknown>, query?: Record<string, unknown>): string
}

function rawRequest(origin: string, method: string, path: string, headers: Record<string, string>, body?: string): Promise<FetchResult> {
  const url = new URL(path.startsWith('http') ? path : origin + path)
  return new Promise((resolve, reject) => {
    const req = request(
      { hostname: url.hostname, port: url.port, path: url.pathname + url.search, method, headers },
      (res) => {
        const chunks: Buffer[] = []
        res.on('data', (c: Buffer) => chunks.push(c))
        res.on('end', () => {
          const text = Buffer.concat(chunks).toString('utf8')
          let json: Record<string, unknown> | null = null
          try { json = JSON.parse(text) as Record<string, unknown> } catch { json = null }
          resolve({ status: res.statusCode ?? 0, headers: res.headers as Record<string, string | string[]>, text, json })
        })
      },
    )
    req.on('error', reject)
    if (body !== undefined) req.write(body)
    req.end()
  })
}

function buildRoutePath(plan: VariantPlan, routeKey: string, pathParams: Record<string, unknown> = {}, query: Record<string, unknown> = {}): string {
  const r = plan.routes[routeKey]
  if (!r) throw new Error(`site-matrix: unknown route key '${routeKey}'`)
  let p = r.path
  for (const [logical, val] of Object.entries(pathParams)) {
    const runtime = plan.params[logical] ?? logical
    p = p.replace(`:${runtime}`, encodeURIComponent(String(val)))
  }
  const qs = Object.entries(query)
    .map(([logical, val]) => `${encodeURIComponent(plan.params[logical] ?? logical)}=${encodeURIComponent(String(val))}`)
    .join('&')
  return qs ? `${p}?${qs}` : p
}

function cookieFrom(setCookie: string | string[] | undefined, name: string): string | null {
  const list = Array.isArray(setCookie) ? setCookie : setCookie ? [setCookie] : []
  for (const c of list) {
    const m = c.match(new RegExp(`${name}=([^;]+)`))
    if (m) return m[1]!
  }
  return null
}

export function makeSolverCtx(app: StartedApp, sessionCookie = 'acme_sid'): SolverCtx {
  const origin = app.origin
  const plan = app.plan
  const ctx: SolverCtx = {
    origin,
    plan,
    path: (routeKey, pathParams, query) => buildRoutePath(plan, routeKey, pathParams, query),
    async fetch(path, init = {}) {
      const headers: Record<string, string> = { ...(init.session?.headers ?? {}), ...(init.headers ?? {}) }
      let body: string | undefined
      if (init.body !== undefined) {
        if (typeof init.body === 'string') body = init.body
        else { body = JSON.stringify(init.body); headers['content-type'] = headers['content-type'] ?? 'application/json' }
      }
      if (init.session?.csrfToken && !headers['x-csrf-token']) headers['x-csrf-token'] = init.session.csrfToken
      return rawRequest(origin, (init.method ?? 'GET').toUpperCase(), path, headers, body)
    },
    async login(persona) {
      const cred = plan.personas[persona]
      const emailField = plan.params.email ?? 'email'
      const res = await this.fetch(buildRoutePath(plan, 'login'), {
        method: 'POST',
        body: { [emailField]: cred.email, email: cred.email, password: cred.password },
      })
      const sid = cookieFrom(res.headers['set-cookie'], sessionCookie)
      const headers: Record<string, string> = {}
      if (sid) headers.cookie = `${sessionCookie}=${sid}`
      return {
        persona,
        headers,
        csrfToken: typeof res.json?.csrfToken === 'string' ? res.json.csrfToken : undefined,
        user: (res.json?.user as Record<string, unknown>) ?? undefined,
      }
    },
  }
  return ctx
}

/** Count oracle events attributable to a site: event.kind in spec kinds AND routeKey in spec routeKeys. */
export function attributeEvents(events: OracleEvent[], spec: SiteSpec): OracleEvent[] {
  const kinds = new Set<string>(spec.oracle.kinds)
  const routeKeys = new Set<string>(spec.oracle.routeKeys)
  return events.filter((e) => kinds.has(e.kind) && e.routeKey !== null && routeKeys.has(e.routeKey))
}

/** Boot an app with every planted site forced to a single mode (ignores decoy-count constraints). */
export function bootForced(mod: AppModule, plan: VariantPlan, mode: SiteMode): Promise<StartedApp> {
  const forced: VariantPlan = {
    ...plan,
    sites: Object.fromEntries(mod.blueprint.sites.map((s) => [s.id, mode])),
  }
  const groundTruth = buildGroundTruth(mod.blueprint, forced)
  return mod.start({ plan: forced, groundTruth })
}
