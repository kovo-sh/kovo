// Helpers for tests/decoy-audit.test.ts: per-app solver contexts, oracle-event attribution, and
// file-tree readers used to prove decoy twins are neutral and materialization leaks no identity.
import { readdirSync, readFileSync, statSync } from 'node:fs'
import { join } from 'node:path'
import { pathToFileURL } from 'node:url'
import type { AppModule, OracleEvent, SiteMode, SiteSpec, StartedApp, VariantPlan } from '../../lib/types.ts'
import { makeSolverCtx as makeAcmeCtx } from './site-matrix.ts'
import { makeSolverCtx as makeShopCtx } from '../../apps/shopflow/truth/matrix-helpers.ts'
import { makeClient as makeOpsCtx } from '../../apps/opsportal/truth/matrix-helpers.ts'

const BENCH_DIR = join(import.meta.dirname, '..', '..')
export const APPS_DIR = join(BENCH_DIR, 'apps')
export const LIB_DIR = join(BENCH_DIR, 'lib')

export function appDir(app: string): string {
  return join(APPS_DIR, app)
}

export function siteDir(app: string, siteId: string): string {
  return join(APPS_DIR, app, 'sites', siteId)
}

export function readText(path: string): string {
  return readFileSync(path, 'utf8')
}

/** Every regular file under root with its text content (tests only; the lab itself uses lib/vfs). */
export function readTree(root: string): Array<{ file: string; text: string }> {
  const out: Array<{ file: string; text: string }> = []
  const walk = (dir: string): void => {
    for (const name of readdirSync(dir)) {
      const full = join(dir, name)
      const st = statSync(full)
      if (st.isDirectory()) walk(full)
      else if (st.isFile()) out.push({ file: full, text: readFileSync(full, 'utf8') })
    }
  }
  walk(root)
  return out
}

/** Oracle events attributed to a site: (kind, routeKey) evidence only, matching the grader rule. */
export function attributed(events: OracleEvent[], spec: Pick<SiteSpec, 'oracle'>): OracleEvent[] {
  const kinds = new Set<string>(spec.oracle.kinds)
  const routeKeys = new Set<string>(spec.oracle.routeKeys)
  return events.filter((e) => kinds.has(e.kind) && e.routeKey !== null && routeKeys.has(e.routeKey))
}

/** The app-specific solver context (each app shipped its own helper type before the shared one). */
export function solverContext(mod: AppModule, app: StartedApp): unknown {
  if (mod.name === 'acme-saas') return makeAcmeCtx(app, 'acme_sid')
  if (mod.name === 'shopflow') return makeShopCtx(app.origin, app.plan)
  return makeOpsCtx(app.origin, app.plan)
}

export async function runSolver(mod: AppModule, siteId: string, ctx: unknown): Promise<void> {
  const file = join(APPS_DIR, mod.name, 'sites', siteId, 'solver.ts')
  const solver = (await import(pathToFileURL(file).href)) as { solve(ctx: unknown): Promise<void> }
  await solver.solve(ctx)
}

/** Concretize a route template with a benign-looking id for every path param. */
export function concretePath(plan: VariantPlan, routeKey: string, value = '1'): string {
  const route = plan.routes[routeKey]
  if (!route) throw new Error(`unknown routeKey ${routeKey}`)
  return route.path.replace(/:([a-zA-Z0-9_]+)/g, encodeURIComponent(value))
}

/** Logical site param name -> runtime query/body field name. */
export function paramName(plan: VariantPlan, logical: string): string {
  return plan.params[logical] ?? logical
}

export function modesOf(plan: VariantPlan): SiteMode[] {
  return Object.values(plan.sites)
}

export interface MinimalResponse {
  status: number
  location: string
}

/** GET a path through any app solver context and normalise the redirect Location shape. */
export async function fetchLocation(
  ctx: { fetch(path: string, init?: unknown): Promise<unknown> },
  path: string,
): Promise<MinimalResponse> {
  const res = (await ctx.fetch(path)) as {
    status?: number
    headers?: { get?: (name: string) => string | null; location?: string | string[] }
  }
  const status = typeof res.status === 'number' ? res.status : 0
  const headerGet = res.headers && typeof res.headers.get === 'function' ? res.headers.get.bind(res.headers) : undefined
  const raw = headerGet ? headerGet('location') : res.headers?.location
  const location = Array.isArray(raw) ? (raw[0] ?? '') : (raw ?? '')
  return { status, location }
}

/** Resolve a Location the way a browser would; returns the host or '' when unparsable. */
export function resolvedHost(location: string, origin: string): string {
  try {
    return new URL(location, origin).host.toLowerCase()
  } catch {
    return ''
  }
}
