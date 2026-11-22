// Shared helpers for the opsportal site self-test matrix: a cookie-jar HTTP client used by solvers,
// a forced-mode boot, and runSiteMatrix which boots each seed twice (all-vulnerable / all-hardened)
// and checks that vulnerable boots emit >=1 attributed oracle event while hardened boots emit none.
import type { VariantPlan, PersonaId, SiteMode } from '../../../lib/types.ts'
import { generateVariant } from '../../../generator/variant.ts'
import { buildGroundTruth } from '../../../generator/groundtruth.ts'
import { blueprint } from './blueprint.ts'
import { sites } from './sites.ts'
import { bootApp, IMPLEMENTED } from '../index.ts'

export interface SolverCtx {
  origin: string
  plan: VariantPlan
  login(persona: PersonaId): Promise<void>
  fetch(path: string, init?: RequestInit): Promise<Response>
}

export function makeClient(origin: string, plan: VariantPlan): SolverCtx {
  const jar = new Map<string, string>()
  const cookieHeader = (): string => [...jar].map(([k, v]) => `${k}=${v}`).join('; ')

  const req = async (path: string, init: RequestInit = {}): Promise<Response> => {
    const headers = new Headers(init.headers)
    if (jar.size) headers.set('cookie', cookieHeader())
    const res = await fetch(origin + path, { ...init, headers, redirect: 'manual' })
    for (const c of res.headers.getSetCookie?.() ?? []) {
      const pair = c.split(';')[0] ?? ''
      const eq = pair.indexOf('=')
      if (eq < 0) continue
      const k = pair.slice(0, eq).trim()
      const v = pair.slice(eq + 1).trim()
      if (v === '') jar.delete(k)
      else jar.set(k, v)
    }
    return res
  }

  const login = async (persona: PersonaId): Promise<void> => {
    const cred = plan.personas[persona]
    await req(plan.routes.login!.path, {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ email: cred.email, password: cred.password }),
    })
  }

  return { origin, plan, login, fetch: req }
}

export interface MatrixRow {
  siteId: string; seed: number; mode: SiteMode; ok: boolean; detail: string
}
export interface MatrixResult { summary: string; rows: MatrixRow[] }

async function runSolver(siteId: string, client: SolverCtx): Promise<void> {
  const mod = (await import(new URL(`../sites/${siteId}/solver.ts`, import.meta.url).href)) as {
    solve(ctx: SolverCtx): Promise<void>
  }
  await mod.solve(client)
}

export async function runSiteMatrix(opts: { seeds: number[]; siteIds?: string[] }): Promise<MatrixResult> {
  const ids = (opts.siteIds ?? [...IMPLEMENTED]).filter((id) => IMPLEMENTED.has(id))
  const rows: MatrixRow[] = []

  // Each site is exercised against its OWN fresh boot so solvers never contaminate one another via
  // shared seeded state (e.g. two sites mutating the same seeded job row). All sites stay mounted so
  // route registration matches production; only one solver runs per boot.
  for (const seed of opts.seeds) {
    for (const mode of ['vulnerable', 'hardened'] as SiteMode[]) {
      for (const id of ids) {
        const plan = generateVariant(blueprint, seed)
        for (const other of ids) plan.sites[other] = mode
        const gt = buildGroundTruth(blueprint, plan)
        const started = await bootApp(plan, gt)
        const client = makeClient(started.origin, plan)
        try {
          const spec = sites.find((s) => s.id === id)!
          started.oracle.reset()
          let detail = ''
          try { await runSolver(id, client) } catch (err) { detail = `solver error: ${(err as Error).message}` }
          const matched = started.oracle.events().filter(
            (e) => spec.oracle.kinds.includes(e.kind) && e.routeKey !== null && spec.oracle.routeKeys.includes(e.routeKey),
          )
          const ok = mode === 'vulnerable' ? matched.length >= 1 : matched.length === 0
          if (!ok && !detail) {
            detail = mode === 'vulnerable'
              ? `expected an attributed ${spec.oracle.kinds.join('|')} event, saw ${started.oracle.events().map((e) => e.kind).join(',') || 'none'}`
              : `expected no event, saw ${matched.map((e) => e.kind).join(',')}`
          }
          rows.push({ siteId: id, seed, mode, ok, detail })
        } finally {
          await started.stop()
        }
      }
    }
  }

  const failed = rows.filter((r) => !r.ok).length
  return { summary: `opsportal matrix: ${rows.length - failed}/${rows.length} ok across ${opts.seeds.length} seed(s)`, rows }
}
