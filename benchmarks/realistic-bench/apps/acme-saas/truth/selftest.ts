// Self-test matrix for acme-saas: for each seed, boot the app once with every planted site forced
// vulnerable and once forced hardened, run each implemented site's solver, and assert the vulnerable
// boot produces >=1 attributed oracle event while the hardened boot produces zero.
import type { SiteMode, SiteSpec } from '../../../lib/types.ts'
import { generateVariant } from '../../../generator/variant.ts'
import { makeSolverCtx, bootForced, attributeEvents, type SolverCtx } from '../../../tests/helpers/site-matrix.ts'
import appModule from '../index.ts'
import { blueprint } from './blueprint.ts'

interface Implemented { id: string; spec: SiteSpec; solve(ctx: SolverCtx): Promise<void> }

// Every planted site ships spec.ts + solver.ts; load them dynamically from the blueprint so new
// sites light up without hand-editing a static import list.
async function loadImplemented(ids: string[]): Promise<Implemented[]> {
  const out: Implemented[] = []
  for (const id of ids) {
    const specMod = (await import(new URL(`../sites/${id}/spec.ts`, import.meta.url).href)) as { spec: SiteSpec }
    const solveMod = (await import(new URL(`../sites/${id}/solver.ts`, import.meta.url).href)) as { solve(ctx: SolverCtx): Promise<void> }
    out.push({ id: specMod.spec.id, spec: specMod.spec, solve: solveMod.solve })
  }
  return out
}

export interface MatrixRow { siteId: string; seed: number; mode: SiteMode; ok: boolean; detail: string }
export interface MatrixResult { summary: string; rows: MatrixRow[] }

const MODES: SiteMode[] = ['vulnerable', 'hardened']

export async function runSiteMatrix(opts: { seeds: number[]; siteIds?: string[] }): Promise<MatrixResult> {
  const ids = opts.siteIds ?? blueprint.sites.map((s) => s.id)
  const impl = await loadImplemented(ids)
  const rows: MatrixRow[] = []

  // Boot a fresh app per site so solvers never contaminate one another through shared seeded state.
  // All sites stay mounted (route registration matches production); only one solver runs per boot.
  for (const seed of opts.seeds) {
    const plan = generateVariant(blueprint, seed)
    for (const mode of MODES) {
      for (const site of impl) {
        const app = await bootForced(appModule, plan, mode)
        try {
          const ctx = makeSolverCtx(app)
          app.oracle.reset()
          let ok = false
          let detail = ''
          try {
            await site.solve(ctx)
            const matched = attributeEvents(app.oracle.events(), site.spec)
            if (mode === 'vulnerable') {
              ok = matched.length >= 1
              detail = ok ? `${matched.length} attributed event(s)` : 'no attributed event'
            } else {
              ok = matched.length === 0
              detail = ok ? 'no events (decoy safe)' : `unexpected: ${matched.map((e) => e.kind).join(',')}`
            }
          } catch (err) {
            detail = `solver error: ${(err as Error).message}`
          }
          rows.push({ siteId: site.id, seed, mode, ok, detail })
        } finally {
          await app.stop()
        }
      }
    }
  }

  const passed = rows.filter((r) => r.ok).length
  return { summary: `${passed}/${rows.length} matrix checks passed`, rows }
}
