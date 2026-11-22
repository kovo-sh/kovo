// Site self-test matrix. Every planted site is exercised against its OWN fresh boot (all sites stay
// mounted so route registration matches production; only one solver runs per boot) so solvers never
// contaminate one another through shared seeded state. Vulnerable sites must attribute >=1 oracle
// event; hardened twins must attribute none. Sites load dynamically from the blueprint.
import type { OracleEvent, SiteMode, SiteSpec, VariantPlan } from '../../../lib/types.ts'
import { generateVariant } from '../../../generator/variant.ts'
import { buildGroundTruth } from '../../../generator/groundtruth.ts'
import shopflow from '../index.ts'
import { blueprint, implementedSiteIds } from './blueprint.ts'
import { makeSolverCtx } from './matrix-helpers.ts'
import type { SolverCtx } from './matrix-helpers.ts'

interface Impl { id: string; kinds: string[]; routeKeys: string[]; solve: (ctx: SolverCtx) => Promise<void> }

async function loadImpl(id: string): Promise<Impl> {
  const specMod = (await import(new URL(`../sites/${id}/spec.ts`, import.meta.url).href)) as { spec: SiteSpec }
  const solveMod = (await import(new URL(`../sites/${id}/solver.ts`, import.meta.url).href)) as { solve: (ctx: SolverCtx) => Promise<void> }
  return { id: specMod.spec.id, kinds: specMod.spec.oracle.kinds, routeKeys: specMod.spec.oracle.routeKeys, solve: solveMod.solve }
}

export interface MatrixRow { siteId: string; seed: number; mode: SiteMode; ok: boolean; detail: string }
export interface MatrixResult { summary: string; rows: MatrixRow[] }

function matches(events: OracleEvent[], impl: Impl): number {
  return events.filter((e) => impl.kinds.includes(e.kind) && e.routeKey != null && impl.routeKeys.includes(e.routeKey)).length
}

function forcedPlan(seed: number, mode: SiteMode): VariantPlan {
  const plan = generateVariant(blueprint, seed)
  for (const id of implementedSiteIds) plan.sites[id] = mode
  return plan
}

export async function runSiteMatrix(opts: { seeds: number[]; siteIds?: string[] }): Promise<MatrixResult> {
  const ids = opts.siteIds ?? [...implementedSiteIds]
  const impls = await Promise.all(ids.map(loadImpl))
  const rows: MatrixRow[] = []

  for (const seed of opts.seeds) {
    for (const mode of ['vulnerable', 'hardened'] as SiteMode[]) {
      for (const impl of impls) {
        const plan = forcedPlan(seed, mode)
        const started = await shopflow.start({ plan, groundTruth: buildGroundTruth(blueprint, plan) })
        try {
          const sctx = makeSolverCtx(started.origin, plan)
          started.oracle.reset()
          let detail = ''
          try {
            await impl.solve(sctx)
            await new Promise((r) => setTimeout(r, 30))
          } catch (err) { detail = `solver error: ${(err as Error).message}` }
          const hits = matches(started.oracle.events(), impl)
          const ok = mode === 'vulnerable' ? hits >= 1 : hits === 0
          rows.push({ siteId: impl.id, seed, mode, ok, detail: detail || (ok ? `${hits} event(s)` : `expected ${mode === 'vulnerable' ? '>=1' : '0'}, got ${hits}`) })
        } finally {
          await started.stop()
        }
      }
    }
  }

  const failed = rows.filter((r) => !r.ok).length
  return { summary: `${rows.length - failed}/${rows.length} matrix checks passed`, rows }
}
