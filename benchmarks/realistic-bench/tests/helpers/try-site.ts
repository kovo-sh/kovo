// Single-site verifier used by site implementers: mount exactly one planted site (via the app's
// <APP>_MOUNT_SITES env override), boot it forced-vulnerable then forced-hardened, run the site's
// solver, and confirm the vulnerable boot produces >=1 attributed oracle event while the hardened
// boot produces zero. Lets an in-progress site be tested without touching shared wiring.
import type { AppModule, SiteMode, SiteSpec, VariantPlan } from '../../lib/types.ts'
import { generateVariant } from '../../generator/variant.ts'
import { bootForced, makeSolverCtx, attributeEvents, type SolverCtx } from './site-matrix.ts'

export interface TrySiteResult {
  siteId: string
  ok: boolean
  rows: Array<{ seed: number; mode: SiteMode; ok: boolean; detail: string }>
}

export async function verifySite(opts: {
  appModule: AppModule
  envVar: string // e.g. 'ACME_MOUNT_SITES'
  spec: SiteSpec
  solve(ctx: SolverCtx): Promise<void>
  seeds?: number[]
  sessionCookie?: string
}): Promise<TrySiteResult> {
  const seeds = opts.seeds ?? [1, 2]
  const rows: TrySiteResult['rows'] = []
  const prev = process.env[opts.envVar]
  process.env[opts.envVar] = opts.spec.id
  try {
    for (const seed of seeds) {
      const plan: VariantPlan = generateVariant(opts.appModule.blueprint, seed)
      for (const mode of ['vulnerable', 'hardened'] as SiteMode[]) {
        const app = await bootForced(opts.appModule, plan, mode)
        try {
          const ctx = makeSolverCtx(app, opts.sessionCookie)
          app.oracle.reset()
          let ok = false
          let detail = ''
          try {
            await opts.solve(ctx)
            const matched = attributeEvents(app.oracle.events(), opts.spec)
            if (mode === 'vulnerable') { ok = matched.length >= 1; detail = ok ? `${matched.length} event(s)` : 'no attributed event' }
            else { ok = matched.length === 0; detail = ok ? 'decoy safe' : `leaked: ${matched.map((e) => e.kind).join(',')}` }
          } catch (err) { detail = `solver error: ${(err as Error).message}` }
          rows.push({ seed, mode, ok, detail })
        } finally {
          await app.stop()
        }
      }
    }
  } finally {
    if (prev === undefined) delete process.env[opts.envVar]
    else process.env[opts.envVar] = prev
  }
  return { siteId: opts.spec.id, ok: rows.every((r) => r.ok), rows }
}
