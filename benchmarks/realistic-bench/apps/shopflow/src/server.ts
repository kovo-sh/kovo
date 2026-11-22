// Materialized entrypoint. Builds the application context (database + schema + fixtures + router),
// registers the common feature modules, dynamically loads the per-feature modules listed in
// modules.json, serves the SPA and starts listening on loopback.
import { buildContext } from './context.ts'
import type { AppContext } from './context.ts'
import type { VariantPlan } from '../../../lib/types.ts'
import type { MonitorSet } from '../../../lib/http.ts'
import registerCommon from './common.ts'
import registerStorefront from './storefront.ts'
import registerOrders from './orders.ts'
import registerBackoffice from './backoffice.ts'
import registerExtra from './extra.ts'

type Report = Parameters<typeof buildContext>[0]['report']

export interface StartServerOpts {
  plan: VariantPlan
  report: Report
  monitors?: MonitorSet
  uiDir: string
  oobCallbackPorts?: number[]
}
export interface RunningServer {
  origin: string
  close(): Promise<void>
}

export async function startServer(opts: StartServerOpts): Promise<RunningServer> {
  const ctx = buildContext({ plan: opts.plan, report: opts.report, monitors: opts.monitors, oob: opts.oobCallbackPorts })

  // Mount the per-feature site modules first so a mounted site owns its route key; the shared feature
  // modules below then supply safe defaults for every route no mounted site has already claimed.
  let modules: string[] = []
  try {
    const url = new URL('modules.json', import.meta.url).href
    modules = ((await import(url, { with: { type: 'json' } })) as { default: string[] }).default
  } catch {
    modules = []
  }
  for (const rel of modules) {
    const mod = (await import(new URL(rel, import.meta.url).href)) as {
      default?: (app: AppContext) => void
      register?: (app: AppContext) => void
    }
    const fn = mod.default ?? mod.register
    if (fn) fn(ctx)
  }

  registerCommon(ctx)
  registerStorefront(ctx)
  registerOrders(ctx)
  registerBackoffice(ctx)
  registerExtra(ctx)

  ctx.serve(opts.uiDir)
  const port = await ctx.listen()
  return { origin: `http://127.0.0.1:${port}`, close: () => ctx.close() }
}
