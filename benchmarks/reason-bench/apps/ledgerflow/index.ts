// ledgerflow app module. Discovers site specs at runtime from sites/<id>/spec.ts, wires the impact
// recorder and generic policy monitors, materializes a per-seed tree with the mounted site variants,
// then starts the materialized server on loopback. The shell runs with zero discovered sites.
import { dirname, join } from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'
import type { AppModule, SiteSpec, StartedApp, VariantPlan } from '../../lib/types.ts'
import type { Oracle } from '../../lib/oracle.ts'
import { materialize } from '../../generator/materialize.ts'
import { discoverSiteSpecs } from '../../generator/variant.ts'
import { blueprintWith, ROUTES } from './truth/blueprint.ts'
import { createMonitors } from './truth/monitors.ts'
import type { RunningServer, StartServerOpts } from './src/server.ts'

const HERE = dirname(fileURLToPath(import.meta.url))

const discoveredAll = await discoverSiteSpecs(HERE)
const discovered = discoveredAll.filter((spec) => {
  const keys = Array.isArray(spec.routeKeys) ? spec.routeKeys : []
  const file = spec.rootCause && typeof spec.rootCause.file === 'string' ? spec.rootCause.file : ''
  const ok = keys.every((key) => Boolean(ROUTES[key])) && /^[a-z0-9-]+\/[a-z0-9-]+\.ts$/.test(file)
  if (!ok) console.warn(`ledgerflow: skipping site ${spec.id} with an unknown route key or root-cause path`)
  return ok
})
const blueprint = blueprintWith(discovered)

async function start(opts: {
  plan: VariantPlan
  groundTruth: StartedApp['groundTruth']
  oobCallbackPorts?: number[]
  sourceDir?: string
}): Promise<StartedApp> {
  const { plan, groundTruth } = opts
  const mounted = blueprint.sites.filter((site) => Boolean(plan.sites[site.id]))
  const mat = opts.sourceDir
    ? null
    : materialize({
      blueprint: { ...blueprint, sites: mounted },
      plan,
      appDir: HERE,
      libDir: join(HERE, '..', '..', 'lib'),
    })
  const sourceDir = opts.sourceDir ?? mat!.sourceDir
  const root = mat ? mat.root : join(sourceDir, '..', '..', '..')
  const oracleMod = (await import(pathToFileURL(join(root, 'lib', 'oracle.ts')).href)) as {
    createOracle(o: { app: typeof plan.app }): Oracle
  }
  const sink = oracleMod.createOracle({ app: plan.app })
  const monitors = createMonitors({ plan })
  const serverMod = (await import(pathToFileURL(join(sourceDir, 'server.ts')).href)) as {
    startServer(o: StartServerOpts): Promise<RunningServer>
  }
  const running = await serverMod.startServer({
    plan,
    report: sink,
    monitors,
    uiDir: mat ? mat.uiDir : join(sourceDir, '..', 'ui'),
    oobCallbackPorts: opts.oobCallbackPorts,
  })
  return {
    app: plan.app,
    origin: running.origin,
    plan,
    groundTruth,
    sourceDir,
    oracle: sink,
    async stop() {
      await running.close()
      mat?.cleanup()
    },
  }
}

const mod: AppModule = { name: blueprint.app, blueprint, reasonBench: true, start }
export default mod
