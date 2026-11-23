// ledgerflow app module. Discovers site specs at runtime from sites/<id>/spec.ts, wires the impact
// recorder and generic policy monitors, materializes a per-seed tree with the mounted site variants,
// then starts the materialized server on loopback. The shell runs with zero discovered sites.
import { existsSync, readdirSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'
import type { AppModule, SiteSpec, StartedApp, VariantPlan } from '../../lib/types.ts'
import { createOracle } from '../../lib/oracle.ts'
import { createDb } from '../../lib/db.ts'
import { createIdCodec } from '../../lib/ids.ts'
import { createCanaryRegistry } from '../../lib/canary.ts'
import { materialize } from '../../generator/materialize.ts'
import { blueprintWith, ROUTES } from './truth/blueprint.ts'
import { createMonitors } from './truth/monitors.ts'
import { createAppHttp, createWiring, type RunningServer, type StartServerOpts } from './src/server.ts'
import { createDbFacade } from './src/db-facade.ts'
import { deriveSecrets } from './src/plan.ts'

const HERE = dirname(fileURLToPath(import.meta.url))

async function discoverSites(): Promise<SiteSpec[]> {
  const dir = join(HERE, 'sites')
  if (!existsSync(dir)) return []
  const found: SiteSpec[] = []
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    if (!entry.isDirectory()) continue
    const specPath = join(dir, entry.name, 'spec.ts')
    if (!existsSync(specPath)) continue
    try {
      const mod = (await import(pathToFileURL(specPath).href)) as { spec?: SiteSpec; default?: SiteSpec }
      const spec = mod.spec ?? mod.default
      if (!spec || typeof spec !== 'object' || typeof spec.id !== 'string') continue
      const keys = Array.isArray(spec.routeKeys) ? spec.routeKeys : []
      const file = spec.rootCause && typeof spec.rootCause.file === 'string' ? spec.rootCause.file : ''
      if (!keys.every((key) => Boolean(ROUTES[key])) || !/^[a-z0-9-]+\/[a-z0-9-]+\.ts$/.test(file)) {
        console.warn(`ledgerflow: skipping site ${spec.id} with an unknown route key or root-cause path`)
        continue
      }
      found.push(spec)
    } catch {
      // A partially authored site must not prevent the shell from starting.
    }
  }
  return found.sort((a, b) => a.id.localeCompare(b.id))
}

const discovered = await discoverSites()
const blueprint = blueprintWith(discovered)

async function start(opts: {
  plan: VariantPlan
  groundTruth: StartedApp['groundTruth']
  oobCallbackPorts?: number[]
  sourceDir?: string
}): Promise<StartedApp> {
  const { plan, groundTruth } = opts
  const sink = createOracle({ app: plan.app })
  const monitors = createMonitors({ plan })
  const db = createDbFacade(createDb(sink))
  const ids = createIdCodec(plan.idFormat, plan.canarySalt)
  const canaries = createCanaryRegistry(plan.canarySalt)
  const secrets = deriveSecrets(plan)
  const wiring = createWiring(sink, secrets)
  const makeApp = (resolveActor: Parameters<typeof createAppHttp>[0]['resolveActor']) =>
    createAppHttp({ plan, impact: sink, monitors, canaries, db, resolveActor })
  const mounted = blueprint.sites.filter((site) => {
    const mode = plan.sites[site.id]
    if (!mode) return false
    if (existsSync(join(HERE, 'sites', site.id, `${mode}.ts`))) return true
    console.warn(`ledgerflow: skipping site ${site.id}; missing ${mode} implementation`)
    return false
  })
  const mat = opts.sourceDir
    ? null
    : materialize({
      blueprint: { ...blueprint, sites: mounted },
      plan,
      appDir: HERE,
      libDir: join(HERE, '..', '..', 'lib'),
    })
  const sourceDir = opts.sourceDir ?? mat!.sourceDir
  const serverMod = (await import(pathToFileURL(join(sourceDir, 'server.ts')).href)) as {
    startServer(o: StartServerOpts): Promise<RunningServer>
  }
  const running = await serverMod.startServer({
    plan,
    oracle: sink,
    monitors,
    uiDir: mat ? mat.uiDir : join(sourceDir, '..', 'ui'),
    oobCallbackPorts: opts.oobCallbackPorts,
    db, ids, canaries, secrets, wiring, makeApp,
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
