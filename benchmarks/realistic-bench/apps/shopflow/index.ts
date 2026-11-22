// shopflow AppModule: wires the blueprint to a per-seed materialized lab. Creates the impact oracle +
// monitors, materializes the white-box source tree (only the fully-implemented feature modules are
// mounted), dynamically imports the materialized server and starts it on loopback.
import { join, dirname } from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'
import type { AppBlueprint, AppModule, OracleHandle, StartedApp } from '../../lib/types.ts'
import type { createOracle as CreateOracle } from '../../lib/oracle.ts'
import { materialize } from '../../generator/materialize.ts'
import { blueprint, implementedSiteIds } from './truth/blueprint.ts'
import { createMonitors } from './truth/monitors.ts'

const APP_DIR = dirname(fileURLToPath(import.meta.url))
const LIB_DIR = join(APP_DIR, '..', '..', 'lib')

type Oracle = ReturnType<typeof CreateOracle>
interface OracleModule { createOracle(opts: { app: string }): Oracle }
interface ServerModule {
  startServer(opts: {
    plan: StartedApp['plan']
    report: Oracle
    monitors: ReturnType<typeof createMonitors>
    uiDir: string
    oobCallbackPorts?: number[]
  }): Promise<{ origin: string; close(): Promise<void> }>
}

function mountedBlueprint(implemented: readonly string[]): AppBlueprint {
  // Test-only override: mount exactly the comma-separated ids in SHOP_MOUNT_SITES so an in-progress
  // site can be exercised without editing the shared implemented-id list.
  const override = process.env.SHOP_MOUNT_SITES
  const ids = override
    ? new Set(override.split(',').map((s) => s.trim()).filter(Boolean))
    : new Set(implemented)
  return { ...blueprint, sites: blueprint.sites.filter((s) => ids.has(s.id)) }
}

const shopflow: AppModule = {
  name: 'shopflow',
  blueprint,
  async start({ plan, groundTruth, oobCallbackPorts }) {
    const monitors = createMonitors({ plan })
    const mat = materialize({ bp: mountedBlueprint(implementedSiteIds), plan, appDir: APP_DIR, libDir: LIB_DIR })
    const uiDir = join(mat.root, 'apps', 'shopflow', 'ui')
    // Create the oracle from the materialized lib so it shares the request-context ALS with the
    // materialized HTTP layer (a separate lib copy would have an independent, empty context store).
    const oracleMod = (await import(pathToFileURL(join(mat.root, 'lib', 'oracle.ts')).href)) as OracleModule
    const oracle = oracleMod.createOracle({ app: 'shopflow' })
    const mod = (await import(pathToFileURL(join(mat.sourceDir, 'server.ts')).href)) as ServerModule
    const running = await mod.startServer({ plan, report: oracle, monitors, uiDir, oobCallbackPorts })
    const started: StartedApp = {
      app: 'shopflow',
      origin: running.origin,
      plan,
      groundTruth,
      sourceDir: mat.sourceDir,
      oracle,
      async stop() {
        await running.close()
        mat.cleanup()
      },
    }
    return started
  },
}

export default shopflow
