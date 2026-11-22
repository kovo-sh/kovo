// opsportal AppModule: wires the blueprint to a per-seed boot. bootApp() materializes the implemented
// sites into a temp tree, then creates the impact oracle, database and canary registry FROM THE
// MATERIALIZED lib copy (so the server's async-context side-channel and these handles share one module
// instance), builds the monitors, and starts the materialized server. The matrix self-test reuses
// bootApp with forced site modes.
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'
import type { AppModule, StartedApp, VariantPlan, GroundTruth, OracleHandle } from '../../lib/types.ts'
import { materialize } from '../../generator/materialize.ts'
import { blueprint } from './truth/blueprint.ts'
import { createMonitors } from './truth/monitors.ts'

// The four fully-implemented exemplar sites (the other 20 are spec-only).
export const IMPLEMENTED = new Set([
  'og.graphql-account-bola', 'og.report-ssti', 'og.ticket-note-xss', 'og.diag-cmdi',
  'og.webhook-ssrf', 'og.dashboard-cache-poison', 'og.log-path-traversal', 'og.saml-xxe',
  'og.ticket-bola-read', 'og.account-bola-write', 'og.viewer-bfla', 'og.user-mass-assignment',
  'og.search-sqli', 'og.api-jwt-forgery', 'og.sso-open-redirect', 'og.job-csrf',
  'og.integration-secret-disclosure', 'og.log-filter-sqli', 'og.account-search-xss', 'og.flag-bola',
  'og.job-workflow-skip', 'og.backup-webhook-forgery', 'og.ticket-assign-cross-write', 'og.integration-ssrf-direct',
])

interface RunningServer { origin: string; close(): Promise<void> }
interface ServerModule {
  startServer(opts: {
    plan: VariantPlan; sink: unknown; monitors: unknown; db: unknown; canaries: unknown;
    uiDir: string; oobCallbackPorts?: number[]
  }): Promise<RunningServer>
}
interface OracleLike extends OracleHandle { emit(...a: unknown[]): void }
interface DbLike { close(): void }

export async function bootApp(
  plan: VariantPlan, groundTruth: GroundTruth, oobCallbackPorts?: number[],
): Promise<StartedApp> {
  const appDir = dirname(fileURLToPath(import.meta.url))
  const libDir = resolve(appDir, '..', '..', 'lib')
  // Test-only override: mount exactly the comma-separated ids in OPS_MOUNT_SITES so an in-progress
  // site can be exercised without editing the shared IMPLEMENTED set.
  const mountOverride = process.env.OPS_MOUNT_SITES
  const mountIds = mountOverride
    ? new Set(mountOverride.split(',').map((s) => s.trim()).filter(Boolean))
    : IMPLEMENTED
  const subset = { ...blueprint, sites: blueprint.sites.filter((s) => mountIds.has(s.id)) }
  const mat = materialize({ bp: subset, plan, appDir, libDir })
  const root = resolve(mat.sourceDir, '..', '..', '..')
  const matLib = (name: string): string => pathToFileURL(join(root, 'lib', name)).href

  const { createOracle } = (await import(matLib('oracle.ts'))) as { createOracle(o: { app: string }): OracleLike }
  const { createDb } = (await import(matLib('db.ts'))) as { createDb(o: OracleLike): DbLike }
  const { createCanaryRegistry } = (await import(matLib('canary.ts'))) as { createCanaryRegistry(salt: string): unknown }

  const oracle = createOracle({ app: 'opsportal' })
  const db = createDb(oracle)
  const canaries = createCanaryRegistry(plan.canarySalt)
  const monitors = createMonitors({ personas: plan.personas, canaries: canaries as never })

  const mod = (await import(pathToFileURL(join(mat.sourceDir, 'server.ts')).href)) as ServerModule
  const uiDir = join(mat.sourceDir, '..', 'ui')
  const running = await mod.startServer({ plan, sink: oracle, monitors, db, canaries, uiDir, oobCallbackPorts })

  return {
    app: 'opsportal', origin: running.origin, plan, groundTruth, sourceDir: mat.sourceDir,
    oracle: oracle as OracleHandle,
    async stop() { await running.close(); db.close(); mat.cleanup() },
  }
}

const appModule: AppModule = {
  name: 'opsportal',
  blueprint,
  start: ({ plan, groundTruth, oobCallbackPorts }) => bootApp(plan, groundTruth, oobCallbackPorts),
}

export default appModule
