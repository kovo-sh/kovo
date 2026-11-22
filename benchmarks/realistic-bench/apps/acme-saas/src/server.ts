// Materialized entrypoint. The host (apps/acme-saas/index.ts) injects pre-wired collaborators; this
// module applies the schema, seeds deterministic data, starts the internal service mocks, builds the
// app context, mounts the planted site modules (listed in modules.json) ahead of the shared area
// modules, serves the SPA and starts listening on loopback.
import { fileURLToPath, pathToFileURL } from 'node:url'
import { dirname, join } from 'node:path'
import type { IncomingMessage, ServerResponse } from 'node:http'
import type { VariantPlan } from '../../../lib/types.ts'
import type { Db } from '../../../lib/db.ts'
import type { IdCodec } from '../../../lib/ids.ts'
import type { CanaryRegistry } from '../../../lib/canary.ts'
import type { Egress } from '../../../lib/egress.ts'
import type { HttpApp, ResolveActor } from '../../../lib/http.ts'
import { startInternalService } from '../../../lib/egress.ts'
import { applySchema } from './schema.ts'
import { seed } from './seed-data.ts'
import { createResolveActor } from './auth.ts'
import { buildContext, type AppContext, type Wiring, type AppConfig } from './context.ts'
import { registerAuthRoutes } from './auth/auth-routes.ts'
import { registerProjectRoutes } from './catalog/project-routes.ts'
import { registerBillingRoutes } from './billing/billing-routes.ts'
import { registerFileRoutes } from './files/file-routes.ts'
import { registerMemberRoutes } from './members/member-routes.ts'
import { registerWebhookRoutes } from './webhooks/webhook-routes.ts'
import { registerReportRoutes } from './reports/report-routes.ts'
import { registerNotificationRoutes } from './notifications/notification-routes.ts'
import { registerIntegrationRoutes } from './integrations/integration-routes.ts'
import { registerAdminRoutes } from './admin/admin-routes.ts'

const HERE = dirname(fileURLToPath(import.meta.url))

export interface StartServerOpts {
  plan: VariantPlan
  uiDir: string
  oobCallbackPorts?: number[]
  db: Db
  ids: IdCodec
  canaries: CanaryRegistry
  secrets: { jwt: string; webhook: string }
  wiring: Wiring
  makeApp(resolveActor: ResolveActor): HttpApp
}

export interface RunningServer {
  origin: string
  close(): Promise<void>
}

export async function startServer(opts: StartServerOpts): Promise<RunningServer> {
  const { plan, db, ids, canaries } = opts
  applySchema(db)
  const seeded = seed(db, { plan, ids, canaries })

  const metaSecret = canaries.secretToken('int-metadata', 'token')
  const metadata = await startInternalService({
    name: 'metadata',
    internal: true,
    handler: (req: IncomingMessage, res: ServerResponse) => {
      res.writeHead(200, { 'content-type': 'application/json' })
      res.end(JSON.stringify({ instance: 'acme-prod-1', token: metaSecret, region: 'loopback' }))
    },
  })

  const egress: Egress = opts.wiring.makeEgress(
    [{ name: 'metadata', port: metadata.port, internal: true }],
    opts.oobCallbackPorts,
  )
  const vfs = opts.wiring.makeVfs(seeded.files)
  const config: AppConfig = {
    metadataOrigin: `http://127.0.0.1:${metadata.port}`,
    jwtSecret: opts.secrets.jwt,
    webhookSecret: opts.secrets.webhook,
  }

  const resolveActor = createResolveActor(db)
  const app = opts.makeApp(resolveActor)
  const ctx: AppContext = buildContext({
    app, plan, db, ids, canaries, config, wiring: opts.wiring, vfs, egress,
  })

  // Mount planted site modules first so a mounted site owns its route key.
  await mountSiteModules(ctx)
  // Shared area modules provide the rest of the API (safe defaults for any unmounted site route).
  registerAuthRoutes(ctx)
  registerProjectRoutes(ctx)
  registerBillingRoutes(ctx)
  registerFileRoutes(ctx)
  registerMemberRoutes(ctx)
  registerWebhookRoutes(ctx)
  registerReportRoutes(ctx)
  registerNotificationRoutes(ctx)
  registerIntegrationRoutes(ctx)
  registerAdminRoutes(ctx)

  app.static(opts.uiDir)
  const port = await app.listen()
  const origin = `http://127.0.0.1:${port}`
  return {
    origin,
    async close() {
      await app.close()
      await metadata.stop()
    },
  }
}

async function mountSiteModules(ctx: AppContext): Promise<void> {
  let modules: string[] = []
  try {
    const url = pathToFileURL(join(HERE, 'modules.json')).href
    modules = ((await import(url, { with: { type: 'json' } })) as { default: string[] }).default
  } catch {
    modules = []
  }
  for (const rel of modules) {
    const url = pathToFileURL(join(HERE, ...rel.split('/'))).href
    const mod = (await import(url)) as { default?: (app: AppContext) => void }
    if (typeof mod.default === 'function') mod.default(ctx)
  }
}
