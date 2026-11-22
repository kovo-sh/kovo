// Materialized server entrypoint. Builds the database + seed data, wires the HTTP app with per-seed
// routes, mounts the common endpoints and every feature module listed in modules.json, serves the
// SPA, and listens on loopback. The impact side-channel handle is injected by the host under its
// expected key without this file naming it.
import type { VariantPlan } from '../../../lib/types.ts'
import type { Db } from '../../../lib/db.ts'
import type { CanaryRegistry } from '../../../lib/canary.ts'
import type { MonitorSet } from '../../../lib/http.ts'
import { createHttpApp } from '../../../lib/http.ts'
import { createVfs } from '../../../lib/vfs.ts'
import { createEgress, startInternalService, type InternalService } from '../../../lib/egress.ts'
import { createIdCodec } from '../../../lib/ids.ts'
import { createSchema } from './schema.ts'
import { seedData } from './seed-data.ts'
import { buildContext, type Sink, type PlanView, type AppContext } from './context.ts'
import { makeResolveActor, registerAuthRoutes } from './auth.ts'
import { registerCommon } from './common/routes.ts'

export interface StartServerOpts {
  plan: VariantPlan
  sink: Sink // impact side-channel handle (created by the host)
  monitors: MonitorSet
  db: Db
  canaries: CanaryRegistry
  uiDir: string
  oobCallbackPorts?: number[]
}

export interface RunningServer {
  origin: string
  close(): Promise<void>
}

const SINK_KEY = ['or', 'acle'].join('')
function inject<T>(base: object, sink: Sink): T {
  ;(base as Record<string, unknown>)[SINK_KEY] = sink
  return base as T
}

type Registrar = (app: AppContext) => void

export async function startServer(opts: StartServerOpts): Promise<RunningServer> {
  const { plan, sink, monitors, db, canaries, uiDir } = opts
  createSchema(db)
  const ids = createIdCodec(plan.idFormat, plan.canarySalt)
  const vfs = createVfs(sink, {})

  // internal mock service (metadata/admin endpoint) reachable only through contained egress
  const mock: InternalService = await startInternalService({
    name: 'metadata', internal: true,
    handler: (_req, res) => {
      res.writeHead(200, { 'content-type': 'application/json' })
      res.end(JSON.stringify({ role: 'admin', token: 'rbs_meta_000000000000' }))
    },
  })
  const egress = createEgress(inject({
    internalServices: [{ name: mock.name, port: mock.port, internal: true }],
    oobCallbackPorts: opts.oobCallbackPorts,
  }, sink))

  seedData({ db, vfs, ids, canaries, personas: plan.personas, internalOrigin: `http://127.0.0.1:${mock.port}` })

  const resolveActor = makeResolveActor(db)
  const app = createHttpApp(inject({ plan, monitors, canaries, resolveActor, db }, sink))

  const planView: PlanView = {
    apiPrefix: plan.apiPrefix, idFormat: plan.idFormat, routes: plan.routes, params: plan.params,
  }
  const ctx = buildContext({ plan: planView, db, sink, canaries, vfs, egress, ids, app, sessions: app.sessions })

  registerAuthRoutes(ctx)

  // Feature modules are mounted ahead of the shared area routes so that a feature's specific path
  // (e.g. a literal sub-resource under a collection) takes precedence over the shared parameterised
  // detail route for that collection.
  const list = (await import(new URL('./modules.json', import.meta.url).href, { with: { type: 'json' } })).default as string[]
  for (const file of list) {
    const mod = (await import(new URL('./' + file, import.meta.url).href)) as { default?: Registrar; register?: Registrar }
    const reg = mod.default ?? mod.register
    if (reg) reg(ctx)
  }

  registerCommon(ctx)

  app.static(uiDir)
  const port = await app.listen()
  return {
    origin: `http://127.0.0.1:${port}`,
    async close() { await app.close(); await mock.stop() },
  }
}
