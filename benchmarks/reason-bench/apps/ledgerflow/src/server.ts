// Materialized entrypoint. The host (apps/ledgerflow/index.ts) injects the impact recorder and the
// policy monitor set; this module applies the schema, seeds deterministic data, starts the internal
// loopback service mocks, builds the app context, mounts the materialized site modules ahead of the
// shared area modules, serves the SPA and listens on loopback only.
import { fileURLToPath, pathToFileURL } from 'node:url'
import { dirname, join } from 'node:path'
import type { IncomingMessage, ServerResponse } from 'node:http'
import type { VariantPlan } from '../../../lib/types.ts'
import type { Db } from '../../../lib/db.ts'
import type { IdCodec } from '../../../lib/ids.ts'
import type { CanaryRegistry } from '../../../lib/canary.ts'
import type { Egress } from '../../../lib/egress.ts'
import type { CreateHttpAppOpts, HttpApp, MonitorSet, ResolveActor } from '../../../lib/http.ts'
import { createHttpApp } from '../../../lib/http.ts'
import { createDb } from '../../../lib/db.ts'
import { createIdCodec } from '../../../lib/ids.ts'
import { createCanaryRegistry } from '../../../lib/canary.ts'
import { createVfs } from '../../../lib/vfs.ts'
import { createEgress, startInternalService } from '../../../lib/egress.ts'
import { render } from '../../../lib/template.ts'
import type { RenderOpts } from '../../../lib/template.ts'
import { sign as jwtSign, verify as jwtVerify } from '../../../lib/jwt.ts'
import type { VerifyOpts } from '../../../lib/jwt.ts'
import { signWebhook, verifyWebhook } from '../../../lib/webhook.ts'
import type { VerifyWebhookOpts } from '../../../lib/webhook.ts'
import { simulateCommand } from '../../../lib/simshell.ts'
import { parseXml } from '../../../lib/xml.ts'
import type { ParseXmlOpts } from '../../../lib/xml.ts'
import { verifyCanonical } from '../../../lib/hmac.ts'
import { assertLocalLabAllowed } from '../../../lib/safety.ts'
import { applySchema } from './db.ts'
import { createDbFacade } from './db-facade.ts'
import { seed } from './seed.ts'
import { createResolveActor, SESSION_COOKIE } from './auth.ts'
import { deriveSecrets, labelsFor } from './plan.ts'
import { buildContext, type AppContext, type Wiring } from './context.ts'
import { registerAuthRoutes } from './routes/auth-routes.ts'
import { registerBillingRoutes } from './routes/billing-routes.ts'
import { registerCartRoutes } from './routes/cart-routes.ts'
import { registerWalletRoutes } from './routes/wallet-routes.ts'
import { registerTeamRoutes } from './routes/team-routes.ts'
import { registerOpsRoutes } from './routes/ops-routes.ts'

const HERE = dirname(fileURLToPath(import.meta.url))
const REC = ['or', 'acle'].join('')
type Recorder = Parameters<NonNullable<MonitorSet['afterRequest']>>[1]

export interface StartServerOpts {
  plan: VariantPlan
  report?: Recorder
  monitors?: MonitorSet
  uiDir: string
  oobCallbackPorts?: number[]
  db?: Db
  ids?: IdCodec
  canaries?: CanaryRegistry
  secrets?: { jwt: string; webhookSecretFor(tenant: string): string }
  wiring?: Wiring
  makeApp?: (resolveActor: ResolveActor) => HttpApp
  [key: string]: unknown
}

export interface RunningServer {
  origin: string
  close(): Promise<void>
}

export function createWiring(impact: Recorder, secrets: { jwt: string; webhookSecretFor(tenant: string): string }): Wiring {
  return {
    makeVfs: (files) => createVfs(impact, files),
    makeEgress: (services, oob) => createEgress({ internalServices: services, oobCallbackPorts: oob, [REC]: impact } as unknown as Parameters<typeof createEgress>[0]),
    render: (source, data, inputDerived) => render(source, data, { inputDerived, [REC]: impact } as RenderOpts),
    signToken: (payload) => jwtSign(payload, secrets.jwt),
    signTokenWith: (payload, secret, opts) => jwtSign(payload, secret, opts),
    verifyToken: (token, acceptNone) => {
      const res = jwtVerify(token, { secret: secrets.jwt, algorithms: acceptNone ? ['HS256', 'none'] : ['HS256'], acceptNone, [REC]: impact } as VerifyOpts)
      return { valid: res.valid, payload: res.payload }
    },
    verifyTokenWith: (token, opts) => jwtVerify(token, { ...opts, [REC]: impact } as VerifyOpts),
    signWebhook: (secret, body, ts) => signWebhook(secret, body, ts),
    verifyWebhook: (secret, body, ts, sig, opts) => verifyWebhook(secret, body, ts, sig, { toleranceSec: 300, ...(opts ?? {}), [REC]: impact } as VerifyWebhookOpts),
    verifyScopedWebhook: (secret, scope, body, ts, sig) => {
      const dot = scope.indexOf('.')
      const tenantId = dot >= 0 ? scope.slice(0, dot) : scope
      const eventType = dot >= 0 ? scope.slice(dot + 1) : ''
      return verifyCanonical(secret, ts, { tenantId, eventType }, body, sig, { toleranceSec: 300 })
    },
    simulate: (template, args) => {
      const result = simulateCommand(template, args, impact)
      return { output: result.output, commands: result.commands }
    },
    parseXml: (source, external, innerVfs, innerEgress) => parseXml(source, {
      resolveExternalEntities: external,
      vfs: { read: (path: string) => innerVfs.read(path) ?? '' },
      [REC]: impact,
      egress: {
        fetch: (url: string) => {
          void innerEgress.fetch(url, { inputDerived: true }).catch(() => undefined)
          return ''
        },
      },
    } as ParseXmlOpts),
  }
}

export function createAppHttp(deps: {
  plan: VariantPlan; impact: Recorder; monitors?: MonitorSet; canaries: CanaryRegistry; db: Db; resolveActor: ResolveActor
}): HttpApp {
  return createHttpApp({
    plan: deps.plan, monitors: deps.monitors, canaries: deps.canaries, db: deps.db,
    resolveActor: deps.resolveActor, sessionCookie: SESSION_COOKIE, [REC]: deps.impact,
  } as unknown as CreateHttpAppOpts)
}

export async function startServer(opts: StartServerOpts): Promise<RunningServer> {
  assertLocalLabAllowed()
  const { plan, monitors } = opts
  const impact = (opts.report ?? (opts as Record<string, unknown>)[REC]) as Recorder
  const db = createDbFacade(opts.db ?? createDb(impact))
  const ids = opts.ids ?? createIdCodec(plan.idFormat, plan.canarySalt)
  const canaries = opts.canaries ?? createCanaryRegistry(plan.canarySalt)
  const secrets = opts.secrets ?? deriveSecrets(plan)

  applySchema(db)
  const seeded = seed(db, { plan, ids, canaries, secrets })

  const metadata = await startInternalService({
    name: 'ledger-metadata',
    internal: true,
    handler: (_req: IncomingMessage, res: ServerResponse) => {
      res.writeHead(200, { 'content-type': 'application/json' })
      res.end(JSON.stringify({ service: 'ledgerflow', instance: 'ledger-prod-1', region: 'loopback', token: seeded.metadataSecret }))
    },
  })

  const wiring: Wiring = opts.wiring ?? createWiring(impact, secrets)
  const egress: Egress = wiring.makeEgress(
    [{ name: 'ledger-metadata', port: metadata.port, internal: true }],
    opts.oobCallbackPorts,
  )
  const vfs = wiring.makeVfs(seeded.files)
  const config = {
    metadataOrigin: `http://127.0.0.1:${metadata.port}`,
    jwtSecret: secrets.jwt,
    webhookSecretFor: secrets.webhookSecretFor,
    labels: labelsFor(plan),
  }
  const resolveActor = createResolveActor(db)
  const app = opts.makeApp ? opts.makeApp(resolveActor) : createAppHttp({ plan, impact, monitors, canaries, db, resolveActor })
  const ctx: AppContext = buildContext({ app, plan, db, ids, canaries, config, wiring, vfs, egress })

  await mountSiteModules(ctx)
  registerAuthRoutes(ctx)
  registerBillingRoutes(ctx)
  registerCartRoutes(ctx)
  registerWalletRoutes(ctx)
  registerTeamRoutes(ctx)
  registerOpsRoutes(ctx)

  app.static(opts.uiDir)
  const port = await app.listen()
  return {
    origin: `http://127.0.0.1:${port}`,
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
