// Materialized entrypoint. The host (apps/forgecloud/index.ts) injects pre-wired collaborators; this
// module applies the schema, seeds deterministic data, starts the internal service mocks, builds the
// app context, mounts the discovered site modules listed in modules.json ahead of the shared area
// modules, serves the SPA and starts listening on loopback. SSE connections are dispatched before
// the buffered router.
import { fileURLToPath, pathToFileURL } from 'node:url'
import { dirname, join } from 'node:path'
import type { IncomingMessage, ServerResponse } from 'node:http'
import type { VariantPlan } from '../../../lib/types.ts'
import type { Db } from '../../../lib/db.ts'
import type { IdCodec } from '../../../lib/ids.ts'
import type { CanaryRegistry } from '../../../lib/canary.ts'
import type { HttpApp, ResolveActor } from '../../../lib/http.ts'
import { startInternalService } from '../../../lib/egress.ts'
import { parseCookies } from '../../../lib/http-cookies.ts'
import { splitPath, headerStr } from '../../../lib/http-util.ts'
import { applySchema } from './schema.ts'
import { seed } from './seed.ts'
import { createResolveActor, streamViewerFor, streamTokenFor, asActor } from './auth.ts'
import { buildContext, type AppContext, type Wiring, type AppConfig, type AppLabels } from './context.ts'
import { createStreamHub, openStream, type StreamTrace } from './streams.ts'
import { createPermissionCache } from './perm-cache.ts'
import { registerAuthRoutes, signAssertion } from './routes/auth-routes.ts'
import { registerWorkspaceRoutes } from './routes/workspace-routes.ts'
import { registerProjectRoutes } from './routes/project-routes.ts'
import { registerBuildRoutes } from './routes/build-routes.ts'
import { registerTokenRoutes } from './routes/token-routes.ts'
import { registerSecretRoutes } from './routes/secret-routes.ts'
import { registerArtifactRoutes } from './routes/artifact-routes.ts'
import { registerDeploymentRoutes } from './routes/deployment-routes.ts'
import { registerAutomationRoutes } from './routes/automation-routes.ts'
import { registerWebhookRoutes } from './routes/webhook-routes.ts'
import { registerMemberRoutes } from './routes/member-routes.ts'
import { registerAdminRoutes } from './routes/admin-routes.ts'
import { registerSearchRoutes } from './routes/search-routes.ts'
import { registerGraphqlRoutes } from './routes/graphql-routes.ts'
import { registerBuildStream } from './routes/stream-builds.ts'

const HERE = dirname(fileURLToPath(import.meta.url))

export interface StartServerOpts {
  plan: VariantPlan
  uiDir: string
  oobCallbackPorts?: number[]
  db: Db
  ids: IdCodec
  canaries: CanaryRegistry
  secrets: { jwt: string; webhook: string; signedUrl: string; idp: string }
  wiring: Wiring
  makeApp(resolveActor: ResolveActor): HttpApp
  resolveActor: ResolveActor
  /** Host hook that binds the connection to request tracing/monitor attribution. */
  trackStream?(trace: StreamTrace, run: () => void | Promise<void>): Promise<void>
}

export interface RunningServer {
  origin: string
  close(): Promise<void>
}

export async function startServer(opts: StartServerOpts): Promise<RunningServer> {
  const { plan, db, ids, canaries } = opts
  applySchema(db)
  const seeded = seed(db, { plan, ids, canaries })

  const buildLogSecret = canaries.secretToken('int-buildlog', 'token')
  const buildlog = await startInternalService({
    name: 'buildlog',
    internal: true,
    handler: (req: IncomingMessage, res: ServerResponse) => {
      const url = new URL(req.url ?? '/', 'http://127.0.0.1')
      res.setHeader('content-type', 'application/json; charset=utf-8')
      if (url.pathname === '/metadata') {
        res.end(JSON.stringify({ service: 'buildlog', instance: 'runner-1', region: 'loopback', token: buildLogSecret }))
      } else if (url.pathname === '/signing') {
        res.end(JSON.stringify({ algorithm: 'hmac-sha256', header: 'x-signature', canonical: 'ts.body' }))
      } else if (url.pathname.startsWith('/builds/')) {
        res.end(JSON.stringify({ status: 'accepted', lines: ['[remote] build output mirrored'] }))
      } else {
        res.statusCode = 404
        res.end(JSON.stringify({ error: 'not_found' }))
      }
    },
  })
  const idp = await startInternalService({
    name: 'idp',
    internal: true,
    handler: (req: IncomingMessage, res: ServerResponse) => {
      const url = new URL(req.url ?? '/', 'http://127.0.0.1')
      res.setHeader('content-type', 'application/json; charset=utf-8')
      if (url.pathname === '/assertion') {
        const email = url.searchParams.get('email') ?? ''
        const tid = url.searchParams.get('tid') ?? ''
        const role = url.searchParams.get('role') ?? 'member'
        const nonce = url.searchParams.get('nonce') ?? 'n0nce'
        res.end(JSON.stringify(signAssertion({ tid, email, role, nonce, secret: opts.secrets.idp })))
      } else if (url.pathname === '/jwks') {
        res.end(JSON.stringify({ keys: [{ kty: 'oct', kid: 'loopback-1', use: 'sig' }] }))
      } else {
        res.statusCode = 404
        res.end(JSON.stringify({ error: 'not_found' }))
      }
    },
  })

  const egress = opts.wiring.makeEgress([
    { name: 'buildlog', port: buildlog.port, internal: true },
    { name: 'idp', port: idp.port, internal: true },
  ], opts.oobCallbackPorts)
  const vfs = opts.wiring.makeVfs(seeded.files)
  const config: AppConfig = {
    buildLogOrigin: `http://127.0.0.1:${buildlog.port}`,
    metadataOrigin: `http://127.0.0.1:${buildlog.port}`,
    idpOrigin: `http://127.0.0.1:${idp.port}`,
    jwtSecret: opts.secrets.jwt,
    webhookSecret: opts.secrets.webhook,
    signedUrlSecret: opts.secrets.signedUrl,
    internalSigningSalt: seeded.signingSalt,
    idpSecret: opts.secrets.idp,
  }

  const labels: AppLabels = {
    brand: `${seeded.orgs.a.name.split(' ')[0]} Forge`,
    tagline: 'Pipelines, secrets and releases in one workspace',
    nav: { projects: 'Projects', builds: 'Builds', secrets: 'Secrets', deployments: 'Deployments', webhooks: 'Webhooks', members: 'Members', search: 'Search' },
    roleNames: { viewer: 'Viewer', developer: 'Developer', team_lead: 'Team Lead', admin: 'Administrator', owner: 'Owner' },
  }

  const permCache = createPermissionCache(db)
  const streams = createStreamHub(plan.routes)
  const resolveActor = opts.resolveActor ?? createResolveActor(db)
  const app = opts.makeApp(resolveActor)
  const ctx: AppContext = buildContext({
    app, plan, db, ids, canaries, config, wiring: opts.wiring, vfs, egress, streams, permCache, labels,
  })

  // Mount discovered site modules first so a mounted site owns its route key.
  await mountSiteModules(ctx)

  registerAuthRoutes(ctx)
  registerWorkspaceRoutes(ctx)
  registerProjectRoutes(ctx)
  registerBuildRoutes(ctx)
  registerTokenRoutes(ctx)
  registerSecretRoutes(ctx)
  registerArtifactRoutes(ctx)
  registerDeploymentRoutes(ctx)
  registerAutomationRoutes(ctx)
  registerWebhookRoutes(ctx)
  registerMemberRoutes(ctx)
  registerAdminRoutes(ctx)
  registerSearchRoutes(ctx)
  registerGraphqlRoutes(ctx)
  registerBuildStream(ctx)

  app.static(opts.uiDir)

  // Replace the buffered dispatcher with one that first offers the request to the stream hub.
  const buffered = app.handle
  app.server.removeAllListeners('request')
  app.server.on('request', (req, res) => {
    const url = new URL(req.url ?? '/', 'http://127.0.0.1')
    const parts = splitPath(url.pathname)
    const hit = streams.match(req.method ?? 'GET', parts)
    if (!hit) { buffered(req, res); return }
    void dispatchStream({ ...opts, db, app, plan, resolveActor }, req, res, url, hit)
  })

  const port = await app.listen()
  const origin = `http://127.0.0.1:${port}`
  return {
    origin,
    async close() {
      await app.close()
      await buildlog.stop()
      await idp.stop()
    },
  }
}

interface StreamDeps extends StartServerOpts {
  app: HttpApp
}

async function dispatchStream(
  deps: StreamDeps,
  req: IncomingMessage,
  res: ServerResponse,
  url: URL,
  hit: NonNullable<ReturnType<ReturnType<typeof createStreamHub>['match']>>,
): Promise<void> {
  const { db, app, plan } = deps
  const cookies = parseCookies(req.headers.cookie)
  const query: Record<string, string | string[]> = {}
  for (const key of url.searchParams.keys()) {
    const all = url.searchParams.getAll(key)
    query[key] = all.length > 1 ? all : all[0]!
  }
  const headerAuth = headerStr(req, 'authorization')
  const queryToken = Array.isArray(query.token) ? query.token[0] : query.token
  const rawToken = headerAuth && headerAuth.toLowerCase().startsWith('bearer ')
    ? headerAuth.slice(7).trim()
    : queryToken ?? null
  const sid = cookies['forge_sid'] ?? null
  const viewer = streamViewerFor(db, sid, app.sessions)
  const verified = rawToken ? deps.wiring.verifyToken(rawToken, false) : { valid: false }
  const token = rawToken ? streamTokenFor(db, rawToken, () => verified.valid) : null
  const actor = token
    ? asActor(db.get<{ persona: string | null }>('SELECT persona FROM users WHERE external_id = ?', [token.userExt ?? ''])?.persona ?? null)
    : viewer ? asActor(viewer.persona) : 'anonymous'
  const tenant = token?.org ?? viewer?.org ?? null
  const session = openStream({
    req, res, routeKey: hit.routeKey, method: req.method ?? 'GET', path: url.pathname,
    params: hit.params, query, headers: req.headers as Record<string, string | undefined>, cookies,
    actor, tenant, sessionId: sid, viewer, token,
  })
  const trace: StreamTrace = {
    routeKey: hit.routeKey, method: req.method ?? 'GET', path: url.pathname, params: hit.params, query,
    actor, tenant, sessionId: sid, tokenExt: token?.externalId ?? null,
    opened: () => session.opened, status: () => session.status,
  }
  try {
    if (deps.trackStream) await deps.trackStream(trace, () => hit.handler(session))
    else await hit.handler(session)
  } catch {
    if (!session.opened) session.reject(500, 'stream_failed')
  }
  void plan
}

/** Mount the materialized site modules listed in modules.json; zero modules is a valid shell state. */
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
