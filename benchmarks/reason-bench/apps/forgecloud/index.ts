// forgecloud app module. Wires the impact recorder, database, canary registry and monitors, discovers
// the site modules that have landed on disk, materializes a per-seed source tree, dynamically imports
// its server, and starts it on loopback. Everything that must stay out of the materialized source
// (the recorder and its bound sinks) is constructed here and injected as pre-bound factories.
import { existsSync, readdirSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'
import type {
  AppBlueprint, AppModule, SiteMode, SiteSpec, StartedApp, VariantPlan,
} from '../../lib/types.ts'
import type { ResolveActor, HttpApp } from '../../lib/http.ts'
import { createOracle, runWithCtx, type RequestCtx } from '../../lib/oracle.ts'
import { createDb } from '../../lib/db.ts'
import { createHttpApp } from '../../lib/http.ts'
import { createCanaryRegistry } from '../../lib/canary.ts'
import { createIdCodec } from '../../lib/ids.ts'
import { createVfs } from '../../lib/vfs.ts'
import { createEgress } from '../../lib/egress.ts'
import { render } from '../../lib/template.ts'
import { sign as jwtSign, verify as jwtVerify } from '../../lib/jwt.ts'
import { signWebhook, verifyWebhook } from '../../lib/webhook.ts'
import { simulateCommand } from '../../lib/simshell.ts'
import { parseXml } from '../../lib/xml.ts'
import { materialize } from '../../generator/materialize.ts'
import { withSites } from './truth/blueprint.ts'
import { createMonitors } from './truth/monitors.ts'
import { createDbFacade } from './src/db-facade.ts'
import { SESSION_COOKIE, createResolveActor } from './src/auth.ts'
import type { Wiring } from './src/context.ts'
import type { StartServerOpts, RunningServer } from './src/server.ts'

const HERE = dirname(fileURLToPath(import.meta.url))

/** Read every `sites/<id>/spec.ts` that has landed; zero directories is a valid shell state. */
async function discoverSites(): Promise<SiteSpec[]> {
  const dir = join(HERE, 'sites')
  if (!existsSync(dir)) return []
  const entries = readdirSync(dir, { withFileTypes: true })
    .filter((e) => e.isDirectory())
    .map((e) => e.name)
    .sort()
  const specs: SiteSpec[] = []
  for (const name of entries) {
    const specPath = join(dir, name, 'spec.ts')
    if (!existsSync(specPath)) continue
    try {
      const mod = (await import(pathToFileURL(specPath).href)) as {
        spec?: SiteSpec; default?: SiteSpec
      }
      const spec = mod.spec ?? mod.default
      if (spec && typeof spec.id === 'string') specs.push(spec)
    } catch {
      // An in-progress site with a broken spec must not stop the shell from starting.
    }
  }
  return specs
}

/** Sites the plan asks for, intersected with those actually present on disk. */
function plannedSites(specs: SiteSpec[], plan: VariantPlan): SiteSpec[] {
  const override = process.env.FORGECLOUD_MOUNT_SITES
  if (override) {
    const want = new Set(override.split(',').map((s) => s.trim()).filter(Boolean))
    return specs.filter((s) => want.has(s.id))
  }
  const modes = plan.sites ?? {}
  return specs.filter((s) => typeof modes[s.id] === 'string')
}

function planWithSites(plan: VariantPlan, sites: SiteSpec[]): VariantPlan {
  const modes: Record<string, SiteMode> = { ...(plan.sites ?? {}) }
  const override = process.env.FORGECLOUD_MOUNT_SITES
  for (const site of sites) {
    if (override && !modes[site.id]) modes[site.id] = 'vulnerable'
  }
  return { ...plan, sites: modes }
}

async function start(opts: { plan: VariantPlan; groundTruth: StartedApp['groundTruth']; oobCallbackPorts?: number[] }): Promise<StartedApp> {
  const { plan, groundTruth } = opts
  const sink = createOracle({ app: 'forgecloud' as never })
  const canaries = createCanaryRegistry(plan.canarySalt)
  const db = createDbFacade(createDb(sink))
  const ids = createIdCodec(plan.idFormat, plan.canarySalt)
  const secrets = {
    jwt: `rb_fake_jwt_${plan.canarySalt.slice(0, 12)}`,
    webhook: `rb_fake_whk_${plan.canarySalt.slice(0, 12)}`,
    signedUrl: `rb_fake_sig_${plan.canarySalt.slice(0, 12)}`,
    idp: `rb_fake_idp_${plan.canarySalt.slice(12, 24)}`,
  }
  const monitors = createMonitors({ db, oracle: sink, canaries, plan })

  const selected = plannedSites(discoveredSites, plan)
  const runPlan = planWithSites(plan, selected)
  const bp: AppBlueprint = withSites(selected)

  const mat = materialize({
    blueprint: bp, plan: runPlan, appDir: HERE, libDir: join(HERE, '..', '..', 'lib'),
  })
  const serverMod = (await import(pathToFileURL(join(mat.sourceDir, 'server.ts')).href)) as {
    startServer(o: StartServerOpts): Promise<RunningServer>
  }
  const uiDir = join(mat.sourceDir, '..', 'ui')

  const wiring: Wiring = {
    makeVfs: (files) => createVfs(sink, files),
    makeEgress: (services, oob) => createEgress({ oracle: sink, internalServices: services, oobCallbackPorts: oob }),
    render: (src, data, inputDerived) => render(src, data, { oracle: sink, inputDerived }),
    signToken: (payload) => jwtSign(payload, secrets.jwt),
    verifyToken: (token, acceptNone) => {
      const res = jwtVerify(token, {
        secret: secrets.jwt, algorithms: acceptNone ? ['HS256', 'none'] : ['HS256'], acceptNone, oracle: sink,
      })
      return { valid: res.valid, payload: res.payload }
    },
    signWebhook: (secret, body, ts) => signWebhook(secret, body, ts),
    verifyWebhook: (secret, body, ts, sig) => verifyWebhook(secret, body, ts, sig, { oracle: sink, toleranceSec: 300 }),
    simulate: (template, args) => {
      const r = simulateCommand(template, args, sink)
      return { output: r.output, commands: r.commands }
    },
    parseXml: (source, external, vfs, egress) => parseXml(source, {
      resolveExternalEntities: external,
      vfs: { read: (path: string) => vfs.read(path) ?? '' },
      oracle: sink,
      egress: {
        fetch: (url: string) => {
          void egress.fetch(url, { inputDerived: true }).catch(() => undefined)
          return ''
        },
      },
    }),
  }

  const makeApp = (resolveActor: ResolveActor): HttpApp => createHttpApp({
    plan: runPlan, oracle: sink, monitors, canaries, db, resolveActor, sessionCookie: SESSION_COOKIE,
  })

  const resolveActorImpl = createResolveActor(db)
  const running = await serverMod.startServer({
    plan: runPlan, uiDir, oobCallbackPorts: opts.oobCallbackPorts,
    db, ids, canaries, secrets, wiring, makeApp, resolveActor: resolveActorImpl,
    trackStream: async (trace, run) => {
      const values = [
        ...Object.values(trace.params), ...Object.values(trace.query).flat().map(String),
      ].filter(Boolean)
      const rc: RequestCtx = {
        routeKey: trace.routeKey, method: trace.method, path: trace.path, actor: trace.actor,
        tenant: trace.tenant, sessionId: trace.sessionId, inputs: values, inputSet: new Set(values),
        startedAt: Date.now(),
      }
      await runWithCtx(rc, run)
      const accepted = trace.opened()
      db.run(
        'INSERT INTO auth_events (kind,transport,actor_ext,org_slug,token_ext,route_key,accepted,detail) VALUES (?,?,?,?,?,?,?,?)',
        ['sse_connect', 'sse', trace.tokenExt ? '' : '', trace.tenant ?? '', trace.tokenExt ?? '', trace.routeKey,
          accepted ? 1 : 0, accepted ? 'stream_open' : `rejected:${trace.status()}`],
      )
      monitors.afterRequest?.(rc, sink, db)
      sink.logRequest({
        method: trace.method, path: trace.path, routeKey: trace.routeKey, status: trace.status(),
        actor: trace.actor, paramNames: Object.keys(trace.query).concat(Object.keys(trace.params)), suspicious: false,
      })
    },
  })

  return {
    app: 'forgecloud' as never,
    origin: running.origin,
    plan: runPlan,
    groundTruth,
    sourceDir: mat.sourceDir,
    oracle: sink,
    async stop() {
      await running.close()
      db.close()
      mat.cleanup()
    },
  }
}

// Discover specs at module load so the generator sees the same site list the shell will mount.
// Zero site directories is a valid shell state; in-progress site specs are skipped on error.
export const discoveredSites: SiteSpec[] = await discoverSites()

export const blueprint: AppBlueprint = withSites(discoveredSites)

const mod: AppModule = { name: 'forgecloud', blueprint, reasonBench: true, start }
export default mod
