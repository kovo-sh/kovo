// acme-saas app module. Wires the impact recorder, database, canary registry and monitors, then
// materializes a per-seed source tree, dynamically imports its server, and starts it on loopback.
// Everything that must stay out of the materialized source (the recorder and its bound sinks) is
// constructed here and injected as pre-bound factories.
import { dirname, join } from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'
import type { AppBlueprint, AppModule, StartedApp, VariantPlan, SiteSpec } from '../../lib/types.ts'
import type { ResolveActor, HttpApp } from '../../lib/http.ts'
import { createOracle } from '../../lib/oracle.ts'
import { createDb } from '../../lib/db.ts'
import { createDbFacade } from './src/db-facade.ts'
import { createHttpApp } from '../../lib/http.ts'
import { createCanaryRegistry } from '../../lib/canary.ts'
import { createIdCodec } from '../../lib/ids.ts'
import { createVfs } from '../../lib/vfs.ts'
import { createEgress } from '../../lib/egress.ts'
import { render } from '../../lib/template.ts'
import { sign as jwtSign, verify as jwtVerify } from '../../lib/jwt.ts'
import { verifyWebhook } from '../../lib/webhook.ts'
import { simulateCommand } from '../../lib/simshell.ts'
import { parseXml } from '../../lib/xml.ts'
import { materialize } from '../../generator/materialize.ts'
import { blueprint } from './truth/blueprint.ts'
import { createMonitors } from './truth/monitors.ts'
import type { Wiring } from './src/context.ts'
import type { StartServerOpts, RunningServer } from './src/server.ts'

const HERE = dirname(fileURLToPath(import.meta.url))
const SESSION_COOKIE = 'acme_sid'
// Sites with a fully implemented (vulnerable, hardened) twin pair; see truth/sites-manifest.json.
const IMPLEMENTED_IDS = new Set([
  'acme.invoice-bola', 'acme.project-search-sqli', 'acme.file-path-traversal', 'acme.avatar-ssrf',
  'acme.member-role-privesc', 'acme.project-mass-assign', 'acme.invoice-write-bola', 'acme.report-ssti',
  'acme.webhook-forgery', 'acme.jwt-none', 'acme.sso-open-redirect', 'acme.project-stored-xss',
  'acme.reflected-search-xss', 'acme.import-xxe', 'acme.export-cmd-injection', 'acme.settings-csrf',
  'acme.report-cache-poison', 'acme.apikey-disclosure', 'acme.seat-invariant', 'acme.credit-double-spend',
  'acme.invite-workflow-skip', 'acme.admin-bfla', 'acme.legacy-auth-bypass', 'acme.notification-idor',
  'acme.file-list-bola', 'acme.billing-tamper', 'acme.auditlog-secret', 'acme.export-open-redirect',
])

function implementedSites(bp: AppBlueprint): SiteSpec[] {
  // Test-only override: mount exactly the comma-separated ids in ACME_MOUNT_SITES so a single
  // in-progress site can be exercised without editing the shared IMPLEMENTED_IDS set.
  const override = process.env.ACME_MOUNT_SITES
  if (override) {
    const want = new Set(override.split(',').map((s) => s.trim()).filter(Boolean))
    return bp.sites.filter((s) => want.has(s.id))
  }
  return bp.sites.filter((s) => IMPLEMENTED_IDS.has(s.id))
}

async function start(opts: { plan: VariantPlan; groundTruth: StartedApp['groundTruth']; oobCallbackPorts?: number[] }): Promise<StartedApp> {
  const { plan, groundTruth } = opts
  const sink = createOracle({ app: 'acme-saas' })
  const canaries = createCanaryRegistry(plan.canarySalt)
  const db = createDbFacade(createDb(sink))
  const ids = createIdCodec(plan.idFormat, plan.canarySalt)
  const secrets = { jwt: `rb_fake_jwt_${plan.canarySalt.slice(0, 12)}`, webhook: `rb_fake_whk_${plan.canarySalt.slice(0, 12)}` }
  const monitors = createMonitors({ db, oracle: sink, canaries, plan })

  const mat = materialize({ bp: { ...blueprint, sites: implementedSites(blueprint) }, plan, appDir: HERE, libDir: join(HERE, '..', '..', 'lib') })
  const serverMod = (await import(pathToFileURL(join(mat.sourceDir, 'server.ts')).href)) as {
    startServer(o: StartServerOpts): Promise<RunningServer>
  }

  const wiring: Wiring = {
    makeVfs: (files) => createVfs(sink, files),
    makeEgress: (services, oob) => createEgress({ oracle: sink, internalServices: services, oobCallbackPorts: oob }),
    render: (src, data, inputDerived) => render(src, data, { oracle: sink, inputDerived }),
    signToken: (payload) => jwtSign(payload, secrets.jwt),
    verifyToken: (token, acceptNone) => {
      const res = jwtVerify(token, { secret: secrets.jwt, algorithms: acceptNone ? ['HS256', 'none'] : ['HS256'], acceptNone, oracle: sink })
      return { valid: res.valid, payload: res.payload }
    },
    verifyWebhook: (secret, body, ts, sig) => verifyWebhook(secret, body, ts, sig, { oracle: sink, toleranceSec: 300 }),
    simulate: (template, args) => { const r = simulateCommand(template, args, sink); return { output: r.output, commands: r.commands } },
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
  const makeApp: (resolveActor: ResolveActor) => HttpApp = (resolveActor) =>
    createHttpApp({ plan, oracle: sink, monitors, canaries, db, resolveActor, sessionCookie: SESSION_COOKIE })

  const running = await serverMod.startServer({
    plan, uiDir: join(mat.sourceDir, '..', 'ui'), oobCallbackPorts: opts.oobCallbackPorts,
    db, ids, canaries, secrets, wiring, makeApp,
  })

  return {
    app: 'acme-saas', origin: running.origin, plan, groundTruth, sourceDir: mat.sourceDir, oracle: sink,
    async stop() {
      await running.close()
      db.close()
      mat.cleanup()
    },
  }
}

const mod: AppModule = { name: 'acme-saas', blueprint, start }
export default mod
