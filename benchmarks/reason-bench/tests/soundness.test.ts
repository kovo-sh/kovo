// Benign-traffic soundness sweep (M2 acceptance): an all-hardened deployment must emit **zero**
// oracle events for every persona's normal read traffic, the decoy solvers must stay 0/0, and a
// run-scoped `kovo-qa-` probe record must be gone after cleanup and teardown.
//
// Seeds 1–2 always run. The full 1..30 sweep is opt-in (REASON_SOUNDNESS_SEEDS=1) because it
// materializes 30 variants per app; it is the M2 soundness gate, not the inner loop.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { randomBytes } from 'node:crypto'
import { existsSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'
import type {
  AppModule, AppName, PersonaId, SiteMode, SolverCtx, StartedApp, VariantPlan,
} from '../lib/types.ts'
import { generateVariant } from '../generator/variant.ts'
import { buildGroundTruth } from '../generator/groundtruth.ts'
import { validateBlueprint } from '../generator/validate.ts'
import ledgerflow from '../apps/ledgerflow/index.ts'
import forgecloud from '../apps/forgecloud/index.ts'

const APPS_ROOT = join(dirname(fileURLToPath(import.meta.url)), '..', 'apps')
const SEEDS = [1, 2]
const SWEEP = Boolean(process.env.REASON_SOUNDNESS_SEEDS)

const LEDGER_READS = [
  'health', 'appConfig', 'apiReference', 'me', 'dashboard',
  'listInvoices', 'listOrders', 'listCarts', 'listWallets', 'listTransfers', 'listPayouts',
  'listApprovals', 'getSubscription', 'listMembers', 'listInvites', 'activityFeed',
  'listExports', 'listFiles', 'listCoupons',
]

const FORGE_READS = [
  'health', 'me', 'orgs.list', 'workspaces.list', 'workspaces.current',
  'projects.list', 'pipelines.list', 'builds.list', 'tokens.list', 'secrets.list',
  'artifacts.list', 'exports.list', 'deployments.list', 'automations.list', 'webhooks.list',
  'members.list', 'teams.list', 'audit.list', 'search.facets',
]

interface TagProbe {
  /** Create a run-tagged benign record. Returns its id and whether the tag is visible in the list. */
  create(app: StartedApp, cookie: string, tag: string): Promise<{ id: string; listed: boolean }>
  /** Delete the tagged record. Returns whether the tag is still visible afterwards. */
  remove(app: StartedApp, cookie: string, id: string, tag: string): Promise<{ remaining: boolean }>
}

interface AppCase {
  app: AppName
  mod: AppModule
  reads: string[]
  probe: TagProbe
}

function routePath(app: StartedApp, key: string): string {
  return app.plan.routes[key]!.path
}

function login(app: StartedApp, id: PersonaId): Promise<string | null> {
  const route = app.plan.routes.login
  if (!route) throw new Error('plan has no login route')
  const cred = app.plan.personas[id]
  if (!cred) throw new Error(`unknown persona ${id}`)
  return fetch(app.origin + route.path, {
    method: route.method,
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ email: cred.email, password: cred.password }),
    redirect: 'manual',
  }).then((res) => {
    if (res.status >= 400) return null
    const cookie = (res.headers.getSetCookie?.() ?? []).map((c) => c.split(';')[0]!).join('; ')
    return cookie || null
  })
}

async function readBody(app: StartedApp, key: string, cookie: string): Promise<{ status: number; body: string }> {
  const route = app.plan.routes[key]
  if (!route) throw new Error(`plan has no route ${key}`)
  const res = await fetch(app.origin + route.path, { method: route.method, headers: { cookie } })
  return { status: res.status, body: await res.text() }
}

async function probeLedger(app: StartedApp, cookie: string, tag: string): Promise<{ id: string; listed: boolean }> {
  const res = await fetch(app.origin + routePath(app, 'createInvoice'), {
    method: 'POST',
    headers: { cookie, 'content-type': 'application/json' },
    body: JSON.stringify({ number: tag, amount_cents: 100, description: `${tag} benign probe` }),
  })
  assert.equal(res.status, 201, `createInvoice returned ${res.status}`)
  const created = (await res.json()) as { id?: unknown }
  const id = String(created.id ?? '')
  assert.ok(id, 'createInvoice returned no id')
  const listed = (await readBody(app, 'listInvoices', cookie)).body.includes(tag)
  return { id, listed }
}

async function removeLedger(app: StartedApp, cookie: string, id: string, tag: string): Promise<{ remaining: boolean }> {
  const path = routePath(app, 'deleteInvoice').replace(/:([A-Za-z0-9_]+)/g, () => encodeURIComponent(id))
  const res = await fetch(app.origin + path, { method: 'DELETE', headers: { cookie } })
  assert.equal(res.status, 200, `deleteInvoice returned ${res.status}`)
  return { remaining: (await readBody(app, 'listInvoices', cookie)).body.includes(tag) }
}

async function probeForge(app: StartedApp, cookie: string, tag: string): Promise<{ id: string; listed: boolean }> {
  const res = await fetch(app.origin + routePath(app, 'secrets.create'), {
    method: 'POST',
    headers: { cookie, 'content-type': 'application/json' },
    body: JSON.stringify({ name: tag, value: 'rb_fake_probe' }),
  })
  assert.equal(res.status, 201, `secrets.create returned ${res.status}`)
  const created = (await res.json()) as { item?: { id?: unknown } }
  const id = String(created.item?.id ?? '')
  assert.ok(id, 'secrets.create returned no item id')
  const listed = (await readBody(app, 'secrets.list', cookie)).body.includes(tag)
  return { id, listed }
}

async function removeForge(app: StartedApp, cookie: string, id: string, tag: string): Promise<{ remaining: boolean }> {
  const path = routePath(app, 'secrets.delete').replace(/:([A-Za-z0-9_]+)/g, () => encodeURIComponent(id))
  const res = await fetch(app.origin + path, { method: 'DELETE', headers: { cookie } })
  assert.equal(res.status, 200, `secrets.delete returned ${res.status}`)
  return { remaining: (await readBody(app, 'secrets.list', cookie)).body.includes(tag) }
}

const CASES: AppCase[] = [
  {
    app: 'ledgerflow',
    mod: ledgerflow as AppModule,
    reads: LEDGER_READS,
    probe: { create: probeLedger, remove: removeLedger },
  },
  {
    app: 'forgecloud',
    mod: forgecloud as AppModule,
    reads: FORGE_READS,
    probe: { create: probeForge, remove: removeForge },
  },
]

/** Freeze every site to its hardened twin so a benign read can never be credited as an exploit. */
async function startHardened(ctx: AppCase, seed: number): Promise<StartedApp> {
  const blueprint = validateBlueprint(ctx.mod.blueprint)
  const base = generateVariant(blueprint, seed)
  const modes: Record<string, SiteMode> = Object.fromEntries(blueprint.sites.map((s) => [s.id, 'hardened']))
  const plan: VariantPlan = { ...base, sites: { ...base.sites, ...modes } }
  return ctx.mod.start({ plan, groundTruth: buildGroundTruth(blueprint, plan) })
}

function solverContext(app: StartedApp): SolverCtx {
  const loginRoute = app.plan.routes.login
  if (!loginRoute) throw new Error('plan has no login route')
  return {
    origin: app.origin,
    plan: app.plan,
    persona: (id: PersonaId) => app.plan.personas[id]!,
    login: async (id: PersonaId): Promise<Record<string, string>> => {
      const cred = app.plan.personas[id]
      if (!cred) throw new Error(`unknown persona ${id}`)
      const res = await fetch(app.origin + loginRoute.path, {
        method: loginRoute.method,
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ email: cred.email, password: cred.password }),
        redirect: 'manual',
      })
      if (res.status >= 400) throw new Error(`login ${id} failed: ${res.status}`)
      const cookie = (res.headers.getSetCookie?.() ?? []).map((c) => c.split(';')[0]!).join('; ')
      return cookie ? { cookie } : {}
    },
    request: async (input) => {
      const res = await fetch(app.origin + input.path, {
        method: input.method,
        headers: { ...(input.headers ?? {}) },
        body: input.body === undefined ? undefined
          : typeof input.body === 'string' ? input.body : JSON.stringify(input.body),
        redirect: 'manual',
      })
      const text = await res.text()
      return {
        status: res.status,
        headers: Object.fromEntries(res.headers.entries()),
        body: text,
        json<T = unknown>(): T { return JSON.parse(text) as T },
      }
    },
  }
}

interface SoundnessResult {
  events: string[]
  personas: number
  reads: number
  deniedLogins: string[]
}

async function soundnessPass(ctx: AppCase, seed: number): Promise<SoundnessResult> {
  const app = await startHardened(ctx, seed)
  const tag = `kovo-qa-${seed}-${randomBytes(4).toString('hex')}`
  const result: SoundnessResult = { events: [], personas: 0, reads: 0, deniedLogins: [] }
  try {
    // 1. every persona attempts a login and reads the common area.
    for (const id of Object.keys(app.plan.personas) as PersonaId[]) {
      result.personas += 1
      const cookie = await login(app, id)
      if (!cookie) { result.deniedLogins.push(id); continue }
      for (const key of ctx.reads) {
        const res = await readBody(app, key, cookie)
        result.reads += 1
        // 401/403 for a low-privilege persona is a normal authorization outcome, not an oracle event.
        assert.ok(res.status < 500, `${ctx.app}/${seed} ${id} ${key} returned ${res.status}`)
      }
    }

    // 2. run-scoped record: visible while it exists, gone after the app's own cleanup route.
    const owner = await login(app, 'owner_a')
    assert.ok(owner, `${ctx.app}/${seed} owner_a could not log in`)
    const created = await ctx.probe.create(app, owner, tag)
    assert.equal(created.listed, true, `${ctx.app}/${seed} tagged record ${tag} was not listed after create`)
    const removed = await ctx.probe.remove(app, owner, created.id, tag)
    assert.equal(removed.remaining, false, `${ctx.app}/${seed} orphan ${tag} still listed after cleanup`)

    // 3. reads and the tagged write must not have tripped any oracle.
    result.events = app.oracle.events().map((e) => `${e.kind}:${e.routeKey ?? 'n/a'}:${e.actor ?? 'n/a'}`)
    assert.deepEqual(result.events, [], `${ctx.app}/${seed} benign traffic emitted oracle events`)

    // 4. decoy solvers against the hardened look-alikes: 0 oracle events.
    for (const site of validateBlueprint(ctx.mod.blueprint).sites) {
      if (!site.id.includes('-d')) continue
      const file = join(APPS_ROOT, ctx.app, 'sites', site.id, 'solver.ts')
      const mod = (await import(pathToFileURL(file).href)) as { solve?: (c: SolverCtx) => Promise<void> }
      if (!mod.solve) continue
      try {
        await mod.solve(solverContext(app))
      } catch {
        // A hardened twin rejecting the decoy walkthrough is the expected outcome.
      }
      const decoyEvents = app.oracle.events().filter((e) =>
        (site.oracle.kinds as readonly string[]).includes(e.kind) &&
        site.oracle.routeKeys.includes(e.routeKey ?? ''))
      assert.equal(decoyEvents.length, 0, `${ctx.app}/${seed} decoy ${site.id} emitted ${decoyEvents.length} event(s)`)
    }
    assert.deepEqual(app.oracle.events(), [], `${ctx.app}/${seed} decoy solvers emitted oracle events`)

    // 5. teardown: the materialized tree is removed and the loopback listener is closed. The lab
    // DB is per-run `node:sqlite :memory:`, so no run-tagged record can outlive this point.
    const sourceDir = app.sourceDir
    await app.stop()
    assert.equal(existsSync(sourceDir), false, `${ctx.app}/${seed} materialized tree survived teardown (orphan state)`)
    await assert.rejects(fetch(app.origin + routePath(app, 'health')), `${ctx.app}/${seed} listener survived teardown`)

    return result
  } finally {
    await app.stop().catch(() => undefined)
  }
}

for (const ctx of CASES) {
  for (const seed of SEEDS) {
    test(`${ctx.app} seed=${seed}: benign traffic and decoys emit zero oracle events`, async () => {
      const result = await soundnessPass(ctx, seed)
      assert.ok(result.reads >= 90, `${ctx.app}/${seed} exercised only ${result.reads} read(s)`)
      assert.ok(result.personas === 6, `${ctx.app}/${seed} exercised ${result.personas} personas`)
    })
  }
}

test('30-seed benign soundness sweep (REASON_SOUNDNESS_SEEDS)', { skip: !SWEEP }, async (t) => {
  for (const ctx of CASES) {
    for (let seed = 1; seed <= 30; seed++) {
      await t.test(`${ctx.app} seed=${seed}`, async () => {
        const result = await soundnessPass(ctx, seed)
        assert.deepEqual(result.events, [], `${ctx.app}/${seed} emitted oracle events`)
      })
    }
  }
})
