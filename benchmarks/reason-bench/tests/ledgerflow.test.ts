// Full ledgerflow twin matrix (M2 acceptance): every one of the 14 sites fires its attributed
// oracle on the vulnerable twin and stays silent on the hardened twin, and the five decoy
// look-alikes emit zero oracle events in their decoy role.
//
// Four mountings per seed keep this bounded:
//   A. the seed's real variant (via run.ts startReasonApp) — every already-vulnerable site fires
//   B. a forced plan with the remaining real sites vulnerable — the rest of the 14 also fire
//   C. an all-hardened plan — every real solver is silent, then the decoy solvers are silent too
// The forced plans are built exactly the way `run.ts selftest`'s generic runner forces them.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { dirname, join } from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'
import type {
  AppModule, AppName, OracleEvent, PersonaId, SiteMode, SiteSpec, SolverCtx, StartedApp, VariantPlan,
} from '../lib/types.ts'
import { startReasonApp } from '../run.ts'
import { generateVariant } from '../generator/variant.ts'
import { buildGroundTruth } from '../generator/groundtruth.ts'
import { validateBlueprint } from '../generator/validate.ts'
import ledgerflow from '../apps/ledgerflow/index.ts'

const APP: AppName = 'ledgerflow'
const SEEDS = [1, 2]
const MOD = ledgerflow as AppModule
const APPS_ROOT = join(dirname(fileURLToPath(import.meta.url)), '..', 'apps')

function blueprintSites(): SiteSpec[] {
  return validateBlueprint(MOD.blueprint).sites
}

function realSites(): string[] {
  return blueprintSites().map((s) => s.id).filter((id) => !id.includes('-d')).sort()
}

function decoySites(): string[] {
  return blueprintSites().map((s) => s.id).filter((id) => id.includes('-d')).sort()
}

function siteSpec(id: string): SiteSpec {
  const spec = blueprintSites().find((s) => s.id === id)
  if (!spec) throw new Error(`blueprint is missing site ${id}`)
  return spec
}

/** Events attributed to the site: matching oracle kind and route key (same rule as run.ts). */
function siteEvents(app: StartedApp, spec: SiteSpec): OracleEvent[] {
  return app.oracle.events().filter((e) =>
    (spec.oracle.kinds as readonly string[]).includes(e.kind) &&
    spec.oracle.routeKeys.includes(e.routeKey ?? ''))
}

/** Request context shared by every solver (mirrors run.ts#solverContext). */
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

async function runSolver(app: StartedApp, id: string): Promise<Error | null> {
  const file = join(APPS_ROOT, APP, 'sites', id, 'solver.ts')
  const mod = (await import(pathToFileURL(file).href)) as { solve?: (ctx: SolverCtx) => Promise<void> }
  if (!mod.solve) return new Error(`sites/${id}/solver.ts must export solve(ctx)`)
  try {
    await mod.solve(solverContext(app))
    return null
  } catch (err) {
    return err as Error
  }
}

async function startForced(seed: number, modes: Record<string, SiteMode>): Promise<StartedApp> {
  const blueprint = validateBlueprint(MOD.blueprint)
  const base = generateVariant(blueprint, seed)
  const plan: VariantPlan = { ...base, sites: { ...base.sites, ...modes } }
  return MOD.start({ plan, groundTruth: buildGroundTruth(blueprint, plan) })
}

function allSites(mode: SiteMode): Record<string, SiteMode> {
  return Object.fromEntries(blueprintSites().map((s) => [s.id, mode]))
}

test('ledgerflow blueprint exposes 14 real sites and 5 decoy look-alikes', () => {
  assert.equal(realSites().length, 14, `real sites: ${realSites().join(',')}`)
  assert.equal(decoySites().length, 5, `decoy sites: ${decoySites().join(',')}`)
})

for (const seed of SEEDS) {
  test(`ledgerflow seed=${seed}: every vulnerable site fires and every decoy is 0/0`, async () => {
    // --- A. the seed's real variant (run.ts entrypoint) ---
    const started = await startReasonApp({ app: APP, seed })
    const fired = new Set<string>()
    try {
      for (const site of blueprintSites()) {
        const mode: SiteMode = started.plan.sites[site.id] ?? 'hardened'
        // Decoy look-alikes are only exercised in their decoy (hardened) role; when a variant
        // happens to mount one vulnerable it is just another target and is covered by phase C.
        if (mode !== 'vulnerable' || site.id.includes('-d')) continue
        const err = await runSolver(started, site.id)
        assert.equal(err, null, `${site.id} solver failed on the vulnerable twin: ${err?.message}`)
        const events = siteEvents(started, site)
        assert.ok(events.length > 0, `${site.id} vulnerable twin emitted no attributed event`)
        fired.add(site.id)
      }
      for (const decoy of decoySites()) {
        if (started.plan.sites[decoy] === 'vulnerable') continue
        const events = siteEvents(started, siteSpec(decoy))
        assert.equal(events.length, 0, `${decoy} emitted ${events.length} event(s) in its decoy role`)
      }
    } finally {
      await started.stop()
    }

    // --- B. force the real sites that this seed mounted hardened, so all 14 are covered ---
    const missing = realSites().filter((id) => !fired.has(id))
    if (missing.length) {
      const modes = allSites('hardened')
      for (const id of missing) modes[id] = 'vulnerable'
      const forced = await startForced(seed, modes)
      try {
        for (const id of missing) {
          const err = await runSolver(forced, id)
          assert.equal(err, null, `${id} solver failed on the forced vulnerable twin: ${err?.message}`)
          const events = siteEvents(forced, siteSpec(id))
          assert.ok(events.length > 0, `${id} forced vulnerable twin emitted no attributed event`)
          fired.add(id)
        }
      } finally {
        await forced.stop()
      }
    }
    assert.deepEqual([...fired].sort(), realSites(), 'all 14 real sites must fire on a vulnerable twin')

    // --- C. all-hardened plan: real solvers silent, decoy solvers 0/0 ---
    const hardened = await startForced(seed, allSites('hardened'))
    try {
      for (const id of realSites()) {
        await runSolver(hardened, id) // a hardened twin may legitimately reject the solver
        const events = siteEvents(hardened, siteSpec(id))
        assert.equal(events.length, 0, `${id} hardened twin emitted ${events.length} attributed event(s)`)
      }
      hardened.oracle.reset()
      for (const id of decoySites()) {
        await runSolver(hardened, id)
      }
      assert.equal(hardened.oracle.events().length, 0, 'decoy solvers must emit no oracle events on hardened twins')
    } finally {
      await hardened.stop()
    }
  })
}
