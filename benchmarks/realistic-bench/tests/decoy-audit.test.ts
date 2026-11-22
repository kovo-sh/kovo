// Adversarial decoy audit: proves that every hardened twin is (a) non-exploitable under its own
// solver, (b) invisible to the impact oracle under benign browsing, and (c) indistinguishable from a
// vulnerable site by route naming, file size or materialized-tree identity. Also exercises the
// browser-normalised redirect bypass class that a naive "starts with //" guard misses.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { join } from 'node:path'
import type { AppModule, PersonaId } from '../lib/types.ts'
import { personaIds } from '../lib/types.ts'
import { validateBlueprint } from '../generator/validate.ts'
import { generateVariant } from '../generator/variant.ts'
import { buildGroundTruth } from '../generator/groundtruth.ts'
import { groupUnits } from '../generator/subset.ts'
import { materialize, assertNoLeakage } from '../generator/materialize.ts'
import * as H from './helpers/decoy-audit.ts'
import acme from '../apps/acme-saas/index.ts'
import opsportal from '../apps/opsportal/index.ts'
import shopflow from '../apps/shopflow/index.ts'

const apps = [acme, opsportal, shopflow] as AppModule[]
const SEEDS = [1, 2, 3]
const TRUTH_MARKERS = /vulnerab|hardened|decoy|oracle|solver|CWE-\d|ground.?truth/i
const TRUTH_SEGMENTS = /vulnerab|hardened|decoy|oracle|solver|truth|planted|exploit|^sites$/i

interface CtxLike {
  login(persona: PersonaId): Promise<unknown>
  fetch(path: string, init?: unknown): Promise<unknown>
}

function forcedPlan(mod: AppModule, seed: number, mode: 'vulnerable' | 'hardened') {
  const plan = generateVariant(mod.blueprint, seed)
  for (const id of Object.keys(plan.sites)) plan.sites[id] = mode
  return plan
}

test('twin files and root-cause paths carry no decoy tells', () => {
  for (const mod of apps) {
    validateBlueprint(mod.blueprint)
    const { min, max } = mod.blueprint.decoyCount
    assert.ok(min >= 1 && max >= min, `${mod.name}: decoyCount range must include >=1`)
    const keystones = mod.blueprint.sites.filter((s) => s.canBeDecoy === false)
    assert.ok(keystones.length >= 1, `${mod.name}: needs at least one non-decoyable keystone`)

    for (const [routeKey, tmpl] of Object.entries(mod.blueprint.routes)) {
      assert.ok(!TRUTH_MARKERS.test(routeKey), `${mod.name}: route key "${routeKey}" is a tell`)
      for (const seg of tmpl.path.split('/')) {
        const name = seg.replace(/^\{noun:|\}$/g, '')
        assert.ok(!TRUTH_SEGMENTS.test(name), `${mod.name}: route segment "${seg}" is a tell`)
      }
    }

    for (const site of mod.blueprint.sites) {
      assert.ok(site.lure.length >= 20, `${site.id}: needs a realistic lure`)
      const dir = H.siteDir(mod.name, site.id)
      const vuln = H.readText(join(dir, 'vulnerable.ts'))
      const hard = H.readText(join(dir, 'hardened.ts'))
      assert.ok(H.readText(join(dir, 'solver.ts')).length > 0, `${site.id}: missing solver`)
      for (const [mode, text] of [['vulnerable', vuln], ['hardened', hard]] as const) {
        assert.ok(Buffer.byteLength(text) >= 400, `${site.id} ${mode}: stub-sized twin`)
        assert.ok(!TRUTH_MARKERS.test(text), `${site.id} ${mode}: truth marker leaked into site file`)
        assert.ok(!text.includes(site.id), `${site.id} ${mode}: site id leaked into site file`)
        assert.ok(!text.includes(site.lure), `${site.id} ${mode}: lure leaked into site file`)
      }
      const ratio = Math.max(vuln.length, hard.length) / Math.min(vuln.length, hard.length)
      assert.ok(ratio <= 2.5, `${site.id}: twin size ratio ${ratio.toFixed(2)} is a mode tell`)
      for (const seg of site.rootCause.file.split('/')) {
        assert.ok(!TRUTH_SEGMENTS.test(seg), `${site.id}: root-cause segment "${seg}" is a tell`)
      }
    }
  }
})

test('per-seed plans keep decoys in range, keystones vulnerable, chains coherent (1..30)', () => {
  for (const mod of apps) {
    const bp = mod.blueprint
    const units = groupUnits(bp.sites)
    const blocked = new Set(units.filter((u) => !u.decoyable).flatMap((u) => u.siteIds))
    const decoySeen = new Set<string>()
    for (let seed = 1; seed <= 30; seed++) {
      const plan = generateVariant(bp, seed)
      const hardened = H.modesOf(plan).filter((m) => m === 'hardened').length
      assert.ok(hardened >= bp.decoyCount.min && hardened <= bp.decoyCount.max, `${mod.name} seed ${seed}: ${hardened} decoys`)
      assert.ok(hardened >= 1, `${mod.name} seed ${seed}: no decoys`)
      for (const site of bp.sites) {
        if (site.canBeDecoy === false) assert.equal(plan.sites[site.id], 'vulnerable', `${site.id} seed ${seed}: keystone hardened`)
        if (plan.sites[site.id] === 'hardened') decoySeen.add(site.id)
      }
      for (const unit of units) {
        const modes = new Set(unit.siteIds.map((id) => plan.sites[id]))
        assert.equal(modes.size, 1, `${mod.name} seed ${seed}: chain unit split modes`)
      }
      const gt = buildGroundTruth(bp, plan)
      assert.equal(gt.vulns.length + gt.decoys.length, bp.sites.length)
      assert.equal(gt.decoys.length, hardened)
      for (const chain of gt.chains) {
        for (const sid of chain.siteIds) assert.equal(plan.sites[sid], 'vulnerable', `${chain.id}: decoy member scored as a chain`)
      }
      const liveChains = new Set(bp.sites.filter((s) => s.chain && plan.sites[s.id] === 'vulnerable').map((s) => s.chain!.id))
      assert.equal(gt.chains.length, liveChains.size, `${mod.name} seed ${seed}: chain accounting`)
    }
    for (const site of bp.sites) {
      if (site.canBeDecoy !== false && !blocked.has(site.id)) {
        assert.ok(decoySeen.has(site.id), `${site.id} is never selected as a decoy across seeds 1..30`)
      }
    }
  }
})

test('benign browsing and decoy solvers never trip the oracle (seeds 1..3)', async () => {
  for (const mod of apps) {
    for (const seed of SEEDS) {
      const plan = generateVariant(mod.blueprint, seed)
      const gt = buildGroundTruth(mod.blueprint, plan)
      const app = await mod.start({ plan, groundTruth: gt })
      try {
        const ctx = H.solverContext(mod, app) as unknown as CtxLike
        // Benign per-persona browsing of every decoy entry endpoint.
        for (const persona of personaIds) {
          await ctx.login(persona)
          for (const decoy of gt.decoys) {
            for (const ep of decoy.endpoints) {
              const path = ep.path.replace(/:([a-zA-Z0-9_]+)/g, '1') + '?page=1'
              await ctx.fetch(path).catch(() => undefined)
            }
          }
        }
        const benignHits = app.oracle.events()
        assert.deepEqual(
          benignHits.map((e) => `${e.kind}@${e.routeKey}`), [],
          `${mod.name} seed ${seed}: benign decoy traffic tripped the oracle`,
        )

        // Adversarial traffic: each decoy's own exploit attempt, isolated per boot.
        for (const decoy of gt.decoys) {
          app.oracle.reset()
          await H.runSolver(mod, decoy.siteId, ctx)
          const emitted = app.oracle.events()
          assert.deepEqual(
            emitted.map((e) => `${e.kind}@${e.routeKey}`), [],
            `${mod.name} seed ${seed}: decoy ${decoy.siteId} emitted an event under solver traffic`,
          )
          assert.equal(H.attributed(emitted, { oracle: decoy.oracle }).length, 0, `${mod.name} seed ${seed}: decoy ${decoy.siteId} attributed`)
        }
      } finally {
        await app.stop()
      }
    }
  }
})

test('open-redirect decoys reject browser-normalised off-origin targets', async () => {
  const variants = [
    { label: 'absolute', value: 'https://audit.example/landing' },
    { label: 'protocol-relative', value: '//audit.example/landing' },
    { label: 'origin-relative backslash', value: '/\\audit.example/landing' },
  ]
  for (const mod of apps) {
    const sites = mod.blueprint.sites.filter((s) => s.oracle.kinds.includes('open_redirect'))
    for (const mode of ['hardened', 'vulnerable'] as const) {
      const plan = forcedPlan(mod, 1, mode)
      const app = await mod.start({ plan, groundTruth: buildGroundTruth(mod.blueprint, plan) })
      try {
        const ctx = H.solverContext(mod, app) as unknown as CtxLike
        const ownHost = new URL(app.origin).host.toLowerCase()
        for (const site of sites) {
          const routeKey = site.routeKeys[0]!
          const route = plan.routes[routeKey]!
          const q = H.paramName(plan, site.params[0] ?? 'url')
          const probes = mode === 'hardened' ? variants : [variants[2]!]
          for (const probe of probes) {
            app.oracle.reset()
            const res = await H.fetchLocation(ctx, `${route.path}?${q}=${encodeURIComponent(probe.value)}`)
            assert.ok(res.location, `${mod.name} ${mode} ${site.id}: expected a redirect`)
            const host = H.resolvedHost(res.location, app.origin)
            if (mode === 'hardened') {
              assert.equal(host, ownHost, `${mod.name} ${site.id}: hardened twin redirected off-origin (${probe.label})`)
              assert.equal(H.attributed(app.oracle.events(), site).length, 0, `${mod.name} ${site.id}: hardened twin emitted open_redirect`)
            } else {
              assert.notEqual(host, ownHost, `${mod.name} ${site.id}: vulnerable twin failed to redirect off-origin (${probe.label})`)
              assert.ok(H.attributed(app.oracle.events(), site).length >= 1, `${mod.name} ${site.id}: oracle missed the ${probe.label} bypass`)
            }
          }
        }
      } finally {
        await app.stop()
      }
    }
  }
})

test('materialized trees expose no site identity, modes or truth', () => {
  for (const mod of apps) {
    const plan = generateVariant(mod.blueprint, 1)
    const res = materialize({ bp: mod.blueprint, plan, appDir: H.appDir(mod.name), libDir: H.LIB_DIR })
    try {
      assertNoLeakage(res.root)
      const variant = JSON.parse(H.readText(res.variantPath)) as Record<string, unknown>
      assert.deepEqual(Object.keys(variant).sort(), ['apiPrefix', 'app', 'idFormat', 'params', 'routes'])
      const serialized = JSON.stringify(variant)
      for (const site of mod.blueprint.sites) assert.ok(!serialized.includes(site.id), `${site.id} leaked into variant.json`)

      const tree = H.readTree(join(res.root, 'apps'))
      for (const site of mod.blueprint.sites) {
        for (const f of tree) {
          assert.ok(!f.text.includes(site.id), `${site.id} leaked into ${f.file}`)
          assert.ok(!f.text.includes(site.lure), `lure for ${site.id} leaked into ${f.file}`)
        }
        const expected = H.readText(join(H.siteDir(mod.name, site.id), `${plan.sites[site.id]}.ts`))
          .replace(/(['"])\.\.\/\.\.\/src\//g, '$1../')
        const planted = H.readText(join(res.sourceDir, ...site.rootCause.file.split('/')))
        assert.equal(planted, expected, `${site.id}: materialized twin differs from plan mode`)
      }
      const modules = JSON.parse(H.readText(join(res.sourceDir, 'modules.json'))) as string[]
      assert.deepEqual([...modules].sort(), mod.blueprint.sites.map((s) => s.rootCause.file).sort())
    } finally {
      res.cleanup()
    }
  }
})
