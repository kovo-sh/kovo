// Held-out integrity: the uncommitted salt must never reach an artifact or a scanner-visible
// briefing, variant.json must carry routes/params/idFormat/apiPrefix only, and two salts must yield
// different plans/materialized surfaces. Uses a fixed, obviously fake test salt (never a real secret).
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { join } from 'node:path'
import type { AppModule } from '../lib/types.ts'
import { generateVariant } from '../generator/variant.ts'
import { buildGroundTruth } from '../generator/groundtruth.ts'
import { listSeeds } from '../generator/seeds.ts'
import { materialize, assertNoLeakage } from '../generator/materialize.ts'
import { briefingFor, startRealisticApp } from '../run.ts'
import * as H from './helpers/decoy-audit.ts'
import acme from '../apps/acme-saas/index.ts'
import opsportal from '../apps/opsportal/index.ts'
import shopflow from '../apps/shopflow/index.ts'

const apps = [acme, opsportal, shopflow] as AppModule[]
const SALT_A = 'rb-fake-test-salt-aaaaaaaa-0001'
const SALT_B = 'rb-fake-test-salt-bbbbbbbb-0002'
const HELD_OUT_SEED = 1_000_001

test('held-out plans are deterministic, salt-keyed, and never contain the salt', () => {
  for (const mod of apps) {
    const a = generateVariant(mod.blueprint, HELD_OUT_SEED, { salt: SALT_A })
    const b = generateVariant(mod.blueprint, HELD_OUT_SEED, { salt: SALT_A })
    const c = generateVariant(mod.blueprint, HELD_OUT_SEED, { salt: SALT_B })
    assert.deepStrictEqual(a, b, `${mod.name}: held-out plan is not deterministic`)
    assert.notDeepStrictEqual(a, c, `${mod.name}: different salts produced the same plan`)
    assert.equal(a.seedSet, 'held-out')
    assert.equal(a.canarySalt === SALT_A || a.canarySalt === SALT_B, false, `${mod.name}: salt reused as canary salt`)
    const serialized = JSON.stringify(a)
    assert.ok(!serialized.includes(SALT_A) && !serialized.includes(SALT_B), `${mod.name}: salt serialized into the plan`)
  }
})

test('held-out derivation refuses missing/short salts and ignores salts on dev seeds', () => {
  const bp = acme.blueprint
  assert.throws(() => generateVariant(bp, HELD_OUT_SEED), /held-out seeds require a salt/)
  assert.throws(() => generateVariant(bp, HELD_OUT_SEED, { salt: 'too-short-salt' }), /held-out seeds require a salt/)
  assert.throws(() => listSeeds('held-out', 3), /held-out seeds require a salt/)
  assert.deepStrictEqual(generateVariant(bp, 7, { salt: SALT_A }), generateVariant(bp, 7), 'dev plans must ignore the salt')
})

test('GUARDIAN_RB_HELDOUT_SALT is honoured as the fallback (and only for held-out seeds)', () => {
  const prev = process.env.GUARDIAN_RB_HELDOUT_SALT
  process.env.GUARDIAN_RB_HELDOUT_SALT = SALT_A
  try {
    assert.deepStrictEqual(generateVariant(acme.blueprint, HELD_OUT_SEED), generateVariant(acme.blueprint, HELD_OUT_SEED, { salt: SALT_A }))
    assert.notDeepStrictEqual(generateVariant(acme.blueprint, HELD_OUT_SEED), generateVariant(acme.blueprint, HELD_OUT_SEED, { salt: SALT_B }))
  } finally {
    if (prev === undefined) delete process.env.GUARDIAN_RB_HELDOUT_SALT
    else process.env.GUARDIAN_RB_HELDOUT_SALT = prev
  }
})

test('listed held-out seeds are opaque, unique and salt-dependent', () => {
  const a = listSeeds('held-out', 6, SALT_A)
  const b = listSeeds('held-out', 6, SALT_B)
  assert.deepStrictEqual(a, listSeeds('held-out', 6, SALT_A))
  assert.notDeepStrictEqual(a, b)
  assert.equal(new Set(a).size, a.length)
  assert.ok(a.every((s) => Number.isInteger(s) && s >= 1_000_000))
  assert.ok(!JSON.stringify(a).includes(SALT_A))
})

test('materialized artifacts expose only routes/params/idFormat/apiPrefix (no salt, modes or truth)', () => {
  for (const mod of apps) {
    const plan = generateVariant(mod.blueprint, HELD_OUT_SEED, { salt: SALT_A })
    const gt = buildGroundTruth(mod.blueprint, plan)
    assert.ok(!JSON.stringify(gt).includes(SALT_A), `${mod.name}: salt leaked into ground truth`)
    const res = materialize({ bp: mod.blueprint, plan, appDir: H.appDir(mod.name), libDir: H.LIB_DIR })
    try {
      const text = H.readText(res.variantPath)
      const variant = JSON.parse(text) as Record<string, unknown>
      assert.deepEqual(Object.keys(variant).sort(), ['apiPrefix', 'app', 'idFormat', 'params', 'routes'])
      assert.deepEqual(variant.routes, plan.routes)
      assert.deepEqual(variant.params, plan.params)
      assert.equal(variant.apiPrefix, plan.apiPrefix)
      assert.equal(variant.idFormat, plan.idFormat)
      assert.ok(!text.includes(SALT_A), `${mod.name}: salt leaked into variant.json`)
      assert.ok(!/"(sites|seedSet|personas|canarySalt|groundTruth)"/.test(text), `${mod.name}: hidden plan fields leaked into variant.json`)
      assertNoLeakage(res.root)
      const tree = H.readTree(join(res.root, 'apps'))
      for (const site of mod.blueprint.sites) {
        assert.ok(!text.includes(site.id), `${site.id} leaked into variant.json`)
        for (const f of tree) assert.ok(!f.text.includes(site.lure), `lure for ${site.id} leaked into ${f.file}`)
        const planted = H.readText(join(res.sourceDir, ...site.rootCause.file.split('/')))
        const expected = H.readText(join(H.siteDir(mod.name, site.id), `${plan.sites[site.id]}.ts`))
          .replace(/(['"])\.\.\/\.\.\/src\//g, '$1../')
        assert.equal(planted, expected, `${site.id}: salted plan did not plant the chosen mode`)
      }
    } finally {
      res.cleanup()
    }
  }
})

test('two salts materialize different route surfaces', () => {
  const mod = acme
  const a = generateVariant(mod.blueprint, HELD_OUT_SEED, { salt: SALT_A })
  const b = generateVariant(mod.blueprint, HELD_OUT_SEED, { salt: SALT_B })
  const ra = materialize({ bp: mod.blueprint, plan: a, appDir: H.appDir(mod.name), libDir: H.LIB_DIR })
  const rb = materialize({ bp: mod.blueprint, plan: b, appDir: H.appDir(mod.name), libDir: H.LIB_DIR })
  try {
    const va = JSON.parse(H.readText(ra.variantPath)) as { routes: unknown; params: unknown; apiPrefix: string }
    const vb = JSON.parse(H.readText(rb.variantPath)) as { routes: unknown; params: unknown; apiPrefix: string }
    assert.notDeepStrictEqual({ routes: va.routes, params: va.params, apiPrefix: va.apiPrefix }, { routes: vb.routes, params: vb.params, apiPrefix: vb.apiPrefix })
  } finally {
    ra.cleanup()
    rb.cleanup()
  }
})

test('white-box briefing stays truth-free on a held-out variant', async () => {
  const app = await startRealisticApp({ app: 'acme-saas', seed: HELD_OUT_SEED, heldOutSalt: SALT_A })
  try {
    for (const mode of ['black-box', 'grey-box', 'white-box'] as const) {
      const briefing = JSON.stringify(briefingFor(app, mode))
      assert.ok(!briefing.includes(SALT_A), `${mode}: salt leaked into the briefing`)
      assert.ok(!/"sites"|seedSet|canarySalt|groundTruth/.test(briefing), `${mode}: hidden plan fields leaked into the briefing`)
      for (const site of acme.blueprint.sites) assert.ok(!briefing.includes(site.id), `${mode}: ${site.id} leaked into the briefing`)
    }
  } finally {
    await app.stop()
  }
})
