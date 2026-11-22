import { test } from 'node:test'
import assert from 'node:assert/strict'
import type { AppBlueprint, SiteMode } from '../lib/types.ts'
import { generateVariant } from '../generator/variant.ts'
import { validateBlueprint } from '../generator/validate.ts'
import { listSeeds, resolveSeed } from '../generator/seeds.ts'
import { miniBlueprint } from './fixtures/mini-blueprint.ts'

const clone = (bp: AppBlueprint): AppBlueprint => structuredClone(bp)
const SALT_A = 'held-out-salt-aaaaaaaa'
const SALT_B = 'held-out-salt-bbbbbbbb'

function hardenedCount(modes: Record<string, SiteMode>): number {
  return Object.values(modes).filter((m) => m === 'hardened').length
}

test('determinism: same seed => deep-equal plan; different seeds differ', () => {
  const a = generateVariant(miniBlueprint, 42)
  const b = generateVariant(miniBlueprint, 42)
  assert.deepStrictEqual(a, b)
  assert.notDeepStrictEqual(generateVariant(miniBlueprint, 42), generateVariant(miniBlueprint, 43))
})

test('held-out: same seed+salt deep-equal; different salts differ', () => {
  const a = generateVariant(miniBlueprint, 1_000_000, { salt: SALT_A })
  const b = generateVariant(miniBlueprint, 1_000_000, { salt: SALT_A })
  assert.deepStrictEqual(a, b)
  assert.notDeepStrictEqual(a, generateVariant(miniBlueprint, 1_000_000, { salt: SALT_B }))
  assert.equal(a.seedSet, 'held-out')
})

test('decoy count stays within bounds across seeds 1..20', () => {
  for (let seed = 1; seed <= 20; seed++) {
    const plan = generateVariant(miniBlueprint, seed)
    const n = hardenedCount(plan.sites)
    assert.ok(n >= miniBlueprint.decoyCount.min && n <= miniBlueprint.decoyCount.max, `seed ${seed}: ${n} hardened`)
  }
})

test('chain members always share a mode', () => {
  const bp = clone(miniBlueprint)
  bp.sites[0]!.chain = { id: 'chain-x', step: 1 }
  bp.sites[1]!.chain = { id: 'chain-x', step: 2 }
  for (let seed = 1; seed <= 20; seed++) {
    const plan = generateVariant(bp, seed)
    assert.equal(plan.sites['demo-site'], plan.sites['demo-site-2'], `seed ${seed}`)
  }
})

test('canBeDecoy:false sites are never hardened', () => {
  const bp = clone(miniBlueprint)
  bp.sites[0]!.canBeDecoy = false
  for (let seed = 1; seed <= 20; seed++) {
    assert.equal(generateVariant(bp, seed).sites['demo-site'], 'vulnerable', `seed ${seed}`)
  }
})

test('held-out seeds and listSeeds refuse without a salt', () => {
  assert.throws(() => generateVariant(miniBlueprint, 1_000_000), /held-out seeds require a salt/)
  assert.throws(() => resolveSeed(1_000_000), /held-out seeds require a salt/)
  assert.throws(() => listSeeds('held-out'), /held-out seeds require a salt/)
  const seeds = listSeeds('held-out', 4, SALT_A)
  assert.equal(seeds.length, 4)
  assert.ok(seeds.every((s) => s >= 1_000_000))
  assert.notDeepStrictEqual(seeds, listSeeds('held-out', 4, SALT_B))
  assert.deepStrictEqual(listSeeds('dev', 3), [1, 2, 3])
})

test('validateBlueprint passes the fixture', () => {
  assert.doesNotThrow(() => validateBlueprint(miniBlueprint))
})

test('validateBlueprint catches a duplicate site id', () => {
  const bp = clone(miniBlueprint)
  bp.sites[1]!.id = 'demo-site'
  assert.throws(() => validateBlueprint(bp), /duplicate site id/)
})

test('validateBlueprint catches a missing routeKey', () => {
  const bp = clone(miniBlueprint)
  bp.sites[0]!.routeKeys = ['nope']
  assert.throws(() => validateBlueprint(bp), /routeKey "nope" is not in bp.routes/)
})

test('validateBlueprint catches a duplicate (kind,routeKey) pair', () => {
  const bp = clone(miniBlueprint)
  bp.sites[1]!.oracle = { kinds: ['cross_tenant_read'], routeKeys: ['getInvoice'] }
  assert.throws(() => validateBlueprint(bp), /duplicate \(kind,routeKey\) pair cross_tenant_read@getInvoice/)
})

test('validateBlueprint catches a bad rootCause path', () => {
  const bp = clone(miniBlueprint)
  bp.sites[0]!.rootCause = { file: 'BadPath.ts', symbol: 'x' }
  assert.throws(() => validateBlueprint(bp), /rootCause.file "BadPath.ts" must match/)
})
