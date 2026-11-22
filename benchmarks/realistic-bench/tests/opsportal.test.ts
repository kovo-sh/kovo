// opsportal app self-tests: blueprint validity, boot + health + login for all personas, white-box
// leakage check on the materialized tree, and the implemented-site exploit matrix in both modes.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { resolve } from 'node:path'
import { personaIds } from '../lib/types.ts'
import { validateBlueprint } from '../generator/validate.ts'
import { generateVariant } from '../generator/variant.ts'
import { buildGroundTruth } from '../generator/groundtruth.ts'
import { assertNoLeakage } from '../generator/materialize.ts'
import { blueprint } from '../apps/opsportal/truth/blueprint.ts'
import { bootApp } from '../apps/opsportal/index.ts'
import { makeClient } from '../apps/opsportal/truth/matrix-helpers.ts'
import { runSiteMatrix } from '../apps/opsportal/truth/selftest.ts'

test('blueprint validates with 24 sites and 55-85 routes', () => {
  validateBlueprint(blueprint)
  assert.equal(blueprint.sites.length, 24)
  const n = Object.keys(blueprint.routes).length
  assert.ok(n >= 55 && n <= 85, `route count ${n} out of range`)
})

test('boots, serves health, and logs in all four personas', async () => {
  const plan = generateVariant(blueprint, 1)
  const started = await bootApp(plan, buildGroundTruth(blueprint, plan))
  try {
    const health = await fetch(started.origin + plan.routes.health!.path)
    assert.equal(health.status, 200)
    assert.equal(((await health.json()) as { status: string }).status, 'ok')

    for (const persona of personaIds) {
      const client = makeClient(started.origin, plan)
      await client.login(persona)
      const me = (await (await client.fetch(plan.routes.me!.path)).json()) as { authenticated: boolean; persona: string }
      assert.equal(me.authenticated, true, `login failed for ${persona}`)
      assert.equal(me.persona, persona)
    }
  } finally {
    await started.stop()
  }
})

test('materialized tree leaks no truth content', async () => {
  const plan = generateVariant(blueprint, 2)
  const started = await bootApp(plan, buildGroundTruth(blueprint, plan))
  try {
    const root = resolve(started.sourceDir, '..', '..', '..')
    assertNoLeakage(root)
  } finally {
    await started.stop()
  }
})

test('implemented-site matrix: vulnerable emits, hardened is clean (seeds 1,2)', async () => {
  const result = await runSiteMatrix({ seeds: [1, 2] })
  const failed = result.rows.filter((r) => !r.ok)
  assert.equal(failed.length, 0, `failing rows:\n${failed.map((r) => `${r.siteId} seed=${r.seed} ${r.mode}: ${r.detail}`).join('\n')}`)
  assert.equal(result.rows.length, blueprint.sites.length * 2 * 2) // 2 seeds x 2 modes x all sites
})
