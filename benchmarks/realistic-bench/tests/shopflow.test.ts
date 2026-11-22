// shopflow lab self-tests: blueprint validity, boot + health + login for all personas, white-box
// leakage control on the materialized tree, and the site solver matrix for the implemented exemplars.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { join } from 'node:path'
import { startRealisticApp } from '../run.ts'
import { assertNoLeakage } from '../generator/materialize.ts'
import { validateBlueprint } from '../generator/validate.ts'
import { blueprint, implementedSiteIds } from '../apps/shopflow/truth/blueprint.ts'
import { runSiteMatrix } from '../apps/shopflow/truth/selftest.ts'
import { buildPath } from '../apps/shopflow/truth/matrix-helpers.ts'
import { personaIds } from '../lib/types.ts'

process.env.GUARDIAN_ALLOW_LOCAL_LAB = '1'

test('blueprint validates with the expected shape', () => {
  assert.doesNotThrow(() => validateBlueprint(blueprint))
  assert.equal(blueprint.sites.length, 26)
  assert.ok(Object.keys(blueprint.routes).length >= 55)
})

test('boot, health, login for every persona + no white-box leakage', async () => {
  for (const seed of [1, 2]) {
    const app = await startRealisticApp({ app: 'shopflow', seed })
    try {
      const health = await fetch(app.origin + buildPath(app.plan, 'healthCheck'))
      assert.equal(health.status, 200)
      assert.equal((await health.json()).status, 'ok')

      for (const persona of personaIds) {
        const cred = app.plan.personas[persona]
        const res = await fetch(app.origin + buildPath(app.plan, 'login'), {
          method: 'POST', headers: { 'content-type': 'application/json' },
          body: JSON.stringify({ email: cred.email, password: cred.password }),
        })
        assert.equal(res.status, 200, `login ${persona} seed ${seed}`)
        assert.equal((await res.json()).persona, persona)
      }

      // sourceDir is <root>/apps/shopflow/src; assertNoLeakage scans <root>/apps.
      const root = join(app.sourceDir, '..', '..', '..')
      assert.doesNotThrow(() => assertNoLeakage(root), 'materialized tree has no truth leakage')
    } finally {
      await app.stop()
    }
  }
})

test('site solver matrix: implemented exemplars pass both modes', async () => {
  const result = await runSiteMatrix({ seeds: [1, 2], siteIds: [...implementedSiteIds] })
  const failed = result.rows.filter((r) => !r.ok)
  assert.equal(failed.length, 0, `${result.summary}\n${failed.map((r) => `${r.siteId} seed=${r.seed} ${r.mode}: ${r.detail}`).join('\n')}`)
  // all sites x 2 seeds x 2 modes
  assert.equal(result.rows.length, implementedSiteIds.length * 2 * 2)
})
