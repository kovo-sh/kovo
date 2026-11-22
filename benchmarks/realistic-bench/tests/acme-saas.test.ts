// acme-saas app tests: boot seeds 1 & 2, confirm health + login for all four personas, assert the
// materialized tree is leak-free, and run the implemented-site matrix in both modes.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { join } from 'node:path'
import { personaIds } from '../lib/types.ts'
import { startRealisticApp } from '../run.ts'
import { assertNoLeakage } from '../generator/materialize.ts'
import { makeSolverCtx } from './helpers/site-matrix.ts'
import { blueprint } from '../apps/acme-saas/truth/blueprint.ts'
import { runSiteMatrix } from '../apps/acme-saas/truth/selftest.ts'

test('acme-saas boots, authenticates every persona, and leaks nothing', async () => {
  for (const seed of [1, 2]) {
    const app = await startRealisticApp({ app: 'acme-saas', seed })
    try {
      const ctx = makeSolverCtx(app)
      const health = await ctx.fetch(ctx.path('health'))
      assert.equal(health.status, 200, `seed ${seed} health`)
      assert.equal(health.json?.status, 'ok')

      for (const persona of personaIds) {
        const session = await ctx.login(persona)
        assert.ok(session.headers.cookie, `seed ${seed} ${persona} received a session cookie`)
        const me = await ctx.fetch(ctx.path('me'), { session })
        assert.equal(me.status, 200, `seed ${seed} ${persona} /me`)
        assert.equal(me.json?.user && (me.json.user as { tenant: string }).tenant, app.plan.personas[persona].tenant)
      }

      const root = join(app.sourceDir, '..', '..', '..')
      assert.doesNotThrow(() => assertNoLeakage(root), 'materialized tree is free of white-box leakage')
    } finally {
      await app.stop()
    }
  }
})

test('implemented site matrix: vulnerable twins fire, hardened twins stay silent', async () => {
  const result = await runSiteMatrix({ seeds: [1, 2] }) // all planted sites
  for (const row of result.rows) {
    assert.ok(row.ok, `${row.siteId} seed=${row.seed} mode=${row.mode}: ${row.detail}`)
  }
  assert.equal(result.rows.length, blueprint.sites.length * 2 * 2)
})
