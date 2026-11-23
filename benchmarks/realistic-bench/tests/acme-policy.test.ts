// acme-saas authorization policy boundary: encodes what the app deliberately allows, so a future
// change cannot silently turn an in-policy behaviour into an unplanted "vulnerability" (or the
// reverse). Two agentic claims were triaged against this boundary (viewer content writes and a
// plan-price overpost); both are in-policy here and must stay unconfirmed by the impact oracle.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { startRealisticApp } from '../run.ts'
import { makeSolverCtx } from './helpers/site-matrix.ts'

type Json = Record<string, unknown>

test('viewer may write tenant content; the tenant, not the owner, is the object boundary', async () => {
  const app = await startRealisticApp({ app: 'acme-saas', seed: 1 })
  try {
    const ctx = makeSolverCtx(app)
    const viewer = await ctx.login('viewer')
    const owner = await ctx.login('persona_a')
    const other = await ctx.login('persona_b')

    const own = ((await ctx.fetch(ctx.path('listProjects'), { session: owner })).json?.items ?? []) as Json[]
    const foreign = ((await ctx.fetch(ctx.path('listProjects'), { session: other })).json?.items ?? []) as Json[]
    assert.ok(own.length > 0 && foreign.length > 0)

    // Seeded spaces carry no owner id: the tenant is the only object-level boundary the app enforces.
    assert.equal(own[0]!.owner, '', 'seeded project has no owner_id')

    const sameTenant = await ctx.fetch(ctx.path('updateProject', { projectId: own[0]!.id }), {
      method: 'PATCH', session: viewer, body: { description: 'policy-probe' },
    })
    assert.equal(sameTenant.status, 200, 'viewer may edit tenant content')
    const reread = await ctx.fetch(ctx.path('getProject', { projectId: own[0]!.id }), { session: owner })
    assert.equal((reread.json as Json)?.description, 'policy-probe')

    const crossTenant = await ctx.fetch(ctx.path('updateProject', { projectId: foreign[0]!.id }), {
      method: 'PATCH', session: viewer, body: { description: 'policy-probe' },
    })
    assert.equal(crossTenant.status, 404, 'cross-tenant project writes are denied')

    // A cross-tenant DELETE answers 200 but is an idempotent no-op: the row survives.
    const crossDelete = await ctx.fetch(ctx.path('deleteProject', { projectId: foreign[0]!.id }), {
      method: 'DELETE', session: viewer,
    })
    assert.equal(crossDelete.status, 200)
    assert.equal((await ctx.fetch(ctx.path('getProject', { projectId: foreign[0]!.id }), { session: other })).status, 200)

    assert.deepEqual(app.oracle.events().map((e) => e.kind), [], 'in-policy content writes emit no impact event')
  } finally {
    await app.stop()
  }
})

test('2FA verify endpoint is inert: no pending state, no access delta, no impact event', async () => {
  const app = await startRealisticApp({ app: 'acme-saas', seed: 1 })
  try {
    const ctx = makeSolverCtx(app)
    const owner = await ctx.login('persona_a')
    // persona_a is seeded with twofa_enabled=1, yet the password login is already fully authorised.
    assert.equal((await ctx.fetch(ctx.path('me'), { session: owner })).status, 200)
    assert.equal((await ctx.fetch(ctx.path('getBilling'), { session: owner })).status, 200)

    const wrong = await ctx.fetch(ctx.path('twofaVerify'), { method: 'POST', session: owner, body: { code: '000000' } })
    const empty = await ctx.fetch(ctx.path('twofaVerify'), { method: 'POST', session: owner, body: {} })
    assert.deepEqual(wrong.json, { ok: true }, 'the verify endpoint accepts any code')
    assert.deepEqual(empty.json, { ok: true }, 'and an empty body')
    assert.equal((await ctx.fetch(ctx.path('getBilling'), { session: owner })).status, 200, 'access was already granted before verification')
    assert.equal((await ctx.fetch(ctx.path('twofaVerify'), { method: 'POST', body: { code: '000000' } })).status, 401)
    assert.deepEqual(app.oracle.events().map((e) => e.kind), [], 'no impact event: the call changes no state')
  } finally {
    await app.stop()
  }
})

test('hardened plan route ignores caller price/limit/credit fields and stays oracle-silent', async () => {
  const app = await startRealisticApp({ app: 'acme-saas', seed: 1 })
  try {
    const ctx = makeSolverCtx(app)
    const owner = await ctx.login('persona_a')
    const admin = await ctx.login('admin')
    assert.equal(app.plan.sites['acme.billing-tamper'], 'hardened', 'seed 1 mounts the hardened plan twin')

    const before = (await ctx.fetch(ctx.path('getBilling'), { session: owner })).json as Json
    const downgrade = await ctx.fetch(ctx.path('updatePlan'), {
      method: 'PATCH', session: owner, body: { planId: 'free', price: 0, seat_limit: 999, credits: 999999 },
    })
    assert.equal(downgrade.status, 200)

    app.oracle.reset()
    const mismatch = await ctx.fetch(ctx.path('updatePlan'), {
      method: 'PATCH', session: owner, body: { planId: 'pro', price: 1 },
    })
    assert.equal(mismatch.status, 200)
    assert.equal((mismatch.json as Json)?.price, 4900, 'response carries the catalog price, not the body price')

    const after = (await ctx.fetch(ctx.path('getBilling'), { session: admin })).json as Json
    assert.equal(after.price, before.price, 'plan price is unchanged')
    assert.equal(after.credits, before.credits, 'credits are not mass-assignable')
    assert.deepEqual(
      app.oracle.events().map((e) => `${e.kind}@${String(e.routeKey)}`), [],
      'a self-service plan switch (even below the seat limit) is not an impact event',
    )

    // Protected fields stay out of reach for a non-owner actor.
    const viewer = await ctx.login('viewer')
    assert.equal((await ctx.fetch(ctx.path('updatePlan'), { method: 'PATCH', session: viewer, body: { planId: 'pro' } })).status, 403)
  } finally {
    await app.stop()
  }
})
