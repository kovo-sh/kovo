/**
 * Held-out lift stream: false-positive containment for non-target mutation routes.
 *
 * The held-out unified run produced unmatched claims on shopflow's merchant-configuration and
 * review-moderation routes. Those routes are not planted targets: the benchmark's ground truth
 * has `settings-secret-disclosure` on GET /settings (a read leak) and `review-stored-xss` on the
 * catalog submit/queue lifecycle, not on PATCH settings or PATCH admin/reviews. The routes only
 * had an authentication guard, so a differential scanner could legitimately observe a viewer
 * mutating them and the grader correctly counted the claim as an unmatched false positive.
 *
 * This test pins the app-side fix (merchant-owner gate) and the taxonomy fact that a BFLA claim on
 * PATCH settings is not class/endpoint-compatible with any planted shopflow target. It is an app
 * contract test: no engine, verifier, or ground-truth entry is loosened.
 */
import assert from 'node:assert/strict'
import { test } from 'node:test'

import { startRealisticApp } from '../benchmarks/realistic-bench/run.ts'
import { generateVariant } from '../benchmarks/realistic-bench/generator/variant.ts'
import { buildGroundTruth } from '../benchmarks/realistic-bench/generator/groundtruth.ts'
import { matchFindingToEntries } from '../benchmarks/realistic-bench/grader/match.ts'
import { blueprint } from '../benchmarks/realistic-bench/apps/shopflow/truth/blueprint.ts'
import { buildPath, makeSolverCtx } from '../benchmarks/realistic-bench/apps/shopflow/truth/matrix-helpers.ts'
import type { SubmittedFinding } from '../benchmarks/realistic-bench/lib/types.ts'
import { endpointMatches } from '../benchmarks/realistic-bench/grader/match.ts'

process.env.KOVO_ALLOW_LOCAL_LAB = '1'

test('shopflow: viewer cannot mutate settings or moderate reviews; owner/admin still can', async () => {
  const app = await startRealisticApp({ app: 'shopflow', seed: 1 })
  try {
    const viewer = makeSolverCtx(app.origin, app.plan)
    const owner = makeSolverCtx(app.origin, app.plan)
    const admin = makeSolverCtx(app.origin, app.plan)
    await viewer.login('viewer')
    await owner.login('persona_a')
    await admin.login('admin')

    const settingsPath = buildPath(app.plan, 'updateSettings')
    const settings = JSON.stringify({ settings: { theme: 'dark' } })

    const viewerSettings = await viewer.fetch(settingsPath, {
      method: 'PATCH', headers: { 'content-type': 'application/json' }, body: settings,
    })
    assert.equal(viewerSettings.status, 403, 'viewer settings mutation must be forbidden')

    const ownerSettings = await owner.fetch(settingsPath, {
      method: 'PATCH', headers: { 'content-type': 'application/json' }, body: settings,
    })
    assert.equal(ownerSettings.status, 200, 'owner settings mutation must still work')

    const reviewPath = buildPath(app.plan, 'moderateReview', { reviewId: 'heldout-lift-contract' })
    const viewerReview = await viewer.fetch(reviewPath, { method: 'PATCH' })
    assert.equal(viewerReview.status, 403, 'viewer review moderation must be forbidden')

    // The role gate runs before the record lookup, so an unknown id is an authorization probe:
    // the privileged caller reaches the handler (404 for the missing record), never a 403.
    const adminReview = await admin.fetch(reviewPath, { method: 'PATCH' })
    assert.notEqual(adminReview.status, 403, 'admin review moderation must pass the role gate')
    assert.equal(adminReview.status, 404)
  } finally {
    await app.stop()
  }
})

test('shopflow: a cart id is not an authorization token across personas', async () => {
  const app = await startRealisticApp({ app: 'shopflow', seed: 1 })
  try {
    const owner = makeSolverCtx(app.origin, app.plan)
    const other = makeSolverCtx(app.origin, app.plan)
    await owner.login('persona_a')
    await other.login('persona_b')

    const created = await owner.fetch(buildPath(app.plan, 'createCart'), { method: 'POST' })
    assert.equal(created.status, 201)
    const cart = (await created.json()) as { id: string }
    const path = buildPath(app.plan, 'getCart', { cartId: cart.id })

    assert.equal((await owner.fetch(path)).status, 200, 'owner reads own cart')
    assert.equal((await other.fetch(path)).status, 404, 'cross-persona cart read must not be a BOLA')
    const injected = await other.fetch(buildPath(app.plan, 'addCartItem', { cartId: cart.id }), {
      method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ qty: 1 }),
    })
    assert.equal(injected.status, 404, 'cross-persona cart write must not be accepted')
  } finally {
    await app.stop()
  }
})

test('shopflow: BFLA claim on PATCH settings is not a planted target (unmatched, never recall)', () => {
  const plan = generateVariant(blueprint, 1)
  const truth = buildGroundTruth(blueprint, plan)
  const settingsPath = buildPath(plan, 'updateSettings')
  const finding: SubmittedFinding = {
    id: 'heldout-lift-settings-fp',
    title: 'BFLA: viewer can mutate store settings',
    endpoints: [{ method: 'PATCH', path: settingsPath }],
    status: 'runtime_confirmed',
    submittedAtMs: 1,
    costUsdAtSubmit: 0,
    cwe: 'CWE-862',
  }
  const entries = [
    ...truth.vulns.map(entry => ({ entry, isDecoy: false })),
    ...truth.decoys.map(entry => ({ entry, isDecoy: true })),
  ]
  assert.ok(finding.endpoints.some(ep => endpointMatches(ep, { method: 'PATCH', path: settingsPath })))
  assert.equal(matchFindingToEntries(finding, entries), null)
  // The finding is a genuine over-claim only because the app now enforces the owner gate; no
  // ground-truth endpoint is added or relabelled to absorb it.
})

test('shopflow: admin review moderation is not a planted target on any noun', () => {
  const plan = generateVariant(blueprint, 1)
  const truth = buildGroundTruth(blueprint, plan)
  // The generated noun set includes testimonials; the real PATCH route exists but has no planted
  // BFLA/IDOR site. A 2xx here (pre-fix) was an unmatched over-claim, never recall.
  const finding: SubmittedFinding = {
    id: 'heldout-lift-admin-review-fp',
    title: 'BFLA: viewer moderates admin testimonials',
    endpoints: [{ method: 'PATCH', path: buildPath(plan, 'moderateReview', { reviewId: '1' }) }],
    status: 'runtime_confirmed',
    submittedAtMs: 1,
    costUsdAtSubmit: 0,
    cwe: 'CWE-862',
  }
  const entries = [
    ...truth.vulns.map(entry => ({ entry, isDecoy: false })),
    ...truth.decoys.map(entry => ({ entry, isDecoy: true })),
  ]
  assert.equal(matchFindingToEntries(finding, entries), null)
})
