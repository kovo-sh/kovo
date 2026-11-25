/**
 * v7 agent-FP triage (stream: agent-fp-triage).
 *
 * Rulings pinned here, from the fixture source and recorded serial replays (never from claim text):
 *
 * 1. opsportal `GET /api/me` + CWE-269 "viewer reassigns another tenant's case" — the *behaviour*
 *    is real and planted (`og.ticket-assign-cross-write`, idor/CWE-639). The claim's declared route
 *    (`/api/me`) is not the mutating exchange and CWE-269 is a sibling label, so it earns no recall
 *    and is charged in strict precision. The planted route must NOT be hardened (that would cost
 *    recall); the fix is verifier-side (bind the finding route to the mutating step and forbid an
 *    anonymous 401 as the sole authorization control). Contract: keep the planted idor exploitable
 *    and keep `/api/me` target-free.
 *
 * 2. shopflow `POST /orders/:id/payments` CWE-840 "non-idempotent double capture" — the route is
 *    not a planted target and repeated capture inserted a second charge with no concurrency
 *    (serial replay on a fresh order: 200/200/200, ledger 1 -> 4). Unintended, non-planted: the
 *    capture is now a one-shot ledger write, so a retried POST is refused with 409 and the ledger
 *    grows by exactly one row. Recall is unchanged because no site solver calls this route.
 *
 * 3. opsportal `POST /api/logs/filter` CWE-20 "unhandled 500 on a filter value" — the 500 is the
 *    planted SQL interpolation choking on a non-numeric value; it is the sqli target's symptom, not
 *    a separate input-validation bug. Hardening it (400) would neuter `og.log-filter-sqli`, so the
 *    fixture is left alone and a 500-only assertion must never count as injection confirmation.
 */
import assert from 'node:assert/strict'
import { test } from 'node:test'

import { startRealisticApp } from '../benchmarks/realistic-bench/run.ts'
import { generateVariant } from '../benchmarks/realistic-bench/generator/variant.ts'
import { buildGroundTruth } from '../benchmarks/realistic-bench/generator/groundtruth.ts'
import { buildPath, makeSolverCtx } from '../benchmarks/realistic-bench/apps/shopflow/truth/matrix-helpers.ts'
import {
  classCompatible, matchFindingToEntries, siblingClassPair,
} from '../benchmarks/realistic-bench/grader/match.ts'
import type { GroundTruth, SubmittedFinding, VariantPlan } from '../benchmarks/realistic-bench/lib/types.ts'
import { blueprint as shopflowBlueprint } from '../benchmarks/realistic-bench/apps/shopflow/truth/blueprint.ts'
import { blueprint as opsportalBlueprint } from '../benchmarks/realistic-bench/apps/opsportal/truth/blueprint.ts'
import { makeClient } from '../benchmarks/realistic-bench/apps/opsportal/truth/matrix-helpers.ts'
import opsportal from '../benchmarks/realistic-bench/apps/opsportal/index.ts'

process.env.KOVO_ALLOW_LOCAL_LAB = '1'

function finding(overrides: Partial<SubmittedFinding> & Pick<SubmittedFinding, 'id' | 'endpoints'>): SubmittedFinding {
  return {
    title: overrides.id,
    status: 'runtime_confirmed',
    submittedAtMs: 1,
    costUsdAtSubmit: 0,
    ...overrides,
  }
}

function entriesFor(app: 'shopflow' | 'opsportal'): {
  plan: VariantPlan
  entries: Array<{ entry: GroundTruth['vulns'][number]; isDecoy: boolean }>
  truth: GroundTruth
} {
  const bp = app === 'shopflow' ? shopflowBlueprint : opsportalBlueprint
  const plan = generateVariant(bp, 1)
  // The rulings are about planted sites; pin the two opsportal sites under test to their vulnerable
  // twin so the assertion cannot silently flip with the seed's random mode assignment.
  if (app === 'opsportal') {
    plan.sites['og.ticket-assign-cross-write'] = 'vulnerable'
    plan.sites['og.log-filter-sqli'] = 'vulnerable'
  }
  const truth = buildGroundTruth(bp, plan)
  return {
    plan,
    entries: [
      ...truth.vulns.map(entry => ({ entry, isDecoy: false })),
      ...truth.decoys.map(entry => ({ entry, isDecoy: true })),
    ],
    truth,
  }
}

/** Boot opsportal with the two sites under test forced to their vulnerable twin. */
async function bootForcedOpsportal(): Promise<{
  plan: VariantPlan
  origin: string
  stop(): Promise<void>
}> {
  const { plan, truth } = entriesFor('opsportal')
  const app = await opsportal.start({ plan, groundTruth: truth })
  return { plan, origin: app.origin, stop: () => app.stop() }
}

// ---------------------------------------------------------------------------------------------
// Ruling 2: shopflow capturePayment is a one-shot ledger write (unintended, non-planted).
// ---------------------------------------------------------------------------------------------

interface OrderRef { id: string }

async function freshOrder(ctx: ReturnType<typeof makeSolverCtx>, plan: ReturnType<typeof generateVariant>): Promise<OrderRef> {
  const created = await ctx.fetch(buildPath(plan, 'createCart'), {
    method: 'POST', headers: { 'content-type': 'application/json' }, body: '{}',
  })
  assert.equal(created.status, 201, 'cart creation')
  const cart = (await created.json()) as { id: string }
  await ctx.fetch(buildPath(plan, 'addCartItem', { cartId: cart.id }), {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ [plan.params['itemQty'] ?? 'qty']: 1 }),
  })
  const checkout = await ctx.fetch(buildPath(plan, 'checkout', { cartId: cart.id }), {
    method: 'POST', headers: { 'content-type': 'application/json' }, body: '{}',
  })
  assert.equal(checkout.status, 201, 'checkout')
  const order = (await checkout.json()) as { id: string }
  return order
}

async function paymentCount(ctx: ReturnType<typeof makeSolverCtx>, plan: ReturnType<typeof generateVariant>): Promise<number> {
  const res = await ctx.fetch(buildPath(plan, 'listPayments'))
  assert.equal(res.status, 200, 'list payments')
  const body = (await res.json()) as { payments?: unknown[]; items?: unknown[] }
  return (body.payments ?? body.items ?? []).length
}

test('shopflow: serial double capture is refused and adds exactly one ledger row', async () => {
  const app = await startRealisticApp({ app: 'shopflow', seed: 1 })
  try {
    const owner = makeSolverCtx(app.origin, app.plan)
    await owner.login('persona_a')
    const order = await freshOrder(owner, app.plan)
    const before = await paymentCount(owner, app.plan)
    const path = buildPath(app.plan, 'capturePayment', { orderId: order.id })

    const first = await owner.fetch(path, { method: 'POST', headers: { 'content-type': 'application/json' }, body: '{}' })
    assert.equal(first.status, 200, 'the first capture must succeed')

    const second = await owner.fetch(path, { method: 'POST', headers: { 'content-type': 'application/json' }, body: '{}' })
    assert.equal(second.status, 409, 'a repeated capture is a conflict, never a second charge')
    assert.equal(((await second.json()) as { error?: string }).error, 'already_captured')

    const third = await owner.fetch(path, { method: 'POST', headers: { 'content-type': 'application/json' }, body: '{}' })
    assert.equal(third.status, 409, 'every repeat is refused')

    const after = await paymentCount(owner, app.plan)
    assert.equal(after, before + 1, `ledger grew by exactly one row (${before} -> ${after})`)

    // The guard is per order, not global: a second, uncaptured order still captures.
    const other = await freshOrder(owner, app.plan)
    const otherCapture = await owner.fetch(buildPath(app.plan, 'capturePayment', { orderId: other.id }), {
      method: 'POST', headers: { 'content-type': 'application/json' }, body: '{}',
    })
    assert.equal(otherCapture.status, 200, 'a different order is unaffected by the ledger guard')
  } finally {
    await app.stop()
  }
})

test('shopflow: capturePayment is not a planted target (recall cannot move)', () => {
  const { plan, entries } = entriesFor('shopflow')
  const claim = finding({
    id: 'agent-fp-triage-capture-fp',
    title: 'Non-idempotent capture: repeated POST /purchases/:order/charges',
    endpoints: [{ method: 'POST', path: buildPath(plan, 'capturePayment', { orderId: 'x' }) }],
    vulnClass: 'business_logic',
    cwe: 'CWE-840',
  })
  assert.equal(matchFindingToEntries(claim, entries), null, 'no ground-truth entry absorbs the claim')
  assert.ok(!entries.some(e => !e.isDecoy && e.entry.endpoints.some(ep => ep.routeKey === 'capturePayment')),
    'capturePayment must not gain a target: hardening a non-planted route is not truth inflation')
})

// ---------------------------------------------------------------------------------------------
// Ruling 1: opsportal cross-tenant ticket assign is a PLANTED idor; /api/me is not the write.
// ---------------------------------------------------------------------------------------------

test('opsportal: the planted cross-tenant ticket assign stays exploitable', async () => {
  const app = await bootForcedOpsportal()
  try {
    const owner = makeClient(app.origin, app.plan)
    const viewer = makeClient(app.origin, app.plan)
    const anon = makeClient(app.origin, app.plan)
    await owner.login('persona_b')
    await viewer.login('viewer')

    const listRes = await owner.fetch(app.plan.routes['ticketList']!.path)
    assert.equal(listRes.status, 200)
    const list = (await listRes.json()) as { items?: Array<{ ext_id: string }>; tickets?: Array<{ ext_id: string }> }
    const victim = (list.items ?? list.tickets ?? [])[0]
    assert.ok(victim?.ext_id, 'persona_b must own at least one ticket')

    const assignPath = buildPath(app.plan, 'ticketAssign', { ticketId: victim.ext_id })
    const readPath = buildPath(app.plan, 'ticketGet', { ticketId: victim.ext_id })
    const before = (await (await owner.fetch(readPath)).json()) as { assignee_id?: string }

    const anonRes = await anon.fetch(assignPath, {
      method: 'POST', headers: { 'content-type': 'application/json' }, body: '{}',
    })
    assert.equal(anonRes.status, 401, 'anonymous is denied by authentication, not authorization')

    // The viewer is in a different tenant; the assignee defaults to the acting user, so the
    // assignee-team gate passes and only the missing target-team check (the planted bug) bites.
    const write = await viewer.fetch(assignPath, {
      method: 'POST', headers: { 'content-type': 'application/json' }, body: '{}',
    })
    assert.equal(write.status, 200, 'og.ticket-assign-cross-write must remain exploitable')

    const after = (await (await owner.fetch(readPath)).json()) as { assignee_id?: string }
    assert.notEqual(after.assignee_id, before.assignee_id, 'the foreign ticket was actually mutated')

    // The same route is a ground-truth target: hardening it would drop recall for a planted site.
    const claim = finding({
      id: 'agent-fp-triage-assign-planted',
      title: 'Cross-tenant ticket assignment (idor)',
      endpoints: [{ method: 'POST', path: assignPath }],
      vulnClass: 'idor',
      cwe: 'CWE-639',
    })
    const matched = matchFindingToEntries(claim, entriesFor('opsportal').entries)
    assert.equal(matched?.entry.siteId, 'og.ticket-assign-cross-write')
  } finally {
    await app.stop()
  }
})

test('opsportal: GET /api/me is target-free; CWE-269 on the assign route is a sibling, not recall', () => {
  const { plan, entries } = entriesFor('opsportal')
  const meClaim = finding({
    id: 'agent-fp-triage-me-route',
    title: 'Cross-tenant BFLA declared on GET /api/me',
    endpoints: [{ method: 'GET', path: plan.routes['me']!.path }],
    cwe: 'CWE-269',
  })
  assert.equal(matchFindingToEntries(meClaim, entries), null, 'the claim-declared route is not a target')

  const target = entries.find(e => e.entry.siteId === 'og.ticket-assign-cross-write')
  assert.ok(target && !target.isDecoy, 'the assign route is a planted vulnerable entry')
  const siblingClaim = finding({
    id: 'agent-fp-triage-assign-cwe269',
    title: 'Cross-tenant BFLA: viewer reassigns another tenant support case',
    endpoints: [{ method: 'POST', path: buildPath(plan, 'ticketAssign', { ticketId: 'x' }) }],
    cwe: 'CWE-269',
  })
  // A sibling label earns no recall (matchFindingToEntries is class-compatible only)…
  assert.equal(matchFindingToEntries(siblingClaim, entries), null)
  // …and the documented sibling tolerance is what keeps it out of the loose `precision` denominator.
  assert.equal(classCompatible(siblingClaim, target.entry), false)
  assert.equal(siblingClassPair(siblingClaim, target.entry), true, 'CWE-269/idor is a documented sibling pair')
})

// ---------------------------------------------------------------------------------------------
// Ruling 2b: the settings document is fixed-schema; an unknown/protected-looking key is rejected.
// ---------------------------------------------------------------------------------------------

test('shopflow: settings accepts only known config keys and merges them', async () => {
  const app = await startRealisticApp({ app: 'shopflow', seed: 1 })
  try {
    const owner = makeSolverCtx(app.origin, app.plan)
    await owner.login('persona_a')
    const path = buildPath(app.plan, 'updateSettings')

    const unknown = await owner.fetch(path, {
      method: 'PATCH', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ settings: { role: 'store-owner-canary' } }),
    })
    assert.equal(unknown.status, 400, 'a security-looking key inside the config document is rejected')

    const known = await owner.fetch(path, {
      method: 'PATCH', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ settings: { theme: 'dark' } }),
    })
    assert.equal(known.status, 200, 'an allow-listed key is accepted')

    const read = await owner.fetch(buildPath(app.plan, 'getSettings'))
    const body = (await read.json()) as { settings?: Record<string, unknown> }
    assert.equal(body.settings?.['theme'], 'dark', 'the accepted key persisted')
    assert.ok(!('role' in (body.settings ?? {})), 'the rejected key never persisted')
    assert.ok('currency' in (body.settings ?? {}), 'omitted keys survive the merge (no wholesale replace)')
  } finally {
    await app.stop()
  }
})

// ---------------------------------------------------------------------------------------------
// Ruling 3: the log-filter 500 is the planted SQLi choking, not an input-validation bug.
// ---------------------------------------------------------------------------------------------

test('opsportal: log filter interpolation stays exploitable (a 500 on a value is its symptom)', async () => {
  const app = await bootForcedOpsportal()
  try {
    const admin = makeClient(app.origin, app.plan)
    await admin.login('persona_a')
    const field = app.plan.params['filterExpr'] ?? 'filter'
    const post = async (value: string) => {
      const res = await admin.fetch(app.plan.routes['logFilter']!.path, {
        method: 'POST', headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ [field]: value }),
      })
      const body = (await res.json().catch(() => ({}))) as { items?: unknown[] }
      return { status: res.status, items: body.items?.length ?? 0 }
    }

    const inRange = await post('0')
    assert.equal(inRange.status, 200)
    assert.ok(inRange.items >= 1, 'the control threshold returns the caller team rows')

    const outOfRange = await post('999999')
    assert.equal(outOfRange.status, 200)
    assert.equal(outOfRange.items, 0, 'a high threshold returns nothing')

    // The tautology is appended to the interpolated predicate, so the high threshold no longer binds.
    const injected = await post('999999 OR 1=1')
    assert.equal(injected.status, 200)
    assert.ok(injected.items > outOfRange.items, 'og.log-filter-sqli stays exploitable')

    // A non-numeric value reaches the interpolated expression and raises the planted unhandled error.
    // Turning this into a 400 would be "fixing" the planted sqli and is explicitly not done here.
    const nonNumeric = await post('level=error')
    assert.equal(nonNumeric.status, 500)

    const { entries } = entriesFor('opsportal')
    const sqliTarget = entries.find(e => e.entry.siteId === 'og.log-filter-sqli')
    assert.ok(sqliTarget && !sqliTarget.isDecoy, 'the sqli target stays planted')
    const inputValidationClaim = finding({
      id: 'agent-fp-triage-logfilter-input',
      title: 'Filter value raises an unhandled 500 (input validation)',
      endpoints: [{ method: 'POST', path: app.plan.routes['logFilter']!.path }],
      vulnClass: 'injection-input',
      cwe: 'CWE-20',
    })
    assert.equal(matchFindingToEntries(inputValidationClaim, entries), null,
      'a CWE-20/input-validation claim is not the sqli target: no recall, charged as a false positive')
  } finally {
    await app.stop()
  }
})
