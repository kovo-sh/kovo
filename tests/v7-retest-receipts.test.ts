/**
 * v7 M0 — retest receipts (Cut 3 retest migration).
 *
 * A proof confirmed by a typed floor recipe persists `{ recipeId, args }` on its spec record, so a
 * retest re-runs that recipe and is judged by a fresh `verifyReceipt()` — not by re-interpreting the
 * legacy declarative shape. These tests pin:
 *   1. the envelope survives the persisted-spec schema,
 *   2. retest reproduces a still-vulnerable fixture and reports fixed after hardening,
 *   3. the declarative `assertionsJq` is NOT consulted for a recipe-owned proof (proves the legacy
 *      branch is bypassed),
 *   4. a spec without an envelope still retests through the legacy replay (agent-authored proofs).
 */
import assert from 'node:assert/strict'
import { createServer } from 'node:http'
import { once } from 'node:events'
import test from 'node:test'
import type { DeclarativeReplaySpec } from '../src/replay-spec.ts'
import { declarativeReplaySpecSchema } from '../src/replay-spec.ts'
import { RequestBroker } from '../src/server/broker.ts'
import { floorRecipe, runFloorRecipe, brokerFloorRecipeDeps } from '../src/server/floor-recipes.ts'
import type { BooleanOrTimingArgs } from '../src/server/floor-recipes.ts'
import type { FloorRecipePlan } from '../src/server/floor-recipe-engine.ts'
import { recipeSpecRecord, retestPersistedRecipe } from '../src/server/floor-recipe-engine.ts'
import { retestReplaySpec } from '../src/server/replay-verifier.ts'
import { LocalJqBackend } from '../scripts/benchmark-backend.ts'
import { makeLabGrant } from './v4-tier-helpers.ts'

process.env.KOVO_ALLOW_LOCAL_LAB = '1'

interface Fixture {
  origin: string
  /** When true the injected predicate no longer separates (the "patched" fixture). */
  hardened: boolean
  close: () => Promise<void>
}

async function startBooleanFixture(): Promise<Fixture> {
  const state = { hardened: false }
  const server = createServer((req, res) => {
    const url = new URL(req.url ?? '/', 'http://127.0.0.1')
    if (url.pathname !== '/api/search') {
      res.statusCode = 404
      res.end('{}')
      return
    }
    const q = url.searchParams.get('q') ?? ''
    res.setHeader('content-type', 'application/json')
    // The vulnerable predicate (`AND 1=2`) empties the row set; the patched fixture parameterises
    // the query so the same injected text is treated as data and returns the baseline rows.
    const injected = /AND\s+1\s*=\s*2/i.test(q)
    const rows = injected && !state.hardened ? [] : [{ id: 1, title: 'widget' }]
    res.end(JSON.stringify({ rows }))
  })
  server.listen(0, '127.0.0.1')
  await once(server, 'listening')
  const port = (server.address() as { port: number }).port
  return {
    origin: `http://127.0.0.1:${port}`,
    get hardened() { return state.hardened },
    set hardened(value: boolean) { state.hardened = value },
    close: async () => {
      server.closeAllConnections()
      await new Promise<void>(resolve => server.close(() => resolve()))
    },
  } as Fixture
}

test('v7 retest receipts: a recipe-confirmed spec persists its recipe envelope', async (t) => {
  const fixture = await startBooleanFixture()
  t.after(() => fixture.close())
  const origin = fixture.origin
  const grant = makeLabGrant(origin, { tier: 3 })
  const broker = new RequestBroker({ rejectUnauthorized: false })
  const signal = AbortSignal.timeout(20_000)
  const args: BooleanOrTimingArgs = {
    origin,
    method: 'GET',
    pathAndQuery: '/api/search?q=widget',
    controlPathAndQuery: '/api/search?q=widget',
    probePathAndQuery: `/api/search?q=${encodeURIComponent("widget' AND 1=2-- -")}`,
    param: 'q',
    vulnClass: 'sqli',
    mode: 'boolean',
    rounds: 2,
  }
  const execution = await runFloorRecipe(floorRecipe('boolean_or_timing', args), brokerFloorRecipeDeps({ broker, grant, signal, origin }))
  assert.equal(execution.result.confirmed, true, execution.failure?.message ?? execution.result.verification.reason)

  const plan: FloorRecipePlan = { recipeId: 'boolean_or_timing', specKind: 'sql_boolean_diff', vulnClass: 'sqli', endpoint: '/api/search', args }
  const record = recipeSpecRecord(plan, execution)
  const parsed = declarativeReplaySpecSchema.safeParse(record.spec)
  assert.equal(parsed.success, true, parsed.success ? '' : JSON.stringify(parsed.error.issues))
  if (!parsed.success) return
  assert.equal(parsed.data.recipe?.recipeId, 'boolean_or_timing')
  assert.deepEqual(parsed.data.recipe?.args.probePathAndQuery, args.probePathAndQuery)
  assert.equal(parsed.data.recipe?.args.vulnClass, 'sqli')
})

test('v7 retest receipts: retest re-runs the recipe and never consults the declarative assertion', async (t) => {
  const fixture = await startBooleanFixture()
  t.after(() => fixture.close())
  const origin = fixture.origin
  const grant = makeLabGrant(origin, { tier: 3 })
  const broker = new RequestBroker({ rejectUnauthorized: false })
  const backend = new LocalJqBackend()
  const signal = AbortSignal.timeout(20_000)
  const args: BooleanOrTimingArgs = {
    origin,
    method: 'GET',
    pathAndQuery: '/api/search?q=widget',
    controlPathAndQuery: '/api/search?q=widget',
    probePathAndQuery: `/api/search?q=${encodeURIComponent("widget' AND 1=2-- -")}`,
    param: 'q',
    vulnClass: 'sqli',
    mode: 'boolean',
    rounds: 2,
  }
  const execution = await runFloorRecipe(floorRecipe('boolean_or_timing', args), brokerFloorRecipeDeps({ broker, grant, signal, origin }))
  assert.equal(execution.result.confirmed, true, execution.failure?.message ?? execution.result.verification.reason)
  const plan: FloorRecipePlan = { recipeId: 'boolean_or_timing', specKind: 'sql_boolean_diff', vulnClass: 'sqli', endpoint: '/api/search', args }
  const record = recipeSpecRecord(plan, execution)
  // A deliberately false assertion proves retest does not fall back to the legacy replay verdict.
  const spec = { ...record.spec, assertionsJq: '{ controlPassed: false, confirmed: false, observed: "legacy assertion must not run", expected: "never" }' } as unknown as DeclarativeReplaySpec

  const before = await retestReplaySpec({ spec, broker, backend, grant, signal })
  assert.equal(before.verdict, 'reproduced', before.replay.outcome.reason ?? 'no reason')
  assert.equal(before.replay.receipt?.verification.confirmed, true)
  assert.equal(before.replay.receipt?.receipt.exchangeIds.length, 4, 'two paired boolean rounds make four exchanges')

  fixture.hardened = true
  const after = await retestReplaySpec({ spec, broker, backend, grant, signal })
  assert.equal(after.verdict, 'fixed', after.replay.outcome.reason ?? 'no reason')
  assert.notEqual(after.replay.receipt?.verification.confirmed, true)
})

test('v7 retest receipts: a recipe that cannot execute is inconclusive, never falsely fixed', async (t) => {
  const fixture = await startBooleanFixture()
  t.after(() => fixture.close())
  const origin = fixture.origin
  const grant = makeLabGrant(origin, { tier: 3 })
  const broker = new RequestBroker({ rejectUnauthorized: false })
  const args: BooleanOrTimingArgs = {
    origin,
    method: 'GET',
    pathAndQuery: '/api/search?q=widget',
    controlPathAndQuery: '/api/search?q=widget',
    probePathAndQuery: `/api/search?q=${encodeURIComponent("widget' AND 1=2-- -")}`,
    param: 'q',
    vulnClass: 'sqli',
    mode: 'boolean',
    rounds: 2,
  }
  const result = await retestPersistedRecipe({
    envelope: { recipeId: 'boolean_or_timing', args: args as unknown as Record<string, unknown> },
    specKind: 'sql_boolean_diff',
    vulnClass: 'sqli',
    endpoint: '/api/search',
    origin,
    broker,
    grant,
    signal: AbortSignal.abort(),
  })
  assert.equal(result.verdict, 'inconclusive', result.replay.outcome.reason ?? 'no reason')
})

test('v7 retest receipts: an agent spec without an envelope still retests through the legacy replay', async (t) => {
  let state = { owner_id: 'u1' }
  let patched = false
  const server = createServer((req, res) => {
    res.setHeader('content-type', 'application/json')
    if (req.method === 'GET' && req.url === '/api/invoices/42') {
      res.end(JSON.stringify(state))
      return
    }
    if (req.method === 'PATCH' && req.url === '/api/invoices/42') {
      let body = ''
      req.on('data', chunk => { body += chunk })
      req.on('end', () => {
        try {
          const next = JSON.parse(body) as Record<string, unknown>
          // The patched build binds owner changes to an authorized workflow transition.
          state = { ...state, ...(patched ? {} : next) }
        } catch { /* ignore */ }
        res.end(JSON.stringify(state))
      })
      return
    }
    res.statusCode = 404
    res.end('{}')
  })
  server.listen(0, '127.0.0.1')
  await once(server, 'listening')
  const port = (server.address() as { port: number }).port
  t.after(async () => {
    server.closeAllConnections()
    await new Promise<void>(resolve => server.close(() => resolve()))
  })
  const origin = `http://127.0.0.1:${port}`
  const spec = {
    version: 1,
    kind: 'http_chain',
    origin,
    title: 'Business logic owner reassignment',
    category: 'business-logic-race',
    cwe: 'CWE-840',
    severity: 'high',
    severityRationale: 'An owner field moves outside the workflow rules.',
    impact: 'A caller reassigns the object owner and the change persists.',
    remediation: 'Bind owner changes to an authorized workflow transition.',
    recheckInstructions: 'Replay the before/write/after chain after the patch.',
    assertionsJq: '{ controlPassed: (.steps.a1.json.owner_id == "u2"), confirmed: (.steps.a1.json.owner_id == "u2"), observed: ("owner=" + (.steps.a1.json.owner_id | tostring)), expected: "owner=u1" }',
    expectedImpactEvents: ['invariant_violation'],
    steps: [
      { id: 'b1', role: 'control', description: 'Read before', expectedStatus: 200, request: { origin, method: 'GET', pathAndQuery: '/api/invoices/42', followRedirects: false } },
      { id: 'p1', role: 'probe', description: 'Reassign owner', expectedStatus: 200, request: { origin, method: 'PATCH', pathAndQuery: '/api/invoices/42', jsonBody: { owner_id: 'u2' }, followRedirects: false } },
      { id: 'a1', role: 'control', description: 'Read after', expectedStatus: 200, request: { origin, method: 'GET', pathAndQuery: '/api/invoices/42', followRedirects: false } },
    ],
  } as unknown as DeclarativeReplaySpec
  const params = {
    spec,
    broker: new RequestBroker({ rejectUnauthorized: false }),
    backend: new LocalJqBackend(),
    grant: makeLabGrant(origin, { tier: 3 }),
    signal: AbortSignal.timeout(20_000),
  }
  const before = await retestReplaySpec(params)
  assert.equal(before.verdict, 'reproduced', before.replay.outcome.reason ?? 'no reason')
  patched = true
  state = { owner_id: 'u1' }
  const after = await retestReplaySpec(params)
  // The legacy branch is only kept for agent-authored specs; on a hardened fixture it may report
  // `inconclusive` instead of `fixed` (the recipe path is the precise reproduced/fixed oracle).
  assert.notEqual(after.verdict, 'reproduced', after.replay.outcome.reason ?? 'no reason')
})
