/**
 * v7 proof obligation: route-scoped gaps, not one global counter.
 *
 * Conversion autopsy (plans/CONVERSION-AUTOPSY.md, 24/52 missed targets in `route_hit_no_verify`):
 * a single global `codedProofGaps` counter let one `record_coverage` gap discharge the settlement
 * obligation for every probed route. These tests pin the replacement contract:
 *
 *  1. each probed route family owes its own spec/verify result or coded gap;
 *  2. a gap bound to route A never discharges route B;
 *  3. one route-scoped gap per route is idempotent;
 *  4. the reserved wrap-up turn targets the highest-value uncovered route (anomaly/2xx first);
 *  5. a fully covered assignment is unchanged;
 *  6. a coded gap without a route key is rejected and names the exact missing field;
 *  7. assignment (Tier-A/chain) targets owe proof even when never probed.
 */
import assert from 'node:assert/strict'
import { test } from 'node:test'

import {
  SpecSubmissionTracker,
  buildWorkerTools,
  proofRouteKey,
  settlementSpecDirective,
  specSubmissionPending,
  type ProofObligationStats,
  type SpecRouteEvidence,
} from '../src/server/agent-session.ts'

const ORIGIN = 'https://proof.gap.route.test'
const ADMIN = { method: 'POST', path: '/api/admin/9001' } as const
const ORDER = { method: 'GET', path: '/api/orders/1001' } as const
const ADMIN_KEY = 'POST /api/admin/:id'
const ORDER_KEY = 'GET /api/orders/:id'

type InvokeResult = { output?: readonly { type: string; text?: string }[]; isError?: boolean }

function toolByName(tools: ReturnType<typeof buildWorkerTools>, name: string) {
  return tools.find(tool => tool.name === name)
}

async function invoke(tool: NonNullable<ReturnType<typeof toolByName>>, args: Record<string, unknown>): Promise<InvokeResult> {
  return tool.execute(args as never, {} as never, { abortSignal: AbortSignal.timeout(5_000) } as never) as Promise<InvokeResult>
}

function textOf(result: InvokeResult): string {
  return (result.output ?? []).map(part => part.text ?? '').join('\n')
}

/** Worker surface with two route families: an anomalous 5xx admin route and a benign 2xx order. */
function fixture(options?: {
  routes?: ReadonlyArray<{ method: string; path: string; result: unknown }>
}) {
  const routes = options?.routes ?? [
    { method: ADMIN.method, path: ADMIN.path, result: { status: 500, anomalies: ['status-diff'], bodySha256: 'sha-admin' } },
    { method: ORDER.method, path: ORDER.path, result: { status: 200, bodySha256: 'sha-order' } },
  ]
  const tracker = new SpecSubmissionTracker()
  const coverage: Array<Record<string, unknown>> = []
  const required: Array<{ status: string; count: number; route?: SpecRouteEvidence }> = []
  const completions: Array<{ status: string; summary: string }> = []
  const tools = buildWorkerTools({
    request_http: async args => {
      const hit = routes.find(route => route.method === args.method && args.pathAndQuery.split(/[?#]/, 1)[0] === route.path)
      return hit?.result ?? { status: 200 }
    },
    verify_replay_spec: async () => ({ oraclePassed: true, attempts: [] }),
    guardian_verify: async () => ({ oraclePassed: true, attempts: [] }),
    record_coverage: async args => {
      coverage.push(args as unknown as Record<string, unknown>)
      return { id: `cov-${coverage.length}`, status: args.status }
    },
    complete_intent: async completion => {
      completions.push(completion)
      return { recorded: true }
    },
  }, value => value, AbortSignal.timeout(5_000), 24 * 1024, () => {}, {
    tracker,
    onRequired: info => { required.push(info) },
  })
  return { tracker, coverage, required, completions, tools }
}

async function probe(tools: ReturnType<typeof buildWorkerTools>, route: { method: string; path: string }) {
  const result = await invoke(toolByName(tools, 'request_http')!, {
    origin: ORIGIN,
    method: route.method,
    pathAndQuery: route.path,
  })
  assert.notEqual(result.isError, true, `the fixture probe succeeds for ${route.method} ${route.path}`)
}

function gap(route: string, reason = 'no_authenticated_persona: no second tenant session was available') {
  return {
    origin: ORIGIN,
    category: 'broken-access-control',
    status: 'needs_follow_up',
    summary: 'Cross-tenant proof needs a second persona.',
    proofGapReason: reason,
    route,
  }
}

function specFor(method: string, path: string) {
  return {
    version: 1,
    origin: ORIGIN,
    title: 'Cross-boundary differential',
    category: 'injection',
    cwe: 'CWE-639',
    severity: 'high',
    severityRationale: 'Control and probe differ consistently.',
    impact: 'An attacker can read another tenant object.',
    remediation: 'Bind the object to the caller.',
    recheckInstructions: 'Replay the same control/probe pair.',
    assertionsJq: '.probe.status == 200',
    steps: [
      { id: 'control', role: 'control', description: 'Owner baseline', request: { origin: ORIGIN, method, pathAndQuery: '/api/control' } },
      { id: 'probe', role: 'probe', description: 'Cross-tenant probe', request: { origin: ORIGIN, method, pathAndQuery: path } },
    ],
  }
}

function statsOf(tracker: SpecSubmissionTracker): ProofObligationStats {
  return tracker.snapshot().obligation
}

// ============================================================================
// 1. Per-route obligation: a gap on A never discharges B
// ============================================================================

test('a gap on route A leaves route B demanded; a second route-bound gap discharges it', async () => {
  const { tracker, coverage, required, completions, tools } = fixture()
  await probe(tools, ADMIN)
  await probe(tools, ORDER)

  const initial = tracker.snapshot()
  assert.equal(initial.obligations.length, 2, 'two probed route families owe proof')
  assert.deepEqual(initial.obligations.map(obligation => obligation.key).sort(), [ADMIN_KEY, ORDER_KEY].sort())
  assert.equal(specSubmissionPending(initial), true)
  assert.deepEqual(statsOf(tracker), {
    probedRoutes: 2, coveredRoutes: 0, gapRoutes: 0, demandedRoutes: 0, dischargedByGap: 0,
  })

  // Gap on the benign order route only.
  const first = await invoke(toolByName(tools, 'record_coverage')!, gap(ORDER.path))
  assert.notEqual(first.isError, true)
  assert.equal(coverage.length, 1)
  assert.match(String(coverage[0]!.proofGapReason), /^no_authenticated_persona:.*\[route=GET \/api\/orders\/:id\]$/,
    'the persisted coverage entry carries the normalized route binding')
  const afterFirst = tracker.snapshot()
  assert.equal(afterFirst.proofGaps.length, 1)
  assert.equal(afterFirst.proofGaps[0]!.route, ORDER_KEY, 'the gap entry carries the route key')
  assert.equal(afterFirst.obligations.find(obligation => obligation.key === ORDER_KEY)!.gap, 'no_authenticated_persona')
  assert.equal(afterFirst.obligations.find(obligation => obligation.key === ADMIN_KEY)!.gap, undefined)
  assert.equal(specSubmissionPending(afterFirst), true, 'the admin route still owes proof')

  // complete_intent names the highest-value uncovered route, not the route that was last probed.
  const rejected = await invoke(toolByName(tools, 'complete_intent')!, { status: 'proved', summary: 'Admin write is likely BOLA.' })
  assert.equal(rejected.isError, true)
  assert.ok(textOf(rejected).includes('POST /api/admin/9001'), 'the anomalous route is demanded')
  assert.equal(required.length, 1)
  assert.deepEqual(required[0]!.route, { method: 'POST', path: '/api/admin/9001', params: [], origin: ORIGIN })
  assert.equal(completions.length, 0)

  // A second gap bound to the admin route closes the remaining obligation.
  const second = await invoke(toolByName(tools, 'record_coverage')!, gap(ADMIN.path, 'baseline_empty: the admin route returned no stable baseline'))
  assert.notEqual(second.isError, true)
  const done = tracker.snapshot()
  assert.equal(specSubmissionPending(done), false, 'one gap per route discharges both routes')
  assert.deepEqual(statsOf(tracker), {
    probedRoutes: 2, coveredRoutes: 0, gapRoutes: 2, demandedRoutes: 1, dischargedByGap: 2,
  })
  const accepted = await invoke(toolByName(tools, 'complete_intent')!, { status: 'proved', summary: 'Recorded route-scoped gaps.' })
  assert.notEqual(accepted.isError, true)
  assert.equal(completions.length, 1)
})

test('two probed routes with one route-bound gap each are both discharged', () => {
  const tracker = new SpecSubmissionTracker()
  tracker.noteRoute({ method: ADMIN.method, pathAndQuery: ADMIN.path })
  tracker.noteObservation({ method: ADMIN.method, pathAndQuery: ADMIN.path, status: 500, anomaly: true })
  tracker.noteRoute({ method: ORDER.method, pathAndQuery: ORDER.path })
  tracker.noteObservation({ method: ORDER.method, pathAndQuery: ORDER.path, status: 200 })

  assert.equal(tracker.noteProofGap({ proofGapReason: 'tier_blocked: admin mutation needs Tier 3 approval', route: ADMIN.path }).ok, true)
  assert.equal(specSubmissionPending(tracker.snapshot()), true, 'the order route is still open')
  assert.equal(tracker.noteProofGap({ proofGapReason: 'no_reproducible_signal: order read is consistently 403', route: ORDER.path }).ok, true)

  const snapshot = tracker.snapshot()
  assert.equal(specSubmissionPending(snapshot), false)
  assert.deepEqual(new Set(snapshot.proofGaps.map(entry => entry.route)), new Set([ADMIN_KEY, ORDER_KEY]))
  assert.deepEqual(statsOf(tracker), {
    probedRoutes: 2, coveredRoutes: 0, gapRoutes: 2, demandedRoutes: 0, dischargedByGap: 2,
  })
})

// ============================================================================
// 2. Cost bound: a repeated gap for the same route is idempotent
// ============================================================================

test('a repeated route-scoped gap is idempotent (no array or counter growth)', () => {
  const tracker = new SpecSubmissionTracker()
  tracker.noteObservation({ method: ORDER.method, pathAndQuery: ORDER.path, status: 200 })
  const reason = 'runtime_unavailable: local-lab runtime is not mounted for this route'

  assert.equal(tracker.noteProofGap({ proofGapReason: reason, route: ORDER.path }).ok, true)
  assert.equal(tracker.noteProofGap({ proofGapReason: reason, route: ORDER.path }).ok, true)
  assert.equal(tracker.noteProofGap({ proofGapReason: reason, route: ORDER_KEY }).ok, true)

  const snapshot = tracker.snapshot()
  assert.equal(snapshot.proofGaps.length, 1, 'only one entry per route')
  assert.equal(snapshot.codedProofGaps, 1, 'the legacy counter cannot inflate')
  assert.equal(snapshot.required, 0, 'no demand loop was created')
  assert.deepEqual(statsOf(tracker), {
    probedRoutes: 1, coveredRoutes: 0, gapRoutes: 1, demandedRoutes: 0, dischargedByGap: 1,
  })
})

// ============================================================================
// 3. Wrap-up targets the highest-value uncovered route
// ============================================================================

test('the reserved wrap-up turn targets the anomalous route even when a benign route was probed last', () => {
  const tracker = new SpecSubmissionTracker()
  // Anomalous route first; benign 2xx route last.
  tracker.noteObservation({ method: ADMIN.method, pathAndQuery: ADMIN.path, status: 500, anomaly: true })
  tracker.noteObservation({ method: ORDER.method, pathAndQuery: ORDER.path, status: 200 })

  const snapshot = tracker.snapshot()
  const target = snapshot.obligationTarget!
  assert.equal(target.method, 'POST')
  assert.equal(target.path, '/api/admin/9001')
  assert.deepEqual(target.params, [])
  assert.equal(proofRouteKey(target.method, target.path), ADMIN_KEY)

  const directive = settlementSpecDirective(target)
  assert.ok(directive.includes('POST /api/admin/9001'), 'the directive names the anomalous route')
  assert.ok(directive.includes(`route="POST /api/admin/9001"`), 'the directive names the route-scoped gap binding')
  assert.doesNotMatch(directive, /GET \/api\/orders\/1001/, 'the benign last-probed route is not the target')
})

// ============================================================================
// 4. A fully covered assignment is unchanged
// ============================================================================

test('a route covered by a submitted verify spec needs no gap and no extra demand', async () => {
  const { tracker, required, completions, tools } = fixture()
  await probe(tools, ORDER)

  const verify = await invoke(toolByName(tools, 'verify_replay_spec')!, { spec: specFor(ORDER.method, ORDER.path) })
  assert.notEqual(verify.isError, true)
  const snapshot = tracker.snapshot()
  assert.equal(snapshot.targetCovered, true)
  assert.equal(specSubmissionPending(snapshot), false)
  assert.deepEqual(statsOf(tracker), {
    probedRoutes: 1, coveredRoutes: 1, gapRoutes: 0, demandedRoutes: 0, dischargedByGap: 0,
  })

  const accepted = await invoke(toolByName(tools, 'complete_intent')!, { status: 'proved', summary: 'Verified.' })
  assert.notEqual(accepted.isError, true)
  assert.equal(completions.length, 1)
  assert.equal(required.length, 0, 'a covered route is never demanded')
})

// ============================================================================
// 5. A coded gap without a route key is rejected with the exact missing field
// ============================================================================

test('a coded gap without a route key is rejected with the exact missing field when binding is ambiguous', async () => {
  const { tracker, coverage, tools } = fixture()
  await probe(tools, ADMIN)
  await probe(tools, ORDER)

  const rejected = await invoke(toolByName(tools, 'record_coverage')!, {
    origin: ORIGIN,
    category: 'broken-access-control',
    status: 'needs_follow_up',
    summary: 'Needs a persona.',
    proofGapReason: 'no_authenticated_persona: no second session was available',
  })
  assert.equal(rejected.isError, true)
  const text = textOf(rejected)
  assert.match(text, /missing required field `route`/i, 'the exact missing field is named')
  assert.ok(text.includes(ADMIN_KEY) && text.includes(ORDER_KEY), 'the rejection lists the probed routes')
  assert.equal(coverage.length, 0, 'nothing was persisted without a route binding')
  assert.equal(tracker.snapshot().codedProofGaps, 0)
  assert.equal(specSubmissionPending(tracker.snapshot()), true)

  // Ambiguous auto-binding is rejected; an explicit route is accepted.
  const routed = await invoke(toolByName(tools, 'record_coverage')!, gap(ORDER.path))
  assert.notEqual(routed.isError, true)
  assert.equal(coverage.length, 1)
  assert.equal(tracker.snapshot().proofGaps[0]!.route, ORDER_KEY)
})

test('a single probed route may bind a coded gap implicitly (unambiguous target)', async () => {
  const tracker = new SpecSubmissionTracker()
  tracker.noteObservation({ method: ORDER.method, pathAndQuery: ORDER.path, status: 200 })
  assert.equal(tracker.noteProofGap({ proofGapReason: 'no_spec_shape: one route, one inferred binding' }).ok, true)
  assert.equal(tracker.snapshot().proofGaps[0]!.route, ORDER_KEY)
  assert.equal(specSubmissionPending(tracker.snapshot()), false)
})

// ============================================================================
// 6. Assigned (Tier-A/chain) targets owe proof even when never probed
// ============================================================================

test('an assigned target route owes its own proof even when the worker never probes it', () => {
  const tracker = new SpecSubmissionTracker()
  tracker.noteAssignedRoutes([{ method: 'POST', path: '/api/payouts' }])
  const assignedKey = 'POST /api/payouts'

  assert.equal(specSubmissionPending(tracker.snapshot()), true, 'an assigned route is an obligation')
  tracker.noteObservation({ method: ORDER.method, pathAndQuery: ORDER.path, status: 200 })
  assert.deepEqual(statsOf(tracker), {
    probedRoutes: 1, coveredRoutes: 0, gapRoutes: 0, demandedRoutes: 0, dischargedByGap: 0,
  })

  const rejected = tracker.noteProofGap({ proofGapReason: 'tier_blocked: payout needs Tier 3 approval' })
  assert.equal(rejected.ok, false, 'two uncovered routes make the binding ambiguous')
  assert.match(rejected.ok ? '' : rejected.error, /missing required field `route`/i)

  assert.equal(tracker.noteProofGap({ proofGapReason: 'tier_blocked: payout needs Tier 3 approval', route: '/api/payouts' }).ok, true)
  assert.equal(specSubmissionPending(tracker.snapshot()), true, 'the probed order route is still open')
  assert.equal(tracker.noteProofGap({ proofGapReason: 'baseline_empty: order read has no baseline', route: ORDER.path }).ok, true)
  assert.equal(specSubmissionPending(tracker.snapshot()), false)
  assert.equal(tracker.snapshot().proofGaps.some(entry => entry.route === assignedKey), true)
})
