/**
 * v7 M5 throughput: early-exit settlement on clearly clean/hardened routes.
 *
 * The single-step budget was raised 12→18 turns / 80→120 s because 78.9% of held-out no-spec
 * targets were cap-truncated. The accepted cost is a higher assignment p50. The remedy here is not
 * a lower ceiling: when the target route is *provably* hardened, settlement starts at turn 5-6
 * instead of burning turns 7-18. These tests pin the evidence contract, not a vibe:
 *
 *  1. two distinct denial attempts on distinct paths/params earn `hardened_denial` (event + stat);
 *  2. a route with an anomaly never early-exits;
 *  3. a pending spec submission, an in-flight repair, and an uncoded proof gap all block the exit;
 *  4. the stat counts saved turns and the effective final turn reserves the wrap-up verify turn;
 *  5. the exit still demands one spec or coded gap — a coded gap closes the obligation with zero
 *     complete_intent rejections (no demand loop), and probe/analysis tools stay revoked.
 *
 * Fixtures are generic/synthetic: no benchmark/app/route/seed literals.
 */
import assert from 'node:assert/strict'
import { test } from 'node:test'

import {
  EARLY_EXIT_GRACE_TURNS,
  EARLY_EXIT_MIN_TURNS,
  SpecSubmissionTracker,
  buildEarlyExitEvent,
  buildWorkerTools,
  earlyExitDirectiveMessage,
  earlyExitEligible,
  earlyExitTurnsSaved,
  settlementToolBlock,
  specSubmissionPending,
  type EarlyExitBlock,
  type SpecRouteEvidence,
} from '../src/server/agent-session.ts'

const ORIGIN = 'https://hardened.route.test'
const MAX_TURNS = 18

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

/** Worker surface with a denial-shaped target route, verify, coverage and complete_intent spies. */
function fixture(options?: {
  http?: (args: { method: string; pathAndQuery: string }) => unknown
  differential?: unknown
  verify?: () => unknown
}) {
  const tracker = new SpecSubmissionTracker()
  const completions: Array<{ status: string; summary: string }> = []
  const required: Array<{ status: string; count: number }> = []
  const tools = buildWorkerTools({
    request_http: async args => options?.http?.(args) ?? { exchangeId: 'ex-1', status: 403, bodySha256: 'sha-denied' },
    ...(options?.differential ? { probe_differential: async () => options.differential } : {}),
    kovo_verify: async () => options?.verify?.() ?? { oraclePassed: false, attempts: [] },
    record_coverage: async args => ({ id: 'cov-1', status: args.status }),
    complete_intent: async completion => {
      completions.push(completion)
      return { recorded: true }
    },
  }, value => value, AbortSignal.timeout(5_000), 24 * 1024, () => {}, {
    tracker,
    onRequired: info => { required.push({ status: info.status, count: info.count }) },
  })
  return { tracker, completions, required, tools }
}

async function probe(tools: ReturnType<typeof buildWorkerTools>, method: string, pathAndQuery: string) {
  const result = await invoke(toolByName(tools, 'request_http')!, { origin: ORIGIN, method, pathAndQuery })
  assert.notEqual(result.isError, true, 'the fixture probe succeeds')
}

function decisionFor(tracker: SpecSubmissionTracker, overrides: Partial<Parameters<typeof earlyExitEligible>[0]> = {}) {
  return earlyExitEligible({
    evidence: tracker.observationSnapshot(),
    turnsUsed: 6,
    maxTurns: MAX_TURNS,
    ...overrides,
  })
}

// ============================================================================
// 1. A hardened route with two distinct denial attempts exits early
// ============================================================================

test('two denial attempts on distinct params earn hardened_denial with a structured event and stat', async () => {
  const { tracker, tools } = fixture()
  await probe(tools, 'GET', '/api/invoices/1001?tenant=alpha')
  await probe(tools, 'GET', '/api/invoices/1002?tenant=beta')

  const snapshot = tracker.observationSnapshot()
  assert.equal(snapshot.attempts, 2)
  assert.equal(snapshot.distinctAttempts, 2, 'two distinct resource ids')
  assert.equal(snapshot.distinctPaths, 2, 'two resource ids, one route family')
  assert.deepEqual(snapshot.routes.map(route => route.family), ['/api/invoices/:id'], 'ids normalize to one family')
  assert.deepEqual([...snapshot.denialStatuses], [403, 403], 'both attempts answered the hardened denial')
  assert.equal(snapshot.anomalyCount, 0)

  const decision = decisionFor(tracker)
  assert.equal(decision.eligible, true)
  assert.equal(decision.eligible && decision.reason, 'hardened_denial')
  assert.equal(decision.eligible && decision.evidenceCount, 2)

  const event = buildEarlyExitEvent({ reason: 'hardened_denial', evidence: snapshot, turnsUsed: 6, maxTurns: MAX_TURNS })
  assert.deepEqual(event.route, { method: 'GET', path: '/api/invoices/1002', params: ['tenant'] })
  assert.deepEqual([...event.denialStatuses], [403, 403])
  assert.equal(event.evidenceCount, 2)
  assert.equal(event.turnsUsed, 6)
  assert.equal(event.turnsSaved, MAX_TURNS - 6 - EARLY_EXIT_GRACE_TURNS)

  const directive = earlyExitDirectiveMessage({ ...event, proofTools: ['kovo_verify'] })
  assert.match(directive, /KOVO(?: HUNTER)? EARLY EXIT — Turn 6\/18/)
  assert.match(directive, /hardened_denial/)
  assert.match(directive, /403\/403/)
  assert.match(directive, /do not probe further/)
  assert.match(directive, /kovo_verify/)
  assert.match(directive, /proofGapReason/)
})

test('two identical attempts are not two distinct attempts (repetition is not evidence)', async () => {
  const { tracker, tools } = fixture()
  await probe(tools, 'GET', '/api/invoices/1001?tenant=alpha')
  await probe(tools, 'GET', '/api/invoices/1001?tenant=alpha')

  const snapshot = tracker.observationSnapshot()
  assert.equal(snapshot.attempts, 2)
  assert.equal(snapshot.distinctAttempts, 1, 'the exact same request twice collapses')
  assert.equal(snapshot.distinctPaths, 1)
  assert.equal(snapshot.distinctParams, 1)
  const decision = decisionFor(tracker)
  assert.equal(decision.eligible, false)
  assert.equal(decision.eligible === false && decision.blockedBy, 'insufficient_evidence')
})

// ============================================================================
// 2. A route with an anomaly never early-exits
// ============================================================================

test('a differential anomaly blocks early exit even after denial attempts', async () => {
  const { tracker, tools } = fixture({
    differential: { verdict: 'signal', anomalies: [{ type: 'sqli_boolean' }], requestsSent: 8 },
  })
  await probe(tools, 'GET', '/api/invoices/1001?tenant=alpha')
  await probe(tools, 'GET', '/api/invoices/1002?tenant=beta')
  await invoke(toolByName(tools, 'probe_differential')!, {
    origin: ORIGIN,
    probeClass: 'sqli_boolean',
    pathAndQuery: '/api/invoices/1001?tenant=alpha',
  })

  const snapshot = tracker.observationSnapshot()
  assert.equal(snapshot.attempts, 3)
  assert.equal(snapshot.anomalyCount, 1, 'the signal is recorded on the route ledger')

  const decision = decisionFor(tracker)
  assert.equal(decision.eligible, false)
  assert.equal(decision.eligible === false && decision.blockedBy, 'anomaly_recorded')
})

test('a non-denial answer to a state-changing method blocks the hardened reading', async () => {
  const { tracker, tools } = fixture({
    http: args => args.method === 'POST'
      ? { exchangeId: 'ex-2', status: 201, bodySha256: 'sha-created' }
      : { exchangeId: 'ex-1', status: 403, bodySha256: 'sha-denied' },
  })
  await probe(tools, 'GET', '/api/invoices/1001?tenant=alpha')
  await probe(tools, 'POST', '/api/invoices/1002?tenant=beta')

  const snapshot = tracker.observationSnapshot()
  assert.equal(snapshot.stateChangeAttempts, 1, 'the 201 is a state change, not a hardened denial')
  const decision = decisionFor(tracker)
  assert.equal(decision.eligible, false)
})

// ============================================================================
// 3. Work in flight blocks the exit
// ============================================================================

test('pending spec submission, in-flight repair and uncoded proof gap each block early exit', async () => {
  const { tracker, tools } = fixture()
  await probe(tools, 'GET', '/api/invoices/1001?tenant=alpha')
  await probe(tools, 'GET', '/api/invoices/1002?tenant=beta')
  const base = { evidence: tracker.observationSnapshot(), turnsUsed: 6, maxTurns: MAX_TURNS }

  const blocks: Array<[EarlyExitBlock, Record<string, boolean>]> = [
    ['spec_pending', { specPending: true }],
    ['repair_in_flight', { repairInFlight: true }],
    ['unresolved_proof_gap', { unresolvedProofGap: true }],
  ]
  for (const [expected, overrides] of blocks) {
    const decision = earlyExitEligible({ ...base, ...overrides })
    assert.equal(decision.eligible, false, `${expected} must block the exit`)
    assert.equal(decision.eligible === false && decision.blockedBy, expected)
  }

  // A rejected leaning conclusion is a repair in flight until a spec or coded gap lands.
  await invoke(toolByName(tools, 'complete_intent')!, { status: 'proved', summary: 'Invoice reads look cross-tenant.' })
  const snapshot = tracker.snapshot()
  assert.equal(snapshot.required, 1, 'the leaning claim was rejected once')
  assert.equal(earlyExitEligible({
    ...base,
    specPending: snapshot.specAttempts > 0 && !snapshot.targetCovered,
    repairInFlight: snapshot.codedProofGaps === 0 && !snapshot.targetCovered,
    unresolvedProofGap: snapshot.proofGaps.some(gap => !gap.code),
  }).eligible, false, 'the open repair blocks the exit')
})

test('the turn floor keeps the exit from firing before settlement can be armed', async () => {
  const { tracker, tools } = fixture()
  await probe(tools, 'GET', '/api/invoices/1001?tenant=alpha')
  await probe(tools, 'GET', '/api/invoices/1002?tenant=beta')
  const decision = decisionFor(tracker, { turnsUsed: EARLY_EXIT_MIN_TURNS - 1 })
  assert.equal(decision.eligible, false)
  assert.equal(decision.eligible === false && decision.blockedBy, 'below_min_turns')
})

// ============================================================================
// 4. Stat + reserved wrap-up turn
// ============================================================================

test('the stat counts saved turns and the final turn stays reserved for complete_intent', () => {
  assert.equal(earlyExitTurnsSaved({ turnsUsed: 6, maxTurns: 18 }), 10)
  assert.equal(earlyExitTurnsSaved({ turnsUsed: 18, maxTurns: 18 }), 0, 'never negative')
  assert.equal(earlyExitTurnsSaved({ turnsUsed: 6, maxTurns: 18, graceTurns: 4 }), 8)

  const triggerTurn = 6
  const finalTurn = triggerTurn + EARLY_EXIT_GRACE_TURNS
  assert.equal(settlementToolBlock({ name: 'kovo_verify', settling: true, turnsUsed: triggerTurn, maxTurns: 18, finalTurn }), undefined,
    'the reserved wrap-up verify turn still fires')
  assert.match(settlementToolBlock({ name: 'request_http', settling: true, turnsUsed: triggerTurn, maxTurns: 18, finalTurn }) ?? '', /disabled during settlement/)
  assert.match(settlementToolBlock({ name: 'verify_replay_spec', settling: true, turnsUsed: finalTurn, maxTurns: 18, finalTurn }) ?? '', /Final settlement turn/)
  assert.equal(settlementToolBlock({ name: 'kovo_verify', settling: true, turnsUsed: finalTurn, maxTurns: 18, finalTurn }), undefined,
    'kovo_verify stays available on the final turn as primary proof submission tool')
  // Without early exit the legacy maxTurns behaviour is unchanged.
  assert.equal(settlementToolBlock({ name: 'kovo_verify', settling: true, turnsUsed: 11, maxTurns: 18 }), undefined)
})

// ============================================================================
// 5. The obligation is still one spec or one coded gap (no demand loop)
// ============================================================================

test('after an early exit a coded gap closes the obligation with zero complete_intent rejections', async () => {
  const { tracker, tools, completions, required } = fixture()
  await probe(tools, 'GET', '/api/invoices/1001?tenant=alpha')
  await probe(tools, 'GET', '/api/invoices/1002?tenant=beta')
  assert.equal(specSubmissionPending(tracker.snapshot()), true, 'a probed route still owes proof')

  const decision = decisionFor(tracker)
  assert.equal(decision.eligible, true)

  const gap = await invoke(toolByName(tools, 'record_coverage')!, {
    status: 'needs_follow_up',
    proofGapReason: `no_reproducible_signal: consistent 403 denial on 2 distinct attempts, no anomaly on ${ORIGIN}`,
  })
  assert.notEqual(gap.isError, true)
  const snapshot = tracker.snapshot()
  assert.equal(snapshot.codedProofGaps, 1)
  assert.equal(specSubmissionPending(snapshot), false, 'the coded gap satisfies the obligation')

  const done = await invoke(toolByName(tools, 'complete_intent')!, {
    status: 'ruled_out',
    summary: 'Route is hardened: both attempts denied with 403 and no differential.',
  })
  assert.notEqual(done.isError, true)
  assert.equal(completions.length, 1)
  assert.equal(required.length, 0, 'no spec demand loop: nothing was rejected')
  assert.equal(tracker.snapshot().required, 0)
})

test('a free-text gap does not satisfy the obligation (the exit cannot launder an uncoded skip)', async () => {
  const { tracker, tools, completions } = fixture()
  await probe(tools, 'GET', '/api/invoices/1001?tenant=alpha')
  await probe(tools, 'GET', '/api/invoices/1002?tenant=beta')
  assert.equal(decisionFor(tracker).eligible, true)

  await invoke(toolByName(tools, 'record_coverage')!, {
    status: 'needs_follow_up',
    proofGapReason: 'the route just looked hardened to me',
  })
  const snapshot = tracker.snapshot()
  assert.equal(snapshot.codedProofGaps, 0)
  assert.equal(specSubmissionPending(snapshot), true, 'a free-text gap stays pending')
  assert.equal(earlyExitEligible({ evidence: tracker.observationSnapshot(), turnsUsed: 6, maxTurns: MAX_TURNS, unresolvedProofGap: snapshot.proofGaps.some(gap => !gap.code) }).eligible, false)

  const rejected = await invoke(toolByName(tools, 'complete_intent')!, { status: 'proved', summary: 'Hardened route.' })
  assert.equal(rejected.isError, true)
  assert.equal(completions.length, 0)
})

// ============================================================================
// 6. The other two earned reasons stay evidence-based
// ============================================================================

test('a control-vs-probe refutation with no anomaly is an earned exit; a signal never is', async () => {
  const refuted = fixture({ differential: { verdict: 'no_signal', anomalies: [], requestsSent: 6 } })
  await invoke(toolByName(refuted.tools, 'probe_differential')!, {
    origin: ORIGIN,
    probeClass: 'sqli_boolean',
    pathAndQuery: '/api/items?id=1',
  })
  await invoke(toolByName(refuted.tools, 'probe_differential')!, {
    origin: ORIGIN,
    probeClass: 'sqli_boolean',
    pathAndQuery: '/api/items?id=2',
  })
  const snapshot = refuted.tracker.observationSnapshot()
  assert.equal(snapshot.refutedHypotheses, 2)
  assert.equal(snapshot.staticCatchAll, false)
  const decision = decisionFor(refuted.tracker)
  assert.equal(decision.eligible, true)
  assert.equal(decision.eligible && decision.reason, 'hypothesis_refuted')
})

test('a calibrated static catch-all with no state change is an earned exit; a mutation is not', () => {
  const evidence = {
    attempts: 2,
    distinctAttempts: 2,
    distinctPaths: 2,
    distinctParams: 0,
    distinctBodies: 1,
    anomalyCount: 0,
    statuses: [200, 200],
    denialStatuses: [],
    stateChangeAttempts: 0,
    staticCatchAll: true,
    refutedHypotheses: 0,
    routes: [],
  }
  const decision = earlyExitEligible({ evidence, turnsUsed: 6, maxTurns: MAX_TURNS })
  assert.equal(decision.eligible, true)
  assert.equal(decision.eligible && decision.reason, 'static_no_state_change')

  const mutated = earlyExitEligible({ evidence: { ...evidence, stateChangeAttempts: 1 }, turnsUsed: 6, maxTurns: MAX_TURNS })
  assert.equal(mutated.eligible, false, 'a state change disqualifies the static reading')
})

test('the event route is the target family and evidence count matches its attempts', async () => {
  const { tracker, tools } = fixture()
  await probe(tools, 'GET', '/api/invoices/1001?tenant=alpha')
  await probe(tools, 'GET', '/api/invoices/1002?tenant=beta')
  await probe(tools, 'DELETE', '/api/invoices/1003?tenant=gamma')
  await probe(tools, 'DELETE', '/api/invoices/1004?tenant=gamma')
  await probe(tools, 'DELETE', '/api/invoices/1005?tenant=gamma')
  const snapshot = tracker.observationSnapshot()
  assert.equal(snapshot.attempts, 3, 'three attempts on the hottest family (DELETE)')
  assert.deepEqual(snapshot.routes.map(route => `${route.method} ${route.family}`).sort(), [
    'DELETE /api/invoices/:id',
    'GET /api/invoices/:id',
  ])
  const route: SpecRouteEvidence | undefined = snapshot.route
  assert.deepEqual(route, { method: 'DELETE', path: '/api/invoices/1005', params: ['tenant'] })
  const event = buildEarlyExitEvent({ reason: 'hardened_denial', evidence: snapshot, turnsUsed: 5, maxTurns: MAX_TURNS })
  assert.equal(event.evidenceCount, 3)
  assert.equal(event.turnsSaved, 11)
})
