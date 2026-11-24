/**
 * v7 M5: mandatory spec-or-explicit-gap at settlement.
 *
 * Held-out autopsy (seed 1000042, K=6): 23 targets had a real agent request on the target
 * route+method, but only 4 produced a persisted replay spec and 19 were `no_spec_submitted`.
 * These tests pin the enforcement that turns "route hit → silent skip" into
 * "route hit → one reserved guardian_verify attempt, or a machine-readable proof gap":
 *
 *   1. complete_intent(proved|partial) is rejected without a spec or a coded proofGapReason;
 *   2. a coded record_coverage proof gap is accepted and recorded (`open_proof_gap` in the funnel);
 *   3. a submitted spec needs no extra prompt;
 *   4. settlement reserves the wrap-up turn for guardian_verify and still revokes probe tools;
 *   5. the funnel classifier distinguishes `open_proof_gap` from `no_spec_submitted`.
 */
import assert from 'node:assert/strict'
import { test } from 'node:test'

import {
  GUARDIAN_VERIFY_SPEC_SHAPE,
  SPEC_PROOF_GAP_CODES,
  SpecSubmissionTracker,
  buildWorkerTools,
  classifySpecSubmission,
  parseProofGapCode,
  settlementBannerMessage,
  settlementNudgeMessage,
  settlementSpecDirective,
  settlementToolBlock,
  specSubmissionPending,
  specSubmissionRequiredFor,
  replaySpecRouteSteps,
  type SpecRouteEvidence,
} from '../src/server/agent-session.ts'
import { renderSettlementSpecDirective } from '../src/server/assignment-brief.ts'

const ORIGIN = 'https://spec.submission.test'
const ROUTE: SpecRouteEvidence = { method: 'POST', path: '/v1/baskets/current/coupons', params: ['code'] }

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

/** Minimal worker surface: one probe route, one accepted spec, coverage and complete_intent spies. */
function fixture() {
  const tracker = new SpecSubmissionTracker()
  const requiredCalls: Array<{ status: string; count: number; route?: SpecRouteEvidence }> = []
  const completions: Array<{ status: string; summary: string }> = []
  const coverage: Array<Record<string, unknown>> = []
  const tools = buildWorkerTools({
    request_http: async () => ({ exchangeId: 'ex-1', status: 200 }),
    guardian_verify: async () => ({ oraclePassed: true, attempts: [] }),
    record_coverage: async args => {
      coverage.push(args as unknown as Record<string, unknown>)
      return { id: 'cov-1', status: args.status }
    },
    complete_intent: async completion => {
      completions.push(completion)
      return { recorded: true }
    },
  }, value => value, AbortSignal.timeout(5_000), 24 * 1024, () => {}, {
    tracker,
    onRequired: info => { requiredCalls.push(info) },
  })
  return { tracker, requiredCalls, completions, coverage, tools }
}

async function probeRoute(tools: ReturnType<typeof buildWorkerTools>) {
  const result = await invoke(toolByName(tools, 'request_http')!, {
    origin: ORIGIN,
    method: 'POST',
    pathAndQuery: '/v1/baskets/current/coupons?code=CANARY-1',
  })
  assert.notEqual(result.isError, true, 'the fixture probe succeeds')
}

// ============================================================================
// 1. Leaning conclusion without spec or proof gap is rejected (exact field named)
// ============================================================================

test('complete_intent(proved) without a spec or coded proof gap is rejected, counted, and not completed', async () => {
  const { tracker, requiredCalls, completions, tools } = fixture()
  await probeRoute(tools)
  assert.equal(specSubmissionPending(tracker.snapshot()), true, 'a probed route without a spec is pending')

  const rejected = await invoke(toolByName(tools, 'complete_intent')!, {
    status: 'proved',
    summary: 'Coupon reuse looks exploitable from the observed differential.',
  })

  assert.equal(rejected.isError, true, 'the conclusion is rejected instead of terminating the worker')
  const text = textOf(rejected)
  assert.match(text, /agent\.spec_submission_required/)
  assert.match(text, /missing required field `proofGapReason`/, 'the exact missing field is named')
  assert.ok(text.includes('POST /v1/baskets/current/coupons param=code'), 'the repair names the probed route+method+param')
  assert.ok(text.includes(GUARDIAN_VERIFY_SPEC_SHAPE), 'the repair repeats the full spec shape')
  assert.equal(completions.length, 0, 'the complete_intent handler is never called for a rejected conclusion')
  assert.equal(tracker.snapshot().required, 1, 'the rejection is counted on the assignment ledger')
  assert.equal(requiredCalls.length, 1)
  assert.equal(requiredCalls[0]!.status, 'proved')
  assert.equal(requiredCalls[0]!.count, 1)
  assert.deepEqual(requiredCalls[0]!.route, {
    method: 'POST', path: '/v1/baskets/current/coupons', params: ['code'], origin: ORIGIN,
  })
})

test('partial is treated as a leaning conclusion; ruled_out and blocked are not spec-gated', async () => {
  const { tools } = fixture()
  await probeRoute(tools)
  const partial = await invoke(toolByName(tools, 'complete_intent')!, { status: 'partial', summary: 'Possible coupon reuse.' })
  assert.equal(partial.isError, true, 'partial is a leaning conclusion')

  const ruledOut = await invoke(toolByName(tools, 'complete_intent')!, { status: 'ruled_out', summary: 'Control enforced.' })
  assert.notEqual(ruledOut.isError, true, 'ruled_out is a negative conclusion, not a proof claim')
  assert.equal((ruledOut as { control?: { terminate?: boolean } }).control?.terminate, true)
})

test('an assignment with no probe is never spec-gated', async () => {
  const { tools, completions } = fixture()
  const result = await invoke(toolByName(tools, 'complete_intent')!, { status: 'proved', summary: 'Static-only reasoning.' })
  assert.notEqual(result.isError, true, 'no route evidence means no proof obligation')
  assert.equal(completions.length, 1)
})

// ============================================================================
// 2. A genuine, machine-readable proof gap is accepted and recorded
// ============================================================================

test('complete_intent is accepted after a coded record_coverage proof gap and the gap is recorded', async () => {
  const { tracker, coverage, completions, tools } = fixture()
  await probeRoute(tools)

  const recorded = await invoke(toolByName(tools, 'record_coverage')!, {
    origin: ORIGIN,
    category: 'business-logic-race',
    status: 'needs_follow_up',
    summary: 'Coupon reuse needs a valid spec but the replay shape is unclear.',
    proofGapReason: 'no_spec_shape: the coupon route needs a multi-step baseline step we cannot express',
  })
  assert.notEqual(recorded.isError, true)
  assert.equal(coverage.length, 1)
  assert.equal(tracker.snapshot().proofGaps.length, 1)
  assert.equal(tracker.snapshot().codedProofGaps, 1)
  assert.equal(tracker.snapshot().proofGaps[0]!.code, 'no_spec_shape')
  assert.equal(specSubmissionPending(tracker.snapshot()), false, 'a coded gap closes the obligation honestly')

  const accepted = await invoke(toolByName(tools, 'complete_intent')!, {
    status: 'proved',
    summary: 'Likely coupon reuse; proof gap recorded with a machine-readable reason.',
  })
  assert.notEqual(accepted.isError, true, 'an explicit proof gap is not punished')
  assert.equal(completions.length, 1)
})

test('a free-text-only gap is recorded but does not satisfy the obligation', async () => {
  const { tracker, tools } = fixture()
  await probeRoute(tools)
  await invoke(toolByName(tools, 'record_coverage')!, {
    origin: ORIGIN,
    category: 'business-logic-race',
    status: 'needs_follow_up',
    summary: 'Needs more work.',
    proofGapReason: 'ran out of time on the coupon route',
  })
  assert.equal(tracker.snapshot().proofGaps.length, 1, 'the gap is still recorded for the report')
  assert.equal(tracker.snapshot().codedProofGaps, 0)
  assert.equal(parseProofGapCode('ran out of time on the coupon route'), null)
  const rejected = await invoke(toolByName(tools, 'complete_intent')!, { status: 'proved', summary: 'Likely.' })
  assert.equal(rejected.isError, true, 'only a machine-readable gap discharges the obligation')
})

test('every declared proof-gap code parses and shares the record_coverage error text', () => {
  for (const code of SPEC_PROOF_GAP_CODES) {
    assert.equal(parseProofGapCode(`${code}: detail`), code)
    assert.equal(parseProofGapCode(code.toUpperCase()), code)
  }
  assert.equal(parseProofGapCode(''), null)
  assert.equal(parseProofGapCode(undefined), null)
  assert.equal(parseProofGapCode('generic blocker'), null)
})

// ============================================================================
// 3. A submitted spec needs no extra prompt
// ============================================================================

test('a successful guardian_verify attempt clears the obligation and complete_intent proceeds', async () => {
  const { tracker, completions, tools } = fixture()
  await probeRoute(tools)

  const verify = await invoke(toolByName(tools, 'guardian_verify')!, {
    script: 'return ctx.result({ title: "coupon reuse", claims: [] })',
    runtime: 'ts',
  })
  assert.notEqual(verify.isError, true, 'the fixture verify call succeeds')
  assert.equal(tracker.snapshot().specAttempts, 1)
  assert.equal(specSubmissionPending(tracker.snapshot()), false)
  assert.equal(specSubmissionRequiredFor(tracker.snapshot()), false)

  const accepted = await invoke(toolByName(tools, 'complete_intent')!, { status: 'proved', summary: 'Verified.' })
  assert.notEqual(accepted.isError, true, 'no extra prompt after a spec submission')
  assert.equal(completions.length, 1)
})

test('a spec for a different route does not clear the target obligation', async () => {
  const tracker = new SpecSubmissionTracker()
  const spec = (path: string) => ({
    version: 1,
    origin: ORIGIN,
    title: 'Coupon reuse differential',
    category: 'injection',
    cwe: 'CWE-89',
    severity: 'high',
    severityRationale: 'Control and probe differ consistently.',
    impact: 'An attacker can reuse a coupon.',
    remediation: 'Bind coupons to baskets.',
    recheckInstructions: 'Replay the same control/probe pair.',
    assertionsJq: '.probe.status == 200',
    steps: [
      { id: 'control', role: 'control', description: 'Baseline coupon use', request: { origin: ORIGIN, method: 'POST', pathAndQuery: '/v1/control' } },
      { id: 'probe', role: 'probe', description: 'Probe the coupon route', request: { origin: ORIGIN, method: 'POST', pathAndQuery: path } },
    ],
  })
  const tools = buildWorkerTools({
    request_http: async () => ({ exchangeId: 'ex-1', status: 200 }),
    verify_replay_spec: async () => ({ oraclePassed: false, rejectedBy: 'dismissed', attempts: [] }),
    complete_intent: async () => ({ recorded: true }),
  }, value => value, AbortSignal.timeout(5_000), 24 * 1024, () => {}, { tracker })

  await probeRoute(tools)
  const other = await invoke(toolByName(tools, 'verify_replay_spec')!, { spec: spec('/v1/other/route') })
  assert.notEqual(other.isError, true, 'the unrelated spec is schema-valid and verified')
  assert.equal(tracker.snapshot().specAttempts, 1)
  assert.equal(tracker.snapshot().targetCovered, false)
  assert.equal(specSubmissionPending(tracker.snapshot()), true, 'the target route is still unproven')

  const rejected = await invoke(toolByName(tools, 'complete_intent')!, { status: 'proved', summary: 'Likely reuse.' })
  assert.equal(rejected.isError, true, 'a spec on another route cannot support the target claim')

  // The same spec shape pointed at the target route clears it.
  await invoke(toolByName(tools, 'verify_replay_spec')!, { spec: spec('/v1/baskets/current/coupons?code=x') })
  assert.equal(tracker.snapshot().targetCovered, true)
  assert.equal(specSubmissionPending(tracker.snapshot()), false)
})

test('batch/race-only route evidence is never spec-gated without a routable target', () => {
  const tracker = new SpecSubmissionTracker()
  tracker.noteProbe()
  tracker.noteSpecAttempt([{ method: 'GET', path: '/api/other' }])
  assert.equal(tracker.snapshot().route, undefined)
  assert.equal(specSubmissionPending(tracker.snapshot()), false, 'no routable target means no false rejection')
})

test('replaySpecRouteSteps extracts requests from mixed spec shapes', () => {
  const steps = replaySpecRouteSteps({
    steps: {
      control: { request: { method: 'get', pathAndQuery: '/v1/a?x=1' } },
      probe: { method: 'POST', path: '/v1/b' },
    },
    probe: { request: { method: 'PATCH', pathAndQuery: '/v1/c' } },
  })
  assert.deepEqual(steps, [
    { method: 'GET', path: '/v1/a' },
    { method: 'POST', path: '/v1/b' },
    { method: 'PATCH', path: '/v1/c' },
  ])
})

// ============================================================================
// 4. Settlement reservation names the route; revoked probes stay revoked
// ============================================================================

test('the settlement directive names route+method+param and the smallest valid spec', () => {
  const directive = settlementSpecDirective(ROUTE)
  assert.match(directive, /POST \/v1\/baskets\/current\/coupons param=code/)
  assert.ok(directive.includes(GUARDIAN_VERIFY_SPEC_SHAPE), 'the smallest valid spec shape is included')
  assert.match(directive, /reserved/i)
  assert.match(directive, /record_coverage\(status="needs_follow_up"/)
  for (const code of SPEC_PROOF_GAP_CODES) assert.ok(directive.includes(code), `directive lists ${code}`)

  const banner = settlementBannerMessage({ turnsUsed: 10, maxTurns: 12, proofTools: ['guardian_verify'], specDirective: directive })
  const nudge = settlementNudgeMessage({ turn: 10, maxTurns: 12, proofTools: ['guardian_verify'], specDirective: directive })
  assert.ok(banner.includes('POST /v1/baskets/current/coupons param=code'))
  assert.ok(nudge.includes('POST /v1/baskets/current/coupons param=code'))
})

test('settlement pauses offline analysis while a probed route still owes a spec', () => {
  const directive = settlementSpecDirective(ROUTE)
  const base = { settling: true, turnsUsed: 10, maxTurns: 12, specPending: true, specDirective: directive }

  const analysis = settlementToolBlock({ name: 'derive_evidence', ...base })
  assert.ok(analysis, 'offline analysis is paused for the reserved turn')
  assert.match(analysis!, /paused during settlement/)
  assert.match(analysis!, /POST \/v1\/baskets\/current\/coupons/)

  assert.equal(settlementToolBlock({ name: 'guardian_verify', ...base }), undefined, 'guardian_verify is never paused')
  assert.equal(settlementToolBlock({ name: 'record_coverage', ...base }), undefined, 'a coded gap can still be recorded')
  assert.equal(settlementToolBlock({ name: 'complete_intent', ...base }), undefined, 'complete_intent stays reachable (it enforces)')

  const revoked = settlementToolBlock({ name: 'request_http', ...base })
  assert.ok(revoked, 'the network-probe revocation is not lifted by the reservation')
  assert.match(revoked!, /disabled during settlement/)
  assert.doesNotMatch(revoked!, /reserved/i)

  // Once a spec/gap clears the obligation, analysis is no longer paused.
  assert.equal(settlementToolBlock({ name: 'derive_evidence', ...base, specPending: false }), undefined)
})

test('the final turn does not re-enable guardian_verify or probe tools', () => {
  const directive = settlementSpecDirective(ROUTE)
  for (const name of ['request_http', 'guardian_verify', 'verify_replay_spec']) {
    const block = settlementToolBlock({
      name, settling: true, turnsUsed: 12, maxTurns: 12, specPending: true, specDirective: directive,
    })
    assert.ok(block, `${name} stays blocked on the final turn`)
  }
})

// ============================================================================
// 5. Funnel classification: proofGapReason -> open_proof_gap, skip -> no_spec_submitted
// ============================================================================

test('funnel classification distinguishes an explicit proof gap from a silent skip', () => {
  assert.equal(classifySpecSubmission({ routeHit: false }), 'no_route_hit')
  assert.equal(classifySpecSubmission({ routeHit: true, confirmed: true, specSubmitted: true }), 'confirmed')
  assert.equal(classifySpecSubmission({ routeHit: true, specSubmitted: true }), 'verify_called')
  assert.equal(classifySpecSubmission({ routeHit: true, proofGapReason: 'no_spec_shape: missing baseline' }), 'open_proof_gap')
  assert.equal(classifySpecSubmission({ routeHit: true, proofGapReason: '   ' }), 'no_spec_submitted')
  assert.equal(classifySpecSubmission({ routeHit: true }), 'no_spec_submitted')
})

test('the tracker names the most-probed route as the settlement target', () => {
  const tracker = new SpecSubmissionTracker()
  tracker.noteRoute({ method: 'GET', pathAndQuery: '/' })
  tracker.noteRoute({ method: 'POST', pathAndQuery: '/v1/baskets/current/coupons?code=x' })
  tracker.noteRoute({ method: 'POST', pathAndQuery: '/v1/baskets/current/coupons?code=y' })
  tracker.noteRoute({ method: 'GET', pathAndQuery: '/v1/catalog?page=2' })
  assert.deepEqual(tracker.snapshot().route, { method: 'POST', path: '/v1/baskets/current/coupons', params: ['code'] })
})

test('the settlement directive is pure, redacts values and keeps parameter names only', () => {
  const withValue = renderSettlementSpecDirective(
    { method: 'post', path: '/v1/baskets/current/coupons?code=SECRET-CANARY#frag', params: ['code=coupon-123', 'code'], origin: `${ORIGIN}/path?x=1` },
    GUARDIAN_VERIFY_SPEC_SHAPE,
    SPEC_PROOF_GAP_CODES,
  )
  assert.match(withValue, /POST \/v1\/baskets\/current\/coupons param=code/)
  assert.doesNotMatch(withValue, /SECRET-CANARY/)
  assert.doesNotMatch(withValue, /coupon-123/)
  assert.doesNotMatch(withValue, /\/path\?x=1/)
  assert.equal(withValue, renderSettlementSpecDirective(
    { method: 'post', path: '/v1/baskets/current/coupons?code=SECRET-CANARY#frag', params: ['code=coupon-123', 'code'], origin: `${ORIGIN}/path?x=1` },
    GUARDIAN_VERIFY_SPEC_SHAPE,
    SPEC_PROOF_GAP_CODES,
  ))
})
