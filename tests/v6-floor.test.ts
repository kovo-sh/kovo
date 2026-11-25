/**
 * v6 Phase 1: always-on Layer-2 floor, det_lead upgrades, structural probe eligibility and
 * accurate dedupe through the Execution path.
 *
 * Pins the Phase-1 contracts from plans/better-architecture.md §2.2 / §3 / §4:
 *  - the deterministic floor runs on every agentic run (no opt-in flag needed);
 *  - `--no-llm` stays floor-only and never starts the concurrent lane;
 *  - confirmed floor routes are read-only context, never re-dispatched as new work;
 *  - det_lead facts become prioritized upgrade assignments bound to their fact;
 *  - dynamicStepBudget and K=6 are untouched;
 *  - probe eligibility is structural (declared type / observed shape / content-type), not
 *    benchmark token literals or English route-name gates;
 *  - two findings that mutate different parameters stay distinct through Execution.
 */
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { randomUUID } from 'node:crypto'
import { test } from 'node:test'
import { setTimeout as delay } from 'node:timers/promises'

import { declarativeReplaySpecSchema } from '../src/replay-spec.ts'
import type { DeclarativeReplaySpec } from '../src/replay-spec.ts'
import {
  computeDynamicStepBudget,
  diminishingReturnsDryThreshold,
  Execution,
  resolveDeterministicSweepMode,
  resolveFloorLaneMode,
} from '../src/server/execution.ts'
import {
  classifyValueShape,
  enumerateHypotheses,
  floorHypothesesForEnvironment,
  paramNameShape,
  rankEngineParams,
  rankEndpoints,
} from '../src/server/deterministic-engine.ts'
import type { EngineEndpoint, EngineParam } from '../src/server/deterministic-engine.ts'
import type { ChainStep, Run } from '../src/server/store.ts'
import { makeStore, setupApprovedRun } from './v4-tier-helpers.ts'

process.env.KOVO_ALLOW_LOCAL_LAB = '1'

type LaneOptions = {
  lane?: boolean
  signal?: AbortSignal
  maxDurationMs?: number
  onAssignment?: (assignmentId: string) => void
}

type Internals = {
  driveInvestigation: (run: Run, profiles: readonly unknown[]) => void
  driveEngineInvestigation: (run: Run) => void
  startDeterministicLane: (run: Run, profiles: readonly unknown[]) => void
  runEngineInvestigation: (run: Run, opts?: LaneOptions) => Promise<void>
  startInvestigationStep: (run: Run, step: ChainStep, profiles: readonly unknown[]) => void
  advanceToVerification: (run: Run) => void
  stepRepeatsConfirmedWork: (step: Pick<ChainStep, 'title' | 'hypothesis' | 'dependsOnFactIds' | 'dependsOnStepIds'>, confirmed: readonly unknown[]) => boolean
  queueDetLeadUpgradeSteps: (run: Run, origins: ReadonlySet<string>, budget: number) => number
  detLeadConsumed: Set<string>
  prePhase0SeededSteps: Map<string, boolean>
  persistDeterministicConfirmed: (input: unknown) => string | null
}

function internals(execution: Execution): Internals {
  return execution as unknown as Internals
}

function laneKey(run: Run): string {
  return `${run.id}:${run.goalRevision}:${run.scopeRevision}`
}

async function startRun(t: Parameters<typeof makeStore>[0]) {
  const { storage } = makeStore(t)
  const { runId } = await setupApprovedRun(storage, { budgetRequests: 500 })
  storage.updateRun(runId, { phase: 'investigation', status: 'running' })
  return { storage, runId }
}

function addStep(storage: ReturnType<typeof makeStore>['storage'], run: Run, overrides: Record<string, unknown> = {}): ChainStep {
  const assetIds = run.candidates.filter(c => run.approved.includes(c.id)).map(c => c.id)
  const origin = run.candidates.find(c => run.approved.includes(c.id))?.origin ?? 'http://127.0.0.1:9'
  const step = storage.addChainStep(run, {
    title: 'BOLA matrix probe',
    hypothesis: 'Cross-persona read differential on the invoice route.',
    category: 'broken-access-control',
    priority: 60,
    targetAssetIds: assetIds,
    sourceOrigins: [origin],
    ...overrides,
  } as never)
  storage.updateChainStep(step.id, { status: 'ready' })
  return step
}

/** Lane stub: starts, then settles only when the lane signal aborts. */
function stubLane(execution: Execution) {
  const calls: Array<{ maxDurationMs?: number; signal?: AbortSignal; settledAt?: number }> = []
  internals(execution).runEngineInvestigation = async (_run, opts = {}) => {
    const call: { maxDurationMs?: number; signal?: AbortSignal; settledAt?: number } = {
      maxDurationMs: opts.maxDurationMs,
      signal: opts.signal,
    }
    calls.push(call)
    opts.onAssignment?.('lane-assignment')
    await new Promise<void>(resolve => {
      if (opts.signal?.aborted) resolve()
      else opts.signal?.addEventListener('abort', () => resolve(), { once: true })
    })
    call.settledAt = Date.now()
  }
  return { calls }
}

test('floor lane resolver defaults ON; explicit false/env 0 is the operator kill switch', () => {
  // v6 Phase 1 inverts the v5 opt-in: an agentic run gets the floor unless explicitly disabled.
  assert.equal(resolveFloorLaneMode(undefined, {}), 'on')
  assert.equal(resolveFloorLaneMode(true, {}), 'on')
  assert.equal(resolveFloorLaneMode('always', {}), 'always')
  assert.equal(resolveFloorLaneMode(false, {}), 'off')
  assert.equal(resolveFloorLaneMode(undefined, { KOVO_DETERMINISTIC_SWEEP: '0' }), 'off')
  assert.equal(resolveFloorLaneMode(undefined, { KOVO_DETERMINISTIC_SWEEP: 'off' }), 'off')
  assert.equal(resolveFloorLaneMode(undefined, { KOVO_DETERMINISTIC_SWEEP: '1' }), 'on')
  // The legacy parser is retained unchanged for callers that pin the v5 opt-in semantics.
  assert.equal(resolveDeterministicSweepMode(undefined, {}), 'off')
})

test('agentic run starts the deep floor first and dispatches agents only after it settles', async (t) => {
  const { storage, runId } = await startRun(t)
  const run = storage.run(runId)
  addStep(storage, run)
  const execution = new Execution(storage, { maxDurationMs: 600_000 })
  t.after(() => execution.stop())
  internals(execution).prePhase0SeededSteps.set(laneKey(run), false)
  const dispatched: string[] = []
  internals(execution).startInvestigationStep = (_r, step) => { dispatched.push(step.id) }
  const lane = stubLane(execution)

  internals(execution).driveInvestigation(storage.run(runId), [{ id: 'profile', model: 'mock' }])

  assert.equal(lane.calls.length, 1, 'the floor runs on an agentic run without an opt-in flag')
  assert.equal(dispatched.length, 0, 'specialist dispatch waits for Phase A to settle')
  assert.equal(lane.calls[0].maxDurationMs, 72_000, 'Phase A budget = min(75 s, 12% x maxDuration)')
  const steps = storage.listChainSteps(runId, storage.run(runId).goalRevision)
  assert.ok(steps.every(step => step.status !== 'canceled'), 'the floor never cancels steps')

  // The lane stub resolves when its run signal aborts; the phase transition aborts it.
  await internals(execution).advanceToVerification(storage.run(runId))
  await delay(20)
  assert.ok(lane.calls[0].settledAt, 'Phase A settles before verification')
})

test('--no-llm stays floor-only: engine path runs, concurrent lane never starts', async (t) => {
  const { storage, runId } = await startRun(t)
  const run = storage.run(runId)
  addStep(storage, run)
  const execution = new Execution(storage, { deterministicOnly: true })
  t.after(() => execution.stop())
  internals(execution).prePhase0SeededSteps.set(laneKey(run), false)
  let engineCalls = 0
  let laneCalls = 0
  internals(execution).driveEngineInvestigation = () => { engineCalls += 1 }
  internals(execution).startDeterministicLane = () => { laneCalls += 1 }
  const lane = stubLane(execution)

  // `--no-llm` runs with no model profile: the floor is the whole run.
  internals(execution).driveInvestigation(storage.run(runId), [])
  assert.equal(engineCalls, 1, '--no-llm runs the unrestricted floor')
  assert.equal(laneCalls, 0, '--no-llm never starts the concurrent lane')
  assert.equal(lane.calls.length, 0)
})

test('confirmed floor routes are read-only: duplicate dispatch is filtered, chains are allowed', async (t) => {
  const { storage, runId } = await startRun(t)
  const run = storage.run(runId)
  const origin = run.candidates.find(c => run.approved.includes(c.id))!.origin
  const execution = new Execution(storage)
  t.after(() => execution.stop())
  const confirmed = [{ origin, method: 'GET', path: '/api/invoices/:id', probeClass: 'bola' }]

  const duplicate = { title: 'Re-check BOLA', hypothesis: 'Repeat the cross-persona read on GET /api/invoices/:id.', dependsOnFactIds: [], dependsOnStepIds: [] }
  assert.equal(internals(execution).stepRepeatsConfirmedWork(duplicate, confirmed), true)

  const escalation = { ...duplicate, dependsOnFactIds: ['fact-1'] }
  assert.equal(internals(execution).stepRepeatsConfirmedWork(escalation, confirmed), false, 'chained work is an escalation, not a duplicate')

  const fresh = { title: 'New route', hypothesis: 'Probe GET /api/orders/:id for tenant isolation.', dependsOnFactIds: [], dependsOnStepIds: [] }
  assert.equal(internals(execution).stepRepeatsConfirmedWork(fresh, confirmed), false)
})

test('det_lead facts become prioritized upgrade assignments bound to their fact', async (t) => {
  const { storage, runId } = await startRun(t)
  const run = storage.run(runId)
  const origin = run.candidates.find(c => run.approved.includes(c.id))!.origin
  const assignment = storage.makeWorker(run, 'investigation', run.candidates[0], 'floor', 'floor')
  const claimed = storage.updateWorker(assignment.id, { status: 'running', lease: randomUUID() })!
  storage.addFact(run, claimed, {
    kind: 'note',
    origin,
    summary: 'lead',
    data: { kind: 'det_lead', source: 'deterministic_engine', probeClass: 'ssrf_canary', endpoint: '/v2/relay', method: 'POST', leadEvidenceKind: 'near_miss', reason: 'canary-shaped parameter observed' },
  })
  const execution = new Execution(storage)
  t.after(() => execution.stop())
  const budget = computeDynamicStepBudget(storage, runId)
  const created = internals(execution).queueDetLeadUpgradeSteps(storage.run(runId), new Set([origin]), budget)

  assert.equal(created, 1, 'one unconfirmed lead becomes an upgrade assignment')
  const steps = storage.listChainSteps(runId, storage.run(runId).goalRevision)
  const upgrade = steps.find(step => step.title.startsWith('det_lead upgrade'))
  assert.ok(upgrade, 'upgrade step created')
  assert.equal(upgrade!.dependsOnFactIds.length, 1, 'upgrade is bound to its originating fact')
  assert.equal(upgrade!.status, 'ready')
  assert.equal(upgrade!.priority, 55)
  assert.equal(storage.run(runId).dynamicStepBudget, null, 'the upgrade path does not write dynamicStepBudget')
  assert.equal(internals(execution).detLeadConsumed.size, 1)
  assert.ok(storage.eventsAfter(runId, 0).some(e => e.kind === 'deterministic_lane.lead_consumed'))

  // Re-queueing is idempotent: the bound lead is never dispatched twice.
  const createdAgain = internals(execution).queueDetLeadUpgradeSteps(storage.run(runId), new Set([origin]), budget)
  assert.equal(createdAgain, 0)

  // A lead whose (route, family) the floor already confirmed is not re-dispatched as new work.
  const confirmedSpec = sqlSpec(origin, 'q')
  const findingId = randomUUID()
  const specRow = storage.createReplaySpec(
    storage.run(runId),
    claimed,
    findingId,
    confirmedSpec,
    [origin],
    {
      verifiedInline: true,
      lastVerificationDiff: {
        verdict: 'confirmed',
        controlPassed: true,
        stepStatuses: [],
        assertionSummary: { observed: 'ok', expected: 'denied' },
        retriesRemaining: 0,
      },
    },
  )
  storage.upsertChainFinding(storage.run(runId), run.candidates[0].id, {
    id: findingId,
    origin,
    title: `Boolean SQL differential on q · GET /api/items`,
    status: 'confirmed',
    verificationTier: 'runtime_confirmed',
    severity: 'high',
    reason: 'boolean differential held',
    remediation: 'Parameterize the query.',
    impact: 'Query semantics can be altered.',
    recheck: 'Replay the boolean differential.',
    category: 'injection',
    cwe: 'CWE-89',
    confidence: 'high',
    verification: 'deterministic replay',
    findingKind: 'multi_step_chain',
    replaySpecId: specRow.id,
    chainFactIds: [],
    exchangeIds: ['ex-1'],
    evidenceIds: [],
    scopeRevision: storage.run(runId).scopeRevision,
  }, specRow.id, [origin])
  storage.addFact(storage.run(runId), claimed, {
    kind: 'note',
    origin,
    summary: 'new lead on the confirmed class+route',
    data: { kind: 'det_lead', source: 'deterministic_engine', probeClass: 'sqli_boolean', endpoint: '/api/items', method: 'GET' },
  })
  const createdOnConfirmed = internals(execution).queueDetLeadUpgradeSteps(storage.run(runId), new Set([origin]), budget)
  assert.equal(createdOnConfirmed, 0, 'a lead on an already-confirmed (route, family) is not re-dispatched')
})

test('budget and K=6 invariants are unchanged by the floor lane', async (t) => {
  const { storage, runId } = await startRun(t)
  const run = storage.run(runId)
  addStep(storage, run)
  storage.updateRunDynamicStepBudget(runId, 77)
  const computedBefore = computeDynamicStepBudget(storage, runId)
  const execution = new Execution(storage)
  t.after(() => execution.stop())
  internals(execution).prePhase0SeededSteps.set(laneKey(run), false)
  internals(execution).startInvestigationStep = () => undefined
  stubLane(execution)

  internals(execution).startDeterministicLane(storage.run(runId), [{ id: 'profile', model: 'mock' }])
  assert.equal(storage.run(runId).dynamicStepBudget, 77)
  assert.equal(computeDynamicStepBudget(storage, runId), computedBefore)
  assert.equal(diminishingReturnsDryThreshold, 6)
  await internals(execution).advanceToVerification(storage.run(runId))
  await delay(20)
})

test('no benchmark token literals or mandatory English route gates remain in the engine', () => {
  const source = readFileSync(new URL('../src/server/deterministic-engine.ts', import.meta.url), 'utf8')
  assert.doesNotMatch(source, /rb\[cst?\]_/, 'benchmark token literal must not remain')
  assert.ok(!source.includes('reveal=0'), 'no reveal=0 assumption')
  assert.ok(!source.includes('strongSqlName'), 'no mandatory SQL name gate')
  // The four named gates may only appear as scoring/tie-breakers, never as `&& gate` eligibility.
  assert.doesNotMatch(source, /if\s*\([^\n]*pathHasUrlHint\(bare\)\s*&&/, 'pathHasUrlHint must not gate eligibility')
  assert.doesNotMatch(source, /if\s*\([^\n]*pathHasXmlHint\(bare\)\s*&&/, 'pathHasXmlHint must not gate eligibility')
  // The workflow verb is only an eligibility hint here; observed state evidence raises its rank.
  assert.match(source, /risk: endpointRiskScore\(endpoint\) \+ 8 \+ \(statusLike \? 10 : 0\)/, 'workflow rank is boosted by structural state evidence')
})

test('structural selection finds a URL parameter on a renamed route', () => {
  const origin = 'https://app.example.test'
  const relay: EngineEndpoint = {
    id: 'ep-relay',
    origin,
    method: 'POST',
    pathTemplate: '/v2/relay',
    params: [
      { name: 'target', location: 'json', declaredType: 'string', observedShape: 'url' },
      { name: 'note', location: 'json', declaredType: 'string' },
    ],
    riskScore: 40,
    source: 'openapi',
  }
  const hypotheses = enumerateHypotheses([relay], new Map(), {
    personas: [{ handle: 'owner', roleLabel: 'member', privilege: 'member' }, { handle: 'other', roleLabel: 'member (other)', privilege: 'member' }],
    tier: 2,
  })
  const ssrf = hypotheses.find(h => h.intent === 'ssrf')
  assert.ok(ssrf, 'a URL-shaped declared body field is enough for SSRF eligibility, no route noun needed')
  assert.equal(ssrf!.param?.name, 'target')
  assert.equal(ssrf!.method, 'POST')
})

test('structural selection finds XML (XXE) and textual (SQLi/XSS) params without route nouns', () => {
  const origin = 'https://app.example.test'
  const endpoints: EngineEndpoint[] = [
    {
      id: 'ep-doc', origin, method: 'POST', pathTemplate: '/v2/ingest',
      params: [{ name: 'payload', location: 'json', declaredType: 'string', observedShape: 'xml' }],
      riskScore: 40, source: 'openapi',
    },
    {
      id: 'ep-list', origin, method: 'GET', pathTemplate: '/v2/thing',
      params: [{ name: 'needle', location: 'query', declaredType: 'string' }],
      riskScore: 40, source: 'openapi',
    },
  ]
  const hypotheses = enumerateHypotheses(endpoints, new Map(), {
    personas: [{ handle: 'owner', roleLabel: 'member', privilege: 'member' }, { handle: 'other', roleLabel: 'member (other)', privilege: 'member' }],
    tier: 2,
  })
  assert.ok(hypotheses.some(h => h.intent === 'xxe' && h.endpoint.id === 'ep-doc'), 'XML-shaped value selects XXE')
  assert.ok(hypotheses.some(h => h.intent === 'sqli' && h.endpoint.id === 'ep-list'), 'declared textual query param selects SQLi')
  assert.ok(hypotheses.some(h => h.intent === 'xss' && h.endpoint.id === 'ep-list'), 'declared textual query param selects reflected XSS')
})

test('explicit param ranking recognizes declared type, observed shape and family', () => {
  const params: EngineParam[] = [
    { name: 'cursor', location: 'query', declaredType: 'string' },
    { name: 'avatarUrl', location: 'json', declaredType: 'string', observedShape: 'url' },
    { name: 'accountId', location: 'path', declaredType: 'integer' },
  ]
  const ranked = rankEngineParams(params, { method: 'POST', authRequired: true })
  assert.equal(ranked[0].param.name, 'avatarUrl', 'URL-shaped declared field ranks first')
  assert.ok(ranked.every(item => item.reasons.length > 0))
  assert.equal(classifyValueShape('https://example.test/a'), 'url')
  assert.equal(classifyValueShape('<doc><item/></doc>'), 'xml')
  assert.equal(classifyValueShape('42'), 'number')
  assert.equal(paramNameShape('accountId'), 'id')
  assert.deepEqual(
    rankEndpoints([{ id: 'x', origin: 'o', method: 'GET', pathTemplate: '/health', params: [] }]),
    [],
    'static/baseline routes still sink out of the ranked surface',
  )
})

function sqlSpec(origin: string, paramName: string): DeclarativeReplaySpec {
  return declarativeReplaySpecSchema.parse({
    version: 1,
    kind: 'sql_boolean_diff',
    origin,
    targetOrigin: origin,
    title: `Boolean SQL differential on ${paramName}`,
    category: 'injection',
    cwe: 'CWE-89',
    severity: 'high',
    severityRationale: 'Boolean differential held across randomized rounds.',
    impact: 'Attacker can alter query semantics.',
    remediation: 'Parameterize the query.',
    recheckInstructions: 'Replay the boolean differential.',
    method: 'GET',
    pathAndQuery: '/api/items',
    paramName,
    paramLocation: 'query',
    baselineValue: '1',
    quoteStyle: 'single',
    assertionsJq: '{ controlPassed: (.sqlDiff.controlPassed == true), confirmed: (.sqlDiff.passed == true), observed: "diff", expected: "no sql diff" }',
  })
}

test('prod_readonly forms no mutating floor hypotheses', () => {
  const origin = 'https://app.example.test'
  const endpoints: EngineEndpoint[] = [
    {
      id: 'ep-write', origin, method: 'POST', pathTemplate: '/v2/relay',
      params: [{ name: 'target', location: 'json', declaredType: 'string', observedShape: 'url' }],
      riskScore: 40, source: 'openapi',
    },
    {
      id: 'ep-read', origin, method: 'GET', pathTemplate: '/v2/things',
      params: [{ name: 'needle', location: 'query', declaredType: 'string' }],
      riskScore: 40, source: 'openapi',
    },
  ]
  const hypotheses = enumerateHypotheses(endpoints, new Map(), {
    personas: [{ handle: 'owner', roleLabel: 'member', privilege: 'member' }, { handle: 'other', roleLabel: 'member (other)', privilege: 'member' }],
    tier: 2,
  })
  assert.ok(hypotheses.some(h => h.intent === 'ssrf'), 'control: mutating hypothesis exists in a lab')
  const readOnly = floorHypothesesForEnvironment(hypotheses, 'prod_readonly')
  assert.ok(readOnly.every(h => h.method === 'GET' && !['ssrf', 'xxe', 'workflow', 'csrf', 'mass_assignment', 'ssti', 'command_injection'].includes(h.intent)))
  assert.ok(readOnly.length > 0, 'read-only checks are still formed')
})

test('two findings mutating different params stay distinct through Execution', async (t) => {
  const { storage, runId } = await startRun(t)
  const run = storage.run(runId)
  const asset = run.candidates[0]
  const origin = asset.origin
  const execution = new Execution(storage)
  t.after(() => execution.stop())
  const assignment = storage.makeWorker(run, 'investigation', asset, 'engine', 'engine')
  const specFor = (paramName: string): DeclarativeReplaySpec => sqlSpec(origin, paramName)

  const persist = (paramName: string) => internals(execution).persistDeterministicConfirmed({
    run: storage.run(runId),
    assignment,
    asset,
    secrets: [],
    confirmed: {
      hypothesis: { probeClass: 'sqli_boolean', intent: 'sqli', method: 'GET', endpoint: { pathTemplate: '/api/items', origin }, param: { name: paramName, location: 'query' } },
      spec: specFor(paramName),
      specRecord: {},
      vulnClass: 'sqli',
      endpoint: '/api/items',
      result: {
        verdict: 'confirmed',
        verificationTier: 'runtime_confirmed',
        outcome: { controlPassed: true, observed: 'boolean differential', reason: 'boolean differential', expected: 'no differential' },
        exchangeIds: ['ex-1'],
      },
      exchangeIds: ['ex-1'],
    },
  })

  const first = persist('q')
  assert.ok(first, 'first parameter finding persists')
  const second = persist('filter')
  assert.ok(second, 'a different mutated parameter on the same endpoint is a distinct finding')
  const duplicate = persist('q')
  assert.equal(duplicate, null, 'the same mutated parameter dedupes')
  assert.equal(storage.runDetail(runId).findings.length, 2)
})
