/**
 * Move O3 + O5 Architectural Regression Tests:
 *  1. Unified pure `resolveAssignmentBudget(stepDescriptor, runPolicy)` (no silent clamp on multiStep).
 *  2. Unified typed `FrontierDispatcher` / `dispatchFrontierWave` (typed metadata, EVI wave priority,
 *     white-box priority without starving runtime/grey-box chains).
 *  3. LLM planner-storm gating (`shouldInvokeLlmPlanner` + live `ExecReconPlanner.runChainPlanner`
 *     saturation deferral & milestone wakeup).
 *  4. `code_audit_suspect` conversion into Wave-1 steps & typed `ChainHop` ingestion (World Graph planner input).
 *  5. `RunOrchestrationStateStore` single-call atomic cleanup on `disposeRun` (unit + live `Execution`).
 */
import assert from 'node:assert/strict'
import { createServer, type Server } from 'node:http'
import type { AddressInfo } from 'node:net'
import { test } from 'node:test'

import { RequestBroker } from '../src/server/broker.ts'
import {
  CHAIN_ASSIGNMENT_MAX_WALL_CLOCK_MS,
  CHAIN_ASSIGNMENT_MIN_WALL_CLOCK_MS,
  CODE_AUDIT_WAVE1_MAX_STEPS,
  DET_LEAD_CONCURRENT_CAP,
  FrontierDispatcher,
  FrontierWaveController,
  MULTI_HOP_CHAIN_DEFAULT_WALL_CLOCK_MS,
  MULTI_HOP_CHAIN_MAX_WALL_CLOCK_MS,
  MULTI_STEP_ASSIGNMENT_MAX_TURNS,
  MULTI_STEP_ASSIGNMENT_MIN_TURNS,
  RunOrchestrationStateStore,
  SINGLE_STEP_ASSIGNMENT_MAX_TURNS,
  SINGLE_STEP_ASSIGNMENT_WALL_CLOCK_MS,
  classifyAssignmentBudgetClass,
  classifyDispatchLane,
  convertCodeAuditSuspectsToChainSteps,
  dispatchFrontierWave,
  resolveAssignmentBudget,
  resolveWorkerSettlementMs,
  shouldInvokeLlmPlanner,
  type DispatchLaneStep,
} from '../src/server/exec-dispatch.ts'
import { Execution } from '../src/server/execution.ts'
import type { ExecReconPlanner } from '../src/server/exec-recon-planner.ts'
import type { FrontierBranch } from '../src/server/frontier-scheduler.ts'
import { extractChainHops } from '../src/server/graph-coordinator.ts'
import type { ResolvedModelProfile } from '../src/server/model-settings.ts'
import type { WorkerBackend, WorkerSession } from '../src/server/worker-backend.ts'
import { makeStore, setupApprovedRun } from './v4-tier-helpers.ts'

process.env.KOVO_ALLOW_LOCAL_LAB = '1'
process.env.KOVO_ALLOW_LOCAL_MODEL = '1'

const ORIGIN_A = 'https://app-o3o5.example.invalid'
const ORIGIN_B = 'https://api-o3o5.example.invalid'

function stubBackend(): WorkerBackend {
  return {
    async run() { return { exitCode: 0, stdout: '{}', stderr: '', outputs: {} } },
    async verifyStaticAst(_aid, req) {
      return { verified: false, engine: req.engine, repo: req.repo, file: req.file, startLine: req.startLine, endLine: req.endLine, matchedLines: [], codeExcerpt: '', matchCount: 0, durationMs: 1 }
    },
    async openSession(): Promise<WorkerSession> {
      return {
        stage: async name => `/evidence/${name}`,
        exec: async () => ({ exitCode: 0, stdout: '', stderr: '', outputs: {} }),
        analyze: async () => ({ ok: true }),
        sast: async req => ({ repo: req.repo, enginesRun: [], engineStatus: {}, findings: [], totalFindings: 0, truncated: false, durationMs: 1 }),
        runScript: async req => ({ runtime: req.runtime, exitCode: 0, stdout: '', stderr: '', durationMs: 1, timedOut: false }),
        verifyStaticAst: async req => ({ verified: false, engine: req.engine, repo: req.repo, file: req.file, startLine: req.startLine, endLine: req.endLine, matchedLines: [], codeExcerpt: '', matchCount: 0, durationMs: 1 }),
        close: async () => undefined,
      }
    },
  }
}

function makeBroker(): RequestBroker {
  return new RequestBroker({
    resolve: async () => [{ address: '93.184.216.34', family: 4 }],
    transport: async () => ({ status: 200, headers: { 'content-type': 'application/json' }, body: '{"ok":true}' }),
  })
}

async function startCountingMockLlmServer(
  t: { after: (fn: () => void | Promise<void>) => void },
): Promise<{ endpoint: string; getCallCount: () => number }> {
  let calls = 0
  const server: Server = createServer((_req, res) => {
    calls += 1
    res.statusCode = 200
    res.setHeader('Content-Type', 'text/event-stream')
    const text = JSON.stringify({ newSteps: [], cancelStepIds: [], done: false })
    const emit = (event: string, data: Record<string, unknown>) => {
      res.write(`event: ${event}\ndata: ${JSON.stringify(data)}\n\n`)
    }
    emit('response.created', { type: 'response.created', response: { id: `resp_${calls}`, status: 'in_progress', output: [] } })
    emit('response.output_item.added', { type: 'response.output_item.added', output_index: 0, item: { id: `item_${calls}`, type: 'message', status: 'in_progress', role: 'assistant', content: [] } })
    emit('response.output_text.done', { type: 'response.output_text.done', output_index: 0, item_id: `item_${calls}`, content_index: 0, text })
    emit('response.output_item.done', { type: 'response.output_item.done', output_index: 0, item: { id: `item_${calls}`, type: 'message', status: 'completed', role: 'assistant', content: [{ type: 'output_text', text }] } })
    emit('response.completed', {
      type: 'response.completed',
      response: {
        id: `resp_${calls}`,
        status: 'completed',
        output: [{ id: `item_${calls}`, type: 'message', status: 'completed', role: 'assistant', content: [{ type: 'output_text', text }] }],
        usage: { input_tokens: 40, output_tokens: 20, total_tokens: 60 },
      },
    })
    res.end()
  })
  await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve))
  const port = (server.address() as AddressInfo).port
  t.after(() => new Promise<void>(resolve => server.close(() => resolve())))
  return { endpoint: `http://127.0.0.1:${port}/v1`, getCallCount: () => calls }
}

// ============================================================================
// 1. Unified resolveAssignmentBudget (fixes live budget-override silent clamp)
// ============================================================================

test('resolveAssignmentBudget keeps full 120–180s wallClockMs for multiStep race/BOLA/cross-persona steps without silent clamp', () => {
  // Multi-step race assignment with 160s specialist wall-clock & 85s single-step cap must NOT clamp to 85s or 120s.
  const raceBudget = resolveAssignmentBudget(
    {
      title: 'Concurrent coupon redemption race burst · POST /api/v1/coupons/redeem',
      hypothesis: 'Send parallel burst requests to test double-spend conservation.',
      category: 'business-logic',
      skills: ['bola-idor-race'],
      dependsOnFactIds: [],
      dependsOnStepIds: [],
    },
    {
      baseMaxTurns: 25,
      baseWallClockMs: 160_000,
      runDurationMs: 900_000,
      singleStepWallClockMs: 85_000,
    },
  )
  assert.equal(raceBudget.budgetClass, 'multi_step')
  assert.equal(raceBudget.kind, 'chain')
  assert.equal(raceBudget.wallClockMs, 160_000, 'multiStep race budget must stay 160s, never clamped to 85s or 120s')
  assert.ok(raceBudget.wallClockMs >= CHAIN_ASSIGNMENT_MIN_WALL_CLOCK_MS && raceBudget.wallClockMs <= CHAIN_ASSIGNMENT_MAX_WALL_CLOCK_MS)
  assert.ok(raceBudget.maxTurns >= MULTI_STEP_ASSIGNMENT_MIN_TURNS && raceBudget.maxTurns <= MULTI_STEP_ASSIGNMENT_MAX_TURNS)
  assert.equal(raceBudget.wallClockSettlementMs, resolveWorkerSettlementMs(160_000, false))

  // Cross-persona BOLA matrix with oversized baseWallClockMs caps cleanly at CHAIN_ASSIGNMENT_MAX_WALL_CLOCK_MS (240s).
  const bolaBudget = resolveAssignmentBudget(
    {
      title: 'Cross-persona BOLA/IDOR matrix · app.example · resource:invoiceId',
      hypothesis: 'Replay invoice resources across personas.',
      category: 'broken-access-control',
      skills: ['bola-idor-race', 'false-positive-elimination'],
    },
    {
      baseMaxTurns: 28,
      baseWallClockMs: CHAIN_ASSIGNMENT_MAX_WALL_CLOCK_MS + 20_000,
      runDurationMs: 900_000,
      singleStepWallClockMs: 120_000,
    },
  )
  assert.equal(bolaBudget.budgetClass, 'multi_step')
  assert.equal(bolaBudget.wallClockMs, CHAIN_ASSIGNMENT_MAX_WALL_CLOCK_MS)

  // Multi-hop chain scales proportionally (30% of runDurationMs, 180s..300s) with 25s / 0.82 settlement.
  const multiHopBudget = resolveAssignmentBudget(
    {
      title: 'Source audit composite chain · Outbound/SSRF -> Signing/Webhook -> Terminal Impact',
      hypothesis: '[chain_hops=4] [lane=chain] Composite workflow (4 stages)',
      skills: ['multihop-chains', 'chain-primitives'],
    },
    {
      baseMaxTurns: 30,
      baseWallClockMs: 160_000,
      runDurationMs: 1_200_000,
      singleStepWallClockMs: 85_000,
    },
  )
  assert.equal(multiHopBudget.budgetClass, 'multi_hop_chain')
  assert.equal(multiHopBudget.wallClockMs, MULTI_HOP_CHAIN_MAX_WALL_CLOCK_MS)
  assert.equal(multiHopBudget.wallClockSettlementMs, resolveWorkerSettlementMs(MULTI_HOP_CHAIN_MAX_WALL_CLOCK_MS, true))

  // Default runDurationMs yields 240s for multi_hop_chain.
  const defaultMultiHop = resolveAssignmentBudget(
    { budgetClass: 'multi_hop_chain' },
    { baseMaxTurns: 25, baseWallClockMs: 120_000 },
  )
  assert.equal(defaultMultiHop.wallClockMs, MULTI_HOP_CHAIN_DEFAULT_WALL_CLOCK_MS)

  // Standalone single-step & det_lead upgrade stay strictly capped at singleStepWallClockMs & 18 turns.
  const singleBudget = resolveAssignmentBudget(
    {
      title: 'det_lead upgrade · sqli_boolean POST /api/orders/:id',
      hypothesis: 'Reproduce and chain it into a higher-impact finding.',
      category: 'injection',
      skills: ['injection-sqli-nosqli'],
    },
    {
      baseMaxTurns: 25,
      baseWallClockMs: 160_000,
      singleStepWallClockMs: 90_000,
    },
  )
  assert.equal(classifyAssignmentBudgetClass({ title: 'det_lead upgrade · sqli_boolean POST /api/orders/:id' }), 'single_step')
  assert.equal(singleBudget.budgetClass, 'single_step')
  assert.equal(singleBudget.kind, 'single_step')
  assert.equal(singleBudget.maxTurns, SINGLE_STEP_ASSIGNMENT_MAX_TURNS)
  assert.equal(singleBudget.wallClockMs, 90_000)

  // Explicit run-level wallClockOverrideMs overrides cleanly without ad-hoc post-mutation.
  const overridden = resolveAssignmentBudget(
    { budgetClass: 'multi_step' },
    { baseMaxTurns: 25, baseWallClockMs: 160_000, wallClockOverrideMs: 42_000 },
  )
  assert.equal(overridden.wallClockMs, 42_000)
  assert.equal(overridden.wallClockSettlementMs, resolveWorkerSettlementMs(42_000, false))
  assert.equal(SINGLE_STEP_ASSIGNMENT_WALL_CLOCK_MS, 120_000)
})

// ============================================================================
// 2. Unified Typed FrontierDispatcher (typed metadata, EVI, white-box + anti-starvation)
// ============================================================================

test('FrontierDispatcher honors typed routing metadata, ranks by live EVI, and prioritizes white-box without starving runtime chains', () => {
  // Typed lane bypasses regex-soup inversion (title mentions "race" and "chain", but stamped lane is business_logic).
  const typedBiz: DispatchLaneStep = {
    id: 'typed-biz',
    seq: 1,
    priority: 75,
    title: 'Investigate race chain wording on invoice quota',
    hypothesis: 'Check quantity invariant.',
    lane: 'business_logic',
    originSource: 'planner',
    sourceOrigins: [ORIGIN_A],
  }
  assert.equal(classifyDispatchLane(typedBiz), 'business_logic')

  // EVI wave ranking: FrontierWaveController branch EVI lifts high-EVI chain ahead of lower-EVI chain.
  const controller = new FrontierWaveController({ beamWidth: 8 })
  const makeBranch = (key: string, capId: string, endpoint: string, feasibilityProb: number, terminalImpactWeight: number): FrontierBranch => ({
    branchKey: key,
    depth: 3,
    verifiedHops: [{
      hopIndex: 1,
      hopReceiptId: `hr_${key}`,
      capabilityId: capId,
      kind: 'signing_material',
      surface: 'webhook',
      serviceOrigin: ORIGIN_A,
      tenantScope: 'org_a',
      actorPersona: 'member_b',
      endpoint,
      method: 'POST',
      summary: `Branch ${key}`,
    }],
    nextTarget: {
      targetSurfaceKey: `${ORIGIN_B}|http|${endpoint}`,
      surface: 'http',
      serviceOrigin: ORIGIN_B,
      endpoint,
      method: 'POST',
      hypothesisClass: 'broken-access-control',
      goalSummary: `Reach ${endpoint}`,
    },
    feasibilityProb,
    terminalImpactWeight,
    surfaceNovelty: 1.6,
    attemptsOnBranch: 0,
    consecutiveFailedAttempts: 0,
    lane: 'partial_chain',
    createdWave: 1,
    lastUpdatedWave: 1,
  })
  controller.admitBranches([
    makeBranch('low-evi', 'cap:hop_low:sig', '/api/v1/low-evi', 0.35, 5.0),
    makeBranch('high-evi', 'cap:hop_high:sig', '/api/v1/high-evi', 0.92, 9.8),
  ])

  const dispatcher = new FrontierDispatcher({ controller })
  const lowEviStep: DispatchLaneStep = {
    id: 'chain-low',
    seq: 1,
    priority: 95,
    title: 'Runtime composite chain · low branch',
    hypothesis: '[lane=chain] [cap=cap:hop_low:sig] Low EVI branch across origins',
    skills: ['multihop-chains', 'runtime-composite-chain'],
    sourceOrigins: [ORIGIN_A, ORIGIN_B],
  }
  const highEviStep: DispatchLaneStep = {
    id: 'chain-high',
    seq: 2,
    priority: 85,
    title: 'Runtime composite chain · high branch',
    hypothesis: '[lane=chain] [cap=cap:hop_high:sig] High EVI branch across origins',
    skills: ['multihop-chains', 'runtime-composite-chain'],
    sourceOrigins: [ORIGIN_A, ORIGIN_B],
  }
  const eviPlan = dispatcher.dispatch([lowEviStep, highEviStep], 2)
  assert.equal(eviPlan.ordered[0]!.id, 'chain-high', 'higher-EVI branch from FrontierWaveController must dispatch first')
  assert.equal(eviPlan.eviRankedCount, 2)
  assert.ok(eviPlan.waveSelection, 'FrontierDispatcher must invoke FrontierWaveController.selectNextWave')

  // White-box priority without starving runtime/grey-box chains when white-box steps saturate all slots.
  const wbSteps: DispatchLaneStep[] = [1, 2, 3, 4].map(i => ({
    id: `wb-${i}`,
    seq: i,
    priority: 94 - i,
    title: `Source audit verify · /v1/internal/op-${i}`,
    hypothesis: `Source-First Code Audit suspect at services/api/op-${i}.ts:${i * 10}`,
    skills: ['source-first-audit'],
    sourceOrigins: [ORIGIN_A],
    originSource: 'whitebox_code_audit',
  }))
  const runtimeChain: DispatchLaneStep = {
    id: 'rt-chain-1',
    seq: 5,
    priority: 90,
    title: 'Runtime composite chain · Producer -> Consumer -> Cross-Boundary Pivot',
    hypothesis: '[chain_hops=3] [lane=chain] [evi=7.40] api_dependency:sessionToken cross_origin_edge',
    skills: ['multihop-chains', 'runtime-composite-chain', 'api-dependency'],
    sourceOrigins: [ORIGIN_A, ORIGIN_B],
    lane: 'chain',
    originSource: 'runtime_chain',
    evi: 7.4,
    hopDepth: 3,
  }
  const genericBb: DispatchLaneStep = {
    id: 'bb-route',
    seq: 6,
    priority: 99,
    title: 'Surface investigation · /v1/generic',
    hypothesis: 'Generic black-box route probe',
    sourceOrigins: [ORIGIN_A],
  }

  const saturatedWbPlan = dispatchFrontierWave([...wbSteps, runtimeChain, genericBb], 3, {
    sourceMounted: true,
    leadCap: DET_LEAD_CONCURRENT_CAP,
  })
  assert.equal(saturatedWbPlan.ordered.length, 3)
  assert.equal(saturatedWbPlan.whiteBoxSelected, 2, 'top 2 white-box steps take priority slots')
  assert.equal(saturatedWbPlan.runtimeChainReserved, 1, '1 slot reserved so white-box backlog never starves ready runtime chain')
  assert.deepEqual(
    saturatedWbPlan.ordered.map(s => s.id),
    ['wb-1', 'wb-2', 'rt-chain-1'],
    'white-box steps lead while runtime chain avoids starvation and generic black-box waits',
  )
})

// ============================================================================
// 3. LLM Planner Storm Gating (pure gate + live ExecReconPlanner integration)
// ============================================================================

test('shouldInvokeLlmPlanner gates saturated queues and wakes immediately on milestones or low buffer', () => {
  assert.deepEqual(
    shouldInvokeLlmPlanner({
      roundNo: 2,
      readyStepCount: 14,
      activeWorkerCount: 4,
      waveBufferTarget: 12,
      newConfirmedFindings: 0,
      newCrossOriginCapabilities: 0,
      openProofGaps: 0,
    }),
    { invokeLlm: false, reason: 'queue_saturated_deferred' },
  )

  assert.deepEqual(
    shouldInvokeLlmPlanner({
      roundNo: 2,
      readyStepCount: 16,
      activeWorkerCount: 4,
      waveBufferTarget: 12,
      newConfirmedFindings: 1,
    }),
    { invokeLlm: true, reason: 'milestone_confirmed_finding' },
  )

  assert.deepEqual(
    shouldInvokeLlmPlanner({
      roundNo: 2,
      readyStepCount: 16,
      activeWorkerCount: 4,
      waveBufferTarget: 12,
      newCrossOriginCapabilities: 1,
    }),
    { invokeLlm: true, reason: 'milestone_cross_origin_capability' },
  )

  assert.deepEqual(
    shouldInvokeLlmPlanner({
      roundNo: 3,
      readyStepCount: 4,
      activeWorkerCount: 2,
      waveBufferTarget: 12,
    }),
    { invokeLlm: true, reason: 'queue_below_buffer' },
  )

  assert.deepEqual(
    shouldInvokeLlmPlanner({
      roundNo: 2,
      readyStepCount: 0,
      activeWorkerCount: 0,
      waveBufferTarget: 12,
    }),
    { invokeLlm: true, reason: 'queue_draining' },
  )
})

test('ExecReconPlanner.runChainPlanner defers redundant LLM calls when ready queue is saturated and wakes once drained', async (t) => {
  const { storage } = makeStore(t, 'kovo-o3o5-gate-')
  const llm = await startCountingMockLlmServer(t)
  const profiles: ResolvedModelProfile[] = [{
    id: 'o3o5-mock-profile',
    name: 'Mock O3O5 Planner',
    endpoint: llm.endpoint,
    protocol: 'responses',
    model: 'mock-flash',
    enabled: true,
    priority: 100,
    key: 'sk-test-o3o5',
    contextWindow: 128_000,
    maxTokens: 4096,
    thinkingLevel: 'medium',
    roleAffinity: 'tactical',
    inputCostPerMtok: 0,
    outputCostPerMtok: 0,
    cachedInputCostPerMtok: 0,
    healthState: 'closed',
    cooldownUntil: null,
    lastError: null,
  }]

  const { runId } = await setupApprovedRun(storage, { seeds: [ORIGIN_A], tier: 2 })
  storage.updateRun(runId, { phase: 'investigation', status: 'running', workerConcurrency: 4 })
  const run = storage.run(runId)
  const asset = run.candidates.find(c => run.approved.includes(c.id))!

  // Saturate ready queue with 14 steps (>= waveBufferTarget=12)
  const seededIds: string[] = []
  for (let i = 0; i < 14; i += 1) {
    const step = storage.addChainStep(run, {
      title: `Ready route check ${i + 1}`,
      hypothesis: `Verify /api/v1/items/${i + 1}`,
      category: 'broken-access-control',
      priority: 80,
      targetAssetIds: [asset.id],
      skills: ['bola-idor-race'],
      sourceOrigins: [ORIGIN_A],
    })
    seededIds.push(step.id)
  }

  const exec = new Execution(storage, {
    broker: makeBroker(),
    backend: stubBackend(),
    deterministicSweep: false,
  })
  t.after(() => exec.stop())

  const priv = exec as unknown as {
    reconPlanner: ExecReconPlanner
    plannerTasks: Map<string, { controller: AbortController; goalRevision: number; scopeRevision: number }>
  }
  const task1 = { controller: new AbortController(), goalRevision: run.goalRevision, scopeRevision: run.scopeRevision }
  priv.plannerTasks.set(runId, task1)
  await priv.reconPlanner.runChainPlanner(storage.run(runId), profiles, task1)
  priv.plannerTasks.delete(runId)

  assert.equal(llm.getCallCount(), 0, 'saturated queue must gate out the 10-turn LLM planner call')
  const events = storage.eventsAfter(runId, 0, 50)
  assert.ok(events.some(e => e.kind === 'planner.llm_gated'), 'must emit planner.llm_gated telemetry event')

  // Drain ready steps below waveBufferTarget (mark 12 of 14 complete) -> LLM planner must now wake up.
  for (const id of seededIds.slice(0, 12)) {
    storage.updateChainStep(id, { status: 'complete' })
  }
  const task2 = { controller: new AbortController(), goalRevision: run.goalRevision, scopeRevision: run.scopeRevision }
  priv.plannerTasks.set(runId, task2)
  await priv.reconPlanner.runChainPlanner(storage.run(runId), profiles, task2)
  priv.plannerTasks.delete(runId)

  assert.ok(llm.getCallCount() >= 1, 'draining queue below waveBufferTarget must wake LLM planner')
})

// ============================================================================
// 4. code_audit_suspect conversion + typed ChainHop ingestion
// ============================================================================

test('code_audit_suspects convert into multi-hop Wave-1 steps and ingest as typed ChainHop artifacts', async (t) => {
  const { storage } = makeStore(t, 'kovo-o3o5-ledger-')
  const { run } = await setupApprovedRun(storage, { seeds: [ORIGIN_A, ORIGIN_B], tier: 2 })
  const assetA = run.candidates.find(c => c.origin === ORIGIN_A)!
  const auditor = storage.makeWorker(run, 'threat_model', assetA, 'Audit', 'Audit', { sourceOrigins: [ORIGIN_A, ORIGIN_B] })

  const fSsrf = storage.addFact(run, auditor, {
    kind: 'code_audit_suspect',
    origin: ORIGIN_A,
    summary: 'Outbound render endpoint POST /api/v1/render follows redirects to internal signer.',
    data: {
      subkind: 'code_audit_suspect',
      file: 'services/renderer/fetch.ts',
      line: 40,
      routeOrAction: 'POST /api/v1/render',
      sinkKind: 'outbound_fetch',
    },
  })
  const fWebhook = storage.addFact(run, auditor, {
    kind: 'code_audit_suspect',
    origin: ORIGIN_B,
    summary: 'Webhook signer POST /internal/sign generates HMAC signatures with weak validation.',
    data: {
      subkind: 'code_audit_suspect',
      file: 'services/webhooks/sign.ts',
      line: 82,
      routeOrAction: 'POST /internal/sign',
      sinkKind: 'webhook',
    },
  })

  // 1. convertCodeAuditSuspectsToChainSteps emits one targeted step per suspect with sibling leads.
  const wbSteps = convertCodeAuditSuspectsToChainSteps(storage, run, [fSsrf, fWebhook], undefined, {
    maxSteps: CODE_AUDIT_WAVE1_MAX_STEPS,
    promoteMultiHop: true,
  })
  assert.equal(wbSteps.length, 2)
  assert.ok(wbSteps.every(step => step.skills.includes('multihop-chains')), 'multi-hop promotion tags every Wave-1 suspect step')
  const ssrfStep = wbSteps.find(step => step.dependsOnFactIds[0] === fSsrf.id)
  assert.ok(ssrfStep)
  assert.ok(ssrfStep.dependsOnFactIds.includes(fWebhook.id), 'cross-service sibling lead is attached as a parent fact')

  // 2. extractChainHops ingests code_audit_suspect facts as opaque typed hops for the World Graph planner.
  const hops = extractChainHops({ facts: [fSsrf, fWebhook], findings: [], endpoints: [] })
  const ssrfHop = hops.find(h => h.artifactKind === 'ssrf_redirect_target')
  assert.ok(ssrfHop)
  assert.equal(ssrfHop.endpoint, '/api/v1/render')
  assert.equal(ssrfHop.method, 'POST')
  const signerHop = hops.find(h => h.artifactKind === 'token_ref')
  assert.ok(signerHop)
  assert.equal(signerHop.origin, ORIGIN_B)
  assert.ok(/^(?:secret|jwt|finding):/.test(signerHop.artifactRef), 'signing hops stay opaque handles')
})

// ============================================================================
// 5. RunOrchestrationStateStore single-call cleanup (unit + live Execution)
// ============================================================================

test('RunOrchestrationStateStore.disposeRun atomically cancels timers/controllers and evicts all per-run state without touching sibling runs', async (t) => {
  const store = new RunOrchestrationStateStore()
  let timerACanceled = false
  let timerBCanceled = false
  let unsubACalled = false
  const authCtrlA = new AbortController()
  const authCtrlB = new AbortController()
  const laneCtrlA = new AbortController()

  const timersView = store.mapView('plannerTimerCancel')
  const dirtyView = store.setView('plannerDirty')
  const authView = store.mapView('runAuthInFlight')
  const laneView = store.mapView('agenticLaneJob')
  const stallTurnsView = store.mapView('providerStallTurns')
  const prePhaseView = store.prefixedMapView<boolean, 'prePhase0SeededSteps'>('prePhase0SeededSteps', ':')
  const leadsSeededView = store.prefixedSetView('programGraphLeadsSeeded', '\0')

  timersView.set('run-a', () => { timerACanceled = true })
  timersView.set('run-b', () => { timerBCanceled = true })
  dirtyView.add('run-a')
  dirtyView.add('run-b')
  authView.set('run-a', authCtrlA)
  authView.set('run-b', authCtrlB)
  laneView.set('run-a', { controller: laneCtrlA, promise: Promise.resolve(), key: 'run-a:1:1', assignmentId: 'a1' })
  stallTurnsView.set('run-a', 7)
  stallTurnsView.set('run-b', 3)
  prePhaseView.set('run-a:1:1', true)
  prePhaseView.set('run-b:1:1', true)
  leadsSeededView.add('run-a\0hyp-1')
  leadsSeededView.add('run-b\0hyp-2')
  store.ensure('run-a').runLifecycleUnsub = () => { unsubACalled = true }
  store.ensure('run-a').stepIds = new Set(['step-a1'])
  store.ensure('run-a').detLeadConsumedIds = new Set(['fact-a1'])

  const evictedSteps: string[] = []
  const evictedFacts: string[] = []
  const disposed = store.disposeRun('run-a', {
    onStepIds: ids => evictedSteps.push(...ids),
    onDetLeadConsumedIds: ids => evictedFacts.push(...ids),
  })

  assert.equal(disposed, true)
  assert.equal(timerACanceled, true, 'planner timer for run-a must be canceled')
  assert.equal(timerBCanceled, false, 'sibling run-b timer must stay untouched')
  assert.equal(authCtrlA.signal.aborted, true, 'in-flight auth controller for run-a must abort')
  assert.equal(authCtrlB.signal.aborted, false, 'sibling run-b auth controller must stay active')
  assert.equal(laneCtrlA.signal.aborted, true, 'active floor lane controller for run-a must abort')
  assert.equal(unsubACalled, true, 'run-a lifecycle unsubscribe must fire')
  assert.deepEqual(evictedSteps, ['step-a1'])
  assert.deepEqual(evictedFacts, ['fact-a1'])

  assert.equal(store.has('run-a'), false, 'run-a record must be completely deleted in one call')
  assert.equal(store.has('run-b'), true, 'sibling run-b record must remain intact')
  assert.equal(dirtyView.has('run-a'), false)
  assert.equal(stallTurnsView.get('run-a'), undefined)
  assert.equal(prePhaseView.has('run-a:1:1'), false)
  assert.equal(leadsSeededView.has('run-a\0hyp-1'), false)
  assert.equal(dirtyView.has('run-b'), true)
  assert.equal(stallTurnsView.get('run-b'), 3)
  assert.equal(prePhaseView.get('run-b:1:1'), true)
  assert.equal(leadsSeededView.has('run-b\0hyp-2'), true)

  // Live Execution.disposeRun single-call cleanup verification.
  const { storage } = makeStore(t, 'kovo-o3o5-dispose-')
  const { runId } = await setupApprovedRun(storage, { seeds: [ORIGIN_A], tier: 2 })
  const exec = new Execution(storage, {
    broker: makeBroker(),
    backend: stubBackend(),
    deterministicSweep: false,
  })
  t.after(() => exec.stop())

  exec.runState.ensure(runId).providerStallTurns = 5
  exec.runState.ensure(runId).plannerDirty = true
  exec.frontierControllerFor(runId)
  assert.ok(exec.getRunOrchestrationState(runId), 'run orchestration state must exist while run is active')

  await exec.disposeRun(runId, { terminalState: 'canceled', reason: 'o3o5 test cleanup' })
  assert.equal(exec.getRunOrchestrationState(runId), undefined, 'Execution.disposeRun must evict RunOrchestrationState in one call')
  assert.equal(exec.runState.has(runId), false)
})
