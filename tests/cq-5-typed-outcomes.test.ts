/**
 * CQ-5 (`typed-terminal-outcomes-and-loss-accounting`) + Tier-2 Q6
 * (`FrontierWaveController` authority & lossless hop-continuation handoffs) tests.
 */
import assert from 'node:assert/strict'
import { createServer, type Server } from 'node:http'
import type { AddressInfo } from 'node:net'
import { test } from 'node:test'
import { eq } from 'drizzle-orm'

import {
  classifyExtendedFailure,
  classifyFailure,
  classifyProductAttribution,
  extractProductSignalsForTarget,
  productAttributionBuckets,
  type ProductEventRecord,
} from '../benchmarks/realistic-bench/grader/attribution.ts'
import { RequestBroker } from '../src/server/broker.ts'
import { formatDerivedCapabilityHandle } from '../src/server/capability-ledger.ts'
import {
  FLOOR_INTENT_PRIORITY,
  UNIFIED_FLOOR_CLASS_QUOTAS,
  computeFloorClassQuotas,
  runDeterministicEngine,
  type EngineEndpoint,
} from '../src/server/deterministic-engine.ts'
import {
  FrontierWaveController,
  MAX_RETRYABLE_STEP_RETRIES,
  classifyWorkerErrorToStepStatus,
  dispatchableReadySteps,
  isRetryableChainStepStatus,
  isTerminalChainStepStatus,
  mapSessionStatusToStepStatus,
  passOneCoverage,
  permanentlyBlockedStepIds,
  reinvestigationKey,
  resolveAssignmentBudget,
  structuredCoverageKey,
} from '../src/server/exec-dispatch.ts'
import type { ExecFloorLane } from '../src/server/exec-floor-lane.ts'
import type { ExecReconPlanner } from '../src/server/exec-recon-planner.ts'
import type { ExecWorkerRunner } from '../src/server/exec-worker-runner.ts'
import { Execution } from '../src/server/execution.ts'
import type { ResolvedModelProfile } from '../src/server/model-settings.ts'
import {
  chainStepRetryableStatuses,
  chainStepTerminalStatuses,
  coverageEntries,
  events,
  findings,
} from '../src/server/schema.ts'
import type { WorkerBackend, WorkerSession } from '../src/server/worker-backend.ts'
import { makeLabGrant, makeStore, setupApprovedRun } from './v4-tier-helpers.ts'

process.env.KOVO_ALLOW_LOCAL_LAB = '1'
process.env.KOVO_ALLOW_LOCAL_MODEL = '1'

const ORIGIN = 'https://cq5-app.example.invalid'

function stubBackend(): WorkerBackend {
  return {
    async run() { return { exitCode: 0, stdout: '{}', stderr: '', outputs: {} } },
    async verifyStaticAst(_aid, req) {
      return {
        verified: false, engine: req.engine, repo: req.repo, file: req.file,
        startLine: req.startLine, endLine: req.endLine, matchedLines: [],
        codeExcerpt: '', matchCount: 0, durationMs: 1,
      }
    },
    async openSession(): Promise<WorkerSession> {
      return {
        stage: async name => `/evidence/${name}`,
        exec: async () => ({ exitCode: 0, stdout: '', stderr: '', outputs: {} }),
        analyze: async () => ({ ok: true }),
        sast: async req => ({ repo: req.repo, enginesRun: [], engineStatus: {}, findings: [], totalFindings: 0, truncated: false, durationMs: 1 }),
        runScript: async req => ({ runtime: req.runtime, exitCode: 0, stdout: '', stderr: '', durationMs: 1, timedOut: false }),
        verifyStaticAst: async req => ({
          verified: false, engine: req.engine, repo: req.repo, file: req.file,
          startLine: req.startLine, endLine: req.endLine, matchedLines: [],
          codeExcerpt: '', matchCount: 0, durationMs: 1,
        }),
        close: async () => undefined,
      }
    },
  }
}

function internals(engine: Execution) {
  return engine as unknown as {
    reconPlanner: ExecReconPlanner
    workerRunner: ExecWorkerRunner
    floorLane: ExecFloorLane
    wallClockRotatedAssignments: Set<string>
    active: Map<string, { assignment: unknown; origins: Set<string>; controller: AbortController; stallAbort?: boolean }>
    plannerTasks: Map<string, { controller: AbortController; goalRevision: number; scopeRevision: number }>
  }
}

async function startCustomLlmServer(
  t: { after: (fn: () => void | Promise<void>) => void },
  responseText: () => string,
): Promise<{ endpoint: string; getCalls: () => number }> {
  let calls = 0
  const server: Server = createServer((_req, res) => {
    calls += 1
    const text = responseText()
    res.statusCode = 200
    res.setHeader('Content-Type', 'text/event-stream')
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
  return { endpoint: `http://127.0.0.1:${port}/v1`, getCalls: () => calls }
}

// ============================================================================
// 1. Typed terminal chain-step statuses & worker-runner mapping
// ============================================================================

test('CQ-5.1: typed terminal statuses are defined, mapped accurately, and treated as terminal by scheduler', () => {
  for (const status of ['infra_failed', 'turn_capped', 'nudged_out', 'rotated_partial', 'model_failure', 'complete'] as const) {
    assert.ok((chainStepTerminalStatuses as readonly string[]).includes(status), `missing terminal status ${status}`)
    assert.equal(isTerminalChainStepStatus(status), true, `${status} must be terminal`)
  }
  assert.deepEqual([...chainStepRetryableStatuses].sort(), ['nudged_out', 'turn_capped'])
  assert.equal(isRetryableChainStepStatus('turn_capped'), true)
  assert.equal(isRetryableChainStepStatus('nudged_out'), true)
  assert.equal(isRetryableChainStepStatus('infra_failed'), false)
  assert.equal(isRetryableChainStepStatus('rotated_partial'), false)
  assert.equal(isRetryableChainStepStatus('model_failure'), false)

  assert.equal(mapSessionStatusToStepStatus('completed'), 'complete')
  assert.equal(mapSessionStatusToStepStatus('turn_limit'), 'turn_capped')
  assert.equal(mapSessionStatusToStepStatus('nudged_out'), 'nudged_out')
  assert.equal(mapSessionStatusToStepStatus('wall_clock_rotated'), 'rotated_partial')

  assert.equal(classifyWorkerErrorToStepStatus(new Error('OpenRouter 429 rate limit exceeded')), 'model_failure')
  assert.equal(classifyWorkerErrorToStepStatus(new Error('Provider stream stalled (no token)')), 'model_failure')
  assert.equal(classifyWorkerErrorToStepStatus(new Error('Docker daemon container start ECONNREFUSED')), 'infra_failed')

  const steps = [
    { id: 's-ready', status: 'ready', dependsOnStepIds: [] },
    { id: 's-infra', status: 'infra_failed', dependsOnStepIds: [] },
    { id: 's-model', status: 'model_failure', dependsOnStepIds: [] },
    { id: 's-cap', status: 'turn_capped', dependsOnStepIds: [] },
    { id: 's-nudge', status: 'nudged_out', dependsOnStepIds: [] },
    { id: 's-rot', status: 'rotated_partial', dependsOnStepIds: [] },
    { id: 's-dep-infra', status: 'pending', dependsOnStepIds: ['s-infra'] },
    { id: 's-dep-model', status: 'pending', dependsOnStepIds: ['s-model'] },
  ]
  const blocked = permanentlyBlockedStepIds(steps)
  assert.deepEqual(blocked.sort(), ['s-dep-infra', 's-dep-model'])
  const ready = dispatchableReadySteps(steps)
  assert.deepEqual(ready.map(s => s.id), ['s-ready'], 'only non-terminal ready work is dispatchable')
})

test('CQ-5.1b: ExecWorkerRunner.handleInvestigationWorkerError sets exact typed terminal statuses & emits worker.step_terminal', async t => {
  const { storage } = makeStore(t, 'kovo-cq5-worker-err-')
  const { runId, run } = await setupApprovedRun(storage, { seeds: [ORIGIN], tier: 2 })
  const asset = run.candidates.find(c => run.approved.includes(c.id))!
  const engine = new Execution(storage, { backend: stubBackend() })
  t.after(() => engine.stop())
  const { workerRunner, wallClockRotatedAssignments, active } = internals(engine)
  const budget = resolveAssignmentBudget(
    { title: 'Test step', hypothesis: 'Probe route', category: 'broken-access-control' },
    { baseMaxTurns: 18, baseWallClockMs: 60_000, runDurationMs: 600_000, singleStepWallClockMs: 60_000 },
  )

  // (a) Stall after retry -> model_failure
  const sStall = storage.addChainStep(run, { title: 'Stall step', hypothesis: 'Probe /api/a', targetAssetIds: [asset.id], sourceOrigins: [ORIGIN] })
  const wStall = storage.updateWorker(
    storage.makeWorker(run, 'investigation', asset, sStall.title, sStall.hypothesis, { stepId: sStall.id, sourceOrigins: [ORIGIN] }).id,
    { status: 'running', attempt: 1 },
  )!
  const jobStall = { assignment: wStall, origins: new Set([ORIGIN]), controller: new AbortController(), stallAbort: true }
  active.set(wStall.id, jobStall)
  workerRunner.handleInvestigationWorkerError(
    run,
    jobStall,
    sStall, 'bola-bfla-specialist', budget, new Error('Provider stream stalled'),
  )
  assert.equal(storage.listChainSteps(runId).find(s => s.id === sStall.id)?.status, 'model_failure')

  // (b) Pre-session wall-clock rotation -> rotated_partial
  const sRot = storage.addChainStep(run, { title: 'Rot step', hypothesis: 'Probe /api/b', targetAssetIds: [asset.id], sourceOrigins: [ORIGIN] })
  const wRot = storage.updateWorker(
    storage.makeWorker(run, 'investigation', asset, sRot.title, sRot.hypothesis, { stepId: sRot.id, sourceOrigins: [ORIGIN] }).id,
    { status: 'running' },
  )!
  const jobRot = { assignment: wRot, origins: new Set([ORIGIN]), controller: new AbortController() }
  active.set(wRot.id, jobRot)
  wallClockRotatedAssignments.add(wRot.id)
  workerRunner.handleInvestigationWorkerError(
    run,
    jobRot,
    sRot, 'bola-bfla-specialist', budget, new Error('Pre-session wall-clock deadline reached'),
  )
  assert.equal(storage.listChainSteps(runId).find(s => s.id === sRot.id)?.status, 'rotated_partial')

  storage.updateRun(runId, { status: 'running', phase: 'investigation' })
  const activeRun = storage.run(runId)
  // (c) Infrastructure error -> infra_failed
  const sInfra = storage.addChainStep(activeRun, { title: 'Infra step', hypothesis: 'Probe /api/c', targetAssetIds: [asset.id], sourceOrigins: [ORIGIN] })
  const wInfra = storage.updateWorker(
    storage.makeWorker(activeRun, 'investigation', asset, sInfra.title, sInfra.hypothesis, { stepId: sInfra.id, sourceOrigins: [ORIGIN] }).id,
    { status: 'running', lease: 'lease-infra', leaseExpiresAt: Date.now() + 60_000 },
  )!
  const jobInfra = { assignment: wInfra, origins: new Set([ORIGIN]), controller: new AbortController() }
  active.set(wInfra.id, jobInfra)
  workerRunner.handleInvestigationWorkerError(
    activeRun,
    jobInfra,
    sInfra, 'bola-bfla-specialist', budget, new Error('Container sandbox exec EPIPE'),
  )
  assert.equal(storage.listChainSteps(runId).find(s => s.id === sInfra.id)?.status, 'infra_failed')

  const terminalEvents = storage.db.select().from(events).where(eq(events.runId, runId)).all()
    .filter(e => e.kind === 'worker.step_terminal')
  const statuses = terminalEvents.map(e => e.detail.stepStatus)
  assert.ok(statuses.includes('model_failure'))
  assert.ok(statuses.includes('rotated_partial'))
  assert.ok(statuses.includes('infra_failed'))
})

// ============================================================================
// 2. Structured (origin, METHOD, route, class) coverage (no prose parsing!)
// ============================================================================

test('CQ-5.2: passOneCoverageFor counts ONLY proved/gap_coded completions and ignores prose-mentioned routes', async t => {
  const { storage } = makeStore(t, 'kovo-cq5-coverage-')
  const { runId, run } = await setupApprovedRun(storage, { seeds: [ORIGIN], tier: 2 })
  const asset = run.candidates.find(c => run.approved.includes(c.id))!
  const engine = new Execution(storage, { backend: stubBackend() })
  t.after(() => engine.stop())
  const { reconPlanner } = internals(engine)

  const anchorWorker = storage.makeWorker(run, 'investigation', asset, 'Anchor', 'Seed facts', { sourceOrigins: [ORIGIN] })
  // Seed two Tier-A program_graph leads
  storage.addFact(run, anchorWorker, {
    kind: 'note', origin: ORIGIN, summary: 'Tier-A lead 1',
    data: {
      producer: 'host_planner', source: 'program_graph', kind: 'det_lead',
      endpoint: '/api/v1/orders', method: 'GET', probeClass: 'sqli',
      codeSlice: { hops: [{ file: 'orders.ts', line: 10 }] },
    },
    sourceOrigins: [ORIGIN],
  })
  storage.addFact(run, anchorWorker, {
    kind: 'note', origin: ORIGIN, summary: 'Tier-A lead 2',
    data: {
      producer: 'host_planner', source: 'program_graph', kind: 'det_lead',
      endpoint: '/api/v1/admin/export', method: 'POST', probeClass: 'bfla',
      codeSlice: { hops: [{ file: 'admin.ts', line: 22 }] },
    },
    sourceOrigins: [ORIGIN],
  })

  // Step A: turn_capped on GET /api/v1/orders (must NOT count as covered!)
  const stepCapped = storage.addChainStep(run, {
    title: 'Investigate orders',
    hypothesis: 'Mentions /api/v1/admin/export in prose only, actually bound to /api/v1/orders',
    category: 'injection-input',
    targetAssetIds: [asset.id],
    sourceOrigins: [ORIGIN],
  })
  reconPlanner.registerStepTargets(runId, stepCapped.id, [
    { origin: ORIGIN, method: 'GET', route: '/api/v1/orders', vulnClass: 'injection-input' },
  ])
  const wCapped = storage.makeWorker(run, 'investigation', asset, stepCapped.title, stepCapped.hypothesis, { stepId: stepCapped.id, sourceOrigins: [ORIGIN] })
  storage.updateChainStep(stepCapped.id, { status: 'turn_capped', assignedWorkerId: wCapped.id })

  // Step B: ready step bound to POST /api/v1/admin/export
  const stepReady = storage.addChainStep(run, {
    title: 'Investigate admin export',
    hypothesis: 'Test BFLA on admin export',
    category: 'broken-access-control',
    targetAssetIds: [asset.id],
    sourceOrigins: [ORIGIN],
  })
  reconPlanner.registerStepTargets(runId, stepReady.id, [
    { origin: ORIGIN, method: 'POST', route: '/api/v1/admin/export', vulnClass: 'broken-access-control' },
  ])

  // Neither step is proved or gap_coded -> BOTH Tier-A endpoints stay uncovered!
  const covBefore = reconPlanner.passOneCoverageFor(run, storage.listChainSteps(runId))
  assert.deepEqual(covBefore.uncoveredTierAEndpoints, ['GET /api/v1/orders', 'POST /api/v1/admin/export'])
  assert.equal(covBefore.uninvestigatedFirstPassClasses.length, 1)
  assert.equal(
    covBefore.uninvestigatedFirstPassClasses[0],
    structuredCoverageKey({ origin: ORIGIN, method: 'POST', route: '/api/v1/admin/export', vulnClass: 'broken-access-control' }),
  )

  // Now complete Step A with a coded proof gap in `coverageEntries` -> ONLY its structured target
  // (GET /api/v1/orders) becomes covered; prose-mentioned /api/v1/admin/export stays uncovered!
  storage.updateChainStep(stepCapped.id, { status: 'complete', assignedWorkerId: wCapped.id })
  storage.db.insert(coverageEntries).values({
    id: 'cov-gap-1',
    runId,
    scopeRevision: run.scopeRevision,
    goalRevision: run.goalRevision,
    origin: ORIGIN,
    category: 'injection-input',
    status: 'ruled_out',
    summary: 'Parameterized query verified',
    proofGapReason: 'control_blocked_cleanly',
    assignmentId: wCapped.id,
    updatedAt: Date.now(),
  }).run()

  const covAfterGap = reconPlanner.passOneCoverageFor(run, storage.listChainSteps(runId))
  assert.deepEqual(
    covAfterGap.uncoveredTierAEndpoints,
    ['POST /api/v1/admin/export'],
    'prose-mentioned /api/v1/admin/export must NEVER be covered by a step structurally bound to /api/v1/orders',
  )

  // Direct unit check on passOneCoverage: covered=false is never covered even if dispatched=true
  const direct = passOneCoverage({
    tierAEndpoints: ['GET /api/v1/items'],
    steps: [
      {
        id: 's1', dispatchable: false, dispatched: true, covered: false,
        structuredTargets: [{ origin: ORIGIN, method: 'GET', route: '/api/v1/items', vulnClass: 'authz' }],
        routes: ['/api/v1/items'], keys: [structuredCoverageKey({ origin: ORIGIN, method: 'GET', route: '/api/v1/items', vulnClass: 'authz' })],
      },
    ],
  })
  assert.deepEqual(direct.uncoveredTierAEndpoints, ['GET /api/v1/items'])
})

test('CQ-5.2b: queueHighRiskCoverageSteps uses structured (origin, METHOD, route, class) exclusion and paginates >80 endpoints', async t => {
  const { storage } = makeStore(t, 'kovo-cq5-highrisk-')
  const { runId, run } = await setupApprovedRun(storage, { seeds: [ORIGIN], tier: 2 })
  const asset = run.candidates.find(c => run.approved.includes(c.id))!
  const engine = new Execution(storage, { backend: stubBackend() })
  t.after(() => engine.stop())
  const { reconPlanner } = internals(engine)

  // Add 85 endpoints: 84 low-risk (risk 30) + 1 high-risk at #85 (risk 85) and another high-risk
  // route where SQLi (different class!) is already confirmed.
  for (let i = 0; i < 84; i += 1) {
    storage.upsertEndpoint({ runId, origin: ORIGIN, method: 'GET', pathTemplate: `/api/v1/low/${i}`, source: 'spa_crawl', riskScore: 30 })
  }
  storage.upsertEndpoint({ runId, origin: ORIGIN, method: 'GET', pathTemplate: '/api/v1/orders', source: 'spa_crawl', riskScore: 90 })
  storage.upsertEndpoint({ runId, origin: ORIGIN, method: 'POST', pathTemplate: '/api/v1/orders', source: 'spa_crawl', riskScore: 88 })

  // Record SQLi on GET /api/v1/orders with a real replay spec -> must NOT exclude broken-access-control on GET /api/v1/orders!
  const floorWorker = storage.makeWorker(run, 'investigation', asset, 'Floor', 'Floor pass', { sourceOrigins: [ORIGIN] })
  const sqliSpec = storage.createReplaySpec(run, floorWorker, 'f-sqli-orders', {
    version: 1,
    origin: ORIGIN,
    title: 'SQLi on GET /api/v1/orders',
    category: 'injection-input',
    cwe: 'CWE-89',
    severity: 'high',
    severityRationale: 'Boolean differential confirmed',
    impact: 'SQL injection',
    remediation: 'Parameterize query',
    recheckInstructions: 'Replay GET /api/v1/orders',
    kind: 'http_chain',
    spaCatchallControl: false,
    assertionsJq: '{ controlPassed: true, confirmed: true, observed: "diff", expected: "bound" }',
    steps: [
      { id: 'ctrl', role: 'control', description: 'Control', request: { origin: ORIGIN, method: 'GET', pathAndQuery: '/api/v1/orders?q=1', followRedirects: false } },
      { id: 'prb', role: 'probe', description: 'Probe', request: { origin: ORIGIN, method: 'GET', pathAndQuery: '/api/v1/orders?q=2', followRedirects: false } },
    ],
  }, [ORIGIN])
  storage.db.insert(findings).values({
    id: 'f-sqli-orders',
    runId,
    assetId: asset.id,
    goalRevision: run.goalRevision,
    checkId: 'chain',
    caseId: 'sqli-orders',
    findingKind: 'multi_step_chain',
    replaySpecId: sqliSpec.id,
    provenance: 'floor',
    verificationClass: 'static_advisory',
    sourceOrigins: [ORIGIN],
    finding: {
      id: 'f-sqli-orders',
      title: 'SQLi on GET /api/v1/orders',
      severity: 'high',
      category: 'injection-input',
      cwe: 'CWE-89',
      origin: ORIGIN,
      checkId: 'chain',
      caseId: 'sqli-orders',
      findingKind: 'multi_step_chain',
      status: 'static_verified',
      confidence: 'high',
      impact: 'SQL injection',
      remediation: 'Parameterize query',
      verification: 'Replay confirmed',
      reason: 'Boolean diff confirmed',
      evidenceIds: [],
      exchangeIds: [],
      scopeRevision: run.scopeRevision,
      severityRationale: 'High severity SQLi',
      recheckInstructions: 'Replay GET /api/v1/orders',
    } as never,
  }).run()

  // Record broken-access-control on POST /api/v1/orders -> SHOULD exclude POST /api/v1/orders!
  const bacSpec = storage.createReplaySpec(run, floorWorker, 'f-bac-orders-post', {
    version: 1,
    origin: ORIGIN,
    title: 'BFLA on POST /api/v1/orders',
    category: 'broken-access-control',
    cwe: 'CWE-862',
    severity: 'high',
    severityRationale: 'Cross-role mutation confirmed',
    impact: 'Unauthorized order creation',
    remediation: 'Enforce authorization',
    recheckInstructions: 'Replay POST /api/v1/orders',
    kind: 'http_chain',
    spaCatchallControl: false,
    assertionsJq: '{ controlPassed: true, confirmed: true, observed: "200", expected: "403" }',
    steps: [
      { id: 'ctrl', role: 'control', description: 'Control', request: { origin: ORIGIN, method: 'POST', pathAndQuery: '/api/v1/orders', followRedirects: false } },
      { id: 'prb', role: 'probe', description: 'Probe', request: { origin: ORIGIN, method: 'POST', pathAndQuery: '/api/v1/orders', followRedirects: false } },
    ],
  }, [ORIGIN])
  storage.db.insert(findings).values({
    id: 'f-bac-orders-post',
    runId,
    assetId: asset.id,
    goalRevision: run.goalRevision,
    checkId: 'chain',
    caseId: 'bac-orders-post',
    findingKind: 'multi_step_chain',
    replaySpecId: bacSpec.id,
    provenance: 'floor',
    verificationClass: 'static_advisory',
    sourceOrigins: [ORIGIN],
    finding: {
      id: 'f-bac-orders-post',
      title: 'BFLA on POST /api/v1/orders',
      severity: 'high',
      category: 'broken-access-control',
      cwe: 'CWE-862',
      origin: ORIGIN,
      checkId: 'chain',
      caseId: 'bac-orders-post',
      findingKind: 'multi_step_chain',
      status: 'static_verified',
      confidence: 'high',
      impact: 'Unauthorized order creation',
      remediation: 'Enforce authorization',
      verification: 'Replay confirmed',
      reason: 'Cross-role access confirmed',
      evidenceIds: [],
      exchangeIds: [],
      scopeRevision: run.scopeRevision,
      severityRationale: 'High severity BFLA',
      recheckInstructions: 'Replay POST /api/v1/orders',
    } as never,
  }).run()

  const seeded = reconPlanner.queueHighRiskCoverageSteps(run, new Set([ORIGIN]), 20, [])
  assert.deepEqual(
    seeded.endpoints,
    ['GET /api/v1/orders'],
    'GET /api/v1/orders (confirmed only for SQLi) must be seeded for broken-access-control, while POST /api/v1/orders (confirmed for broken-access-control) is excluded',
  )
})

// ============================================================================
// 3. Strictly bounded single retry (max 1 retry per reinvestigationKey)
// ============================================================================

test('CQ-5.3: maybeRequeueRetryableStep enforces max 1 retry per reinvestigationKey inside step & wall-clock budgets', async t => {
  const { storage } = makeStore(t, 'kovo-cq5-retry-')
  const { runId, run } = await setupApprovedRun(storage, { seeds: [ORIGIN], tier: 2 })
  const asset = run.candidates.find(c => run.approved.includes(c.id))!
  const engine = new Execution(storage, { backend: stubBackend(), maxDurationMs: 600_000 })
  t.after(() => engine.stop())
  const { reconPlanner } = internals(engine)

  assert.equal(MAX_RETRYABLE_STEP_RETRIES, 1)
  storage.updateRun(runId, { phase: 'investigation', status: 'running', dynamicStepBudget: 10 })

  const step1 = storage.addChainStep(run, {
    title: 'BOLA test on GET /api/v1/invoices/:id',
    hypothesis: 'Check cross-tenant read on GET /api/v1/invoices/:id',
    category: 'broken-access-control',
    targetAssetIds: [asset.id],
    sourceOrigins: [ORIGIN],
  })
  reconPlanner.registerStepTargets(runId, step1.id, [
    { origin: ORIGIN, method: 'GET', route: '/api/v1/invoices/:id', vulnClass: 'broken-access-control' },
  ])
  const worker1 = storage.makeWorker(run, 'investigation', asset, step1.title, step1.hypothesis, { stepId: step1.id, sourceOrigins: [ORIGIN] })
  storage.updateChainStep(step1.id, { status: 'turn_capped', assignedWorkerId: worker1.id })

  const first = reconPlanner.maybeRequeueRetryableStep({
    run: storage.run(runId),
    step: { ...step1, status: 'turn_capped', assignedWorkerId: worker1.id },
    assignment: worker1,
    terminalStatus: 'turn_capped',
    targetOrigins: [ORIGIN],
  })
  assert.equal(first.requeued, true)
  assert.equal(first.retryStep?.status, 'ready')
  assert.ok(first.retryStep?.skills.includes('cq5:retry:1'))
  assert.equal(first.retryKey, reinvestigationKey('GET /api/v1/invoices/:id', 'broken-access-control'))

  // Second retry on the same reinvestigationKey MUST be blocked!
  const second = reconPlanner.maybeRequeueRetryableStep({
    run: storage.run(runId),
    step: { ...step1, status: 'nudged_out', assignedWorkerId: worker1.id },
    assignment: worker1,
    terminalStatus: 'nudged_out',
    targetOrigins: [ORIGIN],
  })
  assert.equal(second.requeued, false)
  assert.equal(second.reason, 'retry_cap_reached')

  // Retrying the retry step itself MUST be blocked!
  const retryOfRetry = reconPlanner.maybeRequeueRetryableStep({
    run: storage.run(runId),
    step: first.retryStep!,
    assignment: worker1,
    terminalStatus: 'turn_capped',
    targetOrigins: [ORIGIN],
  })
  assert.equal(retryOfRetry.requeued, false)
  assert.equal(retryOfRetry.reason, 'already_retry_step')

  // Step budget exhausted MUST block retry on a fresh key!
  storage.updateRun(runId, { dynamicStepBudget: 2 })
  const stepBudgeted = storage.addChainStep(run, {
    title: 'Fresh target /api/v1/reports',
    hypothesis: 'Probe /api/v1/reports',
    category: 'injection-input',
    targetAssetIds: [asset.id],
    sourceOrigins: [ORIGIN],
  })
  reconPlanner.registerStepTargets(runId, stepBudgeted.id, [
    { origin: ORIGIN, method: 'GET', route: '/api/v1/reports', vulnClass: 'injection-input' },
  ])
  const blockedByBudget = reconPlanner.maybeRequeueRetryableStep({
    run: storage.run(runId),
    step: { ...stepBudgeted, status: 'turn_capped' },
    assignment: worker1,
    terminalStatus: 'turn_capped',
    targetOrigins: [ORIGIN],
  })
  assert.equal(blockedByBudget.requeued, false)
  assert.equal(blockedByBudget.reason, 'step_budget_exhausted')
})

// ============================================================================
// 4. Structured planner_parse_failed event & 0-hop FrontierWaveController progress
// ============================================================================

test('CQ-5.4 & Q6: runChainPlanner emits planner_parse_failed on invalid JSON and evaluates 0-hop FrontierWaveController wave progress', async t => {
  const { storage } = makeStore(t, 'kovo-cq5-planner-parse-')
  const { runId, run } = await setupApprovedRun(storage, { seeds: [ORIGIN], tier: 2 })
  const asset = run.candidates.find(c => run.approved.includes(c.id))!
  const engine = new Execution(storage, { backend: stubBackend(), maxDurationMs: 600_000 })
  t.after(() => engine.stop())
  const { reconPlanner, plannerTasks } = internals(engine)

  storage.updateRun(runId, { phase: 'investigation', status: 'running', roundNo: 1 })
  // Admit a branch into FrontierWaveController & mark 1 completed worker with 0 hops
  const controller = reconPlanner.frontierControllerFor(runId)
  const admitted = controller.admitStepBranch({
    branchKey: 'wave1:test-0hop',
    depth: 1,
    origin: ORIGIN,
    endpoint: '/api/v1/checkout',
    method: 'POST',
    hypothesisClass: 'workflow',
    goalSummary: 'Test 0-hop wave progression',
  })
  assert.equal(admitted.admitted, true)

  const worker = storage.makeWorker(run, 'investigation', asset, 'W1', 'Obj', { sourceOrigins: [ORIGIN] })
  storage.updateWorker(worker.id, { status: 'complete', outcome: 'Done with 0 hops' })

  // Spy on evaluateWaveProgress to prove it runs even with 0 new hop events
  let evalCalls = 0
  let lastHopCount = -1
  const origEval = controller.evaluateWaveProgress.bind(controller)
  controller.evaluateWaveProgress = (input) => {
    evalCalls += 1
    lastHopCount = input.verifiedHopReceipts?.length ?? 0
    return origEval(input)
  }

  const mockLlm = await startCustomLlmServer(t, () => 'NOT_VALID_JSON {{{ broken')
  const profile: ResolvedModelProfile = {
    id: 'p-test',
    name: 'mock',
    endpoint: mockLlm.endpoint,
    model: 'mock-model',
    protocol: 'responses',
    key: 'test-key',
    priority: 1,
    enabled: true,
    contextWindow: 128_000,
    maxTokens: 4096,
    thinkingLevel: 'off',
    roleAffinity: 'any',
    inputCostPerMtok: 0,
    cachedInputCostPerMtok: 0,
    outputCostPerMtok: 0,
    healthState: 'closed',
    cooldownUntil: null,
    lastError: null,
  }

  const task = { controller: new AbortController(), goalRevision: run.goalRevision, scopeRevision: run.scopeRevision }
  plannerTasks.set(runId, task)
  await reconPlanner.runChainPlanner(storage.run(runId), [profile], task)
  plannerTasks.delete(runId)

  const parseEvents = storage.db.select().from(events).where(eq(events.runId, runId)).all()
    .filter(e => e.kind === 'planner_parse_failed')
  assert.equal(parseEvents.length, 1, 'planner_parse_failed must be emitted instead of silent catch')
  assert.equal(parseEvents[0]!.detail.stage, 'json')
  assert.equal(parseEvents[0]!.detail.degradation, true)
  assert.equal(evalCalls, 1, 'frontierController.evaluateWaveProgress must run even when 0 new hop events occurred')
  assert.equal(lastHopCount, 0)
})

// ============================================================================
// 5. Q6: FrontierWaveController branch admission & lossless continuation handoff
// ============================================================================

test('Q6: FrontierWaveController suppresses pruned Wave-1 branches and preserves lossless hop-continuation handoffs on rotated_partial parents', async t => {
  const { storage } = makeStore(t, 'kovo-cq5-q6-frontier-')
  const { runId, run } = await setupApprovedRun(storage, { seeds: [ORIGIN], tier: 2 })
  const asset = run.candidates.find(c => run.approved.includes(c.id))!
  const engine = new Execution(storage, { backend: stubBackend(), maxDurationMs: 600_000 })
  t.after(() => engine.stop())
  const { reconPlanner } = internals(engine)

  // (a) Dead-end negative edge synced from CapabilityLedger suppresses Wave-1 runtime composite admission
  const ledger = storage.capabilityLedger(runId)
  const controller = reconPlanner.frontierControllerFor(runId)
  ledger.recordNegativeEdge({
    preconditionCapIds: ['cap:seed_pruned'],
    targetSurfaceKey: `${ORIGIN}|http|/api/v1/deadend`,
    hypothesisClass: 'broken-access-control',
    falsifiedByExchangeIds: ['ex-1', 'ex-2'],
    reason: 'control_blocked_cleanly',
    forcePrune: true,
    notes: 'Pruned dead-end branch',
  })
  const suppressed = controller.admitStepBranch({
    branchKey: 'wave1:deadend',
    depth: 1,
    origin: ORIGIN,
    endpoint: '/api/v1/deadend',
    method: 'GET',
    hypothesisClass: 'broken-access-control',
    goalSummary: 'Should be suppressed',
    preconditionCapIds: ['cap:seed_pruned'],
  })
  assert.equal(suppressed.admitted, false, 'FrontierWaveController must suppress dead-end negative-edge branches')

  // (b) Lossless hop continuation from a `rotated_partial` parent step with >14 facts!
  const w1 = storage.makeWorker(run, 'investigation', asset, 'Multi-hop chain', 'Investigate chain', { sourceOrigins: [ORIGIN] })
  const cap1 = formatDerivedCapabilityHandle('q6_1', 'session')
  const cap2 = formatDerivedCapabilityHandle('q6_2', 'signer')
  ledger.addCapability({
    capId: cap1, kind: 'identity_session', provenance: 'attacker_seed',
    tenantScope: 'org_a', actorPersona: 'alice', serviceOrigin: ORIGIN,
    surface: 'http', artifactDigest: 'a'.repeat(64), artifactSummary: 'Seed session', createdAtMs: 1000,
  })
  ledger.addCapability({
    capId: cap2, kind: 'signing_material', provenance: 'derived_hop',
    tenantScope: 'org_a', actorPersona: 'alice', serviceOrigin: ORIGIN,
    surface: 'webhook', artifactDigest: 'b'.repeat(64), artifactSummary: 'Derived signer', createdAtMs: 1100,
  })

  // Create 15 noise facts PLUS a critical hop_checkpoint parent fact at the end
  const noiseFacts = []
  for (let i = 0; i < 15; i += 1) {
    noiseFacts.push(storage.addFact(run, w1, {
      kind: 'note', origin: ORIGIN, summary: `Noise fact ${i}`, data: { idx: i }, sourceOrigins: [ORIGIN],
    }))
  }
  const criticalCapFact = storage.addFact(run, w1, {
    kind: 'note', origin: ORIGIN, summary: `Hop checkpoint carrying ${cap2}`,
    data: { subkind: 'hop_checkpoint', checkpointCapId: cap2 }, sourceOrigins: [ORIGIN],
  })

  const parentStep = storage.addChainStep(run, {
    title: 'Multi-hop chain pivot',
    hypothesis: 'Pivot from Hop 1 to Hop 3 [chain_hops=h1->h2->h3].',
    category: 'broken-access-control',
    priority: 92,
    targetAssetIds: [asset.id],
    dependsOnFactIds: [...noiseFacts.map(f => f.id), criticalCapFact.id],
    sourceOrigins: [ORIGIN],
    skills: ['multihop-chains', 'chain-primitives'],
  })
  // Mark parent step with typed terminal status `rotated_partial` (NOT `complete`!)
  storage.updateChainStep(parentStep.id, { status: 'rotated_partial', assignedWorkerId: w1.id })

  const cont = reconPlanner.enqueueHopContinuationOnRotation({
    run: storage.run(runId),
    step: storage.listChainSteps(runId).find(s => s.id === parentStep.id)!,
    assignment: w1,
    targetOrigins: [ORIGIN],
    confirmed: false,
    partialSummary: '[partial] Sealed signing material before rotation.',
    recordedFacts: [criticalCapFact],
    recordedExchanges: [{ id: 'ex-q6', origin: ORIGIN, method: 'POST', pathAndQuery: '/api/v1/hooks/sign', status: 200 }],
    sealedCapHandles: [cap2],
  })
  assert.equal(cont.enqueued, true)
  assert.equal(
    cont.continuationStep?.status,
    'ready',
    'continuation child of rotated_partial parent must be immediately ready (never stranded in pending)',
  )
  assert.ok(
    cont.continuationStep?.dependsOnFactIds.includes(criticalCapFact.id),
    'critical hop_checkpoint capability fact must be preserved losslessly even with >12 parent facts',
  )
  assert.ok(
    controller.scheduler.getActiveBeam().some(item => item.branch.branchKey.startsWith('cont:')),
    'hop-continuation branch must be admitted through FrontierWaveController',
  )
})

// ============================================================================
// 6. Unified floor quota table, sqli-last ordering, byClassUnprobed & det_lead tail
// ============================================================================

test('CQ-5.4: floor quotas use single unified table (sqli last), emit byClassUnprobed + cappedOut, and persist det_lead tail', async t => {
  // Verify SQLi stays strictly last for 5xx circuit-breaker safety
  const sqliPriority = FLOOR_INTENT_PRIORITY.sqli
  assert.ok(typeof sqliPriority === 'number')
  for (const [cls, prio] of Object.entries(FLOOR_INTENT_PRIORITY)) {
    if (cls === 'sqli') continue
    assert.ok(prio > sqliPriority, `class ${cls} (${prio}) must outrank sqli (${sqliPriority}) for 5xx breaker safety`)
  }

  // Verify unified quota table has no split between formation and runtime execution
  const deep = computeFloorClassQuotas({ maxRequests: 1000, maxHypotheses: 90, breadthFirst: false })
  assert.ok(deep.quotas.xxe >= UNIFIED_FLOOR_CLASS_QUOTAS.xxe)
  assert.ok(deep.quotas.race >= UNIFIED_FLOOR_CLASS_QUOTAS.race)
  assert.ok(deep.quotas.ssrf >= UNIFIED_FLOOR_CLASS_QUOTAS.ssrf)
  assert.ok(deep.quotas.auth_protocol >= UNIFIED_FLOOR_CLASS_QUOTAS.auth_protocol)

  // Run deterministic engine with a tiny request budget so remaining hypotheses hit budget/cap tail
  const endpoints: EngineEndpoint[] = [
    {
      id: 'ep-1', origin: ORIGIN, method: 'GET', pathTemplate: '/api/v1/search',
      params: [{ name: 'q', location: 'query' }, { name: 'sort', location: 'query' }],
      riskScore: 85, source: 'crawl',
    },
    {
      id: 'ep-2', origin: ORIGIN, method: 'GET', pathTemplate: '/api/v1/redirect',
      params: [{ name: 'next', location: 'query' }],
      riskScore: 80, source: 'crawl',
    },
    {
      id: 'ep-3', origin: ORIGIN, method: 'GET', pathTemplate: '/api/v1/files',
      params: [{ name: 'file', location: 'query' }],
      riskScore: 80, source: 'crawl',
    },
  ]
  const broker = new RequestBroker({
    resolve: async () => [{ address: '93.184.216.34', family: 4 }],
    transport: async () => ({ status: 200, headers: { 'content-type': 'application/json' }, body: '{"items":[]}' }),
  })
  const grant = makeLabGrant(ORIGIN, { tier: 2 })
  const report = await runDeterministicEngine({
    runId: 'run-tail-test',
    assignmentId: 'asgn-tail-test',
    signal: new AbortController().signal,
    endpoints,
    personas: [],
    broker,
    grant,
    backend: stubBackend(),
    tier: 2,
    maxRequests: 14,
    maxDurationMs: 10_000,
    maxHypotheses: 30,
    onConfirmed: () => null,
  })

  assert.equal(report.stoppedReason, 'budget')
  assert.ok(report.unprobedTail.length > 0, 'unprobedTail must capture remaining hypotheses when floor stops early')
  assert.ok(Object.keys(report.byClassUnprobed).length > 0, 'byClassUnprobed must report per-class unprobed counts')
  assert.ok(
    report.cappedOut.some(rec => rec.stage === 'budget' && rec.dropped > 0),
    'cappedOut must emit structured { cap, stage, class, kept, dropped } records',
  )

  // Persist unprobed tail into Store as det_lead facts via ExecFloorLane
  const { storage } = makeStore(t, 'kovo-cq5-tail-leads-')
  const { runId, run } = await setupApprovedRun(storage, { seeds: [ORIGIN], tier: 2 })
  const asset = run.candidates.find(c => run.approved.includes(c.id))!
  const worker = storage.makeWorker(run, 'investigation', asset, 'Floor', 'Floor pass', { sourceOrigins: [ORIGIN] })
  const engine = new Execution(storage, { backend: stubBackend() })
  t.after(() => engine.stop())
  const { floorLane } = internals(engine)

  const persisted = floorLane.persistUnprobedTailLeads({
    run,
    assignment: worker,
    unprobedTail: report.unprobedTail,
    secrets: [],
  })
  assert.ok(persisted > 0, 'persistUnprobedTailLeads must persist det_lead facts')
  const tailFacts = storage.listFacts(runId, { includeTainted: false, limit: 100 })
    .filter(f => f.data?.subkind === 'deterministic_engine_unprobed_tail' && f.data?.kind === 'det_lead')
  assert.equal(tailFacts.length, persisted)
})

// ============================================================================
// 7. Attribution funnel buckets (never_dispatched, route_hit_no_verify, verify_rejected, capped_out)
// ============================================================================

test('CQ-5.5: attribution.ts classifies product events into never_dispatched, route_hit_no_verify, verify_rejected, capped_out, and typed terminals', () => {
  assert.ok(productAttributionBuckets.includes('never_dispatched'))
  assert.ok(productAttributionBuckets.includes('route_hit_no_verify'))
  assert.ok(productAttributionBuckets.includes('verify_rejected'))
  assert.ok(productAttributionBuckets.includes('capped_out'))

  const target = { vulnClass: 'sqli', endpoints: [{ method: 'GET', path: '/api/v1/products/search' }] }

  // 1. Proved
  assert.equal(classifyProductAttribution({ confirmed: true, routeHit: true, target }), 'proved')

  // 2. Capped out from deterministic_engine.summary
  const cappedEvents: ProductEventRecord[] = [
    { kind: 'deterministic_engine.summary', detail: { byClassUnprobed: { sqli: 4 }, cappedOut: [{ cap: 10, stage: 'deadline', class: 'sqli', kept: 2, dropped: 4 }] } },
  ]
  assert.equal(classifyProductAttribution({ confirmed: false, routeHit: false, target, events: cappedEvents }), 'capped_out')

  // 3. Never dispatched
  assert.equal(classifyProductAttribution({ confirmed: false, routeHit: false, target, events: [] }), 'never_dispatched')

  // 4. Route hit, no verify
  assert.equal(classifyProductAttribution({ confirmed: false, routeHit: true, target, events: [] }), 'route_hit_no_verify')

  // 5. Verify rejected
  const rejectedEvents: ProductEventRecord[] = [
    { kind: 'agent.script_proof_rejected', detail: { endpoint: '/api/v1/products/search', vulnClass: 'sqli' } },
  ]
  assert.equal(classifyProductAttribution({ confirmed: false, routeHit: true, target, events: rejectedEvents }), 'verify_rejected')

  // 6. Gap coded & typed terminal step statuses from worker.step_terminal
  const gapEvents: ProductEventRecord[] = [
    {
      kind: 'worker.step_terminal',
      detail: {
        stepStatus: 'complete', gapCoded: true,
        targets: [{ origin: ORIGIN, method: 'GET', route: '/api/v1/products/search', vulnClass: 'sqli' }],
      },
    },
  ]
  assert.equal(classifyProductAttribution({ confirmed: false, routeHit: true, target, events: gapEvents }), 'gap_coded')

  const turnCappedEvents: ProductEventRecord[] = [
    {
      kind: 'worker.step_terminal',
      detail: {
        stepStatus: 'turn_capped', gapCoded: false,
        targets: [{ origin: ORIGIN, method: 'GET', route: '/api/v1/products/search', vulnClass: 'sqli' }],
      },
    },
  ]
  assert.equal(extractProductSignalsForTarget(turnCappedEvents, target).terminalStepStatus, 'turn_capped')
  assert.equal(classifyProductAttribution({ confirmed: false, routeHit: true, target, events: turnCappedEvents }), 'turn_capped')

  // 7. classifyExtendedFailure avoids blind replay_spec_miss fallthrough while classifyFailure stays backwards-compatible
  const baseCtx = {
    surfaceDiscovered: true,
    hypothesisFormed: true,
    signalObserved: true,
    hasMatchingFinding: false,
    confirmed: false,
    telemetryExhausted: false,
    tierBlocked: false,
    csrfBlocked: false,
    formEncodingMissing: false,
    contextReset: false,
    triggerMiss: false,
    assertionFailure: false,
  }
  assert.equal(classifyFailure(baseCtx), 'replay_spec_miss')
  assert.equal(classifyExtendedFailure({ ...baseCtx, routeHit: true, verifyAttempted: false }), 'route_hit_no_verify')
  assert.equal(classifyExtendedFailure({ ...baseCtx, verifyRejected: true }), 'verify_rejected')
  assert.equal(classifyExtendedFailure({ ...baseCtx, surfaceDiscovered: false, dispatched: false }), 'never_dispatched')
  assert.equal(classifyExtendedFailure({ ...baseCtx, cappedOut: true, dispatched: false, verifyAttempted: false }), 'capped_out')
})
