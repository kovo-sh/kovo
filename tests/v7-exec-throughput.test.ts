/**
 * v7 execution-throughput — unit & contract tests for Backlog #4 (`execution.ts`):
 *
 *  1. Demoting unstarted trial duplicates (`trialIndex > 0`) strictly behind distinct primary
 *     ready steps across all lanes, and accounting for existing queued trial groups in surplus.
 *  2. Planner coverage assertion for discovered high-risk unconfirmed endpoints (`riskScore >= 60`).
 *  3. Assigned target-route extraction for per-route proof-obligation tracking.
 *  4. Wiring `onProofObligation`, `onGapValidation`, `assignedTargetRoutes`, and `approvedOrigins`
 *     into `Execution` telemetry & `AssignmentThroughputMetrics` (live mock-LLM session, no Docker).
 */
import assert from 'node:assert/strict'
import { test } from 'node:test'
import { coordinatorPlannerPrompt } from '../src/server/agent-session.ts'
import {
  Execution,
  extractAssignedTargetRoutes,
  nextPlannerDryRounds,
  planMultiTrialExpansion,
  planRoundRobinDispatch,
  plannerWaveDispatchCap,
  selectUncoveredHighRiskEndpoints,
} from '../src/server/execution.ts'
import type { DispatchLaneStep } from '../src/server/execution.ts'
import { privateModelProfiles, saveModelProfile } from '../src/server/model-settings.ts'
import type { WorkerBackend, WorkerSession } from '../src/server/worker-backend.ts'
import {
  makeStore,
  setupApprovedRun,
  startHttpFixture,
  startMockLlmServer,
  stopExecution,
  withEnv,
} from './v4-tier-helpers.ts'

const origin = 'https://target.example.invalid'

function step(id: string, overrides: Partial<DispatchLaneStep> = {}): DispatchLaneStep {
  return {
    id,
    seq: Number(id.replace(/\D+/g, '')) || 1,
    priority: 80,
    title: `Step ${id}`,
    category: 'broken-access-control',
    hypothesis: `Investigate /api/v1/resource/${id}`,
    skills: [],
    dependsOnFactIds: [],
    dependsOnStepIds: [],
    sourceOrigins: [origin],
    trialIndex: 0,
    ...overrides,
  }
}

test('planRoundRobinDispatch demotes unstarted trial duplicates strictly behind all distinct primary ready steps', () => {
  const steps: DispatchLaneStep[] = [
    // High-priority duplicate trial (priority 100, trialIndex 1 & 2) must NOT displace lower-priority primary hypotheses!
    step('t1-primary', { seq: 1, priority: 100, trialIndex: 0 }),
    step('t1-dup-1', { seq: 2, priority: 100, trialIndex: 1 }),
    step('t1-dup-2', { seq: 3, priority: 100, trialIndex: 2 }),
    step('primary-workflow', { seq: 4, priority: 60, category: 'business-logic', title: 'Workflow check', trialIndex: 0 }),
    step('primary-route', { seq: 5, priority: 55, title: 'Another route check', trialIndex: 0 }),
    step('primary-lead', { seq: 6, priority: 50, title: 'det_lead upgrade · /api/v1/items', trialIndex: 0 }),
  ]

  // With 4 slots: all 4 distinct primary steps (including lead) must win before any duplicate trial.
  const fourSlots = planRoundRobinDispatch(steps, 4)
  assert.equal(fourSlots.ordered.length, 4)
  assert.ok(
    fourSlots.ordered.every(entry => (entry.trialIndex ?? 0) === 0),
    `expected only primary steps in 4 slots, got: ${fourSlots.ordered.map(s => `${s.id}(t=${s.trialIndex})`).join(', ')}`,
  )

  // With 6 slots: the 2 surplus slots are filled by the duplicate trials AFTER all 4 primary steps.
  const sixSlots = planRoundRobinDispatch(steps, 6)
  assert.equal(sixSlots.ordered.length, 6)
  assert.deepEqual(
    sixSlots.ordered.slice(4).map(entry => entry.id),
    ['t1-dup-1', 't1-dup-2'],
    'duplicate trials fill only surplus capacity after distinct primary hypotheses',
  )
})

test('planMultiTrialExpansion subtracts existing queued trial-group steps from surplus slots', () => {
  const steps = [
    // Existing queued 2-trial group already occupies 2 of 3 slots.
    { id: 'g1-0', status: 'ready' as const, priority: 96, trialGroupId: 'grp-1', dependsOnFactIds: [], dependsOnStepIds: [] },
    { id: 'g1-1', status: 'ready' as const, priority: 96, trialGroupId: 'grp-1', dependsOnFactIds: [], dependsOnStepIds: [] },
    // One fresh hypothesis takes the 3rd slot -> 0 surplus left!
    { id: 'fresh-1', status: 'ready' as const, priority: 96, trialGroupId: null, dependsOnFactIds: [], dependsOnStepIds: [] },
  ]
  assert.deepEqual(planMultiTrialExpansion({ steps, concurrency: 3 }), [])
  // With concurrency 5 (2 surplus slots), fresh-1 expands cleanly up to 3 trials.
  const expanded = planMultiTrialExpansion({ steps, concurrency: 5 })
  assert.equal(expanded.length, 1)
  assert.equal(expanded[0]?.step.id, 'fresh-1')
  assert.equal(expanded[0]?.fanout, 3)
})

test('selectUncoveredHighRiskEndpoints filters risk >= 60, skips confirmed/covered routes, and ranks deterministically', () => {
  const endpoints = [
    { origin, method: 'POST', pathTemplate: '/api/v1/transfers', riskScore: 85, coveragePct: 0 },
    { origin, method: 'GET', pathTemplate: '/api/v1/reports/:id', riskScore: 72, coveragePct: 10 },
    { origin, method: 'POST', pathTemplate: '/api/v1/confirmed-route', riskScore: 95, coveragePct: 100 },
    { origin, method: 'PATCH', pathTemplate: '/api/v1/already-planned', riskScore: 90, coveragePct: 0 },
    { origin, method: 'GET', pathTemplate: '/api/v1/low-risk', riskScore: 45, coveragePct: 0 },
    { origin: 'https://other.invalid', method: 'POST', pathTemplate: '/api/v1/foreign', riskScore: 99, coveragePct: 0 },
  ]
  const picked = selectUncoveredHighRiskEndpoints({
    endpoints,
    approvedOrigins: new Set([origin]),
    confirmedPaths: new Set(['/api/v1/confirmed-route']),
    coveredRoutes: new Set(['/api/v1/already-planned']),
    minRisk: 60,
    limit: 6,
  })
  assert.deepEqual(
    picked.map(ep => `${ep.method} ${ep.pathTemplate}`),
    ['POST /api/v1/transfers', 'GET /api/v1/reports/:id'],
  )
})

test('extractAssignedTargetRoutes merges parent fact endpoints and step-mentioned routes without duplicates', () => {
  const routes = extractAssignedTargetRoutes({
    title: 'Investigate /api/v1/wallets/:id balance invariant',
    hypothesis: 'Check POST /api/v1/wallets/42/redeem and GET /api/v1/wallets/:id',
    parentFacts: [
      { origin, data: { kind: 'det_lead', method: 'POST', endpoint: '/api/v1/wallets/:id/redeem' } },
    ],
    defaultOrigin: origin,
  })
  assert.equal(routes.length, 3)
  assert.ok(routes.some(r => r.method === 'POST' && r.path === '/api/v1/wallets/:id/redeem'))
  assert.ok(routes.some(r => r.path === '/api/v1/wallets/:id'))
})

test('Execution wires onProofObligation, onGapValidation, and assignedTargetRoutes into run events and throughput metrics', async (t) => {
  const fx = await startHttpFixture(t, (_req, _b, res) => {
    res.statusCode = 403
    res.setHeader('Content-Type', 'application/json')
    res.end(JSON.stringify({ error: 'forbidden' }))
  })
  let calls = 0
  const llm = await startMockLlmServer(t, call => {
    calls += 1
    const bodyText = JSON.stringify(call.body.input ?? '')
    if (calls === 1) {
      return {
        type: 'tool_call',
        callId: 'call_req_1',
        name: 'request_http',
        argumentsJson: JSON.stringify({ origin: fx.origin, method: 'GET', pathAndQuery: '/api/v1/admin/settings' }),
      }
    }
    if (!bodyText.includes('call_cov_1')) {
      return {
        type: 'tool_call',
        callId: 'call_cov_1',
        name: 'record_coverage',
        argumentsJson: JSON.stringify({
          origin: fx.origin,
          category: 'broken-access-control',
          status: 'blocked',
          summary: 'Admin settings returned 403.',
          proofGapReason: 'auth_blocked',
          route: '/api/v1/admin/settings',
          method: 'GET',
        }),
      }
    }
    return {
      type: 'tool_call',
      callId: `call_done_${calls}`,
      name: 'complete_intent',
      argumentsJson: JSON.stringify({ status: 'ruled_out', summary: 'Endpoint returned 403 auth_blocked.' }),
    }
  })

  const backend: WorkerBackend = {
    async run() { return { exitCode: 0, stdout: '{}', stderr: '', outputs: {} } },
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
    async verifyStaticAst(_aid, req) {
      return { verified: false, engine: req.engine, repo: req.repo, file: req.file, startLine: req.startLine, endLine: req.endLine, matchedLines: [], codeExcerpt: '', matchCount: 0, durationMs: 1 }
    },
  }

  const { storage } = makeStore(t)
  await saveModelProfile({
    name: 'Throughput-Mock', endpoint: llm.endpoint, model: 'mock-t', protocol: 'responses', key: 'sk-mock-tp-1234',
    priority: 100, enabled: true, contextWindow: 128_000, maxTokens: 4096, thinkingLevel: 'medium', roleAffinity: 'tactical',
    inputCostPerMtok: 0, cachedInputCostPerMtok: 0, outputCostPerMtok: 0,
  }, storage, { skipConnectionCheck: true })

  const { runId, run } = await setupApprovedRun(storage, { seeds: [fx.origin] })
  storage.addChainStep(run, {
    title: 'Check /api/v1/admin/settings access boundary',
    hypothesis: 'Probe GET /api/v1/admin/settings for unauthorized access.',
    category: 'broken-access-control',
    priority: 80,
    targetAssetIds: run.approved,
    sourceOrigins: [fx.origin],
  })
  storage.updateRun(runId, { phase: 'investigation', status: 'running', workerConcurrency: 1, multiTrialEnabled: false })

  const engine = new Execution(storage, { backend, deterministicSweep: false })
  await withEnv({ GUARDIAN_ALLOW_LOCAL_LAB: '1' }, async () => {
    engine.start()
    engine.wake()
    const deadline = Date.now() + 8_000
    while (Date.now() < deadline) {
      const evs = storage.client.prepare('SELECT kind FROM events WHERE run_id = ?').all(runId) as Array<{ kind: string }>
      if (evs.some(e => e.kind === 'agent.proof_obligation') && evs.some(e => e.kind === 'agent.gap_validation')) break
      await new Promise(r => setTimeout(r, 40))
    }
    await stopExecution(engine as never)
  })

  const events = storage.client.prepare('SELECT kind FROM events WHERE run_id = ?').all(runId) as Array<{ kind: string }>
  assert.ok(events.some(e => e.kind === 'agent.proof_obligation'), 'expected agent.proof_obligation run event')
  assert.ok(events.some(e => e.kind === 'agent.gap_validation'), 'expected agent.gap_validation run event')
})

test('nextPlannerDryRounds ignores Round 1 and mid-wave rounds with 0 newly completed workers while preserving DRY_ROUND_LIMIT', () => {
  // Round 1 seeds Wave 1 before any agent worker has completed -> never counts as dry.
  assert.equal(nextPlannerDryRounds({
    roundNo: 1, previousDryRounds: 0, newRuntimeConfirmed: 0, newChainPrimitives: 0,
    completedInvestigations: 1, previousCompletedInvestigations: 1,
  }), 0)
  // Round 2 mid-wave with zero newly completed investigation assignments -> keeps previousDryRounds.
  assert.equal(nextPlannerDryRounds({
    roundNo: 2, previousDryRounds: 0, newRuntimeConfirmed: 0, newChainPrimitives: 0,
    completedInvestigations: 1, previousCompletedInvestigations: 1,
  }), 0)
  // Round 2 after completed agentic work with no frontier progress -> increments to 1.
  assert.equal(nextPlannerDryRounds({
    roundNo: 2, previousDryRounds: 0, newRuntimeConfirmed: 0, newChainPrimitives: 0,
    completedInvestigations: 4, previousCompletedInvestigations: 1,
  }), 1)
  // Mid-wave Round 3 with no additional completions -> stays at 1 (no false kill).
  assert.equal(nextPlannerDryRounds({
    roundNo: 3, previousDryRounds: 1, newRuntimeConfirmed: 0, newChainPrimitives: 0,
    completedInvestigations: 4, previousCompletedInvestigations: 4,
  }), 1)
  // Next completed wave with no frontier progress -> hits DRY_ROUND_LIMIT (2).
  assert.equal(nextPlannerDryRounds({
    roundNo: 4, previousDryRounds: 1, newRuntimeConfirmed: 0, newChainPrimitives: 0,
    completedInvestigations: 8, previousCompletedInvestigations: 4,
  }), 2)
  // Any new confirmation or chain primitive resets to 0.
  assert.equal(nextPlannerDryRounds({
    roundNo: 4, previousDryRounds: 1, newRuntimeConfirmed: 1, newChainPrimitives: 0,
    completedInvestigations: 8, previousCompletedInvestigations: 4,
  }), 0)
})

test('plannerWaveDispatchCap buffers 2 waves (>= 12 or maxConc * 2) and coordinatorPlannerPrompt hints 12 hypotheses', () => {
  assert.equal(plannerWaveDispatchCap(6, 40), 12)
  assert.equal(plannerWaveDispatchCap(8, 40), 16)
  assert.equal(plannerWaveDispatchCap(4, 40), 12)
  assert.equal(plannerWaveDispatchCap(6, 7), 7)
  const prompt = coordinatorPlannerPrompt({
    goal: 'verify api', roundNo: 1, capabilityTier: 2, approvedOrigins: [origin],
    budgetRemaining: { usd: 2, requests: 500 }, dynamicStepBudget: 40, pendingOob: 0, chainSteps: [],
  })
  assert.match(prompt, /up to 12 diverse unconfirmed hypotheses/i)
})

test('runChainPlanner buffers 2 waves on Round 1 and never increments dryRounds on Round 1 or 0-completion mid-wave Round 2', async (t) => {
  const llm = await startMockLlmServer(t, () => ({
    type: 'text',
    text: JSON.stringify({
      done: false,
      summary: 'Seeded initial hypotheses.',
      cancelStepIds: [],
      newSteps: [
        {
          title: 'Workflow step 1',
          hypothesis: 'Probe POST /api/v1/orders/checkout workflow invariant.',
          category: 'business-logic',
          priority: 85,
          origins: [origin],
          skills: ['business-logic-chains'],
          dependsOnFactIds: [],
          dependsOnStepIds: [],
        },
      ],
    }),
  }))
  const { storage } = makeStore(t)
  await saveModelProfile({
    name: 'Planner-Wave-Mock', endpoint: llm.endpoint, model: 'mock-wave', protocol: 'responses', key: 'sk-mock-wave-1234',
    priority: 100, enabled: true, contextWindow: 128_000, maxTokens: 4096, thinkingLevel: 'medium', roleAffinity: 'tactical',
    inputCostPerMtok: 0, cachedInputCostPerMtok: 0, outputCostPerMtok: 0,
  }, storage, { skipConnectionCheck: true })

  const { runId, run } = await setupApprovedRun(storage, { seeds: [origin] })
  storage.updateRun(runId, { phase: 'investigation', status: 'running', workerConcurrency: 6, multiTrialEnabled: false })
  for (let i = 1; i <= 14; i += 1) {
    storage.upsertEndpoint({
      runId, scopeRevision: run.scopeRevision, origin, method: 'POST',
      pathTemplate: `/api/v1/resource-${i}/action`, source: 'openapi', riskScore: 80 - i,
    })
  }

  const engine = new Execution(storage, { deterministicSweep: false })
  const profiles = privateModelProfiles(storage)
  const priv = engine as unknown as {
    runChainPlanner: (r: ReturnType<typeof storage.run>, p: typeof profiles, task: { controller: AbortController; goalRevision: number }) => Promise<void>
    plannerDoneRound: Map<string, number>
  }

  // Round 1: should top up to 2 waves (12 steps) with dryRounds = 0.
  const task1 = { controller: new AbortController(), goalRevision: run.goalRevision }
  await priv.runChainPlanner(storage.run(runId), profiles, task1)
  const stepsAfterR1 = storage.listChainSteps(runId, run.goalRevision)
  assert.ok(stepsAfterR1.length >= 12, `expected 2-wave buffer (>=12 steps) on Round 1, got ${stepsAfterR1.length}`)
  const dryEventsAfterR1 = storage.eventsAfter(runId, 0, 200).filter(e => e.kind === 'planner.dry_rounds')
  assert.equal(dryEventsAfterR1.at(-1)?.detail?.consecutiveDryRounds, 0, 'Round 1 must never increment dryRounds')
  assert.equal(priv.plannerDoneRound.has(runId), false)

  // Round 2 mid-wave (0 newly completed investigation assignments): must stay at dryRounds = 0.
  const task2 = { controller: new AbortController(), goalRevision: run.goalRevision }
  await priv.runChainPlanner(storage.run(runId), profiles, task2)
  const dryEventsAfterR2 = storage.eventsAfter(runId, 0, 200).filter(e => e.kind === 'planner.dry_rounds')
  assert.equal(dryEventsAfterR2.at(-1)?.detail?.consecutiveDryRounds, 0, 'mid-wave Round 2 with 0 new completions must not increment dryRounds')
  assert.equal(priv.plannerDoneRound.has(runId), false)

  // Now simulate completed investigation workers without new confirmations across Rounds 3 & 4 -> dryRounds hits 1 then 2.
  const asset = storage.run(runId).candidates[0]!
  const w1 = storage.makeWorker(storage.run(runId), 'investigation', asset, 'Completed wave 1', 'done')
  storage.updateWorker(w1.id, { status: 'complete', outcome: 'no finding' })
  await priv.runChainPlanner(storage.run(runId), profiles, { controller: new AbortController(), goalRevision: run.goalRevision })
  const dryEventsAfterR3 = storage.eventsAfter(runId, 0, 200).filter(e => e.kind === 'planner.dry_rounds')
  assert.equal(dryEventsAfterR3.at(-1)?.detail?.consecutiveDryRounds, 1, 'completed wave without progress increments dryRounds to 1')

  const w2 = storage.makeWorker(storage.run(runId), 'investigation', asset, 'Completed wave 2', 'done')
  storage.updateWorker(w2.id, { status: 'complete', outcome: 'no finding' })
  await priv.runChainPlanner(storage.run(runId), profiles, { controller: new AbortController(), goalRevision: run.goalRevision })
  const dryEventsAfterR4 = storage.eventsAfter(runId, 0, 200).filter(e => e.kind === 'planner.dry_rounds')
  assert.equal(dryEventsAfterR4.at(-1)?.detail?.consecutiveDryRounds, 2, 'second completed dry wave reaches DRY_ROUND_LIMIT=2')
})
