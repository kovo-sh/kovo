/**
 * v8 Phase-B slot starvation & hard `wallClockMs` worker rotation tests.
 *
 * Proves (zero Docker, real SQLite WAL `Store`, real `Execution`, real `runAgentSession`,
 * synthetic mock LLM server):
 *  1. `resolveEffectivePhaseBConcurrency` prevents `slots=1` starvation when >= 3 distinct
 *     primary steps are ready and budget/RPS headroom allow parallel slots, while honoring
 *     tight budgets/RPS and small queues.
 *  2. `planRoundRobinDispatch` reserves dedicated frontier slots for ready multi-hop / depth >= 2
 *     `chain_step`s so synthesized chains dispatch immediately ahead of single-route BOLA sweeps.
 *  3. Live `Execution` with `workerConcurrency=1` and 10 ready steps (including 4 multi-hop
 *     chains) emits `scheduler.dispatch` with `slots >= 3` (`effectiveConcurrency >= 3`) and
 *     schedules multi-hop chains immediately without starvation.
 *  4. `runAgentSession` enforces `wallClockMs` as a real per-assignment `AbortController` timer:
 *     - stalled LLM stream with `wallClockMs=150` aborts cleanly in `< 400ms`;
 *     - active `kovo_verify` call gets its bounded grace window to finish before rotation;
 *     - final wall-clock settlement nudge fires at `max(wallClockMs - 15_000, wallClockMs * 0.8)`.
 *  5. Live `Execution` with a stalled specialist (`wallClockMs=150`) emits
 *     `worker.wall_clock_rotated`, frees its slot within `< 400ms`, and immediately dispatches
 *     the next queued step into the released slot.
 */
import assert from 'node:assert/strict'
import { createServer, type Server } from 'node:http'
import type { AddressInfo } from 'node:net'
import { test } from 'node:test'

import {
  runAgentSession,
  wallClockSettlementMessage,
  wallClockSettlementMs,
} from '../src/server/agent-session.ts'
import {
  DET_LEAD_CONCURRENT_CAP,
  Execution,
  PHASE_B_MIN_CONCURRENCY_FLOOR,
  isMultiHopChainStep,
  planRoundRobinDispatch,
  resolveEffectivePhaseBConcurrency,
  type DispatchLaneStep,
} from '../src/server/execution.ts'
import { saveModelProfile } from '../src/server/model-settings.ts'
import type { WorkerBackend, WorkerSession } from '../src/server/worker-backend.ts'
import { makeStore, setupApprovedRun, stopExecution, withEnv } from './v4-tier-helpers.ts'

process.env.KOVO_ALLOW_LOCAL_LAB = '1'
process.env.KOVO_ALLOW_LOCAL_MODEL = '1'

const ORIGIN = 'https://target.example.invalid'

function makeStep(id: string, overrides: Partial<DispatchLaneStep> = {}): DispatchLaneStep {
  return {
    id,
    seq: Number(id.replace(/\D+/g, '')) || 1,
    priority: 80,
    title: `Single-route BOLA sweep ${id}`,
    category: 'broken-access-control',
    hypothesis: `Probe GET /api/v1/items/${id} across personas.`,
    skills: ['bola-bfla'],
    dependsOnFactIds: [],
    dependsOnStepIds: [],
    sourceOrigins: [ORIGIN],
    trialIndex: 0,
    ...overrides,
  }
}

function stubBackend(): WorkerBackend {
  return {
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
}

interface CustomLlmResponse {
  delayMs?: number
  hang?: boolean
  toolCall?: { callId: string; name: string; argumentsJson: string }
  text?: string
}

async function startCustomMockLlmServer(
  t: { after: (fn: () => void | Promise<void>) => void },
  handler: (body: Record<string, unknown>, reqIndex: number) => CustomLlmResponse,
): Promise<{ endpoint: string; calls: Array<Record<string, unknown>> }> {
  const calls: Array<Record<string, unknown>> = []
  const timers = new Set<NodeJS.Timeout>()
  const server: Server = createServer((req, res) => {
    const chunks: Buffer[] = []
    req.on('data', chunk => chunks.push(chunk as Buffer))
    req.on('end', () => {
      const body = JSON.parse(Buffer.concat(chunks).toString('utf8') || '{}') as Record<string, unknown>
      calls.push(body)
      const reply = handler(body, calls.length)
      if (reply.hang) {
        // Intentionally hold the HTTP stream open until the client aborts or server closes.
        res.on('close', () => { if (!res.writableEnded) res.end() })
        return
      }
      const send = () => {
        if (res.destroyed || res.writableEnded) return
        res.statusCode = 200
        res.setHeader('Content-Type', 'text/event-stream')
        res.setHeader('Cache-Control', 'no-cache')
        const idx = calls.length
        const itemId = `item_${idx}`
        const responseId = `resp_${idx}`
        const emit = (event: string, data: Record<string, unknown>) => {
          res.write(`event: ${event}\ndata: ${JSON.stringify(data)}\n\n`)
        }
        emit('response.created', { type: 'response.created', response: { id: responseId, status: 'in_progress', output: [] } })
        if (reply.toolCall) {
          emit('response.output_item.added', {
            type: 'response.output_item.added',
            output_index: 0,
            item: { id: itemId, type: 'function_call', status: 'in_progress', call_id: reply.toolCall.callId, name: reply.toolCall.name, arguments: '' },
          })
          emit('response.function_call_arguments.delta', {
            type: 'response.function_call_arguments.delta',
            output_index: 0,
            item_id: itemId,
            delta: reply.toolCall.argumentsJson,
          })
          emit('response.function_call_arguments.done', {
            type: 'response.function_call_arguments.done',
            output_index: 0,
            item_id: itemId,
            name: reply.toolCall.name,
            arguments: reply.toolCall.argumentsJson,
          })
          emit('response.output_item.done', {
            type: 'response.output_item.done',
            output_index: 0,
            item: { id: itemId, type: 'function_call', status: 'completed', call_id: reply.toolCall.callId, name: reply.toolCall.name, arguments: reply.toolCall.argumentsJson },
          })
          emit('response.completed', {
            type: 'response.completed',
            response: {
              id: responseId,
              status: 'completed',
              output: [{ id: itemId, type: 'function_call', status: 'completed', call_id: reply.toolCall.callId, name: reply.toolCall.name, arguments: reply.toolCall.argumentsJson }],
              usage: { input_tokens: 100, output_tokens: 40, total_tokens: 140, input_tokens_details: { cached_tokens: 0 } },
            },
          })
        } else {
          const text = reply.text ?? 'done'
          emit('response.output_item.added', {
            type: 'response.output_item.added',
            output_index: 0,
            item: { id: itemId, type: 'message', status: 'in_progress', role: 'assistant', content: [] },
          })
          emit('response.output_text.delta', {
            type: 'response.output_text.delta',
            output_index: 0,
            item_id: itemId,
            content_index: 0,
            delta: text,
          })
          emit('response.output_text.done', {
            type: 'response.output_text.done',
            output_index: 0,
            item_id: itemId,
            content_index: 0,
            text,
          })
          emit('response.output_item.done', {
            type: 'response.output_item.done',
            output_index: 0,
            item: { id: itemId, type: 'message', status: 'completed', role: 'assistant', content: [{ type: 'output_text', text }] },
          })
          emit('response.completed', {
            type: 'response.completed',
            response: {
              id: responseId,
              status: 'completed',
              output: [{ id: itemId, type: 'message', status: 'completed', role: 'assistant', content: [{ type: 'output_text', text }] }],
              usage: { input_tokens: 80, output_tokens: 30, total_tokens: 110, input_tokens_details: { cached_tokens: 0 } },
            },
          })
        }
        res.write('data: [DONE]\n\n')
        res.end()
      }
      if (reply.delayMs && reply.delayMs > 0) {
        const timer = setTimeout(() => {
          timers.delete(timer)
          send()
        }, reply.delayMs)
        timer.unref?.()
        timers.add(timer)
        res.on('close', () => {
          clearTimeout(timer)
          timers.delete(timer)
        })
      } else {
        send()
      }
    })
  })
  await new Promise<void>(resolve => server.listen(0, '127.0.0.1', () => resolve()))
  const port = (server.address() as AddressInfo).port
  t.after(async () => {
    for (const timer of timers) clearTimeout(timer)
    timers.clear()
    server.closeAllConnections?.()
    await new Promise<void>(resolve => server.close(() => resolve()))
  })
  return { endpoint: `http://127.0.0.1:${port}/v1`, calls }
}

// ============================================================================
// 1. Effective Phase-B Concurrency & Chain Frontier Slot Reservation
// ============================================================================

test('resolveEffectivePhaseBConcurrency lifts slots=1 to >= 3 when >= 3 primary ready steps exist and headroom allows', () => {
  assert.equal(PHASE_B_MIN_CONCURRENCY_FLOOR, 3)
  assert.equal(
    resolveEffectivePhaseBConcurrency({
      configuredConcurrency: 1,
      readyPrimarySteps: 10,
      readyChainSteps: 4,
      budgetUsdRemaining: 1.9,
      budgetRequestsRemaining: 4500,
      maxRpsPerOrigin: 15,
    }),
    3,
  )
  // Two ready steps with a ready multi-hop chain still opens a 2nd slot so the chain never starves.
  assert.equal(
    resolveEffectivePhaseBConcurrency({
      configuredConcurrency: 1,
      readyPrimarySteps: 2,
      readyChainSteps: 1,
      budgetUsdRemaining: 1.9,
      budgetRequestsRemaining: 500,
      maxRpsPerOrigin: 10,
    }),
    2,
  )
  // Small single-step queue keeps configured concurrency (1) so single-worker control runs are preserved.
  assert.equal(
    resolveEffectivePhaseBConcurrency({
      configuredConcurrency: 1,
      readyPrimarySteps: 1,
      readyChainSteps: 0,
      budgetUsdRemaining: 1.9,
      budgetRequestsRemaining: 500,
      maxRpsPerOrigin: 10,
    }),
    1,
  )
  // Tight RPS or request budget respects the configured bound.
  assert.equal(
    resolveEffectivePhaseBConcurrency({
      configuredConcurrency: 1,
      readyPrimarySteps: 10,
      readyChainSteps: 4,
      budgetUsdRemaining: 1.9,
      budgetRequestsRemaining: 20,
      maxRpsPerOrigin: 15,
    }),
    1,
  )
  assert.equal(
    resolveEffectivePhaseBConcurrency({
      configuredConcurrency: 1,
      readyPrimarySteps: 10,
      readyChainSteps: 4,
      budgetUsdRemaining: 1.9,
      budgetRequestsRemaining: 500,
      maxRpsPerOrigin: 2,
    }),
    1,
  )
  // Higher configured concurrency (>= 3) is preserved.
  assert.equal(
    resolveEffectivePhaseBConcurrency({
      configuredConcurrency: 6,
      readyPrimarySteps: 10,
      readyChainSteps: 4,
    }),
    6,
  )
})

test('planRoundRobinDispatch reserves dedicated frontier slots for multi-hop chains ahead of BOLA route sweeps and det_leads', () => {
  const steps: DispatchLaneStep[] = [
    makeStep('lead-1', { seq: 1, priority: 95, title: 'det_lead upgrade · /api/v1/orders' }),
    makeStep('lead-2', { seq: 2, priority: 94, title: 'det_lead upgrade · /api/v1/invoices' }),
    makeStep('route-1', { seq: 3, priority: 92 }),
    makeStep('route-2', { seq: 4, priority: 91 }),
    makeStep('route-3', { seq: 5, priority: 90 }),
    makeStep('route-4', { seq: 6, priority: 89 }),
    makeStep('chain-1', {
      seq: 7,
      priority: 82,
      title: 'Cross-origin capability pivot 1',
      hypothesis: 'Advance derived token across origin boundary [chain_hops=h1->h2->h3->h4]',
      skills: ['chain:state_handle', 'chain-primitives'],
    }),
    makeStep('chain-2', {
      seq: 8,
      priority: 81,
      title: 'Multi-hop policy escalation 2',
      hypothesis: 'Escalate policy asymmetry using hopCheckpoint artifact',
      skills: ['multihop-chains'],
    }),
    makeStep('chain-3', {
      seq: 9,
      priority: 80,
      title: 'Dependent step pivot 3',
      dependsOnStepIds: ['route-1'],
    }),
    makeStep('route-5', { seq: 10, priority: 88 }),
  ]
  assert.equal(steps.filter(step => isMultiHopChainStep(step)).length, 3)

  const plan = planRoundRobinDispatch(steps, 3, { leadCap: DET_LEAD_CONCURRENT_CAP })
  assert.equal(plan.ordered.length, 3)
  assert.ok(plan.selectedByLane.chain >= 2, `expected >= 2 reserved chain slots out of 3, got ${plan.selectedByLane.chain}`)
  assert.deepEqual(
    plan.ordered.slice(0, 2).map(step => step.id),
    ['chain-1', 'chain-2'],
    'top multi-hop chain steps must claim dedicated frontier slots immediately',
  )

  // When 2 chains are already in flight, remaining free slot still gives non-chain lanes a turn.
  const followUp = planRoundRobinDispatch(steps.slice(0, 6).concat(steps[8]!), 2, {
    leadCap: DET_LEAD_CONCURRENT_CAP,
    activeChainCount: 2,
  })
  assert.equal(followUp.ordered.length, 2)
  assert.ok(followUp.selectedByLane.lead >= 1, 'non-chain lanes still make progress once chain reserve is met')
})

test('Execution scheduler.dispatch opens >= 3 concurrent slots (not slots=1) and schedules multi-hop chains immediately', async (t) => {
  const llm = await startCustomMockLlmServer(t, () => ({
    delayMs: 30,
    toolCall: {
      callId: 'c_done',
      name: 'complete_intent',
      argumentsJson: JSON.stringify({ status: 'ruled_out', summary: 'Checked route cleanly.' }),
    },
  }))
  const { storage } = makeStore(t)
  await saveModelProfile({
    name: 'Slot-Mock',
    endpoint: llm.endpoint,
    model: 'mock-slot',
    protocol: 'responses',
    key: 'sk-mock-slot-1234',
    priority: 100,
    enabled: true,
    contextWindow: 128_000,
    maxTokens: 4096,
    thinkingLevel: 'medium',
    roleAffinity: 'tactical',
    inputCostPerMtok: 0,
    cachedInputCostPerMtok: 0,
    outputCostPerMtok: 0,
  }, storage, { skipConnectionCheck: true })

  const { runId, run } = await setupApprovedRun(storage, {
    seeds: [ORIGIN],
    budgetUsd: 2,
    budgetRequests: 5000,
    maxRpsPerOrigin: 15,
  })
  // Queue 10 ready steps: 6 single-route BOLA sweeps + 4 multi-hop chain steps.
  for (let i = 1; i <= 6; i += 1) {
    storage.addChainStep(run, {
      title: `Single-route BOLA sweep ${i}`,
      hypothesis: `Probe GET /api/v1/resource/${i} across personas.`,
      category: 'broken-access-control',
      priority: 95 - i,
      targetAssetIds: run.approved,
      sourceOrigins: [ORIGIN],
      skills: ['bola-bfla'],
    })
  }
  const chainIds = new Set<string>()
  for (let i = 1; i <= 4; i += 1) {
    const created = storage.addChainStep(run, {
      title: `Multi-hop chain hypothesis ${i}`,
      hypothesis: `Chain capability handle across service boundary [chain_hops=h1->h2->h3->h4]`,
      category: 'broken-access-control',
      priority: 82 - i,
      targetAssetIds: run.approved,
      sourceOrigins: [ORIGIN],
      skills: ['chain:state_handle', 'chain-primitives'],
    })
    chainIds.add(created.id)
  }
  // Reproduce Queue #17 Step 2 starvation condition: caller configured workerConcurrency: 1!
  storage.updateRun(runId, {
    phase: 'investigation',
    status: 'running',
    workerConcurrency: 1,
    multiTrialEnabled: false,
  })

  const engine = new Execution(storage, { backend: stubBackend(), deterministicSweep: false })
  await withEnv({ KOVO_ALLOW_LOCAL_LAB: '1', KOVO_ALLOW_LOCAL_MODEL: '1' }, async () => {
    engine.start()
    engine.wake()
    const deadline = Date.now() + 4_000
    while (Date.now() < deadline) {
      const dispatchEvents = storage.eventsAfter(runId, 0, 100).filter(e => e.kind === 'scheduler.dispatch')
      if (dispatchEvents.length > 0) break
      await new Promise(r => setTimeout(r, 20))
    }
    await stopExecution(engine as never)
  })

  const firstDispatch = storage.eventsAfter(runId, 0, 100).find(e => e.kind === 'scheduler.dispatch')
  assert.ok(firstDispatch, 'expected scheduler.dispatch telemetry event')
  const detail = firstDispatch.detail as {
    slots: number
    effectiveConcurrency: number
    dispatched: number
    selectedByLane: Record<string, number>
    stepIds: string[]
  }
  assert.ok(detail.slots >= 3, `expected >= 3 slots (never slots=1 starvation), got slots=${detail.slots}`)
  assert.ok(detail.effectiveConcurrency >= 3, `expected effectiveConcurrency >= 3, got ${detail.effectiveConcurrency}`)
  assert.ok(detail.dispatched >= 3, `expected >= 3 concurrent steps dispatched, got ${detail.dispatched}`)
  assert.ok((detail.selectedByLane.chain ?? 0) >= 2, `expected >= 2 multi-hop chains dispatched immediately, got ${JSON.stringify(detail.selectedByLane)}`)
  assert.ok(detail.stepIds.some(id => chainIds.has(id)), 'multi-hop chain step must be included in first dispatch wave')
})

// ============================================================================
// 2. Hard `wallClockMs` Per-Assignment Rotation & Proof Grace Window
// ============================================================================

test('wallClockSettlementMs computes max(wallClockMs - 15s, 80%) and settlement message names proof/coverage actions', () => {
  assert.equal(wallClockSettlementMs(120_000), 105_000)
  assert.equal(wallClockSettlementMs(180_000), 165_000)
  assert.equal(wallClockSettlementMs(60_000), 48_000)
  assert.equal(wallClockSettlementMs(150), 120)
  const msg = wallClockSettlementMessage({ elapsedMs: 105_000, wallClockMs: 120_000, proofTools: ['kovo_verify'] })
  assert.match(msg, /kovo_verify/i)
  assert.match(msg, /record_coverage/i)
  assert.match(msg, /complete_intent/i)
})

test('runAgentSession hard-aborts a stalled specialist at wallClockMs=150 within < 400ms', async (t) => {
  const llm = await startCustomMockLlmServer(t, () => ({ hang: true }))
  const { dir } = makeStore(t)
  const rotations: Array<{ elapsedMs: number; wallClockMs: number; turnsUsed: number }> = []
  const startedAt = Date.now()

  const result = await runAgentSession({
    directory: dir,
    sessionId: 'sess-wall-hang',
    requestId: 'req-wall-hang',
    settings: {
      name: 'Hang-Mock',
      endpoint: llm.endpoint,
      model: 'mock-hang',
      protocol: 'responses',
      key: 'sk-mock-hang-1234',
      contextWindow: 128_000,
      maxTokens: 4096,
      thinkingLevel: 'medium',
      roleAffinity: 'tactical',
      inputCostPerMtok: 0,
      cachedInputCostPerMtok: 0,
      outputCostPerMtok: 0,
    },
    scenario: 'worker-investigation',
    prompt: 'Investigate route and submit proof.',
    signal: new AbortController().signal,
    maxTurns: 12,
    wallClockMs: 150,
    handlers: {
      complete_intent: async c => JSON.stringify(c),
    },
    onWallClockRotate: info => rotations.push(info),
  })

  const elapsedMs = Date.now() - startedAt
  assert.equal(result.status, 'wall_clock_rotated')
  assert.equal(result.wallClockRotated, true)
  assert.equal(rotations.length, 1)
  assert.ok(elapsedMs < 400, `expected hard rotation within < 400ms for wallClockMs=150, took ${elapsedMs}ms`)
})

test('runAgentSession grants bounded grace for an actively running kovo_verify proof call before rotating', async (t) => {
  let verifyFinished = false
  const llm = await startCustomMockLlmServer(t, (_body, idx) => {
    if (idx === 1) {
      return {
        toolCall: {
          callId: 'call_gv_1',
          name: 'kovo_verify',
          argumentsJson: JSON.stringify({ runtime: 'ts', script: 'export default async () => ({ confirmed: true })' }),
        },
      }
    }
    return { hang: true }
  })
  const { dir } = makeStore(t)
  const startedAt = Date.now()

  const result = await runAgentSession({
    directory: dir,
    sessionId: 'sess-wall-grace',
    requestId: 'req-wall-grace',
    settings: {
      name: 'Grace-Mock',
      endpoint: llm.endpoint,
      model: 'mock-grace',
      protocol: 'responses',
      key: 'sk-mock-grace-1234',
      contextWindow: 128_000,
      maxTokens: 4096,
      thinkingLevel: 'medium',
      roleAffinity: 'tactical',
      inputCostPerMtok: 0,
      cachedInputCostPerMtok: 0,
      outputCostPerMtok: 0,
    },
    scenario: 'worker-investigation',
    prompt: 'Submit kovo_verify proof now.',
    signal: new AbortController().signal,
    maxTurns: 10,
    wallClockMs: 90,
    wallClockGraceMs: 250,
    handlers: {
      kovo_verify: async () => {
        await new Promise(r => setTimeout(r, 140))
        verifyFinished = true
        return JSON.stringify({ ok: true, confirmed: true })
      },
      complete_intent: async c => JSON.stringify(c),
    },
  })

  const elapsedMs = Date.now() - startedAt
  assert.equal(verifyFinished, true, 'in-flight kovo_verify proof must be allowed to complete inside the grace window')
  assert.equal(result.status, 'wall_clock_rotated')
  assert.ok(elapsedMs < 500, `expected bounded rotation shortly after grace completion, took ${elapsedMs}ms`)
})

test('Execution rotates a stalled specialist at wallClockMs=150 in < 400ms and dispatches the queued next step immediately', async (t) => {
  let rotatedAt: number | null = null
  let step2DispatchedAt: number | null = null
  const llm = await startCustomMockLlmServer(t, body => {
    const promptText = JSON.stringify(body.input ?? '')
    if (promptText.includes('STALL_STEP_ONE') && !promptText.includes('QUEUED_STEP_TWO')) {
      return { hang: true }
    }
    if (promptText.includes('QUEUED_STEP_TWO') && !step2DispatchedAt) step2DispatchedAt = Date.now()
    return {
      toolCall: {
        callId: 'c_step2_done',
        name: 'complete_intent',
        argumentsJson: JSON.stringify({ status: 'ruled_out', summary: 'Queued step 2 executed cleanly after slot rotation.' }),
      },
    }
  })

  const { storage } = makeStore(t)
  await saveModelProfile({
    name: 'Rotate-Mock',
    endpoint: llm.endpoint,
    model: 'mock-rotate',
    protocol: 'responses',
    key: 'sk-mock-rotate-1234',
    priority: 100,
    enabled: true,
    contextWindow: 128_000,
    maxTokens: 4096,
    thinkingLevel: 'medium',
    roleAffinity: 'tactical',
    inputCostPerMtok: 0,
    cachedInputCostPerMtok: 0,
    outputCostPerMtok: 0,
  }, storage, { skipConnectionCheck: true })

  // Keep maxRpsPerOrigin=2 so slots=1 is intentionally exercised, proving step 2 waits on step 1's slot
  // and dispatches IMMEDIATELY after step 1 rotates at wallClockMs=150.
  const { runId, run } = await setupApprovedRun(storage, {
    seeds: [ORIGIN],
    budgetUsd: 2,
    budgetRequests: 500,
    maxRpsPerOrigin: 2,
  })
  const step1 = storage.addChainStep(run, {
    title: 'STALL_STEP_ONE slow sweep',
    hypothesis: 'Probe GET /api/v1/stalled-route (STALL_STEP_ONE).',
    category: 'broken-access-control',
    priority: 95,
    targetAssetIds: run.approved,
    sourceOrigins: [ORIGIN],
  })
  const step2 = storage.addChainStep(run, {
    title: 'QUEUED_STEP_TWO follow-up',
    hypothesis: 'Probe GET /api/v1/queued-next (QUEUED_STEP_TWO).',
    category: 'broken-access-control',
    priority: 80,
    targetAssetIds: run.approved,
    sourceOrigins: [ORIGIN],
  })
  storage.updateRun(runId, {
    phase: 'investigation',
    status: 'running',
    workerConcurrency: 1,
    multiTrialEnabled: false,
  })

  const engine = new Execution(storage, {
    backend: stubBackend(),
    deterministicSweep: false,
    assignmentWallClockOverrideMs: 150,
  })

  const startedAt = Date.now()
  await withEnv({ KOVO_ALLOW_LOCAL_LAB: '1', KOVO_ALLOW_LOCAL_MODEL: '1' }, async () => {
    engine.start()
    engine.wake()
    const deadline = Date.now() + 4_000
    while (Date.now() < deadline) {
      const events = storage.eventsAfter(runId, 0, 200)
      if (!rotatedAt && events.some(e => e.kind === 'worker.wall_clock_rotated')) {
        rotatedAt = Date.now()
      }
      const steps = storage.listChainSteps(runId, run.goalRevision)
      const s1 = steps.find(s => s.id === step1.id)
      const s2 = steps.find(s => s.id === step2.id)
      if (s1?.status === 'rotated_partial' && s2?.status === 'complete') break
      await new Promise(r => setTimeout(r, 15))
    }
    await stopExecution(engine as never)
  })

  const events = storage.eventsAfter(runId, 0, 200)
  const rotationEvent = events.find(e => e.kind === 'worker.wall_clock_rotated')
  assert.ok(rotationEvent, 'expected worker.wall_clock_rotated event for stalled assignment')
  assert.equal((rotationEvent.detail as { stepId?: string }).stepId, step1.id)
  assert.ok(rotatedAt !== null, 'rotation timestamp must be recorded')
  const rotationLatencyMs = rotatedAt! - startedAt
  assert.ok(rotationLatencyMs < 400, `expected stalled worker slot release within < 400ms, took ${rotationLatencyMs}ms`)

  const finalSteps = storage.listChainSteps(runId, run.goalRevision)
  assert.equal(finalSteps.find(s => s.id === step1.id)?.status, 'rotated_partial')
  assert.equal(finalSteps.find(s => s.id === step2.id)?.status, 'complete', 'queued next step must dispatch and complete after rotation')
  assert.ok(step2DispatchedAt !== null, 'queued step 2 must have received LLM turns after step 1 rotated')

  const throughput = engine.getAssignmentThroughput(runId)
  assert.ok((throughput?.wallClockRotations ?? 0) >= 1, `expected wallClockRotations >= 1 in throughput metrics, got ${JSON.stringify(throughput)}`)
})
