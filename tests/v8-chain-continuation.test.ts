/**
 * v8 Multi-Hop Chain Continuation, Wall-Clock Budget & Zero-Turn Code-Audit Digest Tests.
 *
 * Proves (Docker-free, real SQLite WAL `Store`, real `Execution`, real `ExecReconPlanner`,
 * real `ExecWorkerRunner`, synthetic mock Responses LLM server):
 *  1. `resolveWorkerWallClockMs` scales multi-hop `chain` / continuation steps proportionally
 *     (10m -> 180s, 15m -> 270s, 30m -> 300s, unset -> 240s) with `resolveWorkerSettlementMs`
 *     at `max(wall - 25s, wall * 0.82)`, while single-route sweeps stay at 120s.
 *  2. Automatic Hop-Continuation checkpointing on `wall_clock_rotated`:
 *     - enqueues ONE `chain_continuation:1` step when rotated + unconfirmed + concrete progress
 *       (facts, exchanges, or sealed `cap:hop_*` handles in `CapabilityLedger`),
 *     - persists canonical `<= 2 KB` `v8.hop_checkpoint.v1` SQLite checkpoint (`checkpointCapId`
 *       + `hop_checkpoint` `Fact`) that rehydrates cleanly across restarts,
 *     - prioritizes continuation steps at the top of the `chain` frontier lane,
 *     - caps continuation depth at `MAX_CHAIN_CONTINUATIONS = 2` and skips zero-progress /
 *       already-confirmed / non-chain workers so it never loops or inflates dead-end waste,
 *     - executes end-to-end inside live `Execution` when a progressing chain worker rotates.
 *  3. Zero-turn `StaticWorkspaceSnapshot` digest (`<= 8 KB`) pre-injected into `Source-First
 *     Code Audit` `specsSummary` on Turn 1 with grouped services, HTTP/GraphQL/webhook/worker
 *     routes, authz guards, and sinks with `file:line`.
 */
import assert from 'node:assert/strict'
import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from 'node:fs'
import { createServer, type Server } from 'node:http'
import type { AddressInfo } from 'node:net'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { test } from 'node:test'

import {
  CHAIN_CONTINUATION_SKILL_PREFIX,
  Execution,
  HOP_CONTINUATION_DIRECTIVE,
  MAX_CHAIN_CONTINUATIONS,
  MAX_WORKSPACE_DIGEST_BYTES,
  buildWorkspaceSourceDigest,
  classifyDispatchLane,
  extractContinuationDepth,
  isChainContinuationStep,
  isMultiHopChainStep,
  planAssignmentBudget,
  planRoundRobinDispatch,
  resolveWorkerSettlementMs,
  resolveWorkerWallClockMs,
  type DispatchLaneStep,
} from '../src/server/execution.ts'
import {
  CHECKPOINT_CAP_SKILL_PREFIX,
  extractCheckpointCapIdFromStep,
  type ExecReconPlanner,
} from '../src/server/exec-recon-planner.ts'
import {
  DEFAULT_CHECKPOINT_BRIEF_MAX_BYTES,
  formatDerivedCapabilityHandle,
} from '../src/server/capability-ledger.ts'
import { privateModelProfiles, saveModelProfile } from '../src/server/model-settings.ts'
import { buildStaticWorkspaceSnapshot } from '../src/server/static-workspace-snapshot.ts'
import { Store, type ChainStep, type Run } from '../src/server/store.ts'
import type { WorkerBackend, WorkerSession } from '../src/server/worker-backend.ts'
import { makeStore, setupApprovedRun, stopExecution, withEnv } from './v4-tier-helpers.ts'

process.env.KOVO_ALLOW_LOCAL_LAB = '1'

const ORIGIN = 'https://app.example.invalid'

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

interface MockLlmReply {
  delayMs?: number
  hang?: boolean
  toolCall?: { callId: string; name: string; argumentsJson: string }
  text?: string
}

async function startMockLlmServer(
  t: { after: (fn: () => void | Promise<void>) => void },
  handler: (body: Record<string, unknown>, reqIndex: number) => MockLlmReply,
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
              usage: { input_tokens: 90, output_tokens: 35, total_tokens: 125 },
            },
          })
        } else {
          const text = reply.text ?? 'done'
          emit('response.output_item.added', {
            type: 'response.output_item.added',
            output_index: 0,
            item: { id: itemId, type: 'message', status: 'in_progress', role: 'assistant', content: [] },
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
              usage: { input_tokens: 70, output_tokens: 25, total_tokens: 95 },
            },
          })
        }
        res.write('data: [DONE]\n\n')
        res.end()
      }
      if (reply.delayMs && reply.delayMs > 0) {
        const timer = setTimeout(() => { timers.delete(timer); send() }, reply.delayMs)
        timer.unref?.()
        timers.add(timer)
        res.on('close', () => { clearTimeout(timer); timers.delete(timer) })
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

type ExecInternals = {
  reconPlanner: ExecReconPlanner
  projectReposMount: (projectId: string) => { reposDir?: string; mountedRepos: string[] }
  startInvestigationStep: (run: Run, step: ChainStep, profiles: readonly unknown[]) => void
}

function internals(execution: Execution): ExecInternals {
  return execution as unknown as ExecInternals
}

// ============================================================================
// 1. Multi-Hop `chain` Wall-Clock Budget & Settlement
// ============================================================================

test('resolveWorkerWallClockMs scales multi-hop chain steps (180s/270s/300s/240s) while keeping single-route sweeps at 120s', () => {
  const multiHopStep = {
    title: 'Cross-service token pivot',
    hypothesis: 'Pivot derived capability across services [chain_hops=h1->h2->h3]',
    category: 'broken-access-control',
    skills: ['multihop-chains', 'chain-primitives'],
    dependsOnStepIds: [],
  }
  const continuationStep = {
    title: 'Cross-service token pivot [continuation #1]',
    hypothesis: HOP_CONTINUATION_DIRECTIVE,
    category: 'broken-access-control',
    skills: [`${CHAIN_CONTINUATION_SKILL_PREFIX}1`],
    dependsOnStepIds: ['parent-step-1'],
  }
  const singleRouteStep = {
    title: 'Single-route access sweep',
    hypothesis: 'Verify GET /api/v1/items/:id authorization matrix.',
    category: 'broken-access-control',
    skills: ['bola-bfla'],
    dependsOnStepIds: [],
  }

  assert.equal(isMultiHopChainStep(multiHopStep), true)
  assert.equal(isMultiHopChainStep(continuationStep), true)
  assert.equal(isChainContinuationStep(continuationStep), true)
  assert.equal(extractContinuationDepth(continuationStep), 1)
  assert.equal(isMultiHopChainStep(singleRouteStep), false)

  // Multi-hop chain scaling: clamp(180s, 300s, floor(runDurationMs * 0.30)), default 240s
  assert.equal(resolveWorkerWallClockMs(multiHopStep, 600_000), 180_000)   // 10m -> 180s
  assert.equal(resolveWorkerWallClockMs(multiHopStep, 900_000), 270_000)   // 15m -> 270s
  assert.equal(resolveWorkerWallClockMs(multiHopStep, 1_800_000), 300_000) // 30m -> 300s
  assert.equal(resolveWorkerWallClockMs(multiHopStep, 300_000), 180_000)   // 5m  -> 180s floor
  assert.equal(resolveWorkerWallClockMs(multiHopStep, undefined), 240_000) // unset -> 240s default
  assert.equal(resolveWorkerWallClockMs(multiHopStep, 0), 240_000)
  assert.equal(resolveWorkerWallClockMs(continuationStep, 900_000), 270_000)

  // Single-route sweeps stay fast at 120s regardless of run duration
  assert.equal(resolveWorkerWallClockMs(singleRouteStep, 600_000), 120_000)
  assert.equal(resolveWorkerWallClockMs(singleRouteStep, 900_000), 120_000)
  assert.equal(resolveWorkerWallClockMs(singleRouteStep, 1_800_000), 120_000)
  assert.equal(resolveWorkerWallClockMs(singleRouteStep, undefined), 120_000)

  // Multi-hop settlement: max(wallMs - 25s, wallMs * 0.82)
  assert.equal(resolveWorkerSettlementMs(180_000, true), 155_000)
  assert.equal(resolveWorkerSettlementMs(240_000, true), 215_000)
  assert.equal(resolveWorkerSettlementMs(270_000, true), 245_000)
  assert.equal(resolveWorkerSettlementMs(300_000, true), 275_000)
  assert.equal(resolveWorkerSettlementMs(100_000, true), 82_000)
  assert.equal(resolveWorkerSettlementMs(120_000, false), 105_000)

  // planAssignmentBudget wires multiHopChain proportionally while leaving legacy single-step at 120s
  const chainBudget15m = planAssignmentBudget({
    routes: ['/api/v1/tokens', '/api/v1/webhooks'],
    parentEvidenceIds: [],
    dependsOnStepIds: [],
    multiHopChain: true,
    runDurationMs: 900_000,
    baseMaxTurns: 25,
    baseWallClockMs: 160_000,
  })
  assert.equal(chainBudget15m.kind, 'chain')
  assert.equal(chainBudget15m.wallClockMs, 270_000)
  assert.equal(chainBudget15m.wallClockSettlementMs, 245_000)

  const singleBudget15m = planAssignmentBudget({
    routes: ['/api/v1/items/:id'],
    parentEvidenceIds: [],
    dependsOnStepIds: [],
    multiHopChain: false,
    runDurationMs: 900_000,
    baseMaxTurns: 25,
    baseWallClockMs: 160_000,
  })
  assert.equal(singleBudget15m.kind, 'single_step')
  assert.equal(singleBudget15m.wallClockMs, 120_000)
})

test('Execution emits 270s wall-clock budget for multi-hop chain step vs 120s for single-route step on a 15m run', async (t) => {
  const llm = await startMockLlmServer(t, () => ({
    toolCall: {
      callId: 'c_done',
      name: 'complete_intent',
      argumentsJson: JSON.stringify({ status: 'ruled_out', summary: 'Checked cleanly.' }),
    },
  }))
  const { storage } = makeStore(t)
  await saveModelProfile({
    name: 'Budget-Mock',
    endpoint: llm.endpoint,
    model: 'mock-budget',
    protocol: 'responses',
    key: 'sk-mock-budget-1234',
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

  const { runId, run } = await setupApprovedRun(storage, { seeds: [ORIGIN], budgetUsd: 2, budgetRequests: 500 })
  const chainStep = storage.addChainStep(run, {
    title: 'Multi-hop chain budget check',
    hypothesis: 'Verify cross-service chain [chain_hops=h1->h2->h3].',
    category: 'broken-access-control',
    priority: 95,
    targetAssetIds: run.approved,
    sourceOrigins: [ORIGIN],
    skills: ['multihop-chains', 'chain-primitives'],
  })
  const routeStep = storage.addChainStep(run, {
    title: 'Single-route access sweep',
    hypothesis: 'Probe GET /api/v1/profile.',
    category: 'broken-access-control',
    priority: 80,
    targetAssetIds: run.approved,
    sourceOrigins: [ORIGIN],
    skills: ['bola-bfla'],
  })
  storage.updateRun(runId, { phase: 'investigation', status: 'running', workerConcurrency: 3, multiTrialEnabled: false })

  const engine = new Execution(storage, { backend: stubBackend(), deterministicSweep: false, maxDurationMs: 900_000 })
  await withEnv({ KOVO_ALLOW_LOCAL_LAB: '1' }, async () => {
    engine.start()
    engine.wake()
    const deadline = Date.now() + 4_000
    while (Date.now() < deadline) {
      const started = storage.eventsAfter(runId, 0, 200).filter(e => e.kind === 'worker.started')
      if (started.length >= 2) break
      await new Promise(r => setTimeout(r, 20))
    }
    await stopExecution(engine as never)
  })

  const startedEvents = storage.eventsAfter(runId, 0, 200).filter(e => e.kind === 'worker.started')
  const chainStarted = startedEvents.find(e => (e.detail as { stepId?: string }).stepId === chainStep.id)
  const routeStarted = startedEvents.find(e => (e.detail as { stepId?: string }).stepId === routeStep.id)
  assert.ok(chainStarted, 'expected worker.started event for multi-hop chain step')
  assert.ok(routeStarted, 'expected worker.started event for single-route step')
  const chainBudget = (chainStarted.detail as { assignmentBudget?: { wallClockMs?: number; wallClockSettlementMs?: number } }).assignmentBudget
  const routeBudget = (routeStarted.detail as { assignmentBudget?: { wallClockMs?: number } }).assignmentBudget
  assert.equal(chainBudget?.wallClockMs, 270_000, '15m multi-hop chain step must receive 270s wall-clock budget')
  assert.equal(chainBudget?.wallClockSettlementMs, 245_000, '15m multi-hop chain step must settle at 245s (25s before rotation)')
  assert.equal(routeBudget?.wallClockMs, 120_000, 'single-route step must keep fast 120s rotation window')
})

// ============================================================================
// 2. Automatic Hop-Continuation Checkpointing, Priority & Depth Cap
// ============================================================================

test('enqueueHopContinuationOnRotation persists <= 2 KB v8.hop_checkpoint.v1 checkpoint, caps at depth 2, and rejects non-progress/confirmed workers', async (t) => {
  const { storage, dir } = makeStore(t)
  const { runId, run } = await setupApprovedRun(storage, { seeds: [ORIGIN], tier: 2 })
  const asset = run.candidates.find(c => run.approved.includes(c.id))!
  const engine = new Execution(storage, { backend: stubBackend(), maxDurationMs: 900_000 })
  t.after(() => engine.stop())
  const planner = internals(engine).reconPlanner

  const parentStep = storage.addChainStep(run, {
    title: 'Multi-hop signing pivot across async export',
    hypothesis: 'Derive signing handle at Hop 1-2 then execute Hops 3-5 [chain_hops=h1->h2->h3->h4].',
    category: 'broken-access-control',
    priority: 92,
    targetAssetIds: [asset.id],
    sourceOrigins: [ORIGIN],
    skills: ['multihop-chains', 'chain-primitives'],
  })
  const worker1 = storage.makeWorker(run, 'investigation', asset, parentStep.title, parentStep.hypothesis, {
    stepId: parentStep.id,
    sourceOrigins: [ORIGIN],
  })
  storage.updateChainStep(parentStep.id, { status: 'complete', assignedWorkerId: worker1.id })

  // Seed sealed Hop 1 -> Hop 2 capabilities in SQLite CapabilityLedger.
  const ledger = storage.capabilityLedger(runId)
  const cap1 = formatDerivedCapabilityHandle('cont_1', 'seed_session')
  const cap2 = formatDerivedCapabilityHandle('cont_2', 'derived_signer')
  ledger.addCapability({
    capId: cap1,
    kind: 'identity_session',
    provenance: 'attacker_seed',
    tenantScope: 'org_alpha',
    actorPersona: 'member_alpha',
    serviceOrigin: ORIGIN,
    surface: 'http',
    artifactDigest: 'a'.repeat(64),
    artifactSummary: 'Hop 1 attacker session',
    createdAtMs: 1000,
  })
  ledger.addCapability({
    capId: cap2,
    kind: 'signing_material',
    provenance: 'derived_hop',
    tenantScope: 'org_alpha',
    actorPersona: 'member_alpha',
    serviceOrigin: ORIGIN,
    surface: 'webhook',
    artifactDigest: 'b'.repeat(64),
    artifactSummary: 'Hop 2 derived webhook signing material handle',
    createdAtMs: 1100,
  })
  ledger.addCausalEdge({
    preconditionCapIds: [cap1],
    actorContext: { persona: 'member_alpha', tenantScope: 'org_alpha', serviceOrigin: ORIGIN },
    hopReceiptId: 'rcpt-h1-h2',
    edgeBindingKind: 'derived_crypto_binding',
    postconditionCapId: cap2,
    sourceTimestampMs: 1000,
    targetTimestampMs: 1100,
  })

  const progressFact = storage.addFact(run, worker1, {
    kind: 'note',
    origin: ORIGIN,
    summary: `Verified Hop 1-2 webhook signing key derivation into ${cap2}`,
    data: { subkind: 'chain_progress', capId: cap2 },
    sourceOrigins: [ORIGIN],
  })

  // Guard 1: already confirmed -> NO continuation
  const confirmedSkip = planner.enqueueHopContinuationOnRotation({
    run,
    step: parentStep,
    assignment: worker1,
    targetOrigins: [ORIGIN],
    confirmed: true,
    partialSummary: 'Confirmed finding.',
    recordedFacts: [progressFact],
    recordedExchanges: [],
    sealedCapHandles: [cap2],
  })
  assert.equal(confirmedSkip.enqueued, false)
  assert.equal(confirmedSkip.reason, 'already_confirmed')

  // Guard 2: zero concrete progress -> NO continuation (prevents dead-end waste)
  const noProgressSkip = planner.enqueueHopContinuationOnRotation({
    run,
    step: parentStep,
    assignment: worker1,
    targetOrigins: [ORIGIN],
    confirmed: false,
    partialSummary: 'Rotated with zero actions.',
    recordedFacts: [],
    recordedExchanges: [],
    sealedCapHandles: [],
  })
  assert.equal(noProgressSkip.enqueued, false)
  assert.equal(noProgressSkip.reason, 'no_concrete_progress')

  // Guard 3: non-chain single-route step -> NO continuation
  const singleStep = storage.addChainStep(run, {
    title: 'Single route sweep',
    hypothesis: 'Probe GET /api/v1/profile.',
    category: 'broken-access-control',
    priority: 80,
    targetAssetIds: [asset.id],
    sourceOrigins: [ORIGIN],
    skills: ['bola-bfla'],
  })
  const nonChainSkip = planner.enqueueHopContinuationOnRotation({
    run,
    step: singleStep,
    assignment: worker1,
    targetOrigins: [ORIGIN],
    confirmed: false,
    partialSummary: 'Checked profile.',
    recordedFacts: [progressFact],
    recordedExchanges: [],
    sealedCapHandles: [cap2],
  })
  assert.equal(nonChainSkip.enqueued, false)
  assert.equal(nonChainSkip.reason, 'not_multi_hop_chain')

  // Valid continuation #1
  const cont1 = planner.enqueueHopContinuationOnRotation({
    run,
    step: parentStep,
    assignment: worker1,
    targetOrigins: [ORIGIN],
    confirmed: false,
    partialSummary: '[partial] Completed Hops 1-2 and sealed signing handle.',
    recordedFacts: [progressFact],
    recordedExchanges: [{ id: 'ex-h2', origin: ORIGIN, method: 'POST', pathAndQuery: '/api/v1/webhooks/dispatch', status: 202 }],
    sealedCapHandles: [cap2],
  })
  assert.equal(cont1.enqueued, true)
  assert.equal(cont1.continuationDepth, 1)
  assert.equal(cont1.checkpointCapId, cap2)
  assert.ok((cont1.checkpointBytes ?? 0) > 0 && (cont1.checkpointBytes ?? 0) <= DEFAULT_CHECKPOINT_BRIEF_MAX_BYTES)
  const step1 = cont1.continuationStep!
  assert.equal(step1.status, 'ready', 'continuation step must be immediately ready')
  assert.equal(extractContinuationDepth(step1), 1)
  assert.equal(extractCheckpointCapIdFromStep(step1), cap2)
  assert.ok(step1.skills.includes(`${CHAIN_CONTINUATION_SKILL_PREFIX}1`))
  assert.ok(step1.skills.includes(`${CHECKPOINT_CAP_SKILL_PREFIX}${cap2}`))
  assert.equal(classifyDispatchLane(step1), 'chain')
  assert.ok(step1.hypothesis.includes('DO NOT re-read source or repeat Hops 1–2'))
  assert.ok(step1.hypothesis.includes('ctx.prove_composite'))

  // Duplicate call on the same rotated parent step is idempotent
  const dup = planner.enqueueHopContinuationOnRotation({
    run,
    step: parentStep,
    assignment: worker1,
    targetOrigins: [ORIGIN],
    confirmed: false,
    partialSummary: '[partial] Duplicate check.',
    recordedFacts: [progressFact],
    recordedExchanges: [],
    sealedCapHandles: [cap2],
  })
  assert.equal(dup.enqueued, false)
  assert.equal(dup.reason, 'already_enqueued')

  // Verify hop_checkpoint Fact persisted and rehydrates across SQLite restart
  const cpFacts = storage.listFacts(runId, { includeTainted: false, limit: 100 })
    .filter(f => f.data?.subkind === 'hop_checkpoint')
  assert.ok(cpFacts.length >= 1, 'expected persisted hop_checkpoint Fact')

  // Valid continuation #2 (maxContinuations = 2)
  storage.updateChainStep(step1.id, { status: 'complete', assignedWorkerId: worker1.id })
  const cont2 = planner.enqueueHopContinuationOnRotation({
    run,
    step: step1,
    assignment: worker1,
    targetOrigins: [ORIGIN],
    confirmed: false,
    partialSummary: '[partial] Completed Hop 3 async job poll, finalizing Hop 4.',
    recordedFacts: [progressFact],
    recordedExchanges: [{ id: 'ex-h3', origin: ORIGIN, method: 'GET', pathAndQuery: '/api/v1/jobs/j-42', status: 200 }],
    sealedCapHandles: [cap2],
  })
  assert.equal(cont2.enqueued, true)
  assert.equal(cont2.continuationDepth, 2)
  const step2 = cont2.continuationStep!
  assert.equal(extractContinuationDepth(step2), MAX_CHAIN_CONTINUATIONS)

  // Depth cap: continuation #3 MUST be blocked (`max_continuations_reached`)
  storage.updateChainStep(step2.id, { status: 'complete', assignedWorkerId: worker1.id })
  const cont3 = planner.enqueueHopContinuationOnRotation({
    run,
    step: step2,
    assignment: worker1,
    targetOrigins: [ORIGIN],
    confirmed: false,
    partialSummary: '[partial] Attempt beyond cap.',
    recordedFacts: [progressFact],
    recordedExchanges: [],
    sealedCapHandles: [cap2],
  })
  assert.equal(cont3.enqueued, false)
  assert.equal(cont3.reason, 'max_continuations_reached')

  // Rehydration across process restart
  storage.close()
  const reopened = new Store(dir)
  t.after(() => reopened.close())
  const engine2 = new Execution(reopened, { backend: stubBackend() })
  t.after(() => engine2.stop())
  const reloadedRun = reopened.run(runId)
  const reloadedCont1 = reopened.listChainSteps(runId, reloadedRun.goalRevision).find(s => s.id === step1.id)!
  const parentFacts = reopened.listFacts(runId, { includeTainted: false, limit: 100 })
    .filter(f => reloadedCont1.dependsOnFactIds.includes(f.id))
  const briefText = internals(engine2).reconPlanner.assignmentBriefForStep({
    run: reloadedRun,
    step: reloadedCont1,
    targetOrigins: [ORIGIN],
    personas: [{ handle: 'member_alpha', roleLabel: 'member (org_alpha)' }],
    parentFacts,
    confirmed: [],
    detLeads: [],
    maxTurns: 24,
  })
  assert.ok(briefText, 'expected hydrated assignment brief for continuation step')
  const parsed = JSON.parse(briefText) as {
    hopCheckpoint?: { schema?: string; doNotRediscover?: boolean; capabilityHandles?: string[]; nextGoal?: { goal?: string } }
  }
  assert.equal(parsed.hopCheckpoint?.schema, 'v8.hop_checkpoint.v1')
  assert.equal(parsed.hopCheckpoint?.doNotRediscover, true)
  assert.ok(parsed.hopCheckpoint?.capabilityHandles?.includes(cap2))
  assert.match(parsed.hopCheckpoint?.nextGoal?.goal ?? '', /DO NOT re-read source|ctx\.prove_composite/i)
})

test('planRoundRobinDispatch fairly interleaves unstarted source/planner chains ahead of sealed depth-1 continuations and generic Wave-1 stubs', () => {
  const coldPlannerChain: DispatchLaneStep = {
    id: 'chain-cold-1',
    seq: 1,
    priority: 100,
    title: 'Fresh cold chain hypothesis',
    category: 'broken-access-control',
    hypothesis: 'Investigate cross-service chain [chain_hops=h1->h2->h3]',
    skills: ['multihop-chains', 'chain-primitives'],
    dependsOnFactIds: [],
    dependsOnStepIds: [],
    sourceOrigins: [ORIGIN],
    trialIndex: 0,
  }
  const wave1Stub: DispatchLaneStep = {
    id: 'chain-wave1-stub',
    seq: 2,
    priority: 96,
    title: 'Wave-1 chain · Cross-service boundary chain (edge/http)',
    category: 'broken-access-control',
    hypothesis: '[chain_hops=3] [lane=chain] [inv_hyp=inv-1] [cap=cap:hop_synth:edge] Multi-hop invariant chain',
    skills: ['multihop-chains', 'chain-primitives'],
    dependsOnFactIds: [],
    dependsOnStepIds: [],
    sourceOrigins: [ORIGIN],
    trialIndex: 0,
  }
  const contStep: DispatchLaneStep = {
    id: 'chain-cont-1',
    seq: 5,
    priority: 85,
    title: 'Verified Hop 1-2 continuation [continuation #1]',
    category: 'broken-access-control',
    hypothesis: HOP_CONTINUATION_DIRECTIVE,
    skills: [
      'multihop-chains',
      'chain-primitives',
      `${CHAIN_CONTINUATION_SKILL_PREFIX}1`,
      `${CHECKPOINT_CAP_SKILL_PREFIX}cap:hop_cont_1:derived_signer`,
    ],
    dependsOnFactIds: ['f-cp'],
    dependsOnStepIds: ['chain-parent-1'],
    sourceOrigins: [ORIGIN],
    trialIndex: 0,
  }
  const routeSweep: DispatchLaneStep = {
    id: 'route-1',
    seq: 3,
    priority: 99,
    title: 'Single-route access sweep',
    category: 'broken-access-control',
    hypothesis: 'Probe GET /api/v1/items/1.',
    skills: ['bola-bfla'],
    dependsOnFactIds: [],
    dependsOnStepIds: [],
    sourceOrigins: [ORIGIN],
    trialIndex: 0,
  }

  const withPlanner = planRoundRobinDispatch([wave1Stub, coldPlannerChain, routeSweep, contStep], 3)
  assert.equal(withPlanner.ordered[0]?.id, 'chain-cold-1', 'unstarted planner multi-hop chain must rank first')
  assert.equal(withPlanner.ordered[1]?.id, 'chain-cont-1', 'depth-1 sealed continuation must outrank generic Wave-1 boundary stub')

  const vsWave1Only = planRoundRobinDispatch([wave1Stub, routeSweep, contStep], 2)
  assert.equal(vsWave1Only.ordered[0]?.id, 'chain-cont-1', 'depth-1 sealed continuation must beat generic Wave-1 stub in chain lane')
})

test('Live Execution automatically enqueues and dispatches a hop-continuation step when a progressing multi-hop worker rotates, and skips stalled zero-progress chains', async (t) => {
  let continuationPromptReceived = ''
  const llm = await startMockLlmServer(t, body => {
    const inputItems = Array.isArray(body.input) ? body.input : [body.input]
    // Inspect the worker's own initial user task message (not developer instructions or shared board deltas).
    const firstUserMsg = inputItems.find(item => item && typeof item === 'object' && (item as { role?: string }).role === 'user')
    const ownTaskText = JSON.stringify(firstUserMsg ?? '')
    const fullText = JSON.stringify(body.input ?? '')
    // Zero-progress chain hangs immediately on Turn 1 -> must NOT spawn continuation
    if (ownTaskText.includes('ZERO_PROGRESS_CHAIN')) {
      return { hang: true }
    }
    // Continuation step receives hydrated checkpoint & completes cleanly
    if (ownTaskText.includes('continuation #1')) {
      continuationPromptReceived = ownTaskText
      return {
        toolCall: {
          callId: 'c_cont_done',
          name: 'complete_intent',
          argumentsJson: JSON.stringify({ status: 'completed', summary: 'Resumed Hops 3-5 from verified checkpoint.' }),
        },
      }
    }
    // Initial progressing chain records a concrete fact on Turn 1, then hangs on Turn 2 to hit rotation
    if (ownTaskText.includes('PROGRESS_CHAIN_STEP') && !fullText.includes('factId')) {
      return {
        toolCall: {
          callId: 'c_record_h2',
          name: 'record_fact',
          argumentsJson: JSON.stringify({
            kind: 'note',
            origin: ORIGIN,
            summary: 'Hop 1-2 verified: derived handle ready for Hop 3 webhook signing pivot.',
            data: { subkind: 'chain_progress', hop: 2 },
          }),
        },
      }
    }
    return { hang: true }
  })

  const { storage } = makeStore(t)
  await saveModelProfile({
    name: 'Cont-Live-Mock',
    endpoint: llm.endpoint,
    model: 'mock-cont-live',
    protocol: 'responses',
    key: 'sk-mock-cont-1234',
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

  const { runId, run } = await setupApprovedRun(storage, { seeds: [ORIGIN], budgetUsd: 2, budgetRequests: 500, maxRpsPerOrigin: 10 })
  const progressStep = storage.addChainStep(run, {
    title: 'PROGRESS_CHAIN_STEP multi-hop pivot',
    hypothesis: 'Execute Hops 1-5 across signing boundary [chain_hops=h1->h2->h3->h4].',
    category: 'broken-access-control',
    priority: 95,
    targetAssetIds: run.approved,
    sourceOrigins: [ORIGIN],
    skills: ['multihop-chains', 'chain-primitives'],
  })
  const zeroStep = storage.addChainStep(run, {
    title: 'ZERO_PROGRESS_CHAIN stalled pivot',
    hypothesis: 'Stalled before any progress [chain_hops=h1->h2].',
    category: 'broken-access-control',
    priority: 90,
    targetAssetIds: run.approved,
    sourceOrigins: [ORIGIN],
    skills: ['multihop-chains', 'chain-primitives'],
  })
  storage.updateRun(runId, { phase: 'investigation', status: 'running', workerConcurrency: 3, multiTrialEnabled: false })

  const engine = new Execution(storage, {
    backend: stubBackend(),
    deterministicSweep: false,
    assignmentWallClockOverrideMs: 220,
  })

  await withEnv({ KOVO_ALLOW_LOCAL_LAB: '1' }, async () => {
    engine.start()
    engine.wake()
    const deadline = Date.now() + 5_000
    while (Date.now() < deadline) {
      const steps = storage.listChainSteps(runId, run.goalRevision)
      const cont = steps.find(s => s.dependsOnStepIds.includes(progressStep.id) && extractContinuationDepth(s) === 1)
      const z = steps.find(s => s.id === zeroStep.id)
      if (cont?.status === 'complete' && z?.status === 'complete') break
      await new Promise(r => setTimeout(r, 25))
    }
    await stopExecution(engine as never)
  })

  const allSteps = storage.listChainSteps(runId, run.goalRevision)
  const contForProgress = allSteps.filter(s => s.dependsOnStepIds.includes(progressStep.id))
  const contForZero = allSteps.filter(s => s.dependsOnStepIds.includes(zeroStep.id))

  assert.equal(contForProgress.length, 1, 'progressing rotated multi-hop chain must enqueue exactly one continuation step')
  assert.equal(contForProgress[0]!.status, 'complete', 'enqueued continuation step must dispatch and complete')
  assert.equal(contForZero.length, 0, 'zero-progress rotated multi-hop chain must NOT enqueue a continuation step')

  const events = storage.eventsAfter(runId, 0, 200)
  assert.ok(events.some(e => e.kind === 'worker.hop_continuation_enqueued'), 'expected worker.hop_continuation_enqueued event')
  assert.ok(continuationPromptReceived.includes('v8.hop_checkpoint.v1'), 'continuation worker must receive hydrated v8.hop_checkpoint.v1 brief')
  assert.ok(continuationPromptReceived.includes('DO NOT re-read source'), 'continuation worker must receive explicit no-rediscovery directive')
})

// ============================================================================
// 3. Zero-Turn `StaticWorkspaceSnapshot` Digest Pre-Injection in Code Audit
// ============================================================================

test('buildWorkspaceSourceDigest produces a <= 8 KB multi-service route/guard/sink map and injects it into Turn 1 of runSourceFirstCodeAudit', async (t) => {
  const reposDir = mkdtempSync(join(tmpdir(), 'kovo-digest-repo-'))
  t.after(() => rmSync(reposDir, { recursive: true, force: true }))

  mkdirSync(join(reposDir, 'acme', 'platform', 'services', 'edge'), { recursive: true })
  mkdirSync(join(reposDir, 'acme', 'platform', 'services', 'api'), { recursive: true })
  mkdirSync(join(reposDir, 'acme', 'platform', 'services', 'worker'), { recursive: true })

  writeFileSync(join(reposDir, 'acme', 'platform', 'services', 'edge', 'proxy.ts'), `
import express from 'express'
const app = express()
app.get('/internal/proxy', async (req, res) => {
  const r = await fetch(String(req.query.target))
  res.send(await r.text())
})
`, 'utf8')

  writeFileSync(join(reposDir, 'acme', 'platform', 'services', 'api', 'orders.ts'), `
import express from 'express'
const router = express.Router()
router.get('/api/v1/orders/:id', requireAuth, requireTenantScope, async (req, res) => {
  return db.query('SELECT * FROM orders WHERE id = $1', [req.params.id])
})
router.post('/api/v1/orders/:id/approve', requireAuth, async (req, res) => {
  return db.query('UPDATE orders SET status = $1 WHERE id = $2', ['approved', req.params.id])
})
`, 'utf8')

  writeFileSync(join(reposDir, 'acme', 'platform', 'services', 'api', 'schema.graphql'), `
type Query {
  orderById(id: ID!): String
}
type Mutation {
  approveOrder(id: ID!): Boolean
}
`, 'utf8')

  writeFileSync(join(reposDir, 'acme', 'platform', 'services', 'worker', 'webhook.ts'), `
export async function verifyWebhookSignature(req: { headers: Record<string, string> }) {
  const sig = req.headers['x-hub-signature']
  return Boolean(sig)
}
export async function onJob(job: { callbackUrl: string }) {
  return fetch(job.callbackUrl)
}
`, 'utf8')

  const snapshot = buildStaticWorkspaceSnapshot(reposDir, { mountedRepos: ['acme/platform'] })
  const digest = buildWorkspaceSourceDigest(snapshot, MAX_WORKSPACE_DIGEST_BYTES)
  assert.ok(Buffer.byteLength(digest, 'utf8') <= MAX_WORKSPACE_DIGEST_BYTES, 'digest must be strictly <= 8 KB')
  assert.match(digest, /services\/edge/, 'digest must group edge service')
  assert.match(digest, /services\/api/, 'digest must group api service')
  assert.match(digest, /services\/worker/, 'digest must group worker service')
  assert.match(digest, /GET \/internal\/proxy @ .+:4/, 'digest must include unguarded route with file:line')
  assert.match(digest, /guards=\[NONE\]/, 'digest must highlight unguarded routes')
  assert.match(digest, /requireAuth/, 'digest must include authz guards')
  assert.match(digest, /\[graphql\]/, 'digest must include GraphQL schema/resolver ops')
  assert.match(digest, /\[webhook\/worker\]/, 'digest must include webhook/worker handlers')
  assert.match(digest, /Key Sinks & Handlers/, 'digest must list key sinks with file:line')

  // Stress bound: large workspace with 180 routes still stays strictly <= 8 KB
  const bigDir = mkdtempSync(join(tmpdir(), 'kovo-digest-big-'))
  t.after(() => rmSync(bigDir, { recursive: true, force: true }))
  mkdirSync(join(bigDir, 'svc', 'routes'), { recursive: true })
  const bigRoutes = Array.from({ length: 180 }, (_, i) =>
    `app.get('/api/v1/resource-${i}/:id', async (req, res) => db.query('SELECT ' + req.params.id))`,
  ).join('\n')
  writeFileSync(join(bigDir, 'svc', 'routes', 'many.ts'), `import express from 'express'\nconst app = express()\n${bigRoutes}\n`, 'utf8')
  const bigSnap = buildStaticWorkspaceSnapshot(bigDir)
  const bigDigest = buildWorkspaceSourceDigest(bigSnap, MAX_WORKSPACE_DIGEST_BYTES)
  assert.ok(Buffer.byteLength(bigDigest, 'utf8') <= MAX_WORKSPACE_DIGEST_BYTES, `oversized workspace digest (${Buffer.byteLength(bigDigest, 'utf8')} B) must stay <= 8192 B`)

  // Live runSourceFirstCodeAudit Turn-1 injection check
  const capturedBodies: Array<Record<string, unknown>> = []
  const llm = await startMockLlmServer(t, body => {
    capturedBodies.push(body)
    return {
      toolCall: {
        callId: 'c_audit_done',
        name: 'complete_intent',
        argumentsJson: JSON.stringify({ status: 'completed', summary: 'Audited from Turn-1 digest.' }),
      },
    }
  })

  const { storage } = makeStore(t)
  const { runId } = await setupApprovedRun(storage, { seeds: [ORIGIN], tier: 2 })
  const run = storage.run(runId)
  await saveModelProfile({
    name: 'Audit-Digest-Mock',
    endpoint: llm.endpoint,
    model: 'mock-audit-digest',
    protocol: 'responses',
    key: 'sk-mock-audit-1234',
    priority: 100,
    enabled: true,
    contextWindow: 128_000,
    maxTokens: 4096,
    thinkingLevel: 'medium',
    roleAffinity: 'reasoning',
    inputCostPerMtok: 0,
    cachedInputCostPerMtok: 0,
    outputCostPerMtok: 0,
  }, storage, { skipConnectionCheck: true })
  const profiles = await privateModelProfiles(storage)

  const engine = new Execution(storage, { backend: stubBackend(), maxDurationMs: 600_000 })
  t.after(() => engine.stop())
  internals(engine).projectReposMount = () => ({ reposDir, mountedRepos: ['acme/platform'] })

  await withEnv({ KOVO_STAGE1_LLM: '0' }, async () => {
    await engine.runSourceFirstCodeAudit(run, [], profiles, new AbortController().signal)
  })

  assert.ok(capturedBodies.length >= 1, 'code auditor must have executed Turn 1')
  const turn1Text = JSON.stringify(capturedBodies[0])
  assert.ok(turn1Text.includes('workspace_source_digest'), 'Turn 1 specsSummary must include workspace_source_digest entry')
  assert.ok(turn1Text.includes('/internal/proxy'), 'Turn 1 code audit prompt must expose discovered routes immediately')
  assert.ok(turn1Text.includes('services/worker'), 'Turn 1 code audit prompt must expose multi-service directory map immediately')
})
