/**
 * v8 Queue #25 Multi-Hop Scheduling & Phase-A-to-Phase-B Promotion Regression Tests.
 *
 * Proves (Docker-free, real SQLite WAL `Store`, real `Execution`, real `ExecReconPlanner`,
 * synthetic mock Responses LLM server):
 *  1. `benchmark-multihop.ts` CLI accepts `--duration-min <m>` as an alias for `--max-duration-ms`,
 *     rejects conflicting / non-positive / out-of-range values, and forwards `maxDurationMs` into
 *     `new Execution(...)` so 15m runs yield 270s (settlement 245s) and 30m runs yield 300s
 *     (settlement 275s) for multi-hop chain workers.
 *  2. Fair Multi-Hop Frontier Interleaving (`planRoundRobinDispatch` + `enqueueHopContinuationOnRotation`):
 *     - Distinguishes high-signal source/planner multi-hop chains from generic Wave-1 boundary stubs.
 *     - Caps automatic continuations on generic Wave-1 heuristic chains at 1 (and unsealed chains
 *       at 1), while allowing 2 for source/planner-backed chains that sealed >= 1 `cap:hop_*`
 *       handle in `CapabilityLedger` (without stealing another worker's ledger handles).
 *     - Orders the `chain` lane strictly as:
 *         (1) unstarted (depth 0) source-audit / planner-synthesized multi-hop chains,
 *         (2) depth 1 continuations that sealed a `cap:hop_*` handle,
 *         (3) remaining unstarted Wave-1 boundary chains,
 *         (4) depth 1 unsealed continuations,
 *         (5) depth >= 2 continuations.
 *  3. Source-First Code Audit cross-cutting fact promotion:
 *     - Collects BOTH `kind === 'code_audit_suspect'` facts AND non-tainted cross-cutting defect
 *       facts authored by `codeAuditAssignmentId` (or recorded in the code-audit window),
 *       excluding benign inventory / fingerprint / checkpoint notes.
 *     - Deduplicates and bounds promotion to up to 6 targeted multi-hop `chain` steps queued
 *       immediately into Wave 1 with `dependsOnFactIds` pointing to those facts so they receive
 *       Rank 0 priority ahead of generic Wave-1 boundary stubs.
 */
import assert from 'node:assert/strict'
import { mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { createServer, type Server } from 'node:http'
import type { AddressInfo } from 'node:net'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import { test } from 'node:test'

import { parseMultihopArgs } from '../scripts/benchmark-multihop.ts'
import { formatDerivedCapabilityHandle } from '../src/server/capability-ledger.ts'
import {
  CHAIN_CONTINUATION_SKILL_PREFIX,
  CODE_AUDIT_WAVE1_MAX_STEPS,
  Execution,
  HOP_CONTINUATION_DIRECTIVE,
  MAX_CHAIN_CONTINUATIONS,
  MAX_GENERIC_WAVE1_CHAIN_CONTINUATIONS,
  chainLaneDispatchRank,
  classifyDispatchLane,
  extractContinuationDepth,
  hasSealedHopCapability,
  isGenericWave1BoundaryChainStep,
  isHighSignalSourceOrPlannerChainStep,
  isMultiHopChainStep,
  isPromotableCodeAuditFact,
  planRoundRobinDispatch,
  resolveWorkerSettlementMs,
  resolveWorkerWallClockMs,
  settleCodeAuditSuspects,
  type DispatchLaneStep,
} from '../src/server/execution.ts'
import { CHECKPOINT_CAP_SKILL_PREFIX, type ExecReconPlanner } from '../src/server/exec-recon-planner.ts'
import { privateModelProfiles, saveModelProfile } from '../src/server/model-settings.ts'
import type { WorkerBackend, WorkerSession } from '../src/server/worker-backend.ts'
import { makeStore, setupApprovedRun, stopExecution, withEnv } from './v4-tier-helpers.ts'

process.env.GUARDIAN_ALLOW_LOCAL_LAB = '1'

const ORIGIN = 'https://saas.example.invalid'

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
  toolCalls?: Array<{ callId: string; name: string; argumentsJson: string }>
  text?: string
}

async function startMockResponsesServer(
  t: { after: (fn: () => void | Promise<void>) => void },
  handler: (body: Record<string, unknown>, reqIndex: number) => MockLlmReply,
): Promise<{ endpoint: string; calls: Array<Record<string, unknown>> }> {
  const calls: Array<Record<string, unknown>> = []
  const server: Server = createServer((req, res) => {
    const chunks: Buffer[] = []
    req.on('data', chunk => chunks.push(chunk as Buffer))
    req.on('end', () => {
      const body = JSON.parse(Buffer.concat(chunks).toString('utf8') || '{}') as Record<string, unknown>
      calls.push(body)
      const reply = handler(body, calls.length)
      res.statusCode = 200
      res.setHeader('Content-Type', 'text/event-stream')
      res.setHeader('Cache-Control', 'no-cache')
      const idx = calls.length
      const responseId = `resp_${idx}`
      const emit = (event: string, data: Record<string, unknown>) => {
        res.write(`event: ${event}\ndata: ${JSON.stringify(data)}\n\n`)
      }
      emit('response.created', { type: 'response.created', response: { id: responseId, status: 'in_progress', output: [] } })
      if (reply.toolCalls?.length) {
        const output: Array<Record<string, unknown>> = []
        reply.toolCalls.forEach((tc, outIdx) => {
          const itemId = `item_${idx}_${outIdx}`
          emit('response.output_item.added', {
            type: 'response.output_item.added',
            output_index: outIdx,
            item: { id: itemId, type: 'function_call', status: 'in_progress', call_id: tc.callId, name: tc.name, arguments: '' },
          })
          emit('response.function_call_arguments.done', {
            type: 'response.function_call_arguments.done',
            output_index: outIdx,
            item_id: itemId,
            name: tc.name,
            arguments: tc.argumentsJson,
          })
          const doneItem = {
            id: itemId,
            type: 'function_call',
            status: 'completed',
            call_id: tc.callId,
            name: tc.name,
            arguments: tc.argumentsJson,
          }
          emit('response.output_item.done', {
            type: 'response.output_item.done',
            output_index: outIdx,
            item: doneItem,
          })
          output.push(doneItem)
        })
        emit('response.completed', {
          type: 'response.completed',
          response: {
            id: responseId,
            status: 'completed',
            output,
            usage: { input_tokens: 90, output_tokens: 35, total_tokens: 125 },
          },
        })
      } else {
        const text = reply.text ?? 'done'
        const itemId = `item_${idx}_0`
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
        const doneItem = {
          id: itemId,
          type: 'message',
          status: 'completed',
          role: 'assistant',
          content: [{ type: 'output_text', text }],
        }
        emit('response.output_item.done', {
          type: 'response.output_item.done',
          output_index: 0,
          item: doneItem,
        })
        emit('response.completed', {
          type: 'response.completed',
          response: {
            id: responseId,
            status: 'completed',
            output: [doneItem],
            usage: { input_tokens: 70, output_tokens: 25, total_tokens: 95 },
          },
        })
      }
      res.write('data: [DONE]\n\n')
      res.end()
    })
  })
  await new Promise<void>(resolveListen => server.listen(0, '127.0.0.1', () => resolveListen()))
  const port = (server.address() as AddressInfo).port
  t.after(async () => {
    server.closeAllConnections?.()
    await new Promise<void>(resolveClose => server.close(() => resolveClose()))
  })
  return { endpoint: `http://127.0.0.1:${port}/v1`, calls }
}

type ExecInternals = {
  reconPlanner: ExecReconPlanner
  projectReposMount: (projectId: string) => { reposDir?: string; mountedRepos: string[] }
}

function internals(execution: Execution): ExecInternals {
  return execution as unknown as ExecInternals
}

// ============================================================================
// 1. `--duration-min` Alias, `maxDurationMs` Forwarding & 270s / 300s Budgets
// ============================================================================

test('parseMultihopArgs supports --duration-min, rejects conflicts/invalid inputs, and benchmark-multihop forwards maxDurationMs to Execution', () => {
  const args15 = parseMultihopArgs(['--seed', '1', '--duration-min', '15'])
  assert.equal(args15.maxDurationMs, 900_000)

  const args30 = parseMultihopArgs(['--seed', '1', '--duration-min', '30'])
  assert.equal(args30.maxDurationMs, 1_800_000)

  assert.throws(
    () => parseMultihopArgs(['--duration-min', '15', '--max-duration-ms', '15m']),
    /use either --max-duration-ms or --duration-min, not both/i,
  )
  assert.throws(
    () => parseMultihopArgs(['--duration-min', '0']),
    /positive number of minutes/i,
  )
  assert.throws(
    () => parseMultihopArgs(['--duration-min', '-10']),
    /positive number of minutes/i,
  )
  assert.throws(
    () => parseMultihopArgs(['--duration-min', 'not-a-number']),
    /positive number of minutes/i,
  )
  assert.throws(
    () => parseMultihopArgs(['--duration-min']),
    /requires a positive number of minutes/i,
  )
  assert.throws(
    () => parseMultihopArgs(['--duration-min', '500']),
    /between 1 and 360 minutes/i,
  )

  // Verify the harness wires args.maxDurationMs directly into `new Execution(storage, { ... })`.
  const runnerSrc = readFileSync(resolve('scripts/benchmark-multihop.ts'), 'utf8')
  const execCtorMatch = /engine = new Execution\(storage,\s*\{[\s\S]*?\n    \}\)/m.exec(runnerSrc)
  assert.ok(execCtorMatch, 'expected engine = new Execution(storage, { ... }) in scripts/benchmark-multihop.ts')
  assert.match(execCtorMatch[0], /maxDurationMs:\s*args\.maxDurationMs/, 'benchmark-multihop.ts must pass maxDurationMs: args.maxDurationMs into Execution')
})

test('Execution computes 270s wall-clock on 15m run and 300s on 30m run for multi-hop chain workers', async (t) => {
  const llm = await startMockResponsesServer(t, () => ({
    toolCalls: [{
      callId: 'c_done',
      name: 'complete_intent',
      argumentsJson: JSON.stringify({ status: 'ruled_out', summary: 'Done.' }),
    }],
  }))

  for (const [durationMin, expectedWallMs, expectedSettleMs] of [
    [15, 270_000, 245_000],
    [30, 300_000, 275_000],
  ] as const) {
    const { maxDurationMs } = parseMultihopArgs(['--seed', '1', '--duration-min', String(durationMin)])
    const { storage } = makeStore(t)
    await saveModelProfile({
      name: `Mock-${durationMin}m`,
      endpoint: llm.endpoint,
      model: 'mock-dur',
      protocol: 'responses',
      key: 'sk-mock-dur-1234',
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
      title: `Source audit verify · /api/v1/webhooks (${durationMin}m)`,
      hypothesis: 'Multi-hop chain verify across signing boundary [chain_hops=h1->h2->h3].',
      category: 'broken-access-control',
      priority: 95,
      targetAssetIds: run.approved,
      sourceOrigins: [ORIGIN],
      skills: ['source-first-audit', 'multihop-chains', 'chain-primitives'],
    })
    assert.equal(resolveWorkerWallClockMs(chainStep, maxDurationMs), expectedWallMs)
    assert.equal(resolveWorkerSettlementMs(expectedWallMs, true), expectedSettleMs)

    storage.updateRun(runId, { phase: 'investigation', status: 'running', workerConcurrency: 3, multiTrialEnabled: false })
    const engine = new Execution(storage, { backend: stubBackend(), deterministicSweep: false, maxDurationMs })
    await withEnv({ GUARDIAN_ALLOW_LOCAL_LAB: '1' }, async () => {
      engine.start()
      engine.wake()
      const deadline = Date.now() + 4_000
      while (Date.now() < deadline) {
        if (storage.eventsAfter(runId, 0, 100).some(e => e.kind === 'worker.started')) break
        await new Promise(r => setTimeout(r, 20))
      }
      await stopExecution(engine as never)
    })

    const started = storage.eventsAfter(runId, 0, 100)
      .find(e => e.kind === 'worker.started' && (e.detail as { stepId?: string }).stepId === chainStep.id)
    assert.ok(started, `expected worker.started for ${durationMin}m run`)
    const budget = (started.detail as { assignmentBudget?: { wallClockMs?: number; wallClockSettlementMs?: number } }).assignmentBudget
    assert.equal(budget?.wallClockMs, expectedWallMs, `${durationMin}m chain worker must get ${expectedWallMs}ms`)
    assert.equal(budget?.wallClockSettlementMs, expectedSettleMs, `${durationMin}m chain worker settlement must be ${expectedSettleMs}ms`)
  }
})

// ============================================================================
// 2. Fair Multi-Hop Frontier Interleaving & Wave-1 Continuation Cap
// ============================================================================

test('planRoundRobinDispatch enforces 4-tier fair interleaving: source/planner depth-0 > sealed depth-1 > Wave-1 stub > unsealed depth-1 > depth-2', () => {
  const sourceAuditChain: DispatchLaneStep = {
    id: 'src-chain-1',
    seq: 10,
    priority: 92,
    title: 'Source audit verify · /api/v1/webhooks/sign (saas.example.invalid)',
    category: 'auth-identity',
    hypothesis: 'Source-First Code Audit suspect at services/api/webhooks.ts:44 targeting /api/v1/webhooks/sign.',
    skills: ['source-first-audit', 'multihop-chains', 'chain-primitives'],
    dependsOnFactIds: ['fact-audit-1'],
    dependsOnStepIds: [],
    sourceOrigins: [ORIGIN],
    trialIndex: 0,
  }
  const plannerArrowChain: DispatchLaneStep = {
    id: 'planner-chain-1',
    seq: 11,
    priority: 90,
    title: 'Cross-service token pivot',
    category: 'broken-access-control',
    hypothesis: 'Pivot derived token from edge proxy -> internal worker -> admin export.',
    skills: ['multihop-chains', 'chain-primitives'],
    dependsOnFactIds: [],
    dependsOnStepIds: [],
    sourceOrigins: [ORIGIN],
    trialIndex: 0,
  }
  const sealedCont1: DispatchLaneStep = {
    id: 'sealed-cont-1',
    seq: 2,
    priority: 98,
    title: 'Token pivot [continuation #1]',
    category: 'broken-access-control',
    hypothesis: HOP_CONTINUATION_DIRECTIVE,
    skills: [
      'multihop-chains',
      'chain-primitives',
      `${CHAIN_CONTINUATION_SKILL_PREFIX}1`,
      `${CHECKPOINT_CAP_SKILL_PREFIX}cap:hop_1:derived_token`,
    ],
    dependsOnFactIds: ['fact-cp-1'],
    dependsOnStepIds: ['parent-1'],
    sourceOrigins: [ORIGIN],
    trialIndex: 0,
  }
  const wave1Stub: DispatchLaneStep = {
    id: 'wave1-stub-1',
    seq: 1,
    priority: 96,
    title: 'Wave-1 chain · Cross-service boundary chain (downstream_service/http)',
    category: 'broken-access-control',
    hypothesis: '[chain_hops=3] [lane=chain] [inv_hyp=inv-1] [cap=cap:hop_synth:edge] Multi-hop invariant chain',
    skills: ['multihop-chains', 'chain-primitives'],
    dependsOnFactIds: [],
    dependsOnStepIds: [],
    sourceOrigins: [ORIGIN],
    trialIndex: 0,
  }
  const wave1Cont1Unsealed: DispatchLaneStep = {
    id: 'wave1-cont-1',
    seq: 3,
    priority: 98,
    title: 'Wave-1 chain · Cross-service boundary chain (downstream_service/http) [continuation #1]',
    category: 'broken-access-control',
    hypothesis: HOP_CONTINUATION_DIRECTIVE,
    skills: ['multihop-chains', 'chain-primitives', `${CHAIN_CONTINUATION_SKILL_PREFIX}1`],
    dependsOnFactIds: ['fact-w1-note'],
    dependsOnStepIds: ['wave1-stub-0'],
    sourceOrigins: [ORIGIN],
    trialIndex: 0,
  }
  const contDepth2: DispatchLaneStep = {
    id: 'cont-depth-2',
    seq: 4,
    priority: 100,
    title: 'Earlier chain [continuation #2]',
    category: 'broken-access-control',
    hypothesis: HOP_CONTINUATION_DIRECTIVE,
    skills: [
      'multihop-chains',
      'chain-primitives',
      `${CHAIN_CONTINUATION_SKILL_PREFIX}2`,
      `${CHECKPOINT_CAP_SKILL_PREFIX}cap:hop_2:derived_signer`,
    ],
    dependsOnFactIds: ['fact-cp-2'],
    dependsOnStepIds: ['parent-cont-1'],
    sourceOrigins: [ORIGIN],
    trialIndex: 0,
  }

  assert.equal(isGenericWave1BoundaryChainStep(wave1Stub), true)
  assert.equal(isGenericWave1BoundaryChainStep(wave1Cont1Unsealed), true)
  assert.equal(isGenericWave1BoundaryChainStep(sourceAuditChain), false)
  assert.equal(isGenericWave1BoundaryChainStep(plannerArrowChain), false)
  assert.equal(isHighSignalSourceOrPlannerChainStep(sourceAuditChain), true)
  assert.equal(isHighSignalSourceOrPlannerChainStep(plannerArrowChain), true)
  assert.equal(isHighSignalSourceOrPlannerChainStep(wave1Stub), false)
  assert.equal(hasSealedHopCapability(sealedCont1), true)
  assert.equal(hasSealedHopCapability(wave1Stub), false, 'static cap:hop_synth:* seed is NOT a runtime-sealed handle')
  assert.equal(hasSealedHopCapability(wave1Cont1Unsealed), false)

  assert.equal(chainLaneDispatchRank(sourceAuditChain), 0)
  assert.equal(chainLaneDispatchRank(plannerArrowChain), 0)
  assert.equal(chainLaneDispatchRank(sealedCont1), 1)
  assert.equal(chainLaneDispatchRank(wave1Stub), 2)
  assert.equal(chainLaneDispatchRank(wave1Cont1Unsealed), 3)
  assert.equal(chainLaneDispatchRank(contDepth2), 4)

  const plan = planRoundRobinDispatch(
    [contDepth2, wave1Cont1Unsealed, wave1Stub, sealedCont1, plannerArrowChain, sourceAuditChain],
    6,
  )
  assert.deepEqual(
    plan.ordered.map(s => s.id),
    ['src-chain-1', 'planner-chain-1', 'sealed-cont-1', 'wave1-stub-1', 'wave1-cont-1', 'cont-depth-2'],
  )

  // Even when `sourceMounted: true` lifts white-box steps, a depth-2 white-box continuation must
  // NEVER preempt an unstarted depth-0 white-box chain.
  const wbCont2: DispatchLaneStep = {
    ...contDepth2,
    id: 'wb-cont-2',
    skills: [...(contDepth2.skills ?? []), 'source-first-audit'],
  }
  const wbPlan = planRoundRobinDispatch([wbCont2, sourceAuditChain], 2, { sourceMounted: true })
  assert.deepEqual(wbPlan.ordered.map(s => s.id), ['src-chain-1', 'wb-cont-2'])
})

test('enqueueHopContinuationOnRotation caps generic Wave-1 and unsealed chains at 1, and allows 2 only for sealed source/planner chains', async (t) => {
  assert.equal(MAX_GENERIC_WAVE1_CHAIN_CONTINUATIONS, 1)
  assert.equal(MAX_CHAIN_CONTINUATIONS, 2)

  const { storage } = makeStore(t)
  const { runId, run } = await setupApprovedRun(storage, { seeds: [ORIGIN], tier: 2 })
  const asset = run.candidates.find(c => run.approved.includes(c.id))!
  const engine = new Execution(storage, { backend: stubBackend(), maxDurationMs: 900_000 })
  t.after(() => engine.stop())
  const planner = internals(engine).reconPlanner

  const worker = storage.makeWorker(run, 'investigation', asset, 'Worker', 'Hyp', { sourceOrigins: [ORIGIN] })
  const noteFact = storage.addFact(run, worker, {
    kind: 'note',
    origin: ORIGIN,
    summary: 'Observed proxy forwarding behavior on /internal/dispatch.',
    data: { subkind: 'chain_progress' },
    sourceOrigins: [ORIGIN],
  })

  // Seed an UNRELATED sealed capability in the ledger to ensure a generic Wave-1 chain cannot
  // steal it and masquerade as a sealed chain.
  const ledger = storage.capabilityLedger(runId)
  const unrelatedCap = formatDerivedCapabilityHandle('other_chain', 'derived_secret')
  ledger.addCapability({
    capId: unrelatedCap,
    kind: 'signing_material',
    provenance: 'derived_hop',
    tenantScope: 'org_alpha',
    actorPersona: 'member_alpha',
    serviceOrigin: ORIGIN,
    surface: 'http',
    artifactDigest: 'c'.repeat(64),
    artifactSummary: 'Unrelated chain derived secret handle',
    createdAtMs: 1000,
  })

  // Case A: Generic Wave-1 heuristic boundary chain -> capped at 1 continuation even with progress
  const wave1Step = storage.addChainStep(run, {
    title: 'Wave-1 chain · Cross-service boundary chain (downstream_service/http)',
    hypothesis: '[chain_hops=3] [lane=chain] [inv_hyp=inv-boundary] [cap=cap:hop_synth:boundary] Multi-hop invariant chain.',
    category: 'broken-access-control',
    priority: 96,
    targetAssetIds: [asset.id],
    sourceOrigins: [ORIGIN],
    skills: ['multihop-chains', 'chain-primitives'],
  })
  storage.updateChainStep(wave1Step.id, { status: 'complete', assignedWorkerId: worker.id })

  const w1Cont1 = planner.enqueueHopContinuationOnRotation({
    run,
    step: wave1Step,
    assignment: worker,
    targetOrigins: [ORIGIN],
    confirmed: false,
    partialSummary: '[partial] Probed downstream boundary.',
    recordedFacts: [noteFact],
    recordedExchanges: [{ id: 'ex-w1', origin: ORIGIN, method: 'GET', pathAndQuery: '/internal/dispatch', status: 200 }],
    sealedCapHandles: [],
  })
  assert.equal(w1Cont1.enqueued, true)
  assert.equal(w1Cont1.continuationDepth, 1)
  assert.equal(w1Cont1.checkpointCapId, undefined, 'must not steal unrelated ledger handle')
  assert.equal(isGenericWave1BoundaryChainStep(w1Cont1.continuationStep!), true)

  // Rotating Wave-1 continuation #1 MUST be blocked at depth 1 (`max_continuations_reached`)
  storage.updateChainStep(w1Cont1.continuationStep!.id, { status: 'complete', assignedWorkerId: worker.id })
  const w1Cont2 = planner.enqueueHopContinuationOnRotation({
    run,
    step: w1Cont1.continuationStep!,
    assignment: worker,
    targetOrigins: [ORIGIN],
    confirmed: false,
    partialSummary: '[partial] Still probing generic Wave-1 boundary.',
    recordedFacts: [noteFact],
    recordedExchanges: [{ id: 'ex-w1-2', origin: ORIGIN, method: 'GET', pathAndQuery: '/internal/dispatch', status: 200 }],
    sealedCapHandles: [],
  })
  assert.equal(w1Cont2.enqueued, false)
  assert.equal(w1Cont2.reason, 'max_continuations_reached')

  // Case B: Source-derived chain WITHOUT a sealed cap:hop_* handle -> capped at 1 continuation
  const unsealedSourceStep = storage.addChainStep(run, {
    title: 'Source audit verify · /api/v1/exports (saas.example.invalid)',
    hypothesis: 'Source-First Code Audit suspect targeting /api/v1/exports.',
    category: 'broken-access-control',
    priority: 94,
    targetAssetIds: [asset.id],
    sourceOrigins: [ORIGIN],
    dependsOnFactIds: [noteFact.id],
    skills: ['source-first-audit', 'multihop-chains', 'chain-primitives'],
  })
  storage.updateChainStep(unsealedSourceStep.id, { status: 'complete', assignedWorkerId: worker.id })

  const srcUnsealed1 = planner.enqueueHopContinuationOnRotation({
    run,
    step: unsealedSourceStep,
    assignment: worker,
    targetOrigins: [ORIGIN],
    confirmed: false,
    partialSummary: '[partial] Found candidate route, no cap sealed yet.',
    recordedFacts: [noteFact],
    recordedExchanges: [],
    sealedCapHandles: [],
  })
  assert.equal(srcUnsealed1.enqueued, true)
  assert.equal(srcUnsealed1.continuationDepth, 1)

  storage.updateChainStep(srcUnsealed1.continuationStep!.id, { status: 'complete', assignedWorkerId: worker.id })
  const srcUnsealed2 = planner.enqueueHopContinuationOnRotation({
    run,
    step: srcUnsealed1.continuationStep!,
    assignment: worker,
    targetOrigins: [ORIGIN],
    confirmed: false,
    partialSummary: '[partial] Still no cap sealed.',
    recordedFacts: [noteFact],
    recordedExchanges: [],
    sealedCapHandles: [],
  })
  assert.equal(srcUnsealed2.enqueued, false)
  assert.equal(srcUnsealed2.reason, 'max_continuations_reached')

  // Case C: Source-derived chain WITH a sealed cap:hop_* in CapabilityLedger -> allowed depth 2!
  const ownCap = formatDerivedCapabilityHandle('src_chain_1', 'webhook_signer')
  ledger.addCapability({
    capId: ownCap,
    kind: 'signing_material',
    provenance: 'derived_hop',
    tenantScope: 'org_alpha',
    actorPersona: 'member_alpha',
    serviceOrigin: ORIGIN,
    surface: 'webhook',
    artifactDigest: 'd'.repeat(64),
    artifactSummary: 'Derived webhook signing material handle',
    createdAtMs: 1100,
  })
  const sealedSourceStep = storage.addChainStep(run, {
    title: 'Source audit verify · /api/v1/webhooks/dispatch (saas.example.invalid)',
    hypothesis: 'Source-First Code Audit suspect targeting /api/v1/webhooks/dispatch.',
    category: 'auth-identity',
    priority: 95,
    targetAssetIds: [asset.id],
    sourceOrigins: [ORIGIN],
    dependsOnFactIds: [noteFact.id],
    skills: ['source-first-audit', 'multihop-chains', 'chain-primitives'],
  })
  storage.updateChainStep(sealedSourceStep.id, { status: 'complete', assignedWorkerId: worker.id })

  const srcSealed1 = planner.enqueueHopContinuationOnRotation({
    run,
    step: sealedSourceStep,
    assignment: worker,
    targetOrigins: [ORIGIN],
    confirmed: false,
    partialSummary: `[partial] Sealed ${ownCap}.`,
    recordedFacts: [noteFact],
    recordedExchanges: [{ id: 'ex-s1', origin: ORIGIN, method: 'POST', pathAndQuery: '/api/v1/webhooks/dispatch', status: 202 }],
    sealedCapHandles: [ownCap],
  })
  assert.equal(srcSealed1.enqueued, true)
  assert.equal(srcSealed1.continuationDepth, 1)
  assert.equal(srcSealed1.checkpointCapId, ownCap)
  assert.equal(hasSealedHopCapability(srcSealed1.continuationStep!), true)

  storage.updateChainStep(srcSealed1.continuationStep!.id, { status: 'complete', assignedWorkerId: worker.id })
  const srcSealed2 = planner.enqueueHopContinuationOnRotation({
    run,
    step: srcSealed1.continuationStep!,
    assignment: worker,
    targetOrigins: [ORIGIN],
    confirmed: false,
    partialSummary: '[partial] Polled async job, executing terminal proof.',
    recordedFacts: [noteFact],
    recordedExchanges: [{ id: 'ex-s2', origin: ORIGIN, method: 'GET', pathAndQuery: '/api/v1/jobs/99', status: 200 }],
    sealedCapHandles: [ownCap],
  })
  assert.equal(srcSealed2.enqueued, true)
  assert.equal(srcSealed2.continuationDepth, 2)
  assert.equal(extractContinuationDepth(srcSealed2.continuationStep!), 2)

  // Depth 3 is still blocked.
  storage.updateChainStep(srcSealed2.continuationStep!.id, { status: 'complete', assignedWorkerId: worker.id })
  const srcSealed3 = planner.enqueueHopContinuationOnRotation({
    run,
    step: srcSealed2.continuationStep!,
    assignment: worker,
    targetOrigins: [ORIGIN],
    confirmed: false,
    partialSummary: '[partial] Beyond max depth.',
    recordedFacts: [noteFact],
    recordedExchanges: [],
    sealedCapHandles: [ownCap],
  })
  assert.equal(srcSealed3.enqueued, false)
  assert.equal(srcSealed3.reason, 'max_continuations_reached')
})

// ============================================================================
// 3. Source-First Code Audit Cross-Cutting Fact Promotion (Up to 6 Wave-1 Steps)
// ============================================================================

test('isPromotableCodeAuditFact filters concrete security defects vs benign inventory/fingerprint notes', () => {
  assert.equal(isPromotableCodeAuditFact({
    kind: 'code_audit_suspect',
    summary: 'Missing tenant scope on /api/v1/orders/:id',
    data: {},
    tainted: false,
  }), true)
  assert.equal(isPromotableCodeAuditFact({
    kind: 'note',
    summary: 'Authz asymmetry: GET /api/v1/exports checks orgId, but POST /api/v1/exports/batch omits tenant check.',
    data: { file: 'services/api/exports.ts', line: 84 },
    tainted: false,
  }), true)
  assert.equal(isPromotableCodeAuditFact({
    kind: 'note',
    summary: 'Trust-boundary leak: edge proxy forwards caller X-Forwarded-Role directly to internal admin service.',
    data: { routeOrAction: '/internal/admin/impersonate' },
    tainted: false,
  }), true)
  assert.equal(isPromotableCodeAuditFact({
    kind: 'note',
    summary: 'Async worker logs webhook HMAC signing secret in plaintext during retry error handling.',
    data: {},
    tainted: false,
  }), true)

  // Non-defect / excluded facts
  assert.equal(isPromotableCodeAuditFact({
    kind: 'note',
    summary: 'Repository layout contains 11 TypeScript files across 5 services.',
    data: {},
    tainted: false,
  }), false)
  assert.equal(isPromotableCodeAuditFact({
    kind: 'tech_fingerprint',
    summary: 'Express 4.19 on Node.js 22 with PostgreSQL.',
    data: {},
    tainted: false,
  }), false)
  assert.equal(isPromotableCodeAuditFact({
    kind: 'note',
    summary: 'Hop checkpoint (branch)',
    data: { subkind: 'hop_checkpoint' },
    tainted: false,
  }), false)
  assert.equal(isPromotableCodeAuditFact({
    kind: 'note',
    summary: 'Missing auth on /api/v1/tainted',
    data: {},
    tainted: true,
  }), false)
})

test('runSourceFirstCodeAudit promotes explicit suspects AND cross-cutting defect facts (up to 6) into Wave-1 multi-hop chain steps with top priority', async (t) => {
  const reposDir = mkdtempSync(join(tmpdir(), 'guardian-q25-audit-'))
  t.after(() => rmSync(reposDir, { recursive: true, force: true }))
  mkdirSync(join(reposDir, 'acme', 'services', 'api'), { recursive: true })
  writeFileSync(join(reposDir, 'acme', 'services', 'api', 'server.ts'), 'export const ok = true\n', 'utf8')

  const llm = await startMockResponsesServer(t, (_body, reqIndex) => {
    if (reqIndex === 1) {
      // Simulate Queue #24: auditor records 1 explicit code_audit_suspect + 5 cross-cutting
      // security defect facts under `kind: "note"` / `"auth_boundary"` + 2 benign inventory notes.
      return {
        toolCalls: [
          {
            callId: 'f1',
            name: 'record_fact',
            argumentsJson: JSON.stringify({
              kind: 'code_audit_suspect',
              origin: ORIGIN,
              summary: 'Missing tenant scope on POST /api/v1/ledger/transfer allows cross-tenant debit.',
              data: { file: 'services/api/ledger.ts', line: 42, routeOrAction: 'POST /api/v1/ledger/transfer', sinkKind: 'api_route', authCheck: 'present', ownershipCheck: 'missing' },
            }),
          },
          {
            callId: 'f2',
            name: 'record_fact',
            argumentsJson: JSON.stringify({
              kind: 'note',
              origin: ORIGIN,
              summary: 'Trust-boundary leak: edge proxy forwards untrusted X-Internal-Role header to /internal/roles/grant.',
              data: { file: 'services/edge/proxy.ts', line: 19, routeOrAction: 'POST /internal/roles/grant' },
            }),
          },
          {
            callId: 'f3',
            name: 'record_fact',
            argumentsJson: JSON.stringify({
              kind: 'note',
              origin: ORIGIN,
              summary: 'Webhook HMAC verification bypass on POST /api/v1/webhooks/ingest when signature header is omitted.',
              data: { file: 'services/api/webhooks.ts', line: 77, routeOrAction: 'POST /api/v1/webhooks/ingest' },
            }),
          },
          {
            callId: 'f4',
            name: 'record_fact',
            argumentsJson: JSON.stringify({
              kind: 'note',
              origin: ORIGIN,
              summary: 'Async worker outbound fetch SSRF sink on POST /api/v1/exports/deliver follows redirects to internal metadata.',
              data: { file: 'services/worker/deliver.ts', line: 105, routeOrAction: 'POST /api/v1/exports/deliver' },
            }),
          },
          {
            callId: 'f5',
            name: 'record_fact',
            argumentsJson: JSON.stringify({
              kind: 'note',
              origin: ORIGIN,
              summary: 'Secret token exposure: debug endpoint GET /api/v1/audit/logs leaks signing key in error payload.',
              data: { file: 'services/api/audit.ts', line: 61, routeOrAction: 'GET /api/v1/audit/logs' },
            }),
          },
          {
            callId: 'f6',
            name: 'record_fact',
            argumentsJson: JSON.stringify({
              kind: 'note',
              origin: ORIGIN,
              summary: 'State-machine creator/approver asymmetry on POST /api/v1/payouts/:id/approve permits self-approval.',
              data: { file: 'services/api/payouts.ts', line: 128, routeOrAction: 'POST /api/v1/payouts/:id/approve' },
            }),
          },
          {
            callId: 'f7_benign',
            name: 'record_fact',
            argumentsJson: JSON.stringify({
              kind: 'note',
              origin: ORIGIN,
              summary: 'Built authz matrix covering 45 handlers across 11 files and 5 services.',
              data: { handlerCount: 45 },
            }),
          },
          {
            callId: 'f8_benign',
            name: 'record_fact',
            argumentsJson: JSON.stringify({
              kind: 'tech_fingerprint',
              origin: ORIGIN,
              summary: 'Node.js Express microservice stack with Redis queue.',
              data: {},
            }),
          },
        ],
      }
    }
    return {
      toolCalls: [{
        callId: 'c_done',
        name: 'complete_intent',
        argumentsJson: JSON.stringify({ status: 'completed', summary: 'Recorded 6 cross-cutting defects.' }),
      }],
    }
  })

  const { storage } = makeStore(t)
  const { runId, run } = await setupApprovedRun(storage, { seeds: [ORIGIN], tier: 2 })
  await saveModelProfile({
    name: 'Audit-Mock',
    endpoint: llm.endpoint,
    model: 'mock-audit',
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

  const engine = new Execution(storage, { maxDurationMs: 900_000, backend: stubBackend() })
  t.after(() => engine.stop())
  internals(engine).projectReposMount = () => ({ reposDir, mountedRepos: ['acme'] })

  const prevStage1 = process.env.GUARDIAN_STAGE1_LLM
  process.env.GUARDIAN_STAGE1_LLM = '0'
  t.after(() => {
    if (prevStage1 === undefined) delete process.env.GUARDIAN_STAGE1_LLM
    else process.env.GUARDIAN_STAGE1_LLM = prevStage1
  })

  const res = await engine.runSourceFirstCodeAudit(run, [], profiles, new AbortController().signal)
  assert.equal(res.suspects.length, 6, 'all 6 cross-cutting security facts (1 suspect + 5 defect notes) must be collected, excluding 2 benign notes')
  assert.equal(res.stepsCreated.length, 6, 'all 6 cross-cutting defects must be promoted immediately into Wave-1 steps')
  assert.ok(res.stepsCreated.length <= CODE_AUDIT_WAVE1_MAX_STEPS)

  for (const step of res.stepsCreated) {
    assert.equal(step.status, 'ready')
    assert.ok(step.dependsOnFactIds.length >= 1, `step "${step.title}" must link its source-audit fact(s) via dependsOnFactIds`)
    assert.equal(isMultiHopChainStep(step), true, `promoted step "${step.title}" must be multi-hop eligible`)
    assert.equal(classifyDispatchLane(step), 'chain', `promoted step "${step.title}" must dispatch in the chain lane`)
    assert.equal(chainLaneDispatchRank(step), 0, `promoted step "${step.title}" must hold top Rank 0 priority`)
  }

  // Verify promoted code-audit steps strictly outrank generic Wave-1 boundary stubs in Wave 1!
  const wave1Stub: DispatchLaneStep = {
    id: 'wave1-generic-1',
    seq: 0,
    priority: 96,
    title: 'Wave-1 chain · Cross-service boundary chain (downstream_service/http)',
    category: 'broken-access-control',
    hypothesis: '[chain_hops=3] [lane=chain] [inv_hyp=inv-1] [cap=cap:hop_synth:edge] Multi-hop invariant chain.',
    skills: ['multihop-chains', 'chain-primitives'],
    dependsOnFactIds: [],
    dependsOnStepIds: [],
    sourceOrigins: [ORIGIN],
    trialIndex: 0,
  }
  const plan = planRoundRobinDispatch([wave1Stub, ...res.stepsCreated], 3)
  assert.ok(
    plan.ordered.every(s => s.id !== wave1Stub.id),
    'all 3 Wave-1 slots must go to source-derived cross-cutting chains ahead of generic Wave-1 boundary stub',
  )
})

test('settleCodeAuditSuspects + convertCodeAuditSuspectsToChainSteps deduplicates duplicates and caps promotion at 6 steps', async (t) => {
  const { storage } = makeStore(t)
  const { runId, run } = await setupApprovedRun(storage, { seeds: [ORIGIN], tier: 2 })
  const asset = run.candidates.find(c => run.approved.includes(c.id))!
  const auditAssignment = storage.makeWorker(run, 'threat_model', asset, 'Source-First Code Audit', 'Audit')
  const approvedOrigins = new Set([ORIGIN])
  const startedAt = Date.now() - 1_000

  // 2 explicit code_audit_suspects + 7 additional cross-cutting defect notes + 1 duplicate location
  storage.addFact(run, auditAssignment, {
    kind: 'code_audit_suspect',
    origin: ORIGIN,
    summary: 'Missing authz on /api/v1/secret-1',
    data: { file: 'services/api/f1.ts', line: 10, routeOrAction: 'GET /api/v1/secret-1', sinkKind: 'api_route' },
  })
  // Duplicate location recorded as a plain note — must be deduplicated against the explicit suspect!
  storage.addFact(run, auditAssignment, {
    kind: 'note',
    origin: ORIGIN,
    summary: 'Duplicate note: missing authz on /api/v1/secret-1',
    data: { file: 'services/api/f1.ts', line: 10, routeOrAction: 'GET /api/v1/secret-1', sinkKind: 'api_route' },
  })
  for (let i = 2; i <= 9; i += 1) {
    storage.addFact(run, auditAssignment, {
      kind: i === 2 ? 'code_audit_suspect' : 'note',
      origin: ORIGIN,
      summary: `Cross-tenant authz bypass on /api/v1/defect-${i}`,
      data: { file: `services/api/f${i}.ts`, line: i * 10, routeOrAction: `POST /api/v1/defect-${i}` },
    })
  }

  const settled = settleCodeAuditSuspects({
    storage,
    run,
    assignment: auditAssignment,
    approvedOrigins,
    semanticSuspects: [],
    preInteractiveFactIds: new Set(),
    auditStartedAtMs: startedAt,
  })
  assert.equal(settled.suspects.length, 9, 'duplicate location must be collapsed (10 facts -> 9 unique)')
  const isExplicitSuspect = (f: { kind: string; data?: Record<string, unknown> } | undefined) =>
    f?.kind === 'code_audit_suspect' || f?.data?.subkind === 'code_audit_suspect'
  assert.equal(isExplicitSuspect(settled.suspects[0]), true, 'explicit code_audit_suspect facts must rank first')
  assert.equal(isExplicitSuspect(settled.suspects[1]), true, 'explicit code_audit_suspect facts must rank first')

  const { convertCodeAuditSuspectsToChainSteps } = await import('../src/server/exec-dispatch.ts')
  const steps = convertCodeAuditSuspectsToChainSteps(storage, run, settled.suspects, undefined, {
    maxSteps: CODE_AUDIT_WAVE1_MAX_STEPS,
    promoteMultiHop: true,
  })
  assert.equal(steps.length, 6, 'promotion must be bounded to CODE_AUDIT_WAVE1_MAX_STEPS = 6')
  assert.ok(steps.some(s => s.title.includes('/api/v1/secret-1')))
  assert.ok(steps.some(s => s.title.includes('/api/v1/defect-2')))
})
