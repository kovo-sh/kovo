/**
 * Grey-Box Planner & Hop-Continuation Wiring Tests.
 *
 * Proves (Docker-free, real SQLite WAL `Store`, real `Execution`, real `ExecReconPlanner`,
 * real `ExecWorkerRunner`, real `VerifyRpcServer`, synthetic mock Responses LLM server):
 *  1. `enqueueHopContinuationOnRotation` lifts `MAX_GENERIC_WAVE1_CHAIN_CONTINUATIONS = 1`
 *     whenever `hasSealedLedgerCap` (`derivedLedgerHandles.length > 0`).
 *  2. `ExecWorkerRunner` triggers hop-continuation NOT ONLY on `wall_clock_rotated`, but also on
 *     non-confirmed `complete_intent` and `max_turns` (`turn_limit`) exits when
 *     `sessionSealedCapHandles.length > 0`, with dedup preventing infinite loops on identical sets.
 */
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { createServer, request as httpRequest, type Server } from 'node:http'
import type { AddressInfo } from 'node:net'
import { join } from 'node:path'
import { test } from 'node:test'

import {
  MAX_CHAIN_CONTINUATIONS,
  MAX_GENERIC_WAVE1_CHAIN_CONTINUATIONS,
  extractContinuationDepth,
  isGenericWave1BoundaryChainStep,
} from '../src/server/exec-dispatch.ts'
import { RequestBroker } from '../src/server/broker.ts'
import { Execution } from '../src/server/execution.ts'
import type { ExecReconPlanner } from '../src/server/exec-recon-planner.ts'
import { formatDerivedCapabilityHandle } from '../src/server/capability-ledger.ts'
import { saveModelProfile } from '../src/server/model-settings.ts'
import {
  VERIFY_NONCE_HEADER,
  VERIFY_RPC_HEADER,
  VERIFY_RPC_SOCKET_NAME,
  VERIFY_RPC_TOKEN_NAME,
} from '../src/server/verify-rpc.ts'
import {
  LinuxWorkerBackend,
  type VerifyScriptRequest,
  type VerifyScriptResult,
  type WorkerBackend,
  type WorkerSession,
  type WorkerSessionOptions,
} from '../src/server/worker-backend.ts'
import { makeStore, setupApprovedRun, stopExecution, withEnv } from './v4-tier-helpers.ts'

process.env.KOVO_ALLOW_LOCAL_LAB = '1'
process.env.KOVO_ALLOW_LOCAL_MODEL = '1'

const API_ORIGIN = 'https://api.example.invalid'

function internals(engine: Execution) {
  return engine as unknown as {
    reconPlanner: ExecReconPlanner
    driveInvestigation: (run: ReturnType<Execution['storage']['run']>, profiles: unknown[]) => void
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

type RpcCallFn = (op: string, args: Record<string, unknown>) => Promise<{ ok: boolean; result?: unknown; error?: string }>

function rpcOverSocket(
  socketPath: string,
  token: string,
  nonce: string,
  op: string,
  args: Record<string, unknown>,
): Promise<{ ok: boolean; result?: unknown; error?: string }> {
  const payload = JSON.stringify({ op, args })
  return new Promise((resolvePromise, rejectPromise) => {
    const req = httpRequest({
      socketPath,
      path: '/rpc',
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        'content-length': Buffer.byteLength(payload),
        [VERIFY_RPC_HEADER]: token,
        [VERIFY_NONCE_HEADER]: nonce,
      },
    }, res => {
      const chunks: Buffer[] = []
      res.on('data', (c: Buffer) => chunks.push(c))
      res.on('end', () => {
        try {
          resolvePromise(JSON.parse(Buffer.concat(chunks).toString('utf8')) as { ok: boolean; result?: unknown; error?: string })
        } catch (err) {
          rejectPromise(err)
        }
      })
    })
    req.on('error', rejectPromise)
    req.end(payload)
  })
}

class LocalRpcTestBackend extends LinuxWorkerBackend {
  private readonly verifyHandler: (req: VerifyScriptRequest, rpc: RpcCallFn) => Promise<VerifyScriptResult>

  constructor(verifyHandler: (req: VerifyScriptRequest, rpc: RpcCallFn) => Promise<VerifyScriptResult>) {
    super({})
    this.verifyHandler = verifyHandler
  }

  override async run() {
    return { exitCode: 0, stdout: '{}', stderr: '', outputs: {} }
  }

  override async verifyStaticAst(
    _aid: string,
    req: Parameters<LinuxWorkerBackend['verifyStaticAst']>[1],
  ) {
    return {
      verified: false,
      engine: req.engine,
      repo: req.repo,
      file: req.file,
      startLine: req.startLine,
      endLine: req.endLine,
      matchedLines: [],
      codeExcerpt: '',
      matchCount: 0,
      durationMs: 1,
    }
  }

  override async openSession(_assignmentId: string, _signal: AbortSignal, options?: WorkerSessionOptions): Promise<WorkerSession> {
    const mountDir = options?.rpcMountDir ?? ''
    const socketPath = mountDir ? join(mountDir, VERIFY_RPC_SOCKET_NAME) : ''
    const token = mountDir ? readFileSync(join(mountDir, VERIFY_RPC_TOKEN_NAME), 'utf8').trim() : ''
    const handler = this.verifyHandler
    return {
      stage: async name => `/evidence/${name}`,
      exec: async () => ({ exitCode: 0, stdout: '', stderr: '', outputs: {} }),
      analyze: async () => ({ ok: true }),
      sast: async req => ({ repo: req.repo, enginesRun: [], engineStatus: {}, findings: [], totalFindings: 0, truncated: false, durationMs: 1 }),
      runScript: async req => ({ runtime: req.runtime, exitCode: 0, stdout: '', stderr: '', durationMs: 1, timedOut: false }),
      verifyStaticAst: async req => ({ verified: false, engine: req.engine, repo: req.repo, file: req.file, startLine: req.startLine, endLine: req.endLine, matchedLines: [], codeExcerpt: '', matchCount: 0, durationMs: 1 }),
      verifyScript: async req => {
        const rpc: RpcCallFn = (op, args) => rpcOverSocket(socketPath, token, req.nonce, op, args)
        return await handler(req, rpc)
      },
      close: async () => undefined,
    }
  }
}

interface MockLlmReply {
  toolCall?: { callId: string; name: string; argumentsJson: string }
  text?: string
}

async function startMockLlmServer(
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
            usage: { input_tokens: 80, output_tokens: 30, total_tokens: 110 },
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
            usage: { input_tokens: 60, output_tokens: 20, total_tokens: 80 },
          },
        })
      }
      res.write('data: [DONE]\n\n')
      res.end()
    })
  })
  await new Promise<void>(resolveListen => server.listen(0, '127.0.0.1', () => resolveListen()))
  const { port } = server.address() as AddressInfo
  t.after(async () => {
    server.closeAllConnections?.()
    await new Promise<void>(resolveClose => server.close(() => resolveClose()))
  })
  return { endpoint: `http://127.0.0.1:${port}/v1`, calls }
}

// ============================================================================
// 1. Lifting MAX_GENERIC_WAVE1_CHAIN_CONTINUATIONS = 1 when hasSealedLedgerCap
// ============================================================================

test('enqueueHopContinuationOnRotation lifts MAX_GENERIC_WAVE1_CHAIN_CONTINUATIONS = 1 whenever derivedLedgerHandles.length > 0', async (t) => {
  assert.equal(MAX_GENERIC_WAVE1_CHAIN_CONTINUATIONS, 1)
  assert.equal(MAX_CHAIN_CONTINUATIONS, 2)

  const { storage } = makeStore(t)
  const { runId, run } = await setupApprovedRun(storage, { seeds: [API_ORIGIN], tier: 2 })
  const asset = run.candidates.find(c => run.approved.includes(c.id))!
  const engine = new Execution(storage, { backend: stubBackend(), maxDurationMs: 900_000 })
  t.after(() => engine.stop())
  const planner = internals(engine).reconPlanner

  const worker = storage.makeWorker(run, 'investigation', asset, 'Wave-1 worker', 'Hyp', { sourceOrigins: [API_ORIGIN] })
  const noteFact = storage.addFact(run, worker, {
    kind: 'note',
    origin: API_ORIGIN,
    summary: 'Observed multi-hop capability transition.',
    data: { subkind: 'chain_progress' },
    sourceOrigins: [API_ORIGIN],
  })

  // Generic Wave-1 boundary step (`isGenericWave1BoundaryChainStep === true`)
  const wave1Step = storage.addChainStep(run, {
    title: 'Wave-1 chain · Cross-service boundary chain (edge/http)',
    hypothesis: '[chain_hops=3] [lane=chain] [inv_hyp=inv-gb-1] [cap=cap:hop_synth:edge] Multi-hop invariant chain.',
    category: 'broken-access-control',
    priority: 96,
    targetAssetIds: [asset.id],
    sourceOrigins: [API_ORIGIN],
    skills: ['multihop-chains', 'chain-primitives'],
  })
  assert.equal(isGenericWave1BoundaryChainStep(wave1Step), true)
  storage.updateChainStep(wave1Step.id, { status: 'complete', assignedWorkerId: worker.id })

  // Seed a real runtime-derived capability handle in CapabilityLedger
  const derivedCap = formatDerivedCapabilityHandle('gb_w1', 'sealed_session')
  storage.capabilityLedger(runId).addCapability({
    capId: derivedCap,
    kind: 'identity_session',
    provenance: 'derived_hop',
    tenantScope: 'org_a',
    actorPersona: 'member_a',
    serviceOrigin: API_ORIGIN,
    surface: 'http',
    artifactDigest: 'd'.repeat(64),
    artifactSummary: 'Runtime-derived sealed session handle for Wave-1 chain',
    createdAtMs: 1000,
  })

  // Continuation #1
  const c1 = planner.enqueueHopContinuationOnRotation({
    run,
    step: wave1Step,
    assignment: worker,
    targetOrigins: [API_ORIGIN],
    confirmed: false,
    partialSummary: '[partial] Sealed derived session handle.',
    recordedFacts: [noteFact],
    recordedExchanges: [{ id: 'ex-1', origin: API_ORIGIN, method: 'POST', pathAndQuery: '/api/v1/tokens', status: 200 }],
    sealedCapHandles: [derivedCap],
  })
  assert.equal(c1.enqueued, true)
  assert.equal(c1.continuationDepth, 1)
  assert.equal(c1.checkpointCapId, derivedCap)

  // Continuation #2 MUST succeed (cap lifted from 1 -> 2 because hasSealedLedgerCap is true!)
  storage.updateChainStep(c1.continuationStep!.id, { status: 'complete', assignedWorkerId: worker.id })
  const c2 = planner.enqueueHopContinuationOnRotation({
    run,
    step: c1.continuationStep!,
    assignment: worker,
    targetOrigins: [API_ORIGIN],
    confirmed: false,
    partialSummary: '[partial] Pivoted to Hop 3 with sealed handle.',
    recordedFacts: [noteFact],
    recordedExchanges: [{ id: 'ex-2', origin: API_ORIGIN, method: 'POST', pathAndQuery: '/api/v1/webhooks', status: 202 }],
    sealedCapHandles: [derivedCap],
  })
  assert.equal(c2.enqueued, true, 'active Wave-1 chain with derivedLedgerHandles.length > 0 must allow depth-2 continuation')
  assert.equal(c2.continuationDepth, 2)
  assert.equal(extractContinuationDepth(c2.continuationStep!), 2)

  // Continuation #3 still respects MAX_CHAIN_CONTINUATIONS = 2
  storage.updateChainStep(c2.continuationStep!.id, { status: 'complete', assignedWorkerId: worker.id })
  const c3 = planner.enqueueHopContinuationOnRotation({
    run,
    step: c2.continuationStep!,
    assignment: worker,
    targetOrigins: [API_ORIGIN],
    confirmed: false,
    partialSummary: '[partial] Depth 3 attempt.',
    recordedFacts: [noteFact],
    recordedExchanges: [],
    sealedCapHandles: [derivedCap],
  })
  assert.equal(c3.enqueued, false)
  assert.equal(c3.reason, 'max_continuations_reached')
})

// ============================================================================
// 2. ExecWorkerRunner triggers hop-continuation on non-confirmed complete_intent
//    and max_turns exits with sessionSealedCapHandles, deduped against loops
// ============================================================================

async function startLoopbackSealTarget(t: { after: (fn: () => void | Promise<void>) => void }): Promise<string> {
  const server: Server = createServer((_req, res) => {
    res.statusCode = 200
    res.setHeader('Content-Type', 'application/json')
    res.end(JSON.stringify({
      exportToken: 'tok_derived_generic_99441122',
      sessionToken: 'sess_derived_generic_88332211',
    }))
  })
  await new Promise<void>(resolveListen => server.listen(0, '127.0.0.1', () => resolveListen()))
  const { port } = server.address() as AddressInfo
  t.after(async () => {
    server.closeAllConnections?.()
    await new Promise<void>(resolveClose => server.close(() => resolveClose()))
  })
  return `http://127.0.0.1:${port}`
}

test('ExecWorkerRunner triggers hop-continuation on non-confirmed complete_intent and max_turns exits with sealed handles, and dedup blocks identical handle-set loops', async (t) => {
  // Part A: Non-confirmed `complete_intent` exit after sealing a capability handle + dedup loop guard
  {
    const targetOrigin = await startLoopbackSealTarget(t)
    let sealedHandle = ''
    const backend = new LocalRpcTestBackend(async (req, rpc) => {
      const httpRes = await rpc('http.send', {
        origin: targetOrigin,
        method: 'GET',
        path: '/api/v1/tokens/issue',
        sessionGroupRole: 'probe',
      })
      assert.equal(httpRes.ok, true, `http.send must succeed: ${httpRes.error ?? ''}`)
      const ex = httpRes.result as { exchangeId: string; status: number }
      const sealRes = await rpc('capability.seal', {
        exchangeId: ex.exchangeId,
        hopReceiptId: 'ci1',
        slot: 'tok',
        jsonPath: '$.exportToken',
        kind: 'bearer_token',
        allowedOrigins: [targetOrigin],
      })
      assert.equal(sealRes.ok, true, `capability.seal must succeed: ${sealRes.error ?? ''}`)
      sealedHandle = (sealRes.result as { handle: string }).handle
      return {
        runtime: req.runtime,
        result: { sdk: 'kovo_verify.ts', nonce: req.nonce, claims: [], sealedCapabilities: [sealedHandle] },
        stdout: `Sealed ${sealedHandle}\n`,
        stderr: '',
        exitCode: 0,
        durationMs: 5,
        timedOut: false,
      }
    })

    const llm = await startMockLlmServer(t, (body, reqIndex) => {
      const isWorkerCall = Array.isArray(body.tools) && body.tools.some(
        tool => tool && typeof tool === 'object' && (tool as { name?: string }).name === 'complete_intent',
      )
      if (!isWorkerCall) return { text: 'planner no-op' }
      const inputItems = Array.isArray(body.input) ? body.input : [body.input]
      const firstUserMsg = inputItems.find(item => item && typeof item === 'object' && (item as { role?: string }).role === 'user')
      const ownTaskText = JSON.stringify(firstUserMsg ?? '')
      const fullText = JSON.stringify(body.input ?? '')

      if (ownTaskText.includes('continuation #1')) {
        // Continuation #1 logs the existing handle and exits with complete_intent(partial) without sealing a new one -> must NOT spawn depth 2.
        return {
          toolCall: {
            callId: `c_done_cont1_${reqIndex}`,
            name: 'complete_intent',
            argumentsJson: JSON.stringify({ status: 'partial', summary: 'Same handle only, no new hop handle.' }),
          },
        }
      }

      // Parent step seals handle on Turn 1, then exits with non-confirmed complete_intent(partial)
      if (!fullText.includes('c_verify_p1_')) {
        return {
          toolCall: {
            callId: `c_verify_p1_${reqIndex}`,
            name: 'kovo_verify',
            argumentsJson: JSON.stringify({ runtime: 'ts', script: '// seal hop 1' }),
          },
        }
      }
      return {
        toolCall: {
          callId: `c_done_p1_${reqIndex}`,
          name: 'complete_intent',
          argumentsJson: JSON.stringify({ status: 'partial', summary: 'Sealed Hop-1 handle, exiting via complete_intent.' }),
        },
      }
    })

    const { storage } = makeStore(t)
    await saveModelProfile({
      name: 'CI-Sealed-Mock',
      endpoint: llm.endpoint,
      model: 'mock-ci-sealed',
      protocol: 'responses',
      key: 'sk-mock-ci-1234',
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

    const { runId, run } = await setupApprovedRun(storage, { seeds: [targetOrigin], tier: 2, budgetUsd: 2, budgetRequests: 500 })
    const parentStep = storage.addChainStep(run, {
      title: 'GB sealed complete_intent exit step',
      hypothesis: '[chain_hops=3] [lane=chain] Verify multi-hop token -> mutation chain.',
      category: 'broken-access-control',
      priority: 95,
      targetAssetIds: run.approved,
      sourceOrigins: [targetOrigin],
      skills: ['multihop-chains', 'chain-primitives'],
    })
    storage.updateRun(runId, { phase: 'investigation', status: 'running', workerConcurrency: 2, multiTrialEnabled: false })

    const engine = new Execution(storage, {
      broker: new RequestBroker({ rejectUnauthorized: false }),
      backend,
      deterministicSweep: false,
    })
    await withEnv({ KOVO_ALLOW_LOCAL_LAB: '1', KOVO_ALLOW_LOCAL_MODEL: '1' }, async () => {
      engine.start()
      engine.wake()
      const deadline = Date.now() + 15_000
      while (Date.now() < deadline) {
        const steps = storage.listChainSteps(runId, run.goalRevision)
        const cont1 = steps.find(s => s.dependsOnStepIds.includes(parentStep.id) && extractContinuationDepth(s) === 1)
        if (cont1?.status === 'complete') {
          // Give runner a moment to confirm no depth-2 loop step is spawned
          await new Promise(r => setTimeout(r, 120))
          break
        }
        await new Promise(r => setTimeout(r, 25))
      }
      await stopExecution(engine as never)
    })

    const allSteps = storage.listChainSteps(runId, run.goalRevision)
    const cont1 = allSteps.find(s => s.dependsOnStepIds.includes(parentStep.id) && extractContinuationDepth(s) === 1)
    assert.ok(cont1, 'non-confirmed complete_intent exit with sessionSealedCapHandles.length > 0 must enqueue continuation #1')
    assert.equal(cont1.status, 'complete')
    assert.ok(
      cont1.skills.includes(`checkpoint_cap:${sealedHandle}`),
      `expected checkpoint_cap:${sealedHandle} in cont1.skills=${JSON.stringify(cont1.skills)} caps=${JSON.stringify(storage.capabilityLedger(runId).listCapabilities().map(c => c.capId))} events=${JSON.stringify(storage.eventsAfter(runId, 0, 50).map(e => [e.kind, e.message]))}`,
    )

    const cont2 = allSteps.filter(s => extractContinuationDepth(s) >= 2)
    assert.equal(cont2.length, 0, 'dedup must block continuation #2 when continuation #1 exits with the exact same sealed handle set')
  }

  // Part B: `max_turns` (`turn_limit`) exit with sessionSealedCapHandles.length > 0 + distinct-handle vs duplicate-handle dedup
  {
    const targetOrigin = await startLoopbackSealTarget(t)
    let sealedHandleMt = ''
    const backend = new LocalRpcTestBackend(async (req, rpc) => {
      const httpRes = await rpc('http.send', {
        origin: targetOrigin,
        method: 'GET',
        path: '/api/v1/sessions/issue',
        sessionGroupRole: 'probe',
      })
      assert.equal(httpRes.ok, true, `http.send must succeed: ${httpRes.error ?? ''}`)
      const ex = httpRes.result as { exchangeId: string; status: number }
      const sealRes = await rpc('capability.seal', {
        exchangeId: ex.exchangeId,
        hopReceiptId: 'mt1',
        slot: 'sess',
        jsonPath: '$.sessionToken',
        kind: 'bearer_token',
        allowedOrigins: [targetOrigin],
      })
      assert.equal(sealRes.ok, true, `capability.seal must succeed: ${sealRes.error ?? ''}`)
      const currentHandle = (sealRes.result as { handle: string }).handle
      if (!sealedHandleMt) sealedHandleMt = currentHandle
      return {
        runtime: req.runtime,
        result: { sdk: 'kovo_verify.ts', nonce: req.nonce, claims: [], sealedCapabilities: [currentHandle] },
        stdout: `Sealed ${currentHandle}\n`,
        stderr: '',
        exitCode: 0,
        durationMs: 5,
        timedOut: false,
      }
    })

    let cont1PromptText = ''
    const llm = await startMockLlmServer(t, (body, reqIndex) => {
      const isWorkerCall = Array.isArray(body.tools) && body.tools.some(
        tool => tool && typeof tool === 'object' && (tool as { name?: string }).name === 'complete_intent',
      )
      if (!isWorkerCall) return { text: 'planner no-op' }
      const inputItems = Array.isArray(body.input) ? body.input : [body.input]
      const firstUserMsg = inputItems.find(item => item && typeof item === 'object' && (item as { role?: string }).role === 'user')
      const ownTaskText = JSON.stringify(firstUserMsg ?? '')
      const fullText = JSON.stringify(body.input ?? '')
      if (ownTaskText.includes('continuation #1')) {
        if (!cont1PromptText) cont1PromptText = ownTaskText
        return {
          toolCall: {
            callId: `c_done_mt_cont1_${reqIndex}`,
            name: 'complete_intent',
            argumentsJson: JSON.stringify({ status: 'ruled_out', summary: 'Completed continuation after turn_limit.' }),
          },
        }
      }
      if (!fullText.includes('c_verify_mt1_')) {
        return {
          toolCall: {
            callId: `c_verify_mt1_${reqIndex}`,
            name: 'kovo_verify',
            argumentsJson: JSON.stringify({ runtime: 'ts', script: '// seal before turn limit' }),
          },
        }
      }
      // Subsequent turns: call record_fact instead of complete_intent until maxTurns (`turn_limit`)!
      return {
        toolCall: {
          callId: `c_fact_mt_${reqIndex}`,
          name: 'record_fact',
          argumentsJson: JSON.stringify({
            kind: 'note',
            origin: targetOrigin,
            summary: `Sealed session handle before hitting turn_limit (step ${reqIndex}).`,
          }),
        },
      }
    })

    const { storage } = makeStore(t)
    await saveModelProfile({
      name: 'MT-Sealed-Mock',
      endpoint: llm.endpoint,
      model: 'mock-mt-sealed',
      protocol: 'responses',
      key: 'sk-mock-mt-1234',
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

    const { runId, run } = await setupApprovedRun(storage, { seeds: [targetOrigin], tier: 2, budgetUsd: 2, budgetRequests: 500 })
    const parentStep = storage.addChainStep(run, {
      title: 'GB sealed max_turns exit step',
      hypothesis: '[chain_hops=3] [lane=chain] Verify session handle before max_turns.',
      category: 'broken-access-control',
      priority: 95,
      targetAssetIds: run.approved,
      sourceOrigins: [targetOrigin],
      skills: ['multihop-chains', 'chain-primitives'],
    })
    // Pin workerMaxTurns=25 (specialist minimum) so Part B exercises a full turn_limit exit cleanly within CI CPU budgets.
    storage.updateRun(runId, { phase: 'investigation', status: 'running', workerConcurrency: 2, workerMaxTurns: 25, multiTrialEnabled: false })

    const engine = new Execution(storage, {
      broker: new RequestBroker({ rejectUnauthorized: false }),
      backend,
      deterministicSweep: false,
    })
    const planner = internals(engine).reconPlanner

    await withEnv({ KOVO_ALLOW_LOCAL_LAB: '1', KOVO_ALLOW_LOCAL_MODEL: '1' }, async () => {
      engine.start()
      engine.wake()
      const deadline = Date.now() + 18_000
      while (Date.now() < deadline) {
        const steps = storage.listChainSteps(runId, run.goalRevision)
        const cont1 = steps.find(s => s.dependsOnStepIds.includes(parentStep.id) && extractContinuationDepth(s) === 1)
        if (cont1?.status === 'complete') break
        await new Promise(r => setTimeout(r, 25))
      }
      await stopExecution(engine as never)
    })

    const allSteps = storage.listChainSteps(runId, run.goalRevision)
    const cont1 = allSteps.find(s => s.dependsOnStepIds.includes(parentStep.id) && extractContinuationDepth(s) === 1)
    assert.ok(cont1, 'turn_limit (max_turns) exit with sessionSealedCapHandles.length > 0 must enqueue continuation #1')
    assert.equal(cont1.status, 'complete', `continuation #1 must finish executing after turn_limit exit (llmCalls=${llm.calls.length})`)
    assert.ok(cont1PromptText.includes(sealedHandleMt), 'continuation #1 prompt must hydrate the sealed handle from turn_limit exit')

    // Direct dedup verification on `sealed_handle_exit`: identical handle set rejected, new handle accepted
    const worker = storage.makeWorker(run, 'investigation', run.candidates[0]!, cont1.title, cont1.hypothesis, {
      stepId: cont1.id,
      sourceOrigins: [targetOrigin],
    })
    const dupExit = planner.enqueueHopContinuationOnRotation({
      run: storage.run(runId),
      step: cont1,
      assignment: worker,
      targetOrigins: [targetOrigin],
      confirmed: false,
      partialSummary: '[partial] Repeated same handle.',
      recordedFacts: [],
      recordedExchanges: [],
      sealedCapHandles: [sealedHandleMt],
      trigger: 'sealed_handle_exit',
    })
    assert.equal(dupExit.enqueued, false)
    assert.equal(dupExit.reason, 'duplicate_sealed_handles')

    const freshHandle = 'cap:hop_mt2:derived_admin'
    storage.capabilityLedger(runId).addCapability({
      capId: freshHandle,
      kind: 'signing_material',
      provenance: 'derived_hop',
      tenantScope: 'org_b',
      actorPersona: 'member_b',
      serviceOrigin: targetOrigin,
      surface: 'http',
      artifactDigest: 'e'.repeat(64),
      artifactSummary: 'New Hop-2 signing handle',
      createdAtMs: 2000,
    })
    const newHandleExit = planner.enqueueHopContinuationOnRotation({
      run: storage.run(runId),
      step: cont1,
      assignment: worker,
      targetOrigins: [targetOrigin],
      confirmed: false,
      partialSummary: '[partial] Derived new Hop-2 handle.',
      recordedFacts: [],
      recordedExchanges: [],
      sealedCapHandles: [freshHandle],
      trigger: 'sealed_handle_exit',
    })
    assert.equal(newHandleExit.enqueued, true, 'sealing a genuinely new derived handle must allow continuation #2')
    assert.equal(newHandleExit.continuationDepth, 2)
  }
})
