/**
 * Move O4 Regression & Unit Tests:
 *  1. Pause-Aware `ActiveClock` (`activeElapsedMs`, nested/re-entrant `pause`/`resume`,
 *     `createDeadlineTimer` deferral, parent->child propagation, `RunActor` pause wiring,
 *     and `waitForHumanTier3Card` + `runAgentSession` deadline deferral during approval wait).
 *  2. True Pass-Through SSE Streaming (`makeFetch` returns a real `TransformStream` piped through
 *     `sanitizeProviderStream`, delivering SSE chunks before stream close, enforcing per-chunk
 *     `idleTimeoutMs`, and flushing `onUsage` + `record` idempotently on consumer abort/cancel).
 *  3. Incremental Transcript Token Estimation (no synchronous `JSON.stringify(transcript)` per
 *     turn) & Removal of Redundant `LiveDoc` / `conversation.watch` in `agent-session.ts`.
 *  4. Separation of Transient `429`/`5xx` Transport Retries from Logical Turn Budget (`maxCalls`)
 *     with a bounded `maxTransportRetries` cap in both `provider()` and `providerPool()`.
 */
import assert from 'node:assert/strict'
import { randomUUID } from 'node:crypto'
import { once } from 'node:events'
import { mkdtempSync, readFileSync, rmSync } from 'node:fs'
import { createServer } from 'node:http'
import type { AddressInfo } from 'node:net'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import { describe, test } from 'node:test'
import { eq } from 'drizzle-orm'
import { runCommand } from '../src/domain.ts'
import {
  ActiveClock,
  getAssignmentClock,
  getRunClock,
  registerAssignmentClock,
} from '../src/server/active-clock.ts'
import { runAgentSession } from '../src/server/agent-session.ts'
import { createAppRuntime } from '../src/server/app-runtime.ts'
import { RequestBroker } from '../src/server/broker.ts'
import { Execution } from '../src/server/execution.ts'
import type { ResolvedModelProfile } from '../src/server/model-settings.ts'
import {
  BudgetExceededError,
  createTranscriptTokenEstimator,
  provider,
  providerPool,
  type ProviderCall,
  type UsageEvent,
} from '../src/server/provider.ts'
import { RunActor, type RunTier3ApprovalCoordinator } from '../src/server/run-actor.ts'
import { approvalRequests } from '../src/server/schema.ts'
import { Store } from '../src/server/store.ts'
import type { WorkerBackend } from '../src/server/worker-backend.ts'

const REPO_ROOT = resolve(import.meta.dirname, '..')
const ORIGIN_A = 'https://o4-clock.example.test'

function makeProfile(overrides: Partial<ResolvedModelProfile> & {
  id: string
  endpoint: string
  key: string
}): ResolvedModelProfile {
  return {
    name: overrides.id,
    model: 'o4-test-model',
    protocol: 'responses',
    enabled: true,
    priority: 100,
    contextWindow: 128_000,
    maxTokens: 4096,
    inputCostPerMtok: 0.5,
    cachedInputCostPerMtok: 0.1,
    outputCostPerMtok: 1.5,
    thinkingLevel: 'off',
    roleAffinity: 'any',
    healthState: 'closed',
    cooldownUntil: null,
    lastError: null,
    ...overrides,
  }
}

function responsesSse(events: Array<{ type: string } & Record<string, unknown>>, done = true): string {
  return events.map(ev => `data: ${JSON.stringify(ev)}\n\n`).join('') + (done ? 'data: [DONE]\n\n' : '')
}

function responsesTextTurn(text: string, usage = { input_tokens: 100, output_tokens: 25 }, done = true): string {
  const item = {
    type: 'message',
    id: 'msg_o4',
    role: 'assistant',
    status: 'completed',
    content: [{ type: 'output_text', text, annotations: [] }],
  }
  return responsesSse([
    { type: 'response.created', response: { id: 'resp_o4', status: 'in_progress' } },
    { type: 'response.output_item.added', output_index: 0, item: { ...item, content: [], status: 'in_progress' } },
    { type: 'response.output_text.delta', output_index: 0, content_index: 0, delta: text },
    { type: 'response.output_item.done', output_index: 0, item },
    {
      type: 'response.completed',
      response: {
        id: 'resp_o4',
        status: 'completed',
        output: [item],
        usage,
      },
    },
  ], done)
}

function responsesToolCallTurn(callId: string, name: string, args: Record<string, unknown>): string {
  const argsJson = JSON.stringify(args)
  const item = {
    type: 'function_call',
    id: `fc_${callId}`,
    call_id: callId,
    name,
    arguments: argsJson,
    status: 'completed',
  }
  return responsesSse([
    { type: 'response.created', response: { id: `resp_${callId}`, status: 'in_progress' } },
    { type: 'response.output_item.added', output_index: 0, item: { ...item, arguments: '', status: 'in_progress' } },
    { type: 'response.function_call_arguments.delta', output_index: 0, delta: argsJson },
    { type: 'response.function_call_arguments.done', output_index: 0, arguments: argsJson },
    { type: 'response.output_item.done', output_index: 0, item },
    {
      type: 'response.completed',
      response: {
        id: `resp_${callId}`,
        status: 'completed',
        output: [item],
        usage: { input_tokens: 60, output_tokens: 20 },
      },
    },
  ])
}

function makeTempDir(t: { after(fn: () => void | Promise<void>): void }, prefix = 'kovo-o4-'): string {
  const dir = mkdtempSync(join(tmpdir(), prefix))
  t.after(() => rmSync(dir, { recursive: true, force: true }))
  return dir
}

function stubBackend(): WorkerBackend {
  return {
    openSession: async () => ({
      stage: async (name: string) => `/work/${name}`,
      exec: async () => ({ exitCode: 0, stdout: '', stderr: '', outputs: {} }),
      analyze: async () => ({ ok: true }),
      sast: async () => ({ repo: 'app', enginesRun: [], engineStatus: {}, findings: [], durationMs: 1 }),
      runScript: async () => ({ runtime: 'python', exitCode: 0, stdout: '', stderr: '', timedOut: false, durationMs: 1 }),
      close: async () => undefined,
    }),
  } as unknown as WorkerBackend
}

function makeBroker(): RequestBroker {
  return new RequestBroker({
    resolve: async () => [{ address: '93.184.216.34', family: 4 }],
    transport: async () => ({ status: 200, headers: { 'content-type': 'application/json' }, body: '{"ok":true}' }),
  })
}

async function waitFor(predicate: () => boolean, timeoutMs = 4_000, label = 'condition'): Promise<void> {
  const deadline = Date.now() + timeoutMs
  while (Date.now() < deadline) {
    if (predicate()) return
    await new Promise(resolve => setTimeout(resolve, 10))
  }
  assert.ok(predicate(), `Timed out waiting for ${label} after ${timeoutMs}ms`)
}

// ============================================================================
// 1. Pause-Aware ActiveClock Primitive & Approval-Wait Deadline Deferral
// ============================================================================

describe('Move O4.1: Pause-Aware ActiveClock & Approval-Wait Deadline Deferral', () => {
  test('ActiveClock tracks active vs paused elapsed time across nested & re-entrant pause reasons', () => {
    let nowMs = 1_000
    const clock = new ActiveClock({ now: () => nowMs })

    nowMs += 400
    assert.equal(clock.activeElapsedMs(), 400)
    assert.equal(clock.pausedElapsedMs(), 0)
    assert.equal(clock.isPaused, false)

    // Enter first pause reason ('approval_wait')
    clock.pause('approval_wait')
    assert.equal(clock.isPaused, true)
    assert.deepEqual(clock.activePauseReasons, ['approval_wait'])

    nowMs += 5_000
    assert.equal(clock.activeElapsedMs(), 400, 'active time must stay frozen while paused')
    assert.equal(clock.pausedElapsedMs(), 5_000)

    // Nest second distinct reason ('run_paused') AND re-entrant 'approval_wait'
    clock.pause('run_paused')
    clock.pause('approval_wait')
    assert.deepEqual([...clock.activePauseReasons].sort(), ['approval_wait', 'run_paused'])

    nowMs += 3_000
    // Resuming one 'approval_wait' leaves nested 'approval_wait' + 'run_paused' active
    clock.resume('approval_wait')
    assert.equal(clock.isPaused, true)
    // Resuming second 'approval_wait' leaves 'run_paused' active
    clock.resume('approval_wait')
    assert.equal(clock.isPaused, true)
    assert.deepEqual(clock.activePauseReasons, ['run_paused'])

    nowMs += 2_000
    assert.equal(clock.activeElapsedMs(), 400, 'active time must remain frozen until ALL pause reasons clear')
    assert.equal(clock.pausedElapsedMs(), 10_000)

    // Resume final reason -> clock resumes cleanly
    clock.resume('run_paused')
    assert.equal(clock.isPaused, false)
    assert.deepEqual(clock.activePauseReasons, [])

    // Extra idempotent resume is a safe no-op
    clock.resume('run_paused')
    clock.resume('nonexistent')

    nowMs += 250
    assert.equal(clock.activeElapsedMs(), 650)
    assert.equal(clock.pausedElapsedMs(), 10_000)
    clock.dispose()
  })

  test('createDeadlineTimer suspends while paused (including parent clock pause) and fires after remaining active budget', async () => {
    const parent = new ActiveClock()
    const child = new ActiveClock({ parent })

    let expiredAt: number | undefined
    const handle = child.createDeadlineTimer(120, () => {
      expiredAt = Date.now()
    })

    // Consume ~45ms active time
    await new Promise(r => setTimeout(r, 45))
    assert.equal(handle.expired, false)

    // Pause child for approval_wait AND parent for run_paused for 200ms (> total 120ms budget!)
    child.pause('approval_wait')
    parent.pause('run_paused')
    await new Promise(r => setTimeout(r, 120))
    assert.equal(expiredAt, undefined, 'deadline timer must NEVER expire while paused')
    assert.equal(handle.active, true)

    // Resuming child alone must keep timer suspended because parent is still paused
    child.resume('approval_wait')
    await new Promise(r => setTimeout(r, 100))
    assert.equal(expiredAt, undefined, 'child timer must stay paused while parent run clock is paused')

    // Now resume parent -> remaining ~75ms should expire cleanly
    const resumedAt = Date.now()
    parent.resume('run_paused')
    await waitFor(() => expiredAt !== undefined, 500, 'deadline timer expiration after resume')
    const afterResumeMs = expiredAt! - resumedAt
    assert.ok(afterResumeMs >= 30 && afterResumeMs < 350, `expected expiry near remaining ~75ms, got ${afterResumeMs}ms`)
    assert.equal(handle.expired, true)
    assert.equal(handle.active, false)
    assert.equal(handle.remainingMs(), 0)

    child.dispose()
    parent.dispose()
  })

  test('RunActor automatically pauses/resumes its ActiveClock on paused transitions and cleans up registry on dispose', async t => {
    const dir = makeTempDir(t, 'kovo-o4-actor-')
    const runtime = createAppRuntime({ dataDir: dir })
    t.after(() => runtime.dispose())

    const runId = `run-o4-clock-${randomUUID().slice(0, 8)}`
    const ctx = runtime.createRunContext(runId)
    const actor = new RunActor({ context: ctx, initialState: 'investigating' })
    assert.equal(getRunClock(runId), actor.clock)
    assert.equal(actor.clock.isPaused, false)

    await new Promise(r => setTimeout(r, 30))
    actor.transition('paused', 'operator pause')
    assert.equal(actor.clock.isPaused, true)
    assert.deepEqual(actor.clock.activePauseReasons, ['run_paused'])
    const frozenMs = actor.activeElapsedMs()

    await new Promise(r => setTimeout(r, 50))
    assert.equal(actor.activeElapsedMs(), frozenMs, 'RunActor active clock must stay frozen while paused')

    actor.transition('investigating', 'operator resume')
    assert.equal(actor.clock.isPaused, false)
    await new Promise(r => setTimeout(r, 30))
    assert.ok(actor.activeElapsedMs() > frozenMs, 'RunActor active clock must advance after resume')

    await actor.drainAndDispose({ terminalState: 'canceled', reason: 'done' })
    assert.equal(getRunClock(runId), undefined, 'RunActor disposal must unregister run clock')
    assert.equal(actor.clock.isDisposed, true)
  })

  test('runAgentSession + waitForHumanTier3Card pauses wall-clock timer during approval wait and completes without timing out', async t => {
    const prevLocal = process.env.KOVO_ALLOW_LOCAL_MODEL
    process.env.KOVO_ALLOW_LOCAL_MODEL = '1'
    t.after(() => {
      if (prevLocal === undefined) delete process.env.KOVO_ALLOW_LOCAL_MODEL
      else process.env.KOVO_ALLOW_LOCAL_MODEL = prevLocal
    })

    const dir = makeTempDir(t, 'kovo-o4-approval-clock-')
    const store = new Store(dir)
    t.after(() => { try { store.close() } catch { /* ignore */ } })

    const runtime = createAppRuntime({ dataDir: dir, store })
    const exec = new Execution(store, {
      runtime,
      broker: makeBroker(),
      backend: stubBackend(),
      deterministicSweep: false,
    })
    t.after(async () => {
      await exec.stop()
      await runtime.dispose()
    })

    // Seed an approved Tier-3 strict run + running worker assignment
    const project = store.createProject({
      requestId: randomUUID(),
      name: 'O4 Approval Deferral',
      seeds: [ORIGIN_A],
      environment: 'public',
    })
    const { id: runId } = store.createRun({
      requestId: randomUUID(),
      projectId: project.id,
      goal: 'Verify approval wait pauses wallClockMs',
      sourceMode: 'public',
      capabilityTier: 3,
      approvalPolicy: 'strict',
    } as Parameters<Store['createRun']>[0])
    store.command(runCommand.parse({ requestId: randomUUID(), runId, action: 'discover', consent: true }))
    const discovered = store.run(runId)
    store.command(runCommand.parse({
      requestId: randomUUID(),
      runId,
      action: 'scope',
      assetIds: discovered.candidates.map(c => c.id),
      expectedScopeRevision: discovered.scopeRevision,
      consent: true,
    }))
    store.updateRun(runId, { phase: 'investigation', status: 'running' })
    const run = store.run(runId)
    const asset = run.candidates[0]!
    const worker = store.updateWorker(
      store.makeWorker(run, 'investigation', asset, 'o4-worker', 'tier3 approval deferral', {
        sourceOrigins: [ORIGIN_A],
      }).id,
      { status: 'running', lease: randomUUID(), leaseExpiresAt: Date.now() + 60_000 },
    )!

    const priv = exec as unknown as {
      tier3Approvals: RunTier3ApprovalCoordinator
      active: Map<string, { assignment: typeof worker; origins: Set<string>; controller: AbortController }>
    }
    const jobController = new AbortController()
    const job = { assignment: worker, origins: new Set([ORIGIN_A]), controller: jobController }
    priv.active.set(worker.id, job)

    // Mock LLM: turn 1 calls derive_evidence (which parks on Tier-3 approval), turn 2 calls complete_intent
    let turn = 0
    const server = createServer((req, res) => {
      req.resume()
      turn += 1
      res.writeHead(200, { 'content-type': 'text/event-stream' })
      if (turn === 1) {
        res.end(responsesToolCallTurn('call_t3', 'derive_evidence', { command: 'echo tier3-probe' }))
        return
      }
      if (turn === 2) {
        res.end(responsesToolCallTurn('call_done', 'complete_intent', {
          status: 'ruled_out',
          summary: 'Completed cleanly after operator Tier-3 approval pause.',
        }))
        return
      }
      res.end(responsesTextTurn('Completed cleanly after operator Tier-3 approval pause.'))
    }).listen(0, '127.0.0.1')
    await once(server, 'listening')
    t.after(async () => {
      server.closeAllConnections()
      await new Promise<void>(resolve => server.close(() => resolve()))
    })
    const port = (server.address() as AddressInfo).port

    // Register assignment ActiveClock with 450ms wallClockMs budget while approval wait takes 700ms (> 450ms!)
    const assignmentClock = new ActiveClock()
    const unregisterClock = registerAssignmentClock(worker.id, assignmentClock)
    t.after(() => {
      unregisterClock()
      assignmentClock.dispose()
    })
    assert.equal(getAssignmentClock(worker.id), assignmentClock)

    let rotatedCount = 0
    let pausedDuringApproval = false
    const sessionPromise = runAgentSession({
      directory: dir,
      sessionId: 'o4-approval-defer-session',
      requestId: 'o4-approval-defer-req',
      settings: {
        endpoint: `http://127.0.0.1:${port}/v1`,
        model: 'mock-o4-approval',
        protocol: 'responses',
        key: 'sk-o4-approval-key-1234',
      },
      scenario: 'worker-investigation',
      prompt: 'Run Tier-3 probe and finish.',
      signal: jobController.signal,
      maxTurns: 4,
      wallClockMs: 450,
      activeClock: assignmentClock,
      compaction: false,
      enableSettlement: false,
      requireCompleteIntent: true,
      onWallClockRotate: () => { rotatedCount += 1 },
      handlers: {
        derive_evidence: async (_args, sig) => {
          const waitPromise = priv.tier3Approvals.waitForTier3Approval(job, {
            origin: ORIGIN_A,
            method: 'POST',
            pathAndQuery: '/api/state-change',
            rationale: 'Verify state mutation control',
            requestPreview: 'POST /api/state-change',
            secrets: [],
          }, sig)
          await waitFor(() => store.listApprovalRequests(runId).some(r => r.status === 'pending'), 2_000, 'pending card')
          pausedDuringApproval = assignmentClock.isPaused && assignmentClock.activePauseReasons.includes('approval_wait')
          // Hold on human approval LONGER than the 450ms wallClockMs budget (700ms)
          await new Promise(r => setTimeout(r, 700))
          const pending = store.listApprovalRequests(runId).find(r => r.status === 'pending')!
          store.db.update(approvalRequests)
            .set({ status: 'approved', decidedAt: Date.now(), decidedBy: 'operator' })
            .where(eq(approvalRequests.id, pending.id))
            .run()
          store.event(runId, 'approval.approved', 'Approved in O4 test', { approvalId: pending.id })
          const decision = await waitPromise
          assert.equal(decision.approved, true)
          return { exitCode: 0, stdout: 'approved-ok', stderr: '', outputs: {} }
        },
        complete_intent: async c => ({ recorded: true, status: c.status }),
      },
    })

    const result = await sessionPromise
    assert.equal(pausedDuringApproval, true, 'assignment ActiveClock must auto-pause with approval_wait during waitForHumanTier3Card')
    assert.equal(assignmentClock.isPaused, false, 'assignment ActiveClock must auto-resume after approval resolves')
    assert.equal(rotatedCount, 0, 'worker must NOT wall-clock rotate while parked on human Tier-3 approval')
    assert.equal(result.status, 'completed')
    assert.equal(result.wallClockRotated, undefined)
  })
})

// ============================================================================
// 2. True Pass-Through SSE Streaming & Abort Usage Flush
// ============================================================================

describe('Move O4.2: True Pass-Through SSE Streaming, Abort Usage Flush & Incremental Token Estimation', () => {
  test('provider() delivers sanitized SSE chunks to consumer BEFORE upstream HTTP stream closes', async t => {
    const prevLocal = process.env.KOVO_ALLOW_LOCAL_MODEL
    process.env.KOVO_ALLOW_LOCAL_MODEL = '1'
    t.after(() => {
      if (prevLocal === undefined) delete process.env.KOVO_ALLOW_LOCAL_MODEL
      else process.env.KOVO_ALLOW_LOCAL_MODEL = prevLocal
    })

    let closeUpstream!: () => void
    const upstreamCanClose = new Promise<void>(resolve => { closeUpstream = resolve })
    let upstreamClosed = false

    const server = createServer((req, res) => {
      req.resume()
      res.writeHead(200, { 'content-type': 'text/event-stream' })
      // Send a complete Responses turn WITHOUT ending the HTTP connection yet
      res.write(responsesTextTurn('live-chunk-before-close', { input_tokens: 180, output_tokens: 42 }, false))
      void upstreamCanClose.then(() => {
        if (!res.writableEnded) {
          res.write('data: [DONE]\n\n')
          res.end()
        }
        upstreamClosed = true
      })
    }).listen(0, '127.0.0.1')
    await once(server, 'listening')
    t.after(async () => {
      closeUpstream()
      server.closeAllConnections()
      await new Promise<void>(resolve => server.close(() => resolve()))
    })
    const port = (server.address() as AddressInfo).port

    const usages: UsageEvent[] = []
    const recorded: ProviderCall[] = []
    let activities = 0

    const { models, model } = provider(
      {
        endpoint: `http://127.0.0.1:${port}/v1`,
        model: 'mock-passthrough',
        protocol: 'responses',
        key: 'sk-passthrough-key-1234',
      },
      'worker-investigation',
      {
        idleTimeoutMs: 5_000,
        onStreamActivity: () => { activities += 1 },
        onUsage: u => usages.push(u),
        record: c => recorded.push(c),
      },
    )

    const stream = models.stream(model, {
      systemPrompt: 'Stream incrementally.',
      messages: [{ role: 'user', content: 'go', timestamp: Date.now() }],
      tools: [],
    })

    let receivedText = ''
    let sawEventBeforeClose = false
    for await (const ev of stream) {
      if (ev.type === 'text_delta') {
        receivedText += ev.delta
        if (!upstreamClosed) {
          sawEventBeforeClose = true
          // Release upstream HTTP stream ONLY after consumer already received incremental SSE delta
          closeUpstream()
        }
      }
    }
    const finalRes = await stream.result()
    assert.equal(sawEventBeforeClose, true, 'text_delta must be delivered before upstream stream closes')
    assert.equal(receivedText, 'live-chunk-before-close')
    assert.notEqual(finalRes.stopReason, 'error', finalRes.errorMessage ?? 'unexpected error')

    await waitFor(() => usages.length === 1 && recorded.length === 1, 1_000, 'usage and record flush')
    assert.equal(usages.length, 1)
    assert.equal(usages[0]!.inputTokens, 180)
    assert.equal(usages[0]!.outputTokens, 42)
    assert.equal(recorded.length, 1)
    assert.ok(activities >= 4, `expected >= 4 real-time SSE activity callbacks, got ${activities}`)
  })

  test('mid-stream consumer abort/cancel flushes observed Anthropic message_start usage exactly once', async t => {
    const prevLocal = process.env.KOVO_ALLOW_LOCAL_MODEL
    process.env.KOVO_ALLOW_LOCAL_MODEL = '1'
    t.after(() => {
      if (prevLocal === undefined) delete process.env.KOVO_ALLOW_LOCAL_MODEL
      else process.env.KOVO_ALLOW_LOCAL_MODEL = prevLocal
    })

    const server = createServer((req, res) => {
      req.resume()
      res.writeHead(200, { 'content-type': 'text/event-stream' })
      // Emit message_start (with input_tokens + cache_read_input_tokens) and partial delta, then hold open
      res.write(
        `event: message_start\ndata: ${JSON.stringify({
          type: 'message_start',
          message: {
            id: 'msg_abort_1',
            type: 'message',
            role: 'assistant',
            model: 'claude-o4',
            content: [],
            usage: { input_tokens: 300, cache_read_input_tokens: 200, output_tokens: 5 },
          },
        })}\n\n` +
        `event: content_block_start\ndata: ${JSON.stringify({ type: 'content_block_start', index: 0, content_block: { type: 'text', text: '' } })}\n\n` +
        `event: content_block_delta\ndata: ${JSON.stringify({ type: 'content_block_delta', index: 0, delta: { type: 'text_delta', text: 'partial...' } })}\n\n`,
      )
      // Intentionally never end stream; consumer will abort mid-stream
    }).listen(0, '127.0.0.1')
    await once(server, 'listening')
    t.after(async () => {
      server.closeAllConnections()
      await new Promise<void>(resolve => server.close(() => resolve()))
    })
    const port = (server.address() as AddressInfo).port

    const abortController = new AbortController()
    const usages: UsageEvent[] = []
    let frameCount = 0

    const { models, model } = provider(
      {
        endpoint: `http://127.0.0.1:${port}/v1`,
        model: 'claude-o4',
        protocol: 'messages',
        key: 'sk-ant-abort-key-1234',
      },
      'worker-investigation',
      {
        signal: abortController.signal,
        idleTimeoutMs: 5_000,
        onStreamActivity: () => {
          frameCount += 1
          if (frameCount === 3) {
            abortController.abort(new Error('consumer aborted mid-stream'))
          }
        },
        onUsage: u => usages.push(u),
      },
    )

    const stream = models.stream(model, {
      systemPrompt: 'Abort mid-stream.',
      messages: [{ role: 'user', content: 'start', timestamp: Date.now() }],
      tools: [],
    })
    for await (const _ev of stream) { /* consume until abort */ }
    await stream.result().catch(() => undefined)

    await waitFor(() => usages.length >= 1, 1_000, 'abort usage flush')
    assert.equal(usages.length, 1, 'onUsage must be flushed exactly once on mid-stream abort')
    assert.equal(usages[0]!.inputTokens, 500, 'Anthropic input_tokens (300) + cache_read_input_tokens (200) must be flushed on abort')
    assert.equal(usages[0]!.cachedInputTokens, 200)
    assert.equal(usages[0]!.outputTokens, 5)
  })

  test('createTranscriptTokenEstimator uses incremental WeakMap cache and agent-session removes LiveDoc watch', () => {
    const estimator = createTranscriptTokenEstimator()
    const toolDef = { name: 'http_send', description: 'Send HTTP request', parameters: { type: 'object' } }
    const msg1 = { role: 'user', content: 'A'.repeat(350) }
    const msg2 = { role: 'assistant', content: 'B'.repeat(700) }
    const msg3 = { role: 'user', content: 'C'.repeat(350) }

    const est1 = estimator.estimate({ systemPrompt: 'sys', tools: [toolDef], messages: [msg1, msg2] })
    assert.ok(est1 > 300, `expected > 300 estimated tokens, got ${est1}`)
    assert.equal(estimator.cacheHits, 0)
    assert.equal(estimator.cacheMisses, 3) // toolDef, msg1, msg2

    // Turn 2: append msg3 while keeping toolDef, msg1, msg2 identical -> 3 WeakMap hits, 1 miss!
    const est2 = estimator.estimate({ systemPrompt: 'sys', tools: [toolDef], messages: [msg1, msg2, msg3] })
    assert.ok(est2 > est1)
    assert.equal(estimator.cacheHits, 3, 'unchanged tools and prior messages must hit WeakMap cache')
    assert.equal(estimator.cacheMisses, 4, 'only the newly appended message should be measured')

    // Structural cleanliness checks
    const providerSrc = readFileSync(join(REPO_ROOT, 'src', 'server', 'provider.ts'), 'utf8')
    assert.doesNotMatch(providerSrc, /JSON\.stringify\(transcript\)/, 'provider.ts must not synchronously JSON.stringify(transcript) per turn')
    assert.doesNotMatch(providerSrc, /readStreamWithIdleTimeout/, 'provider.ts must not buffer SSE streams via readStreamWithIdleTimeout')

    const sessionSrc = readFileSync(join(REPO_ROOT, 'src', 'server', 'agent-session.ts'), 'utf8')
    assert.doesNotMatch(sessionSrc, /\bLiveDoc\b/, 'agent-session.ts must remove redundant LiveDoc watcher')
    assert.doesNotMatch(sessionSrc, /conversation\.watch\(/, 'agent-session.ts must remove redundant conversation.watch workaround')
  })
})

// ============================================================================
// 3. Separate Transport Retries from Logical Turn Budget (`callCounter`)
// ============================================================================

describe('Move O4.3: Separate Transient 429/5xx Transport Retries from Logical Turn Budget', () => {
  test('providerPool charges callCounter once per logical turn across 429/5xx retries and failovers, with bounded maxTransportRetries', async () => {
    const p1 = makeProfile({ id: 'p-1', endpoint: 'https://pool-1.o4.test/v1', key: 'sk-o4-p1-111111', priority: 200 })
    const p2 = makeProfile({ id: 'p-2', endpoint: 'https://pool-2.o4.test/v1', key: 'sk-o4-p2-222222', priority: 100 })

    // Turn 1: p1 returns 429 (rate limit), fails over to p2 which returns 503, retries p2 -> 200 OK (3 transport calls, 1 logical turn!)
    // Turn 2: p1 returns 502, fails over to p2 -> 200 OK (2 transport calls, 2nd logical turn!)
    // Turn 3: exceeds maxCalls=2 -> throws BudgetExceededError BEFORE hitting fetch!
    const responsesQueue: Array<() => Response> = [
      () => new Response(JSON.stringify({ error: { message: 'Requests per minute rate limit exceeded, retry after 1s' } }), {
        status: 429, headers: { 'content-type': 'application/json' },
      }),
      () => new Response(JSON.stringify({ error: { message: 'Service unavailable' } }), {
        status: 503, headers: { 'content-type': 'application/json' },
      }),
      () => new Response(responsesTextTurn('turn-1-ok'), { status: 200, headers: { 'content-type': 'text/event-stream' } }),
      () => new Response(JSON.stringify({ error: { message: 'Bad gateway' } }), {
        status: 502, headers: { 'content-type': 'application/json' },
      }),
      () => new Response(responsesTextTurn('turn-2-ok'), { status: 200, headers: { 'content-type': 'text/event-stream' } }),
    ]
    let transportCalls = 0
    const stubFetch: typeof fetch = async () => {
      transportCalls += 1
      const next = responsesQueue.shift()
      assert.ok(next, `unexpected extra transport call #${transportCalls}`)
      return next()
    }

    const { models, model } = providerPool([p1, p2], 'worker-investigation', {
      maxCalls: 2,
      maxTransportRetries: 2,
      transportRetryBaseMs: 5,
      fetch: stubFetch,
    })
    const transcript = {
      systemPrompt: 'Test logical vs transport budget.',
      messages: [{ role: 'user' as const, content: 'go', timestamp: Date.now() }],
      tools: [],
    }

    // Logical Turn 1 (3 transport attempts -> still 1 logical turn)
    const s1 = models.stream(model, transcript)
    for await (const _ev of s1) { /* drain */ }
    const r1 = await s1.result()
    assert.notEqual(r1.stopReason, 'error', r1.errorMessage ?? 'turn 1 failed')
    assert.equal(transportCalls, 3)

    // Logical Turn 2 (2 transport attempts -> 2nd logical turn succeeds!)
    const s2 = models.stream(model, transcript)
    for await (const _ev of s2) { /* drain */ }
    const r2 = await s2.result()
    assert.notEqual(r2.stopReason, 'error', r2.errorMessage ?? 'turn 2 failed')
    assert.equal(transportCalls, 5)

    // Logical Turn 3 -> rejected immediately with BudgetExceededError without issuing a 6th fetch
    const s3 = models.stream(model, transcript)
    let turn3ThrewBudget = false
    let r3StopReason: string | undefined
    let r3ErrorMsg = ''
    try {
      for await (const _ev of s3) { /* drain */ }
      const r3 = await s3.result()
      r3StopReason = r3.stopReason
      r3ErrorMsg = r3.errorMessage ?? ''
    } catch (err) {
      assert.ok(err instanceof BudgetExceededError, `expected BudgetExceededError, got ${String(err)}`)
      turn3ThrewBudget = true
    }
    if (!turn3ThrewBudget) {
      assert.equal(r3StopReason, 'error')
      assert.match(r3ErrorMsg, /budget/i)
    }
    assert.equal(transportCalls, 5, 'BudgetExceededError must stop Turn 3 before making any transport request')
  })

  test('single provider() retries transient 429/5xx up to maxTransportRetries without consuming logical callCounter, and never retries 402 quota', async () => {
    let transportCalls = 0
    const queue: Array<() => Response> = [
      // Turn 1: 429 rate limit -> 503 -> 200 OK
      () => new Response(JSON.stringify({ error: { message: 'Rate limit exceeded, retry after 1s' } }), {
        status: 429, headers: { 'content-type': 'application/json' },
      }),
      () => new Response(JSON.stringify({ error: { message: 'Temporary 503' } }), {
        status: 503, headers: { 'content-type': 'application/json' },
      }),
      () => new Response(responsesTextTurn('single-turn-1'), { status: 200, headers: { 'content-type': 'text/event-stream' } }),
      // Turn 2: succeeds immediately
      () => new Response(responsesTextTurn('single-turn-2'), { status: 200, headers: { 'content-type': 'text/event-stream' } }),
    ]

    const { models, model } = provider(
      {
        endpoint: 'https://single.o4.test/v1',
        model: 'o4-single',
        protocol: 'responses',
        key: 'sk-single-o4-key-1234',
      },
      'worker-investigation',
      {
        maxCalls: 2,
        maxTransportRetries: 2,
        transportRetryBaseMs: 5,
        fetch: async () => {
          transportCalls += 1
          return queue.shift()!()
        },
      },
    )
    const transcript = {
      systemPrompt: 'Single provider retry test.',
      messages: [{ role: 'user' as const, content: 'hi', timestamp: Date.now() }],
      tools: [],
    }

    const s1 = models.stream(model, transcript)
    for await (const _ev of s1) { /* drain */ }
    const r1 = await s1.result()
    assert.notEqual(r1.stopReason, 'error', r1.errorMessage ?? 'single turn 1 failed')
    assert.equal(transportCalls, 3)

    const s2 = models.stream(model, transcript)
    for await (const _ev of s2) { /* drain */ }
    const r2 = await s2.result()
    assert.notEqual(r2.stopReason, 'error', r2.errorMessage ?? 'single turn 2 failed')
    assert.equal(transportCalls, 4)

    // Turn 3 exceeds logical maxCalls=2
    const s3 = models.stream(model, transcript)
    for await (const _ev of s3) { /* drain */ }
    const r3 = await s3.result()
    assert.equal(r3.stopReason, 'error')
    assert.match(r3.errorMessage ?? '', /budget/i)
    assert.equal(transportCalls, 4)

    // Bounded maxTransportRetries cap (maxTransportRetries=1 -> 1 initial + 1 retry = 2 total fetches on persistent 503)
    let persistentCalls = 0
    const bounded = provider(
      {
        endpoint: 'https://bounded.o4.test/v1',
        model: 'o4-bounded',
        protocol: 'responses',
        key: 'sk-bounded-o4-key-1234',
      },
      'worker-investigation',
      {
        maxCalls: 5,
        maxTransportRetries: 1,
        transportRetryBaseMs: 5,
        fetch: async () => {
          persistentCalls += 1
          return new Response(JSON.stringify({ error: { message: 'Persistent 503' } }), {
            status: 503, headers: { 'content-type': 'application/json' },
          })
        },
      },
    )
    const sb = bounded.models.stream(bounded.model, transcript)
    for await (const _ev of sb) { /* drain */ }
    const rb = await sb.result()
    assert.equal(rb.stopReason, 'error')
    assert.equal(persistentCalls, 2, 'must stop after 1 initial attempt + maxTransportRetries=1')

    // Quota 429 -> mapped to 402 hard error and NEVER retried
    let quotaCalls = 0
    const quota = provider(
      {
        endpoint: 'https://quota.o4.test/v1',
        model: 'o4-quota',
        protocol: 'responses',
        key: 'sk-quota-o4-key-1234',
      },
      'worker-investigation',
      {
        maxCalls: 5,
        maxTransportRetries: 3,
        transportRetryBaseMs: 5,
        fetch: async () => {
          quotaCalls += 1
          return new Response(JSON.stringify({ error: { message: 'Insufficient credits on balance' } }), {
            status: 429, headers: { 'content-type': 'application/json' },
          })
        },
      },
    )
    const sq = quota.models.stream(quota.model, transcript)
    for await (const _ev of sq) { /* drain */ }
    const rq = await sq.result()
    assert.equal(rq.stopReason, 'error')
    assert.equal(quotaCalls, 1, '429 quota exhaustion (402) must never be retried as transient')
  })
})
