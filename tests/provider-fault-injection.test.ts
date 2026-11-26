/**
 * R2-13: Provider fault-injection contract test suite.
 *
 * Covers the full fault matrix against a deterministic stub transport (`options.fetch`) plus
 * live `ExecWorkerRunner` / `Execution` and `evaluateTier3Approval` integration:
 *   1. HTTP 429 with `Retry-After` (seconds & HTTP-date) -> typed `ProviderFailureError`
 *      (`kind: 'rate_limited'`, `retryAfterMs`, `emitted: false`, `retryable: true`).
 *   2. HTTP 402 & HTTP 429 quota-body -> throws typed `QuotaExhaustedError`
 *      (`instanceof ProviderFailureError`, `kind: 'quota'`, `status: 402`, `hard: true`).
 *   3. HTTP 401 / 403 -> throws typed `ProviderFailureError` (`kind: 'auth'`, `hard: true`).
 *   4. HTTP 5xx (500/502/503/504) -> typed `ProviderFailureError` (`kind: 'server'`, `retryable: true`).
 *   5. HTTP 400 context overflow -> typed `ProviderFailureError` (`kind: 'context_overflow'`).
 *   6. Mid-stream drop (before any tool call AND after a tool call executes) -> typed
 *      `ProviderFailureError` (`kind: 'stream_drop'`, `emitted: true`), enforcing the
 *      `noToolCallExecuted` target-safety idempotency guard on worker retries.
 *   7. Stream silence / stall (first-event & mid-stream idle) -> typed `ProviderFailureError`
 *      (`kind: 'stall'`, `retryable: true`).
 *   8. Run-level `provider_paused` circuit on hard quota/auth exhaustion: pauses the run
 *      within one dispatch tick with ZERO cascading `model_failure` steps.
 *   9. Bounded 1-retry-per-key transient retry charged to `RunSafetyBudgets` (re-entering
 *      the same scope/tier/approval gates, never infinite churn).
 *  10. Safety Judge transient 1-retry + structured `failSafe: true` / `failSafeReason`
 *      surfacing to distinguish Judge outage from normal human escalation.
 */
import assert from 'node:assert/strict'
import { eq } from 'drizzle-orm'
import { test } from 'node:test'

import { evaluateTier3Approval, createSafetyJudgeLlmCall } from '../src/server/approval-judge.ts'
import {
  classifyWorkerErrorToStepStatus,
  evaluateTransientProviderRetry,
  normalizeDispatchStopReason,
  resolveAssignmentBudget,
} from '../src/server/exec-dispatch.ts'
import { Execution } from '../src/server/execution.ts'
import {
  privateModelProfiles,
  recordProfileFailure,
  saveModelProfile,
  type ResolvedModelProfile,
} from '../src/server/model-settings.ts'
import {
  ProviderFailureError,
  QuotaExhaustedError,
  classifyFailoverError,
  classifyProviderFailure,
  evaluateRoleProviderCircuit,
  providerPool,
} from '../src/server/provider.ts'
import { events } from '../src/server/schema.ts'
import type { WorkerBackend, WorkerSession } from '../src/server/worker-backend.ts'
import { makeStore, setupApprovedRun } from './v4-tier-helpers.ts'

process.env.KOVO_ALLOW_LOCAL_LAB = '1'
process.env.KOVO_ALLOW_LOCAL_MODEL = '1'

const ORIGIN = 'https://r2-13-fault-injection.example.invalid'

function makeProfile(overrides: Partial<ResolvedModelProfile> = {}): ResolvedModelProfile {
  return {
    id: overrides.id ?? 'prof-primary',
    name: overrides.name ?? 'Primary Fixture',
    endpoint: overrides.endpoint ?? 'http://127.0.0.1:18080/v1',
    model: overrides.model ?? 'fixture-model',
    protocol: overrides.protocol ?? 'responses',
    key: overrides.key ?? 'fixture-key-12345',
    enabled: overrides.enabled ?? true,
    priority: overrides.priority ?? 100,
    contextWindow: overrides.contextWindow ?? 128_000,
    maxTokens: overrides.maxTokens ?? 4096,
    thinkingLevel: overrides.thinkingLevel ?? 'off',
    roleAffinity: overrides.roleAffinity ?? 'any',
    inputCostPerMtok: overrides.inputCostPerMtok ?? 0.1,
    cachedInputCostPerMtok: overrides.cachedInputCostPerMtok ?? 0.01,
    outputCostPerMtok: overrides.outputCostPerMtok ?? 0.2,
    healthState: overrides.healthState ?? 'closed',
    cooldownUntil: overrides.cooldownUntil ?? null,
    lastError: overrides.lastError ?? null,
  }
}

function responsesSse(eventsList: Record<string, unknown>[]): string {
  return eventsList.map(ev => `data: ${JSON.stringify(ev)}\n\n`).join('')
}

function responsesTextStreamBody(text: string): string {
  return responsesSse([
    { type: 'response.created', response: { id: 'resp_1', status: 'in_progress' } },
    { type: 'response.output_item.added', output_index: 0, item: { type: 'message', id: 'msg_1', role: 'assistant', content: [], status: 'in_progress' } },
    { type: 'response.output_text.delta', output_index: 0, delta: text },
    {
      type: 'response.completed',
      response: {
        id: 'resp_1',
        status: 'completed',
        output: [{ type: 'message', id: 'msg_1', role: 'assistant', status: 'completed', content: [{ type: 'output_text', text }] }],
        usage: { input_tokens: 100, output_tokens: 20 },
      },
    },
  ])
}

async function drainPoolStream(
  profiles: readonly ResolvedModelProfile[],
  fetchImpl: typeof fetch,
  extraOptions: Partial<Parameters<typeof providerPool>[2]> = {},
) {
  const { models, model } = providerPool(profiles, 'worker-investigation', {
    fetch: fetchImpl,
    maxTransportRetries: 0,
    transportRetryBaseMs: 0,
    firstEventTimeoutMs: 2_000,
    idleTimeoutMs: 2_000,
    totalTimeoutMs: 5_000,
    ...extraOptions,
  })
  const stream = models.stream(model, {
    systemPrompt: 'Fault injection probe.',
    messages: [{ role: 'user', content: 'Run check.', timestamp: Date.now() }],
    tools: [],
  })
  const collected: unknown[] = []
  for await (const ev of stream) {
    collected.push(ev)
  }
  const result = await stream.result()
  return { collected, result }
}

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

function internals(engine: Execution): Record<string, any> {
  return engine as unknown as Record<string, any>
}

// ============================================================================
// 1. Stub-transport fault matrix: 429+Retry-After, 402, 401/403, 5xx, 400 overflow
// ============================================================================

test('R2-13.1: 429 with Retry-After throws typed ProviderFailureError and respects Retry-After on bounded retry', async () => {
  const profile = makeProfile()

  // (a) Exhausted 429 preserves kind, status, retryAfterMs, emitted=false, retryable=true
  let caught: unknown
  try {
    await drainPoolStream([profile], async () => new Response(
      JSON.stringify({ error: { message: 'Requests per minute rate limit exceeded.' } }),
      { status: 429, headers: { 'content-type': 'application/json', 'retry-after': '3' } },
    ))
  } catch (err) {
    caught = err
  }
  assert.ok(caught instanceof ProviderFailureError, `expected ProviderFailureError, got ${String(caught)}`)
  assert.equal(caught.kind, 'rate_limited')
  assert.equal(caught.status, 429)
  assert.equal(caught.retryAfterMs, 3_000)
  assert.equal(caught.emitted, false)
  assert.equal(caught.retryable, true)
  assert.equal(caught.hard, false)

  // (b) 429 with HTTP-date Retry-After parses positive ms
  const futureDate = new Date(Date.now() + 2_000).toUTCString()
  let caughtDate: unknown
  try {
    await drainPoolStream([profile], async () => new Response(
      JSON.stringify({ error: { message: 'Rate limited' } }),
      { status: 429, headers: { 'content-type': 'application/json', 'retry-after': futureDate } },
    ))
  } catch (err) {
    caughtDate = err
  }
  assert.ok(caughtDate instanceof ProviderFailureError)
  assert.equal(caughtDate.kind, 'rate_limited')
  assert.ok(
    typeof caughtDate.retryAfterMs === 'number' && caughtDate.retryAfterMs >= 500 && caughtDate.retryAfterMs <= 4_000,
    `expected HTTP-date retryAfterMs in [500, 4000], got ${caughtDate.retryAfterMs}`,
  )

  // (c) Transient 429 with Retry-After=0.05 retries and succeeds on 2nd attempt
  let calls = 0
  const startedAt = Date.now()
  const { result } = await drainPoolStream(
    [profile],
    async () => {
      calls += 1
      if (calls === 1) {
        return new Response(
          JSON.stringify({ error: { message: 'RPM limit hit' } }),
          { status: 429, headers: { 'content-type': 'application/json', 'retry-after': '0.06' } },
        )
      }
      return new Response(responsesTextStreamBody('recovered-after-429'), {
        status: 200,
        headers: { 'content-type': 'text/event-stream' },
      })
    },
    { maxTransportRetries: 1, transportRetryBaseMs: 0 },
  )
  assert.equal(calls, 2)
  assert.ok(Date.now() - startedAt >= 40, 'should wait for Retry-After header before retrying')
  assert.equal(result.stopReason, 'stop')
})

test('R2-13.2: 402 and 429-quota-body actually throw QuotaExhaustedError; 401/403 throw hard auth error; 5xx & overflow typed', async () => {
  const profile = makeProfile()

  // (a) HTTP 402 -> QuotaExhaustedError (extends ProviderFailureError)
  let err402: unknown
  let calls402 = 0
  try {
    await drainPoolStream(
      [profile],
      async () => {
        calls402 += 1
        return new Response(
          JSON.stringify({ error: { message: 'Insufficient credits' } }),
          { status: 402, headers: { 'content-type': 'application/json' } },
        )
      },
      { maxTransportRetries: 2 },
    )
  } catch (err) {
    err402 = err
  }
  assert.equal(calls402, 1, '402 quota exhaustion must never be retried')
  assert.ok(err402 instanceof QuotaExhaustedError, '402 must throw QuotaExhaustedError')
  assert.ok(err402 instanceof ProviderFailureError)
  assert.equal(err402.kind, 'quota')
  assert.equal(err402.status, 402)
  assert.equal(err402.emitted, false)
  assert.equal(err402.retryable, false)
  assert.equal(err402.hard, true)

  // (b) HTTP 429 with quota body -> reclassified as 402 QuotaExhaustedError
  let err429Quota: unknown
  try {
    await drainPoolStream([profile], async () => new Response(
      JSON.stringify({ error: { message: 'You exceeded your current quota, please check billing.' } }),
      { status: 429, headers: { 'content-type': 'application/json' } },
    ))
  } catch (err) {
    err429Quota = err
  }
  assert.ok(err429Quota instanceof QuotaExhaustedError)
  assert.equal(err429Quota.kind, 'quota')
  assert.equal(err429Quota.hard, true)

  // (c) HTTP 401 & 403 -> hard auth ProviderFailureError (zero retries)
  for (const status of [401, 403] as const) {
    let errAuth: unknown
    let authCalls = 0
    try {
      await drainPoolStream(
        [profile],
        async () => {
          authCalls += 1
          return new Response(
            JSON.stringify({ error: { message: 'Invalid API key' } }),
            { status, headers: { 'content-type': 'application/json' } },
          )
        },
        { maxTransportRetries: 2 },
      )
    } catch (err) {
      errAuth = err
    }
    assert.equal(authCalls, 1, `HTTP ${status} must not be retried`)
    assert.ok(errAuth instanceof ProviderFailureError)
    assert.equal(errAuth.kind, 'auth')
    assert.equal(errAuth.status, status)
    assert.equal(errAuth.emitted, false)
    assert.equal(errAuth.retryable, false)
    assert.equal(errAuth.hard, true)
  }

  // (d) HTTP 503 -> transient server ProviderFailureError
  let err503: unknown
  try {
    await drainPoolStream([profile], async () => new Response(
      JSON.stringify({ error: { message: 'Upstream gateway overloaded' } }),
      { status: 503, headers: { 'content-type': 'application/json' } },
    ))
  } catch (err) {
    err503 = err
  }
  assert.ok(err503 instanceof ProviderFailureError)
  assert.equal(err503.kind, 'server')
  assert.equal(err503.status, 503)
  assert.equal(err503.emitted, false)
  assert.equal(err503.retryable, true)
  assert.equal(err503.hard, false)

  // (e) HTTP 400 context overflow -> typed context_overflow (non-retryable)
  const overflowClassified = classifyProviderFailure(
    new Error('maximum context length exceeded (prompt is too long)'),
    { status: 400 },
  )
  assert.ok(overflowClassified instanceof ProviderFailureError)
  assert.equal(overflowClassified.kind, 'context_overflow')
  assert.equal(overflowClassified.retryable, false)
  assert.equal(overflowClassified.hard, false)
})

// ============================================================================
// 2. Mid-stream drop & stream silence / stall fault injection
// ============================================================================

test('R2-13.3: mid-stream drop and stream silence/stall produce typed ProviderFailureError with accurate emitted flag', async () => {
  const profile = makeProfile()

  // (a) First-event silence (stall before any emitted chunk)
  let stallFirstErr: unknown
  try {
    await drainPoolStream(
      [profile],
      async (_input, init) => new Promise<Response>((_resolve, reject) => {
        init?.signal?.addEventListener('abort', () => reject(init.signal?.reason ?? new Error('aborted')), { once: true })
      }),
      { firstEventTimeoutMs: 60, idleTimeoutMs: 200, totalTimeoutMs: 2_000, maxTransportRetries: 0 },
    )
  } catch (err) {
    stallFirstErr = err
  }
  assert.ok(stallFirstErr instanceof ProviderFailureError, `expected ProviderFailureError on first-event stall, got ${String(stallFirstErr)}`)
  assert.equal(stallFirstErr.kind, 'stall')
  assert.equal(stallFirstErr.emitted, false)
  assert.equal(stallFirstErr.retryable, true)

  // (b) Mid-stream silence (emits one delta, then hangs past idleTimeoutMs)
  const encoder = new TextEncoder()
  const { result: idleRes } = await drainPoolStream(
    [profile],
    async () => {
      const body = new ReadableStream<Uint8Array>({
        start(controller) {
          controller.enqueue(encoder.encode(responsesSse([
            { type: 'response.created', response: { id: 'resp_idle', status: 'in_progress' } },
            { type: 'response.output_item.added', output_index: 0, item: { type: 'message', id: 'msg_idle', role: 'assistant', content: [], status: 'in_progress' } },
            { type: 'response.output_text.delta', output_index: 0, delta: 'half-way ' },
          ])))
          // Never close -> triggers idleTimeoutMs
        },
      })
      return new Response(body, { status: 200, headers: { 'content-type': 'text/event-stream' } })
    },
    { firstEventTimeoutMs: 500, idleTimeoutMs: 70, totalTimeoutMs: 2_000, maxTransportRetries: 0 },
  )
  assert.equal(idleRes.stopReason, 'error')
  const classifiedIdle = classifyProviderFailure(idleRes.errorMessage, { emitted: true })
  assert.ok(classifiedIdle instanceof ProviderFailureError)
  assert.equal(classifiedIdle.kind, 'stall')
  assert.equal(classifiedIdle.emitted, true)
  assert.equal(classifiedIdle.retryable, true)

  // (c) Mid-stream drop (stream aborts/errors after emitting text delta)
  const { result: dropRes } = await drainPoolStream(
    [profile],
    async () => {
      const body = new ReadableStream<Uint8Array>({
        start(controller) {
          controller.enqueue(encoder.encode(responsesSse([
            { type: 'response.created', response: { id: 'resp_drop', status: 'in_progress' } },
            { type: 'response.output_item.added', output_index: 0, item: { type: 'message', id: 'msg_drop', role: 'assistant', content: [], status: 'in_progress' } },
            { type: 'response.output_text.delta', output_index: 0, delta: 'partial ' },
          ])))
          setTimeout(() => controller.error(new Error('socket hang up ECONNRESET')), 15)
        },
      })
      return new Response(body, { status: 200, headers: { 'content-type': 'text/event-stream' } })
    },
    { firstEventTimeoutMs: 500, idleTimeoutMs: 500, totalTimeoutMs: 2_000, maxTransportRetries: 0 },
  )
  assert.equal(dropRes.stopReason, 'error')
  const classifiedDrop = classifyProviderFailure(dropRes.errorMessage, { emitted: true })
  assert.ok(classifiedDrop instanceof ProviderFailureError)
  assert.equal(classifiedDrop.kind, 'stream_drop')
  assert.equal(classifiedDrop.emitted, true)
  assert.equal(classifiedDrop.retryable, true)
})

// ============================================================================
// 3. Single classifier parity across provider.ts and exec-dispatch.ts
// ============================================================================

test('R2-13.4: single typed classifier drives classifyWorkerErrorToStepStatus and classifyFailoverError', () => {
  assert.equal(classifyWorkerErrorToStepStatus(new QuotaExhaustedError('quota gone')), 'model_failure')
  assert.equal(classifyWorkerErrorToStepStatus(new ProviderFailureError('429', { kind: 'rate_limited', status: 429 })), 'model_failure')
  assert.equal(classifyWorkerErrorToStepStatus(new ProviderFailureError('drop', { kind: 'stream_drop', emitted: true })), 'model_failure')
  assert.equal(classifyWorkerErrorToStepStatus(new Error('OpenRouter 429 rate limit exceeded')), 'model_failure')
  assert.equal(classifyWorkerErrorToStepStatus(new Error('Provider stream stalled (no token)')), 'model_failure')
  assert.equal(classifyWorkerErrorToStepStatus(new Error('Docker daemon container start ECONNREFUSED')), 'infra_failed')
  assert.equal(classifyWorkerErrorToStepStatus(new Error('Container sandbox exec EPIPE')), 'infra_failed')

  assert.deepEqual(classifyFailoverError('The provider quota or credit balance was exhausted.'), { failover: true, hard: true })
  assert.deepEqual(classifyFailoverError('The provider rejected the API key.'), { failover: true, hard: true })
  assert.deepEqual(classifyFailoverError('The provider rate limit was reached.'), { failover: true, hard: false })
  assert.deepEqual(classifyFailoverError('The model provider returned HTTP 503.'), { failover: true, hard: false })
  assert.deepEqual(classifyFailoverError('The operation was aborted by user'), { failover: false, hard: false })
  assert.equal(normalizeDispatchStopReason('provider_paused'), 'provider_paused')
})

// ============================================================================
// 4. Run-level provider_paused circuit on hard quota / auth exhaustion
// ============================================================================

test('R2-13.5: hard 402/401 exhaustion trips run-level provider_paused within one tick with ZERO model_failure steps', async t => {
  const { storage } = makeStore(t, 'kovo-r213-circuit-')
  const { runId, run } = await setupApprovedRun(storage, { seeds: [ORIGIN], tier: 2 })
  const asset = run.candidates.find(c => run.approved.includes(c.id))!

  const saved = await saveModelProfile({
    name: 'Only Profile',
    endpoint: 'http://127.0.0.1:18081/v1',
    model: 'fixture-only',
    protocol: 'responses',
    key: 'fixture-key-only-12345',
    priority: 100,
    roleAffinity: 'any',
  }, storage, { skipConnectionCheck: true })

  // Mark the sole profile hard-open for quota (as providerPool.onProfileFailure does on 402).
  recordProfileFailure(saved.id, 'The provider quota or credit balance was exhausted.', true, storage)
  const liveProfiles = privateModelProfiles(storage)
  const circuit = evaluateRoleProviderCircuit(liveProfiles)
  assert.equal(circuit.hardOpen, true)
  assert.equal(circuit.kind, 'quota')
  assert.deepEqual(circuit.profileIds, [saved.id])

  storage.updateRun(runId, { status: 'running', phase: 'investigation' })
  const activeRun = storage.run(runId)

  // Seed 3 steps: step 1 is currently running, steps 2 & 3 are ready waiting in the queue.
  const s1 = storage.addChainStep(activeRun, {
    title: 'Step 1 (hits 402)',
    hypothesis: 'Probe GET /api/orders',
    category: 'broken-access-control',
    targetAssetIds: [asset.id],
    sourceOrigins: [ORIGIN],
  })
  const s2 = storage.addChainStep(activeRun, {
    title: 'Step 2 (queued ready)',
    hypothesis: 'Probe GET /api/invoices',
    category: 'broken-access-control',
    targetAssetIds: [asset.id],
    sourceOrigins: [ORIGIN],
  })
  const s3 = storage.addChainStep(activeRun, {
    title: 'Step 3 (depends on step 1)',
    hypothesis: 'Follow-up on /api/orders',
    category: 'broken-access-control',
    targetAssetIds: [asset.id],
    sourceOrigins: [ORIGIN],
    dependsOnStepIds: [s1.id],
  })
  storage.updateChainStep(s1.id, { status: 'running' })
  storage.updateChainStep(s2.id, { status: 'ready' })

  const engine = new Execution(storage, { backend: stubBackend() })
  t.after(() => engine.stop())
  const { workerRunner, active } = internals(engine)
  const budget = resolveAssignmentBudget(
    { title: s1.title, hypothesis: s1.hypothesis, category: s1.category },
    { baseMaxTurns: 12, baseWallClockMs: 60_000, runDurationMs: 600_000, singleStepWallClockMs: 60_000 },
  )

  const w1 = storage.updateWorker(
    storage.makeWorker(activeRun, 'investigation', asset, s1.title, s1.hypothesis, { stepId: s1.id, sourceOrigins: [ORIGIN] }).id,
    { status: 'running', lease: 'lease-402', leaseExpiresAt: Date.now() + 60_000 },
  )!
  const job1 = { assignment: w1, origins: new Set([ORIGIN]), controller: new AbortController() }
  active.set(w1.id, job1)

  workerRunner.handleInvestigationWorkerError(
    activeRun,
    job1,
    s1,
    'bola-bfla-specialist',
    budget,
    new QuotaExhaustedError('The provider quota or credit balance was exhausted.', { profileId: saved.id }),
  )

  // Run must be cleanly paused, ZERO steps marked model_failure, s1 restored to ready, s3 NOT tainted/blocked!
  assert.equal(storage.run(runId).status, 'paused', 'run must transition to paused on hard quota circuit')
  const stepsAfter = storage.listChainSteps(runId)
  assert.equal(stepsAfter.filter(s => s.status === 'model_failure').length, 0, 'ZERO model_failure cascade on 402')
  assert.equal(stepsAfter.find(s => s.id === s1.id)?.status, 'ready', 'failed step returns to ready for resume')
  assert.equal(stepsAfter.find(s => s.id === s2.id)?.status, 'ready', 'queued step stays ready (never dispatched into failure)')
  assert.equal(stepsAfter.find(s => s.id === s3.id)?.status, 'pending', 'dependent step is NOT cascade-blocked')

  const pauseEvents = storage.db.select().from(events).where(eq(events.runId, runId)).all()
    .filter(e => e.kind === 'run.provider_paused')
  assert.equal(pauseEvents.length, 1, 'must emit structured run.provider_paused event')
  assert.equal(pauseEvents[0]!.detail.reason, 'provider_paused')
  assert.equal(pauseEvents[0]!.detail.failureKind, 'quota')
  assert.deepEqual(pauseEvents[0]!.detail.profileIds, [saved.id])
})

// ============================================================================
// 5. Bounded 1-retry transient recovery + CRITICAL mid-stream idempotency guard
// ============================================================================

test('R2-13.6: transient failure retries once under RunSafetyBudgets; mid-stream drop BLOCKED after tool call executed', async t => {
  const { storage } = makeStore(t, 'kovo-r213-retry-')
  const { runId, run } = await setupApprovedRun(storage, { seeds: [ORIGIN], tier: 2 })
  const asset = run.candidates.find(c => run.approved.includes(c.id))!
  storage.updateRun(runId, { status: 'running', phase: 'investigation' })
  const activeRun = storage.run(runId)

  const engine = new Execution(storage, { backend: stubBackend() })
  t.after(() => engine.stop())
  const { workerRunner, active } = internals(engine)
  const budget = resolveAssignmentBudget(
    { title: 'Probe /api/items', hypothesis: 'Check GET /api/items', category: 'broken-access-control' },
    { baseMaxTurns: 12, baseWallClockMs: 60_000, runDurationMs: 600_000, singleStepWallClockMs: 60_000 },
  )

  // (a) Pure decision matrix: mid-stream drop allowed ONLY when toolCallsExecutedInTurn === 0
  const midDrop = new ProviderFailureError('The model stream dropped before completion.', {
    kind: 'stream_drop',
    emitted: true,
    retryable: true,
  })
  const allowedDecision = evaluateTransientProviderRetry({
    failure: midDrop,
    retryKey: 'GET /api/items::broken-access-control',
    priorKeyRetries: 0,
    stepSkills: [],
    assignmentAttempt: 0,
    toolCallsExecutedInTurn: 0,
    runStatus: 'running',
    runPhase: 'investigation',
    budgetExhausted: false,
    requestBudgetExhausted: false,
    wallClockExhausted: false,
    existingStepCount: 1,
    effectiveStepCap: 24,
    runProviderRetries: 0,
  })
  assert.equal(allowedDecision.retry, true)

  const blockedDecision = evaluateTransientProviderRetry({
    failure: midDrop,
    retryKey: 'GET /api/items::broken-access-control',
    priorKeyRetries: 0,
    stepSkills: [],
    assignmentAttempt: 0,
    toolCallsExecutedInTurn: 1,
    runStatus: 'running',
    runPhase: 'investigation',
    budgetExhausted: false,
    requestBudgetExhausted: false,
    wallClockExhausted: false,
    existingStepCount: 1,
    effectiveStepCap: 24,
    runProviderRetries: 0,
  })
  assert.equal(blockedDecision.retry, false)
  assert.equal(blockedDecision.reason, 'midstream_tool_call_executed')

  // (b) Live ExecWorkerRunner: 429 rate_limited retries ONCE, then 2nd failure terminates as model_failure
  const s429 = storage.addChainStep(activeRun, {
    title: 'Transient 429 step',
    hypothesis: 'Check GET /api/widgets',
    category: 'broken-access-control',
    targetAssetIds: [asset.id],
    sourceOrigins: [ORIGIN],
  })
  storage.updateChainStep(s429.id, { status: 'running' })
  const wAttempt0 = storage.updateWorker(
    storage.makeWorker(activeRun, 'investigation', asset, s429.title, s429.hypothesis, { stepId: s429.id, sourceOrigins: [ORIGIN] }).id,
    { status: 'running', attempt: 0, lease: 'lease-429-0', leaseExpiresAt: Date.now() + 60_000 },
  )!
  const job0 = { assignment: wAttempt0, origins: new Set([ORIGIN]), controller: new AbortController() }
  active.set(wAttempt0.id, job0)

  workerRunner.handleInvestigationWorkerError(
    activeRun,
    job0,
    s429,
    'bola-bfla-specialist',
    budget,
    new ProviderFailureError('The provider rate limit was reached.', { kind: 'rate_limited', status: 429, retryAfterMs: 1_000, emitted: false }),
  )
  const stepAfterFirst429 = storage.listChainSteps(runId).find(s => s.id === s429.id)!
  assert.equal(stepAfterFirst429.status, 'ready', 'first transient 429 must requeue step to ready once')
  assert.ok(stepAfterFirst429.skills.includes('r213:provider_retry:1'), 'retry marker skill prevents unbounded loops')

  // Second transient failure on the same step hits the 1-retry cap -> terminal model_failure
  storage.updateChainStep(s429.id, { status: 'running' })
  const wAttempt1 = storage.updateWorker(
    storage.makeWorker(activeRun, 'investigation', asset, s429.title, s429.hypothesis, { stepId: s429.id, sourceOrigins: [ORIGIN] }).id,
    { status: 'running', attempt: 1, lease: 'lease-429-1', leaseExpiresAt: Date.now() + 60_000 },
  )!
  const job1 = { assignment: wAttempt1, origins: new Set([ORIGIN]), controller: new AbortController() }
  active.set(wAttempt1.id, job1)

  workerRunner.handleInvestigationWorkerError(
    activeRun,
    job1,
    stepAfterFirst429,
    'bola-bfla-specialist',
    budget,
    new ProviderFailureError('The provider rate limit was reached.', { kind: 'rate_limited', status: 429, retryAfterMs: 1_000, emitted: false }),
  )
  assert.equal(
    storage.listChainSteps(runId).find(s => s.id === s429.id)?.status,
    'model_failure',
    'second transient failure must respect 1-retry cap and close as model_failure',
  )

  // (c) Live ExecWorkerRunner: mid-stream drop BEFORE any tool call -> requeued once
  const sDropSafe = storage.addChainStep(activeRun, {
    title: 'Mid-stream drop safe',
    hypothesis: 'Check GET /api/safe-drop',
    category: 'idor',
    targetAssetIds: [asset.id],
    sourceOrigins: [ORIGIN],
  })
  storage.updateChainStep(sDropSafe.id, { status: 'running' })
  const wDropSafe = storage.updateWorker(
    storage.makeWorker(activeRun, 'investigation', asset, sDropSafe.title, sDropSafe.hypothesis, { stepId: sDropSafe.id, sourceOrigins: [ORIGIN] }).id,
    { status: 'running', attempt: 0, lease: 'lease-drop-safe', leaseExpiresAt: Date.now() + 60_000 },
  )!
  const jobDropSafe = { assignment: wDropSafe, origins: new Set([ORIGIN]), controller: new AbortController() }
  active.set(wDropSafe.id, jobDropSafe)
  workerRunner.handleInvestigationWorkerError(
    activeRun,
    jobDropSafe,
    sDropSafe,
    'bola-bfla-specialist',
    budget,
    midDrop,
    { noToolCallExecuted: true },
  )
  assert.equal(
    storage.listChainSteps(runId).find(s => s.id === sDropSafe.id)?.status,
    'ready',
    'mid-stream drop with noToolCallExecuted=true may retry once',
  )

  // (d) Live ExecWorkerRunner: mid-stream drop AFTER a tool call executed -> MUST NOT retry!
  const sDropUnsafe = storage.addChainStep(activeRun, {
    title: 'Mid-stream drop after tool',
    hypothesis: 'Check POST /api/unsafe-drop',
    category: 'business-logic',
    targetAssetIds: [asset.id],
    sourceOrigins: [ORIGIN],
  })
  storage.updateChainStep(sDropUnsafe.id, { status: 'running' })
  const wDropUnsafe = storage.updateWorker(
    storage.makeWorker(activeRun, 'investigation', asset, sDropUnsafe.title, sDropUnsafe.hypothesis, { stepId: sDropUnsafe.id, sourceOrigins: [ORIGIN] }).id,
    { status: 'running', attempt: 0, lease: 'lease-drop-unsafe', leaseExpiresAt: Date.now() + 60_000 },
  )!
  const jobDropUnsafe = { assignment: wDropUnsafe, origins: new Set([ORIGIN]), controller: new AbortController() }
  active.set(wDropUnsafe.id, jobDropUnsafe)
  workerRunner.handleInvestigationWorkerError(
    activeRun,
    jobDropUnsafe,
    sDropUnsafe,
    'bola-bfla-specialist',
    budget,
    midDrop,
    { noToolCallExecuted: false },
  )
  assert.equal(
    storage.listChainSteps(runId).find(s => s.id === sDropUnsafe.id)?.status,
    'model_failure',
    'mid-stream drop AFTER tool execution MUST NOT retry (target-safety idempotency invariant)',
  )
  const blockedEvents = storage.db.select().from(events).where(eq(events.runId, runId)).all()
    .filter(e => e.kind === 'worker.provider_retry_blocked')
  assert.equal(blockedEvents.length, 1)
  assert.equal(blockedEvents[0]!.detail.reason, 'midstream_tool_call_executed')
})

// ============================================================================
// 6. Safety Judge transient 1-retry + structured fail_safe surfacing
// ============================================================================

test('R2-13.7: Safety Judge retries transient provider failure once and surfaces structured failSafe + failSafeReason', async () => {
  // (a) Transient 503 on attempt 1 -> retries once and succeeds on attempt 2
  let transientCalls = 0
  const recovered = await evaluateTier3Approval({
    policy: 'auto_review',
    origin: ORIGIN,
    method: 'POST',
    pathAndQuery: '/api/profile/update',
    personaHandle: 'user_a',
    bodyPreview: '{"bio":"hello"}',
    offline: false,
    llmCall: async () => {
      transientCalls += 1
      if (transientCalls === 1) {
        throw new ProviderFailureError('The model provider returned HTTP 503.', {
          kind: 'server',
          status: 503,
          retryAfterMs: 5,
        })
      }
      return JSON.stringify({ decision: 'approve', riskLevel: 'low', reason: 'Benign profile bio check.' })
    },
  })
  assert.equal(transientCalls, 2, 'Judge must retry transient provider failure once')
  assert.equal(recovered.decision, 'approve')
  assert.equal(recovered.stage, 'safety_judge')
  assert.equal(recovered.failSafe, undefined)
  assert.equal(recovered.judgeAttempts, 2)

  // (b) Transient 429 failing both attempts -> bounded at 2 attempts, surfaces failSafe + failSafeReason
  let exhaustedCalls = 0
  const exhausted = await evaluateTier3Approval({
    policy: 'auto_review',
    origin: ORIGIN,
    method: 'POST',
    pathAndQuery: '/api/profile/update',
    personaHandle: 'user_a',
    bodyPreview: '{"bio":"hello"}',
    offline: false,
    llmCall: async () => {
      exhaustedCalls += 1
      throw new ProviderFailureError('The provider rate limit was reached.', {
        kind: 'rate_limited',
        status: 429,
        retryAfterMs: 5,
      })
    },
  })
  assert.equal(exhaustedCalls, 2, 'Judge must cap retries at 1 (2 total attempts)')
  assert.equal(exhausted.decision, 'escalate_human')
  assert.equal(exhausted.stage, 'fail_safe')
  assert.equal(exhausted.failSafe, true)
  assert.equal(exhausted.failSafeReason, 'judge_provider_rate_limited')
  assert.equal(exhausted.judgeAttempts, 2)

  // (c) Hard 402 quota failure -> NEVER retried (1 attempt), distinct failSafeReason
  let quotaCalls = 0
  const quotaFail = await evaluateTier3Approval({
    policy: 'auto_review',
    origin: ORIGIN,
    method: 'POST',
    pathAndQuery: '/api/profile/update',
    personaHandle: 'user_a',
    bodyPreview: '{"bio":"hello"}',
    offline: false,
    llmCall: async () => {
      quotaCalls += 1
      throw new QuotaExhaustedError('The provider quota or credit balance was exhausted.')
    },
  })
  assert.equal(quotaCalls, 1, 'Hard quota exhaustion must not be retried by Judge')
  assert.equal(quotaFail.stage, 'fail_safe')
  assert.equal(quotaFail.failSafe, true)
  assert.equal(quotaFail.failSafeReason, 'judge_provider_quota')
  assert.equal(quotaFail.judgeAttempts, 1)

  // (d) Invalid JSON -> NEVER retried (1 attempt), failSafeReason='judge_invalid_response'
  let badJsonCalls = 0
  const badJson = await evaluateTier3Approval({
    policy: 'auto_review',
    origin: ORIGIN,
    method: 'POST',
    pathAndQuery: '/api/profile/update',
    personaHandle: 'user_a',
    bodyPreview: '{"bio":"hello"}',
    offline: false,
    llmCall: async () => {
      badJsonCalls += 1
      return 'not-json'
    },
  })
  assert.equal(badJsonCalls, 1)
  assert.equal(badJson.stage, 'fail_safe')
  assert.equal(badJson.failSafe, true)
  assert.equal(badJson.failSafeReason, 'judge_invalid_response')

  // (e) Offline & unconfigured surface distinct structured failSafeReason values
  const offlineRes = await evaluateTier3Approval({
    policy: 'auto_review',
    origin: ORIGIN,
    method: 'POST',
    pathAndQuery: '/api/profile/update',
    personaHandle: 'user_a',
    bodyPreview: '{"bio":"hello"}',
    offline: true,
  })
  assert.equal(offlineRes.stage, 'fail_safe')
  assert.equal(offlineRes.failSafe, true)
  assert.equal(offlineRes.failSafeReason, 'judge_offline')

  const unconfiguredRes = await evaluateTier3Approval({
    policy: 'auto_review',
    origin: ORIGIN,
    method: 'POST',
    pathAndQuery: '/api/profile/update',
    personaHandle: 'user_a',
    bodyPreview: '{"bio":"hello"}',
    offline: false,
  })
  assert.equal(unconfiguredRes.stage, 'fail_safe')
  assert.equal(unconfiguredRes.failSafe, true)
  assert.equal(unconfiguredRes.failSafeReason, 'judge_unconfigured')

  // (f) createSafetyJudgeLlmCall propagates typed QuotaExhaustedError from stub fetch
  const profile = makeProfile({ roleAffinity: 'fast' })
  const judgeCall = createSafetyJudgeLlmCall([profile], {
    fetch: async () => new Response(
      JSON.stringify({ error: { message: 'Insufficient credits' } }),
      { status: 402, headers: { 'content-type': 'application/json' } },
    ),
  })
  await assert.rejects(
    () => judgeCall({ systemPrompt: 'judge', userPrompt: '{}' }),
    (err: unknown) => err instanceof QuotaExhaustedError && err.kind === 'quota',
  )
})
