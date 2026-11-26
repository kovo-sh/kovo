/**
 * Gap #4 — Structured Cost/Token Economics & Prompt-Cache Hit Telemetry Tests:
 *  1. Prompt-cache hit rate math (`cached / (cached + uncached)`), reasoning tokens, and clamping.
 *  2. Retry, stall, and truncated-tool-call waste attribution (`retryStallWasteUsd`) + rotations.
 *  3. Per-tool result byte & spill tracking (`toolResultBytesByTool` + `topToolResultDrivers` ranking).
 *  4. Secret-free summary guarantees and bounded per-run memory + `disposeRunTokenTelemetry` cleanup.
 *  5. End-to-end integration with `provider()` and `providerPool()` SSE streaming (Responses &
 *     Messages cache/reasoning usage, 429/503 failover retries, idle/stall timeouts, and Q1
 *     truncated tool-call JSON diagnostics).
 */
import assert from 'node:assert/strict'
import { once } from 'node:events'
import { createServer } from 'node:http'
import type { AddressInfo } from 'node:net'
import { afterEach, describe, test } from 'node:test'

import type { ResolvedModelProfile } from '../src/server/model-settings.ts'
import {
  TOOL_CALL_JSON_REPAIR_HINT,
  provider,
  providerPool,
  type UsageEvent,
} from '../src/server/provider.ts'
import {
  MAX_TOOLS_PER_RUN_TELEMETRY,
  MAX_TRACKED_RUN_TELEMETRY,
  disposeRunTokenTelemetry,
  getRunTokenTelemetrySummary,
  getTrackedRunTelemetryCount,
  hasRunTokenTelemetry,
  rankToolResultByteDrivers,
  recordProviderUsageTelemetry,
  recordToolResultSizeTelemetry,
  recordWallClockRotationTelemetry,
  type ProviderUsageTelemetryInput,
} from '../src/server/token-telemetry.ts'

const createdRunIds: string[] = []

function trackRun(runId: string): string {
  createdRunIds.push(runId)
  return runId
}

afterEach(() => {
  while (createdRunIds.length > 0) {
    const id = createdRunIds.pop()
    if (id) disposeRunTokenTelemetry(id)
  }
})

function makeProfile(overrides: Partial<ResolvedModelProfile> & {
  id: string
  endpoint: string
  key: string
}): ResolvedModelProfile {
  return {
    name: overrides.id,
    model: 'telemetry-test-model',
    protocol: 'responses',
    enabled: true,
    priority: 100,
    contextWindow: 128_000,
    maxTokens: 4096,
    inputCostPerMtok: 1.0,
    cachedInputCostPerMtok: 0.1,
    outputCostPerMtok: 2.0,
    thinkingLevel: 'off',
    roleAffinity: 'any',
    healthState: 'closed',
    cooldownUntil: null,
    lastError: null,
    ...overrides,
  }
}

function sse(events: Array<{ type: string } & Record<string, unknown>>, done = true, named = false): string {
  return events
    .map(ev => (named ? `event: ${ev.type}\n` : '') + `data: ${JSON.stringify(ev)}\n\n`)
    .join('') + (done ? 'data: [DONE]\n\n' : '')
}

async function waitFor(predicate: () => boolean, timeoutMs = 2_000, label = 'condition'): Promise<void> {
  const deadline = Date.now() + timeoutMs
  while (Date.now() < deadline) {
    if (predicate()) return
    await new Promise(resolve => setTimeout(resolve, 10))
  }
  assert.ok(predicate(), `Timed out waiting for ${label} after ${timeoutMs}ms`)
}

// ============================================================================
// 1. Token, Prompt-Cache Hit Rate, Cost & Waste Attribution Math
// ============================================================================

describe('Gap #4: Token Telemetry Accumulator & Math', () => {
  test('computes exact cacheHitRate = cached / (cached + uncached), reasoning tokens, and zero-input edge cases', () => {
    const runId = trackRun('run-cache-math-1')

    // Querying before any record returns clean zeroed summary without allocating state
    const initial = getRunTokenTelemetrySummary(runId)
    assert.equal(initial.cacheHitRate, 0)
    assert.equal(initial.inputTokens, 0)
    assert.equal(hasRunTokenTelemetry(runId), false)

    // Turn 1: 1000 input, 750 cached -> 250 uncached
    recordProviderUsageTelemetry({
      runId,
      inputTokens: 1_000,
      cachedInputTokens: 750,
      outputTokens: 200,
      reasoningTokens: 120,
      costUsd: 0.005,
      outcome: 'ok',
    })

    // Turn 2: explicit cached + uncached (250 cached, 750 uncached -> 1000 input)
    recordProviderUsageTelemetry({
      runId,
      cachedInputTokens: 250,
      uncachedInputTokens: 750,
      outputTokens: 300,
      reasoningTokens: 80,
      costUsd: 0.007,
      outcome: 'ok',
    })

    // Turn 3: invalid negative / clamped cached > input edge cases
    recordProviderUsageTelemetry({
      runId,
      inputTokens: 500,
      cachedInputTokens: 900, // clamped to 500
      outputTokens: -10,
      costUsd: -5,
    })

    const summary = getRunTokenTelemetrySummary(runId)
    assert.equal(summary.inputTokens, 2_500)
    assert.equal(summary.cachedInputTokens, 1_500)
    assert.equal(summary.uncachedInputTokens, 1_000)
    assert.equal(summary.outputTokens, 500)
    assert.equal(summary.reasoningTokens, 200)
    assert.ok(Math.abs(summary.cacheHitRate - 0.6) < 1e-12, `expected 0.6 cacheHitRate, got ${summary.cacheHitRate}`)
    assert.ok(Math.abs(summary.totalCostUsd - 0.012) < 1e-12)
    assert.equal(summary.retryStallWasteUsd, 0)
    assert.equal(summary.providerCalls, 3)
  })

  test('attributes cost of stalled, retried, and truncated tool-call turns to retryStallWasteUsd while keeping healthy calls clean', () => {
    const runId = trackRun('run-waste-attr-1')

    // Healthy call: $0.10 -> NOT wasted
    recordProviderUsageTelemetry({
      runId,
      inputTokens: 10_000,
      cachedInputTokens: 8_000,
      outputTokens: 1_000,
      costUsd: 0.10,
      outcome: 'ok',
    })

    // Stalled call with partial tokens: $0.03 -> wasted
    recordProviderUsageTelemetry({
      runId,
      inputTokens: 4_000,
      cachedInputTokens: 0,
      outputTokens: 100,
      costUsd: 0.03,
      outcome: 'stalled',
      stalled: true,
    })

    // Retried attempt: $0.02 -> wasted
    recordProviderUsageTelemetry({
      runId,
      inputTokens: 2_000,
      cachedInputTokens: 1_000,
      outputTokens: 50,
      costUsd: 0.02,
      outcome: 'retried',
      retried: true,
    })

    // Truncated tool-call attempt (2 broken tool calls): $0.04 -> wasted
    recordProviderUsageTelemetry({
      runId,
      inputTokens: 5_000,
      cachedInputTokens: 3_000,
      outputTokens: 400,
      costUsd: 0.04,
      outcome: 'truncated',
      truncatedToolCalls: 2,
    })

    recordWallClockRotationTelemetry(runId)
    recordWallClockRotationTelemetry(runId, 2)

    const summary = getRunTokenTelemetrySummary(runId)
    assert.equal(summary.providerCalls, 4)
    assert.equal(summary.providerStalls, 1)
    assert.equal(summary.providerRetries, 1)
    assert.equal(summary.truncatedToolCalls, 2)
    assert.equal(summary.wallClockRotations, 3)
    assert.ok(Math.abs(summary.totalCostUsd - 0.19) < 1e-12, `expected 0.19 totalCostUsd, got ${summary.totalCostUsd}`)
    assert.ok(Math.abs(summary.retryStallWasteUsd - 0.09) < 1e-12, `expected 0.09 retryStallWasteUsd, got ${summary.retryStallWasteUsd}`)
  })

  test('ranks toolResultBytesByTool descending by bytes to highlight context bloat drivers', () => {
    const runId = trackRun('run-tool-drivers-1')

    recordToolResultSizeTelemetry({ runId, toolName: 'query_facts', bytes: 1_200, spilled: false })
    recordToolResultSizeTelemetry({ runId, toolName: 'derive_evidence', bytes: 42_000, spilled: true })
    recordToolResultSizeTelemetry({ runId, toolName: 'request_http', bytes: 8_500, spilled: false })
    recordToolResultSizeTelemetry({ runId, toolName: 'request_http', bytes: 19_500, spilled: true })
    recordToolResultSizeTelemetry({ runId, toolName: 'derive_evidence', bytes: 18_000, spilled: true })

    const summary = getRunTokenTelemetrySummary(runId)
    assert.equal(summary.totalToolResultBytes, 89_200)
    assert.equal(summary.toolResultSpills, 3)
    assert.deepEqual(Object.keys(summary.toolResultBytesByTool), [
      'derive_evidence',
      'request_http',
      'query_facts',
    ])
    assert.deepEqual(summary.toolResultBytesByTool.derive_evidence, {
      calls: 2,
      bytes: 60_000,
      spilledCount: 2,
    })
    assert.deepEqual(summary.toolResultBytesByTool.request_http, {
      calls: 2,
      bytes: 28_000,
      spilledCount: 1,
    })
    assert.deepEqual(summary.toolResultBytesByTool.query_facts, {
      calls: 1,
      bytes: 1_200,
      spilledCount: 0,
    })
    assert.deepEqual(summary.topToolResultDrivers.map(d => d.toolName), [
      'derive_evidence',
      'request_http',
      'query_facts',
    ])
    assert.deepEqual(rankToolResultByteDrivers(summary.toolResultBytesByTool, 2).map(d => d.toolName), [
      'derive_evidence',
      'request_http',
    ])

    // Mutating returned summary must not corrupt internal state
    summary.toolResultBytesByTool.derive_evidence!.bytes = 0
    assert.equal(getRunTokenTelemetrySummary(runId).toolResultBytesByTool.derive_evidence?.bytes, 60_000)
  })
})

// ============================================================================
// 2. Bounded Memory, Disposal Cleanup & Secret-Free Output
// ============================================================================

describe('Gap #4: Memory Bounds, Disposal Cleanup & Secret Hygiene', () => {
  test('disposeRunTokenTelemetry clears state completely without re-allocating on subsequent reads', () => {
    const runId = trackRun('run-dispose-clean-1')
    recordProviderUsageTelemetry({ runId, inputTokens: 100, outputTokens: 20, costUsd: 0.001 })
    recordToolResultSizeTelemetry({ runId, toolName: 'request_http', bytes: 512 })
    assert.equal(hasRunTokenTelemetry(runId), true)

    const beforeCount = getTrackedRunTelemetryCount()
    assert.equal(disposeRunTokenTelemetry(runId), true)
    assert.equal(hasRunTokenTelemetry(runId), false)
    assert.equal(getTrackedRunTelemetryCount(), beforeCount - 1)

    // Idempotent second disposal returns false
    assert.equal(disposeRunTokenTelemetry(runId), false)

    // Reading after disposal returns clean zeros and leaves tracked count unchanged
    const afterSummary = getRunTokenTelemetrySummary(runId)
    assert.equal(afterSummary.inputTokens, 0)
    assert.deepEqual(afterSummary.toolResultBytesByTool, {})
    assert.equal(hasRunTokenTelemetry(runId), false)
    assert.equal(getTrackedRunTelemetryCount(), beforeCount - 1)
  })

  test('bounds tracked runs (LRU) and per-run tool buckets (overflow bucket)', () => {
    const toolOverflowRun = trackRun('run-tool-cap-1')
    for (let i = 0; i < MAX_TOOLS_PER_RUN_TELEMETRY + 15; i++) {
      recordToolResultSizeTelemetry({ runId: toolOverflowRun, toolName: `tool_${i}`, bytes: 10 })
    }
    const toolSummary = getRunTokenTelemetrySummary(toolOverflowRun)
    assert.equal(Object.keys(toolSummary.toolResultBytesByTool).length, MAX_TOOLS_PER_RUN_TELEMETRY + 1)
    assert.equal(toolSummary.toolResultBytesByTool.__other__?.calls, 15)
    assert.equal(toolSummary.toolResultBytesByTool.__other__?.bytes, 150)

    // Verify global run map stays bounded at MAX_TRACKED_RUN_TELEMETRY
    const prefix = 'run-lru-cap-'
    for (let i = 0; i < MAX_TRACKED_RUN_TELEMETRY + 20; i++) {
      const id = trackRun(`${prefix}${i}`)
      recordProviderUsageTelemetry({ runId: id, inputTokens: 10, costUsd: 0.0001 })
    }
    assert.ok(
      getTrackedRunTelemetryCount() <= MAX_TRACKED_RUN_TELEMETRY,
      `expected tracked runs <= ${MAX_TRACKED_RUN_TELEMETRY}, got ${getTrackedRunTelemetryCount()}`,
    )
    assert.equal(hasRunTokenTelemetry(`${prefix}0`), false, 'oldest run must be evicted when capacity exceeded')
    assert.equal(hasRunTokenTelemetry(`${prefix}${MAX_TRACKED_RUN_TELEMETRY + 19}`), true)
  })
})

// ============================================================================
// 3. Provider.ts Streaming Integration (Responses, Messages, Retries, Stalls, Q1 Truncation)
// ============================================================================

describe('Gap #4: provider.ts & providerPool() Streaming Telemetry Integration', () => {
  test('records Responses & Messages streaming usage (cached + reasoning tokens) with zero secret leakage and zero overhead when runId is absent', async t => {
    const prevLocal = process.env.KOVO_ALLOW_LOCAL_MODEL
    process.env.KOVO_ALLOW_LOCAL_MODEL = '1'
    t.after(() => {
      if (prevLocal === undefined) delete process.env.KOVO_ALLOW_LOCAL_MODEL
      else process.env.KOVO_ALLOW_LOCAL_MODEL = prevLocal
    })

    const apiKey = 'sk-telemetry-secret-key-998877'
    const vaultSecret = 'vault-session-bearer-secret-445566'

    const server = createServer((req, res) => {
      req.resume()
      res.writeHead(200, { 'content-type': 'text/event-stream' })
      if (req.url?.includes('/responses')) {
        const item = {
          type: 'message',
          id: 'msg_r1',
          role: 'assistant',
          status: 'completed',
          content: [{ type: 'output_text', text: `ok ${vaultSecret}`, annotations: [] }],
        }
        res.end(sse([
          { type: 'response.created', response: { id: 'resp_1', status: 'in_progress' } },
          { type: 'response.output_item.added', output_index: 0, item: { ...item, content: [], status: 'in_progress' } },
          { type: 'response.output_text.delta', output_index: 0, content_index: 0, delta: `ok ${vaultSecret}` },
          { type: 'response.output_item.done', output_index: 0, item },
          {
            type: 'response.completed',
            response: {
              id: 'resp_1',
              status: 'completed',
              output: [item],
              usage: {
                input_tokens: 1_000,
                input_tokens_details: { cached_tokens: 600 },
                output_tokens: 250,
                output_tokens_details: { reasoning_tokens: 150 },
              },
            },
          },
        ]))
        return
      }
      // Anthropic Messages protocol
      res.end(sse([
        {
          type: 'message_start',
          message: {
            id: 'msg_m1',
            type: 'message',
            role: 'assistant',
            model: 'claude-telemetry',
            content: [],
            usage: { input_tokens: 400, cache_read_input_tokens: 600, output_tokens: 0 },
          },
        },
        { type: 'content_block_start', index: 0, content_block: { type: 'text', text: '' } },
        { type: 'content_block_delta', index: 0, delta: { type: 'text_delta', text: 'anthropic-ok' } },
        { type: 'content_block_stop', index: 0 },
        { type: 'message_delta', delta: { stop_reason: 'end_turn' }, usage: { output_tokens: 100 } },
        { type: 'message_stop' },
      ], false, true))
    }).listen(0, '127.0.0.1')
    await once(server, 'listening')
    t.after(async () => {
      server.closeAllConnections()
      await new Promise<void>(resolve => server.close(() => resolve()))
    })
    const port = (server.address() as AddressInfo).port

    // 1. Without runId / onTelemetry -> zero telemetry allocation
    const baselineTracked = getTrackedRunTelemetryCount()
    const untracked = provider({
      endpoint: `http://127.0.0.1:${port}/v1`,
      model: 'gpt-telemetry',
      protocol: 'responses',
      key: apiKey,
    }, 'worker-investigation')
    const su = untracked.models.stream(untracked.model, {
      systemPrompt: 'sys',
      messages: [{ role: 'user', content: 'hi', timestamp: Date.now() }],
      tools: [],
    })
    for await (const _ev of su) { /* drain */ }
    await su.result()
    assert.equal(getTrackedRunTelemetryCount(), baselineTracked, 'absent runId must allocate zero telemetry state')

    // 2. With runId + onTelemetry across both Responses and Messages
    const runId = trackRun('run-provider-stream-1')
    const events: ProviderUsageTelemetryInput[] = []
    const usages: UsageEvent[] = []

    const respProv = provider({
      endpoint: `http://127.0.0.1:${port}/v1`,
      model: 'gpt-telemetry',
      protocol: 'responses',
      key: apiKey,
      inputCostPerMtok: 1.0,
      cachedInputCostPerMtok: 0.1,
      outputCostPerMtok: 2.0,
    }, 'worker-investigation', {
      runId,
      secrets: [{ value: vaultSecret, placeholder: '[redacted]' }],
      onUsage: u => usages.push(u),
      onTelemetry: ev => events.push(ev),
    })
    const sr = respProv.models.stream(respProv.model, {
      systemPrompt: 'sys',
      messages: [{ role: 'user', content: 'hi', timestamp: Date.now() }],
      tools: [],
    })
    for await (const _ev of sr) { /* drain */ }
    await sr.result()

    const msgProv = provider({
      endpoint: `http://127.0.0.1:${port}/v1`,
      model: 'claude-telemetry',
      protocol: 'messages',
      key: apiKey,
      inputCostPerMtok: 1.0,
      cachedInputCostPerMtok: 0.1,
      outputCostPerMtok: 2.0,
    }, 'worker-investigation', {
      runId,
      onUsage: u => usages.push(u),
      onTelemetry: ev => events.push(ev),
    })
    const sm = msgProv.models.stream(msgProv.model, {
      systemPrompt: 'sys',
      messages: [{ role: 'user', content: 'hi', timestamp: Date.now() }],
      tools: [],
    })
    for await (const _ev of sm) { /* drain */ }
    await sm.result()

    await waitFor(() => events.length === 2 && usages.length === 2, 1_500, 'telemetry & usage flush')

    const summary = getRunTokenTelemetrySummary(runId)
    assert.equal(summary.inputTokens, 2_000)
    assert.equal(summary.cachedInputTokens, 1_200)
    assert.equal(summary.uncachedInputTokens, 800)
    assert.equal(summary.outputTokens, 350)
    assert.equal(summary.reasoningTokens, 150)
    assert.ok(Math.abs(summary.cacheHitRate - 0.6) < 1e-12)
    // Resp cost: (400*1 + 600*0.1 + 250*2)/1M = 0.00096; Msg cost: (400*1 + 600*0.1 + 100*2)/1M = 0.00066 -> 0.00162
    assert.ok(Math.abs(summary.totalCostUsd - 0.00162) < 1e-9, `unexpected cost ${summary.totalCostUsd}`)
    assert.equal(summary.retryStallWasteUsd, 0)
    assert.equal(usages[0]!.reasoningTokens, 150)

    const serialized = JSON.stringify(summary)
    assert.equal(serialized.includes(apiKey), false, 'telemetry summary must never contain provider API key')
    assert.equal(serialized.includes(vaultSecret), false, 'telemetry summary must never contain vault secret')
  })

  test('captures providerPool failover retries, idle-timeout stall waste, and Q1 truncated tool-call JSON without secrets', async () => {
    const runId = trackRun('run-provider-failures-1')
    const secret = 'sk-fail-secret-abc-12345'
    const p1 = makeProfile({ id: 'pool-a', endpoint: 'https://a.telemetry.test/v1', key: secret, priority: 200 })
    const p2 = makeProfile({ id: 'pool-b', endpoint: 'https://b.telemetry.test/v1', key: 'sk-pool-b-key', priority: 100 })

    // 1. Failover retry: p1 returns 429, fails over to p2 which returns truncated tool-call JSON
    const brokenArgs = `{"script":"const tok='${secret}'; await ctx.prove(`
    const fcId = 'fc_trunc_tel'
    const truncatedSse = sse([
      { type: 'response.created', response: { id: 'resp_t', status: 'in_progress' } },
      { type: 'response.output_item.added', output_index: 0, item: { type: 'function_call', id: fcId, call_id: 'c1', name: 'kovo_verify', arguments: '', status: 'in_progress' } },
      { type: 'response.function_call_arguments.delta', output_index: 0, item_id: fcId, delta: brokenArgs },
      { type: 'response.function_call_arguments.done', output_index: 0, item_id: fcId, name: 'kovo_verify', arguments: brokenArgs },
      { type: 'response.output_item.done', output_index: 0, item: { type: 'function_call', id: fcId, call_id: 'c1', name: 'kovo_verify', arguments: brokenArgs, status: 'incomplete' } },
      {
        type: 'response.incomplete',
        response: {
          id: 'resp_t',
          status: 'incomplete',
          incomplete_details: { reason: 'max_output_tokens' },
          output: [{ type: 'function_call', id: fcId, call_id: 'c1', name: 'kovo_verify', arguments: brokenArgs, status: 'incomplete' }],
          usage: { input_tokens: 1_000, input_tokens_details: { cached_tokens: 500 }, output_tokens: 200 },
        },
      },
    ])

    let callIdx = 0
    const { models, model } = providerPool([p1, p2], 'worker-investigation', {
      runId,
      maxTransportRetries: 1,
      transportRetryBaseMs: 1,
      secrets: [{ value: secret, placeholder: '[redacted]' }],
      fetch: async () => {
        callIdx += 1
        if (callIdx === 1) {
          return new Response(JSON.stringify({ error: { message: 'Requests per minute rate limit exceeded' } }), {
            status: 429,
            headers: { 'content-type': 'application/json' },
          })
        }
        return new Response(truncatedSse, { status: 200, headers: { 'content-type': 'text/event-stream' } })
      },
    })

    const s1 = models.stream(model, {
      systemPrompt: 'Verify.',
      messages: [{ role: 'user', content: 'run', timestamp: Date.now() }],
      tools: [{ name: 'kovo_verify', description: 'Verify', parameters: { type: 'object' } as never }],
    })
    for await (const _ev of s1) { /* drain */ }
    const res1 = await s1.result()
    const toolPart = res1.content.find(part => part.type === 'toolCall') as { argumentsError?: string } | undefined
    assert.ok(toolPart?.argumentsError?.includes(TOOL_CALL_JSON_REPAIR_HINT), 'Q1 tool-call repair hint must stay intact')

    // 2. Idle timeout stall after emitting partial message_start usage on Anthropic Messages
    const stallProv = provider({
      endpoint: 'https://stall.telemetry.test/v1',
      model: 'claude-stall',
      protocol: 'messages',
      key: secret,
      inputCostPerMtok: 1.0,
      cachedInputCostPerMtok: 0.1,
      outputCostPerMtok: 2.0,
    }, 'worker-investigation', {
      runId,
      idleTimeoutMs: 40,
      maxTransportRetries: 0,
      fetch: async () => {
        const body = new ReadableStream<Uint8Array>({
          start(controller) {
            controller.enqueue(new TextEncoder().encode(
              `event: message_start\ndata: ${JSON.stringify({
                type: 'message_start',
                message: {
                  id: 'msg_stall',
                  type: 'message',
                  role: 'assistant',
                  model: 'claude-stall',
                  content: [],
                  usage: { input_tokens: 1_000, cache_read_input_tokens: 0, output_tokens: 50 },
                },
              })}\n\n`,
            ))
            // Leave stream open without closing to trigger idleTimeoutMs stall
          },
        })
        return new Response(body, { status: 200, headers: { 'content-type': 'text/event-stream' } })
      },
    })

    const s2 = stallProv.models.stream(stallProv.model, {
      systemPrompt: 'Stall test.',
      messages: [{ role: 'user', content: 'go', timestamp: Date.now() }],
      tools: [],
    })
    for await (const _ev of s2) { /* drain until stall error */ }
    const res2 = await s2.result().catch(() => undefined)
    assert.equal(res2?.stopReason, 'error')

    await waitFor(() => {
      const s = getRunTokenTelemetrySummary(runId)
      return s.providerCalls === 3 && s.providerStalls === 1 && s.truncatedToolCalls === 1
    }, 1_500, 'stall + retry + truncated telemetry flush')

    const summary = getRunTokenTelemetrySummary(runId)
    assert.equal(summary.providerCalls, 3) // 1 429 retry + 1 truncated turn + 1 stalled turn
    assert.equal(summary.providerRetries, 1)
    assert.equal(summary.providerStalls, 1)
    assert.equal(summary.truncatedToolCalls, 1)
    // Truncated turn cost: (500*1 + 500*0.1 + 200*2)/1M = 0.00095
    // Stalled turn cost: (1000*1 + 50*2)/1M = 0.0011
    // Total wasted = 0.00205
    assert.ok(Math.abs(summary.totalCostUsd - 0.00205) < 1e-9, `expected 0.00205 totalCostUsd, got ${summary.totalCostUsd}`)
    assert.ok(Math.abs(summary.retryStallWasteUsd - 0.00205) < 1e-9, `expected 0.00205 retryStallWasteUsd, got ${summary.retryStallWasteUsd}`)
    assert.equal(JSON.stringify(summary).includes(secret), false, 'summary must never leak secret')
  })
})
