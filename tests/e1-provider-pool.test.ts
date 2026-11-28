/**
 * Track E1: 3-Tier DeepSeek V4.1 Flash Failover Pool Contract Tests.
 *
 * Covers:
 *   1. `'chat-completions'` protocol end-to-end SSE streaming: usage (`prompt_tokens`,
 *      `completion_tokens`, `prompt_tokens_details.cached_tokens`, `completion_tokens_details.reasoning_tokens`),
 *      `choices[0].delta.{content,reasoning_content,tool_calls}`, split-chunk secret redaction via
 *      `prepareDeltas` + `sanitizeInboundDelta`, truncated tool-call JSON repair hints, and `testProvider`.
 *   2. Session cache affinity wiring: `model.compat` (`promptCacheKeyMode: 'enabled'`,
 *      `sendSessionAffinityHeaders: true`, `sessionAffinityFormat`), `prompt_cache_key` in outbound JSON,
 *      `x-session-id` on all endpoints, and `x-opencode-session` strictly on `opencode.ai` hosts.
 *   3. 3-tier priority failover (300 -> 200 -> 100) with streak-1 HTTP 429 `healthState='open'` +
 *      `Retry-After` clamped cooldown (`[1_000, 300_000]`), immediate bypass of cooled-down tier 300 on
 *      subsequent turns (both same `providerPool` and fresh `privateModelProfiles`), and auto-recovery
 *      via `open -> half_open` once cooldown expires.
 *   4. Morph Ultra steady + burst response header inspection (`x-morph-ultra-uncached-input-remaining`,
 *      `x-morph-ultra-uncached-input-burst-remaining`, `x-morph-ultra-output-remaining`,
 *      `x-morph-ultra-output-burst-remaining`, `*-burst-reset`): uses burst reserve when steady=0 and
 *      burst>0, triggers proactive cooldown on 2xx only when BOTH steady<=0 and burst<=0, and uses
 *      reset delta on 429 when `Retry-After` is absent.
 *   5. Per-provider telemetry breakdown (`providerBreakdown`) in `getRunTokenTelemetrySummary` across
 *      direct recording and multi-tier `providerPool` failover.
 *   6. Key-safe `configureModelPool` CLI helper (`scripts/configure-model-pool.ts`): idempotent upsert of
 *      Morph Ultra (300) + OpenCode Go (200) alongside OpenRouter (100), mode-0600 enforcement, and zero
 *      secret leakage in formatted summary output.
 */
import assert from 'node:assert/strict'
import { chmodSync, mkdtempSync, rmSync, statSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, describe, test } from 'node:test'
import { eq } from 'drizzle-orm'

import { configureModelPool, formatPoolSummaryTable } from '../scripts/configure-model-pool.ts'
import {
  isProfileHealthy,
  listModelProfiles,
  privateModelProfiles,
  recordProfileFailure,
  recordProfileSuccess,
  saveModelProfile,
  type ResolvedModelProfile,
} from '../src/server/model-settings.ts'
import {
  ProviderFailureError,
  TOOL_CALL_JSON_REPAIR_HINT,
  extractUsageFromSse,
  orderProfiles,
  provider,
  providerPool,
  testProvider,
  type UsageEvent,
} from '../src/server/provider.ts'
import { inspectMorphBurstCooldown } from '../src/server/provider-stream.ts'
import { modelProfiles } from '../src/server/schema.ts'
import { Store } from '../src/server/store.ts'
import {
  disposeRunTokenTelemetry,
  getRunTokenTelemetrySummary,
  recordProviderUsageTelemetry,
} from '../src/server/token-telemetry.ts'

process.env.KOVO_ALLOW_LOCAL_MODEL = '1'

const tempDirs: string[] = []
const trackedRunIds: string[] = []

function makeTempDir(prefix: string): string {
  const dir = mkdtempSync(join(tmpdir(), prefix))
  tempDirs.push(dir)
  return dir
}

function trackRun(runId: string): string {
  trackedRunIds.push(runId)
  return runId
}

afterEach(() => {
  while (trackedRunIds.length > 0) {
    const id = trackedRunIds.pop()
    if (id) disposeRunTokenTelemetry(id)
  }
  while (tempDirs.length > 0) {
    const dir = tempDirs.pop()
    if (dir) {
      try { rmSync(dir, { recursive: true, force: true }) } catch { /* ignore cleanup error */ }
    }
  }
})

function chatSse(chunks: Record<string, unknown>[]): string {
  return chunks.map(c => `data: ${JSON.stringify(c)}\n\n`).join('') + 'data: [DONE]\n\n'
}

function responsesTextSse(text: string, usage?: { input_tokens: number; cached_tokens?: number; output_tokens: number }): string {
  const events: Record<string, unknown>[] = [
    { type: 'response.created', response: { id: 'resp_e1', status: 'in_progress' } },
    { type: 'response.output_item.added', output_index: 0, item: { type: 'message', id: 'msg_e1', role: 'assistant', content: [], status: 'in_progress' } },
    { type: 'response.output_text.delta', output_index: 0, delta: text },
    {
      type: 'response.completed',
      response: {
        id: 'resp_e1',
        status: 'completed',
        output: [{ type: 'message', id: 'msg_e1', role: 'assistant', status: 'completed', content: [{ type: 'output_text', text }] }],
        usage: {
          input_tokens: usage?.input_tokens ?? 1000,
          input_tokens_details: { cached_tokens: usage?.cached_tokens ?? 600 },
          output_tokens: usage?.output_tokens ?? 100,
        },
      },
    },
  ]
  return events.map(ev => `data: ${JSON.stringify(ev)}\n\n`).join('')
}

function makeProfile(overrides: Partial<ResolvedModelProfile> = {}): ResolvedModelProfile {
  return {
    id: overrides.id ?? 'prof-default',
    name: overrides.name ?? 'Default Profile',
    endpoint: overrides.endpoint ?? 'https://api.morphllm.com/v1',
    model: overrides.model ?? 'morph-dsv41flash-1017',
    protocol: overrides.protocol ?? 'chat-completions',
    key: overrides.key ?? 'sk-e1-fixture-secret-key-9999',
    priority: overrides.priority ?? 300,
    enabled: overrides.enabled ?? true,
    contextWindow: overrides.contextWindow ?? 1_048_576,
    maxTokens: overrides.maxTokens ?? 16_384,
    thinkingLevel: overrides.thinkingLevel ?? 'medium',
    roleAffinity: overrides.roleAffinity ?? 'any',
    inputCostPerMtok: overrides.inputCostPerMtok ?? 0,
    cachedInputCostPerMtok: overrides.cachedInputCostPerMtok ?? 0,
    outputCostPerMtok: overrides.outputCostPerMtok ?? 0,
    healthState: overrides.healthState ?? 'closed',
    cooldownUntil: overrides.cooldownUntil ?? null,
    lastError: overrides.lastError ?? null,
  }
}

describe('Track E1: chat-completions protocol & SSE parsing', () => {
  test('extractUsageFromSse parses Chat Completions prompt_tokens, cached_tokens, and completion_tokens', () => {
    const body = chatSse([
      {
        id: 'chatcmpl-1',
        object: 'chat.completion.chunk',
        model: 'deepseek-v4.1-flash',
        choices: [{ index: 0, delta: { role: 'assistant', reasoning_content: 'thinking...' }, finish_reason: null }],
      },
      {
        id: 'chatcmpl-1',
        object: 'chat.completion.chunk',
        model: 'deepseek-v4.1-flash',
        choices: [{ index: 0, delta: { content: 'OK' }, finish_reason: 'stop' }],
      },
      {
        id: 'chatcmpl-1',
        object: 'chat.completion.chunk',
        model: 'deepseek-v4.1-flash',
        choices: [],
        usage: {
          prompt_tokens: 12_000,
          completion_tokens: 450,
          prompt_tokens_details: { cached_tokens: 9_600 },
          completion_tokens_details: { reasoning_tokens: 300 },
          cost: 0,
        },
      },
    ])

    const usage = extractUsageFromSse(body, 'chat-completions')
    assert.deepEqual(usage, {
      inputTokens: 12_000,
      cachedInputTokens: 9_600,
      outputTokens: 450,
    })
  })

  test('chat-completions streams reasoning_content, text, tool_calls, redacts split secrets, and flags truncated JSON', async () => {
    const capturedUrls: string[] = []
    const capturedAuthHeaders: Array<string | null> = []
    const usageEvents: UsageEvent[] = []
    const vaultSecret = 'ULTRA_SECRET_TOKEN_XYZ_987654'

    const body = chatSse([
      {
        id: 'chatcmpl-2',
        object: 'chat.completion.chunk',
        model: 'morph-dsv41flash-1017',
        choices: [{ index: 0, delta: { role: 'assistant', reasoning_content: 'Plan step 1: ' }, finish_reason: null }],
      },
      {
        id: 'chatcmpl-2',
        object: 'chat.completion.chunk',
        model: 'morph-dsv41flash-1017',
        choices: [{ index: 0, delta: { reasoning_content: 'check ULTRA_SECRET_' }, finish_reason: null }],
      },
      {
        id: 'chatcmpl-2',
        object: 'chat.completion.chunk',
        model: 'morph-dsv41flash-1017',
        choices: [{ index: 0, delta: { reasoning_content: 'TOKEN_XYZ_987654 safely' }, finish_reason: null }],
      },
      {
        id: 'chatcmpl-2',
        object: 'chat.completion.chunk',
        model: 'morph-dsv41flash-1017',
        choices: [{ index: 0, delta: { content: 'Answer with ULTRA_SECRET_' }, finish_reason: null }],
      },
      {
        id: 'chatcmpl-2',
        object: 'chat.completion.chunk',
        model: 'morph-dsv41flash-1017',
        choices: [{ index: 0, delta: { content: 'TOKEN_XYZ_987654 done.' }, finish_reason: null }],
      },
      {
        id: 'chatcmpl-2',
        object: 'chat.completion.chunk',
        model: 'morph-dsv41flash-1017',
        choices: [{
          index: 0,
          delta: {
            tool_calls: [{ index: 0, id: 'call_cc_1', type: 'function', function: { name: 'inspect', arguments: '{"note":"ULTRA_SECRET_' } }],
          },
          finish_reason: null,
        }],
      },
      {
        id: 'chatcmpl-2',
        object: 'chat.completion.chunk',
        model: 'morph-dsv41flash-1017',
        choices: [{
          index: 0,
          delta: {
            tool_calls: [{ index: 0, function: { arguments: 'TOKEN_XYZ_987654"}' } }],
          },
          finish_reason: 'tool_calls',
        }],
      },
      {
        id: 'chatcmpl-2',
        object: 'chat.completion.chunk',
        model: 'morph-dsv41flash-1017',
        choices: [],
        usage: {
          prompt_tokens: 5_000,
          completion_tokens: 200,
          prompt_tokens_details: { cached_tokens: 4_000 },
          completion_tokens_details: { reasoning_tokens: 80 },
        },
      },
    ])

    const { models, model } = provider(
      makeProfile({ key: 'sk-morph-test-key-12345' }),
      'worker-investigation',
      {
        secrets: [{ value: vaultSecret, placeholder: '[persona:secret]' }],
        onUsage: ev => usageEvents.push(ev),
        fetch: async (url, init) => {
          capturedUrls.push(String(url))
          capturedAuthHeaders.push(new Headers(init?.headers).get('authorization'))
          return new Response(body, { status: 200, headers: { 'content-type': 'text/event-stream' } })
        },
      },
    )

    assert.equal(model.api, 'openai-completions')
    const stream = models.stream(model, {
      systemPrompt: 'Defensive QA check.',
      messages: [{ role: 'user', content: 'Run probe.', timestamp: Date.now() }],
      tools: [],
    })
    for await (const _ev of stream) { /* drain */ }
    const result = await stream.result()

    assert.deepEqual(capturedUrls, ['https://api.morphllm.com/v1/chat/completions'])
    assert.deepEqual(capturedAuthHeaders, ['Bearer sk-morph-test-key-12345'])
    assert.equal(result.stopReason, 'toolUse')

    const thinkingBlock = result.content.find(c => c.type === 'thinking')
    const textBlock = result.content.find(c => c.type === 'text')
    const toolBlock = result.content.find(c => c.type === 'toolCall')
    assert.ok(thinkingBlock && thinkingBlock.type === 'thinking')
    assert.ok(textBlock && textBlock.type === 'text')
    assert.ok(toolBlock && toolBlock.type === 'toolCall')
    assert.ok(!thinkingBlock.thinking.includes(vaultSecret), 'split secret in reasoning_content must be redacted')
    assert.ok(!textBlock.text.includes(vaultSecret), 'split secret in content must be redacted')
    assert.equal(toolBlock.name, 'inspect')
    assert.ok(!JSON.stringify(toolBlock.arguments).includes(vaultSecret), 'split secret in tool_calls arguments must be redacted')
    assert.equal(usageEvents.length, 1)
    assert.equal(usageEvents[0]!.inputTokens, 5_000)
    assert.equal(usageEvents[0]!.cachedInputTokens, 4_000)
    assert.equal(usageEvents[0]!.outputTokens, 200)
    assert.equal(usageEvents[0]!.reasoningTokens, 80)

    // Truncated tool-call JSON on chat-completions (finish_reason: 'length') -> repair hint attached
    const truncatedBody = chatSse([
      {
        id: 'chatcmpl-trunc',
        object: 'chat.completion.chunk',
        model: 'morph-dsv41flash-1017',
        choices: [{
          index: 0,
          delta: {
            role: 'assistant',
            tool_calls: [{ index: 0, id: 'call_trunc', type: 'function', function: { name: 'run_script', arguments: '{"script":"console.log(1' } }],
          },
          finish_reason: 'length',
        }],
      },
    ])
    const { models: truncModels, model: truncModel } = provider(
      makeProfile(),
      'worker-investigation',
      {
        fetch: async () => new Response(truncatedBody, { status: 200, headers: { 'content-type': 'text/event-stream' } }),
      },
    )
    const truncStream = truncModels.stream(truncModel, {
      systemPrompt: 'Check truncation.',
      messages: [{ role: 'user', content: 'Go.', timestamp: Date.now() }],
      tools: [],
    })
    for await (const _ev of truncStream) { /* drain */ }
    const truncResult = await truncStream.result()
    const truncTool = truncResult.content.find(c => c.type === 'toolCall')
    assert.ok(truncTool && truncTool.type === 'toolCall')
    assert.ok(
      typeof truncTool.argumentsError === 'string' && truncTool.argumentsError.includes(TOOL_CALL_JSON_REPAIR_HINT),
      `expected repair hint on truncated chat-completions toolCall, got ${String(truncTool.argumentsError)}`,
    )
  })

  test('testProvider succeeds over chat-completions protocol', async () => {
    let seenUrl = ''
    const ok = await testProvider(
      makeProfile({
        endpoint: 'https://opencode.ai/inference/go/openai/v1',
        model: 'deepseek-v4.1-flash',
        protocol: 'chat-completions',
      }),
      undefined,
      {
        fetch: async url => {
          seenUrl = String(url)
          return new Response(
            chatSse([
              {
                id: 'chatcmpl-conn',
                object: 'chat.completion.chunk',
                model: 'deepseek-v4.1-flash',
                choices: [{
                  index: 0,
                  delta: {
                    role: 'assistant',
                    tool_calls: [{ index: 0, id: 'call_conn', type: 'function', function: { name: 'kovo_connection', arguments: '{"status":"ready"}' } }],
                  },
                  finish_reason: 'tool_calls',
                }],
              },
            ]),
            { status: 200, headers: { 'content-type': 'text/event-stream' } },
          )
        },
      },
    )
    assert.deepEqual(ok, { ok: true })
    assert.equal(seenUrl, 'https://opencode.ai/inference/go/openai/v1/chat/completions')
  })
})

describe('Track E1: sessionId, prompt_cache_key, x-session-id & x-opencode-session', () => {
  test('populates model.compat, prompt_cache_key, x-session-id, and host-scoped x-opencode-session', async () => {
    const cases: Array<{
      label: string
      profile: ResolvedModelProfile
      expectedAffinity: 'openai' | 'openrouter'
      expectOpencodeHeader: boolean
      sessionIdOpt?: string
      streamSessionId?: string
      expectedSessionId: string
    }> = [
      {
        label: 'OpenCode Go chat-completions (options.sessionId)',
        profile: makeProfile({
          id: 'oc-1',
          endpoint: 'https://opencode.ai/inference/go/openai/v1',
          model: 'deepseek-v4.1-flash',
          protocol: 'chat-completions',
        }),
        expectedAffinity: 'openai',
        expectOpencodeHeader: true,
        sessionIdOpt: 'sess-opencode-abc',
        expectedSessionId: 'sess-opencode-abc',
      },
      {
        label: 'Morph Ultra chat-completions (sOpts.sessionId overrides options.sessionId)',
        profile: makeProfile({
          id: 'morph-1',
          endpoint: 'https://api.morphllm.com/v1',
          model: 'morph-dsv41flash-1017',
          protocol: 'chat-completions',
        }),
        expectedAffinity: 'openai',
        expectOpencodeHeader: false,
        sessionIdOpt: 'sess-default',
        streamSessionId: 'sess-override-morph',
        expectedSessionId: 'sess-override-morph',
      },
      {
        label: 'OpenRouter responses',
        profile: makeProfile({
          id: 'or-1',
          endpoint: 'https://openrouter.ai/api/v1',
          model: 'deepseek/deepseek-v4.1-flash-1017',
          protocol: 'responses',
        }),
        expectedAffinity: 'openrouter',
        expectOpencodeHeader: false,
        sessionIdOpt: 'sess-openrouter-xyz',
        expectedSessionId: 'sess-openrouter-xyz',
      },
    ]

    for (const tc of cases) {
      let seenHeaders: Headers | null = null
      let seenBody: Record<string, unknown> | null = null

      const { models, model } = provider(tc.profile, 'worker-investigation', {
        sessionId: tc.sessionIdOpt,
        fetch: async (_url, init) => {
          seenHeaders = new Headers(init?.headers)
          seenBody = JSON.parse(String(init?.body ?? '{}')) as Record<string, unknown>
          const body = tc.profile.protocol === 'responses'
            ? responsesTextSse('ok')
            : chatSse([
                {
                  id: 'c-1',
                  object: 'chat.completion.chunk',
                  model: tc.profile.model,
                  choices: [{ index: 0, delta: { role: 'assistant', content: 'ok' }, finish_reason: 'stop' }],
                },
              ])
          return new Response(body, { status: 200, headers: { 'content-type': 'text/event-stream' } })
        },
      })

      const compat = model.compat as Record<string, unknown> | undefined
      assert.equal(compat?.promptCacheKeyMode, 'enabled', `${tc.label}: promptCacheKeyMode`)
      assert.equal(compat?.sendSessionAffinityHeaders, true, `${tc.label}: sendSessionAffinityHeaders`)
      assert.equal(compat?.sessionAffinityFormat, tc.expectedAffinity, `${tc.label}: sessionAffinityFormat`)

      const stream = models.stream(
        model,
        {
          systemPrompt: 'Cache affinity check.',
          messages: [{ role: 'user', content: 'Hello.', timestamp: Date.now() }],
          tools: [],
        },
        tc.streamSessionId ? { sessionId: tc.streamSessionId } : undefined,
      )
      for await (const _ev of stream) { /* drain */ }
      await stream.result()

      assert.ok(seenHeaders !== null && seenBody !== null)
      const headersObj = seenHeaders as Headers
      const bodyObj = seenBody as Record<string, unknown>
      assert.equal(bodyObj.prompt_cache_key, tc.expectedSessionId, `${tc.label}: prompt_cache_key`)
      assert.equal(headersObj.get('x-session-id'), tc.expectedSessionId, `${tc.label}: x-session-id`)
      if (tc.expectOpencodeHeader) {
        assert.equal(headersObj.get('x-opencode-session'), tc.expectedSessionId, `${tc.label}: x-opencode-session`)
      } else {
        assert.equal(headersObj.get('x-opencode-session'), null, `${tc.label}: must not set x-opencode-session off opencode.ai`)
      }
    }
  })
})

describe('Track E1: 3-tier priority failover, streak-1 429 cooldown & Morph burst headers', () => {
  test('streak-1 HTTP 429 with Retry-After immediately opens tier 300 and routes next turn directly to tier 200, then recovers', async () => {
    const dir = makeTempDir('kovo-e1-failover-')
    const storage = new Store(dir, { autoRecover: false })
    try {
      const p300 = await saveModelProfile({
        name: 'Morph Ultra DeepSeek V4.1 Flash',
        endpoint: 'https://api.morphllm.com/v1',
        model: 'morph-dsv41flash-1017',
        protocol: 'chat-completions',
        key: 'sk-morph-key-111111',
        priority: 300,
        inputCostPerMtok: 0,
        cachedInputCostPerMtok: 0,
        outputCostPerMtok: 0,
      }, storage, { skipConnectionCheck: true })

      const p200 = await saveModelProfile({
        name: 'OpenCode Go DeepSeek V4.1 Flash',
        endpoint: 'https://opencode.ai/inference/go/openai/v1',
        model: 'deepseek-v4.1-flash',
        protocol: 'chat-completions',
        key: 'sk-opencode-key-222222',
        priority: 200,
        inputCostPerMtok: 0,
        cachedInputCostPerMtok: 0,
        outputCostPerMtok: 0,
      }, storage, { skipConnectionCheck: true })

      const p100 = await saveModelProfile({
        name: 'OpenRouter DeepSeek V4.1 Flash',
        endpoint: 'https://openrouter.ai/api/v1',
        model: 'deepseek/deepseek-v4.1-flash-1017',
        protocol: 'responses',
        key: 'sk-openrouter-key-333333',
        priority: 100,
        inputCostPerMtok: 0.15,
        cachedInputCostPerMtok: 0.003,
        outputCostPerMtok: 0.6,
      }, storage, { skipConnectionCheck: true })

      const runId = trackRun('run-e1-3tier-failover')
      const hitHosts: string[] = []
      const failureCallbacks: Array<{ id: string; hard: boolean; kind?: string; retryAfterMs?: number | null }> = []
      let opencodeShould429 = false

      const fetchStub: typeof fetch = async url => {
        const host = new URL(String(url)).hostname
        hitHosts.push(host)
        if (host === 'api.morphllm.com') {
          return new Response(
            JSON.stringify({ error: { message: 'Morph Ultra rate limit reached' } }),
            { status: 429, headers: { 'content-type': 'application/json', 'retry-after': '30' } },
          )
        }
        if (host === 'opencode.ai') {
          if (opencodeShould429) {
            return new Response(
              JSON.stringify({ error: { message: 'OpenCode Go busy' } }),
              { status: 429, headers: { 'content-type': 'application/json' } },
            )
          }
          return new Response(
            chatSse([
              {
                id: 'oc-ok',
                object: 'chat.completion.chunk',
                model: 'deepseek-v4.1-flash',
                choices: [{ index: 0, delta: { role: 'assistant', content: 'from-opencode' }, finish_reason: 'stop' }],
              },
              {
                id: 'oc-ok',
                object: 'chat.completion.chunk',
                model: 'deepseek-v4.1-flash',
                choices: [],
                usage: {
                  prompt_tokens: 1_000,
                  completion_tokens: 100,
                  prompt_tokens_details: { cached_tokens: 800 },
                  cost: 0,
                },
              },
            ]),
            { status: 200, headers: { 'content-type': 'text/event-stream' } },
          )
        }
        return new Response(
          responsesTextSse('from-openrouter', { input_tokens: 2_000, cached_tokens: 1_000, output_tokens: 200 }),
          { status: 200, headers: { 'content-type': 'text/event-stream' } },
        )
      }

      const profiles = privateModelProfiles(storage)
      assert.deepEqual(profiles.map(p => p.id), [p300.id, p200.id, p100.id])

      const { models, model } = providerPool(profiles, 'worker-investigation', {
        runId,
        sessionId: 'sess-3tier',
        fetch: fetchStub,
        maxTransportRetries: 0,
        onProfileFailure: (id, err, hard, meta) => {
          failureCallbacks.push({ id, hard, kind: meta?.kind, retryAfterMs: meta?.retryAfterMs })
          recordProfileFailure(id, err, hard, storage)
        },
        onProfileSuccess: id => recordProfileSuccess(id, storage),
      })

      // Turn 1: hits Morph (300) -> 429 Retry-After: 30 -> fails over to OpenCode Go (200)
      const s1 = models.stream(model, {
        systemPrompt: 'Turn 1',
        messages: [{ role: 'user', content: 'Hello 1', timestamp: Date.now() }],
        tools: [],
      })
      for await (const _ev of s1) { /* drain */ }
      const r1 = await s1.result()
      assert.equal(r1.stopReason, 'stop')
      assert.deepEqual(hitHosts, ['api.morphllm.com', 'opencode.ai'])
      assert.equal(failureCallbacks.length, 1)
      assert.equal(failureCallbacks[0]!.id, p300.id)
      assert.equal(failureCallbacks[0]!.hard, false)
      assert.equal(failureCallbacks[0]!.kind, 'rate_limited')
      assert.equal(failureCallbacks[0]!.retryAfterMs, 30_000)

      // Persisted state: tier 300 MUST be 'open' on streak 1 with ~30s cooldown!
      const afterTurn1 = privateModelProfiles(storage)
      const morphAfter1 = afterTurn1.find(p => p.id === p300.id)!
      assert.equal(morphAfter1.healthState, 'open')
      assert.ok(morphAfter1.cooldownUntil !== null)
      const deltaMs = morphAfter1.cooldownUntil - Date.now()
      assert.ok(deltaMs >= 25_000 && deltaMs <= 31_000, `expected ~30s cooldown, got ${deltaMs}ms`)
      assert.equal(isProfileHealthy(morphAfter1), false)
      assert.deepEqual(orderProfiles(afterTurn1, 1000).map(p => p.id), [p200.id, p100.id])

      // Turn 2 on SAME providerPool: bypasses tier 300 directly -> goes straight to tier 200!
      hitHosts.length = 0
      const s2 = models.stream(model, {
        systemPrompt: 'Turn 2',
        messages: [{ role: 'user', content: 'Hello 2', timestamp: Date.now() }],
        tools: [],
      })
      for await (const _ev of s2) { /* drain */ }
      await s2.result()
      assert.deepEqual(hitHosts, ['opencode.ai'], 'Turn 2 must skip cooled-down tier 300 directly')

      // Turn 3: tier 200 also 429s -> fails over cleanly to tier 100 (OpenRouter responses)
      opencodeShould429 = true
      hitHosts.length = 0
      const s3 = models.stream(model, {
        systemPrompt: 'Turn 3',
        messages: [{ role: 'user', content: 'Hello 3', timestamp: Date.now() }],
        tools: [],
      })
      for await (const _ev of s3) { /* drain */ }
      const r3 = await s3.result()
      assert.equal(r3.stopReason, 'stop')
      assert.deepEqual(hitHosts, ['opencode.ai', 'openrouter.ai'])

      // Tier 200 is also 'open' on streak 1 with 15s default cooldown (no Retry-After)
      const ocAfter3 = privateModelProfiles(storage).find(p => p.id === p200.id)!
      assert.equal(ocAfter3.healthState, 'open')
      assert.ok(ocAfter3.cooldownUntil !== null)
      const ocDelta = ocAfter3.cooldownUntil - Date.now()
      assert.ok(ocDelta >= 10_000 && ocDelta <= 16_000, `expected ~15s default cooldown, got ${ocDelta}ms`)

      // Verify per-provider telemetry breakdown across all 3 tiers!
      const summary = getRunTokenTelemetrySummary(runId)
      assert.ok(summary.providerBreakdown['Morph Ultra DeepSeek V4.1 Flash'])
      assert.equal(summary.providerBreakdown['Morph Ultra DeepSeek V4.1 Flash'].retries, 1)
      assert.ok(summary.providerBreakdown['OpenCode Go DeepSeek V4.1 Flash'])
      assert.equal(summary.providerBreakdown['OpenCode Go DeepSeek V4.1 Flash'].calls, 3) // 2 ok + 1 retried
      assert.equal(summary.providerBreakdown['OpenCode Go DeepSeek V4.1 Flash'].retries, 1)
      assert.equal(summary.providerBreakdown['OpenCode Go DeepSeek V4.1 Flash'].inputTokens, 2_000)
      assert.equal(summary.providerBreakdown['OpenCode Go DeepSeek V4.1 Flash'].cachedInputTokens, 1_600)
      assert.ok(Math.abs(summary.providerBreakdown['OpenCode Go DeepSeek V4.1 Flash'].cacheHitRate - 0.8) < 1e-9)
      assert.equal(summary.providerBreakdown['OpenCode Go DeepSeek V4.1 Flash'].costUsd, 0)
      assert.ok(summary.providerBreakdown['OpenRouter DeepSeek V4.1 Flash'])
      assert.equal(summary.providerBreakdown['OpenRouter DeepSeek V4.1 Flash'].calls, 1)
      assert.equal(summary.providerBreakdown['OpenRouter DeepSeek V4.1 Flash'].inputTokens, 2_000)
      assert.equal(summary.providerBreakdown['OpenRouter DeepSeek V4.1 Flash'].cachedInputTokens, 1_000)
      assert.ok(Math.abs(summary.providerBreakdown['OpenRouter DeepSeek V4.1 Flash'].cacheHitRate - 0.5) < 1e-9)
      assert.ok(summary.providerBreakdown['OpenRouter DeepSeek V4.1 Flash'].costUsd > 0)

      // Cooldown expiration auto-recovers tier 300 via open -> half_open
      storage.db.update(modelProfiles).set({ cooldownUntil: Date.now() - 1000 })
        .where(eq(modelProfiles.id, p300.id)).run()
      const recoveredProfiles = privateModelProfiles(storage)
      const morphRecovered = recoveredProfiles.find(p => p.id === p300.id)!
      assert.equal(morphRecovered.healthState, 'half_open')
      assert.equal(isProfileHealthy(morphRecovered), true)
      assert.equal(orderProfiles(recoveredProfiles, 1000)[0]!.id, p300.id)

      // Non-429 transient failure (HTTP 503) still keeps streak-1 half_open
      recordProfileSuccess(p100.id, storage)
      recordProfileFailure(
        p100.id,
        new ProviderFailureError('Service unavailable', { kind: 'server', status: 503 }),
        false,
        storage,
      )
      const serverFail = privateModelProfiles(storage).find(p => p.id === p100.id)!
      assert.equal(serverFail.healthState, 'half_open')
    } finally {
      storage.close()
    }
  })

  test('Morph Ultra steady + burst headers use burst reserve when burst > 0 and trigger proactive cooldown when both <= 0', async () => {
    // Unit checks on inspectMorphBurstCooldown
    assert.equal(
      inspectMorphBurstCooldown(new Headers({
        'x-morph-ultra-uncached-input-remaining': '0',
        'x-morph-ultra-uncached-input-burst-remaining': '900000',
        'x-morph-ultra-uncached-input-burst-reset': '20',
      })),
      null,
      'must NOT cool down while burst reserve is still positive',
    )
    const bothZero = inspectMorphBurstCooldown(new Headers({
      'x-morph-ultra-uncached-input-remaining': '0',
      'x-morph-ultra-uncached-input-burst-remaining': '0',
      'x-morph-ultra-uncached-input-burst-reset': '25',
    }))
    assert.ok(bothZero !== null)
    assert.equal(bothZero.retryAfterMs, 25_000)

    const outputExhaustedDefault = inspectMorphBurstCooldown(new Headers({
      'x-morph-ultra-output-remaining': '0',
      'x-morph-ultra-output-burst-remaining': '0',
    }))
    assert.ok(outputExhaustedDefault !== null)
    assert.equal(outputExhaustedDefault.retryAfterMs, 15_000)

    // End-to-end 2xx proactive cooldown in providerPool
    const dir = makeTempDir('kovo-e1-morph-burst-')
    const storage = new Store(dir, { autoRecover: false })
    try {
      const p300 = await saveModelProfile({
        name: 'Morph Ultra',
        endpoint: 'https://api.morphllm.com/v1',
        model: 'morph-dsv41flash-1017',
        protocol: 'chat-completions',
        key: 'sk-morph-burst-key-1111',
        priority: 300,
        inputCostPerMtok: 0,
        cachedInputCostPerMtok: 0,
        outputCostPerMtok: 0,
      }, storage, { skipConnectionCheck: true })
      const p200 = await saveModelProfile({
        name: 'OpenCode Go',
        endpoint: 'https://opencode.ai/inference/go/openai/v1',
        model: 'deepseek-v4.1-flash',
        protocol: 'chat-completions',
        key: 'sk-opencode-burst-key-2222',
        priority: 200,
        inputCostPerMtok: 0,
        cachedInputCostPerMtok: 0,
        outputCostPerMtok: 0,
      }, storage, { skipConnectionCheck: true })

      const calls: string[] = []
      let morphCallNo = 0
      const { models, model } = providerPool(privateModelProfiles(storage), 'worker-investigation', {
        fetch: async url => {
          const host = new URL(String(url)).hostname
          calls.push(host)
          const headers: Record<string, string> = { 'content-type': 'text/event-stream' }
          if (host === 'api.morphllm.com') {
            morphCallNo += 1
            if (morphCallNo === 1) {
              // Steady=0, Burst=500000 -> keep using Morph!
              headers['x-morph-ultra-uncached-input-remaining'] = '0'
              headers['x-morph-ultra-uncached-input-burst-remaining'] = '500000'
              headers['x-morph-ultra-uncached-input-burst-reset'] = '20'
            } else {
              // Both Steady=0 and Burst=0 -> trigger proactive 22s cooldown AFTER this 200 completes!
              headers['x-morph-ultra-uncached-input-remaining'] = '0'
              headers['x-morph-ultra-uncached-input-burst-remaining'] = '0'
              headers['x-morph-ultra-uncached-input-burst-reset'] = '22'
            }
          }
          return new Response(
            chatSse([{
              id: `c-${calls.length}`,
              object: 'chat.completion.chunk',
              model: 'morph-dsv41flash-1017',
              choices: [{ index: 0, delta: { role: 'assistant', content: `ok-${calls.length}` }, finish_reason: 'stop' }],
            }]),
            { status: 200, headers },
          )
        },
        onProfileFailure: (id, err, hard) => recordProfileFailure(id, err, hard, storage),
        onProfileSuccess: id => recordProfileSuccess(id, storage),
      })

      // Turn 1: Morph steady=0, burst=500000 -> succeeds and stays closed
      const t1 = models.stream(model, { systemPrompt: 's', messages: [{ role: 'user', content: '1', timestamp: Date.now() }], tools: [] })
      for await (const _e of t1) { /* drain */ }
      await t1.result()
      assert.equal(privateModelProfiles(storage).find(p => p.id === p300.id)?.healthState, 'closed')

      // Turn 2: Still hits Morph! Now both steady=0 & burst=0 -> succeeds AND proactively opens Morph for ~22s
      const t2 = models.stream(model, { systemPrompt: 's', messages: [{ role: 'user', content: '2', timestamp: Date.now() }], tools: [] })
      for await (const _e of t2) { /* drain */ }
      await t2.result()
      const morphAfter2 = privateModelProfiles(storage).find(p => p.id === p300.id)!
      assert.equal(morphAfter2.healthState, 'open')
      assert.ok(morphAfter2.cooldownUntil !== null)
      const coolDelta = morphAfter2.cooldownUntil - Date.now()
      assert.ok(coolDelta >= 18_000 && coolDelta <= 23_000, `expected ~22s burst cooldown, got ${coolDelta}ms`)

      // Turn 3: Automatically routes straight to OpenCode Go (tier 200) without hitting Morph!
      const t3 = models.stream(model, { systemPrompt: 's', messages: [{ role: 'user', content: '3', timestamp: Date.now() }], tools: [] })
      for await (const _e of t3) { /* drain */ }
      await t3.result()
      assert.deepEqual(calls, ['api.morphllm.com', 'api.morphllm.com', 'opencode.ai'])
      assert.equal(privateModelProfiles(storage).find(p => p.id === p200.id)?.healthState, 'closed')
    } finally {
      storage.close()
    }
  })
})

describe('Track E1: providerBreakdown telemetry & key-safe configure-model-pool CLI', () => {
  test('getRunTokenTelemetrySummary aggregates providerBreakdown accurately per provider', () => {
    const runId = trackRun('run-e1-provider-breakdown')
    recordProviderUsageTelemetry({
      runId,
      profileId: 'p-morph',
      providerName: 'Morph Ultra',
      model: 'morph-dsv41flash-1017',
      inputTokens: 10_000,
      cachedInputTokens: 9_000,
      outputTokens: 500,
      costUsd: 0,
      outcome: 'ok',
    })
    recordProviderUsageTelemetry({
      runId,
      profileId: 'p-morph',
      providerName: 'Morph Ultra',
      model: 'morph-dsv41flash-1017',
      costUsd: 0,
      outcome: 'stalled',
      stalled: true,
    })
    recordProviderUsageTelemetry({
      runId,
      profileId: 'p-morph',
      providerName: 'Morph Ultra',
      model: 'morph-dsv41flash-1017',
      costUsd: 0,
      outcome: 'retried',
      retried: true,
      countCall: false,
    })
    recordProviderUsageTelemetry({
      runId,
      profileId: 'p-or',
      providerName: 'OpenRouter',
      model: 'deepseek/deepseek-v4.1-flash-1017',
      inputTokens: 4_000,
      cachedInputTokens: 1_000,
      outputTokens: 200,
      costUsd: 0.002,
      outcome: 'ok',
    })

    const summary = getRunTokenTelemetrySummary(runId)
    assert.deepEqual(summary.providerBreakdown['Morph Ultra'], {
      calls: 2,
      retries: 1,
      stalls: 1,
      inputTokens: 10_000,
      cachedInputTokens: 9_000,
      outputTokens: 500,
      costUsd: 0,
      cacheHitRate: 0.9,
    })
    assert.deepEqual(summary.providerBreakdown['OpenRouter'], {
      calls: 1,
      retries: 0,
      stalls: 0,
      inputTokens: 4_000,
      cachedInputTokens: 1_000,
      outputTokens: 200,
      costUsd: 0.002,
      cacheHitRate: 0.25,
    })
  })

  test('configureModelPool idempotently upserts Morph (300) + OpenCode Go (200) alongside OpenRouter (100) with mode-0600 safety', async () => {
    const dataDir = makeTempDir('kovo-e1-pool-cli-')
    const keyDir = makeTempDir('kovo-e1-keys-')
    const morphKey = 'sk-morph-super-secret-value-111111'
    const opencodeKey = 'sk-opencode-super-secret-value-222222'
    const morphKeyFile = join(keyDir, 'morph.key')
    const opencodeKeyFile = join(keyDir, 'opencode-go.key')
    writeFileSync(morphKeyFile, morphKey + '\n', { mode: 0o600 })
    writeFileSync(opencodeKeyFile, opencodeKey + '\n', { mode: 0o600 })

    // Seed existing OpenRouter profile (priority 100)
    const seedStore = new Store(dataDir, { autoRecover: false })
    try {
      await saveModelProfile({
        name: 'OpenRouter DeepSeek V4.1 Flash',
        endpoint: 'https://openrouter.ai/api/v1',
        model: 'deepseek/deepseek-v4.1-flash-1017',
        protocol: 'responses',
        key: 'sk-openrouter-existing-333333',
        priority: 100,
      }, seedStore, { skipConnectionCheck: true })
    } finally {
      seedStore.close()
    }

    // First run creates both profiles
    const res1 = await configureModelPool({ dataDir, morphKeyFile, opencodeKeyFile })
    assert.equal(res1.upserted.length, 2)
    assert.deepEqual(res1.upserted.map(u => u.action), ['created', 'created'])
    assert.equal(res1.profiles.length, 3)
    assert.deepEqual(
      res1.profiles.map(p => ({ name: p.name, priority: p.priority, protocol: p.protocol, model: p.model })),
      [
        { name: 'Morph Ultra DeepSeek V4.1 Flash', priority: 300, protocol: 'chat-completions', model: 'morph-dsv41flash-1017' },
        { name: 'OpenCode Go DeepSeek V4.1 Flash', priority: 200, protocol: 'chat-completions', model: 'deepseek-v4.1-flash' },
        { name: 'OpenRouter DeepSeek V4.1 Flash', priority: 100, protocol: 'responses', model: 'deepseek/deepseek-v4.1-flash-1017' },
      ],
    )

    // Summary output must NEVER contain any API key
    const table = formatPoolSummaryTable(res1)
    assert.ok(!table.includes(morphKey))
    assert.ok(!table.includes(opencodeKey))
    assert.ok(!table.includes('sk-openrouter-existing-333333'))

    // Second run is idempotent (updates in place, still 3 profiles)
    const res2 = await configureModelPool({ dataDir, morphKeyFile, opencodeKeyFile })
    assert.deepEqual(res2.upserted.map(u => u.action), ['updated', 'updated'])
    assert.equal(res2.profiles.length, 3)

    // Verify stored credential files are mode 0600 and load cleanly via privateModelProfiles
    const checkStore = new Store(dataDir, { autoRecover: false })
    try {
      const loaded = privateModelProfiles(checkStore)
      assert.equal(loaded.length, 3)
      assert.equal(loaded[0]!.key, morphKey)
      assert.equal(loaded[1]!.key, opencodeKey)
      assert.equal(loaded[0]!.contextWindow, 1_048_576)
      assert.equal(loaded[0]!.thinkingLevel, 'medium')
      assert.equal(loaded[0]!.inputCostPerMtok, 0)
      assert.equal(loaded[1]!.inputCostPerMtok, 0)
      const credDirSt = statSync(join(dataDir, 'credentials'))
      assert.equal(credDirSt.mode & 0o077, 0)
    } finally {
      checkStore.close()
    }

    // Reject world-readable key file (mode 0644)
    chmodSync(morphKeyFile, 0o644)
    await assert.rejects(
      () => configureModelPool({ dataDir, morphKeyFile, opencodeKeyFile }),
      /owner-only permissions/i,
    )
  })
})
