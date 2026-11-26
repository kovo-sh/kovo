/**
 * R2-21: Provider runtime policy, unified `providerOptionsFor`, pricing truth,
 * abort-path output cost estimation, split `stallAborts` vs `slowTurns`, and
 * record-only `costPerConfirmed` / `wastedUsd` ledger fields.
 */
import assert from 'node:assert/strict'
import { mkdtempSync, readFileSync, readdirSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import { describe, test } from 'node:test'
import { eq } from 'drizzle-orm'

import { DEFAULT_PROVIDER } from '../src/domain.ts'
import {
  CONSERVATIVE_FALLBACK_PRICING,
  DEFAULT_NO_TOKEN_WATCHDOG_MS,
  MEDIUM_THINKING_NO_TOKEN_WATCHDOG_MS,
  REASONING_NO_TOKEN_WATCHDOG_MS,
  isDefaultFlashModel,
  providerOptionsFor,
  resolveProfilePricing,
  resolveProviderRuntimePolicy,
  type ProviderRuntimePolicy,
} from '../src/server/provider-runtime-policy.ts'
import {
  createProviderStreamTelemetry,
  resolveProfileNoTokenWatchdogMs,
} from '../src/server/provider-stream.ts'
import {
  estimateCostUsd,
  providerPool,
  type UsageEvent,
} from '../src/server/provider.ts'
import {
  checkModelConnection,
  privateModelProfiles,
  saveModelProfile,
  type ResolvedModelProfile,
} from '../src/server/model-settings.ts'
import { modelProfiles } from '../src/server/schema.ts'
import {
  disposeRunTokenTelemetry,
  getRunTokenTelemetrySummary,
  type ProviderUsageTelemetryInput,
} from '../src/server/token-telemetry.ts'
import {
  LEDGER_SCHEMA_VERSION,
  appendLedgerRow,
  compareLedgerRows,
  computeCostPerConfirmed,
  readLedgerRows,
  type LedgerRow,
} from '../scripts/bench-ledger.ts'
import { makeStore } from './v4-tier-helpers.ts'

process.env.KOVO_ALLOW_LOCAL_MODEL = '1'

function makeProfile(overrides: Partial<ResolvedModelProfile> = {}): ResolvedModelProfile {
  return {
    id: overrides.id ?? 'prof-r2-21',
    name: overrides.name ?? 'R2-21 Fixture',
    endpoint: overrides.endpoint ?? 'http://127.0.0.1:18080/v1',
    model: overrides.model ?? 'fixture-model-v1',
    protocol: overrides.protocol ?? 'responses',
    key: overrides.key ?? 'fixture-key-123456',
    enabled: overrides.enabled ?? true,
    priority: overrides.priority ?? 100,
    contextWindow: overrides.contextWindow ?? 128_000,
    maxTokens: overrides.maxTokens ?? 4_096,
    thinkingLevel: overrides.thinkingLevel ?? 'off',
    roleAffinity: overrides.roleAffinity ?? 'any',
    inputCostPerMtok: overrides.inputCostPerMtok ?? 1.0,
    cachedInputCostPerMtok: overrides.cachedInputCostPerMtok ?? 0.25,
    outputCostPerMtok: overrides.outputCostPerMtok ?? 4.0,
    healthState: overrides.healthState ?? 'closed',
    cooldownUntil: overrides.cooldownUntil ?? null,
    lastError: overrides.lastError ?? null,
  }
}

function responsesSse(eventsList: Record<string, unknown>[]): string {
  return eventsList.map(ev => `data: ${JSON.stringify(ev)}\n\n`).join('')
}

function makeLedgerRow(overrides: Partial<LedgerRow> = {}): LedgerRow {
  return {
    schemaVersion: LEDGER_SCHEMA_VERSION,
    recordedAt: '2026-11-26T00:00:00.000Z',
    suite: 'realistic-bench',
    gitSha: 'abc123456789',
    dirty: false,
    benchmarkVersion: 'a'.repeat(64),
    effectiveConfigHash: 'b'.repeat(64),
    app: 'acme-saas',
    split: 'dev',
    mode: 'grey-box',
    llm: 'agentic',
    seed: 1,
    repeat: 1,
    certifying: true,
    reportable: true,
    status: 'VALID',
    targets: 20,
    confirmed: 10,
    recall: 0.5,
    rawPrecision: 1,
    strictPrecision: 1,
    precision: 1,
    decoyFalsePositives: 0,
    unmatchedFalsePositives: 0,
    costUsd: 2.5,
    durationMs: 15_000,
    ...overrides,
  }
}

// ============================================================================
// 1. PR-21a: ProviderRuntimePolicy from explicit fields, failover recompute,
//    no model-name regexes, split stallAborts vs slowTurns
// ============================================================================

describe('R2-21a: ProviderRuntimePolicy explicit fields, per-failover recompute, split stream telemetry', () => {
  test('provider-stream.ts deletes hardcoded model-name regexes and derives watchdog tiers solely from explicit fields', () => {
    const streamSource = readFileSync(resolve('src/server/provider-stream.ts'), 'utf8')
    assert.equal(/REASONING_MODEL_RE/.test(streamSource), false, 'hardcoded model-name regex must be deleted')
    assert.equal(/deepseek-v4/.test(streamSource), false, 'hardcoded model family name must not appear in provider-stream.ts')

    // Model name alone NEVER escalates timeout tier without explicit thinkingLevel / roleAffinity
    const flashOff = resolveProviderRuntimePolicy(
      { model: 'deepseek/deepseek-v4.1-flash-1017', thinkingLevel: 'off', roleAffinity: 'fast', contextWindow: 1_048_576, maxTokens: 16_384 },
      { env: {} },
    )
    assert.equal(flashOff.timeoutTier, 'fast')
    assert.equal(flashOff.noTokenWatchdogMs, DEFAULT_NO_TOKEN_WATCHDOG_MS)
    assert.equal(resolveProfileNoTokenWatchdogMs({ model: 'openai/o3-reasoner', thinkingLevel: 'off', roleAffinity: 'fast' }, {}), DEFAULT_NO_TOKEN_WATCHDOG_MS)

    // Explicit thinkingLevel=medium -> medium tier (45s) regardless of model name
    const med = resolveProviderRuntimePolicy(
      { model: 'deepseek/deepseek-v4.1-flash-1017', thinkingLevel: 'medium', roleAffinity: 'tactical' },
      { env: {} },
    )
    assert.equal(med.timeoutTier, 'medium')
    assert.equal(med.noTokenWatchdogMs, MEDIUM_THINKING_NO_TOKEN_WATCHDOG_MS)

    // Explicit thinkingLevel=high or roleAffinity=reasoning -> reasoning tier (60s) for any model name
    const highCustom = resolveProviderRuntimePolicy(
      { model: 'opaque-internal-model', thinkingLevel: 'high', roleAffinity: 'tactical', contextWindow: 200_000, maxTokens: 8_192 },
      { env: {} },
    )
    assert.equal(highCustom.timeoutTier, 'reasoning')
    assert.equal(highCustom.reasoningCapable, true)
    assert.equal(highCustom.noTokenWatchdogMs, REASONING_NO_TOKEN_WATCHDOG_MS)

    // Compaction reserve is derived per profile contextWindow/maxTokens (never hardcoded to 1M primary)
    const smallCtx = resolveProviderRuntimePolicy({ model: 'small-32k', contextWindow: 32_000, maxTokens: 4_096 }, { env: {} })
    const largeCtx = resolveProviderRuntimePolicy({ model: 'large-1m', contextWindow: 1_048_576, maxTokens: 16_384 }, { env: {} })
    assert.ok(smallCtx.compactionReserveTokens < largeCtx.compactionReserveTokens, 'smaller context window must yield smaller compaction reserve')
    assert.ok(smallCtx.compactionReserveTokens <= Math.floor(32_000 * 0.35), 'compaction reserve must stay bounded to candidate window')
  })

  test('providerPool recomputes ProviderRuntimePolicy per failover candidate', async () => {
    const fastPrimary = makeProfile({
      id: 'prof-fast-128k',
      model: 'fast-128k',
      priority: 100,
      contextWindow: 128_000,
      maxTokens: 4_096,
      thinkingLevel: 'off',
      roleAffinity: 'fast',
      inputCostPerMtok: 0.5,
      cachedInputCostPerMtok: 0.1,
      outputCostPerMtok: 1.5,
    })
    const reasoningBackup = makeProfile({
      id: 'prof-reason-256k',
      model: 'reason-256k',
      priority: 50,
      contextWindow: 256_000,
      maxTokens: 16_384,
      thinkingLevel: 'high',
      roleAffinity: 'reasoning',
      inputCostPerMtok: 5.0,
      cachedInputCostPerMtok: 1.0,
      outputCostPerMtok: 20.0,
    })

    const observedPolicies: ProviderRuntimePolicy[] = []
    let calls = 0
    const { models, model } = providerPool(
      [fastPrimary, reasoningBackup],
      'dedupe-judge',
      providerOptionsFor({ id: 'run-failover-policy' }, 'fast', 'dedupe-judge', {
        profile: fastPrimary,
        maxTransportRetries: 0,
        transportRetryBaseMs: 0,
        onCandidatePolicy: policy => observedPolicies.push(policy),
        fetch: async () => {
          calls += 1
          if (calls === 1) {
            return new Response(
              JSON.stringify({ error: { message: 'Temporary 503 on fast primary' } }),
              { status: 503, headers: { 'content-type': 'application/json' } },
            )
          }
          return new Response(
            responsesSse([
              { type: 'response.created', response: { id: 'resp_fo', status: 'in_progress' } },
              { type: 'response.output_item.added', output_index: 0, item: { type: 'message', id: 'msg_fo', role: 'assistant', content: [], status: 'in_progress' } },
              { type: 'response.output_text.delta', output_index: 0, delta: 'ok' },
              {
                type: 'response.completed',
                response: {
                  id: 'resp_fo',
                  status: 'completed',
                  output: [{ type: 'message', id: 'msg_fo', role: 'assistant', status: 'completed', content: [{ type: 'output_text', text: 'ok' }] }],
                  usage: { input_tokens: 100, output_tokens: 10 },
                },
              },
            ]),
            { status: 200, headers: { 'content-type': 'text/event-stream' } },
          )
        },
      }),
    )

    const stream = models.stream(model, {
      systemPrompt: 'Failover policy test.',
      messages: [{ role: 'user', content: 'Check.', timestamp: Date.now() }],
      tools: [],
    })
    for await (const _ev of stream) { /* drain */ }
    const res = await stream.result()
    assert.equal(res.stopReason, 'stop')
    assert.equal(calls, 2)
    assert.equal(observedPolicies.length, 2, 'must recompute ProviderRuntimePolicy for each failover candidate')

    assert.equal(observedPolicies[0]!.profileId, 'prof-fast-128k')
    assert.equal(observedPolicies[0]!.timeoutTier, 'fast')
    assert.equal(observedPolicies[0]!.firstEventTimeoutMs, 30_000)
    assert.equal(observedPolicies[0]!.contextWindow, 128_000)

    assert.equal(observedPolicies[1]!.profileId, 'prof-reason-256k')
    assert.equal(observedPolicies[1]!.timeoutTier, 'reasoning')
    assert.equal(observedPolicies[1]!.firstEventTimeoutMs, REASONING_NO_TOKEN_WATCHDOG_MS)
    assert.equal(observedPolicies[1]!.contextWindow, 256_000)
    assert.ok(
      observedPolicies[1]!.compactionReserveTokens > observedPolicies[0]!.compactionReserveTokens,
      'failover candidate must recompute its own compactionReserveTokens',
    )
    assert.equal(observedPolicies[1]!.pricing.outputCostPerMtok, 20.0)
  })

  test('stream telemetry cleanly splits stallAborts from slowTurns without conflation', async () => {
    const telemetry = createProviderStreamTelemetry(1_000)
    assert.deepEqual(telemetry.snapshot(), { stallAborts: 0, slowTurns: 0 })

    // Stall abort increments ONLY stallAborts
    telemetry.recordStallAbort()
    assert.deepEqual(telemetry.snapshot(), { stallAborts: 1, slowTurns: 0 })

    // Fast completed turn increments neither
    assert.equal(telemetry.recordCompletedTurn(400), false)
    assert.deepEqual(telemetry.snapshot(), { stallAborts: 1, slowTurns: 0 })

    // Slow completed turn increments ONLY slowTurns
    assert.equal(telemetry.recordCompletedTurn(2_500), true)
    assert.deepEqual(telemetry.snapshot(), { stallAborts: 1, slowTurns: 1 })

    // Live providerPool first-event stall increments stallAborts (not slowTurns)
    const liveTelemetry = createProviderStreamTelemetry(10)
    const profile = makeProfile()
    let stallErr: unknown
    try {
      const { models, model } = providerPool([profile], 'worker-investigation', {
        streamTelemetry: liveTelemetry,
        firstEventTimeoutMs: 40,
        idleTimeoutMs: 100,
        totalTimeoutMs: 1_000,
        maxTransportRetries: 0,
        fetch: async (_input, init) => new Promise<Response>((_res, reject) => {
          init?.signal?.addEventListener('abort', () => reject(init.signal?.reason ?? new Error('aborted')), { once: true })
        }),
      })
      const stream = models.stream(model, {
        systemPrompt: 'Stall test.',
        messages: [{ role: 'user', content: 'Wait.', timestamp: Date.now() }],
        tools: [],
      })
      for await (const _ev of stream) { /* drain */ }
      await stream.result()
    } catch (err) {
      stallErr = err
    }
    assert.ok(stallErr instanceof Error)
    assert.deepEqual(liveTelemetry.snapshot(), { stallAborts: 1, slowTurns: 0 })
  })
})

// ============================================================================
// 2. PR-21b: Unified providerOptionsFor across all 5 call sites + no literals
// ============================================================================

describe('R2-21b: Unified providerOptionsFor and zero hardcoded firstEventTimeoutMs literals', () => {
  test('zero hardcoded firstEventTimeoutMs numeric literals remain in src/server/ outside provider-runtime-policy.ts', () => {
    const serverDir = resolve('src/server')
    const offenders: string[] = []
    const literalRe = /\bfirstEventTimeoutMs\s*:\s*\d/
    for (const entry of readdirSync(serverDir)) {
      if (!entry.endsWith('.ts') || entry === 'provider-runtime-policy.ts') continue
      const content = readFileSync(join(serverDir, entry), 'utf8')
      const lines = content.split('\n')
      for (let i = 0; i < lines.length; i += 1) {
        if (literalRe.test(lines[i]!)) {
          offenders.push(`src/server/${entry}:${i + 1}: ${lines[i]!.trim()}`)
        }
      }
    }
    assert.deepEqual(offenders, [], `Found hardcoded firstEventTimeoutMs literals outside policy module:\n${offenders.join('\n')}`)
  })

  test('semantic-audit reasoning affinity never gets capped below 60s reasoning tier and injects runId', () => {
    const semanticOpts = providerOptionsFor({ id: 'run-sem-1' }, 'reasoning', 'semantic-audit', {
      profile: makeProfile({ thinkingLevel: 'off', roleAffinity: 'any' }),
    })
    assert.equal(semanticOpts.runId, 'run-sem-1')
    assert.equal(semanticOpts.roleAffinity, 'reasoning')
    assert.equal(semanticOpts.purpose, 'semantic-audit')
    assert.equal(semanticOpts.runtimePolicyManaged, true)
    assert.ok(
      (semanticOpts.firstEventTimeoutMs ?? 0) >= REASONING_NO_TOKEN_WATCHDOG_MS,
      `semantic-audit firstEventTimeoutMs must be >= ${REASONING_NO_TOKEN_WATCHDOG_MS}ms (got ${semanticOpts.firstEventTimeoutMs})`,
    )

    const judgeFastOpts = providerOptionsFor('run-judge-1', 'fast', 'approval-safety-judge', {
      profile: makeProfile({ thinkingLevel: 'off', roleAffinity: 'fast' }),
    })
    assert.equal(judgeFastOpts.runId, 'run-judge-1')
    assert.equal(judgeFastOpts.firstEventTimeoutMs, 20_000)

    const dedupeOpts = providerOptionsFor('run-dedupe-1', 'fast', 'dedupe-judge', {
      profile: makeProfile({ thinkingLevel: 'off', roleAffinity: 'fast' }),
    })
    assert.equal(dedupeOpts.runId, 'run-dedupe-1')
    assert.equal(dedupeOpts.firstEventTimeoutMs, 30_000)

    const patchOpts = providerOptionsFor('run-patch-1', 'reasoning', 'patch-author', {
      profile: makeProfile({ thinkingLevel: 'high', roleAffinity: 'reasoning' }),
    })
    assert.equal(patchOpts.firstEventTimeoutMs, REASONING_NO_TOKEN_WATCHDOG_MS)

    const connOpts = providerOptionsFor(undefined, 'fast', 'connection')
    assert.equal(connOpts.firstEventTimeoutMs, 35_000)
    assert.equal(connOpts.runId, undefined)
  })
})

// ============================================================================
// 3. PR-21c: Pricing truth, provider-reported cost preference, abort-path spend
// ============================================================================

describe('R2-21c: Conservative non-Flash pricing, no null-price USD cap bypass, provider-reported & abort-path cost', () => {
  test('non-Flash profiles never silently default to Flash prices and null pricing is strictly rejected', async t => {
    assert.equal(isDefaultFlashModel(DEFAULT_PROVIDER.model), true)
    assert.equal(isDefaultFlashModel('anthropic/claude-opus-4'), false)

    // Direct pricing resolution for non-Flash model without explicit rates -> conservative high fallback
    const opusFallback = resolveProfilePricing({ model: 'anthropic/claude-opus-4' })
    assert.equal(opusFallback.source, 'conservative_fallback')
    assert.equal(opusFallback.inputCostPerMtok, CONSERVATIVE_FALLBACK_PRICING.inputCostPerMtok)
    assert.equal(opusFallback.outputCostPerMtok, CONSERVATIVE_FALLBACK_PRICING.outputCostPerMtok)
    assert.ok(opusFallback.inputCostPerMtok > DEFAULT_PROVIDER.inputCostPerMtok * 10)

    // estimateCostUsd on a non-Flash model with omitted or null prices uses conservative fallback (NEVER 0 or Flash)
    const conservativeUsd = estimateCostUsd(
      { endpoint: 'https://api.anthropic.com/v1', model: 'anthropic/claude-opus-4', protocol: 'messages', key: 'sk-test-12345678' },
      1_000_000,
      1_000_000,
    )
    assert.equal(conservativeUsd, CONSERVATIVE_FALLBACK_PRICING.inputCostPerMtok + CONSERVATIVE_FALLBACK_PRICING.outputCostPerMtok)

    const flashUsd = estimateCostUsd(
      { endpoint: 'https://openrouter.ai/api/v1', model: DEFAULT_PROVIDER.model, protocol: 'responses', key: 'sk-test-12345678' },
      1_000_000,
      1_000_000,
    )
    assert.equal(flashUsd, DEFAULT_PROVIDER.inputCostPerMtok + DEFAULT_PROVIDER.outputCostPerMtok)

    // saveModelProfile validation on SQLite store
    const { storage } = makeStore(t, 'kovo-r2-21-pricing-')

    // (a) Null pricing MUST be rejected (never disables USD cap)
    await assert.rejects(
      () => saveModelProfile(
        {
          name: 'Null Price Attempt',
          endpoint: 'https://api.openai.com/v1',
          model: 'gpt-5',
          protocol: 'responses',
          key: 'sk-null-price-attempt-123456',
          inputCostPerMtok: null as unknown as number,
          outputCostPerMtok: null as unknown as number,
        },
        storage,
        { skipConnectionCheck: true },
      ),
      /null pricing is forbidden|finite non-negative/i,
    )

    await assert.rejects(
      () => checkModelConnection(
        {
          name: 'Null Price Check',
          endpoint: 'https://api.openai.com/v1',
          model: 'gpt-5',
          protocol: 'responses',
          key: 'sk-null-price-check-123456',
          outputCostPerMtok: null as unknown as number,
        },
        storage,
      ),
      /null pricing is forbidden|finite non-negative/i,
    )

    // (b) requireExplicitPricing rejects non-Flash profile without explicit prices
    await assert.rejects(
      () => saveModelProfile(
        {
          name: 'Strict Opus Missing Prices',
          endpoint: 'https://api.anthropic.com/v1',
          model: 'anthropic/claude-opus-4',
          protocol: 'messages',
          key: 'sk-strict-opus-missing-123456',
        },
        storage,
        { skipConnectionCheck: true, requireExplicitPricing: true },
      ),
      /Explicit inputCostPerMtok and outputCostPerMtok are required/i,
    )

    // (c) Non-Flash profile without explicit prices falls back to conservative pricing (NOT Flash 0.15/0.60)
    const savedConservative = await saveModelProfile(
      {
        name: 'Conservative Opus',
        endpoint: 'https://api.anthropic.com/v1',
        model: 'anthropic/claude-opus-4',
        protocol: 'messages',
        key: 'sk-conservative-opus-123456',
      },
      storage,
      { skipConnectionCheck: true },
    )
    const row = storage.db.select().from(modelProfiles).where(eq(modelProfiles.id, savedConservative.id)).get()!
    assert.equal(row.inputCostPerMtok, CONSERVATIVE_FALLBACK_PRICING.inputCostPerMtok)
    assert.equal(row.cachedInputCostPerMtok, CONSERVATIVE_FALLBACK_PRICING.cachedInputCostPerMtok)
    assert.equal(row.outputCostPerMtok, CONSERVATIVE_FALLBACK_PRICING.outputCostPerMtok)

    // (d) Explicit pricing on non-Flash profile is preserved verbatim (and omitted cached rate defaults to input rate, not Flash 0.003)
    const savedExplicit = await saveModelProfile(
      {
        name: 'Explicit Sonnet',
        endpoint: 'https://api.anthropic.com/v1',
        model: 'anthropic/claude-sonnet-4',
        protocol: 'messages',
        key: 'sk-explicit-sonnet-123456',
        inputCostPerMtok: 3.0,
        outputCostPerMtok: 15.0,
      },
      storage,
      { skipConnectionCheck: true, requireExplicitPricing: true },
    )
    const loaded = privateModelProfiles(storage).find(p => p.id === savedExplicit.id)!
    assert.equal(loaded.inputCostPerMtok, 3.0)
    assert.equal(loaded.cachedInputCostPerMtok, 3.0)
    assert.equal(loaded.outputCostPerMtok, 15.0)
  })

  test('prefers provider-reported cost when present in SSE usage payload', async () => {
    const profile = makeProfile({
      inputCostPerMtok: 1.0,
      cachedInputCostPerMtok: 0.25,
      outputCostPerMtok: 4.0,
    })
    const usages: UsageEvent[] = []
    const { models, model } = providerPool([profile], 'worker-investigation', {
      onUsage: u => usages.push(u),
      maxTransportRetries: 0,
      fetch: async () => new Response(
        responsesSse([
          { type: 'response.created', response: { id: 'resp_cost', status: 'in_progress' } },
          { type: 'response.output_item.added', output_index: 0, item: { type: 'message', id: 'msg_cost', role: 'assistant', content: [], status: 'in_progress' } },
          { type: 'response.output_text.delta', output_index: 0, delta: 'done' },
          {
            type: 'response.completed',
            response: {
              id: 'resp_cost',
              status: 'completed',
              output: [{ type: 'message', id: 'msg_cost', role: 'assistant', status: 'completed', content: [{ type: 'output_text', text: 'done' }] }],
              usage: { input_tokens: 1_000, output_tokens: 500, cost: 0.0425 },
            },
          },
        ]),
        { status: 200, headers: { 'content-type': 'text/event-stream' } },
      ),
    })

    const stream = models.stream(model, {
      systemPrompt: 'Cost reporting test.',
      messages: [{ role: 'user', content: 'Hi.', timestamp: Date.now() }],
      tools: [],
    })
    for await (const _ev of stream) { /* drain */ }
    await stream.result()

    assert.equal(usages.length, 1)
    assert.equal(usages[0]!.costUsd, 0.0425)
    assert.equal(usages[0]!.costSource, 'provider_reported')
    assert.equal(Boolean(usages[0]!.costEstimated), false)
  })

  test('mid-stream abort/stall after streamed deltas records > 0 estimated USD spend labeled as estimate', async t => {
    const runId = `run-r2-21-abort-cost-${Date.now()}`
    t.after(() => disposeRunTokenTelemetry(runId))

    const profile = makeProfile({
      inputCostPerMtok: 2.0,
      cachedInputCostPerMtok: 0.5,
      outputCostPerMtok: 10.0,
    })
    const usages: UsageEvent[] = []
    const telemetryEvents: ProviderUsageTelemetryInput[] = []
    const encoder = new TextEncoder()

    const { models, model } = providerPool([profile], 'worker-investigation', {
      runId,
      onUsage: u => usages.push(u),
      onTelemetry: ev => telemetryEvents.push(ev),
      firstEventTimeoutMs: 500,
      idleTimeoutMs: 60,
      totalTimeoutMs: 2_000,
      maxTransportRetries: 0,
      fetch: async () => {
        const body = new ReadableStream<Uint8Array>({
          start(controller) {
            controller.enqueue(encoder.encode(responsesSse([
              { type: 'response.created', response: { id: 'resp_abort', status: 'in_progress' } },
              { type: 'response.output_item.added', output_index: 0, item: { type: 'message', id: 'msg_abort', role: 'assistant', content: [], status: 'in_progress' } },
              { type: 'response.output_text.delta', output_index: 0, delta: 'Streamed partial investigation findings before mid-stream stall... ' },
              { type: 'response.output_text.delta', output_index: 0, delta: 'More output tokens streamed before upstream hung.' },
            ])))
            // Never close -> triggers idleTimeoutMs stall before terminal usage frame
          },
        })
        return new Response(body, { status: 200, headers: { 'content-type': 'text/event-stream' } })
      },
    })

    const stream = models.stream(model, {
      systemPrompt: 'Abort-path cost test.',
      messages: [{ role: 'user', content: 'Analyze target.', timestamp: Date.now() }],
      tools: [],
    })
    for await (const _ev of stream) { /* drain */ }
    const result = await stream.result()
    assert.equal(result.stopReason, 'error')

    assert.equal(usages.length, 1, 'mid-stream stall/abort must still emit estimated usage')
    assert.ok(usages[0]!.costUsd > 0, `abort-path costUsd must be > 0 (got ${usages[0]!.costUsd})`)
    assert.ok(usages[0]!.outputTokens > 0, `abort-path estimated outputTokens must be > 0 (got ${usages[0]!.outputTokens})`)
    assert.equal(usages[0]!.costEstimated, true, 'abort-path spend must be labeled costEstimated=true')
    assert.equal(usages[0]!.costSource, 'abort_delta_estimate')

    const summary = getRunTokenTelemetrySummary(runId)
    assert.ok(summary.totalCostUsd > 0, 'token telemetry must record abort-path totalCostUsd > 0')
    assert.ok(summary.retryStallWasteUsd > 0, 'token telemetry must attribute abort-path spend to retryStallWasteUsd')
    assert.ok(telemetryEvents.some(ev => ev.outcome === 'stalled' && (ev.costUsd ?? 0) > 0))
  })
})

// ============================================================================
// 4. PR-21d: bench-ledger.ts record-only costPerConfirmed & wastedUsd
// ============================================================================

describe('R2-21d: bench-ledger persists record-only costPerConfirmed and wastedUsd without gating', () => {
  test('appendLedgerRow computes/persists costPerConfirmed & wastedUsd and never gates on cost thresholds', t => {
    const dir = mkdtempSync(join(tmpdir(), 'kovo-r2-21-ledger-'))
    t.after(() => rmSync(dir, { recursive: true, force: true }))
    const ledgerPath = join(dir, 'ledger.jsonl')

    assert.equal(computeCostPerConfirmed(2.5, 10), 0.25)
    assert.equal(computeCostPerConfirmed(2.5, 0), null)

    // Auto-computed costPerConfirmed + explicit wastedUsd
    const row1 = appendLedgerRow(makeLedgerRow({ gitSha: 'sha-1', confirmed: 10, costUsd: 2.5, wastedUsd: 0.42 }), ledgerPath)
    assert.equal(row1.costPerConfirmed, 0.25)
    assert.equal(row1.wastedUsd, 0.42)

    // Zero confirmed -> costPerConfirmed is null; omitted wastedUsd -> null
    const row2 = appendLedgerRow(makeLedgerRow({ gitSha: 'sha-2', confirmed: 0, recall: 0, costUsd: 5.0 }), ledgerPath)
    assert.equal(row2.costPerConfirmed, null)
    assert.equal(row2.wastedUsd, null)

    // Record-only / no gate: arbitrarily high costPerConfirmed & wastedUsd still succeed cleanly
    const row3 = appendLedgerRow(makeLedgerRow({ gitSha: 'sha-3', confirmed: 1, costUsd: 999.0, wastedUsd: 500.0 }), ledgerPath)
    assert.equal(row3.costPerConfirmed, 999.0)
    assert.equal(row3.wastedUsd, 500.0)

    const loaded = readLedgerRows(ledgerPath)
    assert.equal(loaded.length, 3)
    assert.equal(loaded[0]!.costPerConfirmed, 0.25)
    assert.equal(loaded[0]!.wastedUsd, 0.42)
    assert.equal(loaded[1]!.costPerConfirmed, null)
    assert.equal(loaded[1]!.wastedUsd, null)
    assert.equal(loaded[2]!.costPerConfirmed, 999.0)
    assert.equal(loaded[2]!.wastedUsd, 500.0)

    const cmp = compareLedgerRows(loaded[0]!, loaded[2]!)
    assert.equal(cmp.costPerConfirmedDelta, 998.75)
    assert.equal(cmp.wastedUsdDelta, 499.58)
  })
})
