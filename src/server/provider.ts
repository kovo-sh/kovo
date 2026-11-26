import { setTimeout as delay } from 'node:timers/promises'
import { createModels, createProvider } from '@earendil-works/pi-ai/models'
import { stream as responses, streamSimple as simpleResponses } from '@earendil-works/pi-ai/api/openai-responses'
import { stream as messages, streamSimple as simpleMessages } from '@earendil-works/pi-ai/api/anthropic-messages'
import type { Api, Model, ProviderStreams } from '@earendil-works/pi-ai'
import { obj, str } from '@earendil-works/pi-schema'
import { DEFAULT_PROVIDER, isLocalModelEnvEnabled } from '../domain.ts'
import type { ProviderSettings, RoleAffinity, ThinkingLevel } from '../domain.ts'
import { EgressDeniedError, EgressGateway } from './egress-gateway.ts'
import type { ResolvedModelProfile } from './model-settings.ts'
import {
  defaultStreamResponseLimit,
  redactProviderText,
  resolveSecretSource,
  sanitizeProviderStream,
  sanitizeProviderValue,
  scrubOutboundProviderRequest,
  verifyOutboundProviderRequestIntegrity,
} from './provider-stream.ts'
import type { SecretSource } from './provider-stream.ts'
import { redact } from './redact.ts'
import type { NamedSecret } from './redact.ts'
import {
  recordProviderUsageTelemetry,
  type ProviderUsageTelemetryInput,
  type ProviderUsageTelemetryOutcome,
} from './token-telemetry.ts'

export type { SecretSource }

type Protocol = 'openai-responses' | 'anthropic-messages'

const providerId = 'kovo'
export const defaultMaxRequestBytes = 4 * 1024 * 1024
export const maxRequestBytesCeiling = 12 * 1024 * 1024
export const defaultFirstEventTimeoutMs = 120_000
export const defaultIdleTimeoutMs = 180_000
export const defaultTotalTimeoutMs = 600_000
export const defaultMaxCalls = 220
export const defaultMaxTransportRetries = 2
const defaultTransportRetryBaseMs = 350

/**
 * Explicit repair hint attached to `toolCall.argumentsError` whenever upstream SSE tool-call JSON
 * arguments are truncated or syntactically malformed (instead of silently erasing them to `{}`).
 */
export const TOOL_CALL_JSON_REPAIR_HINT =
  'Tool call arguments were truncated/malformed JSON; keep the script concise or split into smaller steps and retry'

export interface ToolCallArgParseDiagnostic {
  callId?: string
  itemId?: string
  name?: string
  outputIndex?: number
  kind: 'truncated_json' | 'malformed_json'
  rawBytes: number
  parseError: string
  errorMessage: string
}

interface TrackedToolCallSlot {
  ordinal: number
  outputIndex?: number
  callId?: string
  itemId?: string
  name?: string
  deltaText: string
  doneText?: string
  itemDoneText?: string
}

function sanitizeJsonParseErrorMessage(rawMessage: string): string {
  // Strip any quoted token echo from V8 SyntaxError messages (e.g. `"..." is not valid JSON`)
  // so truncated tool-call payloads containing secrets are never echoed into diagnostics.
  const withoutQuotedSnippets = rawMessage
    .replace(/"[^"]*"/g, '"<snippet>"')
    .replace(/'[^']*'/g, "'<snippet>'")
    .trim()
  return (withoutQuotedSnippets || 'invalid JSON').slice(0, 160)
}

/**
 * Observes raw upstream SSE frames (before `sanitizeProviderStream` collapses unparseable JSON
 * tool-call arguments to `'{}'`) and preserves structured parse-error diagnostics per tool call.
 *
 * When a model emits truncated (`max_tokens` / `response.incomplete`) or malformed JSON arguments,
 * `annotateToolCall` stamps `toolCall.argumentsError` with `TOOL_CALL_JSON_REPAIR_HINT` so tool
 * validation returns an actionable repair message instead of blaming missing schema fields.
 */
export class SseToolCallArgTracker {
  private readonly slotsByIndex = new Map<number, TrackedToolCallSlot>()
  private readonly slotsByKey = new Map<string, TrackedToolCallSlot>()
  private readonly orderedSlots: TrackedToolCallSlot[] = []
  private truncatedByMaxTokens = false

  reset(): void {
    this.slotsByIndex.clear()
    this.slotsByKey.clear()
    this.orderedSlots.length = 0
    this.truncatedByMaxTokens = false
  }

  private getOrCreateSlot(index: number | undefined, keys: readonly (string | undefined)[]): TrackedToolCallSlot {
    if (index !== undefined) {
      const existing = this.slotsByIndex.get(index)
      if (existing) {
        this.registerKeys(existing, keys)
        return existing
      }
    }
    for (const key of keys) {
      if (!key) continue
      const existing = this.slotsByKey.get(key)
      if (existing) {
        if (index !== undefined && existing.outputIndex === undefined) {
          existing.outputIndex = index
          this.slotsByIndex.set(index, existing)
        }
        this.registerKeys(existing, keys)
        return existing
      }
    }
    const slot: TrackedToolCallSlot = {
      ordinal: this.orderedSlots.length,
      ...(index !== undefined ? { outputIndex: index } : {}),
      deltaText: '',
    }
    this.orderedSlots.push(slot)
    if (index !== undefined) this.slotsByIndex.set(index, slot)
    this.registerKeys(slot, keys)
    return slot
  }

  private registerKeys(slot: TrackedToolCallSlot, keys: readonly (string | undefined)[]): void {
    for (const key of keys) {
      if (key) this.slotsByKey.set(key, slot)
    }
    if (slot.callId && slot.itemId) {
      this.slotsByKey.set(`${slot.callId}|${slot.itemId}`, slot)
    }
  }

  private recordFunctionCallItem(
    index: number | undefined,
    item: Record<string, unknown>,
    isDone: boolean,
  ): void {
    const callId = typeof item.call_id === 'string' && item.call_id ? item.call_id : undefined
    const itemId = typeof item.id === 'string' && item.id ? item.id : undefined
    const name = typeof item.name === 'string' && item.name ? item.name : undefined
    const slot = this.getOrCreateSlot(index, [callId, itemId])
    if (callId) slot.callId = callId
    if (itemId) slot.itemId = itemId
    if (name) slot.name = name
    this.registerKeys(slot, [callId, itemId])
    if (typeof item.arguments === 'string' && item.arguments.length > 0) {
      if (isDone) slot.itemDoneText = item.arguments
      else if (!slot.deltaText) slot.deltaText += item.arguments
    }
  }

  feedData(data: Record<string, unknown> | '[DONE]' | undefined): void {
    if (!data || data === '[DONE]') return
    const type = typeof data.type === 'string' ? data.type : ''

    // OpenAI Responses API events
    if (type === 'response.output_item.added' || type === 'response.output_item.done') {
      const item = data.item && typeof data.item === 'object' && !Array.isArray(data.item)
        ? data.item as Record<string, unknown>
        : undefined
      if (item?.type === 'function_call') {
        const index = typeof data.output_index === 'number' ? data.output_index : undefined
        this.recordFunctionCallItem(index, item, type === 'response.output_item.done')
      }
      return
    }
    if (type === 'response.function_call_arguments.delta') {
      const index = typeof data.output_index === 'number' ? data.output_index : undefined
      const itemId = typeof data.item_id === 'string' && data.item_id ? data.item_id : undefined
      const slot = this.getOrCreateSlot(index, [itemId])
      if (itemId) slot.itemId = itemId
      if (typeof data.delta === 'string') slot.deltaText += data.delta
      return
    }
    if (type === 'response.function_call_arguments.done') {
      const index = typeof data.output_index === 'number' ? data.output_index : undefined
      const itemId = typeof data.item_id === 'string' && data.item_id ? data.item_id : undefined
      const name = typeof data.name === 'string' && data.name ? data.name : undefined
      const slot = this.getOrCreateSlot(index, [itemId])
      if (itemId) slot.itemId = itemId
      if (name) slot.name = name
      if (typeof data.arguments === 'string') slot.doneText = data.arguments
      return
    }
    if (type === 'response.completed' || type === 'response.incomplete') {
      const response = data.response && typeof data.response === 'object' && !Array.isArray(data.response)
        ? data.response as Record<string, unknown>
        : undefined
      const incompleteDetails = response?.incomplete_details && typeof response.incomplete_details === 'object'
        ? response.incomplete_details as Record<string, unknown>
        : undefined
      if (
        type === 'response.incomplete'
        || response?.status === 'incomplete'
        || incompleteDetails?.reason === 'max_output_tokens'
      ) {
        this.truncatedByMaxTokens = true
      }
      if (Array.isArray(response?.output)) {
        for (let i = 0; i < response.output.length; i++) {
          const entry = response.output[i]
          if (entry && typeof entry === 'object' && !Array.isArray(entry)) {
            const rec = entry as Record<string, unknown>
            if (rec.type === 'function_call') {
              this.recordFunctionCallItem(i, rec, true)
            }
          }
        }
      }
      return
    }

    // Anthropic Messages API events
    if (type === 'content_block_start') {
      const block = data.content_block && typeof data.content_block === 'object' && !Array.isArray(data.content_block)
        ? data.content_block as Record<string, unknown>
        : undefined
      if (block?.type === 'tool_use') {
        const index = typeof data.index === 'number' ? data.index : undefined
        const callId = typeof block.id === 'string' && block.id ? block.id : undefined
        const name = typeof block.name === 'string' && block.name ? block.name : undefined
        const slot = this.getOrCreateSlot(index, [callId])
        if (callId) slot.callId = callId
        if (name) slot.name = name
      }
      return
    }
    if (type === 'content_block_delta') {
      const delta = data.delta && typeof data.delta === 'object' && !Array.isArray(data.delta)
        ? data.delta as Record<string, unknown>
        : undefined
      if (delta?.type === 'input_json_delta' && typeof delta.partial_json === 'string') {
        const index = typeof data.index === 'number' ? data.index : undefined
        const slot = this.getOrCreateSlot(index, [])
        slot.deltaText += delta.partial_json
      }
      return
    }
    if (type === 'message_delta') {
      const delta = data.delta && typeof data.delta === 'object' && !Array.isArray(data.delta)
        ? data.delta as Record<string, unknown>
        : undefined
      if (delta?.stop_reason === 'max_tokens') {
        this.truncatedByMaxTokens = true
      }
    }
  }

  private resolveSlot(toolCall: { id?: string; name?: string }, ordinal?: number): TrackedToolCallSlot | undefined {
    const id = typeof toolCall.id === 'string' ? toolCall.id : ''
    if (id) {
      const direct = this.slotsByKey.get(id)
      if (direct) return direct
      if (id.includes('|')) {
        const [callPart, itemPart] = id.split('|')
        const byCall = callPart ? this.slotsByKey.get(callPart) : undefined
        if (byCall) return byCall
        const byItem = itemPart ? this.slotsByKey.get(itemPart) : undefined
        if (byItem) return byItem
      }
    }
    if (ordinal !== undefined && this.orderedSlots[ordinal]) {
      const candidate = this.orderedSlots[ordinal]
      if (!toolCall.name || !candidate.name || candidate.name === toolCall.name) {
        return candidate
      }
    }
    if (toolCall.name) {
      const matching = this.orderedSlots.filter(s => s.name === toolCall.name)
      if (matching.length === 1) return matching[0]
    }
    return undefined
  }

  private evaluateSlot(
    slot: TrackedToolCallSlot,
    redactError?: (text: string) => string,
  ): ToolCallArgParseDiagnostic | undefined {
    const deltaTrimmed = slot.deltaText.trim()
    let raw = ''
    if (slot.doneText !== undefined && slot.doneText.trim()) {
      raw = slot.doneText.trim() === '{}' && deltaTrimmed.length > 2 ? slot.deltaText : slot.doneText
    } else if (slot.itemDoneText !== undefined && slot.itemDoneText.trim()) {
      raw = slot.itemDoneText.trim() === '{}' && deltaTrimmed.length > 2 ? slot.deltaText : slot.itemDoneText
    } else {
      raw = slot.deltaText
    }
    if (!raw.trim()) return undefined

    let parseFailure: string | undefined
    try {
      const parsed: unknown = JSON.parse(raw)
      if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
        parseFailure = 'Tool arguments must be a JSON object'
      }
    } catch (error) {
      parseFailure = error instanceof Error ? error.message : String(error)
    }
    if (!parseFailure) return undefined

    const rawBytes = Buffer.byteLength(raw, 'utf8')
    const truncated = this.truncatedByMaxTokens
      || /unexpected end of json|unterminated string|end of (?:json )?input/i.test(parseFailure)
    const kind: 'truncated_json' | 'malformed_json' = truncated ? 'truncated_json' : 'malformed_json'
    const sanitized = sanitizeJsonParseErrorMessage(parseFailure)
    const safeParseError = redactError ? redactError(sanitized) : sanitized
    const errorMessage = `${TOOL_CALL_JSON_REPAIR_HINT} (${kind}, ${rawBytes} bytes: ${safeParseError}).`
    return {
      ...(slot.callId ? { callId: slot.callId } : {}),
      ...(slot.itemId ? { itemId: slot.itemId } : {}),
      ...(slot.name ? { name: slot.name } : {}),
      ...(slot.outputIndex !== undefined ? { outputIndex: slot.outputIndex } : {}),
      kind,
      rawBytes,
      parseError: safeParseError,
      errorMessage,
    }
  }

  diagnosticForToolCall(
    toolCall: { id?: string; name?: string },
    ordinal?: number,
    redactError?: (text: string) => string,
  ): ToolCallArgParseDiagnostic | undefined {
    const slot = this.resolveSlot(toolCall, ordinal)
    if (!slot) return undefined
    return this.evaluateSlot(slot, redactError)
  }

  allDiagnostics(redactError?: (text: string) => string): ToolCallArgParseDiagnostic[] {
    const out: ToolCallArgParseDiagnostic[] = []
    for (const slot of this.orderedSlots) {
      const diag = this.evaluateSlot(slot, redactError)
      if (diag) out.push(diag)
    }
    return out
  }
}

export type ProviderCall = {
  scenario: string
  endpoint: string
  request: Record<string, unknown>
  status: number
  contentType: string
  body: string
}

export type CallRecorder = (call: ProviderCall) => void

export type UsageEvent = {
  inputTokens: number
  cachedInputTokens?: number
  outputTokens: number
  reasoningTokens?: number
  costUsd: number
  profileId?: string
}

export type UsageCallback = (usage: UsageEvent) => void

export type TelemetryCallback = (event: ProviderUsageTelemetryInput) => void

export class QuotaExhaustedError extends Error {
  readonly status = 402
  constructor(message: string) {
    super(message)
    this.name = 'QuotaExhaustedError'
  }
}

export class BudgetExceededError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'BudgetExceededError'
  }
}

export class ProviderRequestMutationError extends Error {
  readonly status = 400
  constructor(message: string) {
    super(message)
    this.name = 'ProviderRequestMutationError'
  }
}

const LOCAL_MUTATION_400_PLACEHOLDER_RE = /\[persona:[^\]]+\]|\[redacted(?::[^\]]+)?\]/
const LOCAL_MUTATION_400_SCHEMA_RE = /(?:invalid_value|invalid_request_error|invalid enum|expected one of|must be one of|unknown (?:role|type|variant|field)|unrecognized|not valid json|\brole\b|\btool_choice\b|\breasoning(?:\.(?:effort|summary))?\b|\binput_text\b|\boutput_text\b)/i

function extractConciseProviderErrorDetail(errText: string, key: string, secrets: readonly NamedSecret[]): string {
  let detail = ''
  if (errText) {
    try {
      const parsed = JSON.parse(errText) as { error?: { message?: unknown } | string; message?: unknown }
      if (parsed && typeof parsed === 'object') {
        if (parsed.error && typeof parsed.error === 'object' && typeof parsed.error.message === 'string') {
          detail = parsed.error.message
        } else if (typeof parsed.error === 'string') {
          detail = parsed.error
        } else if (typeof parsed.message === 'string') {
          detail = parsed.message
        }
      }
    } catch {
      detail = errText
    }
  }
  const normalized = detail.replace(/\s+/g, ' ').trim()
  if (!normalized) return ''
  return redactProviderText(normalized, key, secrets).slice(0, 200)
}

function diagnoseLocalMutation400(
  errText: string,
  locallyMutated: boolean,
  key: string,
  secrets: readonly NamedSecret[],
): string | null {
  if (!errText) return null
  const echoesPlaceholder = LOCAL_MUTATION_400_PLACEHOLDER_RE.test(errText)
  const schemaFailureAfterMutation = locallyMutated && LOCAL_MUTATION_400_SCHEMA_RE.test(errText)
  if (!echoesPlaceholder && !schemaFailureAfterMutation) return null
  const detail = extractConciseProviderErrorDetail(errText, key, secrets)
  return detail
    ? `Local provider request mutation caused HTTP 400: ${detail}`
    : 'Local provider request mutation caused HTTP 400 (provider rejected locally modified request payload).'
}

export function isQuotaBody(body: string): boolean {
  const lower = body.toLowerCase()
  if (
    /(?:requests? per minute|tokens? per minute|rpm|tpm|rate.?limit.*retry)/i.test(lower) &&
    !/(?:insufficient|quota|credit|balance|billing|spend.?limit|exceeded your current quota)/i.test(lower)
  ) {
    return false
  }
  return /(?:insufficient[_\s]?(?:credits?|quota|balance|funds)|exceeded your current quota|billing|spend.?limit|credit.?limit|out of credits)/i.test(lower)
}

export type ProviderConfig = Pick<ProviderSettings, 'endpoint' | 'model' | 'protocol' | 'key'> & Partial<ProviderSettings>

export type ProviderOptions = {
  signal?: AbortSignal
  record?: CallRecorder
  secrets?: SecretSource
  maxCalls?: number
  /** Bounded transient 429/5xx transport retry cap (separate from logical `maxCalls` turn budget). */
  maxTransportRetries?: number
  /** Base exponential backoff delay in ms for transient transport retries (default 350ms). */
  transportRetryBaseMs?: number
  maxRequestBytes?: number
  responseLimit?: number
  firstEventTimeoutMs?: number
  idleTimeoutMs?: number
  totalTimeoutMs?: number
  thinkingLevel?: ThinkingLevel
  roleAffinity?: RoleAffinity
  beforeCall?: () => void
  onUsage?: UsageCallback
  /** Optional run ID for structured per-run token, cost, cache, stall, and truncation telemetry. */
  runId?: string
  /** Optional direct telemetry sink for provider usage, retry, stall, and truncation events. */
  onTelemetry?: TelemetryCallback
  /** Called in real time on each upstream SSE data frame (resets no-token stall watchdogs). */
  onStreamActivity?: () => void
  onProfileSuccess?: (profileId: string) => void
  onProfileFailure?: (profileId: string, err: string, hard: boolean) => void
  /** Optional test/embedder fetch seam (production traffic always routes through `EgressGateway`). */
  fetch?: typeof fetch
  /** Optional injectable DNS resolver passed to `EgressGateway` for deterministic SSRF/rebinding tests. */
  resolveHost?: (hostname: string) => Promise<string[]>
}

function clampContextWindow(value?: number): number {
  const raw = value ?? DEFAULT_PROVIDER.contextWindow
  return Math.max(32_000, Math.min(2_000_000, Math.floor(raw)))
}

function clampMaxTokens(value?: number): number {
  const raw = value ?? DEFAULT_PROVIDER.maxTokens
  return Math.max(512, Math.min(393_216, Math.floor(raw)))
}

export function estimateCostUsd(
  profile: ProviderConfig,
  inputTokens: number,
  outputTokens: number,
  cachedInputTokens = 0,
): number {
  const inRate = profile.inputCostPerMtok ?? DEFAULT_PROVIDER.inputCostPerMtok
  const cachedRate = profile.cachedInputCostPerMtok ?? DEFAULT_PROVIDER.cachedInputCostPerMtok
  const outRate = profile.outputCostPerMtok ?? DEFAULT_PROVIDER.outputCostPerMtok
  const cached = Math.max(0, Math.min(inputTokens, cachedInputTokens))
  const uncached = Math.max(0, inputTokens - cached)
  return (uncached * inRate + cached * cachedRate + outputTokens * outRate) / 1_000_000
}

class SseUsageAccumulator {
  private rawInputTokens = 0
  private cachedInputTokens = 0
  private outputTokens = 0
  private anthropicCacheRead = 0
  private reasoningTokens = 0

  feedData(data: Record<string, unknown> | '[DONE]' | undefined): void {
    if (!data || data === '[DONE]') return
    const responseUsage = (data.response as Record<string, unknown> | undefined)?.usage as Record<string, unknown> | undefined
    const topUsage = data.usage as Record<string, unknown> | undefined
    const msgUsage = (data.message as Record<string, unknown> | undefined)?.usage as Record<string, unknown> | undefined
    const usage = responseUsage ?? topUsage ?? msgUsage
    if (!usage) return
    const inp = Number(usage.input_tokens ?? usage.prompt_tokens ?? 0)
    const out = Number(usage.output_tokens ?? usage.completion_tokens ?? 0)
    const inputDetails = usage.input_tokens_details as Record<string, unknown> | undefined
    const promptDetails = usage.prompt_tokens_details as Record<string, unknown> | undefined
    const outputDetails = usage.output_tokens_details as Record<string, unknown> | undefined
    const completionDetails = usage.completion_tokens_details as Record<string, unknown> | undefined
    const openaiCached = Number(inputDetails?.cached_tokens ?? promptDetails?.cached_tokens ?? 0)
    const msgCached = Number(usage.cache_read_input_tokens ?? 0)
    const reasoning = Number(
      outputDetails?.reasoning_tokens
      ?? completionDetails?.reasoning_tokens
      ?? usage.reasoning_tokens
      ?? usage.thinking_tokens
      ?? 0,
    )
    if (Number.isFinite(inp) && inp > this.rawInputTokens) this.rawInputTokens = inp
    if (Number.isFinite(out) && out > this.outputTokens) this.outputTokens = out
    if (Number.isFinite(openaiCached) && openaiCached > this.cachedInputTokens) this.cachedInputTokens = openaiCached
    if (Number.isFinite(msgCached) && msgCached > this.anthropicCacheRead) this.anthropicCacheRead = msgCached
    if (Number.isFinite(reasoning) && reasoning > this.reasoningTokens) this.reasoningTokens = reasoning
  }

  feedSseText(sseText: string): void {
    for (const line of sseText.split('\n')) {
      if (!line.startsWith('data: ') || line === 'data: [DONE]') continue
      try {
        const data = JSON.parse(line.slice(6)) as Record<string, unknown>
        this.feedData(data)
      } catch {
        // Ignore unparseable frames.
      }
    }
  }

  reasoningSnapshot(): number {
    return this.reasoningTokens
  }

  snapshot(protocol: 'responses' | 'messages' = 'responses'): {
    inputTokens: number
    cachedInputTokens: number
    outputTokens: number
  } {
    if (protocol === 'messages' && this.anthropicCacheRead > 0) {
      // Anthropic Messages reports `input_tokens` excluding `cache_read_input_tokens`.
      return {
        inputTokens: this.rawInputTokens + this.anthropicCacheRead,
        cachedInputTokens: this.anthropicCacheRead,
        outputTokens: this.outputTokens,
      }
    }
    const effectiveCached = Math.min(this.rawInputTokens, Math.max(this.cachedInputTokens, this.anthropicCacheRead))
    return { inputTokens: this.rawInputTokens, cachedInputTokens: effectiveCached, outputTokens: this.outputTokens }
  }
}

export function extractUsageFromSse(
  sseText: string,
  protocol: 'responses' | 'messages' = 'responses',
): { inputTokens: number; cachedInputTokens: number; outputTokens: number } {
  const acc = new SseUsageAccumulator()
  acc.feedSseText(sseText)
  return acc.snapshot(protocol)
}

function estimateValueChars(
  value: unknown,
  cache: WeakMap<object, number>,
  cacheObjects: boolean,
  depth = 0,
): number {
  if (typeof value === 'string') return value.length + 2
  if (typeof value === 'number' || typeof value === 'boolean') return 8
  if (value === null || value === undefined) return 4
  if (typeof value !== 'object' || depth > 16) return 8

  if (cacheObjects) {
    const cached = cache.get(value)
    if (cached !== undefined) return cached
  }

  let total = 2
  if (Array.isArray(value)) {
    for (let i = 0; i < value.length; i++) {
      total += estimateValueChars(value[i], cache, true, depth + 1) + 1
    }
  } else {
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
      total += k.length + 4 + estimateValueChars(v, cache, true, depth + 1)
    }
  }
  if (cacheObjects) {
    cache.set(value, total)
  }
  return total
}

/**
 * Incremental transcript token estimator backed by a per-session `WeakMap` cache.
 * Avoids synchronous full-transcript serialization on every LLM turn:
 * previously seen message & tool objects hit the cache in O(1), measuring only new turns.
 */
export function createTranscriptTokenEstimator(): {
  estimate(transcript: unknown): number
  readonly cacheHits: number
  readonly cacheMisses: number
} {
  const cache = new WeakMap<object, number>()
  let hits = 0
  let misses = 0

  const measureEntry = (entry: unknown): number => {
    if (entry && typeof entry === 'object') {
      const cached = cache.get(entry)
      if (cached !== undefined) {
        hits += 1
        return cached
      }
      misses += 1
      return estimateValueChars(entry, cache, true, 0)
    }
    return estimateValueChars(entry, cache, false, 0)
  }

  return {
    get cacheHits() { return hits },
    get cacheMisses() { return misses },
    estimate(transcript: unknown): number {
      if (!transcript || typeof transcript !== 'object') {
        return Math.ceil(estimateValueChars(transcript, cache, false, 0) / 3.5)
      }
      const rec = transcript as Record<string, unknown>
      let chars = 2
      for (const [k, v] of Object.entries(rec)) {
        chars += k.length + 4
        if (Array.isArray(v)) {
          chars += 2
          for (let i = 0; i < v.length; i++) {
            chars += measureEntry(v[i]) + 1
          }
        } else {
          chars += estimateValueChars(v, cache, false, 1)
        }
      }
      return Math.ceil(chars / 3.5)
    },
  }
}

export function estimateTranscriptTokens(transcript: unknown): number {
  return createTranscriptTokenEstimator().estimate(transcript)
}

interface MakeFetchInternalOptions {
  /** Charge logical turn budget (`callCounter.count++`) inside `makeFetch` (true for single `provider()`, false for `providerPool()`). */
  chargeLogicalTurn?: boolean
  /** Retry transient 429/5xx HTTP errors inside `makeFetch` without incrementing `callCounter` (true for single `provider()`). */
  retryTransientInFetch?: boolean
  /** Optional per-call tracker that captures raw tool-call JSON parse errors before stream redaction. */
  argTracker?: SseToolCallArgTracker
  /** Optional per-attempt marker set when `makeFetch` emits telemetry for this HTTP attempt. */
  attemptTelemetryState?: { recorded: boolean }
}

const STALL_ERROR_RE = /stall|timed?\s*out|no token/i

function isStallAbortReason(reason: unknown): boolean {
  if (reason instanceof Error) return STALL_ERROR_RE.test(reason.message)
  return typeof reason === 'string' && STALL_ERROR_RE.test(reason)
}

function createTelemetryEmitter(options: Pick<ProviderOptions, 'runId' | 'onTelemetry'>) {
  const normalizedRunId = typeof options.runId === 'string' ? options.runId.trim() : ''
  const hasRunId = normalizedRunId.length > 0
  const onTelemetry = options.onTelemetry
  if (!hasRunId && !onTelemetry) return undefined
  const effectiveRunId = hasRunId ? normalizedRunId : '__unscoped__'
  return (event: Omit<ProviderUsageTelemetryInput, 'runId'>) => {
    const payload: ProviderUsageTelemetryInput = {
      runId: effectiveRunId,
      ...event,
    }
    if (hasRunId) {
      try { recordProviderUsageTelemetry(payload) } catch { /* telemetry must never throw */ }
    }
    if (onTelemetry) {
      try { onTelemetry(payload) } catch { /* telemetry observer must never throw */ }
    }
  }
}

function isTransientHttpStatus(status: number): boolean {
  return status === 429 || (status >= 500 && status <= 599)
}

function makeFetch(
  settings: ProviderConfig,
  scenario: string,
  options: ProviderOptions,
  callCounter: { count: number; maxCalls: number },
  profileId?: string,
  internal: MakeFetchInternalOptions = {},
) {
  const chargeLogicalTurn = internal.chargeLogicalTurn ?? true
  const retryTransientInFetch = internal.retryTransientInFetch ?? false
  const emitTelemetry = createTelemetryEmitter(options)
  const endpoint = settings.protocol === 'responses'
    ? settings.endpoint + '/responses'
    : settings.endpoint.replace(/\/v1$/, '') + '/v1/messages'
  const maxRequestBytes = Math.max(
    64 * 1024,
    Math.min(maxRequestBytesCeiling, options.maxRequestBytes ?? defaultMaxRequestBytes),
  )
  const firstEventTimeoutMs = options.firstEventTimeoutMs ?? defaultFirstEventTimeoutMs
  const idleTimeoutMs = options.idleTimeoutMs ?? defaultIdleTimeoutMs
  const totalTimeoutMs = options.totalTimeoutMs ?? defaultTotalTimeoutMs
  const responseLimit = options.responseLimit ?? defaultStreamResponseLimit
  const maxTransportRetries = options.maxTransportRetries !== undefined
    ? Math.max(0, Math.floor(options.maxTransportRetries))
    : defaultMaxTransportRetries
  const retryBaseMs = options.transportRetryBaseMs !== undefined && Number.isFinite(options.transportRetryBaseMs)
    ? Math.max(0, Math.floor(options.transportRetryBaseMs))
    : defaultTransportRetryBaseMs
  const getSecrets = (): readonly NamedSecret[] => resolveSecretSource(options.secrets)

  const send: typeof fetch = async (input, init) => {
    options.beforeCall?.()
    if (chargeLogicalTurn) {
      if (callCounter.count + 1 > callCounter.maxCalls) {
        throw new BudgetExceededError('The model call budget for this operation was reached.')
      }
      callCounter.count += 1
    }
    const request = new Request(input, init)
    const actual = new URL(request.url)
    const beta = settings.protocol === 'messages' && actual.search === '?beta=true'
    if (beta) actual.search = ''
    if (actual.href !== endpoint || request.method !== 'POST') throw new Error('Unexpected model endpoint.')
    if (process.env.KOVO_OFFLINE === '1' && actual.hostname !== '127.0.0.1' && actual.hostname !== 'localhost') {
      throw new Error('Offline mode requires a loopback model fixture endpoint.')
    }
    const headers = new Headers(request.headers)
    // R2-H-2: Explicitly strip any incoming auth headers (e.g. primary pool key injected by SDK
    // auth resolver or caller opts) and stamp solely from this candidate profile's `settings.key`.
    headers.delete('authorization')
    headers.delete('x-api-key')
    headers.delete('api-key')
    const endpointOrigin = new URL(endpoint).origin
    if (endpointOrigin === 'https://openrouter.ai' || settings.protocol === 'responses') {
      headers.set('authorization', 'Bearer ' + settings.key)
    } else {
      headers.set('x-api-key', settings.key)
    }

    const raw = await request.text()
    if (Buffer.byteLength(raw) > maxRequestBytes) {
      throw new Error('The model request exceeded Kovo Hunter’s size limit.')
    }
    const payload = JSON.parse(raw) as Record<string, unknown>
    // R3-H-10 / H-8: Scrub live registered/rotated secrets EXCLUSIVELY from content-bearing
    // leaves in outbound model requests (never object keys, roles, types, enums, tool_choice,
    // reasoning config, or tool definitions/schemas).
    const currentSecrets = getSecrets()
    const scrubbedPayload = scrubOutboundProviderRequest(payload, settings.key, currentSecrets)
    const integrityViolation = verifyOutboundProviderRequestIntegrity(payload, scrubbedPayload)
    if (integrityViolation) {
      throw new ProviderRequestMutationError(
        `Local provider request integrity check failed: protected protocol field "${integrityViolation}" was corrupted before egress.`,
      )
    }
    const locallyMutated = scrubbedPayload !== payload
    const outboundRaw = locallyMutated ? JSON.stringify(scrubbedPayload) : raw
    if (outboundRaw !== raw && Buffer.byteLength(outboundRaw) > maxRequestBytes) {
      throw new Error('The model request exceeded Kovo Hunter’s size limit.')
    }

    const targetUrl = beta ? endpoint + '?beta=true' : endpoint
    const allowLocalModel = isLocalModelEnvEnabled()

    let transportRetry = 0
    for (;;) {
      internal.argTracker?.reset()
      if (internal.attemptTelemetryState) internal.attemptTelemetryState.recorded = false
      const totalSignal = AbortSignal.any([
        request.signal,
        AbortSignal.timeout(totalTimeoutMs),
        ...(options.signal ? [options.signal] : []),
      ])
      const firstEventController = new AbortController()
      const streamAbortController = new AbortController()
      const firstEventTimeoutError = () => new Error('The model provider timed out before returning the first event.')
      let firstEventCleared = false
      let firstEventTimer: ReturnType<typeof setTimeout> | undefined
      let onFirstEventTimeout: ((err: Error) => void) | undefined
      let onTotalAbortHook: (() => void) | undefined
      const clearFirstEventTimer = () => {
        if (firstEventCleared) return
        firstEventCleared = true
        if (firstEventTimer) {
          clearTimeout(firstEventTimer)
          firstEventTimer = undefined
        }
      }
      if (Number.isFinite(firstEventTimeoutMs) && firstEventTimeoutMs > 0) {
        firstEventTimer = setTimeout(() => {
          if (!firstEventCleared) {
            const err = firstEventTimeoutError()
            onFirstEventTimeout?.(err)
            firstEventController.abort(err)
          }
        }, firstEventTimeoutMs)
        firstEventTimer.unref?.()
      }
      const onTotalAbort = () => {
        clearFirstEventTimer()
        onTotalAbortHook?.()
      }
      totalSignal.addEventListener('abort', onTotalAbort, { once: true })
      // Enforce firstEventTimeoutMs ONLY until the first chunk/event arrives (disarmed via
      // clearFirstEventTimer), so healthy multi-chunk streams are never aborted mid-body.
      const fetchSignal = AbortSignal.any([totalSignal, firstEventController.signal, streamAbortController.signal])
      let handoffToStream = false

      try {
        const response = options.fetch
          ? await options.fetch(targetUrl, {
              method: 'POST',
              headers,
              body: outboundRaw,
              redirect: 'error',
              signal: fetchSignal,
            })
          : await EgressGateway.egressFetchStream(
              targetUrl,
              {
                method: 'POST',
                headers,
                body: outboundRaw,
                redirect: 'error',
                signal: fetchSignal,
              },
              {
                allowLocalLab: false,
                allowHttp: allowLocalModel,
                allowedLoopbackOnlyHosts: allowLocalModel ? ['127.0.0.1', 'localhost'] : undefined,
                timeoutMs: totalTimeoutMs,
                maxResponseBytes: Math.max(responseLimit * 2, 4 * 1024 * 1024),
                ...(options.resolveHost ? { resolveHost: options.resolveHost } : {}),
              },
            )

        const contentType = response.headers.get('content-type') ?? 'application/json'
        const recordResponse = options.record && ((body: string) => {
          const recordSecrets = getSecrets()
          options.record!({
            scenario,
            endpoint: redactProviderText(new URL(endpoint).pathname, settings.key, recordSecrets),
            request: sanitizeProviderValue(scrubbedPayload, settings.key, undefined, recordSecrets) as Record<string, unknown>,
            status: response.status,
            contentType: redactProviderText(contentType, settings.key, recordSecrets),
            body,
          })
        })

        if (!response.ok) {
          clearFirstEventTimer()
          const errText = await response.text().catch(() => '')
          const effectiveStatus = response.status === 429 && isQuotaBody(errText) ? 402 : response.status
          if (retryTransientInFetch && isTransientHttpStatus(effectiveStatus) && transportRetry < maxTransportRetries) {
            transportRetry += 1
            if (emitTelemetry) {
              emitTelemetry({ outcome: 'retried', retried: true, costUsd: 0 })
              if (internal.attemptTelemetryState) internal.attemptTelemetryState.recorded = true
            }
            const waitMs = Math.min(4_000, retryBaseMs * (2 ** (transportRetry - 1)))
            if (waitMs > 0) {
              await delay(waitMs, undefined, { signal: totalSignal })
            }
            continue
          }
          if (emitTelemetry && retryTransientInFetch) {
            emitTelemetry({ outcome: 'error', costUsd: 0 })
            if (internal.attemptTelemetryState) internal.attemptTelemetryState.recorded = true
          }
          const localMutationDiagnostic = effectiveStatus === 400
            ? diagnoseLocalMutation400(errText, locallyMutated, settings.key, currentSecrets)
            : null
          const message = effectiveStatus === 401 || effectiveStatus === 403
            ? 'The provider rejected the API key.'
            : effectiveStatus === 402
              ? 'The provider quota or credit balance was exhausted.'
              : effectiveStatus === 404
                ? 'The provider endpoint or model was not found.'
                : effectiveStatus === 429
                  ? 'The provider rate limit was reached.'
                  : localMutationDiagnostic ?? `The model provider returned HTTP ${effectiveStatus}.`
          const error = JSON.stringify({ error: { message } })
          recordResponse?.(error)
          return new Response(error, { status: effectiveStatus, headers: { 'content-type': 'application/json' } })
        }

        if (!response.body || !contentType.toLowerCase().includes('text/event-stream')) {
          clearFirstEventTimer()
          await response.body?.cancel()
          throw new Error('The provider did not return a streaming response.')
        }

        // Move O4: True pass-through TransformStream over sanitizeProviderStream.
        // Enforces per-chunk idleTimeoutMs + firstEventTimeoutMs while streaming chunks directly
        // to the consumer before EOF, and flushes usage + transcript idempotently in finalize()
        // on normal EOF, timeout, error, or mid-stream consumer cancel/abort.
        const usageAccumulator = new SseUsageAccumulator()
        const recordedParts: string[] = []
        const streamDecoder = new TextDecoder()
        let idleTimer: ReturnType<typeof setTimeout> | undefined
        let finalized = false
        let errored = false
        let stalled = false
        let streamAborted = false
        let sawErrorFrame = false
        let transformController: TransformStreamDefaultController<Uint8Array> | undefined

        const clearIdleTimer = () => {
          if (idleTimer) {
            clearTimeout(idleTimer)
            idleTimer = undefined
          }
        }

        const finalize = () => {
          if (finalized) return
          finalized = true
          clearFirstEventTimer()
          clearIdleTimer()
          totalSignal.removeEventListener('abort', onTotalAbort)
          if (options.record) {
            const tail = streamDecoder.decode()
            if (tail) recordedParts.push(tail)
            if (recordedParts.length > 0) {
              try { recordResponse?.(recordedParts.join('')) } catch { /* recording must never throw */ }
            }
          }
          if (options.onUsage || emitTelemetry) {
            const usage = usageAccumulator.snapshot(settings.protocol)
            const reasoningTokens = usageAccumulator.reasoningSnapshot()
            const hasUsage = usage.inputTokens > 0 || usage.outputTokens > 0
            const costUsd = hasUsage || reasoningTokens > 0
              ? estimateCostUsd(settings, usage.inputTokens, usage.outputTokens, usage.cachedInputTokens)
              : 0
            if (options.onUsage && hasUsage) {
              try {
                options.onUsage({
                  ...usage,
                  ...(reasoningTokens > 0 ? { reasoningTokens } : {}),
                  costUsd,
                  profileId,
                })
              } catch { /* usage observer must never throw */ }
            }
            if (emitTelemetry) {
              const truncatedToolCalls = internal.argTracker ? internal.argTracker.allDiagnostics().length : 0
              const isStalled = stalled
              const isAborted = !isStalled && streamAborted
              const isErrored = errored || (sawErrorFrame && retryTransientInFetch)
              if (hasUsage || reasoningTokens > 0 || isStalled || truncatedToolCalls > 0 || isAborted || isErrored) {
                const outcome: ProviderUsageTelemetryOutcome = isStalled
                  ? 'stalled'
                  : truncatedToolCalls > 0
                    ? 'truncated'
                    : isAborted
                      ? 'aborted'
                      : isErrored
                        ? 'error'
                        : 'ok'
                emitTelemetry({
                  inputTokens: usage.inputTokens,
                  cachedInputTokens: usage.cachedInputTokens,
                  outputTokens: usage.outputTokens,
                  reasoningTokens,
                  costUsd,
                  outcome,
                  stalled: isStalled,
                  truncatedToolCalls,
                })
                if (internal.attemptTelemetryState) internal.attemptTelemetryState.recorded = true
              }
            }
          }
        }

        const failStream = (err: Error) => {
          if (errored) return
          errored = true
          try { transformController?.error(err) } catch { /* stream already closed/errored */ }
          finalize()
        }

        const armIdleTimer = () => {
          clearIdleTimer()
          if (finalized || errored || !Number.isFinite(idleTimeoutMs) || idleTimeoutMs <= 0) return
          idleTimer = setTimeout(() => {
            idleTimer = undefined
            const err = new Error('The model stream timed out while waiting for data.')
            stalled = true
            failStream(err)
            if (!streamAbortController.signal.aborted) {
              streamAbortController.abort(err)
            }
          }, idleTimeoutMs)
          idleTimer.unref?.()
        }

        onFirstEventTimeout = err => {
          stalled = true
          failStream(err)
        }
        onTotalAbortHook = () => {
          const reason = totalSignal.reason
          const err = reason instanceof Error
            ? reason
            : new Error(typeof reason === 'string' && reason ? reason : 'The model stream was aborted.')
          if (isStallAbortReason(reason ?? err)) {
            stalled = true
          } else {
            streamAborted = true
          }
          failStream(err)
        }

        const sanitized = sanitizeProviderStream(response.body, settings.key, settings.protocol, {
          secrets: getSecrets,
          responseLimit,
          onFirstChunk: () => {
            clearFirstEventTimer()
            armIdleTimer()
          },
          onFrame: data => {
            usageAccumulator.feedData(data)
            internal.argTracker?.feedData(data)
            if (emitTelemetry && data && data !== '[DONE]') {
              const t = data.type
              if (t === 'error' || t === 'response.failed') sawErrorFrame = true
            }
          },
          onActivity: () => {
            clearFirstEventTimer()
            armIdleTimer()
            options.onStreamActivity?.()
          },
        })

        const monitorTransformer: Transformer<Uint8Array, Uint8Array> & { cancel?: () => void } = {
          start(controller) {
            transformController = controller
            if (totalSignal.aborted) {
              onTotalAbortHook?.()
              return
            }
            if (firstEventController.signal.aborted) {
              stalled = true
              failStream(firstEventTimeoutError())
              return
            }
            armIdleTimer()
          },
          transform(chunk, controller) {
            armIdleTimer()
            if (options.record) {
              const decoded = streamDecoder.decode(chunk, { stream: true })
              if (decoded) recordedParts.push(decoded)
            }
            controller.enqueue(chunk)
          },
          flush() {
            finalize()
          },
          cancel() {
            streamAborted = true
            finalize()
            if (!streamAbortController.signal.aborted) {
              streamAbortController.abort(new Error('The model stream consumer canceled.'))
            }
          },
        }
        const monitor = new TransformStream<Uint8Array, Uint8Array>(monitorTransformer as Transformer<Uint8Array, Uint8Array>)

        handoffToStream = true
        void sanitized.pipeTo(monitor.writable)
          .catch(() => { errored = true })
          .finally(() => finalize())

        return new Response(monitor.readable, {
          status: response.status,
          headers: { 'content-type': 'text/event-stream' },
        })
      } catch (error) {
        if (firstEventController.signal.aborted && !totalSignal.aborted) {
          if (emitTelemetry) {
            emitTelemetry({ outcome: 'stalled', stalled: true, costUsd: 0 })
            if (internal.attemptTelemetryState) internal.attemptTelemetryState.recorded = true
          }
          throw firstEventController.signal.reason instanceof Error
            ? firstEventController.signal.reason
            : firstEventTimeoutError()
        }
        if (emitTelemetry) {
          const isStall = isStallAbortReason(totalSignal.aborted ? totalSignal.reason : error)
          if (isStall) {
            emitTelemetry({ outcome: 'stalled', stalled: true, costUsd: 0 })
            if (internal.attemptTelemetryState) internal.attemptTelemetryState.recorded = true
          } else if (totalSignal.aborted) {
            emitTelemetry({ outcome: 'aborted', costUsd: 0 })
            if (internal.attemptTelemetryState) internal.attemptTelemetryState.recorded = true
          } else if (retryTransientInFetch) {
            emitTelemetry({ outcome: 'error', costUsd: 0 })
            if (internal.attemptTelemetryState) internal.attemptTelemetryState.recorded = true
          }
        }
        throw error
      } finally {
        if (!handoffToStream) {
          clearFirstEventTimer()
          totalSignal.removeEventListener('abort', onTotalAbort)
        }
      }
    }
  }
  return send
}

type ToolCallLike = {
  type?: unknown
  id?: string
  name?: string
  arguments?: unknown
  argumentsError?: string
}

function annotateToolCallPart(
  part: ToolCallLike | undefined,
  tracker: SseToolCallArgTracker,
  ordinal: number | undefined,
  redactError: (text: string) => string,
): void {
  if (!part || part.type !== 'toolCall') return
  if (typeof part.argumentsError === 'string' && part.argumentsError.trim()) {
    if (!part.argumentsError.includes(TOOL_CALL_JSON_REPAIR_HINT)) {
      const diag = tracker.diagnosticForToolCall(part, ordinal, redactError)
      part.argumentsError = diag
        ? diag.errorMessage
        : `${TOOL_CALL_JSON_REPAIR_HINT} (${redactError(sanitizeJsonParseErrorMessage(part.argumentsError))}).`
    }
    return
  }
  const diag = tracker.diagnosticForToolCall(part, ordinal, redactError)
  if (diag) {
    part.argumentsError = diag.errorMessage
  }
}

function annotateAssistantMessageToolCalls(
  message: { content?: unknown } | undefined,
  tracker: SseToolCallArgTracker,
  redactError: (text: string) => string,
): void {
  if (!message || !Array.isArray(message.content)) return
  let toolOrdinal = 0
  for (const part of message.content) {
    if (part && typeof part === 'object' && (part as ToolCallLike).type === 'toolCall') {
      annotateToolCallPart(part as ToolCallLike, tracker, toolOrdinal, redactError)
      toolOrdinal += 1
    }
  }
}

function wrapStreamWithToolCallIntegrity<TStream extends ReturnType<ProviderStreams['stream']>>(
  rawStream: TStream,
  tracker: SseToolCallArgTracker,
  redactError: (text: string) => string,
): TStream {
  let seenToolEnds = 0
  const annotateEvent = (event: unknown) => {
    if (!event || typeof event !== 'object') return
    const rec = event as { type?: unknown; toolCall?: ToolCallLike; message?: { content?: unknown } }
    if (rec.type === 'toolcall_end' && rec.toolCall) {
      annotateToolCallPart(rec.toolCall, tracker, seenToolEnds, redactError)
      seenToolEnds += 1
    } else if (rec.type === 'done' && rec.message) {
      annotateAssistantMessageToolCalls(rec.message, tracker, redactError)
    }
  }
  const wrapped = {
    async *[Symbol.asyncIterator]() {
      for await (const event of rawStream) {
        annotateEvent(event)
        yield event
      }
    },
    async result() {
      const res = await rawStream.result()
      annotateAssistantMessageToolCalls(res as { content?: unknown }, tracker, redactError)
      return res
    },
  }
  return wrapped as unknown as TStream
}

function buildSingleStreamImpl(
  settings: ProviderConfig,
  scenario: string,
  options: ProviderOptions,
  callCounter: { count: number; maxCalls: number },
  profileId?: string,
  fetchInternal: MakeFetchInternalOptions = {},
) {
  const api: Protocol = settings.protocol === 'responses' ? 'openai-responses' : 'anthropic-messages'
  const maxTokens = clampMaxTokens(settings.maxTokens)
  const contextWindow = clampContextWindow(settings.contextWindow)
  const effectiveThinking: ThinkingLevel = scenario === 'connection'
    ? 'off'
    : (options.thinkingLevel ?? settings.thinkingLevel ?? DEFAULT_PROVIDER.thinkingLevel)
  const thinkingEnabled = effectiveThinking !== 'off'
  const model: Model<Protocol> = {
    id: settings.model,
    name: settings.model,
    provider: providerId,
    api,
    baseUrl: settings.protocol === 'messages' ? settings.endpoint.replace(/\/v1$/, '') : settings.endpoint,
    input: ['text'],
    reasoning: thinkingEnabled,
    contextWindow,
    maxTokens,
    cost: {
      input: settings.inputCostPerMtok ?? DEFAULT_PROVIDER.inputCostPerMtok,
      output: settings.outputCostPerMtok ?? DEFAULT_PROVIDER.outputCostPerMtok,
      cacheRead: settings.cachedInputCostPerMtok ?? DEFAULT_PROVIDER.cachedInputCostPerMtok,
      cacheWrite: 0,
    },
  }
  const connection = scenario === 'connection'
  const chooseEvidenceTool = (transcript: { messages: { role: string }[] }) =>
    (scenario === 'worker-analysis' || scenario === 'response-analysis') && transcript.messages.at(-1)?.role === 'user'
  const redactError = (text: string) => redactProviderText(text, settings.key, options.secrets)
  const makeCallContext = () => {
    const tracker = new SseToolCallArgTracker()
    const send = makeFetch(settings, scenario, options, callCounter, profileId, {
      ...fetchInternal,
      argTracker: tracker,
    })
    const streamOpts = {
      fetch: send,
      maxTokens,
      maxRetries: 0,
      // Total call ceiling for the SDK; per-chunk idle timeouts are enforced inside `makeFetch`
      // and reset in real time on every upstream SSE frame via `sanitizeProviderStream`.
      timeoutMs: options.totalTimeoutMs ?? defaultTotalTimeoutMs,
      // R2-H-2: Applied LAST in `streamOpts` so primary/caller `sOpts.apiKey` can never overwrite it.
      apiKey: settings.key,
    }
    return { tracker, streamOpts }
  }

  const implementation: ProviderStreams = api === 'openai-responses' ? {
    stream: (selected, transcript, sOpts) => {
      const { tracker, streamOpts } = makeCallContext()
      return wrapStreamWithToolCallIntegrity(
        responses(selected as Model<'openai-responses'>, transcript, {
          ...sOpts,
          ...streamOpts,
          ...(effectiveThinking !== 'off' ? { reasoningEffort: effectiveThinking } : { reasoningEffort: undefined }),
          ...(connection ? { toolChoice: 'required' as const } : {}),
        }),
        tracker,
        redactError,
      )
    },
    streamSimple: (selected, transcript, sOpts) => {
      const { tracker, streamOpts } = makeCallContext()
      return wrapStreamWithToolCallIntegrity(
        chooseEvidenceTool(transcript)
          ? responses({ ...(selected as Model<'openai-responses'>), reasoning: false }, transcript, {
              ...sOpts,
              ...streamOpts,
              reasoningEffort: undefined,
              toolChoice: 'required',
            })
          : simpleResponses(selected as Model<'openai-responses'>, transcript, {
              ...sOpts,
              ...streamOpts,
              ...(effectiveThinking !== 'off' ? { reasoning: effectiveThinking } : { reasoning: undefined }),
            }),
        tracker,
        redactError,
      )
    },
  } : {
    stream: (selected, transcript, sOpts) => {
      const { tracker, streamOpts } = makeCallContext()
      return wrapStreamWithToolCallIntegrity(
        messages(selected as Model<'anthropic-messages'>, transcript, {
          ...sOpts,
          ...streamOpts,
          thinkingEnabled,
          ...(thinkingEnabled ? { effort: effectiveThinking } : {}),
          ...(connection ? { toolChoice: { type: 'tool' as const, name: 'kovo_connection' } } : {}),
        }),
        tracker,
        redactError,
      )
    },
    streamSimple: (selected, transcript, sOpts) => {
      const { tracker, streamOpts } = makeCallContext()
      return wrapStreamWithToolCallIntegrity(
        chooseEvidenceTool(transcript)
          ? messages(selected as Model<'anthropic-messages'>, transcript, {
            ...sOpts, ...streamOpts, thinkingEnabled: false, toolChoice: { type: 'tool', name: 'derive_evidence' },
          })
          : simpleMessages(selected as Model<'anthropic-messages'>, transcript, {
            ...sOpts,
            ...streamOpts,
            ...(thinkingEnabled ? { reasoning: effectiveThinking } : {}),
          }),
        tracker,
        redactError,
      )
    },
  }

  return { model, implementation }
}

export function provider(
  settings: ProviderConfig,
  scenario: string,
  signalOrOptions?: AbortSignal | ProviderOptions,
  record?: CallRecorder,
) {
  const options: ProviderOptions = signalOrOptions instanceof AbortSignal
    ? { signal: signalOrOptions, record }
    : (signalOrOptions ?? { record })
  const callCounter = { count: 0, maxCalls: options.maxCalls ?? defaultMaxCalls }
  const { model, implementation } = buildSingleStreamImpl(settings, scenario, options, callCounter, settings.id, {
    chargeLogicalTurn: true,
    retryTransientInFetch: true,
  })
  const models = createModels({ identity: { attribution: null } })
  models.setProvider(createProvider<Api>({
    id: providerId,
    auth: { apiKey: { name: 'Workspace provider key', resolve: async () => ({ auth: { apiKey: settings.key } }) } },
    api: implementation,
    models: [model],
  }))
  return { models, model }
}

let rrCounter = 0

export function classifyFailoverError(message: string): { failover: boolean; hard: boolean } {
  if (/aborted due to timeout/i.test(message)) {
    return { failover: true, hard: false }
  }
  if (/aborted|cancelled|canceled|budget|exceeded Kovo Hunter’s size limit|Unexpected model endpoint|Local provider request|refused by SSRF policy|never permitted|Plaintext HTTP egress|without local-lab or explicit loopback/i.test(message)) {
    return { failover: false, hard: false }
  }
  if (/rejected the API key|quota|credit balance|401|402|403|404|not found/i.test(message)) {
    return { failover: true, hard: true }
  }
  if (/rate limit|429|HTTP 5\d\d|timed out|timeout|fetch failed|ECONNREFUSED|ECONNRESET|ETIMEDOUT|socket/i.test(message)) {
    return { failover: true, hard: false }
  }
  return { failover: false, hard: false }
}

function roleRank(profile: ResolvedModelProfile, preferredRole?: RoleAffinity): number {
  if (!preferredRole || preferredRole === 'any') return 0
  const aff = profile.roleAffinity ?? 'any'
  if (aff === preferredRole) return 0
  if (aff === 'any') return 1
  return 2
}

function compareProfiles(a: ResolvedModelProfile, b: ResolvedModelProfile, preferredRole?: RoleAffinity): number {
  return roleRank(a, preferredRole) - roleRank(b, preferredRole) || b.priority - a.priority
}

export function orderProfiles(
  profiles: readonly ResolvedModelProfile[],
  estimatedTokens: number,
  preferredRole?: RoleAffinity,
): ResolvedModelProfile[] {
  const now = Date.now()
  const sorted = [...profiles].sort((a, b) => compareProfiles(a, b, preferredRole))
  const fitting = sorted.filter(p => p.contextWindow <= 0 || estimatedTokens <= p.contextWindow * 0.95)
  const pool = fitting.length ? fitting : sorted
  const healthy = pool.filter(p => !(p.healthState === 'open' && p.cooldownUntil !== null && p.cooldownUntil > now))
  const base = healthy.length
    ? healthy
    : [...pool].sort((a, b) => (a.cooldownUntil ?? 0) - (b.cooldownUntil ?? 0)).slice(0, 1)

  // Round-robin within equal (roleRank, priority) groups.
  const tick = rrCounter++
  const out: ResolvedModelProfile[] = []
  for (let i = 0; i < base.length;) {
    let j = i + 1
    while (
      j < base.length &&
      roleRank(base[j], preferredRole) === roleRank(base[i], preferredRole) &&
      base[j].priority === base[i].priority
    ) j++
    const group = base.slice(i, j)
    if (group.length > 1) {
      const offset = tick % group.length
      for (let k = 0; k < group.length; k++) out.push(group[(k + offset) % group.length])
    } else {
      out.push(group[0])
    }
    i = j
  }
  return out
}

export function providerPool(
  profiles: readonly ResolvedModelProfile[],
  scenario: string,
  options: ProviderOptions = {},
) {
  if (!profiles.length) throw new Error('No enabled workspace model profiles are configured.')
  const sorted = [...profiles].sort((a, b) => compareProfiles(a, b, options.roleAffinity))
  const now = Date.now()
  const primary = sorted.find(p => !(p.healthState === 'open' && p.cooldownUntil !== null && p.cooldownUntil > now)) ?? sorted[0]
  const callCounter = { count: 0, maxCalls: options.maxCalls ?? defaultMaxCalls }
  const poolKeySecrets: readonly NamedSecret[] = profiles.map(p => ({ value: p.key, placeholder: '[redacted]' }))
  const poolOptions: ProviderOptions = {
    ...options,
    secrets: () => {
      const base = resolveSecretSource(options.secrets)
      return base.length ? [...base, ...poolKeySecrets] : poolKeySecrets
    },
  }
  const primaryBuilt = buildSingleStreamImpl(primary, scenario, poolOptions, callCounter, primary.id, {
    chargeLogicalTurn: false,
    retryTransientInFetch: false,
  })
  const tokenEstimator = createTranscriptTokenEstimator()
  const emitTelemetry = createTelemetryEmitter(poolOptions)
  const retryBaseMs = options.transportRetryBaseMs !== undefined && Number.isFinite(options.transportRetryBaseMs)
    ? Math.max(0, Math.floor(options.transportRetryBaseMs))
    : defaultTransportRetryBaseMs

  const recordPoolAttemptFailure = (
    attemptState: { recorded: boolean } | undefined,
    willRetryOrFailover: boolean,
  ) => {
    if (!emitTelemetry) return
    if (willRetryOrFailover) {
      emitTelemetry({
        outcome: 'retried',
        retried: true,
        costUsd: 0,
        countCall: !(attemptState?.recorded),
      })
    } else if (!attemptState?.recorded) {
      emitTelemetry({ outcome: 'error', costUsd: 0 })
    }
    if (attemptState) attemptState.recorded = true
  }

  const wrapMethod = (method: 'stream' | 'streamSimple'): ProviderStreams['stream'] => {
    return (_selected, transcript, sOpts) => {
      const estimatedTokens = tokenEstimator.estimate(transcript)
      const ordered = orderProfiles(sorted, estimatedTokens, options.roleAffinity)

      // Execute failover strictly inside the safe window (before yielding the first non-error event).
      const iter = (async function* () {
        // Move O4: Charge logical turn budget ONCE per LLM turn (never per transient 429/5xx retry
        // or failover hop), bounded separately by `maxTransportRetries`.
        options.beforeCall?.()
        if (callCounter.count + 1 > callCounter.maxCalls) {
          throw new BudgetExceededError('The model call budget for this operation was reached.')
        }
        callCounter.count += 1

        let lastError: unknown
        let transientAttempts = 0
        const maxTransportRetries = options.maxTransportRetries !== undefined
          ? Math.max(0, Math.floor(options.maxTransportRetries))
          : (ordered.length === 1 ? defaultMaxTransportRetries : 1)

        for (let idx = 0; idx < ordered.length; idx++) {
          const candidate = ordered[idx]
          if (options.signal?.aborted) throw options.signal.reason ?? new Error('Aborted')

          let attempt = 0
          for (;;) {
            const attemptTelemetryState = emitTelemetry ? { recorded: false } : undefined
            const built = buildSingleStreamImpl(candidate, scenario, poolOptions, callCounter, candidate.id, {
              chargeLogicalTurn: false,
              retryTransientInFetch: false,
              ...(attemptTelemetryState ? { attemptTelemetryState } : {}),
            })
            const candidateOpts = { ...sOpts, apiKey: candidate.key }
            const stream = built.implementation[method](built.model, transcript, candidateOpts)
            let emitted = false
            let retrySame = false
            let failedOver = false

            try {
              for await (const event of stream) {
                if (event.type === 'error' && !emitted) {
                  const msg = String((event as { error?: { errorMessage?: string } }).error?.errorMessage ?? 'Model error')
                  const decision = classifyFailoverError(msg)
                  if (decision.failover) {
                    options.onProfileFailure?.(candidate.id, msg, decision.hard)
                    lastError = new Error(msg)
                    failedOver = true
                    if (!decision.hard && idx === ordered.length - 1 && transientAttempts < maxTransportRetries) {
                      transientAttempts++
                      attempt++
                      retrySame = true
                    }
                    recordPoolAttemptFailure(attemptTelemetryState, retrySame || idx + 1 < ordered.length)
                    break
                  }
                }
                emitted = true
                yield event
              }

              if (retrySame) {
                const waitMs = Math.min(4_000, retryBaseMs * 2 ** (attempt - 1))
                if (waitMs > 0) await delay(waitMs, undefined, { signal: options.signal })
                continue
              }
              if (failedOver) break

              const res = await stream.result()
              if (!emitted && res.stopReason === 'error') {
                const msg = res.errorMessage ?? 'Model error'
                const decision = classifyFailoverError(msg)
                if (decision.failover) {
                  options.onProfileFailure?.(candidate.id, msg, decision.hard)
                  lastError = new Error(msg)
                  const willRetrySame = !decision.hard && idx === ordered.length - 1 && transientAttempts < maxTransportRetries
                  recordPoolAttemptFailure(attemptTelemetryState, willRetrySame || idx + 1 < ordered.length)
                  if (willRetrySame) {
                    transientAttempts++
                    attempt++
                    const waitMs = Math.min(4_000, retryBaseMs * 2 ** (attempt - 1))
                    if (waitMs > 0) await delay(waitMs, undefined, { signal: options.signal })
                    continue
                  }
                  break
                }
              }
              if (res.stopReason === 'error') {
                recordPoolAttemptFailure(attemptTelemetryState, false)
              } else {
                options.onProfileSuccess?.(candidate.id)
              }
              return res
            } catch (error) {
              if (emitted) throw error
              const msg = error instanceof Error ? error.message : String(error)
              const decision = classifyFailoverError(msg)
              if (!decision.failover) {
                recordPoolAttemptFailure(attemptTelemetryState, false)
                throw error
              }
              options.onProfileFailure?.(candidate.id, msg, decision.hard)
              lastError = error
              const willRetrySame = !decision.hard && idx === ordered.length - 1 && transientAttempts < maxTransportRetries
              recordPoolAttemptFailure(attemptTelemetryState, willRetrySame || idx + 1 < ordered.length)
              if (willRetrySame) {
                transientAttempts++
                attempt++
                const waitMs = Math.min(4_000, retryBaseMs * 2 ** (attempt - 1))
                if (waitMs > 0) await delay(waitMs, undefined, { signal: options.signal })
                continue
              }
              break
            }
          }
        }
        throw lastError instanceof Error ? lastError : new Error('All configured model profiles failed.')
      })()

      let cachedResult: Promise<Awaited<ReturnType<ReturnType<ProviderStreams['stream']>['result']>>> | undefined
      const resolveResult = () => {
        if (!cachedResult) {
          cachedResult = (async () => {
            for (;;) {
              const step = await iter.next()
              if (step.done) return step.value
            }
          })()
        }
        return cachedResult
      }

      const wrapped = {
        async *[Symbol.asyncIterator]() {
          for (;;) {
            const step = await iter.next()
            if (step.done) {
              cachedResult = Promise.resolve(step.value)
              return
            }
            yield step.value
          }
        },
        result: resolveResult,
      }
      return wrapped as unknown as ReturnType<ProviderStreams['stream']>
    }
  }

  const implementation: ProviderStreams = {
    stream: wrapMethod('stream'),
    streamSimple: wrapMethod('streamSimple'),
  }

  const models = createModels({ identity: { attribution: null } })
  models.setProvider(createProvider<Api>({
    id: providerId,
    // R2-H-2: Never expose `primary.key` at pool auth scope; each candidate injects its own key in
    // `wrapMethod`, `buildSingleStreamImpl`, and `makeFetch`.
    auth: { apiKey: { name: 'Workspace provider pool', resolve: async () => ({ auth: { apiKey: 'kovo-pool-per-candidate-key' } }) } },
    api: implementation,
    models: [primaryBuilt.model],
  }))
  return { models, model: primaryBuilt.model }
}

export async function testProvider(
  settings: ProviderConfig,
  record?: CallRecorder,
  extraOptions: Pick<ProviderOptions, 'fetch' | 'resolveHost'> = {},
): Promise<{ ok: true }> {
  const { models, model } = provider(settings, 'connection', {
    record,
    maxCalls: 2,
    maxTransportRetries: 0,
    firstEventTimeoutMs: 35_000,
    idleTimeoutMs: 35_000,
    totalTimeoutMs: 45_000,
    ...extraOptions,
  })
  const stream = models.stream(model, {
    systemPrompt: 'Kovo Hunter connection test. Call kovo_connection with status ready. Do not add prose.',
    messages: [{ role: 'user', content: 'Check the Kovo Hunter connection.', timestamp: Date.now() }],
    tools: [{
      name: 'kovo_connection',
      description: 'Return status ready to confirm this synthetic connection test.',
      parameters: obj({ status: str() }),
    }],
  })
  let toolEvents = false
  for await (const event of stream) {
    if (event.type === 'toolcall_delta' || event.type === 'toolcall_end') toolEvents = true
  }
  const result = await stream.result()
  if (result.stopReason === 'error' || result.stopReason === 'aborted') {
    const error = redact(result.errorMessage ?? '').slice(0, 350)
    if (/(?:Egress host|Egress origin|Plaintext HTTP egress|SSRF policy|never permitted|explicit loopback allowlist|redirect)/i.test(error)) {
      throw new EgressDeniedError('scope_denied', error)
    }
    const match = error.match(/The (?:provider rejected the API key|provider quota or credit balance was exhausted|provider endpoint or model was not found|provider rate limit was reached|model provider returned HTTP \d+)\./)
    throw new Error(match?.[0] ?? 'The provider connection failed. Check the base URL, model, key, and protocol.')
  }
  if (
    !toolEvents ||
    !result.content.some(part => part.type === 'toolCall' && part.name === 'kovo_connection' &&
      part.arguments.status === 'ready')
  ) {
    throw new Error('The model did not return the expected streamed tool call.')
  }
  return { ok: true as const }
}
