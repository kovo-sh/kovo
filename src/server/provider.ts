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
  scrubExactSecretsValue,
} from './provider-stream.ts'
import type { SecretSource } from './provider-stream.ts'
import { redact } from './redact.ts'
import type { NamedSecret } from './redact.ts'

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
  costUsd: number
  profileId?: string
}

export type UsageCallback = (usage: UsageEvent) => void

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
    const openaiCached = Number(inputDetails?.cached_tokens ?? promptDetails?.cached_tokens ?? 0)
    const msgCached = Number(usage.cache_read_input_tokens ?? 0)
    if (Number.isFinite(inp) && inp > this.rawInputTokens) this.rawInputTokens = inp
    if (Number.isFinite(out) && out > this.outputTokens) this.outputTokens = out
    if (Number.isFinite(openaiCached) && openaiCached > this.cachedInputTokens) this.cachedInputTokens = openaiCached
    if (Number.isFinite(msgCached) && msgCached > this.anthropicCacheRead) this.anthropicCacheRead = msgCached
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
    // H-8: Scrub live registered/rotated secrets from outbound model requests via exact-only
    // matching (zero heuristics so JSON structure and tool-call code remain byte-intact).
    const currentSecrets = getSecrets()
    const scrubbedPayload = scrubExactSecretsValue(payload, settings.key, currentSecrets) as Record<string, unknown>
    const outboundRaw = scrubbedPayload === payload ? raw : JSON.stringify(scrubbedPayload)
    if (outboundRaw !== raw && Buffer.byteLength(outboundRaw) > maxRequestBytes) {
      throw new Error('The model request exceeded Kovo Hunter’s size limit.')
    }

    const targetUrl = beta ? endpoint + '?beta=true' : endpoint
    const allowLocalModel = isLocalModelEnvEnabled()

    let transportRetry = 0
    for (;;) {
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
            const waitMs = Math.min(4_000, retryBaseMs * (2 ** (transportRetry - 1)))
            if (waitMs > 0) {
              await delay(waitMs, undefined, { signal: totalSignal })
            }
            continue
          }
          const message = effectiveStatus === 401 || effectiveStatus === 403
            ? 'The provider rejected the API key.'
            : effectiveStatus === 402
              ? 'The provider quota or credit balance was exhausted.'
              : effectiveStatus === 404
                ? 'The provider endpoint or model was not found.'
                : effectiveStatus === 429
                  ? 'The provider rate limit was reached.'
                  : `The model provider returned HTTP ${effectiveStatus}.`
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
          if (options.onUsage) {
            const usage = usageAccumulator.snapshot(settings.protocol)
            if (usage.inputTokens > 0 || usage.outputTokens > 0) {
              try {
                options.onUsage({
                  ...usage,
                  costUsd: estimateCostUsd(settings, usage.inputTokens, usage.outputTokens, usage.cachedInputTokens),
                  profileId,
                })
              } catch { /* usage observer must never throw */ }
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
            failStream(err)
            if (!streamAbortController.signal.aborted) {
              streamAbortController.abort(err)
            }
          }, idleTimeoutMs)
          idleTimer.unref?.()
        }

        onFirstEventTimeout = err => failStream(err)
        onTotalAbortHook = () => {
          const reason = totalSignal.reason
          const err = reason instanceof Error
            ? reason
            : new Error(typeof reason === 'string' && reason ? reason : 'The model stream was aborted.')
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
            finalize()
            if (!streamAbortController.signal.aborted) {
              streamAbortController.abort(new Error('The model stream consumer canceled.'))
            }
          },
        }
        const monitor = new TransformStream<Uint8Array, Uint8Array>(monitorTransformer as Transformer<Uint8Array, Uint8Array>)

        handoffToStream = true
        void sanitized.pipeTo(monitor.writable)
          .catch(() => undefined)
          .finally(() => finalize())

        return new Response(monitor.readable, {
          status: response.status,
          headers: { 'content-type': 'text/event-stream' },
        })
      } catch (error) {
        if (firstEventController.signal.aborted && !totalSignal.aborted) {
          throw firstEventController.signal.reason instanceof Error
            ? firstEventController.signal.reason
            : firstEventTimeoutError()
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
  const send = makeFetch(settings, scenario, options, callCounter, profileId, fetchInternal)
  const connection = scenario === 'connection'
  const chooseEvidenceTool = (transcript: { messages: { role: string }[] }) =>
    (scenario === 'worker-analysis' || scenario === 'response-analysis') && transcript.messages.at(-1)?.role === 'user'
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

  const implementation: ProviderStreams = api === 'openai-responses' ? {
    stream: (selected, transcript, sOpts) => responses(selected as Model<'openai-responses'>, transcript, {
      ...sOpts,
      ...streamOpts,
      ...(effectiveThinking !== 'off' ? { reasoningEffort: effectiveThinking } : { reasoningEffort: undefined }),
      ...(connection ? { toolChoice: 'required' as const } : {}),
    }),
    streamSimple: (selected, transcript, sOpts) =>
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
  } : {
    stream: (selected, transcript, sOpts) => messages(selected as Model<'anthropic-messages'>, transcript, {
      ...sOpts,
      ...streamOpts,
      thinkingEnabled,
      ...(thinkingEnabled ? { effort: effectiveThinking } : {}),
      ...(connection ? { toolChoice: { type: 'tool' as const, name: 'kovo_connection' } } : {}),
    }),
    streamSimple: (selected, transcript, sOpts) =>
      chooseEvidenceTool(transcript)
        ? messages(selected as Model<'anthropic-messages'>, transcript, {
          ...sOpts, ...streamOpts, thinkingEnabled: false, toolChoice: { type: 'tool', name: 'derive_evidence' },
        })
        : simpleMessages(selected as Model<'anthropic-messages'>, transcript, {
          ...sOpts,
          ...streamOpts,
          ...(thinkingEnabled ? { reasoning: effectiveThinking } : {}),
        }),
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
  if (/aborted|cancelled|canceled|budget|exceeded Kovo Hunter’s size limit|Unexpected model endpoint|refused by SSRF policy|never permitted|Plaintext HTTP egress|without local-lab or explicit loopback/i.test(message)) {
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
  const retryBaseMs = options.transportRetryBaseMs !== undefined && Number.isFinite(options.transportRetryBaseMs)
    ? Math.max(0, Math.floor(options.transportRetryBaseMs))
    : defaultTransportRetryBaseMs

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
            const built = buildSingleStreamImpl(candidate, scenario, poolOptions, callCounter, candidate.id, {
              chargeLogicalTurn: false,
              retryTransientInFetch: false,
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
                  if (!decision.hard && idx === ordered.length - 1 && transientAttempts < maxTransportRetries) {
                    transientAttempts++
                    attempt++
                    const waitMs = Math.min(4_000, retryBaseMs * 2 ** (attempt - 1))
                    if (waitMs > 0) await delay(waitMs, undefined, { signal: options.signal })
                    continue
                  }
                  break
                }
              }
              if (res.stopReason !== 'error') options.onProfileSuccess?.(candidate.id)
              return res
            } catch (error) {
              if (emitted) throw error
              const msg = error instanceof Error ? error.message : String(error)
              const decision = classifyFailoverError(msg)
              if (!decision.failover) throw error
              options.onProfileFailure?.(candidate.id, msg, decision.hard)
              lastError = error
              if (!decision.hard && idx === ordered.length - 1 && transientAttempts < maxTransportRetries) {
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
