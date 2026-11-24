import { setTimeout as delay } from 'node:timers/promises'
import { createModels, createProvider } from '@earendil-works/pi-ai/models'
import { stream as responses, streamSimple as simpleResponses } from '@earendil-works/pi-ai/api/openai-responses'
import { stream as messages, streamSimple as simpleMessages } from '@earendil-works/pi-ai/api/anthropic-messages'
import type { Api, Model, ProviderStreams } from '@earendil-works/pi-ai'
import { obj, str } from '@earendil-works/pi-schema'
import { DEFAULT_PROVIDER } from '../domain.ts'
import type { ProviderSettings, RoleAffinity, ThinkingLevel } from '../domain.ts'
import type { ResolvedModelProfile } from './model-settings.ts'
import { defaultStreamResponseLimit, redactProviderText, sanitizeProviderStream, sanitizeProviderValue } from './provider-stream.ts'
import { redact } from './redact.ts'
import type { NamedSecret } from './redact.ts'

type Protocol = 'openai-responses' | 'anthropic-messages'

const providerId = 'guardian'
export const defaultMaxRequestBytes = 4 * 1024 * 1024
export const maxRequestBytesCeiling = 12 * 1024 * 1024
export const defaultFirstEventTimeoutMs = 120_000
export const defaultIdleTimeoutMs = 180_000
export const defaultTotalTimeoutMs = 600_000
export const defaultMaxCalls = 220

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
  secrets?: readonly NamedSecret[]
  maxCalls?: number
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

export function extractUsageFromSse(
  sseText: string,
  protocol: 'responses' | 'messages' = 'responses',
): { inputTokens: number; cachedInputTokens: number; outputTokens: number } {
  let rawInputTokens = 0
  let cachedInputTokens = 0
  let outputTokens = 0
  let anthropicCacheRead = 0
  for (const line of sseText.split('\n')) {
    if (!line.startsWith('data: ') || line === 'data: [DONE]') continue
    try {
      const data = JSON.parse(line.slice(6)) as Record<string, unknown>
      const responseUsage = (data.response as Record<string, unknown> | undefined)?.usage as Record<string, unknown> | undefined
      const topUsage = data.usage as Record<string, unknown> | undefined
      const msgUsage = (data.message as Record<string, unknown> | undefined)?.usage as Record<string, unknown> | undefined
      const usage = responseUsage ?? topUsage ?? msgUsage
      if (!usage) continue
      const inp = Number(usage.input_tokens ?? usage.prompt_tokens ?? 0)
      const out = Number(usage.output_tokens ?? usage.completion_tokens ?? 0)
      const inputDetails = usage.input_tokens_details as Record<string, unknown> | undefined
      const promptDetails = usage.prompt_tokens_details as Record<string, unknown> | undefined
      const openaiCached = Number(inputDetails?.cached_tokens ?? promptDetails?.cached_tokens ?? 0)
      const msgCached = Number(usage.cache_read_input_tokens ?? 0)
      if (Number.isFinite(inp) && inp > rawInputTokens) rawInputTokens = inp
      if (Number.isFinite(out) && out > outputTokens) outputTokens = out
      if (Number.isFinite(openaiCached) && openaiCached > cachedInputTokens) cachedInputTokens = openaiCached
      if (Number.isFinite(msgCached) && msgCached > anthropicCacheRead) anthropicCacheRead = msgCached
    } catch {
      // Ignore unparseable frames.
    }
  }
  if (protocol === 'messages' && anthropicCacheRead > 0) {
    // Anthropic Messages reports `input_tokens` excluding `cache_read_input_tokens`.
    return {
      inputTokens: rawInputTokens + anthropicCacheRead,
      cachedInputTokens: anthropicCacheRead,
      outputTokens,
    }
  }
  const effectiveCached = Math.min(rawInputTokens, Math.max(cachedInputTokens, anthropicCacheRead))
  return { inputTokens: rawInputTokens, cachedInputTokens: effectiveCached, outputTokens }
}

async function readStreamWithIdleTimeout(
  stream: ReadableStream<Uint8Array>,
  idleTimeoutMs: number,
  signal: AbortSignal,
  registerActivityReset?: (reset: () => void) => void,
): Promise<string> {
  const reader = stream.getReader()
  const decoder = new TextDecoder()
  const parts: string[] = []
  try {
    for (;;) {
      signal.throwIfAborted()
      let timer: ReturnType<typeof setTimeout> | undefined
      let rejectIdle: ((err: Error) => void) | undefined
      const armTimer = () => {
        if (timer) clearTimeout(timer)
        timer = setTimeout(() => rejectIdle?.(new Error('The model stream timed out while waiting for data.')), idleTimeoutMs)
      }
      const idle = new Promise<never>((_, reject) => {
        rejectIdle = reject
        armTimer()
      })
      registerActivityReset?.(armTimer)
      const onAbort = () => {
        if (timer) clearTimeout(timer)
      }
      signal.addEventListener('abort', onAbort, { once: true })
      let next: ReadableStreamReadResult<Uint8Array>
      try {
        next = await Promise.race([reader.read(), idle])
      } finally {
        registerActivityReset?.(() => undefined)
        if (timer) clearTimeout(timer)
        signal.removeEventListener('abort', onAbort)
      }
      if (next.done) break
      parts.push(decoder.decode(next.value, { stream: true }))
    }
    parts.push(decoder.decode())
    return parts.join('')
  } finally {
    await reader.cancel().catch(() => undefined)
  }
}

function makeFetch(
  settings: ProviderConfig,
  scenario: string,
  options: ProviderOptions,
  callCounter: { count: number; maxCalls: number },
  profileId?: string,
) {
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
  const secrets = options.secrets ?? []

  const send: typeof fetch = async (input, init) => {
    options.beforeCall?.()
    if (++callCounter.count > callCounter.maxCalls) {
      throw new BudgetExceededError('The model call budget for this operation was reached.')
    }
    const request = new Request(input, init)
    const actual = new URL(request.url)
    const beta = settings.protocol === 'messages' && actual.search === '?beta=true'
    if (beta) actual.search = ''
    if (actual.href !== endpoint || request.method !== 'POST') throw new Error('Unexpected model endpoint.')
    if (process.env.GUARDIAN_OFFLINE === '1' && actual.hostname !== '127.0.0.1') {
      throw new Error('Offline mode requires a loopback model fixture endpoint.')
    }
    const headers = new Headers(request.headers)
    if (new URL(endpoint).origin === 'https://openrouter.ai') {
      headers.delete('x-api-key')
      headers.set('authorization', 'Bearer ' + settings.key)
    }

    const raw = await request.text()
    if (Buffer.byteLength(raw) > maxRequestBytes) {
      throw new Error('The model request exceeded Guardian’s size limit.')
    }
    const payload = JSON.parse(raw) as Record<string, unknown>
    const totalSignal = AbortSignal.any([
      request.signal,
      AbortSignal.timeout(totalTimeoutMs),
      ...(options.signal ? [options.signal] : []),
    ])
    const connectSignal = AbortSignal.any([totalSignal, AbortSignal.timeout(firstEventTimeoutMs)])
    const response = await fetch(beta ? endpoint + '?beta=true' : endpoint, {
      method: 'POST',
      headers,
      body: raw,
      redirect: 'error',
      signal: connectSignal,
    })

    const contentType = response.headers.get('content-type') ?? 'application/json'
    const recordResponse = options.record && ((body: string) => options.record!({
      scenario,
      endpoint: redactProviderText(new URL(endpoint).pathname, settings.key, secrets),
      request: sanitizeProviderValue(payload, settings.key, undefined, secrets) as Record<string, unknown>,
      status: response.status,
      contentType: redactProviderText(contentType, settings.key, secrets),
      body,
    }))

    if (!response.ok) {
      const errText = await response.text().catch(() => '')
      const effectiveStatus = response.status === 429 && isQuotaBody(errText) ? 402 : response.status
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
      await response.body?.cancel()
      throw new Error('The provider did not return a streaming response.')
    }

    let resetIdleTimer: () => void = () => undefined
    const sanitized = sanitizeProviderStream(response.body, settings.key, settings.protocol, {
      secrets,
      responseLimit,
      onActivity: () => {
        resetIdleTimer()
        options.onStreamActivity?.()
      },
    })
    const text = await readStreamWithIdleTimeout(sanitized, idleTimeoutMs, totalSignal, reset => {
      resetIdleTimer = reset
    })
    recordResponse?.(text)

    if (options.onUsage) {
      const usage = extractUsageFromSse(text, settings.protocol)
      if (usage.inputTokens > 0 || usage.outputTokens > 0) {
        options.onUsage({
          ...usage,
          costUsd: estimateCostUsd(settings, usage.inputTokens, usage.outputTokens, usage.cachedInputTokens),
          profileId,
        })
      }
    }

    return new Response(text, {
      status: response.status,
      headers: { 'content-type': 'text/event-stream' },
    })
  }
  return send
}

function buildSingleStreamImpl(
  settings: ProviderConfig,
  scenario: string,
  options: ProviderOptions,
  callCounter: { count: number; maxCalls: number },
  profileId?: string,
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
  const send = makeFetch(settings, scenario, options, callCounter, profileId)
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
      ...(connection ? { toolChoice: { type: 'tool' as const, name: 'guardian_connection' } } : {}),
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
  const { model, implementation } = buildSingleStreamImpl(settings, scenario, options, callCounter, settings.id)
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
  if (/aborted|cancelled|canceled|budget|exceeded Guardian’s size limit|Unexpected model endpoint/i.test(message)) {
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
  const primaryBuilt = buildSingleStreamImpl(primary, scenario, options, callCounter, primary.id)

  const wrapMethod = (method: 'stream' | 'streamSimple'): ProviderStreams['stream'] => {
    return (_selected, transcript, sOpts) => {
      const estimatedTokens = Math.ceil(JSON.stringify(transcript).length / 3.5)
      const ordered = orderProfiles(sorted, estimatedTokens, options.roleAffinity)

      // Execute failover strictly inside the safe window (before yielding the first non-error event).
      const iter = (async function* () {
        let lastError: unknown
        let transientAttempts = 0
        const maxTransientRetries = ordered.length === 1 ? 2 : 1

        for (let idx = 0; idx < ordered.length; idx++) {
          const candidate = ordered[idx]
          if (options.signal?.aborted) throw options.signal.reason ?? new Error('Aborted')

          let attempt = 0
          for (;;) {
            const built = buildSingleStreamImpl(candidate, scenario, options, callCounter, candidate.id)
            const stream = built.implementation[method](built.model, transcript, sOpts)
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
                    if (!decision.hard && idx === ordered.length - 1 && transientAttempts < maxTransientRetries) {
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
                const waitMs = Math.min(4_000, 350 * 2 ** (attempt - 1))
                await delay(waitMs, undefined, { signal: options.signal })
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
                  if (!decision.hard && idx === ordered.length - 1 && transientAttempts < maxTransientRetries) {
                    transientAttempts++
                    attempt++
                    const waitMs = Math.min(4_000, 350 * 2 ** (attempt - 1))
                    await delay(waitMs, undefined, { signal: options.signal })
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
              if (!decision.hard && idx === ordered.length - 1 && transientAttempts < maxTransientRetries) {
                transientAttempts++
                attempt++
                const waitMs = Math.min(4_000, 350 * 2 ** (attempt - 1))
                await delay(waitMs, undefined, { signal: options.signal })
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
    auth: { apiKey: { name: 'Workspace provider pool', resolve: async () => ({ auth: { apiKey: primary.key } }) } },
    api: implementation,
    models: [primaryBuilt.model],
  }))
  return { models, model: primaryBuilt.model }
}

export async function testProvider(settings: ProviderConfig, record?: CallRecorder): Promise<{ ok: true }> {
  const { models, model } = provider(settings, 'connection', { record, maxCalls: 2, firstEventTimeoutMs: 35_000, idleTimeoutMs: 35_000, totalTimeoutMs: 45_000 })
  const stream = models.stream(model, {
    systemPrompt: 'Guardian connection test. Call guardian_connection with status ready. Do not add prose.',
    messages: [{ role: 'user', content: 'Check the Guardian connection.', timestamp: Date.now() }],
    tools: [{
      name: 'guardian_connection',
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
    const match = error.match(/The (?:provider rejected the API key|provider quota or credit balance was exhausted|provider endpoint or model was not found|provider rate limit was reached|model provider returned HTTP \d+)\./)
    throw new Error(match?.[0] ?? 'The provider connection failed. Check the base URL, model, key, and protocol.')
  }
  if (
    !toolEvents ||
    !result.content.some(part => part.type === 'toolCall' && part.name === 'guardian_connection' &&
      part.arguments.status === 'ready')
  ) {
    throw new Error('The model did not return the expected streamed tool call.')
  }
  return { ok: true as const }
}
