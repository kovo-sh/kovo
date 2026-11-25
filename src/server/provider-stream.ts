import type { ProviderSettings, RoleAffinity, ThinkingLevel } from '../domain.ts'
import { createEgressSanitizer, redactSecrets } from './egress-sanitizer.ts'
import type { NamedSecret } from './redact.ts'

type Fields = Record<string, unknown>
type Fragment = { owner: Fields; field: string; text: string }
type Frame = { lines: string[]; data: Fields | '[DONE]' | undefined }
type Prepared = WeakMap<Fields, Set<string>>

export const defaultStreamResponseLimit = 16 * 1024 * 1024
export const maxStreamResponseLimit = 32 * 1024 * 1024
/** Default no-token watchdog window for fast/non-reasoning profiles (ms). */
export const DEFAULT_NO_TOKEN_WATCHDOG_MS = 28_000
/** Medium-thinking profile no-token watchdog window before first/next SSE frame (ms). */
export const MEDIUM_THINKING_NO_TOKEN_WATCHDOG_MS = 45_000
/** High-thinking / reasoning-model no-token watchdog window (ms). */
export const REASONING_NO_TOKEN_WATCHDOG_MS = 60_000
const REASONING_MODEL_RE = /(?:reasoner|thinking|(?:^|[-_/])r1\b|(?:^|[-_/])o[134](?:[-_]|$)|deepseek-v4)/i

/**
 * Profile-aware no-token watchdog window. Reasoning / thinking models routinely pause 25–45 s
 * before emitting their first SSE frame (or between reasoning bursts under concurrent load),
 * whereas a flat 28 s threshold aborts healthy turns. An explicit `KOVO_PROVIDER_NO_TOKEN_MS`
 * override always wins (clamped 5–180 s).
 */
export function resolveProfileNoTokenWatchdogMs(
  profile?: { model?: string; thinkingLevel?: ThinkingLevel; roleAffinity?: RoleAffinity },
  env: NodeJS.ProcessEnv = process.env,
): number {
  const raw = Number(env.KOVO_PROVIDER_NO_TOKEN_MS)
  if (Number.isFinite(raw) && raw > 0) {
    return Math.max(5_000, Math.min(180_000, Math.floor(raw)))
  }
  if (!profile) return DEFAULT_NO_TOKEN_WATCHDOG_MS
  if (
    profile.thinkingLevel === 'high' ||
    profile.roleAffinity === 'reasoning' ||
    (typeof profile.model === 'string' && REASONING_MODEL_RE.test(profile.model))
  ) {
    return REASONING_NO_TOKEN_WATCHDOG_MS
  }
  if (profile.thinkingLevel === 'medium') {
    return MEDIUM_THINKING_NO_TOKEN_WATCHDOG_MS
  }
  return DEFAULT_NO_TOKEN_WATCHDOG_MS
}

export interface StreamSanitizeOptions {
  secrets?: readonly NamedSecret[]
  responseLimit?: number
  /**
   * Called once as soon as the first non-empty body chunk arrives from upstream, so callers can
   * disarm connect / first-event timers without aborting an active stream mid-body.
   */
  onFirstChunk?: () => void
  /**
   * Called in real time as each upstream SSE data frame arrives (before end-of-stream redaction
   * buffering completes). Used to reset provider idle/no-token watchdogs so active streams are
   * never misclassified as stalled.
   */
  onActivity?: () => void
}

const replacement = '[redacted]'
const credentialField = /^(?:authorization|proxy-authorization|cookie|set-cookie|password|api[_-]?key|token|session[_-]?(?:id|key)|client[_-]?secret|service[_-]?role[_-]?key)$/i
type FragmentMode = 'text' | 'json_args' | 'raw_args'
const terminalEvents = new Set(['response.completed', 'response.incomplete', 'response.failed', 'message_stop', 'error'])
const messageEvents = new Set([
  'message_start', 'message_delta', 'message_stop', 'content_block_start', 'content_block_delta', 'content_block_stop',
])
const responseChannels = new Map([
  ['response.output_text.delta', 'text'],
  ['response.refusal.delta', 'text'],
  ['response.reasoning_text.delta', 'thinking'],
  ['response.reasoning_summary_text.delta', 'thinking'],
  ['response.function_call_arguments.delta', 'arguments'],
  ['response.custom_tool_call_input.delta', 'input'],
])
const messageDeltaFields = new Map([
  ['text_delta', 'text'],
  ['thinking_delta', 'thinking'],
  ['signature_delta', 'signature'],
  ['input_json_delta', 'partial_json'],
])

function fields(value: unknown): Fields | undefined {
  return value && typeof value === 'object' && !Array.isArray(value) ? value as Fields : undefined
}

export function redactProviderText(value: string, key: string, secrets: readonly NamedSecret[] = []): string {
  return createEgressSanitizer({ providerKey: key, secrets }).redactText(value, 'llm_context')
}

function fragment(owner: Fields | undefined, field: string): Fragment | undefined {
  const text = owner?.[field]
  return owner && typeof text === 'string' ? { owner, field, text } : undefined
}

/**
 * Redacts only the exact provider API key and registered vault/persona secrets (including
 * URL-encoded, base64/base64url, JSON-escaped, and HTML-entity variants) via EgressSanitizer
 * without applying heuristic credential regexes (H-25).
 */
export function redactExactSecrets(value: string, key: string, secrets: readonly NamedSecret[] = []): string {
  return redactSecrets(value, secrets, { providerKey: key })
}

function sanitizeToolArgumentValue(
  value: unknown,
  key: string,
  secrets: readonly NamedSecret[] = [],
): unknown {
  return createEgressSanitizer({ providerKey: key, secrets }).sanitizeValue(value, 'llm_tool_args')
}

function redactArguments(value: string, key: string, secrets: readonly NamedSecret[]): string {
  if (!value.trim()) return value
  let parsed: unknown
  try {
    parsed = JSON.parse(value)
  } catch {
    return '{}'
  }
  const safe = JSON.stringify(sanitizeToolArgumentValue(parsed, key, secrets))
  return safe === JSON.stringify(parsed) ? value : safe
}

function prepareFragments(
  items: Fragment[],
  key: string,
  prepared: Prepared,
  secrets: readonly NamedSecret[],
  mode: FragmentMode = 'text',
) {
  if (!items.length) return
  const joined = items.map(item => item.text).join('')
  const safe = mode === 'json_args'
    ? redactArguments(joined, key, secrets)
    : mode === 'raw_args'
      ? redactExactSecrets(joined, key, secrets)
      : redactProviderText(joined, key, secrets)
  let offset = 0
  for (const [index, item] of items.entries()) {
    const end = index === items.length - 1 ? undefined : offset + item.text.length
    item.owner[item.field] = safe.slice(offset, end)
    offset += item.text.length
    if (!prepared.has(item.owner)) prepared.set(item.owner, new Set())
    prepared.get(item.owner)!.add(item.field)
  }
}

export function sanitizeProviderValue(
  value: unknown,
  key: string,
  prepared: Prepared = new WeakMap(),
  secrets: readonly NamedSecret[] = [],
): unknown {
  if (typeof value === 'string') return redactProviderText(value, key, secrets)
  if (Array.isArray(value)) return value.map(item => sanitizeProviderValue(item, key, prepared, secrets))
  const record = fields(value)
  if (!record) return value
  if (record.type === 'message' && Array.isArray(record.content)) {
    const parts = record.content.flatMap(item => {
      const part = fields(item)
      const text = fragment(part, part?.type === 'refusal' ? 'refusal' : 'text')
      return text ? [text] : []
    })
    prepareFragments(parts, key, prepared, secrets)
  }
  return Object.fromEntries(Object.entries(record).map(([name, item]) => {
    const safeName = redactProviderText(name, key, secrets)
    if (prepared.get(record)?.has(name)) return [safeName, item]
    if (credentialField.test(name)) return [safeName, replacement]
    if (
      name === 'arguments' && typeof item === 'string' &&
      (record.type === 'function_call' || record.type === 'response.function_call_arguments.done')
    ) {
      return [safeName, redactArguments(item, key, secrets)]
    }
    if (
      name === 'input' && typeof item === 'string' &&
      (record.type === 'custom_tool_call' || record.type === 'response.custom_tool_call_input.done')
    ) {
      return [safeName, redactExactSecrets(item, key, secrets)]
    }
    if (name === 'input' && record.type === 'tool_use') {
      return [safeName, sanitizeToolArgumentValue(item, key, secrets)]
    }
    return [safeName, sanitizeProviderValue(item, key, prepared, secrets)]
  }))
}

function prepareDeltas(frames: Frame[], key: string, secrets: readonly NamedSecret[]): Prepared {
  const groups = new Map<string, { mode: FragmentMode; parts: Fragment[] }>()
  function add(protocol: 'responses' | 'messages', index: unknown, channel: string, part: Fragment | undefined) {
    if (!part) return
    const id = JSON.stringify([protocol, index, channel])
    let group = groups.get(id)
    if (!group) {
      const mode: FragmentMode = (channel === 'arguments' || channel === 'partial_json')
        ? 'json_args'
        : channel === 'input'
          ? 'raw_args'
          : 'text'
      group = { mode, parts: [] }
      groups.set(id, group)
    }
    group.parts.push(part)
  }
  for (const { data } of frames) {
    if (!data || data === '[DONE]') continue
    const type = String(data.type)
    const channel = responseChannels.get(type)
    if (channel) add('responses', data.output_index, channel, fragment(data, 'delta'))
    else if (type === 'response.output_item.added') {
      const item = fields(data.item)
      if (item?.type === 'function_call') add('responses', data.output_index, 'arguments', fragment(item, 'arguments'))
      if (item?.type === 'custom_tool_call') add('responses', data.output_index, 'input', fragment(item, 'input'))
    } else if (type === 'content_block_delta') {
      const delta = fields(data.delta)
      const field = messageDeltaFields.get(String(delta?.type))
      if (field) add('messages', data.index, field, fragment(delta, field))
    } else if (type === 'content_block_start') {
      const block = fields(data.content_block)
      for (const field of ['text', 'thinking', 'signature']) add('messages', data.index, field, fragment(block, field))
    }
  }
  const prepared: Prepared = new WeakMap()
  for (const group of groups.values()) prepareFragments(group.parts, key, prepared, secrets, group.mode)
  return prepared
}

function isData(line: string): boolean {
  return line === 'data' || line.startsWith('data:')
}

function readFrame(text: string, protocol: ProviderSettings['protocol']): Frame {
  const lines = text.split('\n')
  const values = lines.filter(isData).map(line => line.slice(5).replace(/^ /, ''))
  if (!values.length) return { lines, data: undefined }
  const raw = values.join('\n')
  if (raw === '[DONE]') return { lines, data: raw }
  let data: Fields | undefined
  try {
    data = fields(JSON.parse(raw))
  } catch {
    /* Keep the provider's payload out of parse errors. */
  }
  if (!data) throw new Error('The model returned invalid streaming data.')
  if (protocol === 'messages') {
    const event = lines.findLast(line => line === 'event' || line.startsWith('event:'))?.slice(6).replace(/^ /, '') ?? ''
    if ((messageEvents.has(event) || messageEvents.has(String(data.type))) && data.type !== event) {
      throw new Error('The model returned a mismatched Messages event.')
    }
  }
  return { lines, data }
}

function isSecretList(value: readonly NamedSecret[] | StreamSanitizeOptions): value is readonly NamedSecret[] {
  return Array.isArray(value)
}

export function sanitizeProviderStream(
  body: ReadableStream<Uint8Array>,
  key: string,
  protocol: ProviderSettings['protocol'],
  secretsOrOptions: readonly NamedSecret[] | StreamSanitizeOptions = [],
  responseLimitArg?: number,
): ReadableStream<Uint8Array> {
  const secrets = isSecretList(secretsOrOptions) ? secretsOrOptions : (secretsOrOptions.secrets ?? [])
  const onFirstChunk = isSecretList(secretsOrOptions) ? undefined : secretsOrOptions.onFirstChunk
  const onActivity = isSecretList(secretsOrOptions) ? undefined : secretsOrOptions.onActivity
  const requestedLimit = isSecretList(secretsOrOptions)
    ? (responseLimitArg ?? defaultStreamResponseLimit)
    : (secretsOrOptions.responseLimit ?? responseLimitArg ?? defaultStreamResponseLimit)
  const responseLimit = Math.max(1024, Math.min(maxStreamResponseLimit, Math.floor(requestedLimit)))

  let pending = ''
  let size = 0
  let finished = false
  let trailingCr = false
  let sawFirstChunk = false
  const frames: Frame[] = []
  const decoder = new TextDecoder()
  const encoder = new TextEncoder()
  type Output = TransformStreamDefaultController<Uint8Array>

  function emit(controller: Output) {
    const prepared = prepareDeltas(frames, key, secrets)
    for (const frame of frames.splice(0)) {
      const first = frame.lines.findIndex(isData)
      const safe = frame.data === '[DONE]'
        ? '[DONE]'
        : JSON.stringify(sanitizeProviderValue(frame.data, key, prepared, secrets))
      const lines = frame.lines.flatMap((line, index) => {
        if (!isData(line)) return [redactProviderText(line, key, secrets)]
        return index === first ? ['data: ' + safe] : []
      })
      controller.enqueue(encoder.encode(lines.join('\n') + '\n\n'))
    }
  }

  function push(text: string, controller: Output) {
    const frame = readFrame(text, protocol)
    if (finished && frame.data && frame.data !== '[DONE]') {
      throw new Error('The model returned data after the turn ended.')
    }
    frames.push(frame)
    if (frame.data !== undefined && onActivity) {
      try { onActivity() } catch { /* activity signal must never break the stream */ }
    }
    if (frame.data === '[DONE]' || terminalEvents.has(String(frame.data?.type))) finished = true
    if (finished) emit(controller)
  }

  function append(decoded: string, controller: Output, eof = false) {
    const text = (trailingCr ? '\r' : '') + decoded
    trailingCr = !eof && text.endsWith('\r')
    pending += (trailingCr ? text.slice(0, -1) : text).replace(/\r\n?/g, '\n')
    let boundary: number
    while ((boundary = pending.indexOf('\n\n')) !== -1) {
      const frame = pending.slice(0, boundary)
      pending = pending.slice(boundary + 2)
      push(frame, controller)
    }
  }

  return body.pipeThrough(new TransformStream<Uint8Array, Uint8Array>({
    transform(chunk, controller) {
      if (!sawFirstChunk && chunk.byteLength > 0) {
        sawFirstChunk = true
        if (onFirstChunk) {
          try { onFirstChunk() } catch { /* first-chunk signal must never break the stream */ }
        }
      }
      size += chunk.byteLength
      if (size > responseLimit) throw new Error('The model response exceeded Kovo Hunter’s size limit.')
      append(decoder.decode(chunk, { stream: true }), controller)
    },
    flush(controller) {
      append(decoder.decode(), controller, true)
      if (pending.trim()) push(pending, controller)
      emit(controller)
    },
  }))
}
