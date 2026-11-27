import type { ProviderSettings, RoleAffinity, ThinkingLevel } from '../domain.ts'
import { createEgressSanitizer, redactSecrets } from './egress-sanitizer.ts'
import {
  DEFAULT_NO_TOKEN_WATCHDOG_MS,
  MEDIUM_THINKING_NO_TOKEN_WATCHDOG_MS,
  REASONING_NO_TOKEN_WATCHDOG_MS,
  resolveProviderRuntimePolicy,
} from './provider-runtime-policy.ts'
import type { NamedSecret } from './redact.ts'

type Fields = Record<string, unknown>
type Fragment = { owner: Fields; field: string; text: string }
type Frame = { lines: string[]; data: Fields | '[DONE]' | undefined }
type Prepared = WeakMap<Fields, Map<string, string>>

export const defaultStreamResponseLimit = 16 * 1024 * 1024
export const maxStreamResponseLimit = 32 * 1024 * 1024
export {
  DEFAULT_NO_TOKEN_WATCHDOG_MS,
  MEDIUM_THINKING_NO_TOKEN_WATCHDOG_MS,
  REASONING_NO_TOKEN_WATCHDOG_MS,
}

/**
 * Profile-aware no-token watchdog window backed by `resolveProviderRuntimePolicy` (R2-21).
 * Computed strictly from the profile's explicit fields (`thinkingLevel`, `roleAffinity`) with
 * zero model-name regexes. An explicit `KOVO_PROVIDER_NO_TOKEN_MS` override always wins (5–180 s).
 */
export function resolveProfileNoTokenWatchdogMs(
  profile?: { model?: string; thinkingLevel?: ThinkingLevel; roleAffinity?: RoleAffinity },
  env: NodeJS.ProcessEnv = process.env,
): number {
  return resolveProviderRuntimePolicy(profile, { env }).noTokenWatchdogMs
}

export interface ProviderStreamTelemetrySnapshot {
  /** Number of turns aborted due to provider stall (first-event, idle, or no-token watchdog). */
  stallAborts: number
  /** Number of completed turns whose latency exceeded the slow-turn threshold (never counts stall aborts). */
  slowTurns: number
}

export interface ProviderStreamTelemetry {
  recordStallAbort(): void
  recordCompletedTurn(durationMs: number, slowTurnThresholdMs?: number): boolean
  snapshot(): ProviderStreamTelemetrySnapshot
}

/**
 * Splits `stallAborts` (hard timeout/stall cancellations) from `slowTurns` (completed turns that
 * exceeded `slowTurnThresholdMs`) so stream telemetry never conflates the two failure modes.
 */
export function createProviderStreamTelemetry(
  defaultSlowTurnThresholdMs = 20_000,
): ProviderStreamTelemetry {
  let stallAborts = 0
  let slowTurns = 0
  const fallbackThreshold = Number.isFinite(defaultSlowTurnThresholdMs) && defaultSlowTurnThresholdMs > 0
    ? defaultSlowTurnThresholdMs
    : 20_000

  return {
    recordStallAbort() {
      stallAborts += 1
    },
    recordCompletedTurn(durationMs: number, slowTurnThresholdMs?: number): boolean {
      const threshold = typeof slowTurnThresholdMs === 'number' && Number.isFinite(slowTurnThresholdMs) && slowTurnThresholdMs > 0
        ? slowTurnThresholdMs
        : fallbackThreshold
      if (Number.isFinite(durationMs) && durationMs > threshold) {
        slowTurns += 1
        return true
      }
      return false
    },
    snapshot(): ProviderStreamTelemetrySnapshot {
      return { stallAborts, slowTurns }
    },
  }
}

export type SecretSource = readonly NamedSecret[] | (() => readonly NamedSecret[])

export function resolveSecretSource(source?: SecretSource): readonly NamedSecret[] {
  return typeof source === 'function' ? source() : (source ?? [])
}

export interface StreamSanitizeOptions {
  secrets?: SecretSource
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
  /**
   * Called in real time as each parsed upstream SSE data frame arrives (for incremental usage
   * accounting even when a consumer aborts mid-stream before a terminal event).
   */
  onFrame?: (data: Record<string, unknown> | '[DONE]') => void
}

const replacement = '[redacted]'
const credentialField = /^(?:authorization|proxy-authorization|cookie|set-cookie|password|api[_-]?key|token|session[_-]?(?:id|key)|client[_-]?secret|service[_-]?role[_-]?key)$/i
const rawCookieField = /^(?:cookie|set-cookie)$/i
const toolArgHeaderMapKeys = new Set(['headers', 'reqHeaders', 'requestHeaders', 'upgradeHeaders'])
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

export function redactProviderText(value: string, key: string, secrets: SecretSource = []): string {
  return createEgressSanitizer({ providerKey: key, secrets: resolveSecretSource(secrets) }).redactText(value, 'llm_context')
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
export function redactExactSecrets(value: string, key: string, secrets: SecretSource = []): string {
  return redactSecrets(value, resolveSecretSource(secrets), { providerKey: key })
}

/**
 * Null-prototype-safe own data property setter (never mutates prototype on `__proto__` or
 * crashes on reserved keys such as `constructor` / `toString` / `hasOwnProperty`).
 */
function setOwnProperty(target: Record<string, unknown>, key: string, value: unknown): void {
  Object.defineProperty(target, key, {
    value,
    writable: true,
    enumerable: true,
    configurable: true,
  })
}

function ownValue(record: Fields, key: string): unknown {
  return Object.prototype.hasOwnProperty.call(record, key) ? record[key] : undefined
}

function patchRecord(record: Fields, patches: ReadonlyMap<string, unknown>): Fields {
  if (patches.size === 0) return record
  const out: Fields = {}
  for (const key of Object.keys(record)) {
    setOwnProperty(out, key, patches.has(key) ? patches.get(key) : record[key])
  }
  return out
}

/**
 * Copy-on-write recursive exact-secret scrubber over arbitrary JSON values that scrubs ONLY
 * string leaf values and NEVER mutates object keys (R3-H-10). Safe with null-prototype objects
 * and reserved keys (`__proto__`, `constructor`, `toString`).
 */
function scrubStringValuesOnly(node: unknown, scrubString: (value: string) => string): unknown {
  if (typeof node === 'string') return scrubString(node)
  if (Array.isArray(node)) {
    let changed = false
    const mapped = node.map(item => {
      const next = scrubStringValuesOnly(item, scrubString)
      if (next !== item) changed = true
      return next
    })
    return changed ? mapped : node
  }
  const rec = fields(node)
  if (!rec) return node
  let changed = false
  const out: Fields = {}
  for (const key of Object.keys(rec)) {
    const val = rec[key]
    const nextVal = scrubStringValuesOnly(val, scrubString)
    if (nextVal !== val) changed = true
    setOwnProperty(out, key, nextVal)
  }
  return changed ? out : node
}

/**
 * Scrubs exact secrets ONLY inside JSON string values of a serialized tool-call `arguments`
 * payload, never mutating JSON object keys or structure. Preserves exact original string when
 * unchanged. Falls back to string scrubbing only when `raw` is not valid JSON.
 */
function scrubJsonStringValues(raw: string, scrubString: (value: string) => string): string {
  if (!raw) return raw
  let parsed: unknown
  try {
    parsed = JSON.parse(raw)
  } catch {
    return scrubString(raw)
  }
  if (typeof parsed === 'string') {
    const next = scrubString(parsed)
    return next === parsed ? raw : JSON.stringify(next)
  }
  if (!parsed || typeof parsed !== 'object') return raw
  const next = scrubStringValuesOnly(parsed, scrubString)
  return next === parsed ? raw : JSON.stringify(next)
}

interface ProviderScrubHooks {
  scrubText: (value: string) => string
  scrubExact: (value: string) => string
  scrubJsonArgs: (raw: string) => string
  scrubToolInput: (value: unknown) => unknown
  scrubSignature: boolean
  joinMessageContent?: boolean
  prepared?: Prepared
}

function createOutboundScrubHooks(scrubExact: (value: string) => string): ProviderScrubHooks {
  return {
    scrubText: scrubExact,
    scrubExact,
    scrubJsonArgs: raw => scrubJsonStringValues(raw, scrubExact),
    scrubToolInput: value => scrubStringValuesOnly(value, scrubExact),
    scrubSignature: false,
  }
}

function scrubContentBlock(block: unknown, hooks: ProviderScrubHooks): unknown {
  if (typeof block === 'string') return hooks.scrubText(block)
  const rec = fields(block)
  if (!rec) return block
  const blockType = ownValue(rec, 'type')
  const type = typeof blockType === 'string' ? blockType : ''

  // Protocol / opaque / binary blocks: never mutate.
  if (
    type === 'redacted_thinking' ||
    type === 'input_image' ||
    type === 'image' ||
    type === 'tool_addition' ||
    type === 'tool_removal'
  ) {
    return block
  }

  const preparedForRec = hooks.prepared?.get(rec)
  const scrubLeaf = (fieldName: string, raw: string, fn: (v: string) => string): string => {
    if (preparedForRec?.has(fieldName)) return preparedForRec.get(fieldName)!
    return fn(raw)
  }

  const patches = new Map<string, unknown>()
  if (type === 'text' || type === 'input_text' || type === 'output_text' || type === 'summary_text') {
    const text = ownValue(rec, 'text')
    if (typeof text === 'string') {
      const next = scrubLeaf('text', text, hooks.scrubText)
      if (next !== text) patches.set('text', next)
    }
    return patchRecord(rec, patches)
  }

  if (type === 'refusal') {
    const refusal = ownValue(rec, 'refusal')
    if (typeof refusal === 'string') {
      const next = scrubLeaf('refusal', refusal, hooks.scrubText)
      if (next !== refusal) patches.set('refusal', next)
    }
    return patchRecord(rec, patches)
  }

  if (type === 'thinking') {
    // Scrub thinking prose; outbound NEVER touches opaque signature, inbound uses exact-only.
    const thinking = ownValue(rec, 'thinking')
    if (typeof thinking === 'string') {
      const next = scrubLeaf('thinking', thinking, hooks.scrubText)
      if (next !== thinking) patches.set('thinking', next)
    }
    if (hooks.scrubSignature) {
      const signature = ownValue(rec, 'signature')
      if (typeof signature === 'string') {
        const next = scrubLeaf('signature', signature, hooks.scrubExact)
        if (next !== signature) patches.set('signature', next)
      }
    }
    return patchRecord(rec, patches)
  }

  if (type === 'tool_use') {
    // Scrub only string values inside `input`; NEVER mutate keys, `type`, `id`, or `name`.
    const input = ownValue(rec, 'input')
    if (input !== undefined) {
      const next = hooks.scrubToolInput(input)
      if (next !== input) patches.set('input', next)
    }
    return patchRecord(rec, patches)
  }

  if (type === 'tool_result') {
    const content = ownValue(rec, 'content')
    if (typeof content === 'string') {
      const next = scrubLeaf('content', content, hooks.scrubText)
      if (next !== content) patches.set('content', next)
    } else if (Array.isArray(content)) {
      const next = scrubContentBlocks(content, hooks)
      if (next !== content) patches.set('content', next)
    }
    return patchRecord(rec, patches)
  }

  if (type === 'document') {
    for (const fieldName of ['title', 'context'] as const) {
      const val = ownValue(rec, fieldName)
      if (typeof val === 'string') {
        const next = scrubLeaf(fieldName, val, hooks.scrubText)
        if (next !== val) patches.set(fieldName, next)
      }
    }
    const source = fields(ownValue(rec, 'source'))
    if (source && ownValue(source, 'type') === 'text') {
      const data = ownValue(source, 'data')
      if (typeof data === 'string') {
        const nextData = hooks.scrubText(data)
        if (nextData !== data) {
          patches.set('source', patchRecord(source, new Map([['data', nextData]])))
        }
      }
    }
    return patchRecord(rec, patches)
  }

  // Fallback for unknown content blocks: scrub only a `text` string leaf if present; never keys/type.
  const fallbackText = ownValue(rec, 'text')
  if (typeof fallbackText === 'string') {
    const next = scrubLeaf('text', fallbackText, hooks.scrubText)
    if (next !== fallbackText) patches.set('text', next)
  }
  return patchRecord(rec, patches)
}

function scrubContentBlocks(blocks: unknown[], hooks: ProviderScrubHooks): unknown[] {
  let changed = false
  const mapped = blocks.map(block => {
    const next = scrubContentBlock(block, hooks)
    if (next !== block) changed = true
    return next
  })
  return changed ? mapped : blocks
}

function scrubChatToolCalls(toolCalls: unknown[], hooks: ProviderScrubHooks): unknown[] {
  let changed = false
  const mapped = toolCalls.map(entry => {
    const tc = fields(entry)
    if (!tc) return entry
    const fn = fields(ownValue(tc, 'function'))
    if (!fn) return entry
    const args = ownValue(fn, 'arguments')
    if (typeof args !== 'string') return entry
    const nextArgs = hooks.scrubJsonArgs(args)
    if (nextArgs === args) return entry
    changed = true
    return patchRecord(tc, new Map([['function', patchRecord(fn, new Map([['arguments', nextArgs]]))]]))
  })
  return changed ? mapped : toolCalls
}

function scrubStructuredItem(item: unknown, hooks: ProviderScrubHooks): unknown {
  if (typeof item === 'string') return hooks.scrubText(item)
  const rec = fields(item)
  if (!rec) return item
  const itemType = ownValue(rec, 'type')
  const type = typeof itemType === 'string' ? itemType : ''

  // Protocol-only items (tool definitions, effort updates, tool search): never touch.
  if (
    type === 'additional_tools' ||
    type === 'configuration_update' ||
    type === 'tool_search_call' ||
    type === 'tool_search_output' ||
    type === 'tool_addition' ||
    type === 'tool_removal'
  ) {
    return item
  }

  const preparedForRec = hooks.prepared?.get(rec)
  const patches = new Map<string, unknown>()

  if (type === 'function_call') {
    const args = ownValue(rec, 'arguments')
    if (typeof args === 'string') {
      const next = preparedForRec?.has('arguments')
        ? preparedForRec.get('arguments')!
        : hooks.scrubJsonArgs(args)
      if (next !== args) patches.set('arguments', next)
    } else if (args && typeof args === 'object') {
      const next = hooks.scrubToolInput(args)
      if (next !== args) patches.set('arguments', next)
    }
    return patchRecord(rec, patches)
  }

  if (type === 'custom_tool_call') {
    const input = ownValue(rec, 'input')
    if (typeof input === 'string') {
      const next = preparedForRec?.has('input')
        ? preparedForRec.get('input')!
        : hooks.scrubExact(input)
      if (next !== input) patches.set('input', next)
    } else if (input && typeof input === 'object') {
      const next = hooks.scrubToolInput(input)
      if (next !== input) patches.set('input', next)
    }
    return patchRecord(rec, patches)
  }

  if (type === 'function_call_output' || type === 'custom_tool_call_output') {
    const output = ownValue(rec, 'output')
    if (typeof output === 'string') {
      const next = hooks.scrubText(output)
      if (next !== output) patches.set('output', next)
    } else if (Array.isArray(output)) {
      const next = scrubContentBlocks(output, hooks)
      if (next !== output) patches.set('output', next)
    }
    return patchRecord(rec, patches)
  }

  if (type === 'reasoning') {
    // Scrub human-readable summary text only; NEVER touch `encrypted_content`, `id`, `status`, `type`.
    const summary = ownValue(rec, 'summary')
    if (Array.isArray(summary)) {
      const next = scrubContentBlocks(summary, hooks)
      if (next !== summary) patches.set('summary', next)
    }
    return patchRecord(rec, patches)
  }

  // Message items (OpenAI Responses `type: 'message'` or `role`, Anthropic Messages `role`).
  const role = ownValue(rec, 'role')
  if (type === 'message' || typeof role === 'string') {
    const content = ownValue(rec, 'content')
    if (typeof content === 'string') {
      const next = hooks.scrubText(content)
      if (next !== content) patches.set('content', next)
    } else if (Array.isArray(content)) {
      if (hooks.joinMessageContent && content.length > 1) {
        const localPrepared: Prepared = new WeakMap()
        const parts = content.flatMap(entry => {
          const part = fields(entry)
          const text = fragment(part, part?.type === 'refusal' ? 'refusal' : 'text')
          return text ? [text] : []
        })
        if (parts.length > 1) {
          const joined = parts.map(p => p.text).join('')
          const safe = hooks.scrubText(joined)
          let offset = 0
          for (const [idx, part] of parts.entries()) {
            const end = idx === parts.length - 1 ? undefined : offset + part.text.length
            let map = localPrepared.get(part.owner)
            if (!map) {
              map = new Map<string, string>()
              localPrepared.set(part.owner, map)
            }
            map.set(part.field, safe.slice(offset, end))
            offset += part.text.length
          }
          const next = scrubContentBlocks(content, { ...hooks, prepared: localPrepared })
          if (next !== content) patches.set('content', next)
        } else {
          const next = scrubContentBlocks(content, hooks)
          if (next !== content) patches.set('content', next)
        }
      } else {
        const next = scrubContentBlocks(content, hooks)
        if (next !== content) patches.set('content', next)
      }
    }
    const toolCalls = ownValue(rec, 'tool_calls')
    if (Array.isArray(toolCalls)) {
      const next = scrubChatToolCalls(toolCalls, hooks)
      if (next !== toolCalls) patches.set('tool_calls', next)
    }
    return patchRecord(rec, patches)
  }

  return item
}

function isProviderRequestPayload(value: unknown): value is Record<string, unknown> {
  const rec = fields(value)
  if (!rec) return false
  return (
    typeof ownValue(rec, 'model') === 'string' ||
    Array.isArray(ownValue(rec, 'input')) ||
    Array.isArray(ownValue(rec, 'messages')) ||
    typeof ownValue(rec, 'instructions') === 'string' ||
    Array.isArray(ownValue(rec, 'tools')) ||
    ownValue(rec, 'tool_choice') !== undefined ||
    ownValue(rec, 'reasoning') !== undefined
  )
}

/**
 * Structural copy-on-write exact-secret scrubber for outbound LLM provider requests (R3-H-10 / H-8).
 *
 * Walks ONLY content-bearing leaves:
 *  - top-level `instructions` (string) and `system` (string or content blocks)
 *  - `input` (string or OpenAI Responses items: message `content`/`text`/`refusal`,
 *    `function_call.arguments` JSON string values, `custom_tool_call.input`,
 *    `function_call_output.output`, `custom_tool_call_output.output`, `reasoning.summary[].text`)
 *  - `messages` (Anthropic Messages / chat items: `content`, `tool_use.input` values,
 *    `tool_result.content`, `thinking.thinking`, `tool_calls[].function.arguments`)
 *
 * NEVER rewrites object keys or protocol/structural metadata (`model`, `role`, `type`,
 * `tool_choice`, `reasoning.effort`, `reasoning.summary`, `thinking.type`, `tools` definitions
 * and JSON schemas, `status`, `id`, `call_id`, `tool_use_id`, `signature`, `encrypted_content`).
 */
export function scrubOutboundProviderRequest(
  payload: Record<string, unknown>,
  key: string,
  secrets: SecretSource = [],
): Record<string, unknown> {
  const rec = fields(payload)
  if (!rec) return payload
  const resolved = resolveSecretSource(secrets)
  const scrubString = (text: string): string => redactSecrets(text, resolved, { providerKey: key })
  const hooks = createOutboundScrubHooks(scrubString)
  const patches = new Map<string, unknown>()

  const instructions = ownValue(rec, 'instructions')
  if (typeof instructions === 'string') {
    const next = scrubString(instructions)
    if (next !== instructions) patches.set('instructions', next)
  }

  const system = ownValue(rec, 'system')
  if (typeof system === 'string') {
    const next = scrubString(system)
    if (next !== system) patches.set('system', next)
  } else if (Array.isArray(system)) {
    const next = scrubContentBlocks(system, hooks)
    if (next !== system) patches.set('system', next)
  }

  const input = ownValue(rec, 'input')
  if (typeof input === 'string') {
    const next = scrubString(input)
    if (next !== input) patches.set('input', next)
  } else if (Array.isArray(input)) {
    let changed = false
    const mapped = input.map(item => {
      const next = scrubStructuredItem(item, hooks)
      if (next !== item) changed = true
      return next
    })
    if (changed) patches.set('input', mapped)
  }

  const messages = ownValue(rec, 'messages')
  if (Array.isArray(messages)) {
    let changed = false
    const mapped = messages.map(item => {
      const next = scrubStructuredItem(item, hooks)
      if (next !== item) changed = true
      return next
    })
    if (changed) patches.set('messages', mapped)
  }

  return patchRecord(rec, patches)
}

const REDACTION_PLACEHOLDER_RE = /\[persona:[^\]]+\]|\[redacted(?::[^\]]+)?\]/

function valueHasRedactionPlaceholder(value: unknown): boolean {
  if (typeof value === 'string') return REDACTION_PLACEHOLDER_RE.test(value)
  if (Array.isArray(value)) return value.some(valueHasRedactionPlaceholder)
  const rec = fields(value)
  if (!rec) return false
  for (const key of Object.keys(rec)) {
    if (REDACTION_PLACEHOLDER_RE.test(key) || valueHasRedactionPlaceholder(rec[key])) return true
  }
  return false
}

function stableJsonEqual(a: unknown, b: unknown): boolean {
  if (a === b) return true
  try {
    return JSON.stringify(a) === JSON.stringify(b)
  } catch {
    return false
  }
}

const PROTECTED_TOP_LEVEL_FIELDS = [
  'model',
  'tool_choice',
  'reasoning',
  'thinking',
  'output_config',
  'tools',
  'stream',
  'store',
  'include',
  'betas',
  'fallbacks',
  'thread',
  'service_tier',
] as const

const PLACEHOLDER_FORBIDDEN_TOP_LEVEL_FIELDS = [
  'model',
  'tool_choice',
  'reasoning',
  'thinking',
  'output_config',
] as const

const PROTECTED_ITEM_FIELDS = [
  'type',
  'role',
  'id',
  'call_id',
  'name',
  'status',
  'phase',
  'namespace',
  'output_config',
  'encrypted_content',
] as const

const PROTECTED_BLOCK_FIELDS = [
  'type',
  'id',
  'name',
  'tool_use_id',
  'is_error',
  'cache_control',
  'signature',
] as const

function verifyBlocksIntegrity(
  origBlocks: unknown[],
  nextBlocks: unknown[],
  basePath: string,
): string | null {
  if (origBlocks.length !== nextBlocks.length) return `${basePath}.length`
  for (let j = 0; j < origBlocks.length; j++) {
    const origBlock = fields(origBlocks[j])
    const nextBlock = fields(nextBlocks[j])
    if (!origBlock || !nextBlock) continue
    for (const fieldName of PROTECTED_BLOCK_FIELDS) {
      const ov = ownValue(origBlock, fieldName)
      const nv = ownValue(nextBlock, fieldName)
      if (!stableJsonEqual(ov, nv)) return `${basePath}[${j}].${fieldName}`
      if (nv !== undefined && valueHasRedactionPlaceholder(nv)) return `${basePath}[${j}].${fieldName}`
    }
    if (ownValue(origBlock, 'type') === 'redacted_thinking') {
      if (!stableJsonEqual(ownValue(origBlock, 'data'), ownValue(nextBlock, 'data'))) {
        return `${basePath}[${j}].data`
      }
    }
    const origChild = ownValue(origBlock, 'content')
    const nextChild = ownValue(nextBlock, 'content')
    if (Array.isArray(origChild) && Array.isArray(nextChild)) {
      const nested = verifyBlocksIntegrity(origChild, nextChild, `${basePath}[${j}].content`)
      if (nested) return nested
    }
  }
  return null
}

/**
 * Verifies that local outbound scrubbing never mutated protected protocol/structural fields
 * or introduced redaction placeholders into protocol metadata (R3-H-10).
 * Returns `null` when intact, or the violated field path when corrupted.
 */
export function verifyOutboundProviderRequestIntegrity(
  original: Record<string, unknown>,
  scrubbed: Record<string, unknown>,
): string | null {
  const origRec = fields(original)
  const nextRec = fields(scrubbed)
  if (!origRec || !nextRec) return 'payload'

  const origKeys = Object.keys(origRec)
  const nextKeys = Object.keys(nextRec)
  if (origKeys.length !== nextKeys.length || origKeys.some((k, idx) => nextKeys[idx] !== k)) {
    return 'top-level keys'
  }

  for (const fieldName of PROTECTED_TOP_LEVEL_FIELDS) {
    if (!stableJsonEqual(ownValue(origRec, fieldName), ownValue(nextRec, fieldName))) {
      return fieldName
    }
  }
  for (const fieldName of PLACEHOLDER_FORBIDDEN_TOP_LEVEL_FIELDS) {
    const val = ownValue(nextRec, fieldName)
    if (val !== undefined && valueHasRedactionPlaceholder(val)) {
      return fieldName
    }
  }

  const origSystem = ownValue(origRec, 'system')
  const nextSystem = ownValue(nextRec, 'system')
  if (Array.isArray(origSystem) && Array.isArray(nextSystem)) {
    const sysErr = verifyBlocksIntegrity(origSystem, nextSystem, 'system')
    if (sysErr) return sysErr
  }

  for (const listKey of ['input', 'messages'] as const) {
    const origList = ownValue(origRec, listKey)
    const nextList = ownValue(nextRec, listKey)
    if (!Array.isArray(origList) || !Array.isArray(nextList)) continue
    if (origList.length !== nextList.length) return `${listKey}.length`
    for (let i = 0; i < origList.length; i++) {
      const origItem = fields(origList[i])
      const nextItem = fields(nextList[i])
      if (!origItem || !nextItem) continue
      for (const fieldName of PROTECTED_ITEM_FIELDS) {
        const ov = ownValue(origItem, fieldName)
        const nv = ownValue(nextItem, fieldName)
        if (!stableJsonEqual(ov, nv)) return `${listKey}[${i}].${fieldName}`
        if (nv !== undefined && valueHasRedactionPlaceholder(nv)) return `${listKey}[${i}].${fieldName}`
      }
      const origContent = ownValue(origItem, 'content')
      const nextContent = ownValue(nextItem, 'content')
      if (Array.isArray(origContent) && Array.isArray(nextContent)) {
        const blockErr = verifyBlocksIntegrity(origContent, nextContent, `${listKey}[${i}].content`)
        if (blockErr) return blockErr
      }
      const origOutput = ownValue(origItem, 'output')
      const nextOutput = ownValue(nextItem, 'output')
      if (Array.isArray(origOutput) && Array.isArray(nextOutput)) {
        const outErr = verifyBlocksIntegrity(origOutput, nextOutput, `${listKey}[${i}].output`)
        if (outErr) return outErr
      }
    }
  }
  return null
}

/**
 * Copy-on-write exact-secret scrubber over structured JSON payloads (H-8 / H-25 / R3-H-10).
 * For outbound provider request payloads, scrubs ONLY content-bearing leaves and never mutates
 * keys or protocol metadata. For generic JSON values, scrubs string values only (never keys)
 * with null-prototype safety, returning the original object reference when unchanged.
 */
export function scrubExactSecretsValue(
  value: unknown,
  key: string,
  secrets: SecretSource = [],
): unknown {
  if (isProviderRequestPayload(value)) {
    return scrubOutboundProviderRequest(value, key, secrets)
  }
  const resolved = resolveSecretSource(secrets)
  return scrubStringValuesOnly(value, text => redactSecrets(text, resolved, { providerKey: key }))
}

/**
 * Sanitizes model tool-call argument values (`llm_tool_args` channel, H-25):
 * - Exact-known-secret scrubbing ONLY (zero heuristic keyword regexes on code, scripts, tokens,
 *   or auth probes).
 * - Preserves `headers.Cookie` (and `reqHeaders`/`requestHeaders`/`upgradeHeaders`) so HTTP probe
 *   tool calls can supply explicit probe cookies without clobbering, while still redacting any
 *   exact registered vault/session/provider secrets inside them.
 */
function sanitizeToolArgumentValue(
  value: unknown,
  key: string,
  secrets: readonly NamedSecret[] = [],
  inHeadersMap = false,
): unknown {
  if (typeof value === 'string') return redactSecrets(value, secrets, { providerKey: key })
  if (Array.isArray(value)) return value.map(item => sanitizeToolArgumentValue(item, key, secrets, inHeadersMap))
  const rec = fields(value)
  if (!rec) return value
  const out: Record<string, unknown> = {}
  for (const fieldKey of Object.keys(rec)) {
    const item = rec[fieldKey]
    if (!inHeadersMap && rawCookieField.test(fieldKey) && typeof item === 'string') {
      setOwnProperty(out, fieldKey, replacement)
      continue
    }
    const childInHeaders = inHeadersMap || toolArgHeaderMapKeys.has(fieldKey)
    setOwnProperty(out, fieldKey, sanitizeToolArgumentValue(item, key, secrets, childInHeaders))
  }
  return out
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

const PROTECTED_INBOUND_PROTOCOL_FIELDS = new Set<string>([
  'type',
  'event',
  'id',
  'item_id',
  'response_id',
  'call_id',
  'tool_use_id',
  'index',
  'output_index',
  'content_index',
  'summary_index',
  'sequence_number',
  'status',
  'role',
  'model',
  'name',
  'stop_reason',
  'finish_reason',
  'stop_sequence',
  'object',
  'phase',
  'namespace',
  'service_tier',
  'created',
  'created_at',
  'encrypted_content',
  'obfuscation',
  'code',
  'param',
  'is_error',
  'cache_control',
  'tool_choice',
  'tools',
  'usage',
  'incomplete_details',
  'display',
  'effort',
])

const STRUCTURED_ITEM_TYPES = new Set([
  'message',
  'function_call',
  'custom_tool_call',
  'function_call_output',
  'custom_tool_call_output',
  'reasoning',
  'additional_tools',
  'configuration_update',
  'tool_search_call',
  'tool_search_output',
  'tool_addition',
  'tool_removal',
])

const CONTENT_BLOCK_TYPES = new Set([
  'text',
  'input_text',
  'output_text',
  'summary_text',
  'refusal',
  'thinking',
  'redacted_thinking',
  'tool_use',
  'tool_result',
  'document',
  'image',
  'input_image',
])

const INBOUND_INTEGRITY_CONTAINER_FIELDS = [
  'response',
  'message',
  'item',
  'part',
  'delta',
  'content_block',
  'error',
] as const

const INBOUND_INTEGRITY_LIST_FIELDS = [
  'output',
  'content',
  'summary',
] as const

function verifyInboundNodeIntegrity(
  origNode: unknown,
  nextNode: unknown,
  path: string,
): string | null {
  const origRec = fields(origNode)
  const nextRec = fields(nextNode)
  if (!origRec || !nextRec) return null

  const origKeys = Object.keys(origRec)
  const nextKeys = Object.keys(nextRec)
  if (origKeys.length !== nextKeys.length || origKeys.some((k, idx) => nextKeys[idx] !== k)) {
    return `${path}.keys`
  }

  for (const fieldName of PROTECTED_INBOUND_PROTOCOL_FIELDS) {
    if (!Object.prototype.hasOwnProperty.call(origRec, fieldName)) continue
    const ov = ownValue(origRec, fieldName)
    const nv = ownValue(nextRec, fieldName)
    if (!stableJsonEqual(ov, nv)) return `${path}.${fieldName}`
    if (
      nv !== undefined &&
      !valueHasRedactionPlaceholder(ov) &&
      valueHasRedactionPlaceholder(nv)
    ) {
      return `${path}.${fieldName}`
    }
  }

  for (const containerKey of INBOUND_INTEGRITY_CONTAINER_FIELDS) {
    const ov = ownValue(origRec, containerKey)
    const nv = ownValue(nextRec, containerKey)
    if (fields(ov) && fields(nv)) {
      const nested = verifyInboundNodeIntegrity(ov, nv, `${path}.${containerKey}`)
      if (nested) return nested
    }
  }

  for (const listKey of INBOUND_INTEGRITY_LIST_FIELDS) {
    const ov = ownValue(origRec, listKey)
    const nv = ownValue(nextRec, listKey)
    if (Array.isArray(ov) && Array.isArray(nv)) {
      if (ov.length !== nv.length) return `${path}.${listKey}.length`
      for (let i = 0; i < ov.length; i++) {
        const nested = verifyInboundNodeIntegrity(ov[i], nv[i], `${path}.${listKey}[${i}]`)
        if (nested) return nested
      }
    }
  }

  return null
}

/**
 * Verifies that local inbound stream scrubbing never rewrote JSON object keys or mutated
 * protected SSE protocol fields (`type`, `event`, `id`, `index`, `status`, `role`, `stop_reason`,
 * `finish_reason`, etc.) or introduced redaction placeholders into protocol metadata (R4-H-17).
 * Returns `null` when intact, or the violated field path when corrupted.
 */
export function verifyInboundProviderFrameIntegrity(
  original: Record<string, unknown>,
  scrubbed: Record<string, unknown>,
): string | null {
  const origRec = fields(original)
  const nextRec = fields(scrubbed)
  if (!origRec || !nextRec) return 'frame'
  return verifyInboundNodeIntegrity(origRec, nextRec, 'frame')
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
    let ownerMap = prepared.get(item.owner)
    if (!ownerMap) {
      ownerMap = new Map<string, string>()
      prepared.set(item.owner, ownerMap)
    }
    ownerMap.set(item.field, safe.slice(offset, end))
    offset += item.text.length
  }
}

function createInboundScrubHooks(
  key: string,
  resolved: readonly NamedSecret[],
  prepared: Prepared,
): ProviderScrubHooks {
  return {
    scrubText: text => redactProviderText(text, key, resolved),
    scrubExact: text => redactExactSecrets(text, key, resolved),
    scrubJsonArgs: raw => redactArguments(raw, key, resolved),
    scrubToolInput: value => sanitizeToolArgumentValue(value, key, resolved),
    scrubSignature: true,
    joinMessageContent: true,
    prepared,
  }
}

function sanitizeInboundDelta(
  delta: Fields,
  hooks: ProviderScrubHooks,
): Fields {
  const deltaType = typeof ownValue(delta, 'type') === 'string' ? String(ownValue(delta, 'type')) : ''
  const preparedForDelta = hooks.prepared?.get(delta)
  const patches = new Map<string, unknown>()

  if (deltaType === 'text_delta') {
    const text = ownValue(delta, 'text')
    if (typeof text === 'string') {
      const next = preparedForDelta?.has('text') ? preparedForDelta.get('text')! : hooks.scrubText(text)
      if (next !== text) patches.set('text', next)
    }
    return patchRecord(delta, patches)
  }
  if (deltaType === 'thinking_delta') {
    const thinking = ownValue(delta, 'thinking')
    if (typeof thinking === 'string') {
      const next = preparedForDelta?.has('thinking') ? preparedForDelta.get('thinking')! : hooks.scrubText(thinking)
      if (next !== thinking) patches.set('thinking', next)
    }
    return patchRecord(delta, patches)
  }
  if (deltaType === 'signature_delta') {
    const sig = ownValue(delta, 'signature')
    if (typeof sig === 'string') {
      const next = preparedForDelta?.has('signature') ? preparedForDelta.get('signature')! : hooks.scrubExact(sig)
      if (next !== sig) patches.set('signature', next)
    }
    return patchRecord(delta, patches)
  }
  if (deltaType === 'input_json_delta') {
    const partial = ownValue(delta, 'partial_json')
    if (typeof partial === 'string') {
      const next = preparedForDelta?.has('partial_json')
        ? preparedForDelta.get('partial_json')!
        : hooks.scrubJsonArgs(partial)
      if (next !== partial) patches.set('partial_json', next)
    }
    return patchRecord(delta, patches)
  }
  // e.g. `message_delta.delta` (`{ stop_reason, stop_sequence }`): protocol-only, untouched.
  return delta
}

function sanitizeInboundErrorObject(errObj: Fields, hooks: ProviderScrubHooks): Fields {
  const msg = ownValue(errObj, 'message')
  if (typeof msg !== 'string') return errObj
  const next = hooks.scrubText(msg)
  if (next === msg) return errObj
  return patchRecord(errObj, new Map([['message', next]]))
}

function sanitizeInboundResponseObject(respObj: Fields, hooks: ProviderScrubHooks): Fields {
  const patches = new Map<string, unknown>()
  const output = ownValue(respObj, 'output')
  if (Array.isArray(output)) {
    let changed = false
    const mapped = output.map(item => {
      const next = scrubStructuredItem(item, hooks)
      if (next !== item) changed = true
      return next
    })
    if (changed) patches.set('output', mapped)
  }
  const outputText = ownValue(respObj, 'output_text')
  if (typeof outputText === 'string') {
    const next = hooks.scrubText(outputText)
    if (next !== outputText) patches.set('output_text', next)
  }
  const instructions = ownValue(respObj, 'instructions')
  if (typeof instructions === 'string') {
    const next = hooks.scrubText(instructions)
    if (next !== instructions) patches.set('instructions', next)
  }
  const errObj = fields(ownValue(respObj, 'error'))
  if (errObj) {
    const nextErr = sanitizeInboundErrorObject(errObj, hooks)
    if (nextErr !== errObj) patches.set('error', nextErr)
  }
  return patchRecord(respObj, patches)
}

/**
 * Structural content-only sanitizer for provider stream frames & recorded payloads (R4-H-17).
 *
 * Shares the same structural content-leaf walker as `scrubOutboundProviderRequest`:
 *  - NEVER rewrites JSON object keys (null-prototype safe).
 *  - NEVER mutates protocol/structural fields (`type`, `event`, `id`, `index`, `status`,
 *    `role`, `model`, `name`, `stop_reason`, `finish_reason`, `call_id`, `tool_use_id`,
 *    `usage`, `tools`, `tool_choice`, `encrypted_content`, etc.).
 *  - Scrubs ONLY content/text/argument leaves (and non-tool-call credential headers on
 *    recorded payloads).
 */
export function sanitizeProviderValue(
  value: unknown,
  key: string,
  prepared: Prepared = new WeakMap(),
  secrets: SecretSource = [],
): unknown {
  const resolved = resolveSecretSource(secrets)
  if (typeof value === 'string') return redactProviderText(value, key, resolved)
  if (Array.isArray(value)) return value.map(item => sanitizeProviderValue(item, key, prepared, resolved))
  const record = fields(value)
  if (!record) return value

  const hooks = createInboundScrubHooks(key, resolved, prepared)
  const recordType = typeof ownValue(record, 'type') === 'string' ? String(ownValue(record, 'type')) : ''
  const preparedForRec = prepared.get(record)

  // 1. Direct content block (e.g. `thinking`, `text`, `output_text`, `tool_use`, `tool_result`, `redacted_thinking`).
  if (recordType && CONTENT_BLOCK_TYPES.has(recordType)) {
    return scrubContentBlock(record, hooks)
  }

  // 2. Direct structured item (e.g. `message`, `function_call`, `custom_tool_call`, `reasoning`).
  if (recordType && STRUCTURED_ITEM_TYPES.has(recordType)) {
    return scrubStructuredItem(record, hooks)
  }

  // 3. Inbound SSE event envelopes (OpenAI Responses & Anthropic Messages) and generic/recorded records.
  const patches = new Map<string, unknown>()
  for (const name of Object.keys(record)) {
    const item = record[name]

    // Prepared delta / fragment string takes precedence (already scrubbed across frame boundaries).
    if (preparedForRec?.has(name)) {
      const next = preparedForRec.get(name)!
      if (next !== item) patches.set(name, next)
      continue
    }

    // NEVER mutate protected protocol/structural fields (keys are NEVER rewritten either).
    if (PROTECTED_INBOUND_PROTOCOL_FIELDS.has(name)) {
      continue
    }

    // Non-tool-call credential headers/fields on recorded payloads.
    if (credentialField.test(name)) {
      if (item !== replacement) patches.set(name, replacement)
      continue
    }

    // SSE response / message / item / part / content_block / delta / error containers.
    if (name === 'response') {
      const respObj = fields(item)
      if (respObj) {
        const next = sanitizeInboundResponseObject(respObj, hooks)
        if (next !== respObj) patches.set(name, next)
      }
      continue
    }
    if (name === 'message' && fields(item)) {
      const next = scrubStructuredItem(item, hooks)
      if (next !== item) patches.set(name, next)
      continue
    }
    if (name === 'item' && fields(item)) {
      const next = scrubStructuredItem(item, hooks)
      if (next !== item) patches.set(name, next)
      continue
    }
    if ((name === 'part' || name === 'content_block') && fields(item)) {
      const next = scrubContentBlock(item, hooks)
      if (next !== item) patches.set(name, next)
      continue
    }
    if (name === 'delta') {
      if (typeof item === 'string') {
        const next = recordType === 'response.function_call_arguments.delta'
          ? hooks.scrubJsonArgs(item)
          : recordType === 'response.custom_tool_call_input.delta'
            ? hooks.scrubExact(item)
            : hooks.scrubText(item)
        if (next !== item) patches.set(name, next)
      } else {
        const deltaObj = fields(item)
        if (deltaObj) {
          const next = sanitizeInboundDelta(deltaObj, hooks)
          if (next !== deltaObj) patches.set(name, next)
        }
      }
      continue
    }
    if (name === 'error' && fields(item)) {
      const next = sanitizeInboundErrorObject(item as Fields, hooks)
      if (next !== item) patches.set(name, next)
      continue
    }
    if (name === 'arguments' && typeof item === 'string') {
      const next = hooks.scrubJsonArgs(item)
      if (next !== item) patches.set(name, next)
      continue
    }
    if (
      name === 'input' &&
      typeof item === 'string' &&
      recordType === 'response.custom_tool_call_input.done'
    ) {
      const next = hooks.scrubExact(item)
      if (next !== item) patches.set(name, next)
      continue
    }
    if ((name === 'input' || name === 'messages' || name === 'output') && Array.isArray(item)) {
      let changed = false
      const mapped = item.map(entry => {
        const next = scrubStructuredItem(entry, hooks)
        if (next !== entry) changed = true
        return next
      })
      if (changed) patches.set(name, mapped)
      continue
    }
    if ((name === 'content' || name === 'system' || name === 'summary') && Array.isArray(item)) {
      const next = scrubContentBlocks(item, hooks)
      if (next !== item) patches.set(name, next)
      continue
    }
    if (
      name === 'signature' &&
      typeof item === 'string' &&
      (recordType === 'thinking' || recordType === 'signature_delta')
    ) {
      const next = hooks.scrubExact(item)
      if (next !== item) patches.set(name, next)
      continue
    }
    if (name === 'reasoning' || name === 'thinking' || name === 'output_config' || name === 'betas' || name === 'fallbacks' || name === 'include' || name === 'thread') {
      // Request-level config objects (`reasoning: { effort, summary }`, `thinking: { type, budget_tokens }`):
      // scrub only string `thinking` prose if this is a prose leaf, never config objects.
      if (name === 'thinking' && typeof item === 'string') {
        const next = hooks.scrubText(item)
        if (next !== item) patches.set(name, next)
      }
      continue
    }
    if (name === 'annotation' && fields(item)) {
      const ann = item as Fields
      const annPatches = new Map<string, unknown>()
      for (const annField of ['title', 'url', 'filename', 'text'] as const) {
        const val = ownValue(ann, annField)
        if (typeof val === 'string') {
          const nextVal = hooks.scrubText(val)
          if (nextVal !== val) annPatches.set(annField, nextVal)
        }
      }
      const nextAnn = patchRecord(ann, annPatches)
      if (nextAnn !== ann) patches.set(name, nextAnn)
      continue
    }
    // Explicit content-bearing string leaves (`text`, `refusal`, `instructions`, `system`, `message`, `content`, `output`, `input`).
    if (
      typeof item === 'string' &&
      (name === 'text' ||
        name === 'refusal' ||
        name === 'instructions' ||
        name === 'system' ||
        name === 'message' ||
        name === 'content' ||
        name === 'output' ||
        name === 'input' ||
        name === 'output_text')
    ) {
      const next = hooks.scrubText(item)
      if (next !== item) patches.set(name, next)
      continue
    }
    // Recurse into non-protocol nested arrays/objects (keys and protected protocol fields stay untouched).
    if (Array.isArray(item) || fields(item)) {
      const next = sanitizeProviderValue(item, key, prepared, resolved)
      if (next !== item) patches.set(name, next)
    }
  }
  return patchRecord(record, patches)
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
        : (channel === 'input' || channel === 'signature')
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

function isSecretSource(value: SecretSource | StreamSanitizeOptions): value is SecretSource {
  return Array.isArray(value) || typeof value === 'function'
}

export function sanitizeProviderStream(
  body: ReadableStream<Uint8Array>,
  key: string,
  protocol: ProviderSettings['protocol'],
  secretsOrOptions: SecretSource | StreamSanitizeOptions = [],
  responseLimitArg?: number,
): ReadableStream<Uint8Array> {
  const secretSource: SecretSource = isSecretSource(secretsOrOptions)
    ? secretsOrOptions
    : (secretsOrOptions.secrets ?? [])
  const onFirstChunk = isSecretSource(secretsOrOptions) ? undefined : secretsOrOptions.onFirstChunk
  const onActivity = isSecretSource(secretsOrOptions) ? undefined : secretsOrOptions.onActivity
  const onFrame = isSecretSource(secretsOrOptions) ? undefined : secretsOrOptions.onFrame
  const requestedLimit = isSecretSource(secretsOrOptions)
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

  function sanitizeNonDataSseLine(line: string, secrets: readonly NamedSecret[]): string {
    // R4-H-17: NEVER scrub SSE protocol control lines (`event:`, `id:`, `retry:`) or empty lines.
    // Only scrub free-form SSE comment lines (`:...`).
    if (line.startsWith(':')) {
      return ':' + redactProviderText(line.slice(1), key, secrets)
    }
    return line
  }

  function emit(controller: Output) {
    const secrets = resolveSecretSource(secretSource)
    const prepared = prepareDeltas(frames, key, secrets)
    for (const frame of frames.splice(0)) {
      const first = frame.lines.findIndex(isData)
      let safe: string
      if (frame.data === '[DONE]') {
        safe = '[DONE]'
      } else if (frame.data) {
        const sanitized = sanitizeProviderValue(frame.data, key, prepared, secrets)
        const sanitizedRecord = fields(sanitized)
        const violation = sanitizedRecord
          ? verifyInboundProviderFrameIntegrity(frame.data, sanitizedRecord)
          : 'frame'
        if (violation) {
          throw new Error(
            `Inbound provider stream integrity violation at ${violation}: local sanitizer mutated protocol structure.`,
          )
        }
        safe = JSON.stringify(sanitized)
      } else {
        safe = ''
      }
      const lines = frame.lines.flatMap((line, index) => {
        if (!isData(line)) return [sanitizeNonDataSseLine(line, secrets)]
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
    if (frame.data !== undefined) {
      if (onFrame) {
        try { onFrame(frame.data) } catch { /* frame observer must never break the stream */ }
      }
      if (onActivity) {
        try { onActivity() } catch { /* activity signal must never break the stream */ }
      }
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
      if (size > responseLimit) throw new Error('The model response exceeded Kovo’s size limit.')
      append(decoder.decode(chunk, { stream: true }), controller)
    },
    flush(controller) {
      append(decoder.decode(), controller, true)
      if (pending.trim()) push(pending, controller)
      emit(controller)
    },
  }))
}
