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

function scrubContentBlock(block: unknown, scrubString: (value: string) => string): unknown {
  if (typeof block === 'string') return scrubString(block)
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

  const patches = new Map<string, unknown>()
  if (type === 'text' || type === 'input_text' || type === 'output_text' || type === 'summary_text') {
    const text = ownValue(rec, 'text')
    if (typeof text === 'string') {
      const next = scrubString(text)
      if (next !== text) patches.set('text', next)
    }
    return patchRecord(rec, patches)
  }

  if (type === 'refusal') {
    const refusal = ownValue(rec, 'refusal')
    if (typeof refusal === 'string') {
      const next = scrubString(refusal)
      if (next !== refusal) patches.set('refusal', next)
    }
    return patchRecord(rec, patches)
  }

  if (type === 'thinking') {
    // Scrub thinking prose only; NEVER touch opaque cryptographic `signature` or `type`.
    const thinking = ownValue(rec, 'thinking')
    if (typeof thinking === 'string') {
      const next = scrubString(thinking)
      if (next !== thinking) patches.set('thinking', next)
    }
    return patchRecord(rec, patches)
  }

  if (type === 'tool_use') {
    // Scrub only string values inside `input`; NEVER mutate keys, `type`, `id`, or `name`.
    const input = ownValue(rec, 'input')
    if (input !== undefined) {
      const next = scrubStringValuesOnly(input, scrubString)
      if (next !== input) patches.set('input', next)
    }
    return patchRecord(rec, patches)
  }

  if (type === 'tool_result') {
    const content = ownValue(rec, 'content')
    if (typeof content === 'string') {
      const next = scrubString(content)
      if (next !== content) patches.set('content', next)
    } else if (Array.isArray(content)) {
      const next = scrubContentBlocks(content, scrubString)
      if (next !== content) patches.set('content', next)
    }
    return patchRecord(rec, patches)
  }

  if (type === 'document') {
    for (const fieldName of ['title', 'context'] as const) {
      const val = ownValue(rec, fieldName)
      if (typeof val === 'string') {
        const next = scrubString(val)
        if (next !== val) patches.set(fieldName, next)
      }
    }
    const source = fields(ownValue(rec, 'source'))
    if (source && ownValue(source, 'type') === 'text') {
      const data = ownValue(source, 'data')
      if (typeof data === 'string') {
        const nextData = scrubString(data)
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
    const next = scrubString(fallbackText)
    if (next !== fallbackText) patches.set('text', next)
  }
  return patchRecord(rec, patches)
}

function scrubContentBlocks(blocks: unknown[], scrubString: (value: string) => string): unknown[] {
  let changed = false
  const mapped = blocks.map(block => {
    const next = scrubContentBlock(block, scrubString)
    if (next !== block) changed = true
    return next
  })
  return changed ? mapped : blocks
}

function scrubChatToolCalls(toolCalls: unknown[], scrubString: (value: string) => string): unknown[] {
  let changed = false
  const mapped = toolCalls.map(entry => {
    const tc = fields(entry)
    if (!tc) return entry
    const fn = fields(ownValue(tc, 'function'))
    if (!fn) return entry
    const args = ownValue(fn, 'arguments')
    if (typeof args !== 'string') return entry
    const nextArgs = scrubJsonStringValues(args, scrubString)
    if (nextArgs === args) return entry
    changed = true
    return patchRecord(tc, new Map([['function', patchRecord(fn, new Map([['arguments', nextArgs]]))]]))
  })
  return changed ? mapped : toolCalls
}

function scrubOutboundItem(item: unknown, scrubString: (value: string) => string): unknown {
  if (typeof item === 'string') return scrubString(item)
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

  const patches = new Map<string, unknown>()

  if (type === 'function_call') {
    const args = ownValue(rec, 'arguments')
    if (typeof args === 'string') {
      const next = scrubJsonStringValues(args, scrubString)
      if (next !== args) patches.set('arguments', next)
    } else if (args && typeof args === 'object') {
      const next = scrubStringValuesOnly(args, scrubString)
      if (next !== args) patches.set('arguments', next)
    }
    return patchRecord(rec, patches)
  }

  if (type === 'custom_tool_call') {
    const input = ownValue(rec, 'input')
    if (typeof input === 'string') {
      const next = scrubString(input)
      if (next !== input) patches.set('input', next)
    } else if (input && typeof input === 'object') {
      const next = scrubStringValuesOnly(input, scrubString)
      if (next !== input) patches.set('input', next)
    }
    return patchRecord(rec, patches)
  }

  if (type === 'function_call_output' || type === 'custom_tool_call_output') {
    const output = ownValue(rec, 'output')
    if (typeof output === 'string') {
      const next = scrubString(output)
      if (next !== output) patches.set('output', next)
    } else if (Array.isArray(output)) {
      const next = scrubContentBlocks(output, scrubString)
      if (next !== output) patches.set('output', next)
    }
    return patchRecord(rec, patches)
  }

  if (type === 'reasoning') {
    // Scrub human-readable summary text only; NEVER touch `encrypted_content`, `id`, `status`, `type`.
    const summary = ownValue(rec, 'summary')
    if (Array.isArray(summary)) {
      const next = scrubContentBlocks(summary, scrubString)
      if (next !== summary) patches.set('summary', next)
    }
    return patchRecord(rec, patches)
  }

  // Message items (OpenAI Responses `type: 'message'` or `role`, Anthropic Messages `role`).
  const role = ownValue(rec, 'role')
  if (type === 'message' || typeof role === 'string') {
    const content = ownValue(rec, 'content')
    if (typeof content === 'string') {
      const next = scrubString(content)
      if (next !== content) patches.set('content', next)
    } else if (Array.isArray(content)) {
      const next = scrubContentBlocks(content, scrubString)
      if (next !== content) patches.set('content', next)
    }
    const toolCalls = ownValue(rec, 'tool_calls')
    if (Array.isArray(toolCalls)) {
      const next = scrubChatToolCalls(toolCalls, scrubString)
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
    const next = scrubContentBlocks(system, scrubString)
    if (next !== system) patches.set('system', next)
  }

  const input = ownValue(rec, 'input')
  if (typeof input === 'string') {
    const next = scrubString(input)
    if (next !== input) patches.set('input', next)
  } else if (Array.isArray(input)) {
    let changed = false
    const mapped = input.map(item => {
      const next = scrubOutboundItem(item, scrubString)
      if (next !== item) changed = true
      return next
    })
    if (changed) patches.set('input', mapped)
  }

  const messages = ownValue(rec, 'messages')
  if (Array.isArray(messages)) {
    let changed = false
    const mapped = messages.map(item => {
      const next = scrubOutboundItem(item, scrubString)
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
  secrets: SecretSource = [],
): unknown {
  const resolved = resolveSecretSource(secrets)
  if (typeof value === 'string') return redactProviderText(value, key, resolved)
  if (Array.isArray(value)) return value.map(item => sanitizeProviderValue(item, key, prepared, resolved))
  const record = fields(value)
  if (!record) return value
  if (record.type === 'message' && Array.isArray(record.content)) {
    const parts = record.content.flatMap(item => {
      const part = fields(item)
      const text = fragment(part, part?.type === 'refusal' ? 'refusal' : 'text')
      return text ? [text] : []
    })
    prepareFragments(parts, key, prepared, resolved)
  }
  return Object.fromEntries(Object.entries(record).map(([name, item]) => {
    const safeName = redactProviderText(name, key, resolved)
    if (prepared.get(record)?.has(name)) return [safeName, item]
    if (credentialField.test(name)) return [safeName, replacement]
    if (
      name === 'arguments' && typeof item === 'string' &&
      (record.type === 'function_call' || record.type === 'response.function_call_arguments.done')
    ) {
      return [safeName, redactArguments(item, key, resolved)]
    }
    if (
      name === 'input' && typeof item === 'string' &&
      (record.type === 'custom_tool_call' || record.type === 'response.custom_tool_call_input.done')
    ) {
      return [safeName, redactExactSecrets(item, key, resolved)]
    }
    if (
      name === 'signature' && typeof item === 'string' &&
      (record.type === 'thinking' || record.type === 'signature_delta')
    ) {
      return [safeName, redactExactSecrets(item, key, resolved)]
    }
    if (name === 'input' && record.type === 'tool_use') {
      return [safeName, sanitizeToolArgumentValue(item, key, resolved)]
    }
    return [safeName, sanitizeProviderValue(item, key, prepared, resolved)]
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

  function emit(controller: Output) {
    const secrets = resolveSecretSource(secretSource)
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
