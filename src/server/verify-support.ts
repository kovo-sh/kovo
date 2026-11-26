/**
 * Layer-3 verification support primitives shared by the replay verifier.
 *
 * Two responsibilities:
 *   1. Noise-tolerant structural comparison for boolean/content differentials. Per-request
 *      tokens (CSRF nonces, UUIDs, ISO timestamps, request ids, long hex/base64 blobs) are
 *      normalized before similarity, so a rotating nonce never fakes a differential and a single
 *      real field delta inside a large HTML shell is still detected when it is stable across
 *      rounds.
 *   2. Two-stage async OOB correlation: a durable `pending_oob` subscription plus a short
 *      immediate check, then `awaitAny()` up to the caller's run budget and `promoteLate()` so
 *      background-worker callbacks are promoted into verified candidates.
 *
 * This module is stateless and imports only the public relay/broker seam.
 */
import { createHmac, randomBytes, randomInt, randomUUID } from 'node:crypto'
import { once } from 'node:events'
import { createServer } from 'node:http'
import type { Server } from 'node:http'
import type { WireCredentialProvenance } from './broker.ts'
import type { CanaryBroker } from './canary-broker.ts'
import { isDerivedCapabilityHandle, type InjectCapabilityTarget } from './derived-custody.ts'
import type { HostCredentialPlacement } from './host-fact-log.ts'
import type { ResolvedPersona } from './persona-vault.ts'
import { responseSimilarity } from './probes/context.ts'
import { resolveBoundedBudgetCap } from './run-safety-budgets.ts'
import { compileSafeClaimRegex, MAX_CLAIM_REGEX_HAYSTACK } from './safe-regex.ts'
import type { Store } from './store.ts'

// ---------------------------------------------------------------------------
// Structural (noise-tolerant) comparison
// ---------------------------------------------------------------------------

const STRUCTURAL_KEYED_TOKEN_RE = /(["']?(?:csrf|xsrf|nonce|authenticity[_-]?token|request[_-]?id|trace[_-]?id|correlation[_-]?id|span[_-]?id|session[_-]?id|etag|server[_-]?time|request[_-]?time)["']?[ \t]{0,8}[:=][ \t]{0,8})("[^"\r\n]{0,256}"|'[^'\r\n]{0,256}'|[^\s,;&}<]{1,256})/gi
const STRUCTURAL_UUID_RE = /[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/gi
const STRUCTURAL_ISO_TS_RE = /\b\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?(?:Z|[+-]\d{2}:?\d{2})?/g
const STRUCTURAL_EPOCH_RE = /\b1[5-9]\d{11}\b|\b2\d{12}\b/g
const STRUCTURAL_LONG_HEX_RE = /\b[0-9a-f]{16,256}\b/gi
const STRUCTURAL_LONG_OPAQUE_RE = /[A-Za-z0-9+/_=-]{24,256}/g
const STRUCTURAL_REDACTED_RE = /\[redacted(?::[^\]]{1,160})?\]/gi
const TAG_NONCE_KEY_RE = /(?:csrf|xsrf|nonce|authenticity|request[_-]?id)/i
const MAX_TAG_SCAN_LEN = 512
/** Cap structural normalization input to 8 KiB (head + tail) so large adversarial bodies stay linear and fast. */
export const MAX_STRUCTURAL_NORMALIZE_BYTES = 8_192

function readQuotedAttrValue(tag: string, eqPos: number): { start: number; end: number; value: string } | null {
  let i = eqPos + 1
  while (i < tag.length && (tag[i] === ' ' || tag[i] === '\t' || tag[i] === '\r' || tag[i] === '\n')) i += 1
  if (i >= tag.length) return null
  const quote = tag[i]
  if (quote !== '"' && quote !== "'") return null
  const close = tag.indexOf(quote, i + 1)
  if (close === -1 || close - i > 256) return null
  return { start: i, end: close + 1, value: tag.slice(i + 1, close) }
}

/** Linear O(N) tag-scoped scanner replacing the quadratic `STRUCTURAL_TAG_NONCE_RE` regex. */
function stripTagNonceValues(input: string): string {
  if (!input.includes('<')) return input
  let out = ''
  let pos = 0
  while (pos < input.length) {
    const lt = input.indexOf('<', pos)
    if (lt === -1) {
      out += input.slice(pos)
      break
    }
    const gt = input.indexOf('>', lt + 1)
    if (gt === -1) {
      out += input.slice(pos)
      break
    }
    if (gt - lt > MAX_TAG_SCAN_LEN) {
      out += input.slice(pos, lt + 1)
      pos = lt + 1
      continue
    }
    const tag = input.slice(lt, gt + 1)
    let hasNonceAttr = false
    let valueSpan: { start: number; end: number } | null = null
    // Linear attribute scan inside the bounded tag (<= 512 chars).
    for (let i = 1; i < tag.length - 1; i += 1) {
      const ch = tag[i]!
      if (ch === ' ' || ch === '\t' || ch === '\r' || ch === '\n' || ch === '/') continue
      const nameStart = i
      while (i < tag.length - 1 && /[A-Za-z0-9_:-]/.test(tag[i]!)) i += 1
      const attrName = tag.slice(nameStart, i).toLowerCase()
      while (i < tag.length - 1 && (tag[i] === ' ' || tag[i] === '\t')) i += 1
      if (tag[i] !== '=') continue
      const quoted = readQuotedAttrValue(tag, i)
      if (!quoted) continue
      i = quoted.end - 1
      if ((attrName === 'name' || attrName === 'id') && TAG_NONCE_KEY_RE.test(quoted.value)) {
        hasNonceAttr = true
      } else if (attrName === 'content' || attrName === 'value') {
        valueSpan = { start: quoted.start, end: quoted.end }
      }
    }
    out += input.slice(pos, lt)
    if (hasNonceAttr && valueSpan) {
      out += `${tag.slice(0, valueSpan.start)}"<dynamic>"${tag.slice(valueSpan.end)}`
    } else {
      out += tag
    }
    pos = gt + 1
  }
  return out
}

/** Strip run-scoped nonces and other dynamic tokens before structural comparison. */
export function normalizeStructuralTokens(input: string): string {
  if (!input) return input
  const bounded = input.length > MAX_STRUCTURAL_NORMALIZE_BYTES
    ? `${input.slice(0, 6_144)}\n${input.slice(-2_048)}`
    : input
  let out = stripTagNonceValues(bounded)
    .replace(STRUCTURAL_REDACTED_RE, '<redacted>')
    .replace(STRUCTURAL_KEYED_TOKEN_RE, '$1"<dynamic>"')
    .replace(STRUCTURAL_UUID_RE, '<uuid>')
    .replace(STRUCTURAL_ISO_TS_RE, '<timestamp>')
    .replace(STRUCTURAL_EPOCH_RE, '<epoch>')
    .replace(STRUCTURAL_LONG_HEX_RE, '<hex>')
  // Long opaque values are dynamic when they mix letters and digits (base64url/ULID/idempotency
  // keys). Plain prose and long alphabetic DOM class names are preserved.
  out = out.replace(STRUCTURAL_LONG_OPAQUE_RE, token =>
    /[A-Za-z]/.test(token) && /\d/.test(token) ? '<opaque>' : token)
  return out
}

export interface StructuralDiff {
  similarity: number
  changedTokens: string[]
  normalizedEqual: boolean
}

function structuralTokenSet(normalized: string): Set<string> {
  return new Set(normalized.toLowerCase().split(/[^a-z0-9]+/).filter(token => token.length >= 2))
}

/** Structural comparison over already-normalized strings (avoids redundant normalization in loops). */
export function structuralDiffNormalized(normalizedA: string, normalizedB: string, maxTokens = 32): StructuralDiff {
  if (normalizedA === normalizedB) {
    return { similarity: 1, changedTokens: [], normalizedEqual: true }
  }
  const tokensA = structuralTokenSet(normalizedA)
  const tokensB = structuralTokenSet(normalizedB)
  const changed = new Set<string>()
  for (const token of tokensA) if (!tokensB.has(token)) changed.add(token)
  for (const token of tokensB) if (!tokensA.has(token)) changed.add(token)
  return {
    similarity: responseSimilarity(normalizedA, normalizedB),
    changedTokens: [...changed].sort().slice(0, maxTokens),
    normalizedEqual: false,
  }
}

/** Structural comparison that ignores dynamic tokens and reports the field-level delta. */
export function structuralDiff(a: string, b: string, maxTokens = 32): StructuralDiff {
  return structuralDiffNormalized(normalizeStructuralTokens(a), normalizeStructuralTokens(b), maxTokens)
}

/** Similarity over noise-normalized tokens (1 = structurally identical). */
export function structuralSimilarity(a: string, b: string): number {
  return structuralDiff(a, b).similarity
}

/** Tokens that changed in every round (a stable field delta, not per-request jitter). */
export function intersectStructuralDeltas(deltas: readonly (readonly string[])[]): string[] {
  if (deltas.length === 0) return []
  const [first, ...rest] = deltas
  return first.filter(token => rest.every(other => other.includes(token)))
}

export interface WorkerStructuralDiffResult {
  passed: boolean
  stableControl: boolean
  stableVariant: boolean
  similarity: number
  stableDeltaCount: number
  /** Keyed HMAC digests of changed tokens — NEVER plaintext lowercased fragments (R3-H-2). */
  stableDeltaDigests: string[]
  rounds: number
}

/**
 * R3-H-2: Evaluate structural differential strictly over worker-visible scrubbed bodies
 * and return counts + keyed HMAC digests instead of raw lowercased plaintext tokens.
 */
export function evaluateWorkerStructuralDiff(
  controls: readonly string[],
  variants: readonly string[],
  options: { minDeltaTokens?: number; maxSimilarity?: number; digestKey: string },
): WorkerStructuralDiffResult {
  if (controls.length === 0 || variants.length === 0) {
    return { passed: false, stableControl: false, stableVariant: false, similarity: 1, stableDeltaCount: 0, stableDeltaDigests: [], rounds: 0 }
  }
  const normControls = controls.map(normalizeStructuralTokens)
  const normVariants = variants.map(normalizeStructuralTokens)
  const stableControl = !normControls.some(body => !structuralDiffNormalized(normControls[0]!, body).normalizedEqual)
  const stableVariant = !normVariants.some(body => !structuralDiffNormalized(normVariants[0]!, body).normalizedEqual)
  if (!stableControl || !stableVariant) {
    return { passed: false, stableControl, stableVariant, similarity: 1, stableDeltaCount: 0, stableDeltaDigests: [], rounds: controls.length }
  }
  const roundDeltas = normControls.map((body, idx) => structuralDiffNormalized(body, normVariants[idx] ?? normVariants[0]!).changedTokens)
  const stableDelta = intersectStructuralDeltas(roundDeltas)
  const cross = structuralDiffNormalized(normControls[0]!, normVariants[0]!)
  const minDelta = Math.max(1, Math.min(options.minDeltaTokens ?? 1, 32))
  const maxSimilarity = options.maxSimilarity ?? 1
  const passed = !cross.normalizedEqual && stableDelta.length >= minDelta && cross.similarity < maxSimilarity
  const stableDeltaDigests = stableDelta.slice(0, 16).map(tok =>
    `hmac:${createHmac('sha256', options.digestKey).update(tok, 'utf8').digest('hex').slice(0, 16)}`)
  return {
    passed,
    stableControl,
    stableVariant,
    similarity: Number(cross.similarity.toFixed(4)),
    stableDeltaCount: stableDelta.length,
    stableDeltaDigests,
    rounds: controls.length,
  }
}

// ---------------------------------------------------------------------------
// R3-H-2: Safe async.awaitResult predicate & run-scoped call/attempt budget
// ---------------------------------------------------------------------------

export const DEFAULT_MAX_ASYNC_POLL_CALLS_PER_RUN = 128
export const HARD_MAX_ASYNC_POLL_CALLS_PER_RUN = 2_048
export const DEFAULT_MAX_ASYNC_POLL_ATTEMPTS_PER_RUN = 512
export const HARD_MAX_ASYNC_POLL_ATTEMPTS_PER_RUN = 8_192
const ASYNC_POLL_CALLS_ENV = 'KOVO_MAX_ASYNC_POLL_CALLS_PER_RUN'
const ASYNC_POLL_ATTEMPTS_ENV = 'KOVO_MAX_ASYNC_POLL_ATTEMPTS_PER_RUN'
const MAX_TRACKED_ASYNC_BUDGETS = 2_048

interface AsyncPollBudgetState { calls: number; attempts: number }
const runAsyncPollBudgets = new Map<string, AsyncPollBudgetState>()

function getOrCreateAsyncBudget(runId: string): AsyncPollBudgetState {
  const key = runId.trim() || '__default__'
  let state = runAsyncPollBudgets.get(key)
  if (!state) {
    if (runAsyncPollBudgets.size >= MAX_TRACKED_ASYNC_BUDGETS) {
      const oldest = runAsyncPollBudgets.keys().next().value
      if (oldest !== undefined) runAsyncPollBudgets.delete(oldest)
    }
    state = { calls: 0, attempts: 0 }
    runAsyncPollBudgets.set(key, state)
  }
  return state
}

export function consumeRunAsyncPollCallBudget(runId: string, maxPerRun?: number): number {
  const cap = resolveBoundedBudgetCap(maxPerRun, ASYNC_POLL_CALLS_ENV, DEFAULT_MAX_ASYNC_POLL_CALLS_PER_RUN, HARD_MAX_ASYNC_POLL_CALLS_PER_RUN)
  const state = getOrCreateAsyncBudget(runId)
  if (state.calls >= cap) {
    throw new Error(`async.awaitResult run call budget exceeded (max ${cap} per run).`)
  }
  state.calls += 1
  return state.calls
}

export function consumeRunAsyncPollAttemptBudget(runId: string, maxPerRun?: number): number {
  const cap = resolveBoundedBudgetCap(maxPerRun, ASYNC_POLL_ATTEMPTS_ENV, DEFAULT_MAX_ASYNC_POLL_ATTEMPTS_PER_RUN, HARD_MAX_ASYNC_POLL_ATTEMPTS_PER_RUN)
  const state = getOrCreateAsyncBudget(runId)
  if (state.attempts >= cap) {
    throw new Error(`async.awaitResult run poll-attempt budget exceeded (max ${cap} per run).`)
  }
  state.attempts += 1
  return state.attempts
}

export function getRunAsyncPollBudgetUsage(runId: string): { calls: number; attempts: number } {
  const state = runAsyncPollBudgets.get(runId.trim() || '__default__')
  return state ? { calls: state.calls, attempts: state.attempts } : { calls: 0, attempts: 0 }
}

export function resetRunAsyncPollBudgets(runId?: string): void {
  if (runId === undefined) runAsyncPollBudgets.clear()
  else runAsyncPollBudgets.delete(runId.trim() || '__default__')
}

export interface CompiledAsyncPredicate {
  readonly empty: boolean
  readonly expectedStatuses?: readonly unknown[]
  readonly bodyContains?: string
  readonly bodyRegex?: RegExp
  readonly jsonPath?: string
  readonly hasJsonEquals: boolean
  readonly jsonEqualsSerialized?: string
  readonly jsonInSerialized?: readonly string[]
  readonly jsonRegex?: RegExp
  readonly headerNameLower?: string
  readonly headerEquals?: string
  readonly headerRegex?: RegExp
}

function compileSafeAsyncRegex(pattern: string, label: string): RegExp {
  const compiled = compileSafeClaimRegex(pattern, { maxLength: 256 })
  if (!compiled.ok) {
    throw new Error(`async.awaitResult ${label} regex rejected: ${compiled.reason}`)
  }
  return compiled.regex
}

/** R3-H-2: Compile & validate worker-supplied async.awaitResult predicate via safe-regex before polling. */
export function compileAsyncMatchPredicate(predicate: Record<string, unknown> | null): CompiledAsyncPredicate {
  if (!predicate || Object.keys(predicate).length === 0) {
    return { empty: true, hasJsonEquals: false }
  }
  const expectedStatuses = predicate.status !== undefined
    ? (Array.isArray(predicate.status) ? predicate.status : [predicate.status])
    : undefined
  const bodyContains = typeof predicate.bodyContains === 'string' ? predicate.bodyContains : undefined
  const bodyRegex = typeof predicate.bodyMatches === 'string'
    ? compileSafeAsyncRegex(predicate.bodyMatches, 'bodyMatches')
    : undefined
  const jsonPath = typeof predicate.jsonPath === 'string' && predicate.jsonPath.trim()
    ? predicate.jsonPath.trim()
    : undefined
  const hasJsonEquals = jsonPath !== undefined && predicate.equals !== undefined
  const jsonEqualsSerialized = hasJsonEquals ? JSON.stringify(predicate.equals) : undefined
  const jsonInSerialized = jsonPath !== undefined && Array.isArray(predicate.in)
    ? predicate.in.map(v => JSON.stringify(v))
    : undefined
  const jsonRegex = jsonPath !== undefined && typeof predicate.matches === 'string'
    ? compileSafeAsyncRegex(predicate.matches, 'jsonPath matches')
    : undefined
  const rawHeader = predicate.header && typeof predicate.header === 'object' && !Array.isArray(predicate.header)
    ? (predicate.header as Record<string, unknown>)
    : null
  const headerNameLower = rawHeader && typeof rawHeader.name === 'string' ? rawHeader.name.toLowerCase() : undefined
  const headerEquals = headerNameLower && typeof rawHeader?.equals === 'string' ? rawHeader.equals : undefined
  const headerRegex = headerNameLower && typeof rawHeader?.matches === 'string'
    ? compileSafeAsyncRegex(rawHeader.matches, 'header matches')
    : undefined
  return {
    empty: false,
    ...(expectedStatuses ? { expectedStatuses } : {}),
    ...(bodyContains !== undefined ? { bodyContains } : {}),
    ...(bodyRegex ? { bodyRegex } : {}),
    ...(jsonPath ? { jsonPath } : {}),
    hasJsonEquals,
    ...(jsonEqualsSerialized !== undefined ? { jsonEqualsSerialized } : {}),
    ...(jsonInSerialized ? { jsonInSerialized } : {}),
    ...(jsonRegex ? { jsonRegex } : {}),
    ...(headerNameLower ? { headerNameLower } : {}),
    ...(headerEquals !== undefined ? { headerEquals } : {}),
    ...(headerRegex ? { headerRegex } : {}),
  }
}

/** R3-H-2: Evaluate a compiled predicate strictly over worker-visible scrubbed response data. */
export function evaluateAsyncMatchPredicate(
  compiled: CompiledAsyncPredicate,
  pollOutcome: { status: number; body: string; headers: Record<string, string> },
  evalJsonPath: (root: unknown, path: string) => { found: boolean; value?: unknown },
): boolean {
  if (compiled.empty) {
    return pollOutcome.status >= 200 && pollOutcome.status < 300 && pollOutcome.body.trim().length > 0
  }
  if (compiled.expectedStatuses && !compiled.expectedStatuses.includes(pollOutcome.status)) return false
  if (compiled.bodyContains !== undefined && !pollOutcome.body.includes(compiled.bodyContains)) return false
  if (compiled.bodyRegex && !compiled.bodyRegex.test(pollOutcome.body.slice(0, MAX_CLAIM_REGEX_HAYSTACK))) return false
  if (compiled.jsonPath) {
    let parsed: unknown
    try { parsed = JSON.parse(pollOutcome.body) } catch { return false }
    const evalRes = evalJsonPath(parsed, compiled.jsonPath)
    if (!evalRes.found) return false
    const serialized = JSON.stringify(evalRes.value)
    if (compiled.hasJsonEquals && serialized !== compiled.jsonEqualsSerialized) return false
    if (compiled.jsonInSerialized && !compiled.jsonInSerialized.includes(serialized)) return false
    if (compiled.jsonRegex && !compiled.jsonRegex.test(String(evalRes.value ?? '').slice(0, MAX_CLAIM_REGEX_HAYSTACK))) return false
  }
  if (compiled.headerNameLower) {
    const val = Object.entries(pollOutcome.headers).find(([k]) => k.toLowerCase() === compiled.headerNameLower)?.[1]
    if (val === undefined) return false
    if (compiled.headerEquals !== undefined && val !== compiled.headerEquals) return false
    if (compiled.headerRegex && !compiled.headerRegex.test(val.slice(0, MAX_CLAIM_REGEX_HAYSTACK))) return false
  }
  return true
}

// ---------------------------------------------------------------------------
// R3-H-5: Explicit host-derived wire auth placement stamp
// ---------------------------------------------------------------------------

/**
 * Authoritative host-derived wire credential placement stamped directly from host injection
 * and broker wire provenance (R3-H-5), extending `HostCredentialPlacement` for Stream 4b.
 */
export interface HostAuthPlacement extends HostCredentialPlacement {
  readonly wireAuthHeaders?: readonly string[]
  readonly vaultCookieNames?: readonly string[]
  readonly authSources?: readonly string[]
  readonly capabilityAuthInjected?: boolean
  readonly basePersonaDropped?: boolean
}

const NON_AUTH_WIRE_HEADERS = new Set(['cookie', 'x-csrf-token', 'x-xsrf-token'])
const AUTH_COOKIE_PICK_RE = /(?:^|[._-])(?:sid|sess|session|sessionid|auth|token|jwt|access|identity|connect\.sid|jsessionid|phpsessid|asp\.net_sessionid)(?:$|[._-])/i
const COSMETIC_COOKIE_PICK_RE = /^(?:theme|locale|lang|tz|timezone|prefs?|ab_?test|ga|_ga|_gid|csrftoken|csrf[_-]?token|xsrf[_-]?token|_csrf)$/i

function pickHostVaultCookieName(names: readonly string[]): string | null {
  if (names.length === 0) return null
  return names.find(n => AUTH_COOKIE_PICK_RE.test(n))
    ?? names.find(n => !COSMETIC_COOKIE_PICK_RE.test(n))
    ?? names[0]
    ?? null
}

/**
 * Build an explicit, authoritative `HostAuthPlacement` directly from host injection state and
 * broker-observed `WireCredentialProvenance` (never fooled by worker-named capability cookies).
 */
export function buildHostAuthPlacement(input: {
  wireProvenance?: WireCredentialProvenance
  injectedAuthHeaders?: Readonly<Record<string, string>>
  capabilityTargets?: readonly ('cookie' | 'bearer' | 'header' | 'query' | 'body')[]
  basePersonaAuthKind?: 'cookie' | 'bearer' | 'header' | 'none' | null
  basePersonaDropped?: boolean
  requestHeaders?: Readonly<Record<string, string>> | null
}): HostAuthPlacement {
  const wp = input.wireProvenance
  const capTargets = [...new Set(input.capabilityTargets ?? [])]
  const capAuthInjected = Boolean(
    (input.injectedAuthHeaders && Object.keys(input.injectedAuthHeaders).length > 0)
    || capTargets.some(t => t === 'bearer' || t === 'cookie' || t === 'header'),
  )
  const wireAuthSet = new Set<string>()
  for (const h of [...(wp?.headerNames ?? []), ...(wp?.vaultHeaderNames ?? []), ...(wp?.callerAuthHeaderNames ?? [])]) {
    const lower = h.toLowerCase()
    if (!NON_AUTH_WIRE_HEADERS.has(lower)) wireAuthSet.add(lower)
  }
  for (const k of Object.keys(input.injectedAuthHeaders ?? {})) {
    const lower = k.toLowerCase()
    if (!NON_AUTH_WIRE_HEADERS.has(lower)) wireAuthSet.add(lower)
  }
  for (const [k, v] of Object.entries(input.requestHeaders ?? {})) {
    const lower = k.toLowerCase()
    if (v && (lower === 'authorization' || lower === 'x-api-key' || lower === 'x-auth-token' || lower === 'proxy-authorization')) {
      wireAuthSet.add(lower)
    }
  }
  const wireAuthHeaders = [...wireAuthSet].sort()

  // Only host persona-vault cookies (never worker-named capability cookies) populate vaultCookieNames.
  const vaultCookieNames = capAuthInjected
    ? []
    : [...new Set(wp?.vaultCookieNames ?? [])].sort()
  const jarCookieNames = [...new Set(wp?.jarCookieNames ?? [])].sort()
  const hostBoundCookies = [...new Set([...vaultCookieNames, ...jarCookieNames])].sort()

  const injectedAuthVal = Object.entries(input.injectedAuthHeaders ?? {}).find(([k]) => /^authorization$/i.test(k))?.[1]
  const reqAuthVal = Object.entries(input.requestHeaders ?? {}).find(([k]) => /^authorization$/i.test(k))?.[1]
  const activeBaseKind = input.basePersonaDropped ? null : (input.basePersonaAuthKind ?? null)

  const hasBearer = activeBaseKind === 'bearer'
    || capTargets.includes('bearer')
    || Boolean(injectedAuthVal && /^bearer\s+/i.test(injectedAuthVal))
    || Boolean(reqAuthVal && /^bearer\s+/i.test(reqAuthVal))
  const hasHeaderAuth = activeBaseKind === 'header'
    || capTargets.includes('header')
    || wireAuthHeaders.some(h => h !== 'authorization' || !hasBearer)
  const hasCookie = (wp?.cookieNames.length ?? 0) > 0
    || (wp?.vaultCookieNames.length ?? 0) > 0
    || jarCookieNames.length > 0
    || capTargets.includes('cookie')
    || Object.keys(input.injectedAuthHeaders ?? {}).some(k => /^cookie$/i.test(k))
    || Boolean(!wp && Object.entries(input.requestHeaders ?? {}).some(([k, v]) => /^cookie$/i.test(k) && v.length > 0))

  const mixed = (hasBearer || hasHeaderAuth) && hasCookie
  const personaAuthKind: HostAuthPlacement['personaAuthKind'] = hasBearer
    ? 'bearer'
    : hasHeaderAuth
      ? 'header'
      : hasCookie
        ? 'cookie'
        : 'none'
  const authenticatingCookieName = hasCookie && !mixed
    ? pickHostVaultCookieName(hostBoundCookies)
    : null

  return Object.freeze({
    personaAuthKind,
    mixed,
    ...(capTargets.length > 0 ? { capabilityTargets: Object.freeze(capTargets) } : {}),
    ...(hostBoundCookies.length > 0 ? { jarCookieNames: Object.freeze(hostBoundCookies) } : {}),
    vaultCookieNames: Object.freeze(vaultCookieNames),
    ...(wireAuthHeaders.length > 0 ? { headerNames: Object.freeze(wireAuthHeaders), wireAuthHeaders: Object.freeze(wireAuthHeaders) } : {}),
    authenticatingCookieName,
    ...(wp?.sources?.length ? { authSources: Object.freeze([...wp.sources]) } : {}),
    ...(capAuthInjected ? { capabilityAuthInjected: true } : {}),
    ...(input.basePersonaDropped ? { basePersonaDropped: true } : {}),
  })
}

export interface ParsedCapabilityArg {
  handle: string
  target?: InjectCapabilityTarget
  headerName?: string
  cookieName?: string
  queryParam?: string
}

const INJECT_CAPABILITY_TARGETS = new Set<InjectCapabilityTarget>(['bearer', 'header', 'cookie', 'url'])

export function parseCapabilityArg(args: Record<string, unknown>): ParsedCapabilityArg | null {
  const raw = args.capability
  if (raw === undefined || raw === null) return null
  let targetRaw = args.capabilityTarget ?? args.capability_target
  let headerNameRaw = args.capabilityHeaderName ?? args.capability_header_name
  let cookieNameRaw = args.capabilityCookieName ?? args.capability_cookie_name
  let queryParamRaw = args.capabilityQueryParam ?? args.capability_query_param
  let handle = ''
  if (typeof raw === 'string') {
    handle = raw.trim()
  } else {
    const obj = raw && typeof raw === 'object' && !Array.isArray(raw) ? (raw as Record<string, unknown>) : null
    const rawHandle = obj ? (obj.handle ?? obj.derivedHandle ?? obj.cap_id) : undefined
    if (!obj || typeof rawHandle !== 'string') throw new Error('capability must be a handle string or { handle, target?, headerName?, cookieName?, queryParam? }.')
    handle = rawHandle.trim()
    targetRaw = obj.target ?? targetRaw
    headerNameRaw = obj.headerName ?? obj.header_name ?? headerNameRaw
    cookieNameRaw = obj.cookieName ?? obj.cookie_name ?? cookieNameRaw
    queryParamRaw = obj.queryParam ?? obj.query_param ?? queryParamRaw
  }
  if (!isDerivedCapabilityHandle(handle)) throw new Error(`Invalid derived capability handle "${handle}".`)
  let target: InjectCapabilityTarget | undefined
  if (targetRaw !== undefined) {
    if (typeof targetRaw !== 'string' || !INJECT_CAPABILITY_TARGETS.has(targetRaw as InjectCapabilityTarget)) throw new Error(`Unsupported capability target "${String(targetRaw)}".`)
    target = targetRaw as InjectCapabilityTarget
  }
  return {
    handle,
    ...(target ? { target } : {}),
    ...(typeof headerNameRaw === 'string' && headerNameRaw.trim() ? { headerName: headerNameRaw.trim() } : {}),
    ...(typeof cookieNameRaw === 'string' && cookieNameRaw.trim() ? { cookieName: cookieNameRaw.trim() } : {}),
    ...(typeof queryParamRaw === 'string' && queryParamRaw.trim() ? { queryParam: queryParamRaw.trim() } : {}),
  }
}

export function resolvePersonaAuthKind(persona: ResolvedPersona | undefined): 'cookie' | 'bearer' | 'header' | 'none' | null {
  if (!persona) return null
  if (persona.authKind === 'bearer' || persona.session?.headerType === 'bearer') return 'bearer'
  if (persona.authKind === 'cookie' || persona.session?.headerType === 'cookie') return 'cookie'
  if (persona.authKind === 'header' || persona.session?.headerType === 'header') return 'header'
  return null
}

// ---------------------------------------------------------------------------
// R3-C-4: Host-minted boolean pairs & base-value parity verification
// ---------------------------------------------------------------------------

export type BooleanPairStyle = 'numeric' | 'single_quote' | 'double_quote'

export interface HostMintedBooleanPair {
  readonly challengeId: string
  readonly baseValue: string
  readonly style: BooleanPairStyle
  readonly trueSuffix: string
  readonly falseSuffix: string
  readonly trueValue: string
  readonly falseValue: string
  readonly mintedAtMs: number
}

/**
 * R3-C-4: Mint a randomized host-owned boolean predicate pair bound to a single exact `baseValue`.
 * Both true and false arms share the exact byte-identical `baseValue` prefix so integer-coercing
 * endpoints cannot fabricate boolean SQLi from differing IDs.
 */
export function mintHostBooleanPair(
  baseValue: string,
  options: { style?: BooleanPairStyle } = {},
): HostMintedBooleanPair {
  const style: BooleanPairStyle = options.style ?? 'numeric'
  const a = randomInt(100, 900)
  const b = a + randomInt(1, 90)
  const trueSuffix = style === 'single_quote'
    ? `' AND '${a}'='${a}'--`
    : style === 'double_quote'
      ? `" AND "${a}"="${a}"--`
      : ` AND ${a}=${a}`
  const falseSuffix = style === 'single_quote'
    ? `' AND '${a}'='${b}'--`
    : style === 'double_quote'
      ? `" AND "${a}"="${b}"--`
      : ` AND ${a}=${b}`
  return Object.freeze({
    challengeId: `bool-${randomUUID()}`,
    baseValue,
    style,
    trueSuffix,
    falseSuffix,
    trueValue: `${baseValue}${trueSuffix}`,
    falseValue: `${baseValue}${falseSuffix}`,
    mintedAtMs: Date.now(),
  })
}

const BOOL_SUFFIX_NUMERIC_RE = /(['")]*)\s*\b(?:AND|OR)\s*\(?\s*(\d+)\s*(==|=|!=|<>)\s*(\d+)(?:\s*([+-])\s*(\d+))?\s*\)?\s*(?:--[^\r\n]*|#[^\r\n]*|\/\*[\s\S]*?\*\/)?\s*$/i
const BOOL_SUFFIX_STRING_RE = /(['")]*)\s*\b(?:AND|OR)\s*\(?\s*(['"])([^'"]*)\2\s*(==|=|!=|<>)\s*(['"])([^'"]*)\5?\s*\)?\s*(?:--[^\r\n]*|#[^\r\n]*|\/\*[\s\S]*?\*\/)?\s*$/i
const BOOL_SUFFIX_LITERAL_RE = /(['")]*)\s*\b(?:AND|OR)\s*\(?\s*(NOT\s+)?(TRUE|FALSE)\s*\)?\s*(?:--[^\r\n]*|#[^\r\n]*|\/\*[\s\S]*?\*\/)?\s*$/i

/** Strip a trailing explicit boolean predicate expression and return the exact leading base value + truth. */
export function stripBooleanPredicateSuffix(raw: string): {
  baseValue: string
  predicateTruth: boolean | null
  predicateText: string | null
} {
  const num = BOOL_SUFFIX_NUMERIC_RE.exec(raw)
  if (num) {
    const left = Number(num[2])
    let right = Number(num[4])
    if (num[5] && num[6]) right += num[5] === '-' ? -Number(num[6]) : Number(num[6])
    const eq = left === right
    const truth = num[3] === '!=' || num[3] === '<>' ? !eq : eq
    return { baseValue: raw.slice(0, num.index), predicateTruth: truth, predicateText: num[0] }
  }
  const str = BOOL_SUFFIX_STRING_RE.exec(raw)
  if (str) {
    const eq = str[3] === str[6]
    const truth = str[4] === '!=' || str[4] === '<>' ? !eq : eq
    return { baseValue: raw.slice(0, str.index), predicateTruth: truth, predicateText: str[0] }
  }
  const lit = BOOL_SUFFIX_LITERAL_RE.exec(raw)
  if (lit) {
    const baseTruth = lit[3]!.toLowerCase() === 'true'
    const truth = lit[2] ? !baseTruth : baseTruth
    return { baseValue: raw.slice(0, lit.index), predicateTruth: truth, predicateText: lit[0] }
  }
  return { baseValue: raw, predicateTruth: null, predicateText: null }
}

/**
 * R3-C-4: Enforce byte-identical stripped base values across baseline, true, and false boolean arms.
 */
export function verifyBooleanArmBaseParity(input: {
  controlValue: string
  variantValue: string
  baselineValue?: string
  hostPair?: HostMintedBooleanPair
}): { ok: true; sharedBase: string | null; controlTruth: boolean | null; variantTruth: boolean | null } | { ok: false; reason: string } {
  if (input.hostPair) {
    const pair = input.hostPair
    if (input.baselineValue !== undefined && input.baselineValue !== pair.baseValue) {
      return { ok: false, reason: `baseline value "${input.baselineValue}" does not match host-minted base "${pair.baseValue}"` }
    }
    const ctlIsTrue = input.controlValue === pair.trueValue && input.variantValue === pair.falseValue
    const ctlIsFalse = input.controlValue === pair.falseValue && input.variantValue === pair.trueValue
    if (!ctlIsTrue && !ctlIsFalse) {
      return { ok: false, reason: 'control and variant arms do not match the host-minted boolean pair' }
    }
    return { ok: true, sharedBase: pair.baseValue, controlTruth: ctlIsTrue, variantTruth: ctlIsFalse }
  }

  const ctl = stripBooleanPredicateSuffix(input.controlValue)
  const vr = stripBooleanPredicateSuffix(input.variantValue)
  const base = input.baselineValue !== undefined ? stripBooleanPredicateSuffix(input.baselineValue) : null

  if (base && base.predicateTruth !== null) {
    return { ok: false, reason: 'baseline arm must carry a benign non-predicate base value' }
  }
  if (ctl.predicateTruth !== null && vr.predicateTruth !== null) {
    if (ctl.predicateTruth === vr.predicateTruth) {
      return { ok: false, reason: 'boolean differential arms must carry opposite explicit boolean predicates' }
    }
    if (ctl.baseValue !== vr.baseValue) {
      return {
        ok: false,
        reason: `boolean predicate arms have mismatched base values ("${ctl.baseValue}" vs "${vr.baseValue}"); arms must share the identical base value`,
      }
    }
    if (base && input.baselineValue !== ctl.baseValue) {
      return {
        ok: false,
        reason: `baseline value "${input.baselineValue}" does not match boolean arm base "${ctl.baseValue}"`,
      }
    }
    return { ok: true, sharedBase: ctl.baseValue, controlTruth: ctl.predicateTruth, variantTruth: vr.predicateTruth }
  }
  if (ctl.predicateTruth !== null || vr.predicateTruth !== null) {
    const predArm = ctl.predicateTruth !== null ? ctl : vr
    const benignVal = ctl.predicateTruth !== null ? input.variantValue : input.controlValue
    if (predArm.baseValue !== benignVal) {
      return {
        ok: false,
        reason: `boolean predicate arm base "${predArm.baseValue}" does not match benign arm value "${benignVal}"`,
      }
    }
    if (base && input.baselineValue !== benignVal) {
      return {
        ok: false,
        reason: `baseline value "${input.baselineValue}" does not match shared base "${benignVal}"`,
      }
    }
    return { ok: true, sharedBase: benignVal, controlTruth: ctl.predicateTruth, variantTruth: vr.predicateTruth }
  }
  return { ok: true, sharedBase: base ? input.baselineValue! : null, controlTruth: null, variantTruth: null }
}

// ---------------------------------------------------------------------------
// Async OOB correlation
// ---------------------------------------------------------------------------

export interface CanaryWaitOutcome {
  triggered: boolean
  stage: 'immediate' | 'late' | 'none'
  detail: Record<string, unknown> | null
  subscriptionId: string | null
  promoted: boolean
}

export interface ReplayCanaryWaitOptions {
  immediateMs?: number
  /** Total polling budget; bounded by the caller's run deadline signal. */
  budgetMs?: number
  pollMs?: number
  now?: () => number
  signal?: AbortSignal
}

export const defaultReplayCanaryImmediateMs = 3_000

/**
 * Registers a durable `pending_oob` subscription, performs an immediate in-memory check, then
 * polls via `awaitAny` up to the run budget and `promoteLate()`s any callback that landed outside
 * the immediate window. The subscription stays pending (and promotes later at run level) when no
 * callback arrived in the budget.
 */
export async function awaitReplayCanary(
  broker: CanaryBroker,
  input: { runId: string; assignmentId: string; token: string; canaryId?: string },
  options: ReplayCanaryWaitOptions = {},
): Promise<CanaryWaitOutcome> {
  const now = options.now ?? (() => Date.now())
  const immediateMs = Math.max(0, options.immediateMs ?? defaultReplayCanaryImmediateMs)
  const budgetMs = Math.max(0, options.budgetMs ?? immediateMs)
  let subscriptionId: string | null = null
  let subscriptionCreatedAt: number | null = null
  try {
    const subscription = broker.subscribe({
      runId: input.runId,
      assignmentId: input.assignmentId,
      // The canary id binds the subscription to the minted token; fall back to the token itself
      // when the caller only has an opaque handle.
      canaryId: input.canaryId ?? input.token,
      token: input.token,
      // Empty artifact: real callbacks rarely carry Kovo Hunter's artifact header, and a truthy
      // artifact would reject them at ingest. Token↔canary binding is the causal link.
      artifact: '',
      immediateMs,
    })
    subscriptionId = subscription.id
    subscriptionCreatedAt = subscription.createdAt
  } catch {
    // Relays that cannot persist subscriptions must not break a synchronous OOB proof.
    subscriptionId = null
  }
  // Anchor the immediate window at subscription creation, not at this call: a repeated check
  // for an existing pending subscription must still classify a late callback as late.
  const immediateDeadline = (subscriptionCreatedAt ?? now()) + immediateMs
  const readCheck = () => broker.checkCanary(input.token, { runId: input.runId })
  let check = readCheck()
  if (check.hit) {
    broker.promoteLate({ runId: input.runId, now: now() })
    const at = typeof check.detail?.timestamp === 'number'
      ? check.detail.timestamp
      : typeof check.detail?.receivedAt === 'number' ? check.detail.receivedAt : null
    const stage = at !== null && at > immediateDeadline ? 'late' : 'immediate'
    return { triggered: true, stage, detail: check.detail ?? null, subscriptionId, promoted: false }
  }
  let callbackReceivedAt: number | null = null
  try {
    const awaited = await broker.awaitAny({ token: input.token, runId: input.runId }, {
      timeoutMs: budgetMs,
      pollMs: options.pollMs ?? 150,
      ...(options.signal ? { signal: options.signal } : {}),
    })
    callbackReceivedAt = awaited.callback?.receivedAt ?? null
  } catch {
    // Polling failures fall through to the recorded in-memory hit check below.
  }
  const promotions = broker.promoteLate({ runId: input.runId, now: now() })
  const promotion = promotions.find(item => item.subscription.token === input.token)
  if (promotion?.subscription.id) subscriptionId = promotion.subscription.id
  check = readCheck()
  if (check.hit || promotion) {
    const receivedAt = callbackReceivedAt ?? promotion?.callback.receivedAt ?? null
    const stage = receivedAt !== null && receivedAt > immediateDeadline ? 'late' : 'immediate'
    return { triggered: true, stage, detail: check.detail ?? null, subscriptionId, promoted: Boolean(promotion) }
  }
  return { triggered: false, stage: 'none', detail: check.detail ?? null, subscriptionId, promoted: false }
}

// ---------------------------------------------------------------------------
// Canary session (brokered relay or standalone loopback)
// ---------------------------------------------------------------------------

export interface EphemeralCanarySession {
  mint(purpose: string): { token: string; url: string; dnsHost: string }
  check(token: string): { triggered: boolean; detail: Record<string, unknown> | null }
  /** Two-stage wait: short immediate window, then a durable subscription with late promotion. */
  waitForCallback(token: string, signal: AbortSignal, options?: { immediateMs?: number; budgetMs?: number }): Promise<CanaryWaitOutcome>
  close(): Promise<void>
}

export async function openCanarySession(
  canaryBroker: CanaryBroker | undefined,
  storage: Store | undefined,
  runId: string | undefined,
  assignmentId: string,
  origin?: string,
): Promise<EphemeralCanarySession> {
  if (canaryBroker) {
    const info = await canaryBroker.startListener()
    const effectiveRunId = runId ?? 'replay-verifier'
    const baseUrl = info.effectiveBaseUrl ?? ''
    const canaryIds = new Map<string, string>()
    return {
      mint(purpose: string) {
        const minted = canaryBroker.mintCanary(
          effectiveRunId,
          purpose,
          origin,
          storage ? { storage, assignmentId } : undefined,
        )
        canaryIds.set(minted.token, minted.id)
        return {
          token: minted.token,
          url: minted.httpUrl || `${baseUrl}/c/${minted.token}`,
          dnsHost: minted.dnsHost,
        }
      },
      check(token: string) {
        const res = canaryBroker.checkCanary(token, storage ? { storage, runId: effectiveRunId } : undefined)
        return { triggered: res.hit, detail: res.detail }
      },
      waitForCallback(token, signal, options = {}) {
        return awaitReplayCanary(canaryBroker, {
          runId: effectiveRunId,
          assignmentId,
          token,
          ...(canaryIds.has(token) ? { canaryId: canaryIds.get(token)! } : {}),
        }, {
          ...(options.immediateMs !== undefined ? { immediateMs: options.immediateMs } : {}),
          ...(options.budgetMs !== undefined ? { budgetMs: options.budgetMs } : {}),
          signal,
        })
      },
      async close() { /* Managed by host CanaryBroker lifecycle */ },
    }
  }

  // Standalone ephemeral loopback canary listener (used in unit tests without a CanaryBroker).
  const callbacks = new Map<string, Record<string, unknown>>()
  const server: Server = createServer((req, res) => {
    const url = new URL(req.url ?? '/', 'http://127.0.0.1')
    const match = /^\/c\/(kovo-canary-[a-f0-9]{24})$/.exec(url.pathname)
    if (match) {
      callbacks.set(match[1], {
        method: req.method ?? 'GET',
        path: url.pathname,
        receivedAt: new Date().toISOString(),
      })
    }
    res.writeHead(200, { 'content-type': 'text/plain; charset=utf-8' }).end('kovo-canary-ok')
  })
  server.listen(0, '127.0.0.1')
  await once(server, 'listening')
  const addr = server.address()
  if (!addr || typeof addr === 'string') {
    server.close()
    throw new Error('Could not bind ephemeral replay canary listener.')
  }
  const baseUrl = `http://127.0.0.1:${addr.port}`
  return {
    mint() {
      const token = `kovo-canary-${randomBytes(12).toString('hex')}`
      return { token, url: `${baseUrl}/c/${token}`, dnsHost: `${token}.canary.kovo.invalid` }
    },
    check(token: string) {
      const detail = callbacks.get(token) ?? null
      return { triggered: Boolean(detail), detail }
    },
    async waitForCallback(token, signal) {
      // Unchanged no-relay behaviour: ten 150 ms polls (1.5 s total).
      let detail = callbacks.get(token) ?? null
      for (let attempt = 0; attempt < 10 && !detail; attempt += 1) {
        await sleepAbortable(150, signal)
        detail = callbacks.get(token) ?? null
      }
      return {
        triggered: Boolean(detail),
        stage: detail ? 'immediate' : 'none',
        detail,
        subscriptionId: null,
        promoted: false,
      }
    },
    async close() {
      server.closeAllConnections()
      await new Promise<void>(resolve => server.close(() => resolve()))
    },
  }
}

async function sleepAbortable(ms: number, signal: AbortSignal) {
  if (signal.aborted) throw signal.reason
  await new Promise<void>((resolve, reject) => {
    const timer = setTimeout(() => {
      signal.removeEventListener('abort', onAbort)
      resolve()
    }, ms)
    const onAbort = () => {
      clearTimeout(timer)
      reject(signal.reason)
    }
    signal.addEventListener('abort', onAbort, { once: true })
  })
}
