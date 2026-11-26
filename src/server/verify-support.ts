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
import { createHash, createHmac, randomBytes, randomInt, randomUUID } from 'node:crypto'
import { once } from 'node:events'
import { createServer } from 'node:http'
import type { Server } from 'node:http'
import type { Grant, WireCredentialProvenance } from './broker.ts'
import type { CanaryBroker } from './canary-broker.ts'
import { isDerivedCapabilityHandle, type InjectCapabilityTarget } from './derived-custody.ts'
import type { HostCredentialPlacement } from './host-fact-log.ts'
import {
  stripBooleanPredicateSuffix,
  verifyBooleanArmBaseParityCore,
} from './proof-kernel/boolean-differential.ts'
export { stripBooleanPredicateSuffix }
import {
  carrierEchoesSignedUrlNeedles,
  hasTraversalOrSeparatorDifferential,
  normalizeRequestCarrier,
  type NormalizedRequestCarrier,
} from './proof-kernel/reflection.ts'
import type { ResolvedPersona } from './persona-vault.ts'
import type { HostMintedBooleanPairChallenge } from './proof-receipt.ts'
import { responseSimilarity } from './probes/context.ts'
import { registerRunDisposer } from './run-disposers.ts'
import {
  DEFAULT_MAX_ASYNC_POLL_ATTEMPTS_PER_RUN,
  DEFAULT_MAX_ASYNC_POLL_CALLS_PER_RUN,
  HARD_MAX_ASYNC_POLL_ATTEMPTS_PER_RUN,
  HARD_MAX_ASYNC_POLL_CALLS_PER_RUN,
  RunAsyncPollBudgetLedger,
  type AsyncPollBudgetUsage,
} from './run-safety-budgets.ts'
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

export {
  DEFAULT_MAX_ASYNC_POLL_CALLS_PER_RUN,
  HARD_MAX_ASYNC_POLL_CALLS_PER_RUN,
  DEFAULT_MAX_ASYNC_POLL_ATTEMPTS_PER_RUN,
  HARD_MAX_ASYNC_POLL_ATTEMPTS_PER_RUN,
}

const runAsyncPollBudgets = new RunAsyncPollBudgetLedger({
  defaultMaxCallsPerRun: DEFAULT_MAX_ASYNC_POLL_CALLS_PER_RUN,
  hardMaxCallsPerRun: HARD_MAX_ASYNC_POLL_CALLS_PER_RUN,
  defaultMaxAttemptsPerRun: DEFAULT_MAX_ASYNC_POLL_ATTEMPTS_PER_RUN,
  hardMaxAttemptsPerRun: HARD_MAX_ASYNC_POLL_ATTEMPTS_PER_RUN,
})

export function consumeRunAsyncPollCallBudget(runId: string, maxPerRun?: number, maxTrackedRuns?: number): number {
  return runAsyncPollBudgets.consumeCall(runId, maxPerRun, maxTrackedRuns)
}

export function consumeRunAsyncPollAttemptBudget(runId: string, maxPerRun?: number, maxTrackedRuns?: number): number {
  return runAsyncPollBudgets.consumeAttempt(runId, maxPerRun, maxTrackedRuns)
}

export function getRunAsyncPollBudgetUsage(runId: string): AsyncPollBudgetUsage {
  return runAsyncPollBudgets.getUsage(runId)
}

export function resetRunAsyncPollBudgets(runId?: string): void {
  runAsyncPollBudgets.delete(runId)
}

registerRunDisposer('verify-support:async-poll-budgets', runId => {
  resetRunAsyncPollBudgets(runId)
})

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
// R4-C-1 / R3-C-4: Host-minted boolean pairs & canonical predicate parity
// ---------------------------------------------------------------------------

export type BooleanPairStyle = 'numeric' | 'single_quote' | 'double_quote'

export interface HostMintedBooleanPair {
  readonly challengeId: string
  readonly baseValue: string
  readonly style: BooleanPairStyle
  readonly param?: string | null
  readonly trueSuffix: string
  readonly falseSuffix: string
  readonly trueValue: string
  readonly falseValue: string
  readonly mintedAtMs: number
}

/**
 * R4-C-1 / R3-C-4: Mint a randomized host-owned boolean predicate pair bound to a non-empty `baseValue`.
 * Routes through `options.oracle.mintBooleanPair` (e.g. `defaultHostMintedOracle`) when provided so
 * minted pairs are registered in the kernel oracle, and enforces identical equal-length,
 * same-character-multiset digit-permutation invariants in all cases.
 */
export function mintHostBooleanPair(
  baseValue: string,
  options: {
    style?: BooleanPairStyle
    param?: string | null
    oracle?: {
      mintBooleanPair(
        baseValue: string,
        opts?: { style?: BooleanPairStyle; param?: string | null },
      ): HostMintedBooleanPairChallenge
    }
  } = {},
): HostMintedBooleanPair {
  if (typeof baseValue !== 'string' || baseValue.trim().length === 0) {
    throw new Error('mintHostBooleanPair requires a non-empty baseValue (empty-base standalone predicates are forbidden).')
  }
  const style: BooleanPairStyle = options.style ?? 'numeric'
  if (options.oracle) {
    return options.oracle.mintBooleanPair(baseValue, {
      style,
      ...(options.param !== undefined ? { param: options.param } : {}),
    })
  }
  const d1 = randomInt(1, 10)
  const d2 = ((d1 + randomInt(0, 8)) % 9) + 1
  const d3 = randomInt(0, 10)
  const a = d1 * 100 + d2 * 10 + d3
  const b = d2 * 100 + d1 * 10 + d3
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
    challengeId: `bool_${randomUUID()}`,
    baseValue,
    style,
    ...(options.param !== undefined ? { param: options.param } : {}),
    trueSuffix,
    falseSuffix,
    trueValue: `${baseValue}${trueSuffix}`,
    falseValue: `${baseValue}${falseSuffix}`,
    mintedAtMs: Date.now(),
  })
}

/**
 * R4-C-1 / R3-17: Handler-side defense-in-depth wrapper into `proof-kernel/boolean-differential.ts`
 * enforcing byte-identical non-empty base values, canonical predicate skeletons, and
 * equal-length/same-character-multiset invariants before probe dispatch.
 */
export function verifyBooleanArmBaseParity(input: {
  controlValue: string
  variantValue: string
  baselineValue?: string
  hostPair?: HostMintedBooleanPair
}): { ok: true; sharedBase: string | null; controlTruth: boolean | null; variantTruth: boolean | null } | { ok: false; reason: string } {
  return verifyBooleanArmBaseParityCore(input)
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

// ---------------------------------------------------------------------------
// P0 #2: First-class `signed_url_mint` host-verified runtime oracle
// ---------------------------------------------------------------------------

export type SignedCloudStorageProvider = 'gcs' | 'aws_s3' | 'azure_blob' | 'cloudflare_r2'
export type SignedUrlMintVariant = 'key_traversal' | 'unauth_write_mint'

export interface ParsedSignedCloudUrl {
  readonly rawUrl: string
  readonly provider: SignedCloudStorageProvider
  readonly host: string
  readonly bucket: string
  readonly canonicalPathname: string
  readonly objectKey: string
  readonly parentDir: string
  readonly normalizedParentDir: string
  readonly signatureParam: string
  readonly signature: string
  readonly algorithm: string | null
  readonly writeCapable: boolean
  readonly writeReason: string | null
}

export interface SignedUrlMintExchange {
  readonly exchangeId?: string
  readonly origin: string
  readonly method: string
  readonly pathAndQuery: string
  readonly status: number | null
  readonly actorHandle?: string | null
  readonly requestHeaders?: Readonly<Record<string, string>> | null
  readonly requestBody?: string | null
  readonly requestJson?: unknown
  readonly responseHeaders?: Readonly<Record<string, string>> | null
  readonly responseBody?: string | null
  readonly responseJson?: unknown
  readonly wireCredentialProvenance?: WireCredentialProvenance | null
  readonly consumedCapabilityId?: string | null
  readonly consumedCapabilities?: readonly string[]
}

export interface SignedUrlMintAssessment {
  readonly confirmed: boolean
  readonly variant: SignedUrlMintVariant | null
  readonly provider: SignedCloudStorageProvider | null
  readonly reason: string
  readonly rejectedBy: string | null
  readonly missingEvidence: string[]
  readonly evidence: Record<string, unknown>
}

const GCS_STORAGE_HOST_RE = /^(?:storage\.googleapis\.com|storage\.cloud\.google\.com|[a-z0-9][a-z0-9._-]{1,62}\.storage\.googleapis\.com)$/i
const AWS_S3_HOST_RE = /^(?:[a-z0-9][a-z0-9.-]*\.)?s3(?:[.-](?:accelerate|dualstack|[a-z0-9-]+))?\.amazonaws\.com$/i
const AZURE_BLOB_HOST_RE = /^[a-z0-9][a-z0-9-]{1,62}\.blob\.core\.windows\.net$/i
const CLOUDFLARE_R2_HOST_RE = /^[a-z0-9][a-z0-9.-]*\.r2\.cloudflarestorage\.com$/i
const SIGNATURE_TOKEN_RE = /^[A-Za-z0-9+/_=-]{32,1024}$/
const HTTPS_URL_CANDIDATE_RE = /https:\/\/[^\s"'<>\\`]{16,4096}/gi
const DYNAMIC_PATH_SEG_RE = /^(?:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}|[0-9a-f]{16,}|[0-9]{6,}|[A-Za-z0-9_-]{24,})$/i
const WRITE_URL_FIELD_RE = /(?:upload|put|write|signed|presigned).*url|url/i
const WRITE_ROUTE_HINT_RE = /(?:upload|presign|signed[-_]?url|put[-_]?url|create[-_]?upload|generate[-_]?upload)/i
const REDACTED_PLACEHOLDER_RE = /\[redacted(?::[^\]]{0,160})?\]/i

function shannonEntropy(value: string): number {
  if (!value) return 0
  const counts = new Map<string, number>()
  for (let i = 0; i < value.length; i += 1) {
    const ch = value[i]!
    counts.set(ch, (counts.get(ch) ?? 0) + 1)
  }
  let entropy = 0
  for (const count of counts.values()) {
    const p = count / value.length
    entropy -= p * Math.log2(p)
  }
  return entropy
}

function isHighEntropySignature(raw: string | null | undefined): boolean {
  if (!raw) return false
  let decoded = raw.trim()
  try { decoded = decodeURIComponent(decoded) } catch { /* keep trimmed */ }
  if (decoded.length < 32 || !SIGNATURE_TOKEN_RE.test(decoded)) return false
  const distinct = new Set(decoded).size
  if (distinct < 8) return false
  return shannonEntropy(decoded) >= 2.5
}

function queryParamCI(params: URLSearchParams, name: string): string | null {
  const lower = name.toLowerCase()
  for (const [k, v] of params.entries()) {
    if (k.toLowerCase() === lower && v.trim().length > 0) return v.trim()
  }
  return null
}

function classifyCloudStorageHost(hostname: string): SignedCloudStorageProvider | null {
  const host = hostname.toLowerCase()
  if (GCS_STORAGE_HOST_RE.test(host)) return 'gcs'
  if (AWS_S3_HOST_RE.test(host)) return 'aws_s3'
  if (AZURE_BLOB_HOST_RE.test(host)) return 'azure_blob'
  if (CLOUDFLARE_R2_HOST_RE.test(host)) return 'cloudflare_r2'
  return null
}

function canonicalizeStoragePathname(rawPathname: string): string {
  // Decode percent-encoded dot / slash sequences so `%2e%2e` or `%2f` traversal resolves canonically.
  let decoded = rawPathname
  try {
    decoded = rawPathname
      .replace(/%2e/gi, '.')
      .replace(/%2f/gi, '/')
      .replace(/%5c/gi, '/')
      .replace(/\\/g, '/')
  } catch { /* keep raw */ }
  const segments: string[] = []
  for (const rawSeg of decoded.split('/')) {
    if (!rawSeg || rawSeg === '.') continue
    if (rawSeg === '..') {
      segments.pop()
      continue
    }
    segments.push(rawSeg)
  }
  return `/${segments.join('/')}`
}

function extractBucketAndKey(
  provider: SignedCloudStorageProvider,
  host: string,
  canonicalPathname: string,
): { bucket: string; objectKey: string; parentDir: string; normalizedParentDir: string } {
  const parts = canonicalPathname.split('/').filter(Boolean)
  let bucket = ''
  let keyParts: string[] = []
  if (provider === 'gcs') {
    const virtualMatch = /^([a-z0-9][a-z0-9._-]{1,62})\.storage\.googleapis\.com$/i.exec(host)
    if (virtualMatch) {
      bucket = virtualMatch[1]!.toLowerCase()
      keyParts = parts
    } else {
      bucket = (parts[0] ?? '').toLowerCase()
      keyParts = parts.slice(1)
    }
  } else if (provider === 'aws_s3') {
    const virtualMatch = /^([a-z0-9][a-z0-9.-]*?)\.s3(?:[.-](?:accelerate|dualstack|[a-z0-9-]+))?\.amazonaws\.com$/i.exec(host)
    if (virtualMatch) {
      bucket = virtualMatch[1]!.toLowerCase()
      keyParts = parts
    } else {
      bucket = (parts[0] ?? '').toLowerCase()
      keyParts = parts.slice(1)
    }
  } else if (provider === 'azure_blob') {
    const acct = host.split('.')[0]?.toLowerCase() ?? ''
    const container = (parts[0] ?? '').toLowerCase()
    bucket = container ? `${acct}/${container}` : acct
    keyParts = parts.slice(1)
  } else {
    bucket = (parts[0] ?? '').toLowerCase()
    keyParts = parts.slice(1)
  }

  const dirParts = parts.length > 1 ? parts.slice(0, -1) : []
  const parentDir = dirParts.length > 0 ? `/${dirParts.join('/')}/` : '/'
  const normDirParts = dirParts.map((seg, idx) => {
    if (idx === 0 && bucket && seg.toLowerCase() === bucket) return seg.toLowerCase()
    const isDynamic = DYNAMIC_PATH_SEG_RE.test(seg) && (/\d/.test(seg) || seg.length >= 24)
    return isDynamic ? '<dynamic>' : seg.toLowerCase()
  })
  const normalizedParentDir = normDirParts.length > 0 ? `/${normDirParts.join('/')}/` : '/'
  return {
    bucket,
    objectKey: keyParts.join('/'),
    parentDir,
    normalizedParentDir,
  }
}

function parseSignedCloudUrl(rawUrl: string): ParsedSignedCloudUrl | null {
  const trimmed = rawUrl.trim().replace(/[),.;]+$/, '')
  if (!trimmed.toLowerCase().startsWith('https://')) return null
  let parsed: URL
  try { parsed = new URL(trimmed) } catch { return null }
  if (parsed.protocol !== 'https:') return null
  const host = parsed.hostname.toLowerCase()
  const provider = classifyCloudStorageHost(host)
  if (!provider) return null

  const sp = parsed.searchParams
  let signatureParam = ''
  let signature = ''
  let algorithm: string | null = null
  let writeCapable = false
  let writeReason: string | null = null

  if (provider === 'gcs') {
    const v4Sig = queryParamCI(sp, 'X-Goog-Signature')
    const v4Alg = queryParamCI(sp, 'X-Goog-Algorithm')
    const v2Sig = queryParamCI(sp, 'Signature')
    const v2Id = queryParamCI(sp, 'GoogleAccessId')
    const v2Exp = queryParamCI(sp, 'Expires')
    if (v4Sig && v4Alg) {
      signatureParam = 'X-Goog-Signature'
      signature = v4Sig
      algorithm = v4Alg
      const signedHeaders = (queryParamCI(sp, 'X-Goog-SignedHeaders') ?? '').toLowerCase()
      if (signedHeaders.includes('content-type') || signedHeaders.includes('x-goog-') || queryParamCI(sp, 'uploadType') || queryParamCI(sp, 'x-goog-resumable')) {
        writeCapable = true
        writeReason = 'gcs_signed_write_headers'
      }
    } else if (v2Sig && v2Id && v2Exp) {
      signatureParam = 'Signature'
      signature = v2Sig
      algorithm = 'GOOG2-RSA-SHA256'
    } else {
      return null
    }
  } else if (provider === 'aws_s3' || provider === 'cloudflare_r2') {
    const v4Sig = queryParamCI(sp, 'X-Amz-Signature')
    const v4Alg = queryParamCI(sp, 'X-Amz-Algorithm')
    const v2Sig = queryParamCI(sp, 'Signature')
    const v2Key = queryParamCI(sp, 'AWSAccessKeyId')
    const v2Exp = queryParamCI(sp, 'Expires')
    if (v4Sig && v4Alg) {
      signatureParam = 'X-Amz-Signature'
      signature = v4Sig
      algorithm = v4Alg
      const signedHeaders = (queryParamCI(sp, 'X-Amz-SignedHeaders') ?? '').toLowerCase()
      if (signedHeaders.includes('content-type') || signedHeaders.includes('x-amz-') || queryParamCI(sp, 'uploadId') || queryParamCI(sp, 'partNumber') || queryParamCI(sp, 'x-amz-acl')) {
        writeCapable = true
        writeReason = 's3_signed_write_headers'
      }
    } else if (v2Sig && v2Key && v2Exp) {
      signatureParam = 'Signature'
      signature = v2Sig
      algorithm = 'AWS2-HMAC-SHA1'
    } else {
      return null
    }
  } else {
    // Azure Blob SAS strictly requires `sig`, `se`, and write/create permission in `sp`.
    const sig = queryParamCI(sp, 'sig')
    const se = queryParamCI(sp, 'se')
    const perms = queryParamCI(sp, 'sp')
    if (!sig || !se || !perms || !/[wc]/i.test(perms)) return null
    signatureParam = 'sig'
    signature = sig
    algorithm = 'AZURE-SAS'
    writeCapable = true
    writeReason = `azure_sas_sp:${perms}`
  }

  if (!isHighEntropySignature(signature)) return null
  const canonicalPathname = canonicalizeStoragePathname(parsed.pathname)
  const { bucket, objectKey, parentDir, normalizedParentDir } = extractBucketAndKey(provider, host, canonicalPathname)
  if (!bucket || !objectKey) return null

  return {
    rawUrl: trimmed,
    provider,
    host,
    bucket,
    canonicalPathname,
    objectKey,
    parentDir,
    normalizedParentDir,
    signatureParam,
    signature,
    algorithm,
    writeCapable,
    writeReason,
  }
}

function extractSignedCloudUrls(exchange: SignedUrlMintExchange): {
  urls: ParsedSignedCloudUrl[]
  hasWriteEnvelopeHint: boolean
  writeHintReason: string | null
} {
  const candidates: string[] = []
  const seen = new Set<string>()
  let hasWriteEnvelopeHint = false
  let writeHintReason: string | null = null

  const pushCandidate = (value: string) => {
    const trimmed = value.trim()
    if (!trimmed || seen.has(trimmed) || candidates.length >= 24) return
    seen.add(trimmed)
    candidates.push(trimmed)
  }

  for (const [k, v] of Object.entries(exchange.responseHeaders ?? {})) {
    if (k.toLowerCase() === 'location' && typeof v === 'string') pushCandidate(v)
  }

  let parsedJson: unknown = exchange.responseJson
  if (parsedJson === undefined && typeof exchange.responseBody === 'string' && exchange.responseBody.trim()) {
    try { parsedJson = JSON.parse(exchange.responseBody) } catch { parsedJson = undefined }
  }
  const visitJson = (val: unknown, depth: number): void => {
    if (depth > 6 || val === null || val === undefined) return
    if (typeof val === 'string') {
      if (val.includes('https://')) {
        for (const match of val.matchAll(HTTPS_URL_CANDIDATE_RE)) pushCandidate(match[0])
      }
      return
    }
    if (Array.isArray(val)) {
      for (const item of val.slice(0, 32)) visitJson(item, depth + 1)
      return
    }
    if (typeof val === 'object') {
      for (const [k, child] of Object.entries(val as Record<string, unknown>)) {
        const lk = k.toLowerCase()
        if (typeof child === 'string') {
          if (/^(?:method|http_?method|verb)$/i.test(lk) && /^(?:PUT|POST)$/i.test(child.trim())) {
            hasWriteEnvelopeHint = true
            writeHintReason = `response_method:${child.trim().toUpperCase()}`
          } else if (/(?:upload|put|write)_?url/i.test(lk) && child.includes('https://')) {
            hasWriteEnvelopeHint = true
            writeHintReason = `response_field:${k}`
          } else if (WRITE_URL_FIELD_RE.test(lk) && child.includes('https://')) {
            pushCandidate(child)
          }
          if (child.includes('https://')) {
            for (const match of child.matchAll(HTTPS_URL_CANDIDATE_RE)) pushCandidate(match[0])
          }
        } else if (lk === 'fields' && child && typeof child === 'object' && !Array.isArray(child)) {
          // S3 presigned POST policy envelope
          const fObj = child as Record<string, unknown>
          if ('Policy' in fObj || 'policy' in fObj || 'X-Amz-Signature' in fObj || 'x-amz-signature' in fObj) {
            hasWriteEnvelopeHint = true
            writeHintReason = 's3_presigned_post_fields'
          }
          visitJson(child, depth + 1)
        } else {
          visitJson(child, depth + 1)
        }
      }
    }
  }
  if (parsedJson !== undefined) visitJson(parsedJson, 0)
  if (typeof exchange.responseBody === 'string' && exchange.responseBody.includes('https://')) {
    for (const match of exchange.responseBody.matchAll(HTTPS_URL_CANDIDATE_RE)) pushCandidate(match[0])
  }

  const urls: ParsedSignedCloudUrl[] = []
  const seenUrls = new Set<string>()
  for (const raw of candidates) {
    const parsed = parseSignedCloudUrl(raw)
    if (parsed && !seenUrls.has(parsed.rawUrl)) {
      seenUrls.add(parsed.rawUrl)
      urls.push(parsed)
    }
  }
  return { urls, hasWriteEnvelopeHint, writeHintReason }
}

function requestCarrierText(exchange: SignedUrlMintExchange): string {
  const headerVals = Object.entries(exchange.requestHeaders ?? {})
    .map(([k, v]) => `${k}:${v}`)
    .join('\n')
  const bodyText = typeof exchange.requestBody === 'string'
    ? exchange.requestBody
    : exchange.requestJson !== undefined
      ? (typeof exchange.requestJson === 'string' ? exchange.requestJson : JSON.stringify(exchange.requestJson))
      : ''
  return `${exchange.pathAndQuery}\n${headerVals}\n${bodyText}`
}

function normalizeOriginKey(origin: string): string {
  try { return new URL(origin).origin.toLowerCase() } catch { return origin.trim().toLowerCase().replace(/\/+$/, '') }
}

function canonicalRoutePath(pathAndQuery: string): string {
  return pathAndQuery.split('?')[0]!.split('#')[0]!.replace(/\/+$/, '').toLowerCase() || '/'
}

function containsRedactedRequestPlane(exchange: SignedUrlMintExchange): boolean {
  return REDACTED_PLACEHOLDER_RE.test(requestCarrierText(exchange))
}

function stableCanonicalJson(value: unknown, depth = 0): string {
  if (depth > 8) return 'null'
  if (value === null || typeof value !== 'object') return JSON.stringify(value)
  if (Array.isArray(value)) return `[${value.map(v => stableCanonicalJson(v, depth + 1)).join(',')}]`
  const entries = Object.entries(value as Record<string, unknown>).sort(([a], [b]) => a.localeCompare(b))
  return `{${entries.map(([k, v]) => `${JSON.stringify(k)}:${stableCanonicalJson(v, depth + 1)}`).join(',')}}`
}

function canonicalExchangeBody(exchange: SignedUrlMintExchange): string {
  if (exchange.requestJson !== undefined) {
    if (typeof exchange.requestJson === 'string') {
      const trimmed = exchange.requestJson.trim()
      if (!trimmed) return ''
      try { return stableCanonicalJson(JSON.parse(trimmed)) } catch { return trimmed }
    }
    return stableCanonicalJson(exchange.requestJson)
  }
  if (typeof exchange.requestBody === 'string') {
    const trimmed = exchange.requestBody.trim()
    if (!trimmed) return ''
    try { return stableCanonicalJson(JSON.parse(trimmed)) } catch { return trimmed }
  }
  return ''
}

function normalizedPersonaHandle(value: string | null | undefined): string | null {
  const trimmed = (value ?? '').trim().toLowerCase()
  if (!trimmed || /^(?:anonymous|anon|unauthenticated|none)$/.test(trimmed)) return null
  return trimmed
}

function isUnauthenticatedExchange(exchange: SignedUrlMintExchange): boolean {
  if (normalizedPersonaHandle(exchange.actorHandle)) return false
  if (exchange.consumedCapabilityId) return false
  if (exchange.consumedCapabilities && exchange.consumedCapabilities.length > 0) return false
  const wp = exchange.wireCredentialProvenance
  if (wp && (
    wp.sources.some(s => s === 'persona_vault' || s === 'session_jar' || s === 'ephemeral_observed')
    || wp.source === 'persona_and_jar'
    || wp.vaultHeaderNames.length > 0
    || wp.vaultCookieNames.length > 0
    || wp.jarCookieNames.length > 0
  )) {
    return false
  }
  for (const [k, v] of Object.entries(exchange.requestHeaders ?? {})) {
    const lk = k.toLowerCase()
    if ((lk === 'authorization' || lk === 'cookie' || lk === 'proxy-authorization') && v.trim().length > 0) {
      return false
    }
  }
  return true
}

function hasPathInjectionIntoNestedDir(
  control: ParsedSignedCloudUrl,
  probe: ParsedSignedCloudUrl,
  prbCarrier: NormalizedRequestCarrier,
): boolean {
  if (prbCarrier.malformedEscape) return false
  if (probe.normalizedParentDir === control.normalizedParentDir) return false
  const probeSegs = probe.normalizedParentDir.split('/').filter(Boolean)
  const ctlSegs = control.normalizedParentDir.split('/').filter(Boolean)
  const extraSegs = probeSegs.slice(ctlSegs.length).filter(seg => seg !== '<dynamic>' && seg.length >= 2)
  if (extraSegs.length === 0) return false
  const decodedAll = [...prbCarrier.inputComponents, ...prbCarrier.comparables].join('\n').toLowerCase()
  const hasSep = decodedAll.includes('/') || decodedAll.includes('..') || decodedAll.includes('\\')
  return hasSep && extraSegs.some(seg => decodedAll.includes(seg))
}

/**
 * Authoritative, fail-closed host-verified oracle for `signed_url_mint` (R4-C-6 / P0 #2).
 *
 * Evaluates strictly over host-signed transcript exchanges:
 *   - Fail-closed per-component carrier normalization on BOTH control & probe (rejecting malformed
 *     percent and JSON unicode escapes) and echo-checking BOTH arms against decoded carriers.
 *   - Variant A (`key_traversal`): same-persona 2xx control vs 2xx probe on the same approved
 *     origin & route, with a single differing parameter carrying a traversal/separator construct,
 *     optional in-prefix ablation arm check, same host & bucket (host/bucket differences are
 *     non-evidence), and distinct non-echoed signatures where probe escapes the control parent dir.
 *   - Variant B (`unauth_write_mint`): anonymous 401/403 authentication-denied negative control
 *     (never 400/422 validation errors) on the same route & canonical body vs unauthenticated 2xx
 *     probe minting a valid high-entropy non-echoed write-capable signed cloud URL.
 */
export function assessSignedUrlMintDifferential(input: {
  control: SignedUrlMintExchange
  probe: SignedUrlMintExchange
  ablation?: SignedUrlMintExchange | null
  controlSessionId?: string | null
  probeSessionId?: string | null
  ablationSessionId?: string | null
  variant?: SignedUrlMintVariant | 'auto'
}): SignedUrlMintAssessment {
  const { control, probe, ablation } = input
  const requestedVariant = input.variant ?? 'auto'
  const fail = (
    rejectedBy: string,
    missingEvidence: string[],
    reason: string,
    extra: Record<string, unknown> = {},
  ): SignedUrlMintAssessment => ({
    confirmed: false,
    variant: null,
    provider: null,
    reason,
    rejectedBy,
    missingEvidence,
    evidence: {
      controlStatus: control.status,
      probeStatus: probe.status,
      ...extra,
    },
  })

  if (containsRedactedRequestPlane(control) || containsRedactedRequestPlane(probe) || (ablation && containsRedactedRequestPlane(ablation))) {
    return fail(
      'redacted_request_plane',
      ['clean_request_plane'],
      'Signed-URL oracle rejected: kernel request plane contains a redacted placeholder.',
    )
  }

  const ctlCarrier = normalizeRequestCarrier(control)
  const prbCarrier = normalizeRequestCarrier(probe)
  const ablCarrier = ablation ? normalizeRequestCarrier(ablation) : null
  if (ctlCarrier.malformedEscape || prbCarrier.malformedEscape || ablCarrier?.malformedEscape) {
    const reason = ctlCarrier.malformedEscape
      ? `Signed-URL control request contained a malformed escape (${ctlCarrier.malformedReason}); anti-reflection fails closed.`
      : prbCarrier.malformedEscape
        ? `Signed-URL probe request contained a malformed escape (${prbCarrier.malformedReason}); anti-reflection fails closed.`
        : `Signed-URL ablation request contained a malformed escape (${ablCarrier?.malformedReason}); anti-reflection fails closed.`
    return fail('signed_url_malformed_request_carrier', ['clean_request_carrier'], reason)
  }

  const ctlOrigin = normalizeOriginKey(control.origin)
  const prbOrigin = normalizeOriginKey(probe.origin)
  if (!ctlOrigin || ctlOrigin !== prbOrigin) {
    return fail(
      'signed_url_origin_mismatch',
      ['same_origin_control_and_probe'],
      `Control (${ctlOrigin || 'none'}) and probe (${prbOrigin || 'none'}) target different origins.`,
    )
  }
  const ctlMethod = control.method.toUpperCase()
  const prbMethod = probe.method.toUpperCase()
  if (ctlMethod !== prbMethod) {
    return fail(
      'signed_url_method_mismatch',
      ['same_method_control_and_probe'],
      `Control (${ctlMethod}) and probe (${prbMethod}) use different HTTP methods.`,
    )
  }
  const ctlRoute = canonicalRoutePath(control.pathAndQuery)
  const prbRoute = canonicalRoutePath(probe.pathAndQuery)
  if (ctlRoute !== prbRoute) {
    return fail(
      'signed_url_route_mismatch',
      ['same_route_control_and_probe'],
      `Control (${ctlRoute}) and probe (${prbRoute}) target different routes.`,
    )
  }

  const ctlStatus = control.status
  const prbStatus = probe.status
  const ctlIs2xx = ctlStatus !== null && ctlStatus >= 200 && ctlStatus < 300
  const ctlIsAuthDenied = ctlStatus === 401 || ctlStatus === 403
  const ctlIs4xx = ctlStatus !== null && ctlStatus >= 400 && ctlStatus < 500
  const prbIs2xx = prbStatus !== null && prbStatus >= 200 && prbStatus < 300
  if (!prbIs2xx) {
    return fail(
      'signed_url_probe_not_2xx',
      ['probe_2xx_signed_url'],
      `Probe returned status ${prbStatus ?? 'null'}; a 2xx response minting a signed cloud-storage URL is required.`,
    )
  }

  const probeExtracted = extractSignedCloudUrls(probe)
  if (probeExtracted.urls.length === 0) {
    return fail(
      'signed_url_missing_or_invalid',
      ['valid_cloud_signed_url'],
      'Probe response does not contain a valid cloud-storage signed URL with high-entropy cryptographic signature query parameters.',
    )
  }

  const nonEchoedProbeUrls = probeExtracted.urls.filter(u => !carrierEchoesSignedUrlNeedles(prbCarrier, [u.signature, u.rawUrl]))
  if (nonEchoedProbeUrls.length === 0) {
    return fail(
      'signed_url_echoed',
      ['server_generated_signature'],
      'Probe signed URL or cryptographic signature was echoed from the normalized request carrier rather than generated by the server.',
    )
  }

  // Variant A: Key-traversal differential (same-persona 2xx control vs 2xx probe)
  if (ctlIs2xx && requestedVariant !== 'unauth_write_mint') {
    const ctlPersona = normalizedPersonaHandle(control.actorHandle ?? control.wireCredentialProvenance?.personaHandle)
    const prbPersona = normalizedPersonaHandle(probe.actorHandle ?? probe.wireCredentialProvenance?.personaHandle)
    const ctlSess = (input.controlSessionId ?? control.wireCredentialProvenance?.session ?? null) || null
    const prbSess = (input.probeSessionId ?? probe.wireCredentialProvenance?.session ?? null) || null
    const ctlAuthed = Boolean(ctlPersona || ctlSess || control.wireCredentialProvenance?.authenticated)
    const prbAuthed = Boolean(prbPersona || prbSess || probe.wireCredentialProvenance?.authenticated)
    if (ctlPersona !== prbPersona || ctlSess !== prbSess || ctlAuthed !== prbAuthed) {
      return fail(
        'signed_url_persona_mismatch',
        ['same_persona_control_and_probe'],
        `Signed-URL key_traversal rejected (R4-C-6): control (${ctlPersona ?? 'anon'}) and probe (${prbPersona ?? 'anon'}) must execute under the exact same persona/session.`,
      )
    }

    const ctlExtracted = extractSignedCloudUrls(control)
    if (ctlExtracted.urls.length === 0) {
      return fail(
        'signed_url_control_missing',
        ['control_signed_url'],
        'Control returned 2xx but did not contain a valid cloud-storage signed URL for baseline comparison.',
      )
    }
    const nonEchoedControlUrls = ctlExtracted.urls.filter(u => !carrierEchoesSignedUrlNeedles(ctlCarrier, [u.signature, u.rawUrl]))
    if (nonEchoedControlUrls.length === 0) {
      return fail(
        'signed_url_control_echoed',
        ['server_generated_control_signature'],
        'Control signed URL or cryptographic signature was echoed from the normalized control request carrier.',
      )
    }
    if (ctlCarrier.raw === prbCarrier.raw) {
      return fail(
        'signed_url_identical_request',
        ['differing_probe_input'],
        'Control and probe requests are identical; a traversal differential requires distinct control vs probe input.',
      )
    }

    const hasBoundTraversalInput = hasTraversalOrSeparatorDifferential(ctlCarrier, prbCarrier, 'single_param')
    const ablationUrls = (() => {
      if (!ablation || !ablCarrier) return null
      if (ablation.status === null || ablation.status < 200 || ablation.status >= 300) return []
      return extractSignedCloudUrls(ablation).urls.filter(u => !carrierEchoesSignedUrlNeedles(ablCarrier, [u.signature, u.rawUrl]))
    })()

    let sawSameSignature = false
    let sawNoEscape = false
    let sawHostOrBucketOnly = false
    let sawNoTraversalInput = false
    let sawAblationEscaped = false
    for (const prbUrl of nonEchoedProbeUrls) {
      for (const ctlUrl of nonEchoedControlUrls) {
        if (ctlUrl.signature === prbUrl.signature) {
          sawSameSignature = true
          continue
        }
        const hostEscaped = prbUrl.host !== ctlUrl.host
        const bucketEscaped = prbUrl.bucket !== ctlUrl.bucket
        if (hostEscaped || bucketEscaped) {
          sawHostOrBucketOnly = true
          continue
        }
        const escapedParentPrefix = !prbUrl.normalizedParentDir.startsWith(ctlUrl.normalizedParentDir)
        const injectedNestedDir = !escapedParentPrefix && hasPathInjectionIntoNestedDir(ctlUrl, prbUrl, prbCarrier)
        if (escapedParentPrefix || injectedNestedDir) {
          if (!hasBoundTraversalInput) {
            sawNoTraversalInput = true
            continue
          }
          if (ablationUrls && ablationUrls.length > 0) {
            const ablationStaysInPrefix = ablationUrls.some(
              au => au.host === ctlUrl.host && au.bucket === ctlUrl.bucket && au.normalizedParentDir.startsWith(ctlUrl.normalizedParentDir),
            )
            if (!ablationStaysInPrefix) {
              sawAblationEscaped = true
              continue
            }
          }
          const escapeKind = escapedParentPrefix ? 'parent_prefix_escape' : 'injected_prefix_escape'
          return {
            confirmed: true,
            variant: 'key_traversal',
            provider: prbUrl.provider,
            reason: `Server re-signed a canonicalized ${prbUrl.provider} object path (${prbUrl.canonicalPathname}) escaping control prefix (${ctlUrl.parentDir}) via ${escapeKind} with a distinct server-generated cryptographic signature (${prbUrl.signatureParam}).`,
            rejectedBy: null,
            missingEvidence: [],
            evidence: {
              variant: 'key_traversal',
              escapeKind,
              provider: prbUrl.provider,
              controlStatus: ctlStatus,
              probeStatus: prbStatus,
              controlHost: ctlUrl.host,
              probeHost: prbUrl.host,
              controlBucket: ctlUrl.bucket,
              probeBucket: prbUrl.bucket,
              controlPathname: ctlUrl.canonicalPathname,
              probePathname: prbUrl.canonicalPathname,
              controlParentDir: ctlUrl.parentDir,
              probeParentDir: prbUrl.parentDir,
              signatureParam: prbUrl.signatureParam,
              algorithm: prbUrl.algorithm,
              signatureDistinct: true,
              ...(ablation ? { ablationVerifiedInPrefix: Boolean(ablationUrls && ablationUrls.length > 0) } : {}),
            },
          }
        }
        sawNoEscape = true
      }
    }
    if (sawAblationEscaped) {
      return fail(
        'signed_url_ablation_escaped',
        ['in_prefix_ablation_control'],
        'In-prefix ablation arm also escaped the control directory prefix; prefix change is not bound to the traversal construct.',
      )
    }
    if (sawNoTraversalInput) {
      return fail(
        'signed_url_no_traversal_input',
        ['traversal_or_separator_input'],
        'Signed-URL key_traversal rejected (R4-C-6): probe must differ in a single parameter carrying a traversal or path-separator construct (benign multi-folder presign is not CWE-22).',
      )
    }
    if (sawHostOrBucketOnly && !sawNoEscape) {
      return fail(
        'signed_url_host_or_bucket_non_evidence',
        ['bound_prefix_traversal'],
        'Signed-URL key_traversal rejected (R4-C-6): host/bucket differences alone are non-evidence without a bound prefix traversal.',
      )
    }
    if (sawSameSignature && !sawNoEscape) {
      return fail(
        'signed_url_identical_signature',
        ['distinct_server_signature'],
        'Control and probe returned the identical cryptographic signature; the server did not re-sign a traversed object path.',
      )
    }
    return fail(
      'signed_url_no_prefix_escape',
      ['canonical_prefix_or_bucket_escape'],
      'Probe signed URL remained inside the control directory/prefix with no parent-prefix escape.',
      {
        controlPathname: nonEchoedControlUrls[0]?.canonicalPathname ?? null,
        probePathname: nonEchoedProbeUrls[0]?.canonicalPathname ?? null,
      },
    )
  }

  // Variant B: Unauthenticated privileged write-URL minting (anonymous 401/403 control on same route & body vs unauth 2xx probe)
  if (ctlIs4xx && requestedVariant !== 'key_traversal') {
    if (!ctlIsAuthDenied) {
      return fail(
        'signed_url_control_not_auth_denied',
        ['auth_denied_401_or_403_control'],
        `Signed-URL unauth_write_mint rejected (R4-C-6): negative control must be an authentication/authorization denial (401/403), not ${ctlStatus ?? 'null'} (validation errors on public presign endpoints are not CWE-306).`,
      )
    }
    if (!isUnauthenticatedExchange(control)) {
      return fail(
        'signed_url_control_authenticated',
        ['anonymous_401_or_403_control'],
        'Signed-URL unauth_write_mint rejected (R4-C-6): negative 401/403 control must be anonymous.',
      )
    }
    if (canonicalExchangeBody(control) !== canonicalExchangeBody(probe)) {
      return fail(
        'signed_url_control_body_mismatch',
        ['same_body_negative_control'],
        'Signed-URL unauth_write_mint rejected (R4-C-6): negative 401/403 control must use the same route and request body as the probe.',
      )
    }
    const ctlExtracted = extractSignedCloudUrls(control)
    if (ctlExtracted.urls.length > 0) {
      return fail(
        'signed_url_control_minted',
        ['negative_401_or_403_control'],
        'Control exchange returned a signed cloud URL despite 401/403 status; a clean negative control is required.',
      )
    }
    if (!isUnauthenticatedExchange(probe)) {
      return fail(
        'signed_url_probe_authenticated',
        ['unauthenticated_probe'],
        'Unauthenticated write-URL minting requires an unauthenticated probe (no persona, session cookie, capability, or Authorization header).',
      )
    }
    const isMutatingRoute = (prbMethod === 'POST' || prbMethod === 'PUT' || prbMethod === 'PATCH')
      && (probeExtracted.hasWriteEnvelopeHint || WRITE_ROUTE_HINT_RE.test(prbRoute))
    const writeUrl = nonEchoedProbeUrls.find(u => u.writeCapable || isMutatingRoute)
    if (!writeUrl) {
      return fail(
        'signed_url_not_write_capable',
        ['write_capable_signed_url'],
        'Minted signed URL lacks verifiable write-capability (no Azure SAS write/create sp, no GCS/S3 write-signed headers/params, and no mutating upload-URL envelope).',
      )
    }
    return {
      confirmed: true,
      variant: 'unauth_write_mint',
      provider: writeUrl.provider,
      reason: `Unauthenticated ${prbMethod} ${prbRoute} minted a write-capable ${writeUrl.provider} signed URL (${writeUrl.canonicalPathname}, ${writeUrl.signatureParam}) against an anonymous ${ctlStatus} negative control.`,
      rejectedBy: null,
      missingEvidence: [],
      evidence: {
        variant: 'unauth_write_mint',
        provider: writeUrl.provider,
        controlStatus: ctlStatus,
        probeStatus: prbStatus,
        probeHost: writeUrl.host,
        probeBucket: writeUrl.bucket,
        probePathname: writeUrl.canonicalPathname,
        signatureParam: writeUrl.signatureParam,
        algorithm: writeUrl.algorithm,
        writeReason: writeUrl.writeReason ?? probeExtracted.writeHintReason ?? 'mutating_upload_endpoint',
        unauthenticated: true,
      },
    }
  }

  return fail(
    'signed_url_control_invalid',
    ['valid_control_exchange'],
    `Control returned status ${ctlStatus ?? 'null'}; expected 2xx signed-URL control for key_traversal or 401/403 negative control for unauth_write_mint.`,
  )
}

// ---------------------------------------------------------------------------
// R4-H-4 / R4-C-2: Worker-visible digest & challenge sanitization primitives
// ---------------------------------------------------------------------------

/**
 * R4-H-4: Compute worker-facing `bodyBytes` and `bodySha256` strictly over the
 * worker-visible vault-scrubbed body (NEVER over plaintext injected sealed values).
 */
export function computeWorkerVisibleBodyDigest(
  rawBody: string | null | undefined,
  scrubFn: (text: string) => string,
): { scrubbedBody: string; bodyBytes: number; bodySha256: string } {
  const scrubbedBody = rawBody ? scrubFn(rawBody) : ''
  return {
    scrubbedBody,
    bodyBytes: Buffer.byteLength(scrubbedBody, 'utf8'),
    bodySha256: createHash('sha256').update(scrubbedBody, 'utf8').digest('hex'),
  }
}

const MAX_WORKER_PREVIEW_BODY_LEN = 512 * 1024

/**
 * R4-H-4 / R4-C-2: Defense-in-depth sanitizer applied inside `scrubRecord`:
 *  1. Strips `expectedOutput`, `operandA`, `operandB`, `operator`, and `expressionSyntax`
 *     from any worker-facing host-minted expression challenge object so workers never
 *     receive challenge answers or operands.
 *  2. Recomputes `bodySha256`/`bodyBytes` from an already-scrubbed sibling `body` field
 *     whenever `body` is below the 512 KiB truncation cap, preventing raw digests from
 *     slipping through any RPC summary.
 *  3. Replaces any raw `observedValueDigests` hex entries with host-keyed HMAC digests.
 */
export function sanitizeWorkerFacingObject<T>(value: T, hmacKey: string): T {
  const walk = (node: unknown, depth: number): unknown => {
    if (depth > 16 || node === null || node === undefined || typeof node !== 'object') return node
    if (Array.isArray(node)) return node.map(item => walk(item, depth + 1))
    const rec = node as Record<string, unknown>
    const isExprChallenge = typeof rec.challengeId === 'string'
      && rec.challengeId.startsWith('expr_')
      && ('expectedOutput' in rec || 'operandA' in rec || 'operandB' in rec || 'expressionSyntax' in rec)
    if (isExprChallenge) {
      return {
        challengeId: rec.challengeId,
        ...(typeof rec.family === 'string' ? { family: rec.family } : {}),
        ...(typeof rec.mintedAtMs === 'number' ? { mintedAtMs: rec.mintedAtMs } : {}),
      }
    }
    const out: Record<string, unknown> = {}
    for (const [k, v] of Object.entries(rec)) {
      if (k === 'observedValueDigests' && Array.isArray(v)) {
        out[k] = v.map(item => (typeof item === 'string'
          ? createHmac('sha256', hmacKey).update(item, 'utf8').digest('hex')
          : walk(item, depth + 1)))
        continue
      }
      out[k] = walk(v, depth + 1)
    }
    if (
      typeof out.body === 'string'
      && out.body.length < MAX_WORKER_PREVIEW_BODY_LEN
      && ('bodySha256' in out || 'bodyBytes' in out)
    ) {
      if ('bodySha256' in out) out.bodySha256 = createHash('sha256').update(out.body, 'utf8').digest('hex')
      if ('bodyBytes' in out) out.bodyBytes = Buffer.byteLength(out.body, 'utf8')
    }
    return out
  }
  return walk(value, 0) as T
}

// ---------------------------------------------------------------------------
// Synthetic authMutation passthrough validation (paired with @fix-synth-auth-probe)
// ---------------------------------------------------------------------------

const SYNTHETIC_AUTH_MUTATION_KINDS = new Set(['synthetic_invalid_bearer', 'synthetic_invalid_api_key'])
const PERSONA_AUTH_MUTATION_KINDS = new Set([
  'alg_none',
  'strip_signature',
  'expired_replay',
  'rs256_to_hs256_jwks',
  'kid_inject',
  'jku_x5u_canary',
  'claim_swap',
])
const SAFE_API_KEY_HEADER_RE = /^[A-Za-z0-9_-]{1,64}$/

/**
 * Validate and normalize RPC `authMutation` arguments.
 * Allows `synthetic_invalid_bearer` and `synthetic_invalid_api_key` without a persona handle,
 * while keeping persona-mutating kinds strictly fail-closed when `persona` is absent.
 */
export function parseVerifyAuthMutation(
  raw: unknown,
  persona: string | undefined,
): Record<string, unknown> | undefined {
  if (raw === undefined || raw === null) return undefined
  if (typeof raw !== 'object' || Array.isArray(raw)) {
    throw new Error('authMutation must be an object with a valid `kind`.')
  }
  const rec = raw as Record<string, unknown>
  const kind = typeof rec.kind === 'string' ? rec.kind.trim() : ''
  if (SYNTHETIC_AUTH_MUTATION_KINDS.has(kind)) {
    if (kind === 'synthetic_invalid_api_key' && rec.headerName !== undefined) {
      if (typeof rec.headerName !== 'string' || !SAFE_API_KEY_HEADER_RE.test(rec.headerName.trim())) {
        throw new Error('authMutation.headerName must be a valid HTTP header token.')
      }
      return { kind, headerName: rec.headerName.trim() }
    }
    return { kind }
  }
  if (!PERSONA_AUTH_MUTATION_KINDS.has(kind)) {
    throw new Error(`Unsupported authMutation kind "${kind || '<empty>'}".`)
  }
  if (!persona) {
    throw new Error('authMutation requires an approved persona handle.')
  }
  return { ...rec, kind }
}

// ---------------------------------------------------------------------------
// P1 #6: ScopedBrowser -> VerifyBrowserDriver adapter & run/grant registry
// ---------------------------------------------------------------------------

export interface ScopedBrowserLike {
  visitPage(
    req: {
      origin: string
      pathAndQuery: string
      persona?: string
      runId?: string
      assignmentId?: string
      selector?: string
      timeoutMs?: number
      readOnlyMode?: boolean
    },
    grant: Grant,
    signal: AbortSignal,
  ): Promise<{
    finalUrl: string
    title: string
    status: number | null
    domSnippet: string
    canaryCheck?: { token: string | null; triggered: boolean; attested?: boolean }
    attestedSinks?: string[]
    attestation?: { verified: boolean; attestedSinks: string[] }
  }>
}

export interface VerifyBrowserDriverLike {
  open(
    request: {
      url: string
      origin: string
      personaHandle: string | null
      headers: Record<string, string>
      waitForSelector?: string
      timeoutMs: number
    },
    signal: AbortSignal,
  ): Promise<{
    status: number
    url: string
    html: string
    title?: string
    executedSentinels?: string[]
  }>
}

const grantBrowserRegistry = new WeakMap<Grant, ScopedBrowserLike>()
const runBrowserRegistry = new Map<string, ScopedBrowserLike>()
const MAX_REGISTERED_RUN_BROWSERS = 512

/** Bind a run's `ScopedBrowser` to an issued `Grant` (auto-GC'd with the Grant). */
export function bindScopedBrowserToGrant(grant: Grant, browser: ScopedBrowserLike): void {
  if ((grant.tier ?? 0) < 1) return
  grantBrowserRegistry.set(grant, browser)
}

/** Register a run's `ScopedBrowser` by runId (bounded LRU cap) for Tier >= 1 `kovo_verify` runs. */
export function registerScopedBrowserForRun(runId: string, browser: ScopedBrowserLike): void {
  const key = runId.trim()
  if (!key) return
  if (runBrowserRegistry.has(key)) runBrowserRegistry.delete(key)
  runBrowserRegistry.set(key, browser)
  if (runBrowserRegistry.size > MAX_REGISTERED_RUN_BROWSERS) {
    const oldest = runBrowserRegistry.keys().next().value
    if (oldest !== undefined) runBrowserRegistry.delete(oldest)
  }
}

export function unregisterScopedBrowserForRun(runId: string): void {
  runBrowserRegistry.delete(runId.trim())
}

/** Wrap a `ScopedBrowser` instance as a `VerifyBrowserDriver` for `VerifyRpcServer` (`ctx.browser()`). */
function createScopedBrowserVerifyDriver(
  browser: ScopedBrowserLike,
  ctx: { grant: Grant; runId: string; assignmentId: string },
): VerifyBrowserDriverLike {
  return {
    async open(request, signal) {
      const parsed = new URL(request.url)
      const pathAndQuery = `${parsed.pathname}${parsed.search}${parsed.hash}`
      const visit = await browser.visitPage(
        {
          origin: request.origin,
          pathAndQuery,
          ...(request.personaHandle ? { persona: request.personaHandle } : {}),
          runId: ctx.runId,
          assignmentId: ctx.assignmentId,
          ...(request.waitForSelector ? { selector: request.waitForSelector } : {}),
          timeoutMs: request.timeoutMs,
          readOnlyMode: true,
        },
        ctx.grant,
        signal,
      )
      const sentinels = new Set<string>()
      for (const sink of visit.attestedSinks ?? []) if (sink) sentinels.add(sink)
      if (visit.attestation?.verified) {
        for (const sink of visit.attestation.attestedSinks ?? []) if (sink) sentinels.add(sink)
      }
      if (visit.canaryCheck?.attested && visit.canaryCheck.token) {
        sentinels.add(visit.canaryCheck.token)
      }
      return {
        status: visit.status ?? 200,
        url: visit.finalUrl || request.url,
        html: visit.domSnippet ?? '',
        ...(visit.title ? { title: visit.title } : {}),
        executedSentinels: [...sentinels],
      }
    },
  }
}

/**
 * Resolve the effective `VerifyBrowserDriver` for a `VerifyRpcServer` session:
 *   1. Explicit `options.browser` always wins (tests & custom drivers).
 *   2. For Tier >= 1 runs, falls back to the `ScopedBrowser` bound to `grant` or `runId`.
 *   3. Tier 0 runs fail closed (`undefined`).
 */
export function resolveScopedBrowserDriverForVerify(options: {
  explicitDriver?: VerifyBrowserDriverLike
  grant: Grant
  runId: string
  assignmentId: string
}): VerifyBrowserDriverLike | undefined {
  if (options.explicitDriver) return options.explicitDriver
  if ((options.grant.tier ?? 0) < 1) return undefined
  const scoped = grantBrowserRegistry.get(options.grant) ?? runBrowserRegistry.get(options.runId.trim())
  if (!scoped) return undefined
  return createScopedBrowserVerifyDriver(scoped, {
    grant: options.grant,
    runId: options.runId,
    assignmentId: options.assignmentId,
  })
}
