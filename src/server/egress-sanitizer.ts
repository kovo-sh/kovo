/**
 * Single typed egress sanitization boundary for every byte crossing out of the host kernel:
 * LLM context, LLM tool-call arguments, Docker worker RPC responses, Browser tool results,
 * SQLite/UI logs, and exports.
 *
 * Orthogonal guarantees:
 *   1. Exact-value redaction (`redactSecrets`): redacts registered vault secrets, active session
 *      tokens, provider keys, and sealed capability values (>= 8 chars) across raw, URL-encoded
 *      (upper/lower/form), base64 (padded/unpadded/URL-encoded), base64url, JSON-escaped, PHP
 *      slash-escaped, and HTML-entity encodings — with ZERO heuristic keyword regexes on tool
 *      arguments or code (preserves H-25, fixes M-13/M-14).
 *   2. Uniform structural header stripping (`sanitizeHttpHeaders`): strips sensitive auth/session
 *      headers (`Authorization`, `Cookie`, `Set-Cookie`, `X-Auth-Token`, `X-API-Key`,
 *      `Proxy-Authorization`, CSRF/session headers) identically across HTTP/1, HTTP/2, and Browser
 *      results (fixes H-7/H-8).
 *   3. Worker-facing opaque capability metadata (`toPublicCapabilityMeta`) and anti-oracle guards
 *      (`validateCapabilitySealValue`, `checkSealRateLimit`) so `capability.seal` never exposes
 *      raw-secret SHA-256 digests or acts as a byte-level extraction oracle (fixes C-3/H-10).
 */
import type { DerivedCapabilityMeta, DerivedCapabilityVault } from './derived-custody.ts'
import { vaultScrubDescriptors } from './derived-custody.ts'
import {
  DEFAULT_MAX_EXACT_SECRETS,
  SENSITIVE_HTTP_HEADER_RE,
  SecretMatcher,
  buildSecretEncodingVariants,
  compileSecretMatcher,
  redact,
  redactExactValues,
  redactHeaders,
  redactWithMatcher,
  type NamedSecret,
} from './redact.ts'
import { compileSafeClaimRegex } from './safe-regex.ts'

export { SENSITIVE_HTTP_HEADER_RE, buildSecretEncodingVariants }

export type EgressChannel =
  | 'llm_context'
  | 'llm_tool_args'
  | 'worker_rpc'
  | 'browser_result'
  | 'storage_log'
  | 'export'

export type PublicDerivedCapabilityMeta = Omit<DerivedCapabilityMeta, 'sha256' | 'sha256Prefix'>

export type CapabilitySealSelectorKind = 'jsonPath' | 'header' | 'cookie' | 'regex' | 'value'

export const DEFAULT_MIN_CAPABILITY_SECRET_LENGTH = 6
export const MIN_STRUCTURED_SEAL_LENGTH = 6
export const MIN_ORACLE_SELECTOR_SEAL_LENGTH = 8
export const DEFAULT_MAX_SEALS_PER_EXCHANGE = 12
export const DEFAULT_MAX_SEALS_PER_SESSION = 128
export const MAX_SEAL_REGEX_HAYSTACK_BYTES = 65_536

const EPHEMERAL_CAP_PLACEHOLDER_RE = /\[persona:(cap:hop_[A-Za-z0-9._-]+:[A-Za-z0-9._-]+):secret\]/g
const RAW_COOKIE_FIELD_RE = /^(?:cookie|set-cookie)$/i
const HEADER_OBJECT_KEYS = new Set(['headers', 'reqHeaders', 'respHeaders', 'requestHeaders', 'responseHeaders', 'upgradeHeaders'])
const REPEATED_SINGLE_CHAR_RE = /^(.)\1+$/
const STANDARD_CHAR_CLASS_RANGES = new Set(['a-z', 'A-Z', '0-9', 'a-f', 'A-F'])

export interface EgressSanitizerOptions {
  /** Static or dynamically-resolved registered vault/persona/session secrets. */
  secrets?: readonly NamedSecret[] | (() => readonly NamedSecret[])
  /** Optional provider API key (redacted as `[redacted]`). */
  providerKey?: string
  /** Optional capability vaults whose sealed values (>= minCapabilityLength) are scrubbed on egress. */
  capabilityVaults?: readonly DerivedCapabilityVault[] | (() => readonly DerivedCapabilityVault[])
  /** Minimum length for explicitly registered named secrets (default 4). */
  minSecretLength?: number
  /** Minimum length for sealed capability values redacted on egress (default 8). */
  minCapabilityLength?: number
  /** Maximum deduplicated secrets compiled into the exact-match automaton (default 5000). */
  maxSecrets?: number
}

export interface RedactSecretsOptions {
  providerKey?: string
  capabilityVaults?: readonly DerivedCapabilityVault[]
  minSecretLength?: number
  minCapabilityLength?: number
  maxSecrets?: number
}

function normalizeEphemeralCapPlaceholders(text: string): string {
  return text.includes('[persona:cap:hop_')
    ? text.replace(EPHEMERAL_CAP_PLACEHOLDER_RE, '[redacted:$1]')
    : text
}

function collectDedupedSecrets(
  secrets: readonly NamedSecret[],
  options: {
    providerKey?: string
    capabilityVaults?: readonly DerivedCapabilityVault[]
    minSecretLength: number
    minCapLength: number
    maxSecrets: number
  },
): NamedSecret[] {
  const combined: NamedSecret[] = []
  const seenValues = new Set<string>()
  const pushUnique = (entry: NamedSecret): void => {
    if (!entry.value || seenValues.has(entry.value)) return
    seenValues.add(entry.value)
    combined.push(entry)
  }

  if (options.providerKey && options.providerKey.length >= 4) {
    pushUnique({ value: options.providerKey, placeholder: '[redacted]' })
  }
  for (const vault of options.capabilityVaults ?? []) {
    for (const desc of vaultScrubDescriptors(vault, options.minCapLength)) {
      if (desc.value.length >= options.minCapLength) pushUnique(desc)
    }
  }
  const secretLimit = Math.max(options.maxSecrets, combined.length)
  for (const s of secrets) {
    if (combined.length >= secretLimit) break
    if (s.value && s.value.length >= options.minSecretLength) pushUnique(s)
  }
  return combined
}

/**
 * Exact-value redaction across raw, URL-encoded, base64, base64url, JSON-escaped, and HTML-entity
 * encodings with ZERO heuristic keyword regexes. Safe for model tool arguments and code.
 */
export function redactSecrets(
  text: string,
  secrets: readonly NamedSecret[] = [],
  options: RedactSecretsOptions = {},
): string {
  if (!text) return text
  const minSecretLength = Math.max(1, options.minSecretLength ?? 4)
  const minCapLength = Math.max(1, options.minCapabilityLength ?? DEFAULT_MIN_CAPABILITY_SECRET_LENGTH)
  const maxSecrets = Math.max(1, options.maxSecrets ?? DEFAULT_MAX_EXACT_SECRETS)
  const combined = collectDedupedSecrets(secrets, {
    ...(options.providerKey ? { providerKey: options.providerKey } : {}),
    ...(options.capabilityVaults ? { capabilityVaults: options.capabilityVaults } : {}),
    minSecretLength,
    minCapLength,
    maxSecrets,
  })
  if (combined.length === 0) return normalizeEphemeralCapPlaceholders(text)
  const matcher = compileSecretMatcher(combined, { minLength: 1, maxSecrets: combined.length })
  return normalizeEphemeralCapPlaceholders(matcher.redact(text))
}

/**
 * Uniform structural HTTP header stripping across HTTP/1, HTTP/2, and Browser results.
 * Strips sensitive auth/session headers (`Authorization`, `Cookie`, `Set-Cookie`, `X-Auth-Token`,
 * `X-API-Key`, `Proxy-Authorization`, CSRF/session headers) and redacts remaining values.
 */
export function sanitizeHttpHeaders(
  headers: Record<string, string | string[] | undefined>,
  secrets: readonly NamedSecret[] = [],
  options: RedactSecretsOptions = {},
): Record<string, string> {
  const minSecretLength = Math.max(1, options.minSecretLength ?? 4)
  const minCapLength = Math.max(1, options.minCapabilityLength ?? DEFAULT_MIN_CAPABILITY_SECRET_LENGTH)
  const maxSecrets = Math.max(1, options.maxSecrets ?? DEFAULT_MAX_EXACT_SECRETS)
  const combined = collectDedupedSecrets(secrets, {
    ...(options.providerKey ? { providerKey: options.providerKey } : {}),
    ...(options.capabilityVaults ? { capabilityVaults: options.capabilityVaults } : {}),
    minSecretLength,
    minCapLength,
    maxSecrets,
  })
  const matcher = combined.length > 0 ? compileSecretMatcher(combined, { minLength: 1, maxSecrets: combined.length }) : undefined
  const out: Record<string, string> = {}
  for (const [key, rawValue] of Object.entries(headers)) {
    if (rawValue === undefined) continue
    const value = Array.isArray(rawValue) ? rawValue.join(', ') : String(rawValue)
    if (SENSITIVE_HTTP_HEADER_RE.test(key)) {
      out[key] = '[redacted]'
      continue
    }
    const exactRedacted = normalizeEphemeralCapPlaceholders(matcher ? matcher.redact(value) : value)
    out[key] = redact(exactRedacted)
  }
  return out
}

/**
 * Worker-facing opaque capability metadata (C-3): strips raw-secret `sha256` and `sha256Prefix`
 * digests so `capability.seal` never acts as a hash/byte oracle over hidden response bytes.
 */
export function toPublicCapabilityMeta(meta: DerivedCapabilityMeta): PublicDerivedCapabilityMeta {
  const { sha256: _omitDigest, sha256Prefix: _omitPrefix, ...pub } = meta
  return {
    ...pub,
    ...(pub.allowedOrigins ? { allowedOrigins: [...pub.allowedOrigins] } : {}),
  }
}

function shannonEntropyBitsPerChar(value: string): number {
  if (!value.length) return 0
  const freq = new Map<string, number>()
  for (const ch of value) freq.set(ch, (freq.get(ch) ?? 0) + 1)
  let entropy = 0
  for (const count of freq.values()) {
    const p = count / value.length
    entropy -= p * Math.log2(p)
  }
  return entropy
}

/**
 * C-3 / H-8 anti-oracle validation on `capability.seal` extracted values:
 * rejects 1-char / short / trivial repeated-character / low-entropy probes so workers cannot
 * recover hidden response bytes character-by-character via regex or substring membership queries.
 */
export function validateCapabilitySealValue(rawValue: string, selector: CapabilitySealSelectorKind): void {
  const trimmed = rawValue.trim()
  const minLength = (selector === 'regex' || selector === 'value')
    ? MIN_ORACLE_SELECTOR_SEAL_LENGTH
    : MIN_STRUCTURED_SEAL_LENGTH
  if (!trimmed || trimmed.length < minLength) {
    throw new Error(
      `capability.seal rejected extracted value: minimum length is ${minLength} characters for "${selector}" selector (prevents byte-oracle probing).`,
    )
  }
  if (REPEATED_SINGLE_CHAR_RE.test(trimmed)) {
    throw new Error('capability.seal rejected trivial repeated-character value.')
  }
  const distinctChars = new Set(trimmed).size
  if (distinctChars < 3) {
    throw new Error('capability.seal rejected low-entropy extracted value (fewer than 3 distinct characters).')
  }
  const minEntropy = (selector === 'regex' || selector === 'value') ? 1.5 : 1.2
  if (shannonEntropyBitsPerChar(trimmed) < minEntropy) {
    throw new Error(`capability.seal rejected low-entropy extracted value for "${selector}" selector.`)
  }
}

/**
 * Inspect a character class body (the text between `[` and `]`) to detect binary-search
 * alphabet partitioning (e.g. `[a-m]`, `[n-z]`, `[0-4]`, `[5-9]`, `[abcdef]`) used to leak
 * hidden response bytes 1 bit per call. Standard full token classes (`a-z`, `A-Z`, `0-9`,
 * `a-f`, `A-F`) and negated delimiter classes (`[^"\\s]`) are allowed.
 */
function inspectSealCharClass(body: string, isQuantifiedWide: boolean): string | null {
  if (!body) return 'Empty character class in seal regex.'
  // Negated delimiter classes (e.g. [^"]+ or [^\s]+) are standard token extractors.
  if (body[0] === '^') return null

  let hasStandardRange = false
  let literalAlnumCount = 0
  for (let i = 0; i < body.length; ) {
    const ch = body[i]!
    if (ch === '\\') {
      const next = body[i + 1]
      if (next === 'w' || next === 'd' || next === 's' || next === 'S' || next === 'W' || next === 'D') {
        hasStandardRange = true
      }
      i += 2
      continue
    }
    if (i + 2 < body.length && body[i + 1] === '-' && body[i + 2] !== ']') {
      const rangeToken = `${ch}-${body[i + 2]!}`
      if (!STANDARD_CHAR_CLASS_RANGES.has(rangeToken)) {
        return `Seal regex character range "[${rangeToken}]" is rejected (partial-alphabet binary-search oracle guard).`
      }
      hasStandardRange = true
      i += 3
      continue
    }
    if (/[A-Za-z0-9]/.test(ch)) literalAlnumCount += 1
    i += 1
  }

  // Reject unquantified/narrow enumerated alphanumeric subset classes like `[abcdefghijklm]` or `[01234]`
  // that act as binary-search partitions without using a `-` range.
  if (!hasStandardRange && !isQuantifiedWide && literalAlnumCount >= 2) {
    return 'Seal regex unquantified alphanumeric subset class is rejected (binary-search oracle guard).'
  }
  return null
}

function readSealQuantifierMax(pattern: string, idx: number): { max: number; end: number } | null {
  const ch = pattern[idx]
  if (ch === '+' || ch === '*') {
    const end = pattern[idx + 1] === '?' ? idx + 2 : idx + 1
    return { max: Infinity, end }
  }
  if (ch === '?') {
    const end = pattern[idx + 1] === '?' ? idx + 2 : idx + 1
    return { max: 1, end }
  }
  if (ch === '{') {
    const m = /^\{(\d+)(?:,(\d*))?\}/.exec(pattern.slice(idx))
    if (!m) return null
    const min = Number(m[1])
    const max = m[0].includes(',') ? (m[2] ? Number(m[2]) : Infinity) : min
    const rawEnd = idx + m[0].length
    const end = pattern[rawEnd] === '?' ? rawEnd + 1 : rawEnd
    return { max, end }
  }
  return null
}

/**
 * H-8 hardened regex compiler for `capability.seal`:
 *  1. Enforces static ReDoS safety via `compileSafeClaimRegex` (length, nesting, backtracking,
 *     lookarounds, backreferences).
 *  2. Blocks byte-by-byte / binary-search oracle probes: partial-alphabet character ranges
 *     (`[a-m]`, `[0-4]`), unquantified alphanumeric subset classes (`[abcdef]`), and fixed-prefix
 *     1-char suffix padding probes that lack a wide variable token capture.
 *  3. Preserves legitimate `kovo_verify` SSE / JSON / Bearer / JWT / hex token regexes.
 */
export function compileSafeSealRegex(pattern: string): RegExp {
  const compiled = compileSafeClaimRegex(pattern)
  if (!compiled.ok) {
    throw new Error(`capability.seal regex rejected: ${compiled.reason}`)
  }

  // Scan top-level and capture-group tokens for binary-search character classes and verify
  // that the regex captures/matches a genuine variable token (not a 1-char probe padded by literals).
  let hasCaptureGroup = false
  let captureHasWideVariableToken = false
  let topHasWideVariableToken = false
  let captureDepth = 0
  let nonCapturingDepth = 0
  const groupKindStack: Array<'capture' | 'noncapture'> = []

  for (let i = 0; i < pattern.length; ) {
    const ch = pattern[i]!
    if (ch === '\\') {
      const esc = pattern[i + 1]
      const isWildcardEsc = esc === 'w' || esc === 'd' || esc === 'S' || esc === 'W' || esc === 'D'
      const q = readSealQuantifierMax(pattern, i + 2)
      const isWide = isWildcardEsc && Boolean(q && q.max >= MIN_ORACLE_SELECTOR_SEAL_LENGTH)
      if (isWide) {
        if (captureDepth > 0) captureHasWideVariableToken = true
        topHasWideVariableToken = true
      }
      i = q ? q.end : i + 2
      continue
    }
    if (ch === '[') {
      let end = i + 1
      while (end < pattern.length) {
        if (pattern[end] === '\\') { end += 2; continue }
        if (pattern[end] === ']') break
        end += 1
      }
      const classBody = pattern.slice(i + 1, end)
      const q = readSealQuantifierMax(pattern, end + 1)
      const isWide = Boolean(q && q.max >= MIN_ORACLE_SELECTOR_SEAL_LENGTH)
      const classErr = inspectSealCharClass(classBody, isWide)
      if (classErr) {
        throw new Error(`capability.seal regex rejected: ${classErr}`)
      }
      if (isWide) {
        if (captureDepth > 0) captureHasWideVariableToken = true
        topHasWideVariableToken = true
      }
      i = q ? q.end : end + 1
      continue
    }
    if (ch === '(') {
      if (pattern[i + 1] === '?' && pattern[i + 2] === ':') {
        nonCapturingDepth += 1
        groupKindStack.push('noncapture')
        i += 3
      } else {
        hasCaptureGroup = true
        captureDepth += 1
        groupKindStack.push('capture')
        i += 1
      }
      continue
    }
    if (ch === ')') {
      const kind = groupKindStack.pop()
      if (kind === 'capture') captureDepth = Math.max(0, captureDepth - 1)
      else if (kind === 'noncapture') nonCapturingDepth = Math.max(0, nonCapturingDepth - 1)
      i += 1
      continue
    }
    if (ch === '.') {
      const q = readSealQuantifierMax(pattern, i + 1)
      const isWide = Boolean(q && q.max >= MIN_ORACLE_SELECTOR_SEAL_LENGTH)
      if (isWide) {
        if (captureDepth > 0) captureHasWideVariableToken = true
        topHasWideVariableToken = true
      }
      i = q ? q.end : i + 1
      continue
    }
    i += 1
  }
  void nonCapturingDepth

  if (hasCaptureGroup && !captureHasWideVariableToken) {
    throw new Error(
      `capability.seal regex rejected: capture group must match a variable token of at least ${MIN_ORACLE_SELECTOR_SEAL_LENGTH} characters (prevents byte-oracle probing).`,
    )
  }
  if (!hasCaptureGroup && !topHasWideVariableToken) {
    throw new Error(
      `capability.seal regex rejected: pattern must match a variable token of at least ${MIN_ORACLE_SELECTOR_SEAL_LENGTH} characters (prevents byte-oracle probing).`,
    )
  }
  return compiled.regex
}

/**
 * Safely execute a seal regex against a bounded response body slice and validate the extracted
 * secret value against anti-oracle length/entropy guards.
 */
export function extractSafeSealRegexMatch(
  pattern: string,
  body: string,
  options: { maxHaystackBytes?: number } = {},
): string {
  const re = compileSafeSealRegex(pattern)
  const cap = Math.max(1024, options.maxHaystackBytes ?? MAX_SEAL_REGEX_HAYSTACK_BYTES)
  const bounded = body.length > cap ? body.slice(0, cap) : body
  const match = re.exec(bounded)
  const extracted = match?.[1] ?? match?.[0]
  if (!extracted) {
    throw new Error('Regex did not match response body.')
  }
  validateCapabilitySealValue(extracted, 'regex')
  return extracted
}

/** C-3 per-exchange and per-session seal rate-limit guard (counts every attempt, hit or miss). */
export function checkSealRateLimit(
  perExchangeCounts: Map<string, number>,
  exchangeId: string,
  sessionTotal: number,
  limits: { maxPerExchange?: number; maxPerSession?: number } = {},
): number {
  const maxPerExchange = limits.maxPerExchange ?? DEFAULT_MAX_SEALS_PER_EXCHANGE
  const maxPerSession = limits.maxPerSession ?? DEFAULT_MAX_SEALS_PER_SESSION
  if (sessionTotal >= maxPerSession) {
    throw new Error(`capability.seal session rate limit exceeded (max ${maxPerSession} seals per verification session).`)
  }
  const nextCount = (perExchangeCounts.get(exchangeId) ?? 0) + 1
  if (nextCount > maxPerExchange) {
    throw new Error(`capability.seal rate limit exceeded for exchange "${exchangeId}" (max ${maxPerExchange} attempts per exchange).`)
  }
  perExchangeCounts.set(exchangeId, nextCount)
  return sessionTotal + 1
}

function isPlainStringHeaderMap(value: unknown): value is Record<string, string | string[] | undefined> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false
  for (const v of Object.values(value as Record<string, unknown>)) {
    if (v !== undefined && typeof v !== 'string' && !Array.isArray(v)) return false
  }
  return true
}

interface SanitizerMatcherCache {
  rawSecretsSnapshot: readonly NamedSecret[]
  vaultDescriptorsSnapshot: readonly NamedSecret[]
  matcher: SecretMatcher
}

function sameNamedSecretList(a: readonly NamedSecret[], b: readonly NamedSecret[]): boolean {
  if (a.length !== b.length) return false
  for (let i = 0; i < a.length; i += 1) {
    if (a[i]!.value !== b[i]!.value || a[i]!.placeholder !== b[i]!.placeholder) return false
  }
  return true
}

export class EgressSanitizer {
  private readonly getSecretsFn: () => readonly NamedSecret[]
  private readonly getVaultsFn: () => readonly DerivedCapabilityVault[]
  private readonly providerKey?: string
  private readonly minSecretLength: number
  private readonly minCapabilityLength: number
  private readonly maxSecrets: number
  private cachedMatcher: SanitizerMatcherCache | null = null

  constructor(options: EgressSanitizerOptions = {}) {
    const rawSecrets = options.secrets
    this.getSecretsFn = typeof rawSecrets === 'function' ? rawSecrets : () => (rawSecrets ?? [])
    const rawVaults = options.capabilityVaults
    this.getVaultsFn = typeof rawVaults === 'function' ? rawVaults : () => (rawVaults ?? [])
    this.providerKey = options.providerKey
    this.minSecretLength = Math.max(1, options.minSecretLength ?? 4)
    this.minCapabilityLength = Math.max(1, options.minCapabilityLength ?? DEFAULT_MIN_CAPABILITY_SECRET_LENGTH)
    this.maxSecrets = Math.max(1, options.maxSecrets ?? DEFAULT_MAX_EXACT_SECRETS)
  }

  private getCompiledMatcher(): SecretMatcher {
    const rawSecrets = this.getSecretsFn()
    const vaults = this.getVaultsFn()
    const vaultDescriptors: NamedSecret[] = []
    for (const vault of vaults) {
      for (const desc of vaultScrubDescriptors(vault, this.minCapabilityLength)) {
        if (desc.value.length >= this.minCapabilityLength) vaultDescriptors.push(desc)
      }
    }

    if (
      this.cachedMatcher &&
      sameNamedSecretList(rawSecrets, this.cachedMatcher.rawSecretsSnapshot) &&
      sameNamedSecretList(vaultDescriptors, this.cachedMatcher.vaultDescriptorsSnapshot)
    ) {
      return this.cachedMatcher.matcher
    }

    const combined = collectDedupedSecrets(rawSecrets, {
      ...(this.providerKey ? { providerKey: this.providerKey } : {}),
      ...(vaultDescriptors.length > 0 ? { capabilityVaults: vaults } : {}),
      minSecretLength: this.minSecretLength,
      minCapLength: this.minCapabilityLength,
      maxSecrets: this.maxSecrets,
    })
    const matcher = compileSecretMatcher(combined, {
      minLength: 1,
      maxSecrets: Math.max(this.maxSecrets, combined.length),
    })
    this.cachedMatcher = {
      rawSecretsSnapshot: rawSecrets.map(s => ({ value: s.value, placeholder: s.placeholder })),
      vaultDescriptorsSnapshot: vaultDescriptors,
      matcher,
    }
    return matcher
  }

  private redactExactWithMatcher(text: string, matcher: SecretMatcher): string {
    if (!text) return text
    return normalizeEphemeralCapPlaceholders(matcher.redact(text))
  }

  private redactTextWithMatcher(text: string, channel: EgressChannel, matcher: SecretMatcher): string {
    if (!text) return text
    const exact = this.redactExactWithMatcher(text, matcher)
    if (channel === 'llm_tool_args') return exact
    return normalizeEphemeralCapPlaceholders(redactWithMatcher(exact))
  }

  private sanitizeHttpHeadersWithMatcher(
    headers: Record<string, string | string[] | undefined>,
    channel: EgressChannel,
    matcher: SecretMatcher,
  ): Record<string, string> {
    if (channel === 'llm_tool_args') {
      const out: Record<string, string> = {}
      for (const [k, rawValue] of Object.entries(headers)) {
        if (rawValue === undefined) continue
        const v = Array.isArray(rawValue) ? rawValue.join(', ') : String(rawValue)
        out[this.redactExactWithMatcher(k, matcher)] = RAW_COOKIE_FIELD_RE.test(k)
          ? '[redacted]'
          : this.redactExactWithMatcher(v, matcher)
      }
      return out
    }
    const out: Record<string, string> = {}
    for (const [key, rawValue] of Object.entries(headers)) {
      if (rawValue === undefined) continue
      const value = Array.isArray(rawValue) ? rawValue.join(', ') : String(rawValue)
      if (SENSITIVE_HTTP_HEADER_RE.test(key)) {
        out[key] = '[redacted]'
        continue
      }
      const exactRedacted = this.redactExactWithMatcher(value, matcher)
      out[key] = normalizeEphemeralCapPlaceholders(redactWithMatcher(exactRedacted))
    }
    return out
  }

  private sanitizeNode<T>(value: T, channel: EgressChannel, matcher: SecretMatcher): T {
    if (typeof value === 'string') return this.redactTextWithMatcher(value, channel, matcher) as unknown as T
    if (Array.isArray(value)) return value.map(item => this.sanitizeNode(item, channel, matcher)) as unknown as T
    if (!value || typeof value !== 'object') return value
    const out: Record<string, unknown> = {}
    for (const [key, item] of Object.entries(value as Record<string, unknown>)) {
      const safeKey = channel === 'llm_tool_args'
        ? this.redactExactWithMatcher(key, matcher)
        : this.redactTextWithMatcher(key, channel, matcher)
      if (channel === 'llm_tool_args') {
        out[safeKey] = RAW_COOKIE_FIELD_RE.test(key) && typeof item === 'string'
          ? '[redacted]'
          : this.sanitizeNode(item, channel, matcher)
      } else if (HEADER_OBJECT_KEYS.has(key) && isPlainStringHeaderMap(item)) {
        out[safeKey] = this.sanitizeHttpHeadersWithMatcher(item, channel, matcher)
      } else {
        out[safeKey] = this.sanitizeNode(item, channel, matcher)
      }
    }
    return out as T
  }

  /** Operation 1: Exact-value secret redaction ONLY (zero heuristic keyword regexes). */
  redactSecrets(text: string): string {
    if (!text) return text
    return this.redactExactWithMatcher(text, this.getCompiledMatcher())
  }

  /**
   * Channel-aware text sanitization:
   * - `llm_tool_args`: exact-value redaction ONLY (preserves H-25 tool arguments & code).
   * - All other channels: exact-value redaction + heuristic credential pattern redaction.
   */
  redactText(text: string, channel: EgressChannel = 'worker_rpc'): string {
    if (!text) return text
    return this.redactTextWithMatcher(text, channel, this.getCompiledMatcher())
  }

  /** Operation 2: Uniform structural HTTP header stripping across HTTP/1, HTTP/2, and Browser. */
  sanitizeHttpHeaders(
    headers: Record<string, string | string[] | undefined>,
    channel: EgressChannel = 'worker_rpc',
  ): Record<string, string> {
    return this.sanitizeHttpHeadersWithMatcher(headers, channel, this.getCompiledMatcher())
  }

  /**
   * Recursively sanitizes structured payloads crossing out of the host kernel:
   * - On `llm_tool_args`: exact-value scrubbing only (preserving H-25 tool args/code), stripping
   *   only raw `cookie`/`set-cookie` string properties.
   * - On `worker_rpc`, `browser_result`, `llm_context`, `storage_log`, `export`: strips sensitive
   *   HTTP header maps uniformly via `sanitizeHttpHeaders` and scrubs every string leaf via
   *   `redactText` (without clobbering benign structured fields like `canaryCheck.token`).
   */
  sanitizeValue<T>(value: T, channel: EgressChannel = 'worker_rpc'): T {
    return this.sanitizeNode(value, channel, this.getCompiledMatcher())
  }

  /** Dedicated typed choke point for all Browser tool results (H-8). */
  sanitizeBrowserResult<T>(result: T): T {
    return this.sanitizeValue(result, 'browser_result')
  }
}

export function createEgressSanitizer(options: EgressSanitizerOptions = {}): EgressSanitizer {
  return new EgressSanitizer(options)
}

/** Re-export helper for direct HTTP header redaction callers migrating from `redactHeaders`. */
export { redactHeaders }

// ---------------------------------------------------------------------------
// Capability seal & RPC metadata extraction helpers (shared with verify-rpc)
// ---------------------------------------------------------------------------

const DERIVED_SECRET_KINDS = new Set([
  'bearer_token', 'api_token', 'cookie', 'signed_url', 'oidc_assertion',
  'signing_salt', 'hmac_key', 'jwt', 'header_secret', 'generic_secret',
] as const)
const STATIC_PATH_SEG_RE = /^(?:api|rest|v\d+|read|public|admin|me|settings|login|logout|auth|token|refresh|verify|mfa|2fa|otp|session)$/i
const ENTITY_PATH_SEG_RE = /^\d+$|(?:^|[-_.])\d|^[0-9a-f]{8,}$|^[a-z]{2,10}_[A-Za-z0-9_-]{4,}$|^[A-Za-z0-9_-]*\d[A-Za-z0-9_-]*$/i
const BODY_ENTITY_KEY_RE = /^(?:id|entity_?id|[a-z]+_?id)$/i
const BODY_SCOPE_KEY_RE = /^(?:tenant|org|organization|workspace|project|user|actor|session|client)_?id$/i

export function extractRequestEntityIds(args: Record<string, unknown>, pathAndQuery: string, rawBody?: string): string[] {
  const ids = new Set<string>()
  if (typeof args.entityId === 'string' && args.entityId.trim()) ids.add(args.entityId.trim().slice(0, 256))
  for (const rawSeg of (pathAndQuery.split(/[?#]/, 1)[0] ?? '').split('/')) {
    if (!rawSeg) continue
    let seg = rawSeg; try { seg = decodeURIComponent(rawSeg) } catch { /* keep raw */ }
    if (!STATIC_PATH_SEG_RE.test(seg) && ENTITY_PATH_SEG_RE.test(seg) && (/^\d+$/.test(seg) || seg.length >= 4 || /^[a-z]\d{1,3}$/i.test(seg))) ids.add(seg.slice(0, 256))
  }
  if (ids.size === 0 && rawBody && rawBody.trim().startsWith('{')) {
    try {
      const parsed = JSON.parse(rawBody) as Record<string, unknown>
      if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) {
        for (const [k, v] of Object.entries(parsed)) {
          if (!BODY_ENTITY_KEY_RE.test(k) || BODY_SCOPE_KEY_RE.test(k)) continue
          if (typeof v === 'string' && v.trim()) ids.add(v.trim().slice(0, 256))
          else if (typeof v === 'number' && Number.isFinite(v)) ids.add(String(v))
        }
      }
    } catch { /* non-JSON body */ }
  }
  return [...ids]
}

export function resolveSealJsonPath(
  root: unknown,
  rawPath: string,
  fallback: (root: unknown, path: string) => { found: boolean; value?: unknown },
): { found: boolean; value?: unknown } {
  const cleaned = rawPath.trim().replace(/^\$/, '')
  if (!cleaned) return { found: root !== undefined, value: root }
  const tokens: Array<string | number> = []
  const re = /\.?([^.[\]]+)|\[(\d+|'(?:[^'\\]|\\.)*'|"(?:[^"\\]|\\.)*")\]/g
  let m: RegExpExecArray | null, consumed = 0
  while ((m = re.exec(cleaned)) !== null) {
    if (m.index !== consumed && cleaned.slice(consumed, m.index).replace(/^\.+/, '') !== '') return fallback(root, rawPath)
    consumed = re.lastIndex
    if (m[1] !== undefined) tokens.push(/^\d+$/.test(m[1]) ? Number(m[1]) : m[1])
    else if (m[2] !== undefined) tokens.push((m[2].startsWith("'") || m[2].startsWith('"')) ? m[2].slice(1, -1).replace(/\\(.)/g, '$1') : Number(m[2]))
  }
  if (consumed < cleaned.length) return fallback(root, rawPath)
  let cur: unknown = root
  for (const tok of tokens) {
    if (Array.isArray(cur)) { if (typeof tok !== 'number' || tok < 0 || tok >= cur.length) return { found: false }; cur = cur[tok] }
    else if (cur && typeof cur === 'object') { const rec = cur as Record<string, unknown>, k = String(tok); if (!Object.prototype.hasOwnProperty.call(rec, k)) return { found: false }; cur = rec[k] }
    else return { found: false }
    if (cur === undefined) return { found: false }
  }
  return { found: true, value: cur }
}

export function describeJsonTopKeys(parsed: unknown): string {
  if (Array.isArray(parsed)) {
    const first = parsed[0]
    if (first && typeof first === 'object' && !Array.isArray(first)) {
      const keys = Object.keys(first as Record<string, unknown>).slice(0, 20)
      return `top-level array length=${parsed.length}, [0] keys: ${keys.join(', ') || 'none'}`
    }
    return `top-level array length=${parsed.length}`
  }
  if (parsed && typeof parsed === 'object') {
    const keys = Object.keys(parsed as Record<string, unknown>).slice(0, 20)
    return keys.length ? `top-level keys: ${keys.join(', ')}` : 'top-level object is empty'
  }
  return `top-level type: ${parsed === null ? 'null' : typeof parsed}`
}

export function normalizeDerivedSecretKind(raw: unknown): DerivedCapabilityMeta['kind'] | undefined {
  if (raw === undefined || raw === null) return undefined
  if (typeof raw !== 'string') throw new Error(`Unsupported capability kind "${String(raw)}".`)
  const norm = raw.trim().toLowerCase().replace(/[\s-]+/g, '_')
  if (!norm) return undefined
  if (DERIVED_SECRET_KINDS.has(norm as DerivedCapabilityMeta['kind'])) return norm as DerivedCapabilityMeta['kind']
  if (/(?:^|_)jwt(?:$|_)/.test(norm)) return 'jwt'
  if (/oidc|assertion/.test(norm)) return 'oidc_assertion'
  if (/salt/.test(norm)) return 'signing_salt'
  if (/cookie/.test(norm)) return 'cookie'
  if (/signed.*url|presigned|url/.test(norm)) return 'signed_url'
  if (/header/.test(norm)) return 'header_secret'
  if (/bearer|access_token|session_token|identity_session/.test(norm)) return 'bearer_token'
  if (/signing|hmac|secret_key|private_key|mac_key|key_material/.test(norm)) return 'hmac_key'
  if (/api_key|token|pat/.test(norm)) return 'api_token'
  if (/secret|key/.test(norm)) return 'hmac_key'
  return 'generic_secret'
}
