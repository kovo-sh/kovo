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
  SENSITIVE_HTTP_HEADER_RE,
  buildSecretEncodingVariants,
  redact,
  redactExactValues,
  redactHeaders,
  type NamedSecret,
} from './redact.ts'

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

export const DEFAULT_MIN_CAPABILITY_SECRET_LENGTH = 8
export const MIN_STRUCTURED_SEAL_LENGTH = 6
export const MIN_ORACLE_SELECTOR_SEAL_LENGTH = 8
export const DEFAULT_MAX_SEALS_PER_EXCHANGE = 12
export const DEFAULT_MAX_SEALS_PER_SESSION = 128

const EPHEMERAL_CAP_PLACEHOLDER_RE = /\[persona:(cap:hop_[A-Za-z0-9._-]+:[A-Za-z0-9._-]+):secret\]/g
const RAW_COOKIE_FIELD_RE = /^(?:cookie|set-cookie)$/i
const HEADER_OBJECT_KEYS = new Set(['headers', 'reqHeaders', 'respHeaders', 'requestHeaders', 'responseHeaders', 'upgradeHeaders'])
const REPEATED_SINGLE_CHAR_RE = /^(.)\1+$/

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
}

export interface RedactSecretsOptions {
  providerKey?: string
  capabilityVaults?: readonly DerivedCapabilityVault[]
  minSecretLength?: number
  minCapabilityLength?: number
}

function normalizeEphemeralCapPlaceholders(text: string): string {
  return text.includes('[persona:cap:hop_')
    ? text.replace(EPHEMERAL_CAP_PLACEHOLDER_RE, '[redacted:$1]')
    : text
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
  const combined: NamedSecret[] = []
  if (options.providerKey && options.providerKey.length >= 4) {
    combined.push({ value: options.providerKey, placeholder: '[redacted]' })
  }
  for (const s of secrets) {
    if (s.value && s.value.length >= minSecretLength) combined.push(s)
  }
  for (const vault of options.capabilityVaults ?? []) {
    for (const desc of vaultScrubDescriptors(vault)) {
      if (desc.value.length >= minCapLength) combined.push(desc)
    }
  }
  return normalizeEphemeralCapPlaceholders(redactExactValues(text, combined, { minLength: 1 }))
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
  const out: Record<string, string> = {}
  for (const [key, rawValue] of Object.entries(headers)) {
    if (rawValue === undefined) continue
    const value = Array.isArray(rawValue) ? rawValue.join(', ') : String(rawValue)
    if (SENSITIVE_HTTP_HEADER_RE.test(key)) {
      out[key] = '[redacted]'
      continue
    }
    const exactRedacted = redactSecrets(value, secrets, options)
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

/**
 * C-3 anti-oracle validation on `capability.seal` extracted values:
 * rejects 1-char / short / trivial repeated-character probes so workers cannot recover hidden
 * response bytes character-by-character via regex or substring membership queries.
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

export class EgressSanitizer {
  private readonly getSecretsFn: () => readonly NamedSecret[]
  private readonly getVaultsFn: () => readonly DerivedCapabilityVault[]
  private readonly providerKey?: string
  private readonly minSecretLength: number
  private readonly minCapabilityLength: number

  constructor(options: EgressSanitizerOptions = {}) {
    const rawSecrets = options.secrets
    this.getSecretsFn = typeof rawSecrets === 'function' ? rawSecrets : () => (rawSecrets ?? [])
    const rawVaults = options.capabilityVaults
    this.getVaultsFn = typeof rawVaults === 'function' ? rawVaults : () => (rawVaults ?? [])
    this.providerKey = options.providerKey
    this.minSecretLength = Math.max(1, options.minSecretLength ?? 4)
    this.minCapabilityLength = Math.max(1, options.minCapabilityLength ?? DEFAULT_MIN_CAPABILITY_SECRET_LENGTH)
  }

  private resolveOptions(): { secrets: readonly NamedSecret[]; opts: RedactSecretsOptions } {
    return {
      secrets: this.getSecretsFn(),
      opts: {
        ...(this.providerKey ? { providerKey: this.providerKey } : {}),
        capabilityVaults: this.getVaultsFn(),
        minSecretLength: this.minSecretLength,
        minCapabilityLength: this.minCapabilityLength,
      },
    }
  }

  /** Operation 1: Exact-value secret redaction ONLY (zero heuristic keyword regexes). */
  redactSecrets(text: string): string {
    const { secrets, opts } = this.resolveOptions()
    return redactSecrets(text, secrets, opts)
  }

  /**
   * Channel-aware text sanitization:
   * - `llm_tool_args`: exact-value redaction ONLY (preserves H-25 tool arguments & code).
   * - All other channels: exact-value redaction + heuristic credential pattern redaction.
   */
  redactText(text: string, channel: EgressChannel = 'worker_rpc'): string {
    if (!text) return text
    const exact = this.redactSecrets(text)
    if (channel === 'llm_tool_args') return exact
    return normalizeEphemeralCapPlaceholders(redact(exact))
  }

  /** Operation 2: Uniform structural HTTP header stripping across HTTP/1, HTTP/2, and Browser. */
  sanitizeHttpHeaders(
    headers: Record<string, string | string[] | undefined>,
    channel: EgressChannel = 'worker_rpc',
  ): Record<string, string> {
    if (channel === 'llm_tool_args') {
      const out: Record<string, string> = {}
      for (const [k, rawValue] of Object.entries(headers)) {
        if (rawValue === undefined) continue
        const v = Array.isArray(rawValue) ? rawValue.join(', ') : String(rawValue)
        out[this.redactSecrets(k)] = RAW_COOKIE_FIELD_RE.test(k) ? '[redacted]' : this.redactSecrets(v)
      }
      return out
    }
    const { secrets, opts } = this.resolveOptions()
    return sanitizeHttpHeaders(headers, secrets, opts)
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
    if (typeof value === 'string') return this.redactText(value, channel) as unknown as T
    if (Array.isArray(value)) return value.map(item => this.sanitizeValue(item, channel)) as unknown as T
    if (!value || typeof value !== 'object') return value
    const out: Record<string, unknown> = {}
    for (const [key, item] of Object.entries(value as Record<string, unknown>)) {
      const safeKey = channel === 'llm_tool_args' ? this.redactSecrets(key) : this.redactText(key, channel)
      if (channel === 'llm_tool_args') {
        out[safeKey] = RAW_COOKIE_FIELD_RE.test(key) && typeof item === 'string'
          ? '[redacted]'
          : this.sanitizeValue(item, channel)
      } else if (HEADER_OBJECT_KEYS.has(key) && isPlainStringHeaderMap(item)) {
        out[safeKey] = this.sanitizeHttpHeaders(item, channel)
      } else {
        out[safeKey] = this.sanitizeValue(item, channel)
      }
    }
    return out as T
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
