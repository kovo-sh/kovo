import { randomUUID } from 'node:crypto'
import {
  accessSync,
  chmodSync,
  constants,
  mkdirSync,
  readFileSync,
  renameSync,
  statSync,
  unlinkSync,
  writeFileSync,
} from 'node:fs'
import { dirname, join } from 'node:path'
import { and, eq } from 'drizzle-orm'
import type { z } from 'zod'
import type {
  PersonaAuthKind,
  PersonaLoginConfig,
  PublicPersona,
  createPersona,
  deletePersona,
  updatePersona,
} from '../domain.ts'
import type { NamedSecret } from './redact.ts'
import { personas } from './schema.ts'
import type { Store } from './store.ts'

export interface LoginCredentialFilePayload {
  v: 1
  email: string
  password: string
}

/** Playwright `context.storageState()` cookie shape. */
export interface PlaywrightStorageCookie {
  name: string
  value: string
  domain: string
  path: string
  expires: number
  httpOnly: boolean
  secure: boolean
  sameSite: 'Strict' | 'Lax' | 'None'
}

/** Playwright `context.storageState()` per-origin localStorage shape. */
export interface PlaywrightStorageOrigin {
  origin: string
  localStorage: Array<{ name: string; value: string }>
}

/** Full Playwright `storageState` JSON payload (cookies across app + IdP domains + localStorage). */
export interface PlaywrightStorageState {
  cookies: PlaywrightStorageCookie[]
  origins: PlaywrightStorageOrigin[]
}

/**
 * Storable universal browser session bundle persisted ONLY in the persona's mode-0600
 * credential file on disk (never in SQLite or PublicPersona).
 */
export interface BrowserStorageBundle {
  v: 1
  kind: 'browser_session'
  targetOrigin: string
  capturedAt: number
  storageState: PlaywrightStorageState
  /** Optional Authorization / custom auth headers observed on target-origin requests. */
  observedHeaders?: Record<string, string>
  /** Q4: Optional per-origin observed auth headers when captured across sibling origins. */
  observedHeadersByOrigin?: Record<string, Record<string, string>>
}

export type BrowserSessionLoginConfig = Omit<PersonaLoginConfig, 'adapter'> & {
  adapter: 'browser_session'
  /** Optional path on targetOrigin visited during headless storageState auto-refresh (default '/'). */
  verifyPath?: string
}

export function isBrowserSessionConfig(
  config: { adapter?: string } | null | undefined,
): config is BrowserSessionLoginConfig {
  return Boolean(config && config.adapter === 'browser_session')
}

/** A single cookie captured for a persona session (including `HttpOnly` cookies). */
export interface PersonaCookieRecord {
  name: string
  value: string
  /** Cookie domain as issued by the server (`app.example.com` or `.example.com`). */
  domain: string
  path: string
  httpOnly?: boolean
  secure?: boolean
  sameSite?: 'Strict' | 'Lax' | 'None'
  /** Epoch milliseconds; omitted for session cookies. */
  expires?: number
}

/**
 * Per-origin attachment rule. `origin` is an exact origin (`https://app.example.com`) or a
 * scheme-scoped subdomain glob (`https://*.example.com`). When a bundle declares attachments,
 * only matching rules receive the bundle's default headers/cookies; unrelated sibling origins
 * (for example a bare `api.` host when only `app.` is mapped) receive nothing.
 */
export interface PersonaOriginAttachment {
  origin: string
  /** Restrict cookie attachment to these names (case-sensitive). Defaults to every applicable cookie. */
  cookies?: string[]
  /** Extra or overriding headers for this origin (tenant/org/CSRF/…). */
  headers?: Record<string, string>
  /** Storage hydration mode for this origin. `false` disables storage for it. */
  storage?: 'local' | 'session' | 'both' | false
}

export interface PersonaStorageSnapshot {
  localStorage?: Record<string, string>
  sessionStorage?: Record<string, string>
}

/**
 * Composite credential bundle: the v6 identity shape that can hold cookies (incl. `HttpOnly`),
 * headers, browser storage, and per-origin attachment rules at the same time. The legacy
 * single `headerType`/`value` fields remain authoritative for plain cookie/bearer/header personas.
 */
export interface PersonaCredentialBundle {
  v?: 2
  cookies?: PersonaCookieRecord[]
  headers?: Record<string, string>
  attachments?: PersonaOriginAttachment[]
  storage?: PersonaStorageSnapshot
  /** Origins allowed to receive `storage` defaults when no attachment explicitly opts in. */
  storageOrigins?: string[]
  /** Q4: Per-origin storage snapshots so sibling origins never clobber same-named keys. */
  storageByOrigin?: Record<string, PersonaStorageSnapshot>
}

/** Headers, scoped cookies, and storage that may be attached to one origin. */
export interface PersonaCredentialFrame {
  headers: Record<string, string>
  cookies: PersonaCookieRecord[]
  storage: PersonaStorageSnapshot | null
}

export interface MintedPersonaSession {
  headerType: 'cookie' | 'bearer' | 'header'
  headerName?: string
  value: string
  expiresAt?: number
  adapterUsed: string
  /**
   * Additional sensitive tokens associated with this persona's login session
   * (e.g., __client cookie, refresh tokens, and historical rotated JWTs) so
   * personaSecrets() always scrubs them even across fresh Store reads.
   * Stored ONLY in this 0600 host file, never in SQLite or PublicPersona.
   */
  scrubTokens?: string[]
  /** Composite v6 credential bundle (cookies + headers + storage + per-origin rules). */
  bundle?: PersonaCredentialBundle
  updatedAt?: number
  /** Live pool generation last served to a cloned worker session (runtime-only, not persisted). */
  generation?: number
}

/** True when a minted session is absent or its `expiresAt` is at or past `nowMs + skewMs`. */
export function isSessionExpired(
  session: MintedPersonaSession | null | undefined,
  nowMs = Date.now(),
  skewMs = 5_000,
): boolean {
  if (!session) return true
  if (typeof session.expiresAt !== 'number' || !Number.isFinite(session.expiresAt) || session.expiresAt <= 0) {
    return false
  }
  return session.expiresAt <= nowMs + Math.max(0, skewMs)
}

export interface ResolvedPersona {
  id: string
  handle: string
  roleLabel: string
  originAllowlist: string[]
  authKind: PersonaAuthKind
  headerName: string | null
  loginConfig?: PersonaLoginConfig | null
  credentialId?: string
  secret: string
  canaryMarkers: string[]
  secretPath?: string
  secretMtimeMs?: number
  secretIno?: number
  secretHistory?: string[]
  sessionPath?: string
  sessionMtimeMs?: number
  sessionIno?: number
  session?: MintedPersonaSession | null
}

const maxScrubHistoryEntries = 64
const MAX_BUNDLE_COOKIES = 64
const MAX_BUNDLE_HEADERS = 32
const MAX_BUNDLE_ATTACHMENTS = 32
const MAX_BUNDLE_STORAGE_KEYS = 128
const MAX_COOKIE_VALUE = 8_192
const MAX_STORAGE_VALUE = 8_192

/** Headers a caller may never smuggle through a credential bundle. */
const UNSAFE_BUNDLE_HEADERS = new Set([
  'host',
  'content-length',
  'connection',
  'transfer-encoding',
  'upgrade',
  'keep-alive',
  'te',
  'trailer',
  'proxy-authorization',
  'proxy-connection',
])

const cookieNamePattern = /^[!#$%&'*+\-.^_`|~0-9A-Za-z]{1,256}$/
const headerNamePattern = /^[!#$%&'*+\-.^_`|~0-9A-Za-z]{1,64}$/

function cleanHostDomain(domain: string): string | null {
  const raw = domain.trim().toLowerCase().replace(/^\.+/, '')
  if (!raw || raw.length > 253) return null
  if (!/^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$/.test(raw)) return null
  if (raw.includes('..')) return null
  return raw
}

function sanitizeCookieRecords(input: unknown): PersonaCookieRecord[] {
  if (!Array.isArray(input)) return []
  const out: PersonaCookieRecord[] = []
  const seen = new Set<string>()
  for (const entry of input.slice(0, MAX_BUNDLE_COOKIES)) {
    if (!entry || typeof entry !== 'object') continue
    const rec = entry as Partial<PersonaCookieRecord>
    if (typeof rec.name !== 'string' || !cookieNamePattern.test(rec.name)) continue
    if (typeof rec.value !== 'string' || rec.value.length > MAX_COOKIE_VALUE) continue
    if (/[\r\n\0]/.test(rec.value)) continue
    const domain = typeof rec.domain === 'string' ? cleanHostDomain(rec.domain) : null
    if (!domain) continue
    const path = typeof rec.path === 'string' && rec.path.startsWith('/') && !/[\r\n;]/.test(rec.path)
      ? rec.path.slice(0, 256)
      : '/'
    const key = `${rec.name}\0${domain}\0${path}`
    if (seen.has(key)) continue
    seen.add(key)
    out.push({
      name: rec.name,
      value: rec.value,
      domain,
      path,
      ...(rec.httpOnly === true ? { httpOnly: true } : {}),
      ...(rec.secure === true ? { secure: true } : {}),
      ...(rec.sameSite === 'Strict' || rec.sameSite === 'Lax' || rec.sameSite === 'None'
        ? { sameSite: rec.sameSite }
        : {}),
      ...(typeof rec.expires === 'number' && Number.isFinite(rec.expires) && rec.expires > 0
        ? { expires: Math.floor(rec.expires) }
        : {}),
    })
  }
  return out
}

function sanitizeHeaders(input: unknown): Record<string, string> {
  if (!input || typeof input !== 'object' || Array.isArray(input)) return {}
  const out: Record<string, string> = {}
  let count = 0
  for (const [rawName, rawValue] of Object.entries(input as Record<string, unknown>)) {
    if (count >= MAX_BUNDLE_HEADERS) break
    const name = rawName.trim()
    if (!headerNamePattern.test(name) || UNSAFE_BUNDLE_HEADERS.has(name.toLowerCase())) continue
    if (typeof rawValue !== 'string' || rawValue.length > MAX_COOKIE_VALUE) continue
    if (/[\r\n\0]/.test(rawValue)) continue
    out[name] = rawValue
    count += 1
  }
  return out
}

function sanitizeStorageSnapshot(input: unknown): PersonaStorageSnapshot | null {
  if (!input || typeof input !== 'object' || Array.isArray(input)) return null
  const pick = (raw: unknown): Record<string, string> | undefined => {
    if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return undefined
    const out: Record<string, string> = {}
    let count = 0
    for (const [key, value] of Object.entries(raw as Record<string, unknown>)) {
      if (count >= MAX_BUNDLE_STORAGE_KEYS) break
      if (!key || key.length > 256 || /[\r\n\0]/.test(key)) continue
      if (typeof value !== 'string' || value.length > MAX_STORAGE_VALUE) continue
      out[key] = value
      count += 1
    }
    return Object.keys(out).length ? out : undefined
  }
  const localStorage = pick((input as PersonaStorageSnapshot).localStorage)
  const sessionStorage = pick((input as PersonaStorageSnapshot).sessionStorage)
  if (!localStorage && !sessionStorage) return null
  return {
    ...(localStorage ? { localStorage } : {}),
    ...(sessionStorage ? { sessionStorage } : {}),
  }
}

function sanitizeOriginPattern(raw: unknown): string | null {
  if (typeof raw !== 'string' || !raw.trim()) return null
  try {
    const url = new URL(raw.trim())
    if (url.protocol !== 'https:' && url.protocol !== 'http:') return null
    if (url.username || url.password) return null
    if (url.hostname === '*') return null
    if (url.hostname.includes('*') && !url.hostname.startsWith('*.')) return null
    return url.origin
  } catch {
    return null
  }
}

function sanitizeAttachments(input: unknown): PersonaOriginAttachment[] {
  if (!Array.isArray(input)) return []
  const out: PersonaOriginAttachment[] = []
  const seen = new Set<string>()
  for (const entry of input.slice(0, MAX_BUNDLE_ATTACHMENTS)) {
    if (!entry || typeof entry !== 'object') continue
    const rec = entry as Partial<PersonaOriginAttachment>
    const origin = sanitizeOriginPattern(rec.origin)
    if (!origin || seen.has(origin)) continue
    seen.add(origin)
    const cookies = Array.isArray(rec.cookies)
      ? [...new Set(rec.cookies.filter((name): name is string =>
          typeof name === 'string' && cookieNamePattern.test(name)))].slice(0, MAX_BUNDLE_COOKIES)
      : undefined
    const headers = sanitizeHeaders(rec.headers)
    out.push({
      origin,
      ...(cookies && cookies.length ? { cookies } : {}),
      ...(Object.keys(headers).length ? { headers } : {}),
      ...(rec.storage === 'local' || rec.storage === 'session' || rec.storage === 'both' || rec.storage === false
        ? { storage: rec.storage }
        : {}),
    })
  }
  return out
}

function sanitizeStorageByOrigin(input: unknown): Record<string, PersonaStorageSnapshot> {
  if (!input || typeof input !== 'object' || Array.isArray(input)) return {}
  const out: Record<string, PersonaStorageSnapshot> = {}
  let count = 0
  for (const [rawOrigin, rawSnapshot] of Object.entries(input as Record<string, unknown>)) {
    if (count >= MAX_BUNDLE_ATTACHMENTS) break
    const origin = sanitizeOriginPattern(rawOrigin)
    if (!origin) continue
    const snapshot = sanitizeStorageSnapshot(rawSnapshot)
    if (!snapshot) continue
    out[origin] = snapshot
    count += 1
  }
  return out
}

function sanitizeHeadersByOrigin(input: unknown): Record<string, Record<string, string>> {
  if (!input || typeof input !== 'object' || Array.isArray(input)) return {}
  const out: Record<string, Record<string, string>> = {}
  let count = 0
  for (const [rawOrigin, rawHeaders] of Object.entries(input as Record<string, unknown>)) {
    if (count >= MAX_BUNDLE_ATTACHMENTS) break
    const origin = sanitizeOriginPattern(rawOrigin)
    if (!origin) continue
    const headers = sanitizeHeaders(rawHeaders)
    if (!Object.keys(headers).length) continue
    out[origin] = headers
    count += 1
  }
  return out
}

function mergeHeadersCaseInsensitive(
  base: Record<string, string> | undefined,
  override: Record<string, string> | undefined,
): Record<string, string> {
  const out: Record<string, string> = {}
  const apply = (src: Record<string, string> | undefined) => {
    if (!src) return
    for (const [k, v] of Object.entries(src)) {
      const lower = k.toLowerCase()
      for (const existing of Object.keys(out)) {
        if (existing.toLowerCase() === lower) delete out[existing]
      }
      out[k] = v
    }
  }
  apply(base)
  apply(override)
  return out
}

function matchingStorageByOrigin(
  bundle: PersonaCredentialBundle,
  origin: string,
): PersonaStorageSnapshot | null {
  const map = bundle.storageByOrigin
  if (!map) return null
  if (Object.prototype.hasOwnProperty.call(map, origin)) return map[origin] ?? null
  let best: PersonaStorageSnapshot | null = null
  let bestScore = -1
  for (const [pattern, snapshot] of Object.entries(map)) {
    if (!originMatchesAttachment(origin, pattern)) continue
    const score = pattern.includes('*') ? pattern.length : 10_000
    if (score > bestScore) {
      best = snapshot
      bestScore = score
    }
  }
  return best
}

/** Normalize an untrusted bundle (operator import, persisted file, adapter output). */
export function normalizePersonaBundle(input: unknown): PersonaCredentialBundle | undefined {
  if (!input || typeof input !== 'object' || Array.isArray(input)) return undefined
  const rec = input as PersonaCredentialBundle
  const cookies = sanitizeCookieRecords(rec.cookies)
  const headers = sanitizeHeaders(rec.headers)
  const attachments = sanitizeAttachments(rec.attachments)
  const storage = sanitizeStorageSnapshot(rec.storage)
  const storageByOrigin = sanitizeStorageByOrigin(rec.storageByOrigin)
  const storageOrigins = Array.isArray(rec.storageOrigins)
    ? [...new Set(rec.storageOrigins
        .map(sanitizeOriginPattern)
        .filter((origin): origin is string => Boolean(origin)))].slice(0, MAX_BUNDLE_ATTACHMENTS)
    : []
  const hasStorageByOrigin = Object.keys(storageByOrigin).length > 0
  if (!cookies.length && !Object.keys(headers).length && !attachments.length && !storage && !hasStorageByOrigin) return undefined
  return {
    v: 2,
    ...(cookies.length ? { cookies } : {}),
    ...(Object.keys(headers).length ? { headers } : {}),
    ...(attachments.length ? { attachments } : {}),
    ...(storage ? { storage } : {}),
    ...(storageOrigins.length ? { storageOrigins } : {}),
    ...(hasStorageByOrigin ? { storageByOrigin } : {}),
  }
}

/** True when an origin matches an exact or `*.` subdomain-glob attachment rule. */
export function originMatchesAttachment(origin: string, pattern: string): boolean {
  let target: URL
  try {
    target = new URL(origin)
  } catch {
    return false
  }
  let rule: URL
  try {
    rule = new URL(pattern)
  } catch {
    return false
  }
  if (target.protocol !== rule.protocol) return false
  if (target.port !== rule.port) return false
  const host = target.hostname.toLowerCase()
  const ruleHost = rule.hostname.toLowerCase()
  if (!ruleHost.includes('*')) return host === ruleHost
  const suffix = ruleHost.slice(2) // strip `*.`
  return host === suffix || host.endsWith(`.${suffix}`)
}

function cookieAppliesToOrigin(cookie: PersonaCookieRecord, origin: URL, requireSecure: boolean): boolean {
  const host = origin.hostname.toLowerCase()
  const domain = cookie.domain.toLowerCase()
  const hostMatches = host === domain || host.endsWith(`.${domain}`)
  if (!hostMatches) return false
  if (cookie.secure === true && origin.protocol !== 'https:') return false
  if (requireSecure && origin.protocol !== 'https:') return false
  if (typeof cookie.expires === 'number' && cookie.expires > 0 && cookie.expires < Date.now()) return false
  return true
}

function matchingAttachment(bundle: PersonaCredentialBundle, origin: string): PersonaOriginAttachment | null {
  const attachments = bundle.attachments ?? []
  if (!attachments.length) return null
  let best: PersonaOriginAttachment | null = null
  let bestScore = -1
  for (const attachment of attachments) {
    if (!originMatchesAttachment(origin, attachment.origin)) continue
    // Exact origin beats a glob; more specific globs beat broader ones.
    const score = attachment.origin.includes('*') ? attachment.origin.length : 10_000
    if (score > bestScore) {
      best = attachment
      bestScore = score
    }
  }
  return best
}

/**
 * Build the credentialed frame (headers + scoped cookies + storage) for one origin.
 *
 * When a bundle is present, cookie attachment honours cookie domain/secure/expiry rules and
 * the per-origin attachment allowlist. Legacy single-value sessions (cookie header string or
 * bearer token) are preserved exactly as before so existing broker call sites keep working.
 */
export function frameForSessionOrigin(
  session: MintedPersonaSession | null | undefined,
  originAllowlist: readonly string[],
  origin: string,
  legacyHeaderName?: string | null,
): PersonaCredentialFrame | null {
  if (!session || !originAllowlist.includes(origin)) return null
  let parsedOrigin: URL
  try {
    parsedOrigin = new URL(origin)
  } catch {
    return null
  }
  const bundle = session.bundle ? normalizePersonaBundle(session.bundle) : undefined
  if (!bundle) {
    if (!session.value) return null
    if (session.headerType === 'bearer') return { headers: { Authorization: 'Bearer ' + session.value }, cookies: [], storage: null }
    if (session.headerType === 'cookie') return { headers: { Cookie: session.value }, cookies: [], storage: null }
    return { headers: { [session.headerName || legacyHeaderName || 'X-Api-Key']: session.value }, cookies: [], storage: null }
  }

  const attachment = matchingAttachment(bundle, origin)
  const attachmentsDeclared = Boolean(bundle.attachments?.length)
  const hasCatchAll = (bundle.attachments ?? []).some(rule => rule.origin.includes('*'))
  if (attachmentsDeclared && !attachment && !hasCatchAll) {
    // A mapped bundle never covers an unmapped sibling origin — even with legacy fallback value.
    return null
  }

  const allowedCookieNames = attachment?.cookies ? new Set(attachment.cookies) : null
  const cookies = (bundle.cookies ?? []).filter(cookie => {
    if (allowedCookieNames && !allowedCookieNames.has(cookie.name)) return false
    return cookieAppliesToOrigin(cookie, parsedOrigin, false)
  })

  const headers = mergeHeadersCaseInsensitive(bundle.headers, attachment?.headers)
  if (cookies.length) {
    for (const existing of Object.keys(headers)) {
      if (existing.toLowerCase() === 'cookie') delete headers[existing]
    }
    headers.Cookie = cookies.map(cookie => `${cookie.name}=${cookie.value}`).join('; ')
  }

  const originStorage = matchingStorageByOrigin(bundle, origin)
  const hasPerOriginStorageMap = Boolean(bundle.storageByOrigin && Object.keys(bundle.storageByOrigin).length > 0)
  const storageSource = originStorage ?? (hasPerOriginStorageMap ? null : (bundle.storage ?? null))
  const storageMode = attachment?.storage ?? (
    originStorage
      ? 'both'
      : bundle.storageOrigins?.length
        ? (bundle.storageOrigins.some(pattern => originMatchesAttachment(origin, pattern)) ? 'both' : false)
        : (attachmentsDeclared ? false : 'both')
  )
  const storage = storageSource && storageMode !== false
    ? {
        ...(storageMode !== 'session' && storageSource.localStorage
          ? { localStorage: { ...storageSource.localStorage } }
          : {}),
        ...(storageMode !== 'local' && storageSource.sessionStorage
          ? { sessionStorage: { ...storageSource.sessionStorage } }
          : {}),
      }
    : null

  if (!Object.keys(headers).length && !cookies.length) {
    // Storage-only bundles still need a frame for browser hydration, but no HTTP attachment.
    if (!storage || (!storage.localStorage && !storage.sessionStorage)) return null
  }
  return {
    headers,
    cookies,
    storage: storage && (storage.localStorage || storage.sessionStorage) ? storage : null,
  }
}

/** Minimum length for exact-scrub persona secret needles (R3-H-10; raised from 4 to 8). */
export const MIN_PERSONA_SECRET_NEEDLE_LENGTH = 8
/** Minimum length for high-entropy values from non-auth-named generic cookies (R3-H-10). */
export const MIN_GENERIC_COOKIE_NEEDLE_LENGTH = 16

const PROTOCOL_AND_GENERIC_WORDS = new Set([
  'user', 'auto', 'text', 'true', 'false', 'none', 'null', 'system', 'model', 'input', 'output',
  'concise', 'detailed', 'assistant', 'developer', 'function', 'function_call',
  'function_call_output', 'custom_tool_call', 'custom_tool_call_output', 'input_text',
  'output_text', 'summary_text', 'tool_use', 'tool_result', 'tool_choice', 'required',
  'optional', 'completed', 'in_progress', 'incomplete', 'disabled', 'enabled', 'adaptive',
  'summarized', 'ephemeral', 'undefined', 'standard', 'default', 'anonymous', 'localhost',
  'unused', 'ready', 'pending', 'error', 'aborted', 'browser_session', 'browser-session-state',
  'application/json', 'text/html', 'text/plain', 'message', 'messages', 'reasoning', 'thinking',
  'refusal', 'image', 'document', 'object', 'string', 'number', 'boolean', 'array', 'properties',
  'strict', 'high', 'medium', 'low',
])

const JWT_LIKE_RE = /^eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}(?:\.[A-Za-z0-9_-]*)?$/
const COOKIE_PAIR_SINGLE_RE = /^[!#$%&'*+\-.^_`|~0-9A-Za-z]{1,64}=[^;\r\n]*$/
const SENSITIVE_HEADER_NAME_RE =
  /^(?:authorization|proxy-authorization|cookie|set-cookie|x-xsrf-token|x-csrf-token)$/i
const SENSITIVE_HEADER_STEM_RE = /csrf|xsrf|token|secret|api[-_]?key|session|auth/i
const AUTH_COOKIE_STEM_RE =
  /(?:^|[._-])(?:sid|sess|session|sessionid|jsessionid|phpsessid|aspsessionid|auth|token|jwt|access|refresh|csrf|xsrf|secret|key|apikey|cred|credential|oauth|oidc|saml|sso|bearer|ticket|nonce|remember|login|logged|client|passport|devise|warden|identity|principal|mfa|totp|otp|recovery|challenge|hmac|sig|signature|appsession|csrftoken)(?:$|[._-\d])/i
const AUTH_COOKIE_SUBSTR_RE =
  /(?:session|token|csrf|xsrf|auth|jwt|secret|apikey|phpsessid|jsessionid)/i
const AUTH_COOKIE_FRAMEWORK_RE =
  /^(?:__session|__client(?:_uat)?|sb-[a-z0-9._-]+|next-auth(?:\.[a-z0-9._-]+)?|authjs(?:\.[a-z0-9._-]+)?|better-auth(?:\.[a-z0-9._-]+)?|connect\.sid|\.aspnetcore\.[a-z0-9._-]+|asp\.net_sessionid|wordpress_(?:logged_in|sec)_[a-f0-9]+|cognitoidentityserviceprovider\.|cf_authorization|ory_kratos_session|a0:[a-z0-9._-]+|laravel_session|ci_session|rack\.session|express\.sid)$/i

function shannonEntropyBitsPerChar(value: string): number {
  if (!value) return 0
  const counts = new Map<string, number>()
  for (const ch of value) counts.set(ch, (counts.get(ch) ?? 0) + 1)
  let entropy = 0
  const len = value.length
  for (const count of counts.values()) {
    const p = count / len
    entropy -= p * Math.log2(p)
  }
  return entropy
}

function distinctCharCount(value: string): number {
  return new Set(value).size
}

function alnumClassCount(value: string): number {
  let classes = 0
  if (/[a-z]/.test(value)) classes += 1
  if (/[A-Z]/.test(value)) classes += 1
  if (/[0-9]/.test(value)) classes += 1
  return classes
}

function isSensitiveHeaderName(name: string): boolean {
  return SENSITIVE_HEADER_NAME_RE.test(name) || SENSITIVE_HEADER_STEM_RE.test(name)
}

/**
 * Identifies cookie names associated with authentication, session state, CSRF/XSRF, or IdP tokens.
 */
export function isAuthRelevantCookieName(name: string): boolean {
  const trimmed = name.trim()
  if (!trimmed) return false
  const stripped = trimmed.replace(/^__(?:Host|Secure)-/i, '')
  return (
    AUTH_COOKIE_FRAMEWORK_RE.test(trimmed) ||
    AUTH_COOKIE_FRAMEWORK_RE.test(stripped) ||
    AUTH_COOKIE_STEM_RE.test(stripped) ||
    AUTH_COOKIE_SUBSTR_RE.test(stripped)
  )
}

/**
 * Checks whether a value has high-entropy token characteristics suitable for scrubbing even when
 * carried under a generic (non-auth-named) cookie (R3-H-10).
 */
export function isHighEntropySecretValue(value: string): boolean {
  const trimmed = value.trim()
  if (!trimmed || /\s/.test(trimmed)) return false
  if (JWT_LIKE_RE.test(trimmed)) return true
  if (trimmed.length < MIN_GENERIC_COOKIE_NEEDLE_LENGTH) return false
  if (PROTOCOL_AND_GENERIC_WORDS.has(trimmed.toLowerCase())) return false
  const distinct = distinctCharCount(trimmed)
  if (distinct < 6) return false
  const entropy = shannonEntropyBitsPerChar(trimmed)
  if (entropy < 3.0) return false
  const classes = alnumClassCount(trimmed)
  if (classes >= 2) return true
  return trimmed.length >= 24 && entropy >= 3.3 && distinct >= 10
}

/**
 * Quality gate for exact-scrub persona secret needles (R3-H-10):
 *  - length >= 8 characters (blocks short words like `user`, `auto`, `text`, `true`, `none`)
 *  - rejects protocol/generic dictionary tokens and trivial low-entropy strings
 *  - for 8..11 char values, rejects plain lowercase/underscore dictionary words (e.g. `input_text`,
 *    `standard`, `dark_mode`) while retaining real mixed-class tokens, passwords, and session IDs
 */
export function isAcceptableSecretNeedle(value: string): boolean {
  const trimmed = value.trim()
  if (trimmed.length < MIN_PERSONA_SECRET_NEEDLE_LENGTH) return false
  if (JWT_LIKE_RE.test(trimmed)) return true
  if (PROTOCOL_AND_GENERIC_WORDS.has(trimmed.toLowerCase())) return false
  if (distinctCharCount(trimmed) < 4) return false
  if (shannonEntropyBitsPerChar(trimmed) < 1.8) return false
  if (trimmed.length < 12 && /^[a-z_]+$/.test(trimmed)) return false
  return true
}

/**
 * Decides whether a `(cookieName, cookieValue)` pair qualifies for the exact-scrub needle set:
 *  - Auth/session-relevant cookie names require >= 8 chars + non-trivial needle quality.
 *  - Arbitrary/preference cookie names require high-entropy tokens >= 16 chars (or JWTs).
 */
export function isScrubbableCookieNeedle(name: string, value: string): boolean {
  const cleaned = value.trim().replace(/^["']|["']$/g, '')
  if (cleaned.length < MIN_PERSONA_SECRET_NEEDLE_LENGTH) return false
  if (PROTOCOL_AND_GENERIC_WORDS.has(cleaned.toLowerCase())) return false
  if (isAuthRelevantCookieName(name)) {
    return isAcceptableSecretNeedle(cleaned)
  }
  return isHighEntropySecretValue(cleaned)
}

function addCookieHeaderSecrets(cookieHeader: string, out: Set<string>, isSetCookie = false): void {
  const trimmedHeader = cookieHeader.trim()
  if (!trimmedHeader) return
  const pairs = isSetCookie ? [trimmedHeader.split(';')[0] ?? ''] : trimmedHeader.split(';')
  let matchedAny = false
  for (const pair of pairs) {
    const eq = pair.indexOf('=')
    if (eq <= 0) continue
    const cookieName = pair.slice(0, eq).trim()
    const cookieValue = pair.slice(eq + 1).trim().replace(/^["']|["']$/g, '')
    if (!cookieName || !isScrubbableCookieNeedle(cookieName, cookieValue)) continue
    out.add(cookieValue)
    matchedAny = true
  }
  if (matchedAny && trimmedHeader.length >= MIN_PERSONA_SECRET_NEEDLE_LENGTH) {
    // Only register the full Cookie header string when at least one cookie inside it is a genuine
    // scrubbable secret (prevents benign single-cookie pairs like `summary=concise` from seeding
    // sub-value extraction in `redact.ts`).
    out.add(isSetCookie ? pairs[0]!.trim() : trimmedHeader)
  }
}

function looksLikeCookieHeaderString(raw: string): boolean {
  const trimmed = raw.trim()
  if (!trimmed || !trimmed.includes('=')) return false
  if (COOKIE_PAIR_SINGLE_RE.test(trimmed)) return true
  if (!trimmed.includes(';')) return false
  const parts = trimmed.split(';').map(p => p.trim()).filter(Boolean)
  if (parts.length === 0) return false
  return parts.every(p => COOKIE_PAIR_SINGLE_RE.test(p))
}

/** All secret material inside a bundle (auth-relevant cookie values, sensitive headers, token-like storage). */
export function bundleSecrets(bundle: PersonaCredentialBundle | undefined): string[] {
  if (!bundle) return []
  const out = new Set<string>()
  const addHeaderValue = (name: string, value: string) => {
    if (!isSensitiveHeaderName(name)) return
    const lower = name.toLowerCase()
    if (lower === 'cookie' || lower === 'set-cookie') {
      addCookieHeaderSecrets(value, out, lower === 'set-cookie')
      return
    }
    const trimmed = value.replace(/^Bearer\s+/i, '').trim()
    if (isAcceptableSecretNeedle(trimmed)) out.add(trimmed)
  }
  for (const cookie of bundle.cookies ?? []) {
    if (isScrubbableCookieNeedle(cookie.name, cookie.value)) {
      out.add(cookie.value.trim().replace(/^["']|["']$/g, ''))
    }
  }
  for (const [name, value] of Object.entries(bundle.headers ?? {})) {
    addHeaderValue(name, value)
  }
  const collectStorageSecrets = (snapshot: PersonaStorageSnapshot | undefined) => {
    for (const scope of [snapshot?.localStorage, snapshot?.sessionStorage]) {
      for (const [key, value] of Object.entries(scope ?? {})) {
        if (
          isAcceptableSecretNeedle(value) &&
          (/token|jwt|auth|secret|key|session|credential/i.test(key) || JWT_LIKE_RE.test(value.trim()))
        ) {
          out.add(value)
        }
      }
    }
  }
  collectStorageSecrets(bundle.storage)
  for (const snapshot of Object.values(bundle.storageByOrigin ?? {})) {
    collectStorageSecrets(snapshot)
  }
  for (const attachment of bundle.attachments ?? []) {
    for (const [name, value] of Object.entries(attachment.headers ?? {})) {
      addHeaderValue(name, value)
    }
  }
  return [...out]
}

/** Serialize a storage snapshot into a safe Playwright init script. */
export function storageHydrationScript(storage: PersonaStorageSnapshot | null): string | null {
  if (!storage || (!storage.localStorage && !storage.sessionStorage)) return null
  const encode = (value: unknown) => JSON.stringify(value)
    .replace(/</g, '\\u003c')
    .replace(/>/g, '\\u003e')
    .replace(/\u2028/g, '\\u2028')
    .replace(/\u2029/g, '\\u2029')
  const local = encode(storage.localStorage ?? {})
  const session = encode(storage.sessionStorage ?? {})
  return `(() => { try { const local = ${local}; const session = ${session};
    for (const [k, v] of Object.entries(local)) window.localStorage.setItem(k, v);
    for (const [k, v] of Object.entries(session)) window.sessionStorage.setItem(k, v);
  } catch { /* storage may be unavailable */ } })();`
}

function readVerifiedSecretFile(path: string): { secret: string; mtimeMs: number; ino: number } {
  const stat = statSync(path)
  if ((stat.mode & 0o077) !== 0) throw new Error('Persona credential must have owner-only permissions.')
  if (!stat.isFile() || stat.size === 0) throw new Error('Persona credential is unavailable.')
  accessSync(path, constants.R_OK)
  const secret = readFileSync(path, 'utf8').replace(/[\r\n]+$/, '')
  if (!secret) throw new Error('Persona credential is unavailable.')
  return { secret, mtimeMs: stat.mtimeMs, ino: stat.ino }
}

function readVerifiedSessionFile(path: string): { session: MintedPersonaSession; mtimeMs: number; ino: number } | null {
  let stat: ReturnType<typeof statSync>
  try {
    stat = statSync(path)
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === 'ENOENT') return null
    throw err
  }
  if ((stat.mode & 0o077) !== 0) throw new Error('Persona session file must have owner-only permissions.')
  if (!stat.isFile() || stat.size === 0) return null
  accessSync(path, constants.R_OK)
  const raw = readFileSync(path, 'utf8').trim()
  if (!raw) return null
  const parsed = JSON.parse(raw) as Partial<MintedPersonaSession>
  if (
    (parsed.headerType !== 'cookie' && parsed.headerType !== 'bearer' && parsed.headerType !== 'header') ||
    typeof parsed.value !== 'string' ||
    !parsed.value
  ) {
    return null
  }
  const bundle = normalizePersonaBundle(parsed.bundle)
  const session: MintedPersonaSession = {
    headerType: parsed.headerType,
    headerName: typeof parsed.headerName === 'string' && parsed.headerName ? parsed.headerName : undefined,
    value: parsed.value,
    expiresAt: typeof parsed.expiresAt === 'number' ? parsed.expiresAt : undefined,
    adapterUsed: typeof parsed.adapterUsed === 'string' ? parsed.adapterUsed : 'login',
    scrubTokens: Array.isArray(parsed.scrubTokens)
      ? parsed.scrubTokens.filter((v): v is string => typeof v === 'string' && v.length > 0)
      : undefined,
    ...(bundle ? { bundle } : {}),
    updatedAt: typeof parsed.updatedAt === 'number' ? parsed.updatedAt : undefined,
  }
  return { session, mtimeMs: stat.mtimeMs, ino: stat.ino }
}

/**
 * Normalize a user-pasted Clerk `__client` cookie value.
 * Accepts a raw token string, `__client=<value>` (with optional attributes),
 * or a full `Cookie:` / `Set-Cookie:` header containing `__client=<value>`.
 */
export function normalizeClerkClientCookie(raw: string): string {
  let text = raw.trim()
  if (!text) return ''
  text = text.replace(/^(?:set-)?cookie\s*:\s*/i, '').trim()
  if (!text) return ''

  const parts = text.split(';')
  for (const part of parts) {
    const trimmed = part.trim()
    const match = /^__client\s*=\s*(.+)$/i.exec(trimmed)
    if (match) {
      let val = match[1].trim()
      if ((val.startsWith('"') && val.endsWith('"')) || (val.startsWith("'") && val.endsWith("'"))) {
        val = val.slice(1, -1).trim()
      }
      if (!val || /[\r\n\0\s]/.test(val)) return ''
      return val
    }
  }

  // Multi-cookie header without a __client entry is not a valid __client token.
  if (text.includes(';')) return ''
  if ((text.startsWith('"') && text.endsWith('"')) || (text.startsWith("'") && text.endsWith("'"))) {
    text = text.slice(1, -1).trim()
  }
  if (!text || /[\r\n\0\s]/.test(text)) return ''
  // Reject another single named cookie (e.g. `__session=abc`), while still allowing base64 `=` padding.
  if (text.includes('=') && !/^[A-Za-z0-9+/_.-]+={1,2}$/.test(text)) return ''
  return text
}

export function readLoginCredentialFile(
  path: string,
  options: { allowEmptyEmail?: boolean } = {},
): {
  email: string
  password: string
  mtimeMs: number
  ino: number
} {
  const { secret: raw, mtimeMs, ino } = readVerifiedSecretFile(path)
  let parsed: Partial<LoginCredentialFilePayload>
  try {
    parsed = JSON.parse(raw) as Partial<LoginCredentialFilePayload>
  } catch {
    throw new Error('Persona login credential file is corrupted.')
  }
  if (
    typeof parsed.email !== 'string' ||
    (!options.allowEmptyEmail && !parsed.email) ||
    typeof parsed.password !== 'string' ||
    !parsed.password
  ) {
    throw new Error(
      options.allowEmptyEmail
        ? 'Persona login credential file is missing credential secret.'
        : 'Persona login credential file is missing email or password.',
    )
  }
  return { email: parsed.email, password: parsed.password, mtimeMs, ino }
}

const MAX_STORAGE_STATE_COOKIES = 256
const MAX_STORAGE_STATE_ORIGINS = 64
const MAX_STORAGE_STATE_ITEMS_PER_ORIGIN = 256

/** Validate and sanitize an untrusted Playwright `storageState` object. */
export function normalizePlaywrightStorageState(input: unknown): PlaywrightStorageState {
  if (!input || typeof input !== 'object' || Array.isArray(input)) {
    throw new Error('storageState must be a JSON object with cookies and/or origins.')
  }
  const rec = input as { cookies?: unknown; origins?: unknown }
  if (!Array.isArray(rec.cookies) && !Array.isArray(rec.origins)) {
    throw new Error('storageState must contain a "cookies" or "origins" array.')
  }

  const cookies: PlaywrightStorageCookie[] = []
  const seenCookies = new Set<string>()
  if (Array.isArray(rec.cookies)) {
    for (const raw of rec.cookies.slice(0, MAX_STORAGE_STATE_COOKIES)) {
      if (!raw || typeof raw !== 'object') continue
      const c = raw as Record<string, unknown>
      if (typeof c.name !== 'string' || !cookieNamePattern.test(c.name)) continue
      if (typeof c.value !== 'string' || c.value.length > MAX_COOKIE_VALUE || /[\r\n\0]/.test(c.value)) continue
      if (typeof c.domain !== 'string') continue
      const rawDomain = c.domain.trim()
      const cleanDomain = cleanHostDomain(rawDomain)
      if (!cleanDomain) continue
      const preservedDomain = rawDomain.startsWith('.') ? `.${cleanDomain}` : cleanDomain
      const path = typeof c.path === 'string' && c.path.startsWith('/') && !/[\r\n;]/.test(c.path)
        ? c.path.slice(0, 256)
        : '/'
      const key = `${c.name}\0${preservedDomain}\0${path}`
      if (seenCookies.has(key)) continue
      seenCookies.add(key)
      const expires = typeof c.expires === 'number' && Number.isFinite(c.expires)
        ? (c.expires > 1e12 ? Math.floor(c.expires / 1000) : c.expires)
        : -1
      const sameSite: 'Strict' | 'Lax' | 'None' =
        c.sameSite === 'Strict' || c.sameSite === 'Lax' || c.sameSite === 'None'
          ? c.sameSite
          : 'Lax'
      cookies.push({
        name: c.name,
        value: c.value,
        domain: preservedDomain,
        path,
        expires,
        httpOnly: c.httpOnly === true,
        secure: c.secure === true,
        sameSite,
      })
    }
  }

  const origins: PlaywrightStorageOrigin[] = []
  const seenOrigins = new Set<string>()
  if (Array.isArray(rec.origins)) {
    for (const rawOrigin of rec.origins.slice(0, MAX_STORAGE_STATE_ORIGINS)) {
      if (!rawOrigin || typeof rawOrigin !== 'object') continue
      const o = rawOrigin as { origin?: unknown; localStorage?: unknown }
      if (typeof o.origin !== 'string') continue
      let origin: string
      try {
        const parsed = new URL(o.origin)
        if (parsed.protocol !== 'https:' && parsed.protocol !== 'http:') continue
        origin = parsed.origin
      } catch {
        continue
      }
      if (seenOrigins.has(origin)) continue
      seenOrigins.add(origin)
      const localStorage: Array<{ name: string; value: string }> = []
      if (Array.isArray(o.localStorage)) {
        for (const item of o.localStorage.slice(0, MAX_STORAGE_STATE_ITEMS_PER_ORIGIN)) {
          if (!item || typeof item !== 'object') continue
          const pair = item as { name?: unknown; value?: unknown }
          if (typeof pair.name !== 'string' || !pair.name || pair.name.length > 256) continue
          if (typeof pair.value !== 'string' || pair.value.length > MAX_STORAGE_VALUE) continue
          localStorage.push({ name: pair.name, value: pair.value })
        }
      }
      origins.push({ origin, localStorage })
    }
  }

  return { cookies, origins }
}

/**
 * Normalize either a raw Playwright `storageState` JSON object or a wrapped `BrowserStorageBundle`.
 */
export function normalizeBrowserStorageBundle(
  input: unknown,
  fallbackTargetOrigin?: string,
  extraObservedHeaders?: Record<string, string>,
): BrowserStorageBundle {
  let rawObj: unknown = input
  if (typeof input === 'string') {
    try {
      rawObj = JSON.parse(input)
    } catch {
      throw new Error('Browser session storageState must be valid JSON.')
    }
  }
  if (!rawObj || typeof rawObj !== 'object' || Array.isArray(rawObj)) {
    throw new Error('Browser session bundle must be a JSON object.')
  }
  const rec = rawObj as Record<string, unknown>
  const isWrapped = rec.kind === 'browser_session' && rec.storageState && typeof rec.storageState === 'object'
  const storageState = normalizePlaywrightStorageState(isWrapped ? rec.storageState : rec)
  const rawTarget = (typeof rec.targetOrigin === 'string' && rec.targetOrigin.trim())
    ? rec.targetOrigin.trim()
    : (fallbackTargetOrigin?.trim() ?? '')
  let targetOrigin = ''
  if (rawTarget) {
    try {
      const parsed = new URL(rawTarget)
      if (parsed.protocol === 'http:' || parsed.protocol === 'https:') targetOrigin = parsed.origin
    } catch {
      // Fall back to first origin below.
    }
  }
  if (!targetOrigin && storageState.origins[0]?.origin) {
    targetOrigin = storageState.origins[0].origin
  }
  if (!targetOrigin) {
    throw new Error('Browser session bundle requires a valid HTTP(S) targetOrigin.')
  }
  const mergedHeaders = sanitizeHeaders({
    ...(isWrapped && rec.observedHeaders && typeof rec.observedHeaders === 'object'
      ? (rec.observedHeaders as Record<string, unknown>)
      : {}),
    ...(extraObservedHeaders ?? {}),
  })
  const observedHeadersByOrigin = isWrapped
    ? sanitizeHeadersByOrigin(rec.observedHeadersByOrigin)
    : {}
  return {
    v: 1,
    kind: 'browser_session',
    targetOrigin,
    capturedAt: typeof rec.capturedAt === 'number' && Number.isFinite(rec.capturedAt)
      ? Math.floor(rec.capturedAt)
      : Date.now(),
    storageState,
    ...(Object.keys(mergedHeaders).length ? { observedHeaders: mergedHeaders } : {}),
    ...(Object.keys(observedHeadersByOrigin).length ? { observedHeadersByOrigin } : {}),
  }
}

/** Collect sensitive auth/session tokens, cookies, and headers inside a `BrowserStorageBundle` for redaction. */
export function extractBrowserBundleSecrets(bundle: BrowserStorageBundle): string[] {
  const out = new Set<string>()
  for (const cookie of bundle.storageState.cookies) {
    if (isScrubbableCookieNeedle(cookie.name, cookie.value)) {
      out.add(cookie.value.trim().replace(/^["']|["']$/g, ''))
    }
  }
  for (const origin of bundle.storageState.origins) {
    for (const item of origin.localStorage) {
      if (
        isAcceptableSecretNeedle(item.value) &&
        (/token|jwt|auth|secret|key|session|credential|refresh|clerk|supabase/i.test(item.name) ||
          item.value.startsWith('eyJ'))
      ) {
        out.add(item.value)
      }
    }
  }
  const addHeaderMap = (headers: Record<string, string> | undefined) => {
    for (const [name, value] of Object.entries(headers ?? {})) {
      if (!isSensitiveHeaderName(name)) continue
      const lower = name.toLowerCase()
      if (lower === 'cookie' || lower === 'set-cookie') {
        addCookieHeaderSecrets(value, out, lower === 'set-cookie')
        continue
      }
      const trimmed = value.replace(/^Bearer\s+/i, '').trim()
      if (isAcceptableSecretNeedle(trimmed)) out.add(trimmed)
    }
  }
  addHeaderMap(bundle.observedHeaders)
  for (const originHeaders of Object.values(bundle.observedHeadersByOrigin ?? {})) {
    addHeaderMap(originHeaders)
  }
  return [...out]
}

export function readBrowserSessionCredentialFile(path: string): {
  bundle: BrowserStorageBundle
  mtimeMs: number
  ino: number
} {
  const { secret: raw, mtimeMs, ino } = readVerifiedSecretFile(path)
  let parsed: unknown
  try {
    parsed = JSON.parse(raw)
  } catch {
    throw new Error('Persona browser session credential file is corrupted.')
  }
  const bundle = normalizeBrowserStorageBundle(parsed)
  return { bundle, mtimeMs, ino }
}

/** Atomically persist a `BrowserStorageBundle` to the persona's mode-0600 credential file. */
export function writeBrowserSessionCredentialFile(
  path: string,
  bundle: BrowserStorageBundle,
): BrowserStorageBundle {
  const normalized = normalizeBrowserStorageBundle(bundle)
  const dir = dirname(path)
  mkdirSync(dir, { recursive: true, mode: 0o700 })
  chmodSync(dir, 0o700)
  const tmpPath = `${path}.${randomUUID()}.tmp`
  try {
    writeFileSync(tmpPath, JSON.stringify(normalized), { mode: 0o600, flag: 'wx' })
    chmodSync(tmpPath, 0o600)
    renameSync(tmpPath, path)
  } catch (err) {
    try { unlinkSync(tmpPath) } catch { /* ignore */ }
    throw err
  }
  return normalized
}

function decodeJwtExpiryMs(jwt: string): number | undefined {
  try {
    const parts = jwt.split('.')
    if (parts.length < 2) return undefined
    const b64 = parts[1]!.replace(/-/g, '+').replace(/_/g, '/')
    const pad = b64.length % 4 === 0 ? '' : '='.repeat(4 - (b64.length % 4))
    const parsed = JSON.parse(Buffer.from(b64 + pad, 'base64').toString('utf8')) as { exp?: unknown }
    if (typeof parsed.exp === 'number' && Number.isFinite(parsed.exp) && parsed.exp > 0) {
      return Math.floor(parsed.exp * 1000)
    }
  } catch {
    // Non-JWT token
  }
  return undefined
}

function cookieMatchesOriginHost(cookieDomain: string, host: string): boolean {
  const cleanCookie = cookieDomain.replace(/^\.+/, '').toLowerCase()
  const cleanHost = host.toLowerCase()
  return Boolean(cleanCookie && (cleanHost === cleanCookie || cleanHost.endsWith(`.${cleanCookie}`)))
}

/**
 * Project a universal `BrowserStorageBundle` into a `MintedPersonaSession` scoped to
 * `originAllowlist` (combining cookies, observed Authorization/auth headers, and localStorage).
 */
export function buildSessionFromBrowserBundle(
  bundle: BrowserStorageBundle,
  originAllowlist: readonly string[],
  extraScrubTokens: readonly string[] = [],
): MintedPersonaSession {
  const allowedOrigins: Array<{ origin: string; url: URL }> = []
  for (const entry of originAllowlist) {
    try {
      const parsed = new URL(entry)
      allowedOrigins.push({ origin: parsed.origin, url: parsed })
    } catch {
      // Ignore malformed entries.
    }
  }

  const nowMs = Date.now()
  const scopedCookies: PersonaCookieRecord[] = []
  for (const c of bundle.storageState.cookies) {
    if (!c.name || !c.value) continue
    const expiresMs = typeof c.expires === 'number' && c.expires > 0
      ? (c.expires < 1e12 ? Math.floor(c.expires * 1000) : Math.floor(c.expires))
      : undefined
    if (expiresMs && expiresMs < nowMs) continue
    const matchesAny = allowedOrigins.some(({ url }) => cookieMatchesOriginHost(c.domain, url.hostname))
    if (!matchesAny) continue
    scopedCookies.push({
      name: c.name,
      value: c.value,
      domain: c.domain.replace(/^\.+/, '').toLowerCase(),
      path: c.path || '/',
      ...(c.httpOnly ? { httpOnly: true } : {}),
      ...(c.secure ? { secure: true } : {}),
      ...(c.sameSite ? { sameSite: c.sameSite } : {}),
      ...(expiresMs ? { expires: expiresMs } : {}),
    })
  }

  const storageByOrigin: Record<string, PersonaStorageSnapshot> = {}
  const storageOrigins: string[] = []
  for (const originEntry of bundle.storageState.origins) {
    if (!allowedOrigins.some(a => a.origin === originEntry.origin)) continue
    if (!originEntry.localStorage.length) continue
    const perOriginLocal: Record<string, string> = {
      ...(storageByOrigin[originEntry.origin]?.localStorage ?? {}),
    }
    for (const pair of originEntry.localStorage) {
      perOriginLocal[pair.name] = pair.value
    }
    if (Object.keys(perOriginLocal).length) {
      storageByOrigin[originEntry.origin] = { localStorage: perOriginLocal }
      if (!storageOrigins.includes(originEntry.origin)) storageOrigins.push(originEntry.origin)
    }
  }

  const observedHeaders = sanitizeHeaders(bundle.observedHeaders ?? {})
  const observedHeadersByOrigin = sanitizeHeadersByOrigin(bundle.observedHeadersByOrigin)
  const hasPerOriginHeaders = Object.keys(observedHeadersByOrigin).length > 0
  const primaryOrigin =
    allowedOrigins.find(a => a.origin === bundle.targetOrigin) ??
    allowedOrigins[0]
  const primaryOriginHeaders = primaryOrigin
    ? (observedHeadersByOrigin[primaryOrigin.origin] ?? (Object.keys(observedHeaders).length ? observedHeaders : undefined))
    : (Object.keys(observedHeaders).length ? observedHeaders : undefined)
  const effectiveTopHeaders =
    primaryOriginHeaders ??
    Object.values(observedHeadersByOrigin)[0] ??
    {}
  const authHeaderEntry = Object.entries(effectiveTopHeaders).find(([k]) => k.toLowerCase() === 'authorization')
  const bearerMatch = authHeaderEntry ? /^Bearer\s+(\S+)$/i.exec(authHeaderEntry[1].trim()) : null
  const bearerToken = bearerMatch?.[1]?.trim() || null

  const attachments: PersonaOriginAttachment[] = allowedOrigins.map(({ origin }) => {
    const originHeaders = observedHeadersByOrigin[origin]
      ?? (!hasPerOriginHeaders && Object.keys(observedHeaders).length ? observedHeaders : undefined)
    return {
      origin,
      ...(originHeaders && Object.keys(originHeaders).length ? { headers: { ...originHeaders } } : {}),
      ...(storageOrigins.includes(origin) ? { storage: 'both' as const } : {}),
    }
  })

  const hasStorage = storageOrigins.length > 0
  const hasAnyHeaders = Object.keys(observedHeaders).length > 0 || hasPerOriginHeaders
  if (!scopedCookies.length && !hasAnyHeaders && !hasStorage) {
    throw new Error('Browser session contains no usable cookies, auth headers, or localStorage for the allowed origins.')
  }

  const primaryCookies = primaryOrigin
    ? scopedCookies.filter(c => cookieMatchesOriginHost(c.domain, primaryOrigin.url.hostname))
    : scopedCookies
  const cookieHeader = (primaryCookies.length ? primaryCookies : scopedCookies)
    .map(c => `${c.name}=${c.value}`)
    .join('; ')

  const primaryStorage = primaryOrigin ? storageByOrigin[primaryOrigin.origin] : undefined
  const fallbackStorage = primaryStorage ?? (storageOrigins[0] ? storageByOrigin[storageOrigins[0]] : undefined)

  const personaBundle = normalizePersonaBundle({
    cookies: scopedCookies,
    ...(!hasPerOriginHeaders && Object.keys(observedHeaders).length ? { headers: observedHeaders } : {}),
    ...(hasStorage
      ? {
          ...(fallbackStorage ? { storage: fallbackStorage } : {}),
          storageOrigins,
          storageByOrigin,
        }
      : {}),
    attachments,
  })

  // Estimate earliest expiry from observed Bearer JWT or JWT-shaped cookies
  let expiresAt: number | undefined
  if (bearerToken) {
    expiresAt = decodeJwtExpiryMs(bearerToken)
  }
  for (const c of scopedCookies) {
    if (c.value.startsWith('eyJ')) {
      const jwtExp = decodeJwtExpiryMs(c.value)
      if (jwtExp && (!expiresAt || jwtExp < expiresAt)) expiresAt = jwtExp
    } else if (c.expires && c.expires > nowMs && (!expiresAt || c.expires < expiresAt)) {
      expiresAt = c.expires
    }
  }

  const headerType: 'cookie' | 'bearer' | 'header' = bearerToken
    ? 'bearer'
    : cookieHeader
      ? 'cookie'
      : 'header'
  const firstCustomHeader = Object.entries(effectiveTopHeaders)[0]
  const value = bearerToken
    ? bearerToken
    : cookieHeader || firstCustomHeader?.[1] || 'browser-session-state'
  const headerName = headerType === 'header' ? (firstCustomHeader?.[0] ?? 'Authorization') : undefined

  const scrubTokens = [
    ...new Set([
      ...extractBrowserBundleSecrets(bundle),
      ...bundleSecrets(personaBundle),
      ...extraScrubTokens.filter(Boolean),
    ]),
  ]

  return {
    headerType,
    ...(headerName ? { headerName } : {}),
    value,
    ...(expiresAt ? { expiresAt } : {}),
    adapterUsed: 'browser_session',
    scrubTokens,
    ...(personaBundle ? { bundle: personaBundle } : {}),
  }
}

export function writePersonaSessionFile(
  sessionPath: string,
  session: MintedPersonaSession,
): MintedPersonaSession {
  const dir = dirname(sessionPath)
  mkdirSync(dir, { recursive: true, mode: 0o700 })
  chmodSync(dir, 0o700)

  // Preserve historical minted session values & extra scrub tokens (e.g. __client, prior JWTs)
  // so personaSecrets() always scrubs every prior & current token after rotation.
  const mergedScrub: string[] = []
  const seen = new Set<string>()
  const pushUnique = (tok: string) => {
    if (!tok || seen.has(tok)) return
    seen.add(tok)
    mergedScrub.push(tok)
  }
  const addToken = (tok: string | undefined, treatAsCookieHeader = false) => {
    if (!tok) return
    if (treatAsCookieHeader || looksLikeCookieHeaderString(tok)) {
      const extracted = new Set<string>()
      addCookieHeaderSecrets(tok, extracted)
      for (const item of extracted) pushUnique(item)
      return
    }
    if (!isAcceptableSecretNeedle(tok)) return
    pushUnique(tok)
  }

  try {
    const existing = readVerifiedSessionFile(sessionPath)
    if (existing) {
      addToken(existing.session.value, existing.session.headerType === 'cookie')
      for (const tok of existing.session.scrubTokens ?? []) addToken(tok)
    }
  } catch {
    // Ignore missing/unparseable prior session file.
  }

  addToken(session.value, session.headerType === 'cookie')
  for (const tok of session.scrubTokens ?? []) addToken(tok)
  const bundle = normalizePersonaBundle(session.bundle)
  for (const tok of bundleSecrets(bundle)) addToken(tok)

  const payload: MintedPersonaSession = {
    headerType: session.headerType,
    ...(session.headerName ? { headerName: session.headerName } : {}),
    value: session.value,
    ...(session.expiresAt !== undefined ? { expiresAt: session.expiresAt } : {}),
    adapterUsed: session.adapterUsed,
    scrubTokens: mergedScrub.slice(-maxScrubHistoryEntries),
    ...(bundle ? { bundle } : {}),
    updatedAt: Date.now(),
  }

  const tmpPath = `${sessionPath}.${randomUUID()}.tmp`
  try {
    writeFileSync(tmpPath, JSON.stringify(payload), { mode: 0o600, flag: 'wx' })
    chmodSync(tmpPath, 0o600)
    renameSync(tmpPath, sessionPath)
  } catch (err) {
    try { unlinkSync(tmpPath) } catch { /* ignore */ }
    throw err
  }
  return payload
}

function appendHistory(persona: ResolvedPersona, values: readonly (string | undefined)[]) {
  const history = persona.secretHistory ?? (persona.secret ? [persona.secret] : [])
  for (const val of values) {
    if (val && !history.includes(val)) history.push(val)
  }
  persona.secretHistory = history
}

export function refreshPersonaSecret(persona: ResolvedPersona): string {
  if (persona.authKind === 'login') {
    refreshPersonaSession(persona)
    return persona.secret
  }
  if (!persona.secretPath) return persona.secret
  let stat: ReturnType<typeof statSync>
  try {
    stat = statSync(persona.secretPath)
  } catch {
    return persona.secret
  }
  if ((stat.mode & 0o077) !== 0) throw new Error('Persona credential must have owner-only permissions.')
  if (!stat.isFile() || stat.size === 0) return persona.secret
  if (stat.mtimeMs !== persona.secretMtimeMs || stat.ino !== persona.secretIno) {
    accessSync(persona.secretPath, constants.R_OK)
    const fresh = readFileSync(persona.secretPath, 'utf8').replace(/[\r\n]+$/, '')
    if (fresh) {
      appendHistory(persona, [persona.secret, fresh])
      persona.secret = fresh
      persona.secretMtimeMs = stat.mtimeMs
      persona.secretIno = stat.ino
    }
  }
  return persona.secret
}

export function refreshPersonaSession(persona: ResolvedPersona): MintedPersonaSession | null {
  if (persona.authKind !== 'login') return null
  if (!persona.sessionPath) return persona.session ?? null
  let stat: ReturnType<typeof statSync>
  try {
    stat = statSync(persona.sessionPath)
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === 'ENOENT') return persona.session ?? null
    throw err
  }
  if ((stat.mode & 0o077) !== 0) throw new Error('Persona session file must have owner-only permissions.')
  if (!stat.isFile() || stat.size === 0) return persona.session ?? null
  if (stat.mtimeMs !== persona.sessionMtimeMs || stat.ino !== persona.sessionIno || !persona.session) {
    const read = readVerifiedSessionFile(persona.sessionPath)
    if (read) {
      appendHistory(persona, [
        persona.session?.value,
        ...(persona.session?.scrubTokens ?? []),
        read.session.value,
        ...(read.session.scrubTokens ?? []),
      ])
      persona.session = read.session
      persona.sessionMtimeMs = read.mtimeMs
      persona.sessionIno = read.ino
    }
  }
  return persona.session ?? null
}

export function listProjectPersonas(storage: Store, projectId: string): PublicPersona[] {
  storage.project(projectId)
  return storage.db.select().from(personas)
    .where(and(eq(personas.projectId, projectId), eq(personas.workspaceId, storage.workspace.id)))
    .all()
    .map(({ credentialId: _omit, workspaceId: _ws, loginConfig, ...pub }) => ({
      ...pub,
      loginConfig: loginConfig ?? null,
    }))
}

export function createProjectPersona(storage: Store, input: z.output<typeof createPersona>): { id: string; handle: string } {
  return storage.operate(input, () => {
    const project = storage.project(input.projectId)
    const dir = join(storage.directory, 'credentials')
    mkdirSync(dir, { recursive: true, mode: 0o700 })
    chmodSync(dir, 0o700)
    const credentialId = 'persona-' + randomUUID()
    const path = join(dir, credentialId)

    const canaryMarkers = [...input.canaryMarkers]
    let fileBody: string
    let storedLoginConfig: PersonaLoginConfig | null = null
    let initialBrowserBundle: BrowserStorageBundle | null = null

    if (input.authKind === 'login') {
      const isBrowserSession = isBrowserSessionConfig(input.loginConfig as { adapter?: string } | undefined)
      const isClerkClient = input.loginConfig?.adapter === 'clerk_client'
      if (isBrowserSession) {
        const targetOrigin = input.originAllowlist[0]
        initialBrowserBundle = normalizeBrowserStorageBundle(input.secret, targetOrigin)
        const rawCfg = input.loginConfig as unknown as BrowserSessionLoginConfig
        storedLoginConfig = {
          adapter: 'browser_session' as unknown as PersonaLoginConfig['adapter'],
          ...(rawCfg.verifyPath ? { verifyPath: rawCfg.verifyPath } : {}),
          ...(rawCfg.loginUrl ? { loginUrl: rawCfg.loginUrl } : {}),
          ...(rawCfg.refreshIntervalSec ? { refreshIntervalSec: rawCfg.refreshIntervalSec } : {}),
        } as PersonaLoginConfig
        fileBody = JSON.stringify(initialBrowserBundle)
      } else {
        if (!input.loginConfig || (!isClerkClient && !input.loginConfig.email)) {
          throw new Error('Email and login configuration are required for Email + Password personas.')
        }
        const email = input.loginConfig.email?.trim() ?? ''
        let password = input.secret
        if (isClerkClient) {
          const normalized = normalizeClerkClientCookie(input.secret)
          if (!normalized) {
            throw new Error('Paste a valid Clerk __client cookie value (raw token, __client=<value>, or Cookie header containing __client=…).')
          }
          password = normalized
        }
        const { email: _omitEmail, ...restLoginConfig } = input.loginConfig
        storedLoginConfig = {
          ...restLoginConfig,
          ...(email ? { email } : {}),
        }
        if (email && !canaryMarkers.some(m => m.toLowerCase() === email.toLowerCase()) && canaryMarkers.length < 16) {
          canaryMarkers.push(email)
        }
        const payload: LoginCredentialFilePayload = {
          v: 1,
          email,
          password,
        }
        fileBody = JSON.stringify(payload)
      }
    } else {
      fileBody = input.secret.trim()
    }

    writeFileSync(path, fileBody, { mode: 0o600, flag: 'wx' })
    chmodSync(path, 0o600)
    const dedupedAllowlist = [...new Set(input.originAllowlist)]
    if (initialBrowserBundle) {
      try {
        const initialSession = buildSessionFromBrowserBundle(initialBrowserBundle, dedupedAllowlist)
        writePersonaSessionFile(`${path}.session`, initialSession)
      } catch {
        // Initial session projection is best-effort; refreshBrowserSession will populate it on first run.
      }
    }
    const personaId = randomUUID()
    try {
      storage.db.insert(personas).values({
        id: personaId,
        projectId: project.id,
        workspaceId: storage.workspace.id,
        handle: input.handle,
        roleLabel: input.roleLabel,
        originAllowlist: dedupedAllowlist,
        authKind: input.authKind,
        headerName: input.authKind === 'header' ? (input.headerName ?? 'X-Api-Key') : null,
        loginConfig: storedLoginConfig,
        credentialId,
        canaryMarkers,
        createdAt: Date.now(),
      }).run()
    } catch (error) {
      try { unlinkSync(path) } catch { /* ignore */ }
      try { unlinkSync(`${path}.session`) } catch { /* ignore */ }
      throw error
    }
    storage.event(null, 'persona.created', `Registered persona ${input.handle}.`, {
      projectId: project.id,
      personaId,
      handle: input.handle,
      authKind: input.authKind,
      adapter: storedLoginConfig?.adapter ?? null,
      origins: input.originAllowlist,
    })
    return { id: personaId, handle: input.handle }
  })
}

export function updateProjectPersona(storage: Store, input: z.output<typeof updatePersona>): { id: string; handle: string } {
  return storage.operate(input, () => {
    storage.project(input.projectId)
    const existing = storage.db.select().from(personas).where(and(
      eq(personas.id, input.personaId), eq(personas.projectId, input.projectId), eq(personas.workspaceId, storage.workspace.id),
    )).get()
    if (!existing) throw new Error('Persona not found.')

    const dir = join(storage.directory, 'credentials')
    mkdirSync(dir, { recursive: true, mode: 0o700 })
    chmodSync(dir, 0o700)

    const existingIsClerkClient = existing.authKind === 'login' && existing.loginConfig?.adapter === 'clerk_client'
    const nextIsClerkClient = input.authKind === 'login' && input.loginConfig?.adapter === 'clerk_client'
    const existingIsBrowserSession = existing.authKind === 'login' && isBrowserSessionConfig(existing.loginConfig as { adapter?: string } | null)
    const nextIsBrowserSession = input.authKind === 'login' && isBrowserSessionConfig(input.loginConfig as { adapter?: string } | undefined)
    const sameAuthKind =
      existing.authKind === input.authKind &&
      existingIsClerkClient === nextIsClerkClient &&
      existingIsBrowserSession === nextIsBrowserSession

    const rawSecret = input.secret ?? ''
    const hasNewSecret = rawSecret.trim().length > 0
    if (!sameAuthKind && !hasNewSecret) {
      throw new Error(
        nextIsBrowserSession
          ? 'A captured or imported browser session (storageState) is required when switching to Browser Session.'
          : nextIsClerkClient
            ? 'Clerk __client cookie value is required when switching sign-in method.'
            : 'Credential secret is required when switching sign-in method.',
      )
    }

    const canaryMarkers = [...(input.canaryMarkers ?? existing.canaryMarkers)]
    let storedLoginConfig: PersonaLoginConfig | null = null
    let newFileBody: string | null = null
    let nextBrowserBundle: BrowserStorageBundle | null = null

    if (input.authKind === 'login') {
      if (nextIsBrowserSession) {
        const rawCfg = input.loginConfig as unknown as BrowserSessionLoginConfig
        storedLoginConfig = {
          adapter: 'browser_session' as unknown as PersonaLoginConfig['adapter'],
          ...(rawCfg.verifyPath ? { verifyPath: rawCfg.verifyPath } : {}),
          ...(rawCfg.loginUrl ? { loginUrl: rawCfg.loginUrl } : {}),
          ...(rawCfg.refreshIntervalSec ? { refreshIntervalSec: rawCfg.refreshIntervalSec } : {}),
        } as PersonaLoginConfig
        if (hasNewSecret) {
          nextBrowserBundle = normalizeBrowserStorageBundle(rawSecret, input.originAllowlist[0])
          newFileBody = JSON.stringify(nextBrowserBundle)
        }
      } else {
        if (!input.loginConfig || (!nextIsClerkClient && !input.loginConfig.email)) {
          throw new Error('Email and login configuration are required for Email + Password personas.')
        }
        const email = input.loginConfig.email?.trim() ?? ''
        const { email: _omitEmail, ...restLoginConfig } = input.loginConfig
        storedLoginConfig = {
          ...restLoginConfig,
          ...(email ? { email } : {}),
        }
        if (email && !canaryMarkers.some(m => m.toLowerCase() === email.toLowerCase()) && canaryMarkers.length < 16) {
          canaryMarkers.push(email)
        }
        if (hasNewSecret) {
          let password = rawSecret
          if (nextIsClerkClient) {
            const normalized = normalizeClerkClientCookie(rawSecret)
            if (!normalized) {
              throw new Error('Paste a valid Clerk __client cookie value (raw token, __client=<value>, or Cookie header containing __client=…).')
            }
            password = normalized
          }
          const payload: LoginCredentialFilePayload = { v: 1, email, password }
          newFileBody = JSON.stringify(payload)
        } else if (!nextIsClerkClient) {
          // Preserve existing password while keeping stored login email in sync.
          const oldPath = join(dir, existing.credentialId)
          try {
            const parsed = JSON.parse(readFileSync(oldPath, 'utf8')) as Partial<LoginCredentialFilePayload>
            if (parsed && typeof parsed.password === 'string' && parsed.email !== email) {
              const payload: LoginCredentialFilePayload = { v: 1, email, password: parsed.password }
              newFileBody = JSON.stringify(payload)
            }
          } catch {
            throw new Error('Existing credential could not be read; enter a new password.')
          }
        }
      }
    } else if (hasNewSecret) {
      newFileBody = rawSecret.trim()
    }

    const oldBasePath = join(dir, existing.credentialId)
    let nextCredentialId = existing.credentialId
    let rotatedPath: string | null = null

    if (newFileBody !== null) {
      nextCredentialId = 'persona-' + randomUUID()
      rotatedPath = join(dir, nextCredentialId)
      writeFileSync(rotatedPath, newFileBody, { mode: 0o600, flag: 'wx' })
      chmodSync(rotatedPath, 0o600)
    }

    const dedupedAllowlist = [...new Set(input.originAllowlist)]
    try {
      storage.db.update(personas).set({
        roleLabel: input.roleLabel,
        originAllowlist: dedupedAllowlist,
        authKind: input.authKind,
        headerName: input.authKind === 'header' ? (input.headerName ?? 'X-Api-Key') : null,
        loginConfig: storedLoginConfig,
        credentialId: nextCredentialId,
        canaryMarkers,
      }).where(eq(personas.id, existing.id)).run()
    } catch (error) {
      if (rotatedPath) {
        try { unlinkSync(rotatedPath) } catch { /* ignore */ }
      }
      throw error
    }

    if (rotatedPath) {
      try { unlinkSync(oldBasePath) } catch { /* ignore */ }
    }
    // Invalidate any cached minted session when credentials or login config are updated.
    try { unlinkSync(oldBasePath + '.session') } catch { /* ignore */ }

    // Seed initial .session immediately when updating a browser_session bundle.
    if (nextBrowserBundle && rotatedPath) {
      try {
        const seeded = buildSessionFromBrowserBundle(nextBrowserBundle, dedupedAllowlist)
        writePersonaSessionFile(`${rotatedPath}.session`, seeded)
      } catch {
        // Best-effort initial projection.
      }
    }

    storage.event(null, 'persona.updated', `Updated persona ${existing.handle}.`, {
      projectId: input.projectId,
      personaId: existing.id,
      handle: existing.handle,
      authKind: input.authKind,
      adapter: storedLoginConfig?.adapter ?? null,
      origins: input.originAllowlist,
      credentialRotated: Boolean(rotatedPath),
    })
    return { id: existing.id, handle: existing.handle }
  })
}

export interface CreateBrowserSessionPersonaInput {
  requestId: string
  projectId: string
  handle: string
  roleLabel: string
  originAllowlist: string[]
  /** Either a raw Playwright storageState object/JSON string or a wrapped BrowserStorageBundle. */
  storageState: unknown
  observedHeaders?: Record<string, string>
  verifyPath?: string
  refreshIntervalSec?: number
  canaryMarkers?: string[]
}

export function createBrowserSessionPersona(
  storage: Store,
  input: CreateBrowserSessionPersonaInput,
): { id: string; handle: string } {
  const targetOrigin = input.originAllowlist[0]
  const normalizedBundle = normalizeBrowserStorageBundle(
    input.storageState,
    targetOrigin,
    input.observedHeaders,
  )
  return createProjectPersona(storage, {
    requestId: input.requestId,
    projectId: input.projectId,
    handle: input.handle,
    roleLabel: input.roleLabel,
    originAllowlist: input.originAllowlist,
    authKind: 'login',
    loginConfig: {
      adapter: 'browser_session' as unknown as PersonaLoginConfig['adapter'],
      ...(input.verifyPath ? { verifyPath: input.verifyPath } : {}),
      ...(input.refreshIntervalSec ? { refreshIntervalSec: input.refreshIntervalSec } : {}),
    } as PersonaLoginConfig,
    secret: JSON.stringify(normalizedBundle),
    canaryMarkers: input.canaryMarkers ?? [],
  })
}

export interface UpdateBrowserSessionPersonaInput {
  requestId: string
  projectId: string
  personaId: string
  roleLabel: string
  originAllowlist: string[]
  /** Optional replacement Playwright storageState or BrowserStorageBundle; omit to keep existing. */
  storageState?: unknown
  observedHeaders?: Record<string, string>
  verifyPath?: string
  refreshIntervalSec?: number
  canaryMarkers?: string[]
}

export function updateBrowserSessionPersona(
  storage: Store,
  input: UpdateBrowserSessionPersonaInput,
): { id: string; handle: string } {
  const hasReplacement = input.storageState !== undefined && input.storageState !== null && input.storageState !== ''
  const secret = hasReplacement
    ? JSON.stringify(normalizeBrowserStorageBundle(input.storageState, input.originAllowlist[0], input.observedHeaders))
    : undefined
  return updateProjectPersona(storage, {
    requestId: input.requestId,
    projectId: input.projectId,
    personaId: input.personaId,
    roleLabel: input.roleLabel,
    originAllowlist: input.originAllowlist,
    authKind: 'login',
    loginConfig: {
      adapter: 'browser_session' as unknown as PersonaLoginConfig['adapter'],
      ...(input.verifyPath ? { verifyPath: input.verifyPath } : {}),
      ...(input.refreshIntervalSec ? { refreshIntervalSec: input.refreshIntervalSec } : {}),
    } as PersonaLoginConfig,
    ...(secret !== undefined ? { secret } : {}),
    ...(input.canaryMarkers ? { canaryMarkers: input.canaryMarkers } : {}),
  })
}

export function deleteProjectPersona(storage: Store, input: z.output<typeof deletePersona>): { id: string } {
  return storage.operate(input, () => {
    storage.project(input.projectId)
    const existing = storage.db.select().from(personas).where(and(
      eq(personas.id, input.personaId), eq(personas.projectId, input.projectId), eq(personas.workspaceId, storage.workspace.id),
    )).get()
    if (!existing) throw new Error('Persona not found.')
    storage.db.delete(personas).where(eq(personas.id, existing.id)).run()
    const basePath = join(storage.directory, 'credentials', existing.credentialId)
    try { unlinkSync(basePath) } catch { /* ignore */ }
    try { unlinkSync(basePath + '.session') } catch { /* ignore */ }
    storage.event(null, 'persona.deleted', `Removed persona ${existing.handle}.`, { projectId: input.projectId, personaId: existing.id })
    return { id: existing.id }
  })
}

/**
 * Remove local 0600 persona credential & minted session files for one or more credential IDs.
 * Intended to run after a project-deletion transaction commits so credential files are never
 * orphaned on disk and a rolled-back transaction never loses credentials.
 */
export function deletePersonaCredentialFiles(dataDirectory: string, credentialIds: readonly string[]): number {
  let removed = 0
  const credDir = join(dataDirectory, 'credentials')
  for (const credentialId of credentialIds) {
    if (!credentialId || credentialId.includes('..') || /[\\/\0]/.test(credentialId)) continue
    const basePath = join(credDir, credentialId)
    for (const candidate of [basePath, `${basePath}.session`]) {
      try {
        unlinkSync(candidate)
        removed += 1
      } catch {
        // Already absent or unreadable; best-effort cleanup.
      }
    }
  }
  return removed
}

export function resolveRunPersonas(storage: Store, projectId: string, approvedPersonaIds: readonly string[]): Map<string, ResolvedPersona> {
  const allowed = new Set(approvedPersonaIds)
  const map = new Map<string, ResolvedPersona>()
  if (!allowed.size) return map
  const rows = storage.db.select().from(personas)
    .where(and(eq(personas.projectId, projectId), eq(personas.workspaceId, storage.workspace.id)))
    .all()
  for (const row of rows) {
    if (!allowed.has(row.id)) continue
    const path = join(storage.directory, 'credentials', row.credentialId)

    if (row.authKind === 'login') {
      const sessionPath = path + '.session'
      const sessionRead = readVerifiedSessionFile(sessionPath)
      if (isBrowserSessionConfig(row.loginConfig as { adapter?: string } | null)) {
        const { bundle, mtimeMs, ino } = readBrowserSessionCredentialFile(path)
        const history: string[] = [...extractBrowserBundleSecrets(bundle)]
        if (sessionRead) {
          if (sessionRead.session.value && !history.includes(sessionRead.session.value)) {
            history.push(sessionRead.session.value)
          }
          for (const tok of sessionRead.session.scrubTokens ?? []) {
            if (tok && !history.includes(tok)) history.push(tok)
          }
          for (const tok of bundleSecrets(sessionRead.session.bundle)) {
            if (tok && !history.includes(tok)) history.push(tok)
          }
        }
        map.set(row.handle, {
          id: row.id,
          handle: row.handle,
          roleLabel: row.roleLabel,
          originAllowlist: row.originAllowlist,
          authKind: row.authKind,
          headerName: row.headerName,
          loginConfig: row.loginConfig ?? null,
          credentialId: row.credentialId,
          secret: sessionRead?.session.value ?? history[0] ?? 'browser_session',
          canaryMarkers: row.canaryMarkers,
          secretPath: path,
          secretMtimeMs: mtimeMs,
          secretIno: ino,
          secretHistory: history,
          sessionPath,
          sessionMtimeMs: sessionRead?.mtimeMs,
          sessionIno: sessionRead?.ino,
          session: sessionRead?.session ?? null,
        })
        continue
      }

      const allowEmptyEmail = row.loginConfig?.adapter === 'clerk_client'
      const { password, mtimeMs, ino } = readLoginCredentialFile(path, { allowEmptyEmail })
      const history: string[] = [password]
      if (sessionRead) {
        if (sessionRead.session.value && !history.includes(sessionRead.session.value)) {
          history.push(sessionRead.session.value)
        }
        for (const tok of sessionRead.session.scrubTokens ?? []) {
          if (tok && !history.includes(tok)) history.push(tok)
        }
        for (const tok of bundleSecrets(sessionRead.session.bundle)) {
          if (tok && !history.includes(tok)) history.push(tok)
        }
      }
      map.set(row.handle, {
        id: row.id,
        handle: row.handle,
        roleLabel: row.roleLabel,
        originAllowlist: row.originAllowlist,
        authKind: row.authKind,
        headerName: row.headerName,
        loginConfig: row.loginConfig ?? null,
        credentialId: row.credentialId,
        secret: password,
        canaryMarkers: row.canaryMarkers,
        secretPath: path,
        secretMtimeMs: mtimeMs,
        secretIno: ino,
        secretHistory: history,
        sessionPath,
        sessionMtimeMs: sessionRead?.mtimeMs,
        sessionIno: sessionRead?.ino,
        session: sessionRead?.session ?? null,
      })
      continue
    }

    const { secret, mtimeMs, ino } = readVerifiedSecretFile(path)
    map.set(row.handle, {
      id: row.id,
      handle: row.handle,
      roleLabel: row.roleLabel,
      originAllowlist: row.originAllowlist,
      authKind: row.authKind,
      headerName: row.headerName,
      loginConfig: row.loginConfig ?? null,
      credentialId: row.credentialId,
      secret,
      canaryMarkers: row.canaryMarkers,
      secretPath: path,
      secretMtimeMs: mtimeMs,
      secretIno: ino,
      secretHistory: [secret],
    })
  }
  return map
}

export function personaSecrets(resolved: ReadonlyMap<string, ResolvedPersona>): NamedSecret[] {
  const out: NamedSecret[] = []
  const seen = new Set<string>()
  const push = (placeholder: string, value: string, prevalidatedCookieHeader = false) => {
    if (!value) return
    if (!prevalidatedCookieHeader && !isAcceptableSecretNeedle(value)) return
    const key = `${placeholder}\0${value}`
    if (seen.has(key)) return
    seen.add(key)
    out.push({ value, placeholder })
  }
  const pushCookieHeader = (placeholder: string, rawCookieHeader: string) => {
    const extracted = new Set<string>()
    addCookieHeaderSecrets(rawCookieHeader, extracted)
    for (const tok of extracted) {
      push(placeholder, tok, true)
    }
  }
  for (const persona of resolved.values()) {
    try {
      if (persona.authKind === 'login') {
        refreshPersonaSession(persona)
      } else {
        refreshPersonaSecret(persona)
      }
    } catch {
      /* keep cached history if file permissions changed */
    }
    const placeholder = `[persona:${persona.handle}:secret]`

    // 1. Primary static credential (cookie header for `cookie` personas, password/token for others).
    if (persona.secret) {
      if (persona.authKind === 'cookie') {
        pushCookieHeader(placeholder, persona.secret)
      } else {
        push(placeholder, persona.secret)
      }
    }

    // 2. Active minted session value.
    if (persona.session?.value) {
      if (persona.session.headerType === 'cookie') {
        pushCookieHeader(placeholder, persona.session.value)
      } else {
        push(placeholder, persona.session.value)
      }
    }

    // 3. Historical secrets, session scrubTokens, and bundle-derived secrets.
    const extraValues = new Set<string>([
      ...(persona.secretHistory ?? []),
      ...(persona.session?.scrubTokens ?? []),
      ...bundleSecrets(persona.session?.bundle),
    ])
    for (const raw of extraValues) {
      if (!raw) continue
      // Never misparse a login password containing `=` as a cookie pair.
      const isRawPassword = persona.authKind === 'login' && raw === persona.secret
      if (!isRawPassword && (persona.authKind === 'cookie' || persona.authKind === 'login') && looksLikeCookieHeaderString(raw)) {
        pushCookieHeader(placeholder, raw)
      } else {
        push(placeholder, raw)
      }
    }
  }
  return out
}

export function buildPersonaHeader(persona: ResolvedPersona, origin: string): Record<string, string> | null {
  if (!persona.originAllowlist.includes(origin)) return null
  let frame: PersonaCredentialFrame | null = null
  if (persona.authKind === 'login') {
    frame = frameForSessionOrigin(refreshPersonaSession(persona), persona.originAllowlist, origin, persona.headerName)
  } else {
    const secret = refreshPersonaSecret(persona)
    frame = {
      headers: persona.authKind === 'bearer'
        ? { Authorization: 'Bearer ' + secret }
        : persona.authKind === 'cookie'
          ? { Cookie: secret }
          : { [persona.headerName ?? 'X-Api-Key']: secret },
      cookies: [],
      storage: null,
    }
  }
  if (!frame || !Object.keys(frame.headers).length) return null
  return frame.headers
}

/**
 * Browser-facing attachment for one origin: Playwright-compatible cookie records (with
 * `httpOnly`/`secure`/`sameSite` preserved), request headers for API calls, and the storage
 * snapshot to hydrate via `storageHydrationScript()`. Returns null outside the allowlist.
 */
export interface PersonaBrowserAttachment {
  origin: string
  headers: Record<string, string>
  cookies: Array<{
    name: string
    value: string
    domain: string
    path: string
    httpOnly: boolean
    secure: boolean
    sameSite?: 'Strict' | 'Lax' | 'None'
    expires?: number
  }>
  storage: PersonaStorageSnapshot | null
  initScript: string | null
}

export function buildPersonaBrowserAttachment(
  persona: ResolvedPersona,
  origin: string,
): PersonaBrowserAttachment | null {
  if (!persona.originAllowlist.includes(origin)) return null
  let frame: PersonaCredentialFrame | null
  if (persona.authKind === 'login') {
    frame = frameForSessionOrigin(refreshPersonaSession(persona), persona.originAllowlist, origin, persona.headerName)
  } else {
    const secret = refreshPersonaSecret(persona)
    frame = {
      headers: persona.authKind === 'bearer'
        ? { Authorization: 'Bearer ' + secret }
        : persona.authKind === 'cookie'
          ? { Cookie: secret }
          : { [persona.headerName ?? 'X-Api-Key']: secret },
      cookies: [],
      storage: null,
    }
  }
  if (!frame) return null
  let secureByOrigin = true
  try { secureByOrigin = new URL(origin).protocol === 'https:' } catch { secureByOrigin = true }
  return {
    origin,
    headers: frame.headers,
    cookies: frame.cookies.map(cookie => ({
      name: cookie.name,
      value: cookie.value,
      domain: cookie.domain,
      path: cookie.path,
      httpOnly: cookie.httpOnly === true,
      secure: cookie.secure === true || secureByOrigin,
      ...(cookie.sameSite ? { sameSite: cookie.sameSite } : {}),
      ...(cookie.expires ? { expires: cookie.expires } : {}),
    })),
    storage: frame.storage,
    initScript: storageHydrationScript(frame.storage),
  }
}

