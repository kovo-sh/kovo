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

/** Normalize an untrusted bundle (operator import, persisted file, adapter output). */
export function normalizePersonaBundle(input: unknown): PersonaCredentialBundle | undefined {
  if (!input || typeof input !== 'object' || Array.isArray(input)) return undefined
  const rec = input as PersonaCredentialBundle
  const cookies = sanitizeCookieRecords(rec.cookies)
  const headers = sanitizeHeaders(rec.headers)
  const attachments = sanitizeAttachments(rec.attachments)
  const storage = sanitizeStorageSnapshot(rec.storage)
  const storageOrigins = Array.isArray(rec.storageOrigins)
    ? [...new Set(rec.storageOrigins
        .map(sanitizeOriginPattern)
        .filter((origin): origin is string => Boolean(origin)))].slice(0, MAX_BUNDLE_ATTACHMENTS)
    : []
  if (!cookies.length && !Object.keys(headers).length && !attachments.length && !storage) return undefined
  return {
    v: 2,
    ...(cookies.length ? { cookies } : {}),
    ...(Object.keys(headers).length ? { headers } : {}),
    ...(attachments.length ? { attachments } : {}),
    ...(storage ? { storage } : {}),
    ...(storageOrigins.length ? { storageOrigins } : {}),
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

  const headers: Record<string, string> = { ...(bundle.headers ?? {}) }
  if (attachment?.headers) Object.assign(headers, attachment.headers)
  if (cookies.length) {
    headers.Cookie = cookies.map(cookie => `${cookie.name}=${cookie.value}`).join('; ')
  }

  const storageMode = attachment?.storage ?? (
    bundle.storageOrigins?.length
      ? (bundle.storageOrigins.some(pattern => originMatchesAttachment(origin, pattern)) ? 'both' : false)
      : (attachmentsDeclared ? false : 'both')
  )
  const storage = bundle.storage && storageMode !== false
    ? {
        ...(storageMode !== 'session' && bundle.storage.localStorage
          ? { localStorage: { ...bundle.storage.localStorage } }
          : {}),
        ...(storageMode !== 'local' && bundle.storage.sessionStorage
          ? { sessionStorage: { ...bundle.storage.sessionStorage } }
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

/** All secret material inside a bundle (cookie values, sensitive header values, token-like storage). */
export function bundleSecrets(bundle: PersonaCredentialBundle | undefined): string[] {
  if (!bundle) return []
  const out = new Set<string>()
  const sensitiveHeader = (name: string) =>
    /^(authorization|cookie|set-cookie|x-xsrf-token)$/i.test(name) ||
    /csrf|xsrf|token|secret|api[-_]?key|session|auth/i.test(name)
  const addHeaderValue = (name: string, value: string) => {
    if (!sensitiveHeader(name)) return
    const trimmed = value.replace(/^Bearer\s+/i, '').trim()
    if (trimmed.length >= 4) out.add(trimmed)
    if (name.toLowerCase() === 'cookie') {
      for (const pair of value.split(';')) {
        const eq = pair.indexOf('=')
        if (eq <= 0) continue
        const cookieValue = pair.slice(eq + 1).trim().replace(/^["']|["']$/g, '')
        if (cookieValue.length >= 8) out.add(cookieValue)
      }
    }
  }
  for (const cookie of bundle.cookies ?? []) {
    if (cookie.value.length >= 4) out.add(cookie.value)
  }
  for (const [name, value] of Object.entries(bundle.headers ?? {})) {
    addHeaderValue(name, value)
  }
  for (const scope of [bundle.storage?.localStorage, bundle.storage?.sessionStorage]) {
    for (const [key, value] of Object.entries(scope ?? {})) {
      if (value.length >= 4 && /token|jwt|auth|secret|key|session|credential/i.test(key)) out.add(value)
    }
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
  const addToken = (tok: string | undefined) => {
    if (!tok || tok.length < 4 || seen.has(tok)) return
    seen.add(tok)
    mergedScrub.push(tok)
  }

  try {
    const existing = readVerifiedSessionFile(sessionPath)
    if (existing) {
      addToken(existing.session.value)
      for (const tok of existing.session.scrubTokens ?? []) addToken(tok)
    }
  } catch {
    // Ignore missing/unparseable prior session file.
  }

  addToken(session.value)
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

    if (input.authKind === 'login') {
      const isClerkClient = input.loginConfig?.adapter === 'clerk_client'
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
    } else {
      fileBody = input.secret.trim()
    }

    writeFileSync(path, fileBody, { mode: 0o600, flag: 'wx' })
    chmodSync(path, 0o600)
    const personaId = randomUUID()
    try {
      storage.db.insert(personas).values({
        id: personaId,
        projectId: project.id,
        workspaceId: storage.workspace.id,
        handle: input.handle,
        roleLabel: input.roleLabel,
        originAllowlist: [...new Set(input.originAllowlist)],
        authKind: input.authKind,
        headerName: input.authKind === 'header' ? (input.headerName ?? 'X-Api-Key') : null,
        loginConfig: storedLoginConfig,
        credentialId,
        canaryMarkers,
        createdAt: Date.now(),
      }).run()
    } catch (error) {
      try { unlinkSync(path) } catch { /* ignore */ }
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
    const sameAuthKind = existing.authKind === input.authKind && existingIsClerkClient === nextIsClerkClient

    const rawSecret = input.secret ?? ''
    const hasNewSecret = rawSecret.trim().length > 0
    if (!sameAuthKind && !hasNewSecret) {
      throw new Error(
        nextIsClerkClient
          ? 'Clerk __client cookie value is required when switching sign-in method.'
          : 'Credential secret is required when switching sign-in method.',
      )
    }

    const canaryMarkers = [...(input.canaryMarkers ?? existing.canaryMarkers)]
    let storedLoginConfig: PersonaLoginConfig | null = null
    let newFileBody: string | null = null

    if (input.authKind === 'login') {
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

    try {
      storage.db.update(personas).set({
        roleLabel: input.roleLabel,
        originAllowlist: [...new Set(input.originAllowlist)],
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
      const allowEmptyEmail = row.loginConfig?.adapter === 'clerk_client'
      const { password, mtimeMs, ino } = readLoginCredentialFile(path, { allowEmptyEmail })
      const sessionPath = path + '.session'
      const sessionRead = readVerifiedSessionFile(sessionPath)
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
  const push = (placeholder: string, value: string) => {
    if (!value || value.length < 4) return
    const key = `${placeholder}\0${value}`
    if (seen.has(key)) return
    seen.add(key)
    out.push({ value, placeholder })
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
    const values = new Set<string>([
      persona.secret,
      ...(persona.secretHistory ?? []),
      ...(persona.session?.value ? [persona.session.value] : []),
      ...(persona.session?.scrubTokens ?? []),
      ...bundleSecrets(persona.session?.bundle),
    ])
    for (const raw of values) {
      if (!raw) continue
      push(placeholder, raw)
      // Also scrub individual cookie values >= 8 chars (e.g., session tokens / rotated JWTs inside "sid=...; __session=<jwt>")
      if (persona.authKind === 'cookie' || persona.authKind === 'login') {
        for (const pair of raw.split(';')) {
          const eq = pair.indexOf('=')
          if (eq <= 0) continue
          const cookieVal = pair.slice(eq + 1).trim().replace(/^["']|["']$/g, '')
          if (cookieVal.length >= 8) push(placeholder, cookieVal)
        }
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

