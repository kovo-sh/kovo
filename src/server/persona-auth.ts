import type { PersonaLoginAdapter, PersonaLoginConfig } from '../domain.ts'
import { createHmac } from 'node:crypto'
import { lookup } from 'node:dns/promises'
import { request as httpRequest } from 'node:http'
import type { IncomingHttpHeaders } from 'node:http'
import { request as httpsRequest } from 'node:https'
import ipaddr from 'ipaddr.js'
import {
  normalizePersonaBundle,
  readLoginCredentialFile,
  resolveRunPersonas,
  writePersonaSessionFile,
} from './persona-vault.ts'
import type {
  MintedPersonaSession,
  PersonaCookieRecord,
  PersonaCredentialBundle,
  PersonaStorageSnapshot,
  ResolvedPersona,
} from './persona-vault.ts'
import { bundleSecrets, frameForSessionOrigin } from './persona-vault.ts'
import { isCredentialScopeHost, isIpLiteralHost, normalizeHostname, registrableDomain } from './public-suffix.ts'
import { redact } from './redact.ts'
import type { Store } from './store.ts'

export { registrableDomain } from './public-suffix.ts'

export type PersonaAuthErrorCode =
  | 'CAPTCHA_DETECTED'
  | 'MFA_REQUIRED'
  | 'INVALID_CREDENTIALS'
  | 'UNSUPPORTED_ADAPTER'
  | 'AUTH_FAILED'

export class PersonaAuthError extends Error {
  readonly code: PersonaAuthErrorCode

  constructor(code: PersonaAuthErrorCode, message: string) {
    super(message)
    this.name = 'PersonaAuthError'
    this.code = code
  }
}

export interface AuthenticateResult {
  personaId: string
  handle: string
  adapterUsed: Exclude<PersonaLoginAdapter, 'auto'> | 'oidc' | 'import'
  headerType: 'cookie' | 'bearer' | 'header'
  expiresAt?: number
  refreshIntervalSec?: number
  refresh?: () => Promise<void>
  /** Composite v6 session (cookies/headers/storage bundle) for per-worker clone seeding. */
  session?: MintedPersonaSession
}

interface PlaywrightFormCookie {
  name: string
  value: string
  domain: string
  path?: string
  httpOnly?: boolean
  secure?: boolean
  sameSite?: 'Strict' | 'Lax' | 'None'
  /** Playwright expresses cookie expiry in seconds. */
  expires?: number
}

interface PlaywrightFormLocator {
  count(): Promise<number>
  first(): PlaywrightFormLocator
  isVisible?(options?: { timeout?: number }): Promise<boolean>
  fill(value: string, options?: { timeout?: number }): Promise<void>
  click(options?: { timeout?: number }): Promise<void>
  press?(key: string, options?: { timeout?: number }): Promise<void>
}

interface PlaywrightFormPage {
  goto(url: string, options?: { waitUntil?: 'load' | 'domcontentloaded' | 'networkidle'; timeout?: number }): Promise<unknown>
  waitForTimeout(ms: number): Promise<void>
  waitForLoadState?(state: 'load' | 'domcontentloaded' | 'networkidle', options?: { timeout?: number }): Promise<void>
  url(): string
  locator(selector: string): PlaywrightFormLocator
  frames?(): Array<{ url(): string }>
  evaluate<T>(fn: () => T | Promise<T>): Promise<T>
  close(): Promise<void>
}

interface PlaywrightFormRoute {
  request(): {
    url(): string
    method?(): string
    resourceType?(): string
    headers?(): Record<string, string>
  }
  abort(errorCode?: string): Promise<void>
  continue(): Promise<void>
  fulfill?(options: { status?: number; contentType?: string; body?: string }): Promise<void>
}

interface PlaywrightFormContext {
  route(url: string, handler: (route: PlaywrightFormRoute) => Promise<void> | void): Promise<void>
  addInitScript?(script: string | (() => void)): Promise<void>
  routeWebSocket?(url: string, handler: (ws: {
    url(): string
    close(options?: { code?: number; reason?: string }): Promise<void> | void
    connectToServer?(): Promise<void> | void
  }) => Promise<void> | void): Promise<void>
  newPage(): Promise<PlaywrightFormPage>
  cookies(urls?: string | string[]): Promise<PlaywrightFormCookie[]>
  close(): Promise<void>
}

export interface PlaywrightFormBrowserLike {
  newContext(options?: Record<string, unknown>): Promise<PlaywrightFormContext>
  close(): Promise<void>
}

export interface PersonaAuthManagerOptions {
  /**
   * Transport override for tests/embedders. When supplied without `resolveHost`, Guardian cannot
   * observe or pin that transport's DNS, so the injector owns the pinning contract. Production
   * (default fetch) always resolves and connects to the validated address.
   */
  fetchImpl?: typeof fetch
  launchBrowser?: (pinnedHosts?: ReadonlyMap<string, readonly string[]>) => Promise<PlaywrightFormBrowserLike>
  timeoutMs?: number
  /** Minimum interval between broker-invoked 401 re-auths per persona (default 60s). */
  reauthMinIntervalMs?: number
  /** Injectable DNS resolver for deterministic SSRF/rebinding checks in tests. */
  resolveHost?: (hostname: string) => Promise<string[]>
}

const DEFAULT_TIMEOUT_MS = 15_000
const DEFAULT_CLERK_REFRESH_SEC = 35

const CAPTCHA_PATTERN = /challenges\.cloudflare\.com|cf-turnstile|turnstile|captcha_invalid|captcha_missing|captcha_failed|captcha_required|recaptcha|hcaptcha|arkoselabs|funcaptcha|bot_detected|anti[_-]?bot|verify you are human|complete the captcha/i
const MFA_PATTERN = /needs_second_factor|second_factor|mfa_required|two_factor|totp_required|multi[- ]?factor/i

function captchaAbortMessage(target: string): string {
  return `Authentication aborted: CAPTCHA / Cloudflare Turnstile challenge detected on ${target}. Guardian never bypasses CAPTCHA or anti-bot challenges — use a Session Cookie / Bearer persona or disable CAPTCHA for dedicated test accounts.`
}

function mfaAbortMessage(email: string): string {
  return `Authentication aborted: Multi-factor authentication (MFA / second factor) is required for ${email}. Guardian cannot bypass MFA — use a Session Cookie / Bearer persona or a test account without MFA.`
}

function decodeJwtPayload(jwt: string): { exp?: number; iat?: number; sub?: string; sid?: string } | null {
  try {
    const parts = jwt.split('.')
    if (parts.length < 2) return null
    const b64 = parts[1].replace(/-/g, '+').replace(/_/g, '/')
    const pad = b64.length % 4 === 0 ? '' : '='.repeat(4 - (b64.length % 4))
    const decoded = Buffer.from(b64 + pad, 'base64').toString('utf8')
    const parsed = JSON.parse(decoded) as Record<string, unknown>
    return {
      exp: typeof parsed.exp === 'number' ? parsed.exp : undefined,
      iat: typeof parsed.iat === 'number' ? parsed.iat : undefined,
      sub: typeof parsed.sub === 'string' ? parsed.sub : undefined,
      sid: typeof parsed.sid === 'string' ? parsed.sid : undefined,
    }
  } catch {
    return null
  }
}

export function decodeClerkPublishableKey(key: string): string | null {
  const match = /^pk_(?:live|test)_([A-Za-z0-9+/=_-]+)$/.exec(key.trim())
  if (!match) return null
  try {
    const raw = match[1].replace(/-/g, '+').replace(/_/g, '/')
    const pad = raw.length % 4 === 0 ? '' : '='.repeat(4 - (raw.length % 4))
    const host = Buffer.from(raw + pad, 'base64').toString('utf8').replace(/\$+$/, '').trim()
    if (!host || !/^[a-z0-9][a-z0-9.-]*\.[a-z]{2,}$/i.test(host)) return null
    return `https://${host.toLowerCase()}`
  } catch {
    return null
  }
}

/**
 * Registrable-domain scoping is backed by the vendored Public Suffix List
 * (`public-suffix.ts`). The old hardcoded list treated shared platform tenants
 * (`github.io`, `vercel.app`, `s3.amazonaws.com`) and ccTLD second levels (`com.co`)
 * as registrable domains, which put every sibling tenant in scope.
 */
function allowedHostnames(allowlist: readonly string[]): string[] {
  const hosts: string[] = []
  for (const origin of allowlist) {
    try {
      hosts.push(normalizeHostname(new URL(origin).hostname))
    } catch {
      // Ignore malformed allowlist entries; the broker rejects them independently.
    }
  }
  return hosts
}

function allowlistOrigins(allowlist: readonly string[]): string[] {
  const origins: string[] = []
  for (const entry of allowlist) {
    try {
      origins.push(new URL(entry).origin)
    } catch {
      // Ignore malformed allowlist entries.
    }
  }
  return origins
}

/**
 * True when `host` is an explicitly allowlisted host or shares the registrable domain
 * of one. Shared/private suffixes (and single-label hosts) never widen scope: an
 * allowlist entry that is itself a suffix matches only that exact host.
 */
export function isHostInScope(host: string, allowlist: readonly string[]): boolean {
  const normalized = normalizeHostname(host)
  if (!normalized) return false
  for (const allowed of allowedHostnames(allowlist)) {
    if (!allowed) continue
    if (normalized === allowed) return true
    const registrable = registrableDomain(allowed)
    if (!registrable) continue
    if (normalized === registrable) return true
    if (normalized.endsWith(`.${registrable}`)) return true
  }
  return false
}

export function isOriginInScope(origin: string, allowlist: readonly string[]): boolean {
  try {
    const parsed = new URL(origin)
    if (parsed.protocol !== 'https:' && parsed.protocol !== 'http:') return false
    // Credentials are never bound to a URL that smuggles userinfo.
    if (parsed.username || parsed.password) return false
    if (!isHostInScope(parsed.hostname, allowlist)) return false
    // An allowlist entry that names this exact host may be port-bound; a widened
    // registrable-domain match (e.g. clerk.<apex>) carries no port constraint.
    const exactEntries: URL[] = []
    for (const entry of allowlist) {
      try {
        const allowed = new URL(entry)
        if (normalizeHostname(allowed.hostname) === normalizeHostname(parsed.hostname)) exactEntries.push(allowed)
      } catch {
        // Ignore malformed entries.
      }
    }
    if (exactEntries.length === 0) return true
    return exactEntries.some(allowed => !allowed.port || allowed.port === parsed.port)
  } catch {
    return false
  }
}


/** Loopback is allowed only for an explicitly allowlisted local-lab origin; link-local is never allowed. */
export type AddressClass = 'public' | 'loopback' | 'blocked'

export function classifyAddress(address: string): AddressClass {
  const bare = address.trim().replace(/^\[|\]$/g, '')
  // `localhost` is a loopback name, not an IP literal. Treating it as `blocked` broke
  // explicitly allowlisted local-lab logins while 127.0.0.1/[::1] worked.
  if (bare.toLowerCase() === 'localhost') return 'loopback'
  try {
    const ip = ipaddr.process(bare)
    const range = ip.range()
    if (range === 'unicast') return 'public'
    if (range === 'loopback') return 'loopback'
    return 'blocked'
  } catch {
    return 'blocked'
  }
}

function isLoopbackLiteral(host: string): boolean {
  const bare = host.replace(/^\[|\]$/g, '')
  if (bare.toLowerCase() === 'localhost') return true
  if (!ipaddr.isValid(bare)) return false
  return ipaddr.process(bare).range() === 'loopback'
}

function extractSetCookies(headers: Headers): Map<string, string> {
  const map = new Map<string, string>()
  const anyHeaders = headers as Headers & { getSetCookie?: () => string[] }
  let lines: string[] = []
  if (typeof anyHeaders.getSetCookie === 'function') {
    lines = anyHeaders.getSetCookie()
  }
  if (!lines.length) {
    const combined = headers.get('set-cookie')
    if (combined) {
      // Split Set-Cookie headers while preserving Expires=Day, DD Mon YYYY commas
      lines = combined.split(/,(?=\s*[^;=,\s]+=)/g)
    }
  }
  for (const line of lines) {
    const first = line.split(';')[0]?.trim()
    if (!first) continue
    const eq = first.indexOf('=')
    if (eq <= 0) continue
    const name = first.slice(0, eq).trim()
    const value = first.slice(eq + 1).trim()
    // Skip deleted/cleared cookies
    if (!value || /;\s*max-age\s*=\s*0\b/i.test(line)) continue
    map.set(name, value)
  }
  return map
}

function cookiesToHeader(cookies: ReadonlyMap<string, string>): string {
  return [...cookies.entries()].map(([k, v]) => `${k}=${v}`).join('; ')
}

function getJsonPath(obj: unknown, path: string): string | null {
  const parts = path.split('.').map(s => s.trim()).filter(Boolean)
  let cur: unknown = obj
  for (const part of parts) {
    if (!cur || typeof cur !== 'object' || !(part in (cur as Record<string, unknown>))) {
      return null
    }
    cur = (cur as Record<string, unknown>)[part]
  }
  return typeof cur === 'string' && cur.trim() ? cur.trim() : null
}

function sanitizeErrorText(text: string, secrets: readonly string[]): string {
  const named = secrets
    .filter(s => s.length >= 4)
    .map(value => ({ value, placeholder: '[redacted]' }))
  return redact(text, named).slice(0, 320)
}

function checkResponseForCaptchaOrMfa(text: string, target: string, email: string): void {
  if (CAPTCHA_PATTERN.test(text)) {
    throw new PersonaAuthError('CAPTCHA_DETECTED', captchaAbortMessage(target))
  }
  if (MFA_PATTERN.test(text)) {
    throw new PersonaAuthError('MFA_REQUIRED', mfaAbortMessage(email))
  }
}

const JWT_SHAPE = /^[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]*$/

/** RFC 6238 TOTP over HMAC-SHA1 (6 digits / 30 s by default). */
export function generateTotp(seed: string, options: { digits?: number; period?: number; atMs?: number } = {}): string {
  const normalized = normalizeTotpSeed(seed)
  if (!normalized) throw new PersonaAuthError('AUTH_FAILED', 'TOTP seed is not valid base32.')
  const digits = options.digits ?? 6
  const period = options.period ?? 30
  const counter = Math.floor((options.atMs ?? Date.now()) / 1000 / period)
  const message = Buffer.alloc(8)
  message.writeUInt32BE(Math.floor(counter / 2 ** 32), 0)
  message.writeUInt32BE(counter >>> 0, 4)
  const digest = createHmac('sha1', normalized).update(message).digest()
  const offset = digest[digest.length - 1] & 0x0f
  const binary = ((digest[offset] & 0x7f) << 24) |
    ((digest[offset + 1] & 0xff) << 16) |
    ((digest[offset + 2] & 0xff) << 8) |
    (digest[offset + 3] & 0xff)
  return String(binary % 10 ** digits).padStart(digits, '0')
}

/** Accepts raw base32 or an `otpauth://totp/...?secret=...` URI. */
export function normalizeTotpSeed(seed: string): Buffer | null {
  const raw = seed.trim()
  if (!raw) return null
  let secret = raw
  if (/^otpauth:\/\//i.test(raw)) {
    try {
      const url = new URL(raw)
      secret = url.searchParams.get('secret') ?? ''
    } catch {
      return null
    }
  }
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'
  const cleaned = secret.replace(/[\s-]/g, '').replace(/=+$/, '').toUpperCase()
  if (!cleaned || /[^A-Z2-7]/.test(cleaned)) return null
  let bits = 0
  let value = 0
  const bytes: number[] = []
  for (const char of cleaned) {
    value = (value << 5) | alphabet.indexOf(char)
    bits += 5
    if (bits >= 8) {
      bytes.push((value >>> (bits - 8)) & 0xff)
      bits -= 8
    }
  }
  return bytes.length ? Buffer.from(bytes) : null
}

function storageStateCookieToRecord(raw: unknown): PersonaCookieRecord | null {
  if (!raw || typeof raw !== 'object') return null
  const rec = raw as Record<string, unknown>
  if (typeof rec.name !== 'string' || typeof rec.value !== 'string') return null
  if (typeof rec.domain !== 'string' || !rec.domain) return null
  const rawExpires = typeof rec.expires === 'number' && Number.isFinite(rec.expires) ? rec.expires : undefined
  return {
    name: rec.name,
    value: rec.value,
    domain: rec.domain,
    path: typeof rec.path === 'string' && rec.path.startsWith('/') ? rec.path : '/',
    ...(rec.httpOnly === true ? { httpOnly: true } : {}),
    ...(rec.secure === true ? { secure: true } : {}),
    ...(rec.sameSite === 'Strict' || rec.sameSite === 'Lax' || rec.sameSite === 'None' ? { sameSite: rec.sameSite } : {}),
    // Playwright storageState uses seconds; be tolerant of millisecond input.
    ...(rawExpires && rawExpires > 0
      ? { expires: rawExpires < 1e12 ? Math.floor(rawExpires * 1000) : Math.floor(rawExpires) }
      : {}),
  }
}

function cookieDomainAllowed(domain: string, allowlist: readonly string[]): boolean {
  const host = domain.replace(/^\.+/, '').toLowerCase()
  if (!host) return false
  return allowedHostnames(allowlist).some(allowed => allowed === host || allowed.endsWith(`.${host}`))
}

function buildImportedBundle(params: {
  cookies: PersonaCookieRecord[]
  headersByOrigin: Map<string, Record<string, string>>
  storageByOrigin: Map<string, PersonaStorageSnapshot>
  allowlist: readonly string[]
  /** Browser-captured cookies are already context-scoped; bind unmatched mock/edge domains here. */
  fallbackOrigin?: string
}): { session: MintedPersonaSession; origins: string[] } {
  const knownOrigins = allowlistOrigins(params.allowlist)
  const isAllowedOrigin = (origin: string) => knownOrigins.includes(origin) || isOriginInScope(origin, params.allowlist)
  const origins = new Set<string>()
  const attachments: NonNullable<PersonaCredentialBundle['attachments']> = []

  let cookies = params.cookies.filter(cookie => cookieDomainAllowed(cookie.domain, params.allowlist))
  if (!cookies.length && params.cookies.length && params.fallbackOrigin && isAllowedOrigin(params.fallbackOrigin)) {
    const fallbackHost = new URL(params.fallbackOrigin).hostname
    cookies = params.cookies.map(cookie => ({ ...cookie, domain: fallbackHost }))
    origins.add(params.fallbackOrigin)
  }

  for (const origin of params.headersByOrigin.keys()) {
    if (isAllowedOrigin(origin)) origins.add(origin)
  }
  for (const origin of params.storageByOrigin.keys()) {
    if (isAllowedOrigin(origin)) origins.add(origin)
  }
  if (!origins.size) {
    // Derive origins from cookie domains + allowlist so a cookie-only import still scopes.
    for (const origin of knownOrigins) {
      const host = new URL(origin).hostname
      if (cookies.some(cookie => host === cookie.domain || host.endsWith(`.${cookie.domain}`))) origins.add(origin)
    }
  }

  // If an allowlisted origin is covered by imported cookies, register an attachment for it.
  for (const origin of knownOrigins) {
    if (origins.has(origin)) continue
    const host = new URL(origin).hostname
    if (cookies.some(cookie => host === cookie.domain || host.endsWith(`.${cookie.domain}`))) origins.add(origin)
  }

  for (const origin of origins) {
    const storage = params.storageByOrigin.get(origin)
    const headers = params.headersByOrigin.get(origin)
    attachments.push({
      origin,
      ...(headers && Object.keys(headers).length ? { headers } : {}),
      ...(storage ? { storage: 'both' } : {}),
    })
  }

  const storage: PersonaStorageSnapshot = {}
  for (const [origin, snapshot] of params.storageByOrigin) {
    if (!origins.has(origin)) continue
    if (snapshot.localStorage) Object.assign(storage.localStorage ??= {}, snapshot.localStorage)
    if (snapshot.sessionStorage) Object.assign(storage.sessionStorage ??= {}, snapshot.sessionStorage)
  }

  if (!cookies.length && !attachments.some(a => a.headers) && !storage.localStorage && !storage.sessionStorage) {
    throw new PersonaAuthError('AUTH_FAILED', 'Imported session state contains no usable cookies, headers, or storage for the persona allowlist.')
  }

  const firstOrigin = [...origins][0]
  const firstHeaders = firstOrigin ? params.headersByOrigin.get(firstOrigin) : undefined
  const authorization = firstHeaders?.Authorization ?? firstHeaders?.authorization
  const bearer = authorization?.replace(/^Bearer\s+/i, '').trim()
  const applicableCookies = firstOrigin
    ? cookies.filter(cookie => {
        const host = new URL(firstOrigin).hostname
        return host === cookie.domain || host.endsWith(`.${cookie.domain}`)
      })
    : cookies
  const cookieHeader = applicableCookies.map(cookie => `${cookie.name}=${cookie.value}`).join('; ')
  const bundle = normalizePersonaBundle({
    cookies,
    ...(Object.keys(storage).length ? { storage } : {}),
    attachments,
  })
  const session: MintedPersonaSession = {
    headerType: bearer ? 'bearer' : 'cookie',
    ...(bearer ? { value: bearer } : { value: cookieHeader || 'imported-session-state' }),
    adapterUsed: 'import',
    scrubTokens: [...bundleSecrets(bundle)],
    ...(bundle ? { bundle } : {}),
  }
  return { session, origins: [...origins] }
}

/** Import a Playwright `storageState` object (passkey / hardware-MFA apps). */
export function importStorageState(input: unknown, allowlist: readonly string[]): { session: MintedPersonaSession; origins: string[] } {
  if (!input || typeof input !== 'object' || Array.isArray(input)) {
    throw new PersonaAuthError('AUTH_FAILED', 'storageState must be a JSON object.')
  }
  const rec = input as { cookies?: unknown; origins?: unknown }
  const cookies = Array.isArray(rec.cookies)
    ? rec.cookies.map(storageStateCookieToRecord).filter((cookie): cookie is PersonaCookieRecord => Boolean(cookie))
    : []
  const storageByOrigin = new Map<string, PersonaStorageSnapshot>()
  if (Array.isArray(rec.origins)) {
    for (const entry of rec.origins.slice(0, 64)) {
      if (!entry || typeof entry !== 'object') continue
      const originRec = entry as { origin?: unknown; localStorage?: unknown }
      if (typeof originRec.origin !== 'string') continue
      let origin: string
      try { origin = new URL(originRec.origin).origin } catch { continue }
      const local: Record<string, string> = {}
      if (Array.isArray(originRec.localStorage)) {
        for (const item of originRec.localStorage.slice(0, 256)) {
          if (!item || typeof item !== 'object') continue
          const pair = item as { name?: unknown; value?: unknown }
          if (typeof pair.name === 'string' && typeof pair.value === 'string') local[pair.name] = pair.value
        }
      }
      if (Object.keys(local).length) storageByOrigin.set(origin, { localStorage: local })
    }
  }
  return buildImportedBundle({ cookies, headersByOrigin: new Map(), storageByOrigin, allowlist })
}

const HAR_HEADER_ALLOW = /^(authorization|cookie|x-[a-z0-9-]*csrf[a-z0-9-]*|x-xsrf-token|x-tenant-id|x-org-id|x-organization-id)$/i

/** Import a HAR capture: cookies, Authorization/Cookie, tenant/org/CSRF headers per origin. */
export function importHar(input: unknown, allowlist: readonly string[]): { session: MintedPersonaSession; origins: string[] } {
  if (!input || typeof input !== 'object' || Array.isArray(input)) {
    throw new PersonaAuthError('AUTH_FAILED', 'HAR must be a JSON object.')
  }
  const log = (input as { log?: unknown }).log
  const entries = log && typeof log === 'object' ? (log as { entries?: unknown }).entries : undefined
  if (!Array.isArray(entries)) {
    throw new PersonaAuthError('AUTH_FAILED', 'HAR is missing log.entries.')
  }
  const headersByOrigin = new Map<string, Record<string, string>>()
  const cookies: PersonaCookieRecord[] = []
  for (const entry of entries.slice(0, 5_000)) {
    if (!entry || typeof entry !== 'object') continue
    const request = (entry as { request?: unknown }).request
    if (!request || typeof request !== 'object') continue
    const req = request as { url?: unknown; headers?: unknown; cookies?: unknown }
    if (typeof req.url !== 'string') continue
    let origin: string
    let parsed: URL
    try {
      parsed = new URL(req.url)
      origin = parsed.origin
    } catch {
      continue
    }
    if (isOriginInScope(origin, allowlist)) {
      const headers = headersByOrigin.get(origin) ?? {}
      if (Array.isArray(req.headers)) {
        for (const header of req.headers) {
          if (!header || typeof header !== 'object') continue
          const pair = header as { name?: unknown; value?: unknown }
          if (typeof pair.name !== 'string' || typeof pair.value !== 'string') continue
          if (!HAR_HEADER_ALLOW.test(pair.name)) continue
          headers[pair.name] = pair.value
        }
      }
      if (Object.keys(headers).length) headersByOrigin.set(origin, headers)
    }
    if (Array.isArray(req.cookies)) {
      for (const rawCookie of req.cookies.slice(0, 64)) {
        const cookie = storageStateCookieToRecord({
          ...(rawCookie && typeof rawCookie === 'object' ? rawCookie : {}),
          domain: (rawCookie && typeof rawCookie === 'object' && typeof (rawCookie as { domain?: unknown }).domain === 'string'
            ? (rawCookie as { domain: string }).domain
            : parsed.hostname),
        })
        if (cookie) cookies.push(cookie)
      }
    }
  }
  return buildImportedBundle({ cookies, headersByOrigin, storageByOrigin: new Map(), allowlist })
}

function isJwtLike(value: string): boolean {
  return value.length > 40 && value.length < 8192 && JWT_SHAPE.test(value) && value.startsWith('eyJ')
}

/** Harvest Bearer JWTs from `localStorage` / `sessionStorage` in the authenticated page. */
async function harvestBrowserTokens(page: PlaywrightFormPage): Promise<string[]> {
  try {
    const tokens = await page.evaluate(() => {
      const shape = /^[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]*$/
      const looksJwt = (v: string) => v.length > 40 && v.length < 8192 && shape.test(v) && v.startsWith('eyJ')
      const keyHint = /(?:token|jwt|auth|access|id_token|session)/i
      const out: string[] = []
      const stores: Storage[] = []
      try { stores.push(window.localStorage) } catch { /* blocked */ }
      try { stores.push(window.sessionStorage) } catch { /* blocked */ }
      const visit = (value: unknown, depth: number) => {
        if (depth > 3 || value === null || value === undefined) return
        if (typeof value === 'string') {
          const trimmed = value.trim()
          if (looksJwt(trimmed)) out.push(trimmed)
          else if ((trimmed.startsWith('{') || trimmed.startsWith('"')) && trimmed.length < 4096) {
            try { visit(JSON.parse(trimmed), depth + 1) } catch { /* not JSON */ }
          }
          return
        }
        if (Array.isArray(value)) {
          for (const item of value.slice(0, 32)) visit(item, depth + 1)
          return
        }
        if (typeof value === 'object') {
          for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
            if (typeof v === 'string' && looksJwt(v) && (keyHint.test(k) || v.startsWith('eyJ'))) out.push(v)
            else if (typeof v === 'object') visit(v, depth + 1)
          }
        }
      }
      for (const store of stores) {
        for (let i = 0; i < store.length && i < 200; i += 1) {
          const key = store.key(i)
          if (!key) continue
          visit(store.getItem(key), 0)
        }
      }
      return [...new Set(out)].slice(0, 8)
    })
    return Array.isArray(tokens) ? tokens.filter((t): t is string => typeof t === 'string') : []
  } catch {
    return []
  }
}

/** Capture localStorage/sessionStorage for the final (allowlisted) page origin. */
async function captureStorageSnapshot(
  page: PlaywrightFormPage,
  allowlist: readonly string[],
): Promise<Map<string, PersonaStorageSnapshot>> {
  const out = new Map<string, PersonaStorageSnapshot>()
  let origin: string | null = null
  try {
    origin = new URL(page.url()).origin
  } catch {
    return out
  }
  if (!origin || !isOriginInScope(origin, allowlist)) return out
  try {
    const captured = await page.evaluate(() => {
      const read = (store: Storage) => {
        const values: Record<string, string> = {}
        for (let i = 0; i < store.length && i < 128; i += 1) {
          const key = store.key(i)
          if (key) values[key] = store.getItem(key) ?? ''
        }
        return values
      }
      const local = (() => { try { return read(window.localStorage) } catch { return {} } })()
      const session = (() => { try { return read(window.sessionStorage) } catch { return {} } })()
      return { localStorage: local, sessionStorage: session }
    }) as { localStorage?: unknown; sessionStorage?: unknown } | null
    if (!captured || typeof captured !== 'object') return out
    const local = captured.localStorage && typeof captured.localStorage === 'object'
      ? captured.localStorage as Record<string, string>
      : {}
    const session = captured.sessionStorage && typeof captured.sessionStorage === 'object'
      ? captured.sessionStorage as Record<string, string>
      : {}
    if (Object.keys(local).length || Object.keys(session).length) {
      out.set(origin, {
        ...(Object.keys(local).length ? { localStorage: local } : {}),
        ...(Object.keys(session).length ? { sessionStorage: session } : {}),
      })
    }
  } catch {
    // Storage access can fail on opaque origins; a cookie-only bundle remains valid.
  }
  return out
}

function extractBearerToken(headerValue: string | undefined): string | null {
  if (!headerValue) return null
  const match = /^Bearer\s+(\S+)$/i.exec(headerValue.trim())
  if (!match || !match[1]) return null
  return isJwtLike(match[1]) ? match[1] : null
}

/** Chromium sandboxing defaults. `--no-sandbox` is an explicit, warned-about insecure opt-in. */
export interface FormChromiumLaunchOptions {
  insecureNoSandbox?: boolean
  /**
   * hostname -> validated addresses, resolved once before launch. Chromium is pinned to the
   * first validated address with `--host-resolver-rules`; every other name is `~NOTFOUND`.
   */
  pinnedHosts?: ReadonlyMap<string, readonly string[]>
}

function chromiumResolverTarget(address: string): string {
  const bare = address.replace(/^\[|\]$/g, '')
  return bare.includes(':') ? `[${bare}]` : bare
}

/** Resolver rules pin validated credential hosts and fail closed for everything else. */
export function formChromiumResolverRules(pinnedHosts?: ReadonlyMap<string, readonly string[]>): string {
  const rules: string[] = []
  for (const [host, addresses] of pinnedHosts ?? []) {
    const address = addresses[0]
    if (!host || !address) continue
    rules.push(`MAP ${host} ${chromiumResolverTarget(address)}`)
  }
  rules.push('MAP * ~NOTFOUND')
  return rules.join(', ')
}

export function formChromiumLaunchArgs(options: FormChromiumLaunchOptions = {}): string[] {
  const args = [
    '--disable-dev-shm-usage',
    '--disable-background-networking',
    `--host-resolver-rules=${formChromiumResolverRules(options.pinnedHosts)}`,
    '--force-webrtc-ip-handling-policy=disable_non_proxied_udp',
    '--webrtc-ip-handling-policy=disable_non_proxied_udp',
    // WebTransport is HTTP/3 over UDP and bypasses HTTP request interception.
    '--disable-quic',
    '--disable-features=WebTransport',
  ]
  if (options.insecureNoSandbox) args.push('--no-sandbox')
  return args
}

const webrtcGuardScript = `(() => {
  const deny = function () { throw new Error('WebRTC is disabled inside Guardian browser sessions.'); };
  for (const name of ['RTCPeerConnection', 'webkitRTCPeerConnection', 'RTCDataChannel', 'WebTransport']) {
    try { Object.defineProperty(window, name, { configurable: false, writable: false, value: deny }); } catch {}
  }
})();`

/**
 * Fallback when `routeWebSocket` is unavailable: no socket can be scope-checked, so the page
 * itself loses the constructors (fail closed). Raw browser-level sockets are additionally
 * unreachable for non-pinned names because of `--host-resolver-rules`.
 */
const formTransportDenyScript = `(() => {
  const deny = function () { throw new Error('WebSocket/WebTransport are disabled inside Guardian browser sessions.'); };
  for (const name of ['WebSocket', 'WebTransport', 'RTCPeerConnection', 'webkitRTCPeerConnection', 'RTCDataChannel']) {
    try { Object.defineProperty(window, name, { configurable: false, writable: false, value: deny }); } catch {}
  }
})();`

async function launchDefaultChromium(pinnedHosts?: ReadonlyMap<string, readonly string[]>): Promise<PlaywrightFormBrowserLike> {
  const insecureNoSandbox = process.env.GUARDIAN_INSECURE_NO_SANDBOX === '1'
  if (insecureNoSandbox) {
    console.warn('WARNING: Chromium sandbox disabled (GUARDIAN_INSECURE_NO_SANDBOX=1). Detection fidelity is reduced.')
  }
  const args = formChromiumLaunchArgs({ insecureNoSandbox, pinnedHosts })
  try {
    const coreName = 'playwright-core'
    const coreMod = await import(/* @vite-ignore */ coreName) as {
      chromium?: { launch: (opts: Record<string, unknown>) => Promise<PlaywrightFormBrowserLike> }
    }
    if (coreMod.chromium) {
      return await coreMod.chromium.launch({ headless: true, args })
    }
  } catch {
    // Fallback to @playwright/test
  }
  const pw = await import('@playwright/test')
  return await pw.chromium.launch({ headless: true, args }) as unknown as PlaywrightFormBrowserLike
}

const MAX_PINNED_RESPONSE_BYTES = 2 * 1024 * 1024

/**
 * DNS lookup pinned to the addresses validated by `assertCredentialTarget`. The transport never
 * asks the system resolver again, so a NXDOMAIN-then-rebind or public-then-loopback answer
 * sequence cannot move the connection. Any other hostname is refused.
 */
export function createPinnedLookup(
  expectedHost: string,
  addresses: readonly string[],
): (hostname: string, options: unknown, callback: (...args: unknown[]) => void) => void {
  const host = normalizeHostname(expectedHost.replace(/^\[|\]$/g, ''))
  const pinned = addresses
    .map(address => address.replace(/^\[|\]$/g, '').trim())
    .filter(Boolean)
    .map(address => ({ address, family: ipaddr.isValid(address) && ipaddr.parse(address).kind() === 'ipv6' ? 6 : 4 }))
  return (hostname, options, callback) => {
    const asked = normalizeHostname(String(hostname).replace(/^\[|\]$/g, ''))
    if (!host || !pinned.length || asked !== host) {
      callback(new Error(`Pinned resolver refused ${asked || '<empty>'} (validated host: ${host || '<none>'}).`))
      return
    }
    const opts = (options && typeof options === 'object' ? options : {}) as { family?: number; all?: boolean }
    const wanted = opts.family === 4 || opts.family === 6 ? pinned.filter(entry => entry.family === opts.family) : pinned
    if (!wanted.length) {
      callback(new Error(`Pinned resolver has no address for family ${String(opts.family)} on ${host}.`))
      return
    }
    if (opts.all) {
      callback(null, wanted)
      return
    }
    callback(null, wanted[0].address, wanted[0].family)
  }
}

function headersToRecord(headers: Headers): Record<string, string> {
  const record: Record<string, string> = {}
  headers.forEach((value, key) => { record[key] = value })
  return record
}

function responseHeadersFromNode(raw: IncomingHttpHeaders): Headers {
  const headers = new Headers()
  for (const [key, value] of Object.entries(raw)) {
    if (value === undefined) continue
    if (Array.isArray(value)) {
      for (const entry of value) headers.append(key, entry)
    } else {
      headers.set(key, value)
    }
  }
  return headers
}

/**
 * Credential transport with a pinned DNS answer (node:http(s) + custom lookup). Returns a
 * `Response` so the adapter code stays identical to the injected-fetch path.
 *
 * `NODE_USE_ENV_PROXY`/`--use-env-proxy` is unsupported for credential flows: the proxy
 * re-resolves and egresses on Guardian's behalf, so the pinned addresses no longer describe
 * the actual connection. A warning is logged once when that mode is detected.
 */
export async function pinnedFetch(
  url: string,
  init: RequestInit,
  options: { addresses: readonly string[]; timeoutMs: number; signal?: AbortSignal },
): Promise<Response> {
  const target = new URL(url)
  if (target.protocol !== 'https:' && target.protocol !== 'http:') {
    throw new PersonaAuthError('AUTH_FAILED', `Unsupported credential URL scheme ${target.protocol}.`)
  }
  const host = normalizeHostname(target.hostname.replace(/^\[|\]$/g, ''))
  const body = typeof init.body === 'string' ? Buffer.from(init.body)
    : init.body instanceof Uint8Array ? Buffer.from(init.body)
      : undefined
  const requestFn = target.protocol === 'https:' ? httpsRequest : httpRequest
  const headers = headersToRecord(new Headers(init.headers))
  if (body) headers['content-length'] = String(body.byteLength)

  return await new Promise<Response>((resolve, reject) => {
    const req = requestFn({
      protocol: target.protocol,
      hostname: host,
      port: target.port || undefined,
      path: `${target.pathname}${target.search}`,
      method: init.method ?? 'GET',
      headers,
      lookup: createPinnedLookup(host, options.addresses) as never,
      servername: target.protocol === 'https:' && !isIpLiteralHost(host) ? host : undefined,
    }, res => {
      const chunks: Buffer[] = []
      let total = 0
      let tooLarge = false
      res.on('data', (chunk: Buffer) => {
        total += chunk.byteLength
        if (total > MAX_PINNED_RESPONSE_BYTES) {
          tooLarge = true
          req.destroy(new Error('Credential response exceeded the size limit.'))
          return
        }
        chunks.push(chunk)
      })
      res.on('end', () => {
        if (tooLarge) return
        const status = res.statusCode ?? 0
        const responseBody = status === 204 || status === 304 ? null : Buffer.concat(chunks)
        resolve(new Response(responseBody, {
          status,
          statusText: res.statusMessage ?? '',
          headers: responseHeadersFromNode(res.headers),
        }))
      })
      res.on('error', reject)
    })
    req.setTimeout(options.timeoutMs, () => {
      req.destroy(new Error(`Login request timed out after ${options.timeoutMs}ms.`))
    })
    req.on('error', reject)
    const onAbort = () => req.destroy(options.signal?.reason instanceof Error ? options.signal.reason : new Error('Credential request aborted.'))
    if (options.signal?.aborted) onAbort()
    else options.signal?.addEventListener('abort', onAbort, { once: true })
    req.on('close', () => options.signal?.removeEventListener('abort', onAbort))
    if (body) req.write(body)
    req.end()
  })
}

let warnedEnvProxy = false
function warnIfEnvProxyEnabled(): void {
  if (warnedEnvProxy) return
  const setting = process.env.NODE_USE_ENV_PROXY
  if (!setting || setting === '0' || setting.toLowerCase() === 'false') return
  warnedEnvProxy = true
  console.warn(
    'WARNING: NODE_USE_ENV_PROXY is set. Credential flows are unsupported behind an environment proxy: ' +
    'the proxy re-resolves and egresses on Guardian\'s behalf, so pinned credential addresses cannot be guaranteed.',
  )
}

async function fetchWithTimeout(
  fetchImpl: typeof fetch,
  url: string,
  init: RequestInit,
  timeoutMs: number,
  outerSignal?: AbortSignal,
): Promise<Response> {
  const controller = new AbortController()
  const timer = setTimeout(() => controller.abort(new Error(`Login request timed out after ${timeoutMs}ms.`)), timeoutMs)
  const onOuterAbort = () => controller.abort(outerSignal?.reason)
  outerSignal?.addEventListener('abort', onOuterAbort, { once: true })
  try {
    // Credential-bearing requests must never replay across a redirect. Every caller (including
    // provider discovery) opts out of automatic redirect following and fails closed on 3xx.
    return await fetchImpl(url, { ...init, redirect: 'manual', signal: controller.signal })
  } finally {
    clearTimeout(timer)
    outerSignal?.removeEventListener('abort', onOuterAbort)
  }
}

function rejectUnexpectedRedirect(res: Response, label: string): void {
  if (res.status >= 300 && res.status < 400) {
    const location = res.headers.get('location') ?? ''
    throw new PersonaAuthError(
      'AUTH_FAILED',
      `${label} returned an unexpected ${res.status} redirect${location ? ` to ${location.slice(0, 200)}` : ''}; Guardian never replays credentials across redirects.`,
    )
  }
}

/**
 * A Clerk/IdP credential host must be named exactly: an allowlisted host, a host explicitly
 * configured by the operator (`config.loginUrl`), or `clerk.<registrable>` derived from an
 * allowlisted host whose apex is a real registrable domain (never a shared tenant suffix).
 */
export function isClerkCredentialHost(originOrHost: string, allowlist: readonly string[], operatorNamed?: string): boolean {
  let host: string
  try {
    host = normalizeHostname(new URL(originOrHost).hostname)
  } catch {
    host = normalizeHostname(originOrHost)
  }
  if (!host) return false
  const exact = allowedHostnames(allowlist)
  if (exact.includes(host)) return true
  if (operatorNamed) {
    try {
      if (normalizeHostname(new URL(operatorNamed).hostname) === host) return true
    } catch {
      // Ignore malformed operator input.
    }
  }
  if (!host.startsWith('clerk.')) return false
  const apex = host.slice('clerk.'.length)
  if (!registrableDomain(apex)) return false
  return exact.some(allowed => registrableDomain(allowed) === apex)
}

/**
 * Per-worker session clone pool with coordinated single-flight refresh.
 *
 * v6 replaces the v5 60 s per-persona global lockout with generation-based coordination:
 * - concurrent 401s from sibling clones join one upstream refresh (`inFlight`);
 * - a clone that saw an older generation is told "already fresh" and retries immediately;
 * - a clone logout/rotation is local to that clone and never cascades 401s to siblings;
 * - `rotate()` bumps the shared generation after an out-of-band rotation (logout probe,
 *   token swap) so sibling workers retry with the fresh credential instead of re-authenticating.
 */
export type PersonaSessionRefreshOutcome = 'refreshed' | 'already-fresh' | 'failed' | 'logged-out' | 'unknown'

export interface PersonaSessionRegistration {
  session: MintedPersonaSession
  allowlist: readonly string[]
  /** Upstream renewer (adapter refresh closure or full re-authentication). */
  refresh?: () => Promise<MintedPersonaSession | null>
}

export interface PersonaSessionClone {
  readonly id: string
  readonly handle: string
  /** Shared credential generation this clone has observed. */
  readonly generation: number
  isLoggedOut(): boolean
  /** Headers (incl. scoped `Cookie`) for one origin, or null when outside the allowlist. */
  headersFor(origin: string): Record<string, string> | null
  storageFor(origin: string): PersonaStorageSnapshot | null
  cookiesFor(origin: string): PersonaCookieRecord[]
  /** Rotate this clone's cookie jar only (a logout/token-swap probe never touches siblings). */
  applySetCookie(origin: string, setCookieLines: readonly string[]): void
  /** Report a 401 from this clone; deduped across siblings into one upstream refresh. */
  reportUnauthorized(observedGeneration?: number): Promise<PersonaSessionRefreshOutcome>
  /** Drop this clone's credentials without invalidating the shared session. */
  logout(): void
  dispose(): void
}

interface PersonaSessionPoolEntry {
  handle: string
  session: MintedPersonaSession
  allowlist: string[]
  generation: number
  refresh?: () => Promise<MintedPersonaSession | null>
  inFlight?: Promise<PersonaSessionRefreshOutcome>
  refreshCount: number
  clones: Set<PersonaSessionCloneImpl>
}

function mergeBundleCookies(
  bundle: PersonaCredentialBundle | undefined,
  cookies: readonly PersonaCookieRecord[],
): PersonaCredentialBundle | undefined {
  const merged = new Map<string, PersonaCookieRecord>()
  const add = (cookie: PersonaCookieRecord) => {
    merged.set(`${cookie.name}\0${cookie.domain}\0${cookie.path}`, cookie)
  }
  for (const cookie of bundle?.cookies ?? []) add(cookie)
  for (const cookie of cookies) add(cookie)
  const all = [...merged.values()]
  if (!bundle && !all.length) return undefined
  return {
    ...(bundle ?? {}),
    v: 2,
    ...(all.length ? { cookies: all } : {}),
  }
}

function parseSetCookieLine(line: string, origin: URL): PersonaCookieRecord | null {
  const parts = line.split(';')
  const first = parts[0]?.trim() ?? ''
  const eq = first.indexOf('=')
  if (eq <= 0) return null
  const name = first.slice(0, eq).trim()
  const value = first.slice(eq + 1).trim()
  if (!name || !value) return null
  let domain = origin.hostname
  let path = '/'
  let httpOnly: boolean | undefined
  let secure: boolean | undefined
  let sameSite: PersonaCookieRecord['sameSite']
  let expires: number | undefined
  for (const attr of parts.slice(1)) {
    const [rawKey, ...rest] = attr.split('=')
    const key = rawKey.trim().toLowerCase()
    const val = rest.join('=').trim()
    if (key === 'domain' && val) domain = val.replace(/^\.+/, '')
    else if (key === 'path' && val.startsWith('/')) path = val
    else if (key === 'httponly') httpOnly = true
    else if (key === 'secure') secure = true
    else if (key === 'samesite') {
      const normalized = val.toLowerCase()
      if (normalized === 'strict') sameSite = 'Strict'
      else if (normalized === 'lax') sameSite = 'Lax'
      else if (normalized === 'none') sameSite = 'None'
    } else if (key === 'max-age') {
      const secs = Number(val)
      if (Number.isFinite(secs) && secs >= 0) expires = Date.now() + secs * 1000
    } else if (key === 'expires') {
      const at = Date.parse(val)
      if (Number.isFinite(at)) expires = at
    }
  }
  return {
    name,
    value,
    domain,
    path,
    ...(httpOnly ? { httpOnly } : {}),
    ...(secure ? { secure } : {}),
    ...(sameSite ? { sameSite } : {}),
    ...(expires ? { expires } : {}),
  }
}

export class PersonaSessionCloneImpl implements PersonaSessionClone {
  readonly id: string
  readonly handle: string
  private loggedOut = false
  private localCookies: PersonaCookieRecord[] = []
  private seenGeneration: number
  private readonly entry: PersonaSessionPoolEntry

  constructor(handle: string, entry: PersonaSessionPoolEntry, id?: string) {
    this.id = id ?? `clone-${handle}-${Math.random().toString(36).slice(2, 10)}`
    this.handle = handle
    this.entry = entry
    this.seenGeneration = entry.generation
    entry.clones.add(this)
  }

  get generation(): number { return this.seenGeneration }

  isLoggedOut(): boolean { return this.loggedOut }

  private view(): MintedPersonaSession {
    if (!this.localCookies.length) return this.entry.session
    return {
      ...this.entry.session,
      bundle: mergeBundleCookies(this.entry.session.bundle, this.localCookies),
    }
  }

  headersFor(origin: string): Record<string, string> | null {
    if (this.loggedOut) return null
    const frame = frameForSessionOrigin(this.view(), this.entry.allowlist, origin, this.entry.session.headerName)
    if (!frame || !Object.keys(frame.headers).length) return null
    return frame.headers
  }

  storageFor(origin: string): PersonaStorageSnapshot | null {
    if (this.loggedOut) return null
    return frameForSessionOrigin(this.view(), this.entry.allowlist, origin, this.entry.session.headerName)?.storage ?? null
  }

  cookiesFor(origin: string): PersonaCookieRecord[] {
    if (this.loggedOut) return []
    return frameForSessionOrigin(this.view(), this.entry.allowlist, origin, this.entry.session.headerName)?.cookies ?? []
  }

  applySetCookie(origin: string, setCookieLines: readonly string[]): void {
    if (this.loggedOut) return
    let parsedOrigin: URL
    try { parsedOrigin = new URL(origin) } catch { return }
    const next: PersonaCookieRecord[] = []
    for (const line of setCookieLines) {
      const cookie = parseSetCookieLine(line, parsedOrigin)
      if (cookie) next.push(cookie)
    }
    if (!next.length) return
    this.localCookies = [...this.localCookies.filter(existing =>
      !next.some(cookie => cookie.name === existing.name && cookie.domain === existing.domain && cookie.path === existing.path),
    ), ...next]
  }

  async reportUnauthorized(observedGeneration?: number): Promise<PersonaSessionRefreshOutcome> {
    if (this.loggedOut) return 'logged-out'
    const observed = observedGeneration ?? this.seenGeneration
    const outcome = await this.entryPoolRefresh(observed)
    if (outcome === 'refreshed' || outcome === 'already-fresh') this.seenGeneration = this.entry.generation
    return outcome
  }

  private entryPoolRefresh(observed: number): Promise<PersonaSessionRefreshOutcome> {
    // The pool owns the single-flight promise; this indirection keeps the clone bound to its entry.
    return PersonaSessionPool.refreshEntry(this.entry, observed)
  }

  logout(): void {
    this.loggedOut = true
    this.localCookies = []
    this.entry.clones.delete(this)
  }

  dispose(): void {
    this.entry.clones.delete(this)
  }
}

export class PersonaSessionPool {
  private readonly entries = new Map<string, PersonaSessionPoolEntry>()

  register(handle: string, registration: PersonaSessionRegistration): void {
    const existing = this.entries.get(handle)
    if (existing) {
      existing.session = registration.session
      existing.allowlist = [...registration.allowlist]
      if (registration.refresh) existing.refresh = registration.refresh
      existing.generation += 1
      return
    }
    this.entries.set(handle, {
      handle,
      session: registration.session,
      allowlist: [...registration.allowlist],
      generation: 1,
      ...(registration.refresh ? { refresh: registration.refresh } : {}),
      refreshCount: 0,
      clones: new Set(),
    })
  }

  unregister(handle: string): void {
    const entry = this.entries.get(handle)
    if (!entry) return
    for (const clone of entry.clones) clone.dispose()
    this.entries.delete(handle)
  }

  has(handle: string): boolean { return this.entries.has(handle) }

  generation(handle: string): number { return this.entries.get(handle)?.generation ?? 0 }

  session(handle: string): MintedPersonaSession | null { return this.entries.get(handle)?.session ?? null }

  refreshCount(handle: string): number { return this.entries.get(handle)?.refreshCount ?? 0 }

  clone(handle: string, id?: string): PersonaSessionClone | null {
    const entry = this.entries.get(handle)
    if (!entry) return null
    return new PersonaSessionCloneImpl(handle, entry, id)
  }

  /** Log out one tracked clone; siblings and the shared credential are untouched. */
  logoutClone(handle: string, cloneId: string): boolean {
    const entry = this.entries.get(handle)
    if (!entry) return false
    for (const clone of entry.clones) {
      if (clone.id === cloneId) {
        clone.logout()
        return true
      }
    }
    return false
  }

  /** Replace the shared credential without an upstream call (logout probe / token swap). */
  rotate(handle: string, session: MintedPersonaSession): number | null {
    const entry = this.entries.get(handle)
    if (!entry) return null
    entry.session = session
    entry.generation += 1
    return entry.generation
  }

  async refresh(handle: string, observedGeneration?: number): Promise<PersonaSessionRefreshOutcome> {
    const entry = this.entries.get(handle)
    if (!entry) return 'unknown'
    return PersonaSessionPool.refreshEntry(entry, observedGeneration)
  }

  static async refreshEntry(
    entry: PersonaSessionPoolEntry,
    observedGeneration?: number,
  ): Promise<PersonaSessionRefreshOutcome> {
    if (observedGeneration !== undefined && entry.generation > observedGeneration) return 'already-fresh'
    if (!entry.refresh) return entry.inFlight ? await entry.inFlight : 'unknown'
    if (entry.inFlight) return entry.inFlight
    const run = (async (): Promise<PersonaSessionRefreshOutcome> => {
      try {
        const next = await entry.refresh!()
        if (!next) return 'failed'
        entry.session = next
        entry.generation += 1
        entry.refreshCount += 1
        return 'refreshed'
      } catch {
        return 'failed'
      } finally {
        entry.inFlight = undefined
      }
    })()
    entry.inFlight = run
    return run
  }
}

export class PersonaAuthManager {
  private readonly fetchImpl: typeof fetch
  private readonly fetchImplInjected: boolean
  private readonly resolveHostInjected: boolean
  private readonly launchBrowser: (pinnedHosts?: ReadonlyMap<string, readonly string[]>) => Promise<PlaywrightFormBrowserLike>
  private readonly timeoutMs: number
  private readonly reauthMinIntervalMs: number
  private readonly resolveHost: (hostname: string) => Promise<string[]>
  private readonly hostSafety = new Map<string, { at: number; addresses: string[]; safe: boolean }>()
  private readonly runTimers = new Map<string, NodeJS.Timeout[]>()
  private readonly reauthHandlers = new Map<string, { fn: () => Promise<void>; lastAt: number; inFlight?: Promise<boolean> }>()
  private readonly sessionPool = new PersonaSessionPool()

  constructor(options: PersonaAuthManagerOptions = {}) {
    this.fetchImplInjected = Boolean(options.fetchImpl)
    this.resolveHostInjected = Boolean(options.resolveHost)
    this.fetchImpl = options.fetchImpl ?? globalThis.fetch.bind(globalThis)
    this.launchBrowser = options.launchBrowser ?? launchDefaultChromium
    this.timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS
    // Legacy pacing for raw registerReauth() handlers only. Session clones (the product path)
    // never use a time-based lockout; they coordinate through PersonaSessionPool generations.
    this.reauthMinIntervalMs = Math.max(1_000, options.reauthMinIntervalMs ?? 60_000)
    this.resolveHost = options.resolveHost ?? (async hostname => {
      const bare = hostname.replace(/^\[|\]$/g, '')
      if (isIpLiteralHost(bare)) return [bare]
      // `localhost` is a name; resolve it to the loopback literals so the pinned lookup has
      // real addresses instead of passing the name through as if it were an IP.
      if (bare.toLowerCase() === 'localhost') return ['127.0.0.1', '::1']
      try {
        const addresses = await lookup(hostname, { all: true, order: 'verbatim' })
        return addresses.map(entry => entry.address)
      } catch {
        // Empty resolution is refused by assertCredentialTarget: NXDOMAIN at check time
        // must never be re-resolved into a private address at connect time.
        return []
      }
    })
  }

  /**
   * Credential transport. The default path pins the validated addresses with a custom lookup
   * so the connection cannot be re-resolved; an injected `fetchImpl` (tests/embedders) keeps
   * the existing fetch contract and is expected to enforce pinning itself.
   */
  private async credentialFetch(
    url: string,
    init: RequestInit,
    pinnedAddresses: readonly string[] | null,
    signal?: AbortSignal,
    timeoutMs = this.timeoutMs,
  ): Promise<Response> {
    warnIfEnvProxyEnabled()
    if (this.fetchImplInjected || !pinnedAddresses) {
      return await fetchWithTimeout(this.fetchImpl, url, init, timeoutMs, signal)
    }
    return await pinnedFetch(url, init, { addresses: pinnedAddresses, timeoutMs, signal })
  }

  private async inspectTargetOrigin(
    targetOrigin: string,
    allowlist: readonly string[],
    signal?: AbortSignal,
  ): Promise<{ html: string; headers: Headers; clerkFapiOrigin: string | null; hasClerk: boolean }> {
    try {
      const target = await this.assertCredentialTarget(targetOrigin, allowlist, 'Target origin')
      // No redirects while discovering provider configuration: a redirect target must never decide
      // which Clerk/IdP host receives credentials.
      const res = await this.credentialFetch(
        targetOrigin,
        { method: 'GET', headers: { Accept: 'text/html,application/xhtml+xml,*/*' }, redirect: 'manual' },
        target.addresses,
        signal,
        Math.min(this.timeoutMs, 8_000),
      )
      if (res.status >= 300 && res.status < 400) {
        return { html: '', headers: res.headers, clerkFapiOrigin: null, hasClerk: false }
      }
      const html = (await res.text()).slice(0, 250_000)
      let clerkFapiOrigin: string | null = null
      const pkMatch = /\b(pk_(?:live|test)_[A-Za-z0-9+/=_-]{12,})\b/.exec(html)
      if (pkMatch) {
        const decoded = decodeClerkPublishableKey(pkMatch[1])
        // A target document can contain an attacker-controlled publishable key; only a Clerk host
        // bound to an allowlisted host may become the credential destination. Registrable-domain
        // siblings are NOT sufficient on shared suffixes (github.io, vercel.app, ...).
        if (decoded && isClerkCredentialHost(decoded, allowlist)) clerkFapiOrigin = decoded
      }
      if (!clerkFapiOrigin) {
        const fapiMatch = /https:\/\/(clerk\.[a-z0-9.-]+\.[a-z]{2,})/i.exec(html)
        if (fapiMatch && isClerkCredentialHost(`https://${fapiMatch[1]}`, allowlist)) {
          clerkFapiOrigin = `https://${fapiMatch[1].toLowerCase()}`
        }
      }
      const hasClerkHeader = Boolean(
        res.headers.get('x-clerk-auth-status') ||
        res.headers.get('x-clerk-auth-reason') ||
        res.headers.get('x-clerk-auth-signature'),
      )
      const hasClerk = Boolean(
        clerkFapiOrigin ||
        hasClerkHeader ||
        /data-clerk-publishable-key|@clerk\/|clerk-js|__clerk_db_jwt/i.test(html),
      )
      return { html, headers: res.headers, clerkFapiOrigin, hasClerk }
    } catch {
      return { html: '', headers: new Headers(), clerkFapiOrigin: null, hasClerk: false }
    }
  }

  /**
   * Validate a credential destination and return the addresses the connection must use.
   *
   * - hostname must be inside the persona allowlist scope;
   * - the host must be a registrable-domain host (or IP literal): shared/private suffixes
   *   (`github.io`, `vercel.app`, `s3.amazonaws.com`, `com.co`, …) and opaque single-label
   *   hosts can never anchor a credential scope;
   * - the scheme must be HTTPS (HTTP only for an explicitly allowlisted loopback lab);
   * - resolution must be non-empty and every address public (loopback only for the exact
   *   allowlisted origin). The returned list is the *only* address set the transport uses.
   *
   * `requireResolution: false` is used for the form browser, whose Chromium resolver rules
   * pin the validated hosts and fail closed (`MAP * ~NOTFOUND`) for everything else; an
   * unresolvable login host simply never connects.
   */
  private async assertCredentialTarget(
    rawUrl: string,
    allowlist: readonly string[],
    label: string,
    options: { requireResolution?: boolean } = {},
  ): Promise<{ url: URL; addresses: string[] }> {
    let parsed: URL
    try {
      parsed = new URL(rawUrl)
    } catch {
      throw new PersonaAuthError('AUTH_FAILED', `${label} is not a valid URL.`)
    }
    if (parsed.protocol !== 'https:' && parsed.protocol !== 'http:') {
      throw new PersonaAuthError('AUTH_FAILED', `${label} must use HTTPS.`)
    }
    if (parsed.username || parsed.password) {
      throw new PersonaAuthError('AUTH_FAILED', `${label} must not contain URL credentials.`)
    }
    const originAllowed = isOriginInScope(parsed.origin, allowlist)
      || allowlist.some(entry => {
        try { return new URL(entry).origin === parsed.origin } catch { return false }
      })
    if (!originAllowed) {
      throw new PersonaAuthError('AUTH_FAILED', `${label} host ${parsed.hostname} is outside the persona origin allowlist.`)
    }
    const loopback = isLoopbackLiteral(parsed.hostname)
    if (parsed.protocol === 'http:' && !loopback) {
      throw new PersonaAuthError('AUTH_FAILED', `${label} must use HTTPS; credentials are never sent over plaintext HTTP.`)
    }
    const exactAllowlisted = allowlist.some(entry => {
      try { return new URL(entry).origin === parsed.origin } catch { return false }
    })
    if (loopback && !exactAllowlisted) {
      throw new PersonaAuthError('AUTH_FAILED', `${label} points at loopback without an explicit allowlist entry.`)
    }
    // A shared platform/private suffix (or a bare single label) is not a security boundary:
    // every sibling tenant would otherwise be in scope.
    if (!loopback && !isCredentialScopeHost(parsed.hostname)) {
      throw new PersonaAuthError(
        'AUTH_FAILED',
        `${label} host ${parsed.hostname} is a shared public/private suffix or an opaque single-label host and cannot anchor a credential scope.`,
      )
    }
    // An injected transport without an injected resolver is an embedding/test seam: Guardian
    // cannot observe or pin that transport's DNS, so resolution is the injector's contract.
    // Production (default fetch) always resolves and pins.
    if (options.requireResolution === false || (this.fetchImplInjected && !this.resolveHostInjected)) {
      return { url: parsed, addresses: [] }
    }
    const addresses = await this.resolveHost(parsed.hostname)
    if (addresses.length === 0) {
      throw new PersonaAuthError(
        'AUTH_FAILED',
        `${label} host ${parsed.hostname} did not resolve; refusing to connect (no re-resolution at connect time).`,
      )
    }
    for (const address of addresses) {
      const kind = classifyAddress(address)
      if (kind === 'blocked' || (kind === 'loopback' && !exactAllowlisted)) {
        throw new PersonaAuthError('AUTH_FAILED', `${label} host ${parsed.hostname} resolves to a private, loopback, or metadata address.`)
      }
    }
    return { url: parsed, addresses }
  }

  /**
   * Re-check a browser request origin immediately before Chromium is allowed to connect.
   * Empty/unknown resolution is NOT safe (the old `unknown -> safe` branch allowed an
   * NXDOMAIN-then-rebind answer), and the verdict cache is short-lived (5 s) and stores the
   * resolved address set so a rebind between checks is visible.
   */
  private async browserHostSafety(
    origin: string,
    allowlist: readonly string[],
  ): Promise<{ safe: boolean; addresses: string[] }> {
    let host: string
    try {
      host = normalizeHostname(new URL(origin).hostname)
    } catch {
      return { safe: false, addresses: [] }
    }
    if (!host) return { safe: false, addresses: [] }
    const cached = this.hostSafety.get(host)
    if (cached && Date.now() - cached.at < 5_000) {
      return { safe: cached.safe, addresses: cached.addresses }
    }
    const addresses = (await this.resolveHost(host)).map(address => address.replace(/^\[|\]$/g, ''))
    const exactAllowlisted = allowlist.some(entry => {
      try { return normalizeHostname(new URL(entry).hostname) === host } catch { return false }
    })
    const kinds = addresses.map(address => classifyAddress(address))
    const safe = addresses.length > 0 && kinds.every(kind => kind === 'public' || (kind === 'loopback' && exactAllowlisted))
    this.hostSafety.set(host, { at: Date.now(), addresses, safe })
    return { safe, addresses }
  }

  /** Shared per-run/persona session clones. Seeded by startRunRefreshers()/registerSession(). */
  get sessions(): PersonaSessionPool { return this.sessionPool }

  /**
   * Register a raw 401 re-authentication callback for a persona handle.
   *
   * Kept for embedders/tests that do not use the session pool. These raw handlers retain the
   * legacy per-handle pacing; personas registered through `registerSession()` use coordinated
   * single-flight refresh with no global 60 s lockout.
   */
  registerReauth(handle: string, fn: () => Promise<void>): () => void {
    this.reauthHandlers.set(handle, { fn, lastAt: 0 })
    return () => {
      const current = this.reauthHandlers.get(handle)
      if (current?.fn === fn) this.reauthHandlers.delete(handle)
    }
  }

  /**
   * Register a persona's composite session for clone/refresh coordination.
   * `refresh` runs at most once for concurrent 401s across every clone of the handle.
   */
  registerSession(handle: string, registration: PersonaSessionRegistration): void {
    this.sessionPool.register(handle, registration)
  }

  /** Create an independent per-worker session clone (credentials shared, cookie jar local). */
  cloneSession(handle: string, workerId?: string): PersonaSessionClone | null {
    return this.sessionPool.clone(handle, workerId)
  }

  /** Log out one worker clone without invalidating siblings or the shared credential. */
  logoutSession(handle: string, cloneId: string): boolean {
    return this.sessionPool.logoutClone(handle, cloneId)
  }

  /**
   * Invoked by RequestBroker on a persona-bound 401. Returns true when a session refresh ran
   * (or a sibling already refreshed this generation, in which case the caller retries with the
   * fresh credential). Pool-backed personas never use the 60 s lockout.
   */
  async requestReauth(handle: string, observedGeneration?: number): Promise<boolean> {
    if (this.sessionPool.has(handle)) {
      const outcome = await this.sessionPool.refresh(handle, observedGeneration)
      return outcome === 'refreshed' || outcome === 'already-fresh'
    }
    const entry = this.reauthHandlers.get(handle)
    if (!entry) return false
    if (entry.inFlight) return entry.inFlight
    const now = Date.now()
    if (now - entry.lastAt < this.reauthMinIntervalMs) return false
    entry.lastAt = now
    const run = (async () => {
      try {
        await entry.fn()
        return true
      } catch {
        return false
      } finally {
        entry.inFlight = undefined
      }
    })()
    entry.inFlight = run
    return run
  }


  /** Import operator-captured session state (Playwright storageState or HAR) for MFA-hardened apps. */
  async importSession(
    storage: Store,
    projectId: string,
    personaId: string,
    input: unknown,
    format: 'storage-state' | 'har' | 'auto' = 'auto',
  ): Promise<AuthenticateResult> {
    const resolved = resolveRunPersonas(storage, projectId, [personaId])
    const persona = [...resolved.values()][0]
    if (!persona) throw new PersonaAuthError('AUTH_FAILED', 'Persona not found.')
    if (persona.authKind !== 'login' || !persona.sessionPath) {
      throw new PersonaAuthError('UNSUPPORTED_ADAPTER', `Persona "${persona.handle}" is not a login persona.`)
    }
    const looksLikeHar = Boolean(input && typeof input === 'object' && 'log' in (input as Record<string, unknown>))
    const resolvedFormat = format === 'auto' ? (looksLikeHar ? 'har' : 'storage-state') : format
    const imported = resolvedFormat === 'har'
      ? importHar(input, persona.originAllowlist)
      : importStorageState(input, persona.originAllowlist)
    const session: MintedPersonaSession = {
      ...imported.session,
      adapterUsed: 'import',
      scrubTokens: [...new Set([...(imported.session.scrubTokens ?? []), ...(persona.secretHistory ?? [])])],
    }
    writePersonaSessionFile(persona.sessionPath, session)
    return {
      personaId: persona.id,
      handle: persona.handle,
      adapterUsed: 'import',
      headerType: session.headerType,
      ...(session.expiresAt ? { expiresAt: session.expiresAt } : {}),
      session,
    }
  }

  async authenticatePersona(
    storage: Store,
    projectId: string,
    personaId: string,
    signal?: AbortSignal,
  ): Promise<AuthenticateResult> {
    const resolved = resolveRunPersonas(storage, projectId, [personaId])
    const persona = [...resolved.values()][0]
    if (!persona) throw new PersonaAuthError('AUTH_FAILED', 'Persona not found.')
    if (persona.authKind !== 'login') {
      throw new PersonaAuthError('UNSUPPORTED_ADAPTER', `Persona "${persona.handle}" uses static ${persona.authKind} auth, not email+password login.`)
    }
    if (!persona.secretPath || !persona.sessionPath || !persona.loginConfig) {
      throw new PersonaAuthError('AUTH_FAILED', `Persona "${persona.handle}" is missing login configuration or credential file.`)
    }

    const { email, password } = readLoginCredentialFile(persona.secretPath)
    const targetOrigin = persona.originAllowlist[0]
    if (!targetOrigin) {
      throw new PersonaAuthError('AUTH_FAILED', `Persona "${persona.handle}" has no allowlisted origin configured.`)
    }

    const config = persona.loginConfig
    let adapter: Exclude<PersonaLoginAdapter, 'auto'> | 'oidc'
    let detectedClerkFapiOrigin: string | null = null

    const crossOriginAuthUrl = (() => {
      if (!config.loginUrl) return false
      try {
        const loginOrigin = new URL(config.loginUrl).origin
        return loginOrigin !== targetOrigin && isOriginInScope(loginOrigin, persona.originAllowlist)
      } catch {
        return false
      }
    })()

    if ((config.adapter as string) === 'oidc') {
      adapter = 'oidc'
    } else if (config.adapter === 'auto') {
      const inspected = await this.inspectTargetOrigin(targetOrigin, persona.originAllowlist, signal)
      if (crossOriginAuthUrl) {
        // An allowlisted external login URL is an SSO/IdP hop, not the app's own form.
        adapter = 'oidc'
      } else if (inspected.hasClerk) {
        adapter = 'clerk'
        detectedClerkFapiOrigin = inspected.clerkFapiOrigin
      } else if (config.loginUrl && /\/auth\/v1\/token\b/i.test(config.loginUrl)) {
        adapter = 'supabase'
      } else if (config.loginUrl && /\/api\//i.test(config.loginUrl)) {
        adapter = 'json'
      } else if (/data-guardian-sso|authorize\?client_id|\/oauth2\/|\/oidc\/|single sign-on/i.test(inspected.html)) {
        adapter = 'oidc'
      } else {
        adapter = 'form'
      }
    } else {
      adapter = config.adapter
    }

    switch (adapter) {
      case 'oidc':
        return await this.authenticateOidc(persona, config, email, password, targetOrigin, signal)
      case 'clerk':
        return await this.authenticateClerk(persona, config, email, password, targetOrigin, detectedClerkFapiOrigin, signal)
      case 'supabase':
        return await this.authenticateSupabase(persona, config, email, password, targetOrigin, signal)
      case 'json':
        return await this.authenticateJson(persona, config, email, password, targetOrigin, signal)
      case 'form':
        return await this.authenticateForm(persona, config, email, password, targetOrigin)
    }
  }

  private async resolveClerkFapiOrigin(
    persona: ResolvedPersona,
    config: PersonaLoginConfig,
    targetOrigin: string,
    detectedFapiOrigin: string | null,
    signal?: AbortSignal,
  ): Promise<string> {
    const allowlist = persona.originAllowlist
    if (config.loginUrl) {
      const parsed = new URL(config.loginUrl)
      // If operator supplied a Clerk FAPI URL (e.g. https://clerk.dyad.sh), use its origin directly.
      // If it matches targetOrigin with a page path, still inspect HTML first. Either way the host
      // must be named explicitly (exact allowlist host, derived clerk.<apex>, or this operator URL).
      if (!isClerkCredentialHost(parsed.origin, allowlist, config.loginUrl)) {
        throw new PersonaAuthError('AUTH_FAILED', `Clerk login URL host ${parsed.hostname} is outside the persona origin allowlist.`)
      }
      if (parsed.origin !== targetOrigin || /^clerk\./i.test(parsed.hostname) || parsed.pathname.includes('/v1/client')) {
        return parsed.origin
      }
    }
    if (detectedFapiOrigin && isClerkCredentialHost(detectedFapiOrigin, allowlist, config.loginUrl)) return detectedFapiOrigin
    const inspected = await this.inspectTargetOrigin(targetOrigin, allowlist, signal)
    if (inspected.clerkFapiOrigin) return inspected.clerkFapiOrigin
    // Only the target origin's registrable domain may host its Clerk instance, and only when the
    // apex is a real registrable domain — never a shared tenant suffix (github.io, vercel.app…)
    // and never a bare last-two-label host (the old `co.uk` bug).
    const targetHost = new URL(targetOrigin).hostname
    if (!isCredentialScopeHost(targetHost)) {
      throw new PersonaAuthError(
        'AUTH_FAILED',
        `Cannot derive a Clerk Frontend API host for ${targetOrigin}: the host is a shared public/private suffix. Configure an explicit Clerk login URL.`,
      )
    }
    const registrable = registrableDomain(targetHost)
    if (!registrable) {
      throw new PersonaAuthError(
        'AUTH_FAILED',
        `Cannot derive a Clerk Frontend API host for ${targetOrigin}; configure an explicit Clerk login URL inside the persona allowlist.`,
      )
    }
    const derived = `https://clerk.${registrable}`
    if (!isClerkCredentialHost(derived, allowlist, config.loginUrl)) {
      throw new PersonaAuthError('AUTH_FAILED', `Derived Clerk host ${derived} is outside the persona origin allowlist.`)
    }
    return derived
  }

  private async authenticateClerk(
    persona: ResolvedPersona,
    config: PersonaLoginConfig,
    email: string,
    password: string,
    targetOrigin: string,
    detectedClerkFapiOrigin: string | null,
    signal?: AbortSignal,
  ): Promise<AuthenticateResult> {
    const fapiOrigin = await this.resolveClerkFapiOrigin(persona, config, targetOrigin, detectedClerkFapiOrigin, signal)
    const signInUrl = `${fapiOrigin}/v1/client/sign_ins`
    const signInTarget = await this.assertCredentialTarget(signInUrl, persona.originAllowlist, 'Clerk sign-in URL')
    const form = new URLSearchParams({
      identifier: email,
      password,
      strategy: 'password',
    })

    const res = await this.credentialFetch(
      signInUrl,
      {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          Accept: 'application/json',
          Origin: targetOrigin,
        },
        body: form.toString(),
      },
      signInTarget.addresses,
      signal,
    )

    const rawText = await res.text()
    rejectUnexpectedRedirect(res, 'Clerk sign-in')
    let body: Record<string, unknown> = {}
    try {
      body = rawText ? (JSON.parse(rawText) as Record<string, unknown>) : {}
    } catch {
      // Non-JSON response checked below
    }

    // Strict CAPTCHA / Turnstile / MFA detection
    checkResponseForCaptchaOrMfa(rawText, fapiOrigin, email)
    const errors = Array.isArray(body.errors) ? (body.errors as Array<Record<string, unknown>>) : []
    for (const errObj of errors) {
      const joined = `${String(errObj.code ?? '')} ${String(errObj.message ?? '')} ${String(errObj.long_message ?? '')}`
      checkResponseForCaptchaOrMfa(joined, fapiOrigin, email)
    }

    const respObj = (body.response && typeof body.response === 'object')
      ? (body.response as Record<string, unknown>)
      : {}
    const statusStr = typeof respObj.status === 'string' ? respObj.status : ''
    if (statusStr === 'needs_second_factor') {
      throw new PersonaAuthError('MFA_REQUIRED', mfaAbortMessage(email))
    }

    if (!res.ok || errors.length > 0) {
      const firstErr = errors[0]
      const errMsg = String(firstErr?.long_message || firstErr?.message || firstErr?.code || `HTTP ${res.status}`)
      const isCred = res.status === 401 || res.status === 422 || /password|identifier|credential|not_found/i.test(errMsg)
      throw new PersonaAuthError(
        isCred ? 'INVALID_CREDENTIALS' : 'AUTH_FAILED',
        `Clerk sign-in failed (${res.status}): ${sanitizeErrorText(errMsg, [password])}`,
      )
    }

    const cookies = extractSetCookies(res.headers)
    let clientCookie = cookies.get('__client') ?? ''
    const authHeaderToken = res.headers.get('authorization') ?? ''

    const clientObj = (body.client && typeof body.client === 'object')
      ? (body.client as Record<string, unknown>)
      : {}
    const sessions = Array.isArray(clientObj.sessions)
      ? (clientObj.sessions as Array<Record<string, unknown>>)
      : []

    const sessionId =
      (typeof respObj.created_session_id === 'string' && respObj.created_session_id) ||
      (typeof clientObj.last_active_session_id === 'string' && clientObj.last_active_session_id) ||
      (typeof sessions[0]?.id === 'string' ? (sessions[0].id as string) : '')

    const matchingSession = sessions.find(s => s.id === sessionId) ?? sessions[0]
    const lastActiveToken = (matchingSession?.last_active_token && typeof matchingSession.last_active_token === 'object')
      ? (matchingSession.last_active_token as Record<string, unknown>)
      : undefined
    const createdToken = (respObj.created_session_token && typeof respObj.created_session_token === 'object')
      ? (respObj.created_session_token as Record<string, unknown>)
      : undefined

    let jwt =
      (typeof lastActiveToken?.jwt === 'string' && lastActiveToken.jwt) ||
      (typeof createdToken?.jwt === 'string' && createdToken.jwt) ||
      (typeof body.jwt === 'string' && body.jwt) ||
      cookies.get('__session') ||
      ''

    const mintFreshToken = async (): Promise<{ jwt: string; expiresAt: number }> => {
      if (!sessionId) {
        throw new PersonaAuthError('AUTH_FAILED', 'Clerk sign-in did not return a session ID for token refresh.')
      }
      const tokenHeaders: Record<string, string> = {
        Accept: 'application/json',
        Origin: targetOrigin,
      }
      if (clientCookie) tokenHeaders.Cookie = `__client=${clientCookie}`
      else if (authHeaderToken) tokenHeaders.Authorization = authHeaderToken

      const tokenUrl = `${fapiOrigin}/v1/client/sessions/${encodeURIComponent(sessionId)}/tokens`
      const tokenTarget = await this.assertCredentialTarget(tokenUrl, persona.originAllowlist, 'Clerk token URL')
      const tokRes = await this.credentialFetch(
        tokenUrl,
        { method: 'POST', headers: tokenHeaders },
        tokenTarget.addresses,
      )
      const tokText = await tokRes.text()
      rejectUnexpectedRedirect(tokRes, 'Clerk token refresh')
      checkResponseForCaptchaOrMfa(tokText, fapiOrigin, email)
      if (!tokRes.ok) {
        throw new PersonaAuthError('AUTH_FAILED', `Clerk token refresh failed (${tokRes.status}): ${sanitizeErrorText(tokText, [password, clientCookie, jwt])}`)
      }
      let tokJson: Record<string, unknown> = {}
      try {
        tokJson = tokText ? (JSON.parse(tokText) as Record<string, unknown>) : {}
      } catch {
        throw new PersonaAuthError('AUTH_FAILED', 'Clerk token refresh returned non-JSON response.')
      }
      const rotatedCookies = extractSetCookies(tokRes.headers)
      const rotatedClient = rotatedCookies.get('__client')
      if (rotatedClient) clientCookie = rotatedClient

      const freshJwt = typeof tokJson.jwt === 'string' ? tokJson.jwt : ''
      if (!freshJwt) {
        throw new PersonaAuthError('AUTH_FAILED', 'Clerk token refresh response did not contain a JWT.')
      }
      const claims = decodeJwtPayload(freshJwt)
      const iat = claims?.iat ?? Math.floor(Date.now() / 1000)
      const expiresAt = claims?.exp ? claims.exp * 1000 : Date.now() + 55_000
      const cookieHeader = `__session=${freshJwt}; __client_uat=${iat}`
      const scrubTokens = [freshJwt, clientCookie, rotatedClient ?? '', authHeaderToken].filter(Boolean)
      writePersonaSessionFile(persona.sessionPath!, {
        headerType: 'cookie',
        value: cookieHeader,
        expiresAt,
        adapterUsed: 'clerk',
        scrubTokens,
      })
      jwt = freshJwt
      return { jwt: freshJwt, expiresAt }
    }

    let expiresAt: number
    if (!jwt) {
      if (!sessionId || (!clientCookie && !authHeaderToken)) {
        throw new PersonaAuthError(
          'AUTH_FAILED',
          `Clerk sign-in succeeded (status=${statusStr || 'unknown'}) but returned no __session JWT or refreshable __client session.`,
        )
      }
      const minted = await mintFreshToken()
      jwt = minted.jwt
      expiresAt = minted.expiresAt
    } else {
      const claims = decodeJwtPayload(jwt)
      const iat = claims?.iat ?? Math.floor(Date.now() / 1000)
      expiresAt = claims?.exp ? claims.exp * 1000 : Date.now() + 55_000
      const cookieHeader = `__session=${jwt}; __client_uat=${iat}`
      const scrubTokens = [jwt, clientCookie, authHeaderToken].filter(Boolean)
      writePersonaSessionFile(persona.sessionPath!, {
        headerType: 'cookie',
        value: cookieHeader,
        expiresAt,
        adapterUsed: 'clerk',
        scrubTokens,
      })
    }

    const refreshIntervalSec = config.refreshIntervalSec ?? DEFAULT_CLERK_REFRESH_SEC
    const canRefresh = Boolean(sessionId && (clientCookie || authHeaderToken))
    return {
      personaId: persona.id,
      handle: persona.handle,
      adapterUsed: 'clerk',
      headerType: 'cookie',
      expiresAt,
      refreshIntervalSec: canRefresh ? refreshIntervalSec : undefined,
      refresh: canRefresh ? async () => { await mintFreshToken() } : undefined,
    }
  }

  private async authenticateSupabase(
    persona: ResolvedPersona,
    config: PersonaLoginConfig,
    email: string,
    password: string,
    targetOrigin: string,
    signal?: AbortSignal,
  ): Promise<AuthenticateResult> {
    const loginUrl = config.loginUrl || `${targetOrigin}/auth/v1/token?grant_type=password`
    const loginTarget = await this.assertCredentialTarget(loginUrl, persona.originAllowlist, 'Supabase login URL')
    const res = await this.credentialFetch(
      loginUrl,
      {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Accept: 'application/json',
        },
        body: JSON.stringify({ email, password }),
      },
      loginTarget.addresses,
      signal,
    )

    const rawText = await res.text()
    rejectUnexpectedRedirect(res, 'Supabase login')
    checkResponseForCaptchaOrMfa(rawText, loginUrl, email)

    let body: Record<string, unknown> = {}
    try {
      body = rawText ? (JSON.parse(rawText) as Record<string, unknown>) : {}
    } catch {
      // handled below
    }

    if (!res.ok) {
      const msg = String(body.error_description || body.msg || body.error || `HTTP ${res.status}`)
      throw new PersonaAuthError(
        res.status === 400 || res.status === 401 ? 'INVALID_CREDENTIALS' : 'AUTH_FAILED',
        `Supabase login failed (${res.status}): ${sanitizeErrorText(msg, [password])}`,
      )
    }

    const accessToken = typeof body.access_token === 'string' ? body.access_token : ''
    if (!accessToken) {
      throw new PersonaAuthError('AUTH_FAILED', 'Supabase login response did not include access_token.')
    }
    let refreshToken = typeof body.refresh_token === 'string' ? body.refresh_token : ''
    const expiresInSec = typeof body.expires_in === 'number' && body.expires_in > 0 ? body.expires_in : 3600
    const expiresAt = typeof body.expires_at === 'number'
      ? body.expires_at * 1000
      : Date.now() + expiresInSec * 1000

    writePersonaSessionFile(persona.sessionPath!, {
      headerType: 'bearer',
      value: accessToken,
      expiresAt,
      adapterUsed: 'supabase',
      scrubTokens: [accessToken, refreshToken].filter(Boolean),
    })

    const refreshUrlObj = new URL(loginUrl)
    refreshUrlObj.searchParams.set('grant_type', 'refresh_token')
    const refreshUrl = refreshUrlObj.toString()

    const refreshIntervalSec = config.refreshIntervalSec ?? Math.max(15, Math.min(1800, Math.floor(expiresInSec * 0.75)))
    const doRefresh = async () => {
      if (!refreshToken) return
      const refreshTarget = await this.assertCredentialTarget(refreshUrl, persona.originAllowlist, 'Supabase refresh URL')
      const rRes = await this.credentialFetch(
        refreshUrl,
        {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            Accept: 'application/json',
          },
          body: JSON.stringify({ refresh_token: refreshToken }),
        },
        refreshTarget.addresses,
      )
      const rText = await rRes.text()
      rejectUnexpectedRedirect(rRes, 'Supabase token refresh')
      checkResponseForCaptchaOrMfa(rText, refreshUrl, email)
      if (!rRes.ok) {
        throw new PersonaAuthError('AUTH_FAILED', `Supabase token refresh failed (${rRes.status}): ${sanitizeErrorText(rText, [password, refreshToken])}`)
      }
      const rBody = JSON.parse(rText) as Record<string, unknown>
      const nextAccess = typeof rBody.access_token === 'string' ? rBody.access_token : ''
      if (!nextAccess) throw new PersonaAuthError('AUTH_FAILED', 'Supabase refresh response missing access_token.')
      const nextRefresh = typeof rBody.refresh_token === 'string' && rBody.refresh_token ? rBody.refresh_token : refreshToken
      const nextExpIn = typeof rBody.expires_in === 'number' && rBody.expires_in > 0 ? rBody.expires_in : expiresInSec
      const nextExpiresAt = typeof rBody.expires_at === 'number'
        ? rBody.expires_at * 1000
        : Date.now() + nextExpIn * 1000
      refreshToken = nextRefresh
      writePersonaSessionFile(persona.sessionPath!, {
        headerType: 'bearer',
        value: nextAccess,
        expiresAt: nextExpiresAt,
        adapterUsed: 'supabase',
        scrubTokens: [nextAccess, nextRefresh].filter(Boolean),
      })
    }

    return {
      personaId: persona.id,
      handle: persona.handle,
      adapterUsed: 'supabase',
      headerType: 'bearer',
      expiresAt,
      refreshIntervalSec: refreshToken ? refreshIntervalSec : undefined,
      refresh: refreshToken ? doRefresh : undefined,
    }
  }

  private async authenticateJson(
    persona: ResolvedPersona,
    config: PersonaLoginConfig,
    email: string,
    password: string,
    targetOrigin: string,
    signal?: AbortSignal,
  ): Promise<AuthenticateResult> {
    // Optional v5 session-hardening knobs (accepted structurally so older persisted configs stay valid).
    const ext = config as PersonaLoginConfig & {
      csrfPrefetchUrl?: string
      refreshUrl?: string
      refreshTokenJsonPath?: string
    }
    const loginUrl = config.loginUrl || `${targetOrigin}/api/auth/login`
    const emailField = config.emailField || 'email'
    const passwordField = config.passwordField || 'password'
    const loginHeaders: Record<string, string> = {
      'Content-Type': 'application/json',
      Accept: 'application/json',
    }

    // Optional CSRF pre-fetch: cookie + token seeding for JSON logins behind CSRF middleware.
    if (ext.csrfPrefetchUrl) {
      try {
        const csrfTarget = await this.assertCredentialTarget(ext.csrfPrefetchUrl, persona.originAllowlist, 'CSRF pre-fetch URL')
        const csrfRes = await this.credentialFetch(
          ext.csrfPrefetchUrl,
          { method: 'GET', headers: { Accept: 'application/json,text/html;q=0.9,*/*;q=0.8' }, redirect: 'follow' },
          csrfTarget.addresses,
          signal,
          Math.min(this.timeoutMs, 8_000),
        )
        const csrfText = (await csrfRes.text()).slice(0, 100_000)
        checkResponseForCaptchaOrMfa(csrfText, ext.csrfPrefetchUrl, email)
        const csrfCookies = extractSetCookies(csrfRes.headers)
        if (csrfCookies.size > 0) loginHeaders.Cookie = cookiesToHeader(csrfCookies)
        let token = csrfRes.headers.get('x-csrf-token') || csrfRes.headers.get('x-xsrf-token') || ''
        if (!token) {
          try {
            const parsed = JSON.parse(csrfText) as unknown
            for (const path of ['csrfToken', 'csrf_token', 'xsrfToken', 'token', 'data.csrfToken']) {
              const candidate = getJsonPath(parsed, path)
              if (candidate) { token = candidate; break }
            }
          } catch {
            const meta = /<meta[^>]+(?:name|property)=["'](?:csrf-token|xsrf-token|_csrf)["'][^>]*content=["']([^"']+)["']/i.exec(csrfText)
            if (meta?.[1]) token = meta[1]
          }
        }
        if (token) loginHeaders['X-CSRF-Token'] = token
      } catch (err) {
        if (err instanceof PersonaAuthError) throw err
        // Pre-fetch is best-effort; the login itself remains authoritative.
      }
    }

    const loginTarget = await this.assertCredentialTarget(loginUrl, persona.originAllowlist, 'JSON login URL')
    const res = await this.credentialFetch(
      loginUrl,
      {
        method: 'POST',
        headers: loginHeaders,
        body: JSON.stringify({ [emailField]: email, [passwordField]: password }),
      },
      loginTarget.addresses,
      signal,
    )

    const rawText = await res.text()
    rejectUnexpectedRedirect(res, 'JSON login')
    checkResponseForCaptchaOrMfa(rawText, loginUrl, email)

    let body: unknown = null
    try {
      body = rawText ? JSON.parse(rawText) : null
    } catch {
      body = null
    }

    if (!res.ok) {
      const rec = (body && typeof body === 'object') ? (body as Record<string, unknown>) : {}
      const detail = String(rec.error || rec.message || rawText.slice(0, 160) || `HTTP ${res.status}`)
      throw new PersonaAuthError(
        res.status === 401 || res.status === 403 ? 'INVALID_CREDENTIALS' : 'AUTH_FAILED',
        `JSON login failed (${res.status}): ${sanitizeErrorText(detail, [password])}`,
      )
    }

    const refreshTokenPath = ext.refreshTokenJsonPath || 'refresh_token'
    const refreshToken = (body && typeof body === 'object') ? getJsonPath(body, refreshTokenPath) : null
    const refreshUrl = ext.refreshUrl ?? null
    const tokenPath = config.tokenJsonPath || 'access_token'
    const refreshIntervalSec = config.refreshIntervalSec ??
      Math.max(60, Math.min(900, Math.floor(((decodeJwtPayload(getJsonPath(body ?? {}, tokenPath) ?? '')?.exp ?? 0) * 1000 - Date.now()) / 2000) || 300))

    const persistBearer = (token: string, scrub: string[]): AuthenticateResult => {
      const claims = decodeJwtPayload(token)
      const expiresAt = claims?.exp ? claims.exp * 1000 : undefined
      let currentRefreshToken = refreshToken
      const doRefresh = refreshUrl && refreshToken
        ? async () => {
            const refreshTarget = await this.assertCredentialTarget(refreshUrl, persona.originAllowlist, 'JSON refresh URL')
            const rr = await this.credentialFetch(
              refreshUrl,
              {
                method: 'POST',
                headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
                body: JSON.stringify({ refresh_token: currentRefreshToken }),
              },
              refreshTarget.addresses,
            )
            const rt = await rr.text()
            rejectUnexpectedRedirect(rr, 'JSON refresh')
            if (!rr.ok) {
              throw new PersonaAuthError('AUTH_FAILED', `JSON refresh failed (${rr.status}): ${sanitizeErrorText(rt.slice(0, 160), [currentRefreshToken ?? '', password])}`)
            }
            let rb: unknown = null
            try { rb = rt ? JSON.parse(rt) : null } catch { rb = null }
            const nextToken = rb ? getJsonPath(rb, tokenPath) : null
            if (!nextToken) throw new PersonaAuthError('AUTH_FAILED', 'JSON refresh response missing access token.')
            const nextRefresh = rb ? getJsonPath(rb, refreshTokenPath) : null
            currentRefreshToken = nextRefresh ?? currentRefreshToken
            writePersonaSessionFile(persona.sessionPath!, {
              headerType: 'bearer',
              value: nextToken,
              expiresAt: decodeJwtPayload(nextToken)?.exp ? decodeJwtPayload(nextToken)!.exp! * 1000 : undefined,
              adapterUsed: 'json',
              scrubTokens: [nextToken, currentRefreshToken ?? '', ...scrub],
            })
          }
        : undefined
      writePersonaSessionFile(persona.sessionPath!, {
        headerType: 'bearer',
        value: token,
        expiresAt,
        adapterUsed: 'json',
        scrubTokens: [token, ...(currentRefreshToken ? [currentRefreshToken] : []), ...scrub],
      })
      return {
        personaId: persona.id,
        handle: persona.handle,
        adapterUsed: 'json',
        headerType: 'bearer',
        expiresAt,
        ...(doRefresh ? { refresh: doRefresh, refreshIntervalSec } : {}),
      }
    }

    // 1. Explicit Authorization response header (IdP / gateway style).
    const authResponseToken = extractBearerToken(res.headers.get('authorization') ?? undefined)
    if (authResponseToken) return persistBearer(authResponseToken, [])

    // 2. Explicit tokenJsonPath.
    if (config.tokenJsonPath && body) {
      const token = getJsonPath(body, config.tokenJsonPath)
      if (!token) {
        throw new PersonaAuthError('AUTH_FAILED', `JSON login succeeded (${res.status}) but tokenJsonPath "${config.tokenJsonPath}" was not found in response.`)
      }
      return persistBearer(token, [])
    }

    // 3. Set-Cookie session.
    const cookies = extractSetCookies(res.headers)
    if (cookies.size > 0) {
      const cookieHeader = cookiesToHeader(cookies)
      const scrubTokens = [cookieHeader, ...cookies.values()]
      writePersonaSessionFile(persona.sessionPath!, {
        headerType: 'cookie',
        value: cookieHeader,
        adapterUsed: 'json',
        scrubTokens,
      })
      return {
        personaId: persona.id,
        handle: persona.handle,
        adapterUsed: 'json',
        headerType: 'cookie',
      }
    }

    // 4. Standard JSON token fields.
    const candidatePaths = [
      'access_token',
      'token',
      'accessToken',
      'session.token',
      'session.access_token',
      'session.accessToken',
      'data.token',
      'data.access_token',
      'data.accessToken',
    ]
    if (body) {
      for (const path of candidatePaths) {
        const token = getJsonPath(body, path)
        if (token) return persistBearer(token, [])
      }
    }

    throw new PersonaAuthError(
      'AUTH_FAILED',
      `JSON login returned HTTP ${res.status} without Set-Cookie headers or a recognizable token field. Specify tokenJsonPath or verify the login endpoint.`,
    )
  }

  /**
   * Interactive enterprise SSO login: Playwright-driven OIDC/OAuth2 through the persona's
   * existing origin allowlist (the `authOrigins` contract), with optional TOTP generation.
   * Every navigation/subresource is origin-guarded and DNS-pinned exactly like the form adapter.
   */
  private async authenticateOidc(
    persona: ResolvedPersona,
    config: PersonaLoginConfig,
    email: string,
    password: string,
    targetOrigin: string,
    signal?: AbortSignal,
  ): Promise<AuthenticateResult> {
    const ext = config as PersonaLoginConfig & {
      authOrigins?: string[]
      totpSeed?: string
      headers?: Record<string, string>
      postLoginUrl?: string
    }
    const loginUrl = config.loginUrl || targetOrigin
    const loginTarget = await this.assertCredentialTarget(
      loginUrl,
      persona.originAllowlist,
      'OIDC login URL',
      { requireResolution: false },
    )
    // `authOrigins` are the existing allowlisted origins (target + IdP); a runtime extra list is
    // only honoured when every entry is already inside that allowlist.
    const authOrigins = [...new Set([
      ...allowlistOrigins(persona.originAllowlist),
      loginTarget.url.origin,
      ...(Array.isArray(ext.authOrigins) ? ext.authOrigins : []),
    ])].filter(origin => origin === loginTarget.url.origin || isOriginInScope(origin, persona.originAllowlist))
    const allowedOrigins = new Set<string>([...authOrigins, loginTarget.url.origin])
    const scopeForSubresources = [...persona.originAllowlist, loginTarget.url.origin]
    const totpSeed = typeof ext.totpSeed === 'string' ? ext.totpSeed : ''
    if (totpSeed && !normalizeTotpSeed(totpSeed)) {
      throw new PersonaAuthError('AUTH_FAILED', 'Persona TOTP seed is not valid base32.')
    }
    const validatedLoginUrl = loginTarget.url.toString()

    const pinnedHosts = new Map<string, string[]>()
    const pinCandidates = new Set<string>([
      normalizeHostname(loginTarget.url.hostname),
      normalizeHostname(new URL(targetOrigin).hostname),
      ...allowedHostnames(persona.originAllowlist),
      ...authOrigins.map(origin => {
        try { return normalizeHostname(new URL(origin).hostname) } catch { return '' }
      }),
    ])
    await Promise.all([...pinCandidates].filter(Boolean).map(async host => {
      try {
        const addresses = await this.resolveHost(host)
        if (addresses.length > 0) pinnedHosts.set(host, addresses)
      } catch {
        // Unresolvable hosts get no MAP rule and therefore cannot connect.
      }
    }))

    let browser: PlaywrightFormBrowserLike | undefined
    let context: PlaywrightFormContext | undefined
    let page: PlaywrightFormPage | undefined
    let captchaRouteHit = false
    const interceptedBearer = new Set<string>()

    const captchaVisible = async (p: PlaywrightFormPage): Promise<boolean> => {
      if (captchaRouteHit) return true
      const frameUrls = p.frames?.().map(f => f.url()) ?? []
      if (frameUrls.some(u => CAPTCHA_PATTERN.test(u))) return true
      const dom = await p.evaluate(() => {
        const selectors = [
          'iframe[src*="challenges.cloudflare.com"]',
          'iframe[src*="turnstile"]',
          'iframe[src*="recaptcha"]',
          'iframe[src*="hcaptcha"]',
          'iframe[src*="arkoselabs"]',
          'input[name="cf-turnstile-response"]',
          '.cf-turnstile',
          '.g-recaptcha',
          '.h-captcha',
          '[data-captcha-provider]',
        ]
        if (selectors.some(selector => document.querySelector(selector))) return { captcha: true }
        const text = (document.body?.innerText || '').slice(0, 4000)
        return { captcha: /verify you are human|complete the captcha|cloudflare security check/i.test(text) }
      }) as unknown as { captcha?: boolean } | boolean
      if (typeof dom === 'boolean') return dom
      return Boolean(dom && typeof dom === 'object' && dom.captcha)
    }
    const otpVisible = async (p: PlaywrightFormPage): Promise<boolean> =>
      await p.locator('input[autocomplete="one-time-code"], input[name*="otp" i], input[name*="totp" i], input[name*="verification" i], input[id*="otp" i]').first().count() > 0
    const submit = async (p: PlaywrightFormPage, fallbackSelector: string): Promise<void> => {
      const btn = p.locator('button[type="submit"], input[type="submit"], button:has-text("Sign in"), button:has-text("Log in"), button:has-text("Continue"), button:has-text("Verify"), button:has-text("Next")').first()
      if (await btn.count() > 0) await btn.click({ timeout: 5_000 })
      else await p.locator(fallbackSelector).first().press?.('Enter', { timeout: 5_000 })
    }

    try {
      browser = await this.launchBrowser(pinnedHosts)
      context = await browser.newContext({
        ignoreHTTPSErrors: false,
        javaScriptEnabled: true,
        bypassCSP: false,
        serviceWorkers: 'block',
      })
      await context.addInitScript?.(webrtcGuardScript)
      if (typeof context.routeWebSocket === 'function') {
        await context.routeWebSocket('**/*', async ws => {
          try {
            const url = new URL(ws.url())
            const websocketOrigin = `${url.protocol === 'wss:' ? 'https:' : 'http:'}//${url.host}`
            if ((url.protocol !== 'wss:' && url.protocol !== 'ws:') || !allowedOrigins.has(websocketOrigin) ||
              typeof ws.connectToServer !== 'function') {
              await ws.close({ code: 1008, reason: 'Blocked by Guardian scope.' })
              return
            }
            await ws.connectToServer()
          } catch {
            await ws.close({ code: 1008, reason: 'Blocked by Guardian scope.' })
          }
        })
      } else if (context.addInitScript) {
        await context.addInitScript(formTransportDenyScript)
      }
      await context.route('**/*', async route => {
        const reqUrl = route.request().url()
        const requestHeaders = route.request().headers?.()
        const bearer = extractBearerToken(requestHeaders?.authorization ?? requestHeaders?.Authorization)
        if (bearer) interceptedBearer.add(bearer)
        if (CAPTCHA_PATTERN.test(reqUrl)) {
          captchaRouteHit = true
          await route.abort('blockedbyclient')
          return
        }
        let parsed: URL
        try { parsed = new URL(reqUrl) } catch {
          await route.abort('blockedbyclient')
          return
        }
        if (parsed.protocol !== 'https:' && parsed.protocol !== 'http:') {
          if (parsed.protocol === 'about:' || parsed.protocol === 'data:' || parsed.protocol === 'blob:') {
            if (route.fulfill) await route.fulfill({ status: 200, contentType: 'text/plain', body: '' })
            else await route.abort('blockedbyclient')
          } else {
            await route.abort('blockedbyclient')
          }
          return
        }
        try {
          const origin = parsed.origin
          const method = (route.request().method?.() ?? 'GET').toUpperCase()
          const resourceType = route.request().resourceType?.() ?? 'document'
          const isReadOnly = method === 'GET' || method === 'HEAD'
          const exactAllowed = allowedOrigins.has(origin)
          const inScopeSubresource = isReadOnly && resourceType !== 'document' && isOriginInScope(origin, scopeForSubresources)
          if (parsed.protocol === 'http:' && !exactAllowed) {
            await route.abort('blockedbyclient')
            return
          }
          if (!exactAllowed && !inScopeSubresource) {
            await route.abort('blockedbyclient')
            return
          }
          const safety = await this.browserHostSafety(origin, scopeForSubresources)
          if (!safety.safe) {
            await route.abort('blockedbyclient')
            return
          }
          const pinned = pinnedHosts.get(normalizeHostname(parsed.hostname))
          if (pinned && !safety.addresses.some(address => pinned.includes(address))) {
            await route.abort('blockedbyclient')
            return
          }
          await route.continue()
        } catch {
          await route.abort('blockedbyclient')
        }
      })

      page = await context.newPage()
      await page.goto(validatedLoginUrl, { waitUntil: 'domcontentloaded', timeout: this.timeoutMs })
      await page.waitForTimeout(400)

      // A script tag alone is never proof of a challenge. Only a rendered widget/challenge
      // endpoint is; and after submission, only an actual challenge failure blocks the login.
      if (await captchaVisible(page)) {
        throw new PersonaAuthError('CAPTCHA_DETECTED', captchaAbortMessage(validatedLoginUrl))
      }

      const ssoSelector = '[data-guardian-sso], a[href*="authorize?client_id"], a[href*="/oauth2/"], a[href*="/oidc/"], button:has-text("Single sign-on"), button:has-text("SSO"), button:has-text("Sign in with"), button:has-text("Continue with")'
      const ssoButton = page.locator(ssoSelector).first()
      if (await ssoButton.count() > 0) {
        await ssoButton.click({ timeout: 5_000 })
        await page.waitForLoadState?.('domcontentloaded', { timeout: 5_000 }).catch(() => undefined)
        await page.waitForTimeout(600)
      }

      const emailSelector = 'input[type="email"], input[name="identifier"], input[name*="email" i], input[name*="user" i], input[autocomplete="email"], input[autocomplete="username"]'
      const passwordSelector = 'input[type="password"]'
      const emailInput = page.locator(emailSelector).first()
      if (await emailInput.count() > 0) {
        await emailInput.fill(email, { timeout: 5_000 })
        await submit(page, emailSelector)
        await page.waitForTimeout(800)
      }

      let passwordInput = page.locator(passwordSelector).first()
      if (await passwordInput.count() > 0) {
        await passwordInput.fill(password, { timeout: 5_000 })
        await submit(page, passwordSelector)
      }

      await page.waitForTimeout(800)
      // TOTP challenge (only when the IdP actually presents a code field).
      if (await otpVisible(page)) {
        if (!totpSeed) {
          throw new PersonaAuthError('MFA_REQUIRED', mfaAbortMessage(email))
        }
        const otpInput = page.locator('input[autocomplete="one-time-code"], input[name*="otp" i], input[name*="totp" i], input[name*="verification" i], input[id*="otp" i]').first()
        await otpInput.fill(generateTotp(totpSeed), { timeout: 5_000 })
        await submit(page, 'input[autocomplete="one-time-code"], input[name*="otp" i]')
        await page.waitForTimeout(800)
      }

      await page.waitForLoadState?.('networkidle', { timeout: 5_000 }).catch(() => undefined)
      await page.waitForTimeout(500)

      // Post-submit: a challenge that actually blocked the login is terminal; otherwise proceed.
      if (await captchaVisible(page)) {
        throw new PersonaAuthError('CAPTCHA_DETECTED', captchaAbortMessage(validatedLoginUrl))
      }
      if (await otpVisible(page)) {
        throw new PersonaAuthError('MFA_REQUIRED', mfaAbortMessage(email))
      }
      const finalUrl = page.url()
      if (new URL(finalUrl).origin === loginTarget.url.origin && await page.locator(passwordSelector).first().count() > 0) {
        throw new PersonaAuthError('INVALID_CREDENTIALS', `OIDC login on ${validatedLoginUrl} did not complete.`)
      }

      const rawCookies = await context.cookies([...persona.originAllowlist])
      const cookieRecords: PersonaCookieRecord[] = []
      for (const cookie of rawCookies) {
        if (!cookie.name || !cookie.value || !cookie.domain) continue
        cookieRecords.push({
          name: cookie.name,
          value: cookie.value,
          domain: cookie.domain,
          path: cookie.path ?? '/',
          ...(cookie.httpOnly ? { httpOnly: true } : {}),
          ...(cookie.secure ? { secure: true } : {}),
          ...(cookie.sameSite ? { sameSite: cookie.sameSite } : {}),
          ...(typeof cookie.expires === 'number' && cookie.expires > 0 ? { expires: Math.floor(cookie.expires * 1000) } : {}),
        })
      }
      const storageTokens = await harvestBrowserTokens(page)
      const bearerToken = [...storageTokens, ...interceptedBearer].find(token => isJwtLike(token))
      const headersByOrigin = new Map<string, Record<string, string>>()
      if (ext.headers && typeof ext.headers === 'object') {
        for (const origin of allowlistOrigins(persona.originAllowlist)) {
          headersByOrigin.set(origin, { ...ext.headers })
        }
      }
      const storageByOrigin = await captureStorageSnapshot(page, persona.originAllowlist)

      if (!cookieRecords.length && !bearerToken) {
        throw new PersonaAuthError('INVALID_CREDENTIALS', `OIDC login on ${validatedLoginUrl} produced no session cookies or Bearer JWT for allowlisted origins.`)
      }

      let session: MintedPersonaSession
      if (!cookieRecords.length && bearerToken) {
        const claims = decodeJwtPayload(bearerToken)
        session = {
          headerType: 'bearer',
          value: bearerToken,
          adapterUsed: 'form',
          ...(claims?.exp ? { expiresAt: claims.exp * 1000 } : {}),
          scrubTokens: [bearerToken, ...storageTokens, ...interceptedBearer],
        }
      } else {
        const imported = buildImportedBundle({ cookies: cookieRecords, headersByOrigin, storageByOrigin, allowlist: persona.originAllowlist, fallbackOrigin: loginTarget.url.origin })
        session = { ...imported.session, adapterUsed: 'form' }
        if (bearerToken) session.scrubTokens = [...new Set([...(session.scrubTokens ?? []), bearerToken, ...storageTokens, ...interceptedBearer])]
      }
      writePersonaSessionFile(persona.sessionPath!, session)
      const claims = session.headerType === 'bearer' ? decodeJwtPayload(session.value) : null
      return {
        personaId: persona.id,
        handle: persona.handle,
        adapterUsed: 'form',
        headerType: session.headerType,
        ...(claims?.exp ? { expiresAt: claims.exp * 1000 } : {}),
        session,
      }
    } finally {
      await page?.close().catch(() => undefined)
      await context?.close().catch(() => undefined)
      await browser?.close().catch(() => undefined)
    }
  }

  private async authenticateForm(
    persona: ResolvedPersona,
    config: PersonaLoginConfig,
    email: string,
    password: string,
    targetOrigin: string,
  ): Promise<AuthenticateResult> {
    const loginUrl = config.loginUrl || `${targetOrigin}/login`
    // Form login types the password into this page: validate it exactly like an API credential
    // destination (allowlist + HTTPS, loopback only when explicitly allowlisted). Resolution is
    // delegated to Chromium's pinned resolver rules below, which fail closed for unknown names.
    const loginTarget = await this.assertCredentialTarget(
      loginUrl,
      persona.originAllowlist,
      'Form login URL',
      { requireResolution: false },
    )
    const validatedLoginUrl = loginTarget.url.toString()
    const loginOrigin = loginTarget.url.origin
    const allowedOrigins = new Set<string>([
      ...allowlistOrigins(persona.originAllowlist),
      loginOrigin,
    ])

    // Resolve every host Chromium may contact, once, before launch. The validated answer becomes
    // a `MAP host ip` rule; all other names resolve to ~NOTFOUND (see formChromiumLaunchArgs).
    const pinnedHosts = new Map<string, string[]>()
    const pinCandidates = new Set<string>([
      normalizeHostname(loginTarget.url.hostname),
      normalizeHostname(new URL(targetOrigin).hostname),
      ...allowedHostnames(persona.originAllowlist),
    ])
    await Promise.all([...pinCandidates].filter(Boolean).map(async host => {
      try {
        const addresses = await this.resolveHost(host)
        if (addresses.length > 0) pinnedHosts.set(host, addresses)
      } catch {
        // Unresolvable hosts get no MAP rule and therefore cannot connect.
      }
    }))

    let browser: PlaywrightFormBrowserLike | undefined
    let context: PlaywrightFormContext | undefined
    let page: PlaywrightFormPage | undefined
    let captchaRouteHit = false
    const interceptedBearer = new Set<string>()

    const assertNoCaptchaInPage = async (p: PlaywrightFormPage) => {
      if (captchaRouteHit) {
        throw new PersonaAuthError('CAPTCHA_DETECTED', captchaAbortMessage(validatedLoginUrl))
      }
      const frameUrls = p.frames?.().map(f => f.url()) ?? []
      if (frameUrls.some(u => CAPTCHA_PATTERN.test(u))) {
        throw new PersonaAuthError('CAPTCHA_DETECTED', captchaAbortMessage(validatedLoginUrl))
      }
      const domCheck = await p.evaluate(() => {
        const captchaSelectors = [
          'iframe[src*="challenges.cloudflare.com"]',
          'iframe[src*="turnstile"]',
          'iframe[src*="recaptcha"]',
          'iframe[src*="hcaptcha"]',
          'iframe[src*="arkoselabs"]',
          'input[name="cf-turnstile-response"]',
          '.cf-turnstile',
          '.g-recaptcha',
          '#g-recaptcha',
          '.h-captcha',
          '[data-captcha-provider]',
        ]
        for (const sel of captchaSelectors) {
          if (document.querySelector(sel)) return { captcha: true, mfa: false }
        }
        // A CAPTCHA *script tag* is not a challenge: many SPAs bundle reCAPTCHA/Turnstile
        // loaders but never invoke them. Only a rendered widget/iframe or challenge text blocks.
        const text = (document.body?.innerText || '').slice(0, 4000)
        const captchaText = /verify you are human|complete the captcha|cloudflare security check/i.test(text)
        const mfaText = /two-factor|2fa code|authenticator app|enter verification code|second factor/i.test(text)
        return { captcha: captchaText, mfa: mfaText }
      })
      if (domCheck.captcha) {
        throw new PersonaAuthError('CAPTCHA_DETECTED', captchaAbortMessage(validatedLoginUrl))
      }
      if (domCheck.mfa) {
        throw new PersonaAuthError('MFA_REQUIRED', mfaAbortMessage(email))
      }
    }

    try {
      browser = await this.launchBrowser(pinnedHosts)
      context = await browser.newContext({
        ignoreHTTPSErrors: false,
        javaScriptEnabled: true,
        bypassCSP: false,
        serviceWorkers: 'block',
      })
      await context.addInitScript?.(webrtcGuardScript)
      // WebSocket upgrades are never brokered HTTP. Only exactly allowed origins may open a
      // socket; everything else is closed before Chromium connects. If the Playwright version
      // cannot route sockets, the page loses the constructors entirely (fail closed).
      if (typeof context.routeWebSocket === 'function') {
        await context.routeWebSocket('**/*', async ws => {
          try {
            const url = new URL(ws.url())
            if (url.protocol !== 'wss:' && url.protocol !== 'ws:') {
              await ws.close({ code: 1008, reason: 'Blocked by Guardian scope.' })
              return
            }
            const websocketOrigin = `${url.protocol === 'wss:' ? 'https:' : 'http:'}//${url.host}`
            if (!allowedOrigins.has(websocketOrigin)) {
              await ws.close({ code: 1008, reason: 'Blocked by Guardian scope.' })
              return
            }
            if (typeof ws.connectToServer !== 'function') {
              await ws.close({ code: 1008, reason: 'Blocked by Guardian scope.' })
              return
            }
            await ws.connectToServer()
          } catch {
            await ws.close({ code: 1008, reason: 'Blocked by Guardian scope.' })
          }
        })
      } else {
        if (context.addInitScript) await context.addInitScript(formTransportDenyScript)
        else console.warn('WARNING: routeWebSocket is unavailable; form-login WebSocket egress cannot be intercepted.')
      }
      const scopeForSubresources = [...persona.originAllowlist, loginOrigin]
      await context.route('**/*', async route => {
        const reqUrl = route.request().url()
        const requestHeaders = route.request().headers?.()
        const bearer = extractBearerToken(requestHeaders?.authorization ?? requestHeaders?.Authorization)
        if (bearer) interceptedBearer.add(bearer)
        if (CAPTCHA_PATTERN.test(reqUrl)) {
          captchaRouteHit = true
          await route.abort('blockedbyclient')
          return
        }
        let parsed: URL
        try {
          parsed = new URL(reqUrl)
        } catch {
          await route.abort('blockedbyclient')
          return
        }
        // Non-HTTP(S) schemes are never credential or subresource channels. Inert local
        // schemes are fulfilled empty; `file:` (and anything else) is aborted.
        if (parsed.protocol !== 'https:' && parsed.protocol !== 'http:') {
          if (parsed.protocol === 'about:' || parsed.protocol === 'data:' || parsed.protocol === 'blob:') {
            if (route.fulfill) await route.fulfill({ status: 200, contentType: 'text/plain', body: '' })
            else await route.abort('blockedbyclient')
          } else {
            await route.abort('blockedbyclient')
          }
          return
        }
        try {
          const origin = parsed.origin
          const method = (route.request().method?.() ?? 'GET').toUpperCase()
          const resourceType = route.request().resourceType?.() ?? 'document'
          const isReadOnly = method === 'GET' || method === 'HEAD'
          const exactAllowed = allowedOrigins.has(origin)
          const inScopeSubresource = isReadOnly && resourceType !== 'document' && isOriginInScope(origin, scopeForSubresources)
          // Plaintext HTTP is only reachable for an exact allowlisted origin (loopback lab).
          if (parsed.protocol === 'http:' && !exactAllowed) {
            await route.abort('blockedbyclient')
            return
          }
          if (!exactAllowed && !inScopeSubresource) {
            await route.abort('blockedbyclient')
            return
          }
          // Re-check DNS immediately before connect: empty/unknown resolution is refused, and a
          // host pinned at launch must still resolve to the pinned address set.
          const safety = await this.browserHostSafety(origin, scopeForSubresources)
          if (!safety.safe) {
            await route.abort('blockedbyclient')
            return
          }
          const pinned = pinnedHosts.get(normalizeHostname(parsed.hostname))
          if (pinned && !safety.addresses.some(address => pinned.includes(address))) {
            await route.abort('blockedbyclient')
            return
          }
          await route.continue()
          return
        } catch {
          await route.abort('blockedbyclient')
          return
        }
      })

      page = await context.newPage()
      await page.goto(validatedLoginUrl, { waitUntil: 'domcontentloaded', timeout: this.timeoutMs })
      await page.waitForTimeout(400)

      // Strict Invariant #2: Check for CAPTCHA/Turnstile/MFA BEFORE interacting!
      await assertNoCaptchaInPage(page)

      const emailSelector = 'input[type="email"], input[name*="email" i], input[name="identifier"], input[name*="user" i], input[autocomplete="email"], input[autocomplete="username"]'
      const passwordSelector = 'input[type="password"]'
      const submitSelector = 'button[type="submit"], input[type="submit"], button:has-text("Sign in"), button:has-text("Log in"), button:has-text("Continue")'

      const emailInput = page.locator(emailSelector).first()
      if (await emailInput.count() === 0) {
        throw new PersonaAuthError('AUTH_FAILED', `Could not locate an email/username input on ${validatedLoginUrl}.`)
      }
      await emailInput.fill(email, { timeout: 5_000 })

      let passwordInput = page.locator(passwordSelector).first()
      if (await passwordInput.count() === 0) {
        // Two-step login form: submit identifier first, then check CAPTCHA again before entering password
        const nextBtn = page.locator(submitSelector).first()
        if (await nextBtn.count() > 0) {
          await nextBtn.click({ timeout: 5_000 })
        } else {
          await emailInput.press?.('Enter', { timeout: 5_000 })
        }
        await page.waitForTimeout(800)
        await assertNoCaptchaInPage(page)
        passwordInput = page.locator(passwordSelector).first()
        if (await passwordInput.count() === 0) {
          throw new PersonaAuthError('AUTH_FAILED', `Could not locate a password input after submitting email on ${validatedLoginUrl}.`)
        }
      }

      await passwordInput.fill(password, { timeout: 5_000 })

      const submitBtn = page.locator(submitSelector).first()
      if (await submitBtn.count() > 0) {
        await submitBtn.click({ timeout: 5_000 })
      } else {
        await passwordInput.press?.('Enter', { timeout: 5_000 })
      }

      await page.waitForLoadState?.('networkidle', { timeout: 5_000 }).catch(() => undefined)
      await page.waitForTimeout(600)
      await assertNoCaptchaInPage(page)

      const cookies = await context.cookies([...persona.originAllowlist])
      const cookieMap = new Map<string, string>()
      const cookieRecords: PersonaCookieRecord[] = []
      for (const c of cookies) {
        if (!c.name || !c.value || !c.domain) continue
        cookieMap.set(c.name, c.value)
        cookieRecords.push({
          name: c.name,
          value: c.value,
          domain: c.domain,
          path: c.path ?? '/',
          ...(c.httpOnly ? { httpOnly: true } : {}),
          ...(c.secure ? { secure: true } : {}),
          ...(c.sameSite ? { sameSite: c.sameSite } : {}),
          ...(typeof c.expires === 'number' && c.expires > 0 ? { expires: Math.floor(c.expires * 1000) } : {}),
        })
      }

      // Harvest Bearer JWTs from storage + intercepted XHR Authorization headers (SPA logins).
      const storageTokens = await harvestBrowserTokens(page)
      const harvested = [...storageTokens, ...interceptedBearer]
      const bearerToken = harvested.find(token => isJwtLike(token))

      if (cookieMap.size === 0 && !bearerToken) {
        throw new PersonaAuthError('INVALID_CREDENTIALS', `Form login on ${validatedLoginUrl} produced no session cookies or Bearer JWT for allowlisted origins.`)
      }

      if (cookieMap.size === 0 && bearerToken) {
        // SPA localStorage/sessionStorage auth: persist the harvested Bearer JWT.
        const claims = decodeJwtPayload(bearerToken)
        const session: MintedPersonaSession = {
          headerType: 'bearer',
          value: bearerToken,
          adapterUsed: 'form',
          ...(claims?.exp ? { expiresAt: claims.exp * 1000 } : {}),
          scrubTokens: [bearerToken, ...harvested],
        }
        writePersonaSessionFile(persona.sessionPath!, session)
        return {
          personaId: persona.id,
          handle: persona.handle,
          adapterUsed: 'form',
          headerType: 'bearer',
          ...(claims?.exp ? { expiresAt: claims.exp * 1000 } : {}),
          session,
        }
      }

      const cookieHeader = cookiesToHeader(cookieMap)
      // Persist the composite bundle so HttpOnly cookies, storage, and per-origin rules survive
      // the browser session (the legacy Cookie value is kept for single-header consumers).
      const imported = buildImportedBundle({
        cookies: cookieRecords,
        headersByOrigin: new Map(),
        storageByOrigin: await captureStorageSnapshot(page, persona.originAllowlist),
        allowlist: persona.originAllowlist,
        fallbackOrigin: (() => {
          try {
            const origin = new URL(page!.url()).origin
            return isOriginInScope(origin, persona.originAllowlist) ? origin : loginOrigin
          } catch {
            return loginOrigin
          }
        })(),
      })
      const session: MintedPersonaSession = {
        ...imported.session,
        headerType: 'cookie',
        value: cookieHeader,
        adapterUsed: 'form',
        scrubTokens: [cookieHeader, ...cookieMap.values(), ...harvested],
      }
      writePersonaSessionFile(persona.sessionPath!, session)

      return {
        personaId: persona.id,
        handle: persona.handle,
        adapterUsed: 'form',
        headerType: 'cookie',
        session,
      }
    } finally {
      await page?.close().catch(() => undefined)
      await context?.close().catch(() => undefined)
      await browser?.close().catch(() => undefined)
    }
  }

  async startRunRefreshers(
    storage: Store,
    runId: string,
    projectId: string,
    approvedPersonaIds: readonly string[],
    signal?: AbortSignal,
  ): Promise<AuthenticateResult[]> {
    this.stopRunRefreshers(runId)
    if (!approvedPersonaIds.length) return []

    const resolved = resolveRunPersonas(storage, projectId, approvedPersonaIds)
    const loginPersonas = [...resolved.values()].filter(p => p.authKind === 'login')
    if (!loginPersonas.length) return []

    const results: AuthenticateResult[] = []
    const timers: NodeJS.Timeout[] = []

    try {
      for (const persona of loginPersonas) {
        const result = await this.authenticatePersona(storage, projectId, persona.id, signal)
        results.push(result)
        const reauthRefresh = result.refresh
        const reloadSession = (): MintedPersonaSession | null => {
          try {
            return resolveRunPersonas(storage, projectId, [persona.id]).get(persona.handle)?.session ?? null
          } catch {
            return null
          }
        }
        const runRefresh = async (): Promise<MintedPersonaSession | null> => {
          if (reauthRefresh) await reauthRefresh()
          else await this.authenticatePersona(storage, projectId, persona.id, signal)
          return reloadSession()
        }
        const seeded = reloadSession() ?? result.session ?? null
        if (seeded) {
          // v6: per-worker clones coordinate a single-flight refresh with no 60 s lockout.
          this.registerSession(persona.handle, {
            session: seeded,
            allowlist: persona.originAllowlist,
            refresh: runRefresh,
          })
        }
        // Raw-handler registration is kept for embedders that call requestReauth() directly
        // without the pool; pool-backed requests bypass this pacing entirely.
        this.registerReauth(persona.handle, async () => {
          const fresh = await runRefresh()
          if (fresh) this.sessionPool.rotate(persona.handle, fresh)
        })
        storage.event(
          runId,
          'persona.authenticated',
          `Authenticated persona ${persona.handle} via ${result.adapterUsed}${result.refreshIntervalSec ? ` (auto-refresh ${result.refreshIntervalSec}s)` : ''}.`,
          {
            personaId: persona.id,
            handle: persona.handle,
            adapter: result.adapterUsed,
            headerType: result.headerType,
            refreshIntervalSec: result.refreshIntervalSec ?? null,
          },
        )

        if (result.refresh && result.refreshIntervalSec && result.refreshIntervalSec > 0) {
          let refreshing = false
          const intervalMs = result.refreshIntervalSec * 1000
          const refreshFn = result.refresh
          const timer = setInterval(() => {
            if (refreshing) return
            refreshing = true
            void refreshFn().catch(err => {
              const safeMsg = sanitizeErrorText(err instanceof Error ? err.message : String(err), [persona.secret])
              try {
                storage.event(
                  runId,
                  'persona.refresh_failed',
                  `Session refresh warning for persona ${persona.handle}: ${safeMsg}`,
                  { personaId: persona.id, handle: persona.handle, adapter: result.adapterUsed },
                )
              } catch {
                // Storage may have closed during shutdown.
              }
            }).finally(() => {
              refreshing = false
              const latest = reloadSession()
              if (latest) this.sessionPool.rotate(persona.handle, latest)
            })
          }, intervalMs)
          timer.unref?.()
          timers.push(timer)
        }
      }
    } catch (err) {
      for (const t of timers) clearInterval(t)
      throw err
    }

    if (timers.length > 0) {
      this.runTimers.set(runId, timers)
    }
    return results
  }

  stopRunRefreshers(runId: string): void {
    const timers = this.runTimers.get(runId)
    if (!timers) return
    for (const timer of timers) clearInterval(timer)
    this.runTimers.delete(runId)
  }

  stopAll(): void {
    for (const timers of this.runTimers.values()) {
      for (const timer of timers) clearInterval(timer)
    }
    this.runTimers.clear()
  }
}
