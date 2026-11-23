import type { PersonaLoginAdapter, PersonaLoginConfig } from '../domain.ts'
import { lookup } from 'node:dns/promises'
import ipaddr from 'ipaddr.js'
import {
  readLoginCredentialFile,
  resolveRunPersonas,
  writePersonaSessionFile,
} from './persona-vault.ts'
import type { MintedPersonaSession, ResolvedPersona } from './persona-vault.ts'
import { redact } from './redact.ts'
import type { Store } from './store.ts'

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
  adapterUsed: Exclude<PersonaLoginAdapter, 'auto'>
  headerType: 'cookie' | 'bearer' | 'header'
  expiresAt?: number
  refreshIntervalSec?: number
  refresh?: () => Promise<void>
}

interface PlaywrightFormCookie {
  name: string
  value: string
  domain: string
  path?: string
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
  fetchImpl?: typeof fetch
  launchBrowser?: () => Promise<PlaywrightFormBrowserLike>
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
 * Conservative public-suffix handling for the multi-label suffixes Guardian encounters in the wild.
 * The previous implementation blindly took the last two labels, so `app.example.co.uk` mapped to
 * `co.uk` and Clerk discovery could be steered to `clerk.co.uk`.
 */
const multiLabelPublicSuffixes = new Set([
  'co.uk', 'org.uk', 'ac.uk', 'gov.uk', 'me.uk', 'net.uk', 'ltd.uk', 'plc.uk', 'sch.uk',
  'com.au', 'net.au', 'org.au', 'edu.au', 'gov.au', 'id.au', 'asn.au',
  'co.nz', 'net.nz', 'org.nz', 'govt.nz', 'ac.nz', 'school.nz',
  'co.jp', 'ne.jp', 'or.jp', 'ac.jp', 'go.jp', 'ad.jp', 'ed.jp', 'gr.jp', 'lg.jp',
  'co.kr', 'or.kr', 'ne.kr', 'go.kr', 'ac.kr',
  'com.br', 'net.br', 'org.br', 'gov.br', 'edu.br',
  'com.cn', 'net.cn', 'org.cn', 'gov.cn', 'edu.cn', 'ac.cn',
  'com.tw', 'net.tw', 'org.tw', 'gov.tw', 'edu.tw',
  'com.hk', 'net.hk', 'org.hk', 'gov.hk', 'edu.hk',
  'com.sg', 'net.sg', 'org.sg', 'gov.sg', 'edu.sg',
  'com.my', 'net.my', 'org.my', 'gov.my', 'edu.my',
  'co.in', 'net.in', 'org.in', 'gov.in', 'ac.in', 'edu.in', 'firm.in', 'gen.in', 'ind.in',
  'co.za', 'net.za', 'org.za', 'gov.za', 'ac.za', 'web.za',
  'com.mx', 'net.mx', 'org.mx', 'gov.mx', 'edu.mx',
  'com.ar', 'net.ar', 'org.ar', 'gov.ar', 'edu.ar',
  'com.tr', 'net.tr', 'org.tr', 'gov.tr', 'edu.tr',
  'co.il', 'org.il', 'net.il', 'gov.il', 'ac.il',
  'com.ua', 'net.ua', 'org.ua', 'gov.ua', 'edu.ua',
  'com.pl', 'net.pl', 'org.pl', 'gov.pl', 'edu.pl',
  'com.ru', 'net.ru', 'org.ru', 'gov.ru', 'edu.ru',
  'com.es', 'net.es', 'org.es', 'gov.es', 'edu.es',
  'co.id', 'or.id', 'ac.id', 'go.id', 'web.id',
  'co.th', 'in.th', 'ac.th', 'go.th',
  'com.vn', 'net.vn', 'org.vn', 'gov.vn', 'edu.vn',
  'com.ph', 'net.ph', 'org.ph', 'gov.ph', 'edu.ph',
  'com.pk', 'net.pk', 'org.pk', 'gov.pk', 'edu.pk',
  'com.ng', 'net.ng', 'org.ng', 'gov.ng', 'edu.ng',
  'co.ke', 'or.ke', 'ne.ke', 'go.ke', 'ac.ke',
  'com.eg', 'net.eg', 'org.eg', 'gov.eg', 'edu.eg',
  'com.sa', 'net.sa', 'org.sa', 'gov.sa', 'edu.sa',
  'co.ae', 'net.ae', 'org.ae', 'gov.ae', 'ac.ae',
])

/** Exact hostname/IP literal, never a scheme. Returns null for single labels and IPs. */
export function registrableDomain(hostname: string): string | null {
  const host = hostname.trim().toLowerCase().replace(/\.$/, '')
  if (!host || host.includes(':')) return null
  if (/^\d{1,3}(?:\.\d{1,3}){3}$/.test(host)) return null
  const labels = host.split('.').filter(Boolean)
  if (labels.length < 2) return null
  const lastTwo = labels.slice(-2).join('.')
  const suffixLabels = multiLabelPublicSuffixes.has(lastTwo) ? 2 : 1
  if (labels.length <= suffixLabels) return null
  return labels.slice(-(suffixLabels + 1)).join('.')
}

function allowedHostnames(allowlist: readonly string[]): string[] {
  const hosts: string[] = []
  for (const origin of allowlist) {
    try {
      hosts.push(new URL(origin).hostname.toLowerCase().replace(/\.$/, ''))
    } catch {
      // Ignore malformed allowlist entries; the broker rejects them independently.
    }
  }
  return hosts
}

/**
 * True when `host` is an explicitly allowlisted host or shares the registrable domain of one.
 * This is the only permitted source for Clerk/IdP hosts — never a raw two-label fallback.
 */
export function isHostInScope(host: string, allowlist: readonly string[]): boolean {
  const normalized = host.trim().toLowerCase().replace(/\.$/, '')
  if (!normalized) return false
  for (const allowed of allowedHostnames(allowlist)) {
    if (normalized === allowed) return true
    const registrable = registrableDomain(allowed)
    if (registrable && normalized === registrable) return true
    if (registrable && normalized.endsWith(`.${registrable}`)) return true
  }
  return false
}

export function isOriginInScope(origin: string, allowlist: readonly string[]): boolean {
  try {
    const parsed = new URL(origin)
    if (parsed.protocol !== 'https:' && parsed.protocol !== 'http:') return false
    return isHostInScope(parsed.hostname, allowlist)
  } catch {
    return false
  }
}

function isIpLiteral(host: string): boolean {
  const bare = host.replace(/^\[|\]$/g, '')
  return ipaddr.isValid(bare)
}

/** Loopback is allowed only for an explicitly allowlisted local-lab origin; link-local is never allowed. */
export type AddressClass = 'public' | 'loopback' | 'blocked'

export function classifyAddress(address: string): AddressClass {
  try {
    const ip = ipaddr.process(address)
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
  if (bare === 'localhost') return true
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

function extractBearerToken(headerValue: string | undefined): string | null {
  if (!headerValue) return null
  const match = /^Bearer\s+(\S+)$/i.exec(headerValue.trim())
  if (!match || !match[1]) return null
  return isJwtLike(match[1]) ? match[1] : null
}

/** Chromium sandboxing defaults. `--no-sandbox` is an explicit, warned-about insecure opt-in. */
export function formChromiumLaunchArgs(options: { insecureNoSandbox?: boolean } = {}): string[] {
  const args = [
    '--disable-dev-shm-usage',
    '--disable-background-networking',
    '--force-webrtc-ip-handling-policy=disable_non_proxied_udp',
    '--webrtc-ip-handling-policy=disable_non_proxied_udp',
  ]
  if (options.insecureNoSandbox) args.push('--no-sandbox')
  return args
}

const webrtcGuardScript = `(() => {
  const deny = function () { throw new Error('WebRTC is disabled inside Guardian browser sessions.'); };
  for (const name of ['RTCPeerConnection', 'webkitRTCPeerConnection', 'RTCDataChannel']) {
    try { Object.defineProperty(window, name, { configurable: false, writable: false, value: deny }); } catch {}
  }
})();`

async function launchDefaultChromium(): Promise<PlaywrightFormBrowserLike> {
  const insecureNoSandbox = process.env.GUARDIAN_INSECURE_NO_SANDBOX === '1'
  if (insecureNoSandbox) {
    console.warn('WARNING: Chromium sandbox disabled (GUARDIAN_INSECURE_NO_SANDBOX=1). Detection fidelity is reduced.')
  }
  const args = formChromiumLaunchArgs({ insecureNoSandbox })
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

async function inspectTargetOrigin(
  fetchImpl: typeof fetch,
  targetOrigin: string,
  allowlist: readonly string[],
  timeoutMs: number,
  signal?: AbortSignal,
): Promise<{ html: string; headers: Headers; clerkFapiOrigin: string | null; hasClerk: boolean }> {
  try {
    // No redirects while discovering provider configuration: a redirect target must never decide
    // which Clerk/IdP host receives credentials.
    const res = await fetchWithTimeout(
      fetchImpl,
      targetOrigin,
      { method: 'GET', headers: { Accept: 'text/html,application/xhtml+xml,*/*' }, redirect: 'manual' },
      Math.min(timeoutMs, 8_000),
      signal,
    )
    if (res.status >= 300 && res.status < 400) {
      return { html: '', headers: res.headers, clerkFapiOrigin: null, hasClerk: false }
    }
    const html = (await res.text()).slice(0, 250_000)
    let clerkFapiOrigin: string | null = null
    const pkMatch = /\b(pk_(?:live|test)_[A-Za-z0-9+/=_-]{12,})\b/.exec(html)
    if (pkMatch) {
      const decoded = decodeClerkPublishableKey(pkMatch[1])
      // A target document can contain an attacker-controlled publishable key; only hosts inside
      // the persona allowlist's registrable domain may become the credential destination.
      if (decoded && isOriginInScope(decoded, allowlist)) clerkFapiOrigin = decoded
    }
    if (!clerkFapiOrigin) {
      const fapiMatch = /https:\/\/(clerk\.[a-z0-9.-]+\.[a-z]{2,})/i.exec(html)
      if (fapiMatch && isOriginInScope(`https://${fapiMatch[1]}`, allowlist)) {
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

export class PersonaAuthManager {
  private readonly fetchImpl: typeof fetch
  private readonly launchBrowser: () => Promise<PlaywrightFormBrowserLike>
  private readonly timeoutMs: number
  private readonly reauthMinIntervalMs: number
  private readonly resolveHost: (hostname: string) => Promise<string[]>
  private readonly hostSafety = new Map<string, { at: number; safe: boolean }>()
  private readonly runTimers = new Map<string, NodeJS.Timeout[]>()
  private readonly reauthHandlers = new Map<string, { fn: () => Promise<void>; lastAt: number; inFlight?: Promise<boolean> }>()

  constructor(options: PersonaAuthManagerOptions = {}) {
    this.fetchImpl = options.fetchImpl ?? globalThis.fetch.bind(globalThis)
    this.launchBrowser = options.launchBrowser ?? launchDefaultChromium
    this.timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS
    this.reauthMinIntervalMs = Math.max(1_000, options.reauthMinIntervalMs ?? 60_000)
    this.resolveHost = options.resolveHost ?? (async hostname => {
      if (isIpLiteral(hostname) || hostname.toLowerCase() === 'localhost') {
        return [hostname.replace(/^\[|\]$/g, '')]
      }
      try {
        const addresses = await lookup(hostname, { all: true, order: 'verbatim' })
        return addresses.map(entry => entry.address)
      } catch {
        // Unresolvable names cannot reach an address; the ensuing fetch fails closed.
        return []
      }
    })
  }

  /**
   * Validate a credential destination: hostname must be inside the persona allowlist scope, the
   * scheme must be HTTPS (HTTP only for an explicitly allowlisted loopback lab), and every resolved
   * address must be public. Loopback is only accepted when the exact origin was allowlisted;
   * link-local/metadata and private ranges are always refused.
   */
  private async assertCredentialTarget(rawUrl: string, allowlist: readonly string[], label: string): Promise<URL> {
    let parsed: URL
    try {
      parsed = new URL(rawUrl)
    } catch {
      throw new PersonaAuthError('AUTH_FAILED', `${label} is not a valid URL.`)
    }
    if (parsed.protocol !== 'https:' && parsed.protocol !== 'http:') {
      throw new PersonaAuthError('AUTH_FAILED', `${label} must use HTTPS.`)
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
    const addresses = await this.resolveHost(parsed.hostname)
    for (const address of addresses) {
      const kind = classifyAddress(address)
      if (kind === 'blocked' || (kind === 'loopback' && !exactAllowlisted)) {
        throw new PersonaAuthError('AUTH_FAILED', `${label} host ${parsed.hostname} resolves to a private, loopback, or metadata address.`)
      }
    }
    return parsed
  }

  /** Re-check a browser navigation origin before Chromium is allowed to connect to it directly. */
  private async hostIsSafeForBrowser(origin: string, allowlist: readonly string[]): Promise<boolean> {
    let host: string
    try {
      host = new URL(origin).hostname
    } catch {
      return false
    }
    const cached = this.hostSafety.get(host)
    if (cached && Date.now() - cached.at < 60_000) return cached.safe
    const addresses = await this.resolveHost(host)
    const kind = addresses.length === 0
      ? 'unknown'
      : addresses.every(address => classifyAddress(address) === 'public') ? 'public'
        : addresses.every(address => classifyAddress(address) === 'loopback') ? 'loopback'
          : 'blocked'
    const exactAllowlisted = allowlist.some(entry => {
      try { return new URL(entry).hostname.toLowerCase() === host.toLowerCase() } catch { return false }
    })
    const safe = kind === 'public' || (kind === 'loopback' && exactAllowlisted) || kind === 'unknown'
    this.hostSafety.set(host, { at: Date.now(), safe })
    return safe
  }

  /**
   * Register a broker-invoked 401 re-authentication callback for a persona handle.
   * Calls are rate-limited to at most one per minute per persona (configurable for tests).
   */
  registerReauth(handle: string, fn: () => Promise<void>): () => void {
    this.reauthHandlers.set(handle, { fn, lastAt: 0 })
    return () => {
      const current = this.reauthHandlers.get(handle)
      if (current?.fn === fn) this.reauthHandlers.delete(handle)
    }
  }

  /** Invoked by RequestBroker on a persona-bound 401. Returns true when a session refresh ran. */
  async requestReauth(handle: string): Promise<boolean> {
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
    let adapter: Exclude<PersonaLoginAdapter, 'auto'>
    let detectedClerkFapiOrigin: string | null = null

    if (config.adapter === 'auto') {
      const inspected = await inspectTargetOrigin(this.fetchImpl, targetOrigin, persona.originAllowlist, this.timeoutMs, signal)
      if (inspected.hasClerk) {
        adapter = 'clerk'
        detectedClerkFapiOrigin = inspected.clerkFapiOrigin
      } else if (config.loginUrl && /\/auth\/v1\/token\b/i.test(config.loginUrl)) {
        adapter = 'supabase'
      } else if (config.loginUrl && /\/api\//i.test(config.loginUrl)) {
        adapter = 'json'
      } else {
        adapter = 'form'
      }
    } else {
      adapter = config.adapter
    }

    switch (adapter) {
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
      // must be inside the persona allowlist scope.
      if (!isOriginInScope(parsed.origin, allowlist)) {
        throw new PersonaAuthError('AUTH_FAILED', `Clerk login URL host ${parsed.hostname} is outside the persona origin allowlist.`)
      }
      if (parsed.origin !== targetOrigin || /^clerk\./i.test(parsed.hostname) || parsed.pathname.includes('/v1/client')) {
        return parsed.origin
      }
    }
    if (detectedFapiOrigin && isOriginInScope(detectedFapiOrigin, allowlist)) return detectedFapiOrigin
    const inspected = await inspectTargetOrigin(this.fetchImpl, targetOrigin, allowlist, this.timeoutMs, signal)
    if (inspected.clerkFapiOrigin) return inspected.clerkFapiOrigin
    // Only the target origin's registrable domain may host its Clerk instance. Never fall back to
    // a bare last-two-label host (the old `co.uk` bug) or an arbitrary host from target HTML.
    const registrable = registrableDomain(new URL(targetOrigin).hostname)
    if (!registrable) {
      throw new PersonaAuthError(
        'AUTH_FAILED',
        `Cannot derive a Clerk Frontend API host for ${targetOrigin}; configure an explicit Clerk login URL inside the persona allowlist.`,
      )
    }
    const derived = `https://clerk.${registrable}`
    if (!isOriginInScope(derived, allowlist)) {
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
    await this.assertCredentialTarget(signInUrl, persona.originAllowlist, 'Clerk sign-in URL')
    const form = new URLSearchParams({
      identifier: email,
      password,
      strategy: 'password',
    })

    const res = await fetchWithTimeout(
      this.fetchImpl,
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
      this.timeoutMs,
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

      const tokRes = await fetchWithTimeout(
        this.fetchImpl,
        `${fapiOrigin}/v1/client/sessions/${encodeURIComponent(sessionId)}/tokens`,
        { method: 'POST', headers: tokenHeaders },
        this.timeoutMs,
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
    await this.assertCredentialTarget(loginUrl, persona.originAllowlist, 'Supabase login URL')
    const res = await fetchWithTimeout(
      this.fetchImpl,
      loginUrl,
      {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Accept: 'application/json',
        },
        body: JSON.stringify({ email, password }),
      },
      this.timeoutMs,
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
      await this.assertCredentialTarget(refreshUrl, persona.originAllowlist, 'Supabase refresh URL')
      const rRes = await fetchWithTimeout(
        this.fetchImpl,
        refreshUrl,
        {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            Accept: 'application/json',
          },
          body: JSON.stringify({ refresh_token: refreshToken }),
        },
        this.timeoutMs,
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
        await this.assertCredentialTarget(ext.csrfPrefetchUrl, persona.originAllowlist, 'CSRF pre-fetch URL')
        const csrfRes = await fetchWithTimeout(
          this.fetchImpl,
          ext.csrfPrefetchUrl,
          { method: 'GET', headers: { Accept: 'application/json,text/html;q=0.9,*/*;q=0.8' }, redirect: 'follow' },
          Math.min(this.timeoutMs, 8_000),
          signal,
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

    await this.assertCredentialTarget(loginUrl, persona.originAllowlist, 'JSON login URL')
    const res = await fetchWithTimeout(
      this.fetchImpl,
      loginUrl,
      {
        method: 'POST',
        headers: loginHeaders,
        body: JSON.stringify({ [emailField]: email, [passwordField]: password }),
      },
      this.timeoutMs,
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
            await this.assertCredentialTarget(refreshUrl, persona.originAllowlist, 'JSON refresh URL')
            const rr = await fetchWithTimeout(
              this.fetchImpl,
              refreshUrl,
              {
                method: 'POST',
                headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
                body: JSON.stringify({ refresh_token: currentRefreshToken }),
              },
              this.timeoutMs,
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

  private async authenticateForm(
    persona: ResolvedPersona,
    config: PersonaLoginConfig,
    email: string,
    password: string,
    targetOrigin: string,
  ): Promise<AuthenticateResult> {
    const loginUrl = config.loginUrl || `${targetOrigin}/login`
    const loginOrigin = new URL(loginUrl).origin
    const allowedOrigins = new Set<string>([...persona.originAllowlist, loginOrigin])

    let browser: PlaywrightFormBrowserLike | undefined
    let context: PlaywrightFormContext | undefined
    let page: PlaywrightFormPage | undefined
    let captchaRouteHit = false
    const interceptedBearer = new Set<string>()

    const assertNoCaptchaInPage = async (p: PlaywrightFormPage) => {
      if (captchaRouteHit) {
        throw new PersonaAuthError('CAPTCHA_DETECTED', captchaAbortMessage(loginUrl))
      }
      const frameUrls = p.frames?.().map(f => f.url()) ?? []
      if (frameUrls.some(u => CAPTCHA_PATTERN.test(u))) {
        throw new PersonaAuthError('CAPTCHA_DETECTED', captchaAbortMessage(loginUrl))
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
        const scripts = Array.from(document.querySelectorAll('script[src]'))
          .map(s => s.getAttribute('src') || '')
        if (scripts.some(src => /challenges\.cloudflare\.com\/turnstile|google\.com\/recaptcha|hcaptcha\.com\/1\/api/i.test(src))) {
          return { captcha: true, mfa: false }
        }
        const text = (document.body?.innerText || '').slice(0, 4000)
        const captchaText = /verify you are human|complete the captcha|cloudflare security check/i.test(text)
        const mfaText = /two-factor|2fa code|authenticator app|enter verification code|second factor/i.test(text)
        return { captcha: captchaText, mfa: mfaText }
      })
      if (domCheck.captcha) {
        throw new PersonaAuthError('CAPTCHA_DETECTED', captchaAbortMessage(loginUrl))
      }
      if (domCheck.mfa) {
        throw new PersonaAuthError('MFA_REQUIRED', mfaAbortMessage(email))
      }
    }

    try {
      browser = await this.launchBrowser()
      context = await browser.newContext({ ignoreHTTPSErrors: false })
      await context.addInitScript?.(webrtcGuardScript)
      // WebSocket upgrades are never brokered HTTP. Only the target/login origins may open a
      // socket; everything else is closed before Chromium connects.
      if (typeof context.routeWebSocket === 'function') {
        await context.routeWebSocket('**/*', async ws => {
          try {
            const url = new URL(ws.url())
            const websocketOrigin = `${url.protocol === 'wss:' ? 'https:' : 'http:'}//${url.host}`
            if (!allowedOrigins.has(websocketOrigin)) {
              await ws.close({ code: 1008, reason: 'Blocked by Guardian scope.' })
              return
            }
            await ws.connectToServer?.()
          } catch {
            await ws.close({ code: 1008, reason: 'Blocked by Guardian scope.' })
          }
        })
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
        try {
          const origin = new URL(reqUrl).origin
          const method = (route.request().method?.() ?? 'GET').toUpperCase()
          const resourceType = route.request().resourceType?.() ?? 'document'
          const isReadOnly = method === 'GET' || method === 'HEAD'
          const exactAllowed = allowedOrigins.has(origin)
          const inScopeSubresource = isReadOnly && resourceType !== 'document' && isOriginInScope(origin, scopeForSubresources)
          if (!exactAllowed && !inScopeSubresource) {
            await route.abort('blockedbyclient')
            return
          }
          // Re-check DNS at request time: a hostname that rebinds to loopback/LAN/metadata after
          // discovery must never receive browser traffic.
          if (!(await this.hostIsSafeForBrowser(origin, scopeForSubresources))) {
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
      await page.goto(loginUrl, { waitUntil: 'domcontentloaded', timeout: this.timeoutMs })
      await page.waitForTimeout(400)

      // Strict Invariant #2: Check for CAPTCHA/Turnstile/MFA BEFORE interacting!
      await assertNoCaptchaInPage(page)

      const emailSelector = 'input[type="email"], input[name*="email" i], input[name="identifier"], input[name*="user" i], input[autocomplete="email"], input[autocomplete="username"]'
      const passwordSelector = 'input[type="password"]'
      const submitSelector = 'button[type="submit"], input[type="submit"], button:has-text("Sign in"), button:has-text("Log in"), button:has-text("Continue")'

      const emailInput = page.locator(emailSelector).first()
      if (await emailInput.count() === 0) {
        throw new PersonaAuthError('AUTH_FAILED', `Could not locate an email/username input on ${loginUrl}.`)
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
          throw new PersonaAuthError('AUTH_FAILED', `Could not locate a password input after submitting email on ${loginUrl}.`)
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
      for (const c of cookies) {
        if (c.name && c.value) cookieMap.set(c.name, c.value)
      }

      // Harvest Bearer JWTs from storage + intercepted XHR Authorization headers (SPA logins).
      const storageTokens = await harvestBrowserTokens(page)
      const harvested = [...storageTokens, ...interceptedBearer]
      const bearerToken = harvested.find(token => isJwtLike(token))

      if (cookieMap.size === 0 && !bearerToken) {
        throw new PersonaAuthError('INVALID_CREDENTIALS', `Form login on ${loginUrl} produced no session cookies or Bearer JWT for allowlisted origins.`)
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
        }
      }

      const cookieHeader = cookiesToHeader(cookieMap)
      const session: MintedPersonaSession = {
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
        // Broker-invoked 401 re-auth uses the existing refresh closure when available,
        // otherwise re-runs the full adapter (both are rate-limited to <=1/60s/persona).
        const reauthRefresh = result.refresh
        this.registerReauth(persona.handle, async () => {
          if (reauthRefresh) await reauthRefresh()
          else await this.authenticatePersona(storage, projectId, persona.id, signal)
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
