import type { PersonaLoginAdapter, PersonaLoginConfig } from '../domain.ts'
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
  request(): { url(): string }
  abort(errorCode?: string): Promise<void>
  continue(): Promise<void>
}

interface PlaywrightFormContext {
  route(url: string, handler: (route: PlaywrightFormRoute) => Promise<void> | void): Promise<void>
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

function deriveApexDomain(hostname: string): string {
  const parts = hostname.toLowerCase().split('.').filter(Boolean)
  if (parts.length <= 2) return hostname.toLowerCase()
  return parts.slice(-2).join('.')
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

async function launchDefaultChromium(): Promise<PlaywrightFormBrowserLike> {
  try {
    const coreName = 'playwright-core'
    const coreMod = await import(/* @vite-ignore */ coreName) as {
      chromium?: { launch: (opts: Record<string, unknown>) => Promise<PlaywrightFormBrowserLike> }
    }
    if (coreMod.chromium) {
      return await coreMod.chromium.launch({
        headless: true,
        args: ['--no-sandbox', '--disable-dev-shm-usage', '--disable-background-networking'],
      })
    }
  } catch {
    // Fallback to @playwright/test
  }
  const pw = await import('@playwright/test')
  return await pw.chromium.launch({
    headless: true,
    args: ['--no-sandbox', '--disable-dev-shm-usage', '--disable-background-networking'],
  }) as unknown as PlaywrightFormBrowserLike
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
    return await fetchImpl(url, { ...init, signal: controller.signal })
  } finally {
    clearTimeout(timer)
    outerSignal?.removeEventListener('abort', onOuterAbort)
  }
}

async function inspectTargetOrigin(
  fetchImpl: typeof fetch,
  targetOrigin: string,
  timeoutMs: number,
  signal?: AbortSignal,
): Promise<{ html: string; headers: Headers; clerkFapiOrigin: string | null; hasClerk: boolean }> {
  try {
    const res = await fetchWithTimeout(
      fetchImpl,
      targetOrigin,
      { method: 'GET', headers: { Accept: 'text/html,application/xhtml+xml,*/*' }, redirect: 'follow' },
      Math.min(timeoutMs, 8_000),
      signal,
    )
    const html = (await res.text()).slice(0, 250_000)
    let clerkFapiOrigin: string | null = null
    const pkMatch = /\b(pk_(?:live|test)_[A-Za-z0-9+/=_-]{12,})\b/.exec(html)
    if (pkMatch) {
      clerkFapiOrigin = decodeClerkPublishableKey(pkMatch[1])
    }
    if (!clerkFapiOrigin) {
      const fapiMatch = /https:\/\/(clerk\.[a-z0-9.-]+\.[a-z]{2,})/i.exec(html)
      if (fapiMatch) clerkFapiOrigin = `https://${fapiMatch[1].toLowerCase()}`
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
  private readonly runTimers = new Map<string, NodeJS.Timeout[]>()

  constructor(options: PersonaAuthManagerOptions = {}) {
    this.fetchImpl = options.fetchImpl ?? globalThis.fetch.bind(globalThis)
    this.launchBrowser = options.launchBrowser ?? launchDefaultChromium
    this.timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS
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
      const inspected = await inspectTargetOrigin(this.fetchImpl, targetOrigin, this.timeoutMs, signal)
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
    config: PersonaLoginConfig,
    targetOrigin: string,
    detectedFapiOrigin: string | null,
    signal?: AbortSignal,
  ): Promise<string> {
    if (config.loginUrl) {
      const parsed = new URL(config.loginUrl)
      // If operator supplied a Clerk FAPI URL (e.g. https://clerk.dyad.sh or http://127.0.0.1:4000 in tests),
      // use its origin directly. If it matches targetOrigin with a page path, still inspect HTML first.
      if (parsed.origin !== targetOrigin || /^clerk\./i.test(parsed.hostname) || parsed.pathname.includes('/v1/client')) {
        return parsed.origin
      }
    }
    if (detectedFapiOrigin) return detectedFapiOrigin
    const inspected = await inspectTargetOrigin(this.fetchImpl, targetOrigin, this.timeoutMs, signal)
    if (inspected.clerkFapiOrigin) return inspected.clerkFapiOrigin
    const host = new URL(targetOrigin).hostname
    return `https://clerk.${deriveApexDomain(host)}`
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
    const fapiOrigin = await this.resolveClerkFapiOrigin(config, targetOrigin, detectedClerkFapiOrigin, signal)
    const signInUrl = `${fapiOrigin}/v1/client/sign_ins`
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
    const loginUrl = config.loginUrl || `${targetOrigin}/api/auth/login`
    const emailField = config.emailField || 'email'
    const passwordField = config.passwordField || 'password'
    const res = await fetchWithTimeout(
      this.fetchImpl,
      loginUrl,
      {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Accept: 'application/json',
        },
        body: JSON.stringify({ [emailField]: email, [passwordField]: password }),
      },
      this.timeoutMs,
      signal,
    )

    const rawText = await res.text()
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

    // If tokenJsonPath is explicitly specified, prefer extracting that token as Bearer.
    if (config.tokenJsonPath && body) {
      const token = getJsonPath(body, config.tokenJsonPath)
      if (!token) {
        throw new PersonaAuthError('AUTH_FAILED', `JSON login succeeded (${res.status}) but tokenJsonPath "${config.tokenJsonPath}" was not found in response.`)
      }
      const claims = decodeJwtPayload(token)
      const expiresAt = claims?.exp ? claims.exp * 1000 : undefined
      writePersonaSessionFile(persona.sessionPath!, {
        headerType: 'bearer',
        value: token,
        expiresAt,
        adapterUsed: 'json',
        scrubTokens: [token],
      })
      return {
        personaId: persona.id,
        handle: persona.handle,
        adapterUsed: 'json',
        headerType: 'bearer',
        expiresAt,
      }
    }

    // Capture Set-Cookie headers first
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

    // Fall back to standard JSON token fields
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
        if (token) {
          const claims = decodeJwtPayload(token)
          const expiresAt = claims?.exp ? claims.exp * 1000 : undefined
          writePersonaSessionFile(persona.sessionPath!, {
            headerType: 'bearer',
            value: token,
            expiresAt,
            adapterUsed: 'json',
            scrubTokens: [token],
          })
          return {
            personaId: persona.id,
            handle: persona.handle,
            adapterUsed: 'json',
            headerType: 'bearer',
            expiresAt,
          }
        }
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
      await context.route('**/*', async route => {
        const reqUrl = route.request().url()
        if (CAPTCHA_PATTERN.test(reqUrl)) {
          captchaRouteHit = true
          await route.abort('blockedbyclient')
          return
        }
        try {
          const origin = new URL(reqUrl).origin
          if (!allowedOrigins.has(origin)) {
            await route.abort('blockedbyclient')
            return
          }
        } catch {
          await route.abort('blockedbyclient')
          return
        }
        await route.continue()
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
      if (cookieMap.size === 0) {
        throw new PersonaAuthError('INVALID_CREDENTIALS', `Form login on ${loginUrl} produced no session cookies for allowlisted origins.`)
      }

      const cookieHeader = cookiesToHeader(cookieMap)
      const session: MintedPersonaSession = {
        headerType: 'cookie',
        value: cookieHeader,
        adapterUsed: 'form',
        scrubTokens: [cookieHeader, ...cookieMap.values()],
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
