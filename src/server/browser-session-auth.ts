/**
 * Universal, IdP-agnostic Browser Session Authentication (`BrowserSessionAuth`).
 *
 * Works for every modern web app (Clerk, Auth0, Supabase, Firebase, NextAuth, Google/GitHub SSO,
 * Passkeys, MFA, CAPTCHAs) with ZERO IdP-specific code:
 *
 * 1. Interactive Login Capture via Embedded CDP Screencast (`startInteractiveLoginCapture`):
 *    - Launches an isolated Playwright Chromium context routed exclusively through
 *      `EgressGateway.createLoopbackProxy` (enforcing SSRF/metadata/scope policy).
 *    - Streams live JPEG frames + current URL over CDP `Page.startScreencast` (1280x800, quality ~75)
 *      and forwards mouse/keyboard/navigation events so operators can sign in directly inside Kovo's
 *      UI (including over Tailscale or inside Docker!).
 *    - On completion, snapshots full `context.storageState()` (cookies across app + IdP domains +
 *      `localStorage`) plus any observed `Authorization`/auth headers sent to `targetOrigin`, closes
 *      Chromium cleanly, and returns a storable `BrowserStorageBundle`.
 *    - Enforces strict TTL (default & max 5 min), single-use session IDs, and guaranteed cleanup.
 *
 * 2. Generic Headless `storageState` Auto-Refresh (`refreshBrowserSession`):
 *    - Loads the persisted `storageState` into a fresh headless Playwright context routed through
 *      `EgressGateway.createLoopbackProxy`.
 *    - Navigates to `targetOrigin + (verifyPath || '/')` and waits briefly (`networkidle` / ~2–4s)
 *      so the app's own client-side JS SDK automatically refreshes short-lived JWTs/cookies.
 *    - Captures updated cookies + `localStorage` + observed `Authorization` headers, atomically
 *      persists the updated `BrowserStorageBundle` back to disk (`0600`), and returns fresh
 *      `MintedPersonaSession` material.
 */
import { randomBytes, timingSafeEqual } from 'node:crypto'
import { assetOriginForEnvironment } from '../domain.ts'
import {
  classifyDetailedAddress,
  EgressGateway,
  isLoopbackLiteral,
} from './egress-gateway.ts'
import type { EgressLoopbackProxy } from './egress-gateway.ts'
import {
  buildSessionFromBrowserBundle,
  createBrowserSessionPersona,
  normalizeBrowserStorageBundle,
  normalizePlaywrightStorageState,
  updateBrowserSessionPersona,
  writeBrowserSessionCredentialFile,
} from './persona-vault.ts'
import type {
  BrowserStorageBundle,
  MintedPersonaSession,
  PlaywrightStorageCookie,
  PlaywrightStorageOrigin,
  PlaywrightStorageState,
} from './persona-vault.ts'
import type { Store } from './store.ts'

export type {
  BrowserStorageBundle,
  PlaywrightStorageCookie,
  PlaywrightStorageOrigin,
  PlaywrightStorageState,
}
import { isIpLiteralHost, isPublicSuffixHost, normalizeHostname } from './public-suffix.ts'
import {
  canonicalPathAndQuery,
  isRouteDenylisted,
  normalizeScopeOrigin,
  originRoleFor,
} from './scope-policy.ts'
import type { ScopePolicy } from './scope-policy.ts'

// ---------------------------------------------------------------------------
// Constants & Types
// ---------------------------------------------------------------------------

export const DEFAULT_CAPTURE_TTL_MS = 5 * 60 * 1000 // 5 minutes
export const MAX_CAPTURE_TTL_MS = 5 * 60 * 1000
export const DEFAULT_CAPTURE_ESCROW_TTL_MS = 5 * 60 * 1000 // 5 minutes
export const MAX_CAPTURE_ESCROW_TTL_MS = 5 * 60 * 1000
export const MAX_CAPTURE_ESCROW_ENTRIES = 64
export const CAPTURE_TOKEN_PREFIX = 'cap_tok_'
export const DEFAULT_CAPTURE_VIEWPORT = { width: 1280, height: 800 } as const
export const DEFAULT_SCREENCAST_QUALITY = 75
export const DEFAULT_REFRESH_SETTLE_MS = 2_500
export const DEFAULT_REFRESH_TIMEOUT_MS = 20_000
export const MAX_CONCURRENT_CAPTURES = 4

const OBSERVABLE_AUTH_HEADER_RE = /^(?:authorization|x-api-key|x-auth-token|x-access-token|x-csrf-token|x-xsrf-token)$/i
const JWT_SHAPE_RE = /^[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]*$/

const WEBRTC_GUARD_SCRIPT = `(() => {
  const deny = function () { throw new Error('WebRTC/WebTransport disabled inside Kovo Hunter browser sessions.'); };
  for (const name of ['RTCPeerConnection', 'webkitRTCPeerConnection', 'RTCDataChannel', 'WebTransport']) {
    try { Object.defineProperty(window, name, { configurable: false, writable: false, value: deny }); } catch {}
  }
})();`

const SOCKET_DENY_SCRIPT = `(() => {
  const deny = function () { throw new Error('WebSocket/WebTransport/WebRTC disabled inside Kovo Hunter browser sessions.'); };
  for (const name of ['WebSocket', 'WebTransport', 'RTCPeerConnection', 'webkitRTCPeerConnection', 'RTCDataChannel']) {
    try { Object.defineProperty(window, name, { configurable: false, writable: false, value: deny }); } catch {}
  }
})();`

export interface BrowserSessionChromiumLaunchOptions {
  readonly headless: true
  readonly chromiumSandbox: boolean
  readonly args: string[]
}

export class BrowserSessionRefreshBlockedError extends Error {
  readonly code = 'VERIFY_PATH_MODIFIED' as const

  constructor(message: string) {
    super(message)
    this.name = 'BrowserSessionRefreshBlockedError'
  }
}

export interface ScreencastFrame {
  /** Base64-encoded JPEG image frame. */
  data: string
  width: number
  height: number
  timestamp: number
  url: string
  title?: string
}

export type CaptureStreamEvent =
  | { type: 'frame'; frame: ScreencastFrame }
  | { type: 'url'; url: string }
  | { type: 'status'; state: CaptureSessionState; reason?: string }

export type CaptureSessionState = 'active' | 'completed' | 'canceled' | 'expired'

export interface CaptureMouseInput {
  type: 'mousePressed' | 'mouseReleased' | 'mouseMoved' | 'mouseWheel'
  x: number
  y: number
  button?: 'none' | 'left' | 'middle' | 'right'
  clickCount?: number
  deltaX?: number
  deltaY?: number
  modifiers?: number
}

export interface CaptureKeyInput {
  type: 'keyDown' | 'keyUp' | 'char' | 'insertText'
  key?: string
  code?: string
  text?: string
  windowsVirtualKeyCode?: number
  modifiers?: number
}

export interface PlaywrightCdpSessionLike {
  send(method: string, params?: Record<string, unknown>): Promise<unknown>
  on(event: string, listener: (payload: Record<string, unknown>) => void): void
  detach?(): Promise<void>
}

export interface PlaywrightPageLike {
  goto(url: string, options?: { waitUntil?: 'load' | 'domcontentloaded' | 'networkidle'; timeout?: number }): Promise<unknown>
  waitForLoadState?(state: 'load' | 'domcontentloaded' | 'networkidle', options?: { timeout?: number }): Promise<void>
  waitForTimeout(ms: number): Promise<void>
  url(): string
  title?(): Promise<string>
  on?(event: string, listener: (...args: unknown[]) => void): void
  evaluate?<T>(fn: () => T | Promise<T>): Promise<T>
  close(): Promise<void>
}

export interface PlaywrightRouteLike {
  request(): { url(): string; method(): string; headers(): Record<string, string> }
  continue(overrides?: { headers?: Record<string, string> }): Promise<void>
  abort(errorCode?: string): Promise<void>
}

export interface PlaywrightWebSocketRouteLike {
  url(): string
  close(options?: { code?: number; reason?: string }): Promise<void> | void
  connectToServer?(): Promise<void> | void
}

export interface PlaywrightContextLike {
  newPage(): Promise<PlaywrightPageLike>
  newCDPSession?(page: PlaywrightPageLike): Promise<PlaywrightCdpSessionLike>
  addInitScript?(script: string): Promise<void>
  route?(pattern: string, handler: (route: PlaywrightRouteLike) => Promise<void> | void): Promise<void>
  routeWebSocket?(pattern: string, handler: (ws: PlaywrightWebSocketRouteLike) => Promise<void> | void): Promise<void>
  storageState(): Promise<PlaywrightStorageState>
  close(): Promise<void>
}

export interface PlaywrightBrowserLike {
  newContext(options?: Record<string, unknown>): Promise<PlaywrightContextLike>
  close(): Promise<void>
}

export interface StartInteractiveCaptureOptions {
  projectId: string
  targetOrigin: string
  allowLocalLab?: boolean
  /** Optional additional allowlisted origins for observing target auth headers. */
  allowedOrigins?: readonly string[]
  /** Explicit, operator-approved IdP origins permitted during login capture. */
  idpOrigins?: readonly string[]
  /** Optional project ScopePolicy enforced on capture egress. */
  scopePolicy?: ScopePolicy
  /** Max capture session lifetime in ms (default & hard cap: 5 minutes). */
  ttlMs?: number
  viewport?: { width: number; height: number }
  jpegQuality?: number
  /** Optional callback invoked when the capture transitions to expired/canceled/completed. */
  onClosed?: (id: string, state: CaptureSessionState) => void
  /** Injectable browser launcher / DNS resolver for deterministic testing. */
  launchBrowser?: (opts: BrowserSessionChromiumLaunchOptions) => Promise<PlaywrightBrowserLike>
  resolveHost?: (hostname: string) => Promise<string[]>
}

export interface InteractiveLoginCaptureSession {
  readonly id: string
  readonly projectId: string
  readonly targetOrigin: string
  readonly createdAt: number
  readonly expiresAt: number
  readonly viewport: { width: number; height: number }
  readonly state: CaptureSessionState
  currentUrl(): string
  latestFrame(): ScreencastFrame | null
  subscribe(listener: (event: CaptureStreamEvent) => void): () => void
  dispatchMouse(input: CaptureMouseInput): Promise<void>
  dispatchKey(input: CaptureKeyInput): Promise<void>
  navigate(url: string): Promise<{ url: string }>
  completeCapture(): Promise<BrowserStorageBundle>
  cancelCapture(): Promise<void>
  dispose(): Promise<void>
}

export interface RefreshBrowserSessionOptions {
  storageState: PlaywrightStorageState
  targetOrigin: string
  /** Allowlisted origins for scoping extracted cookies/headers/storage (defaults to [targetOrigin]). */
  originAllowlist?: readonly string[]
  /** Explicit, operator-approved IdP origins (from login/IdP config — NEVER "any public HTTPS"). */
  idpOrigins?: readonly string[]
  /** Optional project ScopePolicy enforced on refresher proxy & browser routes. */
  scopePolicy?: ScopePolicy
  /**
   * Opt-in to preserve third-party cookies outside allowed persona + IdP origins when seeding
   * the refresher context (default `false`: third-party cookies are stripped fail-closed).
   */
  allowThirdPartyCookies?: boolean
  /** Paths or URLs known to have been modified by the active run; refresh refuses if `verifyPath` matches. */
  modifiedPaths?: readonly string[] | ReadonlySet<string>
  /** Explicit flag indicating `verifyPath` was modified by the active run; refuses automated refresh. */
  verifyPathModifiedByRun?: boolean
  /** Optional path on targetOrigin to visit so client JS SDK refreshes tokens (default '/'). */
  verifyPath?: string
  allowLocalLab?: boolean
  /** Brief wait after page load for client-side JS SDK token rotation (default 2500ms). */
  settleMs?: number
  /** Navigation timeout in ms (default 20_000). */
  timeoutMs?: number
  /** Previously observed auth headers from capture/prior refresh. */
  priorObservedHeaders?: Record<string, string>
  /** Optional path to persist updated BrowserStorageBundle back to disk (mode 0600). */
  persistBundlePath?: string
  signal?: AbortSignal
  /** Injectable browser launcher / DNS resolver for deterministic testing. */
  launchBrowser?: (opts: BrowserSessionChromiumLaunchOptions) => Promise<PlaywrightBrowserLike>
  resolveHost?: (hostname: string) => Promise<string[]>
}

export interface RefreshedBrowserSession {
  session: MintedPersonaSession
  bundle: BrowserStorageBundle
  cookiesCount: number
  observedHeaders: Record<string, string>
  expiresAt?: number
}

// ---------------------------------------------------------------------------
// Helpers: Validation, Proxy Setup & Chromium Launch
// ---------------------------------------------------------------------------

function assertAllowedBrowserHost(hostname: string, allowLocalLab: boolean, label: string): void {
  const host = normalizeHostname(hostname)
  if (!host) {
    throw new Error(`${label} must include a valid hostname.`)
  }
  if (
    host === 'metadata.google.internal'
    || host === 'metadata'
    || (isIpLiteralHost(host) && classifyDetailedAddress(host) === 'metadata_or_link_local')
  ) {
    throw new Error(`${label} cannot target cloud metadata or link-local addresses.`)
  }
  if (allowLocalLab) return
  if (
    isLoopbackLiteral(host)
    || host === 'localhost'
    || host.endsWith('.localhost')
    || host.endsWith('.local')
    || host.endsWith('.internal')
  ) {
    throw new Error(`${label} cannot target loopback or local hosts for public projects.`)
  }
  if (isIpLiteralHost(host)) {
    const cls = classifyDetailedAddress(host)
    if (cls !== 'public') {
      throw new Error(`${label} cannot target loopback, private, or non-public IP addresses for public projects.`)
    }
  }
}

function normalizeTargetOrigin(raw: string, allowLocalLab: boolean): URL {
  let parsed: URL
  try {
    parsed = new URL(raw.trim())
  } catch {
    throw new Error('targetOrigin must be a valid HTTP(S) origin.')
  }
  if (parsed.protocol !== 'https:' && parsed.protocol !== 'http:') {
    throw new Error('targetOrigin must use http:// or https://.')
  }
  if (parsed.username || parsed.password) {
    throw new Error('targetOrigin must not contain embedded credentials.')
  }
  if (parsed.protocol === 'http:' && !allowLocalLab) {
    throw new Error('Plaintext HTTP targetOrigin is blocked for public projects.')
  }
  assertAllowedBrowserHost(parsed.hostname, allowLocalLab, 'targetOrigin')
  return parsed
}

function normalizeVerifyPath(raw?: string): string {
  const trimmed = (raw ?? '/').trim()
  if (!trimmed) return '/'
  if (!trimmed.startsWith('/') || trimmed.startsWith('//')) {
    throw new Error('verifyPath must be a relative path starting with "/".')
  }
  return trimmed.slice(0, 512)
}

export function isInsecureNoSandboxEnabled(env: NodeJS.ProcessEnv = process.env): boolean {
  return env.KOVO_INSECURE_NO_SANDBOX === '1'
}

export function browserSessionChromiumArgs(
  options: { insecureNoSandbox?: boolean; env?: NodeJS.ProcessEnv } = {},
): string[] {
  const insecureNoSandbox = options.insecureNoSandbox ?? isInsecureNoSandboxEnabled(options.env)
  const args = [
    '--disable-dev-shm-usage',
    '--disable-background-networking',
    // Force all outbound connections (including loopback targets) through the EgressGateway proxy.
    '--proxy-bypass-list=<-loopback>',
    // Fail closed for any non-proxied Chromium DNS lookup; proxy itself runs on 127.0.0.1.
    '--host-resolver-rules=MAP * ~NOTFOUND, EXCLUDE 127.0.0.1',
    '--force-webrtc-ip-handling-policy=disable_non_proxied_udp',
    '--webrtc-ip-handling-policy=disable_non_proxied_udp',
    '--disable-quic',
    '--disable-features=WebTransport',
  ]
  if (insecureNoSandbox) {
    args.push('--no-sandbox')
  }
  return args
}

/**
 * Build Playwright `chromium.launch(...)` options for browser-session capture and refresh.
 * R3-H-6: Explicitly passes `chromiumSandbox: true` by default (playwright-core otherwise
 * injects `--no-sandbox` whenever `chromiumSandbox !== true`). Only disables the sandbox when
 * `KOVO_INSECURE_NO_SANDBOX === '1'` (or explicit `insecureNoSandbox: true` in tests).
 */
export function buildBrowserSessionChromiumLaunchOptions(
  options: { insecureNoSandbox?: boolean; env?: NodeJS.ProcessEnv } = {},
): BrowserSessionChromiumLaunchOptions {
  const insecureNoSandbox = options.insecureNoSandbox ?? isInsecureNoSandboxEnabled(options.env)
  return {
    headless: true,
    chromiumSandbox: !insecureNoSandbox,
    args: browserSessionChromiumArgs({ insecureNoSandbox }),
  }
}

export function formatChromiumSandboxLaunchError(err: unknown): Error {
  const detail = err instanceof Error ? err.message : String(err)
  return new Error(
    `Sandboxed Chromium failed to launch (chromiumSandbox: true). Refusing to fall back to --no-sandbox. `
    + `Enable unprivileged user namespaces or configure a Chromium seccomp profile on this host/container, `
    + `or explicitly opt out only in isolated environments with KOVO_INSECURE_NO_SANDBOX=1. `
    + `Underlying error: ${detail}`,
  )
}

async function resolvePlaywrightChromium(): Promise<{
  launch: (o: BrowserSessionChromiumLaunchOptions) => Promise<PlaywrightBrowserLike>
}> {
  try {
    const coreName = 'playwright-core'
    const coreMod = await import(/* @vite-ignore */ coreName) as {
      chromium?: { launch: (o: BrowserSessionChromiumLaunchOptions) => Promise<PlaywrightBrowserLike> }
    }
    if (coreMod.chromium) return coreMod.chromium
  } catch {
    // Fallback to @playwright/test when playwright-core cannot be imported directly.
  }
  const pw = await import('@playwright/test')
  return pw.chromium as unknown as {
    launch: (o: BrowserSessionChromiumLaunchOptions) => Promise<PlaywrightBrowserLike>
  }
}

async function launchDefaultBrowserSessionChromium(
  opts: BrowserSessionChromiumLaunchOptions,
): Promise<PlaywrightBrowserLike> {
  if (!opts.chromiumSandbox) {
    console.warn('WARNING: Chromium sandbox disabled (KOVO_INSECURE_NO_SANDBOX=1). Browser session isolation is reduced.')
  }
  const chromium = await resolvePlaywrightChromium()
  const launchOpts: BrowserSessionChromiumLaunchOptions = {
    headless: true,
    chromiumSandbox: opts.chromiumSandbox,
    args: opts.args,
  }
  try {
    return await chromium.launch(launchOpts)
  } catch (err) {
    if (launchOpts.chromiumSandbox) {
      throw formatChromiumSandboxLaunchError(err)
    }
    throw err
  }
}

export interface BrowserSessionEgressPolicy {
  readonly targetOrigin: string
  /** Target + persona.originAllowlist origins (intersected with ScopePolicy when provided). */
  readonly personaOrigins: ReadonlySet<string>
  /** Explicit, operator-approved IdP origins (from explicit IdP config and/or ScopePolicy.authOrigins). */
  readonly idpOrigins: ReadonlySet<string>
  /** Union of `personaOrigins` and `idpOrigins` — the ONLY origins permitted by the proxy. */
  readonly allowedOrigins: ReadonlySet<string>
  readonly allowLocalLab: boolean
  /** Effective ScopePolicy (with approved `idpOrigins` merged into `authOrigins`) when provided. */
  readonly scopePolicy?: ScopePolicy
}

function validateAndNormalizeOriginEntry(
  raw: string,
  allowLocalLab: boolean,
  label: string,
  strict: boolean,
): string | null {
  let parsed: URL
  try {
    parsed = new URL(raw.trim())
  } catch {
    if (strict) throw new Error(`${label} entry "${raw}" must be a valid HTTP(S) origin.`)
    return null
  }
  if (parsed.protocol !== 'https:' && parsed.protocol !== 'http:') {
    if (strict) throw new Error(`${label} entry "${raw}" must use http:// or https://.`)
    return null
  }
  if (parsed.username || parsed.password) {
    if (strict) throw new Error(`${label} entry "${raw}" must not contain embedded credentials.`)
    return null
  }
  if (parsed.protocol === 'http:' && !allowLocalLab) {
    if (strict) throw new Error(`Plaintext HTTP ${label} entry "${raw}" is blocked for public projects.`)
    return null
  }
  try {
    assertAllowedBrowserHost(parsed.hostname, allowLocalLab, label)
  } catch (err) {
    if (strict) throw err
    return null
  }
  return normalizeScopeOrigin(parsed.origin)
}

/**
 * R3-H-3: Resolve the strict egress policy for browser-session capture/refresh.
 * Egress is strictly scoped to:
 *   1. `persona.originAllowlist` (plus `targetOrigin`, intersected with `scopePolicy` when provided), AND
 *   2. Explicit, operator-approved IdP origins (`idpOrigins` + `scopePolicy.authOrigins`).
 * Arbitrary public HTTPS origins are NEVER permitted.
 */
export function resolveBrowserSessionEgressPolicy(params: {
  targetUrl: URL
  allowLocalLab: boolean
  allowedOrigins?: readonly string[]
  idpOrigins?: readonly string[]
  scopePolicy?: ScopePolicy
}): BrowserSessionEgressPolicy {
  const { targetUrl, allowLocalLab, allowedOrigins, idpOrigins, scopePolicy } = params
  const targetOrigin = normalizeScopeOrigin(targetUrl.origin)
  if (!targetOrigin) {
    throw new Error('targetOrigin must be a valid HTTP(S) origin.')
  }

  const approvedIdpSet = new Set<string>()
  for (const entry of idpOrigins ?? []) {
    const normalized = validateAndNormalizeOriginEntry(entry, allowLocalLab, 'idpOrigins', true)
    if (normalized) approvedIdpSet.add(normalized)
  }
  for (const entry of scopePolicy?.authOrigins ?? []) {
    const normalized = validateAndNormalizeOriginEntry(entry, allowLocalLab, 'scopePolicy.authOrigins', false)
    if (normalized) approvedIdpSet.add(normalized)
  }

  const effectiveScopePolicy: ScopePolicy | undefined = scopePolicy
    ? {
        ...scopePolicy,
        authOrigins: [...new Set([...(scopePolicy.authOrigins ?? []), ...approvedIdpSet])],
      }
    : undefined

  if (effectiveScopePolicy && originRoleFor(effectiveScopePolicy, targetOrigin) === null) {
    throw new Error(`targetOrigin "${targetOrigin}" is outside the project ScopePolicy.`)
  }

  const personaSet = new Set<string>([targetOrigin])
  for (const entry of allowedOrigins ?? []) {
    const normalized = validateAndNormalizeOriginEntry(entry, allowLocalLab, 'originAllowlist', false)
    if (!normalized) continue
    if (effectiveScopePolicy && originRoleFor(effectiveScopePolicy, normalized) === null) continue
    personaSet.add(normalized)
  }

  const unionSet = new Set<string>([...personaSet, ...approvedIdpSet])
  return {
    targetOrigin,
    personaOrigins: personaSet,
    idpOrigins: approvedIdpSet,
    allowedOrigins: unionSet,
    allowLocalLab,
    ...(effectiveScopePolicy ? { scopePolicy: effectiveScopePolicy } : {}),
  }
}

/**
 * R3-H-3: Fail-closed origin predicate for the browser-session loopback proxy and browser routes.
 * Permits ONLY origins in `policy.allowedOrigins` (persona allowlist + explicit approved IdP origins),
 * enforcing scheme, `allowLocalLab`, and optional `ScopePolicy` constraints.
 */
export function evaluateBrowserSessionProxyOrigin(
  policy: BrowserSessionEgressPolicy,
  origin: string,
  method: string,
  url: URL,
): { allowed: true } | { allowed: false; reason: string } {
  if (url.protocol !== 'https:' && url.protocol !== 'http:') {
    return { allowed: false, reason: `Browser session proxy refused unsupported scheme "${url.protocol}" for "${origin}".` }
  }
  if (url.protocol === 'http:' && !policy.allowLocalLab) {
    return { allowed: false, reason: `Browser session proxy refused plaintext HTTP origin "${origin}".` }
  }
  const normalized = normalizeScopeOrigin(origin) ?? normalizeScopeOrigin(url.origin)
  if (!normalized || !policy.allowedOrigins.has(normalized)) {
    return {
      allowed: false,
      reason: `Browser session proxy refused out-of-scope origin "${normalized ?? origin}" (not in persona allowlist or approved IdP origins).`,
    }
  }
  if (policy.scopePolicy) {
    const role = originRoleFor(policy.scopePolicy, normalized)
    if (!role) {
      return {
        allowed: false,
        reason: `Browser session proxy refused origin "${normalized}" outside project ScopePolicy.`,
      }
    }
    const upperMethod = (method || 'GET').toUpperCase()
    if (upperMethod !== 'CONNECT' && role === 'target') {
      const pathAndQuery = `${url.pathname}${url.search}`
      if (isRouteDenylisted(policy.scopePolicy, pathAndQuery)) {
        return {
          allowed: false,
          reason: `Browser session proxy refused denylisted route "${pathAndQuery}" on "${normalized}".`,
        }
      }
    }
  }
  return { allowed: true }
}

/**
 * Create an SSRF- and scope-enforcing `EgressGateway.createLoopbackProxy` for browser sessions.
 *
 * R3-H-3: Strictly limits egress to `persona.originAllowlist` (intersected with `scopePolicy` when
 * provided) plus explicit, operator-approved `idpOrigins`. Denies every other origin fail-closed.
 */
export async function createBrowserSessionProxy(params: {
  targetUrl: URL
  allowLocalLab: boolean
  allowedOrigins?: readonly string[]
  idpOrigins?: readonly string[]
  scopePolicy?: ScopePolicy
  egressPolicy?: BrowserSessionEgressPolicy
  resolveHost?: (hostname: string) => Promise<string[]>
  timeoutMs?: number
}): Promise<EgressLoopbackProxy> {
  const { resolveHost, timeoutMs } = params
  const egressPolicy = params.egressPolicy ?? resolveBrowserSessionEgressPolicy(params)
  const { allowLocalLab } = egressPolicy

  const allowedConnectTargets = new Set<string>()
  for (const origin of egressPolicy.allowedOrigins) {
    try {
      const parsed = new URL(origin)
      const normHost = normalizeHostname(parsed.hostname)
      const port = parsed.port ? Number(parsed.port) : (parsed.protocol === 'https:' ? 443 : 80)
      if (normHost && Number.isInteger(port) && port >= 1 && port <= 65_535) {
        allowedConnectTargets.add(`${normHost}:${port}`)
      }
    } catch {
      // Ignore malformed origin entries.
    }
  }

  return await EgressGateway.createLoopbackProxy({
    allowLocalLab,
    allowHttp: allowLocalLab ? true : undefined,
    allowedOrigins: [...egressPolicy.allowedOrigins],
    ...(egressPolicy.scopePolicy ? { scopePolicy: egressPolicy.scopePolicy } : {}),
    allowConnectPort: (port, hostname) => {
      if (!Number.isInteger(port) || port < 1 || port > 65_535) return false
      const normHost = normalizeHostname(hostname)
      if (!normHost) return false
      return allowedConnectTargets.has(`${normHost}:${port}`)
    },
    allowOrigin: (origin, method, url) => evaluateBrowserSessionProxyOrigin(egressPolicy, origin, method, url),
    ...(resolveHost ? { resolveHost } : {}),
    timeoutMs: timeoutMs ?? DEFAULT_REFRESH_TIMEOUT_MS,
    maxResponseBytes: 8 * 1024 * 1024,
  })
}

/**
 * Determine whether a cookie's `domain` applies to at least one origin in `allowedOrigins`.
 * Rejects public suffixes (e.g. `.com`, `.co.uk`, `.github.io`) so broad cookies can never match.
 */
export function cookieMatchesAllowedOrigins(
  cookieDomain: string,
  allowedOrigins: ReadonlySet<string>,
): boolean {
  const cleanCookie = normalizeHostname(cookieDomain.replace(/^\.+/, ''))
  if (!cleanCookie) return false
  if (!isIpLiteralHost(cleanCookie) && isPublicSuffixHost(cleanCookie)) return false
  for (const origin of allowedOrigins) {
    let originHost: string
    try {
      originHost = normalizeHostname(new URL(origin).hostname)
    } catch {
      continue
    }
    if (!originHost) continue
    if (isIpLiteralHost(originHost) || isIpLiteralHost(cleanCookie)) {
      if (originHost === cleanCookie) return true
    } else if (originHost === cleanCookie || originHost.endsWith(`.${cleanCookie}`)) {
      return true
    }
  }
  return false
}

/**
 * R3-H-3: Strip third-party cookies (and out-of-scope localStorage origins) from `storageState`
 * before seeding a refresher browser context, unless `allowThirdPartyCookies: true` is opted in.
 */
export function filterStorageStateForRefresh(
  storageState: PlaywrightStorageState,
  options: {
    allowedOrigins: ReadonlySet<string>
    allowThirdPartyCookies?: boolean
  },
): {
  storageState: PlaywrightStorageState
  droppedCookiesCount: number
  droppedOriginsCount: number
} {
  const { allowedOrigins, allowThirdPartyCookies = false } = options
  const keptCookies = allowThirdPartyCookies
    ? [...storageState.cookies]
    : storageState.cookies.filter(c => cookieMatchesAllowedOrigins(c.domain, allowedOrigins))
  const keptOrigins = storageState.origins.filter(entry => {
    const normalized = normalizeScopeOrigin(entry.origin)
    return Boolean(normalized && allowedOrigins.has(normalized))
  })
  return {
    storageState: {
      cookies: keptCookies,
      origins: keptOrigins,
    },
    droppedCookiesCount: storageState.cookies.length - keptCookies.length,
    droppedOriginsCount: storageState.origins.length - keptOrigins.length,
  }
}

function normalizePathnameForMatch(pathname: string): string {
  const trimmed = pathname.trim()
  if (!trimmed || trimmed === '/') return '/'
  return trimmed.endsWith('/') ? trimmed.slice(0, -1) : trimmed
}

/**
 * R3-H-3: Check whether `verifyPath` on `targetOrigin` matches any path or URL known to have
 * been modified by the active run (preventing automated JS refresh on stored-XSS / mutated routes).
 */
export function isVerifyPathModifiedByRun(
  verifyPath: string,
  targetOrigin: string,
  modifiedPaths?: readonly string[] | ReadonlySet<string>,
): boolean {
  if (!modifiedPaths) return false
  const entries = Array.isArray(modifiedPaths) ? modifiedPaths : [...modifiedPaths]
  if (entries.length === 0) return false
  const canonicalVerify = canonicalPathAndQuery(verifyPath) ?? verifyPath
  const verifyPathname = normalizePathnameForMatch(canonicalVerify.split('?', 1)[0] ?? '/')
  const normalizedTargetOrigin = normalizeScopeOrigin(targetOrigin)

  for (const rawEntry of entries) {
    if (typeof rawEntry !== 'string') continue
    const trimmed = rawEntry.trim()
    if (!trimmed) continue
    let candidatePath = trimmed
    if (/^https?:\/\//i.test(trimmed)) {
      try {
        const parsed = new URL(trimmed)
        const entryOrigin = normalizeScopeOrigin(parsed.origin)
        if (!entryOrigin || !normalizedTargetOrigin || entryOrigin !== normalizedTargetOrigin) continue
        candidatePath = `${parsed.pathname}${parsed.search}`
      } catch {
        continue
      }
    }
    if (candidatePath.endsWith('/*') || candidatePath.endsWith('/**')) {
      const prefix = normalizePathnameForMatch(candidatePath.replace(/\/\*+$/, ''))
      if (prefix === '/' || verifyPathname === prefix || verifyPathname.startsWith(`${prefix}/`)) {
        return true
      }
      continue
    }
    const canonicalEntry = canonicalPathAndQuery(candidatePath) ?? candidatePath
    if (canonicalEntry === canonicalVerify) return true
    const entryPathname = normalizePathnameForMatch(canonicalEntry.split('?', 1)[0] ?? '/')
    if (entryPathname === verifyPathname) return true
  }
  return false
}

async function installBrowserSessionContextGuards(
  context: PlaywrightContextLike,
  egressPolicy: BrowserSessionEgressPolicy,
): Promise<void> {
  await context.addInitScript?.(WEBRTC_GUARD_SCRIPT)
  if (typeof context.route === 'function') {
    await context.route('**/*', async route => {
      const req = route.request()
      const rawUrl = req.url()
      if (rawUrl.startsWith('about:')) {
        await route.continue()
        return
      }
      let parsed: URL
      try {
        parsed = new URL(rawUrl)
      } catch {
        await route.abort('blockedbyclient')
        return
      }
      const verdict = evaluateBrowserSessionProxyOrigin(egressPolicy, parsed.origin, req.method(), parsed)
      if (!verdict.allowed) {
        await route.abort('blockedbyclient')
        return
      }
      await route.continue()
    })
  }
  if (typeof context.routeWebSocket === 'function') {
    await context.routeWebSocket('**/*', async ws => {
      let parsed: URL
      try {
        parsed = new URL(ws.url())
      } catch {
        await ws.close({ code: 1008, reason: 'Blocked by Kovo Hunter browser session scope.' })
        return
      }
      if (parsed.protocol !== 'wss:' && !(egressPolicy.allowLocalLab && parsed.protocol === 'ws:')) {
        await ws.close({ code: 1008, reason: 'Blocked by Kovo Hunter browser session scope.' })
        return
      }
      const httpEquiv = new URL(parsed.toString().replace(/^wss:/i, 'https:').replace(/^ws:/i, 'http:'))
      const verdict = evaluateBrowserSessionProxyOrigin(egressPolicy, httpEquiv.origin, 'GET', httpEquiv)
      if (!verdict.allowed || typeof ws.connectToServer !== 'function') {
        await ws.close({ code: 1008, reason: 'Blocked by Kovo Hunter browser session scope.' })
        return
      }
      await ws.connectToServer()
    })
  } else {
    // Fail closed when Playwright lacks routeWebSocket: disable WebSocket constructors in-page.
    await context.addInitScript?.(SOCKET_DENY_SCRIPT)
  }
}

function createTargetRequestObserver(
  observedOrigins: ReadonlySet<string>,
  targetOrigin: string,
): {
  observedHeaders: Record<string, string>
  onRequest: (req: unknown) => void
} {
  const observedHeaders: Record<string, string> = {}
  const targetHost = (() => {
    try { return normalizeHostname(new URL(targetOrigin).hostname) } catch { return '' }
  })()

  const onRequest = (rawReq: unknown) => {
    if (!rawReq || typeof rawReq !== 'object') return
    const req = rawReq as { url?: () => string; headers?: () => Record<string, string> }
    if (typeof req.url !== 'function' || typeof req.headers !== 'function') return
    let reqUrl: URL
    try {
      reqUrl = new URL(req.url())
    } catch {
      return
    }
    const reqHost = normalizeHostname(reqUrl.hostname)
    const inTargetScope = observedOrigins.has(reqUrl.origin) || (Boolean(targetHost) && reqHost === targetHost)
    if (!inTargetScope) return

    const hdrs = req.headers()
    for (const [name, value] of Object.entries(hdrs)) {
      if (!OBSERVABLE_AUTH_HEADER_RE.test(name)) continue
      const trimmed = typeof value === 'string' ? value.trim() : ''
      if (!trimmed || /[\r\n\0]/.test(trimmed)) continue
      const canonical = name.toLowerCase() === 'authorization' ? 'Authorization' : name
      observedHeaders[canonical] = trimmed
    }
  }

  return { observedHeaders, onRequest }
}

function findJwtInStorage(storageState: PlaywrightStorageState, allowedOrigins: ReadonlySet<string>): string | null {
  const looksJwt = (v: string) => v.length > 40 && v.length < 8192 && v.startsWith('eyJ') && JWT_SHAPE_RE.test(v)
  const keyHint = /(?:token|jwt|auth|access|id_token|session)/i
  const visit = (val: unknown, depth: number): string | null => {
    if (depth > 3 || val === null || val === undefined) return null
    if (typeof val === 'string') {
      const t = val.trim()
      if (looksJwt(t)) return t
      if ((t.startsWith('{') || t.startsWith('"')) && t.length < 8192) {
        try { return visit(JSON.parse(t), depth + 1) } catch { return null }
      }
      return null
    }
    if (Array.isArray(val)) {
      for (const item of val.slice(0, 32)) {
        const hit = visit(item, depth + 1)
        if (hit) return hit
      }
      return null
    }
    if (typeof val === 'object') {
      for (const [k, v] of Object.entries(val as Record<string, unknown>)) {
        if (typeof v === 'string' && looksJwt(v) && (keyHint.test(k) || v.startsWith('eyJ'))) return v
        if (typeof v === 'object') {
          const hit = visit(v, depth + 1)
          if (hit) return hit
        }
      }
    }
    return null
  }

  for (const originEntry of storageState.origins) {
    if (!allowedOrigins.has(originEntry.origin)) continue
    for (const item of originEntry.localStorage) {
      const hit = visit(item.value, 0)
      if (hit) return hit
    }
  }
  return null
}

// ---------------------------------------------------------------------------
// 1. Interactive Login Capture via Embedded CDP Screencast
// ---------------------------------------------------------------------------

/**
 * Start a single-use, TTL-bounded interactive Chromium login capture session.
 * Traffic is routed through `EgressGateway.createLoopbackProxy` so SSRF/scope rules hold
 * even while operators sign in interactively over Tailscale or inside Docker.
 */
export async function startInteractiveLoginCapture(
  options: StartInteractiveCaptureOptions,
): Promise<InteractiveLoginCaptureSession> {
  const allowLocalLab = Boolean(options.allowLocalLab)
  const targetUrl = normalizeTargetOrigin(options.targetOrigin, allowLocalLab)
  const viewport = {
    width: Math.max(320, Math.min(1920, Math.floor(options.viewport?.width ?? DEFAULT_CAPTURE_VIEWPORT.width))),
    height: Math.max(240, Math.min(1200, Math.floor(options.viewport?.height ?? DEFAULT_CAPTURE_VIEWPORT.height))),
  }
  const jpegQuality = Math.max(25, Math.min(95, Math.floor(options.jpegQuality ?? DEFAULT_SCREENCAST_QUALITY)))
  const ttlMs = Math.max(1_000, Math.min(MAX_CAPTURE_TTL_MS, Math.floor(options.ttlMs ?? DEFAULT_CAPTURE_TTL_MS)))
  const id = `cap_${randomBytes(16).toString('hex')}`
  const createdAt = Date.now()
  const expiresAt = createdAt + ttlMs

  const egressPolicy = resolveBrowserSessionEgressPolicy({
    targetUrl,
    allowLocalLab,
    allowedOrigins: options.allowedOrigins,
    idpOrigins: options.idpOrigins,
    scopePolicy: options.scopePolicy,
  })
  const observedOrigins = new Set<string>(egressPolicy.personaOrigins)
  const { observedHeaders, onRequest } = createTargetRequestObserver(observedOrigins, targetUrl.origin)

  let proxy: EgressLoopbackProxy | undefined
  let browser: PlaywrightBrowserLike | undefined
  let context: PlaywrightContextLike | undefined
  let page: PlaywrightPageLike | undefined
  let cdp: PlaywrightCdpSessionLike | undefined

  const launch = options.launchBrowser ?? launchDefaultBrowserSessionChromium
  try {
    proxy = await createBrowserSessionProxy({
      targetUrl,
      allowLocalLab,
      egressPolicy,
      resolveHost: options.resolveHost,
    })
    browser = await launch(buildBrowserSessionChromiumLaunchOptions())
    context = await browser.newContext({
      viewport,
      ignoreHTTPSErrors: false,
      javaScriptEnabled: true,
      bypassCSP: false,
      serviceWorkers: 'block',
      proxy: proxy.proxyConfig,
    })
    await installBrowserSessionContextGuards(context, egressPolicy)
    page = await context.newPage()
    page.on?.('request', onRequest)
  } catch (err) {
    await page?.close().catch(() => undefined)
    await context?.close().catch(() => undefined)
    await browser?.close().catch(() => undefined)
    await proxy?.close().catch(() => undefined)
    throw err
  }

  let state: CaptureSessionState = 'active'
  let latestFrame: ScreencastFrame | null = null
  let lastKnownUrl = targetUrl.toString()
  let lastTitle = ''
  const listeners = new Set<(event: CaptureStreamEvent) => void>()
  let disposing: Promise<void> | null = null

  const emit = (event: CaptureStreamEvent) => {
    for (const listener of listeners) {
      try { listener(event) } catch { /* ignore broken subscriber */ }
    }
  }

  const cleanupResources = async (nextState: CaptureSessionState, reason?: string) => {
    if (disposing) return disposing
    if (state === 'active') state = nextState
    clearTimeout(ttlTimer)
    emit({ type: 'status', state, ...(reason ? { reason } : {}) })
    listeners.clear()
    options.onClosed?.(id, state)

    disposing = (async () => {
      try { await cdp?.send('Page.stopScreencast').catch(() => undefined) } catch { /* ignore */ }
      try { await cdp?.detach?.().catch(() => undefined) } catch { /* ignore */ }
      await page?.close().catch(() => undefined)
      await context?.close().catch(() => undefined)
      await browser?.close().catch(() => undefined)
      await proxy?.close().catch(() => undefined)
    })()
    await disposing
  }

  const ttlTimer = setTimeout(() => {
    void cleanupResources('expired', 'Capture session timed out after TTL.')
  }, ttlMs)
  ttlTimer.unref?.()

  page.on?.('framenavigated', () => {
    if (state !== 'active' || !page) return
    const nextUrl = page.url()
    if (nextUrl && nextUrl !== lastKnownUrl) {
      lastKnownUrl = nextUrl
      emit({ type: 'url', url: nextUrl })
    }
  })

  if (typeof context.newCDPSession === 'function') {
    try {
      cdp = await context.newCDPSession(page)
      cdp.on('Page.screencastFrame', payload => {
        const sessionId = payload.sessionId
        if (sessionId !== undefined && cdp) {
          void cdp.send('Page.screencastFrameAck', { sessionId }).catch(() => undefined)
        }
        if (state !== 'active') return
        const data = typeof payload.data === 'string' ? payload.data : ''
        if (!data) return
        const meta = (payload.metadata && typeof payload.metadata === 'object'
          ? payload.metadata as Record<string, unknown>
          : {})
        const url = page?.url() || lastKnownUrl
        if (url && url !== lastKnownUrl) {
          lastKnownUrl = url
          emit({ type: 'url', url })
        }
        const frame: ScreencastFrame = {
          data,
          width: typeof meta.deviceWidth === 'number' && meta.deviceWidth > 0 ? meta.deviceWidth : viewport.width,
          height: typeof meta.deviceHeight === 'number' && meta.deviceHeight > 0 ? meta.deviceHeight : viewport.height,
          timestamp: Date.now(),
          url: lastKnownUrl,
          ...(lastTitle ? { title: lastTitle } : {}),
        }
        latestFrame = frame
        emit({ type: 'frame', frame })
      })
      await cdp.send('Page.startScreencast', {
        format: 'jpeg',
        quality: jpegQuality,
        maxWidth: viewport.width,
        maxHeight: viewport.height,
        everyNthFrame: 1,
      })
    } catch {
      // CDP screencast may be unavailable in mock/non-Chromium test harnesses; capture still works.
    }
  }

  // Navigate asynchronously or await initial DOM load (best-effort so slow IdP redirects don't fail start).
  await page.goto(targetUrl.toString(), { waitUntil: 'domcontentloaded', timeout: 15_000 }).catch(() => undefined)
  lastKnownUrl = page.url() || targetUrl.toString()
  if (typeof page.title === 'function') {
    lastTitle = await page.title().catch(() => '')
  }

  const assertActive = () => {
    if (state !== 'active') {
      throw new Error(`Interactive login capture session is no longer active (${state}).`)
    }
  }

  return {
    id,
    projectId: options.projectId,
    targetOrigin: targetUrl.origin,
    createdAt,
    expiresAt,
    viewport,
    get state() {
      return state
    },
    currentUrl() {
      if (state === 'active' && page) {
        try {
          const u = page.url()
          if (u) lastKnownUrl = u
        } catch { /* ignore */ }
      }
      return lastKnownUrl
    },
    latestFrame() {
      return latestFrame
    },
    subscribe(listener) {
      if (state !== 'active') {
        listener({ type: 'status', state })
        return () => {}
      }
      listeners.add(listener)
      if (latestFrame) {
        listener({ type: 'frame', frame: latestFrame })
      } else {
        listener({ type: 'url', url: lastKnownUrl })
      }
      return () => {
        listeners.delete(listener)
      }
    },
    async dispatchMouse(input: CaptureMouseInput): Promise<void> {
      assertActive()
      if (!cdp) return
      const x = Math.max(0, Math.min(viewport.width, Number.isFinite(input.x) ? Math.round(input.x) : 0))
      const y = Math.max(0, Math.min(viewport.height, Number.isFinite(input.y) ? Math.round(input.y) : 0))
      const button = input.button ?? (input.type === 'mouseMoved' || input.type === 'mouseWheel' ? 'none' : 'left')
      const params: Record<string, unknown> = {
        type: input.type,
        x,
        y,
        button,
        modifiers: typeof input.modifiers === 'number' ? input.modifiers : 0,
      }
      if (input.type === 'mousePressed' || input.type === 'mouseReleased') {
        params.clickCount = Math.max(1, Math.min(3, Math.floor(input.clickCount ?? 1)))
      }
      if (input.type === 'mouseWheel') {
        params.deltaX = Number.isFinite(input.deltaX) ? input.deltaX : 0
        params.deltaY = Number.isFinite(input.deltaY) ? input.deltaY : 0
      }
      await cdp.send('Input.dispatchMouseEvent', params)
    },
    async dispatchKey(input: CaptureKeyInput): Promise<void> {
      assertActive()
      if (!cdp) return
      if (input.type === 'insertText') {
        if (typeof input.text === 'string' && input.text.length > 0) {
          await cdp.send('Input.insertText', { text: input.text.slice(0, 4096) })
        }
        return
      }
      const params: Record<string, unknown> = {
        type: input.type,
        modifiers: typeof input.modifiers === 'number' ? input.modifiers : 0,
      }
      if (typeof input.key === 'string') params.key = input.key
      if (typeof input.code === 'string') params.code = input.code
      if (typeof input.text === 'string') params.text = input.text
      if (typeof input.windowsVirtualKeyCode === 'number') {
        params.windowsVirtualKeyCode = input.windowsVirtualKeyCode
        params.nativeVirtualKeyCode = input.windowsVirtualKeyCode
      }
      await cdp.send('Input.dispatchKeyEvent', params)
    },
    async navigate(rawUrl: string): Promise<{ url: string }> {
      assertActive()
      let parsed: URL
      try {
        parsed = new URL(rawUrl.trim())
      } catch {
        throw new Error('Navigation URL must be a valid HTTP(S) URL.')
      }
      if (parsed.protocol !== 'https:' && parsed.protocol !== 'http:') {
        throw new Error('Navigation URL must use http:// or https://.')
      }
      if (parsed.username || parsed.password) {
        throw new Error('Navigation URL must not contain embedded credentials.')
      }
      if (parsed.protocol === 'http:' && !allowLocalLab) {
        throw new Error('Plaintext HTTP navigation is blocked outside local-lab mode.')
      }
      assertAllowedBrowserHost(parsed.hostname, allowLocalLab, 'Navigation URL')
      const verdict = evaluateBrowserSessionProxyOrigin(egressPolicy, parsed.origin, 'GET', parsed)
      if (!verdict.allowed) {
        throw new Error(verdict.reason)
      }
      await page!.goto(parsed.toString(), { waitUntil: 'domcontentloaded', timeout: 15_000 })
      lastKnownUrl = page!.url() || parsed.toString()
      emit({ type: 'url', url: lastKnownUrl })
      return { url: lastKnownUrl }
    },
    async completeCapture(): Promise<BrowserStorageBundle> {
      assertActive()
      state = 'completed'
      try {
        const rawState = await context!.storageState()
        const storageState = normalizePlaywrightStorageState(rawState)
        const headers: Record<string, string> = { ...observedHeaders }
        if (!headers.Authorization) {
          const storageJwt = findJwtInStorage(storageState, observedOrigins)
          if (storageJwt) headers.Authorization = `Bearer ${storageJwt}`
        }
        return normalizeBrowserStorageBundle(
          {
            v: 1,
            kind: 'browser_session',
            targetOrigin: targetUrl.origin,
            capturedAt: Date.now(),
            storageState,
            ...(Object.keys(headers).length ? { observedHeaders: headers } : {}),
          },
          targetUrl.origin,
        )
      } finally {
        await cleanupResources('completed')
      }
    },
    async cancelCapture(): Promise<void> {
      await cleanupResources('canceled', 'Capture session canceled by operator.')
    },
    async dispose(): Promise<void> {
      await cleanupResources(state === 'active' ? 'canceled' : state)
    },
  }
}

// ---------------------------------------------------------------------------
// Server-Side Capture Escrow (Single-Use captureToken, Project-Bound, 5m TTL)
// ---------------------------------------------------------------------------

export interface CaptureSummary {
  targetOrigin: string
  capturedAt: number
  cookieCount: number
  originCount: number
  /** Safe non-secret list of origins present in storageState (never localStorage values). */
  origins: string[]
  /** Safe non-secret list of observed auth header names (never header values). */
  headerNames: string[]
  hasAuthorizationHeader: boolean
}

export interface EscrowedCapture {
  readonly captureToken: string
  readonly projectId: string
  readonly expiresAt: number
  readonly summary: CaptureSummary
}

interface CaptureEscrowRecord {
  readonly projectId: string
  readonly bundle: BrowserStorageBundle
  readonly createdAt: number
  readonly expiresAt: number
  readonly timer: ReturnType<typeof setTimeout>
}

export function summarizeBrowserStorageBundle(bundle: BrowserStorageBundle): CaptureSummary {
  const originSet = new Set<string>()
  for (const entry of bundle.storageState.origins) {
    if (entry.origin) originSet.add(entry.origin)
  }
  const headerNames = Object.keys(bundle.observedHeaders ?? {}).sort()
  return {
    targetOrigin: bundle.targetOrigin,
    capturedAt: bundle.capturedAt,
    cookieCount: bundle.storageState.cookies.length,
    originCount: bundle.storageState.origins.length,
    origins: [...originSet].sort(),
    headerNames,
    hasAuthorizationHeader: Boolean(bundle.observedHeaders?.Authorization),
  }
}

function constantTimeStringEqual(a: string, b: string): boolean {
  const bufA = Buffer.from(a, 'utf8')
  const bufB = Buffer.from(b, 'utf8')
  if (bufA.length !== bufB.length) return false
  return timingSafeEqual(bufA, bufB)
}

/**
 * Process-local server-side escrow holding completed `BrowserStorageBundle` secrets so raw
 * cookies, localStorage values, and Authorization headers NEVER leave the server during
 * interactive login capture.
 */
export class CaptureEscrowStore {
  private readonly entries = new Map<string, CaptureEscrowRecord>()
  private readonly defaultTtlMs: number
  private readonly maxEntries: number
  private readonly now: () => number

  constructor(options: { ttlMs?: number; maxEntries?: number; now?: () => number } = {}) {
    this.defaultTtlMs = Math.max(1_000, Math.min(MAX_CAPTURE_ESCROW_TTL_MS, Math.floor(options.ttlMs ?? DEFAULT_CAPTURE_ESCROW_TTL_MS)))
    this.maxEntries = Math.max(1, Math.floor(options.maxEntries ?? MAX_CAPTURE_ESCROW_ENTRIES))
    this.now = options.now ?? Date.now
  }

  private deleteKey(token: string): void {
    const existing = this.entries.get(token)
    if (!existing) return
    clearTimeout(existing.timer)
    this.entries.delete(token)
  }

  pruneExpired(): number {
    const currentMs = this.now()
    let removed = 0
    for (const [token, record] of this.entries) {
      if (record.expiresAt <= currentMs) {
        this.deleteKey(token)
        removed += 1
      }
    }
    return removed
  }

  get size(): number {
    this.pruneExpired()
    return this.entries.size
  }

  has(captureToken: string): boolean {
    this.pruneExpired()
    const entry = this.entries.get(captureToken)
    return Boolean(entry && entry.expiresAt > this.now())
  }

  store(params: {
    projectId: string
    bundle: BrowserStorageBundle
    ttlMs?: number
  }): EscrowedCapture {
    const projectId = params.projectId.trim()
    if (!projectId) {
      throw new Error('projectId is required to escrow a captured browser session.')
    }
    this.pruneExpired()
    while (this.entries.size >= this.maxEntries) {
      const oldest = this.entries.keys().next().value
      if (oldest === undefined) break
      this.deleteKey(oldest)
    }

    const ttlMs = Math.max(
      1_000,
      Math.min(MAX_CAPTURE_ESCROW_TTL_MS, Math.floor(params.ttlMs ?? this.defaultTtlMs)),
    )
    const createdAt = this.now()
    const expiresAt = createdAt + ttlMs
    const captureToken = `${CAPTURE_TOKEN_PREFIX}${randomBytes(32).toString('hex')}`
    const timer = setTimeout(() => {
      this.deleteKey(captureToken)
    }, ttlMs)
    timer.unref?.()

    this.entries.set(captureToken, {
      projectId,
      bundle: params.bundle,
      createdAt,
      expiresAt,
      timer,
    })

    return {
      captureToken,
      projectId,
      expiresAt,
      summary: summarizeBrowserStorageBundle(params.bundle),
    }
  }

  redeem(captureToken: string, projectId: string): BrowserStorageBundle {
    this.pruneExpired()
    const token = captureToken.trim()
    const requestedProjectId = projectId.trim()
    if (!/^cap_tok_[a-f0-9]{64}$/.test(token)) {
      throw new Error('Captured browser session token is invalid, already used, or expired. Sign in again.')
    }
    const entry = this.entries.get(token)
    if (!entry || entry.expiresAt <= this.now()) {
      this.deleteKey(token)
      throw new Error('Captured browser session token is invalid, already used, or expired. Sign in again.')
    }
    if (!requestedProjectId || !constantTimeStringEqual(entry.projectId, requestedProjectId)) {
      throw new Error('Captured browser session token does not belong to this project.')
    }
    // Single-use: delete immediately before returning the bundle.
    this.deleteKey(token)
    return entry.bundle
  }

  clear(): void {
    for (const token of [...this.entries.keys()]) {
      this.deleteKey(token)
    }
  }
}

const CAPTURE_ESCROW_SYMBOL = Symbol.for('kovo.authCaptureEscrowStore')

/**
 * Process-wide shared escrow singleton (bridging `scripts/serve.ts` and `build/server/server.js`).
 */
export function getCaptureEscrowStore(): CaptureEscrowStore {
  const g = globalThis as Record<symbol, CaptureEscrowStore | undefined>
  let store = g[CAPTURE_ESCROW_SYMBOL]
  if (!store) {
    store = new CaptureEscrowStore()
    g[CAPTURE_ESCROW_SYMBOL] = store
  }
  return store
}

export function redeemCapturedBrowserSession(
  captureToken: string,
  projectId: string,
): BrowserStorageBundle {
  return getCaptureEscrowStore().redeem(captureToken, projectId)
}

function validateBrowserPersonaOrigins(
  environment: 'public' | 'local-lab',
  origins: readonly string[],
): string[] {
  const validator = assetOriginForEnvironment(environment)
  return origins.map(origin => {
    const parsed = validator.safeParse(origin)
    if (!parsed.success) {
      throw new Error(parsed.error.issues[0]?.message ?? `Origin "${origin}" is not allowed for this ${environment} project.`)
    }
    return parsed.data
  })
}

export function registerBrowserSessionPersonaFromAction(
  db: Store,
  data: {
    requestId: string
    projectId: string
    handle: string
    roleLabel: string
    originAllowlist: string[]
    captureToken?: string
    storageState?: unknown
    observedHeaders?: Record<string, string>
    verifyPath?: string
    refreshIntervalSec?: number
    canaryMarkers?: string[]
  },
  escrow: CaptureEscrowStore = getCaptureEscrowStore(),
): { id: string; handle: string } {
  const project = db.project(data.projectId)
  const originAllowlist = validateBrowserPersonaOrigins(project.environment, data.originAllowlist)
  const resolvedStorageState = data.captureToken
    ? escrow.redeem(data.captureToken, data.projectId)
    : data.storageState
  if (resolvedStorageState === undefined) {
    throw new Error('Provide either a captured session token or a storageState.json payload.')
  }
  return createBrowserSessionPersona(db, {
    requestId: data.requestId,
    projectId: data.projectId,
    handle: data.handle,
    roleLabel: data.roleLabel,
    originAllowlist,
    storageState: resolvedStorageState,
    observedHeaders: data.observedHeaders,
    verifyPath: data.verifyPath,
    refreshIntervalSec: data.refreshIntervalSec,
    canaryMarkers: data.canaryMarkers,
  })
}

export function updateBrowserSessionPersonaFromAction(
  db: Store,
  data: {
    requestId: string
    projectId: string
    personaId: string
    roleLabel: string
    originAllowlist: string[]
    captureToken?: string
    storageState?: unknown
    observedHeaders?: Record<string, string>
    verifyPath?: string
    refreshIntervalSec?: number
    canaryMarkers?: string[]
  },
  escrow: CaptureEscrowStore = getCaptureEscrowStore(),
): { id: string; handle: string } {
  const project = db.project(data.projectId)
  const originAllowlist = validateBrowserPersonaOrigins(project.environment, data.originAllowlist)
  const resolvedStorageState = data.captureToken
    ? escrow.redeem(data.captureToken, data.projectId)
    : data.storageState
  return updateBrowserSessionPersona(db, {
    requestId: data.requestId,
    projectId: data.projectId,
    personaId: data.personaId,
    roleLabel: data.roleLabel,
    originAllowlist,
    ...(resolvedStorageState !== undefined ? { storageState: resolvedStorageState } : {}),
    observedHeaders: data.observedHeaders,
    verifyPath: data.verifyPath,
    refreshIntervalSec: data.refreshIntervalSec,
    canaryMarkers: data.canaryMarkers,
  })
}

// ---------------------------------------------------------------------------
// Capture Registry (Single-Use IDs, Bounded Concurrency, Guaranteed Cleanup)
// ---------------------------------------------------------------------------

export class BrowserCaptureManager {
  private readonly sessions = new Map<string, InteractiveLoginCaptureSession>()
  private readonly maxConcurrent: number
  readonly escrow: CaptureEscrowStore

  constructor(options: { maxConcurrent?: number; escrow?: CaptureEscrowStore } = {}) {
    this.maxConcurrent = Math.max(1, options.maxConcurrent ?? MAX_CONCURRENT_CAPTURES)
    this.escrow = options.escrow ?? getCaptureEscrowStore()
  }

  get activeCount(): number {
    this.pruneInactive()
    return this.sessions.size
  }

  private pruneInactive(): void {
    for (const [id, session] of this.sessions) {
      if (session.state !== 'active') this.sessions.delete(id)
    }
  }

  async startCapture(options: Omit<StartInteractiveCaptureOptions, 'onClosed'>): Promise<InteractiveLoginCaptureSession> {
    this.pruneInactive()
    if (this.sessions.size >= this.maxConcurrent) {
      throw new Error(`Maximum concurrent browser sign-in sessions (${this.maxConcurrent}) reached. Close an existing capture first.`)
    }
    const session = await startInteractiveLoginCapture({
      ...options,
      onClosed: id => {
        this.sessions.delete(id)
      },
    })
    this.sessions.set(session.id, session)
    return session
  }

  get(id: string): InteractiveLoginCaptureSession | null {
    this.pruneInactive()
    const session = this.sessions.get(id)
    if (!session || session.state !== 'active') {
      this.sessions.delete(id)
      return null
    }
    return session
  }

  async complete(id: string): Promise<BrowserStorageBundle> {
    const session = this.get(id)
    if (!session) throw new Error('Capture session not found or already closed.')
    // Remove immediately to guarantee single-use semantics even under concurrent calls.
    this.sessions.delete(id)
    return await session.completeCapture()
  }

  async completeToEscrow(id: string, options?: { ttlMs?: number }): Promise<EscrowedCapture> {
    const session = this.get(id)
    if (!session) throw new Error('Capture session not found or already closed.')
    const projectId = session.projectId
    // Remove immediately to guarantee single-use semantics even under concurrent calls.
    this.sessions.delete(id)
    const bundle = await session.completeCapture()
    return this.escrow.store({
      projectId,
      bundle,
      ...(options?.ttlMs !== undefined ? { ttlMs: options.ttlMs } : {}),
    })
  }

  async cancel(id: string): Promise<boolean> {
    const session = this.sessions.get(id)
    if (!session) return false
    this.sessions.delete(id)
    await session.cancelCapture()
    return true
  }

  async disposeAll(): Promise<void> {
    const active = [...this.sessions.values()]
    this.sessions.clear()
    await Promise.all(active.map(s => s.dispose().catch(() => undefined)))
  }
}

let defaultCaptureManager: BrowserCaptureManager | undefined

export function getBrowserCaptureManager(): BrowserCaptureManager {
  defaultCaptureManager ??= new BrowserCaptureManager()
  return defaultCaptureManager
}

// ---------------------------------------------------------------------------
// 2. Generic Headless `storageState` Auto-Refresh (ZERO IdP-specific code!)
// ---------------------------------------------------------------------------

/**
 * Load a persisted Playwright `storageState` into a fresh headless Chromium context routed
 * through `EgressGateway.createLoopbackProxy`, navigate to `targetOrigin + verifyPath`, wait
 * briefly so the app's own JS SDK rotates any short-lived JWT/session cookies, persist the
 * refreshed `storageState` back to disk (`0600`), and return fresh `MintedPersonaSession` material.
 */
export async function refreshBrowserSession(
  options: RefreshBrowserSessionOptions,
): Promise<RefreshedBrowserSession> {
  if (options.signal?.aborted) {
    throw new Error('Browser session refresh aborted.')
  }
  const allowLocalLab = Boolean(options.allowLocalLab)
  const targetUrl = normalizeTargetOrigin(options.targetOrigin, allowLocalLab)
  const verifyPath = normalizeVerifyPath(options.verifyPath)
  if (options.verifyPathModifiedByRun || isVerifyPathModifiedByRun(verifyPath, targetUrl.origin, options.modifiedPaths)) {
    throw new BrowserSessionRefreshBlockedError(
      `Refusing automated browser session refresh on "${verifyPath}": path was modified by the active run.`,
    )
  }

  const visitUrl = `${targetUrl.origin}${verifyPath}`
  const settleMs = Math.max(200, Math.min(10_000, Math.floor(options.settleMs ?? DEFAULT_REFRESH_SETTLE_MS)))
  const timeoutMs = Math.max(2_000, Math.min(60_000, Math.floor(options.timeoutMs ?? DEFAULT_REFRESH_TIMEOUT_MS)))
  const originAllowlist = options.originAllowlist && options.originAllowlist.length > 0
    ? [...new Set(options.originAllowlist)]
    : [targetUrl.origin]

  const egressPolicy = resolveBrowserSessionEgressPolicy({
    targetUrl,
    allowLocalLab,
    allowedOrigins: originAllowlist,
    idpOrigins: options.idpOrigins,
    scopePolicy: options.scopePolicy,
  })
  const inputStorageState = normalizePlaywrightStorageState(options.storageState)
  const { storageState: filteredInputStorageState } = filterStorageStateForRefresh(inputStorageState, {
    allowedOrigins: egressPolicy.allowedOrigins,
    allowThirdPartyCookies: options.allowThirdPartyCookies,
  })
  // H-8 credential isolation: observe and extract target auth headers strictly on persona origins
  // (never on external IdP origins).
  const observedOrigins = new Set<string>(egressPolicy.personaOrigins)
  const { observedHeaders, onRequest } = createTargetRequestObserver(observedOrigins, targetUrl.origin)

  let proxy: EgressLoopbackProxy | undefined
  let browser: PlaywrightBrowserLike | undefined
  let context: PlaywrightContextLike | undefined
  let page: PlaywrightPageLike | undefined

  const launch = options.launchBrowser ?? launchDefaultBrowserSessionChromium
  const onAbort = () => {
    void page?.close().catch(() => undefined)
    void context?.close().catch(() => undefined)
    void browser?.close().catch(() => undefined)
    void proxy?.close().catch(() => undefined)
  }
  options.signal?.addEventListener('abort', onAbort, { once: true })

  try {
    proxy = await createBrowserSessionProxy({
      targetUrl,
      allowLocalLab,
      egressPolicy,
      resolveHost: options.resolveHost,
      timeoutMs,
    })
    browser = await launch(buildBrowserSessionChromiumLaunchOptions())
    context = await browser.newContext({
      storageState: filteredInputStorageState,
      ignoreHTTPSErrors: false,
      javaScriptEnabled: true,
      bypassCSP: false,
      serviceWorkers: 'block',
      proxy: proxy.proxyConfig,
    })
    await installBrowserSessionContextGuards(context, egressPolicy)
    page = await context.newPage()
    page.on?.('request', onRequest)

    await page.goto(visitUrl, { waitUntil: 'domcontentloaded', timeout: timeoutMs })
    if (options.signal?.aborted) throw new Error('Browser session refresh aborted.')

    // Wait briefly for networkidle + client-side JS SDK background token refresh (e.g. Clerk/Auth0/Supabase/NextAuth).
    if (typeof page.waitForLoadState === 'function') {
      await page.waitForLoadState('networkidle', { timeout: Math.min(settleMs, 4_000) }).catch(() => undefined)
    }
    await page.waitForTimeout(Math.min(settleMs, 1_500))
    if (options.signal?.aborted) throw new Error('Browser session refresh aborted.')

    const rawFreshState = await context.storageState()
    const normalizedFreshState = normalizePlaywrightStorageState(rawFreshState)
    const { storageState: freshStorageState } = filterStorageStateForRefresh(normalizedFreshState, {
      allowedOrigins: egressPolicy.allowedOrigins,
      allowThirdPartyCookies: options.allowThirdPartyCookies,
    })

    // Merge newly observed headers over prior headers (fresh wins).
    const mergedHeaders: Record<string, string> = {
      ...(options.priorObservedHeaders ?? {}),
      ...observedHeaders,
    }
    if (!observedHeaders.Authorization) {
      const freshJwt = findJwtInStorage(freshStorageState, observedOrigins)
      if (freshJwt) {
        mergedHeaders.Authorization = `Bearer ${freshJwt}`
      }
    }

    const updatedBundle = normalizeBrowserStorageBundle(
      {
        v: 1,
        kind: 'browser_session',
        targetOrigin: targetUrl.origin,
        capturedAt: Date.now(),
        storageState: freshStorageState,
        ...(Object.keys(mergedHeaders).length ? { observedHeaders: mergedHeaders } : {}),
      },
      targetUrl.origin,
    )

    // Collect old + new cookie values for scrubbing after rotation.
    const priorSecrets = inputStorageState.cookies.map(c => c.value).filter(v => v.length >= 4)
    const session = buildSessionFromBrowserBundle(updatedBundle, [...egressPolicy.personaOrigins], priorSecrets)

    if (options.persistBundlePath) {
      writeBrowserSessionCredentialFile(options.persistBundlePath, updatedBundle)
    }

    return {
      session,
      bundle: updatedBundle,
      cookiesCount: updatedBundle.storageState.cookies.length,
      observedHeaders: mergedHeaders,
      ...(session.expiresAt ? { expiresAt: session.expiresAt } : {}),
    }
  } finally {
    options.signal?.removeEventListener('abort', onAbort)
    await page?.close().catch(() => undefined)
    await context?.close().catch(() => undefined)
    await browser?.close().catch(() => undefined)
    await proxy?.close().catch(() => undefined)
  }
}
