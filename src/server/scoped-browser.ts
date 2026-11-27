import { randomBytes } from 'node:crypto'
import { containsDestructivePayload } from '../replay-spec.ts'
import type { BrowserBuiltinCheck, CsrfBind } from '../replay-spec.ts'
import { constantTimeStringEqual } from './safety-primitives.ts'
import { BrokerDenied, RequestBroker } from './broker.ts'
import type { BrokerExchangeResult, Grant } from './broker.ts'
import { scanSecondOrderMarkers } from './canary-broker.ts'
import type { SecondOrderStore } from './canary-broker.ts'
import {
  buildChromiumLaunchArgs,
  buildPlaywrightChromiumLaunchOptions,
  formatChromiumSandboxError,
  isChromiumSandboxFailure,
  isInsecureNoSandboxEnabled,
  launchPlaywrightChromium,
  type ChromiumPlaywrightLauncher,
  type PlaywrightChromiumLaunchOptions,
} from './chromium-launch.ts'
import { cookieRecordsFromHeader } from './persona-auth.ts'
export { formatChromiumSandboxError, isChromiumSandboxFailure, isInsecureNoSandboxEnabled }
export type { PlaywrightChromiumLaunchOptions }
import { buildPersonaBrowserAttachment, personaSecrets } from './persona-vault.ts'
import { EgressGateway } from './egress-gateway.ts'
import type { EgressLoopbackProxy, LoopbackProxyContextBinding } from './egress-gateway.ts'
import { createEgressSanitizer } from './egress-sanitizer.ts'
import { isIpLiteralHost } from './public-suffix.ts'
import { redact } from './redact.ts'
import type { NamedSecret } from './redact.ts'
import { evaluateBrowserScopeRequest, isRouteDenylisted } from './scope-policy.ts'
import type { ScopePolicy } from './scope-policy.ts'

export interface BrowserSameSiteFetchRequest {
  origin: string
  pathAndQuery: string
  method?: 'GET' | 'HEAD' | 'OPTIONS'
  credentials?: 'include' | 'same-origin' | 'omit'
}

/** A cookie lifted from a persona session bundle; `httpOnly` is preserved for real hydration. */
export interface BrowserSeedCookie {
  name: string
  value: string
  domain: string
  path: string
  secure?: boolean
  httpOnly?: boolean
  sameSite?: 'Strict' | 'Lax' | 'None'
  expires?: number
}

/**
 * Session material for a single persona. The vault is owned by another stream, so this bundle is
 * resolved through an optional hook / structural fields and never requires a schema change here.
 */
export interface BrowserSessionBundle {
  cookies?: BrowserSeedCookie[]
  localStorage?: Record<string, string>
  sessionStorage?: Record<string, string>
  /** Pre-built storage hydration script (v6-auth `storageHydrationScript()`). */
  initScript?: string | null
  /** Per-origin request headers attached to the persona (broker still injects on the wire). */
  headers?: Record<string, string>
}

/** Passive CDN/static hydration scope. Active probing never uses this allowance. */
export interface AssetOriginScope {
  origins?: readonly string[]
  allowlist?: (origin: string) => boolean
}

export interface BrowserWebSocketFrame {
  direction: 'sent' | 'received'
  opcode: number | null
  payloadLength: number
  /** Bounded, redacted preview; frame bodies never enter findings verbatim. */
  preview: string
  timestamp: number
}

export interface BrowserWebSocketRecord {
  url: string
  origin: string
  protocol: string | null
  handshakeStatus: number | null
  openedAt: number
  closedAt?: number
  closeCode?: number | null
  frames: BrowserWebSocketFrame[]
  frameCount: number
}

export interface BrowserInteractiveTraversalSummary {
  candidates: number
  clicked: number
  skipped: number
  visitedUrls: string[]
  /** Non-destructive interactions only; forms/submits are never exercised in read-only mode. */
  readOnlyMode: boolean
}

export type BrowserInteractiveAction =
  | { type: 'fill'; selector: string; value: string }
  | { type: 'click'; selector: string }
  | { type: 'select_option'; selector: string; value: string }
  | { type: 'wait_for_selector'; selector: string; timeoutMs?: number }
  | { type: 'wait_for_xhr'; urlPattern?: string; timeoutMs?: number }
  | { type: 'evaluate_builtin'; builtinCheck: BrowserBuiltinCheck }
  | { type: 'dom_xss_sink_hook' }

export interface BrowserDomSinkTrace {
  sink: 'innerHTML' | 'outerHTML' | 'document.write' | 'eval' | 'Function' | 'location.href' | 'postMessage'
  preview: string
  containsCanary: boolean
  timestamp: number
}

export interface BrowserActionOutcome {
  type: BrowserInteractiveAction['type']
  ok: boolean
  detail?: string
  data?: Record<string, unknown>
}

export interface BrowserVisitRequest {
  origin: string
  pathAndQuery: string
  persona?: string
  session?: string
  sessionGroupRole?: 'setup' | 'control' | 'probe' | 'cleanup'
  csrfBind?: CsrfBind
  runId?: string
  assignmentId?: string
  traceId?: string
  checkKind?: 'dom_xss' | 'postmessage' | 'client_storage' | 'xhr_leak'
  canaryToken?: string
  /** Optional host-minted per-probe nonce for isolated `exposeBinding` execution attestation (C-8). */
  attestationNonce?: string
  selector?: string
  postMessageOrigin?: string
  postMessagePayload?: unknown
  sameSiteFetch?: BrowserSameSiteFetchRequest
  actions?: BrowserInteractiveAction[]
  enableSinkHook?: boolean
  timeoutMs?: number
  waitAfterLoadMs?: number
  secrets?: readonly NamedSecret[]
  /** Session material (HttpOnly cookies + web storage) for pooled per-persona contexts. */
  sessionBundle?: BrowserSessionBundle
  /** Per-visit passive asset hydration origins (merged with ScopedBrowserOptions.assetOrigins). */
  assetOrigins?: readonly string[]
  /** Interactive non-destructive traversal after load (tabs, drawers, pagination, filters, modals). */
  interactiveTraversal?: boolean | { maxClicks?: number }
  /** Defaults to true: never click form submits or destructive controls. */
  readOnlyMode?: boolean
  /** Replace fixed settle sleeps with network-idle + DOM-stability waits. Defaults to true when pooled. */
  waitForNetworkIdle?: boolean
  onExchange?: (exchange: BrokerExchangeResult) => string | void
}

export interface BrowserSessionStep {
  id: string
  role: 'setup' | 'control' | 'probe' | 'cleanup'
  description?: string
  origin: string
  pathAndQuery?: string
  persona?: string
  session?: string
  csrfBind?: CsrfBind
  runId?: string
  assignmentId?: string
  traceId?: string
  action?: string
  checkKind?: 'dom_xss' | 'postmessage' | 'client_storage' | 'xhr_leak'
  canaryToken?: string
  /** Optional host-minted per-probe nonce for isolated `exposeBinding` execution attestation (C-8). */
  attestationNonce?: string
  selector?: string
  value?: string
  builtinCheck?: BrowserBuiltinCheck
  urlPattern?: string
  enableSinkHook?: boolean
  reusePage?: boolean
  resetContext?: boolean
  actions?: BrowserInteractiveAction[]
  fetchTarget?: BrowserSameSiteFetchRequest
  postMessageOrigin?: string
  postMessagePayload?: unknown
  waitAfterLoadMs?: number
  secrets?: readonly NamedSecret[]
  onExchange?: (exchange: BrokerExchangeResult) => string | void
}

export interface BrowserFormSummary {
  action: string
  method: string
  inputNames: string[]
}

export interface BrowserXhrRecord {
  method: string
  url: string
  origin: string
  resourceType: string
  status: number | null
  /**
   * Response media type for same-origin XHR/fetch calls whose body was captured for discovery.
   * Headers are never copied into the record.
   */
  mediaType?: string
  /** Bounded, redacted JSON-ish response preview for same-origin XHR/fetch (no headers, no secrets). */
  bodyPreview?: string
}

export interface BrowserPostMessageSummary {
  count: number
  hasOnMessage: boolean
  handlers: Array<{ preview: string; checksOrigin: boolean }>
  observedEvents: number
  canaryHandledWithoutOriginCheck: boolean
}

export interface BrowserSelectorResult {
  selector: string
  matched: boolean
  count: number
  textPreview: string
}

export interface BrowserFetchResult {
  url: string
  origin: string
  method: string
  credentials: string
  ok: boolean
  status: number | null
  contentType: string | null
  bodyPreview: string
  bodyBytes: number
  error: string | null
}

export interface BrowserRedirectSummary {
  initialUrl: string
  finalUrl: string
  redirected: boolean
  finalOrigin: string
  redirectOrigins: string[]
  blockedRedirectAttempt: boolean
}

export interface BrowserExecutionAttestation {
  /** Cryptographically random per-probe nonce minted on the host (never deterministic). */
  nonce: string
  /** Playwright `exposeBinding` callback name registered on the page. */
  bindingName: string
  /** True ONLY when the host-side `exposeBinding` callback received an exact matching nonce. */
  verified: boolean
  /** Number of valid host-attested callback invocations received with the matching nonce. */
  callbackCount: number
  /** Rejected/forged callback attempts (wrong nonce, missing nonce, cross-origin frame, etc.). */
  rejectedAttempts: number
  /** Verified sink/execution tags reported through the host-attested binding callback. */
  attestedSinks: string[]
  /** Origin of the frame that invoked the binding, when available. */
  frameOrigin: string | null
  /** Host timestamp (ms) when the first valid attestation arrived. */
  attestedAt: number | null
}

export interface BrowserVisitResult {
  origin: string
  finalUrl: string
  title: string
  status: number | null
  domSnippet: string
  links: string[]
  forms: BrowserFormSummary[]
  xhrRequests: BrowserXhrRecord[]
  allRequests?: BrowserXhrRecord[]
  blockedOrigins: string[]
  consoleMessages: Array<{ type: 'error' | 'warning'; text: string }>
  postMessageListeners: BrowserPostMessageSummary
  cookieNames: string[]
  localStorageKeys: string[]
  sessionStorageKeys: string[]
  canaryCheck: {
    token: string | null
    triggered: boolean
    detail: string | null
    attested?: boolean
    nonce?: string | null
  }
  /** Host-minted isolated-world `exposeBinding` execution attestation (C-8). */
  attestation?: BrowserExecutionAttestation
  /** Verified trace sinks backed strictly by host-attested binding callbacks (never unverified sentinels). */
  attestedSinks?: string[]
  domSinkTraces: BrowserDomSinkTrace[]
  actionResults?: BrowserActionOutcome[]
  builtinResults?: Record<string, Record<string, unknown>>
  selectorResult?: BrowserSelectorResult | null
  fetchResult?: BrowserFetchResult | null
  redirectSummary?: BrowserRedirectSummary
  /** WebSocket traffic observed through CDP `Network.webSocket*` events (bounded previews). */
  webSockets?: BrowserWebSocketRecord[]
  /** Non-destructive interactive traversal summary (only present when traversal ran). */
  interactiveTraversal?: BrowserInteractiveTraversalSummary
  exchangeIds: string[]
  exchanges: BrokerExchangeResult[]
  durationMs: number
}

interface PlaywrightRoute {
  request(): {
    url(): string
    method(): string
    headers(): Record<string, string>
    postData(): string | null
    resourceType(): string
  }
  abort(errorCode?: string): Promise<void>
  fulfill(response: {
    status?: number
    headers?: Record<string, string>
    contentType?: string
    body?: string | Buffer
  }): Promise<void>
}

export interface PlaywrightBindingSource {
  context?: unknown
  page?: unknown
  frame?: { url?(): string }
}

interface PlaywrightPage {
  on(event: 'console', listener: (msg: { type(): string; text(): string }) => void): void
  on(event: 'pageerror', listener: (err: Error) => void): void
  exposeBinding?(
    name: string,
    callback: (source: PlaywrightBindingSource, ...args: unknown[]) => unknown,
    options?: { handle?: boolean },
  ): Promise<void>
  goto(url: string, options?: { waitUntil?: 'load' | 'domcontentloaded' | 'networkidle'; timeout?: number }): Promise<{ status(): number } | null>
  waitForTimeout(ms: number): Promise<void>
  waitForLoadState?(state?: 'load' | 'domcontentloaded' | 'networkidle', options?: { timeout?: number }): Promise<void>
  fill?(selector: string, value: string, options?: { timeout?: number }): Promise<void>
  click?(selector: string, options?: { timeout?: number }): Promise<void>
  selectOption?(selector: string, values: string, options?: { timeout?: number }): Promise<string[]>
  waitForSelector?(selector: string, options?: { timeout?: number }): Promise<unknown>
  url(): string
  title(): Promise<string>
  evaluate<T, A = undefined>(fn: (arg: A) => T | Promise<T>, arg?: A): Promise<T>
  close(): Promise<void>
}

/** Minimal CDP surface used for WebSocket observation (`Network.webSocket*`). */
export interface PlaywrightCdpSession {
  send(method: string, params?: Record<string, unknown>): Promise<unknown>
  on(event: string, listener: (payload: Record<string, unknown>) => void): void
  detach?(): Promise<void>
}

interface PlaywrightContext {
  addInitScript(script: string | (() => void)): Promise<void>
  exposeBinding?(
    name: string,
    callback: (source: PlaywrightBindingSource, ...args: unknown[]) => unknown,
    options?: { handle?: boolean },
  ): Promise<void>
  addCookies?(cookies: Array<{
    name: string
    value: string
    domain: string
    path: string
    secure?: boolean
    httpOnly?: boolean
    sameSite?: 'Strict' | 'Lax' | 'None'
    expires?: number
  }>): Promise<void>
  setExtraHTTPHeaders?(headers: Record<string, string>): Promise<void>
  route(url: string, handler: (route: PlaywrightRoute) => Promise<void> | void): Promise<void>
  routeWebSocket?(url: string, handler: (ws: PlaywrightWebSocketRoute) => Promise<void> | void): Promise<void>
  newPage(): Promise<PlaywrightPage>
  newCDPSession?(page: PlaywrightPage): Promise<PlaywrightCdpSession>
  close(): Promise<void>
}

export interface PlaywrightBrowserLike {
  newContext(options?: Record<string, unknown>): Promise<PlaywrightContext>
  close(): Promise<void>
  isConnected?(): boolean
  on?(event: 'disconnected', listener: () => void): unknown
  off?(event: 'disconnected', listener: () => void): unknown
}

export interface ScopedBrowserOptions {
  launchBrowser?: () => Promise<PlaywrightBrowserLike>
  storage?: SecondOrderStore
  /** Passive CDN/static GET hydration allowlist (active probing stays on target origins). */
  assetOrigins?: readonly string[]
  assetOriginAllowlist?: (origin: string) => boolean
  /** Resolve HttpOnly cookie + web-storage material for a persona before pooled context seeding. */
  resolveSessionBundle?: (
    persona: string,
    origin: string,
  ) => BrowserSessionBundle | null | Promise<BrowserSessionBundle | null>
  /** Capture WebSocket traffic through CDP. Defaults to true. */
  captureWebSockets?: boolean
  /** Upper bound on simultaneously pooled idle/active contexts before LRU eviction. Defaults to 8. */
  maxPooledContexts?: number
  /**
   * Hard upper bound on simultaneous active + creating pooled contexts before backpressure kicks in.
   * Defaults to a small bounded burst above `maxPooledContexts` (`min(20, max + clamp(floor(max/2), 1, 4))`).
   */
  maxActiveContexts?: number
  /** Maximum time (ms) a caller waits on pool backpressure when all slots are active. Defaults to 15_000. */
  poolAcquireTimeoutMs?: number
  /** Optional injectable DNS resolver for deterministic EgressGateway loopback proxy tests. */
  proxyResolveHost?: (hostname: string) => Promise<string[]>
}

const DEFAULT_POOL_ACQUIRE_TIMEOUT_MS = 15_000

const maxBrowserTimeoutMs = 30_000
const maxDomSnippetChars = 16_384
/** Per-visit ceiling for captured XHR/fetch JSON bodies used by route-map/navigation discovery. */
const maxXhrBodyCharsPerVisit = 262_144
/** Per-response ceiling; route maps and config tables are small, listings can be large. */
const maxXhrBodyCharsPerRecord = 65_536
const maxInteractiveActions = 20
const forbiddenBrowserForwardHeaders = /^(?:authorization|proxy-authorization|cookie|host|content-length|transfer-encoding|connection|accept-encoding|sec-fetch-.*|sec-ch-.*)$/i
const allowedMethods = new Set(['GET', 'HEAD', 'OPTIONS', 'POST', 'PUT', 'PATCH', 'DELETE'])
const safeReadOnlyFetchMethods = new Set(['GET', 'HEAD', 'OPTIONS'])
const unsafeSelectorPattern = /[<>{};`\\]|javascript:/i

/**
 * Capture a bounded, redacted JSON-ish response preview for a same-origin XHR/fetch so discovery can
 * expand route-map/config documents and navigation payloads that are only reachable from the SPA.
 * Only bodies are exposed; request/response headers never enter the browser record.
 */
function captureXhrJsonBody(input: {
  exchange: BrokerExchangeResult
  sameOrigin: boolean
  secrets: readonly NamedSecret[]
  budget: { chars: number }
}): { mediaType?: string; bodyPreview?: string } {
  const { exchange, sameOrigin, secrets, budget } = input
  if (!sameOrigin) return {}
  if (exchange.status < 200 || exchange.status >= 400) return {}
  if (!exchange.body) return {}
  const looksStructured = /json/i.test(exchange.mediaType) || /^\s*[{[]/.test(exchange.body.slice(0, 64))
  if (!looksStructured) return {}
  if (budget.chars >= maxXhrBodyCharsPerVisit) return {}
  const limit = Math.max(0, Math.min(maxXhrBodyCharsPerRecord, maxXhrBodyCharsPerVisit - budget.chars))
  if (limit === 0) return {}
  const bodyPreview = redact(exchange.body, secrets).slice(0, limit)
  budget.chars += bodyPreview.length
  return { mediaType: exchange.mediaType, bodyPreview }
}

/** Chromium launch hardening shared by every ScopedBrowser context. */
export interface ChromiumLaunchOptions {
  /** Explicit insecure opt-in (KOVO_INSECURE_NO_SANDBOX=1). */
  insecureNoSandbox?: boolean
}

/**
 * Sandboxing is on by default. Delegates to the single authoritative Chromium arg builder
 * in `src/server/chromium-launch.ts`.
 */
export function chromiumLaunchArgs(options: ChromiumLaunchOptions = {}): string[] {
  return buildChromiumLaunchArgs({ insecureNoSandbox: options.insecureNoSandbox })
}

/**
 * Build the authoritative Playwright `chromium.launch(...)` options for `ScopedBrowser`.
 * Explicitly sets `chromiumSandbox: true` by default because Playwright silently appends
 * `--no-sandbox` whenever `chromiumSandbox !== true`.
 */
export function buildChromiumLaunchOptions(
  options: ChromiumLaunchOptions & { env?: NodeJS.ProcessEnv } = {},
): PlaywrightChromiumLaunchOptions {
  const base = buildPlaywrightChromiumLaunchOptions({
    insecureNoSandbox: options.insecureNoSandbox,
    env: options.env,
  })
  return {
    ...base,
    args: chromiumLaunchArgs({ insecureNoSandbox: !base.chromiumSandbox }),
  }
}

/** Neutralise WebRTC constructors for target JS even if a platform ignores the launch flags. */
export const browserWebRtcGuardScript = `(() => {
  const deny = function () { throw new Error('WebRTC is disabled inside Kovo browser sessions.'); };
  for (const name of ['RTCPeerConnection', 'webkitRTCPeerConnection', 'RTCDataChannel', 'WebTransport']) {
    try { Object.defineProperty(window, name, { configurable: false, writable: false, value: deny }); } catch {}
  }
})();`

/**
 * Fail-closed fallback when the Playwright version has no `routeWebSocket`: the page loses the
 * socket constructors entirely instead of being allowed to open an unchecked connection.
 */
export const browserSocketDenyScript = `(() => {
  const deny = function () { throw new Error('WebSocket/WebTransport are disabled inside Kovo browser sessions.'); };
  for (const name of ['WebSocket', 'WebTransport', 'RTCPeerConnection', 'webkitRTCPeerConnection', 'RTCDataChannel']) {
    try { Object.defineProperty(window, name, { configurable: false, writable: false, value: deny }); } catch {}
  }
})();`

export interface PlaywrightWebSocketRoute {
  url(): string
  close(options?: { code?: number; reason?: string }): Promise<void> | void
  connectToServer?(): Promise<void> | void
}

/**
 * Determine whether a CONNECT / WebSocket port is allowed for the active grant and scope policy.
 * Enforces explicit `grant.allowedPorts`, `scopePolicy` origin ports, and fails closed on
 * non-443 ports outside local-lab unless explicitly allowlisted by `canRead` or `assetScope`.
 */
export function isBrowserConnectPortAllowed(params: {
  port: number
  hostname: string
  grant: Pick<Grant, 'canRead' | 'allowedPorts' | 'scopePolicy'>
  allowLocalLab: boolean
  assetScope?: AssetOriginScope
}): boolean {
  const { port, hostname, grant, allowLocalLab, assetScope } = params
  if (!Number.isInteger(port) || port < 1 || port > 65_535) return false
  if (grant.allowedPorts && grant.allowedPorts.length > 0) {
    return grant.allowedPorts.includes(port)
  }
  const bareHost = hostname.trim().toLowerCase().replace(/^\[|\]$/g, '')
  const formattedHost = bareHost.includes(':') ? `[${bareHost}]` : bareHost
  const httpsOrigin = port === 443 ? `https://${formattedHost}` : `https://${formattedHost}:${port}`
  const httpOrigin = port === 80 ? `http://${formattedHost}` : `http://${formattedHost}:${port}`
  if (grant.scopePolicy) {
    const checkScope = (o: string): boolean => evaluateBrowserScopeRequest(grant.scopePolicy!, {
      origin: o,
      method: 'GET',
      pathAndQuery: '/',
      redirectHop: true,
    }).allowed
    if (checkScope(httpsOrigin)) return true
    if (allowLocalLab && checkScope(httpOrigin)) return true
    return false
  }
  if (grant.canRead(httpsOrigin) || isAssetOriginAllowed(httpsOrigin, assetScope)) return true
  if (allowLocalLab && (grant.canRead(httpOrigin) || isAssetOriginAllowed(httpOrigin, assetScope))) return true
  return false
}

/**
 * HTTP interception does not cover WebSocket upgrades. Route every socket through an explicit
 * scope check (including `allowConnectPort` / `allowedPorts` and `scopePolicy`) and only call
 * `connectToServer()` for in-scope wss/ws origins. When the Playwright version has no
 * `routeWebSocket`, the guard fails closed (page-level deny script) instead of allowing upgrades.
 */
export async function installWebSocketGuard(
  context: Pick<PlaywrightContext, 'routeWebSocket'> & Partial<Pick<PlaywrightContext, 'addInitScript'>>,
  options: {
    canRead: (origin: string) => boolean
    allowLocalLab: boolean | (() => boolean)
    scopePolicy?: ScopePolicy | (() => ScopePolicy | undefined)
    allowedPorts?: readonly number[] | (() => readonly number[] | undefined)
    allowConnectPort?: (port: number, hostname: string) => boolean
    audit?: (decision: 'denied', origin: string) => void
  },
): Promise<void> {
  if (typeof context.routeWebSocket !== 'function') {
    // Fail closed: without socket interception an unchecked ws/wss upgrade is possible. Remove
    // the constructors from the page; if even that is impossible, refuse the session.
    if (typeof context.addInitScript === 'function') {
      await context.addInitScript(browserSocketDenyScript)
      return
    }
    throw new Error('WebSocket interception is unavailable; refusing a browser session without it.')
  }
  await context.routeWebSocket('**/*', async ws => {
    let origin: string
    let parsedUrl: URL
    let port: number
    const allowLocalLab = typeof options.allowLocalLab === 'function' ? options.allowLocalLab() : options.allowLocalLab
    try {
      parsedUrl = new URL(ws.url())
      const secure = parsedUrl.protocol === 'wss:'
      if (!secure && !(allowLocalLab && parsedUrl.protocol === 'ws:')) {
        options.audit?.('denied', parsedUrl.origin)
        await ws.close({ code: 1008, reason: 'Blocked by Kovo scope.' })
        return
      }
      port = parsedUrl.port ? Number(parsedUrl.port) : (secure ? 443 : 80)
      origin = `${secure ? 'https:' : 'http:'}//${parsedUrl.host}`
    } catch {
      await ws.close({ code: 1008, reason: 'Blocked by Kovo scope.' })
      return
    }
    const allowedPorts = typeof options.allowedPorts === 'function' ? options.allowedPorts() : options.allowedPorts
    if (allowedPorts && allowedPorts.length > 0 && !allowedPorts.includes(port)) {
      options.audit?.('denied', origin)
      await ws.close({ code: 1008, reason: 'Blocked by Kovo scope.' })
      return
    }
    if (options.allowConnectPort && !options.allowConnectPort(port, parsedUrl.hostname)) {
      options.audit?.('denied', origin)
      await ws.close({ code: 1008, reason: 'Blocked by Kovo scope.' })
      return
    }
    const scopePolicy = typeof options.scopePolicy === 'function' ? options.scopePolicy() : options.scopePolicy
    if (scopePolicy) {
      const wsPath = `${parsedUrl.pathname}${parsedUrl.search}`
      const decision = evaluateBrowserScopeRequest(scopePolicy, {
        origin,
        method: 'GET',
        pathAndQuery: wsPath,
        redirectHop: false,
      })
      // WebSocket upgrades are bidirectional active channels: permit only `target` origins
      // and never allow upgrades to `asset`/`auth` origins or denylisted routes.
      if (!decision.allowed || decision.role !== 'target' || isRouteDenylisted(scopePolicy, wsPath)) {
        options.audit?.('denied', origin)
        await ws.close({ code: 1008, reason: 'Blocked by Kovo scope.' })
        return
      }
    }
    if (!options.canRead(origin)) {
      options.audit?.('denied', origin)
      await ws.close({ code: 1008, reason: 'Blocked by Kovo scope.' })
      return
    }
    if (typeof ws.connectToServer !== 'function') {
      await ws.close({ code: 1008, reason: 'Blocked by Kovo scope.' })
      return
    }
    await ws.connectToServer()
  })
}

export async function launchChromium(deps?: {
  launch?: ChromiumPlaywrightLauncher<PlaywrightBrowserLike>['launch']
  env?: NodeJS.ProcessEnv
}): Promise<PlaywrightBrowserLike> {
  const launchOptions = buildChromiumLaunchOptions({ env: deps?.env })
  return await launchPlaywrightChromium(launchOptions, deps?.launch)
}

const postMessageInstrumentationScript = `
(() => {
  const state = {
    handlers: [],
    hasOnMessage: false,
    observedEvents: 0,
    canaryObserved: false,
    domCanaryTriggered: false,
    sinkTraces: [],
  };
  Object.defineProperty(window, '__kovoBrowserProbe', {
    value: state,
    writable: false,
    configurable: false,
    enumerable: false,
  });

  const inspectHandler = (fn) => {
    try {
      const src = typeof fn === 'function' ? Function.prototype.toString.call(fn) : String(fn);
      const preview = src.slice(0, 300);
      const checksOrigin = /(?:event|evt|e|msg)\\.origin\\s*(?:===|!==|==|!=)|\\.origin\\.endsWith|\\.origin\\.includes|allowedOrigins/i.test(src);
      state.handlers.push({ preview, checksOrigin });
    } catch {
      state.handlers.push({ preview: '[uninspectable handler]', checksOrigin: false });
    }
  };

  const origAdd = EventTarget.prototype.addEventListener;
  EventTarget.prototype.addEventListener = function(type, listener, options) {
    if (this === window && type === 'message' && listener) {
      inspectHandler(listener);
    }
    return origAdd.call(this, type, listener, options);
  };

  const desc = Object.getOwnPropertyDescriptor(window, 'onmessage') ||
               Object.getOwnPropertyDescriptor(Window.prototype, 'onmessage');
  if (desc && desc.set && desc.configurable) {
    Object.defineProperty(window, 'onmessage', {
      configurable: true,
      get() { return desc.get ? desc.get.call(this) : null; },
      set(fn) {
        if (typeof fn === 'function') {
          state.hasOnMessage = true;
          inspectHandler(fn);
        }
        return desc.set.call(this, fn);
      },
    });
  }

  origAdd.call(window, 'message', (ev) => {
    state.observedEvents += 1;
    try {
      const serialized = typeof ev.data === 'string' ? ev.data : JSON.stringify(ev.data ?? '');
      if (serialized && serialized.includes('kovo-pm-canary')) {
        state.canaryObserved = true;
      }
    } catch {}
  }, true);
})();
`

function buildDomSinkHookScript(canaryToken: string | null): string {
  const tokenJson = JSON.stringify(canaryToken ?? '')
  return `
(() => {
  const probe = window.__kovoBrowserProbe;
  if (!probe || probe.__sinkHookInstalled) return;
  probe.__sinkHookInstalled = true;
  const canary = ${tokenJson};

  const recordSink = (sink, raw) => {
    try {
      const text = typeof raw === 'string' ? raw : JSON.stringify(raw ?? '');
      const preview = String(text).slice(0, 400);
      const containsCanary = Boolean(canary && preview.includes(canary)) || Boolean(canary && String(text).includes(canary));
      if (probe.sinkTraces.length < 80) {
        probe.sinkTraces.push({ sink, preview, containsCanary, timestamp: Date.now() });
      }
      if (containsCanary) {
        probe.domCanaryTriggered = true;
      }
    } catch {}
  };

  const wrapSetter = (proto, prop, sinkName) => {
    try {
      const d = Object.getOwnPropertyDescriptor(proto, prop);
      if (d && d.set && d.configurable) {
        Object.defineProperty(proto, prop, {
          configurable: true,
          enumerable: d.enumerable,
          get() { return d.get ? d.get.call(this) : ''; },
          set(val) {
            recordSink(sinkName, val);
            return d.set.call(this, val);
          },
        });
      }
    } catch {}
  };

  wrapSetter(Element.prototype, 'innerHTML', 'innerHTML');
  wrapSetter(Element.prototype, 'outerHTML', 'outerHTML');

  try {
    const origWrite = document.write;
    document.write = function(...args) {
      recordSink('document.write', args.join(''));
      return origWrite.apply(this, args);
    };
    const origWriteln = document.writeln;
    document.writeln = function(...args) {
      recordSink('document.write', args.join(''));
      return origWriteln.apply(this, args);
    };
  } catch {}

  try {
    const origEval = window.eval;
    window.eval = function(code) {
      recordSink('eval', code);
      return origEval.call(window, code);
    };
  } catch {}

  try {
    const OrigFunction = window.Function;
    const WrappedFunction = function(...args) {
      recordSink('Function', args.join(','));
      return OrigFunction.apply(this, args);
    };
    WrappedFunction.prototype = OrigFunction.prototype;
    window.Function = WrappedFunction;
  } catch {}

  try {
    const origAssign = Location.prototype.assign;
    if (typeof origAssign === 'function') {
      Location.prototype.assign = function(url) {
        recordSink('location.href', url);
        return origAssign.call(this, url);
      };
    }
    const origReplace = Location.prototype.replace;
    if (typeof origReplace === 'function') {
      Location.prototype.replace = function(url) {
        recordSink('location.href', url);
        return origReplace.call(this, url);
      };
    }
    const hrefDesc = Object.getOwnPropertyDescriptor(Location.prototype, 'href');
    if (hrefDesc && hrefDesc.set && hrefDesc.configurable) {
      Object.defineProperty(Location.prototype, 'href', {
        configurable: true,
        get() { return hrefDesc.get ? hrefDesc.get.call(this) : ''; },
        set(val) {
          recordSink('location.href', val);
          return hrefDesc.set.call(this, val);
        },
      });
    }
  } catch {}

  try {
    const origPostMessage = window.postMessage;
    window.postMessage = function(message, targetOrigin, transfer) {
      recordSink('postMessage', { message, targetOrigin });
      return origPostMessage.apply(this, arguments);
    };
  } catch {}
})();
`
}

// ---------------------------------------------------------------------------------------------
// C-8: Host-minted isolated-world callback attestation (`page.exposeBinding`)
// ---------------------------------------------------------------------------------------------

/** Host-registered Playwright `page.exposeBinding` callback name for isolated execution attestation. */
export const KOVO_EXECUTION_ATTESTATION_BINDING = '__kovoAttestExecution'

const ATTESTATION_SINK_TAG_RE = /^[A-Za-z0-9_.:-]{1,64}$/

/** Mint a cryptographically random per-probe nonce on the host (never deterministic). */
export function mintExecutionAttestationNonce(): string {
  return `kovo_att_${randomBytes(16).toString('hex')}`
}

export interface HostExecutionAttestor {
  readonly nonce: string
  readonly bindingName: string
  /** Process a host-side binding callback invocation from Playwright `page.exposeBinding`. */
  handleBindingCall(
    source: PlaywrightBindingSource | undefined,
    rawNonce: unknown,
    rawSink?: unknown,
  ): { attested: boolean }
  /** Attach the isolated binding to a Playwright page. Returns false (fail-closed) when unsupported. */
  attachToPage(page: PlaywrightPage): Promise<boolean>
  /** Immutable host-owned attestation state snapshot. */
  snapshot(): BrowserExecutionAttestation
  /** Compute verified `trace.sinks` backed strictly by a matching host-minted callback nonce. */
  verifySinks(input?: {
    executedSentinels?: readonly string[]
    title?: string | null
    domSinkTraces?: readonly BrowserDomSinkTrace[]
  }): string[]
}

/**
 * Create a per-probe host-owned execution attestor. Client-side `console`, `document.title`,
 * DOM markers, and main-world global flags (`window.__kovoDomCanary`, `Object.prototype.*`)
 * can never flip `verified` without presenting the exact host-minted nonce through `exposeBinding`.
 */
export function createHostExecutionAttestor(options: {
  nonce?: string
  bindingName?: string
  expectedOrigin?: string | null
} = {}): HostExecutionAttestor {
  const providedNonce = typeof options.nonce === 'string' && options.nonce.trim().length >= 16
    ? options.nonce.trim()
    : null
  const nonce = providedNonce ?? mintExecutionAttestationNonce()
  const bindingName = options.bindingName && /^[A-Za-z_][A-Za-z0-9_]{0,63}$/.test(options.bindingName)
    ? options.bindingName
    : KOVO_EXECUTION_ATTESTATION_BINDING
  let expectedOrigin: string | null = null
  if (options.expectedOrigin) {
    try {
      expectedOrigin = new URL(options.expectedOrigin).origin
    } catch {
      expectedOrigin = null
    }
  }

  let verified = false
  let callbackCount = 0
  let rejectedAttempts = 0
  let frameOrigin: string | null = null
  let attestedAt: number | null = null
  const attestedSinks: string[] = []

  const handleBindingCall = (
    source: PlaywrightBindingSource | undefined,
    rawNonce: unknown,
    rawSink?: unknown,
  ): { attested: boolean } => {
    if (typeof rawNonce !== 'string' || !rawNonce || !constantTimeStringEqual(rawNonce, nonce)) {
      rejectedAttempts += 1
      return { attested: false }
    }
    let observedOrigin: string | null = null
    const rawFrameUrl = typeof source?.frame?.url === 'function' ? source.frame.url() : ''
    if (rawFrameUrl && /^https?:\/\//i.test(rawFrameUrl)) {
      try {
        observedOrigin = new URL(rawFrameUrl).origin
      } catch {
        rejectedAttempts += 1
        return { attested: false }
      }
      if (expectedOrigin && observedOrigin !== expectedOrigin) {
        rejectedAttempts += 1
        return { attested: false }
      }
    }
    verified = true
    callbackCount += 1
    attestedAt ??= Date.now()
    if (observedOrigin) frameOrigin = observedOrigin
    const sinkTag = typeof rawSink === 'string' && ATTESTATION_SINK_TAG_RE.test(rawSink)
      ? rawSink
      : 'binding:attested'
    if (attestedSinks.length < 32 && !attestedSinks.includes(sinkTag)) {
      attestedSinks.push(sinkTag)
    }
    return { attested: true }
  }

  const snapshot = (): BrowserExecutionAttestation => ({
    nonce,
    bindingName,
    verified,
    callbackCount,
    rejectedAttempts,
    attestedSinks: [...attestedSinks],
    frameOrigin,
    attestedAt,
  })

  return {
    nonce,
    bindingName,
    handleBindingCall,
    async attachToPage(page: PlaywrightPage): Promise<boolean> {
      if (typeof page.exposeBinding !== 'function') return false
      await page.exposeBinding(bindingName, (source, rawNonce, rawSink) =>
        handleBindingCall(source, rawNonce, rawSink))
      return true
    },
    snapshot,
    verifySinks(input = {}): string[] {
      return buildVerifiedTraceSinks({
        attestation: snapshot(),
        executedSentinels: input.executedSentinels,
        title: input.title,
        domSinkTraces: input.domSinkTraces,
      })
    },
  }
}

/**
 * C-8: Build verified `trace.sinks` strictly from host-attested `exposeBinding` callbacks.
 * Never maps unverified `executedSentinels`, `document.title`, `console` messages, or
 * main-world global flags into `trace.sinks` without a matching host-minted binding callback nonce.
 */
export function buildVerifiedTraceSinks(input: {
  attestation: BrowserExecutionAttestation | null | undefined
  executedSentinels?: readonly string[]
  title?: string | null
  domSinkTraces?: readonly BrowserDomSinkTrace[]
}): string[] {
  const att = input.attestation
  if (!att || att.verified !== true || att.callbackCount < 1 || !att.nonce || att.nonce.length < 16) {
    return []
  }
  const sinks = new Set<string>()
  for (const tag of att.attestedSinks) {
    if (typeof tag === 'string' && ATTESTATION_SINK_TAG_RE.test(tag)) sinks.add(tag)
  }
  if (sinks.size === 0) sinks.add('binding:attested')

  // Only include executedSentinels that explicitly match the host-minted binding nonce
  // AND only after the host binding callback itself has already verified the nonce.
  for (const sentinel of input.executedSentinels ?? []) {
    if (typeof sentinel !== 'string' || !sentinel) continue
    if (constantTimeStringEqual(sentinel, att.nonce)) {
      sinks.add('sentinel:attested')
      continue
    }
    const colonIdx = sentinel.lastIndexOf(':')
    if (colonIdx > 0) {
      const prefix = sentinel.slice(0, colonIdx)
      const suffix = sentinel.slice(colonIdx + 1)
      if (constantTimeStringEqual(suffix, att.nonce) && ATTESTATION_SINK_TAG_RE.test(prefix)) {
        sinks.add(`sentinel:${prefix}`)
      }
    }
  }
  return [...sinks]
}

// ---------------------------------------------------------------------------------------------
// H-8: SPA-compatible HttpOnly cookie & Authorization wire placeholder substitution
// ---------------------------------------------------------------------------------------------

export const BROWSER_HTTPONLY_COOKIE_PLACEHOLDER_PREFIX = 'kovo_ph_ck_'
export const BROWSER_AUTH_HEADER_PLACEHOLDER_PREFIX = 'kovo_ph_auth_'

const AUTH_SCHEME_RE = /^([A-Za-z][A-Za-z0-9_-]{0,31})\s+(.+)$/

function normalizeAllowedOrigins(origins: readonly string[]): Set<string> {
  const out = new Set<string>()
  for (const raw of origins) {
    if (typeof raw !== 'string') continue
    const trimmed = raw.trim()
    if (!trimmed || trimmed === '*' || trimmed.includes('*')) continue
    try {
      const parsed = new URL(trimmed)
      if (parsed.protocol === 'https:' || parsed.protocol === 'http:') {
        out.add(parsed.origin)
      }
    } catch {
      // Fail closed on malformed origins.
    }
  }
  return out
}

interface CookiePlaceholderEntry {
  name: string
  placeholder: string
  realValue: string
  allowedOrigins: Set<string>
}

interface AuthPlaceholderEntry {
  opaqueToken: string
  fullPlaceholder: string
  realValue: string
  allowedOrigins: Set<string>
}

/**
 * Host-owned vault mapping opaque browser-side placeholders for HttpOnly cookies and
 * `Authorization` headers to real credential bytes swapped on the wire strictly inside the
 * loopback proxy for allowlisted origins. Client-readable SPA tokens (`localStorage`,
 * `sessionStorage`, and non-HttpOnly SDK cookies) are preserved untouched.
 */
export class BrowserWirePlaceholderVault {
  private readonly cookiesByPlaceholder = new Map<string, CookiePlaceholderEntry>()
  private readonly cookiePlaceholderIndex = new Map<string, string>()
  private readonly authByToken = new Map<string, AuthPlaceholderEntry>()
  private readonly authTokenIndex = new Map<string, string>()

  /**
   * Replace an `httpOnly: true` cookie's raw secret with a per-context opaque placeholder.
   * Non-HttpOnly cookies (`httpOnly !== true`) are returned untouched for SPA JS compatibility.
   */
  registerHttpOnlyCookie(cookie: BrowserSeedCookie, allowedOrigins: readonly string[]): BrowserSeedCookie {
    if (cookie.httpOnly !== true) {
      return { ...cookie }
    }
    const normalized = normalizeAllowedOrigins(allowedOrigins)
    const indexKey = `${cookie.name}\0${cookie.value}`
    const existingPlaceholder = this.cookiePlaceholderIndex.get(indexKey)
    if (existingPlaceholder) {
      const entry = this.cookiesByPlaceholder.get(existingPlaceholder)
      if (entry) {
        for (const origin of normalized) entry.allowedOrigins.add(origin)
        return { ...cookie, value: existingPlaceholder, httpOnly: true }
      }
    }
    const placeholder = `${BROWSER_HTTPONLY_COOKIE_PLACEHOLDER_PREFIX}${randomBytes(16).toString('hex')}`
    this.cookiesByPlaceholder.set(placeholder, {
      name: cookie.name,
      placeholder,
      realValue: cookie.value,
      allowedOrigins: normalized,
    })
    this.cookiePlaceholderIndex.set(indexKey, placeholder)
    return { ...cookie, value: placeholder, httpOnly: true }
  }

  /**
   * Mint an opaque placeholder for an `Authorization` header value, preserving any auth scheme
   * prefix (e.g., `Bearer kovo_ph_auth_<hex>`), strictly scoped to `allowedOrigins`.
   */
  registerAuthorizationHeader(realHeaderValue: string, allowedOrigins: readonly string[]): string {
    const normalized = normalizeAllowedOrigins(allowedOrigins)
    const trimmed = realHeaderValue.trim()
    const existingToken = this.authTokenIndex.get(trimmed)
    if (existingToken) {
      const entry = this.authByToken.get(existingToken)
      if (entry) {
        for (const origin of normalized) entry.allowedOrigins.add(origin)
        return entry.fullPlaceholder
      }
    }
    const schemeMatch = AUTH_SCHEME_RE.exec(trimmed)
    const opaqueToken = `${BROWSER_AUTH_HEADER_PLACEHOLDER_PREFIX}${randomBytes(16).toString('hex')}`
    const fullPlaceholder = schemeMatch ? `${schemeMatch[1]} ${opaqueToken}` : opaqueToken
    this.authByToken.set(opaqueToken, {
      opaqueToken,
      fullPlaceholder,
      realValue: trimmed,
      allowedOrigins: normalized,
    })
    this.authTokenIndex.set(trimmed, opaqueToken)
    return fullPlaceholder
  }

  /**
   * Prepare a session bundle for browser hydration:
   * - HttpOnly cookies -> opaque placeholders scoped strictly to domain-matching allowlisted origins.
   * - Non-HttpOnly SDK cookies -> preserved as-is for SPA JS (`document.cookie` / XSRF / token rotation).
   * - `Authorization` header -> registered as an opaque placeholder scoped strictly to allowlisted origins.
   * - `localStorage`/`sessionStorage`/`initScript` -> preserved untouched by caller.
   */
  prepareSeedBundle(
    bundle: BrowserSessionBundle | null,
    targetOrigin: string,
    allowedOrigins?: readonly string[],
  ): { cookies: BrowserSeedCookie[]; placeholderHeaders: Record<string, string> } {
    if (!bundle) return { cookies: [], placeholderHeaders: {} }
    const baseAllowlist = normalizeAllowedOrigins(
      allowedOrigins && allowedOrigins.length > 0 ? allowedOrigins : [targetOrigin],
    )
    const allowlistArray = [...baseAllowlist]
    const scopedCookies = filterCookiesForOrigin(bundle.cookies ?? [], targetOrigin)
    const cookies = scopedCookies.map(cookie => {
      if (cookie.httpOnly !== true) return { ...cookie }
      const cookieOrigins = allowlistArray.filter(o => filterCookiesForOrigin([cookie], o).length > 0)
      return this.registerHttpOnlyCookie(
        cookie,
        cookieOrigins.length > 0 ? cookieOrigins : [targetOrigin],
      )
    })

    const placeholderHeaders: Record<string, string> = {}
    for (const [k, v] of Object.entries(bundle.headers ?? {})) {
      if (k.toLowerCase() === 'authorization' && v.trim()) {
        placeholderHeaders.authorization = this.registerAuthorizationHeader(v, allowlistArray)
      }
    }
    return { cookies, placeholderHeaders }
  }

  /**
   * Swap opaque placeholders for real HttpOnly cookies and `Authorization` headers strictly on
   * allowlisted origins inside the loopback proxy. Off-origin requests NEVER receive real values
   * and have placeholder credentials stripped fail-closed.
   */
  substituteWireHeaders(
    url: URL,
    headers: Record<string, string>,
    isOriginAllowed?: (origin: string) => boolean,
  ): Record<string, string> {
    const targetOrigin = url.origin
    const grantAllowed = isOriginAllowed ? isOriginAllowed(targetOrigin) : true
    const out: Record<string, string> = {}

    for (const [rawKey, rawValue] of Object.entries(headers)) {
      const lower = rawKey.toLowerCase()
      if (lower === 'cookie') {
        const rewrittenPairs: string[] = []
        for (const segment of rawValue.split(';')) {
          const trimmed = segment.trim()
          if (!trimmed) continue
          const eqIdx = trimmed.indexOf('=')
          if (eqIdx <= 0) {
            rewrittenPairs.push(trimmed)
            continue
          }
          const name = trimmed.slice(0, eqIdx).trim()
          const val = trimmed.slice(eqIdx + 1).trim()
          const entry = this.cookiesByPlaceholder.get(val)
          if (entry) {
            if (grantAllowed && entry.allowedOrigins.has(targetOrigin) && entry.name === name) {
              rewrittenPairs.push(`${name}=${entry.realValue}`)
            }
            // Off-origin or mismatched cookie name: strip placeholder fail-closed (never leak!).
            continue
          }
          if (val.startsWith(BROWSER_HTTPONLY_COOKIE_PLACEHOLDER_PREFIX)) {
            // Unknown or stale placeholder: strip fail-closed.
            continue
          }
          // Preserve non-HttpOnly SPA cookies untouched.
          rewrittenPairs.push(`${name}=${val}`)
        }
        if (rewrittenPairs.length > 0) {
          out[rawKey] = rewrittenPairs.join('; ')
        }
        continue
      }

      if (lower === 'authorization') {
        const trimmed = rawValue.trim()
        const schemeMatch = AUTH_SCHEME_RE.exec(trimmed)
        const candidateToken = schemeMatch ? schemeMatch[2]!.trim() : trimmed
        const entry = this.authByToken.get(candidateToken)
        if (entry) {
          if (grantAllowed && entry.allowedOrigins.has(targetOrigin)) {
            out[rawKey] = entry.realValue
          }
          // Off-origin or grant-denied: strip Authorization header fail-closed!
          continue
        }
        if (trimmed.includes(BROWSER_AUTH_HEADER_PLACEHOLDER_PREFIX)) {
          // Unknown or stale placeholder: strip fail-closed.
          continue
        }
        // Preserve client-rotated SPA Authorization headers untouched.
        out[rawKey] = rawValue
        continue
      }

      // Never substitute placeholders into arbitrary non-credential headers; strip if off-origin.
      let safeValue = rawValue
      if (safeValue.includes(BROWSER_HTTPONLY_COOKIE_PLACEHOLDER_PREFIX)) {
        for (const [placeholder, entry] of this.cookiesByPlaceholder.entries()) {
          if (safeValue.includes(placeholder) && (!grantAllowed || !entry.allowedOrigins.has(targetOrigin))) {
            safeValue = safeValue.split(placeholder).join('[stripped]')
          }
        }
      }
      if (safeValue.includes(BROWSER_AUTH_HEADER_PLACEHOLDER_PREFIX)) {
        for (const [token, entry] of this.authByToken.entries()) {
          if (safeValue.includes(token) && (!grantAllowed || !entry.allowedOrigins.has(targetOrigin))) {
            safeValue = safeValue.split(token).join('[stripped]')
          }
        }
      }
      out[rawKey] = safeValue
    }
    return out
  }

  hasPlaceholder(token: string): boolean {
    const trimmed = token.trim()
    if (this.cookiesByPlaceholder.has(trimmed)) return true
    const schemeMatch = AUTH_SCHEME_RE.exec(trimmed)
    const candidate = schemeMatch ? schemeMatch[2]!.trim() : trimmed
    return this.authByToken.has(candidate)
  }

  clear(): void {
    this.cookiesByPlaceholder.clear()
    this.cookiePlaceholderIndex.clear()
    this.authByToken.clear()
    this.authTokenIndex.clear()
  }
}

function resolveBundleAllowedOrigins(
  grant: Grant,
  persona: string | undefined,
  initialOrigin: string,
): string[] {
  const out = new Set<string>([initialOrigin])
  if (persona) {
    const resolved = grant.personas?.get(persona)
    for (const candidate of resolved?.originAllowlist ?? []) {
      try {
        const parsed = new URL(candidate)
        if (parsed.protocol === 'https:' || parsed.protocol === 'http:') {
          out.add(parsed.origin)
        }
      } catch {
        // Ignore malformed allowlist entries.
      }
    }
  }
  return [...out]
}

function isLoopbackHost(hostname: string): boolean {
  const lower = hostname.toLowerCase()
  return lower === 'localhost' || lower === '127.0.0.1' || lower === '[::1]' || lower === '::1'
}

function areSiblingSiteOrigins(originA: string, originB: string): boolean {
  let urlA: URL
  let urlB: URL
  try {
    urlA = new URL(originA)
    urlB = new URL(originB)
  } catch {
    return false
  }
  const hostA = urlA.hostname.toLowerCase()
  const hostB = urlB.hostname.toLowerCase()
  if (hostA === hostB) return true
  if (isLoopbackHost(hostA) && isLoopbackHost(hostB)) return true
  const labelsA = hostA.split('.').filter(Boolean)
  const labelsB = hostB.split('.').filter(Boolean)
  if (labelsA.length >= 2 && labelsB.length >= 2) {
    const tailA = `${labelsA[labelsA.length - 2]}.${labelsA[labelsA.length - 1]}`
    const tailB = `${labelsB[labelsB.length - 2]}.${labelsB[labelsB.length - 1]}`
    if (tailA === tailB) return true
  }
  return false
}

/**
 * Resolve whether a browser subrequest may attach `persona` credentials.
 *
 * Security invariants:
 * - Never attaches credentials to passive asset hydration (`assetHydration === true`).
 * - Always attaches for exact same-origin requests (`targetOrigin === pageOrigin`).
 * - For cross-origin requests (e.g. an SPA on `app.example.com` calling a sibling API on
 *   `api.example.com`), attaches `persona` ONLY when:
 *   1. `grant.canRead(targetOrigin)` is true (strictly in-scope target origin), AND
 *   2. `targetOrigin` is explicitly listed in `grant.personas.get(persona).originAllowlist`
 *      (strictly refusing out-of-scope or third-party origins — zero credential leakage), AND
 *   3. Not explicitly excluded by a non-credentialed `validatedFetch` (`credentials !== 'include'`), AND
 *   4. The request carries credentials, is same-site / sibling API, or is an API/navigation fetch.
 */
export function resolvePersonaForBrowserRequest(params: {
  persona: string | undefined
  pageOrigin: string
  targetOrigin: string
  grant: Pick<Grant, 'canRead' | 'personas'>
  assetHydration: boolean
  resourceType: string
  requestHeaders: Record<string, string>
  validatedFetch?: { origin: string; credentials: 'include' | 'same-origin' | 'omit' } | null
}): string | undefined {
  const { persona, pageOrigin, targetOrigin, grant, assetHydration, resourceType, requestHeaders, validatedFetch } = params
  if (!persona || assetHydration) return undefined
  if (targetOrigin === pageOrigin) return persona
  if (!grant.canRead(targetOrigin)) return undefined

  const resolvedPersona = grant.personas?.get(persona)
  if (!resolvedPersona || resolvedPersona.originAllowlist.length === 0) return undefined
  let allowlisted = false
  for (const entry of resolvedPersona.originAllowlist) {
    try {
      const parsed = new URL(entry)
      if ((parsed.protocol === 'https:' || parsed.protocol === 'http:') && parsed.origin === targetOrigin) {
        allowlisted = true
        break
      }
    } catch {
      // Ignore malformed allowlist entries (fail closed).
    }
  }
  if (!allowlisted) return undefined

  if (validatedFetch && validatedFetch.origin === targetOrigin) {
    return validatedFetch.credentials === 'include' ? persona : undefined
  }

  let hasCredentialHeader = false
  let secFetchSite = ''
  let secFetchMode = ''
  for (const [key, value] of Object.entries(requestHeaders)) {
    const lower = key.toLowerCase()
    if ((lower === 'cookie' || lower === 'authorization') && value.trim().length > 0) {
      hasCredentialHeader = true
    } else if (lower === 'sec-fetch-site') {
      secFetchSite = value.trim().toLowerCase()
    } else if (lower === 'sec-fetch-mode') {
      secFetchMode = value.trim().toLowerCase()
    }
  }

  if (hasCredentialHeader) return persona
  if (secFetchSite === 'same-site' || secFetchSite === 'same-origin') return persona
  if (secFetchMode === 'cors' || secFetchMode === 'navigate') return persona
  if (resourceType === 'fetch' || resourceType === 'xhr' || resourceType === 'document' || resourceType === 'other') {
    return persona
  }
  if (areSiblingSiteOrigins(pageOrigin, targetOrigin)) return persona
  return undefined
}

function collectSecrets(req: BrowserVisitRequest, grant: Grant): NamedSecret[] {
  const out: NamedSecret[] = []
  if (grant.personas) out.push(...personaSecrets(grant.personas))
  if (grant.secrets) out.push(...grant.secrets)
  if (req.secrets) out.push(...req.secrets)
  return out
}

function safeFulfillHeaders(respHeaders: Record<string, string>): Record<string, string> {
  const out: Record<string, string> = {}
  for (const [k, v] of Object.entries(respHeaders)) {
    const lower = k.toLowerCase()
    if (/^(?:transfer-encoding|content-encoding|content-length|connection|set-cookie)$/.test(lower)) continue
    out[k] = v
  }
  return out
}

// ---------------------------------------------------------------------------------------------
// Passive asset-origin scope + read-only GraphQL/RPC POST classification
// ---------------------------------------------------------------------------------------------

/**
 * Match a browser request origin against the passive asset scope. Fail-closed: malformed entries,
 * wildcard-all patterns, and non-HTTP origins never match. `*.example.com` matches subdomains,
 * never the apex unless the apex is listed separately.
 */
export function isAssetOriginAllowed(origin: string, scope: AssetOriginScope | undefined): boolean {
  if (!scope) return false
  let parsed: URL
  try {
    parsed = new URL(origin)
  } catch {
    return false
  }
  if (parsed.protocol !== 'https:' && parsed.protocol !== 'http:') return false
  if (scope.allowlist) {
    try {
      if (scope.allowlist(parsed.origin)) return true
    } catch {
      return false
    }
  }
  const hostAndPort = parsed.host.toLowerCase()
  const hostOnly = parsed.hostname.toLowerCase()
  for (const raw of scope.origins ?? []) {
    const pattern = raw.trim().toLowerCase()
    if (!pattern || pattern === '*' || pattern === '*/*') continue
    if (pattern.includes('://')) {
      try {
        if (new URL(pattern).origin === parsed.origin) return true
      } catch { /* ignore malformed */ }
      continue
    }
    if (pattern.startsWith('*.')) {
      const bare = pattern.slice(2)
      if (!bare) continue
      if (hostOnly !== bare && hostOnly.endsWith(`.${bare}`)) return true
      continue
    }
    if (pattern === hostAndPort || pattern === hostOnly) return true
  }
  return false
}

/** Asset-scoped grant: broker transport still enforces DNS/SSRF/rate limits and audit. */
function assetScopedGrant(grant: Grant, assetOrigin: string): Grant {
  return {
    ...grant,
    // Never widen the primary grant: the browser only consults this derived grant for a request
    // already classified as passive asset hydration.
    canRead: origin => origin === assetOrigin || grant.canRead(origin),
  }
}

/** Strip GraphQL string/comment literals so operation keywords can be classified safely. */
function stripGraphqlLiterals(doc: string): string {
  return doc
    .replace(/"""[\s\S]*?"""/g, '""')
    .replace(/"(?:[^"\\]|\\.)*"/g, '""')
    .replace(/#[^\n\r]*/g, '')
}

function isReadOnlyGraphqlDocument(doc: string): boolean {
  if (!doc.trim()) return false
  const stripped = stripGraphqlLiterals(doc)
  // A mutation/subscription operation anywhere makes the document state-changing.
  if (/\b(?:mutation|subscription)\s*(?:[A-Za-z_][A-Za-z0-9_]*\s*)?(?:\(|\{)/.test(stripped)) return false
  return /^\s*(?:query\b|\{)/.test(stripped) || /^\s*fragment\b/.test(stripped)
}

const readOnlyRpcSegmentRe = /^(?:get|list|search|query|read|describe|introspect|fetch|lookup|find|count|view|status|health)/i
const mutatingRpcSegments = new Set([
  'create', 'update', 'delete', 'remove', 'write', 'set', 'put', 'post', 'patch', 'mutate',
  'insert', 'drop', 'truncate', 'charge', 'pay', 'send', 'upload', 'import', 'reset', 'revoke', 'grant',
])

/**
 * True when a POST body is a read-only GraphQL operation (`query`/anonymous selection set) —
 * introspection-disabled targets still expose observed operations this way.
 */
export function isReadOnlyGraphqlOperation(body: string | null | undefined): boolean {
  if (!body || !body.trim()) return false
  try {
    const parsed = JSON.parse(body) as unknown
    const checkOp = (op: unknown): boolean => {
      if (!op || typeof op !== 'object') return false
      const record = op as Record<string, unknown>
      if (record.mutation !== undefined || record.subscription !== undefined) return false
      if (typeof record.query !== 'string') return false
      if (record.operationName !== undefined && typeof record.operationName !== 'string') return false
      if (record.variables !== undefined && (typeof record.variables !== 'object' || Array.isArray(record.variables))) return false
      return isReadOnlyGraphqlDocument(record.query)
    }
    if (Array.isArray(parsed)) return parsed.length > 0 && parsed.length <= 10 && parsed.every(checkOp)
    return checkOp(parsed)
  } catch {
    // Raw GraphQL document body.
    return isReadOnlyGraphqlDocument(body)
  }
}

/** True when a JSON-RPC style POST names a read-only method and carries no mutating verb. */
export function isReadOnlyRpcOperation(body: string | null | undefined): boolean {
  if (!body || !body.trim()) return false
  let parsed: unknown
  try { parsed = JSON.parse(body) } catch { return false }
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) return false
  const record = parsed as Record<string, unknown>
  const method = typeof record.method === 'string' ? record.method : ''
  if (!method) return false
  const segments = method.split(/[._:-]+/).filter(Boolean)
  if (segments.some(segment => mutatingRpcSegments.has(segment.toLowerCase()))) return false
  const lastSegment = segments[segments.length - 1] ?? ''
  if (!readOnlyRpcSegmentRe.test(lastSegment) && !readOnlyRpcSegmentRe.test(method)) return false
  if (record.mutation !== undefined || record.subscription !== undefined) return false
  return true
}

export interface BrowserRequestClassification {
  allowed: boolean
  assetHydration: boolean
  readOnlyGraphql: boolean
  reason: string | null
}

/**
 * Single decision point for every intercepted browser request. Read-only GraphQL/RPC POSTs are
 * classified below Tier 3 (the broker remains the authoritative boundary for the wire request).
 */
export function classifyBrowserHttpRequest(input: {
  method: string
  url: string
  body?: string | null
  tier: number
  canRead: (origin: string) => boolean
  allowLocalLab: boolean
  assetScope?: AssetOriginScope
  /** v6 three-tier scope: when present, the single `scope-policy` classifier is authoritative. */
  scopePolicy?: ScopePolicy
}): BrowserRequestClassification {
  const method = input.method.toUpperCase()
  let parsed: URL
  try {
    parsed = new URL(input.url)
  } catch {
    return { allowed: false, assetHydration: false, readOnlyGraphql: false, reason: 'malformed_url' }
  }
  if (input.scopePolicy) {
    const decision = evaluateBrowserScopeRequest(input.scopePolicy, {
      origin: parsed.origin,
      method,
      pathAndQuery: `${parsed.pathname}${parsed.search}`,
      body: input.body ?? null,
      redirectHop: true,
    })
    return {
      allowed: decision.allowed,
      assetHydration: decision.allowed && decision.role === 'asset',
      readOnlyGraphql: false,
      reason: decision.allowed ? null : decision.code,
    }
  }
  const protocolOk = parsed.protocol === 'https:' || (input.allowLocalLab && parsed.protocol === 'http:')
  const inScope = input.canRead(parsed.origin)
  const readOnlyGraphql = method === 'POST' &&
    (isReadOnlyGraphqlOperation(input.body ?? null) || isReadOnlyRpcOperation(input.body ?? null))

  if (!inScope) {
    // Passive hydration only: GET/HEAD from an explicit asset origin. Everything else fails closed.
    if (protocolOk && isAssetOriginAllowed(parsed.origin, input.assetScope)) {
      if (method === 'GET' || method === 'HEAD') {
        return { allowed: true, assetHydration: true, readOnlyGraphql: false, reason: null }
      }
      return { allowed: false, assetHydration: false, readOnlyGraphql: false, reason: 'asset_origin_active_probe' }
    }
    return { allowed: false, assetHydration: false, readOnlyGraphql: false, reason: 'out_of_scope' }
  }

  if (!protocolOk) return { allowed: false, assetHydration: false, readOnlyGraphql: false, reason: 'invalid_protocol' }
  if (!allowedMethods.has(method)) return { allowed: false, assetHydration: false, readOnlyGraphql: false, reason: 'method_not_allowed' }

  if (method === 'GET' || method === 'HEAD' || method === 'OPTIONS') {
    return { allowed: true, assetHydration: false, readOnlyGraphql: false, reason: null }
  }
  if (method === 'POST') {
    if (readOnlyGraphql) return { allowed: true, assetHydration: false, readOnlyGraphql: true, reason: null }
    if (input.tier >= 2) return { allowed: true, assetHydration: false, readOnlyGraphql: false, reason: null }
    return { allowed: false, assetHydration: false, readOnlyGraphql: false, reason: 'tier_too_low' }
  }
  if (input.tier >= 3) return { allowed: true, assetHydration: false, readOnlyGraphql: false, reason: null }
  return { allowed: false, assetHydration: false, readOnlyGraphql: false, reason: 'tier_too_low' }
}

/** Distinct, nested unmatched paths used to calibrate per-origin SPA catch-alls. */
export function buildSoft404ProbePaths(count = 3): string[] {
  const n = Math.max(1, Math.min(6, count))
  const token = randomBytes(6).toString('hex')
  const bases = [
    `/.kovo-cal-${token}`,
    `/api/.kovo-cal-${token}/missing`,
    `/app/.kovo-cal-${token}/detail/view`,
    `/v1/.kovo-cal-${token}?probe=1`,
    `/.well-known/kovo-cal-${token}`,
    `/static/.kovo-cal-${token}/absent.json`,
  ]
  return bases.slice(0, n)
}

/**
 * Mirror non-HttpOnly session-jar cookies into the Playwright context so SPA JS
 * (`document.cookie`, Axios XSRF double-submit) observes the same values that the
 * broker sends on the wire. Values never leave the browser process or enter results.
 */
async function mirrorJarCookies(
  context: PlaywrightContext | undefined,
  broker: RequestBroker,
  scope: { session?: string; persona?: string; runId?: string; assignmentId?: string; sessionGroupRole?: string },
  origin: string,
  mirroredSecrets?: NamedSecret[],
): Promise<void> {
  if (!context?.addCookies) return
  try {
    const cookies = broker.sessionCookiesForBrowser(scope, origin)
    if (cookies.length === 0) return
    if (mirroredSecrets) {
      for (const cookie of cookies) {
        if (cookie.value && cookie.value.length >= 6) {
          mirroredSecrets.push({ value: cookie.value, placeholder: `[redacted:cookie:${cookie.name}]` })
        }
      }
    }
    await context.addCookies(cookies.map(cookie => ({
      name: cookie.name,
      value: cookie.value,
      domain: cookie.domain,
      path: cookie.path,
      secure: cookie.secure,
      httpOnly: false,
      sameSite: cookie.sameSite,
      ...(cookie.expires !== undefined ? { expires: cookie.expires } : {}),
    })))
  } catch {
    // Best-effort mirroring: a cookie that Playwright rejects must never fail a visit.
  }
}

/** Collects secret material seeded into a browser context so EgressSanitizer scrubs every field (H-8). */
function collectBundleSecrets(bundle: BrowserSessionBundle | null | undefined): NamedSecret[] {
  if (!bundle) return []
  const out: NamedSecret[] = []
  for (const c of bundle.cookies ?? []) {
    if (c.value && c.value.length >= 6) out.push({ value: c.value, placeholder: `[redacted:cookie:${c.name}]` })
  }
  for (const [k, v] of Object.entries(bundle.localStorage ?? {})) {
    if (v && v.length >= 8) out.push({ value: v, placeholder: `[redacted:storage:${k}]` })
  }
  for (const [k, v] of Object.entries(bundle.sessionStorage ?? {})) {
    if (v && v.length >= 8) out.push({ value: v, placeholder: `[redacted:storage:${k}]` })
  }
  for (const [k, v] of Object.entries(bundle.headers ?? {})) {
    const trimmed = v.replace(/^Bearer\s+/i, '').trim()
    if (trimmed.length >= 6) out.push({ value: trimmed, placeholder: `[redacted:header:${k.toLowerCase()}]` })
  }
  return out
}

function hasDestructiveInput(text: string): boolean {
  if (containsDestructivePayload(text)) return true
  try {
    const decoded = decodeURIComponent(text.replaceAll('+', ' '))
    if (decoded !== text && containsDestructivePayload(decoded)) return true
  } catch {
    const plusDecoded = text.replaceAll('+', ' ')
    if (plusDecoded !== text && containsDestructivePayload(plusDecoded)) return true
  }
  return false
}

function validateSafeSelector(selector: string, origin: string, grant: Grant) {
  if (!selector.trim() || selector.length > 256 || unsafeSelectorPattern.test(selector)) {
    grant.audit('denied', origin)
    throw new BrokerDenied('Browser selector must be a safe CSS selector.')
  }
}

// ---------------------------------------------------------------------------------------------
// Pooled per-persona contexts, session hydration, WS capture, interactive traversal
// ---------------------------------------------------------------------------------------------

export interface BrowserPoolStats {
  launches: number
  contextsCreated: number
  contextsClosed: number
  pagesCreated: number
  activeContexts: number
}

interface PooledLeaseWaiter {
  resolve: () => void
  reject: (err: unknown) => void
  signal?: AbortSignal
  onAbort?: () => void
}

interface PoolSlotWaiter {
  wake: () => void
  fail: (err: unknown) => void
}

function isBrowserConnected(browser: PlaywrightBrowserLike | null): boolean {
  if (!browser) return false
  if (typeof browser.isConnected === 'function') {
    try {
      return browser.isConnected()
    } catch {
      return false
    }
  }
  return true
}

interface PooledRuntime {
  key: string
  runId: string | undefined
  origin: string
  context: PlaywrightContext
  page: PlaywrightPage
  proxyBinding: LoopbackProxyContextBinding
  wireVault: BrowserWirePlaceholderVault
  sockets: Map<string, BrowserWebSocketRecord>
  cdp: PlaywrightCdpSession | null
  active: PooledVisitState | null
  /** Mutable per-checkout grant bound on visit start and cleared on release (never stale across assignments). */
  activeGrant: Grant | null
  /** Mutable per-checkout local-lab flag paired with `activeGrant`. */
  activeAllowLocalLab: boolean
  /** Active host-side execution attestor for the current leased visit (cleared on release). */
  activeAttestor: HostExecutionAttestor | null
  /** Explicit lease counter (0 when idle, 1 while leased); LRU eviction skips active > 0. */
  activeLeases: number
  /** Ownership token guarding lease release so concurrent callers cannot clobber each other. */
  leaseOwner: symbol | null
  /** FIFO serialization queue for concurrent visits targeting the same runtime key. */
  leaseQueue: PooledLeaseWaiter[]
  /** Set by `releaseRun` when a run is disposed while a visit is still in flight. */
  closeOnRelease: boolean
  /** True once this runtime has been torn down. */
  closed: boolean
  lastUsed: number
}

interface PooledVisitState {
  origin: string
  targetHref: string
  persona?: string
  session?: string
  sessionGroupRole?: string
  csrfBind?: CsrfBind
  runId?: string
  assignmentId?: string
  traceId?: string
  tier: number
  secrets: NamedSecret[]
  assetScope: AssetOriginScope
  validatedFetch: { url: string; origin: string; method: 'GET' | 'HEAD' | 'OPTIONS'; credentials: 'include' | 'same-origin' | 'omit' } | null
  exchanges: BrokerExchangeResult[]
  exchangeIds: string[]
  xhrRequests: BrowserXhrRecord[]
  allRequests: BrowserXhrRecord[]
  xhrBodyBudget: { chars: number }
  blockedOrigins: Set<string>
  consoleMessages: Array<{ type: 'error' | 'warning'; text: string }>
  primaryNavigationError: unknown | null
  onExchange?: (exchange: BrokerExchangeResult) => string | void
  signal?: AbortSignal
}

function normalizeSeedBundle(raw: unknown): BrowserSessionBundle | null {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return null
  const record = raw as Record<string, unknown>
  const hasShape = 'cookies' in record || 'localStorage' in record || 'sessionStorage' in record || 'initScript' in record
  if (!hasShape) return null
  const bundle: BrowserSessionBundle = {}
  if (Array.isArray(record.cookies)) {
    const cookies: BrowserSeedCookie[] = []
    for (const candidate of record.cookies.slice(0, 64)) {
      if (!candidate || typeof candidate !== 'object') continue
      const c = candidate as Record<string, unknown>
      if (typeof c.name !== 'string' || typeof c.value !== 'string' || typeof c.domain !== 'string') continue
      const expiresRaw = typeof c.expires === 'number' && Number.isFinite(c.expires) ? c.expires : undefined
      const sameSiteRaw = typeof c.sameSite === 'string' ? c.sameSite : undefined
      cookies.push({
        name: c.name.slice(0, 256),
        value: c.value.slice(0, 8192),
        domain: c.domain.slice(0, 255),
        path: typeof c.path === 'string' && c.path ? c.path.slice(0, 512) : '/',
        secure: c.secure === true,
        httpOnly: c.httpOnly === true,
        ...(sameSiteRaw === 'Strict' || sameSiteRaw === 'Lax' || sameSiteRaw === 'None' ? { sameSite: sameSiteRaw } : {}),
        // Playwright expects epoch seconds; accept millisecond timestamps defensively.
        ...(expiresRaw !== undefined ? { expires: Math.floor(expiresRaw > 1e12 ? expiresRaw / 1000 : expiresRaw) } : {}),
      })
    }
    if (cookies.length > 0) bundle.cookies = cookies
  }
  const normalizeStorage = (value: unknown): Record<string, string> | undefined => {
    if (!value || typeof value !== 'object' || Array.isArray(value)) return undefined
    const out: Record<string, string> = {}
    for (const [k, v] of Object.entries(value as Record<string, unknown>).slice(0, 64)) {
      if (!k || typeof v !== 'string') continue
      out[k.slice(0, 256)] = v.slice(0, 8192)
    }
    return Object.keys(out).length > 0 ? out : undefined
  }
  const local = normalizeStorage(record.localStorage)
  const session = normalizeStorage(record.sessionStorage)
  if (local) bundle.localStorage = local
  if (session) bundle.sessionStorage = session
  if (typeof record.initScript === 'string' && record.initScript) bundle.initScript = record.initScript
  if (record.headers && typeof record.headers === 'object' && !Array.isArray(record.headers)) {
    const headers: Record<string, string> = {}
    for (const [k, v] of Object.entries(record.headers as Record<string, unknown>).slice(0, 32)) {
      if (typeof v === 'string' && !/[\r\n\0]/.test(k + v)) headers[k.slice(0, 128)] = v.slice(0, 4096)
    }
    if (Object.keys(headers).length > 0) bundle.headers = headers
  }
  return Object.keys(bundle).length > 0 ? bundle : null
}

/** Structural read of optional persona session material (legacy `headerType`/`value` sessions keep working). */
export function personaSessionBundle(grant: Grant, persona: string | undefined, origin?: string): BrowserSessionBundle | null {
  if (!persona) return null
  const resolved = grant.personas?.get(persona)
  if (!resolved) return null
  if (origin) {
    try {
      const attachment = buildPersonaBrowserAttachment(resolved, origin)
      if (attachment) {
        const cookies = attachment.cookies.map(cookie => ({
          name: cookie.name,
          value: cookie.value,
          domain: cookie.domain,
          path: cookie.path,
          secure: cookie.secure,
          httpOnly: cookie.httpOnly,
          ...(cookie.sameSite ? { sameSite: cookie.sameSite } : {}),
          ...(cookie.expires !== undefined ? { expires: cookie.expires } : {}),
        }))
        const headers: Record<string, string> = { ...attachment.headers }
        // A cookie-auth persona stores a raw Cookie header. A pooled context must own the jar
        // instead: split the header into individual HttpOnly cookies and never forward it.
        const rawCookieHeader = headers.Cookie ?? headers.cookie
        if (rawCookieHeader) {
          if (cookies.length === 0) {
            for (const record of cookieRecordsFromHeader(rawCookieHeader, origin)) {
              cookies.push({
                name: record.name,
                value: record.value,
                domain: record.domain,
                path: record.path,
                secure: record.secure === true,
                httpOnly: record.httpOnly === true,
                ...(record.sameSite ? { sameSite: record.sameSite } : {}),
                ...(record.expires !== undefined ? { expires: record.expires } : {}),
              })
            }
          }
          delete headers.Cookie
          delete headers.cookie
        }
        return {
          ...(cookies.length > 0 ? { cookies } : {}),
          ...(attachment.storage?.localStorage ? { localStorage: attachment.storage.localStorage } : {}),
          ...(attachment.storage?.sessionStorage ? { sessionStorage: attachment.storage.sessionStorage } : {}),
          ...(attachment.initScript ? { initScript: attachment.initScript } : {}),
          ...(Object.keys(headers).length > 0 ? { headers } : {}),
        }
      }
    } catch {
      // Fall through to structural legacy material.
    }
  }
  const record = resolved as unknown as Record<string, unknown>
  for (const key of ['sessionBundle', 'bundle']) {
    const bundle = normalizeSeedBundle(record[key])
    if (bundle) return bundle
  }
  return normalizeSeedBundle({
    cookies: record.cookies,
    localStorage: record.localStorage,
    sessionStorage: record.sessionStorage,
  })
}

/** Wrap any storage hydration script so it executes ONLY when `window.location.origin === targetOrigin`. */
export function originLockInitScript(script: string, targetOrigin: string): string {
  const originJson = JSON.stringify(targetOrigin)
  return `(() => {
  try {
    if (window.location.origin !== ${originJson}) return;
  } catch { return; }
  ${script}
})();`
}

function seedStorageInitScript(bundle: BrowserSessionBundle | null, origin: string): string | null {
  if (!bundle) return null
  if (bundle.initScript) {
    return originLockInitScript(bundle.initScript, origin)
  }
  const local = bundle.localStorage ?? {}
  const session = bundle.sessionStorage ?? {}
  if (Object.keys(local).length === 0 && Object.keys(session).length === 0) return null
  const payload = JSON.stringify({ origin, local, session })
  return `(() => {
  try {
    const seed = ${payload};
    if (window.location.origin !== seed.origin) return;
    const apply = (store, entries) => {
      for (const key of Object.keys(entries || {})) {
        try { if (store.getItem(key) === null) store.setItem(key, entries[key]); } catch {}
      }
    };
    apply(window.localStorage, seed.local);
    apply(window.sessionStorage, seed.session);
  } catch {}
})();`
}

/**
 * Strictly filter bundle cookies to those applicable to `targetOrigin` (H9):
 * - Host-only cookies (no leading `.`) require exact hostname match.
 * - Domain cookies (leading `.`) require domain or subdomain match (never IP suffix matches).
 * - `Secure` cookies are never hydrated onto plaintext `http:` origins.
 */
export function filterCookiesForOrigin(
  cookies: readonly BrowserSeedCookie[],
  targetOrigin: string,
): BrowserSeedCookie[] {
  let parsed: URL
  try {
    parsed = new URL(targetOrigin)
  } catch {
    return []
  }
  const targetHost = parsed.hostname.toLowerCase().replace(/^\[|\]$/g, '')
  const isHttps = parsed.protocol === 'https:'
  const targetIsIp = isIpLiteralHost(targetHost)

  return cookies.filter(cookie => {
    if (!cookie.name || !cookie.domain) return false
    if (cookie.secure && !isHttps) return false
    const rawDomain = cookie.domain.trim().toLowerCase().replace(/^\[|\]$/g, '')
    if (!rawDomain) return false
    if (rawDomain.startsWith('.')) {
      const base = rawDomain.slice(1)
      if (!base || targetIsIp || isIpLiteralHost(base)) {
        return targetHost === base
      }
      return targetHost === base || targetHost.endsWith(`.${base}`)
    }
    return targetHost === rawDomain
  })
}

async function hydrateContextSession(
  context: PlaywrightContext,
  bundle: BrowserSessionBundle | null,
  origin: string,
  wireVault?: BrowserWirePlaceholderVault,
  allowedOrigins?: readonly string[],
): Promise<void> {
  if (!bundle) return
  const prepared = wireVault
    ? wireVault.prepareSeedBundle(bundle, origin, allowedOrigins)
    : { cookies: filterCookiesForOrigin(bundle.cookies ?? [], origin), placeholderHeaders: {} }
  if (context.setExtraHTTPHeaders && prepared.placeholderHeaders.authorization) {
    try {
      await context.setExtraHTTPHeaders({ Authorization: prepared.placeholderHeaders.authorization })
    } catch {
      // Best-effort placeholder header binding; never fail a visit if mock context refuses.
    }
  }
  if (!context.addCookies || !prepared.cookies.length) return
  try {
    await context.addCookies(prepared.cookies.map(cookie => ({
      name: cookie.name,
      value: cookie.value,
      domain: cookie.domain,
      path: cookie.path,
      secure: cookie.secure,
      httpOnly: cookie.httpOnly === true,
      ...(cookie.sameSite ? { sameSite: cookie.sameSite } : {}),
      ...(cookie.expires !== undefined ? { expires: cookie.expires } : {}),
    })))
  } catch {
    // Hydration is best-effort: a rejected cookie must never fail a visit.
  }
}

/** Wait for network-idle plus DOM stability instead of a fixed settle sleep. */
export async function waitForBrowserSettle(page: PlaywrightPage, timeoutMs: number): Promise<void> {
  const limit = Math.max(250, Math.min(timeoutMs, 5_000))
  if (typeof page.waitForLoadState === 'function') {
    await page.waitForLoadState('networkidle', { timeout: limit }).catch(() => undefined)
  } else {
    await page.waitForTimeout(Math.min(400, limit)).catch(() => undefined)
  }
  try {
    await page.evaluate(async (quietMs: number) => {
      await new Promise<void>(resolve => {
        let timer: ReturnType<typeof setTimeout> | null = null
        let observer: MutationObserver | null = null
        const finish = () => {
          try { observer?.disconnect() } catch { /* ignore */ }
          resolve()
        }
        try {
          observer = new MutationObserver(() => {
            if (timer) clearTimeout(timer)
            timer = setTimeout(finish, quietMs)
          })
          observer.observe(document.documentElement || document, {
            childList: true, subtree: true, attributes: true, characterData: true,
          })
          timer = setTimeout(finish, quietMs + 100)
        } catch {
          finish()
        }
      })
    }, 200)
  } catch {
    // DOM stability is best-effort; a page without MutationObserver is still inspected.
  }
}

/**
 * Collect non-destructive SPA navigation affordances (tabs, drawers, pagination, filters, modals).
 * Form submits and destructive controls are excluded in read-only mode.
 */
async function collectInteractiveCandidates(page: PlaywrightPage): Promise<Array<{ selector: string; kind: string; text: string }>> {
  try {
    return await page.evaluate((readOnly: boolean) => {
      const destructive = /(?:^|\b)(?:delete|remove|destroy|drop|revoke|deactivate|logout|sign\s*out|pay|purchase|checkout|refund|charge|transfer|send|publish|deploy|reset|purge|wipe|approve|grant)(?:\b|$)/i
      const selectors = [
        '[role="tab"]',
        '[role="tablist"] [role="tab"]',
        '[data-testid*="tab" i]',
        '[data-test*="tab" i]',
        'a[rel="next"]',
        '[aria-label*="next" i]',
        '[data-testid*="pagination" i] a',
        '.pagination a',
        '[aria-expanded][aria-controls]',
        '[data-testid*="drawer" i] button',
        '[data-testid*="menu" i] button',
        '[data-testid*="filter" i] button',
        '[aria-haspopup="dialog"]',
        '[aria-haspopup="listbox"]',
        'button[aria-controls]',
      ]
      const cssPath = (el: Element): string => {
        const parts: string[] = []
        let node: Element | null = el
        let depth = 0
        while (node && node.nodeType === 1 && depth < 6) {
          let part = node.tagName.toLowerCase()
          const id = node.getAttribute('id')
          if (id && /^[A-Za-z][\w-]{0,63}$/.test(id)) { parts.unshift(`${part}#${id}`); break }
          const testId = node.getAttribute('data-testid')
          if (testId && /^[A-Za-z][\w-]{0,63}$/.test(testId)) { parts.unshift(`${part}[data-testid="${testId}"]`); break }
          const parent: Element | null = node.parentElement
          if (parent) {
            const siblings = Array.from(parent.children).filter(child => child.tagName === node!.tagName)
            if (siblings.length > 1) part += `:nth-of-type(${siblings.indexOf(node) + 1})`
          }
          parts.unshift(part)
          node = parent
          depth += 1
        }
        return parts.join(' > ')
      }
      const seen = new Set<string>()
      const out: Array<{ selector: string; kind: string; text: string }> = []
      for (const base of selectors) {
        let nodes: Element[] = []
        try { nodes = Array.from(document.querySelectorAll(base)) } catch { continue }
        for (const el of nodes.slice(0, 12)) {
          if (!(el instanceof HTMLElement)) continue
          if (el.closest('form') && readOnly) continue
          const tag = el.tagName.toLowerCase()
          if (readOnly && (tag === 'input' || tag === 'select' || tag === 'textarea')) continue
          if (readOnly && el.getAttribute('type') === 'submit') continue
          const text = (el.textContent || el.getAttribute('aria-label') || el.getAttribute('title') || '').trim().slice(0, 80)
          if (destructive.test(text)) continue
          const selector = cssPath(el)
          if (!selector || seen.has(selector)) continue
          seen.add(selector)
          out.push({ selector, kind: base, text })
          if (out.length >= 24) return out
        }
      }
      return out
    }, true)
  } catch {
    return []
  }
}

async function traverseInteractive(
  page: PlaywrightPage,
  opts: { maxClicks: number; readOnlyMode: boolean; timeoutMs: number; secrets: readonly NamedSecret[] },
): Promise<BrowserInteractiveTraversalSummary> {
  const candidates = await collectInteractiveCandidates(page)
  let clicked = 0
  let skipped = 0
  const visitedUrls: string[] = []
  for (const candidate of candidates) {
    if (clicked >= opts.maxClicks) break
    try {
      const before = page.url()
      if (typeof page.click === 'function') {
        await page.click(candidate.selector, { timeout: Math.min(2_500, opts.timeoutMs) })
      } else {
        await page.evaluate((selector: string) => {
          const el = document.querySelector(selector) as HTMLElement | null
          if (!el) throw new Error('candidate missing')
          el.click()
        }, candidate.selector)
      }
      await waitForBrowserSettle(page, Math.min(2_000, opts.timeoutMs))
      const after = page.url()
      clicked += 1
      if (after && after !== before && visitedUrls.length < 12) {
        visitedUrls.push(redact(after, [...opts.secrets]).slice(0, 512))
      }
    } catch {
      skipped += 1
    }
  }
  return {
    candidates: candidates.length,
    clicked,
    skipped: skipped + Math.max(0, candidates.length - clicked - skipped),
    visitedUrls,
    readOnlyMode: opts.readOnlyMode,
  }
}

/** Attach CDP `Network.webSocket*` observation; degrades silently when CDP is unavailable. */
async function attachWebSocketCapture(
  context: PlaywrightContext,
  page: PlaywrightPage,
  sockets: Map<string, BrowserWebSocketRecord>,
  secrets: readonly NamedSecret[],
): Promise<PlaywrightCdpSession | null> {
  if (typeof context.newCDPSession !== 'function') return null
  let session: PlaywrightCdpSession
  try {
    session = await context.newCDPSession(page)
  } catch {
    return null
  }
  const boundedPreview = (raw: unknown): string => {
    const text = typeof raw === 'string' ? raw : ''
    return redact(text, [...secrets]).slice(0, 200)
  }
  const ensureSocket = (payload: Record<string, unknown>): BrowserWebSocketRecord | null => {
    const requestId = typeof payload.requestId === 'string' ? payload.requestId : ''
    if (!requestId) return null
    const url = typeof payload.url === 'string' ? payload.url : ''
    let record = sockets.get(requestId)
    if (record) return record
    if (!url) return null
    if (sockets.size >= 20) return null
    let socketOrigin = ''
    try {
      const parsed = new URL(url)
      socketOrigin = `${parsed.protocol === 'wss:' ? 'https:' : parsed.protocol === 'ws:' ? 'http:' : parsed.protocol}//${parsed.host}`
    } catch { /* keep empty */ }
    record = {
      url: redact(url, [...secrets]).slice(0, 512),
      origin: socketOrigin,
      protocol: null,
      handshakeStatus: null,
      openedAt: Date.now(),
      frames: [],
      frameCount: 0,
    }
    sockets.set(requestId, record)
    return record
  }
  session.on('Network.webSocketCreated', payload => { ensureSocket(payload) })
  session.on('Network.webSocketWillSendHandshakeRequest', payload => {
    const record = ensureSocket(payload)
    if (!record) return
    const request = payload.request as Record<string, unknown> | undefined
    const headers = request?.headers as Record<string, unknown> | undefined
    if (headers) {
      const protocol = headers['Sec-WebSocket-Protocol'] ?? headers['sec-websocket-protocol']
      if (typeof protocol === 'string') record.protocol = protocol.slice(0, 128)
    }
  })
  session.on('Network.webSocketHandshakeResponseReceived', payload => {
    const record = ensureSocket(payload)
    if (!record) return
    const response = payload.response as Record<string, unknown> | undefined
    const status = response?.status
    if (typeof status === 'number') record.handshakeStatus = status
  })
  const recordFrame = (direction: 'sent' | 'received', payload: Record<string, unknown>) => {
    const record = ensureSocket(payload)
    if (!record) return
    if (record.frames.length >= 40) return
    const response = payload.response as Record<string, unknown> | undefined
    const rawData = response?.payloadData
    const opcode = typeof response?.opcode === 'number' ? response.opcode : null
    record.frames.push({
      direction,
      opcode,
      payloadLength: typeof rawData === 'string' ? rawData.length : 0,
      preview: boundedPreview(rawData),
      timestamp: Date.now(),
    })
    record.frameCount += 1
  }
  session.on('Network.webSocketFrameSent', payload => recordFrame('sent', payload))
  session.on('Network.webSocketFrameReceived', payload => recordFrame('received', payload))
  session.on('Network.webSocketClosed', payload => {
    const record = ensureSocket(payload)
    if (!record) return
    record.closedAt = Date.now()
  })
  session.on('Network.webSocketFrameError', payload => {
    const record = ensureSocket(payload)
    if (!record || record.frames.length >= 40) return
    record.frames.push({
      direction: 'received',
      opcode: null,
      payloadLength: 0,
      preview: `frame_error:${boundedPreview(payload.errorMessage)}`,
      timestamp: Date.now(),
    })
    record.frameCount += 1
  })
  try {
    await session.send('Network.enable')
  } catch {
    // Observation still works for events emitted by the browser even if enable is a no-op.
  }
  return session
}

export class ScopedBrowser {
  private readonly broker: RequestBroker
  private readonly options: ScopedBrowserOptions
  private poolBrowser: PlaywrightBrowserLike | null = null
  private poolLaunch: Promise<PlaywrightBrowserLike> | null = null
  private poolProxy: EgressLoopbackProxy | null = null
  private poolProxyLaunch: Promise<EgressLoopbackProxy> | null = null
  private poolBrowserDisconnectCleanup: (() => void) | null = null
  private readonly pooled = new Map<string, PooledRuntime>()
  private readonly pooledPending = new Map<string, Promise<PooledRuntime>>()
  private pooledCreating = 0
  private readonly poolSlotWaiters: PoolSlotWaiter[] = []
  private readonly runActiveLeases = new Map<string, number>()
  private readonly poolStats: BrowserPoolStats = {
    launches: 0, contextsCreated: 0, contextsClosed: 0, pagesCreated: 0, activeContexts: 0,
  }

  constructor(broker: RequestBroker, options: ScopedBrowserOptions = {}) {
    this.broker = broker
    this.options = options
  }

  /** Telemetry for the pooled-context design (one Chromium, one context per persona). */
  getPoolStats(): BrowserPoolStats {
    return { ...this.poolStats, activeContexts: this.pooled.size }
  }

  /** Explicit per-run active lease count (`0` when no visits for `runId` are currently in flight). */
  getRunActiveLeases(runId: string): number {
    return this.runActiveLeases.get(runId) ?? 0
  }

  /** Atomically tear down stale pool state when the underlying Chromium process disconnects/crashes. */
  private resetPoolOnBrowserDisconnect(disconnectedBrowser: PlaywrightBrowserLike): void {
    if (this.poolBrowser !== disconnectedBrowser) return
    this.poolBrowserDisconnectCleanup?.()
    this.poolBrowserDisconnectCleanup = null
    this.poolBrowser = null
    this.poolLaunch = null

    const staleEntries = [...this.pooled.values()]
    this.pooled.clear()
    this.pooledPending.clear()
    this.runActiveLeases.clear()

    for (const entry of staleEntries) {
      if (entry.closed) continue
      entry.closed = true
      entry.active = null
      entry.activeGrant = null
      entry.activeAllowLocalLab = false
      entry.activeAttestor = null
      entry.leaseOwner = null
      entry.activeLeases = 0
      const pendingWaiters = entry.leaseQueue.splice(0)
      for (const waiter of pendingWaiters) {
        if (waiter.signal && waiter.onAbort) {
          waiter.signal.removeEventListener('abort', waiter.onAbort)
        }
        waiter.reject(new Error('Pooled browser disconnected unexpectedly before lease acquisition.'))
      }
      entry.wireVault.clear()
      entry.proxyBinding.unregister()
      void entry.cdp?.detach?.().catch(() => undefined)
      void entry.page.close().catch(() => undefined)
      void entry.context.close().catch(() => undefined)
      this.poolStats.contextsClosed += 1
    }
    this.notifyPoolSlotWaiters()
  }

  private async ensurePoolBrowser(allowRetry = true): Promise<PlaywrightBrowserLike> {
    if (this.poolBrowser) {
      if (isBrowserConnected(this.poolBrowser)) {
        return this.poolBrowser
      }
      // Browser process exited or crashed without firing disconnected yet: reset pool atomically.
      this.resetPoolOnBrowserDisconnect(this.poolBrowser)
    }
    if (!this.poolLaunch) {
      let launchPromise: Promise<PlaywrightBrowserLike> | null = null
      launchPromise = (async () => {
        try {
          const browser = await (this.options.launchBrowser ? this.options.launchBrowser() : launchChromium())
          if (!isBrowserConnected(browser)) {
            await browser.close().catch(() => undefined)
            throw new Error('Launched Chromium browser disconnected before pool initialization completed.')
          }
          this.poolStats.launches += 1
          this.poolBrowser = browser
          const onDisconnected = () => {
            this.resetPoolOnBrowserDisconnect(browser)
          }
          if (typeof browser.on === 'function') {
            browser.on('disconnected', onDisconnected)
            this.poolBrowserDisconnectCleanup = () => {
              try { browser.off?.('disconnected', onDisconnected) } catch { /* ignore */ }
            }
          } else {
            this.poolBrowserDisconnectCleanup = null
          }
          return browser
        } catch (err) {
          if (this.poolLaunch === launchPromise) {
            this.poolLaunch = null
          }
          throw err
        }
      })()
      this.poolLaunch = launchPromise
    }
    const browser = await this.poolLaunch
    if (!isBrowserConnected(browser)) {
      this.resetPoolOnBrowserDisconnect(browser)
      if (allowRetry) {
        return await this.ensurePoolBrowser(false)
      }
      throw new Error('Pooled Chromium browser disconnected immediately after launch.')
    }
    return browser
  }

  private async ensurePoolProxy(): Promise<EgressLoopbackProxy> {
    if (this.poolProxy) return this.poolProxy
    if (!this.poolProxyLaunch) {
      this.poolProxyLaunch = (async () => {
        try {
          // C5: The shared loopback proxy itself fails closed on default credentials; every pooled
          // BrowserContext registers its own random Proxy-Authorization credential + isolated policy
          // via `registerContextPolicy` so concurrent contexts NEVER union `allowLocalLab` or origins!
          const proxy = await EgressGateway.createLoopbackProxy({
            allowLocalLab: false,
            allowOrigin: () => ({
              allowed: false,
              reason: 'Pooled browser proxy requires per-context Proxy-Authorization credentials.',
            }),
            ...(this.options.proxyResolveHost ? { resolveHost: this.options.proxyResolveHost } : {}),
          })
          this.poolProxy = proxy
          return proxy
        } catch (err) {
          this.poolProxyLaunch = null
          throw err
        }
      })()
    }
    return await this.poolProxyLaunch
  }

  private async createVisitLoopbackProxy(params: {
    grant: Grant
    tier: number
    allowLocalLab: boolean
    assetScope?: AssetOriginScope
    wireVault?: BrowserWirePlaceholderVault
    getBlockedOrigins: () => Set<string>
  }): Promise<EgressLoopbackProxy> {
    const { grant, tier, allowLocalLab, assetScope, wireVault, getBlockedOrigins } = params
    return await EgressGateway.createLoopbackProxy({
      allowLocalLab,
      ...(grant.scopePolicy ? { scopePolicy: grant.scopePolicy } : {}),
      allowConnectPort: (port, hostname) => isBrowserConnectPortAllowed({
        port,
        hostname,
        grant,
        allowLocalLab,
        assetScope,
      }),
      allowOrigin: (origin, method, url) => {
        const decision = classifyBrowserHttpRequest({
          method: method === 'CONNECT' ? 'GET' : method,
          url: url.href,
          tier,
          canRead: o => grant.canRead(o),
          allowLocalLab,
          assetScope,
          scopePolicy: grant.scopePolicy,
        })
        if (decision.allowed) return true
        if (method === 'CONNECT' && allowLocalLab && url.protocol === 'https:') {
          const httpDecision = classifyBrowserHttpRequest({
            method: 'GET',
            url: url.href.replace(/^https:/i, 'http:'),
            tier,
            canRead: o => grant.canRead(o),
            allowLocalLab,
            assetScope,
            scopePolicy: grant.scopePolicy,
          })
          if (httpDecision.allowed) return true
        }
        return { allowed: false, reason: decision.reason ?? `Browser proxy denied origin "${origin}".` }
      },
      ...(wireVault
        ? {
            transformRequestHeaders: (url, headers) =>
              wireVault.substituteWireHeaders(url, headers, origin => grant.canRead(origin)),
          }
        : {}),
      ...(this.options.proxyResolveHost ? { resolveHost: this.options.proxyResolveHost } : {}),
      onDenied: event => {
        if (event.origin) getBlockedOrigins().add(event.origin)
        try { grant.audit('denied', event.origin || event.url) } catch { /* ignore */ }
      },
    })
  }

  private assetScopeFor(req: Pick<BrowserVisitRequest, 'assetOrigins'>): AssetOriginScope | undefined {
    const origins = [...(this.options.assetOrigins ?? []), ...(req.assetOrigins ?? [])]
    if (origins.length === 0 && !this.options.assetOriginAllowlist) return undefined
    return {
      ...(origins.length > 0 ? { origins } : {}),
      ...(this.options.assetOriginAllowlist ? { allowlist: this.options.assetOriginAllowlist } : {}),
    }
  }

  private async resolveBundle(req: BrowserVisitRequest, grant: Grant, origin: string): Promise<BrowserSessionBundle | null> {
    if (req.sessionBundle) return normalizeSeedBundle(req.sessionBundle)
    // v6-auth: composite bundle (HttpOnly cookies, headers, persisted web storage) is the default
    // seeding source; legacy `headerType`/`value` sessions still resolve through the same helper.
    const fromVault = personaSessionBundle(grant, req.persona, origin)
    if (fromVault) return fromVault
    if (this.options.resolveSessionBundle && req.persona) {
      try {
        const resolved = await this.options.resolveSessionBundle(req.persona, origin)
        const bundle = normalizeSeedBundle(resolved)
        if (bundle) return bundle
      } catch {
        // No bundle available; context is seeded with broker jar cookies only.
      }
    }
    return null
  }

  private async closePooledRuntime(entry: PooledRuntime): Promise<void> {
    if (entry.closed) return
    entry.closed = true
    if (this.pooled.get(entry.key) === entry) {
      this.pooled.delete(entry.key)
    }
    entry.active = null
    entry.activeGrant = null
    entry.activeAllowLocalLab = false
    entry.activeAttestor = null
    entry.leaseOwner = null
    const pendingWaiters = entry.leaseQueue.splice(0)
    for (const waiter of pendingWaiters) {
      if (waiter.signal && waiter.onAbort) {
        waiter.signal.removeEventListener('abort', waiter.onAbort)
      }
      waiter.reject(new Error('Pooled browser context was closed before lease acquisition.'))
    }
    entry.wireVault.clear()
    entry.proxyBinding.unregister()
    await entry.cdp?.detach?.().catch(() => undefined)
    await entry.page.close().catch(() => undefined)
    await entry.context.close().catch(() => undefined)
    this.poolStats.contextsClosed += 1
    this.notifyPoolSlotWaiters()
  }

  private resolvePoolLimits(): { maxContexts: number; hardCap: number } {
    const maxContexts = Math.max(1, Math.min(this.options.maxPooledContexts ?? 8, 16))
    const hardCap = this.options.maxActiveContexts !== undefined
      ? Math.max(1, Math.min(Math.trunc(this.options.maxActiveContexts), 32))
      : Math.min(20, maxContexts + Math.max(1, Math.min(4, Math.floor(maxContexts / 2))))
    return { maxContexts, hardCap }
  }

  private hasIdlePooledContext(): boolean {
    for (const entry of this.pooled.values()) {
      if (!entry.closed && entry.activeLeases === 0 && entry.active === null && entry.leaseQueue.length === 0) {
        return true
      }
    }
    return false
  }

  private notifyPoolSlotWaiters(): void {
    const waiters = this.poolSlotWaiters.splice(0)
    for (const waiter of waiters) {
      waiter.wake()
    }
  }

  private rejectAllPoolSlotWaiters(err: Error): void {
    const waiters = this.poolSlotWaiters.splice(0)
    for (const waiter of waiters) {
      waiter.fail(err)
    }
  }

  private waitForPoolSlotEvent(timeoutMs: number, signal?: AbortSignal): Promise<void> {
    signal?.throwIfAborted()
    return new Promise<void>((resolve, reject) => {
      let settled = false
      const cleanup = () => {
        clearTimeout(timer)
        if (signal && onAbort) signal.removeEventListener('abort', onAbort)
        const idx = this.poolSlotWaiters.indexOf(waiter)
        if (idx >= 0) this.poolSlotWaiters.splice(idx, 1)
      }
      const waiter: PoolSlotWaiter = {
        wake: () => {
          if (settled) return
          settled = true
          cleanup()
          resolve()
        },
        fail: err => {
          if (settled) return
          settled = true
          cleanup()
          reject(err)
        },
      }
      const onAbort = signal
        ? () => {
            if (settled) return
            settled = true
            cleanup()
            reject(signal.reason ?? new Error('Browser pool context wait aborted.'))
          }
        : undefined
      const timer = setTimeout(() => {
        if (settled) return
        settled = true
        cleanup()
        resolve()
      }, Math.max(1, timeoutMs))
      if (signal && onAbort) {
        signal.addEventListener('abort', onAbort, { once: true })
      }
      this.poolSlotWaiters.push(waiter)
    })
  }

  /** Evict strictly idle (`activeLeases === 0`) LRU contexts; never evict an active context. */
  private async evictIdleLruIfNeeded(maxContexts: number): Promise<void> {
    while (this.pooled.size >= maxContexts) {
      let oldestIdle: PooledRuntime | null = null
      for (const entry of this.pooled.values()) {
        if (entry.closed || entry.activeLeases > 0 || entry.active !== null || entry.leaseQueue.length > 0) {
          continue
        }
        if (!oldestIdle || entry.lastUsed < oldestIdle.lastUsed) {
          oldestIdle = entry
        }
      }
      if (!oldestIdle) break
      await this.closePooledRuntime(oldestIdle)
    }
  }

  /**
   * Bounded semaphore backpressure for pooled context creation:
   * - Evicts idle LRU contexts down below `maxContexts` (never evicting active contexts).
   * - When all slots up to `hardCap` are actively leased or being created, waits for an active
   *   context to release (bounded by `poolAcquireTimeoutMs` and `signal`) rather than silently
   *   leaking unbounded Chromium contexts.
   * - Reserves one creation slot (`this.pooledCreating += 1`) synchronously upon acquisition.
   */
  private async reservePoolCreationSlot(signal?: AbortSignal): Promise<void> {
    const { maxContexts, hardCap } = this.resolvePoolLimits()
    const acquireTimeoutMs = Math.max(50, this.options.poolAcquireTimeoutMs ?? DEFAULT_POOL_ACQUIRE_TIMEOUT_MS)
    const deadlineAt = Date.now() + acquireTimeoutMs

    for (;;) {
      signal?.throwIfAborted()
      await this.evictIdleLruIfNeeded(maxContexts)
      // Synchronously check capacity after eviction and reserve slot before any further await.
      if (this.pooled.size + this.pooledCreating < hardCap) {
        this.pooledCreating += 1
        return
      }
      if (this.hasIdlePooledContext()) {
        // An idle context became available during eviction/yield; loop to reclaim it immediately.
        await this.evictIdleLruIfNeeded(Math.max(1, hardCap - this.pooledCreating))
        if (this.pooled.size + this.pooledCreating < hardCap) {
          this.pooledCreating += 1
          return
        }
      }
      const remainingMs = deadlineAt - Date.now()
      if (remainingMs <= 0) {
        throw new Error(
          `ScopedBrowser pool capacity exhausted (${this.pooled.size} active/pooled, ${this.pooledCreating} creating, limit ${hardCap}); timed out after ${acquireTimeoutMs} ms waiting for a pooled context slot.`,
        )
      }
      await this.waitForPoolSlotEvent(remainingMs, signal)
    }
  }

  private async acquireRuntimeLease(runtime: PooledRuntime, signal?: AbortSignal): Promise<symbol> {
    signal?.throwIfAborted()
    while (runtime.activeLeases > 0) {
      if (runtime.closed) {
        throw new Error('Pooled browser context was closed while waiting for lease.')
      }
      await new Promise<void>((resolve, reject) => {
        const waiter: PooledLeaseWaiter = { resolve, reject, signal }
        if (signal) {
          const onAbort = () => {
            const idx = runtime.leaseQueue.indexOf(waiter)
            if (idx >= 0) runtime.leaseQueue.splice(idx, 1)
            reject(signal.reason ?? new Error('Browser lease acquisition aborted.'))
          }
          waiter.onAbort = onAbort
          signal.addEventListener('abort', onAbort, { once: true })
        }
        runtime.leaseQueue.push(waiter)
      })
      signal?.throwIfAborted()
    }
    if (runtime.closed) {
      throw new Error('Pooled browser context was closed.')
    }
    const owner = Symbol('pooled-runtime-lease')
    runtime.leaseOwner = owner
    runtime.activeLeases = 1
    if (runtime.runId) {
      this.runActiveLeases.set(runtime.runId, (this.runActiveLeases.get(runtime.runId) ?? 0) + 1)
    }
    return owner
  }

  private async releaseRuntimeLease(runtime: PooledRuntime, owner: symbol): Promise<void> {
    // Ownership-checked release: a caller that does not own the lease can never clobber an active visit.
    if (runtime.leaseOwner !== owner) return
    runtime.active = null
    runtime.activeGrant = null
    runtime.activeAllowLocalLab = false
    runtime.activeAttestor = null
    runtime.leaseOwner = null
    runtime.activeLeases = Math.max(0, runtime.activeLeases - 1)
    runtime.lastUsed = Date.now()
    if (runtime.runId) {
      const nextCount = (this.runActiveLeases.get(runtime.runId) ?? 1) - 1
      if (nextCount <= 0) this.runActiveLeases.delete(runtime.runId)
      else this.runActiveLeases.set(runtime.runId, nextCount)
    }
    if (runtime.closeOnRelease && runtime.activeLeases === 0 && runtime.leaseQueue.length === 0) {
      await this.closePooledRuntime(runtime)
      return
    }
    while (runtime.leaseQueue.length > 0 && !runtime.closed) {
      const next = runtime.leaseQueue.shift()!
      if (next.signal && next.onAbort) {
        next.signal.removeEventListener('abort', next.onAbort)
      }
      if (next.signal?.aborted) continue
      next.resolve()
      return
    }
    if (runtime.activeLeases === 0 && !runtime.closed) {
      const { maxContexts } = this.resolvePoolLimits()
      if (this.pooled.size > maxContexts) {
        await this.closePooledRuntime(runtime)
        return
      }
      this.notifyPoolSlotWaiters()
    }
  }

  private async ensurePooledContext(
    browser: PlaywrightBrowserLike,
    req: BrowserVisitRequest,
    initialOrigin: string,
    bundle: BrowserSessionBundle | null,
    signal?: AbortSignal,
  ): Promise<PooledRuntime> {
    // H9: Include `initialOrigin` in the pool key so cookies, initScripts, and storage never leak across origins.
    const key = `${req.runId ?? 'default'}::${req.persona ? `persona:${req.persona}` : 'anonymous'}::${initialOrigin}`
    const existing = this.pooled.get(key)
    if (existing && !existing.closed && !existing.closeOnRelease) {
      existing.lastUsed = Date.now()
      return existing
    }
    // H-24: Dedupe concurrent first-use creation with a promise map so no BrowserContext is orphaned.
    const pending = this.pooledPending.get(key)
    if (pending) {
      const created = await pending
      if (!created.closed && !created.closeOnRelease) return created
    }

    const createPromise = (async (): Promise<PooledRuntime> => {
      await this.reservePoolCreationSlot(signal)
      let slotReserved = true
      try {
        const activeBrowser = isBrowserConnected(browser) ? browser : await this.ensurePoolBrowser()
        const poolProxy = await this.ensurePoolProxy()
      const wireVault = new BrowserWirePlaceholderVault()
      const runtime: PooledRuntime = {
        key,
        runId: req.runId,
        origin: initialOrigin,
        context: undefined as unknown as PlaywrightContext,
        page: undefined as unknown as PlaywrightPage,
        proxyBinding: undefined as unknown as LoopbackProxyContextBinding,
        wireVault,
        sockets: new Map(),
        cdp: null,
        active: null,
        activeGrant: null,
        activeAllowLocalLab: false,
        activeAttestor: null,
        activeLeases: 0,
        leaseOwner: null,
        leaseQueue: [],
        closeOnRelease: false,
        closed: false,
        lastUsed: Date.now(),
      }

      // C5 + H-8: Dedicated per-context Proxy-Authorization credential + policy scoped strictly
      // to THIS runtime, with allowlisted-origin HttpOnly cookie / Authorization wire placeholder swap.
      const proxyBinding = poolProxy.registerContextPolicy({
        allowLocalLab: () => Boolean(runtime.active && runtime.activeAllowLocalLab),
        scopePolicy: () => runtime.activeGrant?.scopePolicy,
        allowConnectPort: (port, hostname) => {
          if (!runtime.active || !runtime.activeGrant) return false
          return isBrowserConnectPortAllowed({
            port,
            hostname,
            grant: runtime.activeGrant,
            allowLocalLab: runtime.activeAllowLocalLab,
            assetScope: runtime.active.assetScope,
          })
        },
        allowOrigin: (origin, method, url) => {
          if (!runtime.active || !runtime.activeGrant) {
            return {
              allowed: false,
              reason: 'Browser proxy denied request without an active visit grant.',
            }
          }
          const decision = classifyBrowserHttpRequest({
            method: method === 'CONNECT' ? 'GET' : method,
            url: url.href,
            tier: runtime.active.tier,
            canRead: o => runtime.activeGrant!.canRead(o),
            allowLocalLab: runtime.activeAllowLocalLab,
            assetScope: runtime.active.assetScope,
            scopePolicy: runtime.activeGrant.scopePolicy,
          })
          if (decision.allowed) return true
          if (method === 'CONNECT' && runtime.activeAllowLocalLab && url.protocol === 'https:') {
            const httpDecision = classifyBrowserHttpRequest({
              method: 'GET',
              url: url.href.replace(/^https:/i, 'http:'),
              tier: runtime.active.tier,
              canRead: o => runtime.activeGrant!.canRead(o),
              allowLocalLab: runtime.activeAllowLocalLab,
              assetScope: runtime.active.assetScope,
              scopePolicy: runtime.activeGrant.scopePolicy,
            })
            if (httpDecision.allowed) return true
          }
          return {
            allowed: false,
            reason: decision.reason ?? `Browser proxy denied out-of-scope origin "${origin}".`,
          }
        },
        transformRequestHeaders: (url, headers) =>
          runtime.wireVault.substituteWireHeaders(
            url,
            headers,
            origin => Boolean(runtime.active && runtime.activeGrant?.canRead(origin)),
          ),
        ...(this.options.proxyResolveHost ? { resolveHost: this.options.proxyResolveHost } : {}),
        onDenied: event => {
          if (!runtime.active || !runtime.activeGrant) return
          if (event.origin) runtime.active.blockedOrigins.add(event.origin)
          try { runtime.activeGrant.audit('denied', event.origin || event.url) } catch { /* ignore */ }
        },
      })
      runtime.proxyBinding = proxyBinding

      let context: PlaywrightContext
      try {
        context = await activeBrowser.newContext({
          ignoreHTTPSErrors: false,
          javaScriptEnabled: true,
          bypassCSP: false,
          serviceWorkers: 'block',
          proxy: proxyBinding.proxyConfig,
          userAgent: 'Kovo/6 pooled scoped inspector',
        })
      } catch (err) {
        proxyBinding.unregister()
        wireVault.clear()
        throw err
      }
      runtime.context = context
      this.poolStats.contextsCreated += 1

      await context.addInitScript(postMessageInstrumentationScript)
      await context.addInitScript(browserWebRtcGuardScript)
      await installWebSocketGuard(context, {
        canRead: origin => Boolean(runtime.activeGrant?.canRead(origin)),
        allowLocalLab: () => runtime.activeAllowLocalLab,
        scopePolicy: () => runtime.activeGrant?.scopePolicy,
        allowedPorts: () => runtime.activeGrant?.allowedPorts,
        allowConnectPort: (port, hostname) => {
          if (!runtime.activeGrant) return false
          return isBrowserConnectPortAllowed({
            port,
            hostname,
            grant: runtime.activeGrant,
            allowLocalLab: runtime.activeAllowLocalLab,
            assetScope: runtime.active?.assetScope,
          })
        },
        audit: (decision, origin) => { runtime.activeGrant?.audit(decision, origin) },
      })
      const storageSeed = seedStorageInitScript(bundle, initialOrigin)
      if (storageSeed) await context.addInitScript(storageSeed)

      await context.route('**/*', async route => {
        const state = runtime.active
        const activeGrant = runtime.activeGrant
        if (!state || !activeGrant) {
          await route.abort('blockedbyclient').catch(() => undefined)
          return
        }
        const request = route.request()
        const rawUrl = request.url()
        if (rawUrl.startsWith('about:') || rawUrl.startsWith('data:') || rawUrl.startsWith('blob:')) {
          await route.fulfill({ status: 200, contentType: 'text/plain', body: '' }).catch(() => undefined)
          return
        }
        const method = request.method().toUpperCase()
        const decision = classifyBrowserHttpRequest({
          method,
          url: rawUrl,
          body: request.postData(),
          tier: state.tier,
          canRead: origin => activeGrant.canRead(origin),
          allowLocalLab: runtime.activeAllowLocalLab,
          assetScope: state.assetScope,
          scopePolicy: activeGrant.scopePolicy,
        })
        if (!decision.allowed) {
          try { state.blockedOrigins.add(new URL(rawUrl).origin) } catch { /* ignore */ }
          try { activeGrant.audit('denied', new URL(rawUrl).origin) } catch { /* ignore */ }
          await route.abort('blockedbyclient').catch(() => undefined)
          return
        }
        let parsedUrl: URL
        try { parsedUrl = new URL(rawUrl) } catch {
          await route.abort('blockedbyclient').catch(() => undefined)
          return
        }
        const rawRequestHeaders = request.headers()
        const forwardedHeaders: Record<string, string> = {}
        for (const [k, v] of Object.entries(rawRequestHeaders)) {
          if (forbiddenBrowserForwardHeaders.test(k)) continue
          forwardedHeaders[k] = v
        }
        const resourceType = request.resourceType()
        const personaForRequest = resolvePersonaForBrowserRequest({
          persona: state.persona,
          pageOrigin: state.origin,
          targetOrigin: parsedUrl.origin,
          grant: activeGrant,
          assetHydration: Boolean(decision.assetHydration),
          resourceType,
          requestHeaders: rawRequestHeaders,
          validatedFetch: state.validatedFetch,
        })
        try {
          const exchange = await this.broker.executeHttp({
            origin: parsedUrl.origin,
            method: method as 'GET' | 'HEAD' | 'OPTIONS' | 'POST' | 'PUT' | 'PATCH' | 'DELETE',
            pathAndQuery: parsedUrl.pathname + parsedUrl.search,
            headers: forwardedHeaders,
            body: request.postData() ?? undefined,
            ...(personaForRequest ? { persona: personaForRequest } : {}),
            ...(state.session ? { session: state.session } : {}),
            ...(state.sessionGroupRole ? { sessionGroupRole: state.sessionGroupRole as 'setup' | 'control' | 'probe' | 'cleanup' } : {}),
            ...(state.csrfBind ? { csrfBind: state.csrfBind } : {}),
            ...(state.runId ? { runId: state.runId } : {}),
            ...(state.assignmentId ? { assignmentId: state.assignmentId } : {}),
            ...(state.traceId ? { traceId: state.traceId } : {}),
            followRedirects: true,
            secrets: state.secrets,
            timeoutMs: Math.max(2_000, 20_000),
          }, decision.assetHydration ? assetScopedGrant(activeGrant, parsedUrl.origin) : activeGrant, state.signal ?? AbortSignal.timeout(25_000))
          if (!decision.assetHydration) {
            state.exchanges.push(exchange)
            const recordedId = state.onExchange?.(exchange)
            if (typeof recordedId === 'string' && recordedId) state.exchangeIds.push(recordedId)
            await mirrorJarCookies(runtime.context, this.broker, {
              ...(personaForRequest ? { persona: personaForRequest } : {}),
              ...(state.session ? { session: state.session } : {}),
              ...(state.runId ? { runId: state.runId } : {}),
              ...(state.assignmentId ? { assignmentId: state.assignmentId } : {}),
              ...(state.sessionGroupRole ? { sessionGroupRole: state.sessionGroupRole } : {}),
            }, parsedUrl.origin, state.secrets)
            const reqRecord: BrowserXhrRecord = {
              method,
              url: redact(parsedUrl.href, state.secrets),
              origin: parsedUrl.origin,
              resourceType,
              status: exchange.status,
              ...((resourceType === 'xhr' || resourceType === 'fetch')
                ? captureXhrJsonBody({ exchange, sameOrigin: parsedUrl.origin === state.origin, secrets: state.secrets, budget: state.xhrBodyBudget })
                : {}),
            }
            if (state.allRequests.length < 200) state.allRequests.push(reqRecord)
            if (resourceType === 'xhr' || resourceType === 'fetch') state.xhrRequests.push(reqRecord)
          } else if (state.allRequests.length < 200) {
            state.allRequests.push({
              method,
              url: `asset:${parsedUrl.origin}${parsedUrl.pathname}`,
              origin: parsedUrl.origin,
              resourceType,
              status: exchange.status,
            })
          }
          await route.fulfill({
            status: exchange.status,
            headers: safeFulfillHeaders(exchange.respHeaders),
            contentType: exchange.mediaType === 'unknown' ? 'application/octet-stream' : exchange.mediaType,
            body: exchange.body,
          }).catch(() => undefined)
        } catch (err) {
          if (!decision.assetHydration && resourceType === 'document' && parsedUrl.href === state.targetHref && state.primaryNavigationError === null) {
            state.primaryNavigationError = err
          }
          if (!decision.assetHydration && state.allRequests.length < 200) {
            state.allRequests.push({
              method,
              url: redact(parsedUrl.href, state.secrets),
              origin: parsedUrl.origin,
              resourceType,
              status: null,
            })
          }
          await route.abort('blockedbyclient').catch(() => undefined)
        }
      })

      runtime.page = await context.newPage()
      this.poolStats.pagesCreated += 1
      // C-8: Register isolated-world host binding once per pooled page delegating to the active per-visit attestor.
      if (typeof runtime.page.exposeBinding === 'function') {
        await runtime.page.exposeBinding(KOVO_EXECUTION_ATTESTATION_BINDING, (source, rawNonce, rawSink) => {
          const attestor = runtime.activeAttestor
          if (!attestor) return { attested: false }
          return attestor.handleBindingCall(source, rawNonce, rawSink)
        })
      }
      runtime.page.on('console', msg => {
        const state = runtime.active
        if (!state || state.consoleMessages.length >= 50) return
        const type = msg.type()
        if (type !== 'error' && type !== 'warning') return
        state.consoleMessages.push({ type, text: redact(msg.text(), state.secrets).slice(0, 500) })
      })
      runtime.page.on('pageerror', err => {
        const state = runtime.active
        if (!state || state.consoleMessages.length >= 50) return
        state.consoleMessages.push({ type: 'error', text: redact(err.message || String(err), state.secrets).slice(0, 500) })
      })
      if (this.options.captureWebSockets !== false) {
        runtime.cdp = await attachWebSocketCapture(context, runtime.page, runtime.sockets, [])
      }
      this.pooled.set(key, runtime)
      slotReserved = false
      this.pooledCreating = Math.max(0, this.pooledCreating - 1)
      return runtime
      } finally {
        if (slotReserved) {
          this.pooledCreating = Math.max(0, this.pooledCreating - 1)
          this.notifyPoolSlotWaiters()
        }
      }
    })()

    this.pooledPending.set(key, createPromise)
    try {
      return await createPromise
    } finally {
      if (this.pooledPending.get(key) === createPromise) {
        this.pooledPending.delete(key)
      }
    }
  }

  /**
   * Visit a sequence of pages through one pooled Chromium and one BrowserContext per `(runId, persona, origin)`.
   * Contexts are leased per-visit with serialization protection, never evicting active contexts from
   * concurrent runs. Call `releaseRun(runId)` on run disposal to cleanly close that run's contexts.
   */
  async visitPages(
    requests: readonly BrowserVisitRequest[],
    grant: Grant,
    signal: AbortSignal,
  ): Promise<BrowserVisitResult[]> {
    const tier = grant.tier ?? 1
    if (tier === 0) throw new BrokerDenied('Scoped browser inspection is disabled in Tier 0 (offline prepared mode).')
    if (!Array.isArray(requests) || requests.length === 0) return []
    const results: BrowserVisitResult[] = []
    const allowLocalLab = Boolean(grant.allowLocalLab && process.env.KOVO_ALLOW_LOCAL_LAB === '1')

    for (const req of requests) {
      signal.throwIfAborted()
      const browser = await this.ensurePoolBrowser()
      const initialOrigin = new URL(req.origin).origin
      if (!req.pathAndQuery.startsWith('/') || req.pathAndQuery.startsWith('//') || /[\r\n\0]/.test(req.pathAndQuery)) {
        grant.audit('denied', initialOrigin)
        throw new BrokerDenied('Invalid browser visit path.')
      }
      if (hasDestructiveInput(req.pathAndQuery)) {
        grant.audit('denied', initialOrigin)
        throw new BrokerDenied('Browser visit blocked by destructive-payload denylist.')
      }
      const targetUrl = new URL(req.pathAndQuery, initialOrigin)
      if (targetUrl.origin !== initialOrigin || !grant.canRead(initialOrigin)) {
        grant.audit('denied', initialOrigin)
        throw new BrokerDenied('Browser destination is outside the current assignment scope.')
      }
      if (req.selector !== undefined) validateSafeSelector(req.selector, initialOrigin, grant)
      const actions = (req.actions ?? []).slice(0, maxInteractiveActions)
      for (const action of actions) {
        if (action.type === 'fill' || action.type === 'select_option') {
          validateSafeSelector(action.selector, initialOrigin, grant)
          if (action.value.length > 2048 || hasDestructiveInput(action.value)) {
            grant.audit('denied', initialOrigin)
            throw new BrokerDenied(`Browser ${action.type} value blocked by destructive-payload denylist or length limit.`)
          }
        } else if (action.type === 'click' || action.type === 'wait_for_selector') {
          validateSafeSelector(action.selector, initialOrigin, grant)
        }
      }

      const started = Date.now()
      const timeoutMs = Math.max(2_000, Math.min(req.timeoutMs ?? maxBrowserTimeoutMs, maxBrowserTimeoutMs))
      const deadline = AbortSignal.any([signal, AbortSignal.timeout(timeoutMs)])
      const secrets = [...collectSecrets(req, grant), ...this.broker.getRegisteredSecrets()]
      const bundle = await this.resolveBundle(req, grant, initialOrigin)
      secrets.push(...collectBundleSecrets(bundle))
      const allowedOrigins = resolveBundleAllowedOrigins(grant, req.persona, initialOrigin)

      // Acquire pooled runtime + exclusive per-runtime lease (retrying once if an idle entry closed mid-wait
      // or the underlying Chromium disconnected and relaunched).
      let runtime = await this.ensurePooledContext(browser, req, initialOrigin, bundle, deadline)
      let leaseOwner: symbol
      try {
        leaseOwner = await this.acquireRuntimeLease(runtime, deadline)
      } catch (err) {
        if (runtime.closed && !deadline.aborted) {
          const freshBrowser = await this.ensurePoolBrowser()
          runtime = await this.ensurePooledContext(freshBrowser, req, initialOrigin, bundle, deadline)
          leaseOwner = await this.acquireRuntimeLease(runtime, deadline)
        } else {
          throw err
        }
      }

      const attestor = createHostExecutionAttestor({
        nonce: req.attestationNonce,
        expectedOrigin: initialOrigin,
      })

      const state: PooledVisitState = {
        origin: initialOrigin,
        targetHref: targetUrl.href,
        ...(req.persona ? { persona: req.persona } : {}),
        ...(req.session ? { session: req.session } : {}),
        ...(req.sessionGroupRole ? { sessionGroupRole: req.sessionGroupRole } : {}),
        ...(req.csrfBind ? { csrfBind: req.csrfBind } : {}),
        ...(req.runId ? { runId: req.runId } : {}),
        ...(req.assignmentId ? { assignmentId: req.assignmentId } : {}),
        ...(req.traceId ? { traceId: req.traceId } : {}),
        tier,
        secrets,
        assetScope: this.assetScopeFor(req) ?? {},
        validatedFetch: null,
        exchanges: [],
        exchangeIds: [],
        xhrRequests: [],
        allRequests: [],
        xhrBodyBudget: { chars: 0 },
        blockedOrigins: new Set(),
        consoleMessages: [],
        primaryNavigationError: null,
        ...(req.onExchange ? { onExchange: req.onExchange } : {}),
        signal: deadline,
      }

      try {
        await hydrateContextSession(runtime.context, bundle, initialOrigin, runtime.wireVault, allowedOrigins)
        runtime.active = state
        runtime.activeGrant = grant
        runtime.activeAllowLocalLab = allowLocalLab
        runtime.activeAttestor = attestor
        runtime.lastUsed = Date.now()
        runtime.sockets.clear()

        let navResponse: { status(): number } | null
        try {
          navResponse = await runtime.page.goto(targetUrl.href, {
            waitUntil: 'domcontentloaded',
            timeout: Math.max(2_000, timeoutMs - (Date.now() - started)),
          })
        } catch (navErr) {
          if (state.primaryNavigationError instanceof Error) {
            throw state.primaryNavigationError
          }
          throw navErr
        }
        if (state.primaryNavigationError && state.exchanges.length === 0) {
          throw state.primaryNavigationError
        }
        if (req.waitForNetworkIdle !== false) {
          await waitForBrowserSettle(runtime.page, Math.max(500, timeoutMs - (Date.now() - started) - 250))
        } else if ((req.waitAfterLoadMs ?? 0) > 0) {
          await runtime.page.waitForTimeout(Math.min(req.waitAfterLoadMs ?? 0, 5_000))
        }
        let interactiveTraversal: BrowserInteractiveTraversalSummary | undefined
        const traversal = req.interactiveTraversal
        if (traversal) {
          const readOnlyMode = req.readOnlyMode !== false
          const maxClicks = typeof traversal === 'object' ? Math.max(1, Math.min(traversal.maxClicks ?? 6, 12)) : 6
          interactiveTraversal = await traverseInteractive(runtime.page, {
            maxClicks,
            readOnlyMode,
            timeoutMs: Math.max(1_000, timeoutMs - (Date.now() - started)),
            secrets,
          })
          await waitForBrowserSettle(runtime.page, Math.max(500, timeoutMs - (Date.now() - started) - 250))
        }

        const snapshot = await runtime.page.evaluate(() => {
          const probe = (window as unknown as {
            __kovoBrowserProbe?: { handlers: Array<{ preview: string; checksOrigin: boolean }>; hasOnMessage: boolean; observedEvents: number }
          }).__kovoBrowserProbe
          const domHtml = document.documentElement?.outerHTML ?? ''
          const links = Array.from(document.querySelectorAll('a[href]'))
            .map(el => el.getAttribute('href') || '').filter(Boolean).slice(0, 160)
          const forms = Array.from(document.querySelectorAll('form')).slice(0, 40).map(form => ({
            action: form.getAttribute('action') || '',
            method: (form.getAttribute('method') || 'GET').toUpperCase(),
            inputNames: Array.from(form.querySelectorAll('input, select, textarea'))
              .map(el => el.getAttribute('name') || el.getAttribute('id') || '').filter(Boolean).slice(0, 30),
          }))
          const cookieNames = (document.cookie || '').split(';').map(pair => pair.split('=', 1)[0]?.trim() || '').filter(Boolean).slice(0, 64)
          let localStorageKeys: string[] = []
          let sessionStorageKeys: string[] = []
          try { localStorageKeys = Object.keys(window.localStorage).slice(0, 64) } catch { /* opaque origin */ }
          try { sessionStorageKeys = Object.keys(window.sessionStorage).slice(0, 64) } catch { /* opaque origin */ }
          return {
            domHtml,
            links,
            forms,
            cookieNames,
            localStorageKeys,
            sessionStorageKeys,
            postMessageListeners: {
              count: probe?.handlers.length ?? 0,
              hasOnMessage: Boolean(probe?.hasOnMessage),
              handlers: (probe?.handlers ?? []).slice(0, 30),
              observedEvents: probe?.observedEvents ?? 0,
              canaryHandledWithoutOriginCheck: false,
            },
          }
        })

        const finalUrlRaw = runtime.page.url()
        const runtimeSecrets = [...secrets, ...this.broker.getRegisteredSecrets()]
        const egress = createEgressSanitizer({ secrets: runtimeSecrets })
        const finalUrl = egress.redactText(finalUrlRaw, 'browser_result')
        const title = egress.redactText(await runtime.page.title().catch(() => ''), 'browser_result').slice(0, 300)
        let finalOrigin = initialOrigin
        try { finalOrigin = new URL(finalUrlRaw).origin } catch { /* keep initial */ }
        const primaryExchange = state.exchanges[0]
        const redirectOrigins = primaryExchange?.redirectOrigins ?? [initialOrigin]
        const initialRedactedUrl = egress.redactText(targetUrl.href, 'browser_result')
        const webSockets = [...runtime.sockets.values()].map(socket => ({
          ...socket,
          frames: socket.frames.map(frame => ({ ...frame, preview: egress.redactText(frame.preview, 'browser_result') })),
        }))
        if (webSockets.length > 0) {
          for (const socket of webSockets) {
            if (state.allRequests.length >= 200) break
            state.allRequests.push({
              method: 'GET',
              url: socket.url,
              origin: socket.origin || finalOrigin,
              resourceType: 'websocket',
              status: socket.handshakeStatus,
            })
          }
        }
        const attestation = attestor.snapshot()
        const attestedSinks = buildVerifiedTraceSinks({ attestation })
        results.push(egress.sanitizeBrowserResult({
          origin: initialOrigin,
          finalUrl,
          title,
          status: navResponse ? navResponse.status() : (primaryExchange?.status ?? null),
          domSnippet: egress.redactText(snapshot.domHtml, 'browser_result').slice(0, maxDomSnippetChars),
          links: [...new Set(snapshot.links.map(link => egress.redactText(link, 'browser_result')))].slice(0, 160),
          forms: snapshot.forms,
          xhrRequests: state.xhrRequests.slice(0, 100),
          allRequests: state.allRequests.slice(0, 200),
          blockedOrigins: [...state.blockedOrigins].slice(0, 100),
          consoleMessages: state.consoleMessages,
          postMessageListeners: {
            ...snapshot.postMessageListeners,
            handlers: snapshot.postMessageListeners.handlers.map(handler => ({
              preview: egress.redactText(handler.preview, 'browser_result'),
              checksOrigin: handler.checksOrigin,
            })),
          },
          cookieNames: snapshot.cookieNames,
          localStorageKeys: snapshot.localStorageKeys,
          sessionStorageKeys: snapshot.sessionStorageKeys,
          canaryCheck: {
            token: req.canaryToken ?? null,
            triggered: attestation.verified,
            detail: attestation.verified ? 'Host-attested isolated binding callback verified.' : null,
            attested: attestation.verified,
            nonce: attestation.nonce,
          },
          attestation,
          attestedSinks,
          domSinkTraces: [],
          ...(interactiveTraversal ? { interactiveTraversal } : {}),
          ...(webSockets.length > 0 ? { webSockets } : {}),
          selectorResult: null,
          fetchResult: null,
          redirectSummary: {
            initialUrl: initialRedactedUrl,
            finalUrl,
            redirected: finalUrl !== initialRedactedUrl || redirectOrigins.length > 1,
            finalOrigin,
            redirectOrigins,
            blockedRedirectAttempt: state.blockedOrigins.size > 0,
          },
          exchangeIds: state.exchangeIds,
          exchanges: state.exchanges,
          durationMs: Date.now() - started,
        }))
      } finally {
        await this.releaseRuntimeLease(runtime, leaseOwner)
      }
    }
    return results
  }

  /**
   * Cleanly close only idle/completed pooled contexts belonging to `runId` on run disposal.
   * Any context for `runId` that is still actively leased is marked to close immediately when
   * its lease releases; contexts belonging to other runs are never touched.
   */
  async releaseRun(runId: string): Promise<number> {
    if (!runId) return 0
    let closedCount = 0
    for (const entry of [...this.pooled.values()]) {
      if (entry.runId !== runId) continue
      if (entry.activeLeases === 0 && entry.active === null && entry.leaseQueue.length === 0) {
        await this.closePooledRuntime(entry)
        closedCount += 1
      } else {
        entry.closeOnRelease = true
      }
    }
    return closedCount
  }

  /** Close every pooled context and the single Chromium process. Idempotent. */
  async close(): Promise<void> {
    this.rejectAllPoolSlotWaiters(new Error('ScopedBrowser was closed while waiting for a pooled context slot.'))
    for (const entry of [...this.pooled.values()]) {
      await this.closePooledRuntime(entry)
    }
    this.pooled.clear()
    this.pooledPending.clear()
    this.runActiveLeases.clear()
    this.poolBrowserDisconnectCleanup?.()
    this.poolBrowserDisconnectCleanup = null
    if (this.poolBrowser) {
      const browserToClose = this.poolBrowser
      this.poolBrowser = null
      this.poolLaunch = null
      await browserToClose.close().catch(() => undefined)
    }
    if (this.poolProxy) {
      const proxyToClose = this.poolProxy
      this.poolProxy = null
      this.poolProxyLaunch = null
      await proxyToClose.close().catch(() => undefined)
    }
  }


  async visitPage(req: BrowserVisitRequest, grant: Grant, signal: AbortSignal): Promise<BrowserVisitResult> {
    const tier = grant.tier ?? 1
    if (tier === 0) throw new BrokerDenied('Scoped browser inspection is disabled in Tier 0 (offline prepared mode).')

    const initialOrigin = new URL(req.origin).origin
    if (!req.pathAndQuery.startsWith('/') || req.pathAndQuery.startsWith('//') || /[\r\n\0]/.test(req.pathAndQuery)) {
      grant.audit('denied', initialOrigin)
      throw new BrokerDenied('Invalid browser visit path.')
    }
    if (hasDestructiveInput(req.pathAndQuery)) {
      grant.audit('denied', initialOrigin)
      throw new BrokerDenied('Browser visit blocked by destructive-payload denylist.')
    }
    const targetUrl = new URL(req.pathAndQuery, initialOrigin)
    if (targetUrl.origin !== initialOrigin || !grant.canRead(initialOrigin)) {
      grant.audit('denied', initialOrigin)
      throw new BrokerDenied('Browser destination is outside the current assignment scope.')
    }

    if (req.selector !== undefined) {
      validateSafeSelector(req.selector, initialOrigin, grant)
    }
    if (req.postMessagePayload !== undefined && hasDestructiveInput(JSON.stringify(req.postMessagePayload))) {
      grant.audit('denied', initialOrigin)
      throw new BrokerDenied('Browser postMessage payload blocked by destructive-payload denylist.')
    }

    // Validate all interactive actions up-front
    const actions = (req.actions ?? []).slice(0, maxInteractiveActions)
    for (const action of actions) {
      if (action.type === 'fill' || action.type === 'select_option') {
        validateSafeSelector(action.selector, initialOrigin, grant)
        if (action.value.length > 2048 || hasDestructiveInput(action.value)) {
          grant.audit('denied', initialOrigin)
          throw new BrokerDenied(`Browser ${action.type} value blocked by destructive-payload denylist or length limit.`)
        }
      } else if (action.type === 'click' || action.type === 'wait_for_selector') {
        validateSafeSelector(action.selector, initialOrigin, grant)
      }
    }

    let validatedFetch: { url: string; origin: string; method: 'GET' | 'HEAD' | 'OPTIONS'; credentials: 'include' | 'same-origin' | 'omit' } | null = null
    if (req.sameSiteFetch) {
      const fetchOrigin = new URL(req.sameSiteFetch.origin).origin
      const fetchPath = req.sameSiteFetch.pathAndQuery
      const fetchMethod = (req.sameSiteFetch.method ?? 'GET').toUpperCase() as 'GET' | 'HEAD' | 'OPTIONS'
      if (!safeReadOnlyFetchMethods.has(fetchMethod)) {
        grant.audit('denied', fetchOrigin)
        throw new BrokerDenied('Browser sameSiteFetch only permits read-only GET/HEAD/OPTIONS methods.')
      }
      if (!fetchPath.startsWith('/') || fetchPath.startsWith('//') || /[\r\n\0]/.test(fetchPath) || hasDestructiveInput(fetchPath)) {
        grant.audit('denied', fetchOrigin)
        throw new BrokerDenied('Invalid or blocked browser sameSiteFetch path.')
      }
      const fetchUrl = new URL(fetchPath, fetchOrigin)
      if (fetchUrl.origin !== fetchOrigin || !grant.canRead(fetchOrigin)) {
        grant.audit('denied', fetchOrigin)
        throw new BrokerDenied('Browser sameSiteFetch target is outside approved scope.')
      }
      validatedFetch = {
        url: fetchUrl.href,
        origin: fetchOrigin,
        method: fetchMethod,
        credentials: req.sameSiteFetch.credentials ?? 'include',
      }
    }

    const started = Date.now()
    const timeoutMs = Math.max(2_000, Math.min(req.timeoutMs ?? maxBrowserTimeoutMs, maxBrowserTimeoutMs))
    const deadline = AbortSignal.any([signal, AbortSignal.timeout(timeoutMs)])
    deadline.throwIfAborted()

    const secrets = [...collectSecrets(req, grant), ...this.broker.getRegisteredSecrets()]
    const allowLocalLab = Boolean(grant.allowLocalLab && process.env.KOVO_ALLOW_LOCAL_LAB === '1')
    const secondOrderStorage = this.options.storage ?? grant.storage ?? this.broker.getStorage()
    const exchanges: BrokerExchangeResult[] = []
    const exchangeIds: string[] = []
    const xhrRequests: BrowserXhrRecord[] = []
    const allRequests: BrowserXhrRecord[] = []
    const xhrBodyBudget = { chars: 0 }
    const blockedOrigins = new Set<string>()
    const consoleMessages: Array<{ type: 'error' | 'warning'; text: string }> = []
    const xhrWaiters: Array<(rec: BrowserXhrRecord) => void> = []

    const bundle = req.sessionBundle ? normalizeSeedBundle(req.sessionBundle) : null
    if (bundle) secrets.push(...collectBundleSecrets(bundle))
    const allowedOrigins = resolveBundleAllowedOrigins(grant, req.persona, initialOrigin)
    const wireVault = new BrowserWirePlaceholderVault()
    const attestor = createHostExecutionAttestor({
      nonce: req.attestationNonce,
      expectedOrigin: initialOrigin,
    })
    const loopbackProxy = await this.createVisitLoopbackProxy({
      grant,
      tier,
      allowLocalLab,
      assetScope: this.assetScopeFor(req),
      wireVault,
      getBlockedOrigins: () => blockedOrigins,
    })
    const browser = await (this.options.launchBrowser ? this.options.launchBrowser() : launchChromium())
    let context: PlaywrightContext | undefined
    let page: PlaywrightPage | undefined
    let closed = false

    const forceClose = async () => {
      if (closed) return
      closed = true
      wireVault.clear()
      await page?.close().catch(() => undefined)
      await context?.close().catch(() => undefined)
      await browser.close().catch(() => undefined)
      await loopbackProxy.close().catch(() => undefined)
    }

    const onAbort = () => { void forceClose() }
    deadline.addEventListener('abort', onAbort, { once: true })

    try {
      deadline.throwIfAborted()
      context = await browser.newContext({
        ignoreHTTPSErrors: false,
        javaScriptEnabled: true,
        bypassCSP: false,
        serviceWorkers: 'block',
        proxy: loopbackProxy.proxyConfig,
        userAgent: 'Kovo/3 scoped headless inspector',
      })
      await context.addInitScript(postMessageInstrumentationScript)
      await context.addInitScript(browserWebRtcGuardScript)
      await installWebSocketGuard(context, {
        canRead: origin => grant.canRead(origin),
        allowLocalLab,
        scopePolicy: grant.scopePolicy,
        allowedPorts: grant.allowedPorts,
        allowConnectPort: (port, hostname) => isBrowserConnectPortAllowed({
          port,
          hostname,
          grant,
          allowLocalLab,
          assetScope: this.assetScopeFor(req),
        }),
        audit: (decision, origin) => grant.audit(decision, origin),
      })
      const storageSeed = seedStorageInitScript(bundle, initialOrigin)
      if (storageSeed) await context.addInitScript(storageSeed)
      await hydrateContextSession(context, bundle, initialOrigin, wireVault, allowedOrigins)

      const shouldInstallSinkHook = Boolean(
        req.enableSinkHook ||
        req.checkKind === 'dom_xss' ||
        actions.some(a => a.type === 'dom_xss_sink_hook'),
      )
      if (shouldInstallSinkHook) {
        await context.addInitScript(buildDomSinkHookScript(req.canaryToken ?? null))
      }

      // 100% network interception: every document, script, stylesheet, iframe, XHR, fetch, image, and redirect
      // is routed strictly through RequestBroker or aborted with blockedbyclient. Zero direct network egress!
      await context.route('**/*', async route => {
        const request = route.request()
        const rawUrl = request.url()
        if (rawUrl.startsWith('about:') || rawUrl.startsWith('data:') || rawUrl.startsWith('blob:')) {
          await route.fulfill({ status: 200, contentType: 'text/plain', body: '' }).catch(() => undefined)
          return
        }

        let parsedUrl: URL
        try {
          parsedUrl = new URL(rawUrl)
        } catch {
          await route.abort('blockedbyclient').catch(() => undefined)
          return
        }

        const method = request.method().toUpperCase()
        const decision = classifyBrowserHttpRequest({
          method,
          url: rawUrl,
          body: request.postData(),
          tier,
          canRead: origin => grant.canRead(origin),
          allowLocalLab,
          assetScope: this.assetScopeFor(req),
          scopePolicy: grant.scopePolicy,
        })
        if (!decision.allowed) {
          blockedOrigins.add(parsedUrl.origin)
          grant.audit('denied', parsedUrl.origin)
          await route.abort('blockedbyclient').catch(() => undefined)
          return
        }

        const rawRequestHeaders = request.headers()
        const forwardedHeaders: Record<string, string> = {}
        for (const [k, v] of Object.entries(rawRequestHeaders)) {
          if (forbiddenBrowserForwardHeaders.test(k)) continue
          forwardedHeaders[k] = v
        }

        const resourceType = request.resourceType()
        const personaForRequest = resolvePersonaForBrowserRequest({
          persona: req.persona,
          pageOrigin: initialOrigin,
          targetOrigin: parsedUrl.origin,
          grant,
          assetHydration: Boolean(decision.assetHydration),
          resourceType,
          requestHeaders: rawRequestHeaders,
          validatedFetch,
        })

        try {
          const exchange = await this.broker.executeHttp({
            origin: parsedUrl.origin,
            method: method as 'GET' | 'HEAD' | 'OPTIONS' | 'POST' | 'PUT' | 'PATCH' | 'DELETE',
            pathAndQuery: parsedUrl.pathname + parsedUrl.search,
            headers: forwardedHeaders,
            body: request.postData() ?? undefined,
            ...(personaForRequest ? { persona: personaForRequest } : {}),
            ...(req.session ? { session: req.session } : {}),
            ...(req.sessionGroupRole ? { sessionGroupRole: req.sessionGroupRole } : {}),
            ...(req.csrfBind ? { csrfBind: req.csrfBind } : {}),
            ...(req.runId ? { runId: req.runId } : {}),
            ...(req.assignmentId ? { assignmentId: req.assignmentId } : {}),
            ...(req.traceId ? { traceId: req.traceId } : {}),
            followRedirects: true,
            secrets,
            timeoutMs: Math.max(2_000, timeoutMs - (Date.now() - started)),
          }, decision.assetHydration ? assetScopedGrant(grant, parsedUrl.origin) : grant, deadline)

          if (!decision.assetHydration) {
            exchanges.push(exchange)
            const recordedId = req.onExchange?.(exchange)
            if (typeof recordedId === 'string' && recordedId) exchangeIds.push(recordedId)
            await mirrorJarCookies(context, this.broker, {
              ...(personaForRequest ? { persona: personaForRequest } : {}),
              session: req.session,
              runId: req.runId,
              assignmentId: req.assignmentId,
              sessionGroupRole: req.sessionGroupRole,
            }, parsedUrl.origin, secrets)
          }

          const reqRecord: BrowserXhrRecord = {
            method,
            url: redact(parsedUrl.href, secrets),
            origin: parsedUrl.origin,
            resourceType,
            status: exchange.status,
            ...((resourceType === 'xhr' || resourceType === 'fetch')
              ? captureXhrJsonBody({ exchange, sameOrigin: parsedUrl.origin === initialOrigin, secrets, budget: xhrBodyBudget })
              : {}),
          }
          if (allRequests.length < 150) allRequests.push(reqRecord)
          if (!decision.assetHydration && (resourceType === 'xhr' || resourceType === 'fetch')) {
            xhrRequests.push(reqRecord)
            for (const notify of xhrWaiters) notify(reqRecord)
          }

          await route.fulfill({
            status: exchange.status,
            headers: safeFulfillHeaders(exchange.respHeaders),
            contentType: exchange.mediaType === 'unknown' ? 'application/octet-stream' : exchange.mediaType,
            body: exchange.body,
          }).catch(() => undefined)
        } catch {
          const failedRecord: BrowserXhrRecord = {
            method,
            url: redact(parsedUrl.href, secrets),
            origin: parsedUrl.origin,
            resourceType,
            status: null,
          }
          if (allRequests.length < 150) allRequests.push(failedRecord)
          if (resourceType === 'xhr' || resourceType === 'fetch') {
            xhrRequests.push(failedRecord)
            for (const notify of xhrWaiters) notify(failedRecord)
          }
          await route.abort('blockedbyclient').catch(() => undefined)
        }
      })

      page = await context.newPage()
      // C-8: Register host-minted isolated callback binding on the page before navigation.
      await attestor.attachToPage(page)
      page.on('console', msg => {
        const type = msg.type()
        if ((type === 'error' || type === 'warning') && consoleMessages.length < 50) {
          consoleMessages.push({
            type,
            text: redact(msg.text(), secrets).slice(0, 500),
          })
        }
      })
      page.on('pageerror', err => {
        if (consoleMessages.length < 50) {
          consoleMessages.push({
            type: 'error',
            text: redact(err.message || String(err), secrets).slice(0, 500),
          })
        }
      })

      const navResponse = await page.goto(targetUrl.href, {
        waitUntil: 'domcontentloaded',
        timeout: Math.max(2_000, timeoutMs - (Date.now() - started)),
      })
      deadline.throwIfAborted()

      // Execute safe interactive actions (still 100% broker-proxied)
      const actionResults: BrowserActionOutcome[] = []
      const builtinResults: Record<string, Record<string, unknown>> = {}

      for (const action of actions) {
        deadline.throwIfAborted()
        const remainingMs = Math.max(500, timeoutMs - (Date.now() - started))
        try {
          if (action.type === 'dom_xss_sink_hook') {
            actionResults.push({ type: 'dom_xss_sink_hook', ok: true, detail: 'DOM XSS sink hook active.' })
          } else if (action.type === 'fill') {
            if (typeof page.fill === 'function') {
              await page.fill(action.selector, action.value, { timeout: Math.min(5_000, remainingMs) })
            } else {
              await page.evaluate(({ selector, value }) => {
                const el = document.querySelector(selector) as HTMLInputElement | HTMLTextAreaElement | null
                if (!el) throw new Error(`Element not found: ${selector}`)
                el.value = value
                el.dispatchEvent(new Event('input', { bubbles: true }))
                el.dispatchEvent(new Event('change', { bubbles: true }))
              }, { selector: action.selector, value: action.value })
            }
            actionResults.push({ type: 'fill', ok: true, detail: `Filled ${action.selector}` })
          } else if (action.type === 'click') {
            if (typeof page.click === 'function') {
              await page.click(action.selector, { timeout: Math.min(5_000, remainingMs) })
            } else {
              await page.evaluate((selector) => {
                const el = document.querySelector(selector) as HTMLElement | null
                if (!el) throw new Error(`Element not found: ${selector}`)
                el.click()
              }, action.selector)
            }
            actionResults.push({ type: 'click', ok: true, detail: `Clicked ${action.selector}` })
          } else if (action.type === 'select_option') {
            if (typeof page.selectOption === 'function') {
              await page.selectOption(action.selector, action.value, { timeout: Math.min(5_000, remainingMs) })
            } else {
              await page.evaluate(({ selector, value }) => {
                const el = document.querySelector(selector) as HTMLSelectElement | null
                if (!el) throw new Error(`Element not found: ${selector}`)
                el.value = value
                el.dispatchEvent(new Event('change', { bubbles: true }))
              }, { selector: action.selector, value: action.value })
            }
            actionResults.push({ type: 'select_option', ok: true, detail: `Selected option on ${action.selector}` })
          } else if (action.type === 'wait_for_selector') {
            const waitTimeout = Math.min(action.timeoutMs ?? 5_000, remainingMs)
            if (typeof page.waitForSelector === 'function') {
              await page.waitForSelector(action.selector, { timeout: waitTimeout })
            } else {
              const found = await page.evaluate((selector) => Boolean(document.querySelector(selector)), action.selector)
              if (!found) throw new Error(`Selector not found: ${action.selector}`)
            }
            actionResults.push({ type: 'wait_for_selector', ok: true, detail: `Matched ${action.selector}` })
          } else if (action.type === 'wait_for_xhr') {
            const waitTimeout = Math.min(action.timeoutMs ?? 5_000, remainingMs)
            const matches = (r: BrowserXhrRecord) => !action.urlPattern || r.url.includes(action.urlPattern)
            const existing = xhrRequests.find(matches)
            if (existing) {
              actionResults.push({ type: 'wait_for_xhr', ok: true, detail: `Matched XHR ${existing.method} ${existing.url}` })
            } else {
              const matched = await new Promise<BrowserXhrRecord | null>((resolve) => {
                const timer = setTimeout(() => {
                  const idx = xhrWaiters.indexOf(onXhr)
                  if (idx >= 0) xhrWaiters.splice(idx, 1)
                  resolve(null)
                }, waitTimeout)
                const onXhr = (rec: BrowserXhrRecord) => {
                  if (matches(rec)) {
                    clearTimeout(timer)
                    const idx = xhrWaiters.indexOf(onXhr)
                    if (idx >= 0) xhrWaiters.splice(idx, 1)
                    resolve(rec)
                  }
                }
                xhrWaiters.push(onXhr)
              })
              actionResults.push({
                type: 'wait_for_xhr',
                ok: Boolean(matched),
                detail: matched ? `Observed XHR ${matched.method} ${matched.url}` : 'Timed out waiting for matching XHR.',
              })
            }
          } else if (action.type === 'evaluate_builtin') {
            // Strictly Kovo-authored read-only DOM/sink inspectors (never arbitrary JS!)
            const data = await page.evaluate((opts: { check: BrowserBuiltinCheck; canaryToken: string | null }) => {
              const probe = (window as unknown as {
                __kovoBrowserProbe?: {
                  handlers: Array<{ preview: string; checksOrigin: boolean }>
                  hasOnMessage: boolean
                  observedEvents: number
                  sinkTraces?: BrowserDomSinkTrace[]
                }
              }).__kovoBrowserProbe

              if (opts.check === 'dom_sinks') {
                return {
                  sinkTraces: (probe?.sinkTraces ?? []).slice(0, 50),
                  inlineScriptsCount: document.querySelectorAll('script:not([src])').length,
                  eventHandlerAttrsCount: document.querySelectorAll('[onclick],[onerror],[onload],[onmouseover]').length,
                }
              }
              if (opts.check === 'forms_inventory') {
                return {
                  forms: Array.from(document.querySelectorAll('form')).slice(0, 30).map(form => ({
                    action: form.getAttribute('action') || '',
                    method: (form.getAttribute('method') || 'GET').toUpperCase(),
                    hasCsrfInput: Boolean(form.querySelector('input[name*="csrf" i], input[name*="token" i], input[name*="nonce" i]')),
                  })),
                }
              }
              if (opts.check === 'storage_keys') {
                let ls: string[] = []
                let ss: string[] = []
                try { ls = Object.keys(window.localStorage).slice(0, 64) } catch { /* ignore */ }
                try { ss = Object.keys(window.sessionStorage).slice(0, 64) } catch { /* ignore */ }
                return { localStorageKeys: ls, sessionStorageKeys: ss }
              }
              if (opts.check === 'postmessage_audit') {
                return {
                  count: probe?.handlers.length ?? 0,
                  hasOnMessage: Boolean(probe?.hasOnMessage),
                  uncheckedCount: (probe?.handlers ?? []).filter(h => !h.checksOrigin).length,
                }
              }
              if (opts.check === 'canary_presence') {
                const token = opts.canaryToken ?? ''
                const html = document.documentElement?.outerHTML ?? ''
                return {
                  canaryToken: token || null,
                  presentInHtml: Boolean(token && html.includes(token)),
                  presentInSinkTraces: Boolean(token && (probe?.sinkTraces ?? []).some(t => t.containsCanary)),
                }
              }
              return {
                title: document.title.slice(0, 300),
                readyState: document.readyState,
                iframeCount: document.querySelectorAll('iframe').length,
              }
            }, { check: action.builtinCheck, canaryToken: req.canaryToken ?? null })
            const safeData = JSON.parse(redact(JSON.stringify(data), secrets)) as Record<string, unknown>
            builtinResults[action.builtinCheck] = safeData
            actionResults.push({ type: 'evaluate_builtin', ok: true, detail: action.builtinCheck, data: safeData })
          }
        } catch (err) {
          actionResults.push({
            type: action.type,
            ok: false,
            detail: redact(err instanceof Error ? err.message : String(err), secrets).slice(0, 300),
          })
        }
      }

      const settleMs = Math.min(req.waitAfterLoadMs ?? 800, Math.max(100, timeoutMs - (Date.now() - started) - 1000))
      if (settleMs > 0) {
        await page.waitForTimeout(settleMs)
      }
      deadline.throwIfAborted()

      const canaryToken = req.canaryToken ?? null
      const snapshot = await page.evaluate(async (opts: {
        checkKind?: string
        canaryToken: string | null
        selector: string | null
        postMessageOrigin: string | null
        postMessagePayload: unknown
        hasCustomPostMessage: boolean
        sameSiteFetch: { url: string; origin: string; method: string; credentials: RequestCredentials } | null
      }) => {
        const probe = (window as unknown as {
          __kovoBrowserProbe?: {
            handlers: Array<{ preview: string; checksOrigin: boolean }>
            hasOnMessage: boolean
            observedEvents: number
            canaryObserved: boolean
            domCanaryTriggered?: boolean
            sinkTraces?: BrowserDomSinkTrace[]
          }
        }).__kovoBrowserProbe

        const handlers = (probe?.handlers ?? []).slice(0, 30)
        const hasUncheckedPostMessage = handlers.some(h => !h.checksOrigin)

        let canaryTriggered = false
        let canaryDetail: string | null = null
        let canaryHandledWithoutOriginCheck = false

        if ((opts.checkKind === 'postmessage' || opts.hasCustomPostMessage) && handlers.length > 0) {
          const pmToken = opts.canaryToken ?? 'kovo-pm-canary'
          const pmOrigin = opts.postMessageOrigin ?? 'https://untrusted-origin.invalid'
          const pmData = opts.hasCustomPostMessage && opts.postMessagePayload !== undefined
            ? opts.postMessagePayload
            : { kovoCanary: pmToken, type: 'kovo-probe' }
          try {
            window.dispatchEvent(new MessageEvent('message', {
              data: pmData,
              origin: pmOrigin,
            }))
          } catch { /* ignore */ }
          await new Promise(resolve => setTimeout(resolve, 40))
          if (hasUncheckedPostMessage) {
            canaryHandledWithoutOriginCheck = true
            canaryTriggered = true
            canaryDetail = `Detected ${handlers.filter(h => !h.checksOrigin).length} postMessage listener(s) without an apparent event.origin validation check.`
          }
        }

        let fetchResult: BrowserFetchResult | null = null
        if (opts.sameSiteFetch) {
          try {
            const resp = await window.fetch(opts.sameSiteFetch.url, {
              method: opts.sameSiteFetch.method,
              credentials: opts.sameSiteFetch.credentials,
            })
            const text = await resp.text().catch(() => '')
            fetchResult = {
              url: opts.sameSiteFetch.url,
              origin: opts.sameSiteFetch.origin,
              method: opts.sameSiteFetch.method,
              credentials: opts.sameSiteFetch.credentials,
              ok: resp.ok,
              status: resp.status,
              contentType: resp.headers.get('content-type'),
              bodyPreview: text.slice(0, 4096),
              bodyBytes: text.length,
              error: null,
            }
          } catch (err) {
            fetchResult = {
              url: opts.sameSiteFetch.url,
              origin: opts.sameSiteFetch.origin,
              method: opts.sameSiteFetch.method,
              credentials: opts.sameSiteFetch.credentials,
              ok: false,
              status: null,
              contentType: null,
              bodyPreview: '',
              bodyBytes: 0,
              error: err instanceof Error ? err.message : String(err),
            }
          }
        }

        // C-8: Do NOT trust main-world `window.__kovoDomCanary`, `[data-kovo-canary]` markers,
        // `document.title`, or mutable `probe.domCanaryTriggered` as execution proof; execution
        // attestation is verified strictly on the host via `page.exposeBinding` nonce matching.
        const sinkTraces = (probe?.sinkTraces ?? []).slice(0, 80)

        let selectorResult: BrowserSelectorResult | null = null
        if (opts.selector) {
          try {
            const matchedNodes = Array.from(document.querySelectorAll(opts.selector)).slice(0, 50)
            const preview = matchedNodes
              .map(node => (node.textContent || node.outerHTML || '').trim())
              .filter(Boolean)
              .join(' | ')
              .slice(0, 1000)
            selectorResult = {
              selector: opts.selector,
              matched: matchedNodes.length > 0,
              count: matchedNodes.length,
              textPreview: preview,
            }
          } catch {
            selectorResult = {
              selector: opts.selector,
              matched: false,
              count: 0,
              textPreview: '',
            }
          }
        }

        const domHtml = document.documentElement?.outerHTML ?? ''
        const links = Array.from(document.querySelectorAll('a[href]'))
          .map(el => el.getAttribute('href') || '')
          .filter(Boolean)
          .slice(0, 120)

        const forms = Array.from(document.querySelectorAll('form')).slice(0, 40).map(form => ({
          action: form.getAttribute('action') || '',
          method: (form.getAttribute('method') || 'GET').toUpperCase(),
          inputNames: Array.from(form.querySelectorAll('input, select, textarea'))
            .map(el => el.getAttribute('name') || el.getAttribute('id') || '')
            .filter(Boolean)
            .slice(0, 30),
        }))

        // Capture ONLY cookie & storage key names — never raw values!
        const cookieNames = (document.cookie || '')
          .split(';')
          .map(pair => pair.split('=', 1)[0]?.trim() || '')
          .filter(Boolean)
          .slice(0, 64)

        let localStorageKeys: string[] = []
        let sessionStorageKeys: string[] = []
        try { localStorageKeys = Object.keys(window.localStorage).slice(0, 64) } catch { /* opaque origin */ }
        try { sessionStorageKeys = Object.keys(window.sessionStorage).slice(0, 64) } catch { /* opaque origin */ }

        return {
          domHtml,
          links,
          forms,
          cookieNames,
          localStorageKeys,
          sessionStorageKeys,
          postMessageListeners: {
            count: handlers.length,
            hasOnMessage: Boolean(probe?.hasOnMessage),
            handlers,
            observedEvents: probe?.observedEvents ?? 0,
            canaryHandledWithoutOriginCheck,
          },
          canaryTriggered,
          canaryDetail,
          sinkTraces,
          selectorResult,
          fetchResult,
        }
      }, {
        checkKind: req.checkKind,
        canaryToken,
        selector: req.selector ?? null,
        postMessageOrigin: req.postMessageOrigin ?? null,
        postMessagePayload: req.postMessagePayload,
        hasCustomPostMessage: req.postMessageOrigin !== undefined || req.postMessagePayload !== undefined,
        sameSiteFetch: validatedFetch,
      })

      const finalUrlRaw = page.url()
      const runtimeSecrets = [...secrets, ...this.broker.getRegisteredSecrets()]
      const egress = createEgressSanitizer({ secrets: runtimeSecrets })
      const finalUrl = egress.redactText(finalUrlRaw, 'browser_result')
      const title = egress.redactText(await page.title().catch(() => ''), 'browser_result').slice(0, 300)
      const primaryExchange = exchanges[0]
      let finalOrigin = initialOrigin
      try { finalOrigin = new URL(finalUrlRaw).origin } catch { /* keep initialOrigin */ }
      const redirectOrigins = primaryExchange?.redirectOrigins ?? [initialOrigin]
      const initialRedactedUrl = egress.redactText(targetUrl.href, 'browser_result')
      const redirectSummary: BrowserRedirectSummary = {
        initialUrl: initialRedactedUrl,
        finalUrl,
        redirected: finalUrl !== initialRedactedUrl || redirectOrigins.length > 1,
        finalOrigin,
        redirectOrigins,
        blockedRedirectAttempt: blockedOrigins.size > 0,
      }

      if (secondOrderStorage && req.runId && snapshot.domHtml) {
        scanSecondOrderMarkers({
          text: snapshot.domHtml,
          runId: req.runId,
          assignmentId: req.assignmentId,
          origin: finalOrigin,
          endpoint: req.pathAndQuery,
          persona: req.persona ?? null,
          exchangeId: exchangeIds[0] ?? null,
          storage: secondOrderStorage,
        })
      }

      const safeSelectorResult: BrowserSelectorResult | null = snapshot.selectorResult
        ? {
            ...snapshot.selectorResult,
            textPreview: egress.redactText(snapshot.selectorResult.textPreview, 'browser_result'),
          }
        : null

      const safeFetchResult: BrowserFetchResult | null = snapshot.fetchResult
        ? {
            ...snapshot.fetchResult,
            url: egress.redactText(snapshot.fetchResult.url, 'browser_result'),
            bodyPreview: egress.redactText(snapshot.fetchResult.bodyPreview, 'browser_result'),
            error: snapshot.fetchResult.error ? egress.redactText(snapshot.fetchResult.error, 'browser_result') : null,
          }
        : null

      const safeSinkTraces: BrowserDomSinkTrace[] = (snapshot.sinkTraces ?? []).map(t => ({
        ...t,
        preview: egress.redactText(t.preview, 'browser_result').slice(0, 400),
      }))
      const attestation = attestor.snapshot()
      const attestedSinks = buildVerifiedTraceSinks({ attestation, domSinkTraces: safeSinkTraces })
      const canaryTriggered = attestation.verified || snapshot.canaryTriggered
      const canaryDetail = attestation.verified
        ? 'Host-attested isolated binding callback verified.'
        : snapshot.canaryDetail

      return egress.sanitizeBrowserResult({
        origin: initialOrigin,
        finalUrl,
        title,
        status: navResponse ? navResponse.status() : (exchanges[0]?.status ?? null),
        domSnippet: egress.redactText(snapshot.domHtml, 'browser_result').slice(0, maxDomSnippetChars),
        links: [...new Set(snapshot.links.map(l => egress.redactText(l, 'browser_result')))].slice(0, 120),
        forms: snapshot.forms,
        xhrRequests: xhrRequests.slice(0, 100),
        allRequests: allRequests.slice(0, 150),
        blockedOrigins: [...blockedOrigins].slice(0, 100),
        consoleMessages,
        postMessageListeners: {
          ...snapshot.postMessageListeners,
          handlers: snapshot.postMessageListeners.handlers.map(h => ({
            preview: egress.redactText(h.preview, 'browser_result'),
            checksOrigin: h.checksOrigin,
          })),
        },
        cookieNames: snapshot.cookieNames,
        localStorageKeys: snapshot.localStorageKeys,
        sessionStorageKeys: snapshot.sessionStorageKeys,
        canaryCheck: {
          token: canaryToken,
          triggered: canaryTriggered,
          detail: canaryDetail,
          attested: attestation.verified,
          nonce: attestation.nonce,
        },
        attestation,
        attestedSinks,
        domSinkTraces: safeSinkTraces,
        ...(actionResults.length > 0 ? { actionResults } : {}),
        ...(Object.keys(builtinResults).length > 0 ? { builtinResults } : {}),
        selectorResult: safeSelectorResult,
        fetchResult: safeFetchResult,
        redirectSummary,
        exchangeIds,
        exchanges,
        durationMs: Date.now() - started,
      })
    } finally {
      deadline.removeEventListener('abort', onAbort)
      await forceClose()
    }
  }

  async runBrowserSession(
    steps: readonly BrowserSessionStep[],
    grant: Grant,
    signal: AbortSignal,
  ): Promise<BrowserVisitResult[]> {
    const tier = grant.tier ?? 1
    if (tier === 0) throw new BrokerDenied('Scoped browser inspection is disabled in Tier 0 (offline prepared mode).')
    if (!Array.isArray(steps) || steps.length === 0) return []

    // Pre-validate every step before launching Playwright
    const validatedSteps = steps.map((step, idx) => {
      const origin = new URL(step.origin).origin
      if (!grant.canRead(origin)) {
        grant.audit('denied', origin)
        throw new BrokerDenied('Browser destination is outside the current assignment scope.')
      }
      if (idx === 0 && !step.pathAndQuery) {
        throw new BrokerDenied('First browser session step must specify pathAndQuery.')
      }
      if (step.pathAndQuery !== undefined) {
        if (!step.pathAndQuery.startsWith('/') || step.pathAndQuery.startsWith('//') || /[\r\n\0]/.test(step.pathAndQuery)) {
          grant.audit('denied', origin)
          throw new BrokerDenied('Invalid browser visit path.')
        }
        if (hasDestructiveInput(step.pathAndQuery)) {
          grant.audit('denied', origin)
          throw new BrokerDenied('Browser visit blocked by destructive-payload denylist.')
        }
        const targetUrl = new URL(step.pathAndQuery, origin)
        if (targetUrl.origin !== origin) {
          grant.audit('denied', origin)
          throw new BrokerDenied('Browser destination escaped approved origin.')
        }
      }
      if (step.selector !== undefined) validateSafeSelector(step.selector, origin, grant)
      if (step.value !== undefined && (step.value.length > 2048 || hasDestructiveInput(step.value))) {
        grant.audit('denied', origin)
        throw new BrokerDenied('Browser step value blocked by destructive-payload denylist or length limit.')
      }
      if (step.postMessagePayload !== undefined && hasDestructiveInput(JSON.stringify(step.postMessagePayload))) {
        grant.audit('denied', origin)
        throw new BrokerDenied('Browser postMessage payload blocked by destructive-payload denylist.')
      }

      const actions: BrowserInteractiveAction[] = [...(step.actions ?? [])]
      if (actions.length === 0 && step.action) {
        if (step.action === 'fill' && step.selector) {
          actions.push({ type: 'fill', selector: step.selector, value: step.value ?? '' })
        } else if (step.action === 'click' && step.selector) {
          actions.push({ type: 'click', selector: step.selector })
        } else if (step.action === 'select_option' && step.selector) {
          actions.push({ type: 'select_option', selector: step.selector, value: step.value ?? '' })
        } else if (step.action === 'wait_for_selector' && step.selector) {
          actions.push({ type: 'wait_for_selector', selector: step.selector, timeoutMs: step.waitAfterLoadMs })
        } else if (step.action === 'wait_for_xhr') {
          actions.push({ type: 'wait_for_xhr', urlPattern: step.urlPattern, timeoutMs: step.waitAfterLoadMs })
        } else if (step.action === 'evaluate_builtin' && step.builtinCheck) {
          actions.push({ type: 'evaluate_builtin', builtinCheck: step.builtinCheck })
        } else if (step.action === 'dom_xss_sink_hook') {
          actions.push({ type: 'dom_xss_sink_hook' })
        }
      }
      if (step.builtinCheck && !actions.some(a => a.type === 'evaluate_builtin' && a.builtinCheck === step.builtinCheck)) {
        actions.push({ type: 'evaluate_builtin', builtinCheck: step.builtinCheck })
      }
      for (const action of actions) {
        if (action.type === 'fill' || action.type === 'select_option') {
          validateSafeSelector(action.selector, origin, grant)
          if (action.value.length > 2048 || hasDestructiveInput(action.value)) {
            grant.audit('denied', origin)
            throw new BrokerDenied(`Browser ${action.type} value blocked by destructive-payload denylist or length limit.`)
          }
        } else if (action.type === 'click' || action.type === 'wait_for_selector') {
          validateSafeSelector(action.selector, origin, grant)
        }
      }

      let validatedFetch: { url: string; origin: string; method: 'GET' | 'HEAD' | 'OPTIONS'; credentials: 'include' | 'same-origin' | 'omit' } | null = null
      if (step.fetchTarget) {
        const fetchOrigin = new URL(step.fetchTarget.origin).origin
        const fetchPath = step.fetchTarget.pathAndQuery
        const fetchMethod = (step.fetchTarget.method ?? 'GET').toUpperCase() as 'GET' | 'HEAD' | 'OPTIONS'
        if (!safeReadOnlyFetchMethods.has(fetchMethod)) {
          grant.audit('denied', fetchOrigin)
          throw new BrokerDenied('Browser sameSiteFetch only permits read-only GET/HEAD/OPTIONS methods.')
        }
        if (!fetchPath.startsWith('/') || fetchPath.startsWith('//') || /[\r\n\0]/.test(fetchPath) || hasDestructiveInput(fetchPath)) {
          grant.audit('denied', fetchOrigin)
          throw new BrokerDenied('Invalid or blocked browser sameSiteFetch path.')
        }
        const fetchUrl = new URL(fetchPath, fetchOrigin)
        if (fetchUrl.origin !== fetchOrigin || !grant.canRead(fetchOrigin)) {
          grant.audit('denied', fetchOrigin)
          throw new BrokerDenied('Browser sameSiteFetch target is outside approved scope.')
        }
        validatedFetch = {
          url: fetchUrl.href,
          origin: fetchOrigin,
          method: fetchMethod,
          credentials: step.fetchTarget.credentials ?? 'include',
        }
      }

      return { step, origin, actions: actions.slice(0, maxInteractiveActions), validatedFetch }
    })

    const sessionTimeoutMs = Math.max(10_000, Math.min(steps.length * maxBrowserTimeoutMs, 120_000))
    const deadline = AbortSignal.any([signal, AbortSignal.timeout(sessionTimeoutMs)])
    deadline.throwIfAborted()

    const allowLocalLab = Boolean(grant.allowLocalLab && process.env.KOVO_ALLOW_LOCAL_LAB === '1')
    const secondOrderStorage = this.options.storage ?? grant.storage ?? this.broker.getStorage()
    let stepBlockedOrigins = new Set<string>()
    const sessionWireVault = new BrowserWirePlaceholderVault()
    let activeStepAttestor: HostExecutionAttestor | null = null
    const loopbackProxy = await this.createVisitLoopbackProxy({
      grant,
      tier,
      allowLocalLab,
      wireVault: sessionWireVault,
      getBlockedOrigins: () => stepBlockedOrigins,
    })
    const browser = await (this.options.launchBrowser ? this.options.launchBrowser() : launchChromium())

    let context: PlaywrightContext | undefined
    let page: PlaywrightPage | undefined
    let closed = false

    const forceClose = async () => {
      if (closed) return
      closed = true
      activeStepAttestor = null
      sessionWireVault.clear()
      await page?.close().catch(() => undefined)
      await context?.close().catch(() => undefined)
      await browser.close().catch(() => undefined)
      await loopbackProxy.close().catch(() => undefined)
    }

    const onAbort = () => { void forceClose() }
    deadline.addEventListener('abort', onAbort, { once: true })

    try {
      const results: BrowserVisitResult[] = []
      let activeControlProbeRole: 'control' | 'probe' | null = null
      let lastPersona: string | undefined
      let lastOrigin: string | undefined
      let sessionId = `bs_${randomBytes(4).toString('hex')}`
      let sinkHookInstalled = false
      let currentPathAndQuery = '/'
      let lastNavStatus: number | null = null

      // Mutable per-step collectors attached to the active context's route/page listeners
      let activeStep = validatedSteps[0]
      let stepExchanges: BrokerExchangeResult[] = []
      let stepExchangeIds: string[] = []
      let stepXhrRequests: BrowserXhrRecord[] = []
      let stepAllRequests: BrowserXhrRecord[] = []
      let stepXhrBodyBudget = { chars: 0 }
      let stepConsoleMessages: Array<{ type: 'error' | 'warning'; text: string }> = []
      const xhrWaiters: Array<(rec: BrowserXhrRecord) => void> = []

      const willResetAt = (idx: number): boolean => {
        if (idx === 0) return true
        const cur = validatedSteps[idx].step
        if (cur.resetContext === true || cur.reusePage === false) return true
        if ((cur.role === 'control' && activeControlProbeRole === 'probe') ||
            (cur.role === 'probe' && activeControlProbeRole === 'control') ||
            (cur.role === 'setup' && activeControlProbeRole !== null)) return true
        if ((cur.persona ?? undefined) !== lastPersona) return true
        if (validatedSteps[idx].origin !== lastOrigin) return true
        return false
      }

      for (let i = 0; i < validatedSteps.length; i += 1) {
        deadline.throwIfAborted()
        const entry = validatedSteps[i]
        const { step, origin: stepOrigin, actions, validatedFetch } = entry
        const stepStarted = Date.now()
        const stepSecrets: NamedSecret[] = [
          ...(grant.personas ? personaSecrets(grant.personas) : []),
          ...(grant.secrets ?? []),
          ...(step.secrets ?? []),
          ...this.broker.getRegisteredSecrets(),
        ]

        const shouldReset = willResetAt(i)
        if (step.resetContext === true || (shouldReset && step.role === 'setup')) activeControlProbeRole = null

        // Reset per-step arrays while preserving xhrWaiters/page when continuing a context
        activeStep = entry
        stepExchanges = []
        stepExchangeIds = []
        stepXhrRequests = []
        stepAllRequests = []
        stepXhrBodyBudget = { chars: 0 }
        stepBlockedOrigins = new Set<string>()
        stepConsoleMessages = []

        if (shouldReset) {
          if (!step.pathAndQuery) {
            throw new BrokerDenied(`Browser session step "${step.id}" requires pathAndQuery after context reset.`)
          }
          activeStepAttestor = null
          sessionWireVault.clear()
          await page?.close().catch(() => undefined)
          await context?.close().catch(() => undefined)
          page = undefined
          context = undefined
          sinkHookInstalled = false
          lastNavStatus = null
          sessionId = step.session ?? `bs_${randomBytes(4).toString('hex')}`

          // Look ahead across the contiguous group to check if any step needs the DOM sink hook init script
          let groupNeedsSinkHook = Boolean(
            step.enableSinkHook ||
            step.checkKind === 'dom_xss' ||
            step.action === 'dom_xss_sink_hook' ||
            actions.some(a => a.type === 'dom_xss_sink_hook'),
          )
          let groupCanaryToken: string | null = step.canaryToken ?? null
          let lookRole: 'control' | 'probe' | null =
            step.role === 'control' ? 'control' : step.role === 'probe' ? 'probe' : null
          for (let j = i + 1; j < validatedSteps.length; j += 1) {
            const nxt = validatedSteps[j]
            if (nxt.step.resetContext === true || nxt.step.reusePage === false) break
            if ((nxt.step.role === 'control' && lookRole === 'probe') ||
                (nxt.step.role === 'probe' && lookRole === 'control') ||
                (nxt.step.role === 'setup' && lookRole !== null)) break
            if ((nxt.step.persona ?? undefined) !== (step.persona ?? undefined)) break
            if (nxt.origin !== stepOrigin) break
            if (nxt.step.role === 'control' || nxt.step.role === 'probe') lookRole = nxt.step.role
            if (nxt.step.enableSinkHook || nxt.step.checkKind === 'dom_xss' ||
                nxt.step.action === 'dom_xss_sink_hook' ||
                nxt.actions.some(a => a.type === 'dom_xss_sink_hook')) {
              groupNeedsSinkHook = true
            }
            groupCanaryToken ??= nxt.step.canaryToken ?? null
          }

          context = await browser.newContext({
            ignoreHTTPSErrors: false,
            javaScriptEnabled: true,
            bypassCSP: false,
            serviceWorkers: 'block',
            proxy: loopbackProxy.proxyConfig,
            userAgent: 'Kovo/4 scoped headless session inspector',
          })
          await context.addInitScript(postMessageInstrumentationScript)
          await context.addInitScript(browserWebRtcGuardScript)
          await installWebSocketGuard(context, {
            canRead: origin => grant.canRead(origin),
            allowLocalLab,
            scopePolicy: grant.scopePolicy,
            allowedPorts: grant.allowedPorts,
            allowConnectPort: (port, hostname) => isBrowserConnectPortAllowed({
              port,
              hostname,
              grant,
              allowLocalLab,
              assetScope: this.assetScopeFor({}),
            }),
            audit: (decision, origin) => grant.audit(decision, origin),
          })
          if (groupNeedsSinkHook) {
            await context.addInitScript(buildDomSinkHookScript(groupCanaryToken))
            sinkHookInstalled = true
          }

          await context.route('**/*', async route => {
            const request = route.request()
            const rawUrl = request.url()
            if (rawUrl.startsWith('about:') || rawUrl.startsWith('data:') || rawUrl.startsWith('blob:')) {
              await route.fulfill({ status: 200, contentType: 'text/plain', body: '' }).catch(() => undefined)
              return
            }

            let parsedUrl: URL
            try {
              parsedUrl = new URL(rawUrl)
            } catch {
              await route.abort('blockedbyclient').catch(() => undefined)
              return
            }

            const method = request.method().toUpperCase()
            // H9: Route runBrowserSession requests through the canonical `classifyBrowserHttpRequest`
            // classifier so `grant.scopePolicy` (`prod_readonly`, `staging_denylist`, origin roles) is enforced.
            const decision = classifyBrowserHttpRequest({
              method,
              url: rawUrl,
              body: request.postData(),
              tier,
              canRead: origin => grant.canRead(origin),
              allowLocalLab,
              assetScope: this.assetScopeFor({}),
              scopePolicy: grant.scopePolicy,
            })
            if (!decision.allowed) {
              stepBlockedOrigins.add(parsedUrl.origin)
              grant.audit('denied', parsedUrl.origin)
              await route.abort('blockedbyclient').catch(() => undefined)
              return
            }

            const rawRequestHeaders = request.headers()
            const forwardedHeaders: Record<string, string> = {}
            for (const [k, v] of Object.entries(rawRequestHeaders)) {
              if (forbiddenBrowserForwardHeaders.test(k)) continue
              forwardedHeaders[k] = v
            }

            const cur = activeStep
            const resourceType = request.resourceType()
            const personaForRequest = resolvePersonaForBrowserRequest({
              persona: cur.step.persona,
              pageOrigin: cur.origin,
              targetOrigin: parsedUrl.origin,
              grant,
              assetHydration: Boolean(decision.assetHydration),
              resourceType,
              requestHeaders: rawRequestHeaders,
              validatedFetch: cur.validatedFetch,
            })

            const routeSecrets = [
              ...(grant.personas ? personaSecrets(grant.personas) : []),
              ...(grant.secrets ?? []),
              ...(cur.step.secrets ?? []),
              ...this.broker.getRegisteredSecrets(),
            ]

            try {
              const exchange = await this.broker.executeHttp({
                origin: parsedUrl.origin,
                method: method as 'GET' | 'HEAD' | 'OPTIONS' | 'POST' | 'PUT' | 'PATCH' | 'DELETE',
                pathAndQuery: parsedUrl.pathname + parsedUrl.search,
                headers: forwardedHeaders,
                body: request.postData() ?? undefined,
                persona: personaForRequest,
                session: cur.step.session ?? sessionId,
                sessionGroupRole: cur.step.role,
                csrfBind: cur.step.csrfBind,
                runId: cur.step.runId,
                assignmentId: cur.step.assignmentId,
                traceId: cur.step.traceId,
                followRedirects: true,
                secrets: routeSecrets,
                timeoutMs: maxBrowserTimeoutMs,
              }, decision.assetHydration ? assetScopedGrant(grant, parsedUrl.origin) : grant, deadline)

              stepExchanges.push(exchange)
              const recordedId = cur.step.onExchange?.(exchange)
              if (typeof recordedId === 'string' && recordedId) stepExchangeIds.push(recordedId)
              await mirrorJarCookies(context, this.broker, {
                ...(personaForRequest ? { persona: personaForRequest } : {}),
                session: cur.step.session ?? sessionId,
                runId: cur.step.runId,
                assignmentId: cur.step.assignmentId,
                sessionGroupRole: cur.step.role,
              }, parsedUrl.origin, stepSecrets)

              const reqRecord: BrowserXhrRecord = {
                method,
                url: redact(parsedUrl.href, routeSecrets),
                origin: parsedUrl.origin,
                resourceType,
                status: exchange.status,
                ...((resourceType === 'xhr' || resourceType === 'fetch')
                  ? captureXhrJsonBody({ exchange, sameOrigin: parsedUrl.origin === cur.origin, secrets: routeSecrets, budget: stepXhrBodyBudget })
                  : {}),
              }
              if (stepAllRequests.length < 150) stepAllRequests.push(reqRecord)
              if (resourceType === 'xhr' || resourceType === 'fetch') {
                stepXhrRequests.push(reqRecord)
                for (const notify of [...xhrWaiters]) notify(reqRecord)
              }

              await route.fulfill({
                status: exchange.status,
                headers: safeFulfillHeaders(exchange.respHeaders),
                contentType: exchange.mediaType === 'unknown' ? 'application/octet-stream' : exchange.mediaType,
                body: exchange.body,
              }).catch(() => undefined)
            } catch {
              const failedRecord: BrowserXhrRecord = {
                method,
                url: redact(parsedUrl.href, routeSecrets),
                origin: parsedUrl.origin,
                resourceType,
                status: null,
              }
              if (stepAllRequests.length < 150) stepAllRequests.push(failedRecord)
              if (resourceType === 'xhr' || resourceType === 'fetch') {
                stepXhrRequests.push(failedRecord)
                for (const notify of [...xhrWaiters]) notify(failedRecord)
              }
              await route.abort('blockedbyclient').catch(() => undefined)
            }
          })

          page = await context.newPage()
          // C-8: Register isolated host callback binding once per session page, delegating to each step's fresh attestor.
          if (typeof page.exposeBinding === 'function') {
            await page.exposeBinding(KOVO_EXECUTION_ATTESTATION_BINDING, (source, rawNonce, rawSink) => {
              if (!activeStepAttestor) return { attested: false }
              return activeStepAttestor.handleBindingCall(source, rawNonce, rawSink)
            })
          }
          const currentStepSecrets = (): NamedSecret[] => [
            ...(grant.personas ? personaSecrets(grant.personas) : []),
            ...(grant.secrets ?? []),
            ...(activeStep?.step.secrets ?? []),
            ...this.broker.getRegisteredSecrets(),
          ]
          page.on('console', msg => {
            const type = msg.type()
            if ((type === 'error' || type === 'warning') && stepConsoleMessages.length < 50) {
              stepConsoleMessages.push({
                type,
                text: redact(msg.text(), currentStepSecrets()).slice(0, 500),
              })
            }
          })
          page.on('pageerror', err => {
            if (stepConsoleMessages.length < 50) {
              stepConsoleMessages.push({
                type: 'error',
                text: redact(err.message || String(err), currentStepSecrets()).slice(0, 500),
              })
            }
          })
        }

        if (!page) {
          throw new BrokerDenied('Browser session page initialization failed.')
        }
        // C-8: Mint a fresh per-step host nonce so control/probe steps cannot share or forge attestation.
        const stepAttestor = createHostExecutionAttestor({
          nonce: step.attestationNonce,
          expectedOrigin: stepOrigin,
        })
        activeStepAttestor = stepAttestor

        const navigated = step.pathAndQuery !== undefined
        if (step.pathAndQuery !== undefined) {
          currentPathAndQuery = step.pathAndQuery
          const navUrl = new URL(step.pathAndQuery, stepOrigin)
          const navResp = await page.goto(navUrl.href, {
            waitUntil: 'domcontentloaded',
            timeout: maxBrowserTimeoutMs,
          })
          lastNavStatus = navResp ? navResp.status() : (stepExchanges[0]?.status ?? lastNavStatus)
          deadline.throwIfAborted()
        }

        const stepNeedsSinkHook = Boolean(
          step.enableSinkHook ||
          step.checkKind === 'dom_xss' ||
          step.action === 'dom_xss_sink_hook' ||
          actions.some(a => a.type === 'dom_xss_sink_hook'),
        )
        if (stepNeedsSinkHook && !sinkHookInstalled) {
          await page.evaluate((tok) => {
            const probe = (window as unknown as { __kovoBrowserProbe?: Record<string, unknown> }).__kovoBrowserProbe
            if (!probe || probe.__sinkHookInstalled) return
            probe.__sinkHookInstalled = true
            const sinkTraces = Array.isArray(probe.sinkTraces) ? probe.sinkTraces as Array<Record<string, unknown>> : []
            probe.sinkTraces = sinkTraces
            const recordSink = (sink: string, raw: unknown) => {
              try {
                const text = typeof raw === 'string' ? raw : JSON.stringify(raw ?? '')
                const preview = String(text).slice(0, 400)
                const containsCanary = Boolean(tok && String(text).includes(tok))
                if (sinkTraces.length < 80) sinkTraces.push({ sink, preview, containsCanary, timestamp: Date.now() })
                if (containsCanary) probe.domCanaryTriggered = true
              } catch { /* ignore */ }
            }
            const wrapSetter = (proto: object, prop: string, sinkName: string) => {
              try {
                const d = Object.getOwnPropertyDescriptor(proto, prop)
                if (d && d.set && d.configurable) {
                  Object.defineProperty(proto, prop, {
                    configurable: true,
                    enumerable: d.enumerable,
                    get() { return d.get ? d.get.call(this) : '' },
                    set(val) { recordSink(sinkName, val); return d.set!.call(this, val) },
                  })
                }
              } catch { /* ignore */ }
            }
            wrapSetter(Element.prototype, 'innerHTML', 'innerHTML')
            wrapSetter(Element.prototype, 'outerHTML', 'outerHTML')
          }, step.canaryToken ?? null)
          sinkHookInstalled = true
        }

        const actionResults: BrowserActionOutcome[] = []
        const builtinResults: Record<string, Record<string, unknown>> = {}

        for (const action of actions) {
          deadline.throwIfAborted()
          const remainingMs = Math.max(500, maxBrowserTimeoutMs - (Date.now() - stepStarted))
          try {
            if (action.type === 'dom_xss_sink_hook') {
              actionResults.push({ type: 'dom_xss_sink_hook', ok: true, detail: 'DOM XSS sink hook active.' })
            } else if (action.type === 'fill') {
              if (typeof page.fill === 'function') {
                await page.fill(action.selector, action.value, { timeout: Math.min(5_000, remainingMs) })
              } else {
                await page.evaluate(({ selector, value }) => {
                  const el = document.querySelector(selector) as HTMLInputElement | HTMLTextAreaElement | null
                  if (!el) throw new Error(`Element not found: ${selector}`)
                  el.value = value
                  el.dispatchEvent(new Event('input', { bubbles: true }))
                  el.dispatchEvent(new Event('change', { bubbles: true }))
                }, { selector: action.selector, value: action.value })
              }
              actionResults.push({ type: 'fill', ok: true, detail: `Filled ${action.selector}` })
            } else if (action.type === 'click') {
              if (typeof page.click === 'function') {
                await page.click(action.selector, { timeout: Math.min(5_000, remainingMs) })
              } else {
                await page.evaluate((selector) => {
                  const el = document.querySelector(selector) as HTMLElement | null
                  if (!el) throw new Error(`Element not found: ${selector}`)
                  el.click()
                }, action.selector)
              }
              actionResults.push({ type: 'click', ok: true, detail: `Clicked ${action.selector}` })
            } else if (action.type === 'select_option') {
              if (typeof page.selectOption === 'function') {
                await page.selectOption(action.selector, action.value, { timeout: Math.min(5_000, remainingMs) })
              } else {
                await page.evaluate(({ selector, value }) => {
                  const el = document.querySelector(selector) as HTMLSelectElement | null
                  if (!el) throw new Error(`Element not found: ${selector}`)
                  el.value = value
                  el.dispatchEvent(new Event('change', { bubbles: true }))
                }, { selector: action.selector, value: action.value })
              }
              actionResults.push({ type: 'select_option', ok: true, detail: `Selected option on ${action.selector}` })
            } else if (action.type === 'wait_for_selector') {
              const waitTimeout = Math.min(action.timeoutMs ?? 5_000, remainingMs)
              if (typeof page.waitForSelector === 'function') {
                await page.waitForSelector(action.selector, { timeout: waitTimeout })
              } else {
                const found = await page.evaluate((selector) => Boolean(document.querySelector(selector)), action.selector)
                if (!found) throw new Error(`Selector not found: ${action.selector}`)
              }
              actionResults.push({ type: 'wait_for_selector', ok: true, detail: `Matched ${action.selector}` })
            } else if (action.type === 'wait_for_xhr') {
              const waitTimeout = Math.min(action.timeoutMs ?? 5_000, remainingMs)
              const matches = (r: BrowserXhrRecord) => !action.urlPattern || r.url.includes(action.urlPattern)
              const existing = stepXhrRequests.find(matches)
              if (existing) {
                actionResults.push({ type: 'wait_for_xhr', ok: true, detail: `Matched XHR ${existing.method} ${existing.url}` })
              } else {
                const matched = await new Promise<BrowserXhrRecord | null>((resolve) => {
                  const timer = setTimeout(() => {
                    const idx = xhrWaiters.indexOf(onXhr)
                    if (idx >= 0) xhrWaiters.splice(idx, 1)
                    resolve(null)
                  }, waitTimeout)
                  const onXhr = (rec: BrowserXhrRecord) => {
                    if (matches(rec)) {
                      clearTimeout(timer)
                      const idx = xhrWaiters.indexOf(onXhr)
                      if (idx >= 0) xhrWaiters.splice(idx, 1)
                      resolve(rec)
                    }
                  }
                  xhrWaiters.push(onXhr)
                })
                actionResults.push({
                  type: 'wait_for_xhr',
                  ok: Boolean(matched),
                  detail: matched ? `Observed XHR ${matched.method} ${matched.url}` : 'Timed out waiting for matching XHR.',
                })
              }
            } else if (action.type === 'evaluate_builtin') {
              const data = await page.evaluate((opts: { check: BrowserBuiltinCheck; canaryToken: string | null }) => {
                const probe = (window as unknown as {
                  __kovoBrowserProbe?: {
                    handlers: Array<{ preview: string; checksOrigin: boolean }>
                    hasOnMessage: boolean
                    observedEvents: number
                    sinkTraces?: BrowserDomSinkTrace[]
                  }
                }).__kovoBrowserProbe
                if (opts.check === 'dom_sinks') {
                  return {
                    sinkTraces: (probe?.sinkTraces ?? []).slice(0, 50),
                    inlineScriptsCount: document.querySelectorAll('script:not([src])').length,
                    eventHandlerAttrsCount: document.querySelectorAll('[onclick],[onerror],[onload],[onmouseover]').length,
                  }
                }
                if (opts.check === 'forms_inventory') {
                  return {
                    forms: Array.from(document.querySelectorAll('form')).slice(0, 30).map(form => ({
                      action: form.getAttribute('action') || '',
                      method: (form.getAttribute('method') || 'GET').toUpperCase(),
                      hasCsrfInput: Boolean(form.querySelector('input[name*="csrf" i], input[name*="token" i], input[name*="nonce" i]')),
                    })),
                  }
                }
                if (opts.check === 'storage_keys') {
                  let ls: string[] = []
                  let ss: string[] = []
                  try { ls = Object.keys(window.localStorage).slice(0, 64) } catch { /* ignore */ }
                  try { ss = Object.keys(window.sessionStorage).slice(0, 64) } catch { /* ignore */ }
                  return { localStorageKeys: ls, sessionStorageKeys: ss }
                }
                if (opts.check === 'postmessage_audit') {
                  return {
                    count: probe?.handlers.length ?? 0,
                    hasOnMessage: Boolean(probe?.hasOnMessage),
                    uncheckedCount: (probe?.handlers ?? []).filter(h => !h.checksOrigin).length,
                  }
                }
                if (opts.check === 'canary_presence') {
                  const token = opts.canaryToken ?? ''
                  const html = document.documentElement?.outerHTML ?? ''
                  return {
                    canaryToken: token || null,
                    presentInHtml: Boolean(token && html.includes(token)),
                    presentInSinkTraces: Boolean(token && (probe?.sinkTraces ?? []).some(t => t.containsCanary)),
                  }
                }
                return {
                  title: document.title.slice(0, 300),
                  readyState: document.readyState,
                  iframeCount: document.querySelectorAll('iframe').length,
                }
              }, { check: action.builtinCheck, canaryToken: step.canaryToken ?? null })
              const safeData = JSON.parse(redact(JSON.stringify(data), stepSecrets)) as Record<string, unknown>
              builtinResults[action.builtinCheck] = safeData
              actionResults.push({ type: 'evaluate_builtin', ok: true, detail: action.builtinCheck, data: safeData })
            }
          } catch (err) {
            actionResults.push({
              type: action.type,
              ok: false,
              detail: redact(err instanceof Error ? err.message : String(err), stepSecrets).slice(0, 300),
            })
          }
        }

        const settleMs = step.waitAfterLoadMs !== undefined
          ? Math.min(step.waitAfterLoadMs, 5000)
          : (navigated ? 250 : 120)
        if (settleMs > 0) await page.waitForTimeout(settleMs)
        deadline.throwIfAborted()

        const resolvedCheckKind = step.checkKind ??
          (step.action === 'postmessage_probe' ? 'postmessage'
            : (step.action === 'dom_check' || step.action === 'dom_xss_sink_hook') ? 'dom_xss' : undefined)

        const canaryToken = step.canaryToken ?? null
        const snapshot = await page.evaluate(async (opts: {
          checkKind?: string
          canaryToken: string | null
          selector: string | null
          postMessageOrigin: string | null
          postMessagePayload: unknown
          hasCustomPostMessage: boolean
          sameSiteFetch: { url: string; origin: string; method: string; credentials: RequestCredentials } | null
        }) => {
          const probe = (window as unknown as {
            __kovoBrowserProbe?: {
              handlers: Array<{ preview: string; checksOrigin: boolean }>
              hasOnMessage: boolean
              observedEvents: number
              canaryObserved: boolean
              domCanaryTriggered?: boolean
              sinkTraces?: BrowserDomSinkTrace[]
            }
          }).__kovoBrowserProbe

          const handlers = (probe?.handlers ?? []).slice(0, 30)
          const hasUncheckedPostMessage = handlers.some(h => !h.checksOrigin)
          let canaryTriggered = false
          let canaryDetail: string | null = null
          let canaryHandledWithoutOriginCheck = false

          if ((opts.checkKind === 'postmessage' || opts.hasCustomPostMessage) && handlers.length > 0) {
            const pmToken = opts.canaryToken ?? 'kovo-pm-canary'
            const pmOrigin = opts.postMessageOrigin ?? 'https://untrusted-origin.invalid'
            const pmData = opts.hasCustomPostMessage && opts.postMessagePayload !== undefined
              ? opts.postMessagePayload
              : { kovoCanary: pmToken, type: 'kovo-probe' }
            try {
              window.dispatchEvent(new MessageEvent('message', { data: pmData, origin: pmOrigin }))
            } catch { /* ignore */ }
            await new Promise(resolve => setTimeout(resolve, 40))
            if (hasUncheckedPostMessage) {
              canaryHandledWithoutOriginCheck = true
              canaryTriggered = true
              canaryDetail = `Detected ${handlers.filter(h => !h.checksOrigin).length} postMessage listener(s) without an apparent event.origin validation check.`
            }
          }

          let fetchResult: BrowserFetchResult | null = null
          if (opts.sameSiteFetch) {
            try {
              const resp = await window.fetch(opts.sameSiteFetch.url, {
                method: opts.sameSiteFetch.method,
                credentials: opts.sameSiteFetch.credentials,
              })
              const text = await resp.text().catch(() => '')
              fetchResult = {
                url: opts.sameSiteFetch.url,
                origin: opts.sameSiteFetch.origin,
                method: opts.sameSiteFetch.method,
                credentials: opts.sameSiteFetch.credentials,
                ok: resp.ok,
                status: resp.status,
                contentType: resp.headers.get('content-type'),
                bodyPreview: text.slice(0, 4096),
                bodyBytes: text.length,
                error: null,
              }
            } catch (err) {
              fetchResult = {
                url: opts.sameSiteFetch.url,
                origin: opts.sameSiteFetch.origin,
                method: opts.sameSiteFetch.method,
                credentials: opts.sameSiteFetch.credentials,
                ok: false,
                status: null,
                contentType: null,
                bodyPreview: '',
                bodyBytes: 0,
                error: err instanceof Error ? err.message : String(err),
              }
            }
          }

          // C-8: Do NOT trust main-world `window.__kovoDomCanary`, `[data-kovo-canary]` markers,
          // `document.title`, or mutable `probe.domCanaryTriggered` as execution proof; execution
          // attestation is verified strictly on the host via `page.exposeBinding` nonce matching.
          const sinkTraces = (probe?.sinkTraces ?? []).slice(0, 80)

          let selectorResult: BrowserSelectorResult | null = null
          if (opts.selector) {
            try {
              const matchedNodes = Array.from(document.querySelectorAll(opts.selector)).slice(0, 50)
              const preview = matchedNodes
                .map(node => (node.textContent || node.outerHTML || '').trim())
                .filter(Boolean)
                .join(' | ')
                .slice(0, 1000)
              selectorResult = {
                selector: opts.selector,
                matched: matchedNodes.length > 0,
                count: matchedNodes.length,
                textPreview: preview,
              }
            } catch {
              selectorResult = { selector: opts.selector, matched: false, count: 0, textPreview: '' }
            }
          }

          const domHtml = document.documentElement?.outerHTML ?? ''
          const links = Array.from(document.querySelectorAll('a[href]')).map(el => el.getAttribute('href') || '').filter(Boolean).slice(0, 120)
          const forms = Array.from(document.querySelectorAll('form')).slice(0, 40).map(form => ({
            action: form.getAttribute('action') || '',
            method: (form.getAttribute('method') || 'GET').toUpperCase(),
            inputNames: Array.from(form.querySelectorAll('input, select, textarea')).map(el => el.getAttribute('name') || el.getAttribute('id') || '').filter(Boolean).slice(0, 30),
          }))
          const cookieNames = (document.cookie || '').split(';').map(p => p.split('=', 1)[0]?.trim() || '').filter(Boolean).slice(0, 64)
          let localStorageKeys: string[] = []
          let sessionStorageKeys: string[] = []
          try { localStorageKeys = Object.keys(window.localStorage).slice(0, 64) } catch { /* ignore */ }
          try { sessionStorageKeys = Object.keys(window.sessionStorage).slice(0, 64) } catch { /* ignore */ }

          return {
            domHtml,
            links,
            forms,
            cookieNames,
            localStorageKeys,
            sessionStorageKeys,
            postMessageListeners: {
              count: handlers.length,
              hasOnMessage: Boolean(probe?.hasOnMessage),
              handlers,
              observedEvents: probe?.observedEvents ?? 0,
              canaryHandledWithoutOriginCheck,
            },
            canaryTriggered,
            canaryDetail,
            sinkTraces,
            selectorResult,
            fetchResult,
          }
        }, {
          checkKind: resolvedCheckKind,
          canaryToken,
          selector: step.selector ?? null,
          postMessageOrigin: step.action === 'postmessage_probe'
            ? (step.postMessageOrigin ?? 'https://untrusted-origin.invalid')
            : (step.postMessageOrigin ?? null),
          postMessagePayload: step.postMessagePayload,
          hasCustomPostMessage: step.postMessageOrigin !== undefined || step.postMessagePayload !== undefined,
          sameSiteFetch: validatedFetch,
        })

        const finalUrlRaw = page.url()
        const runtimeSecrets = [...stepSecrets, ...this.broker.getRegisteredSecrets()]
        const egress = createEgressSanitizer({ secrets: runtimeSecrets })
        const finalUrl = egress.redactText(finalUrlRaw, 'browser_result')
        const title = egress.redactText(await page.title().catch(() => ''), 'browser_result').slice(0, 300)
        const primaryExchange = stepExchanges[0]
        let finalOrigin = stepOrigin
        try { finalOrigin = new URL(finalUrlRaw).origin } catch { /* keep stepOrigin */ }
        const redirectOrigins = primaryExchange?.redirectOrigins ?? [stepOrigin]
        const initialRedactedUrl = egress.redactText(new URL(currentPathAndQuery, stepOrigin).href, 'browser_result')
        const redirectSummary: BrowserRedirectSummary = {
          initialUrl: initialRedactedUrl,
          finalUrl,
          redirected: finalUrl !== initialRedactedUrl || redirectOrigins.length > 1,
          finalOrigin,
          redirectOrigins,
          blockedRedirectAttempt: stepBlockedOrigins.size > 0,
        }

        if (secondOrderStorage && step.runId && snapshot.domHtml) {
          scanSecondOrderMarkers({
            text: snapshot.domHtml,
            runId: step.runId,
            assignmentId: step.assignmentId,
            origin: finalOrigin,
            endpoint: currentPathAndQuery,
            persona: step.persona ?? null,
            exchangeId: stepExchangeIds[0] ?? null,
            storage: secondOrderStorage,
          })
        }

        const safeSelectorResult: BrowserSelectorResult | null = snapshot.selectorResult
          ? { ...snapshot.selectorResult, textPreview: egress.redactText(snapshot.selectorResult.textPreview, 'browser_result') }
          : null
        const safeFetchResult: BrowserFetchResult | null = snapshot.fetchResult
          ? {
              ...snapshot.fetchResult,
              url: egress.redactText(snapshot.fetchResult.url, 'browser_result'),
              bodyPreview: egress.redactText(snapshot.fetchResult.bodyPreview, 'browser_result'),
              error: snapshot.fetchResult.error ? egress.redactText(snapshot.fetchResult.error, 'browser_result') : null,
            }
          : null
        const safeSinkTraces: BrowserDomSinkTrace[] = (snapshot.sinkTraces ?? []).map(t => ({
          ...t,
          preview: egress.redactText(t.preview, 'browser_result').slice(0, 400),
        }))
        const stepAttestation = stepAttestor.snapshot()
        activeStepAttestor = null
        const stepAttestedSinks = buildVerifiedTraceSinks({
          attestation: stepAttestation,
          domSinkTraces: safeSinkTraces,
        })
        const stepCanaryTriggered = stepAttestation.verified || snapshot.canaryTriggered
        const stepCanaryDetail = stepAttestation.verified
          ? 'Host-attested isolated binding callback verified.'
          : snapshot.canaryDetail

        results.push(egress.sanitizeBrowserResult({
          origin: stepOrigin,
          finalUrl,
          title,
          status: stepExchanges[0]?.status ?? lastNavStatus,
          domSnippet: egress.redactText(snapshot.domHtml, 'browser_result').slice(0, maxDomSnippetChars),
          links: [...new Set(snapshot.links.map(l => egress.redactText(l, 'browser_result')))].slice(0, 120),
          forms: snapshot.forms,
          xhrRequests: stepXhrRequests.slice(0, 100),
          allRequests: stepAllRequests.slice(0, 150),
          blockedOrigins: [...stepBlockedOrigins].slice(0, 100),
          consoleMessages: stepConsoleMessages,
          postMessageListeners: {
            ...snapshot.postMessageListeners,
            handlers: snapshot.postMessageListeners.handlers.map(h => ({
              preview: egress.redactText(h.preview, 'browser_result'),
              checksOrigin: h.checksOrigin,
            })),
          },
          cookieNames: snapshot.cookieNames,
          localStorageKeys: snapshot.localStorageKeys,
          sessionStorageKeys: snapshot.sessionStorageKeys,
          canaryCheck: {
            token: canaryToken,
            triggered: stepCanaryTriggered,
            detail: stepCanaryDetail,
            attested: stepAttestation.verified,
            nonce: stepAttestation.nonce,
          },
          attestation: stepAttestation,
          attestedSinks: stepAttestedSinks,
          domSinkTraces: safeSinkTraces,
          ...(actionResults.length > 0 ? { actionResults } : {}),
          ...(Object.keys(builtinResults).length > 0 ? { builtinResults } : {}),
          selectorResult: safeSelectorResult,
          fetchResult: safeFetchResult,
          redirectSummary,
          exchangeIds: stepExchangeIds,
          exchanges: stepExchanges,
          durationMs: Date.now() - stepStarted,
        }))

        if (step.role === 'control' || step.role === 'probe') {
          activeControlProbeRole = step.role
        }
        lastPersona = step.persona ?? undefined
        lastOrigin = stepOrigin
      }

      return results
    } finally {
      deadline.removeEventListener('abort', onAbort)
      await forceClose()
    }
  }
}

export async function visitPage(
  broker: RequestBroker,
  req: BrowserVisitRequest,
  grant: Grant,
  signal: AbortSignal,
  options?: ScopedBrowserOptions,
): Promise<BrowserVisitResult> {
  return new ScopedBrowser(broker, options).visitPage(req, grant, signal)
}
