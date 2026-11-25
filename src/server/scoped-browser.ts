import { randomBytes } from 'node:crypto'
import { containsDestructivePayload } from '../replay-spec.ts'
import type { BrowserBuiltinCheck, CsrfBind } from '../replay-spec.ts'
import { BrokerDenied, RequestBroker } from './broker.ts'
import type { BrokerExchangeResult, Grant } from './broker.ts'
import { scanSecondOrderMarkers } from './canary-broker.ts'
import type { SecondOrderStore } from './canary-broker.ts'
import { cookieRecordsFromHeader } from './persona-auth.ts'
import { buildPersonaBrowserAttachment, personaSecrets } from './persona-vault.ts'
import { createEgressSanitizer } from './egress-sanitizer.ts'
import { redact } from './redact.ts'
import type { NamedSecret } from './redact.ts'
import { evaluateBrowserScopeRequest } from './scope-policy.ts'
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
  }
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

interface PlaywrightPage {
  on(event: 'console', listener: (msg: { type(): string; text(): string }) => void): void
  on(event: 'pageerror', listener: (err: Error) => void): void
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
  route(url: string, handler: (route: PlaywrightRoute) => Promise<void> | void): Promise<void>
  routeWebSocket?(url: string, handler: (ws: PlaywrightWebSocketRoute) => Promise<void> | void): Promise<void>
  newPage(): Promise<PlaywrightPage>
  newCDPSession?(page: PlaywrightPage): Promise<PlaywrightCdpSession>
  close(): Promise<void>
}

export interface PlaywrightBrowserLike {
  newContext(options?: Record<string, unknown>): Promise<PlaywrightContext>
  close(): Promise<void>
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
  /** Upper bound on simultaneously pooled per-persona contexts. Defaults to 8. */
  maxPooledContexts?: number
}

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
 * Sandboxing is on by default. Target JavaScript must not be able to reach loopback/LAN/metadata
 * directly: resolver rules fail closed for every non-brokered name, and WebRTC's non-proxied UDP
 * paths are disabled. HTTP is still fulfilled through Playwright's request interception.
 */
export function chromiumLaunchArgs(options: ChromiumLaunchOptions = {}): string[] {
  const args = [
    '--disable-dev-shm-usage',
    '--disable-background-networking',
    '--host-resolver-rules=MAP * ~NOTFOUND',
    '--force-webrtc-ip-handling-policy=disable_non_proxied_udp',
    '--webrtc-ip-handling-policy=disable_non_proxied_udp',
    // WebTransport is HTTP/3 over UDP: it bypasses HTTP interception and the WebRTC flags.
    '--disable-quic',
    '--disable-features=WebTransport',
  ]
  if (options.insecureNoSandbox) args.push('--no-sandbox')
  return args
}

/** Neutralise WebRTC constructors for target JS even if a platform ignores the launch flags. */
export const browserWebRtcGuardScript = `(() => {
  const deny = function () { throw new Error('WebRTC is disabled inside Kovo Hunter browser sessions.'); };
  for (const name of ['RTCPeerConnection', 'webkitRTCPeerConnection', 'RTCDataChannel', 'WebTransport']) {
    try { Object.defineProperty(window, name, { configurable: false, writable: false, value: deny }); } catch {}
  }
})();`

/**
 * Fail-closed fallback when the Playwright version has no `routeWebSocket`: the page loses the
 * socket constructors entirely instead of being allowed to open an unchecked connection.
 */
export const browserSocketDenyScript = `(() => {
  const deny = function () { throw new Error('WebSocket/WebTransport are disabled inside Kovo Hunter browser sessions.'); };
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
 * HTTP interception does not cover WebSocket upgrades. Route every socket through an explicit
 * scope check and only call `connectToServer()` for in-scope wss/ws origins. When the Playwright
 * version has no `routeWebSocket`, the guard fails closed (page-level deny script) instead of
 * silently allowing unchecked upgrades.
 */
export async function installWebSocketGuard(
  context: Pick<PlaywrightContext, 'routeWebSocket'> & Partial<Pick<PlaywrightContext, 'addInitScript'>>,
  options: {
    canRead: (origin: string) => boolean
    allowLocalLab: boolean | (() => boolean)
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
    const allowLocalLab = typeof options.allowLocalLab === 'function' ? options.allowLocalLab() : options.allowLocalLab
    try {
      const url = new URL(ws.url())
      const secure = url.protocol === 'wss:'
      if (!secure && !(allowLocalLab && url.protocol === 'ws:')) {
        options.audit?.('denied', url.origin)
        await ws.close({ code: 1008, reason: 'Blocked by Kovo Hunter scope.' })
        return
      }
      origin = `${secure ? 'https:' : 'http:'}//${url.host}`
    } catch {
      await ws.close({ code: 1008, reason: 'Blocked by Kovo Hunter scope.' })
      return
    }
    if (!options.canRead(origin)) {
      options.audit?.('denied', origin)
      await ws.close({ code: 1008, reason: 'Blocked by Kovo Hunter scope.' })
      return
    }
    if (typeof ws.connectToServer !== 'function') {
      await ws.close({ code: 1008, reason: 'Blocked by Kovo Hunter scope.' })
      return
    }
    await ws.connectToServer()
  })
}

async function launchChromium(): Promise<PlaywrightBrowserLike> {
  const insecureNoSandbox = process.env.KOVO_INSECURE_NO_SANDBOX === '1'
  if (insecureNoSandbox) {
    console.warn('WARNING: Chromium sandbox disabled (KOVO_INSECURE_NO_SANDBOX=1). Detection fidelity is reduced.')
  }
  const args = chromiumLaunchArgs({ insecureNoSandbox })
  try {
    const coreName = 'playwright-core'
    const coreMod = await import(/* @vite-ignore */ coreName) as { chromium?: { launch: (opts: Record<string, unknown>) => Promise<PlaywrightBrowserLike> } }
    if (coreMod.chromium) {
      return await coreMod.chromium.launch({ headless: true, args })
    }
  } catch {
    // Fallback to @playwright/test
  }
  const pw = await import('@playwright/test')
  return await pw.chromium.launch({ headless: true, args }) as unknown as PlaywrightBrowserLike
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

interface PooledRuntime {
  key: string
  runId: string | undefined
  context: PlaywrightContext
  page: PlaywrightPage
  sockets: Map<string, BrowserWebSocketRecord>
  cdp: PlaywrightCdpSession | null
  active: PooledVisitState | null
  /** Mutable per-checkout grant bound on visit start and cleared on release (never stale across assignments). */
  activeGrant: Grant | null
  /** Mutable per-checkout local-lab flag paired with `activeGrant`. */
  activeAllowLocalLab: boolean
  lastUsed: number
}

interface PooledVisitState {
  origin: string
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
  onExchange?: (exchange: BrokerExchangeResult) => string | void
  signal?: AbortSignal
}

function normalizeSeedBundle(raw: unknown): BrowserSessionBundle | null {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return null
  const record = raw as Record<string, unknown>
  const hasShape = 'cookies' in record || 'localStorage' in record || 'sessionStorage' in record
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

function seedStorageInitScript(bundle: BrowserSessionBundle | null, origin: string): string | null {
  if (!bundle) return null
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

async function hydrateContextSession(
  context: PlaywrightContext,
  bundle: BrowserSessionBundle | null,
  origin: string,
): Promise<void> {
  if (!context.addCookies || !bundle?.cookies?.length) return
  try {
    await context.addCookies(bundle.cookies.map(cookie => ({
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
  void origin
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
  private readonly pooled = new Map<string, PooledRuntime>()
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

  private async ensurePoolBrowser(): Promise<PlaywrightBrowserLike> {
    if (this.poolBrowser) return this.poolBrowser
    if (!this.poolLaunch) {
      this.poolLaunch = (async () => {
        const browser = await (this.options.launchBrowser ? this.options.launchBrowser() : launchChromium())
        this.poolStats.launches += 1
        this.poolBrowser = browser
        return browser
      })()
    }
    return await this.poolLaunch
  }

  private assetScopeFor(req: BrowserVisitRequest): AssetOriginScope | undefined {
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

  private async ensurePooledContext(
    browser: PlaywrightBrowserLike,
    req: BrowserVisitRequest,
    initialOrigin: string,
    bundle: BrowserSessionBundle | null,
  ): Promise<PooledRuntime> {
    const key = `${req.runId ?? 'default'}::${req.persona ? `persona:${req.persona}` : 'anonymous'}`
    const existing = this.pooled.get(key)
    if (existing) {
      existing.lastUsed = Date.now()
      await hydrateContextSession(existing.context, bundle, initialOrigin)
      return existing
    }
    const maxContexts = Math.max(1, Math.min(this.options.maxPooledContexts ?? 8, 16))
    if (this.pooled.size >= maxContexts) {
      // Evict the least-recently-used context instead of growing without bound.
      let oldest: PooledRuntime | null = null
      for (const entry of this.pooled.values()) {
        if (!oldest || entry.lastUsed < oldest.lastUsed) oldest = entry
      }
      if (oldest) {
        this.pooled.delete(oldest.key)
        oldest.active = null
        oldest.activeGrant = null
        oldest.activeAllowLocalLab = false
        await oldest.cdp?.detach?.().catch(() => undefined)
        await oldest.page.close().catch(() => undefined)
        await oldest.context.close().catch(() => undefined)
        this.poolStats.contextsClosed += 1
      }
    }

    const context = await browser.newContext({
      ignoreHTTPSErrors: false,
      javaScriptEnabled: true,
      bypassCSP: false,
      serviceWorkers: 'block',
      userAgent: 'KovoHunter/6 pooled scoped inspector',
    })
    this.poolStats.contextsCreated += 1

    const runtime: PooledRuntime = {
      key,
      runId: req.runId,
      context,
      page: undefined as unknown as PlaywrightPage,
      sockets: new Map(),
      cdp: null,
      active: null,
      activeGrant: null,
      activeAllowLocalLab: false,
      lastUsed: Date.now(),
    }

    await context.addInitScript(postMessageInstrumentationScript)
    await context.addInitScript(browserWebRtcGuardScript)
    await installWebSocketGuard(context, {
      canRead: origin => Boolean(runtime.activeGrant?.canRead(origin)),
      allowLocalLab: () => runtime.activeAllowLocalLab,
      audit: (decision, origin) => { runtime.activeGrant?.audit(decision, origin) },
    })
    const storageSeed = bundle?.initScript ?? seedStorageInitScript(bundle, initialOrigin)
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
      const forwardedHeaders: Record<string, string> = {}
      for (const [k, v] of Object.entries(request.headers())) {
        if (forbiddenBrowserForwardHeaders.test(k)) continue
        forwardedHeaders[k] = v
      }
      const resourceType = request.resourceType()
      let personaForRequest: string | undefined
      if (state.persona && !decision.assetHydration) {
        if (parsedUrl.origin === state.origin) {
          personaForRequest = state.persona
        } else if (
          state.validatedFetch &&
          state.validatedFetch.credentials === 'include' &&
          parsedUrl.origin === state.validatedFetch.origin &&
          Boolean(activeGrant.personas?.get(state.persona)?.originAllowlist.includes(parsedUrl.origin))
        ) {
          personaForRequest = state.persona
        }
      }
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
            ...(state.persona ? { persona: state.persona } : {}),
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
      } catch {
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
    await hydrateContextSession(context, bundle, initialOrigin)
    return runtime
  }

  /**
   * Visit a sequence of pages through one pooled Chromium and one BrowserContext per persona.
   * Contexts are hydrated with HttpOnly cookies and web storage, and reused across navigations.
   */
  async visitPages(
    requests: readonly BrowserVisitRequest[],
    grant: Grant,
    signal: AbortSignal,
  ): Promise<BrowserVisitResult[]> {
    const tier = grant.tier ?? 1
    if (tier === 0) throw new BrokerDenied('Scoped browser inspection is disabled in Tier 0 (offline prepared mode).')
    if (!Array.isArray(requests) || requests.length === 0) return []
    // A pooled context carries persona cookies/storage; never let a later run reuse it.
    const activeRunId = requests[0]?.runId
    for (const [key, entry] of [...this.pooled.entries()]) {
      if (entry.runId === activeRunId) continue
      this.pooled.delete(key)
      await entry.cdp?.detach?.().catch(() => undefined)
      await entry.page.close().catch(() => undefined)
      await entry.context.close().catch(() => undefined)
      this.poolStats.contextsClosed += 1
    }
    const browser = await this.ensurePoolBrowser()
    const results: BrowserVisitResult[] = []
    const allowLocalLab = Boolean(grant.allowLocalLab && process.env.KOVO_ALLOW_LOCAL_LAB === '1')

    for (const req of requests) {
      signal.throwIfAborted()
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
      const secrets = [...collectSecrets(req, grant), ...this.broker.getRegisteredSecrets()]
      const bundle = await this.resolveBundle(req, grant, initialOrigin)
      secrets.push(...collectBundleSecrets(bundle))
      const runtime = await this.ensurePooledContext(browser, req, initialOrigin, bundle)
      const state: PooledVisitState = {
        origin: initialOrigin,
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
        ...(req.onExchange ? { onExchange: req.onExchange } : {}),
        signal,
      }
      runtime.active = state
      runtime.activeGrant = grant
      runtime.activeAllowLocalLab = allowLocalLab
      runtime.lastUsed = Date.now()
      runtime.sockets.clear()

      const deadline = AbortSignal.any([signal, AbortSignal.timeout(timeoutMs)])
      state.signal = deadline
      try {
        const navResponse = await runtime.page.goto(targetUrl.href, {
          waitUntil: 'domcontentloaded',
          timeout: Math.max(2_000, timeoutMs - (Date.now() - started)),
        })
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
          canaryCheck: { token: req.canaryToken ?? null, triggered: false, detail: null },
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
        runtime.active = null
        runtime.activeGrant = null
        runtime.activeAllowLocalLab = false
      }
    }
    return results
  }

  /** Close every pooled context and the single Chromium process. Idempotent. */
  async close(): Promise<void> {
    for (const entry of this.pooled.values()) {
      entry.active = null
      entry.activeGrant = null
      entry.activeAllowLocalLab = false
      await entry.cdp?.detach?.().catch(() => undefined)
      await entry.page.close().catch(() => undefined)
      await entry.context.close().catch(() => undefined)
      this.poolStats.contextsClosed += 1
    }
    this.pooled.clear()
    if (this.poolBrowser) {
      await this.poolBrowser.close().catch(() => undefined)
      this.poolBrowser = null
      this.poolLaunch = null
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

    const browser = await (this.options.launchBrowser ? this.options.launchBrowser() : launchChromium())
    let context: PlaywrightContext | undefined
    let page: PlaywrightPage | undefined
    let closed = false

    const forceClose = async () => {
      if (closed) return
      closed = true
      await page?.close().catch(() => undefined)
      await context?.close().catch(() => undefined)
      await browser.close().catch(() => undefined)
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
        userAgent: 'KovoHunter/3 scoped headless inspector',
      })
      await context.addInitScript(postMessageInstrumentationScript)
      await context.addInitScript(browserWebRtcGuardScript)
      await installWebSocketGuard(context, {
        canRead: origin => grant.canRead(origin),
        allowLocalLab,
        audit: (decision, origin) => grant.audit(decision, origin),
      })

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

        const forwardedHeaders: Record<string, string> = {}
        for (const [k, v] of Object.entries(request.headers())) {
          if (forbiddenBrowserForwardHeaders.test(k)) continue
          forwardedHeaders[k] = v
        }

        const resourceType = request.resourceType()
        let personaForRequest: string | undefined
        if (req.persona && !decision.assetHydration) {
          if (parsedUrl.origin === initialOrigin) {
            personaForRequest = req.persona
          } else if (
            validatedFetch &&
            validatedFetch.credentials === 'include' &&
            parsedUrl.origin === validatedFetch.origin &&
            Boolean(grant.personas?.get(req.persona)?.originAllowlist.includes(parsedUrl.origin))
          ) {
            personaForRequest = req.persona
          }
        }

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
              ...(req.persona ? { persona: req.persona } : {}),
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
            // Strictly Kovo Hunter-authored read-only DOM/sink inspectors (never arbitrary JS!)
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

        const sinkTraces = (probe?.sinkTraces ?? []).slice(0, 80)
        const sinkCanaryHit = sinkTraces.find(t => t.containsCanary)
        if (sinkCanaryHit || probe?.domCanaryTriggered) {
          canaryTriggered = true
          canaryDetail = sinkCanaryHit
            ? `Canary reached executable DOM sink "${sinkCanaryHit.sink}".`
            : 'Canary triggered DOM XSS sink hook.'
        }

        if (!canaryTriggered && opts.canaryToken) {
          const markerEl = document.querySelector(`[data-kovo-canary="${opts.canaryToken}"], [id="${opts.canaryToken}"]`)
          const globalFlag = Boolean((window as unknown as Record<string, unknown>).__kovoDomCanary === opts.canaryToken)
          if (markerEl || globalFlag) {
            canaryTriggered = true
            canaryDetail = globalFlag
              ? 'DOM execution canary flag observed on window.'
              : 'Unescaped canary element/attribute observed in rendered DOM.'
          }
        }

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
          triggered: snapshot.canaryTriggered,
          detail: snapshot.canaryDetail,
        },
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
    const browser = await (this.options.launchBrowser ? this.options.launchBrowser() : launchChromium())

    let context: PlaywrightContext | undefined
    let page: PlaywrightPage | undefined
    let closed = false

    const forceClose = async () => {
      if (closed) return
      closed = true
      await page?.close().catch(() => undefined)
      await context?.close().catch(() => undefined)
      await browser.close().catch(() => undefined)
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
      let stepBlockedOrigins = new Set<string>()
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
            userAgent: 'KovoHunter/4 scoped headless session inspector',
          })
          await context.addInitScript(postMessageInstrumentationScript)
          await context.addInitScript(browserWebRtcGuardScript)
          await installWebSocketGuard(context, {
            canRead: origin => grant.canRead(origin),
            allowLocalLab,
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

            const validProtocol = parsedUrl.protocol === 'https:' || (allowLocalLab && parsedUrl.protocol === 'http:')
            if (!validProtocol || !grant.canRead(parsedUrl.origin)) {
              stepBlockedOrigins.add(parsedUrl.origin)
              grant.audit('denied', parsedUrl.origin)
              await route.abort('blockedbyclient').catch(() => undefined)
              return
            }

            const method = request.method().toUpperCase()
            if (!allowedMethods.has(method)) {
              await route.abort('blockedbyclient').catch(() => undefined)
              return
            }
            const isReadOnly = method === 'GET' || method === 'HEAD' || method === 'OPTIONS'
            const isTier2Post = method === 'POST' && tier >= 2
            if (!isReadOnly && !isTier2Post && tier < 3) {
              await route.abort('blockedbyclient').catch(() => undefined)
              return
            }

            const forwardedHeaders: Record<string, string> = {}
            for (const [k, v] of Object.entries(request.headers())) {
              if (forbiddenBrowserForwardHeaders.test(k)) continue
              forwardedHeaders[k] = v
            }

            const cur = activeStep
            const resourceType = request.resourceType()
            let personaForRequest: string | undefined
            if (cur.step.persona) {
              if (parsedUrl.origin === cur.origin) {
                personaForRequest = cur.step.persona
              } else if (
                cur.validatedFetch &&
                cur.validatedFetch.credentials === 'include' &&
                parsedUrl.origin === cur.validatedFetch.origin &&
                Boolean(grant.personas?.get(cur.step.persona)?.originAllowlist.includes(parsedUrl.origin))
              ) {
                personaForRequest = cur.step.persona
              }
            }

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
              }, grant, deadline)

              stepExchanges.push(exchange)
              const recordedId = cur.step.onExchange?.(exchange)
              if (typeof recordedId === 'string' && recordedId) stepExchangeIds.push(recordedId)
              await mirrorJarCookies(context, this.broker, {
                ...(cur.step.persona ? { persona: cur.step.persona } : {}),
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

          const sinkTraces = (probe?.sinkTraces ?? []).slice(0, 80)
          const sinkCanaryHit = sinkTraces.find(t => t.containsCanary)
          if (sinkCanaryHit || probe?.domCanaryTriggered) {
            canaryTriggered = true
            canaryDetail = sinkCanaryHit
              ? `Canary reached executable DOM sink "${sinkCanaryHit.sink}".`
              : 'Canary triggered DOM XSS sink hook.'
          }
          if (!canaryTriggered && opts.canaryToken) {
            const markerEl = document.querySelector(`[data-kovo-canary="${opts.canaryToken}"], [id="${opts.canaryToken}"]`)
            const globalFlag = Boolean((window as unknown as Record<string, unknown>).__kovoDomCanary === opts.canaryToken)
            if (markerEl || globalFlag) {
              canaryTriggered = true
              canaryDetail = globalFlag
                ? 'DOM execution canary flag observed on window.'
                : 'Unescaped canary element/attribute observed in rendered DOM.'
            }
          }

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
            triggered: snapshot.canaryTriggered,
            detail: snapshot.canaryDetail,
          },
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
