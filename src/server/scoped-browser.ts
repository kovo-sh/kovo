import { containsDestructivePayload } from '../replay-spec.ts'
import type { BrowserBuiltinCheck } from '../replay-spec.ts'
import { BrokerDenied, RequestBroker } from './broker.ts'
import type { BrokerExchangeResult, Grant } from './broker.ts'
import { personaSecrets } from './persona-vault.ts'
import { redact } from './redact.ts'
import type { NamedSecret } from './redact.ts'

export interface BrowserSameSiteFetchRequest {
  origin: string
  pathAndQuery: string
  method?: 'GET' | 'HEAD' | 'OPTIONS'
  credentials?: 'include' | 'same-origin' | 'omit'
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
  fill?(selector: string, value: string, options?: { timeout?: number }): Promise<void>
  click?(selector: string, options?: { timeout?: number }): Promise<void>
  selectOption?(selector: string, values: string, options?: { timeout?: number }): Promise<string[]>
  waitForSelector?(selector: string, options?: { timeout?: number }): Promise<unknown>
  url(): string
  title(): Promise<string>
  evaluate<T, A = undefined>(fn: (arg: A) => T | Promise<T>, arg?: A): Promise<T>
  close(): Promise<void>
}

interface PlaywrightContext {
  addInitScript(script: string | (() => void)): Promise<void>
  route(url: string, handler: (route: PlaywrightRoute) => Promise<void> | void): Promise<void>
  newPage(): Promise<PlaywrightPage>
  close(): Promise<void>
}

export interface PlaywrightBrowserLike {
  newContext(options?: Record<string, unknown>): Promise<PlaywrightContext>
  close(): Promise<void>
}

export interface ScopedBrowserOptions {
  launchBrowser?: () => Promise<PlaywrightBrowserLike>
}

const maxBrowserTimeoutMs = 30_000
const maxDomSnippetChars = 16_384
const maxInteractiveActions = 20
const forbiddenBrowserForwardHeaders = /^(?:authorization|proxy-authorization|cookie|host|content-length|transfer-encoding|connection|accept-encoding|sec-fetch-.*|sec-ch-.*)$/i
const allowedMethods = new Set(['GET', 'HEAD', 'OPTIONS', 'POST', 'PUT', 'PATCH', 'DELETE'])
const safeReadOnlyFetchMethods = new Set(['GET', 'HEAD', 'OPTIONS'])
const unsafeSelectorPattern = /[<>{};`\\]|javascript:/i

async function launchChromium(): Promise<PlaywrightBrowserLike> {
  try {
    const coreName = 'playwright-core'
    const coreMod = await import(/* @vite-ignore */ coreName) as { chromium?: { launch: (opts: Record<string, unknown>) => Promise<PlaywrightBrowserLike> } }
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
  }) as unknown as PlaywrightBrowserLike
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
  Object.defineProperty(window, '__guardianBrowserProbe', {
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
      if (serialized && serialized.includes('guardian-pm-canary')) {
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
  const probe = window.__guardianBrowserProbe;
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

export class ScopedBrowser {
  private readonly broker: RequestBroker
  private readonly options: ScopedBrowserOptions

  constructor(broker: RequestBroker, options: ScopedBrowserOptions = {}) {
    this.broker = broker
    this.options = options
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

    const secrets = collectSecrets(req, grant)
    const allowLocalLab = Boolean(grant.allowLocalLab && process.env.GUARDIAN_ALLOW_LOCAL_LAB === '1')
    const exchanges: BrokerExchangeResult[] = []
    const exchangeIds: string[] = []
    const xhrRequests: BrowserXhrRecord[] = []
    const allRequests: BrowserXhrRecord[] = []
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
        userAgent: 'Guardian/3 scoped headless inspector',
      })
      await context.addInitScript(postMessageInstrumentationScript)

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

        const validProtocol = parsedUrl.protocol === 'https:' || (allowLocalLab && parsedUrl.protocol === 'http:')
        if (!validProtocol || !grant.canRead(parsedUrl.origin)) {
          blockedOrigins.add(parsedUrl.origin)
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
        if (!isReadOnly && tier < 3) {
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
        if (req.persona) {
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
            persona: personaForRequest,
            followRedirects: true,
            secrets,
            timeoutMs: Math.max(2_000, timeoutMs - (Date.now() - started)),
          }, grant, deadline)

          exchanges.push(exchange)
          const recordedId = req.onExchange?.(exchange)
          if (typeof recordedId === 'string' && recordedId) exchangeIds.push(recordedId)

          const reqRecord: BrowserXhrRecord = {
            method,
            url: redact(parsedUrl.href, secrets),
            origin: parsedUrl.origin,
            resourceType,
            status: exchange.status,
          }
          if (allRequests.length < 150) allRequests.push(reqRecord)
          if (resourceType === 'xhr' || resourceType === 'fetch') {
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
            // Strictly Guardian-authored read-only DOM/sink inspectors (never arbitrary JS!)
            const data = await page.evaluate((opts: { check: BrowserBuiltinCheck; canaryToken: string | null }) => {
              const probe = (window as unknown as {
                __guardianBrowserProbe?: {
                  handlers: Array<{ preview: string; checksOrigin: boolean }>
                  hasOnMessage: boolean
                  observedEvents: number
                  sinkTraces?: BrowserDomSinkTrace[]
                }
              }).__guardianBrowserProbe

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
          __guardianBrowserProbe?: {
            handlers: Array<{ preview: string; checksOrigin: boolean }>
            hasOnMessage: boolean
            observedEvents: number
            canaryObserved: boolean
            domCanaryTriggered?: boolean
            sinkTraces?: BrowserDomSinkTrace[]
          }
        }).__guardianBrowserProbe

        const handlers = (probe?.handlers ?? []).slice(0, 30)
        const hasUncheckedPostMessage = handlers.some(h => !h.checksOrigin)

        let canaryTriggered = false
        let canaryDetail: string | null = null
        let canaryHandledWithoutOriginCheck = false

        if ((opts.checkKind === 'postmessage' || opts.hasCustomPostMessage) && handlers.length > 0) {
          const pmToken = opts.canaryToken ?? 'guardian-pm-canary'
          const pmOrigin = opts.postMessageOrigin ?? 'https://untrusted-origin.invalid'
          const pmData = opts.hasCustomPostMessage && opts.postMessagePayload !== undefined
            ? opts.postMessagePayload
            : { guardianCanary: pmToken, type: 'guardian-probe' }
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
          const markerEl = document.querySelector(`[data-guardian-canary="${opts.canaryToken}"], [id="${opts.canaryToken}"]`)
          const globalFlag = Boolean((window as unknown as Record<string, unknown>).__guardianDomCanary === opts.canaryToken)
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
      const finalUrl = redact(finalUrlRaw, secrets)
      const title = redact(await page.title().catch(() => ''), secrets).slice(0, 300)
      const primaryExchange = exchanges[0]
      let finalOrigin = initialOrigin
      try { finalOrigin = new URL(finalUrlRaw).origin } catch { /* keep initialOrigin */ }
      const redirectOrigins = primaryExchange?.redirectOrigins ?? [initialOrigin]
      const initialRedactedUrl = redact(targetUrl.href, secrets)
      const redirectSummary: BrowserRedirectSummary = {
        initialUrl: initialRedactedUrl,
        finalUrl,
        redirected: finalUrl !== initialRedactedUrl || redirectOrigins.length > 1,
        finalOrigin,
        redirectOrigins,
        blockedRedirectAttempt: blockedOrigins.size > 0,
      }

      const safeSelectorResult: BrowserSelectorResult | null = snapshot.selectorResult
        ? {
            ...snapshot.selectorResult,
            textPreview: redact(snapshot.selectorResult.textPreview, secrets),
          }
        : null

      const safeFetchResult: BrowserFetchResult | null = snapshot.fetchResult
        ? {
            ...snapshot.fetchResult,
            url: redact(snapshot.fetchResult.url, secrets),
            bodyPreview: redact(snapshot.fetchResult.bodyPreview, secrets),
            error: snapshot.fetchResult.error ? redact(snapshot.fetchResult.error, secrets) : null,
          }
        : null

      const safeSinkTraces: BrowserDomSinkTrace[] = (snapshot.sinkTraces ?? []).map(t => ({
        ...t,
        preview: redact(t.preview, secrets).slice(0, 400),
      }))

      return {
        origin: initialOrigin,
        finalUrl,
        title,
        status: navResponse ? navResponse.status() : (exchanges[0]?.status ?? null),
        domSnippet: redact(snapshot.domHtml, secrets).slice(0, maxDomSnippetChars),
        links: [...new Set(snapshot.links.map(l => redact(l, secrets)))].slice(0, 120),
        forms: snapshot.forms,
        xhrRequests: xhrRequests.slice(0, 100),
        allRequests: allRequests.slice(0, 150),
        blockedOrigins: [...blockedOrigins].slice(0, 100),
        consoleMessages,
        postMessageListeners: {
          ...snapshot.postMessageListeners,
          handlers: snapshot.postMessageListeners.handlers.map(h => ({
            preview: redact(h.preview, secrets),
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
      }
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
