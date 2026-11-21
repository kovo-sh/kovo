import { containsDestructivePayload } from '../replay-spec.ts'
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
const forbiddenBrowserForwardHeaders = /^(?:authorization|proxy-authorization|cookie|host|content-length|transfer-encoding|connection|accept-encoding|sec-fetch-.*|sec-ch-.*)$/i
const allowedMethods = new Set(['GET', 'HEAD', 'OPTIONS', 'POST', 'PUT', 'PATCH'])
const safeReadOnlyFetchMethods = new Set(['GET', 'HEAD', 'OPTIONS'])
const unsafeSelectorPattern = /[<>{};`\\]|javascript:/i

async function launchChromium(): Promise<PlaywrightBrowserLike> {
  // Prefer playwright-core if present, falling back cleanly to @playwright/test.
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
      if (!req.selector.trim() || req.selector.length > 256 || unsafeSelectorPattern.test(req.selector)) {
        grant.audit('denied', initialOrigin)
        throw new BrokerDenied('Browser selector must be a safe read-only CSS selector.')
      }
    }
    if (req.postMessagePayload !== undefined && hasDestructiveInput(JSON.stringify(req.postMessagePayload))) {
      grant.audit('denied', initialOrigin)
      throw new BrokerDenied('Browser postMessage payload blocked by destructive-payload denylist.')
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
        userAgent: 'Guardian/2 scoped headless inspector',
      })
      await context.addInitScript(postMessageInstrumentationScript)

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
        // Never leak persona credentials to other origins unless explicitly authorized for a
        // validated sameSiteFetch (credentials: 'include') AND present in persona.originAllowlist.
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
            method: method as 'GET' | 'HEAD' | 'OPTIONS' | 'POST' | 'PUT' | 'PATCH',
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

        if (!canaryTriggered && opts.canaryToken) {
          // Check for unescaped DOM sink injection (element attribute/tag matching canary) or explicit DOM canary flag.
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
