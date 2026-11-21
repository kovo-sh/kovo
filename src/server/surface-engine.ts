import { createHash, randomBytes, randomInt, randomUUID } from 'node:crypto'
import { BrokerApprovalRequired, BrokerCircuitOpen, BrokerDenied } from './broker.ts'
import type { BrokerExchangeResult, BrokerHttpRequest, Grant, RequestBroker } from './broker.ts'
import type { CanaryBroker } from './canary-broker.ts'
import type { HttpMethod } from '../domain.ts'
import { containsDestructivePayload } from '../replay-spec.ts'
import { loadSafeTemplates, selectSafeTemplates } from '../templates/loader.ts'
import type { SafeTemplate, TemplateMatcher } from '../templates/loader.ts'
import type { Store } from './store.ts'

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

/** Token-set Jaccard similarity of two response bodies (1 = identical). */
export function responseSimilarity(a: string, b: string): number {
  if (a === b) return 1
  const tok = (s: string) => new Set(s.toLowerCase().split(/[^a-z0-9]+/).filter(Boolean).slice(0, 4000))
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

function setQueryParam(pathAndQuery: string, name: string, value: string): string {
  const url = new URL(pathAndQuery, 'http://guardian.invalid')
  url.searchParams.set(name, value)
  return url.pathname + url.search
}

function setJsonPath(target: Record<string, unknown>, dotPath: string, value: unknown) {
  const parts = dotPath.split('.')
  let cur = target
  for (let i = 0; i < parts.length - 1; i += 1) {
    const next = cur[parts[i]]
    if (!next || typeof next !== 'object' || Array.isArray(next)) cur[parts[i]] = {}
    cur = cur[parts[i]] as Record<string, unknown>
  }
  cur[parts[parts.length - 1]] = value
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
  paramLocation?: 'query' | 'json'
  batchSize?: number
  methods?: HttpMethod[]
  persona?: string
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
      const candidateList = [...new Set(merged)].slice(0, Math.max(0, max - 2))
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
      if (!safeProbePath(basePath.split('?')[0])) throw new BrokerDenied('basePath is invalid.')
      const location = req.paramLocation ?? 'query'
      const names = [...new Set((req.params?.length ? req.params : commonParamWordlist)
        .filter(n => /^[A-Za-z0-9_.\-[\]]{1,64}$/.test(n)))].slice(0, maxParamCandidates)
      candidates = names.length
      const batchSize = Math.max(10, Math.min(req.batchSize ?? 25, 25))
      const method: HttpMethod = location === 'json' ? 'POST' : 'GET'

      const values = new Map<string, string>(names.map(n => [n, `gv${randToken(8)}`]))
      const build = (subset: readonly string[]): BrokerHttpRequest => {
        if (location === 'json') {
          const body: Record<string, unknown> = {}
          for (const n of subset) body[n] = values.get(n)
          return { origin, method, pathAndQuery: basePath, body: JSON.stringify(body), headers: { 'Content-Type': 'application/json' } }
        }
        let pq = basePath
        for (const n of subset) pq = setQueryParam(pq, n, values.get(n)!)
        return { origin, method, pathAndQuery: pq }
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
  | 'sqli_boolean' | 'ssti_math' | 'ssrf_canary' | 'nosqli_type'
  | 'path_traversal_benign' | 'graphql_audit' | 'authz_matrix'

export interface ProbeDifferentialRequest {
  probeClass: DifferentialProbeClass
  origin: string
  /** Endpoint path+query. authz_matrix requires a {{id}} placeholder. */
  pathAndQuery: string
  method?: 'GET' | 'POST'
  /** Parameter under test (sqli_boolean, ssti_math, nosqli_type) */
  param?: string
  paramLocation?: 'query' | 'json'
  jsonBody?: Record<string, unknown>
  baselineValue?: string
  persona?: string
  headers?: Record<string, string>
  /** ssrf_canary: candidate URL/webhook/redirect parameter names */
  ssrfParams?: string[]
  injectHeaders?: boolean
  waitMs?: number
  runId?: string
  assignmentId?: string
  storage?: Store
  /** authz_matrix */
  resourceIds?: string[]
  ownerPersona?: string
  otherPersona?: string
  includeAnonymous?: boolean
  includeHeaderBypass?: boolean
  maxRequests?: number
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

type InjectedRequest = Pick<BrokerHttpRequest, 'pathAndQuery' | 'body' | 'headers' | 'method'>

function injectParam(req: ProbeDifferentialRequest, value: string | Record<string, unknown>): InjectedRequest {
  const param = req.param ?? 'q'
  const location = req.paramLocation ?? (req.method === 'POST' ? 'json' : 'query')
  if (location === 'json') {
    const body: Record<string, unknown> = structuredClone(req.jsonBody ?? {})
    setJsonPath(body, param, value)
    return {
      method: 'POST',
      pathAndQuery: req.pathAndQuery,
      body: JSON.stringify(body),
      headers: { 'Content-Type': 'application/json', ...(req.headers ?? {}) },
    }
  }
  if (typeof value !== 'string') {
    const url = new URL(req.pathAndQuery, 'http://guardian.invalid')
    for (const [op, v] of Object.entries(value)) url.searchParams.set(`${param}[${op}]`, String(v))
    return { method: 'GET', pathAndQuery: url.pathname + url.search, headers: req.headers }
  }
  return { method: 'GET', pathAndQuery: setQueryParam(req.pathAndQuery, param, value), headers: req.headers }
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

  // Each style appends a randomized, side-effect-free comparison (k=k vs k=k+1) to the baseline value.
  const styles: Array<{ name: string; make: (k: number, truth: boolean) => string }> = [
    { name: 'numeric', make: (k, t) => `${baseValue} AND ${k}=${t ? k : k + 1}` },
    { name: 'single_quote', make: (k, t) => `${baseValue}' AND ${k}=${t ? k : k + 1}-- -` },
    { name: 'double_quote', make: (k, t) => `${baseValue}" AND ${k}=${t ? k : k + 1}-- -` },
  ]
  const signals: Array<Record<string, unknown>> = []
  for (const style of styles) {
    const rounds: Array<Record<string, unknown>> = []
    let pass = true
    for (let r = 0; r < 2; r += 1) {
      const k = randomInt(1000, 9999)
      const t = await send(injectParam(req, style.make(k, true)))
      const f = await send(injectParam(req, style.make(k, false)))
      if (!t || !f) { pass = false; break }
      const simBaseTrue = responseSimilarity(baseA.body, t.body)
      const simTrueFalse = responseSimilarity(t.body, f.body)
      const statusDiverges = t.status === baseA.status && f.status !== t.status && f.status < 500
      const roundPass = t.status < 500 && f.status < 500 && simBaseTrue >= 0.9 && (simTrueFalse <= 0.75 || statusDiverges)
      rounds.push({ k, statusBase: baseA.status, statusTrue: t.status, statusFalse: f.status, simBaseTrue, simTrueFalse, roundPass })
      if (!roundPass) { pass = false; break }
    }
    const passed = pass && rounds.length === 2
    signals.push({ style: style.name, passed, rounds })
    if (passed) break
  }
  const quoteOne = await send(injectParam(req, `${baseValue}'`))
  const quoteTwo = await send(injectParam(req, `${baseValue}''`))
  const baselineDialect = dbErrorDialect(baseA.body)
  const errorDialect = quoteOne ? dbErrorDialect(quoteOne.body) : null
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
    summary = `Boolean differential (${String(passed.style)}) held across 2 randomized rounds: equal-comparison matches baseline, unequal-comparison diverges.`
    anomalies.push({ type: 'boolean_differential', style: passed.style, rounds: passed.rounds })
  }
  if (details.dbErrorDialect) {
    verdict = 'signal'
    summary = `${passed ? summary + ' ' : ''}${String(details.dbErrorDialect)} database error fingerprint on a stray quote.`
    anomalies.push({ type: 'db_error_fingerprint', dialect: details.dbErrorDialect })
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
    verdict: hitCount > 0 ? 'signal' : 'no_signal',
    summary: hitCount > 0
      ? `${hitCount} correlated out-of-band callback(s) received from the target for Guardian-minted canary tokens.`
      : 'No out-of-band callback was observed within the wait window.',
    details: { results, dnsListenerActive: info.dnsRunning },
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
      anomalies.push({ type: 'operator_type_divergence', operator: variant.name, status: ex.status })
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

async function diffGraphqlSurface(ctx: DiffContext): Promise<DiffOutcome> {
  const { req, send, anomalies } = ctx
  const gql = (query: string, persona?: string): InjectedRequest & { persona?: string } => {
    if (req.method === 'POST') {
      return { method: 'POST', pathAndQuery: req.pathAndQuery, body: JSON.stringify({ query }), headers: { 'Content-Type': 'application/json', ...(req.headers ?? {}) }, persona }
    }
    return { method: 'GET', pathAndQuery: setQueryParam(req.pathAndQuery, 'query', query), headers: req.headers, persona }
  }
  const parse = (body: string): { data?: Record<string, unknown>; errors?: Array<{ message?: string }> } | null => {
    try { return JSON.parse(body) as { data?: Record<string, unknown>; errors?: Array<{ message?: string }> } } catch { return null }
  }
  const typename = await send(gql('{__typename}'))
  if (!typename || !parse(typename.body)) return { verdict: 'inconclusive', summary: 'Endpoint did not return GraphQL JSON.', details: { status: typename?.status ?? null } }
  const introspection = await send(gql('{__schema{queryType{name} types{name kind}}}'))
  const suggestion = await send(gql('{__typenam}'))
  const alias = await send(gql('{a:__typename b:__typename c:__typename}'))
  const introData = introspection ? parse(introspection.body)?.data as { __schema?: { types?: unknown[] } } | undefined : undefined
  const introspectionEnabled = Boolean(introData?.__schema)
  const suggestionLeak = Boolean(suggestion && /did you mean/i.test(suggestion.body))
  const aliasKeys = alias ? Object.keys((parse(alias.body)?.data ?? {})).length : 0
  const details: Record<string, unknown> = {
    introspectionEnabled,
    typeCount: introData?.__schema?.types?.length ?? null,
    fieldSuggestionLeak: suggestionLeak,
    aliasBatchingAllowed: aliasKeys >= 3,
  }
  if (req.persona) {
    const anon = await send(gql('{__schema{queryType{name}}}'))
    const authed = await send(gql('{__schema{queryType{name}}}', req.persona))
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
  if (suggestionLeak) anomalies.push({ type: 'field_suggestion_leak' })
  if (aliasKeys >= 3) anomalies.push({ type: 'alias_batching_allowed', aliases: aliasKeys })
  return {
    verdict: anomalies.length > 0 ? 'signal' : 'no_signal',
    summary: anomalies.length > 0 ? 'GraphQL surface exposure indicators observed.' : 'No GraphQL exposure indicators observed.',
    details,
  }
}

async function diffAuthorizationMatrix(ctx: DiffContext): Promise<DiffOutcome> {
  const { req, runner, notes, anomalies } = ctx
  const method = req.method === 'POST' ? 'POST' : 'GET'
  const ids = (req.resourceIds ?? []).filter(i => /^[A-Za-z0-9_.:-]{1,128}$/.test(i)).slice(0, 10)
  if (!req.pathAndQuery.includes('{{id}}') || ids.length === 0) {
    return { verdict: 'inconclusive', summary: 'authz_matrix needs a {{id}} placeholder in pathAndQuery and resourceIds.', details: {} }
  }
  const actors: Array<{ actor: string; persona?: string; headers?: Record<string, string> }> = []
  if (req.ownerPersona) actors.push({ actor: 'owner', persona: req.ownerPersona })
  if (req.otherPersona) actors.push({ actor: 'other_persona', persona: req.otherPersona })
  if (req.includeAnonymous !== false) actors.push({ actor: 'anonymous' })
  if (req.includeHeaderBypass !== false) {
    actors.push({ actor: 'header_bypass', headers: { 'X-Original-URL': '/', 'X-Rewrite-URL': '/', 'X-Middleware-Subrequest': 'middleware:middleware:middleware:middleware:middleware' } })
  }
  const matrix: Array<Record<string, unknown>> = []
  for (const id of ids) {
    const path = req.pathAndQuery.replaceAll('{{id}}', encodeURIComponent(id))
    let ownerEx: BrokerExchangeResult | null = null
    for (const a of actors) {
      const res = await runner.send({
        origin: ctx.origin, method, pathAndQuery: path,
        headers: { ...(req.headers ?? {}), ...(a.headers ?? {}), ...(a.actor === 'header_bypass' ? { 'X-Original-URL': path, 'X-Rewrite-URL': path } : {}) },
        persona: a.persona,
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
      matrix.push({
        resourceId: id, actor: a.actor, status: res.ex.status, bodyBytes: res.ex.bodyBytes,
        bodySha256: res.ex.bodySha256, similarityToOwner: sim, accessible: ok2xx,
      })
      if (a.actor !== 'owner' && ok2xx && (sim === null || sim >= 0.85)) {
        anomalies.push({ type: 'unauthorized_access', resourceId: id, actor: a.actor, status: res.ex.status, similarityToOwner: sim })
      }
    }
  }
  return {
    verdict: anomalies.length > 0 ? 'signal' : 'no_signal',
    summary: anomalies.length > 0
      ? 'A non-owner actor received an owner-equivalent response; build an http_chain Replay Spec from this matrix.'
      : 'Non-owner actors were denied or received different responses.',
    details: { matrix, suggestedReplayKind: 'http_chain' },
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
  const max = clampMaxRequests(req.maxRequests ?? 60)
  const runner = new ProbeRunner(broker, grant, signal, max, req.persona, req.onExchange)
  const notes: string[] = []
  const anomalies: Array<Record<string, unknown>> = []
  let outcome: DiffOutcome = { verdict: 'inconclusive', summary: 'Probe did not run.', details: {} }

  if (!safeProbePath(req.pathAndQuery.split('?')[0].replace(/\{\{id\}\}/g, 'x'))) {
    throw new BrokerDenied('pathAndQuery is invalid or blocked by the destructive-payload denylist.')
  }

  const send = async (r: InjectedRequest & { persona?: string }): Promise<BrokerExchangeResult | null> => {
    const res = await runner.send({ origin, ...r })
    if (!res.ok) {
      notes.push(`${r.method} ${r.pathAndQuery.slice(0, 80)} -> ${res.kind}: ${res.message.slice(0, 120)}`)
      if (res.kind === 'approval') runner.stop('approval_required')
      return null
    }
    runner.stage(res.ex)
    return res.ex
  }
  const ctx: DiffContext = { req, origin, runner, notes, anomalies, send }

  try {
    switch (req.probeClass) {
      case 'sqli_boolean': outcome = await diffBooleanDifferential(ctx); break
      case 'ssti_math': outcome = await diffTemplateMath(ctx); break
      case 'ssrf_canary': outcome = await diffCanaryCallback(ctx, canaryBroker, grant, signal); break
      case 'nosqli_type': outcome = await diffOperatorTypes(ctx); break
      case 'path_traversal_benign': outcome = await diffPathNormalization(ctx); break
      case 'graphql_audit': outcome = await diffGraphqlSurface(ctx); break
      case 'authz_matrix': outcome = await diffAuthorizationMatrix(ctx); break
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
  return text.replace(/\{\{(rand|guardian_canary_http|guardian_canary_dns)\}\}/g, (_m, name: string) => {
    const value = vars[name] ?? ''
    return encode ? encodeURIComponent(value) : value
  })
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
  const selection = selectSafeTemplates(loaded.templates, {
    techTags: req.techFingerprint, templateIds: req.templateIds, tier, maxTemplates: limit,
  })
  const matches: TemplateMatch[] = []
  const suppressed: RunSafeTemplatesResult['suppressed'] = []
  const skipped = [...selection.skipped]
  let templatesRun = 0
  let calibration: SurfaceCalibration | null = null

  try {
    const cal = await calibrateOrigin(runner, origin)
    calibration = cal
    const runId = req.runId ?? 'surface-engine'

    await runner.pool(selection.selected, async template => {
      const vars: Record<string, string> = { rand: randToken(8), guardian_canary_http: '', guardian_canary_dns: '' }
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

      matches.push({
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
        exchangeId: runner.stage(ex),
        note: 'Template match is a lead only; confirm via a Declarative Replay Spec (never auto-confirmed).',
      })
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
