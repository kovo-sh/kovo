import { randomUUID } from 'node:crypto'
import { BrokerApprovalRequired, BrokerCircuitOpen, BrokerDenied } from './broker.ts'
import type { BrokerExchangeResult, BrokerHttpRequest, Grant, RequestBroker } from './broker.ts'
import type { CanaryBroker } from './canary-broker.ts'
import type { HttpMethod } from '../domain.ts'
import { containsDestructivePayload } from '../replay-spec.ts'
import { loadSafeTemplates, selectSafeTemplates, selectTemplateIdsForCves } from '../templates/loader.ts'
import type { SafeTemplate, TemplateMatcher } from '../templates/loader.ts'
import type { Store } from './store.ts'
// Probe families live in ./probes and are dispatched through the static registry.
import { clampMaxRequests, escapeXmlText, forbiddenParamHeaders, isPrivateOrLoopbackHost, randToken, responseSimilarity, setQueryParam, sha8 } from './probes/context.ts'
import type { DiffContext, DiffOutcome, DifferentialResult, InjectedRequest, ProbeDifferentialRequest, StopReason, SurfaceParamLocation } from './probes/context.ts'
import { probeModuleFor } from './probes/registry.ts'
import { validateXxeCustomPayload } from './probes/xxe.ts'
import { resolveGraphqlArgQuery } from './probes/graphql.ts'

export { appendCacheBuster, clampMaxRequests, dbErrorDialect, defaultSurfaceMaxRequests, escapeXmlAttr, escapeXmlText, injectUniversalParam, normalizeEphemeralNoise, responseSimilarity, surfaceMaxRequestsCeiling, surfaceParamLocations } from './probes/context.ts'
export type { DifferentialProbeClass, DifferentialResult, ProbeDifferentialRequest, StopReason, SurfaceParamLocation, UniversalInjectInput } from './probes/context.ts'
export { analyzeXssReflection } from './probes/xss.ts'
export type { ReflectionAnalysis, ReflectionContext } from './probes/xss.ts'
export { parseGraphqlIntrospection, parseGraphqlSdl } from './probes/graphql.ts'
export type { GraphqlFieldArg, GraphqlFieldDef, GraphqlParsedSchema } from './probes/graphql.ts'
export { redirectHostOf, redirectTargetOf } from './probes/open-redirect.ts'

export const surfaceMaxConcurrency = 2
export const maxWorkerPaths = 120
export const maxParamCandidates = 200
const probeBodyCap = 128 * 1024
const calibrationBodyKeep = 32 * 1024

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

function safeProbePath(path: string): boolean {
  return path.startsWith('/') && !path.startsWith('//') && path.length <= 512 && !/[\r\n\0\\]/.test(path) && !containsDestructivePayload(path)
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
      // Carry the differential class into the brokered request. A 5xx provoked by an
      // injection/parser payload is target evidence, so the broker must count it separately from
      // real target unavailability (it exempts that class from the availability circuit). The
      // class used to be dropped here, so a single payload-induced 5xx storm could open the origin
      // circuit and pause a healthy run.
      probeClass: r.probeClass ?? req.probeClass,
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
    // One module per vulnerability family; the registry owns exclusive class dispatch.
    const mod = probeModuleFor(req.probeClass)
    if (!mod) {
      outcome = { verdict: 'inconclusive', summary: `No probe module owns ${req.probeClass}.`, details: {} }
    } else {
      outcome = await mod.run(ctx, { grant, canaryBroker, signal })
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
