/**
 * Generic hypothesis formation and probe execution for the recall benchmark.
 *
 * Nothing here knows about any benchmark challenge: hypotheses are derived only from the
 * endpoints/params Guardian's recon discovered (names, locations, path shapes, methods), then
 * handed to the real `probeDifferential` engine. Profile capabilities decide which discovery
 * strategies, parameter encodings and probe classes are available.
 */
import { BrokerApprovalRequired, BrokerDenied } from '../src/server/broker.ts'
import type { BrokerExchangeResult, Grant, RequestBroker } from '../src/server/broker.ts'
import type { CanaryBroker } from '../src/server/canary-broker.ts'
import { analyzeXssReflection, injectUniversalParam, probeDifferential, responseSimilarity } from '../src/server/surface-engine.ts'
import type { DifferentialProbeClass, DifferentialResult, ProbeDifferentialRequest, SurfaceParamLocation } from '../src/server/surface-engine.ts'
import type { Store } from '../src/server/store.ts'
import { mineBaselines, mineGraphqlQuery, mineSeedQuery, mineXmlTemplate } from './benchmark-corpus.ts'
import type { Corpus } from './benchmark-corpus.ts'
import type { BenchmarkProfileMode } from './benchmark-core.ts'

export interface ProfileCaps {
  mode: BenchmarkProfileMode
  /** Phase-0 recon (spec/JS/HTML/GraphQL discovery) vs. plain wordlist probing. */
  phase0Recon: boolean
  locations: ReadonlySet<string>
  newProbeClasses: boolean
  sessionAndCsrf: boolean
  authMutation: boolean
  timeDiff: boolean
  inlineRetries: number
  tier: 2 | 3
}

export function profileCaps(mode: BenchmarkProfileMode): ProfileCaps {
  if (mode === 'v3-baseline') {
    return {
      mode, phase0Recon: false, locations: new Set(['query', 'json']), newProbeClasses: false,
      sessionAndCsrf: false, authMutation: false, timeDiff: false, inlineRetries: 0, tier: 2,
    }
  }
  return {
    mode, phase0Recon: true, locations: new Set(['query', 'json', 'form', 'path', 'header', 'xml', 'graphql_var']), newProbeClasses: true,
    sessionAndCsrf: true, authMutation: true, timeDiff: true, inlineRetries: 2, tier: 3,
  }
}

export interface DiscoveredParam { name: string; location: string; isObjectId: boolean; isCsrf: boolean }
export interface DiscoveredEndpoint { method: string; path: string; params: DiscoveredParam[]; source: string }

export type HypothesisClass = DifferentialProbeClass
export interface Hypothesis {
  key: string
  endpoint: DiscoveredEndpoint
  probeClass: HypothesisClass
  param?: DiscoveredParam
  location?: SurfaceParamLocation
  /** Method used for the probe/replay (body locations imply a write method). */
  method: 'GET' | 'POST' | 'PUT' | 'PATCH'
  /** Plant on a write endpoint, then re-read listing/detail routes for stored reflection. */
  secondOrder?: boolean
  readPaths?: string[]
  /** GET page whose XSS probe may need DOM interaction through the persisted browser. */
  browserEligible?: boolean
}

export interface HypothesisPlan {
  hypotheses: Hypothesis[]
  /** Endpoint paths where a param was skipped because the profile cannot emit its encoding. */
  encodingSkips: Array<{ path: string; location: string }>
}

const idName = /(^|[_-])(id|uid|uuid|sku|slug|key|ref)$/i
const urlName = /(url|uri|link|callback|webhook|redirect|next|dest|target|feed|image|src|endpoint)/i
const accountPath = /(profile|account|\/me\b|settings|user|org|tenant|team|member)/i
// Union of the M7B and discovery vocabularies; discovery's ranking + cap still decides the shortlist.
const cacheablePath = /(cache|static|asset|public|catalog|account|profile|\/me\b|settings|dashboard|billing|home|page|news|docs|content|media|banner|promo|shop|store|product|comment|css|js|export|summary|landing|index)/i
const oauthPath = /(oauth|authorize|\/auth\b|openid|oidc|sso|login\/callback)/i
const xmlPath = /(xml|import|soap|upload|feed|sitemap|saml|parse|svg|rss|wsdl)/i
const graphqlPath = /graphql/i
const workflowPath = /(order|checkout|cart|payment|workflow|step|confirm|refund|invoice)/i
const authishPath = /(oauth|authorize|openid|token|jwt|auth|session|login|sso|well-known)/i
/**
 * OAuth/OIDC/session protocol control parameters are not user-data sinks; running injection
 * matrices over them only burns budget. They stay recorded as surface, just not as inject targets.
 */
const protocolParam = /^(?:client[_-]?id|client[_-]?secret|redirect[_-]?uri|response[_-]?type|grant[_-]?type|scope|state|nonce|code|code[_-]?challenge|code[_-]?challenge[_-]?method|audience|prompt|login[_-]?hint|access[_-]?token|refresh[_-]?token|id[_-]?token|assertion|signature|sig|continue|return_to)$/i
const placeholderSeg = /^(:[A-Za-z0-9_]+|\{[^}]+\}|\[[^\]]+\])$/
const maxInjectionParamsPerEndpoint = 8
const maxCacheEndpoints = 5

export function hasPathPlaceholder(path: string): boolean {
  return path.split('/').some(seg => placeholderSeg.test(seg))
}

/** Replace path placeholders: the last one becomes `lastValue`, earlier ones become `otherValue`. */
export function fillPlaceholders(path: string, lastValue: string, otherValue = '1'): string {
  const segs = path.split('/')
  let last = -1
  segs.forEach((s, i) => { if (placeholderSeg.test(s)) last = i })
  return segs.map((s, i) => (placeholderSeg.test(s) ? (i === last ? lastValue : otherValue) : s)).join('/')
}

function writeMethod(ep: DiscoveredEndpoint): 'POST' | 'PUT' | 'PATCH' {
  const m = ep.method.toUpperCase()
  return m === 'PUT' || m === 'PATCH' ? m : 'POST'
}

function lastPathSegment(path: string): string {
  const parts = path.split('?')[0].split('/').filter(Boolean)
  return parts[parts.length - 1] ?? ''
}

/**
 * Candidate read routes for a stored/second-order check, derived only from the discovered surface:
 * the same path as a GET, sibling GET routes with the same resource tail, and prefix-stripped variants
 * (e.g. a write at /api/comments surfaces on /comments). Prefers short, non-API routes.
 */
function secondOrderReadPaths(writePath: string, getPaths: readonly string[]): string[] {
  const tail = lastPathSegment(writePath)
  const out = new Set<string>()
  if (getPaths.includes(writePath)) out.add(writePath)
  if (tail) {
    for (const p of getPaths) {
      if (lastPathSegment(p) === tail) out.add(p)
    }
  }
  const segs = writePath.split('/').filter(Boolean)
  for (let drop = 1; drop < Math.min(3, segs.length); drop += 1) {
    const variant = `/${segs.slice(drop).join('/')}`
    if (getPaths.includes(variant)) out.add(variant)
  }
  return [...out]
    .filter(p => p !== writePath || getPaths.includes(p))
    .sort((a, b) => {
      const api = (p: string) => (/^\/api\//i.test(p) ? 1 : 0)
      return api(a) - api(b) || a.split('/').filter(Boolean).length - b.split('/').filter(Boolean).length || a.localeCompare(b)
    })
    .slice(0, 3)
}

export function formHypotheses(endpoints: readonly DiscoveredEndpoint[], caps: ProfileCaps): HypothesisPlan {
  const hypotheses: Hypothesis[] = []
  const encodingSkips: Array<{ path: string; location: string }> = []
  const seen = new Set<string>()
  const add = (h: Omit<Hypothesis, 'key'>) => {
    const key = `${h.probeClass}|${h.endpoint.method}|${h.endpoint.path}|${h.param?.name ?? ''}|${h.location ?? ''}`
    if (seen.has(key)) return
    seen.add(key)
    hypotheses.push({ ...h, key })
  }

  const getPaths = [...new Set(endpoints.filter(e => e.method.toUpperCase() === 'GET' || e.method.toUpperCase() === 'HEAD').map(e => e.path))]
  const writeProbeSeen = new Set<string>()
  const cacheCandidates: DiscoveredEndpoint[] = []

  for (const ep of endpoints) {
    const method = ep.method.toUpperCase()
    const isGet = method === 'GET' || method === 'HEAD'
    const pathHasPlaceholder = hasPathPlaceholder(ep.path)
    const params = ep.params.filter(p => !p.isCsrf && p.location !== 'cookie')
    const injectParams = params.filter(p => !protocolParam.test(p.name)).slice(0, maxInjectionParamsPerEndpoint)
    const readPaths = !isGet ? secondOrderReadPaths(ep.path, getPaths) : []

    // Object-level authorization: id-bearing paths or id-named parameters.
    const idParam = params.find(p => p.isObjectId || idName.test(p.name))
    if (pathHasPlaceholder || (idParam && idParam.location === 'query')) {
      add({ endpoint: ep, probeClass: 'authz_matrix', method: isGet ? 'GET' : writeMethod(ep) })
    }

    for (const p of injectParams) {
      if (!caps.locations.has(p.location)) {
        encodingSkips.push({ path: ep.path, location: p.location })
        continue
      }
      const location = p.location as SurfaceParamLocation
      const pMethod: Hypothesis['method'] = location === 'query' || location === 'path' || location === 'header' ? (isGet ? 'GET' : writeMethod(ep)) : writeMethod(ep)
      add({ endpoint: ep, probeClass: 'sqli_boolean', param: p, location, method: pMethod })
      if (caps.timeDiff) add({ endpoint: ep, probeClass: 'sqli_time_diff', param: p, location, method: pMethod })
      if (location === 'xml' || xmlPath.test(ep.path)) {
        if (caps.newProbeClasses) add({ endpoint: ep, probeClass: 'xxe_canary', param: p, location, method: writeMethod(ep) })
      }
      if (idName.test(p.name) || p.isObjectId) continue
      add({ endpoint: ep, probeClass: 'ssti_math', param: p, location, method: pMethod })
      if (caps.newProbeClasses) {
        add({
          endpoint: ep, probeClass: 'xss_context', param: p, location, method: pMethod,
          ...(!isGet && (location === 'json' || location === 'form' || location === 'xml') && readPaths.length > 0
            ? { secondOrder: true, readPaths }
            : {}),
          ...(isGet && !pathHasPlaceholder && location === 'query' ? { browserEligible: true } : {}),
        })
      }
      if (urlName.test(p.name)) add({ endpoint: ep, probeClass: 'ssrf_canary', param: p, location, method: pMethod })
    }

    if (isGet && !pathHasPlaceholder && ep.path.split('/').filter(Boolean).length >= 2) {
      add({ endpoint: ep, probeClass: 'path_traversal_benign', method: 'GET' })
    }
    if (graphqlPath.test(ep.path) || ep.source === 'graphql') {
      const key = `graphql_audit|${ep.path}`
      if (!writeProbeSeen.has(key)) {
        writeProbeSeen.add(key)
        add({ endpoint: ep, probeClass: 'graphql_audit', method: 'POST' })
      }
    }
    if (workflowPath.test(ep.path)) add({ endpoint: ep, probeClass: 'workflow_invariant', method: isGet ? 'GET' : writeMethod(ep) })

    if (caps.newProbeClasses) {
      if (accountPath.test(ep.path) && !pathHasPlaceholder) {
        const key = `mass_assignment|${ep.path}|${writeMethod(ep)}`
        if (!writeProbeSeen.has(key)) {
          writeProbeSeen.add(key)
          add({ endpoint: ep, probeClass: 'mass_assignment', method: isGet ? 'PATCH' : writeMethod(ep) })
        }
      }
      const paramlessGet = isGet && !pathHasPlaceholder && params.length === 0
      if (paramlessGet && !graphqlPath.test(ep.path) && !/\.well-known\//i.test(ep.path)) {
        cacheCandidates.push(ep)
      }
      if (isGet && !pathHasPlaceholder && caps.authMutation && (params.length === 0 || authishPath.test(ep.path) || oauthPath.test(ep.path))) {
        add({ endpoint: ep, probeClass: 'auth_protocol_audit', method: 'GET' })
      }
      if (xmlPath.test(ep.path) && !isGet && !params.some(p => p.location === 'xml')) {
        add({ endpoint: ep, probeClass: 'xxe_canary', method: writeMethod(ep) })
      }
    }
  }

  if (caps.newProbeClasses) {
    // Cache probes are expensive (control + header matrix + victim verifies), so rank candidate
    // routes by cache-ish semantics and take a bounded top slice. Response cache headers are not
    // available at hypothesis-formation time, so this stays a heuristic.
    const ranked = [...cacheCandidates].sort((a, b) => {
      const score = (e: DiscoveredEndpoint) => (cacheablePath.test(e.path) ? 2 : 0) + (e.path.split('/').filter(Boolean).length >= 2 ? 1 : 0)
      return score(b) - score(a) || a.path.length - b.path.length || a.path.localeCompare(b.path)
    })
    for (const ep of ranked.slice(0, maxCacheEndpoints)) {
      add({ endpoint: ep, probeClass: 'cache_poison_deception', method: 'GET' })
    }
  }
  return { hypotheses, encodingSkips }
}

// ---------------------------------------------------------------------------
// Probe execution
// ---------------------------------------------------------------------------

export interface ProbeEnv {
  origin: string
  broker: RequestBroker
  grant: Grant
  canaryBroker?: CanaryBroker
  storage: Store
  runId: string
  assignmentId?: string
  signal: AbortSignal
  caps: ProfileCaps
  owner?: string
  other?: string
  admin?: string
  viewer?: string
  /** Persona handle whose credential is a 3-segment JWT (for broker authMutation). */
  jwtPersona?: string
  personaUserIds: string[]
  session: string
  slowProbesLeft: number
  corpus?: Corpus
  ctxCache?: Map<string, ResolvedContext>
  /** Session jar ids already primed for cookies/CSRF tokens in this run. */
  primedSessions?: Set<string>
  /** Remaining persisted-browser attempts (SPA/DOM XSS chains). */
  browserAttemptsLeft?: number
}

/** Target-observed context (baseline value, XML/GraphQL shape, seed query) resolved for a hypothesis. */
export interface ResolvedContext { baseline?: string; xmlTemplate?: string; graphqlQuery?: string; seedQuery?: string }

export interface HypothesisOutcome {
  hyp: Hypothesis
  verdict: 'signal' | 'no_signal' | 'inconclusive' | 'error'
  anomalies: Array<Record<string, unknown>>
  details: Record<string, unknown>
  csrfRejected: boolean
  contextReset: boolean
  tierBlocked: boolean
  requests: number
  summary?: string
  error?: string
  ctx?: ResolvedContext
  /** Personas actually used for an authz_matrix probe (owner = privileged/control, other = probe). */
  pair?: { owner?: string; other?: string }
}

const csrfBody = /(csrf|xsrf|anti-?forgery|invalid token|token (missing|required|mismatch))/i
const sessionBody = /(session (expired|required|invalid|not found)|login required|please (log|sign) ?in|not authenticated|unauthenticated)/i

function siblingBody(h: Hypothesis): Record<string, unknown> | undefined {
  if (h.location !== 'json' && h.location !== 'form' && h.location !== 'graphql_var') return undefined
  const body: Record<string, unknown> = {}
  for (const p of h.endpoint.params) {
    if (p.name === h.param?.name || p.location !== h.location || p.isCsrf) continue
    body[p.name] = idName.test(p.name) || p.isObjectId ? '1' : 'guardian'
  }
  return body
}

export function probePathFor(h: Hypothesis): string {
  if (h.location === 'path') return h.endpoint.path.replace(/\{[^}]+\}|:[A-Za-z0-9_]+|\[[^\]]+\]/, '{{val}}')
  return hasPathPlaceholder(h.endpoint.path) ? fillPlaceholders(h.endpoint.path, '1') : h.endpoint.path
}

export function needsCsrf(h: Hypothesis): boolean {
  return h.endpoint.params.some(p => p.isCsrf)
}

export function buildProbeRequest(h: Hypothesis, env: ProbeEnv, extras: Partial<ProbeDifferentialRequest> = {}): ProbeDifferentialRequest {
  const body = siblingBody(h)
  const req: ProbeDifferentialRequest = {
    probeClass: h.probeClass,
    origin: env.origin,
    pathAndQuery: probePathFor(h),
    method: h.method,
    persona: env.owner,
    runId: env.runId,
    storage: env.storage,
    ...(env.assignmentId ? { assignmentId: env.assignmentId } : {}),
    ...(h.param ? { param: h.param.name, paramLocation: h.location } : {}),
    ...(h.param && h.location === 'json' && body ? { jsonBody: body } : {}),
    ...(h.param && h.location === 'form' && body ? { formBody: Object.fromEntries(Object.entries(body).map(([k, v]) => [k, String(v)])) } : {}),
    ...(h.param && h.location === 'graphql_var' && body ? { jsonBody: { variables: body } } : {}),
    ...(env.caps.sessionAndCsrf ? { session: env.session, csrfBind: needsCsrf(h) ? true : undefined } : {}),
    ...extras,
  }
  if (req.csrfBind === undefined) delete req.csrfBind
  return req
}

function authzIds(env: ProbeEnv, pathTemplate?: string): string[] {
  // Prefer concrete identifiers observed on the target's own surface, then numeric variants of the
  // persona user ids (common `user-1234` -> `1234` object-id convention), then the personas themselves.
  const mined = env.corpus && pathTemplate ? mineBaselines(env.corpus, 'id', pathTemplate) : []
  const derived = env.personaUserIds
    .map(id => id.replace(/^[A-Za-z]+[-_]/, ''))
    .filter((id, i) => id.length > 0 && id !== env.personaUserIds[i])
  // Known persona ids first (they are valid on persona-scoped routes), then their numeric variants,
  // then ids observed in the corpus and small integers.
  const ids = [...env.personaUserIds, ...derived, ...mined, '1', '2', '3']
  return [...new Set(ids)].filter(i => /^[A-Za-z0-9_.:-]{1,128}$/.test(i)).slice(0, 12)
}

export function authzRequest(h: Hypothesis, env: ProbeEnv, owner = env.owner, other = env.other): ProbeDifferentialRequest {
  const idSlot = hasPathPlaceholder(h.endpoint.path)
  const idParam = h.endpoint.params.find(p => (p.isObjectId || idName.test(p.name)) && p.location === 'query')
  const pathAndQuery = idSlot
    ? fillPlaceholders(h.endpoint.path, '{{id}}')
    : `${h.endpoint.path}?${idParam?.name ?? 'id'}={{id}}`
  return {
    probeClass: 'authz_matrix',
    origin: env.origin,
    pathAndQuery,
    method: h.method === 'GET' ? 'GET' : h.method,
    persona: owner,
    ownerPersona: owner,
    otherPersona: other,
    includeAnonymous: true,
    includeHeaderBypass: false,
    resourceIds: authzIds(env, h.endpoint.path),
    runId: env.runId,
    storage: env.storage,
    ...(env.caps.sessionAndCsrf ? { session: env.session } : {}),
  }
}

const sqliClasses = new Set<string>(['sqli_boolean', 'sqli_time_diff'])

async function resolveContext(h: Hypothesis, env: ProbeEnv): Promise<ResolvedContext> {
  const cache = (env.ctxCache ??= new Map())
  // Probe class is part of the key: different classes on the same endpoint need different context
  // (e.g. a path-traversal pass must not pre-populate an empty context for the auth-protocol pass).
  const key = `${h.probeClass}|${h.endpoint.method}|${h.endpoint.path}|${h.param?.name ?? ''}|${h.location ?? ''}`
  const hit = cache.get(key)
  if (hit) return hit
  const ctx: ResolvedContext = {}
  cache.set(key, ctx)
  const corpus = env.corpus
  if (!corpus) return ctx
  if (h.param && h.location === 'xml') ctx.xmlTemplate = mineXmlTemplate(corpus, h.param.name) ?? undefined
  if (h.param && h.location === 'graphql_var') ctx.graphqlQuery = mineGraphqlQuery(corpus, h.param.name) ?? undefined
  if (h.probeClass === 'auth_protocol_audit') {
    // OAuth/OIDC authorize URLs are discovered as links/JS literals; the query seed carries the
    // registered client_id/redirect_uri/scope the endpoint actually expects.
    const seed = mineSeedQuery(corpus, h.endpoint.path.split('?')[0])
    if (seed) ctx.seedQuery = seed
  }
  if (h.param && sqliClasses.has(h.probeClass)) {
    const candidates = mineBaselines(corpus, h.param.name, h.endpoint.path).slice(0, 5)
    if (candidates.length > 0) {
      const body = siblingBody(h)
      const send = async (value: string): Promise<BrokerExchangeResult | null> => {
        try {
          const inj = injectUniversalParam({
            pathAndQuery: probePathFor(h), param: h.param!.name, paramLocation: h.location!, value, method: h.method,
            ...(h.location === 'json' && body ? { jsonBody: body } : {}),
            ...(h.location === 'form' && body ? { formBody: Object.fromEntries(Object.entries(body).map(([k, v]) => [k, String(v)])) } : {}),
            ...(h.location === 'graphql_var' ? { jsonBody: { variables: body ?? {} } } : {}),
            ...(ctx.xmlTemplate ? { xmlTemplate: ctx.xmlTemplate } : {}),
            ...(ctx.graphqlQuery ? { graphqlQuery: ctx.graphqlQuery } : {}),
            ...(env.caps.sessionAndCsrf ? { session: env.session, csrfBind: needsCsrf(h) ? true : undefined } : {}),
          })
          return await env.broker.executeHttp({ origin: env.origin, persona: env.owner, followRedirects: false, ...inj }, env.grant, env.signal)
        } catch { return null }
      }
      const bogus = await send('zzguardianzz')
      for (const value of candidates) {
        const ex = await send(value)
        if (!ex || ex.status >= 500) continue
        if (!bogus || ex.status !== bogus.status || responseSimilarity(ex.body, bogus.body) < 0.9) { ctx.baseline = value; break }
      }
    }
  }
  return ctx
}

function shortToken(chars = 8): string {
  return Math.random().toString(36).slice(2, 2 + chars)
}

interface RawSendOptions {
  method: 'GET' | 'POST' | 'PUT' | 'PATCH'
  pathAndQuery: string
  body?: string
  headers?: Record<string, string>
  persona?: string
  session?: string
  csrfBind?: boolean
}

/** Broker-routed raw request used by multi-step (second-order / browser) checks. */
async function sendRaw(env: ProbeEnv, req: RawSendOptions): Promise<BrokerExchangeResult | null> {
  try {
    return await env.broker.executeHttp({
      origin: env.origin,
      method: req.method,
      pathAndQuery: req.pathAndQuery,
      ...(req.body !== undefined ? { body: req.body } : {}),
      ...(req.headers ? { headers: req.headers } : {}),
      ...(req.persona ? { persona: req.persona } : {}),
      ...(req.session ? { session: req.session } : {}),
      ...(req.csrfBind ? { csrfBind: true } : {}),
      ...(env.runId ? { runId: env.runId } : {}),
      ...(env.assignmentId ? { assignmentId: env.assignmentId } : {}),
      followRedirects: false,
      timeoutMs: 8_000,
    }, env.grant, env.signal)
  } catch {
    return null
  }
}

/**
 * CSRF/session priming: fetch the entry page (and the GET-able target) through the same broker session
 * jar before the first write probe, so Set-Cookie and hidden/meta/JSON CSRF tokens are bound.
 */
async function primeSessionOnce(h: Hypothesis, env: ProbeEnv): Promise<number> {
  if (!env.caps.sessionAndCsrf) return 0
  env.primedSessions ??= new Set<string>()
  if (env.primedSessions.has(env.session)) return 0
  env.primedSessions.add(env.session)
  const paths = new Set<string>(['/'])
  if (h.method === 'GET') paths.add(h.endpoint.path)
  let sent = 0
  for (const p of paths) {
    if (env.signal.aborted) break
    const ex = await sendRaw(env, {
      method: 'GET', pathAndQuery: p,
      persona: env.owner, session: env.session, csrfBind: needsCsrf(h),
    })
    if (ex) sent += 1
  }
  return sent
}

interface MultiStepResult {
  hit: boolean
  anomalies: Array<Record<string, unknown>>
  details: Record<string, unknown>
  requests: number
  summary?: string
}

/** Plant a marker through the write endpoint, then re-read candidate listing/detail routes. */
async function runSecondOrderCheck(
  h: Hypothesis,
  env: ProbeEnv,
  watch: (ex: BrokerExchangeResult) => void,
): Promise<MultiStepResult> {
  const result: MultiStepResult = { hit: false, anomalies: [], details: {}, requests: 0 }
  const param = h.param
  if (!param || !h.location || !h.readPaths?.length) return result
  const marker = `gxss${shortToken(8)}`
  const payload = `${marker}"'<b>`
  const body = siblingBody(h)
  const injected = injectUniversalParam({
    pathAndQuery: probePathFor(h),
    param: param.name,
    paramLocation: h.location,
    value: payload,
    method: h.method,
    jsonBody: h.location === 'json' ? body : undefined,
    formBody: h.location === 'form' ? Object.fromEntries(Object.entries(body ?? {}).map(([k, v]) => [k, String(v)])) : undefined,
    session: env.caps.sessionAndCsrf ? env.session : undefined,
    csrfBind: env.caps.sessionAndCsrf && needsCsrf(h) ? true : undefined,
    runId: env.runId,
    ...(env.assignmentId ? { assignmentId: env.assignmentId } : {}),
  })
  const writeEx = await sendRaw(env, {
    method: (injected.method === 'GET' ? 'POST' : injected.method) as RawSendOptions['method'],
    pathAndQuery: injected.pathAndQuery,
    ...(injected.body !== undefined ? { body: injected.body } : {}),
    ...(injected.headers ? { headers: injected.headers } : {}),
    persona: env.owner,
    ...(injected.session ? { session: injected.session } : {}),
    ...(injected.csrfBind ? { csrfBind: true } : {}),
  })
  result.requests += 1
  if (writeEx) watch(writeEx)
  result.details.writeStatus = writeEx?.status ?? null

  const reads: Array<Record<string, unknown>> = []
  const reflectedOnly: Array<Record<string, unknown>> = []
  for (const readPath of h.readPaths.slice(0, 3)) {
    if (env.signal.aborted) break
    const readEx = await sendRaw(env, {
      method: 'GET', pathAndQuery: readPath,
      persona: env.owner,
      session: env.caps.sessionAndCsrf ? env.session : undefined,
    })
    result.requests += 1
    if (!readEx) continue
    watch(readEx)
    const analysis = analyzeXssReflection(readEx.body, readEx.mediaType, marker)
    reads.push({
      readPath, status: readEx.status, reflected: analysis.reflected,
      context: analysis.context, unencodedChars: analysis.unencodedChars,
      mediaType: analysis.mediaType, exploitable: analysis.exploitable,
    })
    if (analysis.exploitable) {
      result.hit = true
      result.anomalies.push({
        type: 'second_order_xss',
        plantPath: h.endpoint.path,
        plantParam: param.name,
        plantLocation: h.location,
        readPath,
        context: analysis.context,
        unencodedChars: analysis.unencodedChars,
        mediaType: analysis.mediaType,
        suggestedReplayKind: 'http_chain',
      })
      break
    }
    if (analysis.reflected) {
      reflectedOnly.push({ readPath, context: analysis.context, mediaType: analysis.mediaType })
    }
  }
  result.details.reads = reads
  if (!result.hit && reflectedOnly.length > 0) result.details.storedReflection = reflectedOnly
  return result
}

/**
 * Persisted-browser fallback for DOM XSS: only launched when the rendered page actually contains a
 * DOM sink plus fillable controls, then fill + click through the page's own handlers while the sink
 * hook watches for the canary. Uses the existing ScopedBrowser backend.
 */
async function runBrowserChainCheck(
  h: Hypothesis,
  env: ProbeEnv,
  watch: (ex: BrokerExchangeResult) => void,
): Promise<MultiStepResult> {
  const result: MultiStepResult = { hit: false, anomalies: [], details: {}, requests: 0 }
  if ((env.browserAttemptsLeft ?? 3) <= 0) {
    result.details.skipped = 'browser_budget'
    return result
  }
  const pageEx = await sendRaw(env, {
    method: 'GET', pathAndQuery: h.endpoint.path,
    persona: env.owner,
    session: env.caps.sessionAndCsrf ? env.session : undefined,
  })
  result.requests += 1
  if (!pageEx) return result
  watch(pageEx)
  const html = pageEx.body
  if (!/<input\b/i.test(html) || !/<button\b[^>]*\bid\s*=/i.test(html) || !/\b(?:innerHTML|outerHTML|document\.write)\b/i.test(html)) {
    result.details.skipped = 'not_interactive_dom'
    return result
  }
  const attr = (attrs: string, name: string): string | null => {
    const m = new RegExp(`\\b${name}\\s*=\\s*(?:"([^"]*)"|'([^']*)'|([^\\s>]+))`, 'i').exec(attrs)
    return (m?.[1] ?? m?.[2] ?? m?.[3] ?? null)
  }
  const marker = `gxss${shortToken(8)}`
  const fillValue = `${marker}<b>`
  const fills: Array<{ type: 'fill'; selector: string; value: string }> = []
  for (const m of html.matchAll(/<input\b([^>]*)>/gi)) {
    const attrs = m[1]
    const type = (attr(attrs, 'type') ?? '').toLowerCase()
    if (/^(?:hidden|submit|button|reset|checkbox|radio|file|image)$/.test(type)) continue
    const id = attr(attrs, 'id')
    const name = attr(attrs, 'name')
    const selector = id ? `#${id.trim()}` : name ? `[name="${name.trim()}"]` : null
    if (!selector) continue
    fills.push({ type: 'fill', selector, value: fillValue })
    if (fills.length >= 2) break
  }
  const clicks: Array<{ type: 'click'; selector: string }> = []
  for (const m of html.matchAll(/<button\b([^>]*)>/gi)) {
    const id = attr(m[1], 'id')
    if (id) clicks.push({ type: 'click', selector: `#${id.trim()}` })
    if (clicks.length >= 4) break
  }
  if (fills.length === 0 || clicks.length === 0) {
    result.details.skipped = 'no_actions'
    return result
  }
  env.browserAttemptsLeft = (env.browserAttemptsLeft ?? 3) - 1
  try {
    const { ScopedBrowser } = await import('../src/server/scoped-browser.ts')
    const browser = new ScopedBrowser(env.broker, { storage: env.storage })
    const visit = await browser.visitPage({
      origin: env.origin,
      pathAndQuery: h.endpoint.path,
      persona: env.owner,
      ...(env.caps.sessionAndCsrf ? { session: env.session } : {}),
      ...(env.runId ? { runId: env.runId } : {}),
      ...(env.assignmentId ? { assignmentId: env.assignmentId } : {}),
      canaryToken: marker,
      enableSinkHook: true,
      checkKind: 'dom_xss',
      actions: [...fills, ...clicks],
      waitAfterLoadMs: 800,
      timeoutMs: 20_000,
    }, env.grant, AbortSignal.any([env.signal, AbortSignal.timeout(25_000)]))
    result.requests += visit.exchanges.length
    for (const ex of visit.exchanges) watch(ex)
    const sinkHit = visit.domSinkTraces.find(t => t.containsCanary)
    result.details = {
      actions: [...fills.map(f => `fill ${f.selector}`), ...clicks.map(c => `click ${c.selector}`)],
      canaryTriggered: visit.canaryCheck.triggered,
      canaryDetail: visit.canaryCheck.detail,
      sink: sinkHit?.sink ?? null,
      sinkPreview: sinkHit?.preview?.slice(0, 160) ?? null,
    }
    if (visit.canaryCheck.triggered || sinkHit) {
      result.hit = true
      result.anomalies.push({
        type: 'dom_xss_sink',
        path: h.endpoint.path,
        sink: sinkHit?.sink ?? 'dom',
        actions: result.details.actions,
        canaryTriggered: true,
        suggestedReplayKind: 'browser_chain',
      })
    }
  } catch (err) {
    result.details.browserError = err instanceof Error ? err.message.slice(0, 200) : String(err)
  }
  return result
}

export async function runHypothesis(h: Hypothesis, env: ProbeEnv, onExchange: (ex: BrokerExchangeResult) => void): Promise<HypothesisOutcome> {
  const out: HypothesisOutcome = {
    hyp: h, verdict: 'inconclusive', anomalies: [], details: {}, csrfRejected: false, contextReset: false, tierBlocked: false, requests: 0,
  }
  const watch = (ex: BrokerExchangeResult) => {
    onExchange(ex)
    if ((ex.status === 403 || ex.status === 400 || ex.status === 419) && csrfBody.test(ex.body)) out.csrfRejected = true
    if ((ex.status === 401 || ex.status === 403 || ex.status === 440) && sessionBody.test(ex.body)) out.contextReset = true
  }

  // Prime the session jar before write probes so cookies + CSRF tokens discovered on the entry page
  // are available to the broker's csrfBind injection.
  if (h.method !== 'GET') out.requests += await primeSessionOnce(h, env)

  const ctx = await resolveContext(h, env)
  out.ctx = ctx
  let req: ProbeDifferentialRequest
  switch (h.probeClass) {
    case 'authz_matrix': {
      let owner = env.owner
      let other = env.other
      if (/(admin|internal|manage|staff|flag|role|permission)/i.test(h.endpoint.path) && env.admin && (env.viewer ?? env.other)) { owner = env.admin; other = env.viewer ?? env.other }
      out.pair = { owner, other }
      req = authzRequest(h, env, owner, other)
      break
    }
    case 'ssrf_canary':
      req = buildProbeRequest(h, env, { ssrfParams: h.param ? [h.param.name] : [], waitMs: 2500 }); break
    case 'xxe_canary': req = buildProbeRequest(h, env, { waitMs: 2500 }); break
    case 'mass_assignment': req = buildProbeRequest(h, env, { paramLocation: 'json', jsonBody: {} }); break
    case 'cache_poison_deception': case 'auth_protocol_audit': case 'path_traversal_benign': case 'workflow_invariant':
      req = buildProbeRequest(h, env); delete req.param; delete req.paramLocation; break
    default: req = buildProbeRequest(h, env)
  }
  if (h.param) {
    if (ctx.baseline && sqliClasses.has(h.probeClass)) req.baselineValue = ctx.baseline
    if (ctx.xmlTemplate && h.location === 'xml') req.xmlTemplate = ctx.xmlTemplate
    if (ctx.graphqlQuery && h.location === 'graphql_var') req.graphqlQuery = ctx.graphqlQuery
  }
  if (h.probeClass === 'auth_protocol_audit') {
    req.persona = env.jwtPersona ?? env.owner
    req.method = 'GET'
    if (ctx.seedQuery) req.pathAndQuery = `${h.endpoint.path.split('?')[0]}?${ctx.seedQuery}`
  }
  if (h.probeClass === 'graphql_audit') req.method = 'POST'
  req.onExchange = ex => { watch(ex) }
  try {
    const res: DifferentialResult = await probeDifferential(req, env.broker, env.grant, env.canaryBroker, env.signal)
    out.verdict = res.verdict
    out.anomalies = res.anomalies
    out.details = res.details
    out.requests += res.requestsSent
    out.summary = res.summary
    if (res.stoppedReason === 'approval_required' || res.stoppedReason === 'denied') out.tierBlocked = true
  } catch (err) {
    if (err instanceof BrokerApprovalRequired) out.tierBlocked = true
    else if (err instanceof BrokerDenied && /tier/i.test(err.message)) out.tierBlocked = true
    out.verdict = 'error'
    out.error = err instanceof Error ? err.message : String(err)
  }

  // Second-order (stored) verification: only after an inconclusive/negative first-order probe.
  if (h.secondOrder && !out.tierBlocked && out.verdict !== 'signal' && !env.signal.aborted) {
    const stored = await runSecondOrderCheck(h, env, watch)
    out.requests += stored.requests
    out.details = { ...out.details, secondOrder: stored.details }
    if (stored.hit) {
      out.verdict = 'signal'
      out.anomalies = [...out.anomalies, ...stored.anomalies]
      out.summary = 'Stored marker planted via the write endpoint surfaced unencoded on a downstream read route.'
    }
  }

  // Browser-dependent DOM XSS: only when a GET page reflection probe did not already signal.
  if (h.browserEligible && h.probeClass === 'xss_context' && !out.tierBlocked && out.verdict !== 'signal' && !env.signal.aborted) {
    const dom = await runBrowserChainCheck(h, env, watch)
    out.requests += dom.requests
    out.details = { ...out.details, browserChain: dom.details }
    if (dom.hit) {
      out.verdict = 'signal'
      out.anomalies = [...out.anomalies, ...dom.anomalies]
      out.summary = 'Canary reached an executable DOM sink after scripted interaction on a rendered page.'
    }
  }
  return out
}
