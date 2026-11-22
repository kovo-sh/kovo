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
import { probeDifferential } from '../src/server/surface-engine.ts'
import type { DifferentialProbeClass, DifferentialResult, ProbeDifferentialRequest, SurfaceParamLocation } from '../src/server/surface-engine.ts'
import type { Store } from '../src/server/store.ts'
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
}

export interface HypothesisPlan {
  hypotheses: Hypothesis[]
  /** Endpoint paths where a param was skipped because the profile cannot emit its encoding. */
  encodingSkips: Array<{ path: string; location: string }>
}

const idName = /(^|[_-])(id|uid|uuid|sku|slug|key|ref)$/i
const urlName = /(url|uri|link|callback|webhook|redirect|next|dest|target|feed|image|src|endpoint)/i
const accountPath = /(profile|account|\/me\b|settings|user|org|tenant|team|member)/i
const cacheablePath = /(static|asset|public|catalog|account|profile|\/me\b|settings|dashboard|billing|home|page|news|docs|css|js|export)/i
const xmlPath = /(xml|import|soap|upload|feed|sitemap|saml|parse|svg|rss)/i
const graphqlPath = /graphql/i
const workflowPath = /(order|checkout|cart|payment|workflow|step|confirm|refund|invoice)/i
const placeholderSeg = /^(:[A-Za-z0-9_]+|\{[^}]+\}|\[[^\]]+\])$/

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

  for (const ep of endpoints) {
    const method = ep.method.toUpperCase()
    const isGet = method === 'GET' || method === 'HEAD'
    const pathHasPlaceholder = hasPathPlaceholder(ep.path)
    const params = ep.params.filter(p => !p.isCsrf && p.location !== 'cookie')

    // Object-level authorization: id-bearing paths or id-named parameters.
    const idParam = params.find(p => p.isObjectId || idName.test(p.name))
    if (pathHasPlaceholder || (idParam && idParam.location === 'query')) {
      add({ endpoint: ep, probeClass: 'authz_matrix', method: isGet ? 'GET' : writeMethod(ep) })
    }

    for (const p of params) {
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
      if (caps.newProbeClasses) add({ endpoint: ep, probeClass: 'xss_context', param: p, location, method: pMethod })
      if (urlName.test(p.name)) add({ endpoint: ep, probeClass: 'ssrf_canary', param: p, location, method: pMethod })
    }

    if (isGet && !pathHasPlaceholder && ep.path.split('/').filter(Boolean).length >= 2) {
      add({ endpoint: ep, probeClass: 'path_traversal_benign', method: 'GET' })
    }
    if (graphqlPath.test(ep.path) || ep.source === 'graphql') add({ endpoint: ep, probeClass: 'graphql_audit', method: 'POST' })
    if (workflowPath.test(ep.path)) add({ endpoint: ep, probeClass: 'workflow_invariant', method: isGet ? 'GET' : writeMethod(ep) })

    if (caps.newProbeClasses) {
      if (accountPath.test(ep.path) && !pathHasPlaceholder) add({ endpoint: ep, probeClass: 'mass_assignment', method: isGet ? 'PATCH' : writeMethod(ep) })
      if (isGet && !pathHasPlaceholder && params.length === 0 && cacheablePath.test(ep.path)) {
        add({ endpoint: ep, probeClass: 'cache_poison_deception', method: 'GET' })
      }
      if (isGet && !pathHasPlaceholder && params.length === 0 && caps.authMutation) {
        add({ endpoint: ep, probeClass: 'auth_protocol_audit', method: 'GET' })
      }
      if (xmlPath.test(ep.path) && !isGet && !params.some(p => p.location === 'xml')) {
        add({ endpoint: ep, probeClass: 'xxe_canary', method: writeMethod(ep) })
      }
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
}

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

function authzIds(env: ProbeEnv): string[] {
  const ids = [...env.personaUserIds, '1', '2', '3']
  return [...new Set(ids)].filter(i => /^[A-Za-z0-9_.:-]{1,128}$/.test(i)).slice(0, 8)
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
    resourceIds: authzIds(env),
    runId: env.runId,
    storage: env.storage,
    ...(env.caps.sessionAndCsrf ? { session: env.session } : {}),
  }
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
  let req: ProbeDifferentialRequest
  switch (h.probeClass) {
    case 'authz_matrix': req = authzRequest(h, env); break
    case 'ssrf_canary':
      req = buildProbeRequest(h, env, { ssrfParams: h.param ? [h.param.name] : [], waitMs: 2500 }); break
    case 'xxe_canary': req = buildProbeRequest(h, env, { waitMs: 2500 }); break
    case 'mass_assignment': req = buildProbeRequest(h, env, { paramLocation: 'json', jsonBody: {} }); break
    case 'cache_poison_deception': case 'auth_protocol_audit': case 'path_traversal_benign': case 'workflow_invariant':
      req = buildProbeRequest(h, env); delete req.param; delete req.paramLocation; break
    default: req = buildProbeRequest(h, env)
  }
  if (h.probeClass === 'auth_protocol_audit') {
    req.persona = env.jwtPersona ?? env.owner
    req.method = 'GET'
  }
  if (h.probeClass === 'graphql_audit') req.method = 'POST'
  req.onExchange = ex => { watch(ex) }
  try {
    const res: DifferentialResult = await probeDifferential(req, env.broker, env.grant, env.canaryBroker, env.signal)
    out.verdict = res.verdict
    out.anomalies = res.anomalies
    out.details = res.details
    out.requests = res.requestsSent
    out.summary = res.summary
    if (res.stoppedReason === 'approval_required' || res.stoppedReason === 'denied') out.tierBlocked = true
  } catch (err) {
    if (err instanceof BrokerApprovalRequired) out.tierBlocked = true
    else if (err instanceof BrokerDenied && /tier/i.test(err.message)) out.tierBlocked = true
    out.verdict = 'error'
    out.error = err instanceof Error ? err.message : String(err)
  }
  return out
}
