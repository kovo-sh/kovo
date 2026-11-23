/**
 * In-product deterministic closed loop.
 *
 * The benchmark pipeline proved that risk-ranked differential probing plus declarative replay
 * verification can find real vulnerabilities without a model. This module moves that loop into the
 * product engine: it risk-ranks the discovered surface, enumerates generic hypotheses from route
 * and parameter shapes, harvests identifiers/fields from the target's own responses, runs the
 * benign differential probes from `surface-engine.ts`, synthesizes identifier-bound
 * `DeclarativeReplaySpec`s, and lets the normal `verifyReplaySpec` decide. Only
 * ReplayVerifier-confirmed findings are handed to the persistence callback; signals that do not
 * replay are emitted as leads (facts), never as findings.
 *
 * Everything is bounded by a request cap, a wall-clock cap (inside the run budget), the run's
 * capability tier, assignment scope and the broker's RPS/destructive guards.
 */
import type { BrokerExchangeResult, Grant, RequestBroker } from './broker.ts'
import type { CanaryBroker } from './canary-broker.ts'
import { declarativeReplaySpecSchema } from '../replay-spec.ts'
import type { DeclarativeReplaySpec } from '../replay-spec.ts'
import { probeDifferential, responseSimilarity } from './surface-engine.ts'
import type { DifferentialProbeClass, DifferentialResult, ProbeDifferentialRequest, SurfaceParamLocation } from './surface-engine.ts'
import { verifyReplaySpec } from './replay-verifier.ts'
import type { ReplayVerificationResult } from './replay-verifier.ts'
import type { ScopedBrowser } from './scoped-browser.ts'
import { normalizeEndpointTemplate } from './dedupe.ts'
import type { Store } from './store.ts'
import type { WorkerBackend } from './worker-backend.ts'
import { synthesizeEngineSpecs, vulnClassOfSpec } from './deterministic-specs.ts'
import type { EngineEndpoint, EngineHypothesis, EngineParam, SynthesizedEngineSpec } from './deterministic-specs.ts'

export type { EngineEndpoint, EngineHypothesis, EngineParam } from './deterministic-specs.ts'

export const defaultEngineMaxRequests = 1800
export const defaultEngineMaxDurationMs = 240_000
export const defaultEngineMaxEndpoints = 120
export const defaultEngineMaxHypotheses = 120
export const defaultEnginePerProbeRequests = 28

export const engineDisableEnv = 'GUARDIAN_DETERMINISTIC_ENGINE'

/**
 * Conventional noun/action route wordlists (e.g. `/api/tokens`, `/api/admin/users`) are a local-lab
 * convenience: they only match when the target happens to use the same English nouns as the list.
 * They stay ON by default for local-lab compatibility, but a run can turn them OFF so capability is
 * measured from discovered/declared surface only. The switch never changes what is probed on a route
 * the target itself exposed; it only drops endpoints whose sole source is that wordlist.
 */
export const conventionalWordlistEnv = 'GUARDIAN_CONVENTIONAL_WORDLIST'

export function conventionalWordlistEnabled(env: NodeJS.ProcessEnv = process.env): boolean {
  const raw = env[conventionalWordlistEnv]
  if (raw === undefined) return true
  const value = raw.trim().toLowerCase()
  if (value === '') return true
  return !(value === '0' || value === 'off' || value === 'false' || value === 'no')
}

/** Endpoints the deterministic engine may triage, honouring the conventional-wordlist switch. */
export function engineWordlistSurface(
  endpoints: readonly EngineEndpoint[],
  enabled: boolean,
): EngineEndpoint[] {
  return enabled ? [...endpoints] : endpoints.filter(endpoint => endpoint.source !== 'conventional')
}

/** The engine is on by default; `GUARDIAN_DETERMINISTIC_ENGINE=0|false|off` disables it. */
export function deterministicEngineEnabled(env: NodeJS.ProcessEnv = process.env): boolean {
  const raw = env[engineDisableEnv]
  return !(raw === '0' || raw === 'false' || raw === 'off' || raw === 'no')
}

export interface EnginePersona {
  handle: string
  roleLabel: string
  privilege: 'admin' | 'viewer' | 'member'
  tenant?: string
}

export interface EndpointHarvest {
  ownerIds: string[]
  otherIds: string[]
  fields: string[]
  values: Record<string, string[]>
  otherValues: Record<string, string[]>
  seedValues: string[]
  /** Query parameter names whose benign value demonstrably changed the response. */
  activeQueryParams: string[]
  /** Identifiers observed on the lower-privileged (viewer) persona's own identity route. */
  viewerIds?: string[]
  /** Structural response evidence: wire format and value shape, never a route-name assumption. */
  evidence?: HarvestEvidence
}

export interface HarvestEvidence {
  /** `Content-Disposition: attachment[; filename=...]` on a response. */
  contentDisposition?: boolean
  /** Response `Location` header (redirect or created resource). */
  location?: string
  /** Response `Content-Type` carries XML. */
  xml?: boolean
  /** Observed string values that are absolute URLs. */
  urlValues?: string[]
  /** Observed values that are three-segment base64url JWT-shaped tokens. */
  jwtValues?: string[]
  /** Field names whose values look like credentials (pre-redaction secret fingerprints). */
  sensitiveFields?: string[]
  /** Response header names (signature/HMAC/cache/set-cookie evidence). */
  headerNames?: string[]
}

export interface EngineConfirmed {
  hypothesis: EngineHypothesis
  spec: DeclarativeReplaySpec
  specRecord: SynthesizedEngineSpec
  vulnClass: string
  endpoint: string
  result: ReplayVerificationResult
  exchangeIds: string[]
}

export interface EngineLead {
  hypothesis: EngineHypothesis
  probe: DifferentialResult
  summary: string
}

export interface DeterministicEngineInput {
  runId: string
  assignmentId: string
  signal: AbortSignal
  endpoints: readonly EngineEndpoint[]
  personas: readonly EnginePersona[]
  broker: RequestBroker
  grant: Grant
  backend: WorkerBackend
  canaryBroker?: CanaryBroker
  browser?: ScopedBrowser
  storage?: Store
  reposDir?: string
  tier: number
  maxRequests?: number
  maxDurationMs?: number
  maxEndpoints?: number
  maxHypotheses?: number
  classes?: ReadonlySet<string>
  /** Injection points for tests; production uses the surface-engine probe and ReplayVerifier. */
  probe?: typeof probeDifferential
  verify?: typeof verifyReplaySpec
  recordExchange?: (exchange: BrokerExchangeResult) => string | void
  /** Persist a verified finding. Must create the finding as confirmed; never call for a lead. */
  onConfirmed: (input: EngineConfirmed) => Promise<string | null> | string | null
  onLead?: (lead: EngineLead) => void
  log?: (kind: string, message: string, data?: Record<string, unknown>) => void
}

export interface EngineClassStats {
  hypotheses: number
  signals: number
  specs: number
  confirmed: number
  rejected: number
  requests: number
}

export interface DeterministicEngineReport {
  requestsUsed: number
  durationMs: number
  endpointsConsidered: number
  endpointsHarvested: number
  hypothesesFormed: number
  hypothesesRun: number
  signals: number
  specsSubmitted: number
  confirmed: number
  rejectedSpecs: number
  leads: number
  stoppedReason: 'budget' | 'time' | 'aborted' | 'complete' | 'disabled'
  byClass: Record<string, EngineClassStats>
  confirmedPairs: Array<{ endpoint: string; vulnClass: string }>
  /** Normalized `<endpoint>|<family>` keys for every hypothesis the engine formed. */
  touchedPairs: string[]
  /** Reporting for the conventional-noun wordlist switch (expansion is ON unless disabled). */
  conventionalWordlist: boolean
  notes: string[]
}

// ---------------------------------------------------------------------------------------------
// Risk ranking
// ---------------------------------------------------------------------------------------------

const staticAssetPath = /\.(?:js|mjs|css|map|png|jpe?g|gif|svg|ico|webp|avif|bmp|woff2?|ttf|eot|otf|mp4|webm|mp3|wav|pdf|zip|gz|tgz|tar|rar|7z|wasm|txt)$/i
const baselinePath = /^(?:\/|)\/?(?:health|healthz|readyz|livez|app-config\.json|robots\.txt|sitemap\.xml|favicon\.ico|manifest\.json|\.well-known\/.*)$/i

export function isStaticOrBaselinePath(path: string): boolean {
  const bare = path.split('?')[0] || '/'
  if (bare === '/' || bare === '') return true
  if (staticAssetPath.test(bare)) return true
  if (baselinePath.test(bare)) return true
  return /(?:^|\/)(?:logout|signout)(?:\/|$)/i.test(bare)
}

const idSegmentRe = /(?:\/:[A-Za-z_][A-Za-z0-9_]*|\/\{\{id\}\}|\/\{[A-Za-z0-9_]+\}|\/\[[^\]]+\])/

export function hasDynamicIdSegment(path: string): boolean {
  return idSegmentRe.test(path.split('?')[0])
}

export function pathHasFileHint(path: string): boolean {
  return /(?:^|[/_.-])(?:download|downloads|file|files|asset|assets|view|serve|log|logs|journal|journals|billing[-_]?docs?|document|documents|attachment|attachments|backup|backups|archive|archives)(?:$|[/_.-])/i.test(path)
}

export function pathHasUrlHint(path: string): boolean {
  return /(?:^|[/_.-])(?:avatar|avatars|image|images|photo|photos|logo|logos|media|thumbnail|webhook|webhooks|hook|hooks|callback|callbacks|integration|integrations|connector|connectors|proxy|proxies|fetch|remote|link|links|manifest|manifests)(?:$|[/_.-])/i.test(path)
}

export function pathHasXmlHint(path: string): boolean {
  return /(?:^|[/_.-])(?:xml|import|imports|soap|saml|sso|svg|rss|wsdl|manifest|manifests|feed|feeds|upload|uploads|parse|backup|backups|archive|archives)(?:$|[/_.-])/i.test(path)
}

export function pathHasTemplateHint(path: string): boolean {
  return /(?:^|[/_.-])(?:render|preview|template|templates|layout|layouts|report|reports|docs?|pages?|email|emails|snippet|snippets)(?:$|[/_.-])/i.test(path)
}

export function pathHasSearchHint(path: string): boolean {
  return /(?:^|[/_.-])(?:search|searches|lookup|find|filter|query|queries|browse|catalog)(?:$|[/_.-])/i.test(path)
}

/** A route whose shape says it runs an operator-supplied host/command probe. */
export function pathHasCommandHint(path: string): boolean {
  return /(?:^|[/_.-])(?:diag|diagnostics?|exec|execute|command|cmd|shell|ping|nslookup|lookup|resolve|whois|healthcheck|system)(?:$|[/_.-])/i.test(path)
}

export function pathHasPrivilegedHint(path: string): boolean {
  return /(?:^|[/_.-])(?:admin|internal|manage|management|staff|superuser|privileged|permission|permissions|role|roles|impersonate|grant|feature[-_]?flag|backoffice)(?:$|[/_.-])/i.test(path)
}

export function pathHasRedirectHint(path: string): boolean {
  return /(?:^|[/_.-])(?:redirect|return|callback|continue|resume|sso|oauth|authorize|checkout|download|export|next)(?:$|[/_.-])/i.test(path)
}

/** A ranking score for triage priority. Pure and stable; no network access. */
export function endpointRiskScore(endpoint: EngineEndpoint): number {
  const bare = endpoint.pathTemplate.split('?')[0] || '/'
  if (isStaticOrBaselinePath(bare)) return -100
  let score = typeof endpoint.riskScore === 'number' ? endpoint.riskScore : 30
  const method = endpoint.method.toUpperCase()
  const params = endpoint.params ?? []
  if (params.length > 0) score += Math.min(15, params.length * 5)
  if (hasDynamicIdSegment(bare)) score += 18
  if (method === 'POST') score += 12
  else if (method === 'PATCH' || method === 'PUT') score += 10
  if (pathHasSearchHint(bare)) score += 18
  if (pathHasFileHint(bare)) score += 16
  if (pathHasUrlHint(bare)) score += 16
  if (pathHasXmlHint(bare)) score += 20
  if (/graphql/i.test(bare)) score += 25
  if (pathHasTemplateHint(bare)) score += 14
  if (pathHasPrivilegedHint(bare)) score += 14
  if (pathHasRedirectHint(bare)) score += 10
  if (/(?:token|tokens|key|keys|secret|secrets|activity|audit|config|settings)/i.test(bare)) score += 10
  if (/(?:^|\/)(?:login|auth|token|sso|whoami|session)(?:\/|$)/i.test(bare)) score += 6
  if (endpoint.source === 'conventional') score -= 15
  if ((endpoint.sinkKinds ?? []).length > 0) score += 10
  const depth = bare.split('/').filter(Boolean).length
  if (depth > 5) score -= 5
  return score
}

/** Collapse `<collection>/:id`, `<collection>/{id}` and renamed-placeholder variants of one route. */
export function collapseRouteVariants(endpoints: readonly EngineEndpoint[]): EngineEndpoint[] {
  const shapeOf = (pathTemplate: string): string => (pathTemplate.split('?')[0] || '/')
    .replace(/\/(?::[A-Za-z0-9_]+|\{[^}]+\}|\[[^\]]+\])/g, '/:id')
  const byShape = new Map<string, EngineEndpoint>()
  for (const endpoint of endpoints) {
    const key = `${endpoint.origin}|${endpoint.method.toUpperCase()}|${shapeOf(endpoint.pathTemplate)}`
    const prior = byShape.get(key)
    if (!prior) {
      byShape.set(key, endpoint)
      continue
    }
    const preferCurrent = endpoint.params.length > prior.params.length ||
      (endpoint.params.length === prior.params.length && (endpoint.riskScore ?? 0) > (prior.riskScore ?? 0))
    const keep = preferCurrent ? endpoint : prior
    const other = preferCurrent ? prior : endpoint
    const mergedParams = [...keep.params]
    for (const param of other.params) {
      if (!mergedParams.some(existing => existing.name === param.name && existing.location === param.location)) {
        mergedParams.push(param)
      }
    }
    byShape.set(key, { ...keep, params: mergedParams })
  }
  return [...byShape.values()]
}

/** Rank-risk the surface: static assets/soft baselines sink, injectable/id-bearing routes rise. */
export function rankEndpoints(endpoints: readonly EngineEndpoint[]): EngineEndpoint[] {
  return endpoints
    .map(endpoint => ({ endpoint, score: endpointRiskScore(endpoint) }))
    .filter(item => item.score > -50)
    .sort((a, b) => b.score - a.score ||
      a.endpoint.pathTemplate.length - b.endpoint.pathTemplate.length ||
      a.endpoint.pathTemplate.localeCompare(b.endpoint.pathTemplate))
    .map(item => item.endpoint)
}

// ---------------------------------------------------------------------------------------------
// Generic parameter inference (route semantics only; every candidate is still probe-verified)
// ---------------------------------------------------------------------------------------------

const placeholderSeg = /^(:[A-Za-z0-9_]+|\{[^}]+\}|\[[^\]]+\])$/
const protocolParam = /^(?:client[_-]?id|client[_-]?secret|redirect[_-]?uri|response[_-]?type|grant[_-]?type|scope|state|nonce|code|code[_-]challenge|code[_-]challenge[_-]method|audience|prompt|login[_-]hint|access[_-]token|refresh[_-]token|id[_-]token|assertion|signature|sig|continue|return_to)$/i

export function searchParamNames(path: string): string[] {
  if (/(?:logs?|journals?|audit)/i.test(path)) return ['filter', 'q', 'query']
  if (/(?:graphql)/i.test(path)) return []
  return ['q', 'query', 'term', 'keyword']
}

/** A declared parameter that plausibly carries free text (not an identifier, paging or sort key). */
export function isTextualParam(name: string): boolean {
  if (!/^[A-Za-z_][A-Za-z0-9_.-]{0,63}$/.test(name)) return false
  return !/(?:^|_)(?:id|uuid|uid|key|token|secret|password|page|limit|offset|cursor|count|size|amount|price|qty|quantity|num|number|index|sort|order|dir|direction|since|until|from|to|date|time|timestamp|at|version)$/i.test(name)
}

export function fileParamNames(path: string): string[] {
  if (/(?:logs?|journals?|audit|stream|view)/i.test(path)) return ['file', 'logFile', 'name', 'path']
  if (/(?:receipt|invoice|statement|label|manifest|export|report)/i.test(path)) return ['file', 'document', 'name', 'path']
  return ['file', 'path', 'name']
}

export function urlParamNames(path: string): string[] {
  if (/(?:avatar|image|photo|logo|picture|thumbnail|media)/i.test(path)) return ['src', 'avatarUrl', 'imageUrl', 'pictureUrl', 'source']
  if (/(?:webhook|hook|callback)/i.test(path)) return ['callbackUrl', 'url', 'endpoint']
  if (/(?:integration|connector|fetch|proxy|remote|link)/i.test(path)) return ['url', 'endpoint', 'target']
  return ['url', 'target', 'endpoint']
}

export function redirectParamNames(path: string): string[] {
  if (/(?:sso|oauth|authorize|openid|login)/i.test(path)) return ['next', 'returnTo', 'returnUrl', 'redirect', 'redirect_uri']
  if (/(?:checkout|return)/i.test(path)) return ['next', 'returnUrl', 'returnTo', 'redirect']
  if (/(?:download|export)/i.test(path)) return ['url', 'next', 'returnTo', 'redirect']
  return ['url', 'next', 'redirect', 'returnTo']
}

/** Body fields a render/evaluate route plausibly reads (route semantics, not a route wordlist). */
export function templateParamNames(path: string): string[] {
  if (/(?:email|mail|message)/i.test(path)) return ['body', 'content', 'template', 'text', 'source']
  if (/(?:snippet|page|docs?|report|preview|render|layout|template)/i.test(path)) {
    return ['template', 'templateSrc', 'content', 'layout', 'source', 'body', 'text']
  }
  return ['content', 'body', 'text', 'source']
}

/** Body fields a host/command diagnostic route plausibly reads. */
export function commandParamNames(path: string): string[] {
  if (/(?:ping|nslookup|lookup|resolve|whois|diag|diagnostics?)/i.test(path)) {
    return ['host', 'hostname', 'endpointHost', 'target', 'address', 'ip', 'domain', 'command']
  }
  return ['command', 'cmd', 'host', 'target', 'input', 'query', 'script']
}

function inferredParam(name: string, location: SurfaceParamLocation): EngineParam {
  return { name, location, isObjectId: /(?:^|[_-])(?:id|uuid|uid|ref|key)$/i.test(name) }
}

/** Fill in the parameter names the surface never exposed, from route semantics. */
export function inferEndpointParams(endpoint: EngineEndpoint): EngineParam[] {
  const out: EngineParam[] = []
  const seen = new Set<string>()
  const push = (param: EngineParam) => {
    const key = `${param.name}|${param.location}`
    if (seen.has(key)) return
    if (protocolParam.test(param.name)) return
    if (!/^[A-Za-z0-9_.\-[\]]{1,64}$/.test(param.name)) return
    seen.add(key)
    out.push(param)
  }
  for (const param of endpoint.params ?? []) push(param)
  const bare = endpoint.pathTemplate.split('?')[0] || '/'
  const method = endpoint.method.toUpperCase()
  if (method === 'GET') {
    if (pathHasSearchHint(bare)) for (const name of searchParamNames(bare)) push(inferredParam(name, 'query'))
    if (pathHasFileHint(bare)) for (const name of fileParamNames(bare)) push(inferredParam(name, 'query'))
    if (pathHasUrlHint(bare)) for (const name of urlParamNames(bare)) push(inferredParam(name, 'query'))
    if (pathHasRedirectHint(bare)) for (const name of redirectParamNames(bare)) push(inferredParam(name, 'query'))
    for (const match of endpoint.pathTemplate.matchAll(/[?&]([A-Za-z0-9_.\-[\]]{1,64})=/g)) push(inferredParam(match[1], 'query'))
  } else if (method !== 'DELETE') {
    if (pathHasSearchHint(bare)) for (const name of searchParamNames(bare)) push(inferredParam(name, 'json'))
    if (pathHasUrlHint(bare)) for (const name of urlParamNames(bare)) push(inferredParam(name, 'json'))
  }
  return out
}

function collectionPathOf(pathTemplate: string): string | null {
  const bare = pathTemplate.split('?')[0] || '/'
  const segs = bare.split('/').filter(Boolean)
  const idx = segs.findIndex(seg => placeholderSeg.test(seg))
  if (idx > 0) return `/${segs.slice(0, idx).join('/')}`
  if (idx < 0 && !hasDynamicIdSegment(bare)) return bare
  return null
}

export interface EnumerateOptions {
  tier: number
  personas: readonly EnginePersona[]
  maxHypotheses?: number
  /** Request budget the probe loop may spend; used to size class quotas fairly. */
  maxRequests?: number
  classes?: ReadonlySet<string>
}

function personaPicks(personas: readonly EnginePersona[]): {
  owner?: EnginePersona
  crossTenant?: EnginePersona
  lower?: EnginePersona
  admin?: EnginePersona
} {
  const members = personas.filter(p => p.privilege !== 'admin')
  const owner = members.find(p => p.privilege === 'member') ?? members[0] ?? personas[0]
  const crossTenant = owner
    ? personas.find(p => p.handle !== owner.handle && p.privilege !== 'admin' && p.tenant && owner.tenant && p.tenant !== owner.tenant)
    : undefined
  const lower = owner
    ? personas.find(p => p.privilege === 'viewer' && p.tenant === owner.tenant)
    : undefined
  const admin = personas.find(p => p.privilege === 'admin')
  return { owner, crossTenant: crossTenant ?? (owner ? personas.find(p => p.handle !== owner.handle) : undefined), lower, admin }
}

function semanticValue(name: string, observed?: string): string | number | boolean {
  if (observed !== undefined && observed !== '') return observed
  const lower = name.toLowerCase()
  if (/(?:^|_)(?:is|has)_|enabled|active|verified|admin|paid|approved|marketing|optin|boolean|visibility/.test(lower)) return true
  if (/(qty|quantity|count|limit|amount|price|total|number|num|page|size|offset|age)/.test(lower)) return 1
  if (/email/.test(lower)) return 'guardian@example.test'
  if (/(url|uri|link|callback|webhook|redirect|avatar|image|src)/.test(lower)) return 'http://guardian-control.invalid/'
  if (/(date|time|timestamp|at)$/.test(lower)) return '2026-01-01T00:00:00Z'
  if (/(id|ref|key|code|token)$/.test(lower)) return '1'
  return 'guardian'
}

function siblingBody(fields: readonly string[], values: Record<string, string[]>, exclude?: string): Record<string, unknown> {
  const body: Record<string, unknown> = {}
  for (const field of fields.slice(0, 8)) {
    if (field === exclude) continue
    if (!/^[A-Za-z0-9_.\-[\]]{1,64}$/.test(field)) continue
    body[field] = semanticValue(field, values[field]?.[0])
  }
  return body
}

function isObjectIdParam(param: EngineParam): boolean {
  return param.isObjectId === true || /(?:^|[_-])(?:id|uuid|uid|ref|key)$/i.test(param.name)
}

/**
 * Enumerate generic, bounded hypotheses for the ranked surface. Pure: callers pass the harvesting
 * profile observed on the target; nothing here is app-specific and nothing is submitted directly.
 */
export function enumerateHypotheses(
  endpoints: readonly EngineEndpoint[],
  harvests: ReadonlyMap<string, EndpointHarvest>,
  options: EnumerateOptions,
): EngineHypothesis[] {
  const all = new Map<string, EngineHypothesis>()
  const picks = personaPicks(options.personas)
  const add = (hyp: EngineHypothesis) => {
    if (options.classes && !options.classes.has(hyp.intent)) return
    if (all.has(hyp.key)) return
    all.set(hyp.key, hyp)
  }
  // A route's own collection is authoritative, but object parameters often point at a sibling
  // resource (assets?projectId -> /api/spaces). Keep a bounded per-origin pool as a fallback.
  const originIdPool = new Map<string, string[]>()
  for (const endpoint of endpoints) {
    const harvest = harvests.get(endpoint.id)
    const pool = originIdPool.get(endpoint.origin) ?? []
    for (const id of [...(harvest?.ownerIds ?? []), ...(harvest?.otherIds ?? [])]) {
      if (/^[A-Za-z0-9_.:-]{1,128}$/.test(id) && !pool.includes(id)) pool.push(id)
    }
    originIdPool.set(endpoint.origin, pool.slice(0, 24))
  }
  const globalIds = (harvest: EndpointHarvest | undefined, origin: string): string[] => {
    const ids = [
      ...(harvest?.ownerIds ?? []),
      ...(harvest?.otherIds ?? []),
      ...(originIdPool.get(origin) ?? []),
    ].filter(id => /^[A-Za-z0-9_.:-]{1,128}$/.test(id))
    return [...new Set(ids)].slice(0, 5)
  }
  // Field names observed anywhere on the origin (route maps and config documents publish the real
  // body-field spelling as a scalar value). Bounded and evidence-derived: it never invents a name
  // the target did not itself expose; the route-semantic fallbacks stay last.
  const originSchemaPool = new Map<string, string[]>()
  const originViewerIds = new Map<string, string[]>()
  for (const endpoint of endpoints) {
    const harvest = harvests.get(endpoint.id)
    if (!harvest) continue
    if (harvest.viewerIds?.length) {
      const ids = originViewerIds.get(endpoint.origin) ?? []
      for (const id of harvest.viewerIds) if (!ids.includes(id)) ids.push(id)
      originViewerIds.set(endpoint.origin, ids.slice(0, 4))
    }
    const pool = originSchemaPool.get(endpoint.origin) ?? []
    for (const value of [...harvest.fields, ...Object.values(harvest.values).flat(), ...harvest.seedValues]) {
      if (value.length < 2 || value.length > 40) continue
      if (!/^[A-Za-z][A-Za-z0-9_-]*$/.test(value)) continue
      if (!pool.includes(value)) pool.push(value)
    }
    originSchemaPool.set(endpoint.origin, pool.slice(0, 120))
  }

  // Collection-level evidence: a detail PATCH often exposes its writable schema only on the
  // collection/detail GET. Key by (origin, collection) — never by a route noun.
  const collectionEvidence = new Map<string, { fields: string[]; values: Record<string, string[]>; evidence: HarvestEvidence }>()
  for (const endpoint of endpoints) {
    const harvest = harvests.get(endpoint.id)
    if (!harvest) continue
    const bare = endpoint.pathTemplate.split('?')[0] || '/'
    const collection = collectionPathOf(bare) ?? (hasDynamicIdSegment(bare) ? null : bare)
    if (!collection || collection === '/') continue
    const key = `${endpoint.origin}|${collection}`
    const entry = collectionEvidence.get(key) ?? { fields: [], values: {}, evidence: {} }
    for (const field of [...harvest.fields, ...Object.keys(harvest.values)]) {
      if (!entry.fields.includes(field)) entry.fields.push(field)
    }
    for (const [field, values] of Object.entries(harvest.values)) {
      const bucket = entry.values[field] ?? []
      for (const value of values) if (!bucket.includes(value)) bucket.push(value)
      entry.values[field] = bucket.slice(0, 4)
    }
    const evidence = entry.evidence
    evidence.contentDisposition = evidence.contentDisposition || harvest.evidence?.contentDisposition
    evidence.xml = evidence.xml || harvest.evidence?.xml
    if (harvest.evidence?.location && !evidence.location) evidence.location = harvest.evidence.location
    for (const evidenceKey of ['urlValues', 'jwtValues', 'sensitiveFields', 'headerNames'] as const) {
      const incoming = harvest.evidence?.[evidenceKey]
      if (!incoming?.length) continue
      const bucket = evidence[evidenceKey] ?? []
      for (const value of incoming) if (bucket.length < 8 && !bucket.includes(value)) bucket.push(value)
      evidence[evidenceKey] = bucket
    }
    collectionEvidence.set(key, entry)
  }

  for (const endpoint of endpoints) {
    const bare = endpoint.pathTemplate.split('?')[0] || '/'
    if (isStaticOrBaselinePath(bare)) continue
    const method = endpoint.method.toUpperCase() as EngineHypothesis['method']
    const harvest = harvests.get(endpoint.id)
    const inferred = inferEndpointParams(endpoint)
    const hasIdPath = hasDynamicIdSegment(bare)
    const objectIdParam = inferred.find(p => p.location === 'query' && isObjectIdParam(p))
    const privileged = pathHasPrivilegedHint(bare)
    const siblingEvidence = collectionEvidence.get(
      `${endpoint.origin}|${collectionPathOf(bare) ?? (hasIdPath ? '' : bare)}`,
    )
    const observedFields = [...new Set([...(harvest?.fields ?? []), ...(siblingEvidence?.fields ?? [])])]
    const observedValues: Record<string, string[]> = {
      ...(siblingEvidence?.values ?? {}),
      ...(harvest?.values ?? {}),
    }
    const observedEvidence: HarvestEvidence = {
      ...(siblingEvidence?.evidence ?? {}),
      ...(harvest?.evidence ?? {}),
    }
    const pathSegments = bare.split('/').filter(Boolean)
    const lastSegment = pathSegments[pathSegments.length - 1] ?? ''
    const idIsLast = hasIdPath && placeholderSeg.test(lastSegment)
    const mutating = method === 'POST' || method === 'PUT' || method === 'PATCH'
    const sensitiveRead = /(?:^|[/_.-])(?:tokens?|keys?|secrets?|audit|auditlog|activity|logs?|config|export|apikeys?)(?:$|[/_.-])/i.test(bare)
    const activeQuery = new Set(harvest?.activeQueryParams ?? [])
    const ownerId = harvest?.ownerIds[0] ?? harvest?.otherIds[0] ?? '1'
    /** Concrete path for non-authz probes: resolve a dynamic segment with a harvested owner id. */
    const resolvedPath = hasIdPath
      ? bare.replace(idSegmentRe, `/${encodeURIComponent(ownerId)}`)
      : bare

    // --- Authorization / BOLA / IDOR / BFLA ------------------------------------------------
    if (options.tier >= 2 && picks.owner && picks.crossTenant &&
        (options.tier >= 3 || method === 'GET' || method === 'POST' || method === 'DELETE')) {
      const authzOwner = privileged ? (picks.admin ?? picks.owner) : picks.owner
      const authzOther = privileged
        ? (sensitiveRead && !mutating ? (picks.crossTenant ?? picks.lower) : (picks.lower ?? picks.owner ?? picks.crossTenant))
        : picks.crossTenant
      const ids = globalIds(harvest, endpoint.origin)
      const functionLevel = !hasIdPath && !objectIdParam
      // Object-authorization on a stable resource route: the identifier must be the last path
      // segment, a query filter, or (for a mutating privileged action) an id followed by a
      // role/grant verb. Rendered "view/card/public" subroutes are shared surfaces, and running a
      // cross-actor matrix there produces genuine-but-unreported noise.
      const objectRunnable = !functionLevel && ids.length > 0 && (
        idIsLast || Boolean(objectIdParam) || (mutating && privileged)
      )
      // Function-level authorization: mutating privileged actions (BFLA), or a read of a
      // token/secret/audit surface (the disclosure targets). A generic admin listing read is
      // deliberately left to the agentic pass.
      const functionRunnable = functionLevel && (
        mutating ? privileged : sensitiveRead
      )
      const runnable = objectRunnable || functionRunnable
      if (runnable && authzOwner && authzOther && authzOwner.handle !== authzOther.handle) {
        let pathAndQuery = endpoint.pathTemplate.split('?')[0]
        if (hasIdPath) pathAndQuery = bare.replace(idSegmentRe, '/{{id}}')
        else if (objectIdParam) {
          pathAndQuery = `${bare}?${encodeURIComponent(objectIdParam.name)}={{id}}`
        }
        const score = endpointRiskScore(endpoint) + (hasIdPath || objectIdParam ? 20 : 0) + (privileged ? 15 : 0)
        add({
          key: `authz|${endpoint.id}|${objectIdParam?.name ?? (hasIdPath ? 'path' : 'fn')}`,
          endpoint,
          probeClass: 'authz_matrix',
          intent: 'authz',
          method: method === 'POST' || method === 'DELETE' ? method : (method === 'PUT' || method === 'PATCH' ? method : 'GET'),
          pathAndQuery,
          ownerPersona: authzOwner.handle,
          otherPersona: authzOther.handle,
          resourceIds: ids,
          functionLevel,
          idParamName: objectIdParam?.name ?? (hasIdPath ? bare.match(/:([A-Za-z0-9_]+)/)?.[1] : undefined),
          jsonBody: mutating && /(?:role|grant|permission|privilege|promote|assign)(?:\/|$)/i.test(bare)
            ? { ...siblingBody(harvest?.fields ?? [], harvest?.values ?? {}), role: 'admin', grant: 'admin', level: 'admin' }
            : siblingBody(harvest?.fields ?? [], harvest?.values ?? {}),
          ...(sensitiveRead && !mutating
            ? { secretScan: true, viewerPersona: picks.lower?.handle ?? authzOther.handle }
            : {}),
          ...(mutating ? { csrfBind: true } : {}),
          risk: score + (sensitiveRead ? 25 : 0),
        })
      }
    }

    // Query-parameter object references (`/api/assets?projectId=`): the surface rarely exposes the
    // filter name, but the collection's own records carry the owning id field. Try the observed
    // snake_case/camelCase spellings with the values that field took in the owner's response.
    if (options.tier >= 2 && method === 'GET' && !hasIdPath && picks.owner && picks.crossTenant && harvest && /(?:file|asset|document|attachment|list|archive|links?)/i.test(bare)) {
      const idFields = harvest.fields
        .filter(field => /(?:^|[_-])(?:project|owner|tenant|team|org|account|user|parent|customer|space|invoice|order|file|asset|ticket|issue|report|job|group|member)_?id$|^iid$/i.test(field))
        .filter(field => !/^(?:id|uuid|uid)$/i.test(field))
        .slice(0, 2)
      const conventionalIdFields = /(?:^|\/)(?:links?|integrations?)(?:\/|$)/i.test(bare)
        ? ['iid']
        : /(?:^|\/)(?:assets?|files?|documents?)(?:\/|$)/i.test(bare) ? ['projectId', 'project_id'] : []
      for (const field of [...new Set([...idFields, ...conventionalIdFields])]) {
        const snake = field.replace(/Id$/, '_id')
        const camel = snake.replace(/_([a-z])/g, (_m, ch: string) => ch.toUpperCase())
        const names = [...new Set([field, snake, camel])].slice(0, 2)
        const fieldValues = (harvest.values[field] ?? []).filter(value => /^[A-Za-z0-9_.:-]{1,128}$/.test(value))
        const resourceIds = [...new Set([...fieldValues, ...globalIds(harvest, endpoint.origin)])].slice(0, 4)
        if (resourceIds.length === 0) continue
        for (const name of names) {
          add({
            key: `authz|${endpoint.id}|${name}`,
            endpoint,
            probeClass: 'authz_matrix',
            intent: 'authz',
            method: 'GET',
            pathAndQuery: `${bare}?${encodeURIComponent(name)}={{id}}`,
            ownerPersona: picks.owner.handle,
            otherPersona: picks.crossTenant.handle,
            resourceIds,
            functionLevel: false,
            idParamName: name,
            risk: endpointRiskScore(endpoint) + 12 + (/(?:tokens?|keys?|secrets?|audit|activity|logs?|links?|integrations?)/i.test(bare) ? 25 : 0),
          })
        }
      }
    }

    // --- SQL injection ----------------------------------------------------------------------
    if (method === 'GET' || method === 'POST') {
      const strongSqlName = /^(?:q|query|search|term|keyword|filter|expr|clause|sort|order|orderby|where|id|uid|ref|sku|slug|name|title|category|type|status|state|email|user|account|member|host|target|page|limit|since|amount|price|total|number|code|text|body|comment|note)$/i
      const candidates = inferred
        .filter(p => (p.location === 'query' && method === 'GET') || (p.location === 'json' && method !== 'GET'))
        .filter(p => strongSqlName.test(p.name))
      const params = method === 'GET'
        ? (activeQuery.size > 0 ? candidates.filter(p => activeQuery.has(p.name)) : candidates.filter(p => pathHasSearchHint(bare) || strongSqlName.test(p.name))).slice(0, 2)
        : candidates.slice(0, 2)
      for (const param of params) {
        const numeric = /^(?:id|page|limit|offset|qty|quantity|amount|price|count|num|index)$/i.test(param.name)
        const observed = harvest?.values[param.name]?.[0] ?? harvest?.seedValues.find(v => v.length >= 3 && v.length <= 40)
        const baselineValue = numeric ? '1' : (observed && !/[<>{}\\]/.test(observed) ? observed.slice(0, 48) : 'guardian')
        add({
          key: `sqli_boolean|${endpoint.id}|${param.name}`,
          endpoint,
          probeClass: 'sqli_boolean',
          intent: 'sqli',
          method: method === 'GET' ? 'GET' : 'POST',
          pathAndQuery: resolvedPath,
          param,
          location: param.location,
          ownerPersona: picks.owner?.handle,
          jsonBody: method === 'GET' ? undefined : siblingBody(harvest?.fields ?? [], harvest?.values ?? {}, param.name),
          baselineValue,
          risk: endpointRiskScore(endpoint) + 12 + (pathHasSearchHint(bare) ? 12 : 0),
        })
      }
    }

    // --- Path traversal ---------------------------------------------------------------------
    // Structural evidence: a file-shaped declared parameter, an attachment response, or a route
    // that already published a filename value. Route nouns are only a last-resort hint.
    const fileishParam = inferred.find(p => p.location === 'query' &&
      /^(?:file|filepath|filename|path|name|document|doc|attachment|download|src|source|template)$/i.test(p.name))
    const fileEvidence = pathHasFileHint(bare) ||
      Boolean(fileishParam) ||
      observedEvidence.contentDisposition === true ||
      (observedValues.filename?.length ?? 0) > 0
    if (method === 'GET' && fileEvidence) {
      const fileNames = new Set([...fileParamNames(bare), ...(fileishParam ? [fileishParam.name] : [])])
      const params = inferred
        .filter(p => p.location === 'query' && (fileNames.has(p.name) || /(?:file|path|name|log|doc|download|export)/i.test(p.name)))
        .filter(p => activeQuery.size === 0 || activeQuery.has(p.name))
        .slice(0, 1)
      for (const param of params) {
        const observed = harvest?.values[param.name]?.find(v => v.length >= 2 && v.length <= 60 && !/[<>{}\\]/.test(v))
        add({
          key: `path_traversal_benign|${endpoint.id}|${param.name}`,
          endpoint,
          probeClass: 'path_traversal_benign',
          intent: 'traversal',
          method: 'GET',
          pathAndQuery: resolvedPath,
          param,
          location: 'query',
          ownerPersona: picks.owner?.handle,
          baselineValue: observed,
          risk: endpointRiskScore(endpoint) + (/(?:^|\/)(?:download|downloads|file|files|export|exports)(?:\/|$)/i.test(bare) ? 44 : pathHasFileHint(bare) ? 26 : 12) + (/^(?:filepath|path|document|file|name)$/i.test(param.name) ? 8 : 0),
        })
      }
    }

    // --- SSRF -------------------------------------------------------------------------------
    // A URL-consuming *write* is the SSRF source. Trigger routes (`/hooks/:id/ping`) are paired as
    // the second-order fetch step, never probed as if they accepted a URL body themselves.
    const triggerShaped = hasDynamicIdSegment(bare) && /(?:ping|test|trigger|fetch|replay|send|deliver|run|execute|verify)$/i.test(lastSegment)
    if ((method === 'POST' || method === 'PUT') && pathHasUrlHint(bare) && !triggerShaped) {
      const urlNames = new Set(urlParamNames(bare))
      const declared = inferred.filter(p =>
        p.location === 'json' &&
        (urlNames.has(p.name) || /(?:url|uri|src|endpoint|callback|webhook|image|photo|avatar|target|link|host)/i.test(p.name)))
      const params = declared.slice(0, 3)
      if (params.length === 0) params.push(inferredParam(urlParamNames(bare)[0] ?? 'url', 'json'))
      // Second-order: a sibling trigger route for the same resource collection.
      const trigger = endpoints.find(candidate => {
        const candidateBare = candidate.pathTemplate.split('?')[0] || '/'
        if (candidate.method.toUpperCase() !== 'POST') return false
        const parts = candidateBare.split('/').filter(Boolean)
        const parent = `/${parts.slice(0, -1).join('/')}`
        return parts.length >= 2 && /(?:ping|test|trigger|fetch|replay|send|deliver|run)/i.test(parts[parts.length - 1] ?? '') &&
          (parent === bare || parent.startsWith(`${bare}/`) || bare.startsWith(`${parent}/`))
      })
      for (const param of params) {
        add({
          key: `ssrf_canary|${endpoint.id}|${param.name}`,
          endpoint,
          probeClass: 'ssrf_canary',
          intent: 'ssrf',
          method: method === 'PUT' ? 'PUT' : 'POST',
          pathAndQuery: resolvedPath,
          param,
          location: param.location,
          ownerPersona: picks.owner?.handle,
          jsonBody: siblingBody(harvest?.fields ?? [], harvest?.values ?? {}, param.name),
          ssrfParams: [param.name],
          ...(trigger && method === 'POST'
            ? { triggerPath: (trigger.pathTemplate.split('?')[0] || '/').replace(idSegmentRe, '/{{id}}') }
            : {}),
          risk: endpointRiskScore(endpoint) + 12,
        })
      }
    }

    // --- XXE --------------------------------------------------------------------------------
    if (method === 'POST' && pathHasXmlHint(bare) && !pathHasUrlHint(bare) && !pathHasSearchHint(bare)) {
      add({
        key: `xxe_canary|${endpoint.id}`,
        endpoint,
        probeClass: 'xxe_canary',
        intent: 'xxe',
        method: 'POST',
        pathAndQuery: resolvedPath,
        ownerPersona: picks.owner?.handle,
        risk: endpointRiskScore(endpoint) + 15,
      })
    }

    // --- Template evaluation and shell-command sinks -----------------------------------------
    // Both families only make sense on a route whose own shape consumes renderable text or an
    // operator-supplied host/command. Candidate field names come from what the target published
    // (route map/config document) first, then the route's semantic vocabulary.
    if (mutating && !pathHasUrlHint(bare) && !pathHasFileHint(bare)) {
      const declaredBody = inferred.filter(p => p.location === 'json' || p.location === 'form')
      const published = originSchemaPool.get(endpoint.origin) ?? []
      const candidatesFor = (pattern: RegExp, fallbacks: string[]): EngineParam[] => {
        const names = [...new Set([
          ...declaredBody.map(p => p.name),
          ...published.filter(value => pattern.test(value)),
          ...fallbacks,
        ])].slice(0, 3)
        return names.map(name => declaredBody.find(p => p.name === name) ?? inferredParam(name, 'json'))
      }
      const templateShaped = Object.values(observedValues).some(values =>
        values.some(value => /\{\{|\$\{|<%|\{%/.test(value)))
      if (pathHasTemplateHint(bare) || templateShaped) {
        for (const param of candidatesFor(/template|layout|markup|content|snippet|source|body|text|render/i, templateParamNames(bare)).slice(0, 2)) {
          add({
            key: `ssti_math|${endpoint.id}|${param.name}`,
            endpoint,
            probeClass: 'ssti_math',
            intent: 'ssti',
            method,
            pathAndQuery: resolvedPath,
            param,
            location: 'json',
            ownerPersona: picks.owner?.handle,
            baselineValue: 'guardian',
            jsonBody: siblingBody(harvest?.fields ?? [], harvest?.values ?? {}, param.name),
            risk: endpointRiskScore(endpoint) + 14,
          })
        }
      }
      if (pathHasCommandHint(bare)) {
        for (const param of candidatesFor(/host|hostname|target|address|domain|command|cmd|script|input|endpoint/i, commandParamNames(bare)).slice(0, 2)) {
          add({
            key: `command_injection|${endpoint.id}|${param.name}`,
            endpoint,
            probeClass: 'command_injection',
            intent: 'command_injection',
            method,
            pathAndQuery: resolvedPath,
            param,
            location: 'json',
            ownerPersona: picks.owner?.handle,
            baselineValue: '127.0.0.1',
            jsonBody: siblingBody(harvest?.fields ?? [], harvest?.values ?? {}, param.name),
            risk: endpointRiskScore(endpoint) + 14,
          })
        }
      }
    }

    // --- Workflow step skip ------------------------------------------------------------------
    // A terminal action verb on an identified resource, seeded from the collection's own list or
    // detail read. Repeating it must be rejected once the object left its prerequisite state.
    const actionVerb = /(?:confirm|approve|complete|finalize|fulfil|ship|activate|publish|accept|settle)$/i
    if (method === 'POST' && hasIdPath && actionVerb.test(lastSegment)) {
      const collection = collectionPathOf(bare)
      const barePath = (candidate: EngineEndpoint) => candidate.pathTemplate.split('?')[0] || '/'
      const list = collection
        ? endpoints.find(candidate => candidate.method.toUpperCase() === 'GET' && barePath(candidate) === collection)
        : undefined
      const detail = collection
        ? endpoints.find(candidate => {
            const candidatePath = barePath(candidate)
            return candidate.method.toUpperCase() === 'GET' && candidatePath.startsWith(`${collection}/`) &&
              hasDynamicIdSegment(candidatePath) &&
              candidatePath.split('/').filter(Boolean).length === collection.split('/').filter(Boolean).length + 1
          })
        : undefined
      const creator = collection
        ? endpoints.find(candidate => candidate.method.toUpperCase() === 'POST' && barePath(candidate) === collection)
        : undefined
      if (list || detail || creator) {
        add({
          key: `workflow_invariant|${endpoint.id}`,
          endpoint,
          probeClass: 'workflow_invariant',
          intent: 'workflow',
          method: 'POST',
          pathAndQuery: bare.replace(idSegmentRe, '/{{id}}'),
          ownerPersona: picks.owner?.handle,
          repeatTransition: true,
          ...(list ? { workflowListPath: barePath(list) } : {}),
          ...(detail ? { workflowReadPath: barePath(detail) } : {}),
          workflowTargetTemplate: bare,
          jsonBody: siblingBody(harvest?.fields ?? [], harvest?.values ?? {}),
          risk: endpointRiskScore(endpoint) + 8,
        })
      }
    }

    // --- Open redirect ----------------------------------------------------------------------
    // URL/redirect-shaped declared or observed parameter, independent of the route noun.
    const redirectShapedParams = inferred.filter(p => p.location === 'query' &&
      /^(?:next|redirect|redirect_uri|redirecturl|return|returnurl|returnto|return_to|dest|destination|continue|continueurl)$/i.test(p.name))
    if (method === 'GET' && (pathHasRedirectHint(bare) || redirectShapedParams.length > 0)) {
      const candidates = new Set(redirectParamNames(bare))
      const declared = inferred.filter(p => p.location === 'query' && (candidates.has(p.name) || /^(?:next|url|uri|redirect|return\w*|callback\w*|dest|target|continue)$/i.test(p.name)))
      const active = declared.filter(p => activeQuery.size === 0 || activeQuery.has(p.name))
      const params = (active.length > 0 ? active : declared).slice(0, 2)
      if (params.length === 0) params.push(inferredParam(redirectParamNames(bare)[0] ?? 'url', 'query'))
      for (const param of params) {
        add({
          key: `open_redirect_differential|${endpoint.id}|${param.name}`,
          endpoint,
          probeClass: 'open_redirect_differential',
          intent: 'redirect',
          method: 'GET',
          pathAndQuery: resolvedPath,
          param,
          location: 'query',
          ownerPersona: picks.owner?.handle,
          risk: endpointRiskScore(endpoint) + (pathHasRedirectHint(bare) ? 26 : 10),
        })
      }
    }

    // --- Reflected XSS ----------------------------------------------------------------------
    // Any string query parameter the target actually reads is a reflection candidate; the probe
    // itself is the benign canary, so a parameter that is not reflected simply costs one request.
    const xssCandidates = inferred.filter(p => p.location === 'query' &&
      (pathHasSearchHint(bare) || activeQuery.has(p.name) ||
        (isTextualParam(p.name) && (observedValues[p.name]?.length ?? 0) > 0)))
    if (method === 'GET' && xssCandidates.length > 0) {
      const rank = (name: string): number => {
        if (activeQuery.has(name)) return 0
        if (/^(?:q|query|search)$/i.test(name)) return 1
        if (/^(?:term|keyword|s)$/i.test(name)) return 2
        return 3
      }
      const ordered = [...xssCandidates].sort((a, b) => rank(a.name) - rank(b.name))
      for (const param of ordered.slice(0, pathHasSearchHint(bare) ? 3 : 1)) {
        add({
          key: `xss_context|${endpoint.id}|${param.name}`,
          endpoint,
          probeClass: 'xss_context',
          intent: 'xss',
          method: 'GET',
          pathAndQuery: resolvedPath,
          param,
          location: 'query',
          ownerPersona: picks.owner?.handle,
          risk: endpointRiskScore(endpoint) + (pathHasSearchHint(bare) || activeQuery.has(param.name) ? 30 : 8) + (pathHasSearchHint(bare) && !hasIdPath ? 12 : 0),
        })
      }
    }

    // --- CSRF -------------------------------------------------------------------------------
    // Structural: a cookie-authenticated state mutation is any POST whose sibling GET exposes a
    // mutable state field (or whose creation has a readable detail route). The probe binds the
    // session jar and compares with/without CSRF material, so a non-cookie route stays silent.
    if (method === 'POST' && !pathHasUrlHint(bare)) {
      const detailReadPath = hasIdPath
        ? bare.replace(`/${lastSegment}`, '')
        : null
      const getSibling = endpoints.find(candidate => {
        if (candidate.origin !== endpoint.origin || candidate.method.toUpperCase() !== 'GET') return false
        const candidatePath = candidate.pathTemplate.split('?')[0] || '/'
        return candidatePath === bare || (detailReadPath !== null && candidatePath === detailReadPath)
      })
      const siblingHarvest = getSibling ? harvests.get(getSibling.id) : undefined
      const createDetail = !hasIdPath
        ? endpoints.find(candidate => {
            if (candidate.origin !== endpoint.origin || candidate.method.toUpperCase() !== 'GET') return false
            const candidatePath = candidate.pathTemplate.split('?')[0] || '/'
            return candidatePath.startsWith(`${bare}/`) && hasDynamicIdSegment(candidatePath)
          })
        : undefined
      const csrfFields = [...new Set([...observedFields, ...(siblingHarvest?.fields ?? [])])]
      const csrfValues: Record<string, string[]> = { ...(siblingHarvest?.values ?? {}), ...observedValues }
      const stateField = csrfFields.find(field => /^(?:name|title|label|company|timezone|email|status|state|plan|tier|enabled|active|value|notifications|digest|locale|language|amount|total|price)$/i.test(field))
        ?? csrfFields.find(field => typeof csrfValues[field]?.[0] === 'string' && !/(?:^|_)id$/i.test(field))
      const createReadTemplate = createDetail ? (createDetail.pathTemplate.split('?')[0] || '') : undefined
      if ((getSibling && stateField) || createReadTemplate) {
        const bodyField = stateField ?? (/refund|payment|credit|transfer|amount|price/i.test(bare) ? 'amount' : 'value')
        add({
          key: `csrf_state_change|${endpoint.id}|${stateField}`,
          endpoint,
          probeClass: 'csrf_state_change',
          intent: 'csrf',
          method: 'POST',
          pathAndQuery: resolvedPath,
          readPath: getSibling
            ? (getSibling.pathTemplate.split('?')[0] || '/').replace(idSegmentRe, `/${encodeURIComponent(ownerId)}`)
            : resolvedPath,
          stateField: stateField ?? bodyField,
          bodyField,
          ...(createReadTemplate ? { createReadTemplate } : {}),
          session: 'csrf',
          ownerPersona: picks.owner?.handle,
          jsonBody: siblingBody(csrfFields, csrfValues, bodyField),
          risk: endpointRiskScore(endpoint) + 8,
        })
      }
    }

    // --- Credential exposure on a read surface ----------------------------------------------
    // A read that the target itself publishes credential-shaped values from is scanned with a
    // non-entitled viewer actor; the anonymous denial in the same matrix is the control. The
    // selection is response-evidence driven (secret fingerprints) or a credential-surface route.
    const credentialSurface = /(?:^|\/)(?:tokens?|keys?|apikeys?|links?|integrations?|audit|auditlog|activity|logs?|config|settings|credentials?|secrets?|exports?)(?:\/|$)/i.test(bare)
    const secretEvidence = (observedEvidence.sensitiveFields?.length ?? 0) > 0 ||
      (observedEvidence.headerNames ?? []).some(name => /^(?:set-cookie|authorization|x-api-key)$/i.test(name))
    if (method === 'GET' && (credentialSurface || secretEvidence)) {
      add({
        key: `secret_disclosure|${endpoint.id}`,
        endpoint,
        probeClass: 'authz_matrix',
        intent: 'secret_disclosure',
        method: 'GET',
        pathAndQuery: resolvedPath,
        ownerPersona: picks.owner?.handle,
        functionLevel: !hasIdPath && !objectIdParam,
        secretScan: true,
        ...((picks.lower?.handle ?? picks.crossTenant?.handle)
          ? { viewerPersona: (picks.lower?.handle ?? picks.crossTenant?.handle)! }
          : {}),
        risk: endpointRiskScore(endpoint) + (credentialSurface ? 34 : 18),
      })
    }

    // --- GraphQL ----------------------------------------------------------------------------
    // Body shape `{query, variables}` identifies a GraphQL endpoint even without a `/graphql` noun.
    const graphqlShaped = method === 'POST' && (
      /graphql/i.test(bare) ||
      (inferred.some(p => p.location === 'json' && /^query$/i.test(p.name)) &&
        inferred.some(p => p.location === 'json' && /^(?:variables|operationName)$/i.test(p.name)))
    )
    if (graphqlShaped && picks.owner && picks.crossTenant) {
      // Introspection is often disabled. Derive candidate root fields from the discovered
      // collection nouns and pair each root with ids read from that collection for both actors.
      const graphqlRoots = new Set<string>()
      const graphqlSeedsByRoot: Record<string, string[]> = {}
      for (const candidate of endpoints) {
        if (candidate.method.toUpperCase() !== 'GET') continue
        const candidatePath = candidate.pathTemplate.split('?')[0] || '/'
        const segments = candidatePath.split('/').filter(segment => segment && !placeholderSeg.test(segment))
        const last = segments[segments.length - 1] ?? ''
        if (!/^[a-z][a-z0-9_-]{2,30}s?$/i.test(last)) continue
        if (/^(?:api|v1|v2|me|session|health|config|settings|admin|search|logs?|audit|csrf|login|logout|tokens?|keys?|hooks?|links?|jobs?|docs?)$/i.test(last)) continue
        const singular = last.replace(/s$/i, '')
        const ids = globalIds(harvests.get(candidate.id), candidate.origin)
        if (ids.length === 0) continue
        for (const root of [singular, last]) {
          graphqlRoots.add(root)
          graphqlSeedsByRoot[root] = ids
        }
      }
      add({
        key: `graphql_audit|${endpoint.id}`,
        endpoint,
        probeClass: 'graphql_audit',
        intent: 'graphql',
        method: 'POST',
        pathAndQuery: bare,
        ownerPersona: picks.owner.handle,
        otherPersona: picks.crossTenant.handle,
        resourceIds: globalIds(harvest, endpoint.origin),
        graphqlRoots: [...graphqlRoots]
          .sort((a, b) => {
            const priority = ['account', 'user', 'organization', 'org', 'team', 'workspace', 'project', 'invoice', 'order', 'customer', 'member', 'ticket', 'issue', 'document', 'file', 'report', 'product']
            const rank = (name: string): number => {
              const idx = priority.findIndex(entry => name.toLowerCase() === entry || name.toLowerCase().replace(/s$/, '') === entry)
              return idx === -1 ? priority.length : idx
            }
            return rank(a) - rank(b) || a.localeCompare(b)
          })
          .slice(0, 12),
        graphqlSeedsByRoot,
        jsonBody: {},
        risk: endpointRiskScore(endpoint) + 25,
      })
    }

    // --- Auth-protocol / JWT ----------------------------------------------------------------
    // Evidence: the target returned 3-segment base64url values (or a session/token surface whose
    // response carries them). The probe mutates the persona's own token; when the persona session
    // is not a JWT, the broker refuses the mutation, so this cannot manufacture a finding.
    const identityClaims: Record<string, string> = {}
    for (const field of ['email', 'mail', 'sub', 'userId', 'id', 'tenant', 'org', 'store', 'workspace', 'team', 'role']) {
      const value = observedValues[field]?.[0]
      if (value && value.length <= 120) identityClaims[field] = value
    }
    const jwtEvidence = options.tier >= 2 && method === 'GET' && picks.owner &&
      ((observedEvidence.jwtValues?.length ?? 0) > 0 || credentialSurface)
    if (jwtEvidence) {
      add({
        key: `auth_protocol|${endpoint.id}`,
        endpoint,
        probeClass: 'auth_protocol_audit',
        intent: 'auth_protocol',
        method: 'GET',
        pathAndQuery: resolvedPath,
        ownerPersona: picks.owner?.handle,
        tokenFields: Object.keys(observedValues).filter(field => /(?:token|jwt|auth|credential)/i.test(field)).slice(0, 3),
        ...(Object.keys(identityClaims).length > 0 ? { identityClaims } : {}),
        risk: endpointRiskScore(endpoint) + 18 +
          ((observedEvidence.jwtValues?.length ?? 0) > 0 ? 40 : 0) +
          (/(?:^|\/)(?:session|tokens?|auth|whoami|me)(?:\/|$)/i.test(bare) ? 16 : 0),
      })
    }

    // --- Webhook signature bypass -----------------------------------------------------------
    // Evidence: a mutating route that declares a signature/HMAC header, or a receiver-shaped write
    // route with a readable detail/collection sibling. Delivery bodies are built from observed
    // fields; the probe itself requires an accepted unsigned delivery plus a read-back/ack.
    const signatureHeader = inferred.find(p => p.location === 'header' && /signature|hmac|^x-.*sig/i.test(p.name))?.name
    const receiverShaped = method === 'POST' && !hasIdPath && !graphqlShaped && !pathHasUrlHint(bare) &&
      (Boolean(signatureHeader) || /(?:webhook|hooks?|receive|deliver|callback|events?)/i.test(bare))
    if (receiverShaped && picks.owner) {
      const delivery: Record<string, unknown> = {}
      for (const field of observedFields.slice(0, 8)) delivery[field] = semanticValue(field, observedValues[field]?.[0])
      if (Object.keys(delivery).length === 0) {
        delivery.event = 'guardian.verification'
        delivery.type = 'guardian.verification'
      }
      const detail = endpoints.find(candidate => {
        const candidatePath = candidate.pathTemplate.split('?')[0] || '/'
        return candidate.origin === endpoint.origin && candidate.method.toUpperCase() === 'GET' &&
          candidatePath.startsWith(`${bare}/`) && hasDynamicIdSegment(candidatePath)
      })
      const stateField = observedFields.find(field => /^(?:status|state|processed|received|ok|count|total|events?)$/i.test(field))
      add({
        key: `webhook_signature_bypass|${endpoint.id}`,
        endpoint,
        probeClass: 'webhook_signature_bypass',
        intent: 'webhook',
        method: 'POST',
        pathAndQuery: resolvedPath,
        ownerPersona: picks.owner?.handle,
        webhookBody: delivery,
        ...(signatureHeader ? { webhookHeader: signatureHeader } : {}),
        ...(detail ? { readPath: (detail.pathTemplate.split('?')[0] || '/').replace(idSegmentRe, `/${encodeURIComponent(ownerId)}`) } : {}),
        ...(stateField ? { stateField } : {}),
        risk: endpointRiskScore(endpoint) + 16 + (/(?:webhook|hooks?|receive|deliver|callback)(?:\/|$)/i.test(bare) ? 34 : 0),
      })
    }

    // --- Mass assignment: create-shaped POST or an identified PATCH/PUT write -----------------
    // A privileged/ownership field written through an ordinary update body is the same overpost
    // class as on create. The route's real method is kept; the object id must be concrete.
    const massPath = method === 'POST' && !hasIdPath
      ? bare
      : (method === 'PATCH' || method === 'PUT')
        ? (idIsLast ? resolvedPath
          : objectIdParam ? `${bare}?${encodeURIComponent(objectIdParam.name)}=${encodeURIComponent(ownerId)}`
            : null)
        : null
    if (massPath) {
      const massFields = observedFields
      const privilegeField = /(role|roles|admin|permission|privilege|grant|level|tenant|tenant_id|owner|owner_id|team|team_id|org|org_id|plan|tier|verified|email_verified|is_admin|visibility|amount|total|price|payment_state|status|state)/i
      const fieldRank = (field: string): number =>
        /role|roles|permission|privilege|grant|admin|tenant|owner|org|team/i.test(field) ? 0
          : /amount|total|price|payment_state|status|state/i.test(field) ? 1 : 2
      const observedPrivilege = massFields.filter(f => privilegeField.test(f))
        .sort((a, b) => fieldRank(a) - fieldRank(b))
      // On an update route, ordinary editable columns (name, amount, status) are not evidence of
      // overposting by themselves. Restrict the PATCH/PUT candidate set to ownership/privilege and
      // settlement fields that are never a normal client-editable property.
      const updateSensitive = /role|roles|permission|permissions|privilege|grant|level|admin|is_admin|isAdmin|tenant|tenant_id|owner|owner_id|team|team_id|org|org_id|plan|tier|verified|email_verified|visibility|payment_state|return_url/i
      const isUpdate = method === 'PATCH' || method === 'PUT'
      const candidateSource = isUpdate
        ? [...massFields.filter(f => updateSensitive.test(f)), 'role', 'permission', 'tenant_id', 'owner_id', 'plan', 'verified']
        : [...observedPrivilege, ...['role', 'permission', 'tenant_id', 'owner_id', 'plan', 'verified']]
      const candidates = [...new Set(candidateSource)]
        .filter(f => /^[A-Za-z0-9_.-]{1,64}$/.test(f)).slice(0, 10)
      const eligible = isUpdate
        ? massFields.some(f => updateSensitive.test(f)) || pathHasPrivilegedHint(bare)
        : observedPrivilege.length > 0 || pathHasPrivilegedHint(bare)
      if (candidates.length > 0 && eligible) {
        const values: Record<string, string | boolean | number> = {}
        for (const field of candidates) {
          const observed = harvest?.otherValues[field]?.[0]
          if (observed !== undefined && observed.length <= 64) values[field] = observed
        }
        // The cross-tenant persona's tenant label is itself a legitimate overpost value even when
        // the collection response does not expose the owning tenant id field.
        if (picks.crossTenant?.tenant && values.tenant_id === undefined) values.tenant_id = picks.crossTenant.tenant
        // A role/privilege write must be performed by a genuinely lower-privileged actor on that
        // actor's own record: an owner editing its own row cannot demonstrate escalation.
        const roleField = candidates.find(f => /^(?:role|roles|permission|permissions|privilege|grant|level|is_admin|isAdmin|admin)$/i.test(f))
        const viewerIds = originViewerIds.get(endpoint.origin) ?? []
        const viewerTarget = isUpdate && roleField && picks.lower && viewerIds.length > 0
          ? viewerIds[0]
          : null
        // The impact monitor evaluates the writer's role after the mutation, so a self-escalation
        // cannot demonstrate an escalation. Choose a colleague from the same collection, skipping
        // the first (owning) record and the viewer's own id.
        const listIds = (harvest?.ownerIds ?? []).filter(id => /^[A-Za-z0-9_.:-]{1,128}$/.test(id))
        const colleagueTarget = viewerTarget
          ? (listIds.filter(id => id !== viewerTarget && id !== listIds[0])[0]
            ?? listIds.find(id => id !== viewerTarget)
            ?? viewerTarget)
          : null
        const roleTarget = colleagueTarget ?? viewerTarget
        const writer = viewerTarget ? picks.lower!.handle : picks.owner?.handle
        const targetPath = roleTarget && hasIdPath
          ? bare.replace(idSegmentRe, `/${encodeURIComponent(roleTarget)}`)
          : massPath
        add({
          key: `mass_assignment|${endpoint.id}`,
          endpoint,
          probeClass: 'mass_assignment',
          intent: 'mass_assignment',
          method: method === 'PATCH' ? 'PATCH' : method === 'PUT' ? 'PUT' : 'POST',
          pathAndQuery: targetPath,
          ownerPersona: writer,
          otherPersona: picks.crossTenant?.handle,
          candidateFields: candidates,
          candidateValues: values,
          jsonBody: siblingBody(massFields, observedValues),
          risk: endpointRiskScore(endpoint) + 10,
        })
      }
    }
  }

  const intentPriority: Record<string, number> = {
    // SQLi is deliberately last: error-based payloads legitimately return 5xx and can trip the
    // broker's defensive circuit, which pauses the run. Every non-5xx class gets its pass first.
    authz: 100, secret_disclosure: 98, graphql: 95, ssti: 94, command_injection: 93, workflow: 92,
    xxe: 90, ssrf: 88, traversal: 85,
    redirect: 75, xss: 65, mass_assignment: 60, stored_xss: 55, cache: 50, csrf: 45, sqli: 10,
  }
  // Quota selection, not a pure global slice: late classes (SQLi in particular) must not be
  // starved when a richer surface forms more authz/xxe/ssrf hypotheses than the cap.
  const baseQuotas: Record<string, number> = {
    // Quotas reserve breadth: an authz-heavy surface must not starve the other classes when the
    // global hypothesis cap is reached.
    authz: 26, secret_disclosure: 5, graphql: 2, xxe: 5, ssrf: 7, traversal: 6, redirect: 6,
    xss: 6, mass_assignment: 6, csrf: 4, cache: 2, stored_xss: 2, workflow: 3, webhook: 2,
    auth_protocol: 2, ssti: 3, command_injection: 3, sqli: 10,
  }
  const baseMax = options.maxHypotheses ?? defaultEngineMaxHypotheses
  // A probe costs ~11 requests (control/probe variants + read-back). Spend the request budget
  // instead of starving late classes behind a fixed hypothesis count.
  const slots = Math.min(150, Math.max(baseMax, Math.floor((options.maxRequests ?? defaultEngineMaxRequests) / 11)))
  const scale = Math.max(1, slots / baseMax)
  const quotas: Record<string, number> = Object.fromEntries(
    Object.entries(baseQuotas).map(([intent, quota]) => [intent, Math.max(quota, Math.ceil(quota * scale))]),
  )
  const max = slots
  const used: Record<string, number> = {}
  const selected: EngineHypothesis[] = []
  for (const hyp of [...all.values()].sort((a, b) =>
    (intentPriority[b.intent] ?? 0) - (intentPriority[a.intent] ?? 0) ||
    b.risk - a.risk ||
    a.key.localeCompare(b.key))) {
    if ((used[hyp.intent] ?? 0) >= (quotas[hyp.intent] ?? 4)) continue
    used[hyp.intent] = (used[hyp.intent] ?? 0) + 1
    selected.push(hyp)
    if (selected.length >= max) break
  }
  return selected
}

// ---------------------------------------------------------------------------------------------
// Harvesting
// ---------------------------------------------------------------------------------------------

interface JsonHarvest {
  ids: string[]
  fields: string[]
  values: Record<string, string[]>
  textValues: string[]
  body: string
  evidence: HarvestEvidence
}

const credentialFieldRe = /(?:^|[_-])(?:access[_-]?token|refresh[_-]?token|api[_-]?key|apikey|secret|secret[_-]?key|client[_-]?secret|password|passwd|private[_-]?key|signing[_-]?key|webhook[_-]?secret|credential|authorization)$/i
const jwtValueRe = /^[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]*$/

function harvestJson(body: string): JsonHarvest {
  const ids: string[] = []
  const values: Record<string, string[]> = {}
  const textValues: string[] = []
  const evidence: HarvestEvidence = {}
  let parsed: unknown
  try { parsed = JSON.parse(body) } catch { return { ids, fields: [], values, textValues, body, evidence } }
  const walk = (node: unknown, depth: number): void => {
    if (depth > 5 || node === null || node === undefined) return
    if (Array.isArray(node)) {
      for (const item of node.slice(0, 30)) walk(item, depth + 1)
      return
    }
    if (typeof node !== 'object') return
    for (const [key, value] of Object.entries(node as Record<string, unknown>)) {
      if (typeof value === 'string' || typeof value === 'number') {
        const stringValue = String(value)
        const idKey = /(?:^|_)(?:id|uuid|uid|sku|slug|key|ref|code|token)$/i.test(key)
        const ownerKey = /(?:^|_)(?:project|owner|tenant|team|org|account|parent|user|member|invoice|order|customer|ticket|issue)$/i.test(key)
        if (idKey && stringValue.length <= 128 && stringValue.length > 0) ids.push(stringValue)
        else if (ownerKey && /^(?:[A-Za-z]{1,8}[-_])?[A-Za-z0-9_.:-]*\d[A-Za-z0-9_.:-]*$/.test(stringValue) && stringValue.length <= 128) ids.push(stringValue)
        const bucket = values[key] ?? []
        if (bucket.length < 4) bucket.push(stringValue)
        values[key] = bucket
        if (/^(?:name|title|label|slug|subject|description|text|term|query|filename|file)$/i.test(key) &&
            stringValue.length >= 3 && stringValue.length <= 48 && !/[<>{}\\]/.test(stringValue)) {
          textValues.push(stringValue)
        }
        // Wire-format and value-shape evidence: a URL value, a JWT-shaped token, a credential field.
        if (/^https?:\/\/[^\s]{1,300}$/i.test(stringValue)) {
          const urls = evidence.urlValues ?? []
          if (urls.length < 4 && !urls.includes(stringValue)) urls.push(stringValue.slice(0, 300))
          evidence.urlValues = urls
        }
        if (jwtValueRe.test(stringValue)) {
          const tokens = evidence.jwtValues ?? []
          if (tokens.length < 2) tokens.push(stringValue)
          evidence.jwtValues = tokens
        }
        if (credentialFieldRe.test(key) && stringValue.length >= 8 && stringValue.length <= 2048 &&
            !/^(?:redacted|\*+|null|undefined|none|false|true)$/i.test(stringValue)) {
          const fields = evidence.sensitiveFields ?? []
          if (fields.length < 6 && !fields.includes(key)) fields.push(key)
          evidence.sensitiveFields = fields
        }
      } else if (value && typeof value === 'object') {
        walk(value, depth + 1)
      }
    }
  }
  walk(parsed, 0)
  return {
    ids: [...new Set(ids)].filter(id => /^[A-Za-z0-9_.:-]{1,128}$/.test(id)),
    fields: [...new Set(Object.keys(values))],
    values,
    textValues: [...new Set(textValues)],
    body,
    evidence,
  }
}

/** Bounded GET harvest of the target's own responses; every exchange is recorded by the caller. */
class SurfaceHarvester {
  private readonly cache = new Map<string, Promise<JsonHarvest>>()
  private readonly inflight = new Set<string>()
  private readonly deps: Pick<DeterministicEngineInput, 'broker' | 'grant' | 'signal' | 'storage' | 'recordExchange'>
  private readonly log: (kind: string, message: string, data?: Record<string, unknown>) => void
  private readonly origin: string

  constructor(
    deps: Pick<DeterministicEngineInput, 'broker' | 'grant' | 'signal' | 'storage' | 'recordExchange'>,
    log: (kind: string, message: string, data?: Record<string, unknown>) => void,
    origin: string,
  ) {
    this.deps = deps
    this.log = log
    this.origin = origin
  }

  get(persona: string | undefined, pathAndQuery: string): Promise<JsonHarvest> {
    const key = `${persona ?? ''}|${pathAndQuery}`
    const cached = this.cache.get(key)
    if (cached) return cached
    const promise = this.fetch(persona, pathAndQuery)
    this.cache.set(key, promise)
    return promise
  }

  private async fetch(persona: string | undefined, pathAndQuery: string): Promise<JsonHarvest> {
    this.inflight.add(pathAndQuery)
    try {
      const exchange = await this.deps.broker.executeHttp({
        origin: this.origin,
        method: 'GET',
        pathAndQuery,
        ...(persona ? { persona } : {}),
        followRedirects: false,
        timeoutMs: 8_000,
      }, this.deps.grant, this.deps.signal)
      if (exchange.status >= 200 && exchange.status < 300) {
        try { this.deps.recordExchange?.(exchange) } catch { /* persistence is best-effort */ }
        const harvested = harvestJson(exchange.body)
        const headers = exchange.respHeaders ?? {}
        const evidence: HarvestEvidence = { ...harvested.evidence }
        if (/attachment|filename=/i.test(headers['content-disposition'] ?? '')) evidence.contentDisposition = true
        if (headers.location) evidence.location = headers.location.slice(0, 300)
        if (/xml/i.test(exchange.mediaType ?? '')) evidence.xml = true
        const headerNames = Object.keys(headers).map(name => name.toLowerCase())
        if (headerNames.length > 0) evidence.headerNames = headerNames.slice(0, 32)
        return { ...harvested, evidence }
      }
      return { ids: [], fields: [], values: {}, textValues: [], body: '', evidence: {} }
    } catch {
      return { ids: [], fields: [], values: {}, textValues: [], body: '', evidence: {} }
    } finally {
      this.inflight.delete(pathAndQuery)
    }
  }
}

function emptyHarvest(): EndpointHarvest {
  return { ownerIds: [], otherIds: [], fields: [], values: {}, otherValues: {}, seedValues: [], activeQueryParams: [], viewerIds: [] }
}

function mergeEvidence(target: EndpointHarvest, next: HarvestEvidence): void {
  if (!next || Object.keys(next).length === 0) return
  const evidence = target.evidence ?? {}
  evidence.contentDisposition = evidence.contentDisposition || next.contentDisposition
  evidence.xml = evidence.xml || next.xml
  if (next.location && !evidence.location) evidence.location = next.location
  for (const key of ['urlValues', 'jwtValues', 'sensitiveFields', 'headerNames'] as const) {
    const incoming = next[key]
    if (!incoming?.length) continue
    const bucket = evidence[key] ?? []
    for (const value of incoming) if (bucket.length < 8 && !bucket.includes(value)) bucket.push(value)
    evidence[key] = bucket
  }
  target.evidence = evidence
}

function mergeHarvest(target: EndpointHarvest, next: JsonHarvest): void {
  for (const id of next.ids) {
    if (!target.ownerIds.includes(id)) target.ownerIds.push(id)
  }
  for (const field of next.fields) if (!target.fields.includes(field)) target.fields.push(field)
  for (const [field, values] of Object.entries(next.values)) {
    const bucket = target.values[field] ?? []
    for (const value of values) if (!bucket.includes(value)) bucket.push(value)
    target.values[field] = bucket.slice(0, 4)
  }
  for (const value of next.textValues) if (!target.seedValues.includes(value)) target.seedValues.push(value)
  mergeEvidence(target, next.evidence)
}

function mergeOtherHarvest(target: EndpointHarvest, next: JsonHarvest): void {
  for (const id of next.ids) {
    if (!target.otherIds.includes(id)) target.otherIds.push(id)
  }
  for (const [field, values] of Object.entries(next.values)) {
    const bucket = target.otherValues[field] ?? []
    for (const value of values) if (!bucket.includes(value)) bucket.push(value)
    target.otherValues[field] = bucket.slice(0, 4)
  }
  mergeEvidence(target, next.evidence)
}

function mergeViewerHarvest(target: EndpointHarvest, next: JsonHarvest): void {
  const ids = target.viewerIds ?? []
  for (const id of next.ids) if (!ids.includes(id)) ids.push(id)
  target.viewerIds = ids.slice(0, 4)
}

async function harvestSurface(
  input: DeterministicEngineInput,
  ranked: readonly EngineEndpoint[],
  harvester: SurfaceHarvester,
  picks: ReturnType<typeof personaPicks>,
  budget: { requestsUsed: number; maxRequests: number },
  log: (kind: string, message: string, data?: Record<string, unknown>) => void,
): Promise<{ harvests: Map<string, EndpointHarvest>; endpointsHarvested: number }> {
  const harvests = new Map<string, EndpointHarvest>()
  let endpointsHarvested = 0
  const owner = picks.owner?.handle
  const other = picks.crossTenant?.handle
  const lower = picks.lower?.handle

  const take = (endpoint: EngineEndpoint): EndpointHarvest => {
    const existing = harvests.get(endpoint.id)
    if (existing) return existing
    const created = emptyHarvest()
    harvests.set(endpoint.id, created)
    endpointsHarvested += 1
    return created
  }

  for (const endpoint of ranked) {
    if (budget.requestsUsed >= budget.maxRequests || input.signal.aborted) break
    if (isStaticOrBaselinePath(endpoint.pathTemplate)) continue
    const bare = endpoint.pathTemplate.split('?')[0] || '/'
    const method = endpoint.method.toUpperCase()
    const collection = collectionPathOf(bare)
    const target = take(endpoint)
    let baseline: JsonHarvest | null = null
    if (method === 'GET' && !hasDynamicIdSegment(bare)) {
      // The route itself is a readable collection/detail page.
      const own = await harvester.get(owner, bare)
      budget.requestsUsed += 1
      mergeHarvest(target, own)
      baseline = own
    }
    if (collection && collection !== '/' && (hasDynamicIdSegment(bare) || method !== 'GET')) {
      const own = await harvester.get(owner, collection)
      budget.requestsUsed += 1
      mergeHarvest(target, own)
      if (other) {
        const theirs = await harvester.get(other, collection)
        budget.requestsUsed += 1
        mergeOtherHarvest(target, theirs)
      }
    }
    // Query-name discovery: a benign value that changes the response identifies the real filter
    // parameter, so later SQLi/traversal/SSRF/XSS probes do not burn their budget on ignored names.
    if (method === 'GET' && baseline && target.activeQueryParams.length === 0) {
      const candidates = inferEndpointParams(endpoint)
        .filter(param => param.location === 'query')
        .filter(param => !hasDynamicIdSegment(param.name))
        .filter(param => pathHasSearchHint(bare) || pathHasFileHint(bare) || pathHasUrlHint(bare) || pathHasRedirectHint(bare))
        .slice(0, 5)
      const sampleFor = (name: string): string => {
        if (pathHasFileHint(bare) || /(?:file|path|name|log|doc)/i.test(name)) return 'guardian.txt'
        if (pathHasUrlHint(bare) || /(?:url|uri|callback|avatar|image|src)/i.test(name)) return 'http://guardian-control.invalid/'
        if (pathHasRedirectHint(bare)) return '/guardian-return'
        return target.seedValues[0] ?? 'guardian'
      }
      for (const candidate of candidates) {
        const separator = bare.includes('?') ? '&' : '?'
        const probePath = `${bare}${separator}${encodeURIComponent(candidate.name)}=${encodeURIComponent(sampleFor(candidate.name))}`
        const probed = await harvester.get(owner, probePath)
        budget.requestsUsed += 1
        mergeHarvest(target, probed)
        const changed = probed.body.length > 0 && (
          baseline.body.length === 0 ||
          responseSimilarity(baseline.body, probed.body) < 0.98
        )
        if (changed && !target.activeQueryParams.includes(candidate.name)) {
          target.activeQueryParams.push(candidate.name)
        }
      }
    }
    // Detail read with a harvested owner id, so field names (body schema) are observable.
    if (hasDynamicIdSegment(bare) && target.fields.length === 0) {
      const detailPath = bare.replace(idSegmentRe, `/${encodeURIComponent(target.ownerIds[0] ?? '1')}`)
      const detail = await harvester.get(owner, detailPath)
      budget.requestsUsed += 1
      mergeHarvest(target, detail)
    }
  }

  // Persona identity endpoints give user ids for object-level routes whose collection is self-only.
  const identityPaths = ranked
    .filter(endpoint => endpoint.method.toUpperCase() === 'GET' && /(?:^|\/)(?:me|session|whoami)(?:\/|$)/i.test(endpoint.pathTemplate))
    .map(endpoint => endpoint.pathTemplate.split('?')[0])
  for (const path of identityPaths.slice(0, 2)) {
    for (const persona of [owner, other, lower]) {
      if (!persona) continue
      const identity = await harvester.get(persona, path)
      budget.requestsUsed += 1
      const target = ranked.find(e => (e.pathTemplate.split('?')[0] || '/') === path)
      if (!target) continue
      const profile = take(target)
      if (persona === owner) mergeHarvest(profile, identity)
      else if (persona === other) mergeOtherHarvest(profile, identity)
      else mergeViewerHarvest(profile, identity)
    }
  }
  log('deterministic_engine.harvest', `Harvested ${endpointsHarvested} endpoint profile(s) with ${budget.requestsUsed} request(s).`)
  return { harvests, endpointsHarvested }
}

// ---------------------------------------------------------------------------------------------
// Execution
// ---------------------------------------------------------------------------------------------

function buildProbeRequest(
  hyp: EngineHypothesis,
  maxRequests: number,
  context: Pick<DeterministicEngineInput, 'runId' | 'assignmentId' | 'storage'>,
): ProbeDifferentialRequest {
  const base: ProbeDifferentialRequest = {
    probeClass: hyp.probeClass,
    origin: hyp.endpoint.origin,
    pathAndQuery: hyp.pathAndQuery,
    method: hyp.method,
    maxRequests,
    runId: context.runId,
    assignmentId: context.assignmentId,
    ...(context.storage ? { storage: context.storage } : {}),
    ...(hyp.ownerPersona ? { persona: hyp.ownerPersona } : {}),
    ...(hyp.session ? { session: hyp.session } : {}),
    ...(hyp.jsonBody ? { jsonBody: hyp.jsonBody } : {}),
    ...(hyp.formBody ? { formBody: hyp.formBody } : {}),
    ...(hyp.xmlTemplate ? { xmlTemplate: hyp.xmlTemplate } : {}),
    ...(hyp.graphqlQuery ? { graphqlQuery: hyp.graphqlQuery } : {}),
  }
  switch (hyp.probeClass) {
    case 'authz_matrix': {
      // Tenant/owner-scoped resources are never legitimately public. Keeping an anonymous row on
      // such a route mostly records a public-cache or middleware fallback and would make the spec
      // synthesizer reject a real cross-tenant read as "public data".
      const path = hyp.endpoint.pathTemplate.split('?')[0] || '/'
      const scoped = /(?:orders?|purchases?|customers?|invoices?|billing|files?|assets?|documents?|accounts?|tickets?|alerts?|notifications?|members?|users?|shipments?|payments?|refunds?|jobs?|logs?|audit|reports?|issues?|links?|groups?|docs?)/i.test(path)
      const publicSurface = /(?:public|shared|preview|storefront|catalog|embed|community|landing|products?|wares?|ratings?|testimonials?|listings?)/i.test(path)
      const includeAnonymous = hyp.functionLevel ? true : !(scoped && !publicSurface)
      return {
        ...base,
        ownerPersona: hyp.ownerPersona,
        otherPersona: hyp.otherPersona,
        resourceIds: hyp.resourceIds ?? [],
        includeAnonymous,
        includeHeaderBypass: false,
        ...(hyp.functionLevel && hyp.jsonBody ? { functionBody: hyp.jsonBody } : {}),
        ...(hyp.secretScan ? { secretScan: true, ...(hyp.viewerPersona ? { viewerPersona: hyp.viewerPersona } : {}) } : {}),
        ...(hyp.csrfBind ? { csrfBind: true } : {}),
      }
    }
    case 'sqli_boolean':
      return {
        ...base,
        ...(hyp.param ? { param: hyp.param.name } : {}),
        paramLocation: hyp.location,
        baselineValue: hyp.baselineValue,
        ...(hyp.location === 'json' ? { jsonBody: hyp.jsonBody ?? {} } : {}),
      }
    case 'ssti_math':
    case 'command_injection':
      return {
        ...base,
        ...(hyp.param ? { param: hyp.param.name } : {}),
        paramLocation: hyp.location ?? 'json',
        ...(hyp.baselineValue ? { baselineValue: hyp.baselineValue } : {}),
        ...(hyp.location === 'json' ? { jsonBody: hyp.jsonBody ?? {} } : {}),
      }
    case 'workflow_invariant':
      return {
        ...base,
        ...(hyp.workflowListPath ? { workflowListPath: hyp.workflowListPath } : {}),
        ...(hyp.workflowReadPath ? { workflowReadPath: hyp.workflowReadPath } : {}),
        ...(hyp.workflowTargetTemplate ? { workflowTargetTemplate: hyp.workflowTargetTemplate } : {}),
        ...(hyp.repeatTransition ? { repeatTransition: true } : {}),
        ...(hyp.quantityField ? { quantityField: hyp.quantityField } : {}),
        jsonBody: hyp.jsonBody ?? {},
      }
    case 'path_traversal_benign':
      return {
        ...base,
        ...(hyp.param ? { param: hyp.param.name } : {}),
        paramLocation: hyp.location ?? 'query',
        ...(hyp.baselineValue ? { baselineValue: hyp.baselineValue } : {}),
      }
    case 'ssrf_canary':
      return {
        ...base,
        ...(hyp.param ? { param: hyp.param.name } : {}),
        paramLocation: hyp.location,
        ssrfParams: hyp.ssrfParams ?? (hyp.param ? [hyp.param.name] : []),
        ...(hyp.param?.location === 'json' || hyp.jsonBody ? { jsonBody: hyp.jsonBody ?? {} } : {}),
        waitMs: 2_500,
      }
    case 'xxe_canary':
      return { ...base, method: 'POST', waitMs: 2_500 }
    case 'graphql_audit':
      return {
        ...base,
        ownerPersona: hyp.ownerPersona,
        otherPersona: hyp.otherPersona,
        resourceIds: hyp.resourceIds ?? [],
        ...(hyp.graphqlRoots ? { graphqlRoots: hyp.graphqlRoots } : {}),
        ...(hyp.graphqlSeedsByRoot ? { graphqlSeedsByRoot: hyp.graphqlSeedsByRoot } : {}),
        maxDepth: 4,
        maxAliases: 3,
      }
    case 'open_redirect_differential':
      return {
        ...base,
        ...(hyp.param ? { param: hyp.param.name } : {}),
        paramLocation: hyp.location ?? 'query',
      }
    case 'xss_context':
      return {
        ...base,
        ...(hyp.param ? { param: hyp.param.name } : {}),
        paramLocation: hyp.location ?? 'query',
      }
    case 'csrf_state_change':
      return {
        ...base,
        method: 'POST',
        ...(hyp.readPath ? { readPath: hyp.readPath, readPathCandidates: [hyp.readPath] } : {}),
        ...(hyp.createReadTemplate ? { createReadTemplate: hyp.createReadTemplate } : {}),
        ...(hyp.stateField ? { stateField: hyp.stateField } : {}),
        ...(hyp.bodyField ? { bodyField: hyp.bodyField } : {}),
        bodyEncodings: ['form', 'json'],
        ...(hyp.session ? { session: hyp.session } : {}),
      }
    case 'csrf_state_change':
      return {
        ...base,
        method: 'POST',
        ...(hyp.readPath ? { readPath: hyp.readPath, readPathCandidates: [hyp.readPath] } : {}),
        ...(hyp.createReadTemplate ? { createReadTemplate: hyp.createReadTemplate } : {}),
        ...(hyp.stateField ? { stateField: hyp.stateField } : {}),
        ...(hyp.bodyField ? { bodyField: hyp.bodyField } : {}),
        bodyEncodings: ['form', 'json'],
        ...(hyp.session ? { session: hyp.session } : {}),
      }
    case 'mass_assignment':
      return {
        ...base,
        method: hyp.method === 'PATCH' || hyp.method === 'PUT' ? hyp.method : 'POST',
        paramLocation: 'json',
        candidateFields: hyp.candidateFields ?? [],
        jsonBody: hyp.jsonBody ?? {},
      }
    case 'auth_protocol_audit':
      return {
        ...base,
        ...(hyp.tokenFields?.length ? { tokenFields: hyp.tokenFields } : {}),
        ...(hyp.identityClaims ? { identityClaims: hyp.identityClaims } : {}),
      }
    case 'webhook_signature_bypass':
      return {
        ...base,
        method: 'POST',
        webhookBody: hyp.webhookBody ?? {},
        ...(hyp.webhookHeader ? { webhookHeader: hyp.webhookHeader } : {}),
        ...(hyp.readPath ? { readPath: hyp.readPath } : {}),
        ...(hyp.stateField ? { readStateField: hyp.stateField } : {}),
      }
    default:
      return base
  }
}


function extractCreatedId(body: string): string | null {
  let parsed: unknown
  try { parsed = JSON.parse(body) } catch { return null }
  let fallback: string | null = null
  const walk = (node: unknown, depth: number): string | null => {
    if (depth > 4 || !node || typeof node !== 'object') return null
    if (Array.isArray(node)) {
      for (const item of node.slice(0, 5)) {
        const found = walk(item, depth + 1)
        if (found) return found
      }
      return null
    }
    for (const [key, value] of Object.entries(node as Record<string, unknown>)) {
      if ((typeof value === 'string' || typeof value === 'number') &&
          /^(?:id|webhookId|hookId|resourceId|uid|uuid)$/i.test(key)) return String(value)
      if (typeof value === 'string' && /^[A-Za-z0-9_.:-]{1,128}$/.test(value) && !fallback) fallback = value
      if (value && typeof value === 'object') {
        const found = walk(value, depth + 1)
        if (found) return found
      }
    }
    return null
  }
  return walk(parsed, 0) ?? fallback
}

/**
 * Second-order SSRF: register a canary URL through the write route, then trigger the application's
 * own fetch step. The probe layer (`surface-engine`) only covers first-order sinks, so the engine
 * performs this bounded two-step lifecycle itself and hands the same `canary_callback` anomaly to
 * the normal spec synthesizer.
 */
async function probeSecondOrderSsrf(
  hyp: EngineHypothesis,
  input: DeterministicEngineInput,
  track: (exchange: BrokerExchangeResult) => string | void,
): Promise<DifferentialResult> {
  const started = Date.now()
  const base: DifferentialResult = {
    probeClass: 'ssrf_canary',
    origin: hyp.endpoint.origin,
    pathAndQuery: hyp.endpoint.pathTemplate,
    verdict: 'no_signal',
    summary: 'No out-of-band callback was observed from the stored URL.',
    anomalies: [],
    details: {},
    requestsSent: 0,
    exchangeIds: [],
    stoppedReason: null,
    notes: [],
    durationMs: 0,
  }
  const canaryBroker = input.canaryBroker
  const param = hyp.param
  const trigger = hyp.triggerPath
  if (!canaryBroker || !param || !trigger) return { ...base, durationMs: Date.now() - started }
  let info = canaryBroker.listenerInfo()
  if (!info.running) info = await canaryBroker.startListener()
  const exchangeIds: string[] = []
  let requests = 0
  const send = async (pathAndQuery: string, value: string): Promise<BrokerExchangeResult | null> => {
    const body = { ...(hyp.jsonBody ?? {}), [param.name]: value }
    try {
      const exchange = await input.broker.executeHttp({
        origin: hyp.endpoint.origin,
        method: 'POST',
        pathAndQuery,
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
        ...(hyp.ownerPersona ? { persona: hyp.ownerPersona } : {}),
        runId: input.runId,
        assignmentId: input.assignmentId,
        followRedirects: false,
        timeoutMs: 8_000,
      }, input.grant, input.signal)
      requests += 1
      const id = track(exchange)
      if (typeof id === 'string') exchangeIds.push(id)
      return exchange
    } catch {
      requests += 1
      return null
    }
  }
  const triggerFetch = async (resourceId: string): Promise<void> => {
    const path = trigger.replace('{{id}}', encodeURIComponent(resourceId))
    try {
      const exchange = await input.broker.executeHttp({
        origin: hyp.endpoint.origin,
        method: 'POST',
        pathAndQuery: path,
        headers: { 'Content-Type': 'application/json' },
        body: '{}',
        ...(hyp.ownerPersona ? { persona: hyp.ownerPersona } : {}),
        runId: input.runId,
        assignmentId: input.assignmentId,
        followRedirects: false,
        timeoutMs: 8_000,
      }, input.grant, input.signal)
      requests += 1
      const id = track(exchange)
      if (typeof id === 'string') exchangeIds.push(id)
    } catch {
      requests += 1
    }
  }

  const control = await send(hyp.pathAndQuery, 'http://guardian-control.invalid/')
  const controlId = control ? extractCreatedId(control.body) : null
  if (controlId) await triggerFetch(controlId)

  const minted = canaryBroker.mintCanary(
    input.runId,
    `engine:ssrf:${param.name}`,
    hyp.endpoint.origin,
    input.storage ? { storage: input.storage, assignmentId: input.assignmentId } : undefined,
  )
  const probe = await send(hyp.pathAndQuery, minted.httpUrl)
  const probeId = probe ? extractCreatedId(probe.body) : null
  if (probeId) await triggerFetch(probeId)

  const deadline = Date.now() + 3_000
  let hit = false
  while (!input.signal.aborted) {
    const check = canaryBroker.checkCanary(minted.token, input.storage ? { storage: input.storage, runId: input.runId } : undefined)
    if (check.hit) { hit = true; break }
    if (Date.now() >= deadline) break
    await new Promise<void>(resolve => setTimeout(resolve, 200))
  }
  if (hit) {
    return {
      ...base,
      verdict: 'signal',
      summary: 'The stored URL was fetched by the target after the trigger step (second-order SSRF callback).',
      anomalies: [{ type: 'canary_callback', variant: 'http', param: param.name }],
      details: { secondOrder: true, requests },
      requestsSent: requests,
      exchangeIds,
      durationMs: Date.now() - started,
    }
  }
  return { ...base, requestsSent: requests, exchangeIds, details: { secondOrder: true, requests }, durationMs: Date.now() - started }
}


const credentialPatterns: ReadonlyArray<RegExp> = [
  /\brb[cst]_[A-Za-z0-9]+_[0-9a-f]{12}\b/,
  /\bAKIA[0-9A-Z]{16}\b/,
  /\bsk_(?:live|test)_[A-Za-z0-9]{16,}\b/,
  /\bghp_[A-Za-z0-9]{20,}\b/,
  /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/,
]
const sensitiveFieldName = /^(?:secret|client[_-]?secret|api[_-]?key|apikey|access[_-]?token|refresh[_-]?token|password|private[_-]?key|token|webhook[_-]?secret|provider[_-]?key)$/i
const maskedValue = /[*…]|\[redacted\]|^x{4,}$/i

interface SensitiveField { field: string; length: number }

function findSensitiveField(body: string): SensitiveField | null {
  let parsed: unknown
  try { parsed = JSON.parse(body) } catch { parsed = null }
  const visit = (node: unknown, depth: number): SensitiveField | null => {
    if (depth > 5 || !node || typeof node !== 'object') return null
    if (Array.isArray(node)) {
      for (const item of node.slice(0, 20)) {
        const found = visit(item, depth + 1)
        if (found) return found
      }
      return null
    }
    for (const [key, value] of Object.entries(node as Record<string, unknown>)) {
      if (typeof value === 'string' && sensitiveFieldName.test(key) && value.length >= 10 && !maskedValue.test(value)) {
        return { field: key, length: value.length }
      }
      if (value && typeof value === 'object') {
        const found = visit(value, depth + 1)
        if (found) return found
      }
    }
    return null
  }
  return visit(parsed, 0)
}

/**
 * Credential-inventory disclosure. Two generic shapes:
 *  - integration/connector lists return a `secret` field for the caller's own team;
 *  - token/key inventories expose a raw secret while their compact/preview control masks it.
 * The latter requires a masked control before the spec is built, which keeps endpoints that always
 * return masked metadata from being reported.
 */
async function probeSecretExposure(
  hyp: EngineHypothesis,
  input: DeterministicEngineInput,
  track: (exchange: BrokerExchangeResult) => void | string,
): Promise<DifferentialResult> {
  const started = Date.now()
  const base: DifferentialResult = {
    probeClass: 'authz_matrix',
    origin: hyp.endpoint.origin,
    pathAndQuery: hyp.pathAndQuery,
    verdict: 'no_signal',
    summary: 'No unmasked credential-shaped value was returned.',
    anomalies: [],
    details: {},
    requestsSent: 0,
    exchangeIds: [],
    stoppedReason: null,
    notes: [],
    durationMs: 0,
  }
  const exchangeIds: string[] = []
  let requests = 0
  const get = async (path: string): Promise<BrokerExchangeResult | null> => {
    try {
      const exchange = await input.broker.executeHttp({
        origin: hyp.endpoint.origin,
        method: 'GET',
        pathAndQuery: path,
        ...(hyp.ownerPersona ? { persona: hyp.ownerPersona } : {}),
        followRedirects: false,
        timeoutMs: 8_000,
      }, input.grant, input.signal)
      requests += 1
      const id = track(exchange)
      if (typeof id === 'string') exchangeIds.push(id)
      return exchange
    } catch { requests += 1; return null }
  }
  const integrationSurface = /(?:links?|integrations?|connectors?)/i.test(hyp.endpoint.pathTemplate)
  const probePaths: string[] = []
  if (hyp.param) {
    for (const id of (hyp.resourceIds ?? []).slice(0, 4)) {
      const separator = hyp.pathAndQuery.includes('?') ? '&' : '?'
      probePaths.push(`${hyp.pathAndQuery}${separator}${encodeURIComponent(hyp.param.name)}=${encodeURIComponent(id)}`)
    }
  }
  probePaths.push(hyp.pathAndQuery)
  for (const path of [...new Set(probePaths)]) {
    const probe = await get(path)
    if (!probe || probe.status < 200 || probe.status >= 300) continue
    const raw = findSensitiveField(probe.body)
    const literal = credentialPatterns.find(candidate => candidate.test(probe.body))
    if (!raw && !literal) continue
    let controlPath = '/'
    if (!integrationSurface) {
      // Prefer a documented compact/preview toggle; without a masked control there is no proof
      // that the value is meant to be hidden.
      const separator = path.includes('?') ? '&' : '?'
      const control = await get(`${path}${separator}reveal=0`)
      if (!control || control.status < 200 || control.status >= 300) continue
      if (!findSensitiveField(control.body) && !credentialPatterns.some(candidate => candidate.test(control.body))) {
        return {
          ...base,
          verdict: 'signal',
          summary: 'The raw credential is exposed while the compact/preview control masks it.',
          anomalies: [{ type: 'secret_disclosed', path, controlPath: `${path}${separator}reveal=0`, ...(raw ? { field: raw.field } : { pattern: literal?.source }) }],
          details: { mode: 'reveal_toggle', field: raw?.field ?? null },
          requestsSent: requests,
          exchangeIds,
          durationMs: Date.now() - started,
        }
      }
      continue
    }
    return {
      ...base,
      verdict: 'signal',
      summary: 'A connector/integration read returned an unmasked credential field.',
      anomalies: [{ type: 'secret_disclosed', path, controlPath, ...(raw ? { field: raw.field } : { pattern: literal?.source }) }],
      details: { mode: 'integration_secret', field: raw?.field ?? null },
      requestsSent: requests,
      exchangeIds,
      durationMs: Date.now() - started,
    }
  }
  return { ...base, requestsSent: requests, exchangeIds, durationMs: Date.now() - started }
}

function classStats(report: DeterministicEngineReport, intent: string): EngineClassStats {
  const existing = report.byClass[intent]
  if (existing) return existing
  const created: EngineClassStats = { hypotheses: 0, signals: 0, specs: 0, confirmed: 0, rejected: 0, requests: 0 }
  report.byClass[intent] = created
  return created
}

export async function runDeterministicEngine(input: DeterministicEngineInput): Promise<DeterministicEngineReport> {
  const started = Date.now()
  const maxRequests = Math.max(0, input.maxRequests ?? defaultEngineMaxRequests)
  const maxDurationMs = Math.max(1_000, input.maxDurationMs ?? defaultEngineMaxDurationMs)
  const log = input.log ?? (() => {})
  const conventionalWordlist = conventionalWordlistEnabled()
  const report: DeterministicEngineReport = {
    requestsUsed: 0,
    durationMs: 0,
    endpointsConsidered: 0,
    endpointsHarvested: 0,
    hypothesesFormed: 0,
    hypothesesRun: 0,
    signals: 0,
    specsSubmitted: 0,
    confirmed: 0,
    rejectedSpecs: 0,
    leads: 0,
    stoppedReason: 'complete',
    byClass: {},
    confirmedPairs: [],
    touchedPairs: [],
    conventionalWordlist,
    notes: [],
  }

  if (!deterministicEngineEnabled() || input.tier < 1) {
    report.stoppedReason = 'disabled'
    report.durationMs = Date.now() - started
    return report
  }

  const candidateEndpoints = engineWordlistSurface(input.endpoints, conventionalWordlist)
  if (!conventionalWordlist && candidateEndpoints.length !== input.endpoints.length) {
    report.notes.push(`conventional wordlist OFF: ${input.endpoints.length - candidateEndpoints.length} wordlist-only endpoint(s) excluded`)
  }
  const ranked = rankEndpoints(collapseRouteVariants(candidateEndpoints)).slice(0, input.maxEndpoints ?? defaultEngineMaxEndpoints)
  report.endpointsConsidered = ranked.length
  if (ranked.length === 0) {
    report.durationMs = Date.now() - started
    return report
  }

  const picks = personaPicks(input.personas)
  const origins = [...new Set(ranked.map(endpoint => endpoint.origin))]
  const budget = { requestsUsed: 0, maxRequests }
  /** Every brokered request (harvest, probe, replay) counts against the engine's request cap. */
  const trackExchange = (exchange: BrokerExchangeResult): string | void => {
    budget.requestsUsed += 1
    report.requestsUsed = budget.requestsUsed
    return input.recordExchange?.(exchange)
  }

  // Harvest each origin independently (the engine is per-run but a run may carry several assets).
  const harvests = new Map<string, EndpointHarvest>()
  for (const origin of origins) {
    if (budget.requestsUsed >= maxRequests || input.signal.aborted) break
    const originEndpoints = ranked.filter(endpoint => endpoint.origin === origin)
    const harvester = new SurfaceHarvester({ ...input, recordExchange: trackExchange }, log, origin)
    const result = await harvestSurface(input, originEndpoints, harvester, picks, budget, log)
    report.endpointsHarvested += result.endpointsHarvested
    for (const [id, harvest] of result.harvests) harvests.set(id, harvest)
  }

  const hypotheses = enumerateHypotheses(ranked, harvests, {
    tier: input.tier,
    personas: input.personas,
    maxHypotheses: input.maxHypotheses ?? defaultEngineMaxHypotheses,
    maxRequests,
    ...(input.classes ? { classes: input.classes } : {}),
  })
  report.hypothesesFormed = hypotheses.length
  report.touchedPairs = [...new Set(hypotheses.map(hyp =>
    `${normalizeEndpointTemplate(hyp.endpoint.pathTemplate)}|${intentFamily(hyp.intent)}`))]
  for (const hyp of hypotheses) classStats(report, hyp.intent).hypotheses += 1

  const perProbeRequestFloor = 6
  const probeSlots = Math.min(150, Math.max(defaultEngineMaxHypotheses, Math.floor(maxRequests / 11)))
  const capScale = Math.max(1, probeSlots / defaultEngineMaxHypotheses)
  const cap = (value: number): number => Math.max(value, Math.ceil(value * capScale))
  const intentCaps: Record<string, number> = {
    authz: cap(26),
    secret_disclosure: cap(5),
    sqli: cap(10),
    traversal: cap(6),
    ssrf: cap(6),
    xxe: cap(4),
    redirect: cap(6),
    xss: cap(6),
    graphql: cap(2),
    mass_assignment: cap(6),
    csrf: cap(4),
    workflow: cap(3),
    ssti: cap(3),
    command_injection: cap(3),
    webhook: cap(2),
    auth_protocol: cap(2),
  }
  const intentUsed: Record<string, number> = {}
  for (const hyp of hypotheses) {
    if (input.signal.aborted) { report.stoppedReason = 'aborted'; break }
    if (Date.now() - started >= maxDurationMs) { report.stoppedReason = 'time'; break }
    if (budget.requestsUsed >= maxRequests) { report.stoppedReason = 'budget'; break }
    const remaining = maxRequests - budget.requestsUsed
    if (remaining < perProbeRequestFloor) { report.stoppedReason = 'budget'; break }
    const cap = intentCaps[hyp.intent] ?? 6
    if ((intentUsed[hyp.intent] ?? 0) >= cap) continue
    intentUsed[hyp.intent] = (intentUsed[hyp.intent] ?? 0) + 1

    const stats = classStats(report, hyp.intent)
    const maxProbeRequests = Math.max(perProbeRequestFloor, Math.min(defaultEnginePerProbeRequests, remaining))
    let probe: DifferentialResult
    try {
      probe = hyp.intent === 'secret_disclosure' && !hyp.secretScan && !input.probe
        ? await probeSecretExposure(hyp, input, trackExchange)
        : hyp.probeClass === 'ssrf_canary' && hyp.triggerPath && input.canaryBroker && !input.probe
          ? await probeSecondOrderSsrf(hyp, input, trackExchange)
          : await (input.probe ?? probeDifferential)(
              { ...buildProbeRequest(hyp, maxProbeRequests, input), onExchange: trackExchange },
              input.broker, input.grant, input.canaryBroker, input.signal,
            )
    } catch (error) {
      const message = error instanceof Error ? error.message.slice(0, 200) : String(error).slice(0, 200)
      report.notes.push(`${hyp.probeClass} ${hyp.endpoint.pathTemplate}: ${message}`)
      log('deterministic_engine.probe_error', `${hyp.probeClass} ${hyp.method} ${hyp.endpoint.pathTemplate}: ${message}`, {
        intent: hyp.intent, endpoint: hyp.endpoint.pathTemplate, method: hyp.method,
      })
      if (/outside the current assignment scope|run is paused|circuit is open/i.test(message)) {
        report.stoppedReason = 'aborted'
        break
      }
      continue
    }
    report.hypothesesRun += 1
    stats.requests += probe.requestsSent
    log('deterministic_engine.probe', `${hyp.probeClass} ${hyp.method} ${hyp.endpoint.pathTemplate}${hyp.param ? ` param=${hyp.param.name}` : ''} -> ${probe.verdict}`, {
      intent: hyp.intent,
      probeClass: hyp.probeClass,
      endpoint: hyp.endpoint.pathTemplate,
      method: hyp.method,
      param: hyp.param?.name ?? null,
      verdict: probe.verdict,
      requests: probe.requestsSent,
      anomalies: probe.anomalies.map(anomaly => String(anomaly.type)).slice(0, 6),
      stoppedReason: probe.stoppedReason,
      summary: probe.summary.slice(0, 200),
    })
    if (probe.verdict !== 'signal') continue
    report.signals += 1
    stats.signals += 1

    const candidates = synthesizeEngineSpecs(hyp, probe).slice(0, 3)
    if (candidates.length === 0) {
      log('deterministic_engine.spec_skipped', `${hyp.probeClass} ${hyp.endpoint.pathTemplate}: signal had no schema-valid replay shape (${probe.anomalies.map(a => String(a.type)).join(',') || 'no anomaly'})`, {
        intent: hyp.intent,
        endpoint: hyp.endpoint.pathTemplate,
      })
    }
    let confirmedThisHypothesis = false
    for (const candidate of candidates) {
      if (input.signal.aborted || budget.requestsUsed >= maxRequests) break
      const parsed = declarativeReplaySpecSchema.safeParse(candidate.spec)
      if (!parsed.success) {
        log('deterministic_engine.spec_invalid', `${hyp.probeClass} ${hyp.endpoint.pathTemplate}: ${parsed.error.issues[0]?.path.join('.') ?? 'schema'} ${parsed.error.issues[0]?.message ?? ''}`.slice(0, 300), {
          intent: hyp.intent, endpoint: hyp.endpoint.pathTemplate,
        })
        continue
      }
      report.specsSubmitted += 1
      stats.specs += 1
      let replay: ReplayVerificationResult
      try {
        replay = await (input.verify ?? verifyReplaySpec)({
          spec: parsed.data,
          broker: input.broker,
          ...(input.browser ? { browser: input.browser } : {}),
          ...(input.canaryBroker ? { canaryBroker: input.canaryBroker } : {}),
          backend: input.backend,
          ...(input.reposDir ? { reposDir: input.reposDir } : {}),
          grant: input.grant,
          signal: input.signal,
          ...(input.storage ? { storage: input.storage } : {}),
          runId: input.runId,
          assignmentId: input.assignmentId,
          onExchange: trackExchange,
        })
      } catch (error) {
        report.notes.push(`verify ${candidate.kind} ${hyp.endpoint.pathTemplate}: ${error instanceof Error ? error.message.slice(0, 160) : String(error).slice(0, 160)}`)
        continue
      }
      if (replay.verdict !== 'confirmed') {
        log('deterministic_engine.spec_rejected', `${candidate.kind} ${hyp.endpoint.pathTemplate} -> ${replay.verdict}: ${(replay.outcome.reason ?? replay.outcome.observed).slice(0, 200)}`, {
          intent: hyp.intent, endpoint: hyp.endpoint.pathTemplate, kind: candidate.kind,
          verdict: replay.verdict, controlPassed: replay.outcome.controlPassed,
        })
        report.rejectedSpecs += 1
        stats.rejected += 1
        continue
      }
      const vulnClass = candidate.vulnClass || vulnClassOfSpec(parsed.data as unknown as Record<string, unknown>)
      let persistedId: string | null = null
      try {
        persistedId = await input.onConfirmed({
          hypothesis: hyp,
          spec: parsed.data,
          specRecord: candidate,
          vulnClass,
          endpoint: hyp.endpoint.pathTemplate,
          result: replay,
          exchangeIds: [...new Set([...probe.exchangeIds, ...replay.exchangeIds])],
        })
      } catch (error) {
        report.notes.push(`persist ${candidate.kind} ${hyp.endpoint.pathTemplate}: ${error instanceof Error ? error.message.slice(0, 160) : String(error).slice(0, 160)}`)
        continue
      }
      // A null return means the persistence layer recognized a structural duplicate; do not count
      // it as a new confirmation (and stop trying lower-priority specs for this hypothesis).
      confirmedThisHypothesis = true
      if (!persistedId) continue
      report.confirmed += 1
      stats.confirmed += 1
      report.confirmedPairs.push({ endpoint: hyp.endpoint.pathTemplate, vulnClass })
      break
    }
    if (!confirmedThisHypothesis && candidates.length > 0) {
      report.leads += 1
      try {
        input.onLead?.({
          hypothesis: hyp,
          probe,
          summary: probe.summary.slice(0, 240),
        })
      } catch { /* lead emission is best-effort */ }
    }
  }

  if (report.stoppedReason === 'complete' && (Date.now() - started >= maxDurationMs)) report.stoppedReason = 'time'
  report.durationMs = Date.now() - started
  return report
}

// ---------------------------------------------------------------------------------------------
// Hide-confirmed helpers (shared with the Execution specialist queue)
// ---------------------------------------------------------------------------------------------

export function endpointClassPairKey(endpoint: string, vulnClass: string): string {
  return `${endpoint}|${vulnClass}`
}

/** Class -> wording that specialist queue entries use. */
export function engineClassKeywords(vulnClass: string): string[] {
  switch (vulnClass) {
    case 'bola': case 'idor': case 'bfla': case 'authz':
      return ['access-control', 'authorization', 'authorisation', 'idor', 'bola', 'bfla', 'tenant', 'object-level', 'privilege escalation']
    case 'sqli': return ['sql', 'injection-input']
    case 'xxe': return ['xxe', 'xml external', 'xml entity']
    case 'ssrf': return ['ssrf', 'server-side request']
    case 'path_traversal': return ['traversal', 'path traversal', 'directory']
    case 'open_redirect': return ['redirect', 'open-redirect']
    case 'xss_reflected': case 'xss_stored': return ['xss', 'cross-site scripting', 'script injection']
    case 'graphql_bola': return ['graphql', 'resolver']
    case 'mass_assignment': return ['mass assignment', 'mass-assignment', 'overpost']
    case 'ssti': return ['ssti', 'template injection', 'template']
    case 'command_injection': return ['command injection', 'os command', 'rce', 'shell']
    case 'workflow_bypass': return ['workflow', 'step skip', 'business logic']
    case 'cache_poisoning': case 'cache_deception': return ['cache']
    case 'csrf': return ['csrf', 'state change']
    default: return [vulnClass]
  }
}

/** Normalise a path template to the static prefix a queue entry would mention. */
export function stableEndpointKey(endpoint: string): string {
  return endpoint.split('?')[0]
    .replace(/\/:[^/]+/g, '')
    .replace(/\/\{[^}]+\}/g, '')
    .toLowerCase()
}

/** True when a specialist step's text already covers a deterministic (endpoint, class) confirmation. */
export function stepCoveredByConfirmedPairs(stepText: string, pairs: Iterable<string>): boolean {
  const text = stepText.toLowerCase()
  for (const pair of pairs) {
    const idx = pair.lastIndexOf('|')
    if (idx <= 0) continue
    const endpoint = pair.slice(0, idx)
    const vulnClass = pair.slice(idx + 1)
    const endpointKey = stableEndpointKey(endpoint)
    if (!endpointKey || endpointKey === '/') continue
    if (!text.includes(endpointKey)) continue
    if (engineClassKeywords(vulnClass).some(keyword => text.includes(keyword))) return true
  }
  return false
}

// ---------------------------------------------------------------------------------------------
// Class-family helpers shared with the agentic scope guard
// ---------------------------------------------------------------------------------------------

export function intentFamily(intent: string): string {
  switch (intent) {
    case 'authz': case 'graphql': return 'authz'
    case 'sqli': return 'sqli'
    case 'xxe': return 'xxe'
    case 'ssrf': return 'ssrf'
    case 'traversal': return 'traversal'
    case 'redirect': return 'redirect'
    case 'xss': case 'stored_xss': return 'xss'
    case 'mass_assignment': return 'mass_assign'
    case 'csrf': return 'csrf'
    case 'cache': return 'cache'
    case 'secret_disclosure': return 'disclosure'
    case 'workflow': return 'logic'
    case 'ssti': return 'ssti'
    case 'command_injection': return 'cmdi'
    case 'webhook': return 'webhook'
    case 'auth_protocol': return 'auth'
    default: return intent
  }
}

export function specClassFamily(cwe: string | undefined, kind: string | undefined): string | null {
  if (kind === 'static_ast_proof') return null
  const n = Number(/(\d+)/.exec(cwe ?? '')?.[1] ?? NaN)
  if (!Number.isFinite(n)) return kind === 'http_chain' ? null : null
  if ([639, 284, 285, 862, 863, 566].includes(n)) return 'authz'
  if ([89, 564, 943].includes(n)) return 'sqli'
  if ([79, 80, 83].includes(n)) return 'xss'
  if (n === 918) return 'ssrf'
  if ([611, 776].includes(n)) return 'xxe'
  if ([22, 23, 35, 73].includes(n)) return 'traversal'
  if (n === 601) return 'redirect'
  if (n === 915) return 'mass_assign'
  if (n === 352) return 'csrf'
  if ([200, 359, 522, 532].includes(n)) return 'disclosure'
  if ([524, 525, 444, 349].includes(n)) return 'cache'
  if ([840, 841].includes(n)) return 'logic'
  if ([362, 367].includes(n)) return 'race'
  if ([345, 347, 327, 1270].includes(n)) return 'token'
  if ([287, 306, 288, 290].includes(n)) return 'auth'
  if ([77, 78, 88].includes(n)) return 'command'
  if ([1336, 94, 95].includes(n)) return 'ssti'
  return null
}
