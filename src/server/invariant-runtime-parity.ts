/** Runtime Parity Adapter & Shared Normalization Primitives for v8 Layer 2 Invariant Synthesis. */
import { createHash } from 'node:crypto'
import { classifyStructuralFieldEdgeKind, isOpaqueResourceId, type ResponseSignalEdgeKind } from './resource-harvest.ts'
import type {
  CapabilityKind,
  CapabilitySeedRecord,
  CapabilitySurface,
  HypothesisSeverity,
  InvariantHypothesis,
  InvariantHypothesisKind,
  LifecyclePatternKind,
  PersonaSurfaceObservation,
  RuntimeApiDependency,
  RuntimeDiscoveryInput,
  RuntimeGraphqlCatalog,
  RuntimeInvariantParityResult,
  RuntimeOpenApiOperation,
  RuntimeSpaRoute,
} from './invariant-synthesizer.ts'

const WRAPPER_SEG_RE = /^(?:v\d+(?:\.\d+)?|api|rest|rpc|internal|private|public|external|edge|app|portal|admin|batch|bulk|stream|events|sse|ws|socket|graphql|gql|async|jobs|workers|exports|webhooks|callbacks|hooks|files|storage|download|upload|search)$/i
const PUBLIC_EXEMPT_RE = /\/(?:login|signin|sign-in|register|signup|sign-up|logout|health|healthz|ready|readyz|livez|metrics|status|ping|jwks|\.well-known|openid-configuration|favicon)(?:\/|[?#]|$)/i
const STATIC_ASSET_EXT_RE = /\.(?:png|svg|jpe?g|webp|gif|ico|css|m?js|map|woff2?|ttf|eot|avif|mp4|webm|pdf|txt|xml)(?:[?#]|$)/i
const STATIC_ASSET_PREFIX_RE = /^\/(?:_next\/static\/|_next\/image(?:\/|[?#]|$)|static\/|assets\/|images\/|fonts\/|favicon(?:[./?#]|$))/i
const ANONYMOUS_PERSONA_RE = /^(?:|anonymous|anon|unauthenticated|public)$/i
const WCD_SENSITIVE_PATH_RE = /\/(?:profile|account|users?|me|settings|billing|orders?|invoices?|secrets?)\//i
export const BATCH_HINT_RE = /(?:\/(?:batch|bulk|multi)(?:\/|$)|batch[A-Z_]|bulk[A-Z_]|arrayOfIds|\bids\b)/i
export const MUTATING_METHOD_RE = /^(?:POST|PUT|PATCH|DELETE|MUTATION)$/i
const STRUCTURAL_STATE_FIELD_RE = /\b(?:status|state)\b\s*(?:===?|!==?|=|:)/i
const STRUCTURAL_OWNER_ACTOR_RE = /\b(?:createdBy|ownerId|authorId|approverId|approvedBy|userId|actorId)\b/i
const STRUCTURAL_ARITHMETIC_MUTATION_RE = /(?:[+\-*]=\s*[a-zA-Z_][a-zA-Z0-9_]*|\b(?:amount|balance|quantity|quota|limit)\b\s*(?:[+\-*]=|[<>]=?))/i
const SECRET_SCRUB_RE = /(?:eyJ[A-Za-z0-9_-]{12,}\.[A-Za-z0-9_-]{8,}(?:\.[A-Za-z0-9_-]{6,})?|\b(?:sk|pk|rk|pat|tok|sec|key)_(?:live|test|prod|dev|secret)_[A-Za-z0-9_-]{8,}\b|Bearer\s+[A-Za-z0-9._-]{16,}|\b[0-9a-f]{40,}\b)/g
const ENTITY_ACTION_VERB_RE = /^(?:create|update|delete|remove|list|get|fetch|approve|reject|cancel|promote|demote|transfer|export|sync|trigger|download|preview|verify|redeem|revoke|dispatch|run|start|stop|stream|subscribe|watch|listen|notify|emit|read|write|grant|invite|batch|bulk|multi|process|handle|resolve|query|mutate|submit|publish|archive|activate|suspend|release|schedule)$/i

/** True when a persona label represents a real authenticated actor rather than anonymous traffic. */
function isAuthenticatedPersona(persona?: string | null): boolean {
  return typeof persona === 'string' && !ANONYMOUS_PERSONA_RE.test(persona.trim())
}

/** True when `path` is a public/health route or static CDN asset path/extension. */
export function isPublicOrStaticAssetPath(path: string): boolean {
  const normalized = path.trim().replace(/^https?:\/\/[^/?#]+/i, '')
  return PUBLIC_EXEMPT_RE.test(normalized) || STATIC_ASSET_PREFIX_RE.test(normalized) || STATIC_ASSET_EXT_RE.test(normalized)
}

/** True when an observation looks like an authenticated multi-tenant Web Cache Deception route rather than a static asset. */
function isAuthenticatedWcdObservation(obs: PersonaSurfaceObservation): boolean {
  const normalized = obs.path.trim().replace(/^https?:\/\/[^/?#]+/i, '')
  return isAuthenticatedPersona(obs.persona)
    && Boolean(obs.tenantId)
    && obs.surface === 'cdn'
    && !STATIC_ASSET_PREFIX_RE.test(normalized)
    && WCD_SENSITIVE_PATH_RE.test(normalized)
}

const sha256Hex = (v: string): string => createHash('sha256').update(v).digest('hex')
export const stableId = (prefix: string, seed: string): string => `${prefix}_${sha256Hex(seed).slice(0, 12)}`
export const clamp01 = (n: number): number => Math.max(0, Math.min(1, Number(n.toFixed(4))))
const severityRank = (s: HypothesisSeverity): number => (s === 'critical' ? 4 : s === 'high' ? 3 : s === 'medium' ? 2 : 1)
export const scoreToSeverity = (score: number): HypothesisSeverity => (score >= 0.85 ? 'critical' : score >= 0.65 ? 'high' : score >= 0.4 ? 'medium' : 'low')
export const pushMap = <K, V>(map: Map<K, V[]>, key: K, value: V): void => { const l = map.get(key); if (l) l.push(value); else map.set(key, [value]) }
export const sortHypotheses = (list: InvariantHypothesis[], max?: number): InvariantHypothesis[] => {
  list.sort((a, b) => b.score - a.score || severityRank(b.severity) - severityRank(a.severity) || a.id.localeCompare(b.id))
  return max ? list.slice(0, max) : list
}
export const makeHypothesis = (p: Omit<InvariantHypothesis, 'promotionStatus' | 'severity'>): InvariantHypothesis => {
  const score = clamp01(p.score)
  return { ...p, score, severity: scoreToSeverity(score), promotionStatus: 'capability_only' }
}
export const scrubLiteralValues = (text: string): string => text.replace(SECRET_SCRUB_RE, '<redacted>')

function singularizeToken(raw: string): string {
  const token = raw.toLowerCase().replace(/[^a-z0-9]/g, '')
  if (token.length <= 3) return token
  if (token.endsWith('ies') && token.length > 4) return `${token.slice(0, -3)}y`
  if (/(?:ches|shes|xes|zes|ses)$/.test(token) && token.length > 4) return token.slice(0, -2)
  return token.endsWith('s') && !/(?:ss|us|is|status|access)$/.test(token) ? token.slice(0, -1) : token
}

function normalizeEntityCandidate(rawSegment: string): string {
  const cleaned = rawSegment.replace(/\.[a-z0-9]{1,5}$/i, '').trim()
  if (!cleaned) return ''
  const parts = cleaned.replace(/([a-z0-9])([A-Z])/g, '$1 $2').replace(/[_-]+/g, ' ').split(/\s+/).filter(Boolean)
  if (parts.length > 1) {
    if (parts.length >= 3 && parts[parts.length - 2]!.toLowerCase() === 'by') parts.splice(parts.length - 2, 2)
    const nonVerb = parts.filter(p => !ENTITY_ACTION_VERB_RE.test(p) && !WRAPPER_SEG_RE.test(p) && p.length >= 2)
    if (nonVerb.length > 0) return singularizeToken(nonVerb[nonVerb.length - 1]!)
  }
  return singularizeToken(cleaned)
}

/** Infer a normalized domain entity/resource noun from path, handler symbol, or query/body hints. */
export function inferEntityName(path: string, symbol = '', extraText = ''): string {
  const segs = path.split(/[/?#]/).map(s => s.trim()).filter(s => s && !/^[:{<*]/.test(s) && !/^\d+$/.test(s))
  const cands = segs.map(s => s.replace(/\.[a-z0-9]{1,5}$/i, '')).filter(s => s && !WRAPPER_SEG_RE.test(s)).map(normalizeEntityCandidate).filter(Boolean)
  if (cands.length > 0) {
    for (let i = cands.length - 1; i >= 0; i -= 1) if (!ENTITY_ACTION_VERB_RE.test(cands[i])) return cands[i]
    return cands[0]
  }
  const fromSym = symbol ? normalizeEntityCandidate(symbol) : ''
  if (fromSym && !ENTITY_ACTION_VERB_RE.test(fromSym)) return fromSym
  const tbl = /\b(?:from|into|update|table|model|collection|repository)\s*[:.(]?\s*['"`]?([a-z][a-z0-9_]{2,32})/i.exec(extraText)
  return tbl ? singularizeToken(tbl[1].split('_').pop() ?? tbl[1]) : 'resource'
}

export function classifySurface(path: string, method = 'GET', handler = '', bodyHint = ''): CapabilitySurface {
  const combined = `${method} ${path} ${handler}`
  if (/\/(?:graphql|gql)(?:\/|$)/i.test(path) || /^(?:QUERY|MUTATION|SUBSCRIPTION)$/i.test(method) || /\b(?:resolver|graphql)\b/i.test(handler)) return 'graphql'
  if (/\btext\/event-stream\b/i.test(bodyHint) || /\/(?:sse|events|stream)(?:\/|$)/i.test(path) || /\b(?:sse|eventStream|streamEvents)\b/i.test(handler)) return 'sse'
  if (/^WS$/i.test(method) || /\/(?:ws|wss|socket|realtime)(?:\/|$)/i.test(path) || /\b(?:websocket|wsHandler|onSocket|socketOn)\b/i.test(combined)) return 'ws'
  if (/\/(?:webhooks?|callbacks?|hooks?)(?:\/|$)/i.test(path) || /\b(?:webhook|hookHandler)\b/i.test(handler)) return 'webhook'
  if (/\/(?:jobs?|workers?|queues?|exports?|tasks?|async|runners?)(?:\/|$)/i.test(path) || /\b(?:worker|processJob|consumeQueue|enqueue|asyncExport|runJob)\b/i.test(combined)) return 'async_job'
  if (/\/(?:oauth|oidc|idp|sso|scim|authorize|token|consent|saml)(?:\/|$)/i.test(path)) return 'idp'
  if (/\/(?:cdn|static|assets|public\/profile|cache)(?:\/|$)/i.test(path) || /\.(?:css|js|png|svg)$/i.test(path)) return 'cdn'
  if (/\/(?:storage|buckets?|blobs?|files?|artifacts?|downloads?|signed-url)(?:\/|$)/i.test(path)) return 'storage'
  return 'http'
}

export function detectLifecyclePatterns(text: string): LifecyclePatternKind[] {
  const out: LifecyclePatternKind[] = []
  if (STRUCTURAL_STATE_FIELD_RE.test(text)) out.push('state_transition')
  if (STRUCTURAL_OWNER_ACTOR_RE.test(text)) out.push('creator_approver_mutation')
  if (STRUCTURAL_ARITHMETIC_MUTATION_RE.test(text)) out.push('numeric_balance_billing')
  return out
}

export function deduplicateHypotheses(list: readonly InvariantHypothesis[]): InvariantHypothesis[] {
  const byId = new Map<string, InvariantHypothesis>()
  for (const h of list) { const prev = byId.get(h.id); if (!prev || h.score > prev.score) byId.set(h.id, h) }
  return sortHypotheses([...byId.values()])
}

/** Project synthesized hypotheses into quarantined `CapabilityLedger` seed nodes. */
export function toCapabilityLedgerSeeds(hypotheses: readonly InvariantHypothesis[]): CapabilitySeedRecord[] {
  return hypotheses.map(h => ({
    capId: `cap:synth_${h.id}`, kind: h.capabilityKind, promotionStatus: 'capability_only', provenance: `invariant-synthesizer:${h.mode}:${h.kind}`,
    tenantScope: 'unscoped_hypothesis', actorPersona: 'unassigned', serviceOrigin: h.serviceOrigin ?? 'unknown', surface: h.surface,
    temporalState: h.preconditions.includes('temporal_state:revoked_or_demoted') ? 'revoked' : 'active',
    artifactDigest: sha256Hex(`${h.id}|${h.entity}|${h.surface}|${h.targetRoute ?? ''}`), summary: scrubLiteralValues(h.summary).slice(0, 280),
    metadata: { hypothesisId: h.id, hypothesisKind: h.kind, entity: h.entity, mode: h.mode, score: h.score, ...(h.targetRoute ? { targetRoute: h.targetRoute } : {}) },
  }))
}

// Runtime Parity Adapter (Grey-Box / Black-Box)
const isAllowedStatus = (status: number): boolean => (status >= 200 && status < 300) || status === 101
const isDeniedStatus = (status: number): boolean => status === 401 || status === 403
const MISSING_AUTH_REQ_RE = /^(?:|none|public|unknown|anonymous|unauthenticated)$/i
const PRIVILEGED_HINT_RE = /\b(?:admin|owner|role|rbac|superuser|staff|privileged)\b/i
const parseMethodAndPath = (raw: string): { method: string; path: string } => {
  const m = /^(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS|QUERY|MUTATION|SUBSCRIPTION)\s+(.+)$/i.exec(raw.trim())
  return m ? { method: m[1]!.toUpperCase(), path: m[2]!.trim() } : { method: 'GET', path: raw.trim() }
}
const normalizeDepPath = (path: string): string => (path.split(/[?#]/, 1)[0] || '/').replace(/\/+$/, '') || '/'
const hasOpenApiAuth = (op: RuntimeOpenApiOperation): boolean =>
  Array.isArray(op.security) ? op.security.some(s => Object.keys(s).length > 0) : Boolean(op.authRequirement && !MISSING_AUTH_REQ_RE.test(op.authRequirement.trim()))
const hasOpenApiRoleRestriction = (op: RuntimeOpenApiOperation): boolean =>
  Boolean(op.authRequirement && PRIVILEGED_HINT_RE.test(op.authRequirement))
  || Boolean(op.security?.some(req => Object.entries(req).some(([s, sc]) => PRIVILEGED_HINT_RE.test(s) || (Array.isArray(sc) && sc.some(v => PRIVILEGED_HINT_RE.test(v) || /(?:write|admin|delete|manage|grant)/i.test(v))))))

export type RuntimeDependencyEdgeKind = 'await_async' | 'hmac_sign' | 'lifecycle_chain' | 'signed_url' | 'generic'
const ASYNC_ROUTE_RE = /\/(?:jobs?|tasks?|exports?|status|poll|queues?|workers?|async)(?:\/|$)/i
const WEBHOOK_ROUTE_RE = /\/(?:webhooks?|callbacks?|hooks?)(?:\/|$)/i
const STORAGE_ROUTE_RE = /\/(?:downloads?|files?|artifacts?|storage|signed-url|presign)(?:\/|$)/i
const PARAM_CANON_RE = /[^a-z0-9]/g
const canonicalParamToken = (name: string): string => name.toLowerCase().replace(/^x-/, '').replace(PARAM_CANON_RE, '')

/** Normalize route paths so concrete IDs and `{param}`/`:param` templates match consistently. */
function normalizeRouteMatchPath(rawPath: string): string {
  const bare = (rawPath.split(/[?#]/, 1)[0] || '/').replace(/\/+$/, '') || '/'
  if (bare === '/') return '/'
  return '/' + bare.split('/').filter(Boolean).map(seg =>
    /^[:{<*]/.test(seg) || seg.endsWith('}') || isOpaqueResourceId(seg) ? ':*' : seg.toLowerCase(),
  ).join('/')
}

/** Exclude `surface_probe` ghost endpoints whose observed exchanges only ever returned 404/405 with zero non-404 live responses and no OpenAPI/JS/DOM evidence. */
export function filterGhostSurfaceProbeEndpoints<T extends { origin: string; method: string; pathTemplate: string; source?: string | null }>(
  endpoints: readonly T[],
  brokerExchanges: ReadonlyArray<{ origin: string; method: string; pathAndQuery: string; status: number }>,
  evidencedRouteKeys?: ReadonlySet<string>,
): T[] {
  const evidenced = new Set<string>(evidencedRouteKeys ?? [])
  for (const ep of endpoints) {
    if (ep.source && ep.source !== 'surface_probe') {
      const np = normalizeRouteMatchPath(ep.pathTemplate)
      evidenced.add(`${ep.origin}|${np}`)
      evidenced.add(`${ep.origin}|${ep.method.toUpperCase()}|${np}`)
    }
  }
  const byExact = new Map<string, { total: number; nonGhost: number }>()
  const byPath = new Map<string, { total: number; nonGhost: number }>()
  const bump = (map: Map<string, { total: number; nonGhost: number }>, key: string, status: number) => {
    const rec = map.get(key) ?? { total: 0, nonGhost: 0 }
    rec.total += 1
    if (status !== 404 && status !== 405) rec.nonGhost += 1
    map.set(key, rec)
  }
  for (const ex of brokerExchanges) {
    const np = normalizeRouteMatchPath(ex.pathAndQuery)
    bump(byExact, `${ex.origin}|${ex.method.toUpperCase()}|${np}`, ex.status)
    bump(byPath, `${ex.origin}|${np}`, ex.status)
  }
  return endpoints.filter(ep => {
    if (ep.source !== 'surface_probe') return true
    const np = normalizeRouteMatchPath(ep.pathTemplate)
    const mKey = `${ep.origin}|${ep.method.toUpperCase()}|${np}`, pKey = `${ep.origin}|${np}`
    if (evidenced.has(mKey) || evidenced.has(pKey)) return true
    const exact = byExact.get(mKey), pathStats = byPath.get(pKey)
    const stats = exact && exact.total > 0 ? exact : pathStats
    return !(stats && stats.total > 0 && stats.nonGhost === 0)
  })
}

/** Classify a producer -> consumer runtime dependency using structural field, header, and HTTP method signals. */
export function classifyRuntimeDependencyEdgeKind(
  dep: Pick<RuntimeApiDependency, 'producer' | 'consumer' | 'resourceKey' | 'observedTransitions'>,
): RuntimeDependencyEdgeKind {
  const transitions = (dep.observedTransitions ?? []).join(' ').toLowerCase()
  if (transitions.includes('hmac_sign')) return 'hmac_sign'
  if (transitions.includes('await_async') || transitions.includes('status:202')) return 'await_async'
  if (transitions.includes('lifecycle_chain')) return 'lifecycle_chain'
  if (transitions.includes('signed_url')) return 'signed_url'
  const prod = parseMethodAndPath(dep.producer), cons = parseMethodAndPath(dep.consumer)
  const key = dep.resourceKey.trim()
  const keyKind = classifyStructuralFieldEdgeKind(key, key.includes('-') ? 'header' : 'json')
    ?? classifyStructuralFieldEdgeKind(key, 'json')
  if (keyKind === 'hmac_sign' || ((WEBHOOK_ROUTE_RE.test(prod.path) || WEBHOOK_ROUTE_RE.test(cons.path)) && /(?:secret|sign|hmac|key|signature)/i.test(key))) return 'hmac_sign'
  if (keyKind === 'await_async' || key === 'status:202' || (ASYNC_ROUTE_RE.test(cons.path) && /(?:job|task|export|status|poll|async|operation|location)/i.test(key))) return 'await_async'
  if (keyKind === 'signed_url' || (STORAGE_ROUTE_RE.test(cons.path) && /(?:url|link|download|signed|presign|location)/i.test(key))) return 'signed_url'
  if (MUTATING_METHOD_RE.test(prod.method) && MUTATING_METHOD_RE.test(cons.method)) {
    return 'lifecycle_chain'
  }
  return 'generic'
}

/** Resolve OpenAPI schema `$ref`s (local `#/components/schemas/...` / `#/definitions/...`) safely with cycle protection. */
function collectOpenApiSchemaProperties(
  doc: Record<string, unknown>,
  schemaNode: unknown,
  out: Set<string>,
  seenRefs: Set<string> = new Set(),
  depth = 0,
): void {
  if (depth > 6 || out.size >= 40 || !schemaNode || typeof schemaNode !== 'object' || Array.isArray(schemaNode)) return
  const node = schemaNode as Record<string, unknown>
  if (typeof node.$ref === 'string' && node.$ref.startsWith('#/')) {
    if (seenRefs.has(node.$ref)) return
    seenRefs.add(node.$ref)
    let cur: unknown = doc
    for (const rawSeg of node.$ref.slice(2).split('/')) {
      const seg = rawSeg.replace(/~1/g, '/').replace(/~0/g, '~')
      if (!cur || typeof cur !== 'object' || Array.isArray(cur)) { cur = undefined; break }
      cur = (cur as Record<string, unknown>)[seg]
    }
    if (cur) collectOpenApiSchemaProperties(doc, cur, out, seenRefs, depth + 1)
  }
  if (node.properties && typeof node.properties === 'object' && !Array.isArray(node.properties)) {
    for (const [k, v] of Object.entries(node.properties as Record<string, unknown>)) {
      if (out.size >= 40) break
      if (k && k !== '__proto__' && k !== 'constructor') out.add(k)
      if (v && typeof v === 'object' && depth < 3) collectOpenApiSchemaProperties(doc, v, out, seenRefs, depth + 1)
    }
  }
  for (const kw of ['allOf', 'oneOf', 'anyOf'] as const) {
    if (Array.isArray(node[kw])) for (const sub of node[kw] as unknown[]) collectOpenApiSchemaProperties(doc, sub, out, seenRefs, depth + 1)
  }
  if (node.items && typeof node.items === 'object') collectOpenApiSchemaProperties(doc, node.items, out, seenRefs, depth + 1)
}

/** Populate `InvariantHypothesis` & `CapabilitySeedRecord` in grey/black-box mode from diffs, OpenAPI/GraphQL, SPA routes & API dependencies. */
export function inferRuntimeInvariantHypotheses(input: RuntimeDiscoveryInput): RuntimeInvariantParityResult {
  const hypotheses: InvariantHypothesis[] = []
  const observations = input.personaObservations ?? [], openApiOps = input.openApiOperations ?? []
  const gqlCatalogs = [...(input.graphqlCatalog ? [input.graphqlCatalog] : []), ...(input.graphqlCatalogs ?? [])]
  const spaRoutes = input.spaRoutes ?? [], apiDependencies = input.apiDependencies ?? []

  // 1. Multi-persona cross-surface, revocation & cache-key differentials.
  const obsByEntity = new Map<string, PersonaSurfaceObservation[]>()
  for (const obs of observations) {
    if (isPublicOrStaticAssetPath(obs.path) && !isAuthenticatedWcdObservation(obs)) continue
    const entity = inferEntityName(obs.path, '', (obs.bodyKeys ?? []).join(' '))
    pushMap(obsByEntity, entity, obs)
    const headers = Object.fromEntries(Object.entries(obs.responseHeaders ?? {}).map(([k, v]) => [k.toLowerCase(), v]))
    const cc = headers['cache-control'] ?? '', vary = (headers['vary'] ?? '').toLowerCase()
    if ((/(?:public|max-age=\d+|s-maxage=\d+)/i.test(cc) || /hit/i.test(headers['x-cache'] ?? '')) && isAllowedStatus(obs.status) && isAuthenticatedPersona(obs.persona) && !/(?:authorization|cookie)/.test(vary)) {
      hypotheses.push(makeHypothesis({
        id: stableId('hyp_rt_cache', `${obs.method}|${obs.path}|${obs.surface}`), kind: 'trust_boundary_mismatch', capabilityKind: 'parser_or_cache_primitive',
        mode: input.mode, entity, surface: obs.surface === 'http' ? 'cdn' : obs.surface, ...(obs.serviceOrigin ? { serviceOrigin: obs.serviceOrigin } : {}),
        targetRoute: `${obs.method.toUpperCase()} ${obs.path}`, score: 0.76 + (obs.surface === 'cdn' ? 0.08 : 0),
        summary: `Runtime response for ${obs.method.toUpperCase()} ${obs.path} is cacheable under persona "${obs.persona}" without Vary on Authorization/Cookie.`,
        preconditions: [`persona:${obs.persona}`, `cacheable_surface:${obs.surface}`],
        verificationHint: `Prime ${obs.method.toUpperCase()} ${obs.path} as a privileged persona and re-fetch as a distinct tenant/unprivileged persona.`,
        evidence: [`persona=${obs.persona}`, `status=${obs.status}`, `cache_control=${cc || 'none'}`, `vary=${vary || 'none'}`],
      }))
    }
  }
  for (const [entity, group] of [...obsByEntity.entries()].sort(([a], [b]) => a.localeCompare(b))) {
    const byPersona = new Map<string, PersonaSurfaceObservation[]>()
    for (const o of group) pushMap(byPersona, o.persona, o)
    for (const [persona, pObs] of byPersona) {
      const denied = pObs.filter(o => isDeniedStatus(o.status)), allowed = pObs.filter(o => isAllowedStatus(o.status))
      if (!denied.length || !allowed.length) continue
      for (const allow of allowed) {
        const refDeny = denied.find(d => d.surface !== allow.surface || (allow.isBatch && !d.isBatch)) ?? denied[0]
        const crossSurface = refDeny.surface !== allow.surface, batchSkew = Boolean(allow.isBatch && !refDeny.isBatch)
        if (!crossSurface && !batchSkew && !allow.isRevokedOrDemoted) continue
        hypotheses.push(makeHypothesis({
          id: stableId('hyp_rt_asym', `${entity}|${persona}|${allow.surface}|${allow.method}|${allow.path}`), kind: 'runtime_surface_asymmetry', capabilityKind: 'policy_asymmetry',
          mode: input.mode, entity, surface: allow.surface, ...(allow.serviceOrigin ? { serviceOrigin: allow.serviceOrigin } : {}),
          targetRoute: `${allow.method.toUpperCase()} ${allow.path}`, score: 0.62 + (allow.isRevokedOrDemoted ? 0.22 : 0) + (crossSurface ? 0.12 : 0) + (batchSkew ? 0.10 : 0),
          summary: `Persona "${persona}"${allow.isRevokedOrDemoted ? ' (revoked/demoted)' : ''} is denied (${refDeny.status}) on ${refDeny.surface} (${refDeny.method} ${refDeny.path}) but succeeds (${allow.status}) on ${allow.surface} (${allow.method} ${allow.path}) for entity "${entity}".`,
          preconditions: [`persona:${persona}`, `denied_control:${refDeny.surface}:${refDeny.status}`, ...(allow.isRevokedOrDemoted ? ['temporal_state:revoked_or_demoted'] : [])],
          verificationHint: allow.isRevokedOrDemoted
            ? `Record denied control (${refDeny.status}) on ${refDeny.method} ${refDeny.path}, then prove unauthorized access on ${allow.surface} (${allow.method} ${allow.path}).`
            : `Compare authorization enforcement between ${refDeny.method} ${refDeny.path} and ${allow.method} ${allow.path} across tenants and roles.`,
          evidence: [`persona=${persona}`, `denied=${refDeny.surface}:${refDeny.method} ${refDeny.path} -> ${refDeny.status}`, `allowed=${allow.surface}:${allow.method} ${allow.path} -> ${allow.status}`],
        }))
      }
    }
  }

  // 2. OpenAPI + GraphQL catalog cross-surface parity, role-tier asymmetry & lifecycle inference.
  interface CatalogOp { surface: CapabilitySurface; method: string; path: string; hasAuth: boolean; hasRoleGuard: boolean; isBatch: boolean; serviceOrigin?: string; bodyKeys: string[]; operationId?: string }
  const catalogByEntity = new Map<string, CatalogOp[]>(), seenGql = new Set<string>()
  let gqlFieldCount = 0
  for (const op of openApiOps) {
    if (isPublicOrStaticAssetPath(op.path)) continue
    pushMap(catalogByEntity, inferEntityName(op.path, op.operationId ?? '', `${(op.requestBodyKeys ?? []).join(' ')} ${(op.parameters ?? []).join(' ')} ${(op.tags ?? []).join(' ')}`), {
      surface: classifySurface(op.path, op.method, op.operationId ?? ''), method: op.method.toUpperCase(), path: op.path,
      hasAuth: hasOpenApiAuth(op), hasRoleGuard: hasOpenApiRoleRestriction(op), isBatch: BATCH_HINT_RE.test(op.path) || BATCH_HINT_RE.test(op.operationId ?? ''),
      serviceOrigin: op.serviceOrigin, bodyKeys: [...(op.requestBodyKeys ?? []), ...(op.parameters ?? [])], ...(op.operationId ? { operationId: op.operationId } : {}),
    })
  }
  for (const cat of gqlCatalogs) {
    const ep = cat.endpoint ?? '/graphql'
    for (const f of cat.fields ?? []) {
      const k = `${cat.serviceOrigin ?? ''}|${ep}|${f.kind}|${f.name}`
      if (seenGql.has(k)) continue
      seenGql.add(k); gqlFieldCount += 1
      pushMap(catalogByEntity, inferEntityName(`/${f.name}`, f.name, `${f.returnType ?? ''} ${(f.args ?? []).join(' ')}`), {
        surface: 'graphql', method: f.kind.toUpperCase(), path: `${ep}#${f.name}`, hasAuth: Boolean(f.requiresAuth || f.requiredRole),
        hasRoleGuard: Boolean(f.requiredRole && PRIVILEGED_HINT_RE.test(f.requiredRole)), isBatch: BATCH_HINT_RE.test(f.name) || (f.args ?? []).some(a => /ids$/i.test(a)),
        serviceOrigin: cat.serviceOrigin, bodyKeys: f.args ?? [], operationId: f.name,
      })
    }
  }
  for (const [entity, ops] of [...catalogByEntity.entries()].sort(([a], [b]) => a.localeCompare(b))) {
    const authed = ops.filter(o => o.hasAuth), unauthed = ops.filter(o => !o.hasAuth)
    if (authed.length && unauthed.length) {
      for (const weak of unauthed) {
        const strong = authed.find(a => a.surface !== weak.surface) ?? authed[0]
        hypotheses.push(makeHypothesis({
          id: stableId('hyp_cat_asym', `${entity}|${weak.surface}|${weak.method}|${weak.path}`), kind: 'policy_asymmetry', capabilityKind: 'policy_asymmetry',
          mode: input.mode, entity, surface: weak.surface, ...(weak.serviceOrigin ? { serviceOrigin: weak.serviceOrigin } : {}),
          targetRoute: `${weak.method} ${weak.path}`, score: 0.64 + (strong.surface !== weak.surface ? 0.14 : 0) + (weak.isBatch ? 0.08 : 0),
          summary: `Catalog schema for entity "${entity}" declares auth on ${strong.surface} (${strong.method} ${strong.path}) but omits auth on ${weak.surface} (${weak.method} ${weak.path}).`,
          preconditions: [`catalog_surface:${weak.surface}`],
          verificationHint: `Test unauthenticated and low-privilege access on ${weak.method} ${weak.path} against denied control ${strong.method} ${strong.path}.`,
          evidence: [`catalog_weaker=${weak.surface}:${weak.method} ${weak.path}`, `catalog_stronger=${strong.surface}:${strong.method} ${strong.path}`, ...(weak.operationId ? [`operation_id=${weak.operationId}`] : [])],
        }))
      }
    }
    const roleGuarded = ops.filter(o => o.hasRoleGuard)
    const genericAuthed = ops.filter(o => o.hasAuth && !o.hasRoleGuard && (MUTATING_METHOD_RE.test(o.method) || o.isBatch || roleGuarded.some(r => r.surface !== o.surface)))
    if (roleGuarded.length && genericAuthed.length) {
      for (const weak of genericAuthed) {
        const strong = roleGuarded.find(r => r.surface !== weak.surface) ?? roleGuarded[0]
        hypotheses.push(makeHypothesis({
          id: stableId('hyp_cat_role_asym', `${entity}|${weak.surface}|${weak.method}|${weak.path}`), kind: 'policy_asymmetry', capabilityKind: 'policy_asymmetry',
          mode: input.mode, entity, surface: weak.surface, ...(weak.serviceOrigin ? { serviceOrigin: weak.serviceOrigin } : {}),
          targetRoute: `${weak.method} ${weak.path}`, score: 0.63 + (strong.surface !== weak.surface ? 0.12 : 0) + (weak.isBatch ? 0.07 : 0),
          summary: `Catalog schema for entity "${entity}" declares role-scoped auth on ${strong.surface} (${strong.method} ${strong.path}) but only baseline auth on ${weak.surface} (${weak.method} ${weak.path}).`,
          preconditions: [`catalog_surface:${weak.surface}`, 'role_tier_asymmetry'],
          verificationHint: `Compare low-privilege access on ${weak.method} ${weak.path} against denied control on role-gated ${strong.method} ${strong.path}.`,
          evidence: [`catalog_weaker=${weak.surface}:${weak.method} ${weak.path}`, `catalog_stronger=${strong.surface}:${strong.method} ${strong.path}`],
        }))
      }
    }
    const lifecycleSignals = detectLifecyclePatterns(ops.map(o => `${o.path} ${o.operationId ?? ''} ${o.bodyKeys.join(' ')}`).join(' '))
    if (lifecycleSignals.length && ops.length >= 2) {
      hypotheses.push(makeHypothesis({
        id: stableId('hyp_cat_life', `${entity}|${lifecycleSignals.join(',')}`), kind: 'lifecycle_invariant', capabilityKind: 'state_handle',
        mode: input.mode, entity, surface: ops[0].surface, ...(ops[0].serviceOrigin ? { serviceOrigin: ops[0].serviceOrigin } : {}),
        targetRoute: `${ops[0].method} ${ops[0].path}`, score: 0.55 + lifecycleSignals.length * 0.10,
        summary: `Catalog operations for entity "${entity}" expose multi-step lifecycle patterns [${lifecycleSignals.join(', ')}] across ${ops.length} operations.`,
        preconditions: [`catalog_entity:${entity}`, ...lifecycleSignals.map(p => `pattern:${p}`)],
        verificationHint: `Sequence state transitions across ${ops.slice(0, 3).map(o => `${o.method} ${o.path}`).join(' -> ')} and verify conservation / maker-checker invariants.`,
        evidence: ops.slice(0, 4).map(o => `catalog_op=${o.surface}:${o.method} ${o.path}`),
      }))
    }
  }

  // 3. SPA bundle route, client-role gating, cross-origin transitions & state-action extraction.
  for (const spa of spaRoutes) {
    const calls = spa.apiCalls ?? [], actionText = `${spa.path} ${(spa.stateActions ?? []).join(' ')} ${calls.map(c => c.path).join(' ')}`
    const patterns = detectLifecyclePatterns(actionText), hasClientRoles = Boolean(spa.requiredRoles?.length && calls.length)
    const crossOriginCall = spa.serviceOrigin ? calls.find(c => c.serviceOrigin && c.serviceOrigin !== spa.serviceOrigin) : undefined
    const hasMutatingCall = calls.some(c => MUTATING_METHOD_RE.test(c.method))
    if (!patterns.length && !hasClientRoles && !crossOriginCall && !hasMutatingCall) continue
    const target = crossOriginCall ?? calls[0], entity = inferEntityName(target?.path ?? spa.path, '', actionText)
    const surface: CapabilitySurface = target?.surface ?? (target ? classifySurface(target.path, target.method) : 'browser')
    const kind: InvariantHypothesisKind = crossOriginCall ? 'trust_boundary_mismatch' : hasClientRoles ? 'runtime_surface_asymmetry' : 'lifecycle_invariant'
    const capabilityKind: CapabilityKind = crossOriginCall ? 'identity_session' : hasClientRoles ? 'policy_asymmetry' : 'state_handle'
    const targetOrigin = target?.serviceOrigin ?? spa.serviceOrigin
    hypotheses.push(makeHypothesis({
      id: stableId('hyp_spa', `${spa.path}|${target?.path ?? 'ui'}|${patterns.join(',')}|${crossOriginCall?.serviceOrigin ?? ''}`), kind, capabilityKind,
      mode: input.mode, entity, surface, ...(targetOrigin ? { serviceOrigin: targetOrigin } : {}),
      targetRoute: target ? `${target.method.toUpperCase()} ${target.path}` : `SPA ${spa.path}`,
      score: 0.56 + patterns.length * 0.09 + (hasClientRoles ? 0.12 : 0) + (crossOriginCall ? 0.14 : 0) + (hasMutatingCall && !hasClientRoles ? 0.06 : 0),
      summary: crossOriginCall
        ? `SPA route "${spa.path}" (${spa.serviceOrigin}) invokes cross-origin call ${crossOriginCall.method.toUpperCase()} ${crossOriginCall.path} (${crossOriginCall.serviceOrigin}); verify cross-origin authz.`
        : hasClientRoles ? `SPA route "${spa.path}" enforces client-side roles [${spa.requiredRoles!.join(', ')}] in front of API calls (${calls.map(c => `${c.method} ${c.path}`).join(', ')}); verify server-side authorization.`
          : `SPA route "${spa.path}" drives entity "${entity}" mutating actions [${patterns.join(', ') || 'mutating_api'}].`,
      preconditions: [`spa_route:${spa.path}`, ...(crossOriginCall ? [`cross_origin_edge:${spa.serviceOrigin}->${crossOriginCall.serviceOrigin}`] : [])],
      verificationHint: hasClientRoles ? `Call backend endpoint ${target ? `${target.method} ${target.path}` : spa.path} directly as a non-[${spa.requiredRoles!.join(',')}] actor.`
        : `Replay the SPA workflow sequence directly against backend endpoints with out-of-order or dual-actor mutations.`,
      evidence: [`spa_route=${spa.path}`, ...(spa.requiredRoles?.length ? [`client_roles=${spa.requiredRoles.join(',')}`] : []), ...(crossOriginCall ? [`cross_origin=${spa.serviceOrigin} -> ${crossOriginCall.serviceOrigin}`] : []), ...calls.slice(0, 3).map(c => `api_call=${c.method.toUpperCase()} ${c.path}`)],
    }))
  }

  // 4. Producer -> Consumer API dependency edges (same-origin, transitive chains, typed workflows & cross-origin trust boundaries).
  type ParsedDep = { raw: RuntimeApiDependency; pm: string; pp: string; cm: string; cp: string; entity: string; xOrigin: boolean; mut: boolean; life: LifecyclePatternKind[]; edgeKind: RuntimeDependencyEdgeKind }
  const parsedDeps: ParsedDep[] = [], depsByProd = new Map<string, ParsedDep[]>()
  for (const dep of apiDependencies) {
    const prod = parseMethodAndPath(dep.producer), cons = parseMethodAndPath(dep.consumer)
    if (!prod.path.startsWith('/') || !cons.path.startsWith('/') || (isPublicOrStaticAssetPath(prod.path) && isPublicOrStaticAssetPath(cons.path))) continue
    const pp = normalizeDepPath(prod.path), cp = normalizeDepPath(cons.path)
    const item: ParsedDep = {
      raw: dep, pm: prod.method, pp, cm: cons.method, cp, entity: inferEntityName(cp, dep.resourceKey, `${pp} ${(dep.observedTransitions ?? []).join(' ')}`),
      xOrigin: Boolean(dep.producerOrigin && dep.consumerOrigin && dep.producerOrigin !== dep.consumerOrigin),
      mut: MUTATING_METHOD_RE.test(cons.method), life: detectLifecyclePatterns(`${pp} ${cp} ${dep.resourceKey} ${(dep.observedTransitions ?? []).join(' ')}`),
      edgeKind: classifyRuntimeDependencyEdgeKind(dep),
    }
    parsedDeps.push(item); pushMap(depsByProd, pp, item)
  }
  const edgeMeta = (ek: RuntimeDependencyEdgeKind, fallbackSurface: CapabilitySurface, pRef: string, cRef: string, rk: string, nRef?: string) => {
    if (ek === 'hmac_sign') return { cap: 'signing_material' as CapabilityKind, surf: 'webhook' as CapabilitySurface, boost: 0.16, tags: ['edge_kind:hmac_sign', 'workflow:webhook_signing'], hint: `Seal signing material "${rk}" from ${pRef} via ctx.seal_capability, compute callback signature with ctx.hmac_sign, and verify authorization on ${nRef ?? cRef}.` }
    if (ek === 'await_async') return { cap: 'state_handle' as CapabilityKind, surf: 'async_job' as CapabilitySurface, boost: 0.15, tags: ['edge_kind:await_async', 'workflow:async_poll'], hint: `Trigger ${pRef} (202/async), seal "${rk}" via ctx.seal_capability, poll via ctx.await_async against ${nRef ?? cRef}, and verify cross-tenant isolation.` }
    if (ek === 'lifecycle_chain') return { cap: 'state_handle' as CapabilityKind, surf: fallbackSurface, boost: 0.12, tags: ['edge_kind:lifecycle_chain'], hint: `Sequence multi-step mutations (${pRef} -> ${cRef}${nRef ? ` -> ${nRef}` : ''}) with denied control and ctx.prove_composite to test ownership/state invariants.` }
    if (ek === 'signed_url') return { cap: 'signed_artifact_or_url' as CapabilityKind, surf: fallbackSurface === 'http' ? 'storage' as CapabilitySurface : fallbackSurface, boost: 0.10, tags: ['edge_kind:signed_url'], hint: `Harvest signed handle "${rk}" from ${pRef}, seal via ctx.seal_capability, and replay against ${nRef ?? cRef} as a distinct tenant/persona.` }
    return { cap: 'opaque_object_ref' as CapabilityKind, surf: fallbackSurface, boost: 0, tags: [] as string[], hint: `Harvest "${rk}" from ${pRef}, establish a denied control, then replay against ${nRef ?? cRef} as a distinct persona.` }
  }
  for (const d of parsedDeps) {
    const pRef = `${d.pm} ${d.pp}`, cRef = `${d.cm} ${d.cp}`, targetOrigin = d.raw.consumerOrigin ?? d.raw.producerOrigin
    const next = (depsByProd.get(d.cp) ?? []).find(n => n.cp !== d.pp && n.cp !== d.cp)
    if (next) {
      const nRef = `${next.cm} ${next.cp}`, xChain = d.xOrigin || next.xOrigin || Boolean(d.raw.producerOrigin && next.raw.consumerOrigin && d.raw.producerOrigin !== next.raw.consumerOrigin)
      const isMultiMutChain = MUTATING_METHOD_RE.test(d.pm) && d.mut && next.mut
      const chainKind: RuntimeDependencyEdgeKind = d.edgeKind === 'hmac_sign' || next.edgeKind === 'hmac_sign' ? 'hmac_sign'
        : d.edgeKind === 'await_async' || next.edgeKind === 'await_async' ? 'await_async'
          : isMultiMutChain || d.edgeKind === 'lifecycle_chain' || next.edgeKind === 'lifecycle_chain' ? 'lifecycle_chain'
            : d.edgeKind !== 'generic' ? d.edgeKind : next.edgeKind
      const m = edgeMeta(chainKind, classifySurface(next.cp, next.cm), pRef, cRef, d.raw.resourceKey, nRef)
      hypotheses.push(makeHypothesis({
        id: stableId('hyp_dep_chain', `${pRef}|${cRef}|${nRef}|${d.raw.resourceKey}`), kind: xChain ? 'trust_boundary_mismatch' : 'lifecycle_invariant', capabilityKind: chainKind === 'generic' ? 'state_handle' : m.cap,
        mode: input.mode, entity: next.entity || d.entity, surface: m.surf, ...(next.raw.consumerOrigin ?? targetOrigin ? { serviceOrigin: next.raw.consumerOrigin ?? targetOrigin } : {}),
        targetRoute: nRef, score: 0.72 + (xChain ? 0.12 : 0) + (next.mut ? 0.06 : 0) + m.boost,
        summary: `Runtime API dependency chain${chainKind !== 'generic' ? ` [${chainKind}]` : ''} propagates "${d.raw.resourceKey}" across 3 stages: ${pRef} -> ${cRef} -> ${nRef}.`,
        preconditions: [`api_dependency:${d.raw.resourceKey}`, 'multi_hop_dependency', ...m.tags, ...(xChain && d.raw.producerOrigin && (next.raw.consumerOrigin ?? d.raw.consumerOrigin) ? [`cross_origin_edge:${d.raw.producerOrigin}->${next.raw.consumerOrigin ?? d.raw.consumerOrigin}`] : [])],
        verificationHint: chainKind !== 'generic' ? m.hint : `Obtain "${d.raw.resourceKey}" from ${pRef}, pivot through ${cRef}, and verify authorization/state invariants on ${nRef}.`,
        evidence: [`api_dep_producer=${pRef}`, `api_dep_consumer=${cRef}`, `api_dep_next=${nRef}`, `resource_key=${d.raw.resourceKey}`, ...(chainKind !== 'generic' ? [`edge_kind=${chainKind}`] : [])],
      }))
      continue
    }
    if (!d.xOrigin && !d.mut && !d.life.length && d.edgeKind === 'generic' && d.raw.testedBola) continue
    const m = edgeMeta(d.edgeKind, classifySurface(d.cp, d.cm), pRef, cRef, d.raw.resourceKey)
    hypotheses.push(makeHypothesis({
      id: stableId('hyp_dep', `${pRef}|${cRef}|${d.raw.resourceKey}|${d.raw.consumerOrigin ?? ''}`),
      kind: d.xOrigin ? 'trust_boundary_mismatch' : (d.life.length || d.edgeKind === 'lifecycle_chain' || d.edgeKind === 'await_async') ? 'lifecycle_invariant' : d.edgeKind === 'hmac_sign' ? 'trust_boundary_mismatch' : 'runtime_surface_asymmetry',
      capabilityKind: d.edgeKind !== 'generic' ? m.cap : d.life.length ? 'state_handle' : 'opaque_object_ref', mode: input.mode, entity: d.entity, surface: m.surf,
      ...(targetOrigin ? { serviceOrigin: targetOrigin } : {}), targetRoute: cRef,
      score: (d.xOrigin ? 0.76 : d.life.length ? 0.64 + Math.min(0.14, d.life.length * 0.06) : 0.60) + (d.mut ? 0.08 : 0) + m.boost,
      summary: d.xOrigin ? `Cross-origin API dependency${d.edgeKind !== 'generic' ? ` [${d.edgeKind}]` : ''} flows "${d.raw.resourceKey}" from ${pRef} (${d.raw.producerOrigin}) -> ${cRef} (${d.raw.consumerOrigin}).`
        : `Producer ${pRef} -> Consumer ${cRef}${d.edgeKind !== 'generic' ? ` [${d.edgeKind}]` : ''} propagates "${d.raw.resourceKey}"${d.life.length ? ` [${d.life.join(', ')}]` : ''}; verify ownership/workflow invariants.`,
      preconditions: [`api_dependency:${d.raw.resourceKey}`, ...m.tags, ...(d.xOrigin ? [`cross_origin_edge:${d.raw.producerOrigin}->${d.raw.consumerOrigin}`] : []), ...(d.raw.personaHandle ? [`persona:${d.raw.personaHandle}`] : [])],
      verificationHint: m.hint,
      evidence: [`api_dep_producer=${pRef}`, `api_dep_consumer=${cRef}`, `resource_key=${d.raw.resourceKey}`, ...(d.edgeKind !== 'generic' ? [`edge_kind=${d.edgeKind}`] : []), ...(d.xOrigin ? [`cross_origin=${d.raw.producerOrigin} -> ${d.raw.consumerOrigin}`] : [])],
    }))
  }

  const deduped = deduplicateHypotheses(hypotheses), limited = input.maxHypotheses ? deduped.slice(0, input.maxHypotheses) : deduped
  return {
    mode: input.mode, hypotheses: limited, capabilitySeeds: toCapabilityLedgerSeeds(limited),
    stats: { observationsAnalyzed: observations.length, catalogOpsAnalyzed: openApiOps.length + gqlFieldCount, spaRoutesAnalyzed: spaRoutes.length, hypothesesEmitted: limited.length, ...(input.apiDependencies !== undefined ? { apiDependenciesAnalyzed: apiDependencies.length } : {}) },
  }
}

export interface RuntimeCatalogFactsExtract { openApiOperations: RuntimeOpenApiOperation[]; graphqlCatalog?: RuntimeGraphqlCatalog; graphqlCatalogs: RuntimeGraphqlCatalog[]; spaRoutes: RuntimeSpaRoute[]; apiDependencies: RuntimeApiDependency[] }

/** Extract structured Phase-0 runtime catalogs (`runtime_spa_routes`, `runtime_graphql_catalog`, `runtime_openapi_catalog`) from persisted run facts. */
export function extractRuntimeCatalogFromFacts(facts: ReadonlyArray<{ origin?: string; data?: Record<string, unknown> | null; tainted?: boolean }>, approvedOrigins?: ReadonlySet<string>): RuntimeCatalogFactsExtract {
  const openApiOperations: RuntimeOpenApiOperation[] = [], graphqlCatalogs: RuntimeGraphqlCatalog[] = [], spaRoutes: RuntimeSpaRoute[] = [], apiDependencies: RuntimeApiDependency[] = []
  const seenOa = new Set<string>(), seenSpa = new Set<string>(), seenDep = new Set<string>()
  const ok = (o?: string): boolean => !approvedOrigins?.size || !o || approvedOrigins.has(o)
  for (const fact of facts) {
    if (fact.tainted || !ok(fact.origin) || !fact.data || typeof fact.data !== 'object') continue
    const data = fact.data, subkind = typeof data.subkind === 'string' ? data.subkind : '', fOrigin = typeof data.origin === 'string' && data.origin ? data.origin : fact.origin
    if (subkind === 'runtime_spa_routes' && Array.isArray(data.spaRoutes)) {
      for (const r of data.spaRoutes as Partial<RuntimeSpaRoute>[]) {
        const so = typeof r?.serviceOrigin === 'string' ? r.serviceOrigin : fOrigin
        if (typeof r?.path !== 'string' || !r.path.startsWith('/') || !ok(so) || seenSpa.has(`${so ?? ''}|${r.path}`)) continue
        seenSpa.add(`${so ?? ''}|${r.path}`)
        spaRoutes.push({ path: r.path, ...(so ? { serviceOrigin: so } : {}), ...(Array.isArray(r.apiCalls) ? { apiCalls: r.apiCalls } : {}), ...(Array.isArray(r.stateActions) ? { stateActions: r.stateActions } : {}), ...(Array.isArray(r.requiredRoles) ? { requiredRoles: r.requiredRoles } : {}) })
      }
    } else if (subkind === 'runtime_graphql_catalog') {
      const cats = Array.isArray(data.graphqlCatalogs) ? data.graphqlCatalogs : data.graphqlCatalog ? [data.graphqlCatalog] : []
      for (const c of cats as Partial<RuntimeGraphqlCatalog>[]) {
        const so = typeof c?.serviceOrigin === 'string' ? c.serviceOrigin : fOrigin
        if (!Array.isArray(c?.fields) || !c.fields.length || !ok(so)) continue
        graphqlCatalogs.push({ endpoint: typeof c.endpoint === 'string' && c.endpoint ? c.endpoint : '/graphql', ...(so ? { serviceOrigin: so } : {}), fields: c.fields })
      }
    } else if (subkind === 'runtime_openapi_catalog' && Array.isArray(data.openApiOperations)) {
      for (const o of data.openApiOperations as Partial<RuntimeOpenApiOperation>[]) {
        const so = typeof o?.serviceOrigin === 'string' ? o.serviceOrigin : fOrigin
        if (typeof o?.method !== 'string' || typeof o?.path !== 'string' || !ok(so)) continue
        const k = `${so ?? ''}|${o.method.toUpperCase()}|${o.path}`
        if (seenOa.has(k)) continue
        seenOa.add(k)
        openApiOperations.push({ method: o.method.toUpperCase(), path: o.path, ...(o.operationId ? { operationId: o.operationId } : {}), ...(Array.isArray(o.security) ? { security: o.security } : {}), ...(o.authRequirement !== undefined ? { authRequirement: o.authRequirement } : {}), ...(Array.isArray(o.parameters) ? { parameters: o.parameters } : {}), ...(Array.isArray(o.requestBodyKeys) ? { requestBodyKeys: o.requestBodyKeys } : {}), ...(Array.isArray(o.tags) ? { tags: o.tags } : {}), ...(so ? { serviceOrigin: so } : {}) })
      }
    } else if (subkind === 'runtime_api_dependencies' && Array.isArray(data.apiDependencies)) {
      for (const d of data.apiDependencies as Partial<RuntimeApiDependency>[]) {
        if (typeof d?.producer !== 'string' || typeof d?.consumer !== 'string' || typeof d?.resourceKey !== 'string') continue
        const k = `${d.producerOrigin ?? ''}|${d.producer}|${d.consumerOrigin ?? ''}|${d.consumer}|${d.resourceKey}`
        if (seenDep.has(k)) continue
        seenDep.add(k)
        apiDependencies.push({ producer: d.producer, consumer: d.consumer, resourceKey: d.resourceKey, ...(d.producerOrigin ? { producerOrigin: d.producerOrigin } : {}), ...(d.consumerOrigin ? { consumerOrigin: d.consumerOrigin } : {}), ...(d.personaHandle !== undefined ? { personaHandle: d.personaHandle } : {}), ...(Array.isArray(d.observedTransitions) ? { observedTransitions: d.observedTransitions } : {}), ...(typeof d.testedBola === 'boolean' ? { testedBola: d.testedBola } : {}) })
      }
    }
  }
  return { openApiOperations, ...(graphqlCatalogs[0] ? { graphqlCatalog: graphqlCatalogs[0] } : {}), graphqlCatalogs, spaRoutes, apiDependencies }
}

export interface BuildRuntimeDiscoveryInputParams {
  approvedOrigins?: ReadonlySet<string>; endpoints?: ReadonlyArray<{ origin: string; method: string; pathTemplate: string; authRequirement?: string | null; source?: string | null }>
  specs?: ReadonlyArray<{ kind: string; origin?: string | null; content: string }>; facts?: ReadonlyArray<{ origin?: string; data?: Record<string, unknown> | null; tainted?: boolean }>
  brokerExchanges?: ReadonlyArray<{ origin: string; method: string; pathAndQuery: string; status: number; personaHandle?: string | null; respHeaders?: Record<string, string> | null; respHeadersJson?: string | null }>
  apiDependencies?: readonly RuntimeApiDependency[]; spaRoutes?: readonly RuntimeSpaRoute[]; graphqlCatalog?: RuntimeGraphqlCatalog; graphqlCatalogs?: readonly RuntimeGraphqlCatalog[]; maxHypotheses?: number
}

/** Pure builder combining endpoints (filtering 404/405-only `surface_probe` ghosts), OpenAPI specs (with `$ref` response schemas), Phase-0 catalogs, live response headers & synthesized `produces -> consumes` edges. */
export function buildRuntimeDiscoveryInput(params: BuildRuntimeDiscoveryInputParams): Omit<RuntimeDiscoveryInput, 'mode'> {
  const approved = params.approvedOrigins, ok = (o?: string | null): boolean => !approved?.size || !o || approved.has(o)
  const extracted = extractRuntimeCatalogFromFacts(params.facts ?? [], approved), openApiByKey = new Map<string, RuntimeOpenApiOperation>()
  const evidencedRoutes = new Set<string>()
  const markEvidenced = (o: string | undefined | null, p: string, m?: string) => {
    const np = normalizeRouteMatchPath(p); evidencedRoutes.add(`${o ?? ''}|${np}`); if (m) evidencedRoutes.add(`${o ?? ''}|${m.toUpperCase()}|${np}`)
  }
  for (const op of extracted.openApiOperations) markEvidenced(op.serviceOrigin, op.path, op.method)
  for (const r of [...extracted.spaRoutes, ...(params.spaRoutes ?? [])]) for (const c of r.apiCalls ?? []) markEvidenced(c.serviceOrigin ?? r.serviceOrigin, c.path, c.method)
  for (const g of [...extracted.graphqlCatalogs, ...(params.graphqlCatalog ? [params.graphqlCatalog] : []), ...(params.graphqlCatalogs ?? [])]) markEvidenced(g.serviceOrigin, g.endpoint ?? '/graphql')
  const parsedSpecs: Array<{ origin?: string; doc: Record<string, unknown> }> = []
  for (const spec of (params.specs ?? []).slice(0, 8)) {
    if (spec.kind !== 'openapi' || !ok(spec.origin)) continue
    try {
      const doc = JSON.parse(spec.content) as Record<string, unknown>
      if (doc && typeof doc === 'object' && !Array.isArray(doc)) {
        parsedSpecs.push({ ...(spec.origin ? { origin: spec.origin } : {}), doc })
        for (const pk of Object.keys((doc.paths as Record<string, unknown>) ?? {})) markEvidenced(spec.origin, pk)
      }
    } catch { /* non-JSON specs handled by Phase-0 parseOpenApiDoc */ }
  }
  const upsertOp = (op: RuntimeOpenApiOperation): void => {
    if (!ok(op.serviceOrigin)) return
    const k = `${op.serviceOrigin ?? ''}|${op.method.toUpperCase()}|${op.path}`, prev = openApiByKey.get(k)
    openApiByKey.set(k, prev ? { ...prev, ...op, method: op.method.toUpperCase(), operationId: op.operationId ?? prev.operationId, security: op.security !== undefined ? op.security : prev.security, authRequirement: op.authRequirement ?? prev.authRequirement, parameters: op.parameters?.length ? op.parameters : prev.parameters, requestBodyKeys: op.requestBodyKeys?.length ? op.requestBodyKeys : prev.requestBodyKeys, tags: op.tags?.length ? op.tags : prev.tags } : { ...op, method: op.method.toUpperCase() })
  }
  const liveEndpoints = filterGhostSurfaceProbeEndpoints((params.endpoints ?? []).filter(ep => ok(ep.origin)), params.brokerExchanges ?? [], evidencedRoutes)
  for (const ep of liveEndpoints) {
    const ar = ep.authRequirement?.trim() || null
    upsertOp({ method: ep.method, path: ep.pathTemplate, serviceOrigin: ep.origin, ...(ar ? { authRequirement: ar, security: MISSING_AUTH_REQ_RE.test(ar) ? [] : [{ [ar]: [] }] } : {}) })
  }
  for (const op of extracted.openApiOperations) upsertOp(op)
  const producedByRoute = new Map<string, { origin?: string; method: string; path: string; fields: Map<string, ResponseSignalEdgeKind> }>()
  const noteProduced = (origin: string | undefined, method: string, path: string, field: string, kind: ResponseSignalEdgeKind) => {
    const rk = `${origin ?? ''}|${method.toUpperCase()}|${normalizeDepPath(path)}`
    let rec = producedByRoute.get(rk)
    if (!rec) { rec = { ...(origin ? { origin } : {}), method: method.toUpperCase(), path: normalizeDepPath(path), fields: new Map() }; producedByRoute.set(rk, rec) }
    if (rec.fields.size < 24 && !rec.fields.has(field)) rec.fields.set(field, kind)
  }
  for (const { origin, doc } of parsedSpecs) {
    const docSec = Array.isArray(doc.security) ? doc.security as Array<Record<string, string[]>> : undefined
    for (const [pathKey, methods] of Object.entries((doc.paths as Record<string, Record<string, Record<string, unknown>>>) ?? {})) {
      if (!methods || typeof methods !== 'object') continue
      for (const [method, op] of Object.entries(methods)) {
        if (!/^(?:get|post|put|patch|delete|options|head)$/i.test(method) || !op || typeof op !== 'object') continue
        const sec = Array.isArray(op.security) ? op.security as Array<Record<string, string[]>> : docSec
        const reqProps = new Set<string>()
        for (const m of Object.values(((op.requestBody as { content?: Record<string, { schema?: unknown }> })?.content) ?? {})) collectOpenApiSchemaProperties(doc, m?.schema, reqProps)
        const parameters = (Array.isArray(op.parameters) ? op.parameters : []).map(p => (p as { name?: string })?.name).filter((n): n is string => typeof n === 'string' && n.length > 0)
        upsertOp({ method: method.toUpperCase(), path: pathKey, ...(typeof op.operationId === 'string' ? { operationId: op.operationId } : {}), ...(sec !== undefined ? { security: sec } : {}), ...(parameters.length ? { parameters } : {}), ...(reqProps.size ? { requestBodyKeys: [...reqProps] } : {}), ...(Array.isArray(op.tags) ? { tags: op.tags as string[] } : {}), ...(origin ? { serviceOrigin: origin } : {}) })
        for (const [statusKey, rawResp] of Object.entries((op.responses as Record<string, Record<string, unknown>>) ?? {})) {
          if (!/^(?:2\d\d|default)$/i.test(statusKey) || !rawResp || typeof rawResp !== 'object') continue
          const stNum = /^\d+$/.test(statusKey) ? Number(statusKey) : 200
          if (stNum === 202) noteProduced(origin, method, pathKey, 'status:202', 'await_async')
          const respProps = new Set<string>()
          if (rawResp.schema) collectOpenApiSchemaProperties(doc, rawResp.schema, respProps)
          for (const m of Object.values(((rawResp.content as Record<string, { schema?: unknown }>) ?? {}))) collectOpenApiSchemaProperties(doc, m?.schema, respProps)
          for (const f of respProps) { const k = classifyStructuralFieldEdgeKind(f, 'json'); if (k) noteProduced(origin, method, pathKey, f, stNum === 202 && k === 'lifecycle_state' ? 'await_async' : k) }
          for (const h of Object.keys((rawResp.headers as Record<string, unknown>) ?? {})) { const k = classifyStructuralFieldEdgeKind(h, 'header', { status: stNum }); if (k) noteProduced(origin, method, pathKey, h.toLowerCase(), k) }
        }
      }
    }
  }
  const personaObservations: PersonaSurfaceObservation[] = []
  for (const row of params.brokerExchanges ?? []) {
    if (!ok(row.origin)) continue
    const pathOnly = row.pathAndQuery.split(/[?#]/, 1)[0] || '/'
    let responseHeaders = row.respHeaders ?? undefined
    if (!responseHeaders && row.respHeadersJson) { try { responseHeaders = JSON.parse(row.respHeadersJson) as Record<string, string> } catch { /* ignore */ } }
    const headerSignals: string[] = []
    if (row.status >= 200 && row.status < 300) {
      if (row.status === 202) { noteProduced(row.origin, row.method, pathOnly, 'status:202', 'await_async'); headerSignals.push('status:202') }
      for (const [hk, hv] of Object.entries(responseHeaders ?? {})) {
        const lower = hk.trim().toLowerCase()
        const k = classifyStructuralFieldEdgeKind(lower, 'header', { status: row.status, headerValueHint: typeof hv === 'string' ? hv : undefined })
        if (k) { noteProduced(row.origin, row.method, pathOnly, lower, k); headerSignals.push(lower) }
      }
    }
    personaObservations.push({ persona: row.personaHandle?.trim() || 'anonymous', surface: classifySurface(pathOnly, row.method), serviceOrigin: row.origin, method: row.method.toUpperCase(), path: pathOnly, status: row.status, ...(responseHeaders ? { responseHeaders } : {}), ...(headerSignals.length ? { bodyKeys: headerSignals } : {}), isBatch: /\/(?:batch|bulk|multi)(?:\/|$)/i.test(pathOnly) })
  }
  // Synthesize dynamic cross-route `produces -> consumes` edges from harvested OpenAPI responses & live headers.
  const allOps = [...openApiByKey.values()], synthesizedDeps: RuntimeApiDependency[] = [], seenSynth = new Set<string>()
  const consumerByTok = new Map<string, RuntimeOpenApiOperation[]>(), asyncOps: RuntimeOpenApiOperation[] = [], webhookOps: RuntimeOpenApiOperation[] = [], storageOps: RuntimeOpenApiOperation[] = []
  for (const op of allOps) {
    const s = classifySurface(op.path, op.method, op.operationId ?? '')
    if (s === 'async_job' || ASYNC_ROUTE_RE.test(op.path)) asyncOps.push(op)
    if (s === 'webhook' || WEBHOOK_ROUTE_RE.test(op.path)) webhookOps.push(op)
    if (s === 'storage' || STORAGE_ROUTE_RE.test(op.path)) storageOps.push(op)
    const pNames = [...(op.parameters ?? []), ...(op.requestBodyKeys ?? []), ...[...op.path.matchAll(/(?::([a-zA-Z0-9_-]+)|\{([a-zA-Z0-9_-]+)\})/g)].map(m => m[1] ?? m[2] ?? '')]
    for (const pn of pNames) { const t = canonicalParamToken(pn); if (t.length >= 3 && t !== 'id') pushMap(consumerByTok, t, op) }
  }
  const addSynthDep = (pOrigin: string | undefined, pRef: string, cOp: RuntimeOpenApiOperation, rk: string, kind: string) => {
    if (synthesizedDeps.length >= 48) return
    const cRef = `${cOp.method.toUpperCase()} ${normalizeDepPath(cOp.path)}`
    if (pRef === cRef && (pOrigin ?? '') === (cOp.serviceOrigin ?? '')) return
    const dk = `${pOrigin ?? ''}|${pRef}|${cOp.serviceOrigin ?? ''}|${cRef}|${rk}`
    if (seenSynth.has(dk)) return
    seenSynth.add(dk)
    synthesizedDeps.push({ producer: pRef, consumer: cRef, resourceKey: rk, ...(pOrigin ? { producerOrigin: pOrigin } : {}), ...(cOp.serviceOrigin ? { consumerOrigin: cOp.serviceOrigin } : {}), observedTransitions: [`edge_kind:${kind}`] })
  }
  for (const prod of producedByRoute.values()) {
    const pRef = `${prod.method} ${prod.path}`
    for (const [field, kind] of prod.fields) {
      for (const c of consumerByTok.get(canonicalParamToken(field)) ?? []) addSynthDep(prod.origin, pRef, c, field, kind)
      if (kind === 'await_async') for (const c of asyncOps.slice(0, 4)) addSynthDep(prod.origin, pRef, c, field, 'await_async')
      if (kind === 'hmac_sign') for (const c of webhookOps.slice(0, 4)) addSynthDep(prod.origin, pRef, c, field, 'hmac_sign')
      if (kind === 'signed_url') for (const c of storageOps.slice(0, 4)) addSynthDep(prod.origin, pRef, c, field, 'signed_url')
    }
  }
  const graphqlCatalogs = [...extracted.graphqlCatalogs, ...(params.graphqlCatalog ? [params.graphqlCatalog] : []), ...(params.graphqlCatalogs ?? [])].filter(c => ok(c.serviceOrigin))
  const spaRoutes = [...extracted.spaRoutes, ...(params.spaRoutes ?? [])].filter(r => ok(r.serviceOrigin))
  const apiDependencies = [...extracted.apiDependencies, ...(params.apiDependencies ?? []), ...synthesizedDeps].filter(d => ok(d.producerOrigin) && ok(d.consumerOrigin))
  return { personaObservations, openApiOperations: allOps, ...(graphqlCatalogs[0] ? { graphqlCatalog: graphqlCatalogs[0] } : {}), ...(graphqlCatalogs.length ? { graphqlCatalogs } : {}), ...(spaRoutes.length ? { spaRoutes } : {}), ...(apiDependencies.length ? { apiDependencies } : {}), ...(params.maxHypotheses !== undefined ? { maxHypotheses: params.maxHypotheses } : {}) }
}

/** Pre-floor & post-Phase-A-floor helper for `exec-recon-planner.ts` returning full and incremental runtime invariants. */
export function synthesizePostFloorRuntimeInvariants(params: BuildRuntimeDiscoveryInputParams & { mode?: 'grey-box' | 'black-box'; existingHypothesisIds?: ReadonlySet<string> }): {
  mode: 'grey-box' | 'black-box'; runtimeInput: Omit<RuntimeDiscoveryInput, 'mode'>; runtimeParity: RuntimeInvariantParityResult; hypotheses: InvariantHypothesis[]; newHypotheses: InvariantHypothesis[]; capabilitySeeds: CapabilitySeedRecord[]
} {
  const mode = params.mode ?? 'grey-box', runtimeInput = buildRuntimeDiscoveryInput(params)
  const runtimeParity = inferRuntimeInvariantHypotheses({ mode, ...runtimeInput })
  const newHypotheses = params.existingHypothesisIds?.size ? runtimeParity.hypotheses.filter(h => !params.existingHypothesisIds!.has(h.id)) : runtimeParity.hypotheses
  return { mode, runtimeInput, runtimeParity, hypotheses: runtimeParity.hypotheses, newHypotheses, capabilitySeeds: toCapabilityLedgerSeeds(newHypotheses) }
}
