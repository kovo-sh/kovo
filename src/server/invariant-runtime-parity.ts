/** Shared pure normalization primitives for v8 Layer 2 white-box invariant synthesis (`invariant-synthesizer.ts`). */
import { createHash } from 'node:crypto'
import type {
  CapabilitySeedRecord,
  CapabilitySurface,
  HypothesisSeverity,
  InvariantHypothesis,
  LifecyclePatternKind,
} from './invariant-synthesizer.ts'

const WRAPPER_SEG_RE = /^(?:v\d+(?:\.\d+)?|api|rest|rpc|internal|private|public|external|edge|app|portal|admin|batch|bulk|stream|events|sse|ws|socket|graphql|gql|async|jobs|workers|exports|webhooks|callbacks|hooks|files|storage|download|upload|search)$/i
const PUBLIC_EXEMPT_RE = /\/(?:login|signin|sign-in|register|signup|sign-up|logout|health|healthz|ready|readyz|livez|metrics|status|ping|jwks|\.well-known|openid-configuration|favicon)(?:\/|[?#]|$)/i
const STATIC_ASSET_EXT_RE = /\.(?:png|svg|jpe?g|webp|gif|ico|css|m?js|map|woff2?|ttf|eot|avif|mp4|webm|pdf|txt|xml)(?:[?#]|$)/i
const STATIC_ASSET_PREFIX_RE = /^\/(?:_next\/static\/|_next\/image(?:\/|[?#]|$)|static\/|assets\/|images\/|fonts\/|favicon(?:[./?#]|$))/i
export const BATCH_HINT_RE = /(?:\/(?:batch|bulk|multi)(?:\/|$)|batch[A-Z_]|bulk[A-Z_]|arrayOfIds|\bids\b)/i
export const MUTATING_METHOD_RE = /^(?:POST|PUT|PATCH|DELETE|MUTATION)$/i
const STRUCTURAL_STATE_FIELD_RE = /\b(?:status|state)\b\s*(?:===?|!==?|=|:)/i
const STRUCTURAL_OWNER_ACTOR_RE = /\b(?:createdBy|ownerId|authorId|approverId|approvedBy|userId|actorId)\b/i
const STRUCTURAL_ARITHMETIC_MUTATION_RE = /(?:[+\-*]=\s*[a-zA-Z_][a-zA-Z0-9_]*|\b(?:amount|balance|quantity|quota|limit)\b\s*(?:[+\-*]=|[<>]=?))/i
const SECRET_SCRUB_RE = /(?:eyJ[A-Za-z0-9_-]{12,}\.[A-Za-z0-9_-]{8,}(?:\.[A-Za-z0-9_-]{6,})?|\b(?:sk|pk|rk|pat|tok|sec|key)_(?:live|test|prod|dev|secret)_[A-Za-z0-9_-]{8,}\b|Bearer\s+[A-Za-z0-9._-]{16,}|\b[0-9a-f]{40,}\b)/g
const ENTITY_ACTION_VERB_RE = /^(?:create|update|delete|remove|list|get|fetch|approve|reject|cancel|promote|demote|transfer|export|sync|trigger|download|preview|verify|redeem|revoke|dispatch|run|start|stop|stream|subscribe|watch|listen|notify|emit|read|write|grant|invite|batch|bulk|multi|process|handle|resolve|query|mutate|submit|publish|archive|activate|suspend|release|schedule)$/i

/** True when `path` is a public/health route or static CDN asset path/extension. */
export function isPublicOrStaticAssetPath(path: string): boolean {
  const normalized = path.trim().replace(/^https?:\/\/[^/?#]+/i, '')
  return PUBLIC_EXEMPT_RE.test(normalized) || STATIC_ASSET_PREFIX_RE.test(normalized) || STATIC_ASSET_EXT_RE.test(normalized)
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
