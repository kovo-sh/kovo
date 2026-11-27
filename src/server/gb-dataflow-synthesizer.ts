import { createHash } from 'node:crypto'
import { classifyPersonaPrivilege } from './assignment-brief.ts'
import { materializeCapabilityConsumerFrontierSteps, type FrontierLlmMode } from './capability-consumer-frontier.ts'
import {
  computeArtifactDigest,
  formatDerivedCapabilityHandle,
  sanitizeCheckpointText,
  type CapabilityKind,
  type CapabilitySurface,
} from './capability-ledger.ts'
import { resolveRunPersonas } from './persona-vault.ts'
import { normalizeRouteTemplate } from './route-template.ts'
import type { ChainStep, Fact, Run, Store } from './store.ts'

export type ProducerTokenKind = 'signing_secret' | 'credential_token' | 'invite_or_grant' | 'signed_url_or_location' | 'async_job_or_export' | 'entity_id'

export interface GbDataflowEndpointInput { id: string; origin: string; method: string; pathTemplate: string; authRequirement?: string | null; riskScore?: number; source?: string; sinkKinds?: readonly string[] }
export interface GbDataflowParamInput { endpointId: string; name: string; location: string; inferredType?: string | null; isObjectId?: boolean }
export interface GbDataflowDependencyInput { producerEndpointId?: string; consumerEndpointId?: string; producer?: string; consumer?: string; producerOrigin?: string; consumerOrigin?: string; resourceKey: string; personaHandle?: string | null }
export interface GbDataflowExchangeInput { id?: string; origin: string; finalOrigin?: string | null; method: string; pathAndQuery: string; status: number; personaHandle?: string | null; respHeaders?: Record<string, string> | string | null; bodyPreview?: string | null; createdAt?: number }
export interface GbDataflowPersonaInput { handle: string; roleLabel?: string | null; tenantLabel?: string | null; configIndex?: number }
export interface GbDataflowSynthesizeInput {
  approvedOrigins: readonly string[] | ReadonlySet<string>
  endpoints: readonly GbDataflowEndpointInput[]
  endpointParams?: readonly GbDataflowParamInput[]
  apiDependencies?: readonly GbDataflowDependencyInput[]
  brokerExchanges?: readonly GbDataflowExchangeInput[]
  personas?: readonly GbDataflowPersonaInput[]
  sourceMounted?: boolean; mountedRepos?: readonly string[]; maxSteps?: number
}
export interface GbDataflowStepDraft { title: string; hypothesis: string; category: string; priority: number; origins: string[]; skills: string[]; fromLive?: boolean }
export interface GbDataflowChainSummary { signature: string; hops: Array<{ origin: string; method: string; pathTemplate: string }>; origins: string[]; fields: string[]; kinds: ProducerTokenKind[]; score: number; fromLive: boolean; hasPersonaAsymmetry: boolean; has202: boolean; step: GbDataflowStepDraft }
export interface GbDataflowSynthesizeResult { steps: GbDataflowStepDraft[]; chains: GbDataflowChainSummary[]; nodeCount: number; edgeCount: number }

interface ProducedCap { field: string; kind: ProducerTokenKind; noun: string; fromLive: boolean; targetOrigin?: string; targetNormPath?: string; valueDigest?: string; exchangeId?: string; factId?: string; observedAtMs?: number; persona?: string }
interface PersonaDiff { allowed: string[]; denied: string[]; hasAsymmetry: boolean; has202: boolean; summary: string }
interface EndpointNode {
  key: string; id: string; origin: string; host: string; role: 'auth' | 'api' | 'edge' | 'general'
  method: string; normPath: string; nouns: string[]; primaryNoun: string; isMutating: boolean; isHighValue: boolean
  paramNames: Set<string>; consumedNouns: Set<string>; sinkKinds: string[]; acceptsSigning: boolean; acceptsCredential: boolean; acceptsInvite: boolean
  acceptsSignedUrl: boolean; acceptsAsyncJob: boolean; hasSignatureRejection: boolean; produces: ProducedCap[]
  personaStatuses: Map<string, Set<number>>; personaDiff: PersonaDiff
}
interface DataflowEdge { from: EndpointNode; to: EndpointNode; field: string; kind: ProducerTokenKind; crossOrigin: boolean; fromLive: boolean; score: number }

const DEFAULT_MAX_STEPS = 6
const MAX_OUTGOING = 8
const MAX_JSON_KEYS = 60
const MUTATING = new Set(['POST', 'PUT', 'PATCH', 'DELETE'])
const NOISE_KEYS = new Set([
  'ok', 'success', 'error', 'errors', 'message', 'msg', 'status', 'status_code', 'timestamp', 'created_at',
  'updated_at', 'expires_at', 'expires_in', 'ttl', 'count', 'total', 'page', 'limit', 'offset', 'version',
  'type', 'name', 'description', 'title', 'email', 'data', 'result', 'results', 'items', 'meta', 'headers', 'detail', 'reason',
])
const SKIP_SEGS = new Set(['api', 'v1', 'v2', 'v3', 'v4', 'rest', 'public', 'internal', 'service', 'services', 'app', 'oauth', 'oauth2', 'oidc', 'auth', 'graphql', 'gql'])
const ACTION_VERBS = new Set([
  'approve', 'rebind', 'settle', 'release', 'finalize', 'commit', 'publish', 'capture', 'revoke', 'redeem',
  'exchange', 'verify', 'callback', 'resolve', 'sync', 'download', 'content', 'url', 'status', 'result',
  'cancel', 'accept', 'claim', 'dispatch', 'trigger', 'execute', 'run', 'impersonate', 'assume', 'delegate',
  'mint', 'sign', 'rotate', 'reset', 'batch', 'list', 'create', 'update', 'delete', 'get', 'search', 'query',
  'export', 'import', 'transfer', 'grant', 'issue', 'complete', 'confirm', 'fetch', 'proxy', 'redirect', 'render', 'join', 'onboard',
  'promote', 'rollback', 'deliver', 'deliveries', 'trace', 'archive', 'logs', 'redeploy', 'retry', 'resume', 'pause', 'abort', 'ship', 'refund', 'dispute', 'replay',
])
const ASYNC_NOUNS = new Set(['job', 'export', 'render', 'task', 'run', 'build', 'batch', 'report', 'archive', 'snapshot', 'pipeline', 'workflow', 'deployment', 'release'])
const CRED_NOUNS = new Set(['token', 'session', 'key', 'secret', 'credential', 'pat', 'jwt', 'assertion', 'delegation'])
const INVITE_NOUNS = new Set(['invite', 'invitation', 'grant', 'ticket', 'otp', 'challenge'])
const HEALTH_RE = /^\/(?:health|healthz|ready|readyz|live|livez|metrics|ping|favicon\.ico|robots\.txt)(?:\/|$)/i
const SIGNING_KEY_RE = /(?:^|_)(?:signing_secret|signing_key|signing_salt|hmac_secret|hmac_key|hmac_salt|webhook_secret|webhook_key|webhook_salt|shared_secret|secret_key|private_key|jwt_secret|client_secret|sig_secret|mac_key)(?:$|_)/
const INVITE_KEY_RE = /(?:^|_)(?:invite|invitation|invite_token|invite_code|grant|grant_code|ticket|otp|reset_token|reset_code|claim_code|claim_token|magic_link|verify_code|approval_code|auth_code|state)(?:$|_)/
const CRED_KEY_RE = /(?:^|_)(?:token|jwt|bearer|session|access_token|id_token|refresh_token|delegation|assertion|api_key|apikey|pat|secret|signing_key|hmac|auth_token|exchange_token|service_token|client_secret|credential|scim_token|impersonation_token)(?:$|_)/
const URL_KEY_RE = /(?:^|_)(?:signed_url|presigned_url|download_url|upload_url|export_url|artifact_url|file_url|callback_url|redirect_uri|redirect_url|redirect|location|href|url|download_link|result_url)(?:$|_)/
const ASYNC_KEY_RE = /(?:^|_)(?:job_id|export_id|render_id|task_id|run_id|build_id|batch_id|pipeline_id|report_id|archive_id|snapshot_id|workflow_id|operation_id|deployment_id|release_id)(?:$|_)/
const JWT_VAL_RE = /^eyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}/
const PREFIXED_ID_VAL_RE = /^([a-z]{2,12})_[A-Za-z0-9_-]{4,48}$/i
const PREFIX_NOUN_MAP: Record<string, { noun: string; kind: ProducerTokenKind }> = {
  job: { noun: 'job', kind: 'async_job_or_export' },
  exp: { noun: 'export', kind: 'async_job_or_export' },
  export: { noun: 'export', kind: 'async_job_or_export' },
  dep: { noun: 'deployment', kind: 'async_job_or_export' },
  deploy: { noun: 'deployment', kind: 'async_job_or_export' },
  rel: { noun: 'release', kind: 'async_job_or_export' },
  bld: { noun: 'build', kind: 'async_job_or_export' },
  run: { noun: 'run', kind: 'async_job_or_export' },
  ord: { noun: 'order', kind: 'entity_id' },
  order: { noun: 'order', kind: 'entity_id' },
  pay: { noun: 'payout', kind: 'entity_id' },
  payout: { noun: 'payout', kind: 'entity_id' },
  xfer: { noun: 'transfer', kind: 'entity_id' },
  inv: { noun: 'invite', kind: 'invite_or_grant' },
  invite: { noun: 'invite', kind: 'invite_or_grant' },
  wh: { noun: 'webhook', kind: 'entity_id' },
  hook: { noun: 'webhook', kind: 'entity_id' },
  whsec: { noun: 'webhook', kind: 'signing_secret' },
  tok: { noun: 'token', kind: 'credential_token' },
  key: { noun: 'key', kind: 'credential_token' },
}
const LOW_PRIV_RE = /\b(?:member|viewer|guest|basic|user|demoted|revoked|suspended|external|readonly|read_only|limited|standard)\b/i
const AUTH_HOST_RE = /(?:^|[.-])(?:idp|auth|sso|login|oauth|oidc|iam|identity|accounts?)(?:[.-]|$)/i
const EDGE_HOST_RE = /(?:^|[.-])(?:edge|vault|storage|files?|cdn|media|runner|worker|jobs?|webhooks?|hooks?|proxy|gateway|sandbox|exec|render|export)(?:[.-]|$)/i
const API_HOST_RE = /(?:^|[.-])(?:api|core|backend|app|portal|console|admin|graphql|ledger|orders?|payments?)(?:[.-]|$)/i
const ACTION_RE = /\/(?:approve|rebind|settle|release|finalize|url|content|revoke|resolve|redeem|exchange|sync|download|webhook|hooks?|graphql|admin|secrets?|vault|export|dispatch|transfer|assume|impersonate|delegate|callback|verify|accept|claim|rollback|promote|deliver|deliveries|trace|result|results|archive|logs)(?:\/|$)/i
const SIG_CONSUMER_ROUTE_RE = /\/(?:webhooks?|hooks?|ingest|callback|callbacks|events?|notify|deliver|delivery|dispatch|verify|sign|signed|receive|receiver|inbound|push|sync)(?:\/|$)/i
const SIG_REJECTION_BODY_RE = /(?:sig(?:nature)?|hmac|digest|mac\b|webhook|x-signature|x-hub-signature|invalid[_ -]?(?:sig|hmac)|missing[_ -]?sig|bad[_ -]?sig)/i
const INVITE_ROUTE_RE = /\/(?:redeem|accept|claim|exchange|callback|verify|reset|join|onboard|register|invite|invites|grant|grants|token)(?:\/|$)/i
const URL_ROUTE_RE = /\/(?:download|content|files?|artifacts?|fetch|proxy|redirect|resolve|render|import|webhooks?|callback|signed|presign|url|export|exports)(?:\/|$)/i
const CRED_ROUTE_RE = /\/(?:exchange|verify|assume|delegate|impersonate|admin|internal|vault|secrets?|keys?|graphql|webhooks?|payouts?|transfers?|orders?|exports?|users?|roles?|permissions?|settings?|scim|sync)(?:\/|$)/i
const KIND_BONUS: Record<ProducerTokenKind, number> = { signing_secret: 26, credential_token: 22, invite_or_grant: 20, signed_url_or_location: 18, async_job_or_export: 18, entity_id: 12 }

const toSnake = (raw: string) => raw.trim().replace(/([a-z0-9])([A-Z])/g, '$1_$2').replace(/[^A-Za-z0-9]+/g, '_').replace(/^_+|_+$/g, '').toLowerCase()
const singularize = (w: string) => w.length <= 2 ? w : w.endsWith('ies') && w.length > 4 ? `${w.slice(0, -3)}y` : /(?:ses|xes|zes|ches|shes)$/.test(w) && w.length > 4 ? w.slice(0, -2) : w.endsWith('s') && !/(?:ss|us|is)$/.test(w) ? w.slice(0, -1) : w
const hostOf = (o: string) => URL.canParse(o) ? new URL(o).host.toLowerCase() : o.replace(/^https?:\/\//i, '').replace(/\/.*$/, '').toLowerCase()

function classifyOriginRole(origin: string, paths: readonly string[]): 'auth' | 'api' | 'edge' | 'general' {
  const host = URL.canParse(origin) ? new URL(origin).hostname.toLowerCase() : hostOf(origin)
  if (AUTH_HOST_RE.test(host)) return 'auth'
  if (EDGE_HOST_RE.test(host)) return 'edge'
  if (API_HOST_RE.test(host)) return 'api'
  const joined = paths.join(' ').toLowerCase()
  return /\/(?:oauth|oidc|sso|saml|login|token|authorize)\b/.test(joined) ? 'auth'
    : /\/(?:download|artifacts?|vault|secrets?|webhooks?|runner|signed)\b/.test(joined) ? 'edge'
      : /\/(?:api|v1|v2|graphql)\b/.test(joined) ? 'api' : 'general'
}

function extractRouteNouns(normPath: string): string[] {
  const out: string[] = []
  for (const raw of normPath.split('/')) {
    const seg = raw.trim().toLowerCase()
    if (!seg || seg.startsWith(':') || SKIP_SEGS.has(seg) || ACTION_VERBS.has(seg)) continue
    const noun = singularize(toSnake(seg.replace(/[^a-z0-9_-]/g, '')).split('_').pop() ?? '')
    if (noun.length >= 2 && !SKIP_SEGS.has(noun) && !ACTION_VERBS.has(noun)) out.push(noun)
  }
  return [...new Set(out)]
}

function classifyField(rawKey: string, routeNouns: readonly string[], status: number, normPath: string): { kind: ProducerTokenKind; noun: string } | null {
  const snake = toSnake(rawKey)
  if (!snake || snake.length < 2 || NOISE_KEYS.has(snake)) return null
  const primary = routeNouns[routeNouns.length - 1] ?? ''
  if (SIGNING_KEY_RE.test(snake)) return { kind: 'signing_secret', noun: primary || 'webhook' }
  if (INVITE_KEY_RE.test(snake) || (snake === 'code' && (INVITE_ROUTE_RE.test(normPath) || AUTH_HOST_RE.test(normPath)))) return { kind: 'invite_or_grant', noun: primary || 'invite' }
  if (URL_KEY_RE.test(snake)) return { kind: 'signed_url_or_location', noun: primary || 'url' }
  if (CRED_KEY_RE.test(snake)) return { kind: 'credential_token', noun: primary || 'token' }
  if (ASYNC_KEY_RE.test(snake)) return { kind: 'async_job_or_export', noun: singularize(snake.replace(/_id$/, '')) || primary || 'job' }
  if (status === 202 && (snake === 'id' || snake.endsWith('_id'))) return { kind: 'async_job_or_export', noun: snake === 'id' ? (primary || 'job') : singularize(snake.slice(0, -3)) }
  if (snake.endsWith('_id') && snake.length > 3) {
    const noun = singularize(snake.slice(0, -3).split('_').pop() ?? '')
    return !noun || NOISE_KEYS.has(noun) ? null : { kind: ASYNC_NOUNS.has(noun) ? 'async_job_or_export' : INVITE_NOUNS.has(noun) ? 'invite_or_grant' : 'entity_id', noun }
  }
  if ((snake === 'id' || snake === 'slug' || snake === 'handle' || snake === 'uuid') && primary) {
    return { kind: ASYNC_NOUNS.has(primary) ? 'async_job_or_export' : CRED_NOUNS.has(primary) ? 'credential_token' : INVITE_NOUNS.has(primary) ? 'invite_or_grant' : 'entity_id', noun: primary }
  }
  return null
}

function classifyConcreteStringValue(
  rawKey: string,
  rawVal: string,
  baseOrigin: string,
  approved: ReadonlySet<string>,
  routeNouns: readonly string[],
): { kind: ProducerTokenKind; noun: string; targetOrigin?: string; targetNormPath?: string } | null {
  const v = rawVal.trim()
  if (v.length < 4 || v.length > 1024) return null
  if (v.startsWith('http://') || v.startsWith('https://') || (v.startsWith('/') && /\/(?:download|export|file|artifact|result|content|signed|presign|callback|webhook|invite|accept|redeem|verify)/i.test(v))) {
    const target = resolveApprovedUrl(v, baseOrigin, approved)
    if (target) {
      const targetNouns = extractRouteNouns(target.normPath)
      return { kind: 'signed_url_or_location', noun: targetNouns[targetNouns.length - 1] || routeNouns[routeNouns.length - 1] || 'url', targetOrigin: target.origin, targetNormPath: target.normPath }
    }
  }
  if (JWT_VAL_RE.test(v) || /^Bearer\s+\S{8,}/i.test(v)) {
    return { kind: 'credential_token', noun: routeNouns[routeNouns.length - 1] || 'token' }
  }
  const pm = PREFIXED_ID_VAL_RE.exec(v)
  if (pm?.[1]) {
    const hit = PREFIX_NOUN_MAP[pm[1].toLowerCase()]
    if (hit) return { kind: hit.kind, noun: hit.noun }
  }
  const snake = toSnake(rawKey)
  if (snake && !NOISE_KEYS.has(snake) && /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(v)) {
    const noun = singularize(snake.replace(/_(?:id|uuid|ref)$/, '').split('_').pop() ?? '') || routeNouns[routeNouns.length - 1] || ''
    if (noun.length >= 2) return { kind: ASYNC_NOUNS.has(noun) ? 'async_job_or_export' : 'entity_id', noun }
  }
  return null
}

function resolveApprovedUrl(rawUrl: string, baseOrigin: string, approved: ReadonlySet<string>) {
  const t = rawUrl.trim()
  if (!t) return undefined
  try {
    const p = t.startsWith('/') ? new URL(t, baseOrigin) : new URL(t)
    const normPath = approved.has(p.origin) ? normalizeRouteTemplate(p.pathname, { preserveCase: false }) : ''
    return normPath && normPath !== '/' ? { origin: p.origin, normPath } : undefined
  } catch { return undefined }
}

function extractExchangeCaps(ex: GbDataflowExchangeInput, nouns: readonly string[], normPath: string, approved: ReadonlySet<string>): ProducedCap[] {
  const out: ProducedCap[] = []; const seen = new Set<string>()
  const baseMeta = {
    ...(ex.id ? { exchangeId: ex.id } : {}),
    ...(typeof ex.createdAt === 'number' && ex.createdAt > 0 ? { observedAtMs: ex.createdAt } : {}),
    ...(ex.personaHandle ? { persona: ex.personaHandle.trim() } : {}),
  }
  const digestOf = (field: string, rawVal: unknown) => computeArtifactDigest(`${ex.origin}|${ex.method}|${normPath}|${field}|${typeof rawVal === 'string' ? rawVal.slice(0, 128) : ''}`)
  const push = (c: ProducedCap) => { const k = `${c.kind}|${toSnake(c.field)}|${c.targetOrigin ?? ''}|${c.targetNormPath ?? ''}`; if (!seen.has(k)) { seen.add(k); out.push({ ...baseMeta, ...c }) } }
  let hdrObj: Record<string, string> = {}
  if (typeof ex.respHeaders === 'string') { try { const p = JSON.parse(ex.respHeaders) as unknown; if (p && typeof p === 'object' && !Array.isArray(p)) hdrObj = p as Record<string, string> } catch { /* ignore */ } }
  else if (ex.respHeaders) hdrObj = ex.respHeaders
  const hdrs: Record<string, string> = {}
  for (const [k, v] of Object.entries(hdrObj)) if (typeof v === 'string') hdrs[k.toLowerCase()] = v
  for (const locKey of ['location', 'content-location']) {
    if (hdrs[locKey]) {
      const target = resolveApprovedUrl(hdrs[locKey]!, ex.origin, approved)
      push({ field: locKey === 'location' ? 'Location' : 'Content-Location', kind: 'signed_url_or_location', noun: nouns[nouns.length - 1] || 'location', fromLive: true, valueDigest: digestOf(locKey, hdrs[locKey]), ...(target ? { targetOrigin: target.origin, targetNormPath: target.normPath } : {}) })
    }
  }
  if (hdrs['set-cookie']) {
    for (const part of hdrs['set-cookie'].split(/\r?\n|,(?=\s*[A-Za-z0-9_.-]+=)/)) {
      const m = /^\s*([A-Za-z0-9_.-]+)=/.exec(part)
      if (m?.[1] && !/^(?:path|domain|expires|max-age|samesite|secure|httponly)$/i.test(m[1])) push({ field: m[1], kind: 'credential_token', noun: 'session', fromLive: true, valueDigest: digestOf(m[1], part.slice(0, 64)) })
    }
  }
  for (const [hk, hv] of Object.entries(hdrs)) {
    if (!hk.startsWith('x-') || !hv.trim()) continue
    const hCls = classifyField(hk.slice(2), nouns, ex.status, normPath)
    if (hCls) {
      const urlTarget = hCls.kind === 'signed_url_or_location' ? resolveApprovedUrl(hv, ex.origin, approved) : undefined
      push({ field: hk, kind: hCls.kind, noun: hCls.noun, fromLive: true, valueDigest: digestOf(hk, hv), ...(urlTarget ? { targetOrigin: urlTarget.origin, targetNormPath: urlTarget.normPath } : {}) })
    }
  }
  const body = (ex.bodyPreview ?? '').trim()
  if (!body) return out
  let parsedOk = false
  if (body.startsWith('{') || body.startsWith('[')) {
    try {
      let visited = 0
      const walk = (val: unknown, depth: number) => {
        if (depth > 4 || visited >= MAX_JSON_KEYS || !val || typeof val !== 'object') return
        if (Array.isArray(val)) { for (const item of val.slice(0, 4)) walk(item, depth + 1); return }
        for (const [key, child] of Object.entries(val as Record<string, unknown>)) {
          if (++visited > MAX_JSON_KEYS) break
          const cls = classifyField(key, nouns, ex.status, normPath)
          if (cls) {
            const urlTarget = cls.kind === 'signed_url_or_location' && typeof child === 'string' ? resolveApprovedUrl(child, ex.origin, approved) : undefined
            push({ field: key, kind: cls.kind, noun: cls.noun, fromLive: true, valueDigest: digestOf(key, child), ...(urlTarget ? { targetOrigin: urlTarget.origin, targetNormPath: urlTarget.normPath } : {}) })
          } else if (typeof child === 'string') {
            const valCls = classifyConcreteStringValue(key, child, ex.origin, approved, nouns)
            if (valCls) push({ field: key, kind: valCls.kind, noun: valCls.noun, fromLive: true, valueDigest: digestOf(key, child), ...(valCls.targetOrigin ? { targetOrigin: valCls.targetOrigin, targetNormPath: valCls.targetNormPath } : {}) })
          }
          if (child && typeof child === 'object') walk(child, depth + 1)
        }
      }
      walk(JSON.parse(body), 0); parsedOk = true
    } catch { /* truncated JSON falls back to regex */ }
  }
  if (!parsedOk) {
    let count = 0
    for (const m of body.matchAll(/"([A-Za-z_][A-Za-z0-9_-]{0,48})"\s*:\s*("([^"]{1,256})")?/g)) {
      if (++count > MAX_JSON_KEYS) break
      const cls = classifyField(m[1]!, nouns, ex.status, normPath)
      if (cls) {
        const urlTarget = cls.kind === 'signed_url_or_location' && m[3] ? resolveApprovedUrl(m[3], ex.origin, approved) : undefined
        push({ field: m[1]!, kind: cls.kind, noun: cls.noun, fromLive: true, valueDigest: digestOf(m[1]!, m[3] ?? ''), ...(urlTarget ? { targetOrigin: urlTarget.origin, targetNormPath: urlTarget.normPath } : {}) })
      } else if (m[3]) {
        const valCls = classifyConcreteStringValue(m[1]!, m[3], ex.origin, approved, nouns)
        if (valCls) push({ field: m[1]!, kind: valCls.kind, noun: valCls.noun, fromLive: true, valueDigest: digestOf(m[1]!, m[3]), ...(valCls.targetOrigin ? { targetOrigin: valCls.targetOrigin, targetNormPath: valCls.targetNormPath } : {}) })
      }
    }
  }
  return out
}

function enrichNodes(nodes: readonly EndpointNode[], personas: readonly GbDataflowPersonaInput[]): void {
  const lowPriv = new Set(personas.filter(p => LOW_PRIV_RE.test(`${p.handle} ${p.roleLabel ?? ''}`)).map(p => p.handle))
  const deniedByOriginNoun = new Map<string, Set<string>>()
  for (const node of nodes) {
    if (!node.produces.some(p => p.fromLive)) {
      const addSpec = (field: string, kind: ProducerTokenKind, noun: string) => {
        if (!node.produces.some(p => p.kind === kind && toSnake(p.field) === toSnake(field))) node.produces.push({ field, kind, noun, fromLive: false })
      }
      if (/\/(?:signed[-_]?url|presign|download[-_]?url|upload[-_]?url|url)(?:\/|$)/i.test(node.normPath)) addSpec('signed_url', 'signed_url_or_location', node.primaryNoun || 'url')
      if (node.method === 'POST') {
        if (/\/(?:token|tokens|session|sessions|login|exchange|delegate|impersonate|keys|api[-_]?keys|pat|secrets|mint|sign|oauth)(?:\/|$)/i.test(node.normPath)) addSpec('access_token', 'credential_token', node.primaryNoun || 'token')
        else if (/\/(?:invite|invites|invitations|grant|grants|tickets|otp|reset|authorize)(?:\/|$)/i.test(node.normPath)) addSpec('invite_code', 'invite_or_grant', node.primaryNoun || 'invite')
        else if (ASYNC_NOUNS.has(node.primaryNoun) && !ACTION_RE.test(node.normPath)) addSpec(`${node.primaryNoun}_id`, 'async_job_or_export', node.primaryNoun)
        else if (node.primaryNoun && !node.normPath.endsWith('/:id') && !ACTION_RE.test(node.normPath)) addSpec(`${node.primaryNoun}_id`, 'entity_id', node.primaryNoun)
      } else if (node.method === 'GET' && node.primaryNoun && !node.normPath.includes('/:id') && !ACTION_RE.test(node.normPath)) {
        const k: ProducerTokenKind = CRED_NOUNS.has(node.primaryNoun) ? 'credential_token' : ASYNC_NOUNS.has(node.primaryNoun) ? 'async_job_or_export' : 'entity_id'
        addSpec(`${node.primaryNoun}_${k === 'credential_token' ? 'token' : 'id'}`, k, node.primaryNoun)
      }
    }
    const allowed: string[] = []; const denied: string[] = []; let has202 = false
    for (const [persona, statuses] of node.personaStatuses.entries()) {
      if (statuses.has(202)) has202 = true
      if ([...statuses].some(s => s >= 200 && s < 300)) allowed.push(persona)
      if ([...statuses].some(s => s === 401 || s === 403)) denied.push(persona)
    }
    const lowPrivOk = allowed.some(p => lowPriv.has(p) || LOW_PRIV_RE.test(p))
    const hasAsymmetry = (allowed.length > 0 && denied.length > 0) || (lowPrivOk && (node.isMutating || /\/(?:admin|internal|export|approve|rebind|settle|revoke|secrets?|vault)/i.test(node.normPath)))
    const summary = allowed.length && denied.length ? `${node.method} ${node.normPath} 2xx=[${allowed.join(',')}] vs 401/403=[${denied.join(',')}]`
      : has202 ? `${node.method} ${node.normPath} async 202 (${allowed.join(',')})`
        : hasAsymmetry ? `${node.method} ${node.normPath} 2xx for low-priv [${allowed.join(',')}]` : ''
    node.personaDiff = { allowed, denied, hasAsymmetry, has202, summary }
    if (node.primaryNoun && denied.length) {
      const s = deniedByOriginNoun.get(`${node.origin}|${node.primaryNoun}`) ?? new Set<string>()
      for (const p of denied) s.add(p)
      deniedByOriginNoun.set(`${node.origin}|${node.primaryNoun}`, s)
    }
  }
  for (const n of nodes) {
    if (n.personaDiff.hasAsymmetry || !n.primaryNoun || !n.personaDiff.allowed.length) continue
    const overlap = n.personaDiff.allowed.filter(p => deniedByOriginNoun.get(`${n.origin}|${n.primaryNoun}`)?.has(p))
    if (overlap.length) { n.personaDiff.hasAsymmetry = true; n.personaDiff.summary = `${n.method} ${n.normPath} allowed (2xx) for [${overlap.join(',')}] despite 403 on sibling ${n.primaryNoun} route` }
  }
}

function buildNodes(input: GbDataflowSynthesizeInput, approved: ReadonlySet<string>) {
  const paramsByEp = new Map<string, GbDataflowParamInput[]>()
  for (const p of input.endpointParams ?? []) (paramsByEp.get(p.endpointId) ?? paramsByEp.set(p.endpointId, []).get(p.endpointId)!).push(p)
  const pathsByOrigin = new Map<string, string[]>()
  for (const ep of input.endpoints) if (approved.has(ep.origin)) (pathsByOrigin.get(ep.origin) ?? pathsByOrigin.set(ep.origin, []).get(ep.origin)!).push(ep.pathTemplate)
  for (const ex of input.brokerExchanges ?? []) if (approved.has(ex.origin)) (pathsByOrigin.get(ex.origin) ?? pathsByOrigin.set(ex.origin, []).get(ex.origin)!).push(ex.pathAndQuery.split(/[?#]/, 1)[0] ?? '/')
  const byId = new Map<string, EndpointNode>(); const byKey = new Map<string, EndpointNode>()
  const makeNode = (id: string, origin: string, method: string, rawPath: string, authReq = '', risk = 55, params: readonly GbDataflowParamInput[] = [], sinkKinds: readonly string[] = []): EndpointNode | null => {
    if (!approved.has(origin)) return null
    const cleanMethod = method.trim().toUpperCase() || 'GET'
    const normPath = normalizeRouteTemplate(rawPath, { preserveCase: false })
    if (!normPath || normPath === '/' || HEALTH_RE.test(normPath)) return null
    const key = `${origin}|${cleanMethod}|${normPath}`
    const existing = byKey.get(key)
    if (existing) {
      if (id && !byId.has(id)) byId.set(id, existing)
      for (const sk of sinkKinds) if (!existing.sinkKinds.includes(sk)) existing.sinkKinds.push(sk)
      return existing
    }
    const nouns = extractRouteNouns(normPath); const primaryNoun = nouns[nouns.length - 1] ?? ''
    const paramNames = new Set<string>()
    for (const seg of (rawPath.split(/[?#]/, 1)[0] ?? '').split('/')) {
      const m = /^(?::([A-Za-z0-9_.-]+)|\{([A-Za-z0-9_.-]+)\}|\[([A-Za-z0-9_.-]+)\])$/.exec(seg.trim())
      const raw = m?.[1] ?? m?.[2] ?? m?.[3]
      if (raw) paramNames.add(toSnake(raw))
    }
    let hasObjId = normPath.includes('/:id')
    for (const p of params) { const sn = toSnake(p.name); if (sn) paramNames.add(sn); if (p.isObjectId) hasObjId = true }
    const consumedNouns = new Set<string>()
    for (const pn of paramNames) {
      if (pn.endsWith('_id') && pn.length > 3) consumedNouns.add(singularize(pn.slice(0, -3).split('_').pop() ?? ''))
      else if (pn !== 'id') consumedNouns.add(singularize(pn))
    }
    if (hasObjId || ACTION_RE.test(normPath)) for (const n of nouns) consumedNouns.add(n)
    const isMutating = MUTATING.has(cleanMethod); const isHighValue = isMutating || ACTION_RE.test(normPath) || risk >= 75
    const node: EndpointNode = {
      key, id: id || key, origin, host: hostOf(origin), role: classifyOriginRole(origin, pathsByOrigin.get(origin) ?? []),
      method: cleanMethod, normPath, nouns, primaryNoun, isMutating, isHighValue, paramNames, consumedNouns, sinkKinds: [...sinkKinds],
      acceptsSigning: SIG_CONSUMER_ROUTE_RE.test(normPath) || sinkKinds.some(sk => /(?:hmac|webhook|sig|jwt|crypto)/i.test(sk)) || [...paramNames].some(p => SIGNING_KEY_RE.test(p) || /signature|hmac/.test(p)),
      acceptsCredential: CRED_ROUTE_RE.test(normPath) || [...paramNames].some(p => CRED_KEY_RE.test(p)) || (Boolean(authReq && authReq !== 'none') && isHighValue),
      acceptsInvite: INVITE_ROUTE_RE.test(normPath) || [...paramNames].some(p => INVITE_KEY_RE.test(p)),
      acceptsSignedUrl: URL_ROUTE_RE.test(normPath) || [...paramNames].some(p => URL_KEY_RE.test(p) || p === 'file' || p === 'path'),
      acceptsAsyncJob: [...paramNames].some(p => ASYNC_KEY_RE.test(p)) || (nouns.some(n => ASYNC_NOUNS.has(n)) && (hasObjId || /\/(?:status|result|url|download|content|artifact|cancel|logs|rollback|promote|redeploy|retry|deliver|archive)(?:\/|$)/i.test(normPath))),
      hasSignatureRejection: false,
      produces: [], personaStatuses: new Map(), personaDiff: { allowed: [], denied: [], hasAsymmetry: false, has202: false, summary: '' },
    }
    byKey.set(key, node); if (id) byId.set(id, node)
    return node
  }
  for (const ep of input.endpoints) makeNode(ep.id, ep.origin, ep.method, ep.pathTemplate, ep.authRequirement ?? '', ep.riskScore ?? 55, paramsByEp.get(ep.id) ?? [], ep.sinkKinds ?? [])
  for (const ex of input.brokerExchanges ?? []) {
    const node = makeNode('', ex.origin, ex.method, ex.pathAndQuery, '', 65)
    if (!node) continue
    const persona = (ex.personaHandle ?? '').trim() || 'anonymous'
    ;(node.personaStatuses.get(persona) ?? node.personaStatuses.set(persona, new Set<number>()).get(persona)!).add(ex.status)
    if ((ex.status === 401 || ex.status === 403) && SIG_REJECTION_BODY_RE.test(`${ex.bodyPreview ?? ''} ${typeof ex.respHeaders === 'string' ? ex.respHeaders : ''}`)) {
      node.hasSignatureRejection = true
      node.acceptsSigning = true
    }
    if (ex.status >= 200 && ex.status < 400) {
      for (const cap of extractExchangeCaps(ex, node.nouns, node.normPath, approved)) {
        if (!node.produces.some(p => p.kind === cap.kind && toSnake(p.field) === toSnake(cap.field) && p.targetOrigin === cap.targetOrigin)) node.produces.push(cap)
      }
    }
  }
  const nodes = [...byKey.values()]
  enrichNodes(nodes, input.personas ?? [])
  return { nodes, byId, byKey }
}

function buildEdges(nodes: readonly EndpointNode[], byId: ReadonlyMap<string, EndpointNode>, byKey: ReadonlyMap<string, EndpointNode>, apiDeps: readonly GbDataflowDependencyInput[]) {
  const outgoing = new Map<string, DataflowEdge[]>(); const seen = new Set<string>()
  const addEdge = (from: EndpointNode, to: EndpointNode, field: string, kind: ProducerTokenKind, fromLive: boolean, fromDep: boolean, redirect: boolean) => {
    if (from.key === to.key || (from.origin === to.origin && from.normPath === to.normPath) || seen.has(`${from.key}->${to.key}`)) return
    seen.add(`${from.key}->${to.key}`)
    const crossOrigin = from.origin !== to.origin
    let score = KIND_BONUS[kind] + (fromDep ? 28 : redirect ? 32 : fromLive ? 20 : 8) + (to.isHighValue ? 14 : 0) + (from.personaDiff.has202 ? 14 : 0)
    if (crossOrigin) score += 26 + ((from.role === 'auth' && to.role !== 'auth') || (from.role === 'api' && to.role === 'edge') ? 10 : 0)
    if (from.personaDiff.hasAsymmetry || to.personaDiff.hasAsymmetry) score += 18
    ;(outgoing.get(from.key) ?? outgoing.set(from.key, []).get(from.key)!).push({ from, to, field, kind, crossOrigin, fromLive, score })
  }
  const resolveRef = (id?: string, label?: string, origin?: string) => {
    if (id && byId.has(id)) return byId.get(id)
    if (!label) return undefined
    const m = /^(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s+(\S+)$/i.exec(label.trim())
    const norm = normalizeRouteTemplate(m?.[2] ?? label.trim(), { preserveCase: false })
    return (origin && byKey.get(`${origin}|${(m?.[1] ?? 'GET').toUpperCase()}|${norm}`)) || nodes.find(n => (!origin || n.origin === origin) && n.normPath === norm && (!m || n.method === m[1]!.toUpperCase()))
  }
  for (const dep of apiDeps) {
    const prod = resolveRef(dep.producerEndpointId, dep.producer, dep.producerOrigin)
    const cons = resolveRef(dep.consumerEndpointId, dep.consumer, dep.consumerOrigin)
    if (prod && cons) addEdge(prod, cons, dep.resourceKey, classifyField(dep.resourceKey, prod.nouns, 200, prod.normPath)?.kind ?? 'entity_id', true, true, false)
  }
  for (const prod of nodes) {
    for (const cap of prod.produces) {
      for (const cons of nodes) {
        if (prod.key === cons.key || (prod.origin === cons.origin && prod.normPath === cons.normPath)) continue
        const redirect = Boolean(cap.targetOrigin === cons.origin && cap.targetNormPath && (cons.normPath === cap.targetNormPath || cons.normPath.startsWith(cap.targetNormPath)))
        const matched = redirect
          || (cap.kind === 'signing_secret' && (cons.hasSignatureRejection || cons.acceptsSigning || (cons.isMutating && cons.personaDiff.denied.length > 0)))
          || (cap.kind === 'invite_or_grant' && cons.acceptsInvite && (cons.origin !== prod.origin || cons.isMutating || INVITE_ROUTE_RE.test(cons.normPath)))
          || (cap.kind === 'credential_token' && cons.acceptsCredential && (cons.origin !== prod.origin || cons.isHighValue))
          || (cap.kind === 'signed_url_or_location' && cons.acceptsSignedUrl && (cons.origin !== prod.origin || !cap.noun || cons.consumedNouns.has(cap.noun) || URL_ROUTE_RE.test(cons.normPath)))
          || (cap.kind === 'async_job_or_export' && ((cons.acceptsAsyncJob && (!cap.noun || cons.consumedNouns.has(cap.noun) || cons.primaryNoun === cap.noun || [...cons.paramNames].some(p => ASYNC_KEY_RE.test(p)))) || (cons.acceptsSignedUrl && cons.origin !== prod.origin)))
          || (cap.kind === 'entity_id' && Boolean(cap.noun) && (cons.consumedNouns.has(cap.noun) || cons.paramNames.has(toSnake(cap.field))) && (cons.isHighValue || cons.origin !== prod.origin || cons.normPath.includes('/:id')))
        if (matched) addEdge(prod, cons, cap.field, cap.kind, cap.fromLive, false, redirect)
      }
    }
  }
  for (const [k, list] of outgoing.entries()) {
    list.sort((a, b) => b.score - a.score || Number(b.crossOrigin) - Number(a.crossOrigin) || a.to.key.localeCompare(b.to.key))
    outgoing.set(k, list.slice(0, MAX_OUTGOING))
  }
  return outgoing
}

const CACHE_OR_DUAL_TENANT_SIGNAL_RE = /(?:^|[^a-z0-9])(?:cache|cached|cache[_-]?bleed|cache[_-]?key|shared[_-]?(?:edge[_-]?)?cache|edge[_-]?cache|prime|primed[_-]?cache|warm|cdn|cross[_-]?tenant|dual[_-]?tenant|multi[_-]?tenant|abac|switch[_-]?(?:tenant|org|workspace)|(?:tenant|org|workspace)[_-]?switch)(?:[^a-z0-9]|$)/i
const ORG_SWITCH_PATH_RE = /\/(?:orgs?|tenants?|organizations?|workspaces?)(?:\/[^/]+)?\/switch(?:\/|$)/i

function isMultiTenantChainHypothesis(
  pNodes: readonly EndpointNode[],
  pEdges: readonly DataflowEdge[],
  diffs: readonly string[],
): boolean {
  if (pNodes.some(n => ORG_SWITCH_PATH_RE.test(n.normPath))) return true
  const signalCorpus = [
    ...pNodes.map(n => n.normPath),
    ...pNodes.flatMap(n => [...n.paramNames]),
    ...pEdges.map(e => e.field),
    ...diffs,
  ].join(' ')
  return CACHE_OR_DUAL_TENANT_SIGNAL_RE.test(signalCorpus)
}

function orderPersonasLowPrivFirst(
  observed: readonly string[],
  personas: readonly GbDataflowPersonaInput[],
  options?: { preferMultiTenant?: boolean },
): { ordered: string[]; basePersona?: string } {
  const roleByHandle = new Map<string, string | null | undefined>()
  const configIndexByHandle = new Map<string, number>()
  personas.forEach((p, idx) => {
    if (!p.handle) return
    roleByHandle.set(p.handle, p.roleLabel)
    if (!configIndexByHandle.has(p.handle)) {
      configIndexByHandle.set(p.handle, typeof p.configIndex === 'number' && Number.isFinite(p.configIndex) ? p.configIndex : idx)
    }
  })
  const observedClean = observed.filter(p => p && p !== 'anonymous')
  const baseObservedOffset = personas.length
  observedClean.forEach((handle, idx) => {
    if (!configIndexByHandle.has(handle)) configIndexByHandle.set(handle, baseObservedOffset + idx)
  })
  const handles = [...new Set([...personas.map(p => p.handle).filter(Boolean), ...observedClean])]
  const effectiveRank = (handle: string): number => {
    const priv = classifyPersonaPrivilege(handle, roleByHandle.get(handle))
    if (options?.preferMultiTenant && priv.multiTenant) return -1
    return priv.rank
  }
  handles.sort((a, b) =>
    effectiveRank(a) - effectiveRank(b)
    || (configIndexByHandle.get(a) ?? Number.MAX_SAFE_INTEGER) - (configIndexByHandle.get(b) ?? Number.MAX_SAFE_INTEGER),
  )
  const basePersona = (
    options?.preferMultiTenant
      ? handles.find(h => classifyPersonaPrivilege(h, roleByHandle.get(h)).multiTenant)
      : undefined
  ) ?? handles.find(h => {
    const priv = classifyPersonaPrivilege(h, roleByHandle.get(h))
    return !priv.elevated && !priv.revokedStale && !priv.multiTenant
  })
  return { ordered: handles.slice(0, 5), ...(basePersona ? { basePersona } : {}) }
}

function buildChainDraft(pNodes: readonly EndpointNode[], pEdges: readonly DataflowEdge[], score: number, idx: number, personas: readonly GbDataflowPersonaInput[]): GbDataflowChainSummary {
  const origins = [...new Set(pNodes.map(n => n.origin))]; const hosts = [...new Set(pNodes.map(n => n.host))]
  const fields = [...new Set(pEdges.map(e => e.field))]; const kinds = [...new Set(pEdges.map(e => e.kind))]
  const fromLive = pEdges.some(e => e.fromLive)
  const hasPersonaAsymmetry = pNodes.some(n => n.personaDiff.hasAsymmetry); const has202 = pNodes.some(n => n.personaDiff.has202); const crossOrigin = origins.length >= 2
  const title = `GB dataflow chain (${pNodes.length}-hop) · ${(hosts.length >= 2 ? hosts.slice(0, 3).join(' -> ') : hosts[0]!)} (${fields.slice(0, 2).join(' -> ')})`.slice(0, 180)
  const hopTrace = pNodes.map((n, i) => `Hop ${i + 1}: ${n.method} ${n.origin}${n.normPath}${pEdges[i] ? ` (yields ${pEdges[i]!.field} [${pEdges[i]!.kind}])` : ''}`).join(' -> ')
  const diffs = pNodes.map(n => n.personaDiff.summary).filter(Boolean)
  const tags = [`[chain_hops=${pNodes.length}]`, '[lane=chain]', `[dataflow_source=${fromLive ? 'live' : 'spec'}]`, `[api_dependency:${fields.join(',')}]`, ...(crossOrigin ? [`[cross_origin_edge:${origins[0]}->${origins[origins.length - 1]}]`] : []), ...(diffs.length ? [`[persona_diff:${diffs[0]}]`] : [])]
  const preferMultiTenant = isMultiTenantChainHypothesis(pNodes, pEdges, diffs)
  const { ordered: obsPersonas, basePersona } = orderPersonasLowPrivFirst(
    pNodes.flatMap(n => [...n.personaDiff.allowed, ...n.personaDiff.denied]),
    personas,
    { preferMultiTenant },
  )
  const hypothesis = `${tags.join(' ')} Producer->consumer multi-hop dataflow chain: ${hopTrace}.${diffs.length ? ` Observed differentials: ${diffs.slice(0, 2).join('; ')}.` : ''}${basePersona ? ` Base persona: ${basePersona}.` : ''}${obsPersonas.length ? ` Relevant personas: ${obsPersonas.join(', ')}.` : ''} Verify control vs variant boundaries end-to-end with kovo_verify, sealing intermediate tokens/handles with capability.seal.`.slice(0, 1400)
  const category = kinds.includes('signed_url_or_location') && pNodes[pNodes.length - 1]!.acceptsSignedUrl ? 'upload-storage'
    : kinds.includes('signing_secret') || kinds.includes('credential_token') || kinds.includes('invite_or_grant') ? 'auth-identity' : 'broken-access-control'
  const skills = [...new Set(['multihop-chains', 'chain-primitives', 'api-dependency', 'dataflow-graph', ...(crossOrigin ? ['cross-origin-chain'] : []), ...(hasPersonaAsymmetry ? ['authz-differential'] : [])])]
  const priority = fromLive ? Math.max(88, Math.min(98, 98 - idx)) : Math.max(76, Math.min(84, 84 - idx))
  return {
    signature: pNodes.map(n => `${n.host}:${n.method}:${n.normPath}`).join('>'),
    hops: pNodes.map(n => ({ origin: n.origin, method: n.method, pathTemplate: n.normPath })),
    origins, fields, kinds, score, fromLive, hasPersonaAsymmetry, has202,
    step: { title, hypothesis, category, priority, origins, skills, fromLive },
  }
}

/** Deterministically synthesize up to `maxSteps` (default 6) ranked 2–4 hop Grey-Box dataflow chains. */
export function synthesizeGreyBoxDataflowGraph(input: GbDataflowSynthesizeInput): GbDataflowSynthesizeResult {
  if (input.sourceMounted || (input.mountedRepos && input.mountedRepos.length > 0)) return { steps: [], chains: [], nodeCount: 0, edgeCount: 0 }
  const maxSteps = Math.max(0, Math.min(12, Math.floor(input.maxSteps ?? DEFAULT_MAX_STEPS)))
  const approved = new Set(input.approvedOrigins)
  if (maxSteps <= 0 || approved.size === 0) return { steps: [], chains: [], nodeCount: 0, edgeCount: 0 }
  const { nodes, byId, byKey } = buildNodes(input, approved)
  if (nodes.length < 2) return { steps: [], chains: [], nodeCount: nodes.length, edgeCount: 0 }
  const outgoing = buildEdges(nodes, byId, byKey, input.apiDependencies ?? [])
  const edgeCount = [...outgoing.values()].reduce((acc, l) => acc + l.length, 0)
  if (edgeCount === 0) return { steps: [], chains: [], nodeCount: nodes.length, edgeCount: 0 }

  const candidates: Array<{ nodes: EndpointNode[]; edges: DataflowEdge[]; score: number; fromLive: boolean }> = []
  const scorePath = (pNodes: readonly EndpointNode[], pEdges: readonly DataflowEdge[]): number => {
    const origins = new Set(pNodes.map(n => n.origin))
    const roles = new Set(pNodes.map(n => n.role).filter(r => r !== 'general'))
    const kinds = new Set(pEdges.map(e => e.kind))
    let s = (pEdges.reduce((a, e) => a + e.score, 0) / pEdges.length) + pEdges.length * 14
      + (origins.size >= 3 ? 42 : origins.size === 2 ? 24 : 0) + Math.max(0, roles.size - 1) * 12 + Math.max(0, kinds.size - 1) * 10
      + pEdges.filter(e => e.fromLive).length * 10 + (pNodes[pNodes.length - 1]!.isHighValue ? 16 : 0)
    if (pNodes.some(n => n.personaDiff.hasAsymmetry)) s += 20
    if (pNodes.some(n => n.personaDiff.has202)) s += 12
    return Math.round(s)
  }
  const dfs = (pNodes: EndpointNode[], pEdges: DataflowEdge[], visited: Set<string>) => {
    if (candidates.length >= 400) return
    if (pNodes.length >= 2) candidates.push({ nodes: [...pNodes], edges: [...pEdges], score: scorePath(pNodes, pEdges), fromLive: pEdges.some(e => e.fromLive) })
    if (pNodes.length >= 4) return
    for (const edge of outgoing.get(pNodes[pNodes.length - 1]!.key) ?? []) {
      if (visited.has(edge.to.key) || pNodes.some(n => n.origin === edge.to.origin && n.normPath === edge.to.normPath)) continue
      visited.add(edge.to.key); pNodes.push(edge.to); pEdges.push(edge)
      dfs(pNodes, pEdges, visited)
      pEdges.pop(); pNodes.pop(); visited.delete(edge.to.key)
    }
  }
  for (const start of nodes.filter(n => (outgoing.get(n.key)?.length ?? 0) > 0).sort((a, b) => (outgoing.get(b.key)![0]!.score - outgoing.get(a.key)![0]!.score) || a.key.localeCompare(b.key)).slice(0, 60)) {
    dfs([start], [], new Set([start.key]))
  }
  candidates.sort((a, b) => (Number(b.fromLive) - Number(a.fromLive)) || (b.score - a.score) || (b.nodes.length - a.nodes.length) || a.nodes.map(n => n.key).join('>').localeCompare(b.nodes.map(n => n.key).join('>')))
  const selected: typeof candidates = []; const seenTerminal = new Set<string>()
  for (const cand of candidates) {
    if (selected.length >= maxSteps) break
    const termKey = `${cand.nodes[cand.nodes.length - 1]!.key}|${[...new Set(cand.nodes.map(n => n.origin))].join(',')}`
    if (seenTerminal.has(termKey)) continue
    const candSet = new Set(cand.nodes.map(n => n.key))
    if (selected.some(prev => prev.nodes.filter(n => candSet.has(n.key)).length / Math.max(prev.nodes.length, cand.nodes.length) > 0.66)) continue
    seenTerminal.add(termKey); selected.push(cand)
  }
  const chains = selected.map((c, idx) => buildChainDraft(c.nodes, c.edges, c.score, idx, input.personas ?? []))
  return { steps: chains.map(c => c.step), chains, nodeCount: nodes.length, edgeCount }
}

/** Load Phase-0 runtime discovery rows from SQLite WAL `Store` and synthesize Grey-Box dataflow steps. */
export function synthesizeGreyBoxDataflowStepsFromStore(
  storage: Store, run: Run,
  options: { activeOrigins?: ReadonlySet<string>; sourceMounted?: boolean; mountedRepos?: readonly string[]; maxSteps?: number } = {},
): GbDataflowStepDraft[] {
  if (run.capabilityTier <= 0 || options.sourceMounted || (options.mountedRepos && options.mountedRepos.length > 0)) return []
  const approvedOrigins = options.activeOrigins ?? new Set(run.candidates.filter(c => run.approved.includes(c.id)).map(c => c.origin))
  if (!approvedOrigins.size) return []
  const endpoints = storage.listEndpoints(run.id, { limit: 250 }).filter(ep => approvedOrigins.has(ep.origin))
  const endpointParams = storage.listEndpointParams(run.id).slice(0, 500)
  const apiDependencies = storage.listApiDependencies(run.id).slice(0, 250)
  let brokerExchanges: GbDataflowExchangeInput[] = []
  try {
    const okRows = storage.client.prepare(`SELECT id, origin, final_origin AS finalOrigin, method, path_and_query AS pathAndQuery, status, persona_handle AS personaHandle, resp_headers AS respHeaders, body_preview AS bodyPreview, created_at AS createdAt FROM broker_exchanges WHERE run_id = ? AND status BETWEEN 200 AND 399 ORDER BY created_at DESC LIMIT 250`).all(run.id) as unknown as GbDataflowExchangeInput[]
    const deniedRows = storage.client.prepare(`SELECT id, origin, final_origin AS finalOrigin, method, path_and_query AS pathAndQuery, status, persona_handle AS personaHandle, resp_headers AS respHeaders, body_preview AS bodyPreview, created_at AS createdAt FROM broker_exchanges WHERE run_id = ? AND status IN (401, 403) ORDER BY created_at DESC LIMIT 100`).all(run.id) as unknown as GbDataflowExchangeInput[]
    brokerExchanges = [...okRows, ...deniedRows].filter(r => approvedOrigins.has(r.origin))
  } catch { /* best-effort runtime scan */ }
  const approvedOrder = new Map(run.approvedPersonaIds.map((id, i) => [id, i]))
  const personas = [...resolveRunPersonas(storage, run.projectId, run.approvedPersonaIds).values()]
    .map((p, idx) => ({ handle: p.handle, roleLabel: p.roleLabel, configIndex: approvedOrder.get(p.id) ?? idx }))
    .sort((a, b) =>
      classifyPersonaPrivilege(a.handle, a.roleLabel).rank - classifyPersonaPrivilege(b.handle, b.roleLabel).rank
      || a.configIndex - b.configIndex,
    )
  return synthesizeGreyBoxDataflowGraph({ approvedOrigins, endpoints, endpointParams, apiDependencies, brokerExchanges, personas, sourceMounted: options.sourceMounted, mountedRepos: options.mountedRepos, maxSteps: options.maxSteps ?? DEFAULT_MAX_STEPS }).steps
}

/** Idempotently persist Grey-Box dataflow chain steps into `ChainStep` storage for post-floor / Round-1 top-up. */
export function materializeGreyBoxDataflowWave1Steps(
  storage: Store, run: Run,
  options: { activeOrigins: ReadonlySet<string>; sourceMounted: boolean; maxSteps?: number; llmMode?: FrontierLlmMode; routeStep?: (step: { title: string; hypothesis: string; category: string; skills: string[] }) => ChainStep['specialistProfile'] },
): ChainStep[] {
  if (options.sourceMounted || run.capabilityTier <= 0) return []
  const maxSteps = Math.max(0, Math.min(12, options.maxSteps ?? DEFAULT_MAX_STEPS))
  const existingSteps = storage.listChainSteps(run.id, run.goalRevision)
  const existingDataflow = existingSteps.filter(s => s.title.startsWith('GB dataflow chain ('))
  const existingLiveCount = existingDataflow.filter(s => s.hypothesis.includes('[dataflow_source=live]')).length
  const remainingLive = Math.max(0, maxSteps - existingLiveCount)
  const remainingSpec = Math.max(0, maxSteps - existingDataflow.length)
  const created: ChainStep[] = []
  if (remainingLive > 0 || remainingSpec > 0) {
    const drafts = synthesizeGreyBoxDataflowStepsFromStore(storage, run, { activeOrigins: options.activeOrigins, sourceMounted: false, maxSteps })
    const existingTitles = new Set(existingSteps.map(s => s.title.trim().toLowerCase()))
    const existingLiveTitles = new Set(existingDataflow.filter(s => s.hypothesis.includes('[dataflow_source=live]')).map(s => s.title.trim().toLowerCase()))
    let liveAdded = 0
    let specAdded = 0
    for (const draft of drafts) {
      const isLive = Boolean(draft.fromLive)
      if (isLive ? liveAdded >= remainingLive : specAdded >= remainingSpec) continue
      const normTitle = draft.title.trim().toLowerCase()
      const liveTitle = `${draft.title.slice(0, 173)} [live]`
      const normLiveTitle = liveTitle.trim().toLowerCase()
      if (isLive) {
        if (existingLiveTitles.has(normTitle) || existingLiveTitles.has(normLiveTitle)) continue
      } else if (existingTitles.has(normTitle)) continue
      const finalTitle = isLive && existingTitles.has(normTitle) ? liveTitle : draft.title
      const validOrigins = draft.origins.filter(o => options.activeOrigins.has(o))
      const assetIds = run.candidates.filter(c => validOrigins.includes(c.origin) && run.approved.includes(c.id)).map(c => c.id)
      if (!validOrigins.length || !assetIds.length) continue
      existingTitles.add(finalTitle.trim().toLowerCase())
      if (isLive) { existingLiveTitles.add(normTitle); existingLiveTitles.add(finalTitle.trim().toLowerCase()); liveAdded += 1 }
      else specAdded += 1
      const step = storage.addChainStep(run, { title: finalTitle, hypothesis: draft.hypothesis, category: draft.category, priority: draft.priority, targetAssetIds: assetIds, skills: draft.skills, sourceOrigins: validOrigins, ...(options.routeStep ? { specialistProfile: options.routeStep({ ...draft, title: finalTitle }) } : {}) })
      created.push(storage.updateChainStep(step.id, { status: 'ready' }))
    }
  }
  if (options.llmMode === 'agentic') {
    const vf = refreshGreyBoxValueFlowSteps(storage, run, {
      activeOrigins: options.activeOrigins,
      sourceMounted: false,
      llmMode: 'agentic',
      existingSteps: [...existingSteps, ...created],
      routeStep: options.routeStep,
    })
    created.push(...vf.steps)
  }
  if (options.llmMode !== 'deterministic-no-llm') {
    const frontierSteps = materializeCapabilityConsumerFrontierSteps(storage, run, {
      activeOrigins: options.activeOrigins,
      llmMode: options.llmMode,
      maxSteps: Math.min(6, maxSteps),
      existingSteps: [...existingSteps, ...created],
      routeStep: options.routeStep,
    })
    created.push(...frontierSteps)
  }
  return created
}

interface ValueFlowWatermark {
  exchangeCount: number
  lastExchangeTs: number
  factCount: number
  lastFactTs: number
}

interface RuntimeValueFlowCandidate {
  flowSig: string
  producerOrigin: string
  producerMethod: string
  producerNormPath: string
  consumerOrigin: string
  consumerMethod: string
  consumerNormPath: string
  field: string
  kind: ProducerTokenKind
  noun: string
  actingPersona: string
  crossOrigin: boolean
  isNew: boolean
  hasDenied: boolean
  hasSignatureRejection: boolean
  score: number
  valueDigest: string
  exchangeId?: string
  factId?: string
  observedAtMs: number
}

export interface GbValueFlowRefreshResult {
  steps: ChainStep[]
  edgesPersisted: number
  producerCapsPersisted: number
  watermarkChanged: boolean
}

const NON_AGENTIC_VF_SUBKINDS = new Set(['code_audit_suspect', 'det_lead', 'hop_checkpoint', 'chain_hop', 'floor_lead', 'static_suspect'])
const NON_AGENTIC_VF_SOURCES = new Set(['static_analysis', 'code_audit', 'deterministic_floor', 'floor_observation', 'phase0', 'openapi', 'repo_ast', 'attacker_seed', 'synthetic', 'deterministic-no-llm'])
const valueFlowWatermarks = new Map<string, ValueFlowWatermark>()

function shortHash(raw: string, len = 12): string {
  return createHash('sha256').update(raw).digest('hex').slice(0, len)
}

function sanitizeCapSlot(raw: string): string {
  const cleaned = toSnake(raw).replace(/[^a-z0-9._-]/g, '_').replace(/^[^a-z0-9]+/, '').slice(0, 48)
  return cleaned || 'val'
}

function kindToLedgerCapabilityKind(kind: ProducerTokenKind): CapabilityKind {
  switch (kind) {
    case 'signing_secret': return 'signing_material'
    case 'credential_token':
    case 'invite_or_grant': return 'scoped_token'
    case 'signed_url_or_location': return 'signed_artifact_or_url'
    case 'async_job_or_export': return 'state_handle'
    case 'entity_id': return 'opaque_object_ref'
  }
}

function classifyValueFlowSurface(normPath: string): CapabilitySurface {
  if (/\/(?:graphql|gql)\b/i.test(normPath)) return 'graphql'
  if (SIG_CONSUMER_ROUTE_RE.test(normPath)) return 'webhook'
  if (/\/(?:jobs?|exports?|tasks?|builds?|deployments?|releases?|pipelines?|runs?|async)\b/i.test(normPath)) return 'async_job'
  if (/\/(?:storage|files?|artifacts?|downloads?|uploads?|media)\b/i.test(normPath)) return 'storage'
  return 'http'
}

function readValueFlowWatermark(storage: Store, runId: string): ValueFlowWatermark {
  let exchangeCount = 0; let lastExchangeTs = 0; let factCount = 0; let lastFactTs = 0
  try {
    const exRow = storage.client.prepare(`
      SELECT COUNT(*) AS cnt, COALESCE(MAX(created_at), 0) AS maxTs
      FROM broker_exchanges WHERE run_id = ? AND status BETWEEN 200 AND 299
    `).get(runId) as { cnt?: number; maxTs?: number } | undefined
    exchangeCount = Number(exRow?.cnt ?? 0)
    lastExchangeTs = Number(exRow?.maxTs ?? 0)
  } catch { /* best-effort */ }
  try {
    const fRow = storage.client.prepare(`
      SELECT COUNT(*) AS cnt, COALESCE(MAX(created_at), 0) AS maxTs
      FROM facts WHERE run_id = ? AND tainted = 0
    `).get(runId) as { cnt?: number; maxTs?: number } | undefined
    factCount = Number(fRow?.cnt ?? 0)
    lastFactTs = Number(fRow?.maxTs ?? 0)
  } catch { /* best-effort */ }
  return { exchangeCount, lastExchangeTs, factCount, lastFactTs }
}

function extractRuntimeFactCaps(
  facts: readonly Fact[],
  approved: ReadonlySet<string>,
): Array<{ origin: string; method: string; normPath: string; cap: ProducedCap }> {
  const out: Array<{ origin: string; method: string; normPath: string; cap: ProducedCap }> = []
  for (const fact of facts) {
    if (fact.tainted || !approved.has(fact.origin)) continue
    const data = (fact.data ?? {}) as Record<string, unknown>
    const subkind = typeof data.subkind === 'string' ? data.subkind.trim().toLowerCase() : ''
    const source = typeof data.source === 'string' ? data.source.trim().toLowerCase() : ''
    if (
      (fact.kind as string) === 'code_audit_suspect'
      || NON_AGENTIC_VF_SUBKINDS.has(subkind)
      || NON_AGENTIC_VF_SOURCES.has(source)
      || data.hypothetical === true || data.synthetic === true || data.staticOnly === true
    ) continue

    const rawPath = [data.endpoint, data.producerEndpoint, data.path, data.route].find(v => typeof v === 'string' && v.trim()) as string | undefined
    const normPath = rawPath ? normalizeRouteTemplate(rawPath.split(/[?#]/, 1)[0] ?? rawPath, { preserveCase: false }) : `/fact/${fact.kind}`
    const method = (typeof data.method === 'string' ? data.method.trim().toUpperCase() : 'GET') || 'GET'
    const nouns = extractRouteNouns(normPath)
    const persona = ([data.persona, data.personaHandle, data.ownerPersona].find(v => typeof v === 'string' && v.trim()) as string | undefined)?.trim()
    const exchangeId = Array.isArray(fact.exchangeIds) && fact.exchangeIds[0] ? fact.exchangeIds[0] : (typeof data.exchangeId === 'string' ? data.exchangeId : undefined)
    const pushCap = (field: string, kind: ProducerTokenKind, noun: string, rawVal: string, target?: { origin: string; normPath: string }) => {
      out.push({
        origin: fact.origin,
        method,
        normPath,
        cap: {
          field, kind, noun, fromLive: true,
          valueDigest: computeArtifactDigest(`${fact.id}|${fact.origin}|${field}|${rawVal.slice(0, 96)}`),
          factId: fact.id,
          ...(exchangeId ? { exchangeId } : {}),
          observedAtMs: fact.createdAt || Date.now(),
          ...(persona ? { persona } : {}),
          ...(target ? { targetOrigin: target.origin, targetNormPath: target.normPath } : {}),
        },
      })
    }

    let matchedAny = false
    for (const [k, v] of Object.entries(data)) {
      if (k === 'subkind' || k === 'source' || k === 'endpoint' || k === 'path' || k === 'route' || k === 'method' || k === 'persona' || k === 'personaHandle' || k === 'ownerPersona') continue
      const cls = classifyField(k, nouns, 200, normPath)
      if (cls && (typeof v === 'string' || typeof v === 'number')) {
        const sVal = String(v)
        const target = cls.kind === 'signed_url_or_location' ? resolveApprovedUrl(sVal, fact.origin, approved) : undefined
        pushCap(k, cls.kind, cls.noun, sVal, target)
        matchedAny = true
      } else if (typeof v === 'string') {
        const valCls = classifyConcreteStringValue(k, v, fact.origin, approved, nouns)
        if (valCls) {
          pushCap(k, valCls.kind, valCls.noun, v, valCls.targetOrigin && valCls.targetNormPath ? { origin: valCls.targetOrigin, normPath: valCls.targetNormPath } : undefined)
          matchedAny = true
        }
      }
    }
    if (!matchedAny) {
      const summary = `${fact.summary} ${typeof data.fieldName === 'string' ? data.fieldName : ''} ${typeof data.secretKind === 'string' ? data.secretKind : ''}`
      if (fact.kind === 'secret') {
        const isSig = SIGNING_KEY_RE.test(toSnake(summary)) || /(?:hmac|signing|webhook[_ -]?secret|signing[_ -]?salt)/i.test(summary)
        pushCap(typeof data.fieldName === 'string' ? data.fieldName : (isSig ? 'signing_secret' : 'access_token'), isSig ? 'signing_secret' : 'credential_token', nouns[nouns.length - 1] || (isSig ? 'webhook' : 'token'), fact.id)
      } else if (fact.kind === 'object_ref' && (typeof data.resourceId === 'string' || typeof data.id === 'string')) {
        const rawId = String(data.resourceId ?? data.id)
        const noun = nouns[nouns.length - 1] || (PREFIXED_ID_VAL_RE.exec(rawId)?.[1] ? PREFIX_NOUN_MAP[PREFIXED_ID_VAL_RE.exec(rawId)![1]!.toLowerCase()]?.noun : undefined) || 'resource'
        pushCap(`${noun}_id`, ASYNC_NOUNS.has(noun) ? 'async_job_or_export' : 'entity_id', noun, rawId)
      } else if (fact.kind === 'redirect' && typeof data.redirectTarget === 'string') {
        const target = resolveApprovedUrl(data.redirectTarget, fact.origin, approved)
        pushCap('redirect_url', 'signed_url_or_location', nouns[nouns.length - 1] || 'redirect', data.redirectTarget, target)
      } else if (fact.kind === 'cookie' || fact.kind === 'auth') {
        pushCap(typeof data.fieldName === 'string' ? data.fieldName : 'session_token', 'credential_token', nouns[nouns.length - 1] || 'session', fact.id)
      }
    }
  }
  return out
}

function scoreRuntimeValueFlow(
  prod: EndpointNode,
  cap: ProducedCap,
  cons: EndpointNode,
  isNew: boolean,
): number | null {
  if (prod.origin === cons.origin && prod.normPath === cons.normPath && prod.method === cons.method) return null
  if (prod.origin === cons.origin && prod.normPath === cons.normPath) return null
  const redirect = Boolean(cap.targetOrigin === cons.origin && cap.targetNormPath && (cons.normPath === cap.targetNormPath || cons.normPath.startsWith(cap.targetNormPath)))
  const fieldSnake = toSnake(cap.field)
  const exactParam = Boolean(fieldSnake && cons.paramNames.has(fieldSnake))
  const nounOverlap = Boolean(cap.noun && (cons.consumedNouns.has(cap.noun) || cons.primaryNoun === cap.noun || cons.nouns.includes(cap.noun)))
  const hasDenied = cons.personaDiff.denied.length > 0
  const crossOrigin = prod.origin !== cons.origin

  let matched = redirect
  if (!matched) {
    if (cap.kind === 'signing_secret') matched = cons.hasSignatureRejection || cons.acceptsSigning || (cons.isMutating && hasDenied)
    else if (cap.kind === 'invite_or_grant') matched = cons.acceptsInvite || exactParam
    else if (cap.kind === 'credential_token') matched = cons.acceptsCredential && (hasDenied || crossOrigin || cons.isHighValue)
    else if (cap.kind === 'signed_url_or_location') matched = cons.acceptsSignedUrl && (crossOrigin || nounOverlap || URL_ROUTE_RE.test(cons.normPath))
    else if (cap.kind === 'async_job_or_export') matched = ((cons.acceptsAsyncJob || cons.normPath.includes('/:id')) && (nounOverlap || exactParam || [...cons.paramNames].some(p => ASYNC_KEY_RE.test(p)))) || (cons.acceptsSignedUrl && (nounOverlap || crossOrigin))
    else matched = (exactParam || nounOverlap) && (cons.normPath.includes('/:id') || cons.isHighValue || crossOrigin || hasDenied)
  }
  if (!matched) return null

  let score = KIND_BONUS[cap.kind] + (isNew ? 25 : 0) + (redirect ? 36 : 0) + (exactParam ? 22 : nounOverlap ? 16 : 0)
  if (crossOrigin) score += 24
  if (cons.hasSignatureRejection && cap.kind === 'signing_secret') score += 34
  else if (hasDenied) score += 22
  if (cons.isMutating) score += 14
  else if (cons.isHighValue) score += 8
  if (prod.personaDiff.hasAsymmetry || cons.personaDiff.hasAsymmetry) score += 16
  if (prod.personaDiff.has202) score += 10
  return score
}

function collectRuntimeValueFlowCandidates(
  storage: Store,
  run: Run,
  approvedOrigins: ReadonlySet<string>,
  prevWatermark: ValueFlowWatermark | undefined,
): { candidates: RuntimeValueFlowCandidate[]; liveFactIds: Set<string>; personas: GbDataflowPersonaInput[] } {
  const endpoints = storage.listEndpoints(run.id, { limit: 400 }).filter(ep => approvedOrigins.has(ep.origin))
  const endpointParams = storage.listEndpointParams(run.id).slice(0, 800)
  let recentExchanges: GbDataflowExchangeInput[] = []
  try {
    const newestOk = storage.client.prepare(`
      SELECT id, origin, final_origin AS finalOrigin, method, path_and_query AS pathAndQuery, status, persona_handle AS personaHandle, resp_headers AS respHeaders, body_preview AS bodyPreview, created_at AS createdAt
      FROM broker_exchanges WHERE run_id = ? AND status BETWEEN 200 AND 299 ORDER BY created_at DESC LIMIT 250
    `).all(run.id) as unknown as GbDataflowExchangeInput[]
    const deniedRows = storage.client.prepare(`
      SELECT id, origin, final_origin AS finalOrigin, method, path_and_query AS pathAndQuery, status, persona_handle AS personaHandle, resp_headers AS respHeaders, body_preview AS bodyPreview, created_at AS createdAt
      FROM broker_exchanges WHERE run_id = ? AND status IN (401, 403) ORDER BY created_at DESC LIMIT 120
    `).all(run.id) as unknown as GbDataflowExchangeInput[]
    recentExchanges = [...newestOk, ...deniedRows].filter(r => approvedOrigins.has(r.origin))
  } catch { /* best-effort */ }

  let recentFacts: Fact[] = []
  try {
    const rawFacts = storage.listFacts(run.id, { includeTainted: false, limit: 250, offset: 0 })
    recentFacts = rawFacts.filter(f => approvedOrigins.has(f.origin)).sort((a, b) => b.createdAt - a.createdAt)
  } catch { /* best-effort */ }

  const approvedOrder = new Map(run.approvedPersonaIds.map((id, i) => [id, i]))
  const personas: GbDataflowPersonaInput[] = [...resolveRunPersonas(storage, run.projectId, run.approvedPersonaIds).values()]
    .map((p, idx) => ({ handle: p.handle, roleLabel: p.roleLabel, configIndex: approvedOrder.get(p.id) ?? idx }))
    .sort((a, b) => classifyPersonaPrivilege(a.handle, a.roleLabel).rank - classifyPersonaPrivilege(b.handle, b.roleLabel).rank || a.configIndex - b.configIndex)

  const { nodes, byKey } = buildNodes({ approvedOrigins, endpoints, endpointParams, brokerExchanges: recentExchanges, personas }, approvedOrigins)
  for (const fc of extractRuntimeFactCaps(recentFacts, approvedOrigins)) {
    const key = `${fc.origin}|${fc.method}|${fc.normPath}`
    let prod = byKey.get(key)
    if (!prod) {
      const nouns = extractRouteNouns(fc.normPath)
      prod = {
        key, id: key, origin: fc.origin, host: hostOf(fc.origin), role: classifyOriginRole(fc.origin, [fc.normPath]),
        method: fc.method, normPath: fc.normPath, nouns, primaryNoun: nouns[nouns.length - 1] ?? '',
        isMutating: MUTATING.has(fc.method), isHighValue: true, paramNames: new Set(), consumedNouns: new Set(nouns),
        sinkKinds: [], acceptsSigning: false, acceptsCredential: false, acceptsInvite: false, acceptsSignedUrl: false,
        acceptsAsyncJob: false, hasSignatureRejection: false, produces: [], personaStatuses: new Map(),
        personaDiff: { allowed: [], denied: [], hasAsymmetry: false, has202: false, summary: '' },
      }
      byKey.set(key, prod)
      nodes.push(prod)
    }
    if (!prod.produces.some(p => p.fromLive && p.kind === fc.cap.kind && toSnake(p.field) === toSnake(fc.cap.field) && p.factId === fc.cap.factId)) {
      prod.produces.push(fc.cap)
    }
  }

  const basePersona = orderPersonasLowPrivFirst([], personas).basePersona ?? personas[0]?.handle ?? 'attacker'
  const nonElevated = new Set(personas.filter(p => !classifyPersonaPrivilege(p.handle, p.roleLabel).elevated).map(p => p.handle))
  const seenFlows = new Set<string>()
  const candidates: RuntimeValueFlowCandidate[] = []

  for (const prod of nodes) {
    const liveCaps = prod.produces.filter(c => c.fromLive)
    if (!liveCaps.length) continue
    for (const cap of liveCaps) {
      const obsTs = cap.observedAtMs ?? 0
      const isNew = !prevWatermark
        || (cap.exchangeId ? obsTs > prevWatermark.lastExchangeTs : false)
        || (cap.factId ? obsTs > prevWatermark.lastFactTs : false)
      const rawPersona = (cap.persona ?? '').trim()
      const actingPersona = rawPersona && (nonElevated.size === 0 ? !classifyPersonaPrivilege(rawPersona).elevated : nonElevated.has(rawPersona))
        ? rawPersona : basePersona
      for (const cons of nodes) {
        const score = scoreRuntimeValueFlow(prod, cap, cons, isNew)
        if (score === null) continue
        const flowKey = `${prod.origin}|${prod.method}|${prod.normPath}|${cons.origin}|${cons.method}|${cons.normPath}|${toSnake(cap.field)}`
        if (seenFlows.has(flowKey)) continue
        seenFlows.add(flowKey)
        candidates.push({
          flowSig: shortHash(flowKey, 16),
          producerOrigin: prod.origin, producerMethod: prod.method, producerNormPath: prod.normPath,
          consumerOrigin: cons.origin, consumerMethod: cons.method, consumerNormPath: cons.normPath,
          field: cap.field, kind: cap.kind, noun: cap.noun, actingPersona,
          crossOrigin: prod.origin !== cons.origin, isNew,
          hasDenied: cons.personaDiff.denied.length > 0, hasSignatureRejection: cons.hasSignatureRejection,
          score,
          valueDigest: cap.valueDigest ?? computeArtifactDigest(flowKey),
          exchangeId: cap.exchangeId, factId: cap.factId, observedAtMs: obsTs || Date.now(),
        })
      }
    }
  }

  candidates.sort((a, b) =>
    Number(b.isNew) - Number(a.isNew)
    || b.score - a.score
    || Number(b.crossOrigin) - Number(a.crossOrigin)
    || a.flowSig.localeCompare(b.flowSig),
  )
  return { candidates, liveFactIds: new Set(recentFacts.map(f => f.id)), personas }
}

function persistValueFlowCausalEdges(
  storage: Store,
  run: Run,
  candidates: readonly RuntimeValueFlowCandidate[],
): { edgesPersisted: number; producerCapsPersisted: number; prodCapBySig: Map<string, string> } {
  const ledger = storage.capabilityLedger(run.id)
  const prodCapBySig = new Map<string, string>()
  let edgesPersisted = 0
  let producerCapsPersisted = 0

  for (const cand of candidates.slice(0, 24)) {
    const slot = sanitizeCapSlot(cand.field)
    const prodCapId = formatDerivedCapabilityHandle(`vf_${shortHash(`${cand.producerOrigin}|${cand.producerMethod}|${cand.producerNormPath}`, 12)}`, slot)
    const consCapId = formatDerivedCapabilityHandle(`vfc_${shortHash(`${cand.consumerOrigin}|${cand.consumerMethod}|${cand.consumerNormPath}`, 12)}`, slot)
    prodCapBySig.set(cand.flowSig, prodCapId)

    const ts = Math.max(1, Math.floor(cand.observedAtMs || Date.now()))
    if (!ledger.getCapability(prodCapId)) {
      try {
        ledger.addCapability({
          capId: prodCapId,
          kind: kindToLedgerCapabilityKind(cand.kind),
          promotionStatus: 'capability_only',
          provenance: 'runtime_discovery',
          tenantScope: 'runtime_observed',
          actorPersona: cand.actingPersona,
          serviceOrigin: cand.producerOrigin,
          surface: classifyValueFlowSurface(cand.producerNormPath),
          parentHopReceiptIds: cand.exchangeId ? [cand.exchangeId] : [],
          artifactDigest: cand.valueDigest,
          artifactSummary: sanitizeCheckpointText(`Observed ${cand.kind} field ${slot} from ${cand.producerMethod} ${cand.producerNormPath}`, 180),
          metadata: {
            source: 'gb_valueflow',
            runtimeObserved: true,
            fieldName: slot,
            endpoint: cand.producerNormPath,
            method: cand.producerMethod,
            valueKind: cand.kind,
            ...(cand.exchangeId ? { exchangeId: cand.exchangeId } : {}),
            ...(cand.factId ? { factId: cand.factId } : {}),
          },
          createdAtMs: ts,
        })
        producerCapsPersisted += 1
      } catch { /* ignore duplicate or strict ledger validation */ }
    }
    if (!ledger.getCapability(consCapId)) {
      try {
        ledger.addCapability({
          capId: consCapId,
          kind: 'state_handle',
          promotionStatus: 'capability_only',
          provenance: 'runtime_discovery',
          tenantScope: 'unscoped_hypothesis',
          actorPersona: cand.actingPersona,
          serviceOrigin: cand.consumerOrigin,
          surface: classifyValueFlowSurface(cand.consumerNormPath),
          artifactDigest: computeArtifactDigest(`${consCapId}|${cand.consumerOrigin}|${cand.consumerMethod}|${cand.consumerNormPath}`),
          artifactSummary: sanitizeCheckpointText(`Consumer route ${cand.consumerMethod} ${cand.consumerNormPath} for ${slot}`, 180),
          metadata: {
            source: 'gb_valueflow_target',
            consumerTarget: true,
            fieldName: slot,
            endpoint: cand.consumerNormPath,
            method: cand.consumerMethod,
          },
          createdAtMs: ts,
        })
      } catch { /* ignore duplicate */ }
    }
    if (!ledger.getCapability(prodCapId) || !ledger.getCapability(consCapId)) continue
    const edgeId = `edge_vf_${shortHash(`${run.id}|${prodCapId}|${consCapId}|${slot}`, 20)}`
    if (ledger.getCausalEdge(edgeId)) continue
    try {
      ledger.addCausalEdge({
        edgeId,
        preconditionCapIds: [prodCapId],
        postconditionCapId: consCapId,
        edgeBindingKind: 'value_binding',
        hopReceiptId: cand.exchangeId ?? (cand.factId ? `fact:${cand.factId}` : `vf:${cand.flowSig}`),
        actorContext: { persona: cand.actingPersona, serviceOrigin: cand.consumerOrigin },
        sourceTimestampMs: ts,
        targetTimestampMs: ts,
        bindingDigest: cand.valueDigest,
        metadata: {
          source: 'gb_valueflow',
          fieldName: slot,
          valueKind: cand.kind,
          producerEndpoint: cand.producerNormPath,
          consumerEndpoint: cand.consumerNormPath,
          consumerMethod: cand.consumerMethod,
          ...(cand.factId ? { factId: cand.factId } : {}),
        },
      })
      edgesPersisted += 1
    } catch { /* ignore duplicate/timestamp/cycle races */ }
  }
  return { edgesPersisted, producerCapsPersisted, prodCapBySig }
}

/**
 * Continuous Round-2+ Grey-Box value-flow synthesizer & `value_binding` causal-edge persister.
 * Runs strictly in agentic mode (`llmMode === 'agentic'`), tracks a per-run 2xx exchange + fact
 * watermark so newly observed Round-2+ artifacts trigger bounded, deduplicated follow-on steps
 * and `CapabilityLedger.addCausalEdge` persistence without affecting `--no-llm` runs.
 */
export function refreshGreyBoxValueFlowSteps(
  storage: Store,
  run: Run,
  options: {
    activeOrigins: ReadonlySet<string>
    sourceMounted?: boolean
    llmMode?: FrontierLlmMode
    maxPerRound?: number
    maxTotalSteps?: number
    existingSteps?: readonly ChainStep[]
    routeStep?: (step: { title: string; hypothesis: string; category: string; skills: string[] }) => ChainStep['specialistProfile']
  },
): GbValueFlowRefreshResult {
  if (options.llmMode !== 'agentic' || options.sourceMounted || run.capabilityTier <= 0 || options.activeOrigins.size === 0) {
    return { steps: [], edgesPersisted: 0, producerCapsPersisted: 0, watermarkChanged: false }
  }
  const wmKey = `${run.id}:${run.goalRevision}`
  const prevWm = valueFlowWatermarks.get(wmKey)
  const currWm = readValueFlowWatermark(storage, run.id)
  if (
    prevWm
    && prevWm.exchangeCount === currWm.exchangeCount
    && prevWm.lastExchangeTs === currWm.lastExchangeTs
    && prevWm.factCount === currWm.factCount
    && prevWm.lastFactTs === currWm.lastFactTs
  ) {
    return { steps: [], edgesPersisted: 0, producerCapsPersisted: 0, watermarkChanged: false }
  }

  const { candidates, liveFactIds } = collectRuntimeValueFlowCandidates(storage, run, options.activeOrigins, prevWm)
  if (valueFlowWatermarks.size > 256) {
    const oldest = valueFlowWatermarks.keys().next().value
    if (oldest) valueFlowWatermarks.delete(oldest)
  }
  valueFlowWatermarks.set(wmKey, currWm)
  if (!candidates.length) {
    return { steps: [], edgesPersisted: 0, producerCapsPersisted: 0, watermarkChanged: true }
  }

  const { edgesPersisted, producerCapsPersisted, prodCapBySig } = persistValueFlowCausalEdges(storage, run, candidates)
  const existingSteps = options.existingSteps ?? storage.listChainSteps(run.id, run.goalRevision)
  const maxPerRound = Math.max(0, Math.min(8, Math.floor(options.maxPerRound ?? 4)))
  const maxTotal = Math.max(0, Math.min(32, Math.floor(options.maxTotalSteps ?? 18)))
  const existingVfSteps = existingSteps.filter(s => s.title.startsWith('GB value-flow (') || s.hypothesis.includes('[gb_valueflow='))
  const activeVfCount = existingVfSteps.filter(s => s.status === 'pending' || s.status === 'ready' || s.status === 'running').length
  const slotBudget = Math.max(0, Math.min(maxPerRound, maxTotal - existingVfSteps.length, 6 - activeVfCount))

  const existingTitles = new Set(existingSteps.map(s => s.title.trim().toLowerCase()))
  const existingSigs = new Set<string>()
  for (const s of existingSteps) {
    const m = /\[gb_valueflow=([a-f0-9]+)\]/.exec(s.hypothesis)
    if (m?.[1]) existingSigs.add(m[1])
  }

  const created: ChainStep[] = []
  const seenConsumer = new Set<string>()
  for (const cand of candidates) {
    if (created.length >= slotBudget) break
    if (existingSigs.has(cand.flowSig)) continue
    const consKey = `${cand.consumerOrigin}|${cand.consumerMethod}|${cand.consumerNormPath}`
    if (seenConsumer.has(consKey)) continue
    const prodHost = hostOf(cand.producerOrigin)
    const consHost = hostOf(cand.consumerOrigin)
    const title = `GB value-flow (${cand.kind}) · ${prodHost} -> ${consHost} ${cand.consumerMethod} ${cand.consumerNormPath} (${cand.field})`.slice(0, 180)
    const normTitle = title.trim().toLowerCase()
    if (existingTitles.has(normTitle)) continue
    const origins = [...new Set([cand.producerOrigin, cand.consumerOrigin])].filter(o => options.activeOrigins.has(o))
    const assetIds = run.candidates.filter(c => origins.includes(c.origin) && run.approved.includes(c.id)).map(c => c.id)
    if (!origins.length || !assetIds.length) continue

    const prodCapId = prodCapBySig.get(cand.flowSig)
    const tags = [
      '[chain_hops=2]', '[lane=chain]', '[dataflow_source=live]',
      `[gb_valueflow=${cand.flowSig}]`, `[api_dependency:${cand.field}]`,
      `[acting_persona=${cand.actingPersona}]`,
      ...(cand.crossOrigin ? [`[cross_origin_edge:${cand.producerOrigin}->${cand.consumerOrigin}]`] : []),
      ...(prodCapId ? [`[cap=${prodCapId}]`] : []),
    ]
    const actionHint = cand.kind === 'signing_secret'
      ? 'Capture and seal the signing material with kovo_verify seal_capability, then derive HMAC/JWT signatures with hmac_sign/jwt_sign against the consumer route vs a clean unsigned/invalid denied control.'
      : 'Capture and seal the runtime artifact with kovo_verify seal_capability, then replay it into the consumer route vs a clean unauthorized/cross-tenant denied control.'
    const hypothesis = `${tags.join(' ')} Live runtime value-flow: Hop 1 ${cand.producerMethod} ${cand.producerOrigin}${cand.producerNormPath} yields ${cand.field} [${cand.kind}] -> Hop 2 ${cand.consumerMethod} ${cand.consumerOrigin}${cand.consumerNormPath}. Base persona: ${cand.actingPersona}. ${actionHint}`.slice(0, 1400)
    const category = cand.kind === 'signed_url_or_location' ? 'upload-storage'
      : cand.kind === 'signing_secret' || cand.kind === 'credential_token' || cand.kind === 'invite_or_grant' ? 'auth-identity' : 'broken-access-control'
    const skills = [...new Set([
      'multihop-chains', 'chain-primitives', 'api-dependency', 'dataflow-graph',
      ...(cand.crossOrigin ? ['cross-origin-chain'] : []),
      ...(cand.hasDenied ? ['authz-differential'] : []),
      ...(cand.kind === 'signing_secret' ? ['crypto-signature-derivation'] : []),
      ...(prodCapId ? [`checkpoint_cap:${prodCapId}`] : []),
    ])]
    const priority = Math.max(90, Math.min(97, (cand.kind === 'signing_secret' || cand.hasDenied ? 97 : 94) - created.length))
    const dependsOnFactIds = cand.factId && liveFactIds.has(cand.factId) ? [cand.factId] : []

    existingTitles.add(normTitle)
    existingSigs.add(cand.flowSig)
    seenConsumer.add(consKey)
    const step = storage.addChainStep(run, {
      title, hypothesis, category, priority, targetAssetIds: assetIds, skills,
      dependsOnFactIds, sourceOrigins: origins,
      ...(options.routeStep ? { specialistProfile: options.routeStep({ title, hypothesis, category, skills }) } : {}),
    })
    created.push(storage.updateChainStep(step.id, { status: 'ready' }))
  }

  if (edgesPersisted > 0 || created.length > 0) {
    try {
      storage.event(
        run.id, 'planner.gb_valueflow',
        `Grey-Box value-flow refresh persisted ${edgesPersisted} value_binding edge(s) and enqueued ${created.length} follow-on step(s).`,
        { edgesPersisted, producerCapsPersisted, stepsCreated: created.length, roundNo: run.roundNo },
      )
    } catch { /* telemetry is best-effort */ }
  }
  return { steps: created, edgesPersisted, producerCapsPersisted, watermarkChanged: true }
}
