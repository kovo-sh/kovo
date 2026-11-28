/**
 * v8 Extended Oracle Invariant Families — pure, deterministic, fail-closed evaluators
 * operating strictly over host-signed transcript records.
 *
 * Defensive QA framing: every rule here is a precision falsifier for multi-hop, multi-tenant,
 * temporal, economic, cryptographic, parser/cache, and cross-surface impact claims.
 * Missing control arms, unsigned records, non-monotonic timestamps, or hardened responses
 * always fail closed (`satisfied: false`).
 */

import { ROLE_RANK, normalizeRole, type ImpactAssessment, type RoleName } from './oracle-invariants.ts'

export type V8OracleFamily =
  | 'dual_tenant_abac' | 'temporal_revocation' | 'economic_conservation'
  | 'cryptographic_scope_replay' | 'parser_cache_differential' | 'cross_surface_pivot'

export type V8SurfaceKind = 'http' | 'graphql' | 'ws' | 'sse' | 'browser' | 'webhook' | 'async_job' | 'idp' | 'cdn' | 'storage'
export type CausalBindingKind = 'value_binding' | 'derived_crypto_binding' | 'state_transition_binding' | 'async_pivot_binding'
export type SignatureVerifier = (record: HostSignedRecord) => boolean

export interface HostSignedRecord {
  id: string; hostSignature: string; timestampMs: number; status?: number | null; method?: string; route?: string; pathAndQuery?: string; surface?: V8SurfaceKind
  actorId?: string | null; tenantId?: string | null; entityId?: string | null; body?: string; json?: unknown
  requestHeaders?: Readonly<Record<string, string>> | null; responseHeaders?: Readonly<Record<string, string>> | null
  capabilityHandle?: string | null; artifactDigest?: string | null; derivedFromCapabilityId?: string | null
}
export interface V8OracleDecision extends ImpactAssessment { family: V8OracleFamily; subRule?: string }
interface WithVerifier { verifySignature?: SignatureVerifier }

/* ─────────────────────────── Shared pure helpers ─────────────────────────── */

const MIN_SIG_LEN = 8
const DEFAULT_TOL = 1e-6
const FINALIZED_STATES = new Set(['fulfilled', 'completed', 'captured', 'released', 'settled', 'paid', 'shipped', 'delivered', 'disbursed'])
const ERROR_ONLY_KEYS = new Set(['error', 'errors', 'message', 'detail', 'code', 'status', 'statusCode', 'ok', 'success'])
const TENANT_MARKER_KEYS = new Set(['tenant', 'tenantid', 'tenant_id', 'org', 'orgid', 'org_id', 'organizationid', 'organization_id', 'workspaceid', 'workspace_id', 'ownertenant', 'ownertenantid', 'owner_tenant_id', 'merchantid', 'merchant_id'])
const BATCH_DENIAL_KEY_RE = /^(?:error|errors|err|denied|forbidden|unauthorized|unauthorised|rejected|refused|failed|failures|blocked|disallowed|skipped|missing|not_?found|inaccessible|unaccessible|invalid|requested_?ids?|input_?ids?)$/i
const BATCH_ID_KEY_RE = /^(?:id|record_?id|item_?id|entity_?id|object_?id|secret_?id|resource_?id|doc_?id|document_?id|file_?id|project_?id|key|uid|uuid|slug|ref)$|(?:_id|Id)$/i
const BATCH_NON_DATA_KEY_RE = /^(?:id|record_?id|item_?id|entity_?id|object_?id|secret_?id|resource_?id|error|errors|err|message|detail|details|reason|code|status|status_?code|http_?status|ok|success|allowed|authorized|permitted|granted|denied|forbidden|unauthorized|unauthorised|rejected|refused|failed|skipped|missing|found|exists|index|idx)$/i
const BATCH_DENIED_VAL_RE = /^(?:denied|forbidden|unauthorized|unauthorised|rejected|refused|failed|error|not_?found|blocked|disallowed|skipped)$/i
const SENSITIVE_DATA_KEY_RE = /secret|passw|private|credential|api_?key|ssn|card|iban|balance|amount|salary|price|credit|debit|ledger|cents|vault|payout|settlement/i
const URL_OR_PATH_VAL_RE = /^(?:https?:\/\/\S+|\/[A-Za-z0-9._~/%?&=:@+-]+|[A-Za-z0-9._-]+\/[A-Za-z0-9._~/%-]*)$/
const HANDLE_KEY_RE = /^(?:token|code|handle|sig|signature|hmac|mac|nonce|redirect|redirect_?uri|href|link|location|url|uri|cache_?key|etag|checksum|hash|digest|artifact_?key|file_?key|object_?key|storage_?key|prefix|cursor)$|(?:token|handle|url|uri|href|link|path|sig)$/i
const ID_KEY_RE = /^(?:id|key|ref|trace)$|(?:^|[a-z0-9_])(?:_id|Id)$/
const SCOPE_KEY_RE = /^(?:tenant|org|organization|workspace|owner|user|actor|merchant|account|role|roles|email|email_?raw|origin|via|mode|source|reason)(?:_?id|Id|_?slug|Slug)?$/i
const META_KEY_RE = /^(?:ok|success|status|status_?code|state|kind|type|format|scopes?|ts|ttl|eta|exp|iat|nbf|age|retries|attempts|progress|priority|count|size|bytes|length|queued|pending|accepted|created|updated|processed|verified|revoked|linked|cached|primed|active|redeemed|redacted|horodatage|timestamp|expires|expiry)$|(?:At|Ms|Sec|In|Ts|Status|State|Kind|Type|Slug|Key)$|_(?:at|ms|sec|in|ts|en|am|status|state|kind|type|slug|key)$/i
const HTTP_STATUS_KEY_RE = /^(?:status|status_?code|code|estado|statut)$/i
const META_NUM_KEY_RE = /^(?:ts|ttl|eta|exp|iat|nbf|age|retries|attempts|progress|priority|count|size|bytes|length|horodatage|timestamp|expires|expiry)$|(?:At|Ms|Sec|In|Ts)$|_(?:at|ms|sec|in|ts|en|am)$/i

type StubScan = { leaves: number; substantive: boolean; urlOrPath: boolean; tokenOrCode: boolean; handleId: boolean; ts: boolean; bool: boolean; httpSt: boolean; statusLog: boolean; actorBy: boolean; atTs: boolean; tenantScope: boolean; wrapped: boolean; domainShort: number }
const emptyScan = (): StubScan => ({ leaves: 0, substantive: false, urlOrPath: false, tokenOrCode: false, handleId: false, ts: false, bool: false, httpSt: false, statusLog: false, actorBy: false, atTs: false, tenantScope: false, wrapped: false, domainShort: 0 })
const isHttpSt = (k: string, v: number): boolean => Number.isInteger(v) && v >= 100 && v <= 599 && HTTP_STATUS_KEY_RE.test(k)
const isMetaNum = (k: string, v: number): boolean => isHttpSt(k, v) || (v >= 1_000_000_000 && v <= 9_999_999_999_999) || META_NUM_KEY_RE.test(k)

function isStatusLogTuple(obj: Record<string, unknown>): boolean {
  const entries = Object.entries(obj).filter(([, v]) => v !== null && v !== undefined && v !== '')
  if (entries.length < 3 || entries.length > 6) return false
  let hasId = false, hasSt = false, hasTs = false, prose = 0
  for (const [k, v] of entries) {
    if (typeof v === 'object' || SENSITIVE_DATA_KEY_RE.test(k)) return false
    if (typeof v === 'number') { if (isHttpSt(k, v)) hasSt = true; else if (isMetaNum(k, v)) hasTs = true; else return false }
    else if (typeof v === 'string') { if (ID_KEY_RE.test(k) && !/\s/.test(v.trim())) hasId = true; else if (/\s/.test(v.trim())) prose += 1 }
  }
  return hasId && hasSt && hasTs && prose <= 1
}

function scanStub(node: unknown, depth: number, acc: StubScan): void {
  if (depth > 4 || node == null || acc.substantive) return
  if (Array.isArray(node)) {
    for (const item of node.slice(0, 32)) {
      if (item == null || item === '') continue
      if (typeof item === 'string' || typeof item === 'number' || typeof item === 'boolean') {
        acc.leaves += 1
        if ((typeof item === 'string' && /\s/.test(item.trim())) || (typeof item === 'number' && (item < 1_000_000_000 || item > 9_999_999_999_999))) acc.substantive = true
      } else if (typeof item === 'object' && !Array.isArray(item)) scanStub(item, depth + 1, acc)
      else acc.substantive = true
    }
    return
  }
  if (typeof node !== 'object') { acc.substantive = true; return }
  const obj = node as Record<string, unknown>
  const entries = Object.entries(obj).filter(([, v]) => v !== null && v !== undefined && v !== '' && !(Array.isArray(v) && v.length === 0))
  if (entries.length === 0) return
  if (isStatusLogTuple(obj)) { acc.statusLog = acc.handleId = acc.httpSt = acc.ts = true; acc.leaves += entries.length; return }
  const ownHandle = entries.some(([k, v]) => typeof v === 'string' && (HANDLE_KEY_RE.test(k) || URL_OR_PATH_VAL_RE.test(v.trim())))
  if (depth === 0 && entries.length === 1 && typeof entries[0]![1] === 'object' && !SENSITIVE_DATA_KEY_RE.test(entries[0]![0])) acc.wrapped = true
  for (const [k, v] of entries) {
    if (SENSITIVE_DATA_KEY_RE.test(k)) { acc.substantive = true; return }
    if (typeof v === 'object') {
      const isPrimArr = Array.isArray(v) && v.every(x => x == null || typeof x !== 'object')
      if (!isPrimArr && (depth >= 1 || entries.length > 1)) {
        const sub = emptyScan(); scanStub(v, depth + 1, sub)
        if (sub.substantive || (sub.leaves > 0 && !sub.handleId && !sub.urlOrPath && !sub.tokenOrCode && !sub.statusLog)) { acc.substantive = true; return }
        if (sub.leaves > 0 && !(sub.urlOrPath || sub.tokenOrCode || sub.ts || sub.httpSt || sub.statusLog || sub.bool)) { acc.substantive = true; return }
        acc.leaves += sub.leaves; acc.urlOrPath ||= sub.urlOrPath; acc.tokenOrCode ||= sub.tokenOrCode; acc.handleId ||= sub.handleId
        acc.ts ||= sub.ts; acc.bool ||= sub.bool; acc.httpSt ||= sub.httpSt; acc.statusLog ||= sub.statusLog; acc.domainShort += sub.domainShort
      } else scanStub(v, depth + 1, acc)
      continue
    }
    acc.leaves += 1
    if (typeof v === 'boolean') { acc.bool = true; if (!META_KEY_RE.test(k)) acc.domainShort += 1; continue }
    if (typeof v === 'number') {
      if (isHttpSt(k, v)) { acc.httpSt = true; continue }
      if (isMetaNum(k, v)) { acc.ts = true; if (/(?:At|_at)$/.test(k)) acc.atTs = true; continue }
      acc.substantive = true; return
    }
    if (typeof v === 'string') {
      const s = v.trim()
      if (/\s/.test(s)) { acc.substantive = true; return }
      if (URL_OR_PATH_VAL_RE.test(s)) acc.urlOrPath = true
      if (HANDLE_KEY_RE.test(k)) acc.tokenOrCode = true
      if (TENANT_MARKER_KEYS.has(k.toLowerCase())) acc.tenantScope = true
      if (/(?:By|_by)$/.test(k)) { acc.actorBy = true; continue }
      if (ID_KEY_RE.test(k)) { if (!SCOPE_KEY_RE.test(k)) acc.handleId = true; continue }
      if (HANDLE_KEY_RE.test(k) || URL_OR_PATH_VAL_RE.test(s) || META_KEY_RE.test(k)) continue
      if (SCOPE_KEY_RE.test(k)) { if (/^(?:email|role|roles|origin)$/i.test(k) && !ownHandle) acc.domainShort += 1; continue }
      acc.domainShort += 1
    }
  }
}

const parseJsonOrBody = (json: unknown, body?: string): unknown => { if (json !== undefined) return json; if (typeof body === 'string' && /^[\[{]/.test(body.trim())) try { return JSON.parse(body) } catch { return undefined }; return undefined }
function isErrorOrDeniedBatchObj(obj: Record<string, unknown>): boolean {
  if (obj.ok === false || obj.success === false || obj.allowed === false || obj.authorized === false || obj.permitted === false || obj.granted === false || obj.denied === true || obj.forbidden === true || obj.unauthorized === true || obj.rejected === true || obj.failed === true) return true
  if (obj.error === true || (typeof obj.error === 'string' && obj.error.trim().length > 0) || (obj.error !== null && typeof obj.error === 'object') || (Array.isArray(obj.errors) && obj.errors.length > 0)) return true
  return Object.entries(obj).some(([k, v]) => { const lk = k.toLowerCase(); return (typeof v === 'number' && v >= 400 && v <= 599 && /^(?:status|status_?code|http_?status|code)$/.test(lk)) || (typeof v === 'string' && /^(?:status|state|result|outcome|reason|code)$/.test(lk) && BATCH_DENIED_VAL_RE.test(v.trim())) })
}
function hasNonErrorDataVal(v: unknown, d: number): boolean {
  if (d > 3 || v == null || v === '') return false
  if (typeof v === 'string') return v.trim().length > 0
  if (typeof v === 'number' || typeof v === 'boolean') return true
  if (Array.isArray(v)) return v.some(x => hasNonErrorDataVal(x, d + 1))
  if (typeof v === 'object') { const s = v as Record<string, unknown>; return !isErrorOrDeniedBatchObj(s) && Object.entries(s).some(([k, sv]) => !BATCH_DENIAL_KEY_RE.test(k) && !BATCH_NON_DATA_KEY_RE.test(k) && hasNonErrorDataVal(sv, d + 1)) }
  return false
}
const hasNonErrorDataField = (obj: Record<string, unknown>, idKey?: string): boolean => Object.entries(obj).some(([k, v]) => k !== idKey && !BATCH_DENIAL_KEY_RE.test(k) && !BATCH_NON_DATA_KEY_RE.test(k) && hasNonErrorDataVal(v, 0))
export function findNonErrorBatchRecord(json: unknown, body: string | undefined, targetId: string): Record<string, unknown> | null {
  const needle = targetId.trim(), root = parseJsonOrBody(json, body)
  if (!needle || root == null || typeof root !== 'object') return null
  const walk = (node: unknown, d: number): Record<string, unknown> | null => {
    if (d > 5 || node == null || typeof node !== 'object') return null
    if (Array.isArray(node)) { for (const x of node.slice(0, 64)) { const h = walk(x, d + 1); if (h) return h } return null }
    const obj = node as Record<string, unknown>; if (isErrorOrDeniedBatchObj(obj)) return null
    for (const [k, v] of Object.entries(obj)) if ((typeof v === 'string' || typeof v === 'number') && String(v).trim() === needle && BATCH_ID_KEY_RE.test(k) && hasNonErrorDataField(obj, k)) return obj
    for (const [k, v] of Object.entries(obj)) {
      if (BATCH_DENIAL_KEY_RE.test(k) || !v || typeof v !== 'object') continue
      if (k.trim() === needle && !Array.isArray(v) && !isErrorOrDeniedBatchObj(v as Record<string, unknown>) && hasNonErrorDataField(v as Record<string, unknown>)) return v as Record<string, unknown>
      const h = walk(v, d + 1); if (h) return h
    }
    return null
  }
  return walk(root, 0)
}
export function extractTenantMarkers(json: unknown, body?: string, skipDenied = false): Set<string> {
  const out = new Set<string>(), val = parseJsonOrBody(json, body)
  const walk = (v: unknown, d: number): void => {
    if (d > 4 || out.size > 32 || v == null || typeof v !== 'object') return
    if (Array.isArray(v)) { for (const x of v) walk(x, d + 1); return }
    const obj = v as Record<string, unknown>; if (skipDenied && isErrorOrDeniedBatchObj(obj)) return
    for (const [k, x] of Object.entries(obj)) { if (skipDenied && BATCH_DENIAL_KEY_RE.test(k)) continue; if (typeof x === 'string' && x.trim() && TENANT_MARKER_KEYS.has(k.toLowerCase())) out.add(x.trim().toLowerCase()); else if (x && typeof x === 'object') walk(x, d + 1) }
  }
  walk(val, 0); return out
}
const SIGNED_AUTH_QUERY_KEYS = new Set(['sig', 'signature', 'hmac', 'mac', 'token', 'access_token', 'code', 'state', 'nonce', 'ts', 'timestamp', 'expires', 'exp', 'googleaccessid', 'x-amz-signature', 'x-amz-credential', 'x-amz-date', 'x-amz-expires', 'x-amz-signedheaders', 'x-amz-security-token', 'x-amz-algorithm', 'x-goog-signature', 'x-goog-credential', 'x-goog-date', 'x-goog-expires', 'x-goog-signedheaders', 'x-goog-algorithm'])
const SIGNED_URL_PRIMARY_KEYS = new Set(['signedurl', 'signed_url', 'presignedurl', 'presigned_url', 'downloadurl', 'download_url', 'shareurl', 'share_url', 'exporturl', 'export_url', 'verifyurl', 'verify_url', 'inviteurl', 'invite_url', 'redemptionurl', 'redemption_url'])
const SIGNED_URL_FALLBACK_KEYS = new Set(['url', 'href', 'link', 'uri', 'location'])
const SIGNED_URL_SIG_QUERY_RE = /[?&](?:sig|signature|hmac|mac|token|x-amz-signature|x-goog-signature)=/i
export function canonicalSignedResource(rawPathOrUrl: string | null | undefined): string {
  const raw = normStr(rawPathOrUrl); if (!raw) return ''
  let pathPart = '', queryPart = ''
  if (/^https?:\/\//i.test(raw)) { try { const u = new URL(raw); pathPart = u.pathname; queryPart = u.search.startsWith('?') ? u.search.slice(1) : '' } catch { return '' } }
  else { const noHash = raw.split('#', 1)[0] ?? '', qIdx = noHash.indexOf('?'); pathPart = qIdx >= 0 ? noHash.slice(0, qIdx) : noHash; queryPart = qIdx >= 0 ? noHash.slice(qIdx + 1) : '' }
  const cleanPath = pathPart.replace(/\/+$/, '').toLowerCase() || (pathPart.startsWith('/') ? '/' : '')
  if (!cleanPath || !queryPart) return cleanPath
  const pairs: [string, string][] = []
  for (const [k, v] of new URLSearchParams(queryPart).entries()) { const lk = k.trim().toLowerCase(); if (!SIGNED_AUTH_QUERY_KEYS.has(lk)) pairs.push([lk, v.trim()]) }
  if (pairs.length === 0) return cleanPath
  pairs.sort(([a, av], [b, bv]) => (a < b ? -1 : a > b ? 1 : av < bv ? -1 : av > bv ? 1 : 0))
  return `${cleanPath}?${pairs.map(([k, v]) => `${k}=${v}`).join('&')}`
}
export function extractIssuedSignedUrl(json: unknown, body?: string): string {
  let fallback = ''
  const walk = (v: unknown, d: number): string => {
    if (d > 4 || v == null || typeof v !== 'object') return ''
    if (Array.isArray(v)) { for (const x of v.slice(0, 32)) { const h = walk(x, d + 1); if (h) return h } return '' }
    const obj = v as Record<string, unknown>; if (isErrorOrDeniedBatchObj(obj)) return ''
    for (const [k, x] of Object.entries(obj)) {
      if (BATCH_DENIAL_KEY_RE.test(k) || typeof x !== 'string') continue
      const s = x.trim(), lk = k.toLowerCase(); if (!s || !/^(?:https?:\/\/|\/)/i.test(s)) continue
      if (SIGNED_URL_PRIMARY_KEYS.has(lk)) return s
      if (!fallback && SIGNED_URL_FALLBACK_KEYS.has(lk) && SIGNED_URL_SIG_QUERY_RE.test(s)) fallback = s
    }
    for (const [k, x] of Object.entries(obj)) if (!BATCH_DENIAL_KEY_RE.test(k) && x && typeof x === 'object') { const h = walk(x, d + 1); if (h) return h }
    return ''
  }
  return walk(parseJsonOrBody(json, body), 0) || fallback
}
export interface HostAuthzDimension { tenant: string; responseTenants: Set<string>; personaTenant: string; responseScope: string; issuedSignedResource: string; requestSignedResource: string }
/** Shared host-attested authorization-dimension primitive (R4-C-5): symmetric tenant derivation + signed-resource scope. */
export function deriveRecordAuthzDimension(rec: Pick<HostSignedRecord, 'route' | 'pathAndQuery' | 'json' | 'body' | 'tenantId'> | undefined, opts?: { personaTenant?: string | null; preferredTenant?: string | null; stripUrlTokens?: boolean }): HostAuthzDimension {
  if (!rec) return { tenant: '', responseTenants: new Set<string>(), personaTenant: '', responseScope: '', issuedSignedResource: '', requestSignedResource: '' }
  let responseTenants = extractTenantMarkers(rec.json, rec.body, true)
  const rawPq = rec.pathAndQuery ?? rec.route ?? ''
  if (opts?.stripUrlTokens && responseTenants.size > 0 && rawPq) {
    const [p = '', q = ''] = rawPq.split('?', 2), u = new Set<string>()
    for (const s of p.split('/')) if (s) { u.add(s.toLowerCase()); try { u.add(decodeURIComponent(s).toLowerCase()) } catch {} }
    if (q) for (const v of new URLSearchParams(q.split('#', 1)[0]!).values()) if (v.trim()) u.add(v.trim().toLowerCase())
    responseTenants = new Set([...responseTenants].filter(t => !u.has(t)))
  }
  const personaTenant = normKey(opts?.personaTenant ?? rec.tenantId), pref = normKey(opts?.preferredTenant)
  const tenant = (pref && responseTenants.has(pref) ? pref : [...responseTenants][0]) || personaTenant
  return { tenant, responseTenants, personaTenant, responseScope: extractResponseScope(rec.json, rec.body), issuedSignedResource: canonicalSignedResource(extractIssuedSignedUrl(rec.json, rec.body)), requestSignedResource: canonicalSignedResource(rawPq) }
}

export function extractResponseScope(json: unknown, body?: string): string {
  const walk = (v: unknown, d: number): string => {
    if (d > 4 || v == null || typeof v !== 'object') return ''
    if (Array.isArray(v)) { for (const x of v.slice(0, 32)) { const h = walk(x, d + 1); if (h) return h } return '' }
    for (const [k, x] of Object.entries(v as Record<string, unknown>)) if (k.toLowerCase() === 'scope' && typeof x === 'string' && x.trim()) return x.trim().toLowerCase()
    for (const x of Object.values(v as Record<string, unknown>)) if (x && typeof x === 'object') { const h = walk(x, d + 1); if (h) return h }
    return ''
  }
  return walk(parseJsonOrBody(json, body), 0)
}

function shapeEqual(a: unknown, b: unknown, depth = 0): boolean {
  if (depth > 4 || a === b) return a === b
  if (a == null || b == null || typeof a !== 'object' || typeof b !== 'object' || Array.isArray(a) !== Array.isArray(b)) return false
  if (Array.isArray(a) && Array.isArray(b)) return a.length === b.length && a.every((x, i) => shapeEqual(x, b[i], depth + 1))
  const ak = Object.keys(a as Record<string, unknown>).sort(), bk = Object.keys(b as Record<string, unknown>).sort()
  return ak.length === bk.length && ak.every((k, i) => k === bk[i] && shapeEqual((a as Record<string, unknown>)[k], (b as Record<string, unknown>)[k], depth + 1))
}

const SESSION_TOK_RE = /^(?:token|access_?token|session_?token|id_?token|jwt|bearer_?token|auth_?token)$/i, SESSION_AUTH_RE = /^(?:role|roles|permissions|tenant|tenant_?id|org|org_?id|organization_?id|user_?id|userid|actor_?id)$/i, SESSION_DISQ_RE = /^(?:job_?id|export_?id|task_?id|upload_?id|delivery_?id|webhook_?id|pat_?id|signed_?url|presigned_?url|download_?url|share_?url|export_?url|url|href|link|redirect|redirect_?uri|location)$/i
function isVerifiedSessionGrant(val: unknown, status?: number | null, method?: string): boolean {
  if (!method || !/^(?:POST|PUT)$/i.test(method) || status === 202 || (typeof status === 'number' && (status < 200 || status >= 300)) || !val || typeof val !== 'object' || Array.isArray(val)) return false
  const root = val as Record<string, unknown>, es = Object.entries(root), t = es.length === 1 && es[0]![1] && typeof es[0]![1] === 'object' && !Array.isArray(es[0]![1]) ? (es[0]![1] as Record<string, unknown>) : root
  let hasTok = false, hasAuth = false
  for (const [k, v] of Object.entries(t)) { const lk = k.trim().toLowerCase(); if (SESSION_DISQ_RE.test(lk) || ((lk === 'verified' || lk === 'active' || lk === 'ok' || lk === 'success') && v === false) || ((lk === 'revoked' || lk === 'pending' || lk === 'queued') && v === true) || ((lk === 'status' || lk === 'state') && typeof v === 'string' && /^(?:queued|pending|processing|accepted|unverified|denied|failed|error|rejected)$/i.test(v.trim()))) return false; if (SESSION_TOK_RE.test(lk) && typeof v === 'string' && v.trim().length >= 4) hasTok = true; if (SESSION_AUTH_RE.test(lk) && ((typeof v === 'string' && v.trim().length > 0) || (Array.isArray(v) && v.length > 0))) hasAuth = true }
  return hasTok && hasAuth
}
/** Universal structural & differential stub/ack/enqueue detector (language-agnostic). */
export function isJobOrHandleStub(json: unknown, body?: string, status?: number | null, method?: string, _route?: string | null, baselineJson?: unknown, hasDeniedControl = false): boolean {
  let val = json; const trimmed = typeof body === 'string' ? body.trim() : ''
  if (val === undefined && trimmed && /^[\[{]/.test(trimmed)) try { val = JSON.parse(trimmed) } catch { val = undefined }
  if (val == null) return Boolean(trimmed && !/[\r\n\s,;]/.test(trimmed) && (trimmed.length <= 32 || URL_OR_PATH_VAL_RE.test(trimmed)))
  if (typeof val !== 'object') return typeof val === 'string' && !/[\r\n\s,;]/.test(val.trim()) && (val.trim().length <= 32 || URL_OR_PATH_VAL_RE.test(val.trim()))
  if (baselineJson !== undefined && shapeEqual(val, baselineJson)) return true
  if (hasDeniedControl && isVerifiedSessionGrant(val, status, method)) return false
  const acc = emptyScan(); scanStub(val, 0, acc)
  if (acc.substantive) return false
  if (acc.leaves === 0) return true
  if (Boolean(method) && /^(?:POST|PUT)$/i.test(method!) && status !== 202 && !acc.wrapped && acc.actorBy && acc.atTs && !acc.urlOrPath && !acc.tokenOrCode && !acc.httpSt) return false
  if (acc.domainShort > ((status === 202 || acc.urlOrPath || acc.tokenOrCode || acc.statusLog) ? 2 : 1)) return false
  return status === 202 || acc.urlOrPath || acc.tokenOrCode || acc.statusLog || (status === 201 && (acc.handleId || acc.bool || acc.httpSt || acc.ts)) || (acc.wrapped && (acc.handleId || acc.ts || acc.bool || acc.httpSt)) || (acc.handleId && (acc.bool || acc.ts || acc.httpSt)) || (acc.leaves <= 2 && acc.bool && !acc.tenantScope && acc.domainShort === 0)
}
const stubRec = (r: Pick<HostSignedRecord, 'json' | 'body' | 'status' | 'method' | 'route'>): boolean => isJobOrHandleStub(r.json, r.body, r.status, r.method, r.route)

const ok = (family: V8OracleFamily, subRule: string, reason: string, evidence: Record<string, unknown>): V8OracleDecision => ({ family, subRule, required: true, satisfied: true, reason, evidence })
const deny = (family: V8OracleFamily, reason: string, subRule?: string, evidence?: Record<string, unknown>): V8OracleDecision => ({ family, subRule, required: true, satisfied: false, reason, evidence })
const normStr = (v: string | null | undefined): string => (typeof v === 'string' ? v.trim() : '')
const normKey = (v: string | null | undefined): string => normStr(v).toLowerCase()
const normRoute = (r: string | null | undefined): string => (normStr(r).split('?')[0] ?? '').replace(/\/+$/, '').toLowerCase()
const isDenied = (s: number | null | undefined): boolean => s === 401 || s === 403
const isOk = (s: number | null | undefined): boolean => typeof s === 'number' && s >= 200 && s < 300
const isRedirect = (s: number | null | undefined): boolean => s === 301 || s === 302 || s === 303 || s === 307 || s === 308
const allFiniteNonNeg = (...vals: number[]): boolean => vals.every((v) => Number.isFinite(v) && v >= 0)

function checkRecord(record: HostSignedRecord | null | undefined, label: string, verify?: SignatureVerifier): string | null {
  if (!record || typeof record !== 'object') return `missing_${label}_record`
  if (!normStr(record.id)) return `empty_${label}_id`
  if (normStr(record.hostSignature).length < MIN_SIG_LEN) return `unsigned_${label}_record`
  if (!Number.isFinite(record.timestampMs) || record.timestampMs <= 0) return `invalid_${label}_timestamp`
  return verify && !verify(record) ? `invalid_${label}_signature` : null
}
const checkRecords = (pairs: readonly [HostSignedRecord | null | undefined, string][], verify?: SignatureVerifier): string | null => pairs.reduce<string | null>((err, [rec, label]) => err ?? checkRecord(rec, label, verify), null)

function hasSubstantivePayload(record: HostSignedRecord): boolean {
  if (stubRec(record)) return false
  if (normStr(record.artifactDigest) || normStr(record.capabilityHandle)) return true
  if (record.json !== undefined && record.json !== null) {
    if (Array.isArray(record.json)) return record.json.length > 0
    if (typeof record.json === 'object') {
      const obj = record.json as Record<string, unknown>
      if (obj.ok === false || obj.success === false || typeof obj.error === 'string') return false
      return Object.keys(obj).some((k) => !ERROR_ONLY_KEYS.has(k) && obj[k] !== null && obj[k] !== undefined && obj[k] !== '')
    }
    return typeof record.json === 'string' ? record.json.trim().length > 0 : true
  }
  const body = normStr(record.body)
  return Boolean(body) && !/^\s*\{\s*"(?:ok|success)"\s*:\s*(?:true|false)\s*\}\s*$/i.test(body) && !/^\s*\{\s*"(?:error|message)"\s*:/i.test(body)
}

function hasCacheHitHeader(headers: Readonly<Record<string, string>> | null | undefined): boolean {
  if (!headers) return false
  for (const [rawKey, rawVal] of Object.entries(headers)) {
    const k = rawKey.toLowerCase(), v = rawVal.toLowerCase()
    if ((k === 'x-cache' || k === 'cf-cache-status' || k === 'x-cache-status' || k === 'cache-status') && /\bhit\b/.test(v)) return true
    if (k === 'age' && Number.isFinite(Number(v.trim())) && Number(v.trim()) > 0) return true
  }
  return false
}

/* ───────────────────── 1. Dual-Tenant ABAC Evaluator ─────────────────────── */

export interface DualTenantActor { actorId: string; rolesByTenant: Readonly<Record<string, RoleName | string | null | undefined>> }
export interface DualTenantCrossOrgTransferInput extends WithVerifier {
  mode: 'cross_org_transfer'; actor: DualTenantActor; sourceTenantId: string; destTenantId: string; entityId: string
  requiredSourceRole?: RoleName; requiredDestRole?: RoleName; transferRecord: HostSignedRecord; postTransferReadback: HostSignedRecord
  observedOwnerTenantId: string; sourceControlDenied?: HostSignedRecord
}
export interface DualTenantCacheBleedInput extends WithVerifier {
  mode: 'dual_org_cache_bleed'; actor: DualTenantActor; primeTenantId: string; targetTenantId: string; requiredRole?: RoleName
  baselineDeniedControl: HostSignedRecord; primeAction: HostSignedRecord; bledAccess: HostSignedRecord
  isolatedControl?: boolean; targetRecordId?: string; observedTenantId?: string
}
export interface DualTenantBatchPartialAuthzInput extends WithVerifier {
  mode: 'batch_partial_authz'; actor: DualTenantActor; ownTenantId: string; foreignTenantId: string; ownRecordId: string; foreignRecordId: string
  requestedIds: readonly string[]; requiredRole?: RoleName; singleForeignControlDenied: HostSignedRecord; batchRequest: HostSignedRecord
  returnedForeignIds?: readonly string[]; foreignDataObserved?: boolean; postMutationReadback?: HostSignedRecord; foreignMutationPersisted?: boolean
}
export type DualTenantAbacInput = DualTenantCrossOrgTransferInput | DualTenantCacheBleedInput | DualTenantBatchPartialAuthzInput

export function resolveTenantRole(actor: DualTenantActor | null | undefined, tenantId: string): RoleName | null {
  const target = normKey(tenantId)
  if (!actor?.rolesByTenant || !target) return null
  for (const [k, v] of Object.entries(actor.rolesByTenant)) {
    if (normKey(k) === target) return normalizeRole(v ?? undefined)
  }
  return null
}

export function hasTenantRoleAtLeast(actor: DualTenantActor, tenantId: string, required: RoleName): boolean {
  const role = resolveTenantRole(actor, tenantId)
  return role !== null && ROLE_RANK[role] >= ROLE_RANK[required]
}

export function evaluateDualTenantAbac(input: DualTenantAbacInput): V8OracleDecision {
  const f: V8OracleFamily = 'dual_tenant_abac'
  if (!input?.actor || !normStr(input.actor.actorId)) return deny(f, 'missing_actor_identity')

  if (input.mode === 'cross_org_transfer') {
    const sub = input.mode, src = normKey(input.sourceTenantId), dst = normKey(input.destTenantId)
    if (!src || !dst) return deny(f, 'missing_tenant_scope', sub)
    if (src === dst) return deny(f, 'same_tenant_transfer_not_cross_org', sub)
    if (!normStr(input.entityId)) return deny(f, 'missing_entity_id', sub)
    if (!hasTenantRoleAtLeast(input.actor, dst, input.requiredDestRole ?? 'admin')) return deny(f, 'actor_lacks_dest_tenant_privilege', sub)
    if (hasTenantRoleAtLeast(input.actor, src, input.requiredSourceRole ?? 'admin')) return deny(f, 'actor_authorized_in_source_tenant', sub)

    const recErr = checkRecords([[input.sourceControlDenied, 'source_control'], [input.transferRecord, 'transfer'], [input.postTransferReadback, 'post_transfer_readback']], input.verifySignature)
    if (recErr) return deny(f, recErr, sub)
    if (!isDenied(input.sourceControlDenied!.status)) return deny(f, 'source_control_not_denied', sub)
    if (!isOk(input.transferRecord.status) || /^(?:GET|HEAD|OPTIONS)$/i.test(normStr(input.transferRecord.method))) return deny(f, 'transfer_not_accepted', sub)
    if (!isOk(input.postTransferReadback.status) || input.postTransferReadback.id === input.transferRecord.id) return deny(f, 'readback_not_accepted', sub)
    const aKey = normKey(input.actor.actorId), tAct = normKey(input.transferRecord.actorId), cAct = normKey(input.sourceControlDenied!.actorId)
    if ((tAct && tAct !== aKey) || (cAct && cAct !== aKey)) return deny(f, 'actor_record_mismatch', sub)
    if (input.sourceControlDenied!.status === 401 && (!cAct || cAct !== aKey)) return deny(f, 'unauthenticated_baseline_control', sub)
    if (stubRec(input.postTransferReadback)) return deny(f, 'terminal_impact_unproven_intermediate_stub', sub)
    if (input.postTransferReadback.timestampMs < input.transferRecord.timestampMs) return deny(f, 'non_monotonic_readback_timestamp', sub)
    if (normKey(input.observedOwnerTenantId) !== dst) return deny(f, 'transfer_not_persisted_to_dest_tenant', sub)
    return ok(f, sub, 'cross_org_transfer_without_source_tenant_authorization', { actorId: input.actor.actorId, sourceTenantId: src, destTenantId: dst, entityId: input.entityId, sourceRole: resolveTenantRole(input.actor, src), destRole: resolveTenantRole(input.actor, dst), transferId: input.transferRecord.id, readbackId: input.postTransferReadback.id })
  }

  if (input.mode === 'dual_org_cache_bleed') {
    const sub = input.mode, prime = normKey(input.primeTenantId), target = normKey(input.targetTenantId), req = input.requiredRole ?? 'admin'
    if (!prime || !target) {
      const re = Object.entries(input.actor.rolesByTenant ?? {}).map(([t, r]) => [normKey(t), normalizeRole(r ?? undefined)] as const).filter(([t, r]) => Boolean(t && r))
      const hi = prime ? hasTenantRoleAtLeast(input.actor, prime, req) : re.some(([, r]) => r !== null && ROLE_RANK[r] >= ROLE_RANK[req])
      if (new Set(re.map(([t]) => t)).size < 2 || !hi || !re.some(([, r]) => r !== null && ROLE_RANK[r] < ROLE_RANK[req])) return deny(f, 'actor_not_dual_tenant: dual_org_cache_bleed requires a multi-tenant actor with elevated role in primeTenant; for single-tenant cache bleed use parser_cache_differential or omit oracleFamily', sub)
      return deny(f, 'missing_tenant_scope', sub)
    }
    if (prime === target) return deny(f, 'same_tenant_not_cache_bleed', sub)
    if (!hasTenantRoleAtLeast(input.actor, prime, req)) return deny(f, 'actor_lacks_prime_tenant_privilege', sub)
    if (hasTenantRoleAtLeast(input.actor, target, req)) return deny(f, 'actor_authorized_in_target_tenant', sub)
    const recErr = checkRecords([[input.baselineDeniedControl, 'baseline_control'], [input.primeAction, 'prime_action'], [input.bledAccess, 'bled_access']], input.verifySignature)
    if (recErr) return deny(f, recErr, sub)
    if (!isDenied(input.baselineDeniedControl.status)) return deny(f, 'baseline_control_not_denied', sub)
    if (!isOk(input.primeAction.status)) return deny(f, 'prime_action_failed', sub)
    if (!isOk(input.bledAccess.status)) return deny(f, 'bled_access_denied_or_failed', sub)
    const cRt = normRoute(input.baselineDeniedControl.route), bRt = normRoute(input.bledAccess.route)
    if (cRt && bRt && cRt !== bRt) return deny(f, 'baseline_control_and_bled_route_mismatch', sub)
    if (input.baselineDeniedControl.status === 401 && normKey(input.baselineDeniedControl.actorId) !== normKey(input.actor.actorId)) return deny(f, 'unauthenticated_baseline_control', sub)
    if (!input.isolatedControl && input.primeAction.timestampMs < input.baselineDeniedControl.timestampMs) return deny(f, 'non_monotonic_prime_timestamp', sub)
    if (input.bledAccess.timestampMs < input.primeAction.timestampMs) return deny(f, 'non_monotonic_bled_timestamp', sub)
    const obsT = normKey(input.observedTenantId)
    if (obsT && obsT !== target) return deny(f, 'observed_tenant_mismatch', sub)
    if (stubRec(input.bledAccess)) return deny(f, 'terminal_impact_unproven_intermediate_stub', sub)
    const bledTenants = extractTenantMarkers(input.bledAccess.json, input.bledAccess.body)
    if (bledTenants.size > 0 && bledTenants.has(prime) && !bledTenants.has(target)) return deny(f, 'bled_access_own_tenant_only', sub)
    if (!bledTenants.has(target) && obsT !== target) return deny(f, 'bled_access_missing_target_tenant_marker', sub)
    if (!normStr(input.targetRecordId) && !hasSubstantivePayload(input.bledAccess)) return deny(f, 'bled_access_missing_substantive_data', sub)
    return ok(f, sub, 'dual_org_permission_cache_bleed_confirmed', { actorId: input.actor.actorId, primeTenantId: prime, targetTenantId: target, baselineControlId: input.baselineDeniedControl.id, primeActionId: input.primeAction.id, bledAccessId: input.bledAccess.id })
  }

  if (input.mode === 'batch_partial_authz') {
    const sub = input.mode, ownTenant = normKey(input.ownTenantId), foreignTenant = normKey(input.foreignTenantId), req = input.requiredRole ?? 'member'
    if (!ownTenant || !foreignTenant) return deny(f, 'missing_tenant_scope', sub)
    if (ownTenant === foreignTenant) return deny(f, 'same_tenant_batch_not_cross_tenant', sub)
    if (!hasTenantRoleAtLeast(input.actor, ownTenant, req)) return deny(f, 'actor_lacks_own_tenant_role', sub)
    if (hasTenantRoleAtLeast(input.actor, foreignTenant, req)) return deny(f, 'actor_authorized_in_foreign_tenant', sub)

    const ownId = normStr(input.ownRecordId), foreignId = normStr(input.foreignRecordId), reqSet = new Set((input.requestedIds ?? []).map(normStr))
    if (!ownId || !foreignId || ownId === foreignId) return deny(f, 'invalid_batch_record_pair', sub)
    if (!reqSet.has(ownId) || !reqSet.has(foreignId)) return deny(f, 'batch_missing_own_and_foreign_ids', sub)
    const recErr = checkRecords([[input.singleForeignControlDenied, 'single_foreign_control'], [input.batchRequest, 'batch_request']], input.verifySignature)
    if (recErr) return deny(f, recErr, sub)
    if (!isDenied(input.singleForeignControlDenied.status)) return deny(f, 'single_foreign_control_not_denied', sub)
    if (!isOk(input.batchRequest.status)) return deny(f, 'batch_request_denied_or_failed', sub)
    const cAct = normKey(input.singleForeignControlDenied.actorId), bAct = normKey(input.batchRequest.actorId)
    if (input.singleForeignControlDenied.status === 401 && (!cAct || !bAct || cAct !== bAct)) return deny(f, 'unauthenticated_baseline_control', sub)
    const batchHasJson = parseJsonOrBody(input.batchRequest.json, input.batchRequest.body) !== undefined
    const foreignRead = !stubRec(input.batchRequest) && new Set((input.returnedForeignIds ?? []).map(normStr)).has(foreignId) && (!batchHasJson || findNonErrorBatchRecord(input.batchRequest.json, input.batchRequest.body, foreignId) !== null) && (input.foreignDataObserved === true || hasSubstantivePayload(input.batchRequest))
    let foreignMut = false
    if (input.postMutationReadback) {
      const mutErr = checkRecord(input.postMutationReadback, 'post_mutation_readback', input.verifySignature); if (mutErr) return deny(f, mutErr, sub)
      if (stubRec(input.postMutationReadback)) return deny(f, 'terminal_impact_unproven_intermediate_stub', sub)
      foreignMut = isOk(input.postMutationReadback.status) && input.postMutationReadback.timestampMs >= input.batchRequest.timestampMs && input.foreignMutationPersisted === true
    }
    if (!foreignRead && !foreignMut) return deny(f, stubRec(input.batchRequest) ? 'terminal_impact_unproven_intermediate_stub' : 'foreign_record_not_returned_or_mutated', sub)
    return ok(f, sub, 'batch_partial_authorization_bypass_confirmed', { actorId: input.actor.actorId, ownTenantId: ownTenant, foreignTenantId: foreignTenant, foreignRecordId: foreignId, impactMode: foreignMut ? 'mutation' : 'read', controlId: input.singleForeignControlDenied.id, batchRequestId: input.batchRequest.id })
  }
  return deny(f, 'unknown_dual_tenant_mode')
}

/* ───────────────────── 2. Temporal Revocation Evaluator ──────────────────── */
export interface TemporalRevocationInput extends WithVerifier {
  credentialKind: 'token' | 'session' | 'role' | 'invite' | 'pat' | 'async_job' | 'webhook_callback'
  credentialHandle?: string | null; actorId?: string | null; primarySurface: V8SurfaceKind; secondarySurface: V8SurfaceKind
  preRevocationBaseline?: HostSignedRecord; revocationEvent: HostSignedRecord; primaryDeniedCheck: HostSignedRecord; secondarySuccess: HostSignedRecord; elevatedRoleGranted?: boolean
}
export function evaluateTemporalRevocation(input: TemporalRevocationInput): V8OracleDecision {
  const f: V8OracleFamily = 'temporal_revocation'
  if (!input) return deny(f, 'missing_input')
  const sub = input.credentialKind
  const pairs: [HostSignedRecord | undefined, string][] = [[input.revocationEvent, 'revocation_event'], [input.primaryDeniedCheck, 'primary_denied_check'], [input.secondarySuccess, 'secondary_success']]
  if (input.preRevocationBaseline) pairs.push([input.preRevocationBaseline, 'pre_revocation_baseline'])
  const recErr = checkRecords(pairs, input.verifySignature)
  if (recErr) return deny(f, recErr, sub)
  if (input.preRevocationBaseline) {
    if (!isOk(input.preRevocationBaseline.status)) return deny(f, 'baseline_not_active', sub)
    if (input.revocationEvent.timestampMs < input.preRevocationBaseline.timestampMs) return deny(f, 'non_monotonic_revocation_timestamp', sub)
  }
  if (!isOk(input.revocationEvent.status)) return deny(f, 'revocation_event_not_confirmed', sub)
  if (input.revocationEvent.id === input.primaryDeniedCheck.id || input.revocationEvent.id === input.secondarySuccess.id || input.primaryDeniedCheck.id === input.secondarySuccess.id) return deny(f, 'temporal_reuses_exchange_id', sub)
  if (!isDenied(input.primaryDeniedCheck.status)) return deny(f, 'primary_surface_not_revoked', sub)
  if (input.revocationEvent.method && /^(?:GET|HEAD|OPTIONS)$/i.test(normStr(input.revocationEvent.method))) return deny(f, 'revocation_event_not_mutating', sub)
  if (!isOk(input.secondarySuccess.status)) return deny(f, 'secondary_surface_properly_revoked', sub)
  if (input.primaryDeniedCheck.timestampMs < input.revocationEvent.timestampMs) return deny(f, 'primary_check_precedes_revocation', sub)
  if (input.secondarySuccess.timestampMs < input.primaryDeniedCheck.timestampMs) return deny(f, 'secondary_access_precedes_verified_revocation', sub)
  const handle = normStr(input.credentialHandle), actor = normStr(input.actorId)
  const pHandle = normStr(input.primaryDeniedCheck.capabilityHandle), sHandle = normStr(input.secondarySuccess.capabilityHandle)
  const pActor = normStr(input.primaryDeniedCheck.actorId), sActor = normStr(input.secondarySuccess.actorId)
  if (handle && ((pHandle && pHandle !== handle) || (sHandle && sHandle !== handle))) return deny(f, 'credential_handle_mismatch', sub)
  const boundByHandle = Boolean(handle && pHandle === handle && sHandle === handle)
  const boundByActor = Boolean(actor && pActor === actor && sActor === actor && (!pHandle || !sHandle || pHandle === sHandle))
  if (!boundByHandle && !boundByActor) return deny(f, 'unlinked_primary_and_secondary_principal', sub)
  const pRoute = normRoute(input.primaryDeniedCheck.route), sRoute = normRoute(input.secondarySuccess.route)
  if (input.primarySurface === input.secondarySurface && (!pRoute || !sRoute || pRoute === sRoute)) return deny(f, 'secondary_surface_not_distinct_from_primary', sub)
  if (input.elevatedRoleGranted !== true && !hasSubstantivePayload(input.secondarySuccess)) return deny(f, 'secondary_success_lacks_substantive_impact', sub)
  return ok(f, sub, 'revoked_credential_accepted_on_secondary_surface', { credentialKind: sub, primarySurface: input.primarySurface, secondarySurface: input.secondarySurface, revocationEventId: input.revocationEvent.id, primaryDeniedId: input.primaryDeniedCheck.id, secondarySuccessId: input.secondarySuccess.id, boundBy: boundByHandle ? 'capability_handle' : 'actor_id' })
}

/* ─────────────────── 3. Economic Conservation Evaluator ──────────────────── */
interface EconomicBase extends WithVerifier { baselineReadback: HostSignedRecord; actions: readonly HostSignedRecord[]; finalReadback: HostSignedRecord; tolerance?: number }
export interface OverRefundInput extends EconomicBase { equation: 'over_refund'; paidAmount: number; refundedAmounts: readonly number[]; baselineRefunded?: number }
export interface BalanceMintingInput extends EconomicBase { equation: 'balance_minting'; balancesBefore: Readonly<Record<string, number>>; balancesAfter: Readonly<Record<string, number>>; authorizedDeposits: number; authorizedWithdrawals?: number }
export interface UnderpaidFulfillmentInput extends EconomicBase { equation: 'underpaid_fulfillment'; paidAmount: number; fulfilledValue: number; fulfillmentState: string }
export interface IneligibleDiscountInput extends EconomicBase { equation: 'ineligible_discount'; subtotalAmount: number; requiredThreshold: number; discountApplied: number; finalTotalPaid?: number }
export type EconomicConservationInput = OverRefundInput | BalanceMintingInput | UnderpaidFulfillmentInput | IneligibleDiscountInput
function sumFiniteMap(map: Readonly<Record<string, number>> | null | undefined): number | null {
  if (!map || typeof map !== 'object') return null
  const vals = Object.values(map); if (vals.length === 0) return null
  let total = 0; for (const v of vals) { if (!Number.isFinite(v)) return null; total += v }
  return total
}

export function evaluateEconomicConservation(input: EconomicConservationInput): V8OracleDecision {
  const f: V8OracleFamily = 'economic_conservation'
  if (!input) return deny(f, 'missing_input')
  const sub = input.equation

  const recErr = checkRecords([[input.baselineReadback, 'baseline_readback'], [input.finalReadback, 'final_readback']], input.verifySignature)
  if (recErr) return deny(f, recErr, sub)
  if (!Array.isArray(input.actions) || input.actions.length === 0) return deny(f, 'missing_action_records', sub)
  if (!isOk(input.baselineReadback.status)) return deny(f, 'baseline_readback_failed', sub)
  if (!isOk(input.finalReadback.status)) return deny(f, 'final_readback_failed', sub)
  if (input.baselineReadback.id === input.finalReadback.id) return deny(f, 'baseline_and_final_same_exchange', sub)
  if (input.baselineReadback.method && !/^(?:GET|HEAD)$/i.test(normStr(input.baselineReadback.method))) return deny(f, 'baseline_readback_not_read', sub)
  if (input.finalReadback.method && !/^(?:GET|HEAD)$/i.test(normStr(input.finalReadback.method))) return deny(f, 'final_readback_not_read', sub)
  const bRoute = normRoute(input.baselineReadback.route), fRoute = normRoute(input.finalReadback.route)
  if (bRoute && fRoute && bRoute !== fRoute) return deny(f, 'baseline_and_final_route_mismatch', sub)
  const bAct = normKey(input.baselineReadback.actorId), fAct = normKey(input.finalReadback.actorId)
  if (bAct && fAct && bAct !== fAct) return deny(f, 'baseline_and_final_actor_mismatch', sub)
  if (input.finalReadback.timestampMs <= input.baselineReadback.timestampMs) return deny(f, 'non_monotonic_baseline_final_timestamp', sub)

  let maxActionTs = -Infinity, anyActionOk = false
  const seenActIds = new Set<string>()
  for (let i = 0; i < input.actions.length; i++) {
    const act = input.actions[i]
    const err = checkRecord(act, `action_${i}`, input.verifySignature)
    if (err) return deny(f, err, sub)
    if (act.id === input.baselineReadback.id || act.id === input.finalReadback.id) return deny(f, 'action_reuses_readback_exchange', sub)
    if (act.method && /^(?:GET|HEAD|OPTIONS)$/i.test(normStr(act.method))) return deny(f, 'action_not_mutating', sub)
    if (seenActIds.has(act.id)) return deny(f, 'duplicate_action_exchange_id', sub)
    seenActIds.add(act.id)
    if (act.timestampMs < input.baselineReadback.timestampMs) return deny(f, 'action_precedes_baseline_readback', sub)
    if (act.timestampMs > maxActionTs) maxActionTs = act.timestampMs
    if (isOk(act.status)) anyActionOk = true
  }
  if (!anyActionOk) return deny(f, 'no_successful_action', sub)
  if (input.finalReadback.timestampMs < maxActionTs) return deny(f, 'final_readback_precedes_actions', sub)

  const tol = input.tolerance ?? DEFAULT_TOL
  if (!allFiniteNonNeg(tol)) return deny(f, 'invalid_tolerance', sub)

  if (input.equation === 'over_refund') {
    const baseRef = input.baselineRefunded ?? 0
    if (!allFiniteNonNeg(input.paidAmount, baseRef)) return deny(f, 'invalid_refund_parameters', sub)
    if (!Array.isArray(input.refundedAmounts) || input.refundedAmounts.length === 0) return deny(f, 'missing_refunded_amounts', sub)
    let totalRefunded = 0
    for (const amt of input.refundedAmounts) { if (!allFiniteNonNeg(amt)) return deny(f, 'invalid_refund_amount', sub); totalRefunded += amt }
    if (totalRefunded <= input.paidAmount + tol || totalRefunded <= baseRef + tol) return deny(f, 'refund_ledger_conserved', sub, { paidAmount: input.paidAmount, totalRefunded })
    return ok(f, sub, 'over_refund_conservation_violated', { paidAmount: input.paidAmount, totalRefunded, excessRefunded: Number((totalRefunded - input.paidAmount).toFixed(6)), baselineId: input.baselineReadback.id, finalReadbackId: input.finalReadback.id })
  }
  if (input.equation === 'balance_minting') {
    const beforeSum = sumFiniteMap(input.balancesBefore), afterSum = sumFiniteMap(input.balancesAfter), deposits = input.authorizedDeposits, withdrawals = input.authorizedWithdrawals ?? 0
    if (beforeSum === null || afterSum === null) return deny(f, 'invalid_balance_snapshot', sub)
    if (!allFiniteNonNeg(deposits, withdrawals)) return deny(f, 'invalid_deposit_or_withdrawal', sub)
    const ceiling = beforeSum + deposits - withdrawals
    if (afterSum <= ceiling + tol) return deny(f, 'balance_ledger_conserved', sub, { beforeSum, afterSum, deposits, withdrawals })
    return ok(f, sub, 'balance_conservation_violated_value_minted', { beforeSum, afterSum, authorizedDeposits: deposits, authorizedWithdrawals: withdrawals, mintedDelta: Number((afterSum - ceiling).toFixed(6)), baselineId: input.baselineReadback.id, finalReadbackId: input.finalReadback.id })
  }

  if (input.equation === 'underpaid_fulfillment') {
    if (!allFiniteNonNeg(input.paidAmount) || !Number.isFinite(input.fulfilledValue) || input.fulfilledValue <= 0) return deny(f, 'invalid_fulfillment_amounts', sub)
    const state = normKey(input.fulfillmentState); if (!FINALIZED_STATES.has(state)) return deny(f, 'order_not_finalized', sub, { fulfillmentState: state })
    if (input.fulfilledValue <= input.paidAmount + tol) return deny(f, 'fulfillment_payment_conserved', sub)
    return ok(f, sub, 'underpaid_fulfillment_conservation_violated', { paidAmount: input.paidAmount, fulfilledValue: input.fulfilledValue, shortfall: Number((input.fulfilledValue - input.paidAmount).toFixed(6)), fulfillmentState: state, finalReadbackId: input.finalReadback.id })
  }
  if (input.equation === 'ineligible_discount') {
    if (!allFiniteNonNeg(input.subtotalAmount, input.discountApplied) || !Number.isFinite(input.requiredThreshold) || input.requiredThreshold <= 0) return deny(f, 'invalid_discount_parameters', sub)
    if (input.subtotalAmount + tol >= input.requiredThreshold) return deny(f, 'discount_threshold_satisfied_eligible', sub)
    if (input.discountApplied <= tol) return deny(f, 'ineligible_discount_not_applied', sub)
    if (input.finalTotalPaid !== undefined && (!allFiniteNonNeg(input.finalTotalPaid) || input.finalTotalPaid > input.subtotalAmount - input.discountApplied + tol || input.finalTotalPaid >= input.subtotalAmount - tol)) return deny(f, 'discount_not_reflected_in_final_total', sub)
    return ok(f, sub, 'ineligible_discount_applied_below_threshold', { subtotalAmount: input.subtotalAmount, requiredThreshold: input.requiredThreshold, discountApplied: input.discountApplied, finalReadbackId: input.finalReadback.id })
  }
  return deny(f, 'unknown_economic_equation')
}

/* ───────────────── 4. Cryptographic Scope Replay Evaluator ───────────────── */
export interface CryptographicScopeReplayInput extends WithVerifier {
  tamperedSignatureControl: HostSignedRecord; sourceValidIssuance: HostSignedRecord; replayedAcceptance: HostSignedRecord
  sourceTenant: string; sourceScope: string; targetTenant: string; targetScope: string; sourceSignedResource?: string; targetSignedResource?: string
  tamperedSignatureDigest?: string; signatureDigest?: string; replayedSignatureDigest?: string; persistedImpact?: boolean
}
export function evaluateCryptographicScopeReplay(input: CryptographicScopeReplayInput): V8OracleDecision {
  const f: V8OracleFamily = 'cryptographic_scope_replay'
  if (!input) return deny(f, 'missing_input')
  const recErr = checkRecords([[input.tamperedSignatureControl, 'tampered_signature_control'], [input.sourceValidIssuance, 'source_valid_issuance'], [input.replayedAcceptance, 'replayed_acceptance']], input.verifySignature)
  if (recErr) return deny(f, recErr)
  if (!isDenied(input.tamperedSignatureControl.status)) return deny(f, 'signature_verification_not_enforced_decoy', undefined, { tamperedStatus: input.tamperedSignatureControl.status })
  if (!isOk(input.sourceValidIssuance.status)) return deny(f, 'source_signature_issuance_failed')
  if (!isOk(input.replayedAcceptance.status)) return deny(f, 'replayed_signature_rejected_hardened')
  if (input.sourceValidIssuance.id === input.replayedAcceptance.id) return deny(f, 'issuance_and_replay_same_exchange')
  if (input.tamperedSignatureControl.id === input.sourceValidIssuance.id || input.tamperedSignatureControl.id === input.replayedAcceptance.id) return deny(f, 'control_reuses_probe_exchange')
  if (input.replayedAcceptance.timestampMs < input.sourceValidIssuance.timestampMs) return deny(f, 'replay_precedes_signature_issuance')
  const tRoute = normRoute(input.tamperedSignatureControl.route), rRoute = normRoute(input.replayedAcceptance.route)
  if (tRoute && rRoute && tRoute !== rRoute) return deny(f, 'tampered_control_and_replay_route_mismatch')
  const srcT = normKey(input.sourceTenant), srcS = normKey(input.sourceScope), dstT = normKey(input.targetTenant), dstS = normKey(input.targetScope)
  if (!srcT || !srcS || !dstT || !dstS) return deny(f, 'missing_tenant_or_scope_context')
  const sRec = input.sourceValidIssuance, rRec = input.replayedAcceptance, sRoute = normRoute(sRec.route)
  const sDim = deriveRecordAuthzDimension(sRec), rDim = deriveRecordAuthzDimension(rRec)
  const sSignedRes = normKey(input.sourceSignedResource) || sDim.issuedSignedResource || (sRoute && rRoute && sRoute === rRoute ? sDim.requestSignedResource : '')
  const rSignedRes = normKey(input.targetSignedResource) || rDim.requestSignedResource
  const callerDiff = normKey(sRec.actorId) !== normKey(rRec.actorId) || normKey(sRec.tenantId) !== normKey(rRec.tenantId), routeDiff = Boolean(sRoute && rRoute && sRoute !== rRoute)
  const sameReason = callerDiff || routeDiff ? 'same_principal_not_replay' : 'same_tenant_and_scope_not_replay'
  if (srcT === dstT && srcS === dstS) return deny(f, sameReason)
  const sameRespTenants = sDim.responseTenants.size === rDim.responseTenants.size && [...sDim.responseTenants].every(m => rDim.responseTenants.has(m))
  const hasRespTenantDiff = Boolean(sDim.tenant && rDim.responseTenants.size > 0 && !sameRespTenants && !rDim.responseTenants.has(sDim.tenant))
  const hasRespScopeDiff = Boolean(sDim.responseScope && rDim.responseScope && sDim.responseScope !== rDim.responseScope)
  const sameMethod = !normKey(sRec.method) || !normKey(rRec.method) || normKey(sRec.method) === normKey(rRec.method)
  if (sSignedRes && rSignedRes && sSignedRes === rSignedRes && (Boolean(sDim.issuedSignedResource) || sameMethod) && !hasRespTenantDiff && !hasRespScopeDiff) return deny(f, sameReason)
  if (srcT === dstT && !sSignedRes && !hasRespTenantDiff && !hasRespScopeDiff && routeDiff && (srcS === sRoute || srcS.endsWith(`:${sRoute}`)) && (dstS === rRoute || dstS.endsWith(`:${rRoute}`))) return deny(f, 'same_principal_not_replay')
  const tamperedDigest = normStr(input.tamperedSignatureDigest), validDigest = normStr(input.signatureDigest), replayedDigest = normStr(input.replayedSignatureDigest)
  if (!tamperedDigest || !validDigest || !replayedDigest) return deny(f, 'missing_signature_digest_binding')
  if (tamperedDigest === validDigest) return deny(f, 'tampered_digest_matches_valid_signature')
  if (replayedDigest !== validDigest) return deny(f, 'replayed_signature_digest_mismatch')
  if (input.persistedImpact !== true && stubRec(input.replayedAcceptance)) return deny(f, 'terminal_impact_unproven_intermediate_stub')
  if (input.persistedImpact !== true && !hasSubstantivePayload(input.replayedAcceptance)) return deny(f, 'replay_acceptance_lacks_substantive_impact')
  return ok(f, srcT !== dstT ? 'cross_tenant_scope_replay' : 'cross_scope_replay', 'valid_signature_replayed_across_scope_boundary', { sourceTenant: srcT, sourceScope: srcS, targetTenant: dstT, targetScope: dstS, signatureDigest: validDigest, tamperedControlId: input.tamperedSignatureControl.id, sourceIssuanceId: input.sourceValidIssuance.id, replayedAcceptanceId: input.replayedAcceptance.id })
}

/* ───────────────── 5. Parser / Cache Differential Evaluator ──────────────── */
export interface ParserDifferentialInput extends WithVerifier {
  mode: 'parser_differential'; differentialKind: 'duplicate_json_key' | 'path_normalization' | 'header_normalization' | 'hop_by_hop_smuggling' | 'content_type_confusion'
  differentialFeature: string; canonicalValue?: string; variantValue?: string; impactKind: 'read' | 'mutation'
  cleanControl: HostSignedRecord; differentialProbe: HostSignedRecord; isolatedControl?: boolean; postMutationReadback?: HostSignedRecord; mutationPersisted?: boolean; unauthorizedDigest?: string
}
export interface CachePrimedDifferentialInput extends WithVerifier {
  mode: 'cache_primed'; cacheKey: string; victimArtifactDigest: string; cleanControl: HostSignedRecord; cleanControlContainsVictimData?: boolean
  victimOrPrimeRequest: HostSignedRecord; attackerProbe: HostSignedRecord; isolatedControl?: boolean; cacheHitObserved?: boolean
}
export type ParserCacheDifferentialInput = ParserDifferentialInput | CachePrimedDifferentialInput
export function evaluateParserCacheDifferential(input: ParserCacheDifferentialInput): V8OracleDecision {
  const f: V8OracleFamily = 'parser_cache_differential'
  if (!input) return deny(f, 'missing_input')
  if (input.mode === 'parser_differential') {
    const sub = input.differentialKind
    if (!normStr(input.differentialFeature)) return deny(f, 'missing_differential_feature', sub)
    if (input.canonicalValue === undefined || input.variantValue === undefined || input.canonicalValue === input.variantValue) return deny(f, 'no_request_differential_between_control_and_probe', sub)
    const recErr = checkRecords([[input.cleanControl, 'clean_control'], [input.differentialProbe, 'differential_probe']], input.verifySignature)
    if (recErr) return deny(f, recErr, sub)
    if (!isDenied(input.cleanControl.status)) return deny(f, 'clean_control_not_denied', sub)
    if (!isOk(input.differentialProbe.status)) return deny(f, 'differential_probe_rejected', sub)
    const cMeth = normKey(input.cleanControl.method), pMeth = normKey(input.differentialProbe.method); if (cMeth && pMeth && cMeth !== pMeth) return deny(f, 'control_and_probe_method_mismatch', sub)
    const cAct = normKey(input.cleanControl.actorId), pAct = normKey(input.differentialProbe.actorId); if (cAct !== pAct && (cAct || pAct)) return deny(f, 'control_and_probe_actor_mismatch', sub)
    const cRt = normRoute(input.cleanControl.route), pRt = normRoute(input.differentialProbe.route); if (sub !== 'path_normalization' && cRt && pRt && cRt !== pRt) return deny(f, 'control_and_probe_route_mismatch', sub)
    if (!input.isolatedControl && input.differentialProbe.timestampMs < input.cleanControl.timestampMs) return deny(f, 'probe_precedes_clean_control', sub)
    if (input.impactKind === 'mutation') {
      const mutErr = checkRecord(input.postMutationReadback, 'post_mutation_readback', input.verifySignature); if (mutErr) return deny(f, mutErr, sub)
      if (!isOk(input.postMutationReadback!.status)) return deny(f, 'mutation_readback_failed', sub)
      if (input.postMutationReadback!.timestampMs < input.differentialProbe.timestampMs) return deny(f, 'mutation_readback_precedes_probe', sub)
      if (stubRec(input.postMutationReadback!)) return deny(f, 'terminal_impact_unproven_intermediate_stub', sub)
      if (input.mutationPersisted !== true) return deny(f, 'mutation_not_persisted', sub)
    } else {
      if (stubRec(input.differentialProbe)) return deny(f, 'terminal_impact_unproven_intermediate_stub', sub)
      const probeDigest = normStr(input.unauthorizedDigest ?? input.differentialProbe.artifactDigest), ctrlDigest = normStr(input.cleanControl.artifactDigest)
      if (probeDigest && ctrlDigest && probeDigest === ctrlDigest) return deny(f, 'probe_artifact_already_in_control', sub)
      if (!probeDigest && !hasSubstantivePayload(input.differentialProbe)) return deny(f, 'differential_read_missing_substantive_data', sub)
    }
    return ok(f, sub, 'parser_differential_bypass_confirmed', { differentialKind: sub, differentialFeature: input.differentialFeature, impactKind: input.impactKind, cleanControlId: input.cleanControl.id, differentialProbeId: input.differentialProbe.id })
  }
  if (input.mode === 'cache_primed') {
    const sub = input.mode, victimDigest = normStr(input.victimArtifactDigest)
    if (!normStr(input.cacheKey)) return deny(f, 'missing_cache_key', sub)
    if (!victimDigest) return deny(f, 'missing_victim_artifact_digest', sub)
    const recErr = checkRecords([[input.cleanControl, 'clean_control'], [input.victimOrPrimeRequest, 'victim_prime'], [input.attackerProbe, 'attacker_probe']], input.verifySignature)
    if (recErr) return deny(f, recErr, sub)
    const ctrlDenied = isDenied(input.cleanControl.status), ctrlLeaked = input.cleanControlContainsVictimData === true || normStr(input.cleanControl.artifactDigest) === victimDigest
    if (!ctrlDenied && ctrlLeaked) return deny(f, 'resource_already_exposed_in_clean_control', sub)
    if (!ctrlDenied && !isOk(input.cleanControl.status) && input.cleanControl.status !== 404) return deny(f, 'invalid_clean_control_status', sub)
    if (!isOk(input.victimOrPrimeRequest.status)) return deny(f, 'victim_prime_failed', sub)
    if (!isOk(input.attackerProbe.status)) return deny(f, 'attacker_probe_rejected', sub)
    if (!input.isolatedControl && input.victimOrPrimeRequest.timestampMs < input.cleanControl.timestampMs) return deny(f, 'prime_precedes_clean_control', sub)
    if (input.attackerProbe.timestampMs < input.victimOrPrimeRequest.timestampMs) return deny(f, 'attacker_probe_precedes_cache_prime', sub)
    const vActor = normKey(input.victimOrPrimeRequest.actorId), aActor = normKey(input.attackerProbe.actorId), vTenant = normKey(input.victimOrPrimeRequest.tenantId), aTenant = normKey(input.attackerProbe.tenantId)
    const sameActor = Boolean(vActor && aActor && vActor === aActor), sameTenant = Boolean(vTenant && aTenant && vTenant === aTenant)
    if ((!vActor && !vTenant) || (sameActor && (sameTenant || (!vTenant && !aTenant)))) return deny(f, 'victim_and_attacker_not_distinct', sub)
    if (stubRec(input.attackerProbe)) return deny(f, 'terminal_impact_unproven_intermediate_stub', sub)
    if (input.cacheHitObserved !== true && !hasCacheHitHeader(input.attackerProbe.responseHeaders)) return deny(f, 'no_cache_hit_evidence', sub)
    if (normStr(input.attackerProbe.artifactDigest) !== victimDigest) return deny(f, 'attacker_did_not_receive_victim_artifact', sub)
    return ok(f, sub, 'cache_primed_cross_principal_bleed_confirmed', { cacheKey: input.cacheKey, victimArtifactDigest: victimDigest, cleanControlId: input.cleanControl.id, victimPrimeId: input.victimOrPrimeRequest.id, attackerProbeId: input.attackerProbe.id })
  }
  return deny(f, 'unknown_parser_cache_mode')
}

/* ─────────── 6. Cross-Surface Pivot (Backwards-Compat DAG Alias) ─────────── */

export type CrossSurfaceHopRole = 'trigger_write' | 'browser_dom_trace' | 'admin_bot_visit' | 'worker_ssrf_callback' | 'oob_callback' | 'oidc_redirect' | 'token_exchange' | 'terminal_impact'
export interface CrossSurfaceHop {
  surface: V8SurfaceKind; role: CrossSurfaceHopRole; record: HostSignedRecord; bindingKind?: CausalBindingKind
  emittedArtifactDigest?: string | null; consumedArtifactDigest?: string | null; correlationToken?: string | null
  derivedFromCapabilityId?: string | null; ablationControlDenied?: HostSignedRecord
}
export interface CrossSurfacePivotInput extends WithVerifier {
  attackerOriginPersona: { actorId: string; role: RoleName | string; tenantId?: string | null; isPrivilegedPreSeeded?: boolean }
  preChainControlDenied: HostSignedRecord; controlKind?: 'authz_denied' | 'unreachable_internal'; hops: readonly CrossSurfaceHop[]
  terminalImpact: { kind: 'privileged_read' | 'privileged_mutation' | 'credential_capture' | 'internal_secret_exfil' | 'privilege_escalation'; verified: boolean; impactDigest: string; postImpactReadback?: HostSignedRecord }
}
/**
 * @deprecated Cross-surface pivot verification is owned directly by the `CompositeProofReceipt` DAG
 * (`surfaces.size >= 2` over verified causal edges). Standalone calls outside the DAG fail closed.
 */
export function evaluateCrossSurfacePivot(input: CrossSurfacePivotInput): V8OracleDecision {
  const f: V8OracleFamily = 'cross_surface_pivot'
  const sub = input?.terminalImpact?.kind
  const hops = Array.isArray(input?.hops) ? input.hops : []
  const lastHop = hops[hops.length - 1]
  if (lastHop?.record && stubRec(lastHop.record)) return deny(f, 'terminal_impact_unproven_intermediate_stub', sub)
  if (hops.length < 2) return deny(f, 'invalid_hop_count', sub)
  const surfaces = new Set(hops.map(h => h?.surface).filter(Boolean))
  if (surfaces.size < 2) return deny(f, 'single_surface_not_cross_surface_pivot', sub)
  return deny(f, 'cross_surface_pivot_requires_composite_dag', sub)
}

/* ─────────────────────────── Unified Dispatcher ──────────────────────────── */
export interface V8OracleInputMap {
  dual_tenant_abac: DualTenantAbacInput; temporal_revocation: TemporalRevocationInput; economic_conservation: EconomicConservationInput
  cryptographic_scope_replay: CryptographicScopeReplayInput; parser_cache_differential: ParserCacheDifferentialInput; cross_surface_pivot: CrossSurfacePivotInput
}
export function evaluateV8OracleFamily<F extends V8OracleFamily>(family: F, input: V8OracleInputMap[F]): V8OracleDecision {
  switch (family) {
    case 'dual_tenant_abac': return evaluateDualTenantAbac(input as DualTenantAbacInput)
    case 'temporal_revocation': return evaluateTemporalRevocation(input as TemporalRevocationInput)
    case 'economic_conservation': return evaluateEconomicConservation(input as EconomicConservationInput)
    case 'cryptographic_scope_replay': return evaluateCryptographicScopeReplay(input as CryptographicScopeReplayInput)
    case 'parser_cache_differential': return evaluateParserCacheDifferential(input as ParserCacheDifferentialInput)
    case 'cross_surface_pivot': return evaluateCrossSurfacePivot(input as CrossSurfacePivotInput)
    default: return deny(family as V8OracleFamily, 'unknown_v8_oracle_family')
  }
}
