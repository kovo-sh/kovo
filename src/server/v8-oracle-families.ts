/**
 * Universal Tier-1 Deterministic Evidence Primitives (A2) — pure, deterministic, fail-closed,
 * strictly 0-LLM evaluators operating over host-signed transcript records.
 *
 * Five domain-free primitives (`causal_dag`, `access_differential`, `state_delta_and_conservation`,
 * `wire_framing_and_cache_differential`, `oob_and_execution_witness`) are the primary engines; the
 * legacy v8 family evaluators are thin normalization adapters resolved via `resolveUniversalPrimitive`.
 *
 * Defensive QA framing: every rule is a precision falsifier. Missing control arms, unsigned records,
 * non-monotonic timestamps, or hardened responses always fail closed (`satisfied: false`).
 */

import { ROLE_RANK, isReadMethod, normalizeRole, resolvePersonaIdentity, routeFamily, stepReadsState, type ImpactAssessment, type RoleName } from './oracle-invariants.ts'
import type { HydratableEntry } from './v8-oracle-hydrate.ts'
import { resolveTerminalContractKind } from './oracle-spec.ts'
export { resolveCompositeTerminalContract } from './oracle-spec.ts'

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
export interface V8OracleDecision extends ImpactAssessment { family: V8OracleFamily; primitive?: UniversalEvidencePrimitive; subRule?: string }
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

/* ═══════════ Universal Tier-1 Deterministic Evidence Primitives (strictly 0-LLM) ═══════════
 * Five domain-free evaluation engines. Every legacy v8 family, sub-mode, equation, and canonical
 * vuln class resolves to exactly one primitive via `resolveUniversalPrimitive(...)`; the legacy
 * family evaluators further below are thin normalization adapters onto these engines.
 */
export const UNIVERSAL_EVIDENCE_PRIMITIVES = ['causal_dag', 'access_differential', 'state_delta_and_conservation', 'wire_framing_and_cache_differential', 'oob_and_execution_witness'] as const
export type UniversalEvidencePrimitive = (typeof UNIVERSAL_EVIDENCE_PRIMITIVES)[number]
const UNIVERSAL_PRIMITIVE_SET: ReadonlySet<string> = new Set(UNIVERSAL_EVIDENCE_PRIMITIVES)
const P_DAG: UniversalEvidencePrimitive = 'causal_dag', P_ACCESS: UniversalEvidencePrimitive = 'access_differential', P_STATE: UniversalEvidencePrimitive = 'state_delta_and_conservation'
const P_WIRE: UniversalEvidencePrimitive = 'wire_framing_and_cache_differential', P_WITNESS: UniversalEvidencePrimitive = 'oob_and_execution_witness'

/** Legacy family names / sub-modes / equations that are not canonical class labels in `oracle-spec.ts`. */
const LEGACY_PRIMITIVE_ALIASES: ReadonlyMap<string, UniversalEvidencePrimitive> = new Map([
  ...['cross_surface_pivot', 'webhook_forgery', 'webhook', 'forged_signature'].map(k => [k, P_DAG] as const),
  ...['dual_tenant_abac', 'cross_org_transfer', 'batch_partial_authz', 'temporal_revocation', 'cryptographic_scope_replay'].map(k => [k, P_ACCESS] as const),
  ...['economic_conservation', 'over_refund', 'balance_minting', 'underpaid_fulfillment', 'ineligible_discount', 'quantity_conservation', 'mass_assignment'].map(k => [k, P_STATE] as const),
  ...['parser_cache_differential', 'parser_differential', 'cache_primed', 'dual_org_cache_bleed', 'cache_tenant_bleed', 'request_smuggling', 'http_request_smuggling', 'duplicate_json_key', 'path_normalization', 'header_normalization', 'hop_by_hop_smuggling', 'content_type_confusion', 'timing', 'boolean_differential'].map(k => [k, P_WIRE] as const),
])
/** Canonical terminal-contract kind (`oracle-spec.ts`) → primitive; the class taxonomy lives in ONE place. */
const CONTRACT_PRIMITIVE: ReadonlyMap<string, UniversalEvidencePrimitive> = new Map([
  ['access_control', P_ACCESS], ['v8_dual_tenant', P_ACCESS], ['v8_temporal', P_ACCESS], ['v8_crypto', P_ACCESS],
  ['v8_economic', P_STATE], ['v8_parser_cache', P_WIRE], ['v8_pivot', P_DAG],
  ['browser', P_WITNESS], ['injection_or_redirect', P_WITNESS], ['oob', P_WITNESS],
])
const AUTH_BOUNDARY_CLASS_RE = /^(?:auth_bypass|authentication_bypass|broken_auth|auth_protocol|jwt|jwt_forgery|token_forgery|oauth|sso|session_fixation|stale_privilege_use)$/

/**
 * Resolve any legacy family name, sub-mode, equation, canonical vuln class, or primitive name to its
 * universal evidence primitive. Unknown labels fall back to `causal_dag` (generic host assertions over
 * the signed transcript DAG), never to a weaker primitive.
 */
export function resolveUniversalPrimitive(vulnClassOrFamily: string): UniversalEvidencePrimitive {
  const norm = typeof vulnClassOrFamily === 'string' ? vulnClassOrFamily.trim().toLowerCase().replace(/[\s-]+/g, '_') : ''
  if (!norm) return P_DAG
  if (UNIVERSAL_PRIMITIVE_SET.has(norm)) return norm as UniversalEvidencePrimitive
  const alias = LEGACY_PRIMITIVE_ALIASES.get(norm); if (alias) return alias
  const contract = resolveTerminalContractKind(norm) ?? resolveTerminalContractKind(vulnClassOrFamily.trim().toLowerCase())
  if (contract === 'auth_or_logic') return AUTH_BOUNDARY_CLASS_RE.test(norm) ? P_ACCESS : P_STATE
  return (contract && CONTRACT_PRIMITIVE.get(contract)) || P_DAG
}

export interface UniversalPrimitiveDecision extends ImpactAssessment { primitive: UniversalEvidencePrimitive; subRule?: string }
const pOk = (primitive: UniversalEvidencePrimitive, subRule: string | undefined, reason: string, evidence: Record<string, unknown>): UniversalPrimitiveDecision => ({ primitive, subRule, required: true, satisfied: true, reason, evidence })
const pDeny = (primitive: UniversalEvidencePrimitive, reason: string, subRule?: string, evidence?: Record<string, unknown>): UniversalPrimitiveDecision => ({ primitive, subRule, required: true, satisfied: false, reason, evidence })
const primitiveOf = (family: V8OracleFamily, subRule?: string): UniversalEvidencePrimitive => (subRule && LEGACY_PRIMITIVE_ALIASES.get(subRule)) || resolveUniversalPrimitive(family)
const ok = (family: V8OracleFamily, subRule: string, reason: string, evidence: Record<string, unknown>): V8OracleDecision => ({ family, primitive: primitiveOf(family, subRule), subRule, required: true, satisfied: true, reason, evidence })
const deny = (family: V8OracleFamily, reason: string, subRule?: string, evidence?: Record<string, unknown>): V8OracleDecision => ({ family, primitive: primitiveOf(family, subRule), subRule, required: true, satisfied: false, reason, evidence })
/** Thin adapter: re-label a denied primitive decision with the legacy family + reason vocabulary. */
const denyVia = (family: V8OracleFamily, d: UniversalPrimitiveDecision, reasons: Readonly<Record<string, string>>, subRule?: string): V8OracleDecision => deny(family, reasons[d.reason] ?? d.reason, subRule, d.evidence)
const isReadMethodStr = (m: string | null | undefined): boolean => /^(?:GET|HEAD|OPTIONS)$/i.test(normStr(m))
const tsOf = (r: HostSignedRecord): number => r.timestampMs

const MASKED_VALUE_RE = /^(?:[*•]{3,}[\s\S]{0,8}|[xX]{4,}[\s\S]{0,8}|[\s\S]{0,24}[*•]{3,}[\s\S]{0,8}|\[(?:redacted|masked|hidden|filtered)\]|<(?:redacted|masked|hidden)>|redacted|masked|hidden)$/i
/** Masked-read guard: every substantive string leaf is masked (`***`, `[redacted]`, ...) and no numeric data leaks. */
export function isMaskedReadPayload(json: unknown, body?: string): boolean {
  let masked = 0, clear = 0
  const walk = (v: unknown, k: string, d: number): void => {
    if (d > 5 || v == null || clear > 0) return
    if (Array.isArray(v)) { for (const x of v.slice(0, 64)) walk(x, k, d + 1); return }
    if (typeof v === 'object') { for (const [ck, cv] of Object.entries(v as Record<string, unknown>)) walk(cv, ck, d + 1); return }
    if (ID_KEY_RE.test(k) || META_KEY_RE.test(k) || SCOPE_KEY_RE.test(k) || TENANT_MARKER_KEYS.has(k.toLowerCase())) return
    if (typeof v === 'string') { if (MASKED_VALUE_RE.test(v.trim())) masked += 1; else if (v.trim()) clear += 1 }
    else if (typeof v === 'number' && !isMetaNum(k, v)) clear += 1
  }
  walk(parseJsonOrBody(json, body), '', 0)
  return masked > 0 && clear === 0
}

/* ── Primitive 1: causal_dag ── multi-step data/capability/time lineage over signed exchanges. */
export interface CausalDagHop { hopId: string; surface: V8SurfaceKind | string; record: HostSignedRecord }
export interface CausalDagEdge {
  kind: CausalBindingKind; fromHopId: string; toHopId: string
  /** Host-observed binding value (emitted capability / entity / correlation token). */
  boundValue?: string | null
  /** Set ONLY by host edge verification (`CompositeProofReceipt`), never from worker input. */
  hostVerified?: boolean
  /** state_transition_binding ablation: the dependent hop replayed without the mutation is denied. */
  ablationControl?: HostSignedRecord
}
export interface CausalDagInput extends WithVerifier { hops: readonly CausalDagHop[]; edges: readonly CausalDagEdge[]; terminalHopId: string; requireCrossSurface?: boolean }
/** Cross-surface is simply `surfaces.size >= 2` over the DAG (no parallel pivot verifier). */
export const distinctSurfaceCount = (surfaces: Iterable<string | null | undefined>): number => new Set([...surfaces].map(s => normKey(s)).filter(Boolean)).size
const MIN_BOUND_VALUE_LEN = 6
function recordResponseText(r: HostSignedRecord): string {
  const parsed = parseJsonOrBody(r.json, r.body)
  try { return `${parsed !== undefined ? JSON.stringify(parsed) : ''}\n${r.body ?? ''}\n${r.capabilityHandle ?? ''}\n${r.artifactDigest ?? ''}` } catch { return `${r.body ?? ''}` }
}
const recordRequestText = (r: HostSignedRecord): string => `${r.pathAndQuery ?? r.route ?? ''}\n${Object.values(r.requestHeaders ?? {}).join('\n')}\n${r.derivedFromCapabilityId ?? ''}\n${r.capabilityHandle ?? ''}`
function edgeBindingError(e: CausalDagEdge, from: HostSignedRecord, to: HostSignedRecord, verify?: SignatureVerifier): string | null {
  if (tsOf(to) < tsOf(from)) return 'non_monotonic_causal_edge'
  if (e.hostVerified === true) return null
  const v = normStr(e.boundValue)
  if (v.length < MIN_BOUND_VALUE_LEN) return 'unbound_causal_edge'
  if (e.kind === 'derived_crypto_binding') return normStr(to.derivedFromCapabilityId) === v && recordResponseText(from).includes(v) ? null : 'unbound_derived_crypto_edge'
  if (e.kind === 'state_transition_binding') {
    if (!isOk(from.status) || isReadMethodStr(from.method)) return 'state_transition_requires_mutation'
    const abl = e.ablationControl, ablErr = checkRecord(abl, 'ablation_control', verify)
    if (ablErr) return ablErr
    if (abl!.id === from.id || abl!.id === to.id) return 'ablation_control_reuses_hop_exchange'
    if (!isDenied(abl!.status) && abl!.status !== 404) return 'ablation_control_not_denied'
    const aRt = normRoute(abl!.route), tRt = normRoute(to.route)
    if (aRt && tRt && aRt !== tRt) return 'ablation_control_route_mismatch'
    return `${recordRequestText(from)}\n${recordResponseText(from)}`.includes(v) && `${recordRequestText(to)}\n${recordResponseText(to)}`.includes(v) ? null : 'unbound_state_transition_edge'
  }
  // value_binding / async_pivot_binding: emitted by `from` (response) and consumed by `to` (request).
  return recordResponseText(from).includes(v) && (recordRequestText(to).includes(v) || (e.kind === 'async_pivot_binding' && recordResponseText(to).includes(v))) ? null : 'unbound_causal_edge'
}
export function evaluateCausalDag(input: CausalDagInput): UniversalPrimitiveDecision {
  const hops = Array.isArray(input?.hops) ? input.hops : [], edges = Array.isArray(input?.edges) ? input.edges : []
  if (hops.length < 2) return pDeny(P_DAG, 'invalid_hop_count')
  const byId = new Map<string, CausalDagHop>(), seenRecs = new Set<string>()
  for (const h of hops) { const id = normStr(h?.hopId); if (!id || byId.has(id)) return pDeny(P_DAG, 'duplicate_or_empty_hop_id'); byId.set(id, h) }
  const recErr = checkRecords(hops.map(h => [h.record, `hop_${h.hopId}`] as [HostSignedRecord, string]), input.verifySignature); if (recErr) return pDeny(P_DAG, recErr)
  for (const h of hops) { if (seenRecs.has(h.record.id)) return pDeny(P_DAG, 'duplicate_hop_exchange_id', undefined, { hopId: h.hopId, exchangeId: h.record.id }); seenRecs.add(h.record.id) }
  const term = byId.get(normStr(input.terminalHopId)); if (!term) return pDeny(P_DAG, 'missing_terminal_hop')
  const inAdj = new Map<string, string[]>(), outAdj = new Map<string, string[]>(), inDeg = new Map<string, number>(hops.map(h => [h.hopId, 0]))
  for (const e of edges) {
    const from = byId.get(normStr(e?.fromHopId)), to = byId.get(normStr(e?.toHopId))
    if (!from || !to || from === to) return pDeny(P_DAG, 'edge_references_unknown_hop')
    const err = edgeBindingError(e, from.record, to.record, input.verifySignature); if (err) return pDeny(P_DAG, err, e.kind, { fromHopId: from.hopId, toHopId: to.hopId })
    inAdj.set(to.hopId, [...(inAdj.get(to.hopId) ?? []), from.hopId]); outAdj.set(from.hopId, [...(outAdj.get(from.hopId) ?? []), to.hopId]); inDeg.set(to.hopId, (inDeg.get(to.hopId) ?? 0) + 1)
  }
  const topoQ = [...inDeg.entries()].filter(([, d]) => d === 0).map(([id]) => id); let visited = 0
  for (let i = 0; i < topoQ.length; i++) { visited += 1; for (const nxt of outAdj.get(topoQ[i]!) ?? []) { const d = (inDeg.get(nxt) ?? 0) - 1; inDeg.set(nxt, d); if (d === 0) topoQ.push(nxt) } }
  if (visited !== hops.length) return pDeny(P_DAG, 'causal_dag_cycle_detected')
  const reach = new Set<string>([term.hopId]), q = [term.hopId]
  for (let i = 0; i < q.length; i++) for (const p of inAdj.get(q[i]!) ?? []) if (!reach.has(p)) { reach.add(p); q.push(p) }
  const orphan = hops.find(h => !reach.has(h.hopId)); if (orphan) return pDeny(P_DAG, 'hop_does_not_reach_terminal', undefined, { hopId: orphan.hopId })
  if (!isOk(term.record.status)) return pDeny(P_DAG, 'terminal_hop_not_accepted')
  if (stubRec(term.record)) return pDeny(P_DAG, 'terminal_impact_unproven_intermediate_stub')
  const surfaceCount = distinctSurfaceCount(hops.map(h => h.surface))
  if (input.requireCrossSurface && surfaceCount < 2) return pDeny(P_DAG, 'single_surface_not_cross_surface_pivot')
  return pOk(P_DAG, surfaceCount >= 2 ? 'cross_surface' : 'single_surface', 'causal_dag_lineage_verified', { hopCount: hops.length, edgeCount: edges.length, surfaceCount, crossSurface: surfaceCount >= 2, terminalHopId: term.hopId })
}

/* ── Primitive 2: access_differential ── denied clean control vs. succeeding variant + Principal provenance. */
export interface AccessPrincipalScope { actor: DualTenantActor; inScopeTenant: string; outOfScopeTenant: string; requiredInScopeRole?: RoleName; requiredOutOfScopeRole?: RoleName }
/** Host-verified Principal provenance: member of the in-scope tenant, NOT authorized in the out-of-scope tenant. */
export function checkPrincipalScope(s: AccessPrincipalScope): string | null {
  if (!s?.actor || !normStr(s.actor.actorId)) return 'missing_actor_identity'
  const inS = normKey(s.inScopeTenant), out = normKey(s.outOfScopeTenant)
  if (!inS || !out) return 'missing_tenant_scope'
  if (inS === out) return 'same_tenant_not_cross_tenant'
  if (!hasTenantRoleAtLeast(s.actor, inS, s.requiredInScopeRole ?? 'member')) return 'principal_lacks_in_scope_role'
  return hasTenantRoleAtLeast(s.actor, out, s.requiredOutOfScopeRole ?? s.requiredInScopeRole ?? 'member') ? 'principal_authorized_out_of_scope' : null
}
export interface AccessDifferentialInput extends WithVerifier {
  /** Clean baseline control: the same (or single-item) operation denied (`401`/`403`) for the probe principal. */
  control: HostSignedRecord
  /** Variant: the same / batched / replayed operation succeeding (`2xx`) via the probe or chain. */
  variant: HostSignedRecord
  /** Post-variant readback; persisted impact additionally requires host-derived `persistedDelta === true`. */
  readback?: HostSignedRecord; persistedDelta?: boolean; requireReadback?: boolean
  scope?: AccessPrincipalScope
  /** Principal the control/variant must be bound to (`401` controls must be this authenticated principal). */
  principalActorId?: string | null
  /** `same_actor` (default): a 401 control proves nothing unless it is the same authenticated principal. */
  controlPrincipal?: 'same_actor' | 'any'
  /** Host-derived protected record ID returned (non-error) by the variant, outside baseline scope. */
  protectedRecordId?: string; protectedRecordReturned?: boolean; protectedDataObserved?: boolean
  /** Own-tenant guard: a variant exposing ONLY these tenants is an own-tenant (benign) read. */
  ownTenants?: readonly string[]
  bindRoute?: boolean; requireChronology?: boolean; requireMutatingVariant?: boolean; isolatedControl?: boolean
  labels?: { control?: string; variant?: string; readback?: string }
}
function accessReadImpactError(input: AccessDifferentialInput): string | null {
  const v = input.variant
  if (stubRec(v)) return 'terminal_impact_unproven_intermediate_stub'
  const pid = normStr(input.protectedRecordId)
  if (pid && (input.protectedRecordReturned !== true || (parseJsonOrBody(v.json, v.body) !== undefined && findNonErrorBatchRecord(v.json, v.body, pid) === null))) return 'protected_data_not_returned_or_mutated'
  if (input.protectedDataObserved !== true && !hasSubstantivePayload(v)) return 'protected_data_not_returned_or_mutated'
  const own = new Set((input.ownTenants ?? []).map(normKey).filter(Boolean)), markers = extractTenantMarkers(v.json, v.body, true)
  if (own.size > 0 && markers.size > 0 && [...markers].every(m => own.has(m))) return 'own_tenant_only_response'
  return isMaskedReadPayload(v.json, v.body) ? 'masked_read_without_protected_data' : null
}
export function evaluateAccessDifferential(input: AccessDifferentialInput): UniversalPrimitiveDecision {
  if (!input) return pDeny(P_ACCESS, 'missing_input')
  const lc = input.labels?.control ?? 'control', lv = input.labels?.variant ?? 'variant', lr = input.labels?.readback ?? 'readback'
  if (input.scope) { const err = checkPrincipalScope(input.scope); if (err) return pDeny(P_ACCESS, err) }
  const pairs: [HostSignedRecord | undefined, string][] = [[input.control, lc], [input.variant, lv]]; if (input.requireReadback) pairs.push([input.readback, lr])
  const recErr = checkRecords(pairs, input.verifySignature); if (recErr) return pDeny(P_ACCESS, recErr)
  const { control: c, variant: v } = input, rb = input.readback
  if (!isDenied(c.status)) return pDeny(P_ACCESS, 'control_not_denied')
  if (!isOk(v.status) || (input.requireMutatingVariant && isReadMethodStr(v.method))) return pDeny(P_ACCESS, 'variant_rejected')
  if (c.id === v.id) return pDeny(P_ACCESS, 'control_reuses_variant_exchange')
  if (input.requireReadback && (!isOk(rb!.status) || rb!.id === v.id)) return pDeny(P_ACCESS, 'readback_not_accepted')
  const principal = normKey(input.principalActorId ?? input.scope?.actor.actorId), cAct = normKey(c.actorId), vAct = normKey(v.actorId)
  if (principal && ((vAct && vAct !== principal) || (cAct && cAct !== principal))) return pDeny(P_ACCESS, 'actor_record_mismatch')
  const ref = principal || vAct
  if ((input.controlPrincipal ?? 'same_actor') === 'same_actor' && c.status === 401 && (!cAct || !ref || cAct !== ref)) return pDeny(P_ACCESS, 'unauthenticated_baseline_control')
  if (input.bindRoute) { const cRt = normRoute(c.route), vRt = normRoute(v.route); if (cRt && vRt && cRt !== vRt) return pDeny(P_ACCESS, 'control_and_variant_route_mismatch') }
  if (input.requireChronology && !input.isolatedControl && tsOf(v) < tsOf(c)) return pDeny(P_ACCESS, 'variant_precedes_control')
  let mutation = false
  if (rb) {
    if (!input.requireReadback) { const err = checkRecord(rb, lr, input.verifySignature); if (err) return pDeny(P_ACCESS, err) }
    if (rb.id === v.id || rb.id === c.id) return pDeny(P_ACCESS, input.requireReadback ? 'readback_not_accepted' : 'readback_reuses_probe_exchange')
    if (stubRec(rb)) return pDeny(P_ACCESS, 'terminal_impact_unproven_intermediate_stub')
    if (input.requireReadback && tsOf(rb) < tsOf(v)) return pDeny(P_ACCESS, 'non_monotonic_readback_timestamp')
    mutation = isOk(rb.status) && tsOf(rb) >= tsOf(v) && input.persistedDelta === true
  }
  if (input.requireReadback && !mutation) return pDeny(P_ACCESS, 'mutation_not_persisted')
  const readErr = mutation ? null : accessReadImpactError(input)
  if (readErr) return pDeny(P_ACCESS, readErr)
  return pOk(P_ACCESS, mutation ? 'mutation' : 'read', 'access_boundary_crossed', { controlId: c.id, variantId: v.id, ...(rb ? { readbackId: rb.id } : {}), impactMode: mutation ? 'mutation' : 'read' })
}

/* ── Primitive 3: state_delta_and_conservation ── persisted mutation + control-calibrated numeric invariant. */
export interface StateDeltaConservationInput extends WithVerifier {
  baselineReadback: HostSignedRecord; actions: readonly HostSignedRecord[]; finalReadback: HostSignedRecord; tolerance?: number
  /** Explicit host-evaluated JSONPath selector `$Q` over baseline/final readbacks (e.g. `$.balance`, `$.seatsUsed`). */
  quantitySelector?: string
  /** Host-derived quantity operands (used when no selector is given). */
  quantityBefore?: number; quantityAfter?: number
  /** Maximum authorized increase of `$Q` over the window. */
  authorizedDelta?: number
  /** `$Q` delta observed when the same actions replay serially (benign control calibration). */
  controlDelta?: number
  /** Generic `before !== after` structural-diff mode (no numeric invariant). */
  structuralOnly?: boolean
}
const JSONPATH_TOKEN_RE = /\.([A-Za-z_$][\w$-]*)|\[(\d+)\]|\[['"]([^'"\]]+)['"]\]/g
/** Minimal deterministic JSONPath (`$`, `.key`, `['key']`, `[n]`) evaluated host-side; never evals worker code. */
export function evaluateJsonPathNumber(root: unknown, selector: string | null | undefined): number | undefined {
  const sel = normStr(selector); if (!sel.startsWith('$') || sel.length > 256) return undefined
  let cur: unknown = root, consumed = 1
  for (const m of sel.slice(1).matchAll(JSONPATH_TOKEN_RE)) {
    if (m.index !== consumed - 1) return undefined
    consumed += m[0].length
    const key = m[1] ?? m[3], idx = m[2]
    if (key !== undefined) { if (key === '__proto__' || key === 'constructor' || key === 'prototype' || !cur || typeof cur !== 'object' || Array.isArray(cur) || !Object.hasOwn(cur, key)) return undefined; cur = (cur as Record<string, unknown>)[key] }
    else { if (!Array.isArray(cur)) return undefined; cur = cur[Number(idx)] }
  }
  return consumed === sel.length && typeof cur === 'number' && Number.isFinite(cur) ? cur : undefined
}
/** Shared conservation window: signed baseline/final reads on one resource bracketing >= 1 succeeding mutating action. */
function checkConservationWindow(input: Pick<StateDeltaConservationInput, 'baselineReadback' | 'finalReadback' | 'actions' | 'verifySignature' | 'tolerance'>): string | null {
  const recErr = checkRecords([[input.baselineReadback, 'baseline_readback'], [input.finalReadback, 'final_readback']], input.verifySignature); if (recErr) return recErr
  const b = input.baselineReadback, f = input.finalReadback
  if (!Array.isArray(input.actions) || input.actions.length === 0) return 'missing_action_records'
  if (!isOk(b.status)) return 'baseline_readback_failed'
  if (!isOk(f.status)) return 'final_readback_failed'
  if (b.id === f.id) return 'baseline_and_final_same_exchange'
  if (b.method && !/^(?:GET|HEAD)$/i.test(normStr(b.method))) return 'baseline_readback_not_read'
  if (f.method && !/^(?:GET|HEAD)$/i.test(normStr(f.method))) return 'final_readback_not_read'
  const bRoute = normRoute(b.route), fRoute = normRoute(f.route); if (bRoute && fRoute && bRoute !== fRoute) return 'baseline_and_final_route_mismatch'
  const bAct = normKey(b.actorId), fAct = normKey(f.actorId); if (bAct && fAct && bAct !== fAct) return 'baseline_and_final_actor_mismatch'
  if (tsOf(f) <= tsOf(b)) return 'non_monotonic_baseline_final_timestamp'
  let maxActionTs = -Infinity, anyActionOk = false
  const seen = new Set<string>()
  for (let i = 0; i < input.actions.length; i++) {
    const act = input.actions[i]!, err = checkRecord(act, `action_${i}`, input.verifySignature); if (err) return err
    if (act.id === b.id || act.id === f.id) return 'action_reuses_readback_exchange'
    if (act.method && isReadMethodStr(act.method)) return 'action_not_mutating'
    if (seen.has(act.id)) return 'duplicate_action_exchange_id'
    seen.add(act.id)
    if (tsOf(act) < tsOf(b)) return 'action_precedes_baseline_readback'
    maxActionTs = Math.max(maxActionTs, tsOf(act)); anyActionOk ||= isOk(act.status)
  }
  if (!anyActionOk) return 'no_successful_action'
  if (tsOf(f) < maxActionTs) return 'final_readback_precedes_actions'
  return allFiniteNonNeg(input.tolerance ?? DEFAULT_TOL) ? null : 'invalid_tolerance'
}
/** Core quantitative invariant: violated iff `after - before` exceeds EVERY supplied ceiling by more than `tol`. */
export function evaluateQuantityInvariant(before: number, after: number, ceilings: readonly (number | undefined)[], tol = DEFAULT_TOL): { violated: boolean; observedDelta: number; ceiling: number } | null {
  const cs = ceilings.filter((c): c is number => typeof c === 'number' && Number.isFinite(c))
  if (!Number.isFinite(before) || !Number.isFinite(after) || cs.length === 0) return null
  const observedDelta = after - before, ceiling = Math.max(...cs)
  return { violated: observedDelta > ceiling + tol, observedDelta: Number(observedDelta.toFixed(6)), ceiling }
}
export function evaluateStateDeltaAndConservation(input: StateDeltaConservationInput): UniversalPrimitiveDecision {
  if (!input) return pDeny(P_STATE, 'missing_input')
  const winErr = checkConservationWindow(input); if (winErr) return pDeny(P_STATE, winErr)
  const b = input.baselineReadback, f = input.finalReadback, tol = input.tolerance ?? DEFAULT_TOL
  if (input.structuralOnly) {
    if (stubRec(f)) return pDeny(P_STATE, 'terminal_impact_unproven_intermediate_stub')
    return readbackStateFingerprint(b.json, b.body) === readbackStateFingerprint(f.json, f.body) ? pDeny(P_STATE, 'zero_state_delta', 'structural_delta') : pOk(P_STATE, 'structural_delta', 'persisted_state_delta_observed', { baselineId: b.id, finalReadbackId: f.id })
  }
  const sel = normStr(input.quantitySelector)
  const before = sel ? evaluateJsonPathNumber(parseJsonOrBody(b.json, b.body), sel) : input.quantityBefore
  const after = sel ? evaluateJsonPathNumber(parseJsonOrBody(f.json, f.body), sel) : input.quantityAfter
  if (typeof before !== 'number' || typeof after !== 'number') return pDeny(P_STATE, 'missing_conservation_quantity', 'quantity_conservation', sel ? { quantitySelector: sel } : undefined)
  const inv = evaluateQuantityInvariant(before, after, [input.authorizedDelta, input.controlDelta], tol)
  if (!inv) return pDeny(P_STATE, 'missing_authorized_delta_or_benign_control', 'quantity_conservation')
  const evidence = { ...(sel ? { quantitySelector: sel } : {}), quantityBefore: before, quantityAfter: after, observedDelta: inv.observedDelta, ceiling: inv.ceiling, baselineId: b.id, finalReadbackId: f.id }
  return inv.violated ? pOk(P_STATE, 'quantity_conservation', 'conservation_violated', { ...evidence, excess: Number((inv.observedDelta - inv.ceiling).toFixed(6)) }) : pDeny(P_STATE, 'quantity_conserved', 'quantity_conservation', evidence)
}

/* ── Primitive 4: wire_framing_and_cache_differential ── same resource, differing strictly in a wire property. */
const WIRE_DIFF_PROPERTIES = ['signature_validity', 'signature_scope', 'duplicate_json_key', 'path_normalization', 'header_normalization', 'hop_by_hop_smuggling', 'content_type_confusion', 'cache_priming'] as const
export type WireDifferentialProperty = (typeof WIRE_DIFF_PROPERTIES)[number]
const WIRE_DIFF_PROPERTY_SET: ReadonlySet<string> = new Set(WIRE_DIFF_PROPERTIES)
export interface WireFramingCacheDifferentialInput extends WithVerifier {
  property: WireDifferentialProperty
  /** Clean control on the same logical resource: denied, or (cache) lacking the victim digest. */
  control: HostSignedRecord
  /** Variant: differs strictly in `property`; must succeed (`2xx`). */
  variant: HostSignedRecord
  /** Host-observed wire values of `property` on control vs. variant (must differ; not used for cache priming). */
  controlWireValue?: string; variantWireValue?: string
  /** Cache priming: the victim / priming exchange and the victim artifact digest or victim tenant. */
  prime?: HostSignedRecord; victimDigest?: string; victimTenant?: string; primeTenant?: string; observedTenant?: string; targetRecordId?: string
  controlContainsVictimData?: boolean; requireDistinctPrincipals?: boolean; principalActorId?: string | null
  /** Mutation impact: host-derived persisted readback delta. */
  impactKind?: 'read' | 'mutation'; readback?: HostSignedRecord; persistedDelta?: boolean; unauthorizedDigest?: string
  isolatedControl?: boolean; bindActor?: boolean
  labels?: { control?: string; variant?: string; prime?: string; readback?: string }
}
function wireControlError(input: WireFramingCacheDifferentialInput): string | null {
  const c = input.control, victim = normStr(input.victimDigest)
  if (isDenied(c.status)) return null
  if (input.property !== 'cache_priming' || !victim) return 'control_not_denied'
  if (input.controlContainsVictimData === true || normStr(c.artifactDigest) === victim) return 'resource_already_exposed_in_clean_control'
  return isOk(c.status) || c.status === 404 ? null : 'invalid_clean_control_status'
}
function wireBindingError(input: WireFramingCacheDifferentialInput): string | null {
  const c = input.control, v = input.variant, p = input.prime
  if (c.id === v.id || (p && (p.id === c.id || p.id === v.id))) return 'wire_differential_reuses_exchange_id'
  const cMeth = normKey(c.method), vMeth = normKey(v.method); if (cMeth && vMeth && cMeth !== vMeth) return 'control_and_variant_method_mismatch'
  const cAct = normKey(c.actorId), vAct = normKey(v.actorId); if (input.bindActor && cAct !== vAct && (cAct || vAct)) return 'control_and_variant_actor_mismatch'
  const cRt = normRoute(c.route), vRt = normRoute(v.route); if (input.property !== 'path_normalization' && cRt && vRt && cRt !== vRt) return 'control_and_variant_route_mismatch'
  const refActor = normKey(input.principalActorId) || vAct; if (c.status === 401 && refActor && cAct !== refActor) return 'unauthenticated_baseline_control'
  if (!input.isolatedControl && tsOf(p ?? v) < tsOf(c)) return p ? 'prime_precedes_control' : 'variant_precedes_control'
  if (p && tsOf(v) < tsOf(p)) return 'variant_precedes_prime'
  if (input.requireDistinctPrincipals && p) {
    const pa = normKey(p.actorId), va = normKey(v.actorId), pt = normKey(p.tenantId), vt = normKey(v.tenantId)
    const sameActor = Boolean(pa && va && pa === va), sameTenant = Boolean(pt && vt && pt === vt)
    if ((!pa && !pt) || (sameActor && (sameTenant || (!pt && !vt)))) return 'principals_not_distinct'
  }
  return null
}
function wireImpactError(input: WireFramingCacheDifferentialInput): string | null {
  const c = input.control, v = input.variant
  if (input.impactKind === 'mutation') {
    const rb = input.readback, err = checkRecord(rb, input.labels?.readback ?? 'readback', input.verifySignature); if (err) return err
    if (rb!.id === v.id || rb!.id === c.id) return 'readback_reuses_probe_exchange'
    if (!isOk(rb!.status)) return 'readback_failed'
    if (tsOf(rb!) < tsOf(v)) return 'readback_precedes_variant'
    if (stubRec(rb!)) return 'terminal_impact_unproven_intermediate_stub'
    return input.persistedDelta === true ? null : 'mutation_not_persisted'
  }
  const vt = normKey(input.victimTenant), obs = normKey(input.observedTenant)
  if (vt && obs && obs !== vt) return 'observed_tenant_mismatch'
  if (stubRec(v)) return 'terminal_impact_unproven_intermediate_stub'
  const victim = normStr(input.victimDigest)
  if (victim) return normStr(v.artifactDigest) === victim ? null : 'variant_did_not_receive_victim_artifact'
  if (vt) {
    const markers = extractTenantMarkers(v.json, v.body), prime = normKey(input.primeTenant)
    if (markers.size > 0 && prime && markers.has(prime) && !markers.has(vt)) return 'variant_own_tenant_only'
    if (!markers.has(vt) && obs !== vt) return 'variant_missing_victim_tenant_marker'
    return !normStr(input.targetRecordId) && !hasSubstantivePayload(v) ? 'variant_missing_substantive_data' : null
  }
  const probeDigest = normStr(input.unauthorizedDigest ?? v.artifactDigest), ctrlDigest = normStr(c.artifactDigest)
  if (probeDigest && ctrlDigest && probeDigest === ctrlDigest) return 'variant_artifact_already_in_control'
  return !probeDigest && !hasSubstantivePayload(v) ? 'differential_read_missing_substantive_data' : null
}
/** Victim-matched digest (no brittle `X-Cache: HIT` header requirement) or persisted delta, with control ablation. */
export function evaluateWireFramingAndCacheDifferential(input: WireFramingCacheDifferentialInput): UniversalPrimitiveDecision {
  if (!input || !WIRE_DIFF_PROPERTY_SET.has(normStr(input.property))) return pDeny(P_WIRE, 'missing_wire_property')
  const sub = input.property, cache = sub === 'cache_priming'
  if (!cache && (input.controlWireValue === undefined || input.variantWireValue === undefined || input.controlWireValue === input.variantWireValue)) return pDeny(P_WIRE, 'no_wire_differential_between_control_and_variant', sub)
  const pairs: [HostSignedRecord | undefined, string][] = [[input.control, input.labels?.control ?? 'control']]
  if (cache) pairs.push([input.prime, input.labels?.prime ?? 'prime'])
  pairs.push([input.variant, input.labels?.variant ?? 'variant'])
  const recErr = checkRecords(pairs, input.verifySignature); if (recErr) return pDeny(P_WIRE, recErr, sub)
  const ctrlErr = wireControlError(input); if (ctrlErr) return pDeny(P_WIRE, ctrlErr, sub)
  if (input.prime && !isOk(input.prime.status)) return pDeny(P_WIRE, 'prime_failed', sub)
  if (!isOk(input.variant.status)) return pDeny(P_WIRE, 'variant_rejected', sub)
  const err = wireBindingError(input) ?? wireImpactError(input); if (err) return pDeny(P_WIRE, err, sub)
  return pOk(P_WIRE, sub, 'wire_differential_confirmed', { property: sub, controlId: input.control.id, variantId: input.variant.id, ...(input.prime ? { primeId: input.prime.id } : {}), impactKind: input.impactKind ?? 'read' })
}

/* ── Primitive 5: oob_and_execution_witness ── host-minted canary observed on an independent witness channel. */
const EXECUTION_WITNESS_KINDS = ['oob_callback', 'dom_sentinel', 'redirect_canary', 'host_evaluated_expression', 'server_side_effect'] as const
export type ExecutionWitnessKind = (typeof EXECUTION_WITNESS_KINDS)[number]
const EXECUTION_WITNESS_KIND_SET: ReadonlySet<string> = new Set(EXECUTION_WITNESS_KINDS)
export interface OobExecutionWitnessInput extends WithVerifier {
  kind: ExecutionWitnessKind
  /** Probe exchange that planted the host-minted canary. */
  trigger: HostSignedRecord
  /** Host-observed witness (OOB hit, DOM trace, redirect response, evaluation response, side-effect readback). */
  witness: HostSignedRecord
  hostCanary: string; observedCanary?: string | null
  /** Optional benign control that must NOT exhibit the witness. */
  control?: HostSignedRecord; controlObservedCanary?: string | null
  /** host_evaluated_expression: host-computed expected value of the injected expression. */
  expectedValue?: string
}
const MIN_CANARY_LEN = 8
function isExternalRedirectToCanary(headers: Readonly<Record<string, string>> | null | undefined, canary: string): boolean {
  const loc = Object.entries(headers ?? {}).find(([k]) => k.toLowerCase() === 'location')?.[1]?.trim() ?? ''
  if (!loc || (!/^https?:\/\//i.test(loc) && !loc.startsWith('//'))) return false
  try { const u = new URL(loc.startsWith('//') ? `https:${loc}` : loc); return u.hostname.toLowerCase().includes(canary.toLowerCase()) } catch { return false }
}
function witnessObservedError(input: OobExecutionWitnessInput, canary: string): string | null {
  const w = input.witness
  if (input.kind === 'redirect_canary') {
    return isRedirect(w.status) && (normStr(input.observedCanary) === canary || isExternalRedirectToCanary(w.responseHeaders, canary)) ? null : 'redirect_canary_not_observed'
  }
  if (input.kind === 'host_evaluated_expression') {
    const exp = normStr(input.expectedValue); if (!exp || exp === canary) return 'missing_host_expected_value'
    if (recordRequestText(input.trigger).includes(exp)) return 'expected_value_reflected_from_request'
    return recordResponseText(w).includes(exp) ? null : 'expected_value_not_observed'
  }
  return normStr(input.observedCanary) === canary ? null : 'canary_not_observed'
}
export function evaluateOobAndExecutionWitness(input: OobExecutionWitnessInput): UniversalPrimitiveDecision {
  if (!input || !EXECUTION_WITNESS_KIND_SET.has(normStr(input.kind))) return pDeny(P_WITNESS, 'missing_witness_kind')
  const sub = input.kind, canary = normStr(input.hostCanary)
  if (canary.length < MIN_CANARY_LEN) return pDeny(P_WITNESS, 'weak_or_missing_host_canary', sub)
  const pairs: [HostSignedRecord | undefined, string][] = [[input.trigger, 'trigger'], [input.witness, 'witness']]; if (input.control) pairs.push([input.control, 'control'])
  const recErr = checkRecords(pairs, input.verifySignature); if (recErr) return pDeny(P_WITNESS, recErr, sub)
  const sameRecordOk = sub === 'redirect_canary' || sub === 'host_evaluated_expression'
  if (!sameRecordOk && input.trigger.id === input.witness.id) return pDeny(P_WITNESS, 'witness_reuses_trigger_exchange', sub)
  if (tsOf(input.witness) < tsOf(input.trigger)) return pDeny(P_WITNESS, 'witness_precedes_trigger', sub)
  const obsErr = witnessObservedError(input, canary); if (obsErr) return pDeny(P_WITNESS, obsErr, sub)
  if (input.control) {
    if (input.control.id === input.witness.id || input.control.id === input.trigger.id) return pDeny(P_WITNESS, 'control_reuses_probe_exchange', sub)
    if (normStr(input.controlObservedCanary) === canary || (sub === 'redirect_canary' && isRedirect(input.control.status) && isExternalRedirectToCanary(input.control.responseHeaders, canary))) return pDeny(P_WITNESS, 'witness_present_in_control', sub)
    const exp = normStr(input.expectedValue); if (sub === 'host_evaluated_expression' && exp && recordResponseText(input.control).includes(exp)) return pDeny(P_WITNESS, 'expected_value_present_in_control', sub)
  }
  return pOk(P_WITNESS, sub, 'execution_witness_observed', { kind: sub, triggerId: input.trigger.id, witnessId: input.witness.id, ...(input.control ? { controlId: input.control.id } : {}) })
}

export interface UniversalPrimitiveInputMap {
  causal_dag: CausalDagInput; access_differential: AccessDifferentialInput; state_delta_and_conservation: StateDeltaConservationInput
  wire_framing_and_cache_differential: WireFramingCacheDifferentialInput; oob_and_execution_witness: OobExecutionWitnessInput
}
export function evaluateUniversalPrimitive<P extends UniversalEvidencePrimitive>(primitive: P, input: UniversalPrimitiveInputMap[P]): UniversalPrimitiveDecision {
  switch (primitive) {
    case 'causal_dag': return evaluateCausalDag(input as CausalDagInput)
    case 'access_differential': return evaluateAccessDifferential(input as AccessDifferentialInput)
    case 'state_delta_and_conservation': return evaluateStateDeltaAndConservation(input as StateDeltaConservationInput)
    case 'wire_framing_and_cache_differential': return evaluateWireFramingAndCacheDifferential(input as WireFramingCacheDifferentialInput)
    case 'oob_and_execution_witness': return evaluateOobAndExecutionWitness(input as OobExecutionWitnessInput)
    default: return pDeny(P_DAG, 'unknown_universal_primitive')
  }
}

/* ═══════ Composite terminal-impact invariants (absorbed from the retired own-org guard) ═══════
 * Domain-free host invariants consumed by `CompositeProofReceipt` verification: own-scope access
 * guard (access_differential), signature-carrier provenance (causal_dag), zero-delta readback
 * (state_delta_and_conservation), and clean pre-mutation ablation-control selection (causal_dag).
 * No REST path-noun tables: every decision is structural (payload keys, dynamic segments, controls).
 */
export const normalizeTerminalVulnClass = (cls: string): string => cls.trim().toLowerCase().replace(/[\s-]+/g, '_')
const TENANT_ID_CHAR_RE = /[a-z0-9_-]/
/** Exact identifier equality for tenant slugs/IDs (`-`/`_` are part of the token, never boundaries). */
export const matchesExactTenantIdentifier = (candidate: string | null | undefined, tenant: string | null | undefined): boolean => { const a = normKey(candidate), b = normKey(tenant); return Boolean(a && b && a === b) }
/** True when `text` contains `tenant` bounded by non-identifier characters (no sibling-slug prefix confusion). */
export function containsExactTenantToken(text: string | null | undefined, tenant: string | null | undefined): boolean {
  const hay = text?.toLowerCase() ?? '', needle = normKey(tenant)
  if (!hay || needle.length < 3) return false
  for (let pos = hay.indexOf(needle); pos >= 0; pos = hay.indexOf(needle, pos + 1)) {
    const before = pos === 0 ? '' : hay[pos - 1]!, after = hay[pos + needle.length] ?? ''
    if ((!before || !TENANT_ID_CHAR_RE.test(before)) && (!after || !TENANT_ID_CHAR_RE.test(after))) return true
  }
  return false
}
const matchesAnyOwnTenant = (candidate: string | null | undefined, own: ReadonlySet<string>): boolean => Boolean(candidate && [...own].some(t => matchesExactTenantIdentifier(candidate, t)))
const guardActorOf = (e: HydratableEntry): string | null => e.actorPersona !== undefined ? e.actorPersona : (e.step.actor.handle ?? null)
const guardJson = (e: HydratableEntry | undefined): unknown => e ? parseJsonOrBody(e.step.json, e.step.body) : undefined
/** Dot-segment / percent / matrix-param normalized request path (lowercased, no query). */
export function normalizeGuardPath(raw: string | null | undefined): string {
  const base = (raw ?? '').split(/[?#]/, 1)[0]!.replace(/\/+$/, '').toLowerCase(); if (!base) return ''
  const stack: string[] = []
  for (const rawSeg of base.split('/')) {
    let seg = rawSeg; if (seg.includes('%')) { try { seg = decodeURIComponent(seg) } catch { /* keep raw segment */ } }
    seg = seg.split(';', 1)[0]!.trim().toLowerCase()
    if (!seg || seg === '.') continue
    if (seg === '..') stack.pop(); else stack.push(seg)
  }
  return stack.length > 0 ? `/${stack.join('/')}` : '/'
}

/* access_differential own-scope guard (structural; no REST path-noun lists). */
const ACCESS_CONTRACT_EXEMPT_RE = /^(?:csrf|mass_assignment|signed_url_.*|.*_signed_url|presigned_url_.*|.*_presigned_url|azure_sas_mint)$/i
const AUTH_OR_LOGIC_CLASS_RE = /^(?:auth_bypass|authentication_bypass|broken_auth|business_logic|workflow_bypass|workflow_skip|invariant_violation)$/i
const TENANT_SCOPE_SEG_RE = /^(?:orgs?|organizations?|tenants?|workspaces?)$/i
const PAGINATION_KEY_RE = /^(?:next_?(?:page_?)?token|prev(?:ious)?_?(?:page_?)?token|page_?token|continuation_?token|resume_?token|scroll_?token|sync_?token|cursor_?token|cursor|next_?cursor|prev_?cursor)$/i
const SENSITIVE_WORD_RE = /^(?:secret|secrets|password|passwd|private|credential|credentials|apikey|api_key|vault|audit|token|tokens|signing|canary|ssn|card|iban|private_key|access_token|refresh_token|auth_token|session_token|id_token|bearer_token)$/i
const SLUG_LABEL_RE = /\bslug=([a-z0-9][a-z0-9._-]{0,63})(?![a-z0-9._-])/i
export const DYNAMIC_SEG_RE = /^(?:\d+|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}|(?=[0-9a-f]*\d)[0-9a-f]{8,}|[0-9a-f]{16,}|(?=[a-z0-9]*\d)(?=[a-z0-9]*[a-z])[a-z0-9]{8,}|[a-z]+[_-][a-z0-9_-]*\d[a-z0-9_-]*|:id|<scrubbed>)$/i
function isSensitivePayloadKey(key: string): boolean {
  const lk = key.trim().toLowerCase(), norm = key.replace(/([a-z0-9])([A-Z])/g, '$1_$2').toLowerCase()
  if (!lk || PAGINATION_KEY_RE.test(lk) || PAGINATION_KEY_RE.test(norm)) return false
  return SENSITIVE_WORD_RE.test(norm) || norm.split(/[^a-z0-9]+/).filter(Boolean).some(w => SENSITIVE_WORD_RE.test(w))
}
/** Bounded (depth <= 3, <= 128 keys, <= 16 items per array) payload scan: array-bearing and sensitive-key-bearing. */
function scanPayloadShape(parsed: unknown): { hasArray: boolean; hasSensitive: boolean } {
  let hasArray = false, hasSensitive = false, visited = 0
  const walk = (node: unknown, depth: number): void => {
    if (hasSensitive || depth > 3 || !node || typeof node !== 'object') return
    if (Array.isArray(node)) { hasArray = true; for (const item of node.slice(0, 16)) walk(item, depth + 1); return }
    for (const [k, v] of Object.entries(node as Record<string, unknown>)) {
      if (hasSensitive || ++visited > 128) return
      if (isSensitivePayloadKey(k)) { hasSensitive = true; return }
      walk(v, depth + 1)
    }
  }
  walk(parsed, 0)
  return { hasArray, hasSensitive }
}
/** Collection payload (array-bearing) with zero sensitive keys: a directory listing, not protected data. */
const isNonSensitiveCollectionPayload = (parsed: unknown): boolean => { const sh = scanPayloadShape(parsed); return sh.hasArray && !sh.hasSensitive }
function requestCitesOwnTenantToken(entry: HydratableEntry, own: ReadonlySet<string>): boolean {
  const raw = normStr(entry.step.pathAndQuery ?? entry.step.route); if (own.size === 0 || !raw) return false
  const [pathPart = '', queryPart = ''] = raw.split('?', 2)
  for (const seg of pathPart.split('/').filter(Boolean)) { let d = seg; if (seg.includes('%')) { try { d = decodeURIComponent(seg) } catch { d = seg } } if (matchesAnyOwnTenant(d.split(';', 1)[0], own)) return true }
  return Boolean(queryPart) && [...new URLSearchParams(queryPart.split('#', 1)[0]!).values()].some(v => matchesAnyOwnTenant(v, own))
}
/* access_differential Principal + Capability provenance: self-minted session credentials (structural, no path nouns). */
const SESSION_TOKEN_KEY_RE = /^(?:token|access_?token|session_?token|id_?token|jwt|bearer_?token|auth_?token)$/i
const AUTHN_SECRET_KEY_RE = /^(?:password|passwd|pass|pwd|passphrase|client_?secret|otp|totp|mfa_?code)$/i
const TENANT_VALUE_KEY_RE = /^(?:tenant|tenant_?id|org|org_?id|org_?slug|organization|organization_?id|workspace|workspace_?id)$/i
const shallowTenantValue = (obj: unknown, depth = 0): string => { if (depth > 2 || !obj || typeof obj !== 'object' || Array.isArray(obj)) return ''; const es = Object.entries(obj as Record<string, unknown>); return normKey(es.find(([k, v]) => TENANT_VALUE_KEY_RE.test(k.trim()) && typeof v === 'string' && v.trim())?.[1] as string | undefined) || es.map(([, v]) => shallowTenantValue(v, depth + 1)).find(Boolean) || '' }
/** A non-authentication write whose response mints a session credential (capability grant, not login). */
function mintedSession(e: HydratableEntry): { respTenant: string; reqTenant: string; verifiedFalse: boolean; grantedRole: RoleName | null } | null {
  const req = e.step.requestJson
  if (!/^(?:POST|PUT|PATCH)$/i.test(e.step.method) || (req && typeof req === 'object' && Object.keys(req).some(k => AUTHN_SECRET_KEY_RE.test(k.trim())))) return null
  const root = guardJson(e); if (!root || typeof root !== 'object' || Array.isArray(root)) return null
  const es = Object.entries(root as Record<string, unknown>), t = (es.length === 1 && es[0]![1] && typeof es[0]![1] === 'object' && !Array.isArray(es[0]![1]) ? es[0]![1] : root) as Record<string, unknown>
  if (!Object.entries(t).some(([k, v]) => SESSION_TOKEN_KEY_RE.test(k.trim()) && typeof v === 'string' && v.trim().length >= 4)) return null
  const role = Object.entries(t).find(([k, v]) => k.trim().toLowerCase() === 'role' && typeof v === 'string')?.[1] as string | undefined
  return { respTenant: shallowTenantValue(t), reqTenant: shallowTenantValue(req), verifiedFalse: Object.entries(t).some(([k, v]) => k.trim().toLowerCase() === 'verified' && v === false), grantedRole: role ? normalizeRole(role) : null }
}
/** Singleton identity/health read (no dynamic segment, non-collection, no sensitive keys): never compromise provenance. */
const isSelfServiceRead = (e: HydratableEntry): boolean => { const sh = scanPayloadShape(guardJson(e)); return stepReadsState(e.step) && !normalizeGuardPath(e.step.route ?? e.step.pathAndQuery).split('/').some(seg => DYNAMIC_SEG_RE.test(seg)) && !sh.hasArray && !sh.hasSensitive }
const hasDeniedControlFor = (t: HydratableEntry, ids: readonly string[] | undefined, byId: ReadonlyMap<string, HydratableEntry> | undefined): boolean => { const fam = routeFamily(t.step.route ?? t.step.pathAndQuery); return Boolean(fam && ids?.some(id => { const c = byId?.get(id); return Boolean(c && c.exchangeId !== t.exchangeId && c.step.arm === 'control' && isDenied(c.step.status) && c.step.method.toUpperCase() === t.step.method.toUpperCase() && routeFamily(c.step.route ?? c.step.pathAndQuery) === fam) })) }
/**
 * A boundary flip achieved with a credential the principal minted for its OWN tenant is legitimate capability
 * acquisition unless the minting operation itself was denied under a clean control, a substantive upstream
 * leak/compromise hop precedes it, foreign-tenant data is exposed, or (terminal mint) a verified tier escalation.
 */
function selfMintedCapabilityError(p: OwnScopeGuardParams, own: ReadonlySet<string>, ownOrgScoped: boolean): string | null {
  const term = p.termEx!, upstream = p.upstreamEntries ?? [], substantiveUpstream = upstream.some(u => !mintedSession(u) && !isSelfServiceRead(u))
  const ownMint = (m: { respTenant: string; reqTenant: string; verifiedFalse: boolean }) => { const t = m.respTenant || m.reqTenant; return m.verifiedFalse || !(t && own.size > 0 && !matchesAnyOwnTenant(t, own)) }
  if (!((p.hopCount ?? 1) > 2 && substantiveUpstream) && !p.hasForeignTenantData && ownOrgScoped && upstream.some(u => { const m = mintedSession(u); return Boolean(m && ownMint(m) && !hasDeniedControlFor(u, p.preChainControlIds, p.entriesById)) })) return 'terminal_impact_unproven: own-org flow starting directly at a self-minted session credential requires an upstream compromise hop, a verified denied control on the minting operation, or foreign-tenant exposure.'
  const tm = mintedSession(term)
  if (!tm || (tm.respTenant && own.size > 0 && !matchesAnyOwnTenant(tm.respTenant, own))) return null
  const actor = guardActorOf(term), base = resolvePersonaIdentity({ roleLabel: term.actorRoleLabel ?? (actor ? p.personaRoleLabels?.[actor] : undefined), privilege: term.actorPrivilege ?? term.step.actor.role ?? null }).role
  const noEscalation = !tm.grantedRole || (base !== null && ROLE_RANK[tm.grantedRole] <= ROLE_RANK[base])
  return tm.verifiedFalse || !substantiveUpstream || noEscalation ? 'terminal_impact_unproven: own-org self-minted session terminal requires genuine foreign-tenant exposure (exact tenant boundary match) or verified privilege-tier escalation with upstream compromise provenance.' : null
}
export interface OwnScopeGuardParams {
  normCls: string; contract: string | null; isPrivEscCls: boolean; isCrossTenantCls: boolean
  termEx: HydratableEntry | undefined; terminalCtrl: HydratableEntry | undefined; attackerTenants: ReadonlySet<string>; personaRoleLabels?: Readonly<Record<string, string>>
  ownTenantOnly: boolean; hasForeignTenantData: boolean; reflectedTenantOnly?: boolean; hasPostMutation: boolean; hasV8Oracle: boolean; isReadOnlyDir: boolean
  hasTermDerivedCrypto: boolean; hasVerifiedTermStateTransition: boolean; hasVerifiedTermValueBinding: boolean
  hopCount?: number; upstreamEntries?: readonly HydratableEntry[]; preChainControlIds?: readonly string[]; entriesById?: ReadonlyMap<string, HydratableEntry>
}
/**
 * access_differential own-scope guard: rejects own-tenant directory/collection reads, reflected-only
 * tenant reads, plain self-service collection creates, and own-org business_logic without an explicit
 * delta, unless a v8/primitive oracle or a post-mutation readback already proved out-of-scope impact.
 */
export function evaluateOwnScopeTerminalGuard(p: OwnScopeGuardParams): string | null {
  if (p.hasV8Oracle || !p.termEx) return null
  const isAccessOrLogic = (p.contract === 'access_control' && !ACCESS_CONTRACT_EXEMPT_RE.test(p.normCls)) || AUTH_OR_LOGIC_CLASS_RE.test(p.normCls)
  if (!p.isPrivEscCls && !p.isCrossTenantCls && !isAccessOrLogic) return null
  const term = p.termEx, cleanPath = normalizeGuardPath(term.step.route ?? term.step.pathAndQuery), reads = stepReadsState(term.step)
  const termActor = guardActorOf(term), ctrlActor = p.terminalCtrl ? guardActorOf(p.terminalCtrl) : null
  const own = new Set<string>([...p.attackerTenants].map(normKey).filter(Boolean))
  const labels = [term.actorRoleLabel, termActor ? p.personaRoleLabels?.[termActor] : undefined, ctrlActor ? p.personaRoleLabels?.[ctrlActor] : undefined, ...(p.upstreamEntries ?? []).flatMap(u => { const a = guardActorOf(u); return [u.actorRoleLabel, a ? p.personaRoleLabels?.[a] : undefined] })]
  for (const lbl of labels) { const m = lbl ? SLUG_LABEL_RE.exec(lbl) : null; if (m?.[1]) own.add(m[1].toLowerCase()) }
  const segs = cleanPath.split('/').filter(Boolean), lastSeg = segs[segs.length - 1] ?? ''
  const scopeIdx = segs.findIndex(s => TENANT_SCOPE_SEG_RE.test(s)), scopeTenant = scopeIdx >= 0 ? segs[scopeIdx + 1] ?? null : null
  const pathTargetsOwnTenant = Boolean(!p.hasForeignTenantData && scopeTenant && matchesAnyOwnTenant(scopeTenant, own))
  const pathTargetsForeignTenant = Boolean(scopeTenant && own.size > 0 && !matchesAnyOwnTenant(scopeTenant, own))
  const ownOrgScoped = p.ownTenantOnly || pathTargetsOwnTenant
  const mintErr = selfMintedCapabilityError(p, own, ownOrgScoped); if (mintErr) return mintErr
  if (p.hasPostMutation) return null
  if (p.isReadOnlyDir) return 'terminal_impact_unproven: privilege_escalation/bfla/cross-tenant/access-control/business-logic cannot confirm on a read-only directory/roster/metadata listing GET without private payload content, a state-mutating terminal action + postChainReadbackExchangeIds, or a verified v8 oracle family.'
  if (reads && p.reflectedTenantOnly && !p.hasForeignTenantData && requestCitesOwnTenantToken(term, own)) return 'terminal_impact_unproven: read-only terminal response contained only request-reflected tenant markers on an own-tenant-scoped request with zero host-verified non-reflected foreign-tenant evidence.'
  const ctrlStatus = p.terminalCtrl?.step.status ?? null
  const ctrlAuthzDenied = ctrlStatus === 401 || ctrlStatus === 403 || ctrlStatus === 409 || ctrlStatus === 412 || ctrlStatus === 422
  const hasEscalatedCapDelta = Boolean(p.hasVerifiedTermValueBinding && ctrlAuthzDenied && (Boolean(termActor?.startsWith('cap:')) || (term.consumedCapabilities?.length ?? 0) > 0) && termActor !== ctrlActor)
  // Chain-induced boundary flip: a clean same-op authz denial + a verified causal edge INTO the terminal (value binding,
  // derived crypto, or state-transition ablation) proves out-of-baseline-scope impact (replaces REST path-noun lists).
  const chainInducedFlip = (ctrlStatus === 401 || ctrlStatus === 403) && (p.hasVerifiedTermValueBinding || p.hasTermDerivedCrypto || p.hasVerifiedTermStateTransition)
  if (reads && lastSeg && !DYNAMIC_SEG_RE.test(lastSeg) && !chainInducedFlip && !p.hasVerifiedTermStateTransition && isNonSensitiveCollectionPayload(guardJson(term))) {
    const unattributedOwnCollection = !p.hasForeignTenantData && !pathTargetsForeignTenant && p.attackerTenants.size > 0 && !hasEscalatedCapDelta
    if (ownOrgScoped || unattributedOwnCollection) return 'terminal_impact_unproven: own-org directory/invite/collection GET listing is non-terminal impact without foreign-tenant exposure, a state-mutating terminal action + postChainReadbackExchangeIds, or a verified v8 oracle family.'
  }
  const hasNonScopeDynamicSeg = segs.some((seg, i) => !TENANT_SCOPE_SEG_RE.test(segs[i - 1] ?? '') && DYNAMIC_SEG_RE.test(seg))
  // Plain self-service create: collection POST whose response exposes no protected (sensitive-key) data.
  const isPlainCollectionCreate = term.step.method.toUpperCase() === 'POST' && !hasNonScopeDynamicSeg && !chainInducedFlip && !scanPayloadShape(guardJson(term)).hasSensitive
  const unattributedOwnCreate = ownOrgScoped || (!p.hasForeignTenantData && !pathTargetsForeignTenant && !p.isCrossTenantCls)
  const noWriteDelta = !p.hasTermDerivedCrypto && !p.hasVerifiedTermStateTransition
  if (unattributedOwnCreate && isPlainCollectionCreate && noWriteDelta && (isAccessOrLogic || (p.isPrivEscCls && !hasEscalatedCapDelta))) return 'terminal_impact_unproven: plain own-org POST resource creation requires a verified v8 oracle family, postChainReadbackExchangeIds proving unauthorized persisted impact, forged cryptographic signature, or verified state_transition_binding.'
  if (ownOrgScoped && p.normCls === 'business_logic' && !(!reads && !isPlainCollectionCreate && ctrlAuthzDenied && (!noWriteDelta || hasEscalatedCapDelta))) return 'terminal_impact_unproven: own-org business_logic without postChainReadbackExchangeIds requires a verified v8 oracle family (e.g. economic_conservation) or an explicit forged-signature, state-transition, or escalated-credential mutation delta on the same resource.'
  return null
}

/* causal_dag signature-carrier provenance. Hardware MAC-address fields are NOT cryptographic carriers. */
const SIG_CARRIER_KEY_RE = /(?:^|[-_])(?:sig|signature|hmac|digest|derivation)(?:$|[-_])|signature|hmac/i
const MAC_CARRIER_KEY_RE = /^(?:(?:x|request|req|message|msg|auth|api|webhook|payload|body|content)[-_])?mac(?:[-_](?:sha\d+|md5|\d+))?$/i
const SIGNED_URL_QUERY_KEY_RE = /^(?:x-)?sign$|^sig(?:\[\]|\d+)$/i
/** Cryptographic signature/MAC carrier key (`x-signature`, `stripe-signature`, `hmac`, `x-mac`, ...); never `mac_address` / `device_mac`. */
export const isSignatureCarrierKey = (key: string): boolean => { const k = key.trim(); return SIG_CARRIER_KEY_RE.test(k) || MAC_CARRIER_KEY_RE.test(k) }
/** Host-side detector for signature carriers across headers, query params, and (for non-reads) JSON request bodies. */
export function hasSignatureCarrier(entry: HydratableEntry | undefined, includeBody = true): boolean {
  if (!entry) return false
  for (const [k, v] of Object.entries(entry.step.requestHeaders ?? {})) if (isSignatureCarrierKey(k) && (includeBody || (typeof v === 'string' && v.trim().length > 0))) return true
  const raw = entry.step.pathAndQuery ?? entry.step.route ?? '', q = raw.indexOf('?')
  if (q >= 0) for (const [k, v] of new URLSearchParams(raw.slice(q + 1).split('#', 1)[0] ?? '').entries()) if ((isSignatureCarrierKey(k) || SIGNED_URL_QUERY_KEY_RE.test(k.trim())) && (includeBody || v.trim().length > 0)) return true
  const body = entry.step.requestJson
  return includeBody && Boolean(body && typeof body === 'object' && !Array.isArray(body) && Object.keys(body).some(isSignatureCarrierKey))
}
const SIG_DENIED_STATUSES = new Set([401, 403, 404]), SIG_CLASS_RE = /^(?:webhook_forgery|webhook|forged_signature.*)$/i
export interface SignatureProvenanceGuardParams {
  normCls: string; hopCount: number; verifiedEdgeCount: number; singleHopProofOk: boolean; termEx: HydratableEntry | undefined; terminalCtrl: HydratableEntry | undefined
  preChainControlIds: readonly string[]; entriesById: ReadonlyMap<string, HydratableEntry>; hasTermDerivedCrypto: boolean
  /** A primitive crypto oracle (cryptographic_scope_replay) already verified the in-transcript minting exchange. */
  hostVerifiedCryptoOracle?: boolean
}
/**
 * causal_dag provenance: a 1-hop (`hops < 2`, no verified edge) terminal carrying a signature carrier
 * (or claiming a signature-forgery class) must prove in-DAG emitter/crypto provenance; otherwise fail closed.
 */
export function evaluateSignatureProvenanceGuard(p: SignatureProvenanceGuardParams): string | null {
  const term = p.termEx
  if (p.singleHopProofOk || p.hopCount >= 2 || p.verifiedEdgeCount > 0 || !term) return null
  const meth = term.step.method.toUpperCase(), isRead = isReadMethod(meth)
  if ((isRead && p.hostVerifiedCryptoOracle) || p.hasTermDerivedCrypto || (term.cryptoAttestations?.length ?? 0) > 0) return null
  const hasSigCarrier = hasSignatureCarrier(term, !isRead)
  if (!hasSigCarrier && !(!isRead && SIG_CLASS_RE.test(p.normCls))) return null
  const termFam = routeFamily(term.step.route ?? term.step.pathAndQuery)
  const hasDeniedCtrl = SIG_DENIED_STATUSES.has(p.terminalCtrl?.step.status ?? 0) || p.preChainControlIds.some(cid => { const c = p.entriesById.get(cid); return Boolean(c && c.step.arm === 'control' && SIG_DENIED_STATUSES.has(c.step.status ?? 0) && c.step.method.toUpperCase() === meth && (!termFam || routeFamily(c.step.route ?? c.step.pathAndQuery) === termFam)) })
  if (!hasDeniedCtrl && !hasSigCarrier) return null
  return isRead
    ? 'signed_url_unproven_capability_provenance: 1-hop signature-bearing read requires >= 2 hops with a verified causal edge or host-attested derived_crypto_binding proving in-DAG signature/capability provenance.'
    : 'forged_signature_unproven_secret_provenance: 1-hop signature-bearing terminal exchange requires >= 2 hops with a verified causal edge or host-attested derived_crypto_binding proving in-DAG emitter/crypto provenance.'
}

/* state_delta_and_conservation readback delta: persisted state must differ from an earlier same-route baseline. */
const STATE_PRESERVE_KEY_RE = /^(?:role|roles|permission|permissions|scope|scopes|tenant|tenant_id|org|org_id|organization_id|workspace_id|user_id|account_id|wallet_id|owner|owner_id|balance|balance_cents|amount|amount_cents|credits|funds|status|state|verified|active|revoked|admin|is_admin|email|plan|tier|entitlements|members|entries|records|items|payouts|orders|secrets)$/
const VOLATILE_STATE_KEY_RE = /(?:^|_)(?:ts|timestamp|time|date|now|seen|login|accessed|synced|checked|refreshed|issued|expires|expiry|exp|iat|nbf|ttl|age|uptime|latency|duration)(?:$|_)|(?:_at|_ms|_sec|_ts)$|^(?:jti|nonce|etag|e_tag|version|ver|rev|revision|build|sid|csrf|csrf_token|xsrf_token)$|(?:^|_)(?:request|req|trace|span|correlation|session|csrf|xsrf|nonce)_id$/
const isVolatileStateKey = (raw: string): boolean => { const n = raw.trim().replace(/([a-z0-9])([A-Z])/g, '$1_$2').replace(/[\s-]+/g, '_').toLowerCase(); return Boolean(n) && !STATE_PRESERVE_KEY_RE.test(n) && VOLATILE_STATE_KEY_RE.test(n) }
function canonicalReadbackState(node: unknown, depth = 0): unknown {
  if (node === null || typeof node !== 'object') return node
  if (depth >= 32) return '[max_depth]'
  if (Array.isArray(node)) return node.map(x => canonicalReadbackState(x, depth + 1))
  return Object.fromEntries(Object.keys(node as Record<string, unknown>).sort().filter(k => !isVolatileStateKey(k)).map(k => [k, canonicalReadbackState((node as Record<string, unknown>)[k], depth + 1)]))
}
/** Generic structural readback fingerprint (volatile clock/nonce/session keys stripped; state keys preserved). */
export function readbackStateFingerprint(json: unknown, body?: string): string | null {
  const parsed = parseJsonOrBody(json, body)
  if (parsed !== undefined) { try { return `json:${JSON.stringify(canonicalReadbackState(parsed))}` } catch { return null } }
  return normStr(body) ? `text:${normStr(body)}` : null
}
function normalizedReadbackRoute(e: HydratableEntry): string {
  const raw = normStr(e.step.pathAndQuery ?? e.step.route); if (!raw) return ''
  const [path = '', q = ''] = raw.split('?', 2), cleanP = normalizeGuardPath(path), qs = q.split('#', 1)[0] ?? ''
  const pairs = [...new URLSearchParams(qs).entries()].map(([k, v]) => [k.trim().toLowerCase(), v.trim().toLowerCase()] as const).sort((a, b) => a[0].localeCompare(b[0]) || a[1].localeCompare(b[1]))
  return pairs.length > 0 ? `${cleanP}?${pairs.map(([k, v]) => `${k}=${v}`).join('&')}` : cleanP
}
/** True when an earlier same-route/method/actor 2xx readback has IDENTICAL normalized state (zero persisted delta). */
export function isZeroDeltaPostMutationReadback(rb: HydratableEntry, termEx: HydratableEntry | undefined, entriesById: ReadonlyMap<string, HydratableEntry>): boolean {
  const rbFp = readbackStateFingerprint(rb.step.json, rb.step.body), rbRoute = normalizedReadbackRoute(rb)
  if (!rbFp || !rbRoute) return false
  const rbMeth = rb.step.method.toUpperCase(), rbActor = normKey(guardActorOf(rb))
  const cutoff = typeof termEx?.timestampMs === 'number' && Number.isFinite(termEx.timestampMs) ? termEx.timestampMs : (typeof rb.timestampMs === 'number' && Number.isFinite(rb.timestampMs) ? rb.timestampMs : null)
  for (const pre of entriesById.values()) {
    if (pre.exchangeId === rb.exchangeId || pre.exchangeId === termEx?.exchangeId || !isOk(pre.step.status) || !stepReadsState(pre.step) || pre.step.method.toUpperCase() !== rbMeth) continue
    if (cutoff !== null && (typeof pre.timestampMs !== 'number' || !Number.isFinite(pre.timestampMs) || pre.timestampMs >= cutoff)) continue
    if (normalizedReadbackRoute(pre) === rbRoute && normKey(guardActorOf(pre)) === rbActor && readbackStateFingerprint(pre.step.json, pre.step.body) === rbFp) return true
  }
  return false
}
/** First valid post-mutation readback with a non-zero persisted delta; `rejectedZeroDelta` when only zero-delta candidates exist. */
export function selectVerifiedPostMutationReadback<T extends HydratableEntry>(postChainIds: readonly string[], termEx: T | undefined, entriesById: ReadonlyMap<string, T>, isCrossTenantCls: boolean, isOwnTenantOnly: (e: T) => boolean, hasEntryBody: (e: T) => boolean, isStubEntry: (e: T) => boolean): { postMutRb: T | undefined; rejectedZeroDelta: boolean } {
  let sawZeroDelta = false
  for (const id of postChainIds) {
    const e = entriesById.get(id)
    if (!e || (termEx && e.exchangeId === termEx.exchangeId) || !isOk(e.step.status)) continue
    const termTs = termEx?.timestampMs
    if (termEx && typeof termTs === 'number' && Number.isFinite(termTs) && !(typeof e.timestampMs === 'number' && Number.isFinite(e.timestampMs) && e.timestampMs >= termTs)) continue
    if (!(stepReadsState(e.step) || e.step.arm === 'control' || e.step.evidenceRole === 'post_chain_readback') || !hasEntryBody(e) || (isCrossTenantCls && isOwnTenantOnly(e))) continue
    if (isZeroDeltaPostMutationReadback(e, termEx, entriesById)) { sawZeroDelta = true; continue }
    if (!isStubEntry(e)) return { postMutRb: e, rejectedZeroDelta: false }
  }
  return { postMutRb: undefined, rejectedZeroDelta: sawZeroDelta }
}

/* causal_dag ablation: clean pre-mutation denied control (403 -> mutation -> 2xx) on the dependent route. */
const ABLATION_DENIED_STATUSES = new Set([401, 403, 404]), GUARD_ANON_ACTOR_RE = /^(?:anon(?:ymous)?|unauth(?:enticated)?|guest)$/i
const PRIV_MUTATION_PAYLOAD_KEY_RE = /^(?:role|roles|permission|permissions|privileges?|admin|is_admin|isAdmin|acl|entitlements?|membership|memberships|tier)$/i
type GuardChronoEntry = HydratableEntry & { origin?: string; cleanSession?: boolean; replayAttempt?: string }
const finiteNum = (v: unknown): v is number => typeof v === 'number' && Number.isFinite(v)
const isChronoBefore = (a: GuardChronoEntry, b: GuardChronoEntry): boolean => finiteNum(a.timestampMs) && finiteNum(b.timestampMs) && (a.timestampMs < b.timestampMs || (a.timestampMs === b.timestampMs && finiteNum(a.seq) && finiteNum(b.seq) && a.seq < b.seq))
export const compareChronoAsc = (a: GuardChronoEntry, b: GuardChronoEntry): number => ((finiteNum(a.timestampMs) ? a.timestampMs : Number.MAX_SAFE_INTEGER) - (finiteNum(b.timestampMs) ? b.timestampMs : Number.MAX_SAFE_INTEGER)) || ((finiteNum(a.seq) ? a.seq : Number.MAX_SAFE_INTEGER) - (finiteNum(b.seq) ? b.seq : Number.MAX_SAFE_INTEGER))
const originsCompatible = (a?: string, b?: string): boolean => { const na = normKey(a).replace(/\/+$/, ''), nb = normKey(b).replace(/\/+$/, ''); return !na || !nb || na === nb }
const isCleanDeniedControl = (c: GuardChronoEntry): boolean => c.cleanSession === true && (c.step.arm === 'control' || c.replayAttempt === 'ablation_control') && ABLATION_DENIED_STATUSES.has(c.step.status ?? 0)
function hasPrivilegeMutationPayloadKey(node: unknown, depth = 0): boolean {
  if (depth > 2 || !node || typeof node !== 'object') return false
  if (Array.isArray(node)) return node.slice(0, 16).some(x => hasPrivilegeMutationPayloadKey(x, depth + 1))
  return Object.entries(node as Record<string, unknown>).some(([k, v]) => PRIV_MUTATION_PAYLOAD_KEY_RE.test(k.trim()) || (Boolean(v) && typeof v === 'object' && hasPrivilegeMutationPayloadKey(v, depth + 1)))
}
function mutationLogicalEntityId(fromEx: HydratableEntry, fromHopEntityId: string | undefined, actorKey: string): string {
  if (fromEx.entityId?.trim()) return fromEx.entityId.trim()
  if (fromHopEntityId?.trim()) return fromHopEntityId.trim()
  const segs = (fromEx.step.pathAndQuery ?? fromEx.step.route ?? '').split(/[?#]/, 1)[0]!.split('/').map(s => s.trim()).filter(s => s && !/^(?::id|<scrubbed>)$/i.test(s))
  return [...segs].reverse().find(s => DYNAMIC_SEG_RE.test(s)) ?? `actor:${actorKey}`
}
export interface AblationSelectionHelpers<T> { normRouteFam: (p: string | null | undefined, eid?: string) => string; sameCredIdentity: (a: T, b: T) => boolean; isLoginCap: (cap: string) => boolean; canonicalNonAuthQuery: (p: string | null | undefined) => string }
/**
 * Host-completed `state_transition_binding` for an entity-less terminal read: a succeeding same-actor
 * privilege-payload mutation preceded by a clean denied control (same route/query/credential) on the read.
 */
export function resolveEntityLessReadStateTransition<T extends GuardChronoEntry>(params: AblationSelectionHelpers<T> & { fromEx: T; fromHopEntityId?: string; toEx: T; isTerminalTo: boolean; allEntries: readonly T[]; pairExIds: ReadonlySet<string>; allHopExIds: ReadonlySet<string>; preCtrlIds: ReadonlySet<string>; probeActorOf: (e: T) => string | null }): { entityId: string; ablationExchangeId: string } | null {
  const { fromEx, toEx, normRouteFam, canonicalNonAuthQuery } = params
  if (!params.isTerminalTo || !stepReadsState(toEx.step) || toEx.entityId?.trim()) return null
  if (stepReadsState(fromEx.step) || !/^(?:PATCH|POST|PUT)$/i.test(fromEx.step.method) || !(hasPrivilegeMutationPayloadKey(fromEx.step.requestJson) || hasPrivilegeMutationPayloadKey(fromEx.step.json))) return null
  const toRaw = guardActorOf(toEx), toActor = params.probeActorOf(toEx), fromActor = params.probeActorOf(fromEx)
  if (!toRaw || GUARD_ANON_ACTOR_RE.test(toRaw) || !toActor || toActor !== fromActor) return null
  const toFam = normRouteFam(toEx.step.route ?? toEx.step.pathAndQuery), toQuery = canonicalNonAuthQuery(toEx.step.pathAndQuery ?? toEx.step.route)
  if (!toFam) return null
  const cands = params.allEntries.filter(ab => {
    if (params.pairExIds.has(ab.exchangeId) || (!params.preCtrlIds.has(ab.exchangeId) && params.allHopExIds.has(ab.exchangeId)) || !isCleanDeniedControl(ab)) return false
    if (ab.step.method.toUpperCase() !== toEx.step.method.toUpperCase() || !originsCompatible(ab.origin, toEx.origin) || !isChronoBefore(ab, fromEx) || canonicalNonAuthQuery(ab.step.pathAndQuery ?? ab.step.route) !== toQuery) return false
    const abRaw = guardActorOf(ab)
    if (!abRaw || GUARD_ANON_ACTOR_RE.test(abRaw) || (abRaw.startsWith('cap:') && abRaw !== toRaw && !params.isLoginCap(abRaw)) || !params.sameCredIdentity(ab, toEx)) return false
    return normRouteFam(ab.step.route ?? ab.step.pathAndQuery, ab.entityId) === toFam
  }).sort(compareChronoAsc)
  const chosen = cands.find(c => params.preCtrlIds.has(c.exchangeId)) ?? cands[0]
  return chosen ? { entityId: mutationLogicalEntityId(fromEx, params.fromHopEntityId, toActor), ablationExchangeId: chosen.exchangeId } : null
}
/**
 * Earliest clean pre-mutation denied control (`401`/`403`/`404`) when a `state_transition_binding` cited a
 * post-mutation `2xx` control. Never a `2xx`, never an anonymous `401` on an authenticated route, and a real
 * succeeding mutation must sit between the clean denial and the cited `2xx` exchange.
 */
export function findPreMutationDeniedControl<T extends GuardChronoEntry>(params: AblationSelectionHelpers<T> & { citedTwoXx: T; mutationEx: T; toEx: T; entityId?: string; entriesById: ReadonlyMap<string, T>; excludedIds: ReadonlySet<string>; toUsesNewCap: boolean }): T | null {
  const { citedTwoXx, mutationEx, toEx, entityId, normRouteFam, canonicalNonAuthQuery } = params
  if (stepReadsState(mutationEx.step) || (typeof mutationEx.step.status === 'number' && !isOk(mutationEx.step.status))) return null
  const toFam = normRouteFam(toEx.step.route ?? toEx.step.pathAndQuery, entityId); if (!toFam) return null
  const toQuery = canonicalNonAuthQuery(toEx.step.pathAndQuery ?? toEx.step.route), toRaw = guardActorOf(toEx), toAuth = Boolean(toRaw && !GUARD_ANON_ACTOR_RE.test(toRaw))
  const citedAfterMutation = isChronoBefore(mutationEx, citedTwoXx), mutFam = normRouteFam(mutationEx.step.route ?? mutationEx.step.pathAndQuery, entityId), all = [...params.entriesById.values()]
  const hasInterveningMutation = (cand: T): boolean => citedAfterMutation || (Boolean(mutFam) && all.some(m => m.exchangeId !== cand.exchangeId && m.exchangeId !== citedTwoXx.exchangeId && !stepReadsState(m.step) && isOk(m.step.status) && isChronoBefore(cand, m) && isChronoBefore(m, citedTwoXx) && normRouteFam(m.step.route ?? m.step.pathAndQuery, m.entityId ?? entityId) === mutFam))
  const cands = all.filter(c => {
    if (params.excludedIds.has(c.exchangeId) || [citedTwoXx.exchangeId, toEx.exchangeId, mutationEx.exchangeId].includes(c.exchangeId) || !isCleanDeniedControl(c)) return false
    if (c.step.method.toUpperCase() !== toEx.step.method.toUpperCase() || !originsCompatible(c.origin, toEx.origin) || normRouteFam(c.step.route ?? c.step.pathAndQuery, c.entityId ?? entityId) !== toFam) return false
    if (canonicalNonAuthQuery(c.step.pathAndQuery ?? c.step.route) !== toQuery || !isChronoBefore(c, mutationEx) || !isChronoBefore(c, citedTwoXx)) return false
    const cRaw = guardActorOf(c)
    if (cRaw?.startsWith('cap:') && cRaw !== toRaw && !params.isLoginCap(cRaw)) return false
    if (toAuth && (!cRaw || GUARD_ANON_ACTOR_RE.test(cRaw) || (!params.toUsesNewCap && !params.sameCredIdentity(c, toEx)))) return false
    return hasInterveningMutation(c)
  })
  return cands.sort(compareChronoAsc)[0] ?? null
}

/* ═══════════════ Legacy v8 family adapters (thin normalization onto the primitives) ═══════════════ */

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

const CROSS_ORG_REASONS: Readonly<Record<string, string>> = { same_tenant_not_cross_tenant: 'same_tenant_transfer_not_cross_org', principal_lacks_in_scope_role: 'actor_lacks_dest_tenant_privilege', principal_authorized_out_of_scope: 'actor_authorized_in_source_tenant', control_not_denied: 'source_control_not_denied', variant_rejected: 'transfer_not_accepted', mutation_not_persisted: 'transfer_not_persisted_to_dest_tenant' }
const BATCH_REASONS: Readonly<Record<string, string>> = { same_tenant_not_cross_tenant: 'same_tenant_batch_not_cross_tenant', principal_lacks_in_scope_role: 'actor_lacks_own_tenant_role', principal_authorized_out_of_scope: 'actor_authorized_in_foreign_tenant', control_not_denied: 'single_foreign_control_not_denied', variant_rejected: 'batch_request_denied_or_failed', protected_data_not_returned_or_mutated: 'foreign_record_not_returned_or_mutated' }
const CACHE_BLEED_REASONS: Readonly<Record<string, string>> = { same_tenant_not_cross_tenant: 'same_tenant_not_cache_bleed', principal_lacks_in_scope_role: 'actor_lacks_prime_tenant_privilege', principal_authorized_out_of_scope: 'actor_authorized_in_target_tenant', control_not_denied: 'baseline_control_not_denied', prime_failed: 'prime_action_failed', variant_rejected: 'bled_access_denied_or_failed', control_and_variant_route_mismatch: 'baseline_control_and_bled_route_mismatch', prime_precedes_control: 'non_monotonic_prime_timestamp', variant_precedes_prime: 'non_monotonic_bled_timestamp', variant_own_tenant_only: 'bled_access_own_tenant_only', variant_missing_victim_tenant_marker: 'bled_access_missing_target_tenant_marker', variant_missing_substantive_data: 'bled_access_missing_substantive_data' }

function evaluateCrossOrgTransfer(input: DualTenantCrossOrgTransferInput): V8OracleDecision {
  const f: V8OracleFamily = 'dual_tenant_abac', sub = input.mode, src = normKey(input.sourceTenantId), dst = normKey(input.destTenantId)
  if (!src || !dst) return deny(f, 'missing_tenant_scope', sub)
  if (src === dst) return deny(f, 'same_tenant_transfer_not_cross_org', sub)
  if (!normStr(input.entityId)) return deny(f, 'missing_entity_id', sub)
  const scopeErr = checkPrincipalScope({ actor: input.actor, inScopeTenant: dst, outOfScopeTenant: src, requiredInScopeRole: input.requiredDestRole ?? 'admin', requiredOutOfScopeRole: input.requiredSourceRole ?? 'admin' })
  if (scopeErr) return deny(f, CROSS_ORG_REASONS[scopeErr] ?? scopeErr, sub)
  const d = evaluateUniversalPrimitive('access_differential', { control: input.sourceControlDenied!, variant: input.transferRecord, readback: input.postTransferReadback, requireReadback: true, requireMutatingVariant: true, persistedDelta: normKey(input.observedOwnerTenantId) === dst, principalActorId: input.actor.actorId, verifySignature: input.verifySignature, labels: { control: 'source_control', variant: 'transfer', readback: 'post_transfer_readback' } })
  if (!d.satisfied) return denyVia(f, d, CROSS_ORG_REASONS, sub)
  return ok(f, sub, 'cross_org_transfer_without_source_tenant_authorization', { actorId: input.actor.actorId, sourceTenantId: src, destTenantId: dst, entityId: input.entityId, sourceRole: resolveTenantRole(input.actor, src), destRole: resolveTenantRole(input.actor, dst), transferId: input.transferRecord.id, readbackId: input.postTransferReadback.id })
}

function evaluateDualCacheBleed(input: DualTenantCacheBleedInput): V8OracleDecision {
  const f: V8OracleFamily = 'dual_tenant_abac', sub = input.mode, prime = normKey(input.primeTenantId), target = normKey(input.targetTenantId), req = input.requiredRole ?? 'admin'
  if (!prime || !target) {
    const re = Object.entries(input.actor.rolesByTenant ?? {}).map(([t, r]) => [normKey(t), normalizeRole(r ?? undefined)] as const).filter(([t, r]) => Boolean(t && r))
    const hi = prime ? hasTenantRoleAtLeast(input.actor, prime, req) : re.some(([, r]) => r !== null && ROLE_RANK[r] >= ROLE_RANK[req])
    if (new Set(re.map(([t]) => t)).size < 2 || !hi || !re.some(([, r]) => r !== null && ROLE_RANK[r] < ROLE_RANK[req])) return deny(f, 'actor_not_dual_tenant: dual_org_cache_bleed requires a multi-tenant actor with elevated role in primeTenant; for single-tenant cache bleed use parser_cache_differential or omit oracleFamily', sub)
    return deny(f, 'missing_tenant_scope', sub)
  }
  const scopeErr = checkPrincipalScope({ actor: input.actor, inScopeTenant: prime, outOfScopeTenant: target, requiredInScopeRole: req, requiredOutOfScopeRole: req })
  if (scopeErr) return deny(f, CACHE_BLEED_REASONS[scopeErr] ?? scopeErr, sub)
  const d = evaluateUniversalPrimitive('wire_framing_and_cache_differential', { property: 'cache_priming', control: input.baselineDeniedControl, prime: input.primeAction, variant: input.bledAccess, victimTenant: target, primeTenant: prime, observedTenant: input.observedTenantId, targetRecordId: input.targetRecordId, isolatedControl: input.isolatedControl, principalActorId: input.actor.actorId, verifySignature: input.verifySignature, labels: { control: 'baseline_control', prime: 'prime_action', variant: 'bled_access' } })
  if (!d.satisfied) return denyVia(f, d, CACHE_BLEED_REASONS, sub)
  return ok(f, sub, 'dual_org_permission_cache_bleed_confirmed', { actorId: input.actor.actorId, primeTenantId: prime, targetTenantId: target, baselineControlId: input.baselineDeniedControl.id, primeActionId: input.primeAction.id, bledAccessId: input.bledAccess.id })
}

function evaluateBatchPartialAuthz(input: DualTenantBatchPartialAuthzInput): V8OracleDecision {
  const f: V8OracleFamily = 'dual_tenant_abac', sub = input.mode, ownTenant = normKey(input.ownTenantId), foreignTenant = normKey(input.foreignTenantId), req = input.requiredRole ?? 'member'
  if (!ownTenant || !foreignTenant) return deny(f, 'missing_tenant_scope', sub)
  const scopeErr = checkPrincipalScope({ actor: input.actor, inScopeTenant: ownTenant, outOfScopeTenant: foreignTenant, requiredInScopeRole: req, requiredOutOfScopeRole: req })
  if (scopeErr) return deny(f, BATCH_REASONS[scopeErr] ?? scopeErr, sub)
  const ownId = normStr(input.ownRecordId), foreignId = normStr(input.foreignRecordId), reqSet = new Set((input.requestedIds ?? []).map(normStr))
  if (!ownId || !foreignId || ownId === foreignId) return deny(f, 'invalid_batch_record_pair', sub)
  if (!reqSet.has(ownId) || !reqSet.has(foreignId)) return deny(f, 'batch_missing_own_and_foreign_ids', sub)
  const d = evaluateUniversalPrimitive('access_differential', { control: input.singleForeignControlDenied, variant: input.batchRequest, readback: input.postMutationReadback, persistedDelta: input.foreignMutationPersisted === true, protectedRecordId: foreignId, protectedRecordReturned: new Set((input.returnedForeignIds ?? []).map(normStr)).has(foreignId), protectedDataObserved: input.foreignDataObserved === true, verifySignature: input.verifySignature, labels: { control: 'single_foreign_control', variant: 'batch_request', readback: 'post_mutation_readback' } })
  if (!d.satisfied) return denyVia(f, d, BATCH_REASONS, sub)
  return ok(f, sub, 'batch_partial_authorization_bypass_confirmed', { actorId: input.actor.actorId, ownTenantId: ownTenant, foreignTenantId: foreignTenant, foreignRecordId: foreignId, impactMode: d.subRule === 'mutation' ? 'mutation' : 'read', controlId: input.singleForeignControlDenied.id, batchRequestId: input.batchRequest.id })
}

export function evaluateDualTenantAbac(input: DualTenantAbacInput): V8OracleDecision {
  const f: V8OracleFamily = 'dual_tenant_abac'
  if (!input?.actor || !normStr(input.actor.actorId)) return deny(f, 'missing_actor_identity')
  if (input.mode === 'cross_org_transfer') return evaluateCrossOrgTransfer(input)
  if (input.mode === 'dual_org_cache_bleed') return evaluateDualCacheBleed(input)
  if (input.mode === 'batch_partial_authz') return evaluateBatchPartialAuthz(input)
  return deny(f, 'unknown_dual_tenant_mode')
}

/* temporal_revocation → access_differential (time boundary: post-revocation denied primary vs. accepted secondary). */
export interface TemporalRevocationInput extends WithVerifier {
  credentialKind: 'token' | 'session' | 'role' | 'invite' | 'pat' | 'async_job' | 'webhook_callback'
  credentialHandle?: string | null; actorId?: string | null; primarySurface: V8SurfaceKind; secondarySurface: V8SurfaceKind
  preRevocationBaseline?: HostSignedRecord; revocationEvent: HostSignedRecord; primaryDeniedCheck: HostSignedRecord; secondarySuccess: HostSignedRecord; elevatedRoleGranted?: boolean
}
const TEMPORAL_REASONS: Readonly<Record<string, string>> = { control_not_denied: 'primary_surface_not_revoked', variant_rejected: 'secondary_surface_properly_revoked', variant_precedes_control: 'secondary_access_precedes_verified_revocation', terminal_impact_unproven_intermediate_stub: 'secondary_success_lacks_substantive_impact', protected_data_not_returned_or_mutated: 'secondary_success_lacks_substantive_impact' }
export function evaluateTemporalRevocation(input: TemporalRevocationInput): V8OracleDecision {
  const f: V8OracleFamily = 'temporal_revocation'
  if (!input) return deny(f, 'missing_input')
  const sub = input.credentialKind, rev = input.revocationEvent, prim = input.primaryDeniedCheck, sec = input.secondarySuccess
  const pairs: [HostSignedRecord | undefined, string][] = [[rev, 'revocation_event'], [prim, 'primary_denied_check'], [sec, 'secondary_success']]
  if (input.preRevocationBaseline) pairs.push([input.preRevocationBaseline, 'pre_revocation_baseline'])
  const recErr = checkRecords(pairs, input.verifySignature); if (recErr) return deny(f, recErr, sub)
  if (input.preRevocationBaseline) {
    if (!isOk(input.preRevocationBaseline.status)) return deny(f, 'baseline_not_active', sub)
    if (tsOf(rev) < tsOf(input.preRevocationBaseline)) return deny(f, 'non_monotonic_revocation_timestamp', sub)
  }
  if (!isOk(rev.status)) return deny(f, 'revocation_event_not_confirmed', sub)
  if (rev.id === prim.id || rev.id === sec.id || prim.id === sec.id) return deny(f, 'temporal_reuses_exchange_id', sub)
  if (!isDenied(prim.status)) return deny(f, 'primary_surface_not_revoked', sub)
  if (rev.method && isReadMethodStr(rev.method)) return deny(f, 'revocation_event_not_mutating', sub)
  if (!isOk(sec.status)) return deny(f, 'secondary_surface_properly_revoked', sub)
  if (tsOf(prim) < tsOf(rev)) return deny(f, 'primary_check_precedes_revocation', sub)
  // Time boundary core: post-revocation denied primary (control) vs. accepted secondary (variant).
  const d = evaluateUniversalPrimitive('access_differential', { control: prim, variant: sec, controlPrincipal: 'any', requireChronology: true, protectedDataObserved: input.elevatedRoleGranted === true, verifySignature: input.verifySignature, labels: { control: 'primary_denied_check', variant: 'secondary_success' } })
  if (!d.satisfied && d.reason === 'variant_precedes_control') return denyVia(f, d, TEMPORAL_REASONS, sub)
  // Capability provenance: primary and secondary must be the SAME credential / principal lineage.
  const handle = normStr(input.credentialHandle), actor = normStr(input.actorId)
  const pHandle = normStr(prim.capabilityHandle), sHandle = normStr(sec.capabilityHandle), pActor = normStr(prim.actorId), sActor = normStr(sec.actorId)
  if (handle && ((pHandle && pHandle !== handle) || (sHandle && sHandle !== handle))) return deny(f, 'credential_handle_mismatch', sub)
  const boundByHandle = Boolean(handle && pHandle === handle && sHandle === handle)
  const boundByActor = Boolean(actor && pActor === actor && sActor === actor && (!pHandle || !sHandle || pHandle === sHandle))
  if (!boundByHandle && !boundByActor) return deny(f, 'unlinked_primary_and_secondary_principal', sub)
  const pRoute = normRoute(prim.route), sRoute = normRoute(sec.route)
  if (input.primarySurface === input.secondarySurface && (!pRoute || !sRoute || pRoute === sRoute)) return deny(f, 'secondary_surface_not_distinct_from_primary', sub)
  if (!d.satisfied) return denyVia(f, d, TEMPORAL_REASONS, sub)
  return ok(f, sub, 'revoked_credential_accepted_on_secondary_surface', { credentialKind: sub, primarySurface: input.primarySurface, secondarySurface: input.secondarySurface, revocationEventId: rev.id, primaryDeniedId: prim.id, secondarySuccessId: sec.id, boundBy: boundByHandle ? 'capability_handle' : 'actor_id' })
}

/* economic_conservation → state_delta_and_conservation (4 legacy equations become operand mappings onto one invariant). */
interface EconomicBase extends WithVerifier { baselineReadback: HostSignedRecord; actions: readonly HostSignedRecord[]; finalReadback: HostSignedRecord; tolerance?: number }
export interface OverRefundInput extends EconomicBase { equation: 'over_refund'; paidAmount: number; refundedAmounts: readonly number[]; baselineRefunded?: number }
export interface BalanceMintingInput extends EconomicBase { equation: 'balance_minting'; balancesBefore: Readonly<Record<string, number>>; balancesAfter: Readonly<Record<string, number>>; authorizedDeposits: number; authorizedWithdrawals?: number }
export interface UnderpaidFulfillmentInput extends EconomicBase { equation: 'underpaid_fulfillment'; paidAmount: number; fulfilledValue: number; fulfillmentState: string }
export interface IneligibleDiscountInput extends EconomicBase { equation: 'ineligible_discount'; subtotalAmount: number; requiredThreshold: number; discountApplied: number; finalTotalPaid?: number }
/** Domain-free equation: host-evaluated `$Q` (JSONPath) calibrated against a benign serial control delta. */
export interface QuantityConservationInput extends EconomicBase { equation: 'quantity_conservation'; quantitySelector?: string; quantityBefore?: number; quantityAfter?: number; controlDelta?: number; authorizedDelta?: number }
export type EconomicConservationInput = OverRefundInput | BalanceMintingInput | UnderpaidFulfillmentInput | IneligibleDiscountInput | QuantityConservationInput
function sumFiniteMap(map: Readonly<Record<string, number>> | null | undefined): number | null {
  if (!map || typeof map !== 'object') return null
  const vals = Object.values(map); if (vals.length === 0) return null
  let total = 0; for (const v of vals) { if (!Number.isFinite(v)) return null; total += v }
  return total
}
/** Map a legacy equation onto `(before, after, authorizedDelta)` of the universal quantity invariant. */
function economicOperands(input: EconomicConservationInput): { before: number; after: number; authorized: number; conserved: string; violated: string; evidence: Record<string, unknown> } | string {
  if (input.equation === 'over_refund') {
    const baseRef = input.baselineRefunded ?? 0
    if (!allFiniteNonNeg(input.paidAmount, baseRef)) return 'invalid_refund_parameters'
    if (!Array.isArray(input.refundedAmounts) || input.refundedAmounts.length === 0) return 'missing_refunded_amounts'
    let total = 0; for (const amt of input.refundedAmounts) { if (!allFiniteNonNeg(amt)) return 'invalid_refund_amount'; total += amt }
    return { before: 0, after: total, authorized: Math.max(input.paidAmount, baseRef), conserved: 'refund_ledger_conserved', violated: 'over_refund_conservation_violated', evidence: { paidAmount: input.paidAmount, totalRefunded: total, excessRefunded: Number((total - input.paidAmount).toFixed(6)) } }
  }
  if (input.equation === 'balance_minting') {
    const beforeSum = sumFiniteMap(input.balancesBefore), afterSum = sumFiniteMap(input.balancesAfter), deposits = input.authorizedDeposits, withdrawals = input.authorizedWithdrawals ?? 0
    if (beforeSum === null || afterSum === null) return 'invalid_balance_snapshot'
    if (!allFiniteNonNeg(deposits, withdrawals)) return 'invalid_deposit_or_withdrawal'
    return { before: beforeSum, after: afterSum, authorized: deposits - withdrawals, conserved: 'balance_ledger_conserved', violated: 'balance_conservation_violated_value_minted', evidence: { beforeSum, afterSum, authorizedDeposits: deposits, authorizedWithdrawals: withdrawals, mintedDelta: Number((afterSum - (beforeSum + deposits - withdrawals)).toFixed(6)) } }
  }
  if (input.equation === 'underpaid_fulfillment') {
    if (!allFiniteNonNeg(input.paidAmount) || !Number.isFinite(input.fulfilledValue) || input.fulfilledValue <= 0) return 'invalid_fulfillment_amounts'
    const state = normKey(input.fulfillmentState); if (!FINALIZED_STATES.has(state)) return 'order_not_finalized'
    return { before: 0, after: input.fulfilledValue, authorized: input.paidAmount, conserved: 'fulfillment_payment_conserved', violated: 'underpaid_fulfillment_conservation_violated', evidence: { paidAmount: input.paidAmount, fulfilledValue: input.fulfilledValue, shortfall: Number((input.fulfilledValue - input.paidAmount).toFixed(6)), fulfillmentState: state } }
  }
  if (input.equation === 'ineligible_discount') {
    if (!allFiniteNonNeg(input.subtotalAmount, input.discountApplied) || !Number.isFinite(input.requiredThreshold) || input.requiredThreshold <= 0) return 'invalid_discount_parameters'
    if (input.subtotalAmount + (input.tolerance ?? DEFAULT_TOL) >= input.requiredThreshold) return 'discount_threshold_satisfied_eligible'
    return { before: 0, after: input.discountApplied, authorized: 0, conserved: 'ineligible_discount_not_applied', violated: 'ineligible_discount_applied_below_threshold', evidence: { subtotalAmount: input.subtotalAmount, requiredThreshold: input.requiredThreshold, discountApplied: input.discountApplied } }
  }
  return 'unknown_economic_equation'
}
export function evaluateEconomicConservation(input: EconomicConservationInput): V8OracleDecision {
  const f: V8OracleFamily = 'economic_conservation'
  if (!input) return deny(f, 'missing_input')
  const sub = input.equation
  if (sub === 'quantity_conservation') {
    const d = evaluateUniversalPrimitive('state_delta_and_conservation', { ...input, structuralOnly: false })
    return d.satisfied ? ok(f, sub, d.reason, d.evidence ?? {}) : deny(f, d.reason, sub, d.evidence)
  }
  const winErr = checkConservationWindow(input); if (winErr) return deny(f, winErr, sub)
  const ops = economicOperands(input)
  if (typeof ops === 'string') return deny(f, ops, ops === 'unknown_economic_equation' ? undefined : sub, ops === 'order_not_finalized' ? { fulfillmentState: normKey((input as UnderpaidFulfillmentInput).fulfillmentState) } : undefined)
  const tol = input.tolerance ?? DEFAULT_TOL, inv = evaluateQuantityInvariant(ops.before, ops.after, [ops.authorized], tol)
  if (!inv?.violated) return deny(f, ops.conserved, sub, ops.evidence)
  if (input.equation === 'ineligible_discount' && input.finalTotalPaid !== undefined && (!allFiniteNonNeg(input.finalTotalPaid) || input.finalTotalPaid > input.subtotalAmount - input.discountApplied + tol || input.finalTotalPaid >= input.subtotalAmount - tol)) return deny(f, 'discount_not_reflected_in_final_total', sub)
  return ok(f, sub, ops.violated, { ...ops.evidence, baselineId: input.baselineReadback.id, finalReadbackId: input.finalReadback.id })
}

/* cryptographic_scope_replay → access_differential (tampered-signature control denied vs. replayed valid signature accepted). */
export interface CryptographicScopeReplayInput extends WithVerifier {
  tamperedSignatureControl: HostSignedRecord; sourceValidIssuance: HostSignedRecord; replayedAcceptance: HostSignedRecord
  sourceTenant: string; sourceScope: string; targetTenant: string; targetScope: string; sourceSignedResource?: string; targetSignedResource?: string
  tamperedSignatureDigest?: string; signatureDigest?: string; replayedSignatureDigest?: string; persistedImpact?: boolean
}
const CRYPTO_REASONS: Readonly<Record<string, string>> = { control_not_denied: 'signature_verification_not_enforced_decoy', variant_rejected: 'replayed_signature_rejected_hardened', control_reuses_variant_exchange: 'control_reuses_probe_exchange', control_and_variant_route_mismatch: 'tampered_control_and_replay_route_mismatch', terminal_impact_unproven_intermediate_stub: 'terminal_impact_unproven_intermediate_stub', protected_data_not_returned_or_mutated: 'replay_acceptance_lacks_substantive_impact' }
function cryptoScopeError(input: CryptographicScopeReplayInput): string | null {
  const srcT = normKey(input.sourceTenant), srcS = normKey(input.sourceScope), dstT = normKey(input.targetTenant), dstS = normKey(input.targetScope)
  if (!srcT || !srcS || !dstT || !dstS) return 'missing_tenant_or_scope_context'
  const sRec = input.sourceValidIssuance, rRec = input.replayedAcceptance, sRoute = normRoute(sRec.route), rRoute = normRoute(rRec.route)
  const sDim = deriveRecordAuthzDimension(sRec), rDim = deriveRecordAuthzDimension(rRec)
  const sSignedRes = normKey(input.sourceSignedResource) || sDim.issuedSignedResource || (sRoute && rRoute && sRoute === rRoute ? sDim.requestSignedResource : '')
  const rSignedRes = normKey(input.targetSignedResource) || rDim.requestSignedResource
  const callerDiff = normKey(sRec.actorId) !== normKey(rRec.actorId) || normKey(sRec.tenantId) !== normKey(rRec.tenantId), routeDiff = Boolean(sRoute && rRoute && sRoute !== rRoute)
  const sameReason = callerDiff || routeDiff ? 'same_principal_not_replay' : 'same_tenant_and_scope_not_replay'
  if (srcT === dstT && srcS === dstS) return sameReason
  const sameRespTenants = sDim.responseTenants.size === rDim.responseTenants.size && [...sDim.responseTenants].every(m => rDim.responseTenants.has(m))
  const hasRespTenantDiff = Boolean(sDim.tenant && rDim.responseTenants.size > 0 && !sameRespTenants && !rDim.responseTenants.has(sDim.tenant))
  const hasRespScopeDiff = Boolean(sDim.responseScope && rDim.responseScope && sDim.responseScope !== rDim.responseScope)
  const sameMethod = !normKey(sRec.method) || !normKey(rRec.method) || normKey(sRec.method) === normKey(rRec.method)
  if (sSignedRes && rSignedRes && sSignedRes === rSignedRes && (Boolean(sDim.issuedSignedResource) || sameMethod) && !hasRespTenantDiff && !hasRespScopeDiff) return sameReason
  if (srcT === dstT && !sSignedRes && !hasRespTenantDiff && !hasRespScopeDiff && routeDiff && (srcS === sRoute || srcS.endsWith(`:${sRoute}`)) && (dstS === rRoute || dstS.endsWith(`:${rRoute}`))) return 'same_principal_not_replay'
  const tamperedDigest = normStr(input.tamperedSignatureDigest), validDigest = normStr(input.signatureDigest), replayedDigest = normStr(input.replayedSignatureDigest)
  if (!tamperedDigest || !validDigest || !replayedDigest) return 'missing_signature_digest_binding'
  if (tamperedDigest === validDigest) return 'tampered_digest_matches_valid_signature'
  return replayedDigest !== validDigest ? 'replayed_signature_digest_mismatch' : null
}
export function evaluateCryptographicScopeReplay(input: CryptographicScopeReplayInput): V8OracleDecision {
  const f: V8OracleFamily = 'cryptographic_scope_replay'
  if (!input) return deny(f, 'missing_input')
  const recErr = checkRecords([[input.tamperedSignatureControl, 'tampered_signature_control'], [input.sourceValidIssuance, 'source_valid_issuance'], [input.replayedAcceptance, 'replayed_acceptance']], input.verifySignature)
  if (recErr) return deny(f, recErr)
  const t = input.tamperedSignatureControl, s = input.sourceValidIssuance, r = input.replayedAcceptance
  if (!isDenied(t.status)) return deny(f, 'signature_verification_not_enforced_decoy', undefined, { tamperedStatus: t.status })
  if (!isOk(s.status)) return deny(f, 'source_signature_issuance_failed')
  if (!isOk(r.status)) return deny(f, 'replayed_signature_rejected_hardened')
  if (s.id === r.id) return deny(f, 'issuance_and_replay_same_exchange')
  if (t.id === s.id || t.id === r.id) return deny(f, 'control_reuses_probe_exchange')
  if (tsOf(r) < tsOf(s)) return deny(f, 'replay_precedes_signature_issuance')
  const tRoute = normRoute(t.route), rRoute = normRoute(r.route)
  if (tRoute && rRoute && tRoute !== rRoute) return deny(f, 'tampered_control_and_replay_route_mismatch')
  const scopeErr = cryptoScopeError(input); if (scopeErr) return deny(f, scopeErr)
  // Persisted replay impact is host-attested; otherwise the access_differential read-impact gate decides.
  const d = evaluateUniversalPrimitive('access_differential', { control: t, variant: r, controlPrincipal: 'any', bindRoute: true, protectedDataObserved: input.persistedImpact === true, verifySignature: input.verifySignature, labels: { control: 'tampered_signature_control', variant: 'replayed_acceptance' } })
  if (!d.satisfied && !(input.persistedImpact === true && (d.reason === 'terminal_impact_unproven_intermediate_stub' || d.reason === 'masked_read_without_protected_data'))) return denyVia(f, d, CRYPTO_REASONS)
  const srcT = normKey(input.sourceTenant), dstT = normKey(input.targetTenant)
  return ok(f, srcT !== dstT ? 'cross_tenant_scope_replay' : 'cross_scope_replay', 'valid_signature_replayed_across_scope_boundary', { sourceTenant: srcT, sourceScope: normKey(input.sourceScope), targetTenant: dstT, targetScope: normKey(input.targetScope), signatureDigest: normStr(input.signatureDigest), tamperedControlId: t.id, sourceIssuanceId: s.id, replayedAcceptanceId: r.id })
}

/* parser_cache_differential → wire_framing_and_cache_differential. */
export interface ParserDifferentialInput extends WithVerifier {
  mode: 'parser_differential'; differentialKind: 'duplicate_json_key' | 'path_normalization' | 'header_normalization' | 'hop_by_hop_smuggling' | 'content_type_confusion'
  differentialFeature: string; canonicalValue?: string; variantValue?: string; impactKind: 'read' | 'mutation'
  cleanControl: HostSignedRecord; differentialProbe: HostSignedRecord; isolatedControl?: boolean; postMutationReadback?: HostSignedRecord; mutationPersisted?: boolean; unauthorizedDigest?: string
}
export interface CachePrimedDifferentialInput extends WithVerifier {
  mode: 'cache_primed'; cacheKey: string; victimArtifactDigest: string; cleanControl: HostSignedRecord; cleanControlContainsVictimData?: boolean
  /** @deprecated Ignored: cache bleed is proven by the victim-matched digest + control ablation, not by `X-Cache: HIT`. */
  cacheHitObserved?: boolean
  victimOrPrimeRequest: HostSignedRecord; attackerProbe: HostSignedRecord; isolatedControl?: boolean
}
export type ParserCacheDifferentialInput = ParserDifferentialInput | CachePrimedDifferentialInput
const PARSER_REASONS: Readonly<Record<string, string>> = { no_wire_differential_between_control_and_variant: 'no_request_differential_between_control_and_probe', control_not_denied: 'clean_control_not_denied', variant_rejected: 'differential_probe_rejected', control_and_variant_method_mismatch: 'control_and_probe_method_mismatch', control_and_variant_actor_mismatch: 'control_and_probe_actor_mismatch', control_and_variant_route_mismatch: 'control_and_probe_route_mismatch', variant_precedes_control: 'probe_precedes_clean_control', readback_failed: 'mutation_readback_failed', readback_precedes_variant: 'mutation_readback_precedes_probe', variant_artifact_already_in_control: 'probe_artifact_already_in_control' }
const CACHE_PRIMED_REASONS: Readonly<Record<string, string>> = { prime_failed: 'victim_prime_failed', variant_rejected: 'attacker_probe_rejected', control_and_variant_route_mismatch: 'clean_control_and_attacker_route_mismatch', prime_precedes_control: 'prime_precedes_clean_control', variant_precedes_prime: 'attacker_probe_precedes_cache_prime', principals_not_distinct: 'victim_and_attacker_not_distinct', variant_did_not_receive_victim_artifact: 'attacker_did_not_receive_victim_artifact' }
export function evaluateParserCacheDifferential(input: ParserCacheDifferentialInput): V8OracleDecision {
  const f: V8OracleFamily = 'parser_cache_differential'
  if (!input) return deny(f, 'missing_input')
  if (input.mode === 'parser_differential') {
    const sub = input.differentialKind
    if (!normStr(input.differentialFeature)) return deny(f, 'missing_differential_feature', sub)
    const d = evaluateUniversalPrimitive('wire_framing_and_cache_differential', { property: sub, control: input.cleanControl, variant: input.differentialProbe, controlWireValue: input.canonicalValue, variantWireValue: input.variantValue, impactKind: input.impactKind, readback: input.postMutationReadback, persistedDelta: input.mutationPersisted, unauthorizedDigest: input.unauthorizedDigest, isolatedControl: input.isolatedControl, bindActor: true, verifySignature: input.verifySignature, labels: { control: 'clean_control', variant: 'differential_probe', readback: 'post_mutation_readback' } })
    if (!d.satisfied) return denyVia(f, d, PARSER_REASONS, sub)
    return ok(f, sub, 'parser_differential_bypass_confirmed', { differentialKind: sub, differentialFeature: input.differentialFeature, impactKind: input.impactKind, cleanControlId: input.cleanControl.id, differentialProbeId: input.differentialProbe.id })
  }
  if (input.mode === 'cache_primed') {
    const sub = input.mode, victimDigest = normStr(input.victimArtifactDigest)
    if (!normStr(input.cacheKey)) return deny(f, 'missing_cache_key', sub)
    if (!victimDigest) return deny(f, 'missing_victim_artifact_digest', sub)
    const d = evaluateUniversalPrimitive('wire_framing_and_cache_differential', { property: 'cache_priming', control: input.cleanControl, prime: input.victimOrPrimeRequest, variant: input.attackerProbe, victimDigest, controlContainsVictimData: input.cleanControlContainsVictimData, requireDistinctPrincipals: true, bindActor: true, isolatedControl: input.isolatedControl, verifySignature: input.verifySignature, labels: { control: 'clean_control', prime: 'victim_prime', variant: 'attacker_probe' } })
    if (!d.satisfied) return denyVia(f, d, CACHE_PRIMED_REASONS, sub)
    return ok(f, sub, 'cache_primed_cross_principal_bleed_confirmed', { cacheKey: input.cacheKey, victimArtifactDigest: victimDigest, cleanControlId: input.cleanControl.id, victimPrimeId: input.victimOrPrimeRequest.id, attackerProbeId: input.attackerProbe.id })
  }
  return deny(f, 'unknown_parser_cache_mode')
}

/* cross_surface_pivot → causal_dag (backwards-compat delegator; the CompositeProofReceipt DAG owns verification). */
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
 * (`causal_dag`: `surfaces.size >= 2` over verified causal edges). Standalone calls outside the DAG fail closed.
 */
export function evaluateCrossSurfacePivot(input: CrossSurfacePivotInput): V8OracleDecision {
  const f: V8OracleFamily = 'cross_surface_pivot'
  const sub = input?.terminalImpact?.kind
  const hops = Array.isArray(input?.hops) ? input.hops : []
  const lastHop = hops[hops.length - 1]
  if (lastHop?.record && stubRec(lastHop.record)) return deny(f, 'terminal_impact_unproven_intermediate_stub', sub)
  if (hops.length < 2) return deny(f, 'invalid_hop_count', sub)
  if (distinctSurfaceCount(hops.map(h => h?.surface)) < 2) return deny(f, 'single_surface_not_cross_surface_pivot', sub)
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
