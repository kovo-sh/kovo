/**
 * Host-transcript hydration for v8 extended oracle families and logical-key matching
 * for `state_transition_binding`.
 *
 * Pure, deterministic, fail-closed helpers. Verification scripts only observe exchange IDs
 * (`"gx-..."`) and can never know host HMAC signatures; this module resolves exchange-ID
 * references strictly against the host-signed transcript, allowlists ONLY safe structural
 * identifiers from `rawInput`, and derives all numeric operands, digests, tenant markers,
 * and boolean impact predicates exclusively from host-recorded transcript records.
 */
import { createHash } from 'node:crypto'
import { parseBodyFromCarrierText, type WireCredentialProvenance } from './host-fact-log.ts'
import { ROLE_RANK, normalizeRole, parseRoleMemberships, resolvePersonaIdentity, stepReadsState, type RoleName } from './oracle-invariants.ts'
import type { ProofReceipt } from './proof-receipt.ts'
import { deriveRecordAuthzDimension, extractIssuedSignedUrl, extractTenantMarkers, findNonErrorBatchRecord, isJobOrHandleStub, type HostAuthzDimension, type HostSignedRecord, type V8OracleFamily } from './v8-oracle-families.ts'
import { buildTerminalClassContractMap, resolveTerminalContractKind, type OracleTerminalContractKind } from './oracle-spec.ts'
import { extractLedgerBalanceMap, hydrateBalanceMintingOperands, isControlDeniedAction, normalizeTerminalVulnClass, resolveEconomicActionRecords, resolveEntityLessReadStateTransition, resolveOpaqueDualCacheBleedTarget, selectAutoEconomicActions } from './own-org-terminal-guard.ts'

export interface HydratableEntry {
  exchangeId: string; op?: string; seq?: number; timestampMs?: number
  actorPersona?: string | null; actorRoleLabel?: string | null; actorTenant?: string | null; actorPrivilege?: RoleName | null
  emittedCapabilities?: readonly string[]; observedResponseDigests?: readonly string[]; consumedCapabilities?: readonly string[]; injectedRequestDigests?: readonly string[]
  cryptoAttestations?: readonly { derivedFromCapabilityId: string; derivedCapabilityId?: string; artifactDigest?: string }[]
  entityId?: string; correlationIds?: readonly string[]; carrierText?: string; hostSignature?: string; evidenceRole?: string
  raceBatchId?: string | null; sessionId?: string | null; consumedCapabilityId?: string | null; wireCredentialProvenance?: Readonly<WireCredentialProvenance> | null
  step: { arm: string; method: string; route?: string; pathAndQuery?: string; status: number | null; actor: { handle?: string | null; role?: string | null; tenant?: string | null; auth?: string }; body?: string; json?: unknown; requestJson?: unknown; requestHeaders?: Record<string, string> | null; responseHeaders?: Record<string, string> | null; evidenceRole?: string }
}
export interface HydratableOobEvent { id: string; delivered: boolean; receivedAtMs?: number; token?: string; emittedCapabilities?: readonly string[]; observedValueDigests?: readonly string[]; hostSignature?: string }
export interface HydratableBrowserTrace { id: string; timestampMs?: number; actorPersona?: string | null; emittedCapabilities?: readonly string[]; observedValueDigests?: readonly string[]; hostSignature?: string }
export interface HydratableTranscriptIndex { entriesById: ReadonlyMap<string, HydratableEntry>; oobById?: ReadonlyMap<string, HydratableOobEvent>; tracesById?: ReadonlyMap<string, HydratableBrowserTrace>; personaRoleLabels?: Readonly<Record<string, string>> }
export interface EconomicAutoHydrateContext { preChainControlExchangeIds: readonly string[]; termHopExchangeIds: readonly string[]; postChainReadbackExchangeIds: readonly string[]; citedExchangeIds?: readonly string[]; personaRoleLabels?: Readonly<Record<string, string>> }

const sha256Hex = (value: string): string => createHash('sha256').update(value, 'utf8').digest('hex')
const isFiniteTs = (ts: unknown): ts is number => typeof ts === 'number' && Number.isFinite(ts) && ts >= 0
const isPosTs = (ts: unknown): ts is number => typeof ts === 'number' && Number.isFinite(ts) && ts > 0
const is2xx = (st: number | null | undefined): boolean => typeof st === 'number' && st >= 200 && st < 300
const actorOfEntry = (e: HydratableEntry): string | null =>
  e.actorPersona !== undefined ? e.actorPersona : (e.step.actor.handle ?? null)
export const resolveEntryIdentity = (e: HydratableEntry) => resolvePersonaIdentity({ roleLabel: e.actorRoleLabel ?? (e.actorTenant === undefined && !e.step.actor.tenant ? e.actorPersona ?? null : null), tenantRef: e.actorTenant ?? e.step.actor.tenant ?? null, privilege: e.actorPrivilege ?? e.step.actor.role ?? null, handle: e.actorPersona ?? e.step.actor.handle ?? null })
const roleOfEntry = (e: HydratableEntry): string | null => resolveEntryIdentity(e).role

const PRIV_HANDLE_RE = /^(?:admin|owner|super_?admin|org_?admin|tenant_?admin|root|system|manager|operator|staff|superuser)(?:[_-]|$)|(?:^|[_-])(?:super_?admin|org_?admin|tenant_?admin|owner|root)$/i
const PRIV_ROLE_WORD_RE = /(?:^|[^a-z])(owner|superadmin|super|admin|administrator|manager|staff|operator|root|superuser)(?:$|[^a-z])/i
const GLOBAL_PRIV_LABEL_RE = /(?:^|[\s,:;_@(-])(?:super[\s_-]?admin|platform[\s_-]?admin|sys[\s_-]?admin|global[\s_-]?admin|root|superuser|owner)(?:$|[\s,:;_@)-])/i
const LOW_PRIV_ROLE_SET = new Set(['viewer', 'member', 'guest', 'user', 'editor', 'customer', 'anon', 'anonymous', 'unauthenticated', 'revoked', 'demoted', 'readonly', 'basic', 'standard', 'contractor', 'external', 'analyst', 'billing', 'support', 'developer', 'contributor', 'requester', 'reporter', 'subscriber', 'client', 'partner', 'tenant'])
const MIN_TOKEN_LEN = 3
const SIG_HEADER_NAMES = new Set(['x-sig', 'x-signature', 'x-hmac-signature', 'x-hub-signature-256', 'x-webhook-signature', 'x-kovo-derivation'])
const SURFACE_SET = new Set(['http', 'graphql', 'ws', 'sse', 'browser', 'webhook', 'async_job', 'idp', 'cdn', 'storage'])
const DUAL_MODE_SET = new Set(['cross_org_transfer', 'dual_org_cache_bleed', 'batch_partial_authz'])
const CRED_KIND_SET = new Set(['token', 'session', 'role', 'invite', 'pat', 'async_job', 'webhook_callback'])
const ECON_EQ_SET = new Set(['over_refund', 'balance_minting', 'underpaid_fulfillment', 'ineligible_discount'])
const PARSER_MODE_SET = new Set(['parser_differential', 'cache_primed'])
const CACHE_PRIMED_MODE_ALIASES = new Set(['cache_poisoning', 'cache_deception', 'cache_bleed', 'cache_priming'])
const DIFF_KIND_SET = new Set(['duplicate_json_key', 'path_normalization', 'header_normalization', 'hop_by_hop_smuggling', 'content_type_confusion'])
const IMPACT_KIND_SET = new Set(['read', 'mutation'])
const PIVOT_CTRL_SET = new Set(['authz_denied', 'unreachable_internal'])
const FORBIDDEN_KEYS = new Set(['__proto__', 'constructor', 'prototype'])

function parseExtendedRole(raw: string | null | undefined): 'owner' | 'admin' | 'low' | 'unknown' | null {
  if (!raw) return null
  const head = raw.replace(/\[[^\]]*\]/g, ' ').replace(/\([^)]*\)/g, ' ').trim()
  if (!head) return null
  const norm = head.toLowerCase().replace(/[_-]+/g, ' ').trim()
  if (!norm) return null
  if (/(?:^|\s)(?:owner|super\s*admin|superadmin|root|superuser)(?:\s|$)/.test(norm)) return 'owner'
  if (/(?:^|\s)(?:admin|administrator|manager|staff|operator)(?:\s|$)/.test(norm)) return 'admin'
  const nr = normalizeRole(norm)
  if (nr === 'owner') return 'owner'
  if (nr === 'admin') return 'admin'
  if (nr === 'member' || nr === 'viewer') return 'low'
  const words = norm.split(/\s+/).filter(Boolean)
  if (words.length > 0 && words.every(w => LOW_PRIV_ROLE_SET.has(w))) return 'low'
  return PRIV_ROLE_WORD_RE.test(norm) ? 'admin' : 'unknown'
}

/**
 * Fail-closed privilege classifier (H-11).
 * Forbids privileged handles (`owner_*`, `admin_*`, `super_admin`, `org_admin`, `manager`, ...),
 * `owner` / `super_admin` / `manager` / unknown unrecognized roles, single-tenant `admin`,
 * dual-`admin`, and multi-tenant `admin` probing a `targetTenant` where it holds `admin`/`owner`.
 * Allows multi-tenant personas holding `admin` in one tenant and a low-privilege role in at least
 * one distinct non-admin tenant (unless `targetTenant` is one of its admin tenants).
 */
export function isPrivilegedActorOrRole(
  actor: string | null,
  role: string | null,
  actorRoleLabel?: string | null,
  targetTenant?: string | null,
): boolean {
  if (actor && PRIV_HANDLE_RE.test(actor.trim())) return true
  const rawRoleCls = parseExtendedRole(role)
  if (rawRoleCls === 'owner' || rawRoleCls === 'unknown') return true
  const memberships = actorRoleLabel ? parseRoleMemberships(actorRoleLabel) : []
  if (memberships.some(m => m.role === 'owner')) return true
  const labelHead = actorRoleLabel ? actorRoleLabel.replace(/\[[^\]]*\]/g, ' ').trim() : ''
  if (labelHead && GLOBAL_PRIV_LABEL_RE.test(labelHead)) return true
  if (labelHead && memberships.length === 0) {
    const labelCls = parseExtendedRole(labelHead)
    if (labelCls === 'owner' || labelCls === 'admin' || (labelCls === 'unknown' && rawRoleCls !== 'low')) return true
  }
  const hasAdmin = rawRoleCls === 'admin' || memberships.some(m => m.role === 'admin')
  if (!hasAdmin) return false
  const adminTenants = new Set(memberships.filter(m => m.role === 'admin' && m.tenant).map(m => m.tenant!.toLowerCase()))
  const lowPrivTenants = new Set(
    memberships
      .filter(m => (m.role === 'member' || m.role === 'viewer') && m.tenant && !adminTenants.has(m.tenant.toLowerCase()))
      .map(m => m.tenant!.toLowerCase()),
  )
  const distinctTenants = new Set(memberships.filter(m => m.tenant).map(m => m.tenant!.toLowerCase()))
  if (!(distinctTenants.size >= 2 && lowPrivTenants.size >= 1)) return true
  const normTarget = targetTenant?.trim().toLowerCase() ?? ''
  if (normTarget && adminTenants.has(normTarget)) return true
  return false
}

const LOGIN_ROUTE_RE = /(?:^|\/)(?:login|signin|sign-in|authenticate)(?:\/|$)/i
const LOGIN_TENANT_KEYS = new Set([
  'tenant', 'tenantid', 'tenant_id', 'org', 'orgid', 'org_id',
  'orgslug', 'org_slug', 'organization', 'organizationid', 'organization_id',
  'workspace', 'workspaceid', 'workspace_id',
])
const LOGIN_EMAIL_KEYS = new Set(['email', 'useremail', 'user_email', 'username'])

function findFirstStringByKeys(val: unknown, keys: ReadonlySet<string>, depth = 0): string | null {
  if (depth > 3 || val == null || typeof val !== 'object') return null
  if (Array.isArray(val)) {
    for (const item of val) {
      const hit = findFirstStringByKeys(item, keys, depth + 1)
      if (hit) return hit
    }
    return null
  }
  for (const [k, v] of Object.entries(val as Record<string, unknown>)) {
    if (typeof v === 'string' && v.trim() && keys.has(k.toLowerCase())) return v.trim().toLowerCase()
  }
  for (const v of Object.values(val as Record<string, unknown>)) {
    if (v && typeof v === 'object') {
      const hit = findFirstStringByKeys(v, keys, depth + 1)
      if (hit) return hit
    }
  }
  return null
}

export interface CapEmitterOrigin { exchangeId: string; arm: string; isLogin: boolean; actor: string | null; role: string | null; roleLabel: string | null; tenant: string | null }
export interface CapOriginIndex { loginTenantOf(cap: string): string | null; loginActorOf(cap: string): { actor: string | null; role: string | null; roleLabel: string | null } | null; nonProbeOriginActorOf(cap: string): { actor: string | null; role: string | null; roleLabel: string | null } | null; emitterActorOf(cap: string): CapEmitterOrigin | null; actorOf(cap: string): string | null }

export function buildCapOriginIndex(entries: Iterable<HydratableEntry>, anonActorRe: RegExp): CapOriginIndex {
  const isHostOp = (e: HydratableEntry): boolean => e.evidenceRole === 'host_capability_op' || e.evidenceRole === 'host_crypto_op'
  const isLoginEx = (e: HydratableEntry): boolean => !isHostOp(e) && e.step.method.toUpperCase() === 'POST' && is2xx(e.step.status) && LOGIN_ROUTE_RE.test((e.step.route ?? e.step.pathAndQuery ?? '').split('?', 1)[0] ?? '')
  const emitterByCap = new Map<string, HydratableEntry>()
  for (const e of entries) {
    for (const cap of [...(e.emittedCapabilities ?? []), ...(e.cryptoAttestations ?? []).map(a => a.derivedCapabilityId).filter((c): c is string => Boolean(c))]) {
      const prev = emitterByCap.get(cap)
      if (!prev || (isHostOp(prev) && !isHostOp(e)) || (!isLoginEx(prev) && isLoginEx(e))) emitterByCap.set(cap, e)
    }
  }
  const directTenant = (e: HydratableEntry): string | null => { const a = actorOfEntry(e); return (!a || anonActorRe.test(a) || a.startsWith('cap:')) ? null : resolveEntryIdentity(e).tenant }
  const loginTenantOf = (cap: string): string | null => {
    const e = emitterByCap.get(cap); if (!e || !isLoginEx(e)) return null
    return directTenant(e) ?? findFirstStringByKeys(e.step.json, LOGIN_TENANT_KEYS) ?? findFirstStringByKeys(e.step.requestJson, LOGIN_TENANT_KEYS) ?? findFirstStringByKeys(e.step.json, LOGIN_EMAIL_KEYS) ?? findFirstStringByKeys(e.step.requestJson, LOGIN_EMAIL_KEYS)
  }
  const loginActorOf = (cap: string): { actor: string | null; role: string | null; roleLabel: string | null } | null => {
    const e = emitterByCap.get(cap); if (!e || !isLoginEx(e)) return null
    const a = actorOfEntry(e), cleanActor = (!a || anonActorRe.test(a) || a.startsWith('cap:')) ? null : a, r = roleOfEntry(e)
    return (cleanActor || r || e.actorRoleLabel) ? { actor: cleanActor, role: r, roleLabel: e.actorRoleLabel ?? null } : null
  }
  const emitterActorOf = (cap: string, visited = new Set<string>()): CapEmitterOrigin | null => {
    const e = emitterByCap.get(cap); if (!e || visited.has(cap) || visited.size > 8) return null
    visited.add(cap)
    const a = actorOfEntry(e), cleanActor = (!a || anonActorRe.test(a) || a.startsWith('cap:')) ? null : a, r = roleOfEntry(e)
    if (cleanActor || r || e.actorRoleLabel) return { exchangeId: e.exchangeId, arm: e.step.arm, isLogin: isLoginEx(e), actor: cleanActor, role: r, roleLabel: e.actorRoleLabel ?? null, tenant: directTenant(e) }
    for (const parent of [...(a?.startsWith('cap:') ? [a] : []), ...(e.consumedCapabilities ?? []), ...(e.cryptoAttestations ?? []).map(x => x.derivedFromCapabilityId)]) {
      const origin = emitterActorOf(parent, visited); if (origin) return { ...origin, exchangeId: e.exchangeId, arm: e.step.arm, isLogin: isLoginEx(e) || origin.isLogin }
    }
    return { exchangeId: e.exchangeId, arm: e.step.arm, isLogin: isLoginEx(e), actor: null, role: null, roleLabel: null, tenant: null }
  }
  const nonProbeOriginActorOf = (cap: string, visited = new Set<string>()): { actor: string | null; role: string | null; roleLabel: string | null } | null => {
    const e = emitterByCap.get(cap); if (!e || visited.has(cap) || visited.size > 8) return null
    visited.add(cap); if (!isLoginEx(e) && e.step.arm === 'probe') return null
    const origin = emitterActorOf(cap)
    if (origin && (origin.actor || origin.role || origin.roleLabel)) return { actor: origin.actor, role: origin.role, roleLabel: origin.roleLabel }
    return isLoginEx(e) ? null : { actor: 'unattributed', role: 'owner', roleLabel: 'owner (unattributed)' }
  }
  const actorOf = (cap: string, visited = new Set<string>()): string | null => {
    if (visited.has(cap) || visited.size > 8) return null
    visited.add(cap); const e = emitterByCap.get(cap); if (!e) return null
    const a = actorOfEntry(e)?.trim().toLowerCase() ?? ''
    if (a && !anonActorRe.test(a) && !a.startsWith('cap:')) return a
    for (const nc of [...(a.startsWith('cap:') ? [a] : []), ...(e.consumedCapabilities ?? []), ...(e.cryptoAttestations ?? []).map(x => x.derivedFromCapabilityId)]) {
      const hit = actorOf(nc, visited); if (hit) return hit
    }
    return isLoginEx(e) ? (findFirstStringByKeys(e.step.json, LOGIN_EMAIL_KEYS) ?? findFirstStringByKeys(e.step.requestJson, LOGIN_EMAIL_KEYS)) : null
  }
  return { loginTenantOf, loginActorOf, nonProbeOriginActorOf, emitterActorOf: (cap: string) => emitterActorOf(cap), actorOf: (cap: string) => actorOf(cap) }
}

export function isHydratedStub(rec: unknown): boolean {
  if (!rec || typeof rec !== 'object') return false
  const r = rec as HostSignedRecord; return isJobOrHandleStub(r.json, r.body, r.status, r.method, r.route)
}
export function toOracleRecord(e: HydratableEntry, fallbackSig: string): HostSignedRecord {
  return {
    id: e.exchangeId, hostSignature: e.hostSignature ?? fallbackSig, timestampMs: isPosTs(e.timestampMs) ? e.timestampMs : 1,
    status: e.step.status, method: e.step.method, route: e.step.route ?? e.step.pathAndQuery, pathAndQuery: e.step.pathAndQuery,
    actorId: actorOfEntry(e), tenantId: e.step.actor.tenant ?? null, entityId: e.entityId ?? null, body: e.step.body, json: e.step.json,
    requestHeaders: e.step.requestHeaders ?? null, responseHeaders: e.step.responseHeaders ?? null,
    capabilityHandle: e.emittedCapabilities?.[0] ?? e.consumedCapabilities?.[0] ?? null,
    artifactDigest: e.observedResponseDigests?.[0] ?? e.cryptoAttestations?.[0]?.artifactDigest ?? sha256Hex(e.step.body ?? JSON.stringify(e.step.json ?? null)),
    derivedFromCapabilityId: e.cryptoAttestations?.[0]?.derivedFromCapabilityId ?? null,
  }
}
function lookupOracleRecord(id: string, idx: HydratableTranscriptIndex, fallbackSig: string): HostSignedRecord | undefined {
  const entry = idx.entriesById.get(id); if (entry) return toOracleRecord(entry, fallbackSig)
  const oob = idx.oobById?.get(id)
  if (oob) return { id: oob.id, hostSignature: oob.hostSignature ?? fallbackSig, timestampMs: isPosTs(oob.receivedAtMs) ? oob.receivedAtMs : 1, surface: 'webhook', status: oob.delivered ? 200 : 0, capabilityHandle: oob.emittedCapabilities?.[0] ?? null, artifactDigest: oob.observedValueDigests?.[0] ?? (oob.token ? sha256Hex(oob.token) : null) }
  const tr = idx.tracesById?.get(id)
  if (tr) return { id: tr.id, hostSignature: tr.hostSignature ?? fallbackSig, timestampMs: isPosTs(tr.timestampMs) ? tr.timestampMs : 1, surface: 'browser', actorId: tr.actorPersona ?? null, capabilityHandle: tr.emittedCapabilities?.[0] ?? null, artifactDigest: tr.observedValueDigests?.[0] ?? null }
  return undefined
}
export function matchesHydratedRecord(rec: HostSignedRecord, idx: HydratableTranscriptIndex, fallbackSig: string): boolean {
  const ex = lookupOracleRecord(rec.id, idx, fallbackSig); if (!ex) return false
  return rec.hostSignature === ex.hostSignature && rec.timestampMs === ex.timestampMs && rec.status === ex.status && rec.method === ex.method && rec.route === ex.route && rec.body === ex.body && rec.json === ex.json && rec.artifactDigest === ex.artifactDigest && rec.actorId === ex.actorId && rec.tenantId === ex.tenantId && rec.capabilityHandle === ex.capabilityHandle && rec.derivedFromCapabilityId === ex.derivedFromCapabilityId
}
function hydrateRecordValue(raw: unknown, idx: HydratableTranscriptIndex, fallbackSig: string): unknown {
  if (raw === undefined || raw === null) return undefined
  if (typeof raw === 'string') { const id = raw.trim(); return id ? lookupOracleRecord(id, idx, fallbackSig) : undefined }
  if (typeof raw === 'object' && !Array.isArray(raw)) {
    const obj = raw as Record<string, unknown>, id = typeof obj.exchangeId === 'string' && obj.exchangeId.trim() ? obj.exchangeId.trim() : typeof obj.id === 'string' && obj.id.trim() ? obj.id.trim() : ''
    if (!id) return undefined
    const found = lookupOracleRecord(id, idx, fallbackSig); if (found) return found
    return typeof obj.hostSignature === 'string' ? { id, hostSignature: obj.hostSignature, timestampMs: 1 } : undefined
  }
  return undefined
}
function hydrateRoleField(out: Record<string, unknown>, raw: Record<string, unknown>, field: string, idx: HydratableTranscriptIndex, fallbackSig: string, extraAlias?: string): boolean {
  for (const key of [field, `${field}ExchangeId`, ...(extraAlias ? [extraAlias] : [])]) { if (raw[key] !== undefined) { out[field] = hydrateRecordValue(raw[key], idx, fallbackSig); return true } }
  return false
}
function hydrateRecordArrayField(out: Record<string, unknown>, raw: Record<string, unknown>, field: string, aliases: readonly string[], idx: HydratableTranscriptIndex, fallbackSig: string): boolean {
  let src = raw[field]; if (src === undefined) for (const a of aliases) if (raw[a] !== undefined) { src = raw[a]; break }
  if (src === undefined) return false
  if (Array.isArray(src)) out[field] = src.map(item => hydrateRecordValue(item, idx, fallbackSig))
  else if (typeof src === 'string' || (typeof src === 'object' && src !== null)) { const h = hydrateRecordValue(src, idx, fallbackSig); out[field] = h !== undefined ? [h] : [] }
  else out[field] = []
  return true
}

const hasEntryBody = (e: HydratableEntry): boolean =>
  e.step.json !== undefined || (typeof e.step.body === 'string' && e.step.body.trim().length > 0)

const isRecObj = (v: unknown): v is HostSignedRecord =>
  Boolean(v && typeof v === 'object' && !Array.isArray(v) && typeof (v as HostSignedRecord).id === 'string')

const pickStr = (raw: Record<string, unknown>, key: string, max = 256): string | undefined => {
  const v = raw[key]
  if (typeof v !== 'string') return undefined
  const t = v.trim()
  return t.length > 0 && t.length <= max ? t : undefined
}

const pickEnum = (raw: Record<string, unknown>, key: string, allowed: ReadonlySet<string>): string | undefined => {
  const s = pickStr(raw, key, 64)
  return s && allowed.has(s) ? s : undefined
}

const pickFiniteNonNeg = (v: unknown): number | undefined =>
  typeof v === 'number' && Number.isFinite(v) && v >= 0 ? v : undefined

function parseRecJson(rec: HostSignedRecord | undefined): unknown {
  if (!rec) return undefined
  if (rec.json !== undefined) return rec.json
  if (typeof rec.body === 'string') {
    const trimmed = rec.body.trim()
    if (trimmed.startsWith('{') || trimmed.startsWith('[')) {
      try { return JSON.parse(trimmed) } catch { return undefined }
    }
  }
  return undefined
}

function findNumericField(root: unknown, keys: readonly string[]): number | undefined {
  if (root == null || typeof root !== 'object') return undefined
  const keySet = new Set(keys), queue: Array<{ node: unknown; depth: number }> = [{ node: root, depth: 0 }]
  while (queue.length > 0) {
    const { node, depth } = queue.shift()!; if (depth > 4 || node == null || typeof node !== 'object') continue
    if (Array.isArray(node)) { for (const item of node.slice(0, 32)) queue.push({ node: item, depth: depth + 1 }); continue }
    const obj = node as Record<string, unknown>
    for (const k of keys) for (const [ek, ev] of Object.entries(obj)) if (ek.toLowerCase() === k && typeof ev === 'number' && Number.isFinite(ev)) return ev
    for (const [ek, ev] of Object.entries(obj)) if (!keySet.has(ek.toLowerCase()) && ev && typeof ev === 'object') queue.push({ node: ev, depth: depth + 1 })
  }
  return undefined
}
function findStringField(root: unknown, keys: readonly string[]): string | undefined {
  if (root == null || typeof root !== 'object') return undefined
  const queue: Array<{ node: unknown; depth: number }> = [{ node: root, depth: 0 }]
  while (queue.length > 0) {
    const { node, depth } = queue.shift()!; if (depth > 4 || node == null || typeof node !== 'object') continue
    if (Array.isArray(node)) { for (const item of node.slice(0, 32)) queue.push({ node: item, depth: depth + 1 }); continue }
    const obj = node as Record<string, unknown>
    for (const k of keys) for (const [ek, ev] of Object.entries(obj)) if (ek.toLowerCase() === k && typeof ev === 'string' && ev.trim().length > 0) return ev.trim()
    for (const ev of Object.values(obj)) if (ev && typeof ev === 'object') queue.push({ node: ev, depth: depth + 1 })
  }
  return undefined
}
function extractBalanceMap(rec: HostSignedRecord | undefined): Record<string, number> | undefined {
  const json = parseRecJson(rec); if (json == null || typeof json !== 'object') return undefined
  const obj = json as Record<string, unknown>
  for (const mapKey of ['balances', 'accounts', 'wallets']) {
    const sub = obj[mapKey]
    if (sub && typeof sub === 'object' && !Array.isArray(sub)) {
      const map: Record<string, number> = {}; for (const [k, n] of Object.entries(sub as Record<string, unknown>)) if (!FORBIDDEN_KEYS.has(k) && typeof n === 'number' && Number.isFinite(n)) map[k] = n
      if (Object.keys(map).length > 0) return map
    }
    if (Array.isArray(sub)) {
      const map: Record<string, number> = {}
      for (const item of sub.slice(0, 32)) {
        if (!item || typeof item !== 'object' || Array.isArray(item)) continue
        const acct = findStringField(item, ['accountid', 'account_id', 'walletid', 'wallet_id', 'id']), bal = findNumericField(item, ['balance', 'balancecents', 'balance_cents', 'availablebalance', 'available_balance', 'credits', 'funds', 'amount'])
        if (acct && bal !== undefined) map[acct] = bal
      }
      if (Object.keys(map).length > 0) return map
    }
  }
  const single = findNumericField(json, ['balance', 'balancecents', 'balance_cents', 'availablebalance', 'available_balance', 'walletbalance', 'wallet_balance', 'ledgerbalance', 'ledger_balance', 'credits', 'funds'])
  return single !== undefined ? { [findStringField(json, ['accountid', 'account_id', 'walletid', 'wallet_id', 'userid', 'user_id', 'id']) ?? 'default']: single } : extractLedgerBalanceMap(json)
}

function collectJsonStringLeaves(node: unknown, out: Set<string>, depth = 0): void {
  if (depth > 5 || out.size > 256 || node == null) return
  if (typeof node === 'string') { const t = node.trim(); if (t.length > 0 && t.length <= 1024) out.add(t) }
  else if (typeof node === 'number' || typeof node === 'boolean') out.add(String(node))
  else if (Array.isArray(node)) for (const x of node) collectJsonStringLeaves(x, out, depth + 1)
  else if (typeof node === 'object') for (const x of Object.values(node as Record<string, unknown>)) collectJsonStringLeaves(x, out, depth + 1)
}

/** Exact JSON leaf token match with minimum length floor (R2-C-8: never substring/regex scan raw body). */
function recordContainsToken(rec: HostSignedRecord | undefined, token: string): boolean {
  const needle = token.trim()
  if (!rec || needle.length < MIN_TOKEN_LEN) return false
  const leaves = new Set<string>()
  collectJsonStringLeaves(parseRecJson(rec), leaves)
  return leaves.has(needle)
}

/** Exact structural request reference match (entityId, correlationIds, path segment, query value, or requestJson leaf). */
function entryReferencesToken(entry: HydratableEntry | undefined, token: string): boolean {
  const needle = token.trim()
  if (!entry || needle.length < MIN_TOKEN_LEN) return false
  if (entry.entityId === needle || entry.correlationIds?.includes(needle)) return true
  const pq = entry.step.pathAndQuery ?? entry.step.route ?? ''
  if (pq) {
    const [rawPath = '', rawQuery = ''] = pq.split('?', 2)
    for (const seg of rawPath.split('/')) {
      if (seg === needle) return true
      try { if (decodeURIComponent(seg) === needle) return true } catch { /* ignore */ }
    }
    if (rawQuery) {
      for (const v of new URLSearchParams(rawQuery).values()) {
        if (v === needle || v.split(',').map(x => x.trim()).includes(needle)) return true
      }
    }
  }
  const leaves = new Set<string>()
  collectJsonStringLeaves(entry.step.requestJson, leaves)
  return leaves.has(needle)
}

/** Exact structural correlation match (no substring/regex scanning over raw body or carrierText). */
function entryContainsCorrelation(entry: HydratableEntry | undefined, token: string): boolean {
  const needle = token.trim()
  if (!entry || needle.length < MIN_TOKEN_LEN) return false
  if (entry.correlationIds?.includes(needle) || entry.entityId === needle) return true
  if (entryReferencesToken(entry, needle)) return true
  const leaves = new Set<string>()
  collectJsonStringLeaves(entry.step.json, leaves)
  return leaves.has(needle)
}

function deriveHostSurface(entry: HydratableEntry | undefined, rec: HostSignedRecord | undefined): string {
  if (rec?.surface && SURFACE_SET.has(rec.surface)) return rec.surface
  const route = (entry?.step.route ?? entry?.step.pathAndQuery ?? rec?.route ?? '').split('?', 1)[0]!.toLowerCase()
  const respCt = headerLookupCI(entry?.step.responseHeaders ?? rec?.responseHeaders, 'content-type').toLowerCase()
  const reqUp = headerLookupCI(entry?.step.requestHeaders ?? rec?.requestHeaders, 'upgrade').toLowerCase()
  if (/(?:^|\/)graphql(?:\/|$)/.test(route)) return 'graphql'
  if (reqUp === 'websocket' || /(?:^|\/)ws(?:\/|$)/.test(route)) return 'ws'
  if (respCt.includes('text/event-stream') || /(?:^|\/)(?:events|stream)(?:\/|$)/.test(route)) return 'sse'
  if (/(?:^|\/)webhooks?(?:\/|$)/.test(route)) return 'webhook'
  return 'http'
}

const SIG_QUERY_KEYS = new Set(['sig', 'signature', 'hmac', 'mac', 'token', 'x-amz-signature'])
const VOLATILE_DIFF_HEADERS = new Set([
  'host', 'content-length', 'connection', 'user-agent', 'accept', 'accept-encoding',
  'x-request-id', 'x-correlation-id', 'x-trace-id', 'traceparent', 'tracestate', 'date',
])
const INTERNAL_TRANSFER_PAIRS: readonly [string, string][] = [
  ['from', 'to'], ['source', 'destination'], ['fromaccount', 'toaccount'],
  ['sourceaccount', 'destinationaccount'], ['debitaccount', 'creditaccount'],
]

function extractRequestSigDigest(rec: HostSignedRecord | undefined, entry?: HydratableEntry): string | undefined {
  if (rec?.requestHeaders) for (const [k, v] of Object.entries(rec.requestHeaders)) if (SIG_HEADER_NAMES.has(k.toLowerCase()) && typeof v === 'string' && v.trim() && !v.includes('[redacted')) return sha256Hex(v.trim())
  const pq = entry?.step.pathAndQuery ?? rec?.route ?? '', qIdx = pq.indexOf('?')
  if (qIdx >= 0) for (const [k, v] of new URLSearchParams(pq.slice(qIdx + 1)).entries()) if (SIG_QUERY_KEYS.has(k.toLowerCase()) && v.trim() && !v.includes('[redacted')) return sha256Hex(v.trim())
  return undefined
}
function extractIssuedSigDigest(entry: HydratableEntry | undefined): string | undefined {
  if (!entry) return undefined
  const issuedUrl = extractIssuedSignedUrl(entry.step.json, entry.step.body)
  if (issuedUrl && !issuedUrl.includes('[redacted')) {
    const m = /[?&](?:sig|signature|hmac|mac|token|x-amz-signature)=([^&#]+)/i.exec(issuedUrl)
    if (m?.[1]) { try { return sha256Hex(decodeURIComponent(m[1])) } catch { return sha256Hex(m[1]) } }
  }
  const parsed = entry.step.json !== undefined ? entry.step.json : (typeof entry.step.body === 'string' && /^[\[{]/.test(entry.step.body.trim()) ? (() => { try { return JSON.parse(entry.step.body!) } catch { return undefined } })() : undefined)
  if (parsed && typeof parsed === 'object') { const sigVal = findStringField(parsed, ['signature', 'sig', 'hmac', 'mac']); if (sigVal && !sigVal.includes('[redacted')) return sha256Hex(sigVal) }
  return undefined
}
const ANON_HANDLE_RE = /^(?:anon(?:ymous)?|unauth(?:enticated)?|guest)$/i
function extractRequestedActorId(rawInput: Record<string, unknown>): string | undefined {
  for (const key of ['actor', 'actorIdentity', 'actorUserId', 'actorPersona', 'actorId', 'persona'] as const) {
    const val = rawInput[key]
    if (typeof val === 'string' && val.trim() && val.trim().length <= 128) return val.trim()
    if (val && typeof val === 'object' && !Array.isArray(val)) for (const sub of ['actorId', 'persona', 'userId', 'actorUserId', 'handle', 'id'] as const) { const hit = pickStr(val as Record<string, unknown>, sub, 128); if (hit) return hit }
  }
  return undefined
}
function deriveDualActorFromTranscript(idx: HydratableTranscriptIndex, citedEntries: readonly (HydratableEntry | undefined)[], rawInput: Record<string, unknown>, econCtx?: EconomicAutoHydrateContext): { actorId: string; rolesByTenant: Record<string, RoleName> } | undefined {
  const rawId = extractRequestedActorId(rawInput), capIdx = buildCapOriginIndex(idx.entriesById.values(), ANON_HANDLE_RE)
  const resolveEntryActor = (e: HydratableEntry | undefined): string => { const a = e ? actorOfEntry(e)?.trim() ?? '' : ''; return (!a || ANON_HANDLE_RE.test(a)) ? '' : a.startsWith('cap:') ? (capIdx.emitterActorOf(a)?.actor?.trim() ?? capIdx.actorOf(a)?.trim() ?? '') : a }
  let citedActors = citedEntries.map(resolveEntryActor).filter(Boolean)
  if (citedActors.length === 0 && econCtx) citedActors = [...econCtx.termHopExchangeIds, ...(econCtx.citedExchangeIds ?? []), ...econCtx.preChainControlExchangeIds].map(id => resolveEntryActor(idx.entriesById.get(id))).filter(Boolean)
  const actorId = citedActors.length === 0 ? undefined : (rawId ? citedActors.find(a => a.toLowerCase() === rawId.toLowerCase()) : citedActors[0])
  if (!actorId) return undefined
  const rolesByTenant: Record<string, RoleName> = {}, actorLower = actorId.toLowerCase()
  const recordRole = (tenant: string | null | undefined, role: RoleName | null | undefined) => { const t = tenant?.trim().toLowerCase(); if (!t || !role || FORBIDDEN_KEYS.has(t)) return; const prev = rolesByTenant[t]; if (!prev || ROLE_RANK[role] > ROLE_RANK[prev]) rolesByTenant[t] = role }
  const recordMemberships = (label: string | null | undefined, allowSingle: boolean) => { if (!label) return; for (const m of parseRoleMemberships(label)) recordRole(m.tenant, m.role); if (allowSingle) { const idn = resolvePersonaIdentity({ roleLabel: label }); recordRole(idn.tenant, idn.role) } }
  for (const e of idx.entriesById.values()) {
    if (resolveEntryActor(e).toLowerCase() !== actorLower) continue
    const idn = resolveEntryIdentity(e); recordRole(idn.tenant, idn.role)
    if (e.actorRoleLabel && (e.actorRoleLabel.includes('memberships=') || /[,;]/.test(e.actorRoleLabel))) recordMemberships(e.actorRoleLabel, false)
  }
  const needReg = Object.keys(rolesByTenant).length === 0
  for (const reg of [idx.personaRoleLabels, econCtx?.personaRoleLabels]) if (reg) for (const [k, label] of Object.entries(reg)) if (k.trim().toLowerCase() === actorLower) recordMemberships(label, needReg)
  return { actorId, rolesByTenant }
}
const canonicalDiffHeaders = (headers: Readonly<Record<string, string>> | null | undefined): string =>
  !headers ? '' : Object.entries(headers).map(([k, v]) => [k.trim().toLowerCase(), String(v).trim()] as const).filter(([k]) => Boolean(k) && !VOLATILE_DIFF_HEADERS.has(k)).sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0)).map(([k, v]) => `${k}:${v}`).join('\n')
const headerLookupCI = (headers: Readonly<Record<string, string>> | null | undefined, name: string): string => {
  if (!headers) return ''; const target = name.toLowerCase()
  for (const [k, v] of Object.entries(headers)) if (k.trim().toLowerCase() === target) return String(v).trim()
  return ''
}
function rawRequestBodyText(entry: HydratableEntry | undefined): string {
  if (!entry) return ''
  const req = entry.step.requestJson
  if (typeof req === 'string') return req.trim()
  if (req !== undefined && req !== null) { try { return JSON.stringify(req) } catch { return '' } }
  const response = typeof entry.step.body === 'string' ? entry.step.body : entry.step.json !== undefined ? JSON.stringify(entry.step.json) : null
  return parseBodyFromCarrierText(entry.carrierText, entry.step.requestHeaders, response)?.trim() ?? ''
}
function hasDuplicateJsonKeyInRaw(raw: string): boolean {
  const s = raw.trim(); if (!s.startsWith('{') && !s.startsWith('[')) return false
  const stack: Array<Set<string> | null> = []
  for (let i = 0; i < s.length;) {
    const ch = s[i]!
    if (ch === '{') { stack.push(new Set<string>()); i += 1 }
    else if (ch === '[') { stack.push(null); i += 1 }
    else if (ch === '}' || ch === ']') { stack.pop(); i += 1 }
    else if (ch === '"') {
      let j = i + 1; while (j < s.length) { if (s[j] === '\\') { j += 2; continue }; if (s[j] === '"') break; j += 1 }
      const key = s.slice(i + 1, j); let k = j + 1; while (k < s.length && /\s/.test(s[k]!)) k += 1
      const top = stack[stack.length - 1]
      if (s[k] === ':' && top instanceof Set) { if (top.has(key)) return true; top.add(key) }
      i = j + 1
    } else i += 1
  }
  return false
}

function isInternalTransferRequest(request: unknown): boolean {
  if (!request || typeof request !== 'object' || Array.isArray(request)) return false
  const keys = new Set(Object.keys(request as Record<string, unknown>).map(key => key.replace(/[_-]/g, '').toLowerCase()))
  return INTERNAL_TRANSFER_PAIRS.some(([from, to]) => keys.has(from) && keys.has(to))
}

export type V8OracleInferenceResult = { kind: 'matched'; family: V8OracleFamily } | { kind: 'ambiguous'; families: V8OracleFamily[] } | { kind: 'conflicting'; keys: string[] } | { kind: 'unmapped' }
const toCamelKey = (key: string): string => key.replace(/[_-]+([a-zA-Z0-9])/g, (_, ch: string) => ch.toUpperCase())
function sameJsonVal(a: unknown, b: unknown, depth = 0): boolean {
  if (Object.is(a, b)) return true
  if (depth > 6 || a == null || b == null || typeof a !== typeof b || typeof a !== 'object') return false
  if (Array.isArray(a) || Array.isArray(b)) return Array.isArray(a) && Array.isArray(b) && a.length === b.length && a.every((x, i) => sameJsonVal(x, b[i], depth + 1))
  const ka = Object.keys(a as Record<string, unknown>).filter(k => !FORBIDDEN_KEYS.has(k)).sort()
  const kb = Object.keys(b as Record<string, unknown>).filter(k => !FORBIDDEN_KEYS.has(k)).sort()
  return ka.length === kb.length && ka.every((k, i) => k === kb[i] && sameJsonVal((a as Record<string, unknown>)[k], (b as Record<string, unknown>)[k], depth + 1))
}
const isPlainRec = (v: unknown): v is Record<string, unknown> => Boolean(v && typeof v === 'object' && !Array.isArray(v))
function findShallowKeyConflicts(obj: Record<string, unknown>, prefix: string, conflicts: Set<string>): void {
  const seen = new Map<string, unknown>()
  for (const [k, v] of Object.entries(obj)) {
    if (FORBIDDEN_KEYS.has(k) || v === undefined) continue
    const canon = (k.includes('_') || k.includes('-')) ? toCamelKey(k) : k
    if (!canon || FORBIDDEN_KEYS.has(canon)) continue
    if (seen.has(canon)) { if (!sameJsonVal(seen.get(canon), v)) conflicts.add(prefix ? `${prefix}.${canon}` : canon) }
    else seen.set(canon, v)
  }
}
/** Detect conflicting duplicate values across camelCase/snake_case/kebab-case key spellings (fail-closed). */
export function findConflictingOracleInputKeys(rawInput: Record<string, unknown>): string[] {
  const conflicts = new Set<string>()
  findShallowKeyConflicts(rawInput, '', conflicts)
  for (const [k, v] of Object.entries(rawInput)) {
    if (FORBIDDEN_KEYS.has(k) || v == null) continue
    const canon = (k.includes('_') || k.includes('-')) ? toCamelKey(k) : k
    if (canon === 'balancesBefore' || canon === 'balancesAfter') continue
    if (canon === 'hops' && Array.isArray(v)) {
      v.forEach((item, i) => {
        if (!isPlainRec(item)) return
        findShallowKeyConflicts(item, `hops[${i}]`, conflicts)
        for (const [hk, hv] of Object.entries(item)) {
          const hc = (hk.includes('_') || hk.includes('-')) ? toCamelKey(hk) : hk
          if ((hc === 'record' || hc === 'ablationControlDenied') && isPlainRec(hv)) findShallowKeyConflicts(hv, `hops[${i}].${hc}`, conflicts)
        }
      })
    } else if (Array.isArray(v)) {
      v.forEach((item, i) => { if (isPlainRec(item)) findShallowKeyConflicts(item, `${canon}[${i}]`, conflicts) })
    } else if (isPlainRec(v)) {
      findShallowKeyConflicts(v, canon, conflicts)
      if (canon === 'terminalImpact') for (const [tk, tv] of Object.entries(v)) {
        const tc = (tk.includes('_') || tk.includes('-')) ? toCamelKey(tk) : tk
        if (tc === 'postImpactReadback' && isPlainRec(tv)) findShallowKeyConflicts(tv, `terminalImpact.${tc}`, conflicts)
      }
    }
  }
  return [...conflicts]
}
function normalizeShallowRecordKeys(obj: Record<string, unknown>): Record<string, unknown> {
  const out: Record<string, unknown> = {}
  for (const [k, v] of Object.entries(obj)) if (!FORBIDDEN_KEYS.has(k)) out[k] = v
  for (const [k, v] of Object.entries(obj)) {
    if (FORBIDDEN_KEYS.has(k) || (!k.includes('_') && !k.includes('-'))) continue
    const camel = toCamelKey(k); if (camel && !FORBIDDEN_KEYS.has(camel) && out[camel] === undefined) out[camel] = v
  }
  return out
}
const normalizeRecordRefValue = (val: unknown): unknown =>
  (!val || typeof val !== 'object' || Array.isArray(val) || ((val as Record<string, unknown>).exchange_id === undefined && (val as Record<string, unknown>).host_signature === undefined)) ? val : normalizeShallowRecordKeys(val as Record<string, unknown>)

/** Normalize top-level and structural sub-object keys (`snake_case`/`kebab-case` -> `camelCase`) without mutating values or balance-map keys; fails closed (`{}`) on conflicting duplicate keys. */
export function normalizeV8OracleInputKeys(rawInput: Record<string, unknown>): Record<string, unknown> {
  if (findConflictingOracleInputKeys(rawInput).length > 0) return {}
  const out = normalizeShallowRecordKeys(rawInput)
  for (const [k, v] of Object.entries(out)) {
    if (k === 'balancesBefore' || k === 'balancesAfter') continue
    if (k === 'hops' && Array.isArray(v)) {
      out[k] = v.map(item => {
        if (!item || typeof item !== 'object' || Array.isArray(item)) return item
        const nh = normalizeShallowRecordKeys(item as Record<string, unknown>)
        if (nh.record !== undefined) nh.record = normalizeRecordRefValue(nh.record)
        if (nh.ablationControlDenied !== undefined) nh.ablationControlDenied = normalizeRecordRefValue(nh.ablationControlDenied)
        return nh
      })
    } else if ((k === 'terminalImpact' || k === 'actor' || k === 'actorIdentity') && v && typeof v === 'object' && !Array.isArray(v)) {
      const ns = normalizeShallowRecordKeys(v as Record<string, unknown>)
      if (k === 'terminalImpact' && ns.postImpactReadback !== undefined) ns.postImpactReadback = normalizeRecordRefValue(ns.postImpactReadback)
      out[k] = ns
    } else if (Array.isArray(v)) out[k] = v.map(normalizeRecordRefValue)
    else if (v && typeof v === 'object') out[k] = normalizeRecordRefValue(v)
  }
  return out
}

const DUAL_ABAC_INF_KEYS = ['transferRecord', 'transferRecordExchangeId', 'transferExchangeId', 'postTransferReadback', 'postTransferReadbackExchangeId', 'sourceControlDenied', 'sourceControlDeniedExchangeId', 'sourceControlExchangeId', 'baselineDeniedControl', 'baselineDeniedControlExchangeId', 'baselineControlExchangeId', 'primeAction', 'primeActionExchangeId', 'bledAccess', 'bledAccessExchangeId', 'singleForeignControlDenied', 'singleForeignControlDeniedExchangeId', 'singleForeignControlExchangeId', 'batchRequest', 'batchRequestExchangeId', 'sourceTenantId', 'destTenantId', 'observedOwnerTenantId', 'primeTenantId', 'ownTenantId', 'foreignTenantId', 'ownRecordId', 'foreignRecordId', 'returnedForeignIds', 'foreignDataObserved', 'foreignMutationPersisted'] as const
const TEMPORAL_INF_KEYS = ['preRevocationBaseline', 'preRevocationBaselineExchangeId', 'revocationEvent', 'revocationEventExchangeId', 'primaryDeniedCheck', 'primaryDeniedCheckExchangeId', 'secondarySuccess', 'secondarySuccessExchangeId', 'credentialKind', 'credentialHandle', 'primarySurface', 'secondarySurface', 'elevatedRoleGranted'] as const
const ECON_INF_KEYS = ['equation', 'baselineReadback', 'baselineReadbackExchangeId', 'baselineExchangeId', 'finalReadback', 'finalReadbackExchangeId', 'finalExchangeId', 'actionExchangeIds', 'actionsExchangeIds', 'actionExchangeId', 'balancesBefore', 'balancesAfter', 'authorizedDeposits', 'authorizedWithdrawals', 'paidAmount', 'refundedAmounts', 'baselineRefunded', 'fulfilledValue', 'fulfillmentState', 'subtotalAmount', 'requiredThreshold', 'discountApplied', 'finalTotalPaid', 'beforeBalance', 'afterBalance', 'initialBalance', 'finalBalance', 'raceRequests', 'authorizedCap', 'deltaObserved'] as const
const CRYPTO_INF_KEYS = ['tamperedSignatureControl', 'tamperedSignatureControlExchangeId', 'tamperedControlExchangeId', 'sourceValidIssuance', 'sourceValidIssuanceExchangeId', 'sourceIssuanceExchangeId', 'replayedAcceptance', 'replayedAcceptanceExchangeId', 'replayedExchangeId', 'sourceScope', 'targetScope', 'sourceSignedResource', 'targetSignedResource', 'tamperedSignatureDigest', 'signatureDigest', 'replayedSignatureDigest'] as const
const PARSER_DIFF_MODE_KEYS = ['differentialProbe', 'differentialProbeExchangeId', 'differentialKind', 'differentialFeature', 'impactKind', 'canonicalValue', 'variantValue', 'canonicalRequest', 'variantRequest', 'smuggledRequest', 'parserDiff'] as const
const CACHE_PRIMED_MODE_KEYS = ['victimOrPrimeRequest', 'victimOrPrimeRequestExchangeId', 'victimPrimeExchangeId', 'attackerProbe', 'attackerProbeExchangeId', 'cacheKey', 'cachePrimeRequest', 'victimReadback', 'cacheBleed', 'victimArtifactDigest', 'cacheHitObserved', 'cleanControlContainsVictimData'] as const
const PARSER_CACHE_INF_KEYS = ['cleanControl', 'cleanControlExchangeId', ...PARSER_DIFF_MODE_KEYS, ...CACHE_PRIMED_MODE_KEYS] as const

/** Authoritative, fail-closed v8 oracle family inference evaluating all 6 families independently. */
export function inferV8OracleFamilyDetailed(rawInput: Record<string, unknown>): V8OracleInferenceResult {
  const conflicts = findConflictingOracleInputKeys(rawInput)
  if (conflicts.length > 0) return { kind: 'conflicting', keys: conflicts }
  const norm = normalizeV8OracleInputKeys(rawInput), hasAny = (keys: readonly string[]) => keys.some(k => norm[k] !== undefined && norm[k] !== null)
  const mode = typeof norm.mode === 'string' ? norm.mode.trim().toLowerCase().replace(/[\s-]+/g, '_') : '', matches: V8OracleFamily[] = []
  if (DUAL_MODE_SET.has(mode) || hasAny(DUAL_ABAC_INF_KEYS)) matches.push('dual_tenant_abac')
  if (hasAny(TEMPORAL_INF_KEYS)) matches.push('temporal_revocation')
  if (hasAny(ECON_INF_KEYS) || (Array.isArray(norm.actions) && norm.actions.length > 0)) matches.push('economic_conservation')
  if (hasAny(CRYPTO_INF_KEYS) || (norm.sourceTenant !== undefined && norm.sourceTenant !== null && norm.targetTenant !== undefined && norm.targetTenant !== null)) matches.push('cryptographic_scope_replay')
  if (PARSER_MODE_SET.has(mode) || DIFF_KIND_SET.has(mode) || CACHE_PRIMED_MODE_ALIASES.has(mode) || hasAny(PARSER_CACHE_INF_KEYS)) matches.push('parser_cache_differential')
  const hasPivotHop = Array.isArray(norm.hops) && norm.hops.length > 0 && ((norm.terminalImpact !== undefined && norm.terminalImpact !== null) || norm.hops.some(h => Boolean(h && typeof h === 'object' && ('surface' in (h as Record<string, unknown>) || 'role' in (h as Record<string, unknown>)))))
  const hasPivotCtrl = typeof norm.controlKind === 'string' && PIVOT_CTRL_SET.has(norm.controlKind.trim().toLowerCase())
  if (hasAny(['preChainControlDenied', 'preChainControlDeniedExchangeId', 'preChainControlExchangeId', 'attackerOriginPersona']) || hasPivotCtrl || hasPivotHop) matches.push('cross_surface_pivot')
  return matches.length === 1 ? { kind: 'matched', family: matches[0]! } : matches.length > 1 ? { kind: 'ambiguous', families: matches } : { kind: 'unmapped' }
}

function resolveDualAbacMode(raw: Record<string, unknown>): string | undefined {
  if (raw.mode !== undefined) return pickEnum(raw, 'mode', DUAL_MODE_SET)
  const has = (...keys: string[]) => keys.some(k => raw[k] !== undefined && raw[k] !== null), hits: string[] = []
  if (has('transferRecord', 'transferRecordExchangeId', 'transferExchangeId', 'postTransferReadback', 'postTransferReadbackExchangeId', 'sourceControlDenied', 'sourceControlDeniedExchangeId', 'sourceControlExchangeId')) hits.push('cross_org_transfer')
  if (has('baselineDeniedControl', 'baselineDeniedControlExchangeId', 'baselineControlExchangeId', 'primeAction', 'primeActionExchangeId', 'bledAccess', 'bledAccessExchangeId')) hits.push('dual_org_cache_bleed')
  if (has('singleForeignControlDenied', 'singleForeignControlDeniedExchangeId', 'singleForeignControlExchangeId', 'batchRequest', 'batchRequestExchangeId')) hits.push('batch_partial_authz')
  return hits.length === 1 ? hits[0] : undefined
}
function resolveParserCacheMode(raw: Record<string, unknown>): { mode?: 'parser_differential' | 'cache_primed'; inferredDifferentialKind?: string } {
  const has = (keys: readonly string[]) => keys.some(k => raw[k] !== undefined && raw[k] !== null)
  const hasDiff = has(PARSER_DIFF_MODE_KEYS), hasCache = has(CACHE_PRIMED_MODE_KEYS)
  if (hasDiff && hasCache) return {}
  if (raw.mode !== undefined) {
    const rawMode = pickStr(raw, 'mode', 64), norm = rawMode ? rawMode.toLowerCase().replace(/[\s-]+/g, '_') : ''
    if (norm === 'parser_differential' || norm === 'cache_primed') return { mode: norm }
    if (DIFF_KIND_SET.has(norm)) return (raw.differentialKind !== undefined && pickEnum(raw, 'differentialKind', DIFF_KIND_SET) !== norm) ? {} : { mode: 'parser_differential', inferredDifferentialKind: norm }
    return CACHE_PRIMED_MODE_ALIASES.has(norm) ? { mode: 'cache_primed' } : {}
  }
  return hasDiff ? { mode: 'parser_differential' } : hasCache ? { mode: 'cache_primed' } : {}
}
function resolveEconomicEquation(raw: Record<string, unknown>, baseRec: HostSignedRecord | undefined, finRec: HostSignedRecord | undefined): string | undefined {
  if (raw.equation !== undefined) return pickEnum(raw, 'equation', ECON_EQ_SET)
  const has = (...keys: string[]) => keys.some(k => raw[k] !== undefined && raw[k] !== null), rawHits: string[] = []
  if (has('refundedAmounts', 'baselineRefunded')) rawHits.push('over_refund')
  if (has('balancesBefore', 'balancesAfter', 'authorizedDeposits', 'authorizedWithdrawals', 'beforeBalance', 'afterBalance', 'initialBalance', 'finalBalance')) rawHits.push('balance_minting')
  if (has('fulfilledValue', 'fulfillmentState')) rawHits.push('underpaid_fulfillment')
  if (has('subtotalAmount', 'requiredThreshold', 'discountApplied', 'finalTotalPaid')) rawHits.push('ineligible_discount')
  if (rawHits.length === 1) return rawHits[0]
  if (rawHits.length > 1) return undefined
  const baseJson = parseRecJson(baseRec), finJson = parseRecJson(finRec), hostHits: string[] = []
  const paidKeys = ['paidamount', 'paid_amount', 'paid', 'paidcents', 'paid_cents', 'orderamount', 'order_amount', 'amountpaid', 'amount_paid', 'totalpaid', 'total_paid']
  const refKeys = ['refundedtotal', 'refunded_total', 'baselinerefunded', 'baseline_refunded', 'refundedamount', 'refunded_amount', 'refunded', 'totalrefunded', 'total_refunded']
  if ((findNumericField(baseJson, paidKeys) ?? findNumericField(finJson, paidKeys)) !== undefined && (findNumericField(finJson, refKeys) ?? findNumericField(baseJson, refKeys)) !== undefined) hostHits.push('over_refund')
  if (extractBalanceMap(baseRec) !== undefined && extractBalanceMap(finRec) !== undefined) hostHits.push('balance_minting')
  if (findNumericField(finJson, ['paidamount', 'paid_amount', 'paid', 'amountpaid', 'amount_paid', 'chargedamount', 'charged']) !== undefined && findNumericField(finJson, ['fulfilledvalue', 'fulfilled_value', 'ordertotal', 'order_total', 'totalamount', 'total_amount', 'itemvalue', 'subtotal', 'price', 'value']) !== undefined && findStringField(finJson, ['fulfillmentstate', 'fulfillment_state', 'orderstatus', 'order_status', 'status', 'state']) !== undefined) hostHits.push('underpaid_fulfillment')
  if ((findNumericField(finJson, ['subtotalamount', 'subtotal_amount', 'subtotal', 'cartsubtotal', 'prediscounttotal']) ?? findNumericField(baseJson, ['subtotalamount', 'subtotal_amount', 'subtotal', 'cartsubtotal', 'prediscounttotal'])) !== undefined && (findNumericField(finJson, ['requiredthreshold', 'required_threshold', 'minorderamount', 'min_order_amount', 'minimumsubtotal', 'threshold', 'minspend']) ?? findNumericField(baseJson, ['requiredthreshold', 'required_threshold', 'minorderamount', 'min_order_amount', 'minimumsubtotal', 'threshold', 'minspend'])) !== undefined && findNumericField(finJson, ['discountapplied', 'discount_applied', 'discountamount', 'discount_amount', 'discount']) !== undefined) hostHits.push('ineligible_discount')
  return hostHits.length === 1 ? hostHits[0] : undefined
}

/**
 * Hydrate all `HostSignedRecord` fields inside a raw `oracleInput` from `HostSignedTranscript`.
 * Allowlists ONLY safe structural reference IDs/selectors from `rawInput` (never spreading raw
 * model booleans or fabricated numeric operands) and derives all verification operands strictly
 * from host-recorded transcript exchanges.
 */
export function hydrateV8OracleInput(
  family: V8OracleFamily,
  rawInput: Record<string, unknown>,
  idx: HydratableTranscriptIndex,
  fallbackSig: string,
  econCtx?: EconomicAutoHydrateContext,
): Record<string, unknown> {
  const out: Record<string, unknown> = {}; if (findConflictingOracleInputKeys(rawInput).length > 0) return out; rawInput = normalizeV8OracleInputKeys(rawInput)
  const explicit = new Set<string>()
  const hydrateRole = (field: string, extraAlias?: string): void => {
    if (hydrateRoleField(out, rawInput, field, idx, fallbackSig, extraAlias)) explicit.add(field)
  }

  const hostAuthzDim = (e: HydratableEntry | undefined, capIdx?: CapOriginIndex, preferredTenant?: string, stripUrlTokens = false): HostAuthzDimension => {
    let capT = ''
    if (e && capIdx) {
      for (const c of [...(e.actorPersona?.startsWith('cap:') ? [e.actorPersona] : []), ...(e.consumedCapabilities ?? []), ...(e.emittedCapabilities ?? [])]) { const t = capIdx.emitterActorOf(c)?.tenant; if (t) { capT = t; break } }
    }
    const personaTenant = ((e ? resolveEntryIdentity(e).tenant : null) ?? capT).trim().toLowerCase()
    return deriveRecordAuthzDimension(e ? { route: e.step.route, pathAndQuery: e.step.pathAndQuery, json: e.step.json, body: e.step.body, tenantId: personaTenant || null } : undefined, { personaTenant, preferredTenant, stripUrlTokens })
  }

  if (family === 'dual_tenant_abac') {
    for (const [f, a] of [
      ['transferRecord', 'transferExchangeId'], ['postTransferReadback'], ['sourceControlDenied', 'sourceControlExchangeId'],
      ['baselineDeniedControl', 'baselineControlExchangeId'], ['primeAction'], ['bledAccess'],
      ['singleForeignControlDenied', 'singleForeignControlExchangeId'], ['batchRequest'], ['postMutationReadback'],
    ] as const) hydrateRole(f, a)
    const mode = resolveDualAbacMode(rawInput)
    if (mode) out.mode = mode
    const citedEntry = (field: string): HydratableEntry | undefined => isRecObj(out[field]) ? idx.entriesById.get((out[field] as HostSignedRecord).id) : undefined
    const cited = ['transferRecord', 'postTransferReadback', 'sourceControlDenied', 'baselineDeniedControl', 'primeAction', 'bledAccess', 'singleForeignControlDenied', 'batchRequest', 'postMutationReadback'].map(citedEntry)
    const actor = deriveDualActorFromTranscript(idx, cited, rawInput, econCtx)
    if (actor) out.actor = actor
    // Allowlist ONLY record selector IDs (with minimum length); tenant scope and role requirements are host-derived.
    for (const k of ['entityId', 'ownRecordId', 'foreignRecordId'] as const) {
      const v = pickStr(rawInput, k, 128)
      if (v && v.length >= MIN_TOKEN_LEN) out[k] = v
    }
    const tenantOf = (e: HydratableEntry | undefined): string | null => hostAuthzDim(e).personaTenant || null
    // R3-C-5 + Move-1 + R4-C-5: shared host-attested authz-dimension primitive, stripping attacker-supplied URL path/query tokens.
    const markersOf = (e: HydratableEntry | undefined): Set<string> => hostAuthzDim(e, undefined, undefined, true).responseTenants
    const hostKnownTenants = new Set<string>()
    for (const e of idx.entriesById.values()) { const t = tenantOf(e); if (t) hostKnownTenants.add(t); if (e.actorRoleLabel) for (const m of parseRoleMemberships(e.actorRoleLabel)) if (m.tenant) hostKnownTenants.add(m.tenant.trim().toLowerCase()) }
    if (mode === 'cross_org_transfer') {
      const rb = isRecObj(out.postTransferReadback) ? out.postTransferReadback : undefined
      const xferEntry = citedEntry('transferRecord'), ctrlEntry = citedEntry('sourceControlDenied')
      const sourceTenant = tenantOf(ctrlEntry)
      const ownerTenant = findStringField(parseRecJson(rb), ['ownertenantid', 'owner_tenant_id', 'ownerorgid', 'owner_org_id', 'destinationtenant', 'destination_tenant', 'desttenantid', 'dest_tenant_id', 'tenantid', 'tenant_id', 'tenant', 'orgid', 'org_id'])?.trim().toLowerCase()
      if (sourceTenant) out.sourceTenantId = sourceTenant
      if (ownerTenant) { out.destTenantId = ownerTenant; out.observedOwnerTenantId = ownerTenant }
      const eid = typeof out.entityId === 'string' ? out.entityId : ''
      if (!(eid && rb && recordContainsToken(rb, eid) && (entryReferencesToken(xferEntry, eid) || entryReferencesToken(ctrlEntry, eid) || recordContainsToken(isRecObj(out.transferRecord) ? out.transferRecord : undefined, eid)))) delete out.entityId
    } else if (mode === 'dual_org_cache_bleed') {
      const bled = isRecObj(out.bledAccess) ? out.bledAccess : undefined
      const primeTenant = tenantOf(citedEntry('primeAction')) ?? tenantOf(citedEntry('baselineDeniedControl'))
      const markers = markersOf(citedEntry('bledAccess'))
      if (primeTenant) out.primeTenantId = primeTenant
      const foreignMarkers = new Set(markers); if (primeTenant) foreignMarkers.delete(primeTenant)
      if (foreignMarkers.size === 1) out.targetTenantId = [...foreignMarkers][0]; else { const fb = resolveOpaqueDualCacheBleedTarget({ bled, primeTenant, bledMarkers: markers, actor, citedUpstreamMarkers: cited.filter(e => e && e.exchangeId !== bled?.id).map(markersOf), hostKnownTenants }); if (fb) out.targetTenantId = fb }
      if (bled) {
        const target = typeof out.targetTenantId === 'string' ? out.targetTenantId.trim().toLowerCase() : ''
        if (target && markers.has(target)) out.observedTenantId = out.targetTenantId
        else if (markers.size > 0) out.observedTenantId = [...markers][0]
        const rawTargetRec = pickStr(rawInput, 'targetRecordId', 128)
        if (rawTargetRec && rawTargetRec.length >= MIN_TOKEN_LEN && recordContainsToken(bled, rawTargetRec)) out.targetRecordId = rawTargetRec
      }
    } else if (mode === 'batch_partial_authz') {
      const batchRec = isRecObj(out.batchRequest) ? out.batchRequest : undefined
      const batchEntry = batchRec ? idx.entriesById.get(batchRec.id) : undefined
      const ctrlEntry = citedEntry('singleForeignControlDenied'), mutRb = isRecObj(out.postMutationReadback) ? out.postMutationReadback : undefined
      const ownTenant = tenantOf(batchEntry) ?? tenantOf(ctrlEntry)
      if (ownTenant) out.ownTenantId = ownTenant
      if (Array.isArray(rawInput.requestedIds) && batchEntry) {
        out.requestedIds = rawInput.requestedIds.filter((x): x is string => typeof x === 'string' && x.trim().length >= MIN_TOKEN_LEN && x.length <= 128).map(x => x.trim()).slice(0, 32).filter(id => entryReferencesToken(batchEntry, id))
      }
      const foreignId = typeof out.foreignRecordId === 'string' ? out.foreignRecordId : ''
      if (ctrlEntry && foreignId && (ctrlEntry.step.pathAndQuery || ctrlEntry.step.requestJson !== undefined) && !entryReferencesToken(ctrlEntry, foreignId)) delete out.foreignRecordId
      const vFid = typeof out.foreignRecordId === 'string' ? out.foreignRecordId : ''
      const matchedItem = batchRec && vFid && !isHydratedStub(batchRec) ? findNonErrorBatchRecord(batchRec.json, batchRec.body, vFid) : null
      out.returnedForeignIds = matchedItem ? [vFid] : []; out.foreignDataObserved = Boolean(matchedItem)
      if (mutRb) {
        const mutIsJson = mutRb.json !== undefined || (typeof mutRb.body === 'string' && /^[\[{]/.test(mutRb.body.trim()))
        out.foreignMutationPersisted = Boolean(is2xx(mutRb.status) && !isHydratedStub(mutRb) && vFid && (mutIsJson ? findNonErrorBatchRecord(mutRb.json, mutRb.body, vFid) !== null : recordContainsToken(mutRb, vFid)))
      }
      const respForeign = new Set<string>([...(matchedItem ? extractTenantMarkers(matchedItem, undefined, true) : []), ...markersOf(batchEntry), ...markersOf(citedEntry('postMutationReadback'))])
      if (ownTenant) respForeign.delete(ownTenant)
      const rawForeign = pickStr(rawInput, 'foreignTenantId', 128)?.toLowerCase() ?? ''
      if (respForeign.size === 1) out.foreignTenantId = [...respForeign][0]
      else if (respForeign.size > 1 && rawForeign && respForeign.has(rawForeign)) out.foreignTenantId = rawForeign
      else if (rawForeign && rawForeign !== ownTenant && hostKnownTenants.has(rawForeign)) out.foreignTenantId = rawForeign
    }
    return out
  }

  if (family === 'temporal_revocation') {
    for (const f of ['preRevocationBaseline', 'revocationEvent', 'primaryDeniedCheck', 'secondarySuccess'] as const) hydrateRole(f)
    const credKind = pickEnum(rawInput, 'credentialKind', CRED_KIND_SET)
    if (credKind) out.credentialKind = credKind
    const pRec = isRecObj(out.primaryDeniedCheck) ? out.primaryDeniedCheck : undefined
    const sRec = isRecObj(out.secondarySuccess) ? out.secondarySuccess : undefined
    const pEntry = pRec ? idx.entriesById.get(pRec.id) : undefined
    const sEntry = sRec ? idx.entriesById.get(sRec.id) : undefined
    // R2-C-8: derive surfaces strictly from host records, never from model-supplied enum labels.
    if (pRec) out.primarySurface = deriveHostSurface(pEntry, pRec)
    if (sRec) out.secondarySurface = deriveHostSurface(sEntry, sRec)
    const pHandle = pRec?.capabilityHandle?.trim() || '', sHandle = sRec?.capabilityHandle?.trim() || ''
    const rawHandle = pickStr(rawInput, 'credentialHandle', 200)
    if (pHandle && sHandle && pHandle === sHandle) out.credentialHandle = pHandle
    else if (rawHandle && (rawHandle === pHandle || rawHandle === sHandle)) out.credentialHandle = rawHandle
    const pActor = pRec?.actorId?.trim() || '', sActor = sRec?.actorId?.trim() || ''
    const rawActor = pickStr(rawInput, 'actorId', 128)
    if (pActor && sActor && pActor === sActor) out.actorId = pActor
    else if (rawActor && (rawActor === pActor || rawActor === sActor)) out.actorId = rawActor
    return out
  }

  if (family === 'cryptographic_scope_replay') {
    hydrateRole('tamperedSignatureControl', 'tamperedControlExchangeId')
    hydrateRole('sourceValidIssuance', 'sourceIssuanceExchangeId')
    hydrateRole('replayedAcceptance', 'replayedExchangeId')
    const tRec = isRecObj(out.tamperedSignatureControl) ? out.tamperedSignatureControl : undefined
    const sRec = isRecObj(out.sourceValidIssuance) ? out.sourceValidIssuance : undefined
    const rRec = isRecObj(out.replayedAcceptance) ? out.replayedAcceptance : undefined
    const tEntry = tRec ? idx.entriesById.get(tRec.id) : undefined
    const sEntry = sRec ? idx.entriesById.get(sRec.id) : undefined
    const rEntry = rRec ? idx.entriesById.get(rRec.id) : undefined
    // R4-C-5: shared host-attested authz-dimension primitive; symmetric tenant derivation; signed-resource scope only (no route fallback or caller persona).
    const capIdx = buildCapOriginIndex(idx.entriesById.values(), ANON_HANDLE_RE)
    const sDim = hostAuthzDim(sEntry, capIdx, pickStr(rawInput, 'sourceTenant', 128)?.toLowerCase())
    const rDim = hostAuthzDim(rEntry, capIdx, pickStr(rawInput, 'targetTenant', 128)?.toLowerCase())
    const sCarriesSig = Boolean(extractRequestSigDigest(sRec, sEntry))
    const sSignedRes = sDim.issuedSignedResource || (sCarriesSig ? sDim.requestSignedResource : '')
    const rSignedRes = rDim.requestSignedResource
    const hostSrcTenant = sDim.tenant
    const hostDstTenant = rDim.responseTenants.size > 0 ? rDim.tenant : (hostSrcTenant || rDim.tenant)
    if (hostSrcTenant) out.sourceTenant = hostSrcTenant; if (hostDstTenant) out.targetTenant = hostDstTenant
    if (sSignedRes) out.sourceSignedResource = sSignedRes; if (rSignedRes) out.targetSignedResource = rSignedRes
    const [hostSrcScope, hostDstScope] = (sSignedRes && rSignedRes && sSignedRes !== rSignedRes)
      ? [`resource:${sSignedRes}`, `resource:${rSignedRes}`]
      : (sDim.responseScope && rDim.responseScope)
        ? [sDim.responseScope, rDim.responseScope]
        : (sSignedRes && rSignedRes)
          ? [`resource:${sSignedRes}`, `resource:${rSignedRes}`]
          : [hostSrcTenant ? `tenant:${hostSrcTenant}` : '', hostDstTenant ? `tenant:${hostDstTenant}` : '']
    if (hostSrcScope) out.sourceScope = hostSrcScope; if (hostDstScope) out.targetScope = hostDstScope
    // Bind cryptographic digests STRICTLY to cryptoAttestations or request signature/token headers/query —
    // NEVER response-body hashes (`observedResponseDigests` / `rec.artifactDigest`), and NEVER same exchange.
    const sameIssReplay = Boolean(sRec && rRec && sRec.id === rRec.id)
    const emittedSet = new Set(sEntry?.emittedCapabilities ?? [])
    const linkedAtt = !sameIssReplay ? rEntry?.cryptoAttestations?.find(a => emittedSet.has(a.derivedFromCapabilityId)) : undefined
    const replayedDigest = sameIssReplay ? '' : (
      linkedAtt?.artifactDigest
      ?? rEntry?.cryptoAttestations?.[0]?.artifactDigest
      ?? extractRequestSigDigest(rRec, rEntry)
    )
    const sourceDigest = sameIssReplay ? '' : (
      linkedAtt?.artifactDigest
      ?? sEntry?.cryptoAttestations?.[0]?.artifactDigest
      ?? extractRequestSigDigest(sRec, sEntry)
      ?? extractIssuedSigDigest(sEntry)
    )
    const tamperedDigest = tEntry?.cryptoAttestations?.[0]?.artifactDigest
      ?? extractRequestSigDigest(tRec, tEntry)
    out.tamperedSignatureDigest = tamperedDigest ?? ''
    out.signatureDigest = sourceDigest ?? ''
    out.replayedSignatureDigest = replayedDigest ?? ''
    return out
  }

  if (family === 'parser_cache_differential') {
    hydrateRole('cleanControl')
    hydrateRole('differentialProbe')
    hydrateRole('postMutationReadback')
    hydrateRole('victimOrPrimeRequest', 'victimPrimeExchangeId')
    hydrateRole('attackerProbe')
    const { mode, inferredDifferentialKind } = resolveParserCacheMode(rawInput)
    if (mode) out.mode = mode
    if (mode === 'parser_differential') {
      const dk = rawInput.differentialKind !== undefined ? pickEnum(rawInput, 'differentialKind', DIFF_KIND_SET) : inferredDifferentialKind
      const df = pickStr(rawInput, 'differentialFeature', 128)
      const ik = pickEnum(rawInput, 'impactKind', IMPACT_KIND_SET)
      if (dk) out.differentialKind = dk
      if (df) out.differentialFeature = df
      if (ik) out.impactKind = ik
      const ctrl = isRecObj(out.cleanControl) ? out.cleanControl : undefined
      const probe = isRecObj(out.differentialProbe) ? out.differentialProbe : undefined
      const ctlEntry = ctrl ? idx.entriesById.get(ctrl.id) : undefined
      const prbEntry = probe ? idx.entriesById.get(probe.id) : undefined
      // Inspect actual HostFactLog request headers/paths/bodies to verify a real differential occurred;
      // NEVER trust worker-supplied canonicalValue/variantValue verbatim.
      if (dk && ctlEntry && prbEntry) {
        if (dk === 'path_normalization') {
          out.canonicalValue = ctlEntry.step.pathAndQuery ?? ctlEntry.step.route ?? ''
          out.variantValue = prbEntry.step.pathAndQuery ?? prbEntry.step.route ?? ''
        } else if (dk === 'content_type_confusion') {
          const cCt = headerLookupCI(ctlEntry.step.requestHeaders, 'content-type')
          const pCt = headerLookupCI(prbEntry.step.requestHeaders, 'content-type')
          out.canonicalValue = cCt
          out.variantValue = pCt || cCt
        } else if (dk === 'header_normalization' || dk === 'hop_by_hop_smuggling') {
          out.canonicalValue = canonicalDiffHeaders(ctlEntry.step.requestHeaders)
          out.variantValue = canonicalDiffHeaders(prbEntry.step.requestHeaders)
        } else if (dk === 'duplicate_json_key') {
          const cBody = rawRequestBodyText(ctlEntry)
          const pBody = rawRequestBodyText(prbEntry)
          const hasDup = pBody.length > 0 && hasDuplicateJsonKeyInRaw(pBody)
          out.canonicalValue = cBody
          out.variantValue = hasDup ? pBody : cBody
        }
      } else {
        out.canonicalValue = ''
        out.variantValue = ''
      }
      const rb = isRecObj(out.postMutationReadback) ? out.postMutationReadback : undefined
      if (ik === 'mutation' && rb) {
        const rbHasData = rb.json !== undefined || (typeof rb.body === 'string' && rb.body.trim().length > 0)
        out.mutationPersisted = Boolean(
          is2xx(rb.status) && !isHydratedStub(rb) && rbHasData && (!ctrl?.artifactDigest || rb.artifactDigest !== ctrl.artifactDigest),
        )
      }
    } else if (mode === 'cache_primed') {
      const ck = pickStr(rawInput, 'cacheKey', 256)
      if (ck) out.cacheKey = ck
      const prime = isRecObj(out.victimOrPrimeRequest) ? out.victimOrPrimeRequest : undefined
      if (prime?.artifactDigest) out.victimArtifactDigest = prime.artifactDigest
    }
    return out
  }

  if (family === 'cross_surface_pivot') {
    // Retired parallel pivot hydrator: cross-surface pivot is verified directly on the CompositeProofReceipt DAG (`surfaces.size >= 2`).
    return out
  }

  if (family === 'economic_conservation') {
    hydrateRole('baselineReadback', 'baselineExchangeId')
    hydrateRole('finalReadback', 'finalExchangeId')
    const tol = pickFiniteNonNeg(rawInput.tolerance)
    if (tol !== undefined && tol <= 1) out.tolerance = tol

    const hasExplicitActions = hydrateRecordArrayField(
      out, rawInput, 'actions', ['actionExchangeIds', 'actionsExchangeIds', 'actionExchangeId'], idx, fallbackSig,
    )
    if (econCtx) {
      if (!hasExplicitActions) {
        const autoActs = selectAutoEconomicActions({
          econCtx,
          entriesById: idx.entriesById,
          toRecord: e => toOracleRecord(e, fallbackSig),
        })
        if (autoActs.length > 0) {
          out.actions = autoActs
        }
        // Preserves race sub-exchanges and rejects zero-mutating-action pseudo-ops.
      }
      const validActs = Array.isArray(out.actions)
        ? (out.actions as unknown[]).filter((a): a is HostSignedRecord => Boolean(a && typeof a === 'object' && isPosTs((a as HostSignedRecord).timestampMs)))
        : []
      const actionIdSet = new Set(validActs.map(a => a.id))
      const minActTs = validActs.length > 0 ? Math.min(...validActs.map(a => a.timestampMs)) : null
      const maxActTs = validActs.length > 0 ? Math.max(...validActs.map(a => a.timestampMs)) : null

      if (!explicit.has('baselineReadback')) {
        const isBase = (e: HydratableEntry | undefined): e is HydratableEntry =>
          Boolean(e && !actionIdSet.has(e.exchangeId) && is2xx(e.step.status) && isPosTs(e.timestampMs) && (minActTs === null || e.timestampMs <= minActTs) && stepReadsState(e.step))
        const base = [...econCtx.preChainControlExchangeIds, ...(econCtx.citedExchangeIds ?? [])].map(id => idx.entriesById.get(id)).find(isBase)
        if (base) out.baselineReadback = toOracleRecord(base, fallbackSig)
      }
      if (!explicit.has('finalReadback')) {
        const baseId = out.baselineReadback && typeof out.baselineReadback === 'object' ? (out.baselineReadback as HostSignedRecord).id : null
        const isFin = (e: HydratableEntry | undefined): e is HydratableEntry =>
          Boolean(e && !actionIdSet.has(e.exchangeId) && (!baseId || e.exchangeId !== baseId) && is2xx(e.step.status) && isPosTs(e.timestampMs) && (maxActTs === null || e.timestampMs >= maxActTs) && stepReadsState(e.step) && hasEntryBody(e) && !isJobOrHandleStub(e.step.json, e.step.body, e.step.status, e.step.method, e.step.route ?? e.step.pathAndQuery))
        const fin = [...econCtx.postChainReadbackExchangeIds, ...[...econCtx.termHopExchangeIds].reverse()].map(id => idx.entriesById.get(id)).find(isFin)
        if (fin) out.finalReadback = toOracleRecord(fin, fallbackSig)
      }
    }

    const baseRec = isRecObj(out.baselineReadback) ? out.baselineReadback : undefined
    const finRec = isRecObj(out.finalReadback) ? out.finalReadback : undefined
    // Deduplicate action exchange IDs, bind strictly to probe-arm mutating actions (R2-C-8),
    // and retain DAG/window-bound `race` op sub-exchanges cited in `oracleInput.actionExchangeIds`.
    const rawActRecs = Array.isArray(out.actions) ? (out.actions as unknown[]).filter(isRecObj) : []
    const actRecs = resolveEconomicActionRecords({
      rawActRecs,
      entriesById: idx.entriesById,
      citedExchangeIds: econCtx?.citedExchangeIds,
      baseRec,
      finRec,
    })
    // Reject zero-mutating-action economic_conservation receipts cleanly via filtered actions.
    if (Array.isArray(out.actions)) {
      out.actions = actRecs
    }
    const baseJson = parseRecJson(baseRec), finJson = parseRecJson(finRec)
    const eq = resolveEconomicEquation(rawInput, baseRec, finRec)
    if (eq) out.equation = eq

    if (eq === 'over_refund') {
      const paidKeys = ['paidamount', 'paid_amount', 'paid', 'paidcents', 'paid_cents', 'orderamount', 'order_amount', 'amountpaid', 'amount_paid', 'totalpaid', 'total_paid']
      const refTotKeys = ['refundedtotal', 'refunded_total', 'baselinerefunded', 'baseline_refunded', 'refundedamount', 'refunded_amount', 'refunded', 'totalrefunded', 'total_refunded']
      const actRefKeys = ['refunded', 'refundamount', 'refund_amount', 'refundedamount', 'refunded_amount', 'refundedcents', 'credited', 'amount']
      const hostPaid = findNumericField(baseJson, paidKeys) ?? findNumericField(finJson, paidKeys)
      const hostBaseRef = findNumericField(baseJson, refTotKeys) ?? (hostPaid !== undefined ? 0 : undefined)
      const hostFinRef = findNumericField(finJson, refTotKeys)
      const hostActRefs = actRecs
        .filter(a => is2xx(a.status) && !(a.method && /^(?:GET|HEAD|OPTIONS)$/i.test(a.method)))
        .map(a => findNumericField(parseRecJson(a), actRefKeys))
        .filter((n): n is number => n !== undefined && n >= 0)
      const sumNums = (xs: readonly number[]) => xs.reduce((a, b) => a + b, 0)
      let derivedRefs: number[] | undefined
      if (hostActRefs.length > 0) {
        derivedRefs = hostFinRef !== undefined && hostFinRef < sumNums(hostActRefs)
          ? [Math.max(0, hostFinRef)]
          : hostActRefs
      } else if (hostFinRef !== undefined && hostFinRef >= 0) {
        derivedRefs = [hostFinRef]
      }
      if (hostPaid !== undefined) {
        const rawPaid = pickFiniteNonNeg(rawInput.paidAmount)
        out.paidAmount = rawPaid !== undefined && rawPaid > hostPaid ? rawPaid : hostPaid
      }
      if (hostBaseRef !== undefined) {
        const rawBase = pickFiniteNonNeg(rawInput.baselineRefunded)
        out.baselineRefunded = rawBase !== undefined && rawBase > hostBaseRef ? rawBase : hostBaseRef
      }
      if (derivedRefs && derivedRefs.length > 0) {
        const rawRefs = Array.isArray(rawInput.refundedAmounts) && rawInput.refundedAmounts.length > 0
          && rawInput.refundedAmounts.every(n => typeof n === 'number' && Number.isFinite(n) && n >= 0)
          ? (rawInput.refundedAmounts as number[])
          : undefined
        out.refundedAmounts = rawRefs && sumNums(rawRefs) < sumNums(derivedRefs) ? rawRefs : derivedRefs
      }
    } else if (eq === 'balance_minting') {
      const hostBefore = extractBalanceMap(baseRec)
      const hostAfter = extractBalanceMap(finRec)
      if (hostBefore && hostAfter) {
        out.balancesBefore = hostBefore
        out.balancesAfter = hostAfter
        // R9: Deduplicate authorizedDeposits per distinct server-identified entity/order ID across
        // mutating responses in [baseline, final] union cited actions, and fail closed unless an
        // attacker-induced economic conservation break is host-evidenced:
        //  (i)  concurrent raceBatchId multiplicity (>= 2 same-route race actions with >= 1 2xx)
        //       or duplicate credits (>= 2 2xx probe actions on the terminal route + same entity),
        //  (ii) zero-sum internal transfer minting, negative-amount tampering, bypassed control /
        //       derived_crypto_binding forged credit, or a same-actor conserving benign control.
        const mintRes = hydrateBalanceMintingOperands({
          baseRec,
          finRec,
          actRecs,
          entriesById: idx.entriesById,
          preChainControlExchangeIds: econCtx?.preChainControlExchangeIds,
          tolerance: typeof out.tolerance === 'number' ? out.tolerance : 1e-6,
          findNumericField,
          extractBalanceMap,
          isInternalTransferRequest,
          toRecord: e => toOracleRecord(e, fallbackSig),
        })
        if (mintRes.ok) {
          out.authorizedDeposits = mintRes.authorizedDeposits
          out.authorizedWithdrawals = 0
        } else {
          // Leave authorizedDeposits unset so evaluateEconomicConservation fails closed on bare
          // single benign captures that lack race/duplicate multiplicity or conserving control.
          out.conservationBreakRejectedReason = mintRes.reason
        }
        // Maintain stable hydration operands without leaking untrusted worker deposit scalars
        // (strictly host-derived balancesBefore/balancesAfter and per-entity deduplicated deposits).
        //
        // Note:
        //  - distinct order/entity IDs and entity-less deposits continue to sum legitimately;
        //  - echoed order amounts across lifecycle mutations (create/rebind/capture) deduplicate;
        //  - internal transfers and control-denied forged credits remain excluded from deposits;
        //  - bare single benign captures without multiplicity or conserving control fail closed.
      }
    } else if (eq === 'underpaid_fulfillment') {
      const hostPaid = findNumericField(finJson, ['paidamount', 'paid_amount', 'paid', 'amountpaid', 'amount_paid', 'chargedamount', 'charged'])
        ?? findNumericField(baseJson, ['paidamount', 'paid_amount', 'paid', 'amountpaid', 'amount_paid', 'chargedamount', 'charged'])
      const hostVal = findNumericField(finJson, ['fulfilledvalue', 'fulfilled_value', 'ordertotal', 'order_total', 'totalamount', 'total_amount', 'itemvalue', 'subtotal', 'price', 'value'])
        ?? findNumericField(baseJson, ['fulfilledvalue', 'fulfilled_value', 'ordertotal', 'order_total', 'totalamount', 'total_amount', 'itemvalue', 'subtotal', 'price', 'value'])
      const hostState = findStringField(finJson, ['fulfillmentstate', 'fulfillment_state', 'orderstatus', 'order_status', 'status', 'state'])
      if (hostPaid !== undefined) {
        const rawPaid = pickFiniteNonNeg(rawInput.paidAmount)
        out.paidAmount = rawPaid !== undefined && rawPaid > hostPaid ? rawPaid : hostPaid
      }
      if (hostVal !== undefined) {
        const rawVal = pickFiniteNonNeg(rawInput.fulfilledValue)
        out.fulfilledValue = rawVal !== undefined && rawVal < hostVal ? rawVal : hostVal
      }
      if (hostState) out.fulfillmentState = hostState
    } else if (eq === 'ineligible_discount') {
      const hostSub = findNumericField(finJson, ['subtotalamount', 'subtotal_amount', 'subtotal', 'cartsubtotal', 'prediscounttotal'])
        ?? findNumericField(baseJson, ['subtotalamount', 'subtotal_amount', 'subtotal', 'cartsubtotal', 'prediscounttotal'])
      const hostThr = findNumericField(finJson, ['requiredthreshold', 'required_threshold', 'minorderamount', 'min_order_amount', 'minimumsubtotal', 'threshold', 'minspend'])
        ?? findNumericField(baseJson, ['requiredthreshold', 'required_threshold', 'minorderamount', 'min_order_amount', 'minimumsubtotal', 'threshold', 'minspend'])
      const hostDisc = findNumericField(finJson, ['discountapplied', 'discount_applied', 'discountamount', 'discount_amount', 'discount'])
      const hostTotal = findNumericField(finJson, ['finaltotalpaid', 'final_total_paid', 'totalpaid', 'total_paid', 'finaltotal', 'total'])
      if (hostSub !== undefined) out.subtotalAmount = hostSub
      if (hostThr !== undefined) out.requiredThreshold = hostThr
      if (hostDisc !== undefined) out.discountApplied = hostDisc
      if (hostTotal !== undefined) out.finalTotalPaid = hostTotal
    }
  }

  return out
}

export function extractCanonicalEntityTokens(entityId: string): string[] {
  const trimmed = entityId.trim(); if (!trimmed) return []
  const tokens: string[] = [], seen = new Set<string>()
  const push = (t: string) => { const n = t.trim().toLowerCase(); if (n.length >= 2 && !seen.has(n)) { seen.add(n); tokens.push(n) } }
  if (trimmed.includes(':')) { const parts = trimmed.split(':'); for (let i = 1; i < parts.length; i++) push(parts[i]!) } else push(trimmed)
  return tokens
}
export function selectStateTransitionPair<T extends HydratableEntry>(
  entityId: string, fromEntries: readonly T[], toEntries: readonly T[], dagDerivedCaps: ReadonlySet<string>,
  helpers: { actorOf: (e: T) => string | null; probeTenantOf: (e: T) => string | null; entryMatchesEntity: (e: T, eid: string) => boolean; anonActorRe: RegExp; resolveCapActor?: (cap: string) => string | null },
): { ok: true; from: T; to: T; logicalFallback: boolean } | { ok: false; reason: 'missing_from' | 'missing_to' | 'non_monotonic' | 'actor_discontinuity'; missingSide?: 'from' | 'to' } {
  const okLit = (es: readonly T[]) => es.filter(e => is2xx(e.step.status) && isFiniteTs(e.timestampMs) && helpers.entryMatchesEntity(e, entityId))
  const fromLit = okLit(fromEntries), toLit = okLit(toEntries)
  if (fromLit.length > 0 && toLit.length > 0) {
    const lit = fromLit.flatMap(f => toLit.filter(t => f.timestampMs! <= t.timestampMs!).map(t => ({ from: f, to: t })))[0]
    return lit ? { ok: true, from: lit.from, to: lit.to, logicalFallback: false } : { ok: false, reason: 'non_monotonic' }
  }
  const okProbes = (es: readonly T[]) => es.filter(e => e.step.arm === 'probe' && is2xx(e.step.status) && isFiniteTs(e.timestampMs))
  const fromProbes = okProbes(fromEntries), toProbes = okProbes(toEntries)
  if (fromLit.length === 0 && fromProbes.length === 0) return { ok: false, reason: 'missing_from' }
  if (toLit.length === 0 && toProbes.length === 0) return { ok: false, reason: 'missing_to' }
  const tokens = extractCanonicalEntityTokens(entityId)
  const tokMatch = (e: T): boolean => { const a = helpers.actorOf(e)?.trim().toLowerCase() ?? '', t1 = e.step.actor.tenant?.trim().toLowerCase() ?? '', t2 = helpers.probeTenantOf(e) ?? ''; return tokens.some(tok => a === tok || t1 === tok || t2 === tok || helpers.entryMatchesEntity(e, tok)) }
  const rank = (lit: readonly T[], probes: readonly T[]): readonly T[] => lit.length > 0 ? lit : [...probes.filter(tokMatch), ...probes.filter(e => !tokMatch(e))]
  const monoPairs = rank(fromLit, fromProbes).flatMap(f => rank(toLit, toProbes).filter(t => f.timestampMs! <= t.timestampMs!).map(t => ({ from: f, to: t })))
  if (monoPairs.length === 0) return { ok: false, reason: 'non_monotonic' }
  const normAct = (e: T): string | null => { const a = helpers.actorOf(e)?.trim().toLowerCase() ?? ''; return (!a || helpers.anonActorRe.test(a) || a.startsWith('cap:')) ? null : a }
  const capsOf = (e: T): string[] => { const a = helpers.actorOf(e)?.trim() ?? ''; return [...(a.startsWith('cap:') ? [a] : []), ...(e.consumedCapabilities ?? []), ...(e.cryptoAttestations ?? []).flatMap(x => [x.derivedFromCapabilityId, ...(x.derivedCapabilityId ? [x.derivedCapabilityId] : [])])] }
  const lineageActors = (e: T): Set<string> => {
    const out = new Set<string>(), direct = normAct(e); if (direct) out.add(direct)
    if (helpers.resolveCapActor) for (const c of capsOf(e)) { const oa = helpers.resolveCapActor(c)?.trim().toLowerCase(); if (oa && !helpers.anonActorRe.test(oa) && !oa.startsWith('cap:')) out.add(oa) }
    return out
  }
  const matched = monoPairs.find(({ from: f, to: t }) => {
    const fa = normAct(f), ta = normAct(t), fActors = lineageActors(f), tActors = lineageActors(t), fCapSet = new Set(capsOf(f)), tCaps = capsOf(t)
    const sameActor = (fActors.size > 0 && tActors.size > 0) ? [...fActors].some(a => tActors.has(a)) : (fa === null && ta === null && fActors.size === 0 && tActors.size === 0 && f.step.actor.auth === t.step.actor.auth)
    return sameActor || tCaps.some(c => dagDerivedCaps.has(c)) || (tCaps.some(c => fCapSet.has(c)) && (fActors.size === 0 || tActors.size === 0 || sameActor))
  })
  return matched ? { ok: true, from: matched.from, to: matched.to, logicalFallback: true } : { ok: false, reason: 'actor_discontinuity', missingSide: fromLit.length === 0 ? 'from' : 'to' }
}
export { normalizeTerminalVulnClass }
export type TerminalContractKind = OracleTerminalContractKind
export const TERMINAL_CLASS_CONTRACT: Readonly<Record<string, TerminalContractKind>> = buildTerminalClassContractMap()
export const resolveTerminalContract = (cls: string): TerminalContractKind | null => { const raw = cls.trim().toLowerCase(), n = normalizeTerminalVulnClass(cls); return TERMINAL_CLASS_CONTRACT[n] ?? resolveTerminalContractKind(n) ?? (n !== raw ? (TERMINAL_CLASS_CONTRACT[raw] ?? resolveTerminalContractKind(raw)) : null) }
const SECRET_LEAF_KEY_RE = /secret|passw|token|auth|cookie|cred|private|api_?key|jwt|session|sig|hmac/i
const CORR_HEADER_KEYS = new Set(['x-kovo-correlation', 'x-correlation-id', 'x-request-id'])
const AUTH_QUERY_KEYS = new Set(['sig', 'signature', 'hmac', 'mac', 'token', 'access_token', 'code', 'state', 'nonce', 'ts', 'timestamp', 'expires', 'exp'])
function collectSafeLeaves(value: unknown, out: Set<string>, depth = 0): void {
  if (depth > 5 || out.size > 256 || value == null) return
  if (typeof value === 'string') { const t = value.trim(); if (t.length > 0 && t.length <= 512 && !t.includes('[redacted')) out.add(t) }
  else if (typeof value === 'number' || typeof value === 'boolean') out.add(String(value))
  else if (Array.isArray(value)) for (const x of value) collectSafeLeaves(x, out, depth + 1)
  else if (typeof value === 'object') for (const [k, x] of Object.entries(value as Record<string, unknown>)) if (!SECRET_LEAF_KEY_RE.test(k)) collectSafeLeaves(x, out, depth + 1)
}
export function entryMatchesEntity(entry: HydratableEntry, entityId: string): boolean {
  const eid = entityId.trim(), lid = eid.toLowerCase(), pq = entry.step.pathAndQuery ?? entry.step.route ?? ''; if (!eid) return false
  if (entry.entityId?.trim().toLowerCase() === lid || entry.correlationIds?.some(c => c.trim().toLowerCase() === lid)) return true
  if (pq) {
    const [p = '', q = ''] = pq.split('?', 2)
    for (const seg of p.split('/')) { if (seg.toLowerCase() === lid) return true; try { if (decodeURIComponent(seg).toLowerCase() === lid) return true } catch { /* ignore */ } }
    if (q) for (const [k, v] of new URLSearchParams(q).entries()) if (!SECRET_LEAF_KEY_RE.test(k) && v.trim().toLowerCase() === lid) return true
  }
  const leaves = new Set<string>(); collectSafeLeaves(entry.step.requestJson, leaves); collectSafeLeaves(entry.step.json, leaves)
  for (const leaf of leaves) if (leaf.toLowerCase() === lid) return true
  return false
}
export function entryMatchesCorrelation(entry: HydratableEntry, correlationId: string): boolean {
  const cid = correlationId.trim(); if (cid.length < 6 || new Set(cid).size < 4 || cid.includes('[redacted')) return false
  if (entry.correlationIds?.includes(cid) || entry.entityId === cid) return true
  const pq = entry.step.pathAndQuery ?? entry.step.route ?? ''
  if (pq) { const [p = '', q = ''] = pq.split('?', 2); for (const seg of p.split('/')) if (seg === cid) return true; if (q) for (const [k, v] of new URLSearchParams(q).entries()) if (!SECRET_LEAF_KEY_RE.test(k) && v.trim() === cid) return true }
  for (const hdrs of [entry.step.requestHeaders, entry.step.responseHeaders]) if (hdrs) for (const [k, v] of Object.entries(hdrs)) if (CORR_HEADER_KEYS.has(k.toLowerCase()) && v.trim() === cid) return true
  const leaves = new Set<string>(); collectSafeLeaves(entry.step.requestJson, leaves); collectSafeLeaves(entry.step.json, leaves); return leaves.has(cid)
}
export function entryCarriesRequestToken(entry: HydratableEntry, token: string): boolean {
  const tok = token.trim(); if (tok.length < 6) return false
  if (entry.correlationIds?.includes(tok) || entry.entityId === tok || (entry.step.pathAndQuery ?? entry.step.route ?? '').includes(tok)) return true
  for (const v of Object.values(entry.step.requestHeaders ?? {})) if (v.includes(tok)) return true
  const reqLeaves = new Set<string>(); collectJsonStringLeaves(entry.step.requestJson, reqLeaves); return [...reqLeaves].some(l => l === tok || l.includes(tok))
}
export const cleanExactPath = (p: string | null | undefined): string => (p ?? '').split(/[?#]/, 1)[0]!.replace(/\/+$/, '').toLowerCase()
export function matchesNormalizedDotSegmentPath(cRaw: string | null | undefined, rRaw: string | null | undefined): boolean {
  const norm = (s: string) => { const st: string[] = []; for (const seg of cleanExactPath(s).split('/')) { if (!seg || seg === '.') continue; if (seg === '..') st.pop(); else st.push(seg) } return '/' + st.join('/') }
  const cp = cleanExactPath(cRaw), rp = cleanExactPath(rRaw)
  return Boolean(cp && rp && (rp.includes('/..') || rp.includes('/.') || cp.includes('/..') || cp.includes('/.')) && norm(cp) === norm(rp))
}
export function canonicalNonAuthQuery(p: string | null | undefined): string {
  const qIdx = (p ?? '').indexOf('?'); if (qIdx < 0) return ''
  const pairs: [string, string][] = []
  for (const [k, v] of new URLSearchParams((p ?? '').slice(qIdx + 1).split('#', 1)[0]!).entries()) { const lk = k.trim().toLowerCase(); if (!AUTH_QUERY_KEYS.has(lk)) pairs.push([lk, v.trim()]) }
  return pairs.sort(([a, av], [b, bv]) => (a < b ? -1 : a > b ? 1 : av < bv ? -1 : av > bv ? 1 : 0)).map(([k, v]) => `${k}=${v}`).join('&')
}
export function sanitizeEmbeddedProofReceipt(pr: ProofReceipt): ProofReceipt {
  const { requiredRole: _r, resourceTenant: _t, oracleEvents: _e, conservedBalance, ...rest } = pr
  const cb = conservedBalance ? { ...(conservedBalance.balanceField ? { balanceField: conservedBalance.balanceField } : {}), ...(conservedBalance.capField ? { capField: conservedBalance.capField } : {}) } : undefined
  return { ...rest, ...(cb && Object.keys(cb).length > 0 ? { conservedBalance: cb } : {}) }
}

// --- Host-Verified Control Hop Exclusion & Supplemental DAG Inference -------

const V8_VALID_FAMILIES: readonly V8OracleFamily[] = [
  'dual_tenant_abac', 'temporal_revocation', 'economic_conservation',
  'cryptographic_scope_replay', 'parser_cache_differential', 'cross_surface_pivot',
]
const V8_VALID_FAMILY_SET: ReadonlySet<string> = new Set(V8_VALID_FAMILIES)
const DAG_DENIED_CTRL_STATUSES = new Set([401, 403, 404])
const DAG_ABLATION_DENIED_STATUSES = new Set([401, 403, 404, 409, 412, 422])
const DAG_CAP_RE = /^cap:[A-Za-z0-9._:-]{1,180}$/
const DAG_SHA256_RE = /^[0-9a-f]{64}$/
const DAG_ISO_DATE_RE = /^\d{4}-\d{2}-\d{2}(?:[T\s]\d{2}:\d{2}|$)/
const DAG_MAX_EDGES = 28

export function collectUrlParamTokens(rawUrl: string, out: Set<string>): void {
  const qIdx = rawUrl.indexOf('?'), hIdx = rawUrl.indexOf('#')
  const query = qIdx >= 0 ? rawUrl.slice(qIdx + 1, hIdx >= 0 && hIdx > qIdx ? hIdx : undefined) : ''
  const hash = hIdx >= 0 ? rawUrl.slice(hIdx + 1) : ''
  if (query) for (const v of new URLSearchParams(query).values()) if (v.trim()) out.add(v.trim())
  if (hash && hash.includes('=')) for (const v of new URLSearchParams(hash).values()) if (v.trim()) out.add(v.trim())
}

export function resolveV8OracleFamilyOrDiagnostic(
  oracleFamily: V8OracleFamily | undefined,
  normCls: string,
  explicitInput: Record<string, unknown> | undefined,
  legacyInfer?: (input: Record<string, unknown>) => V8OracleFamily | null,
): { ok: true; family: V8OracleFamily | null; inferred: boolean } | { ok: false; reason: string; rejectedBy: string; missingEvidence: string[] } {
  if (explicitInput) {
    const conflicts = findConflictingOracleInputKeys(explicitInput)
    if (conflicts.length > 0) return { ok: false, reason: `v8_oracle_failed (conflicting_oracle_input_keys): terminalImpact.oracleInput contains conflicting duplicate values for normalized keys (${conflicts.join(', ')}) — supply each field under a single canonical spelling.`, rejectedBy: 'v8_oracle_conflicting_keys', missingEvidence: ['deduplicated_oracle_input_keys'] }
  }
  if (oracleFamily) return { ok: true, family: oracleFamily, inferred: false }
  const normalizedCls = normalizeTerminalVulnClass(normCls); if (V8_VALID_FAMILY_SET.has(normalizedCls)) return { ok: true, family: normalizedCls as V8OracleFamily, inferred: false }
  if (!explicitInput) return { ok: true, family: null, inferred: false }
  const normIn = normalizeV8OracleInputKeys(explicitInput), inf = inferV8OracleFamilyDetailed(normIn)
  if (inf.kind === 'matched') return { ok: true, family: inf.family, inferred: true }
  const validList = V8_VALID_FAMILIES.join(' | ')
  if (inf.kind === 'ambiguous') {
    return { ok: false, reason: `v8_oracle_failed (ambiguous_oracle_input): terminalImpact.oracleInput supplied without terminalImpact.oracleFamily matched multiple v8 oracle families (${inf.families.join(', ')}) — specify terminalImpact.oracleFamily explicitly (${validList}) and supply fields for a single family.`, rejectedBy: 'v8_oracle_family_missing', missingEvidence: ['terminalImpact.oracleFamily'] }
  }
  const legacy = legacyInfer?.(normIn) ?? null
  if (legacy) return { ok: true, family: legacy, inferred: true }
  return { ok: false, reason: `v8_oracle_failed (unmapped_oracle_input): terminalImpact.oracleInput supplied without terminalImpact.oracleFamily did not match any v8 oracle family schema — specify terminalImpact.oracleFamily explicitly (${validList}) or remove oracleInput.`, rejectedBy: 'v8_oracle_family_missing', missingEvidence: ['terminalImpact.oracleFamily'] }
}

interface DagHopLike { hopId: string; exchangeIds: string[]; oobEventIds: string[]; browserTraceIds: string[]; entityId?: string }
interface DagEdgeLike { kind: string; fromHopId: string; toHopId: string; [k: string]: unknown }
interface DagReceiptLike<H extends DagHopLike = DagHopLike, E extends DagEdgeLike = DagEdgeLike> {
  hops: H[]; causalEdges: E[]
  terminalImpact: { terminalHopId: string; preChainControlExchangeIds: string[]; postChainReadbackExchangeIds: string[]; [k: string]: unknown }
}
interface DagEntryLike extends HydratableEntry { origin?: string; cleanSession?: boolean; replayAttempt?: 'mode_a' | 'ablation_control' | 'primary' }
interface DagOobLike extends HydratableOobEvent { canaryId?: string; callbackId?: string; correlationIds?: readonly string[] }
interface DagTraceLike extends HydratableBrowserTrace { sinks?: readonly string[]; correlationIds?: readonly string[] }
interface DagTranscriptLike<T extends DagEntryLike = DagEntryLike> {
  entries?: readonly T[]; oobEvents?: readonly DagOobLike[]; browserTraces?: readonly DagTraceLike[]
}

const dagCanReach = (outAdj: ReadonlyMap<string, readonly string[]>, start: string, goal: string): boolean => {
  if (start === goal) return true
  const seen = new Set([start]), q = [start]
  while (q.length > 0) for (const n of outAdj.get(q.shift()!) ?? []) { if (n === goal) return true; if (!seen.has(n)) { seen.add(n); q.push(n) } }
  return false
}
const dagReachesTerminal = (hops: readonly DagHopLike[], termHopId: string, outAdj: ReadonlyMap<string, readonly string[]>): Set<string> => {
  const rev = new Map<string, string[]>(hops.map(h => [h.hopId, []]))
  for (const [f, ts] of outAdj) for (const t of ts) rev.get(t)?.push(f)
  const reach = new Set([termHopId]), q = [termHopId]
  while (q.length > 0) for (const p of rev.get(q.shift()!) ?? []) if (!reach.has(p)) { reach.add(p); q.push(p) }
  return reach
}
const isDagExecArm = (e: DagEntryLike, isTerm = false): boolean => e.step.arm === 'probe' || (!isTerm && e.step.arm === 'setup')
const isStrictHostChrono = (fTs: number, fSeq: number | undefined, tTs: number, tSeq: number | undefined): boolean =>
  fTs < tTs || (fTs === tTs && typeof fSeq === 'number' && typeof tSeq === 'number' && Number.isFinite(fSeq) && Number.isFinite(tSeq) && fSeq < tSeq)
const isHighEntropyUrlTok = (raw: string): boolean => {
  const t = raw.trim()
  if (DAG_CAP_RE.test(t)) return true
  if (t.length < 16 || t.length > 2048 || /\s/.test(t) || /\[redacted/i.test(t) || DAG_ISO_DATE_RE.test(t)) return false
  const c = new Map<string, number>(); for (const ch of t) c.set(ch, (c.get(ch) ?? 0) + 1)
  let h = 0; for (const n of c.values()) { const p = n / t.length; h -= p * Math.log2(p) }
  return c.size >= 8 && h >= 3.0
}
function tokenAppearedBeforeSrc<T extends DagEntryLike>(
  tok: string, digest: string, src: T, allEntries: readonly T[], hostTranscript: DagTranscriptLike<T>,
  collectDigests: (e: T, side: 'request' | 'response') => Set<string>,
): boolean {
  const tl = tok.toLowerCase(), srcTs = src.timestampMs!
  if (collectDigests(src, 'request').has(digest) || entryCarriesRequestToken(src, tok) || src.entityId?.trim().toLowerCase() === tl || src.correlationIds?.some(c => c.trim().toLowerCase() === tl)) return true
  for (const other of allEntries) {
    if (other.exchangeId === src.exchangeId) continue
    if (isFiniteTs(other.timestampMs) && isStrictHostChrono(srcTs, src.seq, other.timestampMs, other.seq)) continue
    if (other.entityId?.trim().toLowerCase() === tl || other.correlationIds?.some(c => c.trim().toLowerCase() === tl)) return true
    if (collectDigests(other, 'request').has(digest) || collectDigests(other, 'response').has(digest) || entryCarriesRequestToken(other, tok)) return true
    if (typeof other.step.body === 'string' && other.step.body.includes(tok)) return true
  }
  for (const o of hostTranscript.oobEvents ?? []) {
    if (isFiniteTs(o.receivedAtMs) && o.receivedAtMs > srcTs) continue
    if ([o.token, o.canaryId, o.callbackId, ...(o.correlationIds ?? [])].some(x => x?.trim().toLowerCase() === tl) || (o.observedValueDigests ?? []).some(x => x.toLowerCase() === digest)) return true
  }
  for (const tr of hostTranscript.browserTraces ?? []) {
    if (isFiniteTs(tr.timestampMs) && tr.timestampMs > srcTs) continue
    if ((tr.correlationIds ?? []).some(x => x.trim().toLowerCase() === tl) || (tr.observedValueDigests ?? []).some(x => x.toLowerCase() === digest)) return true
  }
  return false
}

/** Exclude strictly host-attested non-causal control/baseline/post-readback hops from causal DAG and hopCount. */
export function partitionNonCausalControlHops<H extends DagHopLike, E extends DagEdgeLike, R extends DagReceiptLike<H, E>>(
  receipt: R, hostTranscript: DagTranscriptLike, explicitEdgeCount: number,
): { causalReceipt: R; excludedControlHopIds: string[]; explicitEdgeCount: number } {
  const termHopId = receipt.terminalImpact.terminalHopId
  if (receipt.hops.length <= 1 || !receipt.hops.some(h => h.hopId === termHopId)) return { causalReceipt: receipt, excludedControlHopIds: [], explicitEdgeCount }
  const entriesById = new Map((hostTranscript.entries ?? []).map(e => [e.exchangeId, e]))
  const termHop = receipt.hops.find(h => h.hopId === termHopId)!
  const termTs = termHop.exchangeIds.map(id => entriesById.get(id)).filter((e): e is DagEntryLike => Boolean(e && isDagExecArm(e, true) && isFiniteTs(e.timestampMs))).map(e => e.timestampMs!)
  const termMaxTs = termTs.length > 0 ? Math.max(...termTs) : null
  const postRbSet = new Set(receipt.terminalImpact.postChainReadbackExchangeIds), outHops = new Set(receipt.causalEdges.map(e => e.fromHopId))
  const excluded = new Set<string>(), demotedCtrls: string[] = []
  for (const hop of receipt.hops) {
    if (hop.hopId === termHopId || outHops.has(hop.hopId) || hop.oobEventIds.length > 0 || hop.browserTraceIds.length > 0 || hop.exchangeIds.length === 0) continue
    const resolved = hop.exchangeIds.map(id => entriesById.get(id)); if (resolved.some(e => !e)) continue
    const entries = resolved as DagEntryLike[]
    const isCtrl = entries.every(e => e.step.arm === 'control' || e.replayAttempt === 'ablation_control')
    const isRb = !isCtrl && entries.every(e => postRbSet.has(e.exchangeId) && stepReadsState(e.step) && (e.step.arm === 'control' || e.step.evidenceRole === 'post_chain_readback' || e.evidenceRole === 'post_chain_readback' || (isFiniteTs(e.timestampMs) && termMaxTs !== null && e.timestampMs >= termMaxTs)))
    if (!isCtrl && !isRb) continue
    excluded.add(hop.hopId)
    if (isCtrl) for (const e of entries) if (typeof e.step.status === 'number' && DAG_DENIED_CTRL_STATUSES.has(e.step.status)) demotedCtrls.push(e.exchangeId)
  }
  if (excluded.size === 0) return { causalReceipt: receipt, excludedControlHopIds: [], explicitEdgeCount }
  const keep = (e: E) => !excluded.has(e.fromHopId) && !excluded.has(e.toHopId)
  const expKept = receipt.causalEdges.slice(0, explicitEdgeCount).filter(keep), autoKept = receipt.causalEdges.slice(explicitEdgeCount).filter(keep)
  const mergedPre = [...receipt.terminalImpact.preChainControlExchangeIds]
  for (const id of demotedCtrls) if (!mergedPre.includes(id)) mergedPre.push(id)
  return {
    causalReceipt: { ...receipt, hops: receipt.hops.filter(h => !excluded.has(h.hopId)), causalEdges: [...expKept, ...autoKept], terminalImpact: { ...receipt.terminalImpact, preChainControlExchangeIds: mergedPre } },
    excludedControlHopIds: [...excluded], explicitEdgeCount: expKept.length,
  }
}

/** Infer host-observed OOB/browser pivots, canonical single-owner caps/Location tokens, and multi-hop state transitions before `dag_topology`. */
export function inferSupplementalHostCausalEdges<H extends DagHopLike, E extends DagEdgeLike, R extends DagReceiptLike<H, E>, T extends DagEntryLike>(
  receipt: R, hostTranscript: DagTranscriptLike<T>,
  helpers: { collectDigests: (e: T, side: 'request' | 'response') => Set<string>; normRouteFam: (p: string | null | undefined, eid?: string) => string; sameCredIdentity: (a: T, b: T, capIdx: CapOriginIndex) => boolean; probeActorOf: (e: T, capIdx: CapOriginIndex) => string | null; isLoginCap: (cap: string, capIdx: CapOriginIndex) => boolean },
): { receipt: R; extraInferredEdges: E[] } {
  const termHopId = receipt.terminalImpact.terminalHopId
  if (receipt.hops.length < 2 || !receipt.hops.some(h => h.hopId === termHopId)) return { receipt, extraInferredEdges: [] }
  const outAdj = new Map<string, string[]>(receipt.hops.map(h => [h.hopId, []])), existing = new Set<string>(), hasIn = new Set<string>()
  for (const e of receipt.causalEdges) {
    existing.add(`${e.fromHopId}->${e.toHopId}:${e.kind}`)
    if (outAdj.has(e.fromHopId) && outAdj.has(e.toHopId) && e.fromHopId !== e.toHopId) { outAdj.get(e.fromHopId)!.push(e.toHopId); hasIn.add(e.toHopId) }
  }
  const needAuxRoot = receipt.hops.some(h => h.exchangeIds.length === 0 && (h.oobEventIds.length > 0 || h.browserTraceIds.length > 0) && !hasIn.has(h.hopId))
  if (dagReachesTerminal(receipt.hops, termHopId, outAdj).size === receipt.hops.length && !needAuxRoot) return { receipt, extraInferredEdges: [] }
  const entriesById = new Map((hostTranscript.entries ?? []).map(e => [e.exchangeId, e]))
  const oobById = new Map((hostTranscript.oobEvents ?? []).map(o => [o.id, o]))
  const tracesById = new Map((hostTranscript.browserTraces ?? []).map(t => [t.id, t]))
  const ownerByEx = new Map<string, string>(), ownerByOob = new Map<string, string>(), ownerByTr = new Map<string, string>()
  for (const h of receipt.hops) {
    for (const id of h.exchangeIds) if (!ownerByEx.has(id)) ownerByEx.set(id, h.hopId)
    for (const id of h.oobEventIds) if (!ownerByOob.has(id)) ownerByOob.set(id, h.hopId)
    for (const id of h.browserTraceIds) if (!ownerByTr.has(id)) ownerByTr.set(id, h.hopId)
  }
  const extra: E[] = []
  const tryAppend = (edge: DagEdgeLike): boolean => {
    if (receipt.causalEdges.length + extra.length >= DAG_MAX_EDGES) return false
    const key = `${edge.fromHopId}->${edge.toHopId}:${edge.kind}`
    if (edge.fromHopId === edge.toHopId || existing.has(key) || !outAdj.has(edge.fromHopId) || !outAdj.has(edge.toHopId) || dagCanReach(outAdj, edge.toHopId, edge.fromHopId)) return false
    existing.add(key); outAdj.get(edge.fromHopId)!.push(edge.toHopId); hasIn.add(edge.toHopId); extra.push(edge as E); return true
  }
  // 1. Host-observed async pivots (`oob_relay` & `browser_trace`)
  const validCid = (s: string | null | undefined): s is string => { const t = s?.trim() ?? ''; return t.length >= 6 && new Set(t).size >= 4 && !t.includes('[redacted') }
  const minTrig = (hop: H, cid: string): number | null => {
    const ts: number[] = []
    for (const id of hop.exchangeIds) { if (ownerByEx.get(id) !== hop.hopId) continue; const e = entriesById.get(id); if (e && is2xx(e.step.status) && isFiniteTs(e.timestampMs) && entryMatchesCorrelation(e, cid)) ts.push(e.timestampMs) }
    for (const id of hop.browserTraceIds) { if (ownerByTr.get(id) !== hop.hopId) continue; const tr = tracesById.get(id); if (tr && isFiniteTs(tr.timestampMs) && tr.correlationIds?.includes(cid)) ts.push(tr.timestampMs) }
    return ts.length > 0 ? Math.min(...ts) : null
  }
  for (const toHop of receipt.hops) {
    for (const oobId of toHop.oobEventIds) {
      if (ownerByOob.get(oobId) !== toHop.hopId) continue
      const oob = oobById.get(oobId); if (!oob?.delivered || !isFiniteTs(oob.receivedAtMs)) continue
      for (const cid of [...new Set([oob.token, oob.canaryId, oob.callbackId, ...(oob.correlationIds ?? [])].filter(validCid))]) {
        const from = receipt.hops.find(h => h.hopId !== toHop.hopId && !dagCanReach(outAdj, h.hopId, toHop.hopId) && (() => { const t = minTrig(h, cid); return t !== null && t <= oob.receivedAtMs! })())
        if (from && tryAppend({ kind: 'async_pivot_binding', fromHopId: from.hopId, toHopId: toHop.hopId, correlationId: cid, channel: 'oob_relay', oobEventId: oobId })) break
      }
    }
    for (const trId of toHop.browserTraceIds) {
      if (ownerByTr.get(trId) !== toHop.hopId) continue
      const tr = tracesById.get(trId); if (!tr || !isFiniteTs(tr.timestampMs) || !((tr.sinks?.length ?? 0) > 0 || (tr.emittedCapabilities?.length ?? 0) > 0)) continue
      for (const cid of [...new Set((tr.correlationIds ?? []).filter(validCid))]) {
        const from = receipt.hops.find(h => h.hopId !== toHop.hopId && !dagCanReach(outAdj, h.hopId, toHop.hopId) && (() => { const t = minTrig(h, cid); return t !== null && t <= tr.timestampMs! })())
        if (from && tryAppend({ kind: 'async_pivot_binding', fromHopId: from.hopId, toHopId: toHop.hopId, correlationId: cid, channel: 'browser_trace', browserTraceId: trId })) break
      }
    }
  }
  if (dagReachesTerminal(receipt.hops, termHopId, outAdj).size === receipt.hops.length) {
    return extra.length === 0 ? { receipt, extraInferredEdges: [] } : { receipt: { ...receipt, causalEdges: [...receipt.causalEdges, ...extra] }, extraInferredEdges: extra }
  }
  // 2. Single-owner sealed capabilities + opaque first-appearance Location redirect tokens
  const capEmitters = new Map<string, Array<{ hopId: string; sourceId: string; isEx: boolean; ts: number; seq: number | undefined }>>()
  const pushCap = (cap: string, em: { hopId: string; sourceId: string; isEx: boolean; ts: number; seq: number | undefined }) => {
    if (!DAG_CAP_RE.test(cap)) return; let l = capEmitters.get(cap); if (!l) { l = []; capEmitters.set(cap, l) }; l.push(em)
  }
  for (const h of receipt.hops) {
    for (const id of h.exchangeIds) {
      if (ownerByEx.get(id) !== h.hopId) continue
      const e = entriesById.get(id); if (!e || !isDagExecArm(e, h.hopId === termHopId) || !isFiniteTs(e.timestampMs)) continue
      for (const c of [...(e.emittedCapabilities ?? []), ...(e.cryptoAttestations ?? []).map(a => a.derivedCapabilityId).filter((x): x is string => Boolean(x))]) pushCap(c, { hopId: h.hopId, sourceId: id, isEx: true, ts: e.timestampMs, seq: e.seq })
    }
    for (const id of h.oobEventIds) { if (ownerByOob.get(id) !== h.hopId) continue; const o = oobById.get(id); if (o?.delivered && isFiniteTs(o.receivedAtMs)) for (const c of o.emittedCapabilities ?? []) pushCap(c, { hopId: h.hopId, sourceId: id, isEx: false, ts: o.receivedAtMs, seq: undefined }) }
    for (const id of h.browserTraceIds) { if (ownerByTr.get(id) !== h.hopId) continue; const t = tracesById.get(id); if (t && isFiniteTs(t.timestampMs)) for (const c of t.emittedCapabilities ?? []) pushCap(c, { hopId: h.hopId, sourceId: id, isEx: false, ts: t.timestampMs, seq: undefined }) }
  }
  for (const toHop of receipt.hops) {
    for (const id of toHop.exchangeIds) {
      if (ownerByEx.get(id) !== toHop.hopId) continue
      const e = entriesById.get(id); if (!e || !isDagExecArm(e, toHop.hopId === termHopId) || !isFiniteTs(e.timestampMs)) continue
      const act = actorOfEntry(e)
      for (const att of e.cryptoAttestations ?? []) {
        if (DAG_CAP_RE.test(att.derivedFromCapabilityId) && att.artifactDigest && DAG_SHA256_RE.test(att.artifactDigest.toLowerCase())) {
          const em = (capEmitters.get(att.derivedFromCapabilityId) ?? []).find(x => x.hopId !== toHop.hopId && isStrictHostChrono(x.ts, x.seq, e.timestampMs!, e.seq) && !dagCanReach(outAdj, x.hopId, toHop.hopId))
          if (em) tryAppend({ kind: 'derived_crypto_binding', fromHopId: em.hopId, toHopId: toHop.hopId, sourceCapabilityId: att.derivedFromCapabilityId, ...(att.derivedCapabilityId && DAG_CAP_RE.test(att.derivedCapabilityId) ? { derivedCapabilityId: att.derivedCapabilityId } : {}) })
        }
      }
      const consumed = new Set<string>([...(e.consumedCapabilities ?? []), ...(act && DAG_CAP_RE.test(act) ? [act] : []), ...(e.cryptoAttestations ?? []).map(a => a.derivedCapabilityId).filter((x): x is string => Boolean(x && DAG_CAP_RE.test(x)))])
      for (const cap of consumed) {
        const em = (capEmitters.get(cap) ?? []).find(x => x.hopId !== toHop.hopId && isStrictHostChrono(x.ts, x.seq, e.timestampMs!, e.seq) && !dagCanReach(outAdj, x.hopId, toHop.hopId))
        if (em) tryAppend({ kind: 'value_binding', fromHopId: em.hopId, toHopId: toHop.hopId, capabilityHandle: cap, ...(em.isEx ? { sourceExchangeId: em.sourceId } : {}), targetExchangeId: id })
      }
    }
  }
  const reachAfterCap = dagReachesTerminal(receipt.hops, termHopId, outAdj), allTranscriptEntries = hostTranscript.entries ?? []
  for (const fromHop of receipt.hops) {
    if (reachAfterCap.has(fromHop.hopId)) continue
    for (const srcId of fromHop.exchangeIds) {
      if (ownerByEx.get(srcId) !== fromHop.hopId) continue
      const src = entriesById.get(srcId); if (!src || !isDagExecArm(src, false) || !isFiniteTs(src.timestampMs) || src.step.status == null || src.step.status < 200 || src.step.status >= 400) continue
      const loc = Object.entries(src.step.responseHeaders ?? {}).find(([k]) => k.toLowerCase() === 'location')?.[1]?.trim() ?? ''
      if (!loc || (!loc.includes('?') && !loc.includes('#'))) continue
      const toks = new Set<string>(); collectUrlParamTokens(loc, toks)
      const excl = new Set([actorOfEntry(src), src.step.actor.tenant, src.origin].filter((x): x is string => Boolean(x?.trim())).map(x => x.trim().toLowerCase()))
      const digs = [...toks].filter(t => !excl.has(t.toLowerCase()) && isHighEntropyUrlTok(t)).map(t => ({ t, d: sha256Hex(t) })).filter(({ t, d }) => !tokenAppearedBeforeSrc(t, d, src, allTranscriptEntries, hostTranscript, helpers.collectDigests)).map(({ d }) => d)
      if (digs.length === 0) continue
      for (const toHop of receipt.hops) {
        if (toHop.hopId === fromHop.hopId || dagCanReach(outAdj, fromHop.hopId, toHop.hopId)) continue
        for (const dstId of toHop.exchangeIds) {
          if (ownerByEx.get(dstId) !== toHop.hopId) continue
          const dst = entriesById.get(dstId); if (!dst || !isDagExecArm(dst, toHop.hopId === termHopId) || !isFiniteTs(dst.timestampMs) || !isStrictHostChrono(src.timestampMs, src.seq, dst.timestampMs, dst.seq)) continue
          const hit = digs.find(d => helpers.collectDigests(dst, 'request').has(d))
          if (hit && tryAppend({ kind: 'value_binding', fromHopId: fromHop.hopId, toHopId: toHop.hopId, valueDigest: hit, sourceExchangeId: srcId, targetExchangeId: dstId })) break
        }
      }
    }
  }
  inferFixedPointStateTransitions(receipt, entriesById, ownerByEx, outAdj, tryAppend, helpers)
  return extra.length === 0 ? { receipt, extraInferredEdges: [] } : { receipt: { ...receipt, causalEdges: [...receipt.causalEdges, ...extra] }, extraInferredEdges: extra }
}

function inferFixedPointStateTransitions<H extends DagHopLike, E extends DagEdgeLike, R extends DagReceiptLike<H, E>, T extends DagEntryLike>(
  receipt: R, entriesById: ReadonlyMap<string, T>, ownerByEx: ReadonlyMap<string, string>,
  outAdj: ReadonlyMap<string, readonly string[]>, tryAppend: (edge: DagEdgeLike) => boolean,
  helpers: { normRouteFam: (p: string | null | undefined, eid?: string) => string; sameCredIdentity: (a: T, b: T, capIdx: CapOriginIndex) => boolean; probeActorOf: (e: T, capIdx: CapOriginIndex) => string | null; isLoginCap: (cap: string, capIdx: CapOriginIndex) => boolean },
): void {
  const termHopId = receipt.terminalImpact.terminalHopId, allHopExIds = new Set(receipt.hops.flatMap(h => h.exchangeIds)), preCtrlIds = new Set(receipt.terminalImpact.preChainControlExchangeIds)
  const capIdx = buildCapOriginIndex(entriesById.values(), ANON_HANDLE_RE), allEntries = [...entriesById.values()]
  for (let pass = 0; pass < receipt.hops.length; pass++) {
    const reaches = dagReachesTerminal(receipt.hops, termHopId, outAdj), orphans = receipt.hops.filter(h => !reaches.has(h.hopId))
    if (orphans.length === 0) break
    let changed = false
    for (const hopA of [...orphans].reverse()) {
      const fromExs = hopA.exchangeIds.filter(id => ownerByEx.get(id) === hopA.hopId).map(id => entriesById.get(id)).filter((e): e is T => Boolean(e && isDagExecArm(e, false) && is2xx(e.step.status) && isFiniteTs(e.timestampMs) && !stepReadsState(e.step)))
      if (fromExs.length === 0) continue
      for (const hopB of receipt.hops.filter(h => h.hopId !== hopA.hopId && reaches.has(h.hopId))) {
        const toExs = hopB.exchangeIds.filter(id => ownerByEx.get(id) === hopB.hopId).map(id => entriesById.get(id)).filter((e): e is T => Boolean(e && isDagExecArm(e, hopB.hopId === termHopId) && is2xx(e.step.status) && isFiniteTs(e.timestampMs)))
        const pair = fromExs.flatMap(f => toExs.filter(t => isStrictHostChrono(f.timestampMs!, f.seq, t.timestampMs!, t.seq)).map(t => ({ f, t })))[0]; if (!pair) continue
        const pairExIds = new Set([...hopA.exchangeIds, ...hopB.exchangeIds])
        const hostCands = [...new Set([pair.f.entityId, pair.t.entityId].filter((x): x is string => Boolean(x?.trim())).map(x => x.trim()))]
        const sharedEid = hostCands.find(eid => entryMatchesEntity(pair.f, eid) && entryMatchesEntity(pair.t, eid))
        if (!sharedEid) {
          const elRes = resolveEntityLessReadStateTransition({ fromEx: pair.f, fromHopEntityId: hopA.entityId, toEx: pair.t, isTerminalTo: hopB.hopId === termHopId, allEntries, pairExIds, allHopExIds, preCtrlIds, normRouteFam: helpers.normRouteFam, sameCredIdentity: (a, b) => helpers.sameCredIdentity(a, b, capIdx), probeActorOf: e => helpers.probeActorOf(e, capIdx), isLoginCap: c => helpers.isLoginCap(c, capIdx), canonicalNonAuthQuery })
          if (elRes && tryAppend({ kind: 'state_transition_binding', fromHopId: hopA.hopId, toHopId: hopB.hopId, entityId: elRes.entityId, ablationExchangeIds: [elRes.ablationExchangeId] })) { changed = true; break }; continue }
        const toUsesCap = Boolean(actorOfEntry(pair.t)?.startsWith('cap:') || (pair.t.consumedCapabilities?.length ?? 0) > 0 || (pair.t.cryptoAttestations?.length ?? 0) > 0)
        const toFam = helpers.normRouteFam(pair.t.step.route ?? pair.t.step.pathAndQuery, sharedEid)
        const isCleanAb = (ab: T): boolean => {
          if (pairExIds.has(ab.exchangeId) || (!preCtrlIds.has(ab.exchangeId) && allHopExIds.has(ab.exchangeId)) || ab.cleanSession !== true || (ab.step.arm !== 'control' && ab.replayAttempt !== 'ablation_control') || typeof ab.step.status !== 'number' || !DAG_ABLATION_DENIED_STATUSES.has(ab.step.status)) return false
          const abRaw = actorOfEntry(ab), toRaw = actorOfEntry(pair.t), toAuth = Boolean(toRaw && !ANON_HANDLE_RE.test(toRaw))
          if (abRaw?.startsWith('cap:') && abRaw !== toRaw && !helpers.isLoginCap(abRaw, capIdx)) return false
          if (!toUsesCap && toAuth && abRaw !== null && !helpers.sameCredIdentity(ab, pair.t, capIdx)) return false
          const sameFam = Boolean(toFam) && helpers.normRouteFam(ab.step.route ?? ab.step.pathAndQuery, ab.entityId ?? sharedEid) === toFam
          return entryMatchesEntity(ab, sharedEid) || sameFam
        }
        const ab = allEntries.find(e => preCtrlIds.has(e.exchangeId) && isCleanAb(e)) ?? allEntries.find(e => e.replayAttempt === 'ablation_control' && isCleanAb(e)) ?? allEntries.find(isCleanAb)
        if (ab && tryAppend({ kind: 'state_transition_binding', fromHopId: hopA.hopId, toHopId: hopB.hopId, entityId: sharedEid, ablationExchangeIds: [ab.exchangeId] })) { changed = true; break }
      }
    }
    if (!changed) break
  }
}

/** Concise rejection diagnostics for matching-route candidate controls when `terminalCtrl` is absent. */
export function diagnoseRejectedTerminalControls<T extends DagEntryLike>(
  candidates: readonly string[], entriesById: ReadonlyMap<string, T>, termEx: T | undefined, postMutRb: T | undefined,
  termFam: string, termRawActor: string | null, termAuthd: boolean, nonTermExSet: ReadonlySet<string>, termAblationIds: ReadonlySet<string>,
  hasExplicitVerifiedTermEdge: boolean, hasForeignTenantData: boolean, hopCount: number, capIdx: CapOriginIndex,
  h: { normRouteFam: (p: string | null | undefined, eid?: string) => string; matchesNormalizedCtrlPath: (a: string | null | undefined, b: string | null | undefined) => boolean; matchesBoundTerminalControl: (c: T, ref: T) => boolean; sameCredIdentity: (a: T, b: T, capIdx: CapOriginIndex) => boolean; probeTenantOf: (e: T, capIdx?: CapOriginIndex) => string | null; isLoginCap: (cap: string, capIdx: CapOriginIndex) => boolean },
): string[] {
  const seen = new Set<string>(), out: string[] = [], normOrig = (o: string | null | undefined) => (o ?? '').trim().replace(/\/+$/, '').toLowerCase()
  const rbFam = postMutRb ? h.normRouteFam(postMutRb.step.route ?? postMutRb.step.pathAndQuery, postMutRb.entityId) : ''
  const onRoute = (cp: string, cf: string, ref: T | undefined, rf: string) => Boolean(ref && ((rf && cf === rf) || (cleanExactPath(cp) && cleanExactPath(cp) === cleanExactPath(ref.step.pathAndQuery ?? ref.step.route ?? '')) || h.matchesNormalizedCtrlPath(cp, ref.step.pathAndQuery ?? ref.step.route) || matchesNormalizedDotSegmentPath(cp, ref.step.pathAndQuery ?? ref.step.route)))
  for (const id of candidates) {
    if (out.length >= 3 || seen.has(id) || (termEx && id === termEx.exchangeId)) continue; seen.add(id)
    const c = entriesById.get(id); if (!c) continue
    const cp = c.step.pathAndQuery ?? c.step.route ?? '', cf = h.normRouteFam(c.step.route ?? c.step.pathAndQuery, c.entityId)
    const onTerm = onRoute(cp, cf, termEx, termFam), onRb = onRoute(cp, cf, postMutRb, rbFam); if (!onTerm && !onRb) continue
    const reasons: string[] = [], st = c.step.status, cRaw = actorOfEntry(c), isCap = Boolean(cRaw?.startsWith('cap:')), anon401 = !cRaw || ANON_HANDLE_RE.test(cRaw) || (isCap && cRaw !== termRawActor)
    if (nonTermExSet.has(c.exchangeId)) reasons.push('in_non_terminal_hop')
    if (c.step.arm !== 'control' && c.replayAttempt !== 'ablation_control') reasons.push(`arm=${c.step.arm} (pass arm:'control')`)
    if (!(typeof st === 'number' && (DAG_DENIED_CTRL_STATUSES.has(st) || (termAblationIds.has(c.exchangeId) && DAG_ABLATION_DENIED_STATUSES.has(st))))) reasons.push(`status=${st ?? 'null'} (need 401/403/404)`)
    const peer = Boolean(hopCount >= 2 && hasExplicitVerifiedTermEdge && st === 403 && termEx && hasForeignTenantData && !isPrivilegedActorOrRole(cRaw, resolveEntryIdentity(c).role, c.actorRoleLabel) && h.probeTenantOf(c, capIdx) && h.probeTenantOf(c, capIdx) === h.probeTenantOf(termEx, capIdx) && cleanExactPath(cp) === cleanExactPath(termEx.step.pathAndQuery ?? termEx.step.route ?? ''))
    if ((isCap && cRaw !== termRawActor && !h.isLoginCap(cRaw!, capIdx)) || (termAuthd && !(st === 401 && anon401) && (!termEx || (!h.sameCredIdentity(c, termEx, capIdx) && !peer)))) reasons.push('cred_identity_mismatch')
    else if (st === 401 && termAuthd && anon401) reasons.push('anon_401_for_authd_terminal')
    const ref = onTerm ? termEx : postMutRb, rp = ref ? (ref.step.pathAndQuery ?? ref.step.route ?? '') : ''
    const dot = Boolean(ref && (!c.origin || !ref.origin || normOrig(c.origin) === normOrig(ref.origin)) && c.step.method.toUpperCase() === ref.step.method.toUpperCase() && canonicalNonAuthQuery(cp) === canonicalNonAuthQuery(rp) && matchesNormalizedDotSegmentPath(cp, rp))
    if (ref && !(h.matchesBoundTerminalControl(c, ref) || dot || Boolean(postMutRb && ref !== postMutRb && h.matchesBoundTerminalControl(c, postMutRb)))) reasons.push(c.origin && ref.origin && normOrig(c.origin) !== normOrig(ref.origin) ? 'origin_mismatch' : c.step.method.toUpperCase() !== ref.step.method.toUpperCase() ? `method_mismatch (${c.step.method.toUpperCase()}!=${ref.step.method.toUpperCase()})` : canonicalNonAuthQuery(cp) !== canonicalNonAuthQuery(rp) ? 'query_mismatch' : cleanExactPath(cp) === cleanExactPath(rp) ? 'entity_id_mismatch' : st === 404 ? 'status_404_dynamic_path' : 'sibling_object_unbound')
    if (reasons.length > 0) out.push(`${c.exchangeId}: ${reasons.join(', ')}`)
  }
  return out
}
