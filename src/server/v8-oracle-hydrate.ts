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
import { parseBodyFromCarrierText } from './host-fact-log.ts'
import { ROLE_RANK, normalizeRole, parseRoleLabel, parseRoleMemberships, stepReadsState, type RoleName } from './oracle-invariants.ts'
import type { ProofReceipt } from './proof-receipt.ts'
import { extractTenantMarkers, isJobOrHandleStub, type HostSignedRecord, type V8OracleFamily } from './v8-oracle-families.ts'

export interface HydratableEntry {
  exchangeId: string
  seq?: number
  timestampMs?: number
  actorPersona?: string | null
  actorRoleLabel?: string | null
  emittedCapabilities?: readonly string[]
  observedResponseDigests?: readonly string[]
  consumedCapabilities?: readonly string[]
  injectedRequestDigests?: readonly string[]
  cryptoAttestations?: readonly { derivedFromCapabilityId: string; derivedCapabilityId?: string; artifactDigest?: string }[]
  entityId?: string
  correlationIds?: readonly string[]
  carrierText?: string
  hostSignature?: string
  evidenceRole?: string
  step: {
    arm: string
    method: string
    route?: string
    pathAndQuery?: string
    status: number | null
    actor: { handle?: string | null; role?: string | null; tenant?: string | null; auth?: string }
    body?: string
    json?: unknown
    requestJson?: unknown
    requestHeaders?: Record<string, string> | null
    responseHeaders?: Record<string, string> | null
    evidenceRole?: string
  }
}

export interface HydratableOobEvent {
  id: string
  delivered: boolean
  receivedAtMs?: number
  token?: string
  emittedCapabilities?: readonly string[]
  observedValueDigests?: readonly string[]
  hostSignature?: string
}

export interface HydratableBrowserTrace {
  id: string
  timestampMs?: number
  actorPersona?: string | null
  emittedCapabilities?: readonly string[]
  observedValueDigests?: readonly string[]
  hostSignature?: string
}

export interface HydratableTranscriptIndex {
  entriesById: ReadonlyMap<string, HydratableEntry>
  oobById?: ReadonlyMap<string, HydratableOobEvent>
  tracesById?: ReadonlyMap<string, HydratableBrowserTrace>
}

export interface EconomicAutoHydrateContext {
  preChainControlExchangeIds: readonly string[]
  termHopExchangeIds: readonly string[]
  postChainReadbackExchangeIds: readonly string[]
  citedExchangeIds?: readonly string[]
}

const sha256Hex = (value: string): string => createHash('sha256').update(value, 'utf8').digest('hex')
const isFiniteTs = (ts: unknown): ts is number => typeof ts === 'number' && Number.isFinite(ts) && ts >= 0
const isPosTs = (ts: unknown): ts is number => typeof ts === 'number' && Number.isFinite(ts) && ts > 0
const is2xx = (st: number | null | undefined): boolean => typeof st === 'number' && st >= 200 && st < 300
const actorOfEntry = (e: HydratableEntry): string | null =>
  e.actorPersona !== undefined ? e.actorPersona : (e.step.actor.handle ?? null)
const roleOfEntry = (e: HydratableEntry): string | null =>
  e.actorRoleLabel ? parseRoleLabel(e.actorRoleLabel).role : (e.step.actor.role ?? null)

const PRIV_HANDLE_RE = /^(?:admin|owner|super_?admin|org_?admin|tenant_?admin|root|system|manager|operator|staff|superuser)(?:[_-]|$)|(?:^|[_-])(?:super_?admin|org_?admin|tenant_?admin|owner|root)$/i
const PRIV_ROLE_WORD_RE = /(?:^|[^a-z])(owner|superadmin|super|admin|administrator|manager|staff|operator|root|superuser)(?:$|[^a-z])/i
const GLOBAL_PRIV_LABEL_RE = /(?:^|[\s,:;_@(-])(?:super[\s_-]?admin|platform[\s_-]?admin|sys[\s_-]?admin|global[\s_-]?admin|root|superuser|owner)(?:$|[\s,:;_@)-])/i
const LOW_PRIV_ROLE_SET = new Set(['viewer', 'member', 'guest', 'user', 'editor', 'customer', 'anon', 'anonymous', 'unauthenticated', 'revoked', 'demoted', 'readonly', 'basic', 'standard', 'contractor', 'external', 'analyst', 'billing', 'support', 'developer', 'contributor', 'requester', 'reporter', 'subscriber', 'client', 'partner', 'tenant'])
const MIN_TOKEN_LEN = 3
const SIG_HEADER_NAMES = new Set(['x-sig', 'x-signature', 'x-hmac-signature', 'x-hub-signature-256', 'x-webhook-signature', 'x-kovo-derivation'])
const SURFACE_SET = new Set(['http', 'graphql', 'ws', 'sse', 'browser', 'webhook', 'async_job', 'idp', 'cdn', 'storage'])
const EDGE_KIND_SET = new Set(['value_binding', 'derived_crypto_binding', 'state_transition_binding', 'async_pivot_binding'])
const DUAL_MODE_SET = new Set(['cross_org_transfer', 'dual_org_cache_bleed', 'batch_partial_authz'])
const CRED_KIND_SET = new Set(['token', 'session', 'role', 'invite', 'pat', 'async_job', 'webhook_callback'])
const ECON_EQ_SET = new Set(['over_refund', 'balance_minting', 'underpaid_fulfillment', 'ineligible_discount'])
const PARSER_MODE_SET = new Set(['parser_differential', 'cache_primed'])
const DIFF_KIND_SET = new Set(['duplicate_json_key', 'path_normalization', 'header_normalization', 'hop_by_hop_smuggling', 'content_type_confusion'])
const IMPACT_KIND_SET = new Set(['read', 'mutation'])
const PIVOT_CTRL_SET = new Set(['authz_denied', 'unreachable_internal'])
const PIVOT_ROLE_SET = new Set(['trigger_write', 'browser_dom_trace', 'admin_bot_visit', 'worker_ssrf_callback', 'oob_callback', 'oidc_redirect', 'token_exchange', 'terminal_impact'])
const PIVOT_IMPACT_SET = new Set(['privileged_read', 'privileged_mutation', 'credential_capture', 'internal_secret_exfil', 'privilege_escalation'])
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
    if (labelCls === 'owner' || labelCls === 'admin' || labelCls === 'unknown') return true
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

export interface CapEmitterOrigin {
  exchangeId: string
  arm: string
  isLogin: boolean
  actor: string | null
  role: string | null
  roleLabel: string | null
  tenant: string | null
}

export interface CapOriginIndex {
  loginTenantOf(cap: string): string | null
  loginActorOf(cap: string): { actor: string | null; role: string | null; roleLabel: string | null } | null
  nonProbeOriginActorOf(cap: string): { actor: string | null; role: string | null; roleLabel: string | null } | null
  emitterActorOf(cap: string): CapEmitterOrigin | null
  actorOf(cap: string): string | null
}

/**
 * Index host-signed transcript entries by emitted capability handle (`cap:*`) so verifiers can:
 *  - propagate originating `POST /login` tenant/actor provenance onto `cap:*` sessions;
 *  - resolve `emitterActorOf` for ALL capability emitters (login, setup, control, probe, host ops);
 *  - trace derived-capability actor lineage cleanly across hops in `state_transition_binding`.
 */
export function buildCapOriginIndex(entries: Iterable<HydratableEntry>, anonActorRe: RegExp): CapOriginIndex {
  const isHostOp = (e: HydratableEntry): boolean =>
    e.evidenceRole === 'host_capability_op' || e.evidenceRole === 'host_crypto_op'
  const isLoginEx = (e: HydratableEntry): boolean => {
    if (isHostOp(e) || e.step.method.toUpperCase() !== 'POST' || !is2xx(e.step.status)) return false
    const route = (e.step.route ?? e.step.pathAndQuery ?? '').split('?', 1)[0] ?? ''
    return LOGIN_ROUTE_RE.test(route)
  }
  const emitterByCap = new Map<string, HydratableEntry>()
  for (const e of entries) {
    const caps = [
      ...(e.emittedCapabilities ?? []),
      ...(e.cryptoAttestations ?? []).map(a => a.derivedCapabilityId).filter((c): c is string => Boolean(c)),
    ]
    for (const cap of caps) {
      const prev = emitterByCap.get(cap)
      if (!prev || (isHostOp(prev) && !isHostOp(e)) || (!isLoginEx(prev) && isLoginEx(e))) {
        emitterByCap.set(cap, e)
      }
    }
  }

  const directTenant = (e: HydratableEntry): string | null => {
    const a = actorOfEntry(e)
    if (!a || anonActorRe.test(a) || a.startsWith('cap:')) return null
    return (e.step.actor.tenant ?? parseRoleLabel(e.actorRoleLabel ?? e.actorPersona ?? '').tenant ?? '').trim().toLowerCase() || null
  }

  const loginTenantOf = (cap: string): string | null => {
    const e = emitterByCap.get(cap)
    if (!e || !isLoginEx(e)) return null
    return directTenant(e)
      ?? findFirstStringByKeys(e.step.json, LOGIN_TENANT_KEYS)
      ?? findFirstStringByKeys(e.step.requestJson, LOGIN_TENANT_KEYS)
      ?? findFirstStringByKeys(e.step.json, LOGIN_EMAIL_KEYS)
      ?? findFirstStringByKeys(e.step.requestJson, LOGIN_EMAIL_KEYS)
  }

  const loginActorOf = (cap: string): { actor: string | null; role: string | null; roleLabel: string | null } | null => {
    const e = emitterByCap.get(cap)
    if (!e || !isLoginEx(e)) return null
    const a = actorOfEntry(e)
    const cleanActor = (!a || anonActorRe.test(a) || a.startsWith('cap:')) ? null : a
    const r = roleOfEntry(e)
    return (cleanActor || r || e.actorRoleLabel)
      ? { actor: cleanActor, role: r, roleLabel: e.actorRoleLabel ?? null }
      : null
  }

  const emitterActorOf = (cap: string, visited = new Set<string>()): CapEmitterOrigin | null => {
    const e = emitterByCap.get(cap)
    if (!e || visited.has(cap) || visited.size > 8) return null
    visited.add(cap)
    const a = actorOfEntry(e)
    const cleanActor = (!a || anonActorRe.test(a) || a.startsWith('cap:')) ? null : a
    const r = roleOfEntry(e)
    if (cleanActor || r || e.actorRoleLabel) {
      return {
        exchangeId: e.exchangeId,
        arm: e.step.arm,
        isLogin: isLoginEx(e),
        actor: cleanActor,
        role: r,
        roleLabel: e.actorRoleLabel ?? null,
        tenant: directTenant(e),
      }
    }
    const parents = [
      ...(a?.startsWith('cap:') ? [a] : []),
      ...(e.consumedCapabilities ?? []),
      ...(e.cryptoAttestations ?? []).map(x => x.derivedFromCapabilityId),
    ]
    for (const parent of parents) {
      const origin = emitterActorOf(parent, visited)
      if (origin) return { ...origin, exchangeId: e.exchangeId, arm: e.step.arm, isLogin: isLoginEx(e) || origin.isLogin }
    }
    return {
      exchangeId: e.exchangeId,
      arm: e.step.arm,
      isLogin: isLoginEx(e),
      actor: null,
      role: null,
      roleLabel: null,
      tenant: null,
    }
  }

  const nonProbeOriginActorOf = (cap: string, visited = new Set<string>()): { actor: string | null; role: string | null; roleLabel: string | null } | null => {
    const e = emitterByCap.get(cap)
    if (!e || visited.has(cap) || visited.size > 8) return null
    visited.add(cap)
    if (!isLoginEx(e) && e.step.arm === 'probe') return null
    const origin = emitterActorOf(cap)
    if (origin && (origin.actor || origin.role || origin.roleLabel)) {
      return { actor: origin.actor, role: origin.role, roleLabel: origin.roleLabel }
    }
    return isLoginEx(e) ? null : { actor: 'unattributed', role: 'owner', roleLabel: 'owner (unattributed)' }
  }

  const actorOf = (cap: string, visited = new Set<string>()): string | null => {
    if (visited.has(cap) || visited.size > 8) return null
    visited.add(cap)
    const e = emitterByCap.get(cap)
    if (!e) return null
    const a = actorOfEntry(e)?.trim().toLowerCase() ?? ''
    if (a && !anonActorRe.test(a) && !a.startsWith('cap:')) return a
    const nextCaps = [
      ...(a.startsWith('cap:') ? [a] : []),
      ...(e.consumedCapabilities ?? []),
      ...(e.cryptoAttestations ?? []).map(x => x.derivedFromCapabilityId),
    ]
    for (const nc of nextCaps) {
      const hit = actorOf(nc, visited)
      if (hit) return hit
    }
    if (isLoginEx(e)) {
      return findFirstStringByKeys(e.step.requestJson, LOGIN_EMAIL_KEYS)
        ?? findFirstStringByKeys(e.step.json, LOGIN_EMAIL_KEYS)
    }
    return null
  }

  return { loginTenantOf, loginActorOf, nonProbeOriginActorOf, emitterActorOf: (cap: string) => emitterActorOf(cap), actorOf: (cap: string) => actorOf(cap) }
}

/** True when a hydrated `HostSignedRecord` is an intermediate job/export/handle stub rather than terminal impact. */
export function isHydratedStub(rec: unknown): boolean {
  if (!rec || typeof rec !== 'object') return false
  const r = rec as HostSignedRecord
  return isJobOrHandleStub(r.json, r.body, r.status, r.method, r.route)
}

/** Convert a host transcript entry into a `HostSignedRecord` for v8 oracle family evaluators. */
export function toOracleRecord(e: HydratableEntry, fallbackSig: string): HostSignedRecord {
  return {
    id: e.exchangeId,
    hostSignature: e.hostSignature ?? fallbackSig,
    timestampMs: isPosTs(e.timestampMs) ? e.timestampMs : 1,
    status: e.step.status,
    method: e.step.method,
    route: e.step.route ?? e.step.pathAndQuery,
    actorId: actorOfEntry(e),
    tenantId: e.step.actor.tenant ?? null,
    body: e.step.body,
    json: e.step.json,
    requestHeaders: e.step.requestHeaders ?? null,
    responseHeaders: e.step.responseHeaders ?? null,
    capabilityHandle: e.emittedCapabilities?.[0] ?? e.consumedCapabilities?.[0] ?? null,
    artifactDigest: e.observedResponseDigests?.[0] ?? e.cryptoAttestations?.[0]?.artifactDigest
      ?? sha256Hex(e.step.body ?? JSON.stringify(e.step.json ?? null)),
    derivedFromCapabilityId: e.cryptoAttestations?.[0]?.derivedFromCapabilityId ?? null,
  }
}

function lookupOracleRecord(id: string, idx: HydratableTranscriptIndex, fallbackSig: string): HostSignedRecord | undefined {
  const entry = idx.entriesById.get(id)
  if (entry) return toOracleRecord(entry, fallbackSig)
  const oob = idx.oobById?.get(id)
  if (oob) {
    return {
      id: oob.id,
      hostSignature: oob.hostSignature ?? fallbackSig,
      timestampMs: isPosTs(oob.receivedAtMs) ? oob.receivedAtMs : 1,
      surface: 'webhook',
      status: oob.delivered ? 200 : 0,
      capabilityHandle: oob.emittedCapabilities?.[0] ?? null,
      artifactDigest: oob.observedValueDigests?.[0] ?? (oob.token ? sha256Hex(oob.token) : null),
    }
  }
  const tr = idx.tracesById?.get(id)
  if (tr) {
    return {
      id: tr.id,
      hostSignature: tr.hostSignature ?? fallbackSig,
      timestampMs: isPosTs(tr.timestampMs) ? tr.timestampMs : 1,
      surface: 'browser',
      actorId: tr.actorPersona ?? null,
      capabilityHandle: tr.emittedCapabilities?.[0] ?? null,
      artifactDigest: tr.observedValueDigests?.[0] ?? null,
    }
  }
  return undefined
}

/** Verify that a `HostSignedRecord` matches the host-transcript record for `rec.id` field-for-field. */
export function matchesHydratedRecord(
  rec: HostSignedRecord,
  idx: HydratableTranscriptIndex,
  fallbackSig: string,
): boolean {
  const expected = lookupOracleRecord(rec.id, idx, fallbackSig)
  if (!expected) return false
  return rec.hostSignature === expected.hostSignature
    && rec.timestampMs === expected.timestampMs
    && rec.status === expected.status
    && rec.method === expected.method
    && rec.route === expected.route
    && rec.body === expected.body
    && rec.json === expected.json
    && rec.artifactDigest === expected.artifactDigest
    && rec.actorId === expected.actorId
    && rec.tenantId === expected.tenantId
    && rec.capabilityHandle === expected.capabilityHandle
    && rec.derivedFromCapabilityId === expected.derivedFromCapabilityId
}

function hydrateRecordValue(raw: unknown, idx: HydratableTranscriptIndex, fallbackSig: string): unknown {
  if (raw === undefined || raw === null) return undefined
  if (typeof raw === 'string') {
    const id = raw.trim()
    return id ? lookupOracleRecord(id, idx, fallbackSig) : undefined
  }
  if (typeof raw === 'object' && !Array.isArray(raw)) {
    const obj = raw as Record<string, unknown>
    const id = typeof obj.exchangeId === 'string' && obj.exchangeId.trim()
      ? obj.exchangeId.trim()
      : typeof obj.id === 'string' && obj.id.trim()
        ? obj.id.trim()
        : ''
    if (!id) return undefined
    const found = lookupOracleRecord(id, idx, fallbackSig)
    if (found) return found
    // Never trust caller-supplied inline record fields (`status`/`timestampMs`/`json`/`body`/`artifactDigest`):
    // fail closed when absent from `idx`, keeping only an unverified id/sig stub when `hostSignature` was
    // supplied so signature verification rejects it explicitly.
    return typeof obj.hostSignature === 'string'
      ? { id, hostSignature: obj.hostSignature, timestampMs: 1 }
      : undefined
  }
  return undefined
}

/**
 * Universal structural record-role hydrator: resolves `raw[field]`, `raw[field + 'ExchangeId']`,
 * or a structural short-base alias without maintaining a rigid per-family English alias table.
 */
function hydrateRoleField(
  out: Record<string, unknown>,
  raw: Record<string, unknown>,
  field: string,
  idx: HydratableTranscriptIndex,
  fallbackSig: string,
  extraAlias?: string,
): boolean {
  const candidates = [field, `${field}ExchangeId`, ...(extraAlias ? [extraAlias] : [])]
  for (const key of candidates) {
    if (raw[key] !== undefined) {
      out[field] = hydrateRecordValue(raw[key], idx, fallbackSig)
      return true
    }
  }
  return false
}

function hydrateRecordArrayField(
  out: Record<string, unknown>,
  raw: Record<string, unknown>,
  field: string,
  aliases: readonly string[],
  idx: HydratableTranscriptIndex,
  fallbackSig: string,
): boolean {
  let src = raw[field]
  if (src === undefined) {
    for (const alias of aliases) {
      if (raw[alias] !== undefined) { src = raw[alias]; break }
    }
  }
  if (src === undefined) return false
  if (Array.isArray(src)) {
    out[field] = src.map(item => hydrateRecordValue(item, idx, fallbackSig))
  } else if (typeof src === 'string' || (typeof src === 'object' && src !== null)) {
    const hydrated = hydrateRecordValue(src, idx, fallbackSig)
    out[field] = hydrated !== undefined ? [hydrated] : []
  } else {
    out[field] = []
  }
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
  const keySet = new Set(keys)
  const queue: Array<{ node: unknown; depth: number }> = [{ node: root, depth: 0 }]
  while (queue.length > 0) {
    const { node, depth } = queue.shift()!
    if (depth > 4 || node == null || typeof node !== 'object') continue
    if (Array.isArray(node)) {
      for (const item of node.slice(0, 32)) queue.push({ node: item, depth: depth + 1 })
      continue
    }
    const obj = node as Record<string, unknown>
    for (const k of keys) {
      for (const [ek, ev] of Object.entries(obj)) {
        if (ek.toLowerCase() === k && typeof ev === 'number' && Number.isFinite(ev)) return ev
      }
    }
    for (const [ek, ev] of Object.entries(obj)) {
      if (!keySet.has(ek.toLowerCase()) && ev && typeof ev === 'object') queue.push({ node: ev, depth: depth + 1 })
    }
  }
  return undefined
}

function findStringField(root: unknown, keys: readonly string[]): string | undefined {
  if (root == null || typeof root !== 'object') return undefined
  const queue: Array<{ node: unknown; depth: number }> = [{ node: root, depth: 0 }]
  while (queue.length > 0) {
    const { node, depth } = queue.shift()!
    if (depth > 4 || node == null || typeof node !== 'object') continue
    if (Array.isArray(node)) {
      for (const item of node.slice(0, 32)) queue.push({ node: item, depth: depth + 1 })
      continue
    }
    const obj = node as Record<string, unknown>
    for (const k of keys) {
      for (const [ek, ev] of Object.entries(obj)) {
        if (ek.toLowerCase() === k && typeof ev === 'string' && ev.trim().length > 0) return ev.trim()
      }
    }
    for (const ev of Object.values(obj)) {
      if (ev && typeof ev === 'object') queue.push({ node: ev, depth: depth + 1 })
    }
  }
  return undefined
}

function extractBalanceMap(rec: HostSignedRecord | undefined): Record<string, number> | undefined {
  const json = parseRecJson(rec)
  if (json == null || typeof json !== 'object') return undefined
  const obj = json as Record<string, unknown>
  for (const mapKey of ['balances', 'accounts', 'wallets']) {
    const sub = obj[mapKey]
    if (sub && typeof sub === 'object' && !Array.isArray(sub)) {
      const map: Record<string, number> = {}
      for (const [k, n] of Object.entries(sub as Record<string, unknown>)) {
        if (!FORBIDDEN_KEYS.has(k) && typeof n === 'number' && Number.isFinite(n)) map[k] = n
      }
      if (Object.keys(map).length > 0) return map
    }
    if (Array.isArray(sub)) {
      const map: Record<string, number> = {}
      for (const item of sub.slice(0, 32)) {
        if (!item || typeof item !== 'object' || Array.isArray(item)) continue
        const acct = findStringField(item, ['accountid', 'account_id', 'walletid', 'wallet_id', 'id'])
        const bal = findNumericField(item, ['balance', 'balancecents', 'balance_cents', 'availablebalance', 'available_balance', 'credits', 'funds', 'amount'])
        if (acct && bal !== undefined) map[acct] = bal
      }
      if (Object.keys(map).length > 0) return map
    }
  }
  const single = findNumericField(json, ['balance', 'balancecents', 'balance_cents', 'availablebalance', 'available_balance', 'walletbalance', 'wallet_balance', 'ledgerbalance', 'ledger_balance', 'credits', 'funds'])
  if (single !== undefined) {
    const acct = findStringField(json, ['accountid', 'account_id', 'walletid', 'wallet_id', 'userid', 'user_id', 'id']) ?? 'default'
    return { [acct]: single }
  }
  return undefined
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
  if (rec?.requestHeaders) {
    for (const [k, v] of Object.entries(rec.requestHeaders)) {
      if (SIG_HEADER_NAMES.has(k.toLowerCase()) && typeof v === 'string') {
        const trimmed = v.trim()
        if (trimmed && !trimmed.includes('[redacted')) return sha256Hex(trimmed)
      }
    }
  }
  const pq = entry?.step.pathAndQuery ?? rec?.route ?? ''
  const qIdx = pq.indexOf('?')
  if (qIdx >= 0) {
    for (const [k, v] of new URLSearchParams(pq.slice(qIdx + 1)).entries()) {
      if (SIG_QUERY_KEYS.has(k.toLowerCase()) && v.trim() && !v.includes('[redacted')) return sha256Hex(v.trim())
    }
  }
  return undefined
}

function extractIssuedSigDigest(entry: HydratableEntry | undefined): string | undefined {
  if (!entry) return undefined
  const json = entry.step.json
  if (json && typeof json === 'object') {
    const sigVal = findStringField(json, ['signature', 'sig', 'hmac', 'mac', 'signedurl', 'signed_url', 'presignedurl', 'presigned_url'])
    if (sigVal && !sigVal.includes('[redacted')) {
      const m = /[?&](?:sig|signature|hmac|mac)=([^&]+)/i.exec(sigVal)
      if (!m?.[1]) return sha256Hex(sigVal)
      try { return sha256Hex(decodeURIComponent(m[1])) } catch { return sha256Hex(m[1]) }
    }
  }
  return undefined
}

const ANON_HANDLE_RE = /^(?:anon(?:ymous)?|unauth(?:enticated)?|guest)$/i

function deriveDualActorFromTranscript(
  idx: HydratableTranscriptIndex,
  citedEntries: readonly (HydratableEntry | undefined)[],
  rawActor: unknown,
): { actorId: string; rolesByTenant: Record<string, RoleName> } | undefined {
  const rawId = rawActor && typeof rawActor === 'object' && !Array.isArray(rawActor)
    ? pickStr(rawActor as Record<string, unknown>, 'actorId', 128)
    : undefined
  const citedActors = citedEntries
    .map(e => (e ? actorOfEntry(e)?.trim() ?? '' : ''))
    .filter(a => Boolean(a) && !ANON_HANDLE_RE.test(a) && !a.startsWith('cap:'))
  if (citedActors.length === 0) return undefined
  let actorId: string | undefined
  if (rawId) {
    actorId = citedActors.find(a => a.toLowerCase() === rawId.toLowerCase())
    if (!actorId) return undefined
  } else {
    actorId = citedActors[0]
  }
  if (!actorId) return undefined
  const rolesByTenant: Record<string, RoleName> = {}
  const recordRole = (tenant: string | null | undefined, role: RoleName | null | undefined) => {
    const t = tenant?.trim().toLowerCase()
    if (!t || !role || FORBIDDEN_KEYS.has(t)) return
    const prev = rolesByTenant[t]
    if (!prev || ROLE_RANK[role] > ROLE_RANK[prev]) rolesByTenant[t] = role
  }
  const actorLower = actorId.toLowerCase()
  for (const e of idx.entriesById.values()) {
    const ea = actorOfEntry(e)?.trim().toLowerCase() ?? ''
    if (ea !== actorLower) continue
    if (e.actorRoleLabel) {
      for (const m of parseRoleMemberships(e.actorRoleLabel)) recordRole(m.tenant, m.role)
      const pl = parseRoleLabel(e.actorRoleLabel)
      recordRole(pl.tenant, pl.role)
    }
    recordRole(e.step.actor.tenant ?? parseRoleLabel(e.actorPersona ?? '').tenant, normalizeRole(roleOfEntry(e) ?? undefined))
  }
  return { actorId, rolesByTenant }
}

function canonicalDiffHeaders(headers: Readonly<Record<string, string>> | null | undefined): string {
  if (!headers) return ''
  return Object.entries(headers)
    .map(([k, v]) => [k.trim().toLowerCase(), String(v).trim()] as const)
    .filter(([k]) => Boolean(k) && !VOLATILE_DIFF_HEADERS.has(k))
    .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
    .map(([k, v]) => `${k}:${v}`)
    .join('\n')
}

function headerLookupCI(headers: Readonly<Record<string, string>> | null | undefined, name: string): string {
  if (!headers) return ''
  const target = name.toLowerCase()
  for (const [k, v] of Object.entries(headers)) {
    if (k.trim().toLowerCase() === target) return String(v).trim()
  }
  return ''
}

function rawRequestBodyText(entry: HydratableEntry | undefined): string {
  if (!entry) return ''
  const req = entry.step.requestJson
  if (typeof req === 'string') return req.trim()
  if (req !== undefined && req !== null) {
    try { return JSON.stringify(req) } catch { return '' }
  }
  const response = typeof entry.step.body === 'string'
    ? entry.step.body
    : entry.step.json !== undefined ? JSON.stringify(entry.step.json) : null
  return parseBodyFromCarrierText(entry.carrierText, entry.step.requestHeaders, response)?.trim() ?? ''
}

function hasDuplicateJsonKeyInRaw(raw: string): boolean {
  const s = raw.trim()
  if (!s.startsWith('{') && !s.startsWith('[')) return false
  const stack: Array<Set<string> | null> = []
  let i = 0
  while (i < s.length) {
    const ch = s[i]!
    if (ch === '{') { stack.push(new Set<string>()); i += 1; continue }
    if (ch === '[') { stack.push(null); i += 1; continue }
    if (ch === '}' || ch === ']') { stack.pop(); i += 1; continue }
    if (ch === '"') {
      let j = i + 1
      while (j < s.length) {
        if (s[j] === '\\') { j += 2; continue }
        if (s[j] === '"') break
        j += 1
      }
      const key = s.slice(i + 1, j)
      let k = j + 1
      while (k < s.length && /\s/.test(s[k]!)) k += 1
      const top = stack[stack.length - 1]
      if (s[k] === ':' && top instanceof Set) {
        if (top.has(key)) return true
        top.add(key)
      }
      i = j + 1
      continue
    }
    i += 1
  }
  return false
}

function isInternalTransferRequest(request: unknown): boolean {
  if (!request || typeof request !== 'object' || Array.isArray(request)) return false
  const keys = new Set(Object.keys(request as Record<string, unknown>).map(key => key.replace(/[_-]/g, '').toLowerCase()))
  return INTERNAL_TRANSFER_PAIRS.some(([from, to]) => keys.has(from) && keys.has(to))
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
  const out: Record<string, unknown> = {}
  const explicit = new Set<string>()
  const hydrateRole = (field: string, extraAlias?: string): void => {
    if (hydrateRoleField(out, rawInput, field, idx, fallbackSig, extraAlias)) explicit.add(field)
  }

  if (family === 'dual_tenant_abac') {
    for (const [f, a] of [
      ['transferRecord', 'transferExchangeId'], ['postTransferReadback'], ['sourceControlDenied', 'sourceControlExchangeId'],
      ['baselineDeniedControl', 'baselineControlExchangeId'], ['primeAction'], ['bledAccess'],
      ['singleForeignControlDenied', 'singleForeignControlExchangeId'], ['batchRequest'], ['postMutationReadback'],
    ] as const) hydrateRole(f, a)
    const mode = pickEnum(rawInput, 'mode', DUAL_MODE_SET)
    if (mode) out.mode = mode
    const citedEntry = (field: string): HydratableEntry | undefined =>
      isRecObj(out[field]) ? idx.entriesById.get((out[field] as HostSignedRecord).id) : undefined
    const cited = [
      citedEntry('transferRecord'), citedEntry('postTransferReadback'), citedEntry('sourceControlDenied'),
      citedEntry('baselineDeniedControl'), citedEntry('primeAction'), citedEntry('bledAccess'),
      citedEntry('singleForeignControlDenied'), citedEntry('batchRequest'), citedEntry('postMutationReadback'),
    ]
    const actor = deriveDualActorFromTranscript(idx, cited, rawInput.actor)
    if (actor) out.actor = actor
    // Allowlist ONLY record selector IDs (with minimum length); tenant scope and role requirements are host-derived.
    for (const k of ['entityId', 'ownRecordId', 'foreignRecordId'] as const) {
      const v = pickStr(rawInput, k, 128)
      if (v && v.length >= MIN_TOKEN_LEN) out[k] = v
    }
    const tenantOf = (e: HydratableEntry | undefined): string | null =>
      (e?.step.actor.tenant ?? parseRoleLabel(e?.actorRoleLabel ?? e?.actorPersona ?? '').tenant ?? '').trim().toLowerCase() || null
    const markersOf = (e: HydratableEntry | undefined): Set<string> => new Set([
      ...extractTenantMarkers(e?.step.json, e?.step.body),
      ...extractTenantMarkers(e?.step.requestJson),
      ...extractTenantMarkers(undefined, typeof e?.step.requestJson === 'string' ? e.step.requestJson : undefined),
    ])
    if (mode === 'cross_org_transfer') {
      const rb = isRecObj(out.postTransferReadback) ? out.postTransferReadback : undefined
      const xferEntry = citedEntry('transferRecord')
      const ctrlEntry = citedEntry('sourceControlDenied')
      const sourceTenant = tenantOf(ctrlEntry)
      const ownerTenant = findStringField(parseRecJson(rb), ['ownertenantid', 'owner_tenant_id', 'ownerorgid', 'owner_org_id', 'destinationtenant', 'destination_tenant', 'desttenantid', 'dest_tenant_id', 'tenantid', 'tenant_id', 'tenant', 'orgid', 'org_id'])?.trim().toLowerCase()
      if (sourceTenant) out.sourceTenantId = sourceTenant
      if (ownerTenant) out.destTenantId = ownerTenant
      const eid = typeof out.entityId === 'string' ? out.entityId : ''
      const entityBound = Boolean(
        eid && rb && recordContainsToken(rb, eid)
        && (entryReferencesToken(xferEntry, eid) || entryReferencesToken(ctrlEntry, eid) || recordContainsToken(isRecObj(out.transferRecord) ? out.transferRecord : undefined, eid)),
      )
      if (!entityBound) delete out.entityId
      if (ownerTenant) out.observedOwnerTenantId = ownerTenant
    } else if (mode === 'dual_org_cache_bleed') {
      const bled = isRecObj(out.bledAccess) ? out.bledAccess : undefined
      const primeEntry = citedEntry('primeAction'), controlEntry = citedEntry('baselineDeniedControl')
      const primeTenant = tenantOf(primeEntry) ?? tenantOf(controlEntry)
      const markers = markersOf(citedEntry('bledAccess'))
      if (primeTenant) out.primeTenantId = primeTenant
      if (markers.size === 1) {
        const target = [...markers][0]!
        if (target !== primeTenant) out.targetTenantId = target
      }
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
      const ctrlEntry = citedEntry('singleForeignControlDenied')
      const ownTenant = tenantOf(batchEntry) ?? tenantOf(ctrlEntry)
      const foreignTenants = new Set([...markersOf(batchEntry), ...markersOf(ctrlEntry)])
      if (ownTenant) {
        out.ownTenantId = ownTenant
        foreignTenants.delete(ownTenant)
      }
      if (foreignTenants.size === 1) out.foreignTenantId = [...foreignTenants][0]
      if (Array.isArray(rawInput.requestedIds) && batchEntry) {
        const rawIds = rawInput.requestedIds
          .filter((x): x is string => typeof x === 'string' && x.trim().length >= MIN_TOKEN_LEN && x.length <= 128)
          .map(x => x.trim()).slice(0, 32)
        // Strictly derive requestedIds by exact host-recorded request reference (never substring).
        out.requestedIds = rawIds.filter(id => entryReferencesToken(batchEntry, id))
      }
      const foreignId = typeof out.foreignRecordId === 'string' ? out.foreignRecordId : ''
      if (ctrlEntry && foreignId && (ctrlEntry.step.pathAndQuery || ctrlEntry.step.requestJson !== undefined)) {
        if (!entryReferencesToken(ctrlEntry, foreignId)) delete out.foreignRecordId
      }
      if (batchRec && foreignId && recordContainsToken(batchRec, foreignId) && !isHydratedStub(batchRec)) {
        out.returnedForeignIds = [foreignId]
        out.foreignDataObserved = true
      } else {
        out.returnedForeignIds = []
        out.foreignDataObserved = false
      }
      const mutRb = isRecObj(out.postMutationReadback) ? out.postMutationReadback : undefined
      if (mutRb) {
        out.foreignMutationPersisted = Boolean(
          is2xx(mutRb.status) && !isHydratedStub(mutRb) && foreignId && recordContainsToken(mutRb, foreignId),
        )
      }
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
    // R2-C-8: derive source/target tenant and scope strictly from host transcript records (never free-form untrusted strings).
    const hostSrcTenant = (sEntry?.step.actor.tenant ?? parseRoleLabel(sEntry?.actorRoleLabel ?? '').tenant ?? [...extractTenantMarkers(sEntry?.step.json, sEntry?.step.body)][0] ?? [...extractTenantMarkers(sEntry?.step.requestJson)][0] ?? '').trim().toLowerCase()
    const rRespMarkers = rEntry ? extractTenantMarkers(rEntry.step.json, rEntry.step.body) : new Set<string>()
    const rReqMarkers = rEntry ? extractTenantMarkers(rEntry.step.requestJson) : new Set<string>()
    const rawTarget = pickStr(rawInput, 'targetTenant', 128)?.toLowerCase() ?? ''
    const allRMarkers = new Set([...rRespMarkers, ...rReqMarkers])
    const hostDstTenant = (rawTarget && allRMarkers.has(rawTarget) ? rawTarget : [...rRespMarkers][0] ?? [...rReqMarkers][0] ?? (rEntry?.step.actor.tenant ?? parseRoleLabel(rEntry?.actorRoleLabel ?? '').tenant ?? '')).trim().toLowerCase()
    const hostScopeOf = (entry: HydratableEntry | undefined, tenant: string): string => {
      if (!entry) return ''
      const hdrScope = headerLookupCI(entry.step.requestHeaders, 'x-scope')
      if (hdrScope) return hdrScope.toLowerCase()
      const jsonScope = findStringField(entry.step.json, ['scope']) ?? findStringField(entry.step.requestJson, ['scope'])
      if (jsonScope) return jsonScope.toLowerCase()
      const rt = (entry.step.route ?? entry.step.pathAndQuery ?? '').split('?', 1)[0]?.replace(/\/+$/, '').toLowerCase() ?? ''
      return rt && tenant ? `${tenant}:${rt}` : rt
    }
    if (hostSrcTenant) out.sourceTenant = hostSrcTenant
    if (hostDstTenant) out.targetTenant = hostDstTenant
    const hostSrcScope = hostScopeOf(sEntry, hostSrcTenant)
    const hostDstScope = hostScopeOf(rEntry, hostDstTenant)
    if (hostSrcScope) out.sourceScope = hostSrcScope
    if (hostDstScope) out.targetScope = hostDstScope
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
    const mode = pickEnum(rawInput, 'mode', PARSER_MODE_SET)
    if (mode) out.mode = mode
    if (mode === 'parser_differential') {
      const dk = pickEnum(rawInput, 'differentialKind', DIFF_KIND_SET)
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
    hydrateRole('preChainControlDenied', 'preChainControlExchangeId')
    const ctrlKind = pickEnum(rawInput, 'controlKind', PIVOT_CTRL_SET)
    if (ctrlKind) out.controlKind = ctrlKind
    const hydratedHops: Array<Record<string, unknown>> = []
    if (Array.isArray(rawInput.hops)) {
      for (const rawHop of rawInput.hops.slice(0, 8)) {
        if (!rawHop || typeof rawHop !== 'object' || Array.isArray(rawHop)) continue
        const hIn = rawHop as Record<string, unknown>
        const hOut: Record<string, unknown> = {}
        const surf = pickEnum(hIn, 'surface', SURFACE_SET)
        const role = pickEnum(hIn, 'role', PIVOT_ROLE_SET)
        const bk = pickEnum(hIn, 'bindingKind', EDGE_KIND_SET)
        if (surf) hOut.surface = surf
        if (role) hOut.role = role
        if (bk) hOut.bindingKind = bk
        hydrateRoleField(hOut, hIn, 'record', idx, fallbackSig, 'exchangeId')
        hydrateRoleField(hOut, hIn, 'ablationControlDenied', idx, fallbackSig, 'ablationExchangeId')
        const rec = isRecObj(hOut.record) ? hOut.record : undefined
        const entry = rec ? idx.entriesById.get(rec.id) : undefined
        if (rec) {
          const allowedEmit = new Set<string>([
            ...(entry?.emittedCapabilities ?? []),
            ...(entry?.observedResponseDigests ?? []),
            ...(rec.artifactDigest ? [rec.artifactDigest] : []),
          ])
          const rawEmit = pickStr(hIn, 'emittedArtifactDigest', 256)
          hOut.emittedArtifactDigest = rawEmit && allowedEmit.has(rawEmit)
            ? rawEmit
            : (entry?.emittedCapabilities?.[0] ?? rec.artifactDigest)
          const allowedConsume = new Set<string>([
            ...(entry?.consumedCapabilities ?? []),
            ...(entry?.cryptoAttestations?.map(a => a.derivedFromCapabilityId) ?? []),
          ])
          const rawConsume = pickStr(hIn, 'consumedArtifactDigest', 256)
          if (rawConsume && allowedConsume.has(rawConsume)) hOut.consumedArtifactDigest = rawConsume
          else if (entry?.consumedCapabilities?.[0]) hOut.consumedArtifactDigest = entry.consumedCapabilities[0]
          const allowedDerived = new Set<string>([
            ...(entry?.cryptoAttestations?.map(a => a.derivedFromCapabilityId) ?? []),
            ...(entry?.consumedCapabilities ?? []),
          ])
          const rawDerived = pickStr(hIn, 'derivedFromCapabilityId', 256)
          if (rawDerived && allowedDerived.has(rawDerived)) hOut.derivedFromCapabilityId = rawDerived
          else if (entry?.cryptoAttestations?.[0]?.derivedFromCapabilityId) hOut.derivedFromCapabilityId = entry.cryptoAttestations[0].derivedFromCapabilityId
          const rawCorr = pickStr(hIn, 'correlationToken', 256)
          if (rawCorr && entryContainsCorrelation(entry, rawCorr)) hOut.correlationToken = rawCorr
        }
        hydratedHops.push(hOut)
      }
      out.hops = hydratedHops
    }
    const firstRec = hydratedHops[0] && isRecObj(hydratedHops[0].record) ? hydratedHops[0].record : undefined
    const firstEntry = firstRec ? idx.entriesById.get(firstRec.id) : undefined
    if (firstEntry) {
      const aId = actorOfEntry(firstEntry)
      const aRole = roleOfEntry(firstEntry) ?? 'member'
      out.attackerOriginPersona = {
        actorId: aId ?? '',
        role: aRole,
        tenantId: firstEntry.step.actor.tenant ?? null,
        isPrivilegedPreSeeded: isPrivilegedActorOrRole(aId, aRole, firstEntry.actorRoleLabel),
      }
    }
    if (rawInput.terminalImpact && typeof rawInput.terminalImpact === 'object' && !Array.isArray(rawInput.terminalImpact)) {
      const tiIn = rawInput.terminalImpact as Record<string, unknown>
      const tiOut: Record<string, unknown> = {}
      const kind = pickEnum(tiIn, 'kind', PIVOT_IMPACT_SET)
      if (kind) tiOut.kind = kind
      hydrateRoleField(tiOut, tiIn, 'postImpactReadback', idx, fallbackSig)
      const lastHop = hydratedHops[hydratedHops.length - 1]
      const lastRec = lastHop && isRecObj(lastHop.record) ? lastHop.record : undefined
      const lastRole = typeof lastHop?.role === 'string' ? lastHop.role : ''
      const rb = isRecObj(tiOut.postImpactReadback) ? tiOut.postImpactReadback : undefined
      const lastOk = Boolean(lastRec && (is2xx(lastRec.status) || lastRole === 'oob_callback' || lastRole === 'worker_ssrf_callback'))
      const verified = kind === 'privileged_mutation' || kind === 'privilege_escalation'
        ? Boolean(lastOk && rb && is2xx(rb.status) && !isHydratedStub(rb))
        : Boolean(lastOk && lastRec && !isHydratedStub(lastRec))
      tiOut.verified = verified
      const hostDigest = rb?.artifactDigest ?? lastRec?.artifactDigest
      if (hostDigest) tiOut.impactDigest = hostDigest
      out.terminalImpact = tiOut
    }
    return out
  }

  if (family === 'economic_conservation') {
    hydrateRole('baselineReadback', 'baselineExchangeId')
    hydrateRole('finalReadback', 'finalExchangeId')
    const eq = pickEnum(rawInput, 'equation', ECON_EQ_SET)
    if (eq) out.equation = eq
    const tol = pickFiniteNonNeg(rawInput.tolerance)
    if (tol !== undefined && tol <= 1) out.tolerance = tol

    const hasExplicitActions = hydrateRecordArrayField(
      out, rawInput, 'actions', ['actionExchangeIds', 'actionsExchangeIds', 'actionExchangeId'], idx, fallbackSig,
    )
    if (econCtx) {
      if (!hasExplicitActions) {
        const actEntries = econCtx.termHopExchangeIds
          .map(id => idx.entriesById.get(id))
          .filter((e): e is HydratableEntry => Boolean(e && e.step.arm === 'probe' && !stepReadsState(e.step) && is2xx(e.step.status) && isPosTs(e.timestampMs)))
        if (actEntries.length > 0) out.actions = actEntries.map(e => toOracleRecord(e, fallbackSig))
      }
      const validActs = Array.isArray(out.actions)
        ? (out.actions as unknown[]).filter((a): a is HostSignedRecord => Boolean(a && typeof a === 'object' && isPosTs((a as HostSignedRecord).timestampMs)))
        : []
      const actionIdSet = new Set(validActs.map(a => a.id))
      const minActTs = validActs.length > 0 ? Math.min(...validActs.map(a => a.timestampMs)) : null
      const maxActTs = validActs.length > 0 ? Math.max(...validActs.map(a => a.timestampMs)) : null

      if (!explicit.has('baselineReadback')) {
        const base = econCtx.preChainControlExchangeIds
          .map(id => idx.entriesById.get(id))
          .find((e): e is HydratableEntry => {
            if (!e || actionIdSet.has(e.exchangeId) || !is2xx(e.step.status) || !isPosTs(e.timestampMs)) return false
            if (minActTs !== null && e.timestampMs > minActTs) return false
            return stepReadsState(e.step)
          })
        if (base) out.baselineReadback = toOracleRecord(base, fallbackSig)
      }
      if (!explicit.has('finalReadback')) {
        const baseId = out.baselineReadback && typeof out.baselineReadback === 'object' ? (out.baselineReadback as HostSignedRecord).id : null
        const fin = econCtx.postChainReadbackExchangeIds
          .map(id => idx.entriesById.get(id))
          .find((e): e is HydratableEntry => {
            if (!e || actionIdSet.has(e.exchangeId) || (baseId && e.exchangeId === baseId)) return false
            if (!is2xx(e.step.status) || !isPosTs(e.timestampMs)) return false
            if (maxActTs !== null && e.timestampMs < maxActTs) return false
            return stepReadsState(e.step) && hasEntryBody(e) && !isJobOrHandleStub(e.step.json, e.step.body, e.step.status, e.step.method, e.step.route ?? e.step.pathAndQuery)
          })
        if (fin) out.finalReadback = toOracleRecord(fin, fallbackSig)
      }
    }

    const baseRec = isRecObj(out.baselineReadback) ? out.baselineReadback : undefined
    const finRec = isRecObj(out.finalReadback) ? out.finalReadback : undefined
    const citedSet = econCtx?.citedExchangeIds?.length ? new Set(econCtx.citedExchangeIds) : null
    // Deduplicate action exchange IDs and bind strictly to probe-arm mutating actions (R2-C-8).
    const rawActRecs = Array.isArray(out.actions) ? (out.actions as unknown[]).filter(isRecObj) : []
    const seenActIds = new Set<string>()
    const actRecs: HostSignedRecord[] = []
    for (const a of rawActRecs) {
      if (seenActIds.has(a.id)) continue
      seenActIds.add(a.id)
      const entry = idx.entriesById.get(a.id)
      if (entry && entry.step.arm !== 'probe') continue
      if (citedSet && !citedSet.has(a.id)) continue
      actRecs.push(a)
    }
    if (Array.isArray(out.actions)) out.actions = actRecs
    const baseJson = parseRecJson(baseRec), finJson = parseRecJson(finRec)

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
        const depKeys = ['credited', 'deposited', 'depositamount', 'deposit_amount', 'deposit', 'credit', 'amount', 'amountcents', 'amount_cents', 'delta']
        // Sum ALL distinct non-transfer 2xx mutating/deposit exchanges across the entire host log
        // window [baseline, final] (union with cited actions) so workers can neither omit real
        // deposits nor undercount multiple deposits via Math.max.
        const baseEntry = baseRec ? idx.entriesById.get(baseRec.id) : undefined
        const finEntry = finRec ? idx.entriesById.get(finRec.id) : undefined
        const baseSeq = typeof baseEntry?.seq === 'number' ? baseEntry.seq : null
        const finSeq = typeof finEntry?.seq === 'number' ? finEntry.seq : null
        const baseTs = baseRec?.timestampMs ?? 0
        const finTs = finRec?.timestampMs ?? Number.POSITIVE_INFINITY
        const depositEntries = new Map<string, HydratableEntry>()
        for (const a of actRecs) {
          const e = idx.entriesById.get(a.id)
          if (e) depositEntries.set(e.exchangeId, e)
        }
        for (const e of idx.entriesById.values()) {
          if (e.exchangeId === baseRec?.id || e.exchangeId === finRec?.id) continue
          if (!is2xx(e.step.status) || stepReadsState(e.step)) continue
          const inSeq = baseSeq !== null && finSeq !== null && typeof e.seq === 'number'
            ? (e.seq >= baseSeq && e.seq <= finSeq)
            : true
          const eTs = isPosTs(e.timestampMs) ? e.timestampMs : null
          const inTs = eTs !== null ? (eTs >= baseTs && eTs <= finTs) : true
          if (inSeq && inTs) depositEntries.set(e.exchangeId, e)
        }
        let summedDeposits = 0
        for (const e of depositEntries.values()) {
          if (!is2xx(e.step.status) || stepReadsState(e.step)) continue
          // Internal transfers between two ledger accounts do not inject external value.
          if (isInternalTransferRequest(e.step.requestJson)) continue
          const amt = findNumericField(e.step.json, depKeys) ?? findNumericField(e.step.requestJson, depKeys)
          if (amt !== undefined && amt > 0) summedDeposits += amt
        }
        out.authorizedDeposits = summedDeposits
        out.authorizedWithdrawals = 0
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

/** Extract normalized canonical suffix tokens from a logical/namespaced state key (e.g. `"perm:dual_member"` -> `["dual_member"]`). */
export function extractCanonicalEntityTokens(entityId: string): string[] {
  const trimmed = entityId.trim()
  if (!trimmed) return []
  const tokens: string[] = [], seen = new Set<string>()
  const push = (t: string) => { const n = t.trim().toLowerCase(); if (n.length >= 2 && !seen.has(n)) { seen.add(n); tokens.push(n) } }
  if (trimmed.includes(':')) {
    const parts = trimmed.split(':')
    for (let i = 1; i < parts.length; i++) push(parts[i]!)
  } else {
    push(trimmed)
  }
  return tokens
}

/**
 * Select a monotonic `(from, to)` exchange pair for `state_transition_binding`.
 * Uses literal `entryMatchesEntity` matches as the primary path; when either side has no literal match
 * (e.g. logical/namespaced state keys like `"perm:dual_member"` or `"org_b"`), falls back to canonical
 * token matches and succeeding probe exchanges with actor/session continuity or a DAG-derived capability.
 */
export function selectStateTransitionPair<T extends HydratableEntry>(
  entityId: string,
  fromEntries: readonly T[],
  toEntries: readonly T[],
  dagDerivedCaps: ReadonlySet<string>,
  helpers: {
    actorOf: (e: T) => string | null
    probeTenantOf: (e: T) => string | null
    entryMatchesEntity: (e: T, eid: string) => boolean
    anonActorRe: RegExp
    resolveCapActor?: (cap: string) => string | null
  },
):
  | { ok: true; from: T; to: T; logicalFallback: boolean }
  | { ok: false; reason: 'missing_from' | 'missing_to' | 'non_monotonic' | 'actor_discontinuity'; missingSide?: 'from' | 'to' } {
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
  const tokMatch = (e: T): boolean => {
    const a = helpers.actorOf(e)?.trim().toLowerCase() ?? ''
    const t1 = e.step.actor.tenant?.trim().toLowerCase() ?? ''
    const t2 = helpers.probeTenantOf(e) ?? ''
    return tokens.some(tok => a === tok || t1 === tok || t2 === tok || helpers.entryMatchesEntity(e, tok))
  }
  const rank = (lit: readonly T[], probes: readonly T[]): readonly T[] =>
    lit.length > 0 ? lit : [...probes.filter(tokMatch), ...probes.filter(e => !tokMatch(e))]
  const fCands = rank(fromLit, fromProbes), tCands = rank(toLit, toProbes)
  const monoPairs = fCands.flatMap(f => tCands.filter(t => f.timestampMs! <= t.timestampMs!).map(t => ({ from: f, to: t })))
  if (monoPairs.length === 0) return { ok: false, reason: 'non_monotonic' }
  const normAct = (e: T): string | null => {
    const a = helpers.actorOf(e)?.trim().toLowerCase() ?? ''
    return (!a || helpers.anonActorRe.test(a) || a.startsWith('cap:')) ? null : a
  }
  const capsOf = (e: T): string[] => {
    const a = helpers.actorOf(e)?.trim() ?? ''
    return [
      ...(a.startsWith('cap:') ? [a] : []),
      ...(e.consumedCapabilities ?? []),
      ...(e.cryptoAttestations ?? []).flatMap(x => [
        x.derivedFromCapabilityId,
        ...(x.derivedCapabilityId ? [x.derivedCapabilityId] : []),
      ]),
    ]
  }
  const lineageActors = (e: T): Set<string> => {
    const out = new Set<string>()
    const direct = normAct(e)
    if (direct) out.add(direct)
    if (helpers.resolveCapActor) {
      for (const c of capsOf(e)) {
        const oa = helpers.resolveCapActor(c)?.trim().toLowerCase()
        if (oa && !helpers.anonActorRe.test(oa) && !oa.startsWith('cap:')) out.add(oa)
      }
    }
    return out
  }
  const matched = monoPairs.find(({ from: f, to: t }) => {
    const fa = normAct(f), ta = normAct(t)
    const fActors = lineageActors(f), tActors = lineageActors(t)
    const fCaps = capsOf(f), tCaps = capsOf(t), fCapSet = new Set(fCaps)
    const sameActor = (fActors.size > 0 && tActors.size > 0)
      ? [...fActors].some(a => tActors.has(a))
      : (fa === null && ta === null && fActors.size === 0 && tActors.size === 0 && f.step.actor.auth === t.step.actor.auth)
    const usesCap = tCaps.some(c => dagDerivedCaps.has(c))
    const sharedCap = tCaps.some(c => fCapSet.has(c)) && (fActors.size === 0 || tActors.size === 0 || sameActor)
    return sameActor || usesCap || sharedCap
  })
  return matched
    ? { ok: true, from: matched.from, to: matched.to, logicalFallback: true }
    : { ok: false, reason: 'actor_discontinuity', missingSide: fromLit.length === 0 ? 'from' : 'to' }
}

// --- Closed Terminal Class Contract & Exact Host-Provenance Matchers (R2-C-3, R2-H-6, R2-H-7/H-12) ---

export type TerminalContractKind =
  | 'v8_dual_tenant' | 'v8_temporal' | 'v8_economic' | 'v8_crypto' | 'v8_parser_cache' | 'v8_pivot'
  | 'access_control' | 'auth_or_logic' | 'oob' | 'browser' | 'injection_or_redirect'

const clsMap = (kind: TerminalContractKind, names: string): [string, TerminalContractKind][] =>
  names.split(' ').map(n => [n, kind])

export const TERMINAL_CLASS_CONTRACT: Readonly<Record<string, TerminalContractKind>> = Object.fromEntries([
  ['dual_tenant_abac', 'v8_dual_tenant'], ['temporal_revocation', 'v8_temporal'], ['economic_conservation', 'v8_economic'],
  ['cryptographic_scope_replay', 'v8_crypto'], ['parser_cache_differential', 'v8_parser_cache'], ['cross_surface_pivot', 'v8_pivot'],
  ...clsMap('access_control', 'bola idor authorization broken_access_control broken-access-control access_control authz_bypass authorization_bypass authz_escalation bfla privilege_escalation cross_tenant cross_tenant_read cross_tenant_write cross_tenant_export cross_tenant_document_read cross_tenant_exfiltration cross_tenant_repo_theft cross_tenant_secret_read cross_tenant_partner_export cross_tenant_admin_takeover cross_tenant_chain cache_tenant_bleed disclosure info_disclosure information_disclosure secret_disclosed data_exposure mass_assignment csrf'),
  ...clsMap('auth_or_logic', 'auth_bypass authentication_bypass jwt_forgery broken_auth auth_protocol token_forgery business_logic invariant_violation workflow_skip maker_checker_bypass self_approved_payout unapproved_prod_release unauthorized_prod_release forged_settlement ledger_overcredit stale_privilege_use internal_token_exfiltration delegated_billing_rebate split_refund_ledger_break race race_double_spend race_condition race_burst double_spend oversell inventory_oversell conserved_balance toctou'),
  ...clsMap('oob', 'ssrf blind_ssrf xxe blind_xxe oob webhook_forgery'),
  ...clsMap('browser', 'xss xss_stored xss_reflected markup html_injection dom_xss browser_xss postmessage'),
  ...clsMap('injection_or_redirect', 'sqli sqli_error sqli_time sql_time blind_sqli sql_boolean sql_boolean_diff boolean_sqli boolean_differential sqli_status sql_status sql_status_diff status_sqli status_boolean nosqli nosql_injection ssti template_injection command_injection cmdi rce path_traversal directory_traversal injection injection-input injection_input open_redirect redirect url_redirect unvalidated_redirect'),
])

export const resolveTerminalContract = (cls: string): TerminalContractKind | null => {
  const n = cls.trim().toLowerCase()
  return TERMINAL_CLASS_CONTRACT[n] ?? (/^(?:browser_|dom_|postmessage)/i.test(n) ? 'browser' : null)
}

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
  const eid = entityId.trim(), lid = eid.toLowerCase(), pq = entry.step.pathAndQuery ?? entry.step.route ?? ''
  if (!eid) return false
  if (entry.entityId?.trim().toLowerCase() === lid || entry.correlationIds?.some(c => c.trim().toLowerCase() === lid)) return true
  if (pq) {
    const [p = '', q = ''] = pq.split('?', 2)
    for (const seg of p.split('/')) {
      if (seg.toLowerCase() === lid) return true
      try { if (decodeURIComponent(seg).toLowerCase() === lid) return true } catch { /* ignore */ }
    }
    if (q) for (const [k, v] of new URLSearchParams(q).entries()) if (!SECRET_LEAF_KEY_RE.test(k) && v.trim().toLowerCase() === lid) return true
  }
  const leaves = new Set<string>(); collectSafeLeaves(entry.step.requestJson, leaves); collectSafeLeaves(entry.step.json, leaves)
  for (const leaf of leaves) if (leaf.toLowerCase() === lid) return true
  return false
}

/** R2-C-3: strict exact equality against host-minted IDs / non-secret leaves with length + entropy floor; never substring over raw JSON/carrierText. */
export function entryMatchesCorrelation(entry: HydratableEntry, correlationId: string): boolean {
  const cid = correlationId.trim()
  if (cid.length < 6 || new Set(cid).size < 4 || cid.includes('[redacted')) return false
  if (entry.correlationIds?.includes(cid) || entry.entityId === cid) return true
  const pq = entry.step.pathAndQuery ?? entry.step.route ?? ''
  if (pq) {
    const [p = '', q = ''] = pq.split('?', 2)
    for (const seg of p.split('/')) if (seg === cid) return true
    if (q) for (const [k, v] of new URLSearchParams(q).entries()) if (!SECRET_LEAF_KEY_RE.test(k) && v.trim() === cid) return true
  }
  for (const hdrs of [entry.step.requestHeaders, entry.step.responseHeaders]) {
    if (!hdrs) continue
    for (const [k, v] of Object.entries(hdrs)) if (CORR_HEADER_KEYS.has(k.toLowerCase()) && v.trim() === cid) return true
  }
  const leaves = new Set<string>(); collectSafeLeaves(entry.step.requestJson, leaves); collectSafeLeaves(entry.step.json, leaves)
  return leaves.has(cid)
}

export function entryCarriesRequestToken(entry: HydratableEntry, token: string): boolean {
  const tok = token.trim(); if (tok.length < 6) return false
  if (entry.correlationIds?.includes(tok) || entry.entityId === tok) return true
  const pq = entry.step.pathAndQuery ?? entry.step.route ?? ''
  if (pq.includes(tok)) return true
  for (const v of Object.values(entry.step.requestHeaders ?? {})) if (v.includes(tok)) return true
  const reqLeaves = new Set<string>(); collectJsonStringLeaves(entry.step.requestJson, reqLeaves)
  return [...reqLeaves].some(l => l === tok || l.includes(tok))
}

export const cleanExactPath = (p: string | null | undefined): string =>
  (p ?? '').split(/[?#]/, 1)[0]!.replace(/\/+$/, '').toLowerCase()

export function canonicalNonAuthQuery(p: string | null | undefined): string {
  const qIdx = (p ?? '').indexOf('?')
  if (qIdx < 0) return ''
  const pairs: [string, string][] = []
  for (const [k, v] of new URLSearchParams((p ?? '').slice(qIdx + 1).split('#', 1)[0]!).entries()) {
    const lk = k.trim().toLowerCase()
    if (!AUTH_QUERY_KEYS.has(lk)) pairs.push([lk, v.trim()])
  }
  return pairs
    .sort(([a, av], [b, bv]) => (a < b ? -1 : a > b ? 1 : av < bv ? -1 : av > bv ? 1 : 0))
    .map(([k, v]) => `${k}=${v}`)
    .join('&')
}

export function sanitizeEmbeddedProofReceipt(pr: ProofReceipt): ProofReceipt {
  const { requiredRole: _r, resourceTenant: _t, oracleEvents: _e, conservedBalance, ...rest } = pr
  const cb = conservedBalance
    ? {
        ...(conservedBalance.balanceField ? { balanceField: conservedBalance.balanceField } : {}),
        ...(conservedBalance.capField ? { capField: conservedBalance.capField } : {}),
      }
    : undefined
  return { ...rest, ...(cb && Object.keys(cb).length > 0 ? { conservedBalance: cb } : {}) }
}
