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
import { normalizeRole, parseRoleLabel, parseRoleMemberships, stepReadsState } from './oracle-invariants.ts'
import { extractTenantMarkers, isJobOrHandleStub, type HostSignedRecord, type V8OracleFamily } from './v8-oracle-families.ts'

export interface HydratableEntry {
  exchangeId: string
  timestampMs?: number
  actorPersona?: string | null
  actorRoleLabel?: string | null
  emittedCapabilities?: readonly string[]
  observedResponseDigests?: readonly string[]
  consumedCapabilities?: readonly string[]
  cryptoAttestations?: readonly { derivedFromCapabilityId: string; derivedCapabilityId?: string; artifactDigest?: string }[]
  entityId?: string
  correlationIds?: readonly string[]
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
}

const sha256Hex = (value: string): string => createHash('sha256').update(value, 'utf8').digest('hex')
const isFiniteTs = (ts: unknown): ts is number => typeof ts === 'number' && Number.isFinite(ts) && ts >= 0
const isPosTs = (ts: unknown): ts is number => typeof ts === 'number' && Number.isFinite(ts) && ts > 0
const is2xx = (st: number | null | undefined): boolean => typeof st === 'number' && st >= 200 && st < 300
const actorOfEntry = (e: HydratableEntry): string | null =>
  e.actorPersona !== undefined ? e.actorPersona : (e.step.actor.handle ?? null)
const roleOfEntry = (e: HydratableEntry): string | null =>
  e.actorRoleLabel ? parseRoleLabel(e.actorRoleLabel).role : (e.step.actor.role ?? null)

const PRIV_HANDLE_RE = /^(?:admin|owner|superadmin|root|system)(?:[_-]|$)/i
const SAFE_FIELD_PATH_RE = /^\$?(?:\.?[A-Za-z0-9_-]+|\[\d+\])+$/
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

/**
 * True when an actor persona handle or role represents a privileged pre-seeded identity.
 * Strictly forbids `PRIV_HANDLE_RE` handles (`owner_*`, `admin_*`, ...), `owner` in any tenant,
 * and single-tenant `admin`. Allows multi-tenant personas whose `actorRoleLabel` memberships hold
 * a low-privilege role (`member`/`viewer`/`user`/etc.) in at least one distinct non-admin tenant.
 */
export function isPrivilegedActorOrRole(
  actor: string | null,
  role: string | null,
  actorRoleLabel?: string | null,
): boolean {
  if (actor && PRIV_HANDLE_RE.test(actor.trim())) return true
  const nr = normalizeRole(role ?? undefined)
  if (nr === 'owner') return true
  const memberships = actorRoleLabel ? parseRoleMemberships(actorRoleLabel) : []
  if (memberships.some(m => m.role === 'owner')) return true
  const hasAdmin = nr === 'admin' || memberships.some(m => m.role === 'admin')
  if (!hasAdmin) return false
  const adminTenants = new Set(memberships.filter(m => m.role === 'admin' && m.tenant).map(m => m.tenant!))
  const lowPrivTenants = new Set(
    memberships
      .filter(m => (m.role === 'member' || m.role === 'viewer') && m.tenant && !adminTenants.has(m.tenant))
      .map(m => m.tenant!),
  )
  const distinctTenants = new Set(memberships.filter(m => m.tenant).map(m => m.tenant!))
  return !(distinctTenants.size >= 2 && lowPrivTenants.size >= 1)
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

export interface CapOriginIndex {
  loginTenantOf(cap: string): string | null
  loginActorOf(cap: string): { actor: string | null; role: string | null; roleLabel: string | null } | null
  actorOf(cap: string): string | null
}

/**
 * Index host-signed transcript entries by emitted capability handle (`cap:*`) so verifiers can:
 *  - propagate originating `POST /login` tenant/actor provenance onto `cap:*` sessions;
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

  return { loginTenantOf, loginActorOf, actorOf: (cap: string) => actorOf(cap) }
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

function hydrateSingleField(
  out: Record<string, unknown>,
  raw: Record<string, unknown>,
  field: string,
  aliases: readonly string[],
  idx: HydratableTranscriptIndex,
  fallbackSig: string,
): boolean {
  if (raw[field] !== undefined) {
    out[field] = hydrateRecordValue(raw[field], idx, fallbackSig)
    return true
  }
  for (const alias of aliases) {
    if (raw[alias] !== undefined) {
      out[field] = hydrateRecordValue(raw[alias], idx, fallbackSig)
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

const FAMILY_RECORD_FIELDS: Record<V8OracleFamily, readonly [string, readonly string[]][]> = {
  dual_tenant_abac: [
    ['transferRecord', ['transferRecordExchangeId', 'transferExchangeId']],
    ['postTransferReadback', ['postTransferReadbackExchangeId']],
    ['sourceControlDenied', ['sourceControlDeniedExchangeId', 'sourceControlExchangeId']],
    ['baselineDeniedControl', ['baselineDeniedControlExchangeId', 'baselineControlExchangeId']],
    ['primeAction', ['primeActionExchangeId']],
    ['bledAccess', ['bledAccessExchangeId']],
    ['singleForeignControlDenied', ['singleForeignControlDeniedExchangeId', 'singleForeignControlExchangeId']],
    ['batchRequest', ['batchRequestExchangeId']],
    ['postMutationReadback', ['postMutationReadbackExchangeId']],
  ],
  temporal_revocation: [
    ['preRevocationBaseline', ['preRevocationBaselineExchangeId']],
    ['revocationEvent', ['revocationEventExchangeId']],
    ['primaryDeniedCheck', ['primaryDeniedCheckExchangeId']],
    ['secondarySuccess', ['secondarySuccessExchangeId']],
  ],
  economic_conservation: [
    ['baselineReadback', ['baselineReadbackExchangeId', 'baselineExchangeId']],
    ['finalReadback', ['finalReadbackExchangeId', 'finalExchangeId']],
  ],
  cryptographic_scope_replay: [
    ['tamperedSignatureControl', ['tamperedSignatureControlExchangeId', 'tamperedControlExchangeId']],
    ['sourceValidIssuance', ['sourceValidIssuanceExchangeId', 'sourceIssuanceExchangeId']],
    ['replayedAcceptance', ['replayedAcceptanceExchangeId', 'replayedExchangeId']],
  ],
  parser_cache_differential: [
    ['cleanControl', ['cleanControlExchangeId']],
    ['differentialProbe', ['differentialProbeExchangeId']],
    ['postMutationReadback', ['postMutationReadbackExchangeId']],
    ['victimOrPrimeRequest', ['victimOrPrimeRequestExchangeId', 'victimPrimeExchangeId']],
    ['attackerProbe', ['attackerProbeExchangeId']],
  ],
  cross_surface_pivot: [
    ['preChainControlDenied', ['preChainControlDeniedExchangeId', 'preChainControlExchangeId']],
  ],
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

function resolveFieldPath(root: unknown, rawPath: unknown): unknown {
  if (typeof rawPath !== 'string' || root == null) return undefined
  const trimmed = rawPath.trim()
  if (!trimmed || trimmed.length > 128 || !SAFE_FIELD_PATH_RE.test(trimmed)) return undefined
  const cleaned = trimmed.replace(/^\$\.?/, '')
  const segments: string[] = []
  for (const m of cleaned.matchAll(/([A-Za-z0-9_-]+)|\[(\d+)\]/g)) {
    const seg = m[1] ?? m[2]
    if (seg !== undefined) segments.push(seg)
  }
  let cur: unknown = root
  for (const seg of segments) {
    if (cur == null || typeof cur !== 'object' || FORBIDDEN_KEYS.has(seg)) return undefined
    cur = Array.isArray(cur) ? cur[Number(seg)] : (cur as Record<string, unknown>)[seg]
  }
  return cur
}

function findNumericField(root: unknown, keys: readonly string[], fieldPath?: unknown): number | undefined {
  if (fieldPath !== undefined) {
    const v = resolveFieldPath(root, fieldPath)
    return typeof v === 'number' && Number.isFinite(v) ? v : undefined
  }
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

function findStringField(root: unknown, keys: readonly string[], fieldPath?: unknown): string | undefined {
  if (fieldPath !== undefined) {
    const v = resolveFieldPath(root, fieldPath)
    return typeof v === 'string' && v.trim().length > 0 ? v.trim() : undefined
  }
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

function extractBalanceMap(rec: HostSignedRecord | undefined, fieldPath?: unknown): Record<string, number> | undefined {
  const json = parseRecJson(rec)
  if (json == null || typeof json !== 'object') return undefined
  if (fieldPath !== undefined) {
    const v = resolveFieldPath(json, fieldPath)
    if (typeof v === 'number' && Number.isFinite(v)) return { default: v }
    if (v && typeof v === 'object' && !Array.isArray(v)) {
      const map: Record<string, number> = {}
      for (const [k, n] of Object.entries(v as Record<string, unknown>)) {
        if (!FORBIDDEN_KEYS.has(k) && typeof n === 'number' && Number.isFinite(n)) map[k] = n
      }
      return Object.keys(map).length > 0 ? map : undefined
    }
    return undefined
  }
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

function recordContainsToken(rec: HostSignedRecord | undefined, token: string): boolean {
  const needle = token.trim()
  if (!rec || !needle) return false
  const leaves = new Set<string>()
  collectJsonStringLeaves(parseRecJson(rec), leaves)
  if (leaves.has(needle)) return true
  for (const leaf of leaves) if (leaf.includes(needle)) return true
  return typeof rec.body === 'string' && rec.body.includes(needle)
}

function entryContainsCorrelation(entry: HydratableEntry | undefined, token: string): boolean {
  const needle = token.trim()
  if (!entry || !needle) return false
  if (entry.correlationIds?.includes(needle) || entry.entityId === needle) return true
  if ((entry.step.pathAndQuery ?? entry.step.route ?? '').includes(needle)) return true
  if (typeof entry.step.body === 'string' && entry.step.body.includes(needle)) return true
  const leaves = new Set<string>()
  collectJsonStringLeaves(entry.step.requestJson, leaves)
  collectJsonStringLeaves(entry.step.json, leaves)
  for (const leaf of leaves) if (leaf === needle || leaf.includes(needle)) return true
  return false
}

function extractRequestSigDigest(rec: HostSignedRecord | undefined): string | undefined {
  if (!rec?.requestHeaders) return undefined
  for (const [k, v] of Object.entries(rec.requestHeaders)) {
    if (SIG_HEADER_NAMES.has(k.toLowerCase()) && typeof v === 'string') {
      const trimmed = v.trim()
      if (trimmed && !trimmed.includes('[redacted')) return sha256Hex(trimmed)
    }
  }
  return undefined
}

function sanitizeDualActor(rawActor: unknown): { actorId: string; rolesByTenant: Record<string, string> } | undefined {
  if (!rawActor || typeof rawActor !== 'object' || Array.isArray(rawActor)) return undefined
  const obj = rawActor as Record<string, unknown>
  const actorId = pickStr(obj, 'actorId', 128)
  if (!actorId) return undefined
  const rolesByTenant: Record<string, string> = {}
  if (obj.rolesByTenant && typeof obj.rolesByTenant === 'object' && !Array.isArray(obj.rolesByTenant)) {
    for (const [k, v] of Object.entries(obj.rolesByTenant as Record<string, unknown>).slice(0, 16)) {
      if (!FORBIDDEN_KEYS.has(k) && typeof v === 'string' && v.trim().length > 0 && v.length <= 64) {
        rolesByTenant[k.trim()] = v.trim()
      }
    }
  }
  return { actorId, rolesByTenant }
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
  for (const [field, aliases] of FAMILY_RECORD_FIELDS[family]) {
    if (hydrateSingleField(out, rawInput, field, aliases, idx, fallbackSig)) explicit.add(field)
  }

  if (family === 'dual_tenant_abac') {
    const mode = pickEnum(rawInput, 'mode', DUAL_MODE_SET)
    if (mode) out.mode = mode
    const actor = sanitizeDualActor(rawInput.actor)
    if (actor) out.actor = actor
    for (const k of ['sourceTenantId', 'destTenantId', 'entityId', 'requiredSourceRole', 'requiredDestRole', 'primeTenantId', 'targetTenantId', 'requiredRole', 'ownTenantId', 'foreignTenantId', 'ownRecordId', 'foreignRecordId'] as const) {
      const v = pickStr(rawInput, k, 128)
      if (v) out[k] = v
    }
    if (mode === 'cross_org_transfer') {
      const rb = isRecObj(out.postTransferReadback) ? out.postTransferReadback : undefined
      const ownerTenant = findStringField(
        parseRecJson(rb),
        ['ownertenantid', 'owner_tenant_id', 'ownerorgid', 'owner_org_id', 'destinationtenant', 'destination_tenant', 'desttenantid', 'dest_tenant_id', 'tenantid', 'tenant_id', 'tenant', 'orgid', 'org_id'],
        rawInput.ownerTenantFieldPath,
      )
      if (ownerTenant) out.observedOwnerTenantId = ownerTenant
    } else if (mode === 'dual_org_cache_bleed') {
      const bled = isRecObj(out.bledAccess) ? out.bledAccess : undefined
      if (bled) {
        const markers = extractTenantMarkers(bled.json, bled.body)
        const target = typeof out.targetTenantId === 'string' ? out.targetTenantId.trim().toLowerCase() : ''
        if (target && markers.has(target)) out.observedTenantId = out.targetTenantId
        else if (markers.size > 0) out.observedTenantId = [...markers][0]
        const rawTargetRec = pickStr(rawInput, 'targetRecordId', 128)
        if (rawTargetRec && recordContainsToken(bled, rawTargetRec)) out.targetRecordId = rawTargetRec
      }
    } else if (mode === 'batch_partial_authz') {
      const batchRec = isRecObj(out.batchRequest) ? out.batchRequest : undefined
      const batchEntry = batchRec ? idx.entriesById.get(batchRec.id) : undefined
      if (Array.isArray(rawInput.requestedIds)) {
        const rawIds = rawInput.requestedIds.filter((x): x is string => typeof x === 'string' && x.trim().length > 0 && x.length <= 128).map(x => x.trim()).slice(0, 32)
        if (batchEntry && (batchEntry.step.requestJson !== undefined || (batchEntry.step.pathAndQuery ?? '').includes('?'))) {
          const reqLeaves = new Set<string>()
          collectJsonStringLeaves(batchEntry.step.requestJson, reqLeaves)
          const pq = batchEntry.step.pathAndQuery ?? ''
          out.requestedIds = rawIds.filter(id => reqLeaves.has(id) || pq.includes(id))
        } else {
          out.requestedIds = rawIds
        }
      }
      const foreignId = typeof out.foreignRecordId === 'string' ? out.foreignRecordId : ''
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
    const credKind = pickEnum(rawInput, 'credentialKind', CRED_KIND_SET)
    if (credKind) out.credentialKind = credKind
    const pSurf = pickEnum(rawInput, 'primarySurface', SURFACE_SET)
    const sSurf = pickEnum(rawInput, 'secondarySurface', SURFACE_SET)
    if (pSurf) out.primarySurface = pSurf
    if (sSurf) out.secondarySurface = sSurf
    const pRec = isRecObj(out.primaryDeniedCheck) ? out.primaryDeniedCheck : undefined
    const sRec = isRecObj(out.secondarySuccess) ? out.secondarySuccess : undefined
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
    for (const k of ['sourceTenant', 'sourceScope', 'targetTenant', 'targetScope'] as const) {
      const v = pickStr(rawInput, k, 128)
      if (v) out[k] = v
    }
    const tRec = isRecObj(out.tamperedSignatureControl) ? out.tamperedSignatureControl : undefined
    const sRec = isRecObj(out.sourceValidIssuance) ? out.sourceValidIssuance : undefined
    const rRec = isRecObj(out.replayedAcceptance) ? out.replayedAcceptance : undefined
    const tEntry = tRec ? idx.entriesById.get(tRec.id) : undefined
    const sEntry = sRec ? idx.entriesById.get(sRec.id) : undefined
    const rEntry = rRec ? idx.entriesById.get(rRec.id) : undefined
    const emittedSet = new Set(sEntry?.emittedCapabilities ?? [])
    const linkedAtt = rEntry?.cryptoAttestations?.find(a => emittedSet.has(a.derivedFromCapabilityId))
    const replayedDigest = linkedAtt?.artifactDigest
      ?? rEntry?.cryptoAttestations?.[0]?.artifactDigest
      ?? rEntry?.observedResponseDigests?.[0]
      ?? extractRequestSigDigest(rRec)
      ?? rRec?.artifactDigest
      ?? undefined
    const sourceDigest = linkedAtt?.artifactDigest
      ?? sEntry?.observedResponseDigests?.[0]
      ?? sRec?.artifactDigest
      ?? undefined
    const tamperedDigest = tEntry?.observedResponseDigests?.[0]
      ?? extractRequestSigDigest(tRec)
      ?? tRec?.artifactDigest
      ?? undefined
    if (tamperedDigest) out.tamperedSignatureDigest = tamperedDigest
    if (sourceDigest) out.signatureDigest = sourceDigest
    if (replayedDigest) out.replayedSignatureDigest = replayedDigest
    return out
  }

  if (family === 'parser_cache_differential') {
    const mode = pickEnum(rawInput, 'mode', PARSER_MODE_SET)
    if (mode) out.mode = mode
    if (mode === 'parser_differential') {
      const dk = pickEnum(rawInput, 'differentialKind', DIFF_KIND_SET)
      const df = pickStr(rawInput, 'differentialFeature', 128)
      const ik = pickEnum(rawInput, 'impactKind', IMPACT_KIND_SET)
      if (dk) out.differentialKind = dk
      if (df) out.differentialFeature = df
      if (ik) out.impactKind = ik
      const cv = pickStr(rawInput, 'canonicalValue', 512)
      const vv = pickStr(rawInput, 'variantValue', 512)
      if (cv !== undefined) out.canonicalValue = cv
      if (vv !== undefined) out.variantValue = vv
      const ctrl = isRecObj(out.cleanControl) ? out.cleanControl : undefined
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
        hydrateSingleField(hOut, hIn, 'record', ['recordExchangeId', 'exchangeId'], idx, fallbackSig)
        hydrateSingleField(hOut, hIn, 'ablationControlDenied', ['ablationControlDeniedExchangeId', 'ablationExchangeId'], idx, fallbackSig)
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
      hydrateSingleField(tiOut, tiIn, 'postImpactReadback', ['postImpactReadbackExchangeId'], idx, fallbackSig)
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
          .filter((e): e is HydratableEntry => Boolean(e && e.step.arm === 'probe' && is2xx(e.step.status) && isPosTs(e.timestampMs)))
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
            return stepReadsState(e.step) || e.step.arm === 'control' || e.step.evidenceRole === 'pre_chain_control' || e.step.evidenceRole === 'baseline_readback'
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
            const isRead = stepReadsState(e.step) || e.step.arm === 'control' || e.step.evidenceRole === 'post_chain_readback'
            return isRead && hasEntryBody(e) && !isJobOrHandleStub(e.step.json, e.step.body, e.step.status, e.step.method, e.step.route ?? e.step.pathAndQuery)
          })
        if (fin) out.finalReadback = toOracleRecord(fin, fallbackSig)
      }
    }

    const baseRec = isRecObj(out.baselineReadback) ? out.baselineReadback : undefined
    const finRec = isRecObj(out.finalReadback) ? out.finalReadback : undefined
    const actRecs = Array.isArray(out.actions) ? (out.actions as unknown[]).filter(isRecObj) : []
    const baseJson = parseRecJson(baseRec), finJson = parseRecJson(finRec)

    if (eq === 'over_refund') {
      const paidKeys = ['paidamount', 'paid_amount', 'paid', 'paidcents', 'paid_cents', 'orderamount', 'order_amount', 'amountpaid', 'amount_paid', 'totalpaid', 'total_paid', 'amount', 'total']
      const refTotKeys = ['refundedtotal', 'refunded_total', 'baselinerefunded', 'baseline_refunded', 'refundedamount', 'refunded_amount', 'refunded', 'totalrefunded', 'total_refunded']
      const actRefKeys = ['refunded', 'refundamount', 'refund_amount', 'refundedamount', 'refunded_amount', 'refundedcents', 'credited', 'amount']
      const hostPaid = findNumericField(baseJson, paidKeys, rawInput.paidAmountFieldPath)
        ?? findNumericField(finJson, paidKeys, rawInput.paidAmountFieldPath)
      const hostBaseRef = findNumericField(baseJson, refTotKeys) ?? (hostPaid !== undefined ? 0 : undefined)
      const hostFinRef = findNumericField(finJson, refTotKeys)
      const hostActRefs = actRecs
        .filter(a => is2xx(a.status))
        .map(a => findNumericField(parseRecJson(a), actRefKeys, rawInput.refundFieldPath))
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
      const hostBefore = extractBalanceMap(baseRec, rawInput.balanceFieldPath)
      const hostAfter = extractBalanceMap(finRec, rawInput.balanceFieldPath)
      if (hostBefore && hostAfter) {
        out.balancesBefore = hostBefore
        out.balancesAfter = hostAfter
        const depKeys = ['credited', 'deposited', 'depositamount', 'deposit_amount', 'deposit', 'credit', 'amount', 'amountcents', 'amount_cents', 'delta']
        const actDeps = actRecs
          .filter(a => is2xx(a.status))
          .map(a => {
            const e = idx.entriesById.get(a.id)
            return findNumericField(parseRecJson(a), depKeys) ?? findNumericField(e?.step.requestJson, depKeys)
          })
          .filter((n): n is number => n !== undefined && n >= 0)
        const minAuthorized = actDeps.length > 0 ? Math.max(...actDeps) : 0
        const rawDep = pickFiniteNonNeg(rawInput.authorizedDeposits) ?? 0
        out.authorizedDeposits = Math.max(rawDep, minAuthorized)
        out.authorizedWithdrawals = 0
      }
    } else if (eq === 'underpaid_fulfillment') {
      const hostPaid = findNumericField(finJson, ['paidamount', 'paid_amount', 'paid', 'amountpaid', 'amount_paid', 'chargedamount', 'charged'], rawInput.paidAmountFieldPath)
        ?? findNumericField(baseJson, ['paidamount', 'paid_amount', 'paid', 'amountpaid', 'amount_paid', 'chargedamount', 'charged'], rawInput.paidAmountFieldPath)
      const hostVal = findNumericField(finJson, ['fulfilledvalue', 'fulfilled_value', 'ordertotal', 'order_total', 'totalamount', 'total_amount', 'itemvalue', 'subtotal', 'price', 'value'], rawInput.fulfilledValueFieldPath)
        ?? findNumericField(baseJson, ['fulfilledvalue', 'fulfilled_value', 'ordertotal', 'order_total', 'totalamount', 'total_amount', 'itemvalue', 'subtotal', 'price', 'value'], rawInput.fulfilledValueFieldPath)
      const hostState = findStringField(finJson, ['fulfillmentstate', 'fulfillment_state', 'orderstatus', 'order_status', 'status', 'state'], rawInput.fulfillmentStateFieldPath)
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
      const hostSub = findNumericField(finJson, ['subtotalamount', 'subtotal_amount', 'subtotal', 'cartsubtotal', 'prediscounttotal'], rawInput.subtotalFieldPath)
        ?? findNumericField(baseJson, ['subtotalamount', 'subtotal_amount', 'subtotal', 'cartsubtotal', 'prediscounttotal'], rawInput.subtotalFieldPath)
      const hostThr = findNumericField(finJson, ['requiredthreshold', 'required_threshold', 'minorderamount', 'min_order_amount', 'minimumsubtotal', 'threshold', 'minspend'], rawInput.thresholdFieldPath)
        ?? findNumericField(baseJson, ['requiredthreshold', 'required_threshold', 'minorderamount', 'min_order_amount', 'minimumsubtotal', 'threshold', 'minspend'], rawInput.thresholdFieldPath)
      const hostDisc = findNumericField(finJson, ['discountapplied', 'discount_applied', 'discountamount', 'discount_amount', 'discount'], rawInput.discountFieldPath)
      const hostTotal = findNumericField(finJson, ['finaltotalpaid', 'final_total_paid', 'totalpaid', 'total_paid', 'finaltotal', 'total'], rawInput.finalTotalFieldPath)
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
