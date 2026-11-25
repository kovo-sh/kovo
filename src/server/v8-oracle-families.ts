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
  id: string; hostSignature: string; timestampMs: number; status?: number | null; method?: string; route?: string; surface?: V8SurfaceKind
  actorId?: string | null; tenantId?: string | null; body?: string; json?: unknown
  requestHeaders?: Readonly<Record<string, string>> | null; responseHeaders?: Readonly<Record<string, string>> | null
  capabilityHandle?: string | null; artifactDigest?: string | null; derivedFromCapabilityId?: string | null
}
export interface V8OracleDecision extends ImpactAssessment { family: V8OracleFamily; subRule?: string }
interface WithVerifier { verifySignature?: SignatureVerifier }

/* ─────────────────────────── Shared pure helpers ─────────────────────────── */

const MIN_SIG_LEN = 8
const DEFAULT_TOL = 1e-6
const MAX_PIVOT_HOPS = 8
const FINALIZED_STATES = new Set(['fulfilled', 'completed', 'captured', 'released', 'settled', 'paid', 'shipped', 'delivered', 'disbursed'])
const ERROR_ONLY_KEYS = new Set(['error', 'errors', 'message', 'detail', 'code', 'status', 'statusCode', 'ok', 'success'])
const STUB_META_KEYS = new Set([
  'ok', 'success', 'error', 'errors', 'message', 'detail', 'code', 'status', 'statuscode', 'state',
  'accepted', 'queued', 'pending', 'created', 'updated', 'cached', 'hit', 'primed', 'id',
  'jobid', 'job_id', 'exportid', 'export_id', 'taskid', 'task_id', 'requestid', 'request_id',
  'handle', 'token', 'signedurl', 'signed_url', 'downloadurl', 'download_url', 'exporturl', 'export_url',
  'pollurl', 'poll_url', 'statusurl', 'status_url', 'artifacturl', 'artifact_url', 'url', 'href', 'link',
  'location', 'path', 'filekey', 'file_key', 'createdat', 'created_at', 'updatedat', 'updated_at',
  'expiresat', 'expires_at', 'ttl', 'format', 'type', 'kind', 'scope', 'tenantid', 'tenant_id',
  'orgid', 'org_id', 'workspaceid', 'workspace_id', 'ownerid', 'owner_id', 'userid', 'user_id',
  'actorid', 'actor_id', 'role', 'roles', 'permissions', 'count', 'total', 'size', 'progress', 'poll',
])
const JOB_CACHE_SIGNAL_KEYS = new Set([
  'jobid', 'job_id', 'exportid', 'export_id', 'taskid', 'task_id', 'downloadurl', 'download_url',
  'signedurl', 'signed_url', 'exporturl', 'export_url', 'pollurl', 'poll_url', 'statusurl', 'status_url',
  'artifacturl', 'artifact_url', 'url', 'href', 'queued', 'pending', 'accepted', 'cached', 'primed',
  'permissions', 'roles',
])
const PENDING_STATE_RE = /^(?:queued|pending|processing|accepted|created|scheduled|running|in_progress|started|primed|cached|ok)$/i
const WRAPPER_KEYS = new Set(['job', 'export', 'task', 'result', 'data'])

export function isJobOrHandleStub(json: unknown, body?: string, status?: number | null, method?: string): boolean {
  let val = json
  if (val === undefined && typeof body === 'string' && body.trim().startsWith('{')) {
    try { val = JSON.parse(body) } catch { val = undefined }
  }
  if (!val || typeof val !== 'object' || Array.isArray(val)) return false
  let obj = val as Record<string, unknown>
  const topKeys = Object.keys(obj)
  if (topKeys.length === 1 && WRAPPER_KEYS.has(topKeys[0]!.toLowerCase())) {
    const inner = obj[topKeys[0]!]
    if (inner && typeof inner === 'object' && !Array.isArray(inner)) obj = inner as Record<string, unknown>
  }
  const entries = Object.entries(obj).filter(([, v]) => v !== null && v !== undefined && v !== '' && !(Array.isArray(v) && v.length === 0))
  if (entries.length === 0) return true
  if (!entries.every(([k]) => STUB_META_KEYS.has(k.toLowerCase()))) return false
  const hasSignalKey = entries.some(([k]) => JOB_CACHE_SIGNAL_KEYS.has(k.toLowerCase()))
  const stateVal = typeof obj.status === 'string' ? obj.status : (typeof obj.state === 'string' ? obj.state : '')
  const isCreation = (status === 201 || status === 202) || (Boolean(method) && /^(?:POST|PUT)$/i.test(method!) && entries.some(([k]) => /^(?:id|status|state|url|location|handle)$/i.test(k)))
  return hasSignalKey || isCreation || (Boolean(stateVal) && PENDING_STATE_RE.test(stateVal.trim()))
}

const ok = (family: V8OracleFamily, subRule: string, reason: string, evidence: Record<string, unknown>): V8OracleDecision =>
  ({ family, subRule, required: true, satisfied: true, reason, evidence })
const deny = (family: V8OracleFamily, reason: string, subRule?: string, evidence?: Record<string, unknown>): V8OracleDecision =>
  ({ family, subRule, required: true, satisfied: false, reason, evidence })
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
  if (verify && !verify(record)) return `invalid_${label}_signature`
  return null
}

function checkRecords(pairs: readonly [HostSignedRecord | null | undefined, string][], verify?: SignatureVerifier): string | null {
  for (const [rec, label] of pairs) {
    const err = checkRecord(rec, label, verify)
    if (err) return err
  }
  return null
}

function hasSubstantivePayload(record: HostSignedRecord): boolean {
  if (isJobOrHandleStub(record.json, record.body, record.status, record.method)) return false
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

    const pairs: [HostSignedRecord | undefined, string][] = [[input.transferRecord, 'transfer'], [input.postTransferReadback, 'post_transfer_readback']]
    if (input.sourceControlDenied) pairs.push([input.sourceControlDenied, 'source_control'])
    const recErr = checkRecords(pairs, input.verifySignature)
    if (recErr) return deny(f, recErr, sub)
    if (input.sourceControlDenied && !isDenied(input.sourceControlDenied.status)) return deny(f, 'source_control_not_denied', sub)
    if (!isOk(input.transferRecord.status)) return deny(f, 'transfer_not_accepted', sub)
    if (!isOk(input.postTransferReadback.status)) return deny(f, 'readback_not_accepted', sub)
    if (input.postTransferReadback.timestampMs < input.transferRecord.timestampMs) return deny(f, 'non_monotonic_readback_timestamp', sub)
    if (normKey(input.observedOwnerTenantId) !== dst) return deny(f, 'transfer_not_persisted_to_dest_tenant', sub)

    return ok(f, sub, 'cross_org_transfer_without_source_tenant_authorization', {
      actorId: input.actor.actorId, sourceTenantId: src, destTenantId: dst, entityId: input.entityId,
      sourceRole: resolveTenantRole(input.actor, src), destRole: resolveTenantRole(input.actor, dst),
      transferId: input.transferRecord.id, readbackId: input.postTransferReadback.id,
    })
  }

  if (input.mode === 'dual_org_cache_bleed') {
    const sub = input.mode, prime = normKey(input.primeTenantId), target = normKey(input.targetTenantId), req = input.requiredRole ?? 'admin'
    if (!prime || !target) return deny(f, 'missing_tenant_scope', sub)
    if (prime === target) return deny(f, 'same_tenant_not_cache_bleed', sub)
    if (!hasTenantRoleAtLeast(input.actor, prime, req)) return deny(f, 'actor_lacks_prime_tenant_privilege', sub)
    if (hasTenantRoleAtLeast(input.actor, target, req)) return deny(f, 'actor_authorized_in_target_tenant', sub)

    const recErr = checkRecords([[input.baselineDeniedControl, 'baseline_control'], [input.primeAction, 'prime_action'], [input.bledAccess, 'bled_access']], input.verifySignature)
    if (recErr) return deny(f, recErr, sub)
    if (!isDenied(input.baselineDeniedControl.status)) return deny(f, 'baseline_control_not_denied', sub)
    if (!isOk(input.primeAction.status)) return deny(f, 'prime_action_failed', sub)
    if (!isOk(input.bledAccess.status)) return deny(f, 'bled_access_denied_or_failed', sub)
    if (!input.isolatedControl && input.primeAction.timestampMs < input.baselineDeniedControl.timestampMs) return deny(f, 'non_monotonic_prime_timestamp', sub)
    if (input.bledAccess.timestampMs < input.primeAction.timestampMs) return deny(f, 'non_monotonic_bled_timestamp', sub)
    if (input.observedTenantId && normKey(input.observedTenantId) !== target) return deny(f, 'observed_tenant_mismatch', sub)
    if (isJobOrHandleStub(input.bledAccess.json, input.bledAccess.body, input.bledAccess.status, input.bledAccess.method)) return deny(f, 'terminal_impact_unproven_intermediate_stub', sub)
    if (!normStr(input.targetRecordId) && !hasSubstantivePayload(input.bledAccess)) return deny(f, 'bled_access_missing_substantive_data', sub)

    return ok(f, sub, 'dual_org_permission_cache_bleed_confirmed', {
      actorId: input.actor.actorId, primeTenantId: prime, targetTenantId: target,
      baselineControlId: input.baselineDeniedControl.id, primeActionId: input.primeAction.id, bledAccessId: input.bledAccess.id,
    })
  }

  if (input.mode === 'batch_partial_authz') {
    const sub = input.mode, ownTenant = normKey(input.ownTenantId), foreignTenant = normKey(input.foreignTenantId), req = input.requiredRole ?? 'member'
    if (!ownTenant || !foreignTenant) return deny(f, 'missing_tenant_scope', sub)
    if (ownTenant === foreignTenant) return deny(f, 'same_tenant_batch_not_cross_tenant', sub)
    if (!hasTenantRoleAtLeast(input.actor, ownTenant, req)) return deny(f, 'actor_lacks_own_tenant_role', sub)
    if (hasTenantRoleAtLeast(input.actor, foreignTenant, req)) return deny(f, 'actor_authorized_in_foreign_tenant', sub)

    const ownId = normStr(input.ownRecordId), foreignId = normStr(input.foreignRecordId)
    const reqSet = new Set((input.requestedIds ?? []).map(normStr))
    if (!ownId || !foreignId || ownId === foreignId) return deny(f, 'invalid_batch_record_pair', sub)
    if (!reqSet.has(ownId) || !reqSet.has(foreignId)) return deny(f, 'batch_missing_own_and_foreign_ids', sub)

    const recErr = checkRecords([[input.singleForeignControlDenied, 'single_foreign_control'], [input.batchRequest, 'batch_request']], input.verifySignature)
    if (recErr) return deny(f, recErr, sub)
    if (!isDenied(input.singleForeignControlDenied.status)) return deny(f, 'single_foreign_control_not_denied', sub)
    if (!isOk(input.batchRequest.status)) return deny(f, 'batch_request_denied_or_failed', sub)

    const foreignRead = new Set((input.returnedForeignIds ?? []).map(normStr)).has(foreignId) &&
      (input.foreignDataObserved === true || hasSubstantivePayload(input.batchRequest))
    let foreignMut = false
    if (input.postMutationReadback) {
      const mutErr = checkRecord(input.postMutationReadback, 'post_mutation_readback', input.verifySignature)
      if (mutErr) return deny(f, mutErr, sub)
      foreignMut = isOk(input.postMutationReadback.status) &&
        input.postMutationReadback.timestampMs >= input.batchRequest.timestampMs && input.foreignMutationPersisted === true
    }
    if (!foreignRead && !foreignMut) return deny(f, 'foreign_record_not_returned_or_mutated', sub)

    return ok(f, sub, 'batch_partial_authorization_bypass_confirmed', {
      actorId: input.actor.actorId, ownTenantId: ownTenant, foreignTenantId: foreignTenant, foreignRecordId: foreignId,
      impactMode: foreignMut ? 'mutation' : 'read', controlId: input.singleForeignControlDenied.id, batchRequestId: input.batchRequest.id,
    })
  }

  return deny(f, 'unknown_dual_tenant_mode')
}

/* ───────────────────── 2. Temporal Revocation Evaluator ──────────────────── */

export interface TemporalRevocationInput extends WithVerifier {
  credentialKind: 'token' | 'session' | 'role' | 'invite' | 'pat' | 'async_job' | 'webhook_callback'
  credentialHandle?: string | null
  actorId?: string | null
  primarySurface: V8SurfaceKind
  secondarySurface: V8SurfaceKind
  preRevocationBaseline?: HostSignedRecord
  revocationEvent: HostSignedRecord
  primaryDeniedCheck: HostSignedRecord
  secondarySuccess: HostSignedRecord
  elevatedRoleGranted?: boolean
}

export function evaluateTemporalRevocation(input: TemporalRevocationInput): V8OracleDecision {
  const f: V8OracleFamily = 'temporal_revocation'
  if (!input) return deny(f, 'missing_input')
  const sub = input.credentialKind

  const pairs: [HostSignedRecord | undefined, string][] = [
    [input.revocationEvent, 'revocation_event'], [input.primaryDeniedCheck, 'primary_denied_check'], [input.secondarySuccess, 'secondary_success'],
  ]
  if (input.preRevocationBaseline) pairs.push([input.preRevocationBaseline, 'pre_revocation_baseline'])
  const recErr = checkRecords(pairs, input.verifySignature)
  if (recErr) return deny(f, recErr, sub)

  if (input.preRevocationBaseline) {
    if (!isOk(input.preRevocationBaseline.status)) return deny(f, 'baseline_not_active', sub)
    if (input.revocationEvent.timestampMs < input.preRevocationBaseline.timestampMs) return deny(f, 'non_monotonic_revocation_timestamp', sub)
  }
  if (!isOk(input.revocationEvent.status)) return deny(f, 'revocation_event_not_confirmed', sub)
  if (!isDenied(input.primaryDeniedCheck.status)) return deny(f, 'primary_surface_not_revoked', sub)
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
  if (input.primarySurface === input.secondarySurface && (!pRoute || !sRoute || pRoute === sRoute)) {
    return deny(f, 'secondary_surface_not_distinct_from_primary', sub)
  }
  if (input.elevatedRoleGranted !== true && !hasSubstantivePayload(input.secondarySuccess)) {
    return deny(f, 'secondary_success_lacks_substantive_impact', sub)
  }

  return ok(f, sub, 'revoked_credential_accepted_on_secondary_surface', {
    credentialKind: sub, primarySurface: input.primarySurface, secondarySurface: input.secondarySurface,
    revocationEventId: input.revocationEvent.id, primaryDeniedId: input.primaryDeniedCheck.id,
    secondarySuccessId: input.secondarySuccess.id, boundBy: boundByHandle ? 'capability_handle' : 'actor_id',
  })
}

/* ─────────────────── 3. Economic Conservation Evaluator ──────────────────── */

interface EconomicBase extends WithVerifier {
  baselineReadback: HostSignedRecord
  actions: readonly HostSignedRecord[]
  finalReadback: HostSignedRecord
  tolerance?: number
}

export interface OverRefundInput extends EconomicBase { equation: 'over_refund'; paidAmount: number; refundedAmounts: readonly number[]; baselineRefunded?: number }
export interface BalanceMintingInput extends EconomicBase { equation: 'balance_minting'; balancesBefore: Readonly<Record<string, number>>; balancesAfter: Readonly<Record<string, number>>; authorizedDeposits: number; authorizedWithdrawals?: number }
export interface UnderpaidFulfillmentInput extends EconomicBase { equation: 'underpaid_fulfillment'; paidAmount: number; fulfilledValue: number; fulfillmentState: string }
export interface IneligibleDiscountInput extends EconomicBase { equation: 'ineligible_discount'; subtotalAmount: number; requiredThreshold: number; discountApplied: number; finalTotalPaid?: number }
export type EconomicConservationInput = OverRefundInput | BalanceMintingInput | UnderpaidFulfillmentInput | IneligibleDiscountInput

function sumFiniteMap(map: Readonly<Record<string, number>>): number | null {
  const vals = Object.values(map)
  if (vals.length === 0) return null
  let total = 0
  for (const v of vals) {
    if (!Number.isFinite(v)) return null
    total += v
  }
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

  let maxActionTs = -Infinity, anyActionOk = false
  for (let i = 0; i < input.actions.length; i++) {
    const act = input.actions[i]
    const err = checkRecord(act, `action_${i}`, input.verifySignature)
    if (err) return deny(f, err, sub)
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
    for (const amt of input.refundedAmounts) {
      if (!allFiniteNonNeg(amt)) return deny(f, 'invalid_refund_amount', sub)
      totalRefunded += amt
    }
    if (totalRefunded <= input.paidAmount + tol || totalRefunded <= baseRef + tol) return deny(f, 'refund_ledger_conserved', sub, { paidAmount: input.paidAmount, totalRefunded })
    return ok(f, sub, 'over_refund_conservation_violated', {
      paidAmount: input.paidAmount, totalRefunded, excessRefunded: Number((totalRefunded - input.paidAmount).toFixed(6)),
      baselineId: input.baselineReadback.id, finalReadbackId: input.finalReadback.id,
    })
  }

  if (input.equation === 'balance_minting') {
    const beforeSum = sumFiniteMap(input.balancesBefore), afterSum = sumFiniteMap(input.balancesAfter)
    const deposits = input.authorizedDeposits, withdrawals = input.authorizedWithdrawals ?? 0
    if (beforeSum === null || afterSum === null) return deny(f, 'invalid_balance_snapshot', sub)
    if (!allFiniteNonNeg(deposits, withdrawals)) return deny(f, 'invalid_deposit_or_withdrawal', sub)
    const ceiling = beforeSum + deposits - withdrawals
    if (afterSum <= ceiling + tol) return deny(f, 'balance_ledger_conserved', sub, { beforeSum, afterSum, deposits, withdrawals })
    return ok(f, sub, 'balance_conservation_violated_value_minted', {
      beforeSum, afterSum, authorizedDeposits: deposits, authorizedWithdrawals: withdrawals,
      mintedDelta: Number((afterSum - ceiling).toFixed(6)), baselineId: input.baselineReadback.id, finalReadbackId: input.finalReadback.id,
    })
  }

  if (input.equation === 'underpaid_fulfillment') {
    if (!allFiniteNonNeg(input.paidAmount) || !Number.isFinite(input.fulfilledValue) || input.fulfilledValue <= 0) return deny(f, 'invalid_fulfillment_amounts', sub)
    const state = normKey(input.fulfillmentState)
    if (!FINALIZED_STATES.has(state)) return deny(f, 'order_not_finalized', sub, { fulfillmentState: state })
    if (input.fulfilledValue <= input.paidAmount + tol) return deny(f, 'fulfillment_payment_conserved', sub)
    return ok(f, sub, 'underpaid_fulfillment_conservation_violated', {
      paidAmount: input.paidAmount, fulfilledValue: input.fulfilledValue,
      shortfall: Number((input.fulfilledValue - input.paidAmount).toFixed(6)), fulfillmentState: state, finalReadbackId: input.finalReadback.id,
    })
  }

  if (input.equation === 'ineligible_discount') {
    if (!allFiniteNonNeg(input.subtotalAmount, input.discountApplied) || !Number.isFinite(input.requiredThreshold) || input.requiredThreshold <= 0) {
      return deny(f, 'invalid_discount_parameters', sub)
    }
    if (input.subtotalAmount + tol >= input.requiredThreshold) return deny(f, 'discount_threshold_satisfied_eligible', sub)
    if (input.discountApplied <= tol) return deny(f, 'ineligible_discount_not_applied', sub)
    if (input.finalTotalPaid !== undefined && (!allFiniteNonNeg(input.finalTotalPaid) || input.finalTotalPaid > input.subtotalAmount - input.discountApplied + tol || input.finalTotalPaid >= input.subtotalAmount - tol)) {
      return deny(f, 'discount_not_reflected_in_final_total', sub)
    }
    return ok(f, sub, 'ineligible_discount_applied_below_threshold', {
      subtotalAmount: input.subtotalAmount, requiredThreshold: input.requiredThreshold,
      discountApplied: input.discountApplied, finalReadbackId: input.finalReadback.id,
    })
  }

  return deny(f, 'unknown_economic_equation')
}

/* ───────────────── 4. Cryptographic Scope Replay Evaluator ───────────────── */

export interface CryptographicScopeReplayInput extends WithVerifier {
  tamperedSignatureControl: HostSignedRecord
  sourceValidIssuance: HostSignedRecord
  replayedAcceptance: HostSignedRecord
  sourceTenant: string
  sourceScope: string
  targetTenant: string
  targetScope: string
  tamperedSignatureDigest?: string
  signatureDigest?: string
  replayedSignatureDigest?: string
  persistedImpact?: boolean
}

export function evaluateCryptographicScopeReplay(input: CryptographicScopeReplayInput): V8OracleDecision {
  const f: V8OracleFamily = 'cryptographic_scope_replay'
  if (!input) return deny(f, 'missing_input')

  const recErr = checkRecords([
    [input.tamperedSignatureControl, 'tampered_signature_control'],
    [input.sourceValidIssuance, 'source_valid_issuance'],
    [input.replayedAcceptance, 'replayed_acceptance'],
  ], input.verifySignature)
  if (recErr) return deny(f, recErr)

  if (!isDenied(input.tamperedSignatureControl.status)) {
    return deny(f, 'signature_verification_not_enforced_decoy', undefined, { tamperedStatus: input.tamperedSignatureControl.status })
  }
  if (!isOk(input.sourceValidIssuance.status)) return deny(f, 'source_signature_issuance_failed')
  if (!isOk(input.replayedAcceptance.status)) return deny(f, 'replayed_signature_rejected_hardened')
  if (input.replayedAcceptance.timestampMs < input.sourceValidIssuance.timestampMs) return deny(f, 'replay_precedes_signature_issuance')

  const tRoute = normRoute(input.tamperedSignatureControl.route), rRoute = normRoute(input.replayedAcceptance.route)
  if (tRoute && rRoute && tRoute !== rRoute) return deny(f, 'tampered_control_and_replay_route_mismatch')

  const srcT = normKey(input.sourceTenant), srcS = normKey(input.sourceScope), dstT = normKey(input.targetTenant), dstS = normKey(input.targetScope)
  if (!srcT || !srcS || !dstT || !dstS) return deny(f, 'missing_tenant_or_scope_context')
  if (srcT === dstT && srcS === dstS) return deny(f, 'same_tenant_and_scope_not_replay')

  const tamperedDigest = normStr(input.tamperedSignatureDigest ?? input.tamperedSignatureControl.artifactDigest)
  const validDigest = normStr(input.signatureDigest ?? input.sourceValidIssuance.artifactDigest)
  const replayedDigest = normStr(input.replayedSignatureDigest ?? input.replayedAcceptance.artifactDigest)
  if (!tamperedDigest || !validDigest || !replayedDigest) return deny(f, 'missing_signature_digest_binding')
  if (tamperedDigest === validDigest) return deny(f, 'tampered_digest_matches_valid_signature')
  if (replayedDigest !== validDigest) return deny(f, 'replayed_signature_digest_mismatch')
  if (input.persistedImpact !== true && !hasSubstantivePayload(input.replayedAcceptance)) return deny(f, 'replay_acceptance_lacks_substantive_impact')

  return ok(f, srcT !== dstT ? 'cross_tenant_scope_replay' : 'cross_scope_replay', 'valid_signature_replayed_across_scope_boundary', {
    sourceTenant: srcT, sourceScope: srcS, targetTenant: dstT, targetScope: dstS, signatureDigest: validDigest,
    tamperedControlId: input.tamperedSignatureControl.id, sourceIssuanceId: input.sourceValidIssuance.id, replayedAcceptanceId: input.replayedAcceptance.id,
  })
}

/* ───────────────── 5. Parser / Cache Differential Evaluator ──────────────── */

export interface ParserDifferentialInput extends WithVerifier {
  mode: 'parser_differential'; differentialKind: 'duplicate_json_key' | 'path_normalization' | 'header_normalization' | 'hop_by_hop_smuggling' | 'content_type_confusion'
  differentialFeature: string; canonicalValue?: string; variantValue?: string; impactKind: 'read' | 'mutation'
  cleanControl: HostSignedRecord; differentialProbe: HostSignedRecord; isolatedControl?: boolean
  postMutationReadback?: HostSignedRecord; mutationPersisted?: boolean; unauthorizedDigest?: string
}
export interface CachePrimedDifferentialInput extends WithVerifier {
  mode: 'cache_primed'; cacheKey: string; victimArtifactDigest: string; cleanControl: HostSignedRecord
  cleanControlContainsVictimData?: boolean; victimOrPrimeRequest: HostSignedRecord; attackerProbe: HostSignedRecord
  isolatedControl?: boolean; cacheHitObserved?: boolean
}
export type ParserCacheDifferentialInput = ParserDifferentialInput | CachePrimedDifferentialInput

export function evaluateParserCacheDifferential(input: ParserCacheDifferentialInput): V8OracleDecision {
  const f: V8OracleFamily = 'parser_cache_differential'
  if (!input) return deny(f, 'missing_input')

  if (input.mode === 'parser_differential') {
    const sub = input.differentialKind
    if (!normStr(input.differentialFeature)) return deny(f, 'missing_differential_feature', sub)
    if (input.canonicalValue !== undefined && input.variantValue !== undefined && input.canonicalValue === input.variantValue) {
      return deny(f, 'no_request_differential_between_control_and_probe', sub)
    }

    const recErr = checkRecords([[input.cleanControl, 'clean_control'], [input.differentialProbe, 'differential_probe']], input.verifySignature)
    if (recErr) return deny(f, recErr, sub)
    if (!isDenied(input.cleanControl.status)) return deny(f, 'clean_control_not_denied', sub)
    if (!isOk(input.differentialProbe.status)) return deny(f, 'differential_probe_rejected', sub)
    if (!input.isolatedControl && input.differentialProbe.timestampMs < input.cleanControl.timestampMs) return deny(f, 'probe_precedes_clean_control', sub)

    if (input.impactKind === 'mutation') {
      const mutErr = checkRecord(input.postMutationReadback, 'post_mutation_readback', input.verifySignature)
      if (mutErr) return deny(f, mutErr, sub)
      if (!isOk(input.postMutationReadback!.status)) return deny(f, 'mutation_readback_failed', sub)
      if (input.postMutationReadback!.timestampMs < input.differentialProbe.timestampMs) return deny(f, 'mutation_readback_precedes_probe', sub)
      if (input.mutationPersisted !== true) return deny(f, 'mutation_not_persisted', sub)
    } else {
      if (isJobOrHandleStub(input.differentialProbe.json, input.differentialProbe.body, input.differentialProbe.status, input.differentialProbe.method)) return deny(f, 'terminal_impact_unproven_intermediate_stub', sub)
      const probeDigest = normStr(input.unauthorizedDigest ?? input.differentialProbe.artifactDigest)
      const ctrlDigest = normStr(input.cleanControl.artifactDigest)
      if (probeDigest && ctrlDigest && probeDigest === ctrlDigest) return deny(f, 'probe_artifact_already_in_control', sub)
      if (!probeDigest && !hasSubstantivePayload(input.differentialProbe)) return deny(f, 'differential_read_missing_substantive_data', sub)
    }

    return ok(f, sub, 'parser_differential_bypass_confirmed', {
      differentialKind: sub, differentialFeature: input.differentialFeature, impactKind: input.impactKind,
      cleanControlId: input.cleanControl.id, differentialProbeId: input.differentialProbe.id,
    })
  }

  if (input.mode === 'cache_primed') {
    const sub = input.mode, victimDigest = normStr(input.victimArtifactDigest)
    if (!normStr(input.cacheKey)) return deny(f, 'missing_cache_key', sub)
    if (!victimDigest) return deny(f, 'missing_victim_artifact_digest', sub)

    const recErr = checkRecords([[input.cleanControl, 'clean_control'], [input.victimOrPrimeRequest, 'victim_prime'], [input.attackerProbe, 'attacker_probe']], input.verifySignature)
    if (recErr) return deny(f, recErr, sub)

    const ctrlDenied = isDenied(input.cleanControl.status)
    const ctrlLeaked = input.cleanControlContainsVictimData === true || normStr(input.cleanControl.artifactDigest) === victimDigest
    if (!ctrlDenied && ctrlLeaked) return deny(f, 'resource_already_exposed_in_clean_control', sub)
    if (!ctrlDenied && !isOk(input.cleanControl.status) && input.cleanControl.status !== 404) return deny(f, 'invalid_clean_control_status', sub)
    if (!isOk(input.victimOrPrimeRequest.status)) return deny(f, 'victim_prime_failed', sub)
    if (!isOk(input.attackerProbe.status)) return deny(f, 'attacker_probe_rejected', sub)
    if (!input.isolatedControl && input.victimOrPrimeRequest.timestampMs < input.cleanControl.timestampMs) return deny(f, 'prime_precedes_clean_control', sub)
    if (input.attackerProbe.timestampMs < input.victimOrPrimeRequest.timestampMs) return deny(f, 'attacker_probe_precedes_cache_prime', sub)

    const vActor = normKey(input.victimOrPrimeRequest.actorId), aActor = normKey(input.attackerProbe.actorId)
    const vTenant = normKey(input.victimOrPrimeRequest.tenantId), aTenant = normKey(input.attackerProbe.tenantId)
    const sameActor = Boolean(vActor && aActor && vActor === aActor), sameTenant = Boolean(vTenant && aTenant && vTenant === aTenant)
    if ((!vActor && !vTenant) || (sameActor && (sameTenant || (!vTenant && !aTenant)))) return deny(f, 'victim_and_attacker_not_distinct', sub)

    if (isJobOrHandleStub(input.attackerProbe.json, input.attackerProbe.body, input.attackerProbe.status, input.attackerProbe.method)) return deny(f, 'terminal_impact_unproven_intermediate_stub', sub)
    if (input.cacheHitObserved !== true && !hasCacheHitHeader(input.attackerProbe.responseHeaders)) return deny(f, 'no_cache_hit_evidence', sub)
    if (normStr(input.attackerProbe.artifactDigest) !== victimDigest) return deny(f, 'attacker_did_not_receive_victim_artifact', sub)

    return ok(f, sub, 'cache_primed_cross_principal_bleed_confirmed', {
      cacheKey: input.cacheKey, victimArtifactDigest: victimDigest,
      cleanControlId: input.cleanControl.id, victimPrimeId: input.victimOrPrimeRequest.id, attackerProbeId: input.attackerProbe.id,
    })
  }

  return deny(f, 'unknown_parser_cache_mode')
}

/* ─────────────────── 6. Cross-Surface Pivot Evaluator ────────────────────── */

export type CrossSurfaceHopRole =
  | 'trigger_write' | 'browser_dom_trace' | 'admin_bot_visit'
  | 'worker_ssrf_callback' | 'oob_callback' | 'oidc_redirect' | 'token_exchange' | 'terminal_impact'

export interface CrossSurfaceHop {
  surface: V8SurfaceKind
  role: CrossSurfaceHopRole
  record: HostSignedRecord
  bindingKind?: CausalBindingKind
  emittedArtifactDigest?: string | null
  consumedArtifactDigest?: string | null
  correlationToken?: string | null
  derivedFromCapabilityId?: string | null
  ablationControlDenied?: HostSignedRecord
}

export interface CrossSurfacePivotInput extends WithVerifier {
  attackerOriginPersona: { actorId: string; role: RoleName | string; tenantId?: string | null; isPrivilegedPreSeeded?: boolean }
  preChainControlDenied: HostSignedRecord
  controlKind?: 'authz_denied' | 'unreachable_internal'
  hops: readonly CrossSurfaceHop[]
  terminalImpact: {
    kind: 'privileged_read' | 'privileged_mutation' | 'credential_capture' | 'internal_secret_exfil' | 'privilege_escalation'
    verified: boolean
    impactDigest: string
    postImpactReadback?: HostSignedRecord
  }
}

function hopStatusValid(hop: CrossSurfaceHop): boolean {
  const s = hop.record.status
  if (typeof s === 'number' && s >= 400) return false
  if (hop.role === 'oidc_redirect') return isRedirect(s) || isOk(s)
  if (hop.role === 'terminal_impact') return isOk(s)
  if (s === undefined || s === null) {
    return (hop.surface === 'browser' || hop.surface === 'async_job' || hop.surface === 'webhook') &&
      Boolean(normStr(hop.emittedArtifactDigest ?? hop.record.artifactDigest) || normStr(hop.correlationToken))
  }
  return isOk(s) || isRedirect(s)
}

export function evaluateCrossSurfacePivot(input: CrossSurfacePivotInput): V8OracleDecision {
  const f: V8OracleFamily = 'cross_surface_pivot'
  if (!input?.attackerOriginPersona || !input.terminalImpact) return deny(f, 'missing_pivot_input')
  const sub = input.terminalImpact.kind

  if (!normStr(input.attackerOriginPersona.actorId)) return deny(f, 'missing_attacker_origin_persona', sub)
  if (input.attackerOriginPersona.isPrivilegedPreSeeded === true) return deny(f, 'privileged_persona_shortcut_forbidden', sub)

  const ctrlErr = checkRecord(input.preChainControlDenied, 'pre_chain_control', input.verifySignature)
  if (ctrlErr) return deny(f, ctrlErr, sub)
  const ctrlStatus = input.preChainControlDenied.status
  const ctrlValid = input.controlKind === 'unreachable_internal'
    ? (ctrlStatus === 0 || ctrlStatus === null || ctrlStatus === undefined || isDenied(ctrlStatus))
    : isDenied(ctrlStatus)
  if (!ctrlValid) return deny(f, 'pre_chain_control_not_denied', sub)

  const hops = input.hops
  if (!Array.isArray(hops) || hops.length < 2 || hops.length > MAX_PIVOT_HOPS) return deny(f, 'invalid_hop_count', sub)

  const surfaces = new Set<V8SurfaceKind>()
  const emittedValues = new Set<string>(), emittedHandles = new Set<string>(), correlations = new Set<string>()

  for (let i = 0; i < hops.length; i++) {
    const hop = hops[i]
    if (!hop?.surface) return deny(f, `missing_hop_${i}_surface`, sub)
    const errRec = checkRecord(hop.record, `hop_${i}`, input.verifySignature)
    if (errRec) return deny(f, errRec, sub)
    if (!hopStatusValid(hop)) return deny(f, `hop_${i}_status_failed`, sub)

    if (i === 0) {
      const h0Actor = normKey(hop.record.actorId)
      if (h0Actor && h0Actor !== normKey(input.attackerOriginPersona.actorId)) return deny(f, 'hop_0_actor_mismatch', sub)
    } else {
      if (hop.record.timestampMs < hops[i - 1].record.timestampMs) return deny(f, 'non_monotonic_hop_ordering', sub, { hopIndex: i })
      const kind = hop.bindingKind
      if (!kind) return deny(f, `missing_hop_${i}_causal_binding`, sub)
      if (kind === 'value_binding') {
        const consumed = normStr(hop.consumedArtifactDigest)
        if (!consumed || (!emittedValues.has(consumed) && !emittedHandles.has(consumed))) return deny(f, `broken_value_binding_at_hop_${i}`, sub)
      } else if (kind === 'derived_crypto_binding') {
        const derivedFrom = normStr(hop.derivedFromCapabilityId ?? hop.record.derivedFromCapabilityId)
        if (!derivedFrom || (!emittedHandles.has(derivedFrom) && !emittedValues.has(derivedFrom))) return deny(f, `broken_derived_crypto_binding_at_hop_${i}`, sub)
      } else if (kind === 'async_pivot_binding') {
        const tok = normStr(hop.correlationToken)
        if (!tok || !correlations.has(tok)) return deny(f, `broken_async_pivot_binding_at_hop_${i}`, sub)
      } else if (kind === 'state_transition_binding') {
        const tok = normStr(hop.correlationToken)
        if (!tok || !correlations.has(tok)) return deny(f, `broken_state_transition_binding_at_hop_${i}`, sub)
        const ablErr = checkRecord(hop.ablationControlDenied, `hop_${i}_ablation_control`, input.verifySignature)
        if (ablErr) return deny(f, ablErr, sub)
        if (!isDenied(hop.ablationControlDenied!.status)) return deny(f, `hop_${i}_ablation_control_not_denied`, sub)
      } else {
        return deny(f, `unknown_binding_kind_at_hop_${i}`, sub)
      }
    }

    surfaces.add(hop.surface)
    const emitted = normStr(hop.emittedArtifactDigest ?? hop.record.artifactDigest)
    if (emitted) emittedValues.add(emitted)
    const handle = normStr(hop.record.capabilityHandle)
    if (handle) emittedHandles.add(handle)
    const corr = normStr(hop.correlationToken)
    if (corr) correlations.add(corr)
  }

  if (surfaces.size < 2) return deny(f, 'single_surface_not_cross_surface_pivot', sub)
  const lastHop = hops[hops.length - 1]
  if (input.terminalImpact.verified !== true || !normStr(input.terminalImpact.impactDigest)) return deny(f, 'terminal_impact_unverified', sub)
  if (!isOk(lastHop.record.status) && lastHop.role !== 'oob_callback' && lastHop.role !== 'worker_ssrf_callback') {
    return deny(f, 'terminal_hop_did_not_succeed', sub)
  }

  if (input.terminalImpact.kind === 'privileged_mutation' || input.terminalImpact.kind === 'privilege_escalation') {
    const rb = input.terminalImpact.postImpactReadback
    const rbErr = checkRecord(rb, 'post_impact_readback', input.verifySignature)
    if (rbErr) return deny(f, rbErr, sub)
    if (!isOk(rb!.status)) return deny(f, 'post_impact_readback_failed', sub)
    if (rb!.timestampMs < lastHop.record.timestampMs) return deny(f, 'post_impact_readback_precedes_terminal_hop', sub)
  }

  return ok(f, sub, 'cross_surface_causal_pivot_confirmed', {
    attackerActorId: input.attackerOriginPersona.actorId, hopCount: hops.length, surfaces: Array.from(surfaces),
    impactKind: sub, impactDigest: input.terminalImpact.impactDigest,
    preChainControlId: input.preChainControlDenied.id, terminalHopId: lastHop.record.id,
  })
}

/* ─────────────────────────── Unified Dispatcher ──────────────────────────── */

export interface V8OracleInputMap {
  dual_tenant_abac: DualTenantAbacInput
  temporal_revocation: TemporalRevocationInput
  economic_conservation: EconomicConservationInput
  cryptographic_scope_replay: CryptographicScopeReplayInput
  parser_cache_differential: ParserCacheDifferentialInput
  cross_surface_pivot: CrossSurfacePivotInput
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
