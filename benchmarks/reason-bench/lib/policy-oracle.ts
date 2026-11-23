// Policy oracles: pure evaluators for the implicit domain, economic, temporal and authorization
// invariants that reason-bench sites violate. Each takes a snapshot/policy input and returns
// { violated, detail }. None of them knows about a route, a site, or a FLAG string; apps feed them
// state diffs and the grader attributes the emitted OracleEvent by (kind, routeKey).
import type { Oracle } from './oracle.ts'
import type { ReasonOracleEventKind } from './types.ts'

export interface PolicyResult {
  violated: boolean
  detail: Record<string, string | number | boolean>
}

const ok = (detail: Record<string, string | number | boolean> = {}): PolicyResult => ({ violated: false, detail })
const bad = (detail: Record<string, string | number | boolean>): PolicyResult => ({ violated: true, detail })

/** Emit `kind` through the oracle only when the evaluator says the invariant was violated. */
export function emitIfViolated(
  oracle: Oracle | undefined,
  kind: ReasonOracleEventKind,
  result: PolicyResult,
  sink?: string,
): boolean {
  if (!result.violated || !oracle) return result.violated
  oracle.emit(kind, result.detail, sink)
  return true
}

// ---------------------------------------------------------------------------------------------
// Economic / ledger invariants (lf-01..lf-04, lf-06, lf-10)
// ---------------------------------------------------------------------------------------------
export interface CouponObservation {
  code?: string
  applied: boolean
  cartTotal: number
  minSpend: number
}
export interface LedgerSnapshot {
  paidTotal: number
  refundedTotal: number
  balancesBefore: number
  balancesAfter: number
  deposits?: number
  fulfilledValue?: number
  paidAmount?: number
  coupons?: CouponObservation[]
  epsilon?: number
}

export function checkEconomicConservation(s: LedgerSnapshot): PolicyResult {
  const eps = s.epsilon ?? 0.005
  if (s.refundedTotal - s.paidTotal > eps) {
    return bad({ reason: 'refunded_exceeds_paid', paidTotal: s.paidTotal, refundedTotal: s.refundedTotal })
  }
  const deposits = s.deposits ?? 0
  if (s.balancesAfter - s.balancesBefore - deposits > eps) {
    return bad({
      reason: 'balance_minted', before: s.balancesBefore, after: s.balancesAfter, deposits,
      delta: s.balancesAfter - s.balancesBefore,
    })
  }
  if (s.fulfilledValue != null && s.paidAmount != null && s.fulfilledValue - s.paidAmount > eps) {
    return bad({ reason: 'fulfilled_exceeds_paid', fulfilledValue: s.fulfilledValue, paidAmount: s.paidAmount })
  }
  for (const c of s.coupons ?? []) {
    if (c.applied && c.cartTotal + eps < c.minSpend) {
      return bad({
        reason: 'coupon_below_min_spend', coupon: c.code ?? 'unnamed',
        cartTotal: c.cartTotal, minSpend: c.minSpend,
      })
    }
  }
  return ok({ checked: true })
}

// ---------------------------------------------------------------------------------------------
// Maker/checker self-approval (lf-05)
// ---------------------------------------------------------------------------------------------
export interface SelfApprovalInput {
  creatorId: string
  approverId: string
  // Shadow audit creator, unaffected by any app-side overwrite of createdBy.
  shadowCreatorId?: string
  approved?: boolean
  status?: string
}
export function checkSelfApproval(input: SelfApprovalInput): PolicyResult {
  const creator = input.shadowCreatorId ?? input.creatorId
  const approved = input.approved ?? input.status === 'approved'
  if (!approved) return ok({ approved: false })
  if (creator === input.approverId) {
    return bad({ reason: 'approver_is_creator', creatorId: creator, approverId: input.approverId })
  }
  return ok({ creatorId: creator, approverId: input.approverId })
}

// ---------------------------------------------------------------------------------------------
// Temporal revocation / stale privilege (lf-07, lf-08, fc-01)
// ---------------------------------------------------------------------------------------------
export interface RevocationInput {
  tokenHash: string
  revokedTokens: readonly string[] | ReadonlySet<string>
  accepted: boolean
  delivered?: boolean // e.g. a live SSE event was delivered after revocation
}
export function checkRevocation(input: RevocationInput): PolicyResult {
  const has = typeof (input.revokedTokens as ReadonlySet<string>).has === 'function'
    ? (input.revokedTokens as ReadonlySet<string>).has(input.tokenHash)
    : (input.revokedTokens as readonly string[]).includes(input.tokenHash)
  if (has && (input.accepted || input.delivered)) {
    return bad({
      reason: 'revoked_token_accepted', tokenHash: input.tokenHash,
      accepted: input.accepted, delivered: input.delivered ?? false,
    })
  }
  return ok({ revoked: has, accepted: input.accepted })
}

export interface StalePrivilegeInput {
  actorId: string
  currentRole: string
  requiredRoles: readonly string[]
  actionSucceeded: boolean
  grantRole?: string // role embedded in an invite/token/job
  grantValidUntil?: number
  now?: number
  revoked?: boolean
}
export function checkStalePrivilege(input: StalePrivilegeInput): PolicyResult {
  if (!input.actionSucceeded) return ok({ actionSucceeded: false })
  const now = input.now ?? Date.now()
  const expired = input.grantValidUntil != null && input.grantValidUntil < now
  const currentOk = input.requiredRoles.includes(input.currentRole)
  const grantOk = input.grantRole != null && input.requiredRoles.includes(input.grantRole)
  if (input.revoked || expired || (!currentOk && !grantOk)) {
    return bad({
      reason: input.revoked ? 'grant_revoked' : expired ? 'grant_expired' : 'current_role_insufficient',
      actorId: input.actorId, currentRole: input.currentRole, grantRole: input.grantRole ?? 'none',
      required: input.requiredRoles.join(','), expired,
    })
  }
  return ok({ actorId: input.actorId, currentRole: input.currentRole })
}

// ---------------------------------------------------------------------------------------------
// Cross-org transfer / tenant boundary (fc-03)
// ---------------------------------------------------------------------------------------------
export interface CrossOrgTransferInput {
  resourceTenantBefore: string
  resourceTenantAfter: string
  actorTenant: string
  // The actor's role in the SOURCE tenant (not the destination).
  actorRoleOnSource: string
  requiredSourceRoles?: readonly string[]
  actionSucceeded?: boolean
}
export function checkCrossOrgTransfer(input: CrossOrgTransferInput): PolicyResult {
  const required = input.requiredSourceRoles ?? ['owner', 'admin']
  if (input.resourceTenantBefore === input.resourceTenantAfter) return ok({ transferred: false })
  if (input.actionSucceeded === false) return ok({ transferred: false })
  if (input.actorTenant !== input.resourceTenantBefore || !required.includes(input.actorRoleOnSource)) {
    return bad({
      reason: 'source_tenant_privilege_missing',
      from: input.resourceTenantBefore, to: input.resourceTenantAfter,
      actorTenant: input.actorTenant, actorRoleOnSource: input.actorRoleOnSource,
      required: required.join(','),
    })
  }
  return ok({ transferred: true })
}

// ---------------------------------------------------------------------------------------------
// Batch partial authorization (fc-05)
// ---------------------------------------------------------------------------------------------
export interface BatchAuthzInput {
  status: number
  ownedIds: readonly string[]
  mutatedIds: readonly string[]
  requestedIds?: readonly string[]
}
export function checkBatchPartialAuthz(input: BatchAuthzInput): PolicyResult {
  if (input.status < 200 || input.status >= 300) return ok({ status: input.status })
  const owned = new Set(input.ownedIds)
  const foreign = input.mutatedIds.filter((id) => !owned.has(id))
  if (foreign.length > 0) {
    return bad({
      reason: 'batch_mutated_foreign_rows', mutated: input.mutatedIds.length,
      foreign: foreign.length, firstForeign: foreign[0]!,
    })
  }
  return ok({ mutated: input.mutatedIds.length })
}

// ---------------------------------------------------------------------------------------------
// Tenant existence / aggregate oracle (fc-06)
// ---------------------------------------------------------------------------------------------
export interface TenantExistenceInput {
  actorTenant: string
  entitledTenants: readonly string[]
  responseText?: string
  foreignTokens?: readonly string[]
  counts?: ReadonlyArray<{ tenant: string; value: number }>
}
export function checkTenantExistenceLeak(input: TenantExistenceInput): PolicyResult {
  const entitled = new Set([input.actorTenant, ...input.entitledTenants])
  const body = input.responseText ?? ''
  for (const token of input.foreignTokens ?? []) {
    if (body.includes(token)) {
      return bad({ reason: 'foreign_canary_in_aggregate', token, actorTenant: input.actorTenant })
    }
  }
  for (const c of input.counts ?? []) {
    if (!entitled.has(c.tenant) && c.value > 0) {
      return bad({ reason: 'foreign_bucket_count', tenant: c.tenant, value: c.value })
    }
  }
  return ok({ checked: true })
}

// ---------------------------------------------------------------------------------------------
// HMAC scope binding (lf-11)
// ---------------------------------------------------------------------------------------------
export interface HmacScope { tenantId: string; eventType: string }
export interface HmacScopeInput {
  signatureValid: boolean
  signedScope: HmacScope
  presentedScope: HmacScope
}
export function checkHmacScope(input: HmacScopeInput): PolicyResult {
  if (!input.signatureValid) return ok({ signatureValid: false })
  const tenantMismatch = input.signedScope.tenantId !== input.presentedScope.tenantId
  const eventMismatch = input.signedScope.eventType !== input.presentedScope.eventType
  if (tenantMismatch || eventMismatch) {
    return bad({
      reason: 'signature_scope_mismatch', tenantMismatch, eventMismatch,
      signedTenant: input.signedScope.tenantId, presentedTenant: input.presentedScope.tenantId,
      signedEvent: input.signedScope.eventType, presentedEvent: input.presentedScope.eventType,
    })
  }
  return ok({ signatureValid: true })
}

// ---------------------------------------------------------------------------------------------
// Signed-URL prefix escape (fc-07)
// ---------------------------------------------------------------------------------------------
export interface SignedUrlPrefixInput {
  tenantSlug: string
  requestedPath: string
  root?: string // default '/exports'
}
export function checkSignedUrlPrefix(input: SignedUrlPrefixInput): PolicyResult {
  const root = (input.root ?? '/exports').replace(/\/+$/, '')
  const prefix = `${root}/${input.tenantSlug}`
  if (!input.requestedPath.startsWith(prefix)) return ok({ inside: false })
  if (input.requestedPath === prefix || input.requestedPath.startsWith(`${prefix}/`)) {
    return ok({ inside: true })
  }
  // e.g. tenant 'acme' requesting '/exports/acme-corp/audit.json' passes a raw startsWith check
  // but crosses the trailing-slash tenant boundary.
  return bad({ reason: 'prefix_boundary_escape', tenantSlug: input.tenantSlug, requestedPath: input.requestedPath })
}

// ---------------------------------------------------------------------------------------------
// SSO tenant confusion (lf-09, fc-08)
// ---------------------------------------------------------------------------------------------
export interface SsoTenantInput {
  signatureValid: boolean
  assertionTid?: string
  expectedTid: string
  matchedOn: 'verified_email' | 'pending_email' | 'subject'
  verifiedEmail?: string
  pendingEmail?: string
}
export function checkSsoTenantConfusion(input: SsoTenantInput): PolicyResult {
  if (!input.signatureValid) return ok({ signatureValid: false })
  const tenantMismatch = input.assertionTid !== input.expectedTid
  if (tenantMismatch) {
    return bad({
      reason: 'assertion_tenant_mismatch', assertionTid: input.assertionTid ?? 'omitted',
      expectedTid: input.expectedTid,
    })
  }
  if (input.matchedOn === 'pending_email') {
    return bad({
      reason: 'pending_email_trusted', pendingEmail: input.pendingEmail ?? '',
      verifiedEmail: input.verifiedEmail ?? '',
    })
  }
  return ok({ matchedOn: input.matchedOn })
}

// ---------------------------------------------------------------------------------------------
// Parser differential (fc-09)
// ---------------------------------------------------------------------------------------------
export interface ParserDifferentialInput {
  edgeValue: string
  handlerValue: string
  actionSucceeded: boolean
  field?: string
}
export function checkParserDifferential(input: ParserDifferentialInput): PolicyResult {
  if (!input.actionSucceeded) return ok({ actionSucceeded: false })
  if (input.edgeValue !== input.handlerValue) {
    return bad({
      reason: 'edge_handler_disagreement', field: input.field ?? 'value',
      edgeValue: input.edgeValue, handlerValue: input.handlerValue,
    })
  }
  return ok({ edgeValue: input.edgeValue })
}

// ---------------------------------------------------------------------------------------------
// Cache tenant bleed (fc-13)
// ---------------------------------------------------------------------------------------------
export interface CacheTenantBleedInput {
  hit: boolean
  cacheTenant: string | null
  actorTenant: string | null
  cacheActor?: string
  actor?: string
  actionSucceeded: boolean
}
export function checkCacheTenantBleed(input: CacheTenantBleedInput): PolicyResult {
  if (!input.hit || !input.actionSucceeded) return ok({ hit: input.hit })
  const tenantMismatch = input.cacheTenant !== input.actorTenant
  const actorMismatch = input.cacheActor != null && input.actor != null && input.cacheActor !== input.actor
  if (tenantMismatch || actorMismatch) {
    return bad({
      reason: 'cached_context_reused', cacheTenant: input.cacheTenant ?? 'none',
      actorTenant: input.actorTenant ?? 'none', tenantMismatch, actorMismatch,
    })
  }
  return ok({ hit: true })
}
