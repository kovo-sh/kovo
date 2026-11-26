/**
 * Tier-3 approval bookkeeping: exact-fingerprint grouping and single-use grants.
 *
 * Extracted from `execution.ts` during the v6 Phase-4 deletion pass. There is deliberately no
 * keyword scan here: environment contracts decide, operator opt-in raises one card, and the exact
 * single-use ledger (or a durable route lease) authorizes the retry.
 */
import { createHash } from 'node:crypto'
import {
  buildStateChangeFingerprint,
  computeStateChangeBodyHash,
  detectMultipartRequest,
  hasDeclaredMultipartContentType,
  STATE_CHANGE_APPROVAL_TTL_MS,
} from './approval-judge.ts'
import type {
  MultipartBodyPart,
  MultipartRequestKind,
  StateChangeApprovalLedger,
  StateChangeFingerprintInput,
} from './approval-judge.ts'
import { computeApprovalHeadersDigest, normalizeOriginKey } from './approval-pattern.ts'
import { detectMethodOverride } from './scope-policy.ts'
import type { Run } from './store.ts'

/** Upper bound on per-instance grants a single synchronized burst may register (broker caps bursts at 10). */
const MAX_BURST_APPROVAL_INSTANCES = 10

export type BurstApprovalInstances = Map<string, { remaining: number; expiresAt: number }>

export interface Tier3ApprovalRequest {
  origin: string
  method: string
  pathAndQuery: string
  persona?: string | null
  body?: string | null
  multipartParts?: readonly MultipartBodyPart[] | null
  headers?: Record<string, string>
}

export interface Tier3ApprovalPlanTarget {
  origin: string
  method: string
  /** Effective HTTP verb accounting for method-override carriers (`R2-H-1`). */
  effectiveMethod: string
  pathAndQuery: string
  personaHandle: string | null
  bodyPreview: string | null
  bodyHash: string | null
  headers?: Record<string, string>
  /** H-4: Canonical SHA-256 digest of headers (or null when headerless). */
  headersDigest: string | null
  hasMultipart: boolean
  /** H-4: Explicit multipart classification (`none` | `multipart` | `malformed_multipart`). */
  multipartKind: MultipartRequestKind
  hasCompressedBody: boolean
  hasMethodOverride: boolean
  instances: number
}

export interface Tier3ApprovalPlan {
  primary: {
    origin: string
    method: string
    effectiveMethod: string
    pathAndQuery: string
    personaHandle: string | null
    bodyPreview: string | null
    bodyHash: string | null
    headers?: Record<string, string>
    headersDigest: string | null
    hasMultipart: boolean
    multipartKind: MultipartRequestKind
    hasCompressedBody: boolean
    hasMethodOverride: boolean
    approvalInstances: number
  }
  /** Every distinct state-changing target in the group, in first-seen order; each must be evaluated individually. */
  targets: Tier3ApprovalPlanTarget[]
  additional: Tier3ApprovalPlanTarget[]
  /**
   * H-4: SHA-256 digest over ALL targets in `targets` (never `targets[0]` alone).
   * Batch approval decisions must bind to this hash before registering grants.
   */
  targetsHash: string
}

export interface BatchTargetDigestInput {
  origin: string
  method: string
  effectiveMethod?: string
  pathAndQuery: string
  personaHandle?: string | null
  bodyHash?: string | null
  headersDigest?: string | null
  headers?: Record<string, string>
  hasMultipart?: boolean
  multipartKind?: MultipartRequestKind
  hasCompressedBody?: boolean
  hasMethodOverride?: boolean
  instances?: number
}

/**
 * Compute a deterministic SHA-256 hash binding a batch approval decision to EVERY target in the
 * group (`H-4`). Adding, removing, reordering, or mutating any target (including headers or
 * multipart kind) changes the hash so a decision can never authorize an unevaluated sibling.
 */
export function computeBatchTargetsHash(targets: ReadonlyArray<BatchTargetDigestInput>): string {
  const canonical = targets.map(t => [
    normalizeOriginKey(t.origin),
    t.method.toUpperCase(),
    (t.effectiveMethod ?? t.method).toUpperCase(),
    t.pathAndQuery,
    t.personaHandle ?? '',
    t.bodyHash ?? '',
    t.headersDigest !== undefined ? (t.headersDigest ?? '') : (computeApprovalHeadersDigest(t.headers) ?? ''),
    t.multipartKind ?? (t.hasMultipart ? 'multipart' : 'none'),
    Boolean(t.hasCompressedBody),
    Boolean(t.hasMethodOverride),
    Math.max(1, Math.floor(t.instances ?? 1)),
  ])
  return `batch-targets-v1:${createHash('sha256').update(JSON.stringify(canonical), 'utf8').digest('hex')}`
}

export interface BatchTargetAuditEntry {
  targetIndex: number
  totalTargets: number
  approvalId: string
  targetsHash: string
  runId: string
  assignmentId?: string
  origin: string
  method: string
  effectiveMethod: string
  pathAndQuery: string
  personaHandle: string | null
  bodyHash: string | null
  headersDigest: string | null
  multipartKind: MultipartRequestKind
  hasCompressedBody: boolean
  hasMethodOverride: boolean
  instances: number
  decision: 'approved' | 'denied'
  decidedBy: string
  decidedAt: number
}

export interface BatchApprovalDecisionBinding {
  approvalId: string
  runId: string
  assignmentId?: string
  targetsHash: string
  targetCount: number
  decision: 'approved' | 'denied'
  decidedBy: string
  decidedAt: number
  /** Per-target audit trail entries (one per distinct target in the batch, never target[0] alone). */
  auditEntries: BatchTargetAuditEntry[]
}

/**
 * Group the exact requests of a synchronized operation (race burst / batch) by ledger
 * fingerprint (including canonical headers digest, multipart kind, compression, and method
 * override state). Identical request instances share a fingerprint and therefore a single approval
 * target carrying `instances = N`; each distinct target is returned in `targets` with its full
 * request metadata so EVERY distinct target is evaluated individually (never smuggled under a
 * benign primary target).
 */
export function planTier3ApprovalTargets(
  run: Run,
  requests: ReadonlyArray<Tier3ApprovalRequest>,
  options: { isRaceBurst?: boolean; assignmentId?: string } = {},
): Tier3ApprovalPlan {
  const isReadOnly = (method: string, multipart: boolean, hasMethodOverride: boolean, body: string | null) => {
    if (multipart || hasMethodOverride) return false
    const upper = method.toUpperCase()
    if (upper === 'GET' || upper === 'HEAD') return true
    if (upper === 'OPTIONS') return body === null || body === ''
    return false
  }
  const describe = (request: Tier3ApprovalRequest) => {
    const hasMultipartParts = Boolean(request.multipartParts?.length)
    const multipartKind = detectMultipartRequest({
      headers: request.headers,
      hasMultipart: hasMultipartParts,
      bodyPreview: request.body ?? null,
    })
    const hasMultipart = hasMultipartParts || hasDeclaredMultipartContentType(request.headers) || multipartKind !== 'none'
    const contentEncoding = Object.entries(request.headers ?? {})
      .find(([k]) => k.toLowerCase() === 'content-encoding')?.[1]?.trim() ?? ''
    const hasCompressedBody = contentEncoding !== '' && !/^identity$/i.test(contentEncoding)
    const headersDigest = computeApprovalHeadersDigest(request.headers)
    const override = detectMethodOverride({
      method: request.method,
      pathAndQuery: request.pathAndQuery,
      headers: request.headers,
      body: request.body ?? null,
    })
    return {
      origin: request.origin,
      method: request.method,
      effectiveMethod: override.effectiveMethod,
      pathAndQuery: request.pathAndQuery,
      personaHandle: request.persona ?? null,
      bodyHash: computeStateChangeBodyHash(request.body ?? null, request.multipartParts),
      headersDigest,
      hasMultipart,
      multipartKind,
      hasCompressedBody,
      hasMethodOverride: override.hasOverride,
      bodyPreview: request.body ?? null,
      headers: request.headers,
    }
  }
  const described = requests.map(describe)
  const groupKeyOf = (target: ReturnType<typeof describe>) => buildStateChangeFingerprint({
    runId: run.id,
    origin: target.origin,
    method: target.method,
    pathAndQuery: target.pathAndQuery,
    scopeRevision: run.scopeRevision,
    personaHandle: target.personaHandle,
    bodyHash: target.bodyHash,
    headers: target.headers,
    headersDigest: target.headersDigest,
    hasMultipart: target.hasMultipart,
    multipartKind: target.multipartKind,
    hasCompressedBody: target.hasCompressedBody,
    hasMethodOverride: target.hasMethodOverride,
    isRaceBurst: Boolean(options.isRaceBurst),
    isRceProof: false,
    ...(options.assignmentId ? { assignmentId: options.assignmentId } : {}),
  })
  // Prefer a state-changing request as the first target; fall back to the first request.
  const primaryIndex = Math.max(
    0,
    described.findIndex(target => !isReadOnly(target.effectiveMethod, target.hasMultipart, target.hasMethodOverride, target.bodyPreview)),
  )
  const groups = new Map<string, { target: ReturnType<typeof describe>; instances: number }>()
  for (const target of described) {
    if (isReadOnly(target.effectiveMethod, target.hasMultipart, target.hasMethodOverride, target.bodyPreview)) continue
    const key = groupKeyOf(target)
    const existing = groups.get(key)
    if (existing) existing.instances += 1
    else groups.set(key, { target, instances: 1 })
  }
  const primaryTarget = described[primaryIndex]!
  const primaryKey = groupKeyOf(primaryTarget)
  const primaryGroup = groups.get(primaryKey)
  const toPlanTarget = (target: ReturnType<typeof describe>, instances: number): Tier3ApprovalPlanTarget => ({
    origin: target.origin,
    method: target.method,
    effectiveMethod: target.effectiveMethod,
    pathAndQuery: target.pathAndQuery,
    personaHandle: target.personaHandle,
    bodyPreview: target.bodyPreview,
    bodyHash: target.bodyHash,
    headers: target.headers,
    headersDigest: target.headersDigest,
    hasMultipart: target.hasMultipart,
    multipartKind: target.multipartKind,
    hasCompressedBody: target.hasCompressedBody,
    hasMethodOverride: target.hasMethodOverride,
    instances,
  })
  const targets: Tier3ApprovalPlanTarget[] = []
  const additional: Tier3ApprovalPlanTarget[] = []
  if (groups.size === 0) {
    targets.push(toPlanTarget(primaryTarget, 1))
  } else {
    for (const [key, group] of groups) {
      const entry = toPlanTarget(group.target, group.instances)
      targets.push(entry)
      if (key !== primaryKey) additional.push(entry)
    }
  }
  const targetsHash = computeBatchTargetsHash(targets)
  return {
    primary: {
      origin: primaryTarget.origin,
      method: primaryTarget.method,
      effectiveMethod: primaryTarget.effectiveMethod,
      pathAndQuery: primaryTarget.pathAndQuery,
      personaHandle: primaryTarget.personaHandle,
      bodyPreview: primaryTarget.bodyPreview,
      bodyHash: primaryTarget.bodyHash,
      headers: primaryTarget.headers,
      headersDigest: primaryTarget.headersDigest,
      hasMultipart: primaryTarget.hasMultipart,
      multipartKind: primaryTarget.multipartKind,
      hasCompressedBody: primaryTarget.hasCompressedBody,
      hasMethodOverride: primaryTarget.hasMethodOverride,
      approvalInstances: primaryGroup?.instances ?? 1,
    },
    targets,
    additional,
    targetsHash,
  }
}

/**
 * Bind a batch approval decision to the hashed list of ALL targets (`H-4`) and build one audit
 * entry per target (never recording `targets[0]` alone).
 */
export function bindBatchApprovalDecision(
  plan: Pick<Tier3ApprovalPlan, 'targets' | 'targetsHash'>,
  options: {
    approvalId: string
    runId: string
    assignmentId?: string
    decision: 'approved' | 'denied'
    decidedBy: string
    decidedAt?: number
  },
): BatchApprovalDecisionBinding {
  const decidedAt = options.decidedAt ?? Date.now()
  const expectedHash = computeBatchTargetsHash(plan.targets)
  if (plan.targetsHash !== expectedHash) {
    throw new Error('Tier-3 batch approval plan targetsHash does not match plan.targets.')
  }
  const auditEntries: BatchTargetAuditEntry[] = plan.targets.map((target, idx) => ({
    targetIndex: idx,
    totalTargets: plan.targets.length,
    approvalId: options.approvalId,
    targetsHash: expectedHash,
    runId: options.runId,
    ...(options.assignmentId ? { assignmentId: options.assignmentId } : {}),
    origin: target.origin,
    method: target.method,
    effectiveMethod: target.effectiveMethod,
    pathAndQuery: target.pathAndQuery,
    personaHandle: target.personaHandle,
    bodyHash: target.bodyHash,
    headersDigest: target.headersDigest,
    multipartKind: target.multipartKind,
    hasCompressedBody: target.hasCompressedBody,
    hasMethodOverride: target.hasMethodOverride,
    instances: target.instances,
    decision: options.decision,
    decidedBy: options.decidedBy,
    decidedAt,
  }))
  return {
    approvalId: options.approvalId,
    runId: options.runId,
    ...(options.assignmentId ? { assignmentId: options.assignmentId } : {}),
    targetsHash: expectedHash,
    targetCount: plan.targets.length,
    decision: options.decision,
    decidedBy: options.decidedBy,
    decidedAt,
    auditEntries,
  }
}

/** Verify that a batch approval decision is approved and bound to the exact list of targets. */
export function verifyBatchApprovalBinding(
  binding: BatchApprovalDecisionBinding,
  targets: ReadonlyArray<BatchTargetDigestInput>,
): boolean {
  if (binding.decision !== 'approved') return false
  if (binding.targetCount !== targets.length) return false
  return binding.targetsHash === computeBatchTargetsHash(targets)
}

/**
 * Register N single-use instances of one exact fingerprint for a synchronized burst. The entry is
 * removed once every instance has been consumed, so instance N+1 always re-escalates.
 */
export function grantBurstInstances(
  instances: BurstApprovalInstances,
  input: StateChangeFingerprintInput,
  count: number,
  expiresAt: number,
): void {
  const quota = Math.max(1, Math.min(MAX_BURST_APPROVAL_INSTANCES, Math.floor(count)))
  const key = buildStateChangeFingerprint(input)
  instances.set(key, { remaining: quota, expiresAt })
  if (instances.size > 2048) {
    for (const [candidate, entry] of instances) {
      if (entry.expiresAt <= Date.now()) instances.delete(candidate)
    }
    while (instances.size > 2048) {
      const oldest = instances.keys().next().value
      if (oldest === undefined) break
      instances.delete(oldest)
    }
  }
}

/** Consume one instance of an exact burst fingerprint; expired or exhausted entries never match. */
export function consumeBurstInstance(
  instances: BurstApprovalInstances,
  input: StateChangeFingerprintInput,
  now = Date.now(),
): boolean {
  const key = buildStateChangeFingerprint(input)
  const entry = instances.get(key)
  if (!entry) return false
  if (entry.expiresAt <= now) {
    instances.delete(key)
    return false
  }
  entry.remaining -= 1
  if (entry.remaining <= 0) instances.delete(key)
  return true
}

export interface StateChangeApprovalInput {
  origin: string
  method: string
  pathAndQuery: string
  personaHandle?: string | null
  bodyHash?: string | null
  bodyPreview?: string | null
  headers?: Record<string, string>
  headersDigest?: string | null
  hasMultipart?: boolean
  multipartKind?: MultipartRequestKind
  hasCompressedBody?: boolean
  hasMethodOverride?: boolean
  isRaceBurst?: boolean
  isRceProof?: boolean
  approvalId?: string
  assignmentId?: string
  /** Single-use instances covered by this decision (default 1; race bursts may register N). */
  instances?: number
}

export type StateChangeApprovalTarget = {
  origin: string
  method: string
  pathAndQuery: string
  personaHandle?: string | null
  bodyHash?: string | null
  headers?: Record<string, string>
  headersDigest?: string | null
  hasMultipart?: boolean
  multipartKind?: MultipartRequestKind
  hasCompressedBody?: boolean
  hasMethodOverride?: boolean
  instances?: number
}

/**
 * Register the exact, single-use grant a decision just authorized. The immediate broker retry
 * consumes it only when origin/method/path/persona/body/headers/flag fingerprint and scope revision match.
 *
 * Distinct sibling targets are NEVER granted from a single decision: callers must evaluate and
 * approve each distinct target individually before calling `registerStateChangeGrant`.
 */
export function registerStateChangeGrant(
  ledger: StateChangeApprovalLedger,
  burstInstances: BurstApprovalInstances,
  run: Run,
  input: StateChangeApprovalInput,
): void {
  const primaryBodyHash = input.bodyHash ?? computeStateChangeBodyHash(input.bodyPreview ?? null)
  const expiresAt = Date.now() + STATE_CHANGE_APPROVAL_TTL_MS
  const fingerprint: StateChangeFingerprintInput = {
    runId: run.id,
    origin: input.origin,
    method: input.method,
    pathAndQuery: input.pathAndQuery,
    scopeRevision: run.scopeRevision,
    personaHandle: input.personaHandle ?? null,
    bodyHash: primaryBodyHash ?? null,
    ...(input.headers !== undefined ? { headers: input.headers } : {}),
    ...(input.headersDigest !== undefined ? { headersDigest: input.headersDigest } : {}),
    hasMultipart: Boolean(input.hasMultipart),
    ...(input.multipartKind !== undefined ? { multipartKind: input.multipartKind } : {}),
    ...(input.hasCompressedBody !== undefined ? { hasCompressedBody: input.hasCompressedBody } : {}),
    ...(input.hasMethodOverride !== undefined ? { hasMethodOverride: input.hasMethodOverride } : {}),
    isRaceBurst: Boolean(input.isRaceBurst),
    isRceProof: Boolean(input.isRceProof),
    ...(input.assignmentId ? { assignmentId: input.assignmentId } : {}),
  }
  const instances = Math.max(1, input.instances ?? 1)
  if (instances > 1) {
    grantBurstInstances(burstInstances, fingerprint, instances, expiresAt)
  } else {
    ledger.grant(fingerprint, { expiresAt, approvalId: input.approvalId })
  }
}

/**
 * Register grants for a batch ONLY after verifying the decision binding covers ALL targets (`H-4`),
 * emitting one per-target audit record for each target.
 */
export function registerBatchStateChangeGrants(
  ledger: StateChangeApprovalLedger,
  burstInstances: BurstApprovalInstances,
  run: Run,
  targets: ReadonlyArray<Tier3ApprovalPlanTarget>,
  binding: BatchApprovalDecisionBinding,
  options: {
    isRaceBurst?: boolean
    onAudit?: (entry: BatchTargetAuditEntry) => void
  } = {},
): void {
  if (!verifyBatchApprovalBinding(binding, targets)) {
    throw new Error('Batch approval binding mismatch: decision does not cover the exact target list.')
  }
  for (let i = 0; i < targets.length; i += 1) {
    const target = targets[i]!
    const auditEntry = binding.auditEntries[i]
    if (auditEntry) options.onAudit?.(auditEntry)
    registerStateChangeGrant(ledger, burstInstances, run, {
      origin: target.origin,
      method: target.method,
      pathAndQuery: target.pathAndQuery,
      personaHandle: target.personaHandle,
      bodyHash: target.bodyHash,
      bodyPreview: target.bodyPreview,
      headers: target.headers,
      headersDigest: target.headersDigest,
      hasMultipart: target.hasMultipart,
      multipartKind: target.multipartKind,
      hasCompressedBody: target.hasCompressedBody,
      hasMethodOverride: target.hasMethodOverride,
      isRaceBurst: Boolean(options.isRaceBurst),
      approvalId: binding.approvalId,
      assignmentId: binding.assignmentId,
      instances: target.instances,
    })
  }
}
