/**
 * Tier-3 approval bookkeeping: exact-fingerprint grouping and single-use grants.
 *
 * Extracted from `execution.ts` during the v6 Phase-4 deletion pass. There is deliberately no
 * keyword scan here: environment contracts decide, operator opt-in raises one card, and the exact
 * single-use ledger (or a durable route lease) authorizes the retry.
 */
import {
  buildStateChangeFingerprint,
  computeStateChangeBodyHash,
  hasDeclaredMultipartContentType,
  STATE_CHANGE_APPROVAL_TTL_MS,
} from './approval-judge.ts'
import type {
  MultipartBodyPart,
  StateChangeApprovalLedger,
  StateChangeFingerprintInput,
} from './approval-judge.ts'
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

export interface Tier3ApprovalPlan {
  primary: {
    origin: string
    method: string
    pathAndQuery: string
    personaHandle: string | null
    bodyPreview: string | null
    bodyHash: string | null
    headers?: Record<string, string>
    hasMultipart: boolean
    approvalInstances: number
  }
  additional: Array<{
    origin: string
    method: string
    pathAndQuery: string
    personaHandle: string | null
    bodyHash: string | null
    hasMultipart: boolean
    instances: number
  }>
}

/**
 * Group the exact requests of a synchronized operation (race burst / batch) by ledger
 * fingerprint. Identical request instances share a fingerprint and therefore a single approval
 * target carrying `instances = N`; each instance still consumes its own single-use grant.
 */
export function planTier3ApprovalTargets(
  run: Run,
  requests: ReadonlyArray<Tier3ApprovalRequest>,
  options: { isRaceBurst?: boolean } = {},
): Tier3ApprovalPlan {
  const isReadOnly = (method: string, multipart: boolean) =>
    !multipart && (method.toUpperCase() === 'GET' || method.toUpperCase() === 'HEAD' || method.toUpperCase() === 'OPTIONS')
  const describe = (request: Tier3ApprovalRequest) => {
    const hasMultipart = Boolean(request.multipartParts?.length) ||
      hasDeclaredMultipartContentType(request.headers)
    return {
      origin: request.origin,
      method: request.method,
      pathAndQuery: request.pathAndQuery,
      personaHandle: request.persona ?? null,
      bodyHash: computeStateChangeBodyHash(request.body ?? null, request.multipartParts),
      hasMultipart,
      bodyPreview: request.body ?? null,
      headers: request.headers,
    }
  }
  const described = requests.map(describe)
  const fingerprintOf = (target: ReturnType<typeof describe>) => buildStateChangeFingerprint({
    runId: run.id,
    origin: target.origin,
    method: target.method,
    pathAndQuery: target.pathAndQuery,
    scopeRevision: run.scopeRevision,
    personaHandle: target.personaHandle,
    bodyHash: target.bodyHash,
    hasMultipart: target.hasMultipart,
    isRaceBurst: Boolean(options.isRaceBurst),
    isRceProof: false,
  })
  // Prefer a state-changing request as the judge/operator-facing primary; fall back to the first.
  const primaryIndex = Math.max(0, described.findIndex(target => !isReadOnly(target.method, target.hasMultipart)))
  const groups = new Map<string, { target: ReturnType<typeof describe>; instances: number }>()
  for (const target of described) {
    if (isReadOnly(target.method, target.hasMultipart)) continue
    const key = fingerprintOf(target)
    const existing = groups.get(key)
    if (existing) existing.instances += 1
    else groups.set(key, { target, instances: 1 })
  }
  const primaryTarget = described[primaryIndex]!
  const primaryKey = fingerprintOf(primaryTarget)
  const primaryGroup = groups.get(primaryKey)
  const additional: Tier3ApprovalPlan['additional'] = []
  for (const [key, group] of groups) {
    if (key === primaryKey) continue
    additional.push({
      origin: group.target.origin,
      method: group.target.method,
      pathAndQuery: group.target.pathAndQuery,
      personaHandle: group.target.personaHandle,
      bodyHash: group.target.bodyHash,
      hasMultipart: group.target.hasMultipart,
      instances: group.instances,
    })
  }
  return {
    primary: {
      origin: primaryTarget.origin,
      method: primaryTarget.method,
      pathAndQuery: primaryTarget.pathAndQuery,
      personaHandle: primaryTarget.personaHandle,
      bodyPreview: primaryTarget.bodyPreview,
      bodyHash: primaryTarget.bodyHash,
      headers: primaryTarget.headers,
      hasMultipart: primaryTarget.hasMultipart,
      approvalInstances: primaryGroup?.instances ?? 1,
    },
    additional,
  }
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
  hasMultipart?: boolean
  isRaceBurst?: boolean
  isRceProof?: boolean
  approvalId?: string
  /** Single-use instances covered by this decision (default 1; race bursts may register N). */
  instances?: number
}

export type StateChangeApprovalTarget = {
  origin: string
  method: string
  pathAndQuery: string
  personaHandle?: string | null
  bodyHash?: string | null
  hasMultipart?: boolean
  instances?: number
}

/**
 * Register the exact, single-use grant a decision just authorized. The immediate broker retry
 * consumes it only when origin/method/path/persona/body/flag fingerprint and scope revision match.
 */
export function registerStateChangeGrant(
  ledger: StateChangeApprovalLedger,
  burstInstances: BurstApprovalInstances,
  run: Run,
  input: StateChangeApprovalInput,
  additional: StateChangeApprovalTarget[] = [],
): void {
  const primaryBodyHash = input.bodyHash ?? computeStateChangeBodyHash(input.bodyPreview ?? null)
  const targets = [
    { ...input, bodyHash: primaryBodyHash },
    ...additional.map(target => ({
      ...target,
      hasMultipart: target.hasMultipart ?? input.hasMultipart,
      isRaceBurst: input.isRaceBurst,
      isRceProof: input.isRceProof,
      approvalId: input.approvalId,
    })),
  ]
  const expiresAt = Date.now() + STATE_CHANGE_APPROVAL_TTL_MS
  for (const target of targets) {
    const fingerprint: StateChangeFingerprintInput = {
      runId: run.id,
      origin: target.origin,
      method: target.method,
      pathAndQuery: target.pathAndQuery,
      scopeRevision: run.scopeRevision,
      personaHandle: target.personaHandle ?? null,
      bodyHash: target.bodyHash ?? null,
      hasMultipart: Boolean(target.hasMultipart),
      isRaceBurst: Boolean(target.isRaceBurst),
      isRceProof: Boolean(target.isRceProof),
    }
    const instances = Math.max(1, target.instances ?? 1)
    if (instances > 1) {
      grantBurstInstances(burstInstances, fingerprint, instances, expiresAt)
    } else {
      ledger.grant(fingerprint, { expiresAt, approvalId: target.approvalId })
    }
  }
}
