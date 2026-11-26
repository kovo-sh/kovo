/**
 * R3-14: Single authoritative `RetryGovernor` and typed failure codes.
 *
 * Unifies:
 *   1. Typed provider failure codes (`ProviderFailureCode`) and persisted profile failure
 *      metadata (`PersistedProviderFailureMeta`) so circuits switch on stored typed codes
 *      rather than re-classifying redacted/truncated `lastError` prose.
 *   2. Typed oracle non-confirmation codes (`OracleFailureCode`) so `retest-health.ts`
 *      switches on typed codes instead of regexes over English `verification.reason` strings,
 *      failing closed to inconclusive on unknown/unclassified codes.
 *   3. One disposer-registered `RetryGovernor` enforcing per-key caps, mid-stream tool-call
 *      idempotency, USD/request/step budgets, and real run wall-clock deadlines across all
 *      three retry paths (`provider_transient`, `provider_stall`, `step_requeue`) plus
 *      provider transport retry backoff calculation.
 */
import { isRetryableStepStatus } from '../step-status.ts'
import { registerRunDisposer } from './run-disposers.ts'

export type ProviderFailureCode =
  | 'quota'
  | 'auth'
  | 'rate_limited'
  | 'server'
  | 'stall'
  | 'stream_drop'
  | 'context_overflow'

const PROVIDER_FAILURE_CODE_SET: ReadonlySet<string> = new Set<ProviderFailureCode>([
  'quota',
  'auth',
  'rate_limited',
  'server',
  'stall',
  'stream_drop',
  'context_overflow',
])

export function isProviderFailureCode(value: unknown): value is ProviderFailureCode {
  return typeof value === 'string' && PROVIDER_FAILURE_CODE_SET.has(value)
}

export interface PersistedProviderFailureMeta {
  readonly kind: ProviderFailureCode
  readonly hard: boolean
  readonly status: number | null
  readonly recordedAt: number
}

/**
 * Typed non-confirmation / remediation failure codes emitted by proof oracles and consumed
 * by `retest-health.ts` (replacing regexes over English `verification.reason` prose).
 */
export type OracleFailureCode =
  | 'remediation_boolean_no_delta'
  | 'remediation_timing_no_separation'
  | 'remediation_mutation_idempotent'
  | 'remediation_balance_conserved'
  | 'remediation_access_denied'
  | 'composite_stage_rejected'
  | 'receipt_unbuildable'
  | 'oracle_disagreement'

const REMEDIATION_CODE_BY_RECIPE: Readonly<Record<string, ReadonlySet<OracleFailureCode>>> = {
  boolean_or_timing: new Set<OracleFailureCode>([
    'remediation_boolean_no_delta',
    'remediation_timing_no_separation',
  ]),
  persisted_mutation: new Set<OracleFailureCode>(['remediation_mutation_idempotent']),
  conserved_balance: new Set<OracleFailureCode>(['remediation_balance_conserved']),
  access_boundary: new Set<OracleFailureCode>(['remediation_access_denied']),
  disclosure: new Set<OracleFailureCode>(['remediation_access_denied']),
}

const POSITIVE_REMEDIATION_ORACLE_CODES: ReadonlySet<OracleFailureCode> = new Set<OracleFailureCode>([
  'remediation_boolean_no_delta',
  'remediation_timing_no_separation',
  'remediation_mutation_idempotent',
  'remediation_balance_conserved',
  'remediation_access_denied',
])

/**
 * True ONLY when `code` is a host-emitted positive remediation observation code.
 * Unknown, missing, or structural rejection codes ALWAYS return `false` (fail closed).
 */
export function isPositiveRemediationOracleCode(
  code: OracleFailureCode | string | null | undefined,
): code is OracleFailureCode {
  return typeof code === 'string' && POSITIVE_REMEDIATION_ORACLE_CODES.has(code as OracleFailureCode)
}

/**
 * True ONLY when `code` is a known typed remediation code valid for `(recipeId, rule)`.
 * Unknown, missing, or mismatched codes ALWAYS return `false` (fail closed to inconclusive).
 */
export function isTypedOracleRemediationCode(
  recipeId: string,
  rule: string,
  code: string | null | undefined,
): boolean {
  if (!code) return false
  if (recipeId === 'boolean_or_timing') {
    if (rule === 'boolean') return code === 'remediation_boolean_no_delta'
    if (rule === 'timing') return code === 'remediation_timing_no_separation'
    return false
  }
  const allowed = REMEDIATION_CODE_BY_RECIPE[recipeId]
  return Boolean(allowed && allowed.has(code as OracleFailureCode))
}

/**
 * Derive host-owned `OracleFailureCode` from structured `assessBooleanDifferential` evidence.
 * Returns `'remediation_boolean_no_delta'` ONLY when baseline/control/probe stability and
 * true===baseline equivalence all passed, the result was NOT echoed-only reflection, and
 * `changedPaths` is empty. Echoed-only / unstable / incomplete evidence fails closed to
 * `'oracle_disagreement'`.
 */
export function deriveBooleanRemediationCode(
  evidence: Record<string, unknown> | undefined,
): OracleFailureCode {
  if (!evidence) return 'oracle_disagreement'
  if (evidence.echoedOnly === true) return 'oracle_disagreement'
  if (Array.isArray(evidence.echoPaths) && evidence.echoPaths.length > 0) return 'oracle_disagreement'
  const stableTriangle = evidence.baselineStable === true
    && evidence.controlStable === true
    && evidence.probeStable === true
    && evidence.trueMatchesBaseline === true
  if (!stableTriangle) return 'oracle_disagreement'
  const noDelta = Array.isArray(evidence.changedPaths) && evidence.changedPaths.length === 0
  return noDelta ? 'remediation_boolean_no_delta' : 'oracle_disagreement'
}

const MUTATING_HTTP_METHODS: ReadonlySet<string> = new Set(['POST', 'PUT', 'PATCH', 'DELETE'])

function isJobStubBody(json: unknown): boolean {
  if (!json || typeof json !== 'object' || Array.isArray(json)) return false
  const rec = json as Record<string, unknown>
  const hasJobKey = typeof rec.jobId === 'string' || typeof rec.job_id === 'string' || typeof rec.taskId === 'string' || typeof rec.task_id === 'string'
  const statusStr = typeof rec.status === 'string' ? rec.status.toLowerCase() : ''
  return hasJobKey || statusStr === 'queued' || statusStr === 'pending' || statusStr === 'accepted'
}

function normalizedStepRoute(step: { route?: string | null; pathAndQuery?: string | null }): string {
  const raw = (step.route ?? step.pathAndQuery ?? '').trim()
  return raw.split(/[?#]/, 1)[0] ?? ''
}

/**
 * Derive host-owned `OracleFailureCode` from structured impact verification steps when
 * `assessImpactEvidence` did not confirm. Fails closed to `'oracle_disagreement'` unless:
 *   - Access/disclosure: a healthy 2xx control arm exists on the same route (authenticated
 *     when probes are authenticated) AND every probe was strictly denied with 403 (or 401
 *     for unauthenticated probes). HTTP 404, 5xx, 202, and anonymous-only controls NEVER
 *     emit a positive remediation code.
 *   - Persisted mutation (`mass_assignment`/`business_logic`/`csrf`): no stub/decoy/echoed/
 *     anon-control rejection flag in `evidence`, AND either all probes were strictly denied
 *     alongside a healthy 2xx control OR an acknowledged non-202, non-stub 2xx mutation is
 *     chronologically bracketed by same-route 2xx readbacks with identical JSON state.
 */
export function deriveImpactRemediationCode(
  impactClass: string,
  steps: ReadonlyArray<{
    arm: string
    method: string
    status: number | null
    route?: string | null
    pathAndQuery?: string | null
    actor: { handle?: string | null; tenant?: string | null }
    json?: unknown
  }>,
  evidence?: Record<string, unknown>,
): OracleFailureCode {
  if (
    evidence
    && (evidence.stub === true
      || evidence.decoy === true
      || evidence.echoed === true
      || evidence.echoedOnly === true
      || evidence.anonControlOnly === true)
  ) {
    return 'oracle_disagreement'
  }
  const controls = steps.filter(s => s.arm === 'control')
  const probes = steps.filter(s => s.arm === 'probe')
  if (controls.length === 0 || probes.length === 0) return 'oracle_disagreement'
  const is2xx = (status: number | null): boolean => status !== null && status >= 200 && status < 300
  const isStrictDenial = (s: { status: number | null; actor: { handle?: string | null } }): boolean =>
    s.status === 403 || (!s.actor.handle && s.status === 401)
  const anyAuthProbe = probes.some(p => Boolean(p.actor.handle && p.actor.handle.trim()))
  const healthyControls = controls.filter(c => is2xx(c.status) && (!anyAuthProbe || Boolean(c.actor.handle && c.actor.handle.trim())))
  const sharesControlRoute = (targetRoute: string): boolean =>
    !targetRoute || healthyControls.some(c => {
      const cr = normalizedStepRoute(c)
      return !cr || cr === targetRoute
    })

  if (impactClass === 'authorization' || impactClass === 'bfla' || impactClass === 'disclosure') {
    if (healthyControls.length === 0) return 'oracle_disagreement'
    const allStrictlyDenied = probes.every(p => isStrictDenial(p) && sharesControlRoute(normalizedStepRoute(p)))
    return allStrictlyDenied ? 'remediation_access_denied' : 'oracle_disagreement'
  }
  if (impactClass === 'mass_assignment' || impactClass === 'business_logic' || impactClass === 'csrf') {
    if (healthyControls.length > 0 && probes.every(p => isStrictDenial(p) && sharesControlRoute(normalizedStepRoute(p)))) {
      return 'remediation_mutation_idempotent'
    }
    if (probes.some(p => p.status === null || p.status === 202 || p.status === 404 || p.status >= 500 || p.status === 429 || p.status === 408 || isJobStubBody(p.json))) {
      return 'oracle_disagreement'
    }
    const mutProbeIdx = steps.findIndex(s =>
      s.arm === 'probe'
      && MUTATING_HTTP_METHODS.has(s.method.toUpperCase())
      && is2xx(s.status)
      && s.status !== 202
      && !isJobStubBody(s.json),
    )
    if (mutProbeIdx < 0) return 'oracle_disagreement'
    const readBefore = [...steps.slice(0, mutProbeIdx)]
      .reverse()
      .find(s => (s.method.toUpperCase() === 'GET' || s.method.toUpperCase() === 'HEAD') && is2xx(s.status) && s.json !== undefined)
    const readAfter = steps.slice(mutProbeIdx + 1)
      .find(s => (s.method.toUpperCase() === 'GET' || s.method.toUpperCase() === 'HEAD') && is2xx(s.status) && s.json !== undefined)
    if (!readBefore || !readAfter) return 'oracle_disagreement'
    const beforeRoute = normalizedStepRoute(readBefore)
    const afterRoute = normalizedStepRoute(readAfter)
    if (beforeRoute && afterRoute && beforeRoute !== afterRoute) return 'oracle_disagreement'
    if (JSON.stringify(readBefore.json) === JSON.stringify(readAfter.json)) {
      return 'remediation_mutation_idempotent'
    }
  }
  return 'oracle_disagreement'
}

export function isCompositeRejectedOracleCode(code: string | null | undefined): boolean {
  return code === 'composite_stage_rejected'
}

export function isUnbuildableReceiptOracleCode(code: string | null | undefined): boolean {
  return code === 'receipt_unbuildable'
}

// ---------------------------------------------------------------------------
// Transient profile-failure handoff cache (keyed by profileId, never runId)
// ---------------------------------------------------------------------------

const PROFILE_FAILURE_HANDOFF_TTL_MS = 30_000
const latestProfileFailureMeta = new Map<string, PersistedProviderFailureMeta>()

/**
 * Record the typed failure metadata for `profileId` at the point of production inside
 * `provider.ts` right before invoking `onProfileFailure`, so downstream persistence in
 * `model-settings.ts` receives the typed code even across legacy `(id, errString, hard)` hooks.
 */
export function noteLatestProviderFailureForProfile(
  profileId: string,
  meta: PersistedProviderFailureMeta,
): void {
  if (!profileId) return
  latestProfileFailureMeta.set(profileId, meta)
}

/** Read (without clearing) a recent typed profile failure recorded for `profileId`. */
export function peekLatestProviderFailureForProfile(
  profileId: string,
  nowMs = Date.now(),
): PersistedProviderFailureMeta | null {
  const entry = latestProfileFailureMeta.get(profileId)
  if (!entry) return null
  if (nowMs - entry.recordedAt > PROFILE_FAILURE_HANDOFF_TTL_MS) {
    latestProfileFailureMeta.delete(profileId)
    return null
  }
  return entry
}

/** Consume and clear a recent typed profile failure recorded for `profileId`. */
export function consumeLatestProviderFailureForProfile(
  profileId: string,
  nowMs = Date.now(),
): PersistedProviderFailureMeta | null {
  const entry = peekLatestProviderFailureForProfile(profileId, nowMs)
  latestProfileFailureMeta.delete(profileId)
  return entry
}

// ---------------------------------------------------------------------------
// Provider transport retry backoff & eligibility (single authoritative helper)
// ---------------------------------------------------------------------------

export function shouldRetryProviderTransport(input: {
  retryable: boolean
  hard: boolean
  isLastCandidate: boolean
  transientAttempts: number
  maxTransportRetries: number
}): boolean {
  return (
    input.retryable
    && !input.hard
    && input.isLastCandidate
    && input.transientAttempts < input.maxTransportRetries
  )
}

export function computeProviderRetryBackoffMs(input: {
  retryAfterMs?: number
  attempt: number
  baseMs: number
  maxBackoffMs?: number
  maxRetryAfterMs?: number
}): number {
  const maxRetryAfterMs = input.maxRetryAfterMs ?? 10_000
  if (input.retryAfterMs !== undefined && Number.isFinite(input.retryAfterMs) && input.retryAfterMs >= 0) {
    return Math.min(maxRetryAfterMs, Math.max(0, Math.floor(input.retryAfterMs)))
  }
  const maxBackoffMs = input.maxBackoffMs ?? 4_000
  const exp = Math.max(0, Math.floor(input.attempt) - 1)
  return Math.max(0, Math.floor(Math.min(maxBackoffMs, input.baseMs * 2 ** exp)))
}

// ---------------------------------------------------------------------------
// Unified Run RetryGovernor (provider_transient + provider_stall + step_requeue)
// ---------------------------------------------------------------------------

export type RetryPathKind = 'provider_transient' | 'provider_stall' | 'step_requeue'

export type RetryDenyReason =
  | 'not_retryable_status'
  | 'non_retryable_failure'
  | 'midstream_tool_call_executed'
  | 'already_retry_step'
  | 'retry_cap_reached'
  | 'run_not_investigating'
  | 'budget_exhausted'
  | 'request_budget_exhausted'
  | 'wall_clock_exhausted'
  | 'step_budget_exhausted'

export interface RetryEvaluationInput {
  runId: string
  path: RetryPathKind
  retryKey: string
  /** For `step_requeue`, the terminal `ChainStepStatus`; for provider paths, boolean retryability. */
  stepStatus?: string | null
  retryable?: boolean
  failureCode?: ProviderFailureCode | null
  emitted?: boolean
  toolCallsExecutedInTurn?: number
  stepSkills: readonly string[]
  stepTrialIndex?: number
  assignmentAttempt?: number
  alreadyRetriedPersisted?: boolean
  runStatus: string
  runPhase: string
  budgetExhausted: boolean
  requestBudgetExhausted: boolean
  runCreatedAt: number
  maxDurationMs: number
  nowMs?: number
  existingStepCount: number
  effectiveStepCap: number
  maxRetriesPerKey?: number
}

export interface RetryEvaluationDecision {
  readonly allowed: boolean
  readonly reason: 'allowed' | RetryDenyReason
  readonly retryKey: string
  readonly path: RetryPathKind
  readonly failureCode?: ProviderFailureCode | null
  readonly priorKeyRetries: number
  readonly runProviderRetries: number
  readonly runTotalRetries: number
  readonly wallClockExhausted: boolean
}

export interface RunRetryBudgetState {
  readonly byKey: Map<string, number>
  totalRetries: number
  providerRetries: number
  stallRetries: number
  stepRequeues: number
}

/** True when the run's finite wall-clock deadline has been reached or exceeded. */
export function isRunWallClockExhausted(
  runCreatedAt: number,
  maxDurationMs: number,
  nowMs = Date.now(),
): boolean {
  return Number.isFinite(maxDurationMs) && maxDurationMs > 0 && runCreatedAt + maxDurationMs <= nowMs
}

const DEFAULT_MAX_RETRIES_PER_KEY = 1

export class RetryGovernor {
  private readonly stateByRun = new Map<string, RunRetryBudgetState>()

  private peekState(runId: string): RunRetryBudgetState | undefined {
    return this.stateByRun.get(runId)
  }

  private ensureState(runId: string): RunRetryBudgetState {
    let state = this.stateByRun.get(runId)
    if (!state) {
      state = {
        byKey: new Map<string, number>(),
        totalRetries: 0,
        providerRetries: 0,
        stallRetries: 0,
        stepRequeues: 0,
      }
      this.stateByRun.set(runId, state)
    }
    return state
  }

  evaluate(input: RetryEvaluationInput): RetryEvaluationDecision {
    const state = this.peekState(input.runId)
    const priorKeyRetries = state?.byKey.get(input.retryKey) ?? 0
    const runProviderRetries = state?.providerRetries ?? 0
    const runTotalRetries = state?.totalRetries ?? 0
    const wallClockExhausted = isRunWallClockExhausted(input.runCreatedAt, input.maxDurationMs, input.nowMs)
    const cap = Math.max(1, Math.floor(input.maxRetriesPerKey ?? DEFAULT_MAX_RETRIES_PER_KEY))

    const deny = (reason: RetryDenyReason): RetryEvaluationDecision => ({
      allowed: false,
      reason,
      retryKey: input.retryKey,
      path: input.path,
      ...(input.failureCode !== undefined ? { failureCode: input.failureCode } : {}),
      priorKeyRetries,
      runProviderRetries,
      runTotalRetries,
      wallClockExhausted,
    })

    if (input.path === 'step_requeue') {
      const statusRetryable = input.stepStatus !== undefined
        ? isRetryableStepStatus(input.stepStatus)
        : Boolean(input.retryable)
      if (!statusRetryable) return deny('not_retryable_status')
      if ((input.stepTrialIndex ?? 0) > 0 || input.stepSkills.includes('cq5:retry:1')) {
        return deny('already_retry_step')
      }
      if (priorKeyRetries >= cap || input.alreadyRetriedPersisted) {
        return deny('retry_cap_reached')
      }
    } else {
      if (!input.retryable) return deny('non_retryable_failure')
      const toolCalls = input.toolCallsExecutedInTurn ?? 0
      if ((input.path === 'provider_stall' || input.emitted) && toolCalls > 0) {
        return deny('midstream_tool_call_executed')
      }
      if (
        input.stepSkills.includes('r213:provider_retry:1')
        || input.stepSkills.includes('cq5:retry:1')
        || (input.stepTrialIndex ?? 0) > 0
        || (input.assignmentAttempt ?? 0) >= cap
        || priorKeyRetries >= cap
        || input.alreadyRetriedPersisted
      ) {
        return deny('retry_cap_reached')
      }
    }

    if (input.runStatus !== 'running' || input.runPhase !== 'investigation') {
      return deny('run_not_investigating')
    }
    if (input.budgetExhausted) return deny('budget_exhausted')
    if (input.requestBudgetExhausted) return deny('request_budget_exhausted')
    if (wallClockExhausted) return deny('wall_clock_exhausted')

    const projectedSteps = input.path === 'step_requeue'
      ? input.existingStepCount
      : input.existingStepCount + runProviderRetries
    if (projectedSteps >= input.effectiveStepCap) {
      return deny('step_budget_exhausted')
    }

    return {
      allowed: true,
      reason: 'allowed',
      retryKey: input.retryKey,
      path: input.path,
      ...(input.failureCode !== undefined ? { failureCode: input.failureCode } : {}),
      priorKeyRetries,
      runProviderRetries,
      runTotalRetries,
      wallClockExhausted: false,
    }
  }

  recordRetry(
    runId: string,
    retryKey: string,
    path: RetryPathKind,
  ): { keyRetries: number; runProviderRetries: number; runTotalRetries: number } {
    const state = this.ensureState(runId)
    const keyRetries = (state.byKey.get(retryKey) ?? 0) + 1
    state.byKey.set(retryKey, keyRetries)
    state.totalRetries += 1
    if (path === 'step_requeue') {
      state.stepRequeues += 1
    } else {
      state.providerRetries += 1
      if (path === 'provider_stall') state.stallRetries += 1
    }
    return {
      keyRetries,
      runProviderRetries: state.providerRetries,
      runTotalRetries: state.totalRetries,
    }
  }

  clearRun(runId: string): void {
    this.stateByRun.delete(runId)
  }

  getRunStats(runId: string): { totalRetries: number; providerRetries: number; stallRetries: number; stepRequeues: number; keysTracked: number } | null {
    const state = this.stateByRun.get(runId)
    if (!state) return null
    return {
      totalRetries: state.totalRetries,
      providerRetries: state.providerRetries,
      stallRetries: state.stallRetries,
      stepRequeues: state.stepRequeues,
      keysTracked: state.byKey.size,
    }
  }
}

/** Process-wide authoritative retry governor, automatically evicted on run completion/disposal. */
export const defaultRetryGovernor = new RetryGovernor()

registerRunDisposer('retry-governor', runId => {
  defaultRetryGovernor.clearRun(runId)
})
