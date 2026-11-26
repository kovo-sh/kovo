/**
 * R2-04: Canonical shared retest-health assessor for all three retest engines
 * (floor recipe engine, declarative replay verifier, and agent-script proof engine).
 *
 * Truthfulness invariant:
 *   - `'claim_not_reproduced'` is the ONLY non-reproduction failure reason eligible to map
 *     to `'fixed'` (`'dismissed'`), and ONLY when baseline, probe-arm, and session health
 *     checks all pass.
 *   - `'receipt_unbuildable'`, `'composite_stage_rejected'`, `'session_drifted'`,
 *     `'probe_unhealthy'`, and `'baseline_unhealthy'` MUST ALWAYS map to `'inconclusive'`
 *     — NEVER `'dismissed'` or `'fixed'`.
 */
import type { FloorRecipeExecution } from './floor-recipes.ts'
import type { ScriptProofExchange } from './proof-receipt.ts'

export type RetestFailureReason =
  | 'claim_not_reproduced'
  | 'receipt_unbuildable'
  | 'composite_stage_rejected'
  | 'session_drifted'
  | 'probe_unhealthy'
  | 'baseline_unhealthy'

export type RetestHealthCode =
  | 'healthy'
  | 'recipe_error'
  | 'step_budget'
  | 'control_require_failed'
  | 'harness_require_failed'
  | 'control_status_unhealthy'
  | 'probe_status_unhealthy'
  | 'no_healthy_probe'
  | 'missing_control_arm'
  | 'access_probe_not_denied'
  | 'oracle_disagreement'
  | 'receipt_unbuildable'
  | 'composite_stage_rejected'
  | 'session_drifted'
  | 'probe_unhealthy'
  | 'baseline_unhealthy'

export interface RetestHealthAssessment {
  healthy: boolean
  code: RetestHealthCode
  failureReason: RetestFailureReason
  reason: string | null
}

export interface RetestArmObservation {
  role: string
  status: number | null
  authenticated: boolean
  /** True when the arm is a denied control (e.g. `denied_control`) expecting 403/404 (or unauth 401). */
  expectDenied?: boolean
  /** True when a generic control arm may legitimately be either a 2xx entitled baseline or a 403/404 denied peer control. */
  allowDenied?: boolean
  /** True when a redirect (3xx) status is an expected/permitted probe response. */
  allowRedirect?: boolean
  /** Optional explicit expected status declared on a declarative step. */
  expectedStatus?: number | null
  /** Optional HTTP method (used to distinguish read vs mutating probes on access classes). */
  method?: string
}

export interface RetestBaselineInput {
  setupArms?: readonly RetestArmObservation[]
  controlArms: readonly RetestArmObservation[]
  requireControlArm?: boolean
  missingControlReason?: string
  controlPassed?: boolean
  deniedRequirePassed?: boolean
  accessBoundary?: boolean
  entitledControlPresent?: boolean
  entitledControlStatus?: number | null
}

export interface RetestProbeArmsInput {
  arms: readonly RetestArmObservation[]
  requireProbeArm?: boolean
  missingProbeReason?: string
  allowRedirect?: boolean
  requireDefinitiveDenial?: boolean
  /** True for auth-boundary / CWE-287 retests where HTTP 404 indicates route drift rather than auth enforcement. */
  disallowNotFoundDenial?: boolean
  deterministicProofPassed?: boolean
  proofFailureReason?: string | null
}

export interface RetestSessionInput {
  confirmed?: boolean
  failureReason?: RetestFailureReason | null
  failureDetail?: string | null
  receiptUnbuildable?: boolean
  compositeRejectedStage?: string | null
  sessionDrifted?: boolean
  harnessFailed?: boolean
  harnessCode?: RetestHealthCode
}

export function isFixedEligibleFailureReason(reason: string | null | undefined): reason is 'claim_not_reproduced' {
  return reason === 'claim_not_reproduced'
}

function is2xxStatus(status: number | null): boolean {
  return status !== null && status >= 200 && status < 300
}

function isTransportOrServerUnhealthy(status: number | null): boolean {
  return status === null || status === 0 || status >= 500 || status === 429 || status === 408
}

function isControlStatusAllowed(arm: RetestArmObservation, deniedRequirePassed: boolean): boolean {
  const { role, status } = arm
  if (isTransportOrServerUnhealthy(status)) return false
  if (status === 401 && arm.authenticated) return false
  if (typeof arm.expectedStatus === 'number' && status !== arm.expectedStatus) return false
  if (arm.expectDenied || /denied/i.test(role)) {
    return status === 403 || status === 404 || (!arm.authenticated && status === 401) || (deniedRequirePassed && is2xxStatus(status))
  }
  if (arm.allowDenied) {
    return is2xxStatus(status) || status === 403 || status === 404 || (!arm.authenticated && status === 401)
  }
  if (role === 'same_origin_control') return is2xxStatus(status) || (status !== null && status >= 300 && status < 400)
  if (role === 'post_mutation_read') return is2xxStatus(status) || status === 404 || status === 410
  if (role === 'serial_control_1') return is2xxStatus(status) || status === 400 || status === 409 || status === 422
  if (role === 'benign_control') return is2xxStatus(status) || status === 400 || status === 404
  return is2xxStatus(status)
}

/**
 * Canonical positive-health retest assessor shared across floor recipes, declarative replays,
 * and persisted agent-script retests.
 */
export function assessRetestHealth(
  baseline: RetestBaselineInput,
  probeArms: RetestProbeArmsInput,
  session: RetestSessionInput,
): RetestHealthAssessment {
  if (session.confirmed) {
    return { healthy: true, code: 'healthy', failureReason: 'claim_not_reproduced', reason: null }
  }

  // 1. Typed session / receipt / composite disqualifiers — ALWAYS inconclusive, NEVER fixed.
  if (session.receiptUnbuildable || session.failureReason === 'receipt_unbuildable') {
    return {
      healthy: false,
      code: 'receipt_unbuildable',
      failureReason: 'receipt_unbuildable',
      reason: session.failureDetail || 'ProofReceipt could not be built on retest; cannot mark finding fixed.',
    }
  }
  if (session.compositeRejectedStage || session.failureReason === 'composite_stage_rejected') {
    return {
      healthy: false,
      code: 'composite_stage_rejected',
      failureReason: 'composite_stage_rejected',
      reason: session.failureDetail || `CompositeProofReceipt rejected at stage '${session.compositeRejectedStage ?? 'unknown'}'; cannot mark finding fixed.`,
    }
  }
  if (session.sessionDrifted || session.failureReason === 'session_drifted') {
    return {
      healthy: false,
      code: 'session_drifted',
      failureReason: 'session_drifted',
      reason: session.failureDetail || 'Retest session or credentials drifted; cannot mark finding fixed.',
    }
  }
  if (session.harnessFailed) {
    return {
      healthy: false,
      code: session.harnessCode ?? 'recipe_error',
      failureReason: 'baseline_unhealthy',
      reason: session.failureDetail || 'Retest harness or runtime failed; cannot mark finding fixed.',
    }
  }
  if (session.failureReason === 'baseline_unhealthy') {
    return {
      healthy: false,
      code: 'baseline_unhealthy',
      failureReason: 'baseline_unhealthy',
      reason: session.failureDetail || 'Retest baseline was unhealthy; cannot mark finding fixed.',
    }
  }
  if (session.failureReason === 'probe_unhealthy') {
    return {
      healthy: false,
      code: 'probe_unhealthy',
      failureReason: 'probe_unhealthy',
      reason: session.failureDetail || 'Retest probe arm was unhealthy; cannot mark finding fixed.',
    }
  }

  // 2. Setup arms health check.
  for (const step of baseline.setupArms ?? []) {
    if (isTransportOrServerUnhealthy(step.status)) {
      return {
        healthy: false,
        code: 'control_status_unhealthy',
        failureReason: 'baseline_unhealthy',
        reason: `Setup arm "${step.role}" returned unhealthy HTTP ${step.status ?? 'none'}.`,
      }
    }
    if (step.status === 401 && step.authenticated) {
      return {
        healthy: false,
        code: 'session_drifted',
        failureReason: 'session_drifted',
        reason: `Setup arm "${step.role}" returned HTTP 401; test credential drifted or expired.`,
      }
    }
  }

  // 3. Baseline / control arms presence and health check.
  if ((baseline.requireControlArm ?? true) && baseline.controlArms.length === 0) {
    return {
      healthy: false,
      code: 'missing_control_arm',
      failureReason: 'baseline_unhealthy',
      reason: baseline.missingControlReason ?? 'Retest executed no control arm to prove baseline health.',
    }
  }

  const deniedRequirePassed = baseline.deniedRequirePassed ?? true
  for (const step of baseline.controlArms) {
    if (step.status === 401 && step.authenticated) {
      return {
        healthy: false,
        code: 'session_drifted',
        failureReason: 'session_drifted',
        reason: `Authenticated control arm "${step.role}" returned HTTP 401; session drifted or expired.`,
      }
    }
    if (!isControlStatusAllowed(step, deniedRequirePassed)) {
      return {
        healthy: false,
        code: 'control_status_unhealthy',
        failureReason: 'baseline_unhealthy',
        reason: `Control arm "${step.role}" returned unhealthy HTTP ${step.status ?? 'none'}; baseline health was not established.`,
      }
    }
  }

  // 4. Probe arms presence and health check.
  if ((probeArms.requireProbeArm ?? true) && probeArms.arms.length === 0) {
    return {
      healthy: false,
      code: 'no_healthy_probe',
      failureReason: 'probe_unhealthy',
      reason: probeArms.missingProbeReason ?? 'Retest executed no probe arm during retest.',
    }
  }

  for (const step of probeArms.arms) {
    if (step.status === null || step.status === 0) {
      return {
        healthy: false,
        code: 'probe_status_unhealthy',
        failureReason: 'probe_unhealthy',
        reason: `Probe arm "${step.role}" recorded no HTTP status (network/transport failure).`,
      }
    }
    if (step.status >= 500) {
      return {
        healthy: false,
        code: 'probe_status_unhealthy',
        failureReason: 'probe_unhealthy',
        reason: `Probe arm "${step.role}" returned HTTP ${step.status}; a server error is not evidence of remediation.`,
      }
    }
    if (step.status === 429 || step.status === 408) {
      return {
        healthy: false,
        code: 'probe_status_unhealthy',
        failureReason: 'probe_unhealthy',
        reason: `Probe arm "${step.role}" was throttled/timed out with HTTP ${step.status}; not evidence of remediation.`,
      }
    }
    if (step.status >= 300 && step.status < 400 && !(probeArms.allowRedirect || step.allowRedirect)) {
      return {
        healthy: false,
        code: 'probe_status_unhealthy',
        failureReason: 'probe_unhealthy',
        reason: `Probe arm "${step.role}" returned unexpected HTTP ${step.status} redirect; not a definitive fix.`,
      }
    }
    if (step.status === 401 && step.authenticated) {
      return {
        healthy: false,
        code: 'session_drifted',
        failureReason: 'session_drifted',
        reason: `Authenticated probe arm "${step.role}" returned HTTP 401; session expired rather than authorization enforced.`,
      }
    }
  }

  if (baseline.controlPassed === false) {
    return {
      healthy: false,
      code: 'control_require_failed',
      failureReason: 'baseline_unhealthy',
      reason: session.failureDetail || 'Control baseline check failed during retest.',
    }
  }

  if (probeArms.deterministicProofPassed === false) {
    return {
      healthy: false,
      code: 'probe_unhealthy',
      failureReason: 'probe_unhealthy',
      reason: probeArms.proofFailureReason || 'Deterministic proof-of-execution check could not confirm remediation on retest.',
    }
  }

  // 5. Access / disclosure boundary checks.
  if (baseline.accessBoundary) {
    if (baseline.entitledControlPresent === false || (baseline.entitledControlStatus !== undefined && !is2xxStatus(baseline.entitledControlStatus))) {
      return {
        healthy: false,
        code: 'control_status_unhealthy',
        failureReason: 'baseline_unhealthy',
        reason: 'Entitled control arm was not served HTTP 2xx.',
      }
    }
  }
  if (probeArms.requireDefinitiveDenial) {
    const allow404 = !probeArms.disallowNotFoundDenial
    for (const step of probeArms.arms) {
      const definitivelyDenied = step.authenticated
        ? (step.status === 403 || (allow404 && step.status === 404))
        : (step.status === 401 || step.status === 403 || (allow404 && step.status === 404))
      if (!definitivelyDenied) {
        return {
          healthy: false,
          code: 'access_probe_not_denied',
          failureReason: 'probe_unhealthy',
          reason: `Probe arm "${step.role}" returned HTTP ${step.status ?? 'none'} instead of a definitive denial; cannot mark fixed.`,
        }
      }
    }
  }

  return { healthy: true, code: 'healthy', failureReason: 'claim_not_reproduced', reason: null }
}

/**
 * R2-H-15 / H-19 / R2-04: Floor-recipe adapter over canonical `assessRetestHealth`.
 *
 * A non-confirming retest may transition to `fixed` ONLY when:
 *   1. No `recipe_error`, `step_budget`, control-side `require`, harness-side `require`,
 *      missing/unbuildable receipt, or rejected composite stage failed;
 *   2. Every HTTP recipe executed at least one healthy control arm matching its expected baseline
 *      status class (no-control recipes like `race_burst` and `oob_callback` NEVER report `fixed`);
 *   3. Every probe arm executed cleanly with a definitive status (never null/0, 5xx, 429, 408,
 *      unexpected 3xx, or authenticated 401);
 *   4. Access/disclosure recipes observe the entitled baseline served AND the probe definitively
 *      denied (a 2xx probe is NEVER `fixed`);
 *   5. No `oracle_disagreement` occurred (all recipe preconditions passed yet the receipt gate
 *      rejected for a non-remediation reason).
 */
export function classifyRetestHealth(execution: FloorRecipeExecution): RetestHealthAssessment {
  if (execution.result.confirmed) {
    return { healthy: true, code: 'healthy', failureReason: 'claim_not_reproduced', reason: null }
  }
  const failure = execution.failure
  const recipeId = execution.result.recipeId as string
  const missingRoles = failure?.missingRoles ?? []
  const reqFailures = failure?.requireFailures ?? []

  if (failure?.code === 'recipe_error') {
    const isUnbuildable = !execution.receipt
      || (recipeId !== 'browser_sink' && (execution.receipt.exchangeIds?.length ?? 0) === 0 && execution.result.steps.length > 0)
      || /receipt.*(?:could not|unbuildable|missing)/i.test(failure.message)
    if (isUnbuildable) {
      return assessRetestHealth({ controlArms: [] }, { arms: [] }, {
        receiptUnbuildable: true,
        failureDetail: failure.message,
      })
    }
    return assessRetestHealth({ controlArms: [] }, { arms: [] }, {
      harnessFailed: true,
      harnessCode: 'recipe_error',
      failureDetail: failure.message,
    })
  }
  if (failure?.code === 'step_budget_exceeded' || missingRoles.includes('step_budget')) {
    return assessRetestHealth({ controlArms: [] }, { arms: [] }, {
      harnessFailed: true,
      harnessCode: 'step_budget',
      failureDetail: failure?.message ?? 'Recipe exceeded the step budget during retest.',
    })
  }
  const controlReqFail = reqFailures.find(item => item.side === 'control')
  if (controlReqFail) {
    return assessRetestHealth({ controlArms: [] }, { arms: [] }, {
      harnessFailed: true,
      harnessCode: 'control_require_failed',
      failureDetail: controlReqFail.message,
    })
  }
  const harnessReqFail = reqFailures.find(item => item.side === 'harness')
  if (harnessReqFail) {
    return assessRetestHealth({ controlArms: [] }, { arms: [] }, {
      harnessFailed: true,
      harnessCode: 'harness_require_failed',
      failureDetail: harnessReqFail.message,
    })
  }
  if (missingRoles.includes('browser_trace') || missingRoles.includes('browser_control')) {
    return assessRetestHealth({ controlArms: [] }, { arms: [] }, {
      harnessFailed: true,
      harnessCode: 'harness_require_failed',
      failureDetail: failure?.message ?? 'The retest produced no host-recorded browser trace.',
    })
  }

  if (!execution.receipt || (recipeId !== 'browser_sink' && (execution.receipt.exchangeIds?.length ?? 0) === 0 && execution.result.steps.length > 0)) {
    return assessRetestHealth({ controlArms: [] }, { arms: [] }, {
      receiptUnbuildable: true,
      failureDetail: failure?.message ?? `Recipe "${recipeId}" produced no buildable ProofReceipt on retest.`,
    })
  }

  if (recipeId === 'browser_sink') {
    const traces = execution.result.transcript.browserTraces ?? []
    if (traces.length === 0) {
      return assessRetestHealth({ controlArms: [] }, { arms: [] }, {
        harnessFailed: true,
        harnessCode: 'harness_require_failed',
        failureDetail: 'The browser_sink retest recorded no host browser trace.',
      })
    }
    if (failure?.code === 'receipt_rejected') {
      return {
        healthy: false,
        code: 'oracle_disagreement',
        failureReason: 'probe_unhealthy',
        reason: `Oracle disagreement on browser_sink retest: ${failure.message}`,
      }
    }
    return { healthy: true, code: 'healthy', failureReason: 'claim_not_reproduced', reason: null }
  }

  const steps = execution.result.steps
  const entryById = new Map((execution.result.transcript.entries ?? []).map(entry => [entry.exchangeId, entry]))
  const isAuthenticatedStep = (exchangeId: string): boolean => Boolean(entryById.get(exchangeId)?.step.actor.handle)

  const toArm = (step: FloorRecipeExecution['result']['steps'][number]): RetestArmObservation => ({
    role: step.role,
    status: step.status,
    authenticated: isAuthenticatedStep(step.exchangeId),
    method: step.method,
  })

  const setupArms = steps.filter(step => step.arm === 'setup').map(toArm)
  const controlArms = steps.filter(step => step.arm === 'control').map(toArm)
  const probeArmsList = steps.filter(step => step.arm === 'probe').map(toArm)
  const deniedRequirePassed = !reqFailures.some(item => item.role === 'denied_control')
  const isAccessOrDisclosure = recipeId === 'access_boundary' || recipeId === 'disclosure'
  const entitled = controlArms.find(step => step.role === 'entitled_read')

  const baseHealth = assessRetestHealth(
    {
      setupArms,
      controlArms,
      requireControlArm: true,
      missingControlReason: `Recipe "${recipeId}" executed no control arm to prove baseline health on retest.`,
      deniedRequirePassed,
      accessBoundary: isAccessOrDisclosure,
      ...(isAccessOrDisclosure ? {
        entitledControlPresent: Boolean(entitled),
        entitledControlStatus: entitled?.status ?? null,
      } : {}),
    },
    {
      arms: probeArmsList,
      requireProbeArm: true,
      missingProbeReason: `Recipe "${recipeId}" executed no probe arm during retest.`,
      allowRedirect: recipeId === 'redirect',
      requireDefinitiveDenial: isAccessOrDisclosure,
    },
    {
      confirmed: false,
      failureReason: 'claim_not_reproduced',
    },
  )
  if (!baseHealth.healthy) return baseHealth

  // Oracle-disagreement guard: when every recipe precondition passed yet `verifyReceipt` rejected,
  // allow `fixed` ONLY for explicit remediation-observed verification reasons.
  if (failure?.code === 'receipt_rejected') {
    const reason = execution.result.verification.reason
    const rule = execution.result.verification.rule
    if (/composite.*stage|failedStage|edge_binding|dag_topology|attacker_provenance|transcript_integrity/i.test(reason)) {
      return assessRetestHealth({ controlArms }, { arms: probeArmsList }, {
        compositeRejectedStage: 'composite_receipt',
        failureDetail: `Composite stage rejected on ${recipeId} retest: ${reason}`,
      })
    }
    if (recipeId === 'boolean_or_timing') {
      if (rule === 'boolean' && /no structural response change|identical after token stripping|only difference was the injected predicate|rotating nonce/i.test(reason)) {
        return { healthy: true, code: 'healthy', failureReason: 'claim_not_reproduced', reason: null }
      }
      if (rule === 'timing' && /not distinguishable|stable separation|separation|delay/i.test(reason) && !/wall-clock duration|control and a probe/i.test(reason)) {
        return { healthy: true, code: 'healthy', failureReason: 'claim_not_reproduced', reason: null }
      }
      return { healthy: false, code: 'oracle_disagreement', failureReason: 'probe_unhealthy', reason: `Oracle disagreement on boolean_or_timing retest: ${reason}` }
    }
    if (recipeId === 'persisted_mutation') {
      if (/identical to the baseline|no persisted|state echo|idempotent|not a protected field|not impact/i.test(reason)) {
        return { healthy: true, code: 'healthy', failureReason: 'claim_not_reproduced', reason: null }
      }
      return { healthy: false, code: 'oracle_disagreement', failureReason: 'probe_unhealthy', reason: `Oracle disagreement on persisted_mutation retest: ${reason}` }
    }
    if (recipeId === 'conserved_balance') {
      if (/conserved|conservation|no oversell|within balance|no under-debit/i.test(reason) && !/readback|serial control|concurrent mutation/i.test(reason)) {
        return { healthy: true, code: 'healthy', failureReason: 'claim_not_reproduced', reason: null }
      }
      return { healthy: false, code: 'oracle_disagreement', failureReason: 'probe_unhealthy', reason: `Oracle disagreement on conserved_balance retest: ${reason}` }
    }
    return { healthy: false, code: 'oracle_disagreement', failureReason: 'probe_unhealthy', reason: `Oracle disagreement on ${recipeId} retest: ${reason}` }
  }

  return baseHealth
}

const ACCESS_READ_CLASS_RE = /\b(?:bola|idor|bfla|authz|authorization|access|disclosure|cross[_-]?tenant[_-]?read)\b/i
const AUTH_BOUNDARY_CLASS_RE = /\b(?:auth[_-]?bypass|cwe-287|cwe-306)\b/i

function isReadOnlyMethod(method: string | undefined): boolean {
  const m = (method ?? 'GET').toUpperCase()
  return m === 'GET' || m === 'HEAD'
}

/**
 * Declarative replay adapter over canonical `assessRetestHealth`.
 */
export function assessDeclarativeRetestHealth(
  specLike: unknown,
  replay: {
    verdict: string
    outcome: { confirmed: boolean; controlPassed: boolean; reason?: string }
    evidencePayload: Record<string, unknown>
  },
  opts?: {
    deterministicProofPassed?: boolean
    proofFailureReason?: string | null
    receiptBuildable?: boolean
    compositeRejectedStage?: string | null
  },
): RetestHealthAssessment {
  if (replay.verdict === 'confirmed' || replay.verdict === 'static_verified') {
    return { healthy: true, code: 'healthy', failureReason: 'claim_not_reproduced', reason: null }
  }

  const specRec = specLike && typeof specLike === 'object' && !Array.isArray(specLike)
    ? specLike as Record<string, unknown>
    : {}
  const specKind = typeof specRec.kind === 'string' ? specRec.kind : ''
  const specSteps = Array.isArray(specRec.steps)
    ? specRec.steps.filter((s): s is Record<string, unknown> => Boolean(s) && typeof s === 'object')
    : []
  const stepsOut = (replay.evidencePayload.steps && typeof replay.evidencePayload.steps === 'object' && !Array.isArray(replay.evidencePayload.steps))
    ? replay.evidencePayload.steps as Record<string, Record<string, unknown>>
    : {}

  const compVer = replay.evidencePayload.compositeVerification as { confirmed?: boolean; failedStage?: string; reason?: string } | undefined
  const compositeRejectedStage = opts?.compositeRejectedStage
    ?? (compVer && compVer.confirmed === false ? (compVer.failedStage || 'unknown') : null)

  const setupArms: RetestArmObservation[] = []
  const controlArms: RetestArmObservation[] = []
  const probeArmsList: RetestArmObservation[] = []

  const specStepById = new Map<string, Record<string, unknown>>()
  for (const s of specSteps) {
    if (typeof s.id === 'string') specStepById.set(s.id, s)
  }

  for (const [id, rawEntry] of Object.entries(stepsOut)) {
    if (!rawEntry || typeof rawEntry !== 'object') continue
    const specStep = specStepById.get(id)
    const reqObj = (specStep?.request && typeof specStep.request === 'object') ? specStep.request as Record<string, unknown> : undefined
    const role = typeof rawEntry.role === 'string'
      ? rawEntry.role
      : typeof specStep?.role === 'string'
        ? specStep.role
        : 'probe'
    const status = typeof rawEntry.status === 'number' ? rawEntry.status : null
    const authenticated = Boolean(
      (typeof rawEntry.personaHandle === 'string' && rawEntry.personaHandle.trim())
      || (typeof reqObj?.persona === 'string' && reqObj.persona.trim()),
    )
    const method = typeof reqObj?.method === 'string' ? reqObj.method : undefined
    const expectedStatus = typeof specStep?.expectedStatus === 'number' ? specStep.expectedStatus : null
    const arm: RetestArmObservation = {
      role: id || role,
      status,
      authenticated,
      allowDenied: role === 'control',
      ...(expectedStatus !== null ? { expectedStatus } : {}),
      ...(method ? { method } : {}),
    }
    if (role === 'setup') setupArms.push(arm)
    else if (role === 'control') controlArms.push(arm)
    else if (role === 'probe') probeArmsList.push(arm)
  }

  const boundaryGate = replay.evidencePayload.boundaryGate as { required?: boolean; boundaryClass?: string } | undefined
  const labelText = [specRec.category, specRec.cwe, specRec.title].filter(x => typeof x === 'string').join(' ')
  const isAuthBoundary = (boundaryGate?.required === true && boundaryGate.boundaryClass === 'auth')
    || AUTH_BOUNDARY_CLASS_RE.test(labelText)
  const isAccessRead = ACCESS_READ_CLASS_RE.test(labelText)
    && probeArmsList.length > 0
    && probeArmsList.every(arm => isReadOnlyMethod(arm.method))

  return assessRetestHealth(
    {
      setupArms,
      controlArms,
      requireControlArm: specKind === 'http_chain' || controlArms.length > 0 || probeArmsList.length > 0,
      missingControlReason: 'Declarative retest executed no control arm to prove baseline health.',
      controlPassed: replay.outcome.controlPassed,
      accessBoundary: isAccessRead && controlArms.some(arm => is2xxStatus(arm.status)),
    },
    {
      arms: probeArmsList,
      requireProbeArm: specKind === 'http_chain' || probeArmsList.length > 0,
      missingProbeReason: 'Declarative retest executed no probe arm.',
      allowRedirect: /redirect/i.test(labelText),
      requireDefinitiveDenial: isAccessRead || (isAuthBoundary && probeArmsList.length > 0),
      disallowNotFoundDenial: isAuthBoundary,
      ...(opts?.deterministicProofPassed !== undefined ? { deterministicProofPassed: opts.deterministicProofPassed } : {}),
      ...(opts?.proofFailureReason !== undefined ? { proofFailureReason: opts.proofFailureReason } : {}),
    },
    {
      confirmed: false,
      failureReason: opts?.receiptBuildable === false
        ? 'receipt_unbuildable'
        : compositeRejectedStage
          ? 'composite_stage_rejected'
          : 'claim_not_reproduced',
      failureDetail: compVer?.reason ?? opts?.proofFailureReason ?? replay.outcome.reason ?? null,
      receiptUnbuildable: opts?.receiptBuildable === false,
      compositeRejectedStage,
    },
  )
}

/**
 * Build canonical `(baseline, probeArms, session)` inputs for `assessRetestHealth` from an
 * agent-script retest run.
 */
export function buildAgentScriptRetestInputs(input: {
  confirmed: boolean
  verdictReason: string
  verdictDetail?: string | null
  attempts: readonly { exitCode: number; signaturesValid: boolean; nonceMismatch: boolean; oraclePassed: boolean }[]
  exchanges: readonly ScriptProofExchange[]
  compositeRejectedStage?: string | null
  vulnClass?: string | null
}): { baseline: RetestBaselineInput; probeArms: RetestProbeArmsInput; session: RetestSessionInput } {
  const setupArms: RetestArmObservation[] = []
  const controlArms: RetestArmObservation[] = []
  const probeArmsList: RetestArmObservation[] = []

  for (const ex of input.exchanges) {
    const role = ex.sessionRole ?? null
    const arm: RetestArmObservation = {
      role: role ?? ex.exchangeId,
      status: ex.status ?? null,
      authenticated: Boolean(ex.personaHandle && ex.personaHandle.trim()),
      allowDenied: role === 'control',
      method: ex.method,
    }
    if (role === 'setup') setupArms.push(arm)
    else if (role === 'control') controlArms.push(arm)
    else if (role === 'probe') probeArmsList.push(arm)
  }

  const sessionIntegrityBroken = input.attempts.length === 0
    || input.attempts.some(att => att.nonceMismatch || !att.signaturesValid)
  const executionBroken = input.attempts.some(att => att.exitCode !== 0)

  const receiptUnbuildable = input.verdictReason === 'receipt_unbuildable'
  const compositeRejectedStage = input.verdictReason === 'composite_stage_rejected'
    ? (input.compositeRejectedStage ?? 'unknown')
    : input.compositeRejectedStage ?? null
  const sessionDrifted = input.verdictReason === 'session_drifted'
    || input.verdictReason === 'nonce_mismatch'
    || input.verdictReason === 'nonce_reuse'
    || sessionIntegrityBroken

  const nonRemediationReason = !receiptUnbuildable
    && !compositeRejectedStage
    && !sessionDrifted
    && input.verdictReason !== 'claim_not_reproduced'

  const isAuthBoundary = Boolean(input.vulnClass && AUTH_BOUNDARY_CLASS_RE.test(input.vulnClass))
  const isAccessRead = Boolean(input.vulnClass && ACCESS_READ_CLASS_RE.test(input.vulnClass))
    && probeArmsList.length > 0
    && probeArmsList.every(arm => isReadOnlyMethod(arm.method))

  return {
    baseline: {
      setupArms,
      controlArms,
      requireControlArm: true,
      missingControlReason: 'Agent-script retest executed no control arm to prove baseline health.',
    },
    probeArms: {
      arms: probeArmsList,
      requireProbeArm: true,
      missingProbeReason: 'Agent-script retest executed no probe arm.',
      allowRedirect: Boolean(input.vulnClass && /redirect/i.test(input.vulnClass)),
      requireDefinitiveDenial: isAccessRead || (isAuthBoundary && probeArmsList.length > 0),
      disallowNotFoundDenial: isAuthBoundary,
    },
    session: {
      confirmed: input.confirmed,
      failureReason: receiptUnbuildable
        ? 'receipt_unbuildable'
        : compositeRejectedStage
          ? 'composite_stage_rejected'
          : sessionDrifted
            ? 'session_drifted'
            : nonRemediationReason
              ? 'baseline_unhealthy'
              : 'claim_not_reproduced',
      failureDetail: input.verdictDetail ?? null,
      receiptUnbuildable,
      compositeRejectedStage,
      sessionDrifted,
      harnessFailed: executionBroken || nonRemediationReason,
      harnessCode: 'recipe_error',
    },
  }
}
