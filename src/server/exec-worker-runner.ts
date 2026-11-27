import { randomUUID } from 'node:crypto'
import { mkdirSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { and, eq } from 'drizzle-orm'
import { maxInlineVerifyRetries, type CheckCoverage, type CodeLocation } from '../domain.ts'
import { declarativeReplaySpecSchema, replaySpecOrigins, type DeclarativeReplaySpec } from '../replay-spec.ts'
import { ActiveClock, getRunClock, registerAssignmentClock, type DeadlineTimerHandle } from './active-clock.ts'
import { createCheckpointOnlySessionGuard } from './agent-prompts.ts'
import {
  KOVO_VERIFY_TS_ONLY_ERROR, createBoardTools, filterHandlersForSpecialist, injectBoardTurnInstructions,
  listSkills, loadSkill, parseNegativeEdgeGapReason, resolveSpecialistProfile, routeStepToSpecialist,
  runAgentSession, selectPreInjectionSkills, summarizeKovoVerifyOutcome, workerInvestigationPrompt,
  type AgentSessionHandle, type GapValidationEvent, type KovoVerifyArgs, type KovoVerifyRuntime,
  type ProofObligationEvent, type WorkerToolHandlers,
} from './agent-session.ts'
import { detectKovoVerifyScriptAliases, recordKovoVerifyAliasUsage, type KovoVerifyAliasKey } from './verify-runner.ts'
import type { AgentTrace } from './agent-trace.ts'
import { BrokerDenied, type BrokerExchangeResult, type Grant } from './broker.ts'
import { DERIVED_CAPABILITY_HANDLE_RE, type NegativeEdge } from './capability-ledger.ts'
import type { CompositeProofReceipt, CompositeReceiptVerification, HostSignedTranscript } from './composite-receipt.ts'
import { extractCoverageEvidenceMetadata } from './coverage-category.ts'
import { queryCves } from './cve-broker.ts'
import { DerivedCapabilityVault, vaultScrubDescriptors } from './derived-custody.ts'
import { createEgressSanitizer } from './egress-sanitizer.ts'
import { createProviderLlmCall, evaluateSubmissionDedupe, extractSpecDedupeFields, normalizeEndpointTemplate } from './dedupe.ts'
import type { ExecBoardManager } from './exec-board.ts'
import {
  ProviderNoTokenWatchdog, createAutoDisposedRunState, type RunOrchestrationStateStore,
  buildBolaTestQueue, classifyWorkerErrorToStepStatus, collectAllPages, computeDynamicStepBudget,
  evaluateTransientProviderRetry, extractAssignedTargetRoutes, hardChainStepsCeiling,
  isMultiHopChainStep, isRetryableChainStepStatus, mapSessionStatusToStepStatus,
  percentile, providerStallAbortMs, reinvestigationKey, resolveWorkerSettlementMs,
  selectAssignmentBolaQueueItems, shouldRetryStalledAssignment, type AssignmentBudget,
} from './exec-dispatch.ts'
import {
  ExecServiceModule, buildChainFindingBase, buildExistingFindingRefs, createExchangeRecorder,
  findFindingRow, llmRunHooks, publicPersonasFromGrant, retryLimitExceededFeedback,
  type ExecActiveJob, type ExecCoreServices,
} from './exec-exchange.ts'
import { DETERMINISTIC_PARAM_HINT_RE } from './exec-floor-lane.ts'
import { isPersistentWorkflowContinuationStep, sortPersonasLowPrivFirst, type ExecReconPlanner } from './exec-recon-planner.ts'
import { FindingsRepository } from './store-findings.ts'
import {
  STATIC_AST_LIVE_TARGET_REJECT_MESSAGE, guardConfirmedFindingMutation, isLiveRuntimeVerificationRun,
  type ExecVerifier, type InlineDeferredFindingCandidate,
} from './exec-verify.ts'
import { resolveProfilePoolForRole, type ResolvedModelProfile } from './model-settings.ts'
import type { PersonaAuthManager, PersonaSessionClone } from './persona-auth.ts'
import { crawlStateGraph } from './phase0-recon.ts'
import { resolveProviderRuntimePolicy } from './provider-runtime-policy.ts'
import { createProviderStreamTelemetry, resolveProfileNoTokenWatchdogMs } from './provider-stream.ts'
import { BudgetExceededError, ProviderFailureError, QuotaExhaustedError, classifyProviderFailure, evaluateRoleProviderCircuit } from './provider.ts'
import { redact, type NamedSecret } from './redact.ts'
import { defaultRetryGovernor, peekLatestProviderFailureForProfile } from './retry-governor.ts'
import { sanitizeWorkerFactData } from './run-actor.ts'
import { resolveRunSafetyBudgets } from './run-safety-budgets.ts'
import { brokerExchanges, type ChainStepTerminalStatus } from './schema.ts'
import type { Assignment, BoardMessageRow, ChainStep, Run } from './store.ts'
import { probeDifferential, probeSurface } from './surface-engine.ts'
import { isDecoupledOrPtcExploiterEnabled, prepareExploiterSession } from './ptc-exploiter.ts'
import type { RecordedRequestExchange } from './trace-proof-compiler.ts'
import { recordProviderUsageTelemetry } from './token-telemetry.ts'
import { buildWarmPoolPolicy, type WorkerBackend } from './worker-backend.ts'

const CORPUS_SENSITIVE_HEADER_RE = /^(?:authorization|proxy-authorization|cookie|set-cookie|x-api-key|api-key|x-auth-token|x-access-token|x-csrf-token|x-xsrf-token|x-session-token|x-secret|x-webhook-secret)$/i
const CORPUS_SECRET_VALUE_RE = /-----BEGIN [^-\n]*PRIVATE KEY-----[\s\S]*?-----END [^-\n]*PRIVATE KEY-----|\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9._-]+|\b(?:Bearer|Basic)\s+[A-Za-z0-9._~+/=-]{8,}|\b(?:sk-[A-Za-z0-9_-]{12,}|gh[pousr]_[A-Za-z0-9]{16,})\b/gi
const CORPUS_QUERY_SECRET_RE = /([?&](?:token|access_token|refresh_token|api_key|apikey|secret|password|passwd|session_id)=)[^&#\s]+/gi

function scrubCorpusString(input: string, secrets: readonly NamedSecret[]): string {
  let out = input
  for (const s of secrets) {
    if (s.value && s.value.length >= 4 && out.includes(s.value)) out = out.split(s.value).join('<scrubbed>')
  }
  return redact(out.replace(CORPUS_SECRET_VALUE_RE, '<scrubbed>').replace(CORPUS_QUERY_SECRET_RE, '$1<scrubbed>'))
    .replace(/\[redacted(?::[^\]]*)?\]/gi, '<scrubbed>')
}

function scrubCorpusValue(value: unknown, secrets: readonly NamedSecret[], depth = 0): unknown {
  if (depth > 8 || value == null) return value
  if (typeof value === 'string') return scrubCorpusString(value, secrets)
  if (Array.isArray(value)) return value.map(item => scrubCorpusValue(item, secrets, depth + 1))
  if (typeof value !== 'object') return value
  const out: Record<string, unknown> = {}
  for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
    if (k === 'hostSignature') continue
    if ((k === 'requestHeaders' || k === 'responseHeaders') && v && typeof v === 'object' && !Array.isArray(v)) {
      const cleanHdrs: Record<string, string> = {}
      for (const [hk, hv] of Object.entries(v as Record<string, unknown>)) {
        if (!CORPUS_SENSITIVE_HEADER_RE.test(hk) && typeof hv === 'string') cleanHdrs[hk] = scrubCorpusString(hv, secrets)
      }
      out[k] = cleanHdrs
    } else {
      out[k] = scrubCorpusValue(v, secrets, depth + 1)
    }
  }
  return out
}

/** Opt-in (`KOVO_CAPTURE_VERIFY_CORPUS_DIR`) sanitized CompositeProofReceipt + HostSignedTranscript corpus writer. */
export function captureVerifyCorpusRecord(params: {
  captureDir?: string
  app: string
  runId: string
  assignmentId?: string
  receipt: CompositeProofReceipt
  verification: CompositeReceiptVerification
  hostTranscript: HostSignedTranscript
  personaRoleLabels?: Record<string, string>
  secrets?: readonly NamedSecret[]
  onError?: (err: unknown) => void
}): string | null {
  const dir = (params.captureDir ?? process.env.KOVO_CAPTURE_VERIFY_CORPUS_DIR ?? '').trim()
  if (!dir) return null
  try {
    mkdirSync(dir, { recursive: true, mode: 0o700 })
    const secrets = params.secrets ?? [], safeRun = params.runId.replace(/[^A-Za-z0-9._-]/g, '_').slice(0, 64) || 'run'
    const filePath = join(dir, `${safeRun}_${Date.now()}_${randomUUID().slice(0, 8)}.json`)
    const payload = {
      schemaVersion: 1, capturedAt: new Date().toISOString(), app: params.app.trim() || 'unknown', runId: params.runId,
      ...(params.assignmentId ? { assignmentId: params.assignmentId } : {}),
      receipt: scrubCorpusValue(params.receipt, secrets), transcript: scrubCorpusValue(params.hostTranscript, secrets),
      ...(params.personaRoleLabels && Object.keys(params.personaRoleLabels).length > 0 ? { verifyOptions: { personaRoleLabels: params.personaRoleLabels } } : {}),
      verdict: {
        confirmed: params.verification.confirmed, failedStage: params.verification.failedStage ?? null, rejectedBy: params.verification.rejectedBy ?? null,
        reason: scrubCorpusString(params.verification.reason, secrets).slice(0, 400),
        terminalOracleFamily: params.verification.terminalOracleFamily ?? null, terminalEndpoint: params.verification.terminalEndpoint ?? null,
      },
    }
    writeFileSync(filePath, `${JSON.stringify(payload, null, 2)}\n`, { encoding: 'utf8', mode: 0o600 })
    return filePath
  } catch (err) { params.onError?.(err); return null }
}

type Active = ExecActiveJob

/** Output-size threshold above which `derive_evidence` persists a SQLite `artifacts` row (matches 12 KiB spill threshold). */
export const DERIVE_EVIDENCE_PERSIST_THRESHOLD_BYTES = 12 * 1024

/** Bounded verify-grace bounds applied when an active proof call is running at `wallClockMs`. */
export const DEFAULT_VERIFY_GRACE_MIN_MS = 20_000
export const DEFAULT_VERIFY_GRACE_MAX_MS = 45_000
/** Expanded bounded verify-grace window (+60s) when a worker already entered `kovo_verify` or holds a live sealed capability / active `hop_checkpoint`. */
export const EXPANDED_VERIFY_GRACE_MS = 60_000
/** Bounded settlement-stream grace cap when a worker already entered settlement and is mid-generation at `wallClockMs`. */
export const DEFAULT_SETTLEMENT_VERIFY_GRACE_MAX_MS = 20_000
const SHORT_WALL_CLOCK_THRESHOLD_MS = 20_000
const SETTLEMENT_LEAD_THRESHOLD_MS = 45_000
const PROOF_HANDOFF_GRACE_MS = 400

function clampFiniteNonNegativeMs(value: number | undefined): number {
  if (typeof value !== 'number' || !Number.isFinite(value) || value <= 0) return 0
  return Math.floor(value)
}

export interface EffectiveWorkerElapsedInput {
  /** Total wall-clock elapsed time since assignment/session start (ms). */
  wallElapsedMs: number
  /** Time spent paused waiting on human approval or run pause (ms). */
  approvalPausedMs?: number
  /** Time spent waiting on provider HTTP retries, 429/5xx backoff, and stalled stream timeouts (ms). */
  providerStallWaitMs?: number
  /** Finite maximum stall-wait credit deductible from wall-clock elapsed time (ms). Non-finite values clamp to 0. */
  maxStallCreditMs?: number
}

export interface EffectiveWorkerElapsedBreakdown {
  wallElapsedMs: number
  approvalPausedMs: number
  providerStallWaitMs: number
  creditedStallWaitMs: number
  activeElapsedMs: number
  effectiveElapsedMs: number
}

/**
 * Pure helper computing effective worker elapsed time breakdown for wall-clock rotation decisions.
 * Deducts both human approval/run pause time AND bounded provider-stall/retry wait time (capped
 * by finite `maxStallCreditMs`, e.g. `baseWallClockMs`, so total active duration never exceeds
 * the `2x` hard ceiling).
 */
export function computeEffectiveWorkerElapsedBreakdown(
  input: EffectiveWorkerElapsedInput,
): EffectiveWorkerElapsedBreakdown {
  const wallElapsedMs = clampFiniteNonNegativeMs(input.wallElapsedMs)
  const approvalPausedMs = clampFiniteNonNegativeMs(input.approvalPausedMs)
  const providerStallWaitMs = clampFiniteNonNegativeMs(input.providerStallWaitMs)
  const maxStallCreditMs = clampFiniteNonNegativeMs(input.maxStallCreditMs)
  const activeElapsedMs = Math.max(0, wallElapsedMs - approvalPausedMs)
  const creditedStallWaitMs = Math.min(providerStallWaitMs, maxStallCreditMs)
  const effectiveElapsedMs = Math.max(0, activeElapsedMs - creditedStallWaitMs)
  return {
    wallElapsedMs,
    approvalPausedMs,
    providerStallWaitMs,
    creditedStallWaitMs,
    activeElapsedMs,
    effectiveElapsedMs,
  }
}

/**
 * Pure helper computing effective worker elapsed time (ms) after deducting human approval pauses
 * and bounded provider-stall/retry wait time (capped at `maxStallCreditMs`).
 */
export function computeEffectiveWorkerElapsedMs(input: EffectiveWorkerElapsedInput): number {
  return computeEffectiveWorkerElapsedBreakdown(input).effectiveElapsedMs
}

/**
 * Decide whether a `derive_evidence` shell call warrants inserting a SQLite `artifacts` row.
 * Ephemeral shell reads (`ls`, `head`, `rg`, `cat`) with small stdout and no materialized `/work/*`
 * output files skip SQLite persistence to eliminate thousands of write-amplifying rows per run.
 */
export function shouldPersistDeriveEvidenceArtifact(input: {
  outputs?: Record<string, string>
  stdout?: string
  stderr?: string
  explicitPersist?: boolean
}): boolean {
  if (input.explicitPersist) return true
  if (input.outputs && Object.values(input.outputs).some(v => typeof v === 'string' && v.trim().length > 0)) {
    return true
  }
  const combinedBytes = Buffer.byteLength(input.stdout ?? '', 'utf8') + Buffer.byteLength(input.stderr ?? '', 'utf8')
  return combinedBytes > DERIVE_EVIDENCE_PERSIST_THRESHOLD_BYTES
}

export interface WorkerWallClockPlan {
  remainingBudgetMs: number
  effectiveSettlementMs: number
  verifyGraceMs: number
  expandedVerifyGraceMs: number
  settlementStreamGraceMs: number
  maxStallCreditMs: number
  hardWallClockCeilingMs: number
}

export type WorkerVerifyGraceReason =
  | 'none'
  | 'active_proof'
  | 'expanded_verify'
  | 'settlement_stream'

export interface WorkerVerifyGraceInput {
  plan: WorkerWallClockPlan
  sessionActiveElapsedMs: number
  inFlightProofCall: boolean
  enteredKovoVerify: boolean
  hasLiveSealedCapability: boolean
  hasHopCheckpoint: boolean
  inSettlementStream: boolean
  stallAbort?: boolean
}

export interface WorkerVerifyGraceDecision {
  graceMs: number
  reason: WorkerVerifyGraceReason
  verifyGraceApplied: boolean
  hardCeilingRemainingMs: number
}

/**
 * Compute bounded wall-clock settlement, stall-credit ceiling, and verify-grace windows for an
 * investigation worker.
 *
 * - Normal production budgets (>= 20s) receive a 20s–45s verify grace for in-flight proof calls,
 *   an expanded +60s bounded verify grace when the worker has already entered `kovo_verify` or
 *   holds a live sealed capability / active `hop_checkpoint`, plus a bounded 10s–20s
 *   settlement-stream grace if actively generating its final verification call.
 * - `maxStallCreditMs` is strictly capped at `remainingBudgetMs` so `hardWallClockCeilingMs`
 *   never exceeds `2x` base wall-clock budget (zero infinite hangs).
 * - Short test budgets (< 20s) preserve fast proportional scaling with zero settlement-stream
 *   extension so unit/integration rotation tests stay strictly bounded.
 */
export function computeWorkerWallClockPlan(input: {
  wallClockMs: number
  preSessionElapsedMs?: number
  explicitSettlementMs?: number
  isMultiHop?: boolean
}): WorkerWallClockPlan {
  const wallClockMs = Math.max(1, Math.floor(input.wallClockMs))
  const preSessionElapsedMs = Math.max(0, Math.floor(input.preSessionElapsedMs ?? 0))
  const remainingBudgetMs = Math.max(1, wallClockMs - preSessionElapsedMs)
  const isMultiHop = Boolean(input.isMultiHop)
  const maxStallCreditMs = remainingBudgetMs
  const hardWallClockCeilingMs = remainingBudgetMs + maxStallCreditMs

  const baseSettlementMs = resolveWorkerSettlementMs(wallClockMs, isMultiHop)
  const effectiveSettlementMs = input.explicitSettlementMs !== undefined
    ? Math.max(1, Math.floor(input.explicitSettlementMs))
    : wallClockMs >= SETTLEMENT_LEAD_THRESHOLD_MS
      ? Math.max(1, Math.min(baseSettlementMs, Math.floor(wallClockMs * 0.75)))
      : baseSettlementMs

  if (remainingBudgetMs < SHORT_WALL_CLOCK_THRESHOLD_MS) {
    return {
      remainingBudgetMs,
      effectiveSettlementMs,
      verifyGraceMs: Math.min(5_000, Math.max(25, Math.floor(remainingBudgetMs * 0.25))),
      expandedVerifyGraceMs: Math.min(5_000, Math.max(50, Math.floor(remainingBudgetMs * 0.50))),
      settlementStreamGraceMs: 0,
      maxStallCreditMs,
      hardWallClockCeilingMs,
    }
  }

  const verifyShare = isMultiHop ? 0.30 : 0.25
  const verifyGraceMs = Math.min(
    DEFAULT_VERIFY_GRACE_MAX_MS,
    Math.max(DEFAULT_VERIFY_GRACE_MIN_MS, Math.round(remainingBudgetMs * verifyShare)),
  )
  const expandedVerifyGraceMs = Math.min(EXPANDED_VERIFY_GRACE_MS, maxStallCreditMs)
  const settlementStreamGraceMs = Math.min(
    DEFAULT_SETTLEMENT_VERIFY_GRACE_MAX_MS,
    Math.max(10_000, Math.round(remainingBudgetMs * 0.20)),
  )
  return {
    remainingBudgetMs,
    effectiveSettlementMs,
    verifyGraceMs,
    expandedVerifyGraceMs,
    settlementStreamGraceMs,
    maxStallCreditMs,
    hardWallClockCeilingMs,
  }
}

/**
 * Decide whether a worker whose soft wall-clock budget has expired qualifies for a bounded
 * verify-grace extension, strictly clamped by the remaining headroom to `hardWallClockCeilingMs`.
 */
export function resolveWorkerVerifyGrace(input: WorkerVerifyGraceInput): WorkerVerifyGraceDecision {
  const activeElapsed = clampFiniteNonNegativeMs(input.sessionActiveElapsedMs)
  const hardCeilingRemainingMs = Math.max(0, input.plan.hardWallClockCeilingMs - activeElapsed)
  if (hardCeilingRemainingMs <= 0) {
    return { graceMs: 0, reason: 'none', verifyGraceApplied: false, hardCeilingRemainingMs: 0 }
  }
  const hasExpandedContext = Boolean(
    input.enteredKovoVerify
    || input.hasLiveSealedCapability
    || input.hasHopCheckpoint,
  )
  if (hasExpandedContext) {
    const graceMs = Math.min(input.plan.expandedVerifyGraceMs, hardCeilingRemainingMs)
    return {
      graceMs,
      reason: graceMs > 0 ? 'expanded_verify' : 'none',
      verifyGraceApplied: graceMs > 0,
      hardCeilingRemainingMs,
    }
  }
  if (input.inFlightProofCall) {
    const graceMs = Math.min(input.plan.verifyGraceMs, hardCeilingRemainingMs)
    return {
      graceMs,
      reason: graceMs > 0 ? 'active_proof' : 'none',
      verifyGraceApplied: graceMs > 0,
      hardCeilingRemainingMs,
    }
  }
  if (input.inSettlementStream && !input.stallAbort && input.plan.settlementStreamGraceMs > 0) {
    const graceMs = Math.min(input.plan.settlementStreamGraceMs, hardCeilingRemainingMs)
    return {
      graceMs,
      reason: graceMs > 0 ? 'settlement_stream' : 'none',
      verifyGraceApplied: graceMs > 0,
      hardCeilingRemainingMs,
    }
  }
  return { graceMs: 0, reason: 'none', verifyGraceApplied: false, hardCeilingRemainingMs }
}

function stripUntrustedReplayEnvelopes(rawSpec: unknown): unknown {
  if (!rawSpec || typeof rawSpec !== 'object' || Array.isArray(rawSpec)) return rawSpec
  const copy = { ...(rawSpec as Record<string, unknown>) }
  delete copy.recipe
  delete copy.agentScript
  return copy
}

export interface ExecProofObligationCounts {
  probedRoutes: number
  coveredRoutes: number
  gapRoutes: number
  demandedRoutes: number
  dischargedByGap: number
}

export interface ExecGapValidationCounts {
  accepted: number
  rejected: number
  byCode: Record<string, { accepted: number; rejected: number }>
}

export interface ExecBrokeredTransportContext {
  job: Active
  step: ChainStep
  session: Awaited<ReturnType<WorkerBackend['openSession']>>
  grant: Grant
  currentSecrets: () => NamedSecret[]
  boardTools: { noteEvidence: () => void }
  sharedHandlers: ReturnType<ExecWorkerRunner['buildSharedSessionHandlers']>
  trackPersonaResources: (curRun: Run, res: BrokerExchangeResult, exchangeId: string) => void
  prepareBudgetedProbe: (origin: string, requestedMax: number | undefined, defaultMax: number) => {
    curRun: Run
    cleanOrigin: string
    remainingReqs: number
    cappedMax: number
  }
  stageJsonArtifact: (
    curRun: Run,
    kind: 'dns' | 'tls' | 'browser' | 'surface' | 'ws',
    title: string,
    filename: string, payload: unknown, signal: AbortSignal, secretsList?: readonly NamedSecret[],
  ) => Promise<{ evidenceId: string; stagedPath: string | null }>
  onExchangeRecorded?: (ex: RecordedRequestExchange) => void
}

const UNSAFE_PROTO_SEGMENTS = new Set(['__proto__', 'constructor', 'prototype'])

/**
 * R2-C-2: Reject prototype-accessor segments (`__proto__`, `constructor`, `prototype`) in any
 * dotted or bracketed parameter path before it can reach JSON/GraphQL injection helpers.
 */
export function isSafeParamName(name: string): boolean {
  if (typeof name !== 'string') return false
  const trimmed = name.trim()
  if (!trimmed || /[\0\r\n]/.test(trimmed)) return false
  const segments = trimmed
    .split(/[.[\]]+/)
    .map(seg => seg.trim().replace(/^['"]|['"]$/g, ''))
    .filter(Boolean)
  if (segments.length === 0) return false
  return segments.every(seg => !UNSAFE_PROTO_SEGMENTS.has(seg))
}

export function assertSafeParamName(name: string, fieldLabel = 'paramName'): string {
  if (!isSafeParamName(name)) {
    throw new Error(`Invalid ${fieldLabel}: prototype accessor segments (__proto__, constructor, prototype) are forbidden.`)
  }
  return name.trim()
}

export interface ExecWorkerHost extends ExecCoreServices {
  runState?: RunOrchestrationStateStore
  personaAuth: PersonaAuthManager
  board: ExecBoardManager
  verifier: ExecVerifier
  reconPlanner: ExecReconPlanner
  recordedPersonaResources: Map<string, Set<string>>
  workerSessionClones: Map<string, Array<{ handle: string; clone: PersonaSessionClone }>>
  boardHandleByAssignment: Map<string, string>
  warmSecretEpochByRun: Map<string, string>
  warmPoolPolicyRotationsByRun: Map<string, number>
  wallClockRotatedAssignments: Set<string>
  wallClockRotationsByRun: Map<string, number>
  providerStallTimeoutsByRun: Map<string, number>
  providerStallTurnsByRun: Map<string, number>
  providerStallRetriesByRun: Map<string, number>
  providerStallWallSavedByRun: Map<string, number>
  proofObligationByRun: Map<string, ExecProofObligationCounts>
  gapValidationByRun: Map<string, ExecGapValidationCounts>
  earlyExitTurnsSavedByRun: Map<string, number>
  assignmentWallByRun: Map<string, number[]>
  completedAssignmentWallByRun: Map<string, number[]>
  turnLatencyByRun: Map<string, number[]>
  authorize: (job: Active) => boolean
  check: (job: Active) => Run
  permitted: (run: Run, origin: string) => boolean
  approvedOriginsSet: (run: Run) => Set<string>
  parseOriginForRun: (run: Run, raw: string) => string
  projectReposMount: (projectId: string) => { reposDir?: string; mountedRepos: string[] }
  buildGrant: (job: Active, run: Run, permittedAtAdmission: ReadonlySet<string>) => {
    grant: Grant
    secrets: NamedSecret[]
    currentSecrets: () => NamedSecret[]
  }
  stageProjectSpecs: (
    projectId: string,
    session: Awaited<ReturnType<WorkerBackend['openSession']>>,
    signal: AbortSignal,
  ) => Promise<Array<{ name: string; kind: string; origin?: string | null; stagedPath?: string }>>
  safeEvent: (runId: string, kind: string, message: string, detail?: Record<string, unknown>) => void
  ensureCanaryListenerForRun: (run: Run, ignoreErrors?: boolean) => Promise<void>
  phaseRequestRemaining: (run: Run) => number | null
  markEndpointCoverage: (run: Run, origin: string, method: string, pathAndQuery: string, testedClass: string) => void
  scanSecondOrderExchange: (
    run: Run,
    assignmentId: string,
    res: Pick<BrokerExchangeResult, 'origin' | 'pathAndQuery' | 'personaHandle' | 'mediaType' | 'respHeaders' | 'body'>,
    exchangeId: string | null,
    mediaTypeOverride?: string,
  ) => void
  postCanaryLead: (run: Run, input: Parameters<ExecBoardManager['postCanaryLead']>[1]) => BoardMessageRow | null
  boardTurnDelta: (run: Run, handle: string, lastReadSeq: number) => { text: string; cursor: number }
  schedulePlanner: (runId: string, delayMs?: number) => void
  ensureRunTrace: (run: Run, profiles?: readonly ResolvedModelProfile[]) => AgentTrace | null
  capabilityVaultFor: (runId: string) => DerivedCapabilityVault
  executeInlineVerification: (...a: Parameters<ExecVerifier['executeInlineVerification']>) => ReturnType<ExecVerifier['executeInlineVerification']>
  persistAgentScriptProof: (...a: Parameters<ExecVerifier['persistAgentScriptProof']>) => ReturnType<ExecVerifier['persistAgentScriptProof']>
  alreadyConfirmedRefs: (...a: Parameters<ExecReconPlanner['alreadyConfirmedRefs']>) => ReturnType<ExecReconPlanner['alreadyConfirmedRefs']>
  detLeadSummaries: (...a: Parameters<ExecReconPlanner['detLeadSummaries']>) => ReturnType<ExecReconPlanner['detLeadSummaries']>
  assignmentBriefForStep: (...a: Parameters<ExecReconPlanner['assignmentBriefForStep']>) => ReturnType<ExecReconPlanner['assignmentBriefForStep']>
  buildBrokeredTransportHandlers: (ctx: ExecBrokeredTransportContext) => Partial<WorkerToolHandlers>
}

export class ExecWorkerRunner extends ExecServiceModule<ExecWorkerHost> {
  private readonly turnStateByAssignment = new Map<string, {
    turn: number; toolCallsInTurn: number; totalToolCalls: number
    lastProviderFailure?: ProviderFailureError
  }>()
  private readonly runState = this.host.runState ?? createAutoDisposedRunState()

  private recordWorkerProfileFailure(
    turnState: { lastProviderFailure?: ProviderFailureError },
    profileId: string,
    err: string,
    hard: boolean,
    notify: (profileId: string, err: string, hard: boolean) => void,
  ): void {
    const handedOff = peekLatestProviderFailureForProfile(profileId)
    notify(profileId, err, hard)
    const classified = handedOff
      ? new ProviderFailureError(err, { kind: handedOff.kind, hard: handedOff.hard, ...(handedOff.status !== null ? { status: handedOff.status } : {}), profileId })
      : classifyProviderFailure(err, { profileId })
    if (classified) turnState.lastProviderFailure = classified
  }

  private resolveRunRetryContext(run: Run) {
    void this.runState
    const currentRun = this.storage.run(run.id)
    const existingSteps = this.storage.listChainSteps(currentRun.id, currentRun.goalRevision)
    const dynamicBudget = Math.min(hardChainStepsCeiling, currentRun.dynamicStepBudget ?? computeDynamicStepBudget(this.storage, currentRun.id))
    const effectiveStepCap = Math.min(dynamicBudget, resolveRunSafetyBudgets({ maxAssignments: dynamicBudget }).maxCompositeVerifiesPerRun)
    const maxDurationMs = this.host.reconPlanner?.getRunMaxDurationMs?.(currentRun as { maxDurationMs?: number })
      ?? (Number((currentRun as { maxDurationMs?: number }).maxDurationMs) || 0)
    const budgetExhausted = this.storage.checkBudgetExceeded(currentRun.id)
    const requestBudgetExhausted = currentRun.budgetRequests > 0 && currentRun.budgetRequests - currentRun.spentRequests <= 0
    return { currentRun, existingSteps, effectiveStepCap, maxDurationMs, budgetExhausted, requestBudgetExhausted }
  }

  private pauseRunForProviderCircuit(
    run: Run,
    job: Active,
    step: ChainStep,
    input: {
      failureKind: 'quota' | 'auth'
      roleAffinity: string
      profileIds: readonly string[]
      reason: string
    },
  ): void {
    const assignment = job.assignment
    const label = input.failureKind === 'quota' ? 'provider quota exhaustion' : 'provider authentication failure'
    this.storage.transaction(() => {
      const currentRun = this.storage.run(run.id)
      this.storage.updateWorker(assignment.id, {
        status: 'paused',
        outcome: `Paused due to ${label}: ${input.reason}`,
        lease: null,
        leaseExpiresAt: null,
      })
      this.storage.updateChainStep(step.id, { status: 'ready', assignedWorkerId: null })
      if (currentRun.status === 'running') {
        this.storage.setStatus(currentRun, 'paused')
        this.storage.event(
          run.id,
          'run.provider_paused',
          `Run paused (${input.failureKind}): all model profiles for role "${input.roleAffinity}" are hard-open (${input.reason}).`,
          {
            status: 'provider_paused',
            reason: 'provider_paused',
            failureKind: input.failureKind,
            roleAffinity: input.roleAffinity,
            profileIds: [...input.profileIds],
            stepId: step.id,
            assignmentId: assignment.id,
            error: input.reason,
          },
        )
      }
    }, { behavior: 'immediate' })
  }

  private resolveStepProviderRetryKey(step: ChainStep): string {
    const structuredTargets = this.host.reconPlanner.getStructuredStepTargets(step)
    const primaryTarget = structuredTargets[0]
    const primaryMethod = primaryTarget?.method ?? 'ANY'
    const primaryRoute = primaryTarget?.route ?? (step.title || step.id)
    const primaryClass = primaryTarget?.vulnClass ?? step.category ?? 'unknown'
    return reinvestigationKey(`${primaryMethod} ${primaryRoute}`, primaryClass)
  }

  /**
   * Record a negative-edge settlement (`invariant_enforced_hardened` | `control_blocked_cleanly` |
   * `decoy_guard_verified`) into `CapabilityLedger` and `FrontierWaveController` so dead-end
   * branches prune after 2 strikes and sibling workers skip re-probing them.
   */
  recordNegativeEdgeCoverage(
    runId: string,
    input: {
      origin: string
      category: string
      summary: string
      proofGapReason?: string
      route?: string
      enforcingControl?: string
      preconditionCapIds?: readonly string[]
      branchKey?: string
      hypothesisClass?: string
      exchangeIds?: readonly string[]
      assignmentId?: string
    },
  ): { recorded: boolean; pruned: boolean; attemptCount: number; negativeEdge?: NegativeEdge } {
    const reason = parseNegativeEdgeGapReason(input.proofGapReason)
    if (!reason) return { recorded: false, pruned: false, attemptCount: 0 }

    const ledger = this.storage.capabilityLedger(runId)
    const controller = this.host.reconPlanner.frontierControllerFor(runId)
    const targetSurfaceKey = input.route?.trim()
      ? input.route.trim()
      : `${input.origin}:${input.category}`
    const hypothesisClass = input.hypothesisClass?.trim() || input.category
    const branchKey = input.branchKey?.trim() || ''

    const extractedHandles = [
      ...(input.preconditionCapIds ?? []),
      ...(`${input.summary} ${input.proofGapReason ?? ''}`.match(/cap:hop_[A-Za-z0-9._-]+:[A-Za-z0-9._-]+/g) ?? []),
    ].map(h => h.trim()).filter(h => DERIVED_CAPABILITY_HANDLE_RE.test(h))
    const uniqueHandles = [...new Set(extractedHandles)]

    const extractedExchanges = [
      ...(input.exchangeIds ?? []),
      ...(`${input.enforcingControl ?? ''} ${input.summary}`.match(/\b(?:gx|ex)[_-][A-Za-z0-9._-]{2,80}\b/g) ?? []),
    ].map(id => id.trim()).filter(Boolean)
    const falsifiedByExchangeIds = extractedExchanges.length > 0
      ? [...new Set(extractedExchanges)]
      : [`cov_${input.assignmentId ?? 'worker'}_${Date.now()}`]

    let negativeEdge: NegativeEdge
    if (branchKey && controller.scheduler.getBranch(branchKey)) {
      const outcome = controller.recordPivotOutcome({
        branchKey,
        targetSurfaceKey,
        hypothesisClass,
        status: 'failed',
        failureReason: reason,
        falsifiedByExchangeIds,
      })
      if (uniqueHandles.length > 0 && outcome.ledgerNegativeEdge) {
        const recordedCaps = new Set(outcome.ledgerNegativeEdge.preconditionCapIds)
        const differs = uniqueHandles.length !== recordedCaps.size || uniqueHandles.some(h => !recordedCaps.has(h))
        negativeEdge = differs
          ? ledger.recordNegativeEdge({
              preconditionCapIds: uniqueHandles,
              targetSurfaceKey,
              hypothesisClass,
              falsifiedByExchangeIds,
              reason,
              forcePrune: outcome.pruned,
              notes: input.summary.slice(0, 240),
            })
          : outcome.ledgerNegativeEdge
      } else {
        negativeEdge = outcome.ledgerNegativeEdge ?? ledger.recordNegativeEdge({
          preconditionCapIds: uniqueHandles.length > 0 ? uniqueHandles : [`branch:${branchKey}`],
          targetSurfaceKey,
          hypothesisClass,
          falsifiedByExchangeIds,
          reason,
          forcePrune: outcome.pruned,
          notes: input.summary.slice(0, 240),
        })
      }
      controller.syncNegativeEdgesFromLedger()
    } else {
      const preconditionCapIds = uniqueHandles.length > 0
        ? uniqueHandles
        : [branchKey ? `branch:${branchKey}` : `surface:${targetSurfaceKey}`]
      negativeEdge = ledger.recordNegativeEdge({
        preconditionCapIds,
        targetSurfaceKey,
        hypothesisClass,
        falsifiedByExchangeIds,
        reason,
        notes: input.summary.slice(0, 240),
      })
      controller.syncNegativeEdgesFromLedger()
    }

    this.host.safeEvent(
      runId,
      'frontier.negative_edge',
      `Negative edge recorded (${reason}) on ${targetSurfaceKey} [${hypothesisClass}] (strike ${negativeEdge.attemptCount}${negativeEdge.pruned ? ', PRUNED' : ''}).`,
      {
        reason,
        targetSurfaceKey,
        hypothesisClass,
        preconditionCapIds: negativeEdge.preconditionCapIds,
        attemptCount: negativeEdge.attemptCount,
        pruned: negativeEdge.pruned,
        ...(branchKey ? { branchKey } : {}),
      },
    )
    return {
      recorded: true,
      pruned: negativeEdge.pruned,
      attemptCount: negativeEdge.attemptCount,
      negativeEdge,
    }
  }

  buildSharedSessionHandlers(
    job: Active,
    session: Awaited<ReturnType<WorkerBackend['openSession']>>,
    currentSecrets: () => readonly NamedSecret[],
    options: {
      offlineScriptLabel: string
      deriveEvidenceTitle: string
      onFactRecorded?: (curRun: Run) => void
      guardPrematureRuledOut?: (input: {
        runId: string
        origins: readonly string[]
        status: string
        category?: string
        hypothesisClass?: string
        summary?: string
        enforcingControl?: string
        exchangeIds?: readonly string[]
      }) => void
    },
  ) {
    return {
      spillOutput: async (id: string, content: string, sig: AbortSignal) => session.stage(`tool-output/${id}.txt`, content, sig),
      derive_evidence: async ({ command, outputs, timeoutMs }: Parameters<NonNullable<WorkerToolHandlers['derive_evidence']>>[0], sig: AbortSignal) => {
        const curRun = this.host.check(job)
        const res = await session.exec(command, outputs ?? ['result.txt'], sig, timeoutMs ?? 60_000)
        const shouldPersist = shouldPersistDeriveEvidenceArtifact({
          outputs: res.outputs,
          stdout: res.stdout,
          stderr: res.stderr,
        })
        if (!shouldPersist) {
          return { exitCode: res.exitCode, stdout: res.stdout, stderr: res.stderr, outputs: res.outputs, ephemeral: true }
        }
        const sec = currentSecrets()
        const ev = this.storage.addArtifact(curRun, job.assignment, 'analysis', options.deriveEvidenceTitle,
          JSON.stringify({
            command: redact(command, sec),
            exitStatus: res.exitCode,
            stdout: redact(res.stdout, sec),
            stderr: redact(res.stderr, sec),
            outputs: res.outputs,
          }, null, 2), undefined, sec)
        return { evidenceId: ev.id, exitCode: res.exitCode, stdout: res.stdout, stderr: res.stderr, outputs: res.outputs }
      },
      analyze_artifact: async (args: Parameters<NonNullable<WorkerToolHandlers['analyze_artifact']>>[0], sig: AbortSignal) => {
        this.host.check(job)
        const { tool, ...rest } = args
        return await session.analyze(tool, rest, sig)
      },
      run_sast_scan: async (args: Parameters<NonNullable<WorkerToolHandlers['run_sast_scan']>>[0], sig: AbortSignal) => {
        const curRun = this.host.check(job)
        const res = await session.sast(args, sig)
        const ev = this.storage.addArtifact(curRun, job.assignment, 'sast',
          `SAST scan · ${res.repo} (${res.enginesRun.join(', ')})`,
          JSON.stringify(res, null, 2), undefined, currentSecrets())
        for (const engine of res.enginesRun) {
          const st = res.engineStatus[engine]
          this.storage.recordSastRun({
            runId: curRun.id,
            assignmentId: job.assignment.id,
            repo: res.repo,
            engine,
            rawArtifactId: ev.id,
            findingCount: st?.count ?? 0,
            durationMs: st?.durationMs ?? res.durationMs,
          })
        }
        return { evidenceId: ev.id, ...res }
      },
      run_offline_script: async (args: Parameters<NonNullable<WorkerToolHandlers['run_offline_script']>>[0], sig: AbortSignal) => {
        const curRun = this.host.check(job)
        const res = await session.runScript(args, sig)
        const ev = this.storage.addArtifact(curRun, job.assignment, 'analysis',
          options.offlineScriptLabel.replace('{runtime}', args.runtime),
          JSON.stringify({
            runtime: res.runtime,
            exitCode: res.exitCode,
            timedOut: res.timedOut,
            durationMs: res.durationMs,
            stdout: redact(res.stdout, currentSecrets()),
            stderr: redact(res.stderr, currentSecrets()),
          }, null, 2), undefined, currentSecrets())
        return { evidenceId: ev.id, ...res }
      },
      query_cves: async (args: Parameters<NonNullable<WorkerToolHandlers['query_cves']>>[0], sig: AbortSignal) => {
        this.host.check(job)
        const advisories = await queryCves(args, sig)
        return { count: advisories.length, advisories }
      },
      load_skill: async ({ name }: { name: string }) => {
        if (name.trim().toLowerCase() === 'list') return { skills: listSkills() }
        const skill = loadSkill(name)
        if (!skill) return { error: `Unknown skill "${name}".`, available: listSkills().map(s => s.name) }
        return skill
      },
      search_facts: async ({ query, origin, kind, limit }: Parameters<NonNullable<WorkerToolHandlers['search_facts']>>[0]) => {
        const curRun = this.host.check(job)
        const currentApproved = this.host.approvedOriginsSet(curRun)
        return this.storage.listFacts(curRun.id, { includeTainted: false, query, origin, kind, limit })
          .filter(f => currentApproved.has(f.origin) && f.sourceOrigins.every(o => currentApproved.has(o)))
      },
      record_fact: async (args: Parameters<NonNullable<WorkerToolHandlers['record_fact']>>[0]) => {
        const curRun = this.host.check(job)
        const currentApproved = this.host.approvedOriginsSet(curRun)
        const cleanOrigin = this.host.parseOriginForRun(curRun, args.origin)
        if (!currentApproved.has(cleanOrigin)) throw new BrokerDenied(`Origin ${cleanOrigin} is not approved.`)
        // M-47: Untrusted worker writes can never spoof host planner control signals (det_lead, hop_checkpoint).
        const sanitizedData = sanitizeWorkerFactData(args.data as Record<string, unknown> | undefined)
        const fact = this.storage.addFact(curRun, job.assignment, {
          kind: args.kind,
          origin: cleanOrigin,
          summary: args.summary,
          data: sanitizedData,
          exchangeIds: args.exchangeIds,
          evidenceIds: args.evidenceIds,
          sourceOrigins: args.sourceOrigins,
          secrets: currentSecrets(),
        })
        options.onFactRecorded?.(curRun)
        return { factId: fact.id, kind: args.kind, origin: fact.origin }
      },
      record_coverage: async (args: Parameters<NonNullable<WorkerToolHandlers['record_coverage']>>[0]) => {
        const curRun = this.host.check(job)
        const currentApproved = this.host.approvedOriginsSet(curRun)
        const cleanOrigin = this.host.parseOriginForRun(curRun, args.origin)
        if (!currentApproved.has(cleanOrigin)) throw new BrokerDenied(`Origin ${cleanOrigin} is not approved.`)
        const ext = args as typeof args & {
          enforcingControl?: string
          proofGapReason?: string
          linkedFindingId?: string
          route?: string
          preconditionCapIds?: string[]
          branchKey?: string
          hypothesisClass?: string
          exchangeIds?: string[]
        }
        if (args.status === 'ruled_out' && !ext.enforcingControl?.trim()) {
          throw new Error('record_coverage with status "ruled_out" requires a non-empty enforcingControl (exact file:line or negative-control exchangeId proving the control runs on the attacker path).')
        }
        options.guardPrematureRuledOut?.({
          runId: curRun.id,
          origins: [cleanOrigin],
          status: args.status,
          category: args.category,
          hypothesisClass: ext.hypothesisClass,
          summary: args.summary,
          enforcingControl: ext.enforcingControl,
          exchangeIds: ext.exchangeIds,
        })
        const entry = this.storage.upsertCoverageEntry(curRun, job.assignment.id, {
          origin: cleanOrigin,
          category: args.category,
          status: args.status,
          summary: args.summary,
          enforcingControl: ext.enforcingControl,
          proofGapReason: args.status === 'needs_follow_up' ? (ext.proofGapReason?.trim() || args.summary) : ext.proofGapReason,
          linkedFindingId: ext.linkedFindingId,
          route: ext.route,
          branchKey: ext.branchKey,
          exchangeIds: ext.exchangeIds,
        })
        const storedMeta = extractCoverageEvidenceMetadata(entry)
        const neg = this.recordNegativeEdgeCoverage(curRun.id, {
          origin: cleanOrigin,
          category: args.category,
          summary: args.summary,
          proofGapReason: ext.proofGapReason,
          route: ext.route ?? storedMeta.route ?? undefined,
          enforcingControl: ext.enforcingControl,
          preconditionCapIds: ext.preconditionCapIds,
          branchKey: ext.branchKey ?? storedMeta.branchKey ?? undefined,
          hypothesisClass: ext.hypothesisClass,
          exchangeIds: storedMeta.exchangeIds.length > 0 ? storedMeta.exchangeIds : ext.exchangeIds,
          assignmentId: job.assignment.id,
        })
        return {
          id: entry.id,
          origin: entry.origin,
          category: entry.category,
          status: entry.status,
          ...(storedMeta.route ? { route: storedMeta.route } : {}),
          ...(storedMeta.exchangeIds.length > 0 ? { exchangeIds: storedMeta.exchangeIds } : {}),
          ...(entry.status !== args.status ? { monotonePreserved: true } : {}),
          ...(neg.recorded ? { negativeEdgeRecorded: true, pruned: neg.pruned, attemptCount: neg.attemptCount } : {}),
        }
      },
      complete_intent: async (completion: Parameters<NonNullable<WorkerToolHandlers['complete_intent']>>[0]) => ({ recorded: true, status: completion.status }),
    } satisfies Partial<WorkerToolHandlers>
  }

  completeWorker(
    worker: Assignment,
    run: Run,
    summary: string,
    artifactIds: string[],
    checks?: CheckCoverage[],
    secrets: readonly NamedSecret[] = [],
  ) {
    const outcome = redact(summary, secrets)
    const result = this.storage.addArtifact(run, worker, 'handoff', 'result.md', [
      '# Result', '', outcome, '', 'Evidence: ' + artifactIds.join(', '),
    ].join('\n'), 'result', secrets)
    this.storage.updateWorker(worker.id, { status: 'complete', lease: null, leaseExpiresAt: null, outcome, checks })
    const trackedClones = this.host.workerSessionClones.get(worker.id)
    if (trackedClones) {
      for (const entry of trackedClones) entry.clone.dispose()
      this.host.workerSessionClones.delete(worker.id)
    }
    this.storage.message(run.id, worker.id, 'worker', outcome, undefined, [...artifactIds, result.id], secrets)
    this.storage.event(run.id, 'worker.complete', worker.title + ' completed.', {
      assignmentId: worker.id, artifactId: artifactIds[0] ?? result.id,
    })
  }

  private noteLifecycleWarning(
    runId: string,
    hook: string,
    error: unknown,
    extra: Record<string, unknown> = {},
  ): void {
    const reason = redact(error instanceof Error ? error.message : String(error)).slice(0, 240)
    this.host.safeEvent(
      runId,
      'worker.lifecycle_warning',
      `Worker lifecycle hook "${hook}" failed: ${reason}`,
      { hook, error: reason, ...extra },
    )
  }

  private emitStepTerminalEvent(
    runId: string,
    input: {
      assignmentId: string
      step: ChainStep
      stepStatus: ChainStepTerminalStatus
      sessionStatus?: string
      confirmed: boolean
      gapCoded: boolean
      origins?: readonly string[]
      reason?: string
    },
  ): void {
    const targets = this.host.reconPlanner.getStructuredStepTargets(input.step)
    this.host.safeEvent(
      runId,
      'worker.step_terminal',
      `Chain step "${input.step.title}" terminated with status=${input.stepStatus} (confirmed=${input.confirmed}, gapCoded=${input.gapCoded}).`,
      {
        assignmentId: input.assignmentId,
        stepId: input.step.id,
        stepStatus: input.stepStatus,
        ...(input.sessionStatus ? { sessionStatus: input.sessionStatus } : {}),
        confirmed: input.confirmed,
        gapCoded: input.gapCoded,
        category: input.step.category,
        origins: [...(input.origins ?? input.step.sourceOrigins)],
        targets,
        ...(input.reason ? { reason: input.reason } : {}),
      },
    )
  }

  handleInvestigationWorkerError(
    run: Run,
    job: Active,
    step: ChainStep,
    resolvedSpecialistId: string,
    budget: AssignmentBudget,
    error: unknown,
    context?: { noToolCallExecuted?: boolean; providerFailure?: ProviderFailureError },
  ): void {
    const assignment = job.assignment
    const turnState = this.turnStateByAssignment.get(assignment.id)
    this.turnStateByAssignment.delete(assignment.id)
    const noToolCallExecuted = context?.noToolCallExecuted ?? ((turnState?.toolCallsInTurn ?? 0) === 0)
    const toolCallsExecutedInTurn = noToolCallExecuted ? 0 : Math.max(1, turnState?.toolCallsInTurn ?? 1)

    if (error instanceof BudgetExceededError) {
      this.storage.checkBudgetExceeded(run.id)
      return
    }
    // Provider-stream stall: aborting the assignment's provider call frees the slot without
    // spending the rest of its wall budget. Routed through the single RetryGovernor so per-key
    // caps, USD/request/step budgets, run wall-clock, and mid-stream tool-call safety apply.
    if (job.stallAbort) {
      const attempt = job.assignment.attempt
      const retryKey = this.resolveStepProviderRetryKey(step)
      const retryCtx = this.resolveRunRetryContext(run)
      const stallDecision = defaultRetryGovernor.evaluate({
        runId: run.id, path: 'provider_stall', retryKey, retryable: shouldRetryStalledAssignment(attempt),
        failureCode: 'stall', emitted: true, toolCallsExecutedInTurn, stepSkills: step.skills,
        stepTrialIndex: step.trialIndex, assignmentAttempt: attempt, runStatus: retryCtx.currentRun.status,
        runPhase: retryCtx.currentRun.phase, budgetExhausted: retryCtx.budgetExhausted,
        requestBudgetExhausted: retryCtx.requestBudgetExhausted, runCreatedAt: retryCtx.currentRun.createdAt,
        maxDurationMs: retryCtx.maxDurationMs, existingStepCount: retryCtx.existingSteps.length,
        effectiveStepCap: retryCtx.effectiveStepCap,
      })
      if (stallDecision.allowed) {
        this.host.providerStallRetriesByRun.set(run.id, (this.host.providerStallRetriesByRun.get(run.id) ?? 0) + 1)
        defaultRetryGovernor.recordRetry(run.id, retryKey, 'provider_stall')
        try {
          recordProviderUsageTelemetry({
            runId: run.id, outcome: 'retried', retried: true, retryCount: 1, stalled: true, costUsd: 0, countCall: false,
          })
        } catch { /* telemetry only */ }
        this.storage.transaction(() => {
          this.storage.updateWorker(assignment.id, {
            status: 'canceled',
            outcome: 'Provider stream stalled; requeued once for a fresh attempt.',
            attempt: attempt + 1,
            lease: null,
            leaseExpiresAt: null,
          })
          this.storage.updateChainStep(step.id, { status: 'ready', assignedWorkerId: null })
          this.storage.event(run.id, 'worker.stall_retry', `${step.title} provider stream stalled; requeued once.`, {
            assignmentId: assignment.id, stepId: step.id, attempt: attempt + 1, retryKey, noToolCallExecuted,
          })
        })
        return
      }
      if (stallDecision.reason === 'midstream_tool_call_executed') {
        this.storage.event(
          run.id,
          'worker.provider_retry_blocked',
          `${step.title} stalled mid-turn after tool execution; skipping retry to preserve target safety.`,
          {
            assignmentId: assignment.id, stepId: step.id, failureKind: 'stall',
            reason: 'midstream_tool_call_executed', emitted: true, toolCallsExecutedInTurn,
          },
        )
      }
      this.storage.transaction(() => {
        this.storage.updateWorker(assignment.id, {
          status: 'failed',
          outcome: noToolCallExecuted
            ? 'Provider stream stalled after retry; slot released.'
            : 'Provider stream stalled after tool execution; retry blocked for target safety.',
          attempt: attempt + 1,
          lease: null,
          leaseExpiresAt: null,
        })
        this.storage.updateChainStep(step.id, { status: 'model_failure', assignedWorkerId: assignment.id })
        this.storage.event(run.id, 'worker.stall_failed', `${step.title} provider stream stalled; assignment closed without consuming the wall cap.`, {
          assignmentId: assignment.id, stepId: step.id, stepStatus: 'model_failure', reason: stallDecision.reason,
        })
      })
      this.emitStepTerminalEvent(run.id, {
        assignmentId: assignment.id,
        step,
        stepStatus: 'model_failure',
        confirmed: false,
        gapCoded: false,
        reason: noToolCallExecuted ? stallDecision.reason : 'midstream_tool_call_executed',
      })
      return
    }
    if (this.host.wallClockRotatedAssignments.delete(assignment.id)) {
      this.host.wallClockRotationsByRun.set(run.id, (this.host.wallClockRotationsByRun.get(run.id) ?? 0) + 1)
      const outcome = `[partial] Bounded wall-clock rotation after ${budget.wallClockMs}ms (pre-session timeout); slot released.`
      this.storage.transaction(() => {
        this.storage.updateWorker(assignment.id, {
          status: 'complete',
          outcome,
          lease: null,
          leaseExpiresAt: null,
        })
        this.storage.updateChainStep(step.id, { status: 'rotated_partial', assignedWorkerId: assignment.id })
        this.storage.event(run.id, 'worker.wall_clock_rotated', `${step.title} rotated at wall-clock budget (${budget.wallClockMs}ms); slot released.`, {
          assignmentId: assignment.id, stepId: step.id, stepStatus: 'rotated_partial', specialistProfile: resolvedSpecialistId,
          wallClockMs: budget.wallClockMs, boundedRotation: true, preSession: true,
          providerStallWaitMs: 0, creditedStallWaitMs: 0, verifyGraceApplied: false, verifyGraceReason: 'none',
        })
      })
      this.emitStepTerminalEvent(run.id, {
        assignmentId: assignment.id,
        step,
        stepStatus: 'rotated_partial',
        sessionStatus: 'wall_clock_rotated',
        confirmed: false,
        gapCoded: false,
        reason: 'pre_session_wall_clock_rotated',
      })
      return
    }
    if (!this.host.authorize(job) || job.controller.signal.aborted) return
    const msg = redact(error instanceof Error ? error.message : String(error)).slice(0, 400)
    const providerFailure = context?.providerFailure
      ?? (error instanceof ProviderFailureError ? error : null)
      ?? classifyProviderFailure(error)
      ?? turnState?.lastProviderFailure
      ?? null

    // R2-13 Run-level provider_paused circuit: when every profile for the specialist's role is
    // hard-open due to quota (402) or auth (401/403), pause the run cleanly within one tick and
    // restore the step to `ready` so zero `model_failure` cascade occurs.
    if (
      providerFailure
      && (providerFailure instanceof QuotaExhaustedError || providerFailure.kind === 'quota' || providerFailure.kind === 'auth')
    ) {
      const specialist = resolveSpecialistProfile(resolvedSpecialistId)
      const liveRoleProfiles = resolveProfilePoolForRole(specialist.roleAffinity, this.storage)
      const circuit = evaluateRoleProviderCircuit(liveRoleProfiles)
      if (liveRoleProfiles.length === 0 || circuit.hardOpen) {
        const failureKind: 'quota' | 'auth' = circuit.kind
          ?? (providerFailure.kind === 'quota' ? 'quota' : 'auth')
        const profileIds = circuit.profileIds.length
          ? circuit.profileIds
          : (providerFailure.profileId ? [providerFailure.profileId] : [])
        this.pauseRunForProviderCircuit(run, job, step, {
          failureKind,
          roleAffinity: specialist.roleAffinity,
          profileIds,
          reason: msg,
        })
        return
      }
    }

    // R2-13 / R3-14 Bounded transient retry (rate_limited, server, stall, stream_drop) routed
    // through the single RetryGovernor with real wall-clock exhaustion & mid-stream safety.
    if (providerFailure?.retryable) {
      const retryKey = this.resolveStepProviderRetryKey(step)
      const retryCtx = this.resolveRunRetryContext(run)
      const decision = defaultRetryGovernor.evaluate({
        runId: run.id, path: 'provider_transient', retryKey, retryable: providerFailure.retryable,
        failureCode: providerFailure.kind, emitted: providerFailure.emitted, toolCallsExecutedInTurn,
        stepSkills: step.skills, stepTrialIndex: step.trialIndex, assignmentAttempt: assignment.attempt,
        runStatus: retryCtx.currentRun.status, runPhase: retryCtx.currentRun.phase,
        budgetExhausted: retryCtx.budgetExhausted, requestBudgetExhausted: retryCtx.requestBudgetExhausted,
        runCreatedAt: retryCtx.currentRun.createdAt, maxDurationMs: retryCtx.maxDurationMs,
        existingStepCount: retryCtx.existingSteps.length, effectiveStepCap: retryCtx.effectiveStepCap,
      })
      const policyDecision = evaluateTransientProviderRetry({
        failure: providerFailure, retryKey, priorKeyRetries: decision.priorKeyRetries,
        stepSkills: step.skills, stepTrialIndex: step.trialIndex, assignmentAttempt: assignment.attempt,
        toolCallsExecutedInTurn, runStatus: retryCtx.currentRun.status, runPhase: retryCtx.currentRun.phase,
        budgetExhausted: retryCtx.budgetExhausted, requestBudgetExhausted: retryCtx.requestBudgetExhausted,
        wallClockExhausted: decision.wallClockExhausted, existingStepCount: retryCtx.existingSteps.length,
        effectiveStepCap: retryCtx.effectiveStepCap, runProviderRetries: decision.runProviderRetries,
      })
      if (decision.allowed && policyDecision.retry) {
        const rec = defaultRetryGovernor.recordRetry(run.id, retryKey, 'provider_transient')
        if (providerFailure.kind === 'stall') {
          this.host.providerStallRetriesByRun.set(run.id, (this.host.providerStallRetriesByRun.get(run.id) ?? 0) + 1)
        }
        try {
          recordProviderUsageTelemetry({
            runId: run.id, outcome: 'retried', retried: true, retryCount: 1,
            stalled: providerFailure.kind === 'stall', costUsd: 0, countCall: false,
          })
        } catch { /* telemetry only */ }
        const retrySkills = [...new Set([...step.skills, 'r213:provider_retry:1'])]
        this.storage.transaction(() => {
          this.storage.updateWorker(assignment.id, {
            status: 'canceled',
            outcome: `Transient provider failure (${providerFailure.kind}); requeued once through standard scope/tier/approval gates.`,
            attempt: assignment.attempt + 1,
            lease: null,
            leaseExpiresAt: null,
          })
          this.storage.updateChainStep(step.id, { status: 'ready', assignedWorkerId: null, skills: retrySkills })
          this.storage.event(
            run.id,
            'worker.provider_retry',
            `${step.title} hit transient provider failure (${providerFailure.kind}); requeued once.`,
            {
              assignmentId: assignment.id, stepId: step.id, failureKind: providerFailure.kind,
              status: providerFailure.status ?? null, retryAfterMs: providerFailure.retryAfterMs ?? null,
              emitted: providerFailure.emitted, noToolCallExecuted, retryKey,
              retryCount: rec.keyRetries, runProviderRetries: rec.runProviderRetries,
              effectiveStepCap: retryCtx.effectiveStepCap,
            },
          )
        }, { behavior: 'immediate' })
        return
      }
      if (decision.reason === 'midstream_tool_call_executed') {
        this.storage.event(
          run.id,
          'worker.provider_retry_blocked',
          `${step.title} hit mid-stream ${providerFailure.kind} after tool execution; retry blocked to preserve target safety.`,
          {
            assignmentId: assignment.id, stepId: step.id, failureKind: providerFailure.kind,
            retryKey, reason: decision.reason, emitted: providerFailure.emitted, toolCallsExecutedInTurn,
          },
        )
      }
    }

    const stepStatus = classifyWorkerErrorToStepStatus(providerFailure ?? error)
    this.storage.transaction(() => {
      this.storage.updateWorker(assignment.id, {
        status: 'failed', outcome: msg, lease: null, leaseExpiresAt: null, attempt: assignment.attempt + 1,
      })
      this.storage.updateChainStep(step.id, { status: stepStatus, assignedWorkerId: assignment.id })
      this.storage.event(run.id, 'worker.failed', `${step.title} failed: ${msg}`, {
        assignmentId: assignment.id,
        stepId: step.id,
        stepStatus,
        ...(providerFailure ? { failureKind: providerFailure.kind, emitted: providerFailure.emitted } : {}),
      })
    })
    this.emitStepTerminalEvent(run.id, {
      assignmentId: assignment.id,
      step,
      stepStatus,
      confirmed: false,
      gapCoded: false,
      reason: msg,
    })
  }

  async runInvestigationWorker(
    job: Active,
    step: ChainStep,
    targetOrigins: string[],
    profiles: readonly ResolvedModelProfile[],
    budget: AssignmentBudget,
  ) {
    const run = this.host.check(job)
    const preflightSpecialist = resolveSpecialistProfile(
      step.specialistProfile ?? routeStepToSpecialist({
        title: step.title,
        hypothesis: step.hypothesis,
        category: step.category,
        skills: step.skills,
      }),
    )
    const liveRoleProfiles = resolveProfilePoolForRole(preflightSpecialist.roleAffinity, this.storage)
    const effectiveRoleProfiles = liveRoleProfiles.length
      ? liveRoleProfiles
      : resolveProfilePoolForRole(preflightSpecialist.roleAffinity, profiles)
    const preflightCircuit = evaluateRoleProviderCircuit(effectiveRoleProfiles)
    if (preflightCircuit.hardOpen && preflightCircuit.kind) {
      this.pauseRunForProviderCircuit(run, job, step, {
        failureKind: preflightCircuit.kind,
        roleAffinity: preflightSpecialist.roleAffinity,
        profileIds: preflightCircuit.profileIds,
        reason: preflightCircuit.reason ?? 'All profiles for role are hard-open.',
      })
      return
    }
    const turnState = {
      turn: 0,
      toolCallsInTurn: 0,
      totalToolCalls: 0,
      lastProviderFailure: undefined as ProviderFailureError | undefined,
    }
    this.turnStateByAssignment.set(job.assignment.id, turnState)

    const permittedAtAdmission = this.host.approvedOriginsSet(run)
    const { grant, secrets, currentSecrets } = this.host.buildGrant(job, run, permittedAtAdmission)

    // Warm-pool policy: strictly keyed on container-visible isolation state (run identity +
    // mounted repo tree + worker image). Docker worker containers run `--network none` and never
    // hold host-side persona credentials, so background persona token refreshes never tear down
    // idle warm containers or re-stage `/repos`.
    const { reposDir, mountedRepos } = this.host.projectReposMount(run.projectId)
    const warmPoolPolicy = buildWarmPoolPolicy({
      runId: run.id,
      reposDir,
      mountedRepos,
      image: this.backend.workerImage,
    })
    const isolationEpoch = warmPoolPolicy.slice(warmPoolPolicy.lastIndexOf(':') + 1)
    const priorEpoch = this.host.warmSecretEpochByRun.get(run.id)
    if (priorEpoch !== undefined && priorEpoch !== isolationEpoch) {
      this.host.warmPoolPolicyRotationsByRun.set(run.id, (this.host.warmPoolPolicyRotationsByRun.get(run.id) ?? 0) + 1)
      this.host.safeEvent(run.id, 'worker.warm_pool_rotated', 'Container isolation policy changed; rebuilding idle warm containers.', {
        assignmentId: job.assignment.id, stepId: step.id, previous: priorEpoch, next: isolationEpoch,
      })
    }
    this.host.warmSecretEpochByRun.set(run.id, isolationEpoch)
    try {
      this.backend.setWarmPoolPolicy?.(
        warmPoolPolicy,
        reposDir ? { reposDir } : undefined,
      )
    } catch (err) {
      this.noteLifecycleWarning(run.id, 'setWarmPoolPolicy', err, { assignmentId: job.assignment.id, stepId: step.id })
    }

    // Open ONE persistent air-gapped container for the entire intent.
    // Arm a pause-aware pre-session wall-clock guard backed by `ActiveClock` so a stalled
    // openSession/staging call can never hold a slot past budget.wallClockMs, while human
    // Tier-3 approval waits or run pauses freeze the clock cleanly.
    const assignmentClock = new ActiveClock({ parent: getRunClock(run.id) })
    const unregisterAssignmentClock = registerAssignmentClock(job.assignment.id, assignmentClock)
    let preSessionTimer: DeadlineTimerHandle | undefined = assignmentClock.createDeadlineTimer(budget.wallClockMs, () => {
      preSessionTimer = undefined
      if (job.controller.signal.aborted) return
      this.host.wallClockRotatedAssignments.add(job.assignment.id)
      job.controller.abort(new Error(`Pre-session wall-clock deadline reached (${budget.wallClockMs}ms).`))
    })
    const clearPreSessionTimer = () => {
      if (preSessionTimer) { preSessionTimer.cancel(); preSessionTimer = undefined }
    }
    let session: Awaited<ReturnType<WorkerBackend['openSession']>>
    try {
      session = await this.backend.openSession(
        job.assignment.id,
        job.controller.signal,
        { warmPoolPolicy, ...(reposDir ? { reposDir } : {}) },
      )
    } catch (err) {
      clearPreSessionTimer()
      unregisterAssignmentClock()
      assignmentClock.dispose()
      throw err
    }

    // Per-turn generation latencies (provider stream) plus the no-token watchdog: 28 s of complete
    // provider silence aborts the turn, while every token re-arms the timer so slow streaming is
    // never killed. The old 45–90 s generation watchdog stays only as the wall-saved baseline.
    const turnLatencies: number[] = []
    let generationStartedAt: number | undefined
    const watchdogSpecialist = resolveSpecialistProfile(
      step.specialistProfile ?? routeStepToSpecialist({
        title: step.title,
        hypothesis: step.hypothesis,
        category: step.category,
        skills: step.skills,
      }),
    )
    const primaryProfile = resolveProfilePoolForRole(watchdogSpecialist.roleAffinity, profiles)[0] ?? profiles[0]
    const runtimePolicy = resolveProviderRuntimePolicy(primaryProfile, {
      role: watchdogSpecialist.roleAffinity,
      purpose: 'worker',
    })
    const noTokenThresholdMs = () => resolveProfileNoTokenWatchdogMs({
      model: runtimePolicy.model,
      thinkingLevel: runtimePolicy.thinkingLevel,
      roleAffinity: runtimePolicy.roleAffinity,
    })
    const streamTelemetry = createProviderStreamTelemetry(runtimePolicy.slowTurnThresholdMs)
    const stallAbortMs = () => providerStallAbortMs(percentile(turnLatencies, 50), turnLatencies.length)
    const stallWatchdog = new ProviderNoTokenWatchdog({
      thresholdMs: noTokenThresholdMs,
      onStall: ({ turn, idleMs, thresholdMs }) => {
        if (generationStartedAt === undefined) return
        generationStartedAt = undefined
        job.stallAbort = true
        streamTelemetry.recordStallAbort()
        const streamSnap = streamTelemetry.snapshot()
        this.host.providerStallTimeoutsByRun.set(run.id, (this.host.providerStallTimeoutsByRun.get(run.id) ?? 0) + 1)
        const previousThresholdMs = stallAbortMs()
        const wallSavedMs = Math.max(0, previousThresholdMs - idleMs)
        this.host.providerStallWallSavedByRun.set(run.id, (this.host.providerStallWallSavedByRun.get(run.id) ?? 0) + wallSavedMs)
        this.host.safeEvent(run.id, 'worker.provider_stall', `Provider stream stalled on turn ${turn} (${Math.round(idleMs / 1000)}s without a token); aborting to free the slot.`, {
          assignmentId: job.assignment.id, stepId: step.id, turn, elapsedMs: idleMs, thresholdMs,
          previousThresholdMs, wallSavedMs, stallAbortMs: stallAbortMs(), wallClockMs: budget.wallClockMs,
          stallAborts: streamSnap.stallAborts, slowTurns: streamSnap.slowTurns,
        })
        job.controller.abort(new Error('Provider stream stalled (no token).'))
      },
    })
    const armStallTimer = (turn: number) => {
      stallWatchdog.clear()
      generationStartedAt = Date.now()
      if (job.stallAbort) return
      stallWatchdog.arm(turn)
    }
    const noteProviderToken = () => stallWatchdog.noteToken()
    const recordTurnLatency = () => {
      if (generationStartedAt === undefined) return
      const ms = Math.max(0, Date.now() - generationStartedAt)
      generationStartedAt = undefined
      stallWatchdog.clear()
      turnLatencies.push(ms)
      if (streamTelemetry.recordCompletedTurn(ms, runtimePolicy.slowTurnThresholdMs)) {
        const slowTurns = this.host.providerStallTurnsByRun.get(run.id) ?? 0
        this.host.providerStallTurnsByRun.set(run.id, slowTurns + 1)
      }
    }

    const baselineCapIds = new Set(
      this.storage.capabilityLedger(run.id).listCapabilities().map(c => c.capId),
    )
    const sessionSealedCapHandles: string[] = []
    const checkpointOnlyGuard = createCheckpointOnlySessionGuard()
    let confirmedDuringAssignment = false
    let gapCodedDuringAssignment = false
    let enteredKovoVerify = false
    let inFlightProofCalls = 0
    let onProofCallEnter: (() => void) | undefined
    let onProofCallExit: (() => void) | undefined
    const trackProofCall = async <T>(fn: () => Promise<T>): Promise<T> => {
      inFlightProofCalls += 1
      try { onProofCallEnter?.() } catch (err) {
        this.noteLifecycleWarning(run.id, 'onProofCallEnter', err, { assignmentId: job.assignment.id, stepId: step.id })
      }
      try {
        return await fn()
      } finally {
        inFlightProofCalls = Math.max(0, inFlightProofCalls - 1)
        try { onProofCallExit?.() } catch (err) {
          this.noteLifecycleWarning(run.id, 'onProofCallExit', err, { assignmentId: job.assignment.id, stepId: step.id })
        }
      }
    }

    try {
      const stagedSpecs = await this.host.stageProjectSpecs(run.projectId, session, job.controller.signal)

      const neededParentFactIds = new Set(step.dependsOnFactIds)
      const parentFacts = neededParentFactIds.size > 0
        ? collectAllPages((offset, limit) =>
            this.storage.listFacts(run.id, { includeTainted: false, limit, offset }))
            .filter(f => neededParentFactIds.has(f.id) && permittedAtAdmission.has(f.origin))
        : []
      if (parentFacts.length) {
        await session.stage('parent-facts.json', JSON.stringify(parentFacts, null, 2), job.controller.signal).catch(() => undefined)
      }

      const trackPersonaResources = (curRun: Run, res: BrokerExchangeResult, exchangeId: string) => {
        const observedResources = this.storage.trackExchangeResources({
          runId: curRun.id,
          scopeRevision: curRun.scopeRevision,
          exchange: {
            origin: res.origin,
            method: res.method,
            pathAndQuery: res.pathAndQuery,
            personaHandle: res.personaHandle,
            status: res.status,
            mediaType: res.mediaType,
            body: res.body,
            respHeaders: res.respHeaders,
          },
          source: 'surface_probe',
        })
        if (!observedResources.length || !res.personaHandle) return
        if (curRun.capabilityTier < 2 || (grant.personas?.size ?? 0) < 2) return
        let seenSet = this.host.recordedPersonaResources.get(curRun.id)
        if (!seenSet) {
          seenSet = new Set<string>()
          this.host.recordedPersonaResources.set(curRun.id, seenSet)
        }
        for (const item of observedResources) {
          if (item.resourceId === '[redacted]') continue
          const dedupKey = `${res.origin}|${res.personaHandle}|${item.endpoint}|${item.resourceId}`
          if (seenSet.has(dedupKey)) continue
          seenSet.add(dedupKey)
          this.storage.addFact(curRun, job.assignment, {
            kind: 'persona_resource',
            origin: res.origin,
            summary: `Persona "${res.personaHandle}" observed owned resource ${item.field}=${item.resourceId} at ${item.method} ${item.endpoint} (HTTP ${res.status}).`,
            data: {
              ownerPersona: res.personaHandle,
              resourceId: item.resourceId,
              endpoint: item.endpoint,
              method: item.method,
              field: item.field,
              status: res.status,
            },
            exchangeIds: [exchangeId],
            sourceOrigins: [res.origin],
            secrets: currentSecrets(),
          })
        }
      }

      const boardHandle = this.host.boardHandleByAssignment.get(job.assignment.id) ??
        this.host.board.boardHandleForAssignmentId(run, job.assignment.id)
      const boardTools = createBoardTools({
        store: this.storage,
        run: run.id,
        handle: boardHandle,
        redact: (text: string) => redact(text, currentSecrets()),
        onWakeup: (target, message) => {
          try {
            this.host.board.wakeBoardMember(this.storage.run(run.id), target, message)
          } catch (err) {
            this.noteLifecycleWarning(run.id, 'board.wakeBoardMember', err, { assignmentId: job.assignment.id, target })
          }
        },
      })

      const prepareBudgetedProbe = (origin: string, requestedMax: number | undefined, defaultMax: number) => {
        const curRun = this.host.check(job)
        if (this.storage.checkBudgetExceeded(curRun.id)) throw new BudgetExceededError('Run spend or request budget exceeded.')
        const cleanOrigin = this.host.parseOriginForRun(curRun, origin)
        const remainingReqs = this.host.phaseRequestRemaining(curRun) ?? (requestedMax ?? defaultMax)
        if (remainingReqs <= 0) throw new BudgetExceededError('Agent request budget exhausted.')
        const cappedMax = requestedMax !== undefined ? Math.min(requestedMax, remainingReqs) : Math.min(defaultMax, remainingReqs)
        return { curRun, cleanOrigin, remainingReqs, cappedMax }
      }
      const egressSecrets = (extra: readonly NamedSecret[] = []): NamedSecret[] => [
        ...currentSecrets(),
        ...(typeof this.broker.getRegisteredSecrets === 'function' ? this.broker.getRegisteredSecrets() : []),
        ...extra,
      ]
      const workerEgress = createEgressSanitizer({
        secrets: () => egressSecrets(),
        capabilityVaults: () => [this.host.capabilityVaultFor(run.id)],
      })
      const stageJsonArtifact = async (
        curRun: Run,
        kind: 'dns' | 'tls' | 'browser' | 'surface' | 'ws',
        title: string,
        filename: string,
        payload: unknown,
        signal: AbortSignal,
        secretsList: readonly NamedSecret[] = currentSecrets(),
      ) => {
        const artifactEgress = createEgressSanitizer({
          secrets: () => egressSecrets(secretsList),
          capabilityVaults: () => [this.host.capabilityVaultFor(curRun.id)],
        })
        const sanitizedPayload = kind === 'browser'
          ? artifactEgress.sanitizeBrowserResult(payload)
          : artifactEgress.sanitizeValue(payload, 'worker_rpc')
        const serialized = JSON.stringify(sanitizedPayload, null, 2)
        const ev = this.storage.addArtifact(curRun, job.assignment, kind, title, serialized, undefined, egressSecrets(secretsList))
        const stagedPath = await session.stage(filename.replace('{id}', ev.id.slice(0, 8)), serialized, signal).catch(() => null)
        return { evidenceId: ev.id, stagedPath }
      }
      const verifyInline = (
        spec: DeclarativeReplaySpec,
        findingId?: string,
        replaySpecId?: string,
        deferredCandidate?: InlineDeferredFindingCandidate,
      ) =>
        trackProofCall(() =>
          this.host.executeInlineVerification({
            job, grant, currentSecrets, reposDir, spec, findingId, replaySpecId, deferredCandidate, onExchangeObserved: trackPersonaResources,
          }),
        )
      const makeTrackedExchangeRecorder = (curRun: Run) =>
        createExchangeRecorder(this.storage, () => curRun, job.assignment.id, currentSecrets, {
          onSaved: (r, e, id) => {
            trackPersonaResources(r, e, id)
            this.host.scanSecondOrderExchange(r, job.assignment.id, e, id)
          },
        })

      const personasPub = sortPersonasLowPrivFirst(publicPersonasFromGrant(grant))
      const multiPersonaAuthzRe = /\b(?:authz|bola|bfla|idor|abac|broken[_ -]?access[_ -]?control|access[_ -]?control|cross[_ -]?tenant)\b/i
      const multiStepWorkflowRe = /\b(?:workflow|business[_ -]?logic|lifecycle|chain|race|state[_ -]?machine|multi[_ -]?hop|multihop)\b/i
      const whiteboxFileLineRe = /(?:\/repos\/[^\s:,)'"`]+|(?:^|[\s(`'"])[A-Za-z0-9_.-]+(?:\/[A-Za-z0-9_.-]+)+\.(?:ts|tsx|js|jsx|mjs|cjs|py|go|rb|java|kt|rs|php|cs|sql|yaml|yml|tf|hcl|rego)):[1-9]\d*/
      let prematureRuledOutStrikes = 0
      const guardPrematureRuledOut = (check: {
        runId: string
        origins: readonly string[]
        status: string
        category?: string
        hypothesisClass?: string
        summary?: string
        enforcingControl?: string
        exchangeIds?: readonly string[]
      }) => {
        if (check.status !== 'ruled_out' && check.status !== 'no_issue_found') return
        if (prematureRuledOutStrikes >= 1) return
        const corpus = [check.category, check.hypothesisClass, step.category, step.title, step.hypothesis, step.skills.join(' ')].filter(Boolean).join(' ')
        const isAuthz = multiPersonaAuthzRe.test(corpus)
        const stepLane = (step as { lane?: string | null }).lane
        const isWorkflowOrChain = multiStepWorkflowRe.test(corpus)
          || isMultiHopChainStep(step)
          || stepLane === 'workflow'
          || stepLane === 'business_logic'
        if (!((isAuthz && personasPub.length >= 2) || isWorkflowOrChain)) return
        const citationText = `${check.enforcingControl ?? ''} ${check.summary ?? ''}`
        if (whiteboxFileLineRe.test(citationText)) return
        const extractedIds = [
          ...(check.exchangeIds ?? []),
          ...(check.enforcingControl?.match(/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/gi) ?? []),
          ...(check.enforcingControl?.match(/\b(?:gx|ex)[_-][A-Za-z0-9._-]{2,80}\b/g) ?? []),
        ]
        const ev = FindingsRepository.inspectCoverageExchangeEvidence(
          this.storage.db,
          check.runId,
          check.origins,
          extractedIds.length > 0 ? extractedIds : undefined,
          extractedIds.length > 0 ? undefined : job.assignment.id,
        )
        const needsMultiPersona = isAuthz && personasPub.length >= 2
        const hasEnoughPersonas = !needsMultiPersona || ev.distinctPersonas.length >= 2
        const hasEnoughSteps = ev.distinctExchanges >= 2 && !(ev.allDenial403Or404 && ev.distinctPersonas.length < 2)
        if (hasEnoughPersonas && hasEnoughSteps) return
        prematureRuledOutStrikes += 1
        throw new Error(
          `Premature "${check.status}" rejected (strike 1/1): multi-persona/multi-step class requires an exact /repos file:line citation or concrete run broker_exchanges evidence (>= 2 distinct exchanges${needsMultiPersona ? ' and >= 2 distinct personas or auth+unauth' : ''}, not a single 403/404 probe; observed ${ev.distinctExchanges} exchange(s), ${ev.distinctPersonas.length} persona(s)). Run the missing cross-persona/multi-step check OR call record_coverage(status="needs_follow_up", proofGapReason="<code>").`,
        )
      }

      const sharedHandlers = this.buildSharedSessionHandlers(job, session, currentSecrets, {
        offlineScriptLabel: 'Offline {runtime} script',
        deriveEvidenceTitle: 'Derived evidence',
        onFactRecorded: curRun => {
          boardTools.noteEvidence()
          this.host.schedulePlanner(curRun.id)
        },
        guardPrematureRuledOut,
      })
      const recordedExchanges = new Map<string, RecordedRequestExchange>()
      const transportHandlers = this.host.buildBrokeredTransportHandlers({
        job, step, session, grant, currentSecrets, boardTools, sharedHandlers,
        trackPersonaResources, prepareBudgetedProbe, stageJsonArtifact,
        onExchangeRecorded: ex => { recordedExchanges.set(ex.exchangeId, ex) },
      })

      const handlers: WorkerToolHandlers = {
        ...sharedHandlers,
        ...transportHandlers,

        board_post: async (args) => boardTools.board_post(args),
        board_read: async (args) => boardTools.board_read(args),

        inspect_dns: async ({ origin }, signal) => {
          const curRun = this.host.check(job)
          const dnsRes = await this.broker.inspectDns(origin, grant, signal)
          const staged = await stageJsonArtifact(
            curRun, 'dns', `DNS inspection · ${dnsRes.hostname}`,
            `dns-${dnsRes.hostname.replace(/[^a-z0-9.-]/gi, '_')}.json`, dnsRes, signal, secrets,
          )
          return { ...staged, ...dnsRes }
        },

        inspect_tls: async ({ origin }, signal) => {
          const curRun = this.host.check(job)
          const tlsRes = await this.broker.inspectTls(origin, grant, signal)
          const staged = await stageJsonArtifact(
            curRun, 'tls', `TLS audit · ${tlsRes.hostname}`,
            `tls-${tlsRes.hostname.replace(/[^a-z0-9.-]/gi, '_')}.json`, tlsRes, signal, secrets,
          )
          return { ...staged, ...tlsRes }
        },

        browser_session: async ({ steps }, signal) => {
          const curRun = this.host.check(job)
          if (this.storage.checkBudgetExceeded(curRun.id)) throw new BudgetExceededError('Budget exceeded.')
          const visits = await this.browser.runBrowserSession(
            steps.map(s => ({
              ...s,
              runId: curRun.id,
              assignmentId: job.assignment.id,
              secrets: egressSecrets(),
              onExchange: createExchangeRecorder(this.storage, () => curRun, job.assignment.id, currentSecrets, {
                onSaved: (r, e, id) => {
                  trackPersonaResources(r, e, id)
                  this.host.scanSecondOrderExchange(r, job.assignment.id, e, id)
                },
              }),
            })),
            grant,
            signal,
          )
          const summarized = workerEgress.sanitizeBrowserResult(
            visits.map(({ exchanges: _ex, ...rest }) => ({
              ...rest,
              domSnippet: rest.domSnippet.slice(0, 2000),
            })),
          )
          const ev = this.storage.addArtifact(curRun, job.assignment, 'browser',
            `Browser session (${steps.length} steps)`,
            JSON.stringify(summarized, null, 2), undefined, egressSecrets())
          return { evidenceId: ev.id, stepsCount: visits.length, visits: summarized }
        },

        crawl_state_graph: async (args, signal) => {
          const curRun = this.host.check(job)
          if (this.storage.checkBudgetExceeded(curRun.id)) throw new BudgetExceededError('Budget exceeded.')
          const cleanOrigin = this.host.parseOriginForRun(curRun, args.origin)
          const remainingReqs = this.host.phaseRequestRemaining(curRun) ?? undefined
          if (remainingReqs !== undefined && remainingReqs <= 0) {
            throw new BudgetExceededError('Agent request budget exhausted.')
          }
          return await crawlStateGraph({
            storage: this.storage,
            runId: curRun.id,
            scopeRevision: curRun.scopeRevision,
            origin: cleanOrigin,
            personas: args.personas,
            maxPages: args.maxPages,
            maxDepth: args.maxDepth,
            budgetRemaining: remainingReqs,
            browser: this.browser,
            grant,
            signal,
            assignmentId: job.assignment.id,
          })
        },

        probe_surface: async (args, signal) => {
          const { curRun, cleanOrigin, cappedMax } = prepareBudgetedProbe(args.origin, args.maxRequests, 150)
          const safeParams = args.mode === 'params' && args.candidates?.length
            ? args.candidates.map(candidate => assertSafeParamName(candidate, 'candidates'))
            : undefined
          const res = await probeSurface({
            origin: cleanOrigin,
            mode: args.mode,
            wordlists: args.wordlists?.length ? args.wordlists : (args.wordlist ? [args.wordlist] : undefined),
            paths: args.mode === 'paths' ? args.candidates : undefined,
            params: safeParams,
            basePath: args.basePath,
            paramLocation: args.paramLocation,
            methods: args.methods,
            persona: args.persona,
            maxRequests: cappedMax,
            onExchange: makeTrackedExchangeRecorder(curRun),
          }, this.broker, grant, signal)

          this.host.markEndpointCoverage(curRun, res.origin, args.methods?.[0] ?? 'GET', args.basePath ?? '/', `surface:${res.mode}`)
          this.storage.recordSurfaceProbe({
            runId: curRun.id, assignmentId: job.assignment.id, scopeRevision: curRun.scopeRevision,
            origin: res.origin, probeKind: `surface:${res.mode}`,
            requestsSent: res.requestsSent, anomaliesFound: res.anomalies.length, baselineSignature: res.baselineSignature,
          })
          const staged = await stageJsonArtifact(curRun, 'surface', `Surface probe (${res.mode}) · ${res.origin}`, 'surface-{id}.json', res, signal)
          return { ...staged, ...res }
        },

        probe_differential: async (args, signal) => {
          const { curRun, cleanOrigin, cappedMax } = prepareBudgetedProbe(args.origin, args.maxRequests, 60)

          // R2-C-2: Reject prototype-accessor segments in worker-supplied parameter paths before injection.
          const explicitParamName = args.paramName !== undefined
            ? assertSafeParamName(args.paramName, 'paramName')
            : undefined
          const explicitSsrfParams = args.ssrfParams?.length
            ? args.ssrfParams.map(name => assertSafeParamName(name, 'ssrfParams'))
            : undefined

          const requestedTemplate = normalizeEndpointTemplate(args.pathAndQuery.split('?')[0] || '/')
          const originEndpoints = this.storage.listEndpoints(curRun.id, { origin: cleanOrigin })
          const targetEndpoint = originEndpoints.find(ep => ep.pathTemplate === requestedTemplate && (!args.method || ep.method === args.method.toUpperCase()))
            ?? originEndpoints.find(ep => ep.pathTemplate === requestedTemplate)
          const targetParams = targetEndpoint ? this.storage.listEndpointParams(curRun.id, targetEndpoint.id) : []
          const injectableParams = targetParams.filter(p =>
            ['query', 'json', 'form', 'path', 'graphql_var'].includes(p.location)
            && !p.isCsrf
            && isSafeParamName(p.name),
          )
          const preferredParam = [...injectableParams].sort((a, b) =>
            Number(DETERMINISTIC_PARAM_HINT_RE.test(b.name)) - Number(DETERMINISTIC_PARAM_HINT_RE.test(a.name)) ||
            Number(a.isObjectId) - Number(b.isObjectId),
          )[0]
          const resolvedParamName = explicitParamName ?? preferredParam?.name
          const resolvedParamLocation = args.paramLocation ?? (preferredParam && preferredParam.location !== 'cookie' ? preferredParam.location : undefined)
          const resourceSamples = this.storage.listResourceSamples(curRun.id)
            .filter(sample => sample.origin === cleanOrigin && sample.resourceId !== '[redacted]')
          const matchingResourceIds = [...new Set([
            ...resourceSamples
              .filter(sample => normalizeEndpointTemplate(sample.endpoint) === requestedTemplate ||
                requestedTemplate.includes(`:${sample.resourceKey}`) ||
                requestedTemplate.split('/').includes(sample.resourceId))
              .map(sample => sample.resourceId),
            ...resourceSamples.map(sample => sample.resourceId),
          ])].slice(0, 10)
          const resolvedResourceIds = args.resourceIds?.length ? args.resourceIds : matchingResourceIds
          const resolvedSsrfParams = explicitSsrfParams
            ?? injectableParams
                .map(param => param.name)
                .filter(name => /(?:url|uri|link|redirect|callback|dest|host|path|file|fetch|webhook|next|return)/i.test(name))
                .slice(0, 16)

          if (args.probeClass === 'ssrf_canary') await this.host.ensureCanaryListenerForRun(curRun, true)

          const res = await probeDifferential({
            probeClass: args.probeClass,
            origin: cleanOrigin,
            pathAndQuery: args.pathAndQuery,
            method: args.method,
            param: resolvedParamName,
            paramLocation: resolvedParamLocation,
            jsonBody: args.body,
            baselineValue: args.baselineValue,
            persona: args.persona,
            headers: args.headers,
            ssrfParams: resolvedSsrfParams,
            resourceIds: resolvedResourceIds,
            ownerPersona: args.persona,
            otherPersona: args.otherPersona,
            runId: curRun.id,
            assignmentId: job.assignment.id,
            storage: this.storage,
            maxRequests: cappedMax,
            onExchange: makeTrackedExchangeRecorder(curRun),
          }, this.broker, grant, this.canaryBroker, signal)

          this.host.markEndpointCoverage(curRun, res.origin, args.method ?? 'GET', args.pathAndQuery, `diff:${res.probeClass}`)
          this.storage.recordSurfaceProbe({
            runId: curRun.id, assignmentId: job.assignment.id, scopeRevision: curRun.scopeRevision,
            origin: res.origin, probeKind: `diff:${res.probeClass}`,
            requestsSent: res.requestsSent, anomaliesFound: res.anomalies.length, baselineSignature: res.verdict,
          })
          const staged = await stageJsonArtifact(
            curRun, 'surface', `Differential probe (${res.probeClass}) · ${res.origin}${args.pathAndQuery.slice(0, 48)}`,
            'diff-{id}.json', res, signal,
          )
          return { ...staged, ...res }
        },

        query_cves: async (args, signal) => {
          const res = await sharedHandlers.query_cves!(args, signal)
          return {
            ...res,
            note: 'Advisories are hypotheses only. Record a cve_hypothesis fact and verify reachability with a non-destructive Replay Spec before confirming.',
          }
        },

        mint_canary: async ({ purpose }) => {
          const curRun = this.host.check(job)
          await this.host.ensureCanaryListenerForRun(curRun)
          return this.canaryBroker.mintCanary(curRun.id, purpose, targetOrigins[0], {
            storage: this.storage,
            assignmentId: job.assignment.id,
          })
        },

        check_canary: async ({ token }) => {
          const curRun = this.host.check(job)
          const result = this.canaryBroker.checkCanary(token, { storage: this.storage, runId: curRun.id })
          if (result.hit) {
            const detail = (result.detail ?? {}) as { origin?: unknown; path?: unknown; pathAndQuery?: unknown; persona?: unknown }
            const origin = typeof detail.origin === 'string' && this.host.permitted(curRun, detail.origin)
              ? detail.origin
              : [...this.host.approvedOriginsSet(curRun)][0]
            const endpoint = typeof detail.pathAndQuery === 'string'
              ? detail.pathAndQuery
              : typeof detail.path === 'string' ? detail.path : undefined
            if (origin) {
              this.host.postCanaryLead(curRun, {
                origin,
                endpoint,
                persona: typeof detail.persona === 'string' ? detail.persona : null,
                key: `${curRun.id}:canary:${token}`,
              })
            }
          }
          return result
        },

        mint_second_order_canary: async (args) => {
          const curRun = this.host.check(job)
          const cleanOrigin = this.host.parseOriginForRun(curRun, args.injectedOrigin)
          await this.host.ensureCanaryListenerForRun(curRun)
          const minted = this.canaryBroker.mintSecondOrderCanary({
            runId: curRun.id,
            assignmentId: job.assignment.id,
            injectedOrigin: cleanOrigin,
            injectedEndpoint: args.injectedEndpoint,
            injectedParam: args.injectedParam,
            injectedPersona: args.injectedPersona ?? null,
            storage: this.storage,
          })
          return {
            canaryId: minted.id ?? null,
            id: minted.id ?? null,
            marker: minted.marker,
            httpUrl: minted.httpUrl,
            dnsHost: minted.dnsHost,
            injectedOrigin: minted.injectedOrigin,
            injectedEndpoint: minted.injectedEndpoint,
            injectedParam: minted.injectedParam,
            injectedPersona: minted.injectedPersona,
            listenerActive: this.canaryBroker.listenerInfo().running,
            note: 'Place the marker verbatim in a stored field, then inspect list_second_order_canaries after other personas/renders read it back. A surfaced cross-persona or HTML surface is a high-priority lead, not a confirmed finding.',
          }
        },

        list_second_order_canaries: async ({ status }) => {
          const curRun = this.host.check(job)
          return this.storage.listSecondOrderCanaries(curRun.id, status)
        },

        search_exchanges: async ({ query, origin, status, limit }) => {
          const curRun = this.host.check(job)
          const currentApproved = this.host.approvedOriginsSet(curRun)
          const rows = this.storage.searchExchanges(curRun.id, query, { approvedOrigins: currentApproved, origin, limit })
          return rows
            .filter(ex => status === undefined || ex.status === status)
            .map(ex => ({
              id: ex.id, exchangeId: ex.id, origin: ex.origin, method: ex.method, pathAndQuery: ex.pathAndQuery,
              status: ex.status, mediaType: ex.mediaType, bodyPreview: ex.bodyPreview.slice(0, 600),
            }))
        },

        get_exchange: async ({ exchangeId, includeBody }, signal) => {
          const curRun = this.host.check(job)
          const currentApproved = this.host.approvedOriginsSet(curRun)
          const ex = this.storage.getExchange(curRun.id, exchangeId)
          if ([ex.origin, ex.finalOrigin, ...ex.redirectOrigins].some(o => !currentApproved.has(o))) {
            throw new BrokerDenied('Exchange touches an origin outside current approved scope.')
          }
          let stagedPath: string | null = null
          if (includeBody) {
            stagedPath = await session.stage(`exchanges/${ex.id}.json`, JSON.stringify(ex, null, 2), signal).catch(() => null)
          }
          return {
            ...ex, exchangeId: ex.id,
            body: includeBody ? ex.body.slice(0, 12_000) : undefined,
            stagedPath,
          }
        },

        read_peer_trace: async ({ assignmentId, limit }) => {
          const curRun = this.host.check(job)
          const currentApproved = this.host.approvedOriginsSet(curRun)
          const peers = this.storage.workerList(curRun.id)
            .filter(w => (!assignmentId || w.id === assignmentId) && w.sourceOrigins.every(o => currentApproved.has(o)))
            .slice(-(limit ?? 15))
          return peers.map(p => ({
            id: p.id, phase: p.phase, status: p.status, title: p.title, outcome: p.outcome,
            turnsUsed: p.turnsUsed, requestsUsed: p.requestsUsed,
            facts: this.storage.listFacts(curRun.id, { includeTainted: false, limit: 20 })
              .filter(f => f.assignmentId === p.id)
              .map(f => ({ id: f.id, kind: f.kind, origin: f.origin, summary: f.summary })),
          }))
        },

        expand_digest: async ({ digestId }) => {
          const curRun = this.host.check(job)
          const currentApproved = this.host.approvedOriginsSet(curRun)
          try {
            const expanded = this.storage.getDigest(curRun.id, digestId)
            return { digest: expanded.digest, facts: expanded.facts.filter(f => currentApproved.has(f.origin)) }
          } catch {
            return { error: 'Digest not found.' }
          }
        },

        propose_chain_finding: async (args) => {
          const { replaySpec, chainFactIds, exchangeIds } = args
          const ext = args as typeof args & {
            counterevidence?: string
            confidenceRationale?: string
            severityChangeConditions?: string
            codeLocations?: CodeLocation[]
          }
          const curRun = this.host.check(job)
          const currentApproved = this.host.approvedOriginsSet(curRun)
          const parsed = declarativeReplaySpecSchema.parse(stripUntrustedReplayEnvelopes(replaySpec))
          const specOrigins = replaySpecOrigins(parsed)
          if (specOrigins.some(o => !currentApproved.has(o))) {
            throw new BrokerDenied('Replay spec references an origin outside current approved scope.')
          }
          const isStaticAst = parsed.kind === 'static_ast_proof'
          const isLiveRuntimeRun = isLiveRuntimeVerificationRun(
            curRun,
            this.host.verifier.backendSupportsVerifyScript(),
          )
          if (isStaticAst && isLiveRuntimeRun) {
            // On live-target runs with runtime verification available, static AST pattern matches
            // cannot distinguish hardened/decoy controls from runtime-exploitable defects. Keep the
            // observation strictly as a quarantined `code_audit_suspect` fact (never a findings or
            // replay_specs row) and direct the worker to prove exploitability with `kovo_verify`.
            const suspectOrigin = currentApproved.has(parsed.origin)
              ? parsed.origin
              : [...currentApproved][0] ?? parsed.origin
            const locKey = `${parsed.repo}/${parsed.file}:${parsed.startLine}`
            let recordedFactId: string | undefined
            try {
              const existingSuspect = this.storage
                .listFacts(curRun.id, { includeTainted: false, kind: 'code_audit_suspect', limit: 200 })
                .find(f =>
                  f.data?.repo === parsed.repo
                  && f.data?.file === parsed.file
                  && f.data?.startLine === parsed.startLine
                  && f.data?.demotedFrom === 'static_ast_proof',
                )
              if (existingSuspect) {
                recordedFactId = existingSuspect.id
              } else {
                const fact = this.storage.addFact(curRun, job.assignment, {
                  kind: 'code_audit_suspect',
                  origin: suspectOrigin,
                  summary: `[static_ast suspect] ${parsed.title} (${locKey}-${parsed.endLine})`.slice(0, 320),
                  data: {
                    subkind: 'code_audit_suspect',
                    demotedFrom: 'static_ast_proof',
                    repo: parsed.repo,
                    file: parsed.file,
                    startLine: parsed.startLine,
                    endLine: parsed.endLine,
                    cwe: parsed.cwe,
                    category: parsed.category,
                    engine: parsed.engine,
                    ruleOrPattern: parsed.ruleOrPattern,
                    ...(parsed.sourceToSinkTrace ? { sourceToSinkTrace: parsed.sourceToSinkTrace } : {}),
                  },
                  sourceOrigins: [...specOrigins.filter(o => currentApproved.has(o))],
                  secrets: currentSecrets(),
                })
                recordedFactId = fact.id
                boardTools.noteEvidence()
                this.host.schedulePlanner(curRun.id)
              }
            } catch (err) {
              this.noteLifecycleWarning(run.id, 'propose_chain_finding.static_suspect_fact', err, { assignmentId: job.assignment.id, stepId: step.id })
            }
            const factNote = recordedFactId ? ` Recorded static observation as code_audit_suspect fact ${recordedFactId}.` : ''
            throw new Error(`${STATIC_AST_LIVE_TARGET_REJECT_MESSAGE}${factNote}`)
          }
          const asset = curRun.candidates.find(c => c.origin === parsed.origin && curRun.approved.includes(c.id))
            ?? (isStaticAst ? curRun.candidates.find(c => curRun.approved.includes(c.id)) : undefined)
          if (!asset) throw new BrokerDenied(`Primary finding origin ${parsed.origin} is not in approved scope.`)

          const knownFactIds = new Set(
            collectAllPages((offset, limit) =>
              this.storage.listFacts(curRun.id, { includeTainted: false, limit, offset })).map(f => f.id),
          )
          const validFactIds = chainFactIds.filter(fid => knownFactIds.has(fid))
          const sourceOrigins = new Set<string>(
            isStaticAst
              ? [...specOrigins.filter(o => currentApproved.has(o))]
              : [...specOrigins, ...targetOrigins],
          )

          const specDedupeFields = extractSpecDedupeFields(parsed)
          const { rows: existingRows, refs: existingRefs } = buildExistingFindingRefs(
            this.storage, curRun.id, curRun.goalRevision, { chainOnly: true, includeDescriptions: true },
          )

          const dedupeLlmCall = profiles.length
            ? createProviderLlmCall(profiles, {
                signal: job.controller.signal,
                secrets: currentSecrets(),
                onUsage: u => this.storage.recordLlmSpend(curRun.id, { usd: u.costUsd, tokens: u.inputTokens + u.outputTokens }),
              })
            : undefined
          const dedupeDecision = await evaluateSubmissionDedupe({
            candidate: {
              origin: parsed.origin,
              title: parsed.title,
              cwe: parsed.cwe,
              category: parsed.category,
              severity: parsed.severity,
              endpoint: specDedupeFields.endpoint,
              authState: specDedupeFields.authState,
              specKind: specDedupeFields.specKind,
              method: specDedupeFields.method,
              param: specDedupeFields.param,
              graphqlField: specDedupeFields.graphqlField,
              mutated: specDedupeFields.mutated ?? null,
              reason: parsed.severityRationale,
              impact: parsed.impact,
              remediation: parsed.remediation,
              sourceOrigins: [...sourceOrigins],
            },
            existingFindings: existingRefs,
            llmCall: dedupeLlmCall,
          })

          const matchedRow = dedupeDecision.duplicateOfId
            ? existingRows.find(r => r.id === dedupeDecision.duplicateOfId)
            : undefined

          if (dedupeDecision.action === 'reject_duplicate' && matchedRow) {
            return {
              findingId: matchedRow.id,
              replaySpecId: matchedRow.replaySpecId,
              status: matchedRow.finding.status,
              deduplicated: true,
              rejected: true,
              stage: dedupeDecision.stage,
              rationale: dedupeDecision.rationale,
              instruction: dedupeDecision.instruction ??
                `Duplicate of existing finding ${matchedRow.id}. Use update_proposed_finding(findingId="${matchedRow.id}") if your replay spec proves higher impact or adds new chain steps.`,
            }
          }

          const dbDupRow = this.storage.findDuplicateChainFinding(curRun.id, curRun.goalRevision, {
            origin: parsed.origin,
            cwe: parsed.cwe,
            category: parsed.category,
            title: parsed.title,
            fingerprintHash: dedupeDecision.fingerprintHash,
            endpoint: specDedupeFields.endpoint,
            method: specDedupeFields.method,
            param: specDedupeFields.param,
            graphqlField: specDedupeFields.graphqlField,
          })
          const matchedCandidates = [matchedRow, dbDupRow].filter(
            (row, idx, arr): row is NonNullable<typeof row> =>
              Boolean(row) && arr.findIndex(other => other?.id === row!.id) === idx,
          )
          const verifiedMatch = matchedCandidates.find(
            r => r.finding.status === 'confirmed' || r.finding.status === 'static_verified',
          )

          if (verifiedMatch) {
            const ev = this.storage.addArtifact(curRun, job.assignment, 'replay',
              `Additional corroborating spec · ${parsed.title}`,
              JSON.stringify({ existingFindingId: verifiedMatch.id, dedupeStage: dedupeDecision.stage, spec: parsed }, null, 2),
              undefined, currentSecrets())
            const merged = this.storage.upsertChainFinding(
              curRun,
              verifiedMatch.assetId,
              {
                ...verifiedMatch.finding,
                severity: verifiedMatch.finding.severity,
                fingerprintHash: verifiedMatch.fingerprintHash ?? dedupeDecision.fingerprintHash,
                counterevidence: ext.counterevidence ?? verifiedMatch.counterevidence ?? verifiedMatch.finding.counterevidence,
                confidenceRationale: ext.confidenceRationale ?? verifiedMatch.confidenceRationale ?? verifiedMatch.finding.confidenceRationale,
                severityChangeConditions: ext.severityChangeConditions ?? verifiedMatch.severityChangeConditions ?? verifiedMatch.finding.severityChangeConditions,
                ...(ext.codeLocations?.length ? { codeLocations: ext.codeLocations } : {}),
                chainFactIds: [...new Set([...(verifiedMatch.finding.chainFactIds ?? []), ...validFactIds])],
                exchangeIds: [...new Set([...(verifiedMatch.finding.exchangeIds ?? []), ...exchangeIds])],
                evidenceIds: [...new Set([...verifiedMatch.finding.evidenceIds, ev.id])],
                scopeRevision: curRun.scopeRevision,
              },
              verifiedMatch.replaySpecId ?? verifiedMatch.finding.replaySpecId ?? '',
              [...sourceOrigins],
            )
            return {
              findingId: merged.id,
              replaySpecId: merged.replaySpecId,
              status: merged.status,
              deduplicated: true,
              stage: dedupeDecision.stage,
              note: `Merged corroborating evidence into existing verified finding ${merged.id}. Call update_proposed_finding if you need to replace its Replay Spec.`,
            }
          }

          const canonicalMatchedRow = matchedRow ?? dbDupRow
          const maxAttempts = 1 + maxInlineVerifyRetries
          const priorMaxAttempts = canonicalMatchedRow
            ? Math.max(
                0,
                ...matchedCandidates.flatMap(r =>
                  this.storage.listReplaySpecsForFinding(curRun.id, r.id).map(s => s.attemptCount),
                ),
              )
            : 0
          if (canonicalMatchedRow && priorMaxAttempts >= maxAttempts) {
            return {
              findingId: canonicalMatchedRow.id,
              replaySpecId: canonicalMatchedRow.replaySpecId,
              status: canonicalMatchedRow.finding.status,
              ...(canonicalMatchedRow.verificationTier ? { verificationTier: canonicalMatchedRow.verificationTier } : {}),
              severity: canonicalMatchedRow.finding.severity,
              deduplicated: true,
              rejected: true,
              isError: true,
              inlineVerifyFeedback: retryLimitExceededFeedback(
                maxAttempts,
                `Inline verification retry limit reached for existing finding ${canonicalMatchedRow.id} (maxInlineVerifyRetries=${maxInlineVerifyRetries}).`,
              ),
            }
          }

          const codeLocations: CodeLocation[] | undefined = ext.codeLocations?.length
            ? ext.codeLocations
            : isStaticAst
              ? [{
                  repo: parsed.repo,
                  file: parsed.file,
                  startLine: parsed.startLine,
                  endLine: parsed.endLine,
                  label: parsed.sourceToSinkTrace?.slice(0, 180),
                }]
              : undefined

          const findingId = canonicalMatchedRow?.id ?? randomUUID()
          const verifyNow = args.verifyNow ?? true
          const chainTags = step.skills.filter(skill => skill.startsWith('chain:')).map(skill => skill.slice('chain:'.length))

          if (isLiveRuntimeRun && !canonicalMatchedRow) {
            // Live-target verify-before-persist: never write an unverified `pending` / `inconclusive`
            // row into `findings` before inline verification confirms runtime exploitability.
            const deferredFinding = buildChainFindingBase(parsed, findingId, 'pending-inline', curRun.scopeRevision, {
              status: 'pending',
              confidence: 'medium',
              verification: `Pending Zero-LLM ${parsed.kind} inline replay verification.${chainTags.length ? ` Chain primitives: ${chainTags.join(', ')}.` : ''}`,
              fingerprintHash: dedupeDecision.fingerprintHash,
              counterevidence: ext.counterevidence ?? null,
              confidenceRationale: ext.confidenceRationale ?? null,
              severityChangeConditions: ext.severityChangeConditions ?? null,
              ...(codeLocations?.length ? { codeLocations } : {}),
              chainFactIds: validFactIds,
              exchangeIds: [...new Set(exchangeIds)],
              evidenceIds: [],
            })
            const inline = await verifyInline(parsed, findingId, undefined, {
              assetId: asset.id,
              finding: deferredFinding,
              sourceOrigins: [...sourceOrigins],
              validFactIds,
            })
            if (inline.status === 'confirmed' && inline.findingId) {
              confirmedDuringAssignment = true
              boardTools.noteEvidence()
              this.host.schedulePlanner(curRun.id)
              return {
                findingId: inline.findingId,
                replaySpecId: inline.replaySpecId,
                status: inline.status,
                verificationTier: inline.verificationTier,
                inlineVerifyFeedback: inline.feedback,
                deduplicated: false,
                upgraded: false,
                note: `Inline Zero-LLM verification succeeded (${inline.status}).`,
              }
            }
            return {
              findingId: null,
              replaySpecId: inline.replaySpecId,
              status: inline.status,
              persisted: false,
              inlineVerifyFeedback: inline.feedback,
              deduplicated: false,
              upgraded: false,
              note: `Inline Zero-LLM verification returned ${inline.status}; no unverified finding was persisted. Prove runtime exploitability via kovo_verify or repair the proof (${inline.feedback.retriesRemaining} retries remaining).`,
            }
          }

          const specRow = this.storage.createReplaySpec(
            curRun,
            job.assignment,
            findingId,
            parsed,
            [...sourceOrigins],
            { initialAttemptCount: canonicalMatchedRow ? priorMaxAttempts : 0 },
          )
          boardTools.noteEvidence()
          const ev = this.storage.addArtifact(curRun, job.assignment, 'replay',
            `Proposed replay spec · ${parsed.title}`,
            JSON.stringify({ replaySpecId: specRow.id, specSha256: specRow.specSha256, spec: parsed }, null, 2),
            undefined, currentSecrets())
          const finding = buildChainFindingBase(parsed, findingId, specRow.id, curRun.scopeRevision, {
            status: 'pending',
            confidence: 'medium',
            verification: `Pending Zero-LLM ${parsed.kind} replay verification (spec ${specRow.id}).${chainTags.length ? ` Chain primitives: ${chainTags.join(', ')}.` : ''}`,
            fingerprintHash: dedupeDecision.fingerprintHash,
            counterevidence: ext.counterevidence ?? null,
            confidenceRationale: ext.confidenceRationale ?? null,
            severityChangeConditions: ext.severityChangeConditions ?? null,
            ...(isStaticAst ? { runtimeProofGap: parsed.runtimeProofGap } : {}),
            ...(codeLocations?.length ? { codeLocations } : {}),
            chainFactIds: validFactIds,
            exchangeIds: [...new Set(exchangeIds)],
            evidenceIds: [ev.id],
          })
          const savedFinding = this.storage.upsertChainFinding(curRun, asset.id, finding, specRow.id, [...sourceOrigins])
          for (const fid of validFactIds) {
            this.storage.addGraphEdge(curRun.id, { fromKind: 'fact', fromId: fid, toKind: 'finding', toId: savedFinding.id, edgeKind: 'proves' })
          }
          this.storage.addGraphEdge(curRun.id, { fromKind: 'assignment', fromId: job.assignment.id, toKind: 'finding', toId: savedFinding.id, edgeKind: 'proves' })
          this.host.schedulePlanner(curRun.id)

          if (verifyNow) {
            const inline = await verifyInline(parsed, savedFinding.id, specRow.id)
            if (inline.status === 'confirmed' || inline.status === 'static_verified') {
              confirmedDuringAssignment = true
            }
            return {
              findingId: savedFinding.id,
              replaySpecId: inline.replaySpecId,
              status: inline.status,
              verificationTier: inline.verificationTier,
              inlineVerifyFeedback: inline.feedback,
              deduplicated: Boolean(canonicalMatchedRow),
              upgraded: dedupeDecision.action === 'upgrade_existing',
              note: inline.status === 'confirmed' || inline.status === 'static_verified'
                ? `Inline Zero-LLM verification succeeded (${inline.status}).`
                : `Inline Zero-LLM verification returned ${inline.status}. Inspect inlineVerifyFeedback and call verify_replay_spec or update_proposed_finding to repair (${inline.feedback.retriesRemaining} retries remaining).`,
            }
          }

          return {
            findingId: savedFinding.id,
            replaySpecId: specRow.id,
            status: savedFinding.status,
            deduplicated: Boolean(canonicalMatchedRow),
            upgraded: dedupeDecision.action === 'upgrade_existing',
            note: isStaticAst
              ? 'Candidate static_ast_proof queued for deterministic offline AST/SAST verification (can promote to static_verified only, never runtime confirmed).'
              : 'Candidate finding queued for Zero-LLM Declarative Replay Verification. Only deterministic replay can promote to confirmed.',
          }
        },

        update_proposed_finding: async (args) => {
          const curRun = this.host.check(job)
          const currentApproved = this.host.approvedOriginsSet(curRun)
          const existingRow = findFindingRow(this.storage, curRun.id, args.findingId)
          if (!existingRow) throw new Error(`Finding ${args.findingId} not found in this run.`)

          const isAlreadyVerified = existingRow.finding.status === 'confirmed' || existingRow.finding.status === 'static_verified'
          let nextReplaySpecId = existingRow.replaySpecId ?? undefined
          let nextSourceOrigins = existingRow.sourceOrigins
          const extraEvidenceIds: string[] = []
          let parsedUpdatedSpec: DeclarativeReplaySpec | undefined
          let createdSpecRowId: string | undefined

          const candidateFindingPatch = {
            ...(args.title ? { title: args.title } : {}),
            ...(args.summary ? { reason: args.summary } : {}),
            ...(args.severity ? { severity: args.severity } : {}),
          }
          const guard = guardConfirmedFindingMutation(existingRow.finding, candidateFindingPatch)
          if (isAlreadyVerified && (!guard.allowed || args.replaySpec !== undefined)) {
            const blockedFields = [
              ...guard.blockedFields,
              ...(args.replaySpec !== undefined ? ['replaySpec'] : []),
            ]
            return {
              findingId: existingRow.id,
              replaySpecId: existingRow.replaySpecId,
              status: existingRow.finding.status,
              ...(existingRow.verificationTier ? { verificationTier: existingRow.verificationTier } : {}),
              severity: existingRow.finding.severity,
              blockedFields,
              updated: false,
              isError: true,
              note: `Confirmed/static_verified finding identity is immutable; blocked post-confirmation edits (${blockedFields.join(', ')}).`,
            }
          }

          const isLiveRuntimeRun = isLiveRuntimeVerificationRun(
            curRun,
            this.host.verifier.backendSupportsVerifyScript(),
          )
          if (args.replaySpec) {
            const parsed = declarativeReplaySpecSchema.parse(stripUntrustedReplayEnvelopes(args.replaySpec))
            if (parsed.kind === 'static_ast_proof' && isLiveRuntimeRun) {
              throw new Error(STATIC_AST_LIVE_TARGET_REJECT_MESSAGE)
            }
            const specOrigins = replaySpecOrigins(parsed)
            if (specOrigins.some(o => !currentApproved.has(o))) {
              throw new BrokerDenied('Updated replay spec references an origin outside current approved scope.')
            }
            parsedUpdatedSpec = parsed
            nextSourceOrigins = [...new Set([...existingRow.sourceOrigins, ...specOrigins])]
            const priorSpecs = this.storage.listReplaySpecsForFinding(curRun.id, existingRow.id)
            const priorMaxAttempts = priorSpecs.length ? Math.max(...priorSpecs.map(r => r.attemptCount)) : 0
            const maxAttempts = 1 + maxInlineVerifyRetries
            if (priorMaxAttempts >= maxAttempts) {
              return {
                findingId: existingRow.id,
                replaySpecId: existingRow.replaySpecId,
                status: existingRow.finding.status,
                ...(existingRow.verificationTier ? { verificationTier: existingRow.verificationTier } : {}),
                severity: existingRow.finding.severity,
                inlineVerifyFeedback: retryLimitExceededFeedback(
                  maxAttempts,
                  `Inline verification retry limit reached (maxInlineVerifyRetries=${maxInlineVerifyRetries}).`,
                ),
                updated: false,
                isError: true,
              }
            }
            const specRow = this.storage.createReplaySpec(
              curRun,
              job.assignment,
              existingRow.id,
              parsed,
              nextSourceOrigins,
              { initialAttemptCount: priorMaxAttempts },
            )
            createdSpecRowId = specRow.id
            boardTools.noteEvidence()
            const ev = this.storage.addArtifact(curRun, job.assignment, 'replay',
              `Updated replay spec · ${parsed.title}`,
              JSON.stringify({ findingId: existingRow.id, replaySpecId: specRow.id, specSha256: specRow.specSha256, spec: parsed }, null, 2),
              undefined, currentSecrets())
            extraEvidenceIds.push(ev.id)
            nextReplaySpecId = specRow.id
          }

          const updated = this.storage.updateProposedFinding(curRun, existingRow.id, {
            replaySpecId: nextReplaySpecId,
            sourceOrigins: nextSourceOrigins,
            ...(args.counterevidence !== undefined ? { counterevidence: args.counterevidence } : {}),
            ...(args.confidenceRationale !== undefined ? { confidenceRationale: args.confidenceRationale } : {}),
            ...(args.severityChangeConditions !== undefined ? { severityChangeConditions: args.severityChangeConditions } : {}),
            ...(args.codeLocations !== undefined ? { codeLocations: args.codeLocations } : {}),
            finding: {
              ...guard.sanitizedPatch,
              ...(!isAlreadyVerified && args.replaySpec ? { status: 'pending' as const } : {}),
              ...(extraEvidenceIds.length ? { evidenceIds: extraEvidenceIds } : {}),
            },
          })

          const shouldVerifyNow = Boolean(parsedUpdatedSpec && (isLiveRuntimeRun || (args.verifyNow ?? true)) && !isAlreadyVerified)
          if (shouldVerifyNow && parsedUpdatedSpec) {
            const inline = await verifyInline(parsedUpdatedSpec, existingRow.id, createdSpecRowId ?? nextReplaySpecId)
            if (inline.status === 'confirmed' || inline.status === 'static_verified') {
              confirmedDuringAssignment = true
            }
            return {
              findingId: updated.id,
              replaySpecId: inline.replaySpecId,
              status: inline.status,
              verificationTier: inline.verificationTier,
              severity: updated.severity,
              inlineVerifyFeedback: inline.feedback,
              updated: true,
            }
          }

          return {
            findingId: updated.id,
            replaySpecId: updated.replaySpecId,
            status: updated.status,
            severity: updated.severity,
            updated: true,
          }
        },

        verify_replay_spec: async (args) => trackProofCall(async () => {
          const spec = args.spec ?? args.replaySpec
          if (!spec) throw new Error('verify_replay_spec requires spec or replaySpec.')
          const inline = await verifyInline(spec, args.findingId, args.replaySpecId)
          if (inline.status === 'confirmed' || inline.status === 'static_verified') {
            confirmedDuringAssignment = true
          }
          return {
            findingId: inline.findingId ?? args.findingId ?? null,
            replaySpecId: inline.replaySpecId,
            status: inline.status,
            ...(inline.verificationTier ? { verificationTier: inline.verificationTier } : {}),
            inlineVerifyFeedback: inline.feedback,
          }
        }),

        ...(this.host.verifier.backendSupportsVerifyScript() ? {
          kovo_verify: async (args: KovoVerifyArgs, toolSignal?: AbortSignal) => {
            enteredKovoVerify = true
            return trackProofCall(async () => {
            const curRun = this.host.check(job)
            const rawRuntime = args.runtime as string | undefined
            if ((rawRuntime !== undefined && rawRuntime !== 'ts') || (typeof args.scriptPath === 'string' && /\.py$/i.test(args.scriptPath.trim()))) {
              throw new Error(KOVO_VERIFY_TS_ONLY_ERROR)
            }
            const runtime: KovoVerifyRuntime = 'ts'
            const script = typeof args.script === 'string' && args.script.trim()
              ? args.script.trim()
              : args.scriptPath
                ? this.host.verifier.readAgentProofScript(reposDir, args.scriptPath)
                : ''
            if (!script) {
              throw new Error('kovo_verify requires `script` (inline) or `scriptPath` (a file in the mounted workspace).')
            }
            if (checkpointOnlyGuard.shouldBlockCheckpointOnlyScript(script)) {
              return checkpointOnlyGuard.buildBlockedOutcome()
            }
            const aliasHits: KovoVerifyAliasKey[] = [
              ...(args.aliasUsed === 'code'
                ? ['tool_arg:code' as const]
                : args.aliasUsed === 'source'
                  ? ['tool_arg:source' as const]
                  : []),
              ...detectKovoVerifyScriptAliases(script),
            ]
            const aliasSnapshot = recordKovoVerifyAliasUsage(curRun.id, aliasHits)
            if (aliasHits.length > 0) {
              this.host.safeEvent(
                curRun.id,
                'agent.verify_alias_usage',
                `kovo_verify alias hit(s): ${aliasHits.join(', ')} (run total=${aliasSnapshot.totalAliasHits}/${aliasSnapshot.totalCalls} calls).`,
                { assignmentId: job.assignment.id, stepId: step.id, aliases: aliasHits, snapshot: aliasSnapshot },
              )
            }
            const approved = this.host.approvedOriginsSet(curRun)
            const runVault = this.host.capabilityVaultFor(curRun.id), verifyVault = new DerivedCapabilityVault({ runId: runVault.runId })
            const verifySignal = toolSignal
              ? AbortSignal.any([job.controller.signal, toolSignal])
              : job.controller.signal
            const proof = await this.host.verifier.runAgentScriptProof({
              script, runtime, ...(args.title?.trim() ? { title: args.title.trim() } : {}),
              grant, runId: curRun.id, assignmentId: job.assignment.id,
              targetOrigins: [...approved].slice(0, 8), signal: verifySignal, capabilityVault: verifyVault,
              ...(args.timeoutMs ? { timeoutMs: args.timeoutMs } : {}),
            })
            const ledgerSync = this.host.verifier.syncVerifyArtifactsToLedger({
              runId: curRun.id, proof, defaultOrigin: [...approved][0] ?? '',
            })
            for (const sealed of ledgerSync.sealedCapabilities) {
              if (sealed.handle && !sessionSealedCapHandles.includes(sealed.handle)) {
                sessionSealedCapHandles.push(sealed.handle)
              }
            }
            if (ledgerSync.newCapabilityCount > 0 || ledgerSync.newEdgeCount > 0) {
              this.host.schedulePlanner(curRun.id)
            }
            const compositeReceipt = proof.compositeReceipt ? {
              chainId: proof.compositeReceipt.receipt.chainId,
              terminalVulnClass: proof.compositeReceipt.receipt.terminalVulnClass,
              hopCount: proof.compositeReceipt.receipt.hops.length,
              replayMode: proof.compositeReceipt.receipt.replayMode,
              confirmed: proof.compositeReceipt.verification.confirmed,
              ...(proof.compositeReceipt.verification.failedStage ? { failedStage: proof.compositeReceipt.verification.failedStage } : {}),
              verifiedEdgeCount: proof.compositeReceipt.verification.verifiedEdges.filter(e => e.verified).length,
            } : undefined
            if (proof.compositeReceipt && proof.hostTranscript) {
              const personaRoleLabels = grant.personas
                ? Object.fromEntries([...grant.personas.entries()].filter(([, p]) => Boolean(p.roleLabel?.trim())).map(([h, p]) => [h, p.roleLabel!]))
                : undefined
              captureVerifyCorpusRecord({
                app: [...approved][0] ?? curRun.projectId, runId: curRun.id, assignmentId: job.assignment.id,
                receipt: proof.compositeReceipt.receipt, verification: proof.compositeReceipt.verification, hostTranscript: proof.hostTranscript,
                ...(personaRoleLabels ? { personaRoleLabels } : {}), secrets: [...currentSecrets(), ...vaultScrubDescriptors(runVault), ...vaultScrubDescriptors(verifyVault)],
              })
            }
            if (!proof.verdict.confirmed) {
              const summarized = checkpointOnlyGuard.summarizeOutcome({
                verdict: proof.verdict, sealedCapabilities: ledgerSync.sealedCapabilities,
                verifiedHops: ledgerSync.verifiedHops,
                ...(compositeReceipt ? { compositeReceipt } : {}),
              })
              return proof.compositeReceipt?.verification.rejectedBy ? { ...summarized, compositeRejectedBy: proof.compositeReceipt.verification.rejectedBy } : summarized
            }
            confirmedDuringAssignment = true
            const persisted = this.host.persistAgentScriptProof({
              run: curRun, assignment: job.assignment, script, runtime,
              title: args.title?.trim() || proof.claimTitle || undefined, proof,
              secrets: [...currentSecrets(), ...vaultScrubDescriptors(runVault), ...vaultScrubDescriptors(verifyVault)],
            })
            this.host.schedulePlanner(curRun.id)
            return checkpointOnlyGuard.summarizeOutcome({
              verdict: {
                ...proof.verdict,
                detail: `${proof.verdict.detail} Finding ${persisted.findingId} cites ${persisted.receiptId ? `ProofReceipt ${persisted.receiptId}` : 'the persisted script proof'} (replay spec ${persisted.replaySpecId}).`.trim(),
              },
              sealedCapabilities: ledgerSync.sealedCapabilities, verifiedHops: ledgerSync.verifiedHops, ...(compositeReceipt ? { compositeReceipt } : {}),
            })
            })
          },
        } : {}),

        suggest_candidate_host: async ({ origin, source, thirdParty }) => {
          const curRun = this.host.check(job)
          const clean = this.host.parseOriginForRun(curRun, origin)
          return this.storage.suggestCandidateHost(curRun, clean, source, Boolean(thirdParty))
        },

        complete_intent: async (completion) => {
          guardPrematureRuledOut({
            runId: run.id,
            origins: targetOrigins,
            status: completion.status,
            summary: completion.summary,
          })
          return { recorded: true, status: completion.status }
        },
      }

      const bolaTestQueue = run.capabilityTier >= 2 && personasPub.length >= 2
        ? selectAssignmentBolaQueueItems({
            queue: buildBolaTestQueue(
              this.storage.listFacts(run.id, { includeTainted: false, limit: 200 }),
              personasPub,
              permittedAtAdmission,
              this.storage.listResourceSamples(run.id),
            ),
            targetOrigins,
            step: {
              title: step.title,
              hypothesis: step.hypothesis,
              category: step.category,
              skills: step.skills,
              specialistProfile: step.specialistProfile ?? null,
            },
          })
        : []

      const specialistProfileId = step.specialistProfile ?? routeStepToSpecialist({
        title: step.title,
        hypothesis: step.hypothesis,
        category: step.category,
        skills: step.skills,
      })
      const specialistConfig = resolveSpecialistProfile(specialistProfileId)
      const decoupledPipeline = isDecoupledOrPtcExploiterEnabled()
      const rawScopedHandlers = decoupledPipeline ? handlers : filterHandlersForSpecialist(handlers, specialistConfig)
      const scopedHandlers: WorkerToolHandlers = {}
      for (const [toolName, handlerFn] of Object.entries(rawScopedHandlers)) {
        if (typeof handlerFn !== 'function') continue
        ;(scopedHandlers as Record<string, unknown>)[toolName] = (...args: unknown[]) => {
          turnState.toolCallsInTurn += 1
          turnState.totalToolCalls += 1
          return (handlerFn as (...a: unknown[]) => unknown)(...args)
        }
      }

      const techTags = this.storage.listFacts(run.id, { includeTainted: false, kind: 'tech_fingerprint', limit: 30 })
        .flatMap(f => {
          const tags = f.data?.tags
          return Array.isArray(tags) ? tags.filter((t): t is string => typeof t === 'string') : []
        })
      const sinkKind = parentFacts
        .map(f => (typeof f.data?.sinkKind === 'string' ? f.data.sinkKind : ''))
        .find(Boolean)
      const confirmedRefs = this.host.alreadyConfirmedRefs(run)
      const unconfirmedHardSurface = this.host.reconPlanner.unconfirmedHardSurfaceRefs(run, confirmedRefs)
      const detLeads = this.host.detLeadSummaries(run)
      const assignmentBrief = this.host.assignmentBriefForStep({
        run,
        step,
        targetOrigins, personas: personasPub,
        parentFacts, confirmed: confirmedRefs, detLeads, maxTurns: job.assignment.maxTurns,
      })
      const hasHopCheckpoint = Boolean(assignmentBrief && /\b(?:hopCheckpoint|cap:hop_|doNotRediscover)\b/.test(assignmentBrief))
      const isMultiHopStep = hasHopCheckpoint || isMultiHopChainStep(step)
      const preInjectedSkills = selectPreInjectionSkills({
        profileSkills: specialistConfig.skills, techTags: [...new Set(techTags)], ...(sinkKind ? { sinkKind } : {}),
        category: step.category, title: step.title, hypothesis: step.hypothesis,
        ...(hasHopCheckpoint ? { hasHopCheckpoint: true } : {}),
        ...(isMultiHopStep ? { multiHop: true, hopDepth: Math.max(2, step.dependsOnStepIds.length + 1) } : {}),
        limit: 2,
      })
      const runTrace = this.host.ensureRunTrace(run, profiles)
      const assignedTargetRoutes = extractAssignedTargetRoutes({ title: step.title, hypothesis: step.hypothesis, parentFacts, defaultOrigin: targetOrigins[0] })

      clearPreSessionTimer()
      const preSessionElapsedMs = assignmentClock.activeElapsedMs()
      const preSessionPausedMs = assignmentClock.pausedElapsedMs()
      const wallPlan = computeWorkerWallClockPlan({
        wallClockMs: budget.wallClockMs,
        preSessionElapsedMs,
        explicitSettlementMs: budget.wallClockSettlementMs,
        isMultiHop: isMultiHopStep,
      })
      const effectiveSettlementMs = wallPlan.effectiveSettlementMs
      const sessionSettlementMs = Math.max(1, effectiveSettlementMs - preSessionElapsedMs)

      // Pause-aware, stall-credit-aware verify-grace supervision (backed strictly by `assignmentClock`):
      // - Provider HTTP retries, 429/5xx backoff, and stalled stream timeouts are deducted from
      //   soft wall-clock elapsed time via `computeEffectiveWorkerElapsedMs`, capped at
      //   `wallPlan.maxStallCreditMs` (`<= baseWallClockMs`) so total active time never exceeds
      //   `wallPlan.hardWallClockCeilingMs` (`2x` base budget).
      // - When soft budget expires and the worker has already entered `kovo_verify` OR holds a
      //   live sealed capability / active `hop_checkpoint`, grant an expanded bounded verify-grace
      //   window (+60s in production, clamped by remaining headroom to `hardWallClockCeilingMs`).
      // - Otherwise apply standard active-proof or settlement-stream grace, or rotate immediately.
      const sessionRotateController = new AbortController()
      const onOuterJobAbort = () => sessionRotateController.abort(job.controller.signal.reason)
      job.controller.signal.addEventListener('abort', onOuterJobAbort, { once: true })
      if (job.controller.signal.aborted) sessionRotateController.abort(job.controller.signal.reason)

      let sessionHandle: AgentSessionHandle | undefined
      const getProviderStallWaitMs = () => sessionHandle?.getProviderStallWaitMs() ?? 0
      const sessionActiveElapsedMs = () => Math.max(0, assignmentClock.activeElapsedMs() - preSessionElapsedMs)
      const sessionPausedElapsedMs = () => Math.max(0, assignmentClock.pausedElapsedMs() - preSessionPausedMs)
      const sessionEffectiveElapsedMs = () => computeEffectiveWorkerElapsedMs({
        wallElapsedMs: sessionActiveElapsedMs() + sessionPausedElapsedMs(),
        approvalPausedMs: sessionPausedElapsedMs(),
        providerStallWaitMs: getProviderStallWaitMs(),
        maxStallCreditMs: wallPlan.maxStallCreditMs,
      })
      const hasLiveSealedCapability = () => {
        if (sessionSealedCapHandles.length > 0) return true
        try {
          return this.storage.capabilityLedger(run.id)
            .listCapabilities()
            .some(c => !baselineCapIds.has(c.capId) && DERIVED_CAPABILITY_HANDLE_RE.test(c.capId))
        } catch {
          return false
        }
      }

      let enteredSettlement = false
      let generatingTurn = false
      let turnsCompletedInSession = 0
      let baseWallClockExpired = false
      let localWallClockRotated = false
      let localGraceStartedAtMs: number | undefined
      let verifyGraceUsedMs = 0
      let verifyGraceReason: WorkerVerifyGraceReason = 'none'
      const currentVerifyGraceReason = (): WorkerVerifyGraceReason => verifyGraceReason
      let baseDeadlineTimer: DeadlineTimerHandle | undefined
      let verifyGraceTimer: DeadlineTimerHandle | undefined
      let proofHandoffTimer: DeadlineTimerHandle | undefined
      let hardCeilingTimer: DeadlineTimerHandle | undefined

      const clearSupervisionTimers = () => {
        if (baseDeadlineTimer) { baseDeadlineTimer.cancel(); baseDeadlineTimer = undefined }
        if (verifyGraceTimer) { verifyGraceTimer.cancel(); verifyGraceTimer = undefined }
        if (proofHandoffTimer) { proofHandoffTimer.cancel(); proofHandoffTimer = undefined }
        if (hardCeilingTimer) { hardCeilingTimer.cancel(); hardCeilingTimer = undefined }
      }

      const triggerLocalRotation = () => {
        if (localWallClockRotated || job.controller.signal.aborted) return
        localWallClockRotated = true
        clearSupervisionTimers()
        if (localGraceStartedAtMs !== undefined) {
          verifyGraceUsedMs = Math.max(0, assignmentClock.activeElapsedMs() - localGraceStartedAtMs)
        }
        sessionRotateController.abort(new Error(`Assignment wall-clock deadline reached (${assignmentClock.activeElapsedMs()}ms / ${budget.wallClockMs}ms).`))
      }

      const armBoundedVerifyGrace = (reason: Exclude<WorkerVerifyGraceReason, 'none'>, durationMs: number) => {
        if (verifyGraceTimer) { verifyGraceTimer.cancel(); verifyGraceTimer = undefined }
        if (localGraceStartedAtMs === undefined) localGraceStartedAtMs = assignmentClock.activeElapsedMs()
        if (
          verifyGraceReason === 'none'
          || reason === 'expanded_verify'
          || (reason === 'active_proof' && verifyGraceReason === 'settlement_stream')
        ) {
          verifyGraceReason = reason
        }
        const remainingHardMs = Math.max(0, wallPlan.hardWallClockCeilingMs - sessionActiveElapsedMs())
        const boundedDurationMs = Math.min(durationMs, remainingHardMs)
        if (boundedDurationMs <= 0) {
          triggerLocalRotation()
          return
        }
        verifyGraceTimer = assignmentClock.createDeadlineTimer(boundedDurationMs, () => {
          verifyGraceTimer = undefined
          triggerLocalRotation()
        })
      }

      onProofCallEnter = () => {
        if (proofHandoffTimer) { proofHandoffTimer.cancel(); proofHandoffTimer = undefined }
        if (baseWallClockExpired && !localWallClockRotated) {
          const decision = resolveWorkerVerifyGrace({
            plan: wallPlan,
            sessionActiveElapsedMs: sessionActiveElapsedMs(),
            inFlightProofCall: inFlightProofCalls > 0,
            enteredKovoVerify,
            hasLiveSealedCapability: hasLiveSealedCapability(),
            hasHopCheckpoint,
            inSettlementStream: enteredSettlement && generatingTurn,
            stallAbort: Boolean(job.stallAbort),
          })
          if (decision.verifyGraceApplied && decision.reason !== 'none' && decision.graceMs > 0) {
            armBoundedVerifyGrace(decision.reason, decision.graceMs)
          }
        }
      }
      onProofCallExit = () => {
        if (
          baseWallClockExpired
          && inFlightProofCalls === 0
          && !localWallClockRotated
          && verifyGraceReason === 'active_proof'
        ) {
          queueMicrotask(() => {
            if (inFlightProofCalls === 0 && !localWallClockRotated && verifyGraceReason === 'active_proof') {
              triggerLocalRotation()
            }
          })
        }
      }

      // Finite hard absolute ceiling (2x base budget) — never bypassed by stall credit or verify grace.
      hardCeilingTimer = assignmentClock.createDeadlineTimer(wallPlan.hardWallClockCeilingMs, () => {
        hardCeilingTimer = undefined
        baseWallClockExpired = true
        triggerLocalRotation()
      })

      const armBaseDeadlineTimer = (delayMs: number) => {
        if (baseDeadlineTimer) { baseDeadlineTimer.cancel(); baseDeadlineTimer = undefined }
        baseDeadlineTimer = assignmentClock.createDeadlineTimer(Math.max(1, Math.floor(delayMs)), () => {
          baseDeadlineTimer = undefined
          if (job.controller.signal.aborted || localWallClockRotated) return
          const activeMs = sessionActiveElapsedMs()
          const effectiveMs = sessionEffectiveElapsedMs()
          const remainingSoftMs = wallPlan.remainingBudgetMs - effectiveMs
          const remainingHardMs = wallPlan.hardWallClockCeilingMs - activeMs
          if (remainingSoftMs > 0 && remainingHardMs > 0) {
            armBaseDeadlineTimer(Math.min(remainingSoftMs, remainingHardMs))
            return
          }
          baseWallClockExpired = true
          const decision = resolveWorkerVerifyGrace({
            plan: wallPlan,
            sessionActiveElapsedMs: activeMs,
            inFlightProofCall: inFlightProofCalls > 0,
            enteredKovoVerify,
            hasLiveSealedCapability: hasLiveSealedCapability(),
            hasHopCheckpoint,
            inSettlementStream: enteredSettlement && generatingTurn,
            stallAbort: Boolean(job.stallAbort),
          })
          if (decision.verifyGraceApplied && decision.reason !== 'none' && decision.graceMs > 0) {
            armBoundedVerifyGrace(decision.reason, decision.graceMs)
            return
          }
          triggerLocalRotation()
        })
      }
      armBaseDeadlineTimer(wallPlan.remainingBudgetMs)

      const sessionWallClockMs = wallPlan.hardWallClockCeilingMs

      const baseLlmHooks = llmRunHooks(this.storage, run.id)
      const allPublicOrigins = [...new Set([...targetOrigins, ...permittedAtAdmission])]
      const runAllowWebSearch = (run as { allowWebSearch?: boolean }).allowWebSearch
      const decoupledSession = decoupledPipeline ? await prepareExploiterSession({
        handlers, storage: this.storage, runId: run.id, assignmentId: job.assignment.id, workerSession: session,
        ...(runAllowWebSearch !== undefined ? { runAllowWebSearch } : {}),
        publicOrigins: allPublicOrigins, personasPub, recordedExchanges, mountedRepos,
        userPromptInput: {
          goal: run.goal, step: { id: step.id, title: step.title, hypothesis: step.hypothesis, category: step.category },
          origins: targetOrigins, ...(allPublicOrigins.length > 1 ? { publicOrigins: allPublicOrigins } : {}),
          capabilityTier: run.capabilityTier, maxTurns: budget.maxTurns, budget, personas: personasPub, mountedRepos,
          parentFacts: parentFacts.map(f => ({ id: f.id, kind: f.kind, origin: f.origin, summary: f.summary, data: f.data })),
          alreadyConfirmed: confirmedRefs, detLeads, ...(assignmentBrief ? { assignmentBrief } : {}), specsSummary: stagedSpecs, bolaTestQueue, unconfirmedHardSurface, peerDiscoveries: this.storage.listFacts(run.id, { includeTainted: false, limit: 120 }).filter(f => f.assignmentId !== job.assignment.id && permittedAtAdmission.has(f.origin) && !neededParentFactIds.has(f.id)), specialistFocus: specialistConfig.focusPrompt,
        },
        runKovoVerify: async ({ script, title, signal }) => {
          if (!handlers.kovo_verify) return { confirmed: false, rejectedBy: 'backend', reason: 'verifier_unavailable', detail: 'kovo_verify backend unavailable.' }
          const out = await handlers.kovo_verify({ script, runtime: 'ts', ...(title ? { title } : {}) }, signal ?? job.controller.signal) as Record<string, unknown>
          const detail = typeof out?.detail === 'string' ? out.detail : undefined
          const fid = typeof out?.findingId === 'string' ? out.findingId : detail?.match(/Finding\s+([^\s]+)\s+cites/)?.[1]
          return {
            confirmed: out?.confirmed === true, ...(fid ? { findingId: fid } : {}),
            ...(typeof out?.rejectedBy === 'string' ? { rejectedBy: out.rejectedBy } : {}), ...(typeof out?.compositeRejectedBy === 'string' ? { compositeRejectedBy: out.compositeRejectedBy } : {}),
            ...(typeof out?.reason === 'string' ? { reason: out.reason } : {}),
            ...(detail ? { detail } : {}),
            ...(Array.isArray(out?.missingEvidence) ? { missingEvidence: out.missingEvidence.map(String) } : {}),
          }
        },
        proofWriterDeps: {
          profiles: resolveProfilePoolForRole(specialistConfig.roleAffinity, profiles),
          beforeCall: () => { this.host.check(job); if (this.storage.checkBudgetExceeded(run.id)) throw new BudgetExceededError('Run spend or request budget exceeded.') },
          onUsage: u => { const tok = (u.inputTokens ?? 0) + (u.outputTokens ?? 0); this.storage.recordLlmSpend(run.id, { usd: u.costUsd ?? 0, tokens: tok }); this.host.board.noteTokens(job.assignment.id, boardHandle, tok) },
          onProfileSuccess: baseLlmHooks.onProfileSuccess,
          onProfileFailure: (pid, err, hard) => this.recordWorkerProfileFailure(turnState, pid, err, hard, baseLlmHooks.onProfileFailure),
        },
        onProofConfirmed: () => { confirmedDuringAssignment = true; this.host.schedulePlanner(run.id) },
        onToolExecuted: () => { turnState.toolCallsInTurn += 1; turnState.totalToolCalls += 1 }, isSessionCapabilityHandle: h => sessionSealedCapHandles.includes(h) || this.storage.capabilityLedger(run.id).listCapabilities().some(c => c.capId === h), recordNegativeEdge: neg => { this.recordNegativeEdgeCoverage(run.id, { origin: neg.origin, category: neg.vulnClass || step.category, summary: `Preflight non-2xx terminal (${neg.status}) on ${neg.method} ${neg.path}`, proofGapReason: 'control_blocked_cleanly', route: `${neg.method} ${neg.path}`, ...(neg.exchangeId ? { exchangeIds: [neg.exchangeId] } : {}), assignmentId: job.assignment.id }) },
      }) : undefined
      let sessionResult: Awaited<ReturnType<typeof runAgentSession>>
      try {
        sessionResult = await runAgentSession({
          directory: this.storage.directory, sessionId: job.assignment.sessionId, ...(reposDir ? { reposDir } : {}),
          requestId: `investigate:${step.id}:attempt-${job.assignment.attempt}`,
          profiles: resolveProfilePoolForRole(specialistConfig.roleAffinity, profiles),
          scenario: 'worker-investigation', roleAffinity: specialistConfig.roleAffinity,
          prompt: workerInvestigationPrompt({
            goal: run.goal,
            step: { id: step.id, title: step.title, hypothesis: step.hypothesis, category: step.category, skills: [...new Set([...step.skills, ...specialistConfig.skills])], specialistProfile: specialistProfileId },
            origins: targetOrigins, ...(allPublicOrigins.length > 1 ? { publicOrigins: allPublicOrigins } : {}),
            capabilityTier: run.capabilityTier, maxTurns: budget.maxTurns, budget, personas: personasPub,
            ...(bolaTestQueue.length ? { bolaTestQueue } : {}),
            parentFacts: parentFacts.map(f => ({ id: f.id, kind: f.kind, origin: f.origin, summary: f.summary, data: f.data })),
            specsSummary: stagedSpecs, mountedRepos, preInjectedSkills, alreadyConfirmed: confirmedRefs, unconfirmedHardSurface, detLeads,
            ...(assignmentBrief ? { assignmentBrief } : {}),
          }),
          ...(decoupledSession?.session ?? {}),
          signal: sessionRotateController.signal,
          budget,
          maxTurns: budget.maxTurns,
          wallClockMs: sessionWallClockMs,
          wallClockSettlementMs: sessionSettlementMs,
          wallClockGraceMs: 0,
          wallClockMaxStallCreditMs: wallPlan.maxStallCreditMs,
          wallClockHardCeilingMs: wallPlan.hardWallClockCeilingMs,
          activeClock: assignmentClock,
          onSessionReady: handle => {
            sessionHandle = handle
          },
          onWallClockRotate: info => {
            verifyGraceUsedMs = Math.max(verifyGraceUsedMs, info.graceUsedMs)
            if (info.graceUsedMs > 0 && verifyGraceReason === 'none') {
              verifyGraceReason = 'active_proof'
            }
          },
          ...(runTrace ? {
            trace: runTrace,
            traceContext: {
              runId: run.id,
              assignmentId: job.assignment.id,
              specialistProfile: specialistProfileId,
            },
          } : {}),
          compaction: true,
          enableSettlement: true,
          requireCompleteIntent: true,
          shouldSettle: () => {
            const effectiveTotalMs = computeEffectiveWorkerElapsedMs({
              wallElapsedMs: assignmentClock.activeElapsedMs() + assignmentClock.pausedElapsedMs(),
              approvalPausedMs: assignmentClock.pausedElapsedMs(),
              providerStallWaitMs: getProviderStallWaitMs(),
              maxStallCreditMs: wallPlan.maxStallCreditMs,
            })
            const due = effectiveTotalMs >= effectiveSettlementMs
            if (due) enteredSettlement = true
            return due
          },
          handlers: scopedHandlers,
          secrets,
          beforeCall: () => {
            this.host.check(job)
            if (this.storage.checkBudgetExceeded(run.id)) {
              throw new BudgetExceededError('Run spend or request budget exceeded.')
            }
          },
          ...baseLlmHooks,
          onProfileFailure: (profileId, err, hard) => this.recordWorkerProfileFailure(turnState, profileId, err, hard, baseLlmHooks.onProfileFailure),
          onUsage: usage => {
            const tokens = usage.inputTokens + usage.outputTokens
            this.storage.recordLlmSpend(run.id, { usd: usage.costUsd, tokens })
            this.host.board.noteTokens(job.assignment.id, boardHandle, tokens)
          },
          onTurn: (turn, _maxTurns, settling) => {
            generatingTurn = false
            turnsCompletedInSession = turn
            if (settling) enteredSettlement = true
            recordTurnLatency()
            this.storage.updateWorker(job.assignment.id, { turnsUsed: turn })
            this.storage.recordLlmSpend(run.id, { turns: 1 })
            if (
              baseWallClockExpired
              && inFlightProofCalls === 0
              && !localWallClockRotated
              && verifyGraceReason === 'settlement_stream'
            ) {
              if (proofHandoffTimer) proofHandoffTimer.cancel()
              proofHandoffTimer = assignmentClock.createDeadlineTimer(PROOF_HANDOFF_GRACE_MS, () => {
                proofHandoffTimer = undefined
                if (inFlightProofCalls === 0 && !localWallClockRotated && verifyGraceReason === 'settlement_stream') {
                  triggerLocalRotation()
                }
              })
            }
          },
          onStreamActivity: noteProviderToken,
          onTurnStart: turn => {
            generatingTurn = true
            turnState.turn = turn
            turnState.toolCallsInTurn = 0
            turnState.lastProviderFailure = undefined
            armStallTimer(turn)
            const member = this.storage.boardMember(run.id, boardHandle)
            const delta = this.host.boardTurnDelta(this.storage.run(run.id), boardHandle, member?.lastReadSeq ?? 0)
            if (!delta.text) return undefined
            return {
              messages: [turn === 1 ? injectBoardTurnInstructions('', delta.text) : delta.text],
            }
          },
          approvedOrigins: [...permittedAtAdmission],
          ...(assignedTargetRoutes.length ? { assignedTargetRoutes } : {}),
          onProofObligation: (info: ProofObligationEvent) => {
            const prev = this.host.proofObligationByRun.get(run.id) ?? {
              probedRoutes: 0, coveredRoutes: 0, gapRoutes: 0, demandedRoutes: 0, dischargedByGap: 0,
            }
            this.host.proofObligationByRun.set(run.id, {
              probedRoutes: prev.probedRoutes + info.probedRoutes,
              coveredRoutes: prev.coveredRoutes + info.coveredRoutes,
              gapRoutes: prev.gapRoutes + info.gapRoutes,
              demandedRoutes: prev.demandedRoutes + info.demandedRoutes,
              dischargedByGap: prev.dischargedByGap + info.dischargedByGap,
            })
            this.host.safeEvent(
              run.id, 'agent.proof_obligation',
              `Proof obligation: ${info.coveredRoutes}/${info.probedRoutes} probed route(s) covered, ${info.gapRoutes} gap(s), ${info.demandedRoutes} demanded.`,
              { assignmentId: job.assignment.id, stepId: step.id, ...info },
            )
          },
          onGapValidation: (info: GapValidationEvent) => {
            if (info.accepted > 0) gapCodedDuringAssignment = true
            const prev = this.host.gapValidationByRun.get(run.id) ?? { accepted: 0, rejected: 0, byCode: {} }
            const byCode: Record<string, { accepted: number; rejected: number }> = { ...prev.byCode }
            for (const [code, counts] of Object.entries(info.byCode)) {
              const cur = byCode[code] ?? { accepted: 0, rejected: 0 }
              byCode[code] = { accepted: cur.accepted + counts.accepted, rejected: cur.rejected + counts.rejected }
            }
            this.host.gapValidationByRun.set(run.id, {
              accepted: prev.accepted + info.accepted, rejected: prev.rejected + info.rejected, byCode,
            })
            this.host.safeEvent(
              run.id, 'agent.gap_validation',
              `Gap validation: ${info.accepted} accepted, ${info.rejected} rejected.`,
              { assignmentId: job.assignment.id, stepId: step.id, ...info },
            )
          },
          onEarlyExit: info => {
            this.host.earlyExitTurnsSavedByRun.set(run.id,
              (this.host.earlyExitTurnsSavedByRun.get(run.id) ?? 0) + info.turnsSaved)
            this.storage.event(run.id, 'agent.early_exit',
              `Early exit (${info.reason}) at turn ${info.turnsUsed}/${info.maxTurns}: `
              + `${info.evidenceCount} distinct attempt(s), ${info.turnsSaved} turn(s) saved`
              + (info.route ? ` on ${info.route.method} ${info.route.path}.` : '.'),
              { ...info })
          },
        })
      } catch (err) {
        if (localWallClockRotated && !job.controller.signal.aborted) {
          const elapsedMs = assignmentClock.activeElapsedMs()
          const providerStallWaitMs = getProviderStallWaitMs()
          sessionResult = {
            answer: `Bounded wall-clock rotation after ${elapsedMs}ms (${turnsCompletedInSession}/${budget.maxTurns} turns); slot released.`,
            turnsUsed: turnsCompletedInSession,
            nudgesUsed: 0,
            settled: enteredSettlement,
            status: 'wall_clock_rotated',
            wallClockRotated: true,
            elapsedMs,
            providerStallWaitMs,
          }
        } else {
          throw err
        }
      } finally {
        clearSupervisionTimers(); await decoupledSession?.close?.().catch(() => undefined)
        onProofCallEnter = undefined
        onProofCallExit = undefined
        job.controller.signal.removeEventListener('abort', onOuterJobAbort)
      }

      const latestRun = this.host.check(job)
      const outcomeText = sessionResult.status === 'wall_clock_rotated'
        ? `[partial] ${sessionResult.answer}`
        : sessionResult.completion
          ? `[${sessionResult.completion.status}] ${sessionResult.completion.summary}`
          : sessionResult.answer
      if (sessionResult.status === 'wall_clock_rotated') {
        this.host.wallClockRotationsByRun.set(run.id, (this.host.wallClockRotationsByRun.get(run.id) ?? 0) + 1)
        const elapsedMs = sessionResult.elapsedMs ?? assignmentClock.activeElapsedMs()
        const providerStallWaitMs = Math.max(
          sessionResult.providerStallWaitMs ?? 0,
          getProviderStallWaitMs(),
        )
        const elapsedBreakdown = computeEffectiveWorkerElapsedBreakdown({
          wallElapsedMs: elapsedMs + assignmentClock.pausedElapsedMs(),
          approvalPausedMs: assignmentClock.pausedElapsedMs(),
          providerStallWaitMs,
          maxStallCreditMs: wallPlan.maxStallCreditMs,
        })
        const finalVerifyGraceReason = currentVerifyGraceReason()
        const verifyGraceApplied = finalVerifyGraceReason !== 'none' || verifyGraceUsedMs > 0
        this.host.safeEvent(
          run.id,
          'worker.wall_clock_rotated',
          `${step.title} rotated cleanly at wall-clock budget (${Math.round(elapsedMs / 1000)}s active / ${Math.round(elapsedBreakdown.effectiveElapsedMs / 1000)}s effective / ${Math.round(budget.wallClockMs / 1000)}s budget, ${sessionResult.turnsUsed} turn(s)); slot released.`,
          {
            assignmentId: job.assignment.id,
            stepId: step.id,
            specialistProfile: specialistProfileId,
            elapsedMs,
            effectiveElapsedMs: elapsedBreakdown.effectiveElapsedMs,
            wallClockMs: budget.wallClockMs,
            hardWallClockCeilingMs: wallPlan.hardWallClockCeilingMs,
            maxStallCreditMs: wallPlan.maxStallCreditMs,
            providerStallWaitMs,
            creditedStallWaitMs: elapsedBreakdown.creditedStallWaitMs,
            turnsUsed: sessionResult.turnsUsed,
            boundedRotation: true,
            verifyGraceMs: finalVerifyGraceReason === 'expanded_verify' ? wallPlan.expandedVerifyGraceMs : wallPlan.verifyGraceMs,
            graceUsedMs: verifyGraceUsedMs,
            verifyGraceReason: finalVerifyGraceReason,
            verifyGraceApplied,
          },
        )
      }
      const stepStatus = mapSessionStatusToStepStatus(sessionResult.status)
      this.turnStateByAssignment.delete(job.assignment.id)
      this.storage.transaction(() => {
        this.completeWorker(job.assignment, latestRun, outcomeText, [], undefined, currentSecrets())
        this.storage.updateChainStep(step.id, { status: stepStatus, assignedWorkerId: job.assignment.id })
      }, { behavior: 'immediate' })
      this.emitStepTerminalEvent(run.id, {
        assignmentId: job.assignment.id,
        step,
        stepStatus,
        sessionStatus: sessionResult.status,
        confirmed: confirmedDuringAssignment,
        gapCoded: gapCodedDuringAssignment,
        origins: targetOrigins,
      })
      if (!confirmedDuringAssignment && !gapCodedDuringAssignment && isRetryableChainStepStatus(stepStatus)) {
        try {
          this.host.reconPlanner.maybeRequeueRetryableStep({
            run: latestRun,
            step: { ...step, status: stepStatus, assignedWorkerId: job.assignment.id },
            assignment: job.assignment,
            terminalStatus: stepStatus,
            targetOrigins,
          })
        } catch (err) {
          this.noteLifecycleWarning(run.id, 'maybeRequeueRetryableStep', err, {
            assignmentId: job.assignment.id,
            stepId: step.id,
            stepStatus,
          })
        }
      }
      const isWallClockRotated = sessionResult.status === 'wall_clock_rotated'
      const isNonConfirmedSealedExit = !confirmedDuringAssignment
        && sessionSealedCapHandles.length > 0
        && (sessionResult.status === 'completed' || sessionResult.status === 'turn_limit' || sessionResult.status === 'nudged_out')
      if (!confirmedDuringAssignment && ((isWallClockRotated && (isMultiHopChainStep(step) || isPersistentWorkflowContinuationStep(step))) || isNonConfirmedSealedExit)) {
        try {
          const recordedFacts = collectAllPages((offset, limit) =>
            this.storage.listFacts(run.id, { includeTainted: false, limit, offset }))
            .filter(f => f.assignmentId === job.assignment.id)
          const recordedExchanges = this.storage.db
            .select({
              id: brokerExchanges.id,
              origin: brokerExchanges.origin,
              method: brokerExchanges.method,
              pathAndQuery: brokerExchanges.pathAndQuery,
              status: brokerExchanges.status,
              personaHandle: brokerExchanges.personaHandle,
            })
            .from(brokerExchanges)
            .where(and(eq(brokerExchanges.runId, run.id), eq(brokerExchanges.assignmentId, job.assignment.id)))
            .all()
          const newLedgerHandles = this.storage.capabilityLedger(run.id)
            .listCapabilities()
            .filter(c => !baselineCapIds.has(c.capId) && DERIVED_CAPABILITY_HANDLE_RE.test(c.capId))
            .map(c => c.capId)
          const sealedCapHandles = [...new Set([...sessionSealedCapHandles, ...newLedgerHandles])]
          this.host.reconPlanner.enqueueHopContinuationOnRotation({
            run: latestRun,
            step: { ...step, status: stepStatus, assignedWorkerId: job.assignment.id },
            assignment: job.assignment,
            targetOrigins,
            confirmed: confirmedDuringAssignment,
            partialSummary: redact(outcomeText, currentSecrets()),
            recordedFacts,
            recordedExchanges,
            sealedCapHandles,
            trigger: isWallClockRotated ? 'wall_clock_rotated' : 'sealed_handle_exit',
            allowNonChainWithSealedCap: isNonConfirmedSealedExit,
          })
        } catch (err) {
          this.noteLifecycleWarning(run.id, 'enqueueHopContinuationOnRotation', err, {
            assignmentId: job.assignment.id,
            stepId: step.id,
            stepStatus,
          })
        }
      }
    } finally {
      clearPreSessionTimer()
      unregisterAssignmentClock()
      stallWatchdog.clear()
      generationStartedAt = undefined
      const wallMs = assignmentClock.activeElapsedMs()
      assignmentClock.dispose()
      const walls = this.host.assignmentWallByRun.get(run.id) ?? []
      walls.push(wallMs)
      this.host.assignmentWallByRun.set(run.id, walls)
      if (this.storage.worker(job.assignment.id)?.status === 'complete') {
        const completed = this.host.completedAssignmentWallByRun.get(run.id) ?? []
        completed.push(wallMs)
        this.host.completedAssignmentWallByRun.set(run.id, completed)
      }
      const samples = this.host.turnLatencyByRun.get(run.id) ?? []
      samples.push(...turnLatencies)
      this.host.turnLatencyByRun.set(run.id, samples)
      await session.close().catch(() => undefined)
    }
  }
}
