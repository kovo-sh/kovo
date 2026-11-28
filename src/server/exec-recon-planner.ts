import { randomUUID } from 'node:crypto'
import { existsSync, lstatSync, readdirSync, readFileSync, realpathSync, statSync } from 'node:fs'
import { lstat, readdir, readFile } from 'node:fs/promises'
import { basename, extname, isAbsolute, join, relative, resolve as resolvePath, sep } from 'node:path'
import { and, asc, eq, inArray } from 'drizzle-orm'
import {
  defaultWorkerConcurrency,
  isLocalLabEnvEnabled,
  maxWorkerConcurrency,
  responseCheckIds,
  workerHistory,
  type AssessmentCheckId,
  type Candidate,
  type CheckCoverage,
  type Finding,
  type ResponseCheckId,
  type ThreatModelSummary,
} from '../domain.ts'
import { suppliedResponseLabel } from '../report-summary.ts'
import { isContinuableStepStatus } from '../step-status.ts'
import { accessPolicyReviews } from './access-policy-checks.ts'
import { isSensitiveRepoEntry, isSensitiveRepoRelativePath } from './safety-primitives.ts'; export { isSensitiveRepoEntry, isSensitiveRepoRelativePath }
import { defaultRetryGovernor } from './retry-governor.ts'
import { settleOrReport, settleOrReportAsync } from './run-disposers.ts'
import {
  agentTurn,
  classifyHostTier,
  coordinatorPlannerPrompt,
  coordinatorPrompt,
  detLeadsFromParentFacts,
  routeStepToSpecialist,
  threatModelPrompt,
  type AlreadyConfirmedRef,
  type DetLeadSummary,
  type UnconfirmedSurfaceRef,
} from './agent-session.ts'
import {
  ASSIGNMENT_BRIEF_MAX_BYTES_WITH_CODE,
  assertAssignmentBriefSize,
  buildAssignmentBrief, classifyPersonaPrivilege, selectBriefRoutes,
  type MissionKind,
} from './assignment-brief.ts'
import {
  BrokerCircuitOpen,
  BrokerDenied,
  type BrokerExchangeResult,
  type Grant,
  type PublicObservation,
} from './broker.ts'
import { CapabilityLedger, DERIVED_CAPABILITY_HANDLE_RE, computeArtifactDigest, finalizeHopCheckpointBrief, formatDerivedCapabilityHandle, sanitizeCheckpointHandleRef, sanitizeCheckpointText, type AddCapabilityInput, type CapabilityKind, type CapabilitySurface, type HopCheckpointBrief, type HopWorkflowNotebook } from './capability-ledger.ts'
import { buildHopRuntimeObservationIndex, hasAgenticSealedCapabilities, inspectChainHopRuntimeObservation, materializeCapabilityConsumerFrontierSteps, type FrontierLlmMode } from './capability-consumer-frontier.ts'
import { extractCoverageEvidenceMetadata, normalizeOriginForCoverage } from './coverage-category.ts'
import { extractSpecDedupeFields, normalizeEndpointTemplate } from './dedupe.ts'
import { normalizeRouteTemplate } from './route-template.ts'
import { buildWave1UncoveredOriginFallbackSteps, canonicalPlannerDedupeFamily, classifyRepoDirTier, materializeGreyBoxDataflowWave1Steps, resolveWave1MultiOriginFallback, selectBalancedRepoSourceCandidates } from './exec-recon-multiorigin.ts'
import { meetsBaseline, type EvidenceReview } from './evidence-checks.ts'
import {
  CHAIN_CONTINUATION_SKILL_PREFIX,
  DEFAULT_MAX_ORIGIN_SHARE,
  DET_LEAD_STEP_PRIORITY,
  DRY_ROUND_LIMIT,
  FrontierDispatcher,
  FrontierWaveController,
  MAX_CHAIN_CONTINUATIONS,
  MAX_GENERIC_WAVE1_CHAIN_CONTINUATIONS,
  MAX_RETRYABLE_STEP_RETRIES,
  RunOrchestrationStateStore,
  TIER_A_MAX_SEEDED_STEPS,
  TIER_A_STEP_PRIORITY,
  WHITEBOX_BLACKBOX_CAP_PRIORITY,
  WHITEBOX_TIER_A_MAX_SEEDED_STEPS,
  addFunnelCounts,
  applyCrownJewelStepBudget,
  buildBolaTestQueue,
  chainHopFactPayload,
  chainHypothesisDispatchSteps,
  classifyHostHeuristic,
  collectAllPages,
  compactChainTitle,
  compactText,
  computeDynamicStepBudget,
  computeHostTiers,
  confirmedCategoryFamily,
  coordinatorPlannerHandlers,
  coordinatorSchedulerDecision,
  detLeadCategory,
  detLeadEvidenceGate,
  detLeadSkills,
  detLeadUnlocksReinvestigation,
  detectQuarantinedOrigins,
  dispatchableReadySteps,
  emptyDispatchFunnel,
  enforcePerOriginFairness,
  evaluateDispatchStop,
  hasAuthenticatedPersonaForOrigin,
  isGenericWave1BoundaryChainStep,
  extractContinuationDepth,
  formatHopCheckpointForAssignment,
  hardChainStepsCeiling,
  hostTierOrder,
  isDetLeadDispatchStep,
  isLiveNon401HttpStatus,
  isMultiHopChainStep,
  isRetryableChainStepStatus,
  nextPlannerDryRounds,
  passOneCoverage,
  permanentlyBlockedStepIds,
  plannerResponseSchema,
  plannerWaveDispatchCap,
  prioritizeMountedSourceInitialSteps,
  readChainHopsFromFacts,
  reconcileUnavailableOriginSteps,
  reinvestigationKey,
  selectUncoveredHighRiskEndpoints,
  shouldInvokeLlmPlanner,
  stripJsonFences,
  structuredCoverageKey,
  structuredCoverageRouteMethodKey,
  synthesizeRuntimeCompositeWave1Steps,
  templatesMentionedInText,
  threatModelResponseSchema,
  type BolaTestQueueItem,
  type DetectQuarantinedOriginsInput,
  type DetectQuarantinedOriginsResult,
  type DispatchFunnelCounts,
  type DispatchStopReason,
  type FrontierWaveControllerOptions,
  type QuarantineObservedExchange,
  type QuarantinedOriginRecord,
  type ReinvestigationGuard,
  type RuntimeCompositeApiDependencyInput,
  type StructuredStepTarget,
} from './exec-dispatch.ts'
import {
  ExecServiceModule,
  llmRunHooks,
  publicPersonasFromGrant,
  recordBrokerExchange,
  type ExecActiveJob,
  type ExecCapture,
  type ExecCoordinatorTask,
  type ExecCoreServices,
} from './exec-exchange.ts'
import {
  MAX_CHECKPOINT_BRIEF_BYTES,
  type VerifiedHopReceiptEvent,
} from './frontier-scheduler.ts'
import {
  createGraphCoordinator,
  formatChainHopsBrief,
  type ChainHop,
  type CoordinatorApiDependency,
  type CoordinatorDeps,
  type CoordinatorEndpoint,
  type CoordinatorProgramGraph,
  type DispatchPlan,
  type GraphCoordinator,
} from './graph-coordinator.ts'
import {
  buildRuntimeDiscoveryInput,
  classifySurface,
  extractRuntimeCatalogFromFacts,
  inferRuntimeInvariantHypotheses,
  synthesizePostFloorRuntimeInvariants,
  toCapabilityLedgerSeeds,
  type CapabilitySeedRecord,
  type InvariantHypothesis,
  type RuntimeApiDependency,
  type RuntimeDiscoveryInput,
  type SourceFileInput,
  type SynthesizeInvariantsResult,
  type SynthesizerMode,
} from './invariant-synthesizer.ts'
import type { LabRunner, LabTargetHandle } from './lab-runner.ts'
import { decidePlannerAnswer, planWithWorldGraph, type LlmPlannerDecision } from './llm-planner.ts'
import {
  privateModelProfiles,
  resolveProfilePoolForRole,
  type ResolvedModelProfile,
} from './model-settings.ts'
import { resolveRunPersonas } from './persona-vault.ts'
import { runPhase0Recon } from './phase0-recon.ts'
import {
  applyDiscoveredSubdomainsToRun,
  discoverSubdomainsForOrigins,
  extractDiscoverableApex,
  isMultiTenantSaasOrigin,
  isSharedPaasOrigin,
} from './subdomain-discovery.ts'
import type { Phase0GraphwireExtras, ProbePlanRegistry } from './probe-plan.ts'
import type {
  CodeDataflowSlice,
  CodeToRuntimeHypothesis,
  MonorepoService,
  ProgramGraph,
  ServiceOriginMapping,
} from './program-graph.ts'
import type { NamedSecret } from './redact.ts'
import { responseReview } from './response-checks.ts'
import { availableReviewChecks, parseReviewPlan, reviewPlanPrompt, standardChecks } from './review-plan.ts'
import {
  HOST_PLANNER_PRODUCER,
  isTrustedHostControlFact,
  type SpawnTaskOptions,
  type SupervisedTask,
} from './run-actor.ts'
import { resolveRunSafetyBudgets } from './run-safety-budgets.ts'
import { brokerExchanges, coverageEntries, findings, messages, type ChainStepRetryableStatus } from './schema.ts'
import { runVariantSweepForFinding } from './semantic-audit.ts'
import type { StaticWorkspaceSnapshot } from './static-workspace-snapshot.ts'
import type { Assignment, ChainStep, Fact, Run, Store } from './store.ts'
import { extractProgramGraphInWorker, synthesizeInvariantsInWorker } from './untrusted-compute-pool.ts'
import { collectWorldGraphFromStore, serializeWorldGraph } from './world-graph.ts'

type Active = ExecActiveJob
type Capture = ExecCapture
type CoordinatorTask = ExecCoordinatorTask

const VALID_REFERRER_POLICIES = [
  'no-referrer', 'no-referrer-when-downgrade', 'origin', 'origin-when-cross-origin',
  'same-origin', 'strict-origin', 'strict-origin-when-cross-origin', 'unsafe-url',
] as const

const BASELINE_CAPTURE_CONCURRENCY = 6
const BASELINE_CAPTURE_MIN_CONCURRENCY = 1
const BASELINE_CAPTURE_MAX_CONCURRENCY = 12
const BASELINE_CAPTURE_TIMEOUT_MS = 8_000

/** Parse and clamp `KOVO_BASELINE_CAPTURE_CONCURRENCY` to `[1, 12]` (default `6`). */
function resolveBaselineCaptureConcurrency(env: NodeJS.ProcessEnv = process.env): number {
  const raw = env.KOVO_BASELINE_CAPTURE_CONCURRENCY
  if (raw === undefined || raw.trim() === '') return BASELINE_CAPTURE_CONCURRENCY
  const parsed = Number(raw.trim())
  if (!Number.isFinite(parsed)) return BASELINE_CAPTURE_CONCURRENCY
  return Math.max(
    BASELINE_CAPTURE_MIN_CONCURRENCY,
    Math.min(BASELINE_CAPTURE_MAX_CONCURRENCY, Math.floor(parsed)),
  )
}

function buildObservationFromHeaders(
  row: { origin: string; finalOrigin: string; status: number; mediaType: string },
  headersObj: Record<string, string>,
): PublicObservation {
  const h = (name: string): string | undefined => headersObj[name.toLowerCase()]
  const transport = h('strict-transport-security') ?? ''
  const ages = transport.split(';').filter(d => /^\s*max-age\s*(?:=|$)/i.test(d))
  const parsedAge = ages.length === 1 ? ages[0].match(/^\s*max-age\s*=\s*(?:"(\d+)"|(\d+))\s*$/i) : null
  const maxAge = parsedAge ? Number(parsedAge[1] ?? parsedAge[2]) : NaN
  const xcto = h('x-content-type-options')
  const cspVal = h('content-security-policy')
  const cspRo = h('content-security-policy-report-only')
  const xfo = h('x-frame-options')
  const frameAncestors = Boolean(cspVal && /(?:^|;)\s*frame-ancestors\s+[^;]+/i.test(cspVal))
  const validXfo = Boolean(xfo && /^(?:deny|sameorigin)\s*$/i.test(xfo.split(',', 1)[0]))
  const refRaw = h('referrer-policy')
  const refPolicy: PublicObservation['referrerPolicy'] = refRaw === undefined ? 'absent'
    : refRaw.includes('"') ? 'unrecognized'
      : (refRaw.split(',').map(t => t.trim()).findLast((t): t is typeof VALID_REFERRER_POLICIES[number] => (VALID_REFERRER_POLICIES as readonly string[]).includes(t)) ?? 'unrecognized')
  const srv = h('server')?.trim()
  return {
    origin: row.origin, finalOrigin: row.finalOrigin, status: row.status, mediaType: row.mediaType || 'unknown',
    transportMaxAge: Number.isSafeInteger(maxAge) && maxAge >= 0 ? maxAge : null,
    includeSubDomains: /(?:^|;)\s*includeSubDomains\s*(?:;|$)/i.test(transport),
    source: 'public response',
    contentTypeOptions: xcto === undefined ? 'absent' : xcto.split(',', 1)[0].trim().toLowerCase() === 'nosniff' ? 'nosniff' : 'unrecognized',
    referrerPolicy: refPolicy,
    contentSecurityPolicy: cspVal !== undefined ? (cspVal.trim() ? 'enforced' : 'unrecognized') : cspRo !== undefined ? (cspRo.trim() ? 'report-only' : 'unrecognized') : 'absent',
    frameProtection: frameAncestors && validXfo ? 'both' : frameAncestors ? 'csp-frame-ancestors' : validXfo ? 'x-frame-options' : xfo !== undefined ? 'unrecognized' : 'absent',
    serverDisclosure: h('x-powered-by') ? 'technology' : !srv ? 'absent' : /(?:\d|\/|next|express|php|asp\.net|nginx|apache)/i.test(srv) ? 'technology' : 'generic',
  }
}

export const VARIANT_SWEEP_MAX_FILE_BYTES = 256 * 1024

function isPathStrictlyInside(canonicalRoot: string, candidatePath: string): boolean {
  const rel = relative(canonicalRoot, candidatePath)
  if (!rel || rel === '.' || rel === '..') return false
  if (rel.startsWith(`..${sep}`) || rel.startsWith('../') || isAbsolute(rel)) return false
  return true
}

/**
 * Resolve a model-controlled or discovered file path strictly inside `allowedRootDir`.
 * Enforces:
 *  (a) canonical `realpathSync` strictly contained inside the canonical root (rejects `..` escapes,
 *      null bytes, and symlinks pointing outside the root),
 *  (b) `isSensitiveRepoRelativePath` refusal (rejects `.env`, `.env.*.js`, `.ssh/*`, `.git/*`, keys),
 *  (c) `stat.isFile()` (rejects directories, FIFOs, sockets, devices),
 *  (d) bounded file size (`<= maxBytes`, default 256 KiB).
 */
export function resolveSafeVariantSweepFile(
  allowedRootDir: string,
  candidatePath: string,
  maxBytes = VARIANT_SWEEP_MAX_FILE_BYTES,
): { realPath: string; size: number } | null {
  if (!allowedRootDir || !candidatePath || allowedRootDir.includes('\0') || candidatePath.includes('\0')) {
    return null
  }
  let canonicalRoot: string
  try {
    canonicalRoot = realpathSync(allowedRootDir)
  } catch {
    return null
  }
  let rootStat
  try {
    rootStat = statSync(canonicalRoot)
  } catch {
    return null
  }
  if (!rootStat.isDirectory()) return null

  const resolvedCandidate = isAbsolute(candidatePath)
    ? resolvePath(candidatePath)
    : resolvePath(canonicalRoot, candidatePath)
  if (!isPathStrictlyInside(canonicalRoot, resolvedCandidate)) return null

  const candidateRelPosix = relative(canonicalRoot, resolvedCandidate).split(sep).join('/')
  if (isSensitiveRepoRelativePath(candidateRelPosix)) return null

  let canonicalTarget: string
  try {
    canonicalTarget = realpathSync(resolvedCandidate)
  } catch {
    return null
  }
  if (!isPathStrictlyInside(canonicalRoot, canonicalTarget)) return null

  const canonicalRelPosix = relative(canonicalRoot, canonicalTarget).split(sep).join('/')
  if (isSensitiveRepoRelativePath(canonicalRelPosix)) return null

  let targetStat
  try {
    targetStat = statSync(canonicalTarget)
  } catch {
    return null
  }
  if (!targetStat.isFile() || targetStat.size > maxBytes) return null
  return { realPath: canonicalTarget, size: targetStat.size }
}

const VARIANT_SWEEP_SCAN_EXT = new Set(['.ts', '.tsx', '.js', '.jsx', '.mjs', '.cjs', '.py', '.go', '.java', '.rb'])
const VARIANT_SWEEP_SKIP_DIRS = new Set(['node_modules', '.git', 'dist', 'build'])

/**
 * Deterministic variant-sweep sibling walker over mounted `/repos` (`H-39` sibling).
 * Enforces `isSensitiveRepoEntry` on every directory and file and `resolveSafeVariantSweepFile`
 * before reading so worker-excluded files (`.env.*.js`, `.ssh/*`, `.git/config`, keys) can never
 * be echoed into chain-step hypotheses.
 */
export function collectVariantSweepSiblingHits(
  reposDir: string,
  mountedRepos: readonly string[],
  searchTokens: readonly string[],
  excludeLocations: readonly { repo?: string; file: string; startLine: number; endLine: number }[] = [],
  maxHits = 20,
): Array<{ repo: string; file: string; line: number; preview: string }> {
  const siblingHits: Array<{ repo: string; file: string; line: number; preview: string }> = []
  if (searchTokens.length === 0) return siblingHits

  let canonicalReposRoot: string | null = null
  try { canonicalReposRoot = realpathSync(reposDir) } catch { canonicalReposRoot = null }
  if (!canonicalReposRoot) return siblingHits

  const seenHit = new Set<string>()
  const overlapsOriginal = (repo: string, file: string, line: number) =>
    excludeLocations.some(l => l.repo === repo && l.file === file && line >= l.startLine - 1 && line <= l.endLine + 1)

  for (const mountedRepo of mountedRepos) {
    if (siblingHits.length >= maxHits) break
    const repoRel = mountedRepo.replace(/^\/repos\//, '').replace(/\/+$/, '')
    if (!repoRel || repoRel.includes('\0') || isAbsolute(repoRel)) continue
    const repoRootCandidate = resolvePath(canonicalReposRoot, repoRel)
    const repoRelCheck = relative(canonicalReposRoot, repoRootCandidate)
    if (!repoRelCheck || repoRelCheck === '..' || repoRelCheck.startsWith(`..${sep}`) || isAbsolute(repoRelCheck)) continue
    let canonicalRepoRoot: string
    try { canonicalRepoRoot = realpathSync(repoRootCandidate) } catch { continue }
    const canonicalRepoRel = relative(canonicalReposRoot, canonicalRepoRoot)
    if (!canonicalRepoRel || canonicalRepoRel === '..' || canonicalRepoRel.startsWith(`..${sep}`) || isAbsolute(canonicalRepoRel)) continue

    const stack = [canonicalRepoRoot]
    while (stack.length > 0 && siblingHits.length < maxHits) {
      const dir = stack.pop()!
      let entries: string[]
      try { entries = readdirSync(dir) } catch { continue }
      for (const entry of entries) {
        if (VARIANT_SWEEP_SKIP_DIRS.has(entry)) continue
        const full = join(dir, entry)
        let lst
        try { lst = lstatSync(full) } catch { continue }
        if (lst.isSymbolicLink()) continue
        const relEntryPosix = relative(canonicalRepoRoot, full).split(sep).join('/')
        if (lst.isDirectory()) {
          if (isSensitiveRepoEntry(relEntryPosix, entry, true)) continue
          stack.push(full)
          continue
        }
        if (isSensitiveRepoEntry(relEntryPosix, entry, false)) continue
        if (!VARIANT_SWEEP_SCAN_EXT.has(extname(entry).toLowerCase())) continue
        const safeSibling = resolveSafeVariantSweepFile(canonicalRepoRoot, full, VARIANT_SWEEP_MAX_FILE_BYTES)
        if (!safeSibling) continue
        const relFile = relative(canonicalRepoRoot, safeSibling.realPath).split(sep).join('/')
        if (isSensitiveRepoEntry(relFile, basename(safeSibling.realPath), false)) continue
        let content: string
        try { content = readFileSync(safeSibling.realPath, 'utf8') } catch { continue }
        const lines = content.split('\n')
        for (let i = 0; i < lines.length && siblingHits.length < maxHits; i += 1) {
          const line = lines[i]!
          const lineNo = i + 1
          if (!searchTokens.some(tok => line.includes(tok)) || overlapsOriginal(repoRel, relFile, lineNo)) continue
          const key = `${repoRel}:${relFile}:${lineNo}`
          if (seenHit.has(key)) continue
          seenHit.add(key)
          siblingHits.push({ repo: repoRel, file: relFile, line: lineNo, preview: line.trim().slice(0, 180) })
        }
      }
    }
  }
  return siblingHits
}

/**
 * Resolve a model-controlled `{ repo, file }` code location strictly within `reposDir` and
 * (when provided) one of the explicitly mounted repositories.
 */
export function resolveSafeVariantSweepLocation(
  reposDir: string,
  repo: string,
  file: string,
  mountedRepos?: readonly string[],
  maxBytes = VARIANT_SWEEP_MAX_FILE_BYTES,
): { realPath: string; size: number } | null {
  if (!reposDir || !repo || !file) return null
  if (reposDir.includes('\0') || repo.includes('\0') || file.includes('\0')) return null
  if (isAbsolute(file)) return null

  const repoRel = repo.replace(/^\/repos\//, '').replace(/\/+$/, '')
  if (!repoRel || isAbsolute(repoRel)) return null

  if (mountedRepos && mountedRepos.length > 0) {
    const allowedRepos = new Set(
      mountedRepos.map(m => m.replace(/^\/repos\//, '').replace(/\/+$/, '')).filter(Boolean),
    )
    if (!allowedRepos.has(repoRel)) return null
  }

  let canonicalReposRoot: string
  try {
    canonicalReposRoot = realpathSync(reposDir)
  } catch {
    return null
  }

  const candidateRepoRoot = resolvePath(canonicalReposRoot, repoRel)
  if (!isPathStrictlyInside(canonicalReposRoot, candidateRepoRoot)) return null

  let canonicalRepoRoot: string
  try {
    canonicalRepoRoot = realpathSync(candidateRepoRoot)
  } catch {
    return null
  }
  if (!isPathStrictlyInside(canonicalReposRoot, canonicalRepoRoot)) return null

  return resolveSafeVariantSweepFile(canonicalRepoRoot, file, maxBytes)
}

/**
 * Normalize concrete resource ID segments (UUIDs, ULIDs, numeric IDs, opaque tokens, prefixed IDs,
 * and framework param templates) to `:id` via the canonical `normalizeRouteTemplate`.
 */
export function normalizeConfirmedRouteTemplate(path?: string | null): string {
  return normalizeRouteTemplate(path, { preserveCase: false })
}

export interface PlannerConfirmedRef extends AlreadyConfirmedRef {
  hasCompositeReceipt?: boolean
}

export type DuplicatePlannedStepReason = 'already_confirmed' | 'in_flight' | null

export interface PlannedStepDedupeCandidate {
  title: string
  hypothesis: string
  category?: string | null
  origins?: readonly string[]
  sourceOrigins?: readonly string[]
  skills?: readonly string[]
  dependsOnFactIds?: readonly string[]
  dependsOnStepIds?: readonly string[]
  checkpointCapId?: string | null
  trialIndex?: number
  structuredTargets?: readonly StructuredStepTarget[]
}

const IN_FLIGHT_STEP_STATUSES = new Set<ChainStep['status']>(['pending', 'ready', 'running'])

/** Canonical `(origin, normalizedRoute, classFamily)` dedupe key for planner/dispatch suppression. */
export function plannerDedupeTupleKey(origin: string, route: string, categoryOrClass: string): string | null {
  const cleanOrigin = origin.trim()
  const normRoute = normalizeConfirmedRouteTemplate(route)
  if (!cleanOrigin || !normRoute || normRoute === '/') return null
  const rawClass = (categoryOrClass ?? '').trim()
  if (!rawClass) return null
  const family = canonicalPlannerDedupeFamily(rawClass, confirmedCategoryFamily)
  if (!family) return null
  return `${cleanOrigin}\u0000${normRoute}\u0000${family}`
}

/** Build confirmed `(origin, normalizedRoute, classFamily)` and composite-confirmed lookup sets. */
export function buildConfirmedTupleKeySets(confirmed: readonly PlannerConfirmedRef[]): {
  all: Set<string>
  composite: Set<string>
  compositeRoutes: Set<string>
} {
  const all = new Set<string>()
  const composite = new Set<string>()
  const compositeRoutes = new Set<string>()
  for (const ref of confirmed) {
    const origin = ref.origin?.trim()
    const normRoute = normalizeConfirmedRouteTemplate(ref.path)
    if (!origin || !normRoute || normRoute === '/') continue
    if (ref.hasCompositeReceipt) {
      compositeRoutes.add(`${origin}\u0000${normRoute}`)
    }
    const probeClass = ref.probeClass?.trim()
    if (!probeClass) continue
    const tupleKey = plannerDedupeTupleKey(origin, normRoute, probeClass)
    if (!tupleKey) continue
    all.add(tupleKey)
    if (ref.hasCompositeReceipt) {
      composite.add(tupleKey)
    }
  }
  return { all, composite, compositeRoutes }
}

/** Build active in-flight `(origin, normalizedRoute, classFamily)` tuple set (excludes `trialIndex > 0`). */
export function buildInFlightTupleKeys(
  steps: readonly Pick<ChainStep, 'status' | 'trialIndex' | 'title' | 'hypothesis' | 'category' | 'sourceOrigins'>[],
): Set<string> {
  const keys = new Set<string>()
  for (const step of steps) {
    if (!IN_FLIGHT_STEP_STATUSES.has(step.status)) continue
    if ((step.trialIndex ?? 0) > 0) continue
    const routes = [...new Set(templatesMentionedInText(`${step.title} ${step.hypothesis}`).map(normalizeConfirmedRouteTemplate))]
      .filter(route => route && route !== '/')
    if (!routes.length) continue
    for (const origin of step.sourceOrigins ?? []) {
      for (const route of routes) {
        const key = plannerDedupeTupleKey(origin, route, step.category)
        if (key) keys.add(key)
      }
    }
  }
  return keys
}

function addStepTuplesToInFlightSet(
  inFlight: Set<string>,
  step: { title: string; hypothesis: string; category: string; origins: readonly string[]; trialIndex?: number },
): void {
  if ((step.trialIndex ?? 0) > 0) return
  const routes = [...new Set(templatesMentionedInText(`${step.title} ${step.hypothesis}`).map(normalizeConfirmedRouteTemplate))]
    .filter(route => route && route !== '/')
  if (!routes.length) return
  for (const origin of step.origins) {
    for (const route of routes) {
      const key = plannerDedupeTupleKey(origin, route, step.category)
      if (key) inFlight.add(key)
    }
  }
}

function isCompositeVerificationConfirmed(
  proofReceiptObj: Record<string, unknown> | undefined,
  findingEvidence?: Record<string, unknown>,
  compReceiptObj?: Record<string, unknown>,
): boolean {
  const compVer = (
    proofReceiptObj?.compositeVerification
    ?? findingEvidence?.compositeVerification
    ?? compReceiptObj?.verification
  ) as Record<string, unknown> | undefined
  if (compVer && typeof compVer === 'object') {
    if (compVer.confirmed === true || compVer.ok === true) return true
    if (compVer.confirmed === false || compVer.ok === false) return false
  }
  const ver = proofReceiptObj?.verification as Record<string, unknown> | undefined
  if (ver && typeof ver === 'object') {
    return ver.confirmed === true || ver.ok === true
  }
  return false
}

function parseTerminalEndpointCandidate(raw: unknown): { method: string | null; path: string } | null {
  if (typeof raw !== 'string') return null
  const trimmed = raw.trim()
  if (!trimmed) return null
  const withMethod = /^(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s+(\/\S*)$/i.exec(trimmed)
  if (withMethod) {
    return { method: withMethod[1]!.toUpperCase(), path: withMethod[2]! }
  }
  if (trimmed.startsWith('/')) {
    return { method: null, path: trimmed }
  }
  return null
}

/** Build normalized confirmed path + `(METHOD, path)` lookup sets for floor-dedupe filtering. */
export function buildConfirmedRouteSets(confirmed: readonly AlreadyConfirmedRef[]): {
  paths: Set<string>
  methodPaths: Set<string>
  anyMethodPaths: Set<string>
} {
  const paths = new Set<string>()
  const methodPaths = new Set<string>()
  const anyMethodPaths = new Set<string>()
  for (const ref of confirmed) {
    const norm = normalizeConfirmedRouteTemplate(ref.path)
    if (!norm || norm === '/') continue
    paths.add(norm)
    const method = ref.method?.trim().toUpperCase()
    if (method && method !== 'ANY') {
      methodPaths.add(`${method} ${norm}`)
    } else {
      anyMethodPaths.add(norm)
    }
  }
  return { paths, methodPaths, anyMethodPaths }
}

/** True when a candidate `(method, path)` matches an already-confirmed floor/agent route template. */
export function isRouteConfirmed(
  candidate: { method?: string | null; path: string },
  sets: { paths: ReadonlySet<string>; methodPaths: ReadonlySet<string>; anyMethodPaths: ReadonlySet<string> },
  options?: { matchAnyMethod?: boolean },
): boolean {
  const norm = normalizeConfirmedRouteTemplate(candidate.path)
  if (!norm || norm === '/') return false
  if (options?.matchAnyMethod) return sets.paths.has(norm)
  if (sets.anyMethodPaths.has(norm)) return true
  const method = candidate.method?.trim().toUpperCase()
  if (!method || method === 'ANY') return sets.paths.has(norm)
  return sets.methodPaths.has(`${method} ${norm}`)
}

export interface ExecReconPlannerHost extends ExecCoreServices {
  /** Shared unified per-run orchestration state store (Move O5). */
  runState?: RunOrchestrationStateStore
  labRunner: LabRunner
  maxDurationMs: number
  active: Map<string, Active>
  coordinator: Map<string, CoordinatorTask>
  probePlans: ProbePlanRegistry
  startedLabRuns: Set<string>
  startedLabHandles: Map<string, LabTargetHandle>
  prePhase0SeededSteps: Map<string, boolean>
  plannerDoneRound: Map<string, number>
  dispatchFunnels: Map<string, DispatchFunnelCounts>
  detLeadConsumed: Set<string>
  tierAStepIds: Set<string>
  tierAFactIds: Set<string>
  approvedOriginsSet: (run: Run) => Set<string>
  authorize: (job: Active) => boolean
  currentCoordinator: (runId: string, task: CoordinatorTask) => boolean
  buildGrant: (job: Active, run: Run, permittedAtAdmission: ReadonlySet<string>) => { grant: Grant; secrets: NamedSecret[]; currentSecrets: () => NamedSecret[] }
  projectReposMount: (projectId: string) => { reposDir?: string; mountedRepos: string[] }
  deterministicLaneKey: (run: Run) => string
  notifyCheckpoint: (runId: string, checkpoint: "phase0" | "post-floor" | "deterministic-lane") => void
  seedCodeToRuntimeLeads: (run: Run, assignment: Assignment, hypotheses: readonly CodeToRuntimeHypothesis[]) => number
  correlateSpecDependencies: (
    freshRun: Run,
    claimed: Assignment,
    specs: ReturnType<Store["listProjectSpecsFull"]>,
    approvedOrigins: ReadonlySet<string>,
    defaultOrigin: string | undefined,
    signal: AbortSignal,
    secrets: readonly NamedSecret[],
  ) => Promise<void>
  runSourceFirstCodeAudit: (run: Run, threatModel: readonly ThreatModelSummary[], profiles: readonly ResolvedModelProfile[], signal: AbortSignal) => Promise<{ suspects: Fact[]; stepsCreated: ChainStep[] }>
  baselineFinding: (run: Run, asset: Candidate, review: EvidenceReview) => typeof findings.$inferSelect | undefined
  saveBaselineFinding: (run: Run, asset: Candidate, review: EvidenceReview, status: Finding["status"], reason: string, evidenceIds: string[], existingId?: string) => void
  completeWorker: (worker: Assignment, run: Run, outcome: string, evidenceIds: string[], checks?: CheckCoverage[], secrets?: readonly NamedSecret[]) => void
  expandEligibleMultiTrialSteps: (run: Run) => void
  endpointGraphCatalog: (runId: string) => { endpointParams: unknown[]; apiDependencies: unknown[] }
  noteDryStreak: (run: Run) => unknown
  reinvestigationGuardFor: (runId: string) => ReinvestigationGuard
  highPriorityQueueEmpty: (run: Pick<Run, 'id' | 'goalRevision'>) => boolean
  noteCappedReinvestigation: (run: Pick<Run, 'id'>, key: string, attempted: number) => void
  recordDispatchFunnel: (runId: string, funnel: DispatchFunnelCounts) => void
  noteStrandedReadySteps: (runId: string, detail: { roundNo: number; stopReason: DispatchStopReason; remainingReady: number; dispatched: number; planned: number }) => void
  tracePlannerDecision: (runId: string, payload: { roundIdx: number; factsCount: number; detLeadsCount: number; alreadyConfirmedCount: number; spawnedSteps: number; k6DryStreak: number; dynamicStepBudget: number; durationMs: number; costUsd: number; inputStateHash?: string; summary?: string; error?: string }) => void
  codeSliceForAssignment: (run: Pick<Run, 'id'>, step: Pick<ChainStep, 'title' | 'hypothesis'>, parentFacts: readonly Fact[]) => CodeDataflowSlice | undefined
  shouldCoordinatorAnswer: (content: string) => boolean
  resetBoardHops: (run: Run) => void
  spawnRunTask?: <T = void>(
    runId: string,
    label: string,
    fn: (signal: AbortSignal) => Promise<T> | T,
    options?: SpawnTaskOptions,
  ) => SupervisedTask<T>
}

/**
 * Convert an `InvariantSynthesizer` `CapabilitySeedRecord` into a strictly quarantined
 * (`promotionStatus: 'capability_only'`) `CapabilityLedger` node input with a valid opaque handle.
 */
export function seedRecordToLedgerInput(
  seed: CapabilitySeedRecord,
  defaultOrigin = 'unknown',
): AddCapabilityInput {
  const slot = seed.metadata.hypothesisId.replace(/[^A-Za-z0-9._-]/g, '_').replace(/^[^A-Za-z0-9]+/, '').slice(0, 60) || 'seed'
  const capId = formatDerivedCapabilityHandle('synth', slot)
  const serviceOrigin = seed.serviceOrigin && seed.serviceOrigin !== 'unknown'
    ? seed.serviceOrigin
    : (defaultOrigin || 'unknown')
  return {
    capId,
    kind: seed.kind,
    promotionStatus: 'capability_only',
    provenance: seed.metadata.mode === 'white-box' ? 'static_analysis' : 'runtime_discovery',
    tenantScope: seed.tenantScope,
    actorPersona: seed.actorPersona,
    serviceOrigin,
    surface: seed.surface,
    temporalState: seed.temporalState,
    artifactDigest: seed.artifactDigest,
    artifactSummary: seed.summary,
    metadata: {
      hypothesisId: seed.metadata.hypothesisId,
      hypothesisKind: seed.metadata.hypothesisKind,
      entity: seed.metadata.entity,
      mode: seed.metadata.mode,
      score: seed.metadata.score,
      ...(seed.metadata.targetRoute ? { targetRoute: seed.metadata.targetRoute } : {}),
      synthCapId: seed.capId,
      synthProvenance: seed.provenance,
    },
  }
}

export interface SeedCapabilityLedgerInvariantsOptions {
  mode?: SynthesizerMode
  graph?: ProgramGraph
  /** Optional Phase-0 / Phase-A `StaticWorkspaceSnapshot` to reuse pre-extracted graph & sources without walking disk or re-parsing. */
  staticSnapshot?: StaticWorkspaceSnapshot
  sourceFiles?: readonly SourceFileInput[]
  services?: readonly MonorepoService[]
  serviceOrigins?: readonly ServiceOriginMapping[]
  compose?: string
  ingress?: string
  reposDir?: string
  mountedRepos?: readonly string[]
  specs?: ReturnType<Store['listProjectSpecsFull']>
  runtime?: Omit<RuntimeDiscoveryInput, 'mode'>
  approvedOrigins?: ReadonlySet<string>
  maxHypotheses?: number
  /** Promote high-signal cross-surface / cross-service / lifecycle hypotheses into Wave 1 `chain` steps (default true when tier > 0). */
  promoteWave1Chains?: boolean
  /** Cap on Wave 1 `chain` steps seeded from invariant synthesis (default 6). */
  maxWave1ChainSteps?: number
  /** Optional abort signal propagated to async file collection and worker-isolated `ProgramGraph` extraction. */
  signal?: AbortSignal
}

export interface SeedCapabilityLedgerInvariantsResult {
  mode: SynthesizerMode
  synthesis: SynthesizeInvariantsResult
  seededCount: number
  quarantinedCount: number
  capIds: string[]
  wave1ChainStepsCreated: number
  wave1ChainStepIds: string[]
}

const WAVE1_INVARIANT_KIND_RANK: Record<InvariantHypothesis['kind'], number> = {
  trust_boundary_mismatch: 0,
  policy_asymmetry: 1,
  runtime_surface_asymmetry: 2,
  lifecycle_invariant: 3,
}

const WAVE1_INVARIANT_PRIORITY: Record<InvariantHypothesis['severity'], number> = {
  critical: 96,
  high: 93,
  medium: 90,
  low: 88,
}

function invariantHypothesisSkills(hyp: InvariantHypothesis): string[] {
  const skills = new Set<string>(['multihop-chains', 'chain-primitives', 'false-positive-elimination'])
  if (hyp.kind === 'trust_boundary_mismatch') {
    skills.add('cross-host-chaining')
    skills.add('auth-oauth-oidc')
    if (hyp.capabilityKind === 'parser_or_cache_primitive') skills.add('cache-smuggling-desync')
  } else if (hyp.kind === 'policy_asymmetry' || hyp.kind === 'runtime_surface_asymmetry') {
    skills.add('access-control-bola-bfla')
    if (hyp.surface === 'graphql') skills.add('api-rest-graphql')
    if (hyp.surface === 'ws') skills.add('websocket-cswsh')
    if (hyp.surface === 'storage') skills.add('upload-storage-security')
  } else if (hyp.kind === 'lifecycle_invariant') {
    skills.add('business-logic-workflows')
    skills.add('access-control-bola-bfla')
  }
  return [...skills]
}

function invariantHypothesisCategory(hyp: InvariantHypothesis): string {
  if (hyp.kind === 'lifecycle_invariant') return 'business-logic'
  if (hyp.kind === 'trust_boundary_mismatch' && hyp.capabilityKind === 'identity_session') return 'auth-identity'
  return 'broken-access-control'
}

function extractRouteRefsFromText(texts: readonly string[]): string[] {
  const found: string[] = []
  const seen = new Set<string>()
  const re = /\b(?:(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s+)?(\/[A-Za-z0-9._~!$&'()*+,;=:@%/-]{2,120})/g
  for (const text of texts) {
    for (const match of text.matchAll(re)) {
      const method = match[1]?.toUpperCase()
      const rawPath = match[2]!.replace(/[),.;:'"`]+$/, '')
      if (rawPath.length < 2 || rawPath.startsWith('//') || /\.(?:ts|tsx|js|jsx|py|go|java|rb|yml|yaml|json|md)$/i.test(rawPath)) continue
      const ref = method ? `${method} ${rawPath}` : rawPath
      if (seen.has(ref)) continue
      seen.add(ref)
      found.push(ref)
      if (found.length >= 4) return found
    }
  }
  return found
}

const INVARIANT_SCAN_EXT = new Set(['.ts', '.tsx', '.js', '.jsx', '.mjs', '.cjs', '.py', '.go', '.java', '.rb'])
const INVARIANT_SKIP_DIRS = new Set(['node_modules', '.git', 'dist', 'build', 'coverage', '.next', '__pycache__'])
const INVARIANT_WALK_YIELD_EVERY = 8

function yieldEventLoopTurn(): Promise<void> {
  return new Promise<void>(resolve => {
    setImmediate(resolve)
  })
}

export type RepoOriginAffinityConfidence =
  | 'exact'
  | 'config'
  | 'host'
  | 'path'
  | 'port'
  | 'live_route'
  | 'hostname_affinity'
  | 'single_origin'
  | 'unmapped'

export interface RepoAffinityDescriptor {
  /** Mounted repo identifier or slug (e.g. `mail-svc`, `owner/payments-api`, `/repos/worker-engine`). */
  repo: string
  /** Optional relative root prefix inside workspace/source files. */
  root?: string
  /** Optional `package.json` `name` field. */
  packageName?: string
  /** Optional `package.json` `homepage` URL or hostname. */
  homepage?: string
  /** Optional explicit hostnames/URLs extracted from config files (`wrangler.toml`, `vercel.json`, `fly.toml`, `.env`, `CNAME`, etc.). */
  configHosts?: readonly string[]
  /** Optional routes declared by this repo in static/AST extraction. */
  declaredRoutes?: readonly string[]
}

export interface LiveOriginEndpointObservation {
  origin: string
  pathTemplate: string
  method?: string
  status?: number | null
  source?: string | null
}

export interface RepoOriginAffinityInput {
  approvedOrigins: readonly string[]
  repos: readonly (string | RepoAffinityDescriptor)[]
  /** Optional pre-computed compose/ingress/AST service-to-origin mappings. */
  serviceOrigins?: readonly ServiceOriginMapping[]
  /** Optional docker-compose YAML text. */
  compose?: string
  /** Optional Kubernetes/Traefik ingress YAML text. */
  ingress?: string
  /** Optional discovered live endpoints per origin for route-overlap cross-matching. */
  liveEndpoints?: readonly LiveOriginEndpointObservation[]
}

export interface RepoOriginAffinityMapping {
  repo: string
  root: string
  origin?: string
  pathPrefix?: string
  confidence: RepoOriginAffinityConfidence
  score: number
  evidence: string[]
}

const AFFINITY_GENERIC_STOPWORDS = new Set([
  'app', 'web', 'svc', 'service', 'server', 'backend', 'frontend', 'bot', 'repo',
  'mono', 'monorepo', 'client', 'ui', 'site', 'core', 'main', 'hub', 'platform',
  'tool', 'tools', 'cli', 'lib', 'pkg', 'sdk', 'www', 'prod', 'production', 'staging',
])

const LIVE_ROUTE_BOILERPLATE = new Set([
  '/', '/health', '/healthz', '/ready', '/readyz', '/livez', '/status', '/ping',
  '/metrics', '/robots.txt', '/favicon.ico', '/sitemap.xml',
])

const STATIC_ONLY_ENDPOINT_SOURCES = new Set(['repo_ast', 'program_graph', 'static_ast', 'code_audit'])

function normalizeRepoRelPath(raw: string): string {
  return raw.trim().replace(/^\/repos\//, '').replace(/^\/+|\/+$/g, '')
}

function repoBasenameSlug(raw: string): string {
  const clean = normalizeRepoRelPath(raw)
  const parts = clean.split('/').filter(Boolean)
  return (parts[parts.length - 1] ?? clean).toLowerCase()
}

function stemAffinityToken(raw: string): string {
  const tok = raw.toLowerCase().replace(/[^a-z0-9]/g, '')
  if (!tok) return ''
  if (tok.length > 5 && tok.endsWith('ers')) return tok.slice(0, -3)
  if (tok.length > 5 && tok.endsWith('er') && !/(?:server|worker|cluster|master|helper|member|folder|header|broker|driver|runner|ledger|docker|center|number|filter|render|router|parser)$/.test(tok)) return tok.slice(0, -2)
  if (tok.length > 5 && tok.endsWith('ing')) return tok.slice(0, -3)
  if (tok.length > 4 && tok.endsWith('ies')) return `${tok.slice(0, -3)}y`
  if (tok.length > 4 && /(?:ches|shes|xes|zes|ses)$/.test(tok)) return tok.slice(0, -2)
  return tok.length > 3 && tok.endsWith('s') && !/(?:ss|us|is|status|access)$/.test(tok) ? tok.slice(0, -1) : tok
}

function tokenizeAffinitySlug(raw: string): string[] {
  return raw
    .replace(/([a-z0-9])([A-Z])/g, '$1-$2')
    .toLowerCase()
    .split(/[^a-z0-9]+/)
    .map(t => t.trim())
    .filter(Boolean)
}

function extractHostCandidate(raw: string): string | null {
  const trimmed = raw.trim().replace(/^['"`]+|['"`]+$/g, '')
  if (!trimmed) return null
  if (/^https?:\/\//i.test(trimmed)) {
    try { return new URL(trimmed).hostname.toLowerCase() } catch { return null }
  }
  const hostOnly = trimmed.split(/[/:?#]/, 1)[0]?.toLowerCase() ?? ''
  if (/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$/.test(hostOnly)) {
    return hostOnly
  }
  return null
}

function extractHostsFromConfigText(text: string): string[] {
  const hosts = new Set<string>()
  for (const m of text.matchAll(/https?:\/\/([A-Za-z0-9.-]+)(?::\d+)?/g)) {
    const h = m[1]?.toLowerCase()
    if (h && h.includes('.')) hosts.add(h)
  }
  for (const m of text.matchAll(/\b(?:host|hostname|domain|route|pattern|custom_domain|cname|app_url|public_url|base_url|site_url)\s*[:=]\s*['"]?([A-Za-z0-9.-]+\.[A-Za-z]{2,})/gi)) {
    const h = m[1]?.toLowerCase()
    if (h) hosts.add(h)
  }
  return [...hosts]
}

interface ParsedOriginAffinityInfo {
  origin: string
  hostname: string
  subdomain: string
  apexBrand: string
  subTokens: string[]
  subStems: string[]
  subStemSet: Set<string>
}

function parseOriginAffinityInfo(origin: string): ParsedOriginAffinityInfo | null {
  try {
    const url = new URL(origin)
    const hostname = url.hostname.toLowerCase()
    const labels = hostname.split('.').filter(Boolean)
    let subdomain = hostname
    let apexBrand = ''
    if (labels.length >= 3) {
      // Handle multi-label public suffixes conservatively (e.g. .co.uk) as well as standard 2-label apex (dyad.sh)
      const secondLast = labels[labels.length - 2]!
      const last = labels[labels.length - 1]!
      const isTwoPartTld = last.length === 2 && /^(?:co|com|org|net|gov|edu|ac)$/.test(secondLast) && labels.length >= 4
      const apexStart = isTwoPartTld ? labels.length - 3 : labels.length - 2
      subdomain = labels.slice(0, apexStart).join('.')
      apexBrand = labels[apexStart] ?? ''
    } else if (labels.length === 2) {
      // e.g. `dmail.example` or `upload-logs.example` -> subdomain `dmail` / `upload-logs`, brand `example`
      subdomain = labels[0]!
      apexBrand = labels[1]!
    }
    const subTokens = tokenizeAffinitySlug(subdomain)
    const subStems = [...new Set(subTokens.map(stemAffinityToken).filter(Boolean))]
    return {
      origin,
      hostname,
      subdomain,
      apexBrand,
      subTokens,
      subStems,
      subStemSet: new Set(subStems),
    }
  } catch {
    return null
  }
}

function parseComposeOrIngressHostMatches(
  text: string | undefined,
  approvedHostToOrigin: ReadonlyMap<string, string>,
): Array<{ serviceHint: string; origin: string; source: 'compose' | 'ingress' }> {
  if (!text || !approvedHostToOrigin.size) return []
  const results: Array<{ serviceHint: string; origin: string; source: 'compose' | 'ingress' }> = []
  const lines = text.split(/\r?\n/)
  let currentService = ''
  let currentHost = ''
  for (const rawLine of lines) {
    const trimmed = rawLine.trim()
    if (!trimmed || trimmed.startsWith('#')) continue
    // Compose top-level service key under `services:` (`  my-svc:`)
    const svcMatch = /^ {2}([A-Za-z0-9_.-]{1,80}):\s*$/.exec(rawLine)
    if (svcMatch) {
      currentService = svcMatch[1]!.toLowerCase()
      currentHost = ''
    }
    // Ingress host line (`- host: foo.example` or `host: foo.example`)
    const hostLine = /^-?\s*host\s*:\s*['"]?([A-Za-z0-9.-]+)['"]?/.exec(trimmed)
    if (hostLine) {
      currentHost = hostLine[1]!.toLowerCase()
    }
    // Ingress backend service name (`name: my-svc` or `serviceName: my-svc`)
    const ingressSvc = /^(?:name|serviceName)\s*:\s*['"]?([A-Za-z0-9_.-]{1,80})['"]?/.exec(trimmed)
    if (ingressSvc && currentHost) {
      const origin = approvedHostToOrigin.get(currentHost)
      if (origin) {
        results.push({ serviceHint: ingressSvc[1]!.toLowerCase(), origin, source: 'ingress' })
      }
    }
    // Any approved hostname mentioned inside a compose service stanza (Traefik Host(`...`), env VIRTUAL_HOST, etc.)
    if (currentService) {
      const lower = trimmed.toLowerCase()
      for (const [host, origin] of approvedHostToOrigin.entries()) {
        if (lower.includes(host)) {
          results.push({ serviceHint: currentService, origin, source: 'compose' })
        }
      }
    }
  }
  return results
}

function normalizeDeclaredRouteForOverlap(raw: string): string | null {
  const cleaned = raw.trim().replace(/^(?:GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS|ANY)\s+/i, '').split(/[?#]/, 1)[0] ?? ''
  if (!cleaned.startsWith('/')) return null
  const norm = normalizeEndpointTemplate(cleaned)
  if (!norm || LIVE_ROUTE_BOILERPLATE.has(norm.toLowerCase())) return null
  return norm.toLowerCase()
}

/**
 * Deterministic Repo→Origin affinity resolution:
 * 1. Explicit `serviceOrigins`, compose/ingress host rules, `package.json` `homepage`, or config host hints.
 * 2. Live-route overlap cross-matching (live origin returning 2xx/401/403 on routes matching repo's declared routes).
 * 3. Deterministic repo-slug / package-name ↔ hostname token & stem affinity (bipartite highest-score-first).
 * 4. Single-origin fallback ONLY when `approvedOrigins.length === 1`. When `approvedOrigins.length > 1`
 *    and ZERO confident match exists, marks the repo `unmapped` — NEVER dumping onto `approvedOrigins[0]`.
 */
export function resolveRepoOriginAffinity(input: RepoOriginAffinityInput): RepoOriginAffinityMapping[] {
  const uniqueOrigins = [...new Set(input.approvedOrigins.map(o => o.trim()).filter(Boolean))]
  const parsedOrigins = uniqueOrigins
    .map(parseOriginAffinityInfo)
    .filter((info): info is ParsedOriginAffinityInfo => info !== null)
  const approvedOriginSet = new Set(parsedOrigins.map(o => o.origin))
  const approvedHostToOrigin = new Map<string, string>()
  const brandCounts = new Map<string, number>()
  for (const info of parsedOrigins) {
    approvedHostToOrigin.set(info.hostname, info.origin)
    if (info.apexBrand) brandCounts.set(info.apexBrand, (brandCounts.get(info.apexBrand) ?? 0) + 1)
  }
  // Brand tokens that appear as the apex brand on approved origins (e.g. `dyad` for `*.dyad.sh`).
  const brandTokens = new Set<string>(
    [...brandCounts.entries()].filter(([, count]) => count >= 1).map(([brand]) => brand.toLowerCase()),
  )

  const normalizedRepos: Array<{
    descriptor: RepoAffinityDescriptor
    root: string
    slug: string
    pkgSlug: string
  }> = input.repos.map(entry => {
    const desc: RepoAffinityDescriptor = typeof entry === 'string' ? { repo: entry } : entry
    const root = normalizeRepoRelPath(desc.root ?? desc.repo)
    const slug = repoBasenameSlug(desc.repo)
    const rawPkg = (desc.packageName ?? '').trim().toLowerCase()
    const pkgSlug = rawPkg.includes('/') ? (rawPkg.split('/').pop() ?? rawPkg) : rawPkg
    return { descriptor: desc, root, slug, pkgSlug }
  })

  const resolved = new Map<number, RepoOriginAffinityMapping>()
  const claimedOrigins = new Set<string>()

  // Pre-index compose/ingress host rules if supplied.
  const composeIngressHints = [
    ...parseComposeOrIngressHostMatches(input.compose, approvedHostToOrigin),
    ...parseComposeOrIngressHostMatches(input.ingress, approvedHostToOrigin),
  ]

  // --- Pass 1: Explicit serviceOrigins, homepage, configHosts, compose/ingress ---
  for (let i = 0; i < normalizedRepos.length; i += 1) {
    const item = normalizedRepos[i]!
    const { descriptor, root, slug, pkgSlug } = item
    const aliases = new Set<string>([slug, root.toLowerCase(), ...(pkgSlug ? [pkgSlug] : [])].filter(Boolean))

    // 1a. Pre-computed ServiceOriginMapping (from Phase-0 / mapServicesToOrigins)
    const explicitMapping = (input.serviceOrigins ?? []).find(m => {
      if (!m.origin || m.confidence === 'unmapped' || !approvedOriginSet.has(m.origin)) return false
      const mSvc = m.service.toLowerCase()
      const mRoot = m.root ? normalizeRepoRelPath(m.root).toLowerCase() : ''
      return aliases.has(mSvc) || (Boolean(mRoot) && (aliases.has(mRoot) || mRoot.endsWith(`/${slug}`)))
    })
    if (explicitMapping?.origin) {
      resolved.set(i, {
        repo: descriptor.repo,
        root,
        origin: explicitMapping.origin,
        ...(explicitMapping.pathPrefix ? { pathPrefix: explicitMapping.pathPrefix } : {}),
        confidence: explicitMapping.confidence as RepoOriginAffinityConfidence,
        score: 120,
        evidence: explicitMapping.evidence.length ? [...explicitMapping.evidence] : [`explicit service mapping -> ${explicitMapping.origin}`],
      })
      if (!explicitMapping.pathPrefix) claimedOrigins.add(explicitMapping.origin)
      continue
    }

    // 1b. Explicit homepage or configHosts
    const configCandidates = [
      ...(descriptor.homepage ? [descriptor.homepage] : []),
      ...(descriptor.configHosts ?? []),
    ]
    let configOrigin: string | undefined
    let configHostMatched = ''
    for (const rawHint of configCandidates) {
      const host = extractHostCandidate(rawHint)
      if (!host) continue
      const hit = approvedHostToOrigin.get(host)
      if (hit) {
        configOrigin = hit
        configHostMatched = host
        break
      }
    }
    if (configOrigin) {
      resolved.set(i, {
        repo: descriptor.repo,
        root,
        origin: configOrigin,
        confidence: 'config',
        score: 115,
        evidence: [`repo manifest/config host hint "${configHostMatched}" matches ${configOrigin}`],
      })
      claimedOrigins.add(configOrigin)
      continue
    }

    // 1c. Explicit compose/ingress host rule matching repo alias
    const ciHit = composeIngressHints.find(h => aliases.has(h.serviceHint) || h.serviceHint === slug || slug.endsWith(`-${h.serviceHint}`))
    if (ciHit) {
      resolved.set(i, {
        repo: descriptor.repo,
        root,
        origin: ciHit.origin,
        confidence: 'host',
        score: 110,
        evidence: [`${ciHit.source} service "${ciHit.serviceHint}" mapped to ${ciHit.origin}`],
      })
      claimedOrigins.add(ciHit.origin)
    }
  }

  // --- Pass 2: Live-route overlap cross-matching ---
  const liveRoutesByOrigin = new Map<string, Set<string>>()
  const routeOriginFreq = new Map<string, number>()
  for (const ep of input.liveEndpoints ?? []) {
    const origin = ep.origin.trim()
    if (!approvedOriginSet.has(origin)) continue
    if (typeof ep.status === 'number') {
      const isLiveStatus = (ep.status >= 200 && ep.status < 300) || ep.status === 401 || ep.status === 403
      if (!isLiveStatus) continue
    } else if (ep.source && STATIC_ONLY_ENDPOINT_SOURCES.has(ep.source.toLowerCase())) {
      continue
    }
    const norm = normalizeDeclaredRouteForOverlap(ep.pathTemplate)
    if (!norm) continue
    let set = liveRoutesByOrigin.get(origin)
    if (!set) {
      set = new Set<string>()
      liveRoutesByOrigin.set(origin, set)
    }
    if (!set.has(norm)) {
      set.add(norm)
      routeOriginFreq.set(norm, (routeOriginFreq.get(norm) ?? 0) + 1)
    }
  }

  if (liveRoutesByOrigin.size > 0 && !(normalizedRepos.length === 1 && parsedOrigins.length > 1)) {
    for (let i = 0; i < normalizedRepos.length; i += 1) {
      if (resolved.has(i)) continue
      const { descriptor, root } = normalizedRepos[i]!
      const declared = [...new Set((descriptor.declaredRoutes ?? [])
        .map(normalizeDeclaredRouteForOverlap)
        .filter((r): r is string => Boolean(r)))]
      if (!declared.length) continue
      const scores: Array<{ origin: string; score: number; matched: string[] }> = []
      for (const [origin, liveSet] of liveRoutesByOrigin.entries()) {
        let score = 0
        const matched: string[] = []
        for (const route of declared) {
          if (!liveSet.has(route)) continue
          matched.push(route)
          const freq = routeOriginFreq.get(route) ?? 1
          score += freq === 1 ? 2 : 1
        }
        if (score > 0) scores.push({ origin, score, matched })
      }
      scores.sort((a, b) => b.score - a.score || b.matched.length - a.matched.length || a.origin.localeCompare(b.origin))
      const top = scores[0]
      const second = scores[1]
      if (top && (!second || (normalizedRepos.length >= parsedOrigins.length && top.score > second.score))) {
        resolved.set(i, {
          repo: descriptor.repo,
          root,
          origin: top.origin,
          confidence: 'live_route',
          score: 95 + top.matched.length,
          evidence: [`live-route overlap (${top.matched.length} route(s): ${top.matched.slice(0, 3).join(', ')}) matches ${top.origin}`],
        })
        claimedOrigins.add(top.origin)
      }
    }
  }

  // --- Pass 3: Deterministic repo-slug / package-name <-> hostname affinity (bipartite highest-score-first) ---
  const scoreRepoVsOrigin = (
    item: { slug: string; pkgSlug: string },
    originInfo: ParsedOriginAffinityInfo,
  ): { score: number; confidence: 'exact' | 'hostname_affinity'; reason: string } => {
    const candidates = [item.slug, ...(item.pkgSlug && item.pkgSlug !== item.slug ? [item.pkgSlug] : [])]
    let bestScore = 0
    let bestConfidence: 'exact' | 'hostname_affinity' = 'hostname_affinity'
    let bestReason = ''

    for (const rawName of candidates) {
      const allTokens = tokenizeAffinitySlug(rawName)
      if (!allTokens.length) continue
      // Strip leading/trailing apex brand tokens (e.g. `acme-payments` -> `payments`) when non-brand tokens remain.
      const withoutBrand = allTokens.filter(t => !brandTokens.has(t))
      const baseTokens = withoutBrand.length > 0 ? withoutBrand : allTokens
      const distinctiveTokens = baseTokens.filter(t => !AFFINITY_GENERIC_STOPWORDS.has(t))
      const effectiveTokens = distinctiveTokens.length > 0 ? distinctiveTokens : baseTokens

      const joinedBase = baseTokens.join('-')
      const joinedEffective = effectiveTokens.join('-')
      const subClean = originInfo.subdomain.toLowerCase()
      const subCompact = subClean.replace(/[^a-z0-9]/g, '')
      const baseCompact = joinedBase.replace(/[^a-z0-9]/g, '')
      const effCompact = joinedEffective.replace(/[^a-z0-9]/g, '')

      // Exact subdomain match after brand/stopword normalization
      if (rawName === subClean || joinedBase === subClean || joinedEffective === subClean) {
        if (100 > bestScore) {
          bestScore = 100
          bestConfidence = 'exact'
          bestReason = `repo slug "${rawName}" matches subdomain "${originInfo.subdomain}"`
        }
        continue
      }
      if (baseCompact.length >= 3 && (baseCompact === subCompact || effCompact === subCompact)) {
        if (95 > bestScore) {
          bestScore = 95
          bestConfidence = 'hostname_affinity'
          bestReason = `normalized slug "${joinedEffective}" matches subdomain "${originInfo.subdomain}"`
        }
        continue
      }

      const repoStems = [...new Set(effectiveTokens.map(stemAffinityToken).filter(Boolean))]
      const repoStemSet = new Set(repoStems)
      const subStems = originInfo.subStems
      const subStemSet = originInfo.subStemSet
      if (!repoStems.length || !subStems.length) continue

      const sharedStems = repoStems.filter(s => subStemSet.has(s))
      if (!sharedStems.length) continue

      // Identical stem sets (e.g. `image-uploader` -> {image, upload} === `upload-image` -> {upload, image})
      if (sharedStems.length === repoStemSet.size && sharedStems.length === subStemSet.size) {
        if (90 > bestScore) {
          bestScore = 90
          bestConfidence = 'hostname_affinity'
          bestReason = `repo stems [${repoStems.join(',')}] match subdomain "${originInfo.subdomain}"`
        }
        continue
      }

      // Every subdomain stem appears in repo stems (e.g. `llm-engine` -> `engine`, `dyad-eve-bot` -> `eve`)
      if (subStems.every(s => repoStemSet.has(s))) {
        const extra = Math.max(0, repoStems.length - subStems.length)
        const s = Math.max(62, 78 + subStems.length * 5 - extra * 3)
        if (s > bestScore) {
          bestScore = s
          bestConfidence = 'hostname_affinity'
          bestReason = `subdomain stems [${subStems.join(',')}] matched by repo "${rawName}"`
        }
        continue
      }

      // Every effective repo stem appears in subdomain stems (e.g. `dmail` -> `dmail-app`)
      if (repoStems.every(s => subStemSet.has(s))) {
        const extra = Math.max(0, subStems.length - repoStems.length)
        const s = Math.max(58, 72 + repoStems.length * 5 - extra * 3)
        if (s > bestScore) {
          bestScore = s
          bestConfidence = 'hostname_affinity'
          bestReason = `repo stems [${repoStems.join(',')}] contained in subdomain "${originInfo.subdomain}"`
        }
        continue
      }

      // Partial meaningful stem overlap (e.g. `chat-uploader` sharing `upload` with `upload-logs`)
      const meaningfulShared = sharedStems.filter(s => s.length >= 4 && !AFFINITY_GENERIC_STOPWORDS.has(s))
      if (meaningfulShared.length > 0) {
        const s = 30 + meaningfulShared.length * 15
        if (s > bestScore) {
          bestScore = s
          bestConfidence = 'hostname_affinity'
          bestReason = `shared stem(s) [${meaningfulShared.join(',')}] between repo "${rawName}" and subdomain "${originInfo.subdomain}"`
        }
      }
    }

    return { score: bestScore, confidence: bestConfidence, reason: bestReason }
  }

  // Phase 3a: commit strong hostname affinity matches (score >= 60), highest score first
  const strongEdges: Array<{ repoIdx: number; origin: string; score: number; confidence: 'exact' | 'hostname_affinity'; reason: string }> = []
  for (let i = 0; i < normalizedRepos.length; i += 1) {
    if (resolved.has(i)) continue
    const perOrigin = parsedOrigins
      .map(info => ({ origin: info.origin, ...scoreRepoVsOrigin(normalizedRepos[i]!, info) }))
      .filter(e => e.score >= 60)
      .sort((a, b) => b.score - a.score || a.origin.localeCompare(b.origin))
    if (perOrigin.length > 0 && (perOrigin.length === 1 || perOrigin[0]!.score > perOrigin[1]!.score)) {
      strongEdges.push({ repoIdx: i, ...perOrigin[0]! })
    }
  }
  strongEdges.sort((a, b) => b.score - a.score || a.repoIdx - b.repoIdx)
  for (const edge of strongEdges) {
    if (resolved.has(edge.repoIdx)) continue
    const { descriptor, root } = normalizedRepos[edge.repoIdx]!
    resolved.set(edge.repoIdx, {
      repo: descriptor.repo,
      root,
      origin: edge.origin,
      confidence: edge.confidence,
      score: edge.score,
      evidence: [edge.reason],
    })
    claimedOrigins.add(edge.origin)
  }

  // Phase 3b: commit unique partial stem matches (score >= 30) against UNCLAIMED origins only
  // (e.g., after `image-uploader` claims `upload-image`, `chat-uploader` uniquely binds to `upload-logs`).
  const unclaimedOrigins = parsedOrigins.filter(info => !claimedOrigins.has(info.origin))
  if (unclaimedOrigins.length > 0) {
    const partialCandidates: Array<{ repoIdx: number; origin: string; score: number; reason: string }> = []
    for (let i = 0; i < normalizedRepos.length; i += 1) {
      if (resolved.has(i)) continue
      const perOrigin = unclaimedOrigins
        .map(info => ({ origin: info.origin, ...scoreRepoVsOrigin(normalizedRepos[i]!, info) }))
        .filter(e => e.score >= 30)
        .sort((a, b) => b.score - a.score || a.origin.localeCompare(b.origin))
      if (perOrigin.length > 0 && (perOrigin.length === 1 || perOrigin[0]!.score > perOrigin[1]!.score)) {
        partialCandidates.push({ repoIdx: i, origin: perOrigin[0]!.origin, score: perOrigin[0]!.score, reason: perOrigin[0]!.reason })
      }
    }
    partialCandidates.sort((a, b) => b.score - a.score || a.repoIdx - b.repoIdx)
    for (const edge of partialCandidates) {
      if (resolved.has(edge.repoIdx) || claimedOrigins.has(edge.origin)) continue
      const { descriptor, root } = normalizedRepos[edge.repoIdx]!
      resolved.set(edge.repoIdx, {
        repo: descriptor.repo,
        root,
        origin: edge.origin,
        confidence: 'hostname_affinity',
        score: edge.score,
        evidence: [edge.reason],
      })
      claimedOrigins.add(edge.origin)
    }
  }

  // --- Pass 4: Single-origin bind vs explicit `unmapped` on multi-origin runs ---
  const output: RepoOriginAffinityMapping[] = []
  for (let i = 0; i < normalizedRepos.length; i += 1) {
    const existing = resolved.get(i)
    if (existing) {
      output.push(existing)
      continue
    }
    const { descriptor, root } = normalizedRepos[i]!
    if (parsedOrigins.length === 1) {
      const soleOrigin = parsedOrigins[0]!.origin
      output.push({
        repo: descriptor.repo,
        root,
        origin: soleOrigin,
        confidence: 'single_origin',
        score: 10,
        evidence: [`single approved origin; bound mounted repo "${descriptor.repo}" to ${soleOrigin}`],
      })
    } else {
      output.push({
        repo: descriptor.repo,
        root,
        confidence: 'unmapped',
        score: 0,
        evidence: [
          parsedOrigins.length > 1
            ? `no compose/ingress/config, live-route, or hostname affinity match across ${parsedOrigins.length} approved origins; marked unmapped instead of falling back to approvedOrigins[0]`
            : 'no approved origins configured',
        ],
      })
    }
  }
  return output
}

/** Convert `RepoOriginAffinityMapping[]` into `ServiceOriginMapping[]` for `synthesizeInvariants`. */
export function repoOriginMappingsToServiceOrigins(
  mappings: readonly RepoOriginAffinityMapping[],
): ServiceOriginMapping[] {
  return mappings.map(m => {
    const confidence: ServiceOriginMapping['confidence'] =
      m.confidence === 'unmapped' || !m.origin
        ? 'unmapped'
        : m.confidence === 'exact' || m.confidence === 'config' || m.confidence === 'single_origin'
          ? 'exact'
          : m.confidence === 'path'
            ? 'path'
            : m.confidence === 'port'
              ? 'port'
              : 'host'
    return {
      service: repoBasenameSlug(m.repo),
      ...(m.root ? { root: m.root } : {}),
      ...(m.origin ? { origin: m.origin } : {}),
      ...(m.pathPrefix ? { pathPrefix: m.pathPrefix } : {}),
      confidence,
      evidence: m.evidence,
    }
  })
}

const HOST_HINT_CONFIG_FILES = new Set([
  'wrangler.toml',
  'vercel.json',
  'fly.toml',
  'cname',
  '.env.example',
  '.env.production',
])

async function collectBoundedRepoSourceFiles(
  reposDir: string,
  mountedRepos: readonly string[],
  maxFiles = 160, signal?: AbortSignal,
): Promise<{ files: SourceFileInput[]; compose?: string; ingress?: string; repoDescriptors: RepoAffinityDescriptor[] }> {
  const files: SourceFileInput[] = []
  let compose: string | undefined
  let ingress: string | undefined
  const repoDescriptors: RepoAffinityDescriptor[] = []
  let opsSinceYield = 0
  const maybeYield = async () => {
    if (++opsSinceYield >= INVARIANT_WALK_YIELD_EVERY) { opsSinceYield = 0; await yieldEventLoopTurn() }
  }
  for (let repoIdx = 0; repoIdx < mountedRepos.length; repoIdx += 1) {
    const mountedRepo = mountedRepos[repoIdx]!
    if (signal?.aborted) break
    const remainingFiles = Math.max(0, maxFiles - files.length)
    const remainingRepos = Math.max(1, mountedRepos.length - repoIdx)
    const perRepoCap = mountedRepos.length > 1
      ? Math.min(remainingFiles, Math.max(16, Math.ceil(remainingFiles / remainingRepos)))
      : remainingFiles
    const repoRel = mountedRepo.replace(/^\/repos\//, '').replace(/\/+$/, '')
    const repoRoot = repoRel ? join(reposDir, repoRel) : reposDir
    let rootStat
    try { rootStat = await lstat(repoRoot) } catch { continue }
    if (!rootStat.isDirectory()) continue
    let packageName: string | undefined
    let homepage: string | undefined
    const configHosts = new Set<string>()
    const runtimeQueue: Array<{ dir: string; depth: number; dirTier: 0 | 1 | 2 }> = [{ dir: repoRoot, depth: 0, dirTier: 0 }]
    const deprioritizedQueue: Array<{ dir: string; depth: number; dirTier: 0 | 1 | 2 }> = []
    const candidates: Array<{ full: string; relPath: string; depth: number }> = []
    const maxDirs = Math.max(256, Math.max(perRepoCap, 16) * 8)
    let dirsVisited = 0
    while ((runtimeQueue.length > 0 || deprioritizedQueue.length > 0) && dirsVisited < maxDirs && !signal?.aborted) {
      const { dir, depth, dirTier } = runtimeQueue.length > 0 ? runtimeQueue.shift()! : deprioritizedQueue.shift()!
      dirsVisited += 1
      let entries: string[]
      try { entries = await readdir(dir) } catch { continue }
      entries.sort()
      for (const entry of entries) {
        if (signal?.aborted) break
        if (INVARIANT_SKIP_DIRS.has(entry)) continue
        const full = join(dir, entry)
        let st
        try { st = await lstat(full) } catch { continue }
        await maybeYield()
        if (signal?.aborted) break
        if (st.isSymbolicLink()) continue
        if (st.isDirectory()) {
          const nextTier = classifyRepoDirTier(entry, dirTier)
          ;(nextTier === 2 ? deprioritizedQueue : runtimeQueue).push({ dir: full, depth: depth + 1, dirTier: nextTier })
          continue
        }
        if (!st.isFile() || st.size > 128 * 1024) continue
        const lower = entry.toLowerCase()
        if (lower === 'docker-compose.yml' || lower === 'docker-compose.yaml' || lower === 'compose.yml' || lower === 'compose.yaml') {
          try {
            const text = await readFile(full, 'utf8')
            compose = compose ? `${compose}\n${text}` : text
            for (const h of extractHostsFromConfigText(text)) configHosts.add(h)
          } catch { continue }
          continue
        }
        if (lower === 'ingress.yml' || lower === 'ingress.yaml') {
          try {
            const text = await readFile(full, 'utf8')
            ingress = ingress ? `${ingress}\n${text}` : text
            for (const h of extractHostsFromConfigText(text)) configHosts.add(h)
          } catch { continue }
          continue
        }
        if (lower === 'package.json' && dir === repoRoot && st.size <= 32 * 1024) {
          try {
            const raw = await readFile(full, 'utf8')
            const pkg = JSON.parse(raw) as { name?: unknown; homepage?: unknown }
            if (typeof pkg.name === 'string' && pkg.name.trim()) packageName = pkg.name.trim()
            if (typeof pkg.homepage === 'string' && pkg.homepage.trim()) homepage = pkg.homepage.trim()
            for (const h of extractHostsFromConfigText(raw)) configHosts.add(h)
          } catch { continue }
          continue
        }
        if (HOST_HINT_CONFIG_FILES.has(lower) && st.size <= 32 * 1024) {
          try {
            const raw = await readFile(full, 'utf8')
            if (lower === 'cname') {
              const cnameHost = extractHostCandidate(raw.split(/\r?\n/, 1)[0] ?? '')
              if (cnameHost) configHosts.add(cnameHost)
            } else { for (const h of extractHostsFromConfigText(raw)) configHosts.add(h) }
          } catch { continue }
          continue
        }
        if (!INVARIANT_SCAN_EXT.has(extname(lower))) continue
        candidates.push({ full, relPath: relative(repoRoot, full).split(sep).join('/'), depth })
      }
    }
    for (const cand of selectBalancedRepoSourceCandidates(candidates, perRepoCap)) {
      if (signal?.aborted || files.length >= maxFiles) break
      await maybeYield()
      try { files.push({ path: repoRel ? `${repoRel}/${cand.relPath}` : cand.relPath, content: await readFile(cand.full, 'utf8') }) } catch { continue }
    }
    repoDescriptors.push({
      repo: mountedRepo,
      root: repoRel || mountedRepo,
      ...(packageName ? { packageName } : {}),
      ...(homepage ? { homepage } : {}),
      ...(configHosts.size ? { configHosts: [...configHosts] } : {}),
    })
  }
  return {
    files,
    ...(compose ? { compose } : {}),
    ...(ingress ? { ingress } : {}),
    repoDescriptors,
  }
}

function hopKindToCapabilityKind(kind: ChainHop['artifactKind']): CapabilityKind {
  switch (kind) {
    case 'token_ref': return 'scoped_token'
    case 'leaked_id': return 'opaque_object_ref'
    case 'ssrf_redirect_target': return 'internal_reach_handle'
    case 'role_transition': return 'identity_session'
    case 'workflow_state_handle': return 'state_handle'
    case 'stored_write_handle': return 'write_sink_handle'
  }
}

export const CHECKPOINT_CAP_SKILL_PREFIX = 'checkpoint_cap:'
export const MAX_WORKSPACE_DIGEST_BYTES = 8 * 1024
export const HOP_CONTINUATION_DIRECTIVE =
  'Continue from the verified hop checkpoint — do not repeat verified discovery hops; advance the next boundary with sealed handles and confirm via ctx.prove_composite.'

export function extractCheckpointCapIdFromStep(step: { skills?: readonly string[] }): string | null {
  for (const skill of step.skills ?? []) {
    if (skill.startsWith(CHECKPOINT_CAP_SKILL_PREFIX)) {
      const capId = skill.slice(CHECKPOINT_CAP_SKILL_PREFIX.length).trim()
      if (capId) return capId
    }
  }
  return null
}

function serviceGroupForPath(relPath: string, mountedRepos: readonly string[]): string {
  const parts = relPath.split('/').filter(Boolean)
  if (parts.length <= 1) return '(root)'
  // Strip mounted repo prefix (`owner/repo` or `repo`) when present so service subdirectories group cleanly.
  let offset = 0
  for (const repo of mountedRepos) {
    const clean = repo.replace(/^\/+|\/+$/g, '')
    if (clean && (relPath === clean || relPath.startsWith(`${clean}/`))) {
      offset = clean.split('/').filter(Boolean).length
      break
    }
  }
  const rest = parts.slice(offset)
  if (rest.length <= 1) return offset > 0 ? parts.slice(0, offset).join('/') : '(root)'
  const first = rest[0]!
  if ((first === 'services' || first === 'apps' || first === 'packages' || first === 'workers') && rest.length >= 3) {
    return `${first}/${rest[1]}`
  }
  return first
}

const HIGH_SIGNAL_FILE_RE = /(?:route|router|controller|handler|endpoint|api|auth|guard|middleware|rbac|policy|tenant|webhook|sign|jwt|oauth|oidc|worker|queue|job|consumer|graphql|resolver|sse|stream|socket|proxy|gateway|edge|export|upload|storage|cache)/i
const GRAPHQL_OP_RE = /\b(?:type\s+(?:Query|Mutation|Subscription)|(?:Query|Mutation|Subscription)\s*[:=]\s*\{)\b/
const WEBHOOK_OR_WORKER_RE = /\b(?:webhook|hmac|verifySignature|x-signature|x-hub-signature|queue\.process|worker\.on|subscribe\(|EventSource|text\/event-stream|WebSocketServer|on\(['"](?:message|job|task)['"])/i

/**
 * Build a compact `<= 8 KB` Pre-Indexed Multi-Service Route, Authz Guard & Sink Digest directly
 * from an in-memory `StaticWorkspaceSnapshot` (zero extra filesystem walks). Injected into
 * `Source-First Code Audit` on Turn 1 so the auditor immediately sees services, routes, guards,
 * GraphQL/webhook/worker handlers, and sinks with exact `file:line` references.
 */
export function buildWorkspaceSourceDigest(
  snapshot: StaticWorkspaceSnapshot,
  maxBytes = MAX_WORKSPACE_DIGEST_BYTES,
): string {
  const cap = Math.max(512, Math.min(MAX_WORKSPACE_DIGEST_BYTES, Math.floor(maxBytes)))
  const pg = snapshot.programGraph
  const lines: string[] = []
  const frameworks = pg.frameworks.length ? pg.frameworks.join(', ') : 'unknown'
  const reposLabel = snapshot.mountedRepos.length ? snapshot.mountedRepos.join(', ') : '(workspace-root)'
  const sinkNodes = pg.nodes.filter(n => n.kind === 'sink')
  const middlewareNodes = pg.nodes.filter(n => n.kind === 'middleware')

  lines.push('# Pre-Indexed Multi-Service Route, Authz Guard & Sink Digest')
  lines.push(
    `Summary: files=${snapshot.walkStats.filesScanned}, repos=[${reposLabel}], frameworks=[${frameworks}], routes=${pg.routes.length}, sinks=${sinkNodes.length}, middleware=${middlewareNodes.length}`
    + `${snapshot.compose ? ', compose=yes' : ''}${snapshot.ingress ? ', ingress=yes' : ''}`,
  )

  // 1. Group files by service / top-level directory (prioritizing high-signal files).
  const byService = new Map<string, string[]>()
  for (const relPath of snapshot.files) {
    const svc = serviceGroupForPath(relPath, snapshot.mountedRepos)
    const bucket = byService.get(svc) ?? []
    bucket.push(relPath)
    byService.set(svc, bucket)
  }
  if (byService.size > 0) {
    lines.push('## Services & Key Files')
    const sortedServices = [...byService.entries()].sort((a, b) => a[0].localeCompare(b[0]))
    for (const [svc, svcFiles] of sortedServices.slice(0, 24)) {
      const prioritized = [...svcFiles].sort((a, b) =>
        Number(HIGH_SIGNAL_FILE_RE.test(b)) - Number(HIGH_SIGNAL_FILE_RE.test(a))
        || a.localeCompare(b),
      )
      const shown = prioritized.slice(0, 8).join(', ')
      const extra = prioritized.length > 8 ? ` (+${prioritized.length - 8} more)` : ''
      lines.push(`- ${svc} (${svcFiles.length} files): ${shown}${extra}`)
    }
  }

  // 2. Discovered HTTP routes with authz guards & parameters (unguarded first so asymmetries jump out).
  if (pg.routes.length > 0) {
    lines.push('## Discovered HTTP Routes (method path @ file:line [guards])')
    const unguardedFirst = [...pg.routes].sort((a, b) =>
      Number(b.guards.length === 0) - Number(a.guards.length === 0)
      || a.file.localeCompare(b.file)
      || a.line - b.line,
    )
    for (const r of unguardedFirst.slice(0, 60)) {
      const guardLabel = r.guards.length ? `guards=[${r.guards.slice(0, 4).join(',')}]` : 'guards=[NONE]'
      const params = [...r.input.params, ...r.input.query, ...r.input.body].slice(0, 6)
      const paramLabel = params.length ? ` params=[${params.join(',')}]` : ''
      const handlerLabel = r.handler ? ` (${r.handler})` : ''
      lines.push(`- ${r.method.toUpperCase()} ${r.path} @ ${r.file}:${r.line}${handlerLabel} ${guardLabel}${paramLabel}`)
    }
    if (unguardedFirst.length > 60) {
      lines.push(`- ... +${unguardedFirst.length - 60} additional routes`)
    }
  }

  // 3. GraphQL / Webhook / Async-Worker / SSE / WS entrypoints from cached snapshot sources.
  const secondaryHandlers: string[] = []
  const routeFilesSeen = new Set(pg.routes.map(r => `${r.file}:${r.line}`))
  for (const [relPath, content] of snapshot.sourceByPath.entries()) {
    if (secondaryHandlers.length >= 30) break
    const isGqlFile = /\.(?:graphql|gql)$/i.test(relPath)
    if (!isGqlFile && !GRAPHQL_OP_RE.test(content) && !WEBHOOK_OR_WORKER_RE.test(content)) continue
    const fileLines = content.split(/\r?\n/)
    for (let idx = 0; idx < fileLines.length && secondaryHandlers.length < 30; idx += 1) {
      const lineText = fileLines[idx] ?? ''
      if (
        (isGqlFile && /^\s*(?:type\s+(?:Query|Mutation|Subscription)|[a-zA-Z_][A-Za-z0-9_]*\s*\()/.test(lineText))
        || GRAPHQL_OP_RE.test(lineText)
        || WEBHOOK_OR_WORKER_RE.test(lineText)
      ) {
        const loc = `${relPath}:${idx + 1}`
        if (routeFilesSeen.has(loc)) continue
        routeFilesSeen.add(loc)
        const kindTag = isGqlFile || GRAPHQL_OP_RE.test(lineText) ? 'graphql' : 'webhook/worker'
        secondaryHandlers.push(`- [${kindTag}] ${loc}: ${lineText.trim().slice(0, 96)}`)
      }
    }
  }
  if (secondaryHandlers.length > 0) {
    lines.push('## GraphQL / Webhook / Async Worker Handlers')
    lines.push(...secondaryHandlers)
  }

  // 4. Middleware & Authz Guards.
  if (pg.globalMiddleware.length > 0 || middlewareNodes.length > 0) {
    lines.push('## Middleware & Authz Guards')
    if (pg.globalMiddleware.length > 0) {
      lines.push(`- global: ${pg.globalMiddleware.slice(0, 16).join(', ')}`)
    }
    for (const mw of middlewareNodes.slice(0, 24)) {
      lines.push(`- ${mw.symbol} @ ${mw.file}:${mw.line}${mw.guards.length ? ` [${mw.guards.join(',')}]` : ''}`)
    }
  }

  // 5. Key Sinks & Static Leads (file:line).
  if (sinkNodes.length > 0 || (pg.staticLeads?.length ?? 0) > 0) {
    lines.push('## Key Sinks & Handlers (file:line)')
    const sortedSinks = [...sinkNodes].sort((a, b) =>
      Number(b.guards.length === 0) - Number(a.guards.length === 0)
      || a.file.localeCompare(b.file)
      || a.line - b.line,
    )
    for (const sink of sortedSinks.slice(0, 40)) {
      const guards = sink.guards.length ? ` guards=[${sink.guards.slice(0, 3).join(',')}]` : ' guards=[NONE]'
      lines.push(`- [${sink.sinkKind ?? 'sink'}] ${sink.symbol} @ ${sink.file}:${sink.line}${guards}`)
    }
    for (const lead of (pg.staticLeads ?? []).slice(0, 12)) {
      lines.push(`- [static:${lead.kind}] ${lead.note} @ ${lead.file}:${lead.line}`)
    }
  }

  // Strictly enforce `<= maxBytes` UTF-8 at clean line boundaries.
  const footer = '\n[digest truncated to byte cap]'
  const footerBytes = Buffer.byteLength(footer, 'utf8')
  const outLines: string[] = []
  let usedBytes = 0
  let truncated = false
  for (const line of lines) {
    const prefix = outLines.length > 0 ? '\n' : ''
    const chunk = `${prefix}${line}`
    const chunkBytes = Buffer.byteLength(chunk, 'utf8')
    if (usedBytes + chunkBytes + footerBytes > cap) {
      if (usedBytes + chunkBytes <= cap && line === lines[lines.length - 1]) {
        outLines.push(line)
        usedBytes += chunkBytes
      } else {
        truncated = true
      }
      break
    }
    outLines.push(line)
    usedBytes += chunkBytes
  }
  const joined = truncated ? `${outLines.join('\n')}${footer}` : outLines.join('\n')
  if (Buffer.byteLength(joined, 'utf8') <= cap) return joined
  let trimmed = joined
  while (trimmed.length > 0 && Buffer.byteLength(trimmed, 'utf8') > cap) {
    trimmed = trimmed.slice(0, -1)
  }
  return trimmed
}

export interface HopContinuationExchangeRef {
  id: string
  origin: string
  method: string
  pathAndQuery: string
  status: number
  personaHandle?: string | null
}

/** Sort personas lowest-privilege-first via `classifyPersonaPrivilege`, preserving configured order (`configIndex` ASC). */
export function sortPersonasLowPrivFirst<T extends { handle: string; roleLabel?: string; configIndex?: number }>(personas: readonly T[]): T[] {
  return personas
    .map((persona, idx) => ({
      persona,
      rank: classifyPersonaPrivilege(persona.handle, persona.roleLabel).rank,
      configIndex: typeof persona.configIndex === 'number' && Number.isFinite(persona.configIndex) ? persona.configIndex : idx,
    }))
    .sort((a, b) => (a.rank - b.rank) || (a.configIndex - b.configIndex))
    .map(entry => entry.persona)
}

const PERSISTENT_WORKFLOW_STEP_RE = /\b(?:workflow|business[_ -]?logic|state[_ -]?machine|lifecycle|authz|bola|bfla|idor|abac|broken[_ -]?access[_ -]?control|access[_ -]?control)\b/i

export function isPersistentWorkflowContinuationStep(
  step: Pick<ChainStep, 'title' | 'hypothesis' | 'category' | 'skills'> & { lane?: string | null },
): boolean {
  if (step.lane === 'workflow' || step.lane === 'business_logic') return true
  return PERSISTENT_WORKFLOW_STEP_RE.test(`${step.title} ${step.hypothesis} ${step.category} ${step.skills.join(' ')}`)
}

export interface EnqueueHopContinuationInput {
  run: Run
  step: ChainStep
  assignment: Assignment
  targetOrigins: readonly string[]
  confirmed: boolean
  partialSummary: string
  recordedFacts: readonly Fact[]
  recordedExchanges: readonly HopContinuationExchangeRef[]
  sealedCapHandles: readonly string[]
  maxContinuations?: number
  trigger?: 'wall_clock_rotated' | 'sealed_handle_exit'
  allowNonChainWithSealedCap?: boolean
}

export interface EnqueueHopContinuationResult {
  enqueued: boolean
  reason?: 'not_multi_hop_chain' | 'already_confirmed' | 'max_continuations_reached' | 'no_concrete_progress' | 'already_enqueued' | 'duplicate_sealed_handles' | 'dispatch_filtered'
  continuationStep?: ChainStep
  continuationDepth?: number
  checkpointCapId?: string
  checkpointBytes?: number
}

function parseHopCheckpointJson(raw: unknown): HopCheckpointBrief | null {
  if (!raw) return null
  let obj: unknown = raw
  if (typeof raw === 'string') {
    const trimmed = raw.trim()
    if (!trimmed.startsWith('{')) return null
    try { obj = JSON.parse(trimmed) } catch { return null }
  }
  if (!obj || typeof obj !== 'object' || Array.isArray(obj)) return null
  const rec = obj as Record<string, unknown>
  if (rec.schema !== 'v8.hop_checkpoint.v1' || typeof rec.branchKey !== 'string' || !rec.nextGoal || typeof rec.nextGoal !== 'object') {
    return null
  }
  return rec as unknown as HopCheckpointBrief
}

export class ExecReconPlanner extends ExecServiceModule<ExecReconPlannerHost> {
  private readonly ownRunState?: RunOrchestrationStateStore
  private get runState(): RunOrchestrationStateStore {
    return this.host.runState ?? (this.ownRunState ?? new RunOrchestrationStateStore())
  }
  private readonly persistedStepCheckpoints = new Map<string, { checkpointCapId?: string; checkpointJson?: string }>()
  private readonly structuredStepTargets = new Map<string, StructuredStepTarget[]>()
  private readonly invariantsSeedingInFlight = new Map<string, Promise<void>>()
  private get plannerEmptyRounds() { return this.runState.mapView('plannerEmptyRounds') }
  private get plannerDryRounds() { return this.runState.mapView('plannerDryRounds') }
  private get plannerCompletedAtLastRound() { return this.runState.mapView('plannerCompletedAtLastRound') }
  private get plannerEvidenceFrontier() { return this.runState.mapView('plannerEvidenceFrontier') }
  private get frontierControllers() { return this.runState.mapView('frontierController') }
  private get invariantsSeededRuns() { return this.runState.setView('invariantsSeeded') }
  private get wave1InvariantChainsPromoted() { return this.runState.setView('wave1InvariantChainsPromoted') }
  private get seededHypothesisIdsByRun() { return this.runState.mapView('seededHypothesisIds') }
  private get runtimeSynthesisWatermark() { return this.runState.mapView('runtimeSynthesisWatermark') }
  private get postFloorInvariantsSyncedRuns() { return this.runState.setView('postFloorInvariantsSynced') }
  private get runtimeCompositeSeededRuns() { return this.runState.setView('runtimeCompositeSeeded') }
  private get emittedSealedHandleSets() { return this.runState.prefixedMapView<Set<string>, 'emittedSealedHandleSets'>('emittedSealedHandleSets', ':') }
  private get plannerSeenCausalEdges() { return this.runState.mapView('plannerSeenCausalEdges') }
  private get quarantinedOriginsByRun() { return this.runState.mapView('quarantinedOrigins') }
  private get repoOriginMappingsByRun() { return this.runState.mapView('repoOriginMappings') }
  private get detLeadStepKeys() { return this.runState.prefixedSetView('detLeadStepKeys', '\0') }
  private get detLeadGateRejected() { return this.runState.prefixedSetView('detLeadGateRejected', '\0') }
  private get cappedLeadReported() { return this.runState.prefixedSetView('cappedLeadReported', '\0') }
  private get tierAStepKeys() { return this.runState.prefixedSetView('tierAStepKeys', '\0') }
  private get stepIdsByRun() { return this.runState.mapView('stepIds') }
  private get runLifecycleUnsubs() { return this.runState.mapView('runLifecycleUnsub') }
  private get labRunner() { return this.host.labRunner }
  private readonly emittedPreconditionUnmetByRun = new Map<string, Set<string>>()

  private emitPreconditionUnmet(
    runId: string,
    input: {
      dedupeKey: string
      origin: string
      precondition: 'tier' | 'persona_count' | 'browser' | 'canary'
      vulnClass: string
      required: string
      observed: string
      method?: string
      route?: string
      skippedCount?: number
      source: string
    },
  ): void {
    let seen = this.emittedPreconditionUnmetByRun.get(runId)
    if (!seen) {
      seen = new Set<string>()
      this.emittedPreconditionUnmetByRun.set(runId, seen)
    }
    if (seen.has(input.dedupeKey)) return
    seen.add(input.dedupeKey)
    const method = (input.method ?? 'ANY').toUpperCase()
    const route = input.route?.trim() || '*'
    const skippedCount = Math.max(1, Math.floor(input.skippedCount ?? 1))
    try {
      this.storage.event(
        runId,
        'coverage.precondition_unmet',
        `Precondition unmet (${input.precondition}: need ${input.required}, got ${input.observed}) skipped ${input.vulnClass} on ${method} ${route}.`,
        {
          origin: input.origin,
          precondition: input.precondition,
          vulnClass: input.vulnClass,
          class: input.vulnClass,
          method,
          route,
          required: input.required,
          observed: input.observed,
          skippedCount,
          source: input.source,
        },
      )
    } catch { /* observational telemetry is best-effort */ }
  }

  constructor(host: ExecReconPlannerHost) {
    super(host)
    if (!host.runState) this.ownRunState = new RunOrchestrationStateStore()
  }

  /**
   * Single-call eviction of all per-run planner state for `runId` (reclaims step checkpoints
   * and unsubscribes lifecycle hooks atomically via `RunOrchestrationStateStore`).
   */
  clearRunState(runId: string): void {
    const state = this.runState.get(runId)
    if (state?.stepIds) {
      for (const stepId of state.stepIds) {
        this.persistedStepCheckpoints.delete(stepId)
        this.structuredStepTargets.delete(stepId)
      }
    }
    defaultRetryGovernor.clearRun(runId)
    this.invariantsSeedingInFlight.delete(runId)
    this.emittedPreconditionUnmetByRun.delete(runId)
    if (this.ownRunState) {
      this.ownRunState.disposeRun(runId)
    } else if (state) {
      // Clear planner-owned fields while letting Execution's disposeRun own full record deletion.
      if (state.runLifecycleUnsub) {
        try { state.runLifecycleUnsub() } catch { /* ignore */ }
        state.runLifecycleUnsub = undefined
      }
      state.plannerEmptyRounds = undefined
      state.plannerDryRounds = undefined
      state.plannerCompletedAtLastRound = undefined
      state.plannerEvidenceFrontier = undefined
      state.frontierController = undefined
      state.frontierDispatcher?.clearStepMeta()
      state.frontierDispatcher = undefined
      state.invariantsSeeded = false
      state.wave1InvariantChainsPromoted = false
      state.seededHypothesisIds = undefined
      state.runtimeSynthesisWatermark = undefined
      state.postFloorInvariantsSynced = false
      state.runtimeCompositeSeeded = false
      state.plannerSeenCausalEdges = undefined
      state.quarantinedOrigins = undefined
      state.repoOriginMappings = undefined
      state.stepIds = undefined
      state.emittedSealedHandleSets.clear()
      state.detLeadStepKeys.clear()
      state.detLeadGateRejected.clear()
      state.cappedLeadReported.clear()
      state.tierAStepKeys.clear()
    }
  }

  private trackRunLifecycle(runId: string): void {
    if (this.runLifecycleUnsubs.has(runId)) return
    const onRunEventFn = (this.storage as unknown as {
      onRunEvent?: (runId: string, fn: (event: { kind?: string; detail?: Record<string, unknown> }) => void) => () => void
    }).onRunEvent
    if (typeof onRunEventFn !== 'function') return
    const unsub = onRunEventFn.call(this.storage, runId, event => {
      const kind = typeof event?.kind === 'string' ? event.kind : ''
      if (kind !== 'report.complete' && kind !== 'report.partial' && !kind.startsWith('run.')) return
      try {
        const current = this.storage.run(runId)
        if (current.status === 'complete' || current.status === 'failed' || current.status === 'stopped') {
          this.clearRunState(runId)
        }
      } catch {
        this.clearRunState(runId)
      }
    })
    this.runLifecycleUnsubs.set(runId, unsub)
  }

  /** Emit structured warning telemetry for non-fatal planner lifecycle failures (never silent catch). */
  private noteLifecycleWarning(
    runId: string,
    hook: string,
    error: unknown,
    extra: Record<string, unknown> = {},
  ): void {
    const reason = (error instanceof Error ? error.message : String(error)).slice(0, 240)
    try {
      this.storage.event(
        runId,
        'planner.lifecycle_warning',
        `Planner lifecycle hook "${hook}" failed: ${reason}`,
        { hook, error: reason, ...extra },
      )
    } catch { /* run may already be deleted */ }
  }

  /**
   * Bind structured `(origin, METHOD, route, class)` target(s) to a chain step at creation time
   * so coverage, confirmed-exclusion, and bounded-retry accounting never depend on prose parsing.
   */
  registerStepTargets(
    runId: string,
    stepId: string,
    targets: readonly StructuredStepTarget[],
  ): void {
    const deduped: StructuredStepTarget[] = []
    const seen = new Set<string>()
    for (const raw of targets) {
      const origin = (raw.origin ?? '').trim()
      const method = (raw.method ?? 'ANY').trim().toUpperCase() || 'ANY'
      const rawRoute = (raw.route ?? '').trim().replace(/^[A-Za-z]+\s+/, '')
      const route = normalizeConfirmedRouteTemplate(rawRoute)
      const vulnClass = (raw.vulnClass ?? '').trim() || 'unknown'
      if (!origin || !route) continue
      const target: StructuredStepTarget = { origin, method, route, vulnClass }
      const key = structuredCoverageKey(target)
      if (seen.has(key)) continue
      seen.add(key)
      deduped.push(target)
    }
    if (!deduped.length) return
    this.trackRunLifecycle(runId)
    this.structuredStepTargets.set(stepId, deduped)
    const stepIds = this.stepIdsByRun.get(runId) ?? new Set<string>()
    stepIds.add(stepId)
    this.stepIdsByRun.set(runId, stepIds)
  }

  /**
   * Read structured `(origin, METHOD, route, class)` bindings for a step: prefers bindings stamped
   * at step creation, falling back ONLY to structured parent fact metadata (`det_lead`,
   * `hop_checkpoint`, `chain_hop`) — never prose-parsing title/hypothesis text.
   */
  getStructuredStepTargets(
    step: Pick<ChainStep, 'id' | 'runId' | 'category' | 'sourceOrigins' | 'dependsOnFactIds'>,
  ): StructuredStepTarget[] {
    const registered = this.structuredStepTargets.get(step.id)
    if (registered && registered.length > 0) return registered
    if (!step.dependsOnFactIds?.length) return []
    const needed = new Set(step.dependsOnFactIds)
    const facts = this.pageAll((offset, limit) =>
      this.storage.listFacts(step.runId, { includeTainted: false, limit, offset }))
      .filter(f => needed.has(f.id))
    const derived: StructuredStepTarget[] = []
    const seen = new Set<string>()
    for (const fact of facts) {
      const data = fact.data
      const origin = (fact.origin || step.sourceOrigins[0] || '').trim()
      if (!origin) continue
      const endpoint = typeof data?.endpoint === 'string'
        ? data.endpoint
        : typeof data?.surfacedEndpoint === 'string'
          ? data.surfacedEndpoint
          : typeof (data?.checkpointBrief as { nextGoal?: { endpoint?: unknown } } | undefined)?.nextGoal?.endpoint === 'string'
            ? String((data?.checkpointBrief as { nextGoal?: { endpoint?: unknown } }).nextGoal!.endpoint)
            : ''
      if (!endpoint || !endpoint.startsWith('/')) continue
      const method = typeof data?.method === 'string'
        ? data.method.toUpperCase()
        : typeof (data?.checkpointBrief as { nextGoal?: { method?: unknown } } | undefined)?.nextGoal?.method === 'string'
          ? String((data?.checkpointBrief as { nextGoal?: { method?: unknown } }).nextGoal!.method).toUpperCase()
          : 'ANY'
      const vulnClass = typeof data?.probeClass === 'string' && data.probeClass.trim()
        ? data.probeClass.trim()
        : (step.category || 'unknown')
      const target: StructuredStepTarget = {
        origin,
        method,
        route: normalizeConfirmedRouteTemplate(endpoint),
        vulnClass,
      }
      const key = structuredCoverageKey(target)
      if (!seen.has(key)) {
        seen.add(key)
        derived.push(target)
      }
    }
    return derived
  }

  /** Resolve the effective finite run wall-clock duration budget (ms) for `run`. */
  getRunMaxDurationMs(run?: { maxDurationMs?: number }): number {
    const runMax = Number(run?.maxDurationMs)
    return Number.isFinite(runMax) && runMax > 0 ? runMax : this.host.maxDurationMs
  }

  /**
   * Strictly bounded single-retry requeue (max 1 retry per `reinvestigationKey`) for retryable
   * terminal step statuses (`turn_capped`, `nudged_out`), evaluated through the single
   * `RetryGovernor` against `dynamicStepBudget`, wall-clock, USD/request budget, and `RunSafetyBudgets`.
   */
  maybeRequeueRetryableStep(input: {
    run: Run
    step: ChainStep
    assignment: Pick<Assignment, 'id'>
    terminalStatus: ChainStepRetryableStatus
    targetOrigins: readonly string[]
  }): { requeued: boolean; reason: string; retryStep?: ChainStep; retryKey?: string; repointedDependentIds?: string[] } {
    const { run, step, assignment, terminalStatus } = input
    if (!isRetryableChainStepStatus(terminalStatus)) return { requeued: false, reason: 'not_retryable_status' }
    if ((step.trialIndex ?? 0) > 0 || step.skills.includes('cq5:retry:1')) return { requeued: false, reason: 'already_retry_step' }
    const structuredTargets = this.getStructuredStepTargets(step)
    const primaryTarget = structuredTargets[0]
    const primaryOrigin = primaryTarget?.origin ?? input.targetOrigins[0] ?? step.sourceOrigins[0] ?? ''
    const primaryRoute = primaryTarget?.route ?? '/'
    const primaryMethod = primaryTarget?.method ?? 'ANY'
    const primaryClass = primaryTarget?.vulnClass ?? step.category ?? 'unknown'
    const retryKey = reinvestigationKey(`${primaryMethod} ${primaryRoute}`, primaryClass)
    const existingSteps = this.storage.listChainSteps(run.id, run.goalRevision)
    const alreadyRetriedPersisted = existingSteps.some(s =>
      s.skills.includes('cq5:retry:1')
      && (s.dependsOnStepIds.includes(step.id)
        || this.getStructuredStepTargets(s).some(t => reinvestigationKey(`${t.method} ${t.route}`, t.vulnClass) === retryKey)),
    )
    const currentRun = this.storage.run(run.id)
    const dynamicBudget = Math.min(hardChainStepsCeiling, currentRun.dynamicStepBudget ?? computeDynamicStepBudget(this.storage, currentRun.id))
    const safetyBudgets = resolveRunSafetyBudgets({ maxAssignments: dynamicBudget })
    const effectiveStepCap = Math.min(dynamicBudget, safetyBudgets.maxCompositeVerifiesPerRun)
    const decision = defaultRetryGovernor.evaluate({
      runId: currentRun.id,
      path: 'step_requeue',
      retryKey,
      stepStatus: terminalStatus,
      stepSkills: step.skills,
      stepTrialIndex: step.trialIndex,
      alreadyRetriedPersisted,
      runStatus: currentRun.status,
      runPhase: currentRun.phase,
      budgetExhausted: this.storage.checkBudgetExceeded(currentRun.id),
      requestBudgetExhausted: currentRun.budgetRequests > 0 && currentRun.budgetRequests - currentRun.spentRequests <= 0,
      runCreatedAt: currentRun.createdAt,
      maxDurationMs: this.getRunMaxDurationMs(currentRun as { maxDurationMs?: number }),
      existingStepCount: existingSteps.length,
      effectiveStepCap,
      maxRetriesPerKey: MAX_RETRYABLE_STEP_RETRIES,
    })
    if (!decision.allowed) {
      if (decision.reason === 'retry_cap_reached') {
        this.storage.event(
          run.id,
          'worker.retryable_step_not_requeued',
          `Retryable step "${step.title}" (${terminalStatus}) not requeued: max 1 retry per key already reached.`,
          { stepId: step.id, assignmentId: assignment.id, terminalStatus, retryKey, reason: 'retry_cap_reached' },
        )
      } else if (decision.reason === 'step_budget_exhausted') {
        this.storage.event(
          run.id,
          'worker.retryable_step_not_requeued',
          `Retryable step "${step.title}" (${terminalStatus}) not requeued: step budget exhausted (${existingSteps.length}/${effectiveStepCap}).`,
          { stepId: step.id, assignmentId: assignment.id, terminalStatus, retryKey, reason: 'step_budget_exhausted', existingSteps: existingSteps.length, effectiveStepCap },
        )
      }
      return { requeued: false, reason: decision.reason, retryKey }
    }

    const approvedOrigins = this.host.approvedOriginsSet(currentRun)
    const validOrigins = [...new Set([...input.targetOrigins, ...step.sourceOrigins])].filter(o => approvedOrigins.has(o))
    const assetIds = currentRun.candidates
      .filter(c => validOrigins.includes(c.origin) && currentRun.approved.includes(c.id))
      .map(c => c.id)
    if (!validOrigins.length || !assetIds.length) {
      return { requeued: false, reason: 'no_approved_asset', retryKey }
    }

    if (isMultiHopChainStep(step)) {
      const controller = this.frontierControllerFor(currentRun.id)
      const admission = controller.admitStepBranch({
        branchKey: `retry:${step.id.slice(0, 12)}`,
        parentBranchKey: `step:${step.id.slice(0, 12)}`,
        depth: Math.max(1, extractContinuationDepth(step) + 1),
        origin: primaryOrigin || validOrigins[0]!,
        endpoint: primaryRoute,
        method: primaryMethod,
        hypothesisClass: primaryClass,
        goalSummary: `Bounded retry (${terminalStatus}) for ${step.title}`,
        waveNo: Math.max(1, currentRun.roundNo || 1),
      })
      if (!admission.admitted) {
        return { requeued: false, reason: 'frontier_pruned', retryKey }
      }
    }

    const retryTitle = `${step.title.replace(/\s*\[retry #1\]\s*$/i, '').slice(0, 175)} [retry #1]`
    const retryHypothesis = `[retry_of=${step.id}] [prior_status=${terminalStatus}] Single bounded retry after ${terminalStatus}: complete verification with kovo_verify or record a coded proofGapReason. ${step.hypothesis}`.slice(0, 1200)
    const retrySkills = [...new Set([...step.skills, 'cq5:retry:1'])]
    const created = this.storage.addChainStep(currentRun, {
      title: retryTitle,
      hypothesis: retryHypothesis,
      category: step.category,
      priority: Math.max(40, Math.min(95, step.priority)),
      targetAssetIds: assetIds,
      skills: retrySkills,
      dependsOnFactIds: step.dependsOnFactIds,
      dependsOnStepIds: [step.id],
      sourceOrigins: validOrigins,
      specialistProfile: step.specialistProfile ?? routeStepToSpecialist({
        title: retryTitle,
        hypothesis: retryHypothesis,
        category: step.category,
        skills: retrySkills,
      }),
    })
    const readyRetry = this.storage.updateChainStep(created.id, { status: 'ready' })
    const repointedDependentIds: string[] = []
    for (const candidate of existingSteps) {
      if (candidate.id === step.id || candidate.id === readyRetry.id) continue
      if (candidate.status !== 'pending' || !candidate.dependsOnStepIds.includes(step.id)) continue
      const nextDeps = [...new Set(candidate.dependsOnStepIds.map(sid => (sid === step.id ? readyRetry.id : sid)))]
      this.storage.updateChainStep(candidate.id, { dependsOnStepIds: nextDeps })
      repointedDependentIds.push(candidate.id)
    }
    const targetsToBind: StructuredStepTarget[] = structuredTargets.length > 0
      ? structuredTargets
      : [{ origin: primaryOrigin || validOrigins[0]!, method: primaryMethod, route: primaryRoute, vulnClass: primaryClass }]
    this.registerStepTargets(currentRun.id, created.id, targetsToBind)
    const recorded = defaultRetryGovernor.recordRetry(currentRun.id, retryKey, 'step_requeue')
    this.storage.event(
      currentRun.id,
      'worker.retryable_step_requeued',
      `Requeued retryable step "${step.title}" (${terminalStatus}) once as step #${readyRetry.seq}.`,
      {
        priorStepId: step.id,
        retryStepId: readyRetry.id,
        assignmentId: assignment.id,
        terminalStatus,
        retryKey,
        retryCount: recorded.keyRetries,
        maxRetries: MAX_RETRYABLE_STEP_RETRIES,
        dynamicBudget,
        effectiveStepCap,
        repointedDependentIds,
      },
    )
    return { requeued: true, reason: 'requeued', retryStep: readyRetry, retryKey, repointedDependentIds }
  }

  /** Return (or initialize) the run-scoped v8 FrontierWaveController bound to Store's CapabilityLedger. */
  frontierControllerFor(runId: string, options: Omit<FrontierWaveControllerOptions, 'ledger'> = {}): FrontierWaveController {
    this.trackRunLifecycle(runId)
    const state = this.runState.ensure(runId)
    if (!state.frontierController) {
      state.frontierController = new FrontierWaveController({
        ...options,
        ledger: this.storage.capabilityLedger(runId),
      })
    } else {
      state.frontierController.syncNegativeEdgesFromLedger()
    }
    return state.frontierController
  }

  /** Return (or initialize) the run-scoped unified `FrontierDispatcher` bound to `FrontierWaveController`. */
  frontierDispatcherFor(runId: string): FrontierDispatcher {
    const state = this.runState.ensure(runId)
    if (!state.frontierDispatcher) {
      state.frontierDispatcher = new FrontierDispatcher({
        controller: this.frontierControllerFor(runId),
        getQuarantinedOrigins: () => {
          try {
            const currentRun = this.storage.run(runId)
            return this.getQuarantinedOriginSet(currentRun)
          } catch {
            return new Set<string>()
          }
        },
      })
    }
    return state.frontierDispatcher
  }

  /**
   * Per-origin SQLite evidence reader (`R4-H-11`):
   *  1. Lifetime per-origin live-response summary across ALL `broker_exchanges` rows for the run
   *     (never truncated by a global 240-row window, so busy origin A can never scroll origin B's
   *     earlier live 2xx response out of visibility).
   *  2. Per-origin bounded probe sample (up to 64 recent rows PER origin) joined with `assignments`
   *     so `detectQuarantinedOrigins` can distinguish Phase-0 / host-originated probes from
   *     arbitrary investigation worker traffic and apply `originQuarantineWindowMs`.
   */
  private queryPerOriginQuarantineEvidence(
    runId: string,
    originsToSample: readonly string[],
  ): {
    everLiveOrigins: Set<string>
    everReachableOrigins: Set<string>
    perOriginProbes: QuarantineObservedExchange[]
  } {
    const everLiveOrigins = new Set<string>()
    const everReachableOrigins = new Set<string>()
    const perOriginProbes: QuarantineObservedExchange[] = []
    try {
      const summaryRows = this.storage.client.prepare(`
        SELECT origin,
               MAX(CASE WHEN status >= 100 AND status < 600 AND status NOT IN (401, 407) AND (status < 520 OR status > 526) THEN created_at ELSE 0 END) AS lastLiveNon401At,
               MAX(CASE WHEN status >= 100 AND status < 600 AND (status < 520 OR status > 526) THEN created_at ELSE 0 END) AS lastReachableAt
        FROM broker_exchanges
        WHERE run_id = ?
        GROUP BY origin
      `).all(runId) as Array<{ origin: string; lastLiveNon401At: number; lastReachableAt: number }>
      for (const row of summaryRows) {
        if (!row.origin) continue
        if (Number(row.lastLiveNon401At) > 0) {
          everLiveOrigins.add(row.origin)
          everReachableOrigins.add(row.origin)
        } else if (Number(row.lastReachableAt) > 0) {
          everReachableOrigins.add(row.origin)
        }
      }
      if (originsToSample.length > 0) {
        const sampleStmt = this.storage.client.prepare(`
          SELECT be.origin,
                 be.path_and_query AS pathAndQuery,
                 be.status,
                 be.persona_handle AS personaHandle,
                 be.created_at AS createdAt,
                 a.phase AS assignmentPhase
          FROM broker_exchanges be
          LEFT JOIN assignments a ON a.id = be.assignment_id
          WHERE be.run_id = ? AND be.origin = ?
          ORDER BY be.created_at DESC
          LIMIT 64
        `)
        for (const origin of originsToSample) {
          const rows = sampleStmt.all(runId, origin) as Array<{
            origin: string
            pathAndQuery: string
            status: number
            personaHandle: string | null
            createdAt: number | null
            assignmentPhase: string | null
          }>
          for (const row of rows) {
            perOriginProbes.push(row)
          }
        }
      }
    } catch { /* best-effort DB read */ }
    return { everLiveOrigins, everReachableOrigins, perOriginProbes }
  }

  /** Reconcile non-running steps against current quarantined + circuit-open origins (`R4-H-12`). */
  private reconcileOriginUnavailableStepsForRun(
    run: Run,
    quarantinedRecords: ReadonlyMap<string, QuarantinedOriginRecord>,
    approvedOrigins?: ReadonlySet<string>,
  ): void {
    const scope = approvedOrigins ?? this.host.approvedOriginsSet(run)
    const circuitOpenOrigins = new Set<string>()
    for (const origin of scope) {
      if (this.broker.isCircuitOpen(origin)) circuitOpenOrigins.add(origin)
    }
    try {
      reconcileUnavailableOriginSteps({
        storage: this.storage,
        run,
        quarantinedOrigins: quarantinedRecords,
        circuitOpenOrigins,
        activeAssignmentIds: new Set(this.host.active.keys()),
      })
    } catch { /* step reconciliation is best-effort inside advisory calls */ }
  }

  /**
   * Record quarantined hosts (`edge_protected` / `unreachable`) on run state, emit a single
   * structured coverage gap per quarantined origin (idempotent via `(runId, goalRevision, origin, category)`),
   * transition non-running steps via `reconcileUnavailableOriginSteps`, and emit telemetry so
   * planner & dispatch concentrate turn budgets on live origins.
   */
  quarantineOrigins(
    run: Run,
    records: readonly QuarantinedOriginRecord[],
    assignmentId?: string,
  ): QuarantinedOriginRecord[] {
    if (!records.length) return []
    const existingMap = this.quarantinedOriginsByRun.get(run.id) ?? new Map<string, QuarantinedOriginRecord>()
    this.quarantinedOriginsByRun.set(run.id, existingMap)
    const gapAssignmentId = assignmentId?.trim() || 'planner:host-quarantine'
    const newlyQuarantined: QuarantinedOriginRecord[] = []
    const now = Date.now()

    for (const rec of records) {
      const origin = rec.origin.trim()
      if (!origin) continue
      const prev = existingMap.get(origin)
      // Preserve an existing `unreachable` diagnosis over a softer `edge_protected` one.
      if (prev && (prev.reason === rec.reason || prev.reason === 'unreachable')) continue
      const stamped: QuarantinedOriginRecord = { ...rec, origin, quarantinedAt: rec.quarantinedAt ?? now }
      existingMap.set(origin, stamped)
      newlyQuarantined.push(stamped)

      const category = stamped.reason === 'edge_protected' ? 'auth-identity' : 'misconfig-exposure'
      const summary = stamped.reason === 'edge_protected'
        ? `Host quarantined (edge_protected): ${stamped.detail}. Excluded from unauthenticated investigation steps; supply an authenticated persona for this origin to test behind the edge auth wall.`
        : `Host quarantined (unreachable): ${stamped.detail}. Excluded from investigation queue to concentrate budget on reachable origins.`
      try {
        this.storage.upsertCoverageEntry(run, gapAssignmentId, {
          origin,
          category,
          status: 'needs_follow_up',
          summary,
          proofGapReason: stamped.reason,
        })
      } catch (err) {
        this.noteLifecycleWarning(run.id, 'quarantineOrigins.upsertCoverageEntry', err, { origin, reason: stamped.reason })
      }
      try {
        this.storage.event(
          run.id,
          'planner.origin_quarantined',
          `Quarantined origin ${origin} (${stamped.reason}): ${stamped.detail}`,
          {
            origin,
            reason: stamped.reason,
            source: stamped.source,
            ...(stamped.observedStatuses?.length ? { observedStatuses: stamped.observedStatuses } : {}),
            ...(typeof stamped.requestsObserved === 'number' ? { requestsObserved: stamped.requestsObserved } : {}),
          },
        )
      } catch { /* telemetry is best-effort */ }
    }
    if (newlyQuarantined.length > 0) {
      this.reconcileOriginUnavailableStepsForRun(run, existingMap)
    }
    return newlyQuarantined
  }

  /**
   * Detect and quarantine edge-protected / dead hosts from Phase-0 output + per-origin broker
   * probes, automatically releasing any previously quarantined origin that has since returned a
   * live response, and reconciling queued steps cleanly (`R4-H-11`, `R4-H-12`).
   */
  refreshQuarantinedOriginsFromPhase0(
    run: Run,
    input: {
      approvedOrigins?: ReadonlySet<string>
      edgeProtectedOrigins?: DetectQuarantinedOriginsInput['edgeProtectedOrigins']
      skippedDeadHosts?: DetectQuarantinedOriginsInput['skippedDeadHosts']
      extraExchanges?: DetectQuarantinedOriginsInput['observedExchanges']
      assignmentId?: string
    },
  ): DetectQuarantinedOriginsResult {
    const approvedOrigins = input.approvedOrigins ?? this.host.approvedOriginsSet(run)
    const personas = [...resolveRunPersonas(this.storage, run.projectId, run.approvedPersonaIds).values()]
      .map(p => ({ handle: p.handle, originAllowlist: p.originAllowlist }))
    const approvedList = [...approvedOrigins]
    const evidence = this.queryPerOriginQuarantineEvidence(run.id, approvedList)
    const extraWithSource: QuarantineObservedExchange[] = (input.extraExchanges ?? []).map(ex => ({
      ...ex,
      probeSource: ex.probeSource ?? 'phase0',
    }))
    for (const ex of extraWithSource) {
      const origin = (ex.origin ?? '').trim()
      if (!origin) continue
      if (isLiveNon401HttpStatus(ex.status)) {
        evidence.everLiveOrigins.add(origin)
        evidence.everReachableOrigins.add(origin)
      }
    }

    // Release any previously quarantined origin that has now recorded a live response or persona.
    const stored = this.quarantinedOriginsByRun.get(run.id)
    let anyReleased = false
    if (stored) {
      for (const [origin, rec] of [...stored.entries()]) {
        const liveRecovered = evidence.everLiveOrigins.has(origin)
        const personaRecovered =
          rec.reason === 'edge_protected' && hasAuthenticatedPersonaForOrigin(origin, personas)
        if (liveRecovered || personaRecovered) {
          stored.delete(origin)
          anyReleased = true
          try {
            this.storage.event(
              run.id,
              'planner.origin_unquarantined',
              `Released origin ${origin} from ${rec.reason} quarantine (${liveRecovered ? 'live HTTP response observed' : 'authenticated persona available'}).`,
              { origin, previousReason: rec.reason, trigger: liveRecovered ? 'live_response' : 'persona_available' },
            )
          } catch { /* telemetry is best-effort */ }
        }
      }
    }

    const combinedExchanges: QuarantineObservedExchange[] = [
      ...evidence.perOriginProbes,
      ...extraWithSource,
    ]
    const detected = detectQuarantinedOrigins({
      approvedOrigins: approvedList,
      edgeProtectedOrigins: input.edgeProtectedOrigins,
      skippedDeadHosts: input.skippedDeadHosts,
      observedExchanges: combinedExchanges,
      personas,
      everLiveOrigins: evidence.everLiveOrigins,
      everReachableOrigins: evidence.everReachableOrigins,
    })
    if (detected.records.length > 0) {
      this.quarantineOrigins(run, detected.records, input.assignmentId)
    } else if (anyReleased && stored) {
      this.reconcileOriginUnavailableStepsForRun(run, stored, approvedOrigins)
    }
    return detected
  }

  /**
   * Return currently quarantined origin records for `run`. Automatically releases BOTH
   * `edge_protected` (when an authenticated persona OR live non-401 response arrives) AND
   * `unreachable` (when a live non-401 response arrives, or a reachable response with an
   * authenticated persona arrives), and samples unexamined origins strictly per origin (`R4-H-11`).
   */
  getQuarantinedOriginRecords(
    run: Run,
    approvedOrigins?: ReadonlySet<string>,
  ): Map<string, QuarantinedOriginRecord> {
    const scope = approvedOrigins ?? this.host.approvedOriginsSet(run)
    const personas = [...resolveRunPersonas(this.storage, run.projectId, run.approvedPersonaIds).values()]
      .map(p => ({ handle: p.handle, originAllowlist: p.originAllowlist }))
    const stored = this.quarantinedOriginsByRun.get(run.id)
    const unexamined = [...scope].filter(origin => !stored?.has(origin))
    const evidence = this.queryPerOriginQuarantineEvidence(run.id, unexamined)

    const out = new Map<string, QuarantinedOriginRecord>()
    let anyReleased = false
    if (stored) {
      for (const [origin, rec] of [...stored.entries()]) {
        if (scope.size > 0 && !scope.has(origin)) continue
        const hasLive = evidence.everLiveOrigins.has(origin)
        const hasPersona = hasAuthenticatedPersonaForOrigin(origin, personas)
        const shouldRelease =
          hasLive
          || (rec.reason === 'edge_protected' && hasPersona)
          || (rec.reason === 'unreachable' && evidence.everReachableOrigins.has(origin) && hasPersona)
        if (shouldRelease) {
          stored.delete(origin)
          anyReleased = true
          try {
            this.storage.event(
              run.id,
              'planner.origin_unquarantined',
              `Released origin ${origin} from ${rec.reason} quarantine (${hasLive ? 'live HTTP response observed' : 'authenticated persona available'}).`,
              { origin, previousReason: rec.reason, trigger: hasLive ? 'live_response' : 'persona_available' },
            )
          } catch { /* telemetry is best-effort */ }
          continue
        }
        out.set(origin, rec)
      }
    }

    // Detect any newly observed per-origin dead/401-wall hosts from host-originated probes
    // (covers resumed runs or direct planner invocations without a preceding runThreatModel call).
    const sampleableUnexamined = unexamined.filter(origin => !evidence.everLiveOrigins.has(origin))
    if (sampleableUnexamined.length > 0 && evidence.perOriginProbes.length > 0) {
      const detected = detectQuarantinedOrigins({
        approvedOrigins: sampleableUnexamined,
        observedExchanges: evidence.perOriginProbes,
        personas,
        everLiveOrigins: evidence.everLiveOrigins,
        everReachableOrigins: evidence.everReachableOrigins,
      })
      if (detected.records.length > 0) {
        this.quarantineOrigins(run, detected.records)
        const updatedMap = this.quarantinedOriginsByRun.get(run.id)
        for (const rec of detected.records) {
          out.set(rec.origin, updatedMap?.get(rec.origin) ?? rec)
        }
      }
    }

    if (anyReleased) {
      this.reconcileOriginUnavailableStepsForRun(run, out, scope)
    }
    return out
  }

  /**
   * Return currently quarantined origin set for `run`. Delegates to
   * {@link getQuarantinedOriginRecords} so live-response release and per-origin detection stay in
   * one authoritative path.
   */
  getQuarantinedOriginSet(run: Run, approvedOrigins?: ReadonlySet<string>): Set<string> {
    return new Set(this.getQuarantinedOriginRecords(run, approvedOrigins).keys())
  }

  /** Union of currently quarantined origins and circuit-open origins for `run` (`R4-H-12`). */
  unavailableOriginsForRun(run: Run, approvedOrigins?: ReadonlySet<string>): Set<string> {
    const scope = approvedOrigins ?? this.host.approvedOriginsSet(run)
    const unavailable = this.getQuarantinedOriginSet(run, scope)
    for (const origin of scope) {
      if (this.broker.isCircuitOpen(origin)) unavailable.add(origin)
    }
    return unavailable
  }

  /** Approved origins minus any currently quarantined (`edge_protected` / `unreachable`) hosts. */
  activeApprovedOrigins(run: Run, approvedOrigins?: ReadonlySet<string>): Set<string> {
    const scope = approvedOrigins ?? this.host.approvedOriginsSet(run)
    const quarantined = this.getQuarantinedOriginSet(run, scope)
    if (!quarantined.size) return new Set(scope)
    return new Set([...scope].filter(origin => !quarantined.has(origin)))
  }

  /**
   * Run v8 Layer-2 General Invariant Synthesis (white-box mounted source OR grey-box/black-box
   * runtime parity) and idempotently seed `CapabilityLedger` with strictly quarantined
   * (`promotionStatus: 'capability_only'`) capability nodes.
   *
   * Async & host-event-loop-safe (`R3-H-12`): reuses a pre-extracted `ProgramGraph` /
   * `StaticWorkspaceSnapshot` when supplied, otherwise reads bounded repo files asynchronously
   * via `fs.promises` with periodic event-loop yields and offloads `ProgramGraph` extraction
   * into `extractProgramGraphInWorker`.
   */
  async seedCapabilityLedgerInvariants(
    run: Run,
    options: SeedCapabilityLedgerInvariantsOptions = {},
  ): Promise<SeedCapabilityLedgerInvariantsResult> {
    const approvedOrigins = options.approvedOrigins ?? this.host.approvedOriginsSet(run)
    const mount = this.host.projectReposMount(run.projectId)
    const reposDir = options.reposDir ?? mount.reposDir
    const mountedRepos = options.mountedRepos ?? mount.mountedRepos

    const snap = options.staticSnapshot
    let sourceFiles: readonly SourceFileInput[] = options.sourceFiles ?? []
    let compose = options.compose ?? snap?.compose
    let ingress = options.ingress ?? snap?.ingress
    let graph = options.graph ?? snap?.programGraph
    let repoDescriptors: RepoAffinityDescriptor[] = []

    if (!sourceFiles.length && snap) {
      const fromSnap: SourceFileInput[] = []
      for (const [path, content] of snap.sourceByPath.entries()) {
        if (fromSnap.length >= 160) break
        if (!INVARIANT_SCAN_EXT.has(extname(path.toLowerCase()))) continue
        if (content.length > 128 * 1024) continue
        fromSnap.push({ path, content })
      }
      sourceFiles = fromSnap
    }

    if (!sourceFiles.length && !graph && reposDir && mountedRepos.length > 0 && options.mode !== 'grey-box' && options.mode !== 'black-box') {
      const collected = await collectBoundedRepoSourceFiles(reposDir, mountedRepos, 160, options.signal)
      sourceFiles = collected.files
      compose = compose ?? collected.compose
      ingress = ingress ?? collected.ingress
      repoDescriptors = collected.repoDescriptors
    }

    const hasWhiteBoxSource = Boolean(graph || sourceFiles.length > 0)
    const specs = options.specs ?? this.storage.listProjectSpecsFull(run.projectId)
    const hasGreyBoxContext = run.approvedPersonaIds.length > 0 || specs.length > 0
    const mode: SynthesizerMode = options.mode
      ?? (hasWhiteBoxSource ? 'white-box' : hasGreyBoxContext ? 'grey-box' : 'black-box')

    if (mode === 'white-box' && !graph && sourceFiles.length > 0) {
      graph = await extractProgramGraphInWorker(
        { files: sourceFiles, repo: mountedRepos[0] ?? 'mounted-repo' },
        { signal: options.signal },
      )
    }

    const runtimeInput: Omit<RuntimeDiscoveryInput, 'mode'> =
      options.runtime ?? this.collectRuntimeDiscoveryInput(run, approvedOrigins, specs)
    const { repoOriginMappings, resolvedServiceOrigins } = this.resolveInvariantOriginMappings(run, {
      approvedOrigins,
      mountedRepos,
      repoDescriptors,
      graph,
      serviceOrigins: options.serviceOrigins,
      compose,
      ingress,
    })

    // R4-H-16: White-box post-ProgramGraph invariant synthesis runs off the host event loop inside
    // `UntrustedComputePool` with a hard wall-clock timeout so hostile repo bytes never stall host.
    let precomputedSynthesis: SynthesizeInvariantsResult | undefined
    if (mode === 'white-box' && graph) {
      precomputedSynthesis = await synthesizeInvariantsInWorker({
        mode: 'white-box',
        graph,
        sourceFiles,
        services: options.services,
        serviceOrigins: resolvedServiceOrigins.length ? resolvedServiceOrigins : options.serviceOrigins,
        compose,
        ingress,
        runtime: runtimeInput,
        totalRunBudgetUsd: run.budgetUsd,
        maxHypotheses: options.maxHypotheses ?? 64,
      }, { signal: options.signal })
    }

    return this.finalizeCapabilityLedgerInvariants(run, {
      ...options,
      approvedOrigins,
      mountedRepos,
      repoDescriptors,
      specs,
      mode,
      graph,
      sourceFiles,
      compose,
      ingress,
      runtime: runtimeInput,
      precomputedSynthesis,
      precomputedRepoOriginMappings: repoOriginMappings,
    })
  }

  private resolveInvariantOriginMappings(
    run: Run,
    input: {
      approvedOrigins: ReadonlySet<string>
      mountedRepos?: readonly string[]
      repoDescriptors?: readonly RepoAffinityDescriptor[]
      graph?: ProgramGraph
      serviceOrigins?: readonly ServiceOriginMapping[]
      compose?: SeedCapabilityLedgerInvariantsOptions['compose']
      ingress?: SeedCapabilityLedgerInvariantsOptions['ingress']
    },
  ): {
    repoOriginMappings: RepoOriginAffinityMapping[]
    resolvedServiceOrigins: ServiceOriginMapping[]
  } {
    const { approvedOrigins, graph } = input
    const mountedRepos = input.mountedRepos ?? this.host.projectReposMount(run.projectId).mountedRepos
    const storedLiveEndpoints = this.storage.listEndpoints(run.id, { limit: 250 })
      .filter(ep => approvedOrigins.has(ep.origin))
    const descriptorByRoot = new Map<string, RepoAffinityDescriptor>()
    for (const desc of input.repoDescriptors ?? []) {
      const root = normalizeRepoRelPath(desc.root ?? desc.repo)
      descriptorByRoot.set(root, { ...desc, root })
    }
    for (const repo of mountedRepos) {
      const root = normalizeRepoRelPath(repo)
      if (!descriptorByRoot.has(root)) {
        descriptorByRoot.set(root, { repo, root })
      }
    }
    if (graph && descriptorByRoot.size > 0) {
      const routesByRoot = new Map<string, string[]>()
      for (const route of graph.routes) {
        const fileNorm = route.file.replace(/^\/+/, '')
        for (const root of descriptorByRoot.keys()) {
          if (root && (fileNorm === root || fileNorm.startsWith(`${root}/`))) {
            const list = routesByRoot.get(root) ?? []
            list.push(route.path)
            routesByRoot.set(root, list)
            break
          }
        }
      }
      for (const [root, routes] of routesByRoot.entries()) {
        const desc = descriptorByRoot.get(root)!
        descriptorByRoot.set(root, {
          ...desc,
          declaredRoutes: [...new Set([...(desc.declaredRoutes ?? []), ...routes])],
        })
      }
    }
    const cachedPhase0Mappings = this.repoOriginMappingsByRun.get(run.id) ?? []
    const combinedExplicitServiceOrigins = [
      ...(input.serviceOrigins ?? []),
      ...cachedPhase0Mappings,
    ]
    const repoOriginMappings = descriptorByRoot.size > 0
      ? resolveRepoOriginAffinity({
          approvedOrigins: [...approvedOrigins],
          repos: [...descriptorByRoot.values()],
          serviceOrigins: combinedExplicitServiceOrigins,
          compose: input.compose,
          ingress: input.ingress,
          liveEndpoints: storedLiveEndpoints.map(ep => ({
            origin: ep.origin,
            pathTemplate: ep.pathTemplate,
            method: ep.method,
            source: ep.source,
          })),
        })
      : []
    const resolvedServiceOrigins = [
      ...combinedExplicitServiceOrigins,
      ...repoOriginMappingsToServiceOrigins(repoOriginMappings),
    ]
    if (resolvedServiceOrigins.length > 0) {
      this.repoOriginMappingsByRun.set(run.id, resolvedServiceOrigins)
    }
    return { repoOriginMappings, resolvedServiceOrigins }
  }

  /**
   * Pure in-memory / SQLite finalization for `seedCapabilityLedgerInvariants` (zero filesystem
   * I/O, zero synchronous `ProgramGraph` extraction or white-box `synthesizeInvariants`). Shared
   * by async white-box worker seeding and the synchronous grey-box/black-box fast path in
   * `ensureWave1InvariantChainSteps`.
   */
  private finalizeCapabilityLedgerInvariants(
    run: Run,
    input: SeedCapabilityLedgerInvariantsOptions & {
      approvedOrigins: ReadonlySet<string>
      repoDescriptors?: readonly RepoAffinityDescriptor[]
      specs: ReturnType<Store['listProjectSpecsFull']>
      mode: SynthesizerMode
      graph?: ProgramGraph
      sourceFiles: readonly SourceFileInput[]
      precomputedSynthesis?: SynthesizeInvariantsResult
      precomputedRepoOriginMappings?: readonly RepoOriginAffinityMapping[]
    },
  ): SeedCapabilityLedgerInvariantsResult {
    const { approvedOrigins, specs, mode, graph } = input
    // Never silently default unmapped multi-origin seeds to approvedList[0].
    const defaultOrigin = approvedOrigins.size === 1 ? ([...approvedOrigins][0] ?? 'unknown') : 'unmapped'

    // Build grey-box / black-box runtime parity input from persisted endpoints, specs, and exchanges.
    const runtimeInput: Omit<RuntimeDiscoveryInput, 'mode'> = input.runtime ?? this.collectRuntimeDiscoveryInput(run, approvedOrigins, specs)
    const mountedRepos = input.mountedRepos ?? this.host.projectReposMount(run.projectId).mountedRepos
    const repoOriginMappings = input.precomputedRepoOriginMappings
      ?? this.resolveInvariantOriginMappings(run, {
        approvedOrigins,
        mountedRepos,
        repoDescriptors: input.repoDescriptors,
        graph,
        serviceOrigins: input.serviceOrigins,
        compose: input.compose,
        ingress: input.ingress,
      }).repoOriginMappings

    let synthesis: SynthesizeInvariantsResult
    if (input.precomputedSynthesis) {
      synthesis = input.precomputedSynthesis
    } else {
      const parity = inferRuntimeInvariantHypotheses({
        mode: mode === 'black-box' ? 'black-box' : 'grey-box',
        ...runtimeInput,
        maxHypotheses: input.maxHypotheses ?? 64,
      })
      synthesis = {
        mode: parity.mode,
        runtimeParity: parity,
        hypotheses: parity.hypotheses,
        capabilitySeeds: toCapabilityLedgerSeeds(parity.hypotheses),
      }
    }

    const seeds = synthesis.capabilitySeeds.length > 0
      ? synthesis.capabilitySeeds
      : toCapabilityLedgerSeeds(synthesis.hypotheses)
    const ledger = this.storage.capabilityLedger(run.id)
    const capIds: string[] = []
    const capIdByHypothesisId = new Map<string, string>()
    let seededCount = 0
    for (const seed of seeds) {
      const ledgerInput = seedRecordToLedgerInput(seed, defaultOrigin)
      capIdByHypothesisId.set(seed.metadata.hypothesisId, ledgerInput.capId)
      if (ledger.getCapability(ledgerInput.capId)) {
        capIds.push(ledgerInput.capId)
        continue
      }
      try {
        const added = ledger.addCapability(ledgerInput)
        capIds.push(added.capId)
        seededCount += 1
      } catch {
        // Strict fail-closed validation on malformed/secret-bearing seeds never crashes recon.
      }
    }
    this.invariantsSeededRuns.add(run.id)
    const seededIds = this.seededHypothesisIdsByRun.get(run.id) ?? new Set<string>()
    for (const h of synthesis.hypotheses) seededIds.add(h.id)
    this.seededHypothesisIdsByRun.set(run.id, seededIds)
    if (!input.runtime) {
      this.runtimeSynthesisWatermark.set(run.id, this.computeRuntimeSynthesisWatermark(run.id))
    }

    const shouldPromote = input.promoteWave1Chains !== false && run.capabilityTier > 0
    const wave1ChainStepIds = shouldPromote
      ? this.promoteInvariantHypothesesToWave1ChainSteps(run, synthesis, {
          approvedOrigins,
          capIdByHypothesisId,
          repoOriginMappings,
          mountedRepos,
          maxSteps: input.maxWave1ChainSteps ?? 6,
        })
      : []

    try {
      this.storage.event(
        run.id,
        'invariants.synthesized',
        `InvariantSynthesizer (${mode}) seeded ${seededCount} quarantined capability hypothesis node(s) (${synthesis.hypotheses.length} total, ${wave1ChainStepIds.length} Wave-1 chain step(s)).`,
        {
          mode,
          hypotheses: synthesis.hypotheses.length,
          seeded: seededCount,
          quarantined: capIds.length,
          wave1ChainStepsCreated: wave1ChainStepIds.length,
          wave1ChainStepIds,
          guardAsymmetries: synthesis.guardMatrix?.hypotheses.length ?? 0,
          trustBoundaries: synthesis.trustBoundaries?.hypotheses.length ?? 0,
          lifecycleSlices: synthesis.lifecycleSlices?.slices.length ?? 0,
          runtimeHypotheses: synthesis.runtimeParity?.hypotheses.length ?? 0,
        },
      )
    } catch { /* telemetry is best-effort */ }

    return {
      mode,
      synthesis,
      seededCount,
      quarantinedCount: capIds.length,
      capIds,
      wave1ChainStepsCreated: wave1ChainStepIds.length,
      wave1ChainStepIds,
    }
  }

  /**
   * Kick off worker-isolated white-box invariant seeding asynchronously without blocking a
   * synchronous dispatch tick (`driveInvestigation`). Deduped per `run.id`.
   */
  private scheduleAsyncInvariantSeeding(
    run: Run,
    options: {
      approvedOrigins: ReadonlySet<string>
      promoteWave1Chains?: boolean
      postFloor?: boolean
    },
  ): void {
    if (this.invariantsSeededRuns.has(run.id) || this.invariantsSeedingInFlight.has(run.id)) return
    const runTask = async (signal?: AbortSignal) => {
      try {
        const freshRun = this.storage.run(run.id)
        if (freshRun.status !== 'running' || signal?.aborted) return
        await this.seedCapabilityLedgerInvariants(freshRun, {
          approvedOrigins: options.approvedOrigins,
          promoteWave1Chains: options.promoteWave1Chains ?? true,
          signal,
        })
        if (options.postFloor) this.postFloorInvariantsSyncedRuns.add(run.id)
      } catch {
        // Additive Layer-2 synthesis must never crash background dispatch ticks.
      } finally {
        this.invariantsSeedingInFlight.delete(run.id)
      }
    }
    const promise = this.host.spawnRunTask
      ? this.host.spawnRunTask(run.id, 'invariants.seed', signal => runTask(signal)).promise.then(() => undefined, () => undefined)
      : runTask()
    this.invariantsSeedingInFlight.set(run.id, promise)
  }

  /**
   * Promote high-signal cross-surface / cross-service / entity-lifecycle hypotheses from
   * `synthesizeInvariants()` directly into ready Wave-1 `chain` lane `ChainStep`s BEFORE Phase B's
   * first dispatch tick so multi-hop chain proving starts in Wave 1 instead of Wave 2.
   */
  promoteInvariantHypothesesToWave1ChainSteps(
    run: Run,
    synthesis: SynthesizeInvariantsResult,
    options: {
      approvedOrigins?: ReadonlySet<string>
      capIdByHypothesisId?: ReadonlyMap<string, string>
      repoOriginMappings?: readonly RepoOriginAffinityMapping[]
      mountedRepos?: readonly string[]
      maxSteps?: number
    } = {},
  ): string[] {
    if (run.capabilityTier <= 0) {
      if (synthesis.hypotheses.length > 0) {
        const origins = [...(options.approvedOrigins ?? this.host.approvedOriginsSet(run))]
        this.emitPreconditionUnmet(run.id, {
          dedupeKey: `wave1_invariants:tier:${run.capabilityTier}`,
          origin: origins[0] ?? 'run',
          precondition: 'tier',
          vulnClass: 'chain-invariants',
          required: 'tier>=1',
          observed: `tier=${run.capabilityTier}`,
          method: 'ANY',
          route: '*',
          skippedCount: synthesis.hypotheses.length,
          source: 'planner.promote_wave1_invariants',
        })
      }
      return []
    }
    const approvedOrigins = options.approvedOrigins ?? this.host.approvedOriginsSet(run)
    if (!approvedOrigins.size) return []
    const quarantinedSet = this.getQuarantinedOriginSet(run, approvedOrigins)
    const activeOrigins = new Set([...approvedOrigins].filter(o => !quarantinedSet.has(o)))
    if (!activeOrigins.size) {
      this.wave1InvariantChainsPromoted.add(run.id)
      return []
    }

    const eligible = synthesis.hypotheses
      .filter(h => h.score >= 0.55 || h.severity === 'critical' || h.severity === 'high')
      .sort((a, b) =>
        WAVE1_INVARIANT_KIND_RANK[a.kind] - WAVE1_INVARIANT_KIND_RANK[b.kind]
        || b.score - a.score
        || a.id.localeCompare(b.id),
      )
    if (!eligible.length) {
      this.wave1InvariantChainsPromoted.add(run.id)
      return []
    }

    const existingSteps = this.storage.listChainSteps(run.id, run.goalRevision)
    const existingHypIds = new Set<string>()
    const existingTitles = new Set<string>()
    const existingActiveOriginCounts = new Map<string, number>()
    let existingActiveTotal = 0
    for (const step of existingSteps) {
      existingTitles.add(step.title.trim().toLowerCase())
      const m = /\[inv_hyp=([^\]]+)\]/.exec(step.hypothesis)
      if (m?.[1]) existingHypIds.add(m[1])
      if (step.status !== 'canceled' && step.status !== 'tainted') {
        existingActiveTotal += 1
        const primary = step.sourceOrigins[0]
        if (primary && activeOrigins.has(primary)) {
          existingActiveOriginCounts.set(primary, (existingActiveOriginCounts.get(primary) ?? 0) + 1)
        }
      }
    }

    const budget = computeDynamicStepBudget(this.storage, run.id)
    const maxToAdd = Math.max(0, Math.min(options.maxSteps ?? 6, budget - existingSteps.length))
    if (maxToAdd <= 0) {
      this.wave1InvariantChainsPromoted.add(run.id)
      return []
    }

    const personas = [...resolveRunPersonas(this.storage, run.projectId, run.approvedPersonaIds).values()]
      .sort((a, b) => a.handle.localeCompare(b.handle))
      .slice(0, 6)
    const personasSummary = personas.length
      ? personas.map(p => `${p.handle} (${p.roleLabel})`).join(', ')
      : 'unauthenticated / active run personas'
    const storedEndpoints = this.storage.listEndpoints(run.id, { limit: 250 })
      .filter(ep => approvedOrigins.has(ep.origin))
    const approvedList = [...approvedOrigins]

    // Build / reuse deterministic repo -> origin affinity table so mounted repo hypotheses bind
    // to their true origin and NEVER fall back onto `approvedList[0]` when `approvedOrigins.size > 1`.
    const mountedRepos = options.mountedRepos ?? this.host.projectReposMount(run.projectId).mountedRepos
    const repoMappings: readonly RepoOriginAffinityMapping[] = options.repoOriginMappings?.length
      ? options.repoOriginMappings
      : mountedRepos.length > 0
        ? resolveRepoOriginAffinity({
            approvedOrigins: approvedList,
            repos: mountedRepos,
            serviceOrigins: this.repoOriginMappingsByRun.get(run.id),
            liveEndpoints: storedEndpoints.map(ep => ({
              origin: ep.origin,
              pathTemplate: ep.pathTemplate,
              method: ep.method,
              source: ep.source,
            })),
          })
        : []

    // Index live non-AST endpoints by normalized path for live-route overlap matching.
    const liveOriginsByRoute = new Map<string, Set<string>>()
    for (const ep of storedEndpoints) {
      if (ep.source && STATIC_ONLY_ENDPOINT_SOURCES.has(ep.source.toLowerCase())) continue
      const norm = normalizeDeclaredRouteForOverlap(ep.pathTemplate)
      if (!norm) continue
      let set = liveOriginsByRoute.get(norm)
      if (!set) {
        set = new Set<string>()
        liveOriginsByRoute.set(norm, set)
      }
      set.add(ep.origin)
    }

    const resolveRepoMappingForFile = (filePath?: string): RepoOriginAffinityMapping | undefined => {
      if (!filePath || !repoMappings.length) return undefined
      const cleanFile = filePath.trim().replace(/^\/repos\//, '').replace(/^\/+/, '')
      for (const mapping of repoMappings) {
        if (mapping.root && (cleanFile === mapping.root || cleanFile.startsWith(`${mapping.root}/`))) {
          return mapping
        }
        const slug = repoBasenameSlug(mapping.repo)
        if (slug && (cleanFile === slug || cleanFile.startsWith(`${slug}/`))) {
          return mapping
        }
      }
      return undefined
    }

    const seenCluster = new Set<string>()
    let unmappedCount = 0
    let quarantinedSkippedCount = 0
    const unmappedHypIds: string[] = []
    interface PreparedWave1Candidate {
      hyp: InvariantHypothesis
      targetOrigins: string[]
      targetAssetIds: string[]
      capId: string
      uniqueRoutes: string[]
      hopDepth: number
      title: string
      hypothesis: string
      category: string
      skills: string[]
      clusterKey: string
    }
    const preparedCandidates: PreparedWave1Candidate[] = []

    for (const hyp of eligible) {
      if (existingHypIds.has(hyp.id)) continue
      const clusterKey = `${hyp.kind}|${hyp.entity.toLowerCase()}|${(hyp.targetRoute ?? hyp.surface).toLowerCase()}`
      if (seenCluster.has(clusterKey)) continue

      const resolvedOrigins: string[] = []
      const pushOrigin = (o?: string) => {
        if (o && approvedOrigins.has(o) && !resolvedOrigins.includes(o)) {
          resolvedOrigins.push(o)
        }
      }

      // 1. Explicit serviceOrigin on the hypothesis
      if (hyp.serviceOrigin && approvedOrigins.has(hyp.serviceOrigin)) pushOrigin(hyp.serviceOrigin)

      // 2. Explicit host/origin mention in evidence or summary (critical for trust_boundary_mismatch)
      const evidenceText = `${hyp.summary} ${hyp.evidence.join(' ')}`
      for (const origin of approvedList) {
        if (resolvedOrigins.includes(origin)) continue
        try {
          const host = new URL(origin).host
          if (evidenceText.includes(origin) || evidenceText.includes(host)) pushOrigin(origin)
        } catch { /* ignore */ }
      }

      // 3. Live-route overlap matching BEFORE whole-repo affinity (essential for shared monorepos)
      const candidateRouteRefs = [
        ...(hyp.targetRoute ? [hyp.targetRoute] : []),
        ...extractRouteRefsFromText([...hyp.evidence, ...hyp.preconditions, hyp.summary]),
      ]
      if ((!resolvedOrigins.length || hyp.kind === 'trust_boundary_mismatch') && candidateRouteRefs.length > 0) {
        const originHits = new Map<string, number>()
        for (const ref of candidateRouteRefs) {
          const norm = normalizeDeclaredRouteForOverlap(ref)
          if (!norm) continue
          const hits = liveOriginsByRoute.get(norm)
          if (!hits || hits.size === 0) continue
          const weight = hits.size === 1 ? 2 : 1
          for (const origin of hits) originHits.set(origin, (originHits.get(origin) ?? 0) + weight)
        }
        const rankedHits = [...originHits.entries()].sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]))
        if (rankedHits.length > 0 && (rankedHits.length === 1 || rankedHits[0]![1] > rankedHits[1]![1])) {
          pushOrigin(rankedHits[0]![0])
        }
      }

      // 4. Deterministic repo->origin affinity (skip whole-repo single-origin binding on shared monorepos)
      const isSharedMonorepo = mountedRepos.length > 0 && mountedRepos.length < approvedList.length
      const fileRepoMapping = resolveRepoMappingForFile(hyp.location?.file)
      const skipWholeRepoBind = isSharedMonorepo && (mountedRepos.length === 1 || fileRepoMapping?.confidence === 'live_route')
      if (!resolvedOrigins.length && !skipWholeRepoBind && fileRepoMapping?.origin && fileRepoMapping.confidence !== 'unmapped') {
        pushOrigin(fileRepoMapping.origin)
      }

      // 5. Repo slug mention inside evidence/summary (when no location.file was attached)
      if (!resolvedOrigins.length && !skipWholeRepoBind && repoMappings.length > 0) {
        const lowerEvidence = evidenceText.toLowerCase()
        for (const mapping of repoMappings) {
          if (!mapping.origin || mapping.confidence === 'unmapped') continue
          if (isSharedMonorepo && mapping.confidence === 'live_route') continue
          const slug = repoBasenameSlug(mapping.repo)
          if (slug.length >= 3 && (lowerEvidence.includes(`${slug}/`) || lowerEvidence.includes(` ${slug} `))) {
            pushOrigin(mapping.origin); break
          }
        }
      }

      // 6. Fuzzy path-prefix match + multi-origin fallback + cross-service sibling preservation.
      if (!resolvedOrigins.length) {
        const fb = resolveWave1MultiOriginFallback({
          hypEntity: hyp.entity, candidateRouteRefs, approvedList, activeOrigins, storedEndpoints,
          staticOnlySources: STATIC_ONLY_ENDPOINT_SOURCES,
          explicitlyUnmappedMountedRepo: mountedRepos.length > 1 && fileRepoMapping?.confidence === 'unmapped',
          normalizeRoute: normalizeDeclaredRouteForOverlap, classifyTier: classifyHostTier,
        })
        if (fb.origins.length) { for (const o of fb.origins) pushOrigin(o) }
        else { unmappedCount += 1; if (unmappedHypIds.length < 16) unmappedHypIds.push(hyp.id); continue }
      }
      if (hyp.kind === 'trust_boundary_mismatch' && activeOrigins.size > 1 && resolvedOrigins.some(o => activeOrigins.has(o))) {
        for (const o of approvedList) { if (activeOrigins.has(o)) pushOrigin(o) }
      }

      // 7. Quarantine filter: exclude uniform edge-protected / dead origins so they never burn turns.
      const targetOrigins = resolvedOrigins.filter(origin => activeOrigins.has(origin))
      if (!targetOrigins.length) {
        quarantinedSkippedCount += 1
        continue
      }

      const targetAssetIds = run.candidates
        .filter(c => targetOrigins.includes(c.origin) && run.approved.includes(c.id))
        .map(c => c.id)
      if (!targetAssetIds.length) continue

      const capId = options.capIdByHypothesisId?.get(hyp.id)
        ?? formatDerivedCapabilityHandle(
          'synth',
          hyp.id.replace(/[^A-Za-z0-9._-]/g, '_').replace(/^[^A-Za-z0-9]+/, '').slice(0, 60) || 'seed',
        )
      const routeRefs = [...candidateRouteRefs]
      if (routeRefs.length < 2 && hyp.entity && hyp.entity !== 'service' && hyp.entity !== 'boundary') {
        const entityToken = hyp.entity.toLowerCase().replace(/[^a-z0-9]/g, '')
        for (const ep of storedEndpoints) {
          if (!targetOrigins.includes(ep.origin)) continue
          if (entityToken.length >= 3 && ep.pathTemplate.toLowerCase().includes(entityToken)) {
            const ref = `${ep.method} ${ep.pathTemplate}`
            if (!routeRefs.includes(ref)) routeRefs.push(ref)
            if (routeRefs.length >= 3) break
          }
        }
      }
      const uniqueRoutes = [...new Set(routeRefs)].slice(0, 4)
      const hopDepth = hyp.kind === 'trust_boundary_mismatch' || targetOrigins.length >= 2 ? 3 : 2
      const kindLabel = hyp.kind === 'trust_boundary_mismatch'
        ? 'Cross-service boundary chain'
        : hyp.kind === 'policy_asymmetry' || hyp.kind === 'runtime_surface_asymmetry'
          ? 'Cross-surface policy chain'
          : 'Entity lifecycle chain'
      const routeSuffix = uniqueRoutes[0] ? ` · ${uniqueRoutes[0]}` : ''
      const title = `Wave-1 chain · ${kindLabel} (${hyp.entity}/${hyp.surface})${routeSuffix}`.slice(0, 180)
      if (existingTitles.has(title.toLowerCase())) continue

      const locationTag = hyp.location ? ` Source: ${hyp.location.file}:${hyp.location.line}.` : ''
      const preconditionsTag = hyp.preconditions.length
        ? ` Preconditions: ${hyp.preconditions.slice(0, 3).join('; ')}.`
        : ''
      const endpointsTag = uniqueRoutes.length ? ` Endpoints: ${uniqueRoutes.join(', ')}.` : ''
      const hypothesis = (
        `[chain_hops=${hopDepth}] [lane=chain] [inv_hyp=${hyp.id}] [cap=${capId}] `
        + `Multi-hop invariant chain (${hyp.mode} ${hyp.kind}): ${hyp.summary}`
        + `${endpointsTag} Personas: ${personasSummary}.${preconditionsTag}${locationTag} `
        + `Verification: ${hyp.verificationHint}`
      ).slice(0, 1200)

      const category = invariantHypothesisCategory(hyp)
      const skills = invariantHypothesisSkills(hyp)
      preparedCandidates.push({
        hyp,
        targetOrigins,
        targetAssetIds,
        capId,
        uniqueRoutes,
        hopDepth,
        title,
        hypothesis,
        category,
        skills,
        clusterKey,
      })
      seenCluster.add(clusterKey)
      existingTitles.add(title.toLowerCase())
    }

    // Apply soft per-origin concentration guard (<= 50%) so no single live host monopolizes Wave-1 chains.
    const fairCandidates = enforcePerOriginFairness(preparedCandidates, {
      limit: maxToAdd,
      maxOriginShare: DEFAULT_MAX_ORIGIN_SHARE,
      existingCountsByOrigin: existingActiveOriginCounts,
      existingTotal: existingActiveTotal,
      originOf: item => item.targetOrigins[0],
      quarantinedOrigins: quarantinedSet,
    })

    const createdIds: string[] = []
    for (const item of fairCandidates) {
      const { hyp, targetOrigins, targetAssetIds, capId, uniqueRoutes, hopDepth, title, hypothesis, category, skills } = item
      const primaryRouteRef = uniqueRoutes[0] ?? '/'
      const primaryRouteParts = primaryRouteRef.trim().split(/\s+/)
      const primaryMethod = primaryRouteParts.length >= 2 ? primaryRouteParts[0]!.toUpperCase() : 'ANY'
      const primaryPath = primaryRouteParts.length >= 2 ? primaryRouteParts.slice(1).join(' ') : primaryRouteRef
      const frontierController = this.frontierControllerFor(run.id)
      const branchAdmission = frontierController.admitStepBranch({
        branchKey: `wave1:inv:${hyp.id}`.slice(0, 120),
        depth: hopDepth,
        origin: targetOrigins[0] ?? 'unknown',
        endpoint: primaryPath,
        method: primaryMethod,
        hypothesisClass: category,
        goalSummary: title,
        capabilityId: capId,
        waveNo: Math.max(1, run.roundNo || 1),
      })
      if (!branchAdmission.admitted) {
        try {
          this.storage.event(
            run.id,
            'frontier.branch_suppressed',
            `FrontierWaveController suppressed Wave-1 invariant branch "${title}" (dead-end negative edge).`,
            { branchKey: branchAdmission.branchKey, hypothesisId: hyp.id, category },
          )
        } catch (err) {
          this.noteLifecycleWarning(run.id, 'wave1.branch_suppressed_event', err, { hypothesisId: hyp.id })
        }
        continue
      }
      const created = this.storage.addChainStep(run, {
        title,
        hypothesis,
        category,
        priority: WAVE1_INVARIANT_PRIORITY[hyp.severity],
        targetAssetIds,
        skills,
        dependsOnFactIds: [],
        dependsOnStepIds: [],
        sourceOrigins: targetOrigins,
        specialistProfile: routeStepToSpecialist({ title, hypothesis, category, skills }),
      })
      const targetsToRegister: StructuredStepTarget[] = uniqueRoutes.length > 0
        ? uniqueRoutes.flatMap(ref => {
            const parts = ref.trim().split(/\s+/)
            const method = parts.length >= 2 ? parts[0]!.toUpperCase() : 'ANY'
            const route = parts.length >= 2 ? parts.slice(1).join(' ') : ref
            return targetOrigins.map(origin => ({ origin, method, route, vulnClass: category }))
          })
        : targetOrigins.map(origin => ({ origin, method: 'ANY', route: '/', vulnClass: category }))
      this.registerStepTargets(run.id, created.id, targetsToRegister)
      createdIds.push(created.id)
      existingHypIds.add(hyp.id)
    }

    this.wave1InvariantChainsPromoted.add(run.id)
    if (unmappedCount > 0 || quarantinedSkippedCount > 0) {
      try {
        this.storage.event(
          run.id,
          'invariants.unmapped_origin_skipped',
          `Skipped ${unmappedCount} unmapped-origin and ${quarantinedSkippedCount} quarantined-origin Wave-1 invariant hypothesis(es) instead of falling back to approvedOrigins[0].`,
          {
            unmappedCount,
            quarantinedSkippedCount,
            unmappedHypothesisIds: unmappedHypIds,
            approvedOriginCount: approvedList.length,
          },
        )
      } catch { /* telemetry is best-effort */ }
    }
    if (createdIds.length > 0) {
      try {
        this.storage.event(
          run.id,
          'invariants.wave1_chains_seeded',
          `Promoted ${createdIds.length} synthesized invariant hypothesis(es) directly into ready Wave-1 chain steps.`,
          {
            mode: synthesis.mode,
            count: createdIds.length,
            stepIds: createdIds,
            hypothesisKinds: [...new Set(fairCandidates.slice(0, createdIds.length).map(c => c.hyp.kind))],
          },
        )
      } catch { /* telemetry is best-effort */ }
    }
    return createdIds
  }

  /**
   * Ensure Wave-1 invariant chain steps are promoted before Phase B's first dispatch tick, and
   * incrementally synthesize new grey-box/runtime invariants & Wave-1 composites after Phase A
   * floor settles without letting pre-floor runs suppress post-floor differentials.
   */
  ensureWave1InvariantChainSteps(
    run: Run,
    approvedOrigins: ReadonlySet<string>,
    options: { postFloor?: boolean } = {},
  ): number {
    if (run.capabilityTier <= 0) return 0
    const sourceMounted = this.host.projectReposMount(run.projectId).mountedRepos.length > 0
    if (!this.invariantsSeededRuns.has(run.id)) {
      if (sourceMounted) {
        // White-box mounted repo: never run synchronous disk walk or ProgramGraph extraction on the host event loop.
        this.scheduleAsyncInvariantSeeding(run, {
          approvedOrigins,
          promoteWave1Chains: true,
          postFloor: options.postFloor,
        })
        return 0
      }
      // Grey-box / black-box (no mounted repo): pure in-memory/SQLite runtime parity (zero fs, zero ProgramGraph).
      const specs = this.storage.listProjectSpecsFull(run.projectId)
      const hasGreyBoxContext = run.approvedPersonaIds.length > 0 || specs.length > 0
      const res = this.finalizeCapabilityLedgerInvariants(run, {
        approvedOrigins,
        specs,
        mode: hasGreyBoxContext ? 'grey-box' : 'black-box',
        sourceFiles: [],
        promoteWave1Chains: true,
      })
      const compositeCount = this.promoteRuntimeCompositeWave1Steps(run, approvedOrigins)
      if (options.postFloor) this.postFloorInvariantsSyncedRuns.add(run.id)
      return res.wave1ChainStepsCreated + compositeCount
    }
    return this.syncPostFloorRuntimeInvariants(run, approvedOrigins, {
      sourceMounted,
      postFloor: options.postFloor,
    }).wave1StepsCreated
  }

  private computeRuntimeSynthesisWatermark(runId: string): string {
    const countOf = (table: 'endpoints' | 'facts' | 'broker_exchanges' | 'api_dependencies'): number => {
      try {
        const row = this.storage.client.prepare(`SELECT COUNT(*) AS cnt FROM ${table} WHERE run_id = ?`).get(runId) as { cnt?: number } | undefined
        return Number(row?.cnt ?? 0)
      } catch {
        return 0
      }
    }
    let graphDeps = 0
    try { graphDeps = this.host.endpointGraphCatalog(runId).apiDependencies.length } catch { /* ignore */ }
    return `${countOf('endpoints')}|${countOf('facts')}|${countOf('broker_exchanges')}|${countOf('api_dependencies')}|${graphDeps}`
  }

  private collectRuntimeDiscoveryBundle(
    run: Run,
    approvedOrigins: ReadonlySet<string>,
    specs: ReturnType<Store['listProjectSpecsFull']>,
  ) {
    const endpoints = this.storage.listEndpoints(run.id, { limit: 200 })
      .filter(ep => approvedOrigins.size === 0 || approvedOrigins.has(ep.origin))
    const originByRouteKey = new Map<string, string>()
    for (const ep of endpoints) {
      const routeKey = `${ep.method.toUpperCase()} ${ep.pathTemplate}`
      if (!originByRouteKey.has(routeKey)) originByRouteKey.set(routeKey, ep.origin)
    }
    const facts = this.pageAll((offset, limit) =>
      this.storage.listFacts(run.id, { includeTainted: false, limit, offset }))
      .filter(fact => approvedOrigins.size === 0 || approvedOrigins.has(fact.origin))
    const { catalogFacts, allApiDeps, extraApiDeps } = this.mergeGraphApiDependencies(run.id, approvedOrigins, originByRouteKey, facts)

    let brokerExchanges: Array<{
      origin: string; method: string; pathAndQuery: string; status: number
      personaHandle: string | null; respHeadersJson: string | null
    }> = []
    try {
      const rows = this.storage.client.prepare(`
        SELECT origin, method, path_and_query AS pathAndQuery, status, persona_handle AS personaHandle, resp_headers AS respHeadersJson
        FROM broker_exchanges
        WHERE run_id = ?
        ORDER BY created_at DESC
        LIMIT 120
      `).all(run.id) as typeof brokerExchanges
      brokerExchanges = rows.filter(row => approvedOrigins.size === 0 || approvedOrigins.has(row.origin))
    } catch { /* best-effort runtime observation scan */ }

    return { endpoints, facts, catalogFacts, allApiDeps, extraApiDeps, brokerExchanges, specs }
  }

  private collectRuntimeDiscoveryInput(
    run: Run,
    approvedOrigins: ReadonlySet<string>,
    specs: ReturnType<Store['listProjectSpecsFull']>,
  ): Omit<RuntimeDiscoveryInput, 'mode'> {
    const bundle = this.collectRuntimeDiscoveryBundle(run, approvedOrigins, specs)
    return buildRuntimeDiscoveryInput({
      approvedOrigins,
      endpoints: bundle.endpoints,
      specs: bundle.specs,
      facts: bundle.facts,
      brokerExchanges: bundle.brokerExchanges,
      apiDependencies: bundle.extraApiDeps,
    })
  }

  private promoteRuntimeCompositeWave1Steps(
    run: Run,
    approvedOrigins: ReadonlySet<string>,
    bundle?: ReturnType<ExecReconPlanner['collectRuntimeDiscoveryBundle']>,
  ): number {
    if (run.capabilityTier <= 0) return 0
    const activeOrigins = this.activeApprovedOrigins(run, approvedOrigins)
    if (!activeOrigins.size) return 0
    const specs = bundle?.specs ?? this.storage.listProjectSpecsFull(run.projectId)
    const resolvedBundle = bundle ?? this.collectRuntimeDiscoveryBundle(run, activeOrigins, specs)
    const approvedAssets = run.candidates.filter(c => activeOrigins.has(c.origin) && run.approved.includes(c.id))
    const hostTiers = computeHostTiers([...activeOrigins], approvedAssets.map(classifyHostHeuristic))
    const apiDependencies: RuntimeCompositeApiDependencyInput[] = resolvedBundle.allApiDeps
      .filter(d => (!d.producerOrigin || activeOrigins.has(d.producerOrigin)) && (!d.consumerOrigin || activeOrigins.has(d.consumerOrigin)))
      .map(d => ({
        producer: d.producer,
        consumer: d.consumer,
        resourceKey: d.resourceKey,
        ...(d.producerOrigin ? { producerOrigin: d.producerOrigin } : {}),
        ...(d.consumerOrigin ? { consumerOrigin: d.consumerOrigin } : {}),
        ...(d.personaHandle !== undefined ? { personaHandle: d.personaHandle } : {}),
      }))
    const frontierController = this.frontierControllerFor(run.id)
    const compositeCreated = synthesizeRuntimeCompositeWave1Steps(this.storage, run, {
      sourceMounted: false,
      facts: resolvedBundle.facts.filter(f => activeOrigins.has(f.origin)),
      endpoints: resolvedBundle.endpoints.filter(ep => activeOrigins.has(ep.origin)),
      apiDependencies, specs: resolvedBundle.specs, hostTiers, frontierController,
    })
    const dataflowCreated = materializeGreyBoxDataflowWave1Steps(this.storage, run, {
      activeOrigins, sourceMounted: false, maxSteps: 6, llmMode: privateModelProfiles(this.storage).length > 0 ? 'agentic' : 'deterministic-no-llm', routeStep: routeStepToSpecialist,
    })
    const created = [...dataflowCreated, ...compositeCreated]
    for (const step of created) {
      const origin = step.sourceOrigins[0] ?? [...approvedOrigins][0] ?? ''
      const depEndpoint = resolvedBundle.endpoints.find(ep => step.sourceOrigins.includes(ep.origin) && step.hypothesis.includes(ep.pathTemplate))
      if (origin) {
        this.registerStepTargets(run.id, step.id, [{
          origin: depEndpoint?.origin ?? origin,
          method: depEndpoint?.method?.toUpperCase() ?? 'ANY',
          route: depEndpoint?.pathTemplate ?? '/',
          vulnClass: step.category,
        }])
      }
    }
    this.runtimeCompositeSeededRuns.add(run.id)
    return created.length
  }

  /**
   * Incrementally run `synthesizePostFloorRuntimeInvariants` + `synthesizeRuntimeCompositeWave1Steps`
   * after Phase A floor settles or whenever new runtime facts/exchanges/dependencies arrive.
   */
  syncPostFloorRuntimeInvariants(
    run: Run,
    approvedOrigins: ReadonlySet<string>,
    options: { sourceMounted?: boolean; postFloor?: boolean } = {},
  ): { seededCount: number; wave1StepsCreated: number } {
    if (run.capabilityTier <= 0) return { seededCount: 0, wave1StepsCreated: 0 }
    const sourceMounted = options.sourceMounted ?? this.host.projectReposMount(run.projectId).mountedRepos.length > 0
    const watermark = this.computeRuntimeSynthesisWatermark(run.id)
    const forcePostFloor = Boolean(options.postFloor) && !this.postFloorInvariantsSyncedRuns.has(run.id)
    const needsComposite = !sourceMounted && !this.runtimeCompositeSeededRuns.has(run.id)
    if (!forcePostFloor && !needsComposite && this.runtimeSynthesisWatermark.get(run.id) === watermark) {
      return { seededCount: 0, wave1StepsCreated: 0 }
    }

    const specs = this.storage.listProjectSpecsFull(run.projectId)
    const bundle = this.collectRuntimeDiscoveryBundle(run, approvedOrigins, specs)
    const ledger = this.storage.capabilityLedger(run.id)
    const existingHypIds = new Set<string>(this.seededHypothesisIdsByRun.get(run.id) ?? [])
    for (const node of ledger.listCapabilities()) {
      const hypId = node.metadata?.hypothesisId
      if (typeof hypId === 'string' && hypId) existingHypIds.add(hypId)
    }
    for (const step of this.storage.listChainSteps(run.id, run.goalRevision)) {
      const m = /\[inv_hyp=([^\]]+)\]/.exec(step.hypothesis)
      if (m?.[1]) existingHypIds.add(m[1])
    }

    const mode: 'grey-box' | 'black-box' = run.approvedPersonaIds.length > 0 || specs.length > 0 ? 'grey-box' : 'black-box'
    const res = synthesizePostFloorRuntimeInvariants({
      mode,
      approvedOrigins,
      endpoints: bundle.endpoints,
      specs: bundle.specs,
      facts: bundle.facts,
      brokerExchanges: bundle.brokerExchanges,
      apiDependencies: bundle.extraApiDeps,
      existingHypothesisIds: existingHypIds,
      maxHypotheses: 64,
    })

    const defaultOrigin = approvedOrigins.size === 1 ? ([...approvedOrigins][0] ?? 'unknown') : 'unmapped'
    const capIdByHypothesisId = new Map<string, string>()
    let seededCount = 0
    for (const seed of res.capabilitySeeds) {
      const input = seedRecordToLedgerInput(seed, defaultOrigin)
      capIdByHypothesisId.set(seed.metadata.hypothesisId, input.capId)
      if (ledger.getCapability(input.capId)) continue
      try {
        ledger.addCapability(input)
        seededCount += 1
      } catch { /* fail-closed ledger validation */ }
    }
    for (const hyp of res.hypotheses) existingHypIds.add(hyp.id)
    this.seededHypothesisIdsByRun.set(run.id, existingHypIds)

    let wave1InvariantCreated = 0
    if (res.newHypotheses.length > 0) {
      const createdIds = this.promoteInvariantHypothesesToWave1ChainSteps(run, {
        mode: res.mode,
        runtimeParity: res.runtimeParity,
        hypotheses: res.newHypotheses,
        capabilitySeeds: res.capabilitySeeds,
      }, {
        approvedOrigins,
        capIdByHypothesisId,
        maxSteps: 6,
      })
      wave1InvariantCreated = createdIds.length
    }

    let compositeCreated = 0
    if (!sourceMounted) {
      compositeCreated = this.promoteRuntimeCompositeWave1Steps(run, approvedOrigins, bundle)
    }

    this.runtimeSynthesisWatermark.set(run.id, watermark)
    if (options.postFloor) this.postFloorInvariantsSyncedRuns.add(run.id)
    const wave1StepsCreated = wave1InvariantCreated + compositeCreated
    if (seededCount > 0 || wave1StepsCreated > 0) {
      try {
        this.storage.event(
          run.id,
          'invariants.post_floor_synthesized',
          `Post-floor synthesis (${mode}) added ${seededCount} new capability seed(s) and ${wave1StepsCreated} Wave-1 chain step(s).`,
          {
            mode,
            newHypotheses: res.newHypotheses.length,
            seededCount,
            wave1InvariantCreated,
            compositeCreated,
          },
        )
      } catch { /* telemetry is best-effort */ }
    }
    return { seededCount, wave1StepsCreated }
  }

  private collectCoordinatorApiDependencies(run: Run): CoordinatorApiDependency[] {
    const approvedOrigins = this.host.approvedOriginsSet(run)
    const endpoints = this.storage.listEndpoints(run.id, { limit: 200 })
      .filter(ep => approvedOrigins.size === 0 || approvedOrigins.has(ep.origin))
    const originByRouteKey = new Map<string, string>()
    for (const ep of endpoints) {
      const key = `${ep.method.toUpperCase()} ${ep.pathTemplate}`
      if (!originByRouteKey.has(key)) originByRouteKey.set(key, ep.origin)
    }
    const facts = this.pageAll((offset, limit) =>
      this.storage.listFacts(run.id, { includeTainted: false, limit, offset }))
      .filter(fact => approvedOrigins.size === 0 || approvedOrigins.has(fact.origin))
    return this.mergeGraphApiDependencies(run.id, approvedOrigins, originByRouteKey, facts).allApiDeps
  }

  private mergeGraphApiDependencies(
    runId: string,
    approvedOrigins: ReadonlySet<string>,
    originByRouteKey: ReadonlyMap<string, string>,
    facts: readonly Fact[],
  ): { catalogFacts: ReturnType<typeof extractRuntimeCatalogFromFacts>; allApiDeps: RuntimeApiDependency[]; extraApiDeps: RuntimeApiDependency[] } {
    const catalogFacts = extractRuntimeCatalogFromFacts(facts, approvedOrigins)
    const seenDeps = new Set<string>()
    const allApiDeps: RuntimeApiDependency[] = []
    const extraApiDeps: RuntimeApiDependency[] = []
    const depKey = (d: Pick<RuntimeApiDependency, 'producer' | 'consumer' | 'resourceKey' | 'producerOrigin' | 'consumerOrigin'>) =>
      `${d.producerOrigin ?? ''}|${d.producer}|${d.consumerOrigin ?? ''}|${d.consumer}|${d.resourceKey}`

    for (const d of catalogFacts.apiDependencies) {
      const key = depKey(d)
      if (seenDeps.has(key)) continue
      seenDeps.add(key)
      allApiDeps.push(d)
    }

    let rawGraphDeps: unknown[] = []
    try { rawGraphDeps = this.host.endpointGraphCatalog(runId).apiDependencies } catch { /* ignore */ }
    for (const raw of rawGraphDeps) {
      if (!raw || typeof raw !== 'object') continue
      const d = raw as Partial<RuntimeApiDependency>
      if (typeof d.producer !== 'string' || typeof d.consumer !== 'string' || typeof d.resourceKey !== 'string') continue
      const producerOrigin = d.producerOrigin ?? originByRouteKey.get(d.producer)
      const consumerOrigin = d.consumerOrigin ?? originByRouteKey.get(d.consumer)
      if (approvedOrigins.size > 0 && ((producerOrigin && !approvedOrigins.has(producerOrigin)) || (consumerOrigin && !approvedOrigins.has(consumerOrigin)))) {
        continue
      }
      const normalized: RuntimeApiDependency = {
        producer: d.producer,
        consumer: d.consumer,
        resourceKey: d.resourceKey,
        ...(producerOrigin ? { producerOrigin } : {}),
        ...(consumerOrigin ? { consumerOrigin } : {}),
        ...(d.personaHandle !== undefined ? { personaHandle: d.personaHandle } : {}),
        ...(Array.isArray(d.observedTransitions) ? { observedTransitions: d.observedTransitions } : {}),
        ...(typeof d.testedBola === 'boolean' ? { testedBola: d.testedBola } : {}),
      }
      const key = depKey(normalized)
      if (seenDeps.has(key)) continue
      seenDeps.add(key)
      allApiDeps.push(normalized)
      extraApiDeps.push(normalized)
    }
    return { catalogFacts, allApiDeps, extraApiDeps }
  }

  /** Sync extracted typed ChainHops into CapabilityLedger as quarantined capability_only nodes. */
  private syncChainHopsToLedger(run: Run, ledger: CapabilityLedger, hops: readonly ChainHop[], llmMode: FrontierLlmMode, existingFacts?: readonly Fact[]): void {
    const obsIndex = buildHopRuntimeObservationIndex(this.storage, run.id, llmMode, existingFacts)
    for (const hop of hops.slice(0, 32)) {
      const slot = hop.hopId.replace(/[^A-Za-z0-9._-]/g, '_').replace(/^[^A-Za-z0-9]+/, '').slice(0, 56) || 'hop'
      const capId = formatDerivedCapabilityHandle(`r${hop.roundNo}`, slot)
      if (ledger.getCapability(capId)) continue
      const obs = inspectChainHopRuntimeObservation(hop, llmMode, obsIndex)
      const surface: CapabilitySurface = hop.artifactKind === 'stored_write_handle' ? 'browser'
        : hop.artifactKind === 'ssrf_redirect_target' ? 'webhook'
        : hop.artifactKind === 'workflow_state_handle' ? 'async_job'
        : classifySurface(hop.endpoint ?? '/', hop.method ?? 'GET')
      try {
        ledger.addCapability({
          capId,
          kind: obs.kindOverride ?? hopKindToCapabilityKind(hop.artifactKind), promotionStatus: 'capability_only',
          provenance: hop.verified ? 'derived_hop' : 'runtime_discovery',
          tenantScope: obs.runtimeObserved ? 'runtime_observed' : 'unscoped_hypothesis',
          actorPersona: hop.persona ?? 'attacker', serviceOrigin: hop.origin, surface,
          parentHopReceiptIds: hop.verified ? [obs.safeHopId] : [],
          artifactDigest: computeArtifactDigest(`${hop.hopId}|${hop.origin}|${hop.artifactRef}`),
          artifactSummary: sanitizeCheckpointText(hop.summary, 220),
          metadata: {
            hopId: obs.safeHopId, roundNo: hop.roundNo, ...(obs.runtimeObserved ? { runtimeObserved: true } : {}),
            ...(obs.exchangeId ? { exchangeId: obs.exchangeId } : {}),
            ...(hop.endpoint ? { endpoint: hop.endpoint } : {}), ...(hop.method ? { method: hop.method } : {}),
            ...(hop.factIds[0] ? { factId: hop.factIds[0] } : {}),
            ...(obs.fieldName ? { fieldName: obs.fieldName } : {}), ...(obs.secretKind ? { secretKind: obs.secretKind } : {}), ...(obs.label ? { label: obs.label } : {}),
          },
        })
      } catch { /* ignore invalid/duplicate/secret-rejected hop mirrors */ }
    }
  }

  private approvedAsset(run: Run, origin: string): Candidate | undefined {
    return run.candidates.find(c => c.origin === origin && run.approved.includes(c.id))
  }


  static readonly BASELINE_CAPTURE_CONCURRENCY = BASELINE_CAPTURE_CONCURRENCY
  static readonly BASELINE_CAPTURE_MIN_CONCURRENCY = BASELINE_CAPTURE_MIN_CONCURRENCY
  static readonly BASELINE_CAPTURE_MAX_CONCURRENCY = BASELINE_CAPTURE_MAX_CONCURRENCY
  static readonly BASELINE_CAPTURE_TIMEOUT_MS = BASELINE_CAPTURE_TIMEOUT_MS
  static resolveBaselineCaptureConcurrency = resolveBaselineCaptureConcurrency

  async captureBaselineObservations(input: {
    run: Run
    approvedAssets: readonly Candidate[]
    claimed: Assignment
    job: Active
    grant: Grant
    secrets: readonly NamedSecret[]
    phase0RootExchanges: ReadonlyMap<string, BrokerExchangeResult>
    signal: AbortSignal
    selectedChecks: readonly AssessmentCheckId[]
    concurrency?: number
    timeoutMs?: number
  }): Promise<Record<string, unknown>[]> {
    const {
      run: freshRun,
      approvedAssets,
      claimed,
      job,
      grant,
      secrets,
      phase0RootExchanges,
      signal,
      selectedChecks,
    } = input
    const observations: Record<string, unknown>[] = []
    if (approvedAssets.length === 0) return observations

    const responseChecks = selectedChecks.filter(c => c !== 'access-policy') as ResponseCheckId[]
    const configuredConcurrency = input.concurrency !== undefined && Number.isFinite(input.concurrency)
      ? Math.max(BASELINE_CAPTURE_MIN_CONCURRENCY, Math.min(BASELINE_CAPTURE_MAX_CONCURRENCY, Math.floor(input.concurrency)))
      : resolveBaselineCaptureConcurrency()
    const concurrency = Math.max(1, Math.min(approvedAssets.length, configuredConcurrency))
    const timeoutMs = input.timeoutMs !== undefined && Number.isFinite(input.timeoutMs) && input.timeoutMs > 0
      ? Math.floor(input.timeoutMs)
      : BASELINE_CAPTURE_TIMEOUT_MS

    const selectPriorRootStmt = freshRun.sourceMode !== 'prepared' && freshRun.capabilityTier > 0
      ? this.storage.client.prepare(
          `SELECT id, origin, final_origin AS finalOrigin, status, media_type AS mediaType, resp_headers AS respHeadersJson
           FROM broker_exchanges
           WHERE run_id = ? AND origin = ? AND method = 'GET' AND path_and_query = '/'
           ORDER BY created_at ASC LIMIT 1`,
        )
      : null

    type PriorRootRow = {
      id: string
      origin: string
      finalOrigin: string
      status: number
      mediaType: string
      respHeadersJson: string
    }
    type BaselineCaptureSlot = {
      asset: Candidate
      hostWorker: Assignment
      capture: Capture
      fetchedExchange?: BrokerExchangeResult
      observationEntry?: Record<string, unknown>
      attachSavedExchangeId?: boolean
    }

    const buildObsEntry = (
      origin: string,
      row: { finalOrigin: string; status: number; mediaType: string },
      headers: Record<string, string>,
      exchangeId?: string,
    ): Record<string, unknown> => ({
      origin,
      finalOrigin: row.finalOrigin,
      status: row.status,
      mediaType: row.mediaType,
      server: headers['server'],
      poweredBy: headers['x-powered-by'],
      ...(exchangeId ? { exchangeId } : {}),
    })

    const results = new Array<BaselineCaptureSlot | undefined>(approvedAssets.length)
    let nextCommitIdx = 0

    const commitSlot = (slot: BaselineCaptureSlot) => {
      this.storage.transaction(() => {
        let savedExchangeId: string | undefined
        if (slot.fetchedExchange) {
          const savedEx = recordBrokerExchange(this.storage, freshRun, slot.hostWorker.id, slot.fetchedExchange, secrets)
          savedExchangeId = savedEx.id
        }
        if (slot.observationEntry) {
          observations.push(
            slot.attachSavedExchangeId && savedExchangeId
              ? { ...slot.observationEntry, exchangeId: savedExchangeId }
              : slot.observationEntry,
          )
        }

        const obsArtifact = this.storage.addArtifact(
          freshRun, slot.hostWorker, 'observation',
          freshRun.sourceMode === 'prepared' ? suppliedResponseLabel : 'Observed public response',
          JSON.stringify(slot.capture, null, 2), 'capture:' + freshRun.scopeRevision, secrets,
        )
        const reviews = responseChecks.length ? responseReview(slot.capture.observation, slot.capture.note, responseChecks) : []
        const inputs = [{ artifactId: obsArtifact.id, reviews }]

        if (selectedChecks.includes('access-policy')) {
          const snapshot = slot.asset.accessPolicy?.origin === slot.asset.origin ? slot.asset.accessPolicy : undefined
          const apArtifact = this.storage.addArtifact(freshRun, slot.hostWorker, 'access-policy', 'Supplied access policy records',
            JSON.stringify({ origin: slot.asset.origin, snapshot: snapshot ?? null }, null, 2), 'access-policy', secrets)
          inputs.push({ artifactId: apArtifact.id, reviews: accessPolicyReviews(snapshot) })
        }

        for (const { artifactId, reviews: revs } of inputs) {
          for (const rev of revs) {
            if (rev.comparison && !meetsBaseline(rev.comparison)) {
              const earlier = this.host.baselineFinding(freshRun, slot.asset, rev)
              this.host.saveBaselineFinding(freshRun, slot.asset, rev, 'pending',
                'The recorded value falls outside the expected policy. Verification is pending.', [artifactId], earlier?.id)
            }
          }
        }
        this.storage.updateWorker(slot.hostWorker.id, { status: 'complete', lease: null, outcome: slot.capture.note })
      })
    }

    const flushCompletedInOrder = () => {
      while (nextCommitIdx < results.length) {
        const slot = results[nextCommitIdx]
        if (!slot) break
        results[nextCommitIdx] = undefined
        nextCommitIdx += 1
        commitSlot(slot)
      }
    }

    let nextIndex = 0
    const workers = Array.from({ length: concurrency }, async () => {
      while (true) {
        if (!this.host.authorize(job) || signal.aborted) return
        const idx = nextIndex
        if (idx >= approvedAssets.length) return
        nextIndex += 1
        const asset = approvedAssets[idx]!

        const hostWorker = this.storage.makeWorker(freshRun, 'threat_model', asset,
          `Baseline capture · ${new URL(asset.origin).hostname}`,
          'Capture initial baseline response and access-policy evidence for deterministic checks.', {
            sourceOrigins: [asset.origin],
          })
        this.storage.updateWorker(hostWorker.id, { status: 'running', lease: claimed.lease })

        let capture: Capture
        let fetchedExchange: BrokerExchangeResult | undefined
        let observationEntry: Record<string, unknown> | undefined
        let attachSavedExchangeId = false

        if (freshRun.sourceMode === 'prepared' || freshRun.capabilityTier === 0) {
          capture = asset.prepared
            ? { observation: { ...asset.prepared, origin: asset.origin, finalOrigin: asset.origin, source: 'supplied observation' }, note: 'Supplied project evidence.' }
            : { observation: null, note: 'No prepared observation was supplied.' }
        } else {
          try {
            const cachedPhase0Root = phase0RootExchanges.get(asset.origin)
            const priorRootRow = !cachedPhase0Root && selectPriorRootStmt
              ? selectPriorRootStmt.get(freshRun.id, asset.origin) as PriorRootRow | undefined
              : undefined

            if (cachedPhase0Root) {
              capture = { observation: cachedPhase0Root.observation, note: 'Recorded approved HTTPS root response.' }
              observationEntry = buildObsEntry(asset.origin, cachedPhase0Root, cachedPhase0Root.respHeaders)
            } else if (priorRootRow) {
              let headersObj: Record<string, string> = {}
              try { headersObj = JSON.parse(priorRootRow.respHeadersJson) as Record<string, string> } catch { /* ignore */ }
              capture = { observation: buildObservationFromHeaders(priorRootRow, headersObj), note: 'Reused recorded approved HTTPS root response.' }
              observationEntry = buildObsEntry(asset.origin, priorRootRow, headersObj, priorRootRow.id)
            } else {
              const hostController = new AbortController()
              const onParentAbort = () => {
                hostController.abort(signal.reason ?? new DOMException('Baseline capture aborted', 'AbortError'))
              }
              if (signal.aborted) {
                onParentAbort()
              } else {
                signal.addEventListener('abort', onParentAbort, { once: true })
              }
              const hostTimer = setTimeout(() => {
                hostController.abort(new DOMException(`Baseline capture timed out after ${timeoutMs}ms`, 'TimeoutError'))
              }, timeoutMs)
              hostTimer.unref?.()
              try {
                const abortPromise = new Promise<never>((_, reject) => {
                  const rejectWithReason = () => {
                    reject(hostController.signal.reason ?? new DOMException('Baseline capture aborted', 'AbortError'))
                  }
                  if (hostController.signal.aborted) {
                    rejectWithReason()
                    return
                  }
                  hostController.signal.addEventListener('abort', rejectWithReason, { once: true })
                })
                abortPromise.catch(() => undefined)
                const fetchPromise = this.broker.executeHttp({
                  origin: asset.origin, method: 'GET', pathAndQuery: '/', followRedirects: true, timeoutMs,
                }, grant, hostController.signal)
                fetchPromise.catch(() => undefined)
                const ex = await Promise.race([fetchPromise, abortPromise])
                fetchedExchange = ex
                capture = { observation: ex.observation, note: 'Recorded approved HTTPS root response.' }
                observationEntry = buildObsEntry(asset.origin, ex, ex.respHeaders)
                attachSavedExchangeId = true
              } finally {
                clearTimeout(hostTimer)
                signal.removeEventListener('abort', onParentAbort)
              }
            }
          } catch (error) {
            capture = {
              observation: null,
              note: error instanceof BrokerDenied || error instanceof BrokerCircuitOpen
                ? error.message : 'The approved public response could not be read.',
            }
            observationEntry = { origin: asset.origin, error: capture.note }
          }
        }

        results[idx] = {
          asset,
          hostWorker,
          capture,
          fetchedExchange,
          observationEntry,
          attachSavedExchangeId,
        }
        flushCompletedInOrder()
      }
    })

    await Promise.all(workers)
    // Flush any remaining started slots in deterministic approvedAssets order if an early abort left unstarted gaps
    for (let i = nextCommitIdx; i < results.length; i += 1) {
      const slot = results[i]
      if (!slot) continue
      results[i] = undefined
      commitSlot(slot)
    }
    return observations
  }

  async runThreatModel(run: Run, profiles: readonly ResolvedModelProfile[], task: CoordinatorTask) {
    const approvedAssets = run.candidates.filter(c => run.approved.includes(c.id))
    const approvedOrigins = new Set(approvedAssets.map(a => a.origin))

    // Resolve baseline review plan if pending
    if (run.reviewPlan?.status === 'pending') {
      const available = availableReviewChecks(approvedAssets, run.sourceMode)
      let selection = standardChecks(available)
      if (approvedAssets.length && profiles.length) {
        try {
          const answer = await agentTurn({
            directory: this.storage.directory,
            sessionId: `${run.reviewPlan.goalMessageId}-plan-${run.scopeRevision}`,
            requestId: 'plan',
            profiles: resolveProfilePoolForRole('fast', profiles),
            scenario: 'coordinator-plan',
            roleAffinity: 'fast',
            thinkingLevel: 'off',
            prompt: reviewPlanPrompt(run.goal, run.sourceMode, available),
            signal: task.controller.signal,
            ...llmRunHooks(this.storage, run.id),
          })
          selection = parseReviewPlan(answer, available) ?? selection
        } catch {
          // Fall back cleanly to standard checks
        }
      }
      if (!this.host.currentCoordinator(run.id, task)) return
      this.storage.commitReviewPlan(run, selection)
    }

    let freshRun = this.storage.run(run.id)
    // Slice 3 guard input: remember whether any investigation step was already seeded BEFORE the
    // Phase-0 recon / threat-model seeding ran. A resumed or operator-seeded run skips the
    // concurrent lane (unless deterministicSweep === 'always').
    try {
      this.host.prePhase0SeededSteps.set(
        this.host.deterministicLaneKey(freshRun),
        this.storage.listChainSteps(freshRun.id, freshRun.goalRevision).length > 0,
      )
    } catch { /* guard is advisory only */ }
    const tmWorker = this.storage.makeWorker(freshRun, 'threat_model', approvedAssets[0],
      'Round-0 Threat Model & Surface Ranking',
      `Rank ${approvedAssets.length} approved hosts by attack-surface richness and seed prioritized chain investigation steps.`, {
        sourceOrigins: [...approvedOrigins],
      })
    const claimed = this.storage.updateWorker(tmWorker.id, {
      status: 'running', lease: randomUUID(), leaseExpiresAt: Date.now() + 10 * 60_000,
    })!
    const job: Active = { assignment: claimed, origins: new Set(approvedOrigins), controller: task.controller }
    this.host.active.set(claimed.id, job)

    try {
      let { grant, secrets } = this.host.buildGrant(job, freshRun, approvedOrigins)
      const specs = this.storage.listProjectSpecsFull(freshRun.projectId)
      const { reposDir, mountedRepos } = this.host.projectReposMount(freshRun.projectId)

      // 0a. Optional LabRunner boot when local-lab project has labConfig.enabled
      try {
        const project = this.storage.project(freshRun.projectId)
        if (
          project.environment === 'local-lab' &&
          project.labConfig?.enabled &&
          isLocalLabEnvEnabled() &&
          !this.host.startedLabRuns.has(freshRun.id) &&
          reposDir
        ) {
          const primaryRepoRel = mountedRepos[0] ? mountedRepos[0].replace(/^\/repos\//, '') : ''
          const primaryRepoDir = primaryRepoRel ? join(reposDir, primaryRepoRel) : reposDir
          const hasLabLaunchSpec = Boolean(
            project.labConfig.dockerComposeFile ||
            project.labConfig.dockerfile ||
            project.labConfig.image ||
            project.labConfig.startCommand ||
            (Array.isArray(project.labConfig.services) && project.labConfig.services.length > 0) ||
            (existsSync(primaryRepoDir) && existsSync(join(primaryRepoDir, 'Dockerfile'))),
          )
          if (existsSync(primaryRepoDir) && hasLabLaunchSpec) {
            const handle = await this.labRunner.startLabTarget({
              runId: freshRun.id,
              environment: project.environment,
              repoDir: primaryRepoDir,
              labConfig: project.labConfig,
              storage: this.storage,
              projectId: project.id,
              ...(project.labConfig.iastEnabled ? { telemetryDir: join(this.storage.directory, 'evidence', 'lab-telemetry') } : {}),
              signal: task.controller.signal,
            })
            this.host.startedLabRuns.add(freshRun.id)
            this.host.startedLabHandles.set(freshRun.id, handle)
            this.storage.event(
              freshRun.id,
              'lab.started',
              `Local lab target booted at ${handle.origin}.`,
              {
                origin: handle.origin,
                baseUrls: handle.baseUrls,
                containerName: handle.containerName,
                seededPersonas: handle.seededPersonas.map(p => p.handle),
              },
            )
            // Expose the booted local-lab origin & any seeded personas into the run scope via canonical admission
            let scopeChanged = false
            if (!approvedOrigins.has(handle.origin)) {
              const admitRes = this.storage.runsRepo.admitDynamicOrigin({
                runId: freshRun.id,
                origin: handle.origin,
                source: 'lab_runner',
                thirdParty: false,
                reason: 'lab_runner_boot',
              })
              if (admitRes.admitted) {
                approvedOrigins.add(handle.origin)
                job.origins.add(handle.origin)
                scopeChanged = true
              }
            }
            const seededPersonaIds = handle.seededPersonas
              .map(p => p.personaId)
              .filter((id): id is string => typeof id === 'string' && id.length > 0)
            if (seededPersonaIds.length > 0) {
              const latestForPersonas = this.storage.run(freshRun.id)
              const mergedPersonas = [...new Set([...latestForPersonas.approvedPersonaIds, ...seededPersonaIds])]
              if (mergedPersonas.length !== latestForPersonas.approvedPersonaIds.length) {
                this.storage.updateRun(freshRun.id, { approvedPersonaIds: mergedPersonas })
                scopeChanged = true
              }
            }
            if (scopeChanged) {
              freshRun = this.storage.run(freshRun.id)
              const refreshed = this.host.buildGrant(job, freshRun, approvedOrigins)
              grant = refreshed.grant
              secrets = refreshed.secrets
            }
          }
        }
      } catch {
        // Best-effort lab boot; proceed cleanly if target is externally managed
      }

      // 0b. Persist initial dynamic step budget from pre-existing endpoints + suspects
      this.storage.updateRunDynamicStepBudget(freshRun.id, computeDynamicStepBudget(this.storage, freshRun.id))

      // 0c. Zero-LLM Phase-0 deterministic surface mapper (runs before LLM Turn 1)
      const phase0RootExchanges = new Map<string, BrokerExchangeResult>()
      if (!freshRun.phase0CompletedAt && approvedOrigins.size > 0 && this.host.authorize(job)) {
        // Passive CT-log + live DNS subdomain discovery for public HTTPS origins only (skipped for local-lab/localhost, shared-PaaS, SaaS, and third-party CNAME hosts).
        if (
          freshRun.sourceMode !== 'prepared' &&
          freshRun.capabilityTier > 0 &&
          this.storage.project(freshRun.projectId).environment === 'public'
        ) {
          try {
            const discoverableOrigins = [...approvedOrigins].filter(origin => {
              if (isSharedPaasOrigin(origin) || isMultiTenantSaasOrigin(origin)) return false
              if (extractDiscoverableApex(origin) === null) return false
              const asset = approvedAssets.find(a => a.origin === origin)
              if (asset && (asset.thirdParty || (asset.dnsSource?.externalAliases?.length ?? 0) > 0)) return false
              return true
            })
            if (discoverableOrigins.length > 0) {
              const subResult = await discoverSubdomainsForOrigins(discoverableOrigins, {
                signal: task.controller.signal,
              })
              if (subResult.queriedApexes.length > 0) {
                const applied = applyDiscoveredSubdomainsToRun(this.storage, freshRun.id, subResult, approvedOrigins)
                if (applied.admitted.length > 0) {
                  for (const cand of applied.admitted) {
                    if (isSharedPaasOrigin(cand.origin) || isMultiTenantSaasOrigin(cand.origin)) continue
                    job.origins.add(cand.origin)
                    if (!approvedAssets.some(a => a.origin === cand.origin)) {
                      approvedAssets.push(cand)
                    }
                  }
                  freshRun = this.storage.run(freshRun.id)
                  const refreshed = this.host.buildGrant(job, freshRun, approvedOrigins)
                  grant = refreshed.grant
                  secrets = refreshed.secrets
                }
              }
            }
          } catch {
            // Passive CT discovery must never fail or block Phase-0
          }
        }
        try {
          const phase0Browser = freshRun.capabilityTier >= 2 ? this.browser : undefined
          if (!phase0Browser) {
            const firstOrigin = [...approvedOrigins][0] ?? 'run'
            this.emitPreconditionUnmet(freshRun.id, {
              dedupeKey: `phase0:browser:${freshRun.capabilityTier}`,
              origin: firstOrigin,
              precondition: freshRun.capabilityTier < 2 ? 'tier' : 'browser',
              vulnClass: 'dom-xss',
              required: freshRun.capabilityTier < 2 ? 'tier>=2' : 'browser_available',
              observed: freshRun.capabilityTier < 2 ? `tier=${freshRun.capabilityTier}` : 'browser=unavailable',
              method: 'GET',
              route: '*',
              skippedCount: Math.max(1, approvedOrigins.size),
              source: 'planner.phase0_browser_crawl',
            })
          }
          const reconResult = await runPhase0Recon({
            storage: this.storage,
            runId: freshRun.id,
            scopeRevision: freshRun.scopeRevision,
            tier: freshRun.capabilityTier,
            origins: [...approvedOrigins],
            budgetRequests: freshRun.budgetRequests,
            reposDir,
            personas: sortPersonasLowPrivFirst([...(grant.personas?.values() ?? [])]).map(p => p.handle),
            broker: this.broker,
            browser: phase0Browser,
            canaryBroker: this.canaryBroker,
            grant,
            signal: task.controller.signal,
            assignmentId: claimed.id,
            onExchange: ex => {
              if (ex.method === 'GET' && ex.pathAndQuery === '/' && !phase0RootExchanges.has(ex.origin)) {
                phase0RootExchanges.set(ex.origin, ex)
              }
              return recordBrokerExchange(this.storage, freshRun, claimed.id, ex, secrets).id
            },
          }) as Awaited<ReturnType<typeof runPhase0Recon>> & Phase0GraphwireExtras & {
            edgeProtectedOrigins?: DetectQuarantinedOriginsInput['edgeProtectedOrigins']
          }
          // v6 graphwire: the ranked plan bounds probe breadth without trimming the store, and
          // AST code→runtime hypotheses become prioritized leads for the floor/agentic lane.
          this.host.probePlans.record(this.storage, freshRun.id, reconResult.probePlan)
          this.host.seedCodeToRuntimeLeads(this.storage.run(freshRun.id), claimed, reconResult.codeToRuntimeHypotheses ?? [])
          if (reconResult.repoStaticExtraction?.originMappings?.length) {
            this.repoOriginMappingsByRun.set(freshRun.id, reconResult.repoStaticExtraction.originMappings)
          }
          this.refreshQuarantinedOriginsFromPhase0(this.storage.run(freshRun.id), {
            approvedOrigins,
            edgeProtectedOrigins: reconResult.edgeProtectedOrigins,
            skippedDeadHosts: reconResult.skippedDeadHosts,
            extraExchanges: [...phase0RootExchanges.values()].map(ex => ({
              origin: ex.origin,
              status: ex.status,
              pathAndQuery: ex.pathAndQuery,
            })),
            assignmentId: claimed.id,
          })
          this.storage.updateRunDynamicStepBudget(freshRun.id, computeDynamicStepBudget(this.storage, freshRun.id))
        } catch {
          // Phase-0 failure must not block threat model progression
        }
      }

      // Phase-0 boundary: capture the deterministic surface before the LLM threat model. Resuming
      // here is valid (the threat model simply re-runs from the saved discovery state).
      if (this.storage.run(freshRun.id).phase0CompletedAt) {
        this.host.notifyCheckpoint(freshRun.id, 'phase0')
      }

      // 1. Correlate dependencies from uploaded/synced specs via CVE broker
      await this.host.correlateSpecDependencies(freshRun, claimed, specs, approvedOrigins, approvedAssets[0]?.origin, task.controller.signal, secrets)

      // 1b. v8 M2 General Invariant Synthesis (white-box mounted source OR grey-box/black-box runtime parity)
      //     Seeds SQLite WAL CapabilityLedger with strictly quarantined `capability_only` hypotheses
      //     and promotes high-signal cross-surface / cross-service / lifecycle hypotheses into ready Wave-1 chain steps.
      try {
        await this.seedCapabilityLedgerInvariants(this.storage.run(freshRun.id), {
          reposDir,
          mountedRepos,
          specs,
          approvedOrigins,
          promoteWave1Chains: freshRun.capabilityTier > 0 && profiles.length > 0,
          signal: task.controller.signal,
        })
      } catch {
        // Additive Layer-2 synthesis must never block threat model progression
      }

      // 2. Capture initial lightweight baseline observations for approved hosts (bounded concurrent pool)
      const selectedChecks: readonly AssessmentCheckId[] = freshRun.reviewPlan?.status === 'ready'
        ? freshRun.reviewPlan.checks : responseCheckIds
      const observations = await this.captureBaselineObservations({
        run: freshRun,
        approvedAssets,
        claimed,
        job,
        grant,
        secrets,
        phase0RootExchanges,
        signal: task.controller.signal,
        selectedChecks,
      })
      const baselineTelemetry = observations
        .map(obs => {
          const origin = typeof obs.origin === 'string' ? obs.origin : ''
          if (!origin) return null
          const status = typeof obs.status === 'number' ? obs.status : null
          const error = typeof obs.error === 'string' ? obs.error : null
          return { origin, status, error, pathAndQuery: '/' }
        })
        .filter((entry): entry is NonNullable<typeof entry> => entry !== null)
      this.refreshQuarantinedOriginsFromPhase0(freshRun, {
        approvedOrigins,
        extraExchanges: baselineTelemetry,
        assignmentId: claimed.id,
      })
      const quarantinedOrigins = this.getQuarantinedOriginSet(freshRun, approvedOrigins)
      const activeOrigins = this.activeApprovedOrigins(freshRun, approvedOrigins)

      // 3. Build prioritized Threat Model via LLM (with deterministic fallback)
      const heuristicEntries = approvedAssets.map(classifyHostHeuristic)
      const riskOrder = { critical: 0, high: 1, medium: 2, low: 3 }
      heuristicEntries.sort((a, b) =>
        hostTierOrder[classifyHostTier(a.origin, a.surfaceTags)] - hostTierOrder[classifyHostTier(b.origin, b.surfaceTags)] ||
        riskOrder[a.riskTier] - riskOrder[b.riskTier],
      )
      const initialHostTiers = computeHostTiers([...approvedOrigins], heuristicEntries)

      let finalEntries = heuristicEntries
      let tmSummary = `Ranked ${heuristicEntries.length} approved hosts by attack surface.`
      let seededSteps: Array<{
        title: string
        hypothesis: string
        category: string
        priority: number
        origins: string[]
        skills: string[]
      }> = []

      if (profiles.length && freshRun.capabilityTier > 0 && approvedAssets.length > 0) {
        try {
          const personasPub = publicPersonasFromGrant(grant)
          const graphCatalog = this.host.endpointGraphCatalog(freshRun.id)
          const answer = await agentTurn({
            directory: this.storage.directory,
            sessionId: `tm-${freshRun.id}-${freshRun.goalRevision}-${freshRun.scopeRevision}`,
            requestId: 'threat-model',
            profiles: resolveProfilePoolForRole('tactical', profiles),
            scenario: 'threat-model',
            roleAffinity: 'tactical',
            prompt: threatModelPrompt({
              goal: freshRun.goal,
              capabilityTier: freshRun.capabilityTier,
              approvedOrigins: [...approvedOrigins],
              hostTiers: initialHostTiers,
              personas: personasPub,
              specs: specs.slice(0, 12).map(s => ({
                name: s.name, kind: s.kind, origin: s.origin, preview: s.content.slice(0, 1200),
              })),
              mountedRepos,
              observations: [
                ...observations.slice(0, 38),
                ...(graphCatalog.endpointParams.length || graphCatalog.apiDependencies.length
                  ? [{
                      kind: 'endpoint_graph_catalog',
                      endpointParams: graphCatalog.endpointParams.slice(0, 80),
                      apiDependencies: graphCatalog.apiDependencies.slice(0, 40),
                      note: 'Persisted endpoint_params (injectable locations/CSRF/object-id flags) and producer→consumer api_dependencies harvested from Phase-0, crawl and worker exchanges. Prioritize ID-bearing consumer routes and CSRF-bound write paths.',
                    }]
                  : []),
              ],
            }),
            signal: task.controller.signal,
            secrets,
            ...llmRunHooks(this.storage, freshRun.id),
          })
          const parsed = threatModelResponseSchema.safeParse(JSON.parse(stripJsonFences(answer)))
          if (parsed.success) {
            tmSummary = parsed.data.summary
            const validEntries: ThreatModelSummary[] = parsed.data.entries
              .filter(e => approvedOrigins.has(e.origin))
              .map(e => {
                const tags = [...new Set(e.surfaceTags)]
                const tier = e.hostTier ?? classifyHostTier(e.origin, tags)
                if (tier === 'crown_jewel' && !tags.includes('crown_jewel')) tags.unshift('crown_jewel')
                if (tier === 'low_value_static' && !tags.includes('low_value_static')) tags.push('low_value_static')
                return { origin: e.origin, riskTier: e.riskTier, surfaceTags: tags, rationale: e.rationale }
              })
            if (validEntries.length) {
              const seen = new Set(validEntries.map(e => e.origin))
              finalEntries = [
                ...validEntries,
                ...heuristicEntries.filter(h => !seen.has(h.origin)),
              ].sort((a, b) =>
                hostTierOrder[classifyHostTier(a.origin, a.surfaceTags)] - hostTierOrder[classifyHostTier(b.origin, b.surfaceTags)] ||
                riskOrder[a.riskTier] - riskOrder[b.riskTier],
              )
            }
            seededSteps = parsed.data.initialSteps.filter(s => s.origins.some(o => approvedOrigins.has(o)))
          }
        } catch {
          // Deterministic heuristic fallback guarantees progress even if LLM response isn't valid JSON
        }
      }

      if (!this.host.authorize(job)) return

      const finalHostTiers = computeHostTiers([...approvedOrigins], finalEntries)

      // Save Threat Model before Source-First Code Audit so audit & planner see ranked hosts
      const savedTm = this.storage.transaction(() => {
        const current = this.storage.run(freshRun.id)
        if (current.status !== 'running' || current.phase !== 'threat_model') return null
        const tm = this.storage.saveThreatModel(current, finalEntries, tmSummary)
        const tmArtifact = this.storage.addArtifact(current, claimed, 'threat-model', 'Round-0 Threat Model',
          JSON.stringify({ threatModelId: tm.id, summary: tmSummary, entries: finalEntries, hostTiers: finalHostTiers }, null, 2), 'threat-model', secrets)
        return { tm, tmArtifact }
      }, { behavior: 'immediate' })
      if (!savedTm) return

      // 4. Priority #1 (v7 M2 white-box-first default): Dedicated Source-First Code Audit +
      // Program-Graph Tier-A AST/RBAC/dataflow seeding BEFORE live black-box HTTP steps.
      const sourceMounted = mountedRepos.length > 0
      let codeAuditStepsCreated = 0
      if (sourceMounted && freshRun.capabilityTier > 0 && profiles.length > 0 && this.host.authorize(job)) {
        const reportSettlement = (id: string, kind: string, msg: string, detail?: Record<string, unknown>) => { this.storage.event(id, kind, msg, detail) }
        const auditRes = await settleOrReportAsync(
          freshRun.id,
          'code_audit.run',
          () => this.host.runSourceFirstCodeAudit(
            this.storage.run(freshRun.id),
            finalEntries,
            profiles,
            task.controller.signal,
          ),
          reportSettlement,
        )
        if (auditRes.ok && auditRes.value) codeAuditStepsCreated = auditRes.value.stepsCreated.length
        const tierARes = settleOrReport(
          freshRun.id,
          'code_audit.tier_a_seed',
          () => this.queueTierALeadSteps(
            this.storage.run(freshRun.id), approvedOrigins, computeDynamicStepBudget(this.storage, freshRun.id), { sourceMounted: true },
          ),
          reportSettlement,
        )
        if (tierARes.ok && tierARes.value) codeAuditStepsCreated += tierARes.value
      }

      if (!this.host.authorize(job)) return

      // Ensure every reachable approved origin with discovered endpoints gets Wave-1 coverage
      // even when codeAuditStepsCreated > 0 or LLM threat model only seeded a subset of origins.
      // Fallback steps include reachable sibling origins and stay capped below white-box leads.
      const reachableFinalEntries = finalEntries.filter(entry => activeOrigins.has(entry.origin))
      const preFallbackSteps = this.storage.listChainSteps(freshRun.id, freshRun.goalRevision)
      const discoveredEndpointOrigins = new Set(this.storage.listEndpoints(freshRun.id, { limit: 250 })
        .filter(ep => activeOrigins.has(ep.origin)).map(ep => ep.origin))
      const fallbackResult = buildWave1UncoveredOriginFallbackSteps({
        reachableFinalEntries,
        seededSteps,
        existingSteps: preFallbackSteps,
        discoveredEndpointOrigins,
        finalHostTiers,
        sourceMounted,
        codeAuditStepsCreated,
        capabilityTier: freshRun.capabilityTier,
        whiteBoxCapPriority: WHITEBOX_BLACKBOX_CAP_PRIORITY,
        classifyTier: classifyHostTier,
        storage: this.storage,
        run: freshRun,
        activeOrigins,
      })
      seededSteps = fallbackResult.seededSteps
      const uncoveredFallbackSlots = fallbackResult.uncoveredAddedCount

      const prioritizedInitialSteps = prioritizeMountedSourceInitialSteps(
        seededSteps
          .map(step => ({ ...step, origins: step.origins.filter(o => activeOrigins.has(o)) }))
          .filter(step => step.origins.length > 0),
        { sourceMounted, hasWhiteBoxSteps: codeAuditStepsCreated > 0, whiteBoxFactIds: this.host.tierAFactIds },
      )

      this.storage.transaction(() => {
        const current = this.storage.run(freshRun.id)
        if (current.status !== 'running' || current.phase !== 'threat_model') return

        const existingSteps = this.storage.listChainSteps(current.id, current.goalRevision)
        const remainingInitialSlots = Math.max(uncoveredFallbackSlots, 12 - existingSteps.length)
        const budgetedSteps = applyCrownJewelStepBudget(
          prioritizedInitialSteps,
          finalHostTiers,
          existingSteps,
          remainingInitialSlots,
          { quarantinedOrigins },
        )

        let addedInitial = 0
        for (const step of budgetedSteps) {
          const validOrigins = step.origins.filter(o => activeOrigins.has(o))
          const assetIds = current.candidates.filter(c => validOrigins.includes(c.origin) && current.approved.includes(c.id)).map(c => c.id)
          if (!assetIds.length) continue
          const specialistProfile = routeStepToSpecialist({
            title: step.title,
            hypothesis: step.hypothesis,
            category: step.category,
            skills: step.skills,
          })
          this.storage.addChainStep(current, {
            title: step.title,
            hypothesis: step.hypothesis,
            category: step.category,
            priority: step.priority,
            targetAssetIds: assetIds,
            skills: step.skills,
            sourceOrigins: validOrigins,
            specialistProfile,
          })
          addedInitial += 1
        }
        this.host.expandEligibleMultiTrialSteps(current)
        this.storage.updateRunDynamicStepBudget(current.id, computeDynamicStepBudget(this.storage, current.id))

        const totalQueued = codeAuditStepsCreated + addedInitial
        this.host.completeWorker(claimed, current, tmSummary, [savedTm.tmArtifact.id], undefined, secrets)
        const deterministicMode = !profiles.length && current.capabilityTier > 0
        const nextPhase = current.capabilityTier === 0 ? 'verification' : 'investigation'
        this.storage.updateRun(current.id, { phase: nextPhase })
        this.storage.event(current.id, `${nextPhase}.started`,
          nextPhase === 'investigation'
            ? deterministicMode
              ? 'Threat model complete (no model profile configured). Starting bounded deterministic differential probing.'
              : `Threat model complete${codeAuditStepsCreated ? ` (${codeAuditStepsCreated} source-audit steps + ${addedInitial} initial steps)` : ` (${totalQueued} initial steps)`}. Starting closed-loop chain investigation.`
            : 'Baseline captures complete. Starting deterministic Zero-LLM verification.')
        this.storage.message(current.id, current.coordinatorId, 'kovo',
          nextPhase === 'investigation'
            ? deterministicMode
              ? `Threat model ranked ${finalEntries.length} hosts. No model profile is configured, so Kovo will run a bounded deterministic probe pass over discovered endpoints instead of agentic investigation.`
              : `Threat model ranked ${finalEntries.length} hosts and queued ${totalQueued} initial investigation steps${codeAuditStepsCreated ? ` (including ${codeAuditStepsCreated} from Source-First Code Audit)` : ''}.`
            : 'Baseline capture complete. Deterministic verification is checking the recorded evidence.')
      }, { behavior: 'immediate' })

      // Post-floor boundary: Phase-0 + threat model + deterministic lane are complete and the
      // first agentic assignment has not started yet. This is the primary resume checkpoint.
      const afterFloor = this.storage.run(freshRun.id)
      if (afterFloor.status === 'running' && afterFloor.phase === 'investigation') {
        this.host.notifyCheckpoint(afterFloor.id, 'post-floor')
      } else if (afterFloor.status === 'running' && afterFloor.phase === 'verification') {
        this.host.notifyCheckpoint(afterFloor.id, 'deterministic-lane')
      }
    } finally {
      this.host.active.delete(claimed.id)
    }
  }


  async runPostConfirmationVariantSweep(
    run: Run,
    findingRow: typeof findings.$inferSelect,
    reposDir: string,
    mountedRepos: readonly string[],
  ) {
    const locs = findingRow.finding.codeLocations ?? []
    const primaryLoc = locs[0]
    if (!primaryLoc) return

    const approvedOrigins = this.host.approvedOriginsSet(run)
    const targetOrigin = approvedOrigins.has(findingRow.finding.origin)
      ? findingRow.finding.origin
      : [...approvedOrigins][0]
    if (!targetOrigin) return
    const asset = this.approvedAsset(run, targetOrigin) ?? run.candidates.find(c => run.approved.includes(c.id))
    if (!asset) return

    // 1. Fast deterministic sibling pattern sweep over mounted /repos (matches static_ast_proof ruleOrPattern or primary call signature)
    const searchTokens: string[] = []
    if (findingRow.replaySpecId) {
      try {
        const sp = this.storage.getReplaySpec(run.id, findingRow.replaySpecId)
        if (sp.spec.kind === 'static_ast_proof' && sp.spec.ruleOrPattern.trim()) {
          searchTokens.push(sp.spec.ruleOrPattern.trim())
        }
      } catch { /* ignore */ }
    }
    const safePrimary = resolveSafeVariantSweepLocation(
      reposDir,
      primaryLoc.repo,
      primaryLoc.file,
      mountedRepos,
      VARIANT_SWEEP_MAX_FILE_BYTES,
    )
    if (safePrimary) {
      try {
        const lines = readFileSync(safePrimary.realPath, 'utf8').split('\n')
        const lineText = lines[Math.max(0, primaryLoc.startLine - 1)] ?? ''
        const callSig = /[A-Za-z_$][A-Za-z0-9_$]*\.[A-Za-z_$][A-Za-z0-9_$]*\s*\([^)]*\)/.exec(lineText)
        if (callSig && !searchTokens.includes(callSig[0])) searchTokens.push(callSig[0])
      } catch { /* ignore */ }
    }

    const siblingHits = collectVariantSweepSiblingHits(reposDir, mountedRepos, searchTokens, locs)
    const seenHit = new Set<string>(siblingHits.map(h => `${h.repo}:${h.file}:${h.line}`))

    // 2. Also invoke runVariantSweepForFinding (semantic-audit.ts) when no direct deterministic sibling hits were found
    if (siblingHits.length === 0) {
      try {
        const currentRun = this.storage.run(run.id)
        const profiles = privateModelProfiles(this.storage)
        const sweepRes = await runVariantSweepForFinding({
          storage: this.storage,
          run: currentRun,
          backend: this.backend,
          reposDir,
          mountedRepos,
          approvedOrigins: [...approvedOrigins],
          modelProfiles: resolveProfilePoolForRole('reasoning', profiles),
          signal: AbortSignal.timeout(15_000),
        }, {
          finding: findingRow.finding,
          mountedRepos,
        })
        for (const s of sweepRes.newSuspects) {
          const key = `${s.repo}:${s.file}:${s.line}`
          if (seenHit.has(key)) continue
          seenHit.add(key)
          siblingHits.push({ repo: s.repo, file: s.file, line: s.line, preview: s.hypothesis.slice(0, 180) })
        }
      } catch { /* best-effort */ }
    }

    if (siblingHits.length === 0) return

    const currentRun = this.storage.run(run.id)
    const existingSteps = this.storage.listChainSteps(currentRun.id, currentRun.goalRevision)
    const existingTitles = new Set(existingSteps.map(s => s.title.trim().toLowerCase()))
    for (const hit of siblingHits.slice(0, 12)) {
      const title = `Variant sweep · ${hit.file}:${hit.line} (sibling of ${findingRow.finding.title.slice(0, 60)})`
      if (existingTitles.has(title.toLowerCase())) continue
      const specialistProfile = routeStepToSpecialist({
        title: `${title} ${findingRow.finding.title}`,
        hypothesis: hit.preview,
        category: findingRow.finding.category,
      })
      this.storage.addChainStep(currentRun, {
        title,
        hypothesis: `Post-confirmation Variant Sweep matched sibling pattern of confirmed finding ${findingRow.id} (${findingRow.finding.title}) at ${hit.repo}/${hit.file}:${hit.line}: ${hit.preview}`,
        category: findingRow.finding.category ?? 'broken-access-control',
        priority: 92,
        targetAssetIds: [asset.id],
        skills: ['source-first-audit', 'bola-idor-race', 'false-positive-elimination'],
        sourceOrigins: [targetOrigin],
        specialistProfile,
      })
      existingTitles.add(title.toLowerCase())
    }
    this.storage.event(
      currentRun.id,
      'variant_sweep.complete',
      `Variant sweep for finding "${findingRow.finding.title}" discovered ${siblingHits.length} sibling target(s).`,
      { findingId: findingRow.id, siblingsFound: siblingHits.length },
    )
  }


  // --- Slice 3 / agentic value-add: read-only prompt context builders ---
  /** Confirmed + static-verified (endpoint, method, param, cwe) refs. Prompt context only. */
  alreadyConfirmedRefs(run: Run, limit = 30): PlannerConfirmedRef[] {
    try {
      const rows = this.storage.db.select().from(findings).where(and(
        eq(findings.runId, run.id),
        eq(findings.goalRevision, run.goalRevision),
      )).all()
      const specById = new Map(this.storage.listReplaySpecs(run.id).map(spec => [spec.id, spec]))
      const refs: PlannerConfirmedRef[] = []
      const refIndexByKey = new Map<string, number>()
      const pushRef = (ref: PlannerConfirmedRef): void => {
        const normPath = normalizeConfirmedRouteTemplate(ref.path)
        if (!normPath) return
        const key = `${ref.origin ?? ''} ${ref.method ?? ''} ${normPath} ${ref.param ?? ''} ${ref.cwe ?? ''} ${ref.probeClass ?? ''}`
        const existingIdx = refIndexByKey.get(key)
        if (existingIdx !== undefined) {
          if (ref.hasCompositeReceipt && !refs[existingIdx]!.hasCompositeReceipt) {
            refs[existingIdx] = { ...refs[existingIdx]!, hasCompositeReceipt: true }
          }
          return
        }
        if (refs.length >= limit) return
        refIndexByKey.set(key, refs.length)
        refs.push(ref)
      }
      for (const row of rows) {
        if (row.finding.status !== 'confirmed' && row.finding.status !== 'static_verified') continue
        const spec = row.replaySpecId ? specById.get(row.replaySpecId) : undefined
        const fields = spec ? extractSpecDedupeFields(spec.spec) : null
        const proofReceiptObj = spec?.proofReceipt && typeof spec.proofReceipt === 'object'
          ? spec.proofReceipt as unknown as Record<string, unknown>
          : undefined
        const findingEvidence = (row.finding as Finding & { evidence?: Record<string, unknown> }).evidence
        const compReceiptObj = (proofReceiptObj?.compositeReceipt ?? findingEvidence?.compositeReceipt) as Record<string, unknown> | undefined
        const compVerified = Boolean(compReceiptObj && typeof compReceiptObj === 'object')
          && isCompositeVerificationConfirmed(proofReceiptObj, findingEvidence, compReceiptObj)
        const receiptTarget = spec?.proofReceipt?.receipt?.target
        const rawPath = (fields?.endpoint?.trim() && fields.endpoint.trim() !== '/')
          ? fields.endpoint.trim()
          : (receiptTarget?.pathAndQuery?.trim() ?? fields?.endpoint?.trim() ?? '')
        const path = rawPath.trim()
        if (path) {
          const rawMethod = (fields?.method && fields.method !== 'ANY')
            ? fields.method
            : (receiptTarget?.method?.trim() ?? null)
          const method = rawMethod && rawMethod !== 'ANY' ? rawMethod.toUpperCase() : null
          pushRef({
            origin: row.finding.origin,
            ...(method ? { method } : {}),
            path,
            ...(fields?.param ? { param: fields.param } : {}),
            ...(row.finding.cwe ? { cwe: row.finding.cwe } : {}),
            ...(row.finding.category ? { probeClass: row.finding.category } : {}),
            ...(compVerified ? { hasCompositeReceipt: true } : {}),
          })
        }
        if (compVerified && compReceiptObj) {
          const terminalVulnClass = typeof compReceiptObj.terminalVulnClass === 'string' && compReceiptObj.terminalVulnClass.trim()
            ? compReceiptObj.terminalVulnClass.trim()
            : undefined
          const compProbeClass = row.finding.category || terminalVulnClass
          const hops = Array.isArray(compReceiptObj.hops) ? compReceiptObj.hops as Array<Record<string, unknown>> : []
          let terminalOrigin = row.finding.origin
          const terminalHopId = typeof (compReceiptObj.terminalImpact as Record<string, unknown> | undefined)?.terminalHopId === 'string'
            ? String((compReceiptObj.terminalImpact as Record<string, unknown>).terminalHopId)
            : null
          for (const hop of hops) {
            if (!hop || typeof hop !== 'object') continue
            const target = hop.target && typeof hop.target === 'object' ? hop.target as Record<string, unknown> : undefined
            const hopOrigin = typeof target?.origin === 'string' && target.origin.trim()
              ? target.origin.trim()
              : row.finding.origin
            if (terminalHopId && hop.hopId === terminalHopId) {
              terminalOrigin = hopOrigin
            }
            const hopPath = typeof target?.pathAndQuery === 'string' ? target.pathAndQuery.trim() : ''
            if (!hopPath) continue
            const hopRawMethod = typeof target?.method === 'string' ? target.method.trim().toUpperCase() : ''
            const hopMethod = hopRawMethod && hopRawMethod !== 'ANY' ? hopRawMethod : null
            const hopParam = typeof target?.param === 'string' && target.param.trim() ? target.param.trim() : null
            pushRef({
              origin: hopOrigin,
              ...(hopMethod ? { method: hopMethod } : {}),
              path: hopPath,
              ...(hopParam ? { param: hopParam } : {}),
              ...(row.finding.cwe ? { cwe: row.finding.cwe } : {}),
              ...(compProbeClass ? { probeClass: compProbeClass } : {}),
              hasCompositeReceipt: true,
            })
          }
          const compVer = (
            proofReceiptObj?.compositeVerification
            ?? findingEvidence?.compositeVerification
            ?? compReceiptObj.verification
          ) as Record<string, unknown> | undefined
          const parsedTerminal = parseTerminalEndpointCandidate(compVer?.terminalEndpoint ?? findingEvidence?.terminalEndpoint)
          if (parsedTerminal) {
            pushRef({
              origin: terminalOrigin,
              ...(parsedTerminal.method ? { method: parsedTerminal.method } : {}),
              path: parsedTerminal.path,
              ...(row.finding.cwe ? { cwe: row.finding.cwe } : {}),
              ...(compProbeClass ? { probeClass: compProbeClass } : {}),
              hasCompositeReceipt: true,
            })
          }
        }
        if (refs.length >= limit) break
      }
      return refs
    } catch {
      return []
    }
  }


  /** High-risk or under-covered surface that has not been confirmed. Prompt context only. */
  unconfirmedHardSurfaceRefs(run: Run, confirmed: readonly AlreadyConfirmedRef[], limit = 8): UnconfirmedSurfaceRef[] {
    try {
      const confirmedSets = buildConfirmedRouteSets(confirmed)
      const refs: UnconfirmedSurfaceRef[] = []
      const seen = new Set<string>()
      for (const gap of this.storage.listOpenProofGaps(run.id, run.goalRevision)) {
        const key = `${gap.category} ${gap.origin} ${gap.summary.slice(0, 40)}`
        if (seen.has(key)) continue
        seen.add(key)
        refs.push({
          path: `${gap.origin} ${gap.category}`,
          category: gap.category,
          reason: gap.proofGapReason || gap.summary,
        })
        if (refs.length >= limit) break
      }
      if (refs.length < limit) {
        const endpoints = this.storage.listEndpoints(run.id, { orderBy: 'risk', limit: 40 })
        for (const ep of endpoints) {
          if (refs.length >= limit) break
          if (isRouteConfirmed({ method: ep.method, path: ep.pathTemplate }, confirmedSets, { matchAnyMethod: true })) continue
          if (ep.riskScore < 60) continue
          const key = `${ep.method} ${ep.pathTemplate}`
          if (seen.has(key)) continue
          seen.add(key)
          refs.push({
            method: ep.method,
            path: ep.pathTemplate,
            category: ep.testedClasses?.[0] ?? null,
            reason: `risk ${ep.riskScore}, coverage ${ep.coveragePct ?? 0}%`,
          })
        }
      }
      return refs
    } catch {
      return []
    }
  }


  /** All deterministic lead facts for the run (not only parent-fact dependencies). */
  detLeadSummaries(run: Run): DetLeadSummary[] {
    try {
      const facts = this.pageAll((offset, limit) =>
        this.storage.listFacts(run.id, { includeTainted: false, limit, offset }))
        .filter(f => isTrustedHostControlFact(f, 'det_lead'))
      return detLeadsFromParentFacts(facts)
    } catch {
      return []
    }
  }


  /** Legacy helper retained for `execution.ts` compatibility; prefers structured step targets. */
  stepMentionedRoutes(step: Pick<ChainStep, 'title' | 'hypothesis'> & { id?: string }): string[] {
    if (step.id) {
      const structured = this.structuredStepTargets.get(step.id)
      if (structured && structured.length > 0) {
        return [...new Set(structured.map(t => normalizeConfirmedRouteTemplate(t.route)).filter(Boolean))]
      }
    }
    return [...new Set(templatesMentionedInText(`${step.title} ${step.hypothesis}`).map(normalizeConfirmedRouteTemplate))]
  }

  /** Assignments in `runId` that achieved a proved finding or a coded proof-gap / settled coverage verdict. */
  private provedOrGapCodedAssignmentIds(runId: string): Set<string> {
    const covered = new Set<string>()
    const activeConfirmedFindingIds = new Set<string>()
    const inactiveFindingIds = new Set<string>()
    try {
      const findingRows = this.storage.db.select({
        id: findings.id,
        supersededByFindingId: findings.supersededByFindingId,
        finding: findings.finding,
      })
        .from(findings)
        .where(eq(findings.runId, runId))
        .all()
      for (const row of findingRows) {
        const triageStatus = (row.finding as Finding & { operatorTriage?: { status?: string } }).operatorTriage?.status
        const isInactive = Boolean(row.supersededByFindingId || row.finding.supersededByFindingId)
          || row.finding.status === 'dismissed'
          || triageStatus === 'false_positive'
        if (isInactive) {
          inactiveFindingIds.add(row.id)
        } else if (row.finding.status === 'confirmed') {
          activeConfirmedFindingIds.add(row.id)
        }
      }
      if (activeConfirmedFindingIds.size > 0) {
        for (const spec of this.storage.listReplaySpecs(runId)) {
          if (activeConfirmedFindingIds.has(spec.findingId) && spec.assignmentId) {
            covered.add(spec.assignmentId)
          }
        }
      }
    } catch (err) {
      this.noteLifecycleWarning(runId, 'provedOrGapCodedAssignmentIds.findings', err)
    }
    try {
      const rows = this.storage.db.select({
        assignmentId: coverageEntries.assignmentId,
        origin: coverageEntries.origin,
        status: coverageEntries.status,
        summary: coverageEntries.summary,
        enforcingControl: coverageEntries.enforcingControl,
        proofGapReason: coverageEntries.proofGapReason,
        linkedFindingId: coverageEntries.linkedFindingId,
      })
        .from(coverageEntries)
        .where(eq(coverageEntries.runId, runId))
        .all()

      // Batch-verify all exchangeIds embedded in coverage rows against run-owned broker_exchanges.
      const candidateExchangeIds = new Set<string>()
      const metaByRow = rows.map(row => {
        const meta = extractCoverageEvidenceMetadata(row)
        for (const id of meta.exchangeIds) candidateExchangeIds.add(id)
        return meta
      })
      const exchangeOriginById = new Map<string, string>()
      if (candidateExchangeIds.size > 0) {
        this.storage.flushNow()
        const exRows = this.storage.db.select({
          id: brokerExchanges.id,
          origin: brokerExchanges.origin,
        })
          .from(brokerExchanges)
          .where(and(
            eq(brokerExchanges.runId, runId),
            inArray(brokerExchanges.id, [...candidateExchangeIds]),
          ))
          .all()
        for (const ex of exRows) {
          exchangeOriginById.set(ex.id, normalizeOriginForCoverage(ex.origin))
        }
      }

      for (let i = 0; i < rows.length; i += 1) {
        const row = rows[i]!
        const meta = metaByRow[i]!
        if (!row.assignmentId) continue
        const hasCodedGap = typeof row.proofGapReason === 'string' && row.proofGapReason.trim().length > 0
        const isProved = row.status === 'reported'
          && (!row.linkedFindingId || !inactiveFindingIds.has(row.linkedFindingId))
        const rowOrigin = normalizeOriginForCoverage(row.origin)
        const hasVerifiedExchangeEvidence = (row.status === 'ruled_out' || row.status === 'no_issue_found')
          && meta.exchangeIds.some(id => exchangeOriginById.get(id) === rowOrigin)
        if (isProved || hasCodedGap || hasVerifiedExchangeEvidence) {
          covered.add(row.assignmentId)
        }
      }
    } catch (err) {
      this.noteLifecycleWarning(runId, 'provedOrGapCodedAssignmentIds.coverage', err)
    }
    return covered
  }

  /** Pass-1 coverage view used by the dry-round stop guard and the stop-time telemetry.
   *  Counts ONLY `proved` / `gap_coded` completions as covered and keys strictly on structured
   *  `(origin, METHOD, route, class)` targets bound at step creation (never prose parsing). */
  passOneCoverageFor(run: Pick<Run, 'id'>, steps: readonly ChainStep[]): {
    uncoveredTierAEndpoints: string[]
    uninvestigatedFirstPassClasses: string[]
    tierAEndpoints: string[]
  } {
    let unavailableOrigins = new Set<string>()
    try {
      const fullRun = this.storage.run(run.id)
      unavailableOrigins = this.unavailableOriginsForRun(fullRun)
    } catch { /* fallback to empty unavailable set if run already removed */ }
    const tierAEndpoints = [...new Set(
      this.tierALeadFacts(run)
        .filter(fact => !fact.origin || !unavailableOrigins.has(fact.origin))
        .map(fact => {
          const method = typeof fact.data?.method === 'string' ? fact.data.method.toUpperCase() : 'GET'
          const endpoint = typeof fact.data?.endpoint === 'string' ? fact.data.endpoint : ''
          return `${method} ${endpoint}`
        })
        .filter(endpoint => endpoint.length > 0),
    )].sort()
    const coveredAssignments = this.provedOrGapCodedAssignmentIds(run.id)
    const dispatchableIds = new Set(
      dispatchableReadySteps(steps, undefined, unavailableOrigins).map(step => step.id),
    )
    const coverage = passOneCoverage({
      tierAEndpoints,
      steps: steps.map(step => {
        const structuredTargets = this.getStructuredStepTargets(step)
        const routes = [...new Set(structuredTargets.map(t => normalizeConfirmedRouteTemplate(t.route)).filter(Boolean))]
        const keys = structuredTargets.map(structuredCoverageKey)
        const isCovered = step.status === 'complete'
          && step.assignedWorkerId !== null
          && coveredAssignments.has(step.assignedWorkerId)
        return {
          id: step.id,
          dispatchable: dispatchableIds.has(step.id),
          dispatched: step.assignedWorkerId !== null || step.status === 'complete' || step.status === 'running',
          covered: isCovered,
          structuredTargets,
          routes,
          keys,
        }
      }),
    })
    return { ...coverage, tierAEndpoints }
  }


  /**
   * Planner coverage assertion: before a dry/coordinator stop can terminate Phase B, ensure
   * discovered high-risk unconfirmed endpoints (`riskScore >= 60`) have at least one first-pass
   * investigation step queued (bounded to `min(6, remainingBudget)`).
   * Keys confirmed-exclusion & coverage strictly on structured `(origin, METHOD, route, class)`.
   */
  queueHighRiskCoverageSteps(
    run: Run,
    approvedOrigins: ReadonlySet<string>,
    dynamicStepBudget: number,
    existingSteps: readonly ChainStep[],
    limitOverride?: number,
  ): { seeded: number; endpoints: string[] } {
    const remainingBudget = Math.max(0, dynamicStepBudget - existingSteps.length)
    const defaultCap = plannerWaveDispatchCap(run.workerConcurrency || defaultWorkerConcurrency, remainingBudget)
    const cap = limitOverride !== undefined ? Math.max(0, Math.min(limitOverride, remainingBudget)) : defaultCap
    if (cap <= 0) return { seeded: 0, endpoints: [] }
    let endpoints: Array<{
      origin: string
      method: string
      pathTemplate: string
      riskScore: number
      coveragePct?: number | null
      testedClasses?: string[] | null
    }> = []
    try {
      endpoints = this.pageAll((offset, limit) =>
        this.storage.listEndpoints(run.id, { orderBy: 'risk', limit, offset }))
    } catch (err) {
      this.noteLifecycleWarning(run.id, 'queueHighRiskCoverageSteps.listEndpoints', err)
      return { seeded: 0, endpoints: [] }
    }
    const targetCategory = 'broken-access-control'
    const confirmedRefs = this.alreadyConfirmedRefs(run, 200)
    const confirmedStructuredKeys = new Set<string>()
    const confirmedLegacyAnyMethodKeys = new Set<string>()
    for (const ref of confirmedRefs) {
      const origin = (ref.origin ?? '').trim()
      const method = (ref.method ?? 'ANY').trim().toUpperCase() || 'ANY'
      const normPath = normalizeConfirmedRouteTemplate(ref.path)
      const refClass = (ref.probeClass ?? '').trim()
      if (!normPath) continue
      if (origin && refClass) {
        confirmedStructuredKeys.add(structuredCoverageKey({ origin, method, route: normPath, vulnClass: refClass }))
        if (method === 'ANY') {
          confirmedLegacyAnyMethodKeys.add(structuredCoverageKey({ origin, method: 'ANY', route: normPath, vulnClass: refClass }))
        }
      }
    }
    const isEndpointConfirmedForClass = (ep: { origin: string; method: string; pathTemplate: string }): boolean => {
      const normPath = normalizeConfirmedRouteTemplate(ep.pathTemplate)
      const method = (ep.method || 'GET').toUpperCase()
      const exactKey = structuredCoverageKey({ origin: ep.origin, method, route: normPath, vulnClass: targetCategory })
      const anyMethodKey = structuredCoverageKey({ origin: ep.origin, method: 'ANY', route: normPath, vulnClass: targetCategory })
      return confirmedStructuredKeys.has(exactKey) || confirmedLegacyAnyMethodKeys.has(anyMethodKey)
    }
    const unconfirmedEndpoints = endpoints.filter(ep => !isEndpointConfirmedForClass(ep))
    const coveredAssignments = this.provedOrGapCodedAssignmentIds(run.id)
    const coveredStructuredKeys = new Set<string>()
    const coveredRouteMethodKeys = new Set<string>()
    for (const step of existingSteps) {
      const inFlight = IN_FLIGHT_STEP_STATUSES.has(step.status)
      const provedOrGapCoded = step.status === 'complete'
        && step.assignedWorkerId !== null
        && coveredAssignments.has(step.assignedWorkerId)
      if (!inFlight && !provedOrGapCoded) continue
      for (const target of this.getStructuredStepTargets(step)) {
        coveredStructuredKeys.add(structuredCoverageKey(target))
        if (target.method === 'ANY') {
          coveredRouteMethodKeys.add(`${target.origin}\u0000ANY\u0000${normalizeConfirmedRouteTemplate(target.route)}\u0000${confirmedCategoryFamily(target.vulnClass)}`)
        }
      }
    }
    const uncoveredEndpoints = unconfirmedEndpoints.filter(ep => {
      const method = (ep.method || 'GET').toUpperCase()
      const normPath = normalizeConfirmedRouteTemplate(ep.pathTemplate)
      const exactKey = structuredCoverageKey({ origin: ep.origin, method, route: normPath, vulnClass: targetCategory })
      const anyMethodKey = `${ep.origin}\u0000ANY\u0000${normPath}\u0000${confirmedCategoryFamily(targetCategory)}`
      return !coveredStructuredKeys.has(exactKey) && !coveredRouteMethodKeys.has(anyMethodKey)
    })
    const quarantinedSet = this.getQuarantinedOriginSet(run, approvedOrigins)
    const activeOrigins = new Set([...approvedOrigins].filter(o => !quarantinedSet.has(o)))
    if (!activeOrigins.size) return { seeded: 0, endpoints: [] }
    const candidates = selectUncoveredHighRiskEndpoints({
      endpoints: uncoveredEndpoints,
      approvedOrigins: activeOrigins,
      confirmedPaths: new Set<string>(),
      coveredRoutes: new Set<string>(),
      minRisk: 60,
      limit: cap,
      sourceMounted: this.host.projectReposMount(run.projectId).mountedRepos.length > 0,
      quarantinedOrigins: quarantinedSet,
    })
    const seededEndpoints: string[] = []
    for (const ep of candidates) {
      const asset = this.approvedAsset(run, ep.origin)
      if (!asset) continue
      const method = (ep.method || 'GET').toUpperCase()
      const title = `High-risk route coverage · ${method} ${ep.pathTemplate}`
      const hypothesis = `Discovered high-risk endpoint ${method} ${ep.pathTemplate} on ${ep.origin} (risk ${ep.riskScore}, coverage ${ep.coveragePct ?? 0}%) has no first-pass investigation yet. Probe authorization boundaries, state invariants, and input validation with control vs. variant evidence; submit a verified proof or coded record_coverage gap.`
      const category = targetCategory
      const created = this.storage.addChainStep(run, {
        title, hypothesis, category, priority: 70, targetAssetIds: [asset.id],
        skills: ['false-positive-elimination'], dependsOnFactIds: [], sourceOrigins: [ep.origin],
        specialistProfile: routeStepToSpecialist({ title, hypothesis, category, skills: [] }),
      })
      this.registerStepTargets(run.id, created.id, [{
        origin: ep.origin,
        method,
        route: ep.pathTemplate,
        vulnClass: category,
      }])
      seededEndpoints.push(`${method} ${ep.pathTemplate}`)
    }
    return { seeded: seededEndpoints.length, endpoints: seededEndpoints }
  }


  /**
   * Classify whether a planned step duplicates already-confirmed or currently in-flight work on
   * `(origin, normalizedRoute, classFamily)`, strictly preserving zero-recall-loss invariants:
   * - never suppresses multi-trial siblings (`trialIndex > 0`) or Hop-Continuations
   *   (`checkpointCapId` / `dependsOnStepIds` / continuation skill);
   * - never suppresses a different vuln class on an already-confirmed or in-flight route;
   * - never suppresses a multi-hop chain step (`routes.length >= 2` or multi-hop chain signal)
   *   unless ALL mentioned `(origin, route, classFamily)` tuples are already confirmed with a
   *   composite receipt or currently in-flight.
   */
  classifyDuplicatePlannedStep(
    candidate: PlannedStepDedupeCandidate,
    confirmed: readonly PlannerConfirmedRef[],
    inFlightTuples: ReadonlySet<string> = new Set(),
  ): DuplicatePlannedStepReason {
    // Zero-recall-loss invariant: never suppress multi-trial siblings or Hop-Continuations.
    if ((candidate.trialIndex ?? 0) > 0) return null
    const hasCheckpointCap = Boolean(candidate.checkpointCapId?.trim())
      || Boolean(extractCheckpointCapIdFromStep({ skills: candidate.skills }))
    const hasDepSteps = (candidate.dependsOnStepIds?.length ?? 0) > 0
    const hasContinuationSkill = (candidate.skills ?? []).some(skill =>
      skill.startsWith(CHAIN_CONTINUATION_SKILL_PREFIX))
    if (hasDepSteps || hasCheckpointCap || hasContinuationSkill) return null

    const structuredRoutes = (candidate.structuredTargets ?? [])
      .map(t => normalizeConfirmedRouteTemplate(t.route))
      .filter(route => route && route !== '/')
    const routes = structuredRoutes.length > 0
      ? [...new Set(structuredRoutes)]
      : this.stepMentionedRoutes(candidate).filter(route => route && route !== '/')
    if (!routes.length) return null

    const structuredOrigins = (candidate.structuredTargets ?? []).map(t => t.origin.trim()).filter(Boolean)
    const rawOrigins = candidate.origins ?? candidate.sourceOrigins ?? []
    const origins = [...new Set((rawOrigins.length > 0 ? rawOrigins : structuredOrigins).map(o => o.trim()).filter(Boolean))]
    const category = candidate.category?.trim() ?? ''
    const hasDepFacts = (candidate.dependsOnFactIds?.length ?? 0) > 0
    const confirmedTuples = buildConfirmedTupleKeySets(confirmed)
    const typedCompositeRoutes = new Set<string>()
    for (const ref of confirmed) {
      if (!ref.hasCompositeReceipt || !ref.probeClass?.trim()) continue
      const origin = ref.origin?.trim(), norm = normalizeConfirmedRouteTemplate(ref.path)
      if (origin && norm && norm !== '/') typedCompositeRoutes.add(`${origin}\u0000${norm}`)
    }
    const isCompositeHit = (origin: string, route: string, cat: string): boolean => {
      const key = plannerDedupeTupleKey(origin, route, cat)
      if (key && confirmedTuples.composite.has(key)) return true
      const routeKey = `${origin}\u0000${route}`
      return confirmedTuples.compositeRoutes.has(routeKey) && !typedCompositeRoutes.has(routeKey)
    }

    if (routes.length >= 2) {
      // Multi-hop chain step: suppress if the terminal target route (or every route on a matching
      // origin) hits a composite-confirmed origin+canonical-family (or untyped composite route).
      if (!origins.length || !category) return null
      const terminalRoute = routes[routes.length - 1]!
      if (origins.some(origin => isCompositeHit(origin, terminalRoute, category))) return 'already_confirmed'
      if (routes.every(route => origins.some(origin => isCompositeHit(origin, route, category)))) return 'already_confirmed'
      const allCovered = routes.every(route => origins.some(origin => {
        if (isCompositeHit(origin, route, category)) return true
        const key = plannerDedupeTupleKey(origin, route, category)
        return Boolean(key && inFlightTuples.has(key))
      }))
      return allCovered ? 'in_flight' : null
    }

    // Single-route step: canonical `(origin, normalizedRoute, classFamily)` matching across sibling origins.
    const singleRoute = routes[0]!
    if (origins.length > 0 && category) {
      if (origins.some(origin => isCompositeHit(origin, singleRoute, category))) return 'already_confirmed'
      if (!hasDepFacts && origins.some(origin => {
        const key = plannerDedupeTupleKey(origin, singleRoute, category)
        return Boolean(key && confirmedTuples.all.has(key))
      })) return 'already_confirmed'
      const allInFlightOrConfirmed = origins.every(origin => {
        const key = plannerDedupeTupleKey(origin, singleRoute, category)
        return Boolean(key) && (inFlightTuples.has(key!)
          || (!hasDepFacts && confirmedTuples.all.has(key!))
          || isCompositeHit(origin, singleRoute, category))
      })
      return allInFlightOrConfirmed ? 'in_flight' : null
    }

    // Legacy direct callers (e.g. stepRepeatsConfirmedWork without origins/category).
    if (hasDepFacts) return null
    if (category) {
      const targetFamily = canonicalPlannerDedupeFamily(category, confirmedCategoryFamily)
      const matched = confirmed.some(ref =>
        normalizeConfirmedRouteTemplate(ref.path) === singleRoute
        && Boolean(ref.probeClass?.trim())
        && canonicalPlannerDedupeFamily(ref.probeClass!.trim(), confirmedCategoryFamily) === targetFamily,
      )
      return matched ? 'already_confirmed' : null
    }
    const confirmedPaths = buildConfirmedRouteSets(confirmed).paths
    return routes.every(route => confirmedPaths.has(normalizeConfirmedRouteTemplate(route))) ? 'already_confirmed' : null
  }

  /**
   * A planner step that only names routes the deterministic floor already confirmed is a duplicate
   * dispatch, unless it declares a parent fact/step (that is an explicit chain/escalation) or
   * targets a different vulnerability class / origin.
   */
  stepRepeatsConfirmedWork(
    step: PlannedStepDedupeCandidate,
    confirmed: readonly PlannerConfirmedRef[],
  ): boolean {
    return this.classifyDuplicatePlannedStep(step, confirmed) === 'already_confirmed'
  }


  /**
   * Turn *evidence-backed* deterministic leads into upgrade assignments. A det_lead is only useful
   * to the agentic lane when it is (a) admitted by {@link detLeadEvidenceGate} — a control contrast
   * or near-miss exists, (b) unconfirmed and not a route/class the floor already confirmed, and
   * (c) bound to its originating fact so it becomes a `det_lead_upgrade` mission with a brief.
   *
   * Priority is deliberately below planner-authored class steps; the scheduler also caps lead
   * concurrency independently, so a lead backlog can never pre-empt unproven target classes.
   */
  /** Program-Graph code leads carrying a dataflow slice, RBAC policy diff, or static secret/IaC lead. */
  tierALeadFacts(run: Pick<Run, 'id'>): Fact[] {
    return this.pageAll((offset, limit) =>
      this.storage.listFacts(run.id, { includeTainted: false, limit, offset }))
      .filter(fact => {
        if (!isTrustedHostControlFact(fact, 'det_lead')) return false
        const data = fact.data
        if (data?.source !== 'program_graph') return false
        const slice = data.codeSlice as { hops?: unknown } | undefined
        const hasSlice = Boolean(slice && Array.isArray(slice.hops) && slice.hops.length > 0)
        const hasPolicyDiff = (Array.isArray(data.guardDiff) && data.guardDiff.length > 0) || data.policyDiff === true
        const hasStaticLead = data.staticLeadKind === 'secret' || data.staticLeadKind === 'iac'
        return hasSlice || hasPolicyDiff || hasStaticLead
      })
      .sort((a, b) => {
        const keyOf = (fact: typeof a) =>
          `${String(fact.data?.method ?? '')}\u0000${String(fact.data?.endpoint ?? '')}\u0000${fact.id}`
        return keyOf(a).localeCompare(keyOf(b))
      })
  }


  private enqueueLeadStep(
    run: Run,
    asset: Candidate,
    fact: Fact,
    input: {
      probeClass: string; method: string; endpoint: string; category: string
      dedupeKey: string; isTierA: boolean; reason: string; eventKind: string; eventMessage: string; extraDetail?: Record<string, unknown>
    },
  ): ChainStep {
    const skills = detLeadSkills(input.probeClass)
    const title = `${input.isTierA ? 'Tier-A code lead' : 'det_lead upgrade'} · ${input.probeClass} ${input.method} ${input.endpoint}`.slice(0, 180)
    const hypothesis = input.isTierA
      ? `A white-box dataflow slice proves a ${input.probeClass} sink on ${input.method} ${input.endpoint} (${input.reason}). Prove it on the live route (control/variant differential) or record a coded proofGapReason.`
      : `The deterministic floor observed an unproven ${input.probeClass} signal at ${input.method} ${input.endpoint} (${input.reason}). Reproduce it, identify the concretely mutated input, and submit a verified proof or chain it into a higher-impact finding.`
    const createdStep = this.storage.addChainStep(run, {
      title, hypothesis, category: input.category,
      priority: input.isTierA ? TIER_A_STEP_PRIORITY : DET_LEAD_STEP_PRIORITY,
      targetAssetIds: [asset.id], skills, dependsOnFactIds: [fact.id], sourceOrigins: [fact.origin],
      specialistProfile: routeStepToSpecialist({ title, hypothesis, category: input.category, skills }),
    })
    this.storage.updateChainStep(createdStep.id, { status: 'ready' })
    this.registerStepTargets(run.id, createdStep.id, [{
      origin: fact.origin,
      method: input.method,
      route: input.endpoint,
      vulnClass: input.category,
    }])
    const runScopedDedupeKey = `${run.id}\0${input.dedupeKey}`
    this.detLeadStepKeys.add(runScopedDedupeKey)
    if (input.isTierA) {
      this.tierAStepKeys.add(runScopedDedupeKey)
      this.host.tierAStepIds.add(createdStep.id)
      this.host.tierAFactIds.add(fact.id)
    }
    try {
      this.storage.event(run.id, input.eventKind, input.eventMessage, {
        probeClass: input.probeClass, endpoint: input.endpoint, method: input.method,
        factId: fact.id, stepId: createdStep.id, ...input.extraDetail,
      })
    } catch { /* best-effort */ }
    return createdStep
  }

  /**
   * Seed every Tier-A Program-Graph lead as a ready step before the planner's first round. These
   * are the white-box AST/RBAC/dataflow hypotheses; they must never wait behind generic class/route
   * steps or a dry-round stop. Idempotent per (route, class), bounded by
   * {@link WHITEBOX_TIER_A_MAX_SEEDED_STEPS} when source is mounted (or {@link TIER_A_MAX_SEEDED_STEPS}).
   */
  queueTierALeadSteps(
    run: Run,
    approvedOrigins: ReadonlySet<string>,
    budget: number,
    options: { sourceMounted?: boolean } = {},
  ): number {
    const facts = this.tierALeadFacts(run)
    if (!facts.length) return 0
    const activeOrigins = this.activeApprovedOrigins(run, approvedOrigins)
    if (!activeOrigins.size) return 0
    const existing = this.storage.listChainSteps(run.id, run.goalRevision)
    const boundFactIds = new Set(existing.flatMap(step => step.dependsOnFactIds))
    const confirmedTuples = buildConfirmedTupleKeySets(this.alreadyConfirmedRefs(run, 100)).all
    const inFlightTuples = buildInFlightTupleKeys(existing)
    const sourceMounted = options.sourceMounted ?? (this.host.projectReposMount(run.projectId).mountedRepos.length > 0)
    const maxSeeded = sourceMounted ? WHITEBOX_TIER_A_MAX_SEEDED_STEPS : TIER_A_MAX_SEEDED_STEPS
    let slots = Math.max(0, Math.min(maxSeeded, budget - existing.length))
    let created = 0
    for (const fact of facts) {
      if (slots <= 0) break
      this.host.tierAFactIds.add(fact.id)
      if (boundFactIds.has(fact.id) || !activeOrigins.has(fact.origin)) continue
      const endpoint = typeof fact.data?.endpoint === 'string' ? fact.data.endpoint : ''
      const probeClass = typeof fact.data?.probeClass === 'string' ? fact.data.probeClass : ''
      const method = typeof fact.data?.method === 'string' ? fact.data.method.toUpperCase() : 'GET'
      if (!endpoint.startsWith('/') || !probeClass) continue
      const asset = this.approvedAsset(run, fact.origin)
      if (!asset) continue
      const category = detLeadCategory(probeClass)
      const dedupeKey = `${method} ${normalizeEndpointTemplate(endpoint)}|${confirmedCategoryFamily(category)}`
      const runScopedDedupeKey = `${run.id}\0${dedupeKey}`
      if (this.tierAStepKeys.has(runScopedDedupeKey) || this.detLeadStepKeys.has(runScopedDedupeKey)) continue
      const tupleKey = plannerDedupeTupleKey(fact.origin, endpoint, category)
      if (tupleKey && (confirmedTuples.has(tupleKey) || inFlightTuples.has(tupleKey))) continue
      const reason = typeof fact.data.reason === 'string' ? fact.data.reason.slice(0, 200) : 'white-box dataflow slice'
      this.enqueueLeadStep(run, asset, fact, {
        probeClass, method, endpoint, category, dedupeKey, isTierA: true, reason,
        eventKind: 'deterministic_lane.tier_a_seeded',
        eventMessage: `Tier-A code lead ${probeClass} on ${method} ${endpoint} seeded as a Round-1 step.`,
        extraDetail: { priority: TIER_A_STEP_PRIORITY },
      })
      slots -= 1
      created += 1
    }
    return created
  }


  queueDetLeadUpgradeSteps(run: Run, approvedOrigins: ReadonlySet<string>, budget: number): number {
    const confirmedKeys = new Set(this.alreadyConfirmedRefs(run, 100).map(ref =>
      `${normalizeConfirmedRouteTemplate(ref.path)}|${confirmedCategoryFamily(ref.probeClass ?? '')}`))
    const facts = [...this.pageAll((offset, limit) =>
      this.storage.listFacts(run.id, { includeTainted: false, limit, offset }))]
      .sort((a, b) => {
        const keyOf = (fact: typeof a) =>
          `${fact.data?.source === 'program_graph' ? '0' : '1'}\u0000${String(fact.data?.endpoint ?? '')}\u0000${String(fact.data?.method ?? '')}\u0000${String(fact.data?.probeClass ?? '')}\u0000${fact.id}`
        return keyOf(a).localeCompare(keyOf(b))
      })
    const activeOrigins = this.activeApprovedOrigins(run, approvedOrigins)
    if (!activeOrigins.size) return 0
    const existing = this.storage.listChainSteps(run.id, run.goalRevision)
    const boundFactIds = new Set(existing.flatMap(step => step.dependsOnFactIds))
    let slots = Math.max(0, budget - existing.length)
    let created = 0
    for (const fact of facts) {
      if (slots <= 0 || created >= 4) break
      if (!isTrustedHostControlFact(fact, 'det_lead') || !activeOrigins.has(fact.origin) || boundFactIds.has(fact.id)) continue
      const endpoint = typeof fact.data.endpoint === 'string' ? fact.data.endpoint : ''
      const probeClass = typeof fact.data.probeClass === 'string' ? fact.data.probeClass : ''
      const method = typeof fact.data.method === 'string' ? fact.data.method.toUpperCase() : 'GET'
      if (!endpoint.startsWith('/') || !probeClass) continue
      const category = detLeadCategory(probeClass)
      const routeKey = `${normalizeConfirmedRouteTemplate(endpoint)}|${confirmedCategoryFamily(category)}`
      const dedupeKey = `${method} ${routeKey}`
      const runScopedDedupeKey = `${run.id}\0${dedupeKey}`
      if (confirmedKeys.has(routeKey) || this.detLeadStepKeys.has(runScopedDedupeKey)) continue
      const gate = detLeadEvidenceGate(fact.data)
      if (!gate.admitted) {
        const rejectedKey = `${run.id}\0${fact.id}`
        if (!this.detLeadGateRejected.has(rejectedKey)) {
          this.detLeadGateRejected.add(rejectedKey)
          try {
            this.storage.event(
              run.id, 'deterministic_lane.lead_deferred',
              `det_lead ${probeClass} on ${method} ${endpoint} not promoted: ${gate.reason}.`,
              { probeClass, endpoint, method, factId: fact.id, reason: gate.reason },
            )
          } catch { /* best-effort */ }
        }
        continue
      }
      const asset = this.approvedAsset(run, fact.origin)
      if (!asset) continue
      const guardKey = reinvestigationKey(endpoint, category)
      const verdict = this.host.reinvestigationGuardFor(run.id)
        .record(guardKey, detLeadUnlocksReinvestigation(fact.data))
      if (!verdict.allowed) {
        const cappedKey = `${run.id}\0${fact.id}`
        if (!this.cappedLeadReported.has(cappedKey)) {
          this.cappedLeadReported.add(cappedKey)
          this.host.noteCappedReinvestigation(run, guardKey, verdict.count)
        }
        continue
      }
      const reason = typeof fact.data.reason === 'string' ? fact.data.reason.slice(0, 200) : 'differential observation'
      this.enqueueLeadStep(run, asset, fact, {
        probeClass, method, endpoint, category, dedupeKey, isTierA: fact.data.source === 'program_graph', reason,
        eventKind: 'deterministic_lane.lead_consumed',
        eventMessage: `det_lead ${probeClass} on ${method} ${endpoint} queued as a prioritized upgrade assignment.`,
      })
      this.host.detLeadConsumed.add(fact.id)
      slots -= 1
      created += 1
    }
    return created
  }


  /**
   * Explicit settlement deliverable for a Tier-A white-box assignment: which typed proof tool to run
   * against the named sink, and the coded-gap alternative. The tool still decides the verdict; this
   * only removes "which proof shape / what do I do when it is unreachable" friction.
   */
  tierAProofDeliverable(input: {
    category?: string | null
    title?: string | null
    hypothesis?: string | null
    sinkKind?: string | null
  }): string {
    const text = `${input.category ?? ''} ${input.title ?? ''} ${input.hypothesis ?? ''} ${input.sinkKind ?? ''}`.toLowerCase()
    const tool = /bfla|mass.assignment|privilege|role|grant|persist|csrf|workflow|state.change|business.logic/.test(text)
      ? 'prove_persisted_mutation'
      : /sqli|sql|inject|xss|ssti|command|template|xml|xxe/.test(text)
        ? 'prove_boolean_or_timing_diff'
        : 'prove_access_boundary'
    return `Invoke kovo_verify(${tool}) against this sink (control vs variant on the exact route above), or record_coverage(proofGapReason="<status|cannot_build_spec>") with the blocking HTTP status. A bare "leaning true" without either is rejected at settlement.`
  }


  missionKindForStep(step: ChainStep, hasDetLead: boolean): MissionKind {    if (/second.order|stored|canary/i.test(`${step.title} ${step.hypothesis}`)) return 'second_order'
    if (step.dependsOnStepIds.length > 0) return 'chain_step_2'
    if (/workflow|race|double.spend|business|quantity|price/i.test(`${step.title} ${step.hypothesis} ${step.category}`)) return 'business_logic'
    if (step.dependsOnFactIds.length > 0 && hasDetLead) return 'det_lead_upgrade'
    return 'class_scan'
  }


  /** Pre-packaged <=1.5 KB evidence brief for one assignment (routes/params/personas/IDs). */
  assignmentBriefForStep(input: {
    run: Run
    step: ChainStep
    targetOrigins: readonly string[]
    personas: readonly { handle: string; roleLabel: string }[]
    parentFacts: readonly Fact[]
    confirmed: readonly AlreadyConfirmedRef[]
    detLeads: readonly DetLeadSummary[]
    maxTurns: number
  }): string | undefined {
    const origin = input.targetOrigins[0]
    if (!origin) return undefined
    try {
      const publicOrigins = [...new Set([...input.targetOrigins, ...input.run.candidates.filter(c => input.run.approved.includes(c.id)).map(c => c.origin)])]
      const confirmedPathSet = new Set(
        input.confirmed
          .filter(ref => !ref.origin || ref.origin === origin)
          .map(ref => normalizeConfirmedRouteTemplate(ref.path)),
      )
      const confirmedOriginPathSet = new Set(input.confirmed.map(ref => `${ref.origin ?? origin} ${normalizeConfirmedRouteTemplate(ref.path)}`))
      const samples = this.storage.listResourceSamples(input.run.id).filter(sample => publicOrigins.includes(sample.origin))
      const routes = selectBriefRoutes(
        publicOrigins.length > 1 ? publicOrigins.flatMap(orig => this.storage.listEndpoints(input.run.id, { origin: orig, orderBy: 'risk', limit: 60 })) : this.storage.listEndpoints(input.run.id, { orderBy: 'risk', limit: 40 }),
        {
          publicOrigins,
          targetOrigins: input.targetOrigins,
          confirmedPaths: confirmedPathSet,
          confirmedOriginPaths: confirmedOriginPathSet,
          normalizePath: normalizeConfirmedRouteTemplate,
        },
      )
      // v7 M2: extract typed ChainHop artifacts persisted from prior/current rounds so follow-on
      // round briefs receive structured handles (tokens, leaked IDs, SSRF/redirect targets, role
      // transitions, workflow state handles) without prompt soup.
      const parentChainHops: ChainHop[] = readChainHopsFromFacts(input.parentFacts)
      const hopLinkedRoutes = parentChainHops
        .filter(hop => Boolean(hop.endpoint && hop.endpoint.startsWith('/')))
        .map(hop => ({
          method: hop.method ?? 'GET',
          path: hop.endpoint!,
          riskScore: hop.verified ? 95 : 85,
        }))
      const hopLeakedIds = parentChainHops
        .filter(hop => hop.artifactKind === 'leaked_id' || hop.artifactKind === 'workflow_state_handle')
        .map(hop => hop.artifactRef)
      const personas = input.personas.map(persona => {
        const hopIdsForPersona = parentChainHops
          .filter(hop =>
            (hop.artifactKind === 'leaked_id' || hop.artifactKind === 'workflow_state_handle')
            && (!hop.persona || hop.persona.toLowerCase() === persona.handle.toLowerCase()))
          .map(hop => hop.artifactRef)
        return {
          handle: persona.handle,
          role: persona.roleLabel,
          harvestedIds: [
            ...new Set([
              ...samples.filter(s => s.ownerPersona === persona.handle).map(s => s.resourceId),
              ...hopIdsForPersona,
              ...(hopIdsForPersona.length === 0 ? hopLeakedIds.slice(0, 2) : []),
            ]),
          ].slice(0, 6),
        }
      })
      const parentDetLead = input.detLeads.find(lead =>
        input.parentFacts.some(f => isTrustedHostControlFact(f, 'det_lead') && f.id === lead.exchangeId) ||
        (Boolean(lead.endpoint) && input.targetOrigins.includes(origin)),
      )
      const missionKind = parentChainHops.length > 0 && input.step.dependsOnFactIds.length > 0
        ? 'chain_step_2'
        : this.missionKindForStep(input.step, Boolean(parentDetLead))
      // v7/v8: wire multi-origin & CapabilityLedger counts so grey-box briefs receive Mode-A proof contracts.
      // Compact by default; chains, multi-origin/ledger runs, and multi-persona 4-hop slices expand to full.
      const ledger = this.storage.capabilityLedger(input.run.id)
      const sealedCapabilityCount = ledger.listCapabilities().length
      const codeSlice = this.host.codeSliceForAssignment(input.run, input.step, input.parentFacts)
      const codeExpansion: 'compact' | 'full' = missionKind === 'chain_step_2' ||
        input.step.dependsOnStepIds.length > 0 || parentChainHops.length > 0 || publicOrigins.length >= 2 ||
        sealedCapabilityCount > 0 || ((codeSlice?.hops.length ?? 0) >= 4 && input.personas.length > 0)
        ? 'full' : 'compact'
      // Exact control/variant actors for the differential: low-privilege-first order so the
      // default/starting persona is always the lowest-privilege actor when one exists.
      const tierAPersonas = sortPersonasLowPrivFirst(input.personas)
      const tenantOfPersona = (label: string): string => /\(([^()]+)\)\s*$/.exec(label)?.[1]?.trim() ?? ''
      const controlPersona = tierAPersonas[0]
      const variantPersona = controlPersona
        ? tierAPersonas.find(persona => persona.handle !== controlPersona.handle &&
            tenantOfPersona(persona.roleLabel) !== tenantOfPersona(controlPersona.roleLabel))
          ?? tierAPersonas.find(persona => persona.handle !== controlPersona.handle)
        : undefined
      const hopChainSummary = parentChainHops.length > 0
        ? parentChainHops.slice(0, 4).map(hop =>
            `${hop.artifactKind}:${hop.artifactRef}${hop.stateAfter ? `[${hop.stateBefore ?? '*'}->${hop.stateAfter}]` : ''}`).join('→')
        : ''
      // v8: Resolve canonical <= 2 KB HopCheckpointBrief from SQLite CapabilityLedger (restart-safe)
      // or persisted host-authored checkpoint metadata, preferring the deepest/latest round checkpoint.
      const checkpointFact = input.parentFacts
        .filter(f => isTrustedHostControlFact(f, 'hop_checkpoint'))
        .sort((a, b) => {
          const depthA = parseHopCheckpointJson(a.data?.checkpointBrief ?? a.data?.checkpointJson)?.depth ?? 0
          const depthB = parseHopCheckpointJson(b.data?.checkpointBrief ?? b.data?.checkpointJson)?.depth ?? 0
          return (depthB - depthA) || (b.createdAt - a.createdAt)
        })[0]
      const cachedCheckpoint = this.persistedStepCheckpoints.get(input.step.id)
      const persistedBrief = parseHopCheckpointJson(checkpointFact?.data?.checkpointBrief ?? checkpointFact?.data?.checkpointJson)
        ?? parseHopCheckpointJson(cachedCheckpoint?.checkpointJson)
      const checkpointCapId = extractCheckpointCapIdFromStep(input.step)
        ?? (typeof checkpointFact?.data?.checkpointCapId === 'string' ? checkpointFact.data.checkpointCapId : null)
        ?? cachedCheckpoint?.checkpointCapId
        ?? persistedBrief?.capabilityHandles[persistedBrief.capabilityHandles.length - 1]
        ?? parentChainHops.map(h => h.artifactRef).find(ref => ref.startsWith('cap:hop_'))
        ?? null
      let hopCheckpoint: HopCheckpointBrief | undefined
      if (checkpointCapId && ledger.getCapability(checkpointCapId)) {
        hopCheckpoint = ledger.buildHopCheckpointBrief(checkpointCapId, MAX_CHECKPOINT_BRIEF_BYTES, {
          ...(persistedBrief?.branchKey ? { branchKey: persistedBrief.branchKey } : {}),
          ...(persistedBrief?.evi !== undefined ? { evi: persistedBrief.evi } : {}),
          ...(persistedBrief?.mode ? { mode: persistedBrief.mode } : {}),
          ...(persistedBrief?.fuseWithBranchKey ? { fuseWithBranchKey: persistedBrief.fuseWithBranchKey } : {}),
          ...(persistedBrief?.nextGoal ? { nextGoal: persistedBrief.nextGoal } : {}),
          ...(persistedBrief?.workflowNotebook ? { workflowNotebook: persistedBrief.workflowNotebook } : {}),
        })
      }
      if (!hopCheckpoint && persistedBrief) {
        hopCheckpoint = finalizeHopCheckpointBrief(persistedBrief, MAX_CHECKPOINT_BRIEF_BYTES).brief
      }
      if (!hopCheckpoint && parentChainHops.length > 0) {
        const controller = this.frontierControllers.get(input.run.id)
        const matchingBranch = controller?.scheduler.getActiveBeam().find(item =>
          item.branch.depth >= 2 && item.branch.verifiedHops.some(h =>
            parentChainHops.some(p => p.endpoint && h.endpoint === p.endpoint)))
        if (matchingBranch) {
          hopCheckpoint = formatHopCheckpointForAssignment(
            { branch: matchingBranch.branch, evi: matchingBranch.evi },
            MAX_CHECKPOINT_BRIEF_BYTES,
          ).brief
        }
      }
      const text = buildAssignmentBrief({
        missionKind,
        origin,
        routes,
        ...(hopLinkedRoutes.length ? { linkedRoutes: hopLinkedRoutes } : {}),
        personas,
        alreadyConfirmedOnOrigin: input.confirmed
          .filter(ref => !ref.origin || ref.origin === origin)
          .map(ref => ({
            method: ref.method ?? 'ANY',
            path: ref.path,
            param: ref.param ?? null,
            cwe: ref.cwe ?? null,
            origin: ref.origin ?? origin,
          })),
        ...(parentDetLead
          ? {
              detLead: {
                probeClass: parentDetLead.probeClass,
                exchangeId: parentDetLead.exchangeId ?? null,
                signalSummary: parentDetLead.signalSummary ?? '',
                verifyFailureReason: parentDetLead.verifyFailureReason ?? null,
              },
            }
          : {}),
        ...(codeSlice ? { codeSlice, codeExpansion } : {}),
        ...(hopCheckpoint ? { hopCheckpoint } : {}),
        ...(publicOrigins.length >= 2 ? { publicOrigins } : {}),
        ...(sealedCapabilityCount > 0 ? { sealedCapabilityCount } : {}),
        // Explicit proof obligation for a white-box assignment or a typed multi-round chain step.
        ...(codeSlice
          ? {
              proofObligation: {
                route: codeSlice.route,
                method: codeSlice.methods[0],
                params: [
                  ...(codeSlice.input?.params ?? []),
                  ...(codeSlice.input?.query ?? []),
                  ...(codeSlice.input?.body ?? []),
                ],
                auth: codeSlice.auth,
                ...(codeSlice.sink ? { sink: `${codeSlice.sink.kind}@${codeSlice.sink.at}` } : {}),
                chain: hopChainSummary
                  ? `${hopChainSummary} | ${codeSlice.hops.slice(0, 4).map(hop => hop.at).join('→')}`
                  : codeSlice.hops.slice(0, 6).map(hop => hop.at).join('→'),
                ...(controlPersona
                  ? {
                      controlPersona: controlPersona.handle,
                      variantPersona: (variantPersona ?? controlPersona).handle,
                    }
                  : {}),
                deliverable: this.tierAProofDeliverable({
                  category: input.step.category,
                  title: input.step.title,
                  hypothesis: input.step.hypothesis,
                  ...(codeSlice.sink ? { sinkKind: codeSlice.sink.kind } : {}),
                }),
              },
            }
          : parentChainHops.length > 0
            ? {
                proofObligation: {
                  route: hopLinkedRoutes[hopLinkedRoutes.length - 1]
                    ? `${hopLinkedRoutes[hopLinkedRoutes.length - 1]!.method} ${hopLinkedRoutes[hopLinkedRoutes.length - 1]!.path}`
                    : routes[0] ? `${routes[0].method} ${routes[0].path}` : 'ANY /',
                  chain: formatChainHopsBrief(parentChainHops, 200),
                  ...(controlPersona
                    ? {
                        controlPersona: controlPersona.handle,
                        variantPersona: (variantPersona ?? controlPersona).handle,
                      }
                    : {}),
                  deliverable: this.tierAProofDeliverable({
                    category: input.step.category,
                    title: input.step.title,
                    hypothesis: input.step.hypothesis,
                  }),
                },
              }
            : {}),
        targetCount: routes.length > 1 ? 2 : 1,
        turnBudget: input.maxTurns,
      })
      // The renderer owns the ladder; this assert turns a future regression into a loud failure.
      assertAssignmentBriefSize(text, ASSIGNMENT_BRIEF_MAX_BYTES_WITH_CODE)
      return text
    } catch {
      return undefined
    }
  }


  // --- v6 Phase 4: tool-equipped Graph Coordinator planner ---

  /**
   * Lossless Program Graph view assembled from persisted endpoint code locations and sink tags.
   * The full AST graph is not persisted, but every AST-derived route keeps its `codeLocation`, so
   * sink paths and middleware diffs remain queryable without the old snapshot.
   */
  coordinatorProgramGraph(endpoints: readonly CoordinatorEndpoint[]): CoordinatorProgramGraph | null {
    const routes: CoordinatorProgramGraph['routes'][number][] = []
    const nodes: Array<{ id: string; kind: string; symbol: string; file: string; line: number; sinkKind?: string }> = []
    const edges: Array<{ fromId: string; toId: string }> = []
    for (const endpoint of endpoints) {
      const location = endpoint.codeLocation as { file?: unknown; startLine?: unknown } | null | undefined
      const file = typeof location?.file === 'string' ? location.file : null
      if (!file) continue
      const line = typeof location?.startLine === 'number' ? location.startLine : 1
      routes.push({
        id: endpoint.id, method: endpoint.method, path: endpoint.pathTemplate, file, line, handler: '',
        guards: [endpoint.authRequirement, endpoint.ownershipGuard]
          .filter((guard): guard is string => Boolean(guard && guard.trim())),
      })
      for (const sinkKind of endpoint.sinkKinds ?? []) {
        const sinkId = `${endpoint.id}:${sinkKind}`
        nodes.push({ id: sinkId, kind: 'sink', symbol: sinkKind, file, line, sinkKind })
        edges.push({ fromId: endpoint.id, toId: sinkId })
      }
    }
    return routes.length ? { routes, nodes, edges } : null
  }


  private listCoordinatorFindings(runId: string): ReturnType<CoordinatorDeps['listFindings']> {
    return this.storage.db.select().from(findings).where(eq(findings.runId, runId)).all()
      .map(row => ({
        id: row.id, origin: row.finding.origin, title: row.finding.title, status: row.finding.status,
        severity: row.finding.severity, ...(row.finding.reason ? { reason: row.finding.reason } : {}),
        ...(row.finding.category ? { category: row.finding.category } : {}),
        ...(row.finding.cwe ? { cwe: row.finding.cwe } : {}),
        ...(row.finding.confidence ? { confidence: row.finding.confidence } : {}),
        ...(row.finding.verification ? { verification: row.finding.verification } : {}),
        ...(row.finding.runtimeProofGap ? { runtimeProofGap: row.finding.runtimeProofGap } : {}),
        ...(row.finding.findingKind ? { findingKind: row.finding.findingKind } : {}),
        evidenceIds: row.finding.evidenceIds ?? [], chainFactIds: row.finding.chainFactIds ?? [],
        exchangeIds: row.finding.exchangeIds ?? [],
      }))
  }

  /** Untruncated, paginated data access for the coordinator (optionally backed by a single-round snapshot cache). */
  coordinatorDeps(
    run: Run,
    roundSnapshot?: {
      getEndpoints: () => CoordinatorEndpoint[]
      getFacts: () => Fact[]
      getFindings: () => ReturnType<CoordinatorDeps['listFindings']>
      getApiDependencies: () => CoordinatorApiDependency[]
    },
  ): CoordinatorDeps {
    const endpoints = (): CoordinatorEndpoint[] => roundSnapshot
      ? roundSnapshot.getEndpoints()
      : this.pageAll((offset, limit) => this.storage.listEndpoints(run.id, { limit, offset }))
    return {
      listEndpoints: endpoints,
      listFacts: () => roundSnapshot
        ? roundSnapshot.getFacts()
        : this.pageAll((offset, limit) => this.storage.listFacts(run.id, { includeTainted: false, limit, offset })),
      listApiDependencies: () => roundSnapshot
        ? roundSnapshot.getApiDependencies()
        : this.collectCoordinatorApiDependencies(run),
      listFindings: () => roundSnapshot ? roundSnapshot.getFindings() : this.listCoordinatorFindings(run.id),
      programGraph: () => this.coordinatorProgramGraph(endpoints()),
      // No persisted commit-signal table in v6; git hotspots remain empty rather than fabricated.
      commitSignals: () => [],
      approvedOrigins: () => [...this.host.approvedOriginsSet(run)],
      capabilityLedger: () => this.storage.capabilityLedger(run.id),
      frontierScheduler: () => this.frontierControllerFor(run.id).scheduler,
    }
  }


  pageAll<T>(fetchPage: (offset: number, limit: number) => readonly T[], pageSize = 500): T[] {
    return collectAllPages(fetchPage, pageSize)
  }


  /**
   * Persist a validated dispatch plan as chain steps, citing parent facts and capability bundles.
   * Returns the structured funnel counts so a planner round can report exactly where planned
   * hypotheses were dropped (title dedupe, already-confirmed route, no approved asset, cap, budget).
   */
  persistDispatchPlan(
    run: Run,
    plan: DispatchPlan,
    factIds: ReadonlySet<string>,
    detLeadFactIds: ReadonlySet<string> = new Set(),
    options: { dependsOnStepIds?: readonly string[]; preservePriority?: boolean } = {},
  ): Pick<DispatchFunnelCounts, 'planned' | 'enqueued' | 'filteredDedupe' | 'filteredAlreadyConfirmed' | 'filteredNoAsset'> {
    const existing = this.storage.listChainSteps(run.id, run.goalRevision)
    const quarantinedSet = this.getQuarantinedOriginSet(run)
    const titles = new Set(existing.map(step => step.title.trim().toLowerCase()))
    const confirmed = this.alreadyConfirmedRefs(run, 100)
    const inFlightTuples = buildInFlightTupleKeys(existing)
    const counts = { planned: plan.plan.length, enqueued: 0, filteredDedupe: 0, filteredAlreadyConfirmed: 0, filteredNoAsset: 0 }
    const depStepIds = [...new Set(options.dependsOnStepIds ?? [])]
    for (const step of plan.plan) {
      const effectiveOrigins = quarantinedSet.size > 0
        ? step.origins.filter(o => !quarantinedSet.has(o))
        : step.origins
      if (!effectiveOrigins.length) { counts.filteredNoAsset += 1; continue }
      const title = compactChainTitle(step.hypothesis)
      const key = title.toLowerCase()
      if (titles.has(key)) { counts.filteredDedupe += 1; continue }
      const boundFactIds = step.parentEvidenceIds.filter(id => factIds.has(id))
      const category = step.probeClass === 'stored_xss' ? 'cors-client-side'
        : step.probeClass === 'authz_replay' || step.probeClass === 'auth_bypass' ? 'broken-access-control'
          : step.probeClass === 'ssrf' ? 'injection-input' : 'broken-access-control'
      const parsedBrief = step.checkpointBrief
        ? finalizeHopCheckpointBrief(step.checkpointBrief, MAX_CHECKPOINT_BRIEF_BYTES)
        : (() => {
            const parsed = parseHopCheckpointJson(step.checkpointJson)
            return parsed ? finalizeHopCheckpointBrief(parsed, MAX_CHECKPOINT_BRIEF_BYTES) : null
          })()
      const checkpointCapId = step.checkpointCapId?.trim()
        || parsedBrief?.brief.capabilityHandles[parsedBrief.brief.capabilityHandles.length - 1]
        || parsedBrief?.brief.verifiedHops[parsedBrief.brief.verifiedHops.length - 1]?.capId
        || undefined
      // Tool-dispatched hypotheses obey the same confirmed & in-flight tuple dedupe rule as planner JSON steps.
      const dupReason = this.classifyDuplicatePlannedStep({
        title,
        hypothesis: step.hypothesis,
        category,
        origins: step.origins,
        skills: step.skills,
        dependsOnFactIds: boundFactIds,
        dependsOnStepIds: depStepIds,
        checkpointCapId,
      }, confirmed, inFlightTuples)
      if (dupReason === 'already_confirmed') { counts.filteredAlreadyConfirmed += 1; continue }
      if (dupReason === 'in_flight') { counts.filteredDedupe += 1; continue }
      const assetIds = run.candidates
        .filter(candidate => effectiveOrigins.includes(candidate.origin) && run.approved.includes(candidate.id))
        .map(candidate => candidate.id)
      if (!assetIds.length) { counts.filteredNoAsset += 1; continue }
      // F2: lead-bound coordinator dispatches obey the same low-priority rule as planner steps.
      const leadBound = boundFactIds.some(id => detLeadFactIds.has(id)) ||
        isDetLeadDispatchStep({ title, hypothesis: step.hypothesis })
      const tierABound = boundFactIds.some(id => this.host.tierAFactIds.has(id))
      const checkpointJson = parsedBrief?.checkpointJson
        ?? (typeof step.checkpointJson === 'string' && step.checkpointJson.trim() ? step.checkpointJson.trim().slice(0, MAX_CHECKPOINT_BRIEF_BYTES) : undefined)
      const stepSkills = [...step.skills]
      if (checkpointCapId && !stepSkills.includes(`${CHECKPOINT_CAP_SKILL_PREFIX}${checkpointCapId}`)) {
        stepSkills.push(`${CHECKPOINT_CAP_SKILL_PREFIX}${checkpointCapId}`)
      }
      const finalFactIds = [...boundFactIds]
      if (checkpointCapId || checkpointJson) {
        const workers = this.storage.workerList(run.id)
        const anchorWorker = workers.find(w => w.phase === 'investigation') ?? workers[0]
        if (anchorWorker) {
          try {
            const cpFact = this.storage.addFact(run, anchorWorker, {
              kind: 'note',
              origin: step.origins[0] ?? run.candidates[0]?.origin ?? '',
              summary: `Hop checkpoint (${checkpointCapId ?? parsedBrief?.brief.branchKey ?? 'branch'})`,
              data: {
                producer: HOST_PLANNER_PRODUCER,
                source: HOST_PLANNER_PRODUCER,
                subkind: 'hop_checkpoint',
                ...(checkpointCapId ? { checkpointCapId } : {}),
                ...(checkpointJson ? { checkpointJson } : {}),
                ...(parsedBrief ? { checkpointBrief: parsedBrief.brief } : {}),
              },
              sourceOrigins: step.origins,
            })
            finalFactIds.push(cpFact.id)
          } catch (err) {
            this.noteLifecycleWarning(run.id, 'persistDispatchPlan.hop_checkpoint_fact', err, { checkpointCapId })
          }
        }
      }
      const resolvedPriority = options.preservePriority
        ? step.priority
        : tierABound ? TIER_A_STEP_PRIORITY : leadBound ? Math.min(step.priority, DET_LEAD_STEP_PRIORITY) : step.priority
      const structuredTargets: StructuredStepTarget[] = []
      const nextGoal = parsedBrief?.brief.nextGoal
      if (nextGoal?.endpoint) {
        structuredTargets.push({
          origin: nextGoal.service || step.origins[0] || '',
          method: nextGoal.method || 'ANY',
          route: nextGoal.endpoint,
          vulnClass: nextGoal.hypothesisClass || category,
        })
      }
      for (const hop of step.chainHops ?? []) {
        if (hop.endpoint) {
          structuredTargets.push({
            origin: hop.origin || step.origins[0] || '',
            method: 'ANY',
            route: hop.endpoint,
            vulnClass: category,
          })
        }
      }
      if (!structuredTargets.length) {
        const inferredRoutes = templatesMentionedInText(`${title} ${step.hypothesis}`)
        for (const origin of step.origins) {
          for (const route of inferredRoutes.length ? inferredRoutes : ['/']) {
            structuredTargets.push({ origin, method: 'ANY', route, vulnClass: category })
          }
        }
      }
      const shouldAdmitFrontier = Boolean(checkpointCapId || parsedBrief || depStepIds.length > 0 || step.chainHops?.length)
      if (shouldAdmitFrontier) {
        const frontierController = this.frontierControllerFor(run.id)
        const primaryTarget = structuredTargets[0]
        const branchDepth = parsedBrief?.brief.depth
          ?? Math.max(1, (step.chainHops?.length ?? 0) + (depStepIds.length > 0 ? 1 : 0))
        const branchAdmission = frontierController.admitStepBranch({
          branchKey: parsedBrief?.brief.branchKey ?? `dispatch:${step.id ?? key.slice(0, 48)}`,
          depth: branchDepth,
          origin: primaryTarget?.origin || step.origins[0] || 'unknown',
          endpoint: primaryTarget?.route || '/',
          method: primaryTarget?.method || 'ANY',
          hypothesisClass: primaryTarget?.vulnClass || category,
          goalSummary: title,
          ...(checkpointCapId ? { capabilityId: checkpointCapId } : {}),
          ...(parsedBrief?.brief.capabilityHandles?.length ? { preconditionCapIds: parsedBrief.brief.capabilityHandles } : {}),
          waveNo: Math.max(1, run.roundNo || 1),
        })
        if (!branchAdmission.admitted) {
          counts.filteredDedupe += 1
          try {
            this.storage.event(
              run.id,
              'frontier.branch_suppressed',
              `FrontierWaveController suppressed dispatch branch "${title}" (dead-end negative edge).`,
              { branchKey: branchAdmission.branchKey, category },
            )
          } catch (err) {
            this.noteLifecycleWarning(run.id, 'persistDispatchPlan.branch_suppressed', err)
          }
          continue
        }
      }
      const createdStep = this.storage.addChainStep(run, {
        title: title.slice(0, 200),
        hypothesis: step.hypothesis,
        category,
        priority: resolvedPriority,
        targetAssetIds: assetIds,
        skills: stepSkills,
        dependsOnFactIds: finalFactIds,
        ...(depStepIds.length ? { dependsOnStepIds: depStepIds } : {}),
        sourceOrigins: effectiveOrigins,
        specialistProfile: routeStepToSpecialist({ title, hypothesis: step.hypothesis, category, skills: step.skills }),
      })
      if (depStepIds.length > 0 && (createdStep.status === 'pending' || createdStep.status === 'blocked')) {
        const existingById = new Map(existing.map(s => [s.id, s]))
        const allParentsContinuable = depStepIds.every(sid => {
          const parent = existingById.get(sid)
          return Boolean(parent && isContinuableStepStatus(parent.status))
        })
        if (allParentsContinuable) {
          this.storage.updateChainStep(createdStep.id, { status: 'ready' })
        }
      }
      this.registerStepTargets(run.id, createdStep.id, structuredTargets)
      if (checkpointCapId || checkpointJson) {
        this.trackRunLifecycle(run.id)
        this.persistedStepCheckpoints.set(createdStep.id, {
          ...(checkpointCapId ? { checkpointCapId } : {}),
          ...(checkpointJson ? { checkpointJson } : {}),
        })
        const stepIds = this.stepIdsByRun.get(run.id) ?? new Set<string>()
        stepIds.add(createdStep.id)
        this.stepIdsByRun.set(run.id, stepIds)
      }
      titles.add(key)
      addStepTuplesToInFlightSet(inFlightTuples, {
        title,
        hypothesis: step.hypothesis,
        category,
        origins: step.origins,
      })
      counts.enqueued += 1
    }
    return counts
  }

  /**
   * Automatically enqueue ONE bounded Hop-Continuation `chain` step when a multi-hop worker exits
   * with `wall_clock_rotated`, has not yet confirmed a finding, and made concrete progress
   * (`>= 1` fact, exchange, or sealed `cap:hop_*` handle in `CapabilityLedger`). Reuses the exact
   * `persistDispatchPlan` / `v8.hop_checkpoint.v1` `<= 2 KB` SQLite checkpoint mechanism.
   */
  enqueueHopContinuationOnRotation(input: EnqueueHopContinuationInput): EnqueueHopContinuationResult {
    const { run, step, assignment } = input
    const allowNonChainSealedExit = input.trigger === 'sealed_handle_exit'
      && Boolean(input.allowNonChainWithSealedCap)
      && input.sealedCapHandles.length > 0
    const hasWorkflowConcreteProgress = input.sealedCapHandles.length > 0
      || input.recordedFacts.length > 0
      || input.recordedExchanges.some(ex => ex.status > 0 && ex.status !== 404)
    const allowWorkflowRotation = input.trigger === 'wall_clock_rotated'
      && isPersistentWorkflowContinuationStep(step)
      && hasWorkflowConcreteProgress
    if (!isMultiHopChainStep(step) && !allowNonChainSealedExit && !allowWorkflowRotation) {
      return { enqueued: false, reason: 'not_multi_hop_chain' }
    }
    if (input.confirmed) {
      return { enqueued: false, reason: 'already_confirmed' }
    }
    const requestedMax = Math.max(0, Math.floor(input.maxContinuations ?? MAX_CHAIN_CONTINUATIONS))
    const currentDepth = extractContinuationDepth(step)
    if (currentDepth >= requestedMax) {
      return { enqueued: false, reason: 'max_continuations_reached', continuationDepth: currentDepth }
    }

    const ledger = this.storage.capabilityLedger(run.id)
    const ledgerNodes = ledger.listCapabilities()
    const ledgerNodeById = new Map(ledgerNodes.map(n => [n.capId, n]))
    const factHandleMatches = input.recordedFacts.flatMap(f =>
      `${f.summary} ${JSON.stringify(f.data ?? {})}`.match(/cap:hop_[A-Za-z0-9._-]+:[A-Za-z0-9._-]+/g) ?? [],
    )
    const stepCapId = extractCheckpointCapIdFromStep(step)
    const candidateHandles = [
      ...input.sealedCapHandles,
      ...factHandleMatches,
      ...(stepCapId ? [stepCapId] : []),
    ]
      .map(h => h.trim())
      .filter(h => DERIVED_CAPABILITY_HANDLE_RE.test(h))
    const uniqueHandles = [...new Set(candidateHandles)]

    // Prefer the most recent derived sealed capability handle present in SQLite CapabilityLedger
    // for this chain lineage (excluding static_analysis / attacker_seed / cap:hop_synth:* / cap:hop_seed_*).
    const ledgerHandles = uniqueHandles.filter(id => ledgerNodeById.has(id))
    const derivedLedgerHandles = ledgerHandles.filter(id => {
      const node = ledgerNodeById.get(id)
      return Boolean(
        node
        && node.provenance !== 'static_analysis'
        && node.provenance !== 'attacker_seed'
        && !id.startsWith('cap:hop_synth:')
        && !id.startsWith('cap:hop_seed_'),
      )
    })

    // Cap unsealed / generic heuristic chains at 1 continuation; lift the cap to `requestedMax`
    // whenever `hasSealedLedgerCap` (`derivedLedgerHandles.length > 0`) so active multi-hop
    // chains with sealed capabilities are never prematurely cut off at 1 continuation.
    const isGenericWave1 = isGenericWave1BoundaryChainStep(step)
    const hasSealedLedgerCap = derivedLedgerHandles.length > 0
    const maxContinuations = !hasSealedLedgerCap
      ? Math.min(requestedMax, MAX_GENERIC_WAVE1_CHAIN_CONTINUATIONS)
      : requestedMax
    if (currentDepth >= maxContinuations) {
      return { enqueued: false, reason: 'max_continuations_reached', continuationDepth: currentDepth }
    }

    const hasProgress = input.recordedFacts.length > 0
      || input.recordedExchanges.length > 0
      || uniqueHandles.length > 0
    if (!hasProgress) {
      return { enqueued: false, reason: 'no_concrete_progress' }
    }

    const nextDepth = currentDepth + 1
    const existingSteps = this.storage.listChainSteps(run.id, run.goalRevision)
    const existingContinuation = existingSteps.find(s =>
      s.dependsOnStepIds.includes(step.id) && extractContinuationDepth(s) === nextDepth,
    )
    if (existingContinuation) {
      return {
        enqueued: false,
        reason: 'already_enqueued',
        continuationStep: existingContinuation,
        continuationDepth: nextDepth,
      }
    }

    // Deduplicate identical sealed handle sets on non-rotation exits so a worker that exits via
    // complete_intent / max_turns without sealing any new handle cannot loop infinitely.
    this.trackRunLifecycle(run.id)
    const stepById = new Map(existingSteps.map(s => [s.id, s]))
    let lineageRootId = step.id
    const visitedLineage = new Set<string>([step.id])
    for (let hop = 0; hop < existingSteps.length; hop += 1) {
      const cur = stepById.get(lineageRootId)
      const parentId = cur?.dependsOnStepIds.find(id => stepById.has(id) && !visitedLineage.has(id))
      if (!parentId) break
      visitedLineage.add(parentId)
      lineageRootId = parentId
    }
    const lineageKey = `${run.id}:${lineageRootId}`
    const handleSignatureList = (derivedLedgerHandles.length ? derivedLedgerHandles : uniqueHandles)
      .slice()
      .sort()
    const handleSetSignature = handleSignatureList.join('|')
    if (input.trigger === 'sealed_handle_exit' && handleSetSignature) {
      const seenSets = this.emittedSealedHandleSets.get(lineageKey)
      if (seenSets?.has(handleSetSignature)) {
        return { enqueued: false, reason: 'duplicate_sealed_handles', continuationDepth: currentDepth }
      }
      if (currentDepth >= 1) {
        const inheritedHandles = new Set<string>(stepCapId ? [stepCapId] : [])
        if (step.dependsOnFactIds.length > 0) {
          const neededFactIds = new Set(step.dependsOnFactIds)
          const allRunFacts = this.pageAll((offset, limit) =>
            this.storage.listFacts(run.id, { includeTainted: false, limit, offset }))
          const checkpointFactById = new Map<string, (typeof allRunFacts)[number]>()
          for (const f of allRunFacts) {
            if (neededFactIds.has(f.id) && f.data?.subkind === 'hop_checkpoint') {
              checkpointFactById.set(f.id, f)
            }
          }
          for (const factId of step.dependsOnFactIds) {
            const cpFact = checkpointFactById.get(factId)
            const brief = parseHopCheckpointJson(cpFact?.data?.checkpointBrief ?? cpFact?.data?.checkpointJson)
            for (const h of brief?.capabilityHandles ?? []) {
              if (DERIVED_CAPABILITY_HANDLE_RE.test(h)) inheritedHandles.add(h)
            }
          }
        }
        const incoming = input.sealedCapHandles.filter(h => DERIVED_CAPABILITY_HANDLE_RE.test(h))
        if (incoming.length > 0 && incoming.every(h => inheritedHandles.has(h))) {
          return { enqueued: false, reason: 'duplicate_sealed_handles', continuationDepth: currentDepth }
        }
      }
    }

    const primaryCapId = derivedLedgerHandles.at(-1) ?? ledgerHandles.at(-1) ?? undefined
    const allSealedHandles = [...new Set([
      ...uniqueHandles,
      ...(primaryCapId ? [primaryCapId] : []),
    ])].slice(0, 8)

    const approvedOrigins = this.host.approvedOriginsSet(run)
    const origins = [...new Set(input.targetOrigins.filter(o => approvedOrigins.has(o)))]
    if (!origins.length) {
      return { enqueued: false, reason: 'dispatch_filtered' }
    }
    const primaryOrigin = origins[0]!

    const observedEndpoints = [...new Set(
      input.recordedExchanges.map(ex => `${ex.method.toUpperCase()} ${ex.pathAndQuery.split('?')[0] || '/'} (${ex.status})`),
    )].slice(0, 6)
    const observedFactNotes = input.recordedFacts
      .map(f => sanitizeCheckpointText(f.summary, 110))
      .filter(Boolean)
      .slice(0, 4)
    const partialClean = sanitizeCheckpointText(
      input.partialSummary.replace(/^\[partial\]\s*/i, '').trim(),
      180,
    )

    const lastExchange = input.recordedExchanges[input.recordedExchanges.length - 1]
    const nextEndpoint = lastExchange ? (lastExchange.pathAndQuery.split('?')[0] || '/') : '/'
    const nextMethod = lastExchange?.method?.toUpperCase()
    const branchKey = `cont:${step.id.slice(0, 12)}:d${nextDepth}`

    const allLiveFacts = this.pageAll((offset, limit) =>
      this.storage.listFacts(run.id, { includeTainted: false, limit, offset }))
    const liveFactById = new Map(allLiveFacts.map(f => [f.id, f]))
    const liveFactIds = new Set(liveFactById.keys())
    const parentNotebooks: HopWorkflowNotebook[] = []
    for (const factId of step.dependsOnFactIds) {
      const cpFact = liveFactById.get(factId)
      if (cpFact?.data?.subkind !== 'hop_checkpoint') continue
      const parentBrief = parseHopCheckpointJson(cpFact.data.checkpointBrief ?? cpFact.data.checkpointJson)
      if (parentBrief?.workflowNotebook) parentNotebooks.push(parentBrief.workflowNotebook)
    }
    if (!parentNotebooks.length) {
      const cachedParent = parseHopCheckpointJson(this.persistedStepCheckpoints.get(step.id)?.checkpointJson)
      if (cachedParent?.workflowNotebook) parentNotebooks.push(cachedParent.workflowNotebook)
    }
    const newDiscoveredRoutes = input.recordedExchanges
      .filter(ex => ex.status > 0 && ex.status !== 404)
      .map(ex => sanitizeCheckpointText(`${ex.method.toUpperCase()} ${ex.pathAndQuery.split('?')[0] || '/'}`, 88))
    const newTriedRecipes = input.recordedExchanges.map(ex =>
      sanitizeCheckpointText(`${ex.method.toUpperCase()} ${ex.pathAndQuery.split('?')[0] || '/'} [${ex.personaHandle?.trim() || 'anon'}] -> ${ex.status}`, 110))
    const verifiedFactRe = /\b(?:verified|confirmed|succeeded|sealed|accepted|leaked|bypassed|granted)\b/i
    const newVerifiedHypotheses = [
      ...allSealedHandles.map(h => `Sealed ${h}`),
      ...input.recordedFacts
        .filter(f => f.kind === 'object_ref' || f.data?.subkind === 'chain_hop' || f.data?.verified === true || verifiedFactRe.test(f.summary))
        .map(f => sanitizeCheckpointText(f.summary, 110)),
    ]
    const verifiedSet = new Set(newVerifiedHypotheses)
    const newOpenHypotheses = [
      ...input.recordedFacts
        .map(f => sanitizeCheckpointText(f.summary, 110))
        .filter(s => s && !verifiedSet.has(s)),
      ...(partialClean && !verifiedSet.has(partialClean) ? [sanitizeCheckpointText(partialClean, 110)] : []),
    ]
    const mergeNb = (pick: (nb: HopWorkflowNotebook) => readonly string[] | undefined, extra: readonly string[], limit: number) =>
      [...new Set([...parentNotebooks.flatMap(nb => pick(nb) ?? []), ...extra].filter(Boolean))].slice(-limit)
    const mergedNotebook: HopWorkflowNotebook = {
      discoveredRoutes: mergeNb(nb => nb.discoveredRoutes, newDiscoveredRoutes, 10),
      verifiedHypotheses: mergeNb(nb => nb.verifiedHypotheses, newVerifiedHypotheses, 6),
      triedRecipes: mergeNb(nb => nb.triedRecipes, newTriedRecipes, 10),
      openHypotheses: mergeNb(nb => nb.openHypotheses, newOpenHypotheses, 6),
    }
    const workflowNotebook = (mergedNotebook.discoveredRoutes!.length || mergedNotebook.verifiedHypotheses!.length || mergedNotebook.triedRecipes!.length || mergedNotebook.openHypotheses!.length)
      ? mergedNotebook
      : undefined

    let finalizedBrief: { brief: HopCheckpointBrief; checkpointJson: string; checkpointBytes: number }
    if (primaryCapId && ledgerNodeById.has(primaryCapId)) {
      const ledgerBrief = ledger.buildHopCheckpointBrief(primaryCapId, MAX_CHECKPOINT_BRIEF_BYTES, {
        branchKey,
        mode: 'pivot',
        nextGoal: {
          surface: 'http',
          service: primaryOrigin,
          endpoint: nextEndpoint,
          ...(nextMethod ? { method: nextMethod } : {}),
          hypothesisClass: step.category || 'multi_hop_chain',
          goal: HOP_CONTINUATION_DIRECTIVE,
        },
        ...(workflowNotebook ? { workflowNotebook } : {}),
      })
      const mergedHandles = [...new Set([...ledgerBrief.capabilityHandles, ...allSealedHandles])]
        .map((h, i) => sanitizeCheckpointHandleRef(h, `cap:redacted:${i + 1}`))
      finalizedBrief = finalizeHopCheckpointBrief({
        ...ledgerBrief,
        depth: Math.max(ledgerBrief.depth, nextDepth),
        targetHop: Math.min(6, Math.max(ledgerBrief.targetHop, nextDepth + 2)),
        capabilityHandles: mergedHandles,
        ...(workflowNotebook ? { workflowNotebook } : {}),
        doNotRediscover: true,
      }, MAX_CHECKPOINT_BRIEF_BYTES)
    } else {
      const fallbackHops = input.recordedExchanges.slice(-3).map((ex, idx) => ({
        hop: idx + 1,
        receiptId: sanitizeCheckpointHandleRef(`ex:${ex.id}`, `hop:${idx + 1}`),
        capId: allSealedHandles[idx]
          ? sanitizeCheckpointHandleRef(allSealedHandles[idx]!, `ref:hop_${idx + 1}`)
          : `ref:hop_${idx + 1}`,
        kind: 'state_handle' as CapabilityKind,
        surface: 'http' as CapabilitySurface,
        service: sanitizeCheckpointText(ex.origin || primaryOrigin, 48),
        tenant: 'observed',
        actor: 'worker',
        at: sanitizeCheckpointText(`${ex.method.toUpperCase()} ${ex.pathAndQuery.split('?')[0] || '/'}`, 48),
      }))
      finalizedBrief = finalizeHopCheckpointBrief({
        schema: 'v8.hop_checkpoint.v1',
        branchKey,
        depth: nextDepth,
        targetHop: Math.min(6, nextDepth + 2),
        mode: 'pivot',
        evi: 1,
        verifiedHops: fallbackHops,
        capabilityHandles: allSealedHandles.map((h, i) => sanitizeCheckpointHandleRef(h, `cap:redacted:${i + 1}`)),
        nextGoal: {
          targetSurfaceKey: `${primaryOrigin}|http|${nextEndpoint}`,
          surface: 'http',
          service: primaryOrigin,
          endpoint: nextEndpoint,
          ...(nextMethod ? { method: nextMethod } : {}),
          hypothesisClass: step.category || 'multi_hop_chain',
          goal: HOP_CONTINUATION_DIRECTIVE,
        },
        ...(workflowNotebook ? { workflowNotebook } : {}),
        doNotRediscover: true,
      }, MAX_CHECKPOINT_BRIEF_BYTES)
    }

    const baseTitle = step.title
      .replace(/\s*\[continuation\s*#\d+\]\s*$/i, '')
      .trim()
      .slice(0, 140) || 'Multi-hop chain'
    const continuationTitle = `${baseTitle} [continuation #${nextDepth}]`
    const detailParts = [
      HOP_CONTINUATION_DIRECTIVE,
      partialClean ? `Partial progress: ${partialClean}.` : '',
      allSealedHandles.length ? `Sealed handles: ${allSealedHandles.join(', ')}.` : '',
      observedEndpoints.length ? `Observed endpoints: ${observedEndpoints.join('; ')}.` : '',
      observedFactNotes.length ? `Facts: ${observedFactNotes.join(' | ')}.` : '',
    ].filter(Boolean)
    const hypothesis = `${continuationTitle} — ${detailParts.join(' ')}`.slice(0, 1200)

    const parentSkills = step.skills.filter(s =>
      !s.startsWith(CHAIN_CONTINUATION_SKILL_PREFIX) && !s.startsWith(CHECKPOINT_CAP_SKILL_PREFIX),
    )
    const skills = [...new Set([
      ...parentSkills,
      'multihop-chains',
      'chain-primitives',
      `${CHAIN_CONTINUATION_SKILL_PREFIX}${nextDepth}`,
    ])]

    // Lossless hop-continuation fact handoff: retain EVERY inherited capability/checkpoint/hop
    // parent fact first so multi-hop capability context is never truncated by a fixed slice.
    const isPriorityContinuationFact = (factId: string): boolean => {
      const f = liveFactById.get(factId)
      const subkind = typeof f?.data?.subkind === 'string' ? f.data.subkind : ''
      const kind = typeof f?.data?.kind === 'string' ? f.data.kind : ''
      return subkind === 'hop_checkpoint'
        || subkind === 'chain_hop'
        || kind === 'chain_hop'
        || kind === 'det_lead'
        || typeof f?.data?.capId === 'string'
        || typeof f?.data?.checkpointCapId === 'string'
    }
    const mergedFactCandidates = [...new Set([
      ...step.dependsOnFactIds,
      ...input.recordedFacts.map(f => f.id),
    ])].filter(id => liveFactIds.has(id))
    const priorityFactIds = mergedFactCandidates.filter(isPriorityContinuationFact)
    const remainingFactIds = mergedFactCandidates.filter(id => !isPriorityContinuationFact(id))
    const parentFactIds = [...priorityFactIds, ...remainingFactIds.slice(0, Math.max(12, 32 - priorityFactIds.length))]

    const beforeIds = new Set(existingSteps.map(s => s.id))
    const stepBudgetUsd = Math.max(0.05, Number(Math.max(0, run.budgetUsd - run.spentUsd).toFixed(4)))
    const plan: DispatchPlan = {
      dispatched: false,
      totalBudgetUsd: stepBudgetUsd,
      budgetUsd: stepBudgetUsd,
      parentEvidenceIds: parentFactIds,
      plan: [{
        id: `cont_${step.id.slice(0, 12)}_d${nextDepth}`,
        hypothesis,
        origins,
        capabilities: ['http'],
        parentEvidenceIds: parentFactIds,
        skills,
        priority: hasSealedLedgerCap
          ? Math.min(100, Math.max(step.priority, 95))
          : isGenericWave1
            ? Math.min(step.priority, 88)
            : Math.min(step.priority, 90),
        budgetUsd: stepBudgetUsd,
        ...(primaryCapId ? { checkpointCapId: primaryCapId } : {}),
        checkpointBrief: finalizedBrief.brief,
        checkpointJson: finalizedBrief.checkpointJson,
      }],
      rejected: [],
    }
    const counts = this.persistDispatchPlan(run, plan, liveFactIds, new Set(), {
      dependsOnStepIds: [step.id],
      preservePriority: true,
    })
    if (counts.enqueued === 0) {
      return { enqueued: false, reason: 'dispatch_filtered', continuationDepth: nextDepth }
    }
    const afterSteps = this.storage.listChainSteps(run.id, run.goalRevision)
    const created = afterSteps.find(s => !beforeIds.has(s.id))
    if (!created) {
      return { enqueued: false, reason: 'dispatch_filtered', continuationDepth: nextDepth }
    }
    if (handleSetSignature) {
      const seenSets = this.emittedSealedHandleSets.get(lineageKey) ?? new Set<string>()
      seenSets.add(handleSetSignature)
      this.emittedSealedHandleSets.set(lineageKey, seenSets)
    }

    try {
      this.storage.event(
        run.id,
        'worker.hop_continuation_enqueued',
        `Enqueued hop-continuation #${nextDepth} for rotated chain step "${step.title}" (${allSealedHandles.length} sealed handle(s), ${input.recordedFacts.length} fact(s), ${input.recordedExchanges.length} exchange(s)).`,
        {
          parentAssignmentId: assignment.id,
          parentStepId: step.id,
          continuationStepId: created.id,
          continuationDepth: nextDepth,
          maxContinuations,
          ...(primaryCapId ? { checkpointCapId: primaryCapId } : {}),
          checkpointBytes: finalizedBrief.checkpointBytes,
          sealedHandleCount: allSealedHandles.length,
          recordedFactCount: input.recordedFacts.length,
          recordedExchangeCount: input.recordedExchanges.length,
        },
      )
    } catch { /* telemetry is best-effort */ }

    return {
      enqueued: true,
      continuationStep: created,
      continuationDepth: nextDepth,
      ...(primaryCapId ? { checkpointCapId: primaryCapId } : {}),
      checkpointBytes: finalizedBrief.checkpointBytes,
    }
  }


  /**
   * Auto-enqueue verification steps for cross-persona or active-HTML `second_order_surface` facts,
   * skipping routes that already have a host-verified `CompositeProofReceipt` (never skipping when
   * only a single-hop non-composite finding exists on that route).
   */
  queueSecondOrderSurfaceSteps(
    run: Run,
    approvedOrigins: ReadonlySet<string>,
    allUntaintedFacts: readonly Fact[],
    existingSteps: readonly ChainStep[],
    confirmedForPlanner: readonly PlannerConfirmedRef[],
    remainingSlots: number,
    funnel: DispatchFunnelCounts,
  ): number {
    const confirmedCompositeRoutes = buildConfirmedTupleKeySets(confirmedForPlanner).compositeRoutes
    let secondOrderAutoSteps = 0
    for (const fact of allUntaintedFacts.filter(candidate =>
      candidate.data?.subkind === 'second_order_surface' && run.capabilityTier >= 1).slice(0, 20)) {
      if (secondOrderAutoSteps >= remainingSlots) break
      const marker = typeof fact.data?.marker === 'string' ? fact.data.marker : ''
      const surfacedOrigin = typeof fact.data?.surfacedOrigin === 'string' ? fact.data.surfacedOrigin : fact.origin
      const surfacedEndpoint = typeof fact.data?.surfacedEndpoint === 'string' ? fact.data.surfacedEndpoint : '/'
      const surfacedMediaType = typeof fact.data?.surfacedMediaType === 'string' ? fact.data.surfacedMediaType : ''
      const crossPersona = fact.data?.crossPersona === true
      const activeHtml = /html/i.test(surfacedMediaType)
      if (!marker || !approvedOrigins.has(surfacedOrigin) || (!crossPersona && !activeHtml)) continue
      if (existingSteps.some(step => (step.dependsOnFactIds ?? []).includes(fact.id) ||
        (step.title.includes(marker) && step.sourceOrigins.includes(surfacedOrigin)))) continue
      const asset = run.candidates.find(candidate => candidate.origin === surfacedOrigin && run.approved.includes(candidate.id))
      if (!asset) continue
      const normalizedSurfacedRoute = normalizeConfirmedRouteTemplate(surfacedEndpoint)
      if (normalizedSurfacedRoute && normalizedSurfacedRoute !== '/'
        && confirmedCompositeRoutes.has(`${surfacedOrigin}\u0000${normalizedSurfacedRoute}`)) {
        funnel.planned += 1
        funnel.filteredAlreadyConfirmed += 1
        continue
      }
      const created = this.storage.addChainStep(run, {
        title: `Second-order canary verification · ${marker} → ${new URL(surfacedOrigin).hostname}${surfacedEndpoint.slice(0, 40)}`,
        hypothesis: `Second-order canary ${marker} planted via ${String(fact.data?.injectedEndpoint ?? '/')} (param ${String(fact.data?.injectedParam ?? 'input')}, persona ${String(fact.data?.injectedPersona ?? 'anonymous')}) resurfaced on ${surfacedOrigin}${surfacedEndpoint} as persona ${String(fact.data?.surfacedPersona ?? 'anonymous')} with media type ${surfacedMediaType || 'unknown'}${crossPersona ? ' (cross-persona)' : ''}${activeHtml ? ' (active HTML render)' : ''}. Re-read the surfaced endpoint with a control persona, prove the injected marker is persisted and rendered to a different principal, then submit a ${activeHtml ? 'browser_chain' : 'http_chain'} DeclarativeReplaySpec whose probe step renders the marker verbatim and whose control step does not.`,
        category: crossPersona ? 'broken-access-control' : 'cors-client-side',
        priority: 95,
        targetAssetIds: [asset.id],
        skills: crossPersona
          ? ['oob-ssrf-browser-chain', 'bola-idor-race', 'false-positive-elimination']
          : ['client-side-xss-postmessage', 'oob-ssrf-browser-chain'],
        dependsOnFactIds: [fact.id],
        sourceOrigins: [...new Set([surfacedOrigin, fact.origin])].filter(origin => approvedOrigins.has(origin)),
        specialistProfile: crossPersona ? 'bola-bfla-specialist' : 'client-browser-dom-specialist',
      })
      this.registerStepTargets(run.id, created.id, [{
        origin: surfacedOrigin,
        method: 'GET',
        route: surfacedEndpoint,
        vulnClass: crossPersona ? 'broken-access-control' : 'cors-client-side',
      }])
      funnel.planned += 1
      funnel.enqueued += 1
      secondOrderAutoSteps += 1
    }
    return secondOrderAutoSteps
  }

  /**
   * Budget, dedupe (`(origin, normalizedRoute, classFamily)` against confirmed & in-flight steps),
   * sanitize dependencies, and enqueue planner `decision.newSteps` while keeping exact dispatch
   * funnel accounting.
   */
  applyPlannerNewSteps(input: {
    run: Run
    newSteps: ReturnType<typeof plannerResponseSchema.parse>['newSteps']
    approvedOrigins: ReadonlySet<string>
    existingSteps: readonly ChainStep[]
    dynamicStepBudget: number
    factIds: ReadonlySet<string>
    detLeadFactIds: ReadonlySet<string>
    funnel: DispatchFunnelCounts
  }): number {
    const {
      run: currentRun,
      newSteps,
      approvedOrigins: currentApproved,
      existingSteps,
      dynamicStepBudget,
      factIds,
      detLeadFactIds,
      funnel,
    } = input
    const quarantinedSet = this.getQuarantinedOriginSet(currentRun, currentApproved)
    const activeApproved = new Set([...currentApproved].filter(o => !quarantinedSet.has(o)))
    const confirmedForDispatch = this.alreadyConfirmedRefs(currentRun, 100)
    const inFlightTuples = buildInFlightTupleKeys(existingSteps)
    const remainingSlots = Math.max(0, dynamicStepBudget - existingSteps.length)
    const candidateSteps = newSteps
      .map(step => ({ ...step, origins: step.origins.filter(origin => activeApproved.has(origin)) }))
    const budgetedNewSteps = applyCrownJewelStepBudget(
      candidateSteps,
      computeHostTiers([...activeApproved], this.storage.latestThreatModel(currentRun.id, currentRun.goalRevision)?.entries),
      existingSteps,
      remainingSlots,
      { quarantinedOrigins: quarantinedSet },
    )
    // Attribute the budget gate precisely: duplicate titles and unusable origins are their own
    // funnel buckets; only the remaining drops are capacity (step-budget/crown-jewel share).
    const existingTitles = new Set(existingSteps.map(step => step.title.trim().toLowerCase()))
    const preBudgetDedupe = candidateSteps.filter(step => existingTitles.has(step.title.trim().toLowerCase())).length
    const preBudgetNoAsset = candidateSteps.filter(step => step.origins.length === 0).length
    const droppedAtBudget = Math.max(0, candidateSteps.length - budgetedNewSteps.length)
    funnel.planned += candidateSteps.length
    funnel.filteredDedupe += Math.min(preBudgetDedupe, droppedAtBudget)
    funnel.filteredNoAsset += Math.min(preBudgetNoAsset, Math.max(0, droppedAtBudget - preBudgetDedupe))
    funnel.filteredBudget += Math.max(0, droppedAtBudget - preBudgetDedupe - preBudgetNoAsset)
    // Dependency sanitisation: a planner-emitted id that does not exist can never resolve, and
    // `refreshReadyChainSteps` requires every parent fact/step to exist. Drop unknown ids at
    // enqueue so planned work cannot be stranded as a permanently `pending` step.
    const liveFactIds = new Set(factIds)
    const liveStepIds = new Set(existingSteps.map(step => step.id))
    let enqueued = 0
    for (const step of budgetedNewSteps) {
      const dupReason = this.classifyDuplicatePlannedStep(step, confirmedForDispatch, inFlightTuples)
      if (dupReason === 'already_confirmed') { funnel.filteredAlreadyConfirmed += 1; continue }
      if (dupReason === 'in_flight') { funnel.filteredDedupe += 1; continue }
      const validOrigins = step.origins.filter(origin => currentApproved.has(origin))
      const assetIds = currentRun.candidates
        .filter(candidate => validOrigins.includes(candidate.origin) && currentRun.approved.includes(candidate.id))
        .map(candidate => candidate.id)
      if (!assetIds.length) { funnel.filteredNoAsset += 1; continue }
      // v7 precision guard: a plain re-emission of the same (route, class) is capped at 2
      // investigations unless the step cites a chain primitive or parent evidence.
      const guardRoutes = this.stepMentionedRoutes(step)
      const guardKey = guardRoutes.length ? reinvestigationKey(guardRoutes[0], step.category) : ''
      if (guardKey) {
        const unlocked = step.dependsOnFactIds.length > 0 || step.dependsOnStepIds.length > 0
        const verdict = this.host.reinvestigationGuardFor(currentRun.id).record(guardKey, unlocked)
        if (!verdict.allowed) {
          this.host.noteCappedReinvestigation(currentRun, guardKey, verdict.count)
          funnel.filteredCap += 1
          continue
        }
      }
      const parentFactIds = step.dependsOnFactIds.filter(id => liveFactIds.has(id))
      const parentStepIds = step.dependsOnStepIds.filter(id => liveStepIds.has(id))
      // F2: a planner re-emission of a det_lead upgrade must not jump back above class steps.
      const leadBound = parentFactIds.some(id => detLeadFactIds.has(id)) ||
        isDetLeadDispatchStep({ title: step.title, hypothesis: step.hypothesis })
      const specialistProfile = routeStepToSpecialist({
        title: step.title, hypothesis: step.hypothesis, category: step.category, skills: step.skills,
      })
      const tierABound = parentFactIds.some(id => this.host.tierAFactIds.has(id))
      const created = this.storage.addChainStep(currentRun, {
        title: step.title, hypothesis: step.hypothesis, category: step.category,
        priority: tierABound ? TIER_A_STEP_PRIORITY : leadBound ? Math.min(step.priority, DET_LEAD_STEP_PRIORITY) : step.priority,
        targetAssetIds: assetIds, skills: step.skills, dependsOnFactIds: parentFactIds,
        dependsOnStepIds: parentStepIds, sourceOrigins: validOrigins, specialistProfile,
      })
      if (parentStepIds.length > 0 && (created.status === 'pending' || created.status === 'blocked')) {
        const existingStepById = new Map(existingSteps.map(s => [s.id, s]))
        const allParentsContinuable = parentStepIds.every(sid => {
          const parent = existingStepById.get(sid)
          return Boolean(parent && isContinuableStepStatus(parent.status))
        })
        if (allParentsContinuable) {
          this.storage.updateChainStep(created.id, { status: 'ready' })
        }
      }
      const plannedTargets: StructuredStepTarget[] = (guardRoutes.length ? guardRoutes : ['/'])
        .flatMap(route => validOrigins.map(origin => ({
          origin,
          method: 'ANY',
          route,
          vulnClass: step.category,
        })))
      this.registerStepTargets(currentRun.id, created.id, plannedTargets)
      liveStepIds.add(created.id)
      addStepTuplesToInFlightSet(inFlightTuples, {
        title: step.title,
        hypothesis: step.hypothesis,
        category: step.category,
        origins: validOrigins,
      })
      funnel.enqueued += 1
      enqueued += 1
    }
    return enqueued
  }

  /**
   * Persist newly discovered typed `ChainHop` artifacts as structured `chain_hop` facts so follow-on
   * coordinator rounds and assignment briefs consume typed hop handles instead of prompt soup.
   * Idempotent by `hopId`.
   */
  persistChainHopFacts(run: Run, hops: readonly ChainHop[], existingFacts: readonly Fact[]): Map<string, string> {
    const hopFactById = new Map<string, string>()
    for (const fact of existingFacts) {
      if (fact.tainted) continue
      const hopId = typeof fact.data?.hopId === 'string' ? fact.data.hopId : ''
      if ((fact.data?.subkind === 'chain_hop' || fact.data?.kind === 'chain_hop') && hopId) {
        hopFactById.set(hopId, fact.id)
      }
    }
    const workers = this.storage.workerList(run.id)
    const anchorWorker = workers.find(w => w.phase === 'investigation') ?? workers[0]
    if (!anchorWorker) return hopFactById
    for (const hop of hops.slice(0, 32)) {
      if (hopFactById.has(hop.hopId)) continue
      try {
        const payload = chainHopFactPayload(hop)
        const created = this.storage.addFact(run, anchorWorker, {
          kind: 'note',
          origin: hop.origin,
          summary: payload.summary,
          data: payload.data,
          evidenceIds: hop.evidenceIds,
        })
        hopFactById.set(hop.hopId, created.id)
      } catch { /* best-effort additive persistence */ }
    }
    return hopFactById
  }

  /**
   * Explicit chaining round: extract & persist typed `ChainHop` artifacts across rounds, sync them
   * into `CapabilityLedger`, plan depth 1..6 causal frontier hypotheses via `FrontierScheduler`,
   * and dispatch each with typed hop inputs + <= 2 KB hop-checkpoint briefs + parent evidence.
   */
  dispatchChainRound(
    run: Run,
    coordinator: GraphCoordinator,
    budget: number,
    factIds: ReadonlySet<string>,
    funnel?: DispatchFunnelCounts,
    snapshot?: {
      existingSteps?: readonly ChainStep[]
      existingFacts?: readonly Fact[]
      apiDependencies?: readonly CoordinatorApiDependency[]
      sourceMounted?: boolean
      hops?: readonly ChainHop[]
      llmMode?: FrontierLlmMode
    },
  ): number {
    const existing = snapshot?.existingSteps ?? this.storage.listChainSteps(run.id, run.goalRevision)
    const remaining = Math.max(0, budget - existing.length)
    if (remaining <= 0) return 0
    const roundNo = Math.max(1, run.roundNo || 1)
    const hops = snapshot?.hops ?? coordinator.extractChainHops(roundNo)
    const ledger = this.storage.capabilityLedger(run.id)
    const controller = this.frontierControllerFor(run.id)
    const llmMode: FrontierLlmMode = snapshot?.llmMode ?? (privateModelProfiles(this.storage).length > 0 ? 'agentic' : 'deterministic-no-llm')
    this.syncChainHopsToLedger(run, ledger, hops, llmMode, snapshot?.existingFacts)
    const sourceMounted = snapshot?.sourceMounted ?? (this.host.projectReposMount(run.projectId).mountedRepos.length > 0)
    const apiDependencies = snapshot?.apiDependencies ?? this.collectCoordinatorApiDependencies(run)
    const hypotheses = coordinator.planChainRound({
      hops,
      apiDependencies,
      sourceMounted,
      maxHops: 6,
      limit: Math.min(12, remaining),
      capabilityLedger: ledger,
      frontierScheduler: controller.scheduler,
      waveNo: roundNo,
    })
    let chainEnqueued = 0
    if (hypotheses.length) {
      const existingFacts = snapshot?.existingFacts ?? this.pageAll((offset, limit) =>
        this.storage.listFacts(run.id, { includeTainted: false, limit, offset }))
      const hopFactById = this.persistChainHopFacts(run, hops, existingFacts)
      const liveFactIds = new Set<string>([...factIds, ...hopFactById.values()])
      const enrichedHypotheses = hypotheses.map(hypothesis => {
        const hopFactIds = (hypothesis.chainHops ?? [])
          .map(hop => hopFactById.get(hop.hopId))
          .filter((id): id is string => Boolean(id))
        return hopFactIds.length
          ? { ...hypothesis, parentEvidenceIds: [...new Set([...hypothesis.parentEvidenceIds, ...hopFactIds])] }
          : hypothesis
      })
      const plan = coordinator.dispatchInvestigations(chainHypothesisDispatchSteps(enrichedHypotheses), { maxSteps: remaining })
      const counts = this.persistDispatchPlan(run, plan, liveFactIds)
      if (funnel) addFunnelCounts(funnel, counts)
      chainEnqueued = counts.enqueued
      this.storage.event(run.id, 'chain.round', `Chain round dispatched ${counts.enqueued} hypothesis(es) with ${hops.length} typed hop artifact(s).`, {
        hypotheses: hypotheses.length, dispatched: counts.enqueued, rejected: plan.rejected.length,
        crossOrigin: hypotheses.filter(hypothesis => hypothesis.scope === 'cross_origin').length,
        primitives: [...new Set(hypotheses.flatMap(hypothesis => hypothesis.primitiveKinds))],
        chainHopCount: hops.length, hopArtifactKinds: [...new Set(hops.map(hop => hop.artifactKind))],
        maxChainHops: hypotheses.reduce((max, h) => Math.max(max, h.hops), 0),
      })
    }
    const frontierLimit = Math.min(6, Math.max(0, remaining - chainEnqueued))
    const frontierCreated = frontierLimit > 0 && llmMode !== 'deterministic-no-llm' && hasAgenticSealedCapabilities(ledger, { llmMode })
      ? materializeCapabilityConsumerFrontierSteps(this.storage, run, {
        activeOrigins: this.activeApprovedOrigins(run, this.host.approvedOriginsSet(run)),
        llmMode, maxSteps: frontierLimit, existingSteps: chainEnqueued > 0 ? this.storage.listChainSteps(run.id, run.goalRevision) : existing,
        existingFacts: snapshot?.existingFacts, confirmedRefs: this.alreadyConfirmedRefs(run, 100), routeStep: routeStepToSpecialist,
      }) : []
    for (const step of frontierCreated) {
      const m = /->\s*consumer\s+(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s+(https?:\/\/[^\s/]+)(\/[^\s[\]]+)/i.exec(step.hypothesis)
      if (m?.[1] && m?.[2] && m?.[3]) this.registerStepTargets(run.id, step.id, [{ origin: m[2], method: m[1].toUpperCase(), route: m[3], vulnClass: step.category }])
    }
    if (frontierCreated.length && funnel) { funnel.planned += frontierCreated.length; funnel.enqueued += frontierCreated.length }
    return chainEnqueued + frontierCreated.length
  }

  /** Legacy 10-turn tool-equipped coordinator turn (Cut 1: only with `KOVO_LEGACY_HEURISTIC_PLANNER=1`; Cut 2 deletes it). */
  private async runLegacyToolPlannerTurn(run: Run, profiles: readonly ResolvedModelProfile[], task: CoordinatorTask, ctx: {
    coordinator: GraphCoordinator; roundNo: number; activeOrigins: ReadonlySet<string>; dynamicStepBudget: number
    stepsPreLlm: readonly ChainStep[]; confirmedForPlanner: readonly AlreadyConfirmedRef[]
    personas: ReadonlyArray<{ handle: string; roleLabel: string }>; openProofGaps: number
    factIds: ReadonlySet<string>; detLeadFactIds: ReadonlySet<string>; funnel: DispatchFunnelCounts; onEnqueued: () => void
  }): Promise<{ answer: string; toolDispatched: number }> {
    let toolDispatched = 0
    const handlers = coordinatorPlannerHandlers({
      coordinator: ctx.coordinator,
      onDispatch: plan => {
        try {
          const counts = this.persistDispatchPlan(this.storage.run(run.id), plan, ctx.factIds, ctx.detLeadFactIds)
          addFunnelCounts(ctx.funnel, counts)
          toolDispatched += counts.enqueued
          if (counts.enqueued > 0) ctx.onEnqueued()
        } catch (err) { this.noteLifecycleWarning(run.id, 'runChainPlanner.legacyToolDispatch', err) }
      },
    })
    const prompt = coordinatorPlannerPrompt({
      goal: run.goal, roundNo: ctx.roundNo, capabilityTier: run.capabilityTier, approvedOrigins: [...ctx.activeOrigins],
      budgetRemaining: {
        usd: Math.max(0, Number((run.budgetUsd - run.spentUsd).toFixed(4))),
        requests: run.budgetRequests === 0 ? 'unlimited' : Math.max(0, run.budgetRequests - run.spentRequests),
      },
      dynamicStepBudget: ctx.dynamicStepBudget,
      pendingOob: ctx.coordinator.queryFindings({ status: 'pending_oob', limit: 1 }).total,
      chainSteps: ctx.stepsPreLlm.map(step => ({ id: step.id, title: step.title, status: step.status })),
      alreadyConfirmed: ctx.confirmedForPlanner.slice(0, 30),
      personas: ctx.personas.map(persona => ({ handle: persona.handle, roleLabel: persona.roleLabel })),
      mountedRepos: this.host.projectReposMount(run.projectId).mountedRepos, openProofGaps: ctx.openProofGaps,
    })
    const answer = await agentTurn({
      directory: this.storage.directory, sessionId: `planner-${run.id}-r${ctx.roundNo}`,
      requestId: `planner:${run.goalRevision}:${ctx.roundNo}`, profiles: resolveProfilePoolForRole('tactical', profiles),
      scenario: 'chain-planner', roleAffinity: 'tactical', prompt, signal: task.controller.signal, maxTurns: 10, handlers,
      ...llmRunHooks(this.storage, run.id),
    })
    return { answer, toolDispatched }
  }

  async runChainPlanner(run: Run, profiles: readonly ResolvedModelProfile[], task: CoordinatorTask) {
    const fresh = this.storage.run(run.id)
    if (fresh.status === 'complete' || fresh.status === 'failed' || fresh.status === 'stopped') {
      this.clearRunState(run.id)
      return
    }
    if (fresh.status !== 'running' || fresh.phase !== 'investigation') return
    if (this.storage.checkBudgetExceeded(run.id)) return

    // Advance the planner round without a compactor: facts stay raw and paginated.
    const roundNo = fresh.roundNo + 1
    const plannerStartedAt = Date.now()
    const updated = this.storage.updateRun(fresh.id, { roundNo })
    const dynamicStepBudget = Math.min(hardChainStepsCeiling, computeDynamicStepBudget(this.storage, fresh.id))
    this.storage.updateRunDynamicStepBudget(fresh.id, dynamicStepBudget)
    this.host.noteDryStreak(fresh)
    // v7 dispatch funnel: planned → filtered* → enqueued → dispatched, from step objects only.
    const funnel = emptyDispatchFunnel(roundNo)
    const approvedOrigins = this.host.approvedOriginsSet(updated)
    const activeOrigins = this.activeApprovedOrigins(updated, approvedOrigins)
    const sourceMounted = this.host.projectReposMount(updated.projectId).mountedRepos.length > 0
    // Track B Cut 1: agentic rounds plan from the World Graph; legacy heuristic synthesizers and the
    // 10-turn tool planner stay behind `KOVO_LEGACY_HEURISTIC_PLANNER=1` (deterministic $0 floor keeps them).
    const legacyPlanner = process.env.KOVO_LEGACY_HEURISTIC_PLANNER === '1'
    const legacyHeuristics = legacyPlanner || profiles.length === 0

    // Single-snapshot per-round read cache eliminating 6+ redundant full-table DB scans per round.
    let cachedFacts: Fact[] | null = null
    let cachedSteps: ChainStep[] | null = null
    let cachedEndpoints: CoordinatorEndpoint[] | null = null
    let cachedFindings: ReturnType<CoordinatorDeps['listFindings']> | null = null
    let cachedApiDeps: CoordinatorApiDependency[] | null = null
    const getUntaintedFacts = (): Fact[] => (cachedFacts ??= this.pageAll((offset, limit) =>
      this.storage.listFacts(fresh.id, { includeTainted: false, limit, offset })))
    const getChainSteps = (): ChainStep[] => (cachedSteps ??= this.storage.listChainSteps(fresh.id, updated.goalRevision))
    const getEndpoints = (): CoordinatorEndpoint[] => (cachedEndpoints ??= this.pageAll((offset, limit) =>
      this.storage.listEndpoints(fresh.id, { limit, offset })))
    const getFindings = (): ReturnType<CoordinatorDeps['listFindings']> => (cachedFindings ??= this.listCoordinatorFindings(fresh.id))
    const getApiDeps = (): CoordinatorApiDependency[] => (cachedApiDeps ??= this.collectCoordinatorApiDependencies(updated))
    const invalidateSteps = () => { cachedSteps = null }
    const invalidateFacts = () => { cachedFacts = null }

    // v7 M2 white-box-first default: when source repos are mounted, seed Tier-A AST/RBAC/dataflow
    // leads BEFORE generic black-box floor leads or BOLA auto-steps.
    if (!this.invariantsSeededRuns.has(updated.id)) {
      try {
        await this.seedCapabilityLedgerInvariants(updated, {
          approvedOrigins,
          signal: task.controller.signal,
        })
        invalidateSteps()
        if (!sourceMounted && updated.capabilityTier > 0) {
          const addedComposites = this.promoteRuntimeCompositeWave1Steps(updated, approvedOrigins)
          funnel.planned += addedComposites
          funnel.enqueued += addedComposites
          if (addedComposites > 0) invalidateSteps()
        }
      } catch (err) { this.noteLifecycleWarning(updated.id, 'runChainPlanner.seedInvariants', err) }
    } else {
      try {
        const postSync = this.syncPostFloorRuntimeInvariants(updated, approvedOrigins, { sourceMounted })
        funnel.planned += postSync.wave1StepsCreated
        funnel.enqueued += postSync.wave1StepsCreated
        if (postSync.wave1StepsCreated > 0) invalidateSteps()
      } catch (err) { this.noteLifecycleWarning(updated.id, 'runChainPlanner.syncPostFloorRuntimeInvariants', err) }
    }
    let tierAPlannerSteps = 0
    if (sourceMounted) {
      try {
        tierAPlannerSteps = this.queueTierALeadSteps(updated, approvedOrigins, dynamicStepBudget, { sourceMounted: true })
        if (tierAPlannerSteps > 0) invalidateSteps()
      } catch (err) { this.noteLifecycleWarning(updated.id, 'runChainPlanner.queueTierALeadSteps', err) }
      funnel.planned += tierAPlannerSteps
      funnel.enqueued += tierAPlannerSteps
    }

    // v6 Phase 1: prioritized deterministic leads become upgrade assignments before the planner
    // runs, so the agentic lane never idles on confirmed routes and never loses a floor signal.
    let detLeadSteps = 0
    try {
      detLeadSteps = this.queueDetLeadUpgradeSteps(fresh, approvedOrigins, dynamicStepBudget)
      if (detLeadSteps > 0) invalidateSteps()
    } catch (err) { this.noteLifecycleWarning(fresh.id, 'runChainPlanner.queueDetLeadUpgradeSteps', err) }
    funnel.planned += detLeadSteps
    funnel.enqueued += detLeadSteps

    const initialFacts = getUntaintedFacts()
    const factIds = new Set(initialFacts.map(fact => fact.id))
    const stepsBeforeChain = getChainSteps()
    const remainingBudget = Math.max(0, dynamicStepBudget - stepsBeforeChain.length)
    const maxConcForPlan = Math.max(1, Math.min(maxWorkerConcurrency, updated.workerConcurrency || defaultWorkerConcurrency))
    const waveBufferTarget = Math.max(12, maxConcForPlan * 2)
    const coordinator = createGraphCoordinator({
      deps: this.coordinatorDeps(updated, {
        getEndpoints,
        getFacts: getUntaintedFacts,
        getFindings,
        getApiDependencies: getApiDeps,
      }),
      approvedOrigins: [...approvedOrigins],
      budgetUsd: Math.max(0, Number((updated.budgetUsd - updated.spentUsd).toFixed(4))),
      maxDispatchSteps: plannerWaveDispatchCap(maxConcForPlan, remainingBudget),
    })

    // Explicit chaining round: runs on round >= 2, and also on round 1 when Phase-0/floor already
    // yielded >= 2 composable typed ChainHop artifacts. Deterministic hypotheses dispatch *before*
    // the LLM turn so a planner failure can never leave an empty window.
    let chainSteps = 0
    const greyBoxApiDeps = !sourceMounted ? getApiDeps() : []
    const extractedHops = coordinator.extractChainHops(roundNo)
    if (roundNo >= 2 || extractedHops.length >= 2 || (!sourceMounted && (greyBoxApiDeps.length >= 1 || approvedOrigins.size >= 2)) || (profiles.length > 0 && hasAgenticSealedCapabilities(this.storage.capabilityLedger(updated.id)))) {
      try {
        chainSteps = this.dispatchChainRound(updated, coordinator, dynamicStepBudget, factIds, funnel, {
          existingSteps: stepsBeforeChain,
          existingFacts: initialFacts,
          apiDependencies: !sourceMounted ? greyBoxApiDeps : getApiDeps(),
          sourceMounted, hops: extractedHops,
          llmMode: profiles.length > 0 ? 'agentic' : 'deterministic-no-llm',
        })
        if (chainSteps > 0) {
          invalidateSteps()
          invalidateFacts()
        }
      } catch { /* additive */ }
    }

    const allSteps = getChainSteps()
    const allUntaintedFacts = getUntaintedFacts().filter(fact => approvedOrigins.has(fact.origin))
    for (const fact of allUntaintedFacts) factIds.add(fact.id)
    const detLeadFactIds = new Set(allUntaintedFacts
      .filter(fact => isTrustedHostControlFact(fact, 'det_lead'))
      .map(fact => fact.id))
    const personas = [...resolveRunPersonas(this.storage, updated.projectId, updated.approvedPersonaIds).values()]
      .map(persona => ({ handle: persona.handle, roleLabel: persona.roleLabel, originAllowlist: persona.originAllowlist }))

    // Priority #3: bounded cross-persona BOLA/IDOR matrix per discovered resource type (excluding floor-confirmed BOLA routes).
    const confirmedForPlanner = this.alreadyConfirmedRefs(updated, 100)
    const confirmedBolaRefs = confirmedForPlanner.filter(ref =>
      ref.cwe === 'CWE-639' ||
      ref.cwe === 'CWE-862' ||
      ref.cwe === 'CWE-863' ||
      confirmedCategoryFamily(ref.probeClass ?? '') === 'authz',
    )
    const confirmedBolaSets = buildConfirmedRouteSets(confirmedBolaRefs)
    let bolaAutoSteps = 0
    if (legacyHeuristics && (updated.capabilityTier < 2 || personas.length < 2)) {
      for (const origin of activeOrigins) {
        this.emitPreconditionUnmet(updated.id, {
          dedupeKey: `planner_bola:${origin}:${updated.capabilityTier < 2 ? 'tier' : 'persona_count'}`,
          origin,
          precondition: updated.capabilityTier < 2 ? 'tier' : 'persona_count',
          vulnClass: 'bola',
          required: updated.capabilityTier < 2 ? 'tier>=2' : 'personas>=2',
          observed: updated.capabilityTier < 2 ? `tier=${updated.capabilityTier}` : `personas=${personas.length}`,
          method: 'ANY',
          route: '*',
          skippedCount: 1,
          source: 'planner.bola_matrix_guard',
        })
      }
    }
    if (legacyHeuristics && updated.capabilityTier >= 2 && personas.length >= 2 && allSteps.length < dynamicStepBudget) {
      const typeGroups = new Map<string, BolaTestQueueItem[]>()
      for (const item of buildBolaTestQueue(allUntaintedFacts, personas, activeOrigins, this.storage.listResourceSamples(run.id))) {
        const remainingVariants = item.variants.filter(v =>
          (!v.destructive || updated.capabilityTier >= 3) &&
          !isRouteConfirmed({ method: v.method, path: v.endpoint }, confirmedBolaSets),
        )
        if (remainingVariants.length === 0) continue
        const filteredItem: BolaTestQueueItem = { ...item, variants: remainingVariants }
        const key = `${item.origin}\u0000${item.resourceKey}`
        typeGroups.set(key, [...(typeGroups.get(key) ?? []), filteredItem])
      }
      const perOriginSteps = new Map<string, number>()
      const candidateGroups = [...typeGroups.values()].sort((a, b) =>
        Number(b[0].ownerPersona !== 'anonymous') - Number(a[0].ownerPersona !== 'anonymous') || b.length - a.length)
      for (const itemsForType of candidateGroups) {
        if (allSteps.length + bolaAutoSteps >= dynamicStepBudget) break
        const origin = itemsForType[0].origin
        if ((perOriginSteps.get(origin) ?? 0) >= 3) continue
        const resourceKey = itemsForType[0].resourceKey
        const alreadyPlanned = allSteps.some(step => step.sourceOrigins.includes(origin) &&
          (step.title.includes(`resource:${resourceKey}`) ||
            (step.skills.includes('bola-idor-race') && /\b(?:bola|idor|cross-persona)\b/i.test(step.title))))
        if (alreadyPlanned) continue
        const asset = updated.candidates.find(candidate => candidate.origin === origin && updated.approved.includes(candidate.id))
        if (!asset) continue
        const itemsForOrigin = itemsForType.slice(0, 6)
        const hasGetVariant = itemsForOrigin.some(item => item.variants.some(v => v.method.toUpperCase() === 'GET'))
        const variants = [...new Set(itemsForOrigin.flatMap(item => item.variants.map(variant =>
          `${variant.method} ${variant.endpoint}${variant.destructive ? ' (Tier 3 only)' : ''}`)))].slice(0, 8)
        const readGuidance = hasGetVariant
          ? 'Verify tenant isolation with GET first via kovo_verify(prove_access_boundary); use benign PUT/PATCH field deltas via kovo_verify(prove_persisted_mutation) only where reversible; DELETE stays Tier 3/local-lab.'
          : 'GET read on this route template is ALREADY floor-confirmed — do NOT re-submit a read-only GET proof. Test only the unconfirmed write/mutation variants above with kovo_verify(prove_persisted_mutation) using reversible benign field deltas; DELETE stays Tier 3/local-lab.'
        const createdBolaStep = this.storage.addChainStep(updated, {
          title: `Cross-persona BOLA/IDOR matrix · ${new URL(origin).hostname} · resource:${resourceKey}`,
          hypothesis: `Replay ${itemsForOrigin.length} ${resourceKey} resource(s) owned by ${itemsForOrigin[0].ownerPersona} (e.g. ${itemsForOrigin.map(item => `${item.endpoint} [${item.resourceId}]`).join(', ')}) as ${itemsForOrigin[0].testAsPersonas?.join(', ') ?? 'alternate persona & anonymous'} using bounded consumer item variants: ${variants.join(', ')}. ${readGuidance}`,
          category: 'broken-access-control',
          priority: sourceMounted && this.host.tierAStepIds.size > 0 ? 72 : 92,
          targetAssetIds: [asset.id],
          skills: ['bola-idor-race', 'false-positive-elimination'],
          dependsOnFactIds: itemsForOrigin.map(item => item.factId).filter((id): id is string => Boolean(id)),
          sourceOrigins: [origin],
          specialistProfile: 'bola-bfla-specialist',
        })
        const bolaTargets: StructuredStepTarget[] = itemsForOrigin.flatMap(item =>
          item.variants.map(v => ({
            origin,
            method: v.method.toUpperCase(),
            route: v.endpoint,
            vulnClass: 'broken-access-control',
          })),
        )
        this.registerStepTargets(updated.id, createdBolaStep.id, bolaTargets)
        funnel.planned += 1
        funnel.enqueued += 1
        bolaAutoSteps += 1
        perOriginSteps.set(origin, (perOriginSteps.get(origin) ?? 0) + 1)
      }
      if (bolaAutoSteps > 0) invalidateSteps()
    }

    // Auto-enqueue verification for each new cross-persona or active-HTML second-order surface,
    // skipping routes already confirmed by a host-verified CompositeProofReceipt.
    const secondOrderAutoSteps = !legacyHeuristics ? 0 : this.queueSecondOrderSurfaceSteps(
      updated,
      activeOrigins,
      allUntaintedFacts,
      allSteps,
      confirmedForPlanner,
      Math.max(0, dynamicStepBudget - allSteps.length - bolaAutoSteps),
      funnel,
    )
    if (secondOrderAutoSteps > 0) invalidateSteps()

    // Move O3: Gate redundant 10-turn LLM planner storms when the dispatch queue is already
    // saturated and no high-signal milestone occurred (cheap deterministic synthesis above already ran).
    const stepsPreLlm = getChainSteps()
    const unavailablePreLlm = this.unavailableOriginsForRun(updated, approvedOrigins)
    const readyPreLlm = dispatchableReadySteps(stepsPreLlm, factIds, unavailablePreLlm).length
    const activePreLlm = [...this.host.active.values()].filter(job =>
      job.assignment.runId === run.id && job.assignment.phase === 'investigation').length
    const prevFrontier = this.plannerEvidenceFrontier.get(run.id)
    const confirmedNow = coordinator.queryFindings({ status: 'confirmed', limit: 1 }).total
    const newConfirmedForGate = prevFrontier ? Math.max(0, confirmedNow - prevFrontier.confirmed) : 0
    const seenEdgesPreGate = this.plannerSeenCausalEdges.get(run.id)
    const ledgerPreGate = this.storage.capabilityLedger(run.id)
    const newCrossOriginCaps = ledgerPreGate.listCausalEdges().filter(edge => {
      if (seenEdgesPreGate?.has(edge.edgeId)) return false
      const post = edge.postconditionCapId ? ledgerPreGate.getCapability(edge.postconditionCapId) : null
      return Boolean(post && post.serviceOrigin && edge.actorContext.serviceOrigin && post.serviceOrigin !== edge.actorContext.serviceOrigin)
    }).length
    const openProofGapsPreLlm = this.storage.listOpenProofGaps(fresh.id, updated.goalRevision)
      .filter(gap => approvedOrigins.has(gap.origin)).length
    const llmGate = shouldInvokeLlmPlanner({
      roundNo,
      readyStepCount: readyPreLlm,
      activeWorkerCount: activePreLlm,
      waveBufferTarget,
      newConfirmedFindings: newConfirmedForGate,
      newCrossOriginCapabilities: newCrossOriginCaps,
      openProofGaps: openProofGapsPreLlm,
      queueEmptyOrDraining: readyPreLlm === 0 && activePreLlm === 0,
    })
    if (!llmGate.invokeLlm) {
      const deterministicAdded = tierAPlannerSteps + detLeadSteps + chainSteps + bolaAutoSteps + secondOrderAutoSteps
      const dispatchedTotal = stepsPreLlm.filter(step => step.assignedWorkerId !== null).length
      funnel.dispatched = dispatchedTotal
      funnel.dispatchedThisRound = Math.max(0, dispatchedTotal - (this.host.dispatchFunnels.get(run.id)?.dispatched ?? 0))
      funnel.remainingReady = readyPreLlm
      funnel.stopReason = 'running'
      this.host.recordDispatchFunnel(run.id, funnel)
      try {
        this.storage.event(
          run.id,
          'planner.llm_gated',
          `Deferred LLM planner round ${roundNo} (${llmGate.reason}): ${readyPreLlm} ready step(s) >= buffer ${waveBufferTarget}; deterministic synthesis added ${deterministicAdded} step(s).`,
          {
            roundNo,
            reason: llmGate.reason,
            readyStepCount: readyPreLlm,
            activeWorkerCount: activePreLlm,
            waveBufferTarget,
            deterministicAdded,
          },
        )
      } catch { /* telemetry is best-effort */ }
      this.host.tracePlannerDecision(run.id, {
        roundIdx: roundNo,
        factsCount: allUntaintedFacts.length,
        detLeadsCount: detLeadFactIds.size,
        alreadyConfirmedCount: confirmedForPlanner.length,
        spawnedSteps: deterministicAdded,
        k6DryStreak: 0,
        dynamicStepBudget,
        durationMs: Math.max(0, Date.now() - plannerStartedAt),
        costUsd: 0,
        summary: `llm_gated:${llmGate.reason} (ready=${readyPreLlm}/${waveBufferTarget})`,
      })
      return
    }

    // v7 precision guard: remember the evidence frontier across rounds. A round that adds no
    // runtime_confirmed finding and no chain primitive is dry; two consecutive dry rounds after the
    // high-priority queue drains end the planner.
    const evidenceFrontier = prevFrontier ?? { confirmed: confirmedNow, primitives: coordinator.deriveChainPrimitives().length }
    let toolDispatched = 0
    let plan: LlmPlannerDecision
    if (legacyPlanner) {
      const legacy = await this.runLegacyToolPlannerTurn(updated, profiles, task, {
        coordinator, roundNo, activeOrigins, dynamicStepBudget, stepsPreLlm, confirmedForPlanner, personas,
        openProofGaps: openProofGapsPreLlm, factIds, detLeadFactIds, funnel, onEnqueued: invalidateSteps,
      })
      toolDispatched = legacy.toolDispatched
      plan = decidePlannerAnswer(legacy.answer, Number.MAX_SAFE_INTEGER)
    } else {
      // Pure-fact World Graph (read-only, bounded) -> one tool-free planner turn or the $0 floor.
      const worldGraph = collectWorldGraphFromStore(this.storage, updated, {
        approvedOrigins: [...activeOrigins], confirmedRefs: confirmedForPlanner,
        programGraph: sourceMounted ? this.coordinatorProgramGraph(getEndpoints()) : null,
        onWarning: (stage, err) => this.noteLifecycleWarning(run.id, `runChainPlanner.worldGraph.${stage}`, err),
      })
      plan = await planWithWorldGraph({
        ...llmRunHooks(this.storage, run.id), goal: updated.goal, roundNo, snapshot: worldGraph,
        snapshotJson: serializeWorldGraph(worldGraph, 4096), approvedOrigins: [...activeOrigins], profiles,
        remainingStepCap: Math.max(0, dynamicStepBudget - stepsPreLlm.length), signal: task.controller.signal,
      })
    }
    if (!this.host.currentCoordinator(run.id, task)) return
    // Invalidate cached findings/facts/steps after the async LLM session in case workers updated the DB.
    cachedFacts = null
    cachedSteps = null
    cachedFindings = null

    if (plan.parseError) {
      try {
        this.storage.event(run.id, 'planner_parse_failed', `Planner response failed ${plan.parseError.stage} parsing on round ${roundNo}: ${plan.parseError.message}`, {
          roundNo, stage: plan.parseError.stage, error: plan.parseError.message, rawLength: plan.rawLength,
          rawPreview: plan.rawPreview, plannerMode: plan.mode, degradation: true,
        })
      } catch (err) { this.noteLifecycleWarning(run.id, 'planner_parse_failed.event', err, { roundNo }) }
    }
    const currentRun = this.storage.run(run.id)
    const currentApproved = this.host.approvedOriginsSet(currentRun)
    const existingSteps = this.storage.listChainSteps(run.id, currentRun.goalRevision)
    let addedCount = tierAPlannerSteps + detLeadSteps + chainSteps + bolaAutoSteps + secondOrderAutoSteps + toolDispatched

    for (const cancelId of plan.cancelStepIds) {
      const target = existingSteps.find(step => step.id === cancelId)
      if (target && ['pending', 'ready'].includes(target.status)) this.storage.updateChainStep(target.id, { status: 'canceled' })
    }
    funnel.planned += plan.droppedSteps
    funnel.filteredBudget += plan.droppedSteps
    addedCount += this.applyPlannerNewSteps({
      run: currentRun, newSteps: plan.newSteps, approvedOrigins: currentApproved, existingSteps, dynamicStepBudget, factIds, detLeadFactIds, funnel,
    })
    // Round-1 2-wave pipeline top-up: ensure Wave 1 + Wave 2 stay buffered when uncovered
    // high-risk routes remain so fast workers never sit idle waiting for Round 2.
    if (roundNo === 1 && funnel.enqueued < waveBufferTarget) {
      const stepsAfterRound1 = this.storage.listChainSteps(run.id, currentRun.goalRevision)
      const topUp = this.queueHighRiskCoverageSteps(
        currentRun, currentApproved, dynamicStepBudget, stepsAfterRound1, waveBufferTarget - funnel.enqueued,
      )
      if (topUp.seeded > 0) {
        funnel.planned += topUp.seeded
        funnel.enqueued += topUp.seeded
        addedCount += topUp.seeded
        try {
          this.storage.event(
            run.id, 'planner.wave_topup',
            `Round-1 2-wave buffer topped up ${topUp.seeded} uncovered high-risk route(s) (target ${waveBufferTarget}).`,
            { roundNo, seeded: topUp.seeded, waveBufferTarget, endpoints: topUp.endpoints },
          )
        } catch { /* telemetry is best-effort */ }
      }
    }

    // Deterministic scheduler guard outside the LLM: budget/requests/wall/K=2/done+pending OOB.
    const emptyRounds = addedCount === 0 ? (this.plannerEmptyRounds.get(run.id) ?? 0) + 1 : 0
    this.plannerEmptyRounds.set(run.id, emptyRounds)
    const chainPrimitivesAfterRound = coordinator.deriveChainPrimitives().length
    const confirmedAfterRound = coordinator.queryFindings({ status: 'confirmed', limit: 1 }).total
    const newChainPrimitives = Math.max(0, chainPrimitivesAfterRound - evidenceFrontier.primitives)
    const newRuntimeConfirmed = Math.max(0, confirmedAfterRound - evidenceFrontier.confirmed)
    this.plannerEvidenceFrontier.set(run.id, {
      confirmed: confirmedAfterRound,
      primitives: chainPrimitivesAfterRound,
    })
    const completedInvestigations = this.storage.workerList(run.id)
      .filter(w => w.phase === 'investigation' && (w.status === 'complete' || w.status === 'failed')).length
    const previousCompletedInvestigations = this.plannerCompletedAtLastRound.get(run.id) ?? completedInvestigations
    this.plannerCompletedAtLastRound.set(run.id, completedInvestigations)

    // v8 M3 frontier-progress accounting: inspect CapabilityLedger for newly recorded host-verified
    // causal hop receipts expanding tenant/role/service/surface reach even before terminal confirmation.
    const frontierController = this.frontierControllerFor(run.id)
    const seenEdges = this.plannerSeenCausalEdges.get(run.id) ?? new Set<string>()
    this.plannerSeenCausalEdges.set(run.id, seenEdges)
    const ledgerForProgress = this.storage.capabilityLedger(run.id)
    const newHopEvents: VerifiedHopReceiptEvent[] = []
    for (const edge of ledgerForProgress.listCausalEdges()) {
      if (seenEdges.has(edge.edgeId)) continue
      seenEdges.add(edge.edgeId)
      const postNode = edge.postconditionCapId ? ledgerForProgress.getCapability(edge.postconditionCapId) : null
      const rawTenant = postNode?.tenantScope ?? edge.actorContext.tenantScope ?? ''
      const normalizedTenant = rawTenant === 'unscoped_hypothesis' ? '' : rawTenant
      newHopEvents.push({
        hopReceiptId: edge.hopReceiptId,
        branchKey: edge.postconditionCapId ?? edge.edgeId,
        depth: Math.max(1, edge.preconditionCapIds.length + 1),
        hostVerified: true,
        tenantScope: normalizedTenant,
        ...(edge.actorContext.roleLabel ? { roleLabel: edge.actorContext.roleLabel } : {}),
        serviceOrigin: postNode?.serviceOrigin ?? edge.actorContext.serviceOrigin ?? 'unknown',
        surface: postNode?.surface ?? 'http',
        ...(postNode ? { capabilityId: postNode.capId } : {}),
      })
    }
    const latestForProgress = this.storage.run(run.id)
    const completedSinceLastRound = Math.max(0, completedInvestigations - previousCompletedInvestigations)
    const confirmedCompositeReceipts = this.storage.listReplaySpecs(run.id)
      .filter(spec => spec.proofVerdict === 'confirmed' && Boolean((spec.proofReceipt as Record<string, unknown> | null)?.compositeVerification))
      .map(spec => spec.id)
    const frontierDecision = frontierController.evaluateWaveProgress({
      completedAssignments: completedSinceLastRound,
      confirmedCompositeReceipts,
      verifiedHopReceipts: newHopEvents,
      pendingAsyncOrOob: coordinator.queryFindings({ status: 'pending_oob', limit: 1 }).total,
      budgetUsdSpent: latestForProgress.spentUsd,
      budgetUsdLimit: latestForProgress.budgetUsd,
      elapsedMs: Math.max(0, Date.now() - latestForProgress.createdAt),
      maxDurationMs: this.host.maxDurationMs,
      requestsSpent: latestForProgress.spentRequests,
      agentRequestBudget: latestForProgress.budgetRequests,
      coverageSettledCount: this.provedOrGapCodedAssignmentIds(run.id).size,
    })
    const verifiedHopReachExpansions = frontierDecision.reachDelta.newHopReceiptIds.length

    const dryRounds = nextPlannerDryRounds({
      roundNo,
      previousDryRounds: this.plannerDryRounds.get(run.id) ?? 0,
      newRuntimeConfirmed,
      newChainPrimitives,
      completedInvestigations,
      previousCompletedInvestigations,
      verifiedHopReachExpansions,
    })
    this.plannerDryRounds.set(run.id, dryRounds)
    const queueDrained = this.host.highPriorityQueueEmpty({
      id: run.id,
      goalRevision: this.storage.run(run.id).goalRevision,
    })
    this.storage.event(
      run.id,
      'planner.dry_rounds',
      `Planner dry-round ${dryRounds}/${DRY_ROUND_LIMIT}: ${newRuntimeConfirmed} new confirmed, ${newChainPrimitives} new chain primitive(s)${verifiedHopReachExpansions ? `, ${verifiedHopReachExpansions} verified hop reach expansion(s)` : ''}${queueDrained ? '; high-priority queue empty' : ''}.`,
      {
        consecutiveDryRounds: dryRounds,
        limit: DRY_ROUND_LIMIT,
        newRuntimeConfirmed,
        newChainPrimitives,
        verifiedHopReachExpansions,
        completedSinceLastRound: Math.max(0, completedInvestigations - previousCompletedInvestigations),
        highPriorityQueueEmpty: queueDrained,
      },
    )
    const latest = this.storage.run(run.id)
    const decision = coordinatorSchedulerDecision({
      budgetExhausted: this.storage.checkBudgetExceeded(run.id),
      budgetRequests: latest.budgetRequests,
      spentRequests: latest.spentRequests,
      startedAt: latest.createdAt,
      maxDurationMs: this.host.maxDurationMs,
      emptyRounds,
      coordinatorDone: plan.done,
      pendingOob: coordinator.queryFindings({ status: 'pending_oob', limit: 1 }).total,
      highPriorityQueueEmpty: queueDrained,
      consecutiveDryRounds: dryRounds,
      verifiedHopReachExpansions,
      frontierDecision,
      completedSinceLastRound,
    })

    // v7 coverage guard: a dry/coordinator stop must not abandon planned, dispatchable work while a
    // worker slot is free. The stop is deferred (never silently dropped) and the funnel records it.
    const finalFactIds = new Set(this.pageAll((offset, limit) =>
      this.storage.listFacts(run.id, { includeTainted: true, limit, offset })).map(fact => fact.id))
    const refreshQueueState = () => {
      const steps = this.storage.listChainSteps(run.id, latest.goalRevision)
      const unavailableOrigins = this.unavailableOriginsForRun(latest)
      return {
        steps,
        unavailableOrigins,
        remainingReady: dispatchableReadySteps(steps, finalFactIds, unavailableOrigins).length,
        coverage: this.passOneCoverageFor(run, steps),
      }
    }
    let { steps: finalSteps, unavailableOrigins: stopUnavailableOrigins, remainingReady, coverage } = refreshQueueState()
    let tierASeededAtStop = 0
    if (decision.decision === 'stop' && (coverage.uninvestigatedFirstPassClasses.length || coverage.uncoveredTierAEndpoints.length)) {
      tierASeededAtStop = this.queueTierALeadSteps(
        this.storage.run(run.id), this.host.approvedOriginsSet(run), computeDynamicStepBudget(this.storage, run.id),
      )
      if (tierASeededAtStop > 0) ({ steps: finalSteps, unavailableOrigins: stopUnavailableOrigins, remainingReady, coverage } = refreshQueueState())
    }
    const stopBudgetExhausted = this.storage.checkBudgetExceeded(run.id)
    const stopRequestExhausted = latest.budgetRequests > 0 && latest.budgetRequests - latest.spentRequests <= 0
    const stopWallExhausted = this.host.maxDurationMs > 0 && latest.createdAt + this.host.maxDurationMs <= Date.now()
    let highRiskSeededAtStop = 0
    if (decision.decision === 'stop' && !stopBudgetExhausted && !stopRequestExhausted && !stopWallExhausted) {
      const seededHighRisk = this.queueHighRiskCoverageSteps(
        this.storage.run(run.id), this.host.approvedOriginsSet(run), computeDynamicStepBudget(this.storage, run.id), finalSteps,
      )
      if (seededHighRisk.seeded > 0) {
        highRiskSeededAtStop = seededHighRisk.seeded
        funnel.planned += seededHighRisk.seeded
        funnel.enqueued += seededHighRisk.seeded
        ;({ steps: finalSteps, unavailableOrigins: stopUnavailableOrigins, remainingReady, coverage } = refreshQueueState())
        try {
          this.storage.event(
            run.id, 'planner.high_risk_coverage_assert',
            `Planner coverage assertion seeded ${seededHighRisk.seeded} uncovered high-risk route(s) before stop.`,
            { roundNo, seeded: seededHighRisk.seeded, endpoints: seededHighRisk.endpoints },
          )
        } catch { /* telemetry is best-effort */ }
      }
    }
    // An uncovered Tier-A lead with no approved asset/route binding cannot be dispatched by any
    // lane; report it loudly instead of spinning the stop guard forever.
    const tierAUnseedable = coverage.uncoveredTierAEndpoints.length > 0 &&
      coverage.uninvestigatedFirstPassClasses.length === 0 &&
      tierASeededAtStop === 0
    if (tierAUnseedable) {
      try {
        this.storage.event(
          run.id,
          'planner.tier_a_unseedable',
          `${coverage.uncoveredTierAEndpoints.length} Tier-A endpoint(s) have no dispatchable step (no approved asset or route binding).`,
          { endpoints: coverage.uncoveredTierAEndpoints.slice(0, 8) },
        )
      } catch { /* telemetry is best-effort */ }
    }
    const dispatchedTotal = finalSteps.filter(step => step.assignedWorkerId !== null).length
    const maxConc = Math.max(1, Math.min(maxWorkerConcurrency, latest.workerConcurrency || defaultWorkerConcurrency))
    const activeForRun = [...this.host.active.values()].filter(job =>
      job.assignment.runId === run.id && job.assignment.phase === 'investigation').length
    const stopEval = evaluateDispatchStop({
      decision: decision.decision,
      reason: decision.reason,
      remainingReady,
      freeSlots: Math.max(0, maxConc - activeForRun),
      inFlight: activeForRun,
      budgetExhausted: stopBudgetExhausted,
      requestExhausted: stopRequestExhausted,
      wallExhausted: stopWallExhausted,
      uninvestigatedFirstPassClasses: tierAUnseedable ? [] : coverage.uninvestigatedFirstPassClasses,
      uncoveredTierAEndpoints: tierAUnseedable ? [] : coverage.uncoveredTierAEndpoints,
    })
    if (stopEval.deferred) {
      this.storage.event(
        run.id,
        'planner.stop_deferred',
        `Planner ${decision.reason} stop deferred: ${remainingReady} dispatchable step(s) still queued for ${Math.max(0, maxConc - activeForRun)} free slot(s).`,
        { roundNo, stopReason: decision.reason, remainingReady, freeSlots: Math.max(0, maxConc - activeForRun) },
      )
    }
    if (stopEval.decision === 'stop') this.host.plannerDoneRound.set(run.id, roundNo)
    funnel.dispatched = dispatchedTotal
    funnel.dispatchedThisRound = Math.max(0, dispatchedTotal - (this.host.dispatchFunnels.get(run.id)?.dispatched ?? 0))
    funnel.remainingReady = remainingReady
    funnel.remainingReadyAtStop = stopEval.decision === 'stop' ? remainingReady : 0
    funnel.stopReason = stopEval.decision === 'stop' ? stopEval.stopReason : 'running'
    funnel.filteredDep = permanentlyBlockedStepIds(finalSteps, finalFactIds, stopUnavailableOrigins).length
    const filteredByReason = {
      alreadyConfirmed: funnel.filteredAlreadyConfirmed,
      cap: funnel.filteredCap,
      dep: funnel.filteredDep,
      dedupe: funnel.filteredDedupe,
      noAsset: funnel.filteredNoAsset,
      budget: funnel.filteredBudget,
    }
    const stopped = stopEval.decision === 'stop'
    const coverageAtStop = {
      stopReason: funnel.stopReason,
      uncoveredTierAEndpointsAtStop: stopped ? coverage.uncoveredTierAEndpoints.length : 0,
      uninvestigatedFirstPassClassesAtStop: stopped ? coverage.uninvestigatedFirstPassClasses.length : 0,
      filteredByReason,
      ...(tierASeededAtStop > 0 ? { tierASeededAtStop } : {}),
      ...(highRiskSeededAtStop > 0 ? { highRiskSeededAtStop } : {}),
      ...(tierAUnseedable ? { tierAUnseedable: true } : {}),
    }
    if (stopped) {
      try {
        this.storage.event(
          run.id,
          'planner.coverage_at_stop',
          `Stop ${funnel.stopReason}: Tier-A uncovered ${coverageAtStop.uncoveredTierAEndpointsAtStop}, first-pass uninvestigated ${coverageAtStop.uninvestigatedFirstPassClassesAtStop}, remaining ready ${funnel.remainingReadyAtStop}.`,
          {
            ...coverageAtStop,
            remainingReadyAtStop: funnel.remainingReadyAtStop,
            tierAExamples: coverage.uncoveredTierAEndpoints.slice(0, 6),
            firstPassExamples: coverage.uninvestigatedFirstPassClasses.slice(0, 6),
          },
        )
      } catch { /* telemetry is best-effort */ }
    }
    if (stopEval.stranded) {
      this.host.noteStrandedReadySteps(run.id, {
        roundNo, stopReason: stopEval.stopReason, remainingReady,
        dispatched: dispatchedTotal, planned: funnel.planned,
      })
    }
    this.host.recordDispatchFunnel(run.id, funnel)
    this.storage.event(
      run.id,
      'planner.funnel',
      `Dispatch funnel r${roundNo}: planned ${funnel.planned}, enqueued ${funnel.enqueued}, dispatched ${funnel.dispatched}, ready ${funnel.remainingReady}, stop ${funnel.stopReason}.`,
      { ...funnel, filtered: filteredByReason, coverage: coverageAtStop },
    )

    this.host.tracePlannerDecision(run.id, {
      roundIdx: roundNo, factsCount: allUntaintedFacts.length, detLeadsCount: detLeadSteps,
      alreadyConfirmedCount: funnel.filteredAlreadyConfirmed, spawnedSteps: addedCount, k6DryStreak: emptyRounds,
      dynamicStepBudget, durationMs: Date.now() - plannerStartedAt,
      costUsd: Math.max(0, Number((this.storage.run(run.id).spentUsd - updated.spentUsd).toFixed(6))),
    })
    this.storage.event(run.id, 'planner.round', `Planner round ${roundNo}: added ${addedCount} steps.`, {
      roundNo, addedCount, chainSteps, bolaAutoSteps, secondOrderAutoSteps, detLeadSteps, toolDispatched,
      done: plan.done, plannerMode: plan.mode, providerCalls: plan.providerCalls, worldGraphBytes: plan.snapshotBytes,
      decision: stopEval.decision, reason: stopEval.decision === 'stop' ? decision.reason : 'continue',
      terminationReason: stopEval.decision === 'stop' ? decision.reason : null,
      deferredStopReason: stopEval.deferred ? decision.reason : null,
      consecutiveDryRounds: dryRounds,
      highPriorityQueueEmpty: queueDrained,
      cappedReinvestigations: this.host.reinvestigationGuardFor(run.id).cappedCount(),
      funnel: {
        planned: funnel.planned, enqueued: funnel.enqueued, dispatched: funnel.dispatched,
        remainingReady: funnel.remainingReady, remainingReadyAtStop: funnel.remainingReadyAtStop,
        filteredCap: funnel.filteredCap, filteredDep: funnel.filteredDep,
        filteredAlreadyConfirmed: funnel.filteredAlreadyConfirmed, stopReason: funnel.stopReason,
        coverage: coverageAtStop,
      },
      summary: plan.summary || plan.rawPreview,
    })
  }


  // --- Coordinator Chat ---

  startCoordinator(run: Run, profiles: readonly ResolvedModelProfile[]) {
    if (this.host.coordinator.has(run.id)) return
    const thread = this.storage.db.select().from(messages).where(and(
      eq(messages.runId, run.id), eq(messages.threadId, run.coordinatorId),
    )).orderBy(asc(messages.createdAt)).all()
    const answered = new Set(thread.map(item => item.replyTo))
    const next = thread.find(item => item.role === 'operator' && !answered.has(item.id) &&
      item.id !== run.reviewPlan?.goalMessageId && !item.content.startsWith('Steering hint:') &&
      this.host.shouldCoordinatorAnswer(item.content))
    if (!next) return
    this.host.resetBoardHops(run)

    const controller = new AbortController()
    const task: CoordinatorTask = { controller, goalRevision: run.goalRevision, scopeRevision: run.scopeRevision }
    this.host.coordinator.set(run.id, task)

    const detail = this.storage.runDetail(run.id)
    const history = workerHistory(run, detail.assignments)
    const currentWorkers = detail.assignments.filter(worker => !history.has(worker.id))
    const prompt = coordinatorPrompt({
      phase: run.phase,
      status: run.status,
      approved: run.approved.length,
      queued: currentWorkers.filter(w => w.status === 'queued').length,
      complete: currentWorkers.filter(w => w.status === 'complete').length,
      question: next.content,
      capabilityTier: run.capabilityTier,
      facts: detail.facts.filter(f => !f.tainted).length,
      confirmedFindings: detail.findings.filter(f => f.status === 'confirmed').length,
      pendingFindings: detail.findings.filter(f => f.status === 'pending').length,
      pendingApprovals: detail.approvals.filter(a => a.status === 'pending').length,
      spentUsd: run.spentUsd,
      budgetUsd: run.budgetUsd,
      spentRequests: run.spentRequests,
      budgetRequests: run.budgetRequests === 0 ? 'unlimited' : run.budgetRequests,
      turnsUsed: run.turnsUsed,
    })

    const runTurn = async (signal: AbortSignal) => {
      try {
        const answer = await agentTurn({
          directory: this.storage.directory,
          sessionId: run.coordinatorId,
          requestId: `${next.id}:${run.goalRevision}:${run.scopeRevision}`,
          profiles: resolveProfilePoolForRole('fast', profiles),
          scenario: 'coordinator',
          roleAffinity: 'fast',
          thinkingLevel: 'off',
          prompt,
          signal,
          ...llmRunHooks(this.storage, run.id),
        })
        if (!this.host.currentCoordinator(run.id, task)) return
        this.storage.transaction(() => {
          this.storage.message(run.id, run.coordinatorId, 'coordinator', answer, next.id)
          this.storage.event(run.id, 'coordinator.reply', 'The coordinator replied.')
        })
      } catch {
        if (!this.host.currentCoordinator(run.id, task)) return
        this.storage.transaction(() => {
          this.storage.message(run.id, run.coordinatorId, 'kovo',
            'The coordinator could not reach the model. Review the workflow for current progress.', next.id)
          this.storage.event(run.id, 'coordinator.unavailable', 'The coordinator could not complete its reply.')
        })
      } finally {
        this.host.coordinator.delete(run.id)
      }
    }

    if (this.host.spawnRunTask) {
      this.host.spawnRunTask(run.id, 'coordinator', runTurn, { controller })
    } else {
      void runTurn(controller.signal)
    }
  }

}
