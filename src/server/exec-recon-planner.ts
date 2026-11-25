import { randomUUID } from 'node:crypto'
import { existsSync, lstatSync, readdirSync, readFileSync, realpathSync, statSync } from 'node:fs'
import { extname, isAbsolute, join, relative, resolve as resolvePath, sep } from 'node:path'
import { and, asc, eq } from 'drizzle-orm'
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
import { accessPolicyReviews } from './access-policy-checks.ts'
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
  buildAssignmentBrief,
  type MissionKind,
} from './assignment-brief.ts'
import {
  BrokerCircuitOpen,
  BrokerDenied,
  type BrokerExchangeResult,
  type Grant,
  type PublicObservation,
} from './broker.ts'
import {
  CapabilityLedger,
  DERIVED_CAPABILITY_HANDLE_RE,
  computeArtifactDigest,
  finalizeHopCheckpointBrief,
  formatDerivedCapabilityHandle,
  sanitizeCheckpointHandleRef,
  sanitizeCheckpointText,
  type AddCapabilityInput,
  type CapabilityKind,
  type CapabilitySurface,
  type HopCheckpointBrief,
} from './capability-ledger.ts'
import { extractSpecDedupeFields, normalizeEndpointTemplate } from './dedupe.ts'
import { meetsBaseline, type EvidenceReview } from './evidence-checks.ts'
import {
  CHAIN_CONTINUATION_SKILL_PREFIX,
  DET_LEAD_STEP_PRIORITY,
  DRY_ROUND_LIMIT,
  FrontierWaveController,
  MAX_CHAIN_CONTINUATIONS,
  MAX_GENERIC_WAVE1_CHAIN_CONTINUATIONS,
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
  dispatchableReadySteps,
  emptyDispatchFunnel,
  evaluateDispatchStop,
  isGenericWave1BoundaryChainStep,
  extractContinuationDepth,
  formatHopCheckpointForAssignment,
  hardChainStepsCeiling,
  hostTierOrder,
  isDetLeadDispatchStep,
  isMultiHopChainStep,
  nextPlannerDryRounds,
  passOneCoverage,
  permanentlyBlockedStepIds,
  plannerResponseSchema,
  plannerWaveDispatchCap,
  prioritizeMountedSourceInitialSteps,
  readChainHopsFromFacts,
  reinvestigationKey,
  selectUncoveredHighRiskEndpoints,
  stripJsonFences,
  templatesMentionedInText,
  threatModelResponseSchema,
  type BolaTestQueueItem,
  type DispatchFunnelCounts,
  type DispatchStopReason,
  type FrontierWaveControllerOptions,
  type ReinvestigationGuard,
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
  type CoordinatorDeps,
  type CoordinatorEndpoint,
  type CoordinatorProgramGraph,
  type DispatchPlan,
  type GraphCoordinator,
} from './graph-coordinator.ts'
import {
  classifySurface,
  inferRuntimeInvariantHypotheses,
  synthesizeInvariants,
  toCapabilityLedgerSeeds,
  type CapabilitySeedRecord,
  type InvariantHypothesis,
  type PersonaSurfaceObservation,
  type RuntimeDiscoveryInput,
  type RuntimeOpenApiOperation,
  type SourceFileInput,
  type SynthesizeInvariantsResult,
  type SynthesizerMode,
} from './invariant-synthesizer.ts'
import type { LabRunner, LabTargetHandle } from './lab-runner.ts'
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
  isSharedPaasOrigin,
} from './subdomain-discovery.ts'
import type { Phase0GraphwireExtras, ProbePlanRegistry } from './probe-plan.ts'
import {
  extractProgramGraph,
  type CodeDataflowSlice,
  type CodeToRuntimeHypothesis,
  type MonorepoService,
  type ProgramGraph,
  type ServiceOriginMapping,
} from './program-graph.ts'
import type { NamedSecret } from './redact.ts'
import { responseReview } from './response-checks.ts'
import { availableReviewChecks, parseReviewPlan, reviewPlanPrompt, standardChecks } from './review-plan.ts'
import { findings, messages } from './schema.ts'
import { runVariantSweepForFinding } from './semantic-audit.ts'
import type { StaticWorkspaceSnapshot } from './static-workspace-snapshot.ts'
import type { Assignment, ChainStep, Fact, Run, Store } from './store.ts'

type Active = ExecActiveJob
type Capture = ExecCapture
type CoordinatorTask = ExecCoordinatorTask

const VALID_REFERRER_POLICIES = [
  'no-referrer', 'no-referrer-when-downgrade', 'origin', 'origin-when-cross-origin',
  'same-origin', 'strict-origin', 'strict-origin-when-cross-origin', 'unsafe-url',
] as const

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
 *  (b) `stat.isFile()` (rejects directories, FIFOs, sockets, devices),
 *  (c) bounded file size (`<= maxBytes`, default 256 KiB).
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

  let canonicalTarget: string
  try {
    canonicalTarget = realpathSync(resolvedCandidate)
  } catch {
    return null
  }
  if (!isPathStrictlyInside(canonicalRoot, canonicalTarget)) return null

  let targetStat
  try {
    targetStat = statSync(canonicalTarget)
  } catch {
    return null
  }
  if (!targetStat.isFile() || targetStat.size > maxBytes) return null
  return { realPath: canonicalTarget, size: targetStat.size }
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

const SHORT_PREFIXED_DIGIT_ID_RE = /^[a-z]{1,12}[_-][0-9a-z]*\d[0-9a-z_-]*$/i
const VERSION_OR_PROTOCOL_SEGMENT_RE = /^(?:api[_-]?v\d+|v\d+(?:[_-](?:alpha|beta|rc)\d*)?|oauth[_-]?2|http[_-]?2|2fa|utf[_-]?8|sha[_-]?256|base[_-]?64)$/i
const PREFIXED_HEX_ID_RE = /^(?:[a-z]{1,10}[_-])?[0-9a-f]{8,}$/i
const COMPACT_PREFIX_NUM_ID_RE = /^(?!sha256$|base64$|oauth2$|http2$|es20\d\d$)[a-z]{2,8}\d{3,}$/i

/**
 * Normalize concrete resource ID segments (UUIDs, numeric IDs, short prefixed IDs such as
 * `tkt_123`, `tkt-1001`, `ord_42`, `tkt_a1b2c3`, `inv_deadbeef`, and `:param`/`{param}` template
 * placeholders) to `:id` so floor-confirmed routes match template endpoints and sibling concrete IDs.
 */
export function normalizeConfirmedRouteTemplate(path?: string | null): string {
  const base = normalizeEndpointTemplate(path)
  if (!base || base === '/') return base
  const segments = base.split('/').map((seg, idx) => {
    if (idx === 0 || !seg || seg === ':id') return seg
    if (VERSION_OR_PROTOCOL_SEGMENT_RE.test(seg)) return seg
    if (
      SHORT_PREFIXED_DIGIT_ID_RE.test(seg) ||
      PREFIXED_HEX_ID_RE.test(seg) ||
      COMPACT_PREFIX_NUM_ID_RE.test(seg)
    ) {
      return ':id'
    }
    return seg
  })
  return segments.join('/') || '/'
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
}

const IN_FLIGHT_STEP_STATUSES = new Set<ChainStep['status']>(['pending', 'ready', 'running'])

/** Canonical `(origin, normalizedRoute, classFamily)` dedupe key for planner/dispatch suppression. */
export function plannerDedupeTupleKey(origin: string, route: string, categoryOrClass: string): string | null {
  const cleanOrigin = origin.trim()
  const normRoute = normalizeConfirmedRouteTemplate(route)
  if (!cleanOrigin || !normRoute || normRoute === '/') return null
  const rawClass = (categoryOrClass ?? '').trim()
  if (!rawClass) return null
  const family = confirmedCategoryFamily(rawClass)
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

function collectBoundedRepoSourceFiles(
  reposDir: string,
  mountedRepos: readonly string[],
  maxFiles = 160,
): { files: SourceFileInput[]; compose?: string } {
  const files: SourceFileInput[] = []
  let compose: string | undefined
  for (const mountedRepo of mountedRepos) {
    if (files.length >= maxFiles) break
    const repoRel = mountedRepo.replace(/^\/repos\//, '').replace(/\/+$/, '')
    const repoRoot = repoRel ? join(reposDir, repoRel) : reposDir
    if (!existsSync(repoRoot)) continue
    const stack = [repoRoot]
    while (stack.length > 0 && files.length < maxFiles) {
      const dir = stack.pop()!
      let entries: string[]
      try { entries = readdirSync(dir) } catch { continue }
      entries.sort()
      for (const entry of entries) {
        if (files.length >= maxFiles) break
        if (INVARIANT_SKIP_DIRS.has(entry)) continue
        const full = join(dir, entry)
        let st
        try { st = statSync(full) } catch { continue }
        if (st.isDirectory()) { stack.push(full); continue }
        if (!st.isFile() || st.size > 128 * 1024) continue
        const lower = entry.toLowerCase()
        if (!compose && (lower === 'docker-compose.yml' || lower === 'docker-compose.yaml' || lower === 'compose.yml' || lower === 'compose.yaml')) {
          try { compose = readFileSync(full, 'utf8') } catch { /* ignore */ }
          continue
        }
        if (!INVARIANT_SCAN_EXT.has(extname(lower))) continue
        try {
          const relPath = relative(repoRoot, full).split(sep).join('/')
          files.push({ path: repoRel ? `${repoRel}/${relPath}` : relPath, content: readFileSync(full, 'utf8') })
        } catch { /* ignore */ }
      }
    }
  }
  return { files, ...(compose ? { compose } : {}) }
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
  'Continue from verified Hop 1–2 checkpoint — DO NOT re-read source or repeat Hops 1–2; execute Hops 3–5 using the sealed handles + ctx.hmac_sign/ctx.jwt_sign/ctx.await_async and confirm end-to-end via ctx.prove_composite!'

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
}

export interface EnqueueHopContinuationResult {
  enqueued: boolean
  reason?: 'not_multi_hop_chain' | 'already_confirmed' | 'max_continuations_reached' | 'no_concrete_progress' | 'already_enqueued' | 'dispatch_filtered'
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
  private readonly plannerEmptyRounds = new Map<string, number>()
  private readonly plannerDryRounds = new Map<string, number>()
  private readonly plannerCompletedAtLastRound = new Map<string, number>()
  private readonly plannerEvidenceFrontier = new Map<string, { confirmed: number; primitives: number }>()
  private readonly frontierControllers = new Map<string, FrontierWaveController>()
  private readonly persistedStepCheckpoints = new Map<string, { checkpointCapId?: string; checkpointJson?: string }>()
  private readonly invariantsSeededRuns = new Set<string>()
  private readonly wave1InvariantChainsPromoted = new Set<string>()
  private readonly plannerSeenCausalEdges = new Map<string, Set<string>>()
  private readonly detLeadStepKeys = new Set<string>()
  private readonly detLeadGateRejected = new Set<string>()
  private readonly cappedLeadReported = new Set<string>()
  private readonly tierAStepKeys = new Set<string>()
  private get labRunner() { return this.host.labRunner }

  /** Return (or initialize) the run-scoped v8 FrontierWaveController bound to Store's CapabilityLedger. */
  frontierControllerFor(runId: string, options: Omit<FrontierWaveControllerOptions, 'ledger'> = {}): FrontierWaveController {
    let controller = this.frontierControllers.get(runId)
    if (!controller) {
      controller = new FrontierWaveController({
        ...options,
        ledger: this.storage.capabilityLedger(runId),
      })
      this.frontierControllers.set(runId, controller)
    } else {
      controller.syncNegativeEdgesFromLedger()
    }
    return controller
  }

  /**
   * Run v8 Layer-2 General Invariant Synthesis (white-box mounted source OR grey-box/black-box
   * runtime parity) and idempotently seed `CapabilityLedger` with strictly quarantined
   * (`promotionStatus: 'capability_only'`) capability nodes.
   */
  seedCapabilityLedgerInvariants(
    run: Run,
    options: SeedCapabilityLedgerInvariantsOptions = {},
  ): SeedCapabilityLedgerInvariantsResult {
    const approvedOrigins = options.approvedOrigins ?? this.host.approvedOriginsSet(run)
    const defaultOrigin = [...approvedOrigins][0] ?? 'unknown'
    const mount = this.host.projectReposMount(run.projectId)
    const reposDir = options.reposDir ?? mount.reposDir
    const mountedRepos = options.mountedRepos ?? mount.mountedRepos

    let sourceFiles: readonly SourceFileInput[] = options.sourceFiles ?? []
    let compose = options.compose
    if (!sourceFiles.length && reposDir && mountedRepos.length > 0) {
      const collected = collectBoundedRepoSourceFiles(reposDir, mountedRepos)
      sourceFiles = collected.files
      compose = compose ?? collected.compose
    }

    const hasWhiteBoxSource = Boolean(options.graph || sourceFiles.length > 0)
    const specs = options.specs ?? this.storage.listProjectSpecsFull(run.projectId)
    const hasGreyBoxContext = run.approvedPersonaIds.length > 0 || specs.length > 0
    const mode: SynthesizerMode = options.mode
      ?? (hasWhiteBoxSource ? 'white-box' : hasGreyBoxContext ? 'grey-box' : 'black-box')

    let graph = options.graph
    if (mode === 'white-box' && !graph && sourceFiles.length > 0) {
      graph = extractProgramGraph({ files: sourceFiles, repo: mountedRepos[0] ?? 'mounted-repo' })
    }

    // Build grey-box / black-box runtime parity input from persisted endpoints, specs, and exchanges.
    const runtimeInput: Omit<RuntimeDiscoveryInput, 'mode'> = options.runtime ?? this.collectRuntimeDiscoveryInput(run, approvedOrigins, specs)

    let synthesis: SynthesizeInvariantsResult
    if (mode === 'white-box' && graph) {
      synthesis = synthesizeInvariants({
        mode: 'white-box',
        graph,
        sourceFiles,
        services: options.services,
        serviceOrigins: options.serviceOrigins,
        compose,
        ingress: options.ingress,
        runtime: runtimeInput,
        totalRunBudgetUsd: run.budgetUsd,
        maxHypotheses: options.maxHypotheses ?? 64,
      })
    } else {
      const parity = inferRuntimeInvariantHypotheses({
        mode: mode === 'black-box' ? 'black-box' : 'grey-box',
        ...runtimeInput,
        maxHypotheses: options.maxHypotheses ?? 64,
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
      const input = seedRecordToLedgerInput(seed, defaultOrigin)
      capIdByHypothesisId.set(seed.metadata.hypothesisId, input.capId)
      if (ledger.getCapability(input.capId)) {
        capIds.push(input.capId)
        continue
      }
      try {
        const added = ledger.addCapability(input)
        capIds.push(added.capId)
        seededCount += 1
      } catch {
        // Strict fail-closed validation on malformed/secret-bearing seeds never crashes recon.
      }
    }
    this.invariantsSeededRuns.add(run.id)

    const shouldPromote = options.promoteWave1Chains !== false && run.capabilityTier > 0
    const wave1ChainStepIds = shouldPromote
      ? this.promoteInvariantHypothesesToWave1ChainSteps(run, synthesis, {
          approvedOrigins,
          capIdByHypothesisId,
          maxSteps: options.maxWave1ChainSteps ?? 6,
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
      maxSteps?: number
    } = {},
  ): string[] {
    if (run.capabilityTier <= 0) return []
    const approvedOrigins = options.approvedOrigins ?? this.host.approvedOriginsSet(run)
    if (!approvedOrigins.size) return []

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
    for (const step of existingSteps) {
      existingTitles.add(step.title.trim().toLowerCase())
      const m = /\[inv_hyp=([^\]]+)\]/.exec(step.hypothesis)
      if (m?.[1]) existingHypIds.add(m[1])
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
    const storedEndpoints = this.storage.listEndpoints(run.id, { limit: 120 })
      .filter(ep => approvedOrigins.has(ep.origin))
    const approvedList = [...approvedOrigins]
    const seenCluster = new Set<string>()
    const createdIds: string[] = []

    for (const hyp of eligible) {
      if (createdIds.length >= maxToAdd) break
      if (existingHypIds.has(hyp.id)) continue
      const clusterKey = `${hyp.kind}|${hyp.entity.toLowerCase()}|${(hyp.targetRoute ?? hyp.surface).toLowerCase()}`
      if (seenCluster.has(clusterKey)) continue

      const targetOrigins: string[] = []
      if (hyp.serviceOrigin && approvedOrigins.has(hyp.serviceOrigin)) {
        targetOrigins.push(hyp.serviceOrigin)
      }
      if (hyp.kind === 'trust_boundary_mismatch') {
        const evidenceText = `${hyp.summary} ${hyp.evidence.join(' ')}`
        for (const origin of approvedList) {
          if (targetOrigins.includes(origin)) continue
          try {
            const host = new URL(origin).host
            if (evidenceText.includes(origin) || evidenceText.includes(host)) targetOrigins.push(origin)
          } catch { /* ignore */ }
          if (targetOrigins.length >= 2) break
        }
        if (targetOrigins.length < 2 && approvedList.length >= 2) {
          for (const origin of approvedList) {
            if (!targetOrigins.includes(origin)) targetOrigins.push(origin)
            if (targetOrigins.length >= 2) break
          }
        }
      }
      if (!targetOrigins.length) targetOrigins.push(approvedList[0]!)

      const targetAssetIds = run.candidates
        .filter(c => targetOrigins.includes(c.origin) && run.approved.includes(c.id))
        .map(c => c.id)
      if (!targetAssetIds.length) continue

      const capId = options.capIdByHypothesisId?.get(hyp.id)
        ?? formatDerivedCapabilityHandle(
          'synth',
          hyp.id.replace(/[^A-Za-z0-9._-]/g, '_').replace(/^[^A-Za-z0-9]+/, '').slice(0, 60) || 'seed',
        )
      const routeRefs = [
        ...(hyp.targetRoute ? [hyp.targetRoute] : []),
        ...extractRouteRefsFromText([...hyp.evidence, ...hyp.preconditions, hyp.summary]),
      ]
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
      createdIds.push(created.id)
      existingHypIds.add(hyp.id)
      existingTitles.add(title.toLowerCase())
      seenCluster.add(clusterKey)
    }

    this.wave1InvariantChainsPromoted.add(run.id)
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
            hypothesisKinds: [...new Set(eligible.slice(0, createdIds.length).map(h => h.kind))],
          },
        )
      } catch { /* telemetry is best-effort */ }
    }
    return createdIds
  }

  /**
   * Ensure Wave-1 invariant chain steps are promoted before Phase B's first dispatch tick
   * (idempotent no-op when threat modeling already promoted them).
   */
  ensureWave1InvariantChainSteps(run: Run, approvedOrigins: ReadonlySet<string>): number {
    if (run.capabilityTier <= 0 || this.wave1InvariantChainsPromoted.has(run.id)) return 0
    const res = this.seedCapabilityLedgerInvariants(run, {
      approvedOrigins,
      promoteWave1Chains: true,
    })
    return res.wave1ChainStepsCreated
  }

  private collectRuntimeDiscoveryInput(
    run: Run,
    approvedOrigins: ReadonlySet<string>,
    specs: ReturnType<Store['listProjectSpecsFull']>,
  ): Omit<RuntimeDiscoveryInput, 'mode'> {
    const endpoints = this.storage.listEndpoints(run.id, { limit: 200 })
      .filter(ep => approvedOrigins.size === 0 || approvedOrigins.has(ep.origin))
    const openApiOperations: RuntimeOpenApiOperation[] = endpoints.map(ep => ({
      method: ep.method,
      path: ep.pathTemplate,
      serviceOrigin: ep.origin,
      ...(ep.authRequirement && !/^(?:none|public|anonymous)$/i.test(ep.authRequirement.trim())
        ? { security: [{ [ep.authRequirement.trim()]: [] }] }
        : {}),
    }))

    for (const spec of specs.slice(0, 8)) {
      if (spec.kind !== 'openapi') continue
      try {
        const parsed = JSON.parse(spec.content) as { paths?: Record<string, Record<string, { operationId?: string; security?: Array<Record<string, string[]>> }>> }
        for (const [pathKey, methods] of Object.entries(parsed.paths ?? {})) {
          if (!methods || typeof methods !== 'object') continue
          for (const [method, op] of Object.entries(methods)) {
            if (!/^(?:get|post|put|patch|delete|options|head)$/i.test(method)) continue
            openApiOperations.push({
              method: method.toUpperCase(),
              path: pathKey,
              ...(op?.operationId ? { operationId: op.operationId } : {}),
              ...(Array.isArray(op?.security) ? { security: op.security } : {}),
              ...(spec.origin ? { serviceOrigin: spec.origin } : {}),
            })
          }
        }
      } catch { /* non-JSON OpenAPI specs are handled elsewhere */ }
    }

    const personaObservations: PersonaSurfaceObservation[] = []
    try {
      const rows = this.storage.client.prepare(`
        SELECT origin, method, path_and_query AS pathAndQuery, status, persona_handle AS personaHandle, resp_headers AS respHeadersJson
        FROM broker_exchanges
        WHERE run_id = ?
        ORDER BY created_at DESC
        LIMIT 120
      `).all(run.id) as Array<{
        origin: string; method: string; pathAndQuery: string; status: number
        personaHandle: string | null; respHeadersJson: string | null
      }>
      for (const row of rows) {
        if (approvedOrigins.size > 0 && !approvedOrigins.has(row.origin)) continue
        const pathOnly = row.pathAndQuery.split(/[?#]/, 1)[0] || '/'
        let responseHeaders: Record<string, string> | undefined
        if (row.respHeadersJson) {
          try { responseHeaders = JSON.parse(row.respHeadersJson) as Record<string, string> } catch { /* ignore */ }
        }
        personaObservations.push({
          persona: row.personaHandle?.trim() || 'anonymous',
          surface: classifySurface(pathOnly, row.method),
          serviceOrigin: row.origin,
          method: row.method.toUpperCase(),
          path: pathOnly,
          status: row.status,
          ...(responseHeaders ? { responseHeaders } : {}),
          isBatch: /\/(?:batch|bulk|multi)(?:\/|$)/i.test(pathOnly),
        })
      }
    } catch { /* best-effort runtime observation scan */ }

    return { personaObservations, openApiOperations }
  }

  /** Sync extracted typed ChainHops into CapabilityLedger as quarantined capability_only nodes. */
  private syncChainHopsToLedger(ledger: CapabilityLedger, hops: readonly ChainHop[]): void {
    for (const hop of hops.slice(0, 32)) {
      const slot = hop.hopId.replace(/[^A-Za-z0-9._-]/g, '_').replace(/^[^A-Za-z0-9]+/, '').slice(0, 56) || 'hop'
      const capId = formatDerivedCapabilityHandle(`r${hop.roundNo}`, slot)
      if (ledger.getCapability(capId)) continue
      const surface: CapabilitySurface = hop.artifactKind === 'stored_write_handle' ? 'browser'
        : hop.artifactKind === 'ssrf_redirect_target' ? 'webhook'
        : hop.artifactKind === 'workflow_state_handle' ? 'async_job'
        : classifySurface(hop.endpoint ?? '/', hop.method ?? 'GET')
      try {
        ledger.addCapability({
          capId,
          kind: hopKindToCapabilityKind(hop.artifactKind),
          promotionStatus: 'capability_only',
          provenance: hop.verified ? 'derived_hop' : 'runtime_discovery',
          tenantScope: 'default_tenant',
          actorPersona: hop.persona ?? 'attacker',
          serviceOrigin: hop.origin,
          surface,
          parentHopReceiptIds: hop.verified ? [hop.hopId] : [],
          artifactDigest: computeArtifactDigest(`${hop.hopId}|${hop.origin}|${hop.artifactRef}`),
          artifactSummary: hop.summary.slice(0, 220),
          metadata: {
            hopId: hop.hopId,
            roundNo: hop.roundNo,
            ...(hop.endpoint ? { endpoint: hop.endpoint } : {}),
            ...(hop.method ? { method: hop.method } : {}),
            ...(hop.factIds[0] ? { factId: hop.factIds[0] } : {}),
          },
        })
      } catch { /* ignore invalid/duplicate/secret-rejected hop mirrors */ }
    }
  }

  private approvedAsset(run: Run, origin: string): Candidate | undefined {
    return run.candidates.find(c => c.origin === origin && run.approved.includes(c.id))
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

    const freshRun = this.storage.run(run.id)
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
            // Expose the booted local-lab origin & any seeded personas into the run scope
            let scopeChanged = false
            if (!approvedOrigins.has(handle.origin)) {
              const latestForOrigin = this.storage.run(freshRun.id)
              this.storage.suggestCandidateHost(latestForOrigin, handle.origin, 'lab_runner', false)
              const withCand = this.storage.run(freshRun.id)
              const cand = withCand.candidates.find(c => c.origin === handle.origin)
              if (cand && !withCand.approved.includes(cand.id)) {
                this.storage.updateRun(freshRun.id, { approved: [...withCand.approved, cand.id] })
              }
              approvedOrigins.add(handle.origin)
              job.origins.add(handle.origin)
              scopeChanged = true
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
              const refreshed = this.host.buildGrant(job, this.storage.run(freshRun.id), approvedOrigins)
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
        // Passive CT-log + live DNS subdomain discovery for public HTTPS origins only (skipped for local-lab/localhost and shared-PaaS hosts).
        if (
          freshRun.sourceMode !== 'prepared' &&
          freshRun.capabilityTier > 0 &&
          this.storage.project(freshRun.projectId).environment === 'public'
        ) {
          try {
            const discoverableOrigins = [...approvedOrigins].filter(
              origin => !isSharedPaasOrigin(origin) && extractDiscoverableApex(origin) !== null,
            )
            if (discoverableOrigins.length > 0) {
              const subResult = await discoverSubdomainsForOrigins(discoverableOrigins, {
                signal: task.controller.signal,
              })
              if (subResult.queriedApexes.length > 0) {
                const applied = applyDiscoveredSubdomainsToRun(this.storage, freshRun.id, subResult, approvedOrigins)
                if (applied.admitted.length > 0) {
                  for (const cand of applied.admitted) {
                    if (isSharedPaasOrigin(cand.origin)) continue
                    job.origins.add(cand.origin)
                    if (!approvedAssets.some(a => a.origin === cand.origin)) {
                      approvedAssets.push(cand)
                    }
                  }
                  const refreshed = this.host.buildGrant(job, this.storage.run(freshRun.id), approvedOrigins)
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
          const reconResult = await runPhase0Recon({
            storage: this.storage,
            runId: freshRun.id,
            scopeRevision: freshRun.scopeRevision,
            tier: freshRun.capabilityTier,
            origins: [...approvedOrigins],
            budgetRequests: freshRun.budgetRequests,
            reposDir,
            personas: [...(grant.personas?.keys() ?? [])],
            broker: this.broker,
            browser: freshRun.capabilityTier >= 2 ? this.browser : undefined,
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
          }) as Awaited<ReturnType<typeof runPhase0Recon>> & Phase0GraphwireExtras
          // v6 graphwire: the ranked plan bounds probe breadth without trimming the store, and
          // AST code→runtime hypotheses become prioritized leads for the floor/agentic lane.
          this.host.probePlans.record(this.storage, freshRun.id, reconResult.probePlan)
          this.host.seedCodeToRuntimeLeads(this.storage.run(freshRun.id), claimed, reconResult.codeToRuntimeHypotheses ?? [])
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
        this.seedCapabilityLedgerInvariants(this.storage.run(freshRun.id), {
          reposDir,
          mountedRepos,
          specs,
          approvedOrigins,
          promoteWave1Chains: freshRun.capabilityTier > 0 && profiles.length > 0,
        })
      } catch {
        // Additive Layer-2 synthesis must never block threat model progression
      }

      // 2. Capture initial lightweight baseline observations for approved hosts
      const observations: Record<string, unknown>[] = []
      const selectedChecks: readonly AssessmentCheckId[] = freshRun.reviewPlan?.status === 'ready'
        ? freshRun.reviewPlan.checks : responseCheckIds
      const responseChecks = selectedChecks.filter(c => c !== 'access-policy') as ResponseCheckId[]

      for (const asset of approvedAssets) {
        if (!this.host.authorize(job)) break
        const hostWorker = this.storage.makeWorker(freshRun, 'threat_model', asset,
          `Baseline capture · ${new URL(asset.origin).hostname}`,
          'Capture initial baseline response and access-policy evidence for deterministic checks.', {
            sourceOrigins: [asset.origin],
          })
        this.storage.updateWorker(hostWorker.id, { status: 'running', lease: claimed.lease })

        let capture: Capture
        if (freshRun.sourceMode === 'prepared' || freshRun.capabilityTier === 0) {
          capture = asset.prepared
            ? { observation: { ...asset.prepared, origin: asset.origin, finalOrigin: asset.origin, source: 'supplied observation' }, note: 'Supplied project evidence.' }
            : { observation: null, note: 'No prepared observation was supplied.' }
        } else {
          try {
            const cachedPhase0Root = phase0RootExchanges.get(asset.origin)
            const priorRootRow = !cachedPhase0Root
              ? this.storage.client.prepare(
                  `SELECT id, origin, final_origin AS finalOrigin, status, media_type AS mediaType, resp_headers AS respHeadersJson
                   FROM broker_exchanges
                   WHERE run_id = ? AND origin = ? AND method = 'GET' AND path_and_query = '/'
                   ORDER BY created_at ASC LIMIT 1`,
                ).get(freshRun.id, asset.origin) as {
                  id: string
                  origin: string
                  finalOrigin: string
                  status: number
                  mediaType: string
                  respHeadersJson: string
                } | undefined
              : undefined

            const pushObs = (
              row: { finalOrigin: string; status: number; mediaType: string },
              headers: Record<string, string>,
              exchangeId?: string,
            ) => {
              observations.push({
                origin: asset.origin, finalOrigin: row.finalOrigin, status: row.status, mediaType: row.mediaType,
                server: headers['server'], poweredBy: headers['x-powered-by'], ...(exchangeId ? { exchangeId } : {}),
              })
            }
            if (cachedPhase0Root) {
              capture = { observation: cachedPhase0Root.observation, note: 'Recorded approved HTTPS root response.' }
              pushObs(cachedPhase0Root, cachedPhase0Root.respHeaders)
            } else if (priorRootRow) {
              let headersObj: Record<string, string> = {}
              try { headersObj = JSON.parse(priorRootRow.respHeadersJson) as Record<string, string> } catch { /* ignore */ }
              capture = { observation: buildObservationFromHeaders(priorRootRow, headersObj), note: 'Reused recorded approved HTTPS root response.' }
              pushObs(priorRootRow, headersObj, priorRootRow.id)
            } else {
              const ex = await this.broker.executeHttp({
                origin: asset.origin, method: 'GET', pathAndQuery: '/', followRedirects: true, timeoutMs: 12_000,
              }, grant, task.controller.signal)
              const savedEx = recordBrokerExchange(this.storage, freshRun, hostWorker.id, ex, secrets)
              capture = { observation: ex.observation, note: 'Recorded approved HTTPS root response.' }
              pushObs(ex, ex.respHeaders, savedEx.id)
            }
          } catch (error) {
            capture = {
              observation: null,
              note: error instanceof BrokerDenied || error instanceof BrokerCircuitOpen
                ? error.message : 'The approved public response could not be read.',
            }
            observations.push({ origin: asset.origin, error: capture.note })
          }
        }

        const obsArtifact = this.storage.addArtifact(
          freshRun, hostWorker, 'observation',
          freshRun.sourceMode === 'prepared' ? suppliedResponseLabel : 'Observed public response',
          JSON.stringify(capture, null, 2), 'capture:' + freshRun.scopeRevision, secrets,
        )
        const reviews = responseChecks.length ? responseReview(capture.observation, capture.note, responseChecks) : []
        const inputs = [{ artifactId: obsArtifact.id, reviews }]

        if (selectedChecks.includes('access-policy')) {
          const snapshot = asset.accessPolicy?.origin === asset.origin ? asset.accessPolicy : undefined
          const apArtifact = this.storage.addArtifact(freshRun, hostWorker, 'access-policy', 'Supplied access policy records',
            JSON.stringify({ origin: asset.origin, snapshot: snapshot ?? null }, null, 2), 'access-policy', secrets)
          inputs.push({ artifactId: apArtifact.id, reviews: accessPolicyReviews(snapshot) })
        }

        for (const { artifactId, reviews: revs } of inputs) {
          for (const rev of revs) {
            if (rev.comparison && !meetsBaseline(rev.comparison)) {
              const earlier = this.host.baselineFinding(freshRun, asset, rev)
              this.host.saveBaselineFinding(freshRun, asset, rev, 'pending',
                'The recorded value falls outside the expected policy. Verification is pending.', [artifactId], earlier?.id)
            }
          }
        }
        this.storage.updateWorker(hostWorker.id, { status: 'complete', lease: null, outcome: capture.note })
      }

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
        try {
          const auditResult = await this.host.runSourceFirstCodeAudit(
            this.storage.run(freshRun.id),
            finalEntries,
            profiles,
            task.controller.signal,
          )
          codeAuditStepsCreated = auditResult.stepsCreated.length
        } catch {
          // Code audit failure should not block live investigation rounds
        }
        try {
          const tierASeeded = this.queueTierALeadSteps(
            this.storage.run(freshRun.id),
            approvedOrigins,
            computeDynamicStepBudget(this.storage, freshRun.id),
            { sourceMounted: true },
          )
          codeAuditStepsCreated += tierASeeded
        } catch {
          // Tier-A white-box seeding is additive
        }
      }

      if (!this.host.authorize(job)) return

      // Ensure at least initial investigation steps exist when Tier >= 1.
      // When source repos are mounted, delete black-box-first overrides: generic fallback recon
      // steps never outrank white-box AST/RBAC/dataflow leads (priority capped <= 65).
      if (!seededSteps.length && freshRun.capabilityTier > 0 && approvedAssets.length > 0 && (!sourceMounted || codeAuditStepsCreated === 0)) {
        const topHosts = finalEntries.slice(0, Math.min(8, finalEntries.length))
        seededSteps = topHosts.map((entry, idx) => {
          const tier = finalHostTiers[entry.origin] ?? classifyHostTier(entry.origin, entry.surfaceTags)
          const basePriority = tier === 'low_value_static' ? 30 : Math.max(55, 95 - idx * 6)
          return {
            title: `Surface & chain investigation · ${new URL(entry.origin).hostname}`,
            hypothesis: `Harvest JS/API routes, inspect DNS/TLS/CORS/auth headers, fingerprint stack & CVEs, and verify any candidate vulnerabilities on ${entry.origin} (${entry.surfaceTags.join(', ')}).`,
            category: entry.surfaceTags.includes('auth') ? 'auth-identity'
              : entry.surfaceTags.includes('api') ? 'broken-access-control'
                : entry.surfaceTags.includes('upload') ? 'upload-storage'
                  : entry.surfaceTags.includes('llm-proxy') ? 'llm-ai-security'
                    : 'misconfig-exposure',
            priority: sourceMounted ? Math.min(basePriority, WHITEBOX_BLACKBOX_CAP_PRIORITY - 5) : basePriority,
            origins: [entry.origin],
            skills: ['recon-modern-spa', 'cve-runtime-correlation', 'false-positive-elimination'],
          }
        })
      }

      const prioritizedInitialSteps = prioritizeMountedSourceInitialSteps(
        seededSteps.map(step => ({ ...step, origins: step.origins.filter(o => approvedOrigins.has(o)) })),
        { sourceMounted, hasWhiteBoxSteps: codeAuditStepsCreated > 0, whiteBoxFactIds: this.host.tierAFactIds },
      )

      this.storage.transaction(() => {
        const current = this.storage.run(freshRun.id)
        if (current.status !== 'running' || current.phase !== 'threat_model') return

        const existingSteps = this.storage.listChainSteps(current.id, current.goalRevision)
        const remainingInitialSlots = Math.max(0, 12 - existingSteps.length)
        const budgetedSteps = applyCrownJewelStepBudget(
          prioritizedInitialSteps,
          finalHostTiers,
          existingSteps,
          remainingInitialSlots,
        )

        let addedInitial = 0
        for (const step of budgetedSteps) {
          const validOrigins = step.origins.filter(o => approvedOrigins.has(o))
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
              ? `Threat model ranked ${finalEntries.length} hosts. No model profile is configured, so Kovo Hunter will run a bounded deterministic probe pass over discovered endpoints instead of agentic investigation.`
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

    const siblingHits: Array<{ repo: string; file: string; line: number; preview: string }> = []
    const seenHit = new Set<string>()
    const overlapsOriginal = (repo: string, file: string, line: number) =>
      locs.some(l => l.repo === repo && l.file === file && line >= l.startLine - 1 && line <= l.endLine + 1)

    // 1. Fast deterministic sibling pattern sweep over mounted /repos (matches static_ast_proof ruleOrPattern or primary call signature)
    let searchTokens: string[] = []
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

    if (searchTokens.length > 0) {
      const scanExt = new Set(['.ts', '.tsx', '.js', '.jsx', '.mjs', '.cjs', '.py', '.go', '.java', '.rb'])
      const skipDirs = new Set(['node_modules', '.git', 'dist', 'build'])
      let canonicalReposRoot: string | null = null
      try { canonicalReposRoot = realpathSync(reposDir) } catch { canonicalReposRoot = null }
      for (const mountedRepo of mountedRepos) {
        if (!canonicalReposRoot) break
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
        while (stack.length > 0 && siblingHits.length < 20) {
          const dir = stack.pop()!
          let entries: string[]
          try { entries = readdirSync(dir) } catch { continue }
          for (const entry of entries) {
            if (skipDirs.has(entry)) continue
            const full = join(dir, entry)
            let lst
            try { lst = lstatSync(full) } catch { continue }
            if (lst.isSymbolicLink()) continue
            if (lst.isDirectory()) { stack.push(full); continue }
            if (!scanExt.has(extname(entry).toLowerCase())) continue
            const safeSibling = resolveSafeVariantSweepFile(canonicalRepoRoot, full, VARIANT_SWEEP_MAX_FILE_BYTES)
            if (!safeSibling) continue
            const relFile = relative(canonicalRepoRoot, safeSibling.realPath).split(sep).join('/')
            let content: string
            try { content = readFileSync(safeSibling.realPath, 'utf8') } catch { continue }
            content.split('\n').forEach((line, i) => {
              const lineNo = i + 1
              if (!searchTokens.some(tok => line.includes(tok)) || overlapsOriginal(repoRel, relFile, lineNo)) return
              const key = `${repoRel}:${relFile}:${lineNo}`
              if (seenHit.has(key)) return
              seenHit.add(key)
              siblingHits.push({ repo: repoRel, file: relFile, line: lineNo, preview: line.trim().slice(0, 180) })
            })
          }
        }
      }
    }

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
      const facts = this.storage.listFacts(run.id, { includeTainted: false, limit: 200 })
        .filter(f => f.data?.kind === 'det_lead')
      return detLeadsFromParentFacts(facts)
    } catch {
      return []
    }
  }


  /** Endpoint templates a step explicitly names (normalized). Never used for eligibility. */
  stepMentionedRoutes(step: Pick<ChainStep, 'title' | 'hypothesis'>): string[] {
    return [...new Set(templatesMentionedInText(`${step.title} ${step.hypothesis}`).map(normalizeConfirmedRouteTemplate))]
  }


  /** Pass-1 coverage view used by the dry-round stop guard and the stop-time telemetry. */
  passOneCoverageFor(run: Pick<Run, 'id'>, steps: readonly ChainStep[]): {
    uncoveredTierAEndpoints: string[]
    uninvestigatedFirstPassClasses: string[]
    tierAEndpoints: string[]
  } {
    const tierAEndpoints = [...new Set(this.tierALeadFacts(run).map(fact => {
      const method = typeof fact.data?.method === 'string' ? fact.data.method.toUpperCase() : 'GET'
      const endpoint = typeof fact.data?.endpoint === 'string' ? fact.data.endpoint : ''
      return `${method} ${endpoint}`
    }).filter(endpoint => endpoint.length > 0))].sort()
    const coverage = passOneCoverage({
      tierAEndpoints,
      steps: steps.map(step => {
        const routes = this.stepMentionedRoutes(step)
        return {
          id: step.id,
          dispatchable: step.status === 'ready' || step.status === 'pending',
          dispatched: step.assignedWorkerId !== null || step.status === 'complete' || step.status === 'running',
          routes,
          keys: routes.map(route => reinvestigationKey(route, step.category)),
        }
      }),
    })
    return { ...coverage, tierAEndpoints }
  }


  /**
   * Planner coverage assertion: before a dry/coordinator stop can terminate Phase B, ensure
   * discovered high-risk unconfirmed endpoints (`riskScore >= 60`) have at least one first-pass
   * investigation step queued (bounded to `min(6, remainingBudget)`).
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
      endpoints = this.storage.listEndpoints(run.id, { orderBy: 'risk', limit: 80 })
    } catch {
      return { seeded: 0, endpoints: [] }
    }
    const confirmedRefs = this.alreadyConfirmedRefs(run, 100)
    const confirmedSets = buildConfirmedRouteSets(confirmedRefs)
    const unconfirmedEndpoints = endpoints.filter(ep =>
      !isRouteConfirmed({ method: ep.method, path: ep.pathTemplate }, confirmedSets) &&
      !confirmedSets.paths.has(normalizeConfirmedRouteTemplate(ep.pathTemplate)))
    const coveredRoutes = new Set<string>()
    for (const step of existingSteps) {
      for (const route of this.stepMentionedRoutes(step)) coveredRoutes.add(route)
    }
    const candidates = selectUncoveredHighRiskEndpoints({
      endpoints: unconfirmedEndpoints,
      approvedOrigins,
      confirmedPaths: confirmedSets.paths,
      coveredRoutes,
      minRisk: 60,
      limit: cap,
      sourceMounted: this.host.projectReposMount(run.projectId).mountedRepos.length > 0,
    })
    const seededEndpoints: string[] = []
    for (const ep of candidates) {
      const asset = this.approvedAsset(run, ep.origin)
      if (!asset) continue
      const method = (ep.method || 'GET').toUpperCase()
      const title = `High-risk route coverage · ${method} ${ep.pathTemplate}`
      const hypothesis = `Discovered high-risk endpoint ${method} ${ep.pathTemplate} on ${ep.origin} (risk ${ep.riskScore}, coverage ${ep.coveragePct ?? 0}%) has no first-pass investigation yet. Probe authorization boundaries, state invariants, and input validation with control vs. variant evidence; submit a verified proof or coded record_coverage gap.`
      const category = 'broken-access-control'
      this.storage.addChainStep(run, {
        title, hypothesis, category, priority: 70, targetAssetIds: [asset.id],
        skills: ['false-positive-elimination'], dependsOnFactIds: [], sourceOrigins: [ep.origin],
        specialistProfile: routeStepToSpecialist({ title, hypothesis, category, skills: [] }),
      })
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

    const routes = this.stepMentionedRoutes(candidate).filter(route => route && route !== '/')
    if (!routes.length) return null

    const origins = [...new Set(
      (candidate.origins ?? candidate.sourceOrigins ?? [])
        .map(origin => origin.trim())
        .filter(Boolean),
    )]
    const category = candidate.category?.trim() ?? ''
    const hasDepFacts = (candidate.dependsOnFactIds?.length ?? 0) > 0
    const confirmedTuples = buildConfirmedTupleKeySets(confirmed)

    const multiHop = routes.length >= 2

    if (multiHop) {
      // Multi-hop chain step: only suppress if ALL `(origin, route, classFamily)` tuples are
      // already composite-confirmed or currently in-flight (never suppress on single-hop-only).
      if (!origins.length || !category) return null
      const tuples: string[] = []
      for (const origin of origins) {
        for (const route of routes) {
          const key = plannerDedupeTupleKey(origin, route, category)
          if (!key) return null
          tuples.push(key)
        }
      }
      if (!tuples.length) return null
      if (tuples.every(key => confirmedTuples.composite.has(key))) return 'already_confirmed'
      if (tuples.every(key => confirmedTuples.composite.has(key) || inFlightTuples.has(key))) return 'in_flight'
      return null
    }

    // Single-route step: tuple-scoped `(origin, normalizedRoute, classFamily)` matching.
    if (origins.length > 0 && category) {
      const tuples: string[] = []
      for (const origin of origins) {
        const key = plannerDedupeTupleKey(origin, routes[0]!, category)
        if (!key) return null
        tuples.push(key)
      }
      if (!tuples.length) return null
      if (!hasDepFacts && tuples.every(key => confirmedTuples.all.has(key))) return 'already_confirmed'
      if (tuples.every(key => confirmedTuples.composite.has(key))) return 'already_confirmed'
      if (tuples.every(key =>
        inFlightTuples.has(key)
        || (!hasDepFacts && confirmedTuples.all.has(key))
        || confirmedTuples.composite.has(key))) {
        return 'in_flight'
      }
      return null
    }

    // Legacy direct callers (e.g. stepRepeatsConfirmedWork without origins/category).
    if (hasDepFacts) return null
    if (category) {
      const targetFamily = confirmedCategoryFamily(category)
      const matched = confirmed.some(ref =>
        normalizeConfirmedRouteTemplate(ref.path) === routes[0]
        && Boolean(ref.probeClass?.trim())
        && confirmedCategoryFamily(ref.probeClass!.trim()) === targetFamily,
      )
      return matched ? 'already_confirmed' : null
    }
    const confirmedPaths = buildConfirmedRouteSets(confirmed).paths
    return routes.every(route => confirmedPaths.has(normalizeConfirmedRouteTemplate(route)))
      ? 'already_confirmed'
      : null
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
    return this.storage.listFacts(run.id, { includeTainted: false, limit: 200 })
      .filter(fact => {
        const data = fact.data
        if (data?.kind !== 'det_lead' || data.source !== 'program_graph') return false
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
    this.detLeadStepKeys.add(input.dedupeKey)
    if (input.isTierA) {
      this.tierAStepKeys.add(input.dedupeKey)
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
      if (boundFactIds.has(fact.id) || !approvedOrigins.has(fact.origin)) continue
      const endpoint = typeof fact.data?.endpoint === 'string' ? fact.data.endpoint : ''
      const probeClass = typeof fact.data?.probeClass === 'string' ? fact.data.probeClass : ''
      const method = typeof fact.data?.method === 'string' ? fact.data.method.toUpperCase() : 'GET'
      if (!endpoint.startsWith('/') || !probeClass) continue
      const asset = this.approvedAsset(run, fact.origin)
      if (!asset) continue
      const category = detLeadCategory(probeClass)
      const dedupeKey = `${method} ${normalizeEndpointTemplate(endpoint)}|${confirmedCategoryFamily(category)}`
      if (this.tierAStepKeys.has(dedupeKey) || this.detLeadStepKeys.has(dedupeKey)) continue
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
    const facts = [...this.storage.listFacts(run.id, { includeTainted: false, limit: 200 })]
      .sort((a, b) => {
        const keyOf = (fact: typeof a) =>
          `${fact.data?.source === 'program_graph' ? '0' : '1'}\u0000${String(fact.data?.endpoint ?? '')}\u0000${String(fact.data?.method ?? '')}\u0000${String(fact.data?.probeClass ?? '')}\u0000${fact.id}`
        return keyOf(a).localeCompare(keyOf(b))
      })
    const existing = this.storage.listChainSteps(run.id, run.goalRevision)
    const boundFactIds = new Set(existing.flatMap(step => step.dependsOnFactIds))
    let slots = Math.max(0, budget - existing.length)
    let created = 0
    for (const fact of facts) {
      if (slots <= 0 || created >= 4) break
      if (fact.data?.kind !== 'det_lead' || !approvedOrigins.has(fact.origin) || boundFactIds.has(fact.id)) continue
      const endpoint = typeof fact.data.endpoint === 'string' ? fact.data.endpoint : ''
      const probeClass = typeof fact.data.probeClass === 'string' ? fact.data.probeClass : ''
      const method = typeof fact.data.method === 'string' ? fact.data.method.toUpperCase() : 'GET'
      if (!endpoint.startsWith('/') || !probeClass) continue
      const category = detLeadCategory(probeClass)
      const routeKey = `${normalizeConfirmedRouteTemplate(endpoint)}|${confirmedCategoryFamily(category)}`
      const dedupeKey = `${method} ${routeKey}`
      if (confirmedKeys.has(routeKey) || this.detLeadStepKeys.has(dedupeKey)) continue
      const gate = detLeadEvidenceGate(fact.data)
      if (!gate.admitted) {
        if (!this.detLeadGateRejected.has(fact.id)) {
          this.detLeadGateRejected.add(fact.id)
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
        if (!this.cappedLeadReported.has(fact.id)) {
          this.cappedLeadReported.add(fact.id)
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
      const confirmedPathSet = new Set(
        input.confirmed
          .filter(ref => !ref.origin || ref.origin === origin)
          .map(ref => normalizeConfirmedRouteTemplate(ref.path)),
      )
      const originEndpoints = this.storage.listEndpoints(input.run.id, { orderBy: 'risk', limit: 40 })
        .filter(ep => input.targetOrigins.includes(ep.origin))
      const unconfirmedOriginEndpoints = originEndpoints.filter(ep => !confirmedPathSet.has(normalizeConfirmedRouteTemplate(ep.pathTemplate)))
      const routes = (unconfirmedOriginEndpoints.length > 0 ? unconfirmedOriginEndpoints : originEndpoints)
        .slice(0, 6)
        .map(ep => ({
          method: ep.method,
          path: ep.pathTemplate,
          riskScore: ep.riskScore,
        }))
      const samples = this.storage.listResourceSamples(input.run.id)
        .filter(sample => input.targetOrigins.includes(sample.origin))
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
        input.parentFacts.some(f => f.data?.kind === 'det_lead' && f.id === lead.exchangeId) ||
        (Boolean(lead.endpoint) && input.targetOrigins.includes(origin)),
      )
      const missionKind = parentChainHops.length > 0 && input.step.dependsOnFactIds.length > 0
        ? 'chain_step_2'
        : this.missionKindForStep(input.step, Boolean(parentDetLead))
      // v7 whitebox hop: the persisted slice for this assignment's route reaches the brief.
      // Compact by default; only chain / 4-hop assignments pay for the expanded slice.
      const codeSlice = this.host.codeSliceForAssignment(input.run, input.step, input.parentFacts)
      const codeExpansion: 'compact' | 'full' = missionKind === 'chain_step_2' ||
        input.step.dependsOnStepIds.length > 0 ||
        parentChainHops.length > 0 ||
        (codeSlice?.hops.length ?? 0) >= 4
        ? 'full'
        : 'compact'
      // Exact control/variant actors for the differential: deterministic order by handle, the
      // variant prefers another tenant (the object/authorization boundary the sink sits behind).
      const tierAPersonas = [...input.personas].sort((a, b) => a.handle.localeCompare(b.handle))
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
      // or persisted step/fact checkpoint metadata, without 480 B truncation or 'artifact' skip.
      const checkpointFact = input.parentFacts.find(f => !f.tainted && f.data?.subkind === 'hop_checkpoint')
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
      if (checkpointCapId) {
        const ledger = this.storage.capabilityLedger(input.run.id)
        if (ledger.getCapability(checkpointCapId)) {
          hopCheckpoint = ledger.buildHopCheckpointBrief(checkpointCapId, MAX_CHECKPOINT_BRIEF_BYTES, {
            ...(persistedBrief?.branchKey ? { branchKey: persistedBrief.branchKey } : {}),
            ...(persistedBrief?.evi !== undefined ? { evi: persistedBrief.evi } : {}),
            ...(persistedBrief?.mode ? { mode: persistedBrief.mode } : {}),
            ...(persistedBrief?.fuseWithBranchKey ? { fuseWithBranchKey: persistedBrief.fuseWithBranchKey } : {}),
            ...(persistedBrief?.nextGoal ? { nextGoal: persistedBrief.nextGoal } : {}),
          })
        }
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


  /** Untruncated, paginated data access for the coordinator (never a fixed snapshot). */
  coordinatorDeps(run: Run): CoordinatorDeps {
    const endpoints = (): CoordinatorEndpoint[] => this.pageAll((offset, limit) =>
      this.storage.listEndpoints(run.id, { limit, offset }))
    return {
      listEndpoints: endpoints,
      listFacts: () => this.pageAll((offset, limit) =>
        this.storage.listFacts(run.id, { includeTainted: false, limit, offset })),
      listFindings: () => this.storage.db.select().from(findings).where(eq(findings.runId, run.id)).all()
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
      ,
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
    const titles = new Set(existing.map(step => step.title.trim().toLowerCase()))
    const confirmed = this.alreadyConfirmedRefs(run, 100)
    const inFlightTuples = buildInFlightTupleKeys(existing)
    const counts = { planned: plan.plan.length, enqueued: 0, filteredDedupe: 0, filteredAlreadyConfirmed: 0, filteredNoAsset: 0 }
    const depStepIds = [...new Set(options.dependsOnStepIds ?? [])]
    for (const step of plan.plan) {
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
        .filter(candidate => step.origins.includes(candidate.origin) && run.approved.includes(candidate.id))
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
                subkind: 'hop_checkpoint',
                ...(checkpointCapId ? { checkpointCapId } : {}),
                ...(checkpointJson ? { checkpointJson } : {}),
                ...(parsedBrief ? { checkpointBrief: parsedBrief.brief } : {}),
              },
              sourceOrigins: step.origins,
            })
            finalFactIds.push(cpFact.id)
          } catch { /* non-fatal: checkpoint_cap skill tag + ledger still persist */ }
        }
      }
      const resolvedPriority = options.preservePriority
        ? step.priority
        : tierABound ? TIER_A_STEP_PRIORITY : leadBound ? Math.min(step.priority, DET_LEAD_STEP_PRIORITY) : step.priority
      const createdStep = this.storage.addChainStep(run, {
        title: title.slice(0, 200),
        hypothesis: step.hypothesis,
        category,
        priority: resolvedPriority,
        targetAssetIds: assetIds,
        skills: stepSkills,
        dependsOnFactIds: finalFactIds,
        ...(depStepIds.length ? { dependsOnStepIds: depStepIds } : {}),
        sourceOrigins: step.origins,
        specialistProfile: routeStepToSpecialist({ title, hypothesis: step.hypothesis, category, skills: step.skills }),
      })
      if (checkpointCapId || checkpointJson) {
        this.persistedStepCheckpoints.set(createdStep.id, {
          ...(checkpointCapId ? { checkpointCapId } : {}),
          ...(checkpointJson ? { checkpointJson } : {}),
        })
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
    if (!isMultiHopChainStep(step)) {
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
    // for this chain lineage (excluding static_analysis / cap:hop_synth:* invariant seeds).
    const ledgerHandles = uniqueHandles.filter(id => ledgerNodeById.has(id))
    const derivedLedgerHandles = ledgerHandles.filter(id => {
      const node = ledgerNodeById.get(id)
      return Boolean(node && node.provenance !== 'static_analysis' && !id.startsWith('cap:hop_synth:'))
    })

    // Cap generic Wave-1 heuristic boundary chains to 1 continuation (never 2); allow 2 continuations
    // only for source/planner-backed multi-hop chains that actually sealed >= 1 cap:hop_* handle
    // in CapabilityLedger.
    const isGenericWave1 = isGenericWave1BoundaryChainStep(step)
    const hasSealedLedgerCap = derivedLedgerHandles.length > 0
    const maxContinuations = isGenericWave1 || !hasSealedLedgerCap
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
      })
      const mergedHandles = [...new Set([...ledgerBrief.capabilityHandles, ...allSealedHandles])]
        .map((h, i) => sanitizeCheckpointHandleRef(h, `cap:redacted:${i + 1}`))
      finalizedBrief = finalizeHopCheckpointBrief({
        ...ledgerBrief,
        depth: Math.max(ledgerBrief.depth, nextDepth),
        targetHop: Math.min(6, Math.max(ledgerBrief.targetHop, nextDepth + 2)),
        capabilityHandles: mergedHandles,
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

    const parentFactIds = [...new Set([
      ...step.dependsOnFactIds,
      ...input.recordedFacts.map(f => f.id),
    ])].slice(0, 12)
    const liveFactIds = new Set(
      this.storage.listFacts(run.id, { includeTainted: false, limit: 500 }).map(f => f.id),
    )

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
        priority: isGenericWave1
          ? Math.min(step.priority, 88)
          : hasSealedLedgerCap
            ? Math.min(100, Math.max(step.priority, 95))
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
      this.storage.addChainStep(run, {
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
      funnel.planned += 1
      funnel.enqueued += 1
      secondOrderAutoSteps += 1
    }
    return secondOrderAutoSteps
  }

  /**
   * Budget, dedupe (`(origin, normalizedRoute, classFamily)` against confirmed & in-flight steps),
   * sanitize dependencies, and enqueue `parsedPlanner.data.newSteps` while keeping exact dispatch
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
    const confirmedForDispatch = this.alreadyConfirmedRefs(currentRun, 100)
    const inFlightTuples = buildInFlightTupleKeys(existingSteps)
    const remainingSlots = Math.max(0, dynamicStepBudget - existingSteps.length)
    const candidateSteps = newSteps
      .map(step => ({ ...step, origins: step.origins.filter(origin => currentApproved.has(origin)) }))
    const budgetedNewSteps = applyCrownJewelStepBudget(
      candidateSteps,
      computeHostTiers([...currentApproved], this.storage.latestThreatModel(currentRun.id, currentRun.goalRevision)?.entries),
      existingSteps,
      remainingSlots,
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
  dispatchChainRound(run: Run, coordinator: GraphCoordinator, budget: number, factIds: ReadonlySet<string>, funnel?: DispatchFunnelCounts): number {
    const existing = this.storage.listChainSteps(run.id, run.goalRevision)
    const remaining = Math.max(0, budget - existing.length)
    if (remaining <= 0) return 0
    const roundNo = Math.max(1, run.roundNo || 1)
    const hops = coordinator.extractChainHops(roundNo)
    const ledger = this.storage.capabilityLedger(run.id)
    const controller = this.frontierControllerFor(run.id)
    this.syncChainHopsToLedger(ledger, hops)
    const hypotheses = coordinator.planChainRound({
      hops,
      maxHops: 6,
      limit: Math.min(12, remaining),
      capabilityLedger: ledger,
      frontierScheduler: controller.scheduler,
      waveNo: roundNo,
    })
    if (!hypotheses.length) return 0
    const existingFacts = this.pageAll((offset, limit) =>
      this.storage.listFacts(run.id, { includeTainted: false, limit, offset }))
    const hopFactById = this.persistChainHopFacts(run, hops, existingFacts)
    const liveFactIds = new Set<string>([...factIds, ...hopFactById.values()])
    // Attach persisted chain_hop fact IDs onto parentEvidenceIds so follow-on briefs receive them
    // while always preserving the originating fact IDs.
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
    this.storage.event(run.id, 'chain.round', `Chain round dispatched ${counts.enqueued} hypothesis(es) with ${hops.length} typed hop artifact(s).`, {
      hypotheses: hypotheses.length, dispatched: counts.enqueued, rejected: plan.rejected.length,
      crossOrigin: hypotheses.filter(hypothesis => hypothesis.scope === 'cross_origin').length,
      primitives: [...new Set(hypotheses.flatMap(hypothesis => hypothesis.primitiveKinds))],
      chainHopCount: hops.length,
      hopArtifactKinds: [...new Set(hops.map(hop => hop.artifactKind))],
      maxChainHops: hypotheses.reduce((max, h) => Math.max(max, h.hops), 0),
    })
    return counts.enqueued
  }


  async runChainPlanner(run: Run, profiles: readonly ResolvedModelProfile[], task: CoordinatorTask) {
    const fresh = this.storage.run(run.id)
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
    const sourceMounted = this.host.projectReposMount(updated.projectId).mountedRepos.length > 0

    // v7 M2 white-box-first default: when source repos are mounted, seed Tier-A AST/RBAC/dataflow
    // leads BEFORE generic black-box floor leads or BOLA auto-steps.
    if (!this.invariantsSeededRuns.has(updated.id)) {
      try {
        this.seedCapabilityLedgerInvariants(updated, { approvedOrigins })
      } catch { /* additive Layer-2 synthesis */ }
    }
    let tierAPlannerSteps = 0
    if (sourceMounted) {
      try {
        tierAPlannerSteps = this.queueTierALeadSteps(updated, approvedOrigins, dynamicStepBudget, { sourceMounted: true })
      } catch { /* white-box seeding is additive */ }
      funnel.planned += tierAPlannerSteps
      funnel.enqueued += tierAPlannerSteps
    }

    // v6 Phase 1: prioritized deterministic leads become upgrade assignments before the planner
    // runs, so the agentic lane never idles on confirmed routes and never loses a floor signal.
    let detLeadSteps = 0
    try {
      detLeadSteps = this.queueDetLeadUpgradeSteps(fresh, approvedOrigins, dynamicStepBudget)
    } catch { /* lead queueing is additive */ }
    funnel.planned += detLeadSteps
    funnel.enqueued += detLeadSteps

    const factIds = new Set(this.pageAll((offset, limit) =>
      this.storage.listFacts(fresh.id, { includeTainted: false, limit, offset })).map(fact => fact.id))
    const remainingBudget = Math.max(0, dynamicStepBudget - this.storage.listChainSteps(fresh.id, updated.goalRevision).length)
    const maxConcForPlan = Math.max(1, Math.min(maxWorkerConcurrency, updated.workerConcurrency || defaultWorkerConcurrency))
    const waveBufferTarget = Math.max(12, maxConcForPlan * 2)
    const coordinator = createGraphCoordinator({
      deps: this.coordinatorDeps(updated),
      approvedOrigins: [...approvedOrigins],
      budgetUsd: Math.max(0, Number((updated.budgetUsd - updated.spentUsd).toFixed(4))),
      maxDispatchSteps: plannerWaveDispatchCap(maxConcForPlan, remainingBudget),
    })

    // Explicit chaining round: runs on round >= 2, and also on round 1 when Phase-0/floor already
    // yielded >= 2 composable typed ChainHop artifacts. Deterministic hypotheses dispatch *before*
    // the LLM turn so a planner failure can never leave an empty window.
    let chainSteps = 0
    if (roundNo >= 2 || coordinator.extractChainHops(roundNo).length >= 2) {
      try { chainSteps = this.dispatchChainRound(updated, coordinator, dynamicStepBudget, factIds, funnel) } catch { /* additive */ }
    }

    const allSteps = this.storage.listChainSteps(fresh.id, updated.goalRevision)
    const allUntaintedFacts = this.pageAll((offset, limit) =>
      this.storage.listFacts(fresh.id, { includeTainted: false, limit, offset }))
      .filter(fact => approvedOrigins.has(fact.origin))
    const detLeadFactIds = new Set(allUntaintedFacts
      .filter(fact => fact.data?.kind === 'det_lead')
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
    if (updated.capabilityTier >= 2 && personas.length >= 2 && allSteps.length < dynamicStepBudget) {
      const typeGroups = new Map<string, BolaTestQueueItem[]>()
      for (const item of buildBolaTestQueue(allUntaintedFacts, personas, approvedOrigins, this.storage.listResourceSamples(run.id))) {
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
        this.storage.addChainStep(updated, {
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
        funnel.planned += 1
        funnel.enqueued += 1
        bolaAutoSteps += 1
        perOriginSteps.set(origin, (perOriginSteps.get(origin) ?? 0) + 1)
      }
    }

    // Auto-enqueue verification for each new cross-persona or active-HTML second-order surface,
    // skipping routes already confirmed by a host-verified CompositeProofReceipt.
    const secondOrderAutoSteps = this.queueSecondOrderSurfaceSteps(
      updated,
      approvedOrigins,
      allUntaintedFacts,
      allSteps,
      confirmedForPlanner,
      Math.max(0, dynamicStepBudget - allSteps.length - bolaAutoSteps),
      funnel,
    )

    // Tool-equipped coordinator session: paginated read tools, explicit dispatch, no snapshot.
    let toolDispatched = 0
    const handlers = coordinatorPlannerHandlers({
      coordinator,
      onDispatch: plan => {
        try {
          const counts = this.persistDispatchPlan(this.storage.run(fresh.id), plan, factIds, detLeadFactIds)
          addFunnelCounts(funnel, counts)
          toolDispatched += counts.enqueued
        } catch { /* additive */ }
      },
    })
    const pendingOob = coordinator.queryFindings({ status: 'pending_oob', limit: 1 }).total
    // v7 precision guard: remember the evidence frontier across rounds. A round that adds no
    // runtime_confirmed finding and no chain primitive is dry; two consecutive dry rounds after the
    // high-priority queue drains end the planner.
    const evidenceFrontier = this.plannerEvidenceFrontier.get(run.id) ?? {
      confirmed: coordinator.queryFindings({ status: 'confirmed', limit: 1 }).total,
      primitives: coordinator.deriveChainPrimitives().length,
    }
    const prompt = coordinatorPlannerPrompt({
      goal: updated.goal,
      roundNo,
      capabilityTier: updated.capabilityTier,
      approvedOrigins: [...approvedOrigins],
      budgetRemaining: {
        usd: Math.max(0, Number((updated.budgetUsd - updated.spentUsd).toFixed(4))),
        requests: updated.budgetRequests === 0 ? 'unlimited' : Math.max(0, updated.budgetRequests - updated.spentRequests),
      },
      dynamicStepBudget,
      pendingOob,
      chainSteps: this.storage.listChainSteps(fresh.id, updated.goalRevision)
        .map(step => ({ id: step.id, title: step.title, status: step.status })),
      alreadyConfirmed: confirmedForPlanner.slice(0, 30),
      personas: personas.map(persona => ({ handle: persona.handle, roleLabel: persona.roleLabel })),
      mountedRepos: this.host.projectReposMount(updated.projectId).mountedRepos,
      openProofGaps: this.storage.listOpenProofGaps(fresh.id, updated.goalRevision)
        .filter(gap => approvedOrigins.has(gap.origin)).length,
    })
    const answer = await agentTurn({
      directory: this.storage.directory,
      sessionId: `planner-${run.id}-r${roundNo}`,
      requestId: `planner:${updated.goalRevision}:${roundNo}`,
      profiles: resolveProfilePoolForRole('tactical', profiles),
      scenario: 'chain-planner',
      roleAffinity: 'tactical',
      prompt,
      signal: task.controller.signal,
      maxTurns: 10,
      handlers,
      ...llmRunHooks(this.storage, run.id),
    })
    if (!this.host.currentCoordinator(run.id, task)) return

    let parsedPlanner: ReturnType<typeof plannerResponseSchema.safeParse> | null = null
    try { parsedPlanner = plannerResponseSchema.safeParse(JSON.parse(stripJsonFences(answer))) } catch { parsedPlanner = null }
    const currentRun = this.storage.run(run.id)
    const currentApproved = this.host.approvedOriginsSet(currentRun)
    const existingSteps = this.storage.listChainSteps(run.id, currentRun.goalRevision)
    let addedCount = tierAPlannerSteps + detLeadSteps + chainSteps + bolaAutoSteps + secondOrderAutoSteps + toolDispatched

    if (parsedPlanner?.success) {
      for (const cancelId of parsedPlanner.data.cancelStepIds) {
        const target = existingSteps.find(step => step.id === cancelId)
        if (target && ['pending', 'ready'].includes(target.status)) this.storage.updateChainStep(target.id, { status: 'canceled' })
      }
      addedCount += this.applyPlannerNewSteps({
        run: currentRun,
        newSteps: parsedPlanner.data.newSteps,
        approvedOrigins: currentApproved,
        existingSteps,
        dynamicStepBudget,
        factIds,
        detLeadFactIds,
        funnel,
      })
    }

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
      newHopEvents.push({
        hopReceiptId: edge.hopReceiptId,
        branchKey: edge.postconditionCapId ?? edge.edgeId,
        depth: Math.max(1, edge.preconditionCapIds.length + 1),
        hostVerified: true,
        tenantScope: postNode?.tenantScope ?? edge.actorContext.tenantScope ?? 'default_tenant',
        ...(edge.actorContext.roleLabel ? { roleLabel: edge.actorContext.roleLabel } : {}),
        serviceOrigin: postNode?.serviceOrigin ?? edge.actorContext.serviceOrigin ?? 'unknown',
        surface: postNode?.surface ?? 'http',
        ...(postNode ? { capabilityId: postNode.capId } : {}),
      })
    }
    const latestForProgress = this.storage.run(run.id)
    const frontierDecision = newHopEvents.length > 0
      ? frontierController.evaluateWaveProgress({
          completedAssignments: Math.max(0, completedInvestigations - previousCompletedInvestigations),
          verifiedHopReceipts: newHopEvents,
          pendingAsyncOrOob: coordinator.queryFindings({ status: 'pending_oob', limit: 1 }).total,
          budgetUsdSpent: latestForProgress.spentUsd,
          budgetUsdLimit: latestForProgress.budgetUsd,
          elapsedMs: Math.max(0, Date.now() - latestForProgress.createdAt),
          maxDurationMs: this.host.maxDurationMs,
          requestsSpent: latestForProgress.spentRequests,
          agentRequestBudget: latestForProgress.budgetRequests,
        })
      : null
    const verifiedHopReachExpansions = frontierDecision?.reachDelta.newHopReceiptIds.length ?? 0

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
      coordinatorDone: parsedPlanner?.success ? parsedPlanner.data.done : false,
      pendingOob: coordinator.queryFindings({ status: 'pending_oob', limit: 1 }).total,
      highPriorityQueueEmpty: queueDrained,
      consecutiveDryRounds: dryRounds,
      verifiedHopReachExpansions,
      frontierDecision,
    })

    // v7 coverage guard: a dry/coordinator stop must not abandon planned, dispatchable work while a
    // worker slot is free. The stop is deferred (never silently dropped) and the funnel records it.
    const finalFactIds = new Set(this.pageAll((offset, limit) =>
      this.storage.listFacts(run.id, { includeTainted: true, limit, offset })).map(fact => fact.id))
    const refreshQueueState = () => {
      const steps = this.storage.listChainSteps(run.id, latest.goalRevision)
      return {
        steps,
        remainingReady: dispatchableReadySteps(steps, finalFactIds).length,
        coverage: this.passOneCoverageFor(run, steps),
      }
    }
    let { steps: finalSteps, remainingReady, coverage } = refreshQueueState()
    let tierASeededAtStop = 0
    if (decision.decision === 'stop' && (coverage.uninvestigatedFirstPassClasses.length || coverage.uncoveredTierAEndpoints.length)) {
      tierASeededAtStop = this.queueTierALeadSteps(
        this.storage.run(run.id), this.host.approvedOriginsSet(run), computeDynamicStepBudget(this.storage, run.id),
      )
      if (tierASeededAtStop > 0) ({ steps: finalSteps, remainingReady, coverage } = refreshQueueState())
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
        ;({ steps: finalSteps, remainingReady, coverage } = refreshQueueState())
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
    funnel.filteredDep = permanentlyBlockedStepIds(finalSteps, finalFactIds).length
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
      done: parsedPlanner?.success === true ? parsedPlanner.data.done : false,
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
      summary: parsedPlanner?.success ? parsedPlanner.data.summary.slice(0, 300) : compactText(answer, 300),
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

    void agentTurn({
      directory: this.storage.directory,
      sessionId: run.coordinatorId,
      requestId: `${next.id}:${run.goalRevision}:${run.scopeRevision}`,
      profiles: resolveProfilePoolForRole('fast', profiles),
      scenario: 'coordinator',
      roleAffinity: 'fast',
      thinkingLevel: 'off',
      prompt,
      signal: controller.signal,
      ...llmRunHooks(this.storage, run.id),
    }).then(answer => {
      if (!this.host.currentCoordinator(run.id, task)) return
      this.storage.transaction(() => {
        this.storage.message(run.id, run.coordinatorId, 'coordinator', answer, next.id)
        this.storage.event(run.id, 'coordinator.reply', 'The coordinator replied.')
      })
    }).catch(() => {
      if (!this.host.currentCoordinator(run.id, task)) return
      this.storage.transaction(() => {
        this.storage.message(run.id, run.coordinatorId, 'kovo',
          'The coordinator could not reach the model. Review the workflow for current progress.', next.id)
        this.storage.event(run.id, 'coordinator.unavailable', 'The coordinator could not complete its reply.')
      })
    }).finally(() => {
      this.host.coordinator.delete(run.id)
    })
  }

}
