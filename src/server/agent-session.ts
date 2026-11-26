import { createHash, randomUUID } from "node:crypto"
import { existsSync, lstatSync, mkdirSync, readdirSync, readFileSync, realpathSync, writeFileSync } from "node:fs"
import { join, relative, sep } from "node:path"
import { BACKGROUND_CONTEXT, withAbortSignal } from "@earendil-works/chord/context"
import {
  createRegistry,
  defineExtension,
  defineTool,
  GenerationTask,
  Harness,
  hook,
  ToolTask,
} from "@earendil-works/pi-durable"
import type { ToolRegistration } from "@earendil-works/pi-durable"
import { openNodeSqliteStorage } from "@earendil-works/pi-durable/storage/sqlite/node"
import { arr, bool, int, map, num, obj, oneOf, opt, str, unknown, unsafe } from "@earendil-works/pi-schema"
import {
  DEFAULT_PROVIDER,
  boardMessageKinds,
  defaultWorkerMaxTurns,
  findingSeverities,
  httpMethods,
  maxWorkerMaxTurns,
  owaspCategories,
} from "../domain.ts"
import type {
  HttpMethod,
  RoleAffinity,
  ThinkingLevel,
} from "../domain.ts"
import { declarativeReplaySpecSchema } from "../replay-spec.ts"
import type { CsrfBind, DeclarativeReplaySpec } from "../replay-spec.ts"
import {
  boardPostBodyLimit,
  specialistBoardPostKinds,
} from "./board-tools.ts"
import type { BoardPostArgs, BoardReadArgs } from "./board-tools.ts"
import type { BrokerMultipartPart } from "./broker.ts"
import type { BrowserInteractiveAction, BrowserSessionStep } from "./scoped-browser.ts"
import type { AgentTrace } from "./agent-trace.ts"
import { ActiveClock, type DeadlineTimerHandle } from "./active-clock.ts"
import { isProfileHealthy, resolveProfilePoolForRole } from "./model-settings.ts"
import type { ResolvedModelProfile } from "./model-settings.ts"
import {
  defaultFirstEventTimeoutMs,
  defaultIdleTimeoutMs,
  defaultMaxCalls,
  provider,
  providerPool,
} from "./provider.ts"
import type { CallRecorder, ProviderConfig, ProviderOptions, SecretSource, UsageCallback } from "./provider.ts"
import { redactSecrets } from "./egress-sanitizer.ts"
import { redact } from "./redact.ts"
import type { NamedSecret } from "./redact.ts"
import { resolveRunSafetyBudgets } from "./run-safety-budgets.ts"
import { MAX_CLAIM_REGEX_HAYSTACK, compileSafeClaimRegex } from "./safe-regex.ts"
import {
  executeSearchRepoScan,
  searchRepoInWorker,
  type SearchRepoWorkerRequest,
  type SearchRepoWorkerResult,
} from "./untrusted-compute-pool.ts"
import { listSkills, listSkillTags, loadSkill, searchSkills, selectPreInjectionSkills, skillsByTag } from "./skills.ts"
import {
  ALL_SPEC_PROOF_GAP_CODES,
  EARLY_EXIT_GRACE_TURNS,
  EARLY_EXIT_HARDENED_STATUSES,
  EARLY_EXIT_STATE_CHANGE_METHODS,
  KOVO_VERIFY_SPEC_SHAPE,
  KOVO_VERIFY_TOOL_DESCRIPTION,
  KOVO_VERIFY_TS_ONLY_ERROR,
  SPEC_PROOF_GAP_ALIASES,
  SPEC_PROOF_GAP_CODES,
  WALL_CLOCK_PROOF_GRACE_MS,
  analyzerNames,
  browserActionTypes,
  browserBuiltinCheckNames,
  browserInteractiveActionSchema,
  buildEarlyExitEvent,
  codeLocationInputSchema,
  coverageStatuses,
  csrfBindPiSchema,
  defaultCodeAuditMaxTurns,
  defaultInlineToolOutputBytes,
  defaultPatchMaxTurns,
  defaultPlannerMaxTurns,
  defaultThinkingForRole,
  differentialProbeClasses,
  earlyExitDirectiveMessage,
  earlyExitEligible,
  factKinds,
  fallbackCommand,
  formatReplaySpecValidationIssues,
  gapValidationRejectedMessage,
  kovoVerifyRedirectMessage,
  httpRequestSchema,
  intentCompletionStatuses,
  isPlainRecord,
  maxEmptyTurnNudges,
  maxInlineToolOutputBytes,
  maxSpillFileBytes,
  normalizePiAuthMutation,
  parseProofGapCode,
  probeParamLocations,
  proposeChainFindingDescription,
  roleAffinityForScenario,
  sastEngineNames,
  settlementBannerMessage,
  settlementDue,
  settlementNudgeMessage,
  settlementNudgeTurnFor,
  settlementSpecDirective,
  specSubmissionRequiredMessage,
  summarizeKovoVerifyOutcome,
  surfaceWordlistNames,
  truncateUtf8Head,
  verifierFeedbackKeys,
  verifierRepairFeedback,
  wallClockSettlementMessage,
  wallClockSettlementMs,
  withVerifierRepairFeedback,
  workerSessionInstructions,
} from "./agent-prompts.ts"
import type {
  AgentScenario,
  EarlyExitEvent,
  GapDenialKind,
  GapValidationEvent,
  GapValidationStats,
  KovoVerifyArgs,
  KovoVerifyRuntime,
  IntentCompletion,
  ProofObligationEvent,
  ProofObligationStats,
  ProofRouteObligation,
  PromptAssignmentBudget,
  ReadEvidenceSliceArgs,
  ReadRepoFileArgs,
  RejectedProofGap,
  RequestHttpArgs,
  RouteAttemptObservation,
  RouteObservation,
  RouteObservationSnapshot,
  SearchRepoArgs,
  SpecProofGapCode,
  SpecProofGapEntry,
  SpecRouteEvidence,
  SpecSubmissionSnapshot,
  WorkerToolHandlers,
} from "./agent-prompts.ts"
import {
  AGENT_TOOL_NAMES,
  AGENT_TOOL_REGISTRY,
  NETWORK_TOOLS,
  PARALLEL_READ_ONLY_TOOLS,
  ROUTE_EVIDENCE_TOOLS,
  SETTLEMENT_ALLOWED_TOOLS,
  SETTLEMENT_REVOKED_TOOLS,
  SETTLEMENT_SPEC_PAUSED_TOOLS,
  SETTLEMENT_WRAPUP_TOOLS,
  SPEC_SUBMISSION_TOOLS,
  getAgentToolMetadata,
} from "./agent-tool-registry.ts"
import type {
  AgentToolMetadata,
  AgentToolName,
  SettlementToolPhase,
} from "./agent-tool-registry.ts"
import type { KovoVerifyAliasKey } from "./verify-runner.ts"

export {
  AGENT_TOOL_NAMES,
  AGENT_TOOL_REGISTRY,
  NETWORK_TOOLS,
  PARALLEL_READ_ONLY_TOOLS,
  ROUTE_EVIDENCE_TOOLS,
  SETTLEMENT_ALLOWED_TOOLS,
  SETTLEMENT_REVOKED_TOOLS,
  SETTLEMENT_SPEC_PAUSED_TOOLS,
  SETTLEMENT_WRAPUP_TOOLS,
  SPEC_SUBMISSION_TOOLS,
  getAgentToolMetadata,
} from "./agent-tool-registry.ts"

export {
  ALL_SPEC_PROOF_GAP_CODES,
  AGENTIC_CONTRACT_LINES,
  AGENTIC_DET_LEAD_LIMIT,
  AGENTIC_MAX_MAX_TURNS,
  AGENTIC_MIN_MAX_TURNS,
  AGENTIC_SPECIALIST_MAX_TURNS,
  AGENTIC_SPECIALIST_WALL_CLOCK_MS,
  AGENTIC_UPGRADE_MAX_TURNS,
  BASE_INVESTIGATOR_TOOLS,
  EARLY_EXIT_GRACE_TURNS,
  EARLY_EXIT_HARDENED_STATUSES,
  EARLY_EXIT_MIN_ATTEMPTS,
  EARLY_EXIT_MIN_TURNS,
  EARLY_EXIT_STATE_CHANGE_METHODS,
  EARLY_EXIT_UNCHANGED_MIN_ATTEMPTS,
  KOVO_VERIFY_CLASS_HINTS,
  KOVO_VERIFY_ENFORCED_RUNTIME_KINDS,
  KOVO_VERIFY_HELPERS,
  KOVO_VERIFY_HELPER_GUIDANCE_MAX_BYTES,
  KOVO_VERIFY_MULTIHOP_HELPERS,
  KOVO_VERIFY_REPAIR_INSTRUCTION,
  KOVO_VERIFY_SPEC_SHAPE,
  KOVO_VERIFY_TOOL_DESCRIPTION,
  KOVO_VERIFY_TS_ONLY_ERROR,
  KOVO_VERIFY_USAGE_HINT,
  NEGATIVE_EDGE_PROOF_GAP_CODES,
  SPECIALIST_COMMON_TOOLS,
  SPECIALIST_PROFILES,
  SPEC_PROOF_GAP_ALIASES,
  SPEC_PROOF_GAP_CODES,
  WALL_CLOCK_PROOF_GRACE_MS,
  analyzerNames,
  boardSpecialistTools,
  browserActionTypes,
  browserBuiltinCheckNames,
  buildAgenticPromptContext,
  buildEarlyExitEvent,
  capabilityBundlesFor,
  chainPlannerPrompt,
  classifyHostTier,
  classifySpecSubmission,
  codeAuditPrompt,
  confirmedRefsFromParentFacts,
  coordinatorPlannerPrompt,
  coordinatorPrompt,
  coverageStatuses,
  defaultCodeAuditMaxTurns,
  defaultInlineToolOutputBytes,
  defaultPatchMaxTurns,
  defaultPlannerMaxTurns,
  defaultThinkingForRole,
  detLeadsFromParentFacts,
  differentialProbeClasses,
  earlyExitDirectiveMessage,
  earlyExitEligible,
  earlyExitTurnsSaved,
  factKinds,
  filterHandlersForSpecialist,
  formatReplaySpecValidationIssues,
  gapValidationRejectedMessage,
  kovoVerifyHelperGuidance,
  kovoVerifyPromptHint,
  kovoVerifyRedirectMessage,
  intentCompletionStatuses,
  investigatorTools,
  maxEmptyTurnNudges,
  maxInlineToolOutputBytes,
  maxSpillFileBytes,
  parseNegativeEdgeGapReason,
  parseProofGapCode,
  patchAuthorPrompt,
  patchReviewerPrompt,
  probeParamLocations,
  proofRepairBodyPreviewBytes,
  proofToolHandlerNames,
  proposeChainFindingDescription,
  resolveAgenticTurnBudget,
  resolveSpecialistProfile,
  roleAffinityForScenario,
  routeStepToSpecialist,
  sastEngineNames,
  scenarioInstructions,
  settlementBannerMessage,
  settlementDue,
  settlementNudgeMessage,
  settlementNudgeTurnFor,
  settlementSpecDirective,
  specSubmissionRequiredMessage,
  summarizeKovoVerifyOutcome,
  surfaceWordlistNames,
  threatModelPrompt,
  verifierRepairFeedback,
  wallClockSettlementMessage,
  wallClockSettlementMs,
  withVerifierRepairFeedback,
  workerInput,
  workerInvestigationPrompt,
  workerSessionInstructions,
} from "./agent-prompts.ts"
export type {
  AgentScenario,
  AgenticPromptContextInput,
  AlreadyConfirmedRef,
  BrowserVisitToolArgs,
  CapabilityBundle,
  CodeAuditPromptInput,
  CodeAuditSuspectData,
  CoordinatorDispatchArgs,
  CoordinatorEndpointsArgs,
  CoordinatorFactsArgs,
  CoordinatorFindingsArgs,
  CoordinatorPlannerPromptInput,
  CoordinatorProgramGraphArgs,
  CoverageStatus,
  CrawlStateGraphToolArgs,
  DetLeadSummary,
  EarlyExitBlock,
  EarlyExitDecision,
  EarlyExitInput,
  EarlyExitReason,
  EarlyExitEvent,
  FactKind,
  GapDenialKind,
  GapValidationEvent,
  GapValidationStats,
  KovoVerifyArgs,
  KovoVerifyAttemptSummary,
  KovoVerifyCompositeSummary,
  KovoVerifyHandler,
  KovoVerifyHopSummary,
  KovoVerifyRuntime,
  KovoVerifySealedCapabilitySummary,
  KovoVerifyToolResult,
  HostTier,
  IntentCompletion,
  IntentCompletionStatus,
  NegativeEdgeProofGapCode,
  PatchAuthorPromptInput,
  PatchReviewerPromptInput,
  PersonaResourceQueueItem,
  ProbeDifferentialToolArgs,
  ProbeSurfaceToolArgs,
  ProbeWebsocketToolArgs,
  ProofObligationEvent,
  ProofObligationStats,
  ProofRouteObligation,
  ProofToolHandler,
  ProofToolHandlerName,
  ProposeChainFindingArgs,
  ReadEvidenceSliceArgs,
  ReadRepoFileArgs,
  RecordCoverageArgs,
  RejectedProofGap,
  RequestHttpArgs,
  RequestHttpRaceArgs,
  RouteAttemptObservation,
  RouteObservation,
  RouteObservationSnapshot,
  RunOfflineScriptArgs,
  RunSastScanArgs,
  RunSafeTemplatesToolArgs,
  SearchRepoArgs,
  SpecProofGapCode,
  SpecProofGapEntry,
  SpecRouteEvidence,
  SpecSubmissionFunnelStage,
  SpecSubmissionSnapshot,
  SpecialistProfileConfig,
  ToolHandlers,
  UnconfirmedSurfaceRef,
  UpdateProposedFindingArgs,
  VerifierRepairFeedback,
  VerifyReplaySpecArgs,
  WorkerToolHandlers,
} from "./agent-prompts.ts"

// Re-exported so execution.ts can wire turn-start deltas/guardrails without a second import site.
export {
  buildBoardDelta,
  createBoardTools,
  injectBoardTurnInstructions,
  boardGuardrailInstructions,
  boardGuardrailInstructions as boardTurnInstructions,
  boardNoAckInstruction,
  boardUntrustedDeltaInstruction,
  WarmSpecialistController,
  warmSpecialists,
} from "./board-tools.ts"


export type {
  AgentToolMetadata,
  AgentToolName,
  PromptAssignmentBudget,
  SettlementToolPhase,
}

/** Tools whose arguments carry a replay spec/script we can bind to route evidence (derived from `agent-tool-registry.ts`). */
const ROUTE_BOUND_SPEC_TOOLS: ReadonlySet<string> = SPEC_SUBMISSION_TOOLS


const SPEC_ROUTE_PATH_RE = /^[A-Za-z0-9._~\-/[\]{}:@!$&()*+,;=%]*$/

function cleanSpecRoute(input: { method?: string; pathAndQuery?: string; origin?: string }): SpecRouteEvidence | undefined {
  const method = (input.method ?? '').toUpperCase().replace(/[^A-Z]/g, '').slice(0, 10)
  const raw = (input.pathAndQuery ?? '').trim()
  if (!method || !raw) return undefined
  const [pathPart, query = ''] = raw.split('?', 2)
  const path = (pathPart ?? '/').slice(0, 160)
  if (!path.startsWith('/') || !SPEC_ROUTE_PATH_RE.test(path)) return undefined
  const params = [...new Set(query.split('&')
    .map(pair => (pair.split('=', 1)[0] ?? '').replace(/[^A-Za-z0-9_.:[\]-]/g, ''))
    .filter(Boolean))].slice(0, 4)
  const origin = (input.origin ?? '').split(/[?#]/, 1)[0]?.slice(0, 120)
  return { method, path, params, ...(origin && /^https?:\/\//i.test(origin) ? { origin } : {}) }
}

/** Extract step request routes from a DeclarativeReplaySpec (or any nested spec-shaped object). */
export function replaySpecRouteSteps(spec: unknown): Array<{ method: string; path: string }> {
  const out: Array<{ method: string; path: string }> = []
  const seen = new Set<unknown>()
  const visit = (value: unknown, depth: number) => {
    if (out.length >= 32 || depth > 10 || !value || typeof value !== 'object' || seen.has(value)) return
    seen.add(value)
    if (Array.isArray(value)) {
      for (const item of value) visit(item, depth + 1)
      return
    }
    const rec = value as Record<string, unknown>
    const request = rec.request && typeof rec.request === 'object' && !Array.isArray(rec.request)
      ? rec.request as Record<string, unknown>
      : rec
    const rawPath = typeof request.pathAndQuery === 'string' ? request.pathAndQuery : typeof request.path === 'string' ? request.path : null
    const rawMethod = typeof request.method === 'string' ? request.method : null
    if (rawPath && rawMethod) {
      const path = rawPath.split(/[?#]/, 1)[0] ?? '/'
      if (path.startsWith('/')) out.push({ method: rawMethod.toUpperCase().replace(/[^A-Z]/g, '').slice(0, 10), path: path.slice(0, 160) })
    }
    for (const child of Object.values(rec)) if (child !== request) visit(child, depth + 1)
    return
  }
  visit(spec, 0)
  return out
}

/** Parameter names from a pathAndQuery (values are never retained). */
function paramNamesOf(pathAndQuery: string): string[] {
  return (pathAndQuery.split('?', 2)[1] ?? '')
    .split('&')
    .map(pair => (pair.split('=', 1)[0] ?? '').replace(/[^A-Za-z0-9_.:\[\]-]/g, ''))
    .filter(Boolean)
    .sort()
}

/** Resource-id segments collapse so `/api/items/1001` and `/api/items/1002` share a family. */
function normalizeRouteFamily(path: string): string {
  const parts = path.split('/').map(segment => {
    if (!segment) return segment
    if (/^\d+$/.test(segment)) return ':id'
    if (/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(segment)) return ':id'
    if (/^[0-9a-f]{16,}$/i.test(segment)) return ':id'
    if (/^\{\{?[a-z0-9_]+\}?\}$/i.test(segment)) return ':id'
    if (/^:[a-z0-9_]+$/i.test(segment)) return ':id'
    return segment
  })
  return parts.join('/').slice(0, 160)
}

/**
 * Stable route-obligation key: `METHOD` plus the resource-id-normalized path family. A proof gap or
 * spec bound to `/api/orders/1001` covers `/api/orders/1002` (same family) but never `/api/admin/1`.
 */
export function proofRouteKey(method: string, path: string): string {
  const cleanMethod = (method ?? '').toUpperCase().replace(/[^A-Z]/g, '').slice(0, 10)
  const cleanPath = (path ?? '').split(/[?#]/, 1)[0] ?? '/'
  return `${cleanMethod} ${normalizeRouteFamily(cleanPath)}`
}


/** State-changing methods: a non-denied answer is a mutation (not a readable readback). */
const GAP_MUTATING_METHODS: ReadonlySet<string> = new Set(['POST', 'PUT', 'PATCH', 'DELETE'])

/**
 * Per-assignment spec-submission ledger. Small, mutable and dependency-free so the tool layer and
 * the settlement runner share one source of truth without touching session storage.
 */
interface RouteFamilyState {
  key: string
  method: string
  family: string
  route: SpecRouteEvidence
  attempts: number
  status: number | null
  anomaly: boolean
  assigned: boolean
  /** Monotonic insertion order, so ties resolve to the most recently touched family. */
  seq: number
}

/** Route value: an anomalous route is the best use of the reserved verify turn, then a 2xx route. */
function routeObligationValue(obligation: ProofRouteObligation): number {
  let score = Math.min(obligation.attempts, 20)
  if (obligation.anomaly) score += 1000
  if (obligation.status !== null && obligation.status >= 200 && obligation.status < 300) score += 100
  if (obligation.assigned) score += 10
  return score
}

/** Pick the highest-value route from a set (anomaly > 2xx > probe density; ties → latest). */
function pickHighestValueRoute(obligations: readonly ProofRouteObligation[]): ProofRouteObligation | undefined {
  let best: ProofRouteObligation | undefined
  let bestScore = -1
  for (const obligation of obligations) {
    const score = routeObligationValue(obligation)
    if (!best || score >= bestScore) {
      best = obligation
      bestScore = score
    }
  }
  return best
}

/** Parse a worker-supplied route binding (`METHOD /path`, or `/path` when the method is unambiguous). */
function parseRouteReference(raw: string): { key: string; family: string; hasMethod: boolean } | undefined {
  const trimmed = raw.trim()
  if (!trimmed) return undefined
  const match = /^([A-Za-z]+)\s+(.+)$/.exec(trimmed)
  const method = match ? (match[1] ?? '').toUpperCase().replace(/[^A-Z]/g, '').slice(0, 10) : ''
  const path = (match ? match[2] ?? '' : trimmed).split(/[?#]/, 1)[0] ?? '/'
  if (!path.startsWith('/')) return undefined
  return {
    key: proofRouteKey(method, path),
    family: normalizeRouteFamily(path),
    hasMethod: Boolean(method),
  }
}

export class SpecSubmissionTracker {
  private state: SpecSubmissionSnapshot = {
    probes: 0, specAttempts: 0, targetCovered: false, codedProofGaps: 0, proofGaps: [],
    obligations: [], obligation: { probedRoutes: 0, coveredRoutes: 0, gapRoutes: 0, demandedRoutes: 0, dischargedByGap: 0 },
    required: 0,
  }
  /** Probed route key → evidence + probe count; the most-probed route is the target proxy. */
  private readonly routeCounts = new Map<string, { route: SpecRouteEvidence; count: number }>()
  /** Bounded, body-free route response ledger (status/sha/anomaly only) for early-exit settlement. */
  private readonly observations: RouteAttemptObservation[] = []
  /** Route keys (`METHOD path`) that a submitted spec or verify script positively covers. */
  private readonly coveredRoutes = new Set<string>()
  /** `METHOD family` keys covered by an explicit spec/verify route step. */
  private readonly coveredFamilies = new Set<string>()
  /** One obligation per probed/assigned route family. */
  private readonly routeFamilies = new Map<string, RouteFamilyState>()
  /** Route-scoped coded gaps, at most one per family (idempotent). */
  private readonly gapByRoute = new Map<string, SpecProofGapEntry>()
  /** First settlement verdict per route gap: rejected once, then accepted (never a loop). */
  private readonly gapVerdicts = new Map<string, 'accepted' | 'rejected'>()
  /** Gap-validation totals (accepted/rejected) emitted as `agent.gap_validation`. */
  private readonly gapStats: GapValidationStats = { accepted: 0, rejected: 0, byCode: {} }
  /** Origins the run is approved to test; used to substantiate `out_of_scope` gaps. */
  private readonly approvedOrigins = new Set<string>()
  /** Route keys explicitly demanded (complete_intent rejection or the reserved wrap-up turn). */
  private readonly demandedRoutes = new Set<string>()
  /** Attempts whose spec shape could not be attributed to a route; treated as covering any target. */
  private opaqueSpecAttempts = 0
  private confirmedProofs = 0
  private sequence = 0

  noteProbe(): void {
    this.state = { ...this.state, probes: this.state.probes + 1 }
  }

  private registerFamily(route: SpecRouteEvidence): RouteFamilyState {
    const family = normalizeRouteFamily(route.path)
    const key = proofRouteKey(route.method, route.path)
    const existing = this.routeFamilies.get(key)
    if (existing) {
      // Preserve the origin captured by `noteRoute`: `noteObservation` does not carry it.
      existing.route = route.origin || !existing.route.origin
        ? route
        : { ...route, origin: existing.route.origin }
      return existing
    }
    const created: RouteFamilyState = {
      key,
      method: route.method,
      family,
      route,
      attempts: 0,
      status: null,
      anomaly: false,
      assigned: false,
      seq: ++this.sequence,
    }
    this.routeFamilies.set(key, created)
    return created
  }

  noteRoute(input: { method?: string; pathAndQuery?: string; origin?: string }): void {
    const route = cleanSpecRoute(input)
    if (!route) return
    // Route registration never counts as an attempt: `noteObservation` owns the attempt ledger.
    this.registerFamily(route)
    const key = `${route.method} ${route.path}`
    const existing = this.routeCounts.get(key)
    const count = (existing?.count ?? 0) + 1
    this.routeCounts.delete(key)
    this.routeCounts.set(key, { route, count })
    this.state = { ...this.state, route: this.targetRoute() }
  }

  /** Assignment targets (Tier-A/chain) still owe proof even if the worker never probes them. */
  noteAssignedRoutes(routes?: readonly { method?: string; path?: string; origin?: string }[]): void {
    for (const input of routes ?? []) {
      const route = cleanSpecRoute({ method: input.method, pathAndQuery: input.path, origin: input.origin })
      if (!route) continue
      this.registerFamily(route).assigned = true
    }
  }

  /** Highest probe-count route (ties resolve to the most recent), so the directive names the target. */
  private targetRoute(): SpecRouteEvidence | undefined {
    let best: { route: SpecRouteEvidence; count: number } | undefined
    for (const entry of this.routeCounts.values()) {
      if (!best || entry.count >= best.count) best = entry
    }
    return best?.route
  }

  private markCovered(routes: readonly { method?: string; path?: string }[] | undefined, text?: string): void {
    let matched = false
    if (routes?.length) {
      for (const route of routes) {
        const method = (route.method ?? '').toUpperCase().replace(/[^A-Z]/g, '').slice(0, 10)
        const path = (route.path ?? '').split(/[?#]/, 1)[0] ?? ''
        if (!path || !path.startsWith('/')) continue
        const family = normalizeRouteFamily(path)
        if (method) {
          this.coveredRoutes.add(`${method} ${path}`)
          if (family !== '/') this.coveredFamilies.add(`${method} ${family}`)
          matched = true
        } else if (family !== '/') {
          for (const candidate of this.routeFamilies.values()) {
            if (candidate.family === family) {
              this.coveredRoutes.add(`${candidate.method} ${candidate.route.path}`)
              this.coveredFamilies.add(candidate.key)
              matched = true
            }
          }
        }
      }
      if (matched) return
    }
    if (text) {
      for (const [key, entry] of this.routeCounts) {
        if (entry.route.path !== '/' && text.includes(entry.route.path)) {
          this.coveredRoutes.add(key)
          this.coveredFamilies.add(proofRouteKey(entry.route.method, entry.route.path))
          matched = true
        }
      }
      for (const family of this.routeFamilies.values()) {
        if (family.family === '/') continue
        const literal = family.route.path
        // Match either verbatim path or the static prefix before a parameterized segment
        // (e.g., `/api/v1/orders/` in a template literal covers `/api/v1/orders/:id`).
        const staticPrefix = family.family.includes('/:id')
          ? family.family.slice(0, family.family.indexOf('/:id') + 1)
          : ''
        if (text.includes(literal) || (staticPrefix.length >= 6 && text.includes(staticPrefix))) {
          this.coveredRoutes.add(`${family.method} ${literal}`)
          this.coveredFamilies.add(family.key)
          matched = true
        }
      }
      if (matched) return
    }
    // A route-opaque spec/verify covers exactly one route. Bind it now, to the highest-value route
    // that exists at submission time, so a later probe cannot inherit this proof.
    this.opaqueSpecAttempts += 1
    const candidate = this.highestValueUncoveredFamily()
    if (candidate) {
      this.coveredFamilies.add(candidate.key)
      this.opaqueSpecAttempts -= 1
    }
  }

  /** Highest-value route family that is neither covered nor gap-bound (used for opaque specs). */
  private highestValueUncoveredFamily(): RouteFamilyState | undefined {
    let best: RouteFamilyState | undefined
    let bestScore = -1
    for (const family of this.routeFamilies.values()) {
      if (family.family === '/' || this.coveredFamilies.has(family.key) || this.gapByRoute.has(family.key)) continue
      const score = routeObligationValue({
        key: family.key, method: family.method, path: family.route.path, family: family.family,
        params: family.route.params, attempts: family.attempts, status: family.status,
        anomaly: family.anomaly, assigned: family.assigned, covered: false,
      })
      if (!best || score >= bestScore) {
        best = family
        bestScore = score
      }
    }
    return best
  }

  /** A persisted/attempted replay spec. Route steps bind the attempt to the route(s) it proves. */
  noteSpecAttempt(routes?: readonly { method?: string; path?: string }[]): void {
    this.state = { ...this.state, specAttempts: this.state.specAttempts + 1 }
    this.markCovered(routes)
  }

  /** A kovo_verify script: cover host-observed transcript routes first, then matched script paths. */
  noteVerifyScript(
    script: string | undefined,
    transcriptRoutes?: readonly { method?: string; path?: string }[],
    options?: { confirmed?: boolean },
  ): void {
    this.state = { ...this.state, specAttempts: this.state.specAttempts + 1 }
    if (options?.confirmed) this.confirmedProofs += 1
    this.markCovered(transcriptRoutes?.length ? transcriptRoutes : undefined, script)
  }

  hasConfirmedProof(): boolean {
    return this.confirmedProofs > 0
  }

  /** Resolve the route a coded gap binds to; ambiguous or unknown bindings are rejected. */
  checkGapRoute(raw?: string): { ok: true; key: string } | { ok: false; error: string } {
    const obligations = this.obligationList()
    if (!obligations.length) return { ok: true, key: '' }
    const keys = obligations.slice(0, 8).map(obligation => obligation.key).join(', ')
    const reject = (detail: string) => ({
      ok: false as const,
      error: `record_coverage validation failed: status="needs_follow_up" with a coded proofGapReason is route-scoped. Missing required field \`route\` (the probed route this gap applies to, e.g. "GET /api/orders/:id"); ${detail}. Probed routes: ${keys}.`,
    })
    const trimmed = (raw ?? '').trim()
    if (trimmed) {
      const parsed = parseRouteReference(trimmed)
      if (!parsed) return reject(`route "${trimmed}" is not a \`METHOD /path\` reference`)
      const exact = obligations.find(obligation => obligation.key === parsed.key)
      if (exact) return { ok: true, key: exact.key }
      const byFamily = obligations.filter(obligation => obligation.family === parsed.family)
      if (!parsed.hasMethod && byFamily.length === 1) return { ok: true, key: byFamily[0]!.key }
      return reject(`route "${trimmed}" does not match a probed route`)
    }
    const uncovered = obligations.filter(obligation => !obligation.covered && !obligation.gap)
    if (uncovered.length === 1) return { ok: true, key: uncovered[0]!.key }
    return reject(
      uncovered.length > 1
        ? 'more than one route is uncovered, so the gap cannot be bound automatically'
        : 'every probed route is already covered or has a bound gap',
    )
  }

  noteProofGap(input: { proofGapReason?: string; category?: string; route?: string }): { ok: true } | { ok: false; error: string } {
    const reason = (input.proofGapReason ?? '').trim()
    if (reason.length < 5) return { ok: true }
    const code = parseProofGapCode(reason)
    let routeKey = ''
    if (code) {
      const binding = this.checkGapRoute(input.route)
      if (!binding.ok) return binding
      routeKey = binding.key
      if (routeKey && this.gapByRoute.has(routeKey)) {
        // One route-scoped gap per route: a repeated gap is idempotent (no counter/array growth).
        return { ok: true }
      }
    } else if (input.route) {
      const parsed = parseRouteReference(input.route)
      if (parsed) routeKey = parsed.key
    }
    const entry: SpecProofGapEntry = {
      reason: reason.slice(0, 600),
      code,
      ...(routeKey ? { route: routeKey } : {}),
      ...(input.category ? { category: input.category } : {}),
    }
    if (code && routeKey) this.gapByRoute.set(routeKey, entry)
    this.state = {
      ...this.state,
      proofGaps: [...this.state.proofGaps, entry].slice(-12),
      codedProofGaps: this.state.codedProofGaps + (code ? 1 : 0),
    }
    return { ok: true }
  }

  /** Mark a route as explicitly demanded (deduplicated: a route is demanded at most once). */
  noteDemand(key: string | undefined): void {
    if (key) this.demandedRoutes.add(key)
  }

  /** Running `agent.gap_validation` totals (copies; the ledger itself stays private). */
  gapValidationStats(): GapValidationStats {
    const byCode: Record<string, { accepted: number; rejected: number }> = {}
    for (const [code, entry] of Object.entries(this.gapStats.byCode)) {
      byCode[code] = { accepted: entry.accepted, rejected: entry.rejected }
    }
    return { accepted: this.gapStats.accepted, rejected: this.gapStats.rejected, byCode }
  }

  /**
   * Deterministic settlement gate: every coded `proofGapReason` must be substantiated by the
   * host-observed Layer-1 exchange ledger for the route it is bound to. A route is rejected at
   * most once per assignment (`gapVerdicts`), so an unsupported gap cannot loop complete_intent.
   *
   * Returns the newly rejected gaps plus the highest-value route the reserved wrap-up turn should
   * target (an invalid gap is treated as an open obligation for that selection).
   */
  validateGapsForSettlement(): { rejected: RejectedProofGap[]; target?: ProofRouteObligation } {
    const rejected: RejectedProofGap[] = []
    for (const [key, entry] of this.gapByRoute) {
      if (!entry.code) continue
      if (this.gapVerdicts.has(key)) continue
      const check = this.checkGapEvidence(key, entry.code)
      if (check.ok) {
        this.gapVerdicts.set(key, 'accepted')
        this.recordGapVerdict(entry.code, true)
      } else {
        this.gapVerdicts.set(key, 'rejected')
        this.recordGapVerdict(entry.code, false)
        rejected.push({ key, code: entry.code, missing: check.missing })
      }
    }
    const target = pickHighestValueRoute(this.obligationList().filter(obligation =>
      !obligation.covered && (!obligation.gap || this.gapVerdicts.get(obligation.key) === 'rejected')))
    return { rejected, ...(target ? { target } : {}) }
  }

  private recordGapVerdict(code: SpecProofGapCode, accepted: boolean): void {
    if (accepted) this.gapStats.accepted += 1
    else this.gapStats.rejected += 1
    const entry = this.gapStats.byCode[code] ?? { accepted: 0, rejected: 0 }
    if (accepted) entry.accepted += 1
    else entry.rejected += 1
    this.gapStats.byCode[code] = entry
  }

  /**
   * Evidence contract for each machine-readable code, read only from the host-observed exchange
   * ledger (status/persona/control/differential/denial). Bodies and worker prose are never read.
   */
  private checkGapEvidence(key: string, code: SpecProofGapCode):
    { ok: true; evidence: string } | { ok: false; missing: string } {
    const family = this.routeFamilies.get(key)
    const routeObs = this.observations.filter(observation => proofRouteKey(observation.method, observation.path) === key)
    const familyObs = family
      ? this.observations.filter(observation => normalizeRouteFamily(observation.path) === family.family)
      : routeObs
    const statuses = routeObs.map(observation => observation.status).filter((status): status is number => status !== null)
    const denial = statuses.some(status => status === 401 || status === 403)
    const loginRedirect = statuses.some(status => status >= 300 && status < 400)
    const personasSucceeded = new Set(routeObs
      .filter(observation => observation.persona && observation.status !== null && observation.status >= 200 && observation.status < 300)
      .map(observation => observation.persona!))
    const mutatingProbe = familyObs.some(observation =>
      GAP_MUTATING_METHODS.has(observation.method) && (observation.status === null || observation.status < 400))
    const readableGet = familyObs.some(observation =>
      observation.method === 'GET' && observation.status !== null && observation.status >= 200 && observation.status < 300)
    const controlExchange = routeObs.some(observation => observation.control === true)
    const differentialExchange = routeObs.some(observation => observation.differential === true)
    const route = family?.route

    switch (code) {
      case 'no_authenticated_persona':
      case 'auth_blocked':
        if (!denial && !loginRedirect) return { ok: false, missing: 'a 401/403 or login-redirect exchange on this route' }
        if (personasSucceeded.size >= 2) return { ok: false, missing: `fewer than two authenticated personas succeeding on this route (${personasSucceeded.size} succeeded)` }
        return { ok: true, evidence: `${denial ? '401/403' : 'login-redirect'} denial with ${personasSucceeded.size} authenticated persona(s) succeeding` }
      case 'endpoint_not_found':
        if (!routeObs.some(observation => observation.status === 404)) return { ok: false, missing: 'a 404 response on this exact route+method' }
        return { ok: true, evidence: '404 on the route+method' }
      case 'method_not_allowed':
        if (!routeObs.some(observation => observation.status === 405)) return { ok: false, missing: 'a 405 response on this exact route+method' }
        return { ok: true, evidence: '405 on the route+method' }
      case 'no_readback_surface':
        if (!mutatingProbe) return { ok: false, missing: 'at least one non-denied mutating probe (POST/PUT/PATCH/DELETE) on the resource family' }
        if (readableGet) return { ok: false, missing: 'zero readable GET endpoints in the resource family (a 2xx GET was observed)' }
        return { ok: true, evidence: 'a mutating probe with no readable GET readback' }
      case 'invariant_enforced_hardened':
      case 'control_blocked_cleanly':
      case 'decoy_guard_verified':
        if (
          denial
          || statuses.some(status => status === 404 || status === 409 || status === 412 || status === 422)
          || (controlExchange && differentialExchange)
        ) {
          return { ok: true, evidence: 'enforced denial or control + differential probe exchanges on the route' }
        }
        return {
          ok: false,
          missing: 'a 401/403/404/409/412/422 enforcement denial or control + differential probe exchanges on this route',
        }
      case 'hardened_or_no_anomaly':
      case 'no_reproducible_signal':
        if (!controlExchange) return { ok: false, missing: 'a control exchange on this route' }
        if (!differentialExchange) return { ok: false, missing: 'at least one differential probe exchange on this route' }
        return { ok: true, evidence: 'control + differential probe exchanges on the route' }
      case 'tier_blocked':
        if (!routeObs.some(observation => observation.denial === 'tier')) return { ok: false, missing: 'a host tier-denied exchange (Tier 2/3/approval required)' }
        return { ok: true, evidence: 'a tier-denied exchange' }
      case 'out_of_scope':
        if (routeObs.some(observation => observation.denial === 'scope')) return { ok: true, evidence: 'a scope-denied exchange' }
        if (this.approvedOrigins.size > 0) {
          if (route?.origin && this.approvedOrigins.has(route.origin)) {
            return { ok: false, missing: `a route outside the approved origins (${route.origin} is approved)` }
          }
          return { ok: true, evidence: 'route outside the approved origin set' }
        }
        if (routeObs.length === 0) return { ok: true, evidence: 'route was never reachable inside the approved origin set' }
        return { ok: false, missing: 'a route outside the approved origins (the route was reached in scope)' }
      case 'runtime_unavailable':
        if (routeObs.length === 0) return { ok: true, evidence: 'no exchange was possible on the route' }
        if (routeObs.some(observation => observation.denial === 'runtime')) return { ok: true, evidence: 'a runtime-denied exchange' }
        if (statuses.some(status => status >= 200 && status < 300)) return { ok: false, missing: 'evidence that the runtime is unavailable (a 2xx exchange was recorded)' }
        return { ok: true, evidence: 'no successful exchange on the route' }
      case 'no_spec_shape':
      case 'cannot_build_spec':
      case 'baseline_empty':
      case 'no_control_path':
      default:
        if (routeObs.length === 0) return { ok: false, missing: 'at least one recorded exchange on this route' }
        return { ok: true, evidence: 'the route was exercised' }
    }
  }

  private obligationList(): ProofRouteObligation[] {
    const list: ProofRouteObligation[] = []
    for (const family of [...this.routeFamilies.values()].sort((a, b) => a.seq - b.seq)) {
      if (family.family === '/') continue
      const gap = this.gapByRoute.get(family.key)
      list.push({
        key: family.key,
        method: family.method,
        path: family.route.path,
        family: family.family,
        params: [...family.route.params],
        ...(family.route.origin ? { origin: family.route.origin } : {}),
        attempts: family.attempts,
        status: family.status,
        anomaly: family.anomaly,
        assigned: family.assigned,
        covered: this.coveredFamilies.has(family.key),
        ...(gap?.code ? { gap: gap.code } : {}),
      })
    }
    // A route-opaque spec/verify covers one route only (highest value first), never every route.
    let opaque = this.opaqueSpecAttempts
    while (opaque > 0) {
      const candidate = pickHighestValueRoute(list.filter(obligation => !obligation.covered))
      if (!candidate) break
      candidate.covered = true
      opaque -= 1
    }
    return list
  }

  private statsFrom(obligations: readonly ProofRouteObligation[]): ProofObligationStats {
    return {
      probedRoutes: obligations.filter(obligation => obligation.attempts > 0 || !obligation.assigned).length,
      coveredRoutes: obligations.filter(obligation => obligation.covered).length,
      gapRoutes: obligations.filter(obligation => Boolean(obligation.gap)).length,
      demandedRoutes: obligations.filter(obligation => this.demandedRoutes.has(obligation.key)).length,
      dischargedByGap: obligations.filter(obligation => !obligation.covered && Boolean(obligation.gap)).length,
    }
  }

  proofObligationStats(): ProofObligationStats {
    return this.statsFrom(this.obligationList())
  }

  private obligationTarget(obligations: readonly ProofRouteObligation[]): SpecRouteEvidence | undefined {
    const best = pickHighestValueRoute(obligations.filter(obligation => !obligation.covered && !obligation.gap))
    return best
      ? { method: best.method, path: best.path, params: [...best.params], ...(best.origin ? { origin: best.origin } : {}) }
      : undefined
  }

  noteRequired(): number {
    const required = this.state.required + 1
    this.state = { ...this.state, required }
    return required
  }

  /**
   * Record one observed route response. Called from `wrapExec` with the raw broker/probe result,
   * so the evidence is host-observed and never parsed from tool text. Bounded to the last 64
   * observations; duplicates are kept so repeat density stays visible (attempts vs distinct).
   */
  noteObservation(input: {
    method?: string
    pathAndQuery?: string
    origin?: string
    status?: number | null
    bodySha256?: string | null
    anomaly?: boolean
    refuted?: boolean
    staticCatchAll?: boolean
    persona?: string
    control?: boolean
    differential?: boolean
  }): void {
    const route = cleanSpecRoute(input)
    if (!route) return
    const raw = (input.pathAndQuery ?? '').trim()
    const status = typeof input.status === 'number' && Number.isFinite(input.status) ? Math.trunc(input.status) : null
    // Every observed response is a successful probe on this route family: register/refresh it.
    const family = this.registerFamily(route)
    family.attempts += 1
    if (status !== null) family.status = status
    if (input.anomaly === true) family.anomaly = true
    this.observations.push({
      method: route.method,
      path: route.path,
      pathAndQuery: raw.slice(0, 320),
      status,
      bodySha256: typeof input.bodySha256 === 'string' && input.bodySha256 ? input.bodySha256.slice(0, 128) : null,
      anomaly: input.anomaly === true,
      refuted: input.refuted === true,
      staticCatchAll: input.staticCatchAll === true,
      ...(route.origin ? { origin: route.origin } : {}),
      ...(input.persona ? { persona: input.persona } : {}),
      ...(input.control === true ? { control: true } : {}),
      ...(input.differential === true ? { differential: true } : {}),
    })
    if (this.observations.length > 64) this.observations.splice(0, this.observations.length - 64)
  }

  /**
   * Record a host-side denial (tier/scope/auth/runtime) that reached Kovo Hunter but never the app.
   * This is the transcript evidence that can substantiate a `tier_blocked`/`out_of_scope` gap;
   * it never increments probe attempts.
   */
  noteDenial(input: { method?: string; pathAndQuery?: string; origin?: string; kind: GapDenialKind }): void {
    const route = cleanSpecRoute(input)
    if (!route) return
    this.registerFamily(route)
    this.observations.push({
      method: route.method,
      path: route.path,
      pathAndQuery: (input.pathAndQuery ?? '').trim().slice(0, 320),
      status: null,
      bodySha256: null,
      anomaly: false,
      refuted: false,
      staticCatchAll: false,
      ...(route.origin ? { origin: route.origin } : {}),
      denial: input.kind,
    })
    if (this.observations.length > 64) this.observations.splice(0, this.observations.length - 64)
  }

  /** Approved origins for this run (used only to substantiate `out_of_scope`). */
  noteApprovedOrigins(origins?: readonly string[]): void {
    for (const origin of origins ?? []) {
      const clean = (origin ?? '').trim().replace(/\/+$/, '')
      if (/^https?:\/\//i.test(clean)) this.approvedOrigins.add(clean)
    }
  }

  /** Aggregate the route ledger into the numbers the early-exit predicate and event report. */
  observationSnapshot(): RouteObservationSnapshot {
    interface FamilyState {
      key: string
      method: string
      family: string
      observations: RouteAttemptObservation[]
    }
    const families = new Map<string, FamilyState>()
    let anomalyCount = 0
    for (const observation of this.observations) {
      if (observation.anomaly) anomalyCount += 1
      const family = normalizeRouteFamily(observation.path)
      const key = `${observation.method} ${family}`
      const existing = families.get(key)
      if (existing) existing.observations.push(observation)
      else families.set(key, { key, method: observation.method, family, observations: [observation] })
    }
    const routeSummaries: RouteObservation[] = []
    let target: FamilyState | undefined
    for (const family of families.values()) {
      const statuses = family.observations.map(o => o.status).filter((status): status is number => status !== null)
      routeSummaries.push({
        family: family.family,
        method: family.method,
        attempts: family.observations.length,
        distinctAttempts: new Set(family.observations.map(o => o.pathAndQuery)).size,
        statuses,
        anomalyCount: family.observations.filter(o => o.anomaly).length,
      })
      // Highest attempt count wins; ties resolve to the most recently touched family.
      if (!target || family.observations.length >= target.observations.length) target = family
    }
    const observations = target?.observations ?? []
    const attemptKeys = new Set(observations.map(o => o.pathAndQuery))
    const pathKeys = new Set(observations.map(o => `${o.method} ${o.path}`))
    const paramKeys = new Set(observations.map(o => paramNamesOf(o.pathAndQuery).join('&')))
    const bodies = new Set(observations.map(o => o.bodySha256).filter((sha): sha is string => Boolean(sha)))
    const statuses = observations.map(o => o.status).filter((status): status is number => status !== null)
    const last = observations[observations.length - 1]
    return {
      attempts: observations.length,
      distinctAttempts: attemptKeys.size,
      distinctPaths: pathKeys.size,
      distinctParams: paramKeys.size,
      distinctBodies: bodies.size,
      anomalyCount,
      statuses,
      denialStatuses: statuses.filter(status => EARLY_EXIT_HARDENED_STATUSES.has(status)),
      stateChangeAttempts: observations.filter(o =>
        EARLY_EXIT_STATE_CHANGE_METHODS.has(o.method) && o.status !== null && !EARLY_EXIT_HARDENED_STATUSES.has(o.status)).length,
      staticCatchAll: observations.some(o => o.staticCatchAll),
      refutedHypotheses: observations.filter(o => o.refuted).length,
      ...(last ? { route: { method: last.method, path: last.path, params: paramNamesOf(last.pathAndQuery).slice(0, 4) } } : {}),
      routes: routeSummaries,
    }
  }

  snapshot(): SpecSubmissionSnapshot {
    const target = this.state.route
    // Bind only when we have a non-root target route. Without one (batch/race/probe-only evidence)
    // any submitted spec is conservative: never reject a conclusion we cannot route-check.
    const targetCovered = target && target.path !== '/'
      ? this.coveredRoutes.has(`${target.method} ${target.path}`) || (this.state.probes > 0 && this.opaqueSpecAttempts > 0)
      : this.state.specAttempts > 0
    const obligations = this.obligationList()
    const obligationTarget = this.obligationTarget(obligations)
    return {
      ...this.state,
      targetCovered,
      proofGaps: [...this.state.proofGaps],
      obligations,
      obligation: this.statsFrom(obligations),
      ...(target ? { route: { ...target, params: [...target.params] } } : {}),
      ...(obligationTarget ? { obligationTarget } : {}),
    }
  }
}

/**
 * A proof is owed per route: every probed/assigned route family must be covered by a submitted
 * spec/verify or carry its own coded proof gap. A gap on one route never discharges another.
 */
export function specSubmissionPending(snapshot: SpecSubmissionSnapshot): boolean {
  const obligations = snapshot.obligations ?? []
  if (!obligations.length) return false
  return obligations.some(obligation => !obligation.covered && !obligation.gap)
}

/** Settlement must refuse a leaning conclusion when the proof obligation is still open. */
export function specSubmissionRequiredFor(snapshot: SpecSubmissionSnapshot): boolean {
  return specSubmissionPending(snapshot)
}

// ---------------------------------------------------------------------------
// v7 M5 throughput: early-exit settlement on clearly clean/hardened routes
// ---------------------------------------------------------------------------
//
// The single-step budget was raised 12→18 turns / 80→120 s because most held-out no-spec targets
// were cap-truncated. The accepted cost is a higher p50. The remedy is not a lower ceiling: when a
// route is *provably* hardened, stop probing at turn 5-6 and spend the reserved wrap-up turn on the
// spec / coded proof gap instead of burning turns 7-18. The exit is evidence-gated (never vibes):
// at least two distinct attempts on distinct paths/params, every status a hardened denial (or a
// calibrated static catch-all, or a control-vs-probe refutation), and zero anomalies. It is blocked
// while a spec submission is in flight, a complete_intent repair is in flight, or a free-text proof
// gap is still uncoded, so an unearned exit can never suppress work in progress.

/** Hardened/denial statuses: the route answers the same refusal/rejection to every attempt. */


/** Pure settlement gate shared by the tool hook and tests. */
export function settlementToolBlock(input: {
  name: string
  settling: boolean
  turnsUsed: number
  maxTurns: number
  /** True when a probed route still has no spec attempt and no coded proof gap. */
  specPending?: boolean
  /** Pre-rendered settlement proof obligation naming the route + smallest spec. */
  specDirective?: string
  /**
   * Effective final turn. Defaults to `maxTurns`; an earned early exit passes
   * `min(maxTurns, triggerTurn + EARLY_EXIT_GRACE_TURNS)` so the last grace turn is reserved for
   * complete_intent while the turn before it can still run the one wrap-up kovo_verify.
   */
  finalTurn?: number
}): string | undefined {
  if (!input.settling) return undefined
  const finalTurn = input.finalTurn ?? input.maxTurns
  if (!SETTLEMENT_ALLOWED_TOOLS.has(input.name)) {
    return `Settlement wrap-up active (${input.turnsUsed}/${input.maxTurns} turns). ${input.name} is disabled during settlement. Finalize offline analysis, commit record_fact / record_coverage / propose_chain_finding, and call complete_intent.`
  }
  if (input.turnsUsed >= finalTurn && SETTLEMENT_WRAPUP_TOOLS.has(input.name)) {
    return `Final settlement turn (${input.turnsUsed}/${finalTurn}). ${input.name} is disabled on the final turn; commit results and call complete_intent.`
  }
  if (input.specPending && SETTLEMENT_SPEC_PAUSED_TOOLS.has(input.name)) {
    return `${input.specDirective ? `${input.specDirective} ` : ''}${input.name} is paused during settlement while the proof obligation is open; call kovo_verify (or record a coded record_coverage proof gap) before complete_intent.`
  }
  return undefined
}

// ---------------------------------------------------------------------------
// Output Formatting & Spilling Helpers
// ---------------------------------------------------------------------------


function truncateUtf8Tail(text: string, maxBytes: number): string {
  const buf = Buffer.from(text, 'utf8')
  if (buf.length <= maxBytes) return text
  let start = buf.length - maxBytes
  while (start < buf.length && (buf[start] & 0xc0) === 0x80) start++
  return buf.subarray(start).toString('utf8')
}

// ---------------------------------------------------------------------------
// Q2: Host-Executed Read-Only Repo & Evidence Tools + Malformed-Arg Diagnostics
// ---------------------------------------------------------------------------

const HOST_REPO_SKIP_DIRS = new Set([
  '.git', 'node_modules', '.ssh', '.gnupg', '.aws', '.kube', '.docker', '.azure', '.gcloud', '.terraform',
])
const HOST_REPO_SENSITIVE_FILES = new Set([
  'id_rsa', 'id_ed25519', 'id_ecdsa', 'id_dsa', '.netrc', '.npmrc', '.pypirc', '.pgpass', '.my.cnf', '.git-credentials',
])
const HOST_REPO_SENSITIVE_EXT_RE = /\.(?:pem|key|p12|pfx|jks|keystore|kdbx|ppk)$/i
const HOST_REPO_SAFE_ENV_TEMPLATE_RE = /^\.env\.(?:example|sample|template|dist|defaults?)$/i
const HOST_REPO_SOURCE_EXT_RE = /\.(?:[cm]?[jt]sx?|py|go|rs|java|kt|rb|php|cs|c|cpp|h|hpp|swift|scala)$/i
const SAFE_ARTIFACT_ID_RE = /^[A-Za-z0-9._-]{1,180}$/
const SAFE_MOUNTED_REPO_RE = /^\/repos\/([A-Za-z0-9._-]+)\/([A-Za-z0-9._-]+)$/

const MAX_REPO_FILE_BYTES = 4 * 1024 * 1024
const DEFAULT_REPO_READ_LINES = 200
const MAX_REPO_READ_LINES = 400
const MAX_REPO_READ_OUTPUT_BYTES = 16 * 1024

const DEFAULT_SEARCH_MATCHES = 50
const MAX_SEARCH_MATCHES = 200
const MAX_SEARCH_FILES = 4_000
const MAX_SEARCH_FILE_BYTES = 512 * 1024
const MAX_SEARCH_LINE_CHARS = 240

const DEFAULT_EVIDENCE_SLICE_LIMIT = 8_192
const MAX_EVIDENCE_SLICE_LIMIT = 16_384
const MAX_HOST_SPILL_ENTRIES = 64
const MAX_HOST_SPILL_TOTAL_BYTES = 16 * 1024 * 1024

function isSensitiveHostRepoSegment(segment: string, isDir: boolean, parentSegments: readonly string[]): boolean {
  const lower = segment.toLowerCase()
  if (HOST_REPO_SKIP_DIRS.has(lower)) return true
  if (isDir) return false
  if (HOST_REPO_SENSITIVE_FILES.has(lower)) return true
  if (HOST_REPO_SENSITIVE_EXT_RE.test(lower)) return true
  if (lower === '.env' || (lower.startsWith('.env.') && !HOST_REPO_SAFE_ENV_TEMPLATE_RE.test(lower))) return true
  if (parentSegments.some(p => p.toLowerCase() === 'credentials') && !HOST_REPO_SOURCE_EXT_RE.test(lower)) return true
  return false
}

function isSensitiveHostRepoPath(relPosixPath: string): boolean {
  const segments = relPosixPath.split('/').filter(Boolean)
  if (segments.length === 0) return false
  for (let i = 0; i < segments.length; i += 1) {
    const isDir = i < segments.length - 1
    if (isSensitiveHostRepoSegment(segments[i]!, isDir, segments.slice(0, i))) return true
  }
  return false
}

function assertCleanRootDir(rootDir: string, label: string): string {
  if (!rootDir || /[\0\r\n]/.test(rootDir) || !existsSync(rootDir)) {
    throw new Error(`${label} directory is not available.`)
  }
  const st = lstatSync(rootDir)
  if (!st.isDirectory() || st.isSymbolicLink()) {
    throw new Error(`${label} root must be a real non-symlink directory.`)
  }
  return realpathSync(rootDir)
}

function resolveJailedHostPath(
  rootDir: string,
  rawPath: string,
  kind: 'repo' | 'evidence',
  options?: { allowRoot?: boolean },
): { realRoot: string; realTarget: string; relPosix: string } {
  const label = kind === 'repo' ? '/repos' : '/evidence'
  const realRoot = assertCleanRootDir(rootDir, label)
  const trimmed = rawPath.trim()
  if (/[\0\r\n]/.test(trimmed) || /^[A-Za-z]:/.test(trimmed)) {
    throw new Error(`Invalid ${label} path: control characters or drive prefixes are refused.`)
  }
  if (trimmed.includes('\\')) {
    throw new Error(`Invalid ${label} path: backslashes are not permitted.`)
  }
  const stripped = kind === 'repo'
    ? trimmed.replace(/^\/?repos(?:\/|$)/, '')
    : trimmed.replace(/^\/?evidence(?:\/|$)/, '')
  const rawSegments = stripped.split('/')
  const segments: string[] = []
  for (const seg of rawSegments) {
    if (!seg) continue
    if (seg === '.' || seg === '..') {
      throw new Error(`Path traversal refused: "${rawPath}" escapes ${label}.`)
    }
    segments.push(seg)
  }
  if (segments.length === 0) {
    if (options?.allowRoot) {
      return { realRoot, realTarget: realRoot, relPosix: '' }
    }
    throw new Error(`Path must reference a file inside ${label}.`)
  }
  const candidateRel = segments.join('/')
  if (kind === 'repo' && isSensitiveHostRepoPath(candidateRel)) {
    throw new Error(`Access refused for restricted repository path "${candidateRel}" (.git, node_modules, and credential/secret files are blocked).`)
  }

  let current = realRoot
  for (const seg of segments) {
    current = join(current, seg)
    let lst
    try {
      lst = lstatSync(current)
    } catch {
      throw new Error(`Path not found under ${label}: "${candidateRel}".`)
    }
    if (lst.isSymbolicLink()) {
      throw new Error(`Symlink escape refused under ${label}: symbolic links are not permitted ("${candidateRel}").`)
    }
  }
  const realTarget = realpathSync(current)
  if (realTarget !== realRoot && !realTarget.startsWith(realRoot + sep)) {
    throw new Error(`Path traversal refused: "${rawPath}" escapes ${label}.`)
  }
  const canonicalRel = relative(realRoot, realTarget).split(sep).join('/')
  if (kind === 'repo' && canonicalRel && isSensitiveHostRepoPath(canonicalRel)) {
    throw new Error(`Access refused for restricted repository path "${canonicalRel}".`)
  }
  return { realRoot, realTarget, relPosix: canonicalRel }
}

function isBinaryBuffer(buf: Buffer): boolean {
  const probeLen = Math.min(buf.length, 8_192)
  for (let i = 0; i < probeLen; i += 1) {
    if (buf[i] === 0) return true
  }
  return false
}

export interface HostReadRepoFileResult {
  path: string
  startLine: number
  endLine: number
  totalLines: number
  truncated: boolean
  nextStartLine?: number
  content: string
}

export function readRepoFileHost(reposDir: string, args: ReadRepoFileArgs): HostReadRepoFileResult {
  const resolved = resolveJailedHostPath(reposDir, args.path, 'repo', { allowRoot: false })
  const st = lstatSync(resolved.realTarget)
  if (!st.isFile()) {
    throw new Error(`Path "/repos/${resolved.relPosix}" is not a regular file.`)
  }
  if (st.size > MAX_REPO_FILE_BYTES) {
    throw new Error(`File "/repos/${resolved.relPosix}" exceeds the ${Math.floor(MAX_REPO_FILE_BYTES / (1024 * 1024))} MiB read_repo_file limit.`)
  }
  const buf = readFileSync(resolved.realTarget)
  if (isBinaryBuffer(buf)) {
    throw new Error(`File "/repos/${resolved.relPosix}" appears to be binary and cannot be read as UTF-8 text.`)
  }
  const text = buf.toString('utf8')
  const normalizedText = text.endsWith('\r\n') ? text.slice(0, -2) : (text.endsWith('\n') ? text.slice(0, -1) : text)
  const lines = normalizedText.length === 0 ? [] : normalizedText.split(/\r?\n/)
  const totalLines = lines.length
  const startLine = Math.max(1, Math.trunc(args.startLine ?? 1))
  if (totalLines === 0 || startLine > totalLines) {
    return {
      path: `/repos/${resolved.relPosix}`,
      startLine,
      endLine: totalLines,
      totalLines,
      truncated: false,
      content: '',
    }
  }
  const requestedEnd = args.endLine !== undefined
    ? Math.trunc(args.endLine)
    : startLine + DEFAULT_REPO_READ_LINES - 1
  const cappedEnd = Math.min(totalLines, Math.max(startLine, Math.min(requestedEnd, startLine + MAX_REPO_READ_LINES - 1)))

  const outLines: string[] = []
  let bytesUsed = 0
  let actualEnd = startLine - 1
  for (let lineNo = startLine; lineNo <= cappedEnd; lineNo += 1) {
    const rawLine = lines[lineNo - 1] ?? ''
    const formatted = `${lineNo}: ${rawLine}`
    const lineBytes = Buffer.byteLength(formatted, 'utf8') + (outLines.length > 0 ? 1 : 0)
    if (outLines.length > 0 && bytesUsed + lineBytes > MAX_REPO_READ_OUTPUT_BYTES) {
      break
    }
    if (outLines.length === 0 && lineBytes > MAX_REPO_READ_OUTPUT_BYTES) {
      outLines.push(truncateUtf8Head(formatted, MAX_REPO_READ_OUTPUT_BYTES))
      actualEnd = lineNo
      break
    }
    outLines.push(formatted)
    bytesUsed += lineBytes
    actualEnd = lineNo
  }

  const truncated = actualEnd < totalLines
  return {
    path: `/repos/${resolved.relPosix}`,
    startLine,
    endLine: actualEnd,
    totalLines,
    truncated,
    ...(truncated ? { nextStartLine: actualEnd + 1 } : {}),
    content: outLines.join('\n'),
  }
}

export type HostSearchRepoResult = SearchRepoWorkerResult

export interface SearchRepoHostOptions {
  deadlineMs?: number
  maxBytes?: number
  signal?: AbortSignal
}

function prepareSearchRepoWorkerRequest(
  reposDir: string,
  args: SearchRepoArgs,
  opts: SearchRepoHostOptions = {},
): SearchRepoWorkerRequest {
  const query = typeof args.query === 'string' ? args.query : ''
  if (!query || query.length > 256) {
    throw new Error('search_repo query must be a non-empty string up to 256 characters.')
  }
  const maxMatches = Math.max(1, Math.min(Math.trunc(args.maxMatches ?? DEFAULT_SEARCH_MATCHES), MAX_SEARCH_MATCHES))
  const useRegex = args.regex === true
  const caseSensitive = args.caseSensitive === true

  if (useRegex) {
    // Compile without `i`/`u` flags so V8's linear-time fallback engine engages (R3-H-11).
    const compiled = compileSafeClaimRegex(query, { flags: '', maxLength: 256 })
    if (!compiled.ok) {
      throw new Error(`Unsafe or invalid search_repo regex rejected: ${compiled.reason} Use literal search (regex: false) or a simpler linear pattern.`)
    }
  }

  const budgets = resolveRunSafetyBudgets({
    overrides: {
      ...(opts.deadlineMs !== undefined ? { searchRepoDeadlineMs: opts.deadlineMs } : {}),
      ...(opts.maxBytes !== undefined ? { searchRepoMaxBytes: opts.maxBytes } : {}),
    },
  })
  const resolved = resolveJailedHostPath(reposDir, args.pathPrefix ?? '', 'repo', { allowRoot: true })
  return {
    realTarget: resolved.realTarget,
    relPosix: resolved.relPosix,
    query,
    regex: useRegex,
    caseSensitive,
    maxMatches,
    maxFiles: MAX_SEARCH_FILES,
    maxFileBytes: MAX_SEARCH_FILE_BYTES,
    maxBytes: budgets.searchRepoMaxBytes,
    maxLineChars: MAX_SEARCH_LINE_CHARS,
    deadlineMs: budgets.searchRepoDeadlineMs,
  }
}

export function searchRepoHost(
  reposDir: string,
  args: SearchRepoArgs,
  opts?: Omit<SearchRepoHostOptions, 'signal'>,
): HostSearchRepoResult {
  const req = prepareSearchRepoWorkerRequest(reposDir, args, opts)
  return executeSearchRepoScan(req)
}

/**
 * Off-host worker-thread `search_repo` execution (`R4-H-15`): validates query/regex/path-jail on
 * the host, then delegates repo walking and regex matching to `UntrustedComputePool` with a hard
 * wall-clock `searchRepoDeadlineMs` timeout enforced via `worker.terminate()`.
 */
export async function searchRepoHostInWorker(
  reposDir: string,
  args: SearchRepoArgs,
  opts: SearchRepoHostOptions = {},
): Promise<HostSearchRepoResult> {
  const req = prepareSearchRepoWorkerRequest(reposDir, args, opts)
  return searchRepoInWorker(req, { timeoutMs: req.deadlineMs, signal: opts.signal })
}

/** Registry preserving sync test-compat `searchRepoHost` alongside authoritative off-host `searchRepoHostInWorker`. */
const HOST_REPO_SEARCH_RUNNERS = {
  syncCompat: searchRepoHost,
  worker: searchRepoHostInWorker,
} as const

interface HostSpillRecord {
  artifactId: string
  path: string
  relPath: string
  content: string
  bytes: number
}

export class HostSpillStore {
  private readonly entries = new Map<string, HostSpillRecord>()
  private readonly pathIndex = new Map<string, string>()
  private totalBytes = 0

  put(artifactId: string, spilledPath: string, content: string): void {
    const cleanPath = spilledPath.startsWith('/evidence/') ? spilledPath : `/evidence/${spilledPath.replace(/^\/+/, '')}`
    const relPath = cleanPath.replace(/^\/evidence\//, '')
    const bytes = Buffer.byteLength(content, 'utf8')
    const existing = this.entries.get(artifactId)
    if (existing) {
      this.totalBytes -= existing.bytes
      this.entries.delete(artifactId)
    }
    this.entries.set(artifactId, { artifactId, path: cleanPath, relPath, content, bytes })
    this.pathIndex.set(cleanPath, artifactId)
    this.pathIndex.set(relPath, artifactId)
    this.totalBytes += bytes

    while (this.entries.size > MAX_HOST_SPILL_ENTRIES || this.totalBytes > MAX_HOST_SPILL_TOTAL_BYTES) {
      const oldestKey = this.entries.keys().next().value
      if (oldestKey === undefined || oldestKey === artifactId) break
      const oldest = this.entries.get(oldestKey)!
      this.entries.delete(oldestKey)
      this.pathIndex.delete(oldest.path)
      this.pathIndex.delete(oldest.relPath)
      this.totalBytes -= oldest.bytes
    }
  }

  get(query: { artifactId?: string; path?: string }): HostSpillRecord | undefined {
    const id = query.artifactId?.trim()
    if (id) {
      const byId = this.entries.get(id)
      if (byId) return byId
    }
    const rawPath = query.path?.trim()
    if (rawPath) {
      const normRel = rawPath.replace(/^\/?evidence\//, '').replace(/^\/+/, '')
      const mappedId = this.pathIndex.get(rawPath) ?? this.pathIndex.get(`/evidence/${normRel}`) ?? this.pathIndex.get(normRel)
      if (mappedId) return this.entries.get(mappedId)
      const match = /^tool-output\/([^/]+)\.txt$/.exec(normRel)
      if (match && this.entries.has(match[1]!)) return this.entries.get(match[1]!)
    }
    return undefined
  }

  listIds(limit = 8): string[] {
    return [...this.entries.keys()].slice(-limit)
  }
}

export interface HostReadEvidenceSliceResult {
  artifactId: string | null
  path: string
  offset: number
  limit: number
  returnedChars: number
  totalChars: number
  hasMore: boolean
  nextOffset?: number
  content: string
}

export function readEvidenceSliceHost(
  context: { spillStore?: HostSpillStore; evidenceDir?: string },
  args: ReadEvidenceSliceArgs,
): HostReadEvidenceSliceResult {
  const artifactId = args.artifactId?.trim() || undefined
  const rawPath = args.path?.trim() || undefined
  if (!artifactId && !rawPath) {
    throw new Error('read_evidence_slice requires either `artifactId` or `path`.')
  }
  const offset = Math.max(0, Math.trunc(args.offset ?? 0))
  const limit = Math.max(1, Math.min(Math.trunc(args.limit ?? DEFAULT_EVIDENCE_SLICE_LIMIT), MAX_EVIDENCE_SLICE_LIMIT))

  const sliceText = (resolvedId: string | null, resolvedPath: string, fullText: string): HostReadEvidenceSliceResult => {
    const totalChars = fullText.length
    const clampedOffset = Math.min(offset, totalChars)
    const content = fullText.slice(clampedOffset, clampedOffset + limit)
    const nextOffset = clampedOffset + content.length
    const hasMore = nextOffset < totalChars
    return {
      artifactId: resolvedId,
      path: resolvedPath,
      offset: clampedOffset,
      limit,
      returnedChars: content.length,
      totalChars,
      hasMore,
      ...(hasMore ? { nextOffset } : {}),
      content,
    }
  }

  const cached = context.spillStore?.get({ artifactId, path: rawPath })
  if (cached) {
    return sliceText(cached.artifactId, cached.path, cached.content)
  }

  if (context.evidenceDir) {
    let candidatePath: string
    if (rawPath) {
      candidatePath = rawPath
    } else {
      if (!artifactId || !SAFE_ARTIFACT_ID_RE.test(artifactId) || artifactId === '.' || artifactId === '..') {
        throw new Error(`Invalid evidence artifactId "${artifactId ?? ''}".`)
      }
      const toolOutRel = `tool-output/${artifactId}.txt`
      candidatePath = existsSync(join(context.evidenceDir, toolOutRel)) ? toolOutRel : artifactId
    }
    const resolved = resolveJailedHostPath(context.evidenceDir, candidatePath, 'evidence', { allowRoot: false })
    const st = lstatSync(resolved.realTarget)
    if (!st.isFile()) {
      throw new Error(`Evidence path "/evidence/${resolved.relPosix}" is not a regular file.`)
    }
    if (st.size > MAX_REPO_FILE_BYTES) {
      throw new Error(`Evidence file "/evidence/${resolved.relPosix}" exceeds the host slice read limit.`)
    }
    const buf = readFileSync(resolved.realTarget)
    if (isBinaryBuffer(buf)) {
      throw new Error(`Evidence file "/evidence/${resolved.relPosix}" is binary and cannot be sliced as UTF-8 text.`)
    }
    return sliceText(artifactId ?? null, `/evidence/${resolved.relPosix}`, buf.toString('utf8'))
  }

  const available = context.spillStore?.listIds() ?? []
  const hint = available.length > 0 ? ` Available spilled artifactIds: ${available.join(', ')}.` : ''
  throw new Error(`Evidence artifact/path "${artifactId ?? rawPath}" not found in host spill store.${hint} For exchange bodies use get_exchange; for container-only /evidence files use derive_evidence.`)
}

/**
 * Resolve `<dataDir>/repos/<projectId>` when `runAgentSession` is called with a prompt declaring
 * `mountedRepos` (and no explicit `reposDir`). Fails closed unless exactly one non-symlink project
 * directory matches all declared `/repos/<owner>/<repo>` entries.
 */
export function resolveAutoReposDir(dataDir: string | undefined, prompt: string): string | undefined {
  if (!dataDir || !prompt || !prompt.includes('"mountedRepos"')) return undefined
  let parsed: unknown
  try {
    parsed = JSON.parse(prompt)
  } catch {
    return undefined
  }
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) return undefined
  const rawMounted = (parsed as { mountedRepos?: unknown }).mountedRepos
  if (!Array.isArray(rawMounted) || rawMounted.length === 0) return undefined
  const requiredRepos: Array<{ owner: string; repo: string }> = []
  for (const item of rawMounted) {
    if (typeof item !== 'string') continue
    const m = SAFE_MOUNTED_REPO_RE.exec(item.trim())
    if (!m) return undefined
    requiredRepos.push({ owner: m[1]!, repo: m[2]! })
  }
  if (requiredRepos.length === 0) return undefined

  const reposBase = join(dataDir, 'repos')
  if (!existsSync(reposBase)) return undefined
  let baseStat
  try {
    baseStat = lstatSync(reposBase)
  } catch {
    return undefined
  }
  if (!baseStat.isDirectory() || baseStat.isSymbolicLink()) return undefined

  let projects
  try {
    projects = readdirSync(reposBase, { withFileTypes: true })
  } catch {
    return undefined
  }
  const matches: string[] = []
  for (const proj of projects) {
    if (proj.name.startsWith('.') || !proj.isDirectory() || proj.isSymbolicLink()) continue
    const projDir = join(reposBase, proj.name)
    let allPresent = true
    for (const { owner, repo } of requiredRepos) {
      const ownerDir = join(projDir, owner)
      const repoDir = join(ownerDir, repo)
      try {
        const oSt = lstatSync(ownerDir)
        const rSt = lstatSync(repoDir)
        if (!oSt.isDirectory() || oSt.isSymbolicLink() || !rSt.isDirectory() || rSt.isSymbolicLink()) {
          allPresent = false
          break
        }
      } catch {
        allPresent = false
        break
      }
    }
    if (allPresent) matches.push(projDir)
    if (matches.length > 1) return undefined
  }
  return matches.length === 1 ? matches[0] : undefined
}

export const MALFORMED_TOOL_ARGS_KEYS = [
  '__kovoToolArgsParseError',
  '__kovo_tool_args_parse_error',
  '__kovoParseError',
  '__toolCallParseError',
  '__toolArgsParseError',
  '__jsonParseError',
  '__parseError',
  '__malformedToolArgs',
  '__malformedArgs',
  '__truncatedToolArgs',
  '_parseError',
] as const

export interface MalformedToolArgsDiagnostic {
  markerKey: string
  reason: string
  truncated: boolean
  rawLength?: number
}

export function detectMalformedToolCallArgs(args: unknown): MalformedToolArgsDiagnostic | null {
  if (!args || typeof args !== 'object' || Array.isArray(args)) return null
  const record = args as Record<string, unknown>
  for (const key of MALFORMED_TOOL_ARGS_KEYS) {
    if (!(key in record)) continue
    const raw = record[key]
    if (raw === false || raw === null || raw === undefined) continue
    if (typeof raw === 'string') {
      const reason = raw.trim() || 'Malformed or truncated tool-call JSON.'
      return {
        markerKey: key,
        reason: reason.slice(0, 240),
        truncated: /truncat|unterminated|unexpected end|eof|max_tokens/i.test(reason) || key.toLowerCase().includes('truncat'),
        ...(typeof record.__rawLength === 'number' ? { rawLength: record.__rawLength } : {}),
      }
    }
    if (raw === true) {
      const extraReason = typeof record.__parseErrorMessage === 'string'
        ? record.__parseErrorMessage
        : typeof record.__error === 'string'
          ? record.__error
          : 'Malformed or truncated tool-call JSON.'
      return {
        markerKey: key,
        reason: extraReason.slice(0, 240),
        truncated: record.__truncated === true || /truncat|unterminated|unexpected end|eof|max_tokens/i.test(extraReason) || key.toLowerCase().includes('truncat'),
        ...(typeof record.__rawLength === 'number' ? { rawLength: record.__rawLength } : {}),
      }
    }
    if (typeof raw === 'object' && !Array.isArray(raw)) {
      const objVal = raw as Record<string, unknown>
      const reasonRaw = [objVal.message, objVal.error, objVal.reason, objVal.parseError]
        .find((v): v is string => typeof v === 'string' && v.trim().length > 0)
        ?? 'Malformed or truncated tool-call JSON.'
      const rawLength = typeof objVal.rawLength === 'number'
        ? objVal.rawLength
        : typeof objVal.length === 'number'
          ? objVal.length
          : undefined
      return {
        markerKey: key,
        reason: reasonRaw.trim().slice(0, 240),
        truncated: objVal.truncated === true || /truncat|unterminated|unexpected end|eof|max_tokens/i.test(reasonRaw),
        ...(rawLength !== undefined ? { rawLength } : {}),
      }
    }
  }
  return null
}

export function formatMalformedToolArgsError(toolName: string, diag: MalformedToolArgsDiagnostic): string {
  const lenSuffix = diag.rawLength !== undefined ? ` (${diag.rawLength} chars)` : ''
  const kind = diag.truncated ? 'truncated/malformed JSON' : 'malformed JSON'
  return `Tool ${toolName} call arguments were ${kind}${lenSuffix}: ${diag.reason} Keep the payload/script concise or split into smaller steps and retry with valid JSON.`
}

async function formatToolOutput(
  raw: unknown,
  toolName: string,
  scrub: (value: string) => string,
  inlineLimit: number,
  spillOutput: WorkerToolHandlers['spillOutput'],
  signal: AbortSignal,
  spillStore?: HostSpillStore,
): Promise<string> {
  const serialized = typeof raw === 'string' ? raw : JSON.stringify(raw ?? { ok: true }, null, 2)
  const safe = scrub(serialized)
  const byteLen = Buffer.byteLength(safe, 'utf8')
  if (byteLen <= inlineLimit) return safe

  let spilledPath: string | null = null
  let spillId: string | null = null
  if (spillOutput || spillStore) {
    spillId = `${toolName}-${randomUUID().slice(0, 8)}`
    const spillPayload = truncateUtf8Head(safe, maxSpillFileBytes)
    if (spillOutput) {
      try {
        spilledPath = await spillOutput(spillId, spillPayload, signal)
      } catch {
        spilledPath = null
      }
    }
    if (spillStore) {
      const effectivePath = spilledPath ?? `/evidence/tool-output/${spillId}.txt`
      spillStore.put(spillId, effectivePath, spillPayload)
      if (!spilledPath) spilledPath = effectivePath
    }
  }

  const notice = spilledPath && spillId
    ? `\n\n... [truncated ${byteLen} bytes; full redacted output spilled to ${spilledPath} (artifactId="${spillId}") — inspect in parallel with read_evidence_slice({ artifactId: "${spillId}", offset: 0, limit: 8192 }) or path="${spilledPath}"; use derive_evidence only for custom jq/pipelines] ...\n\n`
    : `\n\n... [truncated ${byteLen} bytes to ${inlineLimit}-byte inline cap] ...\n\n`
  const available = Math.max(256, inlineLimit - Buffer.byteLength(notice, 'utf8'))
  const headBytes = Math.floor(available * 0.55)
  const tailBytes = Math.max(0, available - headBytes)
  return truncateUtf8Head(safe, headBytes) + notice + (tailBytes > 0 ? truncateUtf8Tail(safe, tailBytes) : '')
}

// ---------------------------------------------------------------------------
// Spec submission & verifier repair feedback
// ---------------------------------------------------------------------------

export interface SpecSubmissionToolOptions {
  /** Shared ledger; when omitted, spec enforcement and settlement reservation stay inert. */
  tracker?: SpecSubmissionTracker
  /** Called once per rejected simple conclusion so the caller can emit `agent.spec_submission_required`. */
  onRequired?: (info: { status: string; count: number; route?: SpecRouteEvidence }) => void
  /** Live predicate reporting whether settlement is currently active (controls truthful gap-rejection wording). */
  isSettling?: () => boolean
  /** Optional callback receiving host-side `kovo_verify` tool-arg alias hits (`code`/`source`). */
  onVerifyAliasUsed?: (aliases: readonly KovoVerifyAliasKey[]) => void
  /** Explicitly opt in to registering legacy `verify_replay_spec` while `kovo_verify` is active (default false to prevent LLM DSL dilution). */
  allowLegacyReplaySpec?: boolean
  /** Staged read-only repositories root on host for fast parallel `read_repo_file` / `search_repo`. */
  reposDir?: string
  /** Optional host-side evidence/spill directory for fast parallel `read_evidence_slice`. */
  evidenceDir?: string
}

/** Read-only structural view of a broker/probe result (never a body): status + shape hash. */
interface ObservedRouteResult {
  status?: unknown
  bodySha256?: unknown
  verdict?: unknown
  anomalies?: unknown
  requestsSent?: unknown
  calibration?: unknown
  results?: unknown
}

function asObserved(value: unknown): ObservedRouteResult | undefined {
  return value && typeof value === 'object' && !Array.isArray(value) ? value as ObservedRouteResult : undefined
}

function observedStatus(value: unknown): number | null {
  const observed = asObserved(value)
  return typeof observed?.status === 'number' && Number.isFinite(observed.status) ? Math.trunc(observed.status) : null
}

function observedBodySha(value: unknown): string | null {
  const observed = asObserved(value)
  return typeof observed?.bodySha256 === 'string' && observed.bodySha256 ? observed.bodySha256 : null
}

/** A differential `signal` verdict or any non-empty anomaly list is an anomaly, never a clean route. */
function observedAnomaly(value: unknown): boolean {
  const observed = asObserved(value)
  if (!observed) return false
  if (Array.isArray(observed.anomalies) && observed.anomalies.length > 0) return true
  return observed.verdict === 'signal'
}

/** `no_signal` after a real control-vs-probe matrix (>=2 requests) refutes the class hypothesis. */
function observedRefutation(value: unknown): boolean {
  const observed = asObserved(value)
  if (!observed) return false
  const sent = typeof observed.requestsSent === 'number' ? observed.requestsSent : 0
  return observed.verdict === 'no_signal' && sent >= 2 && !observedAnomaly(value)
}

function observedStaticCatchAll(value: unknown): boolean {
  const observed = asObserved(value)
  if (!observed) return false
  const calibration = observed.calibration
  return Boolean(calibration && typeof calibration === 'object' && !Array.isArray(calibration) &&
    (calibration as { spaCatchall?: unknown }).spaCatchall === true)
}

/**
 * Classify a host-side broker denial. Only used to substantiate a `tier_blocked`/`out_of_scope`/
 * `runtime_unavailable` gap; the denial message itself is never persisted.
 */
function classifyBrokerDenial(error: unknown): GapDenialKind | null {
  const message = error instanceof Error ? error.message : String(error)
  if (/tier\s*[0-9]/i.test(message)) return 'tier'
  if (/outside (the )?(current )?(assignment )?scope|escaped the requested origin|originAllowlist/i.test(message)) return 'scope'
  if (/persona .*(not approved|not have|resolved|authenticated session)|authentication required/i.test(message)) return 'auth'
  if (/runtime|not mounted|no such container|ECONNREFUSED|ENOTFOUND/i.test(message)) return 'runtime'
  return null
}

export interface SessionScrubbers {
  /** Display/logging/LLM-context scrubber: exact live secrets + heuristic credential patterns. */
  scrubForDisplay: (value: string) => string
  /** Executable-argument scrubber (H-25): exact live known secrets ONLY (zero heuristic regexes). */
  scrubExact: (value: string) => string
}

/**
 * Builds live display vs exact-only secret scrubbers (H-8 / H-25).
 * Reads `secrets` on every invocation (never snapshotting at startup), so rotated session tokens
 * or dynamically registered secrets minted mid-run are immediately scrubbed before reaching the model.
 */
export function createSessionScrubbers(
  secrets?: SecretSource,
  staticSecrets: readonly NamedSecret[] = [],
): SessionScrubbers {
  const resolveLive = (): readonly NamedSecret[] => {
    const dynamic = typeof secrets === 'function' ? secrets() : (secrets ?? [])
    if (!dynamic.length) return staticSecrets
    if (!staticSecrets.length) return dynamic
    return [...dynamic, ...staticSecrets]
  }
  return {
    scrubForDisplay: (value: string) => redact(value, resolveLive()),
    scrubExact: (value: string) => redactSecrets(value, resolveLive()),
  }
}

export function buildWorkerTools(
  handlers: WorkerToolHandlers,
  scrub: ((value: string) => string) | SessionScrubbers,
  rootSignal: AbortSignal,
  inlineLimit: number,
  onCompleteIntent: (completion: IntentCompletion) => void,
  specSubmission?: SpecSubmissionToolOptions,
): ToolRegistration[] {
  const scrubForDisplay = typeof scrub === 'function' ? scrub : scrub.scrubForDisplay
  // H-25: Never run heuristic display scrubbing on executable code/command arguments.
  const scrubExact = typeof scrub === 'function' ? ((value: string) => value) : scrub.scrubExact
  const tools: ToolRegistration[] = []
  const outputLimits = { maxBytes: inlineLimit }
  const enableHostEvidenceTool = Boolean(
    handlers.read_evidence_slice || specSubmission?.evidenceDir || handlers.spillOutput || handlers.derive_evidence,
  )
  const hostSpillStore = enableHostEvidenceTool ? new HostSpillStore() : undefined

  const combineSignal = (ctxSignal?: AbortSignal) =>
    ctxSignal ? AbortSignal.any([rootSignal, ctxSignal]) : rootSignal

  const wrapExec = async (
    toolName: string,
    fn: () => Promise<unknown>,
    signal: AbortSignal,
    control?: { terminate?: boolean },
    /** Host-observed route ledger hook. Runs on the raw result, before any text rendering. */
    observe?: (result: unknown) => void,
    /** Host-side denial hook (tier/scope/auth/runtime) for a failed exchange, before scrubbing. */
    observeError?: (error: unknown) => void,
  ) => {
    try {
      const result = await fn()
      if (SPEC_SUBMISSION_TOOLS.has(toolName) && !ROUTE_BOUND_SPEC_TOOLS.has(toolName)) specSubmission?.tracker?.noteSpecAttempt()
      if (ROUTE_EVIDENCE_TOOLS.has(toolName)) specSubmission?.tracker?.noteProbe()
      try { observe?.(result) } catch { /* evidence bookkeeping must never break a probe */ }
      const text = await formatToolOutput(result, toolName, scrubForDisplay, inlineLimit, handlers.spillOutput, signal, hostSpillStore)
      return {
        output: [{ type: 'text' as const, text }],
        ...(control ? { control } : {}),
      }
    } catch (error) {
      if (rootSignal.aborted) throw error
      try { observeError?.(error) } catch { /* denial bookkeeping must never break the error path */ }
      const msg = scrubForDisplay(error instanceof Error ? error.message : String(error)).slice(0, 1600)
      return {
        isError: true,
        output: [{ type: 'text' as const, text: `Tool ${toolName} error: ${msg}` }],
      }
    }
  }

  if (handlers.request_http) {
    const fn = handlers.request_http
    const normalizeHttpArgs = (args: {
      origin: string
      method: HttpMethod
      pathAndQuery: string
      headers?: Record<string, string>
      persona?: string
      session?: string
      csrfBind?: CsrfBind
      authMutation?: Parameters<typeof normalizePiAuthMutation>[0]
      traceId?: string
      jsonBody?: unknown
      textBody?: string
      body?: unknown
      multipartParts?: BrokerMultipartPart[]
      followRedirects?: boolean
      rationale?: string
    }): RequestHttpArgs => {
      const { authMutation, body, ...rest } = args
      const bodyFields: Pick<RequestHttpArgs, 'textBody' | 'jsonBody'> = {}
      if (rest.textBody === undefined && rest.jsonBody === undefined && body !== undefined) {
        if (typeof body === 'string') bodyFields.textBody = body
        else bodyFields.jsonBody = body
      }
      return {
        ...rest,
        ...bodyFields,
        ...(authMutation ? { authMutation: normalizePiAuthMutation(authMutation) } : {}),
      }
    }
    tools.push(defineTool({
      name: 'request_http',
      description: 'Send a scoped HTTP request through Kovo Hunter’s RequestBroker. Responses are redacted and auto-staged into /evidence/exchanges/<id>.json.',
      parameters: httpRequestSchema,
      replay: 'unsafe',
      outputLimits,
      execute: (args, _api, ctx) => {
        const signal = combineSignal(ctx.abortSignal)
        return wrapExec('request_http', () => fn(normalizeHttpArgs(args), signal).then(result => {
          specSubmission?.tracker?.noteRoute({
            method: args.method,
            pathAndQuery: args.pathAndQuery,
            ...(args.origin ? { origin: args.origin } : {}),
          })
          return result
        }), signal, undefined, result => specSubmission?.tracker?.noteObservation({
          method: args.method,
          pathAndQuery: args.pathAndQuery,
          ...(args.origin ? { origin: args.origin } : {}),
          ...(args.persona ? { persona: args.persona } : {}),
          status: observedStatus(result),
          bodySha256: observedBodySha(result),
          anomaly: observedAnomaly(result),
        }), error => {
          const kind = classifyBrokerDenial(error)
          if (kind) specSubmission?.tracker?.noteDenial({ method: args.method, pathAndQuery: args.pathAndQuery, ...(args.origin ? { origin: args.origin } : {}), kind })
        })
      },
    }))
  }

  if (handlers.request_http_batch) {
    const fn = handlers.request_http_batch
    tools.push(defineTool({
      name: 'request_http_batch',
      description: 'Send a bounded synchronized parallel burst of 2–10 scoped HTTP requests (Tier 2/3 only) for race condition / rate-limit verification.',
      parameters: obj({
        requests: arr(httpRequestSchema, { minItems: 2, maxItems: 10 }),
        rationale: opt(str({ maxLength: 500 })),
      }),
      replay: 'unsafe',
      outputLimits,
      execute: (args, _api, ctx) => {
        const signal = combineSignal(ctx.abortSignal)
        const normalized = {
          ...args,
          requests: args.requests.map((r): RequestHttpArgs => {
            const { authMutation, ...rest } = r
            return {
              ...rest,
              ...(authMutation ? { authMutation: normalizePiAuthMutation(authMutation) } : {}),
            }
          }),
        }
        return wrapExec('request_http_batch', () => fn(normalized, signal), signal, undefined, result => {
          const observed = asObserved(result)
          const rows = Array.isArray(observed?.results) ? observed.results : []
          normalized.requests.forEach((request, index) => {
            specSubmission?.tracker?.noteObservation({
              method: request.method,
              pathAndQuery: request.pathAndQuery,
              ...(request.origin ? { origin: request.origin } : {}),
              ...(request.persona ? { persona: request.persona } : {}),
              status: observedStatus(rows[index]),
              bodySha256: observedBodySha(rows[index]),
              anomaly: false,
            })
          })
        })
      },
    }))
  }

  const raceHandler = handlers.requestHttpRace ?? handlers.request_http_race
  if (raceHandler) {
    tools.push(defineTool({
      name: 'request_http_race',
      description: 'Execute a synchronized parallel race-condition burst of 2–10 scoped HTTP requests (Tier 2/3 only) via RequestBroker.executeRaceBurst. Pre-validates and resolves DNS before firing concurrently; returns per-request exchange results and timing/status/distinct-body summary for TOCTOU & idempotency verification.',
      parameters: obj({
        requests: arr(httpRequestSchema, { minItems: 2, maxItems: 10 }),
        rationale: opt(str({ description: 'Concise defensive rationale for the race/TOCTOU test.', maxLength: 500 })),
      }),
      replay: 'unsafe',
      outputLimits,
      execute: (args, _api, ctx) => {
        const signal = combineSignal(ctx.abortSignal)
        const normalized = {
          ...args,
          requests: args.requests.map((r): RequestHttpArgs => {
            const { authMutation, ...rest } = r
            return {
              ...rest,
              ...(authMutation ? { authMutation: normalizePiAuthMutation(authMutation) } : {}),
            }
          }),
        }
        return wrapExec('request_http_race', () => raceHandler(normalized, signal), signal)
      },
    }))
  }

  if (handlers.inspect_dns) {
    const fn = handlers.inspect_dns
    tools.push(defineTool({
      name: 'inspect_dns',
      description: 'Inspect live DNS records (A, AAAA, CNAME, TXT, NS) and dangling-CNAME subdomain takeover hints for an approved origin.',
      parameters: obj({ origin: str({ maxLength: 256 }) }),
      replay: 'safe',
      outputLimits,
      execute: async (args, _api, ctx) => {
        const signal = combineSignal(ctx.abortSignal)
        return wrapExec('inspect_dns', () => fn(args, signal), signal)
      },
    }))
  }

  if (handlers.inspect_tls) {
    const fn = handlers.inspect_tls
    tools.push(defineTool({
      name: 'inspect_tls',
      description: 'Perform a direct-IP TLS handshake on an approved origin to inspect TLS version, cipher, certificate validity, issuer, and SANs.',
      parameters: obj({ origin: str({ maxLength: 256 }) }),
      replay: 'safe',
      outputLimits,
      execute: async (args, _api, ctx) => {
        const signal = combineSignal(ctx.abortSignal)
        return wrapExec('inspect_tls', () => fn(args, signal), signal)
      },
    }))
  }

  if (handlers.browser_visit) {
    const fn = handlers.browser_visit
    tools.push(defineTool({
      name: 'browser_visit',
      description: 'Load an approved URL in Kovo Hunter’s 100% broker-proxied Playwright browser (zero direct egress) and optionally execute safe interactive actions (fill, click, select_option, wait_for_selector, wait_for_xhr, evaluate_builtin, dom_xss_sink_hook). Captures rendered DOM, live XHR/fetch URLs, DOM sink taint traces, console logs, postMessage listeners, and safe storage keys.',
      parameters: obj({
        origin: str({ maxLength: 256 }),
        pathAndQuery: str({ maxLength: 4096 }),
        persona: opt(str({ maxLength: 64 })),
        session: opt(str({ pattern: '^[a-z0-9_-]{1,32}$', maxLength: 32 })),
        waitForSelector: opt(str({ maxLength: 200 })),
        domCheck: opt(oneOf(['none', 'dom_xss', 'postmessage', 'client_storage', 'xhr_leak'] as const)),
        actions: opt(arr(browserInteractiveActionSchema, { maxItems: 20, description: 'Ordered safe interactive actions (100% routed through RequestBroker).' })),
        enableSinkHook: opt(bool({ description: 'Inject read-only DOM XSS sink hook wrapping innerHTML/document.write/eval/Function/location.href/postMessage.' })),
        waitAfterLoadMs: opt(int({ minimum: 0, maximum: 5000 })),
      }),
      replay: 'safe',
      outputLimits,
      execute: async (args, _api, ctx) => {
        const signal = combineSignal(ctx.abortSignal)
        const normalizedActions: BrowserInteractiveAction[] | undefined = args.actions?.map(a => {
          switch (a.type) {
            case 'fill':
              return { type: 'fill', selector: a.selector ?? '', value: a.value ?? '' }
            case 'click':
              return { type: 'click', selector: a.selector ?? '' }
            case 'select_option':
              return { type: 'select_option', selector: a.selector ?? '', value: a.value ?? '' }
            case 'wait_for_selector':
              return { type: 'wait_for_selector', selector: a.selector ?? '', ...(a.timeoutMs !== undefined ? { timeoutMs: a.timeoutMs } : {}) }
            case 'wait_for_xhr':
              return { type: 'wait_for_xhr', ...(a.urlPattern ? { urlPattern: a.urlPattern } : {}), ...(a.timeoutMs !== undefined ? { timeoutMs: a.timeoutMs } : {}) }
            case 'evaluate_builtin':
              return { type: 'evaluate_builtin', builtinCheck: a.builtinCheck ?? 'page_metadata' }
            case 'dom_xss_sink_hook':
              return { type: 'dom_xss_sink_hook' }
          }
        })
        return wrapExec('browser_visit', () => fn({ ...args, actions: normalizedActions }, signal), signal)
      },
    }))
  }

  if (handlers.browser_session) {
    const fn = handlers.browser_session
    const browserSessionStepSchema = obj({
      id: str({ pattern: '^[a-z0-9_-]{1,32}$', maxLength: 32 }),
      role: oneOf(['setup', 'control', 'probe', 'cleanup'] as const),
      origin: str({ maxLength: 256 }),
      pathAndQuery: opt(str({ maxLength: 4096 })),
      persona: opt(str({ maxLength: 64 })),
      session: opt(str({ pattern: '^[a-z0-9_-]{1,32}$', maxLength: 32 })),
      action: opt(oneOf(['navigate', 'fill', 'click', 'select_option', 'wait_for_selector', 'wait_for_xhr', 'evaluate_builtin', 'dom_xss_sink_hook'] as const)),
      selector: opt(str({ maxLength: 256 })),
      value: opt(str({ maxLength: 4096 })),
      builtinCheck: opt(oneOf(['dom_sinks', 'forms_inventory', 'storage_keys', 'postmessage_audit', 'canary_presence', 'page_metadata'] as const)),
      urlPattern: opt(str({ maxLength: 256 })),
      actions: opt(arr(browserInteractiveActionSchema, { maxItems: 20 })),
      enableSinkHook: opt(bool()),
      reusePage: opt(bool()),
      resetContext: opt(bool()),
      waitAfterLoadMs: opt(int({ minimum: 0, maximum: 5000 })),
    })
    tools.push(defineTool({
      name: 'browser_session',
      description: 'Execute a multi-step stateful browser session in Kovo Hunter’s 100%-brokered Playwright browser, preserving DOM, cookies, and localStorage across contiguous steps of the same role/persona and isolating control vs probe groups automatically.',
      parameters: obj({
        steps: arr(browserSessionStepSchema, { minItems: 1, maxItems: 16 }),
      }),
      replay: 'safe',
      outputLimits,
      execute: async (args, _api, ctx) => {
        const signal = combineSignal(ctx.abortSignal)
        const normalizedSteps: BrowserSessionStep[] = args.steps.map(s => ({
          id: s.id,
          role: s.role,
          origin: s.origin,
          ...(s.pathAndQuery !== undefined ? { pathAndQuery: s.pathAndQuery } : {}),
          ...(s.persona !== undefined ? { persona: s.persona } : {}),
          ...(s.session !== undefined ? { session: s.session } : {}),
          ...(s.action !== undefined ? { action: s.action } : {}),
          ...(s.selector !== undefined ? { selector: s.selector } : {}),
          ...(s.value !== undefined ? { value: s.value } : {}),
          ...(s.builtinCheck !== undefined ? { builtinCheck: s.builtinCheck } : {}),
          ...(s.urlPattern !== undefined ? { urlPattern: s.urlPattern } : {}),
          ...(s.actions ? {
            actions: s.actions.map(a => {
              switch (a.type) {
                case 'fill': return { type: 'fill' as const, selector: a.selector ?? '', value: a.value ?? '' }
                case 'click': return { type: 'click' as const, selector: a.selector ?? '' }
                case 'select_option': return { type: 'select_option' as const, selector: a.selector ?? '', value: a.value ?? '' }
                case 'wait_for_selector': return { type: 'wait_for_selector' as const, selector: a.selector ?? '', ...(a.timeoutMs !== undefined ? { timeoutMs: a.timeoutMs } : {}) }
                case 'wait_for_xhr': return { type: 'wait_for_xhr' as const, ...(a.urlPattern ? { urlPattern: a.urlPattern } : {}), ...(a.timeoutMs !== undefined ? { timeoutMs: a.timeoutMs } : {}) }
                case 'evaluate_builtin': return { type: 'evaluate_builtin' as const, builtinCheck: a.builtinCheck ?? 'page_metadata' }
                case 'dom_xss_sink_hook': return { type: 'dom_xss_sink_hook' as const }
              }
            }),
          } : {}),
          ...(s.enableSinkHook !== undefined ? { enableSinkHook: s.enableSinkHook } : {}),
          ...(s.reusePage !== undefined ? { reusePage: s.reusePage } : {}),
          ...(s.resetContext !== undefined ? { resetContext: s.resetContext } : {}),
          ...(s.waitAfterLoadMs !== undefined ? { waitAfterLoadMs: s.waitAfterLoadMs } : {}),
        }))
        return wrapExec('browser_session', () => fn({ steps: normalizedSteps }, signal), signal)
      },
    }))
  }

  if (handlers.crawl_state_graph) {
    const fn = handlers.crawl_state_graph
    tools.push(defineTool({
      name: 'crawl_state_graph',
      description: 'Run a bounded multi-persona SPA state-graph crawl through Kovo Hunter’s 100%-brokered ScopedBrowser, discovering routes, HTML forms/CSRF fields, XHR/fetch/GraphQL/Next-Action endpoints, postMessage listeners, and storage key names into SQLite.',
      parameters: obj({
        origin: str({ description: 'Approved origin to crawl.', maxLength: 256 }),
        personas: opt(arr(str({ maxLength: 64 }), { maxItems: 6, description: 'Optional approved persona handles to crawl alongside anonymous.' })),
        maxPages: opt(int({ minimum: 1, maximum: 60, description: 'Max pages to visit (default 25, ceiling 60).' })),
        maxDepth: opt(int({ minimum: 0, maximum: 4, description: 'Max BFS link depth (default 3, ceiling 4).' })),
      }),
      replay: 'safe',
      outputLimits,
      execute: async (args, _api, ctx) => {
        const signal = combineSignal(ctx.abortSignal)
        return wrapExec('crawl_state_graph', () => fn(args, signal), signal)
      },
    }))
  }

  if (handlers.run_sast_scan) {
    const fn = handlers.run_sast_scan
    tools.push(defineTool({
      name: 'run_sast_scan',
      description: 'Run pinned offline SAST/AST/secret/SCA engines (opengrep, ast-grep, gitleaks, trufflehog, trivy-fs, bandit) over read-only /repos/<repo> inside the --network none worker container. Matched secrets are automatically masked; full JSON spills to /evidence/sast/<id>.json.',
      parameters: obj({
        repo: str({ description: 'Mounted repository identifier under /repos (e.g. owner/repo or repo-name).', maxLength: 200 }),
        engines: arr(oneOf(sastEngineNames), { minItems: 1, maxItems: 6, description: 'Offline SAST engines to run.' }),
        paths: opt(arr(str({ maxLength: 256 }), { maxItems: 32, description: 'Optional repo-relative subpaths to scope the scan.' })),
        ruleFilter: opt(str({ description: 'Optional rule ID / category substring filter.', maxLength: 160 })),
        timeoutMs: opt(int({ minimum: 5000, maximum: 180000 })),
      }),
      replay: 'safe',
      outputLimits,
      execute: async (args, _api, ctx) => {
        const signal = combineSignal(ctx.abortSignal)
        return wrapExec('run_sast_scan', () => fn(args, signal), signal)
      },
    }))
  }

  if (handlers.run_offline_script) {
    const fn = handlers.run_offline_script
    tools.push(defineTool({
      name: 'run_offline_script',
      description: 'Execute a bounded offline Python 3 or Node.js script inside the air-gapped --network none worker container over read-only /repos/* and /evidence/* (for JWT/crypto auditing, AST/schema parsing, response diffing, or encoding analysis). Zero network sockets; stdout/stderr secret-masked.',
      parameters: obj({
        runtime: oneOf(['python', 'node'] as const),
        code: str({ description: 'Offline Python or Node.js script source (<= 64 KiB).', maxLength: 65536 }),
        timeoutMs: opt(int({ minimum: 1000, maximum: 60000, description: 'Timeout in ms (default 30000, max 60000).' })),
      }),
      replay: 'safe',
      outputLimits,
      execute: async (args, _api, ctx) => {
        const signal = combineSignal(ctx.abortSignal)
        return wrapExec('run_offline_script', () => fn({ ...args, code: scrubExact(args.code) }, signal), signal)
      },
    }))
  }

  if (handlers.probe_surface) {
    const fn = handlers.probe_surface
    tools.push(defineTool({
      name: 'probe_surface',
      description: 'Host-side brokered path, parameter, or HTTP-method discovery with automatic 2-probe SPA-catchall calibration. Routes 100% through RequestBroker (RPS caps, 5xx/429 circuit breaker, scope enforcement) and returns only statistically distinct anomalies.',
      parameters: obj({
        origin: str({ description: 'Approved origin.', maxLength: 256 }),
        mode: oneOf(['paths', 'params', 'methods'] as const),
        wordlist: opt(oneOf(surfaceWordlistNames)),
        wordlists: opt(arr(oneOf(surfaceWordlistNames), { maxItems: 7 })),
        candidates: opt(arr(str({ maxLength: 256 }), { maxItems: 200, description: 'Optional worker-supplied paths (<=120) or param names (<=200).' })),
        basePath: opt(str({ description: 'Target endpoint path for mode="params" or mode="methods" (e.g. /api/items).', maxLength: 512 })),
        paramLocation: opt(oneOf(probeParamLocations)),
        methods: opt(arr(oneOf(httpMethods), { maxItems: 7 })),
        persona: opt(str({ maxLength: 64 })),
        maxRequests: opt(int({ minimum: 1, maximum: 300, description: 'Max requests for this call (default 150, ceiling 300).' })),
      }),
      replay: 'unsafe',
      outputLimits,
      execute: (args, _api, ctx) => {
        const signal = combineSignal(ctx.abortSignal)
        return wrapExec('probe_surface', () => fn(args, signal), signal, undefined, result => {
          const target = args.basePath ?? (args.mode === 'paths' ? args.candidates?.[0] : undefined)
          if (!target) return
          const observed = asObserved(result)
          const anomalies = Array.isArray(observed?.anomalies) ? observed.anomalies.length : 0
          specSubmission?.tracker?.noteObservation({
            method: 'GET',
            pathAndQuery: target,
            ...(args.origin ? { origin: args.origin } : {}),
            ...(args.persona ? { persona: args.persona } : {}),
            status: null,
            anomaly: anomalies > 0,
            staticCatchAll: observedStaticCatchAll(result),
          })
        })
      },
    }))
  }

  if (handlers.probe_differential) {
    const fn = handlers.probe_differential
    tools.push(defineTool({
      name: 'probe_differential',
      description: 'Host-side brokered control-vs-probe differential matrix across 7 encodings (query, json, form, path, header, xml, graphql_var) for strictly non-destructive detection: sqli_boolean, sqli_time_diff (local-lab/Tier-3 only), ssti_math, ssrf_canary (CanaryBroker HTTP/DNS only; never RFC1918/metadata), nosqli_type, path_traversal_benign, graphql_audit, authz_matrix, xss_context, auth_protocol_audit, xxe_canary, cache_poison_deception (auto ?_gcb=), or mass_assignment.',
      parameters: obj({
        origin: str({ description: 'Approved origin.', maxLength: 256 }),
        probeClass: oneOf(differentialProbeClasses),
        pathAndQuery: str({ description: 'Target path and optional query (use {{id}} placeholder for authz_matrix).', maxLength: 4096 }),
        method: opt(oneOf(['GET', 'POST', 'PUT', 'PATCH'] as const)),
        paramName: opt(str({ description: 'Parameter name under test (or dot-path for JSON body).', maxLength: 128 })),
        paramLocation: opt(oneOf(probeParamLocations)),
        baselineValue: opt(str({ maxLength: 256 })),
        persona: opt(str({ description: 'Primary/owner persona handle.', maxLength: 64 })),
        otherPersona: opt(str({ description: 'Second persona handle for cross-tenant authz_matrix testing.', maxLength: 64 })),
        session: opt(str({ description: 'Opaque ephemeral session jar handle.', pattern: '^[a-z0-9_-]{1,32}$', maxLength: 32 })),
        csrfBind: opt(csrfBindPiSchema),
        delayMs: opt(int({ minimum: 1500, maximum: 3000, description: 'Bounded sleep delay (1500..3000ms) for sqli_time_diff.' })),
        dialect: opt(oneOf(['mysql', 'postgres', 'mssql', 'sqlite'] as const)),
        candidateFields: opt(arr(str({ maxLength: 64 }), { maxItems: 24, description: 'Candidate privileged fields for mass_assignment.' })),
        xmlTemplate: opt(str({ maxLength: 8192 })),
        graphqlQuery: opt(str({ maxLength: 8192 })),
        resourceIds: opt(arr(str({ maxLength: 128 }), { maxItems: 10, description: 'Resource IDs for authz_matrix.' })),
        body: opt(map(unknown(), { description: 'Optional JSON body template for POST differentials.' })),
        headers: opt(map(str({ maxLength: 1024 }), { description: 'Optional safe headers (no Authorization/Cookie).' })),
        ssrfParams: opt(arr(str({ maxLength: 64 }), { maxItems: 16, description: 'Candidate URL/webhook/redirect parameter names for ssrf_canary.' })),
        maxRequests: opt(int({ minimum: 1, maximum: 150 })),
      }),
      replay: 'unsafe',
      outputLimits,
      execute: (args, _api, ctx) => {
        const signal = combineSignal(ctx.abortSignal)
        return wrapExec('probe_differential', () => fn(args, signal), signal, undefined, result => specSubmission?.tracker?.noteObservation({
          method: args.method ?? 'GET',
          pathAndQuery: args.pathAndQuery,
          ...(args.origin ? { origin: args.origin } : {}),
          ...(args.persona ? { persona: args.persona } : {}),
          status: null,
          anomaly: observedAnomaly(result),
          refuted: observedRefutation(result),
          // A differential matrix always runs a control arm alongside the probe arm.
          control: true,
          differential: true,
        }), error => {
          const kind = classifyBrokerDenial(error)
          if (kind) specSubmission?.tracker?.noteDenial({ method: args.method ?? 'GET', pathAndQuery: args.pathAndQuery, ...(args.origin ? { origin: args.origin } : {}), kind })
        })
      },
    }))
  }

  if (handlers.run_safe_templates) {
    const fn = handlers.run_safe_templates
    tools.push(defineTool({
      name: 'run_safe_templates',
      description: 'Run Kovo Hunter’s vetted, non-destructive YAML template pack filtered by techTags or templateIds, executed 100% through RequestBroker with SPA-catchall exclusion. Matches produce candidate leads/hypotheses (still require Zero-LLM Replay Verification).',
      parameters: obj({
        origin: str({ description: 'Approved origin.', maxLength: 256 }),
        techTags: opt(arr(str({ maxLength: 64 }), { maxItems: 24, description: 'Fingerprinted tech tags (e.g. nextjs, django, fastapi, springboot, graphql, clerk, supabase).' })),
        templateIds: opt(arr(str({ maxLength: 128 }), { maxItems: 60, description: 'Optional explicit vetted template IDs to run.' })),
        persona: opt(str({ maxLength: 64 })),
        maxTemplates: opt(int({ minimum: 1, maximum: 250, description: 'Max templates to execute (default 60, ceiling 250).' })),
      }),
      replay: 'unsafe',
      outputLimits,
      execute: (args, _api, ctx) => {
        const signal = combineSignal(ctx.abortSignal)
        return wrapExec('run_safe_templates', () => fn(args, signal), signal)
      },
    }))
  }

  if (handlers.probe_websocket) {
    const fn = handlers.probe_websocket
    tools.push(defineTool({
      name: 'probe_websocket',
      description: 'Connect to an approved WebSocket endpoint through RequestBroker (scope check, public-IP/direct-IP TLS, persona injection, configurable spoofOrigin for CSWSH testing, max 10 frames / 64 KiB / 10s lifetime, full secret scrubbing).',
      parameters: obj({
        origin: str({ description: 'Approved origin.', maxLength: 256 }),
        pathAndQuery: str({ description: 'WebSocket endpoint path starting with /.', maxLength: 4096 }),
        persona: opt(str({ description: 'Optional approved persona handle for authenticated WS handshake.', maxLength: 64 })),
        spoofOrigin: opt(str({ description: 'Optional Origin header override (e.g. https://evil.invalid) for CSWSH control-vs-probe checks.', maxLength: 256 })),
        subprotocols: opt(arr(str({ maxLength: 64 }), { maxItems: 4 })),
        messages: opt(arr(str({ maxLength: 8192 }), { maxItems: 10, description: 'Optional benign text messages to send after handshake (max 10).' })),
        maxFrames: opt(int({ minimum: 1, maximum: 25 })),
        timeoutMs: opt(int({ minimum: 500, maximum: 20000 })),
      }),
      replay: 'unsafe',
      outputLimits,
      execute: (args, _api, ctx) => {
        const signal = combineSignal(ctx.abortSignal)
        return wrapExec('probe_websocket', () => fn(args, signal), signal)
      },
    }))
  }

  if (handlers.read_repo_file || specSubmission?.reposDir) {
    const customFn = handlers.read_repo_file
    const reposDir = specSubmission?.reposDir
    tools.push(defineTool({
      name: 'read_repo_file',
      description: 'Fast parallel host-executed read-only file reader over staged /repos/<owner>/<repo> (bounded numbered line slices up to 400 lines / 16 KiB; zero shell overhead). Prefer over derive_evidence for reading source files.',
      parameters: obj({
        path: str({ description: 'Repo file path (e.g. /repos/owner/repo/src/app.ts or owner/repo/src/app.ts).', minLength: 1, maxLength: 512 }),
        startLine: opt(int({ description: '1-based start line (default 1).', minimum: 1, maximum: 500000 })),
        endLine: opt(int({ description: '1-based inclusive end line (default startLine + 199; max 400 lines per call).', minimum: 1, maximum: 500000 })),
      }),
      replay: 'safe',
      outputLimits,
      execute: async (args, _api, ctx) => {
        const signal = combineSignal(ctx.abortSignal)
        return wrapExec(
          'read_repo_file',
          async () => customFn ? customFn(args, signal) : readRepoFileHost(reposDir!, args),
          signal,
        )
      },
    }))
  }

  if (handlers.search_repo || specSubmission?.reposDir) {
    const customFn = handlers.search_repo
    const reposDir = specSubmission?.reposDir
    tools.push(defineTool({
      name: 'search_repo',
      description: 'Fast parallel host-executed read-only code search over staged /repos (literal substring by default; optional ReDoS-safe regex; skips .git and node_modules; zero shell overhead). Prefer over derive_evidence for code search.',
      parameters: obj({
        query: str({ description: 'Search pattern (literal by default; set regex=true for ReDoS-safe bounded regex).', minLength: 1, maxLength: 256 }),
        pathPrefix: opt(str({ description: 'Optional repo or directory prefix (e.g. /repos/owner/repo/src).', maxLength: 512 })),
        maxMatches: opt(int({ description: 'Max matching lines to return (default 50, max 200).', minimum: 1, maximum: 200 })),
        regex: opt(bool({ description: 'Evaluate query as a ReDoS-safe regex (default false = fast literal match).' })),
        caseSensitive: opt(bool({ description: 'Case-sensitive match for literal mode (default false; regex mode is always case-sensitive to preserve V8 linear-time engine guarantees).' })),
      }),
      replay: 'safe',
      outputLimits,
      execute: async (args, _api, ctx) => {
        const signal = combineSignal(ctx.abortSignal)
        return wrapExec(
          'search_repo',
          async () => customFn ? customFn(args, signal) : HOST_REPO_SEARCH_RUNNERS.worker(reposDir!, args, { signal }),
          signal,
        )
      },
    }))
  }

  if (enableHostEvidenceTool) {
    const customFn = handlers.read_evidence_slice
    const evidenceDir = specSubmission?.evidenceDir
    tools.push(defineTool({
      name: 'read_evidence_slice',
      description: 'Fast parallel host-executed reader for spilled tool outputs and run evidence slices (by artifactId or /evidence/... path, with bounded offset/limit; zero shell overhead). Prefer over derive_evidence for paging spilled outputs.',
      parameters: obj({
        artifactId: opt(str({ description: 'Spilled tool-output artifactId from truncation notice (e.g. request_http-a1b2c3d4).', maxLength: 200 })),
        path: opt(str({ description: 'Evidence/spill path under /evidence (e.g. /evidence/tool-output/request_http-a1b2c3d4.txt).', maxLength: 512 })),
        offset: opt(int({ description: '0-based character offset to start reading (default 0).', minimum: 0, maximum: 10000000 })),
        limit: opt(int({ description: 'Max characters to return (default 8192, max 16384).', minimum: 1, maximum: 16384 })),
      }),
      replay: 'safe',
      outputLimits,
      execute: async (args, _api, ctx) => {
        const signal = combineSignal(ctx.abortSignal)
        return wrapExec(
          'read_evidence_slice',
          async () => customFn ? customFn(args, signal) : readEvidenceSliceHost({ spillStore: hostSpillStore, evidenceDir }, args),
          signal,
        )
      },
    }))
  }

  if (handlers.derive_evidence) {
    const fn = handlers.derive_evidence
    tools.push(defineTool({
      name: 'derive_evidence',
      description: 'Run an offline just-bash command (jq, diff, sed, awk, wc, base64, find, rg) inside the air-gapped --network none intent container over read-only /evidence/*, read-only /repos/<owner>/<repo>, and writable /work/*. Prefer read_repo_file / search_repo / read_evidence_slice for source reading, search, and spill paging; use derive_evidence for custom jq/pipeline transforms.',
      parameters: obj({
        command: str({ maxLength: 16384 }),
        outputs: opt(arr(str({ maxLength: 64 }), { maxItems: 16 })),
        timeoutMs: opt(int({ minimum: 1000, maximum: 120000 })),
      }),
      replay: 'safe',
      outputLimits,
      execute: async (args, _api, ctx) => {
        const signal = combineSignal(ctx.abortSignal)
        return wrapExec('derive_evidence', () => fn({ ...args, command: scrubExact(args.command) }, signal), signal)
      },
    }))
  }

  if (handlers.analyze_artifact) {
    const fn = handlers.analyze_artifact
    tools.push(defineTool({
      name: 'analyze_artifact',
      description: 'Run a built-in air-gapped analyzer inside the intent container: js-harvest, tech-fingerprint, jwt-inspect, graphql-parse, openapi-parse, diff-response, dns-takeover, or secret-scan.',
      parameters: obj({
        tool: oneOf(analyzerNames),
        file: opt(str({ description: 'Relative path inside /evidence/ (e.g. exchanges/<id>.json or tool-output/<id>.txt).', maxLength: 256 })),
        text: opt(str({ description: 'Inline text input when not reading a staged file.', maxLength: 65536 })),
        controlFile: opt(str({ description: 'Control staged file for diff-response.', maxLength: 256 })),
        probeFile: opt(str({ description: 'Probe staged file for diff-response.', maxLength: 256 })),
        url: opt(str({ maxLength: 512 })),
        headers: opt(map(str({ maxLength: 1024 }))),
        packageJson: opt(str({ maxLength: 65536 })),
        hostname: opt(str({ maxLength: 256 })),
        cnames: opt(arr(str({ maxLength: 256 }), { maxItems: 32 })),
        a: opt(arr(str({ maxLength: 64 }), { maxItems: 32 })),
        aaaa: opt(arr(str({ maxLength: 64 }), { maxItems: 32 })),
        status: opt(int({ minimum: 100, maximum: 599 })),
        nxdomain: opt(bool()),
      }),
      replay: 'safe',
      outputLimits,
      execute: async (args, _api, ctx) => {
        const signal = combineSignal(ctx.abortSignal)
        return wrapExec('analyze_artifact', () => fn(args, signal), signal)
      },
    }))
  }

  if (handlers.query_cves) {
    const fn = handlers.query_cves
    tools.push(defineTool({
      name: 'query_cves',
      description: 'Query OSV.dev and Kovo Hunter’s curated web CVE registry for a fingerprinted (ecosystem, package, version?). Returns advisories and safe verification hints; never confirms a finding on version alone.',
      parameters: obj({
        ecosystem: str({ description: 'Package ecosystem (e.g. npm, PyPI, Go, Debian, infra).', maxLength: 64 }),
        package: str({ description: 'Package or framework name (e.g. next, react, vite, express).', maxLength: 160 }),
        version: opt(str({ description: 'Optional detected semver version.', maxLength: 64 })),
      }),
      replay: 'safe',
      outputLimits,
      execute: async (args, _api, ctx) => {
        const signal = combineSignal(ctx.abortSignal)
        return wrapExec('query_cves', () => fn(args, signal), signal)
      },
    }))
  }

  if (handlers.load_skill) {
    const fn = handlers.load_skill
    tools.push(defineTool({
      name: 'load_skill',
      description: 'Load a curated defensive security playbook from src/skills/*.md (e.g. source-first-audit, bola-idor-race, cross-host-chaining, oob-ssrf-browser-chain, recon-modern-spa, api-rest-graphql, auth-oauth-oidc, cve-runtime-correlation, false-positive-elimination). Pass name="list" to list all available skills.',
      parameters: obj({ name: str({ maxLength: 64 }) }),
      replay: 'safe',
      outputLimits,
      execute: async (args, _api, ctx) => {
        const signal = combineSignal(ctx.abortSignal)
        return wrapExec('load_skill', () => fn(args, signal), signal)
      },
    }))
  }

  if (handlers.mint_canary) {
    const fn = handlers.mint_canary
    tools.push(defineTool({
      name: 'mint_canary',
      description: 'Mint a signed, single-use benign Kovo Hunter canary token/URL for blind reflection or OOB callback validation.',
      parameters: obj({ purpose: str({ maxLength: 200 }) }),
      replay: 'unsafe',
      outputLimits,
      execute: (args, _api, ctx) => {
        const signal = combineSignal(ctx.abortSignal)
        return wrapExec('mint_canary', () => fn(args, signal), signal)
      },
    }))
  }

  if (handlers.check_canary) {
    const fn = handlers.check_canary
    tools.push(defineTool({
      name: 'check_canary',
      description: 'Check whether a previously minted Kovo Hunter canary token has received a benign callback.',
      parameters: obj({ token: str({ maxLength: 128 }) }),
      replay: 'safe',
      outputLimits,
      execute: async (args, _api, ctx) => {
        const signal = combineSignal(ctx.abortSignal)
        return wrapExec('check_canary', () => fn(args, signal), signal)
      },
    }))
  }

  if (handlers.mint_second_order_canary) {
    const fn = handlers.mint_second_order_canary
    tools.push(defineTool({
      name: 'mint_second_order_canary',
      description: 'Mint and persist a unique gn2o_<8hex> second-order canary marker for passive cross-endpoint/cross-persona surfacing detection.',
      parameters: obj({
        injectedOrigin: str({ maxLength: 256 }),
        injectedEndpoint: str({ maxLength: 512 }),
        injectedParam: str({ maxLength: 128 }),
        injectedPersona: opt(str({ maxLength: 64 })),
      }),
      replay: 'unsafe',
      outputLimits,
      execute: (args, _api, ctx) => {
        const signal = combineSignal(ctx.abortSignal)
        return wrapExec('mint_second_order_canary', () => fn(args, signal), signal)
      },
    }))
  }

  if (handlers.list_second_order_canaries) {
    const fn = handlers.list_second_order_canaries
    tools.push(defineTool({
      name: 'list_second_order_canaries',
      description: 'List planted or surfaced second-order canary markers (gn2o_<hex>) in the current run.',
      parameters: obj({
        status: opt(oneOf(['planted', 'surfaced', 'verified'] as const)),
      }),
      replay: 'safe',
      outputLimits,
      execute: async (args, _api, ctx) => {
        const signal = combineSignal(ctx.abortSignal)
        return wrapExec('list_second_order_canaries', () => fn(args, signal), signal)
      },
    }))
  }

  if (handlers.search_exchanges) {
    const fn = handlers.search_exchanges
    tools.push(defineTool({
      name: 'search_exchanges',
      description: 'Full-text search over redacted broker HTTP exchanges in this run (strictly filtered to currently approved origins).',
      parameters: obj({
        query: str({ maxLength: 300 }),
        origin: opt(str({ maxLength: 256 })),
        status: opt(int({ minimum: 100, maximum: 599 })),
        limit: opt(int({ minimum: 1, maximum: 50 })),
      }),
      replay: 'safe',
      outputLimits,
      execute: async (args, _api, ctx) => {
        const signal = combineSignal(ctx.abortSignal)
        return wrapExec('search_exchanges', () => fn(args, signal), signal)
      },
    }))
  }

  if (handlers.get_exchange) {
    const fn = handlers.get_exchange
    tools.push(defineTool({
      name: 'get_exchange',
      description: 'Retrieve a specific redacted broker HTTP exchange by ID (and optionally stage/read its full body).',
      parameters: obj({
        exchangeId: str({ maxLength: 64 }),
        includeBody: opt(bool()),
      }),
      replay: 'safe',
      outputLimits,
      execute: async (args, _api, ctx) => {
        const signal = combineSignal(ctx.abortSignal)
        return wrapExec('get_exchange', () => fn(args, signal), signal)
      },
    }))
  }

  if (handlers.search_facts) {
    const fn = handlers.search_facts
    tools.push(defineTool({
      name: 'search_facts',
      description: 'Search structured, non-tainted facts discovered across all workers in this run.',
      parameters: obj({
        query: opt(str({ maxLength: 300 })),
        origin: opt(str({ maxLength: 256 })),
        kind: opt(oneOf(factKinds)),
        limit: opt(int({ minimum: 1, maximum: 100 })),
      }),
      replay: 'safe',
      outputLimits,
      execute: async (args, _api, ctx) => {
        const signal = combineSignal(ctx.abortSignal)
        return wrapExec('search_facts', () => fn(args, signal), signal)
      },
    }))
  }

  if (handlers.read_peer_trace) {
    const fn = handlers.read_peer_trace
    tools.push(defineTool({
      name: 'read_peer_trace',
      description: 'Inspect recent completed or active peer worker assignments, outcomes, and recorded facts to coordinate multi-step chains.',
      parameters: obj({
        assignmentId: opt(str({ maxLength: 64 })),
        limit: opt(int({ minimum: 1, maximum: 50 })),
      }),
      replay: 'safe',
      outputLimits,
      execute: async (args, _api, ctx) => {
        const signal = combineSignal(ctx.abortSignal)
        return wrapExec('read_peer_trace', () => fn(args, signal), signal)
      },
    }))
  }

  if (handlers.expand_digest) {
    const fn = handlers.expand_digest
    tools.push(defineTool({
      name: 'expand_digest',
      description: 'Expand a cold-compacted graph_digests summary node to inspect its underlying non-tainted facts.',
      parameters: obj({ digestId: str({ maxLength: 64 }) }),
      replay: 'safe',
      outputLimits,
      execute: async (args, _api, ctx) => {
        const signal = combineSignal(ctx.abortSignal)
        return wrapExec('expand_digest', () => fn(args, signal), signal)
      },
    }))
  }

  if (handlers.query_endpoints) {
    const fn = handlers.query_endpoints
    tools.push(defineTool({
      name: 'query_endpoints',
      description: 'Page the untruncated endpoint store (stable v1 cursor, max 500/page). Filter by coverage, untested non-floor semantic classes (`untestedSemanticOnly`), sinks, missing auth guard, role-exclusive paths, or path prefix.',
      parameters: obj({
        cursor: opt(str({ maxLength: 32 })),
        limit: opt(int({ minimum: 1, maximum: 500 })),
        uncoveredOnly: opt(bool()),
        untestedSemanticOnly: opt(bool()),
        hasSink: opt(bool()),
        missingAuthGuard: opt(bool()),
        roleExclusive: opt(bool()),
        pathPrefix: opt(str({ maxLength: 512 })),
      }),
      replay: 'safe',
      outputLimits,
      execute: async (args, _api, ctx) => {
        const signal = combineSignal(ctx.abortSignal)
        return wrapExec('query_endpoints', () => fn(args, signal), signal)
      },
    }))
  }

  if (handlers.query_program_graph) {
    const fn = handlers.query_program_graph
    tools.push(defineTool({
      name: 'query_program_graph',
      description: 'Query the code-to-runtime Program Graph: source-to-sink paths, missing guard families (middleware diff), or security-relevant commit hotspots. No HTTP.',
      parameters: obj({
        kind: oneOf(['sinks', 'middleware_diff', 'git_hotspots'] as const),
        routeOrFile: opt(str({ maxLength: 512 })),
        limit: opt(int({ minimum: 1, maximum: 500 })),
      }),
      replay: 'safe',
      outputLimits,
      execute: async (args, _api, ctx) => {
        const signal = combineSignal(ctx.abortSignal)
        return wrapExec('query_program_graph', () => fn(args, signal), signal)
      },
    }))
  }

  if (handlers.query_facts) {
    const fn = handlers.query_facts
    tools.push(defineTool({
      name: 'query_facts',
      description: 'Page every untainted fact in the run (stable v1 cursor, max 500/page) so early low-severity primitives remain retrievable for late-round chains.',
      parameters: obj({
        cursor: opt(str({ maxLength: 32 })),
        limit: opt(int({ minimum: 1, maximum: 500 })),
        kind: opt(str({ maxLength: 64 })),
        origin: opt(str({ maxLength: 256 })),
        persona: opt(str({ maxLength: 64 })),
        sinceRound: opt(int({ minimum: 0 })),
        search: opt(str({ maxLength: 300 })),
      }),
      replay: 'safe',
      outputLimits,
      execute: async (args, _api, ctx) => {
        const signal = combineSignal(ctx.abortSignal)
        return wrapExec('query_facts', () => fn(args, signal), signal)
      },
    }))
  }

  if (handlers.query_findings) {
    const fn = handlers.query_findings
    tools.push(defineTool({
      name: 'query_findings',
      description: 'Query confirmed findings, findings parked on a durable pending_OOB subscription, or unproven deterministic leads.',
      parameters: obj({
        status: oneOf(['confirmed', 'pending_oob', 'det_lead'] as const),
        limit: opt(int({ minimum: 1, maximum: 500 })),
      }),
      replay: 'safe',
      outputLimits,
      execute: async (args, _api, ctx) => {
        const signal = combineSignal(ctx.abortSignal)
        return wrapExec('query_findings', () => fn(args, signal), signal)
      },
    }))
  }

  if (handlers.dispatch_investigations) {
    const fn = handlers.dispatch_investigations
    tools.push(defineTool({
      name: 'dispatch_investigations',
      description: 'Validate hypotheses (origins in approved scope, parent evidence ids, capability bundles) into a committed dispatch plan. Dispatch never performs HTTP itself.',
      parameters: obj({
        steps: arr(obj({
          hypothesis: str({ maxLength: 1200 }),
          origin: opt(str({ maxLength: 256 })),
          origins: opt(arr(str({ maxLength: 256 }), { maxItems: 8 })),
          capabilities: opt(arr(str({ maxLength: 32 }), { maxItems: 6 })),
          parentEvidenceIds: opt(arr(str({ maxLength: 64 }), { maxItems: 24 })),
          budgetUsd: opt(num({ minimum: 0 })),
          probeClass: opt(str({ maxLength: 64 })),
          expectedSignal: opt(str({ maxLength: 300 })),
          skills: opt(arr(str({ maxLength: 64 }), { maxItems: 12 })),
          priority: opt(int({ minimum: 0, maximum: 100 })),
        }), { maxItems: 24 }),
        maxSteps: opt(int({ minimum: 1, maximum: 50 })),
      }),
      replay: 'safe',
      outputLimits,
      execute: async (args, _api, ctx) => {
        const signal = combineSignal(ctx.abortSignal)
        return wrapExec('dispatch_investigations', () => fn(args, signal), signal)
      },
    }))
  }

  if (handlers.record_fact) {
    const fn = handlers.record_fact
    tools.push(defineTool({
      name: 'record_fact',
      description: 'Persist a typed discovery linked to exchangeIds/evidenceIds so peers and the Coordinator Planner can build chains.',
      parameters: obj({
        kind: oneOf(factKinds),
        origin: str({ maxLength: 256 }),
        summary: str({ maxLength: 600 }),
        data: opt(map(unknown(), { description: 'Structured JSON details (paths, headers, versions, CVE IDs, params).' })),
        exchangeIds: opt(arr(str({ maxLength: 64 }), { maxItems: 32 })),
        evidenceIds: opt(arr(str({ maxLength: 64 }), { maxItems: 32 })),
        sourceOrigins: opt(arr(str({ maxLength: 256 }), { maxItems: 32 })),
      }),
      replay: 'safe',
      outputLimits,
      execute: async (args, _api, ctx) => {
        const signal = combineSignal(ctx.abortSignal)
        return wrapExec('record_fact', () => fn(args, signal), signal)
      },
    }))
  }

  if (handlers.record_coverage) {
    const fn = handlers.record_coverage
    tools.push(defineTool({
      name: 'record_coverage',
      description: [
        'Update the per-origin OWASP/API Top 10 3-state closure coverage ledger.',
        'Strict 3-State Closure Discipline (SPEC-v3 §4.5C):',
        '- status="reported": link to a confirmed or static_verified finding via linkedFindingId.',
        '- status="ruled_out": REQUIRES non-empty enforcingControl quoting the exact file:line in /repos or exact negative-control exchangeId proving the control runs on the attacker path (generic claims are rejected).',
        '- status="needs_follow_up": REQUIRES a non-empty machine-readable proofGapReason (e.g. no_spec_shape, no_authenticated_persona, baseline_empty) explaining the exact blocker so the Coordinator Planner and the held-out autopsy can distinguish an honest gap from a silent skip.',
        'Proof gaps are route-scoped: a coded gap MUST name the route it applies to via route="METHOD /path" (e.g. route="GET /api/orders/:id"); a gap on one route never discharges another probed route.',
      ].join(' '),
      parameters: obj({
        origin: str({ maxLength: 256 }),
        category: oneOf(owaspCategories),
        status: oneOf(coverageStatuses),
        summary: str({ maxLength: 600 }),
        enforcingControl: opt(str({ description: 'REQUIRED when status="ruled_out": exact file:line in /repos or exact negative-control exchangeId.', maxLength: 500 })),
        proofGapReason: opt(str({ description: `REQUIRED when status="needs_follow_up": machine-readable code plus detail (${[...SPEC_PROOF_GAP_CODES, ...SPEC_PROOF_GAP_ALIASES].join('|')}) explaining the exact blocker.`, maxLength: 600 })),
        route: opt(str({ description: 'Route this closure applies to, as "METHOD /path" (path parameters may be concrete: "GET /api/orders/1001"). REQUIRED for a coded needs_follow_up gap when more than one route was probed, because the gap discharges only that route.', maxLength: 200 })),
        linkedFindingId: opt(str({ description: 'Finding ID when status="reported".', maxLength: 64 })),
        preconditionCapIds: opt(arr(str({ maxLength: 160 }), { maxItems: 16 })),
        branchKey: opt(str({ maxLength: 200 })),
        hypothesisClass: opt(str({ maxLength: 100 })),
        exchangeIds: opt(arr(str({ maxLength: 120 }), { maxItems: 16 })),
      }),
      replay: 'safe',
      outputLimits,
      execute: async (args, _api, ctx) => {
        const signal = combineSignal(ctx.abortSignal)
        if (args.status === 'ruled_out' && (!args.enforcingControl || args.enforcingControl.trim().length < 3)) {
          return {
            isError: true,
            output: [{
              type: 'text' as const,
              text: 'record_coverage validation failed: status="ruled_out" REQUIRES a non-empty enforcingControl quoting the exact file:line in /repos or exact negative-control exchangeId proving the control enforces on the attacker path.',
            }],
          }
        }
        if (args.status === 'needs_follow_up' && (!args.proofGapReason || args.proofGapReason.trim().length < 5)) {
          return {
            isError: true,
            output: [{
              type: 'text' as const,
              text: `record_coverage validation failed: status="needs_follow_up" REQUIRES a non-empty proofGapReason explaining what is needed to confirm or rule out this lead. Use a machine-readable code so the settlement proof gap is auditable: ${[...SPEC_PROOF_GAP_CODES, ...SPEC_PROOF_GAP_ALIASES].join(', ')}.`,
            }],
          }
        }
        // A coded gap must bind to a route before it is persisted: one gap discharges one route.
        let boundRoute = args.route?.trim() || undefined
        if (args.status === 'needs_follow_up' && parseProofGapCode(args.proofGapReason)) {
          const binding = specSubmission?.tracker?.checkGapRoute(args.route)
          if (binding && !binding.ok) {
            return { isError: true, output: [{ type: 'text' as const, text: binding.error }] }
          }
          if (binding?.ok && binding.key) boundRoute = binding.key
        }
        const routeText = boundRoute
        // Persist the binding alongside the machine-readable code (the ledger has no route column):
        // `no_spec_shape: ... [route=GET /api/orders/:id]`.
        const persistedGapReason = args.proofGapReason?.trim()
          ? `${args.proofGapReason.trim()}${routeText ? ` [route=${routeText}]` : ''}`
          : undefined
        return wrapExec('record_coverage', () => fn({
          ...args,
          enforcingControl: args.enforcingControl?.trim() || undefined,
          proofGapReason: persistedGapReason,
          route: routeText,
          linkedFindingId: args.linkedFindingId?.trim() || undefined,
          ...(args.preconditionCapIds?.length ? { preconditionCapIds: args.preconditionCapIds } : {}),
          ...(args.branchKey?.trim() ? { branchKey: args.branchKey.trim() } : {}),
          ...(args.hypothesisClass?.trim() ? { hypothesisClass: args.hypothesisClass.trim() } : {}),
          ...(args.exchangeIds?.length ? { exchangeIds: args.exchangeIds } : {}),
        }, signal).then(result => {
          if (args.status === 'needs_follow_up' && args.proofGapReason?.trim()) {
            specSubmission?.tracker?.noteProofGap({
              proofGapReason: args.proofGapReason,
              category: args.category,
              ...(args.route ? { route: args.route } : {}),
            })
          }
          return result
        }), signal)
      },
    }))
  }

  const hasKovoVerify = Boolean(handlers.kovo_verify)
  const allowLegacyReplaySpec = Boolean(specSubmission?.allowLegacyReplaySpec)

  if (handlers.kovo_verify) {
    const fn = handlers.kovo_verify
    let gvValidationErrors = 0
    tools.push(defineTool({
      name: 'kovo_verify',
      description: KOVO_VERIFY_TOOL_DESCRIPTION,
      parameters: obj({
        script: opt(str({
          description: 'REQUIRED (unless `scriptPath` is provided): complete inline TypeScript verification code using pre-injected `ctx` (e.g. `await ctx.prove_access_boundary({ ... }); return ctx.result({ title: "..." })`). Takes precedence over `scriptPath`; never call `kovo_verify` without `script` or `scriptPath`.',
          minLength: 1,
          maxLength: 64 * 1024,
        })),
        scriptPath: opt(str({
          description: 'Optional fallback: workspace-relative path to an existing `.ts` file in `/repos` (omit when passing inline `script`).',
          minLength: 1,
          maxLength: 512,
        })),
        title: opt(str({
          description: 'Optional secondary metadata: short proof title echoed by the verdict. Never send `title` without `script`.',
          maxLength: 300,
        })),
        runtime: opt(oneOf(['ts'] as const, {
          description: 'Optional secondary metadata (TypeScript only; defaults to `"ts"`). Never send `{ runtime, timeoutMs }` without `script`.',
        })),
        timeoutMs: opt(int({
          minimum: 1_000,
          maximum: 120_000,
          description: 'Optional secondary metadata: execution timeout in ms (1000..120000, default 60000). Never send `timeoutMs` without `script`.',
        })),
        code: opt(str({ description: 'Optional alias for `script` (prefer `script`).', minLength: 1, maxLength: 64 * 1024 })),
        source: opt(str({ description: 'Optional alias for `script` (prefer `script`).', minLength: 1, maxLength: 64 * 1024 })),
      }),
      replay: 'unsafe',
      outputLimits,
      execute: async (args, _api, ctx) => {
        const signal = combineSignal(ctx.abortSignal)
        const malformed = detectMalformedToolCallArgs(args)
        if (malformed) {
          return {
            isError: true,
            output: [{
              type: 'text' as const,
              text: formatMalformedToolArgsError('kovo_verify', malformed),
            }],
          }
        }
        const toolArgAlias: 'code' | 'source' | undefined = !args.script?.trim()
          ? (args.code?.trim() ? 'code' : args.source?.trim() ? 'source' : undefined)
          : undefined
        const inlineScript = (args.script ?? args.code ?? args.source)?.trim()
        const scriptPath = args.scriptPath?.trim()
        const rawRuntime = args.runtime as string | undefined
        if ((rawRuntime !== undefined && rawRuntime !== 'ts') || (scriptPath && /\.py$/i.test(scriptPath))) {
          return {
            isError: true,
            output: [{
              type: 'text' as const,
              text: KOVO_VERIFY_TS_ONLY_ERROR,
            }],
          }
        }
        if (!inlineScript && !scriptPath) {
          gvValidationErrors += 1
          const example = '{"script":"await ctx.prove_access_boundary({ controlPersona: \'user_b\', probePersona: \'user_a\', route: \'/api/items/1\' }); return ctx.result({ title: \'BOLA read\' })","runtime":"ts"}'
          const loopStop = gvValidationErrors >= 3
            ? ` Repeated kovo_verify validation errors (${gvValidationErrors}x): stop retrying malformed calls — either pass a non-empty \`script\` string matching the example or call record_coverage(proofGapReason="no_spec_shape") and complete_intent.`
            : ''
          return {
            isError: true,
            output: [{
              type: 'text' as const,
              text: `kovo_verify validation failed: \`script\` is REQUIRED (do not send metadata-only \`{ runtime, timeoutMs, title }\`); provide non-empty inline code in \`script\` (or workspace file in \`scriptPath\`). Example call: ${example}.${loopStop}`,
            }],
          }
        }
        if (toolArgAlias) {
          try {
            specSubmission?.onVerifyAliasUsed?.([toolArgAlias === 'code' ? 'tool_arg:code' : 'tool_arg:source'])
          } catch { /* telemetry only */ }
        }
        gvValidationErrors = 0
        const runtime: KovoVerifyRuntime = 'ts'
        const payload: KovoVerifyArgs = {
          ...(inlineScript ? { script: scrubExact(inlineScript) } : { scriptPath }),
          runtime,
          ...(args.title?.trim() ? { title: scrubExact(args.title.trim()) } : {}),
          ...(args.timeoutMs !== undefined ? { timeoutMs: args.timeoutMs } : {}),
          ...(toolArgAlias ? { aliasUsed: toolArgAlias } : {}),
        }
        return wrapExec(
          'kovo_verify',
          async () => {
            const result = await fn(payload, signal)
            const summary = summarizeKovoVerifyOutcome(result)
            const transcriptRoutes = summary.transcriptSummary
              .filter((entry): entry is Record<string, unknown> => Boolean(entry) && typeof entry === 'object')
              .map(entry => ({
                method: typeof entry.method === 'string' ? entry.method : undefined,
                path: typeof entry.route === 'string'
                  ? entry.route
                  : typeof entry.pathAndQuery === 'string'
                    ? entry.pathAndQuery
                    : typeof entry.path === 'string'
                      ? entry.path
                      : undefined,
              }))
              .filter(entry => Boolean(entry.path))
            specSubmission?.tracker?.noteVerifyScript(payload.script, transcriptRoutes, { confirmed: summary.confirmed })
            return summary
          },
          signal,
        )
      },
    }))
  }

  if (handlers.propose_chain_finding) {
    const fn = handlers.propose_chain_finding
    tools.push(defineTool({
      name: 'propose_chain_finding',
      description: proposeChainFindingDescription(hasKovoVerify, allowLegacyReplaySpec),
      parameters: obj({
        replaySpec: unsafe<Record<string, unknown>>({
          type: 'object',
          description: 'DeclarativeReplaySpec JSON (version: 1, kind [one of the 14 kinds], origin, title, category, cwe, severity, severityRationale, impact, remediation, recheckInstructions, assertionsJq, plus kind-specific fields).',
        }),
        counterevidence: str({
          description: 'REQUIRED non-empty strongest argument AGAINST exploitability (alternative explanations, mitigating controls, scope/preconditions).',
          maxLength: 2000,
        }),
        confidenceRationale: str({
          description: 'REQUIRED non-empty justification for why the finding holds despite counterevidence.',
          maxLength: 1500,
        }),
        severityChangeConditions: opt(str({
          description: 'Optional conditions under which severity would increase or decrease.',
          maxLength: 1000,
        })),
        codeLocations: opt(arr(codeLocationInputSchema, {
          maxItems: 16,
          description: 'Optional concrete source code locations in mounted /repos/<repo>.',
        })),
        chainFactIds: opt(arr(str({ maxLength: 64 }), { maxItems: 32 })),
        exchangeIds: opt(arr(str({ maxLength: 64 }), { maxItems: 32 })),
        verifyNow: opt(bool({ description: 'Run synchronous Zero-LLM inline verification immediately (default true).' })),
      }),
      replay: 'safe',
      outputLimits,
      execute: async (args, _api, ctx) => {
        const signal = combineSignal(ctx.abortSignal)
        const counterevidence = (args.counterevidence ?? '').trim()
        const confidenceRationale = (args.confidenceRationale ?? '').trim()
        const errors: string[] = []
        if (counterevidence.length < 10) {
          errors.push('- counterevidence: must be a non-empty substantive argument against exploitability (>= 10 chars).')
        }
        if (confidenceRationale.length < 10) {
          errors.push('- confidenceRationale: must be a non-empty justification explaining why the finding holds (>= 10 chars).')
        }
        const parsed = declarativeReplaySpecSchema.safeParse(args.replaySpec)
        if (hasKovoVerify && parsed.success && parsed.data.kind !== 'static_ast_proof') {
          return {
            isError: true,
            output: [{
              type: 'text' as const,
              text: kovoVerifyRedirectMessage(parsed.data.kind),
            }],
          }
        }
        if (!parsed.success) {
          errors.push(formatReplaySpecValidationIssues(parsed.error.issues, 'replaySpec'))
        }
        if (errors.length > 0) {
          return {
            isError: true,
            output: [{
              type: 'text' as const,
              text: `propose_chain_finding validation failed. Fix these issues and retry:\n${errors.join('\n')}`,
            }],
          }
        }
        return wrapExec('propose_chain_finding', () => fn({
          replaySpec: parsed.data!,
          chainFactIds: args.chainFactIds ?? [],
          exchangeIds: args.exchangeIds ?? [],
          counterevidence: scrubForDisplay(counterevidence),
          confidenceRationale: scrubForDisplay(confidenceRationale),
          severityChangeConditions: args.severityChangeConditions?.trim() ? scrubForDisplay(args.severityChangeConditions.trim()) : undefined,
          codeLocations: args.codeLocations,
          verifyNow: args.verifyNow ?? true,
        }, signal).then(result => {
          specSubmission?.tracker?.noteSpecAttempt(replaySpecRouteSteps(parsed.data))
          return withVerifierRepairFeedback(result, hasKovoVerify)
        }), signal)
      },
    }))
  }

  if (handlers.update_proposed_finding) {
    const fn = handlers.update_proposed_finding
    tools.push(defineTool({
      name: 'update_proposed_finding',
      description: 'Revise or upgrade an existing finding (e.g. when submission deduplication identifies an existing finding sharing the same root cause, or to attach stronger Replay Spec / higher severity / codeLocations / counterevidence).',
      parameters: obj({
        findingId: str({ description: 'Existing finding ID to update.', maxLength: 64 }),
        title: opt(str({ maxLength: 200 })),
        severity: opt(oneOf(findingSeverities)),
        summary: opt(str({ maxLength: 1500 })),
        counterevidence: opt(str({ maxLength: 2000 })),
        confidenceRationale: opt(str({ maxLength: 1500 })),
        severityChangeConditions: opt(str({ maxLength: 1000 })),
        replaySpec: opt(unsafe<Record<string, unknown>>({
          type: 'object',
          description: 'Optional replacement DeclarativeReplaySpec JSON.',
        })),
        codeLocations: opt(arr(codeLocationInputSchema, { maxItems: 16 })),
        verifyNow: opt(bool({ description: 'Run synchronous Zero-LLM inline verification when replaySpec is provided (default true).' })),
      }),
      replay: 'safe',
      outputLimits,
      execute: async (args, _api, ctx) => {
        const signal = combineSignal(ctx.abortSignal)
        let parsedSpec: DeclarativeReplaySpec | undefined
        if (args.replaySpec !== undefined) {
          const parsed = declarativeReplaySpecSchema.safeParse(args.replaySpec)
          if (hasKovoVerify && parsed.success && parsed.data.kind !== 'static_ast_proof') {
            return {
              isError: true,
              output: [{
                type: 'text' as const,
                text: kovoVerifyRedirectMessage(parsed.data.kind),
              }],
            }
          }
          if (!parsed.success) {
            return {
              isError: true,
              output: [{
                type: 'text' as const,
                text: `update_proposed_finding replaySpec validation failed:\n${formatReplaySpecValidationIssues(parsed.error.issues, 'replaySpec')}`,
              }],
            }
          }
          parsedSpec = parsed.data
        }
        return wrapExec('update_proposed_finding', () => fn({
          findingId: args.findingId,
          title: args.title?.trim() ? scrubForDisplay(args.title.trim()) : undefined,
          severity: args.severity,
          summary: args.summary?.trim() ? scrubForDisplay(args.summary.trim()) : undefined,
          counterevidence: args.counterevidence?.trim() ? scrubForDisplay(args.counterevidence.trim()) : undefined,
          confidenceRationale: args.confidenceRationale?.trim() ? scrubForDisplay(args.confidenceRationale.trim()) : undefined,
          severityChangeConditions: args.severityChangeConditions?.trim() ? scrubForDisplay(args.severityChangeConditions.trim()) : undefined,
          replaySpec: parsedSpec,
          codeLocations: args.codeLocations,
          verifyNow: args.verifyNow,
        }, signal).then(result => {
          specSubmission?.tracker?.noteSpecAttempt(parsedSpec ? replaySpecRouteSteps(parsedSpec) : undefined)
          return withVerifierRepairFeedback(result, hasKovoVerify)
        }), signal)
      },
    }))
  }

  // Wave 3 C1: hide legacy verify_replay_spec from LLM tool schemas whenever kovo_verify is
  // active (unless explicitly opted in via allowLegacyReplaySpec: true) to prevent DSL dilution.
  if (handlers.verify_replay_spec && (!hasKovoVerify || allowLegacyReplaySpec)) {
    const fn = handlers.verify_replay_spec
    tools.push(defineTool({
      name: 'verify_replay_spec',
      description: `${hasKovoVerify ? '[LEGACY FALLBACK — `kovo_verify` is active in this session. Prefer `kovo_verify(script="<inline TS using ctx.prove_*>", runtime="ts")` for all runtime proofs so findings persist ProofReceipt (`proof_kind="agent_script"`). Use `verify_replay_spec` ONLY for `static_ast_proof` or when `kovo_verify` is unavailable.] ' : ''}Execute a DeclarativeReplaySpec synchronously through Kovo Hunter’s Zero-LLM ReplayVerifier and return sanitized InlineVerifyFeedback (jqError, failedStepId, spaCatchallMatched, canaryTriggered, stepStatuses, retriesRemaining). Maximum 2 repair retries (3 attempts total) per hypothesis. ${KOVO_VERIFY_SPEC_SHAPE}`,
      parameters: obj({
        spec: opt(unsafe<Record<string, unknown>>({
          type: 'object',
          description: 'DeclarativeReplaySpec JSON to verify deterministically.',
        })),
        replaySpec: opt(unsafe<Record<string, unknown>>({
          type: 'object',
          description: 'Alias for spec: DeclarativeReplaySpec JSON.',
        })),
        findingId: opt(str({ description: 'Optional finding ID to update/track attempts against.', maxLength: 64 })),
        replaySpecId: opt(str({ description: 'Optional replay_specs row ID to update.', maxLength: 64 })),
      }),
      replay: 'safe',
      outputLimits,
      execute: async (args, _api, ctx) => {
        const signal = combineSignal(ctx.abortSignal)
        const rawSpec = args.spec ?? args.replaySpec
        if (!rawSpec) {
          return {
            isError: true,
            output: [{
              type: 'text' as const,
              text: 'verify_replay_spec validation failed: spec (or replaySpec) is required.',
            }],
          }
        }
        const parsed = declarativeReplaySpecSchema.safeParse(rawSpec)
        if (hasKovoVerify && parsed.success && parsed.data.kind !== 'static_ast_proof') {
          return {
            isError: true,
            output: [{
              type: 'text' as const,
              text: kovoVerifyRedirectMessage(parsed.data.kind),
            }],
          }
        }
        if (!parsed.success) {
          return {
            isError: true,
            output: [{
              type: 'text' as const,
              text: `verify_replay_spec validation failed. Fix these issues and retry:\n${formatReplaySpecValidationIssues(parsed.error.issues)}`,
            }],
          }
        }
        return wrapExec('verify_replay_spec', () => fn({
          spec: parsed.data,
          replaySpec: parsed.data,
          findingId: args.findingId?.trim() || undefined,
          replaySpecId: args.replaySpecId?.trim() || undefined,
        }, signal).then(result => {
          specSubmission?.tracker?.noteSpecAttempt(replaySpecRouteSteps(parsed.data))
          return withVerifierRepairFeedback(result, hasKovoVerify)
        }), signal)
      },
    }))
  }

  if (handlers.suggest_candidate_host) {
    const fn = handlers.suggest_candidate_host
    tools.push(defineTool({
      name: 'suggest_candidate_host',
      description: 'Suggest a newly discovered hostname/subdomain as an unapproved candidate host. It remains out of scope until the operator explicitly approves it.',
      parameters: obj({
        origin: str({ maxLength: 256 }),
        source: str({ maxLength: 160 }),
        thirdParty: opt(bool()),
      }),
      replay: 'safe',
      outputLimits,
      execute: async (args, _api, ctx) => {
        const signal = combineSignal(ctx.abortSignal)
        return wrapExec('suggest_candidate_host', () => fn(args, signal), signal)
      },
    }))
  }

  if (handlers.board_post) {
    const fn = handlers.board_post
    tools.push(defineTool({
      name: 'board_post',
      description: 'Post a concise Swarm Board claim/handoff/lead/blocker/status/note for peers (redacted, <=1200 chars, evidence-gated @mentions). Never post just to acknowledge receipt.',
      parameters: obj({
        kind: opt(oneOf(specialistBoardPostKinds, { description: 'Coordination kind (default note). brief/approval/verdict are deterministic posters only.' })),
        body: str({ description: 'Concise redacted coordination text; cite refFactIds/refExchangeIds instead of raw HTTP bodies, headers, tokens, or secrets.', maxLength: boardPostBodyLimit }),
        mentions: opt(arr(str({ description: 'Roster handle (e.g. bola, coordinator); at most one peer per turn.', maxLength: 25 }), { maxItems: 8 })),
        refFactIds: opt(arr(str({ maxLength: 64 }), { maxItems: 50, description: 'Fact IDs backing this post (required for a peer handoff/lead).' })),
        refExchangeIds: opt(arr(str({ maxLength: 64 }), { maxItems: 50, description: 'Exchange IDs backing this post.' })),
        refFindingIds: opt(arr(str({ maxLength: 64 }), { maxItems: 50 })),
        refStepId: opt(str({ maxLength: 64, description: 'Chain step ID this post relates to.' })),
        replyToSeq: opt(int({ minimum: 1, description: 'Optional board sequence number this post replies to.' })),
      }),
      replay: 'safe',
      outputLimits,
      execute: async (args, _api, ctx) => {
        const signal = combineSignal(ctx.abortSignal)
        return wrapExec('board_post', () => fn(args as BoardPostArgs, signal), signal)
      },
    }))
  }

  if (handlers.board_read) {
    const fn = handlers.board_read
    tools.push(defineTool({
      name: 'board_read',
      description: 'Read untainted, approved-scope, redacted Swarm Board posts (default 20, max 50). Prefer the injected <board_delta> at turn start instead of polling.',
      parameters: obj({
        sinceSeq: opt(int({ minimum: 0, description: 'Only return posts after this board sequence.' })),
        kind: opt(oneOf(boardMessageKinds)),
        authorHandle: opt(str({ maxLength: 25 })),
        limit: opt(int({ minimum: 1, maximum: 50 })),
      }),
      replay: 'safe',
      outputLimits,
      execute: async (args, _api, ctx) => {
        const signal = combineSignal(ctx.abortSignal)
        return wrapExec('board_read', () => fn(args as BoardReadArgs, signal), signal)
      },
    }))
  }

  if (handlers.complete_intent) {
    const fn = handlers.complete_intent
    tools.push(defineTool({
      name: 'complete_intent',
      description: 'Explicitly finish this investigation intent after committing facts, coverage, and any replay specs. Terminates the worker loop cleanly.',
      parameters: obj({
        status: oneOf(intentCompletionStatuses),
        summary: str({ maxLength: 2000 }),
        nextRecommendations: opt(arr(str({ maxLength: 300 }), { maxItems: 8 })),
      }),
      replay: 'safe',
      outputLimits,
      execute: async (args, _api, ctx) => {
        const signal = combineSignal(ctx.abortSignal)
        const snapshot = specSubmission?.tracker?.snapshot()
        if (snapshot && (args.status === 'proved' || args.status === 'partial')) {
          // Validate every coded gap against the host-observed exchange ledger for its route.
          // An unsupported gap is rejected once per route (never a loop) and the next turn is
          // reserved for kovo_verify or for recording the missing exchange.
          const gapCheck = specSubmission?.tracker?.validateGapsForSettlement()
          if (gapCheck && gapCheck.rejected.length > 0) {
            const count = specSubmission?.tracker?.noteRequired() ?? 0
            const gapTarget = gapCheck.target
            const target: SpecRouteEvidence | undefined = gapTarget
              ? { method: gapTarget.method, path: gapTarget.path, params: [...gapTarget.params], ...(gapTarget.origin ? { origin: gapTarget.origin } : {}) }
              : (snapshot.obligationTarget ?? snapshot.route)
            if (target) specSubmission?.tracker?.noteDemand(proofRouteKey(target.method, target.path))
            specSubmission?.onRequired?.({
              status: args.status,
              count,
              ...(target ? { route: target } : {}),
            })
            return {
              isError: true,
              output: [{
                type: 'text' as const,
                text: gapValidationRejectedMessage(gapCheck.rejected, target, {
                  hasKovoVerify: hasKovoVerify && !allowLegacyReplaySpec,
                  settling: specSubmission?.isSettling?.() ?? true,
                }),
              }],
            }
          }
        }
        if (snapshot && (args.status === 'proved' || args.status === 'partial') && specSubmissionRequiredFor(snapshot)) {
          const count = specSubmission?.tracker?.noteRequired() ?? 0
          // Demand the highest-value uncovered route, never whichever happened to be last.
          const target = snapshot.obligationTarget ?? snapshot.route
          if (target) specSubmission?.tracker?.noteDemand(proofRouteKey(target.method, target.path))
          specSubmission?.onRequired?.({
            status: args.status,
            count,
            ...(target ? { route: target } : {}),
          })
          return {
            isError: true,
            output: [{ type: 'text' as const, text: specSubmissionRequiredMessage(target, { hasKovoVerify: hasKovoVerify && !allowLegacyReplaySpec }) }],
          }
        }
        const completion: IntentCompletion = {
          status: args.status,
          summary: scrubForDisplay(args.summary),
          nextRecommendations: args.nextRecommendations?.map(scrubForDisplay),
        }
        onCompleteIntent(completion)
        return wrapExec('complete_intent', () => fn(completion, signal), signal, { terminate: true })
      },
    }))
  }

  // v6 Phase 4: read/query tools run concurrently; network/mutation tools stay sequential.
  return tools.map(tool => ({ ...tool, executionMode: PARALLEL_READ_ONLY_TOOLS.has(tool.name) ? 'parallel' as const : 'sequential' as const }))
}

// ---------------------------------------------------------------------------
// High-Limit Multi-Turn Pi Durable Runner
// ---------------------------------------------------------------------------

/** Identifiers stamped on trace events. Defaults to the request/session/scenario handles. */
export interface AgentTraceContext {
  runId?: string
  assignmentId?: string
  specialistProfile?: string
}

/** Structural view of a pi-ai message, so tracing does not depend on the provider package types. */
interface TraceableMessage {
  role: string
  content?: unknown
  timestamp?: number
}

function traceMessageText(content: unknown): string {
  if (typeof content === 'string') return content
  if (!Array.isArray(content)) return ''
  return content
    .map((part) => {
      if (typeof part === 'string') return part
      if (part && typeof part === 'object' && typeof (part as { text?: unknown }).text === 'string') {
        return (part as { text: string }).text
      }
      return ''
    })
    .join('')
}

function promptPrefixHashFor(messages: readonly TraceableMessage[]): string | null {
  const systemText = messages
    .filter(message => message.role === 'system')
    .map(message => traceMessageText(message.content))
    .filter(text => text.length > 0)
    .join('\n')
  // Providers keep instructions outside the message list; fall back to the stable leading text.
  const prefix = systemText || messages
    .map(message => traceMessageText(message.content))
    .find(text => text.length > 0) || ''
  if (!prefix) return null
  return createHash('sha256').update(prefix, 'utf8').digest('hex')
}

function deltaMessagesFor(messages: readonly TraceableMessage[], previousCount: number): TraceableMessage[] {
  const delta = messages.length >= previousCount ? messages.slice(previousCount) : messages
  return delta.map(message => ({
    role: message.role,
    content: message.content,
    ...(message.timestamp !== undefined ? { timestamp: message.timestamp } : {}),
  }))
}

function assistantToolCalls(assistant: { content?: unknown }): Array<{ callId: string; name: string; args: unknown }> {
  if (!Array.isArray(assistant.content)) return []
  return assistant.content
    .filter((part): part is { type: 'toolCall'; id: string; name: string; arguments?: unknown } =>
      Boolean(part && typeof part === 'object' && (part as { type?: unknown }).type === 'toolCall'))
    .map(part => ({ callId: part.id, name: part.name, args: part.arguments ?? {} }))
}

function assistantOutputText(assistant: { content?: unknown }): string {
  if (!Array.isArray(assistant.content)) return ''
  return assistant.content
    .filter((part): part is { type: 'text'; text: string } =>
      Boolean(part && typeof part === 'object' && (part as { type?: unknown }).type === 'text'))
    .map(part => part.text)
    .join('\n')
    .trim()
}

function toolResultText(output: unknown): string {
  if (typeof output === 'string') return output
  if (!Array.isArray(output)) return ''
  return output
    .filter((part): part is { type: 'text'; text: string } =>
      Boolean(part && typeof part === 'object' && (part as { type?: unknown }).type === 'text'))
    .map(part => part.text)
    .join('\n')
}

function toolResultSummary(text: string): unknown {
  const trimmed = text.trim()
  if (!trimmed) return null
  if (trimmed.startsWith('{') || trimmed.startsWith('[')) {
    try {
      return JSON.parse(trimmed)
    } catch {
      // Truncated or non-JSON output: keep a bounded preview instead.
    }
  }
  return { text: trimmed.slice(0, 2000) }
}

function idListFrom(summary: unknown, keys: readonly string[]): string[] {
  if (!summary || typeof summary !== 'object') return []
  const record = summary as Record<string, unknown>
  const ids: string[] = []
  for (const key of keys) {
    const value = record[key]
    if (typeof value === 'string' && value) ids.push(value)
    else if (Array.isArray(value)) {
      for (const entry of value) if (typeof entry === 'string' && entry) ids.push(entry)
    }
  }
  return [...new Set(ids)]
}

function verifierFeedbackFrom(summary: unknown): unknown {
  if (!summary || typeof summary !== 'object') return undefined
  const record = summary as Record<string, unknown>
  if (isPlainRecord(record.repair)) return record.repair
  for (const key of verifierFeedbackKeys) {
    if (isPlainRecord(record[key])) return record[key]
  }
  if (verifierRepairFeedback(record)) return record
  return undefined
}

export interface AgentSessionHandle {
  /** Live accumulated wall-clock time (ms) spent waiting on provider HTTP retries, 429/5xx backoff, and stalled stream timeouts. */
  getProviderStallWaitMs(): number
}

/**
 * Tracks wall-clock time spent waiting on provider HTTP retries, 429/5xx backoff, and stalled
 * stream timeouts, strictly separated from active model generation and tool execution time.
 */
export class ProviderStallWaitTracker {
  private readonly now: () => number
  private accumulatedWaitMs = 0
  private attemptStartedAtMs: number | null = null
  private lastActivityAtMs: number | null = null
  private stallWaitStartedAtMs: number | null = null

  constructor(now: () => number = Date.now) {
    this.now = now
  }

  /** Called when a provider HTTP attempt begins (`beforeCall`). */
  onCallStart(): void {
    const t = this.now()
    if (this.stallWaitStartedAtMs !== null) {
      this.accumulatedWaitMs += Math.max(0, t - this.stallWaitStartedAtMs)
      this.stallWaitStartedAtMs = null
    }
    this.attemptStartedAtMs = t
    this.lastActivityAtMs = t
  }

  /**
   * Called on transient provider retry / 429 / 5xx backoff (`retried`) or stream stall timeout
   * (`stalled`). Anchors the wait window at `lastActivityAtMs` (for mid-stream stalls) or
   * `attemptStartedAtMs` (for failed HTTP retry attempts) without double-counting active streaming.
   */
  onRetryOrStall(kind: 'retried' | 'stalled'): void {
    const t = this.now()
    if (this.stallWaitStartedAtMs === null) {
      const anchor = kind === 'stalled'
        ? (this.lastActivityAtMs ?? this.attemptStartedAtMs ?? t)
        : (this.attemptStartedAtMs ?? this.lastActivityAtMs ?? t)
      this.stallWaitStartedAtMs = Math.min(t, anchor)
    }
  }

  /** Called when an upstream SSE token/frame arrives (`onStreamActivity`). */
  onStreamActivity(): void {
    const t = this.now()
    if (this.stallWaitStartedAtMs !== null) {
      this.accumulatedWaitMs += Math.max(0, t - this.stallWaitStartedAtMs)
      this.stallWaitStartedAtMs = null
    }
    this.lastActivityAtMs = t
  }

  /** Called when a provider attempt/turn finishes (`ok` / `error` / `aborted` / `afterResponse`). */
  onCallEnd(): void {
    const t = this.now()
    if (this.stallWaitStartedAtMs !== null) {
      this.accumulatedWaitMs += Math.max(0, t - this.stallWaitStartedAtMs)
      this.stallWaitStartedAtMs = null
    }
    this.attemptStartedAtMs = null
    this.lastActivityAtMs = null
  }

  /** Live accumulated provider stall/retry wait time in ms (includes any in-progress backoff). */
  getProviderStallWaitMs(): number {
    if (this.stallWaitStartedAtMs === null) return this.accumulatedWaitMs
    return this.accumulatedWaitMs + Math.max(0, this.now() - this.stallWaitStartedAtMs)
  }
}

export interface RunAgentSessionOptions {
  directory: string
  sessionId: string
  requestId: string
  /** Provide `profiles` for multi-profile failover pool, or a single `settings` object. */
  profiles?: readonly ResolvedModelProfile[]
  settings?: ProviderConfig
  scenario: AgentScenario
  prompt: string
  instructions?: string
  signal: AbortSignal
  /** Authoritative `AssignmentBudget` (single source of truth for maxTurns, settlementTurn, and wall-clock settlement). */
  budget?: PromptAssignmentBudget
  maxTurns?: number
  thinkingLevel?: ThinkingLevel
  roleAffinity?: RoleAffinity
  compaction?: boolean
  inlineToolOutputBytes?: number
  /** Enable Graceful Settlement wrap-up (default: true when complete_intent handler is present). */
  enableSettlement?: boolean
  /** Optional external settlement trigger (e.g., wall-clock or request budget reached). */
  shouldSettle?: () => boolean
  /** Optional wall-clock budget for the session; settles at `wallClockSettlementMs` (or `budget.wallClockSettlementMs`) and hard-rotates at `wallClockMs`. */
  wallClockMs?: number
  /** Explicit wall-clock settlement threshold in ms relative to session start (overrides default recompute when provided). */
  wallClockSettlementMs?: number
  /** Optional pause-aware clock for wall-clock settlement & rotation (auto-pauses on approval waits / run pause). */
  activeClock?: ActiveClock
  /** Optional grace window when a proof call (`kovo_verify`) is actively running at `wallClockMs` (default 5s). */
  wallClockGraceMs?: number
  /** Finite ceiling on provider-stall/retry wait time deductible from `wallClockMs` (defaults to `wallClockMs` so hard cap <= 2x base). */
  wallClockMaxStallCreditMs?: number
  /** Optional explicit finite hard wall-clock ceiling (ms) that neither stall credit nor verify grace may exceed. */
  wallClockHardCeilingMs?: number
  /** Called immediately once session state is initialized with a live handle (e.g. `getProviderStallWaitMs()`). */
  onSessionReady?: (session: AgentSessionHandle) => void
  /** Called whenever provider retry backoff or a stalled stream timeout contributes to `providerStallWaitMs`. */
  onProviderStallWait?: (info: { providerStallWaitMs: number; kind: 'retried' | 'stalled' }) => void
  /** Optional provider transport retry/timeout overrides (primarily for deterministic testing). */
  providerMaxTransportRetries?: number
  providerTransportRetryBaseMs?: number
  providerFirstEventTimeoutMs?: number
  providerIdleTimeoutMs?: number
  /** Called once when the hard per-assignment `wallClockMs` deadline triggers a bounded rotation. */
  onWallClockRotate?: (info: {
    elapsedMs: number
    effectiveElapsedMs: number
    wallClockMs: number
    turnsUsed: number
    graceUsedMs: number
    providerStallWaitMs: number
    verifyGraceApplied: boolean
  }) => void
  /** Optional telemetry callback when `kovo_verify` tool-arg aliases (`code`/`source`) are used. */
  onVerifyAliasUsed?: (aliases: readonly KovoVerifyAliasKey[]) => void
  /** Require complete_intent before finishing (with up to 2 empty-turn nudges; default: true when complete_intent handler is present). */
  requireCompleteIntent?: boolean
  handlers?: WorkerToolHandlers
  extraTools?: readonly ToolRegistration[]
  /** Static array (live-read if mutated) or dynamic getter returning the current secret set (H-8). */
  secrets?: SecretSource
  record?: CallRecorder
  beforeCall?: () => void
  onUsage?: UsageCallback
  onTurn?: (turn: number, maxTurns: number, settling: boolean) => void
  /** Executed before each model request; return extra user messages (e.g. a <board_delta> block). */
  onTurnStart?: (turn: number, maxTurns: number) => { messages?: readonly string[] } | void
  /**
   * Called whenever the in-flight assistant response grows (a text/thinking/tool-call token was
   * committed). The caller uses it to reset a no-token stall watchdog, so slow streaming is never
   * mistaken for a hung provider stream.
   */
  onStreamActivity?: () => void
  /**
   * Called when complete_intent is rejected because a probed route has neither a replay spec nor a
   * machine-readable record_coverage proof gap. Wire this to `agent.spec_submission_required`.
   */
  onSpecSubmissionRequired?: (info: { status: string; count: number; route?: SpecRouteEvidence }) => void
  /**
   * Route-scoped proof coverage at session end. Wire this to the `agent.proof_obligation` run event
   * so the funnel can prove covered/gap/demanded counts per route.
   */
  onProofObligation?: (info: ProofObligationEvent) => void
  /**
   * Coded proof-gap validation totals at session end. Wire this to the `agent.gap_validation` run
   * event so the funnel distinguishes substantiated gaps from rejected gaming attempts.
   */
  onGapValidation?: (info: GapValidationEvent) => void
  /**
   * Approved origins for this assignment. Used only to substantiate an `out_of_scope` proof gap
   * against the transcript; omitted means the scope allowlist is unknown.
   */
  approvedOrigins?: readonly string[]
  /**
   * Tier-A/chain target routes the assignment requires proof for even when the worker never probes
   * them. Each is a route obligation with its own spec/verify or coded gap.
   */
  assignedTargetRoutes?: readonly { method?: string; path?: string; origin?: string }[]
  /**
   * Called once when settlement starts early because the target route is provably clean/hardened.
   * Wire this to the `agent.early_exit` run event and the `earlyExitTurnsSaved` assignment stat.
   */
  onEarlyExit?: (info: EarlyExitEvent) => void
  onProfileSuccess?: (profileId: string) => void
  onProfileFailure?: (profileId: string, err: string, hard: boolean) => void
  /** Explicitly opt in to registering legacy `verify_replay_spec` while `kovo_verify` is active (default false). */
  allowLegacyReplaySpec?: boolean
  /** Optional staged read-only repositories root on host for fast parallel `read_repo_file` / `search_repo`. */
  reposDir?: string
  /** Optional host-side evidence/spill directory for fast parallel `read_evidence_slice`. */
  evidenceDir?: string
  /** Opt-in agentic trace writer (see createAgentTrace). Nothing is recorded when omitted. */
  trace?: AgentTrace
  /** Identifiers stamped on trace events; defaults to requestId/sessionId/scenario. */
  traceContext?: AgentTraceContext
}

export interface AgentSessionResult {
  answer: string
  turnsUsed: number
  settled: boolean
  nudgesUsed: number
  completion?: IntentCompletion
  status: 'completed' | 'turn_limit' | 'nudged_out' | 'wall_clock_rotated'
  /** True when the session terminated cleanly via its hard `wallClockMs` per-assignment rotation timer. */
  wallClockRotated?: boolean
  /** Elapsed wall-clock duration when rotated cleanly. */
  elapsedMs?: number
  /** Accumulated time (ms) spent waiting on provider HTTP retries, 429/5xx backoff, and stalled stream timeouts. */
  providerStallWaitMs?: number
  /** complete_intent rejections for a leaning conclusion without spec or coded proof gap. */
  specSubmissionRequired?: number
  /** Final spec-submission ledger (route evidence / spec attempts / coded gaps). */
  specSubmission?: SpecSubmissionSnapshot
  /** Route-scoped proof coverage (`agent.proof_obligation` payload). */
  proofObligation?: ProofObligationStats
  /** Coded proof-gap adjudication totals (`agent.gap_validation` payload). */
  gapValidation?: GapValidationStats
  /** Earned early exit (`agent.early_exit`): reason, turns used, evidence count, turns saved. */
  earlyExit?: EarlyExitEvent
  /** Turns the session never spent because settlement started early (0 when it did not). */
  earlyExitTurnsSaved?: number
}

export async function runAgentSession(options: RunAgentSessionOptions): Promise<AgentSessionResult> {
  options.signal.throwIfAborted()

  const effectiveRole = options.roleAffinity ?? roleAffinityForScenario(options.scenario)
  const profiles = options.profiles?.length ? resolveProfilePoolForRole(effectiveRole, options.profiles) : undefined
  const now = Date.now()
  const primarySettings = (profiles ? (profiles.find(p => isProfileHealthy(p, now)) ?? profiles[0]) : undefined) ?? options.settings
  if (!primarySettings) {
    throw new Error('runAgentSession requires either profiles or settings.')
  }

  const defaultTurns = options.scenario === 'chain-planner' || options.scenario === 'threat-model' || options.scenario === 'cross-host-synthesizer'
    ? defaultPlannerMaxTurns
    : options.scenario === 'patch-author' || options.scenario === 'patch-reviewer'
      ? defaultPatchMaxTurns
      : options.scenario === 'code-auditor'
        ? defaultCodeAuditMaxTurns
        : options.scenario === 'worker-investigation'
          ? defaultWorkerMaxTurns
          : (primarySettings.protocol === 'messages' ? 3 : 1)
  const budget = options.budget
  const maxTurns = Math.max(1, Math.min(maxWorkerMaxTurns, Math.floor(options.maxTurns ?? budget?.maxTurns ?? defaultTurns)))
  const inlineLimit = Math.max(
    1024,
    Math.min(maxInlineToolOutputBytes, Math.floor(options.inlineToolOutputBytes ?? defaultInlineToolOutputBytes)),
  )
  const contextWindow = Math.max(32_000, Math.min(1_000_000, primarySettings.contextWindow ?? DEFAULT_PROVIDER.contextWindow))
  const effectiveThinking: ThinkingLevel = options.thinkingLevel ?? defaultThinkingForRole(effectiveRole, primarySettings.thinkingLevel)

  const directory = join(options.directory, 'agent-sessions')
  mkdirSync(directory, { recursive: true, mode: 0o700 })
  const sessionPath = join(directory, options.sessionId + '.sqlite')
  try {
    writeFileSync(sessionPath, '', { flag: 'wx', mode: 0o600 })
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== 'EEXIST') throw error
  }

  // H-8: Read live secret set on every model-boundary scrub (never snapshot at session start)
  // so rotated session tokens / newly registered secrets minted mid-run are immediately scrubbed.
  const staticKeySecrets: readonly NamedSecret[] = profiles
    ? profiles.map(p => ({ value: p.key, placeholder: '[redacted]' }))
    : [{ value: primarySettings.key, placeholder: '[redacted]' }]
  const resolveLiveSecrets = (): readonly NamedSecret[] => {
    const dynamic = typeof options.secrets === 'function'
      ? options.secrets()
      : (options.secrets ?? [])
    if (!dynamic.length) return staticKeySecrets
    return [...dynamic, ...staticKeySecrets]
  }
  const scrubbers = createSessionScrubbers(options.secrets, staticKeySecrets)
  const { scrubForDisplay } = scrubbers

  const ownedClock = !options.activeClock
  const activeClock = options.activeClock ?? new ActiveClock()
  let sessionClockBaseMs = activeClock.activeElapsedMs()
  const sessionActiveElapsedMs = () => Math.max(0, activeClock.activeElapsedMs() - sessionClockBaseMs)
  const sessionController = new AbortController()
  const onParentAbort = () => sessionController.abort(options.signal.reason)
  options.signal.addEventListener('abort', onParentAbort, { once: true })
  if (options.signal.aborted) sessionController.abort(options.signal.reason)

  const rawWallClockMs = options.wallClockMs ?? budget?.wallClockMs
  const effectiveWallClockMs = rawWallClockMs && Number.isFinite(rawWallClockMs) && rawWallClockMs > 0
    ? Math.max(1, Math.floor(rawWallClockMs))
    : undefined
  const displayWallClockMs = budget?.wallClockMs && Number.isFinite(budget.wallClockMs) && budget.wallClockMs > 0
    ? Math.max(1, Math.floor(budget.wallClockMs))
    : effectiveWallClockMs
  const rawWallClockSettlementMs = options.wallClockSettlementMs ?? budget?.wallClockSettlementMs
  const wallClockSettlementBudgetMs = rawWallClockSettlementMs !== undefined
    && Number.isFinite(rawWallClockSettlementMs)
    && rawWallClockSettlementMs > 0
    ? Math.max(1, Math.floor(rawWallClockSettlementMs))
    : effectiveWallClockMs !== undefined
      ? wallClockSettlementMs(effectiveWallClockMs, budget?.budgetClass === 'multi_hop_chain')
      : undefined
  const proofGraceMs = effectiveWallClockMs === undefined
    ? 0
    : options.wallClockGraceMs !== undefined
      ? Math.max(0, Math.floor(options.wallClockGraceMs))
      : effectiveWallClockMs >= 20_000
        ? WALL_CLOCK_PROOF_GRACE_MS
        : Math.min(WALL_CLOCK_PROOF_GRACE_MS, Math.max(25, Math.floor(effectiveWallClockMs * 0.25)))
  const maxStallCreditMs = effectiveWallClockMs === undefined
    ? 0
    : options.wallClockMaxStallCreditMs !== undefined
      ? (Number.isFinite(options.wallClockMaxStallCreditMs) && options.wallClockMaxStallCreditMs > 0
          ? Math.min(effectiveWallClockMs, Math.floor(options.wallClockMaxStallCreditMs))
          : 0)
      : effectiveWallClockMs
  const hardWallClockCeilingMs = effectiveWallClockMs === undefined
    ? undefined
    : options.wallClockHardCeilingMs !== undefined && Number.isFinite(options.wallClockHardCeilingMs) && options.wallClockHardCeilingMs > 0
      ? Math.max(1, Math.min(effectiveWallClockMs + maxStallCreditMs, Math.floor(options.wallClockHardCeilingMs)))
      : effectiveWallClockMs + maxStallCreditMs

  const providerStallTracker = new ProviderStallWaitTracker(() => activeClock.activeElapsedMs())
  const getProviderStallWaitMs = () => providerStallTracker.getProviderStallWaitMs()
  const sessionEffectiveElapsedMs = () => {
    const activeMs = sessionActiveElapsedMs()
    const creditedStallMs = Math.min(getProviderStallWaitMs(), maxStallCreditMs)
    return Math.max(0, activeMs - creditedStallMs)
  }
  try {
    options.onSessionReady?.({ getProviderStallWaitMs })
  } catch { /* observer must never break session startup */ }

  let wallClockRotated = false
  let wallClockExpired = false
  let wallClockNudgeSent = false
  let wallClockGraceStartedAtMs: number | undefined
  let wallClockTimer: DeadlineTimerHandle | undefined
  let wallClockGraceTimer: DeadlineTimerHandle | undefined
  const activeProofCallIds = new Set<string>()
  const clearWallClockTimers = () => {
    if (wallClockTimer) { wallClockTimer.cancel(); wallClockTimer = undefined }
    if (wallClockGraceTimer) { wallClockGraceTimer.cancel(); wallClockGraceTimer = undefined }
  }

  const providerOpts: ProviderOptions = {
    signal: sessionController.signal,
    record: options.record,
    secrets: resolveLiveSecrets,
    maxCalls: Math.max(defaultMaxCalls, maxTurns + 40),
    ...(options.providerMaxTransportRetries !== undefined ? { maxTransportRetries: options.providerMaxTransportRetries } : {}),
    ...(options.providerTransportRetryBaseMs !== undefined ? { transportRetryBaseMs: options.providerTransportRetryBaseMs } : {}),
    ...(options.providerFirstEventTimeoutMs !== undefined ? { firstEventTimeoutMs: options.providerFirstEventTimeoutMs } : {}),
    ...(options.providerIdleTimeoutMs !== undefined ? { idleTimeoutMs: options.providerIdleTimeoutMs } : {}),
    thinkingLevel: effectiveThinking,
    roleAffinity: effectiveRole,
    beforeCall: () => {
      options.beforeCall?.()
      providerStallTracker.onCallStart()
    },
    onUsage: options.onUsage,
    onTelemetry: event => {
      if (event.outcome === 'retried' || event.retried) {
        providerStallTracker.onRetryOrStall('retried')
        try {
          options.onProviderStallWait?.({ providerStallWaitMs: getProviderStallWaitMs(), kind: 'retried' })
        } catch { /* telemetry only */ }
      } else if (event.outcome === 'stalled' || event.stalled) {
        providerStallTracker.onRetryOrStall('stalled')
        try {
          options.onProviderStallWait?.({ providerStallWaitMs: getProviderStallWaitMs(), kind: 'stalled' })
        } catch { /* telemetry only */ }
      } else if (
        event.outcome === 'ok'
        || event.outcome === 'truncated'
        || event.outcome === 'error'
        || event.outcome === 'aborted'
      ) {
        providerStallTracker.onCallEnd()
      }
    },
    onStreamActivity: () => {
      providerStallTracker.onStreamActivity()
      options.onStreamActivity?.()
    },
    onProfileSuccess: options.onProfileSuccess,
    onProfileFailure: (profileId, err, hard) => {
      if (!hard) {
        providerStallTracker.onRetryOrStall('retried')
      }
      options.onProfileFailure?.(profileId, err, hard)
    },
  }

  const { models, model } = profiles
    ? providerPool(profiles, options.scenario, providerOpts)
    : provider(primarySettings, options.scenario, providerOpts)

  const handlers = options.handlers ?? {}
  const enableSettlement = options.enableSettlement ?? Boolean(handlers.complete_intent && maxTurns >= 4)
  const requireCompleteIntent = options.requireCompleteIntent ?? Boolean(handlers.complete_intent)
  const settlementTurn = budget && Number.isFinite(budget.settlementTurn) && budget.settlementTurn > 0
    ? Math.max(1, Math.min(maxTurns, Math.floor(budget.settlementTurn)))
    : settlementNudgeTurnFor(maxTurns)
  const settlementNudgeTurn = settlementTurn
  const wallClockDeadline = wallClockSettlementBudgetMs

  let turnsUsed = 0
  let nudgesUsed = 0
  let settled = false
  let completion: IntentCompletion | undefined

  const triggerWallClockRotation = () => {
    if (wallClockRotated || options.signal.aborted || effectiveWallClockMs === undefined) return
    wallClockRotated = true
    clearWallClockTimers()
    const elapsedMs = sessionActiveElapsedMs()
    const providerStallWaitMs = getProviderStallWaitMs()
    const effectiveElapsedMs = sessionEffectiveElapsedMs()
    const graceUsedMs = wallClockGraceStartedAtMs !== undefined
      ? Math.max(0, activeClock.activeElapsedMs() - wallClockGraceStartedAtMs)
      : 0
    const verifyGraceApplied = wallClockGraceStartedAtMs !== undefined || graceUsedMs > 0
    try {
      options.onWallClockRotate?.({
        elapsedMs,
        effectiveElapsedMs,
        wallClockMs: effectiveWallClockMs,
        turnsUsed,
        graceUsedMs,
        providerStallWaitMs,
        verifyGraceApplied,
      })
    } catch { /* telemetry only */ }
    sessionController.abort(new Error(`Assignment wall-clock deadline reached (${elapsedMs}ms / ${effectiveWallClockMs}ms).`))
  }

  const armSessionWallClockTimer = (delayMs: number) => {
    if (wallClockTimer) { wallClockTimer.cancel(); wallClockTimer = undefined }
    if (effectiveWallClockMs === undefined || hardWallClockCeilingMs === undefined) return
    wallClockTimer = activeClock.createDeadlineTimer(Math.max(1, Math.floor(delayMs)), () => {
      wallClockTimer = undefined
      if (options.signal.aborted || wallClockRotated) return
      const activeMs = sessionActiveElapsedMs()
      const effectiveMs = sessionEffectiveElapsedMs()
      const remainingSoftMs = effectiveWallClockMs - effectiveMs
      const remainingHardMs = hardWallClockCeilingMs - activeMs
      if (remainingSoftMs > 0 && remainingHardMs > 0) {
        armSessionWallClockTimer(Math.min(remainingSoftMs, remainingHardMs))
        return
      }
      wallClockExpired = true
      if (activeProofCallIds.size > 0 && proofGraceMs > 0) {
        wallClockGraceStartedAtMs = activeClock.activeElapsedMs()
        wallClockGraceTimer = activeClock.createDeadlineTimer(proofGraceMs, () => {
          wallClockGraceTimer = undefined
          triggerWallClockRotation()
        })
        return
      }
      triggerWallClockRotation()
    })
  }
  /** Shared with the tool layer: route evidence, spec attempts and coded proof gaps. */
  const specTracker = new SpecSubmissionTracker()
  specTracker.noteAssignedRoutes(options.assignedTargetRoutes)
  specTracker.noteApprovedOrigins(options.approvedOrigins)
  /** Earned early exit; set at most once so the event/stat are never double counted. */
  let earlyExit: EarlyExitEvent | undefined
  /** Turn on which complete_intent was last rejected for a missing spec/gap (repair window). */
  let repairTurn: number | undefined
  const specSnapshot = () => specTracker.snapshot()
  /**
   * One wrap-up demand: name the highest-value uncovered route (anomaly/2xx before probe density),
   * not whichever route happened to be probed last. `demand` records the route once for the funnel.
   */
  const specDirectiveForRun = (demand = false) => {
    const snapshot = specSnapshot()
    if (!specSubmissionPending(snapshot)) return undefined
    const target = snapshot.obligationTarget ?? snapshot.route
    if (demand && target) specTracker.noteDemand(proofRouteKey(target.method, target.path))
    return settlementSpecDirective(target)
  }
  /** Attach the route-scoped proof stat to a session result and emit the funnel event once. */
  const finish = (result: AgentSessionResult): AgentSessionResult => {
    providerStallTracker.onCallEnd()
    const stats = specTracker.proofObligationStats()
    try { options.onProofObligation?.({ type: 'agent.proof_obligation', ...stats }) } catch { /* telemetry only */ }
    const gapValidation = specTracker.gapValidationStats()
    try { options.onGapValidation?.({ type: 'agent.gap_validation', ...gapValidation }) } catch { /* telemetry only */ }
    return {
      ...result,
      providerStallWaitMs: getProviderStallWaitMs(),
      proofObligation: stats,
      gapValidation,
    }
  }
  /**
   * Evidence-gated early exit, evaluated after every assistant turn. Distinct from the 85% banner:
   * the route must have answered >=2 distinct attempts with a consistent hardened shape and no
   * anomaly, and no spec submission / repair / uncoded proof gap may be in flight.
   */
  const evaluateEarlyExit = () => {
    if (!enableSettlement || earlyExit || completion || !handlers.complete_intent) return
    // Only genuinely early: at/after the 85% settlement turn the banner already handles wrap-up.
    if (turnsUsed >= settlementTurn) return
    const evidence = specTracker.observationSnapshot()
    const proofConfirmed = specTracker.hasConfirmedProof()
    if (!evidence.attempts && !proofConfirmed) return
    const snapshot = specSnapshot()
    const decision = earlyExitEligible({
      evidence,
      turnsUsed,
      maxTurns,
      specPending: snapshot.specAttempts > 0 && specSubmissionPending(snapshot),
      repairInFlight: repairTurn !== undefined && specSubmissionPending(snapshot),
      unresolvedProofGap: snapshot.proofGaps.some(gap => !gap.code),
      unprobedAssignedRoutes: snapshot.obligations.some(o => o.assigned && o.attempts === 0 && !o.covered && !o.gap),
      proofConfirmed,
    })
    if (!decision.eligible) return
    earlyExit = buildEarlyExitEvent({ reason: decision.reason, evidence, turnsUsed, maxTurns })
    settled = true
    try { options.onEarlyExit?.(earlyExit) } catch { /* telemetry must never break a run */ }
  }
  /** Effective final turn: an early exit reserves one wrap-up verify turn, then one final turn. */
  const finalTurnForRun = () => earlyExit
    ? Math.min(maxTurns, earlyExit.turnsUsed + EARLY_EXIT_GRACE_TURNS)
    : maxTurns
  /** Result fields for an earned early exit; empty (absent) when settlement started normally. */
  const earlyExitFields = () => earlyExit
    ? { earlyExit, earlyExitTurnsSaved: earlyExit.turnsSaved }
    : {}

  const registeredProofTools = handlers.kovo_verify ? ['kovo_verify'] : []
  const trace = options.trace
  const traceRunId = options.traceContext?.runId ?? options.requestId
  const traceAssignmentId = options.traceContext?.assignmentId ?? options.sessionId
  const traceSpecialistProfile = options.traceContext?.specialistProfile ?? options.scenario
  let lastTraceMessageCount = 0
  let pendingTurnTrace: {
    turnIdx: number
    startedAtMs: number
    promptPrefixHash: string | null
    deltaMessages: TraceableMessage[]
  } | undefined
  const toolStartedAt = new Map<string, number>()

  const isSettling = () => {
    if (!enableSettlement) return false
    if (earlyExit) {
      settled = true
      return true
    }
    if (settlementDue({
      turnsUsed,
      settlementTurn,
      settled,
      shouldSettle: options.shouldSettle,
      wallClockDeadline,
      now: sessionEffectiveElapsedMs,
    })) {
      settled = true
      return true
    }
    return false
  }

  const resolvedReposDir = options.reposDir
    ?? ((handlers.derive_evidence || handlers.run_sast_scan || handlers.read_repo_file || handlers.search_repo)
      ? resolveAutoReposDir(options.directory, options.prompt)
      : undefined)

  const builtTools = buildWorkerTools(
    handlers,
    scrubbers,
    sessionController.signal,
    inlineLimit,
    result => { completion = result },
    {
      tracker: specTracker,
      onRequired: (info: { status: string; count: number; route?: SpecRouteEvidence }) => {
        repairTurn = turnsUsed
        options.onSpecSubmissionRequired?.(info)
      },
      isSettling,
      ...(options.onVerifyAliasUsed ? { onVerifyAliasUsed: options.onVerifyAliasUsed } : {}),
      ...(options.allowLegacyReplaySpec ? { allowLegacyReplaySpec: true } : {}),
      ...(resolvedReposDir ? { reposDir: resolvedReposDir } : {}),
      ...(options.evidenceDir ? { evidenceDir: options.evidenceDir } : {}),
    },
  )
  // Extra tools have unknown semantics: keep them sequential so a round that calls one never races.
  const allTools: ToolRegistration[] = [
    ...builtTools,
    ...(options.extraTools ?? []).map(tool => ({ ...tool, executionMode: tool.executionMode ?? 'sequential' as const })),
  ]

  const hooks = [
    hook(GenerationTask, {
      beforeRequest(request) {
        pendingTurnTrace = {
          turnIdx: turnsUsed + 1,
          startedAtMs: Date.now(),
          promptPrefixHash: promptPrefixHashFor(request.messages as readonly TraceableMessage[]),
          deltaMessages: deltaMessagesFor(request.messages as readonly TraceableMessage[], lastTraceMessageCount),
        }
        lastTraceMessageCount = request.messages.length
        const turnStart = options.onTurnStart?.(turnsUsed + 1, maxTurns)
        const extraMessages = (turnStart?.messages ?? []).map(content => ({
          role: 'user' as const, content: scrubForDisplay(content), timestamp: Date.now(),
        }))
        const settlingNow = isSettling()
        const wallClockSettlingNow = effectiveWallClockMs !== undefined && wallClockSettlementBudgetMs !== undefined
          && sessionEffectiveElapsedMs() >= wallClockSettlementBudgetMs && !wallClockNudgeSent
        const willNudge = Boolean(handlers.complete_intent) && turnsUsed + 1 === settlementNudgeTurn
        const specDirective = specDirectiveForRun(Boolean(earlyExit) || settlingNow || wallClockSettlingNow || willNudge)
        if (earlyExit) {
          extraMessages.push({
            role: 'user' as const,
            content: earlyExitDirectiveMessage({ ...earlyExit, proofTools: registeredProofTools, ...(specDirective ? { specDirective } : {}) }),
            timestamp: Date.now(),
          })
        } else if (wallClockSettlingNow) {
          wallClockNudgeSent = true
          extraMessages.push({
            role: 'user' as const,
            content: wallClockSettlementMessage({
              elapsedMs: sessionEffectiveElapsedMs(),
              wallClockMs: displayWallClockMs ?? effectiveWallClockMs,
              proofTools: registeredProofTools,
              ...(specDirective ? { specDirective } : {}),
            }),
            timestamp: Date.now(),
          })
        } else if (settlingNow) {
          extraMessages.push({
            role: 'user' as const,
            content: settlementBannerMessage({ turnsUsed, maxTurns, settlementTurn, proofTools: registeredProofTools, ...(specDirective ? { specDirective } : {}) }),
            timestamp: Date.now(),
          })
        } else if (handlers.complete_intent && turnsUsed + 1 === settlementNudgeTurn) {
          extraMessages.push({
            role: 'user' as const,
            content: settlementNudgeMessage({ turn: turnsUsed + 1, maxTurns, settlementTurn, proofTools: registeredProofTools, ...(specDirective ? { specDirective } : {}) }),
            timestamp: Date.now(),
          })
        }
        if (!extraMessages.length) return undefined
        return {
          messages: [
            ...request.messages,
            ...extraMessages,
          ],
        }
      },
      afterResponse(message) {
        providerStallTracker.onCallEnd()
        turnsUsed += 1
        const pending = pendingTurnTrace
        pendingTurnTrace = undefined
        if (trace) {
          const assistant = message as unknown as {
            content?: unknown
            model?: string
            thinkingLevel?: string | null
            usage?: {
              input?: number
              cacheRead?: number
              output?: number
              reasoning?: number
              cost?: { total?: number }
            }
            stopReason?: string | null
            durationMs?: number
          }
          const outputText = assistantOutputText(assistant)
          try {
            trace.recordTurn({
              runId: traceRunId,
              assignmentId: traceAssignmentId,
              specialistProfile: traceSpecialistProfile,
              turnIdx: pending?.turnIdx ?? turnsUsed,
              promptPrefixHash: pending?.promptPrefixHash ?? undefined,
              deltaMessages: pending?.deltaMessages,
              model: assistant.model ?? primarySettings.model,
              modelParams: {
                temperature: null,
                thinkingLevel: assistant.thinkingLevel ?? effectiveThinking,
                maxTokens: primarySettings.maxTokens ?? DEFAULT_PROVIDER.maxTokens,
                protocol: primarySettings.protocol,
              },
              ttftMs: null,
              latencyMs: assistant.durationMs ?? (pending ? Date.now() - pending.startedAtMs : null),
              usage: {
                input: assistant.usage?.input ?? 0,
                cachedInput: assistant.usage?.cacheRead ?? 0,
                output: assistant.usage?.output ?? 0,
                reasoning: assistant.usage?.reasoning ?? 0,
                costUsd: assistant.usage?.cost?.total ?? 0,
              },
              stopReason: assistant.stopReason ?? null,
              outputText,
              toolCalls: assistantToolCalls(assistant),
            })
          } catch {
            // Tracing must never break an investigation run.
          }
        }
        const nowSettling = isSettling()
        evaluateEarlyExit()
        options.onTurn?.(turnsUsed, maxTurns, nowSettling || Boolean(earlyExit))
      },
      onYield() {
        if (!requireCompleteIntent || completion) return undefined
        if (turnsUsed >= finalTurnForRun() || nudgesUsed >= maxEmptyTurnNudges) return undefined
        nudgesUsed += 1
        return {
          continue: [
            `Plain text does not terminate an investigation intent (nudge ${nudgesUsed}/${maxEmptyTurnNudges}).`,
            'Either continue investigating with tools, record your facts/replay specs, or call complete_intent with status (proved | ruled_out | blocked | partial) and a concise summary.',
          ].join(' '),
        }
      },
    }),
    hook(ToolTask, {
      beforeTool(call) {
        if (!call.parent) toolStartedAt.set(call.id, Date.now())
        const malformed = detectMalformedToolCallArgs(call.arguments)
        if (malformed) {
          return { block: formatMalformedToolArgsError(call.name, malformed) }
        }
        const snapshot = specSnapshot()
        const specPending = specSubmissionPending(snapshot)
        const block = settlementToolBlock({
          name: call.name,
          settling: isSettling(),
          turnsUsed,
          maxTurns,
          finalTurn: finalTurnForRun(),
          ...(specPending ? { specPending, specDirective: settlementSpecDirective(snapshot.obligationTarget ?? snapshot.route) } : {}),
        })
        if (!block && SPEC_SUBMISSION_TOOLS.has(call.name)) activeProofCallIds.add(call.id)
        return block ? { block } : undefined
      },
      afterTool(call, result) {
        const wasProofCall = activeProofCallIds.delete(call.id)
        const malformed = detectMalformedToolCallArgs(call.arguments)
        const effectiveResult = malformed
          ? (() => {
              const message = formatMalformedToolArgsError(call.name, malformed)
              return {
                ...result,
                isError: true,
                output: [{ type: 'text' as const, text: message }],
                diagnostics: [{ severity: 'error' as const, code: 'malformed_tool_args', message }],
              }
            })()
          : result
        if (trace && !call.parent) {
          const startedAt = toolStartedAt.get(call.id)
          toolStartedAt.delete(call.id)
          try {
            const summary = toolResultSummary(toolResultText(effectiveResult.output))
            const diagnostic = (effectiveResult.diagnostics ?? []).find(item => item.severity === 'error')
            trace.recordToolResult({
              assignmentId: traceAssignmentId,
              turnIdx: Math.max(1, turnsUsed),
              callId: call.id,
              name: call.name,
              durationMs: startedAt === undefined ? null : Date.now() - startedAt,
              ok: !effectiveResult.isError,
              errorCode: diagnostic?.code ?? null,
              summaryJson: summary,
              exchangeIds: idListFrom(summary, ['exchangeIds', 'exchangeId']),
              factIds: idListFrom(summary, ['factIds', 'factId']),
              findingIds: idListFrom(summary, ['findingIds', 'findingId']),
              verifierFeedback: verifierFeedbackFrom(summary),
            })
          } catch {
            // Tracing must never break an investigation run.
          }
        }
        if (wasProofCall && wallClockExpired && activeProofCallIds.size === 0 && !wallClockRotated) {
          queueMicrotask(() => triggerWallClockRotation())
        }
        return malformed ? effectiveResult : undefined
      },
    }),
  ]

  const registry = createRegistry()
  const extensions = []
  if (allTools.length || hooks.length) {
    const extension = defineExtension({
      name: 'kovo-v2-worker',
      tools: allTools,
      hooks,
    })
    registry.install(extension)
    extensions.push(extension)
  }

  const compactionEnabled = options.compaction ?? (maxTurns > 5)
  const reserveTokens = Math.max(16_384, Math.floor(contextWindow * 0.25))
  const keepRecentTokens = Math.min(20_000, Math.max(8_000, Math.floor(contextWindow * 0.18)))
  const backgroundTokens = contextWindow >= 64_000 ? Math.floor(contextWindow * 0.05) : 0

  const context = withAbortSignal(sessionController.signal, BACKGROUND_CONTEXT)
  const makeWallClockRotatedResult = (): AgentSessionResult => {
    const elapsedMs = sessionActiveElapsedMs()
    return finish({
      answer: completion
        ? completion.summary
        : `Bounded wall-clock rotation after ${elapsedMs}ms (${turnsUsed}/${maxTurns} turns); slot released.`,
      turnsUsed,
      settled: true,
      nudgesUsed,
      ...(completion ? { completion } : {}),
      status: 'wall_clock_rotated',
      wallClockRotated: true,
      elapsedMs,
      specSubmissionRequired: specTracker.snapshot().required,
      specSubmission: specTracker.snapshot(),
      ...earlyExitFields(),
    })
  }
  const waitWithWallClockAbort = async <T>(promise: Promise<T>): Promise<{ rotated: true } | { rotated: false; value: T }> => {
    if (wallClockRotated && !options.signal.aborted) {
      void promise.catch(() => undefined)
      return { rotated: true }
    }
    if (options.signal.aborted) {
      void promise.catch(() => undefined)
      throw options.signal.reason ?? new Error('Aborted')
    }
    let onAbort: (() => void) | undefined
    const abortRace = new Promise<{ rotated: true }>((resolve, reject) => {
      onAbort = () => {
        if (wallClockRotated && !options.signal.aborted) {
          resolve({ rotated: true })
        } else if (options.signal.aborted) {
          reject(options.signal.reason ?? new Error('Aborted'))
        }
      }
      sessionController.signal.addEventListener('abort', onAbort, { once: true })
    })
    const wrapped = promise.then(value => ({ rotated: false as const, value }))
    try {
      return await Promise.race([wrapped, abortRace])
    } catch (err) {
      if (wallClockRotated && !options.signal.aborted) return { rotated: true }
      throw err
    } finally {
      if (onAbort) sessionController.signal.removeEventListener('abort', onAbort)
      if (wallClockRotated || sessionController.signal.aborted) void wrapped.catch(() => undefined)
    }
  }
  const harness = await Harness.open(await openNodeSqliteStorage(sessionPath), {
    models,
    registry,
    settings: {
      retry: { enabled: false, maxRetries: 0 },
      stream: {
        transport: 'sse',
        timeoutMs: Math.max(defaultFirstEventTimeoutMs, defaultIdleTimeoutMs),
        maxRetries: 0,
      },
      compaction: compactionEnabled
        ? { enabled: true, reserveTokens, keepRecentTokens, backgroundTokens }
        : { enabled: false },
      toolExecution: 'parallel',
      progress: { partialIntervalMs: 250, persistWithinMs: 350 },
    },
  }, BACKGROUND_CONTEXT)

  try {
    const agent = {
      model: { provider: model.provider, modelId: model.id },
      thinkingLevel: effectiveThinking,
      maxTurns,
      extensions,
      instructions: options.instructions ?? workerSessionInstructions(options.scenario, {
        hasKovoVerify: Boolean(options.handlers?.kovo_verify),
      }),
    }
    const conversation = await harness.root(context, { agent })
    await conversation.configure(agent, context)

    // Arm the session wall-clock timer after SQLite/Harness startup completes so local DB open
    // jitter under heavy concurrency never consumes the worker's active investigation budget.
    options.signal.throwIfAborted()
    sessionClockBaseMs = activeClock.activeElapsedMs()
    if (effectiveWallClockMs !== undefined) {
      armSessionWallClockTimer(effectiveWallClockMs)
    }

    const input = { type: 'input' as const, content: scrubForDisplay(options.prompt) }
    const submission = await conversation.submit({ ...input, requestId: options.requestId }, context)
    const initialWait = await waitWithWallClockAbort(submission.wait(context))
    if (initialWait.rotated) return makeWallClockRotatedResult()
    let result = initialWait.value

    while (result.status === 'unanswered' && (result.reason === 'interrupted' || result.reason === 'aborted')) {
      if (wallClockRotated && !options.signal.aborted) return makeWallClockRotatedResult()
      options.signal.throwIfAborted()
      const requestId = options.requestId + ':resume:' + result.id
      const continuation = result.reason === 'interrupted' || result.type === 'continue'
      const retry = await conversation.submit(
        continuation ? { type: 'continue', requestId } : { ...input, requestId },
        context,
      )
      const retryWait = await waitWithWallClockAbort(retry.wait(context))
      if (retryWait.rotated) return makeWallClockRotatedResult()
      result = retryWait.value
    }

    if (wallClockRotated && !options.signal.aborted) return makeWallClockRotatedResult()

    if (completion) {
      return finish({
        answer: completion.summary,
        turnsUsed,
        settled,
        nudgesUsed,
        completion,
        status: 'completed',
        specSubmissionRequired: specTracker.snapshot().required,
        specSubmission: specTracker.snapshot(),
        ...earlyExitFields(),
      })
    }

    if (result.status === 'unanswered' && result.reason === 'turn_limit') {
      const view = await conversation.context(context)
      const lastText = extractLastAssistantText(view.entries)
      return finish({
        answer: scrubForDisplay(lastText || `Reached maxTurns (${maxTurns}) without calling complete_intent.`),
        turnsUsed,
        settled,
        nudgesUsed,
        status: 'turn_limit',
        specSubmissionRequired: specTracker.snapshot().required,
        specSubmission: specTracker.snapshot(),
        ...earlyExitFields(),
      })
    }

    // Legacy single-turn baseline fallback when derive_evidence is used without complete_intent
    if ((result.status !== 'done' || !result.answer) && handlers.derive_evidence && !requireCompleteIntent) {
      const view = await conversation.context(context)
      const toolResults = view.entries.flatMap(item => item.model ?? []).filter(msg => msg.role === 'toolResult')
      if (toolResults.some(msg => !msg.isError)) {
        return finish({
          answer: 'The model reached its output limit after recording the evidence command result.',
          turnsUsed,
          settled,
          nudgesUsed,
          status: 'completed',
        })
      }
      if (toolResults.length) {
        options.signal.throwIfAborted()
        await handlers.derive_evidence(
          { command: 'jq -c . /evidence/observed.json > /work/result.txt && cat /work/result.txt' },
          options.signal,
        )
        return finish({
          answer: 'The model did not provide a usable evidence command. Kovo Hunter recorded the standard observation extraction.',
          turnsUsed,
          settled,
          nudgesUsed,
          status: 'completed',
        })
      }
    }

    if (result.status !== 'done' || !result.answer) {
      throw new Error(`The model did not finish the requested turn (${result.status === 'unanswered' ? result.reason : 'unknown'}).`)
    }

    const view = await conversation.context(context, { at: result.answer })
    const entryMessages = view.entries.find(item => item.id === result.answer)?.model ?? []
    const assistant = entryMessages.filter(msg => msg.role === 'assistant')
    const usedTool = view.entries.some(item => item.model?.some(msg => msg.role === 'toolResult' && !msg.isError))

    if (handlers.derive_evidence && !requireCompleteIntent && assistant.some(msg => msg.stopReason === 'length')) {
      if (!usedTool) {
        const command = options.scenario === 'response-analysis'
          ? 'jq -c . /evidence/observed.json > /work/result.txt'
          : fallbackCommand
        await handlers.derive_evidence({ command }, options.signal)
      }
      return finish({
        answer: 'The model reached its output limit. The worker used the recorded response metadata for the evidence check.',
        turnsUsed,
        settled,
        nudgesUsed,
        status: 'completed',
      })
    }

    const answer = assistant
      .flatMap(msg => msg.content.filter(part => part.type === 'text').map(part => part.text))
      .join('\n')
      .trim()

    if (!answer) {
      if (handlers.derive_evidence && usedTool) {
        return finish({
          answer: 'The worker recorded its analysis of the supplied response metadata.',
          turnsUsed,
          settled,
          nudgesUsed,
          status: 'completed',
        })
      }
      throw new Error('The model returned an empty response.')
    }

    return finish({
      answer: scrubForDisplay(answer),
      turnsUsed,
      settled,
      nudgesUsed,
      status: requireCompleteIntent && !completion ? 'nudged_out' : 'completed',
      ...earlyExitFields(),
    })
  } catch (err) {
    if (wallClockRotated && !options.signal.aborted) return makeWallClockRotatedResult()
    throw err
  } finally {
    clearWallClockTimers()
    if (ownedClock) activeClock.dispose()
    options.signal.removeEventListener('abort', onParentAbort)
    const closePromise = harness.close(BACKGROUND_CONTEXT).catch(() => undefined)
    if (wallClockRotated || sessionController.signal.aborted) {
      let closeTimer: NodeJS.Timeout | undefined
      await Promise.race([
        closePromise,
        new Promise<void>(resolve => {
          closeTimer = setTimeout(resolve, 150)
          closeTimer.unref?.()
        }),
      ])
      if (closeTimer) clearTimeout(closeTimer)
    } else {
      await closePromise
    }
  }
}

function extractLastAssistantText(entries: readonly { model?: readonly { role: string; content?: unknown }[] }[]): string {
  for (let i = entries.length - 1; i >= 0; i--) {
    const msgs = entries[i].model ?? []
    for (let j = msgs.length - 1; j >= 0; j--) {
      const msg = msgs[j]
      if (msg.role !== 'assistant' || !Array.isArray(msg.content)) continue
      const text = msg.content
        .filter((part): part is { type: 'text'; text: string } =>
          Boolean(part && typeof part === 'object' && (part as { type?: string }).type === 'text' && typeof (part as { text?: unknown }).text === 'string'))
        .map(part => part.text)
        .join('\n')
        .trim()
      if (text) return text
    }
  }
  return ''
}

// ---------------------------------------------------------------------------
// Backward-Ergonomic Single/Few-Turn Wrapper (`agentTurn`)
// ---------------------------------------------------------------------------

export interface AgentTurnJob {
  directory: string
  sessionId: string
  requestId: string
  settings?: ProviderConfig
  profiles?: readonly ResolvedModelProfile[]
  scenario: AgentScenario
  prompt: string
  instructions?: string
  signal: AbortSignal
  maxTurns?: number
  thinkingLevel?: ThinkingLevel
  roleAffinity?: RoleAffinity
  secrets?: SecretSource
  derive?: (command: string, signal: AbortSignal) => Promise<string>
  handlers?: WorkerToolHandlers
  record?: CallRecorder
  beforeCall?: () => void
  onUsage?: UsageCallback
  onProfileSuccess?: (profileId: string) => void
  onProfileFailure?: (profileId: string, err: string, hard: boolean) => void
}

export async function agentTurn(job: AgentTurnJob): Promise<string> {
  const handlers: WorkerToolHandlers = {
    ...(job.handlers ?? {}),
    ...(job.derive
      ? {
          derive_evidence: async ({ command }, signal) => job.derive!(command, signal),
        }
      : {}),
  }
  const hasHandlers = Object.keys(handlers).length > 0
  const defaultOffScenarios = new Set<AgentScenario>(['coordinator', 'coordinator-plan', 'worker-analysis', 'response-analysis'])
  const session = await runAgentSession({
    directory: job.directory,
    sessionId: job.sessionId,
    requestId: job.requestId,
    settings: job.settings,
    profiles: job.profiles,
    scenario: job.scenario,
    prompt: job.prompt,
    instructions: job.instructions,
    signal: job.signal,
    maxTurns: job.maxTurns,
    thinkingLevel: job.thinkingLevel ?? (defaultOffScenarios.has(job.scenario) ? 'off' : undefined),
    roleAffinity: job.roleAffinity,
    compaction: false,
    enableSettlement: false,
    requireCompleteIntent: false,
    handlers: hasHandlers ? handlers : undefined,
    secrets: job.secrets,
    record: job.record,
    beforeCall: job.beforeCall,
    onUsage: job.onUsage,
    onProfileSuccess: job.onProfileSuccess,
    onProfileFailure: job.onProfileFailure,
  })
  return session.answer.slice(0, 16_000)
}

export { listSkills, listSkillTags, loadSkill, searchSkills, skillsByTag, selectPreInjectionSkills }
