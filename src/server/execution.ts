import { createHash, randomUUID } from 'node:crypto'
import { existsSync, readdirSync, readFileSync, statSync } from 'node:fs'
import { extname, join, relative, sep } from 'node:path'
import { and, asc, eq } from 'drizzle-orm'
import { z } from 'zod'
import type { AccessPolicySnapshot } from '../access-policy.ts'
import {
  assetOrigin,
  assetOriginForEnvironment,
  defaultWorkerConcurrency,
  isLocalLabEnvEnabled,
  maxInlineVerifyRetries,
  maxWorkerConcurrency,
  owaspCategories,
  parseBoardMentions,
  responseCheckIds,
  specialistHandleByProfile,
  specialistProfileByHandle,
  workerHistory,
} from '../domain.ts'
import type {
  AssessmentCheckId,
  BoardAuthorRole,
  BoardMessageKind,
  Candidate,
  CheckCoverage,
  CodeLocation,
  Finding,
  InlineVerifyFeedback,
  OwaspCategory,
  ResponseCheckId,
  ThreatModelSummary,
  VerificationTier,
} from '../domain.ts'
import { declarativeReplaySpecSchema, replaySpecOrigins } from '../replay-spec.ts'
import type { DeclarativeReplaySpec } from '../replay-spec.ts'
import { suppliedResponseLabel } from '../report-summary.ts'
import { accessPolicyReviews } from './access-policy-checks.ts'
import { evaluateTier3Approval, isLocalLabAutoApprovalOrigin, matchesApprovedEndpointPattern } from './approval-judge.ts'
import {
  agentTurn,
  buildBoardDelta,
  chainPlannerPrompt,
  classifyHostTier,
  codeAuditPrompt,
  coordinatorPrompt,
  createBoardTools,
  crossHostSynthesizerPrompt,
  defaultCodeAuditMaxTurns,
  filterHandlersForSpecialist,
  injectBoardTurnInstructions,
  listSkills,
  loadSkill,
  resolveSpecialistProfile,
  routeStepToSpecialist,
  selectPreInjectionSkills,
  runAgentSession,
  threatModelPrompt,
  WarmSpecialistController,
  workerInvestigationPrompt,
} from './agent-session.ts'
import type {
  CodeAuditSuspectData,
  HostTier,
  PersonaResourceQueueItem,
  RequestHttpArgs,
  RequestHttpRaceArgs,
  WorkerToolHandlers,
} from './agent-session.ts'
import {
  BrokerApprovalRequired,
  BrokerCircuitOpen,
  BrokerDenied,
  RequestBroker,
  websocketResultToExchange,
} from './broker.ts'
import type { BrokerExchangeResult, Grant, PublicObservation } from './broker.ts'
import { CanaryBroker, scanSecondOrderMarkers } from './canary-broker.ts'
import type { SecondOrderStore } from './canary-broker.ts'
import { ColdGraphCompactor } from './compactor.ts'
import { hasCuratedAdvisory, queryCves, templateIdsForCves } from './cve-broker.ts'
import {
  checkStructuralDuplicate,
  createProviderLlmCall,
  evaluateSubmissionDedupe,
  extractSpecDedupeFields,
  normalizeEndpointTemplate,
} from './dedupe.ts'
import type { ExistingFindingRef } from './dedupe.ts'
import { checkCoverage, meetsBaseline, readComparisons, verificationCommand } from './evidence-checks.ts'
import type { EvidenceReview } from './evidence-checks.ts'
import { listMountedRepos, parseDependenciesFromFile, projectReposDir } from './github-connector.ts'
import { LabRunner } from './lab-runner.ts'
import type { LabTargetHandle } from './lab-runner.ts'
import {
  privateModelProfiles,
  recordProfileFailure,
  recordProfileSuccess,
  resolveProfilePoolForRole,
} from './model-settings.ts'
import type { ResolvedModelProfile } from './model-settings.ts'
import { generateAndReviewPatch } from './patch-workflow.ts'
import { PersonaAuthManager } from './persona-auth.ts'
import { personaSecrets, resolveRunPersonas } from './persona-vault.ts'
import { crawlStateGraph, runPhase0Recon } from './phase0-recon.ts'
import { BudgetExceededError } from './provider.ts'
import { redact, redactJsonValue } from './redact.ts'
import type { NamedSecret } from './redact.ts'
import {
  buildInlineVerifyFeedback,
  retestReplaySpec,
  verifyReplaySpec,
  verifyReplaySpecInline,
} from './replay-verifier.ts'
import { responseReview } from './response-checks.ts'
import { availableReviewChecks, parseReviewPlan, reviewPlanPrompt, standardChecks } from './review-plan.ts'
import { approvalRequests, findings, messages, replaySpecs } from './schema.ts'
import { ScopedBrowser } from './scoped-browser.ts'
import { dedupeCodeAuditSuspects, runThreeStageSemanticAudit, runVariantSweepForFinding, toChainStepInputs } from './semantic-audit.ts'
import { assessmentAssignments, extractResourceRefsFromExchange, isOpaqueResourceId, store } from './store.ts'
import type {
  Assignment,
  BoardMessageRow,
  ChainStep,
  ExtractedResourceRef,
  Fact,
  PatchProposal,
  ReplaySpecRow,
  ResourceHarvestExchange,
  ResourceSampleRow,
  Run,
  Store,
} from './store.ts'
import { probeDifferential, probeSurface, runSafeTemplates } from './surface-engine.ts'
import { LinuxWorkerBackend } from './worker-backend.ts'
import type { WorkerBackend } from './worker-backend.ts'

type Active = {
  assignment: Assignment
  origins: Set<string>
  controller: AbortController
}

type Capture = { observation: PublicObservation | null; note: string }
type ReviewInput = { artifactId?: string; reviews: EvidenceReview[]; policy?: AccessPolicySnapshot }
type CoordinatorTask = { controller: AbortController; goalRevision: number; scopeRevision?: number }

const hardChainStepsCeiling = 300
const diminishingReturnsDryThreshold = 6
const plannerDebounceMs = 1_200
const intentLeaseMs = 30 * 60_000
/** Hard cap on bounded Phase-3 reasoning refinements per run (M1.5). */
const maxPhase3RefinementJobs = 10

export function computeDynamicStepBudget(storage: Store, runId: string): number {
  const endpoints = storage.listEndpoints(runId)
  const crownJewels = endpoints.filter(e => e.riskScore >= 80).length
  const suspects = storage.listFacts(runId, { includeTainted: false, kind: 'code_audit_suspect', limit: 500 }).length
  return Math.max(24, Math.min(200, crownJewels * 2 + suspects))
}

export function computeMultiTrialFanout(
  run: Pick<Run, 'multiTrialEnabled' | 'workerConcurrency'>,
  step: Pick<ChainStep, 'priority' | 'dependsOnFactIds' | 'trialGroupId'>,
  highSignalFactIds?: ReadonlySet<string>,
): number {
  if (step.trialGroupId) return 1
  if (run.multiTrialEnabled === false) return 1
  const concurrencyCap = Math.max(1, run.workerConcurrency || defaultWorkerConcurrency)
  const linkedHighSignal = step.dependsOnFactIds.some(id => highSignalFactIds?.has(id))
  if (step.priority >= 96) return Math.min(3, concurrencyCap)
  if (step.priority >= 88 || linkedHighSignal) return Math.min(2, concurrencyCap)
  return 1
}

export function countConsecutiveDrySteps(storage: Store, run: Pick<Run, 'id' | 'goalRevision'>): number {
  const completedSteps = storage.listChainSteps(run.id, run.goalRevision)
    .filter(s => s.status === 'complete')
    .sort((a, b) => b.updatedAt - a.updatedAt || b.seq - a.seq)
  if (completedSteps.length === 0) return 0

  const productiveWorkerIds = new Set<string>()
  const runFacts = storage.listFacts(run.id, { includeTainted: false, limit: 500 })
  for (const f of runFacts) {
    if (f.assignmentId) productiveWorkerIds.add(f.assignmentId)
  }
  const runFindings = storage.db.select().from(findings).where(and(
    eq(findings.runId, run.id),
    eq(findings.goalRevision, run.goalRevision),
  )).all()
  const runSpecs = storage.listReplaySpecs(run.id)
  for (const sp of runSpecs) {
    if (runFindings.some(f => f.id === sp.findingId && f.finding.status !== 'dismissed')) {
      if (sp.assignmentId) productiveWorkerIds.add(sp.assignmentId)
    }
  }

  let dry = 0
  for (const st of completedSteps) {
    if (!st.assignedWorkerId || !productiveWorkerIds.has(st.assignedWorkerId)) {
      dry += 1
    } else {
      break
    }
  }
  return dry
}

const threatModelResponseSchema = z.object({
  summary: z.string().min(1).max(2000),
  entries: z.array(z.object({
    origin: z.string(),
    riskTier: z.enum(['critical', 'high', 'medium', 'low']),
    hostTier: z.enum(['crown_jewel', 'standard', 'low_value_static']).optional(),
    surfaceTags: z.array(z.string()).default([]),
    rationale: z.string().min(1).max(500),
  })),
  initialSteps: z.array(z.object({
    title: z.string().min(1).max(200),
    hypothesis: z.string().min(1).max(1200),
    category: z.string().default('misconfig-exposure'),
    priority: z.number().min(0).max(100).default(70),
    origins: z.array(z.string()).min(1),
    skills: z.array(z.string()).default([]),
  })).default([]),
})

const plannerResponseSchema = z.object({
  summary: z.string().default(''),
  newSteps: z.array(z.object({
    title: z.string().min(1).max(200),
    hypothesis: z.string().min(1).max(1200),
    category: z.string().default('misconfig-exposure'),
    priority: z.number().min(0).max(100).default(60),
    origins: z.array(z.string()).min(1),
    skills: z.array(z.string()).default([]),
    dependsOnFactIds: z.array(z.string()).default([]),
    dependsOnStepIds: z.array(z.string()).default([]),
  })).default([]),
  cancelStepIds: z.array(z.string()).default([]),
  done: z.boolean().default(false),
})

const crossHostSynthesizerResponseSchema = z.object({
  summary: z.string().default(''),
  hypotheses: z.array(z.object({
    title: z.string().min(1).max(200),
    sourceOrigins: z.array(z.string()).default([]),
    factIds: z.array(z.string()).default([]),
    primitiveA: z.string().default(''),
    primitiveB: z.string().default(''),
    combinedImpact: z.string().default(''),
    severity: z.enum(['critical', 'high', 'medium', 'low', 'informational']).default('high'),
    recommendedReplayKind: z.string().optional(),
  })).default([]),
  chainSteps: z.array(z.object({
    title: z.string().min(1).max(200),
    hypothesis: z.string().min(1).max(1200),
    category: z.string().default('cors-client-side'),
    priority: z.number().min(0).max(100).default(85),
    origins: z.array(z.string()).min(1),
    skills: z.array(z.string()).default(['cross-host-chaining']),
    dependsOnFactIds: z.array(z.string()).default([]),
  })).default([]),
})

export function derivedResult(result: { exitStatus: number; result: string; stdout: string }) {
  return JSON.stringify({ exitStatus: result.exitStatus, result: (result.result || result.stdout).slice(0, 1200) })
}

function stripJsonFences(raw: string): string {
  const trimmed = raw.trim()
  const fenced = /^```(?:json)?\s*([\s\S]*?)\s*```$/i.exec(trimmed)
  if (fenced) return fenced[1].trim()
  const start = trimmed.indexOf('{')
  const end = trimmed.lastIndexOf('}')
  if (start >= 0 && end > start) return trimmed.slice(start, end + 1)
  return trimmed
}

const hostTierOrder: Record<HostTier, number> = {
  crown_jewel: 0,
  standard: 1,
  low_value_static: 2,
}

function classifyHostHeuristic(asset: Candidate): ThreatModelSummary {
  const host = new URL(asset.origin).hostname.toLowerCase()
  const tags: string[] = []
  let riskTier: ThreatModelSummary['riskTier'] = 'medium'

  if (/(?:auth|login|sso|oauth|clerk|account|accounts|academy|id|identity)/.test(host)) { tags.push('auth'); riskTier = 'critical' }
  if (/(?:api|graphql|trpc|gateway|backend|cloud|app|dash|admin|portal)/.test(host)) { tags.push('api'); riskTier = riskTier === 'critical' ? 'critical' : 'high' }
  if (/(?:upload|media|file|storage|cdn|asset|bucket|blob)/.test(host)) { tags.push('upload'); riskTier = riskTier === 'medium' ? 'high' : riskTier }
  if (/(?:billing|pay|stripe|checkout|webhook|hook)/.test(host)) { tags.push('billing'); riskTier = 'critical' }
  if (/(?:llm|ai|chat|engine|model|prompt|agent|proxy)/.test(host)) { tags.push('llm-proxy'); riskTier = 'critical' }
  if (/(?:dev|stage|staging|debug|test|beta|preview|sandbox|sandpack|internal|bundler)/.test(host)) { tags.push('staging-debug'); riskTier = 'high' }
  if (asset.dnsSource?.externalAliases?.length) { tags.push('external-cname') }
  if (/(?:blog|docs|marketing|www|status|landing|static)/.test(host) && !tags.length) { tags.push('static'); riskTier = 'low' }
  if (!tags.length) tags.push('web')

  const hostTier = classifyHostTier(asset.origin, tags)
  if (hostTier === 'crown_jewel' && !tags.includes('crown_jewel')) tags.unshift('crown_jewel')
  if (hostTier === 'low_value_static' && !tags.includes('low_value_static')) tags.push('low_value_static')

  return {
    origin: asset.origin,
    riskTier,
    surfaceTags: tags,
    rationale: `Heuristic surface ranking for ${host} (${hostTier}; ${tags.join(', ')}).`,
  }
}

export function computeHostTiers(
  approvedOrigins: readonly string[],
  threatModel?: readonly ThreatModelSummary[],
): Record<string, HostTier> {
  const map: Record<string, HostTier> = {}
  for (const origin of approvedOrigins) {
    const entry = threatModel?.find(e => e.origin === origin)
    map[origin] = classifyHostTier(origin, entry?.surfaceTags)
  }
  return map
}

export function computeStepMaxTurns(
  stepOrigins: readonly string[],
  hostTiers: Record<string, HostTier>,
  baseMaxTurns: number,
): number {
  const hasCrownJewel = Object.values(hostTiers).some(t => t === 'crown_jewel')
  if (!hasCrownJewel || !stepOrigins.length) return baseMaxTurns
  const allLowValueStatic = stepOrigins.every(o => (hostTiers[o] ?? classifyHostTier(o)) === 'low_value_static')
  if (!allLowValueStatic) return baseMaxTurns
  return Math.max(4, Math.min(baseMaxTurns, 15, Math.floor(baseMaxTurns * 0.2)))
}

export function applyCrownJewelStepBudget<T extends { title: string; priority: number; origins: string[] }>(
  candidates: readonly T[],
  hostTiers: Record<string, HostTier>,
  existingSteps: readonly Pick<ChainStep, 'title' | 'sourceOrigins' | 'status'>[],
  maxNewSteps: number,
): T[] {
  if (maxNewSteps <= 0 || !candidates.length) return []
  const hasCrownJewel = Object.values(hostTiers).some(t => t === 'crown_jewel')
  const existingTitles = new Set(existingSteps.map(s => s.title.trim().toLowerCase()))

  const isPureStatic = (origins: readonly string[]) =>
    origins.length > 0 && origins.every(o => (hostTiers[o] ?? classifyHostTier(o)) === 'low_value_static')
  const hasCrownOrigin = (origins: readonly string[]) =>
    origins.some(o => (hostTiers[o] ?? classifyHostTier(o)) === 'crown_jewel')

  const staticStepsByOrigin = new Map<string, number>()
  let existingActiveSteps = 0
  let existingStaticSteps = 0
  for (const step of existingSteps) {
    if (step.status === 'canceled' || step.status === 'tainted') continue
    existingActiveSteps += 1
    if (isPureStatic(step.sourceOrigins)) {
      existingStaticSteps += 1
      for (const o of step.sourceOrigins) {
        staticStepsByOrigin.set(o, (staticStepsByOrigin.get(o) ?? 0) + 1)
      }
    }
  }

  const normalized = candidates
    .filter(step => step.origins.length > 0 && !existingTitles.has(step.title.trim().toLowerCase()))
    .map(step => {
      if (!hasCrownJewel) return { ...step }
      if (isPureStatic(step.origins)) {
        return { ...step, priority: Math.min(step.priority, 35) }
      }
      if (hasCrownOrigin(step.origins)) {
        return { ...step, priority: Math.min(100, Math.max(75, step.priority + 10)) }
      }
      return { ...step }
    })

  // Sort crown-jewel first, then standard, then low-value static; tie-break by priority descending
  normalized.sort((a, b) => {
    const tierA = hasCrownOrigin(a.origins) ? 0 : isPureStatic(a.origins) ? 2 : 1
    const tierB = hasCrownOrigin(b.origins) ? 0 : isPureStatic(b.origins) ? 2 : 1
    return tierA - tierB || b.priority - a.priority
  })

  if (!hasCrownJewel) {
    const out: T[] = []
    const seenTitles = new Set(existingTitles)
    for (const step of normalized) {
      if (out.length >= maxNewSteps) break
      const key = step.title.trim().toLowerCase()
      if (seenTitles.has(key)) continue
      seenTitles.add(key)
      out.push(step)
    }
    return out
  }

  const crownOrStandardPool = normalized.filter(s => !isPureStatic(s.origins))
  const staticPool = normalized.filter(s => isPureStatic(s.origins))

  const selected: T[] = []
  const seenTitles = new Set(existingTitles)

  // Target ~80% crown-jewel/standard allocation when crown-jewel hosts are present
  const projectedTotal = existingActiveSteps + Math.min(maxNewSteps, normalized.length)
  const maxTotalStaticSteps = Math.max(1, Math.floor(projectedTotal * 0.2))
  const crownTargetSlots = crownOrStandardPool.length > 0
    ? Math.max(1, Math.ceil(maxNewSteps * 0.8))
    : 0

  for (const step of crownOrStandardPool) {
    if (selected.length >= maxNewSteps) break
    const key = step.title.trim().toLowerCase()
    if (seenTitles.has(key)) continue
    seenTitles.add(key)
    selected.push(step)
  }

  let staticAdded = 0
  for (const step of staticPool) {
    if (selected.length >= maxNewSteps) break
    // Cap static marketing hosts to 1 fast step per origin and <= ~20% overall share
    if (existingStaticSteps + staticAdded >= maxTotalStaticSteps) break
    if (step.origins.some(o => (staticStepsByOrigin.get(o) ?? 0) >= 1)) continue
    // Ensure we don't crowd out reserved crown-jewel capacity
    if (crownTargetSlots > 0 && selected.length < maxNewSteps && staticAdded >= Math.max(1, maxNewSteps - crownTargetSlots) && crownOrStandardPool.length >= crownTargetSlots) {
      break
    }
    const key = step.title.trim().toLowerCase()
    if (seenTitles.has(key)) continue
    seenTitles.add(key)
    selected.push(step)
    staticAdded += 1
    for (const o of step.origins) {
      staticStepsByOrigin.set(o, (staticStepsByOrigin.get(o) ?? 0) + 1)
    }
  }

  return selected
}

function sinkCategoryAndSkills(sinkKind: string): { category: OwaspCategory; skills: string[] } {
  switch (sinkKind) {
    case 'server_action':
    case 'api_route':
      return { category: 'broken-access-control', skills: ['source-first-audit', 'bola-idor-race', 'false-positive-elimination'] }
    case 'webhook':
    case 'auth_config':
      return { category: 'auth-identity', skills: ['source-first-audit', 'false-positive-elimination'] }
    case 'outbound_fetch':
    case 'redirect':
      return { category: 'ssrf-redirects', skills: ['source-first-audit', 'oob-ssrf-browser-chain', 'false-positive-elimination'] }
    case 'postmessage_iframe':
      return { category: 'cors-client-side', skills: ['cross-host-chaining', 'oob-ssrf-browser-chain'] }
    case 'upload_storage':
      return { category: 'upload-storage', skills: ['source-first-audit', 'false-positive-elimination'] }
    case 'db_query':
      return { category: 'injection-input', skills: ['source-first-audit', 'false-positive-elimination'] }
    default:
      return { category: 'broken-access-control', skills: ['source-first-audit', 'false-positive-elimination'] }
  }
}

export function convertCodeAuditSuspectsToChainSteps(
  storage: Store,
  run: Run,
  suspects: readonly Fact[],
  hostTiers?: Record<string, HostTier>,
): ChainStep[] {
  const approvedOrigins = new Set(run.candidates.filter(c => run.approved.includes(c.id)).map(c => c.origin))
  const existingSteps = storage.listChainSteps(run.id, run.goalRevision)
  const existingTitles = new Set(existingSteps.map(s => s.title.trim().toLowerCase()))
  const coveredFactIds = new Set(existingSteps.flatMap(s => s.dependsOnFactIds))
  const created: ChainStep[] = []
  let totalSteps = existingSteps.length

  for (const fact of dedupeCodeAuditSuspects(suspects)) {
    if (totalSteps >= hardChainStepsCeiling) break
    if (fact.tainted || !approvedOrigins.has(fact.origin)) continue
    if (coveredFactIds.has(fact.id)) continue
    const asset = run.candidates.find(c => c.origin === fact.origin && run.approved.includes(c.id))
    if (!asset) continue

    const data = fact.data as Partial<CodeAuditSuspectData> & Record<string, unknown>
    const routeOrAction = typeof data.routeOrAction === 'string' && data.routeOrAction.trim()
      ? data.routeOrAction.trim()
      : ''
    const endpointHint = typeof data.endpoint === 'string' && data.endpoint.trim()
      ? data.endpoint.trim()
      : routeOrAction
    const fileLoc = typeof data.file === 'string' && data.file.trim()
      ? `${data.file.trim()}${typeof data.line === 'number' ? `:${data.line}` : ''}`
      : ''
    const sinkKind = typeof data.sinkKind === 'string' ? data.sinkKind : 'api_route'
    const authCheck = typeof data.authCheck === 'string' ? data.authCheck : 'unknown'
    const ownershipCheck = typeof data.ownershipCheck === 'string' ? data.ownershipCheck : 'unknown'
    const hypothesisBody = typeof data.hypothesis === 'string' && data.hypothesis.trim()
      ? data.hypothesis.trim()
      : fact.summary

    const host = new URL(fact.origin).hostname
    const title = routeOrAction
      ? `Source audit verify · ${routeOrAction.slice(0, 90)} (${host})`
      : `Source audit verify · ${fact.summary.slice(0, 80)} (${host})`
    if (existingTitles.has(title.toLowerCase())) continue

    const mapped = sinkCategoryAndSkills(sinkKind)
    const explicitCategory = typeof data.category === 'string' && data.category.trim()
      ? data.category.trim()
      : mapped.category
    const specialistProfile = routeStepToSpecialist({
      title: `${fact.summary} ${title}`,
      hypothesis: hypothesisBody,
      category: explicitCategory,
      skills: mapped.skills,
      endpoint: endpointHint,
      sinkKind,
    })
    const missingAuthOrOwner = /missing|none|weak|bypass|absent|unverified|no /i.test(`${authCheck} ${ownershipCheck}`)
    const isCrown = (hostTiers?.[fact.origin] ?? classifyHostTier(fact.origin)) === 'crown_jewel'
    const priority = missingAuthOrOwner ? (isCrown ? 96 : 92) : (isCrown ? 90 : 85)

    const hypothesis = [
      `Source-First Code Audit suspect${fileLoc ? ` at ${fileLoc}` : ''}${endpointHint ? ` targeting ${endpointHint}` : ''}.`,
      `Auth check: ${authCheck}; Ownership check: ${ownershipCheck}; Sink: ${sinkKind}.`,
      hypothesisBody,
      'Verify live reachability with negative control + differential probe (and cross-persona BOLA check if Tier >= 2) and submit a DeclarativeReplaySpec if confirmed.',
    ].join(' ')

    const step = storage.addChainStep(run, {
      title,
      hypothesis,
      category: explicitCategory,
      priority,
      targetAssetIds: [asset.id],
      skills: mapped.skills,
      dependsOnFactIds: [fact.id],
      sourceOrigins: [fact.origin],
      specialistProfile,
    })
    existingTitles.add(title.toLowerCase())
    coveredFactIds.add(fact.id)
    created.push(step)
    totalSteps += 1
  }

  return created
}

export interface BolaConsumerVariant {
  method: 'GET' | 'PUT' | 'PATCH' | 'DELETE'
  endpoint: string
  /** Reversible write variants are benign; DELETE is only replayable at Tier 3 / local-lab. */
  destructive: boolean
  requiresTier: 1 | 2 | 3
}

export interface BolaTestQueueItem extends PersonaResourceQueueItem {
  resourceKey: string
  variants: BolaConsumerVariant[]
  source: 'fact' | 'sample'
}

/** Backwards-compatible re-export: harvesting lives in `store.ts` so Phase-0/crawl can share it. */
export function extractPersonaResourcesFromExchange(ex: ResourceHarvestExchange): ExtractedResourceRef[] {
  return extractResourceRefsFromExchange(ex)
}

/**
 * Instantiate consumer item endpoints (`GET/PUT/PATCH/DELETE /…/:resourceId`) from a producer path.
 * Observed concrete item URLs are preserved; collection URLs get the harvested id appended.
 */
export function instantiateConsumerEndpoints(
  endpoint: string,
  resourceId: string,
  method = 'GET',
): BolaConsumerVariant[] {
  const bare = (endpoint.split('?')[0] || '/').replace(/\/+$/, '') || '/'
  let itemEndpoint = bare
  const last = bare.split('/').filter(Boolean).at(-1) ?? ''
  if (!/:[A-Za-z_][A-Za-z0-9_-]*|\{[A-Za-z0-9_-]+\}|\[[A-Za-z0-9_-]+\]/.test(bare)) {
    if (!isOpaqueResourceId(last)) {
      itemEndpoint = `${bare === '/' ? '' : bare}/${encodeURIComponent(resourceId)}`
    }
  } else {
    itemEndpoint = bare.replace(
      /:[A-Za-z_][A-Za-z0-9_-]*|\{[A-Za-z0-9_-]+\}|\[[A-Za-z0-9_-]+\]/,
      encodeURIComponent(resourceId),
    )
  }
  const itemTemplate = normalizeEndpointTemplate(itemEndpoint)
  const hasPlaceholder = /:[A-Za-z_][A-Za-z0-9_-]*/.test(itemTemplate)
  const concrete = hasPlaceholder
    ? itemTemplate.replace(/:[A-Za-z_][A-Za-z0-9_-]*/, encodeURIComponent(resourceId))
    : itemEndpoint
  const methods: Array<BolaConsumerVariant['method']> = ['GET', 'PUT', 'PATCH', 'DELETE']
  const variants = methods.map(variant => ({
    method: variant,
    endpoint: concrete,
    destructive: variant === 'DELETE',
    requiresTier: (variant === 'DELETE' ? 3 : variant === 'GET' ? 2 : 2) as 1 | 2 | 3,
  }))
  // Keep the original method first so existing single-method consumers remain deterministic.
  const requested = method.toUpperCase()
  return variants.sort((a, b) => Number(b.method === requested) - Number(a.method === requested))
}

function testPersonasForOwner(
  ownerPersona: string,
  origin: string,
  personas: readonly { handle: string; originAllowlist: readonly string[] }[],
): string[] {
  const eligible = personas
    .filter(p => p.originAllowlist.includes(origin))
    .map(p => p.handle)
  if (ownerPersona === 'anonymous') return [...new Set(eligible)]
  return [...new Set([...eligible.filter(handle => handle !== ownerPersona), 'anonymous'])]
}

export function buildBolaTestQueue(
  facts: readonly Fact[],
  personas: readonly { handle: string; originAllowlist: readonly string[] }[],
  approvedOrigins: ReadonlySet<string>,
  samples: readonly ResourceSampleRow[] = [],
): BolaTestQueueItem[] {
  if (personas.length < 2) return []
  const queue: BolaTestQueueItem[] = []
  const seen = new Set<string>()
  const perTypeCount = new Map<string, number>()
  const perTypeBudget = 8
  const overallBudget = 80
  const enqueue = (item: Omit<BolaTestQueueItem, 'variants' | 'testAsPersonas'>) => {
    if (queue.length >= overallBudget) return
    const key = `${item.origin}|${item.ownerPersona}|${item.endpoint}|${item.resourceId}|${item.method ?? 'GET'}`
    if (seen.has(key)) return
    const typeKey = `${item.origin}|${item.resourceKey}`
    const used = perTypeCount.get(typeKey) ?? 0
    if (used >= perTypeBudget) return
    if (!item.resourceId || item.resourceId === '[redacted]') return
    const testAsPersonas = testPersonasForOwner(item.ownerPersona, item.origin, personas)
    if (!testAsPersonas.length) return
    seen.add(key)
    perTypeCount.set(typeKey, used + 1)
    queue.push({
      ...item,
      testAsPersonas,
      variants: instantiateConsumerEndpoints(item.endpoint, item.resourceId, item.method ?? 'GET'),
    })
  }

  for (const fact of facts) {
    if (fact.tainted || !approvedOrigins.has(fact.origin)) continue
    const subkind = typeof fact.data?.subkind === 'string' ? fact.data.subkind : ''
    if (subkind !== 'persona_resource' && fact.kind !== 'object_ref') continue

    const data = fact.data ?? {}
    const ownerPersona = typeof data.ownerPersona === 'string' ? data.ownerPersona
      : typeof data.persona === 'string' ? data.persona
        : typeof data.personaHandle === 'string' ? data.personaHandle : ''
    const resourceId = typeof data.resourceId === 'string' ? data.resourceId
      : typeof data.id === 'string' ? data.id
        : typeof data.resourceId === 'number' ? String(data.resourceId) : ''
    const endpoint = typeof data.endpoint === 'string' ? data.endpoint
      : typeof data.path === 'string' ? data.path
        : typeof data.pathAndQuery === 'string' ? data.pathAndQuery : ''
    if (!ownerPersona || !resourceId || !endpoint) continue
    const method = typeof data.method === 'string' ? data.method.toUpperCase() : 'GET'
    const resourceKey = typeof data.field === 'string' ? data.field.replace(/^path:/, '') : 'id'
    enqueue({
      factId: fact.id,
      origin: fact.origin,
      ownerPersona,
      resourceKey,
      resourceId,
      endpoint,
      method,
      summary: fact.summary,
      source: 'fact',
    })
  }

  for (const sample of samples) {
    if (!approvedOrigins.has(sample.origin)) continue
    enqueue({
      origin: sample.origin,
      ownerPersona: sample.ownerPersona,
      resourceKey: sample.resourceKey,
      resourceId: sample.resourceId,
      endpoint: sample.endpoint,
      method: sample.method,
      summary: `${sample.authenticated ? 'Authenticated' : 'Unauthenticated'} sample ${sample.resourceKey}=${sample.resourceId} observed at ${sample.method} ${sample.endpoint}.`,
      source: 'sample',
    })
  }

  // Prioritize authenticated owners and higher-risk item routes deterministically.
  return queue.sort((a, b) =>
    Number(b.ownerPersona !== 'anonymous') - Number(a.ownerPersona !== 'anonymous') ||
    Number(/:(?:id|uuid)|[0-9]{1,}/i.test(b.endpoint)) - Number(/:(?:id|uuid)|[0-9]{1,}/i.test(a.endpoint)) ||
    a.resourceKey.localeCompare(b.resourceKey),
  ).slice(0, overallBudget)
}

const CROSS_HOST_LEVERAGE_PATTERNS: ReadonlyArray<{ label: string; kindMatch?: string[]; pattern: RegExp }> = [
  { label: 'credentialed-cors-or-wildcard', kindMatch: ['cors'], pattern: /access-control-allow-credentials|wildcard|allow-origin|reflected origin|cors|subdomain trust/i },
  { label: 'dangling-cname-or-takeover', kindMatch: ['dns'], pattern: /dangling|cname|takeover|nxdomain|unclaimed/i },
  { label: 'oauth-redirect-or-sso', kindMatch: ['redirect', 'auth'], pattern: /oauth|oidc|redirect_uri|callback|sso|clerk|token|session|cross-origin/i },
  { label: 'sandboxed-user-js-or-postmessage', kindMatch: ['dom'], pattern: /sandpack|sandbox|postmessage|iframe|user js|script execution|xss|bundler/i },
]

export function shouldRunCrossHostSynthesizer(
  facts: readonly Fact[],
  approvedOrigins: ReadonlySet<string>,
): { trigger: boolean; reason: string; distinctOrigins: string[]; leverageSignals: string[] } {
  const validFacts = facts.filter(f => !f.tainted && approvedOrigins.has(f.origin))
  if (!validFacts.length) {
    return { trigger: false, reason: 'No untainted facts in approved scope.', distinctOrigins: [], leverageSignals: [] }
  }
  const distinctOrigins = [...new Set(validFacts.map(f => f.origin))].sort()
  const signalSet = new Set<string>()
  for (const fact of validFacts) {
    const text = `${fact.summary} ${JSON.stringify(fact.data ?? {})}`
    for (const rule of CROSS_HOST_LEVERAGE_PATTERNS) {
      if ((rule.kindMatch?.includes(fact.kind) && rule.pattern.test(text)) || rule.pattern.test(text)) {
        signalSet.add(rule.label)
      }
    }
  }
  const leverageSignals = [...signalSet]
  const trigger = distinctOrigins.length >= 2 || leverageSignals.length > 0
  const reason = distinctOrigins.length >= 2
    ? `Facts span ${distinctOrigins.length} distinct approved origins${leverageSignals.length ? ` with signals: ${leverageSignals.join(', ')}` : ''}.`
    : leverageSignals.length > 0
      ? `High-leverage cross-origin signals detected: ${leverageSignals.join(', ')}.`
      : 'Single-origin facts without cross-origin leverage signals.'
  return { trigger, reason, distinctOrigins, leverageSignals }
}

function isSafeIdempotentPost(pathAndQuery: string, body?: string): boolean {
  if (!/(?:graphql|search|query|introspect)/i.test(pathAndQuery)) return false
  if (!body) return true
  return !/\bmutation\b/i.test(body)
}

// --- Deterministic (zero-LLM) investigation fallback helpers ---

/** Parameter names worth a differential SQL probe (generic, engine-level — not app-specific). */
const DETERMINISTIC_PARAM_HINT_RE = /^(?:id|uuid|q|query|search|s|filter|sort|order|orderby|where|name|email|slug|path|file|url|uri|host|cmd|exec|template|view|lang|category|type|limit|offset|page|next|redirect|return)$/i
const DETERMINISTIC_NUMERIC_PARAM_RE = /^(?:id|page|limit|offset|qty|quantity|amount|price|count|num|index)$/i
const DETERMINISTIC_ID_SEGMENT_RE = /(?:\/:[a-z_][a-z0-9_]*|\{\{id\}\}|\/[a-z_][a-z0-9_]*\}|\/\[[^\]]+\]|\/\d{2,16}(?=\/|$)|\/[0-9a-f]{8}-[0-9a-f]{4}-)/i
const DETERMINISTIC_PATH_PARAM_RE = /\/:[a-z_][a-z0-9_]*|\/\{\{id\}\}|\/\{[a-z_][a-z0-9_]*\}|\/\[[^\]]+\]/gi

function deterministicQueryParamNames(pathTemplate: string): string[] {
  const qIdx = pathTemplate.indexOf('?')
  if (qIdx < 0) return []
  return pathTemplate
    .slice(qIdx + 1)
    .split('&')
    .map(pair => pair.split('=')[0]?.trim())
    .filter((name): name is string => Boolean(name && /^[A-Za-z0-9_.\-[\]]{1,64}$/.test(name)))
}

function withQueryParam(pathTemplate: string, name: string, value: string): string {
  const base = pathTemplate.split('?')[0]
  return `${base}?${name}=${encodeURIComponent(value)}`
}

function deterministicIdPath(pathTemplate: string): string | null {
  if (!DETERMINISTIC_ID_SEGMENT_RE.test(pathTemplate)) return null
  const replaced = pathTemplate.replace(DETERMINISTIC_PATH_PARAM_RE, '/{{id}}').replace(/\/\d{2,16}(?=\/|$)/, '/{{id}}')
  return replaced.includes('{{id}}') ? replaced : null
}

/** Tolerant OpenAPI extraction for specs whose stored text is redacted or truncated. */
function parseTolerantOpenApiTargets(
  content: string,
  defaultOrigin: string,
  approvedOrigins: ReadonlySet<string>,
): Array<{
  origin: string
  method: string
  pathTemplate: string
  riskScore: number
  params: Array<{ name: string; location: 'query' | 'json' | 'form' | 'path' | 'header' | 'xml' | 'graphql_var' }>
}> {
  const pathKeyRe = /"(\/[A-Za-z0-9_\-{}\/.:$\[\]]{0,200})"\s*:\s*\{/g
  const matches = [...content.matchAll(pathKeyRe)]
  if (!matches.length) return []
  const out: Array<{
    origin: string
    method: string
    pathTemplate: string
    riskScore: number
    params: Array<{ name: string; location: 'query' | 'json' | 'form' | 'path' | 'header' | 'xml' | 'graphql_var' }>
  }> = []
  for (let idx = 0; idx < matches.length; idx += 1) {
    const match = matches[idx]
    const pathTemplate = match[1]
    if (!pathTemplate.startsWith('/')) continue
    const start = (match.index ?? 0) + match[0].length
    const end = idx + 1 < matches.length ? (matches[idx + 1].index ?? content.length) : content.length
    const block = content.slice(start, end)
    const methods = [...block.matchAll(/"(get|post|put|patch|delete)"\s*:\s*\{/g)].map(m => m[1].toUpperCase())
    if (!methods.length) continue
    const params: Array<{ name: string; location: 'query' | 'json' | 'form' | 'path' | 'header' | 'xml' | 'graphql_var' }> = []
    const paramRe = /"name"\s*:\s*"([A-Za-z0-9_.\-\[\]]{1,64})"[\s\S]{0,200}?"in"\s*:\s*"(query|path|header|formData|body)"/g
    for (const param of block.matchAll(paramRe)) {
      const location = param[2] === 'formData' ? 'form' : param[2] === 'body' ? 'json' : param[2] as 'query' | 'path' | 'header'
      if (!params.some(p => p.name === param[1])) params.push({ name: param[1], location })
    }
    for (const matchPath of pathTemplate.matchAll(/\{([A-Za-z0-9_]+)\}/g)) {
      if (!params.some(p => p.name === matchPath[1])) params.push({ name: matchPath[1], location: 'path' })
    }
    for (const method of methods) {
      if (method === 'DELETE') continue
      const hasInjectable = params.some(p => p.location === 'query' || p.location === 'json' || p.location === 'form')
      if (!hasInjectable && !deterministicIdPath(pathTemplate)) continue
      out.push({
        origin: approvedOrigins.has(defaultOrigin) ? defaultOrigin : [...approvedOrigins][0],
        method,
        pathTemplate,
        riskScore: hasInjectable ? 65 : 55,
        params,
      })
    }
  }
  return out.slice(0, 60)
}

/** Shared replay-spec boilerplate for deterministically synthesized specs. */function baseReplaySpecFields(
  _run: Run,
  origin: string,
  overrides: {
    title: string
    category: string
    cwe: string
    severity: Finding['severity']
    severityRationale: string
    impact: string
    remediation: string
    recheckInstructions: string
  },
) {
  return {
    version: 1 as const,
    origin,
    title: overrides.title.slice(0, 200),
    category: overrides.category,
    cwe: overrides.cwe,
    severity: overrides.severity,
    severityRationale: overrides.severityRationale.slice(0, 800),
    impact: overrides.impact.slice(0, 1200),
    remediation: overrides.remediation.slice(0, 1500),
    recheckInstructions: overrides.recheckInstructions.slice(0, 1000),
  }
}

function createBroker(options: { storage: SecondOrderStore; canaryBroker: CanaryBroker }) {
  const target = process.env.GUARDIAN_NETWORK_FIXTURE
  if (!target) {
    return process.env.GUARDIAN_OFFLINE === '1'
      ? new RequestBroker({ resolve: async () => [], storage: options.storage, canaryBroker: options.canaryBroker })
      : new RequestBroker({ storage: options.storage, canaryBroker: options.canaryBroker })
  }
  const fixture = new URL(target)
  if (fixture.origin !== target || fixture.hostname !== '127.0.0.1' || fixture.protocol !== 'http:' || !fixture.port) {
    throw new Error('GUARDIAN_NETWORK_FIXTURE must identify a loopback HTTP origin.')
  }
  return new RequestBroker({
    storage: options.storage,
    canaryBroker: options.canaryBroker,
    source: 'fixture response',
    resolve: async host => host.endsWith('.private-fixture.example')
      ? [{ address: '127.0.0.1', family: 4 }]
      : [{ address: '93.184.216.34', family: 4 }],
    transport: async (url, _address, signal, options) => {
      const reqHeaders: Record<string, string> = {
        ...(options?.headers ?? {}),
        'x-guardian-fixture-target': url.href,
      }
      const response = await fetch(fixture, {
        method: options?.method ?? 'GET',
        headers: reqHeaders,
        body: options?.body,
        signal,
        redirect: 'manual',
      })
      const body = options?.readBody === false ? '' : (await response.text()).slice(0, options?.maxBodyBytes ?? 1024 * 1024)
      return {
        status: response.status,
        headers: Object.fromEntries(response.headers),
        body,
        bodyBytes: Buffer.byteLength(body, 'utf8'),
        bodyTruncated: false,
      }
    },
  })
}

export interface ExecutionOptions {
  broker?: RequestBroker
  browser?: ScopedBrowser
  canaryBroker?: CanaryBroker
  backend?: WorkerBackend
  personaAuth?: PersonaAuthManager
  labRunner?: LabRunner
}

export class Execution {
  private readonly storage: Store
  readonly broker: RequestBroker
  readonly browser: ScopedBrowser
  readonly canaryBroker: CanaryBroker
  readonly backend: WorkerBackend
  readonly personaAuth: PersonaAuthManager
  readonly compactor: ColdGraphCompactor
  readonly labRunner: LabRunner
  private readonly active = new Map<string, Active>()
  private readonly coordinator = new Map<string, CoordinatorTask>()
  private readonly threatModeling = new Map<string, CoordinatorTask>()
  private readonly plannerTasks = new Map<string, CoordinatorTask>()
  private readonly plannerTimers = new Map<string, NodeJS.Timeout>()
  private readonly plannerDirty = new Set<string>()
  private readonly plannerDoneRound = new Map<string, number>()
  private readonly synthesizedSignature = new Map<string, string>()
  private readonly recordedPersonaResources = new Map<string, Set<string>>()
  private readonly circuitNotified = new Set<string>()
  private readonly runAuthStarted = new Map<string, string>()
  private readonly runAuthInFlight = new Map<string, AbortController>()
  private readonly startedLabRuns = new Set<string>()
  private readonly startedLabHandles = new Map<string, LabTargetHandle>()
  private readonly variantSweptFindings = new Set<string>()
  private readonly variantSweepInFlight = new Set<string>()
  private readonly pendingTier3ApprovalKeys = new Set<string>()
  /** runId → replay spec ids whose inline failure is eligible for bounded Phase-3 refinement. */
  private readonly refinementEligible = new Map<string, Set<string>>()
  private readonly deterministicInFlight = new Set<string>()
  private readonly deterministicCompleted = new Set<string>()
  /** v5 M5: chain-scoped warm specialist lifecycle (pure in-memory; mirrored to board_members). */
  private readonly warm = new WarmSpecialistController()
  private readonly boardHandleByAssignment = new Map<string, string>()
  private readonly boardAssignmentTokens = new Map<string, number>()
  private readonly boardHandleTokens = new Map<string, number>()
  private readonly wakeHandleByStepId = new Map<string, string>()
  private readonly routedOperatorBoardSeq = new Map<string, number>()
  private readonly wokenBoardMessageKeys = new Set<string>()
  private readonly postedVerdictKeys = new Set<string>()
  private readonly postedCanaryKeys = new Set<string>()
  private readonly boardScopeSync = new Map<string, string>()
  private readonly trackedBoardRuns = new Set<string>()
  private safetyTimer?: NodeJS.Timeout
  private reclaimTimer?: NodeJS.Timeout
  private unsubWake?: () => void
  private wakeScheduled = false
  /** Set by stop(); prevents queued microtasks/timers from touching a closed store. */
  private stopped = false

  constructor(storage: Store, options: ExecutionOptions = {}) {
    this.storage = storage
    this.canaryBroker = options.canaryBroker ?? new CanaryBroker({ storage })
    this.broker = options.broker ?? createBroker({ storage, canaryBroker: this.canaryBroker })
    // `storage` activates second-order canary scanning inside the browser context too.
    this.browser = options.browser ?? new ScopedBrowser(this.broker, { storage })
    this.backend = options.backend ?? new LinuxWorkerBackend({
      workspace: { id: storage.workspace.id, directory: storage.directory },
    })
    this.personaAuth = options.personaAuth ?? new PersonaAuthManager()
    this.labRunner = options.labRunner ?? new LabRunner()
    this.compactor = new ColdGraphCompactor({
      onProfileSuccess: id => recordProfileSuccess(id, this.storage),
      onProfileFailure: (id, err, hard) => recordProfileFailure(id, err, hard, this.storage),
    })
  }

  private isCanaryDnsConfigured(): boolean {
    return Boolean(
      process.env.GUARDIAN_CANARY_DNS_HOST ||
      process.env.GUARDIAN_CANARY_DNS_PORT ||
      process.env.GUARDIAN_CANARY_DNS_DOMAIN,
    )
  }

  private isCanaryListenerConfigured(): boolean {
    return Boolean(
      process.env.GUARDIAN_CANARY_PUBLIC_URL ||
      process.env.GUARDIAN_CANARY_BASE_URL ||
      process.env.GUARDIAN_CANARY_PORT ||
      process.env.GUARDIAN_CANARY_ENABLE === '1' ||
      this.isCanaryDnsConfigured(),
    )
  }

  private parseOriginForRun(run: Run, raw: string): string {
    const project = this.storage.project(run.projectId)
    return assetOriginForEnvironment(project.environment).parse(raw)
  }

  start() {
    if (this.safetyTimer) return
    this.stopped = false
    if (this.isCanaryListenerConfigured()) {
      void this.canaryBroker.startListener({ enableDns: this.isCanaryDnsConfigured() }).catch(() => undefined)
    }
    this.unsubWake = this.storage.onWake(() => this.scheduleWake())
    this.safetyTimer = setInterval(() => this.wake(), 2_000)
    this.safetyTimer.unref()
    const reclaim = () => {
      if (this.backend instanceof LinuxWorkerBackend) {
        void this.backend.reclaimInactive().catch(() => { /* retry on next cycle */ })
      }
    }
    reclaim()
    this.reclaimTimer = setInterval(reclaim, 30_000)
    this.reclaimTimer.unref()
    this.scheduleWake()
  }

  async stop() {
    this.stopped = true
    this.wakeScheduled = false
    this.unsubWake?.()
    this.unsubWake = undefined
    if (this.safetyTimer) { clearInterval(this.safetyTimer); this.safetyTimer = undefined }
    if (this.reclaimTimer) { clearInterval(this.reclaimTimer); this.reclaimTimer = undefined }
    for (const timer of this.plannerTimers.values()) clearTimeout(timer)
    this.plannerTimers.clear()
    for (const job of this.active.values()) job.controller.abort()
    for (const task of this.coordinator.values()) task.controller.abort()
    for (const task of this.threatModeling.values()) task.controller.abort()
    for (const task of this.plannerTasks.values()) task.controller.abort()
    for (const ctrl of this.runAuthInFlight.values()) ctrl.abort()
    this.runAuthInFlight.clear()
    this.runAuthStarted.clear()
    this.personaAuth.stopAll()
    await this.labRunner.stopAll().catch(() => undefined)
    this.startedLabRuns.clear()
    this.startedLabHandles.clear()
    await this.canaryBroker.stopListener().catch(() => undefined)
  }

  getLabTargetHandle(runId: string): LabTargetHandle | undefined {
    return this.startedLabHandles.get(runId)
  }

  private scheduleWake() {
    if (this.stopped || this.wakeScheduled) return
    this.wakeScheduled = true
    queueMicrotask(() => {
      this.wakeScheduled = false
      if (this.stopped) return
      this.wake()
    })
  }

  private permitted(run: Run, origin: string) {
    return run.candidates.some(asset => asset.origin === origin && run.approved.includes(asset.id))
  }

  private approvedOriginsSet(run: Run): Set<string> {
    return new Set(run.candidates.filter(asset => run.approved.includes(asset.id)).map(asset => asset.origin))
  }

  private projectReposMount(projectId: string): { reposDir?: string; mountedRepos: string[] } {
    try {
      const dir = projectReposDir(this.storage.directory, projectId)
      const mountedRepos = listMountedRepos(dir)
      return mountedRepos.length > 0 ? { reposDir: dir, mountedRepos } : { mountedRepos: [] }
    } catch {
      return { mountedRepos: [] }
    }
  }

  private authorize(job: Active): boolean {
    let current: Assignment
    let run: Run
    try {
      current = this.storage.worker(job.assignment.id)
      run = this.storage.run(current.runId)
    } catch {
      return false
    }
    if (current.lease !== job.assignment.lease) return false
    if (!['running', 'waiting_approval'].includes(current.status)) return false
    if (current.phase === 'retest') {
      return [...job.origins].every(origin => this.permitted(run, origin))
    }
    return run.status === 'running' &&
      run.phase === current.phase &&
      current.goalRevision === run.goalRevision &&
      [...job.origins].every(origin => this.permitted(run, origin))
  }

  private check(job: Active): Run {
    job.controller.signal.throwIfAborted()
    if (!this.authorize(job)) throw new BrokerDenied('The assignment is no longer authorized.')
    return this.storage.run(job.assignment.runId)
  }

  private currentCoordinator(runId: string, task: CoordinatorTask): boolean {
    try {
      const run = this.storage.run(runId)
      return run.status === 'running' &&
        run.goalRevision === task.goalRevision &&
        (task.scopeRevision === undefined || run.scopeRevision === task.scopeRevision) &&
        !task.controller.signal.aborted
    } catch {
      return false
    }
  }

  private buildGrant(job: Active, run: Run, permittedAtAdmission: ReadonlySet<string>): {
    grant: Grant
    secrets: NamedSecret[]
    currentSecrets: () => NamedSecret[]
  } {
    const project = this.storage.project(run.projectId)
    const personas = resolveRunPersonas(this.storage, run.projectId, run.approvedPersonaIds)
    const secrets = personaSecrets(personas)
    const currentSecrets = () => {
      const latest = personaSecrets(personas)
      const seen = new Set(secrets.map(s => `${s.placeholder}\0${s.value}`))
      for (const item of latest) {
        const key = `${item.placeholder}\0${item.value}`
        if (!seen.has(key)) {
          seen.add(key)
          secrets.push(item)
        }
      }
      return secrets
    }
    const allowLocalLab = project.environment === 'local-lab'

    const grant: Grant = {
      tier: run.capabilityTier,
      maxRpsPerOrigin: run.maxRpsPerOrigin,
      allowLocalLab,
      personas,
      secrets,
      // Second-order canary scanning needs both the store and the minting broker; without these
      // the broker/browser silently skip `scanSecondOrderMarkers`.
      storage: this.storage,
      canaryBroker: this.canaryBroker,
      scopeRevision: run.scopeRevision,
      mintCanary: (purpose, origin) => {
        const minted = this.canaryBroker.mintCanary(run.id, purpose, origin, {
          storage: this.storage,
          assignmentId: job.assignment.id,
        })
        return { httpUrl: minted.httpUrl, url: minted.url }
      },
      canRead: origin => {
        if (!this.authorize(job)) return false
        const fresh = this.storage.run(run.id)
        return permittedAtAdmission.has(origin) && this.permitted(fresh, origin)
      },
      isIdempotentPostAllowed: (_origin, pathAndQuery, body) => isSafeIdempotentPost(pathAndQuery, body),
      isStateChangeApproved: (origin, method, pathAndQuery) => {
        const fresh = this.storage.run(run.id)
        if (
          project.environment === 'local-lab' &&
          allowLocalLab && process.env.GUARDIAN_ALLOW_LOCAL_LAB === '1' &&
          fresh.capabilityTier >= 3 &&
          (fresh.approvalPolicy ?? 'auto_review') !== 'strict' &&
          isLocalLabAutoApprovalOrigin(origin)
        ) {
          // Persist the zero-trust audit trail BEFORE the state change leaves the broker:
          // origin-bound local-lab auto-approval is attributed distinctly from rule/judge/yolo.
          this.storage.recordAutoApprovalDecision(fresh, job.assignment, {
            origin,
            method,
            pathAndQuery,
            rationale: `Local-lab Tier-3 state change during step "${job.assignment.stepId ?? 'step'}"`,
            requestPreview: `${method.toUpperCase()} ${origin}${pathAndQuery}`,
            decision: 'approved',
            decidedBy: 'auto-review:local-lab',
            riskLevel: 'medium',
            policyNote: 'Authorized local-lab loopback/lab-internal origin; broker destructive-payload, webshell, SSRF metadata and RPS invariants enforced.',
            secrets: currentSecrets(),
          })
          return true
        }
        const activePatterns = (fresh.approvedEndpointPatterns ?? []).filter(
          p => p.scopeRevision === undefined || p.scopeRevision === fresh.scopeRevision,
        )
        if (matchesApprovedEndpointPattern({ origin, method, pathAndQuery }, activePatterns)) {
          return true
        }
        const now = Date.now()
        const rows = this.storage.db.select().from(approvalRequests).where(and(
          eq(approvalRequests.runId, run.id),
          eq(approvalRequests.scopeRevision, fresh.scopeRevision),
          eq(approvalRequests.origin, origin),
          eq(approvalRequests.method, method.toUpperCase()),
          eq(approvalRequests.status, 'approved'),
        )).all()
        return rows.some(r => r.expiresAt > now && (r.pathAndQuery === pathAndQuery || pathAndQuery.startsWith(r.pathAndQuery.split('?')[0])))
      },
      audit: (outcome, origin, status) => {
        if (outcome === 'allowed') job.origins.add(origin)
        this.storage.event(run.id, 'broker.' + outcome,
          `Broker ${outcome} for ${new URL(origin).hostname}${status ? ` (${status})` : ''}.`,
          { assignmentId: job.assignment.id, origin, status })
        if (outcome === 'circuit_open') {
          const fresh = this.storage.run(run.id)
          if (fresh.status === 'running') {
            const approvedOrigins = [...this.approvedOriginsSet(fresh)]
            const allTripped = approvedOrigins.length <= 1 ||
              approvedOrigins.every(o => o === origin || this.broker.isCircuitOpen(o))
            const notifyKey = `${run.id}:${origin}`
            if (allTripped) {
              this.storage.setStatus(fresh, 'paused')
              if (!this.circuitNotified.has(notifyKey)) {
                this.circuitNotified.add(notifyKey)
                this.storage.message(run.id, fresh.coordinatorId, 'guardian',
                  `Defensive circuit breaker opened for ${origin} due to elevated 5xx/429 responses. Run paused to protect target availability.`)
                this.postBrokerBlocker(fresh, origin, status)
              }
            } else {
              // Isolate circuit breaker to the affected origin while healthy hosts continue
              for (const st of this.storage.listChainSteps(run.id, fresh.goalRevision)) {
                if ((st.status === 'pending' || st.status === 'ready') &&
                    st.sourceOrigins.length > 0 &&
                    st.sourceOrigins.every(o => o === origin || this.broker.isCircuitOpen(o))) {
                  this.storage.updateChainStep(st.id, { status: 'blocked' })
                }
              }
              if (!this.circuitNotified.has(notifyKey)) {
                this.circuitNotified.add(notifyKey)
                this.storage.message(run.id, fresh.coordinatorId, 'guardian',
                  `Defensive circuit breaker opened for ${origin} due to elevated 5xx/429 responses. Further traffic to ${origin} is blocked while healthy hosts continue.`)
                this.postBrokerBlocker(fresh, origin, status)
              }
            }
          }
        }
      },
    }
    return { grant, secrets, currentSecrets }
  }

  // --- v5 M5 Swarm Board wiring -------------------------------------------------

  private boardHost(origin: string): string {
    try { return new URL(origin).hostname } catch { return origin }
  }

  /** Store-level board writes are advisory: a rejected/malformed post must never break the run. */
  private postBoard(run: Run, input: {
    authorHandle: string
    authorRole: BoardAuthorRole
    kind: BoardMessageKind
    body: string
    mentions?: readonly string[]
    refFactIds?: readonly string[]
    refExchangeIds?: readonly string[]
    refFindingIds?: readonly string[]
    refStepId?: string | null
    refApprovalId?: string | null
    sourceOrigins?: readonly string[]
  }, secrets: readonly NamedSecret[] = []): BoardMessageRow | null {
    try {
      this.trackedBoardRuns.add(run.id)
      return this.storage.postBoardMessage(run, input, secrets)
    } catch {
      return null
    }
  }

  private isPeerBoardHandle(handle: string): boolean {
    return !['all', 'system', 'operator', 'coordinator', 'verifier', 'broker', 'canary'].includes(handle)
  }

  /** Plain text (or @coordinator) goes to the legacy coordinator thread; @specialist routes to that peer. */
  private shouldCoordinatorAnswer(content: string): boolean {
    const mentions = parseBoardMentions(content)
    const peers = mentions.filter(handle => this.isPeerBoardHandle(handle))
    return peers.length === 0 || mentions.includes('coordinator')
  }

  private boardBaseHandle(handle: string): string {
    return handle.replace(/-(?:\d+|r\d+)$/, '')
  }

  private boardProfileForHandle(handle: string) {
    return specialistProfileByHandle[this.boardBaseHandle(handle)] ?? null
  }

  private boardMemberMentionable(run: Run, handle: string): boolean {
    const member = this.storage.boardMember(run.id, handle)
    if (member) return member.state !== 'retired'
    return Boolean(this.boardProfileForHandle(handle)) ||
      ['coordinator', 'operator', 'verifier', 'broker', 'canary', 'all'].includes(handle)
  }

  /** Resolve the roster handle for an assignment (mapped at step start, else derived from its step profile). */
  private boardHandleForAssignmentId(run: Run, assignmentId: string): string {
    const mapped = this.boardHandleByAssignment.get(assignmentId)
    if (mapped) return mapped
    const existing = this.storage.listBoardMembers(run.id).find(member => member.activeAssignmentId === assignmentId)
    if (existing) return existing.handle
    try {
      const worker = this.storage.worker(assignmentId)
      const step = worker.stepId
        ? this.storage.listChainSteps(run.id, run.goalRevision).find(candidate => candidate.id === worker.stepId)
        : undefined
      if (step?.specialistProfile) return specialistHandleByProfile[step.specialistProfile]
    } catch { /* assignment may be gone */ }
    return 'coordinator'
  }

  private boardAuthorForAssignmentId(run: Run, assignmentId: string): { handle: string; role: BoardAuthorRole } {
    const handle = this.boardHandleForAssignmentId(run, assignmentId)
    const member = this.storage.boardMember(run.id, handle)
    if (member) return { handle, role: member.role }
    if (handle === 'coordinator') return { handle, role: 'coordinator' }
    if (handle === 'verifier') return { handle, role: 'verifier' }
    return { handle, role: 'specialist' }
  }

  /** Sharded handle allocation: reuse base while free, then base-2..9, then recycle a waiting shard. */
  private allocateBoardHandle(run: Run, profile: NonNullable<ChainStep['specialistProfile']>, step: ChainStep): string {
    const base = specialistHandleByProfile[profile]
    if (step.trialGroupId) return `${base}-${Math.max(1, step.trialIndex + 1)}`
    const members = this.storage.listBoardMembers(run.id)
    if (!members.some(member => member.handle === base)) return base
    for (let shard = 2; shard <= 9; shard += 1) {
      const handle = `${base}-${shard}`
      if (!members.some(member => member.handle === handle)) return handle
    }
    const waiting = members
      .filter(member => member.handle.startsWith(base + '-') && member.state === 'waiting' && !member.activeAssignmentId)
      .sort((a, b) => a.updatedAt - b.updatedAt)[0]
    return waiting?.handle ?? `${base}-r${members.filter(member => member.handle.startsWith(base)).length + 1}`
  }

  /** Deterministic @coordinator brief emitted when a chain step is dispatched. */
  private postCoordinatorBrief(run: Run, step: ChainStep, handle: string, origins: readonly string[]): BoardMessageRow | null {
    if (!this.boardMemberMentionable(run, handle)) return null
    const targets = origins.map(origin => this.boardHost(origin)).join(', ')
    const body = `Brief · ${step.title} [${step.category}] on ${targets}. Hypothesis: ${step.hypothesis}`.slice(0, 900)
    return this.postBoard(run, {
      authorHandle: 'coordinator',
      authorRole: 'coordinator',
      kind: 'brief',
      body,
      mentions: [handle],
      refStepId: step.id,
      sourceOrigins: [...origins],
    })
  }

  /** Deterministic @verifier verdict for inline and Phase-3 Zero-LLM verification. */
  private postVerificationVerdict(run: Run, opts: {
    replaySpecId: string
    findingId?: string | null
    title: string
    status: Finding['status']
    verificationTier?: VerificationTier | null
    feedback?: InlineVerifyFeedback | null
    assignmentId?: string | null
    refStepId?: string | null
    attempt?: number
    secrets?: readonly NamedSecret[]
  }): BoardMessageRow | null {
    const key = `${run.id}:${opts.replaySpecId}:${opts.status}:${opts.findingId ?? ''}:${opts.attempt ?? ''}`
    if (this.postedVerdictKeys.has(key)) return null
    this.postedVerdictKeys.add(key)
    const confirmed = opts.status === 'confirmed' || opts.status === 'static_verified'
    const authorHandle = opts.assignmentId ? this.boardHandleForAssignmentId(run, opts.assignmentId) : 'coordinator'
    const feedback = opts.feedback
    const body = confirmed
      ? `Verdict · ${opts.title.slice(0, 300)} — ${opts.status}${opts.verificationTier ? ` (${opts.verificationTier})` : ''} [spec: ${opts.replaySpecId}${opts.findingId ? `, finding: ${opts.findingId}` : ''}]`
      : [
          `Verdict · spec ${opts.replaySpecId} ${opts.status}:`,
          feedback?.assertionSummary?.observed ?? 'replay did not confirm',
          feedback?.assertionSummary?.expected ? `(expected ${feedback.assertionSummary.expected})` : '',
          feedback?.failedStepId ? `[step: ${feedback.failedStepId}]` : '',
          feedback?.jqError ? `jq=${feedback.jqError.slice(0, 160)}` : '',
        ].filter(Boolean).join(' ').slice(0, 900)
    const mentions = !confirmed && this.boardMemberMentionable(run, authorHandle) ? [authorHandle] : []
    let authorOrigins: string[] = []
    if (opts.assignmentId) {
      try { authorOrigins = this.storage.worker(opts.assignmentId).sourceOrigins } catch { /* assignment may be gone */ }
    }
    const sent = this.postBoard(run, {
      authorHandle: 'verifier',
      authorRole: 'verifier',
      kind: 'verdict',
      body,
      mentions,
      ...(opts.findingId ? { refFindingIds: [opts.findingId] } : {}),
      ...(opts.refStepId ? { refStepId: opts.refStepId } : {}),
      ...(authorOrigins.length ? { sourceOrigins: authorOrigins } : {}),
    }, opts.secrets)
    if (sent) return sent
    // A retired/unknown author handle must not lose the verdict: post without the mention.
    if (!mentions.length) return null
    return this.postBoard(run, {
      authorHandle: 'verifier',
      authorRole: 'verifier',
      kind: 'verdict',
      body,
      ...(opts.findingId ? { refFindingIds: [opts.findingId] } : {}),
      ...(opts.refStepId ? { refStepId: opts.refStepId } : {}),
    }, opts.secrets)
  }

  /** Deterministic @broker blocker for circuit-open / repeated 429 conditions. */
  private postBrokerBlocker(run: Run, origin: string, status?: number): BoardMessageRow | null {
    const reason = status === 429 ? 'HTTP 429 rate limiting' : 'repeated 5xx/429 responses'
    return this.postBoard(run, {
      authorHandle: 'broker',
      authorRole: 'system',
      kind: 'blocker',
      body: `Blocker · circuit open on ${this.boardHost(origin)} after ${reason}; further traffic to this origin is paused while healthy hosts continue.`,
      mentions: ['all'],
      sourceOrigins: [origin],
    })
  }

  /** Tier-3 gate: pause the warm member and post an approval card linked by refApprovalId. */
  private postApprovalCard(run: Run, assignmentId: string, input: {
    approvalId: string
    origin: string
    method: string
    pathAndQuery: string
    rationale: string
  }, secrets: readonly NamedSecret[] = []): BoardMessageRow | null {
    const handle = this.boardHandleForAssignmentId(run, assignmentId)
    const member = this.storage.boardMember(run.id, handle)
    if (member && member.role === 'specialist') {
      try {
        this.storage.updateBoardMemberState(run.id, handle, { state: 'paused', activeAssignmentId: assignmentId })
        this.warm.register(handle, { sessionId: member.sessionId, state: 'working', lastReadSeq: member.lastReadSeq })
        this.warm.pause(handle, assignmentId)
      } catch { /* roster mirror is best-effort */ }
    }
    return this.postBoard(run, {
      authorHandle: 'broker',
      authorRole: 'system',
      kind: 'approval',
      body: `Approval required · Tier ${run.capabilityTier} ${input.method.toUpperCase()} ${this.boardHost(input.origin)}${input.pathAndQuery} — ${input.rationale.slice(0, 400)}`,
      mentions: [handle],
      refApprovalId: input.approvalId,
      sourceOrigins: [input.origin],
    }, secrets)
  }

  private postApprovalResolution(run: Run, assignmentId: string, input: {
    approvalId: string
    decision: string
    origin: string
    method: string
    pathAndQuery: string
  }): void {
    const handle = this.boardHandleForAssignmentId(run, assignmentId)
    const member = this.storage.boardMember(run.id, handle)
    if (member && member.role === 'specialist' && member.state === 'paused') {
      try {
        this.storage.updateBoardMemberState(run.id, handle, { state: 'working', activeAssignmentId: assignmentId })
        this.warm.register(handle, { sessionId: member.sessionId, state: 'paused', lastReadSeq: member.lastReadSeq })
        this.warm.resume(handle, assignmentId)
      } catch { /* roster mirror is best-effort */ }
    }
    this.postBoard(run, {
      authorHandle: 'broker',
      authorRole: 'system',
      kind: 'status',
      body: `Tier-3 ${input.decision} · ${input.method.toUpperCase()} ${this.boardHost(input.origin)}${input.pathAndQuery}`,
      mentions: this.boardMemberMentionable(run, handle) ? [handle] : [],
      refApprovalId: input.approvalId,
      sourceOrigins: [input.origin],
    })
  }

  /** Deterministic @canary lead on OOB callbacks and second-order surfaces. */
  private postCanaryLead(run: Run, input: {
    marker?: string
    origin: string
    endpoint?: string
    persona?: string | null
    exchangeId?: string | null
    mediaType?: string | null
    key?: string
  }): BoardMessageRow | null {
    const key = input.key ?? `${run.id}:${input.marker ?? ''}:${input.origin}:${input.endpoint ?? ''}:${input.exchangeId ?? ''}`
    if (this.postedCanaryKeys.has(key)) return null
    this.postedCanaryKeys.add(key)
    const target = /html|render|page|admin/i.test(`${input.endpoint ?? ''} ${input.mediaType ?? ''}`) ? 'browser' : 'injection'
    const body = [
      'Lead · canary surfaced',
      input.endpoint ? `at ${input.endpoint}` : '',
      input.persona ? `via persona ${input.persona}` : '',
      input.mediaType ? `(${input.mediaType})` : '',
      input.exchangeId ? `[exchange: ${input.exchangeId}]` : '',
      '— second-order/cross-persona evidence; treat as a hypothesis until replay-verified.',
    ].filter(Boolean).join(' ').slice(0, 900)
    return this.postBoard(run, {
      authorHandle: 'canary',
      authorRole: 'system',
      kind: 'lead',
      body,
      mentions: [target],
      ...(input.exchangeId ? { refExchangeIds: [input.exchangeId] } : {}),
      sourceOrigins: [input.origin],
    })
  }

  /** Turn-start delta: sanitized peer posts only, plus the cursor to persist atomically. */
  private boardTurnDelta(run: Run, handle: string, lastReadSeq: number): { text: string; cursor: number } {
    const delta = buildBoardDelta({ store: this.storage, run: run.id, handle, lastReadSeq })
    try {
      this.storage.updateBoardMemberState(run.id, handle, { lastReadSeq: delta.cursor })
      this.warm.noteBoardCursor(handle, delta.cursor)
    } catch { /* member may have been retired between turns */ }
    return { text: delta.text, cursor: delta.cursor }
  }

  /** Operator/coordinator intervention resets every member's consecutive peer-hop budget. */
  private resetBoardHops(run: Run): void {
    for (const member of this.storage.listBoardMembers(run.id)) {
      if (member.peerHopsUsed === 0) continue
      try { this.storage.updateBoardMemberState(run.id, member.handle, { peerHopsUsed: 0 }) } catch { /* ignore */ }
    }
    this.warm.noteEvidence()
  }

  /** Retire/sleep warm members on stop, scope revoke, and mirror roster rows into the controller. */
  private syncBoardRoster(run: Run): void {
    this.trackedBoardRuns.add(run.id)
    const signature = `${run.scopeRevision}:${run.status}:${run.phase}`
    if (this.boardScopeSync.get(run.id) !== signature) {
      this.boardScopeSync.set(run.id, signature)
      if (run.status !== 'running' || run.phase === 'complete') {
        for (const member of this.storage.listBoardMembers(run.id)) {
          if (member.role !== 'specialist' || member.state === 'retired') continue
          try { this.storage.retireBoardMember(run, member.handle, `Run ${run.status}.`) } catch { /* ignore */ }
          this.warm.retire(member.handle, `run_${run.status}`)
        }
        this.trackedBoardRuns.delete(run.id)
        return
      } else {
        try {
          const revoked = this.storage.taintBoardMessagesForRevokedOrigins(run.id, this.approvedOriginsSet(run))
          for (const handle of revoked.retiredHandles) this.warm.retire(handle, 'scope_revoked')
        } catch { /* store may be closing */ }
      }
    }
    for (const member of this.storage.listBoardMembers(run.id)) {
      this.warm.register(member.handle, {
        sessionId: member.sessionId,
        state: member.state === 'working' ? 'working' : member.state === 'paused' ? 'paused' : 'waiting',
        turnsUsed: member.turnsUsed,
        postsCount: member.postsCount,
        peerHopsUsed: member.peerHopsUsed,
        lastReadSeq: member.lastReadSeq,
      })
      if (member.state === 'retired') this.warm.retire(member.handle, 'roster_retired')
    }
  }

  /** Operator composer: plain text is handled by the legacy coordinator thread; @handle wakes that peer. */
  private routeOperatorBoardMessages(run: Run): void {
    this.trackedBoardRuns.add(run.id)
    const cursor = this.routedOperatorBoardSeq.get(run.id) ?? 0
    const messages = this.storage.listBoardMessages(run.id, {
      authorHandle: 'operator', sinceSeq: cursor, limit: 100, includeTainted: false,
    })
    if (!messages.length) return
    this.resetBoardHops(run)
    for (const message of messages) {
      const targets = message.mentions.filter(handle => handle !== 'all' && this.isPeerBoardHandle(handle))
      for (const target of targets) this.wakeBoardMember(run, target, message)
    }
    this.routedOperatorBoardSeq.set(run.id, messages[messages.length - 1].seq)
  }

  /** Queue a chain-scoped follow-up step for a woken member (respects budget + workerConcurrency). */
  private wakeBoardMember(run: Run, handle: string, message: BoardMessageRow): ChainStep | null {
    if (run.status !== 'running' || run.phase !== 'investigation') return null
    if (this.storage.checkBudgetExceeded(run.id)) return null
    const profile = this.boardProfileForHandle(handle)
    if (!profile) return null
    const key = `${run.id}:${message.id}:${handle}`
    if (this.wokenBoardMessageKeys.has(key)) return null
    const member = this.storage.boardMember(run.id, handle)
    if (member?.state === 'paused' || member?.state === 'working') return null

    const approved = this.approvedOriginsSet(run)
    const origins = [...new Set([
      ...message.sourceOrigins.filter(origin => approved.has(origin)),
      ...(member?.sourceOrigins ?? []).filter(origin => approved.has(origin)),
    ])]
    if (!origins.length) return null
    const assetIds = run.candidates
      .filter(candidate => run.approved.includes(candidate.id) && origins.includes(candidate.origin))
      .map(candidate => candidate.id)
    if (!assetIds.length) return null

    const steps = this.storage.listChainSteps(run.id, run.goalRevision)
    const pendingWake = steps.some(candidate =>
      this.wakeHandleByStepId.get(candidate.id) === handle &&
      (candidate.status === 'ready' || candidate.status === 'pending'))
    if (pendingWake) return null
    const dynamicBudget = Math.max(1, Math.min(hardChainStepsCeiling, run.dynamicStepBudget ?? computeDynamicStepBudget(this.storage, run.id)))
    if (steps.length >= dynamicBudget) return null

    this.wokenBoardMessageKeys.add(key)
    const step = this.storage.addChainStep(run, {
      title: `Peer handoff · @${handle}`.slice(0, 200),
      hypothesis: `Follow up ${message.kind} from @${message.authorHandle}: ${message.body}`.slice(0, 1200),
      category: 'misconfig-exposure',
      priority: message.kind === 'blocker' ? 92 : 88,
      targetAssetIds: assetIds,
      sourceOrigins: origins,
      dependsOnFactIds: message.refFactIds,
      specialistProfile: profile,
    })
    this.wakeHandleByStepId.set(step.id, handle)
    if (!member) {
      try {
        this.storage.upsertBoardMember(run, {
          handle,
          role: 'specialist',
          specialistProfile: profile,
          state: 'waiting',
          sourceOrigins: origins,
        })
        this.warm.register(handle, { state: 'waiting' })
      } catch { /* roster mirror is best-effort */ }
    }
    this.storage.event(run.id, 'board.wakeup', `@${handle} queued from @${message.authorHandle}'s ${message.kind} (board #${message.seq}).`, {
      handle, messageSeq: message.seq, stepId: step.id,
    })
    this.scheduleWake()
    return step
  }

  /** Sleep (waiting, same session) or retire a warm member after its assignment finishes. */
  private finishBoardMember(run: Run, assignmentId: string): void {
    const handle = this.boardHandleByAssignment.get(assignmentId)
    if (!handle) return
    const tokens = this.boardHandleTokens.get(handle) ?? this.boardAssignmentTokens.get(assignmentId) ?? 0
    this.boardHandleByAssignment.delete(assignmentId)
    this.boardAssignmentTokens.delete(assignmentId)
    let worker: Assignment | undefined
    try { worker = this.storage.worker(assignmentId) } catch { /* deleted */ }
    const succeeded = worker?.status === 'complete'
    const completion = this.warm.completeTurn(handle, { tokensUsed: tokens })
    try {
      if (!succeeded || completion?.state === 'retired') {
        this.warm.retire(handle, completion?.retiredReason ?? 'step_failed')
        this.storage.updateBoardMemberState(run.id, handle, { state: 'retired', activeAssignmentId: null })
        this.boardHandleTokens.delete(handle)
      } else {
        this.storage.updateBoardMemberState(run.id, handle, { state: 'waiting', activeAssignmentId: null })
      }
    } catch { /* roster mirror is best-effort */ }
    if (completion?.closureRequired) {
      const author = this.boardAuthorForAssignmentId(run, assignmentId)
      this.postBoard(run, {
        authorHandle: author.handle,
        authorRole: author.role,
        kind: 'status',
        body: `Closure · @${author.handle}: ${(worker?.outcome ?? 'step complete').slice(0, 700)}`,
        ...(worker?.stepId ? { refStepId: worker.stepId } : {}),
      })
    }
  }

  /**
   * Scan a brokered HTTP exchange (response body + headers) for second-order canary markers.
   * Runs in Execution (not only inside RequestBroker) so injected/custom brokers are covered too.
   */
  /** SQLite endpoint-parameter and API-dependency catalog, resolved to route/method display keys. */
  private endpointGraphCatalog(runId: string): {
    endpointParams: Array<{
      endpoint: string
      origin: string
      method: string
      name: string
      location: string
      inferredType: string | null
      isCsrf: boolean
      isObjectId: boolean
      source: string
    }>
    apiDependencies: Array<{
      producer: string
      consumer: string
      resourceKey: string
      personaHandle: string | null
      testedBola: boolean
    }>
  } {
    const endpoints = this.storage.listEndpoints(runId, { limit: 2000 })
    const byId = new Map(endpoints.map(ep => [ep.id, ep]))
    const endpointParams = this.storage.listEndpointParams(runId).slice(0, 400).map(param => {
      const ep = byId.get(param.endpointId)
      return {
        endpoint: ep ? `${ep.method} ${ep.pathTemplate}` : param.endpointId,
        origin: ep?.origin ?? '',
        method: ep?.method ?? '',
        name: param.name,
        location: param.location,
        inferredType: param.inferredType,
        isCsrf: param.isCsrf,
        isObjectId: param.isObjectId,
        source: param.source,
      }
    })
    const apiDependencies = this.storage.listApiDependencies(runId).slice(0, 200).map(dep => {
      const producer = byId.get(dep.producerEndpointId)
      const consumer = byId.get(dep.consumerEndpointId)
      return {
        producer: producer ? `${producer.method} ${producer.pathTemplate}` : dep.producerEndpointId,
        consumer: consumer ? `${consumer.method} ${consumer.pathTemplate}` : dep.consumerEndpointId,
        resourceKey: dep.resourceKey,
        personaHandle: dep.personaHandle,
        testedBola: dep.testedBola,
      }
    })
    return { endpointParams, apiDependencies }
  }

  /** Persist real per-endpoint coverage for one exercised request. */
  private markEndpointCoverage(
    run: Run,
    origin: string,
    method: string,
    pathAndQuery: string,
    testedClass: string,
  ): void {
    this.storage.noteEndpointProbe({
      runId: run.id,
      scopeRevision: run.scopeRevision,
      origin,
      method,
      pathAndQuery,
      testedClass,
      source: 'surface_probe',
    })
  }

  /** Mark every concrete request embedded in a declarative replay spec as tested. */
  private markReplaySpecCoverage(run: Run, spec: unknown, testedClass: string): void {
    const visited = new Set<unknown>()
    const walk = (node: unknown, depth: number) => {
      if (depth > 8 || !node || typeof node !== 'object') return
      if (visited.has(node)) return
      visited.add(node)
      const record = node as Record<string, unknown>
      if (
        typeof record.origin === 'string' &&
        typeof record.pathAndQuery === 'string' &&
        typeof record.method === 'string'
      ) {
        this.markEndpointCoverage(run, record.origin, record.method, record.pathAndQuery, testedClass)
      }
      for (const value of Object.values(record)) walk(value, depth + 1)
    }
    walk(spec, 0)
  }

  private scanSecondOrderExchange(
    run: Run,
    assignmentId: string,
    res: Pick<BrokerExchangeResult, 'origin' | 'pathAndQuery' | 'personaHandle' | 'mediaType' | 'respHeaders' | 'body'>,
    exchangeId: string | null,
    mediaTypeOverride?: string,
  ) {
    const headerText = Object.entries(res.respHeaders ?? {}).map(([k, v]) => `${k}: ${v}`).join('\n')
    const body = typeof res.body === 'string' ? res.body : ''
    if (!body.includes('gn2o_') && !headerText.includes('gn2o_')) return
    const surfaced = scanSecondOrderMarkers({
      text: `${headerText}\n${body}`,
      runId: run.id,
      assignmentId,
      origin: res.origin,
      endpoint: res.pathAndQuery,
      persona: res.personaHandle,
      mediaType: mediaTypeOverride ?? res.mediaType,
      exchangeId,
      storage: this.storage,
    })
    for (const record of surfaced) {
      this.postCanaryLead(run, {
        marker: record.marker,
        origin: res.origin,
        endpoint: res.pathAndQuery,
        persona: res.personaHandle,
        exchangeId,
        mediaType: mediaTypeOverride ?? res.mediaType,
      })
    }
  }

  private markRefinementEligible(runId: string, replaySpecId: string) {
    let set = this.refinementEligible.get(runId)
    if (!set) {
      set = new Set<string>()
      this.refinementEligible.set(runId, set)
    }
    set.add(replaySpecId)
  }

  private isRefinementEligible(runId: string, replaySpecId: string): boolean {
    return this.refinementEligible.get(runId)?.has(replaySpecId) === true
  }

  /** Number of Phase-3 refinement jobs already dispatched for this run (complete or active). */
  private refinementJobsDispatched(runId: string): number {
    return this.storage.workerList(runId).filter(w => w.stepId?.startsWith('refine:')).length
  }

  private refinementBudgetRemaining(runId: string): number {
    return Math.max(0, maxPhase3RefinementJobs - this.refinementJobsDispatched(runId))
  }

  /**
   * Strong pre-verification signal gate for bounded Phase-3 reasoning refinement: only findings
   * backed by an observed differential anomaly, a canary/OOB trigger, a second-order surface, or a
   * high-confidence SAST suspect are worth an extra LLM pass. Everything else stays deterministic.
   */
  private hasStrongPreVerificationSignal(
    run: Run,
    findingRow: { finding: Finding },
    specRow: ReplaySpecRow,
    feedback?: InlineVerifyFeedback | null,
  ): boolean {
    if (specRow.spec.kind === 'static_ast_proof') return false
    if (findingRow.finding.codeLocations?.length) return true
    if (feedback?.canaryTriggered === true) return true
    // A vertical-BFLA proof that only missed impact is repairable by adding a role-differential or
    // mutation step, so it is worth one bounded Phase-3 reasoning pass.
    if ((feedback as { impactEvidenceMissing?: boolean } | undefined)?.impactEvidenceMissing === true) return true
    const controlPassed = feedback?.controlPassed === true
    const differentialKinds = new Set([
      'sql_boolean_diff', 'sql_time_diff', 'cache_differential', 'auth_protocol_proof', 'rce_proof', 'race_burst',
    ])
    if (controlPassed && differentialKinds.has(specRow.spec.kind)) return true

    const linkedIds = new Set(findingRow.finding.chainFactIds ?? [])
    if (linkedIds.size === 0) return false
    let facts: Fact[] = []
    try {
      facts = this.storage.listFacts(run.id, { includeTainted: false, limit: 500 })
    } catch {
      return false
    }
    const multiPersona = run.capabilityTier >= 2
    for (const fact of facts) {
      if (!linkedIds.has(fact.id)) continue
      const subkind = typeof fact.data?.subkind === 'string' ? fact.data.subkind : ''
      if (subkind === 'code_audit_suspect' || subkind === 'second_order_surface') return true
      if ((fact.kind as string) === 'cve_hypothesis') return true
      if (fact.kind === 'dns' || fact.kind === 'tls') return true
      if (fact.data?.triggered === true || fact.data?.anomaly === true || fact.data?.differential === true) return true
      if (multiPersona && subkind === 'persona_resource') return true
    }
    return false
  }

  private async waitForTier3Approval(
    job: Active,
    input: {
      origin: string
      method: string
      pathAndQuery: string
      personaHandle?: string | null
      rationale: string
      requestPreview: string
      bodyPreview?: string | null
      headers?: Record<string, string>
      hasMultipart?: boolean
      isRceProof?: boolean
      isRaceBurst?: boolean
      secrets: readonly NamedSecret[]
    },
    signal: AbortSignal,
  ): Promise<{ approved: boolean; deniedReason?: string }> {
    const run = this.check(job)
    const project = this.storage.project(run.projectId)
    if (run.capabilityTier < 3) {
      throw new BrokerDenied('This operation requires Capability Tier 3.')
    }

    // NOTE: local-lab auto-approval is decided exclusively below by evaluateTier3Approval so
    // that every auto-approved action is origin-bound, respects an explicit `strict` policy,
    // and is persisted as an audit record attributed to 'auto-review:local-lab'.

    const activePatterns = (run.approvedEndpointPatterns ?? []).filter(
      p => p.scopeRevision === undefined || p.scopeRevision === run.scopeRevision,
    )
    const evaluation = await evaluateTier3Approval({
      policy: run.approvalPolicy ?? 'auto_review',
      origin: input.origin,
      method: input.method,
      pathAndQuery: input.pathAndQuery,
      personaHandle: input.personaHandle ?? null,
      rationale: input.rationale,
      bodyPreview: input.bodyPreview ?? null,
      headers: input.headers,
      hasMultipart: input.hasMultipart,
      isRceProof: input.isRceProof,
      isRaceBurst: input.isRaceBurst,
      environment: project.environment,
      approvedPatterns: activePatterns,
      profiles: resolveProfilePoolForRole('fast', this.storage),
      signal,
      secrets: input.secrets,
      onUsage: usage => {
        this.storage.recordLlmSpend(run.id, {
          usd: usage.costUsd,
          tokens: usage.inputTokens + usage.outputTokens,
        })
      },
    })

    if (evaluation.decision === 'approve') {
      this.storage.recordAutoApprovalDecision(run, job.assignment, {
        origin: input.origin,
        method: input.method,
        pathAndQuery: input.pathAndQuery,
        personaHandle: input.personaHandle,
        rationale: input.rationale,
        requestPreview: input.requestPreview,
        decision: 'approved',
        decidedBy: evaluation.decidedBy === 'operator' ? 'auto-review:rule' : evaluation.decidedBy,
        riskLevel: evaluation.riskLevel,
        policyNote: evaluation.reason,
        secrets: input.secrets,
      })
      return { approved: true }
    }

    if (evaluation.decision === 'deny') {
      this.storage.recordAutoApprovalDecision(run, job.assignment, {
        origin: input.origin,
        method: input.method,
        pathAndQuery: input.pathAndQuery,
        personaHandle: input.personaHandle,
        rationale: input.rationale,
        requestPreview: input.requestPreview,
        decision: 'denied',
        decidedBy: 'auto-review:judge',
        riskLevel: evaluation.riskLevel,
        policyNote: evaluation.reason,
        secrets: input.secrets,
      })
      return { approved: false, deniedReason: evaluation.reason }
    }

    const approvalKey = [
      run.id,
      run.scopeRevision,
      input.origin,
      input.method.toUpperCase(),
      input.pathAndQuery,
      input.personaHandle ?? '',
      input.isRceProof ? 'rce' : '',
      input.isRaceBurst ? 'race' : '',
      input.bodyPreview ?? '',
    ].join('\0')
    if (this.pendingTier3ApprovalKeys.has(approvalKey)) {
      return {
        approved: false,
        deniedReason: 'An identical Tier 3 probe is already awaiting operator approval; duplicate parallel trial suppressed.',
      }
    }
    this.pendingTier3ApprovalKeys.add(approvalKey)

    let decision: 'approved' | 'denied' | 'canceled' | 'expired'
    let postedApprovalId: string | undefined
    try {
      const req = this.storage.createApprovalRequest(run, job.assignment, {
        origin: input.origin,
        method: input.method,
        pathAndQuery: input.pathAndQuery,
        personaHandle: input.personaHandle,
        rationale: input.rationale,
        requestPreview: input.requestPreview,
        policyNote: evaluation.reason,
        riskLevel: evaluation.riskLevel,
        secrets: input.secrets,
      })
      postedApprovalId = req.id
      this.postApprovalCard(run, job.assignment.id, {
        approvalId: req.id,
        origin: input.origin,
        method: input.method,
        pathAndQuery: input.pathAndQuery,
        rationale: input.rationale,
      }, input.secrets)

      decision = await new Promise<'approved' | 'denied' | 'canceled' | 'expired'>((resolveDecision, rejectDecision) => {
        const checkCurrent = () => {
          try {
            const latest = this.storage.getApprovalRequest(run.id, req.id)
            if (latest.status !== 'pending') {
              cleanup()
              resolveDecision(latest.status)
              return true
            }
            if (Date.now() >= latest.expiresAt) {
              this.storage.db.update(approvalRequests).set({ status: 'expired', decidedAt: Date.now() })
                .where(eq(approvalRequests.id, req.id)).run()
              cleanup()
              resolveDecision('expired')
              return true
            }
          } catch (err) {
            cleanup()
            rejectDecision(err)
            return true
          }
          return false
        }

        const unsub = this.storage.onRunEvent(run.id, () => { checkCurrent() })
        const timer = setInterval(() => { checkCurrent() }, 1_000)
        timer.unref?.()
        const onAbort = () => {
          cleanup()
          rejectDecision(signal.reason instanceof Error ? signal.reason : new Error('Aborted while waiting for approval.'))
        }
        const cleanup = () => {
          unsub()
          clearInterval(timer)
          signal.removeEventListener('abort', onAbort)
        }
        signal.addEventListener('abort', onAbort, { once: true })
        if (signal.aborted) {
          onAbort()
          return
        }
        checkCurrent()
      })
    } finally {
      this.pendingTier3ApprovalKeys.delete(approvalKey)
    }

    if (postedApprovalId) {
      this.postApprovalResolution(run, job.assignment.id, {
        approvalId: postedApprovalId,
        decision,
        origin: input.origin,
        method: input.method,
        pathAndQuery: input.pathAndQuery,
      })
    }
    if (this.authorize(job)) {
      this.storage.updateWorker(job.assignment.id, { status: 'running' })
    }
    return { approved: decision === 'approved' }
  }

  // --- Event-Driven Scheduler ---

  wake() {
    if (this.stopped) return
    // 0. Mirror roster state and retire warm members on stop/scope revocation.
    for (const runId of [...this.trackedBoardRuns]) {
      try { this.syncBoardRoster(this.storage.run(runId)) } catch { this.trackedBoardRuns.delete(runId) }
    }

    // 1. Revoke/abort any active job that lost authorization
    for (const [id, job] of this.active) {
      if (this.authorize(job)) continue
      job.controller.abort()
      try {
        const current = this.storage.worker(id)
        if ((current.status === 'running' || current.status === 'waiting_approval') && current.lease === job.assignment.lease) {
          this.storage.transaction(() => {
            this.storage.updateWorker(id, { status: 'canceled', lease: null, leaseExpiresAt: null, outcome: 'Assignment authorization changed.' })
            this.storage.event(current.runId, 'worker.canceled', 'Assignment canceled after scope or status change.', { assignmentId: id })
          })
        }
      } catch { /* ignore */ }
    }

    for (const [runId, task] of this.coordinator) {
      if (!this.currentCoordinator(runId, task)) task.controller.abort()
    }
    for (const [runId, task] of this.threatModeling) {
      if (!this.currentCoordinator(runId, task)) task.controller.abort()
    }
    for (const [runId, task] of this.plannerTasks) {
      if (!this.currentCoordinator(runId, task)) task.controller.abort()
    }

    // Stop background login-persona session refreshers for any run that paused, stopped, failed, or completed
    for (const runId of [...this.runAuthStarted.keys()]) {
      try {
        const current = this.storage.run(runId)
        if (current.status !== 'running' || current.phase === 'complete') {
          this.personaAuth.stopRunRefreshers(runId)
          this.runAuthStarted.delete(runId)
        }
      } catch {
        this.personaAuth.stopRunRefreshers(runId)
        this.runAuthStarted.delete(runId)
      }
    }
    for (const [runId, ctrl] of [...this.runAuthInFlight.entries()]) {
      try {
        const current = this.storage.run(runId)
        if (current.status !== 'running') {
          ctrl.abort()
        }
      } catch {
        ctrl.abort()
      }
    }

    // Tear down LabRunner containers for any runs no longer active
    for (const runId of [...this.startedLabRuns]) {
      try {
        const current = this.storage.run(runId)
        if (current.status === 'complete' || current.status === 'failed' || current.status === 'stopped') {
          this.startedLabRuns.delete(runId)
          this.startedLabHandles.delete(runId)
          void this.labRunner.stopLabTarget(runId).catch(() => undefined)
        }
      } catch {
        this.startedLabRuns.delete(runId)
        this.startedLabHandles.delete(runId)
        void this.labRunner.stopLabTarget(runId).catch(() => undefined)
      }
    }

    // 2. Dispatch pending one-click Verify Fix retests (works even on completed runs, Zero-LLM!)
    for (const run of this.storage.runsWithPendingRetests()) {
      const retests = this.storage.workerList(run.id).filter(w => w.phase === 'retest' && w.status === 'queued')
      for (const worker of retests) {
        if (this.active.has(worker.id)) continue
        this.startRetestWorker(run, worker)
      }
    }

    // 3. Process runnable runs
    const profiles = privateModelProfiles(this.storage)
    for (const run of this.storage.runnable()) {
      if (this.storage.checkBudgetExceeded(run.id)) continue
      this.ensureVariantSweepsForConfirmedFindings(run)
      this.routeOperatorBoardMessages(run)

      if (profiles.length) {
        this.startCoordinator(run, profiles)
      }

      if (
        run.capabilityTier >= 2 &&
        run.approvedPersonaIds.length > 0 &&
        (run.phase === 'threat_model' || run.phase === 'investigation' || run.phase === 'verification') &&
        this.needsLoginPersonaAuth(run)
      ) {
        this.ensureRunPersonasAuthenticated(run)
        continue
      }

      if (run.phase === 'threat_model') {
        if (!this.threatModeling.has(run.id)) {
          this.startThreatModel(run, profiles)
        }
        continue
      }

      if (run.phase === 'investigation') {
        this.driveInvestigation(run, profiles)
        continue
      }

      if (run.phase === 'verification') {
        this.driveVerification(run)
        continue
      }
    }
  }

  private runAuthKey(run: Run): string {
    return `${run.scopeRevision}:${[...run.approvedPersonaIds].sort().join(',')}`
  }

  private needsLoginPersonaAuth(run: Run): boolean {
    const key = this.runAuthKey(run)
    if (this.runAuthStarted.get(run.id) === key) return false
    try {
      const resolved = resolveRunPersonas(this.storage, run.projectId, run.approvedPersonaIds)
      return [...resolved.values()].some(p => p.authKind === 'login')
    } catch {
      return false
    }
  }

  private ensureRunPersonasAuthenticated(run: Run): void {
    if (this.runAuthInFlight.has(run.id)) return
    const key = this.runAuthKey(run)
    const controller = new AbortController()
    this.runAuthInFlight.set(run.id, controller)

    void this.personaAuth.startRunRefreshers(
      this.storage,
      run.id,
      run.projectId,
      run.approvedPersonaIds,
      controller.signal,
    ).then(() => {
      try {
        const current = this.storage.run(run.id)
        if (current.status === 'running' && this.runAuthKey(current) === key) {
          this.runAuthStarted.set(run.id, key)
        } else {
          this.personaAuth.stopRunRefreshers(run.id)
        }
      } catch {
        this.personaAuth.stopRunRefreshers(run.id)
      }
    }).catch(error => {
      this.personaAuth.stopRunRefreshers(run.id)
      if (controller.signal.aborted) return
      let secrets: NamedSecret[] = []
      try {
        secrets = personaSecrets(resolveRunPersonas(this.storage, run.projectId, run.approvedPersonaIds))
      } catch {
        secrets = []
      }
      const msg = redact(error instanceof Error ? error.message : String(error), secrets).slice(0, 320)
      try {
        this.storage.transaction(() => {
          const current = this.storage.run(run.id)
          if (current.status !== 'running') return
          this.storage.setStatus(current, 'paused')
          this.storage.event(run.id, 'persona.auth_failed', `Persona login failed; run paused: ${msg}`, {
            error: msg,
          })
          this.storage.message(
            run.id,
            run.coordinatorId,
            'guardian',
            `Paused run because Email + Password persona authentication failed: ${msg}`,
          )
        })
      } catch {
        // Ignore if run/storage closed
      }
    }).finally(() => {
      this.runAuthInFlight.delete(run.id)
      this.scheduleWake()
    })
  }

  // --- Phase 1: Round-0 Threat Model & Initial Baseline Checks ---

  private startThreatModel(run: Run, profiles: readonly ResolvedModelProfile[]) {
    const controller = new AbortController()
    const task: CoordinatorTask = { controller, goalRevision: run.goalRevision, scopeRevision: run.scopeRevision }
    this.threatModeling.set(run.id, task)
    void this.runThreatModel(run, profiles, task).catch(error => {
      if (!this.currentCoordinator(run.id, task)) return
      const msg = redact(error instanceof Error ? error.message : String(error)).slice(0, 300)
      this.storage.transaction(() => {
        const current = this.storage.run(run.id)
        this.storage.setStatus(current, 'failed')
        this.storage.event(run.id, 'threat_model.failed', `Threat modeling failed: ${msg}`)
        this.storage.writeReport(this.storage.run(run.id), true)
      })
    }).finally(() => {
      this.threatModeling.delete(run.id)
      this.scheduleWake()
    })
  }

  private async runThreatModel(run: Run, profiles: readonly ResolvedModelProfile[], task: CoordinatorTask) {
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
            onUsage: u => this.storage.recordLlmSpend(run.id, { usd: u.costUsd, tokens: u.inputTokens + u.outputTokens }),
            onProfileSuccess: id => recordProfileSuccess(id, this.storage),
            onProfileFailure: (id, err, hard) => recordProfileFailure(id, err, hard, this.storage),
          })
          selection = parseReviewPlan(answer, available) ?? selection
        } catch {
          // Fall back cleanly to standard checks
        }
      }
      if (!this.currentCoordinator(run.id, task)) return
      this.storage.commitReviewPlan(run, selection)
    }

    const freshRun = this.storage.run(run.id)
    const tmWorker = this.storage.makeWorker(freshRun, 'threat_model', approvedAssets[0],
      'Round-0 Threat Model & Surface Ranking',
      `Rank ${approvedAssets.length} approved hosts by attack-surface richness and seed prioritized chain investigation steps.`, {
        sourceOrigins: [...approvedOrigins],
      })
    const claimed = this.storage.updateWorker(tmWorker.id, {
      status: 'running', lease: randomUUID(), leaseExpiresAt: Date.now() + 10 * 60_000,
    })!
    const job: Active = { assignment: claimed, origins: new Set(approvedOrigins), controller: task.controller }
    this.active.set(claimed.id, job)

    try {
      let { grant, secrets } = this.buildGrant(job, freshRun, approvedOrigins)
      const specs = this.storage.listProjectSpecsFull(freshRun.projectId)
      const { reposDir, mountedRepos } = this.projectReposMount(freshRun.projectId)

      // 0a. Optional LabRunner boot when local-lab project has labConfig.enabled
      try {
        const project = this.storage.project(freshRun.projectId)
        if (
          project.environment === 'local-lab' &&
          project.labConfig?.enabled &&
          isLocalLabEnvEnabled() &&
          !this.startedLabRuns.has(freshRun.id) &&
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
            this.startedLabRuns.add(freshRun.id)
            this.startedLabHandles.set(freshRun.id, handle)
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
              const refreshed = this.buildGrant(job, this.storage.run(freshRun.id), approvedOrigins)
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
      if (!freshRun.phase0CompletedAt && approvedOrigins.size > 0 && this.authorize(job)) {
        try {
          await runPhase0Recon({
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
              const saved = this.storage.recordExchange({
                runId: freshRun.id,
                assignmentId: claimed.id,
                scopeRevision: freshRun.scopeRevision,
                origin: ex.origin,
                finalOrigin: ex.finalOrigin,
                redirectOrigins: ex.redirectOrigins,
                method: ex.method,
                pathAndQuery: ex.pathAndQuery,
                personaHandle: ex.personaHandle,
                status: ex.status,
                mediaType: ex.mediaType,
                reqHeaders: ex.reqHeaders,
                respHeaders: ex.respHeaders,
                body: ex.body,
                durationMs: ex.durationMs,
                secretMatches: ex.secretMatches,
                secrets,
              })
              return saved.id
            },
          })
          this.storage.updateRunDynamicStepBudget(freshRun.id, computeDynamicStepBudget(this.storage, freshRun.id))
        } catch {
          // Phase-0 failure must not block threat model progression
        }
      }

      // 1. Correlate dependencies from uploaded/synced specs via CVE broker
      const seenDeps = new Set<string>()
      let advisoryLookups = 0
      for (const spec of specs) {
        const deps = parseDependenciesFromFile(spec.name.split(':').pop() ?? spec.name, spec.content)
        // Also parse `:dependencies` note format generated by github-connector
        for (const match of spec.content.matchAll(/^([a-zA-Z0-9_.-]+):([@a-zA-Z0-9_./-]+)@([0-9][0-9A-Za-z.+-]*)/gm)) {
          deps.push({ ecosystem: match[1], package: match[2], version: match[3], sourceFile: spec.name })
        }
        for (const dep of deps) {
          // Every parsed dependency is a candidate (no JS-only high-signal allowlist).
          if (!dep.package || !dep.version) continue
          const key = `${dep.ecosystem}:${dep.package}:${dep.version}`
          if (seenDeps.has(key)) continue
          seenDeps.add(key)
          if (advisoryLookups >= 120) break
          advisoryLookups += 1
          try {
            const advisories = await queryCves({ ecosystem: dep.ecosystem, package: dep.package, version: dep.version }, task.controller.signal)
            // Whether the advisory came from the curated offline corpus or a remote feed matters to
            // the operator (offline workers cannot fetch live feeds).
            const curated = hasCuratedAdvisory(dep.ecosystem, dep.package)
            for (const adv of advisories.slice(0, 3)) {
              const targetOrigin = spec.origin && approvedOrigins.has(spec.origin)
                ? spec.origin
                : approvedAssets[0]?.origin
              if (!targetOrigin) continue
              this.storage.addFact(freshRun, claimed, {
                kind: 'cve_hypothesis',
                origin: targetOrigin,
                summary: `${adv.id} (${adv.severity}) hypothesis for ${dep.package}@${dep.version} from ${spec.name}: ${adv.summary}`,
                data: {
                  cveId: adv.id,
                  package: dep.package,
                  version: dep.version,
                  ecosystem: dep.ecosystem,
                  severity: adv.severity,
                  safeVerificationHint: adv.safeVerificationHint,
                  sourceSpec: spec.name,
                  curatedAdvisory: curated,
                  confidence: 'low',
                },
                sourceOrigins: [targetOrigin],
                secrets,
              })
            }
          } catch { /* advisory lookup is best-effort */ }
        }
      }

      // 2. Capture initial lightweight baseline observations for approved hosts
      const observations: Record<string, unknown>[] = []
      const selectedChecks: readonly AssessmentCheckId[] = freshRun.reviewPlan?.status === 'ready'
        ? freshRun.reviewPlan.checks : responseCheckIds
      const responseChecks = selectedChecks.filter(c => c !== 'access-policy') as ResponseCheckId[]

      for (const asset of approvedAssets) {
        if (!this.authorize(job)) break
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

            if (cachedPhase0Root) {
              capture = { observation: cachedPhase0Root.observation, note: 'Recorded approved HTTPS root response.' }
              observations.push({
                origin: asset.origin,
                finalOrigin: cachedPhase0Root.finalOrigin,
                status: cachedPhase0Root.status,
                mediaType: cachedPhase0Root.mediaType,
                server: cachedPhase0Root.respHeaders['server'],
                poweredBy: cachedPhase0Root.respHeaders['x-powered-by'],
              })
            } else if (priorRootRow) {
              let headersObj: Record<string, string> = {}
              try { headersObj = JSON.parse(priorRootRow.respHeadersJson) as Record<string, string> } catch { /* ignore */ }
              const h = (name: string): string | undefined => headersObj[name.toLowerCase()]
              const transport = h('strict-transport-security') ?? ''
              const ages = transport.split(';').filter(d => /^\s*max-age\s*(?:=|$)/i.test(d))
              const parsedAge = ages.length === 1 ? ages[0].match(/^\s*max-age\s*=\s*(?:"(\d+)"|(\d+))\s*$/i) : null
              const maxAge = parsedAge ? Number(parsedAge[1] ?? parsedAge[2]) : NaN
              const xcto = h('x-content-type-options')
              const nosniff = xcto?.split(',', 1)[0].trim().toLowerCase() === 'nosniff'
              const cspVal = h('content-security-policy')
              const cspRo = h('content-security-policy-report-only')
              const xfo = h('x-frame-options')
              const frameAncestors = Boolean(cspVal && /(?:^|;)\s*frame-ancestors\s+[^;]+/i.test(cspVal))
              const validXfo = Boolean(xfo && /^(?:deny|sameorigin)\s*$/i.test(xfo.split(',', 1)[0]))
              const refRaw = h('referrer-policy')
              const validRefs = ['no-referrer', 'no-referrer-when-downgrade', 'origin', 'origin-when-cross-origin', 'same-origin', 'strict-origin', 'strict-origin-when-cross-origin', 'unsafe-url'] as const
              const refPolicy: PublicObservation['referrerPolicy'] = refRaw === undefined
                ? 'absent'
                : refRaw.includes('"')
                  ? 'unrecognized'
                  : (refRaw.split(',').map(t => t.trim()).findLast((t): t is typeof validRefs[number] => (validRefs as readonly string[]).includes(t)) ?? 'unrecognized')
              const srv = h('server')?.trim()
              capture = {
                observation: {
                  origin: priorRootRow.origin,
                  finalOrigin: priorRootRow.finalOrigin,
                  status: priorRootRow.status,
                  mediaType: priorRootRow.mediaType || 'unknown',
                  transportMaxAge: Number.isSafeInteger(maxAge) && maxAge >= 0 ? maxAge : null,
                  includeSubDomains: /(?:^|;)\s*includeSubDomains\s*(?:;|$)/i.test(transport),
                  source: 'public response',
                  contentTypeOptions: xcto === undefined ? 'absent' : nosniff ? 'nosniff' : 'unrecognized',
                  referrerPolicy: refPolicy,
                  contentSecurityPolicy: cspVal !== undefined ? (cspVal.trim() ? 'enforced' : 'unrecognized') : cspRo !== undefined ? (cspRo.trim() ? 'report-only' : 'unrecognized') : 'absent',
                  frameProtection: frameAncestors && validXfo ? 'both' : frameAncestors ? 'csp-frame-ancestors' : validXfo ? 'x-frame-options' : xfo !== undefined ? 'unrecognized' : 'absent',
                  serverDisclosure: h('x-powered-by') ? 'technology' : !srv ? 'absent' : /(?:\d|\/|next|express|php|asp\.net|nginx|apache)/i.test(srv) ? 'technology' : 'generic',
                },
                note: 'Reused recorded approved HTTPS root response.',
              }
              observations.push({
                origin: asset.origin,
                finalOrigin: priorRootRow.finalOrigin,
                status: priorRootRow.status,
                mediaType: priorRootRow.mediaType,
                server: headersObj['server'],
                poweredBy: headersObj['x-powered-by'],
                exchangeId: priorRootRow.id,
              })
            } else {
              const ex = await this.broker.executeHttp({
                origin: asset.origin,
                method: 'GET',
                pathAndQuery: '/',
                followRedirects: true,
                timeoutMs: 12_000,
              }, grant, task.controller.signal)
              const savedEx = this.storage.recordExchange({
                runId: freshRun.id,
                assignmentId: hostWorker.id,
                scopeRevision: freshRun.scopeRevision,
                origin: ex.origin,
                finalOrigin: ex.finalOrigin,
                redirectOrigins: ex.redirectOrigins,
                method: ex.method,
                pathAndQuery: ex.pathAndQuery,
                personaHandle: ex.personaHandle,
                status: ex.status,
                mediaType: ex.mediaType,
                reqHeaders: ex.reqHeaders,
                respHeaders: ex.respHeaders,
                body: ex.body,
                durationMs: ex.durationMs,
                secretMatches: ex.secretMatches,
                secrets,
              })
              capture = { observation: ex.observation, note: 'Recorded approved HTTPS root response.' }
              observations.push({
                origin: asset.origin,
                finalOrigin: ex.finalOrigin,
                status: ex.status,
                mediaType: ex.mediaType,
                server: ex.respHeaders['server'],
                poweredBy: ex.respHeaders['x-powered-by'],
                exchangeId: savedEx.id,
              })
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
              const earlier = this.baselineFinding(freshRun, asset, rev)
              this.saveBaselineFinding(freshRun, asset, rev, 'pending',
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
          const personasPub = [...grant.personas?.values() ?? []].map(p => ({
            handle: p.handle, roleLabel: p.roleLabel, originAllowlist: p.originAllowlist,
          }))
          const graphCatalog = this.endpointGraphCatalog(freshRun.id)
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
            onUsage: u => this.storage.recordLlmSpend(freshRun.id, { usd: u.costUsd, tokens: u.inputTokens + u.outputTokens }),
            onProfileSuccess: id => recordProfileSuccess(id, this.storage),
            onProfileFailure: (id, err, hard) => recordProfileFailure(id, err, hard, this.storage),
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

      if (!this.authorize(job)) return

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

      // 4. Priority #1: Dedicated Source-First Code Audit Phase BEFORE live HTTP investigation rounds
      let codeAuditStepsCreated = 0
      if (mountedRepos.length > 0 && freshRun.capabilityTier > 0 && profiles.length > 0 && this.authorize(job)) {
        try {
          const auditResult = await this.runSourceFirstCodeAudit(
            this.storage.run(freshRun.id),
            finalEntries,
            profiles,
            task.controller.signal,
          )
          codeAuditStepsCreated = auditResult.stepsCreated.length
        } catch {
          // Code audit failure should not block live investigation rounds
        }
      }

      if (!this.authorize(job)) return

      // Ensure at least initial investigation steps exist when Tier >= 1
      if (!seededSteps.length && freshRun.capabilityTier > 0 && approvedAssets.length > 0) {
        const topHosts = finalEntries.slice(0, Math.min(8, finalEntries.length))
        seededSteps = topHosts.map((entry, idx) => {
          const tier = finalHostTiers[entry.origin] ?? classifyHostTier(entry.origin, entry.surfaceTags)
          return {
            title: `Surface & chain investigation · ${new URL(entry.origin).hostname}`,
            hypothesis: `Harvest JS/API routes, inspect DNS/TLS/CORS/auth headers, fingerprint stack & CVEs, and verify any candidate vulnerabilities on ${entry.origin} (${entry.surfaceTags.join(', ')}).`,
            category: entry.surfaceTags.includes('auth') ? 'auth-identity'
              : entry.surfaceTags.includes('api') ? 'broken-access-control'
                : entry.surfaceTags.includes('upload') ? 'upload-storage'
                  : entry.surfaceTags.includes('llm-proxy') ? 'llm-ai-security'
                    : 'misconfig-exposure',
            priority: tier === 'low_value_static' ? 30 : Math.max(55, 95 - idx * 6),
            origins: [entry.origin],
            skills: ['recon-modern-spa', 'cve-runtime-correlation', 'false-positive-elimination'],
          }
        })
      }

      this.storage.transaction(() => {
        const current = this.storage.run(freshRun.id)
        if (current.status !== 'running' || current.phase !== 'threat_model') return

        const existingSteps = this.storage.listChainSteps(current.id, current.goalRevision)
        const remainingInitialSlots = Math.max(0, 12 - existingSteps.length)
        const budgetedSteps = applyCrownJewelStepBudget(
          seededSteps.map(step => ({ ...step, origins: step.origins.filter(o => approvedOrigins.has(o)) })),
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
        this.expandEligibleMultiTrialSteps(current)
        this.storage.updateRunDynamicStepBudget(current.id, computeDynamicStepBudget(this.storage, current.id))

        const totalQueued = codeAuditStepsCreated + addedInitial
        this.completeWorker(claimed, current, tmSummary, [savedTm.tmArtifact.id], undefined, secrets)
        const deterministicMode = !profiles.length && current.capabilityTier > 0
        const nextPhase = current.capabilityTier === 0 ? 'verification' : 'investigation'
        this.storage.updateRun(current.id, { phase: nextPhase })
        this.storage.event(current.id, `${nextPhase}.started`,
          nextPhase === 'investigation'
            ? deterministicMode
              ? 'Threat model complete (no model profile configured). Starting bounded deterministic differential probing.'
              : `Threat model complete${codeAuditStepsCreated ? ` (${codeAuditStepsCreated} source-audit steps + ${addedInitial} initial steps)` : ` (${totalQueued} initial steps)`}. Starting closed-loop chain investigation.`
            : 'Baseline captures complete. Starting deterministic Zero-LLM verification.')
        this.storage.message(current.id, current.coordinatorId, 'guardian',
          nextPhase === 'investigation'
            ? deterministicMode
              ? `Threat model ranked ${finalEntries.length} hosts. No model profile is configured, so Guardian will run a bounded deterministic probe pass over discovered endpoints instead of agentic investigation.`
              : `Threat model ranked ${finalEntries.length} hosts and queued ${totalQueued} initial investigation steps${codeAuditStepsCreated ? ` (including ${codeAuditStepsCreated} from Source-First Code Audit)` : ''}.`
            : 'Baseline capture complete. Deterministic verification is checking the recorded evidence.')
      }, { behavior: 'immediate' })
    } finally {
      this.active.delete(claimed.id)
    }
  }

  // --- Phase 1B: Source-First Code Audit (Mounted /repos BEFORE live HTTP rounds) ---

  async runSourceFirstCodeAudit(
    run: Run,
    threatModel: readonly ThreatModelSummary[],
    profiles: readonly ResolvedModelProfile[],
    signal: AbortSignal,
  ): Promise<{ suspects: Fact[]; stepsCreated: ChainStep[] }> {
    const { reposDir, mountedRepos } = this.projectReposMount(run.projectId)
    if (!reposDir || !mountedRepos.length || !profiles.length || run.capabilityTier === 0) {
      return { suspects: [], stepsCreated: [] }
    }
    const approvedAssets = run.candidates.filter(c => run.approved.includes(c.id))
    const approvedOrigins = new Set(approvedAssets.map(a => a.origin))
    if (!approvedOrigins.size) return { suspects: [], stepsCreated: [] }

    const auditMaxTurns = Math.max(6, Math.min(run.workerMaxTurns || defaultCodeAuditMaxTurns, defaultCodeAuditMaxTurns))
    const auditPhase = run.phase === 'investigation' ? 'investigation' : 'threat_model'
    const auditWorker = this.storage.makeWorker(
      run,
      auditPhase,
      approvedAssets[0],
      `Source-First Code Audit · ${mountedRepos.slice(0, 2).join(', ')}`,
      `Inspect read-only mounted source repositories (${mountedRepos.join(', ')}) under /repos before live HTTP probing to build a Route/Server Action/Webhook Authz Matrix and record code_audit_suspect facts.`,
      { maxTurns: auditMaxTurns, sourceOrigins: [...approvedOrigins] },
    )
    const claimed = this.storage.updateWorker(auditWorker.id, {
      status: 'running',
      lease: randomUUID(),
      leaseExpiresAt: Date.now() + 10 * 60_000,
    })!
    const controller = new AbortController()
    const onParentAbort = () => controller.abort(signal.reason)
    signal.addEventListener('abort', onParentAbort, { once: true })
    if (signal.aborted) controller.abort(signal.reason)

    const job: Active = { assignment: claimed, origins: new Set(approvedOrigins), controller }
    this.active.set(claimed.id, job)
    this.storage.event(run.id, 'code_audit.started', `Source-First Code Audit started across ${mountedRepos.length} mounted ${mountedRepos.length === 1 ? 'repo' : 'repos'}.`, {
      assignmentId: claimed.id, mountedRepos,
    })

    const { grant, secrets, currentSecrets } = this.buildGrant(job, run, approvedOrigins)
    const session = await this.backend.openSession(claimed.id, controller.signal, { reposDir })
    const startedAt = Date.now()

    try {
      const specs = this.storage.listProjectSpecsFull(run.projectId)
      const stagedSpecs: Array<{ name: string; kind: string; origin?: string | null; stagedPath?: string }> = []
      for (const [idx, spec] of specs.slice(0, 8).entries()) {
        try {
          const stagedPath = await session.stage(`specs/spec-${idx + 1}.txt`, spec.content.slice(0, 1_500_000), controller.signal)
          stagedSpecs.push({ name: spec.name, kind: spec.kind, origin: spec.origin, stagedPath })
        } catch { /* skip oversized */ }
      }

      const handlers: WorkerToolHandlers = {
        spillOutput: async (id, content, sig) => session.stage(`tool-output/${id}.txt`, content, sig),
        derive_evidence: async ({ command, outputs, timeoutMs }, sig) => {
          const curRun = this.check(job)
          const res = await session.exec(command, outputs ?? ['result.txt'], sig, timeoutMs ?? 60_000)
          const ev = this.storage.addArtifact(curRun, job.assignment, 'analysis', 'Code audit analysis',
            JSON.stringify({
              command: redact(command, secrets),
              exitStatus: res.exitCode,
              stdout: redact(res.stdout, secrets),
              stderr: redact(res.stderr, secrets),
              outputs: res.outputs,
            }, null, 2), undefined, secrets)
          return { evidenceId: ev.id, exitCode: res.exitCode, stdout: res.stdout, stderr: res.stderr, outputs: res.outputs }
        },
        analyze_artifact: async (args, sig) => {
          this.check(job)
          const { tool, ...rest } = args
          return await session.analyze(tool, rest, sig)
        },
        run_sast_scan: async (args, sig) => {
          const curRun = this.check(job)
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
        run_offline_script: async (args, sig) => {
          const curRun = this.check(job)
          const res = await session.runScript(args, sig)
          const ev = this.storage.addArtifact(curRun, job.assignment, 'analysis',
            `Offline ${args.runtime} script (code audit)`,
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
        query_cves: async (args, sig) => {
          this.check(job)
          const advisories = await queryCves(args, sig)
          return { count: advisories.length, advisories }
        },
        load_skill: async ({ name }) => {
          if (name.trim().toLowerCase() === 'list') return { skills: listSkills() }
          const skill = loadSkill(name)
          if (!skill) return { error: `Unknown skill "${name}".`, available: listSkills().map(s => s.name) }
          return skill
        },
        search_facts: async ({ query, origin, kind, limit }) => {
          const curRun = this.check(job)
          const currentApproved = this.approvedOriginsSet(curRun)
          return this.storage.listFacts(curRun.id, { includeTainted: false, query, origin, kind, limit })
            .filter(f => currentApproved.has(f.origin) && f.sourceOrigins.every(o => currentApproved.has(o)))
        },
        record_fact: async (args) => {
          const curRun = this.check(job)
          const currentApproved = this.approvedOriginsSet(curRun)
          const cleanOrigin = this.parseOriginForRun(curRun, args.origin)
          if (!currentApproved.has(cleanOrigin)) throw new BrokerDenied(`Origin ${cleanOrigin} is not approved.`)
          const fact = this.storage.addFact(curRun, job.assignment, {
            kind: args.kind,
            origin: cleanOrigin,
            summary: args.summary,
            data: args.data,
            exchangeIds: args.exchangeIds,
            evidenceIds: args.evidenceIds,
            sourceOrigins: args.sourceOrigins,
            secrets: currentSecrets(),
          })
          return { factId: fact.id, kind: args.kind, origin: fact.origin }
        },
        record_coverage: async (args) => {
          const curRun = this.check(job)
          const currentApproved = this.approvedOriginsSet(curRun)
          const cleanOrigin = this.parseOriginForRun(curRun, args.origin)
          if (!currentApproved.has(cleanOrigin)) throw new BrokerDenied(`Origin ${cleanOrigin} is not approved.`)
          const ext = args as typeof args & { enforcingControl?: string; proofGapReason?: string; linkedFindingId?: string }
          if (args.status === 'ruled_out' && !ext.enforcingControl?.trim()) {
            throw new Error('record_coverage with status "ruled_out" requires a non-empty enforcingControl (exact file:line or negative-control exchangeId proving the control runs on the attacker path).')
          }
          const entry = this.storage.upsertCoverageEntry(curRun, job.assignment.id, {
            origin: cleanOrigin,
            category: args.category,
            status: args.status,
            summary: args.summary,
            enforcingControl: ext.enforcingControl,
            proofGapReason: args.status === 'needs_follow_up' ? (ext.proofGapReason?.trim() || args.summary) : ext.proofGapReason,
            linkedFindingId: ext.linkedFindingId,
          })
          return { id: entry.id, origin: entry.origin, category: entry.category, status: entry.status }
        },
        complete_intent: async (completion) => ({ recorded: true, status: completion.status }),
      }

      const personasPub = [...grant.personas?.values() ?? []].map(p => ({
        handle: p.handle, roleLabel: p.roleLabel, originAllowlist: p.originAllowlist,
      }))

      // Stage 1-3 deterministic + semantic code audit pipeline (IRIS + call-graph + git history)
      try {
        const hostTiersForAudit = computeHostTiers([...approvedOrigins], threatModel)
        const semanticRes = await runThreeStageSemanticAudit({
          storage: this.storage,
          run,
          assignment: claimed,
          backend: this.backend,
          session,
          reposDir,
          mountedRepos,
          approvedOrigins: [...approvedOrigins],
          hostTiers: hostTiersForAudit,
          modelProfiles: resolveProfilePoolForRole('reasoning', profiles),
          signal: controller.signal,
          secrets: currentSecrets(),
          liveEndpoints: this.storage.listEndpoints(run.id)
            .filter(ep => approvedOrigins.has(ep.origin))
            .map(ep => ({ method: ep.method, path: ep.pathTemplate })),
          onUsage: usage => {
            this.storage.recordLlmSpend(run.id, {
              usd: usage.costUsd,
              tokens: usage.inputTokens + usage.outputTokens,
            })
          },
        }, {
          // Budgeted Stage-1 LLM spec + dynamic rule synthesis; opt out with GUARDIAN_STAGE1_LLM=0.
          enableStage1Llm: process.env.GUARDIAN_STAGE1_LLM !== '0',
          persistToStore: true,
        })
        const semanticSteps = toChainStepInputs(run, semanticRes.rankedSuspects, hostTiersForAudit, semanticRes.persistedFactIds)
        const existingTitles = new Set(this.storage.listChainSteps(run.id, run.goalRevision).map(s => s.title.trim().toLowerCase()))
        for (const stInput of semanticSteps) {
          const key = stInput.title.trim().toLowerCase()
          if (existingTitles.has(key)) continue
          this.storage.addChainStep(run, stInput)
          existingTitles.add(key)
        }
      } catch {
        // Semantic audit is additive; continue with interactive code auditor session
      }

      const sessionResult = await runAgentSession({
        directory: this.storage.directory,
        sessionId: claimed.sessionId,
        requestId: `code-audit:${run.id}:${run.goalRevision}:${run.scopeRevision}`,
        profiles: resolveProfilePoolForRole('reasoning', profiles),
        scenario: 'code-auditor',
        roleAffinity: 'reasoning',
        prompt: codeAuditPrompt({
          goal: run.goal,
          capabilityTier: run.capabilityTier,
          approvedOrigins: [...approvedOrigins],
          mountedRepos,
          personas: personasPub,
          specsSummary: stagedSpecs,
          threatModel,
          maxTurns: auditMaxTurns,
        }),
        signal: controller.signal,
        maxTurns: auditMaxTurns,
        compaction: true,
        enableSettlement: true,
        requireCompleteIntent: true,
        shouldSettle: () => (Date.now() - startedAt) >= 8 * 60_000,
        handlers,
        secrets,
        beforeCall: () => {
          this.check(job)
          if (this.storage.checkBudgetExceeded(run.id)) {
            throw new BudgetExceededError('Run spend or request budget exceeded.')
          }
        },
        onUsage: usage => {
          this.storage.recordLlmSpend(run.id, {
            usd: usage.costUsd,
            tokens: usage.inputTokens + usage.outputTokens,
          })
        },
        onTurn: turn => {
          this.storage.updateWorker(claimed.id, { turnsUsed: turn })
          this.storage.recordLlmSpend(run.id, { turns: 1 })
        },
        onProfileSuccess: id => recordProfileSuccess(id, this.storage),
        onProfileFailure: (id, err, hard) => recordProfileFailure(id, err, hard, this.storage),
      })

      const latestRun = this.storage.run(run.id)
      const suspects = this.storage.listFacts(run.id, { includeTainted: false, kind: 'code_audit_suspect', limit: 100 })
        .filter(f => approvedOrigins.has(f.origin))
      const hostTiers = computeHostTiers([...approvedOrigins], threatModel)
      const stepsCreated = convertCodeAuditSuspectsToChainSteps(this.storage, latestRun, suspects, hostTiers)

      const outcomeText = sessionResult.completion
        ? `[${sessionResult.completion.status}] ${sessionResult.completion.summary} (${suspects.length} suspects → ${stepsCreated.length} targeted chain steps)`
        : `Code audit finished: ${suspects.length} suspects converted into ${stepsCreated.length} targeted chain steps.`
      this.completeWorker(claimed, latestRun, outcomeText, [], undefined, currentSecrets())
      this.storage.event(run.id, 'code_audit.complete', `Source-First Code Audit recorded ${suspects.length} suspects and queued ${stepsCreated.length} targeted steps.`, {
        assignmentId: claimed.id, suspectsCount: suspects.length, stepsCreated: stepsCreated.length,
      })
      return { suspects, stepsCreated }
    } finally {
      signal.removeEventListener('abort', onParentAbort)
      this.active.delete(claimed.id)
      await session.close().catch(() => undefined)
    }
  }

  // --- Phase 2: Closed-Loop Investigation & Debounced Stateless Planner ---

  private expandEligibleMultiTrialSteps(run: Run) {
    if (run.multiTrialEnabled === false) return
    const conc = Math.max(1, run.workerConcurrency || defaultWorkerConcurrency)
    if (conc <= 1) return

    const steps = this.storage.listChainSteps(run.id, run.goalRevision)
    const highSignalFacts = new Set(
      this.storage.listFacts(run.id, { includeTainted: false, limit: 500 })
        .filter(f => {
          const kind = String(f.kind)
          const subkind = typeof f.data?.subkind === 'string' ? f.data.subkind : ''
          return kind === 'code_audit_suspect' || kind === 'cve_hypothesis' || subkind === 'code_audit_suspect' || subkind === 'cve_hypothesis'
        })
        .map(f => f.id),
    )

    for (const step of steps) {
      if (step.status !== 'pending' && step.status !== 'ready') continue
      if (step.trialGroupId) continue
      const fanout = computeMultiTrialFanout(run, step, highSignalFacts)
      if (fanout <= 1) continue

      const trialGroupId = randomUUID()
      this.storage.updateChainStep(step.id, { trialGroupId, trialIndex: 0 })
      for (let idx = 1; idx < fanout; idx += 1) {
        this.storage.addChainStep(run, {
          title: `${step.title.slice(0, 180)} [trial ${idx + 1}]`,
          hypothesis: step.hypothesis,
          category: step.category,
          priority: step.priority,
          targetAssetIds: step.targetAssetIds,
          skills: step.skills,
          dependsOnFactIds: step.dependsOnFactIds,
          dependsOnStepIds: step.dependsOnStepIds,
          sourceOrigins: step.sourceOrigins,
          specialistProfile: step.specialistProfile,
          trialGroupId,
          trialIndex: idx,
        })
      }
    }
  }

  private cancelSiblingTrialsOnConfirmation(run: Run, winningStepId: string | null, findingId?: string) {
    if (!winningStepId) return
    const steps = this.storage.listChainSteps(run.id, run.goalRevision)
    const winningStep = steps.find(s => s.id === winningStepId)
    if (!winningStep?.trialGroupId) return

    const siblings = steps.filter(s =>
      s.trialGroupId === winningStep.trialGroupId &&
      s.id !== winningStep.id &&
      ['pending', 'ready', 'running'].includes(s.status),
    )
    if (!siblings.length) return

    const canceledStepIds: string[] = []
    for (const sib of siblings) {
      this.storage.updateChainStep(sib.id, { status: 'canceled' })
      canceledStepIds.push(sib.id)
      if (sib.assignedWorkerId) {
        const activeSib = this.active.get(sib.assignedWorkerId)
        if (activeSib) {
          activeSib.controller.abort('trial.early_stopped')
        }
        try {
          const w = this.storage.worker(sib.assignedWorkerId)
          if (w.status === 'running' || w.status === 'queued' || w.status === 'waiting_approval') {
            this.storage.updateWorker(w.id, {
              status: 'canceled',
              lease: null,
              leaseExpiresAt: null,
              outcome: 'Canceled via multi-trial early stopping after sibling confirmation.',
            })
          }
        } catch { /* ignore */ }
      }
    }

    if (canceledStepIds.length > 0) {
      this.storage.event(
        run.id,
        'trial.early_stopped',
        `Early-stopped ${canceledStepIds.length} sibling trial(s) in group ${winningStep.trialGroupId} after Zero-LLM confirmation.`,
        {
          trialGroupId: winningStep.trialGroupId,
          winningStepId: winningStep.id,
          findingId: findingId ?? null,
          canceledStepIds,
        },
      )
    }
  }

  private ensureVariantSweepsForConfirmedFindings(run: Run) {
    const { reposDir, mountedRepos } = this.projectReposMount(run.projectId)
    if (!reposDir || mountedRepos.length === 0) return

    const confirmedRows = this.storage.db.select().from(findings).where(and(
      eq(findings.runId, run.id),
      eq(findings.goalRevision, run.goalRevision),
    )).all().filter(row =>
      (row.finding.status === 'confirmed' || row.finding.status === 'static_verified') &&
      (row.finding.codeLocations?.length ?? 0) > 0 &&
      !this.variantSweptFindings.has(row.id) &&
      !this.variantSweepInFlight.has(row.id),
    )

    for (const row of confirmedRows) {
      this.scheduleVariantSweepForFinding(run, row)
    }
  }

  private scheduleVariantSweepForFinding(
    run: Run,
    findingRow: typeof findings.$inferSelect,
  ) {
    if (this.variantSweptFindings.has(findingRow.id) || this.variantSweepInFlight.has(findingRow.id)) return
    const { reposDir, mountedRepos } = this.projectReposMount(run.projectId)
    if (!reposDir || mountedRepos.length === 0) return
    const locs = findingRow.finding.codeLocations ?? []
    if (locs.length === 0) return

    this.variantSweepInFlight.add(findingRow.id)
    void this.runPostConfirmationVariantSweep(run, findingRow, reposDir, mountedRepos)
      .catch(() => { /* best-effort variant sweep */ })
      .finally(() => {
        this.variantSweepInFlight.delete(findingRow.id)
        this.variantSweptFindings.add(findingRow.id)
        this.scheduleWake()
      })
  }

  private async runPostConfirmationVariantSweep(
    run: Run,
    findingRow: typeof findings.$inferSelect,
    reposDir: string,
    mountedRepos: readonly string[],
  ) {
    const locs = findingRow.finding.codeLocations ?? []
    const primaryLoc = locs[0]
    if (!primaryLoc) return

    const approvedOrigins = this.approvedOriginsSet(run)
    const targetOrigin = approvedOrigins.has(findingRow.finding.origin)
      ? findingRow.finding.origin
      : [...approvedOrigins][0]
    if (!targetOrigin) return
    const asset = run.candidates.find(c => c.origin === targetOrigin && run.approved.includes(c.id))
      ?? run.candidates.find(c => run.approved.includes(c.id))
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
    const primaryFilePath = join(reposDir, primaryLoc.repo, primaryLoc.file)
    if (existsSync(primaryFilePath)) {
      try {
        const lines = readFileSync(primaryFilePath, 'utf8').split('\n')
        const lineText = lines[Math.max(0, primaryLoc.startLine - 1)] ?? ''
        const callSig = /[A-Za-z_$][A-Za-z0-9_$]*\.[A-Za-z_$][A-Za-z0-9_$]*\s*\([^)]*\)/.exec(lineText)
        if (callSig && !searchTokens.includes(callSig[0])) searchTokens.push(callSig[0])
      } catch { /* ignore */ }
    }

    if (searchTokens.length > 0) {
      const scanExt = new Set(['.ts', '.tsx', '.js', '.jsx', '.mjs', '.cjs', '.py', '.go', '.java', '.rb'])
      for (const mountedRepo of mountedRepos) {
        const repoRel = mountedRepo.replace(/^\/repos\//, '').replace(/\/+$/, '')
        const repoRoot = join(reposDir, repoRel)
        if (!existsSync(repoRoot)) continue
        const stack = [repoRoot]
        while (stack.length > 0 && siblingHits.length < 20) {
          const dir = stack.pop()!
          let entries: string[]
          try { entries = readdirSync(dir) } catch { continue }
          for (const entry of entries) {
            if (entry === 'node_modules' || entry === '.git' || entry === 'dist' || entry === 'build') continue
            const full = join(dir, entry)
            let st
            try { st = statSync(full) } catch { continue }
            if (st.isDirectory()) {
              stack.push(full)
            } else if (st.isFile() && st.size <= 256 * 1024 && scanExt.has(extname(entry).toLowerCase())) {
              const relFile = relative(repoRoot, full).split(sep).join('/')
              let content: string
              try { content = readFileSync(full, 'utf8') } catch { continue }
              const lines = content.split('\n')
              for (let i = 0; i < lines.length; i += 1) {
                if (searchTokens.some(tok => lines[i].includes(tok))) {
                  const lineNo = i + 1
                  if (overlapsOriginal(repoRel, relFile, lineNo)) continue
                  const key = `${repoRel}:${relFile}:${lineNo}`
                  if (seenHit.has(key)) continue
                  seenHit.add(key)
                  siblingHits.push({ repo: repoRel, file: relFile, line: lineNo, preview: lines[i].trim().slice(0, 180) })
                }
              }
            }
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

  private driveInvestigation(run: Run, profiles: readonly ResolvedModelProfile[]) {
    if (!profiles.length) {
      // No model profile configured: run the bounded deterministic baseline so the run can still
      // produce real findings (see runDeterministicInvestigation). The agentic path is unchanged.
      this.driveDeterministicInvestigation(run)
      return
    }
    // Always compute & persist dynamic step budget clamp(24, crownJewels*2 + suspects, 200)
    const computedBudget = computeDynamicStepBudget(this.storage, run.id)
    if (run.dynamicStepBudget === null || run.dynamicStepBudget < computedBudget) {
      this.storage.updateRunDynamicStepBudget(run.id, computedBudget)
    }

    // Fan out eligible crown-jewel leads into parallel multi-trial branches before scheduling
    this.expandEligibleMultiTrialSteps(run)

    this.storage.refreshReadyChainSteps(run.id, run.goalRevision)
    const steps = this.storage.listChainSteps(run.id, run.goalRevision)
    const readySteps = steps
      .filter(s => s.status === 'ready')
      .sort((a, b) => b.priority - a.priority || a.seq - b.seq)

    const maxConc = Math.max(1, Math.min(maxWorkerConcurrency, run.workerConcurrency || defaultWorkerConcurrency))
    const activeForRun = [...this.active.values()].filter(j => j.assignment.runId === run.id && j.assignment.phase === 'investigation').length

    let slots = Math.max(0, maxConc - activeForRun)
    for (const step of readySteps) {
      if (slots <= 0) break
      if (step.assignedWorkerId && this.active.has(step.assignedWorkerId)) continue
      if (step.sourceOrigins.length > 0 && step.sourceOrigins.every(o => this.broker.isCircuitOpen(o))) {
        this.storage.updateChainStep(step.id, { status: 'blocked' })
        continue
      }
      this.startInvestigationStep(run, step, profiles)
      slots -= 1
    }

    // If nothing is running/ready/pending, check K=6 diminishing returns or trigger final planner review
    const updatedSteps = this.storage.listChainSteps(run.id, run.goalRevision)
    const anyActive = updatedSteps.some(s => ['pending', 'ready', 'running'].includes(s.status))
    if (!anyActive && !this.plannerTasks.has(run.id) && !this.plannerTimers.has(run.id)) {
      const consecutiveDry = countConsecutiveDrySteps(this.storage, run)
      if (consecutiveDry >= diminishingReturnsDryThreshold) {
        this.storage.event(
          run.id,
          'planner.diminishing_returns',
          `Halted dynamic queueing after ${consecutiveDry} consecutive dry steps (K=${diminishingReturnsDryThreshold}).`,
          { consecutiveDrySteps: consecutiveDry, threshold: diminishingReturnsDryThreshold },
        )
        this.advanceToVerification(run)
        return
      }
      const hasCanceledSibling = updatedSteps.some(s => Boolean(s.trialGroupId) && s.status === 'canceled')
      if (hasCanceledSibling) {
        const hasUntestedWork =
          this.storage.listFacts(run.id, { includeTainted: false, limit: 1 }).length > 0 ||
          this.storage.listEndpoints(run.id).length > 0 ||
          this.storage.listOpenProofGaps(run.id, run.goalRevision).length > 0
        if (!hasUntestedWork) {
          this.advanceToVerification(run)
          return
        }
      }
      const doneAt = this.plannerDoneRound.get(run.id)
      if (doneAt !== undefined && doneAt === run.roundNo && !this.plannerDirty.has(run.id)) {
        this.advanceToVerification(run)
      } else {
        this.schedulePlanner(run.id, 100)
      }
    } else if (this.plannerDirty.has(run.id) && !this.plannerTasks.has(run.id) && !this.plannerTimers.has(run.id)) {
      this.schedulePlanner(run.id, plannerDebounceMs)
    }
  }

  // --- Phase 1 (deterministic fallback): bounded zero-LLM probe pass when no model profile exists ---

  private driveDeterministicInvestigation(run: Run) {
    const key = `${run.id}:${run.goalRevision}:${run.scopeRevision}`
    if (this.deterministicCompleted.has(key) || this.deterministicInFlight.has(key)) return
    this.deterministicInFlight.add(key)
    void this.runDeterministicInvestigation(run)
      .catch(error => {
        try {
          const msg = redact(error instanceof Error ? error.message : String(error)).slice(0, 300)
          this.storage.event(run.id, 'deterministic_probes.failed', `Deterministic probe pass failed: ${msg}`)
        } catch { /* store closed or run removed */ }
      })
      .finally(() => {
        this.deterministicInFlight.delete(key)
        this.deterministicCompleted.add(key)
        // The store may already be closed (test teardown / run deletion); never let cleanup throw.
        try {
          const latest = this.storage.run(run.id)
          if (latest.status === 'running' && latest.phase === 'investigation') {
            this.storage.event(
              latest.id,
              'deterministic_probes.complete',
              'Deterministic probe pass complete. Advancing to Zero-LLM verification.',
              { reuse: key },
            )
            this.advanceToVerification(latest)
          }
        } catch { /* store closed or run removed */ }
        try {
          this.scheduleWake()
        } catch { /* scheduler already stopped */ }
      })
  }

  /**
   * Extract entry routes from JSON route maps/config docs already fetched during recon
   * (e.g. `/app-config.json`, `/routes`, OpenAPI JSON). Bounded and generic: any object with a
   * `path`/`pathTemplate` string or an array of `/api/...` strings qualifies.
   */
  private async deriveRuntimeRouteMapTargets(
    run: Run,
    approvedOrigins: ReadonlySet<string>,
    grant: Grant,
    assignment: Assignment,
    signal: AbortSignal,
    recordExchange: (exchange: BrokerExchangeResult) => string,
  ): Promise<Array<{
    origin: string
    method: string
    pathTemplate: string
    riskScore: number
    params: Array<{ name: string; location: 'query' | 'json' | 'form' | 'path' | 'header' | 'xml' | 'graphql_var' }>
  }>> {
    const out: Array<{
      origin: string
      method: string
      pathTemplate: string
      riskScore: number
      params: Array<{ name: string; location: 'query' | 'json' | 'form' | 'path' | 'header' | 'xml' | 'graphql_var' }>
    }> = []
    let summaries: Array<{ id: string; origin: string; method: string; pathAndQuery: string; status: number; mediaType: string }> = []
    try {
      summaries = this.storage.runDetail(run.id).exchangesSummary
    } catch {
      return []
    }
    const configPathRe = /(?:app-config|config|routes|manifest|openapi|swagger|api-docs)(?:\.[a-z]+)?(?:\?|$)/i
    let configExchanges = summaries
      .filter(ex => ex.method === 'GET' && ex.status >= 200 && ex.status < 300 && /json/i.test(ex.mediaType))
      .filter(ex => configPathRe.test(ex.pathAndQuery))
      .slice(0, 4)

    // Phase-0 may not have fetched the runtime route map yet; fetch at most two generic config
    // candidates so recon-derived routes are still reachable in deterministic mode.
    if (configExchanges.length === 0) {
      const origin = [...approvedOrigins][0]
      const alreadyFetched = new Set(summaries.map(ex => ex.pathAndQuery))
      for (const candidate of ['/app-config.json', '/api/routes', '/routes.json']) {
        if (configExchanges.length >= 2) break
        if (alreadyFetched.has(candidate) || signal.aborted) continue
        try {
          const ex = await this.broker.executeHttp({
            origin,
            method: 'GET',
            pathAndQuery: candidate,
            followRedirects: false,
            runId: run.id,
            assignmentId: assignment.id,
          }, grant, signal)
          const id = recordExchange(ex)
          if (ex.status >= 200 && ex.status < 300 && /json/i.test(ex.mediaType)) {
            configExchanges.push({
              id,
              origin: ex.origin,
              method: ex.method,
              pathAndQuery: ex.pathAndQuery,
              status: ex.status,
              mediaType: ex.mediaType,
            })
          }
        } catch {
          // Config probing is best-effort; continue with whatever recon already recorded.
        }
      }
    }

    const normalizeTemplate = (value: string) =>
      value.replace(/\{([a-z][a-z0-9_]*):([a-z][a-z0-9_-]*)\}/gi, '$2').slice(0, 300)

    const pushTarget = (origin: string, method: string, rawPath: string) => {
      if (!approvedOrigins.has(origin)) return
      if (!rawPath.startsWith('/') || rawPath.length > 300) return
      const pathTemplate = normalizeTemplate(rawPath)
      if (!/^\/[A-Za-z0-9_\-{}\/.:]*$/.test(pathTemplate)) return
      if (out.some(t => t.origin === origin && t.method === method && t.pathTemplate === pathTemplate)) return
      if (out.length >= 60) return
      const params: Array<{ name: string; location: 'query' | 'json' | 'form' | 'path' | 'header' | 'xml' | 'graphql_var' }> = []
      for (const match of pathTemplate.matchAll(/\{([A-Za-z0-9_]+)\}/g)) params.push({ name: match[1], location: 'path' })
      out.push({ origin, method, pathTemplate, riskScore: 70, params })
    }

    const visit = (node: unknown, origin: string, depth: number) => {
      if (depth > 5 || out.length >= 60) return
      if (Array.isArray(node)) {
        for (const item of node.slice(0, 200)) visit(item, origin, depth + 1)
        return
      }
      if (!node || typeof node !== 'object') return
      const obj = node as Record<string, unknown>
      const methodRaw = typeof obj.method === 'string' ? obj.method : typeof obj.verb === 'string' ? obj.verb : null
      const pathRaw = typeof obj.path === 'string' ? obj.path
        : typeof obj.pathTemplate === 'string' ? obj.pathTemplate
          : typeof obj.route === 'string' ? obj.route : null
      if (pathRaw && pathRaw.startsWith('/')) {
        const method = (methodRaw ?? 'GET').toUpperCase()
        // Only read methods are probed deterministically without a declared body schema.
        if (method === 'GET' || method === 'HEAD') pushTarget(origin, method, pathRaw)
      }
      for (const [key, value] of Object.entries(obj).slice(0, 200)) {
        if (typeof value === 'string' && value.startsWith('/api/') && value.length <= 200) {
          pushTarget(origin, 'GET', value)
        } else if (key === 'paths' && value && typeof value === 'object') {
          for (const [pathKey, pathValue] of Object.entries(value as Record<string, unknown>).slice(0, 120)) {
            if (!pathKey.startsWith('/')) continue
            const methods = pathValue && typeof pathValue === 'object'
              ? Object.keys(pathValue as Record<string, unknown>).filter(k => ['get', 'post', 'put', 'patch'].includes(k.toLowerCase()))
              : []
            for (const method of methods.length ? methods : ['get']) pushTarget(origin, method.toUpperCase(), pathKey)
          }
        } else if (value && typeof value === 'object') {
          visit(value, origin, depth + 1)
        }
      }
    }

    for (const summary of configExchanges) {
      let body = ''
      try {
        body = this.storage.getExchange(run.id, summary.id).body
      } catch {
        continue
      }
      if (!body || body.length > 512 * 1024) continue
      let doc: unknown
      try {
        doc = JSON.parse(body)
      } catch {
        continue
      }
      visit(doc, summary.origin, 0)
    }
    return out
  }

  /**
   * Parse imported OpenAPI/route-map project specs into bounded deterministic probe targets.
   * Generic engine behavior: no app, route, or parameter hardcoding.
   */
  private deriveDeterministicRouteTargets(
    run: Run,
    approvedOrigins: ReadonlySet<string>,
    existing: ReadonlyArray<{ origin: string; method: string; pathTemplate: string }>,
  ): Array<{
    origin: string
    method: string
    pathTemplate: string
    riskScore: number
    params: Array<{ name: string; location: 'query' | 'json' | 'form' | 'path' | 'header' | 'xml' | 'graphql_var' }>
  }> {
    let specs: Array<{ name: string; kind: string; content: string }> = []
    try {
      specs = this.storage.listProjectSpecsFull(run.projectId)
    } catch {
      return []
    }
    const seen = new Set(existing.map(ep => `${ep.origin}|${ep.method.toUpperCase()}|${ep.pathTemplate}`))
    const out: Array<{
      origin: string
      method: string
      pathTemplate: string
      riskScore: number
      params: Array<{ name: string; location: 'query' | 'json' | 'form' | 'path' | 'header' | 'xml' | 'graphql_var' }>
    }> = []
    const defaultOrigin = [...approvedOrigins][0]
    const mapLocation = (value: unknown): 'query' | 'json' | 'form' | 'path' | 'header' | null => {
      const raw = typeof value === 'string' ? value.toLowerCase() : ''
      if (raw === 'query' || raw === 'path' || raw === 'header') return raw
      if (raw === 'formdata' || raw === 'form') return 'form'
      if (raw === 'body') return 'json'
      return null
    }

    for (const spec of specs.slice(0, 6)) {
      const head = spec.content.slice(0, 400)
      if (!/openapi|swagger/i.test(spec.kind) && !/"(?:openapi|swagger)"\s*:/.test(head) && !/^\s*openapi\s*:/m.test(head)) continue
      let doc: Record<string, unknown> | undefined
      try {
        doc = JSON.parse(spec.content) as Record<string, unknown>
      } catch {
        doc = undefined
      }
      const paths = (doc as { paths?: Record<string, unknown> } | undefined)?.paths
      if (!paths || typeof paths !== 'object') {
        // Tolerant fallback: imported specs can be redacted/truncated before storage, so the JSON
        // may not parse. Extract path keys + methods + parameters textually instead of giving up.
        for (const target of parseTolerantOpenApiTargets(spec.content, defaultOrigin, approvedOrigins)) {
          const key = `${target.origin}|${target.method}|${target.pathTemplate}`
          if (seen.has(key)) continue
          seen.add(key)
          out.push(target)
        }
        continue
      }

      let origin = defaultOrigin
      const servers = (doc as { servers?: Array<{ url?: unknown }> } | undefined)?.servers
      if (Array.isArray(servers) && typeof servers[0]?.url === 'string') {
        try {
          const serverOrigin = new URL(servers[0].url, defaultOrigin).origin
          if (approvedOrigins.has(serverOrigin)) origin = serverOrigin
        } catch { /* keep default */ }
      }

      for (const [rawPath, rawItem] of Object.entries(paths).slice(0, 80)) {
        if (typeof rawPath !== 'string' || !rawPath.startsWith('/') || rawPath.length > 300) continue
        const item = rawItem as Record<string, unknown> | null
        if (!item || typeof item !== 'object') continue
        const sharedParams = Array.isArray(item.parameters) ? item.parameters as Array<Record<string, unknown>> : []
        for (const method of ['get', 'post', 'put', 'patch'] as const) {
          const op = item[method] as Record<string, unknown> | undefined
          if (!op || typeof op !== 'object') continue
          const key = `${origin}|${method.toUpperCase()}|${rawPath}`
          if (seen.has(key)) continue
          const params: Array<{ name: string; location: 'query' | 'json' | 'form' | 'path' | 'header' | 'xml' | 'graphql_var' }> = []
          const pushParam = (name: unknown, location: unknown) => {
            const mapped = mapLocation(location)
            if (typeof name !== 'string' || !name || !/^[A-Za-z0-9_.\-[\]]{1,64}$/.test(name)) return
            if (!mapped) return
            if (params.some(p => p.name === name)) return
            params.push({ name, location: mapped })
          }
          for (const param of [...sharedParams, ...(Array.isArray(op.parameters) ? op.parameters as Array<Record<string, unknown>> : [])]) {
            pushParam(param?.name, param?.in)
          }
          const jsonSchema = (op.requestBody as { content?: Record<string, { schema?: { properties?: Record<string, unknown> } }> } | undefined)
            ?.content?.['application/json']?.schema
          if (jsonSchema?.properties && typeof jsonSchema.properties === 'object') {
            for (const name of Object.keys(jsonSchema.properties).slice(0, 12)) pushParam(name, 'body')
          }
          for (const match of rawPath.matchAll(/\{([A-Za-z0-9_]+)\}/g)) pushParam(match[1], 'path')
          seen.add(key)
          const hasInjectable = params.some(p => p.location === 'query' || p.location === 'json' || p.location === 'form')
          if (!hasInjectable && !deterministicIdPath(rawPath)) continue
          out.push({
            origin,
            method: method.toUpperCase(),
            pathTemplate: rawPath,
            riskScore: hasInjectable ? 65 : 55,
            params,
          })
        }
      }
    }
    return out.slice(0, 60)
  }

  /**
   * Bounded, tier/scope/budget-aware deterministic hypotheses for discovered endpoints. Used only
   * when the run has no model profile: it probes the highest-value discovered routes, records
   * facts, synthesizes DeclarativeReplaySpecs from differential anomalies, and lets the normal
   * Zero-LLM verification queue confirm or dismiss them.
   */
  private async runDeterministicInvestigation(run: Run): Promise<void> {
    const current = this.storage.run(run.id)
    if (current.status !== 'running' || current.phase !== 'investigation') return
    const approvedOrigins = this.approvedOriginsSet(current)
    if (current.capabilityTier < 1 || approvedOrigins.size === 0) return

    const endpoints = this.storage.listEndpoints(current.id, { orderBy: 'risk', limit: 150 })
      .filter(ep => approvedOrigins.has(ep.origin) && ep.method !== 'DELETE')

    const allParams = this.storage.listEndpointParams(current.id)
    const paramsByEndpoint = new Map<string, typeof allParams>()
    for (const param of allParams) {
      const list = paramsByEndpoint.get(param.endpointId) ?? []
      list.push(param)
      paramsByEndpoint.set(param.endpointId, list)
    }


    const personas = [...resolveRunPersonas(this.storage, current.projectId, current.approvedPersonaIds).values()]
    const personaHandles = personas.map(p => p.handle)
    const tier = current.capabilityTier

    const resourceQueue = tier >= 2 && personaHandles.length >= 2
      ? buildBolaTestQueue(
          this.storage.listFacts(current.id, { includeTainted: false, limit: 200 }),
          personas.map(p => ({ handle: p.handle, roleLabel: p.roleLabel, originAllowlist: p.originAllowlist })),
          approvedOrigins,
          this.storage.listResourceSamples(current.id),
        )
      : []

    const asset = current.candidates.find(c => approvedOrigins.has(c.origin) && current.approved.includes(c.id))
    if (!asset) return

    const worker = this.storage.makeWorker(
      current,
      'investigation',
      asset,
      'Deterministic differential probes',
      'No model profile configured: bounded deterministic probe pass over discovered endpoints.',
      { sourceOrigins: [...approvedOrigins] },
    )
    const claimed = this.storage.updateWorker(worker.id, {
      status: 'running',
      lease: randomUUID(),
      leaseExpiresAt: Date.now() + 10 * 60_000,
    }) ?? worker
    const job: Active = { assignment: claimed, origins: new Set(approvedOrigins), controller: new AbortController() }
    const { grant, currentSecrets } = this.buildGrant(job, current, approvedOrigins)

    const recordExchange = (ex: BrokerExchangeResult) => {
      const latest = this.storage.run(current.id)
      const saved = this.storage.recordExchange({
        runId: current.id,
        assignmentId: claimed.id,
        scopeRevision: latest.scopeRevision,
        origin: ex.origin,
        finalOrigin: ex.finalOrigin,
        redirectOrigins: ex.redirectOrigins,
        method: ex.method,
        pathAndQuery: ex.pathAndQuery,
        personaHandle: ex.personaHandle,
        status: ex.status,
        mediaType: ex.mediaType,
        reqHeaders: ex.reqHeaders,
        respHeaders: ex.respHeaders,
        body: ex.body,
        durationMs: ex.durationMs,
        secretMatches: ex.secretMatches,
        secrets: currentSecrets(),
      })
      this.storage.trackExchangeResources({
        runId: current.id,
        scopeRevision: latest.scopeRevision,
        exchange: ex,
        source: 'surface_probe',
      })
      this.markEndpointCoverage(latest, ex.origin, ex.method, ex.pathAndQuery, 'http_exchange')
      this.scanSecondOrderExchange(latest, claimed.id, ex, saved.id)
      return saved.id
    }

    const signal = job.controller.signal

    // Route-map/OpenAPI-derived entry routes: grey-box/white-box runs import API references, and
    // phase-0 may not have materialized every path yet on this branch. Parsing them here keeps the
    // deterministic baseline meaningful without depending on an LLM planner.
    const derivedTargets = [
      ...this.deriveDeterministicRouteTargets(current, approvedOrigins, endpoints),
      ...await this.deriveRuntimeRouteMapTargets(current, approvedOrigins, grant, claimed, signal, recordExchange),
    ].filter((target, idx, all) =>
      all.findIndex(other => other.origin === target.origin && other.method === target.method && other.pathTemplate === target.pathTemplate) === idx,
    )
    const syntheticEndpoints = derivedTargets.map(target => ({
      id: `derived:${target.method}:${target.pathTemplate}`,
      runId: current.id,
      scopeRevision: current.scopeRevision,
      origin: target.origin,
      method: target.method,
      pathTemplate: target.pathTemplate,
      source: 'openapi' as const,
      framework: null,
      authRequirement: null,
      ownershipGuard: null,
      sinkKinds: [] as string[],
      testedClasses: [] as string[],
      coveragePct: 0,
      riskScore: target.riskScore,
      codeLocation: null,
      createdAt: current.createdAt,
      updatedAt: current.createdAt,
    }))
    for (const [idx, target] of derivedTargets.entries()) {
      const endpointId = syntheticEndpoints[idx].id
      paramsByEndpoint.set(endpointId, target.params.map((param, paramIdx) => ({
        id: `${endpointId}:p${paramIdx}`,
        runId: current.id,
        endpointId,
        name: param.name,
        location: param.location,
        inferredType: null,
        isCsrf: false,
        isObjectId: /^(?:id|uuid|[a-z][a-z0-9]*Id)$/i.test(param.name),
        source: 'openapi',
        createdAt: current.createdAt,
      })) as unknown as typeof allParams)
    }
    const probeEndpoints = [...endpoints, ...syntheticEndpoints]
    if (!probeEndpoints.length) return

    const injectableLocations = new Set(['query', 'json', 'form'])
    const ranked = probeEndpoints
      .map(ep => {
        const epParams = paramsByEndpoint.get(ep.id) ?? []
        const injectable = epParams
          .filter(p => injectableLocations.has(p.location))
          .sort((a, b) => Number(DETERMINISTIC_PARAM_HINT_RE.test(b.name)) - Number(DETERMINISTIC_PARAM_HINT_RE.test(a.name)))
          .slice(0, 2)
        const queryNames = deterministicQueryParamNames(ep.pathTemplate)
        const paramCandidates = injectable.length
          ? injectable.map(p => ({ name: p.name, location: p.location as 'query' | 'json' | 'form' }))
          : queryNames.slice(0, 2).map(name => ({ name, location: 'query' as const }))
        const idPath = deterministicIdPath(ep.pathTemplate)
        const originResources = resourceQueue.filter(item => item.origin === ep.origin)
        let score = ep.riskScore
        if (paramCandidates.length) score += 25
        if (idPath) score += 12
        if ((ep.sinkKinds ?? []).length > 0) score += 10
        if (originResources.length > 0) score += 15
        // Generic hints that a route consumes query input even when recon did not persist params.
        if (/\b(?:search|query|filter|export|report|list|lookup|find|browse)\b/i.test(ep.pathTemplate)) score += 20
        if (/^\/api\/[a-z][a-z0-9_-]{1,40}$/i.test(ep.pathTemplate.replace(/\?.*$/, ''))) score += 8
        // Prefer routes with injectable parameters before path-only id routes.
        if (!paramCandidates.length && !idPath) score -= 20
        return { ep, paramCandidates, idPath, originResources, score }
      })
      .filter(item => {
        // Nothing testable: path placeholders without harvested ids and no injectable parameter.
        const placeholderOnly = /:[A-Za-z_][A-Za-z0-9_]*|\{[A-Za-z0-9_]+\}|\[[A-Za-z0-9_]+\]/.test(item.ep.pathTemplate)
        if (item.paramCandidates.length) return true
        if (item.idPath !== null && item.originResources.length > 0) return true
        return !placeholderOnly
      })
      .sort((a, b) => b.score - a.score)

    if (!ranked.length) return

    const maxEndpoints = Math.min(22, Math.max(4, Math.floor((current.dynamicStepBudget ?? 24) * 0.9)))
    const requestCap = current.budgetRequests > 0
      ? Math.max(0, Math.min(200, current.budgetRequests - current.spentRequests))
      : 200
    if (requestCap < 6) return

    let requestsUsed = 0
    let findingsCreated = 0
    try {
      for (const item of ranked.slice(0, maxEndpoints)) {
        if (requestsUsed >= requestCap || signal.aborted) break
        const latest = this.storage.run(current.id)
        if (latest.status !== 'running' || latest.phase !== 'investigation') break
        if (this.storage.checkBudgetExceeded(current.id)) break
        if (!approvedOrigins.has(item.ep.origin)) continue

        const perEndpointCap = Math.max(4, Math.min(16, requestCap - requestsUsed))
        if (perEndpointCap < 4) break

        const base = {
          origin: item.ep.origin,
          runId: current.id,
          assignmentId: claimed.id,
          storage: this.storage,
          maxRequests: perEndpointCap,
          onExchange: recordExchange,
        }

        // 1) Cross-persona object authz (ID-bearing routes with harvested owner resources).
        if (item.idPath && tier >= 2 && item.originResources.length > 0) {
          const resource = item.originResources[0]
          const owner = resource.ownerPersona
          const other = personaHandles.find(handle => handle !== owner)
          if (other) {
            let outcome
            try {
              outcome = await probeDifferential({
                ...base,
                probeClass: 'authz_matrix',
                method: 'GET',
                pathAndQuery: item.idPath,
                persona: owner,
                ownerPersona: owner,
                otherPersona: other,
                resourceIds: item.originResources.slice(0, 3).map(r => r.resourceId),
                includeAnonymous: false,
                includeHeaderBypass: false,
              }, this.broker, grant, this.canaryBroker, signal)
            } catch (error) {
              if (error instanceof BudgetExceededError || error instanceof BrokerDenied) break
              outcome = undefined
            }
            if (outcome) {
              requestsUsed += outcome.requestsSent
              this.markEndpointCoverage(latest, item.ep.origin, 'GET', item.idPath, 'diff:authz_matrix')
              const unauthorized = outcome.anomalies.find(a => a.type === 'unauthorized_access')
              if (outcome.verdict === 'signal' && unauthorized) {
                const resourceId = typeof unauthorized.resourceId === 'string' ? unauthorized.resourceId : resource.resourceId
                const probePath = item.idPath.replace('{{id}}', encodeURIComponent(resourceId))
                const controlPath = item.idPath.replace('{{id}}', encodeURIComponent(resourceId))
                const findingId = this.recordDeterministicFinding({
                  run: latest,
                  assignment: claimed,
                  asset,
                  spec: {
                    ...baseReplaySpecFields(latest, item.ep.origin, {
                      title: `Cross-persona object access · ${item.ep.method} ${item.ep.pathTemplate.slice(0, 80)}`,
                      category: 'broken-access-control',
                      cwe: 'CWE-639',
                      severity: 'high',
                      severityRationale: `Persona ${owner} owns ${resourceId}; persona ${other} received HTTP ${String(unauthorized.status)} on the same object.`,
                      impact: 'Horizontal privilege escalation: one tenant can read another tenant\'s object by ID.',
                      remediation: 'Enforce an ownership/tenant predicate on the object lookup before returning or mutating it.',
                      recheckInstructions: 'Replay the owner control and the cross-persona probe after the fix.',
                    }),
                    kind: 'http_chain',
                    spaCatchallControl: false,
                    assertionsJq: '{ controlPassed: (.steps.ctrl.status == 200), confirmed: (.steps.prb.status == 200), observed: ("probe status " + (.steps.prb.status | tostring)), expected: "cross-persona probe denied" }',
                    steps: [
                      { id: 'ctrl', role: 'control', description: `Owner ${owner} reads its own object`, request: { origin: item.ep.origin, method: 'GET', pathAndQuery: controlPath, persona: owner, followRedirects: false } },
                      { id: 'prb', role: 'probe', description: `Persona ${other} replays the owner object id`, request: { origin: item.ep.origin, method: 'GET', pathAndQuery: probePath, persona: other, followRedirects: false } },
                    ],
                  },
                  factData: {
                    subkind: 'differential_anomaly',
                    probeClass: 'authz_matrix',
                    endpoint: item.ep.pathTemplate,
                    resourceId,
                    ownerPersona: owner,
                    otherPersona: other,
                    anomalies: [unauthorized],
                  },
                  factSummary: `Deterministic authz_matrix signal: ${other} reached ${owner}'s resource ${resourceId} at ${item.ep.method} ${item.ep.pathTemplate} (HTTP ${String(unauthorized.status)}).`,
                  exchangeIds: outcome.exchangeIds,
                  secrets: currentSecrets(),
                })
                if (findingId) findingsCreated += 1
              }
            }
            continue
          }
        }

        // 2) SQL injection differential on parameterized routes (non-destructive boolean/error only).
        // When recon did not persist parameters, discover them first with the deterministic
        // param-differential surface mode (bounded), then inject into the discovered names.
        let candidateParams: Array<{ name: string; location: 'query' | 'json' | 'form' }> = item.paramCandidates
        if (!candidateParams.length && item.ep.method !== 'DELETE' && requestsUsed < requestCap - 6) {
          try {
            const discovery = await probeSurface({
              origin: item.ep.origin,
              mode: 'params',
              basePath: item.ep.pathTemplate.split('?')[0],
              paramLocation: 'query',
              methods: ['GET'],
              persona: personaHandles[0],
              maxRequests: Math.max(4, Math.min(12, requestCap - requestsUsed - 4)),
              onExchange: recordExchange,
            }, this.broker, grant, signal)
            requestsUsed += discovery.requestsSent
            this.markEndpointCoverage(latest, item.ep.origin, 'GET', item.ep.pathTemplate, 'surface:params')
            const discovered = [...new Set(
              discovery.anomalies
                .filter(a => a.kind === 'param' && typeof a.param === 'string')
                .map(a => String(a.param)),
            )].slice(0, 2)
            candidateParams = discovered.map(name => ({ name, location: 'query' as const }))
          } catch (error) {
            if (error instanceof BudgetExceededError || error instanceof BrokerDenied) break
          }
        }

        // Search-like routes commonly take a free-text term even when recon/OpenAPI did not record
        // the parameter name; try the conventional term once (bounded, non-destructive).
        if (!candidateParams.length && /(?:search|query|filter|find|lookup|browse)/i.test(item.ep.pathTemplate)) {
          candidateParams = [{ name: 'q', location: 'query' }]
        }

        for (const candidate of candidateParams.slice(0, 2)) {
          if (requestsUsed >= requestCap || signal.aborted) break
          const location = candidate.location
          const method = item.ep.method === 'POST' ? 'POST' : 'GET'
          if (method === 'POST' && !['query', 'json', 'form'].includes(location)) continue
          const baselineValue = DETERMINISTIC_NUMERIC_PARAM_RE.test(candidate.name) ? '1' : 'guardian'
          const quoteStyle: 'single' | 'double' | 'numeric' = DETERMINISTIC_NUMERIC_PARAM_RE.test(candidate.name) ? 'numeric' : 'single'
          const pathAndQuery = location === 'query'
            ? withQueryParam(item.ep.pathTemplate, candidate.name, baselineValue)
            : item.ep.pathTemplate.split('?')[0]
          const jsonBody = method === 'POST' && location === 'json'
            ? { [candidate.name]: baselineValue }
            : undefined
          let outcome
          try {
            outcome = await probeDifferential({
              ...base,
              probeClass: 'sqli_boolean',
              method,
              pathAndQuery,
              param: candidate.name,
              paramLocation: location,
              baselineValue,
              ...(jsonBody ? { jsonBody } : {}),
              ...(personaHandles[0] ? { persona: personaHandles[0] } : {}),
            }, this.broker, grant, this.canaryBroker, signal)
          } catch (error) {
            if (error instanceof BudgetExceededError || error instanceof BrokerDenied) break
            outcome = undefined
          }
          if (!outcome) continue
          requestsUsed += outcome.requestsSent
          this.markEndpointCoverage(latest, item.ep.origin, method, pathAndQuery, 'diff:sqli_boolean')
          const booleanSignal = outcome.anomalies.find(a => a.type === 'boolean_differential')
          const dbError = outcome.anomalies.find(a => a.type === 'db_error_fingerprint')
          if (outcome.verdict !== 'signal' || (!booleanSignal && !dbError)) continue
          const dialect = typeof dbError?.dialect === 'string' ? dbError.dialect : null
          const findingId = this.recordDeterministicFinding({
            run: latest,
            assignment: claimed,
            asset,
            spec: {
              ...baseReplaySpecFields(latest, item.ep.origin, {
                title: `SQL parameterization differential · ${method} ${item.ep.pathTemplate.slice(0, 80)} (${candidate.name})`,
                category: 'injection-input',
                cwe: 'CWE-89',
                severity: 'high',
                severityRationale: `Deterministic ${booleanSignal ? 'boolean differential' : 'SQL error fingerprint'} observed on parameter "${candidate.name}"${dialect ? ` (${dialect})` : ''}.`,
                impact: 'Unparameterized SQL handling allows boolean/oracle-based data inference.',
                remediation: 'Bind the parameter with the ORM/query parameterizer and remove string interpolation.',
                recheckInstructions: 'Replay the boolean differential after switching to a bound parameter.',
              }),
              kind: 'sql_boolean_diff',
              targetOrigin: item.ep.origin,
              method,
              pathAndQuery,
              paramName: candidate.name,
              paramLocation: location,
              baselineValue,
              quoteStyle,
              ...(jsonBody ? { jsonBody } : {}),
              assertionsJq: '{ controlPassed: true, confirmed: true, observed: "deterministic boolean differential", expected: "parameterized query" }',
            },
            factData: {
              subkind: 'differential_anomaly',
              probeClass: 'sqli_boolean',
              endpoint: item.ep.pathTemplate,
              param: candidate.name,
              paramLocation: location,
              method,
              dialect,
              anomalies: outcome.anomalies.slice(0, 5),
            },
            factSummary: `Deterministic sqli_boolean signal on ${method} ${item.ep.pathTemplate} parameter "${candidate.name}"${dialect ? ` (${dialect} error fingerprint)` : ''}.`,
            exchangeIds: outcome.exchangeIds,
            secrets: currentSecrets(),
          })
          if (findingId) findingsCreated += 1
        }
      }

      this.storage.event(
        current.id,
        'deterministic_probes.summary',
        `Deterministic probe pass used ${requestsUsed} request(s) across ${Math.min(ranked.length, maxEndpoints)} endpoint(s) and proposed ${findingsCreated} replay spec(s).`,
        { requestsUsed, endpointsConsidered: ranked.length, endpointsProbed: Math.min(ranked.length, maxEndpoints), findingsCreated, requestCap },
      )
      this.storage.message(
        current.id,
        current.coordinatorId,
        'guardian',
        `No model profile is configured, so Guardian ran a bounded deterministic probe pass (${requestsUsed} requests) and proposed ${findingsCreated} deterministic replay spec(s) for Zero-LLM verification.`,
      )
    } finally {
      try {
        this.storage.updateWorker(claimed.id, {
          status: 'complete',
          outcome: `Deterministic probes: ${requestsUsed} request(s), ${findingsCreated} spec(s).`,
          lease: null,
          leaseExpiresAt: null,
        })
      } catch { /* run may have been deleted */ }
    }
  }

  private recordDeterministicFinding(input: {
    run: Run
    assignment: Assignment
    asset: Candidate
    spec: unknown
    factData: Record<string, unknown>
    factSummary: string
    exchangeIds: readonly string[]
    secrets: readonly NamedSecret[]
  }): string | null {
    const parsed = declarativeReplaySpecSchema.safeParse(input.spec)
    if (!parsed.success) return null
    const spec = parsed.data

    const fields = extractSpecDedupeFields(spec)
    const existingRows = this.storage.db.select().from(findings).where(and(
      eq(findings.runId, input.run.id),
      eq(findings.goalRevision, input.run.goalRevision),
    )).all()
    const existingRefs: ExistingFindingRef[] = existingRows.map(row => {
      const specRow = row.replaySpecId ? this.storage.getReplaySpec(input.run.id, row.replaySpecId) : null
      const existingFields = specRow ? extractSpecDedupeFields(specRow.spec) : undefined
      return {
        id: row.id,
        origin: row.finding.origin,
        title: row.finding.title,
        status: row.finding.status,
        cwe: row.finding.cwe,
        category: row.finding.category,
        severity: row.finding.severity,
        endpoint: existingFields?.endpoint ?? null,
        authState: existingFields?.authState ?? null,
        specKind: existingFields?.specKind ?? null,
        method: existingFields?.method ?? null,
        param: existingFields?.param ?? null,
        fingerprintHash: row.fingerprintHash ?? null,
      }
    })
    const duplicate = checkStructuralDuplicate({
      origin: spec.origin,
      title: spec.title,
      cwe: spec.cwe,
      category: spec.category,
      severity: spec.severity,
      endpoint: fields.endpoint,
      authState: fields.authState,
      specKind: fields.specKind,
      method: fields.method,
      param: fields.param,
    }, existingRefs)
    if (duplicate.isDuplicate) return null

    const fact = this.storage.addFact(input.run, input.assignment, {
      kind: 'note',
      origin: spec.origin,
      summary: input.factSummary,
      data: input.factData,
      exchangeIds: [...input.exchangeIds].slice(0, 5),
      sourceOrigins: [...new Set(replaySpecOrigins(spec))].filter(o => this.permitted(input.run, o)),
      secrets: input.secrets,
    })

    const findingId = randomUUID()
    const specRow = this.storage.createReplaySpec(input.run, input.assignment, findingId, spec, [...new Set(replaySpecOrigins(spec))])
    const artifact = this.storage.addArtifact(
      input.run,
      input.assignment,
      'replay',
      `Deterministic proposed spec · ${spec.title}`,
      JSON.stringify({ replaySpecId: specRow.id, specSha256: specRow.specSha256, spec }, null, 2),
      undefined,
      input.secrets,
    )
    const finding: Finding = {
      id: findingId,
      origin: spec.origin,
      title: spec.title,
      status: 'pending',
      severity: spec.severity,
      reason: spec.severityRationale,
      remediation: spec.remediation,
      impact: spec.impact,
      recheck: spec.recheckInstructions,
      category: spec.category,
      cwe: spec.cwe,
      confidence: 'medium',
      verification: `Pending Zero-LLM ${spec.kind} replay verification proposed deterministically (spec ${specRow.id}).`,
      findingKind: 'multi_step_chain',
      replaySpecId: specRow.id,
      fingerprintHash: duplicate.fingerprint.hash,
      chainFactIds: [fact.id],
      exchangeIds: [...new Set(input.exchangeIds)].slice(0, 6),
      evidenceIds: [artifact.id],
      scopeRevision: input.run.scopeRevision,
    }
    const saved = this.storage.upsertChainFinding(input.run, input.asset.id, finding, specRow.id, [...new Set(replaySpecOrigins(spec))])
    this.storage.makeWorker(
      input.run,
      'verification',
      input.asset,
      `Replay verify · ${spec.title.slice(0, 80)}`,
      `Zero-LLM deterministic replay verification of deterministically proposed spec ${specRow.id}.`,
      { stepId: specRow.id, sourceOrigins: [...new Set(replaySpecOrigins(spec))] },
    )
    this.storage.addGraphEdge(input.run.id, { fromKind: 'fact', fromId: fact.id, toKind: 'finding', toId: saved.id, edgeKind: 'proves' })
    return saved.id
  }

  private schedulePlanner(runId: string, delayMs = plannerDebounceMs) {
    this.plannerDirty.add(runId)
    if (this.plannerTimers.has(runId) || this.plannerTasks.has(runId)) return
    const timer = setTimeout(() => {
      this.plannerTimers.delete(runId)
      this.plannerDirty.delete(runId)
      try {
        const run = this.storage.run(runId)
        const profiles = privateModelProfiles(this.storage)
        if (run.status === 'running' && run.phase === 'investigation' && profiles.length) {
          this.startChainPlanner(run, profiles)
        }
      } catch { /* ignore */ }
    }, delayMs)
    timer.unref?.()
    this.plannerTimers.set(runId, timer)
  }

  private startChainPlanner(run: Run, profiles: readonly ResolvedModelProfile[]) {
    if (this.plannerTasks.has(run.id)) return
    const controller = new AbortController()
    const task: CoordinatorTask = { controller, goalRevision: run.goalRevision, scopeRevision: run.scopeRevision }
    this.plannerTasks.set(run.id, task)
    void this.runChainPlanner(run, profiles, task).catch(() => {
      // Planner errors should not crash active workers; retry on next wake or advance cleanly
    }).finally(() => {
      this.plannerTasks.delete(run.id)
      this.scheduleWake()
    })
  }

  // --- Priority #4: Cross-Host Chain Synthesizer Pass ---

  async runCrossHostSynthesizer(
    run: Run,
    roundNo: number,
    profiles: readonly ResolvedModelProfile[],
    signal: AbortSignal,
  ): Promise<{ triggered: boolean; stepsCreated: ChainStep[]; hypothesesCount: number; reason: string }> {
    if (!profiles.length) {
      return { triggered: false, stepsCreated: [], hypothesesCount: 0, reason: 'No model profiles configured.' }
    }
    const approvedOrigins = this.approvedOriginsSet(run)
    const allValidFacts = this.storage.listFacts(run.id, { includeTainted: false, limit: 120 })
      .filter(f => approvedOrigins.has(f.origin) && f.sourceOrigins.every(o => approvedOrigins.has(o)))
    const check = shouldRunCrossHostSynthesizer(allValidFacts, approvedOrigins)
    if (!check.trigger) {
      return { triggered: false, stepsCreated: [], hypothesesCount: 0, reason: check.reason }
    }

    const signature = createHash('sha256')
      .update(`${run.goalRevision}:${run.scopeRevision}:${allValidFacts.map(f => f.id).sort().join(',')}`)
      .digest('hex')
    if (this.synthesizedSignature.get(run.id) === signature) {
      return { triggered: false, stepsCreated: [], hypothesesCount: 0, reason: 'Facts unchanged since last cross-host synthesis.' }
    }

    const tm = this.storage.latestThreatModel(run.id, run.goalRevision)
    const existingSteps = this.storage.listChainSteps(run.id, run.goalRevision)
    const personas = [...resolveRunPersonas(this.storage, run.projectId, run.approvedPersonaIds).values()]
      .map(p => ({ handle: p.handle, roleLabel: p.roleLabel, originAllowlist: p.originAllowlist }))

    const factsByOrigin: Record<string, Array<{
      id: string
      kind: string
      summary: string
      data?: Record<string, unknown>
      exchangeIds?: readonly string[]
    }>> = {}
    for (const fact of allValidFacts) {
      const list = factsByOrigin[fact.origin] ?? (factsByOrigin[fact.origin] = [])
      list.push({
        id: fact.id,
        kind: typeof fact.data?.subkind === 'string' ? fact.data.subkind : fact.kind,
        summary: fact.summary,
        data: fact.data,
        exchangeIds: fact.exchangeIds,
      })
    }

    const prompt = crossHostSynthesizerPrompt({
      goal: run.goal,
      roundNo,
      capabilityTier: run.capabilityTier,
      approvedOrigins: [...approvedOrigins],
      personas,
      threatModel: tm?.entries.filter(e => approvedOrigins.has(e.origin)),
      factsByOrigin,
      existingSteps: existingSteps.map(s => ({ id: s.id, title: s.title, status: s.status, origins: s.sourceOrigins })),
    })

    const answer = await agentTurn({
      directory: this.storage.directory,
      sessionId: `synth-${run.id}-r${roundNo}`,
      requestId: `synth:${run.goalRevision}:${roundNo}`,
      profiles: resolveProfilePoolForRole('reasoning', profiles),
      scenario: 'cross-host-synthesizer',
      roleAffinity: 'reasoning',
      prompt,
      signal,
      onUsage: u => this.storage.recordLlmSpend(run.id, { usd: u.costUsd, tokens: u.inputTokens + u.outputTokens }),
      onProfileSuccess: id => recordProfileSuccess(id, this.storage),
      onProfileFailure: (id, err, hard) => recordProfileFailure(id, err, hard, this.storage),
    })

    this.synthesizedSignature.set(run.id, signature)
    let parsedJson: unknown
    try {
      parsedJson = JSON.parse(stripJsonFences(answer))
    } catch {
      return { triggered: true, stepsCreated: [], hypothesesCount: 0, reason: 'Synthesizer returned non-JSON output.' }
    }
    const parsed = crossHostSynthesizerResponseSchema.safeParse(parsedJson)
    if (!parsed.success) {
      return { triggered: true, stepsCreated: [], hypothesesCount: 0, reason: 'Synthesizer output did not match schema.' }
    }

    const currentRun = this.storage.run(run.id)
    const currentApproved = this.approvedOriginsSet(currentRun)
    const latestSteps = this.storage.listChainSteps(run.id, currentRun.goalRevision)
    const existingTitles = new Set(latestSteps.map(s => s.title.trim().toLowerCase()))
    const validFactIdSet = new Set(allValidFacts.map(f => f.id))
    const stepsCreated: ChainStep[] = []
    let totalSteps = latestSteps.length

    const dynamicBudget = Math.min(hardChainStepsCeiling, currentRun.dynamicStepBudget ?? computeDynamicStepBudget(this.storage, currentRun.id))
    for (const step of parsed.data.chainSteps) {
      if (totalSteps >= dynamicBudget || stepsCreated.length >= 6) break
      const validOrigins = step.origins.filter(o => currentApproved.has(o))
      const assetIds = currentRun.candidates
        .filter(c => validOrigins.includes(c.origin) && currentRun.approved.includes(c.id))
        .map(c => c.id)
      if (!assetIds.length) continue
      const titleKey = step.title.trim().toLowerCase()
      if (existingTitles.has(titleKey)) continue
      const depFacts = step.dependsOnFactIds.filter(fid => validFactIdSet.has(fid))
      const specialistProfile = routeStepToSpecialist({
        title: step.title,
        hypothesis: step.hypothesis,
        category: step.category,
        skills: step.skills,
      })
      const created = this.storage.addChainStep(currentRun, {
        title: step.title,
        hypothesis: step.hypothesis,
        category: step.category,
        priority: Math.max(82, Math.min(100, step.priority)),
        targetAssetIds: assetIds,
        skills: [...new Set([...step.skills, 'cross-host-chaining'])],
        dependsOnFactIds: depFacts,
        sourceOrigins: validOrigins,
        specialistProfile,
      })
      existingTitles.add(titleKey)
      stepsCreated.push(created)
      totalSteps += 1
    }

    this.storage.event(run.id, 'synthesizer.round',
      `Cross-host synthesizer round ${roundNo}: ${parsed.data.hypotheses.length} hypotheses, ${stepsCreated.length} cross-host steps queued.`, {
        roundNo,
        hypothesesCount: parsed.data.hypotheses.length,
        addedCount: stepsCreated.length,
        distinctOrigins: check.distinctOrigins,
        leverageSignals: check.leverageSignals,
        summary: parsed.data.summary.slice(0, 300),
      })

    return {
      triggered: true,
      stepsCreated,
      hypothesesCount: parsed.data.hypotheses.length,
      reason: check.reason,
    }
  }

  private async runChainPlanner(run: Run, profiles: readonly ResolvedModelProfile[], task: CoordinatorTask) {
    const fresh = this.storage.run(run.id)
    if (fresh.status !== 'running' || fresh.phase !== 'investigation') return
    if (this.storage.checkBudgetExceeded(run.id)) return

    // Compute & persist dynamic step budget clamp(24, crownJewels*2 + suspects, 200)
    const dynamicStepBudget = Math.min(hardChainStepsCeiling, computeDynamicStepBudget(this.storage, fresh.id))
    this.storage.updateRunDynamicStepBudget(fresh.id, dynamicStepBudget)

    // Diminishing-returns stop: K=6 consecutive dry steps halts dynamic planning cleanly
    const consecutiveDry = countConsecutiveDrySteps(this.storage, fresh)
    if (consecutiveDry >= diminishingReturnsDryThreshold) {
      this.storage.event(
        fresh.id,
        'planner.diminishing_returns',
        `Planner halted after ${consecutiveDry} consecutive dry steps (K=${diminishingReturnsDryThreshold}).`,
        { consecutiveDrySteps: consecutiveDry, threshold: diminishingReturnsDryThreshold },
      )
      this.advanceToVerification(fresh)
      return
    }

    // 1. Advance roundNo & trigger background LSM cold-graph compaction
    const roundRes = this.compactor.onPlannerRound(this.storage, run.id, profiles, task.controller.signal)
    const afterRound = this.storage.run(run.id)
    const approvedOrigins = this.approvedOriginsSet(afterRound)

    // 2. Priority #4: Cross-Host Chain Synthesizer Pass when facts span >=2 origins or cross-origin primitives exist
    let synthesizedStepsCount = 0
    try {
      const synth = await this.runCrossHostSynthesizer(afterRound, roundRes.roundNo, profiles, task.controller.signal)
      synthesizedStepsCount = synth.stepsCreated.length
    } catch {
      // Cross-host synthesis is best-effort; continue planning cleanly
    }
    if (!this.currentCoordinator(run.id, task)) return

    const allSteps = this.storage.listChainSteps(run.id, afterRound.goalRevision)
    const allUntaintedFacts = this.storage.listFacts(run.id, { includeTainted: false, limit: 150 })
      .filter(f => approvedOrigins.has(f.origin))
    const activeFacts = allUntaintedFacts.filter(f => !f.digestId).slice(0, 80)
    const codeAuditSuspects = allUntaintedFacts
      .filter(f => f.data?.subkind === 'code_audit_suspect')
      .slice(0, 30)
      .map(f => ({ factId: f.id, origin: f.origin, summary: f.summary, data: f.data }))
    const coldDigests = this.storage.listDigests(run.id, true)
    const coverageEntries = this.storage.listCoverageEntries(run.id, afterRound.goalRevision)
      .filter(c => approvedOrigins.has(c.origin))
    const tm = this.storage.latestThreatModel(run.id, afterRound.goalRevision)
    const tmEntries = tm?.entries.filter(e => approvedOrigins.has(e.origin))
    const hostTiers = computeHostTiers([...approvedOrigins], tmEntries)
    const pendingFindings = this.storage.runDetail(run.id).findings
      .filter(f => approvedOrigins.has(f.origin))
      .slice(0, 30)

    const personas = [...resolveRunPersonas(this.storage, afterRound.projectId, afterRound.approvedPersonaIds).values()]
      .map(p => ({ handle: p.handle, roleLabel: p.roleLabel, originAllowlist: p.originAllowlist }))
    const { mountedRepos } = this.projectReposMount(afterRound.projectId)

    // Priority #3: Auto-enqueue cross-persona BOLA/IDOR step if >= 2 personas discovered owned resources not yet tested
    let bolaAutoSteps = 0
    if (afterRound.capabilityTier >= 2 && personas.length >= 2 && allSteps.length < dynamicStepBudget) {
      const bolaQueue = buildBolaTestQueue(
        allUntaintedFacts,
        personas,
        approvedOrigins,
        this.storage.listResourceSamples(run.id),
      )
      // A bounded per-resource-type budget (not one step per origin): on realistic multi-tenant
      // apps several ID-bearing resource types share an origin and each deserves its own matrix.
      const typeGroups = new Map<string, BolaTestQueueItem[]>()
      for (const item of bolaQueue) {
        const key = `${item.origin}\u0000${item.resourceKey}`
        const list = typeGroups.get(key) ?? []
        list.push(item)
        typeGroups.set(key, list)
      }
      const candidateGroups = [...typeGroups.values()]
        .sort((a, b) =>
          Number(b[0].ownerPersona !== 'anonymous') - Number(a[0].ownerPersona !== 'anonymous') ||
          b.length - a.length,
        )
      const perOriginSteps = new Map<string, number>()
      for (const itemsForType of candidateGroups) {
        if (allSteps.length + bolaAutoSteps >= dynamicStepBudget) break
        const origin = itemsForType[0].origin
        if ((perOriginSteps.get(origin) ?? 0) >= 3) continue
        const resourceKey = itemsForType[0].resourceKey
        const alreadyPlanned = allSteps.some(s =>
          s.sourceOrigins.includes(origin) &&
          (s.title.includes(`resource:${resourceKey}`) || (
            s.skills.includes('bola-idor-race') && /\b(?:bola|idor|cross-persona)\b/i.test(s.title)
          )),
        )
        if (alreadyPlanned) continue
        const asset = afterRound.candidates.find(c => c.origin === origin && afterRound.approved.includes(c.id))
        if (!asset) continue
        const itemsForOrigin = itemsForType.slice(0, 6)
        const factIds = itemsForOrigin.map(i => i.factId).filter((fid): fid is string => Boolean(fid))
        const variants = [...new Set(itemsForOrigin.flatMap(i => i.variants.map(v =>
          `${v.method} ${v.endpoint}${v.destructive ? ' (Tier 3 only)' : ''}`,
        )))].slice(0, 8)
        this.storage.addChainStep(afterRound, {
          title: `Cross-persona BOLA/IDOR matrix · ${new URL(origin).hostname} · resource:${resourceKey}`,
          hypothesis: `Replay ${itemsForOrigin.length} ${resourceKey} resource(s) owned by ${itemsForOrigin[0].ownerPersona} (e.g. ${itemsForOrigin.map(i => `${i.endpoint} [${i.resourceId}]`).join(', ')}) as ${itemsForOrigin[0].testAsPersonas?.join(', ') ?? 'alternate persona & anonymous'} using bounded consumer item variants: ${variants.join(', ')}. Verify tenant isolation with GET first; use benign PUT/PATCH field deltas only where reversible; DELETE stays Tier 3/local-lab. Submit a DeclarativeReplaySpec if unauthorized access succeeds.`,
          category: 'broken-access-control',
          priority: 92,
          targetAssetIds: [asset.id],
          skills: ['bola-idor-race', 'false-positive-elimination'],
          dependsOnFactIds: factIds,
          sourceOrigins: [origin],
          specialistProfile: 'bola-bfla-specialist',
        })
        bolaAutoSteps += 1
        perOriginSteps.set(origin, (perOriginSteps.get(origin) ?? 0) + 1)
      }
    }

    const secondOrderCanaries = this.storage.listSecondOrderCanaries(run.id).slice(0, 30)
      .map(c => ({
        marker: c.marker,
        status: c.status,
        injectedOrigin: c.injectedOrigin,
        injectedEndpoint: c.injectedEndpoint,
        injectedParam: c.injectedParam,
        injectedPersona: c.injectedPersona,
        surfacedOrigin: c.surfacedOrigin,
        surfacedEndpoint: c.surfacedEndpoint,
        surfacedPersona: c.surfacedPersona,
      }))
    const secondOrderSurfaceFacts = allUntaintedFacts
      .filter(f => f.data?.subkind === 'second_order_surface' && afterRound.capabilityTier >= 1)
      .slice(0, 20)

    // Auto-enqueue a high-priority verification step for each new cross-persona or active-HTML
    // second-order surface, so a surfaced canary is never left as an unexamined fact.
    let secondOrderAutoSteps = 0
    for (const fact of secondOrderSurfaceFacts) {
      if (allSteps.length + bolaAutoSteps + secondOrderAutoSteps >= dynamicStepBudget) break
      const marker = typeof fact.data?.marker === 'string' ? fact.data.marker : ''
      const surfacedOrigin = typeof fact.data?.surfacedOrigin === 'string' ? fact.data.surfacedOrigin : fact.origin
      const surfacedEndpoint = typeof fact.data?.surfacedEndpoint === 'string' ? fact.data.surfacedEndpoint : '/'
      const surfacedMediaType = typeof fact.data?.surfacedMediaType === 'string' ? fact.data.surfacedMediaType : ''
      const crossPersona = fact.data?.crossPersona === true
      const activeHtml = /html/i.test(surfacedMediaType)
      if (!marker || !approvedOrigins.has(surfacedOrigin) || (!crossPersona && !activeHtml)) continue
      const alreadyPlanned = allSteps.some(s =>
        (s.dependsOnFactIds ?? []).includes(fact.id) ||
        (s.title.includes(marker) && s.sourceOrigins.includes(surfacedOrigin)),
      )
      if (alreadyPlanned) continue
      const asset = afterRound.candidates.find(c => c.origin === surfacedOrigin && afterRound.approved.includes(c.id))
      if (!asset) continue
      this.storage.addChainStep(afterRound, {
        title: `Second-order canary verification · ${marker} → ${new URL(surfacedOrigin).hostname}${surfacedEndpoint.slice(0, 40)}`,
        hypothesis: `Second-order canary ${marker} planted via ${String(fact.data?.injectedEndpoint ?? '/')} (param ${String(fact.data?.injectedParam ?? 'input')}, persona ${String(fact.data?.injectedPersona ?? 'anonymous')}) resurfaced on ${surfacedOrigin}${surfacedEndpoint} as persona ${String(fact.data?.surfacedPersona ?? 'anonymous')} with media type ${surfacedMediaType || 'unknown'}${crossPersona ? ' (cross-persona)' : ''}${activeHtml ? ' (active HTML render)' : ''}. Re-read the surfaced endpoint with a control persona, prove the injected marker is persisted and rendered to a different principal, then submit a ${activeHtml ? 'browser_chain' : 'http_chain'} DeclarativeReplaySpec whose probe step renders the marker verbatim and whose control step does not.`,
        category: crossPersona ? 'broken-access-control' : 'cors-client-side',
        priority: 95,
        targetAssetIds: [asset.id],
        skills: crossPersona
          ? ['oob-ssrf-browser-chain', 'bola-idor-race', 'false-positive-elimination']
          : ['client-side-xss-postmessage', 'oob-ssrf-browser-chain'],
        dependsOnFactIds: [fact.id],
        sourceOrigins: [...new Set([surfacedOrigin, fact.origin])].filter(o => approvedOrigins.has(o)),
        specialistProfile: crossPersona ? 'bola-bfla-specialist' : 'client-browser-dom-specialist',
      })
      secondOrderAutoSteps += 1
    }

    const uncoveredEndpoints = this.storage.listEndpoints(run.id, { orderBy: 'coverage', limit: 25 })
      .filter(ep => approvedOrigins.has(ep.origin))
      .map(ep => ({
        id: ep.id,
        origin: ep.origin,
        method: ep.method,
        pathTemplate: ep.pathTemplate,
        riskScore: ep.riskScore,
        coveragePct: ep.coveragePct ?? 0,
        testedClasses: ep.testedClasses,
      }))

    const graphCatalog = this.endpointGraphCatalog(run.id)
    const chainPlannerInput = {
      goal: afterRound.goal,
      roundNo: roundRes.roundNo,
      capabilityTier: afterRound.capabilityTier,
      approvedOrigins: [...approvedOrigins],
      personas,
      mountedRepos,
      threatModel: tmEntries,
      hostTiers,
      codeAuditSuspects,
      activeFacts: activeFacts.map(f => ({
        id: f.id,
        kind: typeof f.data?.subkind === 'string' ? f.data.subkind : f.kind,
        origin: f.origin,
        summary: f.summary,
        exchangeIds: f.exchangeIds,
      })),
      coldDigests: coldDigests.map(d => ({
        id: d.id, level: d.level, roundNo: d.roundNo, summary: d.summary, coveredCount: d.coveredFactIds.length,
      })),
      chainSteps: this.storage.listChainSteps(run.id, afterRound.goalRevision).map(s => ({
        id: s.id, seq: s.seq, title: s.title, category: s.category, status: s.status, priority: s.priority, origins: s.sourceOrigins,
      })),
      coverageEntries: coverageEntries.map(c => ({
        origin: c.origin,
        category: c.category,
        status: c.status,
        summary: c.summary,
        enforcingControl: c.enforcingControl ?? null,
        proofGapReason: c.proofGapReason ?? null,
        linkedFindingId: c.linkedFindingId ?? null,
      })),
      openProofGaps: this.storage.listOpenProofGaps(run.id, afterRound.goalRevision)
        .filter(g => approvedOrigins.has(g.origin))
        .map(g => ({
          origin: g.origin,
          category: g.category,
          summary: g.summary,
          proofGapReason: g.proofGapReason ?? g.summary,
        })),
      pendingFindings: pendingFindings.map(f => ({ id: f.id, origin: f.origin, title: f.title, status: f.status, severity: f.severity })),
      secondOrderCanaries,
      uncoveredEndpoints,
      dynamicStepBudget,
      endpointParams: graphCatalog.endpointParams,
      apiDependencies: graphCatalog.apiDependencies,
      budgetRemaining: {
        usd: Math.max(0, Number((afterRound.budgetUsd - afterRound.spentUsd).toFixed(4))),
        requests: afterRound.budgetRequests === 0
          ? ('unlimited' as const)
          : Math.max(0, afterRound.budgetRequests - afterRound.spentRequests),
      },
    }
    const prompt = chainPlannerPrompt(chainPlannerInput)

    const answer = await agentTurn({
      directory: this.storage.directory,
      sessionId: `planner-${run.id}-r${roundRes.roundNo}`,
      requestId: `planner:${afterRound.goalRevision}:${roundRes.roundNo}`,
      profiles: resolveProfilePoolForRole('tactical', profiles),
      scenario: 'chain-planner',
      roleAffinity: 'tactical',
      prompt,
      signal: task.controller.signal,
      onUsage: u => this.storage.recordLlmSpend(run.id, { usd: u.costUsd, tokens: u.inputTokens + u.outputTokens }),
      onProfileSuccess: id => recordProfileSuccess(id, this.storage),
      onProfileFailure: (id, err, hard) => recordProfileFailure(id, err, hard, this.storage),
    })

    if (!this.currentCoordinator(run.id, task)) return

    let parsedPlanner: ReturnType<typeof plannerResponseSchema.safeParse>
    try {
      parsedPlanner = plannerResponseSchema.safeParse(JSON.parse(stripJsonFences(answer)))
    } catch {
      if (synthesizedStepsCount === 0 && bolaAutoSteps === 0) {
        this.plannerDoneRound.set(run.id, roundRes.roundNo)
      }
      return
    }
    if (!parsedPlanner.success) {
      if (synthesizedStepsCount === 0 && bolaAutoSteps === 0) {
        this.plannerDoneRound.set(run.id, roundRes.roundNo)
      }
      return
    }

    const currentRun = this.storage.run(run.id)
    const currentApproved = this.approvedOriginsSet(currentRun)
    const existingSteps = this.storage.listChainSteps(run.id, currentRun.goalRevision)
    let addedCount = synthesizedStepsCount + bolaAutoSteps

    for (const cancelId of parsedPlanner.data.cancelStepIds) {
      const target = existingSteps.find(s => s.id === cancelId)
      if (target && ['pending', 'ready'].includes(target.status)) {
        this.storage.updateChainStep(target.id, { status: 'canceled' })
      }
    }

    const remainingSlots = Math.max(0, dynamicStepBudget - existingSteps.length)
    const budgetedNewSteps = applyCrownJewelStepBudget(
      parsedPlanner.data.newSteps.map(step => ({ ...step, origins: step.origins.filter(o => currentApproved.has(o)) })),
      hostTiers,
      existingSteps,
      remainingSlots,
    )

    for (const step of budgetedNewSteps) {
      const validOrigins = step.origins.filter(o => currentApproved.has(o))
      const assetIds = currentRun.candidates
        .filter(c => validOrigins.includes(c.origin) && currentRun.approved.includes(c.id))
        .map(c => c.id)
      if (!assetIds.length) continue
      const specialistProfile = routeStepToSpecialist({
        title: step.title,
        hypothesis: step.hypothesis,
        category: step.category,
        skills: step.skills,
      })
      this.storage.addChainStep(currentRun, {
        title: step.title,
        hypothesis: step.hypothesis,
        category: step.category,
        priority: step.priority,
        targetAssetIds: assetIds,
        skills: step.skills,
        dependsOnFactIds: step.dependsOnFactIds,
        dependsOnStepIds: step.dependsOnStepIds,
        sourceOrigins: validOrigins,
        specialistProfile,
      })
      addedCount += 1
    }

    if ((parsedPlanner.data.done && synthesizedStepsCount === 0 && bolaAutoSteps === 0) || addedCount === 0) {
      this.plannerDoneRound.set(run.id, roundRes.roundNo)
    }
    this.storage.event(run.id, 'planner.round', `Planner round ${roundRes.roundNo}: added ${addedCount} steps.`, {
      roundNo: roundRes.roundNo, addedCount, synthesizedStepsCount, bolaAutoSteps, done: parsedPlanner.data.done, summary: parsedPlanner.data.summary.slice(0, 300),
    })
  }

  private startInvestigationStep(run: Run, step: ChainStep, profiles: readonly ResolvedModelProfile[]) {
    const primaryAsset = run.candidates.find(c => step.targetAssetIds.includes(c.id) && run.approved.includes(c.id))
    const targetOrigins = [...new Set([
      ...step.sourceOrigins,
      ...run.candidates.filter(c => step.targetAssetIds.includes(c.id) && run.approved.includes(c.id)).map(c => c.origin),
    ])].filter(o => this.permitted(run, o))
    if (!targetOrigins.length) {
      this.storage.updateChainStep(step.id, { status: 'tainted' })
      return
    }

    const tm = this.storage.latestThreatModel(run.id, run.goalRevision)
    const approvedOriginsList = [...this.approvedOriginsSet(run)]
    const hostTiers = computeHostTiers(approvedOriginsList, tm?.entries)
    const resolvedSpecialistId = step.specialistProfile ?? routeStepToSpecialist({
      title: step.title,
      hypothesis: step.hypothesis,
      category: step.category,
      skills: step.skills,
    })
    const specialistConfig = resolveSpecialistProfile(resolvedSpecialistId)
    const wakeHandle = this.wakeHandleByStepId.get(step.id)
    const warmMember = wakeHandle ? this.storage.boardMember(run.id, wakeHandle) : undefined
    const boardHandle = wakeHandle && warmMember && warmMember.state !== 'retired'
      ? wakeHandle
      : this.allocateBoardHandle(run, resolvedSpecialistId, step)
    const warmSessionId = wakeHandle && warmMember && warmMember.state !== 'retired' ? warmMember.sessionId : undefined
    const baseSpecialistTurns = Math.max(
      25,
      Math.min(specialistConfig.maxTurnsCeiling, run.workerMaxTurns > 0 ? Math.min(run.workerMaxTurns, specialistConfig.defaultMaxTurns) : specialistConfig.defaultMaxTurns),
    )
    const stepMaxTurns = computeStepMaxTurns(targetOrigins, hostTiers, baseSpecialistTurns)

    const assignment = this.storage.transaction(() => {
      const worker = this.storage.makeWorker(run, 'investigation', primaryAsset, step.title, step.hypothesis, {
        stepId: step.id,
        maxTurns: stepMaxTurns,
        parentFactIds: step.dependsOnFactIds,
        sourceOrigins: targetOrigins,
      })
      const claimed = this.storage.updateWorker(worker.id, {
        status: 'running',
        ...(warmSessionId ? { sessionId: warmSessionId } : {}),
        lease: randomUUID(),
        leaseExpiresAt: Date.now() + intentLeaseMs,
      })!
      this.storage.updateChainStep(step.id, {
        status: 'running',
        assignedWorkerId: claimed.id,
        specialistProfile: resolvedSpecialistId,
      })
      this.storage.addGraphEdge(run.id, {
        fromKind: 'step', fromId: step.id, toKind: 'assignment', toId: claimed.id, edgeKind: 'spawns',
      })
      this.storage.event(run.id, 'worker.started', `${step.title} started.`, {
        assignmentId: claimed.id, stepId: step.id, specialistProfile: resolvedSpecialistId,
      })
      return claimed
    }, { behavior: 'immediate' })
    const effectiveStep: ChainStep = { ...step, specialistProfile: resolvedSpecialistId }

    const job: Active = { assignment, origins: new Set(targetOrigins), controller: new AbortController() }
    this.active.set(assignment.id, job)
    this.boardHandleByAssignment.set(assignment.id, boardHandle)
    this.trackedBoardRuns.add(run.id)
    try {
      this.storage.upsertBoardMember(run, {
        handle: boardHandle,
        role: 'specialist',
        specialistProfile: resolvedSpecialistId,
        sessionId: assignment.sessionId,
        activeAssignmentId: assignment.id,
        state: 'working',
        sourceOrigins: targetOrigins,
      })
      this.warm.register(boardHandle, {
        sessionId: assignment.sessionId,
        state: 'waiting',
        lastReadSeq: this.storage.boardMember(run.id, boardHandle)?.lastReadSeq ?? 0,
      })
      this.warm.wake(boardHandle, assignment.id)
    } catch { /* roster mirror is best-effort */ }

    this.postCoordinatorBrief(run, effectiveStep, boardHandle, targetOrigins)

    void this.runInvestigationWorker(job, effectiveStep, targetOrigins, profiles).catch(error => {
      if (error instanceof BudgetExceededError) {
        this.storage.checkBudgetExceeded(run.id)
        return
      }
      if (!this.authorize(job) || job.controller.signal.aborted) return
      const msg = redact(error instanceof Error ? error.message : String(error)).slice(0, 400)
      this.storage.transaction(() => {
        this.storage.updateWorker(assignment.id, {
          status: 'failed', outcome: msg, lease: null, leaseExpiresAt: null, attempt: assignment.attempt + 1,
        })
        this.storage.updateChainStep(step.id, { status: 'complete', assignedWorkerId: assignment.id })
        this.storage.event(run.id, 'worker.failed', `${step.title} failed: ${msg}`, { assignmentId: assignment.id, stepId: step.id })
      })
    }).finally(() => {
      this.active.delete(assignment.id)
      try { this.finishBoardMember(this.storage.run(run.id), assignment.id) } catch { /* run may be gone */ }
      this.schedulePlanner(run.id)
      this.scheduleWake()
    })
  }

  private async runInvestigationWorker(
    job: Active,
    step: ChainStep,
    targetOrigins: string[],
    profiles: readonly ResolvedModelProfile[],
  ) {
    const run = this.check(job)
    const permittedAtAdmission = this.approvedOriginsSet(run)
    const { grant, secrets, currentSecrets } = this.buildGrant(job, run, permittedAtAdmission)

    // Open ONE persistent air-gapped container for the entire intent
    const { reposDir, mountedRepos } = this.projectReposMount(run.projectId)
    const session = await this.backend.openSession(
      job.assignment.id,
      job.controller.signal,
      reposDir ? { reposDir } : undefined,
    )
    const startedAt = Date.now()

    try {
      // Stage relevant specs and parent facts inside the air-gapped container
      const specs = this.storage.listProjectSpecsFull(run.projectId)
      const stagedSpecs: Array<{ name: string; kind: string; origin?: string | null; stagedPath?: string }> = []
      for (const [idx, spec] of specs.slice(0, 8).entries()) {
        const safeName = `specs/spec-${idx + 1}.txt`
        try {
          const stagedPath = await session.stage(safeName, spec.content.slice(0, 1_500_000), job.controller.signal)
          stagedSpecs.push({ name: spec.name, kind: spec.kind, origin: spec.origin, stagedPath })
        } catch { /* skip oversized */ }
      }

      const parentFacts = step.dependsOnFactIds.length
        ? this.storage.listFacts(run.id, { includeTainted: false, limit: 200 })
            .filter(f => step.dependsOnFactIds.includes(f.id) && permittedAtAdmission.has(f.origin))
        : []
      if (parentFacts.length) {
        await session.stage('parent-facts.json', JSON.stringify(parentFacts, null, 2), job.controller.signal).catch(() => undefined)
      }

      const trackPersonaResources = (curRun: Run, res: BrokerExchangeResult, exchangeId: string) => {
        // Persist samples + producer->consumer edges for authenticated AND unauthenticated responses.
        // (Unauthenticated leaks can seed later cross-persona BOLA/IDOR replay targets.)
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
        let seenSet = this.recordedPersonaResources.get(curRun.id)
        if (!seenSet) {
          seenSet = new Set<string>()
          this.recordedPersonaResources.set(curRun.id, seenSet)
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

      const executeBrokerRequest = async (args: RequestHttpArgs, signal: AbortSignal): Promise<{
        exchangeId: string
        stagedPath: string | null
        result: BrokerExchangeResult
      }> => {
        const curRun = this.check(job)
        if (this.storage.checkBudgetExceeded(curRun.id)) {
          throw new BudgetExceededError('Run spend or request budget exceeded.')
        }
        const headers = { ...(args.headers ?? {}) }
        let body: string | undefined
        if (args.textBody !== undefined) {
          body = args.textBody
        } else if (args.jsonBody !== undefined) {
          body = JSON.stringify(args.jsonBody)
          if (!headers['Content-Type'] && !headers['content-type']) headers['Content-Type'] = 'application/json'
        }

        const runHttp = () => this.broker.executeHttp({
          origin: args.origin,
          method: args.method,
          pathAndQuery: args.pathAndQuery,
          headers,
          body,
          multipartParts: args.multipartParts,
          persona: args.persona,
          session: args.session,
          csrfBind: args.csrfBind,
          authMutation: args.authMutation,
          probeClass: args.probeClass,
          traceId: args.traceId,
          runId: curRun.id,
          assignmentId: job.assignment.id,
          scopeRevision: curRun.scopeRevision,
          followRedirects: args.followRedirects ?? false,
        }, grant, signal)

        let res: BrokerExchangeResult
        try {
          res = await runHttp()
        } catch (err) {
          if (err instanceof BrokerApprovalRequired) {
            const approval = await this.waitForTier3Approval(job, {
              origin: err.origin,
              method: err.method,
              pathAndQuery: err.pathAndQuery,
              personaHandle: args.persona ?? null,
              rationale: args.rationale ?? `Tier 3 probe during step "${step.title}"`,
              requestPreview: JSON.stringify({
                method: args.method, origin: args.origin, pathAndQuery: args.pathAndQuery,
                persona: args.persona, headers, bodyPreview: body?.slice(0, 500),
                ...(args.multipartParts?.length ? { multipartPartsCount: args.multipartParts.length } : {}),
              }, null, 2),
              bodyPreview: body,
              headers,
              hasMultipart: Boolean(args.multipartParts?.length),
              secrets: currentSecrets(),
            }, signal)
            if (!approval.approved) {
              throw new BrokerDenied(
                approval.deniedReason
                  ? `Tier 3 Safety Judge denied probe: ${approval.deniedReason}`
                  : 'Tier 3 request was denied or expired.',
              )
            }
            res = await runHttp()
          } else {
            throw err
          }
        }

        const saved = this.storage.recordExchange({
          runId: curRun.id,
          assignmentId: job.assignment.id,
          scopeRevision: curRun.scopeRevision,
          origin: res.origin,
          finalOrigin: res.finalOrigin,
          redirectOrigins: res.redirectOrigins,
          method: res.method,
          pathAndQuery: res.pathAndQuery,
          personaHandle: res.personaHandle,
          status: res.status,
          mediaType: res.mediaType,
          reqHeaders: res.reqHeaders,
          respHeaders: res.respHeaders,
          body: res.body,
          durationMs: res.durationMs,
          secretMatches: res.secretMatches,
          secrets: currentSecrets(),
        })

        // Priority #3: Auto-track persona_resource facts when Tier >= 2 and >= 2 personas are approved
        trackPersonaResources(curRun, res, saved.id)
        boardTools.noteEvidence()
        this.markEndpointCoverage(curRun, res.origin, res.method, res.pathAndQuery, 'http_exchange')
        this.scanSecondOrderExchange(curRun, job.assignment.id, res, saved.id)

        let stagedPath: string | null = null
        try {
          stagedPath = await session.stage(`exchanges/${saved.id}.json`, JSON.stringify({
            exchangeId: saved.id,
            origin: res.origin,
            finalOrigin: res.finalOrigin,
            redirectOrigins: res.redirectOrigins,
            method: res.method,
            pathAndQuery: res.pathAndQuery,
            status: res.status,
            mediaType: res.mediaType,
            reqHeaders: res.reqHeaders,
            respHeaders: res.respHeaders,
            setCookies: res.setCookies,
            bodySha256: res.bodySha256,
            body: res.body,
          }, null, 2), signal)
        } catch { /* ignore stage error */ }
        return { exchangeId: saved.id, stagedPath, result: res }
      }

      const executeRaceBurstTool = async (args: RequestHttpRaceArgs, signal: AbortSignal) => {
        const curRun = this.check(job)
        if (curRun.capabilityTier < 2) {
          throw new BrokerDenied('Race-condition burst testing requires Capability Tier 2 or Tier 3.')
        }
        if (this.storage.checkBudgetExceeded(curRun.id)) {
          throw new BudgetExceededError('Run spend or request budget exceeded.')
        }
        if (curRun.budgetRequests > 0 && curRun.spentRequests + args.requests.length > curRun.budgetRequests) {
          throw new BudgetExceededError('Race burst would exceed run request budget.')
        }
        const brokerReqs = args.requests.map(r => {
          const headers = { ...(r.headers ?? {}) }
          let body: string | undefined
          if (r.textBody !== undefined) body = r.textBody
          else if (r.jsonBody !== undefined) {
            body = JSON.stringify(r.jsonBody)
            if (!headers['Content-Type'] && !headers['content-type']) headers['Content-Type'] = 'application/json'
          }
          return {
            origin: r.origin,
            method: r.method,
            pathAndQuery: r.pathAndQuery,
            headers,
            body,
            persona: r.persona,
            session: r.session,
            csrfBind: r.csrfBind,
            authMutation: r.authMutation,
            probeClass: r.probeClass,
            traceId: r.traceId,
            runId: curRun.id,
            assignmentId: job.assignment.id,
            scopeRevision: curRun.scopeRevision,
            followRedirects: r.followRedirects ?? false,
          }
        })

        let burst
        try {
          burst = await this.broker.executeRaceBurst(brokerReqs, grant, signal)
        } catch (err) {
          if (err instanceof BrokerApprovalRequired) {
            const approval = await this.waitForTier3Approval(job, {
              origin: err.origin,
              method: err.method,
              pathAndQuery: err.pathAndQuery,
              personaHandle: args.requests[0]?.persona ?? null,
              rationale: args.rationale ?? `Tier 3 concurrent race burst (${args.requests.length}x) during step "${step.title}"`,
              requestPreview: JSON.stringify({
                count: args.requests.length,
                sample: args.requests[0],
              }, null, 2),
              bodyPreview: brokerReqs[0]?.body,
              headers: brokerReqs[0]?.headers,
              isRaceBurst: true,
              secrets: currentSecrets(),
            }, signal)
            if (!approval.approved) {
              throw new BrokerDenied(
                approval.deniedReason
                  ? `Tier 3 Safety Judge denied race-burst probe: ${approval.deniedReason}`
                  : 'Tier 3 race-burst request was denied or expired.',
              )
            }
            burst = await this.broker.executeRaceBurst(brokerReqs, grant, signal)
          } else {
            throw err
          }
        }

        const summaries = burst.results.map(res => {
          const saved = this.storage.recordExchange({
            runId: curRun.id,
            assignmentId: job.assignment.id,
            scopeRevision: curRun.scopeRevision,
            origin: res.origin,
            finalOrigin: res.finalOrigin,
            redirectOrigins: res.redirectOrigins,
            method: res.method,
            pathAndQuery: res.pathAndQuery,
            personaHandle: res.personaHandle,
            status: res.status,
            mediaType: res.mediaType,
            reqHeaders: res.reqHeaders,
            respHeaders: res.respHeaders,
            body: res.body,
            durationMs: res.durationMs,
            secretMatches: res.secretMatches,
            secrets: currentSecrets(),
          })
          trackPersonaResources(curRun, res, saved.id)
          this.markEndpointCoverage(curRun, res.origin, res.method, res.pathAndQuery, 'http_exchange')
          this.scanSecondOrderExchange(curRun, job.assignment.id, res, saved.id)
          return {
            exchangeId: saved.id,
            origin: res.origin,
            method: res.method,
            pathAndQuery: res.pathAndQuery,
            personaHandle: res.personaHandle,
            status: res.status,
            durationMs: res.durationMs,
            bodySha256: res.bodySha256,
            bodyPreview: res.bodyPreview.slice(0, 800),
          }
        })
        const stagedPath = await session.stage(`exchanges/race-${randomUUID().slice(0, 8)}.json`,
          JSON.stringify({ summary: burst.summary, results: summaries }, null, 2), signal).catch(() => null)
        boardTools.noteEvidence()
        return { count: summaries.length, summary: burst.summary, stagedPath, results: summaries }
      }

      const boardHandle = this.boardHandleByAssignment.get(job.assignment.id) ??
        this.boardHandleForAssignmentId(run, job.assignment.id)
      const boardTools = createBoardTools({
        store: this.storage,
        run: run.id,
        handle: boardHandle,
        redact: (text: string) => redact(text, currentSecrets()),
        onWakeup: (target, message) => {
          try { this.wakeBoardMember(this.storage.run(run.id), target, message) } catch { /* advisory */ }
        },
      })

      const handlers: WorkerToolHandlers = {
        spillOutput: async (id, content, signal) => session.stage(`tool-output/${id}.txt`, content, signal),

        board_post: async (args) => boardTools.board_post(args),
        board_read: async (args) => boardTools.board_read(args),

        request_http: async (args, signal) => {
          const { exchangeId, stagedPath, result } = await executeBrokerRequest(args, signal)
          return {
            exchangeId,
            stagedPath,
            origin: result.origin,
            finalOrigin: result.finalOrigin,
            redirectOrigins: result.redirectOrigins,
            status: result.status,
            mediaType: result.mediaType,
            respHeaders: result.respHeaders,
            setCookies: result.setCookies,
            bodyBytes: result.bodyBytes,
            bodySha256: result.bodySha256,
            bodyPreview: result.bodyPreview.slice(0, 6000),
            durationMs: result.durationMs,
          }
        },

        request_http_batch: async (args, signal) => {
          const curRun = this.check(job)
          if (this.storage.checkBudgetExceeded(curRun.id)) throw new BudgetExceededError('Budget exceeded.')
          const brokerReqs = args.requests.map(r => {
            const headers = { ...(r.headers ?? {}) }
            let body: string | undefined
            if (r.textBody !== undefined) body = r.textBody
            else if (r.jsonBody !== undefined) {
              body = JSON.stringify(r.jsonBody)
              if (!headers['Content-Type'] && !headers['content-type']) headers['Content-Type'] = 'application/json'
            }
            return {
              origin: r.origin, method: r.method, pathAndQuery: r.pathAndQuery,
              headers, body, persona: r.persona, session: r.session,
              csrfBind: r.csrfBind, authMutation: r.authMutation, probeClass: r.probeClass,
              traceId: r.traceId, runId: curRun.id, assignmentId: job.assignment.id,
              scopeRevision: curRun.scopeRevision,
              followRedirects: r.followRedirects ?? false,
            }
          })
          const results = await this.broker.executeBatch(brokerReqs, grant, signal)
          const summaries = results.map(res => {
            const saved = this.storage.recordExchange({
              runId: curRun.id,
              assignmentId: job.assignment.id,
              scopeRevision: curRun.scopeRevision,
              origin: res.origin,
              finalOrigin: res.finalOrigin,
              redirectOrigins: res.redirectOrigins,
              method: res.method,
              pathAndQuery: res.pathAndQuery,
              personaHandle: res.personaHandle,
              status: res.status,
              mediaType: res.mediaType,
              reqHeaders: res.reqHeaders,
              respHeaders: res.respHeaders,
              body: res.body,
              durationMs: res.durationMs,
              secretMatches: res.secretMatches,
              secrets: currentSecrets(),
            })
            trackPersonaResources(curRun, res, saved.id)
            this.markEndpointCoverage(curRun, res.origin, res.method, res.pathAndQuery, 'http_exchange')
            this.scanSecondOrderExchange(curRun, job.assignment.id, res, saved.id)
            return {
              exchangeId: saved.id, status: res.status, durationMs: res.durationMs,
              bodySha256: res.bodySha256, bodyPreview: res.bodyPreview.slice(0, 800),
            }
          })
          const stagedPath = await session.stage(`exchanges/batch-${randomUUID().slice(0, 8)}.json`,
            JSON.stringify(summaries, null, 2), signal).catch(() => null)
          boardTools.noteEvidence()
          return { count: summaries.length, stagedPath, results: summaries }
        },

        requestHttpRace: executeRaceBurstTool,
        request_http_race: executeRaceBurstTool,

        inspect_dns: async ({ origin }, signal) => {
          const curRun = this.check(job)
          const dnsRes = await this.broker.inspectDns(origin, grant, signal)
          const ev = this.storage.addArtifact(curRun, job.assignment, 'dns',
            `DNS inspection · ${dnsRes.hostname}`, JSON.stringify(dnsRes, null, 2), undefined, secrets)
          const stagedPath = await session.stage(`dns-${dnsRes.hostname.replace(/[^a-z0-9.-]/gi, '_')}.json`,
            JSON.stringify(dnsRes, null, 2), signal).catch(() => null)
          return { evidenceId: ev.id, stagedPath, ...dnsRes }
        },

        inspect_tls: async ({ origin }, signal) => {
          const curRun = this.check(job)
          const tlsRes = await this.broker.inspectTls(origin, grant, signal)
          const ev = this.storage.addArtifact(curRun, job.assignment, 'tls',
            `TLS audit · ${tlsRes.hostname}`, JSON.stringify(tlsRes, null, 2), undefined, secrets)
          const stagedPath = await session.stage(`tls-${tlsRes.hostname.replace(/[^a-z0-9.-]/gi, '_')}.json`,
            JSON.stringify(tlsRes, null, 2), signal).catch(() => null)
          return { evidenceId: ev.id, stagedPath, ...tlsRes }
        },

        browser_visit: async (args, signal) => {
          const curRun = this.check(job)
          if (this.storage.checkBudgetExceeded(curRun.id)) throw new BudgetExceededError('Budget exceeded.')
          const res = await this.browser.visitPage({
            origin: args.origin,
            pathAndQuery: args.pathAndQuery,
            persona: args.persona,
            session: args.session,
            runId: curRun.id,
            assignmentId: job.assignment.id,
            traceId: randomUUID(),
            checkKind: args.domCheck && args.domCheck !== 'none' ? args.domCheck : undefined,
            actions: args.actions,
            enableSinkHook: args.enableSinkHook,
            waitAfterLoadMs: args.waitAfterLoadMs,
            secrets: currentSecrets(),
            onExchange: ex => {
              const saved = this.storage.recordExchange({
                runId: curRun.id,
                assignmentId: job.assignment.id,
                scopeRevision: curRun.scopeRevision,
                origin: ex.origin,
                finalOrigin: ex.finalOrigin,
                redirectOrigins: ex.redirectOrigins,
                method: ex.method,
                pathAndQuery: ex.pathAndQuery,
                personaHandle: ex.personaHandle,
                status: ex.status,
                mediaType: ex.mediaType,
                reqHeaders: ex.reqHeaders,
                respHeaders: ex.respHeaders,
                body: ex.body,
                durationMs: ex.durationMs,
                secretMatches: ex.secretMatches,
                secrets: currentSecrets(),
              })
              this.scanSecondOrderExchange(curRun, job.assignment.id, ex, saved.id)
              return saved.id
            },
          }, grant, signal)
          const summaryObj = {
            origin: res.origin,
            finalUrl: res.finalUrl,
            title: res.title,
            status: res.status,
            links: res.links.slice(0, 60),
            forms: res.forms.slice(0, 30),
            xhrRequests: res.xhrRequests.slice(0, 80),
            blockedOrigins: res.blockedOrigins,
            consoleMessages: res.consoleMessages.slice(0, 40),
            postMessageListeners: res.postMessageListeners,
            cookieNames: res.cookieNames,
            localStorageKeys: res.localStorageKeys,
            sessionStorageKeys: res.sessionStorageKeys,
            canaryCheck: res.canaryCheck,
            actionResults: res.actionResults,
            builtinResults: res.builtinResults,
            domSinkTraces: res.domSinkTraces,
            exchangeIds: res.exchangeIds,
            domSnippet: res.domSnippet.slice(0, 6000),
            durationMs: res.durationMs,
          }
          const ev = this.storage.addArtifact(curRun, job.assignment, 'browser',
            `Browser visit · ${args.origin}${args.pathAndQuery.slice(0, 60)}`,
            JSON.stringify(summaryObj, null, 2), undefined, currentSecrets())
          const stagedPath = await session.stage(`browser-${ev.id.slice(0, 8)}.json`,
            JSON.stringify(summaryObj, null, 2), signal).catch(() => null)
          boardTools.noteEvidence()
          return { evidenceId: ev.id, stagedPath, ...summaryObj }
        },

        browser_session: async ({ steps }, signal) => {
          const curRun = this.check(job)
          if (this.storage.checkBudgetExceeded(curRun.id)) throw new BudgetExceededError('Budget exceeded.')
          const visits = await this.browser.runBrowserSession(
            steps.map(s => ({
              ...s,
              runId: curRun.id,
              assignmentId: job.assignment.id,
              secrets: currentSecrets(),
              onExchange: ex => {
                const saved = this.storage.recordExchange({
                  runId: curRun.id,
                  assignmentId: job.assignment.id,
                  scopeRevision: curRun.scopeRevision,
                  origin: ex.origin,
                  finalOrigin: ex.finalOrigin,
                  redirectOrigins: ex.redirectOrigins,
                  method: ex.method,
                  pathAndQuery: ex.pathAndQuery,
                  personaHandle: ex.personaHandle,
                  status: ex.status,
                  mediaType: ex.mediaType,
                  reqHeaders: ex.reqHeaders,
                  respHeaders: ex.respHeaders,
                  body: ex.body,
                  durationMs: ex.durationMs,
                  secretMatches: ex.secretMatches,
                  secrets: currentSecrets(),
                })
                trackPersonaResources(curRun, ex, saved.id)
              this.scanSecondOrderExchange(curRun, job.assignment.id, ex, saved.id)
                return saved.id
              },
            })),
            grant,
            signal,
          )
          const summarized = visits.map(({ exchanges: _ex, ...rest }) => ({
            ...rest,
            domSnippet: rest.domSnippet.slice(0, 2000),
          }))
          const ev = this.storage.addArtifact(curRun, job.assignment, 'browser',
            `Browser session (${steps.length} steps)`,
            JSON.stringify(summarized, null, 2), undefined, currentSecrets())
          return { evidenceId: ev.id, stepsCount: visits.length, visits: summarized }
        },

        crawl_state_graph: async (args, signal) => {
          const curRun = this.check(job)
          if (this.storage.checkBudgetExceeded(curRun.id)) throw new BudgetExceededError('Budget exceeded.')
          const cleanOrigin = this.parseOriginForRun(curRun, args.origin)
          const remainingReqs = curRun.budgetRequests > 0
            ? Math.max(0, curRun.budgetRequests - curRun.spentRequests)
            : undefined
          const crawlRes = await crawlStateGraph({
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
          return crawlRes
        },

        run_sast_scan: async (args, signal) => {
          const curRun = this.check(job)
          const res = await session.sast(args, signal)
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

          // SCA (trivy-fs) findings carry CVE ids. Record them as low-confidence hypotheses so the
          // planner and safe-template runner can target real advisories (never auto-confirmed).
          const scaCves = new Map<string, { file: string; severity: string }>()
          for (const finding of res.findings) {
            if (finding.engine !== 'trivy-fs') continue
            for (const match of `${finding.ruleId} ${finding.message}`.matchAll(/CVE-\d{4}-\d{4,}/gi)) {
              const cve = match[0].toUpperCase()
              if (!scaCves.has(cve)) scaCves.set(cve, { file: finding.file, severity: finding.severity })
            }
          }
          if (scaCves.size > 0) {
            const targetOrigin = [...this.approvedOriginsSet(curRun)][0]
            const existingCves = new Set(
              this.storage.listFacts(curRun.id, { includeTainted: false, kind: 'cve_hypothesis', limit: 100 })
                .map(f => (typeof f.data?.cveId === 'string' ? f.data.cveId.toUpperCase() : '')),
            )
            for (const [cve, meta] of [...scaCves.entries()].slice(0, 40)) {
              if (!targetOrigin || existingCves.has(cve)) continue
              existingCves.add(cve)
              this.storage.addFact(curRun, job.assignment, {
                kind: 'cve_hypothesis',
                origin: targetOrigin,
                summary: `trivy-fs flagged ${cve} (${meta.severity}) in ${res.repo}/${meta.file}. Hypothesis only: verify runtime reachability with a non-destructive Replay Spec.`,
                data: {
                  cveId: cve,
                  repo: res.repo,
                  file: meta.file,
                  severity: meta.severity,
                  source: 'trivy-fs',
                  templateIds: templateIdsForCves([cve]),
                  confidence: 'low',
                },
                sourceOrigins: [targetOrigin],
                secrets: currentSecrets(),
              })
            }
          }
          return { evidenceId: ev.id, ...res }
        },

        run_offline_script: async (args, signal) => {
          const curRun = this.check(job)
          const res = await session.runScript(args, signal)
          const ev = this.storage.addArtifact(curRun, job.assignment, 'analysis',
            `Offline ${args.runtime} script`,
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

        probe_surface: async (args, signal) => {
          const curRun = this.check(job)
          if (this.storage.checkBudgetExceeded(curRun.id)) throw new BudgetExceededError('Run spend or request budget exceeded.')
          const cleanOrigin = this.parseOriginForRun(curRun, args.origin)
          const remainingReqs = curRun.budgetRequests > 0
            ? Math.max(0, curRun.budgetRequests - curRun.spentRequests)
            : (args.maxRequests ?? 150)
          if (curRun.budgetRequests > 0 && remainingReqs <= 0) {
            throw new BudgetExceededError('Run request budget exhausted.')
          }
          const cappedMax = args.maxRequests !== undefined
            ? Math.min(args.maxRequests, remainingReqs)
            : Math.min(150, remainingReqs)

          const res = await probeSurface({
            origin: cleanOrigin,
            mode: args.mode,
            wordlists: args.wordlists?.length ? args.wordlists : (args.wordlist ? [args.wordlist] : undefined),
            paths: args.mode === 'paths' ? args.candidates : undefined,
            params: args.mode === 'params' ? args.candidates : undefined,
            basePath: args.basePath,
            paramLocation: args.paramLocation,
            methods: args.methods,
            persona: args.persona,
            maxRequests: cappedMax,
            onExchange: ex => {
              const saved = this.storage.recordExchange({
                runId: curRun.id,
                assignmentId: job.assignment.id,
                scopeRevision: curRun.scopeRevision,
                origin: ex.origin,
                finalOrigin: ex.finalOrigin,
                redirectOrigins: ex.redirectOrigins,
                method: ex.method,
                pathAndQuery: ex.pathAndQuery,
                personaHandle: ex.personaHandle,
                status: ex.status,
                mediaType: ex.mediaType,
                reqHeaders: ex.reqHeaders,
                respHeaders: ex.respHeaders,
                body: ex.body,
                durationMs: ex.durationMs,
                secretMatches: ex.secretMatches,
                secrets: currentSecrets(),
              })
              trackPersonaResources(curRun, ex, saved.id)
              this.scanSecondOrderExchange(curRun, job.assignment.id, ex, saved.id)
              return saved.id
            },
          }, this.broker, grant, signal)

          this.markEndpointCoverage(
            curRun,
            res.origin,
            args.methods?.[0] ?? 'GET',
            args.basePath ?? '/',
            `surface:${res.mode}`,
          )
          this.storage.recordSurfaceProbe({
            runId: curRun.id,
            assignmentId: job.assignment.id,
            scopeRevision: curRun.scopeRevision,
            origin: res.origin,
            probeKind: `surface:${res.mode}`,
            requestsSent: res.requestsSent,
            anomaliesFound: res.anomalies.length,
            baselineSignature: res.baselineSignature,
          })
          const ev = this.storage.addArtifact(curRun, job.assignment, 'surface',
            `Surface probe (${res.mode}) · ${res.origin}`,
            JSON.stringify(res, null, 2), undefined, currentSecrets())
          const stagedPath = await session.stage(`surface-${ev.id.slice(0, 8)}.json`,
            JSON.stringify(res, null, 2), signal).catch(() => null)
          return { evidenceId: ev.id, stagedPath, ...res }
        },

        probe_differential: async (args, signal) => {
          const curRun = this.check(job)
          if (this.storage.checkBudgetExceeded(curRun.id)) throw new BudgetExceededError('Run spend or request budget exceeded.')
          const cleanOrigin = this.parseOriginForRun(curRun, args.origin)
          const remainingReqs = curRun.budgetRequests > 0
            ? Math.max(0, curRun.budgetRequests - curRun.spentRequests)
            : (args.maxRequests ?? 60)
          if (curRun.budgetRequests > 0 && remainingReqs <= 0) {
            throw new BudgetExceededError('Run request budget exhausted.')
          }
          const cappedMax = args.maxRequests !== undefined
            ? Math.min(args.maxRequests, remainingReqs)
            : Math.min(60, remainingReqs)

          // Default parameter / resource-ID selection from persisted endpoint_params & api_dependencies.
          const requestedTemplate = normalizeEndpointTemplate(args.pathAndQuery.split('?')[0] || '/')
          const targetEndpoint = this.storage.listEndpoints(curRun.id, { origin: cleanOrigin })
            .find(ep => ep.pathTemplate === requestedTemplate &&
              (!args.method || ep.method === args.method.toUpperCase()))
            ?? this.storage.listEndpoints(curRun.id, { origin: cleanOrigin })
              .find(ep => ep.pathTemplate === requestedTemplate)
          const targetParams = targetEndpoint ? this.storage.listEndpointParams(curRun.id, targetEndpoint.id) : []
          const injectableParams = targetParams.filter(p => ['query', 'json', 'form', 'path', 'graphql_var'].includes(p.location) && !p.isCsrf)
          const preferredParam = [...injectableParams].sort((a, b) =>
            Number(DETERMINISTIC_PARAM_HINT_RE.test(b.name)) - Number(DETERMINISTIC_PARAM_HINT_RE.test(a.name)) ||
            Number(a.isObjectId) - Number(b.isObjectId),
          )[0]
          const resolvedParamName = args.paramName ?? preferredParam?.name
          const preferredParamLocation = preferredParam && preferredParam.location !== 'cookie'
            ? preferredParam.location
            : undefined
          const resolvedParamLocation = args.paramLocation ?? preferredParamLocation
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
          const resolvedSsrfParams = args.ssrfParams?.length
            ? args.ssrfParams
            : injectableParams
                .map(param => param.name)
                .filter(name => /(?:url|uri|link|redirect|callback|dest|host|path|file|fetch|webhook|next|return)/i.test(name))
                .slice(0, 16)

          if (args.probeClass === 'ssrf_canary') {
            const project = this.storage.project(curRun.projectId)
            if (this.isCanaryListenerConfigured() || (project.environment === 'local-lab' && isLocalLabEnvEnabled())) {
              await this.canaryBroker.startListener({ enableDns: this.isCanaryDnsConfigured() }).catch(() => undefined)
            }
          }

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
            onExchange: ex => {
              const saved = this.storage.recordExchange({
                runId: curRun.id,
                assignmentId: job.assignment.id,
                scopeRevision: curRun.scopeRevision,
                origin: ex.origin,
                finalOrigin: ex.finalOrigin,
                redirectOrigins: ex.redirectOrigins,
                method: ex.method,
                pathAndQuery: ex.pathAndQuery,
                personaHandle: ex.personaHandle,
                status: ex.status,
                mediaType: ex.mediaType,
                reqHeaders: ex.reqHeaders,
                respHeaders: ex.respHeaders,
                body: ex.body,
                durationMs: ex.durationMs,
                secretMatches: ex.secretMatches,
                secrets: currentSecrets(),
              })
              trackPersonaResources(curRun, ex, saved.id)
              this.scanSecondOrderExchange(curRun, job.assignment.id, ex, saved.id)
              return saved.id
            },
          }, this.broker, grant, this.canaryBroker, signal)

          this.markEndpointCoverage(
            curRun,
            res.origin,
            args.method ?? 'GET',
            args.pathAndQuery,
            `diff:${res.probeClass}`,
          )
          this.storage.recordSurfaceProbe({
            runId: curRun.id,
            assignmentId: job.assignment.id,
            scopeRevision: curRun.scopeRevision,
            origin: res.origin,
            probeKind: `diff:${res.probeClass}`,
            requestsSent: res.requestsSent,
            anomaliesFound: res.anomalies.length,
            baselineSignature: res.verdict,
          })
          const ev = this.storage.addArtifact(curRun, job.assignment, 'surface',
            `Differential probe (${res.probeClass}) · ${res.origin}${args.pathAndQuery.slice(0, 48)}`,
            JSON.stringify(res, null, 2), undefined, currentSecrets())
          const stagedPath = await session.stage(`diff-${ev.id.slice(0, 8)}.json`,
            JSON.stringify(res, null, 2), signal).catch(() => null)
          return { evidenceId: ev.id, stagedPath, ...res }
        },

        run_safe_templates: async (args, signal) => {
          const curRun = this.check(job)
          if (this.storage.checkBudgetExceeded(curRun.id)) throw new BudgetExceededError('Run spend or request budget exceeded.')
          const cleanOrigin = this.parseOriginForRun(curRun, args.origin)
          const remainingReqs = curRun.budgetRequests > 0
            ? Math.max(0, curRun.budgetRequests - curRun.spentRequests)
            : 150
          if (curRun.budgetRequests > 0 && remainingReqs <= 0) {
            throw new BudgetExceededError('Run request budget exhausted.')
          }

          const techFactTags = this.storage.listFacts(curRun.id, { includeTainted: false, origin: cleanOrigin, kind: 'tech_fingerprint', limit: 30 })
            .flatMap(f => {
              const tags = f.data?.tags
              return Array.isArray(tags) ? tags.filter((t): t is string => typeof t === 'string') : []
            })
          const techFingerprint = [...new Set([...(args.techTags ?? []), ...techFactTags])]

          // Feed recent CVE hypotheses and recon-discovered routes into template selection so
          // dynamic placeholders ({{discovered_protected_path}} / {{discovered_api_path}}) target
          // real live paths instead of hardcoded guesses.
          const cveIds = [...new Set(
            this.storage.listFacts(curRun.id, { includeTainted: false, kind: 'cve_hypothesis', limit: 40 })
              .map(f => (typeof f.data?.cveId === 'string' ? f.data.cveId.trim().toUpperCase() : ''))
              .filter(cve => /^CVE-\d{4}-\d{4,}$/i.test(cve)),
          )]
          const liveOrigins = this.approvedOriginsSet(curRun)
          const runEndpoints = this.storage.listEndpoints(curRun.id)
            .filter(ep => liveOrigins.has(ep.origin))
          const protectedPaths = [...new Set(
            runEndpoints
              .map(ep => ep.pathTemplate.split('?')[0])
              .filter(path => /(admin|account|billing|settings|invoice|dashboard)/i.test(path)),
          )].slice(0, 6)
          const apiPaths = [...new Set(
            runEndpoints
              .map(ep => ep.pathTemplate.split('?')[0])
              .filter(path => /^\/(api|graphql|trpc)/i.test(path)),
          )].slice(0, 6)

          const res = await runSafeTemplates({
            origin: cleanOrigin,
            techFingerprint: techFingerprint.length ? techFingerprint : undefined,
            ...(templateIdsForCves(cveIds).length || args.templateIds?.length
              ? { templateIds: [...new Set([...(args.templateIds ?? []), ...templateIdsForCves(cveIds)])] }
              : {}),
            ...(cveIds.length ? { cveIds } : {}),
            ...(protectedPaths.length || apiPaths.length
              ? { discoveredPaths: { protectedPaths, apiPaths } }
              : {}),
            maxTemplates: args.maxTemplates,
            maxRequests: Math.min(150, remainingReqs),
            persona: args.persona,
            runId: curRun.id,
            assignmentId: job.assignment.id,
            storage: this.storage,
            onExchange: ex => {
              const saved = this.storage.recordExchange({
                runId: curRun.id,
                assignmentId: job.assignment.id,
                scopeRevision: curRun.scopeRevision,
                origin: ex.origin,
                finalOrigin: ex.finalOrigin,
                redirectOrigins: ex.redirectOrigins,
                method: ex.method,
                pathAndQuery: ex.pathAndQuery,
                personaHandle: ex.personaHandle,
                status: ex.status,
                mediaType: ex.mediaType,
                reqHeaders: ex.reqHeaders,
                respHeaders: ex.respHeaders,
                body: ex.body,
                durationMs: ex.durationMs,
                secretMatches: ex.secretMatches,
                secrets: currentSecrets(),
              })
              return saved.id
            },
          }, this.broker, grant, this.canaryBroker, signal)

          this.storage.recordSurfaceProbe({
            runId: curRun.id,
            assignmentId: job.assignment.id,
            scopeRevision: curRun.scopeRevision,
            origin: res.origin,
            probeKind: 'safe_templates',
            requestsSent: res.requestsSent,
            anomaliesFound: res.matches.length,
            baselineSignature: res.baselineSignature,
          })

          // Record template matches strictly as hypothesis/lead facts (NEVER auto-confirmed!)
          for (const match of res.matches) {
            this.storage.addFact(curRun, job.assignment, {
              kind: match.factKind === 'cve_hypothesis' ? 'cve_hypothesis' : 'note',
              origin: res.origin,
              summary: `[Safe template ${match.templateId}] ${match.name} (${match.severity}) on ${match.method} ${match.path} (HTTP ${match.status})`,
              data: {
                templateId: match.templateId,
                cve: match.cve ?? null,
                cwe: match.cwe ?? null,
                severity: match.severity,
                evidence: match.evidence,
                controlStatus: match.controlStatus,
                confidence: 'low',
              },
              exchangeIds: match.exchangeId ? [match.exchangeId] : [],
              sourceOrigins: [res.origin],
              secrets: currentSecrets(),
            })
          }

          const ev = this.storage.addArtifact(curRun, job.assignment, 'surface',
            `Safe templates · ${res.origin} (${res.matches.length} matches)`,
            JSON.stringify(res, null, 2), undefined, currentSecrets())
          const stagedPath = await session.stage(`templates-${ev.id.slice(0, 8)}.json`,
            JSON.stringify(res, null, 2), signal).catch(() => null)
          return { evidenceId: ev.id, stagedPath, ...res }
        },

        probe_websocket: async (args, signal) => {
          const curRun = this.check(job)
          if (this.storage.checkBudgetExceeded(curRun.id)) throw new BudgetExceededError('Run spend or request budget exceeded.')
          const cleanOrigin = this.parseOriginForRun(curRun, args.origin)
          const wsRes = await this.broker.probeWebsocket({
            origin: cleanOrigin,
            pathAndQuery: args.pathAndQuery,
            originHeader: args.spoofOrigin,
            persona: args.persona,
            subprotocols: args.subprotocols,
            sendMessages: args.messages,
            maxFrames: args.maxFrames,
            timeoutMs: args.timeoutMs,
            secrets: currentSecrets(),
          }, grant, signal)
          const syntheticEx = websocketResultToExchange(wsRes)
          const saved = this.storage.recordExchange({
            runId: curRun.id,
            assignmentId: job.assignment.id,
            scopeRevision: curRun.scopeRevision,
            origin: syntheticEx.origin,
            finalOrigin: syntheticEx.finalOrigin,
            redirectOrigins: syntheticEx.redirectOrigins,
            method: syntheticEx.method,
            pathAndQuery: syntheticEx.pathAndQuery,
            personaHandle: syntheticEx.personaHandle,
            status: syntheticEx.status,
            mediaType: syntheticEx.mediaType,
            reqHeaders: syntheticEx.reqHeaders,
            respHeaders: syntheticEx.respHeaders,
            body: syntheticEx.body,
            durationMs: syntheticEx.durationMs,
            secretMatches: syntheticEx.secretMatches,
            secrets: currentSecrets(),
          })
          // Second-order markers can surface in WebSocket frames or upgrade headers.
          const wsScanText = [
            ...Object.entries(wsRes.upgradeHeaders ?? {}).map(([k, v]) => `${k}: ${v}`),
            ...wsRes.frames.map(frame => frame.data),
          ].join('\n')
          if (wsScanText.includes('gn2o_')) {
            const surfaced = scanSecondOrderMarkers({
              text: wsScanText,
              runId: curRun.id,
              assignmentId: job.assignment.id,
              origin: wsRes.origin,
              endpoint: wsRes.pathAndQuery,
              persona: wsRes.personaHandle,
              mediaType: 'websocket',
              exchangeId: saved.id,
              storage: this.storage,
            })
            for (const record of surfaced) {
              this.postCanaryLead(curRun, {
                marker: record.marker,
                origin: wsRes.origin,
                endpoint: wsRes.pathAndQuery,
                persona: wsRes.personaHandle,
                exchangeId: saved.id,
                mediaType: 'websocket',
              })
            }
          }
          const ev = this.storage.addArtifact(curRun, job.assignment, 'ws',
            `WebSocket probe · ${wsRes.origin}${wsRes.pathAndQuery.slice(0, 60)}`,
            JSON.stringify({ exchangeId: saved.id, ...wsRes }, null, 2), undefined, currentSecrets())
          const stagedPath = await session.stage(`ws-${ev.id.slice(0, 8)}.json`,
            JSON.stringify({ exchangeId: saved.id, ...wsRes }, null, 2), signal).catch(() => null)
          return { exchangeId: saved.id, evidenceId: ev.id, stagedPath, ...wsRes }
        },

        derive_evidence: async ({ command, outputs, timeoutMs }, signal) => {
          const curRun = this.check(job)
          const res = await session.exec(command, outputs ?? ['result.txt'], signal, timeoutMs ?? 60_000)
          const ev = this.storage.addArtifact(curRun, job.assignment, 'analysis', 'Derived evidence',
            JSON.stringify({
              command: redact(command, secrets),
              exitStatus: res.exitCode,
              stdout: redact(res.stdout, secrets),
              stderr: redact(res.stderr, secrets),
              outputs: res.outputs,
            }, null, 2), undefined, secrets)
          return {
            evidenceId: ev.id,
            exitCode: res.exitCode,
            stdout: res.stdout,
            stderr: res.stderr,
            outputs: res.outputs,
          }
        },

        analyze_artifact: async (args, signal) => {
          this.check(job)
          const { tool, ...rest } = args
          return await session.analyze(tool, rest, signal)
        },

        query_cves: async (args, signal) => {
          this.check(job)
          const advisories = await queryCves(args, signal)
          return {
            count: advisories.length,
            advisories,
            note: 'Advisories are hypotheses only. Record a cve_hypothesis fact and verify reachability with a non-destructive Replay Spec before confirming.',
          }
        },

        load_skill: async ({ name }) => {
          if (name.trim().toLowerCase() === 'list') return { skills: listSkills() }
          const skill = loadSkill(name)
          if (!skill) return { error: `Unknown skill "${name}".`, available: listSkills().map(s => s.name) }
          return skill
        },

        mint_canary: async ({ purpose }) => {
          const curRun = this.check(job)
          const project = this.storage.project(curRun.projectId)
          if (this.isCanaryListenerConfigured() || (project.environment === 'local-lab' && isLocalLabEnvEnabled())) {
            await this.canaryBroker.startListener({ enableDns: this.isCanaryDnsConfigured() })
          }
          return this.canaryBroker.mintCanary(curRun.id, purpose, targetOrigins[0], {
            storage: this.storage,
            assignmentId: job.assignment.id,
          })
        },

        check_canary: async ({ token }) => {
          const curRun = this.check(job)
          const result = this.canaryBroker.checkCanary(token, { storage: this.storage, runId: curRun.id })
          if (result.hit) {
            const detail = (result.detail ?? {}) as { origin?: unknown; path?: unknown; pathAndQuery?: unknown; persona?: unknown }
            const origin = typeof detail.origin === 'string' && this.permitted(curRun, detail.origin)
              ? detail.origin
              : [...this.approvedOriginsSet(curRun)][0]
            const endpoint = typeof detail.pathAndQuery === 'string'
              ? detail.pathAndQuery
              : typeof detail.path === 'string' ? detail.path : undefined
            if (origin) {
              this.postCanaryLead(curRun, {
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
          const curRun = this.check(job)
          const cleanOrigin = this.parseOriginForRun(curRun, args.injectedOrigin)
          const project = this.storage.project(curRun.projectId)
          if (this.isCanaryListenerConfigured() || (project.environment === 'local-lab' && isLocalLabEnvEnabled())) {
            await this.canaryBroker.startListener({ enableDns: this.isCanaryDnsConfigured() })
          }
          // Route through the CanaryBroker so the marker is registered for OOB callback
          // correlation and for multi-surface second-order scanning.
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
          const curRun = this.check(job)
          return this.storage.listSecondOrderCanaries(curRun.id, status)
        },

        search_exchanges: async ({ query, origin, status, limit }) => {
          const curRun = this.check(job)
          const currentApproved = this.approvedOriginsSet(curRun)
          const rows = this.storage.searchExchanges(curRun.id, query, { approvedOrigins: currentApproved, origin, limit })
          return rows
            .filter(ex => status === undefined || ex.status === status)
            .map(ex => ({
              id: ex.id, origin: ex.origin, method: ex.method, pathAndQuery: ex.pathAndQuery,
              status: ex.status, mediaType: ex.mediaType, bodyPreview: ex.bodyPreview.slice(0, 600),
            }))
        },

        get_exchange: async ({ exchangeId, includeBody }, signal) => {
          const curRun = this.check(job)
          const currentApproved = this.approvedOriginsSet(curRun)
          const ex = this.storage.getExchange(curRun.id, exchangeId)
          if ([ex.origin, ex.finalOrigin, ...ex.redirectOrigins].some(o => !currentApproved.has(o))) {
            throw new BrokerDenied('Exchange touches an origin outside current approved scope.')
          }
          let stagedPath: string | null = null
          if (includeBody) {
            stagedPath = await session.stage(`exchanges/${ex.id}.json`, JSON.stringify(ex, null, 2), signal).catch(() => null)
          }
          return {
            ...ex,
            body: includeBody ? ex.body.slice(0, 12_000) : undefined,
            stagedPath,
          }
        },

        search_facts: async ({ query, origin, kind, limit }) => {
          const curRun = this.check(job)
          const currentApproved = this.approvedOriginsSet(curRun)
          return this.storage.listFacts(curRun.id, { includeTainted: false, query, origin, kind, limit })
            .filter(f => currentApproved.has(f.origin) && f.sourceOrigins.every(o => currentApproved.has(o)))
        },

        read_peer_trace: async ({ assignmentId, limit }) => {
          const curRun = this.check(job)
          const currentApproved = this.approvedOriginsSet(curRun)
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
          const curRun = this.check(job)
          const currentApproved = this.approvedOriginsSet(curRun)
          const expanded = this.compactor.expandDigest(this.storage, curRun.id, digestId)
          if (!expanded) return { error: 'Digest not found.' }
          return {
            digest: expanded.digest,
            facts: expanded.facts.filter(f => currentApproved.has(f.origin)),
          }
        },

        record_fact: async (args) => {
          const curRun = this.check(job)
          const currentApproved = this.approvedOriginsSet(curRun)
          const cleanOrigin = this.parseOriginForRun(curRun, args.origin)
          if (!currentApproved.has(cleanOrigin)) throw new BrokerDenied(`Origin ${cleanOrigin} is not approved.`)
          const fact = this.storage.addFact(curRun, job.assignment, {
            kind: args.kind,
            origin: cleanOrigin,
            summary: args.summary,
            data: args.data,
            exchangeIds: args.exchangeIds,
            evidenceIds: args.evidenceIds,
            sourceOrigins: args.sourceOrigins,
            secrets: currentSecrets(),
          })
          boardTools.noteEvidence()
          this.schedulePlanner(curRun.id)
          return { factId: fact.id, kind: args.kind, origin: fact.origin }
        },

        record_coverage: async (args) => {
          const curRun = this.check(job)
          const currentApproved = this.approvedOriginsSet(curRun)
          const cleanOrigin = this.parseOriginForRun(curRun, args.origin)
          if (!currentApproved.has(cleanOrigin)) throw new BrokerDenied(`Origin ${cleanOrigin} is not approved.`)
          const ext = args as typeof args & { enforcingControl?: string; proofGapReason?: string; linkedFindingId?: string }
          if (args.status === 'ruled_out' && !ext.enforcingControl?.trim()) {
            throw new Error('record_coverage with status "ruled_out" requires a non-empty enforcingControl (exact file:line or negative-control exchangeId proving the control runs on the attacker path).')
          }
          const entry = this.storage.upsertCoverageEntry(curRun, job.assignment.id, {
            origin: cleanOrigin,
            category: args.category,
            status: args.status,
            summary: args.summary,
            enforcingControl: ext.enforcingControl,
            proofGapReason: args.status === 'needs_follow_up' ? (ext.proofGapReason?.trim() || args.summary) : ext.proofGapReason,
            linkedFindingId: ext.linkedFindingId,
          })
          return { id: entry.id, origin: entry.origin, category: entry.category, status: entry.status }
        },

        propose_chain_finding: async (args) => {
          const { replaySpec, chainFactIds, exchangeIds } = args
          const ext = args as typeof args & {
            counterevidence?: string
            confidenceRationale?: string
            severityChangeConditions?: string
            codeLocations?: CodeLocation[]
          }
          const curRun = this.check(job)
          const currentApproved = this.approvedOriginsSet(curRun)
          const parsed = declarativeReplaySpecSchema.parse(replaySpec)
          const specOrigins = replaySpecOrigins(parsed)
          if (specOrigins.some(o => !currentApproved.has(o))) {
            throw new BrokerDenied('Replay spec references an origin outside current approved scope.')
          }
          const isStaticAst = parsed.kind === 'static_ast_proof'
          const asset = curRun.candidates.find(c => c.origin === parsed.origin && curRun.approved.includes(c.id))
            ?? (isStaticAst ? curRun.candidates.find(c => curRun.approved.includes(c.id)) : undefined)
          if (!asset) throw new BrokerDenied(`Primary finding origin ${parsed.origin} is not in approved scope.`)

          const validFactIds = chainFactIds.filter(fid =>
            this.storage.listFacts(curRun.id, { includeTainted: false, limit: 500 }).some(f => f.id === fid))
          const sourceOrigins = new Set<string>(
            isStaticAst
              ? [...specOrigins.filter(o => currentApproved.has(o))]
              : [...specOrigins, ...targetOrigins],
          )

          // Two-stage submission-time deduplication (§4.5B)
          const specDedupeFields = extractSpecDedupeFields(parsed)
          const existingRows = this.storage.db.select().from(findings).where(and(
            eq(findings.runId, curRun.id),
            eq(findings.goalRevision, curRun.goalRevision),
            eq(findings.findingKind, 'multi_step_chain'),
          )).all()
          const specMap = new Map(this.storage.listReplaySpecs(curRun.id).map(s => [s.id, s]))
          const existingRefs: ExistingFindingRef[] = existingRows.map(row => {
            const existingSpec = row.replaySpecId ? specMap.get(row.replaySpecId)?.spec : undefined
            const existingFields = existingSpec ? extractSpecDedupeFields(existingSpec) : undefined
            return {
              id: row.id,
              origin: row.finding.origin,
              title: row.finding.title,
              status: row.finding.status,
              cwe: row.finding.cwe,
              category: row.finding.category,
              severity: row.finding.severity,
              endpoint: existingFields?.endpoint ?? null,
              authState: existingFields?.authState ?? null,
              specKind: existingFields?.specKind ?? null,
              method: existingFields?.method ?? null,
              param: existingFields?.param ?? null,
              reason: row.finding.reason,
              impact: row.finding.impact,
              remediation: row.finding.remediation,
              sourceOrigins: row.sourceOrigins,
              fingerprintHash: row.fingerprintHash ?? row.finding.fingerprintHash ?? null,
            }
          })

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
          })
          const matchedCandidates = [matchedRow, dbDupRow].filter(
            (row, idx, arr): row is NonNullable<typeof row> =>
              Boolean(row) && arr.findIndex(other => other?.id === row!.id) === idx,
          )
          const verifiedMatch = matchedCandidates.find(
            r => r.finding.status === 'confirmed' || r.finding.status === 'static_verified',
          )

          // Preserve Zero-LLM invariant: if upgrading/merging into an already-confirmed finding, keep confirmed severity
          // until a new replay spec independently verifies higher impact.
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
              inlineVerifyFeedback: {
                verdict: 'inconclusive',
                controlPassed: false,
                assertionSummary: {
                  observed: 'retry_limit_exceeded',
                  expected: `<= ${maxAttempts} verification attempts`,
                  reason: `Inline verification retry limit reached for existing finding ${canonicalMatchedRow.id} (maxInlineVerifyRetries=${maxInlineVerifyRetries}).`,
                },
                stepStatuses: [],
                retriesRemaining: 0,
              } satisfies InlineVerifyFeedback,
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
          const finding: Finding = {
            id: findingId,
            origin: parsed.origin,
            title: parsed.title,
            status: 'pending',
            severity: parsed.severity,
            reason: parsed.severityRationale,
            remediation: parsed.remediation,
            impact: parsed.impact,
            recheck: parsed.recheckInstructions,
            category: parsed.category,
            cwe: parsed.cwe,
            confidence: 'medium',
            verification: `Pending Zero-LLM ${parsed.kind} replay verification (spec ${specRow.id}).`,
            findingKind: 'multi_step_chain',
            replaySpecId: specRow.id,
            fingerprintHash: dedupeDecision.fingerprintHash,
            counterevidence: ext.counterevidence ?? null,
            confidenceRationale: ext.confidenceRationale ?? null,
            severityChangeConditions: ext.severityChangeConditions ?? null,
            ...(isStaticAst ? { runtimeProofGap: parsed.runtimeProofGap } : {}),
            ...(codeLocations?.length ? { codeLocations } : {}),
            chainFactIds: validFactIds,
            exchangeIds: [...new Set(exchangeIds)],
            evidenceIds: [ev.id],
            scopeRevision: curRun.scopeRevision,
          }
          const savedFinding = this.storage.upsertChainFinding(curRun, asset.id, finding, specRow.id, [...sourceOrigins])
          for (const fid of validFactIds) {
            this.storage.addGraphEdge(curRun.id, { fromKind: 'fact', fromId: fid, toKind: 'finding', toId: savedFinding.id, edgeKind: 'proves' })
          }
          this.storage.addGraphEdge(curRun.id, { fromKind: 'assignment', fromId: job.assignment.id, toKind: 'finding', toId: savedFinding.id, edgeKind: 'proves' })
          this.schedulePlanner(curRun.id)

          if (verifyNow) {
            const inline = await this.executeInlineVerification({
              job,
              grant,
              currentSecrets,
              reposDir,
              spec: parsed,
              findingId: savedFinding.id,
              replaySpecId: specRow.id,
              onExchangeObserved: trackPersonaResources,
            })
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
          const curRun = this.check(job)
          const currentApproved = this.approvedOriginsSet(curRun)
          const existingRow = this.storage.db.select().from(findings).where(and(
            eq(findings.runId, curRun.id), eq(findings.id, args.findingId),
          )).get()
          if (!existingRow) throw new Error(`Finding ${args.findingId} not found in this run.`)

          const isAlreadyVerified = existingRow.finding.status === 'confirmed' || existingRow.finding.status === 'static_verified'
          let nextReplaySpecId = existingRow.replaySpecId ?? undefined
          let nextSourceOrigins = existingRow.sourceOrigins
          const extraEvidenceIds: string[] = []
          let parsedUpdatedSpec: DeclarativeReplaySpec | undefined
          let createdSpecRowId: string | undefined

          if (args.replaySpec) {
            const parsed = declarativeReplaySpecSchema.parse(args.replaySpec)
            const specOrigins = replaySpecOrigins(parsed)
            if (specOrigins.some(o => !currentApproved.has(o))) {
              throw new BrokerDenied('Updated replay spec references an origin outside current approved scope.')
            }
            parsedUpdatedSpec = parsed
            nextSourceOrigins = [...new Set([...existingRow.sourceOrigins, ...specOrigins])]
            const priorSpecs = this.storage.listReplaySpecsForFinding(curRun.id, existingRow.id)
            const priorMaxAttempts = priorSpecs.length ? Math.max(...priorSpecs.map(r => r.attemptCount)) : 0
            const maxAttempts = 1 + maxInlineVerifyRetries
            if (!isAlreadyVerified && priorMaxAttempts >= maxAttempts) {
              return {
                findingId: existingRow.id,
                replaySpecId: existingRow.replaySpecId,
                status: existingRow.finding.status,
                ...(existingRow.verificationTier ? { verificationTier: existingRow.verificationTier } : {}),
                severity: existingRow.finding.severity,
                inlineVerifyFeedback: {
                  verdict: 'inconclusive',
                  controlPassed: false,
                  assertionSummary: {
                    observed: 'retry_limit_exceeded',
                    expected: `<= ${maxAttempts} verification attempts`,
                    reason: `Inline verification retry limit reached (maxInlineVerifyRetries=${maxInlineVerifyRetries}).`,
                  },
                  stepStatuses: [],
                  retriesRemaining: 0,
                } satisfies InlineVerifyFeedback,
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
            // Only replace active replaySpecId & reset to pending if not already verified;
            // verified findings keep their verified status/severity unless explicitly re-verified.
            if (!isAlreadyVerified) {
              nextReplaySpecId = specRow.id
            }
          }

          const updated = this.storage.updateProposedFinding(curRun, existingRow.id, {
            replaySpecId: nextReplaySpecId,
            sourceOrigins: nextSourceOrigins,
            ...(args.counterevidence !== undefined ? { counterevidence: args.counterevidence } : {}),
            ...(args.confidenceRationale !== undefined ? { confidenceRationale: args.confidenceRationale } : {}),
            ...(args.severityChangeConditions !== undefined ? { severityChangeConditions: args.severityChangeConditions } : {}),
            ...(args.codeLocations !== undefined ? { codeLocations: args.codeLocations } : {}),
            finding: {
              ...(args.title ? { title: args.title } : {}),
              ...(args.summary ? { reason: args.summary } : {}),
              // Zero-LLM invariant: never escalate severity of an already-confirmed finding without Replay Verification
              ...(!isAlreadyVerified && args.severity ? { severity: args.severity } : {}),
              ...(!isAlreadyVerified && args.replaySpec ? { status: 'pending' as const } : {}),
              ...(extraEvidenceIds.length ? { evidenceIds: extraEvidenceIds } : {}),
            },
          })

          const shouldVerifyNow = Boolean(parsedUpdatedSpec && (args.verifyNow ?? true) && !isAlreadyVerified)
          if (shouldVerifyNow && parsedUpdatedSpec) {
            const inline = await this.executeInlineVerification({
              job,
              grant,
              currentSecrets,
              reposDir,
              spec: parsedUpdatedSpec,
              findingId: existingRow.id,
              replaySpecId: createdSpecRowId ?? nextReplaySpecId,
              onExchangeObserved: trackPersonaResources,
            })
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

        verify_replay_spec: async (args) => {
          const spec = args.spec ?? args.replaySpec
          if (!spec) throw new Error('verify_replay_spec requires spec or replaySpec.')
          const inline = await this.executeInlineVerification({
            job,
            grant,
            currentSecrets,
            reposDir,
            spec,
            findingId: args.findingId,
            replaySpecId: args.replaySpecId,
            onExchangeObserved: trackPersonaResources,
          })
          return {
            findingId: inline.findingId ?? args.findingId ?? null,
            replaySpecId: inline.replaySpecId,
            status: inline.status,
            ...(inline.verificationTier ? { verificationTier: inline.verificationTier } : {}),
            inlineVerifyFeedback: inline.feedback,
          }
        },

        suggest_candidate_host: async ({ origin, source, thirdParty }) => {
          const curRun = this.check(job)
          const clean = this.parseOriginForRun(curRun, origin)
          return this.storage.suggestCandidateHost(curRun, clean, source, Boolean(thirdParty))
        },

        complete_intent: async (completion) => ({ recorded: true, status: completion.status }),
      }

      const personasPub = [...grant.personas?.values() ?? []].map(p => ({
        handle: p.handle, roleLabel: p.roleLabel, originAllowlist: p.originAllowlist,
      }))

      const bolaTestQueue = run.capabilityTier >= 2 && personasPub.length >= 2
        ? buildBolaTestQueue(
            this.storage.listFacts(run.id, { includeTainted: false, limit: 200 }),
            personasPub,
            permittedAtAdmission,
            this.storage.listResourceSamples(run.id),
          )
        : []

      const specialistProfileId = step.specialistProfile ?? routeStepToSpecialist({
        title: step.title,
        hypothesis: step.hypothesis,
        category: step.category,
        skills: step.skills,
      })
      const specialistConfig = resolveSpecialistProfile(specialistProfileId)
      const scopedHandlers = filterHandlersForSpecialist(handlers, specialistConfig)

      const techTags = this.storage.listFacts(run.id, { includeTainted: false, kind: 'tech_fingerprint', limit: 30 })
        .flatMap(f => {
          const tags = f.data?.tags
          return Array.isArray(tags) ? tags.filter((t): t is string => typeof t === 'string') : []
        })
      const sinkKind = parentFacts
        .map(f => (typeof f.data?.sinkKind === 'string' ? f.data.sinkKind : ''))
        .find(Boolean)
      const preInjectedSkills = selectPreInjectionSkills({
        profileSkills: specialistConfig.skills,
        techTags: [...new Set(techTags)],
        ...(sinkKind ? { sinkKind } : {}),
        category: step.category,
        title: step.title,
        hypothesis: step.hypothesis,
        limit: 2,
      })

      const sessionResult = await runAgentSession({
        directory: this.storage.directory,
        sessionId: job.assignment.sessionId,
        requestId: `investigate:${step.id}:attempt-${job.assignment.attempt}`,
        profiles: resolveProfilePoolForRole(specialistConfig.roleAffinity, profiles),
        scenario: 'worker-investigation',
        roleAffinity: specialistConfig.roleAffinity,
        prompt: workerInvestigationPrompt({
          goal: run.goal,
          step: {
            id: step.id, title: step.title, hypothesis: step.hypothesis,
            category: step.category, skills: [...new Set([...step.skills, ...specialistConfig.skills])],
            specialistProfile: specialistProfileId,
          },
          origins: targetOrigins,
          capabilityTier: run.capabilityTier,
          maxTurns: job.assignment.maxTurns,
          personas: personasPub,
          ...(bolaTestQueue.length ? { bolaTestQueue } : {}),
          parentFacts: parentFacts.map(f => ({
            id: f.id, kind: f.kind, origin: f.origin, summary: f.summary, data: f.data,
          })),
          specsSummary: stagedSpecs,
          mountedRepos,
          preInjectedSkills,
        }),
        signal: job.controller.signal,
        maxTurns: job.assignment.maxTurns,
        compaction: true,
        enableSettlement: true,
        requireCompleteIntent: true,
        shouldSettle: () => (Date.now() - startedAt) >= intentLeaseMs * 0.85,
        handlers: scopedHandlers,
        secrets,
        beforeCall: () => {
          this.check(job)
          if (this.storage.checkBudgetExceeded(run.id)) {
            throw new BudgetExceededError('Run spend or request budget exceeded.')
          }
        },
        onUsage: usage => {
          this.storage.recordLlmSpend(run.id, {
            usd: usage.costUsd,
            tokens: usage.inputTokens + usage.outputTokens,
          })
          this.boardAssignmentTokens.set(
            job.assignment.id,
            (this.boardAssignmentTokens.get(job.assignment.id) ?? 0) + usage.inputTokens + usage.outputTokens,
          )
          this.boardHandleTokens.set(
            boardHandle,
            (this.boardHandleTokens.get(boardHandle) ?? 0) + usage.inputTokens + usage.outputTokens,
          )
        },
        onTurn: turn => {
          this.storage.updateWorker(job.assignment.id, { turnsUsed: turn })
          this.storage.recordLlmSpend(run.id, { turns: 1 })
        },
        onTurnStart: turn => {
          const member = this.storage.boardMember(run.id, boardHandle)
          const delta = this.boardTurnDelta(this.storage.run(run.id), boardHandle, member?.lastReadSeq ?? 0)
          if (!delta.text) return undefined
          return {
            messages: [turn === 1 ? injectBoardTurnInstructions('', delta.text) : delta.text],
          }
        },
        onProfileSuccess: id => recordProfileSuccess(id, this.storage),
        onProfileFailure: (id, err, hard) => recordProfileFailure(id, err, hard, this.storage),
      })

      const latestRun = this.check(job)
      const outcomeText = sessionResult.completion
        ? `[${sessionResult.completion.status}] ${sessionResult.completion.summary}`
        : sessionResult.answer
      this.storage.transaction(() => {
        this.completeWorker(job.assignment, latestRun, outcomeText, [], undefined, currentSecrets())
        this.storage.updateChainStep(step.id, { status: 'complete', assignedWorkerId: job.assignment.id })
      }, { behavior: 'immediate' })
    } finally {
      await session.close().catch(() => undefined)
    }
  }

  // --- Phase 3: Zero-LLM Verification (Replay Specs + Baseline Checks) ---

  private advanceToVerification(run: Run) {
    this.storage.transaction(() => {
      const current = this.storage.run(run.id)
      if (current.status !== 'running' || current.phase !== 'investigation') return
      const approvedOrigins = this.approvedOriginsSet(current)
      const openProofGaps = this.storage.listOpenProofGaps(current.id, current.goalRevision)
        .filter(g => approvedOrigins.has(g.origin))
      if (openProofGaps.length > 0) {
        this.storage.event(current.id, 'proof_gaps.surfaced',
          `${openProofGaps.length} open proof ${openProofGaps.length === 1 ? 'gap remains' : 'gaps remain'} after investigation and will be reported transparently.`, {
            count: openProofGaps.length,
            gaps: openProofGaps.map(g => ({
              origin: g.origin,
              category: g.category,
              proofGapReason: g.proofGapReason || g.summary,
            })),
          })
      }
      this.storage.updateRun(current.id, { phase: 'verification' })
      this.storage.event(current.id, 'verification.started', 'Investigation complete. Starting Zero-LLM Replay Verification.')
      this.storage.message(current.id, current.coordinatorId, 'guardian',
        `Investigation complete${openProofGaps.length ? ` (${openProofGaps.length} open proof ${openProofGaps.length === 1 ? 'gap' : 'gaps'} surfaced)` : ''}. Deterministic Zero-LLM verification is replaying every proposed finding and checking baselines.`)
    }, { behavior: 'immediate' })
  }

  private driveVerification(run: Run) {
    const approvedOrigins = this.approvedOriginsSet(run)
    const workers = this.storage.workerList(run.id)
    const maxConc = Math.max(1, Math.min(maxWorkerConcurrency, run.workerConcurrency || defaultWorkerConcurrency))

    // 1. Ensure verification workers exist for every pending replay spec in current goalRevision
    const pendingFindings = this.storage.db.select().from(findings).where(and(
      eq(findings.runId, run.id),
      eq(findings.goalRevision, run.goalRevision),
      eq(findings.findingKind, 'multi_step_chain'),
    )).all().filter(f =>
      f.finding.status === 'pending' &&
      f.replaySpecId &&
      run.approved.includes(f.assetId) &&
      f.sourceOrigins.every(o => approvedOrigins.has(o)),
    )

    const ownedRefineSpecIds = new Set<string>()
    for (const w of workers) {
      if (w.phase === 'verification' && w.stepId?.startsWith('refine:') &&
          w.status !== 'complete' && w.status !== 'canceled' && w.status !== 'failed') {
        ownedRefineSpecIds.add(w.stepId.slice('refine:'.length))
      }
    }
    for (const activeJob of this.active.values()) {
      if (activeJob.assignment.runId === run.id &&
          activeJob.assignment.phase === 'verification' &&
          activeJob.assignment.stepId?.startsWith('refine:')) {
        ownedRefineSpecIds.add(activeJob.assignment.stepId.slice('refine:'.length))
      }
    }
    const refinedFindingIds = new Set<string>()
    if (ownedRefineSpecIds.size > 0) {
      for (const s of this.storage.listReplaySpecs(run.id)) {
        if (ownedRefineSpecIds.has(s.id)) refinedFindingIds.add(s.findingId)
      }
    }

    // 1b. Bounded Phase-3 reasoning refinement for inline-failed findings with strong pre-signals.
    // This is what re-connects refinement after an inline `dismissed`/`inconclusive`: those rows are
    // never `pending`, so the normal verification queue would otherwise never look at them again.
    const eligibleRefineSpecIds = new Set<string>()
    const refinementBudget = this.refinementBudgetRemaining(run.id)
    if (refinementBudget > 0 && privateModelProfiles(this.storage).length > 0) {
      const specById = new Map(this.storage.listReplaySpecs(run.id).map(s => [s.id, s]))
      const rowsById = new Map(this.storage.db.select().from(findings).where(and(
        eq(findings.runId, run.id),
        eq(findings.goalRevision, run.goalRevision),
      )).all().map(r => [r.id, r]))
      let dispatched = 0
      for (const specId of [...(this.refinementEligible.get(run.id) ?? [])]) {
        if (dispatched >= refinementBudget) break
        if (ownedRefineSpecIds.has(specId)) continue
        const specRow = specById.get(specId)
        if (!specRow) continue
        const row = rowsById.get(specRow.findingId)
        if (!row) continue
        const status = row.finding.status
        if (status === 'confirmed' || status === 'static_verified') continue
        if (status !== 'pending' && status !== 'inconclusive' && status !== 'dismissed') continue
        if (!row.sourceOrigins.every(o => approvedOrigins.has(o))) continue
        if (!specRow.sourceOrigins.every(o => approvedOrigins.has(o))) continue
        const asset = run.candidates.find(c => c.id === row.assetId)
        this.storage.makeWorker(
          run,
          'verification',
          asset,
          `Refine replay · ${specRow.spec.title.slice(0, 75)}`,
          `Bounded 8-turn Phase-3 refinement for inline-failed ${specRow.spec.kind} spec ${specId} with a strong pre-verification signal.`,
          {
            stepId: `refine:${specId}`,
            sourceOrigins: specRow.sourceOrigins,
            maxTurns: 8,
          },
        )
        eligibleRefineSpecIds.add(specId)
        refinedFindingIds.add(specRow.findingId)
        dispatched += 1
      }
    }
    if (eligibleRefineSpecIds.size > 0) {
      this.storage.event(
        run.id,
        'refinement.dispatched',
        `Dispatched ${eligibleRefineSpecIds.size} bounded Phase-3 refinement job(s) for inline-failed specs.`,
        { specIds: [...eligibleRefineSpecIds], cap: maxPhase3RefinementJobs },
      )
    }

    for (const row of pendingFindings) {
      if (refinedFindingIds.has(row.id)) continue
      const existing = workers.find(w => w.phase === 'verification' && w.stepId === row.replaySpecId && w.status !== 'canceled')
      if (!existing) {
        const asset = run.candidates.find(c => c.id === row.assetId)
        this.storage.makeWorker(run, 'verification', asset,
          `Replay verify · ${row.finding.title.slice(0, 80)}`,
          `Zero-LLM deterministic replay verification of spec ${row.replaySpecId}.`, {
            stepId: row.replaySpecId,
            sourceOrigins: row.sourceOrigins,
          })
      }
    }

    // 2. Ensure baseline verification workers exist for every approved asset
    for (const asset of run.candidates.filter(c => run.approved.includes(c.id))) {
      const existing = workers.find(w =>
        w.phase === 'verification' && w.assetId === asset.id && w.stepId === null &&
        w.goalRevision === run.goalRevision && w.status !== 'canceled')
      if (!existing) {
        const { analysis } = assessmentAssignments(workers, asset.id, run.goalRevision)
        this.storage.makeWorker(run, 'verification', asset,
          `Baseline verify · ${new URL(asset.origin).hostname}`,
          'Verify recorded baseline response and access policy evidence inside an air-gapped container.', {
            input: analysis?.status === 'complete' ? analysis : undefined,
            sourceOrigins: [asset.origin],
          })
      }
    }

    const updatedWorkers = this.storage.workerList(run.id).filter(w =>
      w.phase === 'verification' && w.goalRevision === run.goalRevision &&
      w.sourceOrigins.every(o => approvedOrigins.has(o)))
    const queued = updatedWorkers.filter(w => w.status === 'queued')
    const activeCount = [...this.active.values()].filter(j => j.assignment.runId === run.id).length

    if (!queued.length && updatedWorkers.every(w => w.status === 'complete' || w.status === 'canceled')) {
      this.storage.transaction(() => {
        const current = this.storage.run(run.id)
        if (current.status !== 'running' || current.phase !== 'verification') return
        const complete = this.storage.updateRun(current.id, { phase: 'complete', status: 'complete' })
        this.storage.writeReport(complete, false)
        this.storage.message(current.id, current.coordinatorId, 'guardian', 'Verification finished. The complete report is ready.')
      }, { behavior: 'immediate' })
      return
    }

    let slots = Math.max(0, maxConc - activeCount)
    for (const worker of queued) {
      if (slots <= 0) break
      if (this.active.has(worker.id)) continue
      this.startVerificationWorker(run, worker)
      slots -= 1
    }
  }

  private startVerificationWorker(run: Run, worker: Assignment) {
    const claimed = this.storage.transaction(() => {
      const w = this.storage.updateWorker(worker.id, {
        status: 'running', lease: randomUUID(), leaseExpiresAt: Date.now() + 10 * 60_000, outcome: null,
      })
      this.storage.event(run.id, 'worker.started', worker.title + ' started.', { assignmentId: worker.id })
      return w
    })
    if (!claimed) return

    const job: Active = { assignment: claimed, origins: new Set(claimed.sourceOrigins), controller: new AbortController() }
    this.active.set(claimed.id, job)

    const work = claimed.stepId
      ? (claimed.stepId.startsWith('refine:')
          ? this.runPhase3RefinementJob(job, claimed.stepId.slice('refine:'.length))
          : this.verifyReplaySpecJob(job, claimed.stepId))
      : this.verifyBaselineJob(job)

    void work.catch(error => {
      if (!this.authorize(job) || job.controller.signal.aborted) return
      const msg = redact(error instanceof Error ? error.message : String(error)).slice(0, 400)
      this.storage.transaction(() => {
        this.storage.updateWorker(claimed.id, { status: 'failed', outcome: msg, lease: null, leaseExpiresAt: null })
        this.storage.event(run.id, 'worker.failed', `Verification failed: ${msg}`, { assignmentId: claimed.id })
      })
    }).finally(() => {
      this.active.delete(claimed.id)
      this.scheduleWake()
    })
  }

  private async verifyReplaySpecJob(job: Active, replaySpecId: string) {
    const run = this.check(job)
    const specRow = this.storage.getReplaySpec(run.id, replaySpecId)
    const findingRow = this.storage.db.select().from(findings).where(and(
      eq(findings.runId, run.id), eq(findings.id, specRow.findingId),
    )).get()
    if (!findingRow) {
      this.completeWorker(job.assignment, run, 'Finding no longer exists.', [])
      return
    }

    const permittedAtAdmission = this.approvedOriginsSet(run)
    const { grant, secrets, currentSecrets } = this.buildGrant(job, run, permittedAtAdmission)
    const { reposDir } = this.projectReposMount(run.projectId)

    // Priority #5 / v3 Dual HTTP+DNS CanaryBroker: ensure listener is started when needed or configured
    if ((specRow.spec.kind === 'rce_proof' && specRow.spec.proofMode === 'oob_canary') || this.isCanaryListenerConfigured()) {
      await this.canaryBroker.startListener({ enableDns: this.isCanaryDnsConfigured() }).catch(() => undefined)
    }

    // Tier 3 HITL gate for rce_proof and upload_probe specs on non-local-lab targets
    if (specRow.spec.kind === 'rce_proof' || specRow.spec.kind === 'upload_probe') {
      const gateReq = specRow.spec.kind === 'rce_proof'
        ? {
            origin: specRow.spec.probeStep.request.origin,
            method: specRow.spec.probeStep.request.method,
            pathAndQuery: specRow.spec.probeStep.request.pathAndQuery,
            personaHandle: specRow.spec.probeStep.request.persona ?? null,
            rationale: `[rce_proof:${specRow.spec.proofMode}] Zero-LLM non-destructive PoE verification for "${specRow.spec.title}"`,
            requestPreview: JSON.stringify({
              proofMode: specRow.spec.proofMode,
              controlStep: specRow.spec.controlStep,
              probeStep: specRow.spec.probeStep,
            }, null, 2),
          }
        : {
            origin: specRow.spec.uploadStep.origin,
            method: specRow.spec.uploadStep.method,
            pathAndQuery: specRow.spec.uploadStep.pathAndQuery,
            personaHandle: specRow.spec.uploadStep.persona ?? null,
            rationale: `[upload_probe] Zero-LLM benign multipart upload verification for "${specRow.spec.title}"`,
            requestPreview: JSON.stringify({
              filename: specRow.spec.uploadStep.filename,
              contentType: specRow.spec.uploadStep.contentType,
              uploadStep: specRow.spec.uploadStep.pathAndQuery,
              fetchStep: specRow.spec.fetchStep.request.pathAndQuery,
            }, null, 2),
          }
      const approval = await this.waitForTier3Approval(job, {
        ...gateReq,
        bodyPreview: specRow.spec.kind === 'rce_proof'
          ? (specRow.spec.probeStep.request.textBody ??
              (specRow.spec.probeStep.request.jsonBody !== undefined
                ? JSON.stringify(specRow.spec.probeStep.request.jsonBody)
                : undefined))
          : specRow.spec.uploadStep.contentTemplate,
        hasMultipart: specRow.spec.kind === 'upload_probe',
        isRceProof: specRow.spec.kind === 'rce_proof',
        secrets,
      }, job.controller.signal)
      if (!approval.approved) {
        const current = this.check(job)
        const updatedFinding: Finding = {
          ...findingRow.finding,
          status: 'inconclusive',
          reason: approval.deniedReason
            ? `Tier 3 Safety Judge denied ${specRow.spec.kind} verification: ${approval.deniedReason}`
            : `Tier 3 approval for ${specRow.spec.kind} verification was denied or expired.`,
          confidence: 'low',
        }
        this.storage.upsertChainFinding(current, findingRow.assetId, updatedFinding, specRow.id, specRow.sourceOrigins)
        this.completeWorker(job.assignment, current, 'Inconclusive: Tier 3 approval denied.', [], undefined, secrets)
        return
      }
    }

    const verifyParams = {
      spec: specRow.spec,
      broker: this.broker,
      browser: this.browser,
      canaryBroker: this.canaryBroker,
      backend: this.backend,
      reposDir,
      grant,
      signal: job.controller.signal,
      storage: this.storage,
      runId: run.id,
      assignmentId: job.assignment.id,
      onExchange: (ex: BrokerExchangeResult) => {
        const saved = this.storage.recordExchange({
          runId: run.id,
          assignmentId: job.assignment.id,
          scopeRevision: run.scopeRevision,
          origin: ex.origin,
          finalOrigin: ex.finalOrigin,
          redirectOrigins: ex.redirectOrigins,
          method: ex.method,
          pathAndQuery: ex.pathAndQuery,
          personaHandle: ex.personaHandle,
          status: ex.status,
          mediaType: ex.mediaType,
          reqHeaders: ex.reqHeaders,
          respHeaders: ex.respHeaders,
          body: ex.body,
          durationMs: ex.durationMs,
          secretMatches: ex.secretMatches,
          secrets: currentSecrets(),
        })
        this.storage.trackExchangeResources({
          runId: run.id,
          scopeRevision: run.scopeRevision,
          exchange: ex,
          source: 'surface_probe',
        })
        this.markEndpointCoverage(run, ex.origin, ex.method, ex.pathAndQuery, `replay:${specRow.spec.kind}`)
        return saved.id
      },
    }
    const result = await verifyReplaySpec(verifyParams)
    this.markReplaySpecCoverage(run, specRow.spec, `replay:${specRow.spec.kind}`)

    const current = this.check(job)
    let phaseFeedback: InlineVerifyFeedback | undefined
    this.storage.transaction(() => {
      // Strict Tier Separation (Invariant #4): static_ast_proof NEVER promotes to 'confirmed' / 'runtime_confirmed'
      const staticSpec = specRow.spec.kind === 'static_ast_proof' ? specRow.spec : null
      const isStaticAst = staticSpec !== null
      const rawVerdict = result.verdict as Finding['status']
      const finalStatus: Finding['status'] = isStaticAst
        ? (rawVerdict === 'confirmed' || rawVerdict === 'static_verified' ? 'static_verified' : rawVerdict)
        : rawVerdict
      const verificationTier: VerificationTier | undefined = finalStatus === 'static_verified'
        ? 'static_verified'
        : finalStatus === 'confirmed'
          ? 'runtime_confirmed'
          : undefined

      const receipt = this.storage.addArtifact(current, job.assignment, 'replay',
        `${isStaticAst ? 'Deterministic Static AST' : 'Zero-LLM replay'} · ${specRow.spec.title}`,
        JSON.stringify({
          replaySpecId: specRow.id,
          specSha256: specRow.specSha256,
          kind: specRow.spec.kind,
          origin: specRow.spec.origin,
          verdict: finalStatus,
          verificationTier: verificationTier ?? null,
          outcome: result.outcome,
          exchangeIds: result.exchangeIds,
          sourceOrigins: specRow.sourceOrigins,
          evidenceSha256: result.evidenceSha256,
          evidencePayload: result.evidencePayload,
        }, null, 2), 'replay:' + specRow.id, currentSecrets())

      const staticCodeLocations: CodeLocation[] | undefined = staticSpec
        ? [{
            repo: staticSpec.repo,
            file: staticSpec.file,
            startLine: staticSpec.startLine,
            endLine: staticSpec.endLine,
            label: staticSpec.sourceToSinkTrace?.slice(0, 180),
          }]
        : findingRow.finding.codeLocations

      const secretsList = currentSecrets()
      const cleanReason = redact(result.outcome.reason || result.outcome.observed || findingRow.finding.reason, secretsList)
      const cleanObserved = redact(result.outcome.observed, secretsList)
      const updatedFinding: Finding = {
        ...findingRow.finding,
        status: finalStatus,
        verificationTier,
        reason: cleanReason,
        confidence: (finalStatus === 'confirmed' || finalStatus === 'static_verified')
          ? 'high'
          : finalStatus === 'dismissed'
            ? 'medium'
            : 'low',
        verification: `${isStaticAst ? 'Deterministic offline static_ast_proof' : `Zero-LLM ${specRow.spec.kind} replay`} verdict: ${finalStatus} (controlPassed=${result.outcome.controlPassed}, observed: ${cleanObserved}).`,
        ...(staticSpec ? { runtimeProofGap: staticSpec.runtimeProofGap } : {}),
        ...(staticCodeLocations?.length ? { codeLocations: staticCodeLocations } : {}),
        evidenceIds: [...new Set([...findingRow.finding.evidenceIds, receipt.id])],
        exchangeIds: [...new Set([...(findingRow.finding.exchangeIds ?? []), ...result.exchangeIds])],
        scopeRevision: current.scopeRevision,
      }
      if (finalStatus === 'confirmed' || finalStatus === 'static_verified') {
        this.storage.upsertChainFinding(current, findingRow.assetId, updatedFinding, specRow.id, specRow.sourceOrigins)
        if (owaspCategories.includes(specRow.spec.category as OwaspCategory) &&
            this.permitted(current, specRow.spec.origin)) {
          this.storage.upsertCoverageEntry(current, job.assignment.id, {
            origin: specRow.spec.origin,
            category: specRow.spec.category as OwaspCategory,
            status: 'reported',
            summary: `${finalStatus === 'static_verified' ? 'Static verified' : 'Confirmed'}: ${specRow.spec.title}`,
            linkedFindingId: findingRow.id,
          })
        }
        const refreshedRow = this.storage.db.select().from(findings).where(and(
          eq(findings.runId, current.id), eq(findings.id, findingRow.id),
        )).get()
        if (refreshedRow) this.scheduleVariantSweepForFinding(current, refreshedRow)
      } else {
        const rawFeedback = buildInlineVerifyFeedback(
          specRow.spec,
          result,
          Math.max(1, specRow.attemptCount),
          maxInlineVerifyRetries,
          currentSecrets(),
        )
        phaseFeedback = rawFeedback
        this.storage.db.update(replaySpecs).set({
          lastVerificationDiff: rawFeedback,
        }).where(eq(replaySpecs.id, specRow.id)).run()
        this.storage.updateProposedFinding(current, findingRow.id, {
          verificationTier: null,
          finding: updatedFinding,
        })

        const refineStepId = `refine:${specRow.id}`
        const alreadyQueuedRefine = this.storage.workerList(current.id).some(w =>
          w.phase === 'verification' && w.stepId === refineStepId,
        )
        const strongPreSignal = this.hasStrongPreVerificationSignal(current, findingRow, specRow, rawFeedback)
        if (strongPreSignal) this.markRefinementEligible(current.id, specRow.id)
        // Legacy Phase-3 refinement stays available for any spec that failed deterministic replay;
        // the strong-signal eligibility set only widens dispatch to inline-failed findings that are
        // never `pending` again. Both paths share the hard <=10 jobs/run cap.
        const canRefine =
          current.capabilityTier > 0 &&
          !this.storage.checkBudgetExceeded(current.id) &&
          privateModelProfiles(this.storage).length > 0 &&
          !alreadyQueuedRefine &&
          this.refinementBudgetRemaining(current.id) > 0 &&
          specRow.sourceOrigins.every(o => permittedAtAdmission.has(o))
        if (canRefine) {
          const asset = current.candidates.find(c => c.id === findingRow.assetId)
          this.storage.makeWorker(
            current,
            'verification',
            asset,
            `Refine replay · ${specRow.spec.title.slice(0, 75)}`,
            `Bounded 8-turn Phase-3 refinement for failed ${specRow.spec.kind} spec ${specRow.id}.`,
            {
              stepId: refineStepId,
              input: job.assignment,
              maxTurns: 8,
              sourceOrigins: specRow.sourceOrigins,
            },
          )
        }
      }
      this.completeWorker(
        job.assignment,
        current,
        `Replay verdict: ${finalStatus} (${cleanObserved.slice(0, 160)})`,
        [receipt.id],
        undefined,
        secretsList,
      )
    }, { behavior: 'immediate' })
    const refreshed = this.storage.db.select().from(findings).where(and(
      eq(findings.runId, current.id), eq(findings.id, findingRow.id),
    )).get()
    if (refreshed) {
      this.postVerificationVerdict(current, {
        replaySpecId: specRow.id,
        findingId: refreshed.id,
        title: specRow.spec.title,
        status: refreshed.finding.status,
        verificationTier: refreshed.verificationTier ?? refreshed.finding.verificationTier ?? null,
        feedback: phaseFeedback ?? specRow.lastVerificationDiff ?? null,
        assignmentId: specRow.assignmentId,
        attempt: specRow.attemptCount,
      })
    }
  }

  private async executeInlineVerification(params: {
    job: Active
    grant: Grant
    currentSecrets: () => readonly NamedSecret[]
    reposDir?: string
    spec: DeclarativeReplaySpec
    findingId?: string
    replaySpecId?: string
    phase3RefinementAttempt?: number
    onExchangeObserved?: (curRun: Run, ex: BrokerExchangeResult, exchangeId: string) => void
  }): Promise<{
    findingId?: string
    replaySpecId: string
    attemptCount: number
    status: Finding['status']
    verificationTier?: VerificationTier
    feedback: InlineVerifyFeedback
    artifactId?: string
  }> {
    const curRun = this.check(params.job)
    if (this.storage.checkBudgetExceeded(curRun.id)) {
      throw new BudgetExceededError('Run spend or request budget exceeded.')
    }
    const parsed = declarativeReplaySpecSchema.parse(params.spec)
    const specOrigins = replaySpecOrigins(parsed)
    const currentApproved = this.approvedOriginsSet(curRun)
    if (specOrigins.some(o => !currentApproved.has(o))) {
      throw new BrokerDenied('Replay spec references an origin outside current approved scope.')
    }

    const findingRow = params.findingId
      ? this.storage.db.select().from(findings).where(and(
          eq(findings.runId, curRun.id), eq(findings.id, params.findingId),
        )).get()
      : undefined
    const isAlreadyVerified = Boolean(
      findingRow && (findingRow.finding.status === 'confirmed' || findingRow.finding.status === 'static_verified'),
    )

    const standaloneKey = !params.findingId
      ? 'inline:' + params.job.assignment.id + ':' + createHash('sha256')
          .update(`${parsed.kind}|${parsed.origin}|${parsed.cwe}|${parsed.title.trim().toLowerCase()}`)
          .digest('hex').slice(0, 16)
      : undefined
    const trackingFindingId = findingRow?.id ?? params.findingId ?? standaloneKey!

    let specRow: ReplaySpecRow | undefined
    if (params.replaySpecId) {
      specRow = this.storage.getReplaySpec(curRun.id, params.replaySpecId)
    }
    const existingForFinding = this.storage.listReplaySpecsForFinding(curRun.id, trackingFindingId)
    if (!specRow) {
      specRow = existingForFinding[0]
    }
    if (!specRow) {
      specRow = this.storage.createReplaySpec(
        curRun,
        params.job.assignment,
        trackingFindingId,
        parsed,
        specOrigins.length ? specOrigins : [parsed.origin],
        { initialAttemptCount: 0 },
      )
    }

    const currentAttempts = Math.max(
      specRow.attemptCount,
      ...existingForFinding.map(r => r.attemptCount),
      0,
    )
    const nextAttempt = params.phase3RefinementAttempt ?? (currentAttempts + 1)
    const maxAttempts = 1 + maxInlineVerifyRetries

    if (nextAttempt <= maxAttempts) {
      if ((parsed.kind === 'rce_proof' && parsed.proofMode === 'oob_canary') || this.isCanaryListenerConfigured()) {
        await this.canaryBroker.startListener({ enableDns: this.isCanaryDnsConfigured() }).catch(() => undefined)
      }
      if (parsed.kind === 'rce_proof' || parsed.kind === 'upload_probe') {
        const gateReq = parsed.kind === 'rce_proof'
          ? {
              origin: parsed.probeStep.request.origin,
              method: parsed.probeStep.request.method,
              pathAndQuery: parsed.probeStep.request.pathAndQuery,
              personaHandle: parsed.probeStep.request.persona ?? null,
              rationale: `[rce_proof:${parsed.proofMode}] Inline Zero-LLM verification for "${parsed.title}"`,
              requestPreview: JSON.stringify({
                proofMode: parsed.proofMode,
                controlStep: parsed.controlStep,
                probeStep: parsed.probeStep,
              }, null, 2),
              bodyPreview: parsed.probeStep.request.textBody ??
                (parsed.probeStep.request.jsonBody !== undefined
                  ? JSON.stringify(parsed.probeStep.request.jsonBody)
                  : undefined),
              hasMultipart: false,
              isRceProof: true,
            }
          : {
              origin: parsed.uploadStep.origin,
              method: parsed.uploadStep.method,
              pathAndQuery: parsed.uploadStep.pathAndQuery,
              personaHandle: parsed.uploadStep.persona ?? null,
              rationale: `[upload_probe] Inline Zero-LLM verification for "${parsed.title}"`,
              requestPreview: JSON.stringify({
                filename: parsed.uploadStep.filename,
                contentType: parsed.uploadStep.contentType,
                uploadStep: parsed.uploadStep.pathAndQuery,
                fetchStep: parsed.fetchStep.request.pathAndQuery,
              }, null, 2),
              bodyPreview: parsed.uploadStep.contentTemplate,
              hasMultipart: true,
              isRceProof: false,
            }
        const approval = await this.waitForTier3Approval(params.job, {
          ...gateReq,
          secrets: params.currentSecrets(),
        }, params.job.controller.signal)
        if (!approval.approved) {
          const deniedReason = approval.deniedReason
            ? `Tier 3 Safety Judge denied ${parsed.kind} verification: ${approval.deniedReason}`
            : `Tier 3 approval for ${parsed.kind} verification was denied or expired.`
          const deniedFeedback = redactJsonValue({
            verdict: 'inconclusive',
            controlPassed: false,
            assertionSummary: {
              observed: 'tier3_approval_denied',
              expected: 'Tier 3 approval granted',
              reason: deniedReason,
            },
            stepStatuses: [],
            retriesRemaining: Math.max(0, maxAttempts - nextAttempt),
          } satisfies InlineVerifyFeedback, params.currentSecrets())
          const updatedSpec = this.storage.incrementReplaySpecAttempt(specRow.id, deniedFeedback, {
            spec: parsed,
            sourceOrigins: [...new Set([...specRow.sourceOrigins, ...specOrigins])],
            secrets: params.currentSecrets(),
          })
          if (findingRow && !isAlreadyVerified) {
            const latestRun = this.check(params.job)
            this.storage.updateProposedFinding(latestRun, findingRow.id, {
              replaySpecId: updatedSpec.id,
              verificationTier: null,
              finding: { status: 'inconclusive', verificationTier: undefined, reason: deniedReason, confidence: 'low' },
            })
          }
          return {
            findingId: findingRow?.id,
            replaySpecId: updatedSpec.id,
            attemptCount: updatedSpec.attemptCount,
            status: findingRow && isAlreadyVerified ? findingRow.finding.status : 'inconclusive',
            feedback: deniedFeedback,
          }
        }
      }
    }

    const { feedback, replay } = await verifyReplaySpecInline({
      spec: parsed,
      broker: this.broker,
      browser: this.browser,
      canaryBroker: this.canaryBroker,
      backend: this.backend,
      reposDir: params.reposDir,
      grant: params.grant,
      signal: params.job.controller.signal,
      storage: this.storage,
      runId: curRun.id,
      assignmentId: params.job.assignment.id,
      findingId: findingRow?.id,
      attemptCount: nextAttempt,
      maxRetries: maxInlineVerifyRetries,
      secrets: params.currentSecrets(),
      onExchange: ex => {
        const latest = this.check(params.job)
        const saved = this.storage.recordExchange({
          runId: latest.id,
          assignmentId: params.job.assignment.id,
          scopeRevision: latest.scopeRevision,
          origin: ex.origin,
          finalOrigin: ex.finalOrigin,
          redirectOrigins: ex.redirectOrigins,
          method: ex.method,
          pathAndQuery: ex.pathAndQuery,
          personaHandle: ex.personaHandle,
          status: ex.status,
          mediaType: ex.mediaType,
          reqHeaders: ex.reqHeaders,
          respHeaders: ex.respHeaders,
          body: ex.body,
          durationMs: ex.durationMs,
          secretMatches: ex.secretMatches,
          secrets: params.currentSecrets(),
        })
        this.storage.trackExchangeResources({
          runId: latest.id,
          scopeRevision: latest.scopeRevision,
          exchange: ex,
          source: 'surface_probe',
        })
        this.markEndpointCoverage(latest, ex.origin, ex.method, ex.pathAndQuery, `replay:${parsed.kind}`)
        params.onExchangeObserved?.(latest, ex, saved.id)
        return saved.id
      },
    })
    const latestForCoverage = this.check(params.job)
    this.markReplaySpecCoverage(latestForCoverage, parsed, `replay:${parsed.kind}`)

    if (nextAttempt > maxAttempts) {
      return {
        findingId: findingRow?.id,
        replaySpecId: specRow.id,
        attemptCount: currentAttempts,
        status: findingRow?.finding.status ?? 'inconclusive',
        verificationTier: findingRow?.verificationTier ?? undefined,
        feedback,
      }
    }

    const isStaticAst = parsed.kind === 'static_ast_proof'
    const rawVerdict = replay.verdict as Finding['status']
    const finalStatus: Finding['status'] = isStaticAst
      ? (rawVerdict === 'confirmed' || rawVerdict === 'static_verified' ? 'static_verified' : rawVerdict)
      : rawVerdict
    const verificationTier: VerificationTier | undefined = finalStatus === 'static_verified'
      ? 'static_verified'
      : finalStatus === 'confirmed'
        ? 'runtime_confirmed'
        : undefined
    const normalizedFeedback: InlineVerifyFeedback = {
      ...feedback,
      verdict: finalStatus as InlineVerifyFeedback['verdict'],
      ...(verificationTier ? { verificationTier } : {}),
    }

    const latestRun = this.check(params.job)
    const updatedSpec = this.storage.incrementReplaySpecAttempt(specRow.id, normalizedFeedback, {
      spec: parsed,
      sourceOrigins: [...new Set([...specRow.sourceOrigins, ...specOrigins])],
      secrets: params.currentSecrets(),
    })

    const receipt = this.storage.addArtifact(
      latestRun,
      params.job.assignment,
      'replay',
      `Inline ${isStaticAst ? 'Static AST' : 'Zero-LLM replay'} attempt #${updatedSpec.attemptCount} · ${parsed.title}`,
      JSON.stringify({
        replaySpecId: updatedSpec.id,
        attemptCount: updatedSpec.attemptCount,
        specSha256: updatedSpec.specSha256,
        kind: parsed.kind,
        origin: parsed.origin,
        verdict: finalStatus,
        verificationTier: verificationTier ?? null,
        outcome: replay.outcome,
        feedback: normalizedFeedback,
        exchangeIds: replay.exchangeIds,
        evidenceSha256: replay.evidenceSha256,
        evidencePayload: replay.evidencePayload,
      }, null, 2),
      undefined,
      params.currentSecrets(),
    )

    if (findingRow && !isAlreadyVerified) {
      const staticCodeLocations: CodeLocation[] | undefined = parsed.kind === 'static_ast_proof'
        ? [{
            repo: parsed.repo,
            file: parsed.file,
            startLine: parsed.startLine,
            endLine: parsed.endLine,
            label: parsed.sourceToSinkTrace?.slice(0, 180),
          }]
        : findingRow.finding.codeLocations
      const mergedOrigins = [...new Set([...findingRow.sourceOrigins, ...specOrigins])]
      const secretsList = params.currentSecrets()
      const cleanReason = redact(replay.outcome.reason || replay.outcome.observed || findingRow.finding.reason, secretsList)
      const cleanObserved = redact(replay.outcome.observed, secretsList)
      const nextFindingPatch: Partial<Finding> = {
        status: finalStatus,
        verificationTier,
        reason: cleanReason,
        confidence: (finalStatus === 'confirmed' || finalStatus === 'static_verified')
          ? 'high'
          : finalStatus === 'dismissed'
            ? 'medium'
            : 'low',
        verification: `${isStaticAst ? 'Deterministic offline static_ast_proof' : `Zero-LLM ${parsed.kind} inline replay`} verdict: ${finalStatus} (controlPassed=${replay.outcome.controlPassed}, observed: ${cleanObserved}).`,
        ...(parsed.kind === 'static_ast_proof' ? { runtimeProofGap: parsed.runtimeProofGap } : {}),
        ...(staticCodeLocations?.length ? { codeLocations: staticCodeLocations } : {}),
        evidenceIds: [receipt.id],
        exchangeIds: replay.exchangeIds,
      }
      if (finalStatus === 'confirmed' || finalStatus === 'static_verified') {
        this.storage.upsertChainFinding(
          latestRun,
          findingRow.assetId,
          { ...findingRow.finding, ...nextFindingPatch, replaySpecId: updatedSpec.id, scopeRevision: latestRun.scopeRevision },
          updatedSpec.id,
          mergedOrigins,
        )
        if (owaspCategories.includes(parsed.category as OwaspCategory) && this.permitted(latestRun, parsed.origin)) {
          this.storage.upsertCoverageEntry(latestRun, params.job.assignment.id, {
            origin: parsed.origin,
            category: parsed.category as OwaspCategory,
            status: 'reported',
            summary: `${finalStatus === 'static_verified' ? 'Static verified' : 'Confirmed'}: ${parsed.title}`,
            linkedFindingId: findingRow.id,
          })
        }
        // Multi-Trial Early Stopping: cancel sibling trials immediately on first Zero-LLM confirmation
        this.cancelSiblingTrialsOnConfirmation(latestRun, params.job.assignment.stepId, findingRow.id)
        const refreshedRow = this.storage.db.select().from(findings).where(and(
          eq(findings.runId, latestRun.id), eq(findings.id, findingRow.id),
        )).get()
        if (refreshedRow) this.scheduleVariantSweepForFinding(latestRun, refreshedRow)
      } else {
        if (this.hasStrongPreVerificationSignal(latestRun, findingRow, updatedSpec, normalizedFeedback)) {
          // Phase-2 inline failure with a strong pre-verification signal: eligible for one bounded
          // Phase-3 reasoning refinement (dispatched by driveVerification, <=10 per run).
          this.markRefinementEligible(latestRun.id, updatedSpec.id)
        }
        this.storage.updateProposedFinding(latestRun, findingRow.id, {
          replaySpecId: updatedSpec.id,
          sourceOrigins: mergedOrigins,
          verificationTier: null,
          finding: nextFindingPatch,
        })
      }
    }

    const verdictStatus = findingRow && isAlreadyVerified ? findingRow.finding.status : finalStatus
    const verdictTier = findingRow && isAlreadyVerified ? (findingRow.verificationTier ?? undefined) : verificationTier
    this.postVerificationVerdict(this.storage.run(params.job.assignment.runId), {
      replaySpecId: updatedSpec.id,
      findingId: findingRow?.id ?? params.findingId ?? null,
      title: parsed.title,
      status: verdictStatus,
      verificationTier: verdictTier,
      feedback: normalizedFeedback,
      assignmentId: specRow.assignmentId ?? params.job.assignment.id,
      refStepId: params.job.assignment.stepId,
      attempt: updatedSpec.attemptCount,
    })
    return {
      findingId: findingRow?.id,
      replaySpecId: updatedSpec.id,
      attemptCount: updatedSpec.attemptCount,
      status: verdictStatus,
      verificationTier: verdictTier,
      feedback: normalizedFeedback,
      artifactId: receipt.id,
    }
  }

  private async runPhase3RefinementJob(job: Active, replaySpecId: string) {
    const run = this.check(job)
    const specRow = this.storage.getReplaySpec(run.id, replaySpecId)
    const findingRow = this.storage.db.select().from(findings).where(and(
      eq(findings.runId, run.id), eq(findings.id, specRow.findingId),
    )).get()
    if (!findingRow) {
      this.completeWorker(job.assignment, run, 'Finding no longer exists.', [])
      return
    }
    if (findingRow.finding.status === 'confirmed' || findingRow.finding.status === 'static_verified') {
      this.completeWorker(job.assignment, run, `Finding already ${findingRow.finding.status}.`, [])
      return
    }

    const permittedAtAdmission = this.approvedOriginsSet(run)
    const { grant, secrets, currentSecrets } = this.buildGrant(job, run, permittedAtAdmission)
    const { reposDir } = this.projectReposMount(run.projectId)
    const allProfiles = privateModelProfiles(this.storage)
    const reasoningPool = resolveProfilePoolForRole('reasoning', allProfiles)
    if (!reasoningPool.length) {
      this.completeWorker(job.assignment, run, 'No model profiles configured for Phase-3 refinement.', [])
      return
    }

    const session = await this.backend.openSession(
      job.assignment.id,
      job.controller.signal,
      reposDir ? { reposDir } : undefined,
    )

    let lastInlineFeedback: InlineVerifyFeedback | null = specRow.lastVerificationDiff ?? null
    let lastExchangeIds: string[] = [...(findingRow.finding.exchangeIds ?? [])]
    const collectedArtifactIds: string[] = []
    let refinementVerifyAttempts = 0
    const maxRefinementAttempts = 1 + maxInlineVerifyRetries

    try {
      const refinementHandlers: WorkerToolHandlers = {
        spillOutput: async (id, content, signal) => session.stage(`tool-output/${id}.txt`, content, signal),
        verify_replay_spec: async (args) => {
          const spec = args.spec ?? args.replaySpec
          if (!spec) throw new Error('verify_replay_spec requires spec or replaySpec.')
          refinementVerifyAttempts += 1
          const inline = await this.executeInlineVerification({
            job,
            grant,
            currentSecrets,
            reposDir,
            spec,
            findingId: args.findingId ?? findingRow.id,
            replaySpecId: args.replaySpecId ?? specRow.id,
            phase3RefinementAttempt: refinementVerifyAttempts,
          })
          lastInlineFeedback = inline.feedback
          if (inline.artifactId) collectedArtifactIds.push(inline.artifactId)
          return {
            findingId: inline.findingId ?? findingRow.id,
            replaySpecId: inline.replaySpecId,
            status: inline.status,
            ...(inline.verificationTier ? { verificationTier: inline.verificationTier } : {}),
            inlineVerifyFeedback: inline.feedback,
          }
        },
        update_proposed_finding: async (args) => {
          const curRun = this.check(job)
          const currentApproved = this.approvedOriginsSet(curRun)
          const latestFinding = this.storage.db.select().from(findings).where(and(
            eq(findings.runId, curRun.id), eq(findings.id, args.findingId),
          )).get()
          if (!latestFinding) throw new Error(`Finding ${args.findingId} not found in this run.`)
          const isAlreadyVerified = latestFinding.finding.status === 'confirmed' || latestFinding.finding.status === 'static_verified'
          let parsedUpdatedSpec: DeclarativeReplaySpec | undefined
          let nextReplaySpecId = latestFinding.replaySpecId ?? undefined
          let nextSourceOrigins = latestFinding.sourceOrigins
          const extraEvidenceIds: string[] = []
          let createdSpecRowId: string | undefined

          if (args.replaySpec) {
            const parsed = declarativeReplaySpecSchema.parse(args.replaySpec)
            const specOrigins = replaySpecOrigins(parsed)
            if (specOrigins.some(o => !currentApproved.has(o))) {
              throw new BrokerDenied('Updated replay spec references an origin outside current approved scope.')
            }
            if (!isAlreadyVerified && refinementVerifyAttempts >= maxRefinementAttempts) {
              return {
                findingId: latestFinding.id,
                replaySpecId: latestFinding.replaySpecId,
                status: latestFinding.finding.status,
                ...(latestFinding.verificationTier ? { verificationTier: latestFinding.verificationTier } : {}),
                inlineVerifyFeedback: {
                  verdict: 'inconclusive',
                  controlPassed: false,
                  assertionSummary: {
                    observed: 'retry_limit_exceeded',
                    expected: `<= ${maxRefinementAttempts} verification attempts`,
                    reason: `Phase-3 refinement verification retry limit reached (maxInlineVerifyRetries=${maxInlineVerifyRetries}).`,
                  },
                  stepStatuses: [],
                  retriesRemaining: 0,
                } satisfies InlineVerifyFeedback,
                updated: false,
                isError: true,
              }
            }
            parsedUpdatedSpec = parsed
            nextSourceOrigins = [...new Set([...latestFinding.sourceOrigins, ...specOrigins])]
            const createdSpec = this.storage.createReplaySpec(
              curRun,
              job.assignment,
              latestFinding.id,
              parsed,
              nextSourceOrigins,
              { initialAttemptCount: 0 },
            )
            createdSpecRowId = createdSpec.id
            const ev = this.storage.addArtifact(curRun, job.assignment, 'replay',
              `Refined replay spec · ${parsed.title}`,
              JSON.stringify({ findingId: latestFinding.id, replaySpecId: createdSpec.id, specSha256: createdSpec.specSha256, spec: parsed }, null, 2),
              undefined, currentSecrets())
            extraEvidenceIds.push(ev.id)
            collectedArtifactIds.push(ev.id)
            if (!isAlreadyVerified) {
              nextReplaySpecId = createdSpec.id
            }
          }
          const updated = this.storage.updateProposedFinding(curRun, latestFinding.id, {
            replaySpecId: nextReplaySpecId,
            sourceOrigins: nextSourceOrigins,
            ...(args.counterevidence !== undefined ? { counterevidence: args.counterevidence } : {}),
            ...(args.confidenceRationale !== undefined ? { confidenceRationale: args.confidenceRationale } : {}),
            ...(args.severityChangeConditions !== undefined ? { severityChangeConditions: args.severityChangeConditions } : {}),
            ...(args.codeLocations !== undefined ? { codeLocations: args.codeLocations } : {}),
            finding: {
              ...(args.title ? { title: args.title } : {}),
              ...(args.summary ? { reason: args.summary } : {}),
              ...(!isAlreadyVerified && args.severity ? { severity: args.severity } : {}),
              ...(!isAlreadyVerified && parsedUpdatedSpec ? { status: 'pending' as const } : {}),
              ...(extraEvidenceIds.length ? { evidenceIds: extraEvidenceIds } : {}),
            },
          })
          if (parsedUpdatedSpec && (args.verifyNow ?? true) && !isAlreadyVerified) {
            refinementVerifyAttempts += 1
            const inline = await this.executeInlineVerification({
              job,
              grant,
              currentSecrets,
              reposDir,
              spec: parsedUpdatedSpec,
              findingId: latestFinding.id,
              replaySpecId: createdSpecRowId ?? nextReplaySpecId ?? specRow.id,
              phase3RefinementAttempt: refinementVerifyAttempts,
            })
            lastInlineFeedback = inline.feedback
            if (inline.artifactId) collectedArtifactIds.push(inline.artifactId)
            return {
              findingId: updated.id,
              replaySpecId: inline.replaySpecId,
              status: inline.status,
              verificationTier: inline.verificationTier,
              inlineVerifyFeedback: inline.feedback,
              updated: true,
            }
          }
          return {
            findingId: updated.id,
            replaySpecId: updated.replaySpecId,
            status: updated.status,
            updated: true,
          }
        },
        record_coverage: async (args) => {
          const curRun = this.check(job)
          const currentApproved = this.approvedOriginsSet(curRun)
          const cleanOrigin = this.parseOriginForRun(curRun, args.origin)
          if (!currentApproved.has(cleanOrigin)) throw new BrokerDenied(`Origin ${cleanOrigin} is not approved.`)
          const ext = args as typeof args & { enforcingControl?: string; proofGapReason?: string; linkedFindingId?: string }
          const entry = this.storage.upsertCoverageEntry(curRun, job.assignment.id, {
            origin: cleanOrigin,
            category: args.category,
            status: args.status,
            summary: args.summary,
            enforcingControl: ext.enforcingControl,
            proofGapReason: args.status === 'needs_follow_up' ? (ext.proofGapReason?.trim() || args.summary) : ext.proofGapReason,
            linkedFindingId: ext.linkedFindingId,
          })
          return { id: entry.id, origin: entry.origin, category: entry.category, status: entry.status }
        },
        get_exchange: async ({ exchangeId, includeBody }, signal) => {
          const curRun = this.check(job)
          const currentApproved = this.approvedOriginsSet(curRun)
          const ex = this.storage.getExchange(curRun.id, exchangeId)
          if ([ex.origin, ex.finalOrigin, ...ex.redirectOrigins].some(o => !currentApproved.has(o))) {
            throw new BrokerDenied('Exchange touches an origin outside current approved scope.')
          }
          let stagedPath: string | null = null
          if (includeBody) {
            stagedPath = await session.stage(`exchanges/${ex.id}.json`, JSON.stringify(ex, null, 2), signal).catch(() => null)
          }
          return { ...ex, body: includeBody ? ex.body.slice(0, 12_000) : undefined, stagedPath }
        },
        search_exchanges: async ({ query, origin, status, limit }) => {
          const curRun = this.check(job)
          const currentApproved = this.approvedOriginsSet(curRun)
          return this.storage.searchExchanges(curRun.id, query, { approvedOrigins: currentApproved, origin, limit })
            .filter(ex => status === undefined || ex.status === status)
            .map(ex => ({
              id: ex.id, origin: ex.origin, method: ex.method, pathAndQuery: ex.pathAndQuery,
              status: ex.status, mediaType: ex.mediaType, bodyPreview: ex.bodyPreview.slice(0, 600),
            }))
        },
        search_facts: async ({ query, origin, kind, limit }) => {
          const curRun = this.check(job)
          const currentApproved = this.approvedOriginsSet(curRun)
          return this.storage.listFacts(curRun.id, { includeTainted: false, query, origin, kind, limit })
            .filter(f => currentApproved.has(f.origin) && f.sourceOrigins.every(o => currentApproved.has(o)))
        },
        derive_evidence: async ({ command, outputs, timeoutMs }, signal) => {
          const curRun = this.check(job)
          const res = await session.exec(command, outputs ?? ['result.txt'], signal, timeoutMs ?? 60_000)
          const ev = this.storage.addArtifact(curRun, job.assignment, 'analysis', 'Refinement derived evidence',
            JSON.stringify({
              command: redact(command, secrets),
              exitStatus: res.exitCode,
              stdout: redact(res.stdout, secrets),
              stderr: redact(res.stderr, secrets),
              outputs: res.outputs,
            }, null, 2), undefined, secrets)
          return { evidenceId: ev.id, exitCode: res.exitCode, stdout: res.stdout, stderr: res.stderr, outputs: res.outputs }
        },
        analyze_artifact: async (args, signal) => {
          this.check(job)
          const { tool, ...rest } = args
          return await session.analyze(tool, rest, signal)
        },
        complete_intent: async (completion) => ({ recorded: true, status: completion.status }),
      }

      const maxRefineTurns = Math.max(1, Math.min(8, job.assignment.maxTurns || 8))
      const refineInstructions = [
        'You are Guardian v4’s Phase-3 Replay Spec Refinement specialist (strictly bounded 8-turn pass).',
        'A submitted DeclarativeReplaySpec failed deterministic Zero-LLM verification. Inspect the sanitized InlineVerifyFeedback, prior exchanges, and facts.',
        'If the vulnerability is real and the failure was a replay-spec bug (e.g. jq path/syntax error, missing extraction, wrong expectedStatus, or step ordering), call verify_replay_spec (or update_proposed_finding with verifyNow=true) with a repaired DeclarativeReplaySpec.',
        'If the control genuinely blocks the exploit or the signal cannot be reproduced deterministically, close coverage cleanly via record_coverage ("ruled_out" with enforcingControl or "needs_follow_up" with proofGapReason) and call complete_intent.',
        'You CANNOT mark a finding confirmed directly—only deterministic ReplayVerifier passing can confirm a finding.',
      ].join('\n')

      const refinePrompt = JSON.stringify({
        finding: {
          id: findingRow.id,
          origin: findingRow.finding.origin,
          title: findingRow.finding.title,
          status: findingRow.finding.status,
          category: findingRow.finding.category,
          cwe: findingRow.finding.cwe,
          severity: findingRow.finding.severity,
        },
        replaySpecId: specRow.id,
        replaySpec: specRow.spec,
        lastVerificationDiff: lastInlineFeedback,
        maxTurns: maxRefineTurns,
      }, null, 2)

      const sessionResult = await runAgentSession({
        directory: this.storage.directory,
        sessionId: job.assignment.sessionId,
        requestId: `refine:${specRow.id}:${run.goalRevision}:${run.scopeRevision}`,
        profiles: reasoningPool,
        scenario: 'worker-investigation',
        roleAffinity: 'reasoning',
        instructions: refineInstructions,
        prompt: refinePrompt,
        signal: job.controller.signal,
        maxTurns: maxRefineTurns,
        compaction: false,
        enableSettlement: false,
        requireCompleteIntent: true,
        handlers: refinementHandlers,
        secrets,
        beforeCall: () => {
          this.check(job)
          if (this.storage.checkBudgetExceeded(run.id)) {
            throw new BudgetExceededError('Run spend or request budget exceeded.')
          }
        },
        onUsage: usage => {
          this.storage.recordLlmSpend(run.id, {
            usd: usage.costUsd,
            tokens: usage.inputTokens + usage.outputTokens,
          })
        },
        onTurn: turn => {
          this.storage.updateWorker(job.assignment.id, { turnsUsed: turn })
          this.storage.recordLlmSpend(run.id, { turns: 1 })
        },
        onProfileSuccess: id => recordProfileSuccess(id, this.storage),
        onProfileFailure: (id, err, hard) => recordProfileFailure(id, err, hard, this.storage),
      })

      // Mandatory Post-Refinement Zero-LLM Gate
      const latestRun = this.check(job)
      let currentFinding = this.storage.db.select().from(findings).where(and(
        eq(findings.runId, latestRun.id), eq(findings.id, findingRow.id),
      )).get()
      const activeSpecId = currentFinding?.replaySpecId ?? specRow.id
      const currentSpec = this.storage.getReplaySpec(latestRun.id, activeSpecId)

      if (currentFinding && currentFinding.finding.status === 'pending') {
        const nextAttempt = refinementVerifyAttempts + 1
        refinementVerifyAttempts = nextAttempt
        const inline = await this.executeInlineVerification({
          job,
          grant,
          currentSecrets,
          reposDir,
          spec: currentSpec.spec,
          findingId: currentFinding.id,
          replaySpecId: currentSpec.id,
          phase3RefinementAttempt: nextAttempt,
        })
        lastInlineFeedback = inline.feedback
        if (inline.artifactId) collectedArtifactIds.push(inline.artifactId)
        currentFinding = this.storage.db.select().from(findings).where(and(
          eq(findings.runId, latestRun.id), eq(findings.id, findingRow.id),
        )).get()
        if (currentFinding && currentFinding.finding.status === 'pending') {
          const fallbackStatus: Finding['status'] =
            lastInlineFeedback?.verdict === 'dismissed' ? 'dismissed' : 'inconclusive'
          this.storage.updateProposedFinding(latestRun, currentFinding.id, {
            verificationTier: null,
            finding: {
              status: fallbackStatus,
              verificationTier: undefined,
              confidence: fallbackStatus === 'dismissed' ? 'medium' : 'low',
              reason: redact(
                inline.feedback.assertionSummary?.reason ||
                currentFinding.finding.reason ||
                `Phase-3 refinement retry limit reached (maxInlineVerifyRetries=${maxInlineVerifyRetries}).`,
                currentSecrets(),
              ),
            },
          })
          currentFinding = this.storage.db.select().from(findings).where(and(
            eq(findings.runId, latestRun.id), eq(findings.id, findingRow.id),
          )).get()
        }
      }

      const finalStatus = currentFinding?.finding.status ?? 'inconclusive'
      lastExchangeIds = [...(currentFinding?.finding.exchangeIds ?? lastExchangeIds)]

      if (finalStatus !== 'confirmed' && finalStatus !== 'static_verified') {
        const latestDiff = currentSpec.lastVerificationDiff ?? lastInlineFeedback
        const targetCategory = currentSpec.spec.category as OwaspCategory
        if (owaspCategories.includes(targetCategory) && this.permitted(latestRun, currentSpec.spec.origin)) {
          const existingCov = this.storage.listCoverageEntries(latestRun.id, latestRun.goalRevision)
            .find(c => c.origin === currentSpec.spec.origin && c.category === targetCategory)
          const alreadyClosed = existingCov &&
            (existingCov.status === 'reported' || existingCov.status === 'ruled_out' || existingCov.status === 'needs_follow_up')
          if (!alreadyClosed) {
            if (finalStatus === 'dismissed' && latestDiff?.controlPassed) {
              this.storage.upsertCoverageEntry(latestRun, job.assignment.id, {
                origin: currentSpec.spec.origin,
                category: targetCategory,
                status: 'ruled_out',
                summary: `Ruled out after Phase-3 refinement: ${currentSpec.spec.title}`,
                enforcingControl: lastExchangeIds[0] || `replay:${currentSpec.id}`,
              })
            } else {
              this.storage.upsertCoverageEntry(latestRun, job.assignment.id, {
                origin: currentSpec.spec.origin,
                category: targetCategory,
                status: 'needs_follow_up',
                summary: `Unconfirmed after Phase-3 8-turn refinement: ${currentSpec.spec.title}`,
                proofGapReason: latestDiff?.assertionSummary?.reason ||
                  latestDiff?.assertionSummary?.observed ||
                  currentFinding?.finding.reason ||
                  'Phase-3 refinement could not confirm finding deterministically.',
              })
            }
          }
        }
      }

      const summary = sessionResult.completion
        ? `[${sessionResult.completion.status}] Phase-3 refinement (${finalStatus}): ${sessionResult.completion.summary}`
        : `Phase-3 refinement finished (${finalStatus}): ${sessionResult.answer.slice(0, 160)}`
      this.completeWorker(job.assignment, this.check(job), summary, collectedArtifactIds, undefined, currentSecrets())
    } finally {
      await session.close().catch(() => undefined)
    }
  }

  private async verifyBaselineJob(job: Active) {
    const run = this.check(job)
    const asset = run.candidates.find(c => c.id === job.assignment.assetId)
    if (!asset) {
      this.completeWorker(job.assignment, run, 'Host is no longer in run inventory.', [])
      return
    }
    const { analysis } = assessmentAssignments(this.storage.workerList(run.id), asset.id, run.goalRevision)
    const ready = analysis?.status === 'complete' ? analysis : undefined
    const selected: readonly AssessmentCheckId[] = run.reviewPlan?.status === 'ready' ? run.reviewPlan.checks : responseCheckIds
    const responseChecks = selected.filter(id => id !== 'access-policy') as ResponseCheckId[]
    const includesAccess = selected.includes('access-policy')

    const response: ReviewInput | undefined = responseChecks.length ? (() => {
      const stored = ready ? this.storage.assignmentObservation(ready.id) : undefined
      const record = stored ? JSON.parse(this.storage.artifact(run.id, stored.id).content) as Capture : undefined
      const origins = ready && record?.observation ? [...new Set([record.observation.origin, record.observation.finalOrigin, ...this.storage.brokerOrigins(ready)])] : []
      const authorized = origins.every(origin => this.permitted(run, origin))
      const observation = authorized ? record?.observation : null
      const note = authorized ? record?.note : 'The saved observation includes a host outside the current approval.'
      if (authorized) for (const origin of origins) job.origins.add(origin)
      return { artifactId: authorized ? stored?.id : undefined, reviews: responseReview(observation, note, responseChecks) }
    })() : undefined

    const access: ReviewInput | undefined = includesAccess ? (() => {
      const stored = ready ? this.storage.assignmentEvidence(ready.id, 'access-policy') : undefined
      const record = stored ? JSON.parse(this.storage.artifact(run.id, stored.id).content) as {
        origin: string; snapshot: AccessPolicySnapshot | null
      } : undefined
      const snapshot = record?.origin === asset.origin && record.snapshot?.origin === asset.origin ? record.snapshot : undefined
      return { artifactId: record?.origin === asset.origin ? stored?.id : undefined, reviews: accessPolicyReviews(snapshot), policy: snapshot }
    })() : undefined

    const inputs = [response, access].filter((i): i is ReviewInput => i !== undefined)
    const responseComparisons = response?.reviews.flatMap(r => r.comparison ? [r.comparison] : []) ?? []
    const accessComparisons = access?.reviews.flatMap(r => r.comparison ? [r.comparison] : []) ?? []
    const comparisons = [...responseComparisons, ...accessComparisons]
    const payload = { response: responseComparisons, access: access?.policy ?? null }
    const { reposDir } = this.projectReposMount(run.projectId)
    const result = comparisons.length ? await this.backend.run({
      assignmentId: job.assignment.id,
      files: [{ name: 'verification-input.json', content: JSON.stringify(payload) }],
      command: verificationCommand,
      outputs: ['verification.json'],
    }, job.controller.signal, reposDir ? { reposDir } : undefined) : undefined

    const outcomes = readComparisons(result?.exitCode === 0 ? result.outputs['verification.json'] : undefined, comparisons)
    const verified = inputs.flatMap(({ artifactId, reviews }) =>
      reviews.map(review => ({ artifactId, review, coverage: checkCoverage(review, outcomes) })))
    const checks = verified.map(item => item.coverage)
    const current = this.check(job)
    const assessed = checks.filter(check => check.status === 'met' || check.status === 'gap').length
    const gaps = checks.filter(check => check.status === 'gap').length
    const outcome = assessed
      ? `${assessed} checks verified · ${gaps === 1 ? '1 gap' : gaps + ' gaps'}`
      : 'Inconclusive: ' + (checks[0]?.reason ?? 'No checks evaluated.')

    this.storage.transaction(() => {
      const title = includesAccess ? (responseChecks.length ? 'Evidence verification' : 'Access policy verification') : 'Response policy verification'
      const ev = this.storage.addArtifact(current, job.assignment, 'verification', title,
        JSON.stringify({
          origin: asset.origin,
          inputEvidence: inputs.flatMap(i => i.artifactId ? [i.artifactId] : []),
          checks,
          comparisons,
          accessRecord: access?.artifactId,
          command: result ? verificationCommand : undefined,
          exitStatus: result?.exitCode,
          interpreter: result ? 'just-bash 3.6.1' : undefined,
        }, null, 2), 'verification')
      for (const { artifactId, review, coverage } of verified) {
        const links = artifactId ? [artifactId, ev.id] : [ev.id]
        const earlier = this.baselineFinding(current, asset, review)
        if (coverage.status === 'gap') this.saveBaselineFinding(current, asset, review, 'confirmed', coverage.reason, links, earlier?.id)
        else if (coverage.status === 'inconclusive' && (earlier || review.rule.id === 'hsts')) {
          this.saveBaselineFinding(current, asset, review, 'inconclusive', coverage.reason, links, earlier?.id)
        } else if (earlier) this.saveBaselineFinding(current, asset, review, 'dismissed', coverage.reason, links, earlier.id)
      }
      this.completeWorker(job.assignment, current, outcome, [ev.id], checks)
    }, { behavior: 'immediate' })
  }

  // --- One-Click Verify Fix Retest ---

  private startRetestWorker(run: Run, worker: Assignment) {
    const claimed = this.storage.transaction(() => {
      const w = this.storage.updateWorker(worker.id, {
        status: 'running', lease: randomUUID(), leaseExpiresAt: Date.now() + 10 * 60_000, outcome: null,
      })
      this.storage.event(run.id, 'retest.started', worker.title + ' started.', { assignmentId: worker.id })
      return w
    })
    if (!claimed) return

    const job: Active = { assignment: claimed, origins: new Set(claimed.sourceOrigins), controller: new AbortController() }
    this.active.set(claimed.id, job)

    void this.runRetestJob(job).catch(error => {
      const msg = redact(error instanceof Error ? error.message : String(error)).slice(0, 400)
      this.storage.updateWorker(claimed.id, { status: 'failed', outcome: msg, lease: null, leaseExpiresAt: null })
      this.storage.event(run.id, 'retest.failed', `Verify Fix retest failed: ${msg}`, { assignmentId: claimed.id })
    }).finally(() => {
      this.active.delete(claimed.id)
      this.scheduleWake()
    })
  }

  private async runRetestJob(job: Active) {
    const run = this.check(job)
    const findingId = job.assignment.stepId
    if (!findingId) throw new Error('Retest worker missing finding reference.')
    const findingRow = this.storage.db.select().from(findings).where(and(
      eq(findings.runId, run.id), eq(findings.id, findingId),
    )).get()
    if (!findingRow?.replaySpecId) throw new Error('Finding has no Declarative Replay Spec.')
    const specRow: ReplaySpecRow = this.storage.getReplaySpec(run.id, findingRow.replaySpecId)
    const permittedAtAdmission = this.approvedOriginsSet(run)
    const { grant, secrets, currentSecrets } = this.buildGrant(job, run, permittedAtAdmission)

    if ((specRow.spec.kind === 'rce_proof' && specRow.spec.proofMode === 'oob_canary') || this.isCanaryListenerConfigured()) {
      await this.canaryBroker.startListener({ enableDns: this.isCanaryDnsConfigured() }).catch(() => undefined)
    }

    const { reposDir } = this.projectReposMount(run.projectId)
    const retestRes = await retestReplaySpec({
      spec: specRow.spec,
      broker: this.broker,
      browser: this.browser,
      canaryBroker: this.canaryBroker,
      backend: this.backend,
      reposDir,
      grant,
      signal: job.controller.signal,
      storage: this.storage,
      runId: run.id,
      assignmentId: job.assignment.id,
      onExchange: ex => {
        const saved = this.storage.recordExchange({
          runId: run.id,
          assignmentId: job.assignment.id,
          scopeRevision: run.scopeRevision,
          origin: ex.origin,
          finalOrigin: ex.finalOrigin,
          redirectOrigins: ex.redirectOrigins,
          method: ex.method,
          pathAndQuery: ex.pathAndQuery,
          personaHandle: ex.personaHandle,
          status: ex.status,
          mediaType: ex.mediaType,
          reqHeaders: ex.reqHeaders,
          respHeaders: ex.respHeaders,
          body: ex.body,
          durationMs: ex.durationMs,
          secretMatches: ex.secretMatches,
          secrets: currentSecrets(),
        })
        return saved.id
      },
    })

    const current = this.storage.run(run.id)
    this.storage.transaction(() => {
      const secretsList = currentSecrets()
      const cleanObserved = redact(retestRes.replay.outcome.observed, secretsList)
      const ev = this.storage.addArtifact(current, job.assignment, 'replay',
        `Verify Fix retest · ${findingRow.finding.title}`,
        JSON.stringify({
          findingId,
          replaySpecId: specRow.id,
          verdict: retestRes.verdict,
          outcome: retestRes.replay.outcome,
          exchangeIds: retestRes.replay.exchangeIds,
          evidenceSha256: retestRes.replay.evidenceSha256,
        }, null, 2), 'retest:' + job.assignment.id, secretsList)
      const summary = `${retestRes.verdict}: ${cleanObserved}`
      this.storage.recordRetestRun(current, findingId, specRow.id, retestRes.verdict, summary, [ev.id], retestRes.replay.exchangeIds)
      this.completeWorker(job.assignment, current, `Verify Fix verdict: ${retestRes.verdict}`, [ev.id], undefined, secretsList)
      this.storage.message(current.id, current.coordinatorId, 'guardian',
        `Verify Fix retest for "${findingRow.finding.title}": ${retestRes.verdict}. ${cleanObserved}`, undefined, undefined, secretsList)
    }, { behavior: 'immediate' })
  }

  // --- Coordinator Chat ---

  private startCoordinator(run: Run, profiles: readonly ResolvedModelProfile[]) {
    if (this.coordinator.has(run.id)) return
    const thread = this.storage.db.select().from(messages).where(and(
      eq(messages.runId, run.id), eq(messages.threadId, run.coordinatorId),
    )).orderBy(asc(messages.createdAt)).all()
    const answered = new Set(thread.map(item => item.replyTo))
    const next = thread.find(item => item.role === 'operator' && !answered.has(item.id) &&
      item.id !== run.reviewPlan?.goalMessageId && !item.content.startsWith('Steering hint:') &&
      this.shouldCoordinatorAnswer(item.content))
    if (!next) return
    this.resetBoardHops(run)

    const controller = new AbortController()
    const task: CoordinatorTask = { controller, goalRevision: run.goalRevision, scopeRevision: run.scopeRevision }
    this.coordinator.set(run.id, task)

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
      onUsage: u => this.storage.recordLlmSpend(run.id, { usd: u.costUsd, tokens: u.inputTokens + u.outputTokens }),
      onProfileSuccess: id => recordProfileSuccess(id, this.storage),
      onProfileFailure: (id, err, hard) => recordProfileFailure(id, err, hard, this.storage),
    }).then(answer => {
      if (!this.currentCoordinator(run.id, task)) return
      this.storage.transaction(() => {
        this.storage.message(run.id, run.coordinatorId, 'coordinator', answer, next.id)
        this.storage.event(run.id, 'coordinator.reply', 'The coordinator replied.')
      })
    }).catch(() => {
      if (!this.currentCoordinator(run.id, task)) return
      this.storage.transaction(() => {
        this.storage.message(run.id, run.coordinatorId, 'guardian',
          'The coordinator could not reach the model. Review the workflow for current progress.', next.id)
        this.storage.event(run.id, 'coordinator.unavailable', 'The coordinator could not complete its reply.')
      })
    }).finally(() => {
      this.coordinator.delete(run.id)
    })
  }

  // --- On-Demand / Opt-In Air-Gapped Verified Patch Workflow (§4.6) ---

  async runPatchWorkflow(
    runId: string,
    findingId: string,
    repoOverride?: string,
    signal?: AbortSignal,
  ): Promise<PatchProposal> {
    const run = this.storage.run(runId)
    const findingRow = this.storage.db.select().from(findings).where(and(
      eq(findings.runId, run.id), eq(findings.id, findingId),
    )).get()
    if (!findingRow) throw new Error('Finding not found.')

    const hydratedFinding: Finding = {
      ...findingRow.finding,
      verificationTier: findingRow.verificationTier ?? findingRow.finding.verificationTier,
      codeLocations: findingRow.codeLocations ?? findingRow.finding.codeLocations,
    }
    if (hydratedFinding.status !== 'confirmed' && hydratedFinding.status !== 'static_verified') {
      throw new Error('Verified patch generation requires a confirmed or static_verified finding.')
    }

    const { reposDir, mountedRepos } = this.projectReposMount(run.projectId)
    if (!reposDir || !mountedRepos.length) {
      throw new Error('No mounted source repository found for this project. Sync a GitHub repo first.')
    }
    const repo = repoOverride?.trim() || hydratedFinding.codeLocations?.[0]?.repo || mountedRepos[0]
    const profiles = privateModelProfiles(this.storage)
    const personas = resolveRunPersonas(this.storage, run.projectId, run.approvedPersonaIds)
    const secrets = personaSecrets(personas)

    // Gate 6: when a local-lab target exists, rebuild the patched lab and replay the finding's spec.
    // A temporary `retest` assignment supplies the scoped grant (no interactive worker needed).
    let labRetest: Parameters<typeof generateAndReviewPatch>[0]['labRetest'] | undefined
    let retestWorkerId: string | null = null
    const labHandle = this.getLabTargetHandle(run.id)
    const findingSpecId = findingRow.replaySpecId ?? hydratedFinding.replaySpecId ?? null
    if (labHandle && findingSpecId) {
      try {
        const specRow = this.storage.getReplaySpec(run.id, findingSpecId)
        const approvedOrigins = this.approvedOriginsSet(run)
        if (specRow.sourceOrigins.every(o => approvedOrigins.has(o))) {
          const retestWorker = this.storage.makeWorker(
            run,
            'retest',
            run.candidates.find(c => c.id === findingRow.assetId),
            `Patch Gate 6 retest · ${hydratedFinding.title.slice(0, 70)}`,
            `Deterministic post-patch retest of replay spec ${specRow.id}.`,
            { stepId: findingRow.id, sourceOrigins: specRow.sourceOrigins },
          )
          const claimedRetest = this.storage.updateWorker(retestWorker.id, {
            status: 'running',
            lease: randomUUID(),
            leaseExpiresAt: Date.now() + 15 * 60_000,
          }) ?? retestWorker
          retestWorkerId = claimedRetest.id
          const retestJob: Active = { assignment: claimedRetest, origins: new Set(specRow.sourceOrigins), controller: new AbortController() }
          const { grant: retestGrant } = this.buildGrant(retestJob, run, approvedOrigins)
          const controlStep = specRow.spec.kind === 'http_chain'
            ? specRow.spec.steps.find(step => step.role === 'control') ?? specRow.spec.steps[0]
            : undefined
          labRetest = {
            labRunner: this.labRunner,
            runId: run.id,
            replaySpec: specRow.spec,
            broker: this.broker,
            browser: this.browser,
            canaryBroker: this.canaryBroker,
            backend: this.backend,
            grant: retestGrant,
            storage: this.storage,
            assignmentId: claimedRetest.id,
            ...(controlStep ? {
              baselineCaller: {
                origin: controlStep.request.origin,
                method: controlStep.request.method,
                pathAndQuery: controlStep.request.pathAndQuery,
                persona: controlStep.request.persona,
                ...(controlStep.request.headers ? { headers: controlStep.request.headers } : {}),
                ...(controlStep.request.jsonBody !== undefined ? { body: JSON.stringify(controlStep.request.jsonBody) } : {}),
              },
              baselineExpectStatus: [200, 201, 204],
            } : {}),
          }
        }
      } catch {
        // Gate 6 stays unverified when the spec/lab context cannot be resolved.
      }
    }

    let result: Awaited<ReturnType<typeof generateAndReviewPatch>>
    try {
      result = await generateAndReviewPatch({
        runId: run.id,
        finding: hydratedFinding,
        repo,
        reposDir,
        backend: this.backend,
        modelProfiles: profiles,
        signal,
        secrets,
        ...(labRetest ? { labRetest } : {}),
        onUsage: u => this.storage.recordLlmSpend(run.id, { usd: u.costUsd, tokens: u.inputTokens + u.outputTokens }),
      })
    } finally {
      if (retestWorkerId) {
        try {
          this.storage.updateWorker(retestWorkerId, { status: 'complete', outcome: 'Patch Gate 6 retest finished.', lease: null, leaseExpiresAt: null })
        } catch { /* run may be gone */ }
      }
    }

    const saved = this.storage.savePatchProposal({
      id: result.id,
      runId: run.id,
      findingId: hydratedFinding.id,
      repo: result.repo,
      status: result.status,
      callerCompatibility: result.callerCompatibility,
      diff: result.diff,
      codeLocations: result.codeLocations,
      reviewNotes: result.reviewNotes,
      dynamicRetestVerdict: result.dynamicRetestVerdict,
      secrets,
    })

    const anchorWorker = this.storage.workerList(run.id).at(-1)
    if (anchorWorker) {
      this.storage.addArtifact(
        run,
        anchorWorker,
        'patch',
        `Patch proposal (${saved.status}) · ${hydratedFinding.title.slice(0, 80)}`,
        JSON.stringify({
          patchId: saved.id,
          findingId: saved.findingId,
          repo: saved.repo,
          status: saved.status,
          callerCompatibility: saved.callerCompatibility,
          dynamicRetestVerdict: saved.dynamicRetestVerdict,
          gates: result.gates,
          reviewNotes: saved.reviewNotes,
          diff: saved.diff,
        }, null, 2),
        undefined,
        secrets,
      )
    }

    return saved
  }

  // --- Shared Helpers ---

  private baselineFinding(run: Run, asset: Candidate, review: EvidenceReview) {
    return this.storage.db.select().from(findings).where(and(
      eq(findings.runId, run.id), eq(findings.assetId, asset.id), eq(findings.goalRevision, run.goalRevision),
      eq(findings.checkId, review.rule.id), eq(findings.caseId, review.coverage.caseId ?? ''),
    )).get()
  }

  private saveBaselineFinding(
    run: Run,
    asset: Candidate,
    review: EvidenceReview,
    status: Finding['status'],
    reason: string,
    evidenceIds: string[],
    existingId?: string,
  ) {
    const { rule, coverage } = review
    const confirmed = status === 'confirmed'
    const record: Finding = {
      id: existingId ?? randomUUID(),
      origin: asset.origin,
      title: status === 'inconclusive' ? rule.title + ' could not be assessed' : rule.findingTitle,
      status,
      severity: confirmed ? rule.severity : 'informational',
      reason,
      remediation: confirmed ? rule.remediation : status === 'inconclusive'
        ? 'Supply a current record from the approved host and repeat the review.'
        : status === 'pending' ? 'Resume the run to verify the observation.' : 'Review the verification evidence.',
      impact: confirmed ? rule.impact : undefined,
      recheck: confirmed ? rule.recheck : undefined,
      category: rule.category,
      cwe: rule.cwe,
      confidence: confirmed ? 'high' : status === 'inconclusive' ? 'low' : 'medium',
      verification: confirmed ? rule.verification : undefined,
      verificationTier: confirmed ? 'baseline_confirmed' : undefined,
      findingKind: 'baseline_check',
      check: { id: rule.id, caseId: coverage.caseId, expected: coverage.expected, observed: coverage.observed },
      evidenceIds,
      scopeRevision: run.scopeRevision,
    }
    if (existingId) {
      this.storage.db.update(findings).set({
        verificationTier: confirmed ? 'baseline_confirmed' : null,
        finding: record,
      }).where(eq(findings.id, record.id)).run()
    } else {
      this.storage.db.insert(findings).values({
        id: record.id,
        runId: run.id,
        assetId: asset.id,
        goalRevision: run.goalRevision,
        checkId: rule.id,
        caseId: coverage.caseId ?? '',
        findingKind: 'baseline_check',
        replaySpecId: null,
        sourceOrigins: [asset.origin],
        verificationTier: confirmed ? 'baseline_confirmed' : null,
        finding: record,
      }).run()
    }
  }

  private completeWorker(
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
    this.storage.message(run.id, worker.id, 'worker', outcome, undefined, [...artifactIds, result.id], secrets)
    this.storage.event(run.id, 'worker.complete', worker.title + ' completed.', {
      assignmentId: worker.id, artifactId: artifactIds[0] ?? result.id,
    })
  }
}

let instance: Execution | undefined
export function execution() {
  return instance ??= new Execution(store())
}
