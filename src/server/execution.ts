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
  responseCheckIds,
  workerHistory,
} from '../domain.ts'
import type {
  AssessmentCheckId,
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
import { evaluateTier3Approval, matchesApprovedEndpointPattern } from './approval-judge.ts'
import {
  agentTurn,
  chainPlannerPrompt,
  classifyHostTier,
  codeAuditPrompt,
  coordinatorPrompt,
  crossHostSynthesizerPrompt,
  defaultCodeAuditMaxTurns,
  filterHandlersForSpecialist,
  listSkills,
  loadSkill,
  resolveSpecialistProfile,
  routeStepToSpecialist,
  runAgentSession,
  threatModelPrompt,
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
import { CanaryBroker } from './canary-broker.ts'
import { ColdGraphCompactor } from './compactor.ts'
import { queryCves } from './cve-broker.ts'
import {
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
import { runThreeStageSemanticAudit, runVariantSweepForFinding, toChainStepInputs } from './semantic-audit.ts'
import { assessmentAssignments, store } from './store.ts'
import type { Assignment, ChainStep, Fact, PatchProposal, ReplaySpecRow, Run, Store } from './store.ts'
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

  for (const fact of suspects) {
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

const STATIC_ASSET_PATH_RE = /\.(?:js|mjs|cjs|css|map|png|jpe?g|gif|svg|webp|ico|woff2?|ttf|eot|pdf)(?:\?|$)/i
const RESOURCE_ID_KEY_RE = /^(?:id|uuid|[a-z][a-z0-9]*Id|[a-z][a-z0-9_]*_id)$/
const IGNORED_ID_VALUES = new Set(['true', 'false', 'null', 'undefined', 'default', 'self', 'me', 'current', 'none', 'all', 'new', 'list', 'index', 'health', 'status', 'public'])
const PATH_RESOURCE_RE = /\/(?:api\/(?:v\d+\/)?)?([a-z][a-z0-9_-]{1,32})\/([0-9]{2,16}|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}|(?:usr|org|proj|acct|app|ord|inv|doc|file|chat|team|sub|cus|ws|res)_[a-zA-Z0-9_-]{4,64})(?:\/|$|\?)/i

export function extractPersonaResourcesFromExchange(ex: {
  origin: string
  method: string
  pathAndQuery: string
  personaHandle?: string | null
  status: number
  mediaType: string
  body: string
}): Array<{ resourceId: string; endpoint: string; method: string; field: string }> {
  if (!ex.personaHandle) return []
  if (ex.status < 200 || ex.status >= 300) return []
  if (STATIC_ASSET_PATH_RE.test(ex.pathAndQuery) || ex.pathAndQuery.startsWith('/_next/static/')) return []

  const found: Array<{ resourceId: string; endpoint: string; method: string; field: string }> = []
  const seen = new Set<string>()
  const push = (resourceId: string, endpoint: string, field: string) => {
    const clean = resourceId.trim()
    if (!clean || clean.length < 2 || clean.length > 128) return
    if (IGNORED_ID_VALUES.has(clean.toLowerCase())) return
    const key = `${endpoint}|${clean}`
    if (seen.has(key) || found.length >= 12) return
    seen.add(key)
    found.push({ resourceId: clean, endpoint, method: ex.method.toUpperCase(), field })
  }

  const pathMatch = PATH_RESOURCE_RE.exec(ex.pathAndQuery)
  if (pathMatch) {
    push(pathMatch[2], ex.pathAndQuery.split('?')[0], `path:${pathMatch[1]}`)
  }

  if (ex.mediaType.toLowerCase().includes('json') && ex.body && ex.body.length <= 256 * 1024) {
    try {
      const parsed = JSON.parse(ex.body) as unknown
      const basePath = ex.pathAndQuery.split('?')[0]
      const walk = (node: unknown, depth: number) => {
        if (depth > 8 || found.length >= 12 || !node || typeof node !== 'object') return
        if (Array.isArray(node)) {
          for (const item of node.slice(0, 5)) walk(item, depth + 1)
          return
        }
        for (const [key, val] of Object.entries(node as Record<string, unknown>)) {
          if (found.length >= 12) break
          if (RESOURCE_ID_KEY_RE.test(key)) {
            if (typeof val === 'string' && val.trim().length >= 3) {
              push(val, basePath, key)
            } else if (typeof val === 'number' && Number.isInteger(val) && val > 0) {
              push(String(val), basePath, key)
            }
          } else if (val && typeof val === 'object') {
            walk(val, depth + 1)
          }
        }
      }
      walk(parsed, 1)
    } catch {
      // Ignore non-JSON or truncated bodies
    }
  }

  return found
}

export function buildBolaTestQueue(
  facts: readonly Fact[],
  personas: readonly { handle: string; originAllowlist: readonly string[] }[],
  approvedOrigins: ReadonlySet<string>,
): PersonaResourceQueueItem[] {
  if (personas.length < 2) return []
  const queue: PersonaResourceQueueItem[] = []
  const seen = new Set<string>()

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
    const otherPersonas = personas
      .filter(p => p.handle !== ownerPersona && p.originAllowlist.includes(fact.origin))
      .map(p => p.handle)
    const testAsPersonas = [...new Set([...otherPersonas, 'anonymous'])]
    if (!testAsPersonas.length) continue

    const key = `${fact.origin}|${ownerPersona}|${endpoint}|${resourceId}`
    if (seen.has(key)) continue
    seen.add(key)

    queue.push({
      factId: fact.id,
      origin: fact.origin,
      ownerPersona,
      resourceId,
      endpoint,
      method,
      testAsPersonas,
      summary: fact.summary,
    })
    if (queue.length >= 25) break
  }

  return queue
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

function createBroker() {
  const target = process.env.GUARDIAN_NETWORK_FIXTURE
  if (!target) {
    return process.env.GUARDIAN_OFFLINE === '1'
      ? new RequestBroker({ resolve: async () => [] })
      : new RequestBroker()
  }
  const fixture = new URL(target)
  if (fixture.origin !== target || fixture.hostname !== '127.0.0.1' || fixture.protocol !== 'http:' || !fixture.port) {
    throw new Error('GUARDIAN_NETWORK_FIXTURE must identify a loopback HTTP origin.')
  }
  return new RequestBroker({
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
  private readonly variantSweptFindings = new Set<string>()
  private readonly variantSweepInFlight = new Set<string>()
  private safetyTimer?: NodeJS.Timeout
  private reclaimTimer?: NodeJS.Timeout
  private unsubWake?: () => void
  private wakeScheduled = false

  constructor(storage: Store, options: ExecutionOptions = {}) {
    this.storage = storage
    this.broker = options.broker ?? createBroker()
    this.browser = options.browser ?? new ScopedBrowser(this.broker)
    this.canaryBroker = options.canaryBroker ?? new CanaryBroker({ storage })
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
    await this.canaryBroker.stopListener().catch(() => undefined)
  }

  private scheduleWake() {
    if (this.wakeScheduled) return
    this.wakeScheduled = true
    queueMicrotask(() => {
      this.wakeScheduled = false
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
      canRead: origin => {
        if (!this.authorize(job)) return false
        const fresh = this.storage.run(run.id)
        return permittedAtAdmission.has(origin) && this.permitted(fresh, origin)
      },
      isIdempotentPostAllowed: (_origin, pathAndQuery, body) => isSafeIdempotentPost(pathAndQuery, body),
      isStateChangeApproved: (origin, method, pathAndQuery) => {
        const fresh = this.storage.run(run.id)
        if (allowLocalLab && process.env.GUARDIAN_ALLOW_LOCAL_LAB === '1' && fresh.capabilityTier >= 3) {
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
              }
            }
          }
        }
      },
    }
    return { grant, secrets, currentSecrets }
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
    if (project.environment === 'local-lab' && process.env.GUARDIAN_ALLOW_LOCAL_LAB === '1' && run.capabilityTier >= 3) {
      return { approved: true }
    }
    if (run.capabilityTier < 3) {
      throw new BrokerDenied('This operation requires Capability Tier 3.')
    }

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

    const decision = await new Promise<'approved' | 'denied' | 'canceled' | 'expired'>((resolveDecision, rejectDecision) => {
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

    if (this.authorize(job)) {
      this.storage.updateWorker(job.assignment.id, { status: 'running' })
    }
    return { approved: decision === 'approved' }
  }

  // --- Event-Driven Scheduler ---

  wake() {
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
          void this.labRunner.stopLabTarget(runId).catch(() => undefined)
        }
      } catch {
        this.startedLabRuns.delete(runId)
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
      const { grant, secrets } = this.buildGrant(job, freshRun, approvedOrigins)
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
          reposDir &&
          (project.labConfig.dockerComposeFile || project.labConfig.dockerfile || project.labConfig.image)
        ) {
          const primaryRepoDir = mountedRepos[0] ? join(reposDir, mountedRepos[0]) : reposDir
          if (existsSync(primaryRepoDir)) {
            await this.labRunner.startLabTarget({
              runId: freshRun.id,
              environment: project.environment,
              repoDir: primaryRepoDir,
              labConfig: project.labConfig,
              signal: task.controller.signal,
            })
            this.startedLabRuns.add(freshRun.id)
          }
        }
      } catch {
        // Best-effort lab boot; proceed cleanly if target is externally managed
      }

      // 0b. Persist initial dynamic step budget from pre-existing endpoints + suspects
      this.storage.updateRunDynamicStepBudget(freshRun.id, computeDynamicStepBudget(this.storage, freshRun.id))

      // 0c. Zero-LLM Phase-0 deterministic surface mapper (runs before LLM Turn 1)
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
      const highSignalPkgs = new Set(['next', 'react', 'vite', 'express', '@clerk/nextjs', '@supabase/supabase-js', 'graphql', 'fastify', 'nuxt', 'svelte', 'astro'])
      for (const spec of specs) {
        const deps = parseDependenciesFromFile(spec.name.split(':').pop() ?? spec.name, spec.content)
        // Also parse `:dependencies` note format generated by github-connector
        for (const match of spec.content.matchAll(/^([a-zA-Z0-9_.-]+):([@a-zA-Z0-9_./-]+)@([0-9][0-9A-Za-z.+-]*)/gm)) {
          deps.push({ ecosystem: match[1], package: match[2], version: match[3], sourceFile: spec.name })
        }
        for (const dep of deps) {
          if (!highSignalPkgs.has(dep.package.toLowerCase())) continue
          const key = `${dep.ecosystem}:${dep.package}:${dep.version}`
          if (seenDeps.has(key)) continue
          seenDeps.add(key)
          try {
            const advisories = await queryCves({ ecosystem: dep.ecosystem, package: dep.package, version: dep.version }, task.controller.signal)
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
              observations: observations.slice(0, 40),
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
        const nextPhase = current.capabilityTier === 0 || !profiles.length ? 'verification' : 'investigation'
        this.storage.updateRun(current.id, { phase: nextPhase })
        this.storage.event(current.id, `${nextPhase}.started`,
          nextPhase === 'investigation'
            ? `Threat model complete${codeAuditStepsCreated ? ` (${codeAuditStepsCreated} source-audit steps + ${addedInitial} initial steps)` : ` (${totalQueued} initial steps)`}. Starting closed-loop chain investigation.`
            : 'Baseline captures complete. Starting deterministic Zero-LLM verification.')
        this.storage.message(current.id, current.coordinatorId, 'guardian',
          nextPhase === 'investigation'
            ? `Threat model ranked ${finalEntries.length} hosts and queued ${totalQueued} initial investigation steps${codeAuditStepsCreated ? ` (including ${codeAuditStepsCreated} from Source-First Code Audit)` : ''}.`
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
          onUsage: usage => {
            this.storage.recordLlmSpend(run.id, {
              usd: usage.costUsd,
              tokens: usage.inputTokens + usage.outputTokens,
            })
          },
        }, {
          enableStage1Llm: false,
          persistToStore: true,
        })
        const semanticSteps = toChainStepInputs(run, semanticRes.rankedSuspects, hostTiersForAudit)
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
      for (const repoName of mountedRepos) {
        const repoRoot = join(reposDir, repoName)
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
                  if (overlapsOriginal(repoName, relFile, lineNo)) continue
                  const key = `${repoName}:${relFile}:${lineNo}`
                  if (seenHit.has(key)) continue
                  seenHit.add(key)
                  siblingHits.push({ repo: repoName, file: relFile, line: lineNo, preview: lines[i].trim().slice(0, 180) })
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
    if (!profiles.length) return
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
      const bolaQueue = buildBolaTestQueue(allUntaintedFacts, personas, approvedOrigins)
      const originsWithResources = [...new Set(bolaQueue.map(item => item.origin))]
      for (const origin of originsWithResources) {
        if (allSteps.length + bolaAutoSteps >= dynamicStepBudget) break
        const alreadyPlanned = allSteps.some(s =>
          s.sourceOrigins.includes(origin) &&
          (s.skills.includes('bola-idor-race') || /\b(?:bola|idor|cross-persona)\b/i.test(s.title)),
        )
        if (alreadyPlanned) continue
        const asset = afterRound.candidates.find(c => c.origin === origin && afterRound.approved.includes(c.id))
        if (!asset) continue
        const itemsForOrigin = bolaQueue.filter(i => i.origin === origin).slice(0, 5)
        const factIds = itemsForOrigin.map(i => i.factId).filter((fid): fid is string => Boolean(fid))
        this.storage.addChainStep(afterRound, {
          title: `Cross-persona BOLA/IDOR matrix · ${new URL(origin).hostname}`,
          hypothesis: `Replay ${itemsForOrigin.length} resource(s) owned by ${itemsForOrigin[0].ownerPersona} (e.g. ${itemsForOrigin.map(i => `${i.endpoint} [${i.resourceId}]`).join(', ')}) as ${itemsForOrigin[0].testAsPersonas?.join(', ') ?? 'alternate persona & anonymous'} to verify tenant isolation and submit a DeclarativeReplaySpec if unauthorized access succeeds.`,
          category: 'broken-access-control',
          priority: 92,
          targetAssetIds: [asset.id],
          skills: ['bola-idor-race', 'false-positive-elimination'],
          dependsOnFactIds: factIds,
          sourceOrigins: [origin],
          specialistProfile: 'bola-bfla-specialist',
        })
        bolaAutoSteps += 1
      }
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

    const prompt = chainPlannerPrompt({
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
      uncoveredEndpoints,
      dynamicStepBudget,
      budgetRemaining: {
        usd: Math.max(0, Number((afterRound.budgetUsd - afterRound.spentUsd).toFixed(4))),
        requests: afterRound.budgetRequests === 0
          ? 'unlimited'
          : Math.max(0, afterRound.budgetRequests - afterRound.spentRequests),
      },
    })

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
        if (!res.personaHandle) return
        const observedResources = extractPersonaResourcesFromExchange({
          origin: res.origin,
          method: res.method,
          pathAndQuery: res.pathAndQuery,
          personaHandle: res.personaHandle,
          status: res.status,
          mediaType: res.mediaType,
          body: res.body,
        })
        if (!observedResources.length) return

        // Always infer producer -> consumer edges in SQLite api_dependencies (hashed sample ID, never raw secret)
        try {
          const producerPath = normalizeEndpointTemplate(res.pathAndQuery.split('?')[0] || '/')
          const producerEp = this.storage.upsertEndpoint({
            runId: curRun.id,
            scopeRevision: curRun.scopeRevision,
            origin: res.origin,
            method: res.method.toUpperCase(),
            pathTemplate: producerPath,
            source: 'surface_probe',
          })
          const originEndpoints = this.storage.listEndpoints(curRun.id, { origin: res.origin })
          const basePrefix = producerPath.replace(/\/+$/, '')
          for (const item of observedResources) {
            const sampleHash = `sha256:${createHash('sha256').update(item.resourceId).digest('hex').slice(0, 16)}`
            for (const cand of originEndpoints) {
              if (cand.id === producerEp.id) continue
              const tmpl = cand.pathTemplate
              const extendsBase = basePrefix && basePrefix !== '/' &&
                tmpl.startsWith(`${basePrefix}/`) &&
                /(?::[a-zA-Z0-9_-]+|\{[a-zA-Z0-9_-]+\})/.test(tmpl.slice(basePrefix.length))
              const matchesKey = item.field && !item.field.startsWith('path:') &&
                (tmpl.includes(`:${item.field}`) || tmpl.includes(`{${item.field}}`))
              if (!extendsBase && !matchesKey) continue
              this.storage.recordApiDependency({
                runId: curRun.id,
                producerEndpointId: producerEp.id,
                consumerEndpointId: cand.id,
                resourceKey: item.field.replace(/^path:/, ''),
                sampleResourceIdHash: sampleHash,
                personaHandle: res.personaHandle,
              })
            }
          }
        } catch { /* best-effort dependency edge inference */ }

        if (curRun.capabilityTier < 2 || (grant.personas?.size ?? 0) < 2) return
        let seenSet = this.recordedPersonaResources.get(curRun.id)
        if (!seenSet) {
          seenSet = new Set<string>()
          this.recordedPersonaResources.set(curRun.id, seenSet)
        }
        for (const item of observedResources) {
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
          secrets: currentSecrets(),
        })

        // Priority #3: Auto-track persona_resource facts when Tier >= 2 and >= 2 personas are approved
        trackPersonaResources(curRun, res, saved.id)

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
            secrets: currentSecrets(),
          })
          trackPersonaResources(curRun, res, saved.id)
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
        return { count: summaries.length, summary: burst.summary, stagedPath, results: summaries }
      }

      const handlers: WorkerToolHandlers = {
        spillOutput: async (id, content, signal) => session.stage(`tool-output/${id}.txt`, content, signal),

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
              headers, body, persona: r.persona, followRedirects: r.followRedirects ?? false,
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
              secrets: currentSecrets(),
            })
            trackPersonaResources(curRun, res, saved.id)
            return {
              exchangeId: saved.id, status: res.status, durationMs: res.durationMs,
              bodySha256: res.bodySha256, bodyPreview: res.bodyPreview.slice(0, 800),
            }
          })
          const stagedPath = await session.stage(`exchanges/batch-${randomUUID().slice(0, 8)}.json`,
            JSON.stringify(summaries, null, 2), signal).catch(() => null)
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
                secrets: currentSecrets(),
              })
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
                  secrets: currentSecrets(),
                })
                trackPersonaResources(curRun, ex, saved.id)
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
                secrets: currentSecrets(),
              })
              trackPersonaResources(curRun, ex, saved.id)
              return saved.id
            },
          }, this.broker, grant, signal)

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
            param: args.paramName,
            paramLocation: args.paramLocation,
            jsonBody: args.body,
            baselineValue: args.baselineValue,
            persona: args.persona,
            headers: args.headers,
            ssrfParams: args.ssrfParams,
            resourceIds: args.resourceIds,
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
                secrets: currentSecrets(),
              })
              trackPersonaResources(curRun, ex, saved.id)
              return saved.id
            },
          }, this.broker, grant, this.canaryBroker, signal)

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

          const res = await runSafeTemplates({
            origin: cleanOrigin,
            techFingerprint: techFingerprint.length ? techFingerprint : undefined,
            templateIds: args.templateIds,
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
            secrets: currentSecrets(),
          })
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
          return this.canaryBroker.checkCanary(token, { storage: this.storage, runId: curRun.id })
        },

        mint_second_order_canary: async (args) => {
          const curRun = this.check(job)
          const cleanOrigin = this.parseOriginForRun(curRun, args.injectedOrigin)
          const marker = `gn2o_${randomUUID().replaceAll('-', '').slice(0, 8)}`
          const row = this.storage.insertSecondOrderCanary({
            runId: curRun.id,
            assignmentId: job.assignment.id,
            marker,
            injectedOrigin: cleanOrigin,
            injectedEndpoint: args.injectedEndpoint,
            injectedParam: args.injectedParam,
            injectedPersona: args.injectedPersona ?? null,
          })
          return { id: row.id, marker }
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
        },
        onTurn: turn => {
          this.storage.updateWorker(job.assignment.id, { turnsUsed: turn })
          this.storage.recordLlmSpend(run.id, { turns: 1 })
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
          secrets: currentSecrets(),
        })
        return saved.id
      },
    }
    const result = await verifyReplaySpec(verifyParams)

    const current = this.check(job)
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
        const canRefine =
          current.capabilityTier > 0 &&
          !this.storage.checkBudgetExceeded(current.id) &&
          privateModelProfiles(this.storage).length > 0 &&
          !alreadyQueuedRefine &&
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
          secrets: params.currentSecrets(),
        })
        params.onExchangeObserved?.(latest, ex, saved.id)
        return saved.id
      },
    })

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
        this.storage.updateProposedFinding(latestRun, findingRow.id, {
          replaySpecId: updatedSpec.id,
          sourceOrigins: mergedOrigins,
          verificationTier: null,
          finding: nextFindingPatch,
        })
      }
    }

    return {
      findingId: findingRow?.id,
      replaySpecId: updatedSpec.id,
      attemptCount: updatedSpec.attemptCount,
      status: findingRow && isAlreadyVerified ? findingRow.finding.status : finalStatus,
      verificationTier: findingRow && isAlreadyVerified
        ? (findingRow.verificationTier ?? undefined)
        : verificationTier,
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
      item.id !== run.reviewPlan?.goalMessageId && !item.content.startsWith('Steering hint:'))
    if (!next) return

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

    const result = await generateAndReviewPatch({
      runId: run.id,
      finding: hydratedFinding,
      repo,
      reposDir,
      backend: this.backend,
      modelProfiles: profiles,
      signal,
      secrets,
      onUsage: u => this.storage.recordLlmSpend(run.id, { usd: u.costUsd, tokens: u.inputTokens + u.outputTokens }),
    })

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
