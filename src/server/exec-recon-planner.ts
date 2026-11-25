import { randomUUID } from 'node:crypto'
import { existsSync, readdirSync, readFileSync, statSync } from 'node:fs'
import { extname, join, relative, sep } from 'node:path'
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
import { extractSpecDedupeFields, normalizeEndpointTemplate } from './dedupe.ts'
import { meetsBaseline, type EvidenceReview } from './evidence-checks.ts'
import {
  DET_LEAD_STEP_PRIORITY,
  DRY_ROUND_LIMIT,
  TIER_A_MAX_SEEDED_STEPS,
  TIER_A_STEP_PRIORITY,
  addFunnelCounts,
  applyCrownJewelStepBudget,
  buildBolaTestQueue,
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
  hardChainStepsCeiling,
  hostTierOrder,
  isDetLeadDispatchStep,
  nextPlannerDryRounds,
  passOneCoverage,
  permanentlyBlockedStepIds,
  plannerResponseSchema,
  plannerWaveDispatchCap,
  reinvestigationKey,
  selectUncoveredHighRiskEndpoints,
  stripJsonFences,
  templatesMentionedInText,
  threatModelResponseSchema,
  type BolaTestQueueItem,
  type DispatchFunnelCounts,
  type DispatchStopReason,
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
  createGraphCoordinator,
  type CoordinatorDeps,
  type CoordinatorEndpoint,
  type CoordinatorProgramGraph,
  type DispatchPlan,
  type GraphCoordinator,
} from './graph-coordinator.ts'
import type { LabRunner, LabTargetHandle } from './lab-runner.ts'
import {
  privateModelProfiles,
  resolveProfilePoolForRole,
  type ResolvedModelProfile,
} from './model-settings.ts'
import { resolveRunPersonas } from './persona-vault.ts'
import { runPhase0Recon } from './phase0-recon.ts'
import { applyDiscoveredSubdomainsToRun, discoverSubdomainsForOrigins } from './subdomain-discovery.ts'
import type { Phase0GraphwireExtras, ProbePlanRegistry } from './probe-plan.ts'
import type { CodeDataflowSlice, CodeToRuntimeHypothesis } from './program-graph.ts'
import type { NamedSecret } from './redact.ts'
import { responseReview } from './response-checks.ts'
import { availableReviewChecks, parseReviewPlan, reviewPlanPrompt, standardChecks } from './review-plan.ts'
import { findings, messages } from './schema.ts'
import { runVariantSweepForFinding } from './semantic-audit.ts'
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

export class ExecReconPlanner extends ExecServiceModule<ExecReconPlannerHost> {
  private readonly plannerEmptyRounds = new Map<string, number>()
  private readonly plannerDryRounds = new Map<string, number>()
  private readonly plannerCompletedAtLastRound = new Map<string, number>()
  private readonly plannerEvidenceFrontier = new Map<string, { confirmed: number; primitives: number }>()
  private readonly detLeadStepKeys = new Set<string>()
  private readonly detLeadGateRejected = new Set<string>()
  private readonly cappedLeadReported = new Set<string>()
  private readonly tierAStepKeys = new Set<string>()
  private get labRunner() { return this.host.labRunner }

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
        // Passive CT-log + live DNS subdomain discovery for public HTTPS origins only (skipped for local-lab/localhost).
        if (
          freshRun.sourceMode !== 'prepared' &&
          freshRun.capabilityTier > 0 &&
          this.storage.project(freshRun.projectId).environment === 'public'
        ) {
          try {
            const subResult = await discoverSubdomainsForOrigins([...approvedOrigins], {
              signal: task.controller.signal,
            })
            if (subResult.queriedApexes.length > 0) {
              const applied = applyDiscoveredSubdomainsToRun(this.storage, freshRun.id, subResult, approvedOrigins)
              if (applied.admitted.length > 0) {
                for (const cand of applied.admitted) {
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

      // 4. Priority #1: Dedicated Source-First Code Audit Phase BEFORE live HTTP investigation rounds
      let codeAuditStepsCreated = 0
      if (mountedRepos.length > 0 && freshRun.capabilityTier > 0 && profiles.length > 0 && this.host.authorize(job)) {
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
      }

      if (!this.host.authorize(job)) return

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
        this.storage.message(current.id, current.coordinatorId, 'guardian',
          nextPhase === 'investigation'
            ? deterministicMode
              ? `Threat model ranked ${finalEntries.length} hosts. No model profile is configured, so Guardian will run a bounded deterministic probe pass over discovered endpoints instead of agentic investigation.`
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
      const skipDirs = new Set(['node_modules', '.git', 'dist', 'build'])
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
            if (skipDirs.has(entry)) continue
            const full = join(dir, entry)
            let st
            try { st = statSync(full) } catch { continue }
            if (st.isDirectory()) { stack.push(full); continue }
            if (!st.isFile() || st.size > 256 * 1024 || !scanExt.has(extname(entry).toLowerCase())) continue
            const relFile = relative(repoRoot, full).split(sep).join('/')
            let content: string
            try { content = readFileSync(full, 'utf8') } catch { continue }
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
  alreadyConfirmedRefs(run: Run, limit = 10): AlreadyConfirmedRef[] {
    try {
      const rows = this.storage.db.select().from(findings).where(and(
        eq(findings.runId, run.id),
        eq(findings.goalRevision, run.goalRevision),
      )).all()
      const specById = new Map(this.storage.listReplaySpecs(run.id).map(spec => [spec.id, spec]))
      const refs: AlreadyConfirmedRef[] = []
      const seen = new Set<string>()
      for (const row of rows) {
        if (row.finding.status !== 'confirmed' && row.finding.status !== 'static_verified') continue
        const spec = row.replaySpecId ? specById.get(row.replaySpecId) : undefined
        const fields = spec ? extractSpecDedupeFields(spec.spec) : null
        const path = fields?.endpoint?.trim()
        if (!path) continue
        const method = fields?.method && fields.method !== 'ANY' ? fields.method : null
        const key = `${method ?? ''} ${path} ${fields?.param ?? ''} ${row.finding.cwe ?? ''}`
        if (seen.has(key)) continue
        seen.add(key)
        refs.push({
          origin: row.finding.origin,
          ...(method ? { method } : {}),
          path,
          ...(fields?.param ? { param: fields.param } : {}),
          ...(row.finding.cwe ? { cwe: row.finding.cwe } : {}),
          ...(row.finding.category ? { probeClass: row.finding.category } : {}),
        })
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
      const confirmedPaths = new Set(confirmed.map(ref => normalizeEndpointTemplate(ref.path)))
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
          if (confirmedPaths.has(normalizeEndpointTemplate(ep.pathTemplate))) continue
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
    return templatesMentionedInText(`${step.title} ${step.hypothesis}`)
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
    const confirmedPaths = new Set(
      this.alreadyConfirmedRefs(run, 100).map(ref => normalizeEndpointTemplate(ref.path)),
    )
    const coveredRoutes = new Set<string>()
    for (const step of existingSteps) {
      for (const route of this.stepMentionedRoutes(step)) coveredRoutes.add(route)
    }
    const candidates = selectUncoveredHighRiskEndpoints({
      endpoints,
      approvedOrigins,
      confirmedPaths,
      coveredRoutes,
      minRisk: 60,
      limit: cap,
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
   * A planner step that only names routes the deterministic floor already confirmed is a duplicate
   * dispatch, unless it declares a parent fact/step (that is an explicit chain/escalation).
   */
  stepRepeatsConfirmedWork(step: Pick<ChainStep, 'title' | 'hypothesis' | 'dependsOnFactIds' | 'dependsOnStepIds'>, confirmed: readonly AlreadyConfirmedRef[]): boolean {
    if ((step.dependsOnFactIds?.length ?? 0) > 0 || (step.dependsOnStepIds?.length ?? 0) > 0) return false
    const routes = this.stepMentionedRoutes(step)
    if (!routes.length) return false
    const confirmedPaths = new Set(confirmed.map(ref => normalizeEndpointTemplate(ref.path)))
    return routes.every(route => confirmedPaths.has(route))
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
  /** Program-Graph code leads that carry a dataflow slice (Tier-A white-box hypotheses). */
  tierALeadFacts(run: Pick<Run, 'id'>): Fact[] {
    return this.storage.listFacts(run.id, { includeTainted: false, limit: 200 })
      .filter(fact => {
        const data = fact.data
        if (data?.kind !== 'det_lead' || data.source !== 'program_graph') return false
        const slice = data.codeSlice as { hops?: unknown } | undefined
        return Boolean(slice && Array.isArray(slice.hops) && slice.hops.length > 0)
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
   * are the white-box 4-hop hypotheses; they must never wait behind generic class/route steps or a
   * dry-round stop. Idempotent per (route, class), bounded by {@link TIER_A_MAX_SEEDED_STEPS}.
   */
  queueTierALeadSteps(run: Run, approvedOrigins: ReadonlySet<string>, budget: number): number {
    const facts = this.tierALeadFacts(run)
    if (!facts.length) return 0
    const existing = this.storage.listChainSteps(run.id, run.goalRevision)
    const boundFactIds = new Set(existing.flatMap(step => step.dependsOnFactIds))
    let slots = Math.max(0, Math.min(TIER_A_MAX_SEEDED_STEPS, budget - existing.length))
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
    const confirmedKeys = new Set(this.alreadyConfirmedRefs(run, 40).map(ref =>
      `${normalizeEndpointTemplate(ref.path)}|${confirmedCategoryFamily(ref.probeClass ?? '')}`))
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
      const routeKey = `${normalizeEndpointTemplate(endpoint)}|${confirmedCategoryFamily(category)}`
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
    return `Invoke guardian_verify(${tool}) against this sink (control vs variant on the exact route above), or record_coverage(proofGapReason="<status|cannot_build_spec>") with the blocking HTTP status. A bare "leaning true" without either is rejected at settlement.`
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
      const routes = this.storage.listEndpoints(input.run.id, { orderBy: 'risk', limit: 40 })
        .filter(ep => input.targetOrigins.includes(ep.origin))
        .slice(0, 6)
        .map(ep => ({
          method: ep.method,
          path: ep.pathTemplate,
          riskScore: ep.riskScore,
        }))
      const samples = this.storage.listResourceSamples(input.run.id)
        .filter(sample => input.targetOrigins.includes(sample.origin))
      const personas = input.personas.map(persona => ({
        handle: persona.handle,
        role: persona.roleLabel,
        harvestedIds: [...new Set(samples.filter(s => s.ownerPersona === persona.handle).map(s => s.resourceId))].slice(0, 4),
      }))
      const parentDetLead = input.detLeads.find(lead =>
        input.parentFacts.some(f => f.data?.kind === 'det_lead' && f.id === lead.exchangeId) ||
        (Boolean(lead.endpoint) && input.targetOrigins.includes(origin)),
      )
      const missionKind = this.missionKindForStep(input.step, Boolean(parentDetLead))
      // v7 whitebox hop: the persisted slice for this assignment's route reaches the brief.
      // Compact by default; only chain / 4-hop assignments pay for the expanded slice.
      const codeSlice = this.host.codeSliceForAssignment(input.run, input.step, input.parentFacts)
      const codeExpansion: 'compact' | 'full' = missionKind === 'chain_step_2' ||
        input.step.dependsOnStepIds.length > 0 ||
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
      const text = buildAssignmentBrief({
        missionKind,
        origin,
        routes,
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
        // One explicit proof obligation for a white-box assignment: exact mounted route, declared
        // parameter names, the middleware verdict and the sink chain. Names only; the specialist
        // still has to build and verify the spec through the normal replay path.
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
                chain: codeSlice.hops.slice(0, 6).map(hop => hop.at).join('→'),
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
  persistDispatchPlan(run: Run, plan: DispatchPlan, factIds: ReadonlySet<string>, detLeadFactIds: ReadonlySet<string> = new Set()): Pick<DispatchFunnelCounts, 'planned' | 'enqueued' | 'filteredDedupe' | 'filteredAlreadyConfirmed' | 'filteredNoAsset'> {
    const existing = this.storage.listChainSteps(run.id, run.goalRevision)
    const titles = new Set(existing.map(step => step.title.trim().toLowerCase()))
    const confirmed = this.alreadyConfirmedRefs(run, 40)
    const counts = { planned: plan.plan.length, enqueued: 0, filteredDedupe: 0, filteredAlreadyConfirmed: 0, filteredNoAsset: 0 }
    for (const step of plan.plan) {
      const title = compactChainTitle(step.hypothesis)
      const key = title.toLowerCase()
      if (titles.has(key)) { counts.filteredDedupe += 1; continue }
      const boundFactIds = step.parentEvidenceIds.filter(id => factIds.has(id))
      // Tool-dispatched hypotheses obey the same no-re-dispatch rule as planner JSON steps.
      if (this.stepRepeatsConfirmedWork({
        title, hypothesis: step.hypothesis, dependsOnFactIds: boundFactIds, dependsOnStepIds: [],
      }, confirmed)) { counts.filteredAlreadyConfirmed += 1; continue }
      const assetIds = run.candidates
        .filter(candidate => step.origins.includes(candidate.origin) && run.approved.includes(candidate.id))
        .map(candidate => candidate.id)
      if (!assetIds.length) { counts.filteredNoAsset += 1; continue }
      const category = step.probeClass === 'stored_xss' ? 'cors-client-side'
        : step.probeClass === 'authz_replay' || step.probeClass === 'auth_bypass' ? 'broken-access-control'
          : step.probeClass === 'ssrf' ? 'injection-input' : 'broken-access-control'
      // F2: lead-bound coordinator dispatches obey the same low-priority rule as planner steps.
      const leadBound = boundFactIds.some(id => detLeadFactIds.has(id)) ||
        isDetLeadDispatchStep({ title, hypothesis: step.hypothesis })
      const tierABound = boundFactIds.some(id => this.host.tierAFactIds.has(id))
      this.storage.addChainStep(run, {
        title: title.slice(0, 200),
        hypothesis: step.hypothesis,
        category,
        priority: tierABound ? TIER_A_STEP_PRIORITY : leadBound ? Math.min(step.priority, DET_LEAD_STEP_PRIORITY) : step.priority,
        targetAssetIds: assetIds,
        skills: step.skills,
        dependsOnFactIds: boundFactIds,
        sourceOrigins: step.origins,
        specialistProfile: routeStepToSpecialist({ title, hypothesis: step.hypothesis, category, skills: step.skills }),
      })
      titles.add(key)
      counts.enqueued += 1
    }
    return counts
  }


  /**
   * Explicit chaining round: derive typed primitives from the untruncated store (same-origin and
   * cross-origin), plan 2–3 hop hypotheses and dispatch each with parent evidence + capabilities.
   */
  dispatchChainRound(run: Run, coordinator: GraphCoordinator, budget: number, factIds: ReadonlySet<string>, funnel?: DispatchFunnelCounts): number {
    const existing = this.storage.listChainSteps(run.id, run.goalRevision)
    const remaining = Math.max(0, budget - existing.length)
    if (remaining <= 0) return 0
    const hypotheses = coordinator.planChainRound({ maxHops: 3, limit: Math.min(12, remaining) })
    if (!hypotheses.length) return 0
    const plan = coordinator.dispatchInvestigations(chainHypothesisDispatchSteps(hypotheses), { maxSteps: remaining })
    const counts = this.persistDispatchPlan(run, plan, factIds)
    if (funnel) addFunnelCounts(funnel, counts)
    this.storage.event(run.id, 'chain.round', `Chain round dispatched ${counts.enqueued} hypothesis(es) with parent evidence.`, {
      hypotheses: hypotheses.length, dispatched: counts.enqueued, rejected: plan.rejected.length,
      crossOrigin: hypotheses.filter(hypothesis => hypothesis.scope === 'cross_origin').length,
      primitives: [...new Set(hypotheses.flatMap(hypothesis => hypothesis.primitiveKinds))],
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

    // v6 Phase 1: prioritized deterministic leads become upgrade assignments before the planner
    // runs, so the agentic lane never idles on confirmed routes and never loses a floor signal.
    let detLeadSteps = 0
    try {
      detLeadSteps = this.queueDetLeadUpgradeSteps(fresh, this.host.approvedOriginsSet(fresh), dynamicStepBudget)
    } catch { /* lead queueing is additive */ }
    funnel.planned += detLeadSteps
    funnel.enqueued += detLeadSteps

    const approvedOrigins = this.host.approvedOriginsSet(updated)
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

    // Chain round after the floor + first planner round. Deterministic hypotheses over the full
    // store dispatch *before* the LLM turn, so a planner failure can never leave an empty window.
    let chainSteps = 0
    if (roundNo >= 2) {
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

    // Priority #3: bounded cross-persona BOLA/IDOR matrix per discovered resource type.
    let bolaAutoSteps = 0
    if (updated.capabilityTier >= 2 && personas.length >= 2 && allSteps.length < dynamicStepBudget) {
      const typeGroups = new Map<string, BolaTestQueueItem[]>()
      for (const item of buildBolaTestQueue(allUntaintedFacts, personas, approvedOrigins, this.storage.listResourceSamples(run.id))) {
        const key = `${item.origin}\u0000${item.resourceKey}`
        typeGroups.set(key, [...(typeGroups.get(key) ?? []), item])
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
        const variants = [...new Set(itemsForOrigin.flatMap(item => item.variants.map(variant =>
          `${variant.method} ${variant.endpoint}${variant.destructive ? ' (Tier 3 only)' : ''}`)))].slice(0, 8)
        this.storage.addChainStep(updated, {
          title: `Cross-persona BOLA/IDOR matrix · ${new URL(origin).hostname} · resource:${resourceKey}`,
          hypothesis: `Replay ${itemsForOrigin.length} ${resourceKey} resource(s) owned by ${itemsForOrigin[0].ownerPersona} (e.g. ${itemsForOrigin.map(item => `${item.endpoint} [${item.resourceId}]`).join(', ')}) as ${itemsForOrigin[0].testAsPersonas?.join(', ') ?? 'alternate persona & anonymous'} using bounded consumer item variants: ${variants.join(', ')}. Verify tenant isolation with GET first; use benign PUT/PATCH field deltas only where reversible; DELETE stays Tier 3/local-lab. Submit a DeclarativeReplaySpec if unauthorized access succeeds.`,
          category: 'broken-access-control',
          priority: 92,
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

    // Auto-enqueue verification for each new cross-persona or active-HTML second-order surface.
    let secondOrderAutoSteps = 0
    for (const fact of allUntaintedFacts.filter(candidate =>
      candidate.data?.subkind === 'second_order_surface' && updated.capabilityTier >= 1).slice(0, 20)) {
      if (allSteps.length + bolaAutoSteps + secondOrderAutoSteps >= dynamicStepBudget) break
      const marker = typeof fact.data?.marker === 'string' ? fact.data.marker : ''
      const surfacedOrigin = typeof fact.data?.surfacedOrigin === 'string' ? fact.data.surfacedOrigin : fact.origin
      const surfacedEndpoint = typeof fact.data?.surfacedEndpoint === 'string' ? fact.data.surfacedEndpoint : '/'
      const surfacedMediaType = typeof fact.data?.surfacedMediaType === 'string' ? fact.data.surfacedMediaType : ''
      const crossPersona = fact.data?.crossPersona === true
      const activeHtml = /html/i.test(surfacedMediaType)
      if (!marker || !approvedOrigins.has(surfacedOrigin) || (!crossPersona && !activeHtml)) continue
      if (allSteps.some(step => (step.dependsOnFactIds ?? []).includes(fact.id) ||
        (step.title.includes(marker) && step.sourceOrigins.includes(surfacedOrigin)))) continue
      const asset = updated.candidates.find(candidate => candidate.origin === surfacedOrigin && updated.approved.includes(candidate.id))
      if (!asset) continue
      this.storage.addChainStep(updated, {
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
    let addedCount = detLeadSteps + chainSteps + bolaAutoSteps + secondOrderAutoSteps + toolDispatched

    if (parsedPlanner?.success) {
      for (const cancelId of parsedPlanner.data.cancelStepIds) {
        const target = existingSteps.find(step => step.id === cancelId)
        if (target && ['pending', 'ready'].includes(target.status)) this.storage.updateChainStep(target.id, { status: 'canceled' })
      }
      const confirmedForDispatch = this.alreadyConfirmedRefs(currentRun, 40)
      const remainingSlots = Math.max(0, dynamicStepBudget - existingSteps.length)
      const candidateSteps = parsedPlanner.data.newSteps
        .map(step => ({ ...step, origins: step.origins.filter(origin => currentApproved.has(origin)) }))
      const budgetedNewSteps = applyCrownJewelStepBudget(
        candidateSteps,
        computeHostTiers([...currentApproved], this.storage.latestThreatModel(run.id, currentRun.goalRevision)?.entries),
        existingSteps,
        remainingSlots,
      )
      const dispatchableNewSteps = budgetedNewSteps.filter(step => !this.stepRepeatsConfirmedWork(step, confirmedForDispatch))
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
      funnel.filteredAlreadyConfirmed += Math.max(0, budgetedNewSteps.length - dispatchableNewSteps.length)
      // Dependency sanitisation: a planner-emitted id that does not exist can never resolve, and
      // `refreshReadyChainSteps` requires every parent fact/step to exist. Drop unknown ids at
      // enqueue so planned work cannot be stranded as a permanently `pending` step.
      const liveFactIds = new Set(factIds)
      const liveStepIds = new Set(existingSteps.map(step => step.id))
      for (const step of dispatchableNewSteps) {
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
          const verdict = this.host.reinvestigationGuardFor(run.id).record(guardKey, unlocked)
          if (!verdict.allowed) {
            this.host.noteCappedReinvestigation(run, guardKey, verdict.count)
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
        funnel.enqueued += 1
        addedCount += 1
      }
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
    const dryRounds = nextPlannerDryRounds({
      roundNo,
      previousDryRounds: this.plannerDryRounds.get(run.id) ?? 0,
      newRuntimeConfirmed,
      newChainPrimitives,
      completedInvestigations,
      previousCompletedInvestigations,
    })
    this.plannerDryRounds.set(run.id, dryRounds)
    const queueDrained = this.host.highPriorityQueueEmpty({
      id: run.id,
      goalRevision: this.storage.run(run.id).goalRevision,
    })
    this.storage.event(
      run.id,
      'planner.dry_rounds',
      `Planner dry-round ${dryRounds}/${DRY_ROUND_LIMIT}: ${newRuntimeConfirmed} new confirmed, ${newChainPrimitives} new chain primitive(s)${queueDrained ? '; high-priority queue empty' : ''}.`,
      {
        consecutiveDryRounds: dryRounds,
        limit: DRY_ROUND_LIMIT,
        newRuntimeConfirmed,
        newChainPrimitives,
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
        this.storage.message(run.id, run.coordinatorId, 'guardian',
          'The coordinator could not reach the model. Review the workflow for current progress.', next.id)
        this.storage.event(run.id, 'coordinator.unavailable', 'The coordinator could not complete its reply.')
      })
    }).finally(() => {
      this.host.coordinator.delete(run.id)
    })
  }

}
