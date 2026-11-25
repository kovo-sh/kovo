import { randomUUID } from 'node:crypto'
import { and, eq } from 'drizzle-orm'
import {
  maxInlineVerifyRetries,
  type CheckCoverage,
  type CodeLocation,
} from '../domain.ts'
import { declarativeReplaySpecSchema, replaySpecOrigins, type DeclarativeReplaySpec } from '../replay-spec.ts'
import {
  KOVO_VERIFY_TS_ONLY_ERROR,
  createBoardTools,
  filterHandlersForSpecialist,
  injectBoardTurnInstructions,
  listSkills,
  loadSkill,
  parseNegativeEdgeGapReason,
  resolveSpecialistProfile,
  routeStepToSpecialist,
  runAgentSession,
  selectPreInjectionSkills,
  summarizeKovoVerifyOutcome,
  wallClockSettlementMs,
  workerInvestigationPrompt,
  type GapValidationEvent,
  type KovoVerifyArgs,
  type KovoVerifyRuntime,
  type ProofObligationEvent,
  type WorkerToolHandlers,
} from './agent-session.ts'
import type { AgentTrace } from './agent-trace.ts'
import {
  BrokerDenied,
  type BrokerExchangeResult,
  type Grant,
} from './broker.ts'
import { DERIVED_CAPABILITY_HANDLE_RE, type NegativeEdge } from './capability-ledger.ts'
import { queryCves } from './cve-broker.ts'
import { vaultScrubDescriptors, type DerivedCapabilityVault } from './derived-custody.ts'
import {
  createProviderLlmCall,
  evaluateSubmissionDedupe,
  extractSpecDedupeFields,
  normalizeEndpointTemplate,
} from './dedupe.ts'
import type { ExecBoardManager } from './exec-board.ts'
import {
  PROVIDER_STALL_TURN_MS,
  ProviderNoTokenWatchdog,
  buildBolaTestQueue,
  extractAssignedTargetRoutes,
  isMultiHopChainStep,
  percentile,
  providerStallAbortMs,
  resolveWorkerSettlementMs,
  secretGenerationFingerprint,
  selectAssignmentBolaQueueItems,
  shouldRetryStalledAssignment,
  type AssignmentBudget,
} from './exec-dispatch.ts'
import {
  ExecServiceModule,
  buildChainFindingBase,
  buildExistingFindingRefs,
  createExchangeRecorder,
  findFindingRow,
  llmRunHooks,
  publicPersonasFromGrant,
  retryLimitExceededFeedback,
  type ExecActiveJob,
  type ExecCoreServices,
} from './exec-exchange.ts'
import { DETERMINISTIC_PARAM_HINT_RE } from './exec-floor-lane.ts'
import type { ExecReconPlanner } from './exec-recon-planner.ts'
import type { ExecVerifier } from './exec-verify.ts'
import { resolveProfilePoolForRole, type ResolvedModelProfile } from './model-settings.ts'
import type { PersonaAuthManager, PersonaSessionClone } from './persona-auth.ts'
import { crawlStateGraph } from './phase0-recon.ts'
import { resolveProfileNoTokenWatchdogMs } from './provider-stream.ts'
import { BudgetExceededError } from './provider.ts'
import { redact, type NamedSecret } from './redact.ts'
import { brokerExchanges } from './schema.ts'
import type {
  Assignment,
  BoardMessageRow,
  ChainStep,
  Run,
} from './store.ts'
import { probeDifferential, probeSurface } from './surface-engine.ts'
import type { WorkerBackend } from './worker-backend.ts'

type Active = ExecActiveJob

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
    filename: string,
    payload: unknown,
    signal: AbortSignal,
    secretsList?: readonly NamedSecret[],
  ) => Promise<{ evidenceId: string; stagedPath: string | null }>
}

export interface ExecWorkerHost extends ExecCoreServices {
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
    },
  ) {
    return {
      spillOutput: async (id: string, content: string, sig: AbortSignal) => session.stage(`tool-output/${id}.txt`, content, sig),
      derive_evidence: async ({ command, outputs, timeoutMs }: Parameters<NonNullable<WorkerToolHandlers['derive_evidence']>>[0], sig: AbortSignal) => {
        const curRun = this.host.check(job)
        const res = await session.exec(command, outputs ?? ['result.txt'], sig, timeoutMs ?? 60_000)
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
        const entry = this.storage.upsertCoverageEntry(curRun, job.assignment.id, {
          origin: cleanOrigin,
          category: args.category,
          status: args.status,
          summary: args.summary,
          enforcingControl: ext.enforcingControl,
          proofGapReason: args.status === 'needs_follow_up' ? (ext.proofGapReason?.trim() || args.summary) : ext.proofGapReason,
          linkedFindingId: ext.linkedFindingId,
        })
        const neg = this.recordNegativeEdgeCoverage(curRun.id, {
          origin: cleanOrigin,
          category: args.category,
          summary: args.summary,
          proofGapReason: ext.proofGapReason,
          route: ext.route,
          enforcingControl: ext.enforcingControl,
          preconditionCapIds: ext.preconditionCapIds,
          branchKey: ext.branchKey,
          hypothesisClass: ext.hypothesisClass,
          exchangeIds: ext.exchangeIds,
          assignmentId: job.assignment.id,
        })
        return {
          id: entry.id,
          origin: entry.origin,
          category: entry.category,
          status: entry.status,
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

  handleInvestigationWorkerError(
    run: Run,
    job: Active,
    step: ChainStep,
    resolvedSpecialistId: string,
    budget: AssignmentBudget,
    error: unknown,
  ): void {
    const assignment = job.assignment
    if (error instanceof BudgetExceededError) {
      this.storage.checkBudgetExceeded(run.id)
      return
    }
    // Provider-stream stall: aborting the assignment's provider call frees the slot without
    // spending the rest of its wall budget. One retry is allowed per assignment.
    if (job.stallAbort) {
      const attempt = job.assignment.attempt
      if (shouldRetryStalledAssignment(attempt)) {
        this.host.providerStallRetriesByRun.set(run.id, (this.host.providerStallRetriesByRun.get(run.id) ?? 0) + 1)
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
            assignmentId: assignment.id, stepId: step.id, attempt: attempt + 1,
          })
        })
        return
      }
      this.storage.transaction(() => {
        this.storage.updateWorker(assignment.id, {
          status: 'failed',
          outcome: 'Provider stream stalled after retry; slot released.',
          attempt: attempt + 1,
          lease: null,
          leaseExpiresAt: null,
        })
        this.storage.updateChainStep(step.id, { status: 'complete', assignedWorkerId: assignment.id })
        this.storage.event(run.id, 'worker.stall_failed', `${step.title} provider stream stalled twice; assignment closed without consuming the wall cap.`, {
          assignmentId: assignment.id, stepId: step.id,
        })
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
        this.storage.updateChainStep(step.id, { status: 'complete', assignedWorkerId: assignment.id })
        this.storage.event(run.id, 'worker.wall_clock_rotated', `${step.title} rotated at wall-clock budget (${budget.wallClockMs}ms); slot released.`, {
          assignmentId: assignment.id, stepId: step.id, specialistProfile: resolvedSpecialistId,
          wallClockMs: budget.wallClockMs, boundedRotation: true, preSession: true,
        })
      })
      return
    }
    if (!this.host.authorize(job) || job.controller.signal.aborted) return
    const msg = redact(error instanceof Error ? error.message : String(error)).slice(0, 400)
    this.storage.transaction(() => {
      this.storage.updateWorker(assignment.id, {
        status: 'failed', outcome: msg, lease: null, leaseExpiresAt: null, attempt: assignment.attempt + 1,
      })
      this.storage.updateChainStep(step.id, { status: 'complete', assignedWorkerId: assignment.id })
      this.storage.event(run.id, 'worker.failed', `${step.title} failed: ${msg}`, { assignmentId: assignment.id, stepId: step.id })
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
    const permittedAtAdmission = this.host.approvedOriginsSet(run)
    const { grant, secrets, currentSecrets } = this.host.buildGrant(job, run, permittedAtAdmission)

    // Warm-pool policy: run identity + persona credential generation. A rotation (or a new run or
    // tenant) retires the pool instead of handing an older container to this assignment.
    const generations = (grant.personas ? [...grant.personas.keys()] : []).sort().map(handle =>
      `${handle}:${this.host.personaAuth.sessions.generation(handle)}`)
    const secretEpoch = secretGenerationFingerprint(generations)
    const priorEpoch = this.host.warmSecretEpochByRun.get(run.id)
    if (priorEpoch !== undefined && priorEpoch !== secretEpoch) {
      this.host.warmPoolPolicyRotationsByRun.set(run.id, (this.host.warmPoolPolicyRotationsByRun.get(run.id) ?? 0) + 1)
      this.host.safeEvent(run.id, 'worker.warm_pool_rotated', 'Credential generation changed; rebuilding idle warm containers.', {
        assignmentId: job.assignment.id, stepId: step.id, previous: priorEpoch, next: secretEpoch,
      })
    }
    const { reposDir, mountedRepos } = this.host.projectReposMount(run.projectId)
    this.host.warmSecretEpochByRun.set(run.id, secretEpoch)
    try {
      this.backend.setWarmPoolPolicy?.(
        `${run.id}:${secretEpoch}`,
        reposDir ? { reposDir } : undefined,
      )
    } catch { /* pooling is best-effort */ }

    // Open ONE persistent air-gapped container for the entire intent.
    // Arm a pre-session wall-clock guard so a stalled openSession/staging call can never hold a
    // slot past budget.wallClockMs; disarmed once runAgentSession takes over the exact timer.
    const startedAt = Date.now()
    let preSessionTimer: NodeJS.Timeout | undefined = setTimeout(() => {
      preSessionTimer = undefined
      if (job.controller.signal.aborted) return
      this.host.wallClockRotatedAssignments.add(job.assignment.id)
      job.controller.abort(new Error(`Pre-session wall-clock deadline reached (${budget.wallClockMs}ms).`))
    }, budget.wallClockMs)
    preSessionTimer.unref?.()
    const clearPreSessionTimer = () => {
      if (preSessionTimer) { clearTimeout(preSessionTimer); preSessionTimer = undefined }
    }
    let session: Awaited<ReturnType<WorkerBackend['openSession']>>
    try {
      session = await this.backend.openSession(
        job.assignment.id,
        job.controller.signal,
        reposDir ? { reposDir } : undefined,
      )
    } catch (err) {
      clearPreSessionTimer()
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
    const noTokenMs = resolveProfileNoTokenWatchdogMs(primaryProfile)
    const noTokenThresholdMs = () => noTokenMs
    const stallAbortMs = () => providerStallAbortMs(percentile(turnLatencies, 50), turnLatencies.length)
    const stallWatchdog = new ProviderNoTokenWatchdog({
      thresholdMs: noTokenThresholdMs,
      onStall: ({ turn, idleMs, thresholdMs }) => {
        if (generationStartedAt === undefined) return
        generationStartedAt = undefined
        job.stallAbort = true
        this.host.providerStallTimeoutsByRun.set(run.id, (this.host.providerStallTimeoutsByRun.get(run.id) ?? 0) + 1)
        this.host.providerStallTurnsByRun.set(run.id, (this.host.providerStallTurnsByRun.get(run.id) ?? 0) + 1)
        const previousThresholdMs = stallAbortMs()
        const wallSavedMs = Math.max(0, previousThresholdMs - idleMs)
        this.host.providerStallWallSavedByRun.set(run.id, (this.host.providerStallWallSavedByRun.get(run.id) ?? 0) + wallSavedMs)
        this.host.safeEvent(run.id, 'worker.provider_stall', `Provider stream stalled on turn ${turn} (${Math.round(idleMs / 1000)}s without a token); aborting to free the slot.`, {
          assignmentId: job.assignment.id, stepId: step.id, turn, elapsedMs: idleMs, thresholdMs,
          previousThresholdMs, wallSavedMs, stallAbortMs: stallAbortMs(), wallClockMs: budget.wallClockMs,
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
      const stalls = this.host.providerStallTurnsByRun.get(run.id) ?? 0
      if (ms > PROVIDER_STALL_TURN_MS) this.host.providerStallTurnsByRun.set(run.id, stalls + 1)
    }

    const baselineCapIds = new Set(
      this.storage.capabilityLedger(run.id).listCapabilities().map(c => c.capId),
    )
    const sessionSealedCapHandles: string[] = []
    let confirmedDuringAssignment = false

    try {
      const stagedSpecs = await this.host.stageProjectSpecs(run.projectId, session, job.controller.signal)

      const parentFacts = step.dependsOnFactIds.length
        ? this.storage.listFacts(run.id, { includeTainted: false, limit: 200 })
            .filter(f => step.dependsOnFactIds.includes(f.id) && permittedAtAdmission.has(f.origin))
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
          try { this.host.board.wakeBoardMember(this.storage.run(run.id), target, message) } catch { /* advisory */ }
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
      const stageJsonArtifact = async (
        curRun: Run,
        kind: 'dns' | 'tls' | 'browser' | 'surface' | 'ws',
        title: string,
        filename: string,
        payload: unknown,
        signal: AbortSignal,
        secretsList: readonly NamedSecret[] = currentSecrets(),
      ) => {
        const serialized = JSON.stringify(payload, null, 2)
        const ev = this.storage.addArtifact(curRun, job.assignment, kind, title, serialized, undefined, secretsList)
        const stagedPath = await session.stage(filename.replace('{id}', ev.id.slice(0, 8)), serialized, signal).catch(() => null)
        return { evidenceId: ev.id, stagedPath }
      }
      const verifyInline = (spec: DeclarativeReplaySpec, findingId?: string, replaySpecId?: string) =>
        this.host.executeInlineVerification({
          job, grant, currentSecrets, reposDir, spec, findingId, replaySpecId, onExchangeObserved: trackPersonaResources,
        })
      const makeTrackedExchangeRecorder = (curRun: Run) =>
        createExchangeRecorder(this.storage, () => curRun, job.assignment.id, currentSecrets, {
          onSaved: (r, e, id) => {
            trackPersonaResources(r, e, id)
            this.host.scanSecondOrderExchange(r, job.assignment.id, e, id)
          },
        })

      const sharedHandlers = this.buildSharedSessionHandlers(job, session, currentSecrets, {
        offlineScriptLabel: 'Offline {runtime} script',
        deriveEvidenceTitle: 'Derived evidence',
        onFactRecorded: curRun => {
          boardTools.noteEvidence()
          this.host.schedulePlanner(curRun.id)
        },
      })
      const transportHandlers = this.host.buildBrokeredTransportHandlers({
        job,
        step,
        session,
        grant,
        currentSecrets,
        boardTools,
        sharedHandlers,
        trackPersonaResources,
        prepareBudgetedProbe,
        stageJsonArtifact,
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
              secrets: currentSecrets(),
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

          const requestedTemplate = normalizeEndpointTemplate(args.pathAndQuery.split('?')[0] || '/')
          const originEndpoints = this.storage.listEndpoints(curRun.id, { origin: cleanOrigin })
          const targetEndpoint = originEndpoints.find(ep => ep.pathTemplate === requestedTemplate && (!args.method || ep.method === args.method.toUpperCase()))
            ?? originEndpoints.find(ep => ep.pathTemplate === requestedTemplate)
          const targetParams = targetEndpoint ? this.storage.listEndpointParams(curRun.id, targetEndpoint.id) : []
          const injectableParams = targetParams.filter(p => ['query', 'json', 'form', 'path', 'graphql_var'].includes(p.location) && !p.isCsrf)
          const preferredParam = [...injectableParams].sort((a, b) =>
            Number(DETERMINISTIC_PARAM_HINT_RE.test(b.name)) - Number(DETERMINISTIC_PARAM_HINT_RE.test(a.name)) ||
            Number(a.isObjectId) - Number(b.isObjectId),
          )[0]
          const resolvedParamName = args.paramName ?? preferredParam?.name
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
          const resolvedSsrfParams = args.ssrfParams?.length
            ? args.ssrfParams
            : injectableParams
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
              id: ex.id, origin: ex.origin, method: ex.method, pathAndQuery: ex.pathAndQuery,
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
            ...ex,
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
          const chainTags = step.skills.filter(skill => skill.startsWith('chain:')).map(skill => skill.slice('chain:'.length))
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
              ...(!isAlreadyVerified && args.severity ? { severity: args.severity } : {}),
              ...(!isAlreadyVerified && args.replaySpec ? { status: 'pending' as const } : {}),
              ...(extraEvidenceIds.length ? { evidenceIds: extraEvidenceIds } : {}),
            },
          })

          const shouldVerifyNow = Boolean(parsedUpdatedSpec && (args.verifyNow ?? true) && !isAlreadyVerified)
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

        verify_replay_spec: async (args) => {
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
        },

        ...(this.host.verifier.backendSupportsVerifyScript() ? {
          kovo_verify: async (args: KovoVerifyArgs) => {
            const curRun = this.host.check(job)
            const rawRuntime = args.runtime as string | undefined
            if (
              (rawRuntime !== undefined && rawRuntime !== 'ts')
              || (typeof args.scriptPath === 'string' && /\.py$/i.test(args.scriptPath.trim()))
            ) {
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
            const approved = this.host.approvedOriginsSet(curRun)
            const runVault = this.host.capabilityVaultFor(curRun.id)
            const proof = await this.host.verifier.runAgentScriptProof({
              script,
              runtime,
              ...(args.title?.trim() ? { title: args.title.trim() } : {}),
              grant,
              runId: curRun.id,
              assignmentId: job.assignment.id,
              targetOrigins: [...approved].slice(0, 8),
              signal: job.controller.signal,
              capabilityVault: runVault,
              ...(args.timeoutMs ? { timeoutMs: args.timeoutMs } : {}),
            })
            const ledgerSync = this.host.verifier.syncVerifyArtifactsToLedger({
              runId: curRun.id,
              proof,
              defaultOrigin: [...approved][0] ?? '',
            })
            for (const sealed of ledgerSync.sealedCapabilities) {
              if (sealed.handle && !sessionSealedCapHandles.includes(sealed.handle)) {
                sessionSealedCapHandles.push(sealed.handle)
              }
            }
            if (ledgerSync.newCapabilityCount > 0 || ledgerSync.newEdgeCount > 0) {
              this.host.schedulePlanner(curRun.id)
            }
            const v8Meta = {
              ...(ledgerSync.sealedCapabilities.length ? { sealedCapabilities: ledgerSync.sealedCapabilities } : {}),
              ...(ledgerSync.verifiedHops.length ? { verifiedHops: ledgerSync.verifiedHops } : {}),
              ...(proof.compositeReceipt ? {
                compositeReceipt: {
                  chainId: proof.compositeReceipt.receipt.chainId,
                  terminalVulnClass: proof.compositeReceipt.receipt.terminalVulnClass,
                  hopCount: proof.compositeReceipt.receipt.hops.length,
                  replayMode: proof.compositeReceipt.receipt.replayMode,
                  confirmed: proof.compositeReceipt.verification.confirmed,
                  ...(proof.compositeReceipt.verification.failedStage
                    ? { failedStage: proof.compositeReceipt.verification.failedStage }
                    : {}),
                  verifiedEdgeCount: proof.compositeReceipt.verification.verifiedEdges.filter(e => e.verified).length,
                },
              } : {}),
            }
            if (!proof.verdict.confirmed) {
              return summarizeKovoVerifyOutcome({ ...proof.verdict, ...v8Meta })
            }
            confirmedDuringAssignment = true
            const persisted = this.host.persistAgentScriptProof({
              run: curRun,
              assignment: job.assignment,
              script,
              runtime,
              title: args.title?.trim() || proof.claimTitle || undefined,
              proof,
              secrets: [...currentSecrets(), ...vaultScrubDescriptors(runVault)],
            })
            this.host.schedulePlanner(curRun.id)
            return summarizeKovoVerifyOutcome({
              ...proof.verdict,
              ...v8Meta,
              detail: `${proof.verdict.detail} Finding ${persisted.findingId} cites ${persisted.receiptId ? `ProofReceipt ${persisted.receiptId}` : 'the persisted script proof'} (replay spec ${persisted.replaySpecId}).`
                .trim(),
            })
          },
        } : {}),

        suggest_candidate_host: async ({ origin, source, thirdParty }) => {
          const curRun = this.host.check(job)
          const clean = this.host.parseOriginForRun(curRun, origin)
          return this.storage.suggestCandidateHost(curRun, clean, source, Boolean(thirdParty))
        },

        complete_intent: async (completion) => ({ recorded: true, status: completion.status }),
      }

      const personasPub = publicPersonasFromGrant(grant)

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
      const scopedHandlers = filterHandlersForSpecialist(handlers, specialistConfig)

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
        targetOrigins,
        personas: personasPub,
        parentFacts,
        confirmed: confirmedRefs,
        detLeads,
        maxTurns: job.assignment.maxTurns,
      })
      const hasHopCheckpoint = Boolean(assignmentBrief && /\b(?:hopCheckpoint|cap:hop_|doNotRediscover)\b/.test(assignmentBrief))
      const isMultiHopStep = hasHopCheckpoint || isMultiHopChainStep(step)
      const effectiveSettlementMs = budget.wallClockSettlementMs
        ?? (isMultiHopStep ? resolveWorkerSettlementMs(budget.wallClockMs, true) : wallClockSettlementMs(budget.wallClockMs))
      const preInjectedSkills = selectPreInjectionSkills({
        profileSkills: specialistConfig.skills,
        techTags: [...new Set(techTags)],
        ...(sinkKind ? { sinkKind } : {}),
        category: step.category,
        title: step.title,
        hypothesis: step.hypothesis,
        ...(hasHopCheckpoint ? { hasHopCheckpoint: true } : {}),
        ...(isMultiHopStep ? { multiHop: true, hopDepth: Math.max(2, step.dependsOnStepIds.length + 1) } : {}),
        limit: 2,
      })
      const runTrace = this.host.ensureRunTrace(run, profiles)
      const assignedTargetRoutes = extractAssignedTargetRoutes({
        title: step.title,
        hypothesis: step.hypothesis,
        parentFacts,
        defaultOrigin: targetOrigins[0],
      })

      clearPreSessionTimer()
      const remainingWallClockMs = Math.max(1, budget.wallClockMs - Math.max(0, Date.now() - startedAt))
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
          alreadyConfirmed: confirmedRefs,
          unconfirmedHardSurface,
          detLeads,
          ...(assignmentBrief ? { assignmentBrief } : {}),
        }),
        signal: job.controller.signal,
        maxTurns: budget.maxTurns,
        wallClockMs: remainingWallClockMs,
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
        shouldSettle: () => (Date.now() - startedAt) >= effectiveSettlementMs,
        handlers: scopedHandlers,
        secrets,
        beforeCall: () => {
          this.host.check(job)
          if (this.storage.checkBudgetExceeded(run.id)) {
            throw new BudgetExceededError('Run spend or request budget exceeded.')
          }
        },
        ...llmRunHooks(this.storage, run.id),
        onUsage: usage => {
          const tokens = usage.inputTokens + usage.outputTokens
          this.storage.recordLlmSpend(run.id, { usd: usage.costUsd, tokens })
          this.host.board.noteTokens(job.assignment.id, boardHandle, tokens)
        },
        onTurn: turn => {
          recordTurnLatency()
          this.storage.updateWorker(job.assignment.id, { turnsUsed: turn })
          this.storage.recordLlmSpend(run.id, { turns: 1 })
        },
        onStreamActivity: noteProviderToken,
        onTurnStart: turn => {
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

      const latestRun = this.host.check(job)
      const outcomeText = sessionResult.status === 'wall_clock_rotated'
        ? `[partial] ${sessionResult.answer}`
        : sessionResult.completion
          ? `[${sessionResult.completion.status}] ${sessionResult.completion.summary}`
          : sessionResult.answer
      if (sessionResult.status === 'wall_clock_rotated') {
        this.host.wallClockRotationsByRun.set(run.id, (this.host.wallClockRotationsByRun.get(run.id) ?? 0) + 1)
        const elapsedMs = sessionResult.elapsedMs ?? Math.max(0, Date.now() - startedAt)
        this.host.safeEvent(
          run.id,
          'worker.wall_clock_rotated',
          `${step.title} rotated cleanly at wall-clock budget (${Math.round(elapsedMs / 1000)}s / ${Math.round(budget.wallClockMs / 1000)}s, ${sessionResult.turnsUsed} turn(s)); slot released.`,
          {
            assignmentId: job.assignment.id,
            stepId: step.id,
            specialistProfile: specialistProfileId,
            elapsedMs,
            wallClockMs: budget.wallClockMs,
            turnsUsed: sessionResult.turnsUsed,
            boundedRotation: true,
          },
        )
      }
      this.storage.transaction(() => {
        this.completeWorker(job.assignment, latestRun, outcomeText, [], undefined, currentSecrets())
        this.storage.updateChainStep(step.id, { status: 'complete', assignedWorkerId: job.assignment.id })
      }, { behavior: 'immediate' })
      if (sessionResult.status === 'wall_clock_rotated' && isMultiHopChainStep(step) && !confirmedDuringAssignment) {
        try {
          const recordedFacts = this.storage.listFacts(run.id, { includeTainted: false, limit: 500 })
            .filter(f => f.assignmentId === job.assignment.id)
          const recordedExchanges = this.storage.db
            .select({
              id: brokerExchanges.id,
              origin: brokerExchanges.origin,
              method: brokerExchanges.method,
              pathAndQuery: brokerExchanges.pathAndQuery,
              status: brokerExchanges.status,
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
            step,
            assignment: job.assignment,
            targetOrigins,
            confirmed: confirmedDuringAssignment,
            partialSummary: redact(outcomeText, currentSecrets()),
            recordedFacts,
            recordedExchanges,
            sealedCapHandles,
          })
        } catch { /* continuation checkpointing is best-effort and must never fail worker completion */ }
      }
    } finally {
      clearPreSessionTimer()
      stallWatchdog.clear()
      generationStartedAt = undefined
      const wallMs = Math.max(0, Date.now() - startedAt)
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
