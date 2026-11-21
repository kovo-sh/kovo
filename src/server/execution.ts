import { createHash, randomUUID } from 'node:crypto'
import { and, asc, eq } from 'drizzle-orm'
import { z } from 'zod'
import type { AccessPolicySnapshot } from '../access-policy.ts'
import {
  assetOrigin,
  defaultWorkerConcurrency,
  maxWorkerConcurrency,
  owaspCategories,
  responseCheckIds,
  workerHistory,
} from '../domain.ts'
import type {
  AssessmentCheckId,
  Candidate,
  CheckCoverage,
  Finding,
  OwaspCategory,
  ResponseCheckId,
  ThreatModelSummary,
} from '../domain.ts'
import { declarativeReplaySpecSchema, replaySpecOrigins } from '../replay-spec.ts'
import { suppliedResponseLabel } from '../report-summary.ts'
import { accessPolicyReviews } from './access-policy-checks.ts'
import {
  agentTurn,
  chainPlannerPrompt,
  coordinatorPrompt,
  listSkills,
  loadSkill,
  runAgentSession,
  threatModelPrompt,
  workerInvestigationPrompt,
} from './agent-session.ts'
import type { RequestHttpArgs, WorkerToolHandlers } from './agent-session.ts'
import { BrokerApprovalRequired, BrokerCircuitOpen, BrokerDenied, RequestBroker } from './broker.ts'
import type { BrokerExchangeResult, Grant, PublicObservation } from './broker.ts'
import { CanaryBroker } from './canary-broker.ts'
import { ColdGraphCompactor } from './compactor.ts'
import { queryCves } from './cve-broker.ts'
import { checkCoverage, meetsBaseline, readComparisons, verificationCommand } from './evidence-checks.ts'
import type { EvidenceReview } from './evidence-checks.ts'
import { parseDependenciesFromFile } from './github-connector.ts'
import {
  privateModelProfiles,
  recordProfileFailure,
  recordProfileSuccess,
} from './model-settings.ts'
import type { ResolvedModelProfile } from './model-settings.ts'
import { personaSecrets, resolveRunPersonas } from './persona-vault.ts'
import { BudgetExceededError } from './provider.ts'
import { redact } from './redact.ts'
import type { NamedSecret } from './redact.ts'
import { retestReplaySpec, verifyReplaySpec } from './replay-verifier.ts'
import { responseReview } from './response-checks.ts'
import { availableReviewChecks, parseReviewPlan, reviewPlanPrompt, standardChecks } from './review-plan.ts'
import { approvalRequests, findings, messages } from './schema.ts'
import { ScopedBrowser } from './scoped-browser.ts'
import { assessmentAssignments, store } from './store.ts'
import type { Assignment, ChainStep, ReplaySpecRow, Run, Store } from './store.ts'
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

const maxChainStepsPerRun = 32
const plannerDebounceMs = 1_200
const intentLeaseMs = 30 * 60_000

const threatModelResponseSchema = z.object({
  summary: z.string().min(1).max(2000),
  entries: z.array(z.object({
    origin: z.string(),
    riskTier: z.enum(['critical', 'high', 'medium', 'low']),
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

function classifyHostHeuristic(asset: Candidate): ThreatModelSummary {
  const host = new URL(asset.origin).hostname.toLowerCase()
  const tags: string[] = []
  let riskTier: ThreatModelSummary['riskTier'] = 'medium'

  if (/(?:auth|login|sso|oauth|clerk|account|id|identity)/.test(host)) { tags.push('auth'); riskTier = 'critical' }
  if (/(?:api|graphql|trpc|gateway|backend|cloud|app|dash|admin|portal)/.test(host)) { tags.push('api'); riskTier = riskTier === 'critical' ? 'critical' : 'high' }
  if (/(?:upload|media|file|storage|cdn|asset|bucket|blob)/.test(host)) { tags.push('upload'); riskTier = riskTier === 'medium' ? 'high' : riskTier }
  if (/(?:billing|pay|stripe|checkout|webhook|hook)/.test(host)) { tags.push('billing'); riskTier = 'critical' }
  if (/(?:llm|ai|chat|engine|model|prompt|agent|proxy)/.test(host)) { tags.push('llm-proxy'); riskTier = 'critical' }
  if (/(?:dev|stage|staging|debug|test|beta|preview|sandbox|internal|bundler)/.test(host)) { tags.push('staging-debug'); riskTier = 'high' }
  if (asset.dnsSource?.externalAliases?.length) { tags.push('external-cname') }
  if (/(?:blog|docs|marketing|www|status|landing|static)/.test(host) && !tags.length) { tags.push('static'); riskTier = 'low' }
  if (!tags.length) tags.push('web')

  return {
    origin: asset.origin,
    riskTier,
    surfaceTags: tags,
    rationale: `Heuristic surface ranking for ${host} (${tags.join(', ')}).`,
  }
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
}

export class Execution {
  private readonly storage: Store
  readonly broker: RequestBroker
  readonly browser: ScopedBrowser
  readonly canaryBroker: CanaryBroker
  readonly backend: WorkerBackend
  readonly compactor: ColdGraphCompactor
  private readonly active = new Map<string, Active>()
  private readonly coordinator = new Map<string, CoordinatorTask>()
  private readonly threatModeling = new Map<string, CoordinatorTask>()
  private readonly plannerTasks = new Map<string, CoordinatorTask>()
  private readonly plannerTimers = new Map<string, NodeJS.Timeout>()
  private readonly plannerDirty = new Set<string>()
  private readonly plannerDoneRound = new Map<string, number>()
  private readonly circuitNotified = new Set<string>()
  private safetyTimer?: NodeJS.Timeout
  private reclaimTimer?: NodeJS.Timeout
  private unsubWake?: () => void
  private wakeScheduled = false

  constructor(storage: Store, options: ExecutionOptions = {}) {
    this.storage = storage
    this.broker = options.broker ?? createBroker()
    this.browser = options.browser ?? new ScopedBrowser(this.broker)
    this.canaryBroker = options.canaryBroker ?? new CanaryBroker()
    this.backend = options.backend ?? new LinuxWorkerBackend({
      workspace: { id: storage.workspace.id, directory: storage.directory },
    })
    this.compactor = new ColdGraphCompactor({
      onProfileSuccess: id => recordProfileSuccess(id, this.storage),
      onProfileFailure: (id, err, hard) => recordProfileFailure(id, err, hard, this.storage),
    })
  }

  start() {
    if (this.safetyTimer) return
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
    await this.canaryBroker.stop().catch(() => undefined)
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
  } {
    const project = this.storage.project(run.projectId)
    const personas = resolveRunPersonas(this.storage, run.projectId, run.approvedPersonaIds)
    const secrets = personaSecrets(personas)
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
    return { grant, secrets }
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
      secrets: readonly NamedSecret[]
    },
    signal: AbortSignal,
  ): Promise<boolean> {
    const run = this.check(job)
    const project = this.storage.project(run.projectId)
    if (project.environment === 'local-lab' && process.env.GUARDIAN_ALLOW_LOCAL_LAB === '1' && run.capabilityTier >= 3) {
      return true
    }
    if (run.capabilityTier < 3) {
      throw new BrokerDenied('This operation requires Capability Tier 3.')
    }
    const req = this.storage.createApprovalRequest(run, job.assignment, {
      origin: input.origin,
      method: input.method,
      pathAndQuery: input.pathAndQuery,
      personaHandle: input.personaHandle,
      rationale: input.rationale,
      requestPreview: input.requestPreview,
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
    return decision === 'approved'
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

      if (profiles.length) {
        this.startCoordinator(run, profiles)
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
            profiles,
            scenario: 'coordinator-plan',
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

      // 1. Correlate dependencies from uploaded/synced specs via CVE broker
      const seenDeps = new Set<string>()
      const highSignalPkgs = new Set(['next', 'react', 'vite', 'express', '@clerk/nextjs', '@supabase/supabase-js', 'graphql', 'fastify', 'nuxt', 'svelte', 'astro'])
      for (const spec of specs) {
        const deps = parseDependenciesFromFile(spec.name.split(':').pop() ?? spec.name, spec.content)
        // Also parse `:dependencies` note format generated by github-connector
        for (const match of spec.content.matchAll(/^([a-zA-Z0-9_-]+):([@a-zA-Z0-9_./-]+)@([0-9][0-9A-Za-z.+-]*)/gm)) {
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
      heuristicEntries.sort((a, b) => riskOrder[a.riskTier] - riskOrder[b.riskTier])

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
            profiles,
            scenario: 'threat-model',
            thinkingLevel: 'medium',
            prompt: threatModelPrompt({
              goal: freshRun.goal,
              capabilityTier: freshRun.capabilityTier,
              approvedOrigins: [...approvedOrigins],
              personas: personasPub,
              specs: specs.slice(0, 12).map(s => ({
                name: s.name, kind: s.kind, origin: s.origin, preview: s.content.slice(0, 1200),
              })),
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
            const validEntries = parsed.data.entries.filter(e => approvedOrigins.has(e.origin))
            if (validEntries.length) {
              const seen = new Set(validEntries.map(e => e.origin))
              finalEntries = [
                ...validEntries,
                ...heuristicEntries.filter(h => !seen.has(h.origin)),
              ]
            }
            seededSteps = parsed.data.initialSteps.filter(s => s.origins.some(o => approvedOrigins.has(o)))
          }
        } catch {
          // Deterministic heuristic fallback guarantees progress even if LLM response isn't valid JSON
        }
      }

      if (!this.authorize(job)) return

      // Ensure at least initial investigation steps exist when Tier >= 1
      if (!seededSteps.length && freshRun.capabilityTier > 0 && approvedAssets.length > 0) {
        const topHosts = finalEntries.slice(0, Math.min(6, finalEntries.length))
        seededSteps = topHosts.map((entry, idx) => ({
          title: `Surface & chain investigation · ${new URL(entry.origin).hostname}`,
          hypothesis: `Harvest JS/API routes, inspect DNS/TLS/CORS/auth headers, fingerprint stack & CVEs, and verify any candidate vulnerabilities on ${entry.origin} (${entry.surfaceTags.join(', ')}).`,
          category: entry.surfaceTags.includes('auth') ? 'auth-identity'
            : entry.surfaceTags.includes('api') ? 'broken-access-control'
              : entry.surfaceTags.includes('upload') ? 'upload-storage'
                : entry.surfaceTags.includes('llm-proxy') ? 'llm-ai-security'
                  : 'misconfig-exposure',
          priority: Math.max(40, 95 - idx * 8),
          origins: [entry.origin],
          skills: ['recon-modern-spa', 'cve-runtime-correlation', 'false-positive-elimination'],
        }))
      }

      this.storage.transaction(() => {
        const current = this.storage.run(freshRun.id)
        if (current.status !== 'running' || current.phase !== 'threat_model') return
        const tm = this.storage.saveThreatModel(current, finalEntries, tmSummary)
        const tmArtifact = this.storage.addArtifact(current, claimed, 'threat-model', 'Round-0 Threat Model',
          JSON.stringify({ threatModelId: tm.id, summary: tmSummary, entries: finalEntries }, null, 2), 'threat-model', secrets)

        for (const step of seededSteps.slice(0, 12)) {
          const validOrigins = step.origins.filter(o => approvedOrigins.has(o))
          const assetIds = current.candidates.filter(c => validOrigins.includes(c.origin) && current.approved.includes(c.id)).map(c => c.id)
          if (!assetIds.length) continue
          this.storage.addChainStep(current, {
            title: step.title,
            hypothesis: step.hypothesis,
            category: step.category,
            priority: step.priority,
            targetAssetIds: assetIds,
            skills: step.skills,
            sourceOrigins: validOrigins,
          })
        }

        this.completeWorker(claimed, current, tmSummary, [tmArtifact.id])
        const nextPhase = current.capabilityTier === 0 || !profiles.length ? 'verification' : 'investigation'
        this.storage.updateRun(current.id, { phase: nextPhase })
        this.storage.event(current.id, `${nextPhase}.started`,
          nextPhase === 'investigation'
            ? `Threat model complete. Starting closed-loop chain investigation (${seededSteps.length} initial steps).`
            : 'Baseline captures complete. Starting deterministic Zero-LLM verification.')
        this.storage.message(current.id, current.coordinatorId, 'guardian',
          nextPhase === 'investigation'
            ? `Threat model ranked ${finalEntries.length} hosts and queued ${Math.min(seededSteps.length, 12)} initial investigation steps.`
            : 'Baseline capture complete. Deterministic verification is checking the recorded evidence.')
      }, { behavior: 'immediate' })
    } finally {
      this.active.delete(claimed.id)
    }
  }

  // --- Phase 2: Closed-Loop Investigation & Debounced Stateless Planner ---

  private driveInvestigation(run: Run, profiles: readonly ResolvedModelProfile[]) {
    if (!profiles.length) return
    this.storage.refreshReadyChainSteps(run.id, run.goalRevision)
    const steps = this.storage.listChainSteps(run.id, run.goalRevision)
    const readySteps = steps
      .filter(s => s.status === 'ready')
      .sort((a, b) => b.priority - a.priority || a.seq - b.seq)
    const runningSteps = steps.filter(s => s.status === 'running')
    const pendingSteps = steps.filter(s => s.status === 'pending')

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

    // If nothing is running/ready/pending, trigger final planner review or advance to verification
    const updatedSteps = this.storage.listChainSteps(run.id, run.goalRevision)
    const anyActive = updatedSteps.some(s => ['pending', 'ready', 'running'].includes(s.status))
    if (!anyActive && !this.plannerTasks.has(run.id) && !this.plannerTimers.has(run.id)) {
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

  private async runChainPlanner(run: Run, profiles: readonly ResolvedModelProfile[], task: CoordinatorTask) {
    const fresh = this.storage.run(run.id)
    if (fresh.status !== 'running' || fresh.phase !== 'investigation') return
    if (this.storage.checkBudgetExceeded(run.id)) return

    // 1. Advance roundNo & trigger background LSM cold-graph compaction
    const roundRes = this.compactor.onPlannerRound(this.storage, run.id, profiles, task.controller.signal)
    const afterRound = this.storage.run(run.id)
    const approvedOrigins = this.approvedOriginsSet(afterRound)

    const allSteps = this.storage.listChainSteps(run.id, afterRound.goalRevision)
    const activeFacts = this.storage.listFacts(run.id, { includeTainted: false, limit: 80 })
      .filter(f => !f.digestId && approvedOrigins.has(f.origin))
    const coldDigests = this.storage.listDigests(run.id, true)
    const coverageEntries = this.storage.listCoverageEntries(run.id, afterRound.goalRevision)
      .filter(c => approvedOrigins.has(c.origin))
    const tm = this.storage.latestThreatModel(run.id, afterRound.goalRevision)
    const pendingFindings = this.storage.runDetail(run.id).findings
      .filter(f => approvedOrigins.has(f.origin))
      .slice(0, 30)

    const personas = [...resolveRunPersonas(this.storage, afterRound.projectId, afterRound.approvedPersonaIds).values()]
      .map(p => ({ handle: p.handle, roleLabel: p.roleLabel, originAllowlist: p.originAllowlist }))

    const prompt = chainPlannerPrompt({
      goal: afterRound.goal,
      roundNo: roundRes.roundNo,
      capabilityTier: afterRound.capabilityTier,
      approvedOrigins: [...approvedOrigins],
      personas,
      threatModel: tm?.entries.filter(e => approvedOrigins.has(e.origin)),
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
      chainSteps: allSteps.map(s => ({
        id: s.id, seq: s.seq, title: s.title, category: s.category, status: s.status, priority: s.priority, origins: s.sourceOrigins,
      })),
      coverageEntries: coverageEntries.map(c => ({ origin: c.origin, category: c.category, status: c.status, summary: c.summary })),
      pendingFindings: pendingFindings.map(f => ({ id: f.id, origin: f.origin, title: f.title, status: f.status, severity: f.severity })),
      budgetRemaining: {
        usd: Math.max(0, Number((afterRound.budgetUsd - afterRound.spentUsd).toFixed(4))),
        requests: Math.max(0, afterRound.budgetRequests - afterRound.spentRequests),
      },
    })

    const answer = await agentTurn({
      directory: this.storage.directory,
      sessionId: `planner-${run.id}-r${roundRes.roundNo}`,
      requestId: `planner:${afterRound.goalRevision}:${roundRes.roundNo}`,
      profiles,
      scenario: 'chain-planner',
      thinkingLevel: 'medium',
      prompt,
      signal: task.controller.signal,
      onUsage: u => this.storage.recordLlmSpend(run.id, { usd: u.costUsd, tokens: u.inputTokens + u.outputTokens }),
      onProfileSuccess: id => recordProfileSuccess(id, this.storage),
      onProfileFailure: (id, err, hard) => recordProfileFailure(id, err, hard, this.storage),
    })

    if (!this.currentCoordinator(run.id, task)) return

    const parsed = plannerResponseSchema.safeParse(JSON.parse(stripJsonFences(answer)))
    if (!parsed.success) {
      this.plannerDoneRound.set(run.id, roundRes.roundNo)
      return
    }

    const currentRun = this.storage.run(run.id)
    const currentApproved = this.approvedOriginsSet(currentRun)
    const existingSteps = this.storage.listChainSteps(run.id, currentRun.goalRevision)
    let totalSteps = existingSteps.length
    let addedCount = 0

    for (const cancelId of parsed.data.cancelStepIds) {
      const target = existingSteps.find(s => s.id === cancelId)
      if (target && ['pending', 'ready'].includes(target.status)) {
        this.storage.updateChainStep(target.id, { status: 'canceled' })
      }
    }

    for (const step of parsed.data.newSteps) {
      if (totalSteps >= maxChainStepsPerRun) break
      const validOrigins = step.origins.filter(o => currentApproved.has(o))
      const assetIds = currentRun.candidates
        .filter(c => validOrigins.includes(c.origin) && currentRun.approved.includes(c.id))
        .map(c => c.id)
      if (!assetIds.length) continue
      // Deduplicate identical titles
      if (existingSteps.some(s => s.title.toLowerCase() === step.title.toLowerCase())) continue
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
      })
      totalSteps += 1
      addedCount += 1
    }

    if (parsed.data.done || addedCount === 0) {
      this.plannerDoneRound.set(run.id, roundRes.roundNo)
    }
    this.storage.event(run.id, 'planner.round', `Planner round ${roundRes.roundNo}: added ${addedCount} steps.`, {
      roundNo: roundRes.roundNo, addedCount, done: parsed.data.done, summary: parsed.data.summary.slice(0, 300),
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

    const assignment = this.storage.transaction(() => {
      const worker = this.storage.makeWorker(run, 'investigation', primaryAsset, step.title, step.hypothesis, {
        stepId: step.id,
        maxTurns: run.workerMaxTurns,
        parentFactIds: step.dependsOnFactIds,
        sourceOrigins: targetOrigins,
      })
      const claimed = this.storage.updateWorker(worker.id, {
        status: 'running',
        lease: randomUUID(),
        leaseExpiresAt: Date.now() + intentLeaseMs,
      })!
      this.storage.updateChainStep(step.id, { status: 'running', assignedWorkerId: claimed.id })
      this.storage.addGraphEdge(run.id, {
        fromKind: 'step', fromId: step.id, toKind: 'assignment', toId: claimed.id, edgeKind: 'spawns',
      })
      this.storage.event(run.id, 'worker.started', `${step.title} started.`, { assignmentId: claimed.id, stepId: step.id })
      return claimed
    }, { behavior: 'immediate' })

    const job: Active = { assignment, origins: new Set(targetOrigins), controller: new AbortController() }
    this.active.set(assignment.id, job)

    void this.runInvestigationWorker(job, step, targetOrigins, profiles).catch(error => {
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
    const { grant, secrets } = this.buildGrant(job, run, permittedAtAdmission)

    // Open ONE persistent air-gapped container for the entire intent
    const session = await this.backend.openSession(job.assignment.id, job.controller.signal)
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
          persona: args.persona,
          followRedirects: args.followRedirects ?? false,
        }, grant, signal)

        let res: BrokerExchangeResult
        try {
          res = await runHttp()
        } catch (err) {
          if (err instanceof BrokerApprovalRequired) {
            const approved = await this.waitForTier3Approval(job, {
              origin: err.origin,
              method: err.method,
              pathAndQuery: err.pathAndQuery,
              personaHandle: args.persona ?? null,
              rationale: args.rationale ?? `Tier 3 probe during step "${step.title}"`,
              requestPreview: JSON.stringify({
                method: args.method, origin: args.origin, pathAndQuery: args.pathAndQuery,
                persona: args.persona, headers, bodyPreview: body?.slice(0, 500),
              }, null, 2),
              secrets,
            }, signal)
            if (!approved) throw new BrokerDenied('Tier 3 request was denied or expired.')
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
          secrets,
        })
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
              secrets,
            })
            return {
              exchangeId: saved.id, status: res.status, durationMs: res.durationMs,
              bodySha256: res.bodySha256, bodyPreview: res.bodyPreview.slice(0, 800),
            }
          })
          const stagedPath = await session.stage(`exchanges/batch-${randomUUID().slice(0, 8)}.json`,
            JSON.stringify(summaries, null, 2), signal).catch(() => null)
          return { count: summaries.length, stagedPath, results: summaries }
        },

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
            secrets,
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
                secrets,
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
            exchangeIds: res.exchangeIds,
            domSnippet: res.domSnippet.slice(0, 6000),
            durationMs: res.durationMs,
          }
          const ev = this.storage.addArtifact(curRun, job.assignment, 'browser',
            `Browser visit · ${args.origin}${args.pathAndQuery.slice(0, 60)}`,
            JSON.stringify(summaryObj, null, 2), undefined, secrets)
          const stagedPath = await session.stage(`browser-${ev.id.slice(0, 8)}.json`,
            JSON.stringify(summaryObj, null, 2), signal).catch(() => null)
          return { evidenceId: ev.id, stagedPath, ...summaryObj }
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
          if (process.env.GUARDIAN_CANARY_BASE_URL || (project.environment === 'local-lab' && process.env.GUARDIAN_ALLOW_LOCAL_LAB === '1')) {
            await this.canaryBroker.startLocalListener()
          }
          return this.canaryBroker.mint(this.storage, curRun.id, job.assignment.id, purpose)
        },

        check_canary: async ({ token }) => {
          const curRun = this.check(job)
          return this.canaryBroker.check(this.storage, curRun.id, token)
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
          const cleanOrigin = assetOrigin.parse(args.origin)
          if (!currentApproved.has(cleanOrigin)) throw new BrokerDenied(`Origin ${cleanOrigin} is not approved.`)
          const fact = this.storage.addFact(curRun, job.assignment, {
            kind: args.kind,
            origin: cleanOrigin,
            summary: args.summary,
            data: args.data,
            exchangeIds: args.exchangeIds,
            evidenceIds: args.evidenceIds,
            sourceOrigins: args.sourceOrigins,
            secrets,
          })
          this.schedulePlanner(curRun.id)
          return { factId: fact.id, kind: args.kind, origin: fact.origin }
        },

        record_coverage: async (args) => {
          const curRun = this.check(job)
          const currentApproved = this.approvedOriginsSet(curRun)
          const cleanOrigin = assetOrigin.parse(args.origin)
          if (!currentApproved.has(cleanOrigin)) throw new BrokerDenied(`Origin ${cleanOrigin} is not approved.`)
          const entry = this.storage.upsertCoverageEntry(curRun, job.assignment.id, {
            origin: cleanOrigin,
            category: args.category,
            status: args.status,
            summary: args.summary,
          })
          return { id: entry.id, origin: entry.origin, category: entry.category, status: entry.status }
        },

        propose_chain_finding: async ({ replaySpec, chainFactIds, exchangeIds }) => {
          const curRun = this.check(job)
          const currentApproved = this.approvedOriginsSet(curRun)
          const parsed = declarativeReplaySpecSchema.parse(replaySpec)
          const specOrigins = replaySpecOrigins(parsed)
          if (specOrigins.some(o => !currentApproved.has(o))) {
            throw new BrokerDenied('Replay spec references an origin outside current approved scope.')
          }
          const asset = curRun.candidates.find(c => c.origin === parsed.origin && curRun.approved.includes(c.id))
          if (!asset) throw new BrokerDenied(`Primary finding origin ${parsed.origin} is not in approved scope.`)

          const findingId = randomUUID()
          const validFactIds = chainFactIds.filter(fid =>
            this.storage.listFacts(curRun.id, { includeTainted: false, limit: 500 }).some(f => f.id === fid))
          const sourceOrigins = new Set<string>([...specOrigins, ...targetOrigins])
          const specRow = this.storage.createReplaySpec(curRun, job.assignment, findingId, parsed, [...sourceOrigins])
          const ev = this.storage.addArtifact(curRun, job.assignment, 'replay',
            `Proposed replay spec · ${parsed.title}`,
            JSON.stringify({ replaySpecId: specRow.id, specSha256: specRow.specSha256, spec: parsed }, null, 2),
            undefined, secrets)
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
            chainFactIds: validFactIds,
            exchangeIds: [...new Set(exchangeIds)],
            evidenceIds: [ev.id],
            scopeRevision: curRun.scopeRevision,
          }
          this.storage.upsertChainFinding(curRun, asset.id, finding, specRow.id, [...sourceOrigins])
          for (const fid of validFactIds) {
            this.storage.addGraphEdge(curRun.id, { fromKind: 'fact', fromId: fid, toKind: 'finding', toId: findingId, edgeKind: 'proves' })
          }
          this.storage.addGraphEdge(curRun.id, { fromKind: 'assignment', fromId: job.assignment.id, toKind: 'finding', toId: findingId, edgeKind: 'proves' })
          this.schedulePlanner(curRun.id)
          return {
            findingId,
            replaySpecId: specRow.id,
            status: 'pending',
            note: 'Candidate finding queued for Zero-LLM Declarative Replay Verification. Only deterministic replay can promote to confirmed.',
          }
        },

        suggest_candidate_host: async ({ origin, source, thirdParty }) => {
          const curRun = this.check(job)
          const clean = assetOrigin.parse(origin)
          return this.storage.suggestCandidateHost(curRun, clean, source, Boolean(thirdParty))
        },

        complete_intent: async (completion) => ({ recorded: true, status: completion.status }),
      }

      const personasPub = [...grant.personas?.values() ?? []].map(p => ({
        handle: p.handle, roleLabel: p.roleLabel, originAllowlist: p.originAllowlist,
      }))

      const sessionResult = await runAgentSession({
        directory: this.storage.directory,
        sessionId: job.assignment.sessionId,
        requestId: `investigate:${step.id}:attempt-${job.assignment.attempt}`,
        profiles,
        scenario: 'worker-investigation',
        prompt: workerInvestigationPrompt({
          goal: run.goal,
          step: {
            id: step.id, title: step.title, hypothesis: step.hypothesis,
            category: step.category, skills: step.skills,
          },
          origins: targetOrigins,
          capabilityTier: run.capabilityTier,
          maxTurns: job.assignment.maxTurns,
          personas: personasPub,
          parentFacts: parentFacts.map(f => ({
            id: f.id, kind: f.kind, origin: f.origin, summary: f.summary, data: f.data,
          })),
          specsSummary: stagedSpecs,
        }),
        signal: job.controller.signal,
        maxTurns: job.assignment.maxTurns,
        thinkingLevel: 'medium',
        compaction: true,
        enableSettlement: true,
        requireCompleteIntent: true,
        shouldSettle: () => (Date.now() - startedAt) >= intentLeaseMs * 0.85,
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
        this.completeWorker(job.assignment, latestRun, outcomeText, [])
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
      this.storage.updateRun(current.id, { phase: 'verification' })
      this.storage.event(current.id, 'verification.started', 'Investigation complete. Starting Zero-LLM Replay Verification.')
      this.storage.message(current.id, current.coordinatorId, 'guardian',
        'Investigation complete. Deterministic Zero-LLM verification is replaying every proposed finding and checking baselines.')
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

    for (const row of pendingFindings) {
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
      ? this.verifyReplaySpecJob(job, claimed.stepId)
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
    const { grant, secrets } = this.buildGrant(job, run, permittedAtAdmission)

    // Tier 3 HITL gate for rce_proof specs on non-local-lab targets
    if (specRow.spec.kind === 'rce_proof') {
      const approved = await this.waitForTier3Approval(job, {
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
        secrets,
      }, job.controller.signal)
      if (!approved) {
        const current = this.check(job)
        const updatedFinding: Finding = {
          ...findingRow.finding,
          status: 'inconclusive',
          reason: 'Tier 3 approval for non-destructive rce_proof verification was denied or expired.',
          confidence: 'low',
        }
        this.storage.upsertChainFinding(current, findingRow.assetId, updatedFinding, specRow.id, specRow.sourceOrigins)
        this.completeWorker(job.assignment, current, 'Inconclusive: Tier 3 approval denied.', [])
        return
      }
    }

    const result = await verifyReplaySpec({
      spec: specRow.spec,
      broker: this.broker,
      browser: this.browser,
      canaryBroker: this.canaryBroker,
      backend: this.backend,
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
          secrets,
        })
        return saved.id
      },
    })

    const current = this.check(job)
    this.storage.transaction(() => {
      const receipt = this.storage.addArtifact(current, job.assignment, 'replay',
        `Zero-LLM replay · ${specRow.spec.title}`,
        JSON.stringify({
          replaySpecId: specRow.id,
          specSha256: specRow.specSha256,
          kind: specRow.spec.kind,
          origin: specRow.spec.origin,
          verdict: result.verdict,
          outcome: result.outcome,
          exchangeIds: result.exchangeIds,
          sourceOrigins: specRow.sourceOrigins,
          evidenceSha256: result.evidenceSha256,
          evidencePayload: result.evidencePayload,
        }, null, 2), 'replay:' + specRow.id, secrets)

      const updatedFinding: Finding = {
        ...findingRow.finding,
        status: result.verdict,
        reason: result.outcome.reason || result.outcome.observed || findingRow.finding.reason,
        confidence: result.verdict === 'confirmed' ? 'high' : result.verdict === 'dismissed' ? 'medium' : 'low',
        verification: `Zero-LLM ${specRow.spec.kind} replay verdict: ${result.verdict} (controlPassed=${result.outcome.controlPassed}, observed: ${result.outcome.observed}).`,
        evidenceIds: [...new Set([...findingRow.finding.evidenceIds, receipt.id])],
        exchangeIds: [...new Set([...(findingRow.finding.exchangeIds ?? []), ...result.exchangeIds])],
        scopeRevision: current.scopeRevision,
      }
      this.storage.upsertChainFinding(current, findingRow.assetId, updatedFinding, specRow.id, specRow.sourceOrigins)

      if (result.verdict === 'confirmed' && owaspCategories.includes(specRow.spec.category as OwaspCategory)) {
        this.storage.upsertCoverageEntry(current, job.assignment.id, {
          origin: specRow.spec.origin,
          category: specRow.spec.category as OwaspCategory,
          status: 'reported',
          summary: `Confirmed: ${specRow.spec.title}`,
        })
      }
      this.completeWorker(job.assignment, current,
        `Replay verdict: ${result.verdict} (${result.outcome.observed.slice(0, 160)})`, [receipt.id])
    }, { behavior: 'immediate' })
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
    const result = comparisons.length ? await this.backend.run({
      assignmentId: job.assignment.id,
      files: [{ name: 'verification-input.json', content: JSON.stringify(payload) }],
      command: verificationCommand,
      outputs: ['verification.json'],
    }, job.controller.signal) : undefined

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
    const { grant, secrets } = this.buildGrant(job, run, permittedAtAdmission)

    const retestRes = await retestReplaySpec({
      spec: specRow.spec,
      broker: this.broker,
      browser: this.browser,
      canaryBroker: this.canaryBroker,
      backend: this.backend,
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
          secrets,
        })
        return saved.id
      },
    })

    const current = this.storage.run(run.id)
    this.storage.transaction(() => {
      const ev = this.storage.addArtifact(current, job.assignment, 'replay',
        `Verify Fix retest · ${findingRow.finding.title}`,
        JSON.stringify({
          findingId,
          replaySpecId: specRow.id,
          verdict: retestRes.verdict,
          outcome: retestRes.replay.outcome,
          exchangeIds: retestRes.replay.exchangeIds,
          evidenceSha256: retestRes.replay.evidenceSha256,
        }, null, 2), 'retest:' + job.assignment.id, secrets)
      const summary = `${retestRes.verdict}: ${retestRes.replay.outcome.observed}`
      this.storage.recordRetestRun(current, findingId, specRow.id, retestRes.verdict, summary, [ev.id], retestRes.replay.exchangeIds)
      this.completeWorker(job.assignment, current, `Verify Fix verdict: ${retestRes.verdict}`, [ev.id])
      this.storage.message(current.id, current.coordinatorId, 'guardian',
        `Verify Fix retest for "${findingRow.finding.title}": ${retestRes.verdict}. ${retestRes.replay.outcome.observed}`)
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
      budgetRequests: run.budgetRequests,
      turnsUsed: run.turnsUsed,
    })

    void agentTurn({
      directory: this.storage.directory,
      sessionId: run.coordinatorId,
      requestId: `${next.id}:${run.goalRevision}:${run.scopeRevision}`,
      profiles,
      scenario: 'coordinator',
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
      findingKind: 'baseline_check',
      check: { id: rule.id, caseId: coverage.caseId, expected: coverage.expected, observed: coverage.observed },
      evidenceIds,
      scopeRevision: run.scopeRevision,
    }
    if (existingId) {
      this.storage.db.update(findings).set({ finding: record }).where(eq(findings.id, record.id)).run()
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
        finding: record,
      }).run()
    }
  }

  private completeWorker(worker: Assignment, run: Run, summary: string, artifactIds: string[], checks?: CheckCoverage[]) {
    const outcome = redact(summary)
    const result = this.storage.addArtifact(run, worker, 'handoff', 'result.md', [
      '# Result', '', outcome, '', 'Evidence: ' + artifactIds.join(', '),
    ].join('\n'), 'result')
    this.storage.updateWorker(worker.id, { status: 'complete', lease: null, leaseExpiresAt: null, outcome, checks })
    this.storage.message(run.id, worker.id, 'worker', outcome, undefined, [...artifactIds, result.id])
    this.storage.event(run.id, 'worker.complete', worker.title + ' completed.', {
      assignmentId: worker.id, artifactId: artifactIds[0] ?? result.id,
    })
  }
}

let instance: Execution | undefined
export function execution() {
  return instance ??= new Execution(store())
}
