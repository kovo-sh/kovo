import { createHash, randomUUID } from 'node:crypto'
import { and, asc, eq } from 'drizzle-orm'
import type { Candidate, CheckCoverage, Finding, ProviderSettings, ResponseCheckId } from '../domain.ts'
import { agentTurn, coordinatorPrompt, workerInput } from './agent-session.ts'
import { BrokerDenied, RequestBroker } from './broker.ts'
import type { PublicObservation } from './broker.ts'
import { privateModelSettings } from './model-settings.ts'
import { redact } from './redact.ts'
import { checkCoverage, meetsBaseline, readComparisons, responseReview, responseVerificationCommand } from './response-checks.ts'
import type { ResponseReview } from './response-checks.ts'
import { parseReviewPlan, reviewPlanPrompt, standardChecks } from './review-plan.ts'
import { findings, messages } from './schema.ts'
import { assessmentAssignments, store } from './store.ts'
import type { Assignment, Run, Store } from './store.ts'
import { LinuxWorkerBackend } from './worker-backend.ts'

type Active = {
  assignment: Assignment
  origins: Set<string>
  controller: AbortController
}
type Capture = { observation: PublicObservation | null; note: string }
type CoordinatorTask = { controller: AbortController; goalRevision: number; scopeRevision?: number }

export function derivedResult(result: { exitStatus: number; result: string; stdout: string }) {
  return JSON.stringify({ exitStatus: result.exitStatus, result: (result.result || result.stdout).slice(0, 1200) })
}

function createBroker() {
  const target = process.env.GUARDIAN_NETWORK_FIXTURE
  if (!target) return process.env.GUARDIAN_OFFLINE === '1'
    ? new RequestBroker({ resolve: async () => [] }) : new RequestBroker()
  const fixture = new URL(target)
  if (fixture.origin !== target || fixture.hostname !== '127.0.0.1' || fixture.protocol !== 'http:' || !fixture.port) {
    throw new Error('GUARDIAN_NETWORK_FIXTURE must identify a loopback HTTP origin.')
  }
  return new RequestBroker({
    source: 'fixture response',
    resolve: async host => host.endsWith('.private-fixture.example')
      ? [{ address: '127.0.0.1', family: 4 }] : [{ address: '93.184.216.34', family: 4 }],
    transport: async (url, _address, signal) => {
      const response = await fetch(fixture, {
        signal, redirect: 'error', headers: { 'x-guardian-fixture-target': url.href },
      })
      await response.body?.cancel()
      return { status: response.status, headers: Object.fromEntries(response.headers) }
    },
  })
}

class Execution {
  private readonly storage: Store
  private readonly broker = createBroker()
  private readonly backend = new LinuxWorkerBackend()
  private readonly active = new Map<string, Active>()
  private readonly coordinator = new Map<string, CoordinatorTask>()
  private timer?: NodeJS.Timeout

  constructor(storage: Store) {
    this.storage = storage
  }

  start() {
    if (this.timer) return
    this.timer = setInterval(() => this.wake(), 300)
    this.timer.unref()
  }

  private permitted(run: Run, origin: string) {
    return run.candidates.some(asset => asset.origin === origin && run.approved.includes(asset.id))
  }

  private observationOrigins(assignment: Assignment, observation: PublicObservation) {
    return new Set([observation.origin, observation.finalOrigin, ...this.storage.brokerOrigins(assignment)])
  }

  private authorize(job: Active) {
    const current = this.storage.worker(job.assignment.id)
    const run = this.storage.run(current.runId)
    return current.status === 'running' && current.lease === job.assignment.lease &&
      run.status === 'running' && run.phase === current.phase && current.goalRevision === run.goalRevision &&
      run.reviewPlan?.status !== 'pending' &&
      [...job.origins].every(origin => this.permitted(run, origin))
  }

  private check(job: Active) {
    job.controller.signal.throwIfAborted()
    if (!this.authorize(job)) throw new BrokerDenied('The assignment is no longer authorized.')
    return this.storage.run(job.assignment.runId)
  }

  private currentCoordinator(runId: string, task: CoordinatorTask) {
    const run = this.storage.run(runId)
    return run.status === 'running' && run.goalRevision === task.goalRevision &&
      (task.scopeRevision === undefined || run.scopeRevision === task.scopeRevision) && !task.controller.signal.aborted
  }

  // Called after durable state changes and periodically while the local server is up.
  wake() {
    for (const [id, job] of this.active) {
      if (this.authorize(job)) continue
      job.controller.abort()
      const current = this.storage.worker(id)
      if (current.status === 'running' && current.lease === job.assignment.lease) {
        const run = this.storage.run(current.runId)
        const requeue = run.status === 'running' && current.phase === 'verification' && run.phase === 'analysis'
        const outcome = requeue ? 'Waiting for analysis of the expanded scope.' : 'Assignment authorization changed.'
        this.storage.db.transaction(() => {
          this.storage.updateWorker(id, { status: requeue ? 'queued' : 'canceled', lease: null, outcome })
          this.storage.event(run.id, requeue ? 'worker.waiting' : 'worker.canceled', outcome)
        })
      }
    }
    for (const [runId, task] of this.coordinator) {
      if (!this.currentCoordinator(runId, task)) task.controller.abort()
    }
    let model: ProviderSettings | null
    try {
      model = privateModelSettings()
    } catch {
      return
    }
    for (const run of this.storage.runnable()) {
      if (run.phase === 'analysis' && run.reviewPlan?.status === 'pending') {
        if (model && run.approved.length) this.startPlanning(run, model)
        else this.storage.commitReviewPlan(run.id, run.goalRevision, standardChecks)
        continue
      }
      if (!model) continue
      this.startCoordinator(run, model)
      if (run.phase !== 'analysis' && run.phase !== 'verification') continue
      const workers = this.storage.workerList(run.id).filter(item =>
        item.phase === run.phase && item.goalRevision === run.goalRevision &&
        item.assetId && run.approved.includes(item.assetId))
      const queued = workers.filter(item => item.status === 'queued')
      if (!queued.length && workers.every(item => item.status === 'complete' || item.status === 'canceled')) {
        this.advance(run)
        continue
      }
      for (const worker of queued) {
        if (this.active.size >= 2) return
        if (this.active.has(worker.id)) continue
        this.startWorker(run, worker, model)
      }
    }
  }

  private advance(run: Run) {
    this.storage.db.transaction(() => {
      if (run.phase === 'analysis') {
        const updated = this.storage.updateRun(run.id, { phase: 'verification' })
        const workers = this.storage.workerList(run.id)
        for (const asset of run.candidates.filter(asset => run.approved.includes(asset.id))) {
          if (!assessmentAssignments(workers, asset.id, run.goalRevision).verification) {
            this.storage.makeWorker(updated, 'verification', asset, `Verify ${new URL(asset.origin).hostname}`,
              'Compare the recorded response metadata with the HTTPS and browser header baselines.')
          }
        }
        this.storage.event(run.id, 'verification.started', 'Verification started from recorded evidence.')
        this.storage.message(run.id, run.coordinatorId, 'guardian', 'Analysis complete. Verification is checking the recorded evidence.')
      } else {
        const complete = this.storage.updateRun(run.id, { phase: 'complete', status: 'complete' })
        this.storage.writeReport(complete, false)
        this.storage.message(run.id, run.coordinatorId, 'guardian', 'The complete report is ready.')
      }
    }, { behavior: 'immediate' })
  }

  private startWorker(run: Run, worker: Assignment, model: ProviderSettings) {
    const asset = run.candidates.find(item => item.id === worker.assetId)
    if (!asset) return
    const assignment = this.storage.db.transaction(() => {
      const claimed = this.storage.updateWorker(worker.id, { status: 'running', lease: randomUUID(), outcome: null })
      this.storage.event(run.id, 'worker.started', worker.title + ' started.', { assignmentId: worker.id })
      return claimed
    })
    if (!assignment) return
    const job: Active = { assignment, origins: new Set([asset.origin]), controller: new AbortController() }
    this.active.set(worker.id, job)
    const work = assignment.phase === 'analysis' ? this.analyze(job, asset, model) : this.verify(job, asset)
    void work.catch(() => {
      if (!this.authorize(job) || job.controller.signal.aborted) return
      this.storage.db.transaction(() => {
        const current = this.storage.run(run.id)
        const message = 'An evidence step failed. Check the model connection and local worker image, then resume.'
        this.storage.updateWorker(worker.id, { status: 'failed', outcome: message, lease: null, attempt: worker.attempt + 1 })
        this.storage.event(run.id, 'worker.failed', message)
        this.storage.setStatus(current, 'failed')
        this.storage.writeReport(this.storage.run(run.id), true)
      })
    }).finally(() => {
      this.active.delete(worker.id)
      this.wake()
    })
  }

  private async capture(job: Active, asset: Candidate): Promise<{ capture: Capture; id: string }> {
    const run = this.check(job)
    const operation = 'capture:' + run.scopeRevision
    const saved = this.storage.assignmentObservation(job.assignment.id)
    let capture: Capture
    if (saved) {
      const record = JSON.parse(this.storage.artifact(run.id, saved.id).content) as Capture
      const origins = record.observation ? this.observationOrigins(job.assignment, record.observation) : []
      if ([...origins].every(origin => this.permitted(run, origin))) {
        for (const origin of origins) job.origins.add(origin)
        this.check(job)
        return { capture: record, id: saved.id }
      }
      capture = { observation: null, note: 'The saved observation includes a host outside the current approval.' }
    } else if (run.sourceMode === 'prepared') {
      capture = asset.prepared ? {
        observation: { ...asset.prepared, origin: asset.origin, finalOrigin: asset.origin, source: 'supplied observation' },
        note: 'Supplied project evidence.',
      } : { observation: null, note: 'No prepared observation was supplied.' }
    } else {
      const permittedAtAdmission = new Set(run.candidates.filter(item => run.approved.includes(item.id)).map(item => item.origin))
      try {
        const observation = await this.broker.readPublicRoot({
          origin: asset.origin,
          canRead: origin => this.authorize(job) && permittedAtAdmission.has(origin) &&
            this.permitted(this.storage.run(run.id), origin),
          audit: (outcome, origin, status) => {
            if (outcome === 'allowed') job.origins.add(origin)
            this.storage.event(run.id, 'broker.' + outcome, `Public response read ${outcome} for ${new URL(origin).hostname}.`,
              { assignmentId: job.assignment.id, origin, status })
          },
        }, job.controller.signal)
        capture = { observation, note: 'Recorded selected metadata from the approved public response.' }
      } catch (error) {
        this.check(job)
        capture = { observation: null, note: error instanceof BrokerDenied
          ? error.message : 'The approved public response could not be read.' }
      }
    }
    const updated = this.check(job)
    const evidence = this.storage.db.transaction(() => {
      const item = this.storage.addArtifact(updated, job.assignment, 'observation', 'Observed public response',
        JSON.stringify(capture, null, 2), operation)
      this.storage.event(run.id, 'evidence.committed', 'Response evidence recorded.', { assignmentId: job.assignment.id, artifactId: item.id })
      return item
    })
    return { capture, id: evidence.id }
  }

  private async analyze(job: Active, asset: Candidate, model: ProviderSettings) {
    const { capture, id } = await this.capture(job, asset)
    const run = this.check(job)
    const selectedChecks = run.reviewPlan?.status === 'ready' ? run.reviewPlan.checks : undefined
    let summary = capture.note
    if (capture.observation) {
      const input = workerInput(capture.observation, selectedChecks)
      const inputs = [{ name: 'observed.json', content: JSON.stringify(input.evidence) }]
      summary = await agentTurn({
        directory: this.storage.directory, sessionId: job.assignment.sessionId,
        requestId: 'analysis:' + job.assignment.attempt + ':' + id,
        settings: model, scenario: input.scenario, prompt: input.prompt,
        signal: job.controller.signal,
        derive: async (command, signal) => {
          const operation = 'derive:' + createHash('sha256').update(id).update(command).digest('hex')
          const earlier = this.storage.assignmentEvidence(job.assignment.id, operation)
          if (earlier) return derivedResult(JSON.parse(this.storage.artifact(run.id, earlier.id).content))
          this.check(job)
          const result = await this.backend.run({
            assignmentId: job.assignment.id, files: inputs, command, outputs: ['result.txt'],
          }, signal)
          const current = this.check(job)
          const receipt = this.storage.db.transaction(() => this.storage.addArtifact(
            current, job.assignment, 'analysis', 'Derived evidence',
            JSON.stringify({
              command: redact(command), inputEvidence: [id], inputFields: Object.keys(input.evidence), interpreter: 'just-bash 3.6.1',
              exitStatus: result.exitCode, stdout: result.stdout, stderr: result.stderr,
              result: result.outputs['result.txt'] ?? '',
            }, null, 2), operation))
          return derivedResult(JSON.parse(this.storage.artifact(run.id, receipt.id).content))
        },
      })
    }

    const current = this.check(job)
    this.storage.db.transaction(() => {
      for (const review of responseReview(capture.observation, capture.note, selectedChecks)) {
        if (review.comparison && !meetsBaseline(review.comparison)) {
          const reason = 'The recorded value falls outside the response baseline. Verification is pending.'
          const earlier = this.finding(current, asset, review.rule.id)
          this.saveFinding(current, asset, review, 'pending', reason, [id], earlier?.id)
        }
      }
      this.complete(job, current, summary, id)
    }, { behavior: 'immediate' })
  }

  private async verify(job: Active, asset: Candidate) {
    const run = this.check(job)
    const { analysis } = assessmentAssignments(this.storage.workerList(run.id), asset.id, run.goalRevision)
    const stored = analysis?.status === 'complete' ? this.storage.assignmentObservation(analysis.id) : undefined
    const record = stored ? JSON.parse(this.storage.artifact(run.id, stored.id).content) as Capture : undefined
    const origins = analysis && record?.observation ? this.observationOrigins(analysis, record.observation) : []
    const authorized = [...origins].every(origin => this.permitted(run, origin))
    const observation = authorized ? record?.observation : null
    const note = authorized ? record?.note : 'The saved observation includes a host outside the current approval.'
    const selectedChecks = run.reviewPlan?.status === 'ready' ? run.reviewPlan.checks : undefined
    const reviews = responseReview(observation, note, selectedChecks)
    const comparisons = reviews.flatMap(review => review.comparison ? [review.comparison] : [])
    if (authorized) for (const origin of origins) job.origins.add(origin)
    const result = comparisons.length ? await this.backend.run({
      assignmentId: job.assignment.id,
      files: [{ name: 'checks.json', content: JSON.stringify(comparisons) }],
      command: responseVerificationCommand, outputs: ['verification.json'],
    }, job.controller.signal) : undefined
    const outcomes = readComparisons(result?.exitCode === 0 ? result.outputs['verification.json'] : undefined)
    const checks = reviews.map(review => checkCoverage(review, outcomes.get(review.rule.id)))

    const current = this.check(job)
    const assessed = checks.filter(check => check.status === 'met' || check.status === 'gap').length
    const gaps = checks.filter(check => check.status === 'gap').length
    const outcome = assessed
      ? `${assessed} checks verified · ${gaps === 1 ? '1 gap' : gaps + ' gaps'}`
      : 'Inconclusive: ' + checks[0].reason
    this.storage.db.transaction(() => {
      const inputs = authorized && stored ? [stored.id] : []
      const evidence = this.storage.addArtifact(current, job.assignment, 'verification', 'Response policy verification',
        JSON.stringify({
          origin: asset.origin, inputEvidence: inputs, checks, comparisons,
          command: result ? responseVerificationCommand : undefined,
          exitStatus: result?.exitCode, interpreter: result ? 'just-bash 3.6.1' : undefined,
        }, null, 2), 'verification')
      const links = [...inputs, evidence.id]
      for (const [index, review] of reviews.entries()) {
        const { status, reason } = checks[index]
        const earlier = this.finding(current, asset, review.rule.id)
        if (status === 'gap') this.saveFinding(current, asset, review, 'confirmed', reason, links, earlier?.id)
        else if (status === 'inconclusive' && (earlier || review.rule.id === 'hsts')) {
          this.saveFinding(current, asset, review, 'inconclusive', reason, links, earlier?.id)
        } else if (earlier) this.saveFinding(current, asset, review, 'dismissed', reason, links, earlier.id)
      }
      this.complete(job, current, outcome, evidence.id, checks)
    }, { behavior: 'immediate' })
  }

  private finding(run: Run, asset: Candidate, checkId: ResponseCheckId) {
    return this.storage.db.select().from(findings).where(and(
      eq(findings.runId, run.id), eq(findings.assetId, asset.id), eq(findings.goalRevision, run.goalRevision),
      eq(findings.checkId, checkId),
    )).get()
  }

  private saveFinding(run: Run, asset: Candidate, review: ResponseReview, status: Finding['status'], reason: string,
    evidenceIds: string[], existingId?: string) {
    const { rule, coverage } = review
    const confirmed = status === 'confirmed'
    const record: Finding = {
      id: existingId ?? randomUUID(),
      origin: asset.origin,
      title: status === 'inconclusive' ? rule.title + ' could not be assessed' : rule.findingTitle,
      status, severity: confirmed ? rule.severity : 'informational',
      reason,
      remediation: confirmed ? rule.remediation : status === 'inconclusive'
        ? 'Supply a current authorized response record and repeat the review.'
        : status === 'pending' ? 'Resume the run to verify the observation.' : 'Review the verification evidence.',
      impact: confirmed ? rule.impact : undefined,
      recheck: confirmed ? rule.recheck : undefined,
      check: { id: rule.id, expected: coverage.expected, observed: coverage.observed },
      evidenceIds, scopeRevision: run.scopeRevision,
    }
    if (existingId) this.storage.db.update(findings).set({ finding: record }).where(eq(findings.id, record.id)).run()
    else this.storage.db.insert(findings).values({
      id: record.id, runId: run.id, assetId: asset.id, goalRevision: run.goalRevision, checkId: rule.id, finding: record,
    }).run()
  }

  private complete(job: Active, run: Run, summary: string, artifactId: string, checks?: CheckCoverage[]) {
    const worker = job.assignment
    const outcome = redact(summary)
    this.storage.addArtifact(run, worker, 'handoff', 'result.md', [
      '# Result', '', outcome, '', 'Evidence: ' + artifactId,
    ].join('\n'), 'result')
    this.storage.updateWorker(worker.id, { status: 'complete', lease: null, outcome, checks })
    this.storage.message(run.id, worker.id, 'worker', outcome)
    this.storage.event(run.id, 'worker.complete', worker.title + ' completed.', { assignmentId: worker.id, artifactId })
  }

  private startPlanning(run: Run, model: ProviderSettings) {
    if (this.coordinator.has(run.id) || run.reviewPlan?.status !== 'pending') return
    const controller = new AbortController()
    const task: CoordinatorTask = { controller, goalRevision: run.goalRevision }
    this.coordinator.set(run.id, task)
    void agentTurn({
      directory: this.storage.directory, sessionId: run.reviewPlan.goalMessageId, requestId: 'plan',
      settings: model, scenario: 'coordinator-plan', prompt: reviewPlanPrompt(run.goal, run.sourceMode),
      signal: controller.signal,
    }).then(answer => parseReviewPlan(answer) ?? standardChecks, () => standardChecks).then(selection => {
      if (!this.currentCoordinator(run.id, task)) return
      this.storage.commitReviewPlan(run.id, run.goalRevision, selection)
    }).catch(() => {
      if (!this.currentCoordinator(run.id, task)) return
      this.storage.db.transaction(() => {
        const current = this.storage.run(run.id)
        this.storage.setStatus(current, 'failed')
        this.storage.event(run.id, 'review.plan_failed', 'The review plan could not be saved. Resume to retry.')
        this.storage.writeReport(this.storage.run(run.id), true)
      })
    }).finally(() => {
      this.coordinator.delete(run.id)
      this.wake()
    })
  }

  private startCoordinator(run: Run, model: ProviderSettings) {
    if (this.coordinator.has(run.id)) return
    const thread = this.storage.db.select().from(messages).where(and(
      eq(messages.runId, run.id), eq(messages.threadId, run.coordinatorId),
    )).orderBy(asc(messages.createdAt)).all()
    const answered = new Set(thread.map(item => item.replyTo))
    const next = thread.find(item => item.role === 'operator' && !answered.has(item.id))
    if (!next) return
    const controller = new AbortController()
    const task: CoordinatorTask = {
      controller, goalRevision: run.goalRevision,
      scopeRevision: run.reviewPlan ? run.scopeRevision : undefined,
    }
    this.coordinator.set(run.id, task)
    const workers = this.storage.workerList(run.id)
    const prompt = coordinatorPrompt({
      phase: run.phase, status: run.status, approved: run.approved.length,
      queued: workers.filter(worker => worker.status === 'queued').length,
      complete: workers.filter(worker => worker.status === 'complete').length, question: next.content,
    })
    void agentTurn({
      directory: this.storage.directory, sessionId: run.coordinatorId,
      requestId: run.reviewPlan ? `${next.id}:${run.goalRevision}:${run.scopeRevision}` : next.id,
      settings: model, scenario: 'coordinator', prompt, signal: controller.signal,
    }).then(answer => {
      if (!this.currentCoordinator(run.id, task)) return
      this.storage.db.transaction(() => {
        this.storage.message(run.id, run.coordinatorId, 'coordinator', answer, next.id)
        this.storage.event(run.id, 'coordinator.reply', 'The coordinator replied.')
      })
    }).catch(() => {
      if (!this.currentCoordinator(run.id, task)) return
      this.storage.db.transaction(() => {
        this.storage.message(run.id, run.coordinatorId, 'guardian', 'The coordinator could not reach the model. Review the workflow for current progress.', next.id)
        this.storage.event(run.id, 'coordinator.unavailable', 'The coordinator could not complete its reply.')
      })
    }).finally(() => {
      this.coordinator.delete(run.id)
    })
  }
}

let instance: Execution | undefined
export function execution() {
  return instance ??= new Execution(store())
}
