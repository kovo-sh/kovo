import { createHash, randomUUID } from 'node:crypto'
import { and, asc, eq } from 'drizzle-orm'
import type { Candidate, Finding, ProviderSettings } from '../domain.ts'
import { agentTurn, coordinatorPrompt, workerPrompt } from './agent-session.ts'
import { BrokerDenied, RequestBroker } from './broker.ts'
import type { PublicObservation } from './broker.ts'
import { privateModelSettings } from './model-settings.ts'
import { redact } from './redact.ts'
import { findings, messages } from './schema.ts'
import { store } from './store.ts'
import type { Assignment, Run, Store } from './store.ts'
import { LinuxWorkerBackend } from './worker-backend.ts'

type Active = {
  assignment: Assignment
  origins: Set<string>
  controller: AbortController
}
type Capture = { observation: PublicObservation | null; note: string }

export function derivedResult(result: { exitStatus: number; result: string; stdout: string }) {
  return JSON.stringify({ exitStatus: result.exitStatus, result: (result.result || result.stdout).slice(0, 1200) })
}

const verificationCommand = [
  "jq '{expected: \"positive HSTS max-age\", observed: .transportMaxAge, result:",
  '  (if .status >= 200 and .status < 300 then',
  '     if (.transportMaxAge // 0) > 0 then "present" else "missing" end',
  '   else "inconclusive" end)}\' /evidence/observed.json > /work/verification.json',
].join('\n')

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
  private readonly coordinator = new Map<string, AbortController>()
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

  private authorize(job: Active) {
    const current = this.storage.worker(job.assignment.id)
    const run = this.storage.run(current.runId)
    return current.status === 'running' && current.lease === job.assignment.lease &&
      run.status === 'running' && run.phase === current.phase && current.goalRevision === run.goalRevision &&
      [...job.origins].every(origin => this.permitted(run, origin))
  }

  private check(job: Active) {
    job.controller.signal.throwIfAborted()
    if (!this.authorize(job)) throw new BrokerDenied('The assignment is no longer authorized.')
    return this.storage.run(job.assignment.runId)
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
    for (const [runId, controller] of this.coordinator) {
      if (this.storage.run(runId).status !== 'running') controller.abort()
    }
    let model: ProviderSettings | null
    try {
      model = privateModelSettings()
    } catch {
      return
    }
    if (!model) return
    for (const run of this.storage.runnable()) {
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
        const planned = this.storage.workerList(run.id).filter(item =>
          item.phase === 'verification' && item.goalRevision === run.goalRevision && item.status !== 'canceled')
        for (const asset of run.candidates.filter(asset => run.approved.includes(asset.id))) {
          if (!planned.some(worker => worker.assetId === asset.id)) {
            this.storage.makeWorker(updated, 'verification', asset, `Verify ${new URL(asset.origin).hostname}`,
              'Compare the recorded public response metadata with the transport policy baseline.')
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
    const saved = this.storage.assignmentEvidence(job.assignment.id, operation)
    if (saved) {
      const record = JSON.parse(this.storage.artifact(run.id, saved.id).content) as Capture
      if (record.observation) job.origins.add(record.observation.finalOrigin)
      this.check(job)
      return { capture: record, id: saved.id }
    }
    let capture: Capture
    if (run.sourceMode === 'prepared') {
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
    let summary = capture.note
    if (capture.observation) {
      const inputs = [{ name: 'observed.json', content: JSON.stringify(capture.observation) }]
      summary = await agentTurn({
        directory: this.storage.directory, sessionId: job.assignment.sessionId,
        requestId: 'analysis:' + job.assignment.attempt + ':' + id,
        settings: model, scenario: 'worker-analysis', prompt: workerPrompt(capture.observation),
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
              command: redact(command), inputEvidence: [id], interpreter: 'just-bash 3.6.1',
              exitStatus: result.exitCode, stdout: result.stdout, stderr: result.stderr,
              result: result.outputs['result.txt'] ?? '',
            }, null, 2), operation))
          return derivedResult(JSON.parse(this.storage.artifact(run.id, receipt.id).content))
        },
      })
    }

    const current = this.check(job)
    const observation = capture.observation
    this.storage.db.transaction(() => {
      if (observation && observation.status >= 200 && observation.status < 300 && !observation.transportMaxAge) {
        this.saveFinding(current, asset, 'pending', 'The recorded response did not show a positive HSTS max-age.', [id])
      }
      this.complete(job, current, summary, id)
    }, { behavior: 'immediate' })
  }

  private async verify(job: Active, asset: Candidate) {
    const run = this.check(job)
    const detail = this.storage.runDetail(run.id)
    const analysis = [...detail.assignments].reverse().find(worker =>
      worker.phase === 'analysis' && worker.assetId === asset.id && worker.goalRevision === run.goalRevision && worker.status === 'complete')
    const stored = analysis && [...detail.evidence].reverse().find(item => item.assignmentId === analysis.id && item.kind === 'observation')
    const record = stored ? JSON.parse(this.storage.artifact(run.id, stored.id).content) as Capture : undefined
    let observation = record?.observation
    if (observation && !this.permitted(run, observation.finalOrigin)) observation = null
    let status = 'inconclusive'
    let transcript: object = { expected: 'positive HSTS max-age', observed: null, result: status }
    let command: string | undefined
    let exitStatus: number | undefined
    if (observation) {
      job.origins.add(observation.finalOrigin)
      command = verificationCommand
      const result = await this.backend.run({
        assignmentId: job.assignment.id,
        files: [{ name: 'observed.json', content: JSON.stringify(observation) }],
        command, outputs: ['verification.json'],
      }, job.controller.signal)
      exitStatus = result.exitCode
      if (result.exitCode === 0 && result.outputs['verification.json']) {
        const parsed = JSON.parse(result.outputs['verification.json'])
        if (['present', 'missing', 'inconclusive'].includes(parsed.result)) {
          status = parsed.result
          transcript = parsed
        }
      }
    }

    const current = this.check(job)
    const reason = status === 'present' ? 'The recorded response matches the expected transport policy.'
      : status === 'missing' ? 'The recorded successful HTTPS response did not contain a positive HSTS max-age.'
        : 'Inconclusive: a successful response with a current evidence source was unavailable.'
    this.storage.db.transaction(() => {
      const evidence = this.storage.addArtifact(current, job.assignment, 'verification', 'Transport policy verification',
        JSON.stringify({ ...transcript, command, exitStatus, inputEvidence: observation && stored ? [stored.id] : [],
          interpreter: command ? 'just-bash 3.6.1' : undefined }, null, 2), 'verification')
      const links = observation && stored ? [stored.id, evidence.id] : [evidence.id]
      if (status === 'missing') this.saveFinding(current, asset, 'confirmed', reason, links)
      else if (status === 'inconclusive') this.saveFinding(current, asset, 'inconclusive', reason, links)
      else if (this.finding(current, asset)) this.saveFinding(current, asset, 'dismissed', reason, links)
      this.complete(job, current, reason, evidence.id)
    }, { behavior: 'immediate' })
  }

  private finding(run: Run, asset: Candidate) {
    return this.storage.db.select().from(findings).where(and(
      eq(findings.runId, run.id), eq(findings.assetId, asset.id), eq(findings.goalRevision, run.goalRevision),
    )).get()
  }

  private saveFinding(run: Run, asset: Candidate, status: Finding['status'], reason: string, evidenceIds: string[]) {
    const existing = this.finding(run, asset)
    const record: Finding = {
      id: existing?.id ?? randomUUID(),
      origin: asset.origin,
      title: status === 'inconclusive' ? 'Transport policy could not be assessed' : 'Public response transport policy',
      status, severity: status === 'confirmed' ? 'low' : 'informational',
      reason,
      remediation: status === 'inconclusive' ? 'Supply an authorized response record and repeat the review.'
        : status === 'confirmed' ? 'Review the HTTPS transport policy for this host and set a suitable HSTS max-age where appropriate.'
          : 'See verification evidence.',
      evidenceIds, scopeRevision: run.scopeRevision,
    }
    if (existing) this.storage.db.update(findings).set({ finding: record }).where(eq(findings.id, record.id)).run()
    else this.storage.db.insert(findings).values({
      id: record.id, runId: run.id, assetId: asset.id, goalRevision: run.goalRevision, finding: record,
    }).run()
  }

  private complete(job: Active, run: Run, summary: string, artifactId: string) {
    const worker = job.assignment
    const outcome = redact(summary)
    this.storage.addArtifact(run, worker, 'handoff', 'result.md', [
      '# Result', '', outcome, '', 'Evidence: ' + artifactId,
    ].join('\n'), 'result')
    this.storage.updateWorker(worker.id, { status: 'complete', lease: null, outcome })
    this.storage.message(run.id, worker.id, 'worker', outcome)
    this.storage.event(run.id, 'worker.complete', worker.title + ' completed.', { assignmentId: worker.id, artifactId })
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
    this.coordinator.set(run.id, controller)
    const workers = this.storage.workerList(run.id)
    const prompt = coordinatorPrompt({
      phase: run.phase, status: run.status, approved: run.approved.length,
      queued: workers.filter(worker => worker.status === 'queued').length,
      complete: workers.filter(worker => worker.status === 'complete').length, question: next.content,
    })
    void agentTurn({
      directory: this.storage.directory, sessionId: run.coordinatorId, requestId: next.id,
      settings: model, scenario: 'coordinator', prompt, signal: controller.signal,
    }).then(answer => {
      if (controller.signal.aborted || this.storage.run(run.id).status !== 'running') return
      this.storage.db.transaction(() => {
        this.storage.message(run.id, run.coordinatorId, 'coordinator', answer, next.id)
        this.storage.event(run.id, 'coordinator.reply', 'The coordinator replied.')
      })
    }).catch(() => {
      if (controller.signal.aborted || this.storage.run(run.id).status !== 'running') return
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
