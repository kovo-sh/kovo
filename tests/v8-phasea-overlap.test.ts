/**
 * v8 Phase A Overlap — concurrent `code_audit` + deterministic `floor` contracts.
 *
 * Proves (zero Docker, real SQLite WAL `Store`, real `Execution`, real `ExecFloorLane`):
 *  1. `runSourceFirstCodeAudit` starts the deterministic `floor` concurrently during `threat_model`
 *     while `code_audit` is still running, passes `allowThreatModelPhase: true`, and `wake()` keeps
 *     the overlapped floor alive throughout `threat_model` (while still aborting if the run stops).
 *  2. Ordering B (`code_audit` finishes before `floor`): `post-floor` checkpoint is deferred while
 *     `floor` is still in flight, Phase B (`driveInvestigation`) yields until `floor` settles, split
 *     `request_budget.floor_settled` stays exact, and `post-floor` fires once when `floor` finishes.
 *  3. Ordering A (`floor` finishes before `code_audit`): `floor` settles cleanly during
 *     `threat_model` without emitting a premature `post-floor`, `post-floor` fires once upon
 *     entering `investigation`, and Phase B dispatches immediately without re-running `floor`.
 *  4. `ExecFloorLane.runEngineInvestigation` rejects `threat_model` unless `allowThreatModelPhase`
 *     is set, and runs cleanly when `allowThreatModelPhase: true`.
 *  5. `--no-llm` / `deterministicOnly` and `deterministicSweep: false` paths are untouched.
 */
import assert from 'node:assert/strict'
import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from 'node:fs'
import { createServer, type Server } from 'node:http'
import type { AddressInfo } from 'node:net'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { test } from 'node:test'
import { setTimeout as delay } from 'node:timers/promises'

import { Execution, type ExecutionCheckpoint } from '../src/server/execution.ts'
import type { ExecFloorLane } from '../src/server/exec-floor-lane.ts'
import { privateModelProfiles, saveModelProfile } from '../src/server/model-settings.ts'
import type { ChainStep, Run } from '../src/server/store.ts'
import type { WorkerBackend, WorkerSession } from '../src/server/worker-backend.ts'
import { makeStore, setupApprovedRun } from './v4-tier-helpers.ts'

process.env.GUARDIAN_ALLOW_LOCAL_LAB = '1'

const ORIGIN_API = 'http://api.overlap.test:8081'

function stubBackend(): WorkerBackend {
  return {
    async run() { return { exitCode: 0, stdout: '{}', stderr: '', outputs: {} } },
    async openSession(): Promise<WorkerSession> {
      return {
        stage: async name => `/evidence/${name}`,
        exec: async () => ({ exitCode: 0, stdout: '', stderr: '', outputs: {} }),
        analyze: async () => ({ ok: true }),
        sast: async req => ({ repo: req.repo, enginesRun: [], engineStatus: {}, findings: [], totalFindings: 0, truncated: false, durationMs: 1 }),
        runScript: async req => ({ runtime: req.runtime, exitCode: 0, stdout: '', stderr: '', durationMs: 1, timedOut: false }),
        verifyStaticAst: async req => ({ verified: false, engine: req.engine, repo: req.repo, file: req.file, startLine: req.startLine, endLine: req.endLine, matchedLines: [], codeExcerpt: '', matchCount: 0, durationMs: 1 }),
        close: async () => undefined,
      }
    },
    async verifyStaticAst(_aid, req) {
      return { verified: false, engine: req.engine, repo: req.repo, file: req.file, startLine: req.startLine, endLine: req.endLine, matchedLines: [], codeExcerpt: '', matchCount: 0, durationMs: 1 }
    },
  }
}

type LaneCallOpts = {
  signal?: AbortSignal
  maxDurationMs?: number
  onAssignment?: (assignmentId: string) => void
  allowThreatModelPhase?: boolean
}

type ExecInternals = {
  floorLane: ExecFloorLane
  reconPlanner: { startCoordinator: (...args: unknown[]) => void }
  startThreatModel: (...args: unknown[]) => void
  driveInvestigation: (run: Run, profiles: readonly unknown[]) => void
  shouldStartDeterministicLane: (run: Run, profiles: readonly unknown[], options?: { allowThreatModelPhase?: boolean }) => boolean
  startDeterministicLane: (run: Run, profiles: readonly unknown[], options?: { allowThreatModelPhase?: boolean }) => boolean
  runEngineInvestigation: (run: Run, opts?: LaneCallOpts) => Promise<void>
  startInvestigationStep: (run: Run, step: ChainStep, profiles: readonly unknown[]) => void
  notifyCheckpoint: (runId: string, checkpoint: ExecutionCheckpoint) => void
  prePhase0SeededSteps: Map<string, boolean>
  agenticLaneJobs: Map<string, { controller: AbortController; promise: Promise<void>; key: string; assignmentId: string; allowThreatModelPhase?: boolean }>
  agenticLaneCompleted: Set<string>
  projectReposMount: (projectId: string) => { reposDir?: string; mountedRepos: string[] }
  phaseRequestRemaining: (run: Run) => number | null
}

function internals(execution: Execution): ExecInternals {
  return execution as unknown as ExecInternals
}

function laneKey(run: Run): string {
  return `${run.id}:${run.goalRevision}:${run.scopeRevision}`
}

function addReadyStep(storage: ReturnType<typeof makeStore>['storage'], run: Run): ChainStep {
  const assetIds = run.candidates.filter(c => run.approved.includes(c.id)).map(c => c.id)
  const origin = run.candidates.find(c => run.approved.includes(c.id))?.origin ?? ORIGIN_API
  const step = storage.addChainStep(run, {
    title: 'Cross-persona authorization probe',
    hypothesis: 'Verify object-level access enforcement across member and admin roles.',
    category: 'broken-access-control',
    priority: 80,
    targetAssetIds: assetIds,
    sourceOrigins: [origin],
  })
  storage.updateChainStep(step.id, { status: 'ready' })
  return storage.listChainSteps(run.id, run.goalRevision).find(s => s.id === step.id)!
}

async function startMockAuditServer(
  t: Parameters<typeof makeStore>[0],
  onRequest?: () => Promise<void>,
): Promise<number> {
  const server: Server = createServer((req, res) => {
    req.resume()
    req.on('end', () => {
      void (async () => {
        if (onRequest) await onRequest()
        res.statusCode = 200
        res.setHeader('Content-Type', 'text/event-stream')
        const emit = (event: string, data: Record<string, unknown>) => {
          res.write(`event: ${event}\ndata: ${JSON.stringify(data)}\n\n`)
        }
        const args = JSON.stringify({ status: 'completed', summary: 'Audit complete.' })
        emit('response.created', { type: 'response.created', response: { id: 'resp_overlap', status: 'in_progress', output: [] } })
        emit('response.output_item.added', {
          type: 'response.output_item.added',
          output_index: 0,
          item: { id: 'item_1', type: 'function_call', status: 'in_progress', call_id: 'call_1', name: 'complete_intent', arguments: '' },
        })
        emit('response.function_call_arguments.done', {
          type: 'response.function_call_arguments.done',
          output_index: 0,
          item_id: 'item_1',
          name: 'complete_intent',
          arguments: args,
        })
        emit('response.output_item.done', {
          type: 'response.output_item.done',
          output_index: 0,
          item: { id: 'item_1', type: 'function_call', status: 'completed', call_id: 'call_1', name: 'complete_intent', arguments: args },
        })
        emit('response.completed', {
          type: 'response.completed',
          response: {
            id: 'resp_overlap',
            status: 'completed',
            output: [{ id: 'item_1', type: 'function_call', status: 'completed', call_id: 'call_1', name: 'complete_intent', arguments: args }],
            usage: { input_tokens: 40, output_tokens: 15, total_tokens: 55 },
          },
        })
        res.write('data: [DONE]\n\n')
        res.end()
      })()
    })
  })
  await new Promise<void>(resolve => server.listen(0, '127.0.0.1', () => resolve()))
  const port = (server.address() as AddressInfo).port
  t.after(async () => {
    server.closeAllConnections?.()
    await new Promise<void>(resolve => server.close(() => resolve()))
  })
  return port
}

async function createMockProfile(storage: ReturnType<typeof makeStore>['storage'], port: number) {
  await saveModelProfile({
    name: 'Mock Overlap Reasoning',
    endpoint: `http://127.0.0.1:${port}/v1`,
    model: 'mock-overlap-model',
    protocol: 'responses',
    key: 'sk-test-overlap-1234',
    priority: 100,
    enabled: true,
    contextWindow: 128_000,
    maxTokens: 4_096,
    thinkingLevel: 'medium',
    roleAffinity: 'reasoning',
    inputCostPerMtok: 0,
    cachedInputCostPerMtok: 0,
    outputCostPerMtok: 0,
  }, storage, { skipConnectionCheck: true })
  return privateModelProfiles(storage)
}

function makeMountedRepo(t: Parameters<typeof makeStore>[0]): string {
  const reposDir = mkdtempSync(join(tmpdir(), 'guardian-overlap-repo-'))
  mkdirSync(join(reposDir, 'demo-service'), { recursive: true })
  writeFileSync(join(reposDir, 'demo-service', 'app.ts'), 'export const health = () => ({ ok: true })\n', 'utf8')
  t.after(() => rmSync(reposDir, { recursive: true, force: true }))
  return reposDir
}

function disableStage1Llm(t: Parameters<typeof makeStore>[0]): void {
  const prev = process.env.GUARDIAN_STAGE1_LLM
  process.env.GUARDIAN_STAGE1_LLM = '0'
  t.after(() => {
    if (prev === undefined) delete process.env.GUARDIAN_STAGE1_LLM
    else process.env.GUARDIAN_STAGE1_LLM = prev
  })
}

// ============================================================================
// 1. Overlap during threat_model + code_audit finishes before floor (Ordering B)
// ============================================================================

test('Phase A overlap: floor starts during threat_model while code_audit runs, blocks Phase B, and fires post-floor once on settle', async (t) => {
  disableStage1Llm(t)
  const { storage } = makeStore(t)
  const { runId } = await setupApprovedRun(storage, { seeds: [ORIGIN_API], tier: 2, budgetRequests: 31_000 })
  storage.updateRun(runId, { phase: 'threat_model', status: 'running', spentRequests: 25 })
  const reposDir = makeMountedRepo(t)

  let auditRequestReceived!: () => void
  const auditInFlight = new Promise<void>(resolve => { auditRequestReceived = resolve })
  let releaseAudit!: () => void
  const auditGate = new Promise<void>(resolve => { releaseAudit = resolve })

  const port = await startMockAuditServer(t, async () => {
    auditRequestReceived()
    await auditGate
  })
  const profiles = await createMockProfile(storage, port)

  const checkpoints: ExecutionCheckpoint[] = []
  const execution = new Execution(storage, {
    deterministicSweep: true,
    maxDurationMs: 600_000,
    floorRequestBudget: 6_000,
    agentRequestBudget: 25_000,
    backend: stubBackend(),
    onCheckpoint: event => checkpoints.push(event.checkpoint),
  })
  t.after(() => execution.stop())

  const eng = internals(execution)
  eng.projectReposMount = () => ({ reposDir, mountedRepos: ['demo-service'] })
  eng.prePhase0SeededSteps.set(laneKey(storage.run(runId)), false)
  eng.startThreatModel = () => undefined
  eng.reconPlanner.startCoordinator = () => undefined

  let releaseFloor!: () => void
  const floorGate = new Promise<void>(resolve => { releaseFloor = resolve })
  t.after(() => { releaseAudit(); releaseFloor() })
  const floorCalls: Array<{ phaseAtStart: string; allowThreatModelPhase?: boolean; signal?: AbortSignal }> = []
  eng.runEngineInvestigation = async (r, opts = {}) => {
    floorCalls.push({
      phaseAtStart: storage.run(r.id).phase,
      allowThreatModelPhase: opts.allowThreatModelPhase,
      signal: opts.signal,
    })
    opts.onAssignment?.('overlap-floor-assignment')
    // Simulate floor HTTP spend while code_audit sends 0 target requests.
    storage.updateRun(r.id, { spentRequests: storage.run(r.id).spentRequests + 42 })
    await floorGate
  }
  const dispatched: string[] = []
  eng.startInvestigationStep = (_r, step) => {
    dispatched.push(step.id)
    storage.updateChainStep(step.id, { status: 'running' })
  }

  // Kick off code_audit during threat_model.
  const auditPromise = execution.runSourceFirstCodeAudit(storage.run(runId), [], profiles, new AbortController().signal)
  await auditInFlight

  // Both code_audit and floor must be running concurrently during threat_model!
  assert.equal(floorCalls.length, 1, 'deterministic floor must start concurrently with code_audit')
  assert.equal(floorCalls[0]!.phaseAtStart, 'threat_model', 'floor must launch while run is still in threat_model')
  assert.equal(floorCalls[0]!.allowThreatModelPhase, true, 'floor must receive allowThreatModelPhase: true')
  assert.equal(eng.agenticLaneJobs.has(runId), true, 'floor lane must be tracked as active')
  assert.equal(floorCalls[0]!.signal?.aborted, false)

  // A scheduler wake() during threat_model must NOT abort the overlapped floor lane.
  execution.wake()
  await delay(10)
  assert.equal(floorCalls[0]!.signal?.aborted, false, 'wake() during threat_model must keep overlapped floor alive')
  assert.equal(eng.agenticLaneJobs.has(runId), true)

  // Now let code_audit finish BEFORE floor settles, transition to investigation, and fire recon-planner post-floor.
  releaseAudit()
  await auditPromise
  addReadyStep(storage, storage.run(runId))
  storage.updateRun(runId, { phase: 'investigation', status: 'running' })
  eng.notifyCheckpoint(runId, 'post-floor')

  // post-floor must be deferred while floor is still in flight so snapshots capture completed floor.
  assert.deepEqual(checkpoints, [], 'post-floor checkpoint must wait until overlapped floor completes')

  // Phase B must still yield while overlapped floor is draining.
  eng.driveInvestigation(storage.run(runId), profiles)
  assert.equal(dispatched.length, 0, 'Phase B specialist must not dispatch while overlapped floor is in flight')
  assert.equal(floorCalls.length, 1, 'driveInvestigation must not double-start the floor')

  // Release floor: it settles split request budgets and fires post-floor cleanly.
  releaseFloor()
  await delay(25)

  assert.equal(eng.agenticLaneJobs.has(runId), false, 'floor job cleared after settle')
  assert.equal(eng.agenticLaneCompleted.has(laneKey(storage.run(runId))), true, 'floor marked completed')
  assert.deepEqual(checkpoints, ['post-floor'], 'post-floor checkpoint fires once when floor settles in investigation')

  const settled = storage.eventsAfter(runId, 0).find(e => e.kind === 'request_budget.floor_settled')
  assert.ok(settled, 'request_budget.floor_settled must be emitted')
  assert.equal(settled.detail.floorRequests, 42, 'split floor request accounting stays exact with 0 audit target traffic')
  assert.equal(eng.phaseRequestRemaining(storage.run(runId)), 25_000, 'Phase B retains its full allowance')

  // Next Phase B tick dispatches immediately without re-running floor.
  eng.driveInvestigation(storage.run(runId), profiles)
  assert.equal(dispatched.length, 1, 'Phase B dispatches once floor has settled')
  assert.equal(floorCalls.length, 1, 'floor runs at most once')
})

// ============================================================================
// 2. Ordering A: floor finishes before code_audit
// ============================================================================

test('Phase A overlap: when floor finishes before code_audit, post-floor fires once upon entering investigation and Phase B runs immediately', async (t) => {
  disableStage1Llm(t)
  const { storage } = makeStore(t)
  const { runId } = await setupApprovedRun(storage, { seeds: [ORIGIN_API], tier: 2 })
  storage.updateRun(runId, { phase: 'threat_model', status: 'running' })
  const reposDir = makeMountedRepo(t)

  let auditRequestReceived!: () => void
  const auditInFlight = new Promise<void>(resolve => { auditRequestReceived = resolve })
  let releaseAudit!: () => void
  const auditGate = new Promise<void>(resolve => { releaseAudit = resolve })

  const port = await startMockAuditServer(t, async () => {
    auditRequestReceived()
    await auditGate
  })
  const profiles = await createMockProfile(storage, port)

  const checkpoints: ExecutionCheckpoint[] = []
  const execution = new Execution(storage, {
    deterministicSweep: true,
    backend: stubBackend(),
    onCheckpoint: event => checkpoints.push(event.checkpoint),
  })
  t.after(() => execution.stop())

  const eng = internals(execution)
  eng.projectReposMount = () => ({ reposDir, mountedRepos: ['demo-service'] })
  eng.prePhase0SeededSteps.set(laneKey(storage.run(runId)), false)

  let floorRuns = 0
  eng.runEngineInvestigation = async () => {
    floorRuns += 1
    // Finish immediately while code_audit is still in threat_model.
  }
  const dispatched: string[] = []
  eng.startInvestigationStep = (_r, step) => {
    dispatched.push(step.id)
    storage.updateChainStep(step.id, { status: 'running' })
  }

  const auditPromise = execution.runSourceFirstCodeAudit(storage.run(runId), [], profiles, new AbortController().signal)
  await auditInFlight
  await delay(20)

  assert.equal(floorRuns, 1, 'floor completed during threat_model')
  assert.equal(eng.agenticLaneJobs.has(runId), false)
  assert.deepEqual(checkpoints, [], 'post-floor must NOT fire while run is still in threat_model')

  // Finish code_audit and transition to investigation as exec-recon-planner does.
  releaseAudit()
  await auditPromise
  addReadyStep(storage, storage.run(runId))
  storage.updateRun(runId, { phase: 'investigation', status: 'running' })
  eng.notifyCheckpoint(runId, 'post-floor')
  assert.deepEqual(checkpoints, ['post-floor'], 'post-floor fires cleanly once upon entering investigation')

  // Phase B dispatches immediately with zero extra floor wait.
  eng.driveInvestigation(storage.run(runId), profiles)
  assert.equal(dispatched.length, 1, 'Phase B dispatches immediately when floor already completed during code_audit')
  assert.equal(floorRuns, 1, 'floor must not re-run in investigation')
})

// ============================================================================
// 3. tick() still aborts overlapped floor if run stops/pauses during threat_model
// ============================================================================

test('Phase A overlap: wake() aborts an overlapped floor lane if the run stops during threat_model', async (t) => {
  const { storage } = makeStore(t)
  const { runId } = await setupApprovedRun(storage, { seeds: [ORIGIN_API], tier: 2 })
  storage.updateRun(runId, { phase: 'threat_model', status: 'running' })

  const execution = new Execution(storage, { deterministicSweep: true, backend: stubBackend() })
  t.after(() => execution.stop())
  const eng = internals(execution)
  eng.prePhase0SeededSteps.set(laneKey(storage.run(runId)), false)
  eng.startThreatModel = () => undefined
  eng.reconPlanner.startCoordinator = () => undefined

  let laneSignal: AbortSignal | undefined
  eng.runEngineInvestigation = async (_r, opts = {}) => {
    laneSignal = opts.signal
    await new Promise<void>(resolve => {
      if (opts.signal?.aborted) resolve()
      else opts.signal?.addEventListener('abort', () => resolve(), { once: true })
    })
  }

  const started = eng.startDeterministicLane(storage.run(runId), [{ id: 'p1', model: 'mock' }], { allowThreatModelPhase: true })
  assert.equal(started, true)
  assert.equal(laneSignal?.aborted, false)

  storage.updateRun(runId, { status: 'stopped' })
  execution.wake()
  await delay(20)
  assert.equal(laneSignal?.aborted, true, 'stopping the run must abort the overlapped floor lane')
})

// ============================================================================
// 4. ExecFloorLane.runEngineInvestigation threat_model phase guard
// ============================================================================

test('ExecFloorLane.runEngineInvestigation requires allowThreatModelPhase during threat_model', async (t) => {
  const { storage } = makeStore(t)
  const { runId } = await setupApprovedRun(storage, { seeds: [ORIGIN_API], tier: 2 })
  storage.updateRun(runId, { phase: 'threat_model', status: 'running' })

  const execution = new Execution(storage, { backend: stubBackend() })
  t.after(() => execution.stop())
  const eng = internals(execution)

  // Without flag: must return immediately without claiming a worker or emitting probe selection telemetry.
  let assignedWithoutFlag: string | null = null
  await eng.floorLane.runEngineInvestigation(storage.run(runId), {
    onAssignment: id => { assignedWithoutFlag = id },
  })
  assert.equal(assignedWithoutFlag, null, 'threat_model must be rejected without allowThreatModelPhase')
  assert.equal(
    storage.eventsAfter(runId, 0).filter(e => e.kind === 'deterministic_engine.probe_selection').length,
    0,
  )

  // With allowThreatModelPhase: true: passes the phase guard, emits probe_selection, and claims a worker.
  let assignedWithFlag: string | null = null
  await eng.floorLane.runEngineInvestigation(storage.run(runId), {
    allowThreatModelPhase: true,
    onAssignment: id => { assignedWithFlag = id },
  })
  assert.ok(assignedWithFlag, 'allowThreatModelPhase: true must allow floor engine to claim its worker during threat_model')
  assert.ok(
    storage.eventsAfter(runId, 0).some(e => e.kind === 'deterministic_engine.probe_selection'),
    'allowThreatModelPhase: true must enter probe selection during threat_model',
  )
})

// ============================================================================
// 5. --no-llm / deterministicOnly and default gating stay untouched
// ============================================================================

test('--no-llm / deterministicOnly and non-overlapped guards remain untouched', async (t) => {
  const { storage } = makeStore(t)
  const { runId } = await setupApprovedRun(storage, { seeds: [ORIGIN_API], tier: 2 })
  storage.updateRun(runId, { phase: 'threat_model', status: 'running' })
  const reposDir = makeMountedRepo(t)

  const noLlmExec = new Execution(storage, { deterministicOnly: true, deterministicSweep: 'always', backend: stubBackend() })
  t.after(() => noLlmExec.stop())
  const noLlm = internals(noLlmExec)
  noLlm.projectReposMount = () => ({ reposDir, mountedRepos: ['demo-service'] })
  noLlm.prePhase0SeededSteps.set(laneKey(storage.run(runId)), false)

  // deterministicOnly must never use the agentic lane even with allowThreatModelPhase.
  assert.equal(
    noLlm.shouldStartDeterministicLane(storage.run(runId), [{ id: 'p1', model: 'mock' }], { allowThreatModelPhase: true }),
    false,
    'deterministicOnly must stay out of agenticLane',
  )

  // Without profiles, runSourceFirstCodeAudit is a no-op.
  const auditResult = await noLlmExec.runSourceFirstCodeAudit(storage.run(runId), [], [], new AbortController().signal)
  assert.deepEqual(auditResult, { suspects: [], stepsCreated: [] })

  // In investigation phase, --no-llm drives runEngineInvestigation and advances to verification as before.
  let engineCalled = 0
  let engineAllowThreatModel: boolean | undefined
  noLlm.runEngineInvestigation = async (_r, opts = {}) => {
    engineCalled += 1
    engineAllowThreatModel = opts.allowThreatModelPhase
  }
  storage.updateRun(runId, { phase: 'investigation', status: 'running' })
  noLlm.driveInvestigation(storage.run(runId), [])
  await delay(25)
  assert.equal(engineCalled, 1, '--no-llm must run deterministic engine in investigation')
  assert.equal(engineAllowThreatModel, undefined, '--no-llm calls runEngineInvestigation without allowThreatModelPhase')
  assert.ok(['verification', 'complete'].includes(storage.run(runId).phase), '--no-llm advances to verification')

  // Without allowThreatModelPhase, startDeterministicLane still refuses threat_model on normal agentic runs.
  const { runId: freshRunId } = await setupApprovedRun(storage, { seeds: [ORIGIN_API], tier: 2 })
  storage.updateRun(freshRunId, { phase: 'threat_model', status: 'running' })
  const agentic = new Execution(storage, { deterministicSweep: true, backend: stubBackend() })
  t.after(() => agentic.stop())
  const ag = internals(agentic)
  ag.prePhase0SeededSteps.set(laneKey(storage.run(freshRunId)), false)
  assert.equal(
    ag.shouldStartDeterministicLane(storage.run(freshRunId), [{ id: 'p1', model: 'mock' }]),
    false,
    'threat_model remains disallowed unless allowThreatModelPhase is explicitly set',
  )
  assert.equal(
    ag.shouldStartDeterministicLane(storage.run(freshRunId), [{ id: 'p1', model: 'mock' }], { allowThreatModelPhase: true }),
    true,
    'threat_model is allowed when allowThreatModelPhase is set',
  )
})
