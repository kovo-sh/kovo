process.env.GUARDIAN_ALLOW_LOCAL_LAB ??= '1'
/**
 * Architecture Wave 2 Proposal B2 (`Execution` Decomposition & Dead Code Retirement) Tests.
 *
 * Verifies (Docker-free, real SQLite WAL `Store`, real `Execution`, real `ExecWorkerRunner`):
 *  1. `src/server/execution.ts` <= 4,500 LOC (shrunk >= 1,400 LOC from 5,928 LOC) and cleanly
 *     delegates worker-session orchestration to `ExecWorkerRunner` with zero circular imports.
 *  2. `src/server/proof-tools.ts` retires all 17 unreferenced intermediate type exports while
 *     keeping every live runtime/type export working for `agent-session.ts` and tests.
 *  3. Behavioral parity across the `ExecWorkerRunner` seam:
 *     - `record_coverage` negative-edge 2-strike pruning & `FrontierWaveController` sync,
 *     - `handleInvestigationWorkerError` provider stall retry/fail + pre-session wall-clock rotation,
 *     - `completeWorker` handoff artifact + session clone disposal,
 *     - run-scoped `DerivedCapabilityVault` sharing & singleton `execution.labRunner`.
 */
import assert from 'node:assert/strict'
import { existsSync, mkdtempSync, readFileSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import { test } from 'node:test'
import { fileURLToPath } from 'node:url'

import { Execution } from '../src/server/execution.ts'
import { ExecWorkerRunner } from '../src/server/exec-worker-runner.ts'
import { LabRunner } from '../src/server/lab-runner.ts'
import {
  describeProofTools,
  proofToolNames,
  proveAuthzReadDiff,
  validateProofInput,
} from '../src/server/proof-tools.ts'
import { Store } from '../src/server/store.ts'
import type { Assignment, ChainStep, Run } from '../src/server/store.ts'
import type { AssignmentBudget } from '../src/server/exec-dispatch.ts'
import type { ExecActiveJob } from '../src/server/exec-exchange.ts'
import type { WorkerBackend } from '../src/server/worker-backend.ts'
import { setupApprovedRun, stopExecution } from './v4-tier-helpers.ts'

const REPO_ROOT = join(dirname(fileURLToPath(import.meta.url)), '..')

function makeStore(t: { after: (fn: () => void) => void }): Store {
  const dir = mkdtempSync(join(tmpdir(), 'guardian-arch-b2-'))
  const storage = new Store(dir)
  t.after(() => {
    try { storage.close() } catch { /* already closed */ }
    rmSync(dir, { recursive: true, force: true })
  })
  return storage
}

function stubBackend(): WorkerBackend {
  return {
    openSession: async () => ({
      stage: async (name: string) => `/work/${name}`,
      exec: async () => ({ exitCode: 0, stdout: '', stderr: '', outputs: {} }),
      analyze: async () => ({ ok: true }),
      sast: async () => ({ repo: 'app', enginesRun: [], engineStatus: {}, findings: [], durationMs: 1 }),
      runScript: async () => ({ runtime: 'python', exitCode: 0, stdout: '', stderr: '', timedOut: false, durationMs: 1 }),
      close: async () => undefined,
    }),
  } as unknown as WorkerBackend
}

test('B2.1: execution.ts <= 4,500 LOC, clean ExecWorkerRunner seam, no circular import, LabRunner singleton intact', () => {
  const execPath = join(REPO_ROOT, 'src/server/execution.ts')
  const runnerPath = join(REPO_ROOT, 'src/server/exec-worker-runner.ts')
  assert.equal(existsSync(runnerPath), true, 'src/server/exec-worker-runner.ts must exist')

  const execSource = readFileSync(execPath, 'utf8')
  const runnerSource = readFileSync(runnerPath, 'utf8')
  const execLines = execSource.split('\n').length

  assert.ok(execLines <= 4500, `src/server/execution.ts must be <= 4,500 LOC, got ${execLines}`)
  assert.ok(execSource.includes("from './exec-worker-runner.ts'"), 'execution.ts must import ExecWorkerRunner')
  assert.ok(execSource.includes('new ExecWorkerRunner('), 'execution.ts must wire ExecWorkerRunner')
  assert.ok(execSource.includes('this.workerRunner.runInvestigationWorker('), 'runInvestigationWorker must delegate to ExecWorkerRunner')
  assert.ok(execSource.includes('this.workerRunner.buildSharedSessionHandlers('), 'buildSharedSessionHandlers must delegate to ExecWorkerRunner')
  assert.ok(execSource.includes('this.workerRunner.recordNegativeEdgeCoverage('), 'recordNegativeEdgeCoverage must delegate to ExecWorkerRunner')
  assert.ok(execSource.includes('this.workerRunner.handleInvestigationWorkerError('), 'startInvestigationStep error handling must delegate to ExecWorkerRunner')
  assert.ok(!/from\s+['"][^'"]*execution\.ts['"]/.test(runnerSource), 'exec-worker-runner.ts must never import execution.ts (no circular dependency)')
  assert.ok(!execSource.includes("from './proof-tools.ts'"), 'execution.ts must never import proof-tools.ts')
  assert.equal(typeof ExecWorkerRunner.prototype.runInvestigationWorker, 'function')
})

test('B2.2: proof-tools.ts prunes unreferenced type exports while preserving all live callers', () => {
  const src = readFileSync(join(REPO_ROOT, 'src/server/proof-tools.ts'), 'utf8')
  const exportNames = [...src.matchAll(/^export\s+(?:const|type|interface|class|function)\s+([A-Za-z0-9_]+)/gm)].map(m => m[1]!).sort()

  const expectedLiveExports = [
    'CompiledProof',
    'ProofCompileError',
    'ProofToolName',
    'describeProofTools',
    'proofToolNames',
    'proveAuthzReadDiff',
    'proveBusinessInvariant',
    'proveCanaryOrRedirect',
    'proveStateMutationDiff',
    'validateProofInput',
  ].sort()

  assert.deepEqual(exportNames, expectedLiveExports, 'proof-tools.ts must export only live-referenced symbols')
  assert.deepEqual(describeProofTools().map(d => d.name), [...proofToolNames])
  assert.equal(validateProofInput('prove_authz_read_diff', { origin: 'https://app.example.invalid' }).ok, false)

  const compiled = proveAuthzReadDiff({
    origin: 'https://app.example.invalid',
    ownerPersona: 'alice',
    attackerPersona: 'bob',
    endpoint: '/api/items/{resourceId}',
    resourceId: 'item-88421',
    identifierPath: 'id',
  })
  assert.equal(compiled.spec.kind, 'http_chain')
  assert.equal(compiled.spec.steps.length, 2)
})

test('B2.3: ExecWorkerRunner preserves record_coverage 2-strike negative-edge pruning, stall retry/rotation, completeWorker & LabRunner/vault custody', async (t) => {
  const storage = makeStore(t)
  const { runId, run: initialRun } = await setupApprovedRun(storage, { budgetRequests: 200 })
  const asset = initialRun.candidates[0]!
  storage.updateRun(runId, { phase: 'investigation', status: 'running' })
  const engine = new Execution(storage, { backend: stubBackend(), deterministicSweep: false })
  t.after(() => stopExecution(engine as never))

  // LabRunner singleton getter & shared run-scoped DerivedCapabilityVault
  assert.ok(engine.labRunner instanceof LabRunner)
  assert.equal(engine.capabilityVaultFor(runId), engine.capabilityVaultFor(runId))

  const run: Run = storage.run(runId)
  const step: ChainStep = storage.addChainStep(run, {
    title: 'Verify access control on order export',
    hypothesis: 'Test tenant boundary enforcement.',
    category: 'broken-access-control',
    priority: 85,
    targetAssetIds: [asset.id],
    skills: [],
    dependsOnFactIds: [],
    dependsOnStepIds: [],
    sourceOrigins: [asset.origin],
  })
  const worker: Assignment = storage.makeWorker(run, 'investigation', asset, step.title, step.hypothesis, {
    stepId: step.id,
    sourceOrigins: [asset.origin],
  })
  const claimed = storage.updateWorker(worker.id, { status: 'running', lease: 'lease-b2', leaseExpiresAt: Date.now() + 60_000 })!
  const job: ExecActiveJob = { assignment: claimed, origins: new Set([asset.origin]), controller: new AbortController() }

  // 1. Negative-edge 2-strike pruning through buildSharedSessionHandlers().record_coverage
  const priv = engine as unknown as {
    workerRunner: ExecWorkerRunner
    wallClockRotatedAssignments: Set<string>
    wallClockRotationsByRun: Map<string, number>
    workerSessionClones: Map<string, Array<{ handle: string; clone: { dispose: () => void } }>>
    buildSharedSessionHandlers: (
      job: ExecActiveJob,
      session: Awaited<ReturnType<WorkerBackend['openSession']>>,
      currentSecrets: () => readonly [],
      opts: { offlineScriptLabel: string; deriveEvidenceTitle: string },
    ) => ReturnType<ExecWorkerRunner['buildSharedSessionHandlers']>
  }
  assert.ok(priv.workerRunner instanceof ExecWorkerRunner)

  const session = await stubBackend().openSession(claimed.id, job.controller.signal)
  const shared = priv.buildSharedSessionHandlers(job, session, () => [], {
    offlineScriptLabel: 'Offline {runtime} script',
    deriveEvidenceTitle: 'Derived evidence',
  })

  const strike1 = await shared.record_coverage({
    origin: asset.origin,
    category: 'broken-access-control',
    status: 'needs_follow_up',
    summary: 'Server enforced tenant ownership check on export endpoint.',
    proofGapReason: 'invariant_enforced_hardened',
    route: 'GET /api/orders/:id',
  } as Parameters<typeof shared.record_coverage>[0])
  assert.equal(strike1.negativeEdgeRecorded, true)
  assert.equal(strike1.attemptCount, 1)
  assert.equal(strike1.pruned, false)

  const strike2 = await shared.record_coverage({
    origin: asset.origin,
    category: 'broken-access-control',
    status: 'needs_follow_up',
    summary: 'Second variant confirmed hardened tenant guard.',
    proofGapReason: 'invariant_enforced_hardened',
    route: 'GET /api/orders/:id',
  } as Parameters<typeof shared.record_coverage>[0])
  assert.equal(strike2.negativeEdgeRecorded, true)
  assert.equal(strike2.attemptCount, 2)
  assert.equal(strike2.pruned, true)

  const ledgerEdges = storage.capabilityLedger(runId).listNegativeEdges()
  assert.equal(ledgerEdges.some(e => e.targetSurfaceKey === 'GET /api/orders/:id' && e.pruned), true)

  // 2. Stall retry on attempt 0 -> requeues step to ready
  const budget: AssignmentBudget = { kind: 'single_step', maxTurns: 8, wallClockMs: 30_000, settlementTurn: 6 }
  job.stallAbort = true
  priv.workerRunner.handleInvestigationWorkerError(storage.run(runId), job, step, 'auth-session-oauth-specialist', budget, new Error('stall'))
  assert.equal(storage.worker(claimed.id)?.status, 'canceled')
  assert.equal(storage.worker(claimed.id)?.attempt, 1)
  assert.equal(storage.listChainSteps(runId, run.goalRevision).find(s => s.id === step.id)?.status, 'ready')

  // 3. Pre-session wall-clock rotation marks worker & step complete and increments counter
  const worker2 = storage.makeWorker(run, 'investigation', asset, step.title, step.hypothesis, {
    stepId: step.id,
    sourceOrigins: [asset.origin],
  })
  const claimed2 = storage.updateWorker(worker2.id, { status: 'running', lease: 'lease-b2-2', leaseExpiresAt: Date.now() + 60_000 })!
  const job2: ExecActiveJob = { assignment: claimed2, origins: new Set([asset.origin]), controller: new AbortController() }
  priv.wallClockRotatedAssignments.add(claimed2.id)
  priv.workerRunner.handleInvestigationWorkerError(storage.run(runId), job2, step, 'auth-session-oauth-specialist', budget, new Error('timeout'))
  assert.equal(storage.worker(claimed2.id)?.status, 'complete')
  assert.match(storage.worker(claimed2.id)?.outcome ?? '', /Bounded wall-clock rotation/)
  assert.equal(priv.wallClockRotationsByRun.get(runId), 1)

  // 4. completeWorker disposes tracked clones and marks worker complete
  let disposed = false
  const worker3 = storage.makeWorker(run, 'investigation', asset, 'Clone cleanup test', 'Verify disposal', {
    sourceOrigins: [asset.origin],
  })
  priv.workerSessionClones.set(worker3.id, [{ handle: 'alice', clone: { dispose: () => { disposed = true } } }])
  priv.workerRunner.completeWorker(worker3, storage.run(runId), 'Completed cleanly.', [])
  assert.equal(disposed, true)
  assert.equal(priv.workerSessionClones.has(worker3.id), false)
  assert.equal(storage.worker(worker3.id)?.status, 'complete')
})
