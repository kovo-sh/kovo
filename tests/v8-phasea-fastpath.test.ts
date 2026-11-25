/**
 * v8 Phase A Fast-Path & Wave-1 Invariant Chain Promotion Tests.
 *
 * Proves (zero Docker, real SQLite WAL `Store`, real `Execution`, real `ExecReconPlanner`):
 *  1. `resolveSourceAuditWallClockMs` bounds Phase 1B Source-First Code Audit proportionally
 *     (10m -> 90s, 30m -> 90s, 4m -> 45s, unset -> 120s) and `resolveSourceAuditMaxTurns` caps
 *     turns to <= 8 on runs <= 15m.
 *  2. `synthesizeInvariants()` hypotheses (both white-box mounted source AND grey-box runtime
 *     OpenAPI/observations) are promoted directly into ready Wave-1 `chain` lane `ChainStep`s
 *     (`isMultiHopChainStep === true`, `classifyDispatchLane === 'chain'`, referencing
 *     `CapabilityLedger` node IDs, concrete endpoints, and personas) BEFORE Phase B's first
 *     dispatch tick, and are idempotent on repeat calls.
 *  3. Phase A deterministic floor wall-clock scales proportionally on agentic runs
 *     (`min(75s, 12% * maxDurationMs)`), skips redundant floor sweeps when a pre-hydrated floor
 *     snapshot is already loaded, and preserves the full unrestricted floor budget on `--no-llm`
 *     (`profiles.length === 0`) runs.
 */
import assert from 'node:assert/strict'
import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from 'node:fs'
import { createServer, type Server } from 'node:http'
import type { AddressInfo } from 'node:net'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { test } from 'node:test'
import { setTimeout as delay } from 'node:timers/promises'

import {
  Execution,
  classifyDispatchLane,
  isMultiHopChainStep,
  planRoundRobinDispatch,
  resolvePhaseAFloorWallClockMs,
  resolveSourceAuditMaxTurns,
  resolveSourceAuditWallClockMs,
  type DispatchLaneStep,
} from '../src/server/execution.ts'
import type { ExecReconPlanner } from '../src/server/exec-recon-planner.ts'
import { extractProgramGraph } from '../src/server/program-graph.ts'
import type { SourceFileInput } from '../src/server/invariant-synthesizer.ts'
import { privateModelProfiles, saveModelProfile } from '../src/server/model-settings.ts'
import type { ChainStep, Run } from '../src/server/store.ts'
import type { WorkerBackend, WorkerSession } from '../src/server/worker-backend.ts'
import { makeStore, setupApprovedRun } from './v4-tier-helpers.ts'

process.env.GUARDIAN_ALLOW_LOCAL_LAB = '1'

const ORIGIN_EDGE = 'http://edge.synth.test:8080'
const ORIGIN_API = 'http://api.synth.test:8081'
const ORIGIN_WORKER = 'http://worker.synth.test:8082'

const SYNTH_MULTISERVICE_SOURCE: SourceFileInput[] = [
  {
    path: 'services/edge/proxy.ts',
    content: `
      import express from 'express'
      const router = express.Router()
      router.use('/internal/*', (req, res) => {
        const forwardedRole = req.headers['x-forwarded-role']
        const tenantHeader = req.headers['x-tenant-id']
        return fetch('http://api:8081' + req.originalUrl, {
          headers: { 'x-forwarded-role': String(forwardedRole || ''), 'x-tenant-id': String(tenantHeader || '') },
        })
      })
    `,
  },
  {
    path: 'services/api/invoices.ts',
    content: `
      import express from 'express'
      const app = express()
      app.get('/api/v1/invoices/:id', requireAuth, requireTenantScope, requireRole('member'), async (req, res) => {
        return db.invoices.findOne({ id: req.params.id, tenantId: req.user.tenantId })
      })
      app.post('/api/v1/invoices/batch', requireAuth, async (req, res) => {
        return db.invoices.findMany({ ids: req.body.ids })
      })
      app.post('/api/v1/invoices/:id/approve', requireAuth, async (req, res) => {
        const inv = await db.invoices.findOne({ id: req.params.id })
        inv.status = 'approved'
        inv.balance = inv.balance - Number(req.body.amount)
        return db.invoices.save(inv)
      })
    `,
  },
  {
    path: 'services/worker/exports.ts',
    content: `
      import express from 'express'
      const router = express.Router()
      router.get('/sse/invoices/stream', async (req, res) => {
        const rows = await db.invoices.listAll(req.query.cursor)
        res.write(JSON.stringify(rows))
      })
    `,
  },
]

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

type ExecInternals = {
  reconPlanner: ExecReconPlanner
  driveInvestigation: (run: Run, profiles: readonly unknown[]) => void
  runEngineInvestigation: (run: Run, opts?: { signal?: AbortSignal; maxDurationMs?: number; onAssignment?: (id: string) => void }) => Promise<void>
  startInvestigationStep: (run: Run, step: ChainStep, profiles: readonly unknown[]) => void
  deterministicLaneDeadlineMs: (run?: Pick<Run, 'id'>) => number
  prePhase0SeededSteps: Map<string, boolean>
  projectReposMount: (projectId: string) => { reposDir?: string; mountedRepos: string[] }
  advanceToVerification: (run: Run) => Promise<void>
}

function internals(execution: Execution): ExecInternals {
  return execution as unknown as ExecInternals
}

function laneKey(run: Run): string {
  return `${run.id}:${run.goalRevision}:${run.scopeRevision}`
}

// ============================================================================
// 1. Source-First Code Audit Wall-Clock & Turn Cap Helpers
// ============================================================================

test('resolveSourceAuditWallClockMs scales proportionally across 4m, 10m, 30m, and unset runs', () => {
  // 10m (600s) -> 90s
  assert.equal(resolveSourceAuditWallClockMs(600_000), 90_000)
  // 30m (1800s) -> capped at 90s (never 300s+)
  assert.equal(resolveSourceAuditWallClockMs(1_800_000), 90_000)
  // 4m (240s) -> floored at 45s (240s * 0.15 = 36s -> 45s)
  assert.equal(resolveSourceAuditWallClockMs(240_000), 45_000)
  // 8m (480s) -> 72s
  assert.equal(resolveSourceAuditWallClockMs(480_000), 72_000)
  // Unset / invalid -> 120s default
  assert.equal(resolveSourceAuditWallClockMs(undefined), 120_000)
  assert.equal(resolveSourceAuditWallClockMs(0), 120_000)
  assert.equal(resolveSourceAuditWallClockMs(-5_000), 120_000)
  assert.equal(resolveSourceAuditWallClockMs(Number.NaN), 120_000)
})

test('resolveSourceAuditMaxTurns caps interactive code-audit turns to <= 8 on runs <= 15m', () => {
  assert.equal(resolveSourceAuditMaxTurns(30, 600_000), 8)
  assert.equal(resolveSourceAuditMaxTurns(0, 900_000), 8)
  assert.equal(resolveSourceAuditMaxTurns(6, 600_000), 6)
  // Runs > 15m retain up to defaultCodeAuditMaxTurns (30)
  assert.equal(resolveSourceAuditMaxTurns(20, 1_800_000), 20)
  assert.equal(resolveSourceAuditMaxTurns(0, undefined), 30)
})

// ============================================================================
// 2. synthesizeInvariants() -> Direct Wave-1 `chain` Step Seeding
// ============================================================================

test('synthesizeInvariants() white-box hypotheses directly seed ready Wave-1 chain steps ahead of Phase B', async (t) => {
  const { storage } = makeStore(t)
  const { runId } = await setupApprovedRun(storage, {
    seeds: [ORIGIN_EDGE, ORIGIN_API, ORIGIN_WORKER],
    tier: 2,
  })
  const run = storage.run(runId)
  const execution = new Execution(storage, { backend: stubBackend(), maxDurationMs: 600_000 })
  t.after(() => execution.stop())

  const planner = internals(execution).reconPlanner
  const graph = extractProgramGraph({ files: SYNTH_MULTISERVICE_SOURCE, repo: 'synth-saas' })
  const res = planner.seedCapabilityLedgerInvariants(run, {
    mode: 'white-box',
    graph,
    sourceFiles: SYNTH_MULTISERVICE_SOURCE,
    serviceOrigins: [
      { service: 'edge', root: 'services/edge', origin: ORIGIN_EDGE, confidence: 'exact', evidence: ['test'] },
      { service: 'api', root: 'services/api', origin: ORIGIN_API, confidence: 'exact', evidence: ['test'] },
      { service: 'worker', root: 'services/worker', origin: ORIGIN_WORKER, confidence: 'exact', evidence: ['test'] },
    ],
    approvedOrigins: new Set([ORIGIN_EDGE, ORIGIN_API, ORIGIN_WORKER]),
  })

  assert.equal(res.mode, 'white-box')
  assert.ok(res.seededCount >= 2, `expected >= 2 quarantined ledger seeds, got ${res.seededCount}`)
  assert.ok(res.wave1ChainStepsCreated >= 2, `expected >= 2 Wave-1 chain steps promoted, got ${res.wave1ChainStepsCreated}`)

  const steps = storage.listChainSteps(runId, run.goalRevision)
  const promoted = steps.filter(step => res.wave1ChainStepIds.includes(step.id))
  assert.equal(promoted.length, res.wave1ChainStepsCreated)

  for (const step of promoted) {
    assert.equal(step.status, 'ready', 'Wave-1 invariant chain steps must be immediately ready at Phase A completion')
    assert.equal(isMultiHopChainStep(step), true, `expected isMultiHopChainStep=true for "${step.title}"`)
    assert.equal(classifyDispatchLane(step), 'chain', `expected dispatch lane === 'chain' for "${step.title}"`)
    assert.match(step.hypothesis, /\[cap=cap:hop_synth:/, 'Wave-1 chain step must cite its CapabilityLedger node ID')
    assert.match(step.hypothesis, /Personas:/, 'Wave-1 chain step must list active personas')
    assert.ok(step.priority >= 88, `expected high Wave-1 priority, got ${step.priority}`)
  }

  // Idempotency: repeat synthesis does not duplicate ledger nodes or Wave-1 chain steps.
  const repeat = planner.seedCapabilityLedgerInvariants(run, {
    mode: 'white-box',
    graph,
    sourceFiles: SYNTH_MULTISERVICE_SOURCE,
    approvedOrigins: new Set([ORIGIN_EDGE, ORIGIN_API, ORIGIN_WORKER]),
  })
  assert.equal(repeat.seededCount, 0)
  assert.equal(repeat.wave1ChainStepsCreated, 0)

  // Verify Wave-1 chain steps win dedicated frontier slots ahead of generic single-route sweeps.
  const genericRouteSteps: DispatchLaneStep[] = [
    {
      id: 'route-1', seq: 90, priority: 85, title: 'Single-route BOLA sweep /api/v1/health',
      category: 'broken-access-control', hypothesis: 'Probe GET /api/v1/health.',
      skills: ['access-control-bola-bfla'], dependsOnFactIds: [], dependsOnStepIds: [],
      sourceOrigins: [ORIGIN_API], trialIndex: 0,
    },
    {
      id: 'route-2', seq: 91, priority: 84, title: 'Single-route BOLA sweep /api/v1/profile',
      category: 'broken-access-control', hypothesis: 'Probe GET /api/v1/profile.',
      skills: ['access-control-bola-bfla'], dependsOnFactIds: [], dependsOnStepIds: [],
      sourceOrigins: [ORIGIN_API], trialIndex: 0,
    },
  ]
  const plan = planRoundRobinDispatch([...genericRouteSteps, ...promoted], 3)
  assert.ok(plan.selectedByLane.chain >= 2, `expected >= 2 Wave-1 chain steps dispatched in 3-slot Wave 1, got ${plan.selectedByLane.chain}`)
})

test('synthesizeInvariants() grey-box runtime parity also promotes Wave-1 chain steps without mounted source', async (t) => {
  const { storage } = makeStore(t)
  const { runId } = await setupApprovedRun(storage, { seeds: [ORIGIN_API], tier: 2 })
  const run = storage.run(runId)
  const execution = new Execution(storage, { backend: stubBackend(), maxDurationMs: 600_000 })
  t.after(() => execution.stop())

  const planner = internals(execution).reconPlanner
  const res = planner.seedCapabilityLedgerInvariants(run, {
    mode: 'grey-box',
    runtime: {
      personaObservations: [
        {
          persona: 'revoked_admin',
          isRevokedOrDemoted: true,
          surface: 'http',
          serviceOrigin: ORIGIN_API,
          method: 'GET',
          path: '/api/secrets/:id',
          status: 401,
        },
        {
          persona: 'revoked_admin',
          isRevokedOrDemoted: true,
          surface: 'sse',
          serviceOrigin: ORIGIN_API,
          method: 'GET',
          path: '/sse/secrets/stream',
          status: 200,
        },
      ],
      openApiOperations: [
        { method: 'GET', path: '/api/secrets/:id', security: [{ bearerAuth: [] }], serviceOrigin: ORIGIN_API },
        { method: 'POST', path: '/api/secrets/batch', security: [], serviceOrigin: ORIGIN_API },
      ],
    },
    approvedOrigins: new Set([ORIGIN_API]),
  })

  assert.equal(res.mode, 'grey-box')
  assert.ok(res.wave1ChainStepsCreated >= 1, 'grey-box asymmetries must directly promote Wave-1 chain steps')
  const promoted = storage.listChainSteps(runId, run.goalRevision).filter(s => res.wave1ChainStepIds.includes(s.id))
  assert.ok(promoted.every(s => s.status === 'ready' && isMultiHopChainStep(s) && classifyDispatchLane(s) === 'chain'))
  assert.ok(promoted.some(s => s.hypothesis.includes('/api/secrets') || s.hypothesis.includes('/sse/secrets')))
})

// ============================================================================
// 3. Phase A Floor Budget Proportioning, Snapshot Skip & --no-llm Preservation
// ============================================================================

test('resolvePhaseAFloorWallClockMs scales proportionally for agentic runs and leaves --no-llm unrestricted', () => {
  // --no-llm (profiles.length === 0) retains full unrestricted floor budget
  assert.equal(resolvePhaseAFloorWallClockMs(600_000, { hasProfiles: false }), undefined)
  assert.equal(resolvePhaseAFloorWallClockMs(1_800_000, { hasProfiles: false }), undefined)
  assert.equal(resolvePhaseAFloorWallClockMs(240_000, { hasProfiles: false }), undefined)

  // Agentic runs cap floor wall-clock at min(75s, 12% * maxDurationMs) with a 15s floor
  assert.equal(resolvePhaseAFloorWallClockMs(600_000, { hasProfiles: true }), 72_000)
  assert.equal(resolvePhaseAFloorWallClockMs(1_800_000, { hasProfiles: true }), 75_000)
  assert.equal(resolvePhaseAFloorWallClockMs(240_000, { hasProfiles: true }), 28_800)
  assert.equal(resolvePhaseAFloorWallClockMs(60_000, { hasProfiles: true }), 15_000)
  assert.equal(resolvePhaseAFloorWallClockMs(undefined, { hasProfiles: true }), 75_000)
})

test('--no-llm (profiles.length === 0) retains full unrestricted deterministic floor budget', async (t) => {
  const { storage } = makeStore(t)
  const { runId } = await setupApprovedRun(storage, { seeds: [ORIGIN_API], budgetRequests: 2_000 })
  storage.updateRun(runId, { phase: 'investigation', status: 'running' })
  const execution = new Execution(storage, {
    deterministicOnly: true,
    maxDurationMs: 600_000,
    backend: stubBackend(),
  })
  t.after(() => execution.stop())

  const calls: Array<{ maxDurationMs?: number }> = []
  internals(execution).runEngineInvestigation = async (_run, opts) => {
    calls.push({ maxDurationMs: opts?.maxDurationMs })
  }

  internals(execution).driveInvestigation(storage.run(runId), [])
  await delay(25)

  assert.equal(calls.length, 1, '--no-llm must run deterministic engine investigation')
  assert.equal(calls[0]!.maxDurationMs, undefined, '--no-llm must NOT receive the agentic 72s/75s Phase-A cap')
})

test('agentic Phase A floor uses proportional 72s cap on 10m run and skips redundant floor when pre-hydrated snapshot exists', async (t) => {
  // Part A: Fresh 10m agentic run gets min(75s, 12% * 600s) = 72s cap
  {
    const { storage } = makeStore(t)
    const { runId } = await setupApprovedRun(storage, { seeds: [ORIGIN_API], budgetRequests: 2_000 })
    storage.updateRun(runId, { phase: 'investigation', status: 'running' })
    const run = storage.run(runId)
    const execution = new Execution(storage, { maxDurationMs: 600_000, backend: stubBackend() })
    t.after(() => execution.stop())
    internals(execution).prePhase0SeededSteps.set(laneKey(run), false)

    const floorCalls: Array<{ maxDurationMs?: number }> = []
    internals(execution).runEngineInvestigation = async (_run, opts = {}) => {
      floorCalls.push({ maxDurationMs: opts.maxDurationMs })
      await new Promise<void>(resolve => {
        if (opts.signal?.aborted) resolve()
        else opts.signal?.addEventListener('abort', () => resolve(), { once: true })
      })
    }
    internals(execution).startInvestigationStep = () => undefined

    internals(execution).driveInvestigation(storage.run(runId), [{ id: 'profile', model: 'mock' }])
    assert.equal(floorCalls.length, 1)
    assert.equal(floorCalls[0]!.maxDurationMs, 72_000)
    assert.equal(internals(execution).deterministicLaneDeadlineMs(), 72_000)

    await internals(execution).advanceToVerification(storage.run(runId))
    await delay(20)
  }

  // Part B: Pre-hydrated floor snapshot skips redundant Phase A sweep and dispatches Wave 1 immediately
  {
    const { storage } = makeStore(t)
    const { runId } = await setupApprovedRun(storage, { seeds: [ORIGIN_API], budgetRequests: 2_000 })
    storage.updateRun(runId, { phase: 'investigation', status: 'running' })
    const run = storage.run(runId)
    // Pre-hydrated floor snapshot marker persisted in run events
    storage.event(runId, 'deterministic_engine.summary', 'Restored floor snapshot', { requestsUsed: 250, confirmed: 2 })

    const assetIds = run.candidates.filter(c => run.approved.includes(c.id)).map(c => c.id)
    storage.addChainStep(run, {
      title: 'Wave-1 chain · Cross-surface policy chain (invoices/sse)',
      hypothesis: '[chain_hops=2] [lane=chain] Multi-hop invariant chain on /sse/invoices/stream.',
      category: 'broken-access-control',
      priority: 95,
      targetAssetIds: assetIds,
      skills: ['multihop-chains', 'chain-primitives'],
      sourceOrigins: [ORIGIN_API],
    })

    const execution = new Execution(storage, { maxDurationMs: 600_000, backend: stubBackend() })
    t.after(() => execution.stop())
    internals(execution).prePhase0SeededSteps.set(laneKey(run), false)

    let floorCalls = 0
    internals(execution).runEngineInvestigation = async () => { floorCalls += 1 }
    const dispatchedTitles: string[] = []
    internals(execution).startInvestigationStep = (_run, step) => { dispatchedTitles.push(step.title) }

    internals(execution).driveInvestigation(storage.run(runId), [{ id: 'profile', model: 'mock' }])
    assert.equal(floorCalls, 0, 'pre-hydrated floor snapshot must skip redundant Phase A floor sweep')
    assert.ok(dispatchedTitles.length >= 1, 'Wave-1 chain step must dispatch immediately without waiting on redundant floor')
    assert.ok(dispatchedTitles.every(title => /Wave-1 chain/.test(title)), 'dispatched Wave-1 step must be the invariant chain step')
    const skippedEvent = storage.eventsAfter(runId, 0).find(e => e.kind === 'deterministic_lane.skipped')
    assert.ok(skippedEvent, 'expected deterministic_lane.skipped telemetry event')
  }
})

// ============================================================================
// 4. Live `runSourceFirstCodeAudit` Emits Bounded Wall-Clock / Turn Telemetry
// ============================================================================

test('runSourceFirstCodeAudit enforces proportional wall-clock cap (90s), turn cap (8), and semantic sub-timeout (35s)', async (t) => {
  const { storage } = makeStore(t)
  const { runId } = await setupApprovedRun(storage, { seeds: [ORIGIN_API], tier: 2 })
  const run = storage.run(runId)

  const reposDir = mkdtempSync(join(tmpdir(), 'guardian-phasea-repo-'))
  mkdirSync(join(reposDir, 'demo-app'), { recursive: true })
  writeFileSync(join(reposDir, 'demo-app', 'server.ts'), 'export const ok = true\n', 'utf8')
  t.after(() => rmSync(reposDir, { recursive: true, force: true }))

  // Fast mock OpenAI Responses API server that completes immediately on turn 1.
  const server: Server = createServer((req, res) => {
    req.resume()
    req.on('end', () => {
      res.statusCode = 200
      res.setHeader('Content-Type', 'text/event-stream')
      const emit = (event: string, data: Record<string, unknown>) => {
        res.write(`event: ${event}\ndata: ${JSON.stringify(data)}\n\n`)
      }
      emit('response.created', { type: 'response.created', response: { id: 'resp_1', status: 'in_progress', output: [] } })
      emit('response.output_item.added', {
        type: 'response.output_item.added',
        output_index: 0,
        item: { id: 'item_1', type: 'function_call', status: 'in_progress', call_id: 'call_1', name: 'complete_intent', arguments: '' },
      })
      const args = JSON.stringify({ status: 'completed', summary: 'Quick audit done.' })
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
          id: 'resp_1',
          status: 'completed',
          output: [{ id: 'item_1', type: 'function_call', status: 'completed', call_id: 'call_1', name: 'complete_intent', arguments: args }],
          usage: { input_tokens: 50, output_tokens: 20, total_tokens: 70 },
        },
      })
      res.write('data: [DONE]\n\n')
      res.end()
    })
  })
  await new Promise<void>(resolve => server.listen(0, '127.0.0.1', () => resolve()))
  const port = (server.address() as AddressInfo).port
  t.after(async () => {
    server.closeAllConnections?.()
    await new Promise<void>(resolve => server.close(() => resolve()))
  })

  const execution = new Execution(storage, { maxDurationMs: 600_000, backend: stubBackend() })
  t.after(() => execution.stop())
  internals(execution).projectReposMount = () => ({ reposDir, mountedRepos: ['demo-app'] })

  await saveModelProfile({
    name: 'Mock Reasoning',
    endpoint: `http://127.0.0.1:${port}/v1`,
    model: 'mock-model',
    protocol: 'responses',
    key: 'sk-test-mock-1234',
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
  const profiles = await privateModelProfiles(storage)

  const prevStage1 = process.env.GUARDIAN_STAGE1_LLM
  process.env.GUARDIAN_STAGE1_LLM = '0'
  t.after(() => {
    if (prevStage1 === undefined) delete process.env.GUARDIAN_STAGE1_LLM
    else process.env.GUARDIAN_STAGE1_LLM = prevStage1
  })

  const ac = new AbortController()
  await execution.runSourceFirstCodeAudit(run, [], profiles, ac.signal)

  const started = storage.eventsAfter(runId, 0).find(e => e.kind === 'code_audit.started')
  assert.ok(started, 'expected code_audit.started telemetry event')
  assert.equal(started.detail.auditWallMs, 90_000, '10m run must cap Source-First Code Audit at 90s')
  assert.equal(started.detail.auditSettlementMs, 72_000, 'settlement must trigger at 80% of auditWallMs (72s)')
  assert.equal(started.detail.semanticTimeoutMs, 35_000, 'semantic audit sub-timeout must be <= 35s')
  assert.equal(started.detail.auditMaxTurns, 8, '10m run must cap interactive code-audit turns to 8')
})
