/**
 * R10 Move 4: Worker throughput & stall-ceiling hardening tests.
 *
 * Verifies:
 *  1. Tighter provider stream timeouts (`defaultFirstEventTimeoutMs = 45_000`,
 *     `defaultIdleTimeoutMs = 60_000`) while honoring explicit option and env overrides.
 *  2. Tighter chain / multi-hop wall-clock caps (`180_000` / `210_000`) in `exec-dispatch.ts`.
 *  3. `computeWorkerWallClockPlan` caps `maxStallCreditMs` at `min(60_000, floor(base * 0.35))`
 *     so `hardWallClockCeilingMs <= 1.35x` base (`<= 270_000` for 210s base, never 600s).
 *  4. `expanded_verify` grace is NOT granted for preflight-rejected or non-progressing
 *     `kovo_verify` calls (unit + live `ExecWorkerRunner` verification).
 */
import assert from 'node:assert/strict'
import { randomUUID } from 'node:crypto'
import { once } from 'node:events'
import { mkdtempSync, rmSync } from 'node:fs'
import { createServer } from 'node:http'
import type { AddressInfo } from 'node:net'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { describe, test } from 'node:test'

import { runCommand } from '../src/domain.ts'
import { RequestBroker } from '../src/server/broker.ts'
import {
  CHAIN_ASSIGNMENT_MAX_WALL_CLOCK_MS,
  MULTI_HOP_CHAIN_DEFAULT_WALL_CLOCK_MS,
  MULTI_HOP_CHAIN_MAX_WALL_CLOCK_MS,
  resolveAssignmentBudget,
  type AssignmentBudget,
} from '../src/server/exec-dispatch.ts'
import type { ExecActiveJob } from '../src/server/exec-exchange.ts'
import {
  computeWorkerWallClockPlan,
  resolveWorkerVerifyGrace,
  type ExecWorkerRunner,
} from '../src/server/exec-worker-runner.ts'
import { Execution } from '../src/server/execution.ts'
import type { ResolvedModelProfile } from '../src/server/model-settings.ts'
import {
  defaultFirstEventTimeoutMs,
  defaultIdleTimeoutMs,
  provider,
  type ProviderConfig,
} from '../src/server/provider.ts'
import { Store } from '../src/server/store.ts'
import type { WorkerBackend } from '../src/server/worker-backend.ts'
import type { AgentScriptProofResult } from '../src/server/agent-script-proof.ts'

const ORIGIN = 'https://r10-throughput.example.test'

function makeTempDir(t: { after(fn: () => void | Promise<void>): void }, prefix: string): string {
  const dir = mkdtempSync(join(tmpdir(), prefix))
  t.after(() => rmSync(dir, { recursive: true, force: true }))
  return dir
}

function makeProviderConfig(endpoint: string, overrides: Partial<ProviderConfig> = {}): ProviderConfig {
  return {
    name: 'Test-OpenRouter',
    endpoint,
    model: 'test/flash-model',
    protocol: 'responses',
    key: 'sk-test-r10-throughput-1234',
    contextWindow: 128_000,
    maxTokens: 4_096,
    thinkingLevel: 'off',
    roleAffinity: 'tactical',
    ...overrides,
  }
}

function makeProfile(endpoint: string, id = 'p-r10-throughput'): ResolvedModelProfile {
  return {
    id,
    name: id,
    endpoint,
    model: 'r10-throughput-model',
    protocol: 'responses',
    key: 'sk-r10-throughput-1234',
    enabled: true,
    priority: 100,
    contextWindow: 128_000,
    maxTokens: 4_096,
    inputCostPerMtok: 0,
    cachedInputCostPerMtok: 0,
    outputCostPerMtok: 0,
    thinkingLevel: 'off',
    roleAffinity: 'any',
    healthState: 'closed',
    cooldownUntil: null,
    lastError: null,
  }
}

function makeBroker(): RequestBroker {
  return new RequestBroker({
    resolve: async () => [{ address: '93.184.216.34', family: 4 }],
    transport: async () => ({ status: 200, headers: { 'content-type': 'application/json' }, body: '{"ok":true}' }),
  })
}

function makeStubBackend(): WorkerBackend {
  return {
    workerImage: 'kovo-worker:r10-test',
    run: async () => ({ exitCode: 0, stdout: '', stderr: '', outputs: {} }),
    verifyStaticAst: async () => ({
      verified: false, engine: 'ast-grep', repo: '.', file: 'a.ts', startLine: 1, endLine: 1,
      matchedLines: [], codeExcerpt: '', matchCount: 0, durationMs: 1,
    }),
    openSession: async () => ({
      stage: async name => `/evidence/${name}`,
      exec: async () => ({ exitCode: 0, stdout: 'ok', stderr: '', outputs: {} }),
      analyze: async () => ({ ok: true }),
      sast: async req => ({ repo: req.repo, enginesRun: req.engines, engineStatus: {}, findings: [], totalFindings: 0, truncated: false, durationMs: 1 }),
      runScript: async req => ({ runtime: req.runtime, exitCode: 1, stdout: '', stderr: 'SyntaxError', durationMs: 1, timedOut: false }),
      verifyStaticAst: async () => ({
        verified: false, engine: 'ast-grep', repo: '.', file: 'a.ts', startLine: 1, endLine: 1,
        matchedLines: [], codeExcerpt: '', matchCount: 0, durationMs: 1,
      }),
      close: async () => undefined,
    }),
  }
}

function sse(events: Array<{ type: string } & Record<string, unknown>>): string {
  return events.map(ev => `data: ${JSON.stringify(ev)}\n\n`).join('') + 'data: [DONE]\n\n'
}

function responsesToolCallTurn(callId: string, name: string, args: Record<string, unknown>): string {
  const rawArgs = JSON.stringify(args)
  const fcId = `fc_${callId}`
  const item = {
    type: 'function_call',
    id: fcId,
    call_id: callId,
    name,
    arguments: rawArgs,
    status: 'completed',
  }
  return sse([
    { type: 'response.created', response: { id: `resp_${callId}`, status: 'in_progress' } },
    { type: 'response.output_item.added', output_index: 0, item: { ...item, arguments: '', status: 'in_progress' } },
    { type: 'response.function_call_arguments.delta', output_index: 0, item_id: fcId, delta: rawArgs },
    { type: 'response.function_call_arguments.done', output_index: 0, item_id: fcId, name, arguments: rawArgs },
    { type: 'response.output_item.done', output_index: 0, item },
    {
      type: 'response.completed',
      response: {
        id: `resp_${callId}`,
        status: 'completed',
        output: [item],
        usage: { input_tokens: 60, output_tokens: 30 },
      },
    },
  ])
}

function setupApprovedTestRun(store: Store, name = 'R10 Throughput Test') {
  const project = store.createProject({
    requestId: randomUUID(),
    name,
    seeds: [ORIGIN],
    environment: 'public',
  })
  const { id: runId } = store.createRun({
    requestId: randomUUID(),
    projectId: project.id,
    goal: 'Verify R10 worker throughput and verify-grace gating',
    sourceMode: 'public',
    capabilityTier: 2,
    budgetUsd: 5,
    budgetRequests: 500,
    maxRpsPerOrigin: 10,
    workerConcurrency: 2,
    workerMaxTurns: 10,
  })
  store.command(runCommand.parse({ requestId: randomUUID(), runId, action: 'discover', consent: true }))
  const discovered = store.run(runId)
  store.command(runCommand.parse({
    requestId: randomUUID(),
    runId,
    action: 'scope',
    assetIds: discovered.candidates.map(c => c.id),
    expectedScopeRevision: discovered.scopeRevision,
    consent: true,
  }))
  store.updateRun(runId, { phase: 'investigation', status: 'running' })
  return { project, runId, run: store.run(runId) }
}

describe('R10 Move 4: Provider stream stall defaults and overrides', () => {
  test('tightens defaultFirstEventTimeoutMs to 45s and defaultIdleTimeoutMs to 60s', () => {
    assert.equal(defaultFirstEventTimeoutMs, 45_000)
    assert.equal(defaultIdleTimeoutMs, 60_000)
  })

  test('honors explicit option overrides and env overrides for first-event and idle timeouts', async t => {
    const prevLocal = process.env.KOVO_ALLOW_LOCAL_MODEL
    const prevFirst = process.env.KOVO_PROVIDER_FIRST_EVENT_TIMEOUT_MS
    const prevIdle = process.env.KOVO_PROVIDER_IDLE_TIMEOUT_MS
    process.env.KOVO_ALLOW_LOCAL_MODEL = '1'
    t.after(() => {
      if (prevLocal === undefined) delete process.env.KOVO_ALLOW_LOCAL_MODEL
      else process.env.KOVO_ALLOW_LOCAL_MODEL = prevLocal
      if (prevFirst === undefined) delete process.env.KOVO_PROVIDER_FIRST_EVENT_TIMEOUT_MS
      else process.env.KOVO_PROVIDER_FIRST_EVENT_TIMEOUT_MS = prevFirst
      if (prevIdle === undefined) delete process.env.KOVO_PROVIDER_IDLE_TIMEOUT_MS
      else process.env.KOVO_PROVIDER_IDLE_TIMEOUT_MS = prevIdle
    })

    // Hang before response headers so firstEventTimeoutMs fires predictably.
    const hangServer = createServer((req) => {
      req.resume()
    }).listen(0, '127.0.0.1')
    await once(hangServer, 'listening')
    t.after(async () => {
      hangServer.closeAllConnections()
      await new Promise<void>(resolve => hangServer.close(() => resolve()))
    })
    const port = (hangServer.address() as AddressInfo).port
    const cfg = makeProviderConfig(`http://127.0.0.1:${port}`)

    // (a) Env override works when option is omitted.
    process.env.KOVO_PROVIDER_FIRST_EVENT_TIMEOUT_MS = '120'
    process.env.KOVO_PROVIDER_IDLE_TIMEOUT_MS = '250'
    const envProv = provider(cfg, 'worker-investigation', { maxTransportRetries: 0 })
    const t0 = Date.now()
    const envStream = envProv.models.stream(
      envProv.model,
      { systemPrompt: 'Wait for headers.', messages: [{ role: 'user', content: 'ping', timestamp: Date.now() }] },
    )
    for await (const _ev of envStream) { /* consume */ }
    const envRes = await envStream.result()
    const envElapsed = Date.now() - t0
    assert.equal(envRes.stopReason, 'error', 'env firstEventTimeoutMs override must abort stalled stream')
    assert.ok(envElapsed < 1_500, `expected env firstEventTimeoutMs (~120ms) abort, took ${envElapsed}ms`)

    // (b) Explicit option override takes precedence over a long env value.
    process.env.KOVO_PROVIDER_FIRST_EVENT_TIMEOUT_MS = '30000'
    const optProv = provider(cfg, 'worker-investigation', {
      firstEventTimeoutMs: 110,
      idleTimeoutMs: 250,
      maxTransportRetries: 0,
    })
    const t1 = Date.now()
    const optStream = optProv.models.stream(
      optProv.model,
      { systemPrompt: 'Wait for headers.', messages: [{ role: 'user', content: 'ping', timestamp: Date.now() }] },
    )
    for await (const _ev of optStream) { /* consume */ }
    const optRes = await optStream.result()
    const optElapsed = Date.now() - t1
    assert.equal(optRes.stopReason, 'error', 'explicit firstEventTimeoutMs override must abort stalled stream')
    assert.ok(optElapsed < 1_500, `expected option firstEventTimeoutMs (~110ms) abort, took ${optElapsed}ms`)
  })
})

describe('R10 Move 4: Bounded worker wall-clock ceiling & stall credit', () => {
  test('tightens chain and multi-hop wall-clock caps to 180s and 210s', () => {
    assert.equal(CHAIN_ASSIGNMENT_MAX_WALL_CLOCK_MS, 180_000)
    assert.equal(MULTI_HOP_CHAIN_MAX_WALL_CLOCK_MS, 210_000)
    assert.ok(MULTI_HOP_CHAIN_DEFAULT_WALL_CLOCK_MS <= MULTI_HOP_CHAIN_MAX_WALL_CLOCK_MS)

    const multiHop = resolveAssignmentBudget(
      { budgetClass: 'multi_hop_chain' },
      { baseMaxTurns: 30, baseWallClockMs: 180_000, runDurationMs: 1_800_000 },
    )
    assert.equal(multiHop.wallClockMs, 210_000)

    const multiStep = resolveAssignmentBudget(
      { budgetClass: 'multi_step', dependsOnFactIds: ['f1'] },
      { baseMaxTurns: 30, baseWallClockMs: 240_000, runDurationMs: 1_800_000 },
    )
    assert.equal(multiStep.wallClockMs, 180_000)
  })

  test('computeWorkerWallClockPlan caps maxStallCreditMs at min(60s, floor(0.35 * base)) so hard ceiling <= 1.35x base (<= 270s for 210s)', () => {
    for (const baseMs of [60_000, 90_000, 120_000, 180_000, 210_000, 300_000]) {
      const plan = computeWorkerWallClockPlan({ wallClockMs: baseMs, isMultiHop: baseMs >= 180_000 })
      const expectedCredit = Math.min(60_000, Math.floor((baseMs * 35) / 100))
      assert.equal(plan.maxStallCreditMs, expectedCredit, `base=${baseMs}: unexpected maxStallCreditMs`)
      assert.equal(plan.hardWallClockCeilingMs, baseMs + expectedCredit, `base=${baseMs}: unexpected hardWallClockCeilingMs`)
      assert.ok(
        plan.hardWallClockCeilingMs <= Math.floor((baseMs * 135) / 100),
        `base=${baseMs}: hard ceiling ${plan.hardWallClockCeilingMs} exceeds 1.35x base`,
      )
    }

    const multiHopPlan = computeWorkerWallClockPlan({ wallClockMs: MULTI_HOP_CHAIN_MAX_WALL_CLOCK_MS, isMultiHop: true })
    assert.equal(multiHopPlan.maxStallCreditMs, 60_000)
    assert.equal(multiHopPlan.hardWallClockCeilingMs, 270_000)
    assert.ok(multiHopPlan.hardWallClockCeilingMs <= 270_000, '210s multi-hop worker must never exceed 270s hard ceiling')
  })

  test('resolveWorkerVerifyGrace denies expanded_verify for non-in-flight, non-progressing kovo_verify calls', () => {
    const plan = computeWorkerWallClockPlan({ wallClockMs: 210_000, isMultiHop: true })

    // Preflight-rejected / syntax-errored kovo_verify: not in-flight, no sealed cap, no receipt candidate.
    const rejected = resolveWorkerVerifyGrace({
      plan,
      sessionActiveElapsedMs: 210_000,
      inFlightProofCall: false,
      enteredKovoVerify: true,
      kovoVerifyProgressed: false,
      hasLiveSealedCapability: false,
      hasHopCheckpoint: false,
      inSettlementStream: false,
    })
    assert.equal(rejected.verifyGraceApplied, false)
    assert.equal(rejected.reason, 'none')
    assert.equal(rejected.graceMs, 0)

    // Omitting kovoVerifyProgressed while not in-flight also denies expanded_verify.
    const legacyEnteredOnly = resolveWorkerVerifyGrace({
      plan,
      sessionActiveElapsedMs: 210_000,
      inFlightProofCall: false,
      enteredKovoVerify: true,
      hasLiveSealedCapability: false,
      hasHopCheckpoint: false,
      inSettlementStream: false,
    })
    assert.equal(legacyEnteredOnly.verifyGraceApplied, false)
    assert.equal(legacyEnteredOnly.reason, 'none')

    // In-flight kovo_verify call DOES qualify for expanded_verify grace.
    const inFlight = resolveWorkerVerifyGrace({
      plan,
      sessionActiveElapsedMs: 210_000,
      inFlightProofCall: true,
      enteredKovoVerify: true,
      kovoVerifyProgressed: false,
      hasLiveSealedCapability: false,
      hasHopCheckpoint: false,
      inSettlementStream: false,
    })
    assert.equal(inFlight.verifyGraceApplied, true)
    assert.equal(inFlight.reason, 'expanded_verify')
    assert.equal(inFlight.graceMs, 60_000)

    // Progressed kovo_verify (passed preflight & sealed cap / produced receipt candidate) DOES qualify.
    const progressed = resolveWorkerVerifyGrace({
      plan,
      sessionActiveElapsedMs: 210_000,
      inFlightProofCall: false,
      enteredKovoVerify: true,
      kovoVerifyProgressed: true,
      hasLiveSealedCapability: false,
      hasHopCheckpoint: false,
      inSettlementStream: false,
    })
    assert.equal(progressed.verifyGraceApplied, true)
    assert.equal(progressed.reason, 'expanded_verify')
    assert.equal(progressed.graceMs, 60_000)
  })

  test('ExecWorkerRunner does NOT grant expanded_verify grace after a preflight-rejected or syntax-errored kovo_verify call', async t => {
    const prevLocal = process.env.KOVO_ALLOW_LOCAL_MODEL
    process.env.KOVO_ALLOW_LOCAL_MODEL = '1'
    t.after(() => {
      if (prevLocal === undefined) delete process.env.KOVO_ALLOW_LOCAL_MODEL
      else process.env.KOVO_ALLOW_LOCAL_MODEL = prevLocal
    })

    const dir = makeTempDir(t, 'kovo-r10-preflight-grace-')
    const store = new Store(dir)
    t.after(() => { try { store.close() } catch { /* ignore */ } })

    const exec = new Execution(store, { broker: makeBroker(), backend: makeStubBackend(), deterministicSweep: false })
    t.after(() => exec.stop())

    const priv = exec as unknown as {
      workerRunner: ExecWorkerRunner
      verifier: {
        backendSupportsVerifyScript: () => boolean
        runAgentScriptProof: (...args: unknown[]) => Promise<AgentScriptProofResult>
      }
      active: Map<string, ExecActiveJob>
    }
    priv.verifier.backendSupportsVerifyScript = () => true
    priv.verifier.runAgentScriptProof = async (): Promise<AgentScriptProofResult> => ({
      verdict: {
        confirmed: false,
        reason: 'claims_missing',
        detail: 'SyntaxError: Unexpected token in kovo_verify script',
        attempts: [],
        disagreements: [],
        claimTitle: null,
        rejectedBy: 'preflight',
        missingEvidence: [],
        transcriptSummary: [],
      },
      exchanges: [],
      receipt: null,
      compositeReceipt: null,
      vulnClass: null,
      transcriptDigests: [],
      sealedCapabilities: [],
      transcriptRecords: [],
      hostTranscript: null,
      claimTitle: null,
      severity: null,
      description: null,
    })

    let turn = 0
    const server = createServer((req, res) => {
      req.resume()
      turn += 1
      res.writeHead(200, { 'content-type': 'text/event-stream' })
      if (turn === 1) {
        // Turn 1: preflight-rejected empty script call.
        res.end(responsesToolCallTurn('call_kv_bad_1', 'kovo_verify', { runtime: 'ts', script: '' }))
        return
      }
      if (turn === 2) {
        // Turn 2: syntax-errored kovo_verify returning confirmed=false with 0 sealed caps & no receipt.
        res.end(responsesToolCallTurn('call_kv_bad_2', 'kovo_verify', { runtime: 'ts', script: 'const x = {' }))
        return
      }
      // Turn 3: hang until soft deadline so rotation fires without any in-flight proof call.
    }).listen(0, '127.0.0.1')
    await once(server, 'listening')
    t.after(async () => {
      server.closeAllConnections()
      await new Promise<void>(resolve => server.close(() => resolve()))
    })
    const port = (server.address() as AddressInfo).port
    const profile = makeProfile(`http://127.0.0.1:${port}`)

    const { runId, run } = setupApprovedTestRun(store, 'R10 Preflight Grace Project')
    const asset = run.candidates[0]!
    const step = store.addChainStep(run, {
      title: 'Probe target workflow',
      hypothesis: 'Test rejected kovo_verify grace gating',
      category: 'broken-access-control',
      priority: 80,
      targetAssetIds: run.approved,
      sourceOrigins: [ORIGIN],
    })
    const worker = store.updateWorker(
      store.makeWorker(run, 'investigation', asset, step.title, step.hypothesis, {
        stepId: step.id,
        sourceOrigins: [ORIGIN],
      }).id,
      { status: 'running', lease: randomUUID(), leaseExpiresAt: Date.now() + 60_000 },
    )!
    const job: ExecActiveJob = { assignment: worker, origins: new Set([ORIGIN]), controller: new AbortController() }
    priv.active.set(worker.id, job)

    const budget: AssignmentBudget = { kind: 'chain', maxTurns: 6, wallClockMs: 350, settlementTurn: 5 }
    await priv.workerRunner.runInvestigationWorker(job, step, [ORIGIN], [profile], budget)
    priv.active.delete(worker.id)

    const rotatedEvents = store.eventsAfter(runId, 0, 200).filter(e => e.kind === 'worker.wall_clock_rotated')
    assert.equal(rotatedEvents.length, 1, 'expected worker.wall_clock_rotated event')
    const detail = rotatedEvents[0]!.detail as {
      verifyGraceApplied?: boolean
      verifyGraceReason?: string
    }
    assert.equal(detail.verifyGraceApplied, false, 'preflight/syntax-rejected kovo_verify must NOT unlock verify grace')
    assert.equal(detail.verifyGraceReason, 'none', `expected verifyGraceReason=none, got ${detail.verifyGraceReason}`)
  })
})
