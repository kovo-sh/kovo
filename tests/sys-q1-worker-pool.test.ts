/**
 * Systemic Quality Move Q1 Regression & Unit Tests:
 *  1. Tool-call malformed/truncated JSON preservation (`SseToolCallArgTracker` + `provider()` /
 *     `providerPool()`): stops silent `'{}'` erasure and returns an explicit repair diagnostic
 *     (`TOOL_CALL_JSON_REPAIR_HINT`) without leaking secrets.
 *  2. Warm-pool keying strictly on container-visible isolation state (`buildWarmPoolPolicy`,
 *     `ExecWorkerRunner` decoupled from host-only persona credential generations) AND concurrent-
 *     worker `warmPools` map safety in `LinuxWorkerBackend` during `openSession` / LRU eviction.
 *  3. Wall-clock rotation verify-time cliff (`computeWorkerWallClockPlan` + `ExecWorkerRunner`
 *     bounded verify-grace window preserving `ActiveClock` pause semantics).
 *  4. Ephemeral `derive_evidence` SQLite write hygiene (`shouldPersistDeriveEvidenceArtifact` +
 *     `buildSharedSessionHandlers().derive_evidence` skipping `artifacts` inserts for ephemeral
 *     shell reads while persisting materialized `/work/*` outputs and >12 KiB spilled outputs).
 */
import assert from 'node:assert/strict'
import { type ChildProcess } from 'node:child_process'
import { randomUUID } from 'node:crypto'
import { EventEmitter, once } from 'node:events'
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { createServer } from 'node:http'
import type { AddressInfo } from 'node:net'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { PassThrough } from 'node:stream'
import { describe, test } from 'node:test'
import { eq } from 'drizzle-orm'

import { runCommand } from '../src/domain.ts'
import { ActiveClock } from '../src/server/active-clock.ts'
import { runAgentSession } from '../src/server/agent-session.ts'
import { RequestBroker } from '../src/server/broker.ts'
import type { AssignmentBudget } from '../src/server/exec-dispatch.ts'
import type { ExecActiveJob } from '../src/server/exec-exchange.ts'
import {
  DEFAULT_SETTLEMENT_VERIFY_GRACE_MAX_MS,
  DEFAULT_VERIFY_GRACE_MAX_MS,
  DEFAULT_VERIFY_GRACE_MIN_MS,
  DERIVE_EVIDENCE_PERSIST_THRESHOLD_BYTES,
  ExecWorkerRunner,
  computeWorkerWallClockPlan,
  shouldPersistDeriveEvidenceArtifact,
} from '../src/server/exec-worker-runner.ts'
import { Execution } from '../src/server/execution.ts'
import type { ResolvedModelProfile } from '../src/server/model-settings.ts'
import {
  SseToolCallArgTracker,
  TOOL_CALL_JSON_REPAIR_HINT,
} from '../src/server/provider.ts'
import { evidence as evidenceTable } from '../src/server/schema.ts'
import { Store } from '../src/server/store.ts'
import {
  LinuxWorkerBackend,
  buildWarmPoolPolicy,
  type DockerRunner,
  type WorkerBackend,
  type WorkerResult,
  type WorkerSession,
} from '../src/server/worker-backend.ts'

const ORIGIN = 'https://q1-worker-pool.example.test'

function makeTempDir(t: { after(fn: () => void | Promise<void>): void }, prefix = 'kovo-q1-'): string {
  const dir = mkdtempSync(join(tmpdir(), prefix))
  t.after(() => rmSync(dir, { recursive: true, force: true }))
  return dir
}

function makeProfile(overrides: Partial<ResolvedModelProfile> & {
  id: string
  endpoint: string
  key: string
}): ResolvedModelProfile {
  return {
    name: overrides.id,
    model: 'q1-test-model',
    protocol: 'responses',
    enabled: true,
    priority: 100,
    contextWindow: 128_000,
    maxTokens: 4096,
    inputCostPerMtok: 0,
    cachedInputCostPerMtok: 0,
    outputCostPerMtok: 0,
    thinkingLevel: 'off',
    roleAffinity: 'any',
    healthState: 'closed',
    cooldownUntil: null,
    lastError: null,
    ...overrides,
  }
}

function sse(events: Array<{ type: string } & Record<string, unknown>>, done = true, named = false): string {
  return events
    .map(ev => (named ? `event: ${ev.type}\n` : '') + `data: ${JSON.stringify(ev)}\n\n`)
    .join('') + (done ? 'data: [DONE]\n\n' : '')
}

function responsesRawToolCallTurn(callId: string, name: string, rawArgs: string, incomplete = false): string {
  const fcId = `fc_${callId}`
  const item = {
    type: 'function_call',
    id: fcId,
    call_id: callId,
    name,
    arguments: rawArgs,
    status: incomplete ? 'incomplete' : 'completed',
  }
  const events: Array<{ type: string } & Record<string, unknown>> = [
    { type: 'response.created', response: { id: `resp_${callId}`, status: 'in_progress' } },
    { type: 'response.output_item.added', output_index: 0, item: { ...item, arguments: '', status: 'in_progress' } },
    { type: 'response.function_call_arguments.delta', output_index: 0, item_id: fcId, delta: rawArgs },
    { type: 'response.function_call_arguments.done', output_index: 0, item_id: fcId, name, arguments: rawArgs },
    { type: 'response.output_item.done', output_index: 0, item },
    {
      type: incomplete ? 'response.incomplete' : 'response.completed',
      response: {
        id: `resp_${callId}`,
        status: incomplete ? 'incomplete' : 'completed',
        ...(incomplete ? { incomplete_details: { reason: 'max_output_tokens' } } : {}),
        output: [item],
        usage: { input_tokens: 80, output_tokens: 40 },
      },
    },
  ]
  return sse(events, true)
}

function messagesRawToolCallTurn(callId: string, name: string, rawPartialJson: string, stopReason = 'tool_use'): string {
  return sse([
    {
      type: 'message_start',
      message: {
        id: `msg_${callId}`,
        type: 'message',
        role: 'assistant',
        model: 'q1-test-model',
        content: [],
        usage: { input_tokens: 80, output_tokens: 0 },
      },
    },
    {
      type: 'content_block_start',
      index: 0,
      content_block: { type: 'tool_use', id: callId, name, input: {} },
    },
    {
      type: 'content_block_delta',
      index: 0,
      delta: { type: 'input_json_delta', partial_json: rawPartialJson },
    },
    { type: 'content_block_stop', index: 0 },
    { type: 'message_delta', delta: { stop_reason: stopReason }, usage: { output_tokens: 40 } },
    { type: 'message_stop' },
  ], false, true)
}

function setupApprovedTestRun(store: Store, name = 'Q1 Test Project') {
  const project = store.createProject({
    requestId: randomUUID(),
    name,
    seeds: [ORIGIN],
    environment: 'public',
  })
  const { id: runId } = store.createRun({
    requestId: randomUUID(),
    projectId: project.id,
    goal: 'Q1 regression check',
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

function makeBroker(): RequestBroker {
  return new RequestBroker({
    resolve: async () => [{ address: '93.184.216.34', family: 4 }],
    transport: async () => ({ status: 200, headers: { 'content-type': 'application/json' }, body: '{"ok":true}' }),
  })
}

async function waitFor(predicate: () => boolean, timeoutMs = 3_000, label = 'condition'): Promise<void> {
  const deadline = Date.now() + timeoutMs
  while (Date.now() < deadline) {
    if (predicate()) return
    await new Promise(resolve => setTimeout(resolve, 10))
  }
  assert.ok(predicate(), `Timed out waiting for ${label} after ${timeoutMs}ms`)
}

// ============================================================================
// 1. Silent '{}' erasure fix on malformed/truncated tool-call JSON
// ============================================================================

describe('Q1.1: Malformed/truncated tool-call JSON diagnostic preservation', () => {
  test('SseToolCallArgTracker detects truncated/malformed JSON across Responses & Messages without false positives or secret leaks', () => {
    const secret = 'kovo-live-secret-token-xyz-998877'
    const redact = (s: string) => s.replaceAll(secret, '[redacted]')

    // 1. Valid JSON & genuine empty {} produce no diagnostic.
    const validTracker = new SseToolCallArgTracker()
    validTracker.feedData({
      type: 'response.output_item.added',
      output_index: 0,
      item: { type: 'function_call', id: 'fc_ok', call_id: 'call_ok', name: 'kovo_verify', arguments: '' },
    })
    validTracker.feedData({
      type: 'response.function_call_arguments.delta',
      output_index: 0,
      item_id: 'fc_ok',
      delta: '{"script":"return ctx.result({ title: \\"ok\\" })"}',
    })
    validTracker.feedData({
      type: 'response.output_item.added',
      output_index: 1,
      item: { type: 'function_call', id: 'fc_empty', call_id: 'call_empty', name: 'board_read', arguments: '{}' },
    })
    assert.equal(validTracker.diagnosticForToolCall({ id: 'call_ok|fc_ok', name: 'kovo_verify' }), undefined)
    assert.equal(validTracker.diagnosticForToolCall({ id: 'call_empty|fc_empty', name: 'board_read' }), undefined)

    // 2. Truncated Responses JSON carrying a secret produces truncated_json diagnostic and leaks zero secrets.
    const truncTracker = new SseToolCallArgTracker()
    truncTracker.feedData({
      type: 'response.output_item.added',
      output_index: 0,
      item: { type: 'function_call', id: 'fc_trunc', call_id: 'call_trunc', name: 'kovo_verify', arguments: '' },
    })
    truncTracker.feedData({
      type: 'response.function_call_arguments.delta',
      output_index: 0,
      item_id: 'fc_trunc',
      delta: `{"script":"const x = '${secret}'; await ctx.prove_access_boundary({`,
    })
    const diagResp = truncTracker.diagnosticForToolCall({ id: 'call_trunc|fc_trunc', name: 'kovo_verify' }, 0, redact)
    assert.ok(diagResp, 'truncated Responses JSON must produce diagnostic')
    assert.equal(diagResp.kind, 'truncated_json')
    assert.ok(diagResp.errorMessage.includes(TOOL_CALL_JSON_REPAIR_HINT))
    assert.equal(diagResp.errorMessage.includes(secret), false, 'diagnostic must never leak secret')
    assert.equal(diagResp.parseError.includes(secret), false, 'parseError must never leak secret')

    // 3. Anthropic Messages malformed JSON & max_tokens truncation.
    const msgTracker = new SseToolCallArgTracker()
    msgTracker.feedData({
      type: 'content_block_start',
      index: 0,
      content_block: { type: 'tool_use', id: 'toolu_mal', name: 'kovo_verify', input: {} },
    })
    msgTracker.feedData({
      type: 'content_block_delta',
      index: 0,
      delta: { type: 'input_json_delta', partial_json: `{"script": ${secret} broken` },
    })
    const diagMsg = msgTracker.diagnosticForToolCall({ id: 'toolu_mal', name: 'kovo_verify' }, 0, redact)
    assert.ok(diagMsg, 'malformed Messages JSON must produce diagnostic')
    assert.equal(diagMsg.kind, 'malformed_json')
    assert.ok(diagMsg.errorMessage.includes(TOOL_CALL_JSON_REPAIR_HINT))
    assert.equal(diagMsg.errorMessage.includes(secret), false)
  })

  for (const protocol of ['responses', 'messages'] as const) {
    test(`runAgentSession surfaces explicit truncated/malformed JSON repair message instead of silent '{}' erasure (${protocol})`, async t => {
      const prevLocal = process.env.KOVO_ALLOW_LOCAL_MODEL
      process.env.KOVO_ALLOW_LOCAL_MODEL = '1'
      t.after(() => {
        if (prevLocal === undefined) delete process.env.KOVO_ALLOW_LOCAL_MODEL
        else process.env.KOVO_ALLOW_LOCAL_MODEL = prevLocal
      })

      const dir = makeTempDir(t, `kovo-q1-json-${protocol}-`)
      const seenRequests: string[] = []
      let kovoVerifyCalls = 0
      let turn = 0

      const server = createServer(async (req, res) => {
        const chunks: Buffer[] = []
        for await (const c of req) chunks.push(Buffer.from(c))
        seenRequests.push(Buffer.concat(chunks).toString('utf8'))
        turn += 1
        res.writeHead(200, { 'content-type': 'text/event-stream' })
        if (turn === 1) {
          // Truncated JSON payload (missing closing quotes & brace) that sanitizeProviderStream collapses to '{}'.
          const brokenJson = '{"script":"await ctx.prove_access_boundary({ controlPersona: \'u2\', probePersona: \'u1\''
          res.end(
            protocol === 'responses'
              ? responsesRawToolCallTurn('call_trunc_1', 'kovo_verify', brokenJson)
              : messagesRawToolCallTurn('call_trunc_1', 'kovo_verify', brokenJson),
          )
          return
        }
        if (turn === 2) {
          const validJson = JSON.stringify({
            runtime: 'ts',
            script: 'return ctx.result({ title: "Concise verified proof" })',
          })
          res.end(
            protocol === 'responses'
              ? responsesRawToolCallTurn('call_ok_2', 'kovo_verify', validJson)
              : messagesRawToolCallTurn('call_ok_2', 'kovo_verify', validJson),
          )
          return
        }
        const doneJson = JSON.stringify({
          status: 'proved',
          summary: 'Repaired concise verification script succeeded.',
        })
        res.end(
          protocol === 'responses'
            ? responsesRawToolCallTurn('call_done_3', 'complete_intent', doneJson)
            : messagesRawToolCallTurn('call_done_3', 'complete_intent', doneJson),
        )
      }).listen(0, '127.0.0.1')
      await once(server, 'listening')
      t.after(async () => {
        server.closeAllConnections()
        await new Promise<void>(resolve => server.close(() => resolve()))
      })
      const port = (server.address() as AddressInfo).port

      const result = await runAgentSession({
        directory: dir,
        sessionId: `q1-json-${protocol}`,
        requestId: `req-q1-json-${protocol}`,
        profiles: [makeProfile({
          id: `prof-${protocol}`,
          endpoint: `http://127.0.0.1:${port}`,
          key: 'sk-q1-test-key-1234',
          protocol,
        })],
        scenario: 'worker-investigation',
        prompt: 'Verify the candidate finding with kovo_verify.',
        signal: AbortSignal.timeout(10_000),
        maxTurns: 6,
        handlers: {
          kovo_verify: async args => {
            kovoVerifyCalls += 1
            assert.ok(args.script?.includes('Concise verified proof'), 'kovo_verify must only be called once valid JSON arrives')
            return { confirmed: true, detail: 'ok' }
          },
          complete_intent: async c => c,
        },
      })

      assert.equal(result.status, 'completed')
      assert.equal(kovoVerifyCalls, 1, 'truncated tool call must be rejected before kovo_verify executes with {}')
      assert.ok(seenRequests.length >= 2)
      const secondTurnRequest = seenRequests[1]!
      assert.ok(
        secondTurnRequest.includes(TOOL_CALL_JSON_REPAIR_HINT),
        `turn 2 tool error must include explicit JSON repair guidance; got: ${secondTurnRequest.slice(0, 600)}`,
      )
      assert.equal(
        secondTurnRequest.includes('`script` is REQUIRED'),
        false,
        'must not blame missing `script` field when JSON arguments were truncated/malformed',
      )
    })
  }
})

// ============================================================================
// 2. Warm-pool isolation keying & concurrent openSession map safety
// ============================================================================

describe('Q1.2: Warm-pool decoupling from persona generations & concurrent openSession safety', () => {
  test('buildWarmPoolPolicy keys strictly on container-visible state (runId, reposDir, mountedRepos, image)', t => {
    const dir = makeTempDir(t, 'kovo-q1-policy-')
    const repoA = join(dir, 'repo-a')
    const repoB = join(dir, 'repo-b')
    mkdirSync(repoA)
    mkdirSync(repoB)

    const p1 = buildWarmPoolPolicy({ runId: 'run-1', reposDir: repoA, mountedRepos: ['svc-b', 'svc-a'], image: 'kovo-worker:v4' })
    const p2 = buildWarmPoolPolicy({ runId: 'run-1', reposDir: repoA, mountedRepos: ['svc-a', 'svc-b'], image: 'kovo-worker:v4' })
    assert.equal(p1, p2, 'order of mountedRepos must not change policy hash')
    assert.ok(p1.startsWith('run-1:'), 'policy preserves `${runId}:${hash}` prefix for run eviction')

    const pDiffRepo = buildWarmPoolPolicy({ runId: 'run-1', reposDir: repoB, mountedRepos: ['svc-a', 'svc-b'], image: 'kovo-worker:v4' })
    assert.notEqual(p1, pDiffRepo, 'different reposDir must change policy hash')

    const pDiffImage = buildWarmPoolPolicy({ runId: 'run-1', reposDir: repoA, mountedRepos: ['svc-a', 'svc-b'], image: 'kovo-worker:v5' })
    assert.notEqual(p1, pDiffImage, 'different image must change policy hash')

    const pDiffRun = buildWarmPoolPolicy({ runId: 'run-2', reposDir: repoA, mountedRepos: ['svc-a', 'svc-b'], image: 'kovo-worker:v4' })
    assert.notEqual(p1, pDiffRun, 'different runId must produce distinct policy')
  })

  test('ExecWorkerRunner never rotates warm pool when host-side persona credential generations bump', async t => {
    const prevLocal = process.env.KOVO_ALLOW_LOCAL_MODEL
    process.env.KOVO_ALLOW_LOCAL_MODEL = '1'
    t.after(() => {
      if (prevLocal === undefined) delete process.env.KOVO_ALLOW_LOCAL_MODEL
      else process.env.KOVO_ALLOW_LOCAL_MODEL = prevLocal
    })

    const dir = makeTempDir(t, 'kovo-q1-runner-warm-')
    const store = new Store(dir)
    t.after(() => { try { store.close() } catch { /* ignore */ } })

    const setPolicyCalls: Array<{ policy: string; reposDir?: string }> = []
    const openSessionPolicies: string[] = []
    const backend: WorkerBackend = {
      workerImage: 'kovo-worker:q1-test',
      setWarmPoolPolicy: (policy, opts) => {
        setPolicyCalls.push({ policy, reposDir: opts?.reposDir })
      },
      run: async () => ({ exitCode: 0, stdout: '', stderr: '', outputs: {} }),
      verifyStaticAst: async () => ({
        verified: false, engine: 'ast-grep', repo: '.', file: 'a.ts', startLine: 1, endLine: 1,
        matchedLines: [], codeExcerpt: '', matchCount: 0, durationMs: 1,
      }),
      openSession: async (_assignmentId, _signal, opts) => {
        if (opts?.warmPoolPolicy) openSessionPolicies.push(opts.warmPoolPolicy)
        return {
          stage: async name => `/evidence/${name}`,
          exec: async () => ({ exitCode: 0, stdout: '', stderr: '', outputs: {} }),
          analyze: async () => ({ ok: true }),
          sast: async req => ({ repo: req.repo, enginesRun: req.engines, engineStatus: {}, findings: [], totalFindings: 0, truncated: false, durationMs: 1 }),
          runScript: async req => ({ runtime: req.runtime, exitCode: 0, stdout: '', stderr: '', durationMs: 1, timedOut: false }),
          verifyStaticAst: async () => ({
            verified: false, engine: 'ast-grep', repo: '.', file: 'a.ts', startLine: 1, endLine: 1,
            matchedLines: [], codeExcerpt: '', matchCount: 0, durationMs: 1,
          }),
          close: async () => undefined,
        }
      },
    }

    const exec = new Execution(store, { broker: makeBroker(), backend, deterministicSweep: false })
    t.after(() => exec.stop())

    const server = createServer((req, res) => {
      req.resume()
      res.writeHead(200, { 'content-type': 'text/event-stream' })
      res.end(responsesRawToolCallTurn('call_done', 'complete_intent', JSON.stringify({
        status: 'ruled_out',
        summary: 'Quick completion.',
      })))
    }).listen(0, '127.0.0.1')
    await once(server, 'listening')
    t.after(async () => {
      server.closeAllConnections()
      await new Promise<void>(resolve => server.close(() => resolve()))
    })
    const port = (server.address() as AddressInfo).port
    const profile = makeProfile({ id: 'p-warm', endpoint: `http://127.0.0.1:${port}`, key: 'sk-q1-warm-1234' })

    const { runId, run } = setupApprovedTestRun(store, 'Warm Stability Project')
    const asset = run.candidates[0]!

    const priv = exec as unknown as {
      workerRunner: ExecWorkerRunner
      personaAuth: { sessions: { generation: (handle: string, runId: string) => number } }
      warmPoolPolicyRotationsByRun: Map<string, number>
      active: Map<string, ExecActiveJob>
    }
    let fakeGeneration = 1
    priv.personaAuth.sessions.generation = () => fakeGeneration

    for (let i = 1; i <= 3; i++) {
      fakeGeneration = i * 10 // Simulate background persona token auto-refresh bumping generation every worker!
      const step = store.addChainStep(run, {
        title: `Worker step ${i}`,
        hypothesis: `Check route /api/item-${i}`,
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
      const budget: AssignmentBudget = { kind: 'single_step', maxTurns: 4, wallClockMs: 30_000, settlementTurn: 3 }
      await priv.workerRunner.runInvestigationWorker(job, step, [ORIGIN], [profile], budget)
      priv.active.delete(worker.id)
    }

    assert.equal(setPolicyCalls.length, 3)
    assert.equal(new Set(setPolicyCalls.map(c => c.policy)).size, 1, 'warmPoolPolicy must remain identical across persona generation bumps')
    assert.equal(new Set(openSessionPolicies).size, 1)
    assert.equal(priv.warmPoolPolicyRotationsByRun.get(runId) ?? 0, 0, 'zero warm-pool rotations on persona token refresh')
    const rotatedEvents = store.eventsAfter(runId, 0, 200).filter(e => e.kind === 'worker.warm_pool_rotated')
    assert.equal(rotatedEvents.length, 0, 'no worker.warm_pool_rotated events emitted on persona refresh')
  })

  test('LinuxWorkerBackend concurrent workers never evict active warmPools entries mid-openSession and recycle cleanly', async t => {
    const root = makeTempDir(t, 'kovo-q1-concurrent-pool-')
    const repoA = join(root, 'repo-a')
    mkdirSync(repoA, { mode: 0o700 })
    writeFileSync(join(repoA, 'app.ts'), 'export const x = 1\n', { mode: 0o600 })

    const states = new Map<string, string>()
    const created: string[] = []
    const removed: string[] = []
    const stopHooks = new Map<string, () => void>()
    let releaseSlowInspect: (() => void) | undefined
    let slowInspectTriggered = false

    const runner: DockerRunner = async args => {
      const verb = args[0] === 'container' ? args[1] : args[0]
      if (verb === 'create') {
        const name = args[args.indexOf('--name') + 1]!
        states.set(name, 'created')
        created.push(name)
        return ''
      }
      if (verb === 'inspect') {
        const name = args[args.length - 1]!
        if (!slowInspectTriggered && name === created[0]) {
          slowInspectTriggered = true
          await new Promise<void>(resolve => { releaseSlowInspect = resolve })
        }
        return `${states.get(name) ?? 'missing'}\n`
      }
      if (verb === 'stop') {
        const name = args[args.length - 1]!
        states.set(name, 'exited')
        stopHooks.get(name)?.()
        return ''
      }
      if (verb === 'rm') {
        for (const arg of args.slice(2)) {
          if (arg.startsWith('-')) continue
          states.delete(arg)
          removed.push(arg)
        }
        return ''
      }
      return ''
    }

    const spawner = (name: string): ChildProcess => {
      const emitter = new EventEmitter() as EventEmitter & {
        stdin: PassThrough; stdout: PassThrough; stderr: PassThrough; kill: () => boolean
      }
      emitter.stdin = new PassThrough()
      emitter.stdout = new PassThrough()
      emitter.stderr = new PassThrough()
      let closed = false
      const finish = () => {
        if (closed) return
        closed = true
        emitter.emit('close', 0)
      }
      emitter.kill = () => { finish(); return true }
      stopHooks.set(name, finish)
      return emitter as unknown as ChildProcess
    }

    const backend = new LinuxWorkerBackend({
      workspace: { id: 'ws-q1-conc', directory: root },
      cell: 'q1-conc-cell',
      dockerRunner: runner,
      sessionSpawner: spawner,
      maxWarmPools: 2,
    })
    t.after(() => backend.closeWarmPool())
    backend.setWarmCapacity(2)

    const policyA = buildWarmPoolPolicy({ runId: 'run-a', reposDir: repoA, image: backend.workerImage })
    const policyB = buildWarmPoolPolicy({ runId: 'run-b', reposDir: repoA, image: backend.workerImage })
    const policyC = buildWarmPoolPolicy({ runId: 'run-c', reposDir: repoA, image: backend.workerImage })

    backend.setWarmPoolPolicy(policyA, { reposDir: repoA })
    await waitFor(() => backend.getWarmPoolStats(policyA)?.idle === 2, 2_000, 'run-a warm capacity 2')

    backend.setWarmPoolPolicy(policyB, { reposDir: repoA })
    await waitFor(() => backend.getWarmPoolStats(policyB)?.idle === 2, 2_000, 'run-b warm capacity 2')

    // Start Worker A1 mid-openSession (paused inside take()/inspect) AND Worker B1 active on policyB.
    const openA1Promise = backend.openSession('asgn-a1', AbortSignal.timeout(5_000), { reposDir: repoA, warmPoolPolicy: policyA })
    await waitFor(() => slowInspectTriggered && Boolean(releaseSlowInspect), 2_000, 'A1 paused mid-openSession')
    const sessB1 = await backend.openSession('asgn-b1', AbortSignal.timeout(5_000), { reposDir: repoA, warmPoolPolicy: policyB })

    // Installing Run C while BOTH Run A (mid-openSession) and Run B (active session) are live MUST NOT
    // delete either active slot from warmPools!
    backend.setWarmPoolPolicy(policyC, { reposDir: repoA })
    await waitFor(() => backend.getWarmPoolStats(policyC)?.idle === 2, 2_000, 'run-c warm ready')
    assert.ok(backend.getWarmPoolStats(policyA), 'active mid-openSession Run A pool must NOT be evicted')
    assert.ok(backend.getWarmPoolStats(policyB), 'active Run B pool must NOT be evicted')

    // Concurrently open a second worker on policyA while A1 finishes openSession.
    const openA2Promise = backend.openSession('asgn-a2', AbortSignal.timeout(5_000), { reposDir: repoA, warmPoolPolicy: policyA })
    releaseSlowInspect!()
    const [sessA1, sessA2] = await Promise.all([openA1Promise, openA2Promise])
    assert.equal(backend.containerStats().coldSessions, 0, 'both concurrent workers on policyA hit warm pool')

    // Closing both Run A sessions recycles containers cleanly, and excess idle pool is now reclaimed to maxWarmPools.
    await sessA1.close()
    await sessA2.close()
    assert.equal(backend.activeWarmPoolCount, 2, 'once idle, excess pool count trims back to maxWarmPools=2')
    await sessB1.close()
  })
})

// ============================================================================
// 3. Wall-clock rotation verify-time cliff & ActiveClock preservation
// ============================================================================

describe('Q1.3: Bounded verify-grace window & ActiveClock pause preservation', () => {
  test('computeWorkerWallClockPlan scales verify grace & settlement lead for production vs short test budgets', () => {
    const prodSingle = computeWorkerWallClockPlan({ wallClockMs: 90_000, isMultiHop: false })
    assert.ok(prodSingle.verifyGraceMs >= DEFAULT_VERIFY_GRACE_MIN_MS && prodSingle.verifyGraceMs <= DEFAULT_VERIFY_GRACE_MAX_MS)
    assert.ok(prodSingle.settlementStreamGraceMs >= 10_000 && prodSingle.settlementStreamGraceMs <= DEFAULT_SETTLEMENT_VERIFY_GRACE_MAX_MS)
    assert.ok(prodSingle.effectiveSettlementMs <= Math.floor(90_000 * 0.75))

    const prodMulti = computeWorkerWallClockPlan({ wallClockMs: 180_000, isMultiHop: true })
    assert.equal(prodMulti.verifyGraceMs, DEFAULT_VERIFY_GRACE_MAX_MS)
    assert.equal(prodMulti.settlementStreamGraceMs, DEFAULT_SETTLEMENT_VERIFY_GRACE_MAX_MS)

    const shortTest = computeWorkerWallClockPlan({ wallClockMs: 150, isMultiHop: false })
    assert.equal(shortTest.settlementStreamGraceMs, 0, 'short test budgets keep fast rotation without settlement extension')
    assert.ok(shortTest.verifyGraceMs >= 25 && shortTest.verifyGraceMs <= 150)

    const explicit = computeWorkerWallClockPlan({ wallClockMs: 90_000, explicitSettlementMs: 50_000 })
    assert.equal(explicit.effectiveSettlementMs, 50_000)
  })

  test('in-flight kovo_verify proof finishes inside bounded verify-grace window and respects ActiveClock pauses', async t => {
    const prevLocal = process.env.KOVO_ALLOW_LOCAL_MODEL
    process.env.KOVO_ALLOW_LOCAL_MODEL = '1'
    t.after(() => {
      if (prevLocal === undefined) delete process.env.KOVO_ALLOW_LOCAL_MODEL
      else process.env.KOVO_ALLOW_LOCAL_MODEL = prevLocal
    })

    const dir = makeTempDir(t, 'kovo-q1-verify-grace-')
    let turn = 0
    const server = createServer((req, res) => {
      req.resume()
      turn += 1
      res.writeHead(200, { 'content-type': 'text/event-stream' })
      if (turn === 1) {
        res.end(responsesRawToolCallTurn('call_kv_grace', 'kovo_verify', JSON.stringify({
          runtime: 'ts',
          script: 'return ctx.result({ title: "Grace verified proof" })',
        })))
        return
      }
      // Keep turn 2 open so wall-clock rotation triggers cleanly right after proof completes.
    }).listen(0, '127.0.0.1')
    await once(server, 'listening')
    t.after(async () => {
      server.closeAllConnections()
      await new Promise<void>(resolve => server.close(() => resolve()))
    })
    const port = (server.address() as AddressInfo).port

    const clock = new ActiveClock()
    t.after(() => clock.dispose())
    let verifyCompleted = false
    const rotations: Array<{ elapsedMs: number; graceUsedMs: number }> = []

    const result = await runAgentSession({
      directory: dir,
      sessionId: 'q1-verify-grace',
      requestId: 'req-q1-verify-grace',
      profiles: [makeProfile({ id: 'p-grace', endpoint: `http://127.0.0.1:${port}`, key: 'sk-q1-grace-1234' })],
      scenario: 'worker-investigation',
      prompt: 'Run kovo_verify now.',
      signal: AbortSignal.timeout(5_000),
      maxTurns: 6,
      wallClockMs: 120,
      wallClockGraceMs: 450,
      activeClock: clock,
      onWallClockRotate: info => rotations.push({ elapsedMs: info.elapsedMs, graceUsedMs: info.graceUsedMs }),
      handlers: {
        kovo_verify: async (_args, sig) => {
          // Pause ActiveClock mid-proof (simulating Tier-3 approval or run pause): neither wallClock
          // nor verifyGrace should expire during the pause!
          clock.pause('run_paused')
          await new Promise(r => setTimeout(r, 200))
          assert.equal(sig.aborted, false, 'proof signal must NOT abort while ActiveClock is paused')
          clock.resume('run_paused')
          // Exceed the 120ms wallClockMs budget while still inside the 450ms verify grace window.
          await new Promise(r => setTimeout(r, 220))
          assert.equal(sig.aborted, false, 'proof signal must stay alive inside bounded verify-grace window')
          verifyCompleted = true
          return { confirmed: true, detail: 'Persisted inside verify grace window.' }
        },
        complete_intent: async c => c,
      },
    })

    assert.equal(verifyCompleted, true, 'in-flight kovo_verify must complete inside bounded verify grace')
    assert.equal(result.status, 'wall_clock_rotated')
    assert.equal(rotations.length, 1)
    assert.ok(rotations[0]!.graceUsedMs > 0, `expected graceUsedMs > 0, got ${rotations[0]!.graceUsedMs}`)
  })
})

// ============================================================================
// 4. Ephemeral derive_evidence SQLite write hygiene
// ============================================================================

describe('Q1.4: Ephemeral derive_evidence SQLite artifact write hygiene', () => {
  test('shouldPersistDeriveEvidenceArtifact skips ephemeral reads and persists materialized/oversized/explicit evidence', () => {
    assert.equal(DERIVE_EVIDENCE_PERSIST_THRESHOLD_BYTES, 12 * 1024)
    assert.equal(shouldPersistDeriveEvidenceArtifact({ outputs: {}, stdout: 'line 1\nline 2\n', stderr: '' }), false)
    assert.equal(shouldPersistDeriveEvidenceArtifact({ outputs: { 'result.txt': '   ' }, stdout: 'short' }), false)
    assert.equal(shouldPersistDeriveEvidenceArtifact({ outputs: { 'result.txt': 'extracted-finding' }, stdout: '' }), true)
    assert.equal(shouldPersistDeriveEvidenceArtifact({ outputs: {}, stdout: 'x'.repeat(12 * 1024 + 1) }), true)
    assert.equal(shouldPersistDeriveEvidenceArtifact({ outputs: {}, stdout: 'short', explicitPersist: true }), true)
  })

  test('buildSharedSessionHandlers().derive_evidence inserts 0 SQLite rows for ephemeral calls and persists materialized/spilled calls', async t => {
    const dir = makeTempDir(t, 'kovo-q1-derive-db-')
    const store = new Store(dir)
    t.after(() => { try { store.close() } catch { /* ignore */ } })

    let nextExecResult: WorkerResult = { exitCode: 0, stdout: 'src/app.ts\n', stderr: '', outputs: {} }
    const stubSession: WorkerSession = {
      stage: async name => `/evidence/${name}`,
      exec: async () => nextExecResult,
      analyze: async () => ({ ok: true }),
      sast: async req => ({ repo: req.repo, enginesRun: req.engines, engineStatus: {}, findings: [], totalFindings: 0, truncated: false, durationMs: 1 }),
      runScript: async req => ({ runtime: req.runtime, exitCode: 0, stdout: '', stderr: '', durationMs: 1, timedOut: false }),
      verifyStaticAst: async () => ({
        verified: false, engine: 'ast-grep', repo: '.', file: 'a.ts', startLine: 1, endLine: 1,
        matchedLines: [], codeExcerpt: '', matchCount: 0, durationMs: 1,
      }),
      close: async () => undefined,
    }
    const stubBackend: WorkerBackend = {
      run: async () => nextExecResult,
      openSession: async () => stubSession,
      verifyStaticAst: async () => ({
        verified: false, engine: 'ast-grep', repo: '.', file: 'a.ts', startLine: 1, endLine: 1,
        matchedLines: [], codeExcerpt: '', matchCount: 0, durationMs: 1,
      }),
    }

    const exec = new Execution(store, { broker: makeBroker(), backend: stubBackend, deterministicSweep: false })
    t.after(() => exec.stop())

    const { runId, run } = setupApprovedTestRun(store, 'Derive Evidence Hygiene')
    const asset = run.candidates[0]!
    const worker = store.updateWorker(
      store.makeWorker(run, 'investigation', asset, 'Hygiene worker', 'Inspect source files', {
        sourceOrigins: [ORIGIN],
      }).id,
      { status: 'running', lease: randomUUID(), leaseExpiresAt: Date.now() + 60_000 },
    )!
    const job: ExecActiveJob = { assignment: worker, origins: new Set([ORIGIN]), controller: new AbortController() }
    const priv = exec as unknown as {
      workerRunner: ExecWorkerRunner
      active: Map<string, ExecActiveJob>
    }
    priv.active.set(worker.id, job)

    const shared = priv.workerRunner.buildSharedSessionHandlers(job, stubSession, () => [], {
      offlineScriptLabel: 'Offline {runtime} script',
      deriveEvidenceTitle: 'Derived evidence',
    })

    const countArtifacts = () =>
      store.db.select({ id: evidenceTable.id }).from(evidenceTable).where(eq(evidenceTable.runId, runId)).all().length

    const baselineCount = countArtifacts()

    // 1. 10 ephemeral shell calls (ls/head/rg with no materialized outputs and small stdout) -> 0 DB inserts!
    for (let i = 0; i < 10; i++) {
      nextExecResult = { exitCode: 0, stdout: `file-${i}.ts\n`, stderr: '', outputs: {} }
      const out = await shared.derive_evidence({ command: `head -n 20 /repos/app/file-${i}.ts` }, job.controller.signal)
      assert.equal(out.exitCode, 0)
      assert.equal('evidenceId' in out, false, 'ephemeral derive_evidence must not allocate a SQLite artifact row')
      assert.equal((out as { ephemeral?: boolean }).ephemeral, true)
    }
    assert.equal(countArtifacts(), baselineCount, 'ephemeral derive_evidence calls must write 0 rows to SQLite artifacts')

    // 2. Materialized /work/result.txt output -> persists 1 SQLite artifact row with evidenceId.
    nextExecResult = { exitCode: 0, stdout: 'wrote result\n', stderr: '', outputs: { 'result.txt': 'confirmed-token-match' } }
    const materialized = await shared.derive_evidence({ command: 'jq . /evidence/x.json > /work/result.txt' }, job.controller.signal)
    assert.ok('evidenceId' in materialized && typeof materialized.evidenceId === 'string')
    assert.equal(countArtifacts(), baselineCount + 1)

    // 3. Oversized (>12 KiB) stdout -> persists 1 SQLite artifact row with evidenceId.
    nextExecResult = { exitCode: 0, stdout: 'A'.repeat(12 * 1024 + 64), stderr: '', outputs: {} }
    const oversized = await shared.derive_evidence({ command: 'cat /repos/app/large.json' }, job.controller.signal)
    assert.ok('evidenceId' in oversized && typeof oversized.evidenceId === 'string')
    assert.equal(countArtifacts(), baselineCount + 2)
  })
})
