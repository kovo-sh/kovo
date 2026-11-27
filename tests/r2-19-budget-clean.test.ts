/**
 * R2-19 (`r2-19-budget-clean`) fast class-level guards:
 *  1. Zero remaining references to deleted `@deprecated` legacy specialist wall-clock /
 *     max-turns constants across `src/` and `tests/`.
 *  2. Single-source `resolveAssignmentBudget` derives `wallClockMs` cleanly (bounded by
 *     `intentLeaseMs` and budget caps) with strictly non-decreasing seconds-per-turn as
 *     `maxTurns` grows across `single_step` (8..18), `multi_step` (20..34), and `multi_hop_chain`.
 *  3. `v8-slot-rotation.test.ts` and `gb-planner-wiring.test.ts` are absent from `tests/QUARANTINE.json`.
 *  4. Per-run `token-telemetry.ts` is live on `runAgentSession` (`runId` + `onTelemetry` +
 *     tool-result byte/spill tracking + wall-clock rotation tracking) and readable via
 *     `Execution.getRunTokenTelemetry(runId)` with clean disposal on `disposeRun`.
 */
import assert from 'node:assert/strict'
import { readdirSync, readFileSync, statSync } from 'node:fs'
import { createServer, type Server } from 'node:http'
import type { AddressInfo } from 'node:net'
import { join, resolve } from 'node:path'
import { test } from 'node:test'
import { fileURLToPath } from 'node:url'

import { runAgentSession } from '../src/server/agent-session.ts'
import {
  CHAIN_ASSIGNMENT_MAX_WALL_CLOCK_MS,
  CHAIN_ASSIGNMENT_MIN_WALL_CLOCK_MS,
  MULTI_HOP_CHAIN_MAX_WALL_CLOCK_MS,
  SINGLE_STEP_ASSIGNMENT_WALL_CLOCK_MS,
  intentLeaseMs,
  resolveAssignmentBudget,
} from '../src/server/exec-dispatch.ts'
import { Execution } from '../src/server/execution.ts'
import { saveModelProfile } from '../src/server/model-settings.ts'
import {
  disposeRunTokenTelemetry,
  getRunTokenTelemetrySummary,
  hasRunTokenTelemetry,
  type ProviderUsageTelemetryInput,
} from '../src/server/token-telemetry.ts'
import type { WorkerBackend, WorkerSession } from '../src/server/worker-backend.ts'
import { makeStore, setupApprovedRun, stopExecution, withEnv } from './v4-tier-helpers.ts'

process.env.KOVO_ALLOW_LOCAL_LAB = '1'
process.env.KOVO_ALLOW_LOCAL_MODEL = '1'

const REPO_ROOT = resolve(fileURLToPath(new URL('..', import.meta.url)))

function walkTsFiles(dir: string, out: string[] = []): string[] {
  for (const entry of readdirSync(dir)) {
    const full = join(dir, entry)
    const st = statSync(full)
    if (st.isDirectory()) {
      walkTsFiles(full, out)
    } else if (/\.(?:ts|tsx|mts|cts)$/.test(entry)) {
      out.push(full)
    }
  }
  return out
}

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

async function startTelemetryMockLlm(
  t: { after: (fn: () => void | Promise<void>) => void },
  handler: (reqIndex: number) => {
    hang?: boolean
    toolCall?: { callId: string; name: string; argumentsJson: string }
    text?: string
    usage?: { input: number; cached: number; output: number }
  },
): Promise<{ endpoint: string; calls: number }> {
  let calls = 0
  const server: Server = createServer((req, res) => {
    const chunks: Buffer[] = []
    req.on('data', c => chunks.push(c as Buffer))
    req.on('end', () => {
      calls += 1
      const reply = handler(calls)
      if (reply.hang) {
        res.on('close', () => { if (!res.writableEnded) res.end() })
        return
      }
      res.statusCode = 200
      res.setHeader('Content-Type', 'text/event-stream')
      res.setHeader('Cache-Control', 'no-cache')
      const idx = calls
      const itemId = `item_${idx}`
      const responseId = `resp_${idx}`
      const u = reply.usage ?? { input: 200, cached: 50, output: 60 }
      const emit = (event: string, data: Record<string, unknown>) => {
        res.write(`event: ${event}\ndata: ${JSON.stringify(data)}\n\n`)
      }
      emit('response.created', { type: 'response.created', response: { id: responseId, status: 'in_progress', output: [] } })
      if (reply.toolCall) {
        emit('response.output_item.added', {
          type: 'response.output_item.added',
          output_index: 0,
          item: { id: itemId, type: 'function_call', status: 'in_progress', call_id: reply.toolCall.callId, name: reply.toolCall.name, arguments: '' },
        })
        emit('response.function_call_arguments.done', {
          type: 'response.function_call_arguments.done',
          output_index: 0,
          item_id: itemId,
          name: reply.toolCall.name,
          arguments: reply.toolCall.argumentsJson,
        })
        emit('response.output_item.done', {
          type: 'response.output_item.done',
          output_index: 0,
          item: { id: itemId, type: 'function_call', status: 'completed', call_id: reply.toolCall.callId, name: reply.toolCall.name, arguments: reply.toolCall.argumentsJson },
        })
        emit('response.completed', {
          type: 'response.completed',
          response: {
            id: responseId,
            status: 'completed',
            output: [{ id: itemId, type: 'function_call', status: 'completed', call_id: reply.toolCall.callId, name: reply.toolCall.name, arguments: reply.toolCall.argumentsJson }],
            usage: {
              input_tokens: u.input,
              output_tokens: u.output,
              total_tokens: u.input + u.output,
              input_tokens_details: { cached_tokens: u.cached },
            },
          },
        })
      } else {
        const text = reply.text ?? 'done'
        emit('response.output_item.added', {
          type: 'response.output_item.added',
          output_index: 0,
          item: { id: itemId, type: 'message', status: 'in_progress', role: 'assistant', content: [] },
        })
        emit('response.output_text.done', {
          type: 'response.output_text.done',
          output_index: 0,
          item_id: itemId,
          content_index: 0,
          text,
        })
        emit('response.output_item.done', {
          type: 'response.output_item.done',
          output_index: 0,
          item: { id: itemId, type: 'message', status: 'completed', role: 'assistant', content: [{ type: 'output_text', text }] },
        })
        emit('response.completed', {
          type: 'response.completed',
          response: {
            id: responseId,
            status: 'completed',
            output: [{ id: itemId, type: 'message', status: 'completed', role: 'assistant', content: [{ type: 'output_text', text }] }],
            usage: {
              input_tokens: u.input,
              output_tokens: u.output,
              total_tokens: u.input + u.output,
              input_tokens_details: { cached_tokens: u.cached },
            },
          },
        })
      }
      res.write('data: [DONE]\n\n')
      res.end()
    })
  })
  await new Promise<void>(resolveListen => server.listen(0, '127.0.0.1', () => resolveListen()))
  const { port } = server.address() as AddressInfo
  t.after(async () => {
    server.closeAllConnections?.()
    await new Promise<void>(resolveClose => server.close(() => resolveClose()))
  })
  return {
    endpoint: `http://127.0.0.1:${port}/v1`,
    get calls() { return calls },
  }
}

// ============================================================================
// 1. Deleted @deprecated constants & unquarantined budget/rotation tests
// ============================================================================

test('R2-19a: deprecated AGENTIC_SPECIALIST_* constants are completely removed across src/ and tests/', () => {
  const prefix = 'AGENTIC_SPECIALIST_'
  const banned = new RegExp([`${prefix}WALL_CLOCK_MS`, `${prefix}MAX_TURNS`].join('|'))
  const hits: string[] = []
  for (const root of [join(REPO_ROOT, 'src'), join(REPO_ROOT, 'tests')]) {
    for (const file of walkTsFiles(root)) {
      const content = readFileSync(file, 'utf8')
      if (banned.test(content)) hits.push(file)
    }
  }
  assert.deepEqual(hits, [], `deprecated specialist constants must have zero references, found in: ${hits.join(', ')}`)
})

test('R2-19b: tests/v8-slot-rotation.test.ts and tests/gb-planner-wiring.test.ts are removed from QUARANTINE.json', () => {
  const quarantine = JSON.parse(readFileSync(join(REPO_ROOT, 'tests/QUARANTINE.json'), 'utf8')) as {
    version: number
    maxQuarantinedCases: number
    entries: Array<{ file: string; testName: string }>
  }
  const files = new Set(quarantine.entries.map(e => e.file))
  assert.equal(files.has('tests/v8-slot-rotation.test.ts'), false, 'v8-slot-rotation.test.ts must be out of quarantine')
  assert.equal(files.has('tests/gb-planner-wiring.test.ts'), false, 'gb-planner-wiring.test.ts must be out of quarantine')
  assert.ok(quarantine.entries.length <= quarantine.maxQuarantinedCases)
})

// ============================================================================
// 2. Monotone non-decreasing seconds-per-turn in resolveAssignmentBudget
// ============================================================================

test('R2-19a: resolveAssignmentBudget keeps seconds-per-turn non-decreasing as maxTurns grows and bounds by intentLeaseMs', () => {
  const leaseCeiling = Math.floor(intentLeaseMs * 0.85)

  for (const singleCap of [60_000, 85_000, 90_000, SINGLE_STEP_ASSIGNMENT_WALL_CLOCK_MS]) {
    let prevSingleRate = 0
    for (let turns = 8; turns <= 18; turns += 1) {
      const b = resolveAssignmentBudget(
        { budgetClass: 'single_step' },
        { baseMaxTurns: turns, singleStepWallClockMs: singleCap },
      )
      assert.equal(b.maxTurns, turns)
      assert.ok(b.wallClockMs <= singleCap && b.wallClockMs <= leaseCeiling)
      const rate = b.wallClockMs / b.maxTurns
      assert.ok(
        rate >= prevSingleRate,
        `single_step sec/turn decreased at cap=${singleCap} turns=${turns}: ${rate} < ${prevSingleRate}`,
      )
      prevSingleRate = rate
    }

    let prevMultiRate = prevSingleRate
    const multiByTurns = new Map<number, number>()
    for (let turns = 20; turns <= 34; turns += 1) {
      const b = resolveAssignmentBudget(
        { budgetClass: 'multi_step', dependsOnFactIds: ['f-upstream'] },
        { baseMaxTurns: turns, singleStepWallClockMs: singleCap, runDurationMs: 900_000 },
      )
      assert.equal(b.maxTurns, turns)
      assert.ok(
        b.wallClockMs >= CHAIN_ASSIGNMENT_MIN_WALL_CLOCK_MS && b.wallClockMs <= CHAIN_ASSIGNMENT_MAX_WALL_CLOCK_MS,
        `multi_step wallClockMs=${b.wallClockMs} out of [${CHAIN_ASSIGNMENT_MIN_WALL_CLOCK_MS}..${CHAIN_ASSIGNMENT_MAX_WALL_CLOCK_MS}]`,
      )
      assert.ok(b.wallClockMs <= leaseCeiling)
      multiByTurns.set(turns, b.wallClockMs)
      const rate = b.wallClockMs / b.maxTurns
      if (b.wallClockMs < CHAIN_ASSIGNMENT_MAX_WALL_CLOCK_MS) {
        assert.ok(
          rate >= prevMultiRate,
          `multi_step sec/turn decreased at cap=${singleCap} turns=${turns}: ${rate} < ${prevMultiRate}`,
        )
        prevMultiRate = rate
      } else {
        assert.equal(b.wallClockMs, CHAIN_ASSIGNMENT_MAX_WALL_CLOCK_MS)
      }
    }

    for (const runDurationMs of [600_000, 900_000, 1_800_000]) {
      for (const turns of [20, 25, 30, 34]) {
        const b = resolveAssignmentBudget(
          { budgetClass: 'multi_hop_chain' },
          { baseMaxTurns: turns, singleStepWallClockMs: singleCap, runDurationMs },
        )
        assert.equal(b.maxTurns, turns)
        assert.ok(b.wallClockMs <= MULTI_HOP_CHAIN_MAX_WALL_CLOCK_MS && b.wallClockMs <= leaseCeiling)
        const multiWall = multiByTurns.get(turns) ?? CHAIN_ASSIGNMENT_MIN_WALL_CLOCK_MS
        assert.ok(
          b.wallClockMs >= multiWall,
          `multi_hop_chain wallClockMs (${b.wallClockMs}) must be >= multi_step (${multiWall}) at cap=${singleCap}, runDurationMs=${runDurationMs}, turns=${turns}`,
        )
        const rate = b.wallClockMs / b.maxTurns
        if (b.wallClockMs < MULTI_HOP_CHAIN_MAX_WALL_CLOCK_MS) {
          assert.ok(
            rate >= prevMultiRate,
            `multi_hop_chain sec/turn (${rate}) must be >= multi_step (${prevMultiRate}) at cap=${singleCap}, runDurationMs=${runDurationMs}, turns=${turns}`,
          )
        }
      }
    }
  }
})

// ============================================================================
// 3. Live token-telemetry wiring on runAgentSession + Execution summary reader
// ============================================================================

test('R2-19c: runAgentSession wires runId, onTelemetry, tool-result bytes/spills, and wall-clock rotations into token-telemetry', async t => {
  const runId = `r2-19-live-telemetry-${Date.now()}`
  t.after(() => { disposeRunTokenTelemetry(runId) })

  const observedEvents: ProviderUsageTelemetryInput[] = []
  const llm = await startTelemetryMockLlm(t, idx => {
    if (idx === 1) {
      return {
        toolCall: {
          callId: 'c_fact_1',
          name: 'record_fact',
          argumentsJson: JSON.stringify({ kind: 'note', origin: 'https://target.example.invalid', summary: 'Checked route' }),
        },
        usage: { input: 300, cached: 120, output: 75 },
      }
    }
    return {
      toolCall: {
        callId: 'c_done_1',
        name: 'complete_intent',
        argumentsJson: JSON.stringify({ status: 'ruled_out', summary: 'Done with telemetry.' }),
      },
      usage: { input: 400, cached: 200, output: 50 },
    }
  })

  const { dir } = makeStore(t)
  const result = await runAgentSession({
    directory: dir,
    runId,
    sessionId: 'sess-r219-tel',
    requestId: 'req-r219-tel',
    settings: {
      name: 'Tel-Mock',
      endpoint: llm.endpoint,
      model: 'mock-tel',
      protocol: 'responses',
      key: 'sk-mock-tel-1234',
      contextWindow: 128_000,
      maxTokens: 4096,
      thinkingLevel: 'medium',
      roleAffinity: 'tactical',
      inputCostPerMtok: 2,
      cachedInputCostPerMtok: 0.5,
      outputCostPerMtok: 4,
    },
    scenario: 'worker-investigation',
    prompt: 'Run a quick check.',
    signal: new AbortController().signal,
    maxTurns: 6,
    onTelemetry: ev => observedEvents.push(ev),
    handlers: {
      record_fact: async () => JSON.stringify({ ok: true, id: 'fact-1', detail: 'x'.repeat(256) }),
      complete_intent: async c => JSON.stringify(c),
    },
  })

  assert.equal(result.status, 'completed')
  assert.ok(observedEvents.length >= 2, `expected onTelemetry callback events, got ${observedEvents.length}`)
  assert.ok(observedEvents.every(ev => ev.runId === runId), 'every provider telemetry event must carry the live runId')
  assert.equal(hasRunTokenTelemetry(runId), true)

  const summary = getRunTokenTelemetrySummary(runId)
  assert.equal(summary.inputTokens, 700)
  assert.equal(summary.cachedInputTokens, 320)
  assert.equal(summary.outputTokens, 125)
  assert.ok(summary.totalCostUsd > 0, 'expected non-zero USD spend recorded in per-run token telemetry')
  assert.ok(summary.providerCalls >= 2)
  assert.ok(summary.totalToolResultBytes > 256, `expected tool result bytes tracked, got ${summary.totalToolResultBytes}`)
  assert.ok((summary.toolResultBytesByTool.record_fact?.calls ?? 0) >= 1)

  // Wall-clock rotation increments wallClockRotations under the same runId
  const hangLlm = await startTelemetryMockLlm(t, () => ({ hang: true }))
  const rotResult = await runAgentSession({
    directory: dir,
    runId,
    sessionId: 'sess-r219-rot',
    requestId: 'req-r219-rot',
    settings: {
      name: 'Rot-Tel-Mock',
      endpoint: hangLlm.endpoint,
      model: 'mock-rot-tel',
      protocol: 'responses',
      key: 'sk-mock-rot-1234',
      contextWindow: 128_000,
      maxTokens: 4096,
      thinkingLevel: 'medium',
      roleAffinity: 'tactical',
      inputCostPerMtok: 0,
      cachedInputCostPerMtok: 0,
      outputCostPerMtok: 0,
    },
    scenario: 'worker-investigation',
    prompt: 'Hang until wall-clock rotation.',
    signal: new AbortController().signal,
    maxTurns: 6,
    wallClockMs: 120,
    handlers: {
      complete_intent: async c => JSON.stringify(c),
    },
  })
  assert.equal(rotResult.status, 'wall_clock_rotated')
  assert.equal(getRunTokenTelemetrySummary(runId).wallClockRotations, 1)
})

test('R2-19c: Execution.getRunTokenTelemetry exposes live worker spend/tokens and purges on disposeRun', async t => {
  const origin = 'https://target.example.invalid'
  const llm = await startTelemetryMockLlm(t, () => ({
    toolCall: {
      callId: 'c_exec_done',
      name: 'complete_intent',
      argumentsJson: JSON.stringify({ status: 'ruled_out', summary: 'Checked route.' }),
    },
    usage: { input: 500, cached: 100, output: 120 },
  }))
  const { storage } = makeStore(t)
  await saveModelProfile({
    name: 'Exec-Tel-Mock',
    endpoint: llm.endpoint,
    model: 'mock-exec-tel',
    protocol: 'responses',
    key: 'sk-mock-exec-tel-1234',
    priority: 100,
    enabled: true,
    contextWindow: 128_000,
    maxTokens: 4096,
    thinkingLevel: 'medium',
    roleAffinity: 'tactical',
    inputCostPerMtok: 1,
    cachedInputCostPerMtok: 0.25,
    outputCostPerMtok: 2,
  }, storage, { skipConnectionCheck: true })

  const { runId, run } = await setupApprovedRun(storage, { seeds: [origin], budgetUsd: 2, budgetRequests: 500 })
  const step = storage.addChainStep(run, {
    title: 'Telemetry check step',
    hypothesis: 'Probe GET /api/v1/health.',
    category: 'broken-access-control',
    priority: 90,
    targetAssetIds: run.approved,
    sourceOrigins: [origin],
  })
  // Second step keeps the run active briefly so we can snapshot live telemetry before run disposal.
  const holdStep = storage.addChainStep(run, {
    title: 'Telemetry hold step',
    hypothesis: 'Probe GET /api/v1/status.',
    category: 'broken-access-control',
    priority: 50,
    targetAssetIds: run.approved,
    sourceOrigins: [origin],
    dependsOnStepIds: [step.id],
  })
  storage.updateRun(runId, { phase: 'investigation', status: 'running', workerConcurrency: 1, multiTrialEnabled: false })

  const engine = new Execution(storage, { backend: stubBackend(), deterministicSweep: false })
  assert.equal(engine.getRunTokenTelemetry(runId), null, 'unknown run must not allocate telemetry')

  let liveTelemetry = engine.getRunTokenTelemetry(runId)
  await withEnv({ KOVO_ALLOW_LOCAL_LAB: '1', KOVO_ALLOW_LOCAL_MODEL: '1' }, async () => {
    engine.start()
    engine.wake()
    const deadline = Date.now() + 4_000
    while (Date.now() < deadline) {
      const snap = engine.getRunTokenTelemetry(runId)
      if (snap && snap.providerCalls >= 1) liveTelemetry = snap
      const steps = storage.listChainSteps(runId, run.goalRevision)
      const s1 = steps.find(x => x.id === step.id)
      const s2 = steps.find(x => x.id === holdStep.id)
      if (s1?.status === 'complete' && s2?.status === 'complete') break
      await new Promise(r => setTimeout(r, 15))
    }
    if (!liveTelemetry) liveTelemetry = engine.getRunTokenTelemetry(runId)
    await stopExecution(engine as never)
  })

  const telemetry = liveTelemetry
  assert.ok(telemetry, 'Execution.getRunTokenTelemetry must return live per-run telemetry after worker turns')
  assert.equal(telemetry.runId, runId)
  assert.ok(telemetry.inputTokens >= 500, `expected >= 500 input tokens, got ${telemetry.inputTokens}`)
  assert.ok(telemetry.cachedInputTokens >= 100)
  assert.ok(telemetry.outputTokens >= 120)
  assert.ok(telemetry.totalCostUsd > 0)
  assert.ok(telemetry.providerCalls >= 1)

  await engine.disposeRun(runId)
  assert.equal(engine.getRunTokenTelemetry(runId), null, 'disposeRun must purge per-run token telemetry')
})
