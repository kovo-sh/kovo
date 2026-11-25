/**
 * Kovo Hunter v5.1 — agentic trace capture + metrics contract suite.
 *
 * Covers the trace store layout, content-addressed blob dedupe, deterministic redaction,
 * event schema round-trip, 4 KiB preview bounds, best-effort failure, and the nine metrics
 * (including `--gate` pass/fail). No app/route literals, no network, no new dependencies.
 */
import assert from 'node:assert/strict'
import { existsSync, mkdtempSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { basename, join } from 'node:path'
import { test } from 'node:test'
import {
  createAgentTrace,
  createAgentTraceFromEnv,
  maxTraceEventBytes,
  maxTracePreviewBytes,
  readBlob,
  readTrace,
  resolveTraceConfig,
  SecretRegistry,
  sha256Hex,
  type AgentTrace,
  type LifecycleEvent,
  type PlannerDecisionEvent,
  type ToolResultEvent,
  type TraceManifestInput,
  type TurnEvent,
} from '../src/server/agent-trace.ts'
import {
  computeTraceMetrics,
  evaluateTraceGate,
  formatMetricsTable,
  main,
  type TraceMetrics,
} from '../scripts/trace-metrics.ts'

const cookieSecret = 'COOKIE_SECRET_ABC123XYZ'
const jwtSecret = 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJwZXJzb25hIn0.signaturevalue'
const canarySecret = 'CANARY_TOKEN_9f8e7d6c'
const rawCookieHeader = 'rawcookieval123456'
const rawBearer = 'zzzzzzzzzzzzzzzz'

function tempDir(t: { after: (fn: () => void) => void }, prefix = 'kovo-v5-trace-'): string {
  const dir = mkdtempSync(join(tmpdir(), prefix))
  t.after(() => rmSync(dir, { recursive: true, force: true }))
  return dir
}

function makeTrace(
  t: { after: (fn: () => void) => void },
  manifest: TraceManifestInput = {},
  secrets?: SecretRegistry,
  now?: () => number,
): { dir: string; trace: AgentTrace } {
  const dir = tempDir(t)
  const trace = createAgentTrace({
    dir,
    secrets,
    now,
    manifest: {
      gitSha: 'test-sha',
      app: 'unit-app',
      seed: 42,
      mode: 'agentic',
      model: 'unit-model',
      ...manifest,
    },
  })
  return { dir, trace }
}

function walkFiles(dir: string): string[] {
  const out: string[] = []
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const path = join(dir, entry.name)
    if (entry.isDirectory()) out.push(...walkFiles(path))
    else if (entry.isFile()) out.push(path)
  }
  return out
}

function readEventsText(dir: string): string {
  return readFileSync(join(dir, 'events.jsonl'), 'utf8')
}

function readEventObjects(dir: string): Array<Record<string, unknown>> {
  return readEventsText(dir)
    .split('\n')
    .filter((line) => line.trim().length > 0)
    .map((line) => JSON.parse(line) as Record<string, unknown>)
}

test('blobs are content-addressed and deduped across manifest and repeated prompt prefixes', (t) => {
  const shared = `SYSTEM-PROMPT-${'segment-'.repeat(600)}`
  const { dir, trace } = makeTrace(t, { systemPrompt: shared, toolSchema: '{"tools":["probe_http"]}' })
  const base = {
    runId: 'run-1',
    assignmentId: 'a1',
    specialistProfile: 'probe',
    turnIdx: 1,
    promptPrefix: shared,
  }
  trace.recordTurn({ ...base, deltaMessages: 'first turn' })
  trace.recordTurn({ ...base, turnIdx: 2, deltaMessages: 'second turn' })
  const summary = trace.closeTrace()

  const blobs = readdirSync(join(dir, 'blobs'))
  assert.equal(blobs.length, 2, 'system prompt + tool schema only; repeated prefix deduped')
  assert.equal(summary.blobs, 2)
  assert.equal(readBlob(dir, sha256Hex(shared)), shared)
  assert.equal(readBlob(dir, sha256Hex('{"tools":["probe_http"]}')), '{"tools":["probe_http"]}')
  assert.ok(summary.bytes > 0)
  assert.ok(existsSync(join(dir, 'manifest.json')))
  assert.equal(statSync(dir).mode & 0o777, 0o700, 'trace dir is 0700')
  assert.equal(statSync(join(dir, 'blobs')).mode & 0o777, 0o700, 'blob dir is 0700')
  assert.equal(statSync(join(dir, 'events.jsonl')).mode & 0o777, 0o600, 'events are 0600')
  assert.equal(statSync(join(dir, 'manifest.json')).mode & 0o777, 0o600, 'manifest is 0600')
  assert.equal(statSync(join(dir, 'blobs', blobs[0] ?? '')).mode & 0o777, 0o600, 'blobs are 0600')
})

test('redaction replaces registered secrets, bearer/cookie/api-key patterns, and never leaks values', (t) => {
  const secrets = new SecretRegistry()
  assert.equal(secrets.register('persona_a', 'cookie', cookieSecret), '<<SECRET:persona_a:cookie>>')
  assert.equal(secrets.register('persona_b', 'jwt', jwtSecret), '<<SECRET:persona_b:jwt>>')
  assert.equal(secrets.register('canary', 'c_19', canarySecret), '<<CANARY:c_19>>')
  assert.equal(secrets.register('too-short', 'x', 'abc'), null, 'values under 4 chars are ignored')

  const { dir, trace } = makeTrace(t, { systemPrompt: `auth cookie ${cookieSecret}` }, secrets)
  trace.recordTurn({
    runId: 'run-1',
    assignmentId: 'a1',
    specialistProfile: 'auth',
    turnIdx: 1,
    promptPrefix: `prefix ${cookieSecret}`,
    deltaMessages: [
      `cookie=${cookieSecret}`,
      `Authorization: Bearer ${jwtSecret}`,
      `canary=${canarySecret}`,
      `Authorization: Bearer ${rawBearer}`,
      `Cookie: sid=${rawCookieHeader}`,
      'api_key=sk-live-abcdefghijklmnop',
    ].join('\n'),
    outputText: `leaked ${cookieSecret}`,
  })
  trace.closeTrace()

  const eventsText = readEventsText(dir)
  assert.ok(eventsText.includes('<<SECRET:persona_a:cookie>>'))
  assert.ok(eventsText.includes('<<SECRET:persona_b:jwt>>'))
  assert.ok(eventsText.includes('<<CANARY:c_19>>'))
  assert.ok(eventsText.includes('<<SECRET:generic:bearer>>'))
  assert.ok(eventsText.includes('<<SECRET:generic:cookie>>'))
  assert.ok(eventsText.includes('<<SECRET:generic:api_key>>'))

  const rawValues = [cookieSecret, jwtSecret, canarySecret, rawCookieHeader, rawBearer, 'sk-live-abcdefghijklmnop']
  for (const path of walkFiles(dir)) {
    const buf = readFileSync(path)
    const text = buf.length >= 2 && buf[0] === 0x1f && buf[1] === 0x8b
      ? readBlob(join(dir, 'blobs'), basename(path)) ?? ''
      : buf.toString('utf8')
    for (const raw of rawValues) {
      assert.equal(text.includes(raw), false, `raw secret leaked into ${path}`)
    }
  }

  // The registry itself must not serialize secret values.
  assert.equal(JSON.stringify(secrets).includes(cookieSecret), false)
  assert.equal(JSON.stringify(trace).includes(cookieSecret), false)
})

test('placeholders are deterministic across registries and traces', (t) => {
  const first = new SecretRegistry()
  const second = new SecretRegistry()
  first.register('persona_a', 'cookie', cookieSecret)
  second.register('persona_a', 'cookie', cookieSecret)
  assert.equal(first.redact(`x=${cookieSecret}`), second.redact(`x=${cookieSecret}`))
  assert.equal(first.redact(cookieSecret), '<<SECRET:persona_a:cookie>>')

  const traceA = makeTrace(t, {}, first, () => 1_000)
  traceA.trace.recordTurn({
    runId: 'r',
    assignmentId: 'a',
    specialistProfile: 'p',
    turnIdx: 1,
    deltaMessages: cookieSecret,
  })
  traceA.trace.closeTrace()

  const traceB = makeTrace(t, {}, second, () => 1_000)
  traceB.trace.recordTurn({
    runId: 'r',
    assignmentId: 'a',
    specialistProfile: 'p',
    turnIdx: 1,
    deltaMessages: cookieSecret,
  })
  traceB.trace.closeTrace()

  assert.equal(readEventsText(traceA.dir), readEventsText(traceB.dir))
})

test('all four event types round-trip with the documented schema', (t) => {
  const { dir, trace } = makeTrace(t, {
    systemPrompt: 'system',
    toolSchema: 'tools',
    modelParams: { temperature: 0.2, thinkingLevel: 'high', maxTokens: 4096, protocol: 'responses' },
  })
  trace.recordTurn({
    runId: 'run-1',
    assignmentId: 'a1',
    specialistProfile: 'sqli',
    turnIdx: 1,
    promptPrefix: 'prefix',
    deltaMessages: 'hello',
    ttftMs: 120,
    latencyMs: 900,
    usage: { input: 100, cachedInput: 20, output: 30, reasoning: 5, costUsd: 0.001 },
    stopReason: 'tool_calls',
    outputText: 'out',
    toolCalls: [{ callId: 'c1', name: 'probe_http', args: { path: '/x' } }],
  })
  trace.recordToolResult({
    assignmentId: 'a1',
    turnIdx: 1,
    callId: 'c1',
    name: 'probe_http',
    durationMs: 42,
    ok: true,
    summaryJson: { status: 200 },
    exchangeIds: ['e1'],
    factIds: ['f1'],
    findingIds: ['v1'],
    verifierFeedback: { accepted: true },
    httpRequests: 3,
  })
  trace.recordPlannerDecision({
    roundIdx: 2,
    inputStateHash: 'abc',
    factsCount: 5,
    detLeadsCount: 2,
    alreadyConfirmedCount: 1,
    spawnedSteps: 3,
    k6DryStreak: 0,
    dynamicStepBudget: 8,
    durationMs: 1500,
    costUsd: 0.02,
  })
  trace.recordLifecycle('lane_start', { lane: 'probe', persona: 'a' })
  const summary = trace.closeTrace()

  const read = readTrace(dir)
  assert.deepEqual(read.issues, [])
  assert.equal(read.manifest?.traceSchemaVersion, 1)
  assert.equal(read.manifest?.app, 'unit-app')
  assert.equal(read.manifest?.seed, 42)
  assert.equal(read.manifest?.systemPromptHash, sha256Hex('system'))
  assert.equal(read.manifest?.toolSchemaHash, sha256Hex('tools'))
  assert.equal(read.manifest?.modelParams.protocol, 'responses')
  assert.ok(read.manifest?.endedAtMs)
  assert.equal(read.events.length, 4)
  assert.deepEqual(read.events.map((event) => event.seq), [1, 2, 3, 4])
  assert.equal(summary.events, 4)

  const turn = read.events[0]
  assert.equal(turn?.type, 'turn')
  if (!turn || turn.type !== 'turn') throw new Error('expected turn event')
  const turnEvent: TurnEvent = turn
  assert.equal(turnEvent.promptPrefixHash, sha256Hex('prefix'))
  assert.equal(turnEvent.deltaMessages?.inline, 'hello')
  assert.equal(turnEvent.modelParams.temperature, 0.2)
  assert.equal(turnEvent.usage.cachedInput, 20)
  assert.equal(turnEvent.toolCalls[0]?.name, 'probe_http')

  const tool = read.events[1]
  assert.equal(tool?.type, 'tool_result')
  if (!tool || tool.type !== 'tool_result') throw new Error('expected tool_result event')
  const toolEvent: ToolResultEvent = tool
  assert.equal(toolEvent.ok, true)
  assert.equal(toolEvent.httpRequests, 3)
  assert.deepEqual(toolEvent.factIds, ['f1'])
  assert.equal(toolEvent.summaryJson?.inline, '{"status":200}')

  const planner = read.events[2]
  assert.equal(planner?.type, 'planner_decision')
  if (!planner || planner.type !== 'planner_decision') throw new Error('expected planner event')
  const plannerEvent: PlannerDecisionEvent = planner
  assert.equal(plannerEvent.roundIdx, 2)
  assert.equal(plannerEvent.dynamicStepBudget, 8)

  const lifecycle = read.events[3]
  assert.equal(lifecycle?.type, 'lifecycle')
  if (!lifecycle || lifecycle.type !== 'lifecycle') throw new Error('expected lifecycle event')
  const lifecycleEvent: LifecycleEvent = lifecycle
  assert.equal(lifecycleEvent.kind, 'lane_start')
  assert.equal(lifecycleEvent.payload.lane, 'probe')
})

test('large bodies are hash-only with a bounded ≤4 KiB preview', (t) => {
  const huge = 'X'.repeat(20_000)
  const { dir, trace } = makeTrace(t)
  trace.recordTurn({
    runId: 'r',
    assignmentId: 'a',
    specialistProfile: 'p',
    turnIdx: 1,
    deltaMessages: huge,
    toolCalls: [{ callId: 'c1', name: 'probe_http', args: { body: huge } }],
  })
  trace.recordToolResult({
    assignmentId: 'a',
    turnIdx: 1,
    callId: 'c1',
    name: 'probe_http',
    summaryJson: { body: huge },
  })
  trace.closeTrace()

  const [turn, tool] = readEventObjects(dir)
  const delta = turn?.deltaMessages as { inline?: string; sha256?: string; bytes: number; truncated: boolean }
  assert.equal(delta.truncated, true)
  assert.equal(delta.sha256, sha256Hex(huge))
  assert.ok(delta.bytes > maxTracePreviewBytes)
  assert.ok(Buffer.byteLength(delta.inline ?? '', 'utf8') <= maxTracePreviewBytes)
  assert.ok((delta.inline ?? '').endsWith('…[truncated]'))

  const toolCalls = turn?.toolCalls as Array<{ args?: { inline?: string; truncated: boolean } }>
  assert.equal(toolCalls[0]?.args?.truncated, true)
  assert.ok(Buffer.byteLength(toolCalls[0]?.args?.inline ?? '', 'utf8') <= maxTracePreviewBytes)

  const summary = tool?.summaryJson as { inline?: string; truncated: boolean }
  assert.equal(summary.truncated, true)
  assert.ok(Buffer.byteLength(summary.inline ?? '', 'utf8') <= maxTracePreviewBytes)
})

test('tool-call lists and event lines stay bounded', (t) => {
  const huge = 'Y'.repeat(8_000)
  const { dir, trace } = makeTrace(t)
  trace.recordTurn({
    runId: 'r',
    assignmentId: 'a',
    specialistProfile: 'p',
    turnIdx: 1,
    deltaMessages: huge,
    toolCalls: Array.from({ length: 40 }, (_, index) => ({
      callId: `c${index}`,
      name: 'probe_http',
      args: { body: huge },
    })),
  })
  trace.closeTrace()
  const [event] = readEventObjects(dir)
  const toolCalls = event?.toolCalls as Array<{ args?: { inline?: string } }>
  assert.equal(toolCalls.length, 16, 'tool call count is capped')
  for (const call of toolCalls) {
    assert.ok(Buffer.byteLength(call.args?.inline ?? '', 'utf8') <= maxTracePreviewBytes)
  }
  for (const line of readEventsText(dir).split('\n').filter((entry) => entry.trim())) {
    assert.ok(Buffer.byteLength(line, 'utf8') <= maxTraceEventBytes, 'event line is bounded')
  }
})

test('best-effort: unopenable or vanishing trace dirs never throw', (t) => {
  const dir = tempDir(t)
  const blocked = join(dir, 'blocked')
  writeFileSync(blocked, 'not a directory')

  const warnings: string[] = []
  const originalWarn = console.warn
  console.warn = (...args: unknown[]) => {
    warnings.push(args.map(String).join(' '))
  }
  t.after(() => {
    console.warn = originalWarn
  })

  const disabled = createAgentTrace({ dir: blocked, manifest: { app: 'unit' } })
  assert.equal(disabled.enabled, false)
  assert.doesNotThrow(() => disabled.recordTurn({
    runId: 'r',
    assignmentId: 'a',
    specialistProfile: 'p',
    turnIdx: 1,
  }))
  assert.doesNotThrow(() => disabled.recordToolResult({ assignmentId: 'a', turnIdx: 1, callId: 'c', name: 'n' }))
  assert.doesNotThrow(() => disabled.recordPlannerDecision({ roundIdx: 1, inputStateHash: 'h' }))
  assert.doesNotThrow(() => disabled.recordLifecycle('checkpoint', {}))
  assert.equal(disabled.closeTrace().bytes, 0)

  const liveDir = join(dir, 'live')
  const live = createAgentTrace({ dir: liveDir, manifest: { gitSha: 'test-sha', app: 'unit' } })
  assert.equal(live.enabled, true)
  rmSync(liveDir, { recursive: true, force: true })
  assert.doesNotThrow(() => live.recordTurn({
    runId: 'r',
    assignmentId: 'a',
    specialistProfile: 'p',
    turnIdx: 1,
    deltaMessages: 'x',
  }))
  assert.doesNotThrow(() => live.closeTrace())
  assert.ok(warnings.length >= 1, 'write failure is logged')
})

function buildSyntheticTrace(
  t: { after: (fn: () => void) => void },
): { dir: string; metrics: TraceMetrics; base: number } {
  const base = 1_700_000_000_000
  let clock = base
  const dir = tempDir(t, 'kovo-v5-trace-metrics-')
  const trace = createAgentTrace({
    dir,
    now: () => clock,
    manifest: {
      gitSha: 'test-sha',
      app: 'synthetic',
      seed: 7,
      mode: 'agentic',
      model: 'synthetic-model',
      startedAtMs: base,
    },
  })

  clock = base + 1_000
  trace.recordTurn({
    runId: 'r1',
    assignmentId: 'A1',
    specialistProfile: 'sqli',
    turnIdx: 1,
    promptPrefix: 'p1',
    deltaMessages: 'd1',
    usage: { input: 1000, costUsd: 0.01 },
    toolCalls: [{ callId: 'c1', name: 'probe_http' }],
  })
  clock = base + 2_000
  trace.recordToolResult({
    assignmentId: 'A1',
    turnIdx: 1,
    callId: 'c1',
    name: 'probe_http',
    factIds: ['f1', 'f2', 'f3'],
    httpRequests: 5,
  })
  clock = base + 3_000
  trace.recordToolResult({
    assignmentId: 'A1',
    turnIdx: 1,
    callId: 'c2',
    name: 'fetch_doc',
    factIds: ['f4'],
    httpRequests: 5,
  })
  clock = base + 4_000
  trace.recordTurn({
    runId: 'r1',
    assignmentId: 'A1',
    specialistProfile: 'sqli',
    turnIdx: 2,
    deltaMessages: 'd2',
    usage: { input: 1500, costUsd: 0.01 },
    toolCalls: [],
  })
  clock = base + 5_000
  trace.recordTurn({
    runId: 'r1',
    assignmentId: 'A2',
    specialistProfile: 'xss',
    turnIdx: 1,
    deltaMessages: 'd3',
    usage: { input: 2000, costUsd: 0.01 },
    toolCalls: [{ callId: 'c3', name: 'probe_http' }],
  })
  clock = base + 6_000
  trace.recordToolResult({
    assignmentId: 'A2',
    turnIdx: 1,
    callId: 'c3',
    name: 'probe_http',
    factIds: ['f1'],
    httpRequests: 0,
  })
  clock = base + 7_000
  trace.recordToolResult({
    assignmentId: 'A2',
    turnIdx: 1,
    callId: 'c4',
    name: 'fetch_doc',
    factIds: ['f4'],
    httpRequests: 0,
  })
  clock = base + 8_000
  trace.recordTurn({
    runId: 'r1',
    assignmentId: 'A2',
    specialistProfile: 'xss',
    turnIdx: 2,
    deltaMessages: 'd4',
    usage: { input: 2500, costUsd: 0.01 },
    toolCalls: [],
  })
  clock = base + 9_000
  trace.recordPlannerDecision({
    roundIdx: 1,
    inputStateHash: 'state',
    factsCount: 4,
    detLeadsCount: 2,
    alreadyConfirmedCount: 0,
    spawnedSteps: 2,
    k6DryStreak: 0,
    dynamicStepBudget: 6,
    durationMs: 500,
    costUsd: 0.02,
  })
  for (let index = 0; index < 10; index += 1) {
    clock = base + 10_000 + index
    trace.recordLifecycle('verdict', {
      status: 'confirmed',
      findingId: `v${index + 1}`,
      vulnClass: 'sqli',
    })
  }
  clock = base + 60_000
  trace.closeTrace()

  const computed = computeTraceMetrics(dir, { confirmed: 8 })
  return { dir, metrics: computed.metrics, base }
}

test('metrics math matches a synthetic trace with known counts', (t) => {
  const { metrics, base } = buildSyntheticTrace(t)

  assert.equal(metrics.confirmed, 10)
  assert.equal(metrics.decoyFalsePositives, 0)
  assert.equal(metrics.precision, 1)
  assert.equal(metrics.deltaConfirmed, 2)
  assert.equal(metrics.timeToFirstProbeMs, 2_000)
  assert.equal(metrics.assignmentsPer10Min, 20)
  assert.equal(metrics.signalToSpecConversion, 0.75)
  assert.equal(metrics.wastedTurnRatio, 0.5)
  assert.equal(metrics.batchingEfficiency, 2.5)
  assert.equal(metrics.contextGrowthSlope, 500)
  assert.equal(metrics.totals.costUsd, 0.06)
  assert.equal(metrics.costPerAdditiveConfirmedUsd, 0.03)
  assert.equal(metrics.totals.signals, 4)
  assert.equal(metrics.totals.probedSignals, 3)
  assert.equal(metrics.totals.spanMs, 60_000)

  const findingIds = Array.from({ length: 8 }, (_, index) => `v${index + 1}`)
  assert.equal(computeTraceMetrics(metrics.traceDir, { confirmedFindingIds: findingIds }).metrics.deltaConfirmed, 2)
  assert.equal(computeTraceMetrics(metrics.traceDir, { confirmedByClass: { sqli: 7 } }).metrics.deltaConfirmed, 3)
  assert.equal(computeTraceMetrics(metrics.traceDir).metrics.deltaConfirmed, null)

  const table = formatMetricsTable(metrics, evaluateTraceGate(metrics))
  assert.ok(table.includes('signal→spec conversion'))
  assert.ok(table.includes('gate'))
  assert.ok(!table.includes('d1'), 'table never dumps prompt/body text')
  assert.ok(!table.includes('f1'), 'table never dumps fact IDs')

  // Sanity: the manifest start is what time-to-first-probe is measured from.
  assert.equal(readTrace(metrics.traceDir).manifest?.startedAtMs, base)
})

test('--gate passes the synthetic trace and fails on precision, decoy, or throughput', (t) => {
  const { metrics } = buildSyntheticTrace(t)
  const pass = evaluateTraceGate(metrics)
  assert.deepEqual(pass, { precisionOk: true, decoyOk: true, throughputOk: true, pass: true })

  const base: TraceMetrics = {
    ...metrics,
    confirmed: 19,
    precision: 0.95,
    decoyFalsePositives: 0,
    signalToSpecConversion: 1,
    assignmentsPer10Min: 20,
  }
  assert.equal(evaluateTraceGate(base).pass, true, '95% precision is the inclusive boundary')
  assert.equal(evaluateTraceGate({ ...base, precision: 18 / 19 }).pass, false, 'below 95% fails')
  assert.equal(evaluateTraceGate({ ...base, decoyFalsePositives: 1 }).pass, false, 'any decoy FP fails')
  assert.equal(
    evaluateTraceGate({ ...base, signalToSpecConversion: 0.75, assignmentsPer10Min: 1 }).pass,
    false,
    'low signal→spec and low throughput fails',
  )
  assert.equal(
    evaluateTraceGate({ ...base, signalToSpecConversion: 0.9, assignmentsPer10Min: 1 }).pass,
    true,
    'high signal→spec covers low throughput',
  )
  assert.equal(
    evaluateTraceGate({ ...base, signalToSpecConversion: 0.2, assignmentsPer10Min: 15 }).pass,
    true,
    '15 assignments/10 min covers low signal→spec',
  )

  // End-to-end: a decoy verdict and a verifier false positive both trip the gate.
  const decoyDir = tempDir(t, 'kovo-v5-trace-gate-')
  const decoyTrace = createAgentTrace({
    dir: decoyDir,
    manifest: { gitSha: 'test-sha', app: 'gate', startedAtMs: 1_000 },
  })
  decoyTrace.recordLifecycle('verdict', { status: 'confirmed', findingId: 'real', vulnClass: 'sqli' })
  decoyTrace.recordLifecycle('verdict', { status: 'confirmed', findingId: 'fake', vulnClass: 'sqli', decoy: true })
  decoyTrace.recordToolResult({
    assignmentId: 'a',
    turnIdx: 1,
    callId: 'c1',
    name: 'probe_http',
    verifierFeedback: { falsePositive: true },
  })
  decoyTrace.closeTrace()
  const decoyMetrics = computeTraceMetrics(decoyDir).metrics
  assert.equal(decoyMetrics.decoyFalsePositives, 1)
  assert.ok(decoyMetrics.precision < 0.95)
  assert.equal(evaluateTraceGate(decoyMetrics).pass, false)

  const logs: string[] = []
  const originalLog = console.log
  console.log = (...args: unknown[]) => {
    logs.push(args.map(String).join(' '))
  }
  t.after(() => {
    console.log = originalLog
  })
  assert.equal(main(['--trace', metrics.traceDir, '--gate']), 0, '--gate exit 0 on pass')
  assert.equal(main(['--trace', decoyDir, '--gate']), 1, '--gate exit 1 on fail')
  assert.equal(main(['--trace', decoyDir]), 0, 'no --gate always exits 0 on a readable trace')
  assert.equal(main(['--trace', metrics.traceDir, '--control-confirmed', '8', '--json']), 0)
  const parsed = JSON.parse(logs.at(-1) ?? '{}') as {
    metrics?: { deltaConfirmed?: number }
    gate?: { pass?: boolean }
  }
  assert.equal(parsed.metrics?.deltaConfirmed, 2)
  assert.equal(parsed.gate?.pass, true)
  assert.ok(!logs.join('\n').includes('d1'), 'CLI output never dumps prompt text')
})

test('sub-minute traces clamp assignments/10 min instead of extrapolating', (t) => {
  const { dir, trace } = makeTrace(t, { startedAtMs: 1_000 }, undefined, () => 2_000)
  trace.recordTurn({
    runId: 'r',
    assignmentId: 'a1',
    specialistProfile: 'p',
    turnIdx: 1,
    usage: { input: 100 },
    toolCalls: [{ callId: 'c1', name: 'probe_http' }],
  })
  trace.closeTrace()
  const metrics = computeTraceMetrics(dir).metrics
  assert.equal(metrics.assignmentsPer10Min, 10)
})

test('trace opt-in is off by default and honours KOVO_TRACE_DIR / KOVO_TRACE=1', (t) => {
  assert.deepEqual(resolveTraceConfig({}), { enabled: false, dir: null })
  assert.deepEqual(resolveTraceConfig({ KOVO_TRACE: '0' }), { enabled: false, dir: null })
  assert.deepEqual(
    resolveTraceConfig({ KOVO_TRACE_DIR: '/tmp/explicit-trace' }),
    { enabled: true, dir: '/tmp/explicit-trace' },
  )
  assert.deepEqual(
    resolveTraceConfig({ KOVO_TRACE: '1', KOVO_TRACE_ROOT: '/tmp/root', KOVO_TRACE_ID: 'id1' }),
    { enabled: true, dir: '/tmp/root/id1' },
  )
  assert.equal(createAgentTraceFromEnv({ app: 'unit' }, {}), null)

  const envDir = tempDir(t, 'kovo-v5-trace-env-')
  const fromEnv = createAgentTraceFromEnv({ gitSha: 'test-sha', app: 'unit' }, { KOVO_TRACE_DIR: envDir })
  assert.ok(fromEnv)
  fromEnv.recordLifecycle('lane_start', { lane: 'recon' })
  fromEnv.closeTrace()
  assert.equal(readTrace(envDir).events.length, 1)
})
