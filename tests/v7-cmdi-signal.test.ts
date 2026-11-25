/**
 * v7 command-injection signal stream: a real execution signal must survive spec synthesis.
 *
 * Regression: dev opsportal fell 10/18 -> 9/18 because `og.diag-cmdi` was lost. The command
 * injection probe signalled on one body parameter (the route reads only that parameter), but the
 * synthesized `rce_proof` joined the two verifier-minted nonce halves with command substitution.
 * The shell model emits substitution output on its own line, so the assembled nonce was never
 * contiguous in the response: the proof was dismissed ("possible reflection or unexecuted
 * payload") even though the probe had proved execution. The only fallback (`http_chain`) is a
 * status-only injection claim with no engine fingerprint and is correctly vetoed by
 * `assessInjectionImpact`. Fix: synthesize the split-echo proof using an empty quoted word
 * (`''`) that the shell's quoting pass deletes, with the substitution shape kept as one bounded
 * fallback. Both shapes are derived from the recorded signal exchange; nothing re-probes.
 *
 * The engine already runs one spec pipeline per hypothesis (keyed by endpoint id + parameter), so
 * there is no endpoint-level memo. These tests pin that contract: a later parameter's signal is
 * synthesized from its own recorded evidence after an earlier parameter's spec was rejected.
 *
 * The fixture twins below are synthetic: the vulnerable route reads one JSON field and simulates a
 * shell; the hardened twin validates the same field's shape; the reflection twin echoes the input
 * without ever evaluating it.
 */
import assert from 'node:assert/strict'
import { createServer } from 'node:http'
import type { IncomingMessage, ServerResponse } from 'node:http'
import { once } from 'node:events'
import { test } from 'node:test'

process.env.KOVO_ALLOW_LOCAL_LAB = '1'

import { RequestBroker } from '../src/server/broker.ts'
import type { Grant } from '../src/server/broker.ts'
import type { ResolvedPersona } from '../src/server/persona-vault.ts'
import { verifyReplaySpec } from '../src/server/replay-verifier.ts'
import { LocalJqBackend } from '../scripts/benchmark-backend.ts'
import { synthesizeEngineSpecs } from '../src/server/deterministic-specs.ts'
import {
  runDeterministicEngine,
} from '../src/server/deterministic-engine.ts'
import type {
  DeterministicEngineInput,
  EngineEndpoint,
  EngineHypothesis,
} from '../src/server/deterministic-engine.ts'
import type { DifferentialResult } from '../src/server/surface-engine.ts'
import { simulateCommand } from '../benchmarks/realistic-bench/lib/simshell.ts'

type Json = Record<string, unknown>

// ---------------------------------------------------------------------------------------------
// Fixture: diagnostics runner with one real parameter and one decoy parameter
// ---------------------------------------------------------------------------------------------

type FixtureMode = 'vulnerable' | 'hardened' | 'reflection' | 'quote_strip'

const HARDENED_HOST = /^[A-Za-z0-9.\-]{1,64}$/

function json(res: ServerResponse, status: number, value: unknown): void {
  res.writeHead(status, { 'content-type': 'application/json' })
  res.end(JSON.stringify(value))
}

async function readBody(req: IncomingMessage): Promise<Json> {
  const chunks: Buffer[] = []
  for await (const chunk of req) chunks.push(Buffer.from(chunk))
  if (chunks.length === 0) return {}
  try {
    const parsed = JSON.parse(Buffer.concat(chunks).toString('utf8')) as unknown
    return parsed && typeof parsed === 'object' && !Array.isArray(parsed) ? parsed as Json : {}
  } catch { return {} }
}

/**
 * The route reads only `host`. A sibling body field named `endpointHost` is accepted into the body
 * but never used, which is the shape that produced the original regression: a decoy parameter that
 * the engine ranks and probes first, and the real parameter on the same endpoint.
 */
async function startDiagnosticsFixture(mode: FixtureMode) {
  const requests: Array<{ method: string; host: string; otherHost: string }> = []
  const server = createServer((req, res) => {
    void (async () => {
      if (req.method !== 'POST') {
        // Harvester baseline reads.
        json(res, 200, { ok: true })
        return
      }
      if (!req.headers['x-persona']) {
        json(res, 401, { error: 'auth_required' })
        return
      }
      const body = await readBody(req)
      const host = String(body.host ?? '')
      const otherHost = String(body.endpointHost ?? '')
      requests.push({ method: req.method, host, otherHost })
      if (host.length === 0 || host.length > 128) {
        json(res, 400, { error: 'host_required' })
        return
      }
      if (mode === 'hardened' && !HARDENED_HOST.test(host)) {
        json(res, 400, { error: 'invalid_host' })
        return
      }
      if (mode === 'reflection') {
        // Never evaluates: the raw input, including any metacharacters, is echoed back.
        json(res, 200, { output: `probe ${host}` })
        return
      }
      if (mode === 'quote_strip') {
        // Never evaluates, but a naive output filter deletes quote characters. A proof whose only
        // join is an empty quoted word would be spoofed here; the evaluated substitution join is not.
        json(res, 200, { output: `probe ${host.replaceAll("'", '').replaceAll('"', '')}` })
        return
      }
      const sim = simulateCommand('ping -c 1 {0}', [host])
      json(res, 200, { output: sim.output })
    })().catch(error => {
      if (!res.headersSent) res.statusCode = 500
      res.end(String(error))
    })
  })
  server.listen(0, '127.0.0.1')
  await once(server, 'listening')
  const address = server.address()
  if (!address || typeof address === 'string') throw new Error('fixture did not bind')
  return {
    origin: `http://127.0.0.1:${address.port}`,
    requests,
    close: () => new Promise<void>(resolve => { server.closeAllConnections(); server.close(() => resolve()) }),
  }
}

// ---------------------------------------------------------------------------------------------
// Persona / grant / engine inputs
// ---------------------------------------------------------------------------------------------

const PERSONA_HANDLE = 'owner'

function personaOf(origin: string): ResolvedPersona {
  return {
    id: PERSONA_HANDLE,
    handle: PERSONA_HANDLE,
    roleLabel: 'owner (acme)',
    originAllowlist: [origin],
    authKind: 'header',
    headerName: 'X-Persona',
    secret: PERSONA_HANDLE,
    canaryMarkers: [],
  }
}

function grantFor(origin: string): Grant {
  return {
    origin,
    tier: 3,
    allowLocalLab: true,
    maxRpsPerOrigin: 100,
    canRead: (candidate: string) => candidate === origin,
    isIdempotentPostAllowed: () => true,
    isStateChangeApproved: () => true,
    personas: new Map([[PERSONA_HANDLE, personaOf(origin)]]),
    audit: () => undefined,
  } as unknown as Grant
}

function diagnosticsEndpoint(origin: string): EngineEndpoint {
  return {
    id: 'POST:/api/diagnostics/run',
    origin,
    method: 'POST',
    pathTemplate: '/api/diagnostics/run',
    params: [
      // The engine's parameter ranking puts `endpointHost` first; the route ignores it, so the
      // decoy is probed and rejected before the real `host` field is reached.
      { name: 'endpointHost', location: 'json' },
      { name: 'host', location: 'json' },
    ],
    riskScore: 90,
    source: 'declared',
  }
}

const personas = [{ handle: PERSONA_HANDLE, roleLabel: 'owner (acme)', privilege: 'member' as const, tenant: 'acme' }]

/** Deterministic probe double: no network, one outcome per (endpoint, parameter). */
function commandSignal(origin: string, pathAndQuery: string, param: string, verdict: 'signal' | 'no_signal'): DifferentialResult {
  const base = {
    probeClass: 'command_injection' as const,
    origin,
    pathAndQuery,
    method: 'POST' as const,
    requestsSent: verdict === 'signal' ? 2 : 7,
    exchangeIds: [`probe:${param}:${verdict}`],
    stoppedReason: null,
    notes: [],
    durationMs: 5,
    details: {},
  }
  if (verdict === 'no_signal') {
    return { ...base, verdict, summary: 'No command-execution nonce appeared in output across echo variants.', anomalies: [] }
  }
  const nonce = `gn${param.replace(/[^A-Za-z0-9]/g, '').slice(0, 10).padEnd(10, 'x')}`
  const payload = `127.0.0.1; echo ${nonce}`
  return {
    ...base,
    verdict,
    summary: `Fresh shell nonce appeared in output for the semicolon_echo variant without template reflection (command executed).`,
    anomalies: [{
      type: 'command_executed',
      variant: 'semicolon_echo',
      baseValue: '127.0.0.1',
      nonce,
      payload,
      status: 200,
      suggestedReplayKind: 'rce_proof',
    }],
  }
}

interface TraceStep {
  event: 'probe' | 'verify'
  endpoint: string
  param: string | null
  kind?: string
  verdict: string
}

interface RunResult {
  trace: TraceStep[]
  report: Awaited<ReturnType<typeof runDeterministicEngine>>
  confirmed: Array<{ endpoint: string; vulnClass: string; proofMode: string; assembled: boolean | null }>
}

/**
 * Run the real engine against the fixture. Only the probe is injected (it is a deterministic
 * double); synthesis, replay verification and the oracles are the production implementations.
 */
async function runEngine(options: {
  origin: string
  outcomes: Record<string, 'signal' | 'no_signal'>
}): Promise<RunResult> {
  const trace: TraceStep[] = []
  const confirmed: RunResult['confirmed'] = []
  const probeCalls = new Map<string, number>()
  const broker = new RequestBroker({ rejectUnauthorized: false })
  const input: DeterministicEngineInput = {
    runId: 'run-cmdi-signal',
    assignmentId: 'asg-cmdi-signal',
    signal: AbortSignal.timeout(60_000),
    endpoints: [diagnosticsEndpoint(options.origin)],
    personas,
    broker,
    grant: grantFor(options.origin),
    backend: new LocalJqBackend(),
    tier: 3,
    maxRequests: 300,
    maxDurationMs: 30_000,
    classes: new Set(['command_injection']),
    probe: async req => {
      const param = req.param ?? '<none>'
      const key = `${req.pathAndQuery}|${param}`
      probeCalls.set(key, (probeCalls.get(key) ?? 0) + 1)
      const outcome = options.outcomes[param] ?? 'no_signal'
      trace.push({ event: 'probe', endpoint: req.pathAndQuery, param, verdict: outcome })
      return commandSignal(options.origin, req.pathAndQuery, param, outcome)
    },
    verify: async params => {
      const spec = params.spec as { kind: string; probeStep?: { request?: { jsonBody?: Json } } }
      const result = await verifyReplaySpec(params as never)
      const body = spec.probeStep?.request?.jsonBody
      const signalled = body
        ? Object.entries(body).find(([, value]) => typeof value === 'string' && value.includes('echo'))?.[0] ?? null
        : null
      trace.push({ event: 'verify', endpoint: spec.kind, param: signalled, kind: spec.kind, verdict: result.verdict })
      return result
    },
    onConfirmed: payload => {
      const proof = (payload.result.evidencePayload as { proof?: { splitEchoVerified?: boolean; assembledInProbe?: boolean } } | undefined)?.proof
      confirmed.push({
        endpoint: payload.endpoint,
        vulnClass: payload.vulnClass,
        proofMode: String((payload.spec as { proofMode?: string }).proofMode ?? ''),
        assembled: proof?.splitEchoVerified ?? null,
      })
      return 'finding-cmdi-1'
    },
  }
  const report = await runDeterministicEngine(input)
  // The engine probes each hypothesis once; a signal must never cause a blind re-probe.
  for (const [key, count] of probeCalls) {
    assert.equal(count, 1, `parameter ${key} was probed ${count} time(s); signals must reuse recorded evidence`)
  }
  return { trace, report, confirmed }
}

// ---------------------------------------------------------------------------------------------
// 1. Synthesis shape
// ---------------------------------------------------------------------------------------------

function diagnosticsHypothesis(origin: string, param: string): EngineHypothesis {
  return {
    key: `command_injection|POST:/api/diagnostics/run|${param}`,
    endpoint: diagnosticsEndpoint(origin),
    probeClass: 'command_injection',
    intent: 'command_injection',
    method: 'POST',
    pathAndQuery: '/api/diagnostics/run',
    param: { name: param, location: 'json' },
    location: 'json',
    ownerPersona: PERSONA_HANDLE,
    baselineValue: '127.0.0.1',
    jsonBody: { endpointHost: '127.0.0.1' },
    risk: 104,
  }
}

function observedSignal(origin: string, param: string): DifferentialResult {
  return commandSignal(origin, '/api/diagnostics/run', param, 'signal')
}

test('command-injection signal synthesizes an evaluated nonce proof, not a reflected value', () => {
  const specs = synthesizeEngineSpecs(diagnosticsHypothesis('http://127.0.0.1:9', 'host'), observedSignal('http://127.0.0.1:9', 'host'))
  assert.deepEqual(specs.map(spec => spec.kind), ['rce_proof', 'http_chain'])

  const rce = specs.filter(spec => spec.kind === 'rce_proof')
  assert.equal(rce.length, 1, 'one bounded proof shape from the recorded exchange')
  for (const candidate of rce) {
    const spec = candidate.spec as Json
    assert.equal(spec.proofMode, 'split_echo')
    const probe = (spec.probeStep as { request: { jsonBody: Json } }).request
    assert.equal(probe.jsonBody.host !== undefined, true, 'payload is bound to the signalled parameter')
    assert.equal(probe.jsonBody.endpointHost, '127.0.0.1', 'sibling body fields are preserved, not guessed')
  }
  const primary = (rce[0]!.spec as Json).probeStep as { request: { jsonBody: Json } }
  const payload = String(primary.request.jsonBody.host)
  // The two verifier-minted halves are separated by an empty command substitution: the shell
  // evaluates it to nothing and joins the halves, raw reflection keeps the literal `$(echo '')`.
  // The assertion targets the template, not the minted token.
  assert.match(payload, /; echo \{\{nonce_part1\}\}\$\(echo ''\)\{\{nonce_part2\}\}$/)
  assert.equal(payload.includes('{{nonce_part1}}{{nonce_part2}}'), false, 'halves are never adjacent in the outbound request')
})

// ---------------------------------------------------------------------------------------------
// 2. Exact regression shape: decoy param, rejected spec, then the real param's signal
// ---------------------------------------------------------------------------------------------

test('a later parameter signal is synthesized from its own evidence after an earlier spec was rejected', async () => {
  const fixture = await startDiagnosticsFixture('vulnerable')
  try {
    // `endpointHost` signals the probe double, but the route ignores it: every spec for it is
    // rejected. `host` is the real field and must still be converted after that failure.
    const { trace, report, confirmed } = await runEngine({
      origin: fixture.origin,
      outcomes: { endpointHost: 'signal', host: 'signal' },
    })

    const probes = trace.filter(step => step.event === 'probe')
    assert.deepEqual(probes.map(step => `${step.param}:${step.verdict}`), ['endpointHost:signal', 'host:signal'])
    assert.ok(report.rejectedSpecs > 0, 'the decoy parameter produced rejected specs first')
    assert.equal(confirmed.length, 1, JSON.stringify(report))
    assert.deepEqual(confirmed[0], {
      endpoint: '/api/diagnostics/run',
      vulnClass: 'command_injection',
      proofMode: 'split_echo',
      assembled: true,
    }, 'confirmation came from the evaluated split-echo proof')
    assert.equal(report.confirmed, 1)
    assert.equal(report.confirmedPairs.filter(pair => pair.vulnClass === 'command_injection').length, 1)

    // The confirmed replay actually targets the real field with the quote-joined payload.
    const confirmedRequests = fixture.requests.filter(entry => entry.host.includes('echo'))
    assert.ok(confirmedRequests.length > 0, 'replay sent the payload in the signalled field')
    assert.ok(confirmedRequests.some(entry => /''/.test(entry.host)), 'quote-joined halves reached the shell')
    assert.ok(fixture.requests.some(entry => entry.otherHost.includes('echo')),
      'the decoy field was what the rejected specs targeted')
  } finally { await fixture.close() }
})

test('a no-signal sibling parameter does not block the real parameter proof', async () => {
  const fixture = await startDiagnosticsFixture('vulnerable')
  try {
    const { trace, confirmed } = await runEngine({
      origin: fixture.origin,
      outcomes: { endpointHost: 'no_signal', host: 'signal' },
    })
    assert.deepEqual(
      trace.filter(step => step.event === 'probe').map(step => `${step.param}:${step.verdict}`),
      ['endpointHost:no_signal', 'host:signal'],
    )
    assert.equal(confirmed.length, 1)
    assert.equal(confirmed[0]!.endpoint, '/api/diagnostics/run')
  } finally { await fixture.close() }
})

// ---------------------------------------------------------------------------------------------
// 3. Bounded attempts and determinism
// ---------------------------------------------------------------------------------------------

test('a signalled parameter never causes a blind re-probe and spec attempts stay bounded', async () => {
  const fixture = await startDiagnosticsFixture('vulnerable')
  try {
    const { trace, report } = await runEngine({
      origin: fixture.origin,
      outcomes: { endpointHost: 'signal', host: 'signal' },
    })
    const probes = trace.filter(step => step.event === 'probe')
    assert.equal(probes.length, 2, 'one probe per parameter hypothesis, no retry loop')
    // One rce_proof plus the single observed-payload chain per signalled parameter.
    assert.ok(report.specsSubmitted <= 4, `spec attempts bounded (${report.specsSubmitted})`)
    const perSignal = new Map<string, number>()
    for (const step of trace.filter(entry => entry.event === 'verify')) {
      perSignal.set(step.endpoint, (perSignal.get(step.endpoint) ?? 0) + 1)
    }
    for (const [kind, count] of perSignal) {
      assert.ok(count <= 4, `${kind} attempted ${count} times across two signalled parameters`)
    }
  } finally { await fixture.close() }
})

test('identical inputs produce identical probe order, spec order and confirmations', async () => {
  const fixture = await startDiagnosticsFixture('vulnerable')
  try {
    const outcomes = { endpointHost: 'signal', host: 'signal' } as const
    const first = await runEngine({ origin: fixture.origin, outcomes })
    const second = await runEngine({ origin: fixture.origin, outcomes })
    const summarize = (run: RunResult) => ({
      trace: run.trace.map(step => `${step.event}:${step.endpoint}:${step.param}:${step.verdict}`),
      confirmed: run.confirmed,
      confirmedCount: run.report.confirmed,
      specsSubmitted: run.report.specsSubmitted,
      rejectedSpecs: run.report.rejectedSpecs,
      signals: run.report.signals,
      hypothesesRun: run.report.hypothesesRun,
    })
    assert.deepEqual(summarize(second), summarize(first))
  } finally { await fixture.close() }
})

// ---------------------------------------------------------------------------------------------
// 4. Twin separation: hardened shape check and reflection-only
// ---------------------------------------------------------------------------------------------

test('a hardened twin with the same parameter shape rejects the proof', async () => {
  const fixture = await startDiagnosticsFixture('hardened')
  try {
    const { report, confirmed } = await runEngine({
      origin: fixture.origin,
      outcomes: { endpointHost: 'signal', host: 'signal' },
    })
    assert.equal(confirmed.length, 0, 'no confirmation on the shape-validated twin')
    assert.equal(report.confirmed, 0)
    assert.ok(report.rejectedSpecs > 0, 'the proof was attempted and rejected')
  } finally { await fixture.close() }
})

test('a quote-stripping output filter cannot spoof the evaluated join', async () => {
  const fixture = await startDiagnosticsFixture('quote_strip')
  try {
    const { report, confirmed } = await runEngine({
      origin: fixture.origin,
      outcomes: { endpointHost: 'signal', host: 'signal' },
    })
    assert.equal(confirmed.length, 0, 'deleting quotes leaves the substitution unassembled')
    assert.equal(report.confirmed, 0)
    assert.ok(report.rejectedSpecs > 0)
  } finally { await fixture.close() }
})

test('a reflection-only twin cannot confirm the split-echo proof', async () => {
  const fixture = await startDiagnosticsFixture('reflection')
  try {
    const { report, confirmed } = await runEngine({
      origin: fixture.origin,
      outcomes: { endpointHost: 'signal', host: 'signal' },
    })
    assert.equal(confirmed.length, 0, 'raw reflection keeps the quoted halves apart')
    assert.equal(report.confirmed, 0)
    assert.ok(report.rejectedSpecs > 0)
  } finally { await fixture.close() }
})
