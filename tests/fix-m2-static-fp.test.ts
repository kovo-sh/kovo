/**
 * Regression tests for live-target static_ast_proof & unverified pending/inconclusive FPs.
 *
 * Root cause on live white-box runs:
 *  1. Workers called `propose_chain_finding` with `replaySpec.kind = 'static_ast_proof'`.
 *     `exec-worker-runner.ts` persisted a `pending` finding row first and promoted matching AST
 *     patterns to `static_verified` (`static_advisory`) — triggering hardened decoy twins whose
 *     code looks suspicious statically while remaining safe at runtime.
 *  2. Non-matching / failed / `verifyNow: false` `propose_chain_finding` calls left `pending` or
 *     `inconclusive` (`open_proof_gap`) rows in SQLite `findings`.
 *
 * Product-side fix invariants verified here:
 *  - On live-target runtime verification runs (`LinuxWorkerBackend` + `capabilityTier > 0` +
 *    `sourceMode !== 'prepared'`), `static_ast_proof` is rejected by `propose_chain_finding`,
 *    `update_proposed_finding`, and `executeInlineVerification`, preserved strictly as a
 *    deduplicated `code_audit_suspect` fact, and never persisted as a `findings` or `replay_specs`
 *    row; Phase-3 `verifyReplaySpecJob` dismisses any queued `static_ast_proof` row instead of
 *    promoting it.
 *  - Live-target `propose_chain_finding` uses verify-before-persist (`deferredCandidate`) so
 *    inconclusive / failed / `verifyNow: false` specs never leak `pending` or `inconclusive` rows
 *    into `findings`, while confirmed runtime specs still persist as `runtime_confirmed`.
 *  - Offline / Tier-0 (`capabilityTier === 0` or `sourceMode === 'prepared'`) and legacy replay-only
 *    (`!backendSupportsVerifyScript()`) runs preserve `static_ast_proof` -> `static_verified`.
 */
import assert from 'node:assert/strict'
import { execFile } from 'node:child_process'
import { randomUUID } from 'node:crypto'
import { createServer, type IncomingMessage, type ServerResponse } from 'node:http'
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import test from 'node:test'
import { promisify } from 'node:util'
import { setTimeout as delay } from 'node:timers/promises'
import { eq } from 'drizzle-orm'

import type { Finding } from '../src/domain.ts'
import type { DeclarativeReplaySpec } from '../src/replay-spec.ts'
import { translateFindings } from '../scripts/benchmark-realistic.ts'
import { RequestBroker, type PublicAddress } from '../src/server/broker.ts'
import { Execution } from '../src/server/execution.ts'
import {
  STATIC_AST_LIVE_TARGET_REJECT_MESSAGE,
  isLiveRuntimeVerificationRun,
} from '../src/server/exec-verify.ts'
import { saveModelProfile } from '../src/server/model-settings.ts'
import { findings as findingsTable, replaySpecs as replaySpecsTable } from '../src/server/schema.ts'
import { Store } from '../src/server/store.ts'
import { LinuxWorkerBackend, type WorkerResult, type WorkerSession } from '../src/server/worker-backend.ts'
import { makeLabGrant } from './v4-tier-helpers.ts'

process.env.KOVO_ALLOW_LOCAL_LAB = '1'
process.env.KOVO_ALLOW_LOCAL_MODEL = '1'

const exec = promisify(execFile)
const APP_ORIGIN = 'https://live-static-fp.example.test'
const PUBLIC_ADDR: PublicAddress = { address: '93.184.216.34', family: 4 }

async function httpFixture(handler: (req: IncomingMessage, res: ServerResponse) => void) {
  const srv = createServer(handler)
  await new Promise<void>(resolve => srv.listen(0, '127.0.0.1', resolve))
  const addr = srv.address() as { port: number }
  return {
    port: addr.port,
    url: `http://127.0.0.1:${addr.port}`,
    close: () => new Promise<void>(resolve => srv.close(() => resolve())),
  }
}

function makeFixtureBroker(targetPort: number): RequestBroker {
  const host = new URL(APP_ORIGIN).hostname
  return new RequestBroker({
    resolve: async h => (h === host ? [PUBLIC_ADDR] : []),
    transport: async (url, _addr, signal, opts) => {
      const target = `http://127.0.0.1:${targetPort}${url.pathname}${url.search}`
      const res = await fetch(target, {
        method: opts?.method ?? 'GET',
        headers: opts?.headers,
        body: opts?.body,
        signal,
        redirect: 'manual',
      })
      const body = opts?.readBody === false ? '' : await res.text()
      return {
        status: res.status,
        headers: Object.fromEntries(res.headers),
        body,
        bodyBytes: Buffer.byteLength(body, 'utf8'),
        bodyTruncated: false,
      }
    },
  })
}

function sseResponsesPayload(
  text: string,
  toolCalls: Array<{ name: string; args: Record<string, unknown>; callId?: string }> = [],
): string {
  const responseId = `resp_${randomUUID().slice(0, 12)}`
  const events: Record<string, unknown>[] = [
    { type: 'response.created', response: { id: responseId, status: 'in_progress', output: [] } },
  ]
  const output: Record<string, unknown>[] = []
  let idx = 0

  if (text) {
    const msgId = `msg_${randomUUID().slice(0, 8)}`
    events.push(
      { type: 'response.output_item.added', output_index: idx, item: { id: msgId, type: 'message', status: 'in_progress', role: 'assistant', content: [] } },
      { type: 'response.output_text.delta', output_index: idx, item_id: msgId, content_index: 0, delta: text },
      { type: 'response.output_text.done', output_index: idx, item_id: msgId, content_index: 0, text },
      { type: 'response.output_item.done', output_index: idx, item: { id: msgId, type: 'message', status: 'completed', role: 'assistant', content: [{ type: 'output_text', text }] } },
    )
    output.push({ id: msgId, type: 'message', role: 'assistant', status: 'completed', content: [{ type: 'output_text', text }] })
    idx += 1
  }

  for (const call of toolCalls) {
    const fcId = `fc_${randomUUID().slice(0, 8)}`
    const callId = call.callId ?? `call_${randomUUID().slice(0, 8)}`
    const serialized = JSON.stringify(call.args)
    events.push(
      { type: 'response.output_item.added', output_index: idx, item: { id: fcId, type: 'function_call', status: 'in_progress', call_id: callId, name: call.name, arguments: '' } },
      { type: 'response.function_call_arguments.delta', output_index: idx, item_id: fcId, delta: serialized },
      { type: 'response.function_call_arguments.done', output_index: idx, item_id: fcId, name: call.name, arguments: serialized },
      { type: 'response.output_item.done', output_index: idx, item: { id: fcId, type: 'function_call', status: 'completed', call_id: callId, name: call.name, arguments: serialized } },
    )
    output.push({ id: fcId, type: 'function_call', status: 'completed', call_id: callId, name: call.name, arguments: serialized })
    idx += 1
  }

  events.push({
    type: 'response.completed',
    response: {
      id: responseId,
      status: 'completed',
      output,
      usage: { input_tokens: 100, output_tokens: 50, total_tokens: 150 },
    },
  })
  return events.map(ev => `data: ${JSON.stringify(ev)}\n\n`).join('') + 'data: [DONE]\n\n'
}

class StubLiveLinuxBackend extends LinuxWorkerBackend {
  constructor() {
    super({
      dockerRunner: async () => '',
    })
  }

  override async run(job: Parameters<LinuxWorkerBackend['run']>[0], signal: AbortSignal): Promise<WorkerResult> {
    const dir = mkdtempSync(join(tmpdir(), 'kovo-live-stub-jq-'))
    try {
      for (const f of job.files) {
        writeFileSync(join(dir, f.name.replace(/\//g, '_')), f.content, 'utf8')
      }
      const match = /^jq\s+'([\s\S]*)'\s+\/evidence\/replay-results\.json\s+>\s+\/work\/outcome\.json$/.exec(job.command.trim())
      if (!match) {
        return { exitCode: 1, stdout: '', stderr: `Unsupported command: ${job.command}`, outputs: {} }
      }
      const jqFilter = match[1]!.replaceAll("'\\''", "'")
      const inputPath = join(dir, 'replay-results.json')
      try {
        const { stdout, stderr } = await exec('jq', [jqFilter, inputPath], { signal, timeout: job.timeoutMs ?? 15_000 })
        return { exitCode: 0, stdout, stderr, outputs: { 'outcome.json': stdout } }
      } catch (err) {
        const e = err as { code?: number; stdout?: string; stderr?: string; message?: string }
        return {
          exitCode: typeof e.code === 'number' ? e.code : 2,
          stdout: e.stdout ?? '',
          stderr: e.stderr ?? e.message ?? 'jq failed',
          outputs: {},
        }
      }
    } finally {
      rmSync(dir, { recursive: true, force: true })
    }
  }

  override async verifyStaticAst(
    _assignmentId: string,
    req: Parameters<LinuxWorkerBackend['verifyStaticAst']>[1],
  ) {
    const missing = req.ruleOrPattern.includes('MISSING_PATTERN')
    return {
      verified: !missing,
      engine: req.engine,
      repo: req.repo,
      file: req.file,
      startLine: req.startLine,
      endLine: req.endLine,
      matchCount: missing ? 0 : 1,
      matchedLines: missing ? [] : [req.startLine],
      codeExcerpt: missing ? '' : 'export function checkTenant(req: unknown) { return Boolean(req) }',
      durationMs: 1,
      ...(missing ? { reason: 'No AST match.' } : {}),
    }
  }

  override async openSession(_assignmentId: string): Promise<WorkerSession> {
    return {
      stage: async path => `/evidence/${path}`,
      exec: async () => ({ exitCode: 0, stdout: 'ok', stderr: '', outputs: {} }),
      analyze: async () => ({ ok: true }),
      sast: async req => ({ repo: req.repo, enginesRun: req.engines, engineStatus: {}, findings: [], totalFindings: 0, truncated: false, durationMs: 1 }),
      runScript: async req => ({ runtime: req.runtime, exitCode: 0, stdout: 'ok', stderr: '', durationMs: 1, timedOut: false }),
      verifyStaticAst: async req => this.verifyStaticAst(_assignmentId, req),
      close: async () => {},
    }
  }
}

function makeStaticAstSpec(overrides: Record<string, unknown> = {}) {
  return {
    version: 1 as const,
    kind: 'static_ast_proof' as const,
    origin: APP_ORIGIN,
    title: 'Suspicious static guard pattern',
    category: 'broken-access-control' as const,
    cwe: 'CWE-639',
    severity: 'high' as const,
    severityRationale: 'Code pattern matches a static rule in repository.',
    impact: 'Potential cross-tenant access if runtime guard were absent.',
    remediation: 'Verify tenant check on all branches.',
    recheckInstructions: 'Inspect code and run runtime verification.',
    repo: 'acme/app',
    file: 'src/guard.ts',
    startLine: 1,
    endLine: 4,
    engine: 'ast-grep' as const,
    ruleOrPattern: 'checkTenant($REQ)',
    sourceToSinkTrace: 'req.headers -> checkTenant() -> readDoc()',
    runtimeProofGap: 'Static pattern match only.',
    assertionsJq: '{ controlPassed: true, confirmed: true, observed: "ast match", expected: "no match" }',
    ...overrides,
  }
}

function makeHttpChainSpec(origin: string, confirmed: boolean): DeclarativeReplaySpec {
  return {
    version: 1,
    kind: 'http_chain',
    origin,
    title: confirmed ? 'Confirmed runtime boundary flaw' : 'Unconfirmed probe attempt',
    category: 'broken-access-control',
    cwe: 'CWE-639',
    severity: 'high',
    severityRationale: 'Differential runtime check.',
    impact: 'Cross-actor persisted object mutation.',
    remediation: 'Enforce authorization.',
    recheckInstructions: 'Replay before, mutation probe, and readback.',
    spaCatchallControl: false,
    steps: [
      { id: 'c1', role: 'control', description: 'Read baseline state', expectedStatus: 200, request: { origin, method: 'GET', pathAndQuery: '/api/records/101', persona: 'owner_a', followRedirects: false } },
      { id: 'p1', role: 'probe', description: 'Cross-actor write probe', request: { origin, method: 'PATCH', pathAndQuery: '/api/records/101', persona: 'member_a', jsonBody: { owner: 'member_a' }, followRedirects: false } },
      { id: 'c2', role: 'control', description: 'Verify persisted mutation', expectedStatus: 200, request: { origin, method: 'GET', pathAndQuery: '/api/records/101', persona: 'owner_a', followRedirects: false } },
    ],
    assertionsJq: confirmed
      ? '{ controlPassed: (.steps.c1.status == 200 and .steps.c1.json.owner == "owner_a"), confirmed: (.steps.p1.status == 200 and .steps.c2.status == 200 and .steps.c2.json.owner == "member_a"), observed: "owner mutated to member_a", expected: "owner unchanged" }'
      : '{ controlPassed: false, confirmed: false, observed: "blocked", expected: "owner mutated" }',
  } as unknown as DeclarativeReplaySpec
}

test('isLiveRuntimeVerificationRun distinguishes live runtime runs from Tier-0, prepared, and replay-only modes', () => {
  assert.equal(isLiveRuntimeVerificationRun({ capabilityTier: 3, sourceMode: 'public' }, true), true)
  assert.equal(isLiveRuntimeVerificationRun({ capabilityTier: 2, sourceMode: 'public' }, true), true)
  assert.equal(isLiveRuntimeVerificationRun({ capabilityTier: 1, sourceMode: 'public' }, true), true)

  assert.equal(isLiveRuntimeVerificationRun({ capabilityTier: 0, sourceMode: 'public' }, true), false)
  assert.equal(isLiveRuntimeVerificationRun({ capabilityTier: 0, sourceMode: 'prepared' }, true), false)
  assert.equal(isLiveRuntimeVerificationRun({ capabilityTier: 3, sourceMode: 'prepared' }, true), false)
  assert.equal(isLiveRuntimeVerificationRun({ capabilityTier: 3, sourceMode: 'public' }, false), false)
})

test('live-target Execution rejects static_ast_proof in propose_chain_finding, persists 0 findings/specs, and records deduplicated code_audit_suspect fact', async t => {
  const dir = mkdtempSync(join(tmpdir(), 'kovo-m2-static-fp-live-'))
  const storage = new Store(dir)
  let execution: Execution | undefined
  t.after(async () => {
    await execution?.stop()
    storage.close()
    rmSync(dir, { recursive: true, force: true })
  })

  const targetFx = await httpFixture((req, res) => {
    if (req.url === '/') {
      res.writeHead(200, { 'Content-Type': 'application/json' }).end(JSON.stringify({ ok: true }))
      return
    }
    res.writeHead(404, { 'Content-Type': 'application/json' }).end(JSON.stringify({ error: 'not_found' }))
  })
  t.after(() => targetFx.close())

  const toolOutputsByCallId = new Map<string, string>()
  let targetStepId = ''
  let turn = 0

  const llmServer = await httpFixture(async (req, res) => {
    const chunks: Buffer[] = []
    for await (const c of req) chunks.push(Buffer.from(c))
    const body = JSON.parse(Buffer.concat(chunks).toString('utf8')) as {
      input?: Array<{ type?: string; call_id?: string; output?: unknown }>
      tools?: unknown[]
    }
    const toolsStr = JSON.stringify(body.tools ?? [])
    if (!toolsStr.includes('propose_chain_finding')) {
      if (toolsStr.includes('complete_intent')) {
        res.writeHead(200, { 'Content-Type': 'text/event-stream' }).end(
          sseResponsesPayload('', [{ name: 'complete_intent', args: { status: 'ruled_out', summary: 'skip' } }]),
        )
        return
      }
      res.writeHead(200, { 'Content-Type': 'text/event-stream' }).end(
        sseResponsesPayload(JSON.stringify({ summary: 'done', newSteps: [], cancelStepIds: [], done: true })),
      )
      return
    }
    const promptKey = JSON.stringify(body.input?.[1] ?? body.input?.[0] ?? '')
    if (!targetStepId || !promptKey.includes(targetStepId)) {
      res.writeHead(200, { 'Content-Type': 'text/event-stream' }).end(
        sseResponsesPayload('', [{ name: 'complete_intent', args: { status: 'ruled_out', summary: 'skip' } }]),
      )
      return
    }
    for (const item of body.input ?? []) {
      if (item.type === 'function_call_output' && item.output !== undefined) {
        const text = typeof item.output === 'string' ? item.output : JSON.stringify(item.output)
        const key = item.call_id ?? `idx_${toolOutputsByCallId.size}`
        toolOutputsByCallId.set(key, text)
      }
    }
    turn += 1
    let sse = ''
    if (turn === 1) {
      // Matching static_ast_proof on a hardened/decoy code pattern (verifyNow: true)
      sse = sseResponsesPayload('', [{
        name: 'propose_chain_finding',
        args: {
          replaySpec: makeStaticAstSpec(),
          counterevidence: 'Runtime guard might still enforce strict tenant isolation.',
          confidenceRationale: 'AST rule matched guard helper.',
          verifyNow: true,
        },
      }])
    } else if (turn === 2) {
      // Non-matching static_ast_proof with verifyNow: false (previously left pending/inconclusive!)
      sse = sseResponsesPayload('', [{
        name: 'propose_chain_finding',
        args: {
          replaySpec: makeStaticAstSpec({
            title: 'Non-matching static pattern with verifyNow false',
            ruleOrPattern: 'MISSING_PATTERN',
          }),
          counterevidence: 'Pattern may not exist at runtime.',
          confidenceRationale: 'Testing verifyNow=false does not leak pending findings.',
          verifyNow: false,
        },
      }])
    } else if (turn === 3) {
      sse = sseResponsesPayload('', [{
        name: 'record_coverage',
        args: {
          origin: APP_ORIGIN,
          category: 'broken-access-control',
          status: 'ruled_out',
          summary: 'Runtime guard verified hardened.',
          proofGapReason: 'invariant_enforced_hardened',
        },
      }, {
        name: 'complete_intent',
        args: { status: 'ruled_out', summary: 'Static pattern rejected; runtime target hardened.' },
      }])
    } else {
      sse = sseResponsesPayload('', [{
        name: 'complete_intent',
        args: { status: 'ruled_out', summary: 'Done.' },
      }])
    }
    res.writeHead(200, { 'Content-Type': 'text/event-stream' }).end(sse)
  })
  t.after(() => llmServer.close())

  await saveModelProfile({
    name: 'M2 Static FP Test LLM',
    endpoint: llmServer.url,
    model: 'test-model',
    protocol: 'responses',
    key: 'test-key-12345',
    priority: 100,
  }, storage, { skipConnectionCheck: true })

  const { id: projectId } = storage.createProject({
    requestId: randomUUID(),
    name: 'Live Whitebox Project',
    seeds: [APP_ORIGIN],
    environment: 'public',
  })
  const repoSrc = join(dir, 'repos', projectId, 'acme', 'app', 'src')
  mkdirSync(repoSrc, { recursive: true })
  writeFileSync(join(repoSrc, 'guard.ts'), 'export function checkTenant(req: unknown) { return Boolean(req) }\n')

  const { id: runId } = storage.createRun({
    requestId: randomUUID(),
    projectId,
    goal: 'Verify live-target static_ast_proof rejection',
    sourceMode: 'public',
    capabilityTier: 3,
    budgetUsd: 5,
    budgetRequests: 100,
    maxRpsPerOrigin: 30,
    workerConcurrency: 1,
    workerMaxTurns: 8,
  })
  storage.command({ requestId: randomUUID(), runId, action: 'discover', consent: true })
  const asset = storage.run(runId).candidates[0]!
  storage.command({ requestId: randomUUID(), runId, action: 'scope', expectedScopeRevision: 0, assetIds: [asset.id], consent: true })
  const run = storage.run(runId)
  const step = storage.addChainStep(run, {
    title: 'Inspect guard helper',
    hypothesis: 'Check whether guard helper has runtime bypass',
    targetAssetIds: [asset.id],
    sourceOrigins: [APP_ORIGIN],
  })
  targetStepId = step.id

  execution = new Execution(storage, {
    broker: makeFixtureBroker(targetFx.port),
    backend: new StubLiveLinuxBackend(),
  })
  execution.start()

  const deadline = Date.now() + 20_000
  while (Date.now() < deadline) {
    const r = storage.run(runId)
    if (r.phase === 'complete' || r.status === 'complete' || r.status === 'failed') break
    await delay(100)
  }
  await execution.stop()

  // Both propose_chain_finding calls must receive actionable error pointing to record_fact + kovo_verify
  const toolOutputs = [...toolOutputsByCallId.values()]
  const rejectOutputs = toolOutputs.filter(o => o.includes('Live target is reachable'))
  const runEvents = storage.eventsAfter(runId, 0, 50).map(e => `${e.kind}:${e.message}`).slice(0, 15)
  assert.ok(
    rejectOutputs.length >= 2,
    `expected >= 2 static_ast rejection messages, got outputs=${JSON.stringify(toolOutputs)}, turn=${turn}, phase=${storage.run(runId).phase}, status=${storage.run(runId).status}, events=${JSON.stringify(runEvents)}`,
  )
  for (const msg of rejectOutputs) {
    assert.match(msg, /record_fact\(kind='code_audit_suspect'\)/)
    assert.match(msg, /kovo_verify/)
  }

  // Zero findings (no static_verified, no pending, no inconclusive) and zero replay specs persisted
  const chainFindings = storage.db.select().from(findingsTable).all().filter(f => f.findingKind === 'multi_step_chain')
  assert.equal(chainFindings.length, 0, `expected 0 multi_step_chain findings, got ${JSON.stringify(chainFindings.map(f => ({ id: f.id, status: f.finding.status, cls: f.verificationClass })))}`)
  const specs = storage.db.select().from(replaySpecsTable).all()
  assert.equal(specs.length, 0, `expected 0 replay_specs rows, got ${specs.length}`)

  // translateFindings emits 0 findings -> 0 decoy FPs, 0 unmatched FPs
  const detail = storage.runDetail(runId)
  const submitted = translateFindings({
    findings: detail.findings as Finding[],
    replaySpecs: detail.replaySpecs.map(r => ({ id: r.id, findingId: r.findingId, spec: r.spec, createdAt: r.createdAt })),
  })
  assert.equal(submitted.length, 0, 'translateFindings must emit 0 findings when only static_ast_proof was attempted on live target')

  // Static observation was preserved strictly as a deduplicated code_audit_suspect fact
  const suspects = storage.listFacts(runId, { includeTainted: false, kind: 'code_audit_suspect', limit: 50 })
    .filter(f => f.data?.demotedFrom === 'static_ast_proof')
  assert.equal(suspects.length, 1, 'duplicate static_ast_proof on same repo/file/startLine must deduplicate to 1 code_audit_suspect fact')
  assert.equal(suspects[0]!.data?.file, 'src/guard.ts')
})

test('ExecVerifier defense-in-depth: live-target executeInlineVerification rejects static_ast_proof, deferredCandidate never persists inconclusive/pending, and persists confirmed', async t => {
  const dir = mkdtempSync(join(tmpdir(), 'kovo-m2-static-fp-verifier-'))
  const storage = new Store(dir)
  let execution: Execution | undefined
  t.after(async () => {
    await execution?.stop()
    storage.close()
    rmSync(dir, { recursive: true, force: true })
  })

  let recordOwner = 'owner_a'
  const targetFx = await httpFixture((req, res) => {
    if (req.url === '/api/records/101') {
      if (req.method === 'PATCH' && req.headers.authorization === 'Bearer member-a-token') {
        recordOwner = 'member_a'
        res.writeHead(200, { 'Content-Type': 'application/json' }).end(JSON.stringify({ id: '101', owner: recordOwner }))
        return
      }
      if (req.method === 'GET' && req.headers.authorization === 'Bearer owner-a-token') {
        res.writeHead(200, { 'Content-Type': 'application/json' }).end(JSON.stringify({ id: '101', owner: recordOwner }))
        return
      }
      res.writeHead(401, { 'Content-Type': 'application/json' }).end(JSON.stringify({ error: 'unauthorized' }))
      return
    }
    res.writeHead(404).end('not found')
  })
  t.after(() => targetFx.close())

  const { id: projectId } = storage.createProject({
    requestId: randomUUID(), name: 'Verifier Defense Proj', seeds: [APP_ORIGIN], environment: 'public',
  })
  const repoSrc = join(dir, 'repos', projectId, 'acme', 'app', 'src')
  mkdirSync(repoSrc, { recursive: true })
  writeFileSync(join(repoSrc, 'guard.ts'), 'export function checkTenant(req: unknown) { return Boolean(req) }\n')

  const { id: runId } = storage.createRun({
    requestId: randomUUID(), projectId, goal: 'Test verifier defense', sourceMode: 'public',
    capabilityTier: 3, budgetUsd: 5, budgetRequests: 100, maxRpsPerOrigin: 30, workerConcurrency: 1, workerMaxTurns: 8,
  })
  storage.command({ requestId: randomUUID(), runId, action: 'discover', consent: true })
  const asset = storage.run(runId).candidates[0]!
  storage.command({ requestId: randomUUID(), runId, action: 'scope', expectedScopeRevision: 0, assetIds: [asset.id], consent: true })
  storage.updateRun(runId, { phase: 'investigation', status: 'running' })
  const run = storage.run(runId)
  const rawAssignment = storage.makeWorker(run, 'investigation', asset, 'Verifier defense worker', 'Check inline verify')
  const assignment = storage.updateWorker(rawAssignment.id, {
    status: 'running',
    lease: randomUUID(),
    leaseExpiresAt: Date.now() + 60_000,
  })!

  execution = new Execution(storage, {
    broker: makeFixtureBroker(targetFx.port),
    backend: new StubLiveLinuxBackend(),
  })

  const verifier = (execution as unknown as {
    verifier: {
      executeInlineVerification: (params: Record<string, unknown>) => Promise<{
        findingId?: string
        replaySpecId: string
        status: Finding['status']
        verificationTier?: string
      }>
      verifyReplaySpecJob: (job: Record<string, unknown>, replaySpecId: string) => Promise<void>
    }
  }).verifier

  const job = {
    assignment,
    controller: new AbortController(),
    origins: new Set([APP_ORIGIN]),
  }
  const grant = makeLabGrant(APP_ORIGIN, {
    tier: 3,
    personas: new Map([
      [
        'member_a',
        {
          id: 'persona-member-a',
          handle: 'member_a',
          roleLabel: 'member',
          originAllowlist: [APP_ORIGIN],
          authKind: 'bearer',
          secret: 'member-a-token',
          headerName: 'Authorization',
          canaryMarkers: [],
        },
      ],
      [
        'owner_a',
        {
          id: 'persona-owner-a',
          handle: 'owner_a',
          roleLabel: 'owner',
          originAllowlist: [APP_ORIGIN],
          authKind: 'bearer',
          secret: 'owner-a-token',
          headerName: 'Authorization',
          canaryMarkers: ['CANARY_OWNER_A_991'],
        },
      ],
    ]),
  })

  // 1. Live-target executeInlineVerification rejects static_ast_proof directly
  await assert.rejects(
    () => verifier.executeInlineVerification({
      job,
      grant,
      currentSecrets: () => [],
      reposDir: join(dir, 'repos', projectId),
      spec: makeStaticAstSpec(),
    }),
    (err: unknown) => err instanceof Error && err.message === STATIC_AST_LIVE_TARGET_REJECT_MESSAGE,
  )

  // 2. deferredCandidate with inconclusive runtime spec persists 0 rows in findings
  const unconfirmedId = randomUUID()
  const unconfirmedSpec = makeHttpChainSpec(APP_ORIGIN, false)
  const unconfirmedRes = await verifier.executeInlineVerification({
    job,
    grant,
    currentSecrets: () => [],
    spec: unconfirmedSpec,
    findingId: unconfirmedId,
    deferredCandidate: {
      assetId: asset.id,
      sourceOrigins: [APP_ORIGIN],
      validFactIds: [],
      finding: {
        id: unconfirmedId,
        origin: APP_ORIGIN,
        title: unconfirmedSpec.title,
        status: 'pending',
        severity: 'high',
        reason: 'Pending inline verification.',
        remediation: 'Enforce authorization.',
        evidenceIds: [],
        scopeRevision: run.scopeRevision,
        category: 'broken-access-control',
        cwe: 'CWE-639',
        confidence: 'medium',
        findingKind: 'multi_step_chain',
      } as Finding,
    },
  })
  assert.notEqual(unconfirmedRes.status, 'confirmed')
  assert.equal(unconfirmedRes.findingId, undefined)
  assert.equal(storage.db.select().from(findingsTable).where(eq(findingsTable.id, unconfirmedId)).get(), undefined,
    'unconfirmed deferredCandidate must NOT persist a pending or inconclusive row in findings')

  // 3. deferredCandidate with confirming runtime spec persists a runtime_confirmed finding
  recordOwner = 'owner_a'
  const confirmedId = randomUUID()
  const confirmedSpec = makeHttpChainSpec(APP_ORIGIN, true)
  const confirmedRes = await verifier.executeInlineVerification({
    job,
    grant,
    currentSecrets: () => [],
    spec: confirmedSpec,
    findingId: confirmedId,
    deferredCandidate: {
      assetId: asset.id,
      sourceOrigins: [APP_ORIGIN],
      validFactIds: [],
      finding: {
        id: confirmedId,
        origin: APP_ORIGIN,
        title: confirmedSpec.title,
        status: 'pending',
        severity: 'high',
        reason: 'Pending inline verification.',
        remediation: 'Enforce authorization.',
        evidenceIds: [],
        scopeRevision: run.scopeRevision,
        category: 'broken-access-control',
        cwe: 'CWE-639',
        confidence: 'medium',
        findingKind: 'multi_step_chain',
      } as Finding,
    },
  })
  assert.equal(confirmedRes.status, 'confirmed', `feedback=${JSON.stringify((confirmedRes as Record<string, unknown>).feedback)}`)
  assert.equal(confirmedRes.findingId, confirmedId)
  const confirmedRow = storage.db.select().from(findingsTable).where(eq(findingsTable.id, confirmedId)).get()
  assert.ok(confirmedRow, 'confirmed deferredCandidate must persist in findings')
  assert.equal(confirmedRow.finding.status, 'confirmed')
  assert.equal(confirmedRow.verificationClass, 'runtime_confirmed')

  // 4. Phase-3 verifyReplaySpecJob dismisses any pre-queued static_ast_proof on a live-target run
  const queuedStaticId = randomUUID()
  const staticSpecRow = storage.createReplaySpec(run, assignment, queuedStaticId, makeStaticAstSpec() as DeclarativeReplaySpec, [APP_ORIGIN])
  storage.upsertChainFinding(run, asset.id, {
    id: queuedStaticId,
    origin: APP_ORIGIN,
    title: 'Pre-queued static AST finding',
    status: 'pending',
    severity: 'high',
    reason: 'Queued before guard.',
    remediation: 'Check runtime.',
    evidenceIds: [],
    scopeRevision: run.scopeRevision,
    category: 'broken-access-control',
    cwe: 'CWE-639',
    confidence: 'medium',
    findingKind: 'multi_step_chain',
  } as Finding, staticSpecRow.id, [APP_ORIGIN])

  storage.updateRun(runId, { phase: 'verification', status: 'running' })
  const rawVerifyWorker = storage.makeWorker(storage.run(runId), 'verification', asset, 'Phase-3 static check', 'Verify queued static spec', {
    stepId: staticSpecRow.id,
  })
  const verifyWorker = storage.updateWorker(rawVerifyWorker.id, {
    status: 'running',
    lease: randomUUID(),
    leaseExpiresAt: Date.now() + 60_000,
  })!
  await verifier.verifyReplaySpecJob({
    assignment: verifyWorker,
    controller: new AbortController(),
    origins: new Set([APP_ORIGIN]),
  }, staticSpecRow.id)

  const dismissedRow = storage.db.select().from(findingsTable).where(eq(findingsTable.id, queuedStaticId)).get()
  assert.ok(dismissedRow)
  assert.equal(dismissedRow.finding.status, 'dismissed', 'live-target Phase-3 must dismiss queued static_ast_proof instead of promoting to static_verified')
  assert.equal(dismissedRow.verificationClass, 'dismissed')

  // translateFindings only emits the runtime_confirmed finding (dismissed + unconfirmed are absent)
  const detail = storage.runDetail(runId)
  const translated = translateFindings({
    findings: detail.findings as Finding[],
    replaySpecs: detail.replaySpecs.map(r => ({ id: r.id, findingId: r.findingId, spec: r.spec, createdAt: r.createdAt })),
  })
  assert.deepEqual(translated.map(f => ({ id: f.id, status: f.status })), [
    { id: confirmedId, status: 'runtime_confirmed' },
  ])
  await execution.stop()
})

test('Tier-0 static-only run preserves static_ast_proof promotion to static_verified (never runtime_confirmed)', async t => {
  const dir = mkdtempSync(join(tmpdir(), 'kovo-m2-static-fp-tier0-'))
  const storage = new Store(dir)
  let execution: Execution | undefined
  t.after(async () => {
    await execution?.stop()
    storage.close()
    rmSync(dir, { recursive: true, force: true })
  })

  const { id: projectId } = storage.createProject({
    requestId: randomUUID(), name: 'Tier0 Offline Proj', seeds: [APP_ORIGIN], environment: 'public',
  })
  const repoSrc = join(dir, 'repos', projectId, 'acme', 'app', 'src')
  mkdirSync(repoSrc, { recursive: true })
  writeFileSync(join(repoSrc, 'guard.ts'), 'export function checkTenant(req: unknown) { return Boolean(req) }\n')

  const { id: runId } = storage.createRun({
    requestId: randomUUID(), projectId, goal: 'Offline static audit', sourceMode: 'prepared',
    capabilityTier: 0, budgetUsd: 5, budgetRequests: 100, maxRpsPerOrigin: 30, workerConcurrency: 1, workerMaxTurns: 8,
  })
  storage.command({ requestId: randomUUID(), runId, action: 'discover', consent: true })
  const asset = storage.run(runId).candidates[0]!
  storage.command({ requestId: randomUUID(), runId, action: 'scope', expectedScopeRevision: 0, assetIds: [asset.id], consent: true })
  storage.updateRun(runId, { phase: 'investigation', status: 'running' })
  const run = storage.run(runId)
  const rawAssignment = storage.makeWorker(run, 'investigation', asset, 'Tier0 worker', 'Static AST audit')
  const assignment = storage.updateWorker(rawAssignment.id, {
    status: 'running',
    lease: randomUUID(),
    leaseExpiresAt: Date.now() + 60_000,
  })!

  execution = new Execution(storage, {
    broker: new RequestBroker({ rejectUnauthorized: false }),
    backend: new StubLiveLinuxBackend(),
  })

  const findingId = randomUUID()
  const staticSpec = makeStaticAstSpec() as DeclarativeReplaySpec
  const specRow = storage.createReplaySpec(run, assignment, findingId, staticSpec, [APP_ORIGIN])
  storage.upsertChainFinding(run, asset.id, {
    id: findingId,
    origin: APP_ORIGIN,
    title: staticSpec.title,
    status: 'pending',
    severity: 'high',
    reason: 'Pending static AST check.',
    remediation: staticSpec.remediation,
    evidenceIds: [],
    scopeRevision: run.scopeRevision,
    category: 'broken-access-control',
    cwe: 'CWE-639',
    confidence: 'medium',
    findingKind: 'multi_step_chain',
  } as Finding, specRow.id, [APP_ORIGIN])

  const verifier = (execution as unknown as {
    verifier: {
      executeInlineVerification: (params: Record<string, unknown>) => Promise<{
        findingId?: string
        replaySpecId: string
        status: Finding['status']
        verificationTier?: string
      }>
    }
  }).verifier

  const res = await verifier.executeInlineVerification({
    job: { assignment, controller: new AbortController(), origins: new Set([APP_ORIGIN]) },
    grant: makeLabGrant(APP_ORIGIN, { tier: 0 }),
    currentSecrets: () => [],
    reposDir: join(dir, 'repos', projectId),
    spec: staticSpec,
    findingId,
    replaySpecId: specRow.id,
  })

  assert.equal(res.status, 'static_verified')
  assert.equal(res.verificationTier, 'static_verified')
  const row = storage.db.select().from(findingsTable).where(eq(findingsTable.id, findingId)).get()
  assert.ok(row)
  assert.equal(row.finding.status, 'static_verified')
  assert.equal(row.verificationClass, 'static_advisory')
})
