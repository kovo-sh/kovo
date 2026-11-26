/**
 * R2-04: Retest truthfulness invariants across all three retest engines
 * (floor recipe engine, declarative replay verifier, and agent-script proof engine).
 *
 * Verifies:
 *   1. Shared `assessRetestHealth(baseline, probeArms, session)` and re-exported `classifyRetestHealth`
 *      enforce strict typed failure reasons (`claim_not_reproduced` is the ONLY reason eligible for `fixed`).
 *   2. `receipt_unbuildable`, `composite_stage_rejected`, `session_drifted`, `probe_unhealthy`, and
 *      `baseline_unhealthy` ALWAYS map to `inconclusive` (NEVER `dismissed` / `fixed`).
 *   3. `runAgentScriptProof` emits typed reasons instead of overloaded `oracle_failed`, and
 *      `retestPersistedAgentScript` gates `fixed` strictly on `assessRetestHealth(...)`.
 *   4. `retestReplaySpec` (declarative path) gates `fixed` on `assessRetestHealth(...)` + receipt
 *      buildability, and `!deterministicProofPassed` maps to `inconclusive` even when `controlPassed=true`.
 */
import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { once } from 'node:events'
import { readFileSync } from 'node:fs'
import { createServer, request as httpRequest } from 'node:http'
import { join } from 'node:path'
import test from 'node:test'
import type { DeclarativeReplaySpec } from '../src/replay-spec.ts'
import { RequestBroker, type Grant } from '../src/server/broker.ts'
import {
  classifyRetestHealth as engineClassifyRetestHealth,
  retestPersistedRecipe,
} from '../src/server/floor-recipe-engine.ts'
import {
  assessDeclarativeRetestHealth,
  assessRetestHealth,
  buildAgentScriptRetestInputs,
  classifyRetestHealth,
  isFixedEligibleFailureReason,
  type RetestFailureReason,
  type RetestHealthAssessment,
} from '../src/server/retest-health.ts'
import {
  retestPersistedAgentScript,
  retestReplaySpec,
  runAgentScriptProof,
} from '../src/server/replay-verifier.ts'
import {
  VERIFY_NONCE_HEADER,
  VERIFY_RPC_CONTEXT_NAME,
  VERIFY_RPC_HEADER,
  VERIFY_RPC_SOCKET_NAME,
  VERIFY_RPC_TOKEN_NAME,
} from '../src/server/verify-rpc.ts'
import type { VerifyScriptRequest, VerifyScriptResult, WorkerBackend, WorkerSession, WorkerSessionOptions } from '../src/server/worker-backend.ts'
import { LocalJqBackend } from '../scripts/benchmark-backend.ts'
import { makeLabGrant } from './v4-tier-helpers.ts'

process.env.KOVO_ALLOW_LOCAL_LAB = '1'

function sha256(s: string): string {
  return createHash('sha256').update(s, 'utf8').digest('hex')
}

function makeAuthGrant(origin: string): Grant {
  const personas = new Map([
    ['owner_a', {
      id: 'p-owner-a',
      handle: 'owner_a',
      roleLabel: 'owner (tenant-a)',
      originAllowlist: [origin],
      authKind: 'bearer' as const,
      headerName: 'Authorization',
      secret: 'tok-owner-a',
      canaryMarkers: [],
    }],
    ['viewer_b', {
      id: 'p-viewer-b',
      handle: 'viewer_b',
      roleLabel: 'viewer (tenant-b)',
      originAllowlist: [origin],
      authKind: 'bearer' as const,
      headerName: 'Authorization',
      secret: 'tok-viewer-b',
      canaryMarkers: [],
    }],
    ['member_b', {
      id: 'p-member-b',
      handle: 'member_b',
      roleLabel: 'member (tenant-b)',
      originAllowlist: [origin],
      authKind: 'bearer' as const,
      headerName: 'Authorization',
      secret: 'tok-member-b',
      canaryMarkers: [],
    }],
  ])
  return makeLabGrant(origin, { tier: 3, personas })
}

async function rpcCall(
  socketPath: string,
  token: string,
  nonce: string,
  op: string,
  args: Record<string, unknown>,
): Promise<{ ok: boolean; result?: Record<string, unknown>; error?: string }> {
  const body = JSON.stringify({ op, args })
  return await new Promise((resolvePromise, rejectPromise) => {
    const req = httpRequest(
      {
        socketPath,
        path: '/rpc',
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          'content-length': Buffer.byteLength(body),
          [VERIFY_RPC_HEADER]: token,
          [VERIFY_NONCE_HEADER]: nonce,
        },
      },
      res => {
        let data = ''
        res.setEncoding('utf8')
        res.on('data', chunk => { data += chunk })
        res.on('end', () => {
          try { resolvePromise(JSON.parse(data) as { ok: boolean; result?: Record<string, unknown>; error?: string }) }
          catch (err) { rejectPromise(err) }
        })
      },
    )
    req.on('error', rejectPromise)
    req.end(body)
  })
}

function makeFakeBackend(
  fn: (ctx: {
    req: VerifyScriptRequest
    nonce: string
    rpc: (op: string, args: Record<string, unknown>) => Promise<{ ok: boolean; result?: Record<string, unknown>; error?: string }>
  }) => Promise<VerifyScriptResult>,
): WorkerBackend {
  return {
    async run() { throw new Error('unused') },
    async verifyStaticAst() { throw new Error('unused') },
    async openSession(_id: string, _signal: AbortSignal, opts?: WorkerSessionOptions): Promise<WorkerSession> {
      const rpcDir = opts?.rpcMountDir ?? ''
      return {
        async stage() { throw new Error('unused') },
        async exec() { throw new Error('unused') },
        async analyze() { throw new Error('unused') },
        async sast() { throw new Error('unused') },
        async runScript() { throw new Error('unused') },
        async verifyStaticAst() { throw new Error('unused') },
        async verifyScript(req: VerifyScriptRequest): Promise<VerifyScriptResult> {
          const socketPath = join(rpcDir, VERIFY_RPC_SOCKET_NAME)
          const token = readFileSync(join(rpcDir, VERIFY_RPC_TOKEN_NAME), 'utf8').trim()
          const ctx = JSON.parse(readFileSync(join(rpcDir, VERIFY_RPC_CONTEXT_NAME), 'utf8')) as { nonce: string }
          const rpc = (op: string, args: Record<string, unknown>) => rpcCall(socketPath, token, ctx.nonce, op, args)
          return fn({ req, nonce: ctx.nonce, rpc })
        },
        async close() {},
      }
    },
  }
}

test('R2-04: floor-recipe-engine re-exports canonical classifyRetestHealth and assessRetestHealth enforces strict reason allowlist', () => {
  assert.equal(engineClassifyRetestHealth, classifyRetestHealth)
  assert.equal(isFixedEligibleFailureReason('claim_not_reproduced'), true)
  const forbiddenReasons: readonly RetestFailureReason[] = [
    'receipt_unbuildable',
    'composite_stage_rejected',
    'session_drifted',
    'probe_unhealthy',
    'baseline_unhealthy',
  ]
  for (const reason of forbiddenReasons) {
    assert.equal(isFixedEligibleFailureReason(reason), false, `${reason} must never be eligible for fixed`)
    const res = assessRetestHealth(
      { controlArms: [{ role: 'entitled', status: 200, authenticated: true }] },
      { arms: [{ role: 'probe', status: 403, authenticated: true }] },
      { failureReason: reason },
    )
    assert.equal(res.healthy, false, `assessRetestHealth must mark ${reason} unhealthy`)
    assert.equal(res.failureReason, reason)
  }

  // Healthy baseline + definitively denied probe + claim_not_reproduced -> healthy
  const clean = assessRetestHealth(
    {
      controlArms: [
        { role: 'entitled_read', status: 200, authenticated: true },
        { role: 'denied_control', status: 403, authenticated: true, expectDenied: true },
      ],
      accessBoundary: true,
      entitledControlPresent: true,
      entitledControlStatus: 200,
    },
    {
      arms: [{ role: 'probe_request', status: 403, authenticated: true }],
      requireDefinitiveDenial: true,
    },
    { failureReason: 'claim_not_reproduced' },
  )
  assert.equal(clean.healthy, true)
  assert.equal(clean.code, 'healthy')
  assert.equal(clean.failureReason, 'claim_not_reproduced')
})

test('R2-04: assessRetestHealth rejects deterministicProofPassed=false, 5xx/429/302 probes, and authenticated 401 on setup/control/probe', () => {
  const detFailed = assessDeclarativeRetestHealth(
    { kind: 'http_chain', category: 'bola', cwe: 'CWE-639', steps: [{ id: 'c', role: 'control' }, { id: 'p', role: 'probe' }] },
    {
      verdict: 'dismissed',
      outcome: { confirmed: false, controlPassed: true },
      evidencePayload: {
        steps: {
          c: { id: 'c', role: 'control', status: 200, personaHandle: 'owner_a' },
          p: { id: 'p', role: 'probe', status: 403, personaHandle: 'member_b' },
        },
      },
    },
    { deterministicProofPassed: false, proofFailureReason: 'Proof-of-execution check did not pass.', receiptBuildable: true },
  )
  assert.equal(detFailed.healthy, false)
  assert.equal(detFailed.failureReason, 'probe_unhealthy')

  // Setup 401 -> session_drifted
  const setupDrift = assessRetestHealth(
    {
      setupArms: [{ role: 'setup_auth', status: 401, authenticated: true }],
      controlArms: [{ role: 'ctl', status: 200, authenticated: true }],
    },
    { arms: [{ role: 'prb', status: 403, authenticated: true }] },
    {},
  )
  assert.equal(setupDrift.healthy, false)
  assert.equal(setupDrift.failureReason, 'session_drifted')

  // Control 401 -> session_drifted
  const ctlDrift = assessRetestHealth(
    { controlArms: [{ role: 'ctl', status: 401, authenticated: true, allowDenied: true }] },
    { arms: [{ role: 'prb', status: 403, authenticated: true }] },
    {},
  )
  assert.equal(ctlDrift.healthy, false)
  assert.equal(ctlDrift.failureReason, 'session_drifted')

  // Probe 500, 429, 302 -> probe_unhealthy
  for (const status of [500, 503, 429, 408, 302, 0] as const) {
    const res = assessRetestHealth(
      { controlArms: [{ role: 'ctl', status: 200, authenticated: true }] },
      { arms: [{ role: 'prb', status, authenticated: true }] },
      {},
    )
    assert.equal(res.healthy, false, `probe HTTP ${status} must be unhealthy`)
    assert.equal(res.failureReason, 'probe_unhealthy')
  }
})

test('R2-04: declarative retestReplaySpec rejects drifted session, 5xx probe, and unbuildable receipt as inconclusive; allows clean fix', async (t) => {
  let probeStatus = 403
  let controlStatus = 200
  const server = createServer((req, res) => {
    req.resume()
    res.setHeader('content-type', 'application/json')
    const auth = req.headers.authorization ?? ''
    if (auth === 'Bearer tok-owner-a') {
      res.statusCode = controlStatus
      res.end(controlStatus === 200
        ? JSON.stringify({ id: 'inv_1', owner_id: 'owner_a', tenant_id: 'tenant-a', email: 'a@tenant-a.example' })
        : JSON.stringify({ error: 'auth drift' }))
      return
    }
    if (auth === 'Bearer tok-viewer-b') {
      res.statusCode = 403
      res.end(JSON.stringify({ error: 'forbidden' }))
      return
    }
    res.statusCode = probeStatus
    res.end(probeStatus === 200
      ? JSON.stringify({ id: 'inv_1', owner_id: 'owner_a', tenant_id: 'tenant-a', email: 'a@tenant-a.example' })
      : JSON.stringify({ error: `status-${probeStatus}` }))
  })
  server.listen(0, '127.0.0.1')
  await once(server, 'listening')
  const origin = `http://127.0.0.1:${(server.address() as { port: number }).port}`
  t.after(async () => {
    server.closeAllConnections()
    await new Promise<void>(r => server.close(() => r()))
  })

  const makeSpec = (overrides?: Partial<DeclarativeReplaySpec>): DeclarativeReplaySpec => ({
    version: 1,
    kind: 'http_chain',
    origin,
    title: 'Cross-tenant invoice read',
    category: 'bola',
    cwe: 'CWE-639',
    severity: 'high',
    severityRationale: 'Cross-tenant read.',
    impact: 'Reads another tenant invoice.',
    remediation: 'Enforce tenant isolation.',
    recheckInstructions: 'Replay.',
    resourceTenant: 'tenant-a',
    assertionsJq: '{ controlPassed: (.steps.ctl.status == 200 and .steps.denied.status == 403), confirmed: (.steps.prb.status == 200), observed: (.steps.prb.status | tostring), expected: "403" }',
    steps: [
      { id: 'ctl', role: 'control', description: 'entitled', request: { origin, method: 'GET', pathAndQuery: '/api/invoices/inv_1', persona: 'owner_a', followRedirects: false } },
      { id: 'denied', role: 'control', description: 'denied', request: { origin, method: 'GET', pathAndQuery: '/api/invoices/inv_1', persona: 'viewer_b', followRedirects: false } },
      { id: 'prb', role: 'probe', description: 'probe', request: { origin, method: 'GET', pathAndQuery: '/api/invoices/inv_1', persona: 'member_b', followRedirects: false } },
    ],
    ...overrides,
  } as unknown as DeclarativeReplaySpec)

  const broker = new RequestBroker({ rejectUnauthorized: false })
  const backend = new LocalJqBackend()
  const grant = makeAuthGrant(origin)

  // (1) Drifted session (authenticated probe returns 401) -> inconclusive / session_drifted
  probeStatus = 401
  const drifted = await retestReplaySpec({ spec: makeSpec(), broker, backend, grant, signal: AbortSignal.timeout(10_000) })
  assert.equal(drifted.verdict, 'inconclusive')
  assert.equal((drifted.replay.evidencePayload.retestHealth as RetestHealthAssessment).failureReason, 'session_drifted')

  // (2) Unhealthy probe (500 and 429) -> inconclusive / probe_unhealthy
  for (const st of [500, 429, 302] as const) {
    probeStatus = st
    const res = await retestReplaySpec({ spec: makeSpec(), broker, backend, grant, signal: AbortSignal.timeout(10_000) })
    assert.equal(res.verdict, 'inconclusive', `probe HTTP ${st} must never be fixed`)
    assert.equal((res.replay.evidencePayload.retestHealth as RetestHealthAssessment).failureReason, 'probe_unhealthy')
  }

  // (3) Unbuildable receipt (CWE-0 / category='other') even with clean 403 probe -> inconclusive / receipt_unbuildable
  probeStatus = 403
  const unbuildable = await retestReplaySpec({
    spec: makeSpec({ cwe: 'CWE-0', category: 'other', title: 'Generic endpoint behavior', impact: 'Response observed.' }),
    broker, backend, grant, signal: AbortSignal.timeout(10_000),
  })
  assert.equal(unbuildable.verdict, 'inconclusive')
  assert.equal((unbuildable.replay.evidencePayload.retestHealth as RetestHealthAssessment).failureReason, 'receipt_unbuildable')

  // (4) Genuine clean fix (200 owner, 403 viewer, 403 member_b, valid receipt class) -> fixed / claim_not_reproduced
  probeStatus = 403
  controlStatus = 200
  const fixed = await retestReplaySpec({ spec: makeSpec(), broker, backend, grant, signal: AbortSignal.timeout(10_000) })
  assert.equal(fixed.verdict, 'fixed', fixed.replay.outcome.reason ?? '')
  const fixedHealth = fixed.replay.evidencePayload.retestHealth as RetestHealthAssessment
  assert.equal(fixedHealth.healthy, true)
  assert.equal(fixedHealth.failureReason, 'claim_not_reproduced')
})

test('R2-04: agent-script engine splits oracle_failed into typed reasons and maps unbuildable/composite/drifted to inconclusive, clean fix to fixed', async (t) => {
  let mode: 'unbuildable' | 'drifted' | 'probe_500' | 'clean_fix' = 'unbuildable'
  const server = createServer((req, res) => {
    req.resume()
    res.setHeader('content-type', 'application/json')
    const auth = req.headers.authorization ?? ''
    if (req.url === '/api/inbox/alert-1/read') {
      res.statusCode = 200
      res.end(JSON.stringify({ id: 'alert-1', read: true }))
      return
    }
    if (auth === 'Bearer tok-owner-a') {
      res.statusCode = 200
      res.end(JSON.stringify({ id: 'inv_1', owner_id: 'owner_a', tenant_id: 'tenant-a', email: 'a@tenant-a.example' }))
      return
    }
    if (auth === 'Bearer tok-viewer-b') {
      res.statusCode = 403
      res.end(JSON.stringify({ error: 'forbidden' }))
      return
    }
    if (mode === 'drifted') {
      res.statusCode = 401
      res.end(JSON.stringify({ error: 'expired token' }))
      return
    }
    if (mode === 'probe_500') {
      res.statusCode = 500
      res.end(JSON.stringify({ error: 'internal server error' }))
      return
    }
    res.statusCode = 403
    res.end(JSON.stringify({ error: 'forbidden' }))
  })
  server.listen(0, '127.0.0.1')
  await once(server, 'listening')
  const origin = `http://127.0.0.1:${(server.address() as { port: number }).port}`
  t.after(async () => {
    server.closeAllConnections()
    await new Promise<void>(r => server.close(() => r()))
  })

  const broker = new RequestBroker({ rejectUnauthorized: false })
  const grant = makeAuthGrant(origin)

  const backend = makeFakeBackend(async ({ req, nonce, rpc }) => {
    if (mode === 'unbuildable') {
      const ctl = await rpc('http', { origin, method: 'POST', path: '/api/inbox/alert-1/read', persona: 'owner_a', sessionGroupRole: 'control', headers: { 'content-type': 'application/json' }, body: '{"read":true}' })
      const prb = await rpc('http', { origin, method: 'POST', path: '/api/inbox/alert-1/read', persona: 'member_b', sessionGroupRole: 'probe', headers: { 'content-type': 'application/json' }, body: '{"read":true}' })
      return {
        runtime: req.runtime, exitCode: 0, stdout: '', stderr: '', durationMs: 5, timedOut: false,
        result: {
          nonce, title: 'Mutating boundary without readback',
          claims: [{ kind: 'boundary', boundaryClass: 'access', controlExchangeId: String(ctl.result!.exchangeId), probeExchangeId: String(prb.result!.exchangeId), resourceTenant: 'tenant-a' }],
        },
      }
    }
    const ctl = await rpc('http', { origin, method: 'GET', path: '/api/invoices/inv_1', persona: 'owner_a', sessionGroupRole: 'control' })
    const denied = await rpc('http', { origin, method: 'GET', path: '/api/invoices/inv_1', persona: 'viewer_b', sessionGroupRole: 'control' })
    const prb = await rpc('http', { origin, method: 'GET', path: '/api/invoices/inv_1', persona: 'member_b', sessionGroupRole: 'probe' })
    return {
      runtime: req.runtime, exitCode: 0, stdout: '', stderr: '', durationMs: 5, timedOut: false,
      result: {
        nonce, title: 'Cross-tenant invoice read',
        claims: [{ kind: 'impact', impactClass: 'authorization', probeExchangeId: String(prb.result!.exchangeId), controlExchangeIds: [String(ctl.result!.exchangeId), String(denied.result!.exchangeId)], resourceTenant: 'tenant-a' }],
      },
    }
  })

  const script = '// r2-04 test script\nexport default async () => ({})\n'
  const envelope = {
    kind: 'agent_script' as const,
    runtime: 'ts' as const,
    script,
    scriptSha256: sha256(script),
    verdict: 'confirmed' as const,
    exchangeIds: ['orig-1'],
    vulnClass: 'bola',
    transcriptDigests: [],
    confirmedAt: Date.now(),
  }

  // (a) Unbuildable receipt -> runAgentScriptProof emits 'receipt_unbuildable', retest returns 'inconclusive'
  mode = 'unbuildable'
  const unbuildableProof = await runAgentScriptProof({
    script, runtime: 'ts', broker, grant, backend, runId: 'r204-u', assignmentId: 'a-u', targetOrigins: [origin], signal: AbortSignal.timeout(10_000),
  })
  assert.equal(unbuildableProof.verdict.confirmed, false)
  assert.equal(unbuildableProof.verdict.reason, 'receipt_unbuildable')
  const unbuildableRetest = await retestPersistedAgentScript(envelope, {
    spec: { origin, agentScript: envelope }, origin, broker, grant, backend, runId: 'r204-u2', assignmentId: 'a-u2', signal: AbortSignal.timeout(10_000),
  })
  assert.equal(unbuildableRetest.verdict, 'inconclusive')
  assert.equal(unbuildableRetest.replay.verdict, 'inconclusive')
  assert.equal((unbuildableRetest.replay.evidencePayload.retestHealth as RetestHealthAssessment).failureReason, 'receipt_unbuildable')

  // (b) Drifted session (401) -> runAgentScriptProof emits 'session_drifted', retest returns 'inconclusive'
  mode = 'drifted'
  const driftedProof = await runAgentScriptProof({
    script, runtime: 'ts', broker, grant, backend, runId: 'r204-d', assignmentId: 'a-d', targetOrigins: [origin], signal: AbortSignal.timeout(10_000),
  })
  assert.equal(driftedProof.verdict.reason, 'session_drifted')
  const driftedRetest = await retestPersistedAgentScript(envelope, {
    spec: { origin, agentScript: envelope }, origin, broker, grant, backend, runId: 'r204-d2', assignmentId: 'a-d2', signal: AbortSignal.timeout(10_000),
  })
  assert.equal(driftedRetest.verdict, 'inconclusive')
  assert.equal((driftedRetest.replay.evidencePayload.retestHealth as RetestHealthAssessment).failureReason, 'session_drifted')

  // (c) Probe 500 -> retest returns 'inconclusive' with probe_unhealthy (never fixed)
  mode = 'probe_500'
  const errRetest = await retestPersistedAgentScript(envelope, {
    spec: { origin, agentScript: envelope }, origin, broker, grant, backend, runId: 'r204-500', assignmentId: 'a-500', signal: AbortSignal.timeout(10_000),
  })
  assert.equal(errRetest.verdict, 'inconclusive')
  assert.equal((errRetest.replay.evidencePayload.retestHealth as RetestHealthAssessment).failureReason, 'probe_unhealthy')

  // (d) Genuine clean fix -> runAgentScriptProof emits 'claim_not_reproduced', retest returns 'fixed'
  mode = 'clean_fix'
  const cleanProof = await runAgentScriptProof({
    script, runtime: 'ts', broker, grant, backend, runId: 'r204-f', assignmentId: 'a-f', targetOrigins: [origin], signal: AbortSignal.timeout(10_000),
  })
  assert.equal(cleanProof.verdict.reason, 'claim_not_reproduced')
  const cleanRetest = await retestPersistedAgentScript(envelope, {
    spec: { origin, agentScript: envelope }, origin, broker, grant, backend, runId: 'r204-f2', assignmentId: 'a-f2', signal: AbortSignal.timeout(10_000),
  })
  assert.equal(cleanRetest.verdict, 'fixed', cleanRetest.replay.outcome.reason ?? '')
  assert.equal(cleanRetest.replay.verdict, 'dismissed')
  assert.equal((cleanRetest.replay.evidencePayload.retestHealth as RetestHealthAssessment).healthy, true)
  assert.equal((cleanRetest.replay.evidencePayload.retestHealth as RetestHealthAssessment).failureReason, 'claim_not_reproduced')

  // (e) Direct check: buildAgentScriptRetestInputs + assessRetestHealth rejects composite_stage_rejected
  const compInputs = buildAgentScriptRetestInputs({
    confirmed: false,
    verdictReason: 'composite_stage_rejected',
    verdictDetail: 'CompositeProofReceipt rejected at stage edge_binding',
    attempts: [{ exitCode: 0, signaturesValid: true, nonceMismatch: false, oraclePassed: false }],
    exchanges: [],
    compositeRejectedStage: 'edge_binding',
  })
  const compHealth = assessRetestHealth(compInputs.baseline, compInputs.probeArms, compInputs.session)
  assert.equal(compHealth.healthy, false)
  assert.equal(compHealth.failureReason, 'composite_stage_rejected')
})

test('R2-04: floor retestPersistedRecipe returns inconclusive with session_drifted on expired auth token and fixed on clean 403', async () => {
  const origin = 'http://127.0.0.1:4599'
  const grant = makeAuthGrant(origin)
  const runWith = async (statuses: readonly number[]) => {
    let idx = 0
    const broker = new RequestBroker({
      transport: async () => {
        const status = statuses[idx++] ?? 500
        return {
          status,
          headers: { 'content-type': 'application/json' },
          body: status === 200 ? '{"id":"inv_1","owner_id":"owner_a","email":"a@tenant-a.example"}' : '{"error":"nope"}',
        }
      },
    })
    return retestPersistedRecipe({
      envelope: {
        recipeId: 'access_boundary',
        args: {
          origin,
          method: 'GET',
          pathAndQuery: '/api/invoices/inv_1',
          vulnClass: 'bola',
          owner: { handle: 'owner_a', role: 'owner', tenant: 'tenant-a' },
          denied: { handle: 'viewer_b', role: 'viewer', tenant: 'tenant-b' },
          probe: { handle: 'member_b', role: 'member', tenant: 'tenant-b' },
        },
      },
      specKind: 'http_chain',
      vulnClass: 'bola',
      endpoint: '/api/invoices/inv_1',
      origin,
      broker,
      grant,
      signal: AbortSignal.timeout(5_000),
    })
  }

  const drifted = await runWith([200, 403, 401])
  assert.equal(drifted.verdict, 'inconclusive')
  assert.equal((drifted.replay.evidencePayload.retestHealth as RetestHealthAssessment).failureReason, 'session_drifted')

  const fixed = await runWith([200, 403, 403])
  assert.equal(fixed.verdict, 'fixed')
  assert.equal((fixed.replay.evidencePayload.retestHealth as RetestHealthAssessment).failureReason, 'claim_not_reproduced')
})

test('R2-04 / R3-01e: declarative auth_bypass (CWE-287) retest rejects 503, 404, 302, and marker-drifted 200 probes as inconclusive; allows clean 401/403 fix', async (t) => {
  let probeStatus = 401
  const server = createServer((req, res) => {
    req.resume()
    res.setHeader('content-type', 'application/json')
    const hasSubreq = Boolean(req.headers['x-middleware-subrequest'])
    const status = hasSubreq ? probeStatus : 401
    res.statusCode = status
    res.end(JSON.stringify({ status, error: status === 200 ? undefined : `status-${status}` }))
  })
  server.listen(0, '127.0.0.1')
  await once(server, 'listening')
  const origin = `http://127.0.0.1:${(server.address() as { port: number }).port}`
  t.after(async () => {
    server.closeAllConnections()
    await new Promise<void>(r => server.close(() => r()))
  })

  const spec: DeclarativeReplaySpec = {
    version: 1,
    kind: 'http_chain',
    origin,
    title: 'Middleware auth bypass (CWE-287)',
    category: 'auth-bypass',
    cwe: 'CWE-287',
    severity: 'critical',
    severityRationale: 'Direct authentication bypass.',
    impact: 'Bypasses middleware authentication gate.',
    remediation: 'Strip untrusted internal middleware headers at the edge.',
    recheckInstructions: 'Replay.',
    assertionsJq: '{ controlPassed: (.steps.ctl.status == 401), confirmed: (.steps.prb.status == 200 and (.steps.prb.body | contains("admin_secret"))), observed: (.steps.prb.status | tostring), expected: "401" }',
    steps: [
      { id: 'ctl', role: 'control', description: 'unauth control', request: { origin, method: 'GET', pathAndQuery: '/api/admin/audit-log', followRedirects: false } },
      { id: 'prb', role: 'probe', description: 'header-spoofed probe', request: { origin, method: 'GET', pathAndQuery: '/api/admin/audit-log', headers: { 'x-middleware-subrequest': 'middleware:middleware:middleware:middleware:middleware' }, followRedirects: false } },
    ],
  } as unknown as DeclarativeReplaySpec

  const broker = new RequestBroker({ rejectUnauthorized: false })
  const backend = new LocalJqBackend()
  const grant = makeLabGrant(origin, { tier: 1 })

  // Drifted/unhealthy probes (503, 404, 302) and still-bypassed marker-drifted 200 MUST be inconclusive, NEVER fixed.
  for (const st of [503, 404, 302, 200] as const) {
    probeStatus = st
    const res = await retestReplaySpec({ spec, broker, backend, grant, signal: AbortSignal.timeout(10_000) })
    assert.equal(res.verdict, 'inconclusive', `CWE-287 auth_bypass probe HTTP ${st} must never be fixed`)
    const health = res.replay.evidencePayload.retestHealth as RetestHealthAssessment
    assert.equal(health.healthy, false)
    assert.notEqual(health.failureReason, 'claim_not_reproduced')
  }

  // Direct assessDeclarativeRetestHealth check: even when 404 is explicitly expected (bypassing requireControlNonError),
  // auth_bypass must reject 404 as route drift rather than definitive auth enforcement.
  const direct404 = assessDeclarativeRetestHealth(
    spec,
    {
      verdict: 'dismissed',
      outcome: { confirmed: false, controlPassed: true },
      evidencePayload: {
        boundaryGate: { required: true, satisfied: false, boundaryClass: 'auth' },
        steps: {
          ctl: { id: 'ctl', role: 'control', status: 401 },
          prb: { id: 'prb', role: 'probe', status: 404 },
        },
      },
    },
    { receiptBuildable: true },
  )
  assert.equal(direct404.healthy, false)
  assert.equal(direct404.code, 'access_probe_not_denied')
  assert.equal(direct404.failureReason, 'probe_unhealthy')

  // Clean remediation (401 and 403) MUST return fixed with claim_not_reproduced.
  for (const st of [401, 403] as const) {
    probeStatus = st
    const res = await retestReplaySpec({ spec, broker, backend, grant, signal: AbortSignal.timeout(10_000) })
    assert.equal(res.verdict, 'fixed', `CWE-287 auth_bypass probe HTTP ${st} must be fixed: ${res.replay.outcome.reason ?? ''}`)
    const health = res.replay.evidencePayload.retestHealth as RetestHealthAssessment
    assert.equal(health.healthy, true)
    assert.equal(health.failureReason, 'claim_not_reproduced')
  }
})
