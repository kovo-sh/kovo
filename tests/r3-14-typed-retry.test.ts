/**
 * R3-14: Host decisions switch on typed codes stored where they are produced,
 * and one RetryGovernor honours the run's budgets.
 *
 * Covers:
 *   1. Real wall-clock exhaustion enforcement across `RetryGovernor`, `ExecWorkerRunner`
 *      (both transient provider retries and stall retries), and `ExecReconPlanner`.
 *   2. Persisted typed `failureKind` next to `lastError` in `model-settings.ts` and
 *      typed-only `evaluateRoleProviderCircuit` in `provider.ts` — truncated/redacted
 *      auth & quota outages still trip `provider_paused` with zero `model_failure` cascade.
 *   3. Fail-safe default in `agent-script-proof.ts` / `classifyAgentScriptOracleFailure` —
 *      unrecognized/unhealthy/empty-claim failures fail closed to inconclusive, NEVER `fixed`.
 *   4. Typed `OracleFailureCode` switching in `retest-health.ts` — wording changes in
 *      `verification.reason` preserve verdicts; unknown/missing codes fail closed.
 *   5. Single disposer-registered `RetryGovernor` sharing per-run caps across all three retry
 *      paths (`provider_transient`, `provider_stall`, `step_requeue`) and transport backoff.
 *   6. TypeScript AST decision-module prose-regex guard (zero regexes over `reason`,
 *      `lastError`, `message`, or `summary` in decision modules; zero `wallClockExhausted: false`;
 *      zero duplicate per-run retry maps in worker/planner).
 */
import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { once } from 'node:events'
import { readFileSync } from 'node:fs'
import { createServer, request as httpRequest } from 'node:http'
import { join, resolve } from 'node:path'
import test from 'node:test'
import { eq } from 'drizzle-orm'
import ts from 'typescript'

import { RequestBroker, type Grant } from '../src/server/broker.ts'
import { resolveAssignmentBudget } from '../src/server/exec-dispatch.ts'
import type { ExecActiveJob } from '../src/server/exec-exchange.ts'
import type { ExecReconPlanner } from '../src/server/exec-recon-planner.ts'
import type { ExecWorkerRunner } from '../src/server/exec-worker-runner.ts'
import { Execution } from '../src/server/execution.ts'
import type { FloorRecipeExecution } from '../src/server/floor-recipes.ts'
import {
  privateModelProfiles,
  recordProfileFailure,
  recordProfileSuccess,
  saveModelProfile,
} from '../src/server/model-settings.ts'
import {
  ProviderFailureError,
  QuotaExhaustedError,
  classifyProviderFailure,
  evaluateRoleProviderCircuit,
} from '../src/server/provider.ts'
import { verifyReceipt } from '../src/server/proof-receipt.ts'
import { retestPersistedAgentScript, runAgentScriptProof } from '../src/server/replay-verifier.ts'
import {
  classifyAgentScriptOracleFailure,
  classifyRetestHealth,
  type RetestHealthAssessment,
} from '../src/server/retest-health.ts'
import {
  RetryGovernor,
  computeProviderRetryBackoffMs,
  defaultRetryGovernor,
  isPositiveRemediationOracleCode,
  isRunWallClockExhausted,
  isTypedOracleRemediationCode,
  noteLatestProviderFailureForProfile,
  shouldRetryProviderTransport,
  type OracleFailureCode,
} from '../src/server/retry-governor.ts'
import { runAllRunDisposers } from '../src/server/run-disposers.ts'
import { events } from '../src/server/schema.ts'
import type { VerifyScriptRequest, VerifyScriptResult, WorkerBackend, WorkerSession, WorkerSessionOptions } from '../src/server/worker-backend.ts'
import {
  VERIFY_NONCE_HEADER,
  VERIFY_RPC_CONTEXT_NAME,
  VERIFY_RPC_HEADER,
  VERIFY_RPC_SOCKET_NAME,
  VERIFY_RPC_TOKEN_NAME,
} from '../src/server/verify-rpc.ts'
import { makeLabGrant, makeStore, setupApprovedRun } from './v4-tier-helpers.ts'

process.env.KOVO_ALLOW_LOCAL_LAB = '1'
process.env.KOVO_ALLOW_LOCAL_MODEL = '1'

const ORIGIN = 'https://r3-14-typed-retry.example.invalid'

function stubBackend(): WorkerBackend {
  return {
    async run() { return { exitCode: 0, stdout: '{}', stderr: '', outputs: {} } },
    async verifyStaticAst(_aid, req) {
      return {
        verified: false, engine: req.engine, repo: req.repo, file: req.file,
        startLine: req.startLine, endLine: req.endLine, matchedLines: [],
        codeExcerpt: '', matchCount: 0, durationMs: 1,
      }
    },
    async openSession(): Promise<WorkerSession> {
      return {
        stage: async name => `/evidence/${name}`,
        exec: async () => ({ exitCode: 0, stdout: '', stderr: '', outputs: {} }),
        analyze: async () => ({ ok: true }),
        sast: async req => ({ repo: req.repo, enginesRun: [], engineStatus: {}, findings: [], totalFindings: 0, truncated: false, durationMs: 1 }),
        runScript: async req => ({ runtime: req.runtime, exitCode: 0, stdout: '', stderr: '', durationMs: 1, timedOut: false }),
        verifyStaticAst: async req => ({
          verified: false, engine: req.engine, repo: req.repo, file: req.file,
          startLine: req.startLine, endLine: req.endLine, matchedLines: [],
          codeExcerpt: '', matchCount: 0, durationMs: 1,
        }),
        close: async () => undefined,
      }
    },
  }
}

function internals(engine: Execution) {
  return engine as unknown as {
    workerRunner: ExecWorkerRunner
    reconPlanner: ExecReconPlanner
    active: Map<string, ExecActiveJob>
  }
}

function sha256(s: string): string {
  return createHash('sha256').update(s, 'utf8').digest('hex')
}

function makeAuthGrant(origin: string): Grant {
  const personas = new Map([
    ['owner_a', {
      id: 'p-owner-a', handle: 'owner_a', roleLabel: 'owner (tenant-a)',
      originAllowlist: [origin], authKind: 'bearer' as const, headerName: 'Authorization', secret: 'tok-owner-a', canaryMarkers: [],
    }],
    ['viewer_b', {
      id: 'p-viewer-b', handle: 'viewer_b', roleLabel: 'viewer (tenant-b)',
      originAllowlist: [origin], authKind: 'bearer' as const, headerName: 'Authorization', secret: 'tok-viewer-b', canaryMarkers: [],
    }],
    ['member_b', {
      id: 'p-member-b', handle: 'member_b', roleLabel: 'member (tenant-b)',
      originAllowlist: [origin], authKind: 'bearer' as const, headerName: 'Authorization', secret: 'tok-member-b', canaryMarkers: [],
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

function makeScriptBackend(
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

// ============================================================================
// 1. Real wall-clock exhaustion enforcement in ExecWorkerRunner & RetryGovernor
// ============================================================================

test('R3-14.1: exhausted run wall clock blocks transient provider retries AND stall retries in ExecWorkerRunner', async t => {
  const { storage } = makeStore(t, 'kovo-r314-wallclock-')
  const { runId, run } = await setupApprovedRun(storage, { seeds: [ORIGIN], tier: 2 })
  const asset = run.candidates.find(c => run.approved.includes(c.id))!

  // Backdate run.createdAt so maxDurationMs=5_000 is already exhausted.
  storage.client.prepare('update runs set created_at = ? where id = ?').run(Date.now() - 30_000, runId)
  storage.updateRun(runId, { status: 'running', phase: 'investigation' })
  const expiredRun = storage.run(runId)

  const engine = new Execution(storage, { backend: stubBackend(), maxDurationMs: 5_000 })
  t.after(() => engine.stop())
  const { workerRunner, active } = internals(engine)
  const budget = resolveAssignmentBudget(
    { title: 'Probe /api/orders', hypothesis: 'Check GET /api/orders', category: 'broken-access-control' },
    { baseMaxTurns: 10, baseWallClockMs: 60_000, runDurationMs: 5_000, singleStepWallClockMs: 60_000 },
  )

  // (a) Transient 429 provider failure MUST NOT retry when wall clock is exhausted.
  const s429 = storage.addChainStep(expiredRun, {
    title: 'Expired wall-clock 429 step',
    hypothesis: 'Check GET /api/orders',
    category: 'broken-access-control',
    targetAssetIds: [asset.id],
    sourceOrigins: [ORIGIN],
  })
  storage.updateChainStep(s429.id, { status: 'running' })
  const w429 = storage.updateWorker(
    storage.makeWorker(expiredRun, 'investigation', asset, s429.title, s429.hypothesis, { stepId: s429.id, sourceOrigins: [ORIGIN] }).id,
    { status: 'running', attempt: 0, lease: 'lease-wc-429', leaseExpiresAt: Date.now() + 60_000 },
  )!
  const job429: ExecActiveJob = { assignment: w429, origins: new Set([ORIGIN]), controller: new AbortController() }
  active.set(w429.id, job429)

  workerRunner.handleInvestigationWorkerError(
    expiredRun,
    job429,
    s429,
    'bola-bfla-specialist',
    budget,
    new ProviderFailureError('Rate limited', { kind: 'rate_limited', status: 429, emitted: false }),
  )

  const stepAfter429 = storage.listChainSteps(runId).find(s => s.id === s429.id)!
  assert.equal(stepAfter429.status, 'model_failure', 'exhausted wall clock must prevent transient retry')
  assert.equal(stepAfter429.skills.includes('r213:provider_retry:1'), false)

  // (b) Stall abort MUST ALSO honour exhausted wall clock through the single RetryGovernor.
  const sStall = storage.addChainStep(expiredRun, {
    title: 'Expired wall-clock stall step',
    hypothesis: 'Check GET /api/invoices',
    category: 'broken-access-control',
    targetAssetIds: [asset.id],
    sourceOrigins: [ORIGIN],
  })
  storage.updateChainStep(sStall.id, { status: 'running' })
  const wStall = storage.updateWorker(
    storage.makeWorker(expiredRun, 'investigation', asset, sStall.title, sStall.hypothesis, { stepId: sStall.id, sourceOrigins: [ORIGIN] }).id,
    { status: 'running', attempt: 0, lease: 'lease-wc-stall', leaseExpiresAt: Date.now() + 60_000 },
  )!
  const jobStall: ExecActiveJob = { assignment: wStall, origins: new Set([ORIGIN]), controller: new AbortController(), stallAbort: true }
  active.set(wStall.id, jobStall)

  workerRunner.handleInvestigationWorkerError(
    expiredRun,
    jobStall,
    sStall,
    'bola-bfla-specialist',
    budget,
    new Error('stream stalled'),
    { noToolCallExecuted: true },
  )

  const stepAfterStall = storage.listChainSteps(runId).find(s => s.id === sStall.id)!
  assert.equal(stepAfterStall.status, 'model_failure', 'exhausted wall clock must prevent stall retry')
  const retryEvents = storage.db.select().from(events).where(eq(events.runId, runId)).all()
    .filter(e => e.kind === 'worker.provider_retry' || e.kind === 'worker.stall_retry')
  assert.equal(retryEvents.length, 0, 'zero retry events may fire after wall-clock exhaustion')
})

// ============================================================================
// 2. Persisted failureKind survives truncation/redaction & trips provider_paused
// ============================================================================

test('R3-14.2: truncated & redacted auth/quota outage still trips provider_paused via persisted failureKind', async t => {
  const { storage } = makeStore(t, 'kovo-r314-circuit-')
  const { runId, run } = await setupApprovedRun(storage, { seeds: [ORIGIN], tier: 2 })
  const asset = run.candidates.find(c => run.approved.includes(c.id))!

  const saved = await saveModelProfile({
    name: 'Truncated Outage Profile',
    endpoint: 'http://127.0.0.1:18089/v1',
    model: 'fixture-model',
    protocol: 'responses',
    key: 'fixture-key-secret-99999',
    priority: 100,
    roleAffinity: 'any',
  }, storage, { skipConnectionCheck: true })

  // Long (>350 chars) noise prefix followed by the real 401 auth error at the tail.
  // After redact().slice(0, 300), `lastError` contains ZERO auth keywords!
  const longNoisePrefix = `Upstream gateway diagnostic payload: ${'x'.repeat(340)} | `
  const fullAuthMessage = `${longNoisePrefix}HTTP 401 unauthorized invalid_api_key Bearer sk-live-secret-token`
  recordProfileFailure(saved.id, fullAuthMessage, true, storage)

  const loadedAuth = privateModelProfiles(storage)
  assert.equal(loadedAuth.length, 1)
  assert.equal(classifyProviderFailure(loadedAuth[0]!.lastError ?? ''), null, 'truncated lastError prose alone cannot be re-classified')
  assert.equal(loadedAuth[0]!.failureKind, 'auth', 'persisted failureKind must preserve auth across truncation/redaction')
  assert.equal(loadedAuth[0]!.failureHard, true)

  const authCircuit = evaluateRoleProviderCircuit(loadedAuth)
  assert.equal(authCircuit.hardOpen, true)
  assert.equal(authCircuit.kind, 'auth')
  assert.deepEqual(authCircuit.profileIds, [saved.id])

  // Success clears persisted failureKind.
  recordProfileSuccess(saved.id, storage)
  const afterRecovery = privateModelProfiles(storage)
  assert.equal(afterRecovery[0]!.failureKind, null)
  assert.equal(evaluateRoleProviderCircuit(afterRecovery).hardOpen, false)

  // Typed handoff from providerPool with generic redacted prose still persists quota and pauses run.
  noteLatestProviderFailureForProfile(saved.id, { kind: 'quota', hard: true, status: 402, recordedAt: Date.now() })
  recordProfileFailure(saved.id, '[redacted upstream failure summary]', true, storage)

  const loadedQuota = privateModelProfiles(storage)
  assert.equal(loadedQuota[0]!.failureKind, 'quota')
  assert.equal(classifyProviderFailure(loadedQuota[0]!.lastError ?? ''), null)
  const quotaCircuit = evaluateRoleProviderCircuit(loadedQuota)
  assert.equal(quotaCircuit.hardOpen, true)
  assert.equal(quotaCircuit.kind, 'quota')

  storage.updateRun(runId, { status: 'running', phase: 'investigation' })
  const activeRun = storage.run(runId)
  const s1 = storage.addChainStep(activeRun, {
    title: 'Step hitting redacted quota outage',
    hypothesis: 'Probe GET /api/billing',
    category: 'broken-access-control',
    targetAssetIds: [asset.id],
    sourceOrigins: [ORIGIN],
  })
  storage.updateChainStep(s1.id, { status: 'running' })
  const w1 = storage.updateWorker(
    storage.makeWorker(activeRun, 'investigation', asset, s1.title, s1.hypothesis, { stepId: s1.id, sourceOrigins: [ORIGIN] }).id,
    { status: 'running', lease: 'lease-r314-quota', leaseExpiresAt: Date.now() + 60_000 },
  )!
  const engine = new Execution(storage, { backend: stubBackend() })
  t.after(() => engine.stop())
  const { workerRunner, active } = internals(engine)
  const job1: ExecActiveJob = { assignment: w1, origins: new Set([ORIGIN]), controller: new AbortController() }
  active.set(w1.id, job1)

  workerRunner.handleInvestigationWorkerError(
    activeRun,
    job1,
    s1,
    'bola-bfla-specialist',
    resolveAssignmentBudget(
      { title: s1.title, hypothesis: s1.hypothesis, category: s1.category },
      { baseMaxTurns: 10, baseWallClockMs: 60_000, runDurationMs: 600_000, singleStepWallClockMs: 60_000 },
    ),
    new QuotaExhaustedError('[redacted]', { profileId: saved.id }),
  )

  assert.equal(storage.run(runId).status, 'paused', 'truncated/redacted outage must still trip provider_paused')
  assert.equal(storage.listChainSteps(runId).filter(s => s.status === 'model_failure').length, 0)
})

// ============================================================================
// 3. Fail-safe default in agent-script-proof.ts
// ============================================================================

test('R3-14.3: agent-script-proof fails closed on unclassified/empty-claim/unhealthy oracle failures instead of defaulting to claim_not_reproduced', async (t) => {
  // Pure unit checks for classifyAgentScriptOracleFailure
  assert.equal(
    classifyAgentScriptOracleFailure({
      hasCompositeFailure: false,
      drifted: false,
      hasCaptureWithClaims: false,
      receiptBuilt: false,
      attempts: [{ exitCode: 0, signaturesValid: true, nonceMismatch: false, oraclePassed: false }],
      exchanges: [],
    }),
    'receipt_unbuildable',
    'missing capture/claims must never default to claim_not_reproduced',
  )
  assert.equal(
    classifyAgentScriptOracleFailure({
      hasCompositeFailure: false,
      drifted: false,
      hasCaptureWithClaims: true,
      receiptBuilt: true,
      verdictReason: 'oracle_failed',
      oracleFailureCode: 'remediation_access_denied',
      attempts: [{ exitCode: 1, signaturesValid: true, nonceMismatch: false, oraclePassed: false }],
      exchanges: [
        { exchangeId: 'c1', origin: ORIGIN, method: 'GET', pathAndQuery: '/a', status: 200, body: '{}', sessionRole: 'control', personaHandle: 'owner_a' },
        { exchangeId: 'p1', origin: ORIGIN, method: 'GET', pathAndQuery: '/a', status: 403, body: '{}', sessionRole: 'probe', personaHandle: 'member_b' },
      ],
      vulnClass: 'bola',
    }),
    'baseline_unhealthy',
    'non-zero script exit must fail closed',
  )
  // F1 & F2 regression guard: healthy authenticated 200 control + 403 probe + built receipt (rule != none),
  // but NO positive remediation OracleFailureCode (structural rejection / oracle_disagreement / omitted)
  // MUST fail closed to receipt_unbuildable / probe_unhealthy — NEVER claim_not_reproduced/fixed!
  const healthyBolaExchanges = [
    { exchangeId: 'c1', origin: ORIGIN, method: 'GET', pathAndQuery: '/a', status: 200, body: '{}', sessionRole: 'control' as const, personaHandle: 'owner_a' },
    { exchangeId: 'p1', origin: ORIGIN, method: 'GET', pathAndQuery: '/a', status: 403, body: '{}', sessionRole: 'probe' as const, personaHandle: 'member_b' },
  ]
  const cleanAttempt = [{ exitCode: 0, signaturesValid: true, nonceMismatch: false, oraclePassed: false }]
  assert.equal(
    classifyAgentScriptOracleFailure({
      hasCompositeFailure: false, drifted: false, hasCaptureWithClaims: true, receiptBuilt: true,
      verdictReason: 'oracle_failed', oracleFailureCode: 'oracle_disagreement', rejectedByReceipt: true,
      attempts: cleanAttempt, exchanges: healthyBolaExchanges, vulnClass: 'bola',
    }),
    'receipt_unbuildable',
    'F1: structural receipt rejection with healthy arms must stay receipt_unbuildable, never claim_not_reproduced',
  )
  assert.equal(
    classifyAgentScriptOracleFailure({
      hasCompositeFailure: false, drifted: false, hasCaptureWithClaims: true, receiptBuilt: true,
      verdictReason: 'oracle_failed', oracleFailureCode: null, rejectedByReceipt: true,
      attempts: cleanAttempt, exchanges: healthyBolaExchanges, vulnClass: 'bola',
    }),
    'receipt_unbuildable',
    'F1: missing oracleFailureCode on receipt rejection with healthy arms must fail closed',
  )
  assert.equal(
    classifyAgentScriptOracleFailure({
      hasCompositeFailure: false, drifted: false, hasCaptureWithClaims: true, receiptBuilt: true,
      verdictReason: 'oracle_failed', oracleFailureCode: null, rejectedByReceipt: false,
      attempts: cleanAttempt, exchanges: healthyBolaExchanges, vulnClass: 'bola',
    }),
    'probe_unhealthy',
    'F2: oracle_failed with healthy arms and no positive remediation code must fail closed',
  )
  assert.equal(
    classifyAgentScriptOracleFailure({
      hasCompositeFailure: false, drifted: false, hasCaptureWithClaims: true, receiptBuilt: true,
      verdictReason: 'oracle_failed', oracleFailureCode: 'remediation_access_denied', rejectedByReceipt: false,
      attempts: cleanAttempt, exchanges: healthyBolaExchanges, vulnClass: 'bola',
    }),
    'claim_not_reproduced',
    'positive host remediation code plus healthy arms emits claim_not_reproduced',
  )

  // Live runAgentScriptProof + retestPersistedAgentScript checks
  let probeStatus = 403
  const server = createServer((req, res) => {
    req.resume()
    res.setHeader('content-type', 'application/json')
    const auth = req.headers.authorization ?? ''
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
    res.statusCode = probeStatus
    res.end(JSON.stringify({ error: `status-${probeStatus}` }))
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
  const script = '// r3-14 fail-safe test\nexport default async () => ({})\n'
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

  // (a) Script emits 0 claims despite 200/403 HTTP exchanges -> receipt_unbuildable (never claim_not_reproduced/fixed)
  const zeroClaimsBackend = makeScriptBackend(async ({ req, nonce, rpc }) => {
    await rpc('http', { origin, method: 'GET', path: '/api/invoices/inv_1', persona: 'owner_a', sessionGroupRole: 'control' })
    await rpc('http', { origin, method: 'GET', path: '/api/invoices/inv_1', persona: 'member_b', sessionGroupRole: 'probe' })
    return {
      runtime: req.runtime, exitCode: 0, stdout: '', stderr: '', durationMs: 5, timedOut: false,
      result: { nonce, title: 'Zero claims retest', claims: [] },
    }
  })
  const zeroProof = await runAgentScriptProof({
    script, runtime: 'ts', broker, grant, backend: zeroClaimsBackend,
    runId: 'r314-z1', assignmentId: 'a-z1', targetOrigins: [origin], signal: AbortSignal.timeout(10_000),
  })
  assert.equal(zeroProof.verdict.confirmed, false)
  assert.equal(zeroProof.verdict.reason, 'claims_missing')
  const zeroRetest = await retestPersistedAgentScript(envelope, {
    spec: { origin, agentScript: envelope }, origin, broker, grant, backend: zeroClaimsBackend,
    runId: 'r314-z2', assignmentId: 'a-z2', signal: AbortSignal.timeout(10_000),
  })
  assert.equal(zeroRetest.verdict, 'inconclusive')
  assert.equal((zeroRetest.replay.evidencePayload.retestHealth as RetestHealthAssessment).failureReason, 'receipt_unbuildable')

  // (b) Script with valid claims hitting probe HTTP 500 -> runAgentScriptProof emits probe_unhealthy directly
  probeStatus = 500
  const probe500Backend = makeScriptBackend(async ({ req, nonce, rpc }) => {
    const ctl = await rpc('http', { origin, method: 'GET', path: '/api/invoices/inv_1', persona: 'owner_a', sessionGroupRole: 'control' })
    const denied = await rpc('http', { origin, method: 'GET', path: '/api/invoices/inv_1', persona: 'viewer_b', sessionGroupRole: 'control' })
    const prb = await rpc('http', { origin, method: 'GET', path: '/api/invoices/inv_1', persona: 'member_b', sessionGroupRole: 'probe' })
    return {
      runtime: req.runtime, exitCode: 0, stdout: '', stderr: '', durationMs: 5, timedOut: false,
      result: {
        nonce, title: 'BOLA probe 500',
        claims: [{ kind: 'impact', impactClass: 'authorization', probeExchangeId: String(prb.result!.exchangeId), controlExchangeIds: [String(ctl.result!.exchangeId), String(denied.result!.exchangeId)], resourceTenant: 'tenant-a' }],
      },
    }
  })
  const errProof = await runAgentScriptProof({
    script, runtime: 'ts', broker, grant, backend: probe500Backend,
    runId: 'r314-p500', assignmentId: 'a-p500', targetOrigins: [origin], signal: AbortSignal.timeout(10_000),
  })
  assert.equal(errProof.verdict.confirmed, false)
  assert.equal(errProof.verdict.reason, 'probe_unhealthy', 'probe 500 must fail closed in runAgentScriptProof itself')
})

// ============================================================================
// 4. Typed OracleFailureCode in retest-health.ts (wording-change invariant)
// ============================================================================

test('R3-14.4: classifyRetestHealth switches strictly on top-level host OracleFailureCode (immune to prose & forged evidence.failureCode) and proof-receipt emits real typed codes', () => {
  const makeExec = (
    recipeId: 'boolean_or_timing' | 'persisted_mutation' | 'conserved_balance',
    rule: 'boolean' | 'timing' | 'impact' | 'conserved_balance',
    reason: string,
    failureCode?: OracleFailureCode,
    extraEvidence?: Record<string, unknown>,
  ): FloorRecipeExecution => ({
    result: {
      recipeId,
      confirmed: false,
      steps: [
        { exchangeId: 'c1', role: 'benign_control', arm: 'control', method: 'GET', pathAndQuery: '/api/q', status: 200, durationMs: 5 },
        { exchangeId: 'p1', role: 'probe_request', arm: 'probe', method: 'GET', pathAndQuery: '/api/q', status: 200, durationMs: 5 },
      ],
      exchangeIds: ['c1', 'p1'],
      oobEventIds: [],
      transcript: { entries: [] },
      verification: {
        confirmed: false,
        vulnClass: 'sqli',
        rule,
        ...(failureCode ? { failureCode } : {}),
        reason,
        observed: '',
        expected: '',
        evidence: { ...(extraEvidence ?? {}) },
      },
    },
    receipt: { vulnClass: 'sqli', target: { origin: ORIGIN, method: 'GET', pathAndQuery: '/api/q' }, exchangeIds: ['c1', 'p1'], oobEventIds: [], browserTraceIds: [], claimedDelta: '' } as never,
    failure: { code: 'receipt_rejected', message: reason, missingRoles: [] },
  } as unknown as FloorRecipeExecution)

  const typedPairs: ReadonlyArray<{
    recipeId: 'boolean_or_timing' | 'persisted_mutation' | 'conserved_balance'
    rule: 'boolean' | 'timing' | 'impact' | 'conserved_balance'
    code: OracleFailureCode
    oldProse: string
  }> = [
    { recipeId: 'boolean_or_timing', rule: 'boolean', code: 'remediation_boolean_no_delta', oldProse: 'no structural response change' },
    { recipeId: 'boolean_or_timing', rule: 'timing', code: 'remediation_timing_no_separation', oldProse: 'not distinguishable delay' },
    { recipeId: 'persisted_mutation', rule: 'impact', code: 'remediation_mutation_idempotent', oldProse: 'identical to the baseline (idempotent no-op)' },
    { recipeId: 'conserved_balance', rule: 'conserved_balance', code: 'remediation_balance_conserved', oldProse: 'balance conserved within balance' },
  ]

  for (const pair of typedPairs) {
    assert.equal(isTypedOracleRemediationCode(pair.recipeId, pair.rule, pair.code), true)
    assert.equal(isPositiveRemediationOracleCode(pair.code), true)
    // Completely reworded prose with host top-level failureCode -> healthy / claim_not_reproduced!
    const reworded = classifyRetestHealth(
      makeExec(pair.recipeId, pair.rule, 'Arbitrary reworded diagnostic message #9981', pair.code),
    )
    assert.equal(reworded.healthy, true, `${pair.recipeId}/${pair.code} must remain healthy regardless of prose wording`)
    assert.equal(reworded.failureReason, 'claim_not_reproduced')

    // F3: Untrusted forged `evidence.failureCode` without top-level host `verification.failureCode` MUST FAIL CLOSED!
    const forgedEvidence = classifyRetestHealth(
      makeExec(pair.recipeId, pair.rule, pair.oldProse, undefined, { failureCode: pair.code }),
    )
    assert.equal(forgedEvidence.healthy, false, `${pair.recipeId} must ignore untrusted evidence.failureCode`)
    assert.equal(forgedEvidence.code, 'oracle_disagreement')
    assert.equal(forgedEvidence.failureReason, 'probe_unhealthy')

    // Unknown typed code -> FAILS CLOSED!
    const unknownCode = classifyRetestHealth(
      makeExec(pair.recipeId, pair.rule, pair.oldProse, 'oracle_disagreement'),
    )
    assert.equal(unknownCode.healthy, false)
    assert.equal(unknownCode.code, 'oracle_disagreement')
  }

  // Typed composite stage rejection works regardless of prose wording.
  const compTyped = classifyRetestHealth(
    makeExec('persisted_mutation', 'impact', 'Reworded opaque rejection text', 'composite_stage_rejected', { failedStage: 'edge_binding' }),
  )
  assert.equal(compTyped.healthy, false)
  assert.equal(compTyped.failureReason, 'composite_stage_rejected')

  // F4: recipe_error with non-empty exchangeIds still fails closed to baseline_unhealthy (never healthy/fixed).
  const recipeErrExec = {
    ...makeExec('persisted_mutation', 'impact', 'Receipt unbuildable in harness'),
    failure: { code: 'recipe_error', message: 'Receipt unbuildable in harness', missingRoles: [] },
  } as unknown as FloorRecipeExecution
  const recipeErrHealth = classifyRetestHealth(recipeErrExec)
  assert.equal(recipeErrHealth.healthy, false)
  assert.equal(recipeErrHealth.failureReason, 'baseline_unhealthy')

  // F3: Real host proof-receipt.ts verifyReceipt emits closed-union top-level failureCode!
  const cleanBolaVer = verifyReceipt(
    {
      vulnClass: 'bola',
      target: { origin: ORIGIN, method: 'GET', pathAndQuery: '/api/invoices/inv_1' },
      exchangeIds: ['ctl', 'prb'],
      oobEventIds: [],
      browserTraceIds: [],
      claimedDelta: 'Cross-tenant read',
      resourceTenant: 'tenant-a',
    },
    {
      entries: [
        { exchangeId: 'ctl', origin: ORIGIN, step: { id: 'ctl', arm: 'control', method: 'GET', route: '/api/invoices/inv_1', pathAndQuery: '/api/invoices/inv_1', status: 200, actor: { handle: 'owner_a', role: 'owner', tenant: 'tenant-a', auth: 'bearer', sameSite: null }, json: { id: 'inv_1', tenant_id: 'tenant-a' } } },
        { exchangeId: 'prb', origin: ORIGIN, step: { id: 'prb', arm: 'probe', method: 'GET', route: '/api/invoices/inv_1', pathAndQuery: '/api/invoices/inv_1', status: 403, actor: { handle: 'member_b', role: 'member', tenant: 'tenant-b', auth: 'bearer', sameSite: null }, json: { error: 'forbidden' } } },
      ],
    },
  )
  assert.equal(cleanBolaVer.confirmed, false)
  assert.equal(cleanBolaVer.failureCode, 'remediation_access_denied')

  const stubVer = verifyReceipt(
    {
      vulnClass: 'bola',
      target: { origin: ORIGIN, method: 'POST', pathAndQuery: '/api/invoices/inv_1/export' },
      exchangeIds: ['ctl', 'prb'],
      oobEventIds: [],
      browserTraceIds: [],
      claimedDelta: 'Export stub',
      resourceTenant: 'tenant-a',
    },
    {
      entries: [
        { exchangeId: 'ctl', origin: ORIGIN, step: { id: 'ctl', arm: 'control', method: 'POST', route: '/api/invoices/inv_1/export', pathAndQuery: '/api/invoices/inv_1/export', status: 200, actor: { handle: 'owner_a', role: 'owner', tenant: 'tenant-a', auth: 'bearer', sameSite: null }, json: { jobId: 'j1', status: 'queued' } } },
        { exchangeId: 'prb', origin: ORIGIN, step: { id: 'prb', arm: 'probe', method: 'POST', route: '/api/invoices/inv_1/export', pathAndQuery: '/api/invoices/inv_1/export', status: 200, actor: { handle: 'member_b', role: 'member', tenant: 'tenant-b', auth: 'bearer', sameSite: null }, json: { jobId: 'j2', status: 'queued' } } },
      ],
    },
  )
  assert.equal(stubVer.confirmed, false)
  assert.equal(stubVer.failureCode, 'oracle_disagreement')
})

// ============================================================================
// 5. Single RetryGovernor cross-path cap, disposer eviction & transport helpers
// ============================================================================

test('R3-14.5: single RetryGovernor enforces unified per-key cap across all paths, honours budgets, and drains via runAllRunDisposers', () => {
  const gov = new RetryGovernor()
  const now = 1_700_000_000_000
  const baseInput = {
    runId: 'run-gov-1',
    retryKey: 'GET /api/items::bola',
    retryable: true,
    stepSkills: [] as string[],
    runStatus: 'running',
    runPhase: 'investigation',
    budgetExhausted: false,
    requestBudgetExhausted: false,
    runCreatedAt: now - 5_000,
    maxDurationMs: 60_000,
    nowMs: now,
    existingStepCount: 2,
    effectiveStepCap: 10,
  }

  assert.equal(isRunWallClockExhausted(now - 61_000, 60_000, now), true)
  assert.equal(isRunWallClockExhausted(now - 5_000, 60_000, now), false)

  // First transient retry allowed and recorded
  const d1 = gov.evaluate({ ...baseInput, path: 'provider_transient', failureCode: 'rate_limited', emitted: false, toolCallsExecutedInTurn: 0 })
  assert.equal(d1.allowed, true)
  gov.recordRetry(baseInput.runId, baseInput.retryKey, 'provider_transient')

  // Same key is now capped across BOTH provider_stall AND step_requeue!
  const dStall = gov.evaluate({ ...baseInput, path: 'provider_stall', failureCode: 'stall', emitted: true, toolCallsExecutedInTurn: 0 })
  assert.equal(dStall.allowed, false)
  assert.equal(dStall.reason, 'retry_cap_reached')

  const dRequeue = gov.evaluate({ ...baseInput, path: 'step_requeue', stepStatus: 'turn_capped' })
  assert.equal(dRequeue.allowed, false)
  assert.equal(dRequeue.reason, 'retry_cap_reached')

  // Mid-stream tool execution blocks retry on a fresh key
  const dMid = gov.evaluate({ ...baseInput, retryKey: 'POST /api/transfer::race', path: 'provider_transient', failureCode: 'stream_drop', emitted: true, toolCallsExecutedInTurn: 2 })
  assert.equal(dMid.allowed, false)
  assert.equal(dMid.reason, 'midstream_tool_call_executed')

  // Exhausted wall clock blocks retry on a fresh key
  const dWall = gov.evaluate({ ...baseInput, retryKey: 'GET /api/fresh::sqli', path: 'provider_transient', failureCode: 'server', runCreatedAt: now - 70_000 })
  assert.equal(dWall.allowed, false)
  assert.equal(dWall.reason, 'wall_clock_exhausted')
  assert.equal(dWall.wallClockExhausted, true)

  // Default governor drains cleanly through process-wide runAllRunDisposers
  const dispRunId = 'run-r314-disposer-check'
  defaultRetryGovernor.recordRetry(dispRunId, 'GET /x::bola', 'step_requeue')
  assert.equal(defaultRetryGovernor.getRunStats(dispRunId)?.totalRetries, 1)
  runAllRunDisposers(dispRunId)
  assert.equal(defaultRetryGovernor.getRunStats(dispRunId), null, 'runAllRunDisposers must evict RetryGovernor per-run state')

  // Transport retry helpers
  assert.equal(shouldRetryProviderTransport({ retryable: true, hard: false, isLastCandidate: true, transientAttempts: 0, maxTransportRetries: 2 }), true)
  assert.equal(shouldRetryProviderTransport({ retryable: true, hard: true, isLastCandidate: true, transientAttempts: 0, maxTransportRetries: 2 }), false)
  assert.equal(shouldRetryProviderTransport({ retryable: true, hard: false, isLastCandidate: false, transientAttempts: 0, maxTransportRetries: 2 }), false)
  assert.equal(computeProviderRetryBackoffMs({ retryAfterMs: 25_000, attempt: 1, baseMs: 350 }), 10_000)
  assert.equal(computeProviderRetryBackoffMs({ attempt: 2, baseMs: 350 }), 700)
})

// ============================================================================
// 6. AST Decision-Module Prose-Regex Guard & Single Retry-Governor Invariant
// ============================================================================

function parseAst(relPath: string): ts.SourceFile {
  const abs = resolve(relPath)
  return ts.createSourceFile(relPath, readFileSync(abs, 'utf8'), ts.ScriptTarget.Latest, true, ts.ScriptKind.TS)
}

function findNamedFunctionNode(sf: ts.SourceFile, fnName: string): ts.Node | null {
  let found: ts.Node | null = null
  const visit = (node: ts.Node) => {
    if (found) return
    if ((ts.isFunctionDeclaration(node) || ts.isMethodDeclaration(node)) && node.name && ts.isIdentifier(node.name) && node.name.text === fnName) {
      found = node
      return
    }
    ts.forEachChild(node, visit)
  }
  visit(sf)
  return found
}

const PROSE_IDENTIFIERS = new Set(['reason', 'lastError', 'message', 'summary'])

function exprTouchesProseField(node: ts.Node): boolean {
  let hit = false
  const visit = (n: ts.Node) => {
    if (hit) return
    if (ts.isIdentifier(n) && PROSE_IDENTIFIERS.has(n.text)) {
      hit = true
      return
    }
    if (ts.isPropertyAccessExpression(n) && PROSE_IDENTIFIERS.has(n.name.text)) {
      hit = true
      return
    }
    ts.forEachChild(n, visit)
  }
  visit(node)
  return hit
}

function collectProseRegexCalls(root: ts.Node, sf: ts.SourceFile): Array<{ line: number; text: string }> {
  const hits: Array<{ line: number; text: string }> = []
  const visit = (node: ts.Node) => {
    if (ts.isCallExpression(node) && ts.isPropertyAccessExpression(node.expression)) {
      const method = node.expression.name.text
      const receiver = node.expression.expression
      // Case A: /.../.test(prose) or RE.test(prose) or RE.exec(prose)
      if (method === 'test' || method === 'exec') {
        const arg0 = node.arguments[0]
        if (arg0 && exprTouchesProseField(arg0)) {
          const line = sf.getLineAndCharacterOfPosition(node.getStart(sf)).line + 1
          hits.push({ line, text: node.getText(sf) })
        }
      }
      // Case B: prose.match(/.../) or prose.search(/.../)
      if (method === 'match' || method === 'search') {
        if (exprTouchesProseField(receiver)) {
          const line = sf.getLineAndCharacterOfPosition(node.getStart(sf)).line + 1
          hits.push({ line, text: node.getText(sf) })
        }
      }
    }
    ts.forEachChild(node, visit)
  }
  visit(root)
  return hits
}

test('R3-14.6: AST guard bans prose regexes in decision modules, bans wallClockExhausted:false, and enforces single RetryGovernor', () => {
  // 1. Decision modules must have ZERO regex checks over reason / lastError / message / summary.
  const decisionTargets: Array<{ file: string; fnName?: string }> = [
    { file: 'src/server/retest-health.ts', fnName: 'classifyRetestHealth' },
    { file: 'src/server/provider.ts', fnName: 'evaluateRoleProviderCircuit' },
    { file: 'src/server/agent-script-proof.ts', fnName: 'runAgentScriptProof' },
    { file: 'src/server/agent-script-proof.ts', fnName: 'retestPersistedAgentScript' },
    { file: 'src/server/retry-governor.ts' },
  ]
  for (const target of decisionTargets) {
    const sf = parseAst(target.file)
    const scopeNode = target.fnName ? findNamedFunctionNode(sf, target.fnName) : sf
    assert.ok(scopeNode, `expected AST node ${target.fnName ?? '<module>'} in ${target.file}`)
    const hits = collectProseRegexCalls(scopeNode, sf)
    assert.deepEqual(hits, [], `unexpected prose-regex decision call in ${target.file}${target.fnName ? `::${target.fnName}` : ''}`)
  }

  // 2. evaluateRoleProviderCircuit must NEVER call classifyProviderFailure or read profile.lastError.
  const providerSf = parseAst('src/server/provider.ts')
  const circuitFn = findNamedFunctionNode(providerSf, 'evaluateRoleProviderCircuit')
  assert.ok(circuitFn)
  const forbiddenCircuitRefs: string[] = []
  const visitCircuit = (node: ts.Node) => {
    if (ts.isCallExpression(node) && ts.isIdentifier(node.expression) && node.expression.text === 'classifyProviderFailure') {
      forbiddenCircuitRefs.push('classifyProviderFailure')
    }
    if (ts.isPropertyAccessExpression(node) && node.name.text === 'lastError') {
      forbiddenCircuitRefs.push('lastError')
    }
    ts.forEachChild(node, visitCircuit)
  }
  visitCircuit(circuitFn)
  assert.deepEqual(forbiddenCircuitRefs, [], 'evaluateRoleProviderCircuit must read persisted failureKind only')

  // 3. exec-worker-runner.ts must have ZERO hardcoded `wallClockExhausted: false` and ZERO local retry maps.
  const workerSf = parseAst('src/server/exec-worker-runner.ts')
  const hardcodedWallFalse: number[] = []
  const duplicateWorkerMaps: string[] = []
  const visitWorker = (node: ts.Node) => {
    if (
      ts.isPropertyAssignment(node)
      && ts.isIdentifier(node.name)
      && node.name.text === 'wallClockExhausted'
      && node.initializer.kind === ts.SyntaxKind.FalseKeyword
    ) {
      hardcodedWallFalse.push(workerSf.getLineAndCharacterOfPosition(node.getStart(workerSf)).line + 1)
    }
    if (
      ts.isPropertyDeclaration(node)
      && ts.isIdentifier(node.name)
      && (node.name.text === 'providerRetryCountsByRun' || node.name.text === 'providerRetriesTotalByRun')
    ) {
      duplicateWorkerMaps.push(node.name.text)
    }
    ts.forEachChild(node, visitWorker)
  }
  visitWorker(workerSf)
  assert.deepEqual(hardcodedWallFalse, [], 'exec-worker-runner.ts must never hardcode wallClockExhausted: false')
  assert.deepEqual(duplicateWorkerMaps, [], 'exec-worker-runner.ts must delegate retry state to RetryGovernor')

  // 4. exec-recon-planner.ts must have ZERO local retryCountsByRun map.
  const plannerSf = parseAst('src/server/exec-recon-planner.ts')
  const duplicatePlannerMaps: string[] = []
  const visitPlanner = (node: ts.Node) => {
    if (ts.isPropertyDeclaration(node) && ts.isIdentifier(node.name) && node.name.text === 'retryCountsByRun') {
      duplicatePlannerMaps.push(node.name.text)
    }
    ts.forEachChild(node, visitPlanner)
  }
  visitPlanner(plannerSf)
  assert.deepEqual(duplicatePlannerMaps, [], 'exec-recon-planner.ts must delegate retry state to RetryGovernor')
})
