/**
 * v7 M5 — agent script proofs (receipt-first confirmation, persistence, inline short-circuit, retest).
 *
 * Covers (with zero Docker, using an in-process fake WorkerBackend wired to the real VerifyRpcServer):
 *   1. Schema v8 -> v9 additive migration + replay_specs proof columns + Store accessors.
 *   2. buildAgentScriptReceipt() + verifyReceipt() pass on impact (cross-tenant write with readback),
 *      structural_diff (paired boolean differential), and timing separation — AND fail-closed
 *      rejection on oracle invariant violations (status-only, missing post-mutation readback,
 *      anon-401 control for cross-tenant write, and unmapped claim classes).
 *   3. runAgentScriptProof() end-to-end over real VerifyRpcServer + RequestBroker + HMAC transcript
 *      + fresh double-run nonces, including fail-closed rejection when verifyReceipt() fails.
 *   4. persistAgentScriptProof() writes owner-only redacted artifact, attribution-only spec with
 *      agentScript envelope, replay_specs proof columns, and a finding whose ProofReceipt satisfies
 *      Store.assertConfirmationEvidence() + SQLite triggers; non-confirming verdicts are rejected
 *      with InvariantError('invariant.confirmation_evidence').
 *   5. Receipt-first short-circuit at the top of Execution.executeInlineVerification (by replaySpecId
 *      and via agentProofForFinding fallback when a declarative spec is submitted for the same
 *      finding), bypassing declarativeReplaySpecSchema parsing and demoting cleanly when fixed.
 *   6. retestPersistedAgentScript() via retestReplaySpec() returning 'reproduced' (still vulnerable)
 *      vs 'fixed' (after hardening) vs 'inconclusive' (backend failure), ignoring legacy assertionsJq.
 */
import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { once } from 'node:events'
import { mkdtempSync, readFileSync, rmSync } from 'node:fs'
import { createServer, request as httpRequest } from 'node:http'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import test from 'node:test'
import { DatabaseSync } from 'node:sqlite'
import type { DeclarativeReplaySpec } from '../src/replay-spec.ts'
import { agentScriptProofEnvelopeSchema, declarativeReplaySpecSchema } from '../src/replay-spec.ts'
import { RequestBroker } from '../src/server/broker.ts'
import type { Grant } from '../src/server/broker.ts'
import { Execution } from '../src/server/execution.ts'
import type { ResolvedPersona } from '../src/server/persona-vault.ts'
import { buildAgentScriptReceipt, verifyReceipt } from '../src/server/proof-receipt.ts'
import type { ScriptProofExchange } from '../src/server/proof-receipt.ts'
import { persistedAgentScriptOf, retestReplaySpec, runAgentScriptProof } from '../src/server/replay-verifier.ts'
import type { AgentScriptProofResult } from '../src/server/replay-verifier.ts'
import { assignments, evidence, findings } from '../src/server/schema.ts'
import { eq } from 'drizzle-orm'
import { InvariantError, STORE_SCHEMA_VERSION, Store } from '../src/server/store.ts'
import type { AgentScriptProofRecord, Assignment, Run } from '../src/server/store.ts'
import {
  VERIFY_NONCE_HEADER,
  VERIFY_RPC_CONTEXT_NAME,
  VERIFY_RPC_HEADER,
  VERIFY_RPC_SOCKET_NAME,
  VERIFY_RPC_TOKEN_NAME,
} from '../src/server/verify-rpc.ts'
import type { VerifyScriptRequest, VerifyScriptResult, WorkerBackend, WorkerSession, WorkerSessionOptions } from '../src/server/worker-backend.ts'
import { makeLabGrant, setupApprovedRun } from './v4-tier-helpers.ts'

process.env.GUARDIAN_ALLOW_LOCAL_LAB = '1'

// ---------------------------------------------------------------------------
// Helpers: Store, HTTP fixture, RPC client, and fake WorkerBackend (no Docker)
// ---------------------------------------------------------------------------

function makeStore(t: { after: (fn: () => void) => void }): { storage: Store; dir: string } {
  const dir = mkdtempSync(join(tmpdir(), 'guardian-v7-script-proofs-'))
  const storage = new Store(dir)
  t.after(() => {
    storage.close()
    rmSync(dir, { recursive: true, force: true })
  })
  return { storage, dir }
}

interface TenantWriteFixture {
  origin: string
  hardened: boolean
  close: () => Promise<void>
}

/**
 * Local multi-tenant record server:
 * - Record `rec-acme` belongs to tenant `acme` (initial note: "baseline").
 * - `owner_acme` (token: tok-owner-acme) can read/write `rec-acme`.
 * - `member_beta` (token: tok-member-beta) can read/write its own tenant; on `rec-acme`:
 *     * when `hardened === false`: PATCH mutates `rec-acme` (broken object-level authorization).
 *     * when `hardened === true`: PATCH returns 403 (patched).
 * - `viewer_beta` (token: tok-viewer-beta) is an authenticated peer in tenant `beta` that is
 *   denied (403) on `PATCH /api/records/rec-acme` (peer-entitlement control).
 * - Unauthenticated requests return 401.
 */
async function startTenantWriteFixture(): Promise<TenantWriteFixture> {
  const state = { hardened: false, note: 'baseline', seq: 0 }
  const server = createServer((req, res) => {
    const auth = req.headers.authorization ?? ''
    const url = new URL(req.url ?? '/', 'http://127.0.0.1')
    res.setHeader('content-type', 'application/json')

    if (!auth) {
      res.statusCode = 401
      res.end(JSON.stringify({ error: 'authentication required' }))
      return
    }
    if (url.pathname === '/api/records/rec-acme' && req.method === 'GET') {
      if (auth === 'Bearer tok-owner-acme') {
        res.statusCode = 200
        res.end(JSON.stringify({ id: 'rec-acme', tenant: 'acme', note: state.note }))
        return
      }
      res.statusCode = 403
      res.end(JSON.stringify({ error: 'forbidden' }))
      return
    }
    if (url.pathname === '/api/records/rec-acme' && req.method === 'PATCH') {
      let raw = ''
      req.on('data', chunk => { raw += chunk })
      req.on('end', () => {
        if (auth === 'Bearer tok-viewer-beta') {
          res.statusCode = 403
          res.end(JSON.stringify({ error: 'forbidden for viewer' }))
          return
        }
        if (auth === 'Bearer tok-member-beta') {
          if (state.hardened) {
            res.statusCode = 403
            res.end(JSON.stringify({ error: 'cross-tenant write blocked' }))
            return
          }
          try {
            const parsed = JSON.parse(raw) as { note?: string }
            if (typeof parsed.note === 'string') state.note = parsed.note
          } catch { /* ignore */ }
          state.seq += 1
          res.statusCode = 200
          res.end(JSON.stringify({ id: 'rec-acme', tenant: 'acme', note: state.note, updated: state.seq }))
          return
        }
        if (auth === 'Bearer tok-owner-acme') {
          try {
            const parsed = JSON.parse(raw) as { note?: string }
            if (typeof parsed.note === 'string') state.note = parsed.note
          } catch { /* ignore */ }
          res.statusCode = 200
          res.end(JSON.stringify({ id: 'rec-acme', tenant: 'acme', note: state.note }))
          return
        }
        res.statusCode = 403
        res.end(JSON.stringify({ error: 'forbidden' }))
      })
      return
    }
    res.statusCode = 404
    res.end(JSON.stringify({ error: 'not found' }))
  })
  server.listen(0, '127.0.0.1')
  await once(server, 'listening')
  const port = (server.address() as { port: number }).port
  return {
    origin: `http://127.0.0.1:${port}`,
    get hardened() { return state.hardened },
    set hardened(value: boolean) { state.hardened = value },
    close: async () => {
      server.closeAllConnections()
      await new Promise<void>(resolve => server.close(() => resolve()))
    },
  } as TenantWriteFixture
}

function makeMultiTenantGrant(origin: string): Grant {
  const persona = (handle: string, roleLabel: string, secret: string): ResolvedPersona => ({
    id: `persona-${handle}`,
    handle,
    roleLabel,
    originAllowlist: [origin],
    authKind: 'bearer',
    headerName: 'Authorization',
    secret,
    canaryMarkers: [],
  })
  const personas = new Map<string, ResolvedPersona>([
    ['owner_acme', persona('owner_acme', 'owner (acme)', 'tok-owner-acme')],
    ['member_beta', persona('member_beta', 'member (beta)', 'tok-member-beta')],
    ['viewer_beta', persona('viewer_beta', 'viewer (beta)', 'tok-viewer-beta')],
  ])
  return makeLabGrant(origin, { tier: 3, personas })
}

/** Send one JSON RPC call over the VerifyRpcServer Unix domain socket. */
async function rpcCall(
  socketPath: string,
  token: string,
  nonce: string,
  payload: { op: string; args: Record<string, unknown> },
): Promise<{ ok: boolean; result?: Record<string, unknown>; error?: string }> {
  const body = JSON.stringify(payload)
  return await new Promise((resolve, reject) => {
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
          try { resolve(JSON.parse(data) as { ok: boolean; result?: Record<string, unknown>; error?: string }) }
          catch (err) { reject(err) }
        })
      },
    )
    req.on('error', reject)
    req.end(body)
  })
}

type FakeVerifyScriptHandler = (ctx: {
  request: VerifyScriptRequest
  rpcDir: string
  rpc: (op: string, args: Record<string, unknown>) => Promise<{ ok: boolean; result?: Record<string, unknown>; error?: string }>
  context: { nonce: string; targetOrigins: string[] }
  signal: AbortSignal
}) => Promise<VerifyScriptResult>

/**
 * In-process WorkerBackend fake that speaks the real VerifyRpcServer Unix-socket protocol
 * mounted into `options.rpcMountDir`. Zero Docker containers are started.
 */
function makeFakeVerifyBackend(handler: FakeVerifyScriptHandler): WorkerBackend & { calls: number } {
  const backend: WorkerBackend & { calls: number } = {
    calls: 0,
    async run() {
      throw new Error('Fake verify backend does not support run().')
    },
    async verifyStaticAst() {
      throw new Error('Fake verify backend does not support verifyStaticAst().')
    },
    async openSession(_assignmentId: string, _signal: AbortSignal, options?: WorkerSessionOptions): Promise<WorkerSession> {
      const rpcDir = options?.rpcMountDir ?? ''
      return {
        async stage() { throw new Error('stage() not implemented on fake session') },
        async exec() { throw new Error('exec() not implemented on fake session') },
        async analyze() { throw new Error('analyze() not implemented on fake session') },
        async sast() { throw new Error('sast() not implemented on fake session') },
        async runScript() { throw new Error('runScript() not implemented on fake session') },
        async verifyStaticAst() { throw new Error('verifyStaticAst() not implemented on fake session') },
        async verifyScript(req: VerifyScriptRequest, signal: AbortSignal): Promise<VerifyScriptResult> {
          backend.calls += 1
          const socketPath = join(rpcDir, VERIFY_RPC_SOCKET_NAME)
          const token = readFileSync(join(rpcDir, VERIFY_RPC_TOKEN_NAME), 'utf8').trim()
          const context = JSON.parse(readFileSync(join(rpcDir, VERIFY_RPC_CONTEXT_NAME), 'utf8')) as {
            nonce: string
            targetOrigins: string[]
          }
          const rpc = (op: string, args: Record<string, unknown>) => rpcCall(socketPath, token, context.nonce, { op, args })
          return await handler({ request: req, rpcDir, rpc, context, signal })
        },
        async close() { /* noop */ },
      }
    },
  }
  return backend
}

/**
 * Reusable fake-script executor that performs a genuine cross-tenant write sequence over the real
 * VerifyRpcServer + RequestBroker:
 *   1. owner_acme reads baseline (beforeExchangeId)
 *   2. viewer_beta attempts PATCH and is denied 403 (authenticated peer control)
 *   3. member_beta attempts PATCH with a new note value (mutating probe)
 *   4. owner_acme reads back the record (afterExchangeId)
 *   5. owner_acme resets the note back to "baseline" (cleanup so run #2 starts clean!)
 */
function makeTenantWriteScriptHandler(origin: string, mode: 'valid' | 'missing_readback' | 'anon_401_control' = 'valid'): FakeVerifyScriptHandler {
  return async ({ request, rpc, context }) => {
    if (request.code.includes('THROW_EXECUTION_ERROR')) {
      return {
        runtime: request.runtime,
        exitCode: 1,
        result: null,
        stdout: '',
        stderr: 'simulated execution failure',
        durationMs: 5,
        timedOut: false,
      }
    }
    const before = await rpc('http', {
      origin, method: 'GET', path: '/api/records/rec-acme', persona: 'owner_acme', sessionGroupRole: 'control',
    })
    assert.equal(before.ok, true, before.error ?? 'before RPC failed')
    const beforeId = String(before.result!.exchangeId)

    const control = mode === 'anon_401_control'
      ? await rpc('http', {
          origin, method: 'PATCH', path: '/api/records/rec-acme', sessionGroupRole: 'control',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({ note: 'anon-attempt' }),
        })
      : await rpc('http', {
          origin, method: 'PATCH', path: '/api/records/rec-acme', persona: 'viewer_beta', sessionGroupRole: 'control',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({ note: 'peer-denied' }),
        })
    assert.equal(control.ok, true, control.error ?? 'control RPC failed')
    const controlId = String(control.result!.exchangeId)

    const probe = await rpc('http', {
      origin, method: 'PATCH', path: '/api/records/rec-acme', persona: 'member_beta', sessionGroupRole: 'probe',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ note: `cross-tenant-${context.nonce.slice(0, 6)}` }),
    })
    assert.equal(probe.ok, true, probe.error ?? 'probe RPC failed')
    const probeId = String(probe.result!.exchangeId)

    let afterId: string | undefined
    if (mode !== 'missing_readback') {
      const after = await rpc('http', {
        origin, method: 'GET', path: '/api/records/rec-acme', persona: 'owner_acme', sessionGroupRole: 'control',
      })
      assert.equal(after.ok, true, after.error ?? 'after RPC failed')
      afterId = String(after.result!.exchangeId)
    }

    // Restore baseline between attempts so fresh attempt #2 observes the exact same before->after delta.
    await rpc('http', {
      origin, method: 'PATCH', path: '/api/records/rec-acme', persona: 'owner_acme', sessionGroupRole: 'cleanup',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ note: 'baseline' }),
    })

    const claim: Record<string, unknown> = {
      kind: 'impact',
      impactClass: 'authorization',
      probeExchangeId: probeId,
      controlExchangeIds: [controlId],
      beforeExchangeId: beforeId,
      ...(afterId ? { afterExchangeId: afterId } : {}),
      resourceTenant: 'acme',
      expectControlDenied: true,
      oracleEvents: ['cross_tenant_write'],
      requestBody: { note: `cross-tenant-${context.nonce.slice(0, 6)}` },
    }
    return {
      runtime: request.runtime,
      exitCode: 0,
      result: {
        nonce: context.nonce,
        title: 'Cross-tenant record write via member_beta',
        severity: 'high',
        description: 'CWE-639 cross-tenant record write verified via host transcript.',
        claims: [claim],
      },
      stdout: '',
      stderr: '',
      durationMs: 12,
      timedOut: false,
    }
  }
}

// ---------------------------------------------------------------------------
// 1. Schema v8 -> v9 additive migration & proof column persistence/readback
// ---------------------------------------------------------------------------

test('v7 agent-script-proofs: schema v8->v9 additive migration and proof column accessors', async (t) => {
  const dir = mkdtempSync(join(tmpdir(), 'guardian-v7-mig-'))
  t.after(() => rmSync(dir, { recursive: true, force: true }))

  // Create a database, seed a legacy replay_spec row, then downgrade the schema to v8
  // (dropping the 6 v9 proof_* columns + index and setting user_version = 8).
  const initial = new Store(dir)
  const { runId } = await setupApprovedRun(initial, { seeds: ['http://127.0.0.1:9911'], environment: 'local-lab', tier: 2 })
  const run = initial.run(runId)
  const asset = run.candidates[0]!
  const assignment = initial.makeWorker(run, 'verification', asset, 'Legacy migration fixture', 'fixture')
  const legacySpec = declarativeReplaySpecSchema.parse({
    version: 1,
    kind: 'http_chain',
    origin: 'http://127.0.0.1:9911',
    title: 'Legacy declarative spec',
    category: 'broken-access-control',
    cwe: 'CWE-639',
    severity: 'high',
    severityRationale: 'Fixture',
    impact: 'Fixture',
    remediation: 'Fixture',
    recheckInstructions: 'Fixture',
    assertionsJq: 'true',
    steps: [
      { id: 'c1', role: 'control', description: 'Control', request: { origin: 'http://127.0.0.1:9911', method: 'GET', pathAndQuery: '/a', followRedirects: false } },
      { id: 'p1', role: 'probe', description: 'Probe', request: { origin: 'http://127.0.0.1:9911', method: 'GET', pathAndQuery: '/b', followRedirects: false } },
    ],
  })
  const legacyRow = initial.createReplaySpec(run, assignment, 'finding-legacy-1', legacySpec, ['http://127.0.0.1:9911'])
  initial.close()

  // Simulate an existing v8 database on disk (no proof_* columns, user_version = 8).
  const rawDb = new DatabaseSync(join(dir, 'guardian.sqlite'))
  rawDb.exec('DROP INDEX IF EXISTS replay_specs_proof;')
  for (const col of ['proof_kind', 'proof_verdict', 'proof_runtime', 'proof_script_sha256', 'proof_artifact_id', 'proof_receipt']) {
    rawDb.exec(`ALTER TABLE replay_specs DROP COLUMN ${col};`)
  }
  rawDb.exec('PRAGMA user_version = 8;')
  const v8Cols = (rawDb.prepare('PRAGMA table_info(replay_specs)').all() as Array<{ name: string }>).map(r => r.name)
  assert.equal(v8Cols.includes('proof_kind'), false, 'simulated v8 table must lack proof_kind')
  rawDb.close()

  // Reopen with Store — initV7Schema must migrate v8 -> v9 cleanly and additively.
  const migrated = new Store(dir)
  t.after(() => migrated.close())
  const version = (migrated.client.prepare('PRAGMA user_version').get() as { user_version: number }).user_version
  assert.equal(version, STORE_SCHEMA_VERSION)
  assert.equal(STORE_SCHEMA_VERSION, 9)
  const v9Cols = new Set((migrated.client.prepare('PRAGMA table_info(replay_specs)').all() as Array<{ name: string }>).map(r => r.name))
  for (const col of ['proof_kind', 'proof_verdict', 'proof_runtime', 'proof_script_sha256', 'proof_artifact_id', 'proof_receipt']) {
    assert.equal(v9Cols.has(col), true, `migrated replay_specs must have ${col}`)
  }

  // Pre-migration legacy row is intact and reports no agent script proof.
  assert.equal(migrated.replaySpecProof(runId, legacyRow.id), null)
  assert.equal(migrated.agentProofForFinding(runId, 'finding-legacy-1'), null)

  // Persist a proof on a new spec row and round-trip via replaySpecProof / agentProofForFinding / setReplaySpecProof.
  const scriptSha = createHash('sha256').update('console.log("proof")').digest('hex')
  const receiptRow: NonNullable<AgentScriptProofRecord['receipt']> = {
    receipt: {
      vulnClass: 'authorization',
      target: { origin: 'http://127.0.0.1:9911', method: 'PATCH', pathAndQuery: '/api/records/rec-acme' },
      exchangeIds: ['ex-1', 'ex-2', 'ex-3', 'ex-4'],
      oobEventIds: [],
      browserTraceIds: [],
      claimedDelta: 'Cross-tenant write persisted',
      resourceTenant: 'acme',
      expectControlDenied: true,
    },
    verification: {
      confirmed: true,
      vulnClass: 'authorization',
      rule: 'impact',
      reason: 'Object-level impact persisted',
      observed: 'Cross-tenant write persisted',
      expected: 'Denied for other tenant',
    },
  }
  const findingId = 'finding-script-proof-1'
  const created = migrated.createReplaySpec(migrated.run(runId), assignment, findingId, legacySpec, ['http://127.0.0.1:9911'], {
    verifiedInline: true,
    proof: {
      replaySpecId: '',
      findingId,
      verdict: 'confirmed',
      runtime: 'ts',
      scriptSha256: scriptSha,
      artifactId: 'art-1',
      receipt: receiptRow,
      createdAt: Date.now(),
    },
  })

  const bySpec = migrated.replaySpecProof(runId, created.id)
  assert.ok(bySpec)
  assert.equal(bySpec.replaySpecId, created.id)
  assert.equal(bySpec.findingId, findingId)
  assert.equal(bySpec.verdict, 'confirmed')
  assert.equal(bySpec.runtime, 'ts')
  assert.equal(bySpec.scriptSha256, scriptSha)
  assert.equal(bySpec.artifactId, 'art-1')
  assert.equal(bySpec.receipt?.verification.confirmed, true)
  assert.equal(bySpec.receipt?.receipt.vulnClass, 'authorization')

  const byFinding = migrated.agentProofForFinding(runId, findingId)
  assert.deepEqual(byFinding, bySpec)

  // Update via setReplaySpecProof and confirm readback reflects the update.
  migrated.setReplaySpecProof(runId, created.id, {
    ...bySpec,
    verdict: 'dismissed',
    receipt: null,
  })
  const updated = migrated.replaySpecProof(runId, created.id)
  assert.equal(updated?.verdict, 'dismissed')
  assert.equal(updated?.receipt, null)
})

// ---------------------------------------------------------------------------
// 2. buildAgentScriptReceipt + verifyReceipt: pass & fail-closed oracle checks
// ---------------------------------------------------------------------------

test('v7 agent-script-proofs: buildAgentScriptReceipt + verifyReceipt pass on impact, boolean, and timing', () => {
  const origin = 'http://127.0.0.1:9922'

  // (a) Impact: cross-tenant write with before readback, authenticated peer denial, PATCH probe, after readback.
  const impactExchanges: ScriptProofExchange[] = [
    {
      exchangeId: 'ex-before', method: 'GET', pathAndQuery: '/api/records/rec-acme', origin, status: 200,
      personaHandle: 'owner_acme', actorRoleLabel: 'owner (acme)', sessionRole: 'setup',
      body: JSON.stringify({ id: 'rec-acme', tenant: 'acme', note: 'baseline' }),
    },
    {
      exchangeId: 'ex-ctrl', method: 'PATCH', pathAndQuery: '/api/records/rec-acme', origin, status: 403,
      personaHandle: 'viewer_beta', actorRoleLabel: 'viewer (beta)', sessionRole: 'control',
      body: JSON.stringify({ error: 'forbidden' }),
    },
    {
      exchangeId: 'ex-probe', method: 'PATCH', pathAndQuery: '/api/records/rec-acme', origin, status: 200,
      personaHandle: 'member_beta', actorRoleLabel: 'member (beta)', sessionRole: 'probe',
      body: JSON.stringify({ id: 'rec-acme', tenant: 'acme', note: 'mutated' }),
    },
    {
      exchangeId: 'ex-after', method: 'GET', pathAndQuery: '/api/records/rec-acme', origin, status: 200,
      personaHandle: 'owner_acme', actorRoleLabel: 'owner (acme)', sessionRole: 'setup',
      body: JSON.stringify({ id: 'rec-acme', tenant: 'acme', note: 'mutated' }),
    },
  ]
  const impactBuilt = buildAgentScriptReceipt({
    claims: [{
      kind: 'impact',
      impactClass: 'authorization',
      probeExchangeId: 'ex-probe',
      controlExchangeIds: ['ex-ctrl'],
      beforeExchangeId: 'ex-before',
      afterExchangeId: 'ex-after',
      resourceTenant: 'acme',
      expectControlDenied: true,
      oracleEvents: ['cross_tenant_write'],
    }],
    exchanges: impactExchanges,
    origin,
    title: 'Cross-tenant write',
  })
  assert.ok(impactBuilt, 'impact claim must build a receipt')
  assert.deepEqual(impactBuilt.receipt.exchangeIds, ['ex-before', 'ex-ctrl', 'ex-probe', 'ex-after'], 'must keep chronological order for persistence readback')
  const impactVer = verifyReceipt(impactBuilt.receipt, impactBuilt.transcript)
  assert.equal(impactVer.confirmed, true, impactVer.reason)
  assert.equal(impactVer.rule, 'impact')

  // (b) Structural diff (boolean differential): 2 paired rounds differing in `q` (even with unset sessionRole).
  const boolExchanges: ScriptProofExchange[] = [
    { exchangeId: 'b-c1', method: 'GET', pathAndQuery: '/api/items?q=alpha', origin, status: 200, body: JSON.stringify({ rows: [{ id: 1, name: 'alpha' }] }) },
    { exchangeId: 'b-v1', method: 'GET', pathAndQuery: '/api/items?q=alpha_false', origin, status: 200, body: JSON.stringify({ rows: [] }) },
    { exchangeId: 'b-c2', method: 'GET', pathAndQuery: '/api/items?q=alpha', origin, status: 200, body: JSON.stringify({ rows: [{ id: 1, name: 'alpha' }] }) },
    { exchangeId: 'b-v2', method: 'GET', pathAndQuery: '/api/items?q=alpha_false', origin, status: 200, body: JSON.stringify({ rows: [] }) },
  ]
  const boolBuilt = buildAgentScriptReceipt({
    claims: [{ kind: 'structural_diff', controlIds: ['b-c1', 'b-c2'], variantIds: ['b-v1', 'b-v2'] }],
    exchanges: boolExchanges,
    origin,
    title: 'Paired boolean differential',
  })
  assert.ok(boolBuilt, 'structural_diff claim must build a boolean receipt')
  const boolVer = verifyReceipt(boolBuilt.receipt, boolBuilt.transcript)
  assert.equal(boolVer.confirmed, true, boolVer.reason)
  assert.equal(boolVer.rule, 'boolean')

  // (c) Timing separation: 5 fast controls + 5 slow probes (>3x, >=1000ms).
  const timingExchanges: ScriptProofExchange[] = [
    ...Array.from({ length: 5 }, (_, i) => ({
      exchangeId: `t-c${i}`, method: 'GET', pathAndQuery: '/api/report?id=1', origin, status: 200, durationMs: 45, body: '{"ok":true}',
    })),
    ...Array.from({ length: 5 }, (_, i) => ({
      exchangeId: `t-v${i}`, method: 'GET', pathAndQuery: '/api/report?id=2', origin, status: 200, durationMs: 1_500, body: '{"ok":true}',
    })),
  ]
  const timingBuilt = buildAgentScriptReceipt({
    claims: [{
      kind: 'timing',
      controlIds: ['t-c0', 't-c1', 't-c2', 't-c3', 't-c4'],
      variantIds: ['t-v0', 't-v1', 't-v2', 't-v3', 't-v4'],
    }],
    exchanges: timingExchanges,
    origin,
    title: 'Timing differential',
  })
  assert.ok(timingBuilt, 'timing claim must build a timing receipt')
  const timingVer = verifyReceipt(timingBuilt.receipt, timingBuilt.transcript)
  assert.equal(timingVer.confirmed, true, timingVer.reason)
  assert.equal(timingVer.rule, 'timing')

  // (d) Unmapped claim class (boundary-only) conservatively returns null.
  const unmapped = buildAgentScriptReceipt({
    claims: [{ kind: 'boundary', controlExchangeId: 'ex-ctrl', probeExchangeId: 'ex-probe' }],
    exchanges: impactExchanges,
    origin,
    title: 'Boundary only',
  })
  assert.equal(unmapped, null)
})

test('v7 agent-script-proofs: verifyReceipt fails closed on status-only, missing readback, and anon-401 control', () => {
  const origin = 'http://127.0.0.1:9923'

  // (1) Status-only divergence (200 -> 500 with generic error body, no engine fingerprint).
  const statusOnlyExchanges: ScriptProofExchange[] = [
    { exchangeId: 'so-ctrl', method: 'GET', pathAndQuery: '/api/search?q=ok', origin, status: 200, sessionRole: 'control', body: JSON.stringify({ rows: [{ id: 1 }] }) },
    { exchangeId: 'so-probe', method: 'GET', pathAndQuery: '/api/search?q=bad', origin, status: 500, sessionRole: 'probe', body: JSON.stringify({ error: 'internal server error' }) },
  ]
  const statusOnlyBuilt = buildAgentScriptReceipt({
    claims: [{ kind: 'impact', impactClass: 'injection', probeExchangeId: 'so-probe', controlExchangeIds: ['so-ctrl'] }],
    exchanges: statusOnlyExchanges,
    origin,
    title: 'Status-only 500 probe',
  })
  assert.ok(statusOnlyBuilt)
  const statusOnlyVer = verifyReceipt(statusOnlyBuilt.receipt, statusOnlyBuilt.transcript)
  assert.equal(statusOnlyVer.confirmed, false, 'status-only 200->500 without fingerprint must be rejected')
  assert.match(statusOnlyVer.reason, /status-only|status divergence/i)

  // (2) Missing post-mutation readback (PATCH returns 200 echo with no separate GET after).
  const missingReadbackExchanges: ScriptProofExchange[] = [
    {
      exchangeId: 'mr-before', method: 'GET', pathAndQuery: '/api/records/rec-acme', origin, status: 200,
      personaHandle: 'owner_acme', actorRoleLabel: 'owner (acme)', sessionRole: 'control',
      body: JSON.stringify({ id: 'rec-acme', tenant: 'acme', note: 'baseline' }),
    },
    {
      exchangeId: 'mr-ctrl', method: 'PATCH', pathAndQuery: '/api/records/rec-acme', origin, status: 403,
      personaHandle: 'viewer_beta', actorRoleLabel: 'viewer (beta)', sessionRole: 'control',
      body: JSON.stringify({ error: 'forbidden' }),
    },
    {
      exchangeId: 'mr-probe', method: 'PATCH', pathAndQuery: '/api/records/rec-acme', origin, status: 200,
      personaHandle: 'member_beta', actorRoleLabel: 'member (beta)', sessionRole: 'probe',
      body: JSON.stringify({ id: 'rec-acme', tenant: 'acme', note: 'echo-only' }),
    },
  ]
  const missingReadbackBuilt = buildAgentScriptReceipt({
    claims: [{
      kind: 'impact',
      impactClass: 'authorization',
      probeExchangeId: 'mr-probe',
      controlExchangeIds: ['mr-ctrl'],
      beforeExchangeId: 'mr-before',
      resourceTenant: 'acme',
      expectControlDenied: true,
    }],
    exchanges: missingReadbackExchanges,
    origin,
    title: 'Echo-only write without readback',
  })
  assert.ok(missingReadbackBuilt)
  const missingReadbackVer = verifyReceipt(missingReadbackBuilt.receipt, missingReadbackBuilt.transcript)
  assert.equal(missingReadbackVer.confirmed, false, 'mutating write without separate post-mutation GET readback must be rejected')
  assert.match(missingReadbackVer.reason, /readback|persisted/i)

  // (3) Anon-401 control for an authenticated cross-tenant write (no authenticated peer denial and
  //     no cross-tenant control read: only same-tenant readbacks by member_beta + an anon 401).
  const anon401Exchanges: ScriptProofExchange[] = [
    {
      exchangeId: 'a401-before', method: 'GET', pathAndQuery: '/api/records/rec-acme', origin, status: 200,
      personaHandle: 'member_beta', actorRoleLabel: 'member (beta)', sessionRole: 'control',
      body: JSON.stringify({ id: 'rec-acme', tenant: 'acme', note: 'baseline' }),
    },
    {
      exchangeId: 'a401-ctrl', method: 'PATCH', pathAndQuery: '/api/records/rec-acme', origin, status: 401,
      personaHandle: null, actorRoleLabel: null, sessionRole: 'control',
      body: JSON.stringify({ error: 'authentication required' }),
    },
    {
      exchangeId: 'a401-probe', method: 'PATCH', pathAndQuery: '/api/records/rec-acme', origin, status: 200,
      personaHandle: 'member_beta', actorRoleLabel: 'member (beta)', sessionRole: 'probe',
      body: JSON.stringify({ id: 'rec-acme', tenant: 'acme', note: 'mutated' }),
    },
    {
      exchangeId: 'a401-after', method: 'GET', pathAndQuery: '/api/records/rec-acme', origin, status: 200,
      personaHandle: 'member_beta', actorRoleLabel: 'member (beta)', sessionRole: 'control',
      body: JSON.stringify({ id: 'rec-acme', tenant: 'acme', note: 'mutated' }),
    },
  ]
  const anon401Built = buildAgentScriptReceipt({
    claims: [{
      kind: 'impact',
      impactClass: 'authorization',
      probeExchangeId: 'a401-probe',
      controlExchangeIds: ['a401-ctrl'],
      beforeExchangeId: 'a401-before',
      afterExchangeId: 'a401-after',
      resourceTenant: 'acme',
      expectControlDenied: true,
    }],
    exchanges: anon401Exchanges,
    origin,
    title: 'Cross-tenant write with anon-401 control only',
  })
  assert.ok(anon401Built)
  const anon401Ver = verifyReceipt(anon401Built.receipt, anon401Built.transcript)
  assert.equal(anon401Ver.confirmed, false, 'anon=401 must not qualify as a peer control for a cross-tenant write')
  assert.equal((anon401Ver.evidence as { boundaryControlDenied?: boolean } | undefined)?.boundaryControlDenied, false, 'anon=401 must not count as a boundary control denial')
  assert.equal((anon401Ver.evidence as { crossTenant?: boolean } | undefined)?.crossTenant, false, 'anon=401 must not corroborate a declared resourceTenant')
})

// ---------------------------------------------------------------------------
// 3. runAgentScriptProof + persistAgentScriptProof + confirmation invariant
// ---------------------------------------------------------------------------

test('v7 agent-script-proofs: runAgentScriptProof + persistAgentScriptProof satisfy assertConfirmationEvidence and reject non-confirming verdicts', async (t) => {
  const fixture = await startTenantWriteFixture()
  t.after(() => fixture.close())
  const { storage } = makeStore(t)
  const { runId } = await setupApprovedRun(storage, { seeds: [fixture.origin], environment: 'local-lab', tier: 3 })
  const run = storage.run(runId)
  const asset = run.candidates[0]!
  const assignment = storage.makeWorker(run, 'verification', asset, 'Agent script proof fixture', 'fixture')

  const broker = new RequestBroker({ rejectUnauthorized: false })
  const grant = makeMultiTenantGrant(fixture.origin)
  const backend = makeFakeVerifyBackend(makeTenantWriteScriptHandler(fixture.origin, 'valid'))
  const execution = new Execution(storage, { backend, broker })
  t.after(() => execution.stop())

  const secretToken = 'SUPER_SECRET_BENCH_TOKEN_998877'
  const scriptSource = `// proof script using placeholder ${secretToken}\nexport default async () => ({ ok: true })\n`

  const proof = await runAgentScriptProof({
    script: scriptSource,
    runtime: 'ts',
    title: 'Cross-tenant record write',
    broker,
    grant,
    backend,
    runId: run.id,
    assignmentId: assignment.id,
    targetOrigins: [fixture.origin],
    signal: AbortSignal.timeout(20_000),
  })
  assert.equal(backend.calls, 2, 'runAgentScriptProof must execute two fresh attempts')
  assert.equal(proof.verdict.confirmed, true, proof.verdict.detail)
  assert.ok(proof.receipt, 'impact proof must produce a verified ProofReceipt')
  assert.equal(proof.receipt.verification.confirmed, true)
  assert.equal(proof.vulnClass, 'authorization')
  assert.equal(proof.transcriptDigests.length, 2)

  // Persist via Execution.persistAgentScriptProof and verify every persisted invariant.
  const execInternal = execution as unknown as {
    persistAgentScriptProof: (input: {
      run: Run
      assignment: Assignment
      script: string
      runtime: 'ts' | 'python'
      title?: string
      proof: AgentScriptProofResult
      secrets: ReadonlyArray<{ label: string; value: string }>
    }) => { findingId: string; replaySpecId: string; receiptId: string | null }
  }
  const persisted = execInternal.persistAgentScriptProof({
    run,
    assignment,
    script: scriptSource,
    runtime: 'ts',
    title: 'Cross-tenant record write',
    proof,
    secrets: [{ label: 'test_token', value: secretToken }],
  })
  assert.ok(persisted.findingId)
  assert.ok(persisted.replaySpecId)
  assert.ok(persisted.receiptId)

  // (a) Owner-only evidence artifact exists and redacted the secret.
  const artifactRow = storage.db.select().from(evidence).all().find(row => row.title.includes('Agent proof script'))
  assert.ok(artifactRow, 'owner-only script artifact must be persisted')
  const artifactContent = storage.artifact(run.id, artifactRow.id).content
  assert.equal(artifactContent.includes(secretToken), false, 'script artifact must be redacted at rest')
  const parsedArtifact = JSON.parse(artifactContent) as { mode: string; scriptSha256: string; receipt: unknown; verification: { confirmed: boolean } }
  assert.equal(parsedArtifact.mode, 'agent_script')
  assert.equal(parsedArtifact.scriptSha256, createHash('sha256').update(scriptSource).digest('hex'))
  assert.equal(parsedArtifact.verification.confirmed, true)

  // (b) replay_specs proof columns and attribution-only spec envelope are intact.
  const specRow = storage.getReplaySpec(run.id, persisted.replaySpecId)
  const envelopeInfo = persistedAgentScriptOf(specRow.spec)
  assert.ok(envelopeInfo, 'persisted spec must carry agentScript envelope')
  assert.equal(agentScriptProofEnvelopeSchema.safeParse(envelopeInfo.envelope).success, true)
  assert.equal(envelopeInfo.envelope.script.includes(secretToken), false, 'envelope script must be redacted at rest')
  assert.equal(envelopeInfo.envelope.vulnClass, 'authorization')

  const proofRecord = storage.replaySpecProof(run.id, persisted.replaySpecId)
  assert.ok(proofRecord)
  assert.equal(proofRecord.verdict, 'confirmed')
  assert.equal(proofRecord.artifactId, artifactRow.id)
  assert.equal(proofRecord.receipt?.verification.confirmed, true)

  // (c) Finding cites ProofReceipt and passes Store.assertConfirmationEvidence + zero conflicts.
  const findingRow = storage.db.select().from(findings).all().find(row => row.id === persisted.findingId)
  assert.ok(findingRow)
  assert.equal(findingRow.finding.status, 'confirmed')
  assert.equal(findingRow.verificationClass, 'runtime_confirmed')
  assert.match(findingRow.finding.verification ?? '', /^ProofReceipt /)
  const checkedEvidence = storage.assertConfirmationEvidence(run.id, {
    findingId: findingRow.id,
    replaySpecId: findingRow.replaySpecId,
    verification: findingRow.finding.verification,
    findingKind: findingRow.findingKind,
    verificationTier: findingRow.verificationTier,
    provenance: findingRow.provenance,
  })
  assert.equal(checkedEvidence.backed, true)
  assert.equal(storage.enforceConfirmationEvidence(run.id, findingRow.id, 'post-persist audit'), false)
  assert.equal(storage.confirmationConflictCount(run.id), 0)

  // (d) Non-confirming verdict MUST be rejected by persistAgentScriptProof (fail closed).
  const nonConfirmingProof: AgentScriptProofResult = {
    ...proof,
    verdict: { ...proof.verdict, confirmed: false, reason: 'oracle_failed', detail: 'Oracle rejected claim.' },
    receipt: null,
    vulnClass: null,
  }
  assert.throws(
    () => execInternal.persistAgentScriptProof({
      run,
      assignment,
      script: scriptSource,
      runtime: 'ts',
      title: 'Should never persist',
      proof: nonConfirmingProof,
      secrets: [],
    }),
    (err: unknown) => err instanceof InvariantError && err.code === 'invariant.confirmation_evidence',
    'persistAgentScriptProof must refuse non-confirming verdicts with InvariantError',
  )

  // (e) runAgentScriptProof fails closed when script lacks readback (oracle rejects).
  const badBackend = makeFakeVerifyBackend(makeTenantWriteScriptHandler(fixture.origin, 'missing_readback'))
  const rejectedProof = await runAgentScriptProof({
    script: scriptSource,
    runtime: 'ts',
    broker,
    grant,
    backend: badBackend,
    runId: run.id,
    assignmentId: assignment.id,
    targetOrigins: [fixture.origin],
    signal: AbortSignal.timeout(20_000),
  })
  assert.equal(rejectedProof.verdict.confirmed, false, 'missing readback must fail closed')
  assert.equal(rejectedProof.receipt, null)
})

// ---------------------------------------------------------------------------
// 4. Receipt-first short-circuit in Execution.executeInlineVerification
// ---------------------------------------------------------------------------

test('v7 agent-script-proofs: executeInlineVerification short-circuits receipt-first and demotes when patched', async (t) => {
  const fixture = await startTenantWriteFixture()
  t.after(() => fixture.close())
  const { storage } = makeStore(t)
  const { runId } = await setupApprovedRun(storage, { seeds: [fixture.origin], environment: 'local-lab', tier: 3 })
  const run = storage.run(runId)
  const asset = run.candidates[0]!
  const workerPhase = run.phase === 'discovery' || run.phase === 'investigation' || run.phase === 'verification'
    ? run.phase
    : 'retest'
  const queued = storage.makeWorker(run, workerPhase, asset, 'Inline short-circuit fixture', 'fixture')
  const assignment = storage.db.update(assignments).set({ status: 'running', lease: 'lease-inline-test' })
    .where(eq(assignments.id, queued.id)).returning().get()!

  const broker = new RequestBroker({ rejectUnauthorized: false })
  const grant = makeMultiTenantGrant(fixture.origin)
  const backend = makeFakeVerifyBackend(makeTenantWriteScriptHandler(fixture.origin, 'valid'))
  const execution = new Execution(storage, { backend, broker })
  t.after(() => execution.stop())

  const scriptSource = '// valid agent proof script\nexport default async () => ({ ok: true })\n'
  const initialProof = await runAgentScriptProof({
    script: scriptSource,
    runtime: 'ts',
    title: 'Cross-tenant record write',
    broker,
    grant,
    backend,
    runId: run.id,
    assignmentId: assignment.id,
    targetOrigins: [fixture.origin],
    signal: AbortSignal.timeout(20_000),
  })
  assert.equal(initialProof.verdict.confirmed, true)

  const execInternal = execution as unknown as {
    persistAgentScriptProof: (input: {
      run: Run
      assignment: Assignment
      script: string
      runtime: 'ts' | 'python'
      title?: string
      proof: AgentScriptProofResult
      secrets: ReadonlyArray<{ label: string; value: string }>
    }) => { findingId: string; replaySpecId: string; receiptId: string | null }
    executeInlineVerification: (params: {
      job: { assignment: Assignment; origins: Set<string>; controller: AbortController }
      grant: Grant
      currentSecrets: () => ReadonlyArray<{ label: string; value: string }>
      spec: DeclarativeReplaySpec
      findingId?: string
      replaySpecId?: string
    }) => Promise<{
      findingId?: string
      replaySpecId: string
      attemptCount: number
      status: string
      verificationTier?: string
      feedback: { verdict: string }
    }>
  }

  const persisted = execInternal.persistAgentScriptProof({
    run,
    assignment,
    script: scriptSource,
    runtime: 'ts',
    title: 'Cross-tenant record write',
    proof: initialProof,
    secrets: [],
  })

  // Deliberately malformed declarative spec: if executeInlineVerification did NOT short-circuit
  // receipt-first, `declarativeReplaySpecSchema.parse(params.spec)` would throw immediately!
  const unparseableDeclarativeSpec = { invalidDeclarativeShape: true } as unknown as DeclarativeReplaySpec
  const job = { assignment, origins: new Set([fixture.origin]), controller: new AbortController() }

  // (a) Short-circuit via direct replaySpecId lookup (e.g. verify_replay_spec).
  const callsBefore1 = backend.calls
  const reverify1 = await execInternal.executeInlineVerification({
    job,
    grant,
    currentSecrets: () => [],
    spec: unparseableDeclarativeSpec,
    findingId: persisted.findingId,
    replaySpecId: persisted.replaySpecId,
  })
  assert.equal(reverify1.status, 'confirmed')
  assert.equal(reverify1.verificationTier, 'runtime_confirmed')
  assert.equal(reverify1.replaySpecId, persisted.replaySpecId)
  assert.equal(reverify1.attemptCount, 2)
  assert.equal(backend.calls - callsBefore1, 2, 'must re-run the persisted script through fresh double-run')

  // (b) Short-circuit via findingId fallback even when a brand-new declarative replaySpecId (no
  //     proof columns) is passed — matching update_proposed_finding / propose_chain_finding.
  const decoySpec = storage.createReplaySpec(run, assignment, persisted.findingId, storage.getReplaySpec(run.id, persisted.replaySpecId).spec, [fixture.origin])
  const callsBefore2 = backend.calls
  const reverify2 = await execInternal.executeInlineVerification({
    job,
    grant,
    currentSecrets: () => [],
    spec: unparseableDeclarativeSpec,
    findingId: persisted.findingId,
    replaySpecId: decoySpec.id,
  })
  assert.equal(reverify2.status, 'confirmed')
  assert.equal(reverify2.replaySpecId, persisted.replaySpecId, 'must resolve the finding agent script proof row')
  assert.equal(reverify2.attemptCount, 3)
  assert.equal(backend.calls - callsBefore2, 2)

  // (c) After patching the target, receipt-first re-verification dismisses & demotes the finding cleanly.
  fixture.hardened = true
  const reverifyFixed = await execInternal.executeInlineVerification({
    job,
    grant,
    currentSecrets: () => [],
    spec: unparseableDeclarativeSpec,
    findingId: persisted.findingId,
    replaySpecId: persisted.replaySpecId,
  })
  assert.equal(reverifyFixed.status, 'dismissed')
  assert.equal(reverifyFixed.verificationTier, undefined)
  const demotedRow = storage.db.select().from(findings).all().find(row => row.id === persisted.findingId)!
  assert.equal(demotedRow.finding.status, 'dismissed')
  assert.equal(demotedRow.verificationClass, 'dismissed')
  const updatedProof = storage.replaySpecProof(run.id, persisted.replaySpecId)
  assert.equal(updatedProof?.verdict, 'dismissed')
  assert.equal(updatedProof?.receipt, null, 'dismissed proof must not retain stale confirmed receipt')
})

// ---------------------------------------------------------------------------
// 5. retestPersistedAgentScript via retestReplaySpec: reproduced vs fixed vs inconclusive
// ---------------------------------------------------------------------------

test('v7 agent-script-proofs: retestReplaySpec runs persisted agent script (reproduced vs fixed vs inconclusive) and bypasses legacy assertionsJq', async (t) => {
  const fixture = await startTenantWriteFixture()
  t.after(() => fixture.close())
  const { storage } = makeStore(t)
  const { runId } = await setupApprovedRun(storage, { seeds: [fixture.origin], environment: 'local-lab', tier: 3 })
  const run = storage.run(runId)
  const asset = run.candidates[0]!
  const assignment = storage.makeWorker(run, 'verification', asset, 'Retest agent script fixture', 'fixture')

  const broker = new RequestBroker({ rejectUnauthorized: false })
  const grant = makeMultiTenantGrant(fixture.origin)
  const backend = makeFakeVerifyBackend(makeTenantWriteScriptHandler(fixture.origin, 'valid'))
  const execution = new Execution(storage, { backend, broker })
  t.after(() => execution.stop())

  const scriptSource = '// persisted retest script\nexport default async () => ({ ok: true })\n'
  const proof = await runAgentScriptProof({
    script: scriptSource,
    runtime: 'ts',
    title: 'Cross-tenant record write',
    broker,
    grant,
    backend,
    runId: run.id,
    assignmentId: assignment.id,
    targetOrigins: [fixture.origin],
    signal: AbortSignal.timeout(20_000),
  })
  assert.equal(proof.verdict.confirmed, true)

  const persisted = (execution as unknown as {
    persistAgentScriptProof: (input: {
      run: Run
      assignment: Assignment
      script: string
      runtime: 'ts' | 'python'
      title?: string
      proof: AgentScriptProofResult
      secrets: ReadonlyArray<{ label: string; value: string }>
    }) => { findingId: string; replaySpecId: string; receiptId: string | null }
  }).persistAgentScriptProof({
    run,
    assignment,
    script: scriptSource,
    runtime: 'ts',
    title: 'Cross-tenant record write',
    proof,
    secrets: [],
  })

  const specRow = storage.getReplaySpec(run.id, persisted.replaySpecId)
  // Sabotage assertionsJq to prove retestReplaySpec routes strictly through retestPersistedAgentScript
  // and NEVER consults the legacy declarative VM.
  const sabotagedSpec = {
    ...specRow.spec,
    assertionsJq: '{ controlPassed: false, confirmed: false, observed: "legacy vm must not run", expected: "never" }',
  } as unknown as DeclarativeReplaySpec

  // (a) Still vulnerable -> 'reproduced' with fresh confirmed receipt.
  const stillVuln = await retestReplaySpec({
    spec: sabotagedSpec,
    broker,
    backend,
    grant,
    signal: AbortSignal.timeout(20_000),
    runId: run.id,
    assignmentId: assignment.id,
  })
  assert.equal(stillVuln.verdict, 'reproduced', stillVuln.replay.outcome.reason ?? stillVuln.replay.outcome.observed)
  assert.equal(stillVuln.replay.verdict, 'confirmed')
  assert.equal(stillVuln.replay.verificationTier, 'runtime_confirmed')
  assert.equal(stillVuln.replay.receipt?.verification.confirmed, true)
  assert.equal(stillVuln.replay.evidencePayload.mode, 'agent_script')

  // (b) Patched / hardened -> 'fixed' (verdict 'dismissed').
  fixture.hardened = true
  const afterPatch = await retestReplaySpec({
    spec: sabotagedSpec,
    broker,
    backend,
    grant,
    signal: AbortSignal.timeout(20_000),
    runId: run.id,
    assignmentId: assignment.id,
  })
  assert.equal(afterPatch.verdict, 'fixed', afterPatch.replay.outcome.reason ?? afterPatch.replay.outcome.observed)
  assert.equal(afterPatch.replay.verdict, 'dismissed')
  assert.equal(afterPatch.replay.receipt, undefined)

  // (c) Script execution error -> 'inconclusive' (never falsely 'fixed').
  const failingSpec = {
    ...specRow.spec,
    agentScript: {
      ...specRow.spec.agentScript!,
      script: '// THROW_EXECUTION_ERROR\n',
    },
  } as unknown as DeclarativeReplaySpec
  const errored = await retestReplaySpec({
    spec: failingSpec,
    broker,
    backend,
    grant,
    signal: AbortSignal.timeout(20_000),
    runId: run.id,
    assignmentId: assignment.id,
  })
  assert.equal(errored.verdict, 'inconclusive', errored.replay.outcome.reason ?? errored.replay.outcome.observed)
  assert.equal(errored.replay.verdict, 'inconclusive')
})

// ---------------------------------------------------------------------------
// 6. Strict ProofReceipt gate: receiptless mutating boundary claims fail closed
// ---------------------------------------------------------------------------

test('v7 agent-script-proofs: mutating POST boundary claim without readback fails closed and refuses receiptless persistence', async (t) => {
  const fixture = await startTenantWriteFixture()
  t.after(() => fixture.close())
  const { storage } = makeStore(t)
  // Local endpoint where both owner_acme and member_beta receive 200 on POST (reproduces #150's
  // mutating boundary claim without before/after readback: assessBoundary passes the actor
  // differential, buildAgentScriptReceipt returns null for mutating boundary claims, and
  // runAgentScriptProof MUST fail closed with rejectedBy='receipt' instead of confirming a
  // receiptless CWE-200 FP).
  const postServer = createServer((req, res) => {
    res.setHeader('content-type', 'application/json')
    if (req.method === 'POST' && req.url === '/api/inbox/alert-1/read') {
      res.statusCode = 200
      res.end(JSON.stringify({ id: 'alert-1', read: true }))
      return
    }
    res.statusCode = 404
    res.end(JSON.stringify({ error: 'not found' }))
  })
  postServer.listen(0, '127.0.0.1')
  await once(postServer, 'listening')
  t.after(() => {
    postServer.closeAllConnections()
    postServer.close()
  })
  const postOrigin = `http://127.0.0.1:${(postServer.address() as { port: number }).port}`
  const { runId } = await setupApprovedRun(storage, { seeds: [postOrigin], environment: 'local-lab', tier: 3 })
  const run = storage.run(runId)
  const asset = run.candidates[0]!
  const assignment = storage.makeWorker(run, 'verification', asset, 'Mutating boundary fail-closed', 'fixture')

  const broker = new RequestBroker({ rejectUnauthorized: false })
  const grant = makeMultiTenantGrant(postOrigin)

  const mutatingBoundaryBackend = makeFakeVerifyBackend(async ({ rpc }) => {
    const ctrl = await rpc('http', {
      origin: postOrigin,
      method: 'POST',
      path: '/api/inbox/alert-1/read',
      persona: 'owner_acme',
      sessionGroupRole: 'control',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ read: true }),
    })
    assert.equal(ctrl.ok, true, ctrl.error ?? 'ctrl RPC failed')
    const probe = await rpc('http', {
      origin: postOrigin,
      method: 'POST',
      path: '/api/inbox/alert-1/read',
      persona: 'member_beta',
      sessionGroupRole: 'probe',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ read: true }),
    })
    assert.equal(probe.ok, true, probe.error ?? 'probe RPC failed')
    return {
      runtime: 'ts',
      result: {
        title: 'Mutating POST boundary without readback',
        severity: 'high',
        claims: [{
          kind: 'boundary',
          boundaryClass: 'access',
          controlExchangeId: String(ctrl.result!.exchangeId),
          probeExchangeId: String(probe.result!.exchangeId),
          expectControlDenied: false,
        }],
      },
      stdout: '',
      stderr: '',
      exitCode: 0,
      durationMs: 10,
      timedOut: false,
    }
  })

  const proof = await runAgentScriptProof({
    script: '// mutating POST boundary without readback\n',
    runtime: 'ts',
    title: 'Mutating POST boundary without readback',
    broker,
    grant,
    backend: mutatingBoundaryBackend,
    runId: run.id,
    assignmentId: assignment.id,
    targetOrigins: [postOrigin],
    signal: AbortSignal.timeout(20_000),
  })

  assert.equal(proof.verdict.confirmed, false, 'mutating boundary claim without ProofReceipt MUST fail closed')
  assert.equal(proof.verdict.rejectedBy, 'receipt')
  assert.ok(proof.verdict.missingEvidence?.includes('verified_proof_receipt'))
  assert.equal(proof.receipt, null)

  // Even if a caller artificially forces verdict.confirmed=true with receipt=null, persistAgentScriptProof
  // MUST throw InvariantError and leave zero findings persisted.
  const execution = new Execution(storage, { backend: mutatingBoundaryBackend, broker })
  t.after(() => execution.stop())
  const execInternal = execution as unknown as {
    persistAgentScriptProof: (input: {
      run: Run
      assignment: Assignment
      script: string
      runtime: 'ts' | 'python'
      title?: string
      proof: AgentScriptProofResult
      secrets: ReadonlyArray<{ label: string; value: string }>
    }) => { findingId: string; replaySpecId: string; receiptId: string | null }
  }
  const forgedReceiptless: AgentScriptProofResult = {
    ...proof,
    verdict: { ...proof.verdict, confirmed: true, reason: 'confirmed' },
    receipt: null,
  }
  assert.throws(
    () => execInternal.persistAgentScriptProof({
      run,
      assignment,
      script: '// receiptless forged proof\n',
      runtime: 'ts',
      title: 'Must not persist CWE-200 FP',
      proof: forgedReceiptless,
      secrets: [],
    }),
    (err: unknown) => err instanceof InvariantError && err.code === 'invariant.confirmation_evidence',
    'persistAgentScriptProof must reject receiptless confirmations',
  )
  assert.equal(storage.db.select().from(findings).all().length, 0, 'no receiptless finding may be persisted')
})
