/**
 * v8 Live Execution Seam Wiring Integration Tests (`agent-session.ts`, `exec-verify.ts`, `execution.ts`).
 *
 * Proves end-to-end (zero Docker, real SQLite WAL `Store`, real `Execution`, real `RequestBroker`,
 * real `VerifyRpcServer`, real loopback HTTP fixture):
 *  1. ONE run-scoped `DerivedCapabilityVault` persists sealed handles across two separate
 *     `VerifyRpcServer` worker sessions (Worker 1 seals `cap:hop_h1:salt` -> Worker 2 signs JWT/HMAC
 *     and injects via Layer 1 without raw secret exposure into LLM context/transcripts/DB).
 *  2. Verified `CompositeProofReceipt` persists cleanly to `Store` (`replay_specs.spec`,
 *     `replay_specs.proof_receipt`, `findings.finding.evidence`, owner-only artifact), satisfies
 *     `scripts/audit-confirmation-consistency.ts` (0 conflicts), `extractCompositeReceipts`
 *     (`scripts/benchmark-multihop.ts`), and `extractStoreCompositeReceipts` (`receipt-export.ts`),
 *     while `capability_only` intermediates are NEVER promoted to standalone findings.
 *  3. `record_coverage(proofGapReason="invariant_enforced_hardened" | "control_blocked_cleanly" |
 *     "decoy_guard_verified")` validates in `SpecSubmissionTracker`, records negative edges in
 *     `CapabilityLedger`, and triggers 2-strike pruning in `FrontierWaveController` so sibling
 *     workers never re-probe pruned dead ends.
 *  4. Verified `HopReceipt` counts per round flow into `FrontierWaveController` + `nextPlannerDryRounds`
 *     so Phase B keeps advancing multi-hop chains when Hop 2/3 expands reach before terminal confirmation.
 */
import assert from 'node:assert/strict'
import { execFile } from 'node:child_process'
import { createHmac } from 'node:crypto'
import { once } from 'node:events'
import { mkdtempSync, readFileSync, rmSync } from 'node:fs'
import { createServer, request as httpRequest } from 'node:http'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import test from 'node:test'
import { fileURLToPath } from 'node:url'
import { promisify } from 'node:util'
import { eq } from 'drizzle-orm'

import { extractCompositeReceipts } from '../scripts/benchmark-multihop.ts'
import type { Finding } from '../src/domain.ts'
import {
  NEGATIVE_EDGE_PROOF_GAP_CODES,
  SpecSubmissionTracker,
  buildWorkerTools,
  parseNegativeEdgeGapReason,
  selectPreInjectionSkills,
  summarizeKovoVerifyOutcome,
} from '../src/server/agent-session.ts'
import { RequestBroker, type Grant } from '../src/server/broker.ts'
import { Execution, FrontierWaveController, nextPlannerDryRounds, runV8AgentScriptProof, syncVerifyArtifactsToLedger } from '../src/server/execution.ts'
import type { ResolvedPersona } from '../src/server/persona-vault.ts'
import { extractStoreCompositeReceipts } from '../src/server/receipt-export.ts'
import { evidence, findings, replaySpecs } from '../src/server/schema.ts'
import { InvariantError, Store } from '../src/server/store.ts'
import {
  VERIFY_NONCE_HEADER,
  VERIFY_RPC_HEADER,
  VERIFY_RPC_SOCKET_NAME,
  VERIFY_RPC_TOKEN_NAME,
} from '../src/server/verify-rpc.ts'
import type {
  VerifyScriptRequest,
  VerifyScriptResult,
  WorkerBackend,
  WorkerSession,
  WorkerSessionOptions,
} from '../src/server/worker-backend.ts'
import { setupApprovedRun } from './v4-tier-helpers.ts'

process.env.KOVO_ALLOW_LOCAL_LAB = '1'

const execFileAsync = promisify(execFile)
const REPO_ROOT = join(dirname(fileURLToPath(import.meta.url)), '..')
const RAW_SIGNING_SALT = 's_v8_exec_wire_secret_salt_7a6b5c4d3e2f'

function makeStore(t: { after: (fn: () => void) => void }): { storage: Store; dir: string } {
  const dir = mkdtempSync(join(tmpdir(), 'kovo-v8-exec-wire-'))
  const storage = new Store(dir)
  t.after(() => {
    storage.close()
    rmSync(dir, { recursive: true, force: true })
  })
  return { storage, dir }
}

function makePersona(handle: string, roleLabel: string, token: string, origin: string): ResolvedPersona {
  return {
    id: `persona-${handle}`,
    handle,
    roleLabel,
    originAllowlist: [origin],
    authKind: 'bearer',
    headerName: null,
    secret: token,
    canaryMarkers: [],
  }
}

function makeGrant(origin: string, personas: ResolvedPersona[]): Grant {
  return {
    canRead: (candidate: string) => {
      try { return new URL(candidate).origin === origin } catch { return false }
    },
    audit: () => undefined,
    allowLocalLab: true,
    tier: 3,
    isStateChangeApproved: () => true,
    personas: new Map(personas.map(p => [p.handle, p])),
  }
}

function verifyHs256Jwt(authHeader: string, secret: string): Record<string, unknown> | null {
  const match = /^Bearer\s+([A-Za-z0-9_-]+)\.([A-Za-z0-9_-]+)\.([A-Za-z0-9_-]+)$/i.exec(authHeader.trim())
  if (!match) return null
  const expected = createHmac('sha256', secret).update(`${match[1]}.${match[2]}`, 'utf8').digest('base64url')
  if (expected !== match[3]) return null
  try {
    return JSON.parse(Buffer.from(match[2]!, 'base64url').toString('utf8')) as Record<string, unknown>
  } catch {
    return null
  }
}

function rpcCall(
  socketPath: string,
  token: string,
  nonce: string,
  op: string,
  args: Record<string, unknown>,
): Promise<{ ok: boolean; result?: unknown; error?: string }> {
  const payload = JSON.stringify({ op, args })
  return new Promise((resolvePromise, rejectPromise) => {
    const req = httpRequest({
      socketPath,
      path: '/rpc',
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        'content-length': Buffer.byteLength(payload),
        [VERIFY_RPC_HEADER]: token,
        [VERIFY_NONCE_HEADER]: nonce,
      },
    }, res => {
      const chunks: Buffer[] = []
      res.on('data', (c: Buffer) => chunks.push(c))
      res.on('end', () => {
        try {
          resolvePromise(JSON.parse(Buffer.concat(chunks).toString('utf8')) as { ok: boolean; result?: unknown; error?: string })
        } catch (err) {
          rejectPromise(err)
        }
      })
    })
    req.on('error', rejectPromise)
    req.end(payload)
  })
}

async function startMultiHopTarget(): Promise<{ origin: string; close: () => Promise<void> }> {
  const server = createServer((req, res) => {
    const url = new URL(req.url ?? '/', 'http://127.0.0.1')
    const auth = String(req.headers.authorization ?? '')
    res.setHeader('content-type', 'application/json')

    // Hop 1: member_b reads a diagnostic metadata route leaking a signing salt.
    if (url.pathname === '/api/debug/meta' && req.method === 'GET') {
      if (auth !== 'Bearer tok-member-beta' && auth !== 'Bearer tok-owner-acme') {
        res.statusCode = 401
        res.end(JSON.stringify({ error: 'unauthorized' }))
        return
      }
      res.statusCode = 200
      res.end(JSON.stringify({
        service: 'ledger-edge',
        signing_salt: RAW_SIGNING_SALT,
        banner: `raw-salt=${RAW_SIGNING_SALT}`,
      }))
      return
    }

    // Hop 2: signed webhook route requiring HMAC-SHA256(body, RAW_SIGNING_SALT).
    if (url.pathname === '/api/webhooks/settle' && req.method === 'POST') {
      let body = ''
      req.on('data', chunk => { body += chunk })
      req.on('end', () => {
        const sig = String(req.headers['x-webhook-signature'] ?? '')
        const expected = createHmac('sha256', RAW_SIGNING_SALT).update(body, 'utf8').digest('hex')
        if (!sig || sig !== expected) {
          res.statusCode = 403
          res.end(JSON.stringify({ error: 'invalid signature' }))
          return
        }
        res.statusCode = 200
        res.end(JSON.stringify({ settled: true, status: 'disbursed' }))
      })
      return
    }

    // Hop 3: privileged export route accepting owner_a OR an HS256 JWT signed with RAW_SIGNING_SALT.
    if (url.pathname === '/api/vault/export' && req.method === 'GET') {
      if (auth === 'Bearer tok-owner-acme') {
        res.statusCode = 200
        res.end(JSON.stringify({ tenant: 'acme', records: 9 }))
        return
      }
      const claims = verifyHs256Jwt(auth, RAW_SIGNING_SALT)
      if (claims && claims.scope === 'vault:export') {
        res.statusCode = 200
        // Deliberately echo Authorization + salt to verify Layer-1 derived scrubbing.
        res.end(JSON.stringify({
          tenant: 'acme',
          records: 9,
          echoAuth: auth,
          echoSalt: RAW_SIGNING_SALT,
        }))
        return
      }
      res.statusCode = 403
      res.end(JSON.stringify({ error: 'forbidden' }))
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
    close: async () => {
      server.closeAllConnections()
      await new Promise<void>(resolveClose => server.close(() => resolveClose()))
    },
  }
}

type RpcClient = (op: string, args: Record<string, unknown>) => Promise<{ ok: boolean; result?: unknown; error?: string }>

/** In-process fake WorkerBackend wired to the real VerifyRpcServer Unix socket (zero Docker). */
function makeRpcBackend(
  handler: (req: VerifyScriptRequest, rpc: RpcClient) => Promise<VerifyScriptResult>,
): WorkerBackend {
  return {
    async run() {
      return { exitCode: 0, stdout: '', stderr: '', outputs: {} }
    },
    async verifyStaticAst() {
      throw new Error('Fake verify backend does not support verifyStaticAst().')
    },
    async openSession(_assignmentId: string, _signal: AbortSignal, options?: WorkerSessionOptions): Promise<WorkerSession> {
      const mountDir = options?.rpcMountDir ?? ''
      const socketPath = join(mountDir, VERIFY_RPC_SOCKET_NAME)
      const token = mountDir ? readFileSync(join(mountDir, VERIFY_RPC_TOKEN_NAME), 'utf8').trim() : ''
      return {
        async stage() { throw new Error('stage() not implemented') },
        async exec() { throw new Error('exec() not implemented') },
        async analyze() { throw new Error('analyze() not implemented') },
        async sast() { throw new Error('sast() not implemented') },
        async runScript() {
          return { runtime: 'python', exitCode: 0, stdout: '', stderr: '', timedOut: false, durationMs: 0 }
        },
        async verifyStaticAst() { throw new Error('verifyStaticAst() not implemented') },
        async verifyScript(req: VerifyScriptRequest): Promise<VerifyScriptResult> {
          const rpc: RpcClient = (op, args) => rpcCall(socketPath, token, req.nonce, op, args)
          return handler(req, rpc)
        },
        async close() { /* noop */ },
      }
    },
  }
}

test('1. Run-scoped DerivedCapabilityVault persists sealed handles across two VerifyRpcServer worker sessions without raw secret exposure', async (t) => {
  const target = await startMultiHopTarget()
  t.after(() => target.close())
  const { storage } = makeStore(t)
  const { runId } = await setupApprovedRun(storage, { seeds: [target.origin], environment: 'local-lab', tier: 3 })
  const run = storage.run(runId)
  const asset = run.candidates[0]!
  const assignment1 = storage.makeWorker(run, 'investigation', asset, 'Worker 1 (Hop 1)', 'Seal signing salt')
  const broker = new RequestBroker({ rejectUnauthorized: false })
  const grant = makeGrant(target.origin, [
    makePersona('member_b', 'member (beta)', 'tok-member-beta', target.origin),
    makePersona('owner_a', 'owner (acme)', 'tok-owner-acme', target.origin),
  ])

  const execution = new Execution(storage, { broker })
  t.after(() => { void execution.stop() })

  const vaultA = execution.capabilityVaultFor(runId)
  const vaultB = execution.capabilityVaultFor(runId)
  const vaultOther = execution.capabilityVaultFor('other-run-id')
  assert.equal(vaultA, vaultB, 'Execution must return ONE shared DerivedCapabilityVault per run')
  assert.notEqual(vaultA, vaultOther, 'Separate runs must receive isolated DerivedCapabilityVault instances')

  let sealedHandle = ''
  const worker1Outputs: string[] = []
  const worker1Backend = makeRpcBackend(async (req, rpc) => {
    const hop1 = await rpc('http.send', {
      origin: target.origin,
      method: 'GET',
      path: '/api/debug/meta',
      persona: 'member_b',
      sessionGroupRole: 'probe',
    })
    assert.equal(hop1.ok, true)
    const hop1Res = hop1.result as { exchangeId: string; status: number }
    assert.equal(hop1Res.status, 200)

    const sealed = await rpc('capability.seal', {
      exchangeId: hop1Res.exchangeId,
      hopReceiptId: 'h1',
      slot: 'signing_salt',
      jsonPath: 'signing_salt',
      kind: 'signing_salt',
      allowedOrigins: [target.origin],
    })
    assert.equal(sealed.ok, true)
    const sealedRes = sealed.result as { handle: string; scrubbedPreview: string }
    sealedHandle = sealedRes.handle
    worker1Outputs.push(JSON.stringify(sealedRes))

    return {
      runtime: req.runtime,
      result: { sdk: 'kovo_verify.ts', nonce: req.nonce, title: 'Hop 1 capability seal', claims: [] },
      stdout: '',
      stderr: '',
      exitCode: 0,
      durationMs: 5,
      timedOut: false,
    }
  })

  // Worker 1 executes in Round 1 and seals `cap:hop_h1:signing_salt` into the run-scoped vault.
  const worker1Proof = await runV8AgentScriptProof({
    script: '// worker 1 intermediate hop',
    runtime: 'ts',
    broker,
    grant,
    backend: worker1Backend,
    runId,
    assignmentId: assignment1.id,
    targetOrigins: [target.origin],
    signal: AbortSignal.timeout(15_000),
    capabilityVault: vaultA,
  })
  assert.equal(sealedHandle, 'cap:hop_h1:signing_salt')
  assert.equal(worker1Proof.verdict.confirmed, false, 'Intermediate seal alone must never confirm a finding')
  assert.equal(worker1Proof.sealedCapabilities.some(m => m.handle === sealedHandle), true)

  const sync1 = syncVerifyArtifactsToLedger({
    ledger: storage.capabilityLedger(runId),
    proof: worker1Proof,
    defaultOrigin: target.origin,
    defaultPersona: 'member_b',
  })
  assert.equal(sync1.sealedCapabilities.length >= 1, true)
  const capNode = storage.capabilityLedger(runId).getCapability(sealedHandle)
  assert.ok(capNode, 'Sealed capability must persist into CapabilityLedger')
  assert.equal(capNode.promotionStatus, 'capability_only', 'Intermediate capability MUST stay strictly capability_only')
  assert.equal(capNode.terminalImpactOracleVerified, false)

  // Intermediate capabilities MUST NEVER be promoted to standalone findings.
  assert.throws(
    () => (execution as unknown as {
      persistAgentScriptProof: (arg: Record<string, unknown>) => unknown
    }).persistAgentScriptProof({
      run,
      assignment: assignment1,
      script: '// worker 1 intermediate hop',
      runtime: 'ts',
      proof: worker1Proof,
      secrets: [],
    }),
    (err: unknown) => err instanceof InvariantError && err.code === 'invariant.confirmation_evidence',
    'capability_only intermediate must fail closed if promotion is attempted',
  )
  assert.equal(storage.db.select().from(findings).where(eq(findings.runId, runId)).all().length, 0)

  // Worker 2 opens a completely separate VerifyRpcServer session in Round 2 using the SAME run vault,
  // and immediately signs HMAC + mints JWT + injects via Layer 1 WITHOUT ever calling Hop 1 or seeing RAW_SIGNING_SALT!
  const assignment2 = storage.makeWorker(run, 'investigation', asset, 'Worker 2 (Hop 2-3)', 'Use sealed handle')
  const worker2Outputs: string[] = []
  let hop2Status = 0
  let hop3Status = 0
  let derivedJwtHandle = ''

  const worker2Backend = makeRpcBackend(async (req, rpc) => {
    const body = JSON.stringify({ orderId: 'ord-1', amount: 100 })
    const hmac = await rpc('crypto.hmacSign', {
      secretHandle: sealedHandle,
      payload: body,
      alg: 'sha256',
      encoding: 'hex',
    })
    assert.equal(hmac.ok, true, `Worker 2 must be able to sign with Worker 1's handle: ${hmac.error}`)
    const hmacRes = hmac.result as { signature: string }
    worker2Outputs.push(JSON.stringify(hmacRes))

    const settle = await rpc('http.send', {
      origin: target.origin,
      method: 'POST',
      path: '/api/webhooks/settle',
      headers: { 'content-type': 'application/json', 'x-webhook-signature': hmacRes.signature },
      body,
      persona: 'member_b',
      sessionGroupRole: 'probe',
    })
    assert.equal(settle.ok, true)
    hop2Status = (settle.result as { status: number }).status

    const minted = await rpc('crypto.jwtSign', {
      secretHandle: sealedHandle,
      claims: { sub: 'member_b', scope: 'vault:export' },
      alg: 'HS256',
      hopReceiptId: 'h2',
      slot: 'vault_jwt',
      allowedOrigins: [target.origin],
    })
    assert.equal(minted.ok, true)
    const mintedRes = minted.result as { derivedHandle: string }
    derivedJwtHandle = mintedRes.derivedHandle
    worker2Outputs.push(JSON.stringify(mintedRes))

    const exportRes = await rpc('http.send', {
      origin: target.origin,
      method: 'GET',
      path: '/api/vault/export',
      capability: { handle: derivedJwtHandle, target: 'bearer' },
      sessionGroupRole: 'probe',
    })
    assert.equal(exportRes.ok, true)
    const exportObj = exportRes.result as { status: number; bodyPreview: string }
    hop3Status = exportObj.status
    worker2Outputs.push(JSON.stringify(exportObj))

    return {
      runtime: req.runtime,
      result: { sdk: 'kovo_verify.ts', nonce: req.nonce, title: 'Worker 2 pivot', claims: [] },
      stdout: '',
      stderr: '',
      exitCode: 0,
      durationMs: 5,
      timedOut: false,
    }
  })

  const worker2Proof = await runV8AgentScriptProof({
    script: '// worker 2 uses cap:hop_h1:signing_salt',
    runtime: 'ts',
    broker,
    grant,
    backend: worker2Backend,
    runId,
    assignmentId: assignment2.id,
    targetOrigins: [target.origin],
    signal: AbortSignal.timeout(15_000),
    capabilityVault: vaultB,
  })
  assert.equal(hop2Status, 200, 'Worker 2 HMAC-signed webhook must succeed using Worker 1 handle')
  assert.equal(hop3Status, 200, 'Worker 2 Layer-1 capability-injected vault export must succeed')
  assert.equal(derivedJwtHandle, 'cap:hop_h2:vault_jwt')

  const sync2 = syncVerifyArtifactsToLedger({
    ledger: storage.capabilityLedger(runId),
    proof: worker2Proof,
    defaultOrigin: target.origin,
    defaultPersona: 'member_b',
  })
  assert.equal(sync2.verifiedHops.some(h => h.binding === 'derived_crypto_binding'), true)

  // Raw secret MUST NEVER appear in any RPC output, tool summary, transcript, or CapabilityLedger row!
  const summary2 = summarizeKovoVerifyOutcome({
    ...worker2Proof.verdict,
    sealedCapabilities: sync2.sealedCapabilities,
    verifiedHops: sync2.verifiedHops,
  })
  const allSurfaces = [
    ...worker1Outputs,
    ...worker2Outputs,
    JSON.stringify(summary2),
    JSON.stringify(worker2Proof.exchanges),
    JSON.stringify(storage.capabilityLedger(runId).listCapabilities()),
    JSON.stringify(storage.capabilityLedger(runId).listCausalEdges()),
  ].join('\n')
  assert.equal(allSurfaces.includes(RAW_SIGNING_SALT), false, 'Raw signing salt must NEVER leak into LLM/transcript/ledger surfaces')
  assert.equal(allSurfaces.includes('eyJhbGci'), false, 'Raw minted JWT must NEVER leak into LLM/transcript/ledger surfaces')
})

test('2. Verified CompositeProofReceipt persists cleanly to Store, satisfies audit-confirmation-consistency, benchmark-multihop & receipt-export, while intermediates stay capability_only', async (t) => {
  const target = await startMultiHopTarget()
  t.after(() => target.close())
  const { storage, dir } = makeStore(t)
  const { runId } = await setupApprovedRun(storage, { seeds: [target.origin], environment: 'local-lab', tier: 3 })
  const run = storage.run(runId)
  const asset = run.candidates[0]!
  const assignment = storage.makeWorker(run, 'investigation', asset, 'Multi-hop composite worker', 'Verify 3-hop chain')
  const broker = new RequestBroker({ rejectUnauthorized: false })
  const grant = makeGrant(target.origin, [
    makePersona('member_b', 'member (beta)', 'tok-member-beta', target.origin),
    makePersona('owner_a', 'owner (acme)', 'tok-owner-acme', target.origin),
  ])

  const execution = new Execution(storage, { broker })
  t.after(() => { void execution.stop() })
  const vault = execution.capabilityVaultFor(runId)

  const chainBackend = makeRpcBackend(async (req, rpc) => {
    const preDenied = await rpc('http.send', {
      origin: target.origin,
      method: 'GET',
      path: '/api/vault/export',
      persona: 'member_b',
      sessionGroupRole: 'control',
    })
    const preDeniedId = (preDenied.result as { exchangeId: string }).exchangeId

    const hop1 = await rpc('http.send', {
      origin: target.origin,
      method: 'GET',
      path: '/api/debug/meta',
      persona: 'member_b',
      sessionGroupRole: 'probe',
    })
    const hop1Id = (hop1.result as { exchangeId: string }).exchangeId
    const sealed = await rpc('capability.seal', {
      exchangeId: hop1Id,
      hopReceiptId: 'c1',
      slot: 'salt',
      jsonPath: 'signing_salt',
      kind: 'signing_salt',
      allowedOrigins: [target.origin],
    })
    const saltHandle = (sealed.result as { handle: string }).handle

    const minted = await rpc('crypto.jwtSign', {
      secretHandle: saltHandle,
      claims: { sub: 'member_b', scope: 'vault:export' },
      alg: 'HS256',
      hopReceiptId: 'c2',
      slot: 'jwt',
      allowedOrigins: [target.origin],
    })
    const mintedObj = minted.result as { exchangeId: string; derivedHandle: string }

    const hop3 = await rpc('http.send', {
      origin: target.origin,
      method: 'GET',
      path: '/api/vault/export',
      capability: { handle: mintedObj.derivedHandle, target: 'bearer' },
      sessionGroupRole: 'probe',
    })
    const hop3Id = (hop3.result as { exchangeId: string }).exchangeId

    const compositeReceipt = {
      chainId: 'chain-exec-wire-crypto-1',
      terminalVulnClass: 'cryptographic_scope_replay',
      replayMode: 'fresh_clean_replay',
      hops: [
        {
          hopId: 'hop-1',
          surface: 'http',
          target: { origin: target.origin, method: 'GET', pathAndQuery: '/api/debug/meta' },
          exchangeIds: [hop1Id],
          claimedDelta: 'Low-privilege member_b seals runtime signing salt handle from metadata route.',
          producedCapabilities: [saltHandle],
          consumedCapabilities: [],
        },
        {
          hopId: 'hop-2',
          surface: 'http',
          target: { origin: target.origin, method: 'POST', pathAndQuery: '/crypto/jwt/HS256' },
          exchangeIds: [mintedObj.exchangeId],
          claimedDelta: 'Host signs scoped HS256 JWT derived from sealed signing salt handle.',
          producedCapabilities: [mintedObj.derivedHandle],
          consumedCapabilities: [saltHandle],
        },
        {
          hopId: 'hop-3',
          surface: 'http',
          target: { origin: target.origin, method: 'GET', pathAndQuery: '/api/vault/export' },
          exchangeIds: [hop3Id],
          claimedDelta: 'Layer-1 injects derived JWT handle to read restricted acme vault export.',
          producedCapabilities: [],
          consumedCapabilities: [mintedObj.derivedHandle],
        },
      ],
      causalEdges: [
        {
          kind: 'derived_crypto_binding',
          fromHopId: 'hop-1',
          toHopId: 'hop-2',
          sourceCapabilityId: saltHandle,
          derivedCapabilityId: mintedObj.derivedHandle,
          alg: 'HS256',
        },
        {
          kind: 'value_binding',
          fromHopId: 'hop-2',
          toHopId: 'hop-3',
          capabilityHandle: mintedObj.derivedHandle,
        },
      ],
      terminalImpact: {
        terminalHopId: 'hop-3',
        claimedImpact: 'Cross-tenant restricted vault export accessed via derived HS256 JWT.',
        preChainControlExchangeIds: [preDeniedId],
        postChainReadbackExchangeIds: [hop3Id],
      },
    }

    const verified = await rpc('composite.verify', { receipt: compositeReceipt })
    assert.equal(verified.ok, true)
    assert.equal((verified.result as { confirmed: boolean }).confirmed, true, JSON.stringify(verified.result))

    return {
      runtime: req.runtime,
      result: {
        sdk: 'kovo_verify.ts',
        nonce: req.nonce,
        title: 'Multi-hop cryptographic scope replay into restricted vault export',
        severity: 'critical',
        claims: [],
      },
      stdout: '',
      stderr: '',
      exitCode: 0,
      durationMs: 12,
      timedOut: false,
    }
  })

  const proof = await runV8AgentScriptProof({
    script: '// 3-hop composite verification script',
    runtime: 'ts',
    title: 'Multi-hop cryptographic scope replay into restricted vault export',
    broker,
    grant,
    backend: chainBackend,
    runId,
    assignmentId: assignment.id,
    targetOrigins: [target.origin],
    signal: AbortSignal.timeout(15_000),
    capabilityVault: vault,
    compositeVerifyOptions: { attackerPersonas: ['member_b'], forbiddenShortcutPersonas: ['owner_a'] },
  })
  assert.equal(proof.verdict.confirmed, true, proof.verdict.detail)
  assert.ok(proof.compositeReceipt?.verification.confirmed)

  // Sync to CapabilityLedger: Hop 1 & Hop 2 intermediate capabilities stay strictly capability_only.
  const ledger = storage.capabilityLedger(runId)
  syncVerifyArtifactsToLedger({ ledger, proof, defaultOrigin: target.origin, defaultPersona: 'member_b' })
  assert.equal(ledger.getCapability('cap:hop_c1:salt')?.promotionStatus, 'capability_only')
  assert.equal(ledger.getCapability('cap:hop_c2:jwt')?.promotionStatus, 'capability_only')

  // Persist confirmed CompositeProofReceipt finding to Store.
  const persisted = (execution as unknown as {
    persistAgentScriptProof: (arg: Record<string, unknown>) => { findingId: string; replaySpecId: string; receiptId: string | null }
  }).persistAgentScriptProof({
    run,
    assignment,
    script: '// 3-hop composite verification script',
    runtime: 'ts',
    title: 'Multi-hop cryptographic scope replay into restricted vault export',
    proof,
    secrets: [],
  })
  assert.equal(persisted.receiptId, 'chain-exec-wire-crypto-1')

  // 1) benchmark-multihop.ts extractCompositeReceipts reads it directly from Store!
  const detail = storage.runDetail(runId)
  const extractedBench = extractCompositeReceipts({
    findings: detail.findings as Finding[],
    replaySpecs: detail.replaySpecs.map(r => ({ id: r.id, findingId: r.findingId, spec: r.spec })),
  })
  assert.equal(extractedBench.length, 1)
  assert.equal(extractedBench[0]!.chainId, 'chain-exec-wire-crypto-1')
  assert.equal(extractedBench[0]!.terminalVulnClass, 'cryptographic_scope_replay')
  assert.equal(extractedBench[0]!.replayMode, 'fresh_clean_replay')
  assert.equal(extractedBench[0]!.confirmed, true)
  assert.equal(extractedBench[0]!.attackerProvenanceValid, true)
  assert.equal(extractedBench[0]!.hopCount, 3)

  // 2) receipt-export.ts extractStoreCompositeReceipts reads it from replay_specs.proof_receipt!
  const specRows = storage.db.select().from(replaySpecs).where(eq(replaySpecs.runId, runId)).all()
  const extractedExport = extractStoreCompositeReceipts(specRows)
  assert.equal(extractedExport.length, 1)
  assert.equal(extractedExport[0]!.receipt.chainId, 'chain-exec-wire-crypto-1')
  assert.equal(extractedExport[0]!.verification?.confirmed, true)
  assert.equal(extractedExport[0]!.hopActors?.['hop-1'], 'member_b')

  // 3) scripts/audit-confirmation-consistency.ts passes with 0 conflicts!
  const auditOut = await execFileAsync(process.execPath, [
    join(REPO_ROOT, 'scripts/audit-confirmation-consistency.ts'),
    '--data-dir',
    dir,
  ])
  const parsedAudit = JSON.parse(auditOut.stdout.trim()) as { confirmed: number; conflicts: number }
  assert.equal(parsedAudit.confirmed, 1)
  assert.equal(parsedAudit.conflicts, 0)

  // 4) Zero raw secrets persisted in Store tables (findings, replay_specs, evidence).
  const dbDump = JSON.stringify([
    storage.db.select().from(findings).where(eq(findings.runId, runId)).all(),
    specRows,
    storage.db.select().from(evidence).where(eq(evidence.runId, runId)).all(),
  ])
  assert.equal(dbDump.includes(RAW_SIGNING_SALT), false)
  assert.equal(dbDump.includes('eyJhbGci'), false)
})

test('3. record_coverage(proofGapReason="invariant_enforced_hardened" | "control_blocked_cleanly" | "decoy_guard_verified") records negative edge in CapabilityLedger & triggers 2-strike pruning', async (t) => {
  const { storage } = makeStore(t)
  const origin = 'http://127.0.0.1:41999'
  const { runId } = await setupApprovedRun(storage, { seeds: [origin], environment: 'local-lab', tier: 2 })
  const run = storage.run(runId)
  const asset = run.candidates[0]!
  const assignment = storage.makeWorker(run, 'investigation', asset, 'Hardened-twin worker', 'Test negative-edge pruning')
  const execution = new Execution(storage)
  t.after(() => { void execution.stop() })

  for (const code of NEGATIVE_EDGE_PROOF_GAP_CODES) {
    assert.equal(parseNegativeEdgeGapReason(`${code}: verified denial`), code)
  }

  // Validate SpecSubmissionTracker accepts 403-backed `invariant_enforced_hardened` cleanly.
  const tracker = new SpecSubmissionTracker()
  tracker.noteObservation({ method: 'POST', pathAndQuery: '/api/transfers/approve', status: 403, persona: 'member_b' })
  const noted = tracker.noteProofGap({
    proofGapReason: 'invariant_enforced_hardened: cross-tenant approval rejected with 403',
    route: 'POST /api/transfers/approve',
  })
  assert.equal(noted.ok, true)
  assert.equal(tracker.validateGapsForSettlement().rejected.length, 0)

  // Admit a frontier branch with precondition cap:hop_h1:salt targeting POST /api/transfers/approve.
  const controller = execution.frontierControllerFor(runId)
  const branchKey = 'branch:hardened-approve'
  const admitted = controller.admitBranch({
    branchKey,
    depth: 2,
    verifiedHops: [{
      hopIndex: 1,
      hopReceiptId: 'h1',
      capabilityId: 'cap:hop_h1:salt',
      kind: 'signing_material',
      surface: 'http',
      serviceOrigin: origin,
      endpoint: 'GET /api/debug/meta',
      actorPersona: 'member_b',
      tenantScope: 'beta',
      summary: 'Sealed intermediate handle',
    }],
    nextTarget: {
      targetSurfaceKey: 'POST /api/transfers/approve',
      surface: 'http',
      serviceOrigin: origin,
      endpoint: 'POST /api/transfers/approve',
      hypothesisClass: 'broken-access-control',
      expectedBindingKind: 'value_binding',
      goalSummary: 'Attempt cross-tenant approval pivot',
    },
    feasibilityProb: 0.75,
    terminalImpactWeight: 0.9,
    surfaceNovelty: 0.8,
    attemptsOnBranch: 0,
    consecutiveFailedAttempts: 0,
    createdWave: 1,
    lastUpdatedWave: 1,
  })
  assert.equal(admitted, true)

  // Wire agent-session buildWorkerTools record_coverage -> execution.recordNegativeEdgeCoverage.
  const tools = buildWorkerTools(
    {
      record_coverage: async (args) => {
        const entry = storage.upsertCoverageEntry(run, assignment.id, {
          origin: args.origin,
          category: args.category,
          status: args.status,
          summary: args.summary,
          proofGapReason: args.proofGapReason,
        })
        const neg = execution.recordNegativeEdgeCoverage(runId, {
          origin: args.origin,
          category: args.category,
          summary: args.summary,
          proofGapReason: args.proofGapReason,
          route: args.route,
          preconditionCapIds: args.preconditionCapIds,
          branchKey: args.branchKey,
          hypothesisClass: args.hypothesisClass,
          exchangeIds: args.exchangeIds,
          assignmentId: assignment.id,
        })
        return { id: entry.id, ...neg }
      },
    },
    value => value,
    AbortSignal.timeout(10_000),
    24_576,
    () => undefined,
    { tracker },
  )
  const covTool = tools.find(tool => tool.name === 'record_coverage')!
  assert.ok(covTool)

  // Strike 1: Worker 1 hits hardened 403 -> recorded, not yet pruned.
  await covTool.execute({
    origin,
    category: 'broken-access-control',
    status: 'needs_follow_up',
    route: 'POST /api/transfers/approve',
    proofGapReason: 'invariant_enforced_hardened: server enforced tenant ownership check (403)',
    summary: 'Hop 2 cross-tenant approval denied cleanly using cap:hop_h1:salt',
    preconditionCapIds: ['cap:hop_h1:salt'],
    branchKey,
    hypothesisClass: 'broken-access-control',
    exchangeIds: ['gx-hardened-strike-1'],
  } as never, {} as never, { abortSignal: AbortSignal.timeout(5_000) } as never)

  const ledger = storage.capabilityLedger(runId)
  const strike1 = ledger.getNegativeEdge(['cap:hop_h1:salt'], 'POST /api/transfers/approve', 'broken-access-control')
  assert.ok(strike1)
  assert.equal(strike1.attemptCount, 1)
  assert.equal(strike1.pruned, false)
  assert.equal(strike1.reason, 'invariant_enforced_hardened')

  // Strike 2: Worker 2 hits clean block again -> 2-strike pruning engages!
  await covTool.execute({
    origin,
    category: 'broken-access-control',
    status: 'needs_follow_up',
    route: 'POST /api/transfers/approve',
    proofGapReason: 'control_blocked_cleanly: second strike denied with 403',
    summary: 'Second attempt on POST /api/transfers/approve using cap:hop_h1:salt blocked',
    preconditionCapIds: ['cap:hop_h1:salt'],
    branchKey,
    hypothesisClass: 'broken-access-control',
    exchangeIds: ['gx-hardened-strike-2'],
  } as never, {} as never, { abortSignal: AbortSignal.timeout(5_000) } as never)

  const strike2 = ledger.getNegativeEdge(['cap:hop_h1:salt'], 'POST /api/transfers/approve', 'broken-access-control')
  assert.ok(strike2)
  assert.equal(strike2.attemptCount, 2)
  assert.equal(strike2.pruned, true, '2 strikes must prune the dead-end negative edge')

  // Sibling workers must NOT re-probe the pruned branch!
  const nextWave = controller.selectNextWave(4)
  assert.equal(
    nextWave.assignments.some(a => a.branchKey === branchKey),
    false,
    'Pruned branch must not be selected in subsequent waves',
  )
  const siblingAdmitted = controller.admitBranch({
    branchKey: 'branch:sibling-retry',
    depth: 2,
    verifiedHops: [{
      hopIndex: 1,
      hopReceiptId: 'h1',
      capabilityId: 'cap:hop_h1:salt',
      kind: 'signing_material',
      surface: 'http',
      serviceOrigin: origin,
      endpoint: 'GET /api/debug/meta',
      actorPersona: 'member_b',
      tenantScope: 'beta',
      summary: 'Same precondition handle',
    }],
    nextTarget: {
      targetSurfaceKey: 'POST /api/transfers/approve',
      surface: 'http',
      serviceOrigin: origin,
      endpoint: 'POST /api/transfers/approve',
      hypothesisClass: 'broken-access-control',
      expectedBindingKind: 'value_binding',
      goalSummary: 'Sibling attempt on already-pruned surface',
    },
    feasibilityProb: 0.9,
    terminalImpactWeight: 0.95,
    surfaceNovelty: 0.9,
    attemptsOnBranch: 0,
    consecutiveFailedAttempts: 0,
    createdWave: 2,
    lastUpdatedWave: 2,
  })
  assert.equal(siblingAdmitted, false, 'Sibling branch matching pruned negative edge must be rejected')
})

test('4. Verified HopReceipt reach expansions reset nextPlannerDryRounds via FrontierWaveController before terminal confirmation', async (t) => {
  const { storage } = makeStore(t)
  const origin = 'http://127.0.0.1:42000'
  const { runId } = await setupApprovedRun(storage, { seeds: [origin], environment: 'local-lab', tier: 2 })
  const execution = new Execution(storage)
  t.after(() => { void execution.stop() })

  const ledger = storage.capabilityLedger(runId)
  // Seed Hop 1 + Hop 2 verified causal edges (0 confirmed terminal findings yet!).
  const seed = ledger.addCapability({
    capId: 'cap:hop_seed:member_b',
    kind: 'identity_session',
    provenance: 'attacker_seed',
    tenantScope: 'beta',
    actorPersona: 'member_b',
    serviceOrigin: origin,
    surface: 'http',
    artifactDigest: 'a'.repeat(64),
    createdAtMs: 1000,
  })
  const hop2Cap = ledger.addCapability({
    capId: 'cap:hop_2:scoped_token',
    kind: 'scoped_token',
    promotionStatus: 'capability_only',
    provenance: 'derived_hop',
    tenantScope: 'acme',
    actorPersona: 'member_b',
    serviceOrigin: origin,
    surface: 'webhook',
    artifactDigest: 'b'.repeat(64),
    createdAtMs: 1010,
  })
  ledger.addCausalEdge({
    preconditionCapIds: [seed.capId],
    actorContext: { persona: 'member_b', tenantScope: 'acme', serviceOrigin: origin },
    hopReceiptId: 'hop-2-reach',
    edgeBindingKind: 'derived_crypto_binding',
    postconditionCapId: hop2Cap.capId,
    sourceTimestampMs: 1005,
    targetTimestampMs: 1010,
  })

  const controller = new FrontierWaveController({ ledger })
  const hopEvents = ledger.listCausalEdges().map(edge => {
    const postNode = edge.postconditionCapId ? ledger.getCapability(edge.postconditionCapId) : null
    return {
      hopReceiptId: edge.hopReceiptId,
      branchKey: edge.postconditionCapId ?? edge.edgeId,
      depth: Math.max(1, edge.preconditionCapIds.length + 1),
      hostVerified: true,
      tenantScope: postNode?.tenantScope ?? edge.actorContext.tenantScope ?? 'default_tenant',
      serviceOrigin: postNode?.serviceOrigin ?? edge.actorContext.serviceOrigin ?? 'unknown',
      surface: postNode?.surface ?? 'http',
      ...(postNode ? { capabilityId: postNode.capId } : {}),
    }
  })
  const wave1 = controller.evaluateWaveProgress({ completedAssignments: 1, verifiedHopReceipts: hopEvents })
  const expansions1 = wave1.reachDelta.newHopReceiptIds.length
  const dryRounds1 = nextPlannerDryRounds({
    roundNo: 3, previousDryRounds: 1, newRuntimeConfirmed: 0, newChainPrimitives: 0,
    completedInvestigations: 2, previousCompletedInvestigations: 1, verifiedHopReachExpansions: expansions1,
  })
  assert.equal(expansions1, 1, 'New verified HopReceipt must expand frontier reach')
  assert.equal(dryRounds1, 0, 'Verified HopReceipt reach expansion must reset planner dry rounds to 0')

  // Next round with zero new verified hops increments dry rounds normally.
  const wave2 = controller.evaluateWaveProgress({ completedAssignments: 1, verifiedHopReceipts: hopEvents })
  const expansions2 = wave2.reachDelta.newHopReceiptIds.length
  const dryRounds2 = nextPlannerDryRounds({
    roundNo: 4, previousDryRounds: 0, newRuntimeConfirmed: 0, newChainPrimitives: 0,
    completedInvestigations: 3, previousCompletedInvestigations: 2, verifiedHopReachExpansions: expansions2,
  })
  assert.equal(expansions2, 0)
  assert.equal(dryRounds2, 1)
})

test('5. Multi-hop skill pre-injection & execution.ts LOC budget (< 6,000 LOC)', () => {
  const skills = selectPreInjectionSkills({
    profileSkills: ['bola-idor'],
    category: 'broken-access-control',
    title: 'Pivot from sealed Hop 1 handle',
    hypothesis: 'Advance Hop 2 from checkpoint',
    hasHopCheckpoint: true,
    multiHop: true,
    hopDepth: 2,
    limit: 2,
  })
  assert.equal(skills.some(s => s.name === 'multihop-chains'), true, 'Multi-hop checkpoint assignments must pre-inject multihop-chains')

  const execLines = readFileSync(join(REPO_ROOT, 'src/server/execution.ts'), 'utf8').split('\n').length
  assert.ok(execLines < 6000, `src/server/execution.ts must stay < 6,000 LOC (currently ${execLines})`)
})
