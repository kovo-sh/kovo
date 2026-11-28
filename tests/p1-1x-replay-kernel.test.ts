// @kernel @fixes R3-05
/**
 * Phase 1 Confirmation Kernel tests:
 *  1. 1x clean host-signed replay default (`verifyScript` & `runAgentScriptProof`):
 *     - confirms valid single-hop & composite proofs in 1 attempt (including one-shot token
 *       redemption and non-idempotent state mutations that fail under mandatory 2x replay);
 *     - accepts `fresh_clean_replay` and `clean_host_replay` without requiring fake `modeAFailureExchangeId`,
 *       and grades cleanly in `multihop-saas/run.ts` + `certify-v8.ts` (`modeBViolations === 0`);
 *     - stamps `fresh_clean_replay` (not `one_shot_transcript`) on `prove.signedUrlMint`.
 *  2. 1x strict fail-closed invariants:
 *     - tampered host transcript signature fails closed;
 *     - missing control arm fails closed;
 *     - unhandled HTTP 5xx server error fails closed;
 *     - script crash / non-zero exit fails closed;
 *     - unverified 1-hop signature carrier (any method, any signature header/query/body key, zero
 *       hardcoded class names) fails closed;
 *     - worker-controlled `args.replayAttempt` is ignored and `cleanSession` is tracked truthfully.
 *  3. Explicit `doubleReplay: true` opt-in:
 *     - runs 2 fresh sessions with distinct nonces and enforces cross-attempt fingerprint parity.
 *  4. `cross_surface_pivot` DAG alias & `evidence-provenance.ts` hygiene:
 *     - routes `cross_surface_pivot` through `CompositeProofReceipt` DAG `surfaces.size >= 2` check;
 *     - rejects same-surface spoofing, 1-hop claims, and standalone non-DAG calls;
 *     - confirms benchmark secret prefix regex is removed from `HOST_DISCLOSURE_SECRET_PATTERNS`.
 *
 * Defensive QA framing: pure loopback + in-memory verification tests only.
 */
import assert from 'node:assert/strict'
import { randomBytes } from 'node:crypto'
import { once } from 'node:events'
import { readFileSync } from 'node:fs'
import { createServer, request as httpRequest } from 'node:http'
import type { AddressInfo } from 'node:net'
import { join } from 'node:path'
import test from 'node:test'

import { RequestBroker, type Grant } from '../src/server/broker.ts'
import type { ResolvedPersona } from '../src/server/persona-vault.ts'
import { runAgentScriptProof } from '../src/server/agent-script-proof.ts'
import {
  signHostRecord,
  verifyCompositeReceipt,
  type CompositeProofReceipt,
  type HostSignedTranscript,
  type HostTranscriptEntry,
} from '../src/server/composite-receipt.ts'
import { HOST_DISCLOSURE_SECRET_PATTERNS } from '../src/server/evidence-provenance.ts'
import type { ImpactStep } from '../src/server/oracle-invariants.ts'
import { evaluateCrossSurfacePivot } from '../src/server/v8-oracle-families.ts'
import {
  VERIFY_NONCE_HEADER,
  VERIFY_RPC_CONTEXT_NAME,
  VERIFY_RPC_HEADER,
  VERIFY_RPC_SOCKET_NAME,
  VERIFY_RPC_TOKEN_NAME,
  VerifyRpcServer,
  createLocalAttemptFactory,
  verifyScript,
} from '../src/server/verify-rpc.ts'
import type { WorkerBackend, WorkerSession, WorkerSessionOptions, VerifyScriptRequest, VerifyScriptResult } from '../src/server/worker-backend.ts'
import { gradeRun, type ProductSubmittedCompositeProof } from '../benchmarks/multihop-saas/run.ts'
import { normalizeCell } from '../scripts/certify-v8.ts'

process.env.KOVO_ALLOW_LOCAL_LAB = '1'

const SDK_DIR = join(process.cwd(), 'worker', 'kovo_verify')
const SIGNING_KEY = 'p1-1x-replay-kernel-test-signing-key'

interface StubResponse {
  status: number
  headers?: Record<string, string>
  body: string
}

async function startLoopback(
  handler: (req: { method: string; url: string; headers: Record<string, string | string[] | undefined>; body: string }) => StubResponse,
) {
  const srv = createServer((req, res) => {
    let body = ''
    req.setEncoding('utf8')
    req.on('data', chunk => { body += chunk })
    req.on('end', () => {
      const out = handler({ method: req.method ?? 'GET', url: req.url ?? '/', headers: req.headers, body })
      res.writeHead(out.status, { 'content-type': 'application/json', ...(out.headers ?? {}) })
      res.end(out.body)
    })
  })
  srv.listen(0, '127.0.0.1')
  await once(srv, 'listening')
  const { port } = srv.address() as AddressInfo
  return {
    origin: `http://127.0.0.1:${port}`,
    close: () => new Promise<void>(resolve => srv.close(() => resolve())),
  }
}

function makePersona(handle: string, roleLabel: string, tenant: string, secret: string, origin: string): ResolvedPersona {
  return {
    id: `persona-${handle}`,
    handle,
    roleLabel: `${roleLabel} (${tenant})`,
    originAllowlist: [origin],
    authKind: 'bearer',
    headerName: null,
    secret,
    canaryMarkers: [],
  }
}

function makeGrant(origin: string, personas: Map<string, ResolvedPersona> = new Map()): Grant {
  return {
    canRead: o => { try { return new URL(o).origin === origin } catch { return o === origin } },
    audit: () => undefined,
    allowLocalLab: true,
    maxRpsPerOrigin: 300,
    tier: 3,
    isStateChangeApproved: () => true,
    personas,
  }
}

function rpcCallOnSocket(socketPath: string, token: string, nonce: string, op: string, args: Record<string, unknown> = {}): Promise<{ ok: boolean; result?: Record<string, unknown>; error?: string }> {
  return new Promise((resolvePromise, reject) => {
    const payload = JSON.stringify({ op, args })
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
      let data = ''
      res.setEncoding('utf8')
      res.on('data', chunk => { data += chunk })
      res.on('end', () => {
        try { resolvePromise(JSON.parse(data) as { ok: boolean; result?: Record<string, unknown>; error?: string }) } catch (err) { reject(err) }
      })
    })
    req.on('error', reject)
    req.end(payload)
  })
}

function mkStep(overrides: Partial<ImpactStep> & { id: string }): ImpactStep {
  return {
    arm: 'probe',
    method: 'GET',
    route: '/api/items/1',
    pathAndQuery: '/api/items/1',
    status: 200,
    actor: { handle: 'member_a', role: 'member', tenant: 'org_a', auth: 'bearer', sameSite: 'lax' },
    body: '{}',
    json: {},
    requestHeaders: {},
    responseHeaders: { 'content-type': 'application/json' },
    durationMs: 5,
    ...overrides,
  }
}

function mkSignedEntry(
  exchangeId: string,
  stepOverrides: Partial<ImpactStep>,
  extra: Partial<HostTranscriptEntry> = {},
): HostTranscriptEntry {
  const entry: HostTranscriptEntry = {
    exchangeId,
    origin: 'https://api.example.test',
    timestampMs: 1_000,
    actorPersona: 'member_a',
    cleanSession: true,
    step: mkStep({ id: exchangeId, ...stepOverrides }),
    ...extra,
  }
  return { ...entry, hostSignature: signHostRecord(entry, SIGNING_KEY) }
}

// ---------------------------------------------------------------------------
// 1. 1x clean host-signed replay default: one-shot token & non-idempotent state
// ---------------------------------------------------------------------------

test('1x clean host-signed replay confirms one-shot token redemption & non-idempotent state mutation in 1 attempt', async t => {
  let inviteRedeemed = false
  let inviteRole = 'member'
  let orderMutated = false
  let orderBalance = 100
  let attemptCount = 0

  const srvOneShot = await startLoopback(({ method, url, headers }) => {
    const auth = String(headers.authorization ?? '')
    if (url === '/api/invites/one-shot' && method === 'GET') {
      return { status: 200, body: JSON.stringify({ id: 'inv-1', role: inviteRole, owner: 'org_b' }) }
    }
    if (url === '/api/invites/one-shot/redeem' && method === 'POST') {
      if (auth === 'Bearer tok-control') return { status: 403, body: JSON.stringify({ error: 'invite_requires_token' }) }
      if (inviteRedeemed) return { status: 410, body: JSON.stringify({ error: 'invite_already_consumed' }) }
      inviteRedeemed = true
      inviteRole = 'admin'
      return { status: 200, body: JSON.stringify({ id: 'inv-1', role: 'admin', org: 'org_b' }) }
    }
    if (url === '/api/orders/ord-77' && method === 'GET') {
      return { status: 200, body: JSON.stringify({ id: 'ord-77', balance: orderBalance, owner: 'org_b' }) }
    }
    if (url === '/api/orders/ord-77/approve' && method === 'POST') {
      if (orderMutated) return { status: 409, body: JSON.stringify({ error: 'already_approved' }) }
      orderMutated = true
      orderBalance = 999
      return { status: 200, body: JSON.stringify({ id: 'ord-77', balance: 999, owner: 'org_b' }) }
    }
    return { status: 404, body: JSON.stringify({ error: 'not_found' }) }
  })
  t.after(() => srvOneShot.close())

  const personasOneShot = new Map<string, ResolvedPersona>([
    ['ctrl_user', makePersona('ctrl_user', 'member', 'org_a', 'tok-control', srvOneShot.origin)],
    ['probe_user', makePersona('probe_user', 'member', 'org_a', 'tok-probe', srvOneShot.origin)],
  ])
  const factoryOneShot = createLocalAttemptFactory({
    sdkDir: SDK_DIR,
    createRpcOptions(nonce) {
      attemptCount += 1
      return {
        broker: new RequestBroker({ transportConfig: { http2: false } }),
        grant: makeGrant(srvOneShot.origin, personasOneShot),
        runId: `run-1x-oneshot-${nonce.slice(0, 8)}`,
        assignmentId: 'asg-1x-oneshot',
        targetOrigins: [srvOneShot.origin],
      }
    },
  })

  // (a) One-shot token redemption (would fail with 410 on Attempt 2!)
  const oneShotVerdict = await verifyScript({
    candidate: {
      name: 'one-shot.ts',
      runtime: 'ts',
      code: `
        const proof = await ctx.prove_persisted_mutation({
          readRoute: '/api/invites/one-shot',
          mutation: { target: '/api/invites/one-shot/redeem', method: 'POST', body: { role: 'admin', token: 'one-shot-tok-1' }, as: 'probe_user' },
          fieldPath: 'role',
          expectDelta: 'admin',
          readPersona: 'probe_user',
        })
        if (!proof.ok) throw new Error(proof.missingEvidence.join(','))
        return ctx.result({ title: 'Mass assignment one-shot invite role escalation', severity: 'high' })
      `,
    },
    openAttempt: factoryOneShot,
  })
  assert.equal(oneShotVerdict.confirmed, true, `${oneShotVerdict.reason}: ${oneShotVerdict.detail} (${oneShotVerdict.attempts[0]?.failures.join(' | ')})`)
  assert.equal(oneShotVerdict.attempts.length, 1, '1x default must execute exactly 1 attempt')
  assert.equal(attemptCount, 1)
  assert.equal(oneShotVerdict.attempts[0]!.signaturesValid, true)
  assert.equal(oneShotVerdict.attempts[0]!.oraclePassed, true)

  // (b) Non-idempotent state mutation (before=100 -> mut -> after=999; Attempt 2 would return 409!)
  const nonIdempotentVerdict = await verifyScript({
    candidate: {
      name: 'non-idempotent.ts',
      runtime: 'ts',
      code: `
        const proof = await ctx.prove_persisted_mutation({
          readRoute: '/api/orders/ord-77',
          mutation: { target: '/api/orders/ord-77/approve', method: 'POST', body: { balance: 999 }, as: 'probe_user' },
          fieldPath: 'balance',
          expectDelta: 999,
          readPersona: 'probe_user',
        })
        if (!proof.ok) throw new Error(proof.missingEvidence.join(','))
        return ctx.result({ title: 'Mass assignment non-idempotent balance mutation', severity: 'high' })
      `,
    },
    openAttempt: factoryOneShot,
  })
  assert.equal(nonIdempotentVerdict.confirmed, true, `${nonIdempotentVerdict.reason}: ${nonIdempotentVerdict.detail} (${nonIdempotentVerdict.attempts[0]?.failures.join(' | ')})`)
  assert.equal(nonIdempotentVerdict.attempts.length, 1)
  assert.equal(attemptCount, 2)
})

// ---------------------------------------------------------------------------
// 2. 1x clean host-signed replay confirms CompositeProofReceipt in runAgentScriptProof()
// ---------------------------------------------------------------------------

test('runAgentScriptProof confirms multi-hop CompositeProofReceipt in 1 attempt without requiring Attempt 2', async t => {
  let redeemed = false
  let backendSessionsOpened = 0
  const srv = await startLoopback(({ method, url, headers }) => {
    if (url === '/api/v1/exports/request' && method === 'POST') {
      return { status: 200, body: JSON.stringify({ exportToken: 'tok-oneshot-99887766' }) }
    }
    if (url.startsWith('/api/v1/exports/download') && method === 'GET') {
      if (headers.authorization !== 'Bearer tok-oneshot-99887766') {
        return { status: 403, body: JSON.stringify({ error: 'forbidden' }) }
      }
      if (redeemed) return { status: 410, body: JSON.stringify({ error: 'export_token_consumed' }) }
      redeemed = true
      return { status: 200, body: JSON.stringify({ tenant: 'org_b', records: [{ id: 'r1', accountNumber: 'ACCT-991' }] }) }
    }
    return { status: 404, body: JSON.stringify({ error: 'not_found' }) }
  })
  t.after(() => srv.close())

  const personas = new Map<string, ResolvedPersona>([
    ['member_a', makePersona('member_a', 'member', 'org_a', 'tok-member-a', srv.origin)],
  ])
  const fakeBackend: WorkerBackend = {
    async run() { throw new Error('unused') },
    async verifyStaticAst() { throw new Error('unused') },
    async openSession(_id: string, _signal: AbortSignal, opts?: WorkerSessionOptions): Promise<WorkerSession> {
      backendSessionsOpened += 1
      const rpcDir = opts?.rpcMountDir ?? ''
      return {
        async stage() { throw new Error('unused') },
        async exec() { throw new Error('unused') },
        async analyze() { throw new Error('unused') },
        async sast() { throw new Error('unused') },
        async runScript() { throw new Error('unused') },
        async verifyStaticAst() { throw new Error('unused') },
        async verifyScript(_req: VerifyScriptRequest): Promise<VerifyScriptResult> {
          const socketPath = join(rpcDir, VERIFY_RPC_SOCKET_NAME)
          const token = readFileSync(join(rpcDir, VERIFY_RPC_TOKEN_NAME), 'utf8').trim()
          const context = JSON.parse(readFileSync(join(rpcDir, VERIFY_RPC_CONTEXT_NAME), 'utf8')) as { nonce: string }
          const rpc = (op: string, args: Record<string, unknown>) => rpcCallOnSocket(socketPath, token, context.nonce, op, args)

          const ctl = await rpc('http', { origin: srv.origin, method: 'GET', path: '/api/v1/exports/download', persona: 'member_a', sessionGroupRole: 'control' })
          assert.equal(ctl.ok, true)
          const h1 = await rpc('http', { origin: srv.origin, method: 'POST', path: '/api/v1/exports/request', persona: 'member_a', sessionGroupRole: 'probe' })
          assert.equal(h1.ok, true)
          const sealed = await rpc('capability.seal', {
            exchangeId: h1.result!.exchangeId,
            hopReceiptId: 'hop_1',
            slot: 'exportToken',
            jsonPath: 'exportToken',
            kind: 'bearer_token',
            allowedOrigins: [srv.origin],
          })
          assert.equal(sealed.ok, true)
          const capHandle = String(sealed.result!.handle)
          const h2 = await rpc('http', {
            origin: srv.origin,
            method: 'GET',
            path: '/api/v1/exports/download',
            capability: { handle: capHandle, injectAs: 'bearer' },
            sessionGroupRole: 'probe',
          })
          assert.equal(h2.ok, true)
          const comp = await rpc('composite.verify', {
            chainId: 'chain-p1-oneshot-composite',
            terminalVulnClass: 'cross_tenant_export',
            replayMode: 'clean_host_replay',
            hops: [
              { hopId: 'hop_1', surface: 'http', target: { origin: srv.origin, method: 'POST', pathAndQuery: '/api/v1/exports/request' }, exchangeIds: [h1.result!.exchangeId], producedCapabilities: [capHandle], claimedDelta: 'Obtained one-shot export bearer token.' },
              { hopId: 'hop_2', surface: 'storage', target: { origin: srv.origin, method: 'GET', pathAndQuery: '/api/v1/exports/download' }, exchangeIds: [h2.result!.exchangeId], consumedCapabilities: [capHandle], claimedDelta: 'Downloaded foreign org_b export records using sealed token.' },
            ],
            causalEdges: [{ kind: 'value_binding', fromHopId: 'hop_1', toHopId: 'hop_2', capabilityHandle: capHandle }],
            terminalImpact: {
              terminalHopId: 'hop_2',
              terminalExchangeId: h2.result!.exchangeId,
              summary: 'One-shot sealed export token exposed org_b records on clean 1x host-signed replay.',
              preChainControlExchangeIds: [ctl.result!.exchangeId],
              postChainReadbackExchangeIds: [],
            },
          })
          assert.equal(comp.ok, true)
          assert.equal(comp.result!.confirmed, true)
          return {
            runtime: 'ts',
            result: {
              title: 'Multi-hop one-shot export chain',
              nonce: context.nonce,
              claims: [comp.result!.claim],
            },
            stdout: '',
            stderr: '',
            exitCode: 0,
            durationMs: 25,
            timedOut: false,
          }
        },
        async close() { /* noop */ },
      }
    },
  }

  const res = await runAgentScriptProof({
    script: '// synthetic composite script executed by fakeBackend',
    runtime: 'ts',
    broker: new RequestBroker({ transportConfig: { http2: false } }),
    grant: makeGrant(srv.origin, personas),
    backend: fakeBackend,
    runId: 'run-p1-composite-1x',
    assignmentId: 'asg-p1-composite-1x',
    targetOrigins: [srv.origin],
    signal: AbortSignal.timeout(15_000),
    compositeVerifyOptions: { attackerPersonas: ['member_a'] },
  })
  assert.equal(res.verdict.confirmed, true, `${res.verdict.reason}: ${res.verdict.detail}`)
  assert.equal(res.verdict.attempts.length, 1)
  assert.equal(backendSessionsOpened, 1, '1x default must open exactly 1 isolated worker session')
  assert.equal(res.compositeReceipt?.verification.confirmed, true)
  assert.equal(res.compositeReceipt?.verification.replayMode, 'fresh_clean_replay')
})

// ---------------------------------------------------------------------------
// 3. 1x strict fail-closed: tampered signature, missing control, 5xx, crash
// ---------------------------------------------------------------------------

test('1x clean replay fails closed on invalid host signature, missing control arm, 5xx response, and script crash', async t => {
  const srv = await startLoopback(({ url }) => {
    if (url === '/api/crash-endpoint') return { status: 500, body: JSON.stringify({ error: 'internal_server_error' }) }
    return { status: 200, body: JSON.stringify({ ok: true, owner: 'alice', secret: 'val-1' }) }
  })
  t.after(() => srv.close())

  const personas = new Map<string, ResolvedPersona>([
    ['bob', makePersona('bob', 'member', 'org_a', 'tok-bob', srv.origin)],
  ])
  const factory = createLocalAttemptFactory({
    sdkDir: SDK_DIR,
    createRpcOptions(nonce) {
      return {
        broker: new RequestBroker({ transportConfig: { http2: false } }),
        grant: makeGrant(srv.origin, personas),
        runId: `run-1x-failclosed-${nonce.slice(0, 8)}`,
        assignmentId: 'asg-1x-failclosed',
        targetOrigins: [srv.origin],
      }
    },
  })

  // (a) HTTP 5xx response fails closed even if another exchange passes status/jsonPath claims
  const verdict5xx = await verifyScript({
    candidate: {
      name: 'server-500.ts',
      runtime: 'ts',
      code: `
        await ctx.http('/api/crash-endpoint', { as: 'bob', role: 'probe' })
        const okRes = await ctx.http('/api/ok', { as: 'bob', role: 'probe' })
        ctx.expect.status(okRes, 200)
        ctx.expect.jsonPath(okRes, 'owner', 'alice')
        return ctx.result({ title: 'Transcript containing unhandled 500 server error' })
      `,
    },
    openAttempt: factory,
  })
  assert.equal(verdict5xx.confirmed, false)
  assert.equal(verdict5xx.reason, 'oracle_failed')
  assert.equal(verdict5xx.rejectedBy, 'server_error')

  // (b) Script crash / non-zero exit fails closed
  const verdictCrash = await verifyScript({
    candidate: {
      name: 'crash.ts',
      runtime: 'ts',
      code: `
        await ctx.http('/api/ok', { as: 'bob', role: 'probe' })
        throw new Error('simulated worker script crash')
      `,
    },
    openAttempt: factory,
  })
  assert.equal(verdictCrash.confirmed, false)
  assert.equal(verdictCrash.rejectedBy, 'execution')
  assert.notEqual(verdictCrash.exitCode, 0)

  // (c) Missing control arm on boundary claim fails closed
  const verdictMissingControl = await verifyScript({
    candidate: {
      name: 'missing-ctrl.ts',
      runtime: 'ts',
      code: `
        const r = await ctx.http('/api/ok', { as: 'bob', role: 'probe' })
        ctx.expect.status(r, 200)
        return ctx.result({ title: 'Auth bypass on /api/ok without control arm' })
      `,
    },
    openAttempt: factory,
  })
  assert.equal(verdictMissingControl.confirmed, false)
  assert.equal(verdictMissingControl.reason, 'oracle_failed')

  // (d) Tampered host signature on TranscriptStore fails closed
  const verdictTamperedSig = await verifyScript({
    candidate: {
      name: 'tampered-sig.ts',
      runtime: 'ts',
      code: `
        const r = await ctx.http('/api/ok', { as: 'bob', role: 'probe' })
        ctx.expect.status(r, 200)
        return ctx.result({ title: 'Tampered transcript signature check' })
      `,
    },
    openAttempt: async input => {
      const session = await factory(input)
      return {
        ...session,
        async execute(candidate, signal) {
          const exec = await session.execute(candidate, signal)
          const rec = session.transcript.list()[0]
          if (rec && rec.response) rec.response.status = 403
          return exec
        },
      }
    },
  })
  assert.equal(verdictTamperedSig.confirmed, false)
  assert.equal(verdictTamperedSig.reason, 'transcript_mismatch')
})

// ---------------------------------------------------------------------------
// 4. Worker-controlled args.replayAttempt removed + cleanSession truthful + signedUrlMint replayMode
// ---------------------------------------------------------------------------

test('VerifyRpcServer ignores worker args.replayAttempt, tracks cleanSession truthfully, and stamps fresh_clean_replay on signedUrlMint', async t => {
  const sasSig = Buffer.from(randomBytes(32)).toString('base64url')
  const srv = await startLoopback(({ method, url, headers }) => {
    if (url === '/api/upload-token' && method === 'POST') {
      if (headers['x-require-auth'] === '1' && headers['x-bypass-auth'] !== '1') {
        return { status: 401, body: JSON.stringify({ error: 'auth_required' }) }
      }
      return {
        status: 200,
        body: JSON.stringify({
          uploadUrl: `https://acct.blob.core.windows.net/uploads/report.json?sv=2022-11-02&se=2026-11-27T00:00:00Z&sp=cw&sig=${sasSig}`,
        }),
      }
    }
    return { status: 200, body: JSON.stringify({ ok: true }) }
  })
  t.after(() => srv.close())

  const rpc = new VerifyRpcServer({
    broker: new RequestBroker({ transportConfig: { http2: false } }),
    grant: makeGrant(srv.origin),
    runId: 'run-p1-rpc-truth',
    assignmentId: 'asg-p1-rpc-truth',
    targetOrigins: [srv.origin],
  })
  await rpc.start()
  t.after(() => rpc.close())

  // Worker tries to spoof replayAttempt='mode_a' on a probe exchange -> host MUST ignore it and stamp 'primary'
  const spoofedProbe = await rpcCallOnSocket(rpc.socketPath, rpc.token, rpc.nonce, 'http.send', {
    method: 'PATCH',
    path: '/api/items/item-42',
    arm: 'probe',
    replayAttempt: 'mode_a',
    entityId: 'item-42',
  })
  assert.equal(spoofedProbe.ok, true)

  // Unlabeled post-mutation exchange on the SAME entity -> cleanSession MUST be false (never hardcoded true!)
  const postMutUnlabeled = await rpcCallOnSocket(rpc.socketPath, rpc.token, rpc.nonce, 'http.send', {
    method: 'GET',
    path: '/api/items/item-42',
    arm: 'probe',
    replayAttempt: 'ablation_control',
    entityId: 'item-42',
  })
  assert.equal(postMutUnlabeled.ok, true)

  const signedTranscript = rpc.buildHostSignedTranscript()
  const entry1 = signedTranscript.entries!.find(e => e.exchangeId === spoofedProbe.result!.exchangeId)!
  const entry2 = signedTranscript.entries!.find(e => e.exchangeId === postMutUnlabeled.result!.exchangeId)!
  assert.equal(entry1.replayAttempt, 'primary', 'worker args.replayAttempt=mode_a must never override host stamp')
  assert.equal(entry1.cleanSession, true)
  assert.equal(entry2.cleanSession, false, 'post-mutation non-control exchange must truthfully report cleanSession=false')
  assert.equal(entry2.replayAttempt, 'primary', 'worker args.replayAttempt=ablation_control on dirty probe must be ignored')

  // prove.signedUrlMint stamps fresh_clean_replay (not one_shot_transcript)
  const mintRes = await rpcCallOnSocket(rpc.socketPath, rpc.token, rpc.nonce, 'prove.signedUrlMint', {
    control: { path: '/api/upload-token', method: 'POST', headers: { 'x-require-auth': '1' }, body: { filename: 'report.json' } },
    probe: { path: '/api/upload-token', method: 'POST', headers: { 'x-require-auth': '1', 'x-bypass-auth': '1' }, body: { filename: 'report.json' } },
  })
  assert.equal(mintRes.ok, true)
  assert.equal(mintRes.result!.confirmed, true)
  assert.equal((mintRes.result!.claim as { replayMode?: string }).replayMode, 'fresh_clean_replay')

  // R3-05 review: a repeat mint whose probe route was already mutated in this session (prior 200 POST)
  // is NOT a clean replay -> host must fail closed to one_shot_transcript, never fabricate fresh_clean_replay.
  const dirtyMint = await rpcCallOnSocket(rpc.socketPath, rpc.token, rpc.nonce, 'prove.signedUrlMint', {
    control: { path: '/api/upload-token', method: 'POST', headers: { 'x-require-auth': '1' }, body: { filename: 'report.json' } },
    probe: { path: '/api/upload-token', method: 'POST', headers: { 'x-require-auth': '1', 'x-bypass-auth': '1' }, body: { filename: 'report.json' } },
  })
  assert.equal(dirtyMint.ok, true)
  assert.equal((dirtyMint.result!.claim as { replayMode?: string }).replayMode, 'one_shot_transcript')
})

test('R3-05 review: cross_surface_pivot alias rejects worker-declared surface labels without host-evidenced distinct surfaces', () => {
  const cap = 'cap:hop_1:label_spoof_tok'
  const transcript: HostSignedTranscript = {
    entries: [
      mkSignedEntry('ls-ctrl', { arm: 'control', method: 'GET', route: '/api/admin/audit', pathAndQuery: '/api/admin/audit', status: 403, body: '{"error":"forbidden"}', json: { error: 'forbidden' } }, { timestampMs: 900 }),
      mkSignedEntry('ls-h1', { arm: 'probe', method: 'POST', route: '/api/tokens', pathAndQuery: '/api/tokens', status: 200, body: '{"tok":"ok"}', json: { tok: 'ok' } }, { timestampMs: 1000, emittedCapabilities: [cap] }),
      mkSignedEntry('ls-h2', { arm: 'probe', method: 'GET', route: '/api/admin/audit', pathAndQuery: '/api/admin/audit', status: 200, body: '{"tenantId":"org_b","auditRows":[{"id":1}]}', json: { tenantId: 'org_b', auditRows: [{ id: 1 }] } }, { timestampMs: 1200, consumedCapabilities: [cap] }),
    ],
  }
  // Both hops are plain same-origin HTTP exchanges; the worker merely LABELS them webhook -> storage
  // (no bound OOB event, no browser trace, no GraphQL endpoint, no distinct signed origin).
  const receipt: CompositeProofReceipt = {
    chainId: 'chain-pivot-label-spoof',
    terminalVulnClass: 'cross_surface_pivot',
    hops: [
      { hopId: 'hop_1', surface: 'webhook', target: { origin: 'https://api.example.test', method: 'POST', pathAndQuery: '/api/tokens' }, exchangeIds: ['ls-h1'], oobEventIds: [], browserTraceIds: [], producedCapabilities: [cap], consumedCapabilities: [], claimedDelta: 'Claimed webhook-surface token mint.' },
      { hopId: 'hop_2', surface: 'storage', target: { origin: 'https://api.example.test', method: 'GET', pathAndQuery: '/api/admin/audit' }, exchangeIds: ['ls-h2'], oobEventIds: [], browserTraceIds: [], producedCapabilities: [], consumedCapabilities: [cap], claimedDelta: 'Claimed storage-surface audit read.' },
    ],
    causalEdges: [{ kind: 'value_binding', fromHopId: 'hop_1', toHopId: 'hop_2', capabilityHandle: cap }],
    terminalImpact: {
      terminalHopId: 'hop_2',
      terminalExchangeId: 'ls-h2',
      claimedImpact: 'Cross-surface pivot read foreign tenant audit rows.',
      summary: 'Cross-surface pivot read foreign tenant audit rows.',
      preChainControlExchangeIds: ['ls-ctrl'],
      postChainReadbackExchangeIds: [],
    },
    replayMode: 'fresh_clean_replay',
  }
  const res = verifyCompositeReceipt(receipt, transcript, { attackerPersonas: ['member_a'], signingKey: SIGNING_KEY })
  assert.equal(res.confirmed, false)
  assert.equal(res.rejectedBy, 'v8_oracle_cross_surface_pivot')
  assert.match(res.reason, /single_host_surface_not_cross_surface_pivot/)

  // Same chain with a genuinely distinct host-signed origin on hop_2 is a real cross-surface pivot and still confirms.
  const crossOrigin: HostSignedTranscript = {
    entries: transcript.entries!.map(e => (e.exchangeId === 'ls-h2' || e.exchangeId === 'ls-ctrl'
      ? mkSignedEntry(e.exchangeId, e.step, { timestampMs: e.timestampMs, origin: 'https://files.example.test', ...(e.consumedCapabilities ? { consumedCapabilities: e.consumedCapabilities } : {}) })
      : e)),
  }
  const okRes = verifyCompositeReceipt(
    { ...receipt, hops: [receipt.hops[0]!, { ...receipt.hops[1]!, target: { ...receipt.hops[1]!.target, origin: 'https://files.example.test' } }] },
    crossOrigin,
    { attackerPersonas: ['member_a'], signingKey: SIGNING_KEY },
  )
  assert.equal(okRes.confirmed, true, okRes.reason)
  assert.equal(okRes.terminalOracleFamily, 'cross_surface_pivot')
})

// ---------------------------------------------------------------------------
// 5. Explicit `doubleReplay: true` opt-in
// ---------------------------------------------------------------------------

test('doubleReplay: true runs 2 attempts with distinct nonces and enforces cross-attempt fingerprint parity', async t => {
  let attempt = 0
  let failSecond = false
  let driftSecond = false

  const srv = await startLoopback(({ url }) => {
    if (url === '/api/items/7') {
      if (failSecond && attempt === 2) return { status: 403, body: JSON.stringify({ error: 'denied_on_attempt_2' }) }
      return { status: 200, body: JSON.stringify({ owner: 'alice', item: driftSecond && attempt === 2 ? 'drifted-val' : 'stable-val' }) }
    }
    return { status: 404, body: '{}' }
  })
  t.after(() => srv.close())

  const personas = new Map<string, ResolvedPersona>([
    ['bob', makePersona('bob', 'member', 'org_a', 'tok-bob', srv.origin)],
  ])
  const factory = createLocalAttemptFactory({
    sdkDir: SDK_DIR,
    createRpcOptions(nonce, att) {
      attempt = att
      return {
        broker: new RequestBroker({ transportConfig: { http2: false } }),
        grant: makeGrant(srv.origin, personas),
        runId: `run-2x-${nonce.slice(0, 8)}`,
        assignmentId: 'asg-2x',
        targetOrigins: [srv.origin],
      }
    },
  })

  const candidate = {
    name: 'double-replay.ts',
    runtime: 'ts' as const,
    code: `
      const r = await ctx.http('/api/items/7', { as: 'bob', role: 'probe' })
      ctx.expect.status(r, 200)
      ctx.expect.jsonPath(r, 'owner', 'alice')
      return ctx.result({ title: 'Double-replay opt-in verification', severity: 'medium' })
    `,
  }

  // (a) Passing 2x opt-in
  const ok2x = await verifyScript({ candidate, openAttempt: factory, doubleReplay: true })
  assert.equal(ok2x.confirmed, true, `${ok2x.reason}: ${ok2x.detail}`)
  assert.equal(ok2x.attempts.length, 2)
  assert.notEqual(ok2x.attempts[0]!.nonce, ok2x.attempts[1]!.nonce)

  // (b) Attempt 2 failure fails closed under doubleReplay: true
  failSecond = true
  const flaky2x = await verifyScript({ candidate, openAttempt: factory, doubleReplay: true })
  failSecond = false
  assert.equal(flaky2x.confirmed, false)
  assert.equal(flaky2x.reason, 'oracle_failed')
  assert.equal(flaky2x.attempts.length, 2)
  assert.equal(flaky2x.attempts[0]!.oraclePassed, true)
  assert.equal(flaky2x.attempts[1]!.oraclePassed, false)

  // (c) Cross-attempt causal fingerprint drift fails closed under doubleReplay: true
  driftSecond = true
  const driftCandidate = {
    name: 'drift-replay.ts',
    runtime: 'ts' as const,
    code: `
      const r = await ctx.http('/api/items/7', { as: 'bob', role: 'probe' })
      ctx.expect.status(r, 200)
      ctx.expect.jsonPath(r, 'item', r.json.item)
      return ctx.result({ title: 'Double-replay fingerprint drift check', severity: 'medium' })
    `,
  }
  const drift2x = await verifyScript({ candidate: driftCandidate, openAttempt: factory, doubleReplay: true })
  driftSecond = false
  assert.equal(drift2x.confirmed, false)
  assert.equal(drift2x.reason, 'transcript_mismatch')
  assert.ok(drift2x.disagreements.length > 0)
})

// ---------------------------------------------------------------------------
// 6. Generic 1-hop signature-carrier provenance guard (zero hardcoded class names)
// ---------------------------------------------------------------------------

test('unverified 1-hop signature-bearing terminal exchange fails closed across methods & providers without class hardcoding', () => {
  const cases: Array<{
    name: string
    method: string
    pathAndQuery: string
    requestHeaders?: Record<string, string>
    requestJson?: Record<string, unknown>
    vulnClass: string
  }> = [
    { name: 'POST with Stripe-Signature header', method: 'POST', pathAndQuery: '/v1/events/billing', requestHeaders: { 'stripe-signature': 't=1,v1=deadbeef' }, vulnClass: 'cross_tenant_write' },
    { name: 'PATCH with Svix-Signature header', method: 'PATCH', pathAndQuery: '/v1/hooks/sync', requestHeaders: { 'svix-signature': 'v1,abc123' }, vulnClass: 'business_logic' },
    { name: 'DELETE with X-Slack-Signature header', method: 'DELETE', pathAndQuery: '/v1/records/42', requestHeaders: { 'x-slack-signature': 'v0=abcdef' }, vulnClass: 'broken_access_control' },
    { name: 'GET with ?sig= query carrier', method: 'GET', pathAndQuery: '/v1/files/export?sig=deadbeef1234', vulnClass: 'cross_tenant_export' },
    { name: 'POST with body signature key', method: 'POST', pathAndQuery: '/v1/callbacks', requestJson: { tenantId: 'org_b', signature: 'deadbeef' }, vulnClass: 'cross_tenant_write' },
  ]

  for (const tc of cases) {
    const isRead = tc.method === 'GET'
    const ctrl = mkSignedEntry('ex-ctrl', {
      arm: 'control',
      method: tc.method,
      route: tc.pathAndQuery.split('?')[0]!,
      pathAndQuery: tc.pathAndQuery.split('?')[0]!,
      status: 403,
      body: '{"error":"invalid_signature"}',
      json: { error: 'invalid_signature' },
    }, { timestampMs: 900 })
    const probe = mkSignedEntry('ex-probe', {
      arm: 'probe',
      method: tc.method,
      route: tc.pathAndQuery.split('?')[0]!,
      pathAndQuery: tc.pathAndQuery,
      status: 200,
      requestHeaders: tc.requestHeaders ?? {},
      ...(tc.requestJson ? { requestJson: tc.requestJson } : {}),
      body: JSON.stringify({ tenantId: 'org_b', updated: true, secretRows: [{ id: 1 }] }),
      json: { tenantId: 'org_b', updated: true, secretRows: [{ id: 1 }] },
    }, { timestampMs: 1100 })
    const rb = mkSignedEntry('ex-rb', {
      arm: 'control',
      method: 'GET',
      route: '/v1/org-b/state',
      pathAndQuery: '/v1/org-b/state',
      status: 200,
      body: JSON.stringify({ tenantId: 'org_b', balance: 999 }),
      json: { tenantId: 'org_b', balance: 999 },
    }, { timestampMs: 1300 })

    const transcript: HostSignedTranscript = { entries: isRead ? [ctrl, probe] : [ctrl, probe, rb] }
    const receipt: CompositeProofReceipt = {
      chainId: `chain-1hop-sig-${tc.method.toLowerCase()}`,
      terminalVulnClass: tc.vulnClass,
      hops: [{
        hopId: 'hop_1',
        surface: 'http',
        target: { origin: 'https://api.example.test', method: tc.method, pathAndQuery: tc.pathAndQuery },
        exchangeIds: ['ex-probe'],
        oobEventIds: [],
        browserTraceIds: [],
        producedCapabilities: [],
        consumedCapabilities: [],
        claimedDelta: 'Sent signature-bearing request without in-DAG secret provenance.',
      }],
      causalEdges: [],
      terminalImpact: {
        terminalHopId: 'hop_1',
        terminalExchangeId: 'ex-probe',
        claimedImpact: 'Attempted 1-hop signature-bearing terminal impact without DAG provenance.',
        summary: 'Attempted 1-hop signature-bearing terminal impact without DAG provenance.',
        preChainControlExchangeIds: ['ex-ctrl'],
        postChainReadbackExchangeIds: isRead ? [] : ['ex-rb'],
      },
      replayMode: 'fresh_clean_replay',
    }
    const res = verifyCompositeReceipt(receipt, transcript, { attackerPersonas: ['member_a'], signingKey: SIGNING_KEY })
    assert.equal(res.confirmed, false, `${tc.name} must fail closed without in-DAG provenance`)
    assert.equal(res.failedStage, 'terminal_impact', `${tc.name} failed at ${res.failedStage}: ${res.reason}`)
    assert.match(res.reason, /unproven_(?:secret|capability)_provenance/i)
  }
})

// ---------------------------------------------------------------------------
// 7. cross_surface_pivot DAG alias + evidence-provenance hygiene + grader/certify-v8
// ---------------------------------------------------------------------------

test('cross_surface_pivot routes via CompositeProofReceipt DAG surfaces.size >= 2 and rejects same-surface spoofing', () => {
  const cap = 'cap:hop_1:pivot_tok'
  const transcript: HostSignedTranscript = {
    entries: [
      mkSignedEntry('ex-ctrl', { arm: 'control', method: 'GET', route: '/api/admin/audit', pathAndQuery: '/api/admin/audit', status: 403, body: '{"error":"forbidden"}', json: { error: 'forbidden' } }, { timestampMs: 900 }),
      mkSignedEntry('ex-h1', { arm: 'probe', method: 'POST', route: '/graphql', pathAndQuery: '/graphql', status: 200, body: '{"data":{"tok":"ok"}}', json: { data: { tok: 'ok' } } }, { timestampMs: 1000, emittedCapabilities: [cap] }),
      mkSignedEntry('ex-h2', { arm: 'probe', method: 'GET', route: '/api/admin/audit', pathAndQuery: '/api/admin/audit', status: 200, body: '{"tenantId":"org_b","auditRows":[{"id":1}]}', json: { tenantId: 'org_b', auditRows: [{ id: 1 }] } }, { timestampMs: 1200, consumedCapabilities: [cap] }),
    ],
  }

  const baseReceipt = (s1: 'http' | 'graphql', s2: 'http' | 'storage'): CompositeProofReceipt => ({
    chainId: `chain-pivot-${s1}-${s2}`,
    terminalVulnClass: 'cross_surface_pivot',
    hops: [
      { hopId: 'hop_1', surface: s1, target: { origin: 'https://api.example.test', method: 'POST', pathAndQuery: '/graphql' }, exchangeIds: ['ex-h1'], oobEventIds: [], browserTraceIds: [], producedCapabilities: [cap], consumedCapabilities: [], claimedDelta: 'Obtained token on surface 1.' },
      { hopId: 'hop_2', surface: s2, target: { origin: 'https://api.example.test', method: 'GET', pathAndQuery: '/api/admin/audit' }, exchangeIds: ['ex-h2'], oobEventIds: [], browserTraceIds: [], producedCapabilities: [], consumedCapabilities: [cap], claimedDelta: 'Accessed restricted audit on surface 2.' },
    ],
    causalEdges: [{ kind: 'value_binding', fromHopId: 'hop_1', toHopId: 'hop_2', capabilityHandle: cap }],
    terminalImpact: {
      terminalHopId: 'hop_2',
      terminalExchangeId: 'ex-h2',
      claimedImpact: 'Cross-surface pivot read foreign tenant audit rows.',
      summary: 'Cross-surface pivot read foreign tenant audit rows.',
      preChainControlExchangeIds: ['ex-ctrl'],
      postChainReadbackExchangeIds: [],
    },
    replayMode: 'fresh_clean_replay',
  })

  // Also confirm raw `clean_host_replay` alias parses and verifies cleanly without fake modeAFailureExchangeId
  const cleanAliasRes = verifyCompositeReceipt(
    { ...baseReceipt('graphql', 'storage'), replayMode: 'clean_host_replay' },
    transcript,
    { attackerPersonas: ['member_a'], signingKey: SIGNING_KEY },
  )
  assert.equal(cleanAliasRes.confirmed, true, cleanAliasRes.reason)

  // Valid distinct surfaces (graphql -> storage) confirms cleanly via DAG alias
  const multiRes = verifyCompositeReceipt(baseReceipt('graphql', 'storage'), transcript, { attackerPersonas: ['member_a'], signingKey: SIGNING_KEY })
  assert.equal(multiRes.confirmed, true, multiRes.reason)
  assert.equal(multiRes.terminalOracleFamily, 'cross_surface_pivot')

  // Same-surface spoofing (http -> http) fails closed
  const spoofRes = verifyCompositeReceipt(baseReceipt('http', 'http'), transcript, { attackerPersonas: ['member_a'], signingKey: SIGNING_KEY })
  assert.equal(spoofRes.confirmed, false)
  assert.equal(spoofRes.rejectedBy, 'v8_oracle_cross_surface_pivot')
  assert.match(spoofRes.reason, /single_surface_not_cross_surface_pivot/)

  // Standalone evaluateCrossSurfacePivot shim fails closed outside DAG
  const standalone = evaluateCrossSurfacePivot({
    attackerOriginPersona: { actorId: 'member_a', role: 'member' },
    preChainControlDenied: { id: 'c1', hostSignature: 'sig-12345678', timestampMs: 900, status: 403 },
    hops: [
      { surface: 'graphql', role: 'trigger_write', record: { id: 'h1', hostSignature: 'sig-12345678', timestampMs: 1000, status: 200 } },
      { surface: 'http', role: 'terminal_impact', record: { id: 'h2', hostSignature: 'sig-12345678', timestampMs: 1100, status: 200, json: { tenantId: 'org_b', secret: 'row' } } },
    ],
    terminalImpact: { kind: 'privileged_read', verified: true, impactDigest: 'sha256:ok' },
  })
  assert.equal(standalone.satisfied, false)
  assert.equal(standalone.reason, 'cross_surface_pivot_requires_composite_dag')

  // Evidence provenance benchmark secret prefix regex removed
  const benchPrefix = 'rb' + 's_'
  assert.equal(HOST_DISCLOSURE_SECRET_PATTERNS.some(p => p.includes(benchPrefix)), false)
  assert.ok(HOST_DISCLOSURE_SECRET_PATTERNS.some(p => p.includes('sk_')))
  assert.ok(HOST_DISCLOSURE_SECRET_PATTERNS.some(p => p.includes('AKIA')))
})

test('benchmarks/multihop-saas/run.ts and scripts/certify-v8.ts accept 1x clean_host_replay without modeBViolations while rejecting one_shot_transcript', () => {
  const groundTruth = {
    app: 'synth-app' as Parameters<typeof gradeRun>[0] extends { groundTruth: infer G } ? (G extends { app: infer A } ? A : never) : never,
    labMode: 'vulnerable' as const,
    seed: 42,
    seedSet: 'dev' as const,
    expectedChains: [{ chainId: 'CH-1', vulnClass: 'cross_tenant_export', hopIds: ['h1', 'h2'] }],
    twinDecoys: [],
    topology: { origins: [] },
    personas: [],
  }
  const cleanReceipt: ProductSubmittedCompositeProof = {
    findingId: 'f-1',
    chainId: 'CH-1',
    terminalVulnClass: 'cross_tenant_export',
    hopCount: 2,
    replayMode: 'clean_host_replay',
    confirmed: true,
    attackerProvenanceValid: true,
  }
  const cleanCard = gradeRun({
    groundTruth: groundTruth as never,
    findings: [{ id: 'f-1', status: 'confirmed', vulnClass: 'cross_tenant_export' }],
    compositeReceipts: [cleanReceipt],
    oracleEvents: [
      { seq: 1, chainId: 'CH-1', eventKind: 'hop', hopId: 'h1' },
      { seq: 2, chainId: 'CH-1', eventKind: 'hop', hopId: 'h2' },
      { seq: 3, chainId: 'CH-1', eventKind: 'terminal' },
    ],
  })
  assert.equal(cleanCard.chains[0]!.twoSideConfirmed, true)
  assert.equal(cleanCard.chains[0]!.replayMode, 'fresh_clean_replay')

  // certify-v8 normalizeCell: clean_host_replay produces 0 modeBViolations
  const cleanCell = normalizeCell({
    app: 'synth-app',
    mode: 'dev',
    llm: 'agentic',
    seed: 42,
    budgetUsd: 1,
    maxDurationMs: 60_000,
    chainsTotal: 1,
    chainsConfirmed: 1,
    chains: [{ chainId: 'CH-1', expectedHops: 2, twoSideConfirmed: true, replayMode: 'clean_host_replay' }],
  })
  assert.equal(cleanCell.modeBViolations, 0)

  // certify-v8 normalizeCell: one_shot_transcript still flags modeBViolations = 1
  const modeBCell = normalizeCell({
    app: 'synth-app',
    mode: 'dev',
    llm: 'agentic',
    seed: 42,
    budgetUsd: 1,
    maxDurationMs: 60_000,
    chainsTotal: 1,
    chainsConfirmed: 0,
    chains: [{ chainId: 'CH-1', expectedHops: 2, twoSideConfirmed: false, replayMode: 'one_shot_transcript' }],
  })
  assert.equal(modeBCell.modeBViolations, 1)
})
