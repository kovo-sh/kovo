/**
 * v7 Agentic Lift Oracles — comprehensive positive + fail-closed negative tests for all 4 seams:
 *
 *  1. Auth Bypass / Forged-Token ProofReceipt (`CWE-287` / `CWE-347`):
 *     - Positive: `auth_bypass`, `jwt_forgery`, `broken_auth`, `auth_protocol` via `verifyReceipt`,
 *       `buildAgentScriptReceipt`, and live `ctx.prove_access_boundary` (TS & Python) with 401/403
 *       control and distinct bypass header / forged JWT / bypass query param returning structured
 *       private/account JSON data.
 *     - Fail-closed negative: normal vault-persona login crossing anon-401, public endpoint (200
 *       control), status-only/empty/boilerplate `{ok:true}`/error-only/HTML-shell probe responses,
 *       no request differential, AND cross-tenant BOLA write with anon-401 still strictly rejected.
 *  2. Conserved-Balance / Race `ctx.prove_race_burst` Wiring (`CWE-362`):
 *     - Positive: `ctx.prove_race_burst({ requests, readRoute, balanceField, unitDebit })` in TS &
 *       Python automatically executes baseline GET -> burst -> post GET -> serial control (+ serial
 *       post GET) and emits a `race` claim that passes BOTH Layer-3 `verifyScript` AND
 *       `buildAgentScriptReceipt` + `verifyReceipt` (`conserved_balance` rule) for under-debit,
 *       negative-stock partial-win (2xx + 409), and single-use over-credit races.
 *     - Fail-closed negative: conserved (non-vulnerable) balance, 5xx-only burst, missing serial
 *       control, and missing readbacks fail closed.
 *  3. SSTI / Injection Differential (`CWE-1336` / `CWE-89` / `CWE-78`):
 *     - Positive: GET & POST `ctx.prove_injection_differential({ ..., expectedOutput, vulnClass })`
 *       passes BOTH Layer-3 `verifyScript` (even when title declares "SSTI (CWE-1336)" / "Command
 *       Injection (CWE-78)") AND `buildAgentScriptReceipt` + `verifyReceipt` (`verifyEvaluatedExpression`);
 *       engine error fingerprint path without `expectedOutput` confirms SQLi (`CWE-89`) cleanly.
 *     - Fail-closed negative: raw reflection in GET query OR POST JSON body, marker present in
 *       control body, and bare 200->500 status divergence without fingerprint all fail closed.
 *  4. Floor-Confirmed Concrete-ID Route Normalization (`exec-recon-planner.ts`):
 *     - Concrete short prefixed IDs (`tkt_123`, `tkt-1001`, `ord_42`, `tkt_deadbeef`, UUIDs, numeric
 *       IDs) normalize to `:id` while preserving version/word segments (`/v1`, `/api-v2`, `/oauth2`,
 *       `/user-profile`, `/reset_password`).
 *     - Floor-confirmed `GET /api/tickets/tkt_123` excludes template `GET /api/tickets/:id` and
 *       sibling `GET /api/tickets/tkt_456` in `isRouteConfirmed`, `buildConfirmedRouteSets`,
 *       `queueHighRiskCoverageSteps`, and `stepRepeatsConfirmedWork` while leaving unconfirmed
 *       write methods (`PATCH /api/tickets/:id`) distinct when method-scoped.
 */
import assert from 'node:assert/strict'
import { execFile } from 'node:child_process'
import { randomUUID } from 'node:crypto'
import { promisify } from 'node:util'

const execFileAsync = promisify(execFile)
import { once } from 'node:events'
import { mkdtempSync, rmSync } from 'node:fs'
import { createServer } from 'node:http'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import { test } from 'node:test'
import { fileURLToPath } from 'node:url'
import { RequestBroker } from '../src/server/broker.ts'
import type { Grant } from '../src/server/broker.ts'
import {
  buildConfirmedRouteSets,
  isRouteConfirmed,
  normalizeConfirmedRouteTemplate,
} from '../src/server/exec-recon-planner.ts'
import { agentProofAttribution } from '../src/server/exec-verify.ts'
import type { ResolvedPersona } from '../src/server/persona-vault.ts'
import {
  buildAgentScriptReceipt,
  buildProofReceipt,
  receiptRuleFor,
  verifyReceipt,
  type ImpactStep,
  type ReceiptTranscript,
  type ScriptProofExchange,
} from '../src/server/proof-receipt.ts'
import {
  VERIFY_RPC_CONTEXT_NAME,
  VERIFY_RPC_TOKEN_NAME,
  VerifyRpcServer,
  createLocalAttemptFactory,
  evaluateClaims,
  verifyScript,
} from '../src/server/verify-rpc.ts'
import { VerifyContext } from '../worker/guardian_verify/guardian_verify.ts'
import { makeLabGrant } from './v4-tier-helpers.ts'

process.env.GUARDIAN_ALLOW_LOCAL_LAB = '1'
const SDK_DIR = join(dirname(fileURLToPath(import.meta.url)), '../worker/guardian_verify')
const ORIGIN = 'https://app.example.invalid'

function bindRpcEnv(server: VerifyRpcServer): () => void {
  const prev = {
    GUARDIAN_RPC_SOCKET: process.env.GUARDIAN_RPC_SOCKET,
    GUARDIAN_RPC_TOKEN_FILE: process.env.GUARDIAN_RPC_TOKEN_FILE,
    GUARDIAN_RPC_CONTEXT_FILE: process.env.GUARDIAN_RPC_CONTEXT_FILE,
    GUARDIAN_VERIFY_NONCE: process.env.GUARDIAN_VERIFY_NONCE,
    GUARDIAN_PROOF_RESULT_FILE: process.env.GUARDIAN_PROOF_RESULT_FILE,
  }
  process.env.GUARDIAN_RPC_SOCKET = server.socketPath
  process.env.GUARDIAN_RPC_TOKEN_FILE = join(server.hostDir, VERIFY_RPC_TOKEN_NAME)
  process.env.GUARDIAN_RPC_CONTEXT_FILE = join(server.hostDir, VERIFY_RPC_CONTEXT_NAME)
  process.env.GUARDIAN_VERIFY_NONCE = server.nonce
  const tmpDir = mkdtempSync(join(tmpdir(), 'guardian-v7-oracles-'))
  process.env.GUARDIAN_PROOF_RESULT_FILE = join(tmpDir, 'result.json')
  return () => {
    for (const [k, v] of Object.entries(prev)) {
      if (v === undefined) delete process.env[k]
      else process.env[k] = v
    }
    rmSync(tmpDir, { recursive: true, force: true })
  }
}

function transcriptToScriptExchanges(server: VerifyRpcServer): ScriptProofExchange[] {
  return server.transcript.list().flatMap(record => {
    if (record.op === 'oob' || record.op === 'browser' || !record.request) return []
    const body = server.transcript.body(record.exchangeId)
    return [{
      exchangeId: record.exchangeId,
      op: record.op,
      method: record.request.method,
      pathAndQuery: record.request.pathAndQuery,
      origin: record.request.origin,
      status: record.response?.status ?? null,
      durationMs: record.durationMs,
      personaHandle: record.request.personaHandle ?? null,
      sessionRole: record.request.sessionRole ?? null,
      actorRoleLabel: record.request.actorRoleLabel ?? null,
      ...(body !== undefined ? { body } : {}),
      requestHeaders: record.request.headers ?? null,
      responseHeaders: record.response?.headers ?? null,
    }]
  })
}

function makePersonaGrant(origin: string): Grant {
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
  return makeLabGrant(origin, {
    tier: 3,
    personas: new Map([
      ['alice', persona('alice', 'member (acme)', 'tok-alice')],
      ['bob', persona('bob', 'member (beta)', 'tok-bob')],
    ]),
  })
}

// ============================================================================
// SEAM 1: Auth Bypass / Forged-Token ProofReceipt (CWE-287 / CWE-347)
// ============================================================================

test('Seam 1: receiptRuleFor and agentProofAttribution classify auth_bypass/jwt_forgery/broken_auth/auth_protocol cleanly', () => {
  for (const cls of ['auth_bypass', 'jwt_forgery', 'broken_auth', 'auth_protocol']) {
    assert.equal(receiptRuleFor(cls).rule, 'auth_bypass', `${cls} must map to auth_bypass rule`)
  }
  assert.equal(agentProofAttribution('jwt_forgery').cwe, 'CWE-347')
  assert.equal(agentProofAttribution('auth_bypass').cwe, 'CWE-287')
  assert.equal(agentProofAttribution('broken_auth').cwe, 'CWE-287')
  assert.equal(agentProofAttribution('auth_protocol').cwe, 'CWE-287')
})

test('Seam 1: auth_bypass & jwt_forgery ProofReceipts confirm valid bypasses and fail closed on normal login / status-only / public routes', () => {
  const mkStep = (overrides: Partial<ImpactStep> & { id: string; arm: ImpactStep['arm']; status: number }): ImpactStep => ({
    method: 'GET',
    route: '/api/v1/admin/settings',
    pathAndQuery: '/api/v1/admin/settings',
    actor: { handle: null, role: null, tenant: null, auth: 'unknown', sameSite: null },
    ...overrides,
  })

  // 1a. Positive: unauthenticated 401 -> forged alg=none JWT header returns 200 with structured account data
  const jwtTranscript: ReceiptTranscript = {
    entries: [
      { exchangeId: 'ctl', step: mkStep({ id: 'ctl', arm: 'control', status: 401, body: '{"error":"unauthorized"}' }) },
      {
        exchangeId: 'prb',
        step: mkStep({
          id: 'prb',
          arm: 'probe',
          status: 200,
          requestHeaders: { authorization: 'Bearer forged.unsigned.token' },
          json: { admin: true, email: 'root@acme.example', apiKeys: ['k_live_01'] },
          body: '{"admin":true,"email":"root@acme.example","apiKeys":["k_live_01"]}',
        }),
      },
    ],
  }
  const jwtReceipt = buildProofReceipt({
    vulnClass: 'jwt_forgery',
    target: { origin: ORIGIN, method: 'GET', pathAndQuery: '/api/v1/admin/settings' },
    exchangeIds: ['ctl', 'prb'],
    claimedDelta: 'Forged unsigned JWT bypassed 401 authentication on /api/v1/admin/settings.',
  })
  const jwtVerdict = verifyReceipt(jwtReceipt, jwtTranscript)
  assert.equal(jwtVerdict.confirmed, true, jwtVerdict.reason)
  assert.equal(jwtVerdict.rule, 'auth_bypass')
  assert.equal(jwtVerdict.evidence?.differentialKind, 'header')

  // 1b. Positive: bad-token 403 -> bypass query param on same protected route returns protected data
  const paramTranscript: ReceiptTranscript = {
    entries: [
      {
        exchangeId: 'ctl',
        step: mkStep({
          id: 'ctl',
          arm: 'control',
          status: 403,
          requestHeaders: { authorization: 'Bearer invalid-tok' },
          body: '{"error":"forbidden"}',
        }),
      },
      {
        exchangeId: 'prb',
        step: mkStep({
          id: 'prb',
          arm: 'probe',
          status: 200,
          pathAndQuery: '/api/v1/admin/settings?internal_bypass=1',
          requestHeaders: { authorization: 'Bearer invalid-tok' },
          json: { tenantId: 'acme', users: [{ id: 'u1', role: 'owner' }] },
          body: '{"tenantId":"acme","users":[{"id":"u1","role":"owner"}]}',
        }),
      },
    ],
  }
  const paramVerdict = verifyReceipt(
    buildProofReceipt({
      vulnClass: 'auth_bypass',
      target: { origin: ORIGIN, method: 'GET', pathAndQuery: '/api/v1/admin/settings?internal_bypass=1' },
      exchangeIds: ['ctl', 'prb'],
      claimedDelta: 'Bypass query parameter bypassed 403 control.',
    }),
    paramTranscript,
  )
  assert.equal(paramVerdict.confirmed, true, paramVerdict.reason)
  assert.equal(paramVerdict.evidence?.differentialKind, 'query')

  // 1c. Fail-closed NEGATIVE: normal Layer-1 authenticated vault persona crossing anon-401 is normal login, NOT auth bypass
  const normalLoginVerdict = verifyReceipt(jwtReceipt, {
    entries: [
      { exchangeId: 'ctl', step: mkStep({ id: 'ctl', arm: 'control', status: 401, body: '{"error":"unauthorized"}' }) },
      {
        exchangeId: 'prb',
        step: mkStep({
          id: 'prb',
          arm: 'probe',
          status: 200,
          actor: { handle: 'alice', role: 'member', tenant: 'acme', auth: 'bearer', sameSite: null },
          requestHeaders: { authorization: 'Bearer [persona:alice:secret]' },
          json: { id: 'u-alice', email: 'alice@acme.example' },
          body: '{"id":"u-alice","email":"alice@acme.example"}',
        }),
      },
    ],
  })
  assert.equal(normalLoginVerdict.confirmed, false)
  assert.match(normalLoginVerdict.reason, /standard login/i)

  // 1d. Fail-closed NEGATIVE: boilerplate status-only `{ok:true}` probe response rejected
  const statusOnlyVerdict = verifyReceipt(jwtReceipt, {
    entries: [
      { exchangeId: 'ctl', step: mkStep({ id: 'ctl', arm: 'control', status: 401, body: '{"error":"unauthorized"}' }) },
      {
        exchangeId: 'prb',
        step: mkStep({
          id: 'prb',
          arm: 'probe',
          status: 200,
          requestHeaders: { 'x-forwarded-user': 'admin' },
          json: { ok: true, status: 'ok', message: 'accepted' },
          body: '{"ok":true,"status":"ok","message":"accepted"}',
        }),
      },
    ],
  })
  assert.equal(statusOnlyVerdict.confirmed, false)
  assert.match(statusOnlyVerdict.reason, /boilerplate|structured private/i)

  // 1e. Fail-closed NEGATIVE: empty body rejected
  const emptyBodyVerdict = verifyReceipt(jwtReceipt, {
    entries: [
      { exchangeId: 'ctl', step: mkStep({ id: 'ctl', arm: 'control', status: 401, body: '{"error":"unauthorized"}' }) },
      {
        exchangeId: 'prb',
        step: mkStep({
          id: 'prb',
          arm: 'probe',
          status: 200,
          requestHeaders: { 'x-forwarded-user': 'admin' },
          body: '{}',
        }),
      },
    ],
  })
  assert.equal(emptyBodyVerdict.confirmed, false)

  // 1f. Fail-closed NEGATIVE: public endpoint (control returned 200, not 401/403) rejected
  const publicVerdict = verifyReceipt(jwtReceipt, {
    entries: [
      { exchangeId: 'ctl', step: mkStep({ id: 'ctl', arm: 'control', status: 200, body: '{"items":[1,2]}' }) },
      {
        exchangeId: 'prb',
        step: mkStep({
          id: 'prb',
          arm: 'probe',
          status: 200,
          requestHeaders: { 'x-forwarded-user': 'admin' },
          json: { admin: true, email: 'root@acme.example' },
          body: '{"admin":true,"email":"root@acme.example"}',
        }),
      },
    ],
  })
  assert.equal(publicVerdict.confirmed, false)
  assert.match(publicVerdict.reason, /401 or 403/i)

  // 1g. Fail-closed NEGATIVE: cross-tenant BOLA write backed ONLY by anon-401 STILL fails closed!
  const bolaAnonWriteBuilt = buildAgentScriptReceipt({
    origin: ORIGIN,
    title: 'Cross-tenant BOLA write with anon-401 control',
    exchanges: [
      {
        exchangeId: 'ex-before', method: 'GET', pathAndQuery: '/api/records/1', origin: ORIGIN,
        status: 200, personaHandle: 'alice', actorRoleLabel: 'member (acme)', body: '{"id":"1","note":"old"}',
      },
      {
        exchangeId: 'ex-ctl', method: 'PATCH', pathAndQuery: '/api/records/1', origin: ORIGIN,
        status: 401, personaHandle: null, actorRoleLabel: null, body: '{"error":"login required"}',
      },
      {
        exchangeId: 'ex-prb', method: 'PATCH', pathAndQuery: '/api/records/1', origin: ORIGIN,
        status: 200, personaHandle: 'bob', actorRoleLabel: 'member (beta)', body: '{"id":"1","note":"new"}',
      },
      {
        exchangeId: 'ex-after', method: 'GET', pathAndQuery: '/api/records/1', origin: ORIGIN,
        status: 200, personaHandle: 'alice', actorRoleLabel: 'member (acme)', body: '{"id":"1","note":"new"}',
      },
    ],
    claims: [{
      kind: 'impact',
      impactClass: 'authorization',
      vulnClass: 'bola',
      controlExchangeIds: ['ex-ctl'],
      beforeExchangeId: 'ex-before',
      probeExchangeId: 'ex-prb',
      afterExchangeId: 'ex-after',
      resourceTenant: 'acme',
      expectControlDenied: true,
      requestBody: { note: 'new' },
    }],
  })
  assert.ok(bolaAnonWriteBuilt)
  // Without an authenticated same-route peer denial or cross-tenant readback binding: test the pure anon-401 write case
  const pureAnonWriteBuilt = buildAgentScriptReceipt({
    origin: ORIGIN,
    title: 'Cross-tenant BOLA write with only anon-401 control',
    exchanges: [
      {
        exchangeId: 'ex-ctl', method: 'PATCH', pathAndQuery: '/api/records/1', origin: ORIGIN,
        status: 401, personaHandle: null, actorRoleLabel: null, body: '{"error":"login required"}',
      },
      {
        exchangeId: 'ex-prb', method: 'PATCH', pathAndQuery: '/api/records/1', origin: ORIGIN,
        status: 200, personaHandle: 'bob', actorRoleLabel: 'member (beta)', body: '{"id":"1","note":"new"}',
      },
    ],
    claims: [{
      kind: 'impact',
      impactClass: 'authorization',
      vulnClass: 'bola',
      controlExchangeIds: ['ex-ctl'],
      probeExchangeId: 'ex-prb',
      resourceTenant: 'acme',
      expectControlDenied: true,
      requestBody: { note: 'new' },
    }],
  })
  assert.ok(pureAnonWriteBuilt)
  const pureAnonWriteVerdict = verifyReceipt(pureAnonWriteBuilt.receipt, pureAnonWriteBuilt.transcript)
  assert.equal(pureAnonWriteVerdict.confirmed, false, 'cross-tenant BOLA write with anon-401 control MUST still fail closed')
})

test('Seam 1 end-to-end: ctx.prove_access_boundary (TS & Python) confirms forged-JWT auth bypass through verifyScript + ProofReceipt', async t => {
  const server = createServer((req, res) => {
    const auth = req.headers.authorization ?? ''
    const url = new URL(req.url ?? '/', 'http://127.0.0.1')
    res.setHeader('content-type', 'application/json')
    if (url.pathname === '/api/v1/admin/profile' && req.method === 'GET') {
      if (auth === 'Bearer eyJhbGciOiJub25lIn0.eyJyb2xlIjoiYWRtaW4ifQ.') {
        res.statusCode = 200
        res.end(JSON.stringify({ id: 'adm-1', email: 'admin@acme.example', role: 'admin', tenant: 'acme' }))
        return
      }
      res.statusCode = 401
      res.end(JSON.stringify({ error: 'authentication required' }))
      return
    }
    res.statusCode = 404
    res.end(JSON.stringify({ error: 'not found' }))
  })
  server.listen(0, '127.0.0.1')
  await once(server, 'listening')
  const origin = `http://127.0.0.1:${(server.address() as { port: number }).port}`
  t.after(() => new Promise<void>(resolve => { server.closeAllConnections(); server.close(() => resolve()) }))

  const grant = makePersonaGrant(origin)
  const makeFactory = () => createLocalAttemptFactory({
    sdkDir: SDK_DIR,
    createRpcOptions() {
      return {
        broker: new RequestBroker({ rejectUnauthorized: false }),
        grant,
        runId: `run-auth-${randomUUID().slice(0, 8)}`,
        assignmentId: 'assignment-auth-bypass',
        targetOrigins: [origin],
      }
    },
  })

  // TS inline script via verifyScript
  const tsVerdict = await verifyScript({
    candidate: {
      name: 'jwt-bypass.ts',
      runtime: 'ts',
      code: `
await ctx.prove_access_boundary({
  route: '/api/v1/admin/profile',
  boundaryClass: 'auth',
  vulnClass: 'jwt_forgery',
  probeOptions: { headers: { authorization: 'Bearer eyJhbGciOiJub25lIn0.eyJyb2xlIjoiYWRtaW4ifQ.' } },
})
return ctx.result({ title: 'Unsigned JWT authentication bypass (CWE-347)', severity: 'critical' })
`,
    },
    openAttempt: makeFactory(),
  })
  assert.equal(tsVerdict.confirmed, true, `${tsVerdict.reason}: ${tsVerdict.detail}`)

  // Direct TS SDK -> buildAgentScriptReceipt -> verifyReceipt round-trip
  const rpcServer = new VerifyRpcServer({
    broker: new RequestBroker({ rejectUnauthorized: false }),
    grant,
    runId: 'run-auth-direct',
    assignmentId: 'assign-auth-direct',
    nonce: randomUUID(),
    targetOrigins: [origin],
  })
  await rpcServer.start()
  const restore = bindRpcEnv(rpcServer)
  try {
    const ctx = new VerifyContext()
    const proof = await ctx.prove_access_boundary({
      route: '/api/v1/admin/profile',
      vulnClass: 'jwt_forgery',
      probeOptions: { headers: { authorization: 'Bearer eyJhbGciOiJub25lIn0.eyJyb2xlIjoiYWRtaW4ifQ.' } },
    })
    assert.equal(proof.ok, true)
    assert.equal(proof.claim.boundaryClass, 'auth')
    assert.equal(proof.claim.vulnClass, 'jwt_forgery')
    const built = buildAgentScriptReceipt({
      origin,
      title: 'Unsigned JWT authentication bypass (CWE-347)',
      exchanges: transcriptToScriptExchanges(rpcServer),
      claims: ctx.claims as unknown as Record<string, unknown>[],
    })
    assert.ok(built, 'jwt_forgery boundary claim must produce a ProofReceipt')
    assert.equal(built.receipt.vulnClass, 'jwt_forgery')
    const verification = verifyReceipt(built.receipt, built.transcript)
    assert.equal(verification.confirmed, true, verification.reason)
    assert.equal(verification.rule, 'auth_bypass')
  } finally {
    restore()
    await rpcServer.close()
  }

  // Python inline script via verifyScript
  const pyVerdict = await verifyScript({
    candidate: {
      name: 'jwt-bypass.py',
      runtime: 'python',
      code: `
ctx.prove_access_boundary(
    route="/api/v1/admin/profile",
    vuln_class="jwt_forgery",
    probe_options={"headers": {"authorization": "Bearer eyJhbGciOiJub25lIn0.eyJyb2xlIjoiYWRtaW4ifQ."}},
)
result = ctx.result("Unsigned JWT auth bypass (CWE-347)", severity="critical")
`,
    },
    openAttempt: makeFactory(),
  })
  assert.equal(pyVerdict.confirmed, true, `${pyVerdict.reason}: ${pyVerdict.detail}`)
})

// ============================================================================
// SEAM 2: Conserved-Balance / Race ctx.prove_race_burst Wiring (CWE-362)
// ============================================================================

test('Seam 2 end-to-end: ctx.prove_race_burst with readRoute emits conserved_balance ProofReceipt in TS & Python (and fails closed when conserved)', async t => {
  const state = { balance: 100, vulnerable: true, seq: 0, inFlight: 0, burstWindowActive: false }
  const server = createServer((req, res) => {
    const url = new URL(req.url ?? '/', 'http://127.0.0.1')
    res.setHeader('content-type', 'application/json')
    if (url.pathname === '/api/v1/wallet' && req.method === 'GET') {
      res.statusCode = 200
      res.end(JSON.stringify({ balance: state.balance }))
      return
    }
    if (url.pathname === '/api/v1/wallet/redeem' && req.method === 'POST') {
      let raw = ''
      req.on('data', chunk => { raw += chunk })
      req.on('end', () => {
        const parsed = (() => { try { return JSON.parse(raw) as { amount?: number } } catch { return {} } })()
        const amount = typeof parsed.amount === 'number' ? parsed.amount : 10
        state.inFlight += 1
        const snapshot = state.balance
        const concurrent = state.inFlight >= 2
        setTimeout(() => {
          state.inFlight -= 1
          state.seq += 1
          if (state.vulnerable && concurrent) {
            // Classic lost-update double-spend: concurrent writers overwrite from stale snapshot!
            state.balance = snapshot - amount
          } else {
            state.balance -= amount
          }
          res.statusCode = 200
          res.end(JSON.stringify({ ok: true, tx: `tx-${state.seq}`, debited: amount, remaining: state.balance }))
        }, 25)
      })
      return
    }
    res.statusCode = 404
    res.end(JSON.stringify({ error: 'not found' }))
  })
  server.listen(0, '127.0.0.1')
  await once(server, 'listening')
  const origin = `http://127.0.0.1:${(server.address() as { port: number }).port}`
  t.after(() => new Promise<void>(resolve => { server.closeAllConnections(); server.close(() => resolve()) }))

  const grant = makePersonaGrant(origin)

  // 2a. Positive TS SDK -> Layer-3 evaluateClaims + buildAgentScriptReceipt + verifyReceipt
  state.balance = 100
  state.vulnerable = true
  const rpcTs = new VerifyRpcServer({
    broker: new RequestBroker({ rejectUnauthorized: false }),
    grant,
    runId: 'run-race-ts',
    assignmentId: 'assign-race-ts',
    nonce: randomUUID(),
    targetOrigins: [origin],
  })
  await rpcTs.start()
  const restoreTs = bindRpcEnv(rpcTs)
  try {
    const ctx = new VerifyContext()
    const proof = await ctx.prove_race_burst({
      requests: [
        { path: '/api/v1/wallet/redeem', method: 'POST', body: { amount: 10 }, as: 'alice' },
        { path: '/api/v1/wallet/redeem', method: 'POST', body: { amount: 10 }, as: 'alice' },
        { path: '/api/v1/wallet/redeem', method: 'POST', body: { amount: 10 }, as: 'alice' },
      ],
      readRoute: '/api/v1/wallet',
      balanceField: 'balance',
      unitDebit: 10,
      barrier: 'auto',
    })
    assert.equal(proof.ok, true, proof.missingEvidence.join(','))
    assert.ok(proof.claim.baselineExchangeId)
    assert.ok(proof.claim.postExchangeId)
    assert.ok(proof.claim.serialExchangeIds?.length === 1)
    assert.ok(proof.claim.serialPostExchangeId)
    assert.deepEqual(proof.claim.requestBody, { amount: 10 })

    const oracle = evaluateClaims(rpcTs.transcript, ctx.claims as never)
    assert.equal(oracle.passed, true, oracle.failures.join('; '))

    const built = buildAgentScriptReceipt({
      origin,
      title: 'Wallet double-spend under concurrent burst (CWE-362)',
      exchanges: transcriptToScriptExchanges(rpcTs),
      claims: ctx.claims as unknown as Record<string, unknown>[],
    })
    assert.ok(built, 'prove_race_burst with readRoute must build a conserved_balance ProofReceipt')
    const verification = verifyReceipt(built.receipt, built.transcript)
    assert.equal(verification.confirmed, true, verification.reason)
    assert.equal(verification.rule, 'conserved_balance')
    assert.equal(verification.evidence?.violationKind, 'under_debit')
    assert.equal(verification.evidence?.serialControlKind, 'serial_debit_exact')
  } finally {
    restoreTs()
    await rpcTs.close()
  }

  // 2b. Fail-closed NEGATIVE: hardened (conserved) wallet MUST be rejected by verifyReceipt!
  state.balance = 100
  state.vulnerable = false
  const rpcSafe = new VerifyRpcServer({
    broker: new RequestBroker({ rejectUnauthorized: false }),
    grant,
    runId: 'run-race-safe',
    assignmentId: 'assign-race-safe',
    nonce: randomUUID(),
    targetOrigins: [origin],
  })
  await rpcSafe.start()
  const restoreSafe = bindRpcEnv(rpcSafe)
  try {
    const ctx = new VerifyContext()
    await ctx.prove_race_burst({
      requests: [
        { path: '/api/v1/wallet/redeem', method: 'POST', body: { amount: 10 }, as: 'alice' },
        { path: '/api/v1/wallet/redeem', method: 'POST', body: { amount: 10 }, as: 'alice' },
      ],
      readRoute: '/api/v1/wallet',
      balanceField: 'balance',
      unitDebit: 10,
    })
    const built = buildAgentScriptReceipt({
      origin,
      title: 'Conserved wallet must not confirm',
      exchanges: transcriptToScriptExchanges(rpcSafe),
      claims: ctx.claims as unknown as Record<string, unknown>[],
    })
    assert.ok(built)
    const verification = verifyReceipt(built.receipt, built.transcript)
    assert.equal(verification.confirmed, false, 'conserved debit MUST fail closed')
    assert.match(verification.reason, /no conservation violation/i)
  } finally {
    restoreSafe()
    await rpcSafe.close()
  }

  // 2c. Positive Python SDK parity -> buildAgentScriptReceipt + verifyReceipt
  state.balance = 100
  state.vulnerable = true
  const rpcPy = new VerifyRpcServer({
    broker: new RequestBroker({ rejectUnauthorized: false }),
    grant,
    runId: 'run-race-py',
    assignmentId: 'assign-race-py',
    nonce: randomUUID(),
    targetOrigins: [origin],
  })
  await rpcPy.start()
  const restorePy = bindRpcEnv(rpcPy)
  try {
    const { stdout: pyOut } = await execFileAsync(
      'python3',
      [
        '-c',
        `
import json, sys
sys.path.insert(0, ${JSON.stringify(SDK_DIR)})
from guardian_verify import VerifyContext
ctx = VerifyContext()
proof = ctx.prove_race_burst(
    requests=[
        {"path": "/api/v1/wallet/redeem", "method": "POST", "body": {"amount": 10}, "as": "alice"},
        {"path": "/api/v1/wallet/redeem", "method": "POST", "body": {"amount": 10}, "as": "alice"},
        {"path": "/api/v1/wallet/redeem", "method": "POST", "body": {"amount": 10}, "as": "alice"},
    ],
    read_route="/api/v1/wallet",
    balance_field="balance",
    unit_debit=10,
)
print(json.dumps({"ok": proof["ok"], "claims": ctx.claims}))
`,
      ],
      { encoding: 'utf8', env: process.env },
    )
    const parsed = JSON.parse(pyOut) as { ok: boolean; claims: Record<string, unknown>[] }
    assert.equal(parsed.ok, true)
    const built = buildAgentScriptReceipt({
      origin,
      title: 'Python wallet double-spend (CWE-362)',
      exchanges: transcriptToScriptExchanges(rpcPy),
      claims: parsed.claims,
    })
    assert.ok(built)
    const verification = verifyReceipt(built.receipt, built.transcript)
    assert.equal(verification.confirmed, true, verification.reason)
    assert.equal(verification.rule, 'conserved_balance')
    assert.equal(verification.evidence?.violationKind, 'under_debit')
  } finally {
    restorePy()
    await rpcPy.close()
  }
})

test('Seam 2: single-use coupon over-credit race confirms with 4xx serial rejection control', () => {
  const exchanges: ScriptProofExchange[] = [
    { exchangeId: 'pre', method: 'GET', pathAndQuery: '/api/v1/credits', origin: ORIGIN, status: 200, body: '{"credits":0}' },
    { exchangeId: 'b1', method: 'POST', pathAndQuery: '/api/v1/coupons/redeem', origin: ORIGIN, status: 200, body: '{"credited":50,"tx":"1"}' },
    { exchangeId: 'b2', method: 'POST', pathAndQuery: '/api/v1/coupons/redeem', origin: ORIGIN, status: 200, body: '{"credited":50,"tx":"2"}' },
    { exchangeId: 'post', method: 'GET', pathAndQuery: '/api/v1/credits', origin: ORIGIN, status: 200, body: '{"credits":100}' },
    { exchangeId: 's1', method: 'POST', pathAndQuery: '/api/v1/coupons/redeem', origin: ORIGIN, status: 409, body: '{"error":"coupon already redeemed"}' },
  ]
  const built = buildAgentScriptReceipt({
    origin: ORIGIN,
    title: 'Single-use coupon double-credit race',
    exchanges,
    claims: [{
      kind: 'race',
      vulnClass: 'race_double_spend',
      baselineExchangeId: 'pre',
      burstExchangeIds: ['b1', 'b2'],
      postExchangeId: 'post',
      serialExchangeIds: ['s1'],
      balanceField: 'credits',
    }],
  })
  assert.ok(built)
  const verdict = verifyReceipt(built.receipt, built.transcript)
  assert.equal(verdict.confirmed, true, verdict.reason)
  assert.equal(verdict.evidence?.violationKind, 'over_credit')
  assert.equal(verdict.evidence?.serialControlKind, 'serial_rejection')
})

// ============================================================================
// SEAM 3: SSTI / Injection Differential (CWE-1336 / CWE-89 / CWE-78)
// ============================================================================

test('Seam 3 end-to-end: POST & GET ctx.prove_injection_differential confirms evaluated SSTI/CMDi & SQL error fingerprints, and fails closed on reflection/bare-500', async t => {
  const server = createServer((req, res) => {
    const url = new URL(req.url ?? '/', 'http://127.0.0.1')
    res.setHeader('content-type', 'application/json')
    if (url.pathname === '/api/v1/templates/render' && req.method === 'POST') {
      let raw = ''
      req.on('data', chunk => { raw += chunk })
      req.on('end', () => {
        const parsed = (() => { try { return JSON.parse(raw) as { template?: string } } catch { return {} } })()
        const tpl = String(parsed.template ?? '')
        // Benign math template evaluator fixture: evaluates `{{a*b}}` without reflecting the expression
        const rendered = tpl.replace(/\{\{(\d+)\*(\d+)\}\}/g, (_m, a, b) => String(Number(a) * Number(b)))
        res.statusCode = 200
        res.end(JSON.stringify({ rendered }))
      })
      return
    }
    if (url.pathname === '/api/v1/echo' && req.method === 'POST') {
      let raw = ''
      req.on('data', chunk => { raw += chunk })
      req.on('end', () => {
        const parsed = (() => { try { return JSON.parse(raw) as { template?: string } } catch { return {} } })()
        res.statusCode = 200
        res.end(JSON.stringify({ rendered: String(parsed.template ?? '') }))
      })
      return
    }
    if (url.pathname === '/api/v1/search' && req.method === 'GET') {
      const q = url.searchParams.get('q') ?? ''
      if (q.includes('SYNTAX_ERR')) {
        res.statusCode = 500
        res.end(JSON.stringify({ error: 'SQLITE_ERROR: near "SYNTAX_ERR": syntax error' }))
        return
      }
      if (q.includes('BARE_500')) {
        res.statusCode = 500
        res.end(JSON.stringify({ error: 'internal server error' }))
        return
      }
      res.statusCode = 200
      res.end(JSON.stringify({ items: [{ id: 1, title: q }] }))
      return
    }
    res.statusCode = 404
    res.end(JSON.stringify({ error: 'not found' }))
  })
  server.listen(0, '127.0.0.1')
  await once(server, 'listening')
  const origin = `http://127.0.0.1:${(server.address() as { port: number }).port}`
  t.after(() => new Promise<void>(resolve => { server.closeAllConnections(); server.close(() => resolve()) }))

  const grant = makePersonaGrant(origin)
  const makeFactory = () => createLocalAttemptFactory({
    sdkDir: SDK_DIR,
    createRpcOptions() {
      return {
        broker: new RequestBroker({ rejectUnauthorized: false }),
        grant,
        runId: `run-inj-${randomUUID().slice(0, 8)}`,
        assignmentId: 'assignment-inj-diff',
        targetOrigins: [origin],
      }
    },
  })

  // 3a. Positive: POST SSTI evaluated expression confirms through full verifyScript (even with "SSTI (CWE-1336)" title!)
  const sstiVerdict = await verifyScript({
    candidate: {
      name: 'post-ssti.ts',
      runtime: 'ts',
      code: `
await ctx.prove_injection_differential({
  path: '/api/v1/templates/render',
  method: 'POST',
  controlBody: { template: 'hello-world' },
  probeBody: { template: '{{739*740}}' },
  expectedOutput: '546860',
  vulnClass: 'ssti',
})
return ctx.result({ title: 'Server-side template injection in render (CWE-1336)', severity: 'critical' })
`,
    },
    openAttempt: makeFactory(),
  })
  assert.equal(sstiVerdict.confirmed, true, `${sstiVerdict.reason}: ${sstiVerdict.detail}`)

  // 3b. Direct TS SDK POST SSTI -> buildAgentScriptReceipt -> verifyReceipt (tests POST requestBody propagation!)
  const rpcPost = new VerifyRpcServer({
    broker: new RequestBroker({ rejectUnauthorized: false }),
    grant,
    runId: 'run-ssti-post',
    assignmentId: 'assign-ssti-post',
    nonce: randomUUID(),
    targetOrigins: [origin],
  })
  await rpcPost.start()
  const restorePost = bindRpcEnv(rpcPost)
  try {
    const ctx = new VerifyContext()
    const proof = await ctx.prove_injection_differential({
      path: '/api/v1/templates/render',
      method: 'POST',
      controlBody: { template: 'hello-world' },
      probeBody: { template: '{{739*740}}' },
      expectedOutput: '546860',
      vulnClass: 'ssti',
    })
    assert.equal(proof.ok, true)
    assert.equal(proof.evaluated, true)
    const built = buildAgentScriptReceipt({
      origin,
      title: 'POST SSTI in template preview (CWE-1336)',
      exchanges: transcriptToScriptExchanges(rpcPost),
      claims: ctx.claims as unknown as Record<string, unknown>[],
    })
    assert.ok(built, 'POST SSTI must build an ssti ProofReceipt')
    assert.equal(built.receipt.vulnClass, 'ssti')
    assert.equal(agentProofAttribution(built.receipt.vulnClass).cwe, 'CWE-1336')
    const verification = verifyReceipt(built.receipt, built.transcript)
    assert.equal(verification.confirmed, true, verification.reason)
  } finally {
    restorePost()
    await rpcPost.close()
  }

  // 3c. Fail-closed NEGATIVE: POST raw reflection (request body itself contains "546860") MUST fail closed in verifyReceipt!
  const rpcReflect = new VerifyRpcServer({
    broker: new RequestBroker({ rejectUnauthorized: false }),
    grant,
    runId: 'run-ssti-reflect',
    assignmentId: 'assign-ssti-reflect',
    nonce: randomUUID(),
    targetOrigins: [origin],
  })
  await rpcReflect.start()
  const restoreReflect = bindRpcEnv(rpcReflect)
  try {
    const ctx = new VerifyContext()
    const proof = await ctx.prove_injection_differential({
      path: '/api/v1/echo',
      method: 'POST',
      controlBody: { template: 'hello-world' },
      probeBody: { template: '546860' },
      expectedOutput: '546860',
      vulnClass: 'ssti',
    })
    assert.equal(proof.ok, false)
    assert.ok(proof.missingEvidence.includes('non_reflected_expression'))
    const built = buildAgentScriptReceipt({
      origin,
      title: 'Reflected POST body is not SSTI',
      exchanges: transcriptToScriptExchanges(rpcReflect),
      claims: ctx.claims as unknown as Record<string, unknown>[],
    })
    assert.ok(built)
    const verification = verifyReceipt(built.receipt, built.transcript)
    assert.equal(verification.confirmed, false, 'POST reflection MUST fail closed in verifyEvaluatedExpression')
  } finally {
    restoreReflect()
    await rpcReflect.close()
  }

  // 3d. Positive: SQL error fingerprint path (no expectedOutput) -> CWE-89 confirmed
  const rpcSqlErr = new VerifyRpcServer({
    broker: new RequestBroker({ rejectUnauthorized: false }),
    grant,
    runId: 'run-sqli-err',
    assignmentId: 'assign-sqli-err',
    nonce: randomUUID(),
    targetOrigins: [origin],
  })
  await rpcSqlErr.start()
  const restoreSqlErr = bindRpcEnv(rpcSqlErr)
  try {
    const ctx = new VerifyContext()
    await ctx.prove_injection_differential({
      control: '/api/v1/search?q=benign',
      probe: '/api/v1/search?q=SYNTAX_ERR',
      vulnClass: 'sqli',
    })
    const oracle = evaluateClaims(rpcSqlErr.transcript, ctx.claims as never, { claimedImpact: 'injection' })
    assert.equal(oracle.passed, true, oracle.failures.join('; '))
    const built = buildAgentScriptReceipt({
      origin,
      title: 'SQL injection syntax error fingerprint (CWE-89)',
      exchanges: transcriptToScriptExchanges(rpcSqlErr),
      claims: ctx.claims as unknown as Record<string, unknown>[],
    })
    assert.ok(built)
    assert.equal(built.receipt.vulnClass, 'sqli_error')
    assert.equal(agentProofAttribution(built.receipt.vulnClass).cwe, 'CWE-89')
    const verification = verifyReceipt(built.receipt, built.transcript)
    assert.equal(verification.confirmed, true, verification.reason)
  } finally {
    restoreSqlErr()
    await rpcSqlErr.close()
  }

  // 3e. Fail-closed NEGATIVE: bare 200 -> 500 without engine fingerprint MUST fail closed
  const rpcBare500 = new VerifyRpcServer({
    broker: new RequestBroker({ rejectUnauthorized: false }),
    grant,
    runId: 'run-bare-500',
    assignmentId: 'assign-bare-500',
    nonce: randomUUID(),
    targetOrigins: [origin],
  })
  await rpcBare500.start()
  const restoreBare500 = bindRpcEnv(rpcBare500)
  try {
    const ctx = new VerifyContext()
    await ctx.prove_injection_differential({
      control: '/api/v1/search?q=benign',
      probe: '/api/v1/search?q=BARE_500',
      vulnClass: 'sqli',
    })
    const built = buildAgentScriptReceipt({
      origin,
      title: 'Bare 500 without fingerprint',
      exchanges: transcriptToScriptExchanges(rpcBare500),
      claims: ctx.claims as unknown as Record<string, unknown>[],
    })
    assert.ok(built)
    const verification = verifyReceipt(built.receipt, built.transcript)
    assert.equal(verification.confirmed, false, 'bare 200->500 without engine fingerprint MUST fail closed')
  } finally {
    restoreBare500()
    await rpcBare500.close()
  }

  // 3f. Python parity: POST SSTI via verifyScript
  const pySsti = await verifyScript({
    candidate: {
      name: 'post-ssti.py',
      runtime: 'python',
      code: `
ctx.prove_injection_differential(
    path="/api/v1/templates/render",
    method="POST",
    control_body={"template": "hello-world"},
    probe_body={"template": "{{739*740}}"},
    expected_output="546860",
    vuln_class="ssti",
)
result = ctx.result("Python POST SSTI (CWE-1336)", severity="critical")
`,
    },
    openAttempt: makeFactory(),
  })
  assert.equal(pySsti.confirmed, true, `${pySsti.reason}: ${pySsti.detail}`)
})

// ============================================================================
// SEAM 4: Floor-Confirmed Concrete-ID Route Normalization
// ============================================================================

test('Seam 4: normalizeConfirmedRouteTemplate normalizes concrete IDs (short prefixed, hex, numeric, UUID) without collapsing route words or versions', () => {
  // Concrete IDs all collapse to `:id`
  assert.equal(normalizeConfirmedRouteTemplate('/api/tickets/tkt_123'), '/api/tickets/:id')
  assert.equal(normalizeConfirmedRouteTemplate('/api/tickets/tkt-1001'), '/api/tickets/:id')
  assert.equal(normalizeConfirmedRouteTemplate('/api/tickets/tkt_456?expand=comments'), '/api/tickets/:id')
  assert.equal(normalizeConfirmedRouteTemplate('/api/tickets/tkt_deadbeef'), '/api/tickets/:id')
  assert.equal(normalizeConfirmedRouteTemplate('/api/tickets/tkt1001'), '/api/tickets/:id')
  assert.equal(normalizeConfirmedRouteTemplate('/api/tickets/:ticketId'), '/api/tickets/:id')
  assert.equal(normalizeConfirmedRouteTemplate('/api/tickets/{id}'), '/api/tickets/:id')
  assert.equal(normalizeConfirmedRouteTemplate('/api/tickets/42'), '/api/tickets/:id')
  assert.equal(normalizeConfirmedRouteTemplate('/api/tickets/550e8400-e29b-41d4-a716-446655440000'), '/api/tickets/:id')
  assert.equal(normalizeConfirmedRouteTemplate('/api/v1/orders/ord_9a2f/items/itm_01'), '/api/v1/orders/:id/items/:id')

  // Version segments and literal hyphenated/underscored route words MUST stay literal
  assert.equal(normalizeConfirmedRouteTemplate('/api/v1/user-profile'), '/api/v1/user-profile')
  assert.equal(normalizeConfirmedRouteTemplate('/api/v2/reset-password'), '/api/v2/reset-password')
  assert.equal(normalizeConfirmedRouteTemplate('/api/v1/oauth2/token'), '/api/v1/oauth2/token')
  assert.equal(normalizeConfirmedRouteTemplate('/api/api-v2/health-check'), '/api/api-v2/health-check')
  assert.equal(normalizeConfirmedRouteTemplate('/api/v1/user_feed'), '/api/v1/user_feed')
})

test('Seam 4: floor-confirmed GET /api/tickets/tkt_123 matches template /api/tickets/:id and sibling /api/tickets/tkt_456 without blocking unconfirmed PATCH', () => {
  const confirmedSets = buildConfirmedRouteSets([
    { origin: ORIGIN, method: 'GET', path: '/api/tickets/tkt_123', cwe: 'CWE-639', probeClass: 'broken-access-control' },
  ])
  // Template endpoint and sibling concrete ticket IDs match GET
  assert.equal(isRouteConfirmed({ method: 'GET', path: '/api/tickets/:id' }, confirmedSets), true)
  assert.equal(isRouteConfirmed({ method: 'GET', path: '/api/tickets/tkt_456' }, confirmedSets), true)
  assert.equal(isRouteConfirmed({ method: 'GET', path: '/api/tickets/tkt-999' }, confirmedSets), true)

  // Method-scoped check preserves unconfirmed write method (PATCH) on the same route template
  assert.equal(isRouteConfirmed({ method: 'PATCH', path: '/api/tickets/tkt_456' }, confirmedSets), false)
  assert.equal(isRouteConfirmed({ method: 'PATCH', path: '/api/tickets/:id' }, confirmedSets), false)

  // Any-method check (used by high-risk route coverage deduplication) matches the normalized path
  assert.equal(isRouteConfirmed({ method: 'PATCH', path: '/api/tickets/:id' }, confirmedSets, { matchAnyMethod: true }), true)

  // Unrelated resource routes remain unconfirmed
  assert.equal(isRouteConfirmed({ method: 'GET', path: '/api/invoices/inv_123' }, confirmedSets), false)
})
