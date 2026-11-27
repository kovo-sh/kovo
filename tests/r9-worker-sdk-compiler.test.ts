/**
 * Round 9 Worker SDK & Trace Compiler regression suite (`tests/r9-worker-sdk-compiler.test.ts`).
 *
 * Defensive QA: verifies all four Round 9 SDK + compiler fixes:
 *  1. Regression B (`preflightFail` in `worker/kovo_verify/kovo_verify.ts`): never fabricates an
 *     unsigned `kind: 'composite_receipt'` claim client-side; returns structured `{ confirmed: false,
 *     rejectedBy, reason, evidence }` and emits clear preflight error feedback via `normalizeProofResult`
 *     so `verify-runner.ts` surfaces the real preflight cause instead of `verificationId` rejection.
 *  2. `diagnoseSealFailure()`: honors `raw.jsonPath || raw.path`, puts HTTP >= 400 status + `topKeys`
 *     up front, and puts `capability.seal: jsonPath "..." not found (HTTP 2xx, topKeys=[...])` up front
 *     well inside 140-char truncation boundaries without leaking secrets.
 *  3. Actionable orphan-hop diagnostics in `ChainBuilder.build()` / `prove()`: emits a concise hint
 *     before `composite.verify` without throwing or breaking host `dag_topology` fail-closed checks.
 *  4. `src/server/trace-proof-compiler.ts`: links `GET` cache-prime hops to cross-tenant terminal hops
 *     via `state_transition_binding` when an ablation control is present (`dual_tenant_abac` /
 *     `cache_bleed`), and guards `jsonUrlQuery` seal generation against non-2xx responses and
 *     missing/redacted URLs or query params.
 */
import assert from 'node:assert/strict'
import { randomUUID } from 'node:crypto'
import { once } from 'node:events'
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { createServer } from 'node:http'
import { tmpdir } from 'node:os'
import { dirname, join, resolve } from 'node:path'
import test, { describe, type TestContext } from 'node:test'
import { fileURLToPath } from 'node:url'
import { Script } from 'node:vm'

import { RequestBroker, type Grant } from '../src/server/broker.ts'
import { SEAL_FIELD_NOT_FOUND_ERROR } from '../src/server/derived-custody.ts'
import type { ResolvedPersona } from '../src/server/persona-vault.ts'
import {
  compileTraceToKovoVerifyScript,
  type RecordedRequestExchange,
} from '../src/server/trace-proof-compiler.ts'
import { createLocalAttemptFactory } from '../src/server/verify-rpc.ts'
import { verifyScript } from '../src/server/verify-runner.ts'
import { runVerification, VerifyContext } from '../worker/kovo_verify/kovo_verify.ts'

process.env.KOVO_ALLOW_LOCAL_LAB = '1'

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const SDK_DIR = join(REPO_ROOT, 'worker', 'kovo_verify')
const API_ORIGIN = 'https://api.r9-sdk-compiler.example'
const SAMPLE_JWT = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyX3I5Iiwicm9sZSI6Im1lbWJlciJ9.sigR9Carryover01'

async function withMockVerifyRpc(
  t: TestContext,
  handler: (op: string, args: Record<string, unknown>) => unknown,
): Promise<{ ctx: VerifyContext; rpcOps: string[]; resultPath: string }> {
  const dir = mkdtempSync(join(tmpdir(), 'kovo-r9-sdk-'))
  const socketPath = join(dir, 'verify.sock')
  const tokenPath = join(dir, 'token')
  const contextPath = join(dir, 'context.json')
  const resultPath = join(dir, 'result.json')
  writeFileSync(tokenPath, 'tok-r9-1', 'utf8')
  writeFileSync(contextPath, JSON.stringify({
    nonce: 'nonce-r9-1',
    runId: 'run-r9-1',
    targetOrigins: [API_ORIGIN],
    sdkVersion: 'kovo_verify/v8',
  }), 'utf8')

  const rpcOps: string[] = []
  const server = createServer((req, res) => {
    const chunks: Buffer[] = []
    req.on('data', c => chunks.push(Buffer.from(c)))
    req.on('end', () => {
      try {
        const body = JSON.parse(Buffer.concat(chunks).toString('utf8')) as { op: string; args: Record<string, unknown> }
        rpcOps.push(body.op)
        const result = handler(body.op, body.args ?? {})
        res.writeHead(200, { 'content-type': 'application/json' })
        res.end(JSON.stringify({ ok: true, result }))
      } catch (err) {
        res.writeHead(200, { 'content-type': 'application/json' })
        res.end(JSON.stringify({ ok: false, error: err instanceof Error ? err.message : String(err) }))
      }
    })
  })
  await new Promise<void>((res, rej) => { server.once('error', rej); server.listen(socketPath, () => res()) })

  const savedEnv = {
    KOVO_RPC_SOCKET: process.env.KOVO_RPC_SOCKET,
    KOVO_RPC_TOKEN_FILE: process.env.KOVO_RPC_TOKEN_FILE,
    KOVO_RPC_CONTEXT_FILE: process.env.KOVO_RPC_CONTEXT_FILE,
    KOVO_VERIFY_NONCE: process.env.KOVO_VERIFY_NONCE,
    KOVO_PROOF_RESULT_FILE: process.env.KOVO_PROOF_RESULT_FILE,
  }
  process.env.KOVO_RPC_SOCKET = socketPath
  process.env.KOVO_RPC_TOKEN_FILE = tokenPath
  process.env.KOVO_RPC_CONTEXT_FILE = contextPath
  process.env.KOVO_VERIFY_NONCE = 'nonce-r9-1'
  process.env.KOVO_PROOF_RESULT_FILE = resultPath

  t.after(async () => {
    for (const [k, v] of Object.entries(savedEnv)) {
      if (v === undefined) delete process.env[k]
      else process.env[k] = v
    }
    await new Promise<void>(r => { server.closeAllConnections(); server.close(() => r()) })
    rmSync(dir, { recursive: true, force: true })
  })

  return { ctx: new VerifyContext(), rpcOps, resultPath }
}

function loadCompiledEntrypoint(script: string): (ctx: Record<string, unknown>) => Promise<unknown> {
  assert.ok(Buffer.byteLength(script, 'utf8') <= 64 * 1024, 'Compiled script must be <= 64 KiB')
  const rewritten = script.replace(/^export default\s+/, 'return ')
  new Script(`(function(){ ${rewritten} })`)
  return (new Function(rewritten) as () => (ctx: Record<string, unknown>) => Promise<unknown>)()
}

describe('R9-1: preflightFail never fabricates unsigned composite_receipt claims', () => {
  test('ch.prove preflight rejection leaves claims/effectiveClaims empty and emits structured error via runVerification', async (t) => {
    let seq = 0
    const { ctx, rpcOps, resultPath } = await withMockVerifyRpc(t, (op, args) => {
      if (op === 'http.send' || op === 'http') {
        seq += 1
        const path = String(args.path ?? '/')
        if (path === '/v1/denied') {
          return { exchangeId: `ex-${seq}`, status: 403, method: 'GET', pathAndQuery: path, mediaType: 'application/json', headers: { 'content-type': 'application/json' }, body: '{"error":"denied"}', bodyPreview: '{"error":"denied"}', bodyBytes: 18, bodySha256: 's1', durationMs: 2, personaHandle: 'member_a' }
        }
        if (path === '/v1/mint') {
          const body = JSON.stringify({ access_token: SAMPLE_JWT })
          return { exchangeId: `ex-${seq}`, status: 200, method: 'POST', pathAndQuery: path, mediaType: 'application/json', headers: { 'content-type': 'application/json' }, body, bodyPreview: body, bodyBytes: body.length, bodySha256: 's2', durationMs: 2, personaHandle: 'member_a' }
        }
        return { exchangeId: `ex-${seq}`, status: 200, method: 'GET', pathAndQuery: path, mediaType: 'application/json', headers: { 'content-type': 'application/json' }, body: '{"ok":true}', bodyPreview: '{"ok":true}', bodyBytes: 11, bodySha256: 's3', durationMs: 2, personaHandle: 'member_a' }
      }
      if (op === 'composite.verify') {
        return { confirmed: true, ok: true, verified: true, chainId: 'ok', terminalVulnClass: 'bfla', replayMode: 'fresh_clean_replay', modeBVerified: true, hopCount: 1, verifiedEdges: [], reason: 'ok', claim: { kind: 'composite_receipt', verificationId: 'cv-host-1', chainId: 'ok', terminalVulnClass: 'bfla', exchangeIds: ['ex-3'] } }
      }
      throw new Error(`Unexpected op ${op}`)
    })

    // (a) Non-2xx terminal preflight rejection: NO claim fabricated, NO composite.verify RPC.
    const ch403 = ctx.chain('r9-c-403', 'bfla')
    const denied = await ch403.step('GET /v1/denied', { as: 'member_a' })
    const res403 = await ch403.prove({ terminalExchange: denied, claimedImpact: 'denied read' })
    assert.equal(res403.confirmed, false)
    assert.equal(res403.failedStage, 'preflight')
    assert.equal(res403.rejectedBy, 'terminal_exchange_not_succeeding')
    assert.equal(res403.claim, undefined, 'preflightFail must NEVER attach a synthetic composite_receipt claim')
    assert.equal(ctx.claims.length, 0)
    assert.equal(ctx.effectiveClaims().length, 0, 'preflightFail must NOT push an unsigned composite_receipt into effectiveClaims()')
    assert.equal(rpcOps.includes('composite.verify'), false)

    // (b) Literal token carry-over preflight rejection: NO claim fabricated, NO composite.verify RPC.
    const chCarry = ctx.chain('r9-c-carry', 'privilege_escalation')
    const h1 = await chCarry.step('POST /v1/mint', { as: 'member_a' })
    const rawTok = (h1.json as { access_token: string }).access_token
    await chCarry.step('GET /v1/vault', { headers: { Authorization: `Bearer ${rawTok}` } })
    const resCarry = await chCarry.prove({ claimedImpact: 'carryover read' })
    assert.equal(resCarry.confirmed, false)
    assert.equal(resCarry.failedStage, 'preflight')
    assert.equal(resCarry.rejectedBy, 'literal_token_carryover')
    assert.equal(resCarry.claim, undefined)
    assert.equal(ctx.effectiveClaims().length, 0)
    assert.equal(rpcOps.includes('composite.verify'), false)

    // (c) runVerification writes structured preflight error + empty claims (never an unsigned composite_receipt).
    await runVerification({
      async verify(vctx) {
        const ch = vctx.chain('r9-run-403', 'bfla')
        const d = await ch.step('GET /v1/denied', { as: 'member_a' })
        const p = await ch.prove({ terminalExchange: d, claimedImpact: 'denied' })
        return vctx.result({ title: 'Preflight 403', description: p.reason })
      },
    })
    const written = JSON.parse(readFileSync(resultPath, 'utf8')) as {
      claims: Array<{ kind: string }>; error?: string; rejectedBy?: string; evidence?: { negativeEdge?: { status?: number } }
    }
    assert.deepEqual(written.claims, [], 'written result.json must have zero synthetic composite_receipt claims')
    assert.equal(written.rejectedBy, 'terminal_exchange_not_succeeding')
    assert.match(written.error ?? '', /preflight\[terminal_exchange_not_succeeding\].*HTTP 403/)
    assert.equal(written.evidence?.negativeEdge?.status, 403)
  })

  test('verifyScript end-to-end surfaces real preflight cause and never composite_receipt verificationId error', async (t) => {
    const srv = createServer((req, res) => {
      const u = new URL(req.url ?? '/', 'http://127.0.0.1')
      if (u.pathname === '/v1/protected') {
        const body = JSON.stringify({ error: 'forbidden' })
        res.writeHead(403, { 'content-type': 'application/json', 'content-length': Buffer.byteLength(body) })
        res.end(body)
        return
      }
      res.writeHead(404).end('not found')
    })
    srv.listen(0, '127.0.0.1')
    await once(srv, 'listening')
    const port = (srv.address() as { port: number }).port
    const origin = `http://127.0.0.1:${port}`
    t.after(() => new Promise<void>(r => { srv.closeAllConnections(); srv.close(() => r()) }))

    const member: ResolvedPersona = {
      id: 'p-mem', handle: 'member_a', roleLabel: 'member (org_a)', originAllowlist: [origin],
      authKind: 'bearer', headerName: null, secret: 'r9_member_bearer_secret_001122', canaryMarkers: [],
    }
    const grant: Grant = {
      origin, tier: 3, allowLocalLab: true, allowedPorts: [port], maxRpsPerOrigin: 200,
      personas: new Map([['member_a', member]]),
      canRead: c => c === origin, isStateChangeApproved: () => true, audit: () => {},
    }
    const openAttempt = createLocalAttemptFactory({
      sdkDir: SDK_DIR,
      timeoutMs: 10_000,
      createRpcOptions: (_nonce, attempt) => ({
        broker: new RequestBroker({ transportConfig: { http2: false } }),
        grant,
        runId: `r9-preflight-e2e-${attempt}-${randomUUID().slice(0, 6)}`,
        assignmentId: 'assign-r9',
        targetOrigins: [origin],
        compositeVerifyOptions: { attackerPersonas: ['member_a'] },
      }),
    })
    const verdict = await verifyScript({
      candidate: {
        name: 'r9-preflight-403.ts',
        runtime: 'ts',
        title: 'Denied terminal preflight check',
        code: `
          const ch = ctx.chain('r9-e2e-403', 'bfla')
          const ex = await ch.step('GET /v1/protected', { as: 'member_a' })
          const p = await ch.prove({ terminalExchange: ex, claimedImpact: 'should short-circuit' })
          return ctx.result({ title: 'Denied terminal preflight check', description: p.reason })
        `,
      },
      openAttempt,
      fastFailOnAttempt1: true,
      timeoutMs: 15_000,
    })
    assert.equal(verdict.confirmed, false)
    const allText = `${verdict.detail} ${verdict.stderrPreview ?? ''} ${verdict.attempts.flatMap(a => a.failures).join(' ')}`
    assert.doesNotMatch(allText, /must reference a host-verified composite\.verify verificationId/i)
    assert.match(allText, /terminal_exchange_not_succeeding/)
    assert.match(allText, /HTTP 403/)
  })
})

describe('R9-2: diagnoseSealFailure diagnostics (path alias, 4xx up front, 2xx jsonPath miss up front)', () => {
  test('reads raw.jsonPath || raw.path, puts 4xx HTTP status + topKeys first, and puts 2xx jsonPath miss + topKeys first (<140 chars)', async (t) => {
    const SECRET_VAL = 'r9_secret_token_never_echo_998877'
    let seq = 0
    const { ctx } = await withMockVerifyRpc(t, (op, args) => {
      if (op === 'http.send' || op === 'http') {
        seq += 1
        const path = String(args.path ?? '/')
        if (path === '/v1/err403') {
          const body = JSON.stringify({ error: 'forbidden', code: 'E_AUTH', requestId: 'req-1' })
          return { exchangeId: `ex-${seq}`, status: 403, method: 'POST', pathAndQuery: path, mediaType: 'application/json', headers: { 'content-type': 'application/json' }, body, bodyPreview: body, bodyBytes: body.length, bodySha256: 'e1', durationMs: 2, personaHandle: 'member_a' }
        }
        const body = JSON.stringify({ id: 'obj_1', access_token: SECRET_VAL, scope: 'read' })
        return { exchangeId: `ex-${seq}`, status: 200, method: 'POST', pathAndQuery: path, mediaType: 'application/json', headers: { 'content-type': 'application/json' }, body, bodyPreview: body, bodyBytes: body.length, bodySha256: 'e2', durationMs: 2, personaHandle: 'member_a' }
      }
      if (op === 'capability.seal') {
        throw new Error(SEAL_FIELD_NOT_FOUND_ERROR)
      }
      throw new Error(`Unexpected op ${op}`)
    })

    const ex403 = await ctx.http_send('/v1/err403', { method: 'POST' })
    await assert.rejects(
      () => ctx.seal_capability({ exchange: ex403, slot: 's_err', jsonPath: '$.access_token' }),
      (err: unknown) => {
        const msg = err instanceof Error ? err.message : String(err)
        assert.match(msg, /^capability\.seal: source exchange returned HTTP 403 \(topKeys=\[error, code, requestId\]\)/)
        assert.ok(msg.indexOf('topKeys=[') < 80, `4xx topKeys must appear up front, got: ${msg}`)
        return true
      },
    )

    const ex200 = await ctx.http_send('/v1/ok', { method: 'POST' })
    // Verify `path` alias (not only `jsonPath`) gets full jsonPath-miss diagnosis up front!
    await assert.rejects(
      () => ctx.seal_capability({ exchange: ex200, slot: 's_alias', path: '$.missingField' }),
      (err: unknown) => {
        const msg = err instanceof Error ? err.message : String(err)
        assert.match(msg, /^capability\.seal: jsonPath "\$\.missingField" not found \(HTTP 200, topKeys=\[id, access_token, scope\]\)/)
        assert.ok(msg.slice(0, 140).includes('topKeys=[id, access_token, scope]'), `topKeys must be visible within first 140 chars, got: ${msg}`)
        assert.equal(msg.includes(SECRET_VAL), false, 'raw secret must never leak into diagnostic')
        return true
      },
    )
  })
})

describe('R9-3: actionable orphan-hop diagnostics in ChainBuilder.build()', () => {
  test('emits concise hint before composite.verify without throwing or blocking host dag_topology rejection', async (t) => {
    let seq = 0
    const { ctx, rpcOps } = await withMockVerifyRpc(t, (op, args) => {
      if (op === 'http.send' || op === 'http') {
        seq += 1
        return { exchangeId: `ex-${seq}`, status: 200, method: String(args.method ?? 'GET'), pathAndQuery: String(args.path ?? '/'), mediaType: 'application/json', headers: { 'content-type': 'application/json' }, body: '{"ok":true}', bodyPreview: '{"ok":true}', bodyBytes: 11, bodySha256: `h${seq}`, durationMs: 2, personaHandle: 'member_a' }
      }
      if (op === 'composite.verify') {
        return { confirmed: false, ok: false, verified: false, chainId: 'r9-orphan', terminalVulnClass: 'dual_tenant_abac', replayMode: 'fresh_clean_replay', modeBVerified: false, hopCount: 2, verifiedEdges: [], failedStage: 'dag_topology', rejectedBy: 'composite_receipt', reason: 'composite_verification_rejected' }
      }
      throw new Error(`Unexpected op ${op}`)
    })

    const stderrChunks: string[] = []
    const origWrite = process.stderr.write.bind(process.stderr)
    process.stderr.write = ((chunk: string | Uint8Array) => {
      stderrChunks.push(typeof chunk === 'string' ? chunk : Buffer.from(chunk).toString('utf8'))
      return true
    }) as typeof process.stderr.write
    t.after(() => { process.stderr.write = origWrite })

    const ch = ctx.chain('r9-orphan', 'dual_tenant_abac')
    await ch.step('GET /v1/prime', { hopId: 'prime', as: 'member_a' })
    await ch.step('GET /v1/target', { hopId: 'target', as: 'member_a' })

    const res = await ch.prove({ claimedImpact: 'disconnected chain' })
    assert.equal(res.confirmed, false)
    assert.equal(res.failedStage, 'dag_topology', 'must still forward to host composite.verify for dag_topology enforcement')
    assert.equal(rpcOps.includes('composite.verify'), true)
    assert.match(ch.lastOrphanHint ?? '', /disconnected hop\(s\) \[prime\].*terminal "target"/)
    assert.match(ch.lastOrphanHint ?? '', /ch\.seal\(\.\.\.\)/)
    assert.match(ch.lastOrphanHint ?? '', /ch\.stateTransition\(/)
    assert.match(stderrChunks.join(''), /disconnected hop\(s\) \[prime\]/)
    assert.match(res.reason, /disconnected hop\(s\) \[prime\]/)
  })
})

describe('R9-4: trace-proof-compiler GET cache-prime linking and jsonUrlQuery guarding', () => {
  test('links GET cache-prime hop to cross-tenant terminal hop via state_transition_binding when ablation control is present', async () => {
    const exchanges: RecordedRequestExchange[] = [
      {
        exchangeId: 'ex_ctrl',
        origin: API_ORIGIN,
        method: 'GET',
        pathAndQuery: '/api/v1/orgs/org_victim/records',
        persona: 'dual_member',
        status: 403,
        responseJson: { error: 'forbidden' },
        timestampMs: 50,
      },
      {
        exchangeId: 'ex_prime',
        origin: API_ORIGIN,
        method: 'GET',
        pathAndQuery: '/api/v1/orgs/org_prime/admin-overview',
        persona: 'dual_member',
        status: 200,
        responseJson: { role: 'admin', org: 'org_prime' },
        timestampMs: 100,
      },
      {
        exchangeId: 'ex_term',
        origin: API_ORIGIN,
        method: 'GET',
        pathAndQuery: '/api/v1/orgs/org_victim/records',
        persona: 'dual_member',
        status: 200,
        responseJson: { tenant: 'org_victim', records: [{ id: 'rec_1', total: 5000 }] },
        timestampMs: 200,
      },
    ]

    const compiled = compileTraceToKovoVerifyScript({
      submission: {
        title: 'Dual-tenant GET cache prime bleed',
        vulnClass: 'dual_tenant_abac',
        oracleFamily: 'dual_tenant_abac',
        exchangeIds: ['ex_prime', 'ex_term'],
        controlExchangeId: 'ex_ctrl',
        terminalExchangeId: 'ex_term',
        attackerPersona: 'dual_member',
      },
      exchanges,
      allowedPersonas: ['member_a', 'dual_member'],
      runOrigin: API_ORIGIN,
    })

    assert.equal(compiled.ok, true)
    assert.ok(compiled.script)
    assert.doesNotMatch(compiled.warnings.join('\n'), /pruned.*ex_prime/, 'GET cache-prime hop must NOT be pruned')
    assert.match(compiled.script, /ch\.stateTransition\(\{\s*fromHopId:\s*"step_1",\s*toHopId:\s*"step_2"/)
    assert.match(compiled.script, /ablationExchange:\s*ctrl/)

    // Execute compiled script against a mock ctx and confirm both hops + stateTransition edge reach terminal
    const hops: string[] = []
    const transitions: Array<Record<string, unknown>> = []
    const responses = [{ status: 403, json: { error: 'forbidden' } }, { status: 200, json: { role: 'admin' } }, { status: 200, json: { records: [1] } }]
    let idx = 0
    const mockCtx = {
      chain() {
        const self = {
          control: async () => ({ exchangeId: `ex_${++idx}`, ...responses[idx - 1]! }),
          step: async (_t: unknown, opts: { hopId?: string } = {}) => { hops.push(opts.hopId ?? ''); return { exchangeId: `ex_${++idx}`, ...responses[idx - 1]! } },
          stateTransition: (e: Record<string, unknown>) => { transitions.push(e); return self },
          prove: async () => ({ confirmed: true, reason: 'ok' }),
        }
        return self
      },
      result: (r: unknown) => r,
    }
    await loadCompiledEntrypoint(compiled.script)(mockCtx)
    assert.deepEqual(hops, ['step_1', 'step_2'])
    assert.equal(transitions.length, 1)
    assert.equal(transitions[0]!.fromHopId, 'step_1')
    assert.equal(transitions[0]!.toHopId, 'step_2')
    assert.ok(typeof transitions[0]!.entityId === 'string' && transitions[0]!.entityId.length > 0)
  })

  test('guards jsonUrlQuery seal generation at compile time (non-2xx / redacted) and runtime (never passes value: "")', async () => {
    const liveSig = 'sig_live_url_param_99887766aa'
    // (a) Compile-time: non-2xx source exchange MUST NOT emit a jsonUrlQuery seal
    const non2xxCompiled = compileTraceToKovoVerifyScript({
      submission: { title: 'Non-2xx url query ignored', vulnClass: 'broken_access_control', exchangeIds: ['e1', 'e2'], terminalExchangeId: 'e2' },
      exchanges: [
        { exchangeId: 'e1', origin: API_ORIGIN, method: 'POST', pathAndQuery: '/v1/start', persona: 'member_a', status: 403, responseJson: { nextUrl: `/v1/next?sig=${liveSig}` }, timestampMs: 10 },
        { exchangeId: 'e2', origin: API_ORIGIN, method: 'GET', pathAndQuery: `/v1/other?sig=${liveSig}&item=42`, persona: 'member_a', status: 200, responseJson: { ok: true }, timestampMs: 20 },
      ],
      runOrigin: API_ORIGIN,
    })
    assert.equal(non2xxCompiled.ok, true)
    assert.doesNotMatch(non2xxCompiled.script ?? '', /ch\.seal\(/, 'non-2xx source must not generate jsonUrlQuery seal')

    // (b) Valid 2xx jsonUrlQuery compiles with runtime status/missing/redacted guards (NEVER passing value: "" to ch.seal)
    const okCompiled = compileTraceToKovoVerifyScript({
      submission: { title: 'Guarded jsonUrlQuery seal', vulnClass: 'dual_tenant_abac', exchangeIds: ['g1', 'g2'], terminalExchangeId: 'g2' },
      exchanges: [
        { exchangeId: 'g1', origin: API_ORIGIN, method: 'POST', pathAndQuery: '/v1/mint-link', persona: 'member_a', status: 200, responseJson: { downloadUrl: `/v1/download?sig=${liveSig}` }, timestampMs: 10 },
        { exchangeId: 'g2', origin: API_ORIGIN, method: 'GET', pathAndQuery: `/v1/download?sig=${liveSig}&item=99`, persona: 'member_a', status: 200, responseJson: { ok: true }, timestampMs: 20 },
      ],
      runOrigin: API_ORIGIN,
    })
    assert.equal(okCompiled.ok, true)
    assert.ok(okCompiled.script)
    assert.doesNotMatch(okCompiled.script, /ch\.seal\([^)]*value:[^)]*\?\?\s*""/, 'must never pass fallback empty string directly into ch.seal')

    const runWithStep1 = async (step1Resp: { status: number; json: unknown }) => {
      const sealCalls: Array<Record<string, unknown>> = []
      let n = 0
      const mockCtx = {
        chain() {
          const self = {
            control: async () => ({ exchangeId: `ex_${++n}`, status: 403, json: { error: 'denied' } }),
            step: async () => (++n === 2 ? { exchangeId: `ex_${n}`, ...step1Resp } : { exchangeId: `ex_${n}`, status: 200, json: { ok: true } }),
            seal: async (_ex: unknown, sel: Record<string, unknown>) => { sealCalls.push(sel); return 'cap:hop_1:cap_1' },
            edge: () => self,
            prove: async () => ({ confirmed: true, reason: 'ok' }),
          }
          return self
        },
        result: (r: unknown) => r,
      }
      await loadCompiledEntrypoint(okCompiled.script!)(mockCtx)
      return sealCalls
    }

    // Runtime non-2xx fails before calling ch.seal
    await assert.rejects(() => runWithStep1({ status: 403, json: { error: 'denied' } }), /returned HTTP 403/)
    // Runtime missing param fails before calling ch.seal
    await assert.rejects(() => runWithStep1({ status: 200, json: { downloadUrl: '/v1/download?other=1' } }), /missing or redacted/)
    // Runtime redacted URL fails before calling ch.seal
    await assert.rejects(() => runWithStep1({ status: 200, json: { downloadUrl: '[redacted]' } }), /missing or redacted/)
    // Runtime valid 2xx succeeds and passes exact extracted sig
    const calls = await runWithStep1({ status: 200, json: { downloadUrl: '/v1/download?sig=fresh_sig_11223344' } })
    assert.equal(calls.length, 1)
    assert.equal(calls[0]!.value, 'fresh_sig_11223344')
  })
})

test('R9 LOC ceiling & anti-contamination invariants hold on worker/kovo_verify/kovo_verify.ts', () => {
  const sdkSrc = readFileSync(join(REPO_ROOT, 'worker/kovo_verify/kovo_verify.ts'), 'utf8')
  const loc = sdkSrc.trimEnd().split('\n').length
  assert.ok(loc <= 800, `worker/kovo_verify/kovo_verify.ts must stay <= 800 LOC, got ${loc}`)
  assert.equal(/\bnew\s+RegExp\s*\(/.test(sdkSrc), false, 'kovo_verify.ts must not use new RegExp()')
})
