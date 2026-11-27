// @kernel @fixes R3-12, R3-13
/**
 * Confirmation-Kernel R4 Regression & Security Suite.
 *
 * Covers 4 confirmation-kernel / VerifyRPC fixes and negative security invariants:
 *  1. `conserved_balance` host timestamps (`startedAt`, `endedAt`, `seq`, `op`) in
 *     `VerifyRpcServer.buildHostSignedTranscript()` and `op: 'race'` in `handleRace()`.
 *  2. `parseCapabilityArg` canonical handle object aliases with strict validation & custody.
 *  3. `parser_cache_differential` mode normalization (`differentialKind` + cache-bleed aliases)
 *     and full `PARSER_CACHE_INF_KEYS` inference with fail-closed conflict/garbage handling.
 *  4. `hasVerifiedTermEdge` pre-supplemental `autodag` `state_transition_binding` /
 *     `async_pivot_binding` acceptance (keeping supplemental edges strictly excluded without
 *     capability custody) + actionable `missing_denied_control_on_terminal_route` diagnostics.
 */
import assert from 'node:assert/strict'
import { once } from 'node:events'
import { createServer, request as httpRequest } from 'node:http'
import type { AddressInfo } from 'node:net'
import { join } from 'node:path'
import test from 'node:test'
import { RequestBroker, type Grant } from '../src/server/broker.ts'
import { augmentCompositeReceiptWithAutoDag } from '../src/server/composite-autodag.ts'
import {
  sha256Hex,
  signHostRecord,
  singleReceiptToComposite,
  verifyCompositeReceipt,
  type CompositeProofReceipt,
  type HostAsyncPollRecord,
  type HostOobEvent,
  type HostSignedTranscript,
  type HostTranscriptEntry,
} from '../src/server/composite-receipt.ts'
import { resetRunCustodyBudgets } from '../src/server/derived-custody.ts'
import { HostFactLog } from '../src/server/host-fact-log.ts'
import type { ImpactStep } from '../src/server/oracle-invariants.ts'
import type { ResolvedPersona } from '../src/server/persona-vault.ts'
import type { ProofReceipt } from '../src/server/proof-receipt.ts'
import { defaultTerminalOracleRegistry } from '../src/server/terminal-oracle-registry.ts'
import {
  hydrateV8OracleInput,
  inferV8OracleFamilyDetailed,
  type HydratableTranscriptIndex,
} from '../src/server/v8-oracle-hydrate.ts'
import {
  VERIFY_NONCE_ENV,
  VERIFY_NONCE_HEADER,
  VERIFY_RPC_CONTEXT_ENV,
  VERIFY_RPC_HEADER,
  VERIFY_RPC_SOCKET_ENV,
  VERIFY_RPC_TOKEN_ENV,
  VerifyRpcServer,
} from '../src/server/verify-rpc.ts'
import { TranscriptStore, evaluateClaims } from '../src/server/verify-claims.ts'
import { parseCapabilityArg } from '../src/server/verify-support.ts'
import { VerifyContext } from '../worker/kovo_verify/kovo_verify.ts'

process.env.KOVO_ALLOW_LOCAL_LAB = '1'

const ORIGIN = 'https://api.example.test'
const SIGNING_KEY = 'v8-m2-r4-kernel-test-signing-key-0123456789abcdef'

function makeStep(partial: Partial<ImpactStep> & Pick<ImpactStep, 'id' | 'arm' | 'method' | 'status'>): ImpactStep {
  return {
    id: partial.id,
    arm: partial.arm,
    method: partial.method,
    status: partial.status,
    actor: partial.actor ?? { handle: 'member_a', role: 'member', tenant: 'org_a', auth: 'bearer', sameSite: null },
    ...(partial.route !== undefined ? { route: partial.route } : partial.pathAndQuery ? { route: partial.pathAndQuery.split('?')[0]! } : {}),
    ...(partial.pathAndQuery !== undefined ? { pathAndQuery: partial.pathAndQuery } : {}),
    ...(partial.json !== undefined ? { json: partial.json } : {}),
    ...(partial.body !== undefined ? { body: partial.body } : {}),
    ...(partial.requestJson !== undefined ? { requestJson: partial.requestJson } : {}),
    ...(partial.requestHeaders !== undefined ? { requestHeaders: partial.requestHeaders } : {}),
    ...(partial.responseHeaders !== undefined ? { responseHeaders: partial.responseHeaders } : {}),
    ...(partial.evidenceRole !== undefined ? { evidenceRole: partial.evidenceRole } : {}),
  }
}

function signedEntry(
  exchangeId: string,
  step: ImpactStep,
  extra: Partial<HostTranscriptEntry> = {},
): HostTranscriptEntry {
  const base: HostTranscriptEntry = {
    exchangeId,
    origin: extra.origin ?? ORIGIN,
    step,
    seq: extra.seq ?? 1,
    timestampMs: extra.timestampMs ?? 1_700_000_000_000,
    actorPersona: extra.actorPersona !== undefined ? extra.actorPersona : step.actor.handle,
    actorRoleLabel: extra.actorRoleLabel !== undefined ? extra.actorRoleLabel : 'member (org_a)',
    cleanSession: extra.cleanSession ?? true,
    ...extra,
  }
  return { ...base, hostSignature: signHostRecord(base, SIGNING_KEY) }
}

function makePersona(handle: string, roleLabel: string, secret: string, origin: string): ResolvedPersona {
  return {
    id: handle,
    handle,
    roleLabel,
    originAllowlist: [origin],
    authKind: 'bearer',
    headerName: 'Authorization',
    secret,
    canaryMarkers: [],
    session: { headerType: 'bearer', value: secret, adapterUsed: 'static' },
  }
}

function makeGrant(origin: string, personas: ResolvedPersona[] = []): Grant {
  return {
    canRead: o => { try { return new URL(o).origin === origin } catch { return o === origin } },
    audit: () => undefined,
    allowLocalLab: true,
    tier: 3,
    isStateChangeApproved: () => true,
    personas: new Map(personas.map(p => [p.handle, p])),
    secrets: [],
  }
}

function callVerifyRpc(rpc: VerifyRpcServer, op: string, args: Record<string, unknown>): Promise<{ ok: boolean; result?: Record<string, unknown>; error?: string }> {
  return new Promise((resolve, reject) => {
    const payload = JSON.stringify({ op, args })
    const req = httpRequest({
      socketPath: rpc.socketPath,
      path: '/rpc',
      method: 'POST',
      headers: {
        [VERIFY_RPC_HEADER]: rpc.token,
        [VERIFY_NONCE_HEADER]: rpc.nonce,
        'content-type': 'application/json',
        'content-length': Buffer.byteLength(payload),
      },
    }, res => {
      let data = ''
      res.on('data', chunk => { data += chunk })
      res.on('end', () => resolve(JSON.parse(data) as { ok: boolean; result?: Record<string, unknown>; error?: string }))
    })
    req.on('error', reject)
    req.end(payload)
  })
}

async function withSdkContext<T>(rpc: VerifyRpcServer, fn: (ctx: VerifyContext) => Promise<T>): Promise<T> {
  const saved = {
    sock: process.env[VERIFY_RPC_SOCKET_ENV],
    tok: process.env[VERIFY_RPC_TOKEN_ENV],
    nonce: process.env[VERIFY_NONCE_ENV],
    ctx: process.env[VERIFY_RPC_CONTEXT_ENV],
  }
  process.env[VERIFY_RPC_SOCKET_ENV] = rpc.socketPath
  process.env[VERIFY_RPC_TOKEN_ENV] = join(rpc.hostDir, 'token')
  process.env[VERIFY_RPC_CONTEXT_ENV] = join(rpc.hostDir, 'context.json')
  process.env[VERIFY_NONCE_ENV] = rpc.nonce
  try {
    return await fn(new VerifyContext())
  } finally {
    for (const [k, v] of [
      [VERIFY_RPC_SOCKET_ENV, saved.sock],
      [VERIFY_RPC_TOKEN_ENV, saved.tok],
      [VERIFY_NONCE_ENV, saved.nonce],
      [VERIFY_RPC_CONTEXT_ENV, saved.ctx],
    ] as const) {
      if (v === undefined) delete process.env[k]
      else process.env[k] = v
    }
  }
}

// ============================================================================
// 1. conserved_balance host timestamps & op: 'race'
// ============================================================================

test('Fix 1: VerifyRpcServer forwards startedAt/endedAt/seq/op and records op="race"; conserved_balance confirms across both HostFactLog paths and rejects non-race/un-timestamped/sequential bursts', async (t) => {
  const runId = 'run-r4-fix1-race'
  resetRunCustodyBudgets(runId)
  t.after(() => resetRunCustodyBudgets(runId))

  let balance = 100
  let inFlight = 0

  const target = createServer((req, res) => {
    const url = new URL(req.url ?? '/', 'http://127.0.0.1')
    const chunks: Buffer[] = []
    req.on('data', c => chunks.push(c as Buffer))
    req.on('end', () => {
      if (req.method === 'GET' && url.pathname === '/api/v1/ledger') {
        res.writeHead(200, { 'content-type': 'application/json' })
        res.end(JSON.stringify({ accountId: 'acct_01', balance }))
        return
      }
      if (req.method === 'POST' && url.pathname === '/api/v1/ledger/debit') {
        if (balance < 50 && inFlight === 0) {
          res.writeHead(409, { 'content-type': 'application/json' })
          res.end(JSON.stringify({ error: 'insufficient_balance' }))
          return
        }
        // Snapshot balance before async gap so concurrent burst under-debits (100 -> 50 for two 50-unit debits)
        const snap = balance
        inFlight += 1
        setTimeout(() => {
          balance = snap - 50
          inFlight -= 1
          res.writeHead(200, { 'content-type': 'application/json' })
          res.end(JSON.stringify({ ok: true, debited: 50, balance }))
        }, 25)
        return
      }
      res.writeHead(404)
      res.end('not found')
    })
  }).listen(0, '127.0.0.1')
  t.after(() => new Promise<void>(r => target.close(() => r())))
  await once(target, 'listening')
  const origin = `http://127.0.0.1:${(target.address() as AddressInfo).port}`

  const persona = makePersona('member_a', 'member (org_a)', 'token_member_a_r4_01', origin)
  const rpc = new VerifyRpcServer({
    broker: new RequestBroker(),
    grant: makeGrant(origin, [persona]),
    runId,
    assignmentId: 'a-r4-fix1',
    targetOrigins: [origin],
  })
  await rpc.start()
  t.after(() => rpc.close())

  const { baseId, burstIds, postId, serial1Id, serial2Id } = await withSdkContext(rpc, async (ctx) => {
    const base = await ctx.http_send('/api/v1/ledger', { as: 'member_a', method: 'GET', arm: 'setup' })
    assert.equal(base.status, 200)
    const burst = await ctx.race_burst([
      { path: '/api/v1/ledger/debit', method: 'POST', as: 'member_a', body: { amount: 50 } },
      { path: '/api/v1/ledger/debit', method: 'POST', as: 'member_a', body: { amount: 50 } },
    ])
    assert.equal(burst.results.length, 2)
    const post = await ctx.http_send('/api/v1/ledger', { as: 'member_a', method: 'GET', arm: 'control' })
    assert.equal(post.status, 200)
    // Serial control: first serial debit succeeds (50 -> 0), second serial debit returns 409
    const serial1 = await ctx.http_send('/api/v1/ledger/debit', { as: 'member_a', method: 'POST', arm: 'control', body: { amount: 50 } })
    assert.equal(serial1.status, 200)
    const serial2 = await ctx.http_send('/api/v1/ledger/debit', { as: 'member_a', method: 'POST', arm: 'control', body: { amount: 50 } })
    assert.equal(serial2.status, 409)
    return {
      baseId: base.exchangeId,
      burstIds: burst.results.map(r => r.exchangeId),
      postId: post.exchangeId,
      serial1Id: serial1.exchangeId,
      serial2Id: serial2.exchangeId,
    }
  })

  // 1a. TranscriptStore recorded op='race' and signed raceTransport for every burst exchange
  const burstRecords = burstIds.map(id => rpc.transcript.get(id)!)
  assert.equal(burstRecords.length, 2)
  for (const rec of burstRecords) {
    assert.equal(rec.op, 'race', `handleRace must record op='race', got '${rec.op}'`)
    assert.equal(rec.raceTransport, 'http1-fallback')
  }

  // 1b. buildHostSignedTranscript forwards startedAt, endedAt, seq, op, and signed raceTransport
  const signed = rpc.buildHostSignedTranscript()
  const byId = new Map((signed.entries ?? []).map(e => [e.exchangeId, e]))
  for (const id of [baseId, ...burstIds, postId, serial1Id, serial2Id]) {
    const e = byId.get(id)!
    assert.equal(typeof e.seq, 'number')
    assert.equal(typeof e.op, 'string')
    assert.equal(typeof e.startedAt, 'number')
    assert.equal(typeof e.endedAt, 'number')
    assert.ok(e.endedAt! >= e.startedAt!, `endedAt must be >= startedAt on ${id}`)
  }
  for (const id of burstIds) {
    assert.equal(byId.get(id)!.op, 'race')
    assert.equal(byId.get(id)!.raceTransport, 'http1-fallback')
    assert.ok(byId.get(id)!.raceBatchId?.startsWith('race_'))
  }

  // 1c. conserved_balance confirms cleanly via BOTH fromTranscriptStore AND fromTranscript(buildHostSignedTranscript()) AND verifyComposite
  const receipt: ProofReceipt = {
    vulnClass: 'race_double_spend',
    target: { origin, method: 'POST', pathAndQuery: '/api/v1/ledger/debit' },
    exchangeIds: [baseId, ...burstIds, postId, serial1Id, serial2Id],
    oobEventIds: [],
    browserTraceIds: [],
    claimedDelta: 'Two concurrent 50-unit debits succeeded while balance only decreased by 50; serial retry returned 409.',
  }

  const fromStoreLog = HostFactLog.fromTranscriptStore(rpc.transcript, { hostTranscript: signed })
  const resStore = defaultTerminalOracleRegistry.evaluate(fromStoreLog, { kind: 'single_hop', receipt })
  assert.equal(resStore.confirmed, true, `fromTranscriptStore must confirm conserved_balance, got: ${resStore.reason}`)

  const fromSignedLog = HostFactLog.fromTranscript(signed)
  const resSigned = defaultTerminalOracleRegistry.evaluate(fromSignedLog, { kind: 'single_hop', receipt })
  assert.equal(resSigned.confirmed, true, `fromTranscript(buildHostSignedTranscript()) must confirm conserved_balance, got: ${resSigned.reason}`)

  const compRes = rpc.verifyComposite(singleReceiptToComposite(receipt))
  assert.equal(compRes.confirmed, true, `verifyComposite(conserved_balance) must confirm, got: ${compRes.reason}`)

  // 1d. Negative soundness checks: non-race op, missing timestamps, and strictly sequential windows MUST STILL REJECT
  const nonRaceTranscript: HostSignedTranscript = {
    ...signed,
    entries: (signed.entries ?? []).map(e => burstIds.includes(e.exchangeId) ? { ...e, op: 'http' } : e),
  }
  const nonRaceRes = defaultTerminalOracleRegistry.evaluate(HostFactLog.fromTranscript(nonRaceTranscript), { kind: 'single_hop', receipt })
  assert.equal(nonRaceRes.confirmed, false, 'non-race op burst must reject')
  assert.match(nonRaceRes.reason, /host race runner/i)

  const noTsTranscript: HostSignedTranscript = {
    ...signed,
    entries: (signed.entries ?? []).map(e => {
      if (!burstIds.includes(e.exchangeId)) return e
      const { startedAt: _s, endedAt: _e, ...rest } = e
      return rest
    }),
  }
  const noTsRes = defaultTerminalOracleRegistry.evaluate(HostFactLog.fromTranscript(noTsTranscript), { kind: 'single_hop', receipt })
  assert.equal(noTsRes.confirmed, false, 'missing host timestamps must fail closed')
  assert.match(noTsRes.reason, /host timestamps/i)

  const seqTranscript: HostSignedTranscript = {
    ...signed,
    entries: (signed.entries ?? []).map(e => {
      if (e.exchangeId === burstIds[0]) return { ...e, startedAt: 2000, endedAt: 2010, durationMs: 10 }
      if (e.exchangeId === burstIds[1]) return { ...e, startedAt: 2500, endedAt: 2510, durationMs: 10 }
      if (e.exchangeId === baseId) return { ...e, startedAt: 1000, endedAt: 1005, durationMs: 5 }
      if (e.exchangeId === postId) return { ...e, startedAt: 3000, endedAt: 3005, durationMs: 5 }
      return e
    }),
  }
  const seqRes = defaultTerminalOracleRegistry.evaluate(HostFactLog.fromTranscript(seqTranscript), { kind: 'single_hop', receipt })
  assert.equal(seqRes.confirmed, false, 'strictly sequential burst windows must reject')
  assert.match(seqRes.reason, /did not overlap/i)
})

test('Fix 1b (R3-05 Must-Fix 1): evaluateClaims validates signed raceTransport for h2-single-packet and includes op="race" in transcriptStatusSteps & citedRecords', () => {
  const store = new TranscriptStore(Buffer.from('r4-race-transport-secret'))
  const mkRace = (transport: 'h2-single-packet' | 'http1-fallback' | undefined, body: string, path = '/api/redeem') => store.record({
    op: 'race',
    ...(transport ? { raceTransport: transport } : {}),
    startedAt: 10_000,
    durationMs: 12,
    request: { origin: ORIGIN, method: 'POST', pathAndQuery: path, headers: {}, bodyBytes: 2, bodySha256: sha256Hex('{}'), nonce: 'n1', sessionRole: 'probe', personaHandle: 'member_a' },
    response: { status: 200, headers: { 'content-type': 'application/json' }, bodyBytes: body.length, bodySha256: sha256Hex(body), mediaType: 'application/json' },
    body,
  })
  const h2a = mkRace('h2-single-packet', '{"redeemed":1}')
  const h2b = mkRace('h2-single-packet', '{"redeemed":2}')
  const h1a = mkRace('http1-fallback', '{"redeemed":1}')
  const h1b = mkRace('http1-fallback', '{"redeemed":2}')
  const noTr = mkRace(undefined, '{"redeemed":3}')

  // h2-single-packet passes ONLY when all race records have signed raceTransport='h2-single-packet'
  assert.equal(evaluateClaims(store, [{ kind: 'race', exchangeIds: [h2a.exchangeId, h2b.exchangeId], mode: 'h2-single-packet' }]).passed, true)
  assert.equal(evaluateClaims(store, [{ kind: 'race', exchangeIds: [h1a.exchangeId, h1b.exchangeId], mode: 'h2-single-packet' }]).passed, false)
  assert.equal(evaluateClaims(store, [{ kind: 'race', exchangeIds: [h2a.exchangeId, h1b.exchangeId], mode: 'h2-single-packet' }]).passed, false)
  assert.equal(evaluateClaims(store, [{ kind: 'race', exchangeIds: [h2a.exchangeId, noTr.exchangeId], mode: 'h2-single-packet' }]).passed, false)
  // http1-fallback still passes when mode is 'http1-fallback'
  assert.equal(evaluateClaims(store, [{ kind: 'race', exchangeIds: [h1a.exchangeId, h1b.exchangeId], mode: 'http1-fallback' }]).passed, true)

  // op='race' exchanges participate in citedRecords (intermediate-stub gate catches a queued-job race record)
  const stubStore = new TranscriptStore(Buffer.from('r4-race-stub-secret'))
  const stubBody = '{"jobId":"job_9911","status":"queued"}'
  const stubRace = stubStore.record({
    op: 'race', raceTransport: 'h2-single-packet', startedAt: 20_000, durationMs: 10,
    request: { origin: ORIGIN, method: 'POST', pathAndQuery: '/api/jobs/export', headers: {}, bodyBytes: 2, bodySha256: sha256Hex('{}'), nonce: 'n2', sessionRole: 'probe', personaHandle: 'member_a' },
    response: { status: 202, headers: { 'content-type': 'application/json' }, bodyBytes: stubBody.length, bodySha256: sha256Hex(stubBody), mediaType: 'application/json' },
    body: stubBody,
  })
  const stubEval = evaluateClaims(stubStore, [{ kind: 'body_contains', exchangeId: stubRace.exchangeId, text: 'job_9911' }])
  assert.equal(stubEval.passed, false, 'op="race" queued-job stub must be caught by citedRecords intermediate-stub gate')
  assert.ok(stubEval.failures.some(f => /terminal_impact_unproven/i.test(f)))

  // op='race' exchanges participate in transcriptStatusSteps (status-only divergence gate sees race probe vs control)
  const divStore = new TranscriptStore(Buffer.from('r4-race-div-secret'))
  const ctrlRec = divStore.record({
    op: 'http', startedAt: 30_000, durationMs: 10,
    request: { origin: ORIGIN, method: 'POST', pathAndQuery: '/api/items', headers: {}, bodyBytes: 2, bodySha256: sha256Hex('{}'), nonce: 'n3', sessionRole: 'control', personaHandle: 'member_a' },
    response: { status: 200, headers: { 'content-type': 'application/json' }, bodyBytes: 11, bodySha256: sha256Hex('{"ok":true}'), mediaType: 'application/json' },
    body: '{"ok":true}',
  })
  const errRace = divStore.record({
    op: 'race', raceTransport: 'http1-fallback', startedAt: 30_050, durationMs: 10,
    request: { origin: ORIGIN, method: 'POST', pathAndQuery: '/api/items', headers: {}, bodyBytes: 2, bodySha256: sha256Hex('{}'), nonce: 'n4', sessionRole: 'probe', personaHandle: 'member_a' },
    response: { status: 500, headers: { 'content-type': 'application/json' }, bodyBytes: 17, bodySha256: sha256Hex('{"error":"fault"}'), mediaType: 'application/json' },
    body: '{"error":"fault"}',
  })
  const divEval = evaluateClaims(divStore, [
    { kind: 'status', exchangeId: ctrlRec.exchangeId, expected: 200 },
    { kind: 'status', exchangeId: errRace.exchangeId, expected: 500 },
  ])
  assert.equal(divEval.passed, false, 'status-only divergence against op="race" must be seen by transcriptStatusSteps')
  assert.ok(divEval.failures.some(f => /status-only divergence/i.test(f)))
})

// ============================================================================
// 2. parseCapabilityArg canonical handle object aliases & custody enforcement
// ============================================================================

test('Fix 2: parseCapabilityArg accepts all canonical handle object aliases, rejects malformed/conflicting handles, and VerifyRpcServer enforces host capability registry', async (t) => {
  const cap = 'cap:hop_1:session_tok_r4'
  assert.deepEqual(parseCapabilityArg({ capability: cap }), { handle: cap })

  const aliases = ['handle', 'derivedHandle', 'cap_id', 'capabilityHandle', 'capability', 'sealedHandle', 'capId', 'capabilityId'] as const
  for (const key of aliases) {
    const parsed = parseCapabilityArg({
      capability: { [key]: `  ${cap}  `, target: 'bearer', headerName: 'X-Auth', cookieName: 'sid', queryParam: 'tok' },
    })
    assert.deepEqual(parsed, { handle: cap, target: 'bearer', headerName: 'X-Auth', cookieName: 'sid', queryParam: 'tok' }, `alias "${key}" should parse cleanly`)
  }
  // Agreeing duplicate aliases succeed
  assert.deepEqual(parseCapabilityArg({ capability: { handle: cap, capabilityHandle: cap } }), { handle: cap })

  // Negative cases: empty, whitespace, non-string, missing key, conflicting aliases, non-cap format
  for (const bad of [
    {},
    { target: 'bearer' },
    { capabilityHandle: '' },
    { sealedHandle: '   ' },
    { capId: 12345 },
    { capabilityId: ['cap:hop_1:a'] },
    { handle: 'cap:hop_1:a', capabilityHandle: 'cap:hop_1:b' },
    { capabilityHandle: 'raw_unsealed_value' },
  ]) {
    assert.throws(() => parseCapabilityArg({ capability: bad }), /capability must be a handle string|Invalid derived capability handle/i)
  }

  // Live VerifyRpcServer custody check: sealed capability works via alias object; fabricated handle fails closed
  const runId = 'run-r4-fix2-cap'
  resetRunCustodyBudgets(runId)
  t.after(() => resetRunCustodyBudgets(runId))

  const secretVal = 'tok_live_custody_check_99112233'
  const target = createServer((req, res) => {
    const url = new URL(req.url ?? '/', 'http://127.0.0.1')
    if (url.pathname === '/api/v1/mint') {
      res.writeHead(200, { 'content-type': 'application/json' })
      res.end(JSON.stringify({ accessToken: secretVal }))
      return
    }
    if (url.pathname === '/api/v1/whoami') {
      const ok = req.headers.authorization === `Bearer ${secretVal}`
      res.writeHead(ok ? 200 : 401, { 'content-type': 'application/json' })
      res.end(JSON.stringify({ ok }))
      return
    }
    res.writeHead(404)
    res.end('not found')
  }).listen(0, '127.0.0.1')
  t.after(() => new Promise<void>(r => target.close(() => r())))
  await once(target, 'listening')
  const origin = `http://127.0.0.1:${(target.address() as AddressInfo).port}`

  const rpc = new VerifyRpcServer({
    broker: new RequestBroker(),
    grant: makeGrant(origin),
    runId,
    assignmentId: 'a-r4-fix2',
    targetOrigins: [origin],
  })
  await rpc.start()
  t.after(() => rpc.close())

  await withSdkContext(rpc, async (ctx) => {
    const minted = await ctx.http_send('/api/v1/mint', { method: 'POST' })
    const sealed = await ctx.seal_capability({ exchangeId: minted.exchangeId, slot: 'tok', jsonPath: '$.accessToken' })
    const viaCapHandle = await callVerifyRpc(rpc, 'http', {
      origin, path: '/api/v1/whoami', method: 'GET',
      capability: { capabilityHandle: sealed.handle, target: 'bearer' },
    })
    assert.equal(viaCapHandle.ok, true, `capabilityHandle alias failed: ${viaCapHandle.error}`)
    assert.equal(viaCapHandle.result?.status, 200)

    const viaSealedHandle = await callVerifyRpc(rpc, 'http', {
      origin, path: '/api/v1/whoami', method: 'GET',
      capability: { sealedHandle: sealed.handle, target: 'bearer' },
    })
    assert.equal(viaSealedHandle.ok, true, `sealedHandle alias failed: ${viaSealedHandle.error}`)
    assert.equal(viaSealedHandle.result?.status, 200)

    const fabricated = await callVerifyRpc(rpc, 'http', {
      origin, path: '/api/v1/whoami', method: 'GET',
      capability: { capabilityHandle: 'cap:hop_1:fabricated_unknown', target: 'bearer' },
    })
    assert.equal(fabricated.ok, false, 'unsealed fabricated handle must fail closed against host registry')
    assert.match(fabricated.error ?? '', /Unknown|sealed capability|not found|not issued/i)
  })
})

// ============================================================================
// 3. parser_cache_differential mode normalization & full PARSER_CACHE_INF_KEYS
// ============================================================================

test('Fix 3: parser_cache_differential normalizes differentialKind & cache-bleed mode aliases, infers all PARSER_CACHE_INF_KEYS, and fails closed on garbage mode or conflicting buckets', () => {
  const emptyIdx: HydratableTranscriptIndex = { entriesById: new Map() }

  // 3a. All 5 differentialKind values in raw.mode normalize to parser_differential + populate differentialKind
  for (const dk of ['path_normalization', 'duplicate_json_key', 'header_normalization', 'hop_by_hop_smuggling', 'content_type_confusion'] as const) {
    assert.deepEqual(inferV8OracleFamilyDetailed({ mode: dk }), { kind: 'matched', family: 'parser_cache_differential' })
    const h = hydrateV8OracleInput('parser_cache_differential', { mode: dk }, emptyIdx, 'sig')
    assert.equal(h.mode, 'parser_differential', `mode="${dk}" should normalize to parser_differential`)
    assert.equal(h.differentialKind, dk, `mode="${dk}" should populate differentialKind when omitted`)
  }
  // Matching explicit differentialKind is accepted; conflicting or garbage differentialKind fails closed
  const matchDk = hydrateV8OracleInput('parser_cache_differential', { mode: 'path_normalization', differentialKind: 'path_normalization' }, emptyIdx, 'sig')
  assert.equal(matchDk.mode, 'parser_differential')
  assert.equal(matchDk.differentialKind, 'path_normalization')
  const mismatchDk = hydrateV8OracleInput('parser_cache_differential', { mode: 'path_normalization', differentialKind: 'header_normalization' }, emptyIdx, 'sig')
  assert.equal(mismatchDk.mode, undefined, 'conflicting mode alias + explicit differentialKind must fail closed')
  assert.equal(mismatchDk.differentialKind, undefined)
  const badDk = hydrateV8OracleInput('parser_cache_differential', { mode: 'path_normalization', differentialKind: 'bogus_kind' }, emptyIdx, 'sig')
  assert.equal(badDk.mode, undefined)
  assert.equal(badDk.differentialKind, undefined)

  // 3b. All 4 cache-bleed mode aliases normalize to cache_primed
  for (const alias of ['cache_poisoning', 'cache_deception', 'cache_bleed', 'cache_priming'] as const) {
    assert.deepEqual(inferV8OracleFamilyDetailed({ mode: alias }), { kind: 'matched', family: 'parser_cache_differential' })
    const h = hydrateV8OracleInput('parser_cache_differential', { mode: alias }, emptyIdx, 'sig')
    assert.equal(h.mode, 'cache_primed', `mode="${alias}" should normalize to cache_primed`)
  }

  // 3c. Key-based inference across ALL exclusive PARSER_CACHE_INF_KEYS; cleanControl-only fails closed
  assert.equal(hydrateV8OracleInput('parser_cache_differential', { cleanControl: 'c1' }, emptyIdx, 'sig').mode, undefined, 'cleanControl-only input must fail closed')
  for (const k of ['canonicalValue', 'variantValue', 'canonicalRequest', 'variantRequest', 'smuggledRequest', 'parserDiff', 'differentialProbe', 'differentialKind', 'differentialFeature', 'impactKind']) {
    const h = hydrateV8OracleInput('parser_cache_differential', { cleanControl: 'c1', [k]: 'val_1' }, emptyIdx, 'sig')
    assert.equal(h.mode, 'parser_differential', `key "${k}" should infer parser_differential`)
  }
  for (const k of ['cachePrimeRequest', 'victimReadback', 'cacheBleed', 'victimArtifactDigest', 'cacheHitObserved', 'cleanControlContainsVictimData', 'victimOrPrimeRequest', 'attackerProbe', 'cacheKey']) {
    // Include cleanControl alongside cache_primed keys to prove shared cleanControl never causes false conflict!
    const h = hydrateV8OracleInput('parser_cache_differential', { cleanControl: 'c1', [k]: 'val_1' }, emptyIdx, 'sig')
    assert.equal(h.mode, 'cache_primed', `key "${k}" (+ cleanControl) should infer cache_primed`)
  }

  // 3d. Negative fail-closed tests: garbage mode and cross-bucket conflicts (with or without explicit mode)
  for (const badMode of ['garbage_mode', '', 42, null]) {
    const h = hydrateV8OracleInput('parser_cache_differential', { mode: badMode, differentialProbe: 'p1', cleanControl: 'c1' }, emptyIdx, 'sig')
    assert.equal(h.mode, undefined, `invalid mode=${String(badMode)} must fail closed`)
  }
  for (const conflict of [
    { differentialProbe: 'p1', cacheKey: 'ck1' },
    { mode: 'parser_differential', differentialProbe: 'p1', cacheKey: 'ck1' },
    { mode: 'cache_primed', canonicalRequest: 'c1', cacheBleed: true },
    { canonicalRequest: 'c1', cacheBleed: true },
    { parserDiff: 'x', victimArtifactDigest: 'abc' },
    { smuggledRequest: 's1', cacheHitObserved: true },
    { variantValue: 'v', cleanControlContainsVictimData: false },
  ]) {
    const h = hydrateV8OracleInput('parser_cache_differential', conflict, emptyIdx, 'sig')
    assert.equal(h.mode, undefined, `conflicting parser+cache keys must fail closed: ${JSON.stringify(conflict)}`)
  }

  // 3e. End-to-end verifyCompositeReceipt confirmation with mode: 'path_normalization' (differentialKind omitted) + rejection with garbage mode
  const cleanCtrl = signedEntry('pc-ctrl', makeStep({
    id: 'pc-ctrl', arm: 'control', method: 'GET', status: 403, pathAndQuery: '/api/v1/admin/ledger',
    json: { error: 'forbidden' },
  }), { seq: 1, timestampMs: 1000 })
  const diffProbe = signedEntry('pc-probe', makeStep({
    id: 'pc-probe', arm: 'probe', method: 'GET', status: 200, pathAndQuery: '/api/v1/public/../admin/ledger',
    json: { tenantId: 'org_b', balance: 5000, records: [{ id: 'r1' }] },
  }), { seq: 2, timestampMs: 1100 })

  const makeParserReceipt = (oracleInput: Record<string, unknown>): CompositeProofReceipt => ({
    chainId: 'r4-parser-mode-norm',
    terminalVulnClass: 'parser_cache_differential',
    hops: [{
      hopId: 'hop_1', surface: 'http',
      target: { origin: ORIGIN, method: 'GET', pathAndQuery: '/api/v1/public/../admin/ledger' },
      exchangeIds: ['pc-probe'], oobEventIds: [], browserTraceIds: [],
      claimedDelta: 'Path normalization bypassed route authorization gate.',
      producedCapabilities: [], consumedCapabilities: [],
    }],
    causalEdges: [],
    terminalImpact: {
      terminalHopId: 'hop_1', terminalExchangeId: 'pc-probe',
      summary: 'Normalized path variant bypassed control gate and exposed foreign ledger data.',
      claimedImpact: 'Normalized path variant bypassed control gate and exposed foreign ledger data.',
      preChainControlExchangeIds: ['pc-ctrl'], postChainReadbackExchangeIds: [],
      oracleFamily: 'parser_cache_differential',
      oracleInput,
    },
    replayMode: 'fresh_clean_replay',
  })

  const okNorm = verifyCompositeReceipt(
    makeParserReceipt({
      mode: 'path_normalization',
      differentialFeature: 'dot_segment_proxy_vs_app',
      impactKind: 'read',
      cleanControl: 'pc-ctrl',
      differentialProbe: 'pc-probe',
    }),
    { entries: [cleanCtrl, diffProbe] },
    { signingKey: SIGNING_KEY, attackerPersonas: ['member_a'] },
  )
  assert.equal(okNorm.confirmed, true, `mode='path_normalization' should confirm cleanly, got: ${okNorm.reason}`)

  const badModeRes = verifyCompositeReceipt(
    makeParserReceipt({
      mode: 'not_a_real_mode',
      differentialFeature: 'dot_segment_proxy_vs_app',
      impactKind: 'read',
      cleanControl: 'pc-ctrl',
      differentialProbe: 'pc-probe',
    }),
    { entries: [cleanCtrl, diffProbe] },
    { signingKey: SIGNING_KEY, attackerPersonas: ['member_a'] },
  )
  assert.equal(badModeRes.confirmed, false)
  assert.match(badModeRes.reason, /unknown_parser_cache_mode/)
})

// ============================================================================
// 4. hasVerifiedTermEdge autodag edges + actionable control diagnostics
// ============================================================================

test('Fix 4a/4b: pre-supplemental autodag state_transition_binding and async_pivot_binding satisfy hasVerifiedTermEdge while supplemental edges remain strictly excluded', () => {
  const dualActor = { handle: 'dual_user', role: 'member' as const, tenant: 'org_a', auth: 'bearer' as const, sameSite: null }
  const dualRoleLabel = 'admin (org_a); member (org_b)'

  // 4a. AutoDAG pre-supplemental state_transition_binding (shared entityId + clean ablation on mutating terminal hop)
  const stCtrl = signedEntry('st-ctrl', makeStep({
    id: 'st-ctrl', arm: 'control', method: 'POST', status: 403, pathAndQuery: '/api/v1/reports/rep_7788aabb/approve',
    actor: dualActor, json: { error: 'forbidden' },
  }), { seq: 1, timestampMs: 1000, actorRoleLabel: dualRoleLabel, entityId: 'rep_7788aabb' })
  const stMut = signedEntry('st-mut', makeStep({
    id: 'st-mut', arm: 'probe', method: 'PATCH', status: 200, pathAndQuery: '/api/v1/reports/rep_7788aabb/share',
    actor: dualActor, requestJson: { reportId: 'rep_7788aabb', target: 'org_a' }, json: { ok: true, reportId: 'rep_7788aabb' },
  }), { seq: 2, timestampMs: 1100, actorRoleLabel: dualRoleLabel, entityId: 'rep_7788aabb' })
  const stApprove = signedEntry('st-approve', makeStep({
    id: 'st-approve', arm: 'probe', method: 'POST', status: 200, pathAndQuery: '/api/v1/reports/rep_7788aabb/approve',
    actor: dualActor, json: { reportId: 'rep_7788aabb', tenantId: 'org_b', approved: true, balance: 9900 },
  }), { seq: 3, timestampMs: 1200, actorRoleLabel: dualRoleLabel, entityId: 'rep_7788aabb' })
  const stRb = signedEntry('st-rb', makeStep({
    id: 'st-rb', arm: 'control', method: 'GET', status: 200, pathAndQuery: '/api/v1/reports/rep_7788aabb',
    actor: dualActor, json: { reportId: 'rep_7788aabb', tenantId: 'org_b', approved: true, balance: 9900 },
  }), { seq: 4, timestampMs: 1300, actorRoleLabel: dualRoleLabel, entityId: 'rep_7788aabb', evidenceRole: 'post_chain_readback' })

  const stReceipt: CompositeProofReceipt = {
    chainId: 'r4-autodag-st',
    terminalVulnClass: 'dual_tenant_abac',
    hops: [
      { hopId: 'hop_1', surface: 'http', target: { origin: ORIGIN, method: 'PATCH', pathAndQuery: '/api/v1/reports/rep_7788aabb/share' }, exchangeIds: ['st-mut'], oobEventIds: [], browserTraceIds: [], claimedDelta: 'Modified report ACL state', producedCapabilities: [], consumedCapabilities: [], entityId: 'rep_7788aabb' },
      { hopId: 'hop_2', surface: 'http', target: { origin: ORIGIN, method: 'POST', pathAndQuery: '/api/v1/reports/rep_7788aabb/approve' }, exchangeIds: ['st-approve'], oobEventIds: [], browserTraceIds: [], claimedDelta: 'Approved foreign tenant report after state mutation', producedCapabilities: [], consumedCapabilities: [], entityId: 'rep_7788aabb' },
    ],
    causalEdges: [],
    terminalImpact: {
      terminalHopId: 'hop_2', terminalExchangeId: 'st-approve',
      summary: 'Cross-tenant state mutation unlocked unauthorized foreign report approval.',
      claimedImpact: 'Cross-tenant state mutation unlocked unauthorized foreign report approval.',
      preChainControlExchangeIds: ['st-ctrl'], postChainReadbackExchangeIds: ['st-rb'],
      oracleInput: { note: 'free_form_dag_check' },
    },
    replayMode: 'fresh_clean_replay',
  }

  // Confirm augmentCompositeReceiptWithAutoDag produces the pre-supplemental state_transition_binding
  const stTranscript: HostSignedTranscript = { entries: [stCtrl, stMut, stApprove, stRb] }
  const autoSt = augmentCompositeReceiptWithAutoDag(stReceipt, HostFactLog.fromTranscript(stTranscript))
  assert.ok(autoSt.inferredEdges.some(e => e.kind === 'state_transition_binding'), 'autodag should infer state_transition_binding')

  const stRes = verifyCompositeReceipt(stReceipt, stTranscript, {
    signingKey: SIGNING_KEY,
    attackerPersonas: ['dual_user'],
    personaRoleLabels: { dual_user: dualRoleLabel },
  })
  assert.equal(stRes.confirmed, true, `autodag state_transition_binding must satisfy hasVerifiedTermEdge, got: ${stRes.reason}`)

  // 4b. AutoDAG pre-supplemental async_pivot_binding (poll_convergence)
  const corrId = 'corr_r4_async_9988aabb'
  const apCtrl = signedEntry('ap-ctrl', makeStep({
    id: 'ap-ctrl', arm: 'control', method: 'GET', status: 403, pathAndQuery: `/api/v1/exports/${corrId}`,
    actor: dualActor, json: { error: 'forbidden' },
  }), { seq: 1, timestampMs: 1000, actorRoleLabel: dualRoleLabel })
  const apTrig = signedEntry('ap-trig', makeStep({
    id: 'ap-trig', arm: 'probe', method: 'POST', status: 202, pathAndQuery: '/api/v1/exports/start',
    actor: dualActor, json: { jobId: corrId, status: 'queued' },
  }), { seq: 2, timestampMs: 1100, actorRoleLabel: dualRoleLabel, correlationIds: [corrId] })
  const apRead = signedEntry('ap-read', makeStep({
    id: 'ap-read', arm: 'probe', method: 'GET', status: 200, pathAndQuery: `/api/v1/exports/${corrId}`,
    actor: dualActor, json: { jobId: corrId, tenantId: 'org_b', ledgerTotal: 4200 },
  }), { seq: 3, timestampMs: 1300, actorRoleLabel: dualRoleLabel, correlationIds: [corrId] })
  const pollBase: HostAsyncPollRecord = {
    id: 'poll-r4-1', triggerExchangeId: 'ap-trig', tTriggerMs: 1100, tObservedMs: 1250,
    converged: true, correlationIds: [corrId],
    observedValueDigests: [sha256Hex(JSON.stringify(apRead.step.json))],
  }
  const pollSigned: HostAsyncPollRecord = { ...pollBase, hostSignature: signHostRecord(pollBase, SIGNING_KEY) }

  const apReceipt: CompositeProofReceipt = {
    chainId: 'r4-autodag-async',
    terminalVulnClass: 'dual_tenant_abac',
    hops: [
      { hopId: 'hop_1', surface: 'async_job', target: { origin: ORIGIN, method: 'POST', pathAndQuery: '/api/v1/exports/start' }, exchangeIds: ['ap-trig'], oobEventIds: [], browserTraceIds: [], claimedDelta: 'Triggered async export job', producedCapabilities: [], consumedCapabilities: [] },
      { hopId: 'hop_2', surface: 'http', target: { origin: ORIGIN, method: 'GET', pathAndQuery: `/api/v1/exports/${corrId}` }, exchangeIds: ['ap-read'], oobEventIds: [], browserTraceIds: [], claimedDelta: 'Read converged foreign tenant export', producedCapabilities: [], consumedCapabilities: [] },
    ],
    causalEdges: [],
    terminalImpact: {
      terminalHopId: 'hop_2', terminalExchangeId: 'ap-read',
      summary: 'Converged async export exposed foreign tenant ledger records.',
      claimedImpact: 'Converged async export exposed foreign tenant ledger records.',
      preChainControlExchangeIds: ['ap-ctrl'], postChainReadbackExchangeIds: [],
      oracleInput: { note: 'free_form_dag_check' },
    },
    replayMode: 'fresh_clean_replay',
  }
  const apTranscript: HostSignedTranscript = { entries: [apCtrl, apTrig, apRead], asyncPollRecords: [pollSigned] }
  const autoAp = augmentCompositeReceiptWithAutoDag(apReceipt, HostFactLog.fromTranscript(apTranscript))
  assert.ok(autoAp.inferredEdges.some(e => e.kind === 'async_pivot_binding'), 'autodag should infer async_pivot_binding')

  const apRes = verifyCompositeReceipt(apReceipt, apTranscript, {
    signingKey: SIGNING_KEY,
    attackerPersonas: ['dual_user'],
    personaRoleLabels: { dual_user: dualRoleLabel },
  })
  assert.equal(apRes.confirmed, true, `autodag async_pivot_binding must satisfy hasVerifiedTermEdge, got: ${apRes.reason}`)

  // 4c. Negative R3-05 security invariant: supplemental async_pivot_binding (oob_relay inferred ONLY by
  //     inferSupplementalHostCausalEdges at edgeIndex >= suppStart, NOT by autodag) MUST STILL NOT satisfy hasVerifiedTermEdge!
  const oobTok = 'oob_sup_tok_778899aabbcc'
  const supCtrl = signedEntry('sup-ctrl', makeStep({
    id: 'sup-ctrl', arm: 'control', method: 'GET', status: 403, pathAndQuery: '/api/v1/docs/export',
    actor: dualActor, json: { error: 'forbidden' },
  }), { seq: 1, timestampMs: 1000, actorRoleLabel: dualRoleLabel })
  const supH1 = signedEntry('sup-h1', makeStep({
    id: 'sup-h1', arm: 'probe', method: 'GET', status: 200, pathAndQuery: `/api/v1/docs/preview?cb=https://oob.test/${oobTok}`,
    actor: dualActor, json: { ok: true },
  }), { seq: 2, timestampMs: 1100, actorRoleLabel: dualRoleLabel, correlationIds: [oobTok] })
  const supH2 = signedEntry('sup-h2', makeStep({
    id: 'sup-h2', arm: 'probe', method: 'GET', status: 200, pathAndQuery: '/api/v1/docs/export',
    actor: dualActor, json: { tenantId: 'org_b', balance: 7500 },
  }), { seq: 3, timestampMs: 1250, actorRoleLabel: dualRoleLabel })
  const supOobBase: HostOobEvent = {
    id: 'oob-sup-1', token: oobTok, delivered: true, receivedAtMs: 1180, correlationIds: [oobTok],
  }
  const supOobSigned: HostOobEvent = { ...supOobBase, hostSignature: signHostRecord(supOobBase, SIGNING_KEY) }
  const supReceipt: CompositeProofReceipt = {
    chainId: 'r4-supp-excluded',
    terminalVulnClass: 'dual_tenant_abac',
    hops: [
      { hopId: 'hop_1', surface: 'http', target: { origin: ORIGIN, method: 'GET', pathAndQuery: `/api/v1/docs/preview?cb=https://oob.test/${oobTok}` }, exchangeIds: ['sup-h1'], oobEventIds: [], browserTraceIds: [], claimedDelta: 'Triggered OOB preview', producedCapabilities: [], consumedCapabilities: [] },
      { hopId: 'hop_2', surface: 'webhook', target: { origin: ORIGIN, method: 'GET', pathAndQuery: '/api/v1/docs/export' }, exchangeIds: ['sup-h2'], oobEventIds: ['oob-sup-1'], browserTraceIds: [], claimedDelta: 'Read foreign document export alongside OOB hit', producedCapabilities: [], consumedCapabilities: [] },
    ],
    causalEdges: [],
    terminalImpact: {
      terminalHopId: 'hop_2', terminalExchangeId: 'sup-h2',
      summary: 'Attempted multi-hop confirmation relying only on supplemental oob_relay edge.',
      claimedImpact: 'Attempted multi-hop confirmation relying only on supplemental oob_relay edge.',
      preChainControlExchangeIds: ['sup-ctrl'], postChainReadbackExchangeIds: [],
      oracleInput: { note: 'free_form_dag_check' },
    },
    replayMode: 'fresh_clean_replay',
  }
  const supTranscript: HostSignedTranscript = { entries: [supCtrl, supH1, supH2], oobEvents: [supOobSigned] }
  const autoSup = augmentCompositeReceiptWithAutoDag(supReceipt, HostFactLog.fromTranscript(supTranscript))
  assert.equal(autoSup.inferredEdges.length, 0, 'autodag must NOT infer supplemental oob_relay edge')
  const supRes = verifyCompositeReceipt(supReceipt, supTranscript, {
    signingKey: SIGNING_KEY,
    attackerPersonas: ['dual_user'],
    personaRoleLabels: { dual_user: dualRoleLabel },
  })
  assert.equal(supRes.confirmed, false, 'supplemental oob_relay async_pivot_binding (>= suppStart) must NOT satisfy hasVerifiedTermEdge')
  assert.match(supRes.reason, /missing_v8_oracle_input/i)

  // 4d. Negative R3-05 Must-Fix 2 security invariant: unrelated pad write hop + same-persona denied control
  //     synthesizes a host `logical_key_ablation` state_transition_binding (< suppStart), which MUST NOT satisfy hasVerifiedTermEdge!
  const padCtrl = signedEntry('pad-ctrl', makeStep({
    id: 'pad-ctrl', arm: 'control', method: 'GET', status: 403, pathAndQuery: '/api/v1/changelog/entries/cl_5521',
    actor: dualActor, json: { error: 'forbidden' },
  }), { seq: 1, timestampMs: 1000, actorRoleLabel: dualRoleLabel })
  const padWrite = signedEntry('pad-write', makeStep({
    id: 'pad-write', arm: 'probe', method: 'POST', status: 200, pathAndQuery: '/api/v1/preferences/notifications',
    actor: dualActor, requestJson: { digest: 'weekly' }, json: { saved: true },
  }), { seq: 2, timestampMs: 1100, actorRoleLabel: dualRoleLabel })
  const padRead = signedEntry('pad-read', makeStep({
    id: 'pad-read', arm: 'probe', method: 'GET', status: 200, pathAndQuery: '/api/v1/changelog/entries/cl_5521',
    actor: dualActor, json: { entryId: 'cl_5521', tenantId: 'org_b', balance: 500, notes: 'unrelated' },
  }), { seq: 3, timestampMs: 1200, actorRoleLabel: dualRoleLabel })
  const padReceipt: CompositeProofReceipt = {
    chainId: 'r4-logical-ablation-bypass-guard',
    terminalVulnClass: 'dual_tenant_abac',
    hops: [
      { hopId: 'hop_1', surface: 'http', target: { origin: ORIGIN, method: 'POST', pathAndQuery: '/api/v1/preferences/notifications' }, exchangeIds: ['pad-write'], oobEventIds: [], browserTraceIds: [], claimedDelta: 'Unrelated preference write', producedCapabilities: [], consumedCapabilities: [] },
      { hopId: 'hop_2', surface: 'http', target: { origin: ORIGIN, method: 'GET', pathAndQuery: '/api/v1/changelog/entries/cl_5521' }, exchangeIds: ['pad-read'], oobEventIds: [], browserTraceIds: [], claimedDelta: 'Read unrelated changelog entry', producedCapabilities: [], consumedCapabilities: [] },
    ],
    causalEdges: [],
    terminalImpact: {
      terminalHopId: 'hop_2', terminalExchangeId: 'pad-read',
      summary: 'Unrelated pad hop with logical_key_ablation must not confirm multiHopDualDag.',
      claimedImpact: 'Unrelated pad hop with logical_key_ablation must not confirm multiHopDualDag.',
      preChainControlExchangeIds: ['pad-ctrl'], postChainReadbackExchangeIds: [],
      oracleInput: { note: 'free_form_dag_check' },
    },
    replayMode: 'fresh_clean_replay',
  }
  const padTranscript: HostSignedTranscript = { entries: [padCtrl, padWrite, padRead] }
  const autoPad = augmentCompositeReceiptWithAutoDag(padReceipt, HostFactLog.fromTranscript(padTranscript))
  assert.ok(autoPad.inferredEdges.some(e => e.kind === 'state_transition_binding'), 'autodag synthesizes logical fallback state_transition_binding')
  const padRes = verifyCompositeReceipt(padReceipt, padTranscript, {
    signingKey: SIGNING_KEY,
    attackerPersonas: ['dual_user'],
    personaRoleLabels: { dual_user: dualRoleLabel },
  })
  assert.equal(padRes.confirmed, false, 'logical_key_ablation state_transition_binding must NOT satisfy hasVerifiedTermEdge')
  assert.ok(padRes.verifiedEdges.some(e => e.kind === 'state_transition_binding' && (e.evidence as { bindingMode?: string } | undefined)?.bindingMode === 'logical_key_ablation'))
  assert.match(padRes.reason, /missing_v8_oracle_input/i)
})

test('Fix 4c: missing_denied_control_on_terminal_route reports concise rejection reasons for matching-route candidate controls', () => {
  const cap = 'cap:hop_1:tok_diag_r4'
  const h1 = signedEntry('d-h1', makeStep({
    id: 'd-h1', arm: 'probe', method: 'POST', status: 200, pathAndQuery: '/api/v1/jobs',
    json: { jobId: 'job_r4_001' },
  }), { seq: 1, timestampMs: 1000, emittedCapabilities: [cap] })
  const h2 = signedEntry('d-h2', makeStep({
    id: 'd-h2', arm: 'probe', method: 'GET', status: 200, pathAndQuery: '/api/v1/exports/exp_r4_001?format=json',
    json: { tenantId: 'org_b', balance: 1200 },
  }), { seq: 3, timestampMs: 1200, consumedCapabilities: [cap] })

  const runDiag = (ctrl: HostTranscriptEntry, extraH1Ids: string[] = []) => {
    const receipt: CompositeProofReceipt = {
      chainId: `r4-diag-${ctrl.exchangeId}`,
      terminalVulnClass: 'dual_tenant_abac',
      hops: [
        { hopId: 'hop_1', surface: 'http', target: { origin: ORIGIN, method: 'POST', pathAndQuery: '/api/v1/jobs' }, exchangeIds: ['d-h1', ...extraH1Ids], oobEventIds: [], browserTraceIds: [], claimedDelta: 'Created job', producedCapabilities: [cap], consumedCapabilities: [] },
        { hopId: 'hop_2', surface: 'http', target: { origin: ORIGIN, method: 'GET', pathAndQuery: '/api/v1/exports/exp_r4_001?format=json' }, exchangeIds: ['d-h2'], oobEventIds: [], browserTraceIds: [], claimedDelta: 'Fetched export', producedCapabilities: [], consumedCapabilities: [cap] },
      ],
      causalEdges: [{ kind: 'value_binding', fromHopId: 'hop_1', toHopId: 'hop_2', capabilityHandle: cap }],
      terminalImpact: {
        terminalHopId: 'hop_2', terminalExchangeId: 'd-h2',
        summary: 'Diagnosing rejected matching-route control candidate.',
        claimedImpact: 'Diagnosing rejected matching-route control candidate.',
        preChainControlExchangeIds: [ctrl.exchangeId], postChainReadbackExchangeIds: [],
      },
      replayMode: 'fresh_clean_replay',
    }
    return verifyCompositeReceipt(receipt, { entries: [ctrl, h1, h2] }, { signingKey: SIGNING_KEY, attackerPersonas: ['member_a'] })
  }

  // 1. arm=probe (pass arm:'control')
  const probeArm = runDiag(signedEntry('c-arm', makeStep({
    id: 'c-arm', arm: 'probe', method: 'GET', status: 403, pathAndQuery: '/api/v1/exports/exp_r4_001?format=json',
    json: { error: 'forbidden' },
  }), { seq: 0, timestampMs: 900 }))
  assert.equal(probeArm.confirmed, false)
  assert.match(probeArm.reason, /missing_denied_control_on_terminal_route/)
  assert.match(probeArm.reason, /arm=probe \(pass arm:'control'\)/)

  // 2. status=200 (need 401/403/404)
  const status200 = runDiag(signedEntry('c-200', makeStep({
    id: 'c-200', arm: 'control', method: 'GET', status: 200, pathAndQuery: '/api/v1/exports/exp_r4_001?format=json',
    json: { ok: true },
  }), { seq: 0, timestampMs: 900 }))
  assert.equal(status200.confirmed, false)
  assert.match(status200.reason, /status=200 \(need 401\/403\/404\)/)

  // 3. query_mismatch
  const queryMis = runDiag(signedEntry('c-qry', makeStep({
    id: 'c-qry', arm: 'control', method: 'GET', status: 403, pathAndQuery: '/api/v1/exports/exp_r4_001?format=csv',
    json: { error: 'forbidden' },
  }), { seq: 0, timestampMs: 900 }))
  assert.equal(queryMis.confirmed, false)
  assert.match(queryMis.reason, /query_mismatch/)

  // 4. cred_identity_mismatch
  const credMis = runDiag(signedEntry('c-cred', makeStep({
    id: 'c-cred', arm: 'control', method: 'GET', status: 403, pathAndQuery: '/api/v1/exports/exp_r4_001?format=json',
    actor: { handle: 'other_member', role: 'member', tenant: 'org_c', auth: 'bearer', sameSite: null },
    json: { error: 'forbidden' },
  }), { seq: 0, timestampMs: 900, actorRoleLabel: 'member (org_c)' }))
  assert.equal(credMis.confirmed, false)
  assert.match(credMis.reason, /cred_identity_mismatch/)

  // 5. in_non_terminal_hop
  const nonTermHop = runDiag(signedEntry('c-hop', makeStep({
    id: 'c-hop', arm: 'control', method: 'GET', status: 403, pathAndQuery: '/api/v1/exports/exp_r4_001?format=json',
    json: { error: 'forbidden' },
  }), { seq: 0, timestampMs: 900 }), ['c-hop'])
  assert.equal(nonTermHop.confirmed, false)
  assert.match(nonTermHop.reason, /in_non_terminal_hop/)
})
