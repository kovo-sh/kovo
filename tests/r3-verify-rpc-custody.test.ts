// @kernel @fixes R3-C-3, R3-C-4, R3-H-2, R3-H-4, R3-H-5
/**
 * R3 Verification RPC Custody & Kernel Plane Regression Suite
 *
 * Covers:
 *  - R3-C-3: Raw kernel request plane (exact host-secret scrubbing only, zero key-name heuristics)
 *            so secret-named query/body echoes cannot bypass anti-reflection while real secrets
 *            stay scrubbed on kernel & worker planes.
 *  - R3-H-2: Blind custody across `async.awaitResult` (scrubbed predicates, zero membership oracle,
 *            safe-regex chokepoint, run-scoped call & attempt budgets), `prove.differential`
 *            (scrubbed structural_diff, no plaintext lowercased `stableDelta` fragments), and
 *            worker-visible-only `bodySha256` across `exchangeView` and `transcript.get`.
 *  - R3-H-4(a): No base-persona credential laundering when a capability supplies any auth credential
 *            (drops every base-persona auth header so admin credentials never ride along under a
 *            member capability label).
 *  - R3-H-5: Explicit host-derived `credentialPlacement` (`HostAuthPlacement`) stamped from host
 *            injection + wire provenance onto both `HostSignedTranscript` and `TranscriptStore`.
 *  - R3-C-4: Host-minted boolean pairs & strict stripped base-value parity in `prove.differential`.
 */
import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { once } from 'node:events'
import { createServer, request as httpRequest } from 'node:http'
import type { AddressInfo } from 'node:net'
import test from 'node:test'
import { RequestBroker } from '../src/server/broker.ts'
import type { Grant, WireCredentialProvenance } from '../src/server/broker.ts'
import { resetRunCustodyBudgets } from '../src/server/derived-custody.ts'
import { HostFactLog, deriveAmbientAuthFromHeaders } from '../src/server/host-fact-log.ts'
import { assessInjectionImpact, matchStrippedInjectionFingerprint } from '../src/server/oracle-invariants.ts'
import type { ResolvedPersona } from '../src/server/persona-vault.ts'
import {
  VERIFY_NONCE_HEADER,
  VERIFY_RPC_HEADER,
  VerifyRpcServer,
} from '../src/server/verify-rpc.ts'
import {
  buildHostAuthPlacement,
  mintHostBooleanPair,
  resetRunAsyncPollBudgets,
  stripBooleanPredicateSuffix,
  verifyBooleanArmBaseParity,
} from '../src/server/verify-support.ts'

process.env.KOVO_ALLOW_LOCAL_LAB = '1'

interface RpcResp {
  ok: boolean
  result?: unknown
  error?: string
}

function rpcCall(
  server: VerifyRpcServer,
  op: string,
  args: Record<string, unknown> = {},
): Promise<RpcResp> {
  return new Promise((resolve, reject) => {
    const body = JSON.stringify({ op, args })
    const req = httpRequest({
      socketPath: server.socketPath,
      path: '/rpc',
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        'content-length': Buffer.byteLength(body),
        [VERIFY_RPC_HEADER]: server.token,
        [VERIFY_NONCE_HEADER]: server.nonce,
      },
    }, (res) => {
      let data = ''
      res.setEncoding('utf8')
      res.on('data', chunk => { data += chunk })
      res.on('end', () => {
        try { resolve(JSON.parse(data) as RpcResp) } catch (err) { reject(err) }
      })
    })
    req.on('error', reject)
    req.end(body)
  })
}

function makePersona(
  handle: string,
  roleLabel: string,
  secret: string,
  origin: string,
  authKind: 'bearer' | 'cookie' | 'header' = 'bearer',
  headerName: string | null = null,
): ResolvedPersona {
  return {
    id: handle,
    handle,
    roleLabel,
    originAllowlist: [origin],
    authKind,
    headerName: headerName ?? (authKind === 'bearer' ? 'Authorization' : authKind === 'header' ? 'X-API-Key' : null),
    secret,
    canaryMarkers: [],
    session: { headerType: authKind, value: secret, adapterUsed: 'static' },
  }
}

function makeGrant(
  origin: string,
  personas: ResolvedPersona[] = [],
  secrets: Array<{ value: string; placeholder: string }> = [],
): Grant {
  return {
    canRead: o => { try { return new URL(o).origin === origin } catch { return o === origin } },
    audit: () => undefined,
    allowLocalLab: true,
    tier: 3,
    isStateChangeApproved: () => true,
    personas: new Map(personas.map(p => [p.handle, p])),
    secrets,
  }
}

function sha256(text: string): string {
  return createHash('sha256').update(text, 'utf8').digest('hex')
}

// ============================================================================
// 1. R3-C-3: Raw kernel request plane (no key-name heuristic wiping)
// ============================================================================

test('R3-C-3: secret-named query and JSON body echoes stay intact on kernel plane so anti-reflection blocks forged injection while real secrets remain scrubbed', async (t) => {
  const runId = 'run-r3-c3-kernel-plane'
  resetRunCustodyBudgets(runId)
  t.after(() => resetRunCustodyBudgets(runId))

  const REAL_PERSONA_SECRET = 'persona_real_secret_99441122'
  // Synthetic error-fingerprint phrase echoed back by a reflecting endpoint (never a real exploit).
  const ECHO_FINGERPRINT = 'PG::SyntaxError: ERROR: syntax error at or near'

  const target = createServer((req, res) => {
    const url = new URL(req.url ?? '/', 'http://127.0.0.1')
    const chunks: Buffer[] = []
    req.on('data', c => chunks.push(c as Buffer))
    req.on('end', () => {
      const rawBody = Buffer.concat(chunks).toString('utf8')
      if (url.pathname === '/api/reflect-query') {
        const val = url.searchParams.get('token') ?? ''
        res.writeHead(200, { 'content-type': 'application/json' })
        res.end(JSON.stringify({ ok: true, echoed: val }))
        return
      }
      if (url.pathname === '/api/reflect-body') {
        let parsed: Record<string, unknown> = {}
        try { parsed = JSON.parse(rawBody) as Record<string, unknown> } catch { /* ignore */ }
        res.writeHead(200, { 'content-type': 'application/json' })
        res.end(JSON.stringify({ ok: true, echoed: String(parsed.api_key ?? '') }))
        return
      }
      res.writeHead(404)
      res.end('not found')
    })
  }).listen(0, '127.0.0.1')
  t.after(() => new Promise<void>(r => target.close(() => r())))
  await once(target, 'listening')
  const origin = `http://127.0.0.1:${(target.address() as AddressInfo).port}`

  const grant = makeGrant(origin, [makePersona('alice', 'member (acme)', REAL_PERSONA_SECRET, origin)])
  const rpc = new VerifyRpcServer({ broker: new RequestBroker(), grant, runId, assignmentId: 'a-c3', targetOrigins: [origin] })
  await rpc.start()
  t.after(() => rpc.close())

  // Query parameter named `token` (heuristic secret key name!) carrying echoed fingerprint
  const qCtrl = await rpcCall(rpc, 'http.send', {
    path: '/api/reflect-query?token=benign_value_1', method: 'GET', persona: 'alice', sessionGroupRole: 'control',
  })
  const qProbe = await rpcCall(rpc, 'http.send', {
    path: `/api/reflect-query?token=${encodeURIComponent(ECHO_FINGERPRINT)}`, method: 'GET', persona: 'alice', sessionGroupRole: 'probe',
  })
  // JSON body field named `api_key` carrying echoed fingerprint AND a real persona secret test
  const bCtrl = await rpcCall(rpc, 'http.send', {
    path: '/api/reflect-body', method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ api_key: 'benign_value_1' }), persona: 'alice', sessionGroupRole: 'control',
  })
  const bProbe = await rpcCall(rpc, 'http.send', {
    path: '/api/reflect-body', method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ api_key: ECHO_FINGERPRINT }), persona: 'alice', sessionGroupRole: 'probe',
  })
  const bRealSecret = await rpcCall(rpc, 'http.send', {
    path: '/api/reflect-body', method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ note: REAL_PERSONA_SECRET }), persona: 'alice', sessionGroupRole: 'probe',
  })

  assert.equal(qCtrl.ok, true)
  assert.equal(qProbe.ok, true)
  assert.equal(bCtrl.ok, true)
  assert.equal(bProbe.ok, true)
  assert.equal(bRealSecret.ok, true)

  const qCtrlId = (qCtrl.result as { exchangeId: string }).exchangeId
  const qProbeId = (qProbe.result as { exchangeId: string }).exchangeId
  const bCtrlId = (bCtrl.result as { exchangeId: string }).exchangeId
  const bProbeId = (bProbe.result as { exchangeId: string }).exchangeId
  const bRealId = (bRealSecret.result as { exchangeId: string }).exchangeId

  // Worker-facing response STILL heuristically scrubs secret-named query params!
  const qProbeWorkerPath = (qProbe.result as { pathAndQuery: string }).pathAndQuery
  assert.equal(qProbeWorkerPath.includes(encodeURIComponent(ECHO_FINGERPRINT)), false, 'worker-facing pathAndQuery remains heuristically scrubbed')

  // Kernel plane (both HostFactLog.fromTranscript AND HostFactLog.fromTranscriptStore) keeps
  // non-secret probe values intact (NO bare `[redacted]` wiping!) so anti-reflection strips the echo.
  const logs = [
    rpc.buildHostFactLog(),
    HostFactLog.fromTranscriptStore(rpc.transcript, { hostTranscript: rpc.buildHostSignedTranscript() }),
  ]
  for (const log of logs) {
    const qProbeFact = log.getExchange(qProbeId)!
    assert.equal(qProbeFact.pathAndQuery.includes('[redacted]'), false, 'kernel pathAndQuery must NOT heuristically wipe token= param')
    assert.equal(decodeURIComponent(qProbeFact.pathAndQuery).includes(ECHO_FINGERPRINT), true, 'kernel pathAndQuery must retain non-secret probe value')

    const qCtrlStep = log.toImpactStep(qCtrlId, { arm: 'control' })!
    const qProbeStep = log.toImpactStep(qProbeId, { arm: 'probe' })!
    assert.equal(matchStrippedInjectionFingerprint(qProbeStep, 'sqli'), null, 'query token= echo must be stripped before fingerprint matching')
    const qAssess = assessInjectionImpact({ impactClass: 'injection', steps: [qCtrlStep, qProbeStep], injection: { family: 'sqli' } })
    assert.equal(qAssess.satisfied, false, 'echoed secret-named query parameter must NOT confirm sqli')

    const bProbeFact = log.getExchange(bProbeId)!
    assert.equal((bProbeFact.rawRequestBody ?? '').includes('[redacted]'), false, 'kernel rawRequestBody must NOT heuristically wipe api_key JSON field')
    assert.equal((bProbeFact.rawRequestBody ?? '').includes(ECHO_FINGERPRINT), true)

    const bCtrlStep = log.toImpactStep(bCtrlId, { arm: 'control' })!
    const bProbeStep = log.toImpactStep(bProbeId, { arm: 'probe' })!
    assert.equal(matchStrippedInjectionFingerprint(bProbeStep, 'sqli'), null, 'JSON api_key echo must be stripped before fingerprint matching')
    const bAssess = assessInjectionImpact({ impactClass: 'injection', steps: [bCtrlStep, bProbeStep], injection: { family: 'sqli' } })
    assert.equal(bAssess.satisfied, false, 'echoed secret-named JSON body field must NOT confirm sqli')

    // Real host/persona secret MUST STILL be scrubbed on the kernel plane!
    const realFact = log.getExchange(bRealId)!
    assert.equal((realFact.rawRequestBody ?? '').includes(REAL_PERSONA_SECRET), false, 'real persona secret must STILL be exact-scrubbed on kernel plane')
    assert.equal((realFact.rawRequestBody ?? '').includes('[redacted:alice]'), true)
  }
})

// ============================================================================
// 2. R3-H-2: Blind custody — async.awaitResult, prove.differential, bodySha256
// ============================================================================

test('R3-H-2: async.awaitResult predicates produce identical results on reflected sealed values (zero membership oracle), reject unsafe regexes, and enforce run budget', async (t) => {
  const runId = 'run-r3-h2-async-blind'
  resetRunCustodyBudgets(runId)
  resetRunAsyncPollBudgets(runId)
  t.after(() => {
    resetRunCustodyBudgets(runId)
    resetRunAsyncPollBudgets(runId)
  })

  const VAULT_SECRET = 'MixEd_VaUlt_SeCrEt_882244'
  let reflectCalls = 0

  const target = createServer((req, res) => {
    const url = new URL(req.url ?? '/', 'http://127.0.0.1')
    if (url.pathname === '/api/issue') {
      res.writeHead(200, { 'content-type': 'application/json' })
      res.end(JSON.stringify({ secretToken: VAULT_SECRET }))
      return
    }
    if (url.pathname === '/api/reflect') {
      reflectCalls += 1
      const val = url.searchParams.get('v') ?? ''
      res.writeHead(200, {
        'content-type': 'application/json',
        'x-reflected': val,
      })
      res.end(JSON.stringify({ echoed: val, status: 'ready' }))
      return
    }
    res.writeHead(404)
    res.end('nope')
  }).listen(0, '127.0.0.1')
  t.after(() => new Promise<void>(r => target.close(() => r())))
  await once(target, 'listening')
  const origin = `http://127.0.0.1:${(target.address() as AddressInfo).port}`

  const grant = makeGrant(origin)
  const rpc1 = new VerifyRpcServer({
    broker: new RequestBroker(), grant, runId, assignmentId: 'a-h2-1', targetOrigins: [origin],
    maxAsyncPollCallsPerRun: 12, maxAsyncPollAttemptsPerRun: 12,
  })
  const rpc2 = new VerifyRpcServer({
    broker: new RequestBroker(), grant, runId, assignmentId: 'a-h2-2', targetOrigins: [origin],
    maxAsyncPollCallsPerRun: 12, maxAsyncPollAttemptsPerRun: 12,
  })
  await rpc1.start()
  await rpc2.start()
  t.after(() => Promise.all([rpc1.close(), rpc2.close()]))

  // Seal a target-issued secret that broker.ts itself does not register as a persona secret
  const issue = await rpcCall(rpc1, 'http.send', { path: '/api/issue', method: 'GET' })
  assert.equal(issue.ok, true)
  const seal = await rpcCall(rpc1, 'capability.seal', {
    exchangeId: (issue.result as { exchangeId: string }).exchangeId,
    hopReceiptId: '1',
    slot: 'vault_sec',
    jsonPath: '$.secretToken',
  })
  assert.equal(seal.ok, true)
  const handle = (seal.result as { handle: string }).handle

  // True vs false predicates across bodyContains, bodyMatches, jsonPath equals/matches, and header matches
  const pairs: Array<[string, Record<string, unknown>, Record<string, unknown>]> = [
    ['bodyContains', { bodyContains: VAULT_SECRET.slice(0, 8) }, { bodyContains: 'ZZZZ_NO_MATCH' }],
    ['bodyMatches', { bodyMatches: 'MixEd_VaUlt' }, { bodyMatches: 'ZzZz_NoMatch' }],
    ['jsonPath.equals', { jsonPath: '$.echoed', equals: VAULT_SECRET }, { jsonPath: '$.echoed', equals: 'wrong-val' }],
    ['jsonPath.matches', { jsonPath: '$.echoed', matches: 'VaUlt_SeCrEt' }, { jsonPath: '$.echoed', matches: 'NoMatch_999' }],
    ['header.matches', { header: { name: 'x-reflected', matches: 'MixEd_VaUlt' } }, { header: { name: 'x-reflected', matches: 'ZzZz_NoMatch' } }],
  ]

  for (const [label, truePred, falsePred] of pairs) {
    const tRes = await rpcCall(rpc1, 'async.awaitResult', {
      pollRequest: { path: `/api/reflect?v=${handle}`, method: 'GET' },
      matchPredicate: truePred,
      maxAttempts: 1,
      intervalMs: 1,
      timeoutMs: 1_000,
    })
    const fRes = await rpcCall(rpc1, 'async.awaitResult', {
      pollRequest: { path: `/api/reflect?v=${handle}`, method: 'GET' },
      matchPredicate: falsePred,
      maxAttempts: 1,
      intervalMs: 1,
      timeoutMs: 1_000,
    })
    assert.equal(tRes.ok, true, `${label} true call failed: ${tRes.error}`)
    assert.equal(fRes.ok, true, `${label} false call failed: ${fRes.error}`)
    const tOut = tRes.result as { converged: boolean; status: string; evidence: { attemptLog: Array<{ matched: boolean }> }; exchange: { body: string; bodySha256: string } }
    const fOut = fRes.result as { converged: boolean; status: string; evidence: { attemptLog: Array<{ matched: boolean }> }; exchange: { body: string; bodySha256: string } }
    assert.equal(tOut.converged, false, `${label}: true predicate on reflected vault secret must NOT converge`)
    assert.equal(fOut.converged, false, `${label}: false predicate must NOT converge`)
    assert.equal(tOut.status, fOut.status, `${label}: true vs false status must be identical`)
    assert.deepEqual(
      tOut.evidence.attemptLog.map(a => a.matched),
      fOut.evidence.attemptLog.map(a => a.matched),
      `${label}: attemptLog matched booleans must be identical for true vs false predicates`,
    )
    assert.equal(tOut.exchange.body.includes(VAULT_SECRET), false, `${label}: worker body must scrub vault secret`)
    assert.equal(tOut.exchange.bodySha256, sha256(tOut.exchange.body), `${label}: bodySha256 must hash ONLY worker-visible scrubbed body`)
  }

  // Unsafe regexes (ReDoS nested quantifier, lookahead, backreference) rejected BEFORE any HTTP poll!
  const callsBeforeUnsafe = reflectCalls
  for (const badPred of [
    { bodyMatches: '(a+)+$' },
    { bodyMatches: '(?=MixEd)MixEd' },
    { jsonPath: '$.echoed', matches: '(a+)\\1' },
    { header: { name: 'x-reflected', matches: '(a|a)+$' } },
  ]) {
    const badRes = await rpcCall(rpc1, 'async.awaitResult', {
      pollRequest: { path: `/api/reflect?v=${handle}`, method: 'GET' },
      matchPredicate: badPred,
      maxAttempts: 1,
      intervalMs: 1,
      timeoutMs: 1_000,
    })
    assert.equal(badRes.ok, false, `unsafe regex ${JSON.stringify(badPred)} must be rejected`)
    assert.match(badRes.error ?? '', /regex rejected/i)
  }
  assert.equal(reflectCalls, callsBeforeUnsafe, 'unsafe regexes must be rejected without issuing HTTP polls')

  // Run-scoped budget (10 attempts already used on rpc1 out of max 12): 2 more succeed, 3rd on rpc2 trips run budget!
  const r11 = await rpcCall(rpc2, 'async.awaitResult', {
    pollRequest: { path: '/api/reflect?v=ok', method: 'GET' },
    matchPredicate: { bodyContains: 'status' },
    maxAttempts: 1, intervalMs: 1, timeoutMs: 1_000,
  })
  const r12 = await rpcCall(rpc2, 'async.awaitResult', {
    pollRequest: { path: '/api/reflect?v=ok', method: 'GET' },
    matchPredicate: { bodyContains: 'status' },
    maxAttempts: 1, intervalMs: 1, timeoutMs: 1_000,
  })
  const r13 = await rpcCall(rpc2, 'async.awaitResult', {
    pollRequest: { path: '/api/reflect?v=ok', method: 'GET' },
    matchPredicate: { bodyContains: 'status' },
    maxAttempts: 1, intervalMs: 1, timeoutMs: 1_000,
  })
  assert.equal(r11.ok, true)
  assert.equal(r12.ok, true)
  assert.equal(r13.ok, false, '13th async.awaitResult call across shared runId must trip run-scoped budget')
  assert.match(r13.error ?? '', /budget exceeded/i)
})

test('R3-H-2: prove.differential emits NO plaintext stableDelta fragments, hashes only worker-visible scrubbed bodies, and sees no oracle on sealed values', async (t) => {
  const runId = 'run-r3-h2-diff-blind'
  resetRunCustodyBudgets(runId)
  t.after(() => resetRunCustodyBudgets(runId))

  const VAULT_SECRET_A = 'CaSeSeNs_AlphaTok_9911'
  const VAULT_SECRET_B = 'CaSeSeNs_BetaTok_7733'

  const target = createServer((req, res) => {
    const url = new URL(req.url ?? '/', 'http://127.0.0.1')
    if (url.pathname === '/api/seed') {
      res.writeHead(200, { 'content-type': 'application/json' })
      res.end(JSON.stringify({ secA: VAULT_SECRET_A, secB: VAULT_SECRET_B }))
      return
    }
    if (url.pathname === '/api/echo') {
      const val = url.searchParams.get('x') ?? ''
      res.writeHead(200, { 'content-type': 'application/json' })
      res.end(JSON.stringify({ out: val }))
      return
    }
    res.writeHead(404)
    res.end('nope')
  }).listen(0, '127.0.0.1')
  t.after(() => new Promise<void>(r => target.close(() => r())))
  await once(target, 'listening')
  const origin = `http://127.0.0.1:${(target.address() as AddressInfo).port}`

  const rpc = new VerifyRpcServer({ broker: new RequestBroker(), grant: makeGrant(origin), runId, assignmentId: 'a-h2-diff', targetOrigins: [origin] })
  await rpc.start()
  t.after(() => rpc.close())

  const seed = await rpcCall(rpc, 'http.send', { path: '/api/seed', method: 'GET' })
  const seedId = (seed.result as { exchangeId: string }).exchangeId
  const sA = await rpcCall(rpc, 'capability.seal', { exchangeId: seedId, hopReceiptId: '1', slot: 'sec_a', jsonPath: '$.secA' })
  const sB = await rpcCall(rpc, 'capability.seal', { exchangeId: seedId, hopReceiptId: '1', slot: 'sec_b', jsonPath: '$.secB' })
  const hA = (sA.result as { handle: string }).handle
  const hB = (sB.result as { handle: string }).handle

  // 1) Differential between a literal value and a reflected sealed value:
  //    ZERO lowercased/punctuation-split plaintext fragments of VAULT_SECRET_A may appear anywhere!
  const diff1 = await rpcCall(rpc, 'prove.differential', {
    control: `/api/echo?x=public_plain_word`,
    variant: `/api/echo?x=${hA}`,
    mode: 'boolean',
    rounds: 2,
  })
  assert.equal(diff1.ok, true, diff1.error ?? '')
  const d1 = diff1.result as {
    ok: boolean
    stats: Record<string, unknown>
    exchanges: { control: Array<{ exchangeId: string; body: string; bodySha256: string }>; variant: Array<{ exchangeId: string; body: string; bodySha256: string }> }
  }
  const d1Json = JSON.stringify(d1).toLowerCase()
  assert.equal('stableDelta' in d1.stats, false, 'prove.differential stats must NOT expose raw plaintext stableDelta array')
  assert.equal(d1Json.includes('casesens'), false, 'lowercased secret prefix must never leak in prove.differential')
  assert.equal(d1Json.includes('alphatok'), false, 'lowercased secret token must never leak in prove.differential')
  assert.equal(d1Json.includes('9911'), false, 'secret numeric fragment must never leak in prove.differential')
  assert.equal(typeof d1.stats.stableDeltaCount, 'number')
  const digests = d1.stats.stableDeltaDigests as string[]
  assert.ok(Array.isArray(digests) && digests.every(d => /^hmac:[0-9a-f]{16}$/.test(d)), 'stableDeltaDigests must be keyed HMAC digests')

  // Worker-visible bodySha256 MUST equal sha256(scrubbedBody), NEVER sha256(rawUnscrubbedBody)!
  const variantEx = d1.exchanges.variant[0]!
  const rawVariantBody = JSON.stringify({ out: VAULT_SECRET_A })
  assert.equal(variantEx.bodySha256, sha256(variantEx.body), 'exchangeView bodySha256 must hash worker-visible scrubbed body')
  assert.notEqual(variantEx.bodySha256, sha256(rawVariantBody), 'exchangeView bodySha256 must NOT hash raw pre-scrub body')

  // transcript.get must ALSO return scrubbed bodySha256!
  const txGet = await rpcCall(rpc, 'transcript', { action: 'get', exchangeId: variantEx.exchangeId })
  assert.equal(txGet.ok, true)
  const txOut = txGet.result as { body: string; record: { response: { bodySha256: string } } }
  assert.equal(txOut.record.response.bodySha256, sha256(txOut.body))
  assert.notEqual(txOut.record.response.bodySha256, sha256(rawVariantBody))

  // 2) Differential between two reflected sealed vault secrets: normalized scrubbed bodies are identical -> ok: false!
  const diff2 = await rpcCall(rpc, 'prove.differential', {
    control: `/api/echo?x=${hA}`,
    variant: `/api/echo?x=${hB}`,
    mode: 'boolean',
    rounds: 2,
  })
  assert.equal(diff2.ok, true)
  const d2 = diff2.result as { ok: boolean; stats: { stableDeltaCount: number } }
  assert.equal(d2.ok, false, 'two reflected sealed vault secrets must normalize identically on worker-visible plane')
  assert.equal(d2.stats.stableDeltaCount, 0)
})

// ============================================================================
// 3. R3-H-4(a) & R3-H-5: No base-persona laundering + explicit host placement
// ============================================================================

test('R3-H-4(a) & R3-H-5: admin base persona + member auth capability drops ALL admin headers and stamps explicit host auth placement', async (t) => {
  const runId = 'run-r3-h4a-h5-placement'
  resetRunCustodyBudgets(runId)
  t.after(() => resetRunCustodyBudgets(runId))

  const ADMIN_BEARER = 'adm_bearer_secret_77112233'
  const ADMIN_APIKEY = 'adm_apikey_secret_44556677'
  const MEMBER_COOKIE_VAL = 'mbr_cookie_secret_99001122'
  const MEMBER_KEY_VAL = 'mbr_apikey_secret_33445566'
  const PURE_COOKIE_VAL = 'sid=pure_cookie_secret_556677'

  const observed: Array<{ path: string; auth: string; apiKey: string; cookie: string }> = []

  const target = createServer((req, res) => {
    const url = new URL(req.url ?? '/', 'http://127.0.0.1')
    if (url.pathname === '/api/member/login') {
      res.writeHead(200, {
        'content-type': 'application/json',
        'set-cookie': `member_sid=${MEMBER_COOKIE_VAL}; Path=/; HttpOnly`,
      })
      res.end(JSON.stringify({ apiKey: MEMBER_KEY_VAL }))
      return
    }
    if (url.pathname === '/api/set-jar') {
      res.writeHead(200, {
        'content-type': 'application/json',
        'set-cookie': 'lb_route=node1; Path=/; SameSite=None',
      })
      res.end(JSON.stringify({ ok: true }))
      return
    }
    observed.push({
      path: url.pathname,
      auth: String(req.headers.authorization ?? ''),
      apiKey: String(req.headers['x-api-key'] ?? ''),
      cookie: String(req.headers.cookie ?? ''),
    })
    res.writeHead(200, { 'content-type': 'application/json' })
    res.end(JSON.stringify({ ok: true }))
  }).listen(0, '127.0.0.1')
  t.after(() => new Promise<void>(r => target.close(() => r())))
  await once(target, 'listening')
  const origin = `http://127.0.0.1:${(target.address() as AddressInfo).port}`

  const grant = makeGrant(origin, [
    makePersona('admin_bearer', 'admin (acme)', ADMIN_BEARER, origin, 'bearer', 'Authorization'),
    makePersona('admin_key', 'admin (acme)', ADMIN_APIKEY, origin, 'header', 'X-API-Key'),
    makePersona('member_a', 'member (acme)', 'mbr_bearer_tok_11112222', origin, 'bearer', 'Authorization'),
    makePersona('cookie_user', 'member (acme)', PURE_COOKIE_VAL, origin, 'cookie', null),
  ])
  const rpc = new VerifyRpcServer({ broker: new RequestBroker(), grant, runId, assignmentId: 'a-h4h5', targetOrigins: [origin] })
  await rpc.start()
  t.after(() => rpc.close())

  // Member emits a cookie capability and an API-key capability
  const login = await rpcCall(rpc, 'http.send', { path: '/api/member/login', method: 'POST', persona: 'member_a', sessionGroupRole: 'setup' })
  const loginId = (login.result as { exchangeId: string }).exchangeId
  const ckSeal = await rpcCall(rpc, 'capability.seal', { exchangeId: loginId, hopReceiptId: '1', slot: 'mbr_ck', setCookie: 'member_sid' })
  const keySeal = await rpcCall(rpc, 'capability.seal', { exchangeId: loginId, hopReceiptId: '1', slot: 'mbr_key', jsonPath: '$.apiKey' })
  assert.equal(ckSeal.ok, true)
  assert.equal(keySeal.ok, true)
  const ckHandle = (ckSeal.result as { handle: string }).handle
  const keyHandle = (keySeal.result as { handle: string }).handle

  // R3-H-4(a) Attack 1: admin_bearer persona + member cookie capability (inline Cookie header)
  const atk1 = await rpcCall(rpc, 'http.send', {
    path: '/api/admin/secret-1', method: 'POST', persona: 'admin_bearer',
    headers: { Cookie: `member_sid=${ckHandle}` }, sessionGroupRole: 'probe',
  })
  assert.equal(atk1.ok, true)
  assert.equal(observed[0]!.auth, '', 'admin Authorization header MUST be dropped when member cookie capability is supplied')
  assert.ok(observed[0]!.cookie.includes(`member_sid=${MEMBER_COOKIE_VAL}`))

  // R3-H-4(a) Attack 2: admin_key (X-API-Key) persona + member cookie capability (explicit capability arg)
  const atk2 = await rpcCall(rpc, 'http.send', {
    path: '/api/admin/secret-2', method: 'POST', persona: 'admin_key',
    capability: { handle: ckHandle, target: 'cookie', cookieName: 'member_sid' }, sessionGroupRole: 'probe',
  })
  assert.equal(atk2.ok, true)
  assert.equal(observed[1]!.apiKey, '', 'admin X-API-Key header MUST be dropped when member cookie capability is supplied')
  assert.ok(observed[1]!.cookie.includes(`member_sid=${MEMBER_COOKIE_VAL}`))

  // R3-H-4(a) Attack 3: admin_bearer persona + member X-API-Key capability (target: 'header')
  const atk3 = await rpcCall(rpc, 'http.send', {
    path: '/api/admin/secret-3', method: 'POST', persona: 'admin_bearer',
    capability: { handle: keyHandle, target: 'header', headerName: 'X-API-Key' }, sessionGroupRole: 'probe',
  })
  assert.equal(atk3.ok, true)
  assert.equal(observed[2]!.auth, '', 'admin Authorization header MUST be dropped when member X-API-Key capability is supplied')
  assert.equal(observed[2]!.apiKey, MEMBER_KEY_VAL)

  // R3-H-5 Case A: Bearer persona + session-jar SameSite=None cookie -> MUST stamp mixed=true, personaAuthKind='bearer', ambientAuth='bearer'
  await rpcCall(rpc, 'http.send', { path: '/api/set-jar', method: 'GET', persona: 'admin_bearer', session: 'jar-csrf-test' })
  const mixedEx = await rpcCall(rpc, 'http.send', {
    path: '/api/mutate', method: 'POST', persona: 'admin_bearer', session: 'jar-csrf-test',
  })
  assert.equal(mixedEx.ok, true)
  const mixedId = (mixedEx.result as { exchangeId: string }).exchangeId

  // R3-H-5 Case B: Pure cookie persona -> personaAuthKind='cookie', mixed=false, vaultCookieNames=['sid']
  const pureCkEx = await rpcCall(rpc, 'http.send', {
    path: '/api/cookie-only', method: 'POST', persona: 'cookie_user',
  })
  assert.equal(pureCkEx.ok, true)
  const pureCkId = (pureCkEx.result as { exchangeId: string }).exchangeId

  // Verify stamped HostAuthPlacement on BOTH HostSignedTranscript and TranscriptStore records!
  const signed = rpc.buildHostSignedTranscript()
  const atk1Id = (atk1.result as { exchangeId: string }).exchangeId
  const atk3Id = (atk3.result as { exchangeId: string }).exchangeId

  const entryOf = (id: string) => signed.entries?.find(e => e.exchangeId === id)
  const reqOf = (id: string) => rpc.transcript.get(id)?.request

  // Stamped explicit HostAuthPlacement fields on signed entries & TranscriptStore requests (for Stream 4b)
  for (const src of [entryOf(atk1Id)?.credentialPlacement, reqOf(atk1Id)?.credentialPlacement]) {
    const p = src as { basePersonaDropped?: boolean; capabilityAuthInjected?: boolean; vaultCookieNames?: string[]; authenticatingCookieName?: string | null } | undefined
    assert.equal(p?.basePersonaDropped, true, 'atk1 must stamp basePersonaDropped=true')
    assert.equal(p?.capabilityAuthInjected, true)
    assert.deepEqual(p?.vaultCookieNames, [], 'worker-chosen capability cookie must NOT enter vaultCookieNames')
    assert.equal(p?.authenticatingCookieName, null, 'worker-chosen capability cookie name must not bind vault authenticatingCookieName')
  }
  for (const src of [entryOf(atk3Id)?.credentialPlacement, reqOf(atk3Id)?.credentialPlacement]) {
    const p = src as { personaAuthKind?: string; basePersonaDropped?: boolean } | undefined
    assert.equal(p?.personaAuthKind, 'header')
    assert.equal(p?.basePersonaDropped, true)
  }
  for (const src of [entryOf(mixedId)?.credentialPlacement, reqOf(mixedId)?.credentialPlacement]) {
    const p = src as { personaAuthKind?: string; mixed?: boolean; wireAuthHeaders?: string[]; authenticatingCookieName?: string | null } | undefined
    assert.equal(p?.personaAuthKind, 'bearer')
    assert.equal(p?.mixed, true, 'bearer + session-jar cookie MUST be stamped mixed=true')
    assert.ok(p?.wireAuthHeaders?.includes('authorization'))
    assert.equal(p?.authenticatingCookieName, null)
  }
  for (const src of [entryOf(pureCkId)?.credentialPlacement, reqOf(pureCkId)?.credentialPlacement]) {
    const p = src as { personaAuthKind?: string; mixed?: boolean; vaultCookieNames?: string[]; authenticatingCookieName?: string | null } | undefined
    assert.equal(p?.personaAuthKind, 'cookie')
    assert.equal(p?.mixed, false)
    assert.equal(p?.authenticatingCookieName, 'sid')
    assert.deepEqual(p?.vaultCookieNames, ['sid'])
  }

  // Downstream HostFactLog projections preserve authoritative placement & ambientAuth!
  const logs = [
    HostFactLog.fromTranscript(signed),
    HostFactLog.fromTranscriptStore(rpc.transcript, { hostTranscript: signed }),
  ]
  for (const log of logs) {
    const fAtk1 = log.getExchange(atk1Id)!
    assert.equal(fAtk1.actorRole, 'member', 'atk1 actor role is member capability (and admin auth never went on wire)')
    assert.equal(fAtk1.credentialPlacement?.mixed, false)

    const fAtk3 = log.getExchange(atk3Id)!
    assert.equal(fAtk3.actorRole, 'member')
    assert.equal(fAtk3.credentialPlacement?.personaAuthKind, 'header')

    const fMixed = log.getExchange(mixedId)!
    assert.equal(fMixed.credentialPlacement?.personaAuthKind, 'bearer')
    assert.equal(fMixed.credentialPlacement?.mixed, true, 'bearer + session-jar cookie MUST be stamped mixed=true')
    assert.equal(fMixed.ambientAuth, 'bearer', 'mixed bearer+cookie must NEVER classify as cookie')
    assert.equal(fMixed.credentialPlacement?.authenticatingCookieName ?? null, null)
    assert.ok(fMixed.credentialPlacement?.headerNames?.includes('authorization'))

    const fPureCk = log.getExchange(pureCkId)!
    assert.equal(fPureCk.credentialPlacement?.personaAuthKind, 'cookie')
    assert.equal(fPureCk.credentialPlacement?.mixed, false)
    assert.equal(fPureCk.ambientAuth, 'cookie')
    assert.equal(fPureCk.credentialPlacement?.authenticatingCookieName, 'sid')
    assert.deepEqual(fPureCk.credentialPlacement?.jarCookieNames, ['sid'])
  }

  // Unit check: buildHostAuthPlacement with wire provenance showing BOTH authorization + worker cookie
  const mockWire: WireCredentialProvenance = {
    authenticated: true,
    source: 'persona_vault',
    sources: ['persona_vault'],
    personaHandle: 'bearer_p',
    session: null,
    headerNames: ['authorization', 'cookie'],
    cookieNames: ['lb_samesite_none'],
    vaultCookieNames: [],
    jarCookieNames: [],
    vaultHeaderNames: ['authorization'],
    callerAuthHeaderNames: [],
    authMutated: false,
  }
  const placement = buildHostAuthPlacement({
    wireProvenance: mockWire,
    basePersonaAuthKind: 'bearer',
    requestHeaders: { Cookie: 'lb_samesite_none=[injected]' },
  })
  assert.equal(placement.personaAuthKind, 'bearer')
  assert.equal(placement.mixed, true)
  assert.deepEqual(placement.wireAuthHeaders, ['authorization'])
  assert.equal(placement.authenticatingCookieName ?? null, null)
  assert.equal(deriveAmbientAuthFromHeaders({ Cookie: 'lb_samesite_none=[injected]' }, undefined, placement), 'bearer')
})

// ============================================================================
// 4. R3-C-4: Host-minted boolean pairs & base-value parity in prove.differential
// ============================================================================

test('R3-C-4: prove.differential rejects mismatched boolean base values (integer-coercion attack) and binds host-minted boolean pairs to identical base', async (t) => {
  const runId = 'run-r3-c4-boolean-base'
  resetRunCustodyBudgets(runId)
  t.after(() => resetRunCustodyBudgets(runId))

  // Pure unit checks for host-minted pair + base stripping
  const minted = mintHostBooleanPair('42', { style: 'numeric' })
  assert.equal(stripBooleanPredicateSuffix(minted.trueValue).baseValue, '42')
  assert.equal(stripBooleanPredicateSuffix(minted.trueValue).predicateTruth, true)
  assert.equal(stripBooleanPredicateSuffix(minted.falseValue).baseValue, '42')
  assert.equal(stripBooleanPredicateSuffix(minted.falseValue).predicateTruth, false)
  assert.equal(verifyBooleanArmBaseParity({ controlValue: minted.trueValue, variantValue: minted.falseValue, baselineValue: '42', hostPair: minted }).ok, true)
  assert.equal(verifyBooleanArmBaseParity({ controlValue: '1 AND 1=1', variantValue: '999 AND 1=2', baselineValue: '1' }).ok, false)

  let coerceHits = 0
  const target = createServer((req, res) => {
    const url = new URL(req.url ?? '/', 'http://127.0.0.1')
    const id = url.searchParams.get('id') ?? ''
    if (url.pathname === '/api/coerce') {
      coerceHits += 1
      // Safe parameterized integer-coercing endpoint (parseInt leading digits)
      const parsed = Number.parseInt(id, 10)
      if (parsed === 1) {
        res.writeHead(200, { 'content-type': 'application/json' })
        res.end(JSON.stringify({ id: 1, title: 'Existing Record' }))
      } else {
        res.writeHead(404, { 'content-type': 'application/json' })
        res.end(JSON.stringify({ error: 'not_found' }))
      }
      return
    }
    if (url.pathname === '/api/sqli-bool') {
      // Truly vulnerable boolean-SQLi endpoint evaluating trailing `AND A=B`
      const stripped = stripBooleanPredicateSuffix(id)
      const baseOk = stripped.baseValue === '1'
      const predOk = stripped.predicateTruth !== false
      if (baseOk && predOk) {
        res.writeHead(200, { 'content-type': 'application/json' })
        res.end(JSON.stringify({ id: 1, title: 'Existing Record', rows: 1 }))
      } else {
        res.writeHead(200, { 'content-type': 'application/json' })
        res.end(JSON.stringify({ id: null, title: 'Empty', rows: 0 }))
      }
      return
    }
    res.writeHead(404)
    res.end('nope')
  }).listen(0, '127.0.0.1')
  t.after(() => new Promise<void>(r => target.close(() => r())))
  await once(target, 'listening')
  const origin = `http://127.0.0.1:${(target.address() as AddressInfo).port}`

  const rpc = new VerifyRpcServer({ broker: new RequestBroker(), grant: makeGrant(origin), runId, assignmentId: 'a-c4', targetOrigins: [origin] })
  await rpc.start()
  t.after(() => rpc.close())

  // 1) Integer-coercion bypass attempt (baseline=1, true='1 AND 1=1', false='999 AND 1=2')
  //    MUST be rejected BEFORE sending any HTTP traffic!
  const forgeAttempt = await rpcCall(rpc, 'prove.differential', {
    baseline: '/api/coerce?id=1',
    control: '/api/coerce?id=1%20AND%201%3D1',
    variant: '/api/coerce?id=999%20AND%201%3D2',
    mode: 'boolean',
    rounds: 2,
  })
  assert.equal(forgeAttempt.ok, true)
  const forgeOut = forgeAttempt.result as { ok: boolean; rejectedBy: string; missingEvidence: string[] }
  assert.equal(forgeOut.ok, false, 'mismatched boolean base values (1 vs 999) MUST be rejected')
  assert.equal(forgeOut.rejectedBy, 'boolean_base_mismatch')
  assert.ok(forgeOut.missingEvidence.includes('boolean_base_value_parity'))
  assert.equal(coerceHits, 0, 'mismatched base values must fail closed before issuing traffic')

  // 2) Host-minted boolean pair against integer-coercing SAFE endpoint: all 3 arms share base='1' -> identical 200 -> rejected!
  const safeHostPair = await rpcCall(rpc, 'prove.differential', {
    booleanBase: '1',
    booleanStyle: 'numeric',
    baseline: '/api/coerce?id={{boolBase}}',
    control: '/api/coerce?id={{boolTrue}}',
    variant: '/api/coerce?id={{boolFalse}}',
    mode: 'boolean',
    rounds: 2,
  })
  assert.equal(safeHostPair.ok, true)
  const safeOut = safeHostPair.result as { ok: boolean; stats: { stableDeltaCount: number; sharedBase: string } }
  assert.equal(safeOut.ok, false, 'safe integer-coercing endpoint must NOT confirm with host-minted boolean pair')
  assert.equal(safeOut.stats.stableDeltaCount, 0)
  assert.equal(safeOut.stats.sharedBase, '1')

  // 3) Host-minted boolean pair against truly vulnerable boolean-SQLi endpoint -> confirmed with sharedBase='1' & baselineMatchesTrue=true!
  const vulnHostPair = await rpcCall(rpc, 'prove.differential', {
    booleanBase: '1',
    booleanStyle: 'numeric',
    baseline: '/api/sqli-bool?id={{boolBase}}',
    control: '/api/sqli-bool?id={{boolTrue}}',
    variant: '/api/sqli-bool?id={{boolFalse}}',
    mode: 'boolean',
    rounds: 2,
  })
  assert.equal(vulnHostPair.ok, true)
  const vulnOut = vulnHostPair.result as {
    ok: boolean
    hostBooleanPair?: { baseValue: string }
    stats: { sharedBase: string; baselineMatchesTrue: boolean; stableDeltaCount: number; stableDeltaDigests: string[] }
  }
  assert.equal(vulnOut.ok, true, 'truly vulnerable boolean SQLi endpoint must confirm with host-minted boolean pair')
  assert.equal(vulnOut.hostBooleanPair?.baseValue, '1')
  assert.equal(vulnOut.stats.sharedBase, '1')
  assert.equal(vulnOut.stats.baselineMatchesTrue, true)
  assert.ok(vulnOut.stats.stableDeltaCount >= 1)
  assert.equal('stableDelta' in vulnOut.stats, false)
})
