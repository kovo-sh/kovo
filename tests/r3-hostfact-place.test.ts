/**
 * R3 Stream 4b Regression Suite — HostFactLog Placement, Bound SameSite, Broadened Redacted Guard,
 * Status-Differential Base Binding, and Active H-14 Wire-Provenance Auth-Bypass Enforcement.
 *
 * Covers:
 *  - R3-H-5: Authoritative wire-provenance placement (`deriveCredentialPlacement` reads signed
 *            `wireCredentialProvenance` even when a `Cookie` header exists; marks mixed auth when
 *            any auth header accompanies a cookie; binds `authenticatingCookieName` strictly to
 *            vault/jar cookies; drops unbound SameSite fallback in `resolveSameSite` /
 *            `sameSiteFromRecord` / `extractSameSiteFromHeaders`).
 *            End-to-end `VerifyRpcServer` + `HostFactLog` + `proof-receipt`: bearer persona +
 *            worker-chosen cookie capability named after a same-origin `SameSite=None` cookie ->
 *            NOT pure cookie, `isCrossSiteSendableCsrfRequest` is false, CSRF NOT confirmed.
 *  - R3-C-3: Broadened `[redacted...]` placeholder guard across `host-fact-log.ts`,
 *            `proof-receipt.ts`, and `verify-claims.ts` so bare `[redacted]` / `[redacted:...`
 *            placeholders in injection or markup request arms fail closed.
 *  - R3-C-4: `statusDifferentialRounds` in `proof-receipt.ts` routed through shared
 *            `verifyBooleanTriangleBinding` so integer-coercion triangles fail closed.
 *  - H-14:   Signed `wireCredentialProvenance` actively read and enforced in `proof-receipt.ts`
 *            `auth_bypass` guard, and session-jar identity (`sessionId`) preserved on verify-path
 *            `HostFactLog` facts (`buildHostFactLog` and `fromTranscriptStore`).
 */
import assert from 'node:assert/strict'
import { once } from 'node:events'
import { createServer, request as httpRequest } from 'node:http'
import type { AddressInfo } from 'node:net'
import test from 'node:test'
import { RequestBroker } from '../src/server/broker.ts'
import type { Grant, WireCredentialProvenance } from '../src/server/broker.ts'
import { resetRunCustodyBudgets } from '../src/server/derived-custody.ts'
import {
  HostFactLog,
  VAULT_SCRUBBED_TOKEN_RE,
  assertCleanKernelRequestPlane,
  deriveAmbientAuthFromHeaders,
  deriveCredentialPlacement,
  extractSameSiteFromHeaders,
  hasVaultScrubbedRequestPlane,
  hasVaultScrubbedToken,
} from '../src/server/host-fact-log.ts'
import type { ImpactStep } from '../src/server/oracle-invariants.ts'
import type { ResolvedPersona } from '../src/server/persona-vault.ts'
import {
  HostMintedOracle,
  buildAgentScriptReceipt,
  buildProofReceipt,
  isCrossSiteSendableCsrfRequest,
  verifyReceipt,
} from '../src/server/proof-receipt.ts'
import {
  TranscriptStore,
  evaluateClaims,
  sameSiteFromRecord,
} from '../src/server/verify-claims.ts'
import {
  VERIFY_NONCE_HEADER,
  VERIFY_RPC_HEADER,
  VerifyRpcServer,
} from '../src/server/verify-rpc.ts'

process.env.KOVO_ALLOW_LOCAL_LAB = '1'

const ORIGIN = 'http://127.0.0.1:4100'

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

function mkStep(overrides: Partial<ImpactStep> & Pick<ImpactStep, 'id' | 'arm' | 'method' | 'route' | 'status'>): ImpactStep {
  return {
    actor: { handle: 'alice', role: 'member', tenant: 'acme', auth: 'bearer', sameSite: null },
    ...overrides,
  }
}

// ============================================================================
// 1. R3-H-5: End-to-end VerifyRpcServer + HostFactLog + proof-receipt CSRF guard
// ============================================================================

test('R3-H-5: bearer persona + worker-chosen cookie capability named after SameSite=None cookie is NOT pure cookie and NEVER confirms CSRF', async (t) => {
  const runId = 'run-r3-h5-csrf-e2e'
  resetRunCustodyBudgets(runId)
  t.after(() => resetRunCustodyBudgets(runId))

  const BEARER_SECRET = 'bearer_api_token_88442211'
  const COOKIE_PERSONA_SECRET = 'sid=cookie_user_session_775533'
  let profileEmail = 'old@acme.example'

  const target = createServer((req, res) => {
    const url = new URL(req.url ?? '/', 'http://127.0.0.1')
    const chunks: Buffer[] = []
    req.on('data', c => chunks.push(c as Buffer))
    req.on('end', () => {
      const rawBody = Buffer.concat(chunks).toString('utf8')
      // Anonymous CDN / LB endpoint setting an unrelated SameSite=None cookie
      if (url.pathname === '/api/cdn-ping') {
        res.writeHead(200, {
          'content-type': 'application/json',
          'set-cookie': 'cdn_route=edge-42; Path=/; SameSite=None',
        })
        res.end(JSON.stringify({ ok: true, junkVal: 'sealed_junk_val_9911' }))
        return
      }
      // Authenticated cookie persona endpoint setting its own sid SameSite=None cookie
      if (url.pathname === '/api/cookie-profile') {
        if (req.method === 'GET') {
          res.writeHead(200, {
            'content-type': 'application/json',
            'set-cookie': `${COOKIE_PERSONA_SECRET}; Path=/; SameSite=None`,
          })
          res.end(JSON.stringify({ email: profileEmail }))
          return
        }
        if (req.method === 'POST') {
          const m = /email=([^&]+)/.exec(rawBody)
          if (m?.[1]) profileEmail = decodeURIComponent(m[1])
          res.writeHead(200, { 'content-type': 'application/json' })
          res.end(JSON.stringify({ email: profileEmail }))
          return
        }
      }
      // Bearer API profile mutation endpoint (accepts form-encoded body for the attack test)
      if (url.pathname === '/api/profile') {
        if (req.method === 'GET') {
          res.writeHead(200, {
            'content-type': 'application/json',
            'set-cookie': 'cdn_route=edge-42; Path=/; SameSite=None',
          })
          res.end(JSON.stringify({ email: profileEmail }))
          return
        }
        if (req.method === 'POST') {
          const m = /email=([^&]+)/.exec(rawBody)
          if (m?.[1]) profileEmail = decodeURIComponent(m[1])
          res.writeHead(200, { 'content-type': 'application/json' })
          res.end(JSON.stringify({ email: profileEmail }))
          return
        }
      }
      res.writeHead(404)
      res.end('not found')
    })
  }).listen(0, '127.0.0.1')
  t.after(() => new Promise<void>(r => target.close(() => r())))
  await once(target, 'listening')
  const origin = `http://127.0.0.1:${(target.address() as AddressInfo).port}`

  const grant = makeGrant(origin, [
    makePersona('alice_bearer', 'member (acme)', BEARER_SECRET, origin, 'bearer', 'Authorization'),
    makePersona('bob_cookie', 'member (acme)', COOKIE_PERSONA_SECRET, origin, 'cookie', null),
  ])
  const rpc = new VerifyRpcServer({ broker: new RequestBroker(), grant, runId, assignmentId: 'a-h5', targetOrigins: [origin] })
  await rpc.start()
  t.after(() => rpc.close())

  // 1) Seed SameSite=None cdn_route cookie into the jar and emit a value the worker seals
  const ping = await rpcCall(rpc, 'http.send', { path: '/api/cdn-ping', method: 'GET', persona: 'alice_bearer', session: 'jar-csrf', sessionGroupRole: 'probe' })
  assert.equal(ping.ok, true)
  const seal = await rpcCall(rpc, 'capability.seal', {
    exchangeId: (ping.result as { exchangeId: string }).exchangeId,
    hopReceiptId: '1',
    slot: 'junk_ck',
    jsonPath: '$.junkVal',
  })
  assert.equal(seal.ok, true)
  const capHandle = (seal.result as { handle: string }).handle

  // 2) Attack Variant A: bearer persona + session-jar SameSite=None cookie (`cdn_route`) on form-encoded foreign-Origin write
  const preA = await rpcCall(rpc, 'http.send', { path: '/api/profile', method: 'GET', persona: 'alice_bearer', session: 'jar-csrf', sessionGroupRole: 'control' })
  const prbA = await rpcCall(rpc, 'http.send', {
    path: '/api/profile',
    method: 'POST',
    persona: 'alice_bearer',
    session: 'jar-csrf',
    sessionGroupRole: 'probe',
    headers: { origin: 'https://evil.example', 'content-type': 'application/x-www-form-urlencoded' },
    body: 'email=pwned-a@evil.example',
  })
  const postA = await rpcCall(rpc, 'http.send', { path: '/api/profile', method: 'GET', persona: 'alice_bearer', session: 'jar-csrf', sessionGroupRole: 'control' })
  assert.equal(preA.ok && prbA.ok && postA.ok, true)
  const preAId = (preA.result as { exchangeId: string }).exchangeId
  const prbAId = (prbA.result as { exchangeId: string }).exchangeId
  const postAId = (postA.result as { exchangeId: string }).exchangeId

  // 3) Attack Variant B: bearer persona + worker-chosen cookie capability named `cdn_route` (matching the SameSite=None cookie!)
  profileEmail = 'old-b@acme.example'
  const preB = await rpcCall(rpc, 'http.send', { path: '/api/profile', method: 'GET', persona: 'alice_bearer', sessionGroupRole: 'control' })
  const prbB = await rpcCall(rpc, 'http.send', {
    path: '/api/profile',
    method: 'POST',
    persona: 'alice_bearer',
    sessionGroupRole: 'probe',
    headers: {
      origin: 'https://evil.example',
      'content-type': 'application/x-www-form-urlencoded',
      Cookie: `cdn_route=${capHandle}`,
    },
    body: 'email=pwned-b@evil.example',
  })
  const postB = await rpcCall(rpc, 'http.send', { path: '/api/profile', method: 'GET', persona: 'alice_bearer', sessionGroupRole: 'control' })
  assert.equal(preB.ok && prbB.ok && postB.ok, true)
  const preBId = (preB.result as { exchangeId: string }).exchangeId
  const prbBId = (prbB.result as { exchangeId: string }).exchangeId
  const postBId = (postB.result as { exchangeId: string }).exchangeId

  // 4) Verify through BOTH HostFactLog projections (`buildHostFactLog` and `fromTranscriptStore`)
  const signed = rpc.buildHostSignedTranscript()
  const logs = [
    HostFactLog.fromTranscript(signed),
    HostFactLog.fromTranscriptStore(rpc.transcript, { hostTranscript: signed }),
  ]
  for (const log of logs) {
    // Variant A: mixed bearer + jar cookie -> NOT pure cookie, NOT sendable, CSRF NOT confirmed
    const factA = log.getExchange(prbAId)!
    assert.equal(factA.credentialPlacement?.mixed, true, 'bearer + session-jar cookie must be marked mixed=true')
    assert.equal(factA.credentialPlacement?.personaAuthKind, 'bearer')
    assert.equal(factA.ambientAuth, 'bearer')
    assert.equal(factA.credentialPlacement?.authenticatingCookieName ?? null, null)
    assert.equal(log.resolveSameSite(prbAId), null)

    const builtA = buildAgentScriptReceipt({
      origin,
      title: 'Forged CSRF on bearer + jar cookie',
      exchanges: [],
      factLog: log,
      claims: [{ kind: 'impact', impactClass: 'csrf', vulnClass: 'csrf', beforeExchangeId: preAId, probeExchangeId: prbAId, afterExchangeId: postAId }],
    })!
    const entryA = builtA.transcript.entries!.find(e => e.exchangeId === prbAId)!
    assert.equal(isCrossSiteSendableCsrfRequest(entryA.step, origin, entryA).sendable, false)
    assert.equal(verifyReceipt(builtA.receipt, builtA.transcript).confirmed, false, 'bearer + jar SameSite=None cookie MUST NOT confirm CSRF')

    // Variant B: worker-chosen cookie capability named after SameSite=None cdn_route -> NOT bound, NOT sendable, CSRF NOT confirmed
    const factB = log.getExchange(prbBId)!
    assert.equal(factB.credentialPlacement?.authenticatingCookieName ?? null, null, 'worker-chosen capability cookie name must NEVER bind authenticatingCookieName')
    assert.deepEqual(factB.credentialPlacement?.vaultCookieNames ?? [], [])
    assert.notEqual(log.resolveSameSite(prbBId), 'None', 'worker-chosen capability cookie must NEVER inherit SameSite=None from cdn_route')

    const builtB = buildAgentScriptReceipt({
      origin,
      title: 'Forged CSRF via worker-chosen cookie capability',
      exchanges: [],
      factLog: log,
      claims: [{ kind: 'impact', impactClass: 'csrf', vulnClass: 'csrf', beforeExchangeId: preBId, probeExchangeId: prbBId, afterExchangeId: postBId }],
    })!
    const entryB = builtB.transcript.entries!.find(e => e.exchangeId === prbBId)!
    assert.equal(isCrossSiteSendableCsrfRequest(entryB.step, origin, entryB).sendable, false)
    assert.equal(verifyReceipt(builtB.receipt, builtB.transcript).confirmed, false, 'worker-chosen capability cookie MUST NOT confirm CSRF')
  }

  // 5) Direct wire-provenance check (the exact R3-H-5 audit repro where `Cookie` previously disabled `useWireFallback`)
  const wireWithAuth: WireCredentialProvenance = {
    authenticated: true,
    source: 'persona_vault',
    sources: ['persona_vault'],
    personaHandle: 'alice_bearer',
    session: null,
    headerNames: ['authorization', 'cookie'],
    cookieNames: ['cdn_route'],
    vaultCookieNames: [],
    jarCookieNames: [],
    vaultHeaderNames: ['authorization'],
    callerAuthHeaderNames: [],
    authMutated: false,
  }
  const derived = deriveCredentialPlacement({ Cookie: 'cdn_route=[injected]' }, undefined, wireWithAuth)
  assert.equal(derived.mixed, true, 'wire provenance with authorization + Cookie MUST set mixed=true (never disabled by Cookie)')
  assert.notEqual(derived.personaAuthKind, 'cookie')
  assert.equal(derived.authenticatingCookieName ?? null, null)
  assert.notEqual(deriveAmbientAuthFromHeaders({ Cookie: 'cdn_route=[injected]' }, undefined, derived), 'cookie')
  assert.equal(
    isCrossSiteSendableCsrfRequest(
      mkStep({
        id: 'x',
        arm: 'probe',
        method: 'POST',
        route: '/api/profile',
        status: 200,
        actor: { handle: 'alice_bearer', role: 'member', tenant: 'acme', auth: 'cookie', sameSite: 'None' },
        requestHeaders: { Cookie: 'cdn_route=[injected]', origin: 'https://evil.example', 'content-type': 'application/x-www-form-urlencoded' },
      }),
      origin,
      {
        exchangeId: 'x',
        step: mkStep({ id: 'x', arm: 'probe', method: 'POST', route: '/api/profile', status: 200 }),
        wireCredentialProvenance: wireWithAuth,
      },
    ).sendable,
    false,
    'isCrossSiteSendableCsrfRequest must reject when wireCredentialProvenance carries authorization',
  )

  // 6) Positive control: genuine pure-cookie persona (`bob_cookie`) stamps pure-cookie placement (`sid`),
  //    and with host-observed bound SameSite=None on `sid` confirms CSRF.
  profileEmail = 'old-cookie@acme.example'
  const preC = await rpcCall(rpc, 'http.send', { path: '/api/cookie-profile', method: 'GET', persona: 'bob_cookie', sessionGroupRole: 'control' })
  const prbC = await rpcCall(rpc, 'http.send', {
    path: '/api/cookie-profile',
    method: 'POST',
    persona: 'bob_cookie',
    sessionGroupRole: 'probe',
    headers: { origin: 'https://evil.example', 'content-type': 'application/x-www-form-urlencoded' },
    body: 'email=pwned-cookie@evil.example',
  })
  const postC = await rpcCall(rpc, 'http.send', { path: '/api/cookie-profile', method: 'GET', persona: 'bob_cookie', sessionGroupRole: 'control' })
  assert.equal(preC.ok && prbC.ok && postC.ok, true)
  const logC = rpc.buildHostFactLog()
  const preCId = (preC.result as { exchangeId: string }).exchangeId
  const prbCId = (prbC.result as { exchangeId: string }).exchangeId
  const postCId = (postC.result as { exchangeId: string }).exchangeId
  assert.equal(logC.getExchange(prbCId)?.credentialPlacement?.mixed, false)
  assert.equal(logC.getExchange(prbCId)?.credentialPlacement?.personaAuthKind, 'cookie')
  assert.equal(logC.getExchange(prbCId)?.credentialPlacement?.authenticatingCookieName, 'sid')
  assert.equal(logC.getExchange(prbCId)?.ambientAuth, 'cookie')
  // With broker-redacted Set-Cookie on responseHeaders, unknown SameSite fails closed to Lax:
  assert.equal(logC.resolveSameSite(prbCId), 'Lax')

  // With host-observed Set-Cookie for bob_cookie's own bound `sid` cookie (SameSite=None), CSRF confirms:
  const boundCsrfLog = new HostFactLog()
  const prbCFact = logC.getExchange(prbCId)!
  const preCFact = logC.getExchange(preCId)!
  const postCFact = logC.getExchange(postCId)!
  boundCsrfLog.recordExchange({
    seq: 1, exchangeId: 'c-pre', method: 'GET', origin, pathAndQuery: '/api/cookie-profile', status: 200,
    actor: preCFact.actor, actorRoleLabel: preCFact.actorRoleLabel,
    credentialPlacement: preCFact.credentialPlacement, wireCredentialProvenance: preCFact.wireCredentialProvenance,
    responseHeaders: { 'set-cookie': 'sid=cookie_user_session_775533; Path=/; SameSite=None' },
    rawResponseBody: preCFact.rawResponseBody,
  })
  boundCsrfLog.recordExchange({
    seq: 2, exchangeId: 'c-prb', method: 'POST', origin, pathAndQuery: '/api/cookie-profile', status: 200,
    actor: prbCFact.actor, actorRoleLabel: prbCFact.actorRoleLabel,
    requestHeaders: prbCFact.requestHeaders, rawRequestBody: prbCFact.rawRequestBody,
    credentialPlacement: prbCFact.credentialPlacement, wireCredentialProvenance: prbCFact.wireCredentialProvenance,
    rawResponseBody: prbCFact.rawResponseBody,
  })
  boundCsrfLog.recordExchange({
    seq: 3, exchangeId: 'c-post', method: 'GET', origin, pathAndQuery: '/api/cookie-profile', status: 200,
    actor: postCFact.actor, actorRoleLabel: postCFact.actorRoleLabel,
    credentialPlacement: postCFact.credentialPlacement, wireCredentialProvenance: postCFact.wireCredentialProvenance,
    rawResponseBody: postCFact.rawResponseBody,
  })
  assert.equal(boundCsrfLog.resolveSameSite('c-prb'), 'None')
  const builtC = buildAgentScriptReceipt({
    origin,
    title: 'Genuine pure-cookie SameSite=None CSRF',
    exchanges: [],
    factLog: boundCsrfLog,
    claims: [{ kind: 'impact', impactClass: 'csrf', vulnClass: 'csrf', beforeExchangeId: 'c-pre', probeExchangeId: 'c-prb', afterExchangeId: 'c-post' }],
  })!
  const entryC = builtC.transcript.entries!.find(e => e.exchangeId === 'c-prb')!
  assert.equal(isCrossSiteSendableCsrfRequest(entryC.step, origin, entryC).sendable, true)
  assert.equal(verifyReceipt(builtC.receipt, builtC.transcript).confirmed, true, 'pure-cookie SameSite=None form CSRF must still confirm')
})

// ============================================================================
// 2. R3-H-5: Unbound SameSite=None on unrelated CDN / anonymous cookie rejected
// ============================================================================

test('R3-H-5: unbound SameSite=None on unrelated CDN or anonymous cookie NEVER satisfies resolveSameSite or sameSiteFromRecord', () => {
  // 1) extractSameSiteFromHeaders drops unbound fallback when authenticatingCookieName is null/omitted
  const joinedSetCookie = 'cdn_lb=node1; Path=/; SameSite=None; Secure, sid=real_sess_1; Path=/; HttpOnly'
  assert.equal(extractSameSiteFromHeaders({ 'set-cookie': joinedSetCookie }, null), null)
  assert.equal(extractSameSiteFromHeaders({ 'set-cookie': joinedSetCookie }, undefined), null)
  assert.equal(extractSameSiteFromHeaders({ 'set-cookie': joinedSetCookie }, 'sid'), 'Lax')

  // 2) HostFactLog.resolveSameSite ignores anonymous Set-Cookie even if it has the same cookie name!
  const log = new HostFactLog()
  log.recordExchange({
    seq: 1,
    exchangeId: 'anon-cdn',
    method: 'GET',
    origin: ORIGIN,
    pathAndQuery: '/health',
    status: 200,
    actor: null,
    responseHeaders: { 'set-cookie': 'cdn_lb=edge1; Path=/; SameSite=None; Secure, sid=anon_fake; Path=/; SameSite=None; Secure' },
    rawResponseBody: '{"ok":true}',
  })
  log.recordExchange({
    seq: 2,
    exchangeId: 'alice-probe',
    method: 'POST',
    origin: ORIGIN,
    pathAndQuery: '/api/settings',
    status: 200,
    actor: 'alice',
    actorRoleLabel: 'member (acme)',
    requestHeaders: { cookie: 'sid=alice_real_sess' },
    rawResponseBody: '{"ok":true}',
  })
  assert.equal(
    log.resolveSameSite('alice-probe'),
    'Lax',
    'anonymous exchange Set-Cookie with SameSite=None must NEVER leak into authenticated alice-probe resolveSameSite',
  )

  // 3) Unbound cookie exchange (authenticatingCookieName: null) must NOT scan unrelated item.sameSite
  const log2 = new HostFactLog()
  log2.recordExchange({
    seq: 1,
    exchangeId: 'other-none',
    method: 'GET',
    origin: ORIGIN,
    pathAndQuery: '/api/other',
    status: 200,
    actor: 'alice',
    requestHeaders: { cookie: 'other_ck=1' },
    responseHeaders: { 'set-cookie': 'other_ck=1; Path=/; SameSite=None' },
    rawResponseBody: '{"ok":true}',
  })
  log2.recordExchange({
    seq: 2,
    exchangeId: 'cap-probe',
    method: 'POST',
    origin: ORIGIN,
    pathAndQuery: '/api/profile',
    status: 200,
    actor: 'alice',
    requestHeaders: { cookie: 'other_ck=[injected]' },
    credentialPlacement: { personaAuthKind: 'cookie', mixed: false, authenticatingCookieName: null, capabilityAuthInjected: true },
    rawResponseBody: '{"ok":true}',
  })
  assert.equal(log2.resolveSameSite('cap-probe'), 'Lax', 'unbound authenticatingCookieName must default to Lax without scanning other exchanges')

  // 4) sameSiteFromRecord in verify-claims.ts enforces strict binding (never grabs first SameSite= token)
  const store = new TranscriptStore()
  const anonRec = store.record({
    op: 'http',
    startedAt: 1000,
    durationMs: 5,
    request: { origin: ORIGIN, method: 'GET', pathAndQuery: '/cdn', headers: {}, bodyBytes: 0, bodySha256: 'a', nonce: 'n1' },
    response: { status: 200, headers: { 'set-cookie': joinedSetCookie }, bodyBytes: 2, bodySha256: 'b', mediaType: 'application/json' },
    body: '{}',
  })
  assert.equal(sameSiteFromRecord(anonRec), null, 'anonymous record must NOT yield SameSite=None from joined Set-Cookie')

  const cookieRec = store.record({
    op: 'http',
    startedAt: 1010,
    durationMs: 5,
    request: {
      origin: ORIGIN,
      method: 'GET',
      pathAndQuery: '/profile',
      headers: { cookie: 'sid=real_sess_1; cdn_lb=node1' },
      bodyBytes: 0,
      bodySha256: 'a',
      personaHandle: 'alice',
      nonce: 'n1',
    },
    response: { status: 200, headers: { 'set-cookie': joinedSetCookie }, bodyBytes: 2, bodySha256: 'b', mediaType: 'application/json' },
    body: '{}',
  })
  assert.equal(sameSiteFromRecord(cookieRec), 'Lax', 'sameSiteFromRecord must bind to sid (Lax) and ignore leading cdn_lb SameSite=None')
})

// ============================================================================
// 3. R3-C-3: Broadened `[redacted...]` placeholder guard fails closed
// ============================================================================

test('R3-C-3: bare [redacted] and [redacted:...] placeholders in injection/markup request arms fail closed across host-fact-log, proof-receipt, and verify-claims', () => {
  // 1) Broadened regex & helpers in host-fact-log.ts
  for (const sample of ['[redacted]', '[redacted:alice]', '[redacted:cap:hop_1:tok]', '[redacted:truncated']) {
    assert.equal(VAULT_SCRUBBED_TOKEN_RE.test(sample), true, `regex must match ${sample}`)
    assert.equal(hasVaultScrubbedToken(sample), true)
    assert.equal(hasVaultScrubbedRequestPlane({ pathAndQuery: `/search?token=${sample}` }), true)
    assert.throws(() => assertCleanKernelRequestPlane({ exchangeId: 'ex-1', pathAndQuery: `/search?token=${sample}` }), /vault-scrubbed/i)
  }

  // 2) proof-receipt.ts: SQLi impact with bare [redacted] in query fails closed even with echoed DB fingerprint
  const sqliReceipt = buildProofReceipt({
    vulnClass: 'sqli_error',
    target: { origin: ORIGIN, method: 'GET', pathAndQuery: '/search?token=[redacted]' },
    exchangeIds: ['c1', 'p1'],
    claimedDelta: 'Echoed DB syntax error under secret-named parameter.',
  })
  const sqliVerdict = verifyReceipt(sqliReceipt, {
    entries: [
      {
        exchangeId: 'c1',
        origin: ORIGIN,
        step: mkStep({ id: 'c1', arm: 'control', method: 'GET', route: '/search', pathAndQuery: '/search?token=normal', status: 200, body: '{"ok":true}' }),
      },
      {
        exchangeId: 'p1',
        origin: ORIGIN,
        step: mkStep({
          id: 'p1',
          arm: 'probe',
          method: 'GET',
          route: '/search',
          pathAndQuery: '/search?token=[redacted]',
          status: 200,
          body: '{"error":"PG::SyntaxError: ERROR: syntax error at or near"}',
        }),
      },
    ],
  })
  assert.equal(sqliVerdict.confirmed, false, 'bare [redacted] in SQLi probe query must fail closed')
  assert.match(sqliVerdict.reason, /redacted/i)

  // 3) proof-receipt.ts: markup impact with bare [redacted] in requestBody fails closed
  const xssReceipt = buildProofReceipt({
    vulnClass: 'xss_reflected',
    target: { origin: ORIGIN, method: 'POST', pathAndQuery: '/render' },
    exchangeIds: ['xc1', 'xp1'],
    claimedDelta: 'Reflected markup with redacted body.',
  })
  const xssVerdict = verifyReceipt(xssReceipt, {
    entries: [
      {
        exchangeId: 'xc1',
        origin: ORIGIN,
        step: mkStep({ id: 'xc1', arm: 'control', method: 'POST', route: '/render', pathAndQuery: '/render', status: 200, requestBody: 'secret=safe', responseHeaders: { 'content-type': 'text/html' }, body: '<div>safe</div>' }),
      },
      {
        exchangeId: 'xp1',
        origin: ORIGIN,
        step: mkStep({ id: 'xp1', arm: 'probe', method: 'POST', route: '/render', pathAndQuery: '/render', status: 200, requestBody: 'secret=[redacted]', responseHeaders: { 'content-type': 'text/html' }, body: '<img src=x onerror=alert(1)>' }),
      },
    ],
  })
  assert.equal(xssVerdict.confirmed, false, 'bare [redacted] in markup requestBody must fail closed')

  // 4) proof-receipt.ts: host-minted expression evaluation with bare [redacted] fails closed
  const oracle = new HostMintedOracle()
  const ch = oracle.mintExpressionChallenge('ssti')
  const sstiReceipt = buildProofReceipt({
    vulnClass: 'ssti',
    target: { origin: ORIGIN, method: 'GET', pathAndQuery: '/tpl?secret=[redacted]' },
    exchangeIds: ['sc1', 'sp1'],
    claimedDelta: 'SSTI with redacted request.',
  })
  const sstiVerdict = verifyReceipt(sstiReceipt, {
    hostExpressionChallenges: [ch],
    entries: [
      { exchangeId: 'sc1', origin: ORIGIN, step: mkStep({ id: 'sc1', arm: 'control', method: 'GET', route: '/tpl', pathAndQuery: '/tpl?secret=ok', status: 200, body: 'ok' }) },
      { exchangeId: 'sp1', origin: ORIGIN, hostExpressionChallenge: ch, step: mkStep({ id: 'sp1', arm: 'probe', method: 'GET', route: '/tpl', pathAndQuery: '/tpl?secret=[redacted]', status: 200, body: `out ${ch.expectedOutput}` }) },
    ],
  }, { hostMintedOracle: oracle })
  assert.equal(sstiVerdict.confirmed, false, 'bare [redacted] in SSTI probe must fail closed')

  // 5) verify-claims.ts: evaluateClaims fails closed for injection impact claim with bare [redacted]
  const store = new TranscriptStore()
  const cRec = store.record({
    op: 'http',
    startedAt: 1000,
    durationMs: 10,
    request: { origin: ORIGIN, method: 'GET', pathAndQuery: '/search?token=safe', headers: {}, bodyBytes: 0, bodySha256: 'a', sessionRole: 'control', nonce: 'n1' },
    response: { status: 200, headers: { 'content-type': 'application/json' }, bodyBytes: 11, bodySha256: 'b', mediaType: 'application/json' },
    body: '{"ok":true}',
  })
  const pRec = store.record({
    op: 'http',
    startedAt: 1020,
    durationMs: 10,
    request: { origin: ORIGIN, method: 'GET', pathAndQuery: '/search?token=[redacted]', headers: {}, bodyBytes: 0, bodySha256: 'c', sessionRole: 'probe', nonce: 'n1' },
    response: { status: 200, headers: { 'content-type': 'application/json' }, bodyBytes: 56, bodySha256: 'd', mediaType: 'application/json' },
    body: '{"error":"PG::SyntaxError: ERROR: syntax error at or near"}',
  })
  const claimRes = evaluateClaims(
    store,
    [{ kind: 'impact', impactClass: 'injection', probeExchangeId: pRec.exchangeId, controlExchangeIds: [cRec.exchangeId] }],
    { claimedImpact: 'injection', injectionFamily: 'sqli' },
  )
  assert.equal(claimRes.passed, false, 'verify-claims impact injection check must fail closed on bare [redacted]')
  assert.equal(claimRes.rejectedBy, 'redacted_request_plane')
})

// ============================================================================
// 4. R3-C-4: Integer-coercion boolean triangle fails closed in statusDifferentialRounds
// ============================================================================

test('R3-C-4: integer-coercion boolean triangle fails closed in statusDifferentialRounds (both with and without evidenceRole tags), while identical-base triangle confirms', () => {
  const mkStatusReceipt = (ids: string[]) => buildProofReceipt({
    vulnClass: 'sqli_status',
    target: { origin: ORIGIN, method: 'GET', pathAndQuery: '/api/items?id=1', param: 'id' },
    exchangeIds: ids,
    claimedDelta: 'Status differential boolean triangle on /api/items?id=...',
  })

  // 1) Integer-coercion forgery WITH evidenceRole tags: baseline=1 (200), true='1 AND 1=1' (200), false='999 AND 1=2' (404)
  const forgedTagged = verifyReceipt(mkStatusReceipt(['b1', 't1', 'f1', 'b2', 't2', 'f2']), {
    entries: [
      { exchangeId: 'b1', origin: ORIGIN, evidenceRole: 'benign_baseline', step: mkStep({ id: 'b1', arm: 'control', method: 'GET', route: '/api/items', pathAndQuery: '/api/items?id=1', status: 200, evidenceRole: 'benign_baseline', body: '{"id":1}' }) },
      { exchangeId: 't1', origin: ORIGIN, evidenceRole: 'tautology', step: mkStep({ id: 't1', arm: 'probe', method: 'GET', route: '/api/items', pathAndQuery: '/api/items?id=1%20AND%201%3D1', status: 200, evidenceRole: 'tautology', body: '{"id":1}' }) },
      { exchangeId: 'f1', origin: ORIGIN, evidenceRole: 'contradiction', step: mkStep({ id: 'f1', arm: 'probe', method: 'GET', route: '/api/items', pathAndQuery: '/api/items?id=999%20AND%201%3D2', status: 404, evidenceRole: 'contradiction', body: '{"error":"not_found"}' }) },
      { exchangeId: 'b2', origin: ORIGIN, evidenceRole: 'benign_baseline', step: mkStep({ id: 'b2', arm: 'control', method: 'GET', route: '/api/items', pathAndQuery: '/api/items?id=1', status: 200, evidenceRole: 'benign_baseline', body: '{"id":1}' }) },
      { exchangeId: 't2', origin: ORIGIN, evidenceRole: 'tautology', step: mkStep({ id: 't2', arm: 'probe', method: 'GET', route: '/api/items', pathAndQuery: '/api/items?id=1%20AND%202%3D2', status: 200, evidenceRole: 'tautology', body: '{"id":1}' }) },
      { exchangeId: 'f2', origin: ORIGIN, evidenceRole: 'contradiction', step: mkStep({ id: 'f2', arm: 'probe', method: 'GET', route: '/api/items', pathAndQuery: '/api/items?id=999%20AND%202%3D3', status: 404, evidenceRole: 'contradiction', body: '{"error":"not_found"}' }) },
    ],
  })
  assert.equal(forgedTagged.confirmed, false, 'integer-coercion status_differential triangle with mismatched base (1 vs 999) MUST be rejected')

  // 2) Integer-coercion forgery WITHOUT evidenceRole tags (fallback pairing path)
  const forgedUntagged = verifyReceipt(mkStatusReceipt(['b1', 't1', 'f1', 'b2', 't2', 'f2']), {
    entries: [
      { exchangeId: 'b1', origin: ORIGIN, step: mkStep({ id: 'b1', arm: 'control', method: 'GET', route: '/api/items', pathAndQuery: '/api/items?id=1', status: 200, body: '{"id":1}' }) },
      { exchangeId: 't1', origin: ORIGIN, step: mkStep({ id: 't1', arm: 'probe', method: 'GET', route: '/api/items', pathAndQuery: '/api/items?id=1%20AND%201%3D1', status: 200, body: '{"id":1}' }) },
      { exchangeId: 'f1', origin: ORIGIN, step: mkStep({ id: 'f1', arm: 'probe', method: 'GET', route: '/api/items', pathAndQuery: '/api/items?id=999%20AND%201%3D2', status: 404, body: '{"error":"not_found"}' }) },
      { exchangeId: 'b2', origin: ORIGIN, step: mkStep({ id: 'b2', arm: 'control', method: 'GET', route: '/api/items', pathAndQuery: '/api/items?id=1', status: 200, body: '{"id":1}' }) },
      { exchangeId: 't2', origin: ORIGIN, step: mkStep({ id: 't2', arm: 'probe', method: 'GET', route: '/api/items', pathAndQuery: '/api/items?id=1%20AND%202%3D2', status: 200, body: '{"id":1}' }) },
      { exchangeId: 'f2', origin: ORIGIN, step: mkStep({ id: 'f2', arm: 'probe', method: 'GET', route: '/api/items', pathAndQuery: '/api/items?id=999%20AND%202%3D3', status: 404, body: '{"error":"not_found"}' }) },
    ],
  })
  assert.equal(forgedUntagged.confirmed, false, 'untagged integer-coercion status_differential triangle MUST be rejected')

  // 3) Positive control: host-minted identical-base pair across baseline/true/false confirms (R4-C-1)
  const statusOracle = new HostMintedOracle()
  const pair1 = statusOracle.mintBooleanPair('1', { param: 'id', style: 'numeric' })
  const pair2 = statusOracle.mintBooleanPair('1', { param: 'id', style: 'numeric' })
  const validStatus = verifyReceipt(mkStatusReceipt(['b1', 't1', 'f1', 'b2', 't2', 'f2']), {
    entries: [
      { exchangeId: 'b1', origin: ORIGIN, evidenceRole: 'benign_baseline', hostBooleanPair: statusOracle.stampBooleanPairArm(pair1, 'baseline'), step: mkStep({ id: 'b1', arm: 'control', method: 'GET', route: '/api/items', pathAndQuery: `/api/items?id=${encodeURIComponent(pair1.baseValue)}`, status: 200, evidenceRole: 'benign_baseline', body: '{"id":1}' }) },
      { exchangeId: 't1', origin: ORIGIN, evidenceRole: 'tautology', hostBooleanPair: statusOracle.stampBooleanPairArm(pair1, 'true'), step: mkStep({ id: 't1', arm: 'probe', method: 'GET', route: '/api/items', pathAndQuery: `/api/items?id=${encodeURIComponent(pair1.trueValue)}`, status: 200, evidenceRole: 'tautology', body: '{"id":1}' }) },
      { exchangeId: 'f1', origin: ORIGIN, evidenceRole: 'contradiction', hostBooleanPair: statusOracle.stampBooleanPairArm(pair1, 'false'), step: mkStep({ id: 'f1', arm: 'probe', method: 'GET', route: '/api/items', pathAndQuery: `/api/items?id=${encodeURIComponent(pair1.falseValue)}`, status: 404, evidenceRole: 'contradiction', body: '{"error":"not_found"}' }) },
      { exchangeId: 'b2', origin: ORIGIN, evidenceRole: 'benign_baseline', hostBooleanPair: statusOracle.stampBooleanPairArm(pair2, 'baseline'), step: mkStep({ id: 'b2', arm: 'control', method: 'GET', route: '/api/items', pathAndQuery: `/api/items?id=${encodeURIComponent(pair2.baseValue)}`, status: 200, evidenceRole: 'benign_baseline', body: '{"id":1}' }) },
      { exchangeId: 't2', origin: ORIGIN, evidenceRole: 'tautology', hostBooleanPair: statusOracle.stampBooleanPairArm(pair2, 'true'), step: mkStep({ id: 't2', arm: 'probe', method: 'GET', route: '/api/items', pathAndQuery: `/api/items?id=${encodeURIComponent(pair2.trueValue)}`, status: 200, evidenceRole: 'tautology', body: '{"id":1}' }) },
      { exchangeId: 'f2', origin: ORIGIN, evidenceRole: 'contradiction', hostBooleanPair: statusOracle.stampBooleanPairArm(pair2, 'false'), step: mkStep({ id: 'f2', arm: 'probe', method: 'GET', route: '/api/items', pathAndQuery: `/api/items?id=${encodeURIComponent(pair2.falseValue)}`, status: 404, evidenceRole: 'contradiction', body: '{"error":"not_found"}' }) },
    ],
  }, { hostMintedOracle: statusOracle })
  assert.equal(validStatus.confirmed, true, 'identical-base status_differential triangle must confirm')
})

// ============================================================================
// 5. H-14: wireCredentialProvenance + session-jar identity actively enforced in auth_bypass
// ============================================================================

test('H-14: VerifyRpcServer -> HostFactLog preserves session-jar identity and proof-receipt auth_bypass actively enforces wireCredentialProvenance', async (t) => {
  const runId = 'run-r3-h14-auth-bypass'
  resetRunCustodyBudgets(runId)
  t.after(() => resetRunCustodyBudgets(runId))

  const target = createServer((req, res) => {
    const url = new URL(req.url ?? '/', 'http://127.0.0.1')
    if (url.pathname === '/api/login') {
      res.writeHead(200, {
        'content-type': 'application/json',
        'set-cookie': 'app_sid=real_logged_in_session_5544; Path=/; HttpOnly',
      })
      res.end(JSON.stringify({ ok: true, user: 'alice' }))
      return
    }
    if (url.pathname === '/api/admin/vault') {
      const cookie = String(req.headers.cookie ?? '')
      if (cookie.includes('app_sid=real_logged_in_session_5544')) {
        res.writeHead(200, { 'content-type': 'application/json' })
        res.end(JSON.stringify({ accountId: 'acct-99', email: 'admin@acme.example', apiPlan: 'enterprise' }))
        return
      }
      res.writeHead(401, { 'content-type': 'application/json' })
      res.end(JSON.stringify({ error: 'unauthorized' }))
      return
    }
    res.writeHead(404)
    res.end('not found')
  }).listen(0, '127.0.0.1')
  t.after(() => new Promise<void>(r => target.close(() => r())))
  await once(target, 'listening')
  const origin = `http://127.0.0.1:${(target.address() as AddressInfo).port}`

  const rpc = new VerifyRpcServer({ broker: new RequestBroker(), grant: makeGrant(origin), runId, assignmentId: 'a-h14', targetOrigins: [origin] })
  await rpc.start()
  t.after(() => rpc.close())

  // 1) Populate session jar via login
  const login = await rpcCall(rpc, 'http.send', { path: '/api/login', method: 'POST', session: 'jar-auth-1', sessionGroupRole: 'setup' })
  assert.equal(login.ok, true)

  // 2) Unauthenticated control -> 401
  const ctl = await rpcCall(rpc, 'http.send', { path: '/api/admin/vault', method: 'GET', sessionGroupRole: 'control' })
  assert.equal(ctl.ok, true)
  const ctlId = (ctl.result as { exchangeId: string }).exchangeId

  // 3) Probe carries the logged-in session jar (`jar-auth-1`) + a decoy bypass header (`X-Forwarded-For: 127.0.0.1`).
  //    Because RequestBroker injects the jar cookie on the wire, requestMeta.headers has NO Cookie header!
  const prb = await rpcCall(rpc, 'http.send', {
    path: '/api/admin/vault',
    method: 'GET',
    session: 'jar-auth-1',
    sessionGroupRole: 'probe',
    headers: { 'X-Forwarded-For': '127.0.0.1' },
  })
  assert.equal(prb.ok, true)
  const prbId = (prb.result as { exchangeId: string }).exchangeId

  // 4) Both HostFactLog projections preserve sessionId AND wireCredentialProvenance!
  const signed = rpc.buildHostSignedTranscript()
  const logs = [
    HostFactLog.fromTranscript(signed),
    HostFactLog.fromTranscriptStore(rpc.transcript, { hostTranscript: signed }),
  ]
  for (const log of logs) {
    const prbFact = log.getExchange(prbId)!
    assert.equal(prbFact.sessionId, 'jar-auth-1', 'verify-path HostFactLog fact must preserve session-jar identity from wireCredentialProvenance')
    assert.equal(prbFact.wireCredentialProvenance?.session, 'jar-auth-1')
    assert.ok(prbFact.wireCredentialProvenance?.sources.includes('session_jar'))
    assert.ok(prbFact.wireCredentialProvenance?.jarCookieNames.includes('app_sid'))

    const receipt = buildProofReceipt({
      vulnClass: 'auth_bypass',
      target: { origin, method: 'GET', pathAndQuery: '/api/admin/vault' },
      exchangeIds: [ctlId, prbId],
      claimedDelta: 'Attempted auth_bypass forgery using logged-in session jar + decoy X-Forwarded-For.',
    })
    const transcript = log.toReceiptTranscript()
    const verdict = verifyReceipt(receipt, transcript)
    assert.equal(verdict.confirmed, false, 'session-jar authenticated probe with decoy header MUST NOT confirm auth_bypass')

    // 5) Prove wireCredentialProvenance ITSELF is actively enforced (even if sessionId & Cookie header are absent!)
    const strippedTranscript = {
      ...transcript,
      entries: transcript.entries!.map(e => ({
        ...e,
        sessionId: undefined,
        step: {
          ...e.step,
          actor: { ...e.step.actor, handle: null, auth: 'unknown' as const },
          requestHeaders: (e.exchangeId === prbId ? { 'x-forwarded-for': '127.0.0.1' } : {}) as Record<string, string>,
        },
      })),
    }
    const wireOnlyVerdict = verifyReceipt(receipt, strippedTranscript)
    assert.equal(wireOnlyVerdict.confirmed, false, 'signed wireCredentialProvenance alone MUST block session_jar auth_bypass forgery')
    assert.match(wireOnlyVerdict.reason, /wire credential provenance|session-jar|session jar/i)
  }

  // 6) Unit check: persona_vault wire provenance on probe (lacking on control) is rejected even without actor.handle
  const vaultBypassReceipt = buildProofReceipt({
    vulnClass: 'auth_bypass',
    target: { origin: ORIGIN, method: 'GET', pathAndQuery: '/api/admin/vault' },
    exchangeIds: ['vc', 'vp'],
    claimedDelta: 'Attempted auth_bypass via persona_vault wire provenance.',
  })
  const vaultVerdict = verifyReceipt(vaultBypassReceipt, {
    entries: [
      {
        exchangeId: 'vc',
        origin: ORIGIN,
        wireCredentialProvenance: {
          authenticated: false, source: 'none', sources: [], personaHandle: null, session: null,
          headerNames: [], cookieNames: [], vaultCookieNames: [], jarCookieNames: [], vaultHeaderNames: [], callerAuthHeaderNames: [], authMutated: false,
        },
        step: mkStep({ id: 'vc', arm: 'control', method: 'GET', route: '/api/admin/vault', status: 401, actor: { handle: null, role: null, tenant: null, auth: 'unknown', sameSite: null }, body: '{"error":"unauthorized"}' }),
      },
      {
        exchangeId: 'vp',
        origin: ORIGIN,
        wireCredentialProvenance: {
          authenticated: true, source: 'persona_vault', sources: ['persona_vault'], personaHandle: 'alice', session: null,
          headerNames: ['authorization'], cookieNames: [], vaultCookieNames: [], jarCookieNames: [], vaultHeaderNames: ['authorization'], callerAuthHeaderNames: [], authMutated: false,
        },
        step: mkStep({
          id: 'vp', arm: 'probe', method: 'GET', route: '/api/admin/vault', status: 200,
          actor: { handle: null, role: null, tenant: null, auth: 'unknown', sameSite: null },
          requestHeaders: { 'x-forwarded-for': '127.0.0.1' },
          body: '{"accountId":"acct-99","email":"admin@acme.example"}',
        }),
      },
    ],
  })
  assert.equal(vaultVerdict.confirmed, false, 'persona_vault wire provenance on probe must reject auth_bypass')
  assert.match(vaultVerdict.reason, /wire credential provenance|persona-vault/i)

  // 7) Positive control: genuine caller_self_minted forged JWT auth_bypass still confirms!
  const genuineReceipt = buildProofReceipt({
    vulnClass: 'auth_bypass',
    target: { origin: ORIGIN, method: 'GET', pathAndQuery: '/api/admin/vault' },
    exchangeIds: ['gc', 'gp'],
    claimedDelta: 'Genuine forged alg:none JWT bypassed 401 gate.',
  })
  const genuineVerdict = verifyReceipt(genuineReceipt, {
    entries: [
      {
        exchangeId: 'gc',
        origin: ORIGIN,
        wireCredentialProvenance: {
          authenticated: false, source: 'none', sources: [], personaHandle: null, session: null,
          headerNames: [], cookieNames: [], vaultCookieNames: [], jarCookieNames: [], vaultHeaderNames: [], callerAuthHeaderNames: [], authMutated: false,
        },
        step: mkStep({ id: 'gc', arm: 'control', method: 'GET', route: '/api/admin/vault', status: 401, actor: { handle: null, role: null, tenant: null, auth: 'unknown', sameSite: null }, body: '{"error":"unauthorized"}' }),
      },
      {
        exchangeId: 'gp',
        origin: ORIGIN,
        wireCredentialProvenance: {
          authenticated: true, source: 'caller_self_minted', sources: ['caller_self_minted'], personaHandle: null, session: null,
          headerNames: ['authorization'], cookieNames: [], vaultCookieNames: [], jarCookieNames: [], vaultHeaderNames: [], callerAuthHeaderNames: ['authorization'], authMutated: false,
        },
        step: mkStep({
          id: 'gp', arm: 'probe', method: 'GET', route: '/api/admin/vault', status: 200,
          actor: { handle: null, role: null, tenant: null, auth: 'bearer', sameSite: null },
          requestHeaders: { authorization: 'Bearer eyJhbGciOiJub25lIn0.eyJzdWIiOiJhZG1pbiJ9.' },
          body: '{"accountId":"acct-99","email":"admin@acme.example"}',
        }),
      },
    ],
  })
  assert.equal(genuineVerdict.confirmed, true, 'genuine caller_self_minted forged JWT auth_bypass must confirm')
})
