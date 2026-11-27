import assert from 'node:assert/strict'
import { randomUUID } from 'node:crypto'
import { createServer as createH2Server } from 'node:http2'
import type { IncomingHttpHeaders as H2IncomingHeaders, ServerHttp2Session, ServerHttp2Stream } from 'node:http2'
import { mkdtempSync, readFileSync, rmSync } from 'node:fs'
import type { AddressInfo } from 'node:net'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { test } from 'node:test'
import { RequestBroker } from '../src/server/broker.ts'
import type { Grant, PublicAddress, RawHttpResponse } from '../src/server/broker.ts'
import { PersonaAuthManager } from '../src/server/persona-auth.ts'
import { buildPersonaHeader, createProjectPersona, resolveRunPersonas } from '../src/server/persona-vault.ts'
import type { ResolvedPersona } from '../src/server/persona-vault.ts'
import { Store } from '../src/server/store.ts'

const targetOrigin = 'https://app.iso-ctrl.example'
const publicAddr: PublicAddress = { address: '93.184.216.34', family: 4 }

function makeGrant(personas: ReadonlyMap<string, ResolvedPersona>, overrides: Partial<Grant> = {}): Grant {
  return {
    origin: targetOrigin,
    tier: 2,
    maxRpsPerOrigin: 50,
    personas,
    canRead: origin => origin === targetOrigin,
    isStateChangeApproved: () => true,
    audit: () => undefined,
    ...overrides,
  }
}

function createLoginFixture(t: { after: (fn: () => void) => void }) {
  const dir = mkdtempSync(join(tmpdir(), 'kovo-m2-ctrl-iso-'))
  t.after(() => rmSync(dir, { recursive: true, force: true }))
  const storage = new Store(dir)
  t.after(() => storage.close())

  const { id: projectId } = storage.createProject({
    requestId: randomUUID(),
    name: 'Control Session Isolation Project',
    seeds: [targetOrigin],
    environment: 'public',
  })

  const loginPersona = createProjectPersona(storage, {
    requestId: randomUUID(),
    projectId,
    handle: 'member_b',
    roleLabel: 'Member B',
    originAllowlist: [targetOrigin],
    authKind: 'login',
    loginConfig: {
      adapter: 'json',
      loginUrl: `${targetOrigin}/api/auth/login`,
      email: 'member_b@iso-ctrl.example',
    },
    secret: 'MemberBLoginPass!2026',
    canaryMarkers: [],
  })

  const staticBearer = createProjectPersona(storage, {
    requestId: randomUUID(),
    projectId,
    handle: 'static_viewer',
    roleLabel: 'Static Viewer',
    originAllowlist: [targetOrigin],
    authKind: 'bearer',
    secret: 'static_bearer_secret_token_00112233',
    canaryMarkers: [],
  })

  const staticHeader = createProjectPersona(storage, {
    requestId: randomUUID(),
    projectId,
    handle: 'static_api',
    roleLabel: 'Static API Key',
    originAllowlist: [targetOrigin],
    authKind: 'header',
    headerName: 'X-Api-Key',
    secret: 'static_api_key_secret_44556677',
    canaryMarkers: [],
  })

  let loginCounter = 0
  const mintedTokens: string[] = []
  const mockFetch: typeof fetch = async (input, init) => {
    const url = typeof input === 'string' ? input : input instanceof URL ? input.toString() : input.url
    if (url === `${targetOrigin}/api/auth/login` && (init?.method ?? 'GET').toUpperCase() === 'POST') {
      loginCounter += 1
      const token = `tok_minted_seq_${loginCounter}_abcdef123456`
      mintedTokens.push(token)
      return new Response(JSON.stringify({ access_token: token }), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      })
    }
    return new Response('not found', { status: 404 })
  }

  const authManager = new PersonaAuthManager({ fetchImpl: mockFetch })
  t.after(() => authManager.stopAll())

  const createTestRun = (approvedPersonaIds: string[]): string =>
    storage.createRun({
      requestId: randomUUID(),
      projectId,
      goal: 'Verify control session isolation',
      sourceMode: 'public',
      capabilityTier: 2,
      approvedPersonaIds,
      budgetUsd: 10,
      budgetRequests: 0,
      maxRpsPerOrigin: 20,
      workerConcurrency: 2,
      workerMaxTurns: 10,
    }).id

  return {
    storage,
    projectId,
    loginPersona,
    staticBearer,
    staticHeader,
    authManager,
    createTestRun,
    getLoginCount: () => loginCounter,
    mintedTokens,
  }
}

test('PersonaAuthManager.mintIsolatedPersonaSession mints fresh non-persisted token without mutating sessionPool or .session file and returns null for static personas', async t => {
  const { storage, projectId, loginPersona, staticBearer, staticHeader, authManager, createTestRun, getLoginCount } = createLoginFixture(t)
  const runId = createTestRun([loginPersona.id, staticBearer.id, staticHeader.id])

  await authManager.startRunRefreshers(storage, runId, projectId, [loginPersona.id, staticBearer.id, staticHeader.id])
  assert.equal(getLoginCount(), 1)

  const resolvedBefore = resolveRunPersonas(storage, projectId, [loginPersona.id, staticBearer.id, staticHeader.id])
  const grantMember = resolvedBefore.get('member_b')!
  assert.ok(grantMember.sessionPath)
  const diskBefore = readFileSync(grantMember.sessionPath, 'utf8')
  const sharedHeaderBefore = buildPersonaHeader(grantMember, targetOrigin)
  assert.equal(sharedHeaderBefore?.Authorization, 'Bearer tok_minted_seq_1_abcdef123456')
  assert.equal(authManager.sessions.session('member_b', runId)?.value, 'tok_minted_seq_1_abcdef123456')

  // Mint isolated session: must execute login flow and return a distinct token without touching disk or sessionPool.
  const isolated = await authManager.mintIsolatedPersonaSession('member_b', runId, { origin: targetOrigin })
  assert.equal(getLoginCount(), 2)
  assert.ok(isolated)
  assert.equal(isolated.headers.Authorization, 'Bearer tok_minted_seq_2_abcdef123456')
  assert.notEqual(isolated.headers.Authorization, sharedHeaderBefore?.Authorization)

  // Shared disk session file, sessionPool, and grant persona header are completely untouched.
  assert.equal(readFileSync(grantMember.sessionPath, 'utf8'), diskBefore)
  assert.equal(authManager.sessions.session('member_b', runId)?.value, 'tok_minted_seq_1_abcdef123456')
  assert.deepEqual(buildPersonaHeader(grantMember, targetOrigin), sharedHeaderBefore)

  // Static non-login personas return null cleanly without making any login HTTP calls.
  assert.equal(await authManager.mintIsolatedPersonaSession('static_viewer', runId, { storage, origin: targetOrigin }), null)
  assert.equal(await authManager.mintIsolatedPersonaSession('static_api', runId, { storage, origin: targetOrigin }), null)
  assert.equal(await authManager.mintIsolatedPersonaSession('unknown_actor', runId, { storage, origin: targetOrigin }), null)
  assert.equal(getLoginCount(), 2)
})

test('RequestBroker H1 isolates control sessions from polluted shared tokens, caches per (runId, sessionKey, personaHandle), preserves persona_vault provenance, and redacts isolated secrets', async t => {
  const { storage, projectId, loginPersona, staticBearer, authManager, createTestRun, getLoginCount } = createLoginFixture(t)
  const runId = createTestRun([loginPersona.id, staticBearer.id])

  await authManager.startRunRefreshers(storage, runId, projectId, [loginPersona.id, staticBearer.id])
  const personas = resolveRunPersonas(storage, projectId, [loginPersona.id, staticBearer.id])
  const grant = makeGrant(personas, { tier: 3 })

  // Stateful server simulating per-token server-side state (e.g. export lineage / role elevation).
  const elevatedTokens = new Set<string>()
  const wireAuthSeen: Array<{ path: string; auth: string | null }> = []

  const transport = async (
    url: URL,
    _address: PublicAddress,
    _signal: AbortSignal,
    options?: { method?: string; headers?: Record<string, string> },
  ): Promise<RawHttpResponse> => {
    const auth = options?.headers?.Authorization ?? options?.headers?.authorization ?? null
    wireAuthSeen.push({ path: url.pathname, auth })
    const token = auth?.replace(/^Bearer\s+/i, '') ?? ''
    if (url.pathname === '/api/export/elevate' && (options?.method ?? 'GET') === 'POST') {
      if (token) elevatedTokens.add(token)
      return { status: 200, headers: { 'content-type': 'application/json' }, body: JSON.stringify({ elevated: true }) }
    }
    if (url.pathname === '/api/export/download') {
      const allowed = elevatedTokens.has(token)
      return {
        status: allowed ? 200 : 403,
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ allowed, echoedToken: token }),
      }
    }
    return { status: 404, headers: { 'content-type': 'application/json' }, body: '{}' }
  }

  const broker = new RequestBroker({
    resolve: async () => [publicAddr],
    transport,
    mintIsolatedSession: ({ personaHandle, runId: reqRunId, origin }) =>
      authManager.mintIsolatedPersonaSession(personaHandle, reqRunId, { storage, origin }),
  })
  t.after(() => broker.disposeRun(runId))

  // 1. Earlier exploration mutates server-side state on the shared run-wide bearer token.
  const mutateRes = await broker.executeHttp(
    { origin: targetOrigin, method: 'POST', pathAndQuery: '/api/export/elevate', persona: 'member_b', runId, assignmentId: 'assign-1' },
    grant,
    AbortSignal.timeout(5_000),
  )
  assert.equal(mutateRes.status, 200)
  assert.equal(wireAuthSeen.at(-1)?.auth, 'Bearer tok_minted_seq_1_abcdef123456')

  // 2. Shared probe sees 200 because its shared token was polluted in step 1.
  const sharedProbe = await broker.executeHttp(
    { origin: targetOrigin, method: 'GET', pathAndQuery: '/api/export/download', persona: 'member_b', sessionGroupRole: 'probe', runId, assignmentId: 'assign-1' },
    grant,
    AbortSignal.timeout(5_000),
  )
  assert.equal(sharedProbe.status, 200)
  assert.equal(wireAuthSeen.at(-1)?.auth, 'Bearer tok_minted_seq_1_abcdef123456')
  assert.equal(getLoginCount(), 1)

  // 3. Control request MUST receive a freshly minted isolated token -> server returns clean 403!
  const control1 = await broker.executeHttp(
    {
      origin: targetOrigin,
      method: 'GET',
      pathAndQuery: '/api/export/download',
      persona: 'member_b',
      sessionGroupRole: 'control',
      session: 'ctrl-export',
      runId,
      assignmentId: 'assign-1',
    },
    grant,
    AbortSignal.timeout(5_000),
  )
  assert.equal(control1.status, 403, 'Control request must see clean unpolluted server state (403, not 200)')
  assert.equal(wireAuthSeen.at(-1)?.auth, 'Bearer tok_minted_seq_2_abcdef123456')
  assert.equal(getLoginCount(), 2)
  assert.equal(control1.wireCredentialProvenance?.authenticated, true)
  assert.equal(control1.wireCredentialProvenance?.source, 'persona_vault')
  assert.ok(control1.wireCredentialProvenance?.sources.includes('persona_vault'))
  assert.ok(control1.wireCredentialProvenance?.vaultHeaderNames.includes('authorization'))
  assert.equal(control1.wireCredentialProvenance?.personaHandle, 'member_b')
  // Isolated token must be scrubbed from both returned request headers and echoed response body.
  assert.ok(!control1.body.includes('tok_minted_seq_2_abcdef123456'), 'Isolated bearer token must be redacted from response body')
  assert.ok(!String(control1.reqHeaders.authorization ?? '').includes('tok_minted_seq_2_abcdef123456'), 'Isolated bearer token must be redacted from reqHeaders')

  // 4. Repeat control request with identical (runId, assignmentId, session, personaHandle) hits cache (no extra login).
  const control1Repeat = await broker.executeHttp(
    {
      origin: targetOrigin,
      method: 'GET',
      pathAndQuery: '/api/export/download',
      persona: 'member_b',
      sessionGroupRole: 'control',
      session: 'ctrl-export',
      runId,
      assignmentId: 'assign-1',
    },
    grant,
    AbortSignal.timeout(5_000),
  )
  assert.equal(control1Repeat.status, 403)
  assert.equal(wireAuthSeen.at(-1)?.auth, 'Bearer tok_minted_seq_2_abcdef123456')
  assert.equal(getLoginCount(), 2, 'Cached isolated control session must be reused without redundant login')

  // 5. Distinct control session key mints a separate isolated token.
  const control2 = await broker.executeHttp(
    {
      origin: targetOrigin,
      method: 'GET',
      pathAndQuery: '/api/export/download',
      persona: 'member_b',
      sessionGroupRole: 'control',
      session: 'ctrl-other',
      runId,
      assignmentId: 'assign-1',
    },
    grant,
    AbortSignal.timeout(5_000),
  )
  assert.equal(control2.status, 403)
  assert.equal(wireAuthSeen.at(-1)?.auth, 'Bearer tok_minted_seq_3_abcdef123456')
  assert.equal(getLoginCount(), 3)

  // 6. Shared pool token was NEVER overwritten by isolated control mints.
  assert.equal(authManager.sessions.session('member_b', runId)?.value, 'tok_minted_seq_1_abcdef123456')
  const sharedAfter = await broker.executeHttp(
    { origin: targetOrigin, method: 'GET', pathAndQuery: '/api/export/download', persona: 'member_b', runId, assignmentId: 'assign-1' },
    grant,
    AbortSignal.timeout(5_000),
  )
  assert.equal(sharedAfter.status, 200)
  assert.equal(wireAuthSeen.at(-1)?.auth, 'Bearer tok_minted_seq_1_abcdef123456')

  // 7. Static non-login persona falls back gracefully to buildPersonaHeader and retains persona_vault provenance.
  const staticCtrl = await broker.executeHttp(
    {
      origin: targetOrigin,
      method: 'GET',
      pathAndQuery: '/api/export/download',
      persona: 'static_viewer',
      sessionGroupRole: 'control',
      session: 'ctrl-static',
      runId,
      assignmentId: 'assign-1',
    },
    grant,
    AbortSignal.timeout(5_000),
  )
  assert.equal(staticCtrl.status, 403)
  assert.equal(wireAuthSeen.at(-1)?.auth, 'Bearer static_bearer_secret_token_00112233')
  assert.equal(staticCtrl.wireCredentialProvenance?.source, 'persona_vault')
  assert.equal(getLoginCount(), 3)
})

test('Named isolated session deduplicates concurrent mints (single-flight), clears on disposeRun, and supports cookie-backed isolated sessions', async t => {
  const runId = `run-${randomUUID()}`
  const personas = new Map<string, ResolvedPersona>([
    ['viewer_a', {
      id: 'p-viewer',
      handle: 'viewer_a',
      roleLabel: 'Viewer A',
      originAllowlist: [targetOrigin],
      authKind: 'bearer',
      headerName: null,
      secret: 'shared_viewer_secret_00001111',
      canaryMarkers: [],
    }],
  ])
  const grant = makeGrant(personas, { tier: 3 })

  let mintCalls = 0
  const seenHeaders: Array<{ auth?: string; cookie?: string }> = []
  const broker = new RequestBroker({
    resolve: async () => [publicAddr],
    transport: async (_url, _addr, _sig, opts) => {
      seenHeaders.push({ auth: opts?.headers?.Authorization, cookie: opts?.headers?.Cookie })
      return { status: 200, headers: { 'content-type': 'application/json' }, body: '{"ok":true}' }
    },
    mintIsolatedSession: async ({ sessionKey }) => {
      mintCalls += 1
      await new Promise(r => setTimeout(r, 25))
      if (sessionKey.includes('cookie-iso')) {
        return { headers: {} as Record<string, string>, cookies: { sid: `isolated_sid_cookie_${mintCalls}_998877` } }
      }
      return { headers: { Authorization: `Bearer isolated_flight_tok_${mintCalls}_aabbcc` } as Record<string, string> }
    },
  })
  t.after(() => broker.disposeRun(runId))

  // Two concurrent requests sharing one named isolated session trigger only a single mint.
  const [r1, r2] = await Promise.all([
    broker.executeHttp({ origin: targetOrigin, method: 'GET', pathAndQuery: '/api/me', persona: 'viewer_a', session: 'clean-check', runId }, grant, AbortSignal.timeout(5_000)),
    broker.executeHttp({ origin: targetOrigin, method: 'GET', pathAndQuery: '/api/me', persona: 'viewer_a', session: 'clean-check', runId }, grant, AbortSignal.timeout(5_000)),
  ])
  assert.equal(mintCalls, 1)
  assert.equal(r1.wireCredentialProvenance?.source, 'persona_vault')
  assert.equal(r2.wireCredentialProvenance?.source, 'persona_vault')
  assert.equal(seenHeaders[0]?.auth, 'Bearer isolated_flight_tok_1_aabbcc')
  assert.equal(seenHeaders[1]?.auth, 'Bearer isolated_flight_tok_1_aabbcc')

  // Cookie-backed isolated session stamps vaultCookieNames + persona_vault provenance and redacts cookie value.
  const cookieRes = await broker.executeHttp(
    { origin: targetOrigin, method: 'GET', pathAndQuery: '/api/me', persona: 'viewer_a', sessionGroupRole: 'control', session: 'cookie-iso', runId },
    grant,
    AbortSignal.timeout(5_000),
  )
  assert.equal(mintCalls, 2)
  assert.equal(seenHeaders[2]?.cookie, 'sid=isolated_sid_cookie_2_998877')
  assert.equal(cookieRes.wireCredentialProvenance?.source, 'persona_vault')
  assert.ok(cookieRes.wireCredentialProvenance?.vaultCookieNames.includes('sid'))
  assert.ok(!String(cookieRes.reqHeaders.cookie ?? '').includes('isolated_sid_cookie_2_998877'))

  // disposeRun evicts the run's isolated session cache cleanly.
  broker.disposeRun(runId)
  await broker.executeHttp({ origin: targetOrigin, method: 'GET', pathAndQuery: '/api/me', persona: 'viewer_a', session: 'clean-check', runId }, grant, AbortSignal.timeout(5_000))
  assert.equal(mintCalls, 3)
  assert.equal(seenHeaders[3]?.auth, 'Bearer isolated_flight_tok_3_aabbcc')
})

test('401 on an isolated control session re-mints the isolated credential without invoking shared reauth', async t => {
  const runId = `run-${randomUUID()}`
  const personas = new Map<string, ResolvedPersona>([
    ['member_b', {
      id: 'p-member',
      handle: 'member_b',
      roleLabel: 'Member B',
      originAllowlist: [targetOrigin],
      authKind: 'bearer',
      headerName: null,
      secret: 'shared_member_token_11223344',
      canaryMarkers: [],
    }],
  ])
  const grant = makeGrant(personas, { tier: 3 })

  let mintCalls = 0
  let reauthCalls = 0
  const seenAuth: string[] = []
  const broker = new RequestBroker({
    resolve: async () => [publicAddr],
    reauth: async () => {
      reauthCalls += 1
      return true
    },
    mintIsolatedSession: async () => {
      mintCalls += 1
      return { headers: { Authorization: `Bearer iso_retry_tok_${mintCalls}_xyz987` } }
    },
    transport: async (_url, _addr, _sig, opts) => {
      const auth = opts?.headers?.Authorization ?? ''
      seenAuth.push(auth)
      if (auth.includes('iso_retry_tok_1_')) {
        return { status: 401, headers: { 'content-type': 'application/json' }, body: '{"error":"token expired"}' }
      }
      return { status: 200, headers: { 'content-type': 'application/json' }, body: '{"ok":true}' }
    },
  })
  t.after(() => broker.disposeRun(runId))

  const res = await broker.executeHttp(
    { origin: targetOrigin, method: 'GET', pathAndQuery: '/api/me', persona: 'member_b', sessionGroupRole: 'control', session: 'ctrl-expiry', runId },
    grant,
    AbortSignal.timeout(5_000),
  )
  assert.equal(res.status, 200)
  assert.equal(reauthCalls, 0, 'Isolated control 401 must never trigger shared pool reauth')
  assert.equal(mintCalls, 2)
  assert.deepEqual(seenAuth, ['Bearer iso_retry_tok_1_xyz987', 'Bearer iso_retry_tok_2_xyz987'])
  assert.equal(res.wireCredentialProvenance?.source, 'persona_vault')
})

test('RequestBroker.executeHttp2Exchange (H2) isolates control sessions, caches per sessionKey, and preserves persona_vault provenance', async t => {
  const prevLab = process.env.KOVO_ALLOW_LOCAL_LAB
  process.env.KOVO_ALLOW_LOCAL_LAB = '1'
  t.after(() => {
    if (prevLab === undefined) delete process.env.KOVO_ALLOW_LOCAL_LAB
    else process.env.KOVO_ALLOW_LOCAL_LAB = prevLab
  })

  const sessions = new Set<ServerHttp2Session>()
  const seenAuth: string[] = []
  const h2Server = createH2Server()
  h2Server.on('session', s => {
    sessions.add(s)
    s.once('close', () => sessions.delete(s))
  })
  h2Server.on('stream', (stream: ServerHttp2Stream, headers: H2IncomingHeaders) => {
    const auth = typeof headers.authorization === 'string' ? headers.authorization : ''
    seenAuth.push(auth)
    stream.respond({ ':status': 200, 'content-type': 'application/json' })
    stream.end(JSON.stringify({ ok: true, echoed: auth }))
  })
  await new Promise<void>(resolve => h2Server.listen(0, '127.0.0.1', resolve))
  const port = (h2Server.address() as AddressInfo).port
  t.after(async () => {
    for (const s of sessions) s.destroy()
    await new Promise<void>(resolve => h2Server.close(() => resolve()))
  })

  const h2Origin = `http://127.0.0.1:${port}`
  const runId = `run-${randomUUID()}`
  const personas = new Map<string, ResolvedPersona>([
    ['member_b', {
      id: 'p-h2',
      handle: 'member_b',
      roleLabel: 'Member B',
      originAllowlist: [h2Origin],
      authKind: 'bearer',
      headerName: null,
      secret: 'h2_shared_token_0011223344',
      canaryMarkers: [],
    }],
  ])
  const grant = makeGrant(personas, {
    origin: h2Origin,
    allowLocalLab: true,
    canRead: o => o === h2Origin,
  })

  let mintCalls = 0
  const broker = new RequestBroker({
    resolve: async () => [{ address: '127.0.0.1', family: 4 }],
    mintIsolatedSession: async () => {
      mintCalls += 1
      return { headers: { Authorization: `Bearer h2_isolated_token_${mintCalls}_998877` } }
    },
  })
  t.after(() => {
    broker.disposeRun(runId)
    broker.closeTransport()
  })

  // Shared H2 probe uses shared run-wide token.
  const probeH2 = await broker.executeHttp2Exchange(
    { origin: h2Origin, method: 'GET', pathAndQuery: '/v2/export', persona: 'member_b', sessionGroupRole: 'probe', runId },
    grant,
    AbortSignal.timeout(5_000),
  )
  assert.equal(probeH2.status, 200)
  assert.equal(seenAuth[0], 'Bearer h2_shared_token_0011223344')
  assert.equal(mintCalls, 0)

  // H2 control request receives isolated token, preserves persona_vault provenance, and redacts the secret.
  const ctrlH2 = await broker.executeHttp2Exchange(
    { origin: h2Origin, method: 'GET', pathAndQuery: '/v2/export', persona: 'member_b', sessionGroupRole: 'control', session: 'h2-ctrl', runId },
    grant,
    AbortSignal.timeout(5_000),
  )
  assert.equal(ctrlH2.status, 200)
  assert.equal(seenAuth[1], 'Bearer h2_isolated_token_1_998877')
  assert.equal(mintCalls, 1)
  assert.equal(ctrlH2.wireCredentialProvenance?.authenticated, true)
  assert.equal(ctrlH2.wireCredentialProvenance?.source, 'persona_vault')
  assert.ok(ctrlH2.wireCredentialProvenance?.vaultHeaderNames.includes('authorization'))
  assert.ok(!ctrlH2.body.includes('h2_isolated_token_1_998877'))

  // Repeated H2 control request hits cache.
  await broker.executeHttp2Exchange(
    { origin: h2Origin, method: 'GET', pathAndQuery: '/v2/export', persona: 'member_b', sessionGroupRole: 'control', session: 'h2-ctrl', runId },
    grant,
    AbortSignal.timeout(5_000),
  )
  assert.equal(mintCalls, 1)
  assert.equal(seenAuth[2], 'Bearer h2_isolated_token_1_998877')
})
