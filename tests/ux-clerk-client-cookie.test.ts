import assert from 'node:assert/strict'
import { randomUUID } from 'node:crypto'
import { once } from 'node:events'
import { existsSync, mkdtempSync, readdirSync, readFileSync, rmSync, statSync } from 'node:fs'
import { createServer } from 'node:http'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { test } from 'node:test'
import { createPersona, personaLoginConfigSchema } from '../src/domain.ts'
import { RequestBroker } from '../src/server/broker.ts'
import {
  decodeClerkPublishableKey,
  PersonaAuthError,
  PersonaAuthManager,
} from '../src/server/persona-auth.ts'
import {
  buildPersonaHeader,
  createProjectPersona,
  listProjectPersonas,
  normalizeClerkClientCookie,
  personaSecrets,
  resolveRunPersonas,
} from '../src/server/persona-vault.ts'
import { redact } from '../src/server/redact.ts'
import { Store } from '../src/server/store.ts'
import { testPersonaAuth } from '../src/server/worker-session-reader.ts'

process.env.KOVO_ALLOW_LOCAL_LAB ??= '1'

function makeFakeJwt(payload: Record<string, unknown>, sigSuffix: string): string {
  const header = Buffer.from(JSON.stringify({ alg: 'RS256', typ: 'JWT' })).toString('base64url')
  const body = Buffer.from(JSON.stringify(payload)).toString('base64url')
  return `${header}.${body}.sig_${sigSuffix}_998877665544332211`
}

interface MockClerkServer {
  origin: string
  requests: Array<{ method: string; url: string; cookie: string | null; origin: string | null }>
  setMode: (mode: 'active' | 'empty' | 'expired' | 'unauthorized' | 'redirect') => void
  tokenCalls: () => number
  close: () => Promise<void>
}

async function startMockClerkServer(options: {
  publishableKey: string
  validClientCookies: ReadonlySet<string>
  rotatedClientCookie?: string
  sessionId: string
  jwts: readonly string[]
}): Promise<MockClerkServer> {
  const requests: Array<{ method: string; url: string; cookie: string | null; origin: string | null }> = []
  let mode: 'active' | 'empty' | 'expired' | 'unauthorized' | 'redirect' = 'active'
  let tokenIndex = 0

  const server = createServer((req, res) => {
    const method = req.method ?? 'GET'
    const url = req.url ?? '/'
    const cookie = typeof req.headers.cookie === 'string' ? req.headers.cookie : null
    const origin = typeof req.headers.origin === 'string' ? req.headers.origin : null
    requests.push({ method, url, cookie, origin })

    if (url === '/' && method === 'GET') {
      const hasSession = Boolean(cookie && cookie.includes('__session='))
      res.writeHead(200, {
        'content-type': 'text/html; charset=utf-8',
        'x-clerk-auth-status': hasSession ? 'signed-in' : 'signed-out',
      })
      res.end(`<!doctype html><html><script data-clerk-publishable-key="${options.publishableKey}"></script><body>Clerk app</body></html>`)
      return
    }

    if (url === '/v1/client' && method === 'GET') {
      if (mode === 'redirect') {
        res.writeHead(302, { location: 'https://evil.example/steal' })
        res.end()
        return
      }
      if (mode === 'unauthorized') {
        res.writeHead(401, { 'content-type': 'application/json' })
        res.end(JSON.stringify({
          errors: [{ code: 'client_not_found', message: 'Invalid __client cookie' }],
        }))
        return
      }
      const match = /(?:^|;\s*)__client=([^;]+)/.exec(cookie ?? '')
      const provided = match?.[1]?.trim() ?? ''
      if (!options.validClientCookies.has(provided)) {
        res.writeHead(200, { 'content-type': 'application/json' })
        res.end(JSON.stringify({ response: null }))
        return
      }
      if (mode === 'empty') {
        res.writeHead(200, { 'content-type': 'application/json' })
        res.end(JSON.stringify({
          response: {
            id: 'client_mock_1',
            last_active_session_id: null,
            sessions: [],
          },
        }))
        return
      }
      if (mode === 'expired') {
        res.writeHead(200, { 'content-type': 'application/json' })
        res.end(JSON.stringify({
          response: {
            id: 'client_mock_1',
            last_active_session_id: options.sessionId,
            sessions: [{ id: options.sessionId, status: 'expired' }],
          },
        }))
        return
      }
      res.writeHead(200, { 'content-type': 'application/json' })
      res.end(JSON.stringify({
        response: {
          id: 'client_mock_1',
          last_active_session_id: options.sessionId,
          sessions: [{ id: options.sessionId, status: 'active' }],
        },
      }))
      return
    }

    if (url === `/v1/client/sessions/${options.sessionId}/tokens` && method === 'POST') {
      const match = /(?:^|;\s*)__client=([^;]+)/.exec(cookie ?? '')
      const provided = match?.[1]?.trim() ?? ''
      if (!options.validClientCookies.has(provided) && provided !== options.rotatedClientCookie) {
        res.writeHead(401, { 'content-type': 'application/json' })
        res.end(JSON.stringify({ errors: [{ code: 'session_expired', message: 'Session expired' }] }))
        return
      }
      const jwt = options.jwts[Math.min(tokenIndex, options.jwts.length - 1)]
      tokenIndex += 1
      const headers: Record<string, string> = { 'content-type': 'application/json' }
      if (tokenIndex === 1 && options.rotatedClientCookie) {
        headers['set-cookie'] = `__client=${options.rotatedClientCookie}; Path=/; HttpOnly`
      }
      res.writeHead(200, headers)
      res.end(JSON.stringify({ jwt }))
      return
    }

    res.writeHead(404, { 'content-type': 'text/plain' })
    res.end('not found')
  })

  server.listen(0, '127.0.0.1')
  await once(server, 'listening')
  const address = server.address()
  if (!address || typeof address === 'string') throw new Error('Failed to bind mock Clerk server')
  return {
    origin: `http://127.0.0.1:${address.port}`,
    requests,
    setMode: next => { mode = next },
    tokenCalls: () => tokenIndex,
    close: async () => { await new Promise<void>(resolve => server.close(() => resolve())) },
  }
}

test('clerk_client schema allows passwordless setup without email while preserving email requirement on other adapters', () => {
  const passwordless = personaLoginConfigSchema.parse({ adapter: 'clerk_client' })
  assert.equal(passwordless.adapter, 'clerk_client')
  assert.equal(passwordless.email, undefined)

  const blankEmail = personaLoginConfigSchema.parse({
    adapter: 'clerk_client',
    email: '   ',
    loginUrl: 'https://happy-cat-42.clerk.accounts.dev',
  })
  assert.equal(blankEmail.email, undefined)
  assert.equal(blankEmail.loginUrl, 'https://happy-cat-42.clerk.accounts.dev/')

  const created = createPersona.parse({
    requestId: randomUUID(),
    projectId: randomUUID(),
    handle: 'clerk_oauth_user',
    roleLabel: 'OAuth User',
    originAllowlist: ['https://app.northstar.example'],
    authKind: 'login',
    loginConfig: { adapter: 'clerk_client' },
    secret: 'eyJhbGciOiJSUzI1NiJ9.client_payload.sig_raw_1234',
  })
  assert.equal(created.loginConfig?.adapter, 'clerk_client')
  assert.equal(created.loginConfig?.email, undefined)

  // Non-clerk_client adapters still require email
  assert.equal(personaLoginConfigSchema.safeParse({ adapter: 'auto' }).success, false)
  assert.equal(personaLoginConfigSchema.safeParse({ adapter: 'clerk' }).success, false)
  assert.equal(personaLoginConfigSchema.safeParse({ adapter: 'json' }).success, false)

  // Normalization covers raw token, base64 padding, __client=..., Cookie: ..., Set-Cookie: ..., and rejects invalid strings
  assert.equal(normalizeClerkClientCookie('raw_clerk_tok_123456=='), 'raw_clerk_tok_123456==')
  assert.equal(normalizeClerkClientCookie('__client=tok_direct_123456'), 'tok_direct_123456')
  assert.equal(normalizeClerkClientCookie('__client=tok_attrs_123456; Path=/; HttpOnly; Secure'), 'tok_attrs_123456')
  assert.equal(normalizeClerkClientCookie('Cookie: foo=1; __client=tok_header_123456; bar=2'), 'tok_header_123456')
  assert.equal(normalizeClerkClientCookie('Set-Cookie: __client="tok_quoted_123456"; Path=/'), 'tok_quoted_123456')
  assert.equal(normalizeClerkClientCookie('Cookie: foo=1; bar=2'), '')
  assert.equal(normalizeClerkClientCookie('__session=not_a_client_cookie'), '')
  assert.equal(normalizeClerkClientCookie('   '), '')
})

test('clerk_client paste normalization, local HTTP mock FAPI mint + rotation, PersonaSessionPool, Verify sign-in, and scrubTokens', async t => {
  const rawToken = 'clerk_client_tok_primary_998877665544332211'
  const rotatedClient = 'clerk_client_tok_rotated_112233445566778899'
  const iat1 = 1_760_100_100
  const jwt1 = makeFakeJwt({ sub: 'user_oauth_1', sid: 'sess_oauth_77', iat: iat1, exp: iat1 + 60 }, 'clerk_client_v1')
  const iat2 = 1_760_100_140
  const jwt2 = makeFakeJwt({ sub: 'user_oauth_1', sid: 'sess_oauth_77', iat: iat2, exp: iat2 + 60 }, 'clerk_client_v2')
  const pkTest = `pk_test_${Buffer.from('clerk.northstar.example$').toString('base64')}`
  assert.equal(decodeClerkPublishableKey(pkTest), 'https://clerk.northstar.example')

  const server = await startMockClerkServer({
    publishableKey: pkTest,
    validClientCookies: new Set([rawToken]),
    rotatedClientCookie: rotatedClient,
    sessionId: 'sess_oauth_77',
    jwts: [jwt1, jwt2],
  })
  t.after(() => server.close())

  const dir = mkdtempSync(join(tmpdir(), 'kovo-clerk-client-http-'))
  t.after(() => rmSync(dir, { recursive: true, force: true }))
  const storage = new Store(dir)
  t.after(() => storage.close())

  const { id: projectId } = storage.createProject({
    requestId: randomUUID(),
    name: 'Clerk Client Cookie Local Mock',
    seeds: [server.origin],
    environment: 'local-lab',
  })

  // Prove all 3 paste formats normalize cleanly & authenticate against the real local HTTP server
  const pasteCases = [
    { handle: 'paste_raw', pasted: rawToken },
    { handle: 'paste_pair', pasted: `__client=${rawToken}; Path=/; HttpOnly` },
    { handle: 'paste_header', pasted: `Cookie: foo=1; __client=${rawToken}; bar=2` },
  ] as const

  const authManager = new PersonaAuthManager()
  t.after(() => authManager.stopAll())

  const createdIds: string[] = []
  for (const c of pasteCases) {
    const created = createProjectPersona(storage, {
      requestId: randomUUID(),
      projectId,
      handle: c.handle,
      roleLabel: `User ${c.handle}`,
      originAllowlist: [server.origin],
      authKind: 'login',
      loginConfig: {
        adapter: 'clerk_client',
        loginUrl: `${server.origin}/v1/client`,
      },
      secret: c.pasted,
      canaryMarkers: [],
    })
    createdIds.push(created.id)
    const authRes = await authManager.authenticatePersona(storage, projectId, created.id)
    assert.equal(authRes.adapterUsed, 'clerk')
    assert.equal(authRes.headerType, 'cookie')
    assert.equal(authRes.refreshIntervalSec, 35)
    assert.ok(typeof authRes.refresh === 'function')
  }

  // Verify credential files are 0600, store normalized __client token, and SQLite/PublicPersona never leak it
  const listed = listProjectPersonas(storage, projectId)
  assert.equal(listed.length, 3)
  assert.ok(!JSON.stringify(listed).includes(rawToken))
  const sqliteRaw = readFileSync(join(dir, 'kovo.sqlite'))
  assert.ok(!sqliteRaw.includes(rawToken))
  assert.ok(!sqliteRaw.includes(rotatedClient))
  assert.ok(!sqliteRaw.includes(jwt1))
  assert.ok(!sqliteRaw.includes(jwt2))

  const credDir = join(dir, 'credentials')
  for (const file of readdirSync(credDir)) {
    assert.equal(statSync(join(credDir, file)).mode & 0o777, 0o600)
  }

  // Now run a dedicated lifecycle check on a fresh mock server for jwt1 -> jwt2 rotation, scrubTokens, PersonaSessionPool & Verify sign-in
  const server2 = await startMockClerkServer({
    publishableKey: pkTest,
    validClientCookies: new Set([rawToken]),
    rotatedClientCookie: rotatedClient,
    sessionId: 'sess_oauth_77',
    jwts: [jwt1, jwt2],
  })
  t.after(() => server2.close())

  const { id: project2 } = storage.createProject({
    requestId: randomUUID(),
    name: 'Clerk Client Rotation Project',
    seeds: [server2.origin],
    environment: 'local-lab',
  })
  const primary = createProjectPersona(storage, {
    requestId: randomUUID(),
    projectId: project2,
    handle: 'oauth_user',
    roleLabel: 'OAuth User',
    originAllowlist: [server2.origin],
    authKind: 'login',
    loginConfig: {
      adapter: 'clerk_client',
      loginUrl: `${server2.origin}/v1/client`,
    },
    secret: `Cookie: foo=1; __client=${rawToken}; bar=2`,
    canaryMarkers: [],
  })

  const resolvedBefore = resolveRunPersonas(storage, project2, [primary.id])
  const personaBefore = resolvedBefore.get('oauth_user')!
  assert.equal(buildPersonaHeader(personaBefore, server2.origin), null)

  const initialAuth = await authManager.authenticatePersona(storage, project2, primary.id)
  assert.equal(initialAuth.adapterUsed, 'clerk')
  assert.equal(initialAuth.refreshIntervalSec, 35)
  assert.equal(server2.tokenCalls(), 1)
  assert.deepEqual(
    buildPersonaHeader(personaBefore, server2.origin),
    { Cookie: `__session=${jwt1}; __client_uat=${iat1}` },
  )

  // Subsequent refresh rotates __session to jwt2 and uses rotated __client cookie
  await initialAuth.refresh!()
  assert.equal(server2.tokenCalls(), 2)
  assert.deepEqual(
    buildPersonaHeader(personaBefore, server2.origin),
    { Cookie: `__session=${jwt2}; __client_uat=${iat2}` },
  )
  const secondTokenReq = server2.requests.filter(r => r.url.endsWith('/tokens'))[1]
  assert.equal(secondTokenReq.cookie, `__client=${rotatedClient}`)

  // Fresh Store read scrubs original __client, rotated __client, initial jwt1, AND rotated jwt2
  const freshResolved = resolveRunPersonas(storage, project2, [primary.id])
  const secrets = personaSecrets(freshResolved)
  const probe = `orig=${rawToken} rot=${rotatedClient} j1=${jwt1} j2=${jwt2}`
  const scrubbed = redact(probe, secrets)
  assert.ok(!scrubbed.includes(rawToken), 'Original __client leaked')
  assert.ok(!scrubbed.includes(rotatedClient), 'Rotated __client leaked')
  assert.ok(!scrubbed.includes(jwt1), 'Initial __session JWT leaked')
  assert.ok(!scrubbed.includes(jwt2), 'Rotated __session JWT leaked')

  // startRunRefreshers plugs seamlessly into PersonaSessionPool
  const { id: runId } = storage.createRun({
    requestId: randomUUID(),
    projectId: project2,
    goal: 'Test clerk_client refresher + session pool',
    sourceMode: 'public',
    capabilityTier: 2,
    approvedPersonaIds: [primary.id],
    budgetUsd: 10,
    budgetRequests: 0,
    maxRpsPerOrigin: 5,
    workerConcurrency: 2,
    workerMaxTurns: 20,
  })
  const started = await authManager.startRunRefreshers(storage, runId, project2, [primary.id])
  assert.equal(started.length, 1)
  assert.equal(started[0].adapterUsed, 'clerk')
  assert.equal(authManager.sessions.has('oauth_user'), true)
  const clone = authManager.cloneSession('oauth_user', 'worker-1')
  assert.ok(clone)
  assert.match(clone.headersFor(server2.origin)?.Cookie ?? '', /^__session=.*__client_uat=/)
  clone.dispose()
  authManager.stopRunRefreshers(runId)

  // Verify sign-in (testPersonaAuth) works cleanly for clerk_client personas
  const broker = new RequestBroker({
    resolve: async () => [{ address: '127.0.0.1', family: 4 }],
  })
  const verified = await testPersonaAuth(storage, broker, { projectId: project2, personaId: primary.id }, authManager)
  assert.equal(verified.ok, true)
  assert.equal(verified.status, 200)
  assert.match(verified.authHint, /signed-in.*Clerk \(auto-refresh 35s\)/)
})

test('clerk_client auto-detects pk_test_... FAPI origin from target HTML (proxied to local HTTP mock) and supports operator *.clerk.accounts.dev URL', async t => {
  const targetOrigin = 'https://app.northstar.example'
  const clientCookie = 'clerk_client_autodetect_secret_77665544332211'
  const iat1 = 1_760_200_100
  const jwt1 = makeFakeJwt({ sub: 'user_auto_1', sid: 'sess_auto_1', iat: iat1, exp: iat1 + 60 }, 'auto_v1')
  const pkTest = `pk_test_${Buffer.from('clerk.northstar.example$').toString('base64')}`

  const mockServer = await startMockClerkServer({
    publishableKey: pkTest,
    validClientCookies: new Set([clientCookie]),
    sessionId: 'sess_auto_1',
    jwts: [jwt1],
  })
  t.after(() => mockServer.close())

  // Proxy https://app.northstar.example, https://clerk.northstar.example, and https://happy-cat-42.clerk.accounts.dev to the local mock HTTP server
  const seenUrls: string[] = []
  const proxyFetch: typeof fetch = async (input, init) => {
    const rawUrl = typeof input === 'string' ? input : input instanceof URL ? input.toString() : input.url
    seenUrls.push(rawUrl)
    const parsed = new URL(rawUrl)
    const localUrl = `${mockServer.origin}${parsed.pathname}${parsed.search}`
    return await fetch(localUrl, { ...init, redirect: 'manual' })
  }

  const dir = mkdtempSync(join(tmpdir(), 'kovo-clerk-client-auto-'))
  t.after(() => rmSync(dir, { recursive: true, force: true }))
  const storage = new Store(dir)
  t.after(() => storage.close())

  const { id: projectId } = storage.createProject({
    requestId: randomUUID(),
    name: 'Clerk Auto-Detect Project',
    seeds: [targetOrigin],
    environment: 'public',
  })

  // 1. Auto-detect pk_test_... from target HTML (no loginUrl!)
  const autoPersona = createProjectPersona(storage, {
    requestId: randomUUID(),
    projectId,
    handle: 'auto_clerk',
    roleLabel: 'Auto Clerk User',
    originAllowlist: [targetOrigin],
    authKind: 'login',
    loginConfig: { adapter: 'clerk_client' },
    secret: clientCookie,
    canaryMarkers: [],
  })

  const manager = new PersonaAuthManager({
    fetchImpl: proxyFetch,
    resolveHost: async () => ['93.184.216.34'],
  })
  t.after(() => manager.stopAll())

  const resAuto = await manager.authenticatePersona(storage, projectId, autoPersona.id)
  assert.equal(resAuto.adapterUsed, 'clerk')
  assert.ok(seenUrls.includes(targetOrigin))
  assert.ok(seenUrls.includes('https://clerk.northstar.example/v1/client'))
  assert.ok(seenUrls.includes('https://clerk.northstar.example/v1/client/sessions/sess_auto_1/tokens'))

  // 2. Explicit operator-configured https://<instance>.clerk.accounts.dev loginUrl
  const devPersona = createProjectPersona(storage, {
    requestId: randomUUID(),
    projectId,
    handle: 'dev_clerk',
    roleLabel: 'Dev Clerk User',
    originAllowlist: [targetOrigin],
    authKind: 'login',
    loginConfig: {
      adapter: 'clerk_client',
      loginUrl: 'https://happy-cat-42.clerk.accounts.dev',
    },
    secret: clientCookie,
    canaryMarkers: [],
  })
  const resDev = await manager.authenticatePersona(storage, projectId, devPersona.id)
  assert.equal(resDev.adapterUsed, 'clerk')
  assert.ok(seenUrls.includes('https://happy-cat-42.clerk.accounts.dev/v1/client'))
  assert.ok(seenUrls.includes('https://happy-cat-42.clerk.accounts.dev/v1/client/sessions/sess_auto_1/tokens'))
})

test('clerk_client fails cleanly on expired, empty, unauthorized, or redirecting /v1/client responses without writing a session or leaking secrets', async t => {
  const clientCookie = 'clerk_client_expired_secret_554433221100'
  const pkTest = `pk_test_${Buffer.from('clerk.northstar.example$').toString('base64')}`
  const server = await startMockClerkServer({
    publishableKey: pkTest,
    validClientCookies: new Set([clientCookie]),
    sessionId: 'sess_expired_1',
    jwts: [],
  })
  t.after(() => server.close())

  const dir = mkdtempSync(join(tmpdir(), 'kovo-clerk-client-fail-'))
  t.after(() => rmSync(dir, { recursive: true, force: true }))
  const storage = new Store(dir)
  t.after(() => storage.close())

  const { id: projectId } = storage.createProject({
    requestId: randomUUID(),
    name: 'Clerk Failure Project',
    seeds: [server.origin],
    environment: 'local-lab',
  })

  const persona = createProjectPersona(storage, {
    requestId: randomUUID(),
    projectId,
    handle: 'expired_user',
    roleLabel: 'Expired User',
    originAllowlist: [server.origin],
    authKind: 'login',
    loginConfig: {
      adapter: 'clerk_client',
      loginUrl: `${server.origin}/v1/client`,
    },
    secret: clientCookie,
    canaryMarkers: [],
  })

  const manager = new PersonaAuthManager()
  t.after(() => manager.stopAll())

  // 1. Empty sessions array
  server.setMode('empty')
  await assert.rejects(
    manager.authenticatePersona(storage, projectId, persona.id),
    err => err instanceof PersonaAuthError &&
      err.code === 'INVALID_CREDENTIALS' &&
      /no active session|expired/i.test(err.message) &&
      !err.message.includes(clientCookie),
  )

  // 2. Expired session status
  server.setMode('expired')
  await assert.rejects(
    manager.authenticatePersona(storage, projectId, persona.id),
    err => err instanceof PersonaAuthError &&
      err.code === 'INVALID_CREDENTIALS' &&
      /no active session|expired/i.test(err.message) &&
      !err.message.includes(clientCookie),
  )

  // 3. HTTP 401 unauthorized
  server.setMode('unauthorized')
  await assert.rejects(
    manager.authenticatePersona(storage, projectId, persona.id),
    err => err instanceof PersonaAuthError &&
      err.code === 'INVALID_CREDENTIALS' &&
      /401/.test(err.message) &&
      !err.message.includes(clientCookie),
  )

  // 4. Unexpected 302 redirect MUST be rejected (never replay credentials across redirects)
  server.setMode('redirect')
  await assert.rejects(
    manager.authenticatePersona(storage, projectId, persona.id),
    err => err instanceof PersonaAuthError &&
      err.code === 'AUTH_FAILED' &&
      /redirect/i.test(err.message) &&
      !err.message.includes(clientCookie),
  )

  // Confirm no .session file was created on any failure
  const credFiles = readdirSync(join(dir, 'credentials'))
  assert.equal(credFiles.filter(f => f.endsWith('.session')).length, 0)
  assert.equal(existsSync(join(dir, 'credentials', `${credFiles[0]}.session`)), false)
})
