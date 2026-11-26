import assert from 'node:assert/strict'
import { randomUUID } from 'node:crypto'
import { once } from 'node:events'
import { mkdtempSync, readFileSync, rmSync, statSync } from 'node:fs'
import { request as httpRequest } from 'node:http'
import { createRequire } from 'node:module'
import type { AddressInfo } from 'node:net'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import { test } from 'node:test'
import React from 'react'
import { renderToStaticMarkup } from 'react-dom/server'
import ts from 'typescript'
import { createKovoLocalServer, isAllowedSecFetchSite } from '../scripts/serve.ts'
import {
  createBrowserSessionPersonaSchema,
  updateBrowserSessionPersonaSchema,
} from '../src/actions-auth-capture.ts'
import {
  BrowserCaptureManager,
  CaptureEscrowStore,
  DEFAULT_CAPTURE_ESCROW_TTL_MS,
  registerBrowserSessionPersonaFromAction,
  startInteractiveLoginCapture,
  summarizeBrowserStorageBundle,
  updateBrowserSessionPersonaFromAction,
} from '../src/server/browser-session-auth.ts'
import type {
  BrowserStorageBundle,
  PlaywrightBrowserLike,
} from '../src/server/browser-session-auth.ts'
import {
  buildPersonaHeader,
  readBrowserSessionCredentialFile,
  resolveRunPersonas,
} from '../src/server/persona-vault.ts'
import { Store } from '../src/server/store.ts'

const REPO_ROOT = resolve(import.meta.dirname, '..')
const localRequire = createRequire(import.meta.url)

function makeSampleBundle(overrides: Partial<BrowserStorageBundle> = {}): BrowserStorageBundle {
  return {
    v: 1,
    kind: 'browser_session',
    targetOrigin: 'https://app.example.test',
    capturedAt: 1_770_000_000_000,
    storageState: {
      cookies: [
        {
          name: '__session',
          value: 'super_secret_cookie_value_99887766',
          domain: 'app.example.test',
          path: '/',
          expires: -1,
          httpOnly: true,
          secure: true,
          sameSite: 'Lax',
        },
      ],
      origins: [
        {
          origin: 'https://app.example.test',
          localStorage: [
            { name: 'access_token', value: 'super_secret_localstorage_jwt_112233' },
          ],
        },
        {
          origin: 'https://idp.example.test',
          localStorage: [
            { name: 'idp_hint', value: 'secret_idp_state_445566' },
          ],
        },
      ],
    },
    observedHeaders: {
      Authorization: 'Bearer super_secret_bearer_token_abcdef123456',
      'X-CSRF-Token': 'secret_csrf_value_xyz',
    },
    ...overrides,
  }
}

function makeMockLauncher(bundle: BrowserStorageBundle): (opts: { args: string[] }) => Promise<PlaywrightBrowserLike> {
  return async () => ({
    async newContext() {
      let currentUrl = bundle.targetOrigin
      const requestListeners: Array<(req: unknown) => void> = []
      const page = {
        async goto(url: string) {
          currentUrl = url
          for (const listener of requestListeners) {
            listener({
              url: () => `${bundle.targetOrigin}/api/me`,
              headers: () => bundle.observedHeaders ?? {},
            })
          }
        },
        async waitForTimeout() {},
        url: () => currentUrl,
        async title() { return 'Mock App' },
        on(event: string, listener: (...args: unknown[]) => void) {
          if (event === 'request') requestListeners.push(listener as (req: unknown) => void)
        },
        async close() {},
      }
      return {
        async newPage() { return page },
        async addInitScript() {},
        async storageState() { return bundle.storageState },
        async close() {},
      }
    },
    async close() {},
  })
}

async function startTestLocalServer(
  directory: string,
  extraOptions: Partial<Parameters<typeof createKovoLocalServer>[0]> = {},
) {
  const probe = createKovoLocalServer({
    app: { fetch: () => new Response('ok') },
    directory,
    port: 0,
  })
  await new Promise<void>(resolveListen => probe.server.listen(0, '127.0.0.1', () => resolveListen()))
  const port = (probe.server.address() as AddressInfo).port
  await new Promise<void>(resolveClose => probe.server.close(() => resolveClose()))

  const local = createKovoLocalServer({
    app: {
      fetch: async req => {
        if (req.method === 'POST') {
          const text = await req.text()
          return new Response(JSON.stringify({ receivedBytes: text.length }), {
            status: 200,
            headers: { 'content-type': 'application/json' },
          })
        }
        return new Response(JSON.stringify({ ok: true }), {
          status: 200,
          headers: { 'content-type': 'application/json' },
        })
      },
    },
    directory,
    port,
    ...extraOptions,
  })
  await new Promise<void>(resolveListen => local.server.listen(port, '127.0.0.1', () => resolveListen()))
  return {
    local,
    port,
    origin: `http://127.0.0.1:${port}`,
    cookie: `kovo_local=${local.token}`,
    close: () => new Promise<void>(resolveClose => local.server.close(() => resolveClose())),
  }
}

// ---------------------------------------------------------------------------
// 1. Server-Side CaptureEscrowStore: single-use, projectId binding, 5m TTL
// ---------------------------------------------------------------------------

test('CaptureEscrowStore enforces single-use redemption, projectId binding, and 5-minute TTL expiry', () => {
  let nowMs = 1_770_000_000_000
  const escrow = new CaptureEscrowStore({ now: () => nowMs })
  const projectA = randomUUID()
  const projectB = randomUUID()
  const bundle = makeSampleBundle()

  const stored = escrow.store({ projectId: projectA, bundle })
  assert.match(stored.captureToken, /^cap_tok_[a-f0-9]{64}$/)
  assert.equal(stored.projectId, projectA)
  assert.equal(stored.expiresAt, nowMs + DEFAULT_CAPTURE_ESCROW_TTL_MS)
  assert.equal(escrow.size, 1)
  assert.equal(escrow.has(stored.captureToken), true)

  // Summary contains ONLY non-secret metadata (cookie count, origins, header names)
  const summaryJson = JSON.stringify(stored.summary)
  assert.equal(stored.summary.cookieCount, 1)
  assert.equal(stored.summary.originCount, 2)
  assert.deepEqual(stored.summary.origins, ['https://app.example.test', 'https://idp.example.test'])
  assert.deepEqual(stored.summary.headerNames, ['Authorization', 'X-CSRF-Token'])
  assert.equal(stored.summary.hasAuthorizationHeader, true)
  assert.equal(summaryJson.includes('super_secret_cookie_value_99887766'), false)
  assert.equal(summaryJson.includes('super_secret_localstorage_jwt_112233'), false)
  assert.equal(summaryJson.includes('super_secret_bearer_token_abcdef123456'), false)
  assert.equal(summaryJson.includes('secret_csrf_value_xyz'), false)

  // Cross-project redemption MUST be rejected
  assert.throws(
    () => escrow.redeem(stored.captureToken, projectB),
    /does not belong to this project/i,
  )

  // Valid project redemption succeeds once and deletes entry immediately
  const redeemed = escrow.redeem(stored.captureToken, projectA)
  assert.equal(redeemed.storageState.cookies[0]?.value, 'super_secret_cookie_value_99887766')
  assert.equal(escrow.size, 0)
  assert.equal(escrow.has(stored.captureToken), false)

  // Second redemption MUST fail (strictly single-use)
  assert.throws(
    () => escrow.redeem(stored.captureToken, projectA),
    /invalid, already used, or expired/i,
  )

  // TTL expiry: advance clock by 5 minutes -> rejected and pruned
  const expiring = escrow.store({ projectId: projectA, bundle })
  assert.equal(escrow.size, 1)
  nowMs += DEFAULT_CAPTURE_ESCROW_TTL_MS
  assert.equal(escrow.has(expiring.captureToken), false)
  assert.equal(escrow.size, 0)
  assert.throws(
    () => escrow.redeem(expiring.captureToken, projectA),
    /invalid, already used, or expired/i,
  )

  // Helper summarizeBrowserStorageBundle also never echoes secrets
  const summaryDirect = summarizeBrowserStorageBundle(bundle)
  assert.deepEqual(summaryDirect.headerNames, ['Authorization', 'X-CSRF-Token'])
})

// ---------------------------------------------------------------------------
// 2. HTTP /complete returns ZERO raw secrets & actions redeem captureToken server-side
// ---------------------------------------------------------------------------

test('/_kovo/auth-capture/:id/complete returns only captureToken + safe summary (zero raw secrets) and actions redeem it', async t => {
  const dir = mkdtempSync(join(tmpdir(), 'kovo-u2-escrow-http-'))
  t.after(() => rmSync(dir, { recursive: true, force: true }))
  const store = new Store(dir, { ftsMode: 'preview' })
  t.after(() => store.close())

  const projectA = store.createProject({
    requestId: randomUUID(),
    name: 'Escrow Public App',
    seeds: ['https://app.example.test'],
    environment: 'public',
  })
  const projectB = store.createProject({
    requestId: randomUUID(),
    name: 'Other Public App',
    seeds: ['https://other.example.test'],
    environment: 'public',
  })

  const bundle = makeSampleBundle()
  const escrow = new CaptureEscrowStore()
  const captureManager = new BrowserCaptureManager({ escrow })
  t.after(() => {
    escrow.clear()
    return captureManager.disposeAll()
  })

  // Start a deterministic mock capture session directly on the shared manager
  const session = await captureManager.startCapture({
    projectId: projectA.id,
    targetOrigin: 'https://app.example.test',
    allowLocalLab: false,
    launchBrowser: makeMockLauncher(bundle),
    resolveHost: async () => ['93.184.216.34'],
  })

  const srv = await startTestLocalServer(dir, { store, captureManager })
  t.after(() => srv.close())

  // Complete capture via HTTP control plane
  const completeRes = await fetch(`${srv.origin}/_kovo/auth-capture/${session.id}/complete`, {
    method: 'POST',
    headers: {
      Cookie: srv.cookie,
      Origin: srv.origin,
      'Sec-Fetch-Site': 'same-origin',
      'content-type': 'application/json',
    },
    body: JSON.stringify({}),
  })
  assert.equal(completeRes.status, 200)
  const rawBody = await completeRes.text()

  // ZERO raw secrets or `bundle` field anywhere in HTTP response!
  assert.equal(rawBody.includes('"bundle"'), false, 'HTTP /complete must never include a raw bundle field')
  assert.equal(rawBody.includes('super_secret_cookie_value_99887766'), false)
  assert.equal(rawBody.includes('super_secret_localstorage_jwt_112233'), false)
  assert.equal(rawBody.includes('super_secret_bearer_token_abcdef123456'), false)
  assert.equal(rawBody.includes('secret_csrf_value_xyz'), false)
  assert.equal(rawBody.includes('secret_idp_state_445566'), false)

  const parsed = JSON.parse(rawBody) as {
    ok: boolean
    captureToken: string
    expiresAt: number
    summary: {
      targetOrigin: string
      cookieCount: number
      originCount: number
      origins: string[]
      headerNames: string[]
      hasAuthorizationHeader: boolean
    }
  }
  assert.equal(parsed.ok, true)
  assert.match(parsed.captureToken, /^cap_tok_[a-f0-9]{64}$/)
  assert.equal(parsed.summary.cookieCount, 1)
  assert.deepEqual(parsed.summary.origins, ['https://app.example.test', 'https://idp.example.test'])
  assert.deepEqual(parsed.summary.headerNames, ['Authorization', 'X-CSRF-Token'])
  assert.equal(parsed.summary.hasAuthorizationHeader, true)

  // Attempting to redeem under a different projectId MUST fail
  const wrongProjectInput = createBrowserSessionPersonaSchema.parse({
    requestId: randomUUID(),
    projectId: projectB.id,
    handle: 'stolen-user',
    roleLabel: 'Stolen',
    originAllowlist: ['https://other.example.test'],
    captureToken: parsed.captureToken,
  })
  assert.throws(
    () => registerBrowserSessionPersonaFromAction(store, wrongProjectInput, escrow),
    /does not belong to this project/i,
  )

  // Redeeming under projectA creates persona and persists 0600 bundle on disk
  const validInput = createBrowserSessionPersonaSchema.parse({
    requestId: randomUUID(),
    projectId: projectA.id,
    handle: 'escrowed-user',
    roleLabel: 'Escrowed User',
    originAllowlist: ['https://app.example.test'],
    captureToken: parsed.captureToken,
    verifyPath: '/dashboard',
  })
  const created = registerBrowserSessionPersonaFromAction(store, validInput, escrow)
  assert.equal(created.handle, 'escrowed-user')
  assert.equal(escrow.size, 0, 'captureToken must be deleted immediately upon redemption')

  const resolved = resolveRunPersonas(store, projectA.id, [created.id]).get('escrowed-user')!
  assert.ok(resolved.secretPath)
  assert.equal(statSync(resolved.secretPath).mode & 0o777, 0o600)
  const persisted = readBrowserSessionCredentialFile(resolved.secretPath)
  assert.equal(persisted.bundle.storageState.cookies[0]?.value, 'super_secret_cookie_value_99887766')
  const headers = buildPersonaHeader(resolved, 'https://app.example.test')
  assert.equal(headers?.Authorization, 'Bearer super_secret_bearer_token_abcdef123456')

  // Replay of the already-redeemed captureToken MUST fail
  assert.throws(
    () => registerBrowserSessionPersonaFromAction(
      store,
      createBrowserSessionPersonaSchema.parse({
        requestId: randomUUID(),
        projectId: projectA.id,
        handle: 'replay-user',
        roleLabel: 'Replay User',
        originAllowlist: ['https://app.example.test'],
        captureToken: parsed.captureToken,
      }),
      escrow,
    ),
    /invalid, already used, or expired/i,
  )

  // Update via a fresh captureToken works too
  const rotatedBundle = makeSampleBundle({
    observedHeaders: { Authorization: 'Bearer rotated_escrow_bearer_999999' },
  })
  const escrowed2 = escrow.store({ projectId: projectA.id, bundle: rotatedBundle })
  const updateInput = updateBrowserSessionPersonaSchema.parse({
    requestId: randomUUID(),
    projectId: projectA.id,
    personaId: created.id,
    roleLabel: 'Escrowed User Rotated',
    originAllowlist: ['https://app.example.test'],
    captureToken: escrowed2.captureToken,
  })
  updateBrowserSessionPersonaFromAction(store, updateInput, escrow)
  const resolvedAfterUpdate = resolveRunPersonas(store, projectA.id, [created.id]).get('escrowed-user')!
  assert.equal(
    buildPersonaHeader(resolvedAfterUpdate, 'https://app.example.test')?.Authorization,
    'Bearer rotated_escrow_bearer_999999',
  )

  // Explicit operator "Import storageState.json" paste (no captureToken) continues to work
  const pastedInput = createBrowserSessionPersonaSchema.parse({
    requestId: randomUUID(),
    projectId: projectA.id,
    handle: 'imported-user',
    roleLabel: 'Imported User',
    originAllowlist: ['https://app.example.test'],
    storageState: JSON.stringify(bundle.storageState),
  })
  const imported = registerBrowserSessionPersonaFromAction(store, pastedInput, escrow)
  assert.equal(imported.handle, 'imported-user')

  // Missing both captureToken and storageState is rejected by schema
  const missingBoth = createBrowserSessionPersonaSchema.safeParse({
    requestId: randomUUID(),
    projectId: projectA.id,
    handle: 'empty-user',
    roleLabel: 'Empty',
    originAllowlist: ['https://app.example.test'],
  })
  assert.equal(missingBoth.success, false)

  // Oversized object storageState (> 2 MiB) is rejected by schema
  const hugeObj = createBrowserSessionPersonaSchema.safeParse({
    requestId: randomUUID(),
    projectId: projectA.id,
    handle: 'huge-user',
    roleLabel: 'Huge',
    originAllowlist: ['https://app.example.test'],
    storageState: { blob: 'x'.repeat(2 * 1024 * 1024 + 128) },
  })
  assert.equal(hugeObj.success, false)
})

test('actions-auth-capture.ts has zero top-level ./server/* imports and PersonaFormModal uses captureToken', () => {
  const actionsSrc = readFileSync(join(REPO_ROOT, 'src/actions-auth-capture.ts'), 'utf8')
  assert.doesNotMatch(
    actionsSrc,
    /^\s*import\s+(?!type\b)[\s\S]*?from\s+['"]\.\/server\//m,
    'src/actions-auth-capture.ts must never have top-level value imports from ./server/*',
  )
  assert.match(actionsSrc, /import\('\.\/server\/browser-session-auth\.ts'\)/)

  const modalSrc = readFileSync(join(REPO_ROOT, 'src/components/project/PersonaFormModal.tsx'), 'utf8')
  assert.match(modalSrc, /captureToken/)
  assert.doesNotMatch(modalSrc, /payload\.bundle/, 'PersonaFormModal must not expect raw payload.bundle from /complete')
  assert.match(modalSrc, /\/_kovo\/auth\/status/, 'PersonaFormModal must check /_kovo/auth/status on capture stream errors')
})

// ---------------------------------------------------------------------------
// 3. Scope / Origin Policy Enforcement on /_kovo/auth-capture/start
// ---------------------------------------------------------------------------

test('/_kovo/auth-capture/start blocks loopback/private/HTTP origins on public projects even if KOVO_ALLOW_LOCAL_LAB=1', async t => {
  const prevLab = process.env.KOVO_ALLOW_LOCAL_LAB
  process.env.KOVO_ALLOW_LOCAL_LAB = '1'
  t.after(() => {
    if (prevLab === undefined) delete process.env.KOVO_ALLOW_LOCAL_LAB
    else process.env.KOVO_ALLOW_LOCAL_LAB = prevLab
  })

  const dir = mkdtempSync(join(tmpdir(), 'kovo-u2-ssrf-scope-'))
  t.after(() => rmSync(dir, { recursive: true, force: true }))
  const store = new Store(dir, { ftsMode: 'preview' })
  t.after(() => store.close())

  const publicProj = store.createProject({
    requestId: randomUUID(),
    name: 'Public SaaS',
    seeds: ['https://app.public-target.example'],
    environment: 'public',
  })

  const srv = await startTestLocalServer(dir, { store })
  t.after(() => srv.close())

  const blockedTargets = [
    'http://127.0.0.1:8080',
    'https://127.0.0.1:8443',
    'http://localhost:3000',
    'http://169.254.169.254',
    'https://10.0.0.1',
    'http://app.public-target.example',
  ]
  for (const targetOrigin of blockedTargets) {
    const res = await fetch(`${srv.origin}/_kovo/auth-capture/start`, {
      method: 'POST',
      headers: {
        Cookie: srv.cookie,
        Origin: srv.origin,
        'Sec-Fetch-Site': 'same-origin',
        'content-type': 'application/json',
      },
      body: JSON.stringify({ projectId: publicProj.id, targetOrigin }),
    })
    assert.equal(res.status, 400, `Expected public project auth-capture to block ${targetOrigin}`)
  }

  // Also reject loopback smuggled inside allowedOrigins on a public project
  const smuggledRes = await fetch(`${srv.origin}/_kovo/auth-capture/start`, {
    method: 'POST',
    headers: {
      Cookie: srv.cookie,
      Origin: srv.origin,
      'Sec-Fetch-Site': 'same-origin',
      'content-type': 'application/json',
    },
    body: JSON.stringify({
      projectId: publicProj.id,
      targetOrigin: 'https://app.public-target.example',
      allowedOrigins: ['https://app.public-target.example', 'http://127.0.0.1:9222'],
    }),
  })
  assert.equal(smuggledRes.status, 400)

  // Engine-level guard also refuses loopback/private/HTTP when allowLocalLab === false
  await assert.rejects(
    () => startInteractiveLoginCapture({
      projectId: publicProj.id,
      targetOrigin: 'http://127.0.0.1:8080',
      allowLocalLab: false,
      launchBrowser: makeMockLauncher(makeSampleBundle()),
    }),
    /blocked for public projects/i,
  )
  await assert.rejects(
    () => startInteractiveLoginCapture({
      projectId: publicProj.id,
      targetOrigin: 'https://127.0.0.1:8443',
      allowLocalLab: false,
      launchBrowser: makeMockLauncher(makeSampleBundle()),
    }),
    /loopback|local hosts/i,
  )

  // And navigate() on an active public capture session refuses loopback/HTTP URLs
  const pubSession = await startInteractiveLoginCapture({
    projectId: publicProj.id,
    targetOrigin: 'https://app.example.test',
    allowLocalLab: false,
    launchBrowser: makeMockLauncher(makeSampleBundle()),
    resolveHost: async () => ['93.184.216.34'],
  })
  t.after(() => pubSession.dispose())
  await assert.rejects(() => pubSession.navigate('http://127.0.0.1:8080/secret'), /blocked/i)
  await assert.rejects(() => pubSession.navigate('https://127.0.0.1:8443/secret'), /loopback|local hosts/i)
  await assert.rejects(() => pubSession.navigate('https://169.254.169.254/latest/meta-data/'), /metadata|link-local/i)
})

// ---------------------------------------------------------------------------
// 4. Unified HTTP Control-Plane Guard: strict same-origin CSRF, HEAD /status, body-limiter
// ---------------------------------------------------------------------------

test('scripts/serve.ts enforces strict same-origin Sec-Fetch-Site, HEAD /_kovo/auth/status, JSON 401 for APIs, and safe body-limiter 413', async t => {
  // Unit assertions for isAllowedSecFetchSite
  assert.equal(isAllowedSecFetchSite('same-origin', false), true)
  assert.equal(isAllowedSecFetchSite(undefined, false), true)
  assert.equal(isAllowedSecFetchSite('same-site', false), false, 'Mutating requests must reject loose same-site')
  assert.equal(isAllowedSecFetchSite('cross-site', false), false)
  assert.equal(isAllowedSecFetchSite('none', false), false)
  assert.equal(isAllowedSecFetchSite('same-origin', true), true)
  assert.equal(isAllowedSecFetchSite('none', true), true)
  assert.equal(isAllowedSecFetchSite('same-site', true), false, 'Read-only requests must reject same-site')
  assert.equal(isAllowedSecFetchSite('cross-site', true), false)

  const dir = mkdtempSync(join(tmpdir(), 'kovo-u2-http-guard-'))
  t.after(() => rmSync(dir, { recursive: true, force: true }))
  const srv = await startTestLocalServer(dir, { maxBodyBytes: 1024 })
  t.after(() => srv.close())

  // Unauthenticated HEAD /_kovo/auth/status -> 401 with empty body & x-kovo-auth: expired
  const unauthHead = await fetch(`${srv.origin}/_kovo/auth/status`, { method: 'HEAD' })
  assert.equal(unauthHead.status, 401)
  assert.equal(unauthHead.headers.get('x-kovo-auth'), 'expired')
  assert.equal(await unauthHead.text(), '')

  // Authenticated HEAD /_kovo/auth/status -> 200 with empty body & x-kovo-auth: ok
  const authHead = await fetch(`${srv.origin}/_kovo/auth/status`, {
    method: 'HEAD',
    headers: { Cookie: srv.cookie },
  })
  assert.equal(authHead.status, 200)
  assert.equal(authHead.headers.get('x-kovo-auth'), 'ok')
  assert.equal(await authHead.text(), '')

  // Unauthenticated SSE & server-action paths return JSON 401 (not HTML)
  for (const apiPath of ['/api/runs/run-123/events', '/_serverFn/createProject']) {
    const res = await fetch(`${srv.origin}${apiPath}`)
    assert.equal(res.status, 401)
    assert.match(res.headers.get('content-type') ?? '', /application\/json/)
    const body = await res.json() as { code?: string }
    assert.equal(body.code, 'SESSION_EXPIRED')
  }

  // Strict Sec-Fetch-Site on mutating /_kovo/* and /_serverFn/* endpoints
  for (const mutPath of ['/_kovo/auth/pairing-link', '/_serverFn/testAction', '/api/ops/kill-switch']) {
    const sameSiteBlocked = await fetch(`${srv.origin}${mutPath}`, {
      method: 'POST',
      headers: {
        Cookie: srv.cookie,
        Origin: srv.origin,
        'Sec-Fetch-Site': 'same-site',
        'content-type': 'application/json',
      },
      body: JSON.stringify({}),
    })
    assert.equal(sameSiteBlocked.status, 403, `${mutPath} must reject Sec-Fetch-Site: same-site`)

    const crossSiteBlocked = await fetch(`${srv.origin}${mutPath}`, {
      method: 'POST',
      headers: {
        Cookie: srv.cookie,
        Origin: srv.origin,
        'Sec-Fetch-Site': 'cross-site',
        'content-type': 'application/json',
      },
      body: JSON.stringify({}),
    })
    assert.equal(crossSiteBlocked.status, 403, `${mutPath} must reject Sec-Fetch-Site: cross-site`)

    const noneBlocked = await fetch(`${srv.origin}${mutPath}`, {
      method: 'POST',
      headers: {
        Cookie: srv.cookie,
        Origin: srv.origin,
        'Sec-Fetch-Site': 'none',
        'content-type': 'application/json',
      },
      body: JSON.stringify({}),
    })
    assert.equal(noneBlocked.status, 403, `${mutPath} must reject Sec-Fetch-Site: none`)
  }

  // Valid same-origin POST succeeds
  const allowedMut = await fetch(`${srv.origin}/_serverFn/testAction`, {
    method: 'POST',
    headers: {
      Cookie: srv.cookie,
      Origin: srv.origin,
      'Sec-Fetch-Site': 'same-origin',
      'content-type': 'application/json',
    },
    body: JSON.stringify({ ok: true }),
  })
  assert.equal(allowedMut.status, 200)

  // Read-only same-site is also rejected
  const readSameSite = await fetch(`${srv.origin}/_kovo/auth/status`, {
    method: 'GET',
    headers: { Cookie: srv.cookie, 'Sec-Fetch-Site': 'same-site' },
  })
  assert.equal(readSameSite.status, 403)

  // Invalid tenantId rejected with 400 on /api/ops/kill-switch
  const badTenant = await fetch(`${srv.origin}/api/ops/kill-switch?tenantId=${encodeURIComponent('bad tenant/../../x')}`, {
    method: 'GET',
    headers: { Cookie: srv.cookie },
  })
  assert.equal(badTenant.status, 400)

  // Chunked POST exceeding maxBodyBytes (1024 bytes) without Content-Length returns 413 cleanly
  const chunkedStatus = await new Promise<number>((resolveStatus, rejectStatus) => {
    const req = httpRequest(
      {
        host: '127.0.0.1',
        port: srv.port,
        method: 'POST',
        path: '/_serverFn/chunkedTest',
        headers: {
          Cookie: srv.cookie,
          Origin: srv.origin,
          'Sec-Fetch-Site': 'same-origin',
          'Transfer-Encoding': 'chunked',
          'content-type': 'text/plain',
        },
      },
      res => {
        res.resume()
        res.once('end', () => resolveStatus(res.statusCode ?? 0))
      },
    )
    req.on('error', rejectStatus)
    req.write('A'.repeat(600))
    req.write('B'.repeat(600))
    req.write('C'.repeat(600))
    req.end()
  })
  assert.equal(chunkedStatus, 413, 'Chunked upload exceeding body limit must return 413 without crashing')

  // Server remains completely healthy after body-limiter overflow
  const afterOverflow = await fetch(`${srv.origin}/_kovo/auth/status`, {
    method: 'HEAD',
    headers: { Cookie: srv.cookie },
  })
  assert.equal(afterOverflow.status, 200)
})

// ---------------------------------------------------------------------------
// 5. PanelErrorBoundary Isolation & SSE 401 Session Expiry Diagnostics
// ---------------------------------------------------------------------------

function loadPanelErrorBoundary() {
  const fullPath = join(REPO_ROOT, 'src/components/run/panel-error-boundary.tsx')
  const src = readFileSync(fullPath, 'utf8')
  const stripped = src
    .replace(/^import .*$/gm, '')
    .replace(/^export class /m, 'class ')
    .replace(/^export interface [\s\S]*?\n\}/gm, '')
  const js = ts.transpileModule(stripped, {
    compilerOptions: {
      target: ts.ScriptTarget.ES2022,
      module: ts.ModuleKind.CommonJS,
      jsx: ts.JsxEmit.ReactJSX,
    },
  }).outputText
  const MockIcon = ({ name }: { name: string }) => React.createElement('svg', { 'data-icon': name })
  const mockRunBtn = () => 'btn'
  const mod = { exports: {} as Record<string, unknown> }
  const factory = new Function(
    'require',
    'exports',
    'module',
    'Component',
    'Icon',
    'runBtn',
    `${js}\nreturn { PanelErrorBoundary };`,
  )
  return factory(
    (id: string) => localRequire(id),
    mod.exports,
    mod,
    React.Component,
    MockIcon,
    mockRunBtn,
  ) as {
    PanelErrorBoundary: typeof React.Component<{
      panelName: string
      resetKey?: string
      entityId?: string
      onClose?: () => void
      onError?: (error: Error, componentStack: string) => void
      children?: React.ReactNode
    }> & {
      getDerivedStateFromError: (error: unknown) => Record<string, unknown>
    }
  }
}

test('PanelErrorBoundary isolates panel crashes, offers Reload panel recovery, and auto-resets on resetKey change', () => {
  const { PanelErrorBoundary } = loadPanelErrorBoundary()

  // 1. Healthy children render normally
  const healthyHtml = renderToStaticMarkup(
    React.createElement(
      PanelErrorBoundary,
      { panelName: 'Findings view', resetKey: 'run-1:findings', entityId: 'findings' },
      React.createElement('div', { 'data-testid': 'healthy-child' }, 'Healthy panel content'),
    ),
  )
  assert.match(healthyHtml, /Healthy panel content/)
  assert.doesNotMatch(healthyHtml, /This panel encountered an error/)

  // 2. Simulated child render crash triggers getDerivedStateFromError + componentDidCatch
  let reportedError: Error | null = null
  const boundary = new PanelErrorBoundary({
    panelName: 'Inspector panel',
    resetKey: 'run-1:finding:f-1',
    entityId: 'finding:f-1',
    onClose: () => {},
    onError: err => { reportedError = err },
    children: React.createElement('div', null, 'Recovered content'),
  }) as unknown as {
    props: Record<string, unknown>
    state: Record<string, unknown>
    setState: (patch: unknown) => void
    componentDidCatch: (error: Error, info: { componentStack: string }) => void
    componentDidUpdate: (prevProps: Record<string, unknown>) => void
    handleReload: () => void
    render: () => React.ReactElement
  }
  boundary.setState = (patch: unknown) => {
    const next = typeof patch === 'function' ? (patch as (prev: Record<string, unknown>) => Record<string, unknown>)(boundary.state) : patch
    boundary.state = { ...boundary.state, ...(next as Record<string, unknown>) }
  }

  const boom = new TypeError('Cannot read properties of undefined (reading "observed")')
  boundary.state = { ...boundary.state, ...PanelErrorBoundary.getDerivedStateFromError(boom) }
  boundary.componentDidCatch(boom, { componentStack: '\n    at FindingsInspector\n    at PaneContent' })
  assert.equal(reportedError, boom)

  const crashHtml = renderToStaticMarkup(boundary.render())
  assert.match(crashHtml, /data-testid="panel-error-boundary"/)
  assert.match(crashHtml, /This panel encountered an error/)
  assert.match(crashHtml, /Inspector panel \(finding:f-1\)/)
  assert.match(crashHtml, /Live updates and other panels remain active/)
  assert.match(crashHtml, /Cannot read properties of undefined/)
  assert.match(crashHtml, /data-testid="panel-error-reload"[^>]*>Reload panel<\/button>/)
  assert.match(crashHtml, /data-testid="panel-error-copy"[^>]*>Copy diagnostic<\/button>/)
  assert.match(crashHtml, /data-testid="panel-error-close"[^>]*>Close panel<\/button>/)

  // 3. Clicking "Reload panel" resets error state and increments retryNonce
  boundary.handleReload()
  assert.equal(boundary.state.hasError, false)
  assert.equal(boundary.state.retryNonce, 1)
  const reloadedHtml = renderToStaticMarkup(boundary.render())
  assert.match(reloadedHtml, /Recovered content/)

  // 4. Changing resetKey automatically clears an active error state (switching finding/view)
  boundary.state = { ...boundary.state, ...PanelErrorBoundary.getDerivedStateFromError(boom) }
  assert.equal(boundary.state.hasError, true)
  const prevProps = { ...boundary.props }
  boundary.props = { ...boundary.props, resetKey: 'run-1:finding:f-2', entityId: 'finding:f-2' }
  boundary.componentDidUpdate(prevProps)
  assert.equal(boundary.state.hasError, false)
})

test('shell.tsx wraps both <View /> and right-hand <aside> pane in PanelErrorBoundary and probes HEAD /_kovo/auth/status on reconnect', async t => {
  const shellSrc = readFileSync(join(REPO_ROOT, 'src/components/run/shell.tsx'), 'utf8')
  assert.match(shellSrc, /import \{ PanelErrorBoundary \} from '\.\/panel-error-boundary\.tsx'/)
  // Both main <View /> and right-hand Inspector/Board pane are wrapped
  const boundaryMatches = shellSrc.match(/<PanelErrorBoundary\b/g) ?? []
  assert.ok(boundaryMatches.length >= 2, 'Expected PanelErrorBoundary around both <View /> and right-hand pane')
  assert.match(shellSrc, /<PanelErrorBoundary[\s\S]*?<View \/>[\s\S]*?<\/PanelErrorBoundary>/)
  assert.match(shellSrc, /<PanelErrorBoundary[\s\S]*?<BoardPane \/>[\s\S]*?<\/PanelErrorBoundary>/)
  assert.match(shellSrc, /probeLocalAuthStatus/)
  assert.match(shellSrc, /\/_kovo\/auth\/status/)
  assert.match(shellSrc, /data-testid="session-expired-banner"/)
  assert.match(shellSrc, /Local session expired/)

  // Verify probeLocalAuthStatus behavior against a live local server (401 -> expired, 200 -> ok)
  const dir = mkdtempSync(join(tmpdir(), 'kovo-u2-probe-auth-'))
  t.after(() => rmSync(dir, { recursive: true, force: true }))
  const srv = await startTestLocalServer(dir)
  t.after(() => srv.close())

  // Extract probeLocalAuthStatus from shell.tsx
  const sf = ts.createSourceFile('shell.tsx', shellSrc, ts.ScriptTarget.ES2022, true, ts.ScriptKind.TSX)
  let fnSrc = ''
  for (const stmt of sf.statements) {
    if (ts.isFunctionDeclaration(stmt) && stmt.name?.text === 'probeLocalAuthStatus') {
      fnSrc = shellSrc.slice(stmt.getStart(sf), stmt.getEnd()).replace(/^export\s+/, '')
      break
    }
  }
  assert.ok(fnSrc, 'Expected probeLocalAuthStatus export in shell.tsx')
  const js = ts.transpileModule(fnSrc, {
    compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.CommonJS },
  }).outputText
  const probeLocalAuthStatus = new Function(`${js}\nreturn probeLocalAuthStatus;`)() as (
    fetchImpl?: typeof fetch,
  ) => Promise<'ok' | 'expired' | 'unreachable'>

  const unauthStatus = await probeLocalAuthStatus((url, init) =>
    fetch(`${srv.origin}${String(url)}`, init),
  )
  assert.equal(unauthStatus, 'expired')

  const authStatus = await probeLocalAuthStatus((url, init) =>
    fetch(`${srv.origin}${String(url)}`, {
      ...init,
      headers: { Cookie: srv.cookie },
    }),
  )
  assert.equal(authStatus, 'ok')

  const offlineStatus = await probeLocalAuthStatus(async () => {
    throw new Error('ECONNREFUSED')
  })
  assert.equal(offlineStatus, 'unreachable')
})
