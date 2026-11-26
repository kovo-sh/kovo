import assert from 'node:assert/strict'
import { once } from 'node:events'
import { mkdtempSync, readFileSync, rmSync } from 'node:fs'
import type { AddressInfo } from 'node:net'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import { afterEach, beforeEach, describe, it } from 'node:test'
import { createKovoLocalServer } from '../scripts/serve.ts'
import type { LocalApp } from '../scripts/serve.ts'
import { BrowserCaptureManager } from '../src/server/browser-session-auth.ts'
import type { CaptureStreamEvent, InteractiveLoginCaptureSession } from '../src/server/browser-session-auth.ts'
import { clearQaAnomalies, listQaAnomalies } from '../src/server/qa-anomalies.ts'
import type { QaAnomalyRecord } from '../src/server/qa-anomalies.ts'

const REPO_ROOT = resolve(import.meta.dirname, '..')

interface TestServerHandle {
  origin: string
  cookie: string
  close(): Promise<void>
}

async function startLocalServer(
  app: LocalApp,
  extra: Partial<Parameters<typeof createKovoLocalServer>[0]> = {},
): Promise<TestServerHandle> {
  const dir = mkdtempSync(join(tmpdir(), 'kovo-fix-run-header-qa-'))
  const probe = createKovoLocalServer({ app, directory: dir, port: 0, ...extra })
  probe.server.listen(0, '127.0.0.1')
  await once(probe.server, 'listening')
  const port = (probe.server.address() as AddressInfo).port
  probe.server.close()
  await once(probe.server, 'close')

  const local = createKovoLocalServer({ app, directory: dir, port, ...extra })
  local.server.listen(port, '127.0.0.1')
  await once(local.server, 'listening')

  const origin = `http://127.0.0.1:${port}`
  const cookie = `kovo_local=${local.token}`
  return {
    origin,
    cookie,
    async close() {
      local.server.closeAllConnections?.()
      local.server.close()
      await once(local.server, 'close')
      rmSync(dir, { recursive: true, force: true })
    },
  }
}

function makeFakeCapture(opts: {
  id: string
  projectId: string
  targetOrigin: string
  initialError?: string | null
}): {
  capture: InteractiveLoginCaptureSession
  emit: (event: CaptureStreamEvent) => void
} {
  const listeners = new Set<(event: CaptureStreamEvent) => void>()
  let lastErr: string | null = opts.initialError ?? null
  const nowMs = Date.now()
  const capture: InteractiveLoginCaptureSession = {
    id: opts.id,
    projectId: opts.projectId,
    targetOrigin: opts.targetOrigin,
    createdAt: nowMs,
    expiresAt: nowMs + 60_000,
    viewport: { width: 1280, height: 720 },
    state: 'active',
    currentUrl: () => `${opts.targetOrigin}/login`,
    lastError: () => lastErr,
    latestFrame: () => null,
    captureMetadata: () => ({
      verifyOrigin: opts.targetOrigin,
      verifyPath: '/',
      capturedAppOrigins: [opts.targetOrigin],
      capturedIdpOrigins: [],
    }),
    subscribe(listener) {
      listeners.add(listener)
      return () => {
        listeners.delete(listener)
      }
    },
    async dispatchMouse() {},
    async dispatchKey() {},
    async navigate(url: string) {
      return { url }
    },
    async completeCapture() {
      throw new Error('not used')
    },
    async cancelCapture() {
      listeners.clear()
    },
    async dispose() {
      listeners.clear()
    },
  }
  return {
    capture,
    emit(event) {
      if (event.type === 'error') lastErr = event.message || null
      for (const listener of [...listeners]) listener(event)
    },
  }
}

describe('RunHeader QA fixes (src/components/run/header.tsx)', () => {
  const headerSrc = readFileSync(join(REPO_ROOT, 'src/components/run/header.tsx'), 'utf8')

  it('gives interactive run-line buttons (rlBtnClass) >= 22px clickable height instead of collapsed h-3.5', () => {
    const match = /const rlBtnClass\s*=\s*'([^']+)'/.exec(headerSrc)
    assert.ok(match, 'Expected rlBtnClass constant in src/components/run/header.tsx')
    const tokens = new Set(match[1]!.split(/\s+/).filter(Boolean))
    assert.equal(tokens.has('h-3.5'), false, 'rlBtnClass must not use collapsed h-3.5 (14px < 20px)')
    assert.equal(tokens.has('min-h-[22px]'), true, 'rlBtnClass must enforce min-h-[22px]')
    assert.equal(tokens.has('py-0.5'), true, 'rlBtnClass must include compact vertical padding py-0.5')
    assert.equal(tokens.has('h-auto'), true, 'rlBtnClass must override bare button height via h-auto')
    assert.equal(tokens.has('shadow-none'), true, 'rlBtnClass must reset bare button shadow via shadow-none')
  })

  it('attaches role="menuitem" to dropdown menu item buttons rendered inside role="menu"', () => {
    assert.match(
      headerSrc,
      /const item\s*=\s*\([^\n]*\)\s*=>\s*\n\s*<button[^>]*role="menuitem"/,
      'item(...) helper must render <button ... role="menuitem">',
    )
    assert.match(headerSrc, /role="menu"/, 'Expected role="menu" container in RunHeader')
  })

  it('places suppressHydrationWarning directly on the inner <span> rendering fmtDur(dur)', () => {
    assert.match(
      headerSrc,
      /<span[^>]*suppressHydrationWarning[^>]*>\{[^}]*fmtDur\(dur\)/,
      'suppressHydrationWarning must sit on the inner <span> directly rendering fmtDur(dur)',
    )
    assert.doesNotMatch(
      headerSrc,
      /title=\{`Started \$\{fmtFullDateTime\(r\.createdAt\)\}`\}\s+suppressHydrationWarning>/,
      'suppressHydrationWarning should be moved off the outer wrapper <span> onto the inner duration <span>',
    )
  })
})

describe('Move-4 Opt-In QA Anomaly Endpoint & Recording (scripts/serve.ts)', () => {
  const prevEnv = process.env.KOVO_QA_ANOMALIES

  beforeEach(() => {
    delete process.env.KOVO_QA_ANOMALIES
    clearQaAnomalies()
  })

  afterEach(() => {
    clearQaAnomalies()
    if (prevEnv === undefined) delete process.env.KOVO_QA_ANOMALIES
    else process.env.KOVO_QA_ANOMALIES = prevEnv
  })

  it('returns 404 when KOVO_QA_ANOMALIES is not "1" (and 401 when unauthenticated), with zero-overhead no-op recording', async () => {
    const srv = await startLocalServer({
      fetch: () => new Response('upstream boom', { status: 502 }),
    })
    try {
      // Unauthenticated request gets JSON 401 before revealing whether the endpoint is enabled.
      const unauth = await fetch(`${srv.origin}/_kovo/qa/anomalies`)
      assert.equal(unauth.status, 401)
      assert.equal(unauth.headers.get('x-kovo-auth'), 'expired')
      const unauthJson = await unauth.json() as { code: string }
      assert.equal(unauthJson.code, 'SESSION_EXPIRED')

      // Authenticated GET & DELETE both return 404 when disabled.
      const getDisabled = await fetch(`${srv.origin}/_kovo/qa/anomalies`, {
        headers: { cookie: srv.cookie },
      })
      assert.equal(getDisabled.status, 404)

      const delDisabled = await fetch(`${srv.origin}/_kovo/qa/anomalies`, {
        method: 'DELETE',
        headers: { cookie: srv.cookie, origin: srv.origin },
      })
      assert.equal(delDisabled.status, 404)

      // Triggering a 502 while disabled records nothing.
      const boom = await fetch(`${srv.origin}/api/broken`, {
        headers: { cookie: srv.cookie },
      })
      assert.equal(boom.status, 502)
      assert.deepEqual(listQaAnomalies(), [])
    } finally {
      await srv.close()
    }
  })

  it('enforces local-session auth, Origin/Sec-Fetch-Site guards, method checks, and query validation when enabled', async () => {
    process.env.KOVO_QA_ANOMALIES = '1'
    const srv = await startLocalServer({
      fetch: () => new Response('ok', { status: 200 }),
    })
    try {
      const unauthGet = await fetch(`${srv.origin}/_kovo/qa/anomalies`)
      assert.equal(unauthGet.status, 401)

      const unauthDel = await fetch(`${srv.origin}/_kovo/qa/anomalies`, {
        method: 'DELETE',
        headers: { origin: srv.origin },
      })
      assert.equal(unauthDel.status, 401)

      const badOriginDel = await fetch(`${srv.origin}/_kovo/qa/anomalies`, {
        method: 'DELETE',
        headers: { cookie: srv.cookie, origin: 'https://evil.example.test' },
      })
      assert.equal(badOriginDel.status, 403)

      const crossSiteGet = await fetch(`${srv.origin}/_kovo/qa/anomalies`, {
        headers: { cookie: srv.cookie, 'sec-fetch-site': 'cross-site' },
      })
      assert.equal(crossSiteGet.status, 403)

      const sameSiteDel = await fetch(`${srv.origin}/_kovo/qa/anomalies`, {
        method: 'DELETE',
        headers: { cookie: srv.cookie, origin: srv.origin, 'sec-fetch-site': 'same-site' },
      })
      assert.equal(sameSiteDel.status, 403)

      const postMethod = await fetch(`${srv.origin}/_kovo/qa/anomalies`, {
        method: 'POST',
        headers: { cookie: srv.cookie, origin: srv.origin },
      })
      assert.equal(postMethod.status, 405)

      const badKind = await fetch(`${srv.origin}/_kovo/qa/anomalies?kind=unknown_kind`, {
        headers: { cookie: srv.cookie },
      })
      assert.equal(badKind.status, 400)

      const badLimit = await fetch(`${srv.origin}/_kovo/qa/anomalies?limit=-5`, {
        headers: { cookie: srv.cookie },
      })
      assert.equal(badLimit.status, 400)

      const badSince = await fetch(`${srv.origin}/_kovo/qa/anomalies?sinceTs=notanumber`, {
        headers: { cookie: srv.cookie },
      })
      assert.equal(badSince.status, 400)

      const okHead = await fetch(`${srv.origin}/_kovo/qa/anomalies`, {
        method: 'HEAD',
        headers: { cookie: srv.cookie },
      })
      assert.equal(okHead.status, 200)
    } finally {
      await srv.close()
    }
  })

  it('records sanitized server-side 5xx errors and unhandled throws, supports GET filters and DELETE clear', async () => {
    process.env.KOVO_QA_ANOMALIES = '1'
    const syntheticApiKey = 'sk-or-v1-abcdefghijklmnopqrstuvwxyz0123456789'
    const srv = await startLocalServer({
      fetch(req) {
        const url = new URL(req.url)
        if (url.pathname === '/api/fail-502') {
          return new Response('<!doctype html><html><body>SECRET_HTML_BODY_DO_NOT_LEAK</body></html>', { status: 502 })
        }
        if (url.pathname === '/api/throw-500') {
          throw new Error(
            `Downstream error Authorization: Bearer super_secret_token_99999 ${syntheticApiKey} <!doctype html><html><body>RAW_LEAK</body></html>`,
          )
        }
        return new Response('ok', { status: 200 })
      },
    })
    try {
      const r502 = await fetch(`${srv.origin}/api/fail-502?token=query_secret_abc&secret=${'b'.repeat(64)}`, {
        headers: {
          cookie: srv.cookie,
          authorization: 'Bearer header_secret_xyz',
        },
      })
      assert.equal(r502.status, 502)

      const r500 = await fetch(`${srv.origin}/api/throw-500?api_key=secret_key_777`, {
        headers: { cookie: srv.cookie },
      })
      assert.equal(r500.status, 500)

      const listRes = await fetch(`${srv.origin}/_kovo/qa/anomalies?kind=unexpected_ui_rpc_error`, {
        headers: { cookie: srv.cookie },
      })
      assert.equal(listRes.status, 200)
      const body = await listRes.json() as {
        enabled: boolean
        maxEntries: number
        count: number
        anomalies: QaAnomalyRecord[]
      }
      assert.equal(body.enabled, true)
      assert.equal(body.count, 2)
      assert.equal(body.anomalies[0]!.routeOrOrigin, '/api/fail-502')
      assert.equal(body.anomalies[0]!.detail?.statusCode, 502)
      assert.equal(body.anomalies[1]!.routeOrOrigin, '/api/throw-500')
      assert.equal(body.anomalies[1]!.detail?.statusCode, 500)

      // Strictly sanitized: zero secrets, query params, cookies, or raw HTML bodies.
      const serialized = JSON.stringify(body)
      for (const forbidden of [
        'query_secret_abc',
        'b'.repeat(64),
        'header_secret_xyz',
        'secret_key_777',
        'super_secret_token_99999',
        syntheticApiKey,
        'SECRET_HTML_BODY_DO_NOT_LEAK',
        'RAW_LEAK',
        srv.cookie,
      ]) {
        assert.equal(serialized.includes(forbidden), false, `Anomaly response must never contain "${forbidden}"`)
      }

      // Limit filter works.
      const limitedRes = await fetch(`${srv.origin}/_kovo/qa/anomalies?limit=1`, {
        headers: { cookie: srv.cookie },
      })
      assert.equal(limitedRes.status, 200)
      const limited = await limitedRes.json() as { count: number; anomalies: QaAnomalyRecord[] }
      assert.equal(limited.count, 1)
      assert.equal(limited.anomalies[0]!.routeOrOrigin, '/api/throw-500')

      // DELETE clears all recorded anomalies.
      const delRes = await fetch(`${srv.origin}/_kovo/qa/anomalies`, {
        method: 'DELETE',
        headers: { cookie: srv.cookie, origin: srv.origin },
      })
      assert.equal(delRes.status, 200)
      const delJson = await delRes.json() as { ok: boolean; cleared: boolean }
      assert.deepEqual(delJson, { ok: true, cleared: true })

      const afterClear = await fetch(`${srv.origin}/_kovo/qa/anomalies`, {
        headers: { cookie: srv.cookie },
      })
      const afterClearJson = await afterClear.json() as { count: number; anomalies: QaAnomalyRecord[] }
      assert.equal(afterClearJson.count, 0)
      assert.deepEqual(afterClearJson.anomalies, [])
    } finally {
      await srv.close()
    }
  })

  it('records sanitized interactive auth-capture nav_error events and ignores empty clearing error events', async () => {
    process.env.KOVO_QA_ANOMALIES = '1'
    const fake = makeFakeCapture({
      id: 'cap_qa_test_1234',
      projectId: 'proj_qa_1',
      targetOrigin: 'https://app.example.test',
    })
    const captureManager = {
      get: (id: string) => (id === fake.capture.id ? fake.capture : undefined),
      disposeAll: async () => {},
    } as unknown as BrowserCaptureManager

    const srv = await startLocalServer(
      { fetch: () => new Response('ok', { status: 200 }) },
      { captureManager },
    )
    const abort = new AbortController()
    try {
      const sseRes = await fetch(`${srv.origin}/_kovo/auth-capture/${fake.capture.id}/stream`, {
        headers: { cookie: srv.cookie, accept: 'text/event-stream' },
        signal: abort.signal,
      })
      assert.equal(sseRes.status, 200)
      const reader = sseRes.body!.getReader()
      // Consume initial `init` event so the server has subscribed to capture events.
      await reader.read()

      // 1. Real nav_error with query secret in URL & Cookie in message -> recorded & sanitized.
      fake.emit({
        type: 'error',
        message: 'Navigation failed with ERR_CONNECTION_REFUSED Cookie: sid=topsecret_cookie_123',
        url: 'https://app.example.test/oauth/cb?code=secret_oauth_code_999',
      })

      // 2. Empty message clearing a prior nav_error -> MUST NOT record a duplicate anomaly.
      fake.emit({
        type: 'error',
        message: '',
      })

      // 3. Proxy-denied error -> recorded as interactive_proxy_denied.
      fake.emit({
        type: 'error',
        message: 'Navigation blocked by scope policy (origin not allowed)',
        url: 'https://disallowed.example.test/admin?token=leaked_tok',
      })

      // Read a chunk so events have flushed.
      await reader.read()
      abort.abort()

      const res = await fetch(`${srv.origin}/_kovo/qa/anomalies`, {
        headers: { cookie: srv.cookie },
      })
      assert.equal(res.status, 200)
      const data = await res.json() as { count: number; anomalies: QaAnomalyRecord[] }
      assert.equal(data.count, 2, 'Expected exactly 2 anomalies (empty clearing event must be ignored)')
      assert.equal(data.anomalies[0]!.kind, 'swallowed_nav_error')
      assert.equal(data.anomalies[0]!.routeOrOrigin, 'https://app.example.test/oauth/cb')
      assert.equal(data.anomalies[1]!.kind, 'interactive_proxy_denied')
      assert.equal(data.anomalies[1]!.routeOrOrigin, 'https://disallowed.example.test/admin')

      const serialized = JSON.stringify(data)
      for (const forbidden of ['topsecret_cookie_123', 'secret_oauth_code_999', 'leaked_tok']) {
        assert.equal(serialized.includes(forbidden), false, `nav_error anomaly must never leak "${forbidden}"`)
      }
    } finally {
      abort.abort()
      await srv.close()
    }
  })
})
