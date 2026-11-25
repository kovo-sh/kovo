import assert from 'node:assert/strict'
import { once } from 'node:events'
import { existsSync, mkdtempSync, readdirSync, readFileSync, rmSync, statSync } from 'node:fs'
import { request as httpRequest } from 'node:http'
import { createServer } from 'node:net'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { test } from 'node:test'
import { createKovoLocalServer } from '../scripts/serve.ts'

async function availablePort(): Promise<number> {
  const probe = createServer().listen(0, '127.0.0.1')
  await once(probe, 'listening')
  const address = probe.address()
  if (!address || typeof address === 'string') throw new Error('Could not allocate a port.')
  await new Promise<void>(resolve => probe.close(() => resolve()))
  return address.port
}

async function startLocalServer(
  directory: string,
  extra: { publicOrigin?: string; pairingTtlMs?: number; now?: () => number } = {},
) {
  const port = await availablePort()
  let appFetches = 0
  const local = createKovoLocalServer({
    app: {
      fetch: async () => {
        appFetches += 1
        return new Response('<html><body>kovo app</body></html>', {
          headers: { 'content-type': 'text/html; charset=utf-8' },
        })
      },
    },
    directory,
    port,
    ...extra,
  })
  local.server.listen(port, '127.0.0.1')
  await once(local.server, 'listening')
  return {
    port,
    local,
    origin: `http://127.0.0.1:${port}`,
    appFetches: () => appFetches,
    close: async () => {
      local.server.closeAllConnections()
      await new Promise<void>(resolve => local.server.close(() => resolve()))
    },
  }
}

async function bootstrapSession(origin: string, secret: string): Promise<string> {
  const res = await fetch(`${origin}/?bootstrap=${secret}`, { redirect: 'manual' })
  assert.equal(res.status, 303)
  const setCookie = res.headers.get('set-cookie') ?? ''
  const cookie = setCookie.split(';')[0]
  assert.match(cookie, /^kovo_local=[a-f0-9]{64}$/)
  return cookie
}

async function rawRequest(
  port: number,
  options: { method: string; path: string; headers?: Record<string, string> },
): Promise<{ status: number; headers: Record<string, string | string[] | undefined>; body: string }> {
  return new Promise((resolve, reject) => {
    const req = httpRequest(
      { host: '127.0.0.1', port, method: options.method, path: options.path, headers: options.headers },
      res => {
        const chunks: Buffer[] = []
        res.on('data', chunk => chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk)))
        res.on('end', () => resolve({
          status: res.statusCode ?? 0,
          headers: res.headers,
          body: Buffer.concat(chunks).toString('utf8'),
        }))
      },
    )
    req.on('error', reject)
    req.end()
  })
}

test('unauthenticated POST /_kovo/auth/* is rejected with 401 and origin mismatch is rejected with 403', async t => {
  const dir = mkdtempSync(join(tmpdir(), 'kovo-device-pairing-unauth-'))
  t.after(() => rmSync(dir, { recursive: true, force: true }))
  const app = await startLocalServer(dir)
  t.after(() => app.close())

  for (const endpoint of ['/_kovo/auth/pairing-link', '/_kovo/auth/rotate-session']) {
    const unauth = await fetch(`${app.origin}${endpoint}`, {
      method: 'POST',
      headers: { Origin: app.origin },
    })
    assert.equal(unauth.status, 401, `${endpoint} must reject unauthenticated callers with 401`)
    assert.equal(unauth.headers.get('set-cookie'), null)
    assert.equal(unauth.headers.get('cache-control'), 'no-store')

    const badCookie = await fetch(`${app.origin}${endpoint}`, {
      method: 'POST',
      headers: { Origin: app.origin, Cookie: `kovo_local=${'0'.repeat(64)}` },
    })
    assert.equal(badCookie.status, 401)
    assert.equal(badCookie.headers.get('set-cookie'), null)
  }

  // Authenticated caller still requires exact matching Origin header
  const cookie = await bootstrapSession(app.origin, app.local.bootstrapSecret)
  for (const endpoint of ['/_kovo/auth/pairing-link', '/_kovo/auth/rotate-session']) {
    const missingOrigin = await fetch(`${app.origin}${endpoint}`, {
      method: 'POST',
      headers: { Cookie: cookie },
    })
    assert.equal(missingOrigin.status, 403, `${endpoint} must reject missing Origin`)

    const wrongOrigin = await fetch(`${app.origin}${endpoint}`, {
      method: 'POST',
      headers: { Origin: 'https://evil.example', Cookie: cookie },
    })
    assert.equal(wrongOrigin.status, 403, `${endpoint} must reject mismatched Origin`)

    const wrongMethod = await fetch(`${app.origin}${endpoint}`, {
      method: 'GET',
      headers: { Cookie: cookie },
    })
    assert.equal(wrongMethod.status, 405, `${endpoint} must reject GET with 405`)
  }

  assert.equal(app.appFetches(), 0, 'Local auth endpoints must never reach the application handler')
})

test('authenticated mint returns a single-use pairing link consumed by a second browser and rejected on replay', async t => {
  const dir = mkdtempSync(join(tmpdir(), 'kovo-device-pairing-mint-'))
  t.after(() => rmSync(dir, { recursive: true, force: true }))
  let nowMs = 1_770_000_000_000
  const app = await startLocalServer(dir, { now: () => nowMs })
  t.after(() => app.close())

  // Browser 1 authenticates via startup bootstrap secret (still works identically)
  const browser1Cookie = await bootstrapSession(app.origin, app.local.bootstrapSecret)
  assert.equal(existsSync(join(dir, 'bootstrap')), false, 'Startup bootstrap file must be consumed once')
  const replayStartup = await fetch(`${app.origin}/?bootstrap=${app.local.bootstrapSecret}`, { redirect: 'manual' })
  assert.equal(replayStartup.status, 401)

  // Browser 1 mints an ephemeral pairing link
  const mintRes = await fetch(`${app.origin}/_kovo/auth/pairing-link`, {
    method: 'POST',
    headers: { Origin: app.origin, Cookie: browser1Cookie },
  })
  assert.equal(mintRes.status, 200)
  assert.equal(mintRes.headers.get('cache-control'), 'no-store')
  const minted = await mintRes.json() as { url: string; expiresAt: string; ttlSeconds: number }
  assert.equal(minted.ttlSeconds, 300)
  assert.equal(minted.expiresAt, new Date(nowMs + 300_000).toISOString())
  assert.match(minted.url, new RegExp(`^${app.origin.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}/\\?bootstrap=[a-f0-9]{64}$`))

  // Pairing token must never equal the long-lived session token
  const pairingToken = new URL(minted.url).searchParams.get('bootstrap')!
  assert.notEqual(pairingToken, app.local.token)

  // Browser 2 exchanges the pairing link for a session cookie
  const exchange = await fetch(minted.url, { redirect: 'manual' })
  assert.equal(exchange.status, 303)
  assert.equal(exchange.headers.get('location'), '/')
  const setCookie2 = exchange.headers.get('set-cookie') ?? ''
  assert.match(setCookie2, /^kovo_local=[a-f0-9]{64}; Path=\/; HttpOnly; SameSite=Strict/)
  const browser2Cookie = setCookie2.split(';')[0]
  assert.equal(browser2Cookie, browser1Cookie)

  // Browser 2 can now access the app
  const page = await fetch(`${app.origin}/`, { headers: { Cookie: browser2Cookie } })
  assert.equal(page.status, 200)
  assert.match(await page.text(), /kovo app/)
  assert.equal(app.appFetches(), 1)

  // Replaying the same pairing link a second time must fail with 401
  const replay = await fetch(minted.url, { redirect: 'manual' })
  assert.equal(replay.status, 401)
  assert.equal(replay.headers.get('set-cookie'), null)
})

test('expired pairing tokens are rejected with 401 and active token cap evicts the oldest token beyond 10', async t => {
  const dir = mkdtempSync(join(tmpdir(), 'kovo-device-pairing-expiry-'))
  t.after(() => rmSync(dir, { recursive: true, force: true }))
  let nowMs = 1_770_000_000_000
  const app = await startLocalServer(dir, { now: () => nowMs })
  t.after(() => app.close())

  const cookie = await bootstrapSession(app.origin, app.local.bootstrapSecret)

  // Mint token that will expire after 5 minutes
  const expMint = await fetch(`${app.origin}/_kovo/auth/pairing-link`, {
    method: 'POST',
    headers: { Origin: app.origin, Cookie: cookie },
  })
  assert.equal(expMint.status, 200)
  const { url: expUrl } = await expMint.json() as { url: string }

  // Advance clock exactly 5 minutes -> token is expired and rejected
  nowMs += 5 * 60 * 1000
  const expiredExchange = await fetch(expUrl, { redirect: 'manual' })
  assert.equal(expiredExchange.status, 401)
  assert.equal(expiredExchange.headers.get('set-cookie'), null)

  // Mint 11 active tokens -> cap of 10 evicts the 1st token while keeping tokens 2..11 valid
  const urls: string[] = []
  for (let i = 0; i < 11; i += 1) {
    nowMs += 100
    const res = await fetch(`${app.origin}/_kovo/auth/pairing-link`, {
      method: 'POST',
      headers: { Origin: app.origin, Cookie: cookie },
    })
    assert.equal(res.status, 200)
    urls.push(((await res.json()) as { url: string }).url)
  }

  const evicted = await fetch(urls[0], { redirect: 'manual' })
  assert.equal(evicted.status, 401, '1st token must be evicted once 11th active token is minted')

  const newest = await fetch(urls[10], { redirect: 'manual' })
  assert.equal(newest.status, 303, '11th token must remain valid')

  const second = await fetch(urls[1], { redirect: 'manual' })
  assert.equal(second.status, 303, '2nd token must remain within the 10-token cap')
})

test('rotate-session atomically rotates local-session (0600), clears pending links, invalidates old cookies, and keeps caller signed in', async t => {
  const dir = mkdtempSync(join(tmpdir(), 'kovo-device-pairing-rotate-'))
  t.after(() => rmSync(dir, { recursive: true, force: true }))
  const app = await startLocalServer(dir)
  t.after(() => app.close())

  const originalToken = app.local.token
  const callerCookie = await bootstrapSession(app.origin, app.local.bootstrapSecret)

  // Pair a second browser AND leave a third pending pairing link unused
  const mintA = await fetch(`${app.origin}/_kovo/auth/pairing-link`, {
    method: 'POST',
    headers: { Origin: app.origin, Cookie: callerCookie },
  })
  const { url: pairUrlA } = await mintA.json() as { url: string }
  const pairResA = await fetch(pairUrlA, { redirect: 'manual' })
  assert.equal(pairResA.status, 303)
  const otherDeviceCookie = (pairResA.headers.get('set-cookie') ?? '').split(';')[0]

  const mintPending = await fetch(`${app.origin}/_kovo/auth/pairing-link`, {
    method: 'POST',
    headers: { Origin: app.origin, Cookie: callerCookie },
  })
  const { url: pendingUrl } = await mintPending.json() as { url: string }

  // Caller rotates the session
  const rotateRes = await fetch(`${app.origin}/_kovo/auth/rotate-session`, {
    method: 'POST',
    headers: { Origin: app.origin, Cookie: callerCookie },
  })
  assert.equal(rotateRes.status, 200)
  assert.equal(rotateRes.headers.get('cache-control'), 'no-store')
  assert.deepEqual(await rotateRes.json(), { rotated: true })

  const freshSetCookie = rotateRes.headers.get('set-cookie') ?? ''
  assert.match(freshSetCookie, /^kovo_local=[a-f0-9]{64}; Path=\/; HttpOnly; SameSite=Strict/)
  const freshCookie = freshSetCookie.split(';')[0]
  assert.notEqual(freshCookie, callerCookie, 'Rotated cookie must contain a brand-new session token')

  // Verify on-disk local-session was atomically rotated with 0600 permissions and matches live token
  const sessionFile = join(dir, 'local-session')
  const onDisk = readFileSync(sessionFile, 'utf8')
  assert.match(onDisk, /^[a-f0-9]{64}$/)
  assert.notEqual(onDisk, originalToken)
  assert.equal(onDisk, app.local.token)
  assert.equal(freshCookie, `kovo_local=${onDisk}`)
  assert.equal(statSync(sessionFile).mode & 0o077, 0, 'Rotated local-session must stay mode 0600')
  assert.equal(readdirSync(dir).some(f => f.endsWith('.tmp')), false, 'No temp files should remain after atomic rename')

  // Caller stays signed in with the newly issued cookie
  const callerOk = await fetch(`${app.origin}/`, { headers: { Cookie: freshCookie } })
  assert.equal(callerOk.status, 200)

  // Other device with old cookie is immediately signed out (401)
  const otherBlocked = await fetch(`${app.origin}/`, { headers: { Cookie: otherDeviceCookie } })
  assert.equal(otherBlocked.status, 401)
  const otherApiBlocked = await fetch(`${app.origin}/_kovo/auth/pairing-link`, {
    method: 'POST',
    headers: { Origin: app.origin, Cookie: otherDeviceCookie },
  })
  assert.equal(otherApiBlocked.status, 401)

  // Pending pairing link minted before rotation was cleared and is rejected
  const stalePair = await fetch(pendingUrl, { redirect: 'manual' })
  assert.equal(stalePair.status, 401)
  assert.equal(stalePair.headers.get('set-cookie'), null)
})

test('HTTPS publicOrigin mints HTTPS pairing links and sets Secure cookies on exchange and rotation', async t => {
  const dir = mkdtempSync(join(tmpdir(), 'kovo-device-pairing-https-'))
  t.after(() => rmSync(dir, { recursive: true, force: true }))
  const publicOrigin = 'https://kovo.local.example'
  const app = await startLocalServer(dir, { publicOrigin })
  t.after(() => app.close())

  // Bootstrap via the configured HTTPS proxy origin
  const boot = await rawRequest(app.port, {
    method: 'GET',
    path: `/?bootstrap=${app.local.bootstrapSecret}`,
    headers: { Host: 'kovo.local.example' },
  })
  assert.equal(boot.status, 303)
  const bootCookieHeader = String(boot.headers['set-cookie'] ?? '')
  assert.match(bootCookieHeader, /; Secure$/)
  const cookie = bootCookieHeader.split(';')[0]

  // Mint via HTTPS origin
  const mint = await rawRequest(app.port, {
    method: 'POST',
    path: '/_kovo/auth/pairing-link',
    headers: { Host: 'kovo.local.example', Origin: publicOrigin, Cookie: cookie },
  })
  assert.equal(mint.status, 200)
  const minted = JSON.parse(mint.body) as { url: string }
  assert.ok(minted.url.startsWith(`${publicOrigin}/?bootstrap=`))

  // Rotate via HTTPS origin sets Secure cookie
  const rot = await rawRequest(app.port, {
    method: 'POST',
    path: '/_kovo/auth/rotate-session',
    headers: { Host: 'kovo.local.example', Origin: publicOrigin, Cookie: cookie },
  })
  assert.equal(rot.status, 200)
  assert.match(String(rot.headers['set-cookie'] ?? ''), /; Secure$/)
})
