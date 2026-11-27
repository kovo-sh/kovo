import assert from 'node:assert/strict'
import { mkdtempSync, rmSync, statSync } from 'node:fs'
import { request as httpRequest } from 'node:http'
import type { AddressInfo } from 'node:net'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import test from 'node:test'
import { createKovoLocalServer, formatBootstrapBanner, readPinnedOrigin } from '../scripts/serve.ts'

async function sendRaw(
  port: number,
  options: {
    method?: string
    path?: string
    headers?: Record<string, string>
  },
): Promise<{ status: number; headers: Record<string, string | string[] | undefined>; body: string }> {
  return await new Promise((resolve, reject) => {
    const req = httpRequest(
      {
        host: '127.0.0.1',
        port,
        method: options.method ?? 'GET',
        path: options.path ?? '/',
        headers: options.headers ?? {},
      },
      res => {
        const chunks: Buffer[] = []
        res.on('data', c => chunks.push(Buffer.from(c)))
        res.on('end', () => {
          resolve({
            status: res.statusCode ?? 0,
            headers: res.headers,
            body: Buffer.concat(chunks).toString('utf8'),
          })
        })
      },
    )
    req.on('error', reject)
    req.end()
  })
}

async function startTestServer(
  dir: string,
  extra: Partial<Parameters<typeof createKovoLocalServer>[0]> = {},
) {
  let nowMs = 1_770_000_000_000
  const reminders: string[] = []
  const app = {
    fetch: () => new Response('ok-app', { status: 200 }),
  }
  const local = createKovoLocalServer({
    app,
    directory: dir,
    port: 0,
    now: () => nowMs,
    onBootstrapRemind: origin => reminders.push(origin),
    ...extra,
  })
  await new Promise<void>(resolve => local.server.listen(0, '127.0.0.1', resolve))
  const port = (local.server.address() as AddressInfo).port
  return {
    local,
    port,
    reminders,
    advanceClock: (ms: number) => { nowMs += ms },
    close: () => new Promise<void>(resolve => local.server.close(() => resolve())),
  }
}

test('TOFU HTTPS host pinning: plain HTTP unknown host gets 421, HTTPS proxy shows 401 form and pins on valid bootstrap', async t => {
  const dir = mkdtempSync(join(tmpdir(), 'kovo-tofu-'))
  t.after(() => rmSync(dir, { recursive: true, force: true }))

  const srv = await startTestServer(dir)
  t.after(() => srv.close())

  // 1. Plain HTTP unknown host (DNS rebinding) ALWAYS fails closed with 421, even with valid bootstrap secret
  const rebindPlain = await sendRaw(srv.port, {
    path: `/?bootstrap=${srv.local.bootstrapSecret}`,
    headers: { host: 'evil.example:8000' },
  })
  assert.equal(rebindPlain.status, 421)
  assert.equal(readPinnedOrigin(dir), undefined)

  // 2. HTTPS-proxied unknown host with WRONG bootstrap fails closed with 421 and does NOT pin
  const wrongSecret = await sendRaw(srv.port, {
    path: `/?bootstrap=${'0'.repeat(64)}`,
    headers: { host: 'kovo-test-1.exe.xyz', 'x-forwarded-proto': 'https' },
  })
  assert.equal(wrongSecret.status, 421)
  assert.equal(readPinnedOrigin(dir), undefined)

  // 3. HTTPS-proxied root visit before bootstrap returns 401 with interactive token form & triggers throttled reminder
  const formRes = await sendRaw(srv.port, {
    path: '/',
    headers: { host: 'kovo-test-1.exe.xyz', 'x-forwarded-proto': 'https' },
  })
  assert.equal(formRes.status, 401)
  assert.match(formRes.body, /<form method="GET" action="\/">/)
  assert.match(formRes.body, /name="bootstrap"/)
  assert.match(formRes.body, /https:\/\/kovo-test-1\.exe\.xyz/)
  assert.deepEqual(srv.reminders, ['https://kovo-test-1.exe.xyz'])

  // Immediate second hit is throttled (no duplicate reminder within 30s)
  await sendRaw(srv.port, {
    path: '/',
    headers: { host: 'kovo-test-1.exe.xyz', 'x-forwarded-proto': 'https' },
  })
  assert.equal(srv.reminders.length, 1)
  srv.advanceClock(31_000)
  await sendRaw(srv.port, {
    path: '/',
    headers: { host: 'kovo-test-1.exe.xyz', 'x-forwarded-proto': 'https' },
  })
  assert.equal(srv.reminders.length, 2)

  // 4. Valid bootstrap over HTTPS proxy pins the origin (mode 0600), sets Secure cookie, and redirects
  const bootRes = await sendRaw(srv.port, {
    path: `/?bootstrap=${srv.local.bootstrapSecret}`,
    headers: { host: 'kovo-test-1.exe.xyz', 'x-forwarded-proto': 'https' },
  })
  assert.equal(bootRes.status, 303)
  assert.equal(bootRes.headers.location, '/')
  const setCookie = String(bootRes.headers['set-cookie'] ?? '')
  assert.match(setCookie, /kovo_local=[a-f0-9]{64}/)
  assert.match(setCookie, /Secure/)
  assert.match(setCookie, /HttpOnly/)
  assert.match(setCookie, /SameSite=Strict/)

  assert.equal(readPinnedOrigin(dir), 'https://kovo-test-1.exe.xyz')
  assert.equal(statSync(join(dir, 'pinned-origin')).mode & 0o777, 0o600)

  // 5. Subsequent authenticated request on pinned host succeeds
  const appRes = await sendRaw(srv.port, {
    path: '/',
    headers: { host: 'kovo-test-1.exe.xyz', cookie: `kovo_local=${srv.local.token}` },
  })
  assert.equal(appRes.status, 200)
  assert.equal(appRes.body, 'ok-app')

  // 6. After bootstrap is consumed, ANY other host (even with X-Forwarded-Proto: https) gets 421
  const otherHost = await sendRaw(srv.port, {
    path: '/',
    headers: { host: 'attacker.exe.xyz', 'x-forwarded-proto': 'https' },
  })
  assert.equal(otherHost.status, 421)

  // 7. Persisted pinned-origin survives server restart without KOVO_PUBLIC_ORIGIN
  await srv.close()
  const srv2 = await startTestServer(dir)
  t.after(() => srv2.close())
  const afterRestart = await sendRaw(srv2.port, {
    path: '/',
    headers: { host: 'kovo-test-1.exe.xyz', cookie: `kovo_local=${srv2.local.token}` },
  })
  assert.equal(afterRestart.status, 200)
  assert.equal(afterRestart.body, 'ok-app')
})

test('explicit KOVO_PUBLIC_ORIGIN disables TOFU auto-pinning and failed bootstrap attempts are rate limited', async t => {
  const dir = mkdtempSync(join(tmpdir(), 'kovo-tofu-explicit-'))
  t.after(() => rmSync(dir, { recursive: true, force: true }))

  const srv = await startTestServer(dir, { publicOrigin: 'https://pinned.example.test' })
  t.after(() => srv.close())

  // Unconfigured HTTPS host is rejected even with valid bootstrap when explicit publicOrigin is set
  const rejected = await sendRaw(srv.port, {
    path: `/?bootstrap=${srv.local.bootstrapSecret}`,
    headers: { host: 'other.exe.xyz', 'x-forwarded-proto': 'https' },
  })
  assert.equal(rejected.status, 421)

  // 20 failed bootstrap attempts on the allowed origin trigger 429 on the 21st
  for (let i = 0; i < 20; i++) {
    const r = await sendRaw(srv.port, {
      path: `/?bootstrap=${'f'.repeat(64)}`,
      headers: { host: 'pinned.example.test' },
    })
    assert.equal(r.status, 401)
  }
  const limited = await sendRaw(srv.port, {
    path: `/?bootstrap=${srv.local.bootstrapSecret}`,
    headers: { host: 'pinned.example.test' },
  })
  assert.equal(limited.status, 429)

  // After 60s window expires, valid bootstrap succeeds
  srv.advanceClock(61_000)
  const ok = await sendRaw(srv.port, {
    path: `/?bootstrap=${srv.local.bootstrapSecret}`,
    headers: { host: 'pinned.example.test' },
  })
  assert.equal(ok.status, 303)

  const banner = formatBootstrapBanner({
    localUrl: `http://127.0.0.1:8000/?bootstrap=${srv.local.bootstrapSecret}`,
    secret: srv.local.bootstrapSecret,
  })
  assert.match(banner, /Token\s+: [a-f0-9]{64}/)
  assert.match(banner, /docker compose exec kovo cat \/data\/bootstrap/)
})
