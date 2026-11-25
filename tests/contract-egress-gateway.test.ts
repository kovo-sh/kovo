/**
 * Option 2 — Move 4 Contract & Unit Tests: Unified `EgressGateway` + Chromium Loopback Proxy
 * + Static Raw-Dialer Contract across `src/server/*.ts`.
 *
 * Verifies:
 *  1. IPv4 + IPv6 + IPv4-mapped IPv6 + cloud metadata SSRF blocking (`egressFetch`).
 *  2. Single-resolution pinned DNS (rebinding immunity) + preserved `Host` header.
 *  3. Manual redirect hopping with per-hop re-validation (refusing redirects to private/loopback/metadata IPs,
 *     cross-origin sensitive header stripping, bounded maxRedirects).
 *  4. Pinned-IP HTTP/2 execution (`egressHttp2`) + SSRF enforcement.
 *  5. Host loopback HTTP + HTTPS `CONNECT` proxy (`createLoopbackProxy`): pinned IP dialing, header
 *     injection/stripping hooks, and SSRF/metadata/scope refusal on both HTTP and CONNECT tunnels.
 *  6. `ScopedBrowser` integration: loopback proxy wired into `visitPage`, `visitPages`, and
 *     `runBrowserSession`, origin-locked storage hydration (`window.location.origin === targetOrigin`),
 *     and `EgressSanitizer` scrubbing.
 *  7. Static TypeScript AST contract test scanning `src/server/*.ts` for raw `fetch(`, `http.request(`,
 *     `https.request(`, `http2.connect(`, `undici.request(` against a tightly documented, shrinking
 *     Wave-2B migration allowlist (strictly forbidding `persona-auth.ts`, `scoped-browser.ts`, and any
 *     new file from bypassing `EgressGateway`).
 */
import assert from 'node:assert/strict'
import { once } from 'node:events'
import { readdirSync, readFileSync, statSync } from 'node:fs'
import { createServer as createHttpServer, request as nodeHttpRequest } from 'node:http'
import type { RequestListener } from 'node:http'
import { createServer as createH2Server } from 'node:http2'
import type { ServerHttp2Stream } from 'node:http2'
import { connect as netConnect, createServer as createTcpServer } from 'node:net'
import type { AddressInfo } from 'node:net'
import { join, relative, resolve } from 'node:path'
import { describe, test } from 'node:test'
import type { TestContext } from 'node:test'
import { gzipSync } from 'node:zlib'
import ts from 'typescript'
import { BrokerDenied, RequestBroker } from '../src/server/broker.ts'
import type { BrokerExchangeResult, BrokerHttpRequest, Grant } from '../src/server/broker.ts'
import {
  EgressDeniedError,
  EgressGateway,
  classifyAddress,
  classifyDetailedAddress,
  createLoopbackProxy,
  createPinnedLookup,
  egressFetch,
  egressHttp2,
  egressRawHttp1,
  isMetadataOrLinkLocalAddress,
  isPublicIpAddress,
} from '../src/server/egress-gateway.ts'
import {
  ScopedBrowser,
  chromiumLaunchArgs,
  originLockInitScript,
} from '../src/server/scoped-browser.ts'
import type { PlaywrightBrowserLike } from '../src/server/scoped-browser.ts'
import { VERIFY_NONCE_HEADER, VERIFY_RPC_HEADER, VerifyRpcServer } from '../src/server/verify-rpc.ts'

const repoRoot = resolve(new URL('..', import.meta.url).pathname)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

async function startLocalHttpServer(
  t: TestContext,
  handler: RequestListener,
): Promise<{ origin: string; port: number }> {
  const server = createHttpServer(handler)
  server.listen(0, '127.0.0.1')
  await once(server, 'listening')
  t.after(() => new Promise<void>(r => server.close(() => r())))
  const port = (server.address() as AddressInfo).port
  return { origin: `http://127.0.0.1:${port}`, port }
}

function sendProxyHttpRequest(
  proxyPort: number,
  targetUrl: string,
  headers: Record<string, string> = {},
): Promise<{ status: number; headers: Record<string, string | string[] | undefined>; body: string }> {
  return new Promise((resolvePromise, reject) => {
    const req = nodeHttpRequest({
      host: '127.0.0.1',
      port: proxyPort,
      path: targetUrl,
      method: 'GET',
      headers,
    }, res => {
      const chunks: Buffer[] = []
      res.on('data', chunk => chunks.push(Buffer.from(chunk)))
      res.on('end', () => {
        resolvePromise({
          status: res.statusCode ?? 0,
          headers: res.headers,
          body: Buffer.concat(chunks).toString('utf8'),
        })
      })
    })
    req.once('error', reject)
    req.end()
  })
}

function sendProxyConnect(
  proxyPort: number,
  authority: string,
  payloadAfterConnect?: string,
): Promise<{ statusLine: string; headers: Record<string, string>; body: string }> {
  return new Promise((resolvePromise, reject) => {
    const socket = netConnect({ host: '127.0.0.1', port: proxyPort }, () => {
      socket.write(`CONNECT ${authority} HTTP/1.1\r\nHost: ${authority}\r\n\r\n`)
    })
    let raw = ''
    let headersParsed = false
    let statusLine = ''
    const headers: Record<string, string> = {}
    let body = ''
    let sentPayload = false

    socket.setTimeout(3_000, () => {
      socket.destroy()
      resolvePromise({ statusLine, headers, body })
    })
    socket.on('data', chunk => {
      const text = chunk.toString('utf8')
      if (!headersParsed) {
        raw += text
        const idx = raw.indexOf('\r\n\r\n')
        if (idx >= 0) {
          headersParsed = true
          const head = raw.slice(0, idx)
          const rest = raw.slice(idx + 4)
          const lines = head.split('\r\n')
          statusLine = lines[0] ?? ''
          for (const line of lines.slice(1)) {
            const colon = line.indexOf(':')
            if (colon > 0) {
              headers[line.slice(0, colon).trim().toLowerCase()] = line.slice(colon + 1).trim()
            }
          }
          body += rest
          if (statusLine.includes('200') && payloadAfterConnect && !sentPayload) {
            sentPayload = true
            socket.write(payloadAfterConnect)
          } else if (!statusLine.includes('200')) {
            socket.end()
          }
        }
      } else {
        body += text
      }
    })
    socket.once('end', () => resolvePromise({ statusLine, headers, body }))
    socket.once('close', () => resolvePromise({ statusLine, headers, body }))
    socket.once('error', reject)
  })
}

// ---------------------------------------------------------------------------
// 1. Address Classification & Pinned-DNS SSRF Blocking (IPv4 + IPv6 + Metadata)
// ---------------------------------------------------------------------------

describe('EgressGateway: SSRF address classification & pinned-DNS enforcement', () => {
  test('classifies IPv4, IPv6, IPv4-mapped IPv6, and cloud metadata addresses fail-closed', () => {
    assert.equal(classifyDetailedAddress('93.184.216.34'), 'public')
    assert.equal(classifyDetailedAddress('2606:2800:220:1:248:1893:25c8:1946'), 'public')
    assert.equal(isPublicIpAddress('93.184.216.34'), true)
    assert.equal(isPublicIpAddress('2606:2800:220:1:248:1893:25c8:1946'), true)

    // Loopback
    assert.equal(classifyDetailedAddress('127.0.0.1'), 'loopback')
    assert.equal(classifyDetailedAddress('::1'), 'loopback')
    assert.equal(classifyDetailedAddress('::ffff:127.0.0.1'), 'loopback')
    assert.equal(classifyDetailedAddress('localhost'), 'loopback')
    assert.equal(classifyAddress('localhost'), 'loopback')

    // Private / ULA / CGNAT
    for (const addr of ['10.0.0.1', '172.16.0.5', '192.168.1.10', '::ffff:10.0.0.1', 'fc00::1', 'fd12:3456:789a::1', '100.64.0.1']) {
      assert.equal(classifyDetailedAddress(addr), 'private', `expected ${addr} to classify as private`)
      assert.equal(classifyAddress(addr), 'blocked', `expected coarse class for ${addr} to be blocked`)
      assert.equal(isPublicIpAddress(addr), false)
    }

    // Cloud metadata & link-local (IPv4 + IPv6 + zone ID + IPv4-mapped)
    for (const meta of [
      '169.254.169.254',
      '169.254.170.2',
      '169.254.1.1',
      '::ffff:169.254.169.254',
      'fe80::1',
      'fe80::1%eth0',
      'fd00:ec2::254',
      '100.100.100.200',
    ]) {
      assert.equal(classifyDetailedAddress(meta), 'metadata_or_link_local', `expected ${meta} to classify as metadata_or_link_local`)
      assert.equal(isMetadataOrLinkLocalAddress(meta), true)
      assert.equal(classifyAddress(meta), 'blocked')
    }

    // Unspecified & multicast & malformed
    for (const blocked of ['0.0.0.0', '::', '224.0.0.1', 'ff02::1', 'not-an-ip']) {
      assert.equal(classifyDetailedAddress(blocked), 'blocked', `expected ${blocked} to classify as blocked`)
    }
  })

  test('egressFetch refuses IPv4 private, IPv6 ULA/link-local, loopback, and metadata IPs', async () => {
    const cases: Array<{ name: string; ip: string; expectedCode: string; allowLocalLab?: boolean }> = [
      { name: 'IPv4 RFC1918 10/8', ip: '10.1.2.3', expectedCode: 'private_ip_blocked' },
      { name: 'IPv4 RFC1918 172.16/12', ip: '172.16.4.5', expectedCode: 'private_ip_blocked' },
      { name: 'IPv4 RFC1918 192.168/16', ip: '192.168.1.1', expectedCode: 'private_ip_blocked' },
      { name: 'IPv6 ULA fc00::/7', ip: 'fd12:3456::1', expectedCode: 'private_ip_blocked' },
      { name: 'IPv6 link-local fe80::/10', ip: 'fe80::1', expectedCode: 'metadata_blocked' },
      { name: 'IPv4 cloud metadata', ip: '169.254.169.254', expectedCode: 'metadata_blocked' },
      { name: 'IPv4-mapped IPv6 cloud metadata', ip: '::ffff:169.254.169.254', expectedCode: 'metadata_blocked' },
      { name: 'AWS IPv6 IMDS', ip: 'fd00:ec2::254', expectedCode: 'metadata_blocked' },
      { name: 'Cloud metadata blocked EVEN in localLab', ip: '169.254.169.254', expectedCode: 'metadata_blocked', allowLocalLab: true },
      { name: 'IPv6 link-local blocked EVEN in localLab', ip: 'fe80::1', expectedCode: 'metadata_blocked', allowLocalLab: true },
      { name: 'Loopback blocked without localLab', ip: '127.0.0.1', expectedCode: 'loopback_blocked' },
      { name: 'IPv6 loopback blocked without localLab', ip: '::1', expectedCode: 'loopback_blocked' },
    ]

    for (const tc of cases) {
      await assert.rejects(
        egressFetch('https://target.example/api', { method: 'GET' }, {
          allowLocalLab: tc.allowLocalLab ?? false,
          allowedPrivateHosts: tc.allowLocalLab ? ['target.example'] : undefined,
          resolveHost: async () => [tc.ip],
        }),
        (err: unknown) => err instanceof EgressDeniedError && err.code === tc.expectedCode,
        `Case "${tc.name}" must fail with ${tc.expectedCode}`,
      )
    }
  })

  test('egressFetch refuses empty DNS, unsupported schemes, and URL userinfo', async () => {
    await assert.rejects(
      egressFetch('https://nxdomain.example/api', {}, { resolveHost: async () => [] }),
      (err: unknown) => err instanceof EgressDeniedError && err.code === 'dns_empty',
    )
    await assert.rejects(
      egressFetch('file:///etc/passwd', {}, { allowLocalLab: true }),
      (err: unknown) => err instanceof EgressDeniedError && err.code === 'scheme_blocked',
    )
    await assert.rejects(
      egressFetch('https://user:pass@target.example/api', {}, { resolveHost: async () => ['93.184.216.34'] }),
      (err: unknown) => err instanceof EgressDeniedError && err.code === 'userinfo_blocked',
    )
  })

  test('egressFetch resolves DNS once, pins IP, and preserves Host header (immune to DNS rebinding)', async t => {
    const seenHosts: string[] = []
    const srv = await startLocalHttpServer(t, (req, res) => {
      seenHosts.push(String(req.headers.host ?? ''))
      res.writeHead(200, { 'content-type': 'application/json' })
      res.end(JSON.stringify({ ok: true, host: req.headers.host }))
    })

    let resolveCalls = 0
    const res = await egressFetch(`http://app.local-pin.test:${srv.port}/ping`, { method: 'GET' }, {
      allowLocalLab: true,
      resolveHost: async () => {
        resolveCalls += 1
        // Second call would rebind to metadata — must NEVER be consulted during dial!
        return resolveCalls === 1 ? ['127.0.0.1'] : ['169.254.169.254']
      },
    })

    assert.equal(res.status, 200)
    const body = await res.json() as { ok: boolean; host: string }
    assert.equal(body.ok, true)
    assert.equal(resolveCalls, 1, 'DNS must be resolved exactly once per hop')
    assert.equal(seenHosts[0], `app.local-pin.test:${srv.port}`, 'Original Host header must be preserved when dialing pinned IP')
  })

  test('createPinnedLookup refuses unvalidated hostnames', async () => {
    const lookup = createPinnedLookup('expected.example', ['93.184.216.34'])
    const ok = await new Promise<{ err?: Error; addr?: string }>(resolvePromise => {
      lookup('expected.example', {}, (err: unknown, addr: unknown) => {
        resolvePromise({ err: err as Error | undefined, addr: typeof addr === 'string' ? addr : undefined })
      })
    })
    assert.equal(ok.err, null)
    assert.equal(ok.addr, '93.184.216.34')

    const denied = await new Promise<Error | null>(resolvePromise => {
      lookup('evil.example', {}, (err: unknown) => resolvePromise(err as Error | null))
    })
    assert.ok(denied instanceof Error)
  })
})

// ---------------------------------------------------------------------------
// 2. Manual Redirect Hopping & Per-Hop Re-Validation
// ---------------------------------------------------------------------------

describe('EgressGateway: redirect-hop re-validation & header stripping', () => {
  test('returns 302 directly when followRedirects is false (default)', async t => {
    const srv = await startLocalHttpServer(t, (_req, res) => {
      res.writeHead(302, { location: 'http://169.254.169.254/latest/meta-data/' })
      res.end()
    })
    const res = await egressFetch(`${srv.origin}/start`, {}, { allowLocalLab: true })
    assert.equal(res.status, 302)
    assert.equal(res.headers.get('location'), 'http://169.254.169.254/latest/meta-data/')
  })

  test('refuses redirect to metadata IP (169.254.169.254) and private IP even when followRedirects is true', async t => {
    const srv = await startLocalHttpServer(t, (req, res) => {
      if (req.url === '/to-meta') {
        res.writeHead(302, { location: 'http://169.254.169.254/latest/meta-data/' })
        res.end()
        return
      }
      if (req.url === '/to-private') {
        res.writeHead(302, { location: 'https://internal.corp.example/admin' })
        res.end()
        return
      }
      if (req.url === '/loop') {
        res.writeHead(302, { location: '/loop' })
        res.end()
        return
      }
      res.writeHead(200)
      res.end('ok')
    })

    // Redirect to metadata IP refused even with allowLocalLab: true
    await assert.rejects(
      egressFetch(`${srv.origin}/to-meta`, {}, {
        allowLocalLab: true,
        followRedirects: true,
        maxRedirects: 3,
      }),
      (err: unknown) => err instanceof EgressDeniedError && err.code === 'metadata_blocked',
    )

    // Redirect to private IP refused when only the initial host is in allowedLoopbackOnlyHosts
    await assert.rejects(
      egressFetch(`http://127.0.0.1:${srv.port}/to-private`, {}, {
        allowLocalLab: false,
        allowHttp: true,
        allowedLoopbackOnlyHosts: ['127.0.0.1'],
        followRedirects: true,
        resolveHost: async host => host === '127.0.0.1' ? ['127.0.0.1'] : ['10.0.0.99'],
      }),
      (err: unknown) => err instanceof EgressDeniedError && err.code === 'private_ip_blocked',
    )

    // Bounded redirect hop limit enforced
    await assert.rejects(
      egressFetch(`${srv.origin}/loop`, {}, {
        allowLocalLab: true,
        followRedirects: true,
        maxRedirects: 2,
      }),
      (err: unknown) => err instanceof EgressDeniedError && err.code === 'redirect_limit',
    )
  })

  test('strips Authorization and Cookie headers on cross-origin redirect hops', async t => {
    let secondHopHeaders: Record<string, string | string[] | undefined> = {}
    const second = await startLocalHttpServer(t, (req, res) => {
      secondHopHeaders = { ...req.headers }
      res.writeHead(200, { 'content-type': 'text/plain' })
      res.end('landed')
    })
    const first = await startLocalHttpServer(t, (_req, res) => {
      res.writeHead(302, { location: `${second.origin}/final` })
      res.end()
    })

    const res = await egressFetch(`${first.origin}/start`, {
      headers: {
        Authorization: 'Bearer super_secret_token_1234',
        Cookie: 'sid=secret_cookie_5678',
        'X-Custom-Trace': 'keep-me',
      },
    }, {
      allowLocalLab: true,
      followRedirects: true,
    })

    assert.equal(res.status, 200)
    assert.equal(await res.text(), 'landed')
    assert.equal(secondHopHeaders.authorization, undefined, 'Authorization must be stripped on cross-origin hop')
    assert.equal(secondHopHeaders.cookie, undefined, 'Cookie must be stripped on cross-origin hop')
    assert.equal(secondHopHeaders['x-custom-trace'], 'keep-me')
  })
})

// ---------------------------------------------------------------------------
// 3. Pinned-IP HTTP/2 Helper (`egressHttp2`)
// ---------------------------------------------------------------------------

describe('EgressGateway: egressHttp2 pinned-IP HTTP/2 helper', () => {
  test('dials pinned IP with preserved :authority and enforces SSRF blocking', async t => {
    const seenAuthorities: string[] = []
    const h2 = createH2Server()
    h2.on('stream', (stream: ServerHttp2Stream, headers) => {
      seenAuthorities.push(String(headers[':authority'] ?? ''))
      stream.respond({ ':status': 200, 'content-type': 'application/json', 'x-proto': 'h2c' })
      stream.end(JSON.stringify({ ok: true, method: headers[':method'], path: headers[':path'] }))
    })
    await new Promise<void>(r => h2.listen(0, '127.0.0.1', r))
    t.after(() => new Promise<void>(r => h2.close(() => r())))
    const port = (h2.address() as AddressInfo).port

    let resolves = 0
    const res = await egressHttp2(`http://h2.local-pin.test:${port}/v2/status?ok=1`, {
      method: 'GET',
      headers: { 'x-probe': 'alpha' },
    }, {
      allowLocalLab: true,
      resolveHost: async () => {
        resolves += 1
        return ['127.0.0.1']
      },
    })
    assert.equal(res.status, 200)
    assert.equal(res.pinnedAddress, '127.0.0.1')
    assert.equal(res.headers['x-proto'], 'h2c')
    assert.equal(resolves, 1)
    assert.equal(seenAuthorities[0], `h2.local-pin.test:${port}`)
    const parsed = JSON.parse(res.body) as { ok: boolean; path: string }
    assert.equal(parsed.ok, true)
    assert.equal(parsed.path, '/v2/status?ok=1')

    // SSRF refusal on egressHttp2
    await assert.rejects(
      egressHttp2('https://meta.example/v2', {}, {
        allowLocalLab: true,
        resolveHost: async () => ['169.254.169.254'],
      }),
      (err: unknown) => err instanceof EgressDeniedError && err.code === 'metadata_blocked',
    )
    await assert.rejects(
      egressHttp2('https://ula.example/v2', {}, {
        allowLocalLab: false,
        resolveHost: async () => ['fd00::1'],
      }),
      (err: unknown) => err instanceof EgressDeniedError && err.code === 'private_ip_blocked',
    )
  })
})

// ---------------------------------------------------------------------------
// 4. Host Loopback HTTP + HTTPS CONNECT Proxy (`createLoopbackProxy`)
// ---------------------------------------------------------------------------

describe('EgressGateway: createLoopbackProxy HTTP + CONNECT enforcement', () => {
  test('enforces pinned DNS, SSRF/metadata refusal, header hooks, and CONNECT tunneling on 127.0.0.1', async t => {
    const seenCookieHeaders: string[] = []
    const httpTarget = await startLocalHttpServer(t, (req, res) => {
      seenCookieHeaders.push(String(req.headers.cookie ?? ''))
      res.writeHead(200, { 'content-type': 'text/plain', 'set-cookie': 'raw_secret=should_strip' })
      res.end(`ok:${req.headers.host}:${req.url}`)
    })

    // Raw TCP echo server to test CONNECT bidirectional tunneling
    const tcpServer = createTcpServer(socket => {
      socket.once('data', data => {
        socket.end(`TUNNEL_ECHO:${data.toString('utf8')}`)
      })
    })
    tcpServer.listen(0, '127.0.0.1')
    await once(tcpServer, 'listening')
    t.after(() => new Promise<void>(r => tcpServer.close(() => r())))
    const tcpPort = (tcpServer.address() as AddressInfo).port

    const deniedEvents: Array<{ code: string; url: string }> = []
    const proxy = await createLoopbackProxy({
      allowLocalLab: true,
      allowOrigin: origin =>
        origin === `http://allowed.local:${httpTarget.port}` ||
        origin === `http://tunnel.local:${tcpPort}` ||
        origin === `https://tunnel.local:${tcpPort}` ||
        origin === 'http://169.254.169.254' ||
        origin === 'https://169.254.169.254' ||
        origin === 'https://rebound.local',
      resolveHost: async host => {
        if (host === 'allowed.local' || host === 'tunnel.local') return ['127.0.0.1']
        if (host === 'rebound.local') return ['fe80::1']
        if (host === '169.254.169.254') return ['169.254.169.254']
        return ['10.0.0.5']
      },
      transformRequestHeaders: (_url, headers) => ({ ...headers, cookie: 'injected_session=1' }),
      transformResponseHeaders: (_url, headers) => {
        const next = { ...headers }
        delete next['set-cookie']
        return next
      },
      onDenied: ev => deniedEvents.push({ code: ev.code, url: ev.url }),
    })
    t.after(() => proxy.close())

    assert.equal(proxy.host, '127.0.0.1')
    assert.match(proxy.url, /^http:\/\/127\.0\.0\.1:\d+$/)

    // 1) Allowed HTTP request goes through pinned IP with request/response header hooks applied
    const allowedRes = await sendProxyHttpRequest(proxy.port, `http://allowed.local:${httpTarget.port}/hello`, {
      cookie: 'client_cookie=0',
    })
    assert.equal(allowedRes.status, 200)
    assert.equal(allowedRes.body, `ok:allowed.local:${httpTarget.port}:/hello`)
    assert.equal(seenCookieHeaders[0], 'injected_session=1', 'transformRequestHeaders hook must run before forwarding')
    assert.equal(allowedRes.headers['set-cookie'], undefined, 'transformResponseHeaders hook must strip Set-Cookie')

    // 2) Cloud metadata HTTP request refused even when allowOrigin returns true and allowLocalLab is true
    const metaHttp = await sendProxyHttpRequest(proxy.port, 'http://169.254.169.254/latest/meta-data/')
    assert.equal(metaHttp.status, 403)
    assert.equal(metaHttp.headers['x-kovo-egress-denied'], 'metadata_blocked')

    // 3) Off-scope HTTP request refused
    const offScopeHttp = await sendProxyHttpRequest(proxy.port, 'http://offscope.example/secret')
    assert.equal(offScopeHttp.status, 403)
    assert.equal(offScopeHttp.headers['x-kovo-egress-denied'], 'scope_denied')

    // 4) Allowed CONNECT tunnel establishes 200 and tunnels traffic via pinned IP
    const okConnect = await sendProxyConnect(proxy.port, `tunnel.local:${tcpPort}`, 'PING_H2')
    assert.match(okConnect.statusLine, /^HTTP\/1\.1 200 /)
    assert.equal(okConnect.body, 'TUNNEL_ECHO:PING_H2')

    // 5) Cloud metadata CONNECT refused
    const metaConnect = await sendProxyConnect(proxy.port, '169.254.169.254:443')
    assert.match(metaConnect.statusLine, /^HTTP\/1\.1 403 /)
    assert.equal(metaConnect.headers['x-kovo-egress-denied'], 'metadata_blocked')

    // 6) IPv6 link-local DNS-rebound CONNECT refused
    const ipv6LlConnect = await sendProxyConnect(proxy.port, 'rebound.local:443')
    assert.match(ipv6LlConnect.statusLine, /^HTTP\/1\.1 403 /)
    assert.equal(ipv6LlConnect.headers['x-kovo-egress-denied'], 'metadata_blocked')

    // 7) Off-scope CONNECT refused
    const offScopeConnect = await sendProxyConnect(proxy.port, 'attacker.example:443')
    assert.match(offScopeConnect.statusLine, /^HTTP\/1\.1 403 /)
    assert.equal(offScopeConnect.headers['x-kovo-egress-denied'], 'scope_denied')

    assert.ok(deniedEvents.some(e => e.code === 'metadata_blocked'))
    assert.ok(deniedEvents.some(e => e.code === 'scope_denied'))
  })

  test('CONNECT refuses private IPv4 and IPv6 ULA when allowLocalLab is false', async t => {
    const proxy = await createLoopbackProxy({
      allowLocalLab: false,
      allowOrigin: () => true,
      resolveHost: async host => {
        if (host === 'priv4.example') return ['10.20.30.40']
        if (host === 'ula6.example') return ['fc00::1234']
        return []
      },
    })
    t.after(() => proxy.close())

    const r4 = await sendProxyConnect(proxy.port, 'priv4.example:443')
    assert.match(r4.statusLine, /^HTTP\/1\.1 403 /)
    assert.equal(r4.headers['x-kovo-egress-denied'], 'private_ip_blocked')

    const r6 = await sendProxyConnect(proxy.port, 'ula6.example:443')
    assert.match(r6.statusLine, /^HTTP\/1\.1 403 /)
    assert.equal(r6.headers['x-kovo-egress-denied'], 'private_ip_blocked')
  })
})

// ---------------------------------------------------------------------------
// 5. ScopedBrowser Loopback Proxy + Origin-Locked Storage Hydration
// ---------------------------------------------------------------------------

describe('ScopedBrowser: EgressGateway loopback proxy & origin-locked storage hydration', () => {
  test('wires EgressGateway loopback proxy into Playwright contexts and origin-locks storage hydration', async t => {
    const prevLab = process.env.KOVO_ALLOW_LOCAL_LAB
    process.env.KOVO_ALLOW_LOCAL_LAB = '1'
    t.after(() => {
      if (prevLab === undefined) delete process.env.KOVO_ALLOW_LOCAL_LAB
      else process.env.KOVO_ALLOW_LOCAL_LAB = prevLab
    })

    const launchArgs = chromiumLaunchArgs()
    assert.ok(launchArgs.includes('--host-resolver-rules=MAP * ~NOTFOUND, EXCLUDE 127.0.0.1'))
    assert.ok(launchArgs.includes('--proxy-bypass-list=<-loopback>'))

    const contextOptionsSeen: Array<Record<string, unknown>> = []
    const initScriptsSeen: string[] = []
    const liveProxyChecks: Array<{ metaStatus: string; offScopeStatus: string }> = []

    const targetOrigin = 'http://127.0.0.1:44123'
    const secretToken = 'sb_secret_session_value_99887766'

    const fakeBrowser: PlaywrightBrowserLike = {
      newContext: async (options = {}) => {
        contextOptionsSeen.push(options)
        const proxyObj = options.proxy as { server?: string } | undefined
        if (proxyObj?.server && liveProxyChecks.length === 0) {
          const proxyPort = Number(new URL(proxyObj.server).port)
          const meta = await sendProxyConnect(proxyPort, '169.254.169.254:443')
          const offScope = await sendProxyConnect(proxyPort, 'evil.example:443')
          liveProxyChecks.push({ metaStatus: meta.statusLine, offScopeStatus: offScope.statusLine })
        }
        return {
          addInitScript: async script => {
            initScriptsSeen.push(typeof script === 'string' ? script : script.toString())
          },
          addCookies: async () => undefined,
          route: async () => undefined,
          routeWebSocket: async () => undefined,
          newPage: async () => ({
            on: () => undefined,
            goto: async () => ({ status: () => 200 }),
            waitForTimeout: async () => undefined,
            waitForLoadState: async () => undefined,
            url: () => `${targetOrigin}/app`,
            title: async () => `Page ${secretToken}`,
            evaluate: async () => ({
              domHtml: `<html><body>hello ${secretToken}</body></html>`,
              links: [],
              forms: [],
              cookieNames: [],
              localStorageKeys: ['auth_tok'],
              sessionStorageKeys: [],
              postMessageListeners: {
                count: 0, hasOnMessage: false, handlers: [], observedEvents: 0, canaryHandledWithoutOriginCheck: false,
              },
              canaryTriggered: false,
              canaryDetail: null,
              sinkTraces: [],
              selectorResult: null,
              fetchResult: null,
            }) as never,
            close: async () => undefined,
          }),
          close: async () => undefined,
        }
      },
      close: async () => undefined,
    }

    const fakeBroker = {
      executeHttp: async (req: BrokerHttpRequest): Promise<BrokerExchangeResult> => ({
        origin: req.origin,
        finalOrigin: req.origin,
        redirectOrigins: [req.origin],
        method: req.method,
        pathAndQuery: req.pathAndQuery,
        personaHandle: null,
        status: 200,
        mediaType: 'text/html',
        reqHeaders: {},
        respHeaders: {},
        setCookies: [],
        bodyPreview: '',
        body: '<html></html>',
        bodySha256: '0'.repeat(64),
        bodyBytes: 13,
        bodyTruncated: false,
        durationMs: 1,
        observation: { source: 'fixture' },
      } as unknown as BrokerExchangeResult),
      sessionCookiesForBrowser: () => [],
      getRegisteredSecrets: () => [{ value: secretToken, placeholder: '[persona:test:secret]' }],
      getStorage: () => undefined,
    } as unknown as RequestBroker

    const grant: Grant = {
      canRead: origin => origin === targetOrigin,
      audit: () => undefined,
      allowLocalLab: true,
      tier: 2,
    }

    const scoped = new ScopedBrowser(fakeBroker, {
      launchBrowser: async () => fakeBrowser,
      proxyResolveHost: async host => host === '169.254.169.254' ? ['169.254.169.254'] : ['93.184.216.34'],
    })
    t.after(() => scoped.close())

    // Test visitPage with an unguarded initScript in sessionBundle -> must be origin-locked!
    const visit = await scoped.visitPage({
      origin: targetOrigin,
      pathAndQuery: '/app',
      sessionBundle: {
        initScript: 'window.localStorage.setItem("auth_tok", "hydrated");',
      },
    }, grant, AbortSignal.timeout(10_000))

    assert.equal(contextOptionsSeen.length, 1)
    const proxyCfg = contextOptionsSeen[0]!.proxy as { server?: string } | undefined
    assert.ok(proxyCfg?.server, 'BrowserContext must receive EgressGateway loopback proxy config')
    assert.match(proxyCfg.server, /^http:\/\/127\.0\.0\.1:\d+$/)

    // Live loopback proxy blocked both metadata and off-scope CONNECT attempts
    assert.equal(liveProxyChecks.length, 1)
    assert.match(liveProxyChecks[0]!.metaStatus, /^HTTP\/1\.1 403 /)
    assert.match(liveProxyChecks[0]!.offScopeStatus, /^HTTP\/1\.1 403 /)

    // Storage hydration script is strictly origin-locked to targetOrigin
    const storageInit = initScriptsSeen.find(s => s.includes('auth_tok'))
    assert.ok(storageInit, 'storage hydration init script must be installed')
    assert.ok(
      storageInit.includes(`window.location.origin !== ${JSON.stringify(targetOrigin)}`),
      'storage hydration script must enforce window.location.origin === targetOrigin',
    )

    // EgressSanitizer scrubbed secretToken from BrowserVisitResult
    const serialized = JSON.stringify(visit)
    assert.equal(serialized.includes(secretToken), false, 'BrowserVisitResult must scrub secrets via EgressSanitizer')

    // Standalone helper check
    const locked = originLockInitScript('window.localStorage.setItem("k","v")', 'https://app.example')
    assert.ok(locked.includes('window.location.origin !== "https://app.example"'))
  })
})

// ---------------------------------------------------------------------------
// 5b. RequestBroker HTTP/1.1 & VerifyRpcServer HTTP/2 via EgressGateway
// ---------------------------------------------------------------------------

describe('RequestBroker & VerifyRpcServer: migrated to EgressGateway', () => {
  test('egressRawHttp1 preserves header order, decompresses gzip, caps body bytes, and blocks metadata IPs', async t => {
    const seenHeaderOrder: string[] = []
    const srv = await startLocalHttpServer(t, (req, res) => {
      for (let i = 0; i < req.rawHeaders.length; i += 2) {
        seenHeaderOrder.push(req.rawHeaders[i]!)
      }
      if (req.url === '/gzip') {
        const gz = gzipSync(Buffer.from('hello-compressed-payload', 'utf8'))
        res.writeHead(200, { 'content-type': 'text/plain', 'content-encoding': 'gzip' })
        res.end(gz)
        return
      }
      if (req.url === '/large') {
        res.writeHead(200, { 'content-type': 'text/plain' })
        res.end('A'.repeat(2048))
        return
      }
      res.writeHead(200, { 'content-type': 'text/plain' })
      res.end('ok')
    })

    const gzRes = await egressRawHttp1(new URL(`http://order.local:${srv.port}/gzip`), { address: '127.0.0.1', family: 4 }, {
      method: 'GET',
      headers: {
        Host: `order.local:${srv.port}`,
        'X-First': '1',
        'X-Second': '2',
      },
      readBody: true,
    })
    assert.equal(gzRes.status, 200)
    assert.equal(gzRes.body, 'hello-compressed-payload')
    assert.equal(gzRes.headers['content-encoding'], undefined)
    assert.ok(seenHeaderOrder.indexOf('X-First') >= 0 && seenHeaderOrder.indexOf('X-First') < seenHeaderOrder.indexOf('X-Second'))

    const truncRes = await egressRawHttp1(new URL(`${srv.origin}/large`), { address: '127.0.0.1', family: 4 }, {
      method: 'GET',
      readBody: true,
      maxBodyBytes: 128,
    })
    assert.equal(truncRes.status, 200)
    assert.equal(truncRes.bodyTruncated, true)
    assert.equal(truncRes.bodyBytes, 128)
    assert.equal(truncRes.body.length, 128)

    await assert.rejects(
      egressRawHttp1(new URL('http://169.254.169.254/latest/meta-data/'), { address: '169.254.169.254', family: 4 }, { readBody: true }),
      (err: unknown) => err instanceof EgressDeniedError && err.code === 'metadata_blocked',
    )
  })

  test('RequestBroker routes HTTP/1.1 through EgressGateway and blocks cloud metadata even in localLab', async t => {
    const prevLab = process.env.KOVO_ALLOW_LOCAL_LAB
    process.env.KOVO_ALLOW_LOCAL_LAB = '1'
    t.after(() => {
      if (prevLab === undefined) delete process.env.KOVO_ALLOW_LOCAL_LAB
      else process.env.KOVO_ALLOW_LOCAL_LAB = prevLab
    })

    const srv = await startLocalHttpServer(t, (req, res) => {
      const gz = gzipSync(Buffer.from(JSON.stringify({ host: req.headers.host, path: req.url }), 'utf8'))
      res.writeHead(200, { 'content-type': 'application/json', 'content-encoding': 'gzip' })
      res.end(gz)
    })

    const broker = new RequestBroker({
      resolve: async host => host === 'meta.local'
        ? [{ address: 'fd00:ec2::254', family: 6 }]
        : [{ address: '127.0.0.1', family: 4 }],
    })
    const grant: Grant = {
      canRead: () => true,
      audit: () => undefined,
      allowLocalLab: true,
      allowedPorts: [srv.port, 80],
      tier: 1,
    }

    const ex = await broker.executeHttp({
      origin: `http://broker-pin.local:${srv.port}`,
      method: 'GET',
      pathAndQuery: '/check?via=egress',
    }, grant, AbortSignal.timeout(5_000))
    assert.equal(ex.status, 200)
    const body = JSON.parse(ex.body) as { host: string; path: string }
    assert.equal(body.host, `broker-pin.local:${srv.port}`)
    assert.equal(body.path, '/check?via=egress')

    await assert.rejects(
      broker.executeHttp({
        origin: 'http://meta.local:80',
        method: 'GET',
        pathAndQuery: '/latest/meta-data/',
      }, grant, AbortSignal.timeout(5_000)),
      (err: unknown) => err instanceof BrokerDenied && /link-local\/metadata/i.test(err.message),
    )
  })

  test('VerifyRpcServer HTTP/2 routes through EgressGateway.egressHttp2 and enforces SSRF/metadata refusal', async t => {
    const prevLab = process.env.KOVO_ALLOW_LOCAL_LAB
    process.env.KOVO_ALLOW_LOCAL_LAB = '1'
    t.after(() => {
      if (prevLab === undefined) delete process.env.KOVO_ALLOW_LOCAL_LAB
      else process.env.KOVO_ALLOW_LOCAL_LAB = prevLab
    })

    const seenAuthorities: string[] = []
    const sessions = new Set<import('node:http2').ServerHttp2Session>()
    const h2 = createH2Server()
    h2.on('session', session => {
      sessions.add(session)
      session.once('close', () => sessions.delete(session))
    })
    h2.on('stream', (stream: ServerHttp2Stream, headers) => {
      seenAuthorities.push(String(headers[':authority'] ?? ''))
      stream.respond({ ':status': 200, 'content-type': 'application/json' })
      stream.end(JSON.stringify({ ok: true, authority: headers[':authority'] }))
    })
    await new Promise<void>(r => h2.listen(0, '127.0.0.1', r))
    t.after(async () => {
      for (const s of sessions) s.destroy()
      await new Promise<void>(r => h2.close(() => r()))
    })
    const port = (h2.address() as AddressInfo).port
    const pinnedOrigin = `http://127.0.0.1:${port}`
    const metaOrigin = 'http://169.254.169.254'

    const broker = new RequestBroker()
    const grant: Grant = {
      canRead: origin => origin === pinnedOrigin || origin === metaOrigin,
      audit: () => undefined,
      allowLocalLab: true,
      allowedPorts: [port, 80],
      tier: 1,
    }
    const rpcServer = new VerifyRpcServer({
      broker,
      grant,
      runId: 'egress-h2-wire',
      assignmentId: 'assign-h2-wire',
      targetOrigins: [pinnedOrigin, metaOrigin],
    })
    await rpcServer.start()
    t.after(() => rpcServer.close())

    const callRpc = (args: Record<string, unknown>) =>
      new Promise<{ ok: boolean; result?: unknown; error?: string }>((resolvePromise, reject) => {
        const payload = JSON.stringify({ op: 'http2', args })
        const req = nodeHttpRequest({
          socketPath: rpcServer.socketPath,
          path: '/rpc',
          method: 'POST',
          headers: {
            'content-type': 'application/json',
            'content-length': Buffer.byteLength(payload),
            [VERIFY_RPC_HEADER]: rpcServer.token,
            [VERIFY_NONCE_HEADER]: rpcServer.nonce,
          },
        }, res => {
          const chunks: Buffer[] = []
          res.on('data', chunk => chunks.push(Buffer.from(chunk)))
          res.on('end', () => {
            try { resolvePromise(JSON.parse(Buffer.concat(chunks).toString('utf8')) as { ok: boolean; result?: unknown; error?: string }) } catch (e) { reject(e) }
          })
        })
        req.once('error', reject)
        req.end(payload)
      })

    const ok = await callRpc({ origin: pinnedOrigin, method: 'GET', path: '/h2-ok' })
    assert.equal(ok.ok, true, ok.error ?? 'expected pinned HTTP/2 via EgressGateway to succeed')
    assert.equal(seenAuthorities[0], `127.0.0.1:${port}`)

    const blocked = await callRpc({ origin: metaOrigin, method: 'GET', path: '/latest/meta-data/' })
    assert.equal(blocked.ok, false)
    assert.match(blocked.error ?? '', /link-local|metadata|never permitted/i)
    const lastRecord = rpcServer.transcript.list().at(-1)
    assert.equal(lastRecord?.errorCode, 'denied')
  })
})

// ---------------------------------------------------------------------------
// 6. Static TypeScript AST Contract Test: Zero Unapproved Raw Dialers in src/server/
// ---------------------------------------------------------------------------

/**
 * Tightly documented, shrinking migration allowlist for Wave 2B.
 *
 * Rules:
 *  - `src/server/egress-gateway.ts` is the canonical outbound dialer (exempt).
 *  - `src/server/persona-auth.ts`, `src/server/scoped-browser.ts`, `src/server/broker.ts`,
 *    and `src/server/verify-rpc.ts` are MIGRATED and strictly FORBIDDEN from appearing here.
 *  - Any NEW file in `src/server/` MUST route outbound target traffic through `EgressGateway`
 *    and will FAIL this contract test if it calls raw `fetch(`, `http.request(`, `https.request(`,
 *    `http2.connect(`, or `undici.request(`.
 *  - Entries are removed as Wave 2B migrates each module; stale allowlist entries also fail the test.
 */
const WAVE_2B_RAW_DIALER_ALLOWLIST: Readonly<Record<string, string>> = {
  'src/server/transport.ts': 'Wave 2B: RequestBroker Layer-1 HTTP/1.1 + HTTP/2 transport plumbing',
  'src/server/provider.ts': 'Wave 2B: LLM provider API client',
  'src/server/cve-broker.ts': 'Wave 2B: OSV advisory lookup API client',
  'src/server/github-auth.ts': 'Wave 2B: GitHub OAuth / API client',
  'src/server/github-repo-sync.ts': 'Wave 2B: GitHub repository sync client',
  'src/server/subdomain-discovery.ts': 'Wave 2B: passive CT / OSINT lookup client',
  'src/server/lab-proxy.ts': 'Wave 2B: local-lab telemetry proxy client',
  'src/server/execution.ts': 'Wave 2B: offline fixture server transport seam',
}

function collectServerTsFiles(dir: string): string[] {
  const out: string[] = []
  for (const entry of readdirSync(dir)) {
    const abs = join(dir, entry)
    const st = statSync(abs)
    if (st.isDirectory()) {
      out.push(...collectServerTsFiles(abs))
    } else if (entry.endsWith('.ts')) {
      out.push(abs)
    }
  }
  return out.sort()
}

interface RawDialerHit {
  line: number
  kind: string
  snippet: string
}

function findRawDialersInSource(relPath: string, source: string): RawDialerHit[] {
  const sf = ts.createSourceFile(relPath, source, ts.ScriptTarget.Latest, true, ts.ScriptKind.TS)
  const hits: RawDialerHit[] = []

  // Track imported dialer symbols & namespace imports per file
  const httpRequestAliases = new Set<string>()
  const httpNamespaces = new Set<string>()
  const http2ConnectAliases = new Set<string>()
  const http2Namespaces = new Set<string>()
  const undiciDialerAliases = new Set<string>()
  const undiciNamespaces = new Set<string>()

  for (const stmt of sf.statements) {
    if (!ts.isImportDeclaration(stmt) || !ts.isStringLiteral(stmt.moduleSpecifier)) continue
    const mod = stmt.moduleSpecifier.text
    const clause = stmt.importClause
    if (!clause || clause.isTypeOnly) continue

    const registerImport = (
      targetFnNames: readonly string[],
      fnSet: Set<string>,
      nsSet: Set<string>,
    ) => {
      if (clause.name) nsSet.add(clause.name.text)
      const bindings = clause.namedBindings
      if (!bindings) return
      if (ts.isNamespaceImport(bindings)) {
        nsSet.add(bindings.name.text)
      } else if (ts.isNamedImports(bindings)) {
        for (const el of bindings.elements) {
          if (el.isTypeOnly) continue
          const importedName = el.propertyName ? el.propertyName.text : el.name.text
          if (targetFnNames.includes(importedName)) {
            fnSet.add(el.name.text)
          }
        }
      }
    }

    if (mod === 'node:http' || mod === 'http' || mod === 'node:https' || mod === 'https') {
      registerImport(['request', 'get'], httpRequestAliases, httpNamespaces)
    } else if (mod === 'node:http2' || mod === 'http2') {
      registerImport(['connect'], http2ConnectAliases, http2Namespaces)
    } else if (mod === 'undici') {
      registerImport(['request', 'fetch', 'stream', 'pipeline'], undiciDialerAliases, undiciNamespaces)
    }
  }

  const record = (node: ts.Node, kind: string) => {
    const { line } = sf.getLineAndCharacterOfPosition(node.getStart(sf))
    hits.push({
      line: line + 1,
      kind,
      snippet: node.getText(sf).replace(/\s+/g, ' ').slice(0, 80),
    })
  }

  const isTypePosition = (node: ts.Node): boolean => {
    let cur: ts.Node | undefined = node.parent
    while (cur) {
      if (ts.isTypeNode(cur) || ts.isInterfaceDeclaration(cur) || ts.isTypeAliasDeclaration(cur)) return true
      cur = cur.parent
    }
    return false
  }

  const visit = (node: ts.Node) => {
    if (ts.isCallExpression(node)) {
      const expr = node.expression
      if (ts.isIdentifier(expr)) {
        if (expr.text === 'fetch') record(node, 'raw fetch()')
        else if (httpRequestAliases.has(expr.text)) record(node, 'raw http(s).request()')
        else if (http2ConnectAliases.has(expr.text)) record(node, 'raw http2.connect()')
        else if (undiciDialerAliases.has(expr.text)) record(node, 'raw undici.request()')
      } else if (ts.isPropertyAccessExpression(expr)) {
        const obj = expr.expression.getText(sf)
        const prop = expr.name.text
        // Ignore `window.fetch(...)` inside Playwright `page.evaluate(...)` browser code.
        if (prop === 'fetch' && (obj === 'globalThis' || obj === 'global' || obj === 'self' || undiciNamespaces.has(obj))) {
          record(node, `raw ${obj}.fetch()`)
        } else if ((prop === 'request' || prop === 'get') && httpNamespaces.has(obj)) {
          record(node, `raw ${obj}.${prop}()`)
        } else if (prop === 'connect' && http2Namespaces.has(obj)) {
          record(node, `raw ${obj}.connect()`)
        } else if ((prop === 'request' || prop === 'stream' || prop === 'pipeline') && undiciNamespaces.has(obj)) {
          record(node, `raw ${obj}.${prop}()`)
        }
      }
    } else if (ts.isPropertyAccessExpression(node) && !isTypePosition(node)) {
      // Catch `globalThis.fetch.bind(globalThis)` or `const f = globalThis.fetch`
      if (node.name.text === 'fetch' && (node.expression.getText(sf) === 'globalThis' || node.expression.getText(sf) === 'global')) {
        if (!ts.isCallExpression(node.parent) || node.parent.expression !== node) {
          record(node, 'raw globalThis.fetch reference')
        }
      }
    } else if (ts.isIdentifier(node) && node.text === 'fetch' && !isTypePosition(node)) {
      // Catch `options.fetchImpl ?? fetch` fallback references to global fetch
      const p = node.parent
      const isFallbackValue =
        (ts.isBinaryExpression(p) && p.right === node && (p.operatorToken.kind === ts.SyntaxKind.QuestionQuestionToken || p.operatorToken.kind === ts.SyntaxKind.BarBarToken)) ||
        (ts.isConditionalExpression(p) && (p.whenTrue === node || p.whenFalse === node)) ||
        (ts.isVariableDeclaration(p) && p.initializer === node)
      if (isFallbackValue) {
        record(node, 'raw global fetch reference')
      }
    }
    ts.forEachChild(node, visit)
  }

  visit(sf)
  return hits
}

describe('Contract: single canonical EgressGateway dialer across src/server/*.ts', () => {
  test('forbids persona-auth.ts, scoped-browser.ts, broker.ts, verify-rpc.ts, and any unapproved file from raw outbound dialers', () => {
    assert.equal('src/server/persona-auth.ts' in WAVE_2B_RAW_DIALER_ALLOWLIST, false, 'persona-auth.ts must NOT be in raw-dialer allowlist')
    assert.equal('src/server/scoped-browser.ts' in WAVE_2B_RAW_DIALER_ALLOWLIST, false, 'scoped-browser.ts must NOT be in raw-dialer allowlist')
    assert.equal('src/server/broker.ts' in WAVE_2B_RAW_DIALER_ALLOWLIST, false, 'broker.ts must NOT be in raw-dialer allowlist')
    assert.equal('src/server/verify-rpc.ts' in WAVE_2B_RAW_DIALER_ALLOWLIST, false, 'verify-rpc.ts must NOT be in raw-dialer allowlist')

    const serverFiles = collectServerTsFiles(join(repoRoot, 'src/server'))
    assert.ok(serverFiles.length > 40, `Expected src/server/*.ts files to scan, got ${serverFiles.length}`)

    const violations: string[] = []
    const observedAllowlisted = new Set<string>()

    for (const absPath of serverFiles) {
      const rel = relative(repoRoot, absPath).replaceAll('\\', '/')
      if (rel === 'src/server/egress-gateway.ts') continue
      const source = readFileSync(absPath, 'utf8')
      const hits = findRawDialersInSource(rel, source)
      if (hits.length === 0) continue

      if (rel in WAVE_2B_RAW_DIALER_ALLOWLIST) {
        observedAllowlisted.add(rel)
      } else {
        for (const hit of hits) {
          violations.push(`${rel}:${hit.line} [${hit.kind}] ${hit.snippet}`)
        }
      }
    }

    assert.deepEqual(
      violations,
      [],
      `Unapproved raw outbound network dialer(s) found outside EgressGateway:\n${violations.join('\n')}`,
    )

    // Keep the allowlist strictly shrinking: fail if an allowlisted file has already been migrated
    const staleAllowlist = Object.keys(WAVE_2B_RAW_DIALER_ALLOWLIST).filter(f => !observedAllowlisted.has(f))
    assert.deepEqual(
      staleAllowlist,
      [],
      `Stale WAVE_2B_RAW_DIALER_ALLOWLIST entries (remove migrated files!): ${staleAllowlist.join(', ')}`,
    )

    // Verify EgressGateway itself exports the canonical trio
    assert.equal(typeof EgressGateway.egressFetch, 'function')
    assert.equal(typeof EgressGateway.egressHttp2, 'function')
    assert.equal(typeof EgressGateway.createLoopbackProxy, 'function')
  })
})
