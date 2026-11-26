/**
 * Security remediation regression suite for Adversarial Audit #730:
 *   - C3: `provider.ts` SSRF & DNS rebinding protection via `EgressGateway.egressFetchStream`,
 *         `domain.ts` `providerUrl` non-public IP/metadata refusal, and `KOVO_OFFLINE=1` /
 *         `KOVO_ALLOW_LOCAL_MODEL=1` loopback gating.
 *   - C5: `createLoopbackProxy` per-instance & per-context `Proxy-Authorization` (`407`),
 *         `ScopedBrowser` per-context pooled proxy isolation (no cross-tenant unioning),
 *         and `persona-auth.ts` authenticated loopback proxy + SSRF-validated host pinning.
 *   - H7: `model-settings.ts` M-15 `.pin` hardening (HMAC-verified ledger survives `.pin` deletion +
 *         SQLite tampering, legacy endpoint/protocol change refusal, `lstatSync` symlink refusal).
 *   - H8: `EgressSanitizer` / `derived-custody.ts` / `redact.ts` 6–7 char sealed-capability scrubbing,
 *         expanded sensitive headers & encodings (hex, double-URL, `\uXXXX`, cookie value-only),
 *         and ReDoS + binary-search oracle hardening for `capability.seal` regexes.
 *   - H9: `createLoopbackProxy` `allowConnectPort` / `scopePolicy` / `maxResponseBytes`,
 *         `egressHttp2` gzip/deflate/br decompression, `ScopedBrowser` origin-scoped pool key,
 *         origin-filtered cookie hydration, `runBrowserSession` `ScopePolicy` enforcement, and
 *         `installWebSocketGuard` `allowConnectPort` + `scopePolicy` enforcement.
 *   - H10-egress: `resolveAndValidateHost` intersects `allowedOrigins` AND `allowOrigin` (never OR).
 */
import assert from 'node:assert/strict'
import { once } from 'node:events'
import {
  chmodSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  symlinkSync,
  unlinkSync,
  writeFileSync,
} from 'node:fs'
import { createServer as createHttpServer, request as nodeHttpRequest } from 'node:http'
import type { RequestListener } from 'node:http'
import { createServer as createH2Server } from 'node:http2'
import type { ServerHttp2Stream } from 'node:http2'
import { connect as netConnect, createServer as createTcpServer } from 'node:net'
import type { AddressInfo } from 'node:net'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { describe, test } from 'node:test'
import type { TestContext } from 'node:test'
import { brotliCompressSync, deflateSync, gzipSync } from 'node:zlib'
import { eq } from 'drizzle-orm'

import { providerSettings } from '../src/domain.ts'
import { RequestBroker } from '../src/server/broker.ts'
import type { BrokerExchangeResult, BrokerHttpRequest, Grant } from '../src/server/broker.ts'
import {
  DerivedCapabilityVault,
  DerivedCustodyError,
  scrubDerivedSecrets,
  vaultScrubDescriptors,
} from '../src/server/derived-custody.ts'
import {
  EgressDeniedError,
  createLoopbackProxy,
  egressFetch,
  egressHttp2,
  resolveAndValidateHost,
} from '../src/server/egress-gateway.ts'
import {
  compileSafeSealRegex,
  createEgressSanitizer,
  extractSafeSealRegexMatch,
  sanitizeHttpHeaders,
  validateCapabilitySealValue,
} from '../src/server/egress-sanitizer.ts'
import {
  checkModelConnection,
  privateModelProfiles,
  saveModelProfile,
} from '../src/server/model-settings.ts'
import {
  PersonaAuthManager,
  formChromiumLaunchArgs,
} from '../src/server/persona-auth.ts'
import { createProjectPersona } from '../src/server/persona-vault.ts'
import { provider, testProvider } from '../src/server/provider.ts'
import { buildSecretEncodingVariants } from '../src/server/redact.ts'
import { modelProfiles } from '../src/server/schema.ts'
import type { ScopePolicy } from '../src/server/scope-policy.ts'
import {
  ScopedBrowser,
  filterCookiesForOrigin,
  installWebSocketGuard,
} from '../src/server/scoped-browser.ts'
import type { PlaywrightBrowserLike } from '../src/server/scoped-browser.ts'
import { Store } from '../src/server/store.ts'

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
  t.after(() => new Promise<void>(r => {
    server.closeAllConnections?.()
    server.close(() => r())
  }))
  const port = (server.address() as AddressInfo).port
  return { origin: `http://127.0.0.1:${port}`, port }
}

function sendProxyHttpRequest(
  proxyPort: number,
  targetUrl: string,
  headers: Record<string, string> = {},
  method = 'GET',
): Promise<{ status: number; headers: Record<string, string | string[] | undefined>; body: string; destroyed?: boolean }> {
  return new Promise((resolvePromise, reject) => {
    const req = nodeHttpRequest({
      host: '127.0.0.1',
      port: proxyPort,
      path: targetUrl,
      method,
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
      res.on('close', () => {
        if (!res.complete) {
          resolvePromise({
            status: res.statusCode ?? 0,
            headers: res.headers,
            body: Buffer.concat(chunks).toString('utf8'),
            destroyed: true,
          })
        }
      })
    })
    req.once('error', err => {
      // Mid-stream socket destroy on oversize chunked response surfaces as ECONNRESET/socket hang up
      if ((err as NodeJS.ErrnoException).code === 'ECONNRESET') {
        resolvePromise({ status: 0, headers: {}, body: '', destroyed: true })
      } else {
        reject(err)
      }
    })
    req.end()
  })
}

function sendProxyConnect(
  proxyPort: number,
  authority: string,
  proxyAuthHeader?: string,
  payloadAfterConnect?: string,
): Promise<{ statusLine: string; headers: Record<string, string>; body: string }> {
  return new Promise((resolvePromise, reject) => {
    const socket = netConnect({ host: '127.0.0.1', port: proxyPort }, () => {
      const authLine = proxyAuthHeader ? `Proxy-Authorization: ${proxyAuthHeader}\r\n` : ''
      socket.write(`CONNECT ${authority} HTTP/1.1\r\nHost: ${authority}\r\n${authLine}\r\n`)
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

function basicAuthHeader(username: string, password: string): string {
  return `Basic ${Buffer.from(`${username}:${password}`, 'utf8').toString('base64')}`
}

function sseResponseBody(text = 'ready'): string {
  const argsJson = JSON.stringify({ status: text })
  const events = [
    { type: 'response.created', response: { id: 'resp_audit', status: 'in_progress' } },
    { type: 'response.output_item.added', output_index: 0, item: { type: 'function_call', id: 'fc_1', call_id: 'call_1', name: 'kovo_connection', arguments: '' } },
    { type: 'response.function_call_arguments.delta', output_index: 0, delta: argsJson },
    { type: 'response.function_call_arguments.done', output_index: 0, arguments: argsJson },
    { type: 'response.output_item.done', output_index: 0, item: { type: 'function_call', id: 'fc_1', call_id: 'call_1', name: 'kovo_connection', arguments: argsJson, status: 'completed' } },
    {
      type: 'response.completed',
      response: {
        id: 'resp_audit',
        status: 'completed',
        output: [{ type: 'function_call', id: 'fc_1', call_id: 'call_1', name: 'kovo_connection', arguments: argsJson, status: 'completed' }],
        usage: { input_tokens: 10, output_tokens: 5 },
      },
    },
  ]
  return events.map(ev => `event: ${ev.type}\ndata: ${JSON.stringify(ev)}\n\n`).join('')
}

function makeFakeBroker(): RequestBroker {
  return {
    executeHttp: async (req: BrokerHttpRequest): Promise<BrokerExchangeResult> => ({
      origin: req.origin,
      finalOrigin: req.origin,
      redirectOrigins: [req.origin],
      method: req.method,
      pathAndQuery: req.pathAndQuery,
      personaHandle: req.persona ?? null,
      status: 200,
      mediaType: 'text/html',
      reqHeaders: {},
      respHeaders: {},
      setCookies: [],
      bodyPreview: '',
      body: '<html><body>ok</body></html>',
      bodySha256: '0'.repeat(64),
      bodyBytes: 26,
      bodyTruncated: false,
      durationMs: 1,
      observation: { source: 'audit-fixture' },
    } as unknown as BrokerExchangeResult),
    sessionCookiesForBrowser: () => [],
    getRegisteredSecrets: () => [],
    getStorage: () => undefined,
  } as unknown as RequestBroker
}

// ---------------------------------------------------------------------------
// 1. C3: provider.ts SSRF, DNS Rebinding, Loopback Gating & domain.ts Validation
// ---------------------------------------------------------------------------

describe('C3: provider.ts SSRF, DNS rebinding, and domain.ts endpoint hardening', () => {
  test('domain.ts providerUrl rejects RFC1918, ULA, IPv6 private/link-local, metadata, and https loopback', () => {
    const blockedUrls = [
      'https://10.0.0.1/v1',
      'https://172.16.0.5/v1',
      'https://192.168.1.10/v1',
      'https://169.254.169.254/latest/meta-data',
      'https://100.100.100.200/v1',
      'https://0.0.0.0/v1',
      'https://127.0.0.1:8443/v1',
      'https://localhost/v1',
      'https://[::1]/v1',
      'https://[fc00::1]/v1',
      'https://[fd00:ec2::254]/v1',
      'https://[fe80::1]/v1',
      'https://[::ffff:169.254.169.254]/v1',
      'https://metadata.google.internal/v1',
      'http://10.0.0.1:8080/v1',
      'http://169.254.169.254:80/v1',
      'http://127.0.0.1/v1',
    ]
    for (const endpoint of blockedUrls) {
      const res = providerSettings.safeParse({
        endpoint,
        model: 'test-model',
        protocol: 'responses',
        key: 'sk-test-valid-key-1234',
      })
      assert.equal(res.success, false, `providerSettings must reject SSRF endpoint: ${endpoint}`)
    }

    const okPublic = providerSettings.safeParse({
      endpoint: 'https://openrouter.ai/api/v1',
      model: 'deepseek/deepseek-v4.1-flash-1017',
      protocol: 'responses',
      key: 'sk-test-valid-key-1234',
    })
    assert.equal(okPublic.success, true)
  })

  test('provider.ts blocks 127.0.0.1 by default, allows only with KOVO_ALLOW_LOCAL_MODEL=1 or mock fetch, and blocks RFC1918/ULA/metadata/DNS-rebinding', async t => {
    const prevLocal = process.env.KOVO_ALLOW_LOCAL_MODEL
    const prevOffline = process.env.KOVO_OFFLINE
    delete process.env.KOVO_ALLOW_LOCAL_MODEL
    delete process.env.KOVO_OFFLINE
    t.after(() => {
      if (prevLocal === undefined) delete process.env.KOVO_ALLOW_LOCAL_MODEL
      else process.env.KOVO_ALLOW_LOCAL_MODEL = prevLocal
      if (prevOffline === undefined) delete process.env.KOVO_OFFLINE
      else process.env.KOVO_OFFLINE = prevOffline
    })

    let hits = 0
    const mockServer = await startLocalHttpServer(t, (req, res) => {
      hits += 1
      req.resume()
      if (req.url === '/redirect/responses') {
        res.writeHead(302, { location: 'http://169.254.169.254/latest/meta-data/' })
        res.end()
        return
      }
      res.writeHead(200, { 'content-type': 'text/event-stream' })
      res.end(sseResponseBody('ready'))
    })

    // 1) Without KOVO_ALLOW_LOCAL_MODEL=1 or KOVO_OFFLINE=1, loopback provider endpoint MUST be blocked!
    await assert.rejects(
      testProvider({
        endpoint: `${mockServer.origin}/v1`,
        model: 'local-mock',
        protocol: 'responses',
        key: 'sk-local-test-1234',
      }),
      /egress|loopback|plaintext http/i,
    )
    assert.equal(hits, 0, 'local server must never be dialed when KOVO_ALLOW_LOCAL_MODEL is unset')

    // 2) Mock fetch seam still works without env opt-in (preserves unit test mocks)
    const mockFetchRes = await testProvider(
      {
        endpoint: 'https://mock-provider.example/v1',
        model: 'mock-model',
        protocol: 'responses',
        key: 'sk-mock-test-1234',
      },
      undefined,
      {
        fetch: async () => new Response(sseResponseBody('ready'), {
          status: 200,
          headers: { 'content-type': 'text/event-stream' },
        }),
      },
    )
    assert.deepEqual(mockFetchRes, { ok: true })

    // 3) With KOVO_ALLOW_LOCAL_MODEL=1, 127.0.0.1 loopback streams cleanly via EgressGateway.egressFetchStream
    process.env.KOVO_ALLOW_LOCAL_MODEL = '1'
    const localOk = await testProvider({
      endpoint: `${mockServer.origin}/v1`,
      model: 'local-mock',
      protocol: 'responses',
      key: 'sk-local-test-1234',
    })
    assert.deepEqual(localOk, { ok: true })
    assert.equal(hits, 1)

    // 4) Redirects to cloud metadata MUST be refused even with KOVO_ALLOW_LOCAL_MODEL=1
    await assert.rejects(
      testProvider({
        endpoint: `${mockServer.origin}/redirect`,
        model: 'local-mock',
        protocol: 'responses',
        key: 'sk-local-test-1234',
      }),
      /redirect/i,
    )

    // 5) RFC1918, IPv6 ULA, and cloud metadata DNS answers MUST STILL be blocked EVEN with KOVO_ALLOW_LOCAL_MODEL=1
    for (const badIp of ['10.0.0.5', '172.16.0.9', '192.168.1.50', 'fc00::1', 'fe80::1', '169.254.169.254', 'fd00:ec2::254']) {
      await assert.rejects(
        testProvider(
          {
            endpoint: 'https://rebind-llm.example/v1',
            model: 'evil-model',
            protocol: 'responses',
            key: 'sk-rebind-test-1234',
          },
          undefined,
          { resolveHost: async () => [badIp] },
        ),
        /SSRF|never permitted|metadata|non-public|private/i,
        `provider must block DNS resolution to ${badIp}`,
      )
    }

    // 6) Single-resolution DNS pinning: provider resolves once (second rebind to 169.254.169.254 is never consulted)
    let resolveCount = 0
    const { models, model } = provider(
      {
        endpoint: `http://localhost:${mockServer.port}/v1`,
        model: 'pin-model',
        protocol: 'responses',
        key: 'sk-pin-test-1234',
      },
      'connection',
      {
        resolveHost: async () => {
          resolveCount += 1
          return resolveCount === 1 ? ['127.0.0.1'] : ['169.254.169.254']
        },
      },
    )
    const stream = models.stream(model, {
      systemPrompt: 'test',
      messages: [{ role: 'user', content: 'ping', timestamp: Date.now() }],
      tools: [],
    })
    for await (const _ev of stream) { /* consume */ }
    await stream.result()
    assert.equal(resolveCount, 1, 'provider DNS must be resolved exactly once (immune to rebinding)')
  })
})

// ---------------------------------------------------------------------------
// 2. C5 & H9 & H10-egress: Loopback Proxy Auth, Isolation, Limits, HTTP/2 Decompression, AND Scope
// ---------------------------------------------------------------------------

describe('C5, H9, H10-egress: EgressGateway proxy auth, limits, HTTP/2 decompression & origin intersection', () => {
  test('H10-egress: resolveAndValidateHost intersects allowedOrigins AND allowOrigin (never OR)', async () => {
    // Origin is NOT in allowedOrigins, even though allowOrigin returns true -> MUST deny
    await assert.rejects(
      resolveAndValidateHost('https://evil.example/api', {
        allowedOrigins: ['https://good.example'],
        allowOrigin: () => true,
        resolveHost: async () => ['93.184.216.34'],
      }),
      (err: unknown) => err instanceof EgressDeniedError && err.code === 'scope_denied',
    )

    // Origin IS in allowedOrigins, but allowOrigin returns false -> MUST deny
    await assert.rejects(
      resolveAndValidateHost('https://good.example/api', {
        allowedOrigins: ['https://good.example'],
        allowOrigin: () => ({ allowed: false, reason: 'denied by dynamic predicate' }),
        resolveHost: async () => ['93.184.216.34'],
      }),
      (err: unknown) => err instanceof EgressDeniedError && err.code === 'scope_denied',
    )

    // Both allow -> succeeds
    const ok = await resolveAndValidateHost('https://good.example/api', {
      allowedOrigins: ['https://good.example'],
      allowOrigin: origin => origin === 'https://good.example',
      resolveHost: async () => ['93.184.216.34'],
    })
    assert.equal(ok.url.origin, 'https://good.example')
  })

  test('C5 & H9: createLoopbackProxy requires Proxy-Authorization (407), enforces allowConnectPort, scopePolicy, and maxResponseBytes', async t => {
    const target = await startLocalHttpServer(t, (req, res) => {
      if (req.url === '/oversize-cl') {
        const body = 'X'.repeat(4096)
        res.writeHead(200, { 'content-type': 'text/plain', 'content-length': String(body.length) })
        res.end(body)
        return
      }
      if (req.url === '/oversize-chunked') {
        res.writeHead(200, { 'content-type': 'text/plain', 'transfer-encoding': 'chunked' })
        res.write('A'.repeat(1024))
        res.write('B'.repeat(2048))
        res.end()
        return
      }
      res.writeHead(200, { 'content-type': 'text/plain' })
      res.end('ok-small')
    })

    const tcpEcho = createTcpServer(sock => {
      sock.once('data', d => sock.end(`ECHO:${d.toString('utf8')}`))
    })
    tcpEcho.listen(0, '127.0.0.1')
    await once(tcpEcho, 'listening')
    t.after(() => new Promise<void>(r => tcpEcho.close(() => r())))
    const tcpPort = (tcpEcho.address() as AddressInfo).port

    const scopePolicy: ScopePolicy = {
      mode: 'staging_isolated',
      targetOrigins: [`http://app.local:${target.port}`, `https://app.local:${tcpPort}`],
      routeDenylist: ['/admin'],
    }

    const proxy = await createLoopbackProxy({
      allowLocalLab: true,
      scopePolicy,
      allowConnectPort: port => port === tcpPort,
      maxResponseBytes: 1500,
      resolveHost: async () => ['127.0.0.1'],
    })
    t.after(() => proxy.close())

    // 1) Missing or invalid Proxy-Authorization -> 407 Proxy Authentication Required
    const noAuthHttp = await sendProxyHttpRequest(proxy.port, `http://app.local:${target.port}/ok`)
    assert.equal(noAuthHttp.status, 407)
    assert.equal(noAuthHttp.headers['x-kovo-egress-denied'], 'proxy_auth_required')

    const badAuthHttp = await sendProxyHttpRequest(proxy.port, `http://app.local:${target.port}/ok`, {
      'proxy-authorization': basicAuthHeader('wrong-user', 'wrong-pass'),
    })
    assert.equal(badAuthHttp.status, 407)

    const noAuthConnect = await sendProxyConnect(proxy.port, `app.local:${tcpPort}`)
    assert.match(noAuthConnect.statusLine, /^HTTP\/1\.1 407 /)
    assert.equal(noAuthConnect.headers['x-kovo-egress-denied'], 'proxy_auth_required')

    const authHeaders = { 'proxy-authorization': proxy.authorizationHeader }

    // 2) ScopePolicy staging_denylist (on state-changing POST) & out-of-scope origin enforced inside createLoopbackProxy
    const deniedRoute = await sendProxyHttpRequest(proxy.port, `http://app.local:${target.port}/admin/delete`, authHeaders, 'POST')
    assert.equal(deniedRoute.status, 403)
    assert.equal(deniedRoute.headers['x-kovo-egress-denied'], 'scope_denied')
    const deniedOrigin = await sendProxyHttpRequest(proxy.port, `http://other.local:${target.port}/ok`, authHeaders)
    assert.equal(deniedOrigin.status, 403)
    assert.equal(deniedOrigin.headers['x-kovo-egress-denied'], 'scope_denied')

    // 3) Small allowed response succeeds
    const smallOk = await sendProxyHttpRequest(proxy.port, `http://app.local:${target.port}/ok`, authHeaders)
    assert.equal(smallOk.status, 200)
    assert.equal(smallOk.body, 'ok-small')

    // 4) maxResponseBytes enforced on both Content-Length and chunked streams
    const overCl = await sendProxyHttpRequest(proxy.port, `http://app.local:${target.port}/oversize-cl`, authHeaders)
    assert.equal(overCl.status, 502)
    assert.equal(overCl.headers['x-kovo-egress-denied'], 'response_too_large')

    const overChunked = await sendProxyHttpRequest(proxy.port, `http://app.local:${target.port}/oversize-chunked`, authHeaders)
    assert.ok(
      overChunked.status === 502 || overChunked.destroyed === true,
      `chunked response exceeding maxResponseBytes must be aborted (got status=${overChunked.status})`,
    )
    assert.ok(overChunked.body.length <= 1500)

    // 5) allowConnectPort enforced on CONNECT
    const badPortConnect = await sendProxyConnect(proxy.port, `app.local:${target.port}`, proxy.authorizationHeader)
    assert.match(badPortConnect.statusLine, /^HTTP\/1\.1 403 /)
    assert.equal(badPortConnect.headers['x-kovo-egress-denied'], 'proxy_connect_denied')

    const okConnect = await sendProxyConnect(proxy.port, `app.local:${tcpPort}`, proxy.authorizationHeader, 'HI')
    assert.match(okConnect.statusLine, /^HTTP\/1\.1 200 /)
    assert.equal(okConnect.body, 'ECHO:HI')
  })

  test('H9: egressHttp2 transparently decompresses gzip, deflate, and brotli responses', async t => {
    const sessions = new Set<import('node:http2').ServerHttp2Session>()
    const h2 = createH2Server()
    h2.on('session', s => {
      sessions.add(s)
      s.once('close', () => sessions.delete(s))
    })
    h2.on('stream', (stream: ServerHttp2Stream, headers) => {
      const path = String(headers[':path'] ?? '/')
      const payload = Buffer.from(`decompressed-payload:${path}`, 'utf8')
      if (path === '/gzip') {
        stream.respond({ ':status': 200, 'content-type': 'text/plain', 'content-encoding': 'gzip' })
        stream.end(gzipSync(payload))
      } else if (path === '/deflate') {
        stream.respond({ ':status': 200, 'content-type': 'text/plain', 'content-encoding': 'deflate' })
        stream.end(deflateSync(payload))
      } else if (path === '/br') {
        stream.respond({ ':status': 200, 'content-type': 'text/plain', 'content-encoding': 'br' })
        stream.end(brotliCompressSync(payload))
      } else {
        stream.respond({ ':status': 200, 'content-type': 'text/plain' })
        stream.end(payload)
      }
    })
    await new Promise<void>(r => h2.listen(0, '127.0.0.1', r))
    t.after(async () => {
      for (const s of sessions) s.destroy()
      await new Promise<void>(r => h2.close(() => r()))
    })
    const port = (h2.address() as AddressInfo).port

    for (const enc of ['gzip', 'deflate', 'br'] as const) {
      const res = await egressHttp2(`http://127.0.0.1:${port}/${enc}`, { method: 'GET' }, { allowLocalLab: true })
      assert.equal(res.status, 200)
      assert.equal(res.body, `decompressed-payload:/${enc}`)
      assert.equal(res.headers['content-encoding'], undefined, `decompressed ${enc} must strip content-encoding`)
    }
  })
})

// ---------------------------------------------------------------------------
// 3. C5 & H9: ScopedBrowser Isolation, Cookie Filtering, runBrowserSession, WS Guard, Persona Form Proxy
// ---------------------------------------------------------------------------

describe('C5 & H9: ScopedBrowser isolation, cookie filtering, ScopePolicy, WS guard & persona-auth form proxy', () => {
  test('C5: ScopedBrowser pooled contexts isolate per-context proxy credentials (Context A never inherits Context B allowLocalLab/origins)', async t => {
    const prevLab = process.env.KOVO_ALLOW_LOCAL_LAB
    process.env.KOVO_ALLOW_LOCAL_LAB = '1'
    t.after(() => {
      if (prevLab === undefined) delete process.env.KOVO_ALLOW_LOCAL_LAB
      else process.env.KOVO_ALLOW_LOCAL_LAB = prevLab
    })

    const proxyConfigs: Array<{ server: string; username: string; password: string }> = []
    let releaseContextB!: () => void
    const contextBHeld = new Promise<void>(resolve => { releaseContextB = resolve })
    let contextBActive!: () => void
    const contextBReady = new Promise<void>(resolve => { contextBActive = resolve })

    const fakeBrowser: PlaywrightBrowserLike = {
      newContext: async (options = {}) => {
        const proxyObj = options.proxy as { server: string; username: string; password: string }
        proxyConfigs.push(proxyObj)
        return {
          addInitScript: async () => undefined,
          addCookies: async () => undefined,
          route: async () => undefined,
          routeWebSocket: async () => undefined,
          newPage: async () => ({
            on: () => undefined,
            goto: async (url: string) => {
              if (url.includes('127.0.0.1')) {
                contextBActive()
                await contextBHeld
              }
              return { status: () => 200 }
            },
            waitForTimeout: async () => undefined,
            waitForLoadState: async () => undefined,
            url: () => 'https://public-a.example/',
            title: async () => 'ok',
            evaluate: async () => ({
              domHtml: '<html></html>',
              links: [],
              forms: [],
              cookieNames: [],
              localStorageKeys: [],
              sessionStorageKeys: [],
              postMessageListeners: {
                count: 0, hasOnMessage: false, handlers: [], observedEvents: 0, canaryHandledWithoutOriginCheck: false,
              },
            }) as never,
            close: async () => undefined,
          }),
          close: async () => undefined,
        }
      },
      close: async () => undefined,
    }

    const scoped = new ScopedBrowser(makeFakeBroker(), {
      launchBrowser: async () => fakeBrowser,
      proxyResolveHost: async host => host === '127.0.0.1' ? ['127.0.0.1'] : ['93.184.216.34'],
    })
    t.after(() => scoped.close())

    const grantB: Grant = {
      canRead: o => o === 'http://127.0.0.1:49001',
      audit: () => undefined,
      allowLocalLab: true,
      tier: 2,
    }
    const grantA: Grant = {
      canRead: o => o === 'https://public-a.example',
      audit: () => undefined,
      allowLocalLab: false,
      tier: 2,
    }

    // Start Context B (localLab: true) and hold it active
    const visitB = scoped.visitPages(
      [{ origin: 'http://127.0.0.1:49001', pathAndQuery: '/lab', runId: 'run-iso', persona: 'pB' }],
      grantB,
      AbortSignal.timeout(10_000),
    )
    await contextBReady

    // Create Context A (public target, allowLocalLab: false) while Context B is active
    await scoped.visitPages(
      [{ origin: 'https://public-a.example', pathAndQuery: '/home', runId: 'run-iso', persona: 'pA' }],
      grantA,
      AbortSignal.timeout(10_000),
    )

    assert.equal(proxyConfigs.length, 2)
    const cfgB = proxyConfigs[0]!
    const cfgA = proxyConfigs[1]!
    assert.notEqual(cfgA.username, cfgB.username, 'each pooled context must receive unique Proxy-Authorization credentials')
    const proxyPort = Number(new URL(cfgA.server).port)

    // Using Context A's credentials while Context B is active MUST NOT inherit Context B's allowLocalLab or origin!
    const bleedAttempt = await sendProxyConnect(
      proxyPort,
      '127.0.0.1:49001',
      basicAuthHeader(cfgA.username, cfgA.password),
    )
    assert.match(bleedAttempt.statusLine, /^HTTP\/1\.1 403 /)

    releaseContextB()
    await visitB
  })

  test('H9: filterCookiesForOrigin strictly scopes hydrated cookies to targetOrigin and secure scheme', () => {
    const cookies = [
      { name: 'exact_ok', value: 'v1', domain: 'app.example.com', path: '/', secure: true },
      { name: 'sub_ok', value: 'v2', domain: '.example.com', path: '/', secure: true },
      { name: 'foreign_domain', value: 'v3', domain: 'other.example.com', path: '/', secure: true },
      { name: 'evil_suffix', value: 'v4', domain: 'evil-app.example.com', path: '/', secure: true },
      { name: 'secure_on_http', value: 'v5', domain: '127.0.0.1', path: '/', secure: true },
      { name: 'plain_on_http', value: 'v6', domain: '127.0.0.1', path: '/', secure: false },
    ]
    const httpsFiltered = filterCookiesForOrigin(cookies, 'https://app.example.com')
    assert.deepEqual(httpsFiltered.map(c => c.name), ['exact_ok', 'sub_ok'])

    const httpFiltered = filterCookiesForOrigin(cookies, 'http://127.0.0.1:3000')
    assert.deepEqual(httpFiltered.map(c => c.name), ['plain_on_http'])
  })

  test('H9: runBrowserSession routes through classifyBrowserHttpRequest enforcing ScopePolicy (prod_readonly & staging_denylist)', async t => {
    const abortedUrls: string[] = []
    const fulfilledUrls: string[] = []
    const fakeBrowser: PlaywrightBrowserLike = {
      newContext: async () => {
        let routeHandler: ((route: unknown) => Promise<void>) | null = null
        return {
          addInitScript: async () => undefined,
          addCookies: async () => undefined,
          route: async (_pat, handler) => { routeHandler = handler as (route: unknown) => Promise<void> },
          routeWebSocket: async () => undefined,
          newPage: async () => ({
            on: () => undefined,
            goto: async (url: string) => {
              const runOne = async (reqUrl: string, method: string) => {
                await routeHandler?.({
                  request: () => ({
                    url: () => reqUrl,
                    method: () => method,
                    headers: () => ({}),
                    postData: () => null,
                    resourceType: () => 'fetch',
                  }),
                  abort: async () => { abortedUrls.push(`${method} ${reqUrl}`) },
                  fulfill: async () => { fulfilledUrls.push(`${method} ${reqUrl}`) },
                })
              }
              await runOne(url, 'GET')
              await runOne('https://target.example/admin/nuke', 'POST')
              await runOne('https://target.example/api/orders', 'POST')
              await runOne('https://auth.example/api/probe', 'POST')
              return { status: () => 200 }
            },
            waitForTimeout: async () => undefined,
            waitForLoadState: async () => undefined,
            url: () => 'https://target.example/app',
            title: async () => 'app',
            evaluate: async () => ({
              domHtml: '<html></html>',
              links: [],
              forms: [],
              cookieNames: [],
              localStorageKeys: [],
              sessionStorageKeys: [],
              postMessageListeners: {
                count: 0, hasOnMessage: false, handlers: [], observedEvents: 0, canaryHandledWithoutOriginCheck: false,
              },
            }) as never,
            close: async () => undefined,
          }),
          close: async () => undefined,
        }
      },
      close: async () => undefined,
    }

    const scopePolicy: ScopePolicy = {
      mode: 'prod_readonly',
      targetOrigins: ['https://target.example'],
      authOrigins: ['https://auth.example'],
      routeDenylist: ['/admin'],
    }
    const grant: Grant = {
      canRead: o => o === 'https://target.example' || o === 'https://auth.example',
      audit: () => undefined,
      allowLocalLab: false,
      tier: 3,
      scopePolicy,
    }
    const scoped = new ScopedBrowser(makeFakeBroker(), { launchBrowser: async () => fakeBrowser })
    t.after(() => scoped.close())

    await scoped.runBrowserSession(
      [{ id: 's1', role: 'probe', origin: 'https://target.example', pathAndQuery: '/app' }],
      grant,
      AbortSignal.timeout(10_000),
    )

    assert.ok(fulfilledUrls.includes('GET https://target.example/app'))
    assert.ok(abortedUrls.includes('POST https://target.example/admin/nuke'), 'ScopePolicy must block POST /admin in runBrowserSession')
    assert.ok(abortedUrls.includes('POST https://target.example/api/orders'), 'prod_readonly must block POST mutation in runBrowserSession')
    assert.ok(abortedUrls.includes('POST https://auth.example/api/probe'), 'ScopePolicy must block active POST on auth origin in runBrowserSession')
  })

  test('H9: installWebSocketGuard enforces allowConnectPort, allowedPorts, and ScopePolicy', async () => {
    let wsHandler: ((ws: { url(): string; close(o?: { code?: number; reason?: string }): Promise<void>; connectToServer(): Promise<void> }) => Promise<void>) | null = null
    const ctx: Parameters<typeof installWebSocketGuard>[0] = {
      routeWebSocket: async (_pat, handler) => { wsHandler = handler as unknown as typeof wsHandler },
    }
    const scopePolicy: ScopePolicy = {
      mode: 'staging_isolated',
      targetOrigins: ['https://app.example'],
      assetOrigins: ['https://cdn.example'],
      routeDenylist: ['/admin'],
    }
    await installWebSocketGuard(ctx, {
      canRead: o => o === 'https://app.example' || o === 'https://app.example:8443' || o === 'https://cdn.example',
      allowLocalLab: false,
      scopePolicy,
      allowedPorts: [443],
      allowConnectPort: port => port === 443,
    })

    const runWs = async (url: string) => {
      let connected = false
      let closedCode: number | undefined
      await wsHandler!({
        url: () => url,
        close: async o => { closedCode = o?.code },
        connectToServer: async () => { connected = true },
      })
      return { connected, closedCode }
    }

    assert.deepEqual(await runWs('wss://app.example/ws'), { connected: true, closedCode: undefined })
    assert.deepEqual(await runWs('wss://app.example:8443/ws'), { connected: false, closedCode: 1008 })
    assert.deepEqual(await runWs('wss://app.example/admin/ws'), { connected: false, closedCode: 1008 })
    assert.deepEqual(await runWs('wss://cdn.example/ws'), { connected: false, closedCode: 1008 })
  })

  test('C5: persona-auth.ts routes form Chromium through authenticated loopback proxy, strips unsafe pinned IPs, and checks WS host safety', async t => {
    const dir = mkdtempSync(join(tmpdir(), 'kovo-form-proxy-'))
    t.after(() => rmSync(dir, { recursive: true, force: true }))
    const storage = new Store(dir)
    t.after(() => storage.close())

    const targetOrigin = 'https://app.example.com'
    const { id: projectId } = storage.createProject({
      requestId: 'req-form-proxy',
      name: 'Form Proxy Project',
      seeds: [targetOrigin],
      environment: 'public',
    })
    const persona = createProjectPersona(storage, {
      requestId: 'req-form-persona',
      projectId,
      handle: 'form_user',
      roleLabel: 'User',
      originAllowlist: [targetOrigin, 'https://rebind.example.com'],
      authKind: 'login',
      secret: JSON.stringify({ email: 'u@app.example.com', password: 'pw-secret-value-123' }),
      canaryMarkers: [],
      loginConfig: { adapter: 'form', email: 'u@app.example.com', loginUrl: `${targetOrigin}/login` },
    })

    const args = formChromiumLaunchArgs({ pinnedHosts: new Map([['app.example.com', ['93.184.216.34']]]) })
    assert.ok(args.includes('--proxy-bypass-list=<-loopback>'))
    assert.ok(args.some(a => a.includes('MAP * ~NOTFOUND, EXCLUDE 127.0.0.1')))

    let seenContextOpts: Record<string, unknown> = {}
    let seenPinnedHosts: ReadonlyMap<string, readonly string[]> | undefined
    let wsDeniedCode: number | undefined
    let proxy407Checked = false
    let proxyMeta403Checked = false

    const manager = new PersonaAuthManager({
      resolveHost: async host => {
        if (host === 'app.example.com') return ['93.184.216.34']
        // Unsafe metadata IP must NEVER be pinned into --host-resolver-rules!
        if (host === 'rebind.example.com') return ['169.254.169.254']
        return ['10.0.0.1']
      },
      launchBrowser: async pinnedHosts => {
        seenPinnedHosts = pinnedHosts
        return {
          newContext: async (opts = {}) => {
            seenContextOpts = opts
            const proxyObj = opts.proxy as { server?: string; username?: string; password?: string } | undefined
            if (proxyObj?.server && proxyObj.username && proxyObj.password) {
              const port = Number(new URL(proxyObj.server).port)
              const unauth = await sendProxyConnect(port, 'app.example.com:443')
              proxy407Checked = /^HTTP\/1\.1 407 /.test(unauth.statusLine)
              const meta = await sendProxyConnect(
                port,
                '169.254.169.254:443',
                basicAuthHeader(proxyObj.username, proxyObj.password),
              )
              proxyMeta403Checked = /^HTTP\/1\.1 403 /.test(meta.statusLine)
            }
            let wsHandler: ((ws: { url(): string; close(o?: { code?: number }): Promise<void>; connectToServer(): Promise<void> }) => Promise<void>) | null = null
            return {
              addInitScript: async () => undefined,
              route: async () => undefined,
              routeWebSocket: async (_p, h) => { wsHandler = h as typeof wsHandler },
              newPage: async () => ({
                goto: async () => {
                  // Trigger WS upgrade to metadata-rebound host -> must be closed by browserHostSafety!
                  await wsHandler?.({
                    url: () => 'wss://rebind.example.com/ws',
                    close: async o => { wsDeniedCode = o?.code },
                    connectToServer: async () => undefined,
                  })
                },
                waitForTimeout: async () => undefined,
                waitForLoadState: async () => undefined,
                url: () => `${targetOrigin}/dashboard`,
                locator: () => {
                  const loc = {
                    count: async () => 1,
                    first: () => loc,
                    fill: async () => undefined,
                    click: async () => undefined,
                  }
                  return loc
                },
                evaluate: async () => ({ captcha: false, mfa: false }) as never,
                close: async () => undefined,
              }),
              cookies: async () => [{ name: 'sid', value: 'form_cookie_value_9988', domain: 'app.example.com', path: '/', httpOnly: true, secure: true }],
              close: async () => undefined,
            }
          },
          close: async () => undefined,
        }
      },
    })

    await manager.authenticatePersona(storage, projectId, persona.id)
    const proxyCfg = seenContextOpts.proxy as { server?: string; username?: string; password?: string } | undefined
    assert.ok(proxyCfg?.server && proxyCfg.username && proxyCfg.password, 'form login context MUST receive authenticated loopback proxy')
    assert.equal(proxy407Checked, true, 'form login loopback proxy must reject unauthenticated clients with 407')
    assert.equal(proxyMeta403Checked, true, 'form login loopback proxy must refuse cloud metadata CONNECT with 403')
    assert.deepEqual(seenPinnedHosts?.get('app.example.com'), ['93.184.216.34'])
    assert.equal(seenPinnedHosts?.has('rebind.example.com'), false, 'metadata-resolving host must NEVER be pinned into Chromium resolver rules')
    assert.equal(wsDeniedCode, 1008, 'routeWebSocket must block metadata-rebound WebSocket upgrade via browserHostSafety')
  })
})

// ---------------------------------------------------------------------------
// 4. H7: M-15 .pin Hardening & Symlink Refusal in model-settings.ts
// ---------------------------------------------------------------------------

describe('H7: model-settings.ts .pin fail-closed ledger & symlink refusal', () => {
  test('deleting .pin + tampering SQLite endpoint fails closed; symlinks on credential and .pin are rejected', async t => {
    const dir = mkdtempSync(join(tmpdir(), 'kovo-h7-pin-'))
    t.after(() => rmSync(dir, { recursive: true, force: true }))
    const storage = new Store(dir)
    t.after(() => storage.close())

    const saved = await saveModelProfile({
      name: 'H7 OpenRouter',
      endpoint: 'https://openrouter.ai/api/v1',
      model: 'deepseek/deepseek-v4.1-flash-1017',
      protocol: 'responses',
      key: 'sk-or-v1-h7-hardened-secret-999',
    }, storage, { skipConnectionCheck: true })

    const row = storage.db.select().from(modelProfiles).where(eq(modelProfiles.id, saved.id)).get()!
    const credPath = join(dir, 'credentials', row.credentialId)
    const pinPath = join(dir, 'credentials', `${row.credentialId}.pin`)
    const ledgerPath = join(dir, 'credentials', '.pin-ledger.json')

    // 1) Attack: delete .pin AND tamper SQLite endpoint -> MUST fail closed via HMAC-authenticated ledger!
    unlinkSync(pinPath)
    storage.db.update(modelProfiles)
      .set({ endpoint: 'https://attacker.example/v1' })
      .where(eq(modelProfiles.id, saved.id))
      .run()
    assert.equal(
      privateModelProfiles(storage).length,
      0,
      'deleting .pin + tampering SQLite endpoint MUST fail closed',
    )
    await assert.rejects(
      checkModelConnection({
        id: saved.id,
        name: 'H7 OpenRouter',
        endpoint: 'https://attacker.example/v1',
        model: 'deepseek/deepseek-v4.1-flash-1017',
        protocol: 'responses',
        key: '',
      }, storage),
      /pinned to a different endpoint or protocol/i,
    )

    // Restore original endpoint -> loads cleanly again
    storage.db.update(modelProfiles)
      .set({ endpoint: 'https://openrouter.ai/api/v1' })
      .where(eq(modelProfiles.id, saved.id))
      .run()
    assert.equal(privateModelProfiles(storage).length, 1)

    // 2) Tampering .pin-ledger.json HMAC fails closed
    const originalLedger = readFileSync(ledgerPath, 'utf8')
    writeFileSync(ledgerPath, originalLedger.replace(/"hmac":"[0-9a-f]{64}"/, `"hmac":"${'0'.repeat(64)}"`), { mode: 0o600 })
    assert.equal(privateModelProfiles(storage).length, 0, 'tampered pin ledger HMAC must fail closed')
    writeFileSync(ledgerPath, originalLedger, { mode: 0o600 })
    chmodSync(ledgerPath, 0o600)
    assert.equal(privateModelProfiles(storage).length, 1)

    // 3) Symlink on .pin path (even dangling!) is rejected
    symlinkSync(join(dir, 'nonexistent-target'), pinPath)
    assert.equal(privateModelProfiles(storage).length, 0, 'dangling symlink on .pin path must fail closed')
    unlinkSync(pinPath)

    // 4) Symlink on credential file is rejected via lstatSync
    const outsideFile = join(dir, 'outside-secret')
    writeFileSync(outsideFile, 'sk-or-v1-symlinked-secret-000', { mode: 0o600 })
    unlinkSync(credPath)
    symlinkSync(outsideFile, credPath)
    assert.equal(privateModelProfiles(storage).length, 0, 'symlinked credential file must be refused via lstatSync')
    await assert.rejects(
      saveModelProfile({
        id: saved.id,
        name: 'H7 OpenRouter',
        endpoint: 'https://openrouter.ai/api/v1',
        model: 'deepseek/deepseek-v4.1-flash-1017',
        protocol: 'responses',
        key: '',
      }, storage, { skipConnectionCheck: true }),
      /symbolic link/i,
    )
  })
})

// ---------------------------------------------------------------------------
// 5. H8: Secret Custody, 6-7 Char Scrubbing, Expanded Encodings/Headers & Regex Anti-Oracle/ReDoS
// ---------------------------------------------------------------------------

describe('H8: EgressSanitizer, derived-custody.ts, and redact.ts hardening', () => {
  test('scrubs 6–7 char sealed capabilities while preserving common short English/JSON words', () => {
    const vault = new DerivedCapabilityVault({ runId: 'run-h8-short' })
    vault.seal({ hopReceiptId: '1', slot: 'otp6', rawValue: '482910' })
    vault.seal({ hopReceiptId: '1', slot: 'tok6', rawValue: 'tok987' })
    vault.seal({ hopReceiptId: '1', slot: 'tok7', rawValue: 'xK9mP2a' })
    vault.seal({ hopReceiptId: '1', slot: 'word6', rawValue: 'status' })
    vault.seal({ hopReceiptId: '1', slot: 'word7', rawValue: 'pending' })

    const descriptors = vaultScrubDescriptors(vault)
    const values = descriptors.map(d => d.value)
    assert.ok(values.includes('482910'), '6-char numeric OTP must be scrubbed')
    assert.ok(values.includes('tok987'), '6-char mixed token must be scrubbed')
    assert.ok(values.includes('xK9mP2a'), '7-char high-entropy token must be scrubbed')
    assert.equal(values.includes('status'), false, 'common JSON word "status" must not be scrubbed')
    assert.equal(values.includes('pending'), false, 'common JSON word "pending" must not be scrubbed')

    const sanitizer = createEgressSanitizer({ capabilityVaults: [vault] })
    const sample = JSON.stringify({ status: 'pending', otp: '482910', t6: 'tok987', t7: 'xK9mP2a' })
    const scrubbed = sanitizer.redactSecrets(sample)
    assert.equal(scrubbed.includes('482910'), false)
    assert.equal(scrubbed.includes('tok987'), false)
    assert.equal(scrubbed.includes('xK9mP2a'), false)
    assert.ok(scrubbed.includes('"status":"pending"'), 'common JSON words must stay intact')

    const directScrub = scrubDerivedSecrets('leaked 482910 and tok987 with status', vault)
    assert.equal(directScrub.includes('482910'), false)
    assert.equal(directScrub.includes('tok987'), false)
    assert.ok(directScrub.includes('status'))
  })

  test('redact.ts strips expanded sensitive headers and generates hex, double-URL, \\uXXXX, and cookie value-only variants', () => {
    const headers = sanitizeHttpHeaders({
      'WWW-Authenticate': 'Bearer realm="secret"',
      'Proxy-Authenticate': 'Basic realm="proxy"',
      'Set-Cookie2': 'sid=abc123456',
      'X-Forwarded-Cookie': 'sid=abc123456',
      'Private-Token': 'glpat-xyz123456789',
      'X-Vault-Token': 'hvs.secret998877',
      'X-Normal-Header': 'hello',
    })
    for (const k of ['WWW-Authenticate', 'Proxy-Authenticate', 'Set-Cookie2', 'X-Forwarded-Cookie', 'Private-Token', 'X-Vault-Token']) {
      assert.equal(headers[k], '[redacted]', `${k} must be structurally stripped`)
    }
    assert.equal(headers['X-Normal-Header'], 'hello')

    const cookieSecret = 'sid=s3cr3t+val/99'
    const variants = buildSecretEncodingVariants(cookieSecret, 6)
    const hexLower = Buffer.from(cookieSecret, 'utf8').toString('hex')
    const doubleUrl = encodeURIComponent(encodeURIComponent(cookieSecret))
    assert.ok(variants.includes(hexLower), 'hex encoding variant must be included')
    assert.ok(variants.includes(doubleUrl), 'double URL-encoded variant must be included')
    assert.ok(variants.some(v => v.includes('\\u003d')), '\\uXXXX JSON unicode escape must be included')
    assert.ok(variants.includes('s3cr3t+val/99'), 'cookie value-only stripped variant must be included')
  })

  test('compileSafeSealRegex / extractSafeSealRegexMatch block ReDoS and binary-search oracles while allowing legitimate SSE/token regexes', () => {
    // ReDoS patterns rejected
    assert.throws(() => compileSafeSealRegex('(a+)+$'), /ReDoS|Nested quantifiers/i)
    assert.throws(() => compileSafeSealRegex('([a-zA-Z]+)*$'), /ReDoS|Nested quantifiers/i)
    assert.throws(() => compileSafeSealRegex('(a|aa)+$'), /ReDoS|alternation/i)

    // Byte-by-byte binary-search oracle patterns rejected
    assert.throws(() => compileSafeSealRegex('"token":"sec_live_[a-m]'), /partial-alphabet|binary-search/i)
    assert.throws(() => compileSafeSealRegex('"token":"sec_live_[n-z]'), /partial-alphabet|binary-search/i)
    assert.throws(() => compileSafeSealRegex('"token":"sec_live_[0-4]'), /partial-alphabet|binary-search/i)
    assert.throws(() => compileSafeSealRegex('"token":"(sec_live_[a-m])"'), /partial-alphabet|binary-search/i)
    assert.throws(() => compileSafeSealRegex('"token":"sec_live_[abcdefghijklm]'), /subset class|binary-search/i)
    assert.throws(() => compileSafeSealRegex('"token":"(.)"'), /variable token/i)
    assert.throws(() => compileSafeSealRegex('"token":"(sec_live_.)"'), /variable token/i)

    // Low-entropy alternating value rejected by validateCapabilitySealValue
    assert.throws(() => validateCapabilitySealValue('ababababab', 'regex'), /low-entropy|distinct/i)

    // Legitimate kovo_verify SSE / JSON / Bearer / hex token regexes PASS
    const sseBody = 'event: auth\ndata: tok_live_99887766aabb\n\n'
    assert.equal(extractSafeSealRegexMatch('data:\\s*([A-Za-z0-9._-]{8,})', sseBody), 'tok_live_99887766aabb')
    assert.equal(extractSafeSealRegexMatch('"token"\\s*:\\s*"([^"]+)"', '{"token":"sec_valid_12345678"}'), 'sec_valid_12345678')
    assert.equal(extractSafeSealRegexMatch('Bearer\\s+([A-Za-z0-9._~+/-]+=*)', 'Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.payload.sig123'), 'eyJhbGciOiJIUzI1NiJ9.payload.sig123')
    assert.equal(extractSafeSealRegexMatch('token=([0-9a-fA-F]{16,64})', 'token=0123456789abcdef9876'), '0123456789abcdef9876')

    // Per-session seal attempt cap & symlink persistence refusal in DerivedCapabilityVault
    const cappedVault = new DerivedCapabilityVault({ runId: 'run-h8-cap', maxSealAttempts: 2 })
    cappedVault.seal({ hopReceiptId: '1', slot: 's1', rawValue: 'val_one_123456' })
    cappedVault.seal({ hopReceiptId: '1', slot: 's2', rawValue: 'val_two_123456' })
    assert.throws(
      () => cappedVault.seal({ hopReceiptId: '1', slot: 's3', rawValue: 'val_three_123456' }),
      (err: unknown) => err instanceof DerivedCustodyError && err.code === 'CAPACITY_EXCEEDED',
    )
  })
})
