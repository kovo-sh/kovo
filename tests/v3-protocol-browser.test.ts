/**
 * Guardian v3 protocol & interactive browser loopback unit tests:
 *   1. RequestBroker.probeWebsocket + verifyReplaySpec (ws_chain)
 *   2. RequestBroker benign multipartParts upload + verifyReplaySpec (upload_probe)
 *   3. ScopedBrowser.visitPage interactive actions (fill, click, wait_for_selector, dom_xss_sink_hook)
 *      + verifyReplaySpec (browser_chain)
 *   4. ReplayVerifier requireControlNonError guardrail (unexpected 404/5xx -> inconclusive)
 */
import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { once } from 'node:events'
import { createServer } from 'node:http'
import type { IncomingMessage } from 'node:http'
import type { Duplex } from 'node:stream'
import { test } from 'node:test'
import { BrokerApprovalRequired, BrokerDenied, RequestBroker } from '../src/server/broker.ts'
import type { Grant } from '../src/server/broker.ts'
import type { ResolvedPersona } from '../src/server/persona-vault.ts'
import { verifyReplaySpec } from '../src/server/replay-verifier.ts'
import { ScopedBrowser } from '../src/server/scoped-browser.ts'
import { LinuxWorkerBackend } from '../src/server/worker-backend.ts'

const WS_GUID = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11'

async function withEnv<T>(vars: Record<string, string | undefined>, fn: () => Promise<T> | T): Promise<T> {
  const prev: Record<string, string | undefined> = {}
  for (const [k, v] of Object.entries(vars)) {
    prev[k] = process.env[k]
    if (v === undefined) delete process.env[k]
    else process.env[k] = v
  }
  try {
    return await fn()
  } finally {
    for (const [k, v] of Object.entries(prev)) {
      if (v === undefined) delete process.env[k]
      else process.env[k] = v
    }
  }
}

function makeLabGrant(origin: string, overrides: Partial<Grant> = {}): Grant {
  return {
    origin,
    tier: 2,
    maxRpsPerOrigin: 30,
    allowLocalLab: true,
    canRead: o => o === origin,
    audit: () => {},
    ...overrides,
  }
}

function encodeServerWsFrame(opcode: number, payload: Buffer): Buffer {
  const len = payload.length
  let header: Buffer
  if (len < 126) {
    header = Buffer.alloc(2)
    header[0] = 0x80 | (opcode & 0x0f)
    header[1] = len
  } else if (len < 65_536) {
    header = Buffer.alloc(4)
    header[0] = 0x80 | (opcode & 0x0f)
    header[1] = 126
    header.writeUInt16BE(len, 2)
  } else {
    header = Buffer.alloc(10)
    header[0] = 0x80 | (opcode & 0x0f)
    header[1] = 127
    header.writeBigUInt64BE(BigInt(len), 2)
  }
  return Buffer.concat([header, payload])
}

function decodeMaskedClientFrames(buf: Buffer): { messages: string[]; rest: Buffer } {
  const messages: string[] = []
  let offset = 0
  while (buf.length - offset >= 2) {
    const b0 = buf[offset]
    const b1 = buf[offset + 1]
    const opcode = b0 & 0x0f
    const masked = (b1 & 0x80) !== 0
    let len = b1 & 0x7f
    let pos = offset + 2
    if (len === 126) {
      if (buf.length - offset < 4) break
      len = buf.readUInt16BE(offset + 2)
      pos = offset + 4
    } else if (len === 127) {
      if (buf.length - offset < 10) break
      len = Number(buf.readBigUInt64BE(offset + 2))
      pos = offset + 10
    }
    const maskLen = masked ? 4 : 0
    if (buf.length - pos < maskLen + len) break
    let payload = buf.subarray(pos + maskLen, pos + maskLen + len)
    if (masked) {
      const key = buf.subarray(pos, pos + 4)
      const unmasked = Buffer.alloc(len)
      for (let i = 0; i < len; i += 1) unmasked[i] = payload[i] ^ key[i & 3]
      payload = unmasked
    }
    offset = pos + maskLen + len
    if (opcode === 0x1) messages.push(payload.toString('utf8'))
  }
  return { messages, rest: buf.subarray(offset) }
}

function readRequestBody(req: IncomingMessage): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = []
    req.on('data', chunk => chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk)))
    req.on('end', () => resolve(Buffer.concat(chunks)))
    req.on('error', reject)
  })
}

// ============================================================================
// 1. RequestBroker.probeWebsocket + verifyReplaySpec (ws_chain)
// ============================================================================

test('v3 WebSocket: probeWebsocket origin/scope/bounds/redaction & ws_chain replay confirmation/dismissal', async t => {
  const personaSecret = 'ws-persona-bearer-secret-424242'
  const server = createServer((_req, res) => {
    res.writeHead(426, { 'Content-Type': 'text/plain' }).end('Upgrade Required')
  })

  const upgradeSockets = new Set<Duplex>()
  server.on('upgrade', (req: IncomingMessage, socket: Duplex) => {
    upgradeSockets.add(socket)
    socket.on('close', () => upgradeSockets.delete(socket))
    socket.on('error', () => { /* ignore client reset on bounded probe close */ })

    const reqOrigin = req.headers.origin ?? ''
    const auth = req.headers.authorization ?? ''
    const wsKey = req.headers['sec-websocket-key']
    const path = req.url ?? '/'

    if (!wsKey || typeof wsKey !== 'string') {
      socket.end('HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n')
      return
    }

    const addr = server.address()
    const expectedOrigin = addr && typeof addr !== 'string' ? `http://127.0.0.1:${addr.port}` : ''

    if (path === '/ws/missing') {
      socket.end('HTTP/1.1 404 Not Found\r\nConnection: close\r\n\r\n')
      return
    }

    if (path === '/ws/strict' && reqOrigin !== expectedOrigin) {
      socket.end('HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\n')
      return
    }

    const accept = createHash('sha1').update(wsKey + WS_GUID).digest('base64')
    socket.write([
      'HTTP/1.1 101 Switching Protocols',
      'Upgrade: websocket',
      'Connection: Upgrade',
      `Sec-WebSocket-Accept: ${accept}`,
      '',
      '',
    ].join('\r\n'))

    if (path === '/ws/flood') {
      // Emit 12 frames of 400 bytes each to verify maxFrames and maxBytes caps
      for (let i = 0; i < 12; i += 1) {
        const msg = `frame-${i}:` + 'X'.repeat(390)
        socket.write(encodeServerWsFrame(0x1, Buffer.from(msg, 'utf8')))
      }
      socket.resume()
      return
    }

    const authed = auth === `Bearer ${personaSecret}`
    const hello = JSON.stringify({
      event: 'account_snapshot',
      authenticated: authed,
      originSeen: reqOrigin,
      account: authed ? 'alice@northstar.invalid' : 'anonymous',
      echoAuth: auth, // Intentionally echoes secret so broker redaction is verified
    })
    socket.write(encodeServerWsFrame(0x1, Buffer.from(hello, 'utf8')))

    let pending: Buffer<ArrayBufferLike> = Buffer.alloc(0)
    socket.on('data', (chunk: Buffer) => {
      pending = Buffer.concat([pending, chunk])
      const decoded = decodeMaskedClientFrames(pending)
      pending = decoded.rest
      for (const msg of decoded.messages) {
        const reply = JSON.stringify({ event: 'reply', echo: msg, authenticated: authed })
        socket.write(encodeServerWsFrame(0x1, Buffer.from(reply, 'utf8')))
      }
    })
  })

  server.listen(0, '127.0.0.1')
  await once(server, 'listening')
  t.after(() => {
    for (const s of upgradeSockets) s.destroy()
    server.closeAllConnections()
    return new Promise<void>(resolve => server.close(() => resolve()))
  })
  const addr = server.address()
  if (!addr || typeof addr === 'string') throw new Error('no server address')
  const origin = `http://127.0.0.1:${addr.port}`

  const personas = new Map<string, ResolvedPersona>([
    ['alice', {
      id: 'p-alice',
      handle: 'alice',
      roleLabel: 'Alice',
      authKind: 'bearer',
      headerName: 'Authorization',
      originAllowlist: [origin],
      secret: personaSecret,
      canaryMarkers: [],
    }],
  ])

  await withEnv({ GUARDIAN_ALLOW_LOCAL_LAB: '1' }, async () => {
    const broker = new RequestBroker({ rejectUnauthorized: false })
    const backend = new LinuxWorkerBackend()
    const sig = AbortSignal.timeout(45_000)

    // Scope & tier denials
    await assert.rejects(
      broker.probeWebsocket({ origin, pathAndQuery: '/ws/cswsh' }, makeLabGrant(origin, { tier: 0 }), sig),
      BrokerDenied,
      'Tier 0 must block live WebSocket probing',
    )
    await assert.rejects(
      broker.probeWebsocket({ origin: 'http://127.0.0.1:9', pathAndQuery: '/ws/cswsh' }, makeLabGrant(origin, { tier: 2 }), sig),
      BrokerDenied,
      'Unapproved origin must be denied',
    )
    await assert.rejects(
      broker.probeWebsocket({ origin, pathAndQuery: '/ws/cswsh', persona: 'alice' }, makeLabGrant(origin, { tier: 1, personas }), sig),
      BrokerDenied,
      'Persona-authenticated WS probe must be denied below Tier 2',
    )

    // Same-origin vs untrusted-origin on strict endpoint
    const strictSame = await broker.probeWebsocket({
      origin,
      pathAndQuery: '/ws/strict',
      originHeader: origin,
      persona: 'alice',
      timeoutMs: 1500,
    }, makeLabGrant(origin, { tier: 2, personas }), sig)
    assert.equal(strictSame.connected, true)
    assert.equal(strictSame.upgradeStatus, 101)
    assert.ok(strictSame.frames.some(f => f.direction === 'received' && f.data.includes('alice@northstar.invalid')))
    assert.ok(!JSON.stringify(strictSame).includes(personaSecret), 'persona secret must be redacted from WS frames')

    const strictEvil = await broker.probeWebsocket({
      origin,
      pathAndQuery: '/ws/strict',
      originHeader: 'https://evil.invalid',
      persona: 'alice',
      timeoutMs: 1500,
    }, makeLabGrant(origin, { tier: 2, personas }), sig)
    assert.equal(strictEvil.connected, false)
    assert.equal(strictEvil.upgradeStatus, 403)

    // Frame and byte bounds enforced cleanly
    const boundedFrames = await broker.probeWebsocket({
      origin,
      pathAndQuery: '/ws/flood',
      maxFrames: 2,
      maxBytes: 64 * 1024,
      timeoutMs: 1500,
    }, makeLabGrant(origin, { tier: 2 }), sig)
    assert.equal(boundedFrames.connected, true)
    assert.ok(boundedFrames.receivedFrames <= 2, `expected <= 2 frames, got ${boundedFrames.receivedFrames}`)

    const boundedBytes = await broker.probeWebsocket({
      origin,
      pathAndQuery: '/ws/flood',
      maxFrames: 20,
      maxBytes: 1024,
      timeoutMs: 1500,
    }, makeLabGrant(origin, { tier: 2 }), sig)
    assert.equal(boundedBytes.connected, true)
    assert.ok(boundedBytes.totalBytes <= 1024, `expected <= 1024 bytes, got ${boundedBytes.totalBytes}`)

    // Deterministic ws_chain verification: vulnerable CSWSH confirmed
    const cswshConfirmed = await verifyReplaySpec({
      spec: {
        version: 1,
        kind: 'ws_chain',
        origin,
        title: 'Cross-Site WebSocket Hijacking on /ws/cswsh',
        category: 'cors-client-side',
        cwe: 'CWE-346',
        severity: 'high',
        severityRationale: 'Authenticated WebSocket accepts arbitrary cross-origin handshake.',
        impact: 'Untrusted origin can connect with victim credentials and receive account events.',
        remediation: 'Validate the Origin header against an explicit allowlist during upgrade.',
        recheckInstructions: 'Reject non-allowlisted Origin headers with HTTP 403.',
        steps: [
          {
            id: 'control',
            role: 'control',
            description: 'Same-origin authenticated WebSocket handshake',
            origin,
            pathAndQuery: '/ws/cswsh',
            originHeader: origin,
            persona: 'alice',
            sendMessages: ['ping'],
            maxFrames: 4,
            waitMs: 500,
          },
          {
            id: 'probe',
            role: 'probe',
            description: 'Untrusted-origin authenticated WebSocket handshake',
            origin,
            pathAndQuery: '/ws/cswsh',
            originHeader: 'https://evil.invalid',
            persona: 'alice',
            sendMessages: ['ping'],
            maxFrames: 4,
            waitMs: 500,
          },
        ],
        assertionsJq: '{ controlPassed: (.steps.control.connected and .steps.control.json.authenticated == true), confirmed: (.steps.probe.connected and .steps.probe.upgradeStatus == 101 and .steps.probe.json.authenticated == true and .steps.probe.json.originSeen == "https://evil.invalid"), observed: ("probe_status=" + (.steps.probe.upgradeStatus | tostring)), expected: "untrusted Origin rejected with 403" }',
      },
      broker,
      backend,
      grant: makeLabGrant(origin, { tier: 2, personas }),
      signal: sig,
    })
    assert.equal(cswshConfirmed.verdict, 'confirmed', `expected confirmed, got ${cswshConfirmed.verdict}: ${cswshConfirmed.outcome.observed}`)
    assert.equal(cswshConfirmed.verificationTier, 'runtime_confirmed')
    assert.ok(!JSON.stringify(cswshConfirmed.evidencePayload).includes(personaSecret))

    // Deterministic ws_chain verification: hardened strict endpoint dismissed
    const strictDismissed = await verifyReplaySpec({
      spec: {
        version: 1,
        kind: 'ws_chain',
        origin,
        title: 'Cross-Site WebSocket Hijacking check on /ws/strict',
        category: 'cors-client-side',
        cwe: 'CWE-346',
        severity: 'high',
        severityRationale: 'Verify Origin enforcement on strict WebSocket endpoint.',
        impact: 'Untrusted origin could hijack session if Origin is not checked.',
        remediation: 'Enforce strict Origin allowlist.',
        recheckInstructions: 'Confirm untrusted Origin receives HTTP 403.',
        steps: [
          {
            id: 'control',
            role: 'control',
            description: 'Same-origin WebSocket handshake',
            origin,
            pathAndQuery: '/ws/strict',
            originHeader: origin,
            persona: 'alice',
            maxFrames: 3,
            waitMs: 500,
          },
          {
            id: 'probe',
            role: 'probe',
            description: 'Untrusted-origin WebSocket handshake',
            origin,
            pathAndQuery: '/ws/strict',
            originHeader: 'https://evil.invalid',
            persona: 'alice',
            maxFrames: 3,
            waitMs: 500,
          },
        ],
        assertionsJq: '{ controlPassed: (.steps.control.connected and .steps.control.upgradeStatus == 101), confirmed: (.steps.probe.connected and .steps.probe.upgradeStatus == 101), observed: ("probe_status=" + (.steps.probe.upgradeStatus | tostring)), expected: "403 on untrusted origin" }',
      },
      broker,
      backend,
      grant: makeLabGrant(origin, { tier: 2, personas }),
      signal: sig,
    })
    assert.equal(strictDismissed.verdict, 'dismissed', `expected dismissed, got ${strictDismissed.verdict}`)

    // requireControlNonError on ws_chain unexpected 404 -> inconclusive
    const ws404 = await verifyReplaySpec({
      spec: {
        version: 1,
        kind: 'ws_chain',
        origin,
        title: 'WebSocket endpoint missing',
        category: 'cors-client-side',
        cwe: 'CWE-346',
        severity: 'medium',
        severityRationale: 'Check posture on missing WebSocket endpoint.',
        impact: 'None when endpoint does not exist.',
        remediation: 'N/A',
        recheckInstructions: 'Verify endpoint path.',
        steps: [
          { id: 'control', role: 'control', description: 'Missing WS', origin, pathAndQuery: '/ws/missing', maxFrames: 2, waitMs: 300 },
          { id: 'probe', role: 'probe', description: 'Missing WS probe', origin, pathAndQuery: '/ws/missing', originHeader: 'https://evil.invalid', maxFrames: 2, waitMs: 300 },
        ],
        assertionsJq: '{ controlPassed: true, confirmed: true, observed: "404", expected: "101" }',
      },
      broker,
      backend,
      grant: makeLabGrant(origin, { tier: 2 }),
      signal: sig,
    })
    assert.equal(ws404.verdict, 'inconclusive', 'unexpected 404 on ws_chain posture check must yield inconclusive')
  })
})

// ============================================================================
// 2. RequestBroker multipartParts upload + verifyReplaySpec (upload_probe)
// ============================================================================

test('v3 upload: Tier 3 gating, webshell & 256 KiB rejection, and upload_probe inline vs attachment control', async t => {
  const uploads = new Map<string, { contentType: string; body: string; attachment: boolean }>()
  let seq = 0
  let cleanupCalls = 0

  const server = createServer(async (req, res) => {
    const url = new URL(req.url ?? '/', 'http://127.0.0.1')
    if (req.method === 'GET' && url.pathname === '/api/uploads/status') {
      res.writeHead(200, { 'Content-Type': 'application/json' }).end(JSON.stringify({ ok: true, count: uploads.size }))
      return
    }
    if (req.method === 'POST' && (url.pathname === '/api/upload/inline' || url.pathname === '/api/upload/safe')) {
      const raw = (await readRequestBody(req)).toString('utf8')
      const ctHeader = req.headers['content-type'] ?? ''
      const boundaryMatch = /boundary=([^\s;]+)/i.exec(ctHeader)
      if (!boundaryMatch) {
        res.writeHead(400, { 'Content-Type': 'application/json' }).end(JSON.stringify({ error: 'missing boundary' }))
        return
      }
      // Extract the first file part's Content-Type and body from the multipart payload
      const parts = raw.split(`--${boundaryMatch[1]}`).slice(1, -1)
      const firstPart = parts[0] ?? ''
      const headerEnd = firstPart.indexOf('\r\n\r\n')
      const partHeaders = headerEnd >= 0 ? firstPart.slice(0, headerEnd) : ''
      const partBody = headerEnd >= 0 ? firstPart.slice(headerEnd + 4).replace(/\r\n$/, '') : ''
      const partCtMatch = /content-type:\s*([^\r\n]+)/i.exec(partHeaders)
      const id = `up_${++seq}`
      uploads.set(id, {
        contentType: partCtMatch ? partCtMatch[1].trim() : 'application/octet-stream',
        body: partBody,
        attachment: url.pathname === '/api/upload/safe',
      })
      res.writeHead(201, { 'Content-Type': 'application/json' }).end(JSON.stringify({ id, url: `/files/${id}` }))
      return
    }
    if (req.method === 'GET' && url.pathname.startsWith('/files/')) {
      const id = url.pathname.slice('/files/'.length)
      const item = uploads.get(id)
      if (!item) {
        res.writeHead(404, { 'Content-Type': 'text/plain' }).end('not found')
        return
      }
      const headers: Record<string, string> = {
        'Content-Type': item.contentType,
      }
      if (item.attachment) {
        headers['Content-Disposition'] = 'attachment; filename="download.svg"'
        headers['X-Content-Type-Options'] = 'nosniff'
      }
      res.writeHead(200, headers).end(item.body)
      return
    }
    if (req.method === 'DELETE' && url.pathname.startsWith('/files/')) {
      const id = url.pathname.slice('/files/'.length)
      uploads.delete(id)
      cleanupCalls += 1
      res.writeHead(200, { 'Content-Type': 'application/json' }).end(JSON.stringify({ deleted: id }))
      return
    }
    res.writeHead(404, { 'Content-Type': 'text/plain' }).end('not found')
  })

  server.listen(0, '127.0.0.1')
  await once(server, 'listening')
  t.after(() => {
    server.closeAllConnections()
    return new Promise<void>(resolve => server.close(() => resolve()))
  })
  const addr = server.address()
  if (!addr || typeof addr === 'string') throw new Error('no address')
  const origin = `http://127.0.0.1:${addr.port}`

  await withEnv({ GUARDIAN_ALLOW_LOCAL_LAB: '1' }, async () => {
    const broker = new RequestBroker({ rejectUnauthorized: false })
    const backend = new LinuxWorkerBackend()
    const sig = AbortSignal.timeout(45_000)

    const benignPart = [{
      name: 'file',
      filename: 'benign.svg',
      contentType: 'image/svg+xml',
      content: '<svg xmlns="http://www.w3.org/2000/svg"><text>hello-nonce</text></svg>',
    }]

    // Tier 1 and Tier 2 reject multipartParts
    for (const tier of [1, 2] as const) {
      await assert.rejects(
        broker.executeHttp({ origin, method: 'POST', pathAndQuery: '/api/upload/inline', multipartParts: benignPart }, makeLabGrant(origin, { tier }), sig),
        BrokerDenied,
        `multipart upload must be denied at Tier ${tier}`,
      )
    }

    // Tier 3 without HITL approval raises BrokerApprovalRequired
    await assert.rejects(
      broker.executeHttp(
        { origin, method: 'POST', pathAndQuery: '/api/upload/inline', multipartParts: benignPart },
        makeLabGrant(origin, { tier: 3, isStateChangeApproved: () => false }),
        sig,
      ),
      BrokerApprovalRequired,
    )

    // Webshell signatures rejected even at approved Tier 3
    for (const badPayload of [
      ['<', '?php system($_GET["c"]); ?', '>'].join(''),
      '<% Runtime.getRuntime().exec("id") %>',
      'const cp = require("child_process");',
    ]) {
      await assert.rejects(
        broker.executeHttp(
          {
            origin,
            method: 'POST',
            pathAndQuery: '/api/upload/inline',
            multipartParts: [{ name: 'file', filename: 'test.txt', contentType: 'text/plain', content: badPayload }],
          },
          makeLabGrant(origin, { tier: 3, isStateChangeApproved: () => true }),
          sig,
        ),
        BrokerDenied,
        'webshell signature must be rejected by broker',
      )
    }

    // 256 KiB cap enforced (256 KiB + 1 byte rejected)
    await assert.rejects(
      broker.executeHttp(
        {
          origin,
          method: 'POST',
          pathAndQuery: '/api/upload/inline',
          multipartParts: [{ name: 'file', filename: 'oversize.txt', contentType: 'text/plain', content: 'A'.repeat(256 * 1024 + 1) }],
        },
        makeLabGrant(origin, { tier: 3, isStateChangeApproved: () => true }),
        sig,
      ),
      BrokerDenied,
      'upload exceeding 256 KiB must be rejected',
    )

    const makeUploadSpec = (uploadPath: string) => ({
      version: 1 as const,
      kind: 'upload_probe' as const,
      requiresTier3Approval: true as const,
      origin,
      title: `Inline SVG upload render check on ${uploadPath}`,
      category: 'upload-storage',
      cwe: 'CWE-434',
      severity: 'high' as const,
      severityRationale: 'User-uploaded SVG served inline without Content-Disposition: attachment.',
      impact: 'Stored active content executes in the application origin.',
      remediation: 'Serve uploaded files from an isolated domain or with Content-Disposition: attachment and nosniff.',
      recheckInstructions: 'Verify uploaded SVG is served as attachment.',
      controlStep: {
        id: 'control',
        role: 'control' as const,
        description: 'Check upload endpoint health before upload',
        request: { origin, method: 'GET' as const, pathAndQuery: '/api/uploads/status' },
      },
      uploadStep: {
        id: 'upload',
        role: 'probe' as const,
        description: 'Upload benign nonce-bearing SVG',
        origin,
        method: 'POST' as const,
        pathAndQuery: uploadPath,
        fieldName: 'file',
        filename: 'guardian-benign.svg',
        contentType: 'image/svg+xml',
        contentTemplate: '<svg xmlns="http://www.w3.org/2000/svg"><text>{{upload_nonce}}</text></svg>',
        extract: [{ varName: 'upload_id', from: 'json' as const, selector: 'id' }],
      },
      fetchStep: {
        id: 'fetch',
        role: 'probe' as const,
        description: 'Fetch uploaded file and check Content-Type / Content-Disposition',
        request: { origin, method: 'GET' as const, pathAndQuery: '/files/{{upload_id}}' },
      },
      cleanupStep: {
        id: 'cleanup',
        role: 'cleanup' as const,
        description: 'Delete test upload artifact',
        request: { origin, method: 'DELETE' as const, pathAndQuery: '/files/{{upload_id}}' },
      },
      assertionsJq: '{ controlPassed: (.steps.control.status == 200 and .uploadProof.nonceInFetchBody == true and .uploadProof.controlLeak == false), confirmed: (.uploadProof.nonceInFetchBody == true and .uploadProof.unsafeInlineRender == true and .uploadProof.hasAttachmentDisposition == false), observed: ("ct=" + (.uploadProof.fetchContentType // "") + " attachment=" + (.uploadProof.hasAttachmentDisposition | tostring)), expected: "Content-Disposition: attachment" }',
    })

    // upload_probe blocked below Tier 3 and without Tier 3 HITL approval
    const deniedTier2 = await verifyReplaySpec({
      spec: makeUploadSpec('/api/upload/inline'),
      broker,
      backend,
      grant: makeLabGrant(origin, { tier: 2 }),
      signal: sig,
    })
    assert.equal(deniedTier2.verdict, 'inconclusive')

    const deniedHitl = await verifyReplaySpec({
      spec: makeUploadSpec('/api/upload/inline'),
      broker,
      backend,
      grant: makeLabGrant(origin, { tier: 3, isStateChangeApproved: () => false }),
      signal: sig,
    })
    assert.equal(deniedHitl.verdict, 'inconclusive')

    // Approved Tier 3 upload_probe against inline SVG endpoint -> confirmed + cleanup executed
    const inlineConfirmed = await verifyReplaySpec({
      spec: makeUploadSpec('/api/upload/inline'),
      broker,
      backend,
      grant: makeLabGrant(origin, { tier: 3, isStateChangeApproved: () => true }),
      signal: sig,
    })
    assert.equal(inlineConfirmed.verdict, 'confirmed', `expected confirmed, got ${inlineConfirmed.verdict}: ${inlineConfirmed.outcome.observed}`)
    assert.equal(inlineConfirmed.verificationTier, 'runtime_confirmed')
    const inlineProof = inlineConfirmed.evidencePayload.uploadProof as Record<string, unknown>
    assert.equal(inlineProof.nonceInFetchBody, true)
    assert.equal(inlineProof.hasAttachmentDisposition, false)
    assert.equal(inlineProof.unsafeInlineRender, true)
    assert.equal(cleanupCalls, 1, 'cleanupStep must remove uploaded test artifact')
    assert.equal(uploads.size, 0)

    // Approved Tier 3 upload_probe against Content-Disposition: attachment control -> dismissed + cleanup executed
    const safeDismissed = await verifyReplaySpec({
      spec: makeUploadSpec('/api/upload/safe'),
      broker,
      backend,
      grant: makeLabGrant(origin, { tier: 3, isStateChangeApproved: () => true }),
      signal: sig,
    })
    assert.equal(safeDismissed.verdict, 'dismissed', `expected dismissed on attachment control, got ${safeDismissed.verdict}`)
    const safeProof = safeDismissed.evidencePayload.uploadProof as Record<string, unknown>
    assert.equal(safeProof.nonceInFetchBody, true)
    assert.equal(safeProof.hasAttachmentDisposition, true)
    assert.equal(safeProof.unsafeInlineRender, false)
    assert.equal(cleanupCalls, 2)
  })
})

// ============================================================================
// 3. ScopedBrowser interactive actions + verifyReplaySpec (browser_chain)
// ============================================================================

test('v3 ScopedBrowser & browser_chain: 100% broker-proxied, out-of-scope abort, fill/click/wait_for_selector/dom_xss_sink_hook', async t => {
  let thirdPartyHits = 0
  const thirdPartyServer = createServer((_req, res) => {
    thirdPartyHits += 1
    res.writeHead(200, { 'Content-Type': 'application/javascript' }).end('window.__thirdPartyLoaded = true;')
  })
  thirdPartyServer.listen(0, '127.0.0.1')
  await once(thirdPartyServer, 'listening')
  t.after(() => {
    thirdPartyServer.closeAllConnections()
    return new Promise<void>(resolve => thirdPartyServer.close(() => resolve()))
  })
  const tpAddr = thirdPartyServer.address()
  if (!tpAddr || typeof tpAddr === 'string') throw new Error('no tp address')
  const thirdPartyOrigin = `http://127.0.0.1:${tpAddr.port}`

  let appHits = 0
  const appServer = createServer((req, res) => {
    appHits += 1
    const url = new URL(req.url ?? '/', 'http://127.0.0.1')
    const isSafe = url.pathname === '/safe'
    const html = `<!doctype html>
<html>
<head><title>${isSafe ? 'Safe Preview' : 'Vuln Preview'}</title></head>
<body>
  <script src="${thirdPartyOrigin}/unapproved.js"></script>
  <input id="note-input" type="text" />
  <button id="render-btn" type="button">Render</button>
  <div id="output"></div>
  <script>
    const isSafe = ${isSafe ? 'true' : 'false'};
    function renderValue(v) {
      const out = document.getElementById('output');
      if (isSafe) {
        out.textContent = v;
      } else {
        out.innerHTML = '<em class="preview">' + v + '</em>';
      }
      if (!document.getElementById('rendered-badge')) {
        const badge = document.createElement('span');
        badge.id = 'rendered-badge';
        badge.textContent = 'rendered';
        document.body.appendChild(badge);
      }
    }
    document.getElementById('render-btn').addEventListener('click', () => {
      renderValue(document.getElementById('note-input').value);
    });
    document.getElementById('note-input').addEventListener('input', (e) => {
      if (new URLSearchParams(location.search).get('live') === '1') {
        renderValue(e.target.value);
      }
    });
    const q = new URLSearchParams(location.search).get('q');
    if (q) renderValue(q);
  </script>
</body>
</html>`
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' }).end(html)
  })
  appServer.listen(0, '127.0.0.1')
  await once(appServer, 'listening')
  t.after(() => {
    appServer.closeAllConnections()
    return new Promise<void>(resolve => appServer.close(() => resolve()))
  })
  const appAddr = appServer.address()
  if (!appAddr || typeof appAddr === 'string') throw new Error('no app address')
  const appOrigin = `http://127.0.0.1:${appAddr.port}`

  await withEnv({ GUARDIAN_ALLOW_LOCAL_LAB: '1' }, async () => {
    const broker = new RequestBroker({ rejectUnauthorized: false })
    const browser = new ScopedBrowser(broker)
    const backend = new LinuxWorkerBackend()
    const sig = AbortSignal.timeout(60_000)

    const canary = 'guardianInteractiveCanary7331'
    let auditedAllowed = 0
    let auditedDenied = 0
    const grant = makeLabGrant(appOrigin, {
      tier: 2,
      audit: (outcome) => {
        if (outcome === 'allowed') auditedAllowed += 1
        if (outcome === 'denied') auditedDenied += 1
      },
    })

    // Direct ScopedBrowser.visitPage: fill -> click -> wait_for_selector -> dom_xss_sink_hook
    const visit = await browser.visitPage({
      origin: appOrigin,
      pathAndQuery: '/vuln',
      canaryToken: canary,
      enableSinkHook: true,
      actions: [
        { type: 'dom_xss_sink_hook' },
        { type: 'fill', selector: '#note-input', value: canary },
        { type: 'click', selector: '#render-btn' },
        { type: 'wait_for_selector', selector: '#rendered-badge', timeoutMs: 3_000 },
      ],
      timeoutMs: 20_000,
    }, grant, sig)

    assert.equal(thirdPartyHits, 0, 'out-of-scope third-party server must NEVER receive a direct request')
    assert.ok(visit.blockedOrigins.includes(thirdPartyOrigin), 'blocked third-party origin must be recorded')
    assert.ok(auditedDenied >= 1, 'blocked third-party attempt must be audited as denied')
    assert.ok(auditedAllowed >= 1 && visit.exchanges.length >= 1, 'in-scope page must be fetched via RequestBroker')
    assert.equal(visit.exchanges.length, appHits, '100% of app hits must come through RequestBroker')
    assert.deepEqual(
      visit.actionResults?.map(r => ({ type: r.type, ok: r.ok })),
      [
        { type: 'dom_xss_sink_hook', ok: true },
        { type: 'fill', ok: true },
        { type: 'click', ok: true },
        { type: 'wait_for_selector', ok: true },
      ],
    )
    assert.ok(
      visit.domSinkTraces.some(tr => tr.sink === 'innerHTML' && tr.containsCanary && tr.preview.includes(canary)),
      `dom_xss_sink_hook must capture innerHTML canary trace: ${JSON.stringify(visit.domSinkTraces)}`,
    )

    // Safe page uses textContent: zero innerHTML canary traces
    const safeVisit = await browser.visitPage({
      origin: appOrigin,
      pathAndQuery: '/safe',
      canaryToken: canary,
      enableSinkHook: true,
      actions: [
        { type: 'fill', selector: '#note-input', value: canary },
        { type: 'click', selector: '#render-btn' },
        { type: 'wait_for_selector', selector: '#rendered-badge', timeoutMs: 3_000 },
      ],
      timeoutMs: 20_000,
    }, grant, sig)
    assert.equal(safeVisit.domSinkTraces.some(tr => tr.containsCanary), false, 'textContent must not trigger innerHTML sink hook')
    assert.equal(thirdPartyHits, 0)

    // verifyReplaySpec (browser_chain) deterministic confirmation via fill + dom_xss_sink_hook
    const chainConfirmed = await verifyReplaySpec({
      spec: {
        version: 1,
        kind: 'browser_chain',
        origin: appOrigin,
        title: 'DOM XSS via innerHTML sink on /vuln',
        category: 'xss-client-side',
        cwe: 'CWE-79',
        severity: 'high',
        severityRationale: 'User-controlled input flows into Element.prototype.innerHTML.',
        impact: 'Arbitrary JavaScript execution in the victim browser origin.',
        remediation: 'Use textContent instead of innerHTML for untrusted text.',
        recheckInstructions: 'Verify canary input does not reach innerHTML sink.',
        steps: [
          {
            id: 'control',
            role: 'control',
            description: 'Safe textContent rendering does not hit innerHTML sink',
            origin: appOrigin,
            pathAndQuery: '/safe?live=1',
            action: 'fill',
            selector: '#note-input',
            value: '{{canary_token}}',
            enableSinkHook: true,
          },
          {
            id: 'probe',
            role: 'probe',
            description: 'Vulnerable innerHTML rendering captures verifier canary in sink hook',
            origin: appOrigin,
            pathAndQuery: '/vuln?q={{canary_token}}',
            action: 'dom_xss_sink_hook',
            enableSinkHook: true,
          },
        ],
        assertionsJq: '{ controlPassed: ((.steps.control.status == 200) and (([.steps.control.domSinkTraces[] | select(.containsCanary)] | length) == 0)), confirmed: (([.steps.probe.domSinkTraces[] | select(.sink == "innerHTML" and .containsCanary)] | length) >= 1), observed: ("probe_sink_hits=" + (([.steps.probe.domSinkTraces[] | select(.containsCanary)] | length) | tostring)), expected: "0 canary innerHTML sink hits" }',
      },
      broker,
      browser,
      backend,
      grant,
      signal: sig,
    })
    assert.equal(chainConfirmed.verdict, 'confirmed', `expected browser_chain confirmed, got ${chainConfirmed.verdict}: ${chainConfirmed.outcome.observed}`)
    assert.equal(chainConfirmed.verificationTier, 'runtime_confirmed')
    assert.equal(thirdPartyHits, 0, 'browser_chain must maintain 100% broker proxying and abort third-party origins')
  })
})

// ============================================================================
// 4. ReplayVerifier requireControlNonError guardrail
// ============================================================================

test('v3 ReplayVerifier requireControlNonError: unexpected 404/503 yields inconclusive; explicit expectedStatus allows check', async t => {
  const server = createServer((req, res) => {
    if (req.url === '/err503') {
      res.writeHead(503, { 'Content-Type': 'text/plain' }).end('Service Unavailable')
      return
    }
    res.writeHead(404, { 'Content-Type': 'text/plain' }).end('Not Found')
  })
  server.listen(0, '127.0.0.1')
  await once(server, 'listening')
  t.after(() => {
    server.closeAllConnections()
    return new Promise<void>(resolve => server.close(() => resolve()))
  })
  const addr = server.address()
  if (!addr || typeof addr === 'string') throw new Error('no address')
  const origin = `http://127.0.0.1:${addr.port}`

  await withEnv({ GUARDIAN_ALLOW_LOCAL_LAB: '1' }, async () => {
    const broker = new RequestBroker({ rejectUnauthorized: false })
    const backend = new LinuxWorkerBackend()
    const grant = makeLabGrant(origin, { tier: 1 })
    const sig = AbortSignal.timeout(45_000)

    const basePostureSpec = (pathAndQuery: string, extra: Record<string, unknown> = {}) => ({
      version: 1 as const,
      kind: 'http_chain' as const,
      origin,
      title: 'Security header posture check',
      category: 'misconfig-exposure',
      cwe: 'CWE-693',
      severity: 'low' as const,
      severityRationale: 'Missing Content-Security-Policy header.',
      impact: 'Reduced defense-in-depth against script injection.',
      remediation: 'Add a strict Content-Security-Policy response header.',
      recheckInstructions: 'Verify header on live 200 response.',
      steps: [
        { id: 'control', role: 'control' as const, description: 'Baseline GET', request: { origin, method: 'GET' as const, pathAndQuery } },
        { id: 'probe', role: 'probe' as const, description: 'Probe GET', request: { origin, method: 'GET' as const, pathAndQuery } },
      ],
      assertionsJq: '{ controlPassed: true, confirmed: ((.steps.probe.headers["content-security-policy"] // "") == ""), observed: ("status=" + (.steps.probe.status | tostring)), expected: "csp header present" }',
      ...extra,
    })

    // Unexpected 404 -> inconclusive
    const res404 = await verifyReplaySpec({
      spec: basePostureSpec('/gone'),
      broker,
      backend,
      grant,
      signal: sig,
    })
    assert.equal(res404.verdict, 'inconclusive', `expected inconclusive on unexpected 404, got ${res404.verdict}`)
    assert.match(res404.outcome.reason ?? '', /Unexpected HTTP 404/)

    // Unexpected 503 -> inconclusive
    const res503 = await verifyReplaySpec({
      spec: basePostureSpec('/err503'),
      broker,
      backend,
      grant,
      signal: sig,
    })
    assert.equal(res503.verdict, 'inconclusive', `expected inconclusive on unexpected 503, got ${res503.verdict}`)
    assert.match(res503.outcome.reason ?? '', /Unexpected HTTP 503/)

    // Explicit expectedStatus: 404 opts in to checking 404 response behavior
    const explicit404 = await verifyReplaySpec({
      spec: basePostureSpec('/gone', { expectedStatus: 404 }),
      broker,
      backend,
      grant,
      signal: sig,
    })
    assert.equal(explicit404.verdict, 'confirmed', `explicit expectedStatus 404 should evaluate normally, got ${explicit404.verdict}`)
  })
})
