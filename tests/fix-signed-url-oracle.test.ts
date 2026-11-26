import assert from 'node:assert/strict'
import { createHash, randomBytes, randomUUID } from 'node:crypto'
import { once } from 'node:events'
import { mkdtempSync, readFileSync, rmSync } from 'node:fs'
import { createServer, request as httpRequest } from 'node:http'
import type { AddressInfo } from 'node:net'
import { tmpdir } from 'node:os'
import { dirname, join, resolve } from 'node:path'
import test from 'node:test'
import { fileURLToPath } from 'node:url'

import { RequestBroker, type BrokerHttpRequest, type Grant } from '../src/server/broker.ts'
import { Execution } from '../src/server/execution.ts'
import { HostFactLog } from '../src/server/host-fact-log.ts'
import { buildAgentScriptReceipt, buildProofReceipt, verifyReceipt } from '../src/server/proof-receipt.ts'
import type { ScopedBrowser } from '../src/server/scoped-browser.ts'
import { Store } from '../src/server/store.ts'
import { defaultTerminalOracleRegistry } from '../src/server/terminal-oracle-registry.ts'
import {
  VERIFY_NONCE_HEADER,
  VERIFY_RPC_HEADER,
  VerifyRpcServer,
  createLocalAttemptFactory,
  evaluateClaims,
  verifyScript,
} from '../src/server/verify-rpc.ts'
import {
  assessSignedUrlMintDifferential,
  parseVerifyAuthMutation,
  unregisterScopedBrowserForRun,
} from '../src/server/verify-support.ts'
import type { VerifyClaim } from '../src/server/verify-claims.ts'

process.env.KOVO_ALLOW_LOCAL_LAB = '1'

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..')

interface RpcResp {
  ok: boolean
  result?: unknown
  error?: string
}

function rpcCall(server: VerifyRpcServer, op: string, args: Record<string, unknown> = {}): Promise<RpcResp> {
  return new Promise((resolvePromise, reject) => {
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
    }, res => {
      let data = ''
      res.setEncoding('utf8')
      res.on('data', chunk => { data += chunk })
      res.on('end', () => {
        try { resolvePromise(JSON.parse(data) as RpcResp) } catch (err) { reject(err) }
      })
    })
    req.on('error', reject)
    req.end(body)
  })
}

function makeGrant(origin: string, tier: 0 | 1 | 2 | 3 = 3): Grant {
  return {
    canRead: o => { try { return new URL(o).origin === origin } catch { return o === origin } },
    audit: () => undefined,
    allowLocalLab: true,
    maxRpsPerOrigin: 100,
    tier,
    isStateChangeApproved: () => true,
    personas: new Map(),
    secrets: [],
  }
}

function hexSig(seed: string): string {
  return createHash('sha256').update(seed, 'utf8').digest('hex')
}

async function startMockUploader(
  handler: (reqBody: string, reqPath: string, reqHeaders: Record<string, string>) => { status: number; body: Record<string, unknown> },
): Promise<{ origin: string; close: () => Promise<void> }> {
  const srv = createServer((req, res) => {
    const chunks: Buffer[] = []
    req.on('data', c => chunks.push(c as Buffer))
    req.on('end', () => {
      const bodyStr = Buffer.concat(chunks).toString('utf8')
      const hdrs: Record<string, string> = {}
      for (const [k, v] of Object.entries(req.headers)) {
        if (typeof v === 'string') hdrs[k.toLowerCase()] = v
      }
      const out = handler(bodyStr, req.url ?? '/', hdrs)
      res.writeHead(out.status, { 'content-type': 'application/json' })
      res.end(JSON.stringify(out.body))
    })
  })
  srv.listen(0, '127.0.0.1')
  await once(srv, 'listening')
  const port = (srv.address() as AddressInfo).port
  return {
    origin: `http://127.0.0.1:${port}`,
    close: () => new Promise<void>(r => { srv.closeAllConnections(); srv.close(() => r()) }),
  }
}

test('P0 #2 Positive TP: GCS v4 signed-URL key traversal confirms runtime_confirmed without contacting GCS', async t => {
  const srv = await startMockUploader(bodyStr => {
    const parsed = JSON.parse(bodyStr || '{}') as { extension?: string }
    const ext = String(parsed.extension ?? 'png')
    if (ext.includes('..')) {
      return {
        status: 200,
        body: {
          uploadUrl: `https://storage.googleapis.com/dyad-logs/kovo-canary.json?X-Goog-Algorithm=GOOG4-RSA-SHA256&X-Goog-Credential=sa%40proj.iam.gserviceaccount.com&X-Goog-Date=20261126T000000Z&X-Goog-Expires=900&X-Goog-SignedHeaders=content-type%3Bhost&X-Goog-Signature=${hexSig('probe-gcs-key-traversal')}`,
          method: 'PUT',
        },
      }
    }
    return {
      status: 200,
      body: {
        uploadUrl: `https://storage.googleapis.com/dyad-logs/uploads/abc123.png?X-Goog-Algorithm=GOOG4-RSA-SHA256&X-Goog-Credential=sa%40proj.iam.gserviceaccount.com&X-Goog-Date=20261126T000000Z&X-Goog-Expires=900&X-Goog-SignedHeaders=content-type%3Bhost&X-Goog-Signature=${hexSig('control-gcs-benign')}`,
        method: 'PUT',
      },
    }
  })
  t.after(() => srv.close())

  const broker = new RequestBroker({ transportConfig: { http2: false } })
  const rpc = new VerifyRpcServer({
    broker,
    grant: makeGrant(srv.origin, 3),
    runId: 'run-signed-url-gcs-tp',
    assignmentId: 'asg-gcs-tp',
    targetOrigins: [srv.origin],
  })
  await rpc.start()
  t.after(() => rpc.close())

  const resp = await rpcCall(rpc, 'prove.signedUrlMint', {
    route: '/generate-upload-url',
    method: 'POST',
    controlBody: { extension: 'png' },
    probeBody: { extension: 'png/../../kovo-canary.json' },
  })
  assert.equal(resp.ok, true, `RPC failed: ${resp.error ?? ''}`)
  const proof = resp.result as {
    ok: boolean
    confirmed: boolean
    variant: string
    provider: string
    claim: VerifyClaim
    evidence: Record<string, unknown>
    rejectedBy: string | null
  }
  assert.equal(proof.ok, true)
  assert.equal(proof.confirmed, true)
  assert.equal(proof.variant, 'key_traversal')
  assert.equal(proof.provider, 'gcs')
  assert.equal(proof.rejectedBy, null)
  assert.equal(proof.evidence.controlPathname, '/dyad-logs/uploads/abc123.png')
  assert.equal(proof.evidence.probePathname, '/dyad-logs/kovo-canary.json')

  // Verify claims pass through unmodified verify-claims.ts oracle
  const factLog = rpc.buildHostFactLog()
  const oracleRes = evaluateClaims(rpc.transcript, [proof.claim], { factLog })
  assert.equal(oracleRes.passed, true, `evaluateClaims failed: ${oracleRes.failures.join('; ')}`)

  // Verify single-hop ProofReceipt + TerminalOracleRegistry independently re-verify on host transcript
  const built = buildAgentScriptReceipt({
    claims: [proof.claim as unknown as Record<string, unknown>],
    exchanges: [],
    factLog,
    origin: srv.origin,
    title: 'Unauthenticated GCS signed-URL key traversal',
  })
  assert.ok(built, 'buildAgentScriptReceipt must build a ProofReceipt for signed_url_mint')
  assert.equal(built.receipt.vulnClass, 'signed_url_mint')
  const regRes = defaultTerminalOracleRegistry.evaluate(
    built.factLog,
    { kind: 'single_hop', receipt: built.receipt, armOverrides: built.armOverrides },
    { strictHostDerivation: true },
  )
  assert.equal(regRes.confirmed, true, `TerminalOracleRegistry rejected: ${regRes.reason}`)
  assert.equal(regRes.singleHop?.confirmed, true)
})

test('P0 #2 Positive TP: AWS S3 X-Amz-Signature traversal confirms runtime_confirmed', async t => {
  const srv = await startMockUploader(bodyStr => {
    const parsed = JSON.parse(bodyStr || '{}') as { key?: string }
    const key = String(parsed.key ?? 'avatar.png')
    if (key.includes('..')) {
      return {
        status: 200,
        body: {
          signedUrl: `https://tenant-assets.s3.us-east-1.amazonaws.com/uploads/u1/../admin-config.json?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIAEXAMPLE/20261126/us-east-1/s3/aws4_request&X-Amz-Date=20261126T000000Z&X-Amz-Expires=300&X-Amz-SignedHeaders=content-type%3Bhost&X-Amz-Signature=${hexSig('probe-s3-traversal')}`,
        },
      }
    }
    return {
      status: 200,
      body: {
        signedUrl: `https://tenant-assets.s3.us-east-1.amazonaws.com/uploads/u1/avatar.png?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIAEXAMPLE/20261126/us-east-1/s3/aws4_request&X-Amz-Date=20261126T000000Z&X-Amz-Expires=300&X-Amz-SignedHeaders=content-type%3Bhost&X-Amz-Signature=${hexSig('control-s3-benign')}`,
      },
    }
  })
  t.after(() => srv.close())

  const rpc = new VerifyRpcServer({
    broker: new RequestBroker({ transportConfig: { http2: false } }),
    grant: makeGrant(srv.origin, 3),
    runId: 'run-signed-url-s3-tp',
    assignmentId: 'asg-s3-tp',
    targetOrigins: [srv.origin],
  })
  await rpc.start()
  t.after(() => rpc.close())

  const resp = await rpcCall(rpc, 'prove.signedUrlMint', {
    control: { path: '/api/presign', method: 'POST', body: { key: 'avatar.png' } },
    probe: { path: '/api/presign', method: 'POST', body: { key: '../admin-config.json' } },
  })
  assert.equal(resp.ok, true)
  const proof = resp.result as { ok: boolean; confirmed: boolean; variant: string; provider: string; claim: VerifyClaim }
  assert.equal(proof.ok, true)
  assert.equal(proof.confirmed, true)
  assert.equal(proof.variant, 'key_traversal')
  assert.equal(proof.provider, 'aws_s3')

  const factLog = rpc.buildHostFactLog()
  const built = buildAgentScriptReceipt({
    claims: [proof.claim as unknown as Record<string, unknown>],
    exchanges: [],
    factLog,
    origin: srv.origin,
    title: 'S3 presigned URL key traversal',
  })
  assert.ok(built)
  const regRes = defaultTerminalOracleRegistry.evaluate(
    built.factLog,
    { kind: 'single_hop', receipt: built.receipt, armOverrides: built.armOverrides },
    { strictHostDerivation: true },
  )
  assert.equal(regRes.confirmed, true, regRes.reason)
})

test('P0 #2 Positive TP (Variant B) & Negative FP controls: Azure SAS write minting vs read-only & negative controls', () => {
  const origin = 'https://upload-app.example.test'
  const sasSig = Buffer.from(randomBytes(32)).toString('base64url')

  // Variant B positive TP: 400 negative control vs unauthenticated 200 Azure SAS write URL
  const sasWrite = assessSignedUrlMintDifferential({
    control: {
      origin,
      method: 'POST',
      pathAndQuery: '/api/upload-token',
      status: 400,
      requestBody: JSON.stringify({}),
      responseBody: JSON.stringify({ error: 'filename required' }),
    },
    probe: {
      origin,
      method: 'POST',
      pathAndQuery: '/api/upload-token',
      status: 200,
      requestBody: JSON.stringify({ filename: 'report.json' }),
      responseBody: JSON.stringify({
        uploadUrl: `https://myacct.blob.core.windows.net/uploads/report.json?sv=2022-11-02&se=2026-11-27T00:00:00Z&sp=cw&sig=${sasSig}`,
      }),
    },
  })
  assert.equal(sasWrite.confirmed, true, sasWrite.reason)
  assert.equal(sasWrite.variant, 'unauth_write_mint')
  assert.equal(sasWrite.provider, 'azure_blob')

  // Negative FP 1: Azure SAS read-only (`sp=r`) must be REJECTED
  const sasReadOnly = assessSignedUrlMintDifferential({
    control: {
      origin,
      method: 'POST',
      pathAndQuery: '/api/upload-token',
      status: 400,
      requestBody: '{}',
      responseBody: '{"error":"missing"}',
    },
    probe: {
      origin,
      method: 'POST',
      pathAndQuery: '/api/upload-token',
      status: 200,
      requestBody: '{"filename":"report.json"}',
      responseBody: JSON.stringify({
        url: `https://myacct.blob.core.windows.net/uploads/report.json?sv=2022-11-02&se=2026-11-27T00:00:00Z&sp=r&sig=${sasSig}`,
      }),
    },
  })
  assert.equal(sasReadOnly.confirmed, false)

  // Negative FP 2: Unsigned URL -> REJECTED
  const unsigned = assessSignedUrlMintDifferential({
    control: {
      origin,
      method: 'POST',
      pathAndQuery: '/generate-upload-url',
      status: 200,
      requestBody: '{"extension":"png"}',
      responseBody: JSON.stringify({ uploadUrl: 'https://storage.googleapis.com/bucket/uploads/abc.png' }),
    },
    probe: {
      origin,
      method: 'POST',
      pathAndQuery: '/generate-upload-url',
      status: 200,
      requestBody: '{"extension":"../canary.json"}',
      responseBody: JSON.stringify({ uploadUrl: 'https://storage.googleapis.com/bucket/canary.json' }),
    },
  })
  assert.equal(unsigned.confirmed, false)
  assert.equal(unsigned.rejectedBy, 'signed_url_missing_or_invalid')

  // Negative FP 3: Echoed signature from request -> REJECTED
  const echoedSig = hexSig('attacker-echoed-sig')
  const echoed = assessSignedUrlMintDifferential({
    control: {
      origin,
      method: 'POST',
      pathAndQuery: '/generate-upload-url',
      status: 200,
      requestBody: '{"extension":"png"}',
      responseBody: JSON.stringify({
        uploadUrl: `https://storage.googleapis.com/bucket/uploads/abc.png?X-Goog-Algorithm=GOOG4-RSA-SHA256&X-Goog-Signature=${hexSig('ctl-sig')}`,
      }),
    },
    probe: {
      origin,
      method: 'POST',
      pathAndQuery: '/generate-upload-url',
      status: 200,
      requestBody: JSON.stringify({ extension: `../canary.json?X-Goog-Signature=${echoedSig}` }),
      responseBody: JSON.stringify({
        uploadUrl: `https://storage.googleapis.com/bucket/canary.json?X-Goog-Algorithm=GOOG4-RSA-SHA256&X-Goog-Signature=${echoedSig}`,
      }),
    },
  })
  assert.equal(echoed.confirmed, false)
  assert.equal(echoed.rejectedBy, 'signed_url_echoed')

  // Negative FP 4: Identical control/probe signature -> REJECTED
  const sameSig = hexSig('same-static-signature')
  const identicalSig = assessSignedUrlMintDifferential({
    control: {
      origin,
      method: 'POST',
      pathAndQuery: '/generate-upload-url',
      status: 200,
      requestBody: '{"extension":"png"}',
      responseBody: JSON.stringify({
        uploadUrl: `https://storage.googleapis.com/bucket/uploads/abc.png?X-Goog-Algorithm=GOOG4-RSA-SHA256&X-Goog-Signature=${sameSig}`,
      }),
    },
    probe: {
      origin,
      method: 'POST',
      pathAndQuery: '/generate-upload-url',
      status: 200,
      requestBody: '{"extension":"../canary.json"}',
      responseBody: JSON.stringify({
        uploadUrl: `https://storage.googleapis.com/bucket/canary.json?X-Goog-Algorithm=GOOG4-RSA-SHA256&X-Goog-Signature=${sameSig}`,
      }),
    },
  })
  assert.equal(identicalSig.confirmed, false)
  assert.equal(identicalSig.rejectedBy, 'signed_url_identical_signature')

  // Negative FP 5: Same-prefix benign filename (no directory/bucket escape) -> REJECTED
  const samePrefix = assessSignedUrlMintDifferential({
    control: {
      origin,
      method: 'POST',
      pathAndQuery: '/generate-upload-url',
      status: 200,
      requestBody: '{"extension":"png"}',
      responseBody: JSON.stringify({
        uploadUrl: `https://storage.googleapis.com/bucket/uploads/11111111-1111-4111-8111-111111111111.png?X-Goog-Algorithm=GOOG4-RSA-SHA256&X-Goog-Signature=${hexSig('same-prefix-1')}`,
      }),
    },
    probe: {
      origin,
      method: 'POST',
      pathAndQuery: '/generate-upload-url',
      status: 200,
      requestBody: '{"extension":"jpg"}',
      responseBody: JSON.stringify({
        uploadUrl: `https://storage.googleapis.com/bucket/uploads/22222222-2222-4222-8222-222222222222.jpg?X-Goog-Algorithm=GOOG4-RSA-SHA256&X-Goog-Signature=${hexSig('same-prefix-2')}`,
      }),
    },
  })
  assert.equal(samePrefix.confirmed, false)
  assert.equal(samePrefix.rejectedBy, 'signed_url_no_prefix_escape')

  // Negative FP 6: Non-storage host -> REJECTED
  const nonStorage = assessSignedUrlMintDifferential({
    control: {
      origin,
      method: 'POST',
      pathAndQuery: '/generate-upload-url',
      status: 200,
      requestBody: '{"extension":"png"}',
      responseBody: JSON.stringify({
        uploadUrl: `https://cdn.example.com/bucket/uploads/abc.png?X-Goog-Algorithm=GOOG4-RSA-SHA256&X-Goog-Signature=${hexSig('non-storage-1')}`,
      }),
    },
    probe: {
      origin,
      method: 'POST',
      pathAndQuery: '/generate-upload-url',
      status: 200,
      requestBody: '{"extension":"../canary.json"}',
      responseBody: JSON.stringify({
        uploadUrl: `https://cdn.example.com/bucket/canary.json?X-Goog-Algorithm=GOOG4-RSA-SHA256&X-Goog-Signature=${hexSig('non-storage-2')}`,
      }),
    },
  })
  assert.equal(nonStorage.confirmed, false)
  assert.equal(nonStorage.rejectedBy, 'signed_url_missing_or_invalid')

  // Direct verifyReceipt check on a forged/weak transcript fails closed
  const fakeReceipt = buildProofReceipt({
    vulnClass: 'signed_url_mint',
    target: { origin, method: 'POST', pathAndQuery: '/generate-upload-url' },
    exchangeIds: ['ex-ctl', 'ex-prb'],
    claimedDelta: 'same-prefix upload',
  })
  const receiptVerdict = verifyReceipt(fakeReceipt, {
    entries: [
      {
        exchangeId: 'ex-ctl',
        origin,
        step: {
          id: 'ex-ctl',
          arm: 'control',
          method: 'POST',
          route: '/generate-upload-url',
          pathAndQuery: '/generate-upload-url',
          status: 200,
          actor: { handle: null, role: null, tenant: null, auth: 'unknown', sameSite: 'unknown' },
          requestJson: { extension: 'png' },
          body: JSON.stringify({ uploadUrl: `https://storage.googleapis.com/bucket/uploads/a.png?X-Goog-Algorithm=GOOG4-RSA-SHA256&X-Goog-Signature=${hexSig('rc-1')}` }),
        },
      },
      {
        exchangeId: 'ex-prb',
        origin,
        step: {
          id: 'ex-prb',
          arm: 'probe',
          method: 'POST',
          route: '/generate-upload-url',
          pathAndQuery: '/generate-upload-url',
          status: 200,
          actor: { handle: null, role: null, tenant: null, auth: 'unknown', sameSite: 'unknown' },
          requestJson: { extension: 'jpg' },
          body: JSON.stringify({ uploadUrl: `https://storage.googleapis.com/bucket/uploads/b.jpg?X-Goog-Algorithm=GOOG4-RSA-SHA256&X-Goog-Signature=${hexSig('rc-2')}` }),
        },
      },
    ],
  })
  assert.equal(receiptVerdict.confirmed, false)
})

test('VerifyRpcServer passes through synthetic_invalid_bearer & synthetic_invalid_api_key without personaHandle', async t => {
  assert.deepEqual(parseVerifyAuthMutation({ kind: 'synthetic_invalid_bearer' }, undefined), { kind: 'synthetic_invalid_bearer' })
  assert.deepEqual(
    parseVerifyAuthMutation({ kind: 'synthetic_invalid_api_key', headerName: 'X-Custom-Key' }, undefined),
    { kind: 'synthetic_invalid_api_key', headerName: 'X-Custom-Key' },
  )
  assert.throws(() => parseVerifyAuthMutation({ kind: 'alg_none' }, undefined), /approved persona handle/i)

  const seenRequests: BrokerHttpRequest[] = []
  const origin = 'http://127.0.0.1:49999'
  const mockBroker = {
    executeHttp: async (req: BrokerHttpRequest) => {
      seenRequests.push(req)
      return {
        origin: req.origin,
        finalOrigin: req.origin,
        redirectOrigins: [],
        method: req.method,
        pathAndQuery: req.pathAndQuery,
        personaHandle: null,
        status: 200,
        mediaType: 'application/json',
        reqHeaders: {},
        respHeaders: { 'content-type': 'application/json' },
        setCookies: [],
        bodyPreview: '{"ok":true}',
        body: '{"ok":true}',
        bodySha256: hexSig('{"ok":true}'),
        bodyBytes: 11,
        bodyTruncated: false,
        durationMs: 1,
        secretMatches: [],
        wireCredentialProvenance: {
          authenticated: true,
          source: 'caller_self_minted' as const,
          sources: ['caller_self_minted' as const],
          personaHandle: null,
          headerNames: ['authorization'],
          vaultHeaderNames: [],
          callerAuthHeaderNames: ['authorization'],
          cookieNames: [],
          vaultCookieNames: [],
          jarCookieNames: [],
          session: null,
          authMutated: true,
        },
        observation: {
          origin: req.origin,
          finalOrigin: req.origin,
          status: 200,
          mediaType: 'application/json',
          transportMaxAge: null,
          includeSubDomains: false,
          source: 'public response' as const,
          headers: {},
          cookies: [],
          bodyPreview: '{"ok":true}',
        },
      }
    },
  } as unknown as RequestBroker

  const rpc = new VerifyRpcServer({
    broker: mockBroker,
    grant: makeGrant(origin, 3),
    runId: 'run-synth-auth-rpc',
    assignmentId: 'asg-synth-auth-rpc',
    targetOrigins: [origin],
  })
  await rpc.start()
  t.after(() => rpc.close())

  const r1 = await rpcCall(rpc, 'http.send', {
    path: '/v1/tools/web-crawl',
    method: 'POST',
    body: '{"url":"https://example.com"}',
    authMutation: { kind: 'synthetic_invalid_bearer' },
  })
  assert.equal(r1.ok, true, `synthetic_invalid_bearer failed: ${r1.error ?? ''}`)

  const r2 = await rpcCall(rpc, 'http.send', {
    path: '/v1/tools/web-crawl',
    method: 'POST',
    body: '{"url":"https://example.com"}',
    authMutation: { kind: 'synthetic_invalid_api_key' },
  })
  assert.equal(r2.ok, true, `synthetic_invalid_api_key failed: ${r2.error ?? ''}`)

  assert.equal(seenRequests.length, 2)
  assert.deepEqual(seenRequests[0]?.authMutation, { kind: 'synthetic_invalid_bearer' })
  assert.equal(seenRequests[0]?.persona, undefined)
  assert.deepEqual(seenRequests[1]?.authMutation, { kind: 'synthetic_invalid_api_key' })
  assert.equal(seenRequests[1]?.persona, undefined)

  // Persona-based authMutation without persona still fails closed
  const r3 = await rpcCall(rpc, 'http.send', {
    path: '/v1/tools/web-crawl',
    method: 'GET',
    authMutation: { kind: 'alg_none' },
  })
  assert.equal(r3.ok, false)
  assert.match(r3.error ?? '', /approved persona handle/i)
})

test('P1 #6: Execution wires ScopedBrowser into VerifyRpcServer for Tier >= 1 runs and blocks Tier 0', async t => {
  const tmpRoot = mkdtempSync(join(tmpdir(), 'kovo-exec-browser-wire-'))
  t.after(() => rmSync(tmpRoot, { recursive: true, force: true }))

  const visited: Array<{ origin: string; pathAndQuery: string; runId?: string; assignmentId?: string }> = []
  const fakeScopedBrowser = {
    visitPage: async (req: { origin: string; pathAndQuery: string; runId?: string; assignmentId?: string }) => {
      visited.push(req)
      return {
        origin: req.origin,
        finalUrl: `${req.origin}${req.pathAndQuery}`,
        title: 'Sandpack Preview',
        status: 200,
        domSnippet: '<html><body><div id="root">rendered</div></body></html>',
        links: [],
        forms: [],
        xhrRequests: [],
        blockedOrigins: [],
        consoleMessages: [],
        postMessageListeners: { count: 1, hasOnMessage: true, handlers: [], observedEvents: 1, canaryHandledWithoutOriginCheck: true },
        cookieNames: [],
        localStorageKeys: [],
        sessionStorageKeys: [],
        canaryCheck: { token: 'kovo-dom-sentinel-1', triggered: true, detail: 'attested', attested: true },
        attestedSinks: ['postMessage:wildcard'],
        domSinkTraces: [],
        exchangeIds: [],
        exchanges: [],
        durationMs: 12,
      }
    },
    close: async () => undefined,
  } as unknown as ScopedBrowser

  const storage = new Store(tmpRoot)
  t.after(() => storage.close())
  const exec = new Execution(storage, { browser: fakeScopedBrowser })
  t.after(() => exec.stop())

  const targetOrigin = 'http://127.0.0.1:48123'
  const project = storage.createProject({
    requestId: randomUUID(),
    name: 'Sandpack Tier Test',
    seeds: [targetOrigin],
    environment: 'local-lab',
  })
  const createdTier3 = storage.createRun({
    requestId: randomUUID(),
    projectId: project.id,
    goal: 'Browser verification test',
    sourceMode: 'public',
    capabilityTier: 3,
    budgetUsd: 5,
    budgetRequests: 200,
    maxRpsPerOrigin: 10,
    workerConcurrency: 1,
    workerMaxTurns: 10,
  })
  const createdTier0 = storage.createRun({
    requestId: randomUUID(),
    projectId: project.id,
    goal: 'Offline Tier 0 test',
    sourceMode: 'prepared',
    capabilityTier: 0,
    budgetUsd: 5,
    budgetRequests: 200,
    maxRpsPerOrigin: 10,
    workerConcurrency: 1,
    workerMaxTurns: 10,
  })
  const runTier3 = storage.run(createdTier3.id)
  const runTier0 = storage.run(createdTier0.id)
  t.after(() => {
    unregisterScopedBrowserForRun(runTier3.id)
    unregisterScopedBrowserForRun(runTier0.id)
  })

  const asg3 = storage.makeWorker(runTier3, 'investigation', undefined, 'Browser test worker', 'Verify DOM sink')
  const asg0 = storage.makeWorker(runTier0, 'investigation', undefined, 'Tier 0 worker', 'Offline')
  const approved = new Set([targetOrigin])

  const buildGrant = (exec as unknown as {
    buildGrant: (job: { assignment: typeof asg3; origins: Set<string>; controller: AbortController }, run: typeof runTier3, allowed: ReadonlySet<string>) => { grant: Grant }
  }).buildGrant.bind(exec)

  const { grant: tier3Grant } = buildGrant(
    { assignment: asg3, origins: new Set([targetOrigin]), controller: new AbortController() },
    runTier3,
    approved,
  )
  // Override canRead / scopePolicy so unit test does not require active scheduler registration
  const liveTier3Grant: Grant = Object.assign(tier3Grant, {
    canRead: (o: string) => { try { return new URL(o).origin === targetOrigin } catch { return o === targetOrigin } },
    scopePolicy: undefined,
  })
  const rpcTier3 = new VerifyRpcServer({
    broker: exec.broker,
    grant: liveTier3Grant,
    runId: runTier3.id,
    assignmentId: asg3.id,
    targetOrigins: [targetOrigin],
  })
  assert.ok(rpcTier3.browserDriver, 'Tier >= 1 VerifyRpcServer must have ScopedBrowser wired as browserDriver')
  await rpcTier3.start()
  t.after(() => rpcTier3.close())

  const browseResp = await rpcCall(rpcTier3, 'browser', { path: '/preview?canary=1', waitForSelector: '#root' })
  assert.equal(browseResp.ok, true, `ctx.browser() RPC failed: ${browseResp.error ?? ''}`)
  const bResult = browseResp.result as { exchangeId: string; status: number; url: string; html: string; title?: string; executedSentinels: string[] }
  assert.equal(bResult.status, 200)
  assert.equal(bResult.title, 'Sandpack Preview')
  assert.match(bResult.html, /rendered/)
  assert.ok(bResult.executedSentinels.includes('postMessage:wildcard'))
  assert.ok(bResult.executedSentinels.includes('kovo-dom-sentinel-1'))
  assert.equal(visited.length, 1)
  assert.equal(visited[0]?.origin, targetOrigin)
  assert.equal(visited[0]?.pathAndQuery, '/preview?canary=1')

  // Tier 0 must stay fail-closed (no browserDriver wired)
  const { grant: tier0Grant } = buildGrant(
    { assignment: asg0, origins: new Set([targetOrigin]), controller: new AbortController() },
    runTier0,
    approved,
  )
  const rpcTier0 = new VerifyRpcServer({
    broker: exec.broker,
    grant: tier0Grant,
    runId: runTier0.id,
    assignmentId: asg0.id,
    targetOrigins: [targetOrigin],
  })
  assert.equal(rpcTier0.browserDriver, undefined, 'Tier 0 run must NOT wire browserDriver')
})

test('P0 #2 E2E dual-attempt verifyScript: kovo_verify ctx.prove_signed_url_mint confirms across two fresh sessions', async t => {
  let seq = 0
  const srv = await startMockUploader(bodyStr => {
    seq += 1
    const parsed = JSON.parse(bodyStr || '{}') as { extension?: string }
    const ext = String(parsed.extension ?? 'png')
    if (ext.includes('..')) {
      return {
        status: 200,
        body: {
          uploadUrl: `https://storage.googleapis.com/dyad-logs/kovo-canary.json?X-Goog-Algorithm=GOOG4-RSA-SHA256&X-Goog-SignedHeaders=content-type%3Bhost&X-Goog-Signature=${hexSig(`e2e-probe-${seq}`)}`,
        },
      }
    }
    return {
      status: 200,
      body: {
        uploadUrl: `https://storage.googleapis.com/dyad-logs/uploads/item-${seq}.png?X-Goog-Algorithm=GOOG4-RSA-SHA256&X-Goog-SignedHeaders=content-type%3Bhost&X-Goog-Signature=${hexSig(`e2e-ctl-${seq}`)}`,
      },
    }
  })
  t.after(() => srv.close())

  const broker = new RequestBroker({ transportConfig: { http2: false } })
  const grant = makeGrant(srv.origin, 3)
  const openAttempt = createLocalAttemptFactory({
    sdkDir: join(REPO_ROOT, 'worker/kovo_verify'),
    createRpcOptions: (_nonce, attempt) => ({
      broker,
      grant,
      runId: 'run-e2e-signed-url',
      assignmentId: `asg-e2e-${attempt}`,
      targetOrigins: [srv.origin],
    }),
  })
  const verdict = await verifyScript({
    candidate: {
      name: 'signed-url-traversal.ts',
      runtime: 'ts',
      code: `
        const proof = await ctx.prove_signed_url_mint({
          route: '/generate-upload-url',
          method: 'POST',
          controlBody: { extension: 'png' },
          probeBody: { extension: 'png/../../kovo-canary.json' },
        })
        if (!proof.confirmed) throw new Error('expected signed_url_mint confirmation')
        return ctx.result({ title: 'GCS signed-URL key traversal', severity: 'high' })
      `,
    },
    openAttempt,
  })
  assert.equal(verdict.confirmed, true, `dual-attempt verifyScript failed: ${verdict.detail}`)
  assert.equal(verdict.reason, 'confirmed')
  assert.equal(verdict.disagreements.length, 0)
})

test('Static hygiene: src/server/verify-rpc.ts stays <= 2300 LOC', () => {
  const lines = readFileSync(join(REPO_ROOT, 'src/server/verify-rpc.ts'), 'utf8').split('\n').length
  assert.ok(lines <= 2300, `src/server/verify-rpc.ts exceeded 2300 LOC cap (got ${lines})`)
})
