/**
 * WS-3 class-level guards (`R4-C-1`, `R4-C-2`, `R4-C-6`, `R4-H-4`):
 *  - R4-C-1: Host-minted boolean pair stamping in `prove.differential` & shared canonical skeleton /
 *            equal-length / same-charset invariants in `verify-support.ts`.
 *  - R4-C-2: Host-rendered expression probes stamped with `hostExpressionChallenge` at send time in
 *            `prove.injection`, with `expectedOutput` and operands NEVER returned to the worker
 *            (neither in `prove.injection` nor in `transcript.get`).
 *  - R4-C-6: `signed_url_mint` input binding, same-persona requirement, host/bucket non-evidence,
 *            in-prefix ablation, strict anonymous 401/403 same-body Variant B control (rejecting 400),
 *            fail-closed both-arm echo check (malformed percent-escape & JSON unicode escapes),
 *            and never stamping `replayMode: 'fresh_clean_replay'` without a replay.
 *  - R4-H-4: Worker-visible digest primitive across `applyCapabilityInjection`, `transcript.get`,
 *            `scrubRecord`, and `prove.signedUrlMint` (`exchangeSummaryFromTranscript`): no
 *            worker-facing request or response digest ever equals the SHA-256 of a vault-bearing
 *            plaintext string.
 *
 * Defensive QA framing: pure in-memory + loopback verification stubs only.
 */
import assert from 'node:assert/strict'
import { createHash, randomBytes } from 'node:crypto'
import { once } from 'node:events'
import { createServer, request as httpRequest } from 'node:http'
import type { AddressInfo } from 'node:net'
import test from 'node:test'

import { RequestBroker, type Grant } from '../src/server/broker.ts'
import type { ResolvedPersona } from '../src/server/persona-vault.ts'
import { buildProofReceipt, defaultHostMintedOracle, verifyReceipt } from '../src/server/proof-receipt.ts'
import {
  VERIFY_NONCE_HEADER,
  VERIFY_RPC_HEADER,
  VerifyRpcServer,
  evaluateClaims,
} from '../src/server/verify-rpc.ts'
import {
  assessSignedUrlMintDifferential,
  mintHostBooleanPair,
  stripBooleanPredicateSuffix,
  verifyBooleanArmBaseParity,
} from '../src/server/verify-support.ts'
import type { VerifyClaim } from '../src/server/verify-claims.ts'

process.env.KOVO_ALLOW_LOCAL_LAB = '1'

interface RpcResp {
  ok: boolean
  result?: unknown
  error?: string
}

function sha256(text: string): string {
  return createHash('sha256').update(text, 'utf8').digest('hex')
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

function makeGrant(origin: string): Grant {
  return {
    canRead: o => { try { return new URL(o).origin === origin } catch { return o === origin } },
    audit: () => undefined,
    allowLocalLab: true,
    maxRpsPerOrigin: 200,
    tier: 3,
    isStateChangeApproved: () => true,
    personas: new Map(),
    secrets: [],
  }
}

async function startStubServer(
  handler: (req: { method: string; url: string; headers: Record<string, string>; body: string }) => { status: number; body: string; contentType?: string },
): Promise<{ origin: string; close: () => Promise<void> }> {
  const srv = createServer((req, res) => {
    const chunks: Buffer[] = []
    req.on('data', c => chunks.push(c as Buffer))
    req.on('end', () => {
      const hdrs: Record<string, string> = {}
      for (const [k, v] of Object.entries(req.headers)) {
        if (typeof v === 'string') hdrs[k.toLowerCase()] = v
      }
      const out = handler({
        method: req.method ?? 'GET',
        url: req.url ?? '/',
        headers: hdrs,
        body: Buffer.concat(chunks).toString('utf8'),
      })
      res.writeHead(out.status, { 'content-type': out.contentType ?? 'application/json' })
      res.end(out.body)
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

// ============================================================================
// 1. R4-C-6: signed_url_mint input binding, persona, 401/403 control, both-arm
//    fail-closed echo check, and no fake `fresh_clean_replay`
// ============================================================================

test('R4-C-6: two-folder benign presign, host/bucket-only diff, cross-persona, and escaping ablation reject Variant A', async t => {
  const origin = 'https://storage-app.example.test'
  const sig1 = sha256('ctl-benign-folder-a')
  const sig2 = sha256('prb-benign-folder-b')

  // 1a. Two-folder benign presign by fileId (no traversal/separator in probe) -> REJECT
  const twoFolderById = assessSignedUrlMintDifferential({
    control: {
      origin, method: 'POST', pathAndQuery: '/api/presign', status: 200,
      requestBody: JSON.stringify({ fileId: '101' }),
      responseBody: JSON.stringify({ url: `https://storage.googleapis.com/app-bucket/folder-a/doc101.pdf?X-Goog-Algorithm=GOOG4-RSA-SHA256&X-Goog-Signature=${sig1}` }),
    },
    probe: {
      origin, method: 'POST', pathAndQuery: '/api/presign', status: 200,
      requestBody: JSON.stringify({ fileId: '102' }),
      responseBody: JSON.stringify({ url: `https://storage.googleapis.com/app-bucket/folder-b/doc102.pdf?X-Goog-Algorithm=GOOG4-RSA-SHA256&X-Goog-Signature=${sig2}` }),
    },
  })
  assert.equal(twoFolderById.confirmed, false)
  assert.equal(twoFolderById.rejectedBy, 'signed_url_no_traversal_input')

  // 1b. Two-folder benign presign with sibling paths (both carry a slash, neither has traversal) -> REJECT
  const twoFolderByPath = assessSignedUrlMintDifferential({
    control: {
      origin, method: 'POST', pathAndQuery: '/api/presign', status: 200,
      requestBody: JSON.stringify({ key: 'folder-a/doc101.pdf' }),
      responseBody: JSON.stringify({ url: `https://storage.googleapis.com/app-bucket/folder-a/doc101.pdf?X-Goog-Algorithm=GOOG4-RSA-SHA256&X-Goog-Signature=${sig1}` }),
    },
    probe: {
      origin, method: 'POST', pathAndQuery: '/api/presign', status: 200,
      requestBody: JSON.stringify({ key: 'folder-b/doc102.pdf' }),
      responseBody: JSON.stringify({ url: `https://storage.googleapis.com/app-bucket/folder-b/doc102.pdf?X-Goog-Algorithm=GOOG4-RSA-SHA256&X-Goog-Signature=${sig2}` }),
    },
  })
  assert.equal(twoFolderByPath.confirmed, false)
  assert.equal(twoFolderByPath.rejectedBy, 'signed_url_no_traversal_input')

  // 1c. Bucket/host difference alone is non-evidence -> REJECT
  const bucketDiff = assessSignedUrlMintDifferential({
    control: {
      origin, method: 'POST', pathAndQuery: '/api/presign', status: 200,
      requestBody: JSON.stringify({ key: 'doc.pdf' }),
      responseBody: JSON.stringify({ url: `https://storage.googleapis.com/bucket-a/uploads/doc.pdf?X-Goog-Algorithm=GOOG4-RSA-SHA256&X-Goog-Signature=${sig1}` }),
    },
    probe: {
      origin, method: 'POST', pathAndQuery: '/api/presign', status: 200,
      requestBody: JSON.stringify({ key: '../doc.pdf' }),
      responseBody: JSON.stringify({ url: `https://storage.googleapis.com/bucket-b/uploads/doc.pdf?X-Goog-Algorithm=GOOG4-RSA-SHA256&X-Goog-Signature=${sig2}` }),
    },
  })
  assert.equal(bucketDiff.confirmed, false)
  assert.equal(bucketDiff.rejectedBy, 'signed_url_host_or_bucket_non_evidence')

  // 1d. Cross-persona Variant A -> REJECT
  const crossPersona = assessSignedUrlMintDifferential({
    control: {
      origin, method: 'POST', pathAndQuery: '/api/presign', status: 200,
      actorHandle: 'alice',
      requestBody: JSON.stringify({ key: 'doc.pdf' }),
      responseBody: JSON.stringify({ url: `https://storage.googleapis.com/app-bucket/uploads/doc.pdf?X-Goog-Algorithm=GOOG4-RSA-SHA256&X-Goog-Signature=${sig1}` }),
    },
    probe: {
      origin, method: 'POST', pathAndQuery: '/api/presign', status: 200,
      actorHandle: 'bob',
      requestBody: JSON.stringify({ key: '../secret.pdf' }),
      responseBody: JSON.stringify({ url: `https://storage.googleapis.com/app-bucket/secret.pdf?X-Goog-Algorithm=GOOG4-RSA-SHA256&X-Goog-Signature=${sig2}` }),
    },
  })
  assert.equal(crossPersona.confirmed, false)
  assert.equal(crossPersona.rejectedBy, 'signed_url_persona_mismatch')

  // 1e. Live loopback two-folder presign via prove.signedUrlMint -> REJECT AND never stamps fresh_clean_replay
  const srv = await startStubServer(({ body }) => {
    const parsed = JSON.parse(body || '{}') as { fileId?: string }
    const folder = parsed.fileId === '101' ? 'folder-a' : 'folder-b'
    return {
      status: 200,
      body: JSON.stringify({
        url: `https://storage.googleapis.com/app-bucket/${folder}/file-${parsed.fileId ?? '0'}.pdf?X-Goog-Algorithm=GOOG4-RSA-SHA256&X-Goog-Signature=${sha256(`sig-${parsed.fileId ?? '0'}`)}`,
      }),
    }
  })
  t.after(() => srv.close())

  const rpc = new VerifyRpcServer({
    broker: new RequestBroker({ transportConfig: { http2: false } }),
    grant: makeGrant(srv.origin),
    runId: 'run-r4-c6-twofolder',
    assignmentId: 'asg-r4-c6-twofolder',
    targetOrigins: [srv.origin],
  })
  await rpc.start()
  t.after(() => rpc.close())

  const res = await rpcCall(rpc, 'prove.signedUrlMint', {
    route: '/api/presign',
    method: 'POST',
    controlBody: { fileId: '101' },
    probeBody: { fileId: '102' },
  })
  assert.equal(res.ok, true)
  const proof = res.result as { confirmed: boolean; rejectedBy: string; claim: { replayMode?: string } }
  assert.equal(proof.confirmed, false)
  assert.equal(proof.rejectedBy, 'signed_url_no_traversal_input')
  assert.notEqual(proof.claim.replayMode, 'fresh_clean_replay')
  assert.equal(proof.claim.replayMode, 'one_shot_transcript')
})

test('R4-C-6: 400 validation-error control rejects Variant B; anonymous 401 same-body control confirms without fresh_clean_replay', async t => {
  const origin = 'https://upload.example.test'
  const sasSig = Buffer.from(randomBytes(32)).toString('base64url')

  // 400 validation-error control -> REJECT
  const ctl400 = assessSignedUrlMintDifferential({
    control: {
      origin, method: 'POST', pathAndQuery: '/api/upload-token', status: 400,
      requestBody: JSON.stringify({}),
      responseBody: JSON.stringify({ error: 'filename required' }),
    },
    probe: {
      origin, method: 'POST', pathAndQuery: '/api/upload-token', status: 200,
      requestBody: JSON.stringify({ filename: 'report.json' }),
      responseBody: JSON.stringify({
        uploadUrl: `https://acct.blob.core.windows.net/uploads/report.json?sv=2022-11-02&se=2026-11-27T00:00:00Z&sp=cw&sig=${sasSig}`,
      }),
    },
  })
  assert.equal(ctl400.confirmed, false)
  assert.equal(ctl400.rejectedBy, 'signed_url_control_not_auth_denied')

  // 401 control with mismatched body -> REJECT
  const ctlBodyMismatch = assessSignedUrlMintDifferential({
    control: {
      origin, method: 'POST', pathAndQuery: '/api/upload-token', status: 401,
      requestBody: JSON.stringify({}),
      responseBody: JSON.stringify({ error: 'auth required' }),
    },
    probe: {
      origin, method: 'POST', pathAndQuery: '/api/upload-token', status: 200,
      requestBody: JSON.stringify({ filename: 'report.json' }),
      responseBody: JSON.stringify({
        uploadUrl: `https://acct.blob.core.windows.net/uploads/report.json?sv=2022-11-02&se=2026-11-27T00:00:00Z&sp=cw&sig=${sasSig}`,
      }),
    },
  })
  assert.equal(ctlBodyMismatch.confirmed, false)
  assert.equal(ctlBodyMismatch.rejectedBy, 'signed_url_control_body_mismatch')

  // Live loopback: 400 control vs 200 public presign -> REJECT; 401 same-body vs 200 -> CONFIRM with one_shot_transcript
  const srv = await startStubServer(({ body, headers }) => {
    const parsed = JSON.parse(body || '{}') as { filename?: string }
    if (!parsed.filename) return { status: 400, body: JSON.stringify({ error: 'filename_required' }) }
    if (headers['x-bypass-auth'] !== '1' && headers['x-require-auth'] === '1') {
      return { status: 401, body: JSON.stringify({ error: 'authentication_required' }) }
    }
    return {
      status: 200,
      body: JSON.stringify({
        uploadUrl: `https://acct.blob.core.windows.net/uploads/${parsed.filename}?sv=2022-11-02&se=2026-11-27T00:00:00Z&sp=cw&sig=${sasSig}`,
      }),
    }
  })
  t.after(() => srv.close())

  const rpc = new VerifyRpcServer({
    broker: new RequestBroker({ transportConfig: { http2: false } }),
    grant: makeGrant(srv.origin),
    runId: 'run-r4-c6-varb',
    assignmentId: 'asg-r4-c6-varb',
    targetOrigins: [srv.origin],
  })
  await rpc.start()
  t.after(() => rpc.close())

  const bad400Rpc = await rpcCall(rpc, 'prove.signedUrlMint', {
    route: '/api/upload-token',
    method: 'POST',
    controlBody: {},
    probeBody: { filename: 'report.json' },
  })
  assert.equal(bad400Rpc.ok, true)
  const bad400Proof = bad400Rpc.result as { confirmed: boolean; rejectedBy: string }
  assert.equal(bad400Proof.confirmed, false)
  assert.equal(bad400Proof.rejectedBy, 'signed_url_control_not_auth_denied')

  const ok401Rpc = await rpcCall(rpc, 'prove.signedUrlMint', {
    control: { path: '/api/upload-token', method: 'POST', headers: { 'x-require-auth': '1' }, body: { filename: 'report.json' } },
    probe: { path: '/api/upload-token', method: 'POST', headers: { 'x-require-auth': '1', 'x-bypass-auth': '1' }, body: { filename: 'report.json' } },
  })
  assert.equal(ok401Rpc.ok, true)
  const ok401Proof = ok401Rpc.result as { confirmed: boolean; variant: string; claim: { replayMode?: string } }
  assert.equal(ok401Proof.confirmed, true)
  assert.equal(ok401Proof.variant, 'unauth_write_mint')
  assert.equal(ok401Proof.claim.replayMode, 'one_shot_transcript')
})

test('R4-C-6: malformed percent-escape and JSON-unicode reflecting stubs reject signed_url_mint on both arms', async t => {
  const sigCtl = sha256('echo-ctl-sig')
  const sigPrb = sha256('echo-prb-sig')

  // Malformed percent-escape hiding echoed probe signature -> FAIL CLOSED
  const srv = await startStubServer(({ url, body }) => {
    const parsedUrl = new URL(url, 'http://127.0.0.1')
    const q = parsedUrl.searchParams.get('q')
    if (q) return { status: 200, body: JSON.stringify({ url: q }) }
    const parsedBody = JSON.parse(body || '{}') as { mirror?: string }
    return { status: 200, body: JSON.stringify({ url: parsedBody.mirror ?? '' }) }
  })
  t.after(() => srv.close())

  const rpc = new VerifyRpcServer({
    broker: new RequestBroker({ transportConfig: { http2: false } }),
    grant: makeGrant(srv.origin),
    runId: 'run-r4-c6-echo',
    assignmentId: 'asg-r4-c6-echo',
    targetOrigins: [srv.origin],
  })
  await rpc.start()
  t.after(() => rpc.close())

  const ctlUrl = `https://storage.googleapis.com/bkt/uploads/a.png?X-Goog-Algorithm=GOOG4-RSA-SHA256&X-Goog-Signature=${sigCtl}`
  const prbUrl = `https://storage.googleapis.com/bkt/canary.json?X-Goog-Algorithm=GOOG4-RSA-SHA256&X-Goog-Signature=${sigPrb}`

  // 1) Malformed percent escape on query parameter alongside echoed signed URL
  const malformedPct = await rpcCall(rpc, 'prove.signedUrlMint', {
    control: { path: `/search?q=${encodeURIComponent(ctlUrl)}`, method: 'GET' },
    probe: { path: `/search?q=${encodeURIComponent(prbUrl)}&bad=%ZZ`, method: 'GET' },
  })
  assert.equal(malformedPct.ok, true)
  const malformedProof = malformedPct.result as { confirmed: boolean; rejectedBy: string }
  assert.equal(malformedProof.confirmed, false)
  assert.equal(malformedProof.rejectedBy, 'signed_url_malformed_request_carrier')

  // 2) JSON unicode-escaped signature reflected in probe body
  const uniSig = sigPrb.split('').map(c => `\\u00${c.charCodeAt(0).toString(16).padStart(2, '0')}`).join('')
  const rawUniBody = `{"key":"../canary.json","mirror":"https://storage.googleapis.com/bkt/canary.json?X-Goog-Algorithm=GOOG4-RSA-SHA256&X-Goog-Signature=${uniSig}"}`
  const uniRes = assessSignedUrlMintDifferential({
    control: {
      origin: srv.origin, method: 'POST', pathAndQuery: '/search', status: 200,
      requestBody: '{"key":"a.png"}',
      responseBody: JSON.stringify({ url: ctlUrl }),
    },
    probe: {
      origin: srv.origin, method: 'POST', pathAndQuery: '/search', status: 200,
      requestBody: rawUniBody,
      responseBody: JSON.stringify({ url: prbUrl }),
    },
  })
  assert.equal(uniRes.confirmed, false)
  assert.equal(uniRes.rejectedBy, 'signed_url_echoed')

  // 3) Control-arm echoed signature -> REJECT
  const ctlEchoRes = assessSignedUrlMintDifferential({
    control: {
      origin: srv.origin, method: 'POST', pathAndQuery: '/search', status: 200,
      requestBody: JSON.stringify({ key: 'a.png', mirror: sigCtl }),
      responseBody: JSON.stringify({ url: ctlUrl }),
    },
    probe: {
      origin: srv.origin, method: 'POST', pathAndQuery: '/search', status: 200,
      requestBody: JSON.stringify({ key: '../canary.json' }),
      responseBody: JSON.stringify({ url: prbUrl }),
    },
  })
  assert.equal(ctlEchoRes.confirmed, false)
  assert.equal(ctlEchoRes.rejectedBy, 'signed_url_control_echoed')
})

// ============================================================================
// 2. R4-C-2: prove.injection stamps hostExpressionChallenge & NEVER returns expectedOutput
// ============================================================================

test('R4-C-2: prove.injection stamps hostExpressionChallenge on transcript records and NEVER returns expectedOutput or operands', async t => {
  const srv = await startStubServer(({ url }) => {
    const parsed = new URL(url, 'http://127.0.0.1')
    const expr = parsed.searchParams.get('expr') ?? ''
    const m = /^eval:(\d+)\*(\d+)$/.exec(expr)
    if (m) return { status: 200, body: JSON.stringify({ rendered: String(Number(m[1]) * Number(m[2])) }) }
    return { status: 200, body: JSON.stringify({ rendered: 'benign' }) }
  })
  t.after(() => srv.close())

  const rpc = new VerifyRpcServer({
    broker: new RequestBroker({ transportConfig: { http2: false } }),
    grant: makeGrant(srv.origin),
    runId: 'run-r4-c2-expr',
    assignmentId: 'asg-r4-c2-expr',
    targetOrigins: [srv.origin],
  })
  await rpc.start()
  t.after(() => rpc.close())

  const resp = await rpcCall(rpc, 'prove.injection', {
    control: '/api/eval?expr=benign',
    probe: '/api/eval?expr=eval:{{expr}}',
    expressionFamily: 'ssti',
  })
  assert.equal(resp.ok, true, `prove.injection RPC failed: ${resp.error ?? ''}`)
  const proof = resp.result as {
    ok: boolean
    confirmed: boolean
    probe: { exchangeId: string }
    probe2: { exchangeId: string }
    hostMintedChallenges: Array<Record<string, unknown>>
    claim: VerifyClaim
  }
  assert.equal(proof.ok, true)
  assert.equal(proof.confirmed, true)
  assert.equal(proof.hostMintedChallenges.length, 2)

  // Worker-facing hostMintedChallenges must NEVER contain expectedOutput or operands
  for (const ch of proof.hostMintedChallenges) {
    assert.equal(typeof ch.challengeId, 'string')
    assert.equal('expectedOutput' in ch, false, 'expectedOutput must NEVER be returned to the worker')
    assert.equal('operandA' in ch, false, 'operandA must NEVER be returned to the worker')
    assert.equal('operandB' in ch, false, 'operandB must NEVER be returned to the worker')
    assert.equal('expressionSyntax' in ch, false, 'expressionSyntax must NEVER be returned to the worker')
  }

  // Host TranscriptStore & HostFactLog MUST carry the stamped hostExpressionChallenge
  const rec1 = rpc.transcript.get(proof.probe.exchangeId)
  const rec2 = rpc.transcript.get(proof.probe2.exchangeId)
  assert.ok(rec1?.hostExpressionChallenge, 'probe1 transcript record must carry hostExpressionChallenge stamp')
  assert.ok(rec2?.hostExpressionChallenge, 'probe2 transcript record must carry hostExpressionChallenge stamp')
  assert.equal(rec1.hostExpressionChallenge.challengeId, proof.hostMintedChallenges[0]!.challengeId)
  assert.equal(rec2.hostExpressionChallenge.challengeId, proof.hostMintedChallenges[1]!.challengeId)

  const factLog = rpc.buildHostFactLog()
  assert.equal(factLog.getExchange(proof.probe.exchangeId)?.hostExpressionChallenge?.challengeId, rec1.hostExpressionChallenge.challengeId)
  assert.equal(factLog.getExchange(proof.probe2.exchangeId)?.hostExpressionChallenge?.challengeId, rec2.hostExpressionChallenge.challengeId)

  // Worker-facing transcript.get must ALSO strip expectedOutput / operands from hostExpressionChallenge
  const tGet = await rpcCall(rpc, 'transcript', { action: 'get', exchangeId: proof.probe.exchangeId })
  assert.equal(tGet.ok, true)
  const tRecord = (tGet.result as { record: { hostExpressionChallenge?: Record<string, unknown> } }).record
  if (tRecord.hostExpressionChallenge) {
    assert.equal('expectedOutput' in tRecord.hostExpressionChallenge, false, 'transcript.get must strip expectedOutput')
    assert.equal('operandA' in tRecord.hostExpressionChallenge, false, 'transcript.get must strip operandA')
  }

  // Host-stamped claim passes evaluateClaims
  const evalRes = evaluateClaims(rpc.transcript, [proof.claim], { factLog })
  assert.equal(evalRes.passed, true, evalRes.failures.join('; '))
})

// ============================================================================
// 3. R4-C-1: prove.differential stamps hostBooleanPair & verify-support shares
//            canonicalPredicateSkeleton + equal-length / same-charset invariants
// ============================================================================

test('R4-C-1: verify-support enforces canonical skeleton / equal-length / same-charset and prove.differential stamps hostBooleanPair', async t => {
  // Pure unit guards on mintHostBooleanPair & verifyBooleanArmBaseParity
  assert.throws(() => mintHostBooleanPair('', { oracle: defaultHostMintedOracle }), /non-empty baseValue/i)
  const pair = mintHostBooleanPair('10', { style: 'numeric', oracle: defaultHostMintedOracle })
  assert.equal(pair.trueValue.length, pair.falseValue.length)
  assert.equal([...pair.trueValue].sort().join(''), [...pair.falseValue].sort().join(''))
  assert.ok(defaultHostMintedOracle.getBooleanPair(pair.challengeId), 'mintHostBooleanPair with oracle must register in defaultHostMintedOracle')

  // Reject unequal length / different char multiset / different skeleton / empty-base standalone predicate
  assert.equal(verifyBooleanArmBaseParity({ controlValue: '1 AND 1=1', variantValue: '1 AND 1=12', baselineValue: '1' }).ok, false)
  assert.equal(verifyBooleanArmBaseParity({ controlValue: '1 AND 1=1', variantValue: '1 AND 1!=1', baselineValue: '1' }).ok, false)
  assert.equal(verifyBooleanArmBaseParity({ controlValue: 'NOT 1=2', variantValue: '1=2' }).ok, false)

  // Live prove.differential stamps hostBooleanPair on baseline, true, and false transcript records
  const srv = await startStubServer(({ url }) => {
    const parsed = new URL(url, 'http://127.0.0.1')
    const id = parsed.searchParams.get('id') ?? ''
    const stripped = stripBooleanPredicateSuffix(id)
    if (stripped.baseValue === '7' && stripped.predicateTruth !== false) {
      return { status: 200, body: JSON.stringify({ id: 7, status: 'active', rows: 1 }) }
    }
    return { status: 200, body: JSON.stringify({ id: null, status: 'empty', rows: 0 }) }
  })
  t.after(() => srv.close())

  const rpc = new VerifyRpcServer({
    broker: new RequestBroker({ transportConfig: { http2: false } }),
    grant: makeGrant(srv.origin),
    runId: 'run-r4-c1-bool',
    assignmentId: 'asg-r4-c1-bool',
    targetOrigins: [srv.origin],
  })
  await rpc.start()
  t.after(() => rpc.close())

  const diffResp = await rpcCall(rpc, 'prove.differential', {
    mode: 'boolean',
    booleanBase: '7',
    booleanStyle: 'numeric',
    baseline: '/api/items?id={{boolBase}}',
    control: '/api/items?id={{boolTrue}}',
    variant: '/api/items?id={{boolFalse}}',
    rounds: 2,
  })
  assert.equal(diffResp.ok, true, `prove.differential failed: ${diffResp.error ?? ''}`)
  const out = diffResp.result as {
    ok: boolean
    baselineIds: string[]
    controlIds: string[]
    variantIds: string[]
    hostBooleanPair: { challengeId: string; baseValue: string; trueValue: string; falseValue: string }
  }
  assert.equal(out.ok, true)
  assert.equal(out.hostBooleanPair.trueValue.length, out.hostBooleanPair.falseValue.length)
  assert.equal([...out.hostBooleanPair.trueValue].sort().join(''), [...out.hostBooleanPair.falseValue].sort().join(''))

  // Every baseline/control/variant transcript record carries its hostBooleanPair stamp
  const factLog = rpc.buildHostFactLog()
  for (const id of out.baselineIds) {
    assert.equal(rpc.transcript.get(id)?.hostBooleanPair?.arm, 'baseline')
    assert.equal(rpc.transcript.get(id)?.hostBooleanPair?.challengeId, out.hostBooleanPair.challengeId)
    assert.equal(factLog.getExchange(id)?.hostBooleanPair?.arm, 'baseline')
  }
  for (const id of out.controlIds) {
    assert.equal(rpc.transcript.get(id)?.hostBooleanPair?.arm, 'true')
    assert.equal(factLog.getExchange(id)?.hostBooleanPair?.arm, 'true')
  }
  for (const id of out.variantIds) {
    assert.equal(rpc.transcript.get(id)?.hostBooleanPair?.arm, 'false')
    assert.equal(factLog.getExchange(id)?.hostBooleanPair?.arm, 'false')
  }

  // Kernel verifyReceipt confirms the stamped boolean triangle directly from HostFactLog
  const receipt = buildProofReceipt({
    vulnClass: 'sqli',
    target: { origin: srv.origin, method: 'GET', pathAndQuery: '/api/items', param: 'id' },
    exchangeIds: [...out.baselineIds, ...out.controlIds, ...out.variantIds],
    claimedDelta: 'Host-stamped boolean differential separates true/false arms.',
  })
  const kernelVerdict = verifyReceipt(receipt, factLog.toReceiptTranscript())
  assert.equal(kernelVerdict.confirmed, true, kernelVerdict.reason)
})

// ============================================================================
// 4. R4-H-4: Worker-visible digest primitive (request & response planes)
// ============================================================================

test('R4-H-4: no worker-facing request or response digest (transcript.get, prove.signedUrlMint) equals SHA-256 of a vault-bearing plaintext string', async t => {
  const vaultSecret = 'otp_reset_948271_secret'
  const srv = await startStubServer(({ url, body }) => {
    if (url.startsWith('/api/issue-otp')) {
      return { status: 200, body: JSON.stringify({ reset_token: vaultSecret }) }
    }
    if (url.startsWith('/api/echo-otp')) {
      return { status: 200, body: JSON.stringify({ echoed: body, secretMirror: vaultSecret }) }
    }
    return { status: 404, body: '{"error":"not_found"}' }
  })
  t.after(() => srv.close())

  const rpc = new VerifyRpcServer({
    broker: new RequestBroker({ transportConfig: { http2: false } }),
    grant: makeGrant(srv.origin),
    runId: 'run-r4-h4-digests',
    assignmentId: 'asg-r4-h4-digests',
    targetOrigins: [srv.origin],
  })
  await rpc.start()
  t.after(() => rpc.close())

  // 1) Fetch response containing a heuristically redacted secret field and seal it into the vault
  const issueResp = await rpcCall(rpc, 'http.send', { path: '/api/issue-otp', method: 'GET' })
  assert.equal(issueResp.ok, true)
  const issueView = issueResp.result as { exchangeId: string; body: string; bodySha256: string }
  assert.equal(issueView.body.includes(vaultSecret), false)

  const sealResp = await rpcCall(rpc, 'capability.seal', {
    exchangeId: issueView.exchangeId,
    hopReceiptId: 'h1',
    slot: 'otp',
    jsonPath: '$.reset_token',
    kind: 'opaque_secret',
  })
  assert.equal(sealResp.ok, true, `capability.seal failed: ${sealResp.error ?? ''}`)
  const handle = (sealResp.result as { handle: string }).handle

  // 2) Inject the sealed handle inline into a POST request body
  const templateBody = JSON.stringify({ code: handle })
  const plaintextInjectedBody = JSON.stringify({ code: vaultSecret })
  const plaintextReqSha = sha256(plaintextInjectedBody)

  const sendResp = await rpcCall(rpc, 'http.send', {
    path: '/api/echo-otp',
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: templateBody,
  })
  assert.equal(sendResp.ok, true, `http.send failed: ${sendResp.error ?? ''}`)
  const sendView = sendResp.result as { exchangeId: string; body: string; bodySha256: string; bodyBytes: number }
  assert.equal(sendView.body.includes(vaultSecret), false)

  const rawRespBody = JSON.stringify({ echoed: plaintextInjectedBody, secretMirror: vaultSecret })
  const plaintextRespSha = sha256(rawRespBody)
  assert.notEqual(sendView.bodySha256, plaintextRespSha, 'exchangeView response bodySha256 must NOT equal raw plaintext digest')

  // 3) transcript.get MUST NOT expose raw request OR raw response bodySha256/bodyBytes
  const tGet = await rpcCall(rpc, 'transcript', { action: 'get', exchangeId: sendView.exchangeId })
  assert.equal(tGet.ok, true)
  const tData = tGet.result as {
    body: string
    record: {
      request: { bodySha256: string; bodyBytes: number }
      response: { bodySha256: string; bodyBytes: number }
    }
  }
  assert.equal(tData.body.includes(vaultSecret), false)
  assert.notEqual(tData.record.request.bodySha256, plaintextReqSha, 'transcript.get request.bodySha256 must NOT equal SHA-256 of vault-bearing plaintext body')
  assert.notEqual(tData.record.request.bodyBytes, Buffer.byteLength(plaintextInjectedBody, 'utf8'), 'transcript.get request.bodyBytes must reflect scrubbed placeholder length, not plaintext length')
  assert.notEqual(tData.record.response.bodySha256, plaintextRespSha, 'transcript.get response.bodySha256 must NOT equal SHA-256 of vault-bearing plaintext response')
  assert.equal(tData.record.response.bodySha256, sha256(tData.body))

  // 4) prove.signedUrlMint using existing exchangeIds MUST compute digests strictly from worker-visible scrubbed bodies
  const suResp = await rpcCall(rpc, 'prove.signedUrlMint', {
    controlExchangeId: issueView.exchangeId,
    probeExchangeId: sendView.exchangeId,
  })
  assert.equal(suResp.ok, true, `prove.signedUrlMint existing-id path failed: ${suResp.error ?? ''}`)
  const suData = suResp.result as {
    control: { body: string; bodySha256: string; bodyBytes: number }
    probe: { body: string; bodySha256: string; bodyBytes: number }
  }
  assert.equal(suData.control.body.includes(vaultSecret), false)
  assert.equal(suData.probe.body.includes(vaultSecret), false)
  assert.notEqual(suData.control.bodySha256, sha256(JSON.stringify({ reset_token: vaultSecret })), 'prove.signedUrlMint control.bodySha256 must NOT equal raw plaintext digest')
  assert.notEqual(suData.probe.bodySha256, plaintextRespSha, 'prove.signedUrlMint probe.bodySha256 must NOT equal raw plaintext digest')
  assert.equal(suData.probe.bodySha256, sha256(suData.probe.body))
})

// ============================================================================
// 5. R4-H-2 / L800: VerifyRpcServer getKernelSecrets uses shared
//    provenance-tiered buildPersonaSecretNeedles
// ============================================================================

test('R4-H-2: VerifyRpcServer getKernelSecrets scrubs weak operator primary credentials via shared buildPersonaSecretNeedles without corrupting protocol substrings', async t => {
  const weakBearer = 'tok42a'
  const dictPassword = 'password'
  const genericHexCookie = 'a1b2c3d4e5f6'
  const protocolCookieVal = 'response.output_text.delta'
  const benignPrefVal = 'dark_mode_enabled'

  const srv = await startStubServer(() => ({
    status: 200,
    body: JSON.stringify({
      csvLine: `row,1,${weakBearer},${dictPassword},${genericHexCookie}`,
      streamEvent: protocolCookieVal,
      uiPref: benignPrefVal,
    }),
  }))
  t.after(() => srv.close())

  const personas = new Map<string, ResolvedPersona>([
    ['weak_bearer', {
      id: 'p-weak-bearer',
      handle: 'weak_bearer',
      roleLabel: 'member',
      originAllowlist: [srv.origin],
      authKind: 'bearer',
      headerName: null,
      secret: weakBearer,
      secretHistory: [weakBearer],
      canaryMarkers: [],
    }],
    ['dict_login', {
      id: 'p-dict-login',
      handle: 'dict_login',
      roleLabel: 'member',
      originAllowlist: [srv.origin],
      authKind: 'login',
      headerName: null,
      secret: dictPassword,
      secretHistory: [dictPassword],
      session: {
        headerType: 'cookie',
        value: `prefs=${benignPrefVal}; x_track=${protocolCookieVal}`,
        adapterUsed: 'json',
        scrubTokens: [`x_track=${protocolCookieVal}`, protocolCookieVal],
      },
      canaryMarkers: [],
    }],
    ['hex_cookie', {
      id: 'p-hex-cookie',
      handle: 'hex_cookie',
      roleLabel: 'member',
      originAllowlist: [srv.origin],
      authKind: 'cookie',
      headerName: null,
      secret: `my_c=${genericHexCookie}`,
      secretHistory: [`my_c=${genericHexCookie}`],
      canaryMarkers: [],
    }],
  ])

  const grant: Grant = {
    ...makeGrant(srv.origin),
    personas,
  }

  const rpc = new VerifyRpcServer({
    broker: new RequestBroker({ transportConfig: { http2: false } }),
    grant,
    runId: 'run-r4-h2-kernel-secrets',
    assignmentId: 'asg-r4-h2-kernel-secrets',
    targetOrigins: [srv.origin],
  })
  await rpc.start()
  t.after(() => rpc.close())

  const sendResp = await rpcCall(rpc, 'http.send', { path: '/api/echo-creds', method: 'GET' })
  assert.equal(sendResp.ok, true, `http.send failed: ${sendResp.error ?? ''}`)
  const sendView = sendResp.result as { exchangeId: string; body: string }

  // Weak operator-configured primary credentials MUST be scrubbed across broker + kernel boundaries
  assert.equal(sendView.body.includes(weakBearer), false, 'weak 6-char primary bearer must be scrubbed')
  assert.equal(sendView.body.includes(dictPassword), false, 'dictionary primary login password must be scrubbed')
  assert.equal(sendView.body.includes(genericHexCookie), false, 'non-auth-named 12-hex primary cookie must be scrubbed')

  // Target-derived protocol-substring & benign preference cookies MUST NOT be promoted to exact needles
  assert.equal(sendView.body.includes(protocolCookieVal), true, 'target-derived protocol substring must NOT be scrubbed')
  assert.equal(sendView.body.includes(benignPrefVal), true, 'target-derived benign preference cookie must NOT be scrubbed')

  // Verify transcript.get worker view preserves the exact same provenance-tiered redaction
  const tGet = await rpcCall(rpc, 'transcript', { action: 'get', exchangeId: sendView.exchangeId })
  assert.equal(tGet.ok, true)
  const tBody = (tGet.result as { body: string }).body
  assert.equal(tBody.includes(weakBearer), false)
  assert.equal(tBody.includes(dictPassword), false)
  assert.equal(tBody.includes(genericHexCookie), false)
  assert.equal(tBody.includes(protocolCookieVal), true)

  // Direct VerifyRpcServer kernel-layer check (pass-through broker without broker-side persona redaction)
  // proves `getKernelSecrets` itself routes through `buildPersonaSecretNeedles` with `[redacted:<handle>]`.
  const rawBody = JSON.stringify({
    csvLine: `row,1,${weakBearer},${dictPassword},${genericHexCookie}`,
    streamEvent: protocolCookieVal,
    uiPref: benignPrefVal,
  })
  const passthroughBroker = {
    executeHttp: async () => ({
      origin: srv.origin,
      finalOrigin: srv.origin,
      redirectOrigins: [],
      method: 'GET',
      pathAndQuery: '/api/echo-creds',
      personaHandle: null,
      status: 200,
      mediaType: 'application/json',
      reqHeaders: {},
      respHeaders: { 'content-type': 'application/json' },
      setCookies: [],
      bodyPreview: rawBody,
      body: rawBody,
      bodyBytes: Buffer.byteLength(rawBody, 'utf8'),
      bodySha256: sha256(rawBody),
      bodyTruncated: false,
      durationMs: 1,
    }),
  } as unknown as RequestBroker
  const kernelRpc = new VerifyRpcServer({
    broker: passthroughBroker,
    grant,
    runId: 'run-r4-h2-kernel-direct',
    assignmentId: 'asg-r4-h2-kernel-direct',
    targetOrigins: [srv.origin],
  })
  await kernelRpc.start()
  t.after(() => kernelRpc.close())

  const kernelResp = await rpcCall(kernelRpc, 'http.send', { path: '/api/echo-creds', method: 'GET' })
  assert.equal(kernelResp.ok, true, `kernel http.send failed: ${kernelResp.error ?? ''}`)
  const kernelBody = (kernelResp.result as { body: string }).body
  assert.equal(kernelBody.includes(weakBearer), false, 'kernel sanitizer must scrub weak 6-char primary bearer')
  assert.equal(kernelBody.includes(dictPassword), false, 'kernel sanitizer must scrub dictionary primary password')
  assert.equal(kernelBody.includes(genericHexCookie), false, 'kernel sanitizer must scrub non-auth-named 12-hex primary cookie')
  assert.match(kernelBody, /\[redacted:weak_bearer\]/)
  assert.match(kernelBody, /\[redacted:dict_login\]/)
  assert.match(kernelBody, /\[redacted:hex_cookie\]/)
  assert.equal(kernelBody.includes(protocolCookieVal), true, 'kernel getKernelSecrets must NOT scrub target-derived protocol substring')
  assert.equal(kernelBody.includes(benignPrefVal), true, 'kernel getKernelSecrets must NOT scrub target-derived benign preference cookie')
})
