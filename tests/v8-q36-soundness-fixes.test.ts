/**
 * Regression suite for the 4 host-side soundness & secret-leakage bugs uncovered by Seam 3 (#526):
 *   1. Forged inline `oracleInput` records bypassing host transcript hydration & field integrity.
 *   2. Signature bypass via `terminalImpact.proofReceipt` (and `hops[].proofReceipt`) citations.
 *   3. Unscrubbed RPC catch-block errors (`handle`, `handleBrowser`) and missing generic `redact()` in `VerifyRpcServer.scrub()`.
 *   4. Unredacted `title`, `claimTitle`, and `disagreements` in `verifyScript()`.
 *
 * 100% generic fixtures (zero benchmark literals) + LOC ceiling enforcement.
 */
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { createServer, request as httpRequest } from 'node:http'
import type { IncomingMessage, ServerResponse } from 'node:http'
import test from 'node:test'

import { scanTextForContamination } from '../scripts/check-v8-contamination.ts'
import { RequestBroker } from '../src/server/broker.ts'
import type { Grant } from '../src/server/broker.ts'
import {
  sha256Hex,
  signHostRecord,
  verifyCompositeReceipt,
} from '../src/server/composite-receipt.ts'
import type {
  CompositeProofReceipt,
  HostSignedTranscript,
  HostTranscriptEntry,
} from '../src/server/composite-receipt.ts'
import type { ImpactStep } from '../src/server/oracle-invariants.ts'
import type { ResolvedPersona } from '../src/server/persona-vault.ts'
import { TranscriptStore } from '../src/server/verify-claims.ts'
import {
  VERIFY_NONCE_HEADER,
  VERIFY_RPC_HEADER,
  VerifyRpcServer,
} from '../src/server/verify-rpc.ts'
import { verifyScript } from '../src/server/verify-runner.ts'

process.env.GUARDIAN_ALLOW_LOCAL_LAB = '1'

const ORIGIN = 'https://api.example.test'
const SIGNING_KEY = 'q36-soundness-signing-key-9e4f1a2b3c5d6e7f'

function makeStep(partial: Partial<ImpactStep> & Pick<ImpactStep, 'id' | 'arm' | 'method' | 'status'>): ImpactStep {
  return {
    id: partial.id,
    arm: partial.arm,
    method: partial.method,
    status: partial.status,
    actor: partial.actor ?? {
      handle: 'member_alpha',
      role: 'member',
      tenant: 'org-alpha',
      auth: 'bearer',
      sameSite: null,
    },
    ...(partial.route !== undefined ? { route: partial.route } : {}),
    ...(partial.pathAndQuery !== undefined ? { pathAndQuery: partial.pathAndQuery } : {}),
    ...(partial.json !== undefined ? { json: partial.json } : {}),
    ...(partial.body !== undefined ? { body: partial.body } : {}),
    ...(partial.requestHeaders !== undefined ? { requestHeaders: partial.requestHeaders } : {}),
    ...(partial.responseHeaders !== undefined ? { responseHeaders: partial.responseHeaders } : {}),
  }
}

function makeSignedEntry(
  exchangeId: string,
  step: ImpactStep,
  extra: Partial<HostTranscriptEntry> = {},
  key = SIGNING_KEY,
): HostTranscriptEntry {
  const base: HostTranscriptEntry = {
    exchangeId,
    step,
    timestampMs: extra.timestampMs ?? 1_700_000_000_000,
    actorPersona: extra.actorPersona !== undefined ? extra.actorPersona : step.actor.handle,
    cleanSession: extra.cleanSession ?? true,
    ...extra,
  }
  return { ...base, hostSignature: signHostRecord(base, key) }
}

// ============================================================================
// Bug 1: Forged inline `oracleInput` records MUST fail closed (with & without signingKey)
// ============================================================================

test('Bug 1: forged inline oracleInput record with valid hostSignature cannot spoof status/json/fields', () => {
  const deniedTransfer = makeSignedEntry('ex-1', makeStep({
    id: 'ex-1', arm: 'probe', method: 'POST', status: 403,
    route: '/api/records/rec-50/transfer', pathAndQuery: '/api/records/rec-50/transfer',
    json: { error: 'forbidden' },
  }), { timestampMs: 1000 })
  const ctrlDenied = makeSignedEntry('ex-ctrl', makeStep({
    id: 'ex-ctrl', arm: 'control', method: 'POST', status: 403,
    route: '/api/records/rec-50/transfer', pathAndQuery: '/api/records/rec-50/transfer',
    json: { error: 'forbidden' },
  }), { timestampMs: 900 })
  const readback = makeSignedEntry('ex-rb', makeStep({
    id: 'ex-rb', arm: 'probe', method: 'GET', status: 200,
    route: '/api/records/rec-50', pathAndQuery: '/api/records/rec-50',
    json: { id: 'rec-50', tenantId: 'org-beta', ownerTenantId: 'org-beta' },
  }), { timestampMs: 1200 })

  const transcript: HostSignedTranscript = { entries: [ctrlDenied, deniedTransfer, readback] }

  // Exact #526 attack: pass real hostSignature from ex-1 (status 403 in transcript),
  // but spoof status: 200 and json: { transferred: true } inline in oracleInput.
  const forgedReceipt: CompositeProofReceipt = {
    chainId: 'q36-forged-inline-oracle',
    terminalVulnClass: 'dual_tenant_abac',
    hops: [{
      hopId: 'hop_1', surface: 'http',
      target: { origin: ORIGIN, method: 'GET', pathAndQuery: '/api/records/rec-50' },
      exchangeIds: ['ex-rb'], oobEventIds: [], browserTraceIds: [],
      claimedDelta: 'Attempted cross-org transfer spoofing',
      producedCapabilities: [], consumedCapabilities: [],
    }],
    causalEdges: [],
    terminalImpact: {
      terminalHopId: 'hop_1',
      claimedImpact: 'Attempted to spoof transfer status via inline oracleInput record.',
      summary: 'Attempted to spoof transfer status via inline oracleInput record.',
      terminalExchangeId: 'ex-rb',
      preChainControlExchangeIds: ['ex-ctrl'],
      postChainReadbackExchangeIds: ['ex-rb'],
      oracleFamily: 'dual_tenant_abac',
      oracleInput: {
        mode: 'cross_org_transfer',
        actor: { actorId: 'member_alpha', rolesByTenant: { 'org-alpha': 'member', 'org-beta': 'admin' } },
        sourceTenantId: 'org-alpha',
        destTenantId: 'org-beta',
        entityId: 'rec-50',
        requiredSourceRole: 'admin',
        transferRecord: {
          id: 'ex-1',
          hostSignature: deniedTransfer.hostSignature!,
          timestampMs: 1000,
          status: 200,
          json: { transferred: true },
        },
        postTransferReadback: {
          id: 'ex-rb',
          hostSignature: readback.hostSignature!,
          timestampMs: 1200,
          status: 200,
          json: { id: 'rec-50', ownerTenantId: 'org-beta' },
        },
        sourceControlDenied: {
          id: 'ex-ctrl',
          hostSignature: ctrlDenied.hostSignature!,
          timestampMs: 900,
          status: 403,
        },
        observedOwnerTenantId: 'org-beta',
      },
    },
    replayMode: 'fresh_clean_replay',
  }

  // Must fail closed WITH signingKey
  const resWithKey = verifyCompositeReceipt(forgedReceipt, transcript, {
    attackerPersonas: ['member_alpha'],
    signingKey: SIGNING_KEY,
  })
  assert.equal(resWithKey.confirmed, false, 'forged inline oracleInput must fail closed with signingKey')
  assert.equal(resWithKey.failedStage, 'terminal_impact')
  assert.match(resWithKey.reason, /transfer_not_accepted/)

  // Must ALSO fail closed WITHOUT signingKey
  const resNoKey = verifyCompositeReceipt(forgedReceipt, transcript, {
    attackerPersonas: ['member_alpha'],
  })
  assert.equal(resNoKey.confirmed, false, 'forged inline oracleInput must fail closed without signingKey')
  assert.equal(resNoKey.failedStage, 'terminal_impact')
  assert.match(resNoKey.reason, /transfer_not_accepted/)

  // Fabricated inline record whose ID is ABSENT from transcript must fail closed even WITHOUT signingKey!
  const absentIdReceipt = structuredClone(forgedReceipt)
  ;(absentIdReceipt.terminalImpact.oracleInput as Record<string, unknown>).transferRecord = {
    id: 'ex-fabricated-ghost',
    hostSignature: 'f'.repeat(64),
    timestampMs: 1000,
    status: 200,
    json: { transferred: true },
  }
  const resGhostNoKey = verifyCompositeReceipt(absentIdReceipt, transcript, {
    attackerPersonas: ['member_alpha'],
  })
  assert.equal(resGhostNoKey.confirmed, false, 'absent fabricated inline record must fail closed without signingKey')
  assert.equal(resGhostNoKey.failedStage, 'terminal_impact')
  assert.match(resGhostNoKey.reason, /invalid_transfer_signature/)

  const resGhostWithKey = verifyCompositeReceipt(absentIdReceipt, transcript, {
    attackerPersonas: ['member_alpha'],
    signingKey: SIGNING_KEY,
  })
  assert.equal(resGhostWithKey.confirmed, false, 'absent fabricated inline record must fail closed with signingKey')
  assert.match(resGhostWithKey.reason, /invalid_transfer_signature/)
})

// ============================================================================
// Bug 2: Forged signatures on `terminalImpact.proofReceipt` citations MUST fail closed
// ============================================================================

test('Bug 2: forged hostSignature on terminalImpact.proofReceipt exchange/oob/browser citations fails closed', () => {
  const validCtrl = makeSignedEntry('ex-ctrl-ok', makeStep({
    id: 'ex-ctrl-ok', arm: 'control', method: 'GET', status: 403,
    route: '/api/accounts/acct-2', pathAndQuery: '/api/accounts/acct-2',
    json: { error: 'forbidden' },
  }), { timestampMs: 900 })
  const forgedProbeBase: HostTranscriptEntry = {
    exchangeId: 'ex-probe-forged',
    step: makeStep({
      id: 'ex-probe-forged', arm: 'probe', method: 'GET', status: 200,
      route: '/api/accounts/acct-2', pathAndQuery: '/api/accounts/acct-2',
      json: { id: 'acct-2', tenantId: 'org-beta', balanceCents: 999_000, ownerEmail: 'owner@beta.example.test' },
    }),
    timestampMs: 1100,
    actorPersona: 'member_alpha',
    cleanSession: true,
    hostSignature: '0'.repeat(64),
  }

  // Exact #526 attack: cite valid signed control in hops[0].exchangeIds and hide forged probe
  // ONLY inside terminalImpact.proofReceipt.exchangeIds.
  const baseReceipt: CompositeProofReceipt = {
    chainId: 'q36-proof-receipt-sig-bypass',
    terminalVulnClass: 'bola',
    hops: [{
      hopId: 'hop_1', surface: 'http',
      target: { origin: ORIGIN, method: 'GET', pathAndQuery: '/api/accounts/acct-2' },
      exchangeIds: ['ex-ctrl-ok'], oobEventIds: [], browserTraceIds: [],
      claimedDelta: 'Attempted signature bypass via terminalImpact.proofReceipt',
      producedCapabilities: [], consumedCapabilities: [],
    }],
    causalEdges: [],
    terminalImpact: {
      terminalHopId: 'hop_1',
      claimedImpact: 'Cross-tenant account read via forged proofReceipt exchange.',
      summary: 'Cross-tenant account read via forged proofReceipt exchange.',
      preChainControlExchangeIds: ['ex-ctrl-ok'],
      postChainReadbackExchangeIds: [],
      proofReceipt: {
        vulnClass: 'bola',
        target: { origin: ORIGIN, method: 'GET', pathAndQuery: '/api/accounts/acct-2' },
        exchangeIds: ['ex-ctrl-ok', 'ex-probe-forged'],
        oobEventIds: [],
        browserTraceIds: [],
        claimedDelta: 'Unauthorized foreign account read.',
      },
    },
    replayMode: 'fresh_clean_replay',
  }

  const resEx = verifyCompositeReceipt(
    baseReceipt,
    { entries: [validCtrl, forgedProbeBase] },
    { attackerPersonas: ['member_alpha'], signingKey: SIGNING_KEY },
  )
  assert.equal(resEx.confirmed, false, 'forged exchangeId in terminalImpact.proofReceipt must fail closed')
  assert.equal(resEx.failedStage, 'transcript_integrity')
  assert.match(resEx.reason, /Host signature verification failed.*terminal proofReceipt exchange/)

  // Forged OOB event cited ONLY in terminalImpact.proofReceipt.oobEventIds
  const validProbe = makeSignedEntry('ex-probe-ok', forgedProbeBase.step, { timestampMs: 1100 })
  const oobReceipt = structuredClone(baseReceipt)
  oobReceipt.terminalImpact.proofReceipt!.exchangeIds = ['ex-ctrl-ok', 'ex-probe-ok']
  oobReceipt.terminalImpact.proofReceipt!.oobEventIds = ['oob-forged-1']
  const resOob = verifyCompositeReceipt(
    oobReceipt,
    {
      entries: [validCtrl, validProbe],
      oobEvents: [{ id: 'oob-forged-1', delivered: true, receivedAtMs: 1200, token: 'tok-1', hostSignature: '0'.repeat(64) }],
    },
    { attackerPersonas: ['member_alpha'], signingKey: SIGNING_KEY },
  )
  assert.equal(resOob.confirmed, false, 'forged oobEventId in terminalImpact.proofReceipt must fail closed')
  assert.equal(resOob.failedStage, 'transcript_integrity')
  assert.match(resOob.reason, /Host signature verification failed.*terminal proofReceipt OOB event/)

  // Forged browserTraceId cited ONLY in terminalImpact.proofReceipt.browserTraceIds
  const traceReceipt = structuredClone(baseReceipt)
  traceReceipt.terminalImpact.proofReceipt!.exchangeIds = ['ex-ctrl-ok', 'ex-probe-ok']
  traceReceipt.terminalImpact.proofReceipt!.browserTraceIds = ['trace-forged-1']
  const resTrace = verifyCompositeReceipt(
    traceReceipt,
    {
      entries: [validCtrl, validProbe],
      browserTraces: [{ id: 'trace-forged-1', origin: ORIGIN, sinks: ['dom-sink'], timestampMs: 1200, hostSignature: '0'.repeat(64) }],
    },
    { attackerPersonas: ['member_alpha'], signingKey: SIGNING_KEY },
  )
  assert.equal(resTrace.confirmed, false, 'forged browserTraceId in terminalImpact.proofReceipt must fail closed')
  assert.equal(resTrace.failedStage, 'transcript_integrity')
  assert.match(resTrace.reason, /Host signature verification failed.*terminal proofReceipt browser trace/)
})

// ============================================================================
// Bug 3: VerifyRpcServer scrubs catch-block errors & applies generic redact()
// ============================================================================

async function rpcCall(
  socketPath: string,
  token: string,
  nonce: string,
  op: string,
  args: Record<string, unknown>,
): Promise<{ ok: boolean; result?: unknown; error?: string }> {
  const body = JSON.stringify({ op, args })
  return new Promise((resolve, reject) => {
    const req = httpRequest({
      socketPath,
      path: '/rpc',
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        'content-length': Buffer.byteLength(body),
        [VERIFY_RPC_HEADER]: token,
        [VERIFY_NONCE_HEADER]: nonce,
      },
    }, res => {
      const chunks: Buffer[] = []
      res.on('data', c => chunks.push(c as Buffer))
      res.on('end', () => resolve(JSON.parse(Buffer.concat(chunks).toString('utf8'))))
    })
    req.on('error', reject)
    req.end(body)
  })
}

test('Bug 3: VerifyRpcServer scrubs handle()/handleBrowser() errors and generic secrets in chainId and headers', async () => {
  const PERSONA_SECRET = 'psec_ultra_private_q36_847291'
  const BEARER_TOKEN = 'Bearer tok_q36_raw_bearer_99887766'
  const API_KEY = 'sk-proj-q36RawApiKeySecret987654321'
  const JWT_SECRET = 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhZG1pbiIsInJvbGUiOiJvd25lciJ9.q36RawSignatureVal99'

  const target = createServer((req: IncomingMessage, res: ServerResponse) => {
    res.writeHead(200, { 'content-type': 'application/json' })
    res.end(JSON.stringify({ ok: true, path: req.url ?? '/' }))
  })
  await new Promise<void>(r => target.listen(0, '127.0.0.1', r))
  const port = (target.address() as { port: number }).port
  const targetOrigin = `http://127.0.0.1:${port}`

  const persona: ResolvedPersona = {
    id: 'p-member-alpha',
    handle: 'member_alpha',
    roleLabel: 'member (org-alpha)',
    originAllowlist: [targetOrigin],
    authKind: 'header',
    headerName: 'X-Session-Auth',
    secret: PERSONA_SECRET,
    canaryMarkers: [],
  }
  const grant: Grant = {
    origin: targetOrigin,
    canRead: origin => origin === targetOrigin,
    isStateChangeApproved: () => true,
    audit: () => {},
    allowLocalLab: true,
    allowedPorts: [port],
    maxRpsPerOrigin: 200,
    tier: 3,
    personas: new Map([['member_alpha', persona]]),
  }
  const nonce = 'nonce-q36-rpc-scrub-001'
  const rpc = new VerifyRpcServer({
    runId: 'run-q36-scrub',
    assignmentId: 'assign-q36-scrub',
    nonce,
    grant,
    broker: new RequestBroker({ transportConfig: { http2: false } }),
    targetOrigins: [targetOrigin],
    browser: {
      async open() {
        throw new Error(`Browser nav error leaking ${PERSONA_SECRET} and ${BEARER_TOKEN} and ${API_KEY}`)
      },
    },
  })
  const started = await rpc.start()
  try {
    const assertNoRawSecrets = (payload: unknown, label: string) => {
      const text = JSON.stringify(payload)
      for (const secret of [PERSONA_SECRET, 'tok_q36_raw_bearer_99887766', API_KEY, JWT_SECRET]) {
        assert.equal(text.includes(secret), false, `${label} leaked raw secret (${secret.slice(0, 12)})`)
      }
    }

    // (a) handle() catch block: parseCapabilityArg() throws BEFORE handleHttp's try/catch
    const capErr1 = await rpcCall(started.socketPath, started.token, nonce, 'http.send', {
      path: '/api/check',
      capability: { handle: `${PERSONA_SECRET} ${BEARER_TOKEN} ${API_KEY}` },
    })
    assert.equal(capErr1.ok, false)
    assertNoRawSecrets(capErr1, 'http.send capability parse error')

    // (b) handleBrowser() catch block: error in RPC reply AND recorded transcript entry must be scrubbed
    const browserErr = await rpcCall(started.socketPath, started.token, nonce, 'browser', {
      path: `/page?leak=${API_KEY}`,
    })
    assert.equal(browserErr.ok, false)
    assertNoRawSecrets(browserErr, 'browser catch RPC error')
    assertNoRawSecrets(rpc.transcript.list(), 'browser catch transcript record')

    // (c) Non-auth request headers containing generic Bearer / API key / JWT must be scrubbed in transcript & transcript.get
    const sendOk = await rpcCall(started.socketPath, started.token, nonce, 'http.send', {
      path: '/api/echo',
      method: 'GET',
      headers: {
        'X-Debug-Note': BEARER_TOKEN,
        'X-Trace-Meta': API_KEY,
        'X-Correlation-Info': JWT_SECRET,
      },
    })
    assert.equal(sendOk.ok, true, sendOk.error ?? 'http.send failed')
    const exId = (sendOk.result as { exchangeId: string }).exchangeId
    const txGet = await rpcCall(started.socketPath, started.token, nonce, 'transcript', {
      action: 'get',
      exchangeId: exId,
    })
    assert.equal(txGet.ok, true)
    assertNoRawSecrets(txGet, 'transcript.get non-auth headers')
    assertNoRawSecrets(rpc.transcript.get(exId), 'TranscriptStore stored non-auth headers')

    // (d) composite.verify with generic API key / Bearer token embedded in chainId must be scrubbed in response AND store
    const compRes = await rpcCall(started.socketPath, started.token, nonce, 'composite.verify', {
      chainId: `chain-${API_KEY}`,
      terminalVulnClass: `cls-${JWT_SECRET}`,
      hops: [{
        hopId: 'hop_1',
        surface: 'http',
        target: { origin: targetOrigin, method: 'GET', pathAndQuery: '/api/echo' },
        exchangeIds: [exId],
        claimedDelta: `Delta with ${BEARER_TOKEN}`,
      }],
      causalEdges: [],
      terminalImpact: {
        terminalHopId: 'hop_1',
        summary: `Summary containing ${API_KEY} and ${BEARER_TOKEN}`,
      },
    })
    assertNoRawSecrets(compRes, 'composite.verify response')
    assertNoRawSecrets(rpc.transcript.latestCompositeVerification(), 'TranscriptStore composite verification')
  } finally {
    await rpc.close()
    await new Promise<void>(r => target.close(() => r()))
  }
})

// ============================================================================
// Bug 4: verifyScript() MUST redact secrets in title, claimTitle, disagreements, and errors
// ============================================================================

test('Bug 4: verifyScript redacts Bearer/API-key/JWT tokens in parsed.title, claimTitle, disagreements, and errors', async () => {
  const BEARER = 'Bearer q36_title_secret_bearer_556677'
  const API_KEY = 'sk-ant-q36TitleSecretKey9988776655'
  const JWT = 'eyJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjoidGl0bGVfbGVhayJ9.q36TitleJwtSig9988'
  const NEEDLES = ['q36_title_secret_bearer_556677', API_KEY, JWT]

  const makeMockSession = (title: string, nonce: string, extra?: { exitCode?: number; invalidDoc?: boolean }) => {
    const transcript = new TranscriptStore()
    const ctrl = transcript.record({
      op: 'http', startedAt: 1000, durationMs: 5,
      request: { origin: ORIGIN, method: 'GET', pathAndQuery: '/api/items/1', headers: {}, bodyBytes: 0, bodySha256: sha256Hex(''), personaHandle: 'member_alpha', sessionRole: 'control', nonce },
      response: { status: 403, headers: {}, bodyBytes: 20, bodySha256: sha256Hex('{"error":"denied"}'), mediaType: 'application/json' },
      body: '{"error":"denied"}',
    })
    const probe = transcript.record({
      op: 'http', startedAt: 1100, durationMs: 5,
      request: { origin: ORIGIN, method: 'GET', pathAndQuery: '/api/items/1', headers: {}, bodyBytes: 0, bodySha256: sha256Hex(''), personaHandle: 'member_alpha', sessionRole: 'probe', nonce },
      response: { status: 200, headers: {}, bodyBytes: 42, bodySha256: sha256Hex('{"id":1,"tenantId":"org-beta","ok":true}'), mediaType: 'application/json' },
      body: '{"id":1,"tenantId":"org-beta","ok":true}',
    })
    return {
      nonce,
      transcript,
      async execute() {
        return {
          result: extra?.invalidDoc
            ? { title, claims: [] }
            : {
                title,
                nonce,
                claims: [{
                  kind: 'boundary',
                  boundaryClass: 'access',
                  controlExchangeId: ctrl.exchangeId,
                  probeExchangeId: probe.exchangeId,
                  expectControlDenied: true,
                }],
              },
          stdout: '',
          stderr: '',
          exitCode: extra?.exitCode ?? 0,
          durationMs: 10,
        }
      },
      async close() { /* noop */ },
    }
  }

  const assertZeroTitleLeaks = (verdict: unknown, label: string) => {
    const serialized = JSON.stringify(verdict)
    for (const needle of NEEDLES) {
      assert.equal(serialized.includes(needle), false, `${label} leaked secret (${needle.slice(0, 12)})`)
    }
  }

  // (a) Matching titles with raw secrets -> claimTitle and attempts[].title must be redacted
  const sameVerdict = await verifyScript({
    candidate: { name: 'q36-title-same', runtime: 'ts', code: 'export default async () => {}' },
    openAttempt: async ({ nonce }) =>
      makeMockSession(`Access bypass using ${BEARER} and ${API_KEY} and ${JWT}`, nonce),
  })
  assert.equal(sameVerdict.confirmed, true, `expected confirmed verdict: ${sameVerdict.detail}`)
  assertZeroTitleLeaks(sameVerdict, 'matching titles verdict')
  assert.ok(sameVerdict.claimTitle?.includes('[redacted]'), 'claimTitle must contain [redacted] placeholder')

  // (b) Diverging titles with raw secrets -> disagreements, claimTitle, and attempts[].title must ALL be redacted
  const diffVerdict = await verifyScript({
    candidate: { name: 'q36-title-diff', runtime: 'ts', code: 'export default async () => {}' },
    openAttempt: async ({ attempt, nonce }) =>
      makeMockSession(
        attempt === 1
          ? `Alpha finding with ${BEARER} and ${API_KEY}`
          : `Beta finding with ${JWT}`,
        nonce,
      ),
  })
  assert.equal(diffVerdict.confirmed, false)
  assert.equal(diffVerdict.reason, 'transcript_mismatch')
  assert.ok(diffVerdict.disagreements.length > 0)
  assertZeroTitleLeaks(diffVerdict, 'diverging titles verdict')

  // (c) Invalid proof document with raw secret in rawTitle -> redacted
  const invalidVerdict = await verifyScript({
    candidate: { name: 'q36-title-invalid', runtime: 'ts', code: 'export default async () => {}' },
    openAttempt: async ({ nonce }) =>
      makeMockSession(`Broken proof leaking ${BEARER} and ${API_KEY}`, nonce, { invalidDoc: true }),
  })
  assert.equal(invalidVerdict.confirmed, false)
  assertZeroTitleLeaks(invalidVerdict, 'invalid proof document verdict')

  // (d) Attempt startup error containing raw secret -> redacted in failures & missingEvidence
  const startErrVerdict = await verifyScript({
    candidate: { name: 'q36-start-err', runtime: 'ts', code: 'export default async () => {}' },
    openAttempt: async () => {
      throw new Error(`Startup error leaking ${BEARER} and ${API_KEY}`)
    },
  })
  assert.equal(startErrVerdict.confirmed, false)
  assertZeroTitleLeaks(startErrVerdict, 'startup error verdict')
})

// ============================================================================
// Invariants: LOC ceilings & zero v8 benchmark contamination
// ============================================================================

test('LOC ceilings hold (composite-receipt <= 750, verify-rpc <= 2300) with zero v8 contamination', () => {
  const files: Array<[string, number | null]> = [
    ['src/server/composite-receipt.ts', 750],
    ['src/server/verify-rpc.ts', 2300],
    ['src/server/v8-oracle-hydrate.ts', null],
    ['src/server/verify-runner.ts', null],
    ['tests/v8-q36-soundness-fixes.test.ts', null],
  ]
  for (const [rel, maxLoc] of files) {
    const content = readFileSync(rel, 'utf8')
    const lines = content.split('\n').length
    if (maxLoc !== null) {
      assert.ok(lines <= maxLoc, `${rel} exceeded LOC ceiling: ${lines} > ${maxLoc}`)
    }
    const hits = scanTextForContamination(content, rel)
    assert.deepEqual(hits, [], `${rel} contains v8 contamination hits: ${JSON.stringify(hits)}`)
  }
})
