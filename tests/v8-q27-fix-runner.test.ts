/**
 * Regression suite for v8 Q27 Defect #1 (`verify-runner.ts`):
 *  1. Clean exit (0) with 0 claims + host-recorded capability/crypto/async-poll ops
 *     returns `confirmed: false`, `reason: 'checkpoint_only'`, `rejectedBy: 'checkpoint'`,
 *     `missingEvidence: ['composite_receipt']`, and an actionable next-step hint listing
 *     the sealed capability handles (both unit and end-to-end via `VerifyRpcServer`).
 *  2. Non-zero exit or `result.error` maps `rejectedBy` to `'execution'` (never `'claims'`)
 *     with the real execution/RPC error detail (even if a capability was sealed earlier).
 *  3. Failed `latestCompositeVerification` ALWAYS takes precedence over checkpoint/execution/claims.
 *  4. Plain zero-claim runs (and forged stdout/result claims without host transcript ops)
 *     still fail closed as `claims_missing` + `rejectedBy: 'claims'`.
 */
import test from 'node:test'
import assert from 'node:assert/strict'
import { createServer } from 'node:http'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

import { TranscriptStore } from '../src/server/verify-claims.ts'
import { verifyScript } from '../src/server/verify-runner.ts'
import type { AttemptExecution, VerifyAttemptSession, VerifyReason } from '../src/server/verify-runner.ts'
import { createLocalAttemptFactory } from '../src/server/verify-rpc.ts'
import { RequestBroker } from '../src/server/broker.ts'
import type { Grant } from '../src/server/broker.ts'
import type { ResolvedPersona } from '../src/server/persona-vault.ts'
import { summarizeGuardianVerifyOutcome } from '../src/server/agent-prompts.ts'

process.env.GUARDIAN_ALLOW_LOCAL_LAB = '1'

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const SDK_DIR = join(REPO_ROOT, 'worker/guardian_verify')

function makeMockOpenAttempt(
  populate: (transcript: TranscriptStore, attempt: 1 | 2, nonce: string) => void,
  executeFn: (attempt: 1 | 2, nonce: string) => AttemptExecution,
) {
  return async ({ attempt, nonce }: { attempt: 1 | 2; nonce: string }): Promise<VerifyAttemptSession> => {
    const transcript = new TranscriptStore()
    populate(transcript, attempt, nonce)
    return {
      nonce,
      transcript,
      async execute() {
        return executeFn(attempt, nonce)
      },
      async close() { /* no-op */ },
    }
  }
}

const dummyCandidate = {
  name: 'checkpoint.ts',
  runtime: 'ts' as const,
  code: '// mock',
  title: 'Checkpoint probe',
}

test('VerifyReason union includes checkpoint_only', () => {
  const r: VerifyReason = 'checkpoint_only'
  assert.equal(r, 'checkpoint_only')
})

test('clean exit (0) with 0 claims and host-sealed capability returns checkpoint_only with sealed handle hint', async () => {
  const verdict = await verifyScript({
    candidate: dummyCandidate,
    openAttempt: makeMockOpenAttempt(
      (transcript, _attempt, nonce) => {
        transcript.record({
          op: 'capability',
          startedAt: Date.now(),
          durationMs: 2,
          request: {
            origin: 'http://127.0.0.1:9999',
            method: 'SEAL',
            pathAndQuery: '/capability/seal/signing_key',
            headers: {},
            bodyBytes: 0,
            bodySha256: 'abc123',
            nonce,
          },
          artifact: {
            kind: 'capability',
            capabilityHandle: 'cap:hop_1:signing_key',
            artifactDigest: 'abc123',
          },
        })
      },
      (_attempt, nonce) => ({
        result: { sdk: 'guardian_verify.ts', nonce, title: 'Hop 1 seal', claims: [] },
        stdout: 'guardian_verify: 0 transcript-backed claim(s) recorded\n',
        stderr: '',
        exitCode: 0,
        durationMs: 12,
      }),
    ),
  })

  assert.equal(verdict.confirmed, false, 'checkpoint_only must NEVER confirm')
  assert.equal(verdict.reason, 'checkpoint_only')
  assert.equal(verdict.rejectedBy, 'checkpoint')
  assert.deepEqual(verdict.missingEvidence, ['composite_receipt'])
  assert.equal(verdict.claimTitle, 'Hop 1 seal')
  assert.match(verdict.detail, /cap:hop_1:signing_key/)
  assert.match(verdict.detail, /ctx\.prove_composite/)
  assert.ok(verdict.usageHint && verdict.usageHint.includes('cap:hop_1:signing_key'))
  assert.match(verdict.usageHint, /ctx\.prove_composite/)

  const summary = summarizeGuardianVerifyOutcome(verdict)
  assert.equal(summary.confirmed, false)
  assert.equal(summary.reason, 'checkpoint_only')
  assert.equal(summary.rejectedBy, 'checkpoint')
  assert.deepEqual(summary.missingEvidence, ['composite_receipt'])
  assert.match(summary.detail, /cap:hop_1:signing_key/)
  assert.match(summary.failures.join(' '), /cap:hop_1:signing_key/)
})

test('clean exit (0) with 0 claims and crypto / async_poll / extended host ops returns checkpoint_only', async () => {
  // (a) JWT crypto op with derivedCapabilityId
  const jwtVerdict = await verifyScript({
    candidate: dummyCandidate,
    openAttempt: makeMockOpenAttempt(
      (transcript, _attempt, nonce) => {
        transcript.record({
          op: 'crypto',
          startedAt: Date.now(),
          durationMs: 1,
          request: {
            origin: 'http://127.0.0.1:9999',
            method: 'JWT_SIGN',
            pathAndQuery: '/crypto/jwt/HS256',
            headers: {},
            bodyBytes: 0,
            bodySha256: 'def456',
            derivedFromCapabilityId: 'cap:hop_1:hmac_secret',
            nonce,
          },
          artifact: {
            kind: 'crypto',
            derivedFromCapabilityId: 'cap:hop_1:hmac_secret',
            derivedCapabilityId: 'cap:hop_2:jwt_token',
            alg: 'HS256',
            artifactDigest: 'def456',
          },
        })
      },
      (_attempt, nonce) => ({
        result: { sdk: 'guardian_verify.ts', nonce, claims: [] },
        stdout: '',
        stderr: '',
        exitCode: 0,
        durationMs: 5,
      }),
    ),
  })
  assert.equal(jwtVerdict.confirmed, false)
  assert.equal(jwtVerdict.reason, 'checkpoint_only')
  assert.equal(jwtVerdict.rejectedBy, 'checkpoint')
  assert.deepEqual(jwtVerdict.missingEvidence, ['composite_receipt'])
  assert.match(jwtVerdict.detail, /cap:hop_2:jwt_token/)

  // (b) HMAC crypto op only (no newly sealed handle)
  const hmacVerdict = await verifyScript({
    candidate: dummyCandidate,
    openAttempt: makeMockOpenAttempt(
      (transcript, _attempt, nonce) => {
        transcript.record({
          op: 'crypto',
          startedAt: Date.now(),
          durationMs: 1,
          request: {
            origin: 'http://127.0.0.1:9999',
            method: 'HMAC_SIGN',
            pathAndQuery: '/crypto/hmac/sha256',
            headers: {},
            bodyBytes: 10,
            bodySha256: 'aaa111',
            derivedFromCapabilityId: 'cap:hop_1:hmac_secret',
            nonce,
          },
          artifact: {
            kind: 'crypto',
            derivedFromCapabilityId: 'cap:hop_1:hmac_secret',
            alg: 'sha256',
            artifactDigest: 'bbb222',
          },
        })
      },
      (_attempt, nonce) => ({
        result: { sdk: 'guardian_verify.ts', nonce, claims: [] },
        stdout: '',
        stderr: '',
        exitCode: 0,
        durationMs: 5,
      }),
    ),
  })
  assert.equal(hmacVerdict.confirmed, false)
  assert.equal(hmacVerdict.reason, 'checkpoint_only')
  assert.equal(hmacVerdict.rejectedBy, 'checkpoint')
  assert.deepEqual(hmacVerdict.missingEvidence, ['composite_receipt'])
  assert.match(hmacVerdict.detail, /crypto op/i)
  assert.match(hmacVerdict.detail, /ctx\.prove_composite/)

  // (c) async_poll op
  const pollVerdict = await verifyScript({
    candidate: dummyCandidate,
    openAttempt: makeMockOpenAttempt(
      (transcript, _attempt, nonce) => {
        transcript.record({
          op: 'async_poll',
          startedAt: Date.now(),
          durationMs: 150,
          request: {
            origin: 'http://127.0.0.1:9999',
            method: 'POLL',
            pathAndQuery: '/api/jobs/1',
            headers: {},
            bodyBytes: 0,
            bodySha256: 'ccc333',
            nonce,
          },
          artifact: {
            kind: 'async_poll',
            pollRecordId: 'poll-1',
            converged: true,
            tTriggerMs: 1000,
            tObservedMs: 1150,
          },
        })
      },
      (_attempt, nonce) => ({
        result: { sdk: 'guardian_verify.ts', nonce, claims: [] },
        stdout: '',
        stderr: '',
        exitCode: 0,
        durationMs: 160,
      }),
    ),
  })
  assert.equal(pollVerdict.confirmed, false)
  assert.equal(pollVerdict.reason, 'checkpoint_only')
  assert.equal(pollVerdict.rejectedBy, 'checkpoint')
  assert.deepEqual(pollVerdict.missingEvidence, ['composite_receipt'])
  assert.match(pollVerdict.detail, /async poll/i)

  // (d) extended transcript fields (capabilitiesSealed / polls)
  const extVerdict = await verifyScript({
    candidate: dummyCandidate,
    openAttempt: makeMockOpenAttempt(
      (transcript) => {
        Object.assign(transcript as unknown as Record<string, unknown>, { capabilitiesSealed: 1, polls: [{ id: 'p-1' }] })
      },
      (_attempt, nonce) => ({
        result: { sdk: 'guardian_verify.ts', nonce, claims: [] },
        stdout: '',
        stderr: '',
        exitCode: 0,
        durationMs: 5,
      }),
    ),
  })
  assert.equal(extVerdict.confirmed, false)
  assert.equal(extVerdict.reason, 'checkpoint_only')
  assert.equal(extVerdict.rejectedBy, 'checkpoint')
  assert.deepEqual(extVerdict.missingEvidence, ['composite_receipt'])
})

test('plain zero-claim run (and forged stdout without host transcript ops) still fails closed as claims_missing + rejectedBy=claims', async () => {
  const verdict = await verifyScript({
    candidate: dummyCandidate,
    openAttempt: makeMockOpenAttempt(
      (transcript, _attempt, nonce) => {
        transcript.record({
          op: 'http',
          startedAt: Date.now(),
          durationMs: 4,
          request: {
            origin: 'http://127.0.0.1:9999',
            method: 'GET',
            pathAndQuery: '/api/health',
            headers: {},
            bodyBytes: 0,
            bodySha256: 'e3b0',
            nonce,
          },
          response: {
            status: 200,
            headers: {},
            bodyBytes: 12,
            bodySha256: '1234',
            mediaType: 'application/json',
          },
        })
      },
      (_attempt, nonce) => ({
        result: { sdk: 'guardian_verify.ts', nonce, claims: [], sealedCapabilities: ['cap:hop_1:forged'] },
        stdout: 'Checkpoint saved (sealed: cap:hop_1:forged)\n',
        stderr: '',
        exitCode: 0,
        durationMs: 8,
      }),
    ),
  })

  assert.equal(verdict.confirmed, false)
  assert.equal(verdict.reason, 'claims_missing')
  assert.equal(verdict.rejectedBy, 'claims')
  assert.deepEqual(verdict.missingEvidence, ['valid_proof_document'])
})

test('non-zero exit or result.error maps rejectedBy to execution with real error detail (even after sealing a capability)', async () => {
  // (a) Non-zero exit after sealing a capability -> execution error, NOT checkpoint_only or claims
  const crashAfterSeal = await verifyScript({
    candidate: dummyCandidate,
    openAttempt: makeMockOpenAttempt(
      (transcript, _attempt, nonce) => {
        transcript.record({
          op: 'capability',
          startedAt: Date.now(),
          durationMs: 1,
          request: {
            origin: 'http://127.0.0.1:9999',
            method: 'SEAL',
            pathAndQuery: '/capability/seal/k1',
            headers: {},
            bodyBytes: 0,
            bodySha256: 'abc',
            nonce,
          },
          artifact: {
            kind: 'capability',
            capabilityHandle: 'cap:hop_1:k1',
            artifactDigest: 'abc',
          },
        })
      },
      (_attempt, nonce) => ({
        result: { sdk: 'guardian_verify.ts', nonce, error: 'RPC crypto.hmacSign requires secretHandle.', claims: [] },
        stdout: '',
        stderr: 'guardian_verify: RPC crypto.hmacSign requires secretHandle.\n',
        exitCode: 1,
        durationMs: 14,
      }),
    ),
  })
  assert.equal(crashAfterSeal.confirmed, false)
  assert.notEqual(crashAfterSeal.reason, 'checkpoint_only')
  assert.equal(crashAfterSeal.rejectedBy, 'execution')
  assert.deepEqual(crashAfterSeal.missingEvidence, ['script_completion'])
  assert.equal(crashAfterSeal.exitCode, 1)
  assert.match(crashAfterSeal.stderrPreview ?? '', /crypto\.hmacSign requires secretHandle/)
  assert.match(crashAfterSeal.attempts[0].failures.join(' '), /crypto\.hmacSign requires secretHandle/)

  // (b) Exit code 0 with explicit result.error -> execution error, NOT checkpoint_only or claims
  const resultErrorOnly = await verifyScript({
    candidate: dummyCandidate,
    openAttempt: makeMockOpenAttempt(
      (transcript, _attempt, nonce) => {
        transcript.record({
          op: 'capability',
          startedAt: Date.now(),
          durationMs: 1,
          request: {
            origin: 'http://127.0.0.1:9999',
            method: 'SEAL',
            pathAndQuery: '/capability/seal/k2',
            headers: {},
            bodyBytes: 0,
            bodySha256: 'def',
            nonce,
          },
          artifact: {
            kind: 'capability',
            capabilityHandle: 'cap:hop_1:k2',
            artifactDigest: 'def',
          },
        })
      },
      (_attempt, nonce) => ({
        result: { sdk: 'guardian_verify.ts', nonce, error: 'RPC capability.seal failed: unsupported kind', claims: [] },
        stdout: '',
        stderr: '',
        exitCode: 0,
        durationMs: 9,
      }),
    ),
  })
  assert.equal(resultErrorOnly.confirmed, false)
  assert.notEqual(resultErrorOnly.reason, 'checkpoint_only')
  assert.equal(resultErrorOnly.rejectedBy, 'execution')
  assert.deepEqual(resultErrorOnly.missingEvidence, ['script_completion'])
  assert.match(resultErrorOnly.stderrPreview ?? '', /unsupported kind/)
  assert.match(resultErrorOnly.detail, /unsupported kind/)
  assert.match(resultErrorOnly.attempts[0].failures.join(' '), /unsupported kind/)

  // (c) Script with valid claims that exits non-zero -> reason='execution_failed', rejectedBy='execution'
  const claimThenCrash = await verifyScript({
    candidate: dummyCandidate,
    openAttempt: makeMockOpenAttempt(
      (transcript, _attempt, nonce) => {
        const rec = transcript.record({
          op: 'http',
          startedAt: Date.now(),
          durationMs: 2,
          request: {
            origin: 'http://127.0.0.1:9999',
            method: 'GET',
            pathAndQuery: '/api/item',
            headers: {},
            bodyBytes: 0,
            bodySha256: 'e3b0',
            nonce,
          },
          response: {
            status: 200,
            headers: {},
            bodyBytes: 2,
            bodySha256: '4413',
            mediaType: 'application/json',
          },
        })
        Object.assign(transcript as unknown as Record<string, unknown>, { _lastExId: rec.exchangeId })
      },
      (_attempt, nonce) => ({
        result: {
          sdk: 'guardian_verify.ts',
          nonce,
          title: 'crashed cleanup',
          claims: [{ kind: 'status', exchangeId: 'gx-nonexistent', expected: 200 }],
        },
        stdout: '',
        stderr: 'cleanup boom\n',
        exitCode: 2,
        durationMs: 11,
      }),
    ),
  })
  assert.equal(claimThenCrash.confirmed, false)
  assert.equal(claimThenCrash.reason, 'execution_failed')
  assert.equal(claimThenCrash.exitCode, 2)
  assert.notEqual(claimThenCrash.rejectedBy, 'claims')
})

test('failed latestCompositeVerification ALWAYS takes precedence over checkpoint_only, execution, and claims', async () => {
  const populateFailedComposite = (transcript: TranscriptStore, _attempt: 1 | 2, nonce: string) => {
    transcript.record({
      op: 'capability',
      startedAt: Date.now(),
      durationMs: 1,
      request: {
        origin: 'http://127.0.0.1:9999',
        method: 'SEAL',
        pathAndQuery: '/capability/seal/tok',
        headers: {},
        bodyBytes: 0,
        bodySha256: 'abc',
        nonce,
      },
      artifact: {
        kind: 'capability',
        capabilityHandle: 'cap:hop_1:tok',
        artifactDigest: 'abc',
      },
    })
    transcript.recordCompositeVerification({
      chainId: 'chain-1',
      terminalVulnClass: 'cross_tenant_read',
      replayMode: 'fresh_clean_replay',
      hopCount: 2,
      confirmed: false,
      verifiedEdgeCount: 0,
      reason: 'Edge hop_1 -> hop_2 missing consumed capability attestation.',
      failedStage: 'edge_binding',
      rejectedBy: 'edge_binding',
      missingEvidence: ['causal_edge_hop_1_to_hop_2'],
      exchangeIds: [],
    })
  }

  // (a) Clean exit 0 with 0 claims + sealed cap + failed composite -> oracle_failed + edge_binding
  const compClean = await verifyScript({
    candidate: dummyCandidate,
    openAttempt: makeMockOpenAttempt(
      populateFailedComposite,
      (_attempt, nonce) => ({
        result: { sdk: 'guardian_verify.ts', nonce, title: 'Composite attempt', claims: [] },
        stdout: '',
        stderr: '',
        exitCode: 0,
        durationMs: 20,
      }),
    ),
  })
  assert.equal(compClean.confirmed, false)
  assert.equal(compClean.reason, 'oracle_failed')
  assert.equal(compClean.rejectedBy, 'edge_binding')
  assert.deepEqual(compClean.missingEvidence, ['causal_edge_hop_1_to_hop_2'])

  // (b) Non-zero exit + result.error + failed composite -> still preserves edge_binding + missingEvidence
  const compWithExit = await verifyScript({
    candidate: dummyCandidate,
    openAttempt: makeMockOpenAttempt(
      populateFailedComposite,
      (_attempt, nonce) => ({
        result: { sdk: 'guardian_verify.ts', nonce, error: 'AssertionError: composite rejected', claims: [] },
        stdout: '',
        stderr: 'AssertionError: composite rejected\n',
        exitCode: 1,
        durationMs: 20,
      }),
    ),
  })
  assert.equal(compWithExit.confirmed, false)
  assert.equal(compWithExit.rejectedBy, 'edge_binding')
  assert.deepEqual(compWithExit.missingEvidence, ['causal_edge_hop_1_to_hop_2'])
})

test('end-to-end with real VerifyRpcServer + TS SDK: seal-only script returns checkpoint_only, RPC error script returns rejectedBy=execution', async t => {
  const server = createServer((req, res) => {
    if (req.url === '/api/bootstrap') {
      const payload = JSON.stringify({ bootstrapToken: 'ephemeral-bootstrap-val-12345' })
      res.writeHead(200, { 'content-type': 'application/json', 'content-length': Buffer.byteLength(payload) })
      res.end(payload)
      return
    }
    res.writeHead(404)
    res.end('not found')
  })
  await new Promise<void>(resolveReady => server.listen(0, '127.0.0.1', resolveReady))
  t.after(() => server.close())
  const addr = server.address()
  assert.ok(addr && typeof addr === 'object')
  const origin = `http://127.0.0.1:${addr.port}`

  const testerPersona: ResolvedPersona = {
    id: 'persona-tester',
    handle: 'tester',
    roleLabel: 'tester (orgA)',
    originAllowlist: [origin],
    authKind: 'header',
    headerName: 'X-User',
    secret: 'tester-secret-token',
    canaryMarkers: [],
  }
  const grant: Grant = {
    origin,
    tier: 2,
    allowLocalLab: true,
    allowedPorts: [addr.port],
    maxRpsPerOrigin: 100,
    personas: new Map<string, ResolvedPersona>([['tester', testerPersona]]),
    canRead: candidate => candidate === origin,
    audit: () => {},
  }

  const makeFactory = () => createLocalAttemptFactory({
    sdkDir: SDK_DIR,
    createRpcOptions(nonce) {
      return {
        broker: new RequestBroker({ rejectUnauthorized: false }),
        grant,
        runId: `run-q27-${nonce.slice(0, 8)}`,
        assignmentId: 'assignment-q27-runner',
        targetOrigins: [origin],
      }
    },
  })

  // 1. Real TS script that seals a capability and exits cleanly without prove_composite
  const sealOnly = await verifyScript({
    candidate: {
      name: 'seal-only.ts',
      runtime: 'ts',
      title: 'Hop 1 capability seal checkpoint',
      code: `
const r = await ctx.http('/api/bootstrap', { as: 'tester', role: 'probe' })
await ctx.seal_capability({ exchangeId: r.exchangeId, slot: 'bootstrap_tok', hopReceiptId: '1', jsonPath: '$.bootstrapToken', kind: 'api_token' })
return ctx.result({ title: 'Hop 1 capability seal checkpoint' })
`,
    },
    openAttempt: makeFactory(),
  })
  assert.equal(sealOnly.confirmed, false, 'seal-only checkpoint must not confirm')
  assert.equal(
    sealOnly.reason,
    'checkpoint_only',
    `expected checkpoint_only, got ${sealOnly.reason} (rejectedBy=${sealOnly.rejectedBy}, exitCode=${sealOnly.exitCode}, detail=${sealOnly.detail}, stderr=${sealOnly.stderrPreview ?? ''})`,
  )
  assert.equal(sealOnly.rejectedBy, 'checkpoint')
  assert.deepEqual(sealOnly.missingEvidence, ['composite_receipt'])
  assert.match(sealOnly.detail, /cap:hop_1:bootstrap_tok/)
  assert.match(sealOnly.detail, /ctx\.prove_composite/)
  assert.ok(sealOnly.usageHint && sealOnly.usageHint.includes('cap:hop_1:bootstrap_tok'))

  // 2. Real TS script that triggers a host RPC error -> rejectedBy='execution' with real error detail
  const rpcFail = await verifyScript({
    candidate: {
      name: 'rpc-error.ts',
      runtime: 'ts',
      title: 'Bad HMAC call',
      code: `
await ctx.hmac_sign({ secretHandle: '', payload: 'hello' })
return ctx.result({ title: 'Bad HMAC call' })
`,
    },
    openAttempt: makeFactory(),
  })
  assert.equal(rpcFail.confirmed, false)
  assert.equal(rpcFail.rejectedBy, 'execution')
  assert.equal(rpcFail.exitCode, 1)
  assert.match(rpcFail.stderrPreview ?? '', /secretHandle/i)
  assert.match(rpcFail.attempts[0].failures.join(' '), /secretHandle/i)
})
