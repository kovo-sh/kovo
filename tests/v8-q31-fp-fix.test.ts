/**
 * Regression suite for v8 Q31 (`verify-claims.ts` causalFingerprints + `derived-custody.ts` LOC budget):
 *
 *  1. `jsonpath` with `equals === undefined` (exists/matches/presence) fingerprints
 *     `{ passed, exists, valueType }` so dynamic balances, counters, timestamps, or freshly
 *     minted IDs agree across two independently passing fresh runs, while type mismatches or
 *     oracle failures still fail closed.
 *  2. `jsonpath` with `equals !== undefined` keeps normalized observed value comparison.
 *  3. `structural_diff` fingerprints `{ passed, separated, minRounds }` rather than raw
 *     drifting token deltas/similarity floats.
 *  4. `body_contains` fingerprints `{ passed, absent }` rather than raw body slices.
 *  5. End-to-end `verifyScript` confirms dual passing runs and still rejects when one run fails.
 */
import test from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'

import { TranscriptStore, causalFingerprints } from '../src/server/verify-claims.ts'
import type { VerifyClaimCheck } from '../src/server/verify-claims.ts'
import { verifyScript } from '../src/server/verify-runner.ts'
import type { AttemptExecution, VerifyAttemptSession } from '../src/server/verify-runner.ts'

function recordHttp(
  store: TranscriptStore,
  input: { method: string; pathAndQuery: string; status: number; body: string; nonce: string },
) {
  return store.record({
    op: 'http',
    startedAt: Date.now(),
    durationMs: 3,
    request: {
      origin: 'http://127.0.0.1:9999',
      method: input.method,
      pathAndQuery: input.pathAndQuery,
      headers: {},
      bodyBytes: 0,
      bodySha256: 'req000',
      nonce: input.nonce,
    },
    response: {
      status: input.status,
      mediaType: 'application/json',
      headers: { 'content-type': 'application/json' },
      bodyBytes: Buffer.byteLength(input.body),
      bodySha256: `sha_${input.status}_${Buffer.byteLength(input.body)}_${input.pathAndQuery}`,
    },
    body: input.body,
  })
}

function makeMockOpenAttempt(
  runFn: (transcript: TranscriptStore, attempt: 1 | 2, nonce: string) => AttemptExecution,
) {
  return async ({ attempt, nonce }: { attempt: 1 | 2; nonce: string }): Promise<VerifyAttemptSession> => {
    const transcript = new TranscriptStore()
    return {
      nonce,
      transcript,
      async execute() { return runFn(transcript, attempt, nonce) },
      async close() { /* no-op */ },
    }
  }
}

const dummyCandidate = {
  name: 'q31-fp-fix.ts',
  runtime: 'ts' as const,
  code: '// mock',
  title: 'Q31 fingerprint regression',
}

test('jsonpath without equals fingerprints { passed, exists, valueType } and agrees across dynamic balances/counters/tokens', () => {
  const s1 = new TranscriptStore()
  const s2 = new TranscriptStore()
  const r1 = recordHttp(s1, { method: 'GET', pathAndQuery: '/api/accounts/acc_101', status: 200, body: '{"balance":1000,"counter":1,"items":["a","b"],"token":"tok_alpha"}', nonce: 'n1' })
  const r2 = recordHttp(s2, { method: 'GET', pathAndQuery: '/api/accounts/acc_202', status: 200, body: '{"balance":2000,"counter":2,"items":["x","y","z"],"token":"tok_beta"}', nonce: 'n2' })

  const fpNum1 = causalFingerprints(s1, [{
    claim: { kind: 'jsonpath', exchangeId: r1.exchangeId, path: 'balance', exists: true },
    passed: true,
    detail: 'balance exists',
    observed: { value: 1000 },
  }], 'n1')[0]!
  const fpNum2 = causalFingerprints(s2, [{
    claim: { kind: 'jsonpath', exchangeId: r2.exchangeId, path: 'balance', exists: true },
    passed: true,
    detail: 'balance exists',
    observed: { value: 2000 },
  }], 'n2')[0]!
  assert.deepEqual(fpNum1, fpNum2)
  assert.deepEqual(fpNum1.observed, { passed: true, exists: true, valueType: 'number' })

  const fpRegex1 = causalFingerprints(s1, [{
    claim: { kind: 'jsonpath', exchangeId: r1.exchangeId, path: 'token', matches: '^tok_' },
    passed: true,
    detail: 'token matches',
    observed: { value: 'tok_alpha' },
  }], 'n1')[0]!
  const fpRegex2 = causalFingerprints(s2, [{
    claim: { kind: 'jsonpath', exchangeId: r2.exchangeId, path: 'token', matches: '^tok_' },
    passed: true,
    detail: 'token matches',
    observed: { value: 'tok_beta' },
  }], 'n2')[0]!
  assert.deepEqual(fpRegex1, fpRegex2)
  assert.deepEqual(fpRegex1.observed, { passed: true, exists: true, valueType: 'string' })

  const fpArr1 = causalFingerprints(s1, [{
    claim: { kind: 'jsonpath', exchangeId: r1.exchangeId, path: 'items', exists: true },
    passed: true,
    detail: 'items exists',
    observed: { value: ['a', 'b'] },
  }], 'n1')[0]!
  const fpArr2 = causalFingerprints(s2, [{
    claim: { kind: 'jsonpath', exchangeId: r2.exchangeId, path: 'items', exists: true },
    passed: true,
    detail: 'items exists',
    observed: { value: ['x', 'y', 'z'] },
  }], 'n2')[0]!
  assert.deepEqual(fpArr1, fpArr2)
  assert.deepEqual(fpArr1.observed, { passed: true, exists: true, valueType: 'array' })

  // Type drift (number vs string) MUST still disagree.
  const fpWrongType = causalFingerprints(s2, [{
    claim: { kind: 'jsonpath', exchangeId: r2.exchangeId, path: 'balance', exists: true },
    passed: true,
    detail: 'balance exists',
    observed: { value: '2000' },
  }], 'n2')[0]!
  assert.notDeepEqual(fpNum1, fpWrongType)

  // Missing value reports exists=false, valueType='null'.
  const fpMissing = causalFingerprints(s1, [{
    claim: { kind: 'jsonpath', exchangeId: r1.exchangeId, path: 'secret', exists: false },
    passed: true,
    detail: 'secret missing',
    observed: { value: null },
  }], 'n1')[0]!
  assert.deepEqual(fpMissing.observed, { passed: true, exists: false, valueType: 'null' })
})

test('jsonpath WITH equals keeps normalized observed value comparison', () => {
  const s1 = new TranscriptStore()
  const s2 = new TranscriptStore()
  const r1 = recordHttp(s1, { method: 'GET', pathAndQuery: '/api/status', status: 200, body: '{"role":"admin"}', nonce: 'n1' })
  const r2 = recordHttp(s2, { method: 'GET', pathAndQuery: '/api/status', status: 200, body: '{"role":"member"}', nonce: 'n2' })

  const fpAdmin = causalFingerprints(s1, [{
    claim: { kind: 'jsonpath', exchangeId: r1.exchangeId, path: 'role', equals: 'admin' },
    passed: true,
    detail: 'role matches',
    observed: { value: 'admin' },
  }], 'n1')[0]!
  const fpMember = causalFingerprints(s2, [{
    claim: { kind: 'jsonpath', exchangeId: r2.exchangeId, path: 'role', equals: 'admin' },
    passed: false,
    detail: 'role differs',
    observed: { value: 'member' },
  }], 'n2')[0]!
  assert.deepEqual(fpAdmin.observed, { value: 'admin' })
  assert.deepEqual(fpMember.observed, { value: 'member' })
  assert.notDeepEqual(fpAdmin, fpMember)
})

test('structural_diff and body_contains fingerprint structural summaries instead of drifting tokens or body slices', () => {
  const s1 = new TranscriptStore()
  const s2 = new TranscriptStore()
  const v1 = recordHttp(s1, { method: 'GET', pathAndQuery: '/api/search?q=one', status: 200, body: '{"hits":["item-a"]}', nonce: 'n1' })
  const v2 = recordHttp(s2, { method: 'GET', pathAndQuery: '/api/search?q=two', status: 200, body: '{"hits":["item-b","item-c"]}', nonce: 'n2' })

  const sdCheck1: VerifyClaimCheck = {
    claim: { kind: 'structural_diff', controlIds: ['c1', 'c2', 'c3'], variantIds: [v1.exchangeId, 'v1b', 'v1c'], minRounds: 3 },
    passed: true,
    detail: 'diff ok',
    observed: { stableDelta: ['tok_a', 'tok_b'], similarity: 0.6123, rounds: 3, stableControl: true, stableVariant: true },
  }
  const sdCheck2: VerifyClaimCheck = {
    claim: { kind: 'structural_diff', controlIds: ['d1', 'd2', 'd3'], variantIds: [v2.exchangeId, 'v2b', 'v2c'], minRounds: 3 },
    passed: true,
    detail: 'diff ok',
    observed: { stableDelta: ['tok_x', 'tok_y', 'tok_z'], similarity: 0.7841, rounds: 4, stableControl: true, stableVariant: true },
  }
  const sdFp1 = causalFingerprints(s1, [sdCheck1], 'n1')[0]!
  const sdFp2 = causalFingerprints(s2, [sdCheck2], 'n2')[0]!
  assert.deepEqual(sdFp1, sdFp2)
  assert.deepEqual(sdFp1.observed, { passed: true, separated: true, minRounds: 3 })

  // Failing structural_diff disagrees with passing one.
  const sdFail = causalFingerprints(s2, [{ ...sdCheck2, passed: false }], 'n2')[0]!
  assert.deepEqual(sdFail.observed, { passed: false, separated: false, minRounds: 3 })
  assert.notDeepEqual(sdFp1, sdFail)

  // body_contains ignores raw body slices in observed while preserving passed + absent.
  const bcFp1 = causalFingerprints(s1, [{
    claim: { kind: 'body_contains', exchangeId: v1.exchangeId, text: 'marker' },
    passed: true,
    detail: 'present',
    observed: { snippet: 'run-1 balance=1000 marker ...' },
  }], 'n1')[0]!
  const bcFp2 = causalFingerprints(s2, [{
    claim: { kind: 'body_contains', exchangeId: v2.exchangeId, text: 'marker' },
    passed: true,
    detail: 'present',
    observed: { snippet: 'run-2 balance=2000 marker ...' },
  }], 'n2')[0]!
  assert.deepEqual(bcFp1, bcFp2)
  assert.deepEqual(bcFp1.observed, { passed: true, absent: false })

  const bcAbsent = causalFingerprints(s2, [{
    claim: { kind: 'body_contains', exchangeId: v2.exchangeId, text: 'marker', absent: true },
    passed: true,
    detail: 'absent',
  }], 'n2')[0]!
  assert.deepEqual(bcAbsent.observed, { passed: true, absent: true })
  assert.notDeepEqual(bcFp1, bcAbsent)
})

test('verifyScript confirms dual fresh runs with dynamic jsonpath/structural_diff/body_contains and fails closed if one run fails', async () => {
  const verdict = await verifyScript({
    candidate: dummyCandidate,
    openAttempt: makeMockOpenAttempt((transcript, attempt, nonce) => {
      const id = attempt === 1 ? 'acc_101' : 'acc_202'
      const balance = attempt === 1 ? 1000 : 2500
      const controls = [0, 1, 2].map(i => recordHttp(transcript, {
        method: 'GET', pathAndQuery: `/api/items/${id}?r=${i}`, status: 200,
        body: `{"items":["base"],"balance":${balance},"marker":"ok"}`, nonce,
      }).exchangeId)
      const variants = [0, 1, 2].map(i => recordHttp(transcript, {
        method: 'GET', pathAndQuery: `/api/items/${id}?r=${i}&extra=1`, status: 200,
        body: attempt === 1
          ? `{"items":["base","extra_alpha"],"balance":${balance},"marker":"ok"}`
          : `{"items":["base","extra_beta","extra_gamma"],"balance":${balance},"marker":"ok"}`,
        nonce,
      }).exchangeId)
      return {
        result: {
          sdk: 'kovo_verify.ts',
          nonce,
          title: `Account ${id} dynamic verification`,
          claims: [
            { kind: 'jsonpath', exchangeId: variants[0]!, path: 'balance', exists: true },
            { kind: 'structural_diff', controlIds: controls, variantIds: variants, minRounds: 3 },
            { kind: 'body_contains', exchangeId: variants[0]!, text: 'ok' },
          ],
        },
        stdout: '',
        stderr: '',
        exitCode: 0,
        durationMs: 6,
      }
    }),
  })
  assert.equal(verdict.confirmed, true, `expected confirmed=true, got ${verdict.reason}: ${verdict.detail} (${verdict.disagreements.join('; ')})`)
  assert.equal(verdict.reason, 'confirmed')
  assert.deepEqual(verdict.disagreements, [])

  // Fail closed if Run 2 fails a host oracle check!
  const oneFails = await verifyScript({
    candidate: dummyCandidate,
    openAttempt: makeMockOpenAttempt((transcript, attempt, nonce) => {
      const ex = recordHttp(transcript, {
        method: 'GET', pathAndQuery: '/api/items/acc_101', status: 200,
        body: attempt === 1 ? '{"balance":1000,"marker":"ok"}' : '{"marker":"missing_balance"}',
        nonce,
      })
      return {
        result: {
          sdk: 'kovo_verify.ts',
          nonce,
          title: 'Account balance check',
          claims: [
            { kind: 'jsonpath', exchangeId: ex.exchangeId, path: 'balance', exists: true },
            { kind: 'body_contains', exchangeId: ex.exchangeId, text: 'ok' },
          ],
        },
        stdout: '',
        stderr: '',
        exitCode: 0,
        durationMs: 5,
      }
    }),
  })
  assert.equal(oneFails.confirmed, false)
  assert.equal(oneFails.reason, 'oracle_failed')
})

test('LOC budgets: verify-claims.ts <= 2300 and derived-custody.ts <= 645', () => {
  const vcLines = readFileSync(new URL('../src/server/verify-claims.ts', import.meta.url), 'utf8').trimEnd().split('\n').length
  const dcLines = readFileSync(new URL('../src/server/derived-custody.ts', import.meta.url), 'utf8').trimEnd().split('\n').length
  assert.ok(vcLines <= 2300, `verify-claims.ts is ${vcLines} LOC (> 2300)`)
  assert.ok(dcLines <= 645, `derived-custody.ts is ${dcLines} LOC (> 645)`)
})
