/**
 * Round-4 WS-2 Proof Kernel Regression & Class-Level Guards:
 *  - R4-C-1: `boolean` and `status_differential` receipt rules require host-minted stamped
 *            `hostBooleanPair` metadata with equal-length, same-character-multiset invariants
 *            and byte-for-byte request-parameter binding; unminted worker-chosen triangles reject.
 *  - R4-C-2: Non-transferable per-exchange `hostExpressionChallenge` stamps (transcript-wide
 *            challenge fallback deleted) + shared per-component fail-closed carrier normalizer
 *            (malformed percent-escapes, tag-stripped / zero-width / NFKC / ordered-digit echoes)
 *            enforced identically across `proof-receipt.ts` and `verify-claims.ts`.
 *  - R4-C-6: `signed_url_mint` receipt & composite-claim hardening: same-persona Variant A,
 *            traversal/separator input binding, host/bucket non-evidence, 401/403-only Variant B
 *            control (never 400 validation error), and fail-closed both-arm echo check (malformed
 *            percent-escapes & JSON unicode escapes).
 *  - R4-H-7: `auth_bypass` anonymous self-sabotage guard (control may never carry a credential
 *            real or synthetic that probe lacks), synthetic invalid credentials restricted strictly
 *            to probe arm, and mandatory denied bare anonymous ablation arm.
 */
import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import test from 'node:test'
import { HostFactLog } from '../src/server/host-fact-log.ts'
import type { ImpactStep } from '../src/server/oracle-invariants.ts'
import {
  HostMintedOracle,
  buildProofReceipt,
  defaultHostMintedOracle,
  normalizeRequestCarrier,
  verifyHostExpressionProbe,
  verifyReceipt,
  verifySignedUrlMintPair,
  type ReceiptTranscript,
  type ReceiptTranscriptEntry,
} from '../src/server/proof-receipt.ts'
import { TranscriptStore, evaluateClaim, evaluateClaims } from '../src/server/verify-claims.ts'

const ORIGIN = 'https://qa-target.example.invalid'

const sha256 = (s: string): string => createHash('sha256').update(s, 'utf8').digest('hex')
const hexSig = (seed: string): string => createHash('sha256').update(seed, 'utf8').digest('hex')

function mkStep(overrides: Partial<ImpactStep> & Pick<ImpactStep, 'id' | 'arm' | 'method' | 'status'>): ImpactStep {
  return {
    route: overrides.route ?? (overrides.pathAndQuery ?? '/').split('?')[0] ?? '/',
    pathAndQuery: overrides.pathAndQuery ?? overrides.route ?? '/',
    actor: { handle: null, role: null, tenant: null, auth: 'unknown', sameSite: null },
    ...overrides,
  }
}

// ============================================================================
// 1. R4-C-1: Mandatory host-minted stamped boolean pairs on boolean & status_differential
// ============================================================================

test('R4-C-1: HostMintedOracle.mintBooleanPair enforces non-empty base, equal length, and identical char multiset', () => {
  const oracle = new HostMintedOracle()
  assert.throws(() => oracle.mintBooleanPair(''), /non-empty baseValue/i)
  assert.throws(() => oracle.mintBooleanPair('   '), /non-empty baseValue/i)

  for (const style of ['numeric', 'single_quote', 'double_quote'] as const) {
    const pair = oracle.mintBooleanPair('42', { style, param: 'id' })
    assert.equal(pair.trueValue.length, pair.falseValue.length, `${style}: equal length invariant`)
    assert.notEqual(pair.trueValue, pair.falseValue)
    assert.equal(
      [...pair.trueValue].sort().join(''),
      [...pair.falseValue].sort().join(''),
      `${style}: identical character multiset invariant`,
    )
    assert.ok(pair.trueValue.startsWith('42'))
    assert.ok(pair.falseValue.startsWith('42'))

    const trueStamp = oracle.stampBooleanPairArm(pair, 'true')
    const falseStamp = oracle.stampBooleanPairArm(pair, 'false')
    const baseStamp = oracle.stampBooleanPairArm(pair, 'baseline')
    assert.ok(oracle.verifyBooleanPair(trueStamp))
    assert.ok(oracle.verifyBooleanPair(falseStamp))
    assert.ok(oracle.verifyBooleanPair(baseStamp))

    // Tampering with mintedValue or unknown challengeId fails closed
    assert.equal(oracle.verifyBooleanPair({ ...trueStamp, mintedValue: `${trueStamp.mintedValue}0` }), null)
    assert.equal(oracle.verifyBooleanPair({ ...trueStamp, challengeId: 'bool_unregistered' }), null)
  }
})

test('R4-C-1: boolean and status_differential receipt rules reject unminted worker-chosen triangles and confirm host-stamped pairs', () => {
  const oracle = new HostMintedOracle()
  const boolReceipt = buildProofReceipt({
    vulnClass: 'boolean_differential',
    target: { origin: ORIGIN, method: 'GET', pathAndQuery: '/api/items?id=1', param: 'id' },
    exchangeIds: ['b1', 'c1', 'p1', 'b2', 'c2', 'p2'],
    claimedDelta: 'Paired boolean differential across two rounds.',
  })

  // Negative 1: Worker-chosen unminted boolean triangle (no hostBooleanPair stamp) -> REJECT
  const unmintedBool = verifyReceipt(boolReceipt, {
    entries: [
      { exchangeId: 'b1', origin: ORIGIN, evidenceRole: 'benign_baseline', step: mkStep({ id: 'b1', arm: 'control', method: 'GET', route: '/api/items', pathAndQuery: '/api/items?id=1', status: 200, json: { item: { id: 1 } } }) },
      { exchangeId: 'c1', origin: ORIGIN, step: mkStep({ id: 'c1', arm: 'control', method: 'GET', route: '/api/items', pathAndQuery: `/api/items?id=${encodeURIComponent('1 AND 1=1')}`, status: 200, json: { item: { id: 1 } } }) },
      { exchangeId: 'p1', origin: ORIGIN, step: mkStep({ id: 'p1', arm: 'probe', method: 'GET', route: '/api/items', pathAndQuery: `/api/items?id=${encodeURIComponent('1 AND 1=10')}`, status: 200, json: { item: null } }) },
      { exchangeId: 'b2', origin: ORIGIN, evidenceRole: 'benign_baseline', step: mkStep({ id: 'b2', arm: 'control', method: 'GET', route: '/api/items', pathAndQuery: '/api/items?id=1', status: 200, json: { item: { id: 1 } } }) },
      { exchangeId: 'c2', origin: ORIGIN, step: mkStep({ id: 'c2', arm: 'control', method: 'GET', route: '/api/items', pathAndQuery: `/api/items?id=${encodeURIComponent('1 AND 2=2')}`, status: 200, json: { item: { id: 1 } } }) },
      { exchangeId: 'p2', origin: ORIGIN, step: mkStep({ id: 'p2', arm: 'probe', method: 'GET', route: '/api/items', pathAndQuery: `/api/items?id=${encodeURIComponent('1 AND 2=20')}`, status: 200, json: { item: null } }) },
    ],
  }, { hostMintedOracle: oracle })
  assert.equal(unmintedBool.confirmed, false, 'unminted boolean differential triangle must be rejected')
  assert.match(unmintedBool.reason, /R4-C-1|hostBooleanPair/i)

  // Negative 2: Worker-chosen unminted status_differential triangle -> REJECT
  const statusReceipt = buildProofReceipt({
    vulnClass: 'sqli_status',
    target: { origin: ORIGIN, method: 'GET', pathAndQuery: '/api/items?id=1', param: 'id' },
    exchangeIds: ['sb1', 'st1', 'sf1', 'sb2', 'st2', 'sf2'],
    claimedDelta: 'Status differential across two rounds.',
  })
  const unmintedStatus = verifyReceipt(statusReceipt, {
    entries: [
      { exchangeId: 'sb1', origin: ORIGIN, evidenceRole: 'benign_baseline', step: mkStep({ id: 'sb1', arm: 'control', method: 'GET', route: '/api/items', pathAndQuery: '/api/items?id=1', status: 200, evidenceRole: 'benign_baseline', body: '{"id":1}' }) },
      { exchangeId: 'st1', origin: ORIGIN, evidenceRole: 'tautology', step: mkStep({ id: 'st1', arm: 'probe', method: 'GET', route: '/api/items', pathAndQuery: `/api/items?id=${encodeURIComponent('1 AND 1=1')}`, status: 200, evidenceRole: 'tautology', body: '{"id":1}' }) },
      { exchangeId: 'sf1', origin: ORIGIN, evidenceRole: 'contradiction', step: mkStep({ id: 'sf1', arm: 'probe', method: 'GET', route: '/api/items', pathAndQuery: `/api/items?id=${encodeURIComponent('1 AND 1=2')}`, status: 404, evidenceRole: 'contradiction', body: '{"error":"not_found"}' }) },
      { exchangeId: 'sb2', origin: ORIGIN, evidenceRole: 'benign_baseline', step: mkStep({ id: 'sb2', arm: 'control', method: 'GET', route: '/api/items', pathAndQuery: '/api/items?id=1', status: 200, evidenceRole: 'benign_baseline', body: '{"id":1}' }) },
      { exchangeId: 'st2', origin: ORIGIN, evidenceRole: 'tautology', step: mkStep({ id: 'st2', arm: 'probe', method: 'GET', route: '/api/items', pathAndQuery: `/api/items?id=${encodeURIComponent('1 AND 2=2')}`, status: 200, evidenceRole: 'tautology', body: '{"id":1}' }) },
      { exchangeId: 'sf2', origin: ORIGIN, evidenceRole: 'contradiction', step: mkStep({ id: 'sf2', arm: 'probe', method: 'GET', route: '/api/items', pathAndQuery: `/api/items?id=${encodeURIComponent('1 AND 2=3')}`, status: 404, evidenceRole: 'contradiction', body: '{"error":"not_found"}' }) },
    ],
  }, { hostMintedOracle: oracle })
  assert.equal(unmintedStatus.confirmed, false, 'unminted status_differential triangle must be rejected')
  assert.match(unmintedStatus.reason, /R4-C-1|hostBooleanPair/i)

  // Negative 3: Stamped pair with cross-status-class false arm (400) on `boolean` rule -> REJECT
  const pair1 = oracle.mintBooleanPair('1', { param: 'id', style: 'numeric' })
  const pair2 = oracle.mintBooleanPair('1', { param: 'id', style: 'numeric' })
  const crossStatusBool = verifyReceipt(boolReceipt, {
    entries: [
      { exchangeId: 'b1', origin: ORIGIN, evidenceRole: 'benign_baseline', hostBooleanPair: oracle.stampBooleanPairArm(pair1, 'baseline'), step: mkStep({ id: 'b1', arm: 'control', method: 'GET', route: '/api/items', pathAndQuery: `/api/items?id=${encodeURIComponent(pair1.baseValue)}`, status: 200, json: { item: { id: 1 } } }) },
      { exchangeId: 'c1', origin: ORIGIN, hostBooleanPair: oracle.stampBooleanPairArm(pair1, 'true'), step: mkStep({ id: 'c1', arm: 'control', method: 'GET', route: '/api/items', pathAndQuery: `/api/items?id=${encodeURIComponent(pair1.trueValue)}`, status: 200, json: { item: { id: 1 } } }) },
      { exchangeId: 'p1', origin: ORIGIN, hostBooleanPair: oracle.stampBooleanPairArm(pair1, 'false'), step: mkStep({ id: 'p1', arm: 'probe', method: 'GET', route: '/api/items', pathAndQuery: `/api/items?id=${encodeURIComponent(pair1.falseValue)}`, status: 400, json: { error: 'validation_failed' } }) },
      { exchangeId: 'b2', origin: ORIGIN, evidenceRole: 'benign_baseline', hostBooleanPair: oracle.stampBooleanPairArm(pair2, 'baseline'), step: mkStep({ id: 'b2', arm: 'control', method: 'GET', route: '/api/items', pathAndQuery: `/api/items?id=${encodeURIComponent(pair2.baseValue)}`, status: 200, json: { item: { id: 1 } } }) },
      { exchangeId: 'c2', origin: ORIGIN, hostBooleanPair: oracle.stampBooleanPairArm(pair2, 'true'), step: mkStep({ id: 'c2', arm: 'control', method: 'GET', route: '/api/items', pathAndQuery: `/api/items?id=${encodeURIComponent(pair2.trueValue)}`, status: 200, json: { item: { id: 1 } } }) },
      { exchangeId: 'p2', origin: ORIGIN, hostBooleanPair: oracle.stampBooleanPairArm(pair2, 'false'), step: mkStep({ id: 'p2', arm: 'probe', method: 'GET', route: '/api/items', pathAndQuery: `/api/items?id=${encodeURIComponent(pair2.falseValue)}`, status: 400, json: { error: 'validation_failed' } }) },
    ],
  }, { hostMintedOracle: oracle })
  assert.equal(crossStatusBool.confirmed, false, '4xx false arm on boolean rule must be rejected')

  // Negative 4: Stamped pair whose request parameter was swapped by worker (byte-for-byte mismatch) -> REJECT
  const swappedParamBool = verifyReceipt(boolReceipt, {
    entries: [
      { exchangeId: 'b1', origin: ORIGIN, evidenceRole: 'benign_baseline', hostBooleanPair: oracle.stampBooleanPairArm(pair1, 'baseline'), step: mkStep({ id: 'b1', arm: 'control', method: 'GET', route: '/api/items', pathAndQuery: `/api/items?id=${encodeURIComponent(pair1.baseValue)}`, status: 200, json: { item: { id: 1 } } }) },
      { exchangeId: 'c1', origin: ORIGIN, hostBooleanPair: oracle.stampBooleanPairArm(pair1, 'true'), step: mkStep({ id: 'c1', arm: 'control', method: 'GET', route: '/api/items', pathAndQuery: `/api/items?id=${encodeURIComponent(pair1.trueValue)}`, status: 200, json: { item: { id: 1 } } }) },
      { exchangeId: 'p1', origin: ORIGIN, hostBooleanPair: oracle.stampBooleanPairArm(pair1, 'false'), step: mkStep({ id: 'p1', arm: 'probe', method: 'GET', route: '/api/items', pathAndQuery: `/api/items?id=${encodeURIComponent('999 AND 1=2')}`, status: 200, json: { item: null } }) },
      { exchangeId: 'b2', origin: ORIGIN, evidenceRole: 'benign_baseline', hostBooleanPair: oracle.stampBooleanPairArm(pair2, 'baseline'), step: mkStep({ id: 'b2', arm: 'control', method: 'GET', route: '/api/items', pathAndQuery: `/api/items?id=${encodeURIComponent(pair2.baseValue)}`, status: 200, json: { item: { id: 1 } } }) },
      { exchangeId: 'c2', origin: ORIGIN, hostBooleanPair: oracle.stampBooleanPairArm(pair2, 'true'), step: mkStep({ id: 'c2', arm: 'control', method: 'GET', route: '/api/items', pathAndQuery: `/api/items?id=${encodeURIComponent(pair2.trueValue)}`, status: 200, json: { item: { id: 1 } } }) },
      { exchangeId: 'p2', origin: ORIGIN, hostBooleanPair: oracle.stampBooleanPairArm(pair2, 'false'), step: mkStep({ id: 'p2', arm: 'probe', method: 'GET', route: '/api/items', pathAndQuery: `/api/items?id=${encodeURIComponent(pair2.falseValue)}`, status: 200, json: { item: null } }) },
    ],
  }, { hostMintedOracle: oracle })
  assert.equal(swappedParamBool.confirmed, false, 'mismatched parameter vs stamped mintedValue must be rejected')

  // Positive: Properly host-stamped pairs confirm on both boolean and status_differential via HostFactLog
  const factLog = new HostFactLog()
  factLog.recordExchange({ seq: 1, exchangeId: 'b1', arm: 'control', evidenceRole: 'benign_baseline', hostBooleanPair: oracle.stampBooleanPairArm(pair1, 'baseline'), method: 'GET', origin: ORIGIN, pathAndQuery: `/api/items?id=${encodeURIComponent(pair1.baseValue)}`, status: 200, rawResponseBody: '{"item":{"id":1,"sku":"A"}}' })
  factLog.recordExchange({ seq: 2, exchangeId: 'c1', arm: 'control', hostBooleanPair: oracle.stampBooleanPairArm(pair1, 'true'), method: 'GET', origin: ORIGIN, pathAndQuery: `/api/items?id=${encodeURIComponent(pair1.trueValue)}`, status: 200, rawResponseBody: '{"item":{"id":1,"sku":"A"}}' })
  factLog.recordExchange({ seq: 3, exchangeId: 'p1', arm: 'probe', hostBooleanPair: oracle.stampBooleanPairArm(pair1, 'false'), method: 'GET', origin: ORIGIN, pathAndQuery: `/api/items?id=${encodeURIComponent(pair1.falseValue)}`, status: 200, rawResponseBody: '{"item":null,"matches":0}' })
  factLog.recordExchange({ seq: 4, exchangeId: 'b2', arm: 'control', evidenceRole: 'benign_baseline', hostBooleanPair: oracle.stampBooleanPairArm(pair2, 'baseline'), method: 'GET', origin: ORIGIN, pathAndQuery: `/api/items?id=${encodeURIComponent(pair2.baseValue)}`, status: 200, rawResponseBody: '{"item":{"id":1,"sku":"A"}}' })
  factLog.recordExchange({ seq: 5, exchangeId: 'c2', arm: 'control', hostBooleanPair: oracle.stampBooleanPairArm(pair2, 'true'), method: 'GET', origin: ORIGIN, pathAndQuery: `/api/items?id=${encodeURIComponent(pair2.trueValue)}`, status: 200, rawResponseBody: '{"item":{"id":1,"sku":"A"}}' })
  factLog.recordExchange({ seq: 6, exchangeId: 'p2', arm: 'probe', hostBooleanPair: oracle.stampBooleanPairArm(pair2, 'false'), method: 'GET', origin: ORIGIN, pathAndQuery: `/api/items?id=${encodeURIComponent(pair2.falseValue)}`, status: 200, rawResponseBody: '{"item":null,"matches":0}' })
  const validBool = verifyReceipt(boolReceipt, factLog.toReceiptTranscript(), { hostMintedOracle: oracle })
  assert.equal(validBool.confirmed, true, validBool.reason)
  assert.equal(validBool.evidence?.hostMinted, true)
})

// ============================================================================
// 2. R4-C-2: Non-transferable per-exchange hostExpressionChallenge + carrier anti-reflection
// ============================================================================

test('R4-C-2: worker-sent probes without per-exchange hostExpressionChallenge stamp are rejected in both verifyReceipt and evaluateClaim', () => {
  const oracle = new HostMintedOracle()
  const ch1 = oracle.mintExpressionChallenge('ssti')
  const ch2 = oracle.mintExpressionChallenge('ssti')

  const receipt = buildProofReceipt({
    vulnClass: 'ssti',
    target: { origin: ORIGIN, method: 'GET', pathAndQuery: '/api/render?name=benign' },
    exchangeIds: ['c1', 'p1', 'c2', 'p2'],
    claimedDelta: 'Claimed expression evaluation via worker-sent probes.',
  })

  // Transcript lists minted challenges, but probe entries have NO per-exchange hostExpressionChallenge stamp
  const workerSentTranscript: ReceiptTranscript = {
    hostExpressionChallenges: [ch1, ch2],
    entries: [
      { exchangeId: 'c1', origin: ORIGIN, step: mkStep({ id: 'c1', arm: 'control', method: 'GET', route: '/api/render', pathAndQuery: '/api/render?name=benign', status: 200, body: 'Hello benign' }) },
      { exchangeId: 'p1', origin: ORIGIN, step: mkStep({ id: 'p1', arm: 'probe', method: 'GET', route: '/api/render', pathAndQuery: `/api/render?name=${encodeURIComponent(`{{${ch1.expressionSyntax}}}`)}`, status: 200, body: `Hello ${ch1.expectedOutput}` }) },
      { exchangeId: 'c2', origin: ORIGIN, step: mkStep({ id: 'c2', arm: 'control', method: 'GET', route: '/api/render', pathAndQuery: '/api/render?name=benign', status: 200, body: 'Hello benign' }) },
      { exchangeId: 'p2', origin: ORIGIN, step: mkStep({ id: 'p2', arm: 'probe', method: 'GET', route: '/api/render', pathAndQuery: `/api/render?name=${encodeURIComponent(`{{${ch2.expressionSyntax}}}`)}`, status: 200, body: `Hello ${ch2.expectedOutput}` }) },
    ],
  }
  const receiptVerdict = verifyReceipt(receipt, workerSentTranscript, { hostMintedOracle: oracle })
  assert.equal(receiptVerdict.confirmed, false, 'worker-sent probe citing transcript-wide hostExpressionChallenges must be rejected')

  // Same check through evaluateClaim('host_evaluated_expression') using defaultHostMintedOracle
  const defCh = defaultHostMintedOracle.mintExpressionChallenge('ssti')
  const store = new TranscriptStore()
  const ctl = store.record({
    op: 'http', startedAt: 1000, durationMs: 5,
    request: { origin: ORIGIN, method: 'GET', pathAndQuery: '/api/render?name=benign', headers: {}, bodyBytes: 0, bodySha256: sha256(''), sessionRole: 'control', nonce: 'n1' },
    response: { status: 200, headers: {}, bodyBytes: 12, bodySha256: sha256('Hello benign'), mediaType: 'text/plain' },
    body: 'Hello benign',
  })
  const unstampedPrb = store.record({
    op: 'http', startedAt: 1010, durationMs: 5,
    request: { origin: ORIGIN, method: 'GET', pathAndQuery: `/api/render?name=${encodeURIComponent(`{{${defCh.expressionSyntax}}}`)}`, headers: {}, bodyBytes: 0, bodySha256: sha256(''), sessionRole: 'probe', nonce: 'n1' },
    response: { status: 200, headers: {}, bodyBytes: 20, bodySha256: sha256(`Hello ${defCh.expectedOutput}`), mediaType: 'text/plain' },
    body: `Hello ${defCh.expectedOutput}`,
  })
  const claimVerdict = evaluateClaim(store, {
    kind: 'host_evaluated_expression',
    controlIds: [ctl.exchangeId],
    probeIds: [unstampedPrb.exchangeId],
    hostMintedChallengeIds: [defCh.challengeId],
  }, {})
  assert.equal(claimVerdict.passed, false, 'evaluateClaim must reject worker-sent probe without per-exchange hostExpressionChallenge stamp')
})

test('R4-C-2: malformed percent-escape echo, tag-stripped echo, zero-width echo, NFKC echo, and JSON unicode echo all reject', () => {
  const oracle = new HostMintedOracle()
  const ch = oracle.mintExpressionChallenge('ssti')
  const digits = ch.expectedOutput.split('')

  // 1) Malformed percent-escape in sibling query param alongside percent-encoded expected output -> FAIL CLOSED
  const pctEncodedDigits = digits.map(d => `%${d.charCodeAt(0).toString(16)}`).join('')
  const malformedCheck = verifyHostExpressionProbe({
    probeRequest: {
      pathAndQuery: `/api/render?name=${encodeURIComponent(`{{${ch.expressionSyntax}}}`)}${pctEncodedDigits}&junk=%ZZ`,
    },
    probeBody: `Hello ${ch.expectedOutput}`,
    probeStatus: 200,
    controlBodies: ['Hello benign'],
    stampedChallenge: ch,
    oracle,
  })
  assert.equal(malformedCheck.ok, false, 'malformed percent-escape echo must fail closed')
  assert.match(malformedCheck.reason, /malformed/i)

  // 2) Tag-stripped reflection (digits split by empty inline markup tags) -> REJECT
  const tagSplit = `${digits[0]}<b>${digits[1]}</b><i>${digits.slice(2).join('')}</i>`
  const tagCheck = verifyHostExpressionProbe({
    probeRequest: {
      pathAndQuery: `/api/render?name=${encodeURIComponent(`{{${ch.expressionSyntax}}} ${tagSplit}`)}`,
    },
    probeBody: `Hello ${ch.expectedOutput}`,
    probeStatus: 200,
    controlBodies: ['Hello benign'],
    stampedChallenge: ch,
    oracle,
  })
  assert.equal(tagCheck.ok, false, 'tag-stripped expression echo must be rejected')

  // 3) Zero-width + non-digit character split reflection -> REJECT
  const zwSplit = digits.join('\u200b_')
  const zwCheck = verifyHostExpressionProbe({
    probeRequest: {
      pathAndQuery: `/api/render?name=${encodeURIComponent(`{{${ch.expressionSyntax}}} ${zwSplit}`)}`,
    },
    probeBody: `Hello ${ch.expectedOutput}`,
    probeStatus: 200,
    controlBodies: ['Hello benign'],
    stampedChallenge: ch,
    oracle,
  })
  assert.equal(zwCheck.ok, false, 'zero-width/non-digit split echo must be rejected')

  // 4) Fullwidth NFKC digits reflection -> REJECT
  const fullwidthDigits = digits.map(d => String.fromCharCode(0xff10 + Number(d))).join('')
  const nfkcCheck = verifyHostExpressionProbe({
    probeRequest: {
      pathAndQuery: `/api/render?name=${encodeURIComponent(`{{${ch.expressionSyntax}}} ${fullwidthDigits}`)}`,
    },
    probeBody: `Hello ${ch.expectedOutput}`,
    probeStatus: 200,
    controlBodies: ['Hello benign'],
    stampedChallenge: ch,
    oracle,
  })
  assert.equal(nfkcCheck.ok, false, 'NFKC fullwidth digit echo must be rejected')

  // 5) JSON unicode-escaped digits in request body -> REJECT (also verify via evaluateClaim!)
  const defCh = defaultHostMintedOracle.mintExpressionChallenge('ssti')
  const jsonUniDigits = defCh.expectedOutput.split('').map(d => `\\u00${d.charCodeAt(0).toString(16)}`).join('')
  const rawJsonBody = `{"template":"{{${defCh.expressionSyntax}}} ${jsonUniDigits}"}`
  const store = new TranscriptStore()
  const ctl = store.record({
    op: 'http', startedAt: 1000, durationMs: 5,
    request: { origin: ORIGIN, method: 'POST', pathAndQuery: '/api/render', headers: { 'content-type': 'application/json' }, bodyBytes: 18, bodySha256: sha256('{"template":"ok"}'), sessionRole: 'control', nonce: 'n1' },
    response: { status: 200, headers: {}, bodyBytes: 2, bodySha256: sha256('ok'), mediaType: 'text/plain' },
    body: 'ok',
    rawRequestBody: '{"template":"ok"}',
  })
  const uniPrb = store.record({
    op: 'http', startedAt: 1010, durationMs: 5,
    request: { origin: ORIGIN, method: 'POST', pathAndQuery: '/api/render', headers: { 'content-type': 'application/json' }, bodyBytes: rawJsonBody.length, bodySha256: sha256(rawJsonBody), sessionRole: 'probe', nonce: 'n1' },
    response: { status: 200, headers: {}, bodyBytes: 20, bodySha256: sha256(`Hello ${defCh.expectedOutput}`), mediaType: 'text/plain' },
    body: `Hello ${defCh.expectedOutput}`,
    rawRequestBody: rawJsonBody,
    hostExpressionChallenge: defCh,
  })
  const uniClaim = evaluateClaim(store, {
    kind: 'host_evaluated_expression',
    controlIds: [ctl.exchangeId],
    probeIds: [uniPrb.exchangeId],
    hostMintedChallengeIds: [defCh.challengeId],
  }, {})
  assert.equal(uniClaim.passed, false, 'JSON unicode-escaped expression echo must be rejected by evaluateClaim')

  // 6) Genuine non-reflected host-stamped expression probe -> PASS
  const cleanCheck = verifyHostExpressionProbe({
    probeRequest: {
      pathAndQuery: `/api/render?name=${encodeURIComponent(`{{${ch.expressionSyntax}}}`)}`,
    },
    probeBody: `Hello ${ch.expectedOutput}`,
    probeStatus: 200,
    controlBodies: ['Hello benign'],
    stampedChallenge: ch,
    oracle,
  })
  assert.equal(cleanCheck.ok, true, cleanCheck.reason)

  // Verify carrier normalizer handles clean Jinja percent-encoded query cleanly
  const cleanCarrier = normalizeRequestCarrier({
    pathAndQuery: `/api/render?name=${encodeURIComponent(`{% print ${ch.expressionSyntax} %}`)}`,
  })
  assert.equal(cleanCarrier.malformedEscape, false)
})

// ============================================================================
// 3. R4-C-6: signed_url_mint receipt & composite-claim hardening
// ============================================================================

test('R4-C-6: signed_url_mint rejects 400 validation control, cross-persona Variant A, benign two-folder presign, and malformed/JSON-unicode echo', () => {
  const sigCtl = hexSig('signed-ctl-1')
  const sigPrb = hexSig('signed-prb-1')
  const sasSig = Buffer.from(hexSig('azure-sas-write').slice(0, 48)).toString('base64url')

  const mkSignedReceipt = () => buildProofReceipt({
    vulnClass: 'signed_url_mint',
    target: { origin: ORIGIN, method: 'POST', pathAndQuery: '/api/presign' },
    exchangeIds: ['su-ctl', 'su-prb'],
    claimedDelta: 'Signed URL minting differential.',
  })

  // Negative 1: Variant B with 400 validation-error control -> REJECT (must be 401/403)
  const bad400Control = verifyReceipt(mkSignedReceipt(), {
    entries: [
      { exchangeId: 'su-ctl', origin: ORIGIN, step: mkStep({ id: 'su-ctl', arm: 'control', method: 'POST', route: '/api/presign', pathAndQuery: '/api/presign', status: 400, requestJson: {}, body: '{"error":"filename_required"}' }) },
      { exchangeId: 'su-prb', origin: ORIGIN, step: mkStep({ id: 'su-prb', arm: 'probe', method: 'POST', route: '/api/presign', pathAndQuery: '/api/presign', status: 200, requestJson: { filename: 'report.json' }, body: JSON.stringify({ uploadUrl: `https://acct.blob.core.windows.net/uploads/report.json?sv=2022-11-02&se=2026-11-27T00:00:00Z&sp=cw&sig=${sasSig}` }) }) },
    ],
  })
  assert.equal(bad400Control.confirmed, false, '400 validation-error control must not confirm signed_url_mint Variant B')
  assert.equal(bad400Control.evidence?.rejectedBy, 'signed_url_control_not_auth_denied')

  // Negative 2: Variant A cross-persona mismatch (alice vs bob) -> REJECT
  const crossPersona = verifyReceipt(mkSignedReceipt(), {
    entries: [
      { exchangeId: 'su-ctl', origin: ORIGIN, step: mkStep({ id: 'su-ctl', arm: 'control', method: 'POST', route: '/api/presign', pathAndQuery: '/api/presign', status: 200, actor: { handle: 'alice', role: 'member', tenant: 't1', auth: 'bearer', sameSite: null }, requestJson: { key: 'avatar.png' }, body: JSON.stringify({ url: `https://storage.googleapis.com/bucket/uploads/a/avatar.png?X-Goog-Algorithm=GOOG4-RSA-SHA256&X-Goog-Signature=${sigCtl}` }) }) },
      { exchangeId: 'su-prb', origin: ORIGIN, step: mkStep({ id: 'su-prb', arm: 'probe', method: 'POST', route: '/api/presign', pathAndQuery: '/api/presign', status: 200, actor: { handle: 'bob', role: 'member', tenant: 't1', auth: 'bearer', sameSite: null }, requestJson: { key: '../admin.json' }, body: JSON.stringify({ url: `https://storage.googleapis.com/bucket/uploads/admin.json?X-Goog-Algorithm=GOOG4-RSA-SHA256&X-Goog-Signature=${sigPrb}` }) }) },
    ],
  })
  assert.equal(crossPersona.confirmed, false, 'cross-persona Variant A must be rejected')
  assert.equal(crossPersona.evidence?.rejectedBy, 'signed_url_persona_mismatch')

  // Negative 3: Benign multi-folder presign (fileId=101 -> folderA, fileId=102 -> folderB, NO traversal construct) -> REJECT
  const benignMultiFolder = verifyReceipt(mkSignedReceipt(), {
    entries: [
      { exchangeId: 'su-ctl', origin: ORIGIN, step: mkStep({ id: 'su-ctl', arm: 'control', method: 'POST', route: '/api/presign', pathAndQuery: '/api/presign', status: 200, requestJson: { fileId: '101' }, body: JSON.stringify({ url: `https://storage.googleapis.com/bucket/folder-a/doc101.pdf?X-Goog-Algorithm=GOOG4-RSA-SHA256&X-Goog-Signature=${sigCtl}` }) }) },
      { exchangeId: 'su-prb', origin: ORIGIN, step: mkStep({ id: 'su-prb', arm: 'probe', method: 'POST', route: '/api/presign', pathAndQuery: '/api/presign', status: 200, requestJson: { fileId: '102' }, body: JSON.stringify({ url: `https://storage.googleapis.com/bucket/folder-b/doc102.pdf?X-Goog-Algorithm=GOOG4-RSA-SHA256&X-Goog-Signature=${sigPrb}` }) }) },
    ],
  })
  assert.equal(benignMultiFolder.confirmed, false, 'benign two-folder download presign without traversal input must be rejected')
  assert.equal(benignMultiFolder.evidence?.rejectedBy, 'signed_url_no_traversal_input')

  // Negative 4: Malformed percent-escape hiding echoed probe signature -> FAIL CLOSED
  const malformedEcho = verifyReceipt(
    buildProofReceipt({
      vulnClass: 'signed_url_mint',
      target: { origin: ORIGIN, method: 'GET', pathAndQuery: '/api/presign' },
      exchangeIds: ['su-ctl', 'su-prb'],
      claimedDelta: 'Echoed signed URL hidden behind malformed percent escape.',
    }),
    {
      entries: [
        { exchangeId: 'su-ctl', origin: ORIGIN, step: mkStep({ id: 'su-ctl', arm: 'control', method: 'GET', route: '/api/presign', pathAndQuery: '/api/presign?q=a', status: 200, body: JSON.stringify({ url: `https://storage.googleapis.com/bucket/uploads/a.png?X-Goog-Algorithm=GOOG4-RSA-SHA256&X-Goog-Signature=${sigCtl}` }) }) },
        { exchangeId: 'su-prb', origin: ORIGIN, step: mkStep({ id: 'su-prb', arm: 'probe', method: 'GET', route: '/api/presign', pathAndQuery: `/api/presign?q=${encodeURIComponent(`../x?X-Goog-Signature=${sigPrb}`)}&bad=%ZZ`, status: 200, body: JSON.stringify({ url: `https://storage.googleapis.com/bucket/x.png?X-Goog-Algorithm=GOOG4-RSA-SHA256&X-Goog-Signature=${sigPrb}` }) }) },
      ],
    },
  )
  assert.equal(malformedEcho.confirmed, false, 'malformed percent-escape in signed_url_mint must fail closed')
  assert.equal(malformedEcho.evidence?.rejectedBy, 'signed_url_malformed_request_carrier')

  // Negative 5: JSON unicode-escaped signature echoed in request body -> REJECT (both verifySignedUrlMintPair and composite_receipt claim)
  const uniSig = sigPrb.split('').map(c => `\\u00${c.charCodeAt(0).toString(16).padStart(2, '0')}`).join('')
  const rawUniProbeBody = `{"key":"../escape.json","mirror":"${uniSig}"}`
  const uniPairCheck = verifySignedUrlMintPair({
    control: {
      origin: ORIGIN, method: 'POST', pathAndQuery: '/api/presign', status: 200,
      requestBody: '{"key":"avatar.png"}',
      responseBody: JSON.stringify({ url: `https://storage.googleapis.com/bucket/uploads/avatar.png?X-Goog-Algorithm=GOOG4-RSA-SHA256&X-Goog-Signature=${sigCtl}` }),
    },
    probe: {
      origin: ORIGIN, method: 'POST', pathAndQuery: '/api/presign', status: 200,
      requestBody: rawUniProbeBody,
      responseBody: JSON.stringify({ url: `https://storage.googleapis.com/bucket/escape.json?X-Goog-Algorithm=GOOG4-RSA-SHA256&X-Goog-Signature=${sigPrb}` }),
    },
  })
  assert.equal(uniPairCheck.confirmed, false, 'JSON unicode-escaped signature echo must be rejected')
  assert.equal(uniPairCheck.rejectedBy, 'signed_url_echoed')

  // Negative 6: Control-arm echoed signature -> REJECT
  const ctlEcho = verifySignedUrlMintPair({
    control: {
      origin: ORIGIN, method: 'POST', pathAndQuery: '/api/presign', status: 200,
      requestBody: JSON.stringify({ key: 'avatar.png', mirror: sigCtl }),
      responseBody: JSON.stringify({ url: `https://storage.googleapis.com/bucket/uploads/avatar.png?X-Goog-Algorithm=GOOG4-RSA-SHA256&X-Goog-Signature=${sigCtl}` }),
    },
    probe: {
      origin: ORIGIN, method: 'POST', pathAndQuery: '/api/presign', status: 200,
      requestBody: JSON.stringify({ key: '../escape.json' }),
      responseBody: JSON.stringify({ url: `https://storage.googleapis.com/bucket/escape.json?X-Goog-Algorithm=GOOG4-RSA-SHA256&X-Goog-Signature=${sigPrb}` }),
    },
  })
  assert.equal(ctlEcho.confirmed, false, 'control-arm echoed signature must be rejected')
  assert.equal(ctlEcho.rejectedBy, 'signed_url_control_echoed')

  // Negative 7: verify-claims composite_receipt rejects 400-control signed_url_mint even if hostRec.confirmed was true
  const store = new TranscriptStore()
  const c400 = store.record({
    op: 'http', startedAt: 1000, durationMs: 5,
    request: { origin: ORIGIN, method: 'POST', pathAndQuery: '/api/upload-token', headers: {}, bodyBytes: 2, bodySha256: sha256('{}'), sessionRole: 'control', nonce: 'n1' },
    response: { status: 400, headers: {}, bodyBytes: 29, bodySha256: sha256('{"error":"filename_required"}'), mediaType: 'application/json' },
    body: '{"error":"filename_required"}',
    rawRequestBody: '{}',
  })
  const p200Body = JSON.stringify({ uploadUrl: `https://acct.blob.core.windows.net/uploads/report.json?sv=2022-11-02&se=2026-11-27T00:00:00Z&sp=cw&sig=${sasSig}` })
  const p200 = store.record({
    op: 'http', startedAt: 1010, durationMs: 5,
    request: { origin: ORIGIN, method: 'POST', pathAndQuery: '/api/upload-token', headers: {}, bodyBytes: 26, bodySha256: sha256('{"filename":"report.json"}'), sessionRole: 'probe', nonce: 'n1' },
    response: { status: 200, headers: {}, bodyBytes: p200Body.length, bodySha256: sha256(p200Body), mediaType: 'application/json' },
    body: p200Body,
    rawRequestBody: '{"filename":"report.json"}',
  })
  const compRec = store.recordCompositeVerification({
    chainId: 'signed_url_mint:unauth_write_mint',
    terminalVulnClass: 'signed_url_mint',
    replayMode: 'one_shot_transcript',
    hopCount: 1,
    confirmed: true,
    verifiedEdgeCount: 0,
    reason: 'pre-hardening positive record',
    rejectedBy: null,
    missingEvidence: [],
    exchangeIds: [c400.exchangeId, p200.exchangeId],
    terminalExchangeId: p200.exchangeId,
    route: '/api/upload-token',
  })
  const compClaim = evaluateClaims(store, [{
    kind: 'composite_receipt',
    verificationId: compRec.verificationId,
    chainId: compRec.chainId,
    terminalVulnClass: 'signed_url_mint',
    exchangeIds: [c400.exchangeId, p200.exchangeId],
  }])
  assert.equal(compClaim.passed, false, 'evaluateClaims must reject 400-control signed_url_mint composite_receipt')

  // Positive: Variant B with genuine 401 control + unauthenticated write-capable signed URL -> CONFIRM
  const valid401VariantB = verifyReceipt(mkSignedReceipt(), {
    entries: [
      { exchangeId: 'su-ctl', origin: ORIGIN, step: mkStep({ id: 'su-ctl', arm: 'control', method: 'POST', route: '/api/presign', pathAndQuery: '/api/presign', status: 401, requestJson: { filename: 'report.json' }, body: '{"error":"authentication_required"}' }) },
      { exchangeId: 'su-prb', origin: ORIGIN, step: mkStep({ id: 'su-prb', arm: 'probe', method: 'POST', route: '/api/presign', pathAndQuery: '/api/presign', status: 200, requestJson: { filename: 'report.json' }, body: JSON.stringify({ uploadUrl: `https://acct.blob.core.windows.net/uploads/report.json?sv=2022-11-02&se=2026-11-27T00:00:00Z&sp=cw&sig=${sasSig}` }) }) },
    ],
  })
  assert.equal(valid401VariantB.confirmed, true, valid401VariantB.reason)
})

// ============================================================================
// 4. R4-H-7: auth_bypass anonymous self-sabotage & mandatory anonymous ablation arm
// ============================================================================

test('R4-H-7: permit-all-returns-401-for-invalid-bearer auth_bypass stub rejects, while genuine anonymous-ablation auth_bypass confirms', () => {
  const receipt = buildProofReceipt({
    vulnClass: 'auth_bypass',
    target: { origin: ORIGIN, method: 'GET', pathAndQuery: '/api/public/items' },
    exchangeIds: ['ctl', 'prb'],
    claimedDelta: 'Claimed auth bypass via forwarding header against invalid-bearer 401 control.',
  })
  const publicListBody = '{"items":[{"id":"item-1","title":"Public Doc","owner":"catalog"}]}'

  // Negative 1: Control carries host-minted synthetic invalid Bearer (401), anonymous probe adds X-Forwarded-User (200) -> REJECT
  const synthBearerControl = verifyReceipt(receipt, {
    entries: [
      {
        exchangeId: 'ctl',
        origin: ORIGIN,
        wireCredentialProvenance: {
          authenticated: true,
          source: 'caller_self_minted',
          sources: ['caller_self_minted'],
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
        step: mkStep({
          id: 'ctl', arm: 'control', method: 'GET', route: '/api/public/items', pathAndQuery: '/api/public/items',
          status: 401, requestHeaders: { authorization: 'Bearer kovo-synth-invalid-deadbeef12345678' },
          body: '{"error":"invalid_token"}',
        }),
      },
      {
        exchangeId: 'prb',
        origin: ORIGIN,
        wireCredentialProvenance: {
          authenticated: false,
          source: 'none',
          sources: [],
          personaHandle: null,
          headerNames: [],
          vaultHeaderNames: [],
          callerAuthHeaderNames: [],
          cookieNames: [],
          vaultCookieNames: [],
          jarCookieNames: [],
          session: null,
          authMutated: false,
        },
        step: mkStep({
          id: 'prb', arm: 'probe', method: 'GET', route: '/api/public/items', pathAndQuery: '/api/public/items',
          status: 200, requestHeaders: { 'x-forwarded-user': 'admin' },
          body: publicListBody,
        }),
      },
    ],
  })
  assert.equal(synthBearerControl.confirmed, false, 'synthetic invalid bearer control + anonymous header probe MUST reject')
  assert.match(synthBearerControl.reason, /R4-H-7|self-sabotaged|synthetic invalid/i)

  // Negative 2: Control carries caller invalid Bearer (no authMutated flag) + anonymous probe adds X-Forwarded-User -> REJECT
  const plainBearerControl = verifyReceipt(receipt, {
    entries: [
      {
        exchangeId: 'ctl', origin: ORIGIN,
        step: mkStep({
          id: 'ctl', arm: 'control', method: 'GET', route: '/api/public/items', pathAndQuery: '/api/public/items',
          status: 401, requestHeaders: { authorization: 'Bearer expired.or.invalid.token' },
          body: '{"error":"invalid_token"}',
        }),
      },
      {
        exchangeId: 'prb', origin: ORIGIN,
        step: mkStep({
          id: 'prb', arm: 'probe', method: 'GET', route: '/api/public/items', pathAndQuery: '/api/public/items',
          status: 200, requestHeaders: { 'x-forwarded-user': 'admin' },
          body: publicListBody,
        }),
      },
    ],
  })
  assert.equal(plainBearerControl.confirmed, false, 'invalid bearer control + anonymous header probe MUST reject')
  assert.match(plainBearerControl.reason, /R4-H-7|self-sabotaged/i)

  // Negative 3: Control mutates same header (`x-forwarded-user: wrong` -> 401) vs `x-forwarded-user: admin` -> 200
  // WITHOUT any bare anonymous 401 ablation arm -> REJECT
  const missingAblation = verifyReceipt(receipt, {
    entries: [
      {
        exchangeId: 'ctl', origin: ORIGIN,
        step: mkStep({
          id: 'ctl', arm: 'control', method: 'GET', route: '/api/public/items', pathAndQuery: '/api/public/items',
          status: 401, requestHeaders: { 'x-forwarded-user': 'invalid-user' },
          body: '{"error":"unknown_forwarded_user"}',
        }),
      },
      {
        exchangeId: 'prb', origin: ORIGIN,
        step: mkStep({
          id: 'prb', arm: 'probe', method: 'GET', route: '/api/public/items', pathAndQuery: '/api/public/items',
          status: 200, requestHeaders: { 'x-forwarded-user': 'admin' },
          body: publicListBody,
        }),
      },
    ],
  })
  assert.equal(missingAblation.confirmed, false, 'missing denied bare anonymous ablation arm MUST reject')
  assert.match(missingAblation.reason, /ablation/i)

  // Negative 4: Transcript records a bare anonymous 200 on the same route (endpoint is permit-all) -> REJECT
  const permitAllInTranscript = verifyReceipt(receipt, {
    entries: [
      {
        exchangeId: 'anon-200', origin: ORIGIN,
        step: mkStep({
          id: 'anon-200', arm: 'setup', method: 'GET', route: '/api/public/items', pathAndQuery: '/api/public/items',
          status: 200, body: publicListBody,
        }),
      },
      {
        exchangeId: 'ctl', origin: ORIGIN,
        step: mkStep({
          id: 'ctl', arm: 'control', method: 'GET', route: '/api/public/items', pathAndQuery: '/api/public/items',
          status: 401, body: '{"error":"unauthorized"}',
        }),
      },
      {
        exchangeId: 'prb', origin: ORIGIN,
        step: mkStep({
          id: 'prb', arm: 'probe', method: 'GET', route: '/api/public/items', pathAndQuery: '/api/public/items',
          status: 200, requestHeaders: { 'x-forwarded-user': 'admin' },
          body: publicListBody,
        }),
      },
    ],
  })
  assert.equal(permitAllInTranscript.confirmed, false, 'bare anonymous 200 on same route proves permit-all and MUST reject')
  assert.match(permitAllInTranscript.reason, /permit-all|ablation/i)

  // Positive: Bare anonymous 401 ablation control + probe with synthetic invalid bearer -> CONFIRM
  const genuineEntries: ReceiptTranscriptEntry[] = [
    {
      exchangeId: 'ctl', origin: ORIGIN,
      wireCredentialProvenance: {
        authenticated: false, source: 'none', sources: [], personaHandle: null,
        headerNames: [], vaultHeaderNames: [], callerAuthHeaderNames: [], cookieNames: [], vaultCookieNames: [], jarCookieNames: [], session: null, authMutated: false,
      },
      step: mkStep({
        id: 'ctl', arm: 'control', method: 'GET', route: '/api/public/items', pathAndQuery: '/api/public/items',
        status: 401, body: '{"error":"authentication_required"}',
      }),
    },
    {
      exchangeId: 'prb', origin: ORIGIN,
      wireCredentialProvenance: {
        authenticated: true, source: 'caller_self_minted', sources: ['caller_self_minted'], personaHandle: null,
        headerNames: ['authorization'], vaultHeaderNames: [], callerAuthHeaderNames: ['authorization'], cookieNames: [], vaultCookieNames: [], jarCookieNames: [], session: null, authMutated: true,
      },
      step: mkStep({
        id: 'prb', arm: 'probe', method: 'GET', route: '/api/public/items', pathAndQuery: '/api/public/items',
        status: 200, requestHeaders: { authorization: 'Bearer kovo-synth-invalid-deadbeef12345678' },
        body: '{"accountId":"acct-1","email":"ops@example.invalid","role":"admin"}',
      }),
    },
  ]
  const genuineVerdict = verifyReceipt(receipt, { entries: genuineEntries })
  assert.equal(genuineVerdict.confirmed, true, genuineVerdict.reason)
})
