/**
 * v7 conserved_balance receipt rule tests:
 *  - Positive cases: under-debit double-spend (with exact serial debit control), negative balance /
 *    inventory oversell (with 4xx serial rejection control), cap/quota overshoot (with serial
 *    rejection control), and `buildAgentScriptReceipt` round-trip for `race` / `conserved_balance`.
 *  - Fail-closed negative cases: missing serial control, serial control itself violating
 *    conservation, missing baseline/post readback, 5xx-only burst, single acked burst, status-only
 *    differential without numeric delta, conserved (no-violation) debit, and unverified exchange IDs.
 */
import assert from 'node:assert/strict'
import { test } from 'node:test'
import {
  buildAgentScriptReceipt,
  buildProofReceipt,
  receiptRuleFor,
  verifyReceipt,
  type ImpactStep,
  type ReceiptTranscript,
  type ReceiptTranscriptEntry,
  type ScriptProofExchange,
} from '../src/server/proof-receipt.ts'

const ORIGIN = 'https://app.example.invalid'

function mkStep(overrides: Partial<ImpactStep> & { id: string; arm: ImpactStep['arm']; method: string; status: number | null }): ImpactStep {
  return {
    route: '/api/v1/wallets/1/redeem',
    pathAndQuery: '/api/v1/wallets/1/redeem',
    actor: { handle: 'owner', role: 'member', tenant: 'tenant-a', auth: 'bearer', sameSite: null },
    ...overrides,
  }
}

function mkEntry(
  exchangeId: string,
  step: ImpactStep,
  evidenceRole?: string,
): ReceiptTranscriptEntry {
  return { exchangeId, step, ...(evidenceRole ? { evidenceRole } : {}) }
}

test('receiptRuleFor routes race/double-spend/oversell classes to conserved_balance without disturbing blind_sqli timing', () => {
  for (const cls of ['race', 'race_double_spend', 'race_condition', 'race_burst', 'double_spend', 'oversell', 'inventory_oversell', 'conserved_balance', 'toctou']) {
    assert.equal(receiptRuleFor(cls).rule, 'conserved_balance', `${cls} must map to conserved_balance`)
  }
  assert.equal(receiptRuleFor('blind_sqli').rule, 'timing')
  assert.equal(receiptRuleFor('sqli_time').rule, 'timing')
})

test('conserved_balance confirms under-debit double-spend backed by exact serial debit control', () => {
  const transcript: ReceiptTranscript = {
    entries: [
      mkEntry('pre', mkStep({ id: 'pre', arm: 'setup', method: 'GET', route: '/api/v1/wallets/1', pathAndQuery: '/api/v1/wallets/1', status: 200, json: { balance: 100 } }), 'baseline_read'),
      mkEntry('b1', mkStep({ id: 'b1', arm: 'probe', method: 'POST', status: 200, requestJson: { amount: 10 }, json: { ok: true, debited: 10 } }), 'burst_1'),
      mkEntry('b2', mkStep({ id: 'b2', arm: 'probe', method: 'POST', status: 200, requestJson: { amount: 10 }, json: { ok: true, debited: 10 } }), 'burst_2'),
      mkEntry('b3', mkStep({ id: 'b3', arm: 'probe', method: 'POST', status: 200, requestJson: { amount: 10 }, json: { ok: true, debited: 10 } }), 'burst_3'),
      mkEntry('post', mkStep({ id: 'post', arm: 'control', method: 'GET', route: '/api/v1/wallets/1', pathAndQuery: '/api/v1/wallets/1', status: 200, json: { balance: 90 } }), 'post_read'),
      mkEntry('s1', mkStep({ id: 's1', arm: 'control', method: 'POST', status: 200, requestJson: { amount: 10 }, json: { ok: true, debited: 10 } }), 'serial_control_1'),
      mkEntry('spost', mkStep({ id: 'spost', arm: 'control', method: 'GET', route: '/api/v1/wallets/1', pathAndQuery: '/api/v1/wallets/1', status: 200, json: { balance: 80 } }), 'serial_post_read'),
    ],
  }
  const receipt = buildProofReceipt({
    vulnClass: 'race_double_spend',
    target: { origin: ORIGIN, method: 'POST', pathAndQuery: '/api/v1/wallets/1/redeem' },
    exchangeIds: ['pre', 'b1', 'b2', 'b3', 'post', 's1', 'spost'],
    claimedDelta: '3 concurrent 10-credit redemptions succeeded but balance only dropped from 100 to 90; serial control debited 10 cleanly.',
  })
  const verdict = verifyReceipt(receipt, transcript)
  assert.equal(verdict.confirmed, true, verdict.reason)
  assert.equal(verdict.rule, 'conserved_balance')
  assert.equal(verdict.evidence?.violationKind, 'under_debit')
  assert.equal(verdict.evidence?.serialControlKind, 'serial_debit_exact')
  assert.equal(verdict.evidence?.actualBurstDebit, 10)
  assert.equal(verdict.evidence?.expectedBurstDebit, 30)
})

test('conserved_balance confirms negative balance / inventory oversell backed by 4xx serial rejection control', () => {
  const transcript: ReceiptTranscript = {
    entries: [
      mkEntry('pre', mkStep({ id: 'pre', arm: 'setup', method: 'GET', route: '/api/v1/items/9', pathAndQuery: '/api/v1/items/9', status: 200, json: { stock: 1 } }), 'baseline_read'),
      mkEntry('b1', mkStep({ id: 'b1', arm: 'probe', method: 'POST', route: '/api/v1/checkout', pathAndQuery: '/api/v1/checkout', status: 201, requestJson: { qty: 1 }, json: { orderId: 'o-1' } }), 'burst_1'),
      mkEntry('b2', mkStep({ id: 'b2', arm: 'probe', method: 'POST', route: '/api/v1/checkout', pathAndQuery: '/api/v1/checkout', status: 201, requestJson: { qty: 1 }, json: { orderId: 'o-2' } }), 'burst_2'),
      mkEntry('post', mkStep({ id: 'post', arm: 'control', method: 'GET', route: '/api/v1/items/9', pathAndQuery: '/api/v1/items/9', status: 200, json: { stock: -1 } }), 'post_read'),
      mkEntry('s1', mkStep({ id: 's1', arm: 'control', method: 'POST', route: '/api/v1/checkout', pathAndQuery: '/api/v1/checkout', status: 409, requestJson: { qty: 1 }, json: { error: 'out of stock' } }), 'serial_control_1'),
    ],
  }
  const receipt = buildProofReceipt({
    vulnClass: 'inventory_oversell',
    target: { origin: ORIGIN, method: 'POST', pathAndQuery: '/api/v1/checkout' },
    exchangeIds: ['pre', 'b1', 'b2', 'post', 's1'],
    claimedDelta: 'Concurrent checkout drove stock from 1 to -1 while serial checkout returned 409.',
  })
  const verdict = verifyReceipt(receipt, transcript)
  assert.equal(verdict.confirmed, true, verdict.reason)
  assert.equal(verdict.rule, 'conserved_balance')
  assert.equal(verdict.evidence?.violationKind, 'negative_balance')
  assert.equal(verdict.evidence?.serialControlKind, 'serial_rejection')
})

test('conserved_balance confirms cap/quota overshoot backed by 4xx serial rejection control', () => {
  const transcript: ReceiptTranscript = {
    entries: [
      mkEntry('pre', mkStep({ id: 'pre', arm: 'setup', method: 'GET', route: '/api/v1/org/seats', pathAndQuery: '/api/v1/org/seats', status: 200, json: { seats_used: 3, seat_limit: 4 } }), 'baseline_read'),
      mkEntry('b1', mkStep({ id: 'b1', arm: 'probe', method: 'POST', route: '/api/v1/org/seats', pathAndQuery: '/api/v1/org/seats', status: 201, json: { ok: true } }), 'burst_1'),
      mkEntry('b2', mkStep({ id: 'b2', arm: 'probe', method: 'POST', route: '/api/v1/org/seats', pathAndQuery: '/api/v1/org/seats', status: 201, json: { ok: true } }), 'burst_2'),
      mkEntry('post', mkStep({ id: 'post', arm: 'control', method: 'GET', route: '/api/v1/org/seats', pathAndQuery: '/api/v1/org/seats', status: 200, json: { seats_used: 5, seat_limit: 4 } }), 'post_read'),
      mkEntry('s1', mkStep({ id: 's1', arm: 'control', method: 'POST', route: '/api/v1/org/seats', pathAndQuery: '/api/v1/org/seats', status: 403, json: { error: 'seat limit reached' } }), 'serial_control_1'),
    ],
  }
  const receipt = buildProofReceipt({
    vulnClass: 'oversell',
    target: { origin: ORIGIN, method: 'POST', pathAndQuery: '/api/v1/org/seats' },
    exchangeIds: ['pre', 'b1', 'b2', 'post', 's1'],
    claimedDelta: 'Concurrent seat invites pushed seats_used to 5 past seat_limit 4; serial invite rejected 403.',
  })
  const verdict = verifyReceipt(receipt, transcript)
  assert.equal(verdict.confirmed, true, verdict.reason)
  assert.equal(verdict.evidence?.violationKind, 'cap_overshoot')
  assert.equal(verdict.evidence?.capField, 'seat_limit')
})

test('conserved_balance fails closed on missing control, missing readbacks, 5xx burst, status-only diff, conserved debit, and unverified IDs', () => {
  const baseEntries: ReceiptTranscriptEntry[] = [
    mkEntry('pre', mkStep({ id: 'pre', arm: 'setup', method: 'GET', status: 200, json: { balance: 100 } }), 'baseline_read'),
    mkEntry('b1', mkStep({ id: 'b1', arm: 'probe', method: 'POST', status: 200, requestJson: { amount: 10 }, json: { ok: true } }), 'burst_1'),
    mkEntry('b2', mkStep({ id: 'b2', arm: 'probe', method: 'POST', status: 200, requestJson: { amount: 10 }, json: { ok: true } }), 'burst_2'),
    mkEntry('post', mkStep({ id: 'post', arm: 'control', method: 'GET', status: 200, json: { balance: 90 } }), 'post_read'),
    mkEntry('s1', mkStep({ id: 's1', arm: 'control', method: 'POST', status: 200, requestJson: { amount: 10 }, json: { ok: true } }), 'serial_control_1'),
    mkEntry('spost', mkStep({ id: 'spost', arm: 'control', method: 'GET', status: 200, json: { balance: 80 } }), 'serial_post_read'),
  ]
  const mkReceipt = (exchangeIds: string[]) => buildProofReceipt({
    vulnClass: 'race_double_spend',
    target: { origin: ORIGIN, method: 'POST', pathAndQuery: '/api/v1/wallets/1/redeem' },
    exchangeIds,
    claimedDelta: 'Concurrent debit claim.',
  })

  // 1. Missing serial control
  const noSerial = verifyReceipt(mkReceipt(['pre', 'b1', 'b2', 'post']), { entries: baseEntries.slice(0, 4) })
  assert.equal(noSerial.confirmed, false)
  assert.match(noSerial.reason, /serial control/i)

  // 2. Missing baseline readback
  const noBaseline = verifyReceipt(mkReceipt(['b1', 'b2', 'post', 's1', 'spost']), { entries: baseEntries.slice(1) })
  assert.equal(noBaseline.confirmed, false)
  assert.match(noBaseline.reason, /baseline numeric readback/i)

  // 3. Missing post-burst readback
  const noPost = verifyReceipt(mkReceipt(['pre', 'b1', 'b2', 's1', 'spost']), {
    entries: baseEntries.filter(e => e.exchangeId !== 'post'),
  })
  assert.equal(noPost.confirmed, false)
  assert.match(noPost.reason, /post-burst numeric readback/i)

  // 4. 5xx-only burst
  const burst5xx = verifyReceipt(mkReceipt(['pre', 'b1', 'b2', 'post', 's1', 'spost']), {
    entries: baseEntries.map(e => e.exchangeId.startsWith('b') ? { ...e, step: { ...e.step, status: 500 } } : e),
  })
  assert.equal(burst5xx.confirmed, false)
  assert.match(burst5xx.reason, /no 2xx acknowledged mutations/i)

  // 5. Status-only differential without numeric conserved field
  const statusOnly = verifyReceipt(mkReceipt(['pre', 'b1', 'b2', 'post', 's1', 'spost']), {
    entries: baseEntries.map(e => ({ ...e, step: { ...e.step, json: { message: 'ok' } } })),
  })
  assert.equal(statusOnly.confirmed, false)
  assert.match(statusOnly.reason, /status-only differential/i)

  // 6. Conservation held (pre=100, 2x10 burst -> post=80, serial 1x10 -> 70)
  const conservedOk = verifyReceipt(mkReceipt(['pre', 'b1', 'b2', 'post', 's1', 'spost']), {
    entries: baseEntries.map(e =>
      e.exchangeId === 'post' ? { ...e, step: { ...e.step, json: { balance: 80 } } }
        : e.exchangeId === 'spost' ? { ...e, step: { ...e.step, json: { balance: 70 } } }
          : e),
  })
  assert.equal(conservedOk.confirmed, false)
  assert.match(conservedOk.reason, /no conservation violation/i)

  // 7. Serial control itself under-debited (conservation fails serially too)
  const badSerial = verifyReceipt(mkReceipt(['pre', 'b1', 'b2', 'post', 's1', 'spost']), {
    entries: baseEntries.map(e => e.exchangeId === 'spost' ? { ...e, step: { ...e.step, json: { balance: 90 } } } : e),
  })
  assert.equal(badSerial.confirmed, false)
  assert.match(badSerial.reason, /Serial control under-debited/i)

  // 8. Unverified exchange ID absent from transcript
  const ghostId = verifyReceipt(mkReceipt(['pre', 'b1', 'ghost-id', 'post', 's1', 'spost']), { entries: baseEntries })
  assert.equal(ghostId.confirmed, false)
  assert.match(ghostId.reason, /absent from the transcript/i)
})

test('buildAgentScriptReceipt builds and verifies a conserved_balance receipt from Layer-3 race claim', () => {
  const exchanges: ScriptProofExchange[] = [
    { exchangeId: 'ex-pre', method: 'GET', pathAndQuery: '/api/v1/credits', origin: ORIGIN, status: 200, body: '{"credits":50}' },
    { exchangeId: 'ex-b1', method: 'POST', pathAndQuery: '/api/v1/credits/redeem', origin: ORIGIN, status: 200, body: '{"redeemed":10}' },
    { exchangeId: 'ex-b2', method: 'POST', pathAndQuery: '/api/v1/credits/redeem', origin: ORIGIN, status: 200, body: '{"redeemed":10}' },
    { exchangeId: 'ex-post', method: 'GET', pathAndQuery: '/api/v1/credits', origin: ORIGIN, status: 200, body: '{"credits":40}' },
    { exchangeId: 'ex-s1', method: 'POST', pathAndQuery: '/api/v1/credits/redeem', origin: ORIGIN, status: 200, body: '{"redeemed":10}' },
    { exchangeId: 'ex-spost', method: 'GET', pathAndQuery: '/api/v1/credits', origin: ORIGIN, status: 200, body: '{"credits":30}' },
  ]
  const built = buildAgentScriptReceipt({
    origin: ORIGIN,
    title: 'Credit wallet double-spend under synchronized burst',
    exchanges,
    claims: [{
      kind: 'race',
      vulnClass: 'race_double_spend',
      baselineExchangeId: 'ex-pre',
      burstExchangeIds: ['ex-b1', 'ex-b2'],
      postExchangeId: 'ex-post',
      serialExchangeIds: ['ex-s1'],
      serialPostExchangeId: 'ex-spost',
      balanceField: 'credits',
      unitDebit: 10,
    }],
  })
  assert.ok(built, 'race claim with full conserved-balance evidence must build a receipt')
  const verdict = verifyReceipt(built.receipt, built.transcript)
  assert.equal(verdict.confirmed, true, verdict.reason)
  assert.equal(verdict.rule, 'conserved_balance')
  assert.equal(verdict.evidence?.balanceField, 'credits')
  assert.equal(verdict.evidence?.violationKind, 'under_debit')
})
