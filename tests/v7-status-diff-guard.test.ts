// Status-diff guard: a bare `2xx -> 4xx/5xx` divergence may never confirm any class.
//
// The held-out artifact shape (agent-only `injection-input`, POST /api/journals/filter, control 200
// with items, probe 500) is the regression fixture. Confirmation must instead carry a positive
// semantic oracle (engine/dialect fingerprint, paired structural boolean differential, timing arm,
// verified OOB callback, or the narrow paired status-boolean contrast).
import assert from 'node:assert/strict'
import { test } from 'node:test'

import {
  assessBooleanDifferential,
  assessImpactEvidence,
  assessInjectionImpact,
  assessStatusOnlyDivergence,
  classifyImpactDescriptor,
} from '../src/server/oracle-invariants.ts'
import type { ImpactStep } from '../src/server/oracle-invariants.ts'
import { receiptRuleFor, verifyReceipt } from '../src/server/proof-receipt.ts'
import type { ReceiptTranscript } from '../src/server/proof-receipt.ts'
import { evaluateClaims, TranscriptStore } from '../src/server/verify-rpc.ts'
import { assessHttpChainProofStrength } from '../src/server/replay-verifier.ts'
import { baseFields } from '../src/server/deterministic-specs.ts'
import type { VerifyClaim } from '../src/server/verify-rpc.ts'

const origin = 'https://app.example.invalid'
const viewer = { handle: 'viewer', role: 'viewer' as const, tenant: 'acme', auth: 'cookie' as const, sameSite: null }
const ownerB = { handle: 'persona_b', role: 'owner' as const, tenant: 'globex', auth: 'cookie' as const, sameSite: null }
const anon = { handle: null, role: null, tenant: null, auth: 'unknown' as const, sameSite: null }

function step(partial: Partial<ImpactStep> & Pick<ImpactStep, 'id' | 'arm' | 'method' | 'status'>): ImpactStep {
  return {
    id: partial.id,
    arm: partial.arm,
    method: partial.method,
    status: partial.status,
    actor: partial.actor ?? viewer,
    route: partial.route ?? '/api/journals/filter',
    ...(partial.pathAndQuery !== undefined ? { pathAndQuery: partial.pathAndQuery } : {}),
    ...(partial.json !== undefined ? { json: partial.json } : {}),
    ...(partial.body !== undefined ? { body: partial.body } : {}),
    ...(partial.requestJson !== undefined ? { requestJson: partial.requestJson } : {}),
    ...(partial.requestHeaders !== undefined ? { requestHeaders: partial.requestHeaders } : {}),
    ...(partial.responseHeaders !== undefined ? { responseHeaders: partial.responseHeaders } : {}),
    ...(partial.durationMs !== undefined ? { durationMs: partial.durationMs } : {}),
  }
}

function entry(exchangeId: string, s: ImpactStep, extra: { carrierText?: string } = {}) {
  return { exchangeId, step: s, ...extra }
}

/** The exact held-out artifact shape: control 200 with items, probe 500 generic error body. */
function opsportalShape(): ImpactStep[] {
  return [
    step({
      id: 'control', arm: 'control', method: 'POST', status: 200,
      json: { items: [{ id: 1, action: 'login' }], count: 1 },
      body: JSON.stringify({ items: [{ id: 1, action: 'login' }], count: 1 }),
    }),
    step({
      id: 'probe', arm: 'probe', method: 'POST', status: 500,
      json: { error: 'Internal Server Error' },
      body: JSON.stringify({ error: 'Internal Server Error' }),
    }),
  ]
}

test('status-diff guard: the injection-input category is a machine-readable injection label', () => {
  assert.equal(classifyImpactDescriptor({ category: 'injection-input', cwe: 'CWE-20' }), 'injection')
  // Free-text remains unmodelled: only a CWE/category label may gate a class.
  assert.equal(classifyImpactDescriptor({ title: 'unhandled query construction error' }), 'other')
})

test('status-diff guard: the exact opsportal 200 -> 500 artifact is status-only and rejected', () => {
  const steps = opsportalShape()
  const divergence = assessStatusOnlyDivergence(steps)
  assert.equal(divergence.statusOnly, true, divergence.reason)
  assert.equal(divergence.controlStatus, 200)
  assert.equal(divergence.probeStatus, 500)

  const injection = assessImpactEvidence({ impactClass: 'injection', steps })
  assert.equal(injection.satisfied, false, injection.reason)
  assert.match(injection.reason, /positive semantic oracle|status divergence/i)

  const transcript: ReceiptTranscript = {
    entries: [entry('ex-control', steps[0]!), entry('ex-probe', steps[1]!)],
  }
  const receipt = {
    vulnClass: 'injection-input',
    target: { origin, method: 'POST', pathAndQuery: '/api/journals/filter' },
    exchangeIds: ['ex-control', 'ex-probe'],
    oobEventIds: [],
    browserTraceIds: [],
    claimedDelta: 'control=200 probe=500 | control 200 with items, probe diverges to 500',
  }
  assert.equal(receiptRuleFor('injection-input').rule, 'impact')
  const verdict = verifyReceipt(receipt, transcript)
  assert.equal(verdict.confirmed, false, verdict.reason)
  assert.match(verdict.reason, /status-only|semantic oracle|fingerprint/i)
})

test('status-diff guard: a bare 200 -> 500 cannot confirm XSS, SSRF or traversal either', () => {
  const steps = opsportalShape()
  const transcript: ReceiptTranscript = {
    entries: [entry('ex-control', steps[0]!), entry('ex-probe', steps[1]!)],
  }
  const receipt = (vulnClass: string) => ({
    vulnClass,
    target: { origin, method: 'POST', pathAndQuery: '/api/journals/filter' },
    exchangeIds: ['ex-control', 'ex-probe'],
    oobEventIds: [],
    browserTraceIds: [],
    claimedDelta: 'control 200, probe 500',
  })
  for (const vulnClass of ['xss_reflected', 'xss_stored', 'ssrf', 'path_traversal']) {
    const verdict = verifyReceipt(receipt(vulnClass), transcript)
    assert.equal(verdict.confirmed, false, `${vulnClass}: ${verdict.reason}`)
  }
})

test('status-diff guard: an engine fingerprint makes the same 500 a confirmation', () => {
  const steps = [
    step({
      id: 'control', arm: 'control', method: 'POST', status: 200,
      json: { items: [{ id: 1 }] }, body: JSON.stringify({ items: [{ id: 1 }] }),
    }),
    step({
      id: 'probe', arm: 'probe', method: 'POST', status: 500,
      json: { error: 'SQLITE_ERROR: near "filter": syntax error' },
      body: JSON.stringify({ error: 'SQLITE_ERROR: near "filter": syntax error' }),
    }),
  ]
  assert.equal(assessStatusOnlyDivergence(steps).statusOnly, false)
  const injection = assessInjectionImpact({ impactClass: 'injection', steps })
  assert.equal(injection.satisfied, true, injection.reason)
  assert.match(injection.reason, /sqlite/i)

  const transcript: ReceiptTranscript = {
    entries: [entry('ex-control', steps[0]!), entry('ex-probe', steps[1]!)],
  }
  const verdict = verifyReceipt({
    vulnClass: 'injection-input',
    target: { origin, method: 'POST', pathAndQuery: '/api/journals/filter' },
    exchangeIds: ['ex-control', 'ex-probe'],
    oobEventIds: [],
    browserTraceIds: [],
    claimedDelta: 'SQLite syntax error only on the injected filter shape',
  }, transcript)
  assert.equal(verdict.confirmed, true, verdict.reason)
  assert.match(verdict.reason, /fingerprint/i)
})

test('status-diff guard: verify-rpc rejects a status-only claim set and accepts a fingerprint claim', () => {
  const store = new TranscriptStore(Buffer.alloc(32, 7))
  const record = (path: string, method: string, status: number, role: string, body: string) => {
    const res = store.record({
      op: 'http',
      startedAt: Date.now(),
      durationMs: 8,
      request: {
        origin,
        method,
        pathAndQuery: path,
        headers: { 'content-type': 'application/json' },
        bodyBytes: 0,
        bodySha256: '',
        personaHandle: 'viewer',
        sessionRole: role,
        nonce: 'fixture-nonce',
      },
      response: {
        status,
        headers: { 'content-type': 'application/json' },
        bodyBytes: body.length,
        bodySha256: '',
        mediaType: 'application/json',
      },
      body,
    })
    return res.exchangeId
  }
  const control = record('/api/journals/filter', 'POST', 200, 'control', JSON.stringify({ items: [{ id: 1 }] }))
  const probe = record('/api/journals/filter', 'POST', 500, 'probe', JSON.stringify({ error: 'Internal Server Error' }))

  const statusOnlyClaims: VerifyClaim[] = [
    { kind: 'status', exchangeId: control, expected: 200 },
    { kind: 'status', exchangeId: probe, expected: 500 },
    { kind: 'body_contains', exchangeId: probe, text: 'Internal Server Error' },
  ]
  const rejected = evaluateClaims(store, statusOnlyClaims, { claimedImpact: 'other' })
  assert.equal(rejected.passed, false, rejected.failures.join('; '))
  assert.match(rejected.failures.join(' '), /status-only divergence/i)

  const fingerprintStore = new TranscriptStore(Buffer.alloc(32, 8))
  const fpControl = fingerprintStore.record({
    op: 'http', startedAt: Date.now(), durationMs: 8,
    request: { origin, method: 'POST', pathAndQuery: '/api/journals/filter', headers: {}, bodyBytes: 0, bodySha256: '', sessionRole: 'control', nonce: 'n' },
    response: { status: 200, headers: {}, bodyBytes: 2, bodySha256: '', mediaType: 'application/json' },
    body: '{}',
  }).exchangeId
  const fpProbe = fingerprintStore.record({
    op: 'http', startedAt: Date.now(), durationMs: 8,
    request: { origin, method: 'POST', pathAndQuery: '/api/journals/filter', headers: {}, bodyBytes: 0, bodySha256: '', sessionRole: 'probe', nonce: 'n' },
    response: { status: 500, headers: {}, bodyBytes: 58, bodySha256: '', mediaType: 'application/json' },
    body: JSON.stringify({ error: 'SQLITE_ERROR: near "x": syntax error' }),
  }).exchangeId
  const accepted = evaluateClaims(fingerprintStore, [
    { kind: 'status', exchangeId: fpControl, expected: 200 },
    { kind: 'status', exchangeId: fpProbe, expected: 500 },
    { kind: 'body_contains', exchangeId: fpProbe, text: 'SQLITE_ERROR' },
  ], { claimedImpact: 'other' })
  assert.equal(accepted.passed, true, accepted.failures.join('; '))

  // A declared injection class requires the semantic oracle, not a status/body echo.
  const injectionRejected = evaluateClaims(store, statusOnlyClaims, { claimedImpact: 'injection' })
  assert.equal(injectionRejected.passed, false)
  assert.match(injectionRejected.failures.join(' '), /injection claim requires a positive semantic oracle/i)
})

test('status-diff guard: boolean, timing and OOB receipt paths are unchanged', () => {
  // Boolean: paired rounds with a stable structural delta still confirm.
  const rounds = [0, 1].map(() => ({
    control: {
      status: 200,
      method: 'GET',
      pathAndQuery: '/api/products?category=books',
      json: { count: 2, results: [{ id: 1 }, { id: 2 }] },
    },
    probe: {
      status: 200,
      method: 'GET',
      pathAndQuery: "/api/products?category=books' OR 1=1-- -",
      json: { count: 4, results: [{ id: 1 }, { id: 2 }, { id: 3 }, { id: 4 }] },
    },
  }))
  const boolean = assessBooleanDifferential({ rounds, param: 'category' })
  assert.equal(boolean.satisfied, true, boolean.reason)

  const transcript: ReceiptTranscript = {
    entries: [
      entry('b-control', step({ id: 'b-control', arm: 'control', method: 'GET', status: 200, route: '/api/products', pathAndQuery: '/api/products?category=books', json: { count: 2, results: [{ id: 1 }, { id: 2 }] } })),
      entry('b-probe', step({ id: 'b-probe', arm: 'probe', method: 'GET', status: 200, route: '/api/products', pathAndQuery: "/api/products?category=books' OR 1=1-- -", json: { count: 4, results: [{ id: 1 }, { id: 2 }, { id: 3 }, { id: 4 }] } })),
      entry('b-control-2', step({ id: 'b-control-2', arm: 'control', method: 'GET', status: 200, route: '/api/products', pathAndQuery: '/api/products?category=books', json: { count: 2, results: [{ id: 1 }, { id: 2 }] } })),
      entry('b-probe-2', step({ id: 'b-probe-2', arm: 'probe', method: 'GET', status: 200, route: '/api/products', pathAndQuery: "/api/products?category=books' OR 1=1-- -", json: { count: 4, results: [{ id: 1 }, { id: 2 }, { id: 3 }, { id: 4 }] } })),
    ],
  }
  const booleanVerdict = verifyReceipt({
    vulnClass: 'sqli',
    target: { origin, method: 'GET', pathAndQuery: '/api/products', param: 'category' },
    exchangeIds: ['b-control', 'b-probe', 'b-control-2', 'b-probe-2'],
    oobEventIds: [],
    browserTraceIds: [],
    claimedDelta: 'row count separated across paired rounds',
  }, transcript)
  assert.equal(booleanVerdict.confirmed, true, booleanVerdict.reason)
  assert.equal(booleanVerdict.rule, 'boolean')

  // Timing: a >3x separation still confirms.
  const timingVerdict = verifyReceipt({
    vulnClass: 'blind_sqli',
    target: { origin, method: 'GET', pathAndQuery: '/api/orders/lookup' },
    exchangeIds: ['t-control', 't-probe'],
    oobEventIds: [],
    browserTraceIds: [],
    claimedDelta: 'conditional delay',
  }, {
    entries: [
      entry('t-control', step({ id: 't-control', arm: 'control', method: 'GET', status: 200, route: '/api/orders/lookup', durationMs: 40 })),
      entry('t-probe', step({ id: 't-probe', arm: 'probe', method: 'GET', status: 200, route: '/api/orders/lookup', durationMs: 2_500 })),
    ],
  })
  assert.equal(timingVerdict.confirmed, true, timingVerdict.reason)
  assert.equal(timingVerdict.rule, 'timing')

  // OOB: a delivered callback tied to the carrying exchange still confirms.
  const token = 'guardian-canary-0123456789abcdef01234567'
  const oobVerdict = verifyReceipt({
    vulnClass: 'ssrf',
    target: { origin, method: 'GET', pathAndQuery: '/api/fetch' },
    exchangeIds: ['oob-probe'],
    oobEventIds: ['oob-1'],
    browserTraceIds: [],
    claimedDelta: 'server fetched the canary',
  }, {
    entries: [entry('oob-probe', step({ id: 'oob-probe', arm: 'probe', method: 'GET', status: 200, route: '/api/fetch', pathAndQuery: `/api/fetch?url=${token}` }), { carrierText: token })],
    oobEvents: [{ id: 'oob-1', token, targetOrigin: origin, delivered: true, receivedAtMs: Date.now() }],
  })
  assert.equal(oobVerdict.confirmed, true, oobVerdict.reason)
  assert.equal(oobVerdict.rule, 'oob')
})

test('status-diff guard: paired status-boolean contrast is the only status-only exception', () => {
  const benign = step({ id: 'benign', arm: 'control', method: 'GET', status: 200, route: '/api/items', pathAndQuery: '/api/items?sku=abc' })
  const tautology = step({ id: 'true', arm: 'probe', method: 'GET', status: 200, route: '/api/items', pathAndQuery: "/api/items?sku=abc' AND 1=1-- -" })
  const contradiction = step({ id: 'false', arm: 'probe', method: 'GET', status: 403, route: '/api/items', pathAndQuery: "/api/items?sku=abc' AND 1=2-- -" })
  const accepted = assessInjectionImpact({
    impactClass: 'injection', steps: [benign, tautology, contradiction],
    injection: { family: 'sqli', statusBoolean: { benign, tautology, contradiction } },
  })
  assert.equal(accepted.satisfied, true, accepted.reason)
  assert.match(accepted.reason, /status-only boolean exception/i)

  // The artifact shape (a single malformed request to 500) is not the exception.
  const single = step({ id: 'single', arm: 'probe', method: 'GET', status: 500, route: '/api/items', pathAndQuery: "/api/items?sku=abc'" })
  const rejected = assessInjectionImpact({
    impactClass: 'injection', steps: [benign, single],
    injection: { family: 'sqli', statusBoolean: { benign, tautology, contradiction: single } },
  })
  assert.equal(rejected.satisfied, false, rejected.reason)
})

test('status-diff guard: cross-tenant writes need an authenticated peer control', () => {
  const anonDeny = step({ id: 'deny', arm: 'control', method: 'POST', status: 401, route: '/api/cases/3/assign', actor: anon })
  const before = step({ id: 'before', arm: 'control', method: 'GET', status: 200, route: '/api/cases/3', actor: ownerB, json: { id: 3, assignee: '1' } })
  const write = step({ id: 'write', arm: 'probe', method: 'POST', status: 200, route: '/api/cases/3/assign', actor: viewer, requestJson: { assignee_id: '9' }, json: { ok: true } })
  const after = step({ id: 'after', arm: 'control', method: 'GET', status: 200, route: '/api/cases/3', actor: ownerB, json: { id: 3, assignee: '9' } })
  const anonymousOnly = assessImpactEvidence({
    impactClass: 'authorization',
    resourceTenant: 'globex',
    steps: [anonDeny, write],
  })
  assert.equal(anonymousOnly.satisfied, false, anonymousOnly.reason)
  // Rejected either because an anonymous 401 is not a peer control, or because no pre-mutation
  // readback exists — both are valid; the point is that `anon=401` cannot carry the claim.
  assert.match(anonymousOnly.reason, /anonymous|pre-mutation readback/i)

  const peerDeny = step({ id: 'peer-deny', arm: 'control', method: 'POST', status: 403, route: '/api/cases/3/assign', actor: { handle: 'viewer_b', role: 'viewer', tenant: 'acme', auth: 'cookie', sameSite: null } })
  const peerControlled = assessImpactEvidence({
    impactClass: 'authorization',
    resourceTenant: 'globex',
    steps: [peerDeny, before, write, after],
  })
  assert.equal(peerControlled.satisfied, true, peerControlled.reason)

  // A collection readback above the mutated item is still the victim's evidence: the shopflow
  // shipment write reads `GET /api/shipments` and patches `PATCH /api/shipments/:id`.
  const listBefore = step({ id: 'list-before', arm: 'control', method: 'GET', status: 200, route: '/api/shipments', actor: ownerB, json: { shipments: [{ id: 3, status: 'packed' }] } })
  const itemWrite = step({ id: 'item-write', arm: 'probe', method: 'PATCH', status: 200, route: '/api/shipments/3', actor: viewer, requestJson: { status: 'shipped' }, json: { ok: true } })
  const listAfter = step({ id: 'list-after', arm: 'control', method: 'GET', status: 200, route: '/api/shipments', actor: ownerB, json: { shipments: [{ id: 3, status: 'shipped' }] } })
  const collectionReadback = assessImpactEvidence({
    impactClass: 'authorization',
    steps: [listBefore, itemWrite, listAfter],
  })
  assert.equal(collectionReadback.satisfied, true, collectionReadback.reason)
})

test('status-diff guard: the receipt target is bound to the mutating exchange, not a GET baseline', () => {
  const deny = step({ id: 'deny', arm: 'control', method: 'POST', status: 403, route: '/api/cases/3/assign', actor: { handle: 'viewer_b', role: 'viewer', tenant: 'acme', auth: 'cookie', sameSite: null } })
  const before = step({ id: 'before', arm: 'control', method: 'GET', status: 200, route: '/api/cases/3', actor: ownerB, json: { id: 3, assignee: '1' } })
  const write = step({ id: 'write', arm: 'probe', method: 'POST', status: 200, route: '/api/cases/3/assign', actor: viewer, requestJson: { assignee_id: '9' }, json: { ok: true } })
  const after = step({ id: 'after', arm: 'control', method: 'GET', status: 200, route: '/api/cases/3', actor: ownerB, json: { id: 3, assignee: '9' } })
  const transcript: ReceiptTranscript = {
    entries: [entry('ex-deny', deny), entry('ex-before', before), entry('ex-write', write), entry('ex-after', after)],
  }
  const misattributed = verifyReceipt({
    vulnClass: 'authorization',
    target: { origin, method: 'GET', pathAndQuery: '/api/me' },
    exchangeIds: ['ex-deny', 'ex-before', 'ex-write', 'ex-after'],
    oobEventIds: [],
    browserTraceIds: [],
    claimedDelta: 'viewer cross-tenant assign',
    resourceTenant: 'globex',
  }, transcript)
  assert.equal(misattributed.confirmed, false, misattributed.reason)
  assert.match(misattributed.reason, /not the mutating probe exchange/i)

  const wrongMethod = verifyReceipt({
    vulnClass: 'authorization',
    target: { origin, method: 'GET', pathAndQuery: '/api/cases/3/assign' },
    exchangeIds: ['ex-deny', 'ex-before', 'ex-write', 'ex-after'],
    oobEventIds: [],
    browserTraceIds: [],
    claimedDelta: 'viewer cross-tenant assign',
    resourceTenant: 'globex',
  }, transcript)
  assert.equal(wrongMethod.confirmed, false, wrongMethod.reason)
  assert.match(wrongMethod.reason, /target method/i)

  const bound = verifyReceipt({
    vulnClass: 'authorization',
    target: { origin, method: 'POST', pathAndQuery: '/api/cases/3/assign' },
    exchangeIds: ['ex-deny', 'ex-before', 'ex-write', 'ex-after'],
    oobEventIds: [],
    browserTraceIds: [],
    claimedDelta: 'viewer cross-tenant assign',
    resourceTenant: 'globex',
  }, transcript)
  assert.equal(bound.confirmed, true, bound.reason)
})

test('http_chain: a bare 200 -> 500 assertion is rejected for a non-authz (injection) claim', () => {
  const spec = {
    ...baseFields(
      'http://127.0.0.1:1',
      'POST /api/journals/filter passes unrecognized caller keys',
      'CWE-20',
      'injection-input',
      'high',
      '{ confirmed: (.steps["probe"].status == 500) }',
    ),
    kind: 'http_chain' as const,
    steps: [],
    assertionsJq: '{ confirmed: (.steps["probe"].status == 500) }',
  }
  const snapshots = [
    { index: 0, id: 'control', role: 'control', method: 'POST', route: '/api/journals/filter', pathAndQuery: '/api/journals/filter', actor: 'persona:owner', status: 200, body: '{"items":[]}', bodyBytes: 12, mediaType: 'application/json', json: { items: [] }, secretMatches: 0 },
    { index: 1, id: 'probe', role: 'probe', method: 'POST', route: '/api/journals/filter', pathAndQuery: '/api/journals/filter', actor: 'persona:owner', status: 500, body: '{"error":"Internal Server Error"}', bodyBytes: 30, mediaType: 'application/json', json: { error: 'Internal Server Error' }, secretMatches: 0 },
  ]
  const assessment = assessHttpChainProofStrength(spec as never, snapshots as never)
  assert.equal(assessment.satisfied, false, 'status-only divergence must never confirm an injection claim')
  assert.match(assessment.reason, /status/i)
})
