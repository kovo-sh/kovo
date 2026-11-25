/**
 * v6 det-lane lead promotion (F3).
 *
 * A `det_lead` is only promoted when the observation carries real contrast:
 *  - a denied/failed control on the same route (actor differential, 401/403, or a rejected
 *    bogus-identifier control for a mutating route),
 *  - an observed data delta that only spec synthesis failed to bind, or
 *  - a near-miss verifier rejection with a concrete missing-evidence code.
 *
 * Bare anomalies ("a non-owner received a 2xx" on an idempotent route), 2xx-only signals and
 * unconfirmed authz matrices that accept nonexistent ids must not become leads.
 */
import assert from 'node:assert/strict'
import { randomUUID } from 'node:crypto'
import { test } from 'node:test'

import type { BrokerExchangeResult, Grant, RequestBroker } from '../src/server/broker.ts'
import type { WorkerBackend } from '../src/server/worker-backend.ts'
import {
  bogusIdControlOutcome,
  deriveLeadEvidence,
  leadCandidateKey,
  leadCandidateScore,
  missingEvidenceCode,
  runDeterministicEngine,
  selectEngineLeads,
} from '../src/server/deterministic-engine.ts'
import type {
  DeterministicEngineInput,
  EngineHypothesis,
  EngineLead,
  EngineLeadCandidate,
  EngineEndpoint,
  EnginePersona,
  RejectedSpecEvidence,
} from '../src/server/deterministic-engine.ts'
import type { DifferentialResult } from '../src/server/surface-engine.ts'
import {
  detLeadEvidenceFactFields,
  leadEvidenceRiskBonus,
} from '../src/server/graph-leads.ts'
import { detLeadsFromParentFacts } from '../src/server/agent-session.ts'

process.env.KOVO_ALLOW_LOCAL_LAB = '1'

const origin = 'http://127.0.0.1:4100'

const personas: EnginePersona[] = [
  { handle: 'persona-a', roleLabel: 'owner (f6e944)', privilege: 'member', tenant: 'f6e944' },
  { handle: 'persona-b', roleLabel: 'owner (19837b)', privilege: 'member', tenant: '19837b' },
  { handle: 'admin', roleLabel: 'admin (f6e944)', privilege: 'admin', tenant: 'f6e944' },
  { handle: 'viewer', roleLabel: 'viewer (f6e944)', privilege: 'viewer', tenant: 'f6e944' },
]

function hypothesis(over: Partial<EngineHypothesis> = {}): EngineHypothesis {
  return {
    key: 'authz|invoice',
    endpoint: {
      id: 'GET:/api/invoices/:invoiceId',
      origin,
      method: 'GET',
      pathTemplate: '/api/invoices/:invoiceId',
      params: [{ name: 'invoiceId', location: 'path' }],
      riskScore: 70,
    },
    probeClass: 'authz_matrix',
    intent: 'authz',
    method: 'GET',
    pathAndQuery: '/api/invoices/{{id}}',
    ownerPersona: 'persona-a',
    otherPersona: 'persona-b',
    risk: 70,
    ...over,
  } as EngineHypothesis
}

function signal(over: Partial<DifferentialResult> = {}): DifferentialResult {
  return {
    probeClass: 'authz_matrix',
    origin,
    pathAndQuery: '/api/invoices/{{id}}',
    verdict: 'signal',
    summary: 'cross-tenant observation',
    anomalies: [],
    details: {},
    requestsSent: 6,
    exchangeIds: ['ex-probe-1'],
    stoppedReason: null,
    notes: [],
    durationMs: 5,
    ...over,
  }
}

function rejection(over: Partial<RejectedSpecEvidence> = {}): RejectedSpecEvidence {
  return {
    kind: 'http_chain',
    verdict: 'inconclusive',
    controlPassed: false,
    observed: 'probe status=200 after status=200 bogus status=200',
    reason: null,
    exchangeIds: ['ex-verify-1'],
    ...over,
  }
}

function matrixRow(row: Record<string, unknown>): Record<string, unknown> {
  return { resourceId: 'inv_1', ...row }
}

// ---------------------------------------------------------------------------------------------
// Evidence gate
// ---------------------------------------------------------------------------------------------

test('denied-control lead: a read 2xx with an actor denial on the same route is promoted', () => {
  const evidence = deriveLeadEvidence({
    hypothesis: hypothesis(),
    probe: signal({
      anomalies: [{ type: 'unauthorized_access', resourceId: 'inv_1', actor: 'other_persona', method: 'GET', status: 200 }],
      details: {
        matrix: [
          matrixRow({ actor: 'owner', status: 200, accessible: true, bodyBytes: 64 }),
          matrixRow({ actor: 'other_persona', status: 200, accessible: true, bodyBytes: 12 }),
          matrixRow({ actor: 'anonymous', status: 401, accessible: false }),
        ],
      },
    }),
  })
  assert.ok(evidence, 'denied control must promote the lead')
  assert.equal(evidence!.kind, 'denied_control')
  assert.match(evidence!.controlOutcome, /actor_denied_401/)
  assert.equal(evidence!.candidateProbeClass, 'authz_matrix')
  assert.ok(evidence!.evidenceExchangeIds.length > 0)
  assert.ok(evidence!.evidenceExchangeIds.includes('ex-probe-1'))
})

test('bare 2xx anomaly: no denied control and no owner-equivalent delta is not a lead', () => {
  const evidence = deriveLeadEvidence({
    hypothesis: hypothesis(),
    probe: signal({
      anomalies: [{ type: 'unauthorized_access', resourceId: 'inv_1', actor: 'other_persona', method: 'GET', status: 200, similarityToOwner: 0.1 }],
      details: {
        matrix: [
          matrixRow({ actor: 'owner', status: 200, accessible: true, bodyBytes: 64, bodySha256: 'owner-sha' }),
          matrixRow({ actor: 'other_persona', status: 200, accessible: true, bodyBytes: 12, bodySha256: 'other-sha' }),
        ],
      },
    }),
  })
  assert.equal(evidence, null, 'a 2xx without contrast must not become a lead')
})

test('false DELETE matrix with an accepted bogus-id control produces 0 leads', () => {
  // This is the acme false-lead signature: owner and non-owner both get an idempotent 200 for
  // every id, including nonexistent ones, so the "non-owner 2xx" carries no contrast.
  const evidence = deriveLeadEvidence({
    hypothesis: hypothesis({
      key: 'authz|people',
      endpoint: { id: 'DELETE:/api/people/:personId', origin, method: 'DELETE', pathTemplate: '/api/people/:personId', params: [{ name: 'personId', location: 'path' }], riskScore: 70 },
      method: 'DELETE',
      pathAndQuery: '/api/people/{{id}}',
    }),
    probe: signal({
      pathAndQuery: '/api/people/{{id}}',
      anomalies: [{
        type: 'unauthorized_access', resourceId: 'person_1', actor: 'other_persona', method: 'DELETE', status: 200, similarityToOwner: 1,
      }],
      details: {
        matrix: [
          matrixRow({ resourceId: 'person_1', actor: 'owner', status: 200, accessible: true }),
          matrixRow({ resourceId: 'person_1', actor: 'other_persona', status: 200, accessible: true }),
          matrixRow({ resourceId: 'person_1', actor: 'anonymous', status: 401, accessible: false }),
        ],
      },
    }),
    rejections: [rejection(), rejection({ exchangeIds: ['ex-verify-2'] })],
  })
  assert.equal(evidence, null, 'an accepted bogus-id control means the route is non-selective')
})

test('genuine near-miss: a denied bogus-id control on a mutating route produces exactly one lead', () => {
  const evidence = deriveLeadEvidence({
    hypothesis: hypothesis({
      key: 'authz|people',
      endpoint: { id: 'DELETE:/api/people/:personId', origin, method: 'DELETE', pathTemplate: '/api/people/:personId', params: [{ name: 'personId', location: 'path' }], riskScore: 70 },
      method: 'DELETE',
      pathAndQuery: '/api/people/{{id}}',
    }),
    probe: signal({
      pathAndQuery: '/api/people/{{id}}',
      anomalies: [{ type: 'unauthorized_access', resourceId: 'person_1', actor: 'other_persona', method: 'DELETE', status: 200 }],
      details: { matrix: [matrixRow({ actor: 'owner', status: 200, accessible: true })] },
    }),
    rejections: [rejection({
      observed: 'probe status=200 after status=404 bogus status=404',
      controlPassed: true,
      reason: 'Authorization claim rests on a different-body observation without identifier binding; assert a field-bound value.',
      exchangeIds: ['ex-verify-404'],
    })],
  })
  assert.ok(evidence, 'a denied control on the same route must promote the near-miss')
  assert.equal(evidence!.kind, 'near_miss')
  assert.match(evidence!.controlOutcome, /bogus_id_denied_404/)
  assert.equal(evidence!.verifyFailureCode, 'missing_identifier_binding')
  assert.ok(evidence!.verifyFailureReason?.includes('identifier binding'))
  assert.ok(evidence!.evidenceExchangeIds.includes('ex-verify-404'))
  const leads = selectEngineLeads([{ lead: { hypothesis: hypothesis(), probe: signal(), summary: 'x', evidence }, key: 'k', score: 1 }])
  assert.equal(leads.length, 1)
})

test('mutating 2xx without a bogus-id control, state delta or same-actor denial is not a lead', () => {
  const evidence = deriveLeadEvidence({
    hypothesis: hypothesis({
      endpoint: { id: 'DELETE:/api/spaces/:projectId', origin, method: 'DELETE', pathTemplate: '/api/spaces/:projectId', params: [], riskScore: 60 },
      method: 'DELETE',
      pathAndQuery: '/api/spaces/{{id}}',
      key: 'authz|spaces',
    }),
    probe: signal({
      anomalies: [{ type: 'unauthorized_access', resourceId: 'space_1', actor: 'other_persona', method: 'DELETE', status: 200, similarityToOwner: 1 }],
      details: {
        matrix: [
          matrixRow({ actor: 'owner', status: 200, accessible: true }),
          matrixRow({ actor: 'other_persona', status: 200, accessible: true }),
        ],
      },
    }),
  })
  assert.equal(evidence, null)
})

test('data delta that failed only spec synthesis is promoted with no verifier reason', () => {
  const evidence = deriveLeadEvidence({
    hypothesis: hypothesis({
      endpoint: { id: 'GET:/api/invoices/:invoiceId', origin, method: 'GET', pathTemplate: '/api/invoices/:invoiceId', params: [], riskScore: 64 },
      ownerPersona: 'persona-a',
      otherPersona: 'persona-b',
    }),
    probe: signal({
      anomalies: [{ type: 'unauthorized_access', resourceId: 'inv_1', actor: 'other_persona', method: 'GET', status: 200, similarityToOwner: 0.98 }],
      details: { matrix: [matrixRow({ actor: 'owner', status: 200, accessible: true })] },
    }),
    rejections: [],
  })
  assert.ok(evidence)
  assert.equal(evidence!.kind, 'data_delta')
  assert.equal(evidence!.controlOutcome, 'owner_equivalent_2xx')
  assert.equal(evidence!.verifyFailureReason, null)
})

test('non-authz differential anomalies are data-delta leads; status-only is never a near-miss code', () => {
  const evidence = deriveLeadEvidence({
    hypothesis: hypothesis({
      key: 'sqli|search',
      endpoint: { id: 'GET:/api/search', origin, method: 'GET', pathTemplate: '/api/search', params: [{ name: 'q', location: 'query' }], riskScore: 66 },
      probeClass: 'sqli_boolean',
      intent: 'sqli',
      pathAndQuery: '/api/search',
    }),
    probe: signal({
      probeClass: 'sqli_boolean',
      pathAndQuery: '/api/search',
      anomalies: [{ type: 'boolean_differential', style: 'single_quote' }],
    }),
  })
  assert.ok(evidence)
  assert.equal(evidence!.kind, 'data_delta')

  assert.equal(missingEvidenceCode('Authorization claim is status-only: a 2xx status is not a differential.'), 'status_only')
  assert.equal(missingEvidenceCode('Authorization claim has no genuine control-vs-probe differential in the recorded exchanges.'), 'missing_control_differential')
  assert.equal(missingEvidenceCode('Authorization claim rests on a different-body observation without identifier binding.'), 'missing_identifier_binding')
  assert.equal(missingEvidenceCode('nothing actionable'), null)
  assert.deepEqual(bogusIdControlOutcome('probe status=200 bogus status=204'), { status: 204, accepted: true })
  assert.deepEqual(bogusIdControlOutcome('probe status=200 bogus status=404'), { status: 404, accepted: false })
})

// ---------------------------------------------------------------------------------------------
// Dedupe, severity ranking and cap
// ---------------------------------------------------------------------------------------------

function candidate(key: string, kind: 'near_miss' | 'denied_control' | 'data_delta', risk = 70, exchange = 'ex-1'): EngineLeadCandidate {
  const evidence = {
    kind,
    verifyFailureReason: null,
    verifyFailureCode: null,
    controlOutcome: 'x',
    evidenceExchangeIds: [exchange],
    candidateProbeClass: 'authz_matrix',
    detail: 'x',
  }
  return {
    lead: { hypothesis: hypothesis({ risk }), probe: signal({ exchangeIds: [exchange] }), summary: 'x', evidence },
    key,
    score: leadCandidateScore(hypothesis({ risk }), evidence),
  }
}

test('leads are deduplicated by origin/endpoint/method/mutated-input/class', () => {
  const hypA = hypothesis({ endpoint: { id: 'e', origin, method: 'DELETE', pathTemplate: '/api/invoices/:invoiceId', params: [], riskScore: 70 } })
  const hypB = hypothesis({ endpoint: { id: 'e', origin, method: 'DELETE', pathTemplate: '/api/invoices/:invoiceId', params: [], riskScore: 70 } })
  assert.equal(leadCandidateKey(hypA), leadCandidateKey(hypB))

  const sameRoute = 'same-key'
  const selected = selectEngineLeads([
    candidate(sameRoute, 'data_delta', 70, 'ex-a'),
    candidate(sameRoute, 'denied_control', 70, 'ex-b'),
    candidate(sameRoute, 'data_delta', 90, 'ex-c'),
  ])
  assert.equal(selected.length, 1, 'one key emits one lead')
  assert.equal(selected[0]!.lead.evidence?.kind, 'denied_control', 'the strongest evidence wins the dedupe')
})

test('lead emission is capped and severity-ranked', () => {
  const candidates: EngineLeadCandidate[] = []
  const kinds: Array<'near_miss' | 'denied_control' | 'data_delta'> = ['data_delta', 'denied_control', 'near_miss']
  for (let i = 0; i < 9; i += 1) {
    const kind = kinds[i % kinds.length]!
    candidates.push(candidate(`k${i}`, kind, 50 + i))
  }
  const selected = selectEngineLeads(candidates)
  assert.equal(selected.length, 6)
  const rank = { near_miss: 3, denied_control: 2, data_delta: 1 }
  for (let i = 1; i < selected.length; i += 1) {
    const prev = rank[selected[i - 1]!.lead.evidence!.kind]
    const curr = rank[selected[i]!.lead.evidence!.kind]
    assert.ok(prev >= curr, 'higher-evidence leads sort first')
  }

  for (const cap of [1, 2, 6, 12]) {
    assert.equal(selectEngineLeads(candidates, cap).length, Math.min(cap, 9))
  }
})

// ---------------------------------------------------------------------------------------------
// Engine emission + fact payload
// ---------------------------------------------------------------------------------------------

function endpoint(over: Partial<EngineEndpoint> & Pick<EngineEndpoint, 'method' | 'pathTemplate'>): EngineEndpoint {
  return { id: `${over.method}:${over.pathTemplate}`, origin, params: [], riskScore: 55, ...over }
}

function fakeExchange(req: { origin: string; method: string; pathAndQuery: string; persona?: string }): BrokerExchangeResult {
  const body = req.pathAndQuery.includes('/api/invoices/')
    ? JSON.stringify({ id: 'inv_1', amount: 10, tenant_id: 'f6e944' })
    : JSON.stringify({ id: 'person_1', name: 'Alex', tenant_id: 'f6e944' })
  return {
    origin: req.origin,
    finalOrigin: req.origin,
    redirectOrigins: [],
    method: req.method,
    pathAndQuery: req.pathAndQuery,
    personaHandle: req.persona ?? null,
    status: 200,
    mediaType: 'application/json',
    reqHeaders: {},
    respHeaders: {},
    body,
    bodyPreview: body.slice(0, 200),
    bodyBytes: body.length,
    bodySha256: `sha-${body.length}`,
    durationMs: 2,
    secretMatches: [],
    setCookies: [],
  } as unknown as BrokerExchangeResult
}

function engineInput(over: Partial<DeterministicEngineInput>): DeterministicEngineInput {
  const broker = { executeHttp: async (req: { origin: string; method: string; pathAndQuery: string; persona?: string }) => fakeExchange(req) } as unknown as RequestBroker
  return {
    runId: randomUUID(),
    assignmentId: randomUUID(),
    signal: new AbortController().signal,
    endpoints: [],
    personas,
    broker,
    grant: { tier: 2, personas: [], secrets: [], canRead: () => true, audit: () => {} } as unknown as Grant,
    backend: {} as WorkerBackend,
    tier: 2,
    maxRequests: 200,
    maxDurationMs: 20_000,
    onConfirmed: () => 'finding-1',
    ...over,
  }
}

test('engine emits a denied-control lead with evidence fields on the emitted object', async () => {
  const leads: EngineLead[] = []
  const report = await runDeterministicEngine(engineInput({
    endpoints: [endpoint({ method: 'GET', pathTemplate: '/api/invoices/:invoiceId', params: [{ name: 'invoiceId', location: 'path' }] })],
    probe: async req => {
      if (req.probeClass !== 'authz_matrix') return signal({ probeClass: req.probeClass, verdict: 'no_signal', anomalies: [], details: {}, exchangeIds: [] })
      return signal({
        pathAndQuery: req.pathAndQuery,
        anomalies: [{ type: 'unauthorized_access', resourceId: 'inv_1', actor: 'other_persona', method: 'GET', status: 200, similarityToOwner: 0.8 }],
        details: {
          matrix: [
            { resourceId: 'inv_1', actor: 'owner', status: 200, accessible: true, bodyBytes: 64 },
            { resourceId: 'inv_1', actor: 'other_persona', status: 200, accessible: true, bodyBytes: 64, similarityToOwner: 0.8 },
            { resourceId: 'inv_1', actor: 'anonymous', status: 403, accessible: false },
          ],
        },
      })
    },
    verify: async () => ({
      verdict: 'dismissed',
      outcome: { confirmed: false, controlPassed: true, observed: 'probe status=200', expected: 'non-owner denied', reason: 'Authorization claim rests on a different-body observation without identifier binding.' },
      exchangeIds: ['ex-read-verify'],
      exchanges: [],
      evidencePayload: {},
      evidenceSha256: 'sha',
    }),
    onLead: lead => { leads.push(lead) },
  }))

  assert.ok(report.leads > 0, 'a genuine read differential emits a lead')
  assert.equal(leads.length, report.leads)
  const lead = leads.find(item => item.hypothesis.endpoint.pathTemplate === '/api/invoices/:invoiceId')
  assert.ok(lead, 'invoice route produced the lead')
  assert.ok(lead!.evidence, 'emitted leads always carry evidence')
  assert.equal(lead!.evidence!.kind, 'denied_control')
  assert.equal(lead!.evidence!.candidateProbeClass, 'authz_matrix')
  assert.ok(lead!.evidence!.evidenceExchangeIds.length > 0)
  assert.match(lead!.evidence!.controlOutcome, /actor_denied_403/)
  assert.ok(lead!.evidence!.verifyFailureReason, 'verifier wording is carried for the dispatcher')
})

test('engine emits 0 leads for a non-selective DELETE matrix', async () => {
  const leads: EngineLead[] = []
  const report = await runDeterministicEngine(engineInput({
    endpoints: [endpoint({ method: 'DELETE', pathTemplate: '/api/people/:personId', params: [{ name: 'personId', location: 'path' }] })],
    probe: async req => {
      if (req.probeClass !== 'authz_matrix') return signal({ probeClass: req.probeClass, verdict: 'no_signal', anomalies: [], details: {}, exchangeIds: [] })
      return signal({
        pathAndQuery: req.pathAndQuery,
        anomalies: [{ type: 'unauthorized_access', resourceId: 'person_1', actor: 'other_persona', method: 'DELETE', status: 200, similarityToOwner: 1 }],
        details: {
          matrix: [
            { resourceId: 'person_1', actor: 'owner', status: 200, accessible: true },
            { resourceId: 'person_1', actor: 'other_persona', status: 200, accessible: true },
            { resourceId: 'person_1', actor: 'anonymous', status: 401, accessible: false },
          ],
        },
      })
    },
    verify: async () => ({
      verdict: 'inconclusive',
      outcome: { confirmed: false, controlPassed: false, observed: 'probe status=200 after status=200 bogus status=200', expected: 'the mutation is denied and the protected state is unchanged' },
      exchangeIds: ['ex-delete-verify'],
      exchanges: [],
      evidencePayload: {},
      evidenceSha256: 'sha',
    }),
    onLead: lead => { leads.push(lead) },
  }))

  assert.equal(report.leads, 0, 'the false DELETE observation must not become a lead')
  assert.equal(leads.length, 0)
  assert.ok(report.leadsSuppressed > 0, 'the suppression is observable in the report')
})

test('fact payload carries the evidence fields and the dispatcher reads them', () => {
  const fields = detLeadEvidenceFactFields({
    kind: 'near_miss',
    verifyFailureReason: 'Authorization claim rests on a different-body observation without identifier binding.',
    verifyFailureCode: 'missing_identifier_binding',
    controlOutcome: 'bogus_id_denied_404',
    evidenceExchangeIds: ['ex-1', 'ex-2', 'ex-1'],
    candidateProbeClass: 'authz_matrix',
    detail: 'mutating 2xx with a denied bogus-id control',
  })
  assert.equal(fields.verifyFailureReason, 'Authorization claim rests on a different-body observation without identifier binding.')
  assert.equal(fields.verifyFailureCode, 'missing_identifier_binding')
  assert.equal(fields.controlOutcome, 'bogus_id_denied_404')
  assert.equal(fields.candidateProbeClass, 'authz_matrix')
  assert.deepEqual(fields.evidenceExchangeIds, ['ex-1', 'ex-2'])
  assert.equal(fields.leadEvidenceKind, 'near_miss')
  assert.equal(leadEvidenceRiskBonus(fields), 12)

  const leads = detLeadsFromParentFacts([{
    data: {
      kind: 'det_lead',
      probeClass: 'authz_matrix',
      endpoint: '/api/people/:personId',
      method: 'DELETE',
      reason: 'unproven signal',
      ...fields,
    },
  }])
  assert.equal(leads.length, 1)
  assert.equal(leads[0]!.verifyFailureReason, fields.verifyFailureReason)
})
