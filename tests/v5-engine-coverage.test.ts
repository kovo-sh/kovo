/**
 * v5 engine-coverage: probe-family ports and converter gaps.
 *
 * Covers the deterministic engine's use of already-shipped probe classes that were previously
 * unreachable (template math, command injection, workflow invariant) and the converter fixes that
 * turn an observed differential into an identifier-bound replay spec. Everything here is
 * route-shape/response-shape derived; no app, route, seed or benchmark literal is consulted.
 */
import assert from 'node:assert/strict'
import { describe, test } from 'node:test'

import { declarativeReplaySpecSchema } from '../src/replay-spec.ts'
import {
  enumerateHypotheses,
  pathHasCommandHint,
  pathHasTemplateHint,
} from '../src/server/deterministic-engine.ts'
import type { EndpointHarvest, EngineEndpoint, EngineHypothesis, EnginePersona } from '../src/server/deterministic-engine.ts'
import { synthesizeEngineSpecs } from '../src/server/deterministic-specs.ts'
import type { DifferentialResult } from '../src/server/surface-engine.ts'

process.env.GUARDIAN_ALLOW_LOCAL_LAB = '1'

const personas: EnginePersona[] = [
  { handle: 'persona-a', roleLabel: 'owner (t1)', privilege: 'member', tenant: 't1' },
  { handle: 'persona-b', roleLabel: 'owner (t2)', privilege: 'member', tenant: 't2' },
  { handle: 'viewer', roleLabel: 'viewer (t1)', privilege: 'viewer', tenant: 't1' },
]

function endpoint(over: Partial<EngineEndpoint> & Pick<EngineEndpoint, 'method' | 'pathTemplate'>): EngineEndpoint {
  return {
    id: `${over.method}:${over.pathTemplate}`,
    origin: 'http://127.0.0.1:4100',
    params: [],
    riskScore: 40,
    ...over,
  }
}

function harvest(over: Partial<EndpointHarvest> = {}): EndpointHarvest {
  return {
    ownerIds: [],
    otherIds: [],
    fields: [],
    values: {},
    otherValues: {},
    seedValues: [],
    activeQueryParams: [],
    ...over,
  }
}

function signal(over: Partial<DifferentialResult>): DifferentialResult {
  return {
    probeClass: 'ssti_math',
    origin: 'http://127.0.0.1:4100',
    pathAndQuery: '/api/docs/render',
    verdict: 'signal',
    summary: 'differential',
    anomalies: [],
    details: {},
    requestsSent: 4,
    exchangeIds: [],
    stoppedReason: null,
    notes: [],
    durationMs: 2,
    ...over,
  }
}

describe('route-shape gates for newly ported probe families', () => {
  test('render/evaluate routes are recognised without a route wordlist', () => {
    assert.equal(pathHasTemplateHint('/api/docs/render'), true)
    assert.equal(pathHasTemplateHint('/api/reports/preview'), true)
    assert.equal(pathHasTemplateHint('/api/invoices/:invoiceId'), false)
  })

  test('host/command diagnostic routes are recognised', () => {
    assert.equal(pathHasCommandHint('/api/diagnostics/run'), true)
    assert.equal(pathHasCommandHint('/api/tools/ping'), true)
    assert.equal(pathHasCommandHint('/api/orders/:orderId'), false)
  })
})

describe('new hypothesis enumeration', () => {
  test('a render write forms a template-math hypothesis on a semantic body field', () => {
    const surface = [endpoint({ method: 'POST', pathTemplate: '/api/docs/render' })]
    const hypotheses = enumerateHypotheses(surface, new Map(), { tier: 3, personas })
    const sstiHyps = hypotheses.filter(hyp => hyp.intent === 'ssti')
    assert.ok(sstiHyps.length >= 1)
    assert.ok(sstiHyps.every(hyp => hyp.probeClass === 'ssti_math' && hyp.method === 'POST' && hyp.location === 'json'))
    const paramNames = sstiHyps.map(hyp => hyp.param?.name)
    assert.ok(paramNames.includes('template'), `expected 'template' in ${JSON.stringify(paramNames)}`)
    assert.ok(paramNames.includes('content'), `expected 'content' in ${JSON.stringify(paramNames)}`)
  })

  test('a diagnostic write prefers the field name the target published over the fallback', () => {
    const surface = [endpoint({ method: 'POST', pathTemplate: '/api/diagnostics/run' })]
    const harvests = new Map<string, EndpointHarvest>([
      ['POST:/api/diagnostics/run', harvest({ seedValues: ['endpointHost'] })],
    ])
    const hypotheses = enumerateHypotheses(surface, harvests, { tier: 3, personas })
    const cmdi = hypotheses.find(hyp => hyp.intent === 'command_injection')
    assert.ok(cmdi)
    assert.equal(cmdi.probeClass, 'command_injection')
    assert.equal(cmdi.param?.name, 'endpointHost')
  })

  test('an identified PATCH write forms a mass-assignment hypothesis with the real method', () => {
    const surface = [endpoint({ method: 'PATCH', pathTemplate: '/api/people/:personId' })]
    const harvests = new Map<string, EndpointHarvest>([
      ['PATCH:/api/people/:personId', harvest({ ownerIds: ['per_1'], fields: ['id', 'name', 'role'] })],
    ])
    const hypotheses = enumerateHypotheses(surface, harvests, { tier: 3, personas })
    const mass = hypotheses.find(hyp => hyp.intent === 'mass_assignment')
    assert.ok(mass)
    assert.equal(mass.method, 'PATCH')
    assert.equal(mass.pathAndQuery, '/api/people/per_1')
    assert.ok(mass.candidateFields?.includes('role'))
  })

  test('a role overpost runs as the viewer against a colleague record', () => {
    const surface = [endpoint({ method: 'PATCH', pathTemplate: '/api/people/:personId' })]
    const harvests = new Map<string, EndpointHarvest>([
      ['PATCH:/api/people/:personId', harvest({ ownerIds: ['per_owner', 'per_admin'], viewerIds: ['per_viewer'], fields: ['id', 'name', 'role'] })],
    ])
    const hypotheses = enumerateHypotheses(surface, harvests, { tier: 3, personas })
    const mass = hypotheses.find(hyp => hyp.intent === 'mass_assignment')
    assert.ok(mass)
    assert.equal(mass.ownerPersona, 'viewer')
    assert.equal(mass.pathAndQuery, '/api/people/per_admin')
  })

  test('a credential-bearing collection read enables the viewer secret scan', () => {
    const surface = [endpoint({ method: 'GET', pathTemplate: '/api/links' })]
    const hypotheses = enumerateHypotheses(surface, new Map(), { tier: 3, personas })
    const disclosure = hypotheses.find(hyp => hyp.intent === 'secret_disclosure')
    assert.ok(disclosure)
    assert.equal(disclosure.functionLevel, true)
    assert.equal(disclosure.secretScan, true)
    assert.equal(disclosure.viewerPersona, 'viewer')
  })

  test('a terminal transition with a readable collection forms a workflow hypothesis', () => {    const surface = [
      endpoint({ method: 'GET', pathTemplate: '/api/jobs' }),
      endpoint({ method: 'GET', pathTemplate: '/api/jobs/:jobId' }),
      endpoint({ method: 'POST', pathTemplate: '/api/jobs/:jobId/complete' }),
    ]
    const hypotheses = enumerateHypotheses(surface, new Map(), { tier: 3, personas })
    const workflow = hypotheses.find(hyp => hyp.intent === 'workflow')
    assert.ok(workflow)
    assert.equal(workflow.probeClass, 'workflow_invariant')
    assert.equal(workflow.repeatTransition, true)
    assert.equal(workflow.workflowListPath, '/api/jobs')
    assert.equal(workflow.workflowReadPath, '/api/jobs/:jobId')
    assert.equal(workflow.workflowTargetTemplate, '/api/jobs/:jobId/complete')
    assert.equal(workflow.pathAndQuery, '/api/jobs/{{id}}/complete')
  })
})

describe('new replay-spec converters', () => {
  const baseHypothesis: EngineHypothesis = {
    key: 'ssti',
    endpoint: endpoint({ method: 'POST', pathTemplate: '/api/docs/render' }),
    probeClass: 'ssti_math',
    intent: 'ssti',
    method: 'POST',
    pathAndQuery: '/api/docs/render',
    param: { name: 'template', location: 'json' },
    location: 'json',
    jsonBody: {},
    ownerPersona: 'persona-a',
    risk: 80,
  }

  test('template evaluation becomes a verifier-minted dynamic-math proof', () => {
    const specs = synthesizeEngineSpecs(baseHypothesis, signal({
      anomalies: [{ type: 'expression_evaluated', engine: 'jinja2/twig' }],
    }))
    assert.equal(specs.length, 1)
    assert.equal(specs[0].vulnClass, 'ssti')
    const parsed = declarativeReplaySpecSchema.safeParse(specs[0].spec)
    assert.equal(parsed.success, true, parsed.success ? '' : parsed.error.issues[0]?.message)
    const serialized = JSON.stringify((specs[0].spec as { probeStep: unknown }).probeStep)
    assert.ok(serialized.includes('{{nonce_a}}'))
    assert.ok(serialized.includes('{{nonce_b}}'))
  })

  test('command execution becomes a split-echo proof without literal nonce adjacency', () => {
    const hyp: EngineHypothesis = {
      ...baseHypothesis,
      key: 'cmdi',
      endpoint: endpoint({ method: 'POST', pathTemplate: '/api/diagnostics/run' }),
      probeClass: 'command_injection',
      intent: 'command_injection',
      pathAndQuery: '/api/diagnostics/run',
      param: { name: 'endpointHost', location: 'json' },
    }
    const specs = synthesizeEngineSpecs(hyp, signal({
      probeClass: 'command_injection',
      anomalies: [{ type: 'command_executed', variant: 'semicolon_echo', baseValue: '127.0.0.1', nonce: 'gnabcdef0123', payload: '127.0.0.1; echo gnabcdef0123' }],
    }))
    assert.equal(specs.length, 2)
    assert.equal(specs[0].vulnClass, 'command_injection')
    const parsed = declarativeReplaySpecSchema.safeParse(specs[0].spec)
    assert.equal(parsed.success, true, parsed.success ? '' : parsed.error.issues[0]?.message)
    const serialized = JSON.stringify((specs[0].spec as { probeStep: unknown }).probeStep)
    assert.ok(serialized.includes('{{nonce_part1}}'))
    assert.ok(serialized.includes('{{nonce_part2}}'))
    // The observed-nonce chain fallback is schema-valid too.
    assert.equal(declarativeReplaySpecSchema.safeParse(specs[1].spec).success, true)
  })

  test('a compact PATCH acknowledgement still yields an identifier-bound authz spec', () => {
    const hyp: EngineHypothesis = {
      key: 'authz-patch',
      endpoint: endpoint({ method: 'PATCH', pathTemplate: '/api/invoices/:invoiceId' }),
      probeClass: 'authz_matrix',
      intent: 'authz',
      method: 'PATCH',
      pathAndQuery: '/api/invoices/{{id}}',
      ownerPersona: 'persona-a',
      otherPersona: 'persona-b',
      resourceIds: ['inv_1'],
      jsonBody: { amount: 10, status: 'open' },
      risk: 90,
    }
    const result = signal({
      probeClass: 'authz_matrix',
      pathAndQuery: '/api/invoices/{{id}}',
      anomalies: [{ type: 'unauthorized_access', resourceId: 'inv_1', actor: 'other_persona', method: 'PATCH', status: 200 }],
      details: {
        matrix: [
          { resourceId: 'inv_1', actor: 'owner', status: 200, bodyBytes: 10, bodySha256: 'a', accessible: true },
          { resourceId: 'inv_1', actor: 'other_persona', status: 200, bodyBytes: 10, bodySha256: 'a', accessible: true },
        ],
      },
    })
    const specs = synthesizeEngineSpecs(hyp, result)
    assert.equal(specs.length, 1)
    assert.equal(specs[0].vulnClass, 'bola')
    assert.equal(declarativeReplaySpecSchema.safeParse(specs[0].spec).success, true)
    const steps = (specs[0].spec.steps as Array<{ id: string; request: { method: string } }>)
    assert.equal(steps.find(step => step.id === 'p1')?.request.method, 'PATCH')
  })

  test('an OR-branch boolean spec tries a fresh non-matching baseline first and keeps the empty fallback', () => {
    const hyp: EngineHypothesis = {
      key: 'sqli-search',
      endpoint: endpoint({ method: 'GET', pathTemplate: '/api/v1/search' }),
      probeClass: 'sqli_boolean',
      intent: 'sqli',
      method: 'GET',
      pathAndQuery: '/api/v1/search',
      param: { name: 'query', location: 'query' },
      location: 'query',
      baselineValue: 'guardian',
      ownerPersona: 'persona-a',
      risk: 80,
    }
    const specs = synthesizeEngineSpecs(hyp, signal({
      probeClass: 'sqli_boolean',
      pathAndQuery: '/api/v1/search',
      anomalies: [{ type: 'boolean_differential', style: 'or_branch' }],
    }))
    assert.ok(specs.length >= 2)
    assert.match((specs[1].spec as { baselineValue?: string }).baselineValue ?? '', /^guardian-[0-9a-f]{8}$/)
    assert.ok(
      specs.some(s => (s.spec as { baselineValue?: string }).baselineValue === ''),
      'expected empty-string fallback baseline in OR-branch candidates',
    )
  })

  test('a fingerprint-proven disclosure does not rely on the scrubbed body', () => {
    const hyp: EngineHypothesis = {
      key: 'secret',
      endpoint: endpoint({ method: 'GET', pathTemplate: '/api/links' }),
      probeClass: 'authz_matrix',
      intent: 'secret_disclosure',
      method: 'GET',
      pathAndQuery: '/api/links',
      ownerPersona: 'persona-a',
      functionLevel: true,
      secretScan: true,
      viewerPersona: 'viewer',
      risk: 90,
    }
    const result = signal({
      probeClass: 'authz_matrix',
      pathAndQuery: '/api/links',
      anomalies: [{
        type: 'secret_disclosed', path: '/api/links', persona: 'viewer', actor: 'viewer_persona',
        secretPattern: '\\brb[cst]_[A-Za-z0-9]+_[0-9a-f]{12}\\b',
        secretFingerprints: ['ff86d8824e34'], secretEvidence: 'fingerprint',
      }],
    })
    const specs = synthesizeEngineSpecs(hyp, result)
    assert.equal(specs.length, 1)
    assert.equal(specs[0].vulnClass, 'info_disclosure')
    assert.equal(declarativeReplaySpecSchema.safeParse(specs[0].spec).success, true)
    assert.ok((specs[0].spec.assertionsJq as string).includes('secretMatches'))
  })

  test('a repeated terminal transition becomes a schema-valid step-skip chain', () => {
    const hyp: EngineHypothesis = {
      ...baseHypothesis,
      key: 'workflow',
      endpoint: endpoint({ method: 'POST', pathTemplate: '/api/jobs/:jobId/complete' }),
      probeClass: 'workflow_invariant',
      intent: 'workflow',
      method: 'POST',
      pathAndQuery: '/api/jobs/{{id}}/complete',
      param: undefined,
      location: undefined,
      workflowTargetTemplate: '/api/jobs/:jobId/complete',
      repeatTransition: true,
      jsonBody: {},
    }
    const specs = synthesizeEngineSpecs(hyp, signal({
      probeClass: 'workflow_invariant',
      anomalies: [{
        type: 'workflow_step_skip', repeatTransition: true,
        targetTemplate: '/api/jobs/{{id}}/complete', targetId: 'job_1', targetBody: {}, status: 200,
      }],
    }))
    assert.equal(specs.length, 1)
    assert.equal(specs[0].vulnClass, 'workflow_bypass')
    assert.equal((specs[0].spec as { cwe?: string }).cwe, 'CWE-840')
    const parsed = declarativeReplaySpecSchema.safeParse(specs[0].spec)
    assert.equal(parsed.success, true, parsed.success ? '' : parsed.error.issues[0]?.message)
    const steps = (specs[0].spec.steps as Array<{ id: string; request: { pathAndQuery: string } }>)
    assert.equal(steps.find(step => step.id === 'p1')?.request.pathAndQuery, '/api/jobs/job_1/complete')
  })

  test('an unproven signal yields no ported spec', () => {
    assert.deepEqual(synthesizeEngineSpecs(baseHypothesis, signal({ verdict: 'no_signal', anomalies: [] })), [])
  })
})
