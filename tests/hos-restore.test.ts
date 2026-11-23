/**
 * hos-restore: generic inference rules that restored the held-out SaaS floor after verifier hardening.
 *
 * Covered here:
 *  - function-level mutating proofs must carry a *separate* state readback (never the echo)
 *  - sibling observable-read inference for server actions (action name -> GET status route)
 *  - benign control-body derivation so the replay delta is attributable
 *  - shared-endpoint attribution by mutated parameter/GraphQL selection binding (no double credit)
 *  - read-only GraphQL queries over POST are reads, not state changes
 *
 * No benchmark-app literal appears in these assertions: every input is a synthetic shape.
 */
import assert from 'node:assert/strict'
import { describe, test } from 'node:test'

// Replay specs for loopback lab origins are only schema-valid in local-lab mode.
process.env.GUARDIAN_ALLOW_LOCAL_LAB = '1'

import {
  actionStateTokens,
  alternateStateValue,
  buildStateVariants,
  flattenScalars,
  inferObservableReadRoutes,
  scalarDeltas,
} from '../scripts/benchmark-probes.ts'
import type { DiscoveredEndpoint, Hypothesis, HypothesisOutcome, ProbeEnv, ProfileCaps } from '../scripts/benchmark-probes.ts'
import { synthesizeSpecs } from '../scripts/benchmark-specs.ts'
import { endpointKey, scoreChallenge, sharedEndpointKeys, specBindsParam, specSubjectOf } from '../scripts/benchmark-score.ts'
import type { ScoredOutcome } from '../scripts/benchmark-score.ts'
import type { ManifestChallenge } from '../scripts/benchmark-core.ts'
import { assessAuthorizationImpact, isReadOnlyGraphqlRequest, stepMutatesState, stepReadsState } from '../src/server/oracle-invariants.ts'
import type { ActorIdentity, ImpactStep } from '../src/server/oracle-invariants.ts'

const caps: ProfileCaps = {
  mode: 'v4-full',
  phase0Recon: true,
  locations: new Set(['query', 'json', 'form', 'path', 'header', 'xml', 'graphql_var']),
  newProbeClasses: true,
  sessionAndCsrf: false,
  authMutation: true,
  timeDiff: true,
  inlineRetries: 2,
  tier: 3,
}

function env(over: Partial<ProbeEnv> = {}): ProbeEnv {
  return {
    origin: 'http://127.0.0.1:41000',
    broker: {} as ProbeEnv['broker'],
    grant: {} as ProbeEnv['grant'],
    storage: {} as ProbeEnv['storage'],
    runId: 'run-test',
    signal: AbortSignal.timeout(5_000),
    caps,
    owner: 'persona_a',
    other: 'persona_b',
    admin: 'admin',
    viewer: 'viewer',
    session: 'bench',
    slowProbesLeft: 10,
    ...over,
  } as ProbeEnv
}

// ---------------------------------------------------------------------------
// Sibling observable-read inference
// ---------------------------------------------------------------------------

describe('hos-restore: observable read inference', () => {
  test('action name tokens drop verbs and keep resource/state nouns', () => {
    assert.deepEqual(actionStateTokens('/_actions/updateOrgPlan'), ['org', 'plan'])
    assert.deepEqual(actionStateTokens('/_actions/resetPassword'), ['password'])
  })

  test('server-action read route is inferred from the action name and the route map', () => {
    const routes = ['/_actions/updateOrgPlan', '/api/v1/profile', '/api/v1/org', '/api/v1/org/{id}', '/health']
    assert.deepEqual(inferObservableReadRoutes('/_actions/updateOrgPlan', routes), ['/api/v1/org', '/api/v1/org/{id}'])
  })

  test('no inference when the action shares no noun with any read route', () => {
    assert.deepEqual(inferObservableReadRoutes('/_actions/rotateSigningKey', ['/api/v1/org', '/api/v1/profile']), [])
  })
})

// ---------------------------------------------------------------------------
// Control/probe body derivation
// ---------------------------------------------------------------------------

describe('hos-restore: state variant derivation', () => {
  test('booleans are negated for the control while the selector is preserved', () => {
    const variants = buildStateVariants({ flag: 'beta', enabled: true }, new Set(['flags\u0000beta']))
    assert.deepEqual(variants?.controlBody, { flag: 'beta', enabled: false })
    assert.deepEqual(variants?.probeBody, { flag: 'beta', enabled: true })
  })

  test('positional RPC bodies keep the target argument and vary the state argument', () => {
    const variants = buildStateVariants(['acme', 'team'], new Set(['id\u0000acme', 'plan\u0000team']))
    assert.deepEqual(variants?.controlBody, ['acme', 'team_ctrl'])
    assert.deepEqual(variants?.probeBody, ['acme', 'team'])
  })

  test('a body with no variable state field is rejected (nothing to prove)', () => {
    assert.equal(buildStateVariants({ id: '1' }, new Set()), null)
    assert.equal(buildStateVariants({}, new Set()), null)
    assert.equal(buildStateVariants('text', new Set()), null)
  })

  test('alternate values are format-preserving and always distinct', () => {
    assert.equal(alternateStateValue(true, 'ctrl'), false)
    assert.equal(alternateStateValue(7, 'ctrl'), 8)
    assert.equal(alternateStateValue('team', 'ctrl'), 'team_ctrl')
    assert.notEqual(alternateStateValue('team', 'ctrl'), 'team')
  })

  test('delta discovery prefers state fields and ignores volatile metadata', () => {
    const before = { id: '1', plan: 'team', updatedAt: 't1', flags: { beta: false } }
    const after = { id: '1', plan: 'enterprise', updatedAt: 't2', flags: { beta: true } }
    const deltas = scalarDeltas(before, after)
    assert.ok(deltas.length > 0)
    assert.deepEqual(deltas[0].path, ['plan'])
    assert.ok(!deltas.some(delta => delta.path.includes('updatedAt')))
  })

  test('flattenScalars keeps raw scalar types', () => {
    const flat = flattenScalars({ flags: { beta: true }, count: 2 })
    assert.equal(flat.get('flags\u0000beta'), true)
    assert.equal(flat.get('count'), 2)
  })
})

// ---------------------------------------------------------------------------
// Function-state spec synthesis
// ---------------------------------------------------------------------------

describe('hos-restore: function-state delta spec', () => {
  const action = (): DiscoveredEndpoint => ({ method: 'POST', path: '/api/v1/admin/feature-flags', params: [], source: 'openapi' })

  function outcome(over: Partial<HypothesisOutcome> = {}): HypothesisOutcome {
    const ep = action()
    const hyp: Hypothesis = { key: 'k', endpoint: ep, probeClass: 'authz_matrix', method: 'POST' }
    return {
      hyp,
      verdict: 'signal',
      anomalies: [{ type: 'unauthorized_access', actor: 'other_persona', method: 'POST', status: 200, functionLevel: true, bodyTemplate: { flag: 'beta', enabled: true } }],
      details: {
        functionState: {
          path: '/api/v1/admin/feature-flags',
          controlBody: { flag: 'beta', enabled: false },
          probeBody: { flag: 'beta', enabled: true },
          fieldPath: ['flags', 'beta'],
          controlValue: false,
          probeValue: true,
        },
      },
      csrfRejected: false,
      contextReset: false,
      tierBlocked: false,
      requests: 6,
      pair: { owner: 'admin', other: 'viewer' },
      ...over,
    }
  }

  test('emits a control-write / read / probe-write / read chain bound to the changed field', () => {
    const specs = synthesizeSpecs(outcome(), env())
    assert.equal(specs.length, 1)
    const spec = specs[0].spec as {
      steps: Array<{ id: string; role: string; request: { method: string; persona?: string } }>
      assertionsJq: string
      requiredRole?: string
      expectedImpactEvents?: string[]
    }
    assert.deepEqual(spec.steps.map(step => step.id), ['w1', 'c1', 'p1', 'p2'])
    assert.deepEqual(spec.steps.map(step => step.request.method), ['POST', 'GET', 'POST', 'GET'])
    assert.equal(spec.steps[0].request.persona, 'admin')
    assert.equal(spec.steps[2].request.persona, 'viewer')
    assert.match(spec.assertionsJq, /\.steps\.c1\.json\["flags"\]\["beta"\] == false/)
    assert.match(spec.assertionsJq, /\.steps\.p2\.json\["flags"\]\["beta"\] == true/)
    assert.equal(spec.requiredRole, 'admin')
    assert.deepEqual(spec.expectedImpactEvents, ['state_delta'])
  })

  test('identifier binding is asserted on both readback steps when observed', () => {
    const base = outcome()
    const state = (base.details.functionState as Record<string, unknown>)
    const specs = synthesizeSpecs(outcome({
      details: { functionState: { ...state, bindingPath: ['id'], bindingValue: 'acme' } },
    }), env())
    const jq = (specs[0]?.spec as { assertionsJq?: string }).assertionsJq ?? ''
    assert.match(jq, /\.steps\.c1\.json\["id"\] == "acme"/)
    assert.match(jq, /\.steps\.p2\.json\["id"\] == "acme"/)
  })

  test('no function-state observation means no echo-only confirmation spec', () => {
    const specs = synthesizeSpecs(outcome({ details: {} }), env())
    for (const candidate of specs) {
      const jq = (candidate.spec as { assertionsJq?: string }).assertionsJq ?? ''
      assert.ok(!/only the privileged role may change function state/.test(jq))
    }
  })
})

// ---------------------------------------------------------------------------
// Shared-endpoint attribution
// ---------------------------------------------------------------------------

describe('hos-restore: shared-endpoint attribution', () => {
  const sharedSpec = (over: Record<string, unknown>) => ({ kind: 'http_chain', origin: 'http://127.0.0.1:1', assertionsJq: '', steps: [], ...over })
  const sqliSpec = sharedSpec({ paramName: 'sku', kind: 'sql_boolean_diff' })
  const resolverSpec = sharedSpec({ graphqlQuery: 'query($id: ID!){ user(id: $id){ invoices { id } } }' })

  test('an explicit parameter binding only matches its own declared input', () => {
    const sqliSubject = specSubjectOf(sqliSpec)
    assert.equal(specBindsParam(sqliSubject, 'sku'), true)
    assert.equal(specBindsParam(sqliSubject, 'user.invoices'), false)
    const resolverSubject = specSubjectOf(resolverSpec)
    assert.equal(specBindsParam(resolverSubject, 'user.invoices'), true)
    assert.equal(specBindsParam(resolverSubject, 'sku'), false)
  })

  test('a spec without an observable subject stays attributable (no false exclusion)', () => {
    assert.equal(specBindsParam(specSubjectOf(sharedSpec({})), 'sku'), true)
    assert.equal(specBindsParam(undefined, 'sku'), true)
    assert.equal(specBindsParam(specSubjectOf(sqliSpec), undefined), true)
  })

  test('shared endpoints are detected from the manifest and keyed by template', () => {
    const challenges = [
      { id: 'a', endpoint: '/graphql', isDecoy: false },
      { id: 'b', endpoint: '/graphql', isDecoy: false },
      { id: 'c', endpoint: '/api/items/{id}', isDecoy: false },
    ]
    const shared = sharedEndpointKeys(challenges)
    assert.deepEqual([...shared], ['/graphql'])
    assert.equal(endpointKey('/api/items/:id'), endpointKey('/api/items/{id}'))
  })

  test('one confirming spec is not credited to both targets on a shared endpoint', () => {
    const challenge = (id: string, vulnClass: string, param: string): ManifestChallenge => ({
      id, vulnClass, endpoint: '/graphql', method: 'POST', param, isDecoy: false,
    } as ManifestChallenge)
    const base: Omit<ScoredOutcome, 'specSubject'> = {
      path: '/graphql', probeClass: 'sqli_boolean', signal: true, specSubmitted: true, confirmed: true,
      csrfRejected: false, contextReset: false, tierBlocked: false, jqError: false, spaCatchall: false, skippedForBudget: false,
    }
    const input = {
      discoveredPaths: ['/graphql'],
      outcomes: [{ ...base, specSubject: specSubjectOf(sqliSpec) }],
      encodingSkipPaths: [],
      budgetSkippedPaths: [],
      sharedEndpointKeys: new Set(['/graphql']),
    }
    const sqli = scoreChallenge(challenge('sqli', 'graphql_sqli', 'sku'), input)
    const bola = scoreChallenge(challenge('bola', 'graphql_bola', 'user.invoices'), input)
    assert.equal(sqli.confirmed, true)
    assert.equal(bola.confirmed, false)
    // The funnel still records that the hypothesis was formed and signalled on the route.
    assert.equal(bola.hypothesisFormed, true)
    assert.equal(bola.signalObserved, true)
  })
})

// ---------------------------------------------------------------------------
// Read-only GraphQL over POST
// ---------------------------------------------------------------------------

describe('hos-restore: read-only GraphQL classification', () => {
  test('query documents over POST are reads; mutations stay state-changing', () => {
    const query = { method: 'POST', requestJson: { query: 'query($id: ID!){ node(id: $id){ id } }' } }
    const shorthand = { method: 'POST', requestJson: { query: '{ __typename }' } }
    const mutation = { method: 'POST', requestJson: { query: 'mutation { deleteOrg(id: "1") { ok } }' } }
    const opaque = { method: 'POST', requestJson: { payload: 'binary' } }
    assert.equal(isReadOnlyGraphqlRequest(query), true)
    assert.equal(isReadOnlyGraphqlRequest(shorthand), true)
    assert.equal(isReadOnlyGraphqlRequest(mutation), false)
    assert.equal(isReadOnlyGraphqlRequest(opaque), false)
    assert.equal(stepReadsState(query), true)
    assert.equal(stepMutatesState(query), false)
    assert.equal(stepMutatesState(mutation), true)
  })

  test('a cross-actor GraphQL query is judged as a read disclosure, not an unreadable mutation', () => {
    const actor = (handle: string, role: ActorIdentity['role'], tenant: string): ActorIdentity => ({
      handle, role, tenant, auth: 'bearer', sameSite: null,
    })
    const graphqlQuery = { query: 'query($id: ID!){ user(id: $id){ id tenantId invoices { id memo } } }' }
    const body = JSON.stringify({ data: { user: { id: 'u-owner', tenantId: 'tenant-a', invoices: [{ id: '7', memo: 'renewal' }] } } })
    const step = (id: string, arm: 'control' | 'probe', handle: string, role: ActorIdentity['role'], tenant: string): ImpactStep => ({
      id, arm, method: 'POST', route: '/graphql', status: 200,
      actor: actor(handle, role, tenant),
      json: JSON.parse(body), body, requestJson: graphqlQuery,
    })
    const assessment = assessAuthorizationImpact({
      impactClass: 'authorization',
      steps: [step('c1', 'control', 'owner', 'member', 'tenant-a'), step('p1', 'probe', 'other', 'member', 'tenant-b')],
    })
    assert.equal(assessment.satisfied, true, assessment.reason)
    assert.equal(assessment.evidence.persisted, false)
  })
})
