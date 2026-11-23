/**
 * v5 final specs batch: identifier-bound state-delta proofs for trivial `{ok:true}` mutations and
 * pre-redaction secret-fingerprint assertions. Each case evaluates the synthesized jq against the
 * exact verifier evidence shape, so a trivial acknowledgement cannot confirm and a persisted/absent
 * state change is what does.
 */
import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import { test } from 'node:test'

process.env.GUARDIAN_ALLOW_LOCAL_LAB = '1'

import { declarativeReplaySpecSchema } from '../src/replay-spec.ts'
import { synthesizeSpecs } from '../scripts/benchmark-specs.ts'
import { formHypotheses } from '../scripts/benchmark-probes.ts'
import type { DiscoveredEndpoint, HypothesisOutcome, ProbeEnv, ProfileCaps } from '../scripts/benchmark-probes.ts'

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
    runId: 'run-final-specs',
    signal: AbortSignal.timeout(10_000),
    caps,
    owner: 'owner',
    other: 'other',
    viewer: 'viewer',
    personaUserIds: ['owner-1', 'other-1'],
    session: 'bench',
    slowProbesLeft: 10,
    ...over,
  } as ProbeEnv
}

function endpoint(over: Partial<DiscoveredEndpoint> & Pick<DiscoveredEndpoint, 'method' | 'path'>): DiscoveredEndpoint {
  return { params: [], source: 'materialized-surface', ...over }
}

function authzOutcome(path: string, method: 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE', over: Partial<HypothesisOutcome> = {}): HypothesisOutcome {
  return {
    hyp: {
      key: `authz|${method}|${path}`,
      endpoint: endpoint({ method: 'POST', path }),
      probeClass: 'authz_matrix',
      method,
    },
    verdict: 'signal',
    anomalies: [{ type: 'unauthorized_access', resourceId: 'user-a1', actor: 'other_persona', method, status: 200, functionLevel: false }],
    details: {
      matrix: [
        { resourceId: 'user-a1', actor: 'owner', status: 200, bodyBytes: 11, accessible: true },
        { resourceId: 'user-a1', actor: 'other_persona', status: 200, bodyBytes: 11, accessible: true },
      ],
    },
    csrfRejected: false,
    contextReset: false,
    tierBlocked: false,
    requests: 4,
    ...over,
  }
}

function jq<T = { confirmed?: boolean; controlPassed?: boolean }>(program: string, payload: unknown): T {
  const out = execFileSync('jq', ['-c', program], { input: JSON.stringify(payload), encoding: 'utf8' })
  return JSON.parse(out) as T
}

function deltaSpec(o: HypothesisOutcome, e: ProbeEnv) {
  const built = synthesizeSpecs(o, e).find(s => /state delta/.test(String((s.spec as { title?: string }).title)))
  assert.ok(built, 'expected a state-delta spec')
  const parsed = declarativeReplaySpecSchema.safeParse(built.spec)
  assert.equal(parsed.success, true, parsed.success ? '' : JSON.stringify(parsed.error.issues))
  return parsed.data as Record<string, unknown>
}

// ---------------------------------------------------------------------------
// Trivial acknowledgement mutations: prove the state change, not the 200
// ---------------------------------------------------------------------------

test('trivial {ok:true} delete is proven by reserving a live victim and observing its removal', () => {
  const e = env({
    endpoints: [endpoint({ method: 'GET', path: '/rest/members' })],
  })
  const spec = deltaSpec(authzOutcome('/rest/admin/people/:memberId', 'DELETE'), e)
  const steps = spec.steps as Array<{ id: string; role: string; request: { method: string; pathAndQuery: string }; extract?: unknown }>
  const c1 = steps.find(s => s.id === 'c1')
  const p1 = steps.find(s => s.id === 'p1')
  assert.equal(c1?.request.method, 'GET')
  assert.equal(c1?.request.pathAndQuery, '/rest/members')
  assert.deepEqual(c1?.extract, [{ varName: 'victim_id', from: 'json', selector: 'items.1.id' }])
  assert.equal(p1?.request.method, 'DELETE')
  assert.equal(p1?.request.pathAndQuery, '/rest/admin/people/{{victim_id}}')
  assert.equal(p1?.role, 'probe')

  const program = String(spec.assertionsJq)
  const observed = jq(program, {
    extractedVars: { victim_id: 'user-a2' },
    steps: {
      c1: { status: 200, body: '{"items":[{"id":"user-a1"},{"id":"user-a2"}]}' },
      p1: { status: 200, body: '{"ok":true}' },
      p2: { status: 200, body: '{"items":[{"id":"user-a1"}]}' },
    },
  })
  assert.equal(observed.controlPassed, true)
  assert.equal(observed.confirmed, true)

  // A route that ignores the identifier and acknowledges without deleting must not confirm.
  const unchanged = jq(program, {
    extractedVars: { victim_id: 'user-a2' },
    steps: {
      c1: { status: 200, body: '{"items":[{"id":"user-a1"},{"id":"user-a2"}]}' },
      p1: { status: 200, body: '{"ok":true}' },
      p2: { status: 200, body: '{"items":[{"id":"user-a1"},{"id":"user-a2"}]}' },
    },
  })
  assert.equal(unchanged.controlPassed, true)
  assert.equal(unchanged.confirmed, false)

  // No reservation => no control, regardless of the probe status.
  const noVictim = jq(program, {
    extractedVars: {},
    steps: { c1: { status: 200, body: '{"items":[]}' }, p1: { status: 200 }, p2: { status: 200 } },
  })
  assert.equal(noVictim.controlPassed, false)
  assert.equal(noVictim.confirmed, false)
})

test('state-delta synthesis stays gated to privileged function-level surfaces', () => {
  const e = env({ endpoints: [endpoint({ method: 'GET', path: '/rest/spaces' })] })
  const built = synthesizeSpecs(authzOutcome('/rest/spaces/:projId', 'POST'), e)
  assert.equal(built.some(s => /state delta/.test(String((s.spec as { title?: string }).title))), false)
})

test('delete hypotheses report the wire method so findings attribute to the DELETE route', () => {
  const plan = formHypotheses(
    [endpoint({ method: 'DELETE', path: '/rest/admin/people/:memberId' })],
    caps,
  )
  const hyp = plan.hypotheses.find(h => h.probeClass === 'authz_matrix' && h.endpoint.path === '/rest/admin/people/:memberId')
  assert.ok(hyp)
  assert.equal(hyp.method, 'DELETE')
})

// ---------------------------------------------------------------------------
// Pre-redaction secret fingerprints
// ---------------------------------------------------------------------------

test('secret disclosure asserts the pre-redaction fingerprint without ever materializing the secret', () => {
  const o: HypothesisOutcome = {
    hyp: {
      key: 'authz|secret',
      endpoint: endpoint({ method: 'GET', path: '/rest/api-keys' }),
      probeClass: 'authz_matrix',
      method: 'GET',
    },
    verdict: 'signal',
    anomalies: [{
      type: 'secret_disclosed',
      path: '/rest/api-keys',
      method: 'GET',
      persona: 'viewer',
      controlActor: 'anonymous',
      secretPattern: 'rbs_[a-z0-9]+_[0-9a-f]{12}',
      secretEvidence: 'fingerprint',
      secretFingerprints: ['a1b2c3d4e5f6', 'feedfacecafe'],
      actor: 'viewer_persona',
    }],
    details: {},
    csrfRejected: false,
    contextReset: false,
    tierBlocked: false,
    requests: 3,
  }
  const built = synthesizeSpecs(o, env()).find(s => s.kind === 'http_chain')
  assert.ok(built)
  const parsed = declarativeReplaySpecSchema.safeParse(built.spec)
  assert.equal(parsed.success, true)
  const spec = parsed.data as Record<string, unknown>
  const program = String(spec.assertionsJq)
  assert.match(program, /secretMatches/)
  assert.match(program, /a1b2c3d4e5f6/)
  assert.equal(spec.proofPatterns, undefined, 'fingerprint proof must not depend on the redaction placeholder')
  assert.doesNotMatch(program, /rbs_/)

  const matched = jq(program, {
    steps: {
      c1: { status: 401, body: '', secretMatches: [] },
      p1: { status: 200, body: '{"items":[{"secret":"[redacted]"}]}', secretMatches: [{ kind: 'api_key', sha256Prefix: 'a1b2c3d4e5f6', fieldPath: 'items[0].secret', count: 1 }] },
    },
  })
  assert.equal(matched.controlPassed, true)
  assert.equal(matched.confirmed, true)

  // A masked/denied control that carries the same fingerprint is not a control.
  const controlLeaks = jq(program, {
    steps: {
      c1: { status: 200, body: '{}', secretMatches: [{ kind: 'api_key', sha256Prefix: 'a1b2c3d4e5f6', count: 1 }] },
      p1: { status: 200, body: '{}', secretMatches: [{ kind: 'api_key', sha256Prefix: 'a1b2c3d4e5f6', count: 1 }] },
    },
  })
  assert.equal(controlLeaks.controlPassed, false)

  // A different fingerprint on the probe is not the observed secret.
  const wrongSecret = jq(program, {
    steps: {
      c1: { status: 401, body: '', secretMatches: [] },
      p1: { status: 200, body: '{}', secretMatches: [{ kind: 'api_key', sha256Prefix: '000000000000', count: 1 }] },
    },
  })
  assert.equal(wrongSecret.confirmed, false)
})
