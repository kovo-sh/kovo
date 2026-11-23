// Floor-hardening regress: restore the two product-floor targets lost to the title/impact, peer-denial
// and signed-role tightening — without loosening the over-claim gates.
//
// Targets:
//   1. vertical BFLA on a privileged destructive route (admin → viewer delete): the post-delete 404
//      readback is persistence evidence, not a denied boundary control.
//   2. credential disclosure in a free-text audit record: an authenticated, unentitled read whose
//      body matches a credential shape the proof itself asserts (absent from every control).
//
// Every fixture is a synthetic acme-style tenant/role surface; no app or route literal is added to
// product code. Defensive framing: authorized local differential fixtures only.
import assert from 'node:assert/strict'
import { test } from 'node:test'

import type { DifferentialResult } from '../src/server/probes/context.ts'
import type { EngineHypothesis } from '../src/server/deterministic-specs.ts'
import { synthesizeEngineSpecs } from '../src/server/deterministic-specs.ts'
import {
  assessAuthorizationImpact,
  assessBoundary,
  assessBusinessLogicImpact,
  assessImpactEvidence,
  assessMarkupImpact,
} from '../src/server/oracle-invariants.ts'
import type { ActorIdentity, ImpactStep } from '../src/server/oracle-invariants.ts'

const admin: ActorIdentity = { handle: 'admin', role: 'admin', tenant: 'acme', auth: 'cookie', sameSite: 'Lax' }
const viewer: ActorIdentity = { handle: 'viewer', role: 'viewer', tenant: 'acme', auth: 'cookie', sameSite: 'Lax' }
const anon: ActorIdentity = { handle: null, role: null, tenant: null, auth: 'unknown', sameSite: null }

const credentialShape = 'gl_[a-z0-9]+_[0-9a-f]{12}'
const credentialValue = 'gl_acme1_0123456789ab'

function adminDeleteChain(hardened: boolean): ImpactStep[] {
  const victim = 'usr-42'
  return [
    // The bogus-id control is a 200 no-op on this app, so it contributes no boundary signal.
    { id: 'c2', arm: 'control', method: 'DELETE', route: `/api/admin/people/gx9000001`, status: 200, actor: admin },
    { id: 'c1', arm: 'control', method: 'GET', route: `/api/people/${victim}`, status: 200, actor: admin, json: { id: victim, email: 'victim@acme.test', role: 'member' } },
    { id: 'c3', arm: 'control', method: 'GET', route: `/api/people/${victim}`, status: 200, actor: admin, json: { id: victim, email: 'victim@acme.test', role: 'member' } },
    { id: 'p1', arm: 'probe', method: 'DELETE', route: `/api/admin/people/${victim}`, status: hardened ? 403 : 200, actor: viewer },
    hardened
      ? { id: 'p2', arm: 'control', method: 'GET', route: `/api/people/${victim}`, status: 200, actor: admin, json: { id: victim, email: 'victim@acme.test', role: 'member' } }
      // The successful delete makes the admin's readback a 404 record — persistence, not a denial.
      : { id: 'p2', arm: 'control', method: 'GET', route: `/api/people/${victim}`, status: 404, actor: admin, json: { error: 'not found' } },
  ]
}

test('floor regress: a post-delete readback is persistence evidence, not a denied boundary control', () => {
  const vulnerable = assessBoundary({
    impactClass: 'bfla',
    boundaryClass: 'access',
    // The reserved-victim delete spec declares the strongest arm to be the actor differential.
    expectControlDenied: false,
    requiredRole: 'admin',
    steps: adminDeleteChain(false),
  })
  assert.equal(vulnerable.satisfied, true, vulnerable.reason)
  assert.equal(vulnerable.arm, 'actor_differential')

  // The impact gate must still confirm the persistent removal (the readback 404 is the delta).
  const impact = assessImpactEvidence({
    impactClass: 'bfla',
    requiredRole: 'admin',
    expectControlDenied: false,
    steps: adminDeleteChain(false),
  })
  assert.equal(impact.satisfied, true, impact.reason)
})

test('floor regress: the hardened twin of the privileged delete is dismissed', () => {
  const steps = adminDeleteChain(true)
  const boundary = assessBoundary({
    impactClass: 'bfla', boundaryClass: 'access', expectControlDenied: false, requiredRole: 'admin', steps,
  })
  // The actor differential still exists, but nothing was mutated.
  assert.equal(boundary.satisfied, true, boundary.reason)
  const impact = assessImpactEvidence({ impactClass: 'bfla', requiredRole: 'admin', expectControlDenied: false, steps })
  assert.equal(impact.satisfied, false, impact.reason)
  assert.match(impact.reason, /no mutating probe|not served|without persisted impact/i)
})

test('floor regress: a denial recorded before the probe still has to be crossed', () => {
  const steps: ImpactStep[] = [
    { id: 'control', arm: 'control', method: 'GET', route: '/api/admin/activity', status: 403, actor: viewer },
    { id: 'probe', arm: 'probe', method: 'GET', route: '/api/admin/activity', status: 200, actor: admin, json: { items: [] } },
  ]
  const crossed = assessBoundary({ impactClass: 'authorization', boundaryClass: 'access', steps })
  assert.equal(crossed.satisfied, true, crossed.reason)
  assert.equal(crossed.arm, 'control_denied')

  const unrelated = assessBoundary({
    impactClass: 'authorization',
    boundaryClass: 'access',
    steps: [
      { id: 'control', arm: 'control', method: 'GET', route: '/api/admin/audit', status: 403, actor: viewer },
      { id: 'probe', arm: 'probe', method: 'GET', route: '/api/invoices/i1', status: 200, actor: admin, json: { id: 'i1' } },
    ],
  })
  assert.equal(unrelated.satisfied, false, unrelated.reason)
  assert.match(unrelated.reason, /no variant exchange on the same route family/i)
})

function privilegeFunctionSteps(hardened: boolean): ImpactStep[] {
  return [
    { id: 'c1', arm: 'control', method: 'GET', route: '/api/v1/admin/feature-flags', status: 200, actor: admin, json: { flags: { audit: false } } },
    {
      id: 'p1', arm: 'probe', method: 'POST', route: '/api/v1/admin/feature-flags', status: hardened ? 403 : 200,
      actor: viewer, requestJson: { flag: 'escalate', enabled: true }, json: { ok: true },
    },
    {
      id: 'p2', arm: 'control', method: 'GET', route: '/api/v1/admin/feature-flags', status: 200, actor: admin,
      json: hardened ? { flags: { audit: false } } : { flags: { audit: false, escalate: true } },
    },
  ]
}

test('floor regress: a lower role mutating a role-gated function surface is vertical impact', () => {
  const vulnerable = assessImpactEvidence({ impactClass: 'authorization', requiredRole: 'admin', steps: privilegeFunctionSteps(false) })
  assert.equal(vulnerable.satisfied, true, vulnerable.reason)
  assert.match(vulnerable.reason, /Vertical|role-gated function surface/i)

  const hardened = assessImpactEvidence({ impactClass: 'authorization', requiredRole: 'admin', steps: privilegeFunctionSteps(true) })
  assert.equal(hardened.satisfied, false, hardened.reason)

  // The same role differential on a content route is in policy: a viewer editing a workspace field
  // is not vertical escalation, even if a claim declares a required admin role (the K=6 FP).
  const contentRoute = assessImpactEvidence({
    impactClass: 'bfla',
    requiredRole: 'admin',
    steps: [
      { id: 'c1', arm: 'control', method: 'GET', route: '/api/projects/p1', status: 200, actor: admin, json: { id: 'p1', description: 'old' } },
      { id: 'p1', arm: 'probe', method: 'PATCH', route: '/api/projects/p1', status: 200, actor: viewer, requestJson: { description: 'policy-probe' }, json: { ok: true } },
      { id: 'p2', arm: 'control', method: 'GET', route: '/api/projects/p1', status: 200, actor: admin, json: { id: 'p1', description: 'policy-probe' } },
    ],
  })
  assert.equal(contentRoute.satisfied, false, contentRoute.reason)
  assert.match(contentRoute.reason, /not a protected field|self-service|in policy/i)
})

function auditDisclosureSteps(hardened: boolean): ImpactStep[] {
  const detail = hardened ? 'rotated secret gl_[redacted]' : `rotated secret ${credentialValue}`
  const body = JSON.stringify({ items: [{ actor: 'system', action: 'rotate_key', detail }] })
  return [
    { id: 'c1', arm: 'control', method: 'GET', route: '/api/admin/activity', status: 401, actor: anon, body: '' },
    {
      id: 'p1', arm: 'probe', method: 'GET', route: '/api/admin/activity', status: 200, actor: viewer,
      json: { items: [{ actor: 'system', action: 'rotate_key', detail }] }, body,
    },
  ]
}

test('floor regress: a credential-shaped value in a free-text audit record confirms disclosure', () => {
  const vulnerable = assessImpactEvidence({
    impactClass: 'disclosure',
    steps: auditDisclosureSteps(false),
    credentialPatterns: [credentialShape],
  })
  assert.equal(vulnerable.satisfied, true, vulnerable.reason)
  assert.match(vulnerable.reason, /credential-shaped value disclosed/i)

  // Hardened twin masks the credential: same route, same boundary, no value -> dismissed.
  const hardened = assessImpactEvidence({
    impactClass: 'disclosure',
    steps: auditDisclosureSteps(true),
    credentialPatterns: [credentialShape],
  })
  assert.equal(hardened.satisfied, false, hardened.reason)
  assert.match(hardened.reason, /lacks impact evidence|no owner-scoped/i)
})

test('floor regress: the credential pattern is evidence, not a declaration', () => {
  // A value every control also returns is a public constant, not a disclosure.
  const constant = assessImpactEvidence({
    impactClass: 'disclosure',
    steps: [
      { id: 'c1', arm: 'control', method: 'GET', route: '/api/admin/activity', status: 401, actor: anon, body: credentialValue },
      {
        id: 'p1', arm: 'probe', method: 'GET', route: '/api/admin/activity', status: 200, actor: viewer,
        json: { items: [] }, body: JSON.stringify({ items: [{ detail: credentialValue }] }),
      },
    ],
    credentialPatterns: [credentialShape],
  })
  assert.equal(constant.satisfied, false, constant.reason)

  // A wildcard-shaped "pattern" must never satisfy the gate.
  const wildcard = assessImpactEvidence({
    impactClass: 'disclosure',
    steps: auditDisclosureSteps(false),
    credentialPatterns: ['.*'],
  })
  assert.equal(wildcard.satisfied, false, wildcard.reason)

  // An anonymous probe has no entitlement boundary to disclose across.
  const anonymous = assessImpactEvidence({
    impactClass: 'disclosure',
    steps: [
      { id: 'c1', arm: 'control', method: 'GET', route: '/api/admin/activity', status: 404, actor: anon, body: '' },
      { id: 'p1', arm: 'probe', method: 'GET', route: '/api/admin/activity', status: 200, actor: anon, json: { items: [] }, body: credentialValue },
    ],
    credentialPatterns: [credentialShape],
  })
  assert.equal(anonymous.satisfied, false, anonymous.reason)
})

test('floor regress: the sensitive-read spec carries the observed credential shape as a proof pattern', () => {
  const hyp: EngineHypothesis = {
    key: 'secret|audit',
    endpoint: { id: 'ep-audit', origin: 'http://127.0.0.1:1', method: 'GET', pathTemplate: '/api/admin/activity', params: [] },
    probeClass: 'authz_matrix',
    intent: 'secret_disclosure',
    method: 'GET',
    pathAndQuery: '/api/admin/activity',
    ownerPersona: 'admin',
    otherPersona: 'viewer',
    viewerPersona: 'viewer',
    secretScan: true,
    risk: 50,
  }
  const result: DifferentialResult = {
    probeClass: 'authz_matrix',
    origin: 'http://127.0.0.1:1',
    pathAndQuery: '/api/admin/activity',
    verdict: 'signal',
    summary: 'Credential-shaped value served to an unentitled authenticated actor.',
    anomalies: [{
      type: 'secret_disclosed',
      path: '/api/admin/activity',
      controlPath: '/api/admin/activity',
      controlActor: 'anonymous',
      persona: 'viewer',
      secretPattern: credentialShape,
    }],
    details: {},
    requestsSent: 3,
    exchangeIds: [],
    stoppedReason: null,
    notes: [],
    durationMs: 1,
  }
  const specs = synthesizeEngineSpecs(hyp, result)
  assert.ok(specs.length > 0, 'a sensitive read with a secret anomaly must synthesize a spec')
  const disclosure = specs.find(item => item.vulnClass === 'info_disclosure')
  assert.ok(disclosure, 'expected an info_disclosure spec')
  assert.deepEqual(disclosure!.spec.proofPatterns, [credentialShape])
})

test('floor regress: the three K=6 over-claims are still dismissed (no loosening)', () => {
  const owner: ActorIdentity = { handle: 'persona_a', role: 'owner', tenant: 'acme', auth: 'cookie', sameSite: 'Lax' }

  const selfService = assessBusinessLogicImpact({
    impactClass: 'business_logic',
    steps: [
      { id: 'before', arm: 'control', method: 'GET', route: '/api/invoices/i1', status: 200, actor: owner, json: { id: 'i1', status: 'draft' } },
      { id: 'probe', arm: 'probe', method: 'PATCH', route: '/api/invoices/i1', status: 200, actor: owner, requestJson: { status: 'paid' }, json: { ok: true } },
      { id: 'after', arm: 'control', method: 'GET', route: '/api/invoices/i1', status: 200, actor: owner, json: { id: 'i1', status: 'paid' } },
    ],
  })
  assert.equal(selfService.satisfied, false, selfService.reason)
  assert.match(selfService.reason, /self-service|non-protected/i)

  const inertMarkup = assessMarkupImpact({
    impactClass: 'markup',
    steps: [
      { id: 'p1', arm: 'probe', method: 'GET', route: '/api/reports/r1/render', status: 200, actor: owner, body: '<h2><b>gnmarker</b></h2>' },
    ],
  })
  assert.equal(inertMarkup.satisfied, false, inertMarkup.reason)

  // A public-route read of a tenant data canary remains in policy: no pattern is asserted and the
  // probe is anonymous, so neither the owner-scoped nor the credential-shape path can confirm it.
  const publicRead = assessAuthorizationImpact({
    impactClass: 'disclosure',
    credentialPatterns: [credentialShape],
    steps: [
      { id: 'c1', arm: 'control', method: 'GET', route: '/api/reports/none/public', status: 404, actor: anon },
      {
        id: 'p1', arm: 'probe', method: 'GET', route: '/api/reports/9f1/public', status: 200, actor: anon,
        json: { id: '9f1', name: 'Quarterly', summary: 'internal', workspace: 'acme', ref: credentialValue },
        body: JSON.stringify({ id: '9f1', ref: credentialValue }),
      },
    ],
  })
  assert.equal(publicRead.satisfied, false, publicRead.reason)
})
