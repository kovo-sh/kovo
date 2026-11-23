process.env.GUARDIAN_ALLOW_LOCAL_LAB ??= '1'
/**
 * v5.1 Slice 4 — proof-strength + endpoint-binding guards for LLM-authored specs.
 *
 * Each vulnerable fixture is paired with a decoy that a naive spec could confirm on: a status-only
 * assertion, a "the body differs" assertion (dynamic nonce), an SPA catch-all 200 HTML shell, and a
 * spec whose declared finding origin differs from the endpoint actually exchanged.
 */
import assert from 'node:assert/strict'
import { once } from 'node:events'
import { createServer } from 'node:http'
import type { IncomingMessage, ServerResponse } from 'node:http'
import { randomUUID } from 'node:crypto'
import { test } from 'node:test'

process.env.GUARDIAN_ALLOW_LOCAL_LAB = '1'

import { RequestBroker } from '../src/server/broker.ts'
import type { Grant } from '../src/server/broker.ts'
import {
  assessHttpChainEndpointBinding,
  assessHttpChainProofStrength,
  buildInlineVerifyFeedback,
  classifyHttpChainAssertion,
  retestReplaySpec,
  verifyReplaySpec,
} from '../src/server/replay-verifier.ts'
import { declarativeReplaySpecSchema } from '../src/replay-spec.ts'
import { LocalJqBackend } from '../scripts/benchmark-backend.ts'
import type { ResolvedPersona } from '../src/server/persona-vault.ts'

async function fixture(handler: (req: IncomingMessage, res: ServerResponse) => unknown) {
  const server = createServer((req, res) => { void handler(req, res) }).listen(0, '127.0.0.1')
  await once(server, 'listening')
  const address = server.address()
  if (!address || typeof address === 'string') throw new Error('fixture has no port')
  return {
    origin: `http://127.0.0.1:${address.port}`,
    close: () => new Promise<void>(resolve => { server.closeAllConnections(); server.close(() => resolve()) }),
  }
}

function json(res: ServerResponse, status: number, value: unknown): void {
  res.statusCode = status
  res.setHeader('Content-Type', 'application/json')
  res.end(JSON.stringify(value))
}

function html(res: ServerResponse, status: number, body: string): void {
  res.statusCode = status
  res.setHeader('Content-Type', 'text/html; charset=utf-8')
  res.end(body)
}

function persona(handle: string, origin: string): ResolvedPersona {
  return {
    id: handle, handle, roleLabel: handle, originAllowlist: [origin], authKind: 'header',
    headerName: 'X-Persona', secret: handle, canaryMarkers: [],
  }
}

function grantFor(origins: string[], personas: string[] = ['owner', 'other']): Grant {
  const originSet = new Set(origins)
  return {
    origin: origins[0], tier: 3, allowLocalLab: true, maxRpsPerOrigin: 100,
    canRead: origin => originSet.has(origin),
    isIdempotentPostAllowed: () => true,
    isStateChangeApproved: () => true,
    personas: new Map(personas.map(handle => [handle, persona(handle, origins[0])])),
    audit: () => undefined,
  }
}

function baseFields(origin: string) {
  return {
    version: 1 as const,
    origin,
    title: 'Cross-tenant resource read',
    category: 'broken-access-control' as const,
    cwe: 'CWE-639',
    severity: 'high' as const,
    severityRationale: 'A different tenant actor receives the owner resource body.',
    impact: 'Unauthorized access across a tenant boundary.',
    remediation: 'Enforce an object-level ownership check on the handler.',
    recheckInstructions: 'Replay the owner read and the non-owner read.',
  }
}

async function verify(spec: Record<string, unknown>, grant: Grant) {
  const parsed = declarativeReplaySpecSchema.safeParse(spec)
  assert.equal(parsed.success, true, parsed.success ? '' : JSON.stringify(parsed.error.issues))
  const broker = new RequestBroker({ rejectUnauthorized: false })
  return verifyReplaySpec({
    spec, broker, backend: new LocalJqBackend(), grant,
    signal: AbortSignal.timeout(20_000),
  })
}

// ---------------------------------------------------------------------------
// 1. Vulnerable cross-actor read confirms (guards are additive)
// ---------------------------------------------------------------------------

function ordersFixture(hardened: boolean) {
  return fixture((req, res) => {
    const url = new URL(req.url ?? '/', 'http://127.0.0.1')
    if (url.pathname !== '/api/orders/42') return json(res, 404, { error: 'not_found' })
    const actor = req.headers['x-persona']
    if (!actor) return json(res, 401, { error: 'unauthorized' })
    if (hardened && actor !== 'owner') return json(res, 403, { error: 'forbidden' })
    return json(res, 200, { id: 42, owner: 'owner', total: 9912 })
  })
}

function crossActorSpec(origin: string, assertionsJq: string) {
  return {
    ...baseFields(origin),
    kind: 'http_chain',
    steps: [
      {
        id: 'c1', role: 'control', description: 'Owner reads order 42',
        request: { origin, method: 'GET', pathAndQuery: '/api/orders/42', persona: 'owner' },
      },
      {
        id: 'p1', role: 'probe', description: 'Non-owner reads order 42',
        request: { origin, method: 'GET', pathAndQuery: '/api/orders/42', persona: 'other' },
      },
    ],
    assertionsJq,
  }
}

const crossActorJq = `{ controlPassed: (.steps.c1.status == 200 and .steps.c1.json.id == 42),
  confirmed: (.steps.p1.status == 200 and .steps.p1.json.id == .steps.c1.json.id and .steps.p1.json.owner == .steps.c1.json.owner and .steps.p1.json.total == .steps.c1.json.total),
  observed: ("probe=" + (.steps.p1.status | tostring) + " id=" + (.steps.p1.json.id | tostring)),
  expected: "403 for a non-owner actor" }`

test('guards: vulnerable cross-actor read still confirms and records the verified endpoint', async () => {
  const fx = await ordersFixture(false)
  try {
    const res = await verify(crossActorSpec(fx.origin, crossActorJq), grantFor([fx.origin]))
    assert.equal(res.verdict, 'confirmed', String(res.outcome.reason))
    const proof = res.evidencePayload.proofStrength as { satisfied?: boolean; differential?: string }
    assert.equal(proof.satisfied, true)
    assert.equal(proof.differential, 'cross_actor_access')
    const binding = res.evidencePayload.endpointBinding as {
      bound?: boolean
      verifiedEndpoint?: { method?: string; pathAndQuery?: string; origin?: string }
    }
    assert.equal(binding.bound, true)
    assert.equal(binding.verifiedEndpoint?.method, 'GET')
    assert.equal(binding.verifiedEndpoint?.pathAndQuery, '/api/orders/42')
    assert.equal(binding.verifiedEndpoint?.origin, fx.origin)
  } finally { await fx.close() }
})

test('guards: hardened non-owner denial dismisses (not inconclusive) so Verify Fix still reports fixed', async () => {
  const fx = await ordersFixture(true)
  try {
    const spec = crossActorSpec(fx.origin, crossActorJq)
    const res = await verify(spec, grantFor([fx.origin]))
    assert.equal(res.verdict, 'dismissed', String(res.outcome.reason))
    const retest = await retestReplaySpec({
      spec,
      broker: new RequestBroker({ rejectUnauthorized: false }),
      backend: new LocalJqBackend(),
      grant: grantFor([fx.origin]),
      signal: AbortSignal.timeout(20_000),
    })
    assert.equal(retest.verdict, 'fixed')
  } finally { await fx.close() }
})

// ---------------------------------------------------------------------------
// 2. Status-only authorization claim is rejected
// ---------------------------------------------------------------------------

test('guards: status-only authorization decoy is rejected even on a vulnerable fixture', async () => {
  const fx = await ordersFixture(false)
  try {
    const spec = crossActorSpec(fx.origin, `{ controlPassed: (.steps.c1.status == 200),
      confirmed: (.steps.p1.status == 200),
      observed: ("probe=" + (.steps.p1.status | tostring)),
      expected: "403 for a non-owner actor" }`)
    const res = await verify(spec, grantFor([fx.origin]))
    assert.equal(res.verdict, 'inconclusive')
    assert.equal(res.outcome.confirmed, false)
    assert.match(res.outcome.reason ?? '', /status-only/i)
    const feedback = buildInlineVerifyFeedback(spec, res, 1)
    assert.equal(feedback.proofStrengthSatisfied, false)
    assert.match(feedback.proofStrengthReason ?? '', /status-only/i)
  } finally { await fx.close() }
})

// ---------------------------------------------------------------------------
// 3. "Different body" decoy is rejected (dynamic nonce, no identifier binding)
// ---------------------------------------------------------------------------

test('guards: different-body authorization decoy (per-request nonce) is rejected', async () => {
  const fx = await fixture((req, res) => {
    const url = new URL(req.url ?? '/', 'http://127.0.0.1')
    if (url.pathname !== '/api/account') return json(res, 404, { error: 'not_found' })
    json(res, 200, { ok: true, nonce: randomUUID(), servedAt: Date.now() })
  })
  try {
    const spec = crossActorSpec(fx.origin, `{ controlPassed: (.steps.c1.status == 200),
      confirmed: (.steps.p1.status == 200 and .steps.p1.body != .steps.c1.body),
      observed: "bodies differ", expected: "non-owner denied" }`)
    spec.steps[0]!.request.pathAndQuery = '/api/account'
    spec.steps[1]!.request.pathAndQuery = '/api/account'
    const res = await verify(spec, grantFor([fx.origin]))
    assert.equal(res.verdict, 'inconclusive')
    assert.equal(res.outcome.confirmed, false)
    assert.match(res.outcome.reason ?? '', /different-body|identifier-binding/i)
  } finally { await fx.close() }
})

// ---------------------------------------------------------------------------
// 4. SPA catch-all HTML baseline does not confirm (auto control required)
// ---------------------------------------------------------------------------

const spaShell = '<!doctype html><html><head><title>App</title></head><body><div id="root">SPA shell admin_panel</div></body></html>'

test('guards: catch-all HTML response cannot confirm without a real endpoint baseline', async () => {
  const fx = await fixture((_req, res) => html(res, 200, spaShell))
  try {
    const spec = {
      ...baseFields(fx.origin),
      kind: 'http_chain',
      steps: [
        { id: 'c1', role: 'control', description: 'Baseline admin read', request: { origin: fx.origin, method: 'GET', pathAndQuery: '/admin' } },
        { id: 'p1', role: 'probe', description: 'Probe admin read', request: { origin: fx.origin, method: 'GET', pathAndQuery: '/admin' } },
      ],
      assertionsJq: `{ controlPassed: true,
        confirmed: (.steps.p1.status == 200 and (.steps.p1.body | contains("admin_panel"))),
        observed: "200 html", expected: "401/403" }`,
    }
    const res = await verify(spec, grantFor([fx.origin]))
    assert.equal(res.verdict, 'inconclusive')
    assert.equal(res.outcome.confirmed, false)
    assert.match(res.outcome.reason ?? '', /SPA catch-all/i)
    const auto = res.evidencePayload.spaCatchallAuto as { requiresControl?: boolean; matchedProbes?: number } | undefined
    assert.equal(auto?.requiresControl, true)
    assert.equal(auto?.matchedProbes, 1)
    const feedback = buildInlineVerifyFeedback(spec, res, 1)
    assert.equal(feedback.spaCatchallRequired, true)

    // Opting in to the explicit catch-all control must still reject the same shell.
    const explicit = await verify({ ...spec, spaCatchallControl: true }, grantFor([fx.origin]))
    assert.equal(explicit.verdict, 'inconclusive')
    assert.equal(explicit.outcome.confirmed, false)
  } finally { await fx.close() }
})

// ---------------------------------------------------------------------------
// 4b. Auth bypass with a login-redirect control still confirms
// ---------------------------------------------------------------------------

test('guards: auth-bypass whose control is a login redirect still confirms via marker differential', async () => {
  const fx = await fixture((req, res) => {
    const url = new URL(req.url ?? '/', 'http://127.0.0.1')
    if (url.pathname !== '/admin') return html(res, 404, 'not found')
    if (req.headers['x-middleware-subrequest']) return html(res, 200, '<html><body>admin dashboard</body></html>')
    res.statusCode = 302
    res.setHeader('Location', '/login')
    res.end()
  })
  try {
    const spec = {
      ...baseFields(fx.origin),
      category: 'broken-access-control',
      cwe: 'CWE-287',
      kind: 'http_chain',
      steps: [
        { id: 'c1', role: 'control', description: 'Admin without bypass header', request: { origin: fx.origin, method: 'GET', pathAndQuery: '/admin' } },
        { id: 'p1', role: 'probe', description: 'Admin with bypass header', request: { origin: fx.origin, method: 'GET', pathAndQuery: '/admin', headers: { 'x-middleware-subrequest': 'middleware' } } },
      ],
      assertionsJq: `{ controlPassed: (.steps.c1.status == 302),
        confirmed: (.steps.p1.status == 200 and (.steps.p1.body | contains("admin dashboard"))),
        observed: ("probe=" + (.steps.p1.status | tostring)), expected: "login redirect on both" }`,
    }
    const res = await verify(spec, grantFor([fx.origin]))
    assert.equal(res.verdict, 'confirmed', String(res.outcome.reason))
    const proof = res.evidencePayload.proofStrength as { differential?: string }
    assert.equal(proof.differential, 'denied_then_allowed')
  } finally { await fx.close() }
})

// ---------------------------------------------------------------------------
// 5. Declared-vs-actual endpoint binding
// ---------------------------------------------------------------------------
function itemServer() {
  return fixture((req, res) => {
    const url = new URL(req.url ?? '/', 'http://127.0.0.1')
    if (url.pathname !== '/api/item') return json(res, 404, { error: 'not_found' })
    json(res, 200, { ok: true, exposed: url.searchParams.get('id') === 'priv' })
  })
}

function fieldBoundSpec(declaredOrigin: string, requestOrigin: string) {
  return {
    ...baseFields(declaredOrigin),
    kind: 'http_chain',
    steps: [
      { id: 'c1', role: 'control', description: 'Public item', request: { origin: requestOrigin, method: 'GET', pathAndQuery: '/api/item?id=pub' } },
      { id: 'p1', role: 'probe', description: 'Private item', request: { origin: requestOrigin, method: 'GET', pathAndQuery: '/api/item?id=priv' } },
    ],
    assertionsJq: `{ controlPassed: (.steps.c1.json.exposed == false),
      confirmed: (.steps.p1.status == 200 and .steps.p1.json.exposed == true),
      observed: ("exposed=" + (.steps.p1.json.exposed | tostring)),
      expected: "exposed=false" }`,
  }
}

test('guards: field-bound same-actor deterministic pattern still confirms when the origin matches', async () => {
  const fx = await itemServer()
  try {
    const res = await verify(fieldBoundSpec(fx.origin, fx.origin), grantFor([fx.origin]))
    assert.equal(res.verdict, 'confirmed', String(res.outcome.reason))
  } finally { await fx.close() }
})

test('guards: declared finding origin that differs from the exchanged endpoint is rejected', async () => {
  const claimed = await itemServer()
  const actual = await itemServer()
  try {
    const res = await verify(fieldBoundSpec(claimed.origin, actual.origin), grantFor([claimed.origin, actual.origin]))
    assert.equal(res.verdict, 'inconclusive')
    assert.equal(res.outcome.confirmed, false)
    assert.match(res.outcome.reason ?? '', /does not match the probe endpoint origin/i)
    const binding = res.evidencePayload.endpointBinding as {
      bound?: boolean
      verifiedEndpoint?: { origin?: string } | null
      declaredEndpoint?: { origin?: string } | null
      mismatches?: Array<{ field?: string }>
    }
    assert.equal(binding.bound, false)
    assert.equal(binding.verifiedEndpoint?.origin, actual.origin)
    assert.equal(binding.declaredEndpoint?.origin, actual.origin)
    assert.ok(binding.mismatches?.some(m => m.field === 'specOrigin'))
    const feedback = buildInlineVerifyFeedback(fieldBoundSpec(claimed.origin, actual.origin), res, 1)
    assert.equal(feedback.endpointBindingFailed, true)
    assert.equal(feedback.verifiedEndpoint, `GET ${actual.origin}/api/item?id=priv`)
  } finally {
    await claimed.close()
    await actual.close()
  }
})

// ---------------------------------------------------------------------------
// 6. Guard helpers are exported and behave (unit level)
// ---------------------------------------------------------------------------

test('guards: assertion classification and authorization proof assessment are mechanical', () => {
  assert.equal(classifyHttpChainAssertion('{ confirmed: (.steps.p1.status == 200) }'), 'status_only')
  assert.equal(classifyHttpChainAssertion('{ confirmed: (.steps.p1.body != .steps.c1.body) }'), 'unbound_content')
  assert.equal(classifyHttpChainAssertion('{ confirmed: (.steps.p1.json.role == "admin") }'), 'content_bound')
  assert.equal(classifyHttpChainAssertion('{ confirmed: .proofMatches.p1[0] }'), 'content_bound')

  const spec = {
    ...baseFields('http://127.0.0.1:1'),
    kind: 'http_chain' as const,
    steps: [],
    assertionsJq: '{ confirmed: (.steps.p1.json.role == "admin") }',
  }
  const snapshots = [
    { index: 0, id: 'c1', role: 'control', method: 'GET', route: '/a', pathAndQuery: '/a', actor: 'persona:owner', status: 200, body: '{"role":"user"}', bodyBytes: 15, mediaType: 'application/json', json: { role: 'user' }, secretMatches: 0 },
    { index: 1, id: 'p1', role: 'probe', method: 'GET', route: '/a', pathAndQuery: '/a', actor: 'persona:other', status: 200, body: '{"role":"admin"}', bodyBytes: 16, mediaType: 'application/json', json: { role: 'admin' }, secretMatches: 0 },
  ]
  const assessment = assessHttpChainProofStrength(spec as never, snapshots as never)
  assert.equal(assessment.satisfied, true)
  assert.equal(assessment.differential, 'cross_actor_access')

  const binding = assessHttpChainEndpointBinding(
    {
      ...spec,
      steps: [
        { id: 'c1', role: 'control', description: 'control', request: { origin: 'http://127.0.0.1:1', method: 'GET', pathAndQuery: '/a' } },
        { id: 'p1', role: 'probe', description: 'probe', request: { origin: 'http://127.0.0.1:1', method: 'GET', pathAndQuery: '/a' } },
      ],
    } as never,
    new Map([
      ['c1', [{ origin: 'http://127.0.0.1:1', method: 'GET', pathAndQuery: '/a' }]],
      ['p1', [{ origin: 'http://127.0.0.1:1', method: 'GET', pathAndQuery: '/a' }]],
    ]) as never,
    new Map([
      ['c1', [{ origin: 'http://127.0.0.1:1', finalOrigin: 'http://127.0.0.1:1', method: 'GET', pathAndQuery: '/a' }]],
      ['p1', [{ origin: 'http://127.0.0.1:1', finalOrigin: 'http://127.0.0.1:1', method: 'GET', pathAndQuery: '/a' }]],
    ]) as never,
  )
  assert.equal(binding.bound, true)

  const escaped = assessHttpChainEndpointBinding(
    {
      ...spec,
      steps: [
        { id: 'p1', role: 'probe', description: 'probe', request: { origin: 'http://127.0.0.1:1', method: 'GET', pathAndQuery: '/a', followRedirects: true } },
      ],
    } as never,
    new Map([['p1', [{ origin: 'http://127.0.0.1:1', method: 'GET', pathAndQuery: '/a' }]]]) as never,
    new Map([['p1', [{ origin: 'http://127.0.0.1:1', finalOrigin: 'http://127.0.0.1:2', method: 'GET', pathAndQuery: '/a' }]]]) as never,
  )
  assert.equal(escaped.bound, false)
  assert.ok(escaped.mismatches.some(m => m.field === 'redirectHost'))
})
