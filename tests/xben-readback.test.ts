// xben-readback: mutating authorization proofs must carry a real readback chain.
//
// `v6-verifier-harden` (see tests/v6-verifier-harden.test.ts) requires a separate pre/post GET that
// shows the protected field changed before a mutating authz proof may confirm. The deterministic
// synthesizer for the in-product engine (`src/server/deterministic-specs.ts`) and the benchmark
// parity synthesizer (`scripts/benchmark-specs-http.ts`) must therefore emit that chain instead of a
// status/echo-only pair. This file pins:
//  - a privileged function-level BFLA spec confirms only when the post readback shows the role change;
//  - a denied low-privilege mutation stays inconclusive;
//  - a read-only authorization proof keeps its original three-step shape;
//  - the xben-12 shape (an elevated `/admin/users/{id}/promote` route with a self-profile readback)
//    reproduces end to end and is deterministic.
//
// Defensive framing: authorized local differential probes against an intentional fixture.
import assert from 'node:assert/strict'
import { createServer } from 'node:http'
import type { IncomingMessage, ServerResponse } from 'node:http'
import { once } from 'node:events'
import { test } from 'node:test'

process.env.KOVO_ALLOW_LOCAL_LAB = '1'

import { RequestBroker } from '../src/server/broker.ts'
import type { Grant } from '../src/server/broker.ts'
import type { ResolvedPersona } from '../src/server/persona-vault.ts'
import { verifyReplaySpec } from '../src/server/replay-verifier.ts'
import { declarativeReplaySpecSchema } from '../src/replay-spec.ts'
import { LocalJqBackend } from '../scripts/benchmark-backend.ts'
import { synthesizeEngineSpecs } from '../src/server/deterministic-specs.ts'
import type { EngineHypothesis } from '../src/server/deterministic-specs.ts'
import type { DifferentialResult } from '../src/server/surface-engine.ts'
import { synthAuthz } from '../scripts/benchmark-specs-http.ts'
import type { HypothesisOutcome, ProbeEnv } from '../scripts/benchmark-probes.ts'

type Json = Record<string, unknown>

// ---------------------------------------------------------------------------
// Fixture: xben-12-shaped admin promote surface, plus a read-only invoice route
// ---------------------------------------------------------------------------

interface FixtureOptions {
  /** Hardened: the promote function rejects non-admin callers (the fixed twin). */
  denyLowPrivPromote?: boolean
}

interface Fixture {
  origin: string
  close(): Promise<void>
  users: Map<string, Json>
  policy: { role: string }
}

const USERS: Record<string, { role: string; plan: string }> = {
  'u-1000': { role: 'admin', plan: 'pro' },
  'u-1001': { role: 'member', plan: 'pro' },
  'u-1002': { role: 'member', plan: 'pro' },
  'u-1003': { role: 'viewer', plan: 'free' },
}

const ROLE_LABEL: Record<string, string> = {
  admin: 'admin (acme)',
  persona_a: 'member (acme)',
  persona_b: 'member (acme)',
  viewer: 'viewer (acme)',
}

const USER_OF_PERSONA: Record<string, string> = {
  admin: 'u-1000',
  persona_a: 'u-1001',
  persona_b: 'u-1002',
  viewer: 'u-1003',
}

async function startFixture(options: FixtureOptions = {}): Promise<Fixture> {
  const users = new Map<string, Json>()
  for (const [id, user] of Object.entries(USERS)) users.set(id, { id, role: user.role, plan: user.plan })
  const policy = { role: 'viewer' }
  const server = createServer((req, res) => {
    void handle(req, res, users, policy, options).catch(error => {
      if (!res.headersSent) res.statusCode = 500
      res.end(String(error))
    })
  })
  server.listen(0, '127.0.0.1')
  await once(server, 'listening')
  const address = server.address()
  if (!address || typeof address === 'string') throw new Error('fixture did not bind')
  return {
    origin: `http://127.0.0.1:${address.port}`,
    users,
    policy,
    close: () => new Promise<void>(resolve => { server.closeAllConnections(); server.close(() => resolve()) }),
  }
}

function json(res: ServerResponse, status: number, value: unknown): void {
  res.writeHead(status, { 'content-type': 'application/json' })
  res.end(JSON.stringify(value))
}

async function handle(req: IncomingMessage, res: ServerResponse, users: Map<string, Json>, policy: { role: string }, options: FixtureOptions): Promise<void> {
  const url = new URL(req.url ?? '/', 'http://127.0.0.1')
  const chunks: Buffer[] = []
  if (req.method !== 'GET') for await (const chunk of req) chunks.push(Buffer.from(chunk))
  const caller = typeof req.headers['x-persona'] === 'string' ? req.headers['x-persona'] : null
  const callerId = caller ? USER_OF_PERSONA[caller] : null
  const callerRole = callerId ? String(users.get(callerId)?.role ?? '') : ''

  if (url.pathname === '/api/admin/policy') {
    if (!callerId) return json(res, 401, { error: 'unauthenticated' })
    if (req.method === 'GET') return json(res, 200, policy)
    if (req.method === 'POST') {
      if (options.denyLowPrivPromote && callerRole !== 'admin') return json(res, 403, { error: 'forbidden' })
      // Merge-and-echo: the acknowledgement alone never proves the protected field moved.
      policy.role = 'admin'
      return json(res, 200, { ok: true, ...policy })
    }
  }
  if (url.pathname === '/api/profile') {
    if (!callerId) return json(res, 401, { error: 'unauthenticated' })
    return json(res, 200, users.get(callerId))
  }
  // Detail read of one account. The privileged actor may read it; that is the pre/post readback the
  // generic (no explicit hint) synthesizer derives from the route shape.
  const detail = /^\/api\/admin\/users\/([A-Za-z0-9_-]{1,32})$/.exec(url.pathname)
  if (detail && req.method === 'GET') {
    if (!callerId) return json(res, 401, { error: 'unauthenticated' })
    if (callerRole !== 'admin') return json(res, 403, { error: 'forbidden' })
    const row = users.get(detail[1]!)
    return row ? json(res, 200, row) : json(res, 404, { error: 'not_found' })
  }
  const promote = /^\/api\/admin\/users\/([A-Za-z0-9_-]{1,32})\/promote$/.exec(url.pathname)
  if (promote && req.method === 'POST') {
    if (!callerId) return json(res, 401, { error: 'unauthenticated' })
    if (options.denyLowPrivPromote && callerRole !== 'admin') return json(res, 403, { error: 'forbidden' })
    const row = users.get(promote[1]!)
    if (!row) return json(res, 404, { error: 'user not found' })
    let nextRole = 'admin'
    if (chunks.length > 0) {
      try {
        const parsed = JSON.parse(Buffer.concat(chunks).toString('utf8')) as { role?: unknown }
        if (typeof parsed.role === 'string' && parsed.role) nextRole = parsed.role
      } catch { /* keep default */ }
    }
    users.set(promote[1]!, { ...row, role: nextRole })
    // The buggy function echoes the new role; the echo alone is never accepted as persistence.
    return json(res, 200, { ok: true, user: promote[1], role: nextRole })
  }
  const invoice = /^\/api\/invoices\/([a-z0-9]{1,8})$/.exec(url.pathname)
  if (invoice && req.method === 'GET') {
    if (!callerId) return json(res, 401, { error: 'unauthenticated' })
    return json(res, 200, { id: invoice[1], tenant: 'acme', amount_cents: 4200 })
  }
  json(res, 404, { error: 'not_found' })
}

// ---------------------------------------------------------------------------
// Personas / grant / verifier
// ---------------------------------------------------------------------------

function personaOf(handle: string, origin: string): ResolvedPersona {
  return {
    id: handle,
    handle,
    roleLabel: ROLE_LABEL[handle] ?? handle,
    originAllowlist: [origin],
    authKind: 'header',
    headerName: 'X-Persona',
    secret: handle,
    canaryMarkers: [],
  }
}

function grantFor(origin: string): Grant {
  return {
    origin,
    tier: 3,
    allowLocalLab: true,
    maxRpsPerOrigin: 100,
    canRead: candidate => candidate === origin,
    isIdempotentPostAllowed: () => true,
    isStateChangeApproved: () => true,
    personas: new Map(Object.keys(ROLE_LABEL).map(handle => [handle, personaOf(handle, origin)])),
    audit: () => undefined,
  }
}

async function verify(spec: Json, origin: string) {
  const parsed = declarativeReplaySpecSchema.safeParse(spec)
  assert.equal(parsed.success, true, parsed.success ? '' : JSON.stringify(parsed.error.issues))
  return verifyReplaySpec({
    spec,
    broker: new RequestBroker({ rejectUnauthorized: false }),
    backend: new LocalJqBackend(),
    grant: grantFor(origin),
    signal: AbortSignal.timeout(30_000),
  })
}

function signal(anomalies: Array<Record<string, unknown>>, matrix: Array<Record<string, unknown>>): DifferentialResult {
  return {
    probeClass: 'authz_matrix',
    origin: 'http://fixture.invalid',
    pathAndQuery: '/api/admin/users/{{id}}/promote',
    method: 'POST',
    verdict: 'signal',
    summary: 'A non-owner actor received a mutating 2xx response.',
    requestsSent: 0,
    exchangeIds: [],
    stoppedReason: null,
    anomalies,
    details: { matrix },
  } as unknown as DifferentialResult
}

/**
 * xben-12 shape as the engine forms it: an elevated `/admin/users/{id}/promote` action asserted by
 * an admin control and a lower-role probe. `readbackPath` names the harvested self-profile route the
 * mutated account can read; without it the synthesizer derives a detail read from the route shape.
 */
function promoteHypothesis(origin: string, readback?: { path: string; persona: string }): EngineHypothesis {
  return {
    key: 'authz|promote',
    endpoint: {
      id: 'POST:/api/admin/users/{id}/promote',
      origin,
      method: 'POST',
      pathTemplate: '/api/admin/users/{id}/promote',
      params: [{ name: 'id', location: 'path', isObjectId: true }],
    },
    probeClass: 'authz_matrix',
    intent: 'authz',
    method: 'POST',
    pathAndQuery: '/api/admin/users/{{id}}/promote',
    ownerPersona: 'admin',
    otherPersona: 'viewer',
    resourceIds: ['u-1001'],
    functionLevel: false,
    jsonBody: { role: 'admin' },
    authzRequiredRole: 'admin',
    ...(readback ? { readbackPath: readback.path, readbackPersona: readback.persona } : {}),
    risk: 95,
  }
}

function promoteMatrix(id = 'u-1001'): Array<Record<string, unknown>> {
  return [
    { resourceId: id, actor: 'owner', status: 200, bodyBytes: 42, bodySha256: 'owner', accessible: true },
    { resourceId: id, actor: 'other_persona', status: 200, bodyBytes: 42, bodySha256: 'probe', accessible: true },
  ]
}

function promoteAnomaly(id = 'u-1001'): Array<Record<string, unknown>> {
  return [{ type: 'unauthorized_access', resourceId: id, actor: 'other_persona', method: 'POST', status: 200, functionLevel: false, bodyTemplate: { role: 'admin' } }]
}

// ---------------------------------------------------------------------------
// 1. Function-level BFLA confirms only with the post-readback protected change
// ---------------------------------------------------------------------------

test('product: a privileged promote proof carries a pre/post readback and confirms on the role change', async () => {
  const fx = await startFixture()
  try {
    const hyp = promoteHypothesis(fx.origin)
    const specs = synthesizeEngineSpecs(hyp, signal(promoteAnomaly(), promoteMatrix()))
    assert.equal(specs.length, 1)
    const spec = specs[0]!.spec as Json
    assert.equal(declarativeReplaySpecSchema.safeParse(spec).success, true)
    assert.equal(spec.requiredRole, 'admin')
    const steps = spec.steps as Array<{ id: string; role: string; request: { method: string; pathAndQuery: string; persona?: string } }>
    assert.deepEqual(steps.map(step => step.id), ['w1', 'c2', 'c3', 'c1', 'p1', 'p2'])
    // A separate read of the mutated account brackets the lower-privileged mutation.
    assert.equal(steps[3]!.request.method, 'GET')
    assert.equal(steps[3]!.request.pathAndQuery, '/api/admin/users/u-1001')
    assert.equal(steps[4]!.request.method, 'POST')
    assert.equal(steps[4]!.request.persona, 'viewer')
    assert.equal(steps[5]!.request.method, 'GET')
    assert.equal(steps[5]!.request.pathAndQuery, '/api/admin/users/u-1001')
    // Deterministic: the same observation always produces byte-identical steps.
    assert.deepEqual(synthesizeEngineSpecs(hyp, signal(promoteAnomaly(), promoteMatrix()))[0]!.spec, spec)

    const res = await verify(spec, fx.origin)
    assert.equal(res.verdict, 'confirmed', String(res.outcome.reason))
    assert.equal(res.outcome.confirmed, true)
    assert.equal(fx.users.get('u-1001')?.role, 'admin')
  } finally { await fx.close() }
})

// ---------------------------------------------------------------------------
// 1b. True function-level BFLA (no identifier) brackets the same function surface
// ---------------------------------------------------------------------------

test('product: a function-level BFLA proof brackets the function surface with owner reads', async () => {
  const fx = await startFixture()
  try {
    const hyp: EngineHypothesis = {
      key: 'authz|admin-policy',
      endpoint: {
        id: 'POST:/api/admin/policy',
        origin: fx.origin,
        method: 'POST',
        pathTemplate: '/api/admin/policy',
        params: [],
      },
      probeClass: 'authz_matrix',
      intent: 'authz',
      method: 'POST',
      pathAndQuery: '/api/admin/policy',
      ownerPersona: 'admin',
      otherPersona: 'viewer',
      functionLevel: true,
      jsonBody: { role: 'admin' },
      authzRequiredRole: 'admin',
      risk: 95,
    }
    const result = signal(
      [{ type: 'unauthorized_access', resourceId: '', actor: 'other_persona', method: 'POST', status: 200, functionLevel: true, bodyTemplate: { role: 'admin' } }],
      [
        { resourceId: '', actor: 'owner', status: 200, bodyBytes: 17, bodySha256: 'owner', accessible: true },
        { resourceId: '', actor: 'other_persona', status: 200, bodyBytes: 17, bodySha256: 'probe', accessible: true },
      ],
    )
    const specs = synthesizeEngineSpecs(hyp, result)
    assert.equal(specs.length, 1)
    const spec = specs[0]!.spec as Json
    assert.equal(declarativeReplaySpecSchema.safeParse(spec).success, true)
    assert.equal(spec.requiredRole, 'admin')
    const steps = spec.steps as Array<{ id: string; role: string; request: { method: string; pathAndQuery: string; persona?: string } }>
    // No object identifier, so no negative id control; owner reads bracket the function surface and
    // the lower-privileged actor re-reads the function state it changed.
    assert.deepEqual(steps.map(step => step.id), ['c1', 'p1', 'p2', 'p3'])
    assert.equal(steps[0]!.request.method, 'GET')
    assert.equal(steps[0]!.request.pathAndQuery, '/api/admin/policy')
    assert.equal(steps[1]!.request.method, 'POST')
    assert.equal(steps[1]!.request.persona, 'viewer')
    assert.equal(steps[2]!.request.method, 'GET')
    assert.equal(steps[3]!.request.persona, 'viewer')

    const res = await verify(spec, fx.origin)
    assert.equal(res.verdict, 'confirmed', String(res.outcome.reason))
    assert.equal(fx.policy.role, 'admin')
  } finally { await fx.close() }
})

// ---------------------------------------------------------------------------
// 2. A denied low-privilege mutation stays inconclusive
// ---------------------------------------------------------------------------

test('product: a denied low-privilege mutation stays inconclusive', async () => {
  const fx = await startFixture({ denyLowPrivPromote: true })
  try {
    const specs = synthesizeEngineSpecs(promoteHypothesis(fx.origin), signal(promoteAnomaly(), promoteMatrix()))
    assert.equal(specs.length, 1)
    const res = await verify(specs[0]!.spec as Json, fx.origin)
    assert.notEqual(res.verdict, 'confirmed', String(res.outcome.reason))
    assert.equal(res.outcome.confirmed, false)
    assert.equal(fx.users.get('u-1001')?.role, 'member')
  } finally { await fx.close() }
})

// ---------------------------------------------------------------------------
// 3. A read-only authorization probe is unchanged
// ---------------------------------------------------------------------------

test('product: a read-only cross-actor proof keeps its three-step shape', () => {
  const hyp: EngineHypothesis = {
    key: 'authz|invoice-read',
    endpoint: {
      id: 'GET:/api/invoices/{id}',
      origin: 'http://fixture.invalid',
      method: 'GET',
      pathTemplate: '/api/invoices/{id}',
      params: [{ name: 'id', location: 'path', isObjectId: true }],
    },
    probeClass: 'authz_matrix',
    intent: 'authz',
    method: 'GET',
    pathAndQuery: '/api/invoices/{{id}}',
    ownerPersona: 'persona_a',
    otherPersona: 'persona_b',
    resourceIds: ['i1'],
    functionLevel: false,
    risk: 60,
  }
  const result = signal(
    [{ type: 'unauthorized_access', resourceId: 'i1', actor: 'other_persona', method: 'GET', status: 200, similarityToOwner: 1 }],
    [
      { resourceId: 'i1', actor: 'owner', status: 200, bodyBytes: 64, bodySha256: 'a', accessible: true },
      { resourceId: 'i1', actor: 'other_persona', status: 200, bodyBytes: 64, bodySha256: 'a', similarityToOwner: 1, accessible: true },
    ],
  )
  const specs = synthesizeEngineSpecs(hyp, result)
  assert.equal(specs.length, 1)
  const spec = specs[0]!.spec as Json
  assert.equal(declarativeReplaySpecSchema.safeParse(spec).success, true)
  assert.equal(spec.requiredRole, undefined)
  const steps = spec.steps as Array<{ id: string; request: { method: string } }>
  assert.deepEqual(steps.map(step => step.id), ['c2', 'c1', 'p1'])
  assert.equal(steps[1]!.request.method, 'GET')
  assert.equal(steps[2]!.request.method, 'GET')
})

// ---------------------------------------------------------------------------
// 4. xben-12 shape reproduces through the benchmark parity synthesizer
// ---------------------------------------------------------------------------

function parityEnv(origin: string): ProbeEnv {
  return {
    origin,
    owner: 'persona_a',
    other: 'persona_b',
    admin: 'admin',
    viewer: 'viewer',
    ownerUserId: 'u-1001',
    otherUserId: 'u-1002',
    viewerUserId: 'u-1003',
    personaUserIds: ['u-1000', 'u-1001', 'u-1002', 'u-1003'],
    caps: { sessionAndCsrf: false },
    session: 'bench',
    slowProbesLeft: 0,
    endpoints: [{ method: 'GET', path: '/api/profile', params: [] }],
    idCache: new Map<string, string[]>(),
  } as unknown as ProbeEnv
}

function parityOutcome(origin: string): HypothesisOutcome {
  return {
    hyp: {
      key: 'authz|promote',
      endpoint: { method: 'POST', path: '/api/admin/users/{id}/promote', params: [{ name: 'id', location: 'path', isObjectId: true }] },
      probeClass: 'authz_matrix',
      method: 'POST',
    },
    pair: { owner: 'admin', other: 'viewer' },
    verdict: 'signal',
    anomalies: promoteAnomaly(),
    details: { matrix: promoteMatrix() },
    csrfRejected: false,
    contextReset: false,
    tierBlocked: false,
    requests: 0,
  } as unknown as HypothesisOutcome
}

test('parity: the xben-12 self-profile readback confirms the promoted role', async () => {
  const fx = await startFixture()
  try {
    const env = parityEnv(fx.origin)
    const specs = synthAuthz(parityOutcome(fx.origin), env)
    assert.ok(specs.length >= 1)
    const spec = specs[0]!.spec
    assert.equal(declarativeReplaySpecSchema.safeParse(spec).success, true)
    assert.equal((spec as Json).requiredRole, 'admin')
    assert.equal((spec as Json).cwe, 'CWE-285')
    const steps = (spec as Json).steps as Array<{ id: string; request: { method: string; pathAndQuery: string; persona?: string } }>
    // Fresh self-service victim: the viewer invokes the admin function on its own account and reads
    // its own profile back, so the observed (already-promoted) identifiers cannot mask the change.
    assert.equal(steps[1]!.request.pathAndQuery, '/api/admin/users/u-1003/promote')
    assert.equal(steps[1]!.request.persona, 'viewer')
    assert.equal(steps.find(step => step.id === 'c1')!.request.pathAndQuery, '/api/profile')
    assert.equal(steps.find(step => step.id === 'p2')!.request.pathAndQuery, '/api/profile')
    assert.equal(steps.find(step => step.id === 'p2')!.request.persona, 'viewer')
    // Determinism: repeated synthesis is identical.
    assert.deepEqual(synthAuthz(parityOutcome(fx.origin), parityEnv(fx.origin))[0]!.spec, spec)

    const res = await verify(spec as Json, fx.origin)
    assert.equal(res.verdict, 'confirmed', String(res.outcome.reason))
    assert.equal(fx.users.get('u-1003')?.role, 'admin')
  } finally { await fx.close() }
})

test('parity: a hardened promote function keeps the same proof inconclusive', async () => {
  const fx = await startFixture({ denyLowPrivPromote: true })
  try {
    const specs = synthAuthz(parityOutcome(fx.origin), parityEnv(fx.origin))
    assert.ok(specs.length >= 1)
    const res = await verify(specs[0]!.spec as Json, fx.origin)
    assert.notEqual(res.verdict, 'confirmed', String(res.outcome.reason))
    assert.equal(res.outcome.confirmed, false)
    assert.equal(fx.users.get('u-1003')?.role, 'viewer')
  } finally { await fx.close() }
})
