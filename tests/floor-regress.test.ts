// floor-regress: the four Layer-2 spec recipes that restore the post-verifier-harden floor.
//
// Every fixture below is a synthetic wind-twin pair: the vulnerable twin persists the state change,
// the hardened twin refuses or ignores it. A recipe is only accepted when it confirms on the
// vulnerable twin AND stays unconfirmed on the hardened twin. The recipes are:
//  - fresh baseline value for a lifecycle/state field (a re-sent value is an idempotent no-op);
//  - mass assignment of a privileged column, proven through a separate readback;
//  - a LIKE-wrapped boolean SQL differential whose baseline must not match on its own;
//  - a privileged function whose only observable effect is the caller's own identity state.
//
// No benchmark-app name or route literal appears in the assertions: inputs are synthetic shapes and
// the engine derives every path/field from the fixture's own responses.
import assert from 'node:assert/strict'
import { createServer } from 'node:http'
import type { IncomingMessage, ServerResponse } from 'node:http'
import { once } from 'node:events'
import { test } from 'node:test'

process.env.GUARDIAN_ALLOW_LOCAL_LAB = '1'

import { RequestBroker } from '../src/server/broker.ts'
import type { Grant } from '../src/server/broker.ts'
import type { ResolvedPersona } from '../src/server/persona-vault.ts'
import { verifyReplaySpec } from '../src/server/replay-verifier.ts'
import { declarativeReplaySpecSchema } from '../src/replay-spec.ts'
import { LocalJqBackend } from '../scripts/benchmark-backend.ts'
import { synthesizeEngineSpecs } from '../src/server/deterministic-specs.ts'
import type { EngineHypothesis } from '../src/server/deterministic-specs.ts'
import {
  buildIdentityProfiles,
  enumerateHypotheses,
} from '../src/server/deterministic-engine.ts'
import type { EndpointHarvest, EngineEndpoint, EnginePersona } from '../src/server/deterministic-engine.ts'
import type { DifferentialResult } from '../src/server/surface-engine.ts'

type Json = Record<string, unknown>

// ---------------------------------------------------------------------------
// Personas / grant / verifier
// ---------------------------------------------------------------------------

const ROLE_LABEL: Record<string, string> = {
  admin: 'admin (acme)',
  owner_a: 'owner (acme)',
  owner_b: 'owner (globex)',
  viewer: 'viewer (acme)',
}

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

function json(res: ServerResponse, status: number, value: unknown): void {
  res.writeHead(status, { 'content-type': 'application/json' })
  res.end(JSON.stringify(value))
}

async function readBody(req: IncomingMessage): Promise<Json> {
  const chunks: Buffer[] = []
  for await (const chunk of req) chunks.push(Buffer.from(chunk))
  if (chunks.length === 0) return {}
  try {
    const parsed = JSON.parse(Buffer.concat(chunks).toString('utf8')) as unknown
    return parsed && typeof parsed === 'object' && !Array.isArray(parsed) ? parsed as Json : {}
  } catch { return {} }
}

const PERSONA_TENANT: Record<string, string> = {
  admin: 'acme',
  owner_a: 'acme',
  owner_b: 'globex',
  viewer: 'acme',
}

function startFixture(handler: (req: IncomingMessage, res: ServerResponse, caller: string) => Promise<void>) {
  const server = createServer((req, res) => {
    const caller = typeof req.headers['x-persona'] === 'string' ? req.headers['x-persona'] : ''
    void handler(req, res, caller).catch(error => {
      if (!res.headersSent) res.statusCode = 500
      res.end(String(error))
    })
  })
  server.listen(0, '127.0.0.1')
  return once(server, 'listening').then(() => {
    const address = server.address()
    if (!address || typeof address === 'string') throw new Error('fixture did not bind')
    return {
      origin: `http://127.0.0.1:${address.port}`,
      close: () => new Promise<void>(resolve => { server.closeAllConnections(); server.close(() => resolve()) }),
    }
  })
}

function signal(anomalies: Array<Record<string, unknown>>, matrix: Array<Record<string, unknown>>, over: Partial<DifferentialResult> = {}): DifferentialResult {
  return {
    probeClass: 'authz_matrix',
    origin: 'http://fixture.invalid',
    pathAndQuery: '/',
    method: 'PATCH',
    verdict: 'signal',
    summary: 'A lower-privileged actor received a mutating 2xx response.',
    requestsSent: 0,
    exchangeIds: [],
    stoppedReason: null,
    anomalies,
    details: { matrix },
    ...over,
  } as unknown as DifferentialResult
}

// ---------------------------------------------------------------------------
// 1. Fresh baseline value for a lifecycle/state field
// ---------------------------------------------------------------------------

interface ShipmentOptions { hardened?: boolean }

function startShipmentFixture(options: ShipmentOptions = {}) {
  const rows = new Map<string, Json>([
    ['s-1', { id: 's-1', owner: 'acme', status: 'pending' }],
  ])
  return startFixture(async (req, res, caller) => {
    const url = new URL(req.url ?? '/', 'http://127.0.0.1')
    const detail = /^\/api\/shipments\/([A-Za-z0-9_-]{1,32})$/.exec(url.pathname)
    if (!detail) return json(res, 404, { error: 'not_found' })
    const row = rows.get(detail[1]!)
    if (!caller) return json(res, 401, { error: 'unauthenticated' })
    if (!row) return json(res, 404, { error: 'not_found' })
    if (req.method === 'GET') return json(res, 200, row)
    if (req.method !== 'PATCH') return json(res, 405, { error: 'method' })
    const tenant = PERSONA_TENANT[caller] ?? ''
    // Hardened twin re-checks ownership of the addressed row before writing.
    if (options.hardened && row.owner !== tenant) return json(res, 404, { error: 'not_found' })
    const body = await readBody(req)
    if (body.status !== undefined) rows.set(detail[1]!, { ...row, status: String(body.status) })
    return json(res, 200, { ok: true, id: detail[1] })
  })
}

function shipmentHypothesis(origin: string): EngineHypothesis {
  return {
    key: 'authz|shipments',
    endpoint: {
      id: 'PATCH:/api/shipments/{id}',
      origin,
      method: 'PATCH',
      pathTemplate: '/api/shipments/{id}',
      params: [{ name: 'id', location: 'path', isObjectId: true }],
    },
    probeClass: 'authz_matrix',
    intent: 'authz',
    method: 'PATCH',
    pathAndQuery: '/api/shipments/{{id}}',
    ownerPersona: 'owner_a',
    otherPersona: 'owner_b',
    resourceIds: ['s-1'],
    // The harvested body carries the value the record already holds: a re-send is a no-op.
    jsonBody: { status: 'pending' },
    risk: 90,
  }
}

function shipmentSignal(): DifferentialResult {
  return signal(
    [{ type: 'unauthorized_access', resourceId: 's-1', actor: 'other_persona', method: 'PATCH', status: 200, functionLevel: false, bodyTemplate: { status: 'pending' } }],
    [
      { resourceId: 's-1', actor: 'owner', status: 200, bodyBytes: 60, bodySha256: 'owner', accessible: true },
      { resourceId: 's-1', actor: 'other_persona', status: 200, bodyBytes: 60, bodySha256: 'probe', accessible: true },
    ],
  )
}

test('floor: a state-field mutation carries a fresh baseline write', async () => {
  const fx = await startShipmentFixture()
  try {
    const specs = synthesizeEngineSpecs(shipmentHypothesis(fx.origin), shipmentSignal())
    assert.equal(specs.length, 1)
    const spec = specs[0]!.spec as Json
    const steps = spec.steps as Array<{ id: string; role: string; request: { method: string; pathAndQuery: string; jsonBody?: Json } }>
    assert.deepEqual(steps.map(step => step.id), ['c2', 'w1', 'c1', 'p1', 'p2'])
    const baseline = steps[1]!
    assert.equal(baseline.request.method, 'PATCH')
    assert.equal(typeof baseline.request.jsonBody?.status, 'string')
    assert.notEqual(baseline.request.jsonBody?.status, 'pending')
    assert.equal(steps[3]!.request.jsonBody?.status, 'pending')

    const res = await verify(spec, fx.origin)
    assert.equal(res.verdict, 'confirmed', String(res.outcome.reason))
  } finally { await fx.close() }
})

test('floor: the same state-field recipe stays unconfirmed on the ownership-checked twin', async () => {
  const fx = await startShipmentFixture({ hardened: true })
  try {
    const spec = synthesizeEngineSpecs(shipmentHypothesis(fx.origin), shipmentSignal())[0]!.spec as Json
    const res = await verify(spec, fx.origin)
    assert.notEqual(res.verdict, 'confirmed', 'the hardened twin must not confirm')
  } finally { await fx.close() }
})

// ---------------------------------------------------------------------------
// 2. Mass assignment of a privileged column (declared impact event)
// ---------------------------------------------------------------------------

function startUserFixture(options: { hardened?: boolean } = {}) {
  const rows = new Map<string, Json>([
    ['u-1', { id: 'u-1', role: 'member', name: 'Pat' }],
  ])
  return startFixture(async (req, res, caller) => {
    const url = new URL(req.url ?? '/', 'http://127.0.0.1')
    const detail = /^\/api\/users\/([A-Za-z0-9_-]{1,32})$/.exec(url.pathname)
    if (!detail) return json(res, 404, { error: 'not_found' })
    if (!caller) return json(res, 401, { error: 'unauthenticated' })
    const row = rows.get(detail[1]!)
    if (!row) return json(res, 404, { error: 'not_found' })
    if (req.method === 'GET') return json(res, 200, row)
    const body = await readBody(req)
    const next = { ...row }
    // The hardened twin only applies ordinary profile columns; privileged ones are ignored.
    const allowed = options.hardened ? ['name'] : ['name', 'role']
    if (typeof body.name === 'string' && allowed.includes('name')) next.name = body.name
    if (typeof body.role === 'string' && allowed.includes('role')) next.role = body.role
    rows.set(detail[1]!, next)
    return json(res, 200, { ok: true, updated: Object.keys(body).length })
  })
}

function massHypothesis(origin: string): EngineHypothesis {
  return {
    key: 'mass_assignment|users',
    endpoint: {
      id: 'PATCH:/api/users/{id}',
      origin,
      method: 'PATCH',
      pathTemplate: '/api/users/{id}',
      params: [{ name: 'id', location: 'path', isObjectId: true }],
    },
    probeClass: 'mass_assignment',
    intent: 'mass_assignment',
    method: 'PATCH',
    pathAndQuery: '/api/users/u-1',
    ownerPersona: 'viewer',
    otherPersona: 'owner_b',
    candidateFields: ['role'],
    candidateValues: { role: 'owner' },
    jsonBody: { name: 'Pat' },
    risk: 80,
  }
}

function massSignal(): DifferentialResult {
  return {
    probeClass: 'mass_assignment',
    origin: 'http://fixture.invalid',
    pathAndQuery: '/api/users/u-1',
    method: 'PATCH',
    verdict: 'signal',
    summary: 'Privileged field "role" persisted after PATCH.',
    requestsSent: 0,
    exchangeIds: [],
    stoppedReason: null,
    anomalies: [{ type: 'mass_assignment', field: 'role', writeStatus: 200, persisted: true }],
    details: { results: [{ field: 'role', writeStatus: 200, persisted: true }] },
  } as unknown as DifferentialResult
}

test('floor: a persisted privileged column confirms through the readback chain', async () => {
  const fx = await startUserFixture()
  try {
    const specs = synthesizeEngineSpecs(massHypothesis(fx.origin), massSignal())
    assert.equal(specs.length, 1)
    const spec = specs[0]!.spec as Json
    assert.deepEqual(spec.expectedImpactEvents, ['mass_assignment'])
    const steps = spec.steps as Array<{ id: string; request: { method: string; pathAndQuery: string } }>
    assert.deepEqual(steps.map(step => step.id), ['w1', 'c1', 'p1', 'p2'])
    const res = await verify(spec, fx.origin)
    assert.equal(res.verdict, 'confirmed', String(res.outcome.reason))
  } finally { await fx.close() }
})

test('floor: the mass-assignment recipe stays unconfirmed when the privileged column is ignored', async () => {
  const fx = await startUserFixture({ hardened: true })
  try {
    const spec = synthesizeEngineSpecs(massHypothesis(fx.origin), massSignal())[0]!.spec as Json
    const res = await verify(spec, fx.origin)
    assert.notEqual(res.verdict, 'confirmed', 'the hardened twin must not confirm')
  } finally { await fx.close() }
})

// ---------------------------------------------------------------------------
// 3. LIKE-wrapped boolean SQL differential (baseline must discriminate)
// ---------------------------------------------------------------------------

function startSearchFixture(options: { hardened?: boolean } = {}) {
  const titles = ['alpha widget', 'beta widget', 'gamma widget']
  return startFixture(async (req, res, caller) => {
    if (!caller) return json(res, 401, { error: 'unauthenticated' })
    const url = new URL(req.url ?? '/', 'http://127.0.0.1')
    if (url.pathname !== '/api/search') return json(res, 404, { error: 'not_found' })
    const term = url.searchParams.get('q') ?? ''
    if (options.hardened) {
      // Parameterized lookup: the term never reaches the SQL structure.
      const results = titles.filter(title => title.includes(term))
      return json(res, 200, { query: term, results })
    }
    const injected = /' OR (\d+)=(\d+)-- -/.exec(term)
    if (injected) {
      const holds = injected[1] === injected[2]
      return json(res, 200, { results: holds ? titles : [] })
    }
    return json(res, 200, { results: titles.filter(title => title.includes(term)) })
  })
}

function sqliHypothesis(origin: string, baselineValue: string): EngineHypothesis {
  return {
    key: 'sqli|search',
    endpoint: {
      id: 'GET:/api/search',
      origin,
      method: 'GET',
      pathTemplate: '/api/search',
      params: [{ name: 'q', location: 'query' }],
    },
    probeClass: 'sqli_boolean',
    intent: 'sqli',
    method: 'GET',
    pathAndQuery: '/api/search',
    param: { name: 'q', location: 'query' },
    location: 'query',
    ownerPersona: 'owner_a',
    baselineValue,
    risk: 70,
  }
}

function sqliSignal(): DifferentialResult {
  return {
    probeClass: 'sqli_boolean',
    origin: 'http://fixture.invalid',
    pathAndQuery: '/api/search',
    method: 'GET',
    verdict: 'signal',
    summary: 'Boolean differential (or_branch) held across randomized rounds.',
    requestsSent: 0,
    exchangeIds: [],
    stoppedReason: null,
    anomalies: [{ type: 'boolean_differential', style: 'or_branch' }],
    details: {},
  } as unknown as DifferentialResult
}

test('floor: a broad LIKE baseline is ordered so a non-matching term is tried first', () => {
  const specs = synthesizeEngineSpecs(sqliHypothesis('http://fixture.invalid', ''), sqliSignal())
  assert.ok(specs.length >= 2)
  const baselines = specs.map(spec => String((spec.spec as Json).baselineValue ?? ''))
  // The first (empty) baseline cannot separate a LIKE '%' match, so the next tried candidate is a
  // fresh non-matching term rather than another common character.
  assert.equal(baselines[0], '')
  assert.match(baselines[1] ?? '', /^guardian-[a-f0-9]{8}$/)
})

test('floor: the discriminating baseline confirms on the concatenating twin', async () => {
  const fx = await startSearchFixture()
  try {
    const specs = synthesizeEngineSpecs(sqliHypothesis(fx.origin, ''), sqliSignal())
    const nonce = specs.find(spec => /^guardian-/.test(String((spec.spec as Json).baselineValue ?? '')))
    assert.ok(nonce, 'a fresh baseline candidate exists')
    const res = await verify(nonce!.spec as Json, fx.origin)
    assert.equal(res.verdict, 'confirmed', String(res.outcome.reason))
  } finally { await fx.close() }
})

test('floor: the same boolean recipe stays unconfirmed on the parameterized twin', async () => {
  const fx = await startSearchFixture({ hardened: true })
  try {
    const specs = synthesizeEngineSpecs(sqliHypothesis(fx.origin, ''), sqliSignal())
    const nonce = specs.find(spec => /^guardian-/.test(String((spec.spec as Json).baselineValue ?? '')))
    assert.ok(nonce)
    const res = await verify(nonce!.spec as Json, fx.origin)
    assert.notEqual(res.verdict, 'confirmed', 'the hardened twin must not confirm')
  } finally { await fx.close() }
})

// ---------------------------------------------------------------------------
// 4. Privileged function whose observable effect is the caller's identity state
// ---------------------------------------------------------------------------

function startIdentityFixture(options: { hardened?: boolean } = {}) {
  const acting = new Map<string, string>()
  const ownTenant = (caller: string): string => PERSONA_TENANT[caller] ?? ''
  return startFixture(async (req, res, caller) => {
    if (!caller) return json(res, 401, { error: 'unauthenticated' })
    const url = new URL(req.url ?? '/', 'http://127.0.0.1')
    if (url.pathname === '/api/session' && req.method === 'GET') {
      return json(res, 200, { actor: caller, store: acting.get(caller) ?? ownTenant(caller) })
    }
    if (url.pathname === '/api/admin/act-as' && req.method === 'POST') {
      if (options.hardened && caller !== 'admin') return json(res, 403, { error: 'forbidden' })
      const body = await readBody(req)
      if (typeof body.store === 'string') acting.set(caller, body.store)
      return json(res, 200, { ok: true, actingAs: body.store ?? '' })
    }
    json(res, 404, { error: 'not_found' })
  })
}

function identityHypothesis(origin: string): EngineHypothesis {
  return {
    key: 'authz-self|act-as',
    endpoint: {
      id: 'POST:/api/admin/act-as',
      origin,
      method: 'POST',
      pathTemplate: '/api/admin/act-as',
      params: [],
    },
    probeClass: 'authz_matrix',
    intent: 'authz',
    method: 'POST',
    pathAndQuery: '/api/admin/act-as',
    ownerPersona: 'admin',
    otherPersona: 'viewer',
    functionLevel: true,
    readbackPath: '/api/session',
    readbackPersona: 'viewer',
    functionState: {
      bindings: [{ field: 'store', value: 'globex' }],
      reset: [{ field: 'store', value: 'acme' }],
      body: { store: 'globex' },
    },
    jsonBody: { store: 'acme' },
    authzRequiredRole: 'admin',
    risk: 95,
  }
}

function identitySignal(origin: string): DifferentialResult {
  return signal(
    [{ type: 'unauthorized_access', resourceId: '', actor: 'other_persona', method: 'POST', status: 200, functionLevel: true, bodyTemplate: { store: 'globex' } }],
    [
      { resourceId: '', actor: 'owner', status: 200, bodyBytes: 24, bodySha256: 'owner', accessible: true },
      { resourceId: '', actor: 'other_persona', status: 200, bodyBytes: 24, bodySha256: 'probe', accessible: true },
    ],
  ) as DifferentialResult
}

test('floor: a privileged identity mutation is proven by a named state delta on the actor read', async () => {
  const fx = await startIdentityFixture()
  try {
    const specs = synthesizeEngineSpecs(identityHypothesis(fx.origin), identitySignal(fx.origin))
    assert.equal(specs.length, 1)
    const spec = specs[0]!.spec as Json
    const steps = spec.steps as Array<{ id: string; role: string; request: { method: string; pathAndQuery: string; persona?: string; jsonBody?: Json } }>
    assert.deepEqual(steps.map(step => step.id), ['w0', 'c1', 'p1', 'p2'])
    assert.equal(steps[0]!.request.persona, 'viewer')
    assert.equal(steps[0]!.request.jsonBody?.store, 'acme')
    assert.equal(steps[1]!.request.pathAndQuery, '/api/session')
    assert.equal(steps[1]!.request.persona, 'viewer')
    assert.equal(steps[2]!.request.jsonBody?.store, 'globex')
    assert.equal(steps[3]!.request.persona, 'viewer')
    assert.match(String(spec.assertionsJq), /"store"/)
    assert.deepEqual(spec.expectedImpactEvents, ['privilege_escalation'])
    const res = await verify(spec, fx.origin)
    assert.equal(res.verdict, 'confirmed', String(res.outcome.reason))
  } finally { await fx.close() }
})

test('floor: the identity-state recipe stays unconfirmed on the role-checked twin', async () => {
  const fx = await startIdentityFixture({ hardened: true })
  try {
    const spec = synthesizeEngineSpecs(identityHypothesis(fx.origin), identitySignal(fx.origin))[0]!.spec as Json
    const res = await verify(spec, fx.origin)
    assert.notEqual(res.verdict, 'confirmed', 'the hardened twin must not confirm')
  } finally { await fx.close() }
})

// ---------------------------------------------------------------------------
// 5. Engine-side inference: identity profiles and the writer's own row
// ---------------------------------------------------------------------------

const PERSONAS: EnginePersona[] = [
  { handle: 'admin', roleLabel: ROLE_LABEL.admin!, privilege: 'admin', tenant: 'acme' },
  { handle: 'owner_a', roleLabel: ROLE_LABEL.owner_a!, privilege: 'member', tenant: 'acme' },
  { handle: 'owner_b', roleLabel: ROLE_LABEL.owner_b!, privilege: 'member', tenant: 'globex' },
  { handle: 'viewer', roleLabel: ROLE_LABEL.viewer!, privilege: 'viewer', tenant: 'acme' },
]

function harvestOf(over: Partial<EndpointHarvest> = {}): EndpointHarvest {
  return {
    ownerIds: [], otherIds: [], fields: [], values: {}, otherValues: {},
    seedValues: [], activeQueryParams: [], viewerIds: [], rowIds: {}, ...over,
  }
}

test('engine: identity profiles bind only the cross-actor scope fields', () => {
  const origin = 'http://fixture.invalid'
  const identity: EngineEndpoint = { id: 'GET:/api/session', origin, method: 'GET', pathTemplate: '/api/session', params: [] }
  const harvests = new Map<string, EndpointHarvest>([
    [identity.id, harvestOf({
      values: { actor: ['admin'], role: ['admin'], store: ['acme'], csrf: ['t1'] },
      otherValues: { actor: ['owner_b'], role: ['owner'], store: ['globex'], csrf: ['t2'] },
    })],
  ])
  const profiles = buildIdentityProfiles([identity], harvests)
  const profile = profiles.get(origin)
  assert.ok(profile)
  assert.equal(profile!.path, '/api/session')
  assert.deepEqual(profile!.bindings.map(binding => binding.field).sort(), ['role', 'store'])
})

test('engine: a privileged mutation forms a self-state variant bound to the identity read', () => {
  const origin = 'http://fixture.invalid'
  const actAs: EngineEndpoint = { id: 'POST:/api/admin/act-as', origin, method: 'POST', pathTemplate: '/api/admin/act-as', params: [] }
  const identity: EngineEndpoint = { id: 'GET:/api/session', origin, method: 'GET', pathTemplate: '/api/session', params: [] }
  const harvests = new Map<string, EndpointHarvest>([
    [actAs.id, harvestOf({ values: { store: ['acme'] }, fields: [] })],
    [identity.id, harvestOf({
      values: { store: ['acme'] },
      otherValues: { store: ['globex'] },
      viewerValues: { store: ['acme'] },
    })],
  ])
  const hypotheses = enumerateHypotheses([actAs, identity], harvests, {
    tier: 3,
    personas: PERSONAS,
    identityProfiles: buildIdentityProfiles([actAs, identity], harvests),
  })
  const selfVariant = hypotheses.find(hyp => hyp.key.startsWith('authz-self|'))
  assert.ok(selfVariant, 'a self-state authz variant exists')
  assert.equal(selfVariant!.readbackPath, '/api/session')
  assert.equal(selfVariant!.readbackPersona, 'viewer')
  assert.deepEqual(selfVariant!.functionState?.bindings, [{ field: 'store', value: 'globex' }])
  assert.deepEqual(selfVariant!.functionState?.reset, [{ field: 'store', value: 'acme' }])
  assert.equal(selfVariant!.functionState?.body?.store, 'globex')
  // The probe itself writes the actor's own value, so it never leaves the session mutated.
  assert.equal(selfVariant!.jsonBody?.store, 'acme')
})

test('engine: a self-service update addresses the writer row the collection correlates', () => {
  const origin = 'http://fixture.invalid'
  const users: EngineEndpoint = {
    id: 'PATCH:/api/users/{id}', origin, method: 'PATCH', pathTemplate: '/api/users/{id}',
    params: [{ name: 'id', location: 'path', isObjectId: true }],
  }
  const collection: EngineEndpoint = { id: 'GET:/api/users', origin, method: 'GET', pathTemplate: '/api/users', params: [] }
  const harvests = new Map<string, EndpointHarvest>([
    [users.id, harvestOf({
      ownerIds: ['u-1', 'u-2'],
      fields: ['id', 'name', 'role'],
      values: { id: ['u-1', 'u-2'], name: ['Pat', 'Sam'], role: ['owner', 'viewer'] },
      rowIds: { viewer: 'u-2', Pat: 'u-1', Sam: 'u-2' },
    })],
  ])
  const hypotheses = enumerateHypotheses([users, collection], harvests, { tier: 3, personas: PERSONAS })
  const mass = hypotheses.find(hyp => hyp.probeClass === 'mass_assignment')
  assert.ok(mass, 'a mass-assignment hypothesis exists')
  assert.equal(mass!.ownerPersona, 'viewer')
  assert.equal(mass!.pathAndQuery, '/api/users/u-2')
})
