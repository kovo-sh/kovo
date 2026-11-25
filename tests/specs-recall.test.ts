process.env.KOVO_ALLOW_LOCAL_LAB ??= '1'
/**
 * Spec-shape recall: the five product floor targets that were lost to spec/gate interplay, not to
 * discovery. Each case drives the real deterministic engine's hypothesis + spec synthesis, then
 * replays the spec through ReplayVerifier against a loopback vulnerable twin and its hardened twin.
 * The vulnerable twin must confirm through the unchanged impact/proof gates; the hardened twin must
 * be dismissed.
 *
 * The fixtures are shape-only (REST resources, tenant scoping, credential inventories) and carry no
 * benchmark route or app literals.
 */
import assert from 'node:assert/strict'
import { once } from 'node:events'
import { createServer } from 'node:http'
import type { IncomingMessage, ServerResponse } from 'node:http'
import { test } from 'node:test'

process.env.KOVO_ALLOW_LOCAL_LAB = '1'

import { RequestBroker } from '../src/server/broker.ts'
import type { Grant } from '../src/server/broker.ts'
import { verifyReplaySpec } from '../src/server/replay-verifier.ts'
import { declarativeReplaySpecSchema } from '../src/replay-spec.ts'
import { enumerateHypotheses } from '../src/server/deterministic-engine.ts'
import type { EndpointHarvest, EngineEndpoint, EnginePersona } from '../src/server/deterministic-engine.ts'
import { synthesizeEngineSpecs } from '../src/server/deterministic-specs.ts'
import type { DifferentialResult } from '../src/server/surface-engine.ts'
import { LocalJqBackend } from '../scripts/benchmark-backend.ts'
import type { ResolvedPersona } from '../src/server/persona-vault.ts'

const personas: EnginePersona[] = [
  { handle: 'member-a', roleLabel: 'member (t1)', privilege: 'member', tenant: 't1' },
  { handle: 'member-b', roleLabel: 'member (t2)', privilege: 'member', tenant: 't2' },
  { handle: 'viewer', roleLabel: 'viewer (t1)', privilege: 'viewer', tenant: 't1' },
  { handle: 'admin', roleLabel: 'admin (t1)', privilege: 'admin', tenant: 't1' },
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
    probeClass: 'authz_matrix',
    origin: 'http://127.0.0.1:4100',
    pathAndQuery: '/',
    verdict: 'signal',
    summary: 'differential signal',
    anomalies: [],
    details: {},
    requestsSent: 3,
    exchangeIds: [],
    stoppedReason: null,
    notes: [],
    durationMs: 3,
    ...over,
  }
}

// ---------------------------------------------------------------------------
// Replay harness
// ---------------------------------------------------------------------------

async function fixture(handler: (req: IncomingMessage, res: ServerResponse, body: string) => unknown) {
  const server = createServer(async (req, res) => {
    const chunks: Buffer[] = []
    for await (const chunk of req) chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk))
    const body = Buffer.concat(chunks).toString('utf8')
    await handler(req, res, body)
  }).listen(0, '127.0.0.1')
  await once(server, 'listening')
  const address = server.address()
  if (!address || typeof address === 'string') throw new Error('fixture has no port')
  const origin = `http://127.0.0.1:${address.port}`
  return {
    origin,
    close: () => new Promise<void>(resolve => { server.closeAllConnections(); server.close(() => resolve()) }),
  }
}

function json(res: ServerResponse, status: number, value: unknown): void {
  res.statusCode = status
  res.setHeader('Content-Type', 'application/json')
  res.end(JSON.stringify(value))
}

/** Actor directory: the loopback twin resolves the header value to the same tenant/role. */
type Actor = { tenant: string; role: string; userId: string }

function actorOf(req: IncomingMessage, directory: Record<string, Actor>): Actor | null {
  const handle = req.headers['x-persona']
  return typeof handle === 'string' ? directory[handle] ?? null : null
}

function persona(handle: string, origin: string): ResolvedPersona {
  const role = handle === 'admin' ? 'admin' : handle === 'viewer' ? 'viewer' : 'member'
  const tenant = handle === 'member-b' ? 't2' : 't1'
  return {
    id: handle,
    handle,
    roleLabel: `${role} (${tenant})`,
    originAllowlist: [origin],
    authKind: 'header',
    headerName: 'X-Persona',
    secret: handle,
    canaryMarkers: [],
  }
}

function grantFor(origin: string, personasByHandle: string[]): Grant {
  return {
    origin,
    tier: 3,
    allowLocalLab: true,
    maxRpsPerOrigin: 100,
    canRead: candidate => candidate === origin,
    isIdempotentPostAllowed: () => true,
    isStateChangeApproved: () => true,
    personas: new Map(personasByHandle.map(handle => [handle, persona(handle, origin)])),
    audit: () => undefined,
  }
}

async function verify(spec: Record<string, unknown>, origin: string, personaHandles: string[]) {
  const parsed = declarativeReplaySpecSchema.safeParse(spec)
  assert.equal(parsed.success, true, parsed.success ? '' : JSON.stringify(parsed.error.issues))
  const broker = new RequestBroker({ rejectUnauthorized: false })
  return verifyReplaySpec({
    spec: parsed.data,
    broker,
    backend: new LocalJqBackend(),
    grant: grantFor(origin, personaHandles),
    signal: AbortSignal.timeout(20_000),
  })
}

function authzHypothesis(
  surface: EngineEndpoint[],
  harvests: Map<string, EndpointHarvest>,
  method: 'POST' | 'PUT' | 'PATCH' | 'DELETE' | 'GET',
  pathTemplate: string,
) {
  const hypotheses = enumerateHypotheses(surface, harvests, { tier: 3, personas })
  const hyp = hypotheses.find(candidate =>
    candidate.probeClass === 'authz_matrix' &&
    candidate.method === method &&
    candidate.endpoint.pathTemplate === pathTemplate)
  assert.ok(hyp, `expected an authz hypothesis on ${method} ${pathTemplate}`)
  return hyp
}

// ---------------------------------------------------------------------------
// 1. Cross-tenant write: baseline write makes the probe a real delta
// ---------------------------------------------------------------------------

function invoiceFixture(hardened: boolean) {
  const directory: Record<string, Actor> = {
    'member-a': { tenant: 't1', role: 'member', userId: 'u-a' },
    'member-b': { tenant: 't2', role: 'member', userId: 'u-b' },
    viewer: { tenant: 't1', role: 'viewer', userId: 'u-v' },
  }
  const invoices = new Map<string, { id: string; tenant: string; amount: number; status: string; description: string }>([
    ['inv-t1', { id: 'inv-t1', tenant: 't1', amount: 1000, status: 'open', description: 'Initial' }],
    ['inv-t2', { id: 'inv-t2', tenant: 't2', amount: 2000, status: 'open', description: 'Other' }],
  ])
  return fixture((req, res, body) => {
    const url = new URL(req.url ?? '/', 'http://127.0.0.1')
    const actor = actorOf(req, directory)
    if (!actor) return json(res, 401, { error: 'unauthorized' })
    const match = /^\/api\/invoices\/([^/]+)$/.exec(url.pathname)
    if (!match) return json(res, 404, { error: 'not_found' })
    if (req.method === 'DELETE') {
      const id = decodeURIComponent(match[1]!)
      const row = invoices.get(id)
      if (!row) return json(res, 404, { error: 'not_found' })
      if (hardened && row.tenant !== actor.tenant) return json(res, 404, { error: 'not_found' })
      invoices.delete(id)
      return json(res, 200, { ok: true })
    }
    const invoice = invoices.get(decodeURIComponent(match[1]!))
    if (!invoice) return json(res, 404, { error: 'not_found' })
    if (req.method === 'GET') {
      if (hardened && invoice.tenant !== actor.tenant) return json(res, 404, { error: 'not_found' })
      return json(res, 200, invoice)
    }
    if (req.method === 'PATCH') {
      if (hardened && invoice.tenant !== actor.tenant) return json(res, 404, { error: 'not_found' })
      const payload = JSON.parse(body || '{}') as { amount?: unknown; status?: unknown }
      if (payload.amount !== undefined) invoice.amount = Number(payload.amount)
      if (payload.status !== undefined) invoice.status = String(payload.status)
      return json(res, 200, { ok: true })
    }
    return json(res, 405, { error: 'method_not_allowed' })
  })
}

function invoiceSpec(origin: string) {
  const surface = [
    endpoint({ method: 'PATCH', pathTemplate: '/api/invoices/:invoiceId', origin }),
    endpoint({ method: 'GET', pathTemplate: '/api/invoices/:invoiceId', origin }),
  ]
  const harvests = new Map<string, EndpointHarvest>([
    ['PATCH:/api/invoices/:invoiceId', harvest({
      ownerIds: ['inv-t1'],
      otherIds: ['inv-t2'],
      fields: ['amount', 'status', 'description'],
      values: { amount: ['1000'], status: ['open'], description: ['Initial'] },
    })],
  ])
  const hyp = authzHypothesis(surface, harvests, 'PATCH', '/api/invoices/:invoiceId')
  assert.ok(hyp.readbackPath, 'the object detail route is named as the readback')
  const result = signal({
    pathAndQuery: hyp.pathAndQuery,
    anomalies: [{
      type: 'unauthorized_access',
      resourceId: 'inv-t1',
      actor: 'other_persona',
      method: 'PATCH',
      status: 200,
      similarityToOwner: 1,
      bodyTemplate: hyp.jsonBody,
    }],
  })
  const [spec] = synthesizeEngineSpecs(hyp, result)
  assert.ok(spec, 'a cross-tenant write spec is synthesized')
  return spec
}

test('cross-tenant write: the baseline-write delta is confirmed on the vulnerable twin', async () => {
  const fx = await invoiceFixture(false)
  try {
    const spec = invoiceSpec(fx.origin)
    const steps = spec.spec.steps as Array<{ id: string; request: { method: string; pathAndQuery: string; jsonBody?: Record<string, unknown> } }>
    const baseline = steps.find(step => step.id === 'w1')
    assert.equal(baseline?.request.method, 'PATCH')
    assert.ok(baseline?.request.jsonBody, 'baseline write carries a body')
    const result = await verify(spec.spec, fx.origin, ['member-a', 'member-b'])
    assert.equal(result.verdict, 'confirmed', String(result.outcome.reason))
    const evidence = result.evidencePayload.steps as Record<string, { json?: { amount?: number } }>
    assert.notEqual(evidence.c1.json?.amount, evidence.p2.json?.amount, 'the readback observes a real delta')
  } finally { await fx.close() }
})

test('cross-tenant write: tenant-checked update twins dismiss the same spec', async () => {
  const fx = await invoiceFixture(true)
  try {
    const spec = invoiceSpec(fx.origin)
    const result = await verify(spec.spec, fx.origin, ['member-a', 'member-b'])
    assert.notEqual(result.verdict, 'confirmed')
  } finally { await fx.close() }
})

// ---------------------------------------------------------------------------
// 2. Create-time mass assignment: baseline read + create/read-back
// ---------------------------------------------------------------------------

function projectFixture(hardened: boolean) {
  const directory: Record<string, Actor> = {
    'member-a': { tenant: 't1', role: 'member', userId: 'u-a' },
    'member-b': { tenant: 't2', role: 'member', userId: 'u-b' },
    viewer: { tenant: 't1', role: 'viewer', userId: 'u-v' },
  }
  type Project = { id: string; tenant_id: string; owner_id: string; name: string; description: string; visibility: string }
  const projects: Project[] = [
    { id: 'sp-t1', tenant_id: 't1', owner_id: 'u-a', name: 'Alpha', description: 'A', visibility: 'private' },
    { id: 'sp-t2', tenant_id: 't2', owner_id: 'u-b', name: 'Beta', description: 'B', visibility: 'private' },
  ]
  let next = 1
  return fixture((req, res, body) => {
    const url = new URL(req.url ?? '/', 'http://127.0.0.1')
    const actor = actorOf(req, directory)
    if (!actor) return json(res, 401, { error: 'unauthorized' })
    if (url.pathname !== '/api/spaces') return json(res, 404, { error: 'not_found' })
    if (req.method === 'GET') {
      return json(res, 200, { items: projects.filter(project => project.tenant_id === actor.tenant) })
    }
    if (req.method === 'POST') {
      const payload = JSON.parse(body || '{}') as Record<string, unknown>
      const id = `sp-new-${next++}`
      const row: Project = hardened
        ? {
            id,
            tenant_id: actor.tenant,
            owner_id: actor.userId,
            name: String(payload.name ?? 'Untitled'),
            description: String(payload.description ?? ''),
            visibility: payload.visibility === 'internal' ? 'internal' : 'private',
          }
        : {
            ...{ tenant_id: actor.tenant, owner_id: actor.userId, visibility: 'private' },
            ...payload,
            id,
          } as Project
      projects.push(row)
      return json(res, 201, { id, name: row.name })
    }
    return json(res, 405, { error: 'method_not_allowed' })
  })
}

function projectMassAssignSpec(origin: string) {
  const surface = [
    endpoint({ method: 'POST', pathTemplate: '/api/spaces', origin }),
    endpoint({ method: 'GET', pathTemplate: '/api/spaces', origin }),
  ]
  const harvests = new Map<string, EndpointHarvest>([
    ['POST:/api/spaces', harvest({
      fields: ['id', 'name', 'description', 'visibility', 'owner'],
      values: { name: ['Alpha'], description: ['A'], visibility: ['private'], owner: ['u-a'] },
      otherValues: { owner: ['u-b'] },
    })],
    ['GET:/api/spaces', harvest({
      ownerIds: ['sp-t1'],
      fields: ['id', 'name', 'description', 'visibility', 'owner'],
      values: { name: ['Alpha'], description: ['A'], visibility: ['private'], owner: ['u-a'] },
      otherValues: { owner: ['u-b'] },
    })],
  ])
  const hypotheses = enumerateHypotheses(surface, harvests, { tier: 3, personas })
  const hyp = hypotheses.find(candidate => candidate.probeClass === 'mass_assignment' && candidate.endpoint.pathTemplate === '/api/spaces')
  assert.ok(hyp, 'expected a mass-assignment hypothesis on the create route')
  assert.equal(hyp.candidateValues?.tenant_id, 't2')
  const result = signal({
    probeClass: 'mass_assignment',
    pathAndQuery: hyp.pathAndQuery,
    anomalies: [{ type: 'mass_assignment', field: 'owner_id' }],
  })
  const [spec] = synthesizeEngineSpecs(hyp, result)
  assert.ok(spec, 'a create-time mass-assignment spec is synthesized')
  return spec
}

test('mass assignment: pre-create baseline read makes the cross-tenant create observable', async () => {
  const fx = await projectFixture(false)
  try {
    const spec = projectMassAssignSpec(fx.origin)
    const steps = spec.spec.steps as Array<{ id: string; request: { method: string } }>
    assert.equal(steps.find(step => step.id === 'b1')?.request.method, 'GET')
    const result = await verify(spec.spec, fx.origin, ['member-a', 'member-b'])
    assert.equal(result.verdict, 'confirmed', String(result.outcome.reason))
  } finally { await fx.close() }
})

test('mass assignment: a session-scoped create twin dismisses the same spec', async () => {
  const fx = await projectFixture(true)
  try {
    const spec = projectMassAssignSpec(fx.origin)
    const result = await verify(spec.spec, fx.origin, ['member-a', 'member-b'])
    assert.notEqual(result.verdict, 'confirmed')
  } finally { await fx.close() }
})

// ---------------------------------------------------------------------------
// 3. Credential inventory: masked control vs unentitled full read
// ---------------------------------------------------------------------------

const apiSecret = 'rbs_ci_0123456789ab'

function tokenFixture(hardened: boolean) {
  const directory: Record<string, Actor> = {
    'member-a': { tenant: 't1', role: 'owner', userId: 'u-a' },
    viewer: { tenant: 't1', role: 'viewer', userId: 'u-v' },
  }
  const mask = (secret: string) => `${secret.slice(0, 6)}…${secret.slice(-2)}`
  return fixture((req, res) => {
    const url = new URL(req.url ?? '/', 'http://127.0.0.1')
    if (url.pathname !== '/api/tokens') return json(res, 404, { error: 'not_found' })
    const actor = actorOf(req, directory)
    if (!actor) return json(res, 401, { error: 'unauthorized' })
    const reveal = url.searchParams.get('reveal')
    const full = hardened ? reveal === '1' && actor.role === 'owner' : reveal !== '0'
    return json(res, 200, {
      items: [{ id: 'key-1', name: 'CI token', secret: full ? apiSecret : mask(apiSecret), scopes: 'read' }],
    })
  })
}

function credentialHypothesis(origin: string) {
  const surface = [endpoint({ method: 'GET', pathTemplate: '/api/tokens', origin })]
  const harvests = new Map<string, EndpointHarvest>([['GET:/api/tokens', harvest()]])
  const hypotheses = enumerateHypotheses(surface, harvests, { tier: 3, personas })
  const hyp = hypotheses.find(candidate => candidate.intent === 'secret_disclosure' && candidate.endpoint.pathTemplate === '/api/tokens')
  assert.ok(hyp, 'expected a credential-exposure hypothesis on the token inventory')
  assert.equal(hyp.viewerPersona, 'viewer')
  return hyp
}

test('credential inventory: the unentitled full secret confirms against the masked control', async () => {
  const fx = await tokenFixture(false)
  try {
    const hyp = credentialHypothesis(fx.origin)
    const result = signal({
      pathAndQuery: hyp.pathAndQuery,
      anomalies: [{
        type: 'secret_disclosed',
        path: '/api/tokens',
        persona: 'viewer',
        actor: 'viewer_persona',
        controlPath: '/api/tokens?reveal=0',
        secretPattern: 'rb[s]_[A-Za-z0-9]+_[0-9a-f]{12}',
      }],
    })
    const [spec] = synthesizeEngineSpecs(hyp, result)
    assert.ok(spec, 'a credential-exposure spec is synthesized')
    const replay = await verify(spec.spec, fx.origin, ['member-a', 'viewer'])
    assert.equal(replay.verdict, 'confirmed', String(replay.outcome.reason ?? replay.outcome.observed ?? 'not confirmed'))
  } finally { await fx.close() }
})

test('credential inventory: a masked-for-everyone twin dismisses the same spec', async () => {
  const fx = await tokenFixture(true)
  try {
    const hyp = credentialHypothesis(fx.origin)
    const result = signal({
      pathAndQuery: hyp.pathAndQuery,
      anomalies: [{
        type: 'secret_disclosed',
        path: '/api/tokens',
        persona: 'viewer',
        actor: 'viewer_persona',
        controlPath: '/api/tokens?reveal=0',
        secretPattern: 'rb[s]_[A-Za-z0-9]+_[0-9a-f]{12}',
      }],
    })
    const [spec] = synthesizeEngineSpecs(hyp, result)
    assert.ok(spec)
    const replay = await verify(spec.spec, fx.origin, ['member-a', 'viewer'])
    assert.notEqual(replay.verdict, 'confirmed')
  } finally { await fx.close() }
})

// ---------------------------------------------------------------------------
// 4. Audit log credential reference: text-tolerant sensitive read
// ---------------------------------------------------------------------------

function auditFixture(hardened: boolean) {
  const directory: Record<string, Actor> = {
    'member-a': { tenant: 't1', role: 'owner', userId: 'u-a' },
    viewer: { tenant: 't1', role: 'viewer', userId: 'u-v' },
  }
  return fixture((req, res) => {
    const url = new URL(req.url ?? '/', 'http://127.0.0.1')
    if (url.pathname !== '/api/admin/activity') return json(res, 404, { error: 'not_found' })
    const actor = actorOf(req, directory)
    if (!actor) return json(res, 401, { error: 'unauthorized' })
    const detail = hardened ? 'rotated secret rbs_[redacted]' : `rotated secret ${apiSecret}`
    return json(res, 200, { items: [{ actor: 'system', action: 'rotate_key', detail }] })
  })
}

function auditHypothesis(origin: string) {
  const surface = [endpoint({ method: 'GET', pathTemplate: '/api/admin/activity', origin })]
  const harvests = new Map<string, EndpointHarvest>([['GET:/api/admin/activity', harvest()]])
  const hypotheses = enumerateHypotheses(surface, harvests, { tier: 3, personas })
  const hyp = hypotheses.find(candidate => candidate.intent === 'secret_disclosure' && candidate.endpoint.pathTemplate === '/api/admin/activity')
  assert.ok(hyp, 'expected a credential-exposure hypothesis on the audit log')
  return hyp
}

function auditSpec(origin: string) {
  const hyp = auditHypothesis(origin)
  // The product signal can be only `unauthorized_access` (the credential is embedded in free text,
  // so no field-bound secret anomaly is emitted). The sensitive-read proof must still be built.
  const result = signal({
    pathAndQuery: hyp.pathAndQuery,
    anomalies: [{ type: 'unauthorized_access', actor: 'viewer_persona', method: 'GET', status: 200, functionLevel: true }],
  })
  const [spec] = synthesizeEngineSpecs(hyp, result)
  assert.ok(spec, 'a text-tolerant sensitive-read spec is synthesized')
  assert.equal(spec.vulnClass, 'info_disclosure')
  return spec
}

test('audit log: a credential reference in free text confirms via the anonymous-denial control', async () => {
  const fx = await auditFixture(false)
  try {
    const spec = auditSpec(fx.origin)
    const replay = await verify(spec.spec, fx.origin, ['member-a', 'viewer'])
    assert.equal(replay.verdict, 'confirmed', String(replay.outcome.reason))
  } finally { await fx.close() }
})

test('audit log: a redacting twin dismisses the same spec', async () => {
  const fx = await auditFixture(true)
  try {
    const spec = auditSpec(fx.origin)
    const replay = await verify(spec.spec, fx.origin, ['member-a', 'viewer'])
    assert.notEqual(replay.verdict, 'confirmed')
  } finally { await fx.close() }
})

// ---------------------------------------------------------------------------
// 5. Privileged delete: reserved live victim + 200-no-op tolerant control
// ---------------------------------------------------------------------------

function adminDeleteFixture(hardened: boolean) {
  const directory: Record<string, Actor> = {
    'member-a': { tenant: 't1', role: 'owner', userId: 'u-alex' },
    'member-b': { tenant: 't2', role: 'owner', userId: 'u-bea' },
    admin: { tenant: 't1', role: 'admin', userId: 'u-avery' },
    viewer: { tenant: 't1', role: 'viewer', userId: 'u-val' },
  }
  type User = { id: string; tenant: string; role: string; email: string; name: string }
  const users: User[] = [
    { id: 'u-alex', tenant: 't1', role: 'owner', email: 'alex@t1.test', name: 'Alex' },
    { id: 'u-avery', tenant: 't1', role: 'admin', email: 'avery@t1.test', name: 'Avery' },
    { id: 'u-val', tenant: 't1', role: 'viewer', email: 'val@t1.test', name: 'Val' },
    { id: 'u-lee', tenant: 't1', role: 'member', email: 'lee@t1.test', name: 'Lee' },
    { id: 'u-bea', tenant: 't2', role: 'owner', email: 'bea@t2.test', name: 'Bea' },
  ]
  return fixture((req, res) => {
    const url = new URL(req.url ?? '/', 'http://127.0.0.1')
    const actor = actorOf(req, directory)
    if (url.pathname === '/api/me') {
      if (!actor) return json(res, 401, { error: 'unauthorized' })
      return json(res, 200, { id: actor.userId, tenant: actor.tenant, role: actor.role })
    }
    if (url.pathname === '/api/people' && req.method === 'GET') {
      if (!actor) return json(res, 401, { error: 'unauthorized' })
      return json(res, 200, { items: users.filter(user => user.tenant === actor.tenant) })
    }
    const detail = /^\/api\/people\/([^/]+)$/.exec(url.pathname)
    if (detail && req.method === 'GET') {
      if (!actor) return json(res, 401, { error: 'unauthorized' })
      const user = users.find(candidate => candidate.id === decodeURIComponent(detail[1]!))
      if (!user || user.tenant !== actor.tenant) return json(res, 404, { error: 'not_found' })
      return json(res, 200, { id: user.id, email: user.email, role: user.role, name: user.name })
    }
    const adminDelete = /^\/api\/admin\/people\/([^/]+)$/.exec(url.pathname)
    if (adminDelete && req.method === 'DELETE') {
      if (!actor) return json(res, 401, { error: 'unauthorized' })
      if (hardened && actor.role !== 'admin' && actor.role !== 'owner') return json(res, 403, { error: 'forbidden' })
      const id = decodeURIComponent(adminDelete[1]!)
      const index = users.findIndex(user => user.id === id && user.tenant === actor.tenant && user.role !== 'owner')
      if (index >= 0) users.splice(index, 1)
      return json(res, 200, { ok: true })
    }
    return json(res, 404, { error: 'not_found' })
  })
}

function adminDeleteSpec(origin: string) {
  const surface = [
    endpoint({ method: 'DELETE', pathTemplate: '/api/admin/people/:personId', origin }),
    endpoint({ method: 'GET', pathTemplate: '/api/people', origin }),
    endpoint({ method: 'GET', pathTemplate: '/api/people/:personId', origin }),
    endpoint({ method: 'GET', pathTemplate: '/api/me', origin }),
  ]
  const harvests = new Map<string, EndpointHarvest>([
    ['DELETE:/api/admin/people/:personId', harvest()],
    ['GET:/api/people', harvest({
      ownerIds: ['u-alex', 'u-avery', 'u-val', 'u-lee'],
      fields: ['id', 'email', 'role', 'name'],
      values: { role: ['owner'], name: ['Alex'] },
    })],
    ['GET:/api/me', harvest({ viewerIds: ['u-val'] })],
  ])
  const hyp = authzHypothesis(surface, harvests, 'DELETE', '/api/admin/people/:personId')
  assert.equal(hyp.reservedVictimId, 'u-avery', 'a deletable colleague is reserved for replay')
  assert.equal(hyp.authzRequiredRole, 'admin')
  const result = signal({
    pathAndQuery: hyp.pathAndQuery,
    anomalies: [{
      type: 'unauthorized_access',
      resourceId: 'u-val',
      actor: 'other_persona',
      method: 'DELETE',
      status: 200,
      functionLevel: false,
      bodyTemplate: {},
    }],
    details: {
      matrix: [
        { resourceId: 'u-val', actor: 'owner', status: 200, bodyBytes: 20, accessible: true },
        { resourceId: 'u-val', actor: 'other_persona', status: 200, bodyBytes: 11, accessible: true },
      ],
    },
  })
  const [spec] = synthesizeEngineSpecs(hyp, result)
  assert.ok(spec, 'a privileged-delete spec is synthesized')
  assert.deepEqual(spec.spec.expectedImpactEvents, ['privilege_escalation'])
  return spec
}

test('privileged delete: the reserved live victim is removed and the bogus delete stays a no-op', async () => {
  const fx = await adminDeleteFixture(false)
  try {
    const spec = adminDeleteSpec(fx.origin)
    const steps = spec.spec.steps as Array<{ id: string; request: { pathAndQuery: string } }>
    assert.equal(steps.find(step => step.id === 'p1')?.request.pathAndQuery, '/api/admin/people/u-avery')
    const replay = await verify(spec.spec, fx.origin, ['member-a', 'member-b', 'viewer', 'admin'])
    assert.equal(replay.verdict, 'confirmed', String(replay.outcome.reason))
    const evidence = replay.evidencePayload.steps as Record<string, { status?: number }>
    assert.equal(evidence.c2.status, 200, 'the bogus-id delete is a tolerated 200 no-op')
    assert.equal(evidence.p2.status, 404, 'the reserved victim is gone after the probe delete')
  } finally { await fx.close() }
})

test('privileged delete: an admin-role-gated twin dismisses the same spec', async () => {
  const fx = await adminDeleteFixture(true)
  try {
    const spec = adminDeleteSpec(fx.origin)
    const replay = await verify(spec.spec, fx.origin, ['member-a', 'member-b', 'viewer', 'admin'])
    assert.notEqual(replay.verdict, 'confirmed')
  } finally { await fx.close() }
})
